use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const MAGIC_COOKIE: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub fn discover_endpoint(
    servers: &[String],
    bind_port: u16,
    timeout: Duration,
) -> Result<SocketAddr> {
    let mut last_err: Option<anyhow::Error> = None;
    for server in servers {
        match discover_endpoint_one(server, bind_port, timeout) {
            Ok(addr) => return Ok(addr),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no stun servers provided")))
}

fn discover_endpoint_one(server: &str, bind_port: u16, timeout: Duration) -> Result<SocketAddr> {
    let server_addr = resolve_server(server)?;
    let bind_addr = match server_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bind_port),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), bind_port),
    };

    let socket = UdpSocket::bind(bind_addr).context("failed to bind stun socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set stun timeout")?;

    let (transaction_id, request) = build_binding_request();
    socket
        .send_to(&request, server_addr)
        .context("failed to send stun request")?;

    let mut buf = [0u8; 1024];
    let (len, from) = socket.recv_from(&mut buf).context("stun recv failed")?;
    if from != server_addr {
        return Err(anyhow!("stun response from unexpected address"));
    }
    parse_binding_response(&buf[..len], &transaction_id)
}

fn resolve_server(server: &str) -> Result<SocketAddr> {
    server
        .to_socket_addrs()
        .context("failed to resolve stun server")?
        .next()
        .ok_or_else(|| anyhow!("stun server resolution returned no addresses"))
}

fn build_binding_request() -> ([u8; 12], [u8; 20]) {
    let mut transaction_id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut transaction_id);
    let mut buf = [0u8; 20];
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(&transaction_id);
    (transaction_id, buf)
}

fn parse_binding_response(buf: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
    if buf.len() < 20 {
        return Err(anyhow!("stun response too short"));
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_SUCCESS {
        return Err(anyhow!("unexpected stun response type {:04x}", msg_type));
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 20 + msg_len {
        return Err(anyhow!("stun response length mismatch"));
    }

    if buf[4..8] != MAGIC_COOKIE.to_be_bytes() {
        return Err(anyhow!("stun response missing magic cookie"));
    }

    if buf[8..20] != transaction_id[..] {
        return Err(anyhow!("stun transaction id mismatch"));
    }

    let mut offset = 20;
    let end = 20 + msg_len;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > end {
            break;
        }
        let attr = &buf[offset..offset + attr_len];
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            if let Some(addr) = parse_xor_mapped(attr, transaction_id) {
                return Ok(addr);
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS {
            if let Some(addr) = parse_mapped(attr) {
                return Ok(addr);
            }
        }
        offset += (attr_len + 3) & !3;
    }

    Err(anyhow!("stun response missing mapped address"))
}

fn parse_mapped(attr: &[u8]) -> Option<SocketAddr> {
    if attr.len() < 4 {
        return None;
    }
    let family = attr[1];
    let port = u16::from_be_bytes([attr[2], attr[3]]);
    match family {
        0x01 => {
            if attr.len() < 8 {
                return None;
            }
            let addr = Ipv4Addr::new(attr[4], attr[5], attr[6], attr[7]);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        0x02 => {
            if attr.len() < 20 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&attr[4..20]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

fn parse_xor_mapped(attr: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if attr.len() < 4 {
        return None;
    }
    let family = attr[1];
    let port = u16::from_be_bytes([attr[2], attr[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        0x01 => {
            if attr.len() < 8 {
                return None;
            }
            let xaddr = u32::from_be_bytes([attr[4], attr[5], attr[6], attr[7]]) ^ MAGIC_COOKIE;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(xaddr)), port))
        }
        0x02 => {
            if attr.len() < 20 {
                return None;
            }
            let mut xor = [0u8; 16];
            xor[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor[4..16].copy_from_slice(transaction_id);
            let mut addr = [0u8; 16];
            for i in 0..16 {
                addr[i] = attr[4 + i] ^ xor[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        _ => None,
    }
}
