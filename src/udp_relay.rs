use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

const MAGIC: &[u8; 4] = b"LSR1";
const TYPE_REGISTER: u8 = 1;
const TYPE_SEND: u8 = 2;
const TYPE_DELIVER: u8 = 3;
const HEADER_LEN: usize = 8;
const MAX_ID_LEN: usize = 64;

pub fn build_register(node_id: &str) -> Result<Vec<u8>> {
    build_packet(TYPE_REGISTER, node_id, "", &[])
}

pub fn build_send(from_id: &str, to_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    build_packet(TYPE_SEND, from_id, to_id, payload)
}

pub fn parse_deliver(buf: &[u8]) -> Option<(String, Vec<u8>)> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    if &buf[0..4] != MAGIC {
        return None;
    }
    let msg_type = buf[4];
    if msg_type != TYPE_DELIVER {
        return None;
    }
    let from_len = buf[5] as usize;
    let to_len = buf[6] as usize;
    if from_len > MAX_ID_LEN || to_len > MAX_ID_LEN || to_len != 0 {
        return None;
    }
    let offset = HEADER_LEN;
    if buf.len() < offset + from_len + to_len {
        return None;
    }
    let from_end = offset + from_len;
    let from_id = std::str::from_utf8(&buf[offset..from_end])
        .ok()?
        .to_string();
    let payload = buf[from_end..].to_vec();
    Some((from_id, payload))
}

pub fn resolve_server(server: &str) -> Result<SocketAddr> {
    server
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("relay server resolution returned no addresses"))
}

pub fn bind_addr_for(server: &SocketAddr) -> SocketAddr {
    match server {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn build_packet(msg_type: u8, from_id: &str, to_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    if from_id.len() > MAX_ID_LEN || to_id.len() > MAX_ID_LEN {
        return Err(anyhow!("relay id too long"));
    }
    let mut buf = Vec::with_capacity(HEADER_LEN + from_id.len() + to_id.len() + payload.len());
    buf.extend_from_slice(MAGIC);
    buf.push(msg_type);
    buf.push(from_id.len() as u8);
    buf.push(to_id.len() as u8);
    buf.push(0);
    buf.extend_from_slice(from_id.as_bytes());
    buf.extend_from_slice(to_id.as_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}
