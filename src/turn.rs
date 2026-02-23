use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

type HmacSha1 = Hmac<Sha1>;

const MAGIC_COOKIE: u32 = 0x2112A442;
const MSG_ALLOCATE_REQUEST: u16 = 0x0003;
const MSG_ALLOCATE_SUCCESS: u16 = 0x0103;
const MSG_ALLOCATE_ERROR: u16 = 0x0113;
const MSG_CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const MSG_CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const MSG_SEND_INDICATION: u16 = 0x0016;
const MSG_DATA_INDICATION: u16 = 0x0017;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;

#[derive(Clone, Debug)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct TurnAllocation {
    pub socket: UdpSocket,
    pub server: SocketAddr,
    pub relay_addr: SocketAddr,
    #[allow(dead_code)]
    pub mapped_addr: Option<SocketAddr>,
    username: Option<String>,
    realm: Option<String>,
    nonce: Option<String>,
    key: Option<Vec<u8>>,
}

pub async fn allocate(
    server: &str,
    creds: Option<&TurnCredentials>,
    timeout_duration: Duration,
) -> Result<TurnAllocation> {
    let server_addr = resolve_server(server)?;
    let bind_addr = match server_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .context("failed to bind turn socket")?;

    let (transaction_id, request) = build_allocate_request(None, None, None);
    socket.send_to(&request, server_addr).await?;
    let response = recv_message(&socket, server_addr, timeout_duration).await?;
    let parsed = parse_message(&response, Some(&transaction_id))?;

    match parsed.msg_type {
        MSG_ALLOCATE_SUCCESS => {
            let (relay_addr, mapped_addr) = extract_addresses(&parsed, &transaction_id)?;
            return Ok(TurnAllocation {
                socket,
                server: server_addr,
                relay_addr,
                mapped_addr,
                username: None,
                realm: None,
                nonce: None,
                key: None,
            });
        }
        MSG_ALLOCATE_ERROR => {
            let error_code = extract_error_code(&parsed);
            if error_code == Some(401) || error_code == Some(438) {
                let creds = creds.ok_or_else(|| anyhow!("turn auth required"))?;
                let realm = extract_string(&parsed, ATTR_REALM)
                    .ok_or_else(|| anyhow!("turn realm missing"))?;
                let nonce = extract_string(&parsed, ATTR_NONCE)
                    .ok_or_else(|| anyhow!("turn nonce missing"))?;
                let key = build_long_term_key(creds, &realm)?;
                let (transaction_id, request) = build_allocate_request(
                    Some(creds.username.as_str()),
                    Some(realm.as_str()),
                    Some(nonce.as_str()),
                );
                let request = add_message_integrity(request, &key)?;
                socket.send_to(&request, server_addr).await?;
                let response = recv_message(&socket, server_addr, timeout_duration).await?;
                let parsed = parse_message(&response, Some(&transaction_id))?;
                if parsed.msg_type != MSG_ALLOCATE_SUCCESS {
                    return Err(anyhow!("turn allocate failed after auth"));
                }
                let (relay_addr, mapped_addr) = extract_addresses(&parsed, &transaction_id)?;
                return Ok(TurnAllocation {
                    socket,
                    server: server_addr,
                    relay_addr,
                    mapped_addr,
                    username: Some(creds.username.clone()),
                    realm: Some(realm),
                    nonce: Some(nonce),
                    key: Some(key),
                });
            }
        }
        _ => {}
    }

    Err(anyhow!("turn allocate failed"))
}

pub async fn create_permission(
    allocation: &mut TurnAllocation,
    peer: SocketAddr,
    timeout_duration: Duration,
) -> Result<()> {
    let (transaction_id, mut request) = build_create_permission_request(allocation, peer)?;
    request = maybe_add_integrity(allocation, request)?;
    allocation
        .socket
        .send_to(&request, allocation.server)
        .await?;
    let response = recv_message(&allocation.socket, allocation.server, timeout_duration).await?;
    let parsed = parse_message(&response, Some(&transaction_id))?;
    if parsed.msg_type == MSG_CREATE_PERMISSION_SUCCESS {
        return Ok(());
    }
    Err(anyhow!("turn create permission failed"))
}

pub async fn send_data(
    allocation: &mut TurnAllocation,
    peer: SocketAddr,
    data: &[u8],
) -> Result<()> {
    let (transaction_id, request) = build_send_indication(peer, data)?;
    let _ = transaction_id;
    allocation
        .socket
        .send_to(&request, allocation.server)
        .await?;
    Ok(())
}

pub async fn recv_data(
    allocation: &mut TurnAllocation,
    timeout_duration: Option<Duration>,
) -> Result<Option<(SocketAddr, Vec<u8>)>> {
    let mut buf = vec![0u8; 2048];
    let result = if let Some(timeout_duration) = timeout_duration {
        timeout(timeout_duration, allocation.socket.recv_from(&mut buf)).await?
    } else {
        allocation.socket.recv_from(&mut buf).await
    };

    let (len, from) = result?;
    if from != allocation.server {
        return Ok(None);
    }
    let parsed = parse_message(&buf[..len], None)?;
    if parsed.msg_type != MSG_DATA_INDICATION {
        return Ok(None);
    }
    let transaction_id = parsed.transaction_id;
    let peer = extract_xor_address(&parsed, ATTR_XOR_PEER_ADDRESS, &transaction_id)
        .ok_or_else(|| anyhow!("turn data indication missing peer address"))?;
    let data = extract_bytes(&parsed, ATTR_DATA).unwrap_or_default();
    Ok(Some((peer, data)))
}

fn resolve_server(server: &str) -> Result<SocketAddr> {
    server
        .to_socket_addrs()
        .context("failed to resolve turn server")?
        .next()
        .ok_or_else(|| anyhow!("turn server resolution returned no addresses"))
}

fn random_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

fn build_allocate_request(
    username: Option<&str>,
    realm: Option<&str>,
    nonce: Option<&str>,
) -> ([u8; 12], Vec<u8>) {
    let transaction_id = random_transaction_id();
    let mut attrs = Vec::new();
    attrs.push(Attribute::new(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]));
    if let Some(username) = username {
        attrs.push(Attribute::new(ATTR_USERNAME, username.as_bytes().to_vec()));
    }
    if let Some(realm) = realm {
        attrs.push(Attribute::new(ATTR_REALM, realm.as_bytes().to_vec()));
    }
    if let Some(nonce) = nonce {
        attrs.push(Attribute::new(ATTR_NONCE, nonce.as_bytes().to_vec()));
    }
    let msg = build_message(MSG_ALLOCATE_REQUEST, &transaction_id, attrs);
    (transaction_id, msg)
}

fn build_create_permission_request(
    allocation: &TurnAllocation,
    peer: SocketAddr,
) -> Result<([u8; 12], Vec<u8>)> {
    let transaction_id = random_transaction_id();
    let mut attrs = Vec::new();
    let xor_peer = encode_xor_address(peer, &transaction_id)?;
    attrs.push(Attribute::new(ATTR_XOR_PEER_ADDRESS, xor_peer));
    if let Some(username) = allocation.username.as_ref() {
        attrs.push(Attribute::new(ATTR_USERNAME, username.as_bytes().to_vec()));
    }
    if let Some(realm) = allocation.realm.as_ref() {
        attrs.push(Attribute::new(ATTR_REALM, realm.as_bytes().to_vec()));
    }
    if let Some(nonce) = allocation.nonce.as_ref() {
        attrs.push(Attribute::new(ATTR_NONCE, nonce.as_bytes().to_vec()));
    }
    let msg = build_message(MSG_CREATE_PERMISSION_REQUEST, &transaction_id, attrs);
    Ok((transaction_id, msg))
}

fn build_send_indication(peer: SocketAddr, data: &[u8]) -> Result<([u8; 12], Vec<u8>)> {
    let transaction_id = random_transaction_id();
    let xor_peer = encode_xor_address(peer, &transaction_id)?;
    let attrs = vec![
        Attribute::new(ATTR_XOR_PEER_ADDRESS, xor_peer),
        Attribute::new(ATTR_DATA, data.to_vec()),
    ];
    let msg = build_message(MSG_SEND_INDICATION, &transaction_id, attrs);
    Ok((transaction_id, msg))
}

fn build_message(msg_type: u16, transaction_id: &[u8; 12], attrs: Vec<Attribute>) -> Vec<u8> {
    let mut body = Vec::new();
    for attr in attrs {
        attr.write(&mut body);
    }
    let length = body.len() as u16;
    let mut buf = Vec::with_capacity(20 + body.len());
    buf.extend_from_slice(&msg_type.to_be_bytes());
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(transaction_id);
    buf.extend_from_slice(&body);
    buf
}

fn add_message_integrity(mut msg: Vec<u8>, key: &[u8]) -> Result<Vec<u8>> {
    let current_len = u16::from_be_bytes([msg[2], msg[3]]);
    let total_len = current_len.saturating_add(24);
    msg[2..4].copy_from_slice(&total_len.to_be_bytes());
    let mi_offset = msg.len() + 4;
    msg.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
    msg.extend_from_slice(&(20u16).to_be_bytes());
    msg.extend_from_slice(&vec![0u8; 20]);

    let mut mac = HmacSha1::new_from_slice(key).map_err(|_| anyhow!("invalid hmac key"))?;
    mac.update(&msg);
    let result = mac.finalize().into_bytes();
    msg[mi_offset..mi_offset + 20].copy_from_slice(&result);
    Ok(msg)
}

fn maybe_add_integrity(allocation: &TurnAllocation, msg: Vec<u8>) -> Result<Vec<u8>> {
    if let Some(key) = allocation.key.as_ref() {
        add_message_integrity(msg, key)
    } else {
        Ok(msg)
    }
}

fn build_long_term_key(creds: &TurnCredentials, realm: &str) -> Result<Vec<u8>> {
    let mut hasher = Md5::new();
    let data = format!("{}:{}:{}", creds.username, realm, creds.password);
    hasher.update(data.as_bytes());
    Ok(hasher.finalize().to_vec())
}

async fn recv_message(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 2048];
    let (len, from) = timeout(timeout_duration, socket.recv_from(&mut buf)).await??;
    if from != server {
        return Err(anyhow!("unexpected turn response source"));
    }
    buf.truncate(len);
    Ok(buf)
}

#[derive(Clone)]
struct Attribute {
    ty: u16,
    value: Vec<u8>,
}

impl Attribute {
    fn new(ty: u16, value: Vec<u8>) -> Self {
        Self { ty, value }
    }

    fn write(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.ty.to_be_bytes());
        buf.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.value);
        let padding = (4 - (self.value.len() % 4)) % 4;
        if padding > 0 {
            buf.extend_from_slice(&vec![0u8; padding]);
        }
    }
}

struct ParsedMessage {
    msg_type: u16,
    transaction_id: [u8; 12],
    attrs: Vec<Attribute>,
}

fn parse_message(buf: &[u8], expected_id: Option<&[u8; 12]>) -> Result<ParsedMessage> {
    if buf.len() < 20 {
        return Err(anyhow!("turn message too short"));
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf[4..8] != MAGIC_COOKIE.to_be_bytes() {
        return Err(anyhow!("turn message missing magic cookie"));
    }
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&buf[8..20]);
    if let Some(expected) = expected_id {
        if &transaction_id != expected {
            return Err(anyhow!("turn transaction id mismatch"));
        }
    }
    if buf.len() < 20 + length {
        return Err(anyhow!("turn message length mismatch"));
    }
    let mut attrs = Vec::new();
    let mut offset = 20;
    let end = 20 + length;
    while offset + 4 <= end {
        let ty = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if offset + len > end {
            break;
        }
        let value = buf[offset..offset + len].to_vec();
        attrs.push(Attribute { ty, value });
        offset += (len + 3) & !3;
    }
    Ok(ParsedMessage {
        msg_type,
        transaction_id,
        attrs,
    })
}

fn extract_error_code(parsed: &ParsedMessage) -> Option<u16> {
    for attr in &parsed.attrs {
        if attr.ty != ATTR_ERROR_CODE || attr.value.len() < 4 {
            continue;
        }
        let class = attr.value[2] & 0x07;
        let number = attr.value[3];
        return Some((class as u16) * 100 + number as u16);
    }
    None
}

fn extract_string(parsed: &ParsedMessage, attr_type: u16) -> Option<String> {
    for attr in &parsed.attrs {
        if attr.ty == attr_type {
            return String::from_utf8(attr.value.clone()).ok();
        }
    }
    None
}

fn extract_bytes(parsed: &ParsedMessage, attr_type: u16) -> Option<Vec<u8>> {
    for attr in &parsed.attrs {
        if attr.ty == attr_type {
            return Some(attr.value.clone());
        }
    }
    None
}

fn extract_addresses(
    parsed: &ParsedMessage,
    transaction_id: &[u8; 12],
) -> Result<(SocketAddr, Option<SocketAddr>)> {
    let relay = extract_xor_address(parsed, ATTR_XOR_RELAYED_ADDRESS, transaction_id)
        .ok_or_else(|| anyhow!("turn allocate missing relay address"))?;
    let mapped = extract_xor_address(parsed, ATTR_XOR_MAPPED_ADDRESS, transaction_id);
    Ok((relay, mapped))
}

fn extract_xor_address(
    parsed: &ParsedMessage,
    attr_type: u16,
    transaction_id: &[u8; 12],
) -> Option<SocketAddr> {
    for attr in &parsed.attrs {
        if attr.ty != attr_type {
            continue;
        }
        if let Some(addr) = decode_xor_address(&attr.value, transaction_id) {
            return Some(addr);
        }
    }
    None
}

fn decode_xor_address(value: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        0x01 => {
            if value.len() < 8 {
                return None;
            }
            let xaddr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ MAGIC_COOKIE;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(xaddr)), port))
        }
        0x02 => {
            if value.len() < 20 {
                return None;
            }
            let mut xor = [0u8; 16];
            xor[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor[4..16].copy_from_slice(transaction_id);
            let mut addr = [0u8; 16];
            for i in 0..16 {
                addr[i] = value[4 + i] ^ xor[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        _ => None,
    }
}

fn encode_xor_address(addr: SocketAddr, transaction_id: &[u8; 12]) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    value.push(0);
    match addr {
        SocketAddr::V4(addr) => {
            value.push(0x01);
            let port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            value.extend_from_slice(&port.to_be_bytes());
            let xaddr = u32::from(*addr.ip()) ^ MAGIC_COOKIE;
            value.extend_from_slice(&xaddr.to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            value.push(0x02);
            let port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            value.extend_from_slice(&port.to_be_bytes());
            let mut xor = [0u8; 16];
            xor[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor[4..16].copy_from_slice(transaction_id);
            let mut ip_bytes = addr.ip().octets();
            for i in 0..16 {
                ip_bytes[i] ^= xor[i];
            }
            value.extend_from_slice(&ip_bytes);
        }
    }
    Ok(value)
}
