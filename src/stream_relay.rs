use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: &[u8; 4] = b"LSR2";
const TYPE_REGISTER: u8 = 1;
const TYPE_SEND: u8 = 2;
const TYPE_DELIVER: u8 = 3;
const HEADER_LEN: usize = 8;
const MAX_ID_LEN: usize = 64;
const MAX_FRAME_LEN: usize = 64 * 1024;

pub async fn write_register<W: AsyncWrite + Unpin>(stream: &mut W, node_id: &str) -> Result<()> {
    let packet = build_packet(TYPE_REGISTER, node_id, "", &[])?;
    write_frame(stream, &packet).await
}

pub async fn write_send<W: AsyncWrite + Unpin>(
    stream: &mut W,
    from_id: &str,
    to_id: &str,
    payload: &[u8],
) -> Result<()> {
    let packet = build_packet(TYPE_SEND, from_id, to_id, payload)?;
    write_frame(stream, &packet).await
}

pub async fn read_deliver<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<Option<(String, Vec<u8>)>> {
    let frame = read_frame(stream).await?;
    Ok(parse_deliver(&frame))
}

async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(anyhow!("invalid frame length {}", len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<W: AsyncWrite + Unpin>(stream: &mut W, body: &[u8]) -> Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME_LEN {
        return Err(anyhow!("invalid frame length {}", body.len()));
    }
    let len = body.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

fn parse_deliver(buf: &[u8]) -> Option<(String, Vec<u8>)> {
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
