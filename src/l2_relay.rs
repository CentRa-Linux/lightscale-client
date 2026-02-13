use crate::model::NetMap;
use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
const RELAY_OFFSET: u16 = 10000;

pub fn spawn(wg_ipv4: Ipv4Addr, netmap: NetMap) -> Result<Arc<Mutex<NetMap>>> {
    let state = Arc::new(Mutex::new(netmap));
    let mdns_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(err) = relay_group(MDNS_GROUP, MDNS_PORT, wg_ipv4, mdns_state).await {
            eprintln!("l2 relay mdns stopped: {}", err);
        }
    });
    let ssdp_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(err) = relay_group(SSDP_GROUP, SSDP_PORT, wg_ipv4, ssdp_state).await {
            eprintln!("l2 relay ssdp stopped: {}", err);
        }
    });
    Ok(state)
}

async fn relay_group(
    group: Ipv4Addr,
    port: u16,
    wg_ipv4: Ipv4Addr,
    state: Arc<Mutex<NetMap>>,
) -> Result<()> {
    let relay_port = port.saturating_add(RELAY_OFFSET);
    let local = build_multicast_socket(port, group, wg_ipv4)?;
    let relay = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        relay_port,
    ))
    .await
    .with_context(|| format!("l2 relay bind {} failed", relay_port))?;
    let mut buf_local = vec![0u8; 2048];
    let mut buf_relay = vec![0u8; 2048];
    loop {
        tokio::select! {
            recv = local.recv_from(&mut buf_local) => {
                let (len, src) = recv?;
                if src.port() == relay_port {
                    continue;
                }
                let peers = peers_from_state(&state, wg_ipv4);
                for peer in peers {
                    let target = SocketAddr::new(IpAddr::V4(peer), relay_port);
                    let _ = relay.send_to(&buf_local[..len], target).await;
                }
            }
            recv = relay.recv_from(&mut buf_relay) => {
                let (len, _) = recv?;
                let target = SocketAddr::new(IpAddr::V4(group), port);
                let _ = local.send_to(&buf_relay[..len], target).await;
            }
        }
    }
}

fn peers_from_state(state: &Arc<Mutex<NetMap>>, self_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let guard = match state.lock() {
        Ok(guard) => guard,
        Err(_) => return Vec::new(),
    };
    guard
        .peers
        .iter()
        .filter_map(|peer| peer.ipv4.parse().ok())
        .filter(|ip| *ip != self_ip)
        .collect()
}

fn build_multicast_socket(port: u16, group: Ipv4Addr, iface: Ipv4Addr) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("l2 relay socket create failed")?;
    socket
        .set_reuse_address(true)
        .context("l2 relay reuseaddr failed")?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    socket.bind(&addr.into()).context("l2 relay bind failed")?;
    socket
        .join_multicast_v4(&group, &iface)
        .context("l2 relay multicast join failed")?;
    socket
        .set_multicast_loop_v4(true)
        .context("l2 relay multicast loop failed")?;
    socket
        .set_nonblocking(true)
        .context("l2 relay socket nonblocking failed")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("l2 relay tokio socket failed")
}

#[allow(dead_code)]
fn ensure_ipv4(value: &str) -> Result<Ipv4Addr> {
    value
        .parse()
        .map_err(|_| anyhow!("invalid ipv4 address {}", value))
}
