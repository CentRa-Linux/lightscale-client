use crate::model::PeerInfo;
use crate::stream_relay;
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

const DATA_MAGIC: &[u8; 4] = b"LSDP";
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

pub struct RelayTunnelManager {
    node_id: String,
    servers: Vec<String>,
    wg_listen_port: u16,
    relay_ip: Option<IpAddr>,
    tunnels: HashMap<String, RelayTunnel>,
}

struct RelayTunnel {
    local_addr: SocketAddr,
    _task: JoinHandle<()>,
}

impl RelayTunnelManager {
    pub fn new(
        node_id: String,
        servers: Vec<String>,
        wg_listen_port: u16,
        relay_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            node_id,
            servers,
            wg_listen_port,
            relay_ip,
            tunnels: HashMap::new(),
        }
    }

    pub async fn ensure_for_peers(
        &mut self,
        peers: &[PeerInfo],
    ) -> Result<HashMap<String, SocketAddr>> {
        let mut endpoints = HashMap::new();
        for peer in peers {
            let addr = self.ensure_peer(&peer.id).await?;
            endpoints.insert(peer.id.clone(), addr);
        }
        Ok(endpoints)
    }

    async fn ensure_peer(&mut self, peer_id: &str) -> Result<SocketAddr> {
        if let Some(tunnel) = self.tunnels.get(peer_id) {
            return Ok(tunnel.local_addr);
        }

        let mut relay_ip = self
            .relay_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let socket = match UdpSocket::bind(SocketAddr::new(relay_ip, 0)).await {
            Ok(socket) => socket,
            Err(_) => {
                relay_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
                UdpSocket::bind(SocketAddr::new(relay_ip, 0)).await?
            }
        };
        let local_addr = SocketAddr::new(relay_ip, socket.local_addr()?.port());
        let node_id = self.node_id.clone();
        let servers = self.servers.clone();
        let peer_id_owned = peer_id.to_string();
        let wg_listen_port = self.wg_listen_port;

        let task = tokio::spawn(async move {
            run_tunnel(node_id, peer_id_owned, servers, socket, wg_listen_port).await;
        });

        self.tunnels.insert(
            peer_id.to_string(),
            RelayTunnel {
                local_addr,
                _task: task,
            },
        );

        Ok(local_addr)
    }
}

async fn run_tunnel(
    node_id: String,
    peer_id: String,
    servers: Vec<String>,
    socket: UdpSocket,
    wg_listen_port: u16,
) {
    if servers.is_empty() {
        eprintln!("stream relay tunnel missing servers");
        return;
    }
    let wg_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), wg_listen_port);
    let mut buf = vec![0u8; 65535];
    let mut server_index: usize = 0;
    loop {
        let server = servers[server_index % servers.len()].clone();
        match TcpStream::connect(&server).await {
            Ok(mut stream) => {
                if let Err(err) = stream_relay::write_register(&mut stream, &node_id).await {
                    eprintln!("stream relay register failed: {}", err);
                    sleep(RECONNECT_DELAY).await;
                    continue;
                }
                eprintln!("relay tunnel {} connected to {} for {}", node_id, server, peer_id);
                let mut saw_send = false;
                let mut saw_recv = false;
                loop {
                    tokio::select! {
                        recv = socket.recv_from(&mut buf) => {
                            let (len, _) = match recv {
                                Ok(data) => data,
                                Err(_) => break,
                            };
                            if !saw_send {
                                eprintln!("relay tunnel {} -> {} forwarding {} bytes", node_id, peer_id, len);
                                saw_send = true;
                            }
                            let payload = wrap_data(&buf[..len]);
                            if stream_relay::write_send(&mut stream, &node_id, &peer_id, &payload).await.is_err() {
                                break;
                            }
                        }
                        deliver = stream_relay::read_deliver(&mut stream) => {
                            let delivered = match deliver {
                                Ok(Some(data)) => data,
                                Ok(None) => continue,
                                Err(_) => break,
                            };
                            if delivered.0 != peer_id {
                                continue;
                            }
                            let payload = match unwrap_data(&delivered.1) {
                                Some(payload) => payload,
                                None => continue,
                            };
                            if !saw_recv {
                                eprintln!("relay tunnel {} <- {} received {} bytes", node_id, peer_id, payload.len());
                                saw_recv = true;
                            }
                            let _ = socket.send_to(payload, wg_addr).await;
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("stream relay tunnel connect failed: {}", err);
            }
        }

        server_index = server_index.wrapping_add(1);
        sleep(RECONNECT_DELAY).await;
    }
}

fn wrap_data(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_MAGIC.len() + payload.len());
    out.extend_from_slice(DATA_MAGIC);
    out.extend_from_slice(payload);
    out
}

fn unwrap_data(payload: &[u8]) -> Option<&[u8]> {
    if payload.starts_with(DATA_MAGIC) {
        Some(&payload[DATA_MAGIC.len()..])
    } else {
        None
    }
}
