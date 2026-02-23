use crate::model::{NetMap, Route, RouteKind};
use crate::routes;
use crate::state::ClientState;
use anyhow::{anyhow, Context, Result};
use defguard_wireguard_rs::{InterfaceConfiguration, WGApi, WireguardInterfaceApi};
use defguard_wireguard_rs::key::Key as DgKey;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer as DgPeer;
#[cfg(target_os = "windows")]
use defguard_wireguard_rs::Kernel;
#[cfg(target_os = "macos")]
use defguard_wireguard_rs::Userspace;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub enum Backend {
    Kernel,
    Boringtun,
}

pub struct WgConfig {
    pub interface: String,
    pub listen_port: u16,
    pub backend: Backend,
}

#[derive(Default)]
pub struct EndpointTracker;

/// Lightscale interface prefix for identification.
pub const INTERFACE_PREFIX: &str = "ls-";

/// Checks if an interface name is managed by lightscale.
pub fn is_lightscale_interface(name: &str) -> bool {
    name.starts_with(INTERFACE_PREFIX)
}

pub async fn apply(
    netmap: &NetMap,
    state: &ClientState,
    cfg: &WgConfig,
    routes_cfg: Option<&routes::RouteApplyConfig>,
) -> Result<()> {
    let interface_cfg = build_interface_configuration(netmap, state, cfg, routes_cfg)?;
    apply_interface_configuration(&interface_cfg, cfg.backend)
}

pub async fn remove(interface: &str, backend: Backend) -> Result<()> {
    if !is_lightscale_interface(interface) {
        return Err(anyhow!(
            "refusing to remove non-lightscale interface '{}': must start with '{}'",
            interface,
            INTERFACE_PREFIX
        ));
    }
    remove_interface_configuration(interface, backend)
}

pub fn probe_peers(netmap: &NetMap, timeout_seconds: u64) -> Result<()> {
    let mut v4_socket: Option<std::net::UdpSocket> = None;
    let mut v6_socket: Option<std::net::UdpSocket> = None;
    for peer in &netmap.peers {
        let mut probed = false;
        for endpoint in &peer.endpoints {
            match endpoint.parse::<SocketAddr>() {
                Ok(addr) => {
                    probe_addr(&mut v4_socket, &mut v6_socket, addr, timeout_seconds);
                    probed = true;
                }
                Err(_) => {
                    eprintln!(
                        "probe skipped invalid endpoint {} for {}",
                        endpoint, peer.id
                    );
                }
            }
        }
        if !probed {
            probe_ip(&mut v4_socket, &mut v6_socket, &peer.ipv4, timeout_seconds);
            probe_ip(&mut v4_socket, &mut v6_socket, &peer.ipv6, timeout_seconds);
        }
    }
    Ok(())
}

pub fn refresh_peer_endpoints(
    _netmap: &NetMap,
    _cfg: &WgConfig,
    _tracker: &mut EndpointTracker,
    _relay_endpoints: &HashMap<String, SocketAddr>,
    _stale_after: Duration,
    _max_rotations: usize,
    _relay_reprobe_after: Duration,
) -> Result<()> {
    // TODO: implement endpoint churn handling for non-linux data planes.
    Ok(())
}

fn build_interface_configuration(
    netmap: &NetMap,
    state: &ClientState,
    cfg: &WgConfig,
    routes_cfg: Option<&routes::RouteApplyConfig>,
) -> Result<InterfaceConfiguration> {
    let _private_key: DgKey = state
        .wg_private_key
        .as_str()
        .try_into()
        .context("invalid wireguard private key")?;

    let v4 = parse_host_ip_mask(&state.ipv4, 32, "ipv4")?;
    let v6 = parse_host_ip_mask(&state.ipv6, 128, "ipv6")?;

    let selected_exit_ids = routes_cfg
        .map(|cfg| routes::selected_exit_peer_ids(netmap, cfg))
        .unwrap_or_default();

    let mut peers = Vec::new();
    for peer in &netmap.peers {
        let key: DgKey = peer
            .wg_public_key
            .as_str()
            .try_into()
            .with_context(|| format!("invalid peer public key {}", peer.id))?;

        let mut allowed: HashSet<IpAddrMask> = HashSet::new();
        allowed.insert(parse_host_ip_mask(&peer.ipv4, 32, "peer ipv4")?);
        allowed.insert(parse_host_ip_mask(&peer.ipv6, 128, "peer ipv6")?);

        let allow_exit = selected_exit_ids.contains(&peer.id);
        for route in &peer.routes {
            if !route.enabled {
                continue;
            }
            let net = match route_allowed_prefix(route) {
                Ok(prefix) => prefix,
                Err(err) => {
                    eprintln!(
                        "skipping allowed ip for route {} on peer {}: {}",
                        route.prefix, peer.id, err
                    );
                    continue;
                }
            };
            match route.kind {
                RouteKind::Subnet => {
                    allowed.insert(IpAddrMask::new(net.addr(), net.prefix_len()));
                }
                RouteKind::Exit => {
                    if allow_exit {
                        allowed.insert(IpAddrMask::new(net.addr(), net.prefix_len()));
                    }
                }
            }
        }

        let mut peer_cfg = DgPeer::new(key);
        peer_cfg.persistent_keepalive_interval = Some(25);
        peer_cfg.set_allowed_ips(allowed.into_iter().collect());

        if let Some(endpoint) = peer
            .endpoints
            .iter()
            .find_map(|endpoint| endpoint.parse::<SocketAddr>().ok())
        {
            peer_cfg.endpoint = Some(endpoint);
        } else if !peer.endpoints.is_empty() {
            eprintln!("no valid endpoint for peer {}", peer.id);
        }

        peers.push(peer_cfg);
    }

    Ok(InterfaceConfiguration {
        name: cfg.interface.clone(),
        prvkey: state.wg_private_key.clone(),
        addresses: vec![v4, v6],
        port: cfg.listen_port,
        peers,
        mtu: None,
        fwmark: None,
    })
}

#[cfg(target_os = "macos")]
fn apply_interface_configuration(config: &InterfaceConfiguration, backend: Backend) -> Result<()> {
    if matches!(backend, Backend::Kernel) {
        eprintln!("kernel backend is not available on macOS; using userspace backend");
    }
    let mut api = WGApi::<Userspace>::new(config.name.clone())
        .context("failed to initialize macOS WireGuard API")?;
    api.create_interface()
        .context("failed to create/open WireGuard interface")?;
    api.configure_interface(config)
        .context("failed to configure WireGuard interface")?;
    api.configure_peer_routing(&config.peers)
        .context("failed to configure peer routes")?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_interface_configuration(config: &InterfaceConfiguration, backend: Backend) -> Result<()> {
    if matches!(backend, Backend::Boringtun) {
        eprintln!("boringtun backend is not available on Windows; using kernel backend");
    }
    let mut api = WGApi::<Kernel>::new(config.name.clone())
        .context("failed to initialize Windows WireGuard API")?;
    api.create_interface()
        .context("failed to create/open WireGuard adapter")?;
    api.configure_interface(config)
        .context("failed to configure WireGuard adapter")?;
    api.configure_peer_routing(&config.peers)
        .context("failed to configure peer routes")?;
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn apply_interface_configuration(_config: &InterfaceConfiguration, _backend: Backend) -> Result<()> {
    Err(anyhow!(
        "portable WireGuard data plane is only implemented for macOS and Windows"
    ))
}

#[cfg(target_os = "macos")]
fn remove_interface_configuration(interface: &str, _backend: Backend) -> Result<()> {
    let api = WGApi::<Userspace>::new(interface.to_string())
        .context("failed to initialize macOS WireGuard API")?;
    api.remove_interface()
        .context("failed to remove macOS WireGuard interface")
}

#[cfg(target_os = "windows")]
fn remove_interface_configuration(interface: &str, _backend: Backend) -> Result<()> {
    let mut api = WGApi::<Kernel>::new(interface.to_string())
        .context("failed to initialize Windows WireGuard API")?;
    // defguard currently exposes adapter close via remove_interface; removal is best-effort.
    api.remove_interface()
        .context("failed to close Windows WireGuard adapter")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn remove_interface_configuration(_interface: &str, _backend: Backend) -> Result<()> {
    Err(anyhow!(
        "portable WireGuard data plane is only implemented for macOS and Windows"
    ))
}

fn route_allowed_prefix(route: &Route) -> Result<IpNet> {
    let Some(mapped) = route.mapped_prefix.as_deref() else {
        return route.prefix.parse().context("invalid route prefix");
    };
    let real_net: IpNet = route.prefix.parse().context("invalid route prefix")?;
    let mapped_net: IpNet = mapped.parse().context("invalid mapped prefix")?;
    let real_v4 = matches!(real_net, IpNet::V4(_));
    let mapped_v4 = matches!(mapped_net, IpNet::V4(_));
    if real_v4 != mapped_v4 {
        return Err(anyhow!("mapped prefix ip version mismatch"));
    }
    if real_net.prefix_len() != mapped_net.prefix_len() {
        return Err(anyhow!("mapped prefix length mismatch"));
    }
    Ok(mapped_net)
}

fn parse_host_ip_mask(address: &str, prefix: u8, label: &str) -> Result<IpAddrMask> {
    let ip: IpAddr = address
        .parse()
        .with_context(|| format!("invalid {}", label))?;
    Ok(IpAddrMask::new(ip, prefix))
}

fn probe_ip(
    v4_socket: &mut Option<std::net::UdpSocket>,
    v6_socket: &mut Option<std::net::UdpSocket>,
    address: &str,
    timeout_seconds: u64,
) {
    let ip: IpAddr = match address.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("probe failed for {} (invalid address)", address);
            return;
        }
    };
    let target = std::net::SocketAddr::new(ip, 9);
    probe_addr(v4_socket, v6_socket, target, timeout_seconds);
}

fn probe_addr(
    v4_socket: &mut Option<std::net::UdpSocket>,
    v6_socket: &mut Option<std::net::UdpSocket>,
    target: SocketAddr,
    timeout_seconds: u64,
) {
    let socket = match target {
        SocketAddr::V4(_) => {
            if v4_socket.is_none() {
                match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(sock) => {
                        let _ = sock
                            .set_write_timeout(Some(Duration::from_secs(timeout_seconds.max(1))));
                        *v4_socket = Some(sock);
                    }
                    Err(_) => {
                        eprintln!("probe failed for {} (udp bind)", target);
                        return;
                    }
                }
            }
            v4_socket
                .as_ref()
                .expect("v4 socket should be present after bind")
        }
        SocketAddr::V6(_) => {
            if v6_socket.is_none() {
                match std::net::UdpSocket::bind("[::]:0") {
                    Ok(sock) => {
                        let _ = sock
                            .set_write_timeout(Some(Duration::from_secs(timeout_seconds.max(1))));
                        *v6_socket = Some(sock);
                    }
                    Err(_) => {
                        eprintln!("probe failed for {} (udp bind)", target);
                        return;
                    }
                }
            }
            v6_socket
                .as_ref()
                .expect("v6 socket should be present after bind")
        }
    };
    if socket.send_to(b"lightscale-probe", target).is_err() {
        eprintln!("probe failed for {} (udp send)", target);
    }
}
