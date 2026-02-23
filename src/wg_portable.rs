use crate::model::{NetMap, Route, RouteKind};
use crate::routes;
use crate::state::ClientState;
use anyhow::{anyhow, Context, Result};
use defguard_wireguard_rs::key::Key as DgKey;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer as DgPeer;
#[cfg(target_os = "windows")]
use defguard_wireguard_rs::Kernel;
#[cfg(target_os = "macos")]
use defguard_wireguard_rs::Userspace;
use defguard_wireguard_rs::{InterfaceConfiguration, WGApi, WireguardInterfaceApi};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

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
pub struct EndpointTracker {
    peers: HashMap<String, PeerEndpointState>,
}

#[derive(Default)]
struct PeerEndpointState {
    next_index: usize,
    rotations: usize,
    relay_active: bool,
    last_direct_probe_at: Option<Instant>,
}

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
    netmap: &NetMap,
    cfg: &WgConfig,
    tracker: &mut EndpointTracker,
    relay_endpoints: &HashMap<String, SocketAddr>,
    stale_after: Duration,
    max_rotations: usize,
    relay_reprobe_after: Duration,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        refresh_peer_endpoints_macos(
            netmap,
            cfg,
            tracker,
            relay_endpoints,
            stale_after,
            max_rotations,
            relay_reprobe_after,
        )
    }
    #[cfg(target_os = "windows")]
    {
        refresh_peer_endpoints_windows(
            netmap,
            cfg,
            tracker,
            relay_endpoints,
            stale_after,
            max_rotations,
            relay_reprobe_after,
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (
            netmap,
            cfg,
            tracker,
            relay_endpoints,
            stale_after,
            max_rotations,
            relay_reprobe_after,
        );
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn refresh_peer_endpoints_windows(
    netmap: &NetMap,
    cfg: &WgConfig,
    tracker: &mut EndpointTracker,
    relay_endpoints: &HashMap<String, SocketAddr>,
    stale_after: Duration,
    max_rotations: usize,
    relay_reprobe_after: Duration,
) -> Result<()> {
    let api = WGApi::<Kernel>::new(cfg.interface.clone())
        .context("failed to initialize Windows WireGuard API")?;
    let host = api
        .read_interface_data()
        .context("failed to read Windows WireGuard interface data")?;
    let private_key = host.private_key.clone().ok_or_else(|| {
        anyhow!("windows endpoint refresh requires adapter private key in interface state")
    })?;

    let mut peer_info: HashMap<String, DgPeer> = HashMap::new();
    for (key, peer) in host.peers {
        peer_info.insert(key.to_string(), peer);
    }

    let max_rotations = max_rotations.max(1);
    let mut desired_updates: Vec<(String, SocketAddr, Option<SocketAddr>)> = Vec::new();

    for peer in &netmap.peers {
        let endpoints: Vec<SocketAddr> = peer
            .endpoints
            .iter()
            .filter_map(|endpoint| endpoint.parse().ok())
            .collect();
        let info = peer_info.get(&peer.wg_public_key);
        let handshake_stale = match info.and_then(|info| info.last_handshake) {
            Some(ts) => ts.elapsed().map(|age| age > stale_after).unwrap_or(true),
            None => true,
        };
        let state = tracker.peers.entry(peer.id.clone()).or_default();
        let relay_active_before = state.relay_active;
        let current_endpoint = info.and_then(|info| info.endpoint);
        let relay_endpoint = relay_endpoints.get(&peer.id).copied();
        let current_is_relay = relay_endpoint
            .map(|relay| Some(relay) == current_endpoint)
            .unwrap_or(false);

        if !handshake_stale {
            state.rotations = 0;
            if current_is_relay && !endpoints.is_empty() {
                let should_probe = state
                    .last_direct_probe_at
                    .map(|ts| ts.elapsed() >= relay_reprobe_after)
                    .unwrap_or(true);
                if should_probe {
                    let idx = state.next_index % endpoints.len();
                    let desired = endpoints[idx];
                    state.next_index = (idx + 1) % endpoints.len();
                    state.last_direct_probe_at = Some(Instant::now());
                    state.relay_active = false;
                    if Some(desired) != current_endpoint {
                        desired_updates.push((peer.id.clone(), desired, current_endpoint));
                    }
                    continue;
                }
                state.relay_active = true;
            } else {
                state.relay_active = false;
            }
            continue;
        }

        let mut desired_endpoint = None;

        if state.relay_active {
            if let Some(relay) = relay_endpoint {
                desired_endpoint = Some(relay);
            } else if !endpoints.is_empty() {
                let idx = state.next_index % endpoints.len();
                desired_endpoint = Some(endpoints[idx]);
                state.next_index = (idx + 1) % endpoints.len();
                state.relay_active = false;
            }
        } else if !endpoints.is_empty() {
            let idx = state.next_index % endpoints.len();
            desired_endpoint = Some(endpoints[idx]);
            state.next_index = (idx + 1) % endpoints.len();
            state.rotations = state.rotations.saturating_add(1);
            if state.rotations >= max_rotations && relay_endpoint.is_some() {
                eprintln!(
                    "endpoint refresh peer={} enabling relay fallback after {} rotation(s)",
                    peer.id, state.rotations
                );
                state.relay_active = true;
                state.rotations = 0;
                state.last_direct_probe_at = Some(Instant::now());
            }
        } else if let Some(relay) = relay_endpoint {
            eprintln!(
                "endpoint refresh peer={} using relay endpoint {} (no direct endpoints available)",
                peer.id, relay
            );
            state.relay_active = true;
            state.rotations = 0;
            state.last_direct_probe_at = Some(Instant::now());
            desired_endpoint = Some(relay);
        }

        if relay_active_before != state.relay_active {
            eprintln!(
                "endpoint refresh peer={} relay_active {} -> {}",
                peer.id, relay_active_before, state.relay_active
            );
        }

        if let Some(desired) = desired_endpoint {
            if Some(desired) != current_endpoint {
                desired_updates.push((peer.id.clone(), desired, current_endpoint));
            }
        }
    }

    if desired_updates.is_empty() {
        return Ok(());
    }

    for (peer_id, desired, current) in &desired_updates {
        eprintln!(
            "endpoint refresh peer={} update {} -> {}",
            peer_id,
            format_opt_endpoint(*current),
            desired
        );
    }

    for (peer_id, desired, _current) in &desired_updates {
        let Some(peer_meta) = netmap.peers.iter().find(|p| p.id == *peer_id) else {
            continue;
        };
        let Some(host_peer) = peer_info.get_mut(&peer_meta.wg_public_key) else {
            eprintln!(
                "endpoint refresh peer={} skipped update because adapter peer state is unavailable",
                peer_id
            );
            continue;
        };
        host_peer.endpoint = Some(*desired);
    }

    let interface_config = InterfaceConfiguration {
        name: cfg.interface.clone(),
        prvkey: private_key.to_string(),
        addresses: vec![
            parse_host_ip_mask(&netmap.node.ipv4, 32, "node ipv4")?,
            parse_host_ip_mask(&netmap.node.ipv6, 128, "node ipv6")?,
        ],
        port: host.listen_port,
        peers: peer_info.into_values().collect(),
        mtu: None,
        fwmark: None,
    };
    api.configure_interface(&interface_config)
        .with_context(|| {
            format!(
                "failed to configure Windows WireGuard interface during endpoint refresh for {}",
                cfg.interface
            )
        })?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn refresh_peer_endpoints_macos(
    netmap: &NetMap,
    cfg: &WgConfig,
    tracker: &mut EndpointTracker,
    relay_endpoints: &HashMap<String, SocketAddr>,
    stale_after: Duration,
    max_rotations: usize,
    relay_reprobe_after: Duration,
) -> Result<()> {
    let api = WGApi::<Userspace>::new(cfg.interface.clone())
        .context("failed to initialize macOS WireGuard API")?;
    let host = api
        .read_interface_data()
        .context("failed to read macOS WireGuard interface data")?;

    let mut peer_info: HashMap<String, DgPeer> = HashMap::new();
    for (key, peer) in host.peers {
        peer_info.insert(key.to_string(), peer);
    }

    let max_rotations = max_rotations.max(1);
    let mut desired_updates: Vec<(String, DgPeer, SocketAddr, Option<SocketAddr>)> = Vec::new();

    for peer in &netmap.peers {
        let endpoints: Vec<SocketAddr> = peer
            .endpoints
            .iter()
            .filter_map(|endpoint| endpoint.parse().ok())
            .collect();
        let info = peer_info.get(&peer.wg_public_key);
        let handshake_stale = match info.and_then(|info| info.last_handshake) {
            Some(ts) => ts.elapsed().map(|age| age > stale_after).unwrap_or(true),
            None => true,
        };
        let state = tracker.peers.entry(peer.id.clone()).or_default();
        let relay_active_before = state.relay_active;
        let current_endpoint = info.and_then(|info| info.endpoint);
        let relay_endpoint = relay_endpoints.get(&peer.id).copied();
        let current_is_relay = relay_endpoint
            .map(|relay| Some(relay) == current_endpoint)
            .unwrap_or(false);

        if !handshake_stale {
            state.rotations = 0;
            if current_is_relay && !endpoints.is_empty() {
                let should_probe = state
                    .last_direct_probe_at
                    .map(|ts| ts.elapsed() >= relay_reprobe_after)
                    .unwrap_or(true);
                if should_probe {
                    let idx = state.next_index % endpoints.len();
                    let desired = endpoints[idx];
                    state.next_index = (idx + 1) % endpoints.len();
                    state.last_direct_probe_at = Some(Instant::now());
                    state.relay_active = false;
                    if Some(desired) != current_endpoint {
                        if let Some(updated_peer) = info.cloned().map(|mut p| {
                            p.endpoint = Some(desired);
                            p
                        }) {
                            desired_updates.push((
                                peer.id.clone(),
                                updated_peer,
                                desired,
                                current_endpoint,
                            ));
                        } else {
                            eprintln!(
                                "endpoint refresh peer={} skipped direct reprobe update because peer state is unavailable",
                                peer.id
                            );
                        }
                    }
                    continue;
                }
                state.relay_active = true;
            } else {
                state.relay_active = false;
            }
            continue;
        }

        let mut desired_endpoint = None;

        if state.relay_active {
            if let Some(relay) = relay_endpoint {
                desired_endpoint = Some(relay);
            } else if !endpoints.is_empty() {
                let idx = state.next_index % endpoints.len();
                desired_endpoint = Some(endpoints[idx]);
                state.next_index = (idx + 1) % endpoints.len();
                state.relay_active = false;
            }
        } else if !endpoints.is_empty() {
            let idx = state.next_index % endpoints.len();
            desired_endpoint = Some(endpoints[idx]);
            state.next_index = (idx + 1) % endpoints.len();
            state.rotations = state.rotations.saturating_add(1);
            if state.rotations >= max_rotations && relay_endpoint.is_some() {
                eprintln!(
                    "endpoint refresh peer={} enabling relay fallback after {} rotation(s)",
                    peer.id, state.rotations
                );
                state.relay_active = true;
                state.rotations = 0;
                state.last_direct_probe_at = Some(Instant::now());
            }
        } else if let Some(relay) = relay_endpoint {
            eprintln!(
                "endpoint refresh peer={} using relay endpoint {} (no direct endpoints available)",
                peer.id, relay
            );
            state.relay_active = true;
            state.rotations = 0;
            state.last_direct_probe_at = Some(Instant::now());
            desired_endpoint = Some(relay);
        }

        if relay_active_before != state.relay_active {
            eprintln!(
                "endpoint refresh peer={} relay_active {} -> {}",
                peer.id, relay_active_before, state.relay_active
            );
        }

        if let Some(desired) = desired_endpoint {
            if Some(desired) != current_endpoint {
                if let Some(updated_peer) = info.cloned().map(|mut p| {
                    p.endpoint = Some(desired);
                    p
                }) {
                    desired_updates.push((
                        peer.id.clone(),
                        updated_peer,
                        desired,
                        current_endpoint,
                    ));
                } else {
                    eprintln!(
                        "endpoint refresh peer={} skipped endpoint update because peer state is unavailable",
                        peer.id
                    );
                }
            }
        }
    }

    for (peer_id, updated_peer, desired, current) in desired_updates {
        eprintln!(
            "endpoint refresh peer={} update {} -> {}",
            peer_id,
            format_opt_endpoint(current),
            desired
        );
        api.configure_peer(&updated_peer).with_context(|| {
            format!(
                "failed to configure macOS peer endpoint refresh for peer {}",
                peer_id
            )
        })?;
    }

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
fn apply_interface_configuration(
    _config: &InterfaceConfiguration,
    _backend: Backend,
) -> Result<()> {
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

fn format_opt_endpoint(endpoint: Option<SocketAddr>) -> String {
    endpoint
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "<none>".to_string())
}
