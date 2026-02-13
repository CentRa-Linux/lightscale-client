use crate::model::{NetMap, Route, RouteKind};
use crate::netlink::Netlink;
use crate::routes;
use crate::state::ClientState;
use anyhow::{anyhow, Context, Result};
use boringtun::device::{DeviceConfig, DeviceHandle};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use wireguard_control::{
    Backend as WgBackend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder,
};

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

static BORINGTUN_HANDLES: OnceLock<Mutex<HashMap<String, DeviceHandle>>> = OnceLock::new();

#[derive(Default)]
pub struct EndpointTracker {
    peers: HashMap<String, PeerEndpointState>,
}

#[derive(Default)]
struct PeerEndpointState {
    next_index: usize,
    rotations: usize,
    relay_active: bool,
}

pub async fn apply(
    netmap: &NetMap,
    state: &ClientState,
    cfg: &WgConfig,
    routes_cfg: Option<&routes::RouteApplyConfig>,
) -> Result<()> {
    let netlink = Netlink::new().await?;
    let index = match cfg.backend {
        Backend::Kernel => apply_kernel(netmap, state, cfg, routes_cfg, &netlink).await?,
        Backend::Boringtun => apply_boringtun(netmap, state, cfg, routes_cfg, &netlink).await?,
    };
    add_peer_routes(netmap, index, &netlink).await?;
    Ok(())
}

pub async fn remove(interface: &str, backend: Backend) -> Result<()> {
    let netlink = Netlink::new().await?;
    match backend {
        Backend::Kernel => {
            netlink.delete_link(interface).await?;
        }
        Backend::Boringtun => {
            stop_boringtun(interface);
            let socket_path = userspace_socket_path(interface);
            let _ = std::fs::remove_file(&socket_path);
            netlink.delete_link(interface).await?;
        }
    }
    Ok(())
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
                    eprintln!("probe skipped invalid endpoint {} for {}", endpoint, peer.id);
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

fn backend_for(backend: Backend) -> WgBackend {
    match backend {
        Backend::Kernel => WgBackend::Kernel,
        Backend::Boringtun => WgBackend::Userspace,
    }
}

pub fn refresh_peer_endpoints(
    netmap: &NetMap,
    cfg: &WgConfig,
    tracker: &mut EndpointTracker,
    relay_endpoints: &HashMap<String, SocketAddr>,
    stale_after: Duration,
    max_rotations: usize,
) -> Result<()> {
    let iface: InterfaceName = cfg
        .interface
        .parse()
        .context("invalid interface name")?;
    let backend = backend_for(cfg.backend);
    let device = Device::get(&iface, backend).context("wireguard device query failed")?;

    let mut peer_info = HashMap::new();
    for info in device.peers {
        peer_info.insert(info.config.public_key.to_base64(), info);
    }

    let max_rotations = max_rotations.max(1);
    let mut update = DeviceUpdate::new();
    let mut changed = false;
    let mut desired_endpoints: HashMap<String, SocketAddr> = HashMap::new();

    for peer in &netmap.peers {
        let endpoints: Vec<SocketAddr> = peer
            .endpoints
            .iter()
            .filter_map(|endpoint| endpoint.parse().ok())
            .collect();
        let info = peer_info.get(&peer.wg_public_key);
        let handshake_stale = match info.and_then(|info| info.stats.last_handshake_time) {
            Some(ts) => ts.elapsed().map(|age| age > stale_after).unwrap_or(true),
            None => true,
        };
        if !handshake_stale {
            let state = tracker.peers.entry(peer.id.clone()).or_default();
            state.rotations = 0;
            state.relay_active = false;
            continue;
        }

        let state = tracker.peers.entry(peer.id.clone()).or_default();
        let current_endpoint = info.and_then(|info| info.config.endpoint);
        let mut desired_endpoint = None;

        if state.relay_active {
            if let Some(relay) = relay_endpoints.get(&peer.id) {
                desired_endpoint = Some(*relay);
            }
        } else if !endpoints.is_empty() {
            let idx = state.next_index % endpoints.len();
            desired_endpoint = Some(endpoints[idx]);
            state.next_index = (idx + 1) % endpoints.len();
            state.rotations = state.rotations.saturating_add(1);
            if state.rotations >= max_rotations && relay_endpoints.contains_key(&peer.id) {
                state.relay_active = true;
                state.rotations = 0;
            }
        } else if let Some(relay) = relay_endpoints.get(&peer.id) {
            state.relay_active = true;
            state.rotations = 0;
            desired_endpoint = Some(*relay);
        }

        if let Some(desired) = desired_endpoint {
            if Some(desired) != current_endpoint {
                changed = true;
                if backend == WgBackend::Userspace {
                    desired_endpoints.insert(peer.id.clone(), desired);
                } else {
                    let peer_key = Key::from_base64(&peer.wg_public_key)
                        .with_context(|| format!("invalid peer public key {}", peer.id))?;
                    update = update.add_peer(
                        PeerConfigBuilder::new(&peer_key)
                            .set_endpoint(desired)
                            .set_persistent_keepalive_interval(25),
                    );
                }
            }
        }
    }

    if changed {
        if backend == WgBackend::Userspace {
            let mut full_update = DeviceUpdate::new().replace_peers();
            for peer in &netmap.peers {
                let info = peer_info.get(&peer.wg_public_key);
                let mut builder = if let Some(info) = info {
                    PeerConfigBuilder::from_peer_config(info.config.clone())
                } else {
                    build_peer_builder_from_netmap(peer)?
                };
                if let Some(desired) = desired_endpoints.get(&peer.id) {
                    builder = builder
                        .set_endpoint(*desired)
                        .set_persistent_keepalive_interval(25);
                }
                full_update = full_update.add_peer(builder);
            }
            full_update
                .apply(&iface, backend)
                .context("wireguard endpoint refresh failed")?;
        } else {
            update
                .apply(&iface, backend)
                .context("wireguard endpoint refresh failed")?;
        }
    }

    Ok(())
}

async fn apply_kernel(
    netmap: &NetMap,
    state: &ClientState,
    cfg: &WgConfig,
    routes_cfg: Option<&routes::RouteApplyConfig>,
    netlink: &Netlink,
) -> Result<u32> {
    apply_wireguard_config(netmap, state, cfg, routes_cfg, WgBackend::Kernel)?;
    let index = netlink
        .wait_for_link(&cfg.interface, Duration::from_secs(3))
        .await?;
    configure_addresses(netlink, index, state).await?;
    netlink.set_link_up(index).await?;
    Ok(index)
}

async fn apply_boringtun(
    netmap: &NetMap,
    state: &ClientState,
    cfg: &WgConfig,
    routes_cfg: Option<&routes::RouteApplyConfig>,
    netlink: &Netlink,
) -> Result<u32> {
    ensure_boringtun(&cfg.interface)?;
    wait_for_userspace_socket(&cfg.interface, Duration::from_secs(3)).await?;
    apply_wireguard_config(netmap, state, cfg, routes_cfg, WgBackend::Userspace)?;
    let index = netlink
        .wait_for_link(&cfg.interface, Duration::from_secs(3))
        .await?;
    configure_addresses(netlink, index, state).await?;
    netlink.set_link_up(index).await?;
    Ok(index)
}

async fn configure_addresses(
    netlink: &Netlink,
    index: u32,
    state: &ClientState,
) -> Result<()> {
    let ipv4 = parse_ip(&state.ipv4, "ipv4")?;
    netlink.replace_address(index, ipv4, 32).await?;
    let ipv6 = parse_ip(&state.ipv6, "ipv6")?;
    netlink.replace_address(index, ipv6, 128).await?;
    Ok(())
}

fn apply_wireguard_config(
    netmap: &NetMap,
    state: &ClientState,
    cfg: &WgConfig,
    routes_cfg: Option<&routes::RouteApplyConfig>,
    backend: WgBackend,
) -> Result<()> {
    let iface: InterfaceName = cfg
        .interface
        .parse()
        .context("invalid interface name")?;
    let update = build_device_update(netmap, state, cfg, routes_cfg)?;
    update
        .apply(&iface, backend)
        .context("wireguard config apply failed")?;
    Ok(())
}

fn build_device_update(
    netmap: &NetMap,
    state: &ClientState,
    cfg: &WgConfig,
    routes_cfg: Option<&routes::RouteApplyConfig>,
) -> Result<DeviceUpdate> {
    let private_key = Key::from_base64(&state.wg_private_key)
        .context("invalid wireguard private key")?;
    let mut update = DeviceUpdate::new()
        .set_private_key(private_key)
        .set_listen_port(cfg.listen_port)
        .replace_peers();
    let selected_exit_ids = routes_cfg
        .map(|cfg| routes::selected_exit_peer_ids(netmap, cfg))
        .unwrap_or_default();

    for peer in &netmap.peers {
        let peer_key =
            Key::from_base64(&peer.wg_public_key).context("invalid peer public key")?;
        let ipv4: IpAddr = peer.ipv4.parse().context("invalid peer ipv4")?;
        let ipv6: IpAddr = peer.ipv6.parse().context("invalid peer ipv6")?;
        let mut allowed: HashSet<IpNet> = HashSet::new();
        allowed.insert(IpNet::new(ipv4, 32).context("invalid peer ipv4 prefix")?);
        allowed.insert(IpNet::new(ipv6, 128).context("invalid peer ipv6 prefix")?);
        let allow_exit = selected_exit_ids.contains(&peer.id);
        for route in &peer.routes {
            if !route.enabled {
                continue;
            }
            let net = match route_allowed_prefix(route) {
                Ok(net) => net,
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
                    allowed.insert(net);
                }
                RouteKind::Exit => {
                    if allow_exit {
                        allowed.insert(net);
                    }
                }
            }
        }
        let mut builder = PeerConfigBuilder::new(&peer_key).replace_allowed_ips();
        for net in allowed {
            builder = add_allowed_ip(builder, net);
        }
        if let Some(addr) = peer
            .endpoints
            .iter()
            .find_map(|endpoint| endpoint.parse::<SocketAddr>().ok())
        {
            builder = builder
                .set_endpoint(addr)
                .set_persistent_keepalive_interval(25);
        } else if !peer.endpoints.is_empty() {
            eprintln!("no valid endpoint for peer {}", peer.id);
        }
        update = update.add_peer(builder);
    }

    Ok(update)
}

async fn add_peer_routes(netmap: &NetMap, index: u32, netlink: &Netlink) -> Result<()> {
    for peer in &netmap.peers {
        let ipv4: IpAddr = peer.ipv4.parse().context("invalid peer ipv4")?;
        let ipv6: IpAddr = peer.ipv6.parse().context("invalid peer ipv6")?;
        let v4 = IpNet::new(ipv4, 32).context("invalid peer ipv4 prefix")?;
        let v6 = IpNet::new(ipv6, 128).context("invalid peer ipv6 prefix")?;
        netlink.replace_route(v4, index).await?;
        netlink.replace_route(v6, index).await?;
    }
    Ok(())
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

fn add_allowed_ip(builder: PeerConfigBuilder, net: IpNet) -> PeerConfigBuilder {
    match net {
        IpNet::V4(v4) => builder.add_allowed_ip(IpAddr::V4(v4.network()), v4.prefix_len()),
        IpNet::V6(v6) => builder.add_allowed_ip(IpAddr::V6(v6.network()), v6.prefix_len()),
    }
}

fn build_peer_builder_from_netmap(peer: &crate::model::PeerInfo) -> Result<PeerConfigBuilder> {
    let peer_key = Key::from_base64(&peer.wg_public_key)
        .with_context(|| format!("invalid peer public key {}", peer.id))?;
    let ipv4: IpAddr = peer.ipv4.parse().context("invalid peer ipv4")?;
    let ipv6: IpAddr = peer.ipv6.parse().context("invalid peer ipv6")?;
    let mut allowed: HashSet<IpNet> = HashSet::new();
    allowed.insert(IpNet::new(ipv4, 32).context("invalid peer ipv4 prefix")?);
    allowed.insert(IpNet::new(ipv6, 128).context("invalid peer ipv6 prefix")?);
    for route in &peer.routes {
        if !route.enabled {
            continue;
        }
        if let RouteKind::Subnet = route.kind {
            if let Ok(net) = route_allowed_prefix(route) {
                allowed.insert(net);
            }
        }
    }
    let mut builder = PeerConfigBuilder::new(&peer_key).replace_allowed_ips();
    for net in allowed {
        builder = add_allowed_ip(builder, net);
    }
    if let Some(addr) = peer
        .endpoints
        .iter()
        .find_map(|endpoint| endpoint.parse::<SocketAddr>().ok())
    {
        builder = builder
            .set_endpoint(addr)
            .set_persistent_keepalive_interval(25);
    }
    Ok(builder)
}

fn ensure_boringtun(interface: &str) -> Result<()> {
    let handles = BORINGTUN_HANDLES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = handles.lock().unwrap();
    if map.contains_key(interface) {
        return Ok(());
    }
    let config = DeviceConfig::default();
    let handle = DeviceHandle::new(interface, config).context("boringtun init failed")?;
    map.insert(interface.to_string(), handle);
    Ok(())
}

fn stop_boringtun(interface: &str) {
    if let Some(handles) = BORINGTUN_HANDLES.get() {
        let mut map = handles.lock().unwrap();
        map.remove(interface);
    }
}

async fn wait_for_userspace_socket(interface: &str, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    let path = userspace_socket_path(interface);
    loop {
        if path.exists() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("userspace wg socket {} did not appear", path.display()));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn userspace_socket_path(interface: &str) -> PathBuf {
    Path::new("/var/run/wireguard").join(format!("{interface}.sock"))
}

fn parse_ip(address: &str, label: &str) -> Result<IpAddr> {
    let ip: IpAddr = address.parse().with_context(|| format!("invalid {}", label))?;
    match (label, ip) {
        ("ipv4", IpAddr::V4(_)) => Ok(ip),
        ("ipv6", IpAddr::V6(_)) => Ok(ip),
        _ => Err(anyhow!("unexpected {} address: {}", label, address)),
    }
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
                        let _ = sock.set_write_timeout(Some(Duration::from_secs(timeout_seconds.max(1))));
                        *v4_socket = Some(sock);
                    }
                    Err(_) => {
                        eprintln!("probe failed for {} (udp bind)", target);
                        return;
                    }
                }
            }
            v4_socket.as_ref().unwrap()
        }
        SocketAddr::V6(_) => {
            if v6_socket.is_none() {
                match std::net::UdpSocket::bind("[::]:0") {
                    Ok(sock) => {
                        let _ = sock.set_write_timeout(Some(Duration::from_secs(timeout_seconds.max(1))));
                        *v6_socket = Some(sock);
                    }
                    Err(_) => {
                        eprintln!("probe failed for {} (udp bind)", target);
                        return;
                    }
                }
            }
            v6_socket.as_ref().unwrap()
        }
    };
    if socket.send_to(b"lightscale-probe", target).is_err() {
        eprintln!("probe failed for {} (udp send)", target);
    }
}
