use crate::model::NetMap;
use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
#[cfg(target_os = "linux")]
use {
    std::ffi::CString,
    zbus::blocking::{Connection, Proxy},
};
#[cfg(target_os = "macos")]
use std::path::Path;

#[cfg(target_os = "macos")]
const MACOS_RESOLVER_DIR: &str = "/etc/resolver";
#[cfg(target_os = "macos")]
const MACOS_MANAGED_MARKER: &str = "# managed-by: lightscale-client";
#[cfg(target_os = "macos")]
const MACOS_INTERFACE_MARKER_PREFIX: &str = "# interface: ";

const DNS_TTL_SECONDS: u32 = 30;

pub fn spawn(addr: SocketAddr, netmap: NetMap) -> Result<Arc<Mutex<NetMap>>> {
    let state = Arc::new(Mutex::new(netmap));
    let state_task = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(err) = serve(addr, state_task).await {
            eprintln!("dns server stopped: {}", err);
        }
    });
    Ok(state)
}

pub async fn serve(addr: SocketAddr, state: Arc<Mutex<NetMap>>) -> Result<()> {
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("dns listen {} failed", addr))?;
    let mut buf = vec![0u8; 512];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let request = match Message::from_vec(&buf[..len]) {
            Ok(msg) => msg,
            Err(_) => continue,
        };
        let response = build_response(&request, &state)?;
        let out = response.to_vec()?;
        let _ = socket.send_to(&out, peer).await;
    }
}

pub fn apply_resolver(interface: &str, domain: &str, server: IpAddr) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        apply_resolver_resolved(interface, domain, server)
    }
    #[cfg(target_os = "macos")]
    {
        apply_resolver_macos(interface, domain, server)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (interface, domain, server);
        Err(anyhow!(
            "resolver integration is not implemented on this platform yet"
        ))
    }
}

pub fn clear_resolver(interface: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        clear_resolver_resolved(interface)
    }
    #[cfg(target_os = "macos")]
    {
        clear_resolver_macos(interface)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface;
        Err(anyhow!(
            "resolver integration is not implemented on this platform yet"
        ))
    }
}

#[cfg(target_os = "linux")]
fn apply_resolver_resolved(interface: &str, domain: &str, server: IpAddr) -> Result<()> {
    let ifindex = interface_index(interface)?;
    let conn = Connection::system().context("connect to system D-Bus failed")?;
    let manager = Proxy::new(
        &conn,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .context("build resolved manager proxy failed")?;

    let (family, bytes) = encode_ip(server);
    let dns_entries = vec![(family, bytes)];
    manager
        .call_method("SetLinkDNS", &(ifindex, dns_entries))
        .context("resolved SetLinkDNS failed")?;

    let normalized_domain = domain.trim_end_matches('.');
    if !normalized_domain.is_empty() {
        // Routing-only domain (equivalent to resolvectl's "~domain" behavior).
        let domains = vec![(normalized_domain.to_string(), true)];
        manager
            .call_method("SetLinkDomains", &(ifindex, domains))
            .context("resolved SetLinkDomains failed")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_resolver_resolved(interface: &str) -> Result<()> {
    let ifindex = interface_index(interface)?;
    let conn = Connection::system().context("connect to system D-Bus failed")?;
    let manager = Proxy::new(
        &conn,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .context("build resolved manager proxy failed")?;
    manager
        .call_method("RevertLink", &(ifindex,))
        .context("resolved RevertLink failed")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn interface_index(interface: &str) -> Result<i32> {
    let c_name =
        CString::new(interface).map_err(|_| anyhow!("interface name contains invalid null byte"))?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(anyhow!(
            "failed to resolve interface index for {}: {}",
            interface,
            std::io::Error::last_os_error()
        ));
    }
    i32::try_from(idx).map_err(|_| anyhow!("interface index overflow for {}", interface))
}

#[cfg(target_os = "linux")]
fn encode_ip(ip: IpAddr) -> (i32, Vec<u8>) {
    match ip {
        IpAddr::V4(addr) => (libc::AF_INET, addr.octets().to_vec()),
        IpAddr::V6(addr) => (libc::AF_INET6, addr.octets().to_vec()),
    }
}

#[cfg(target_os = "macos")]
fn apply_resolver_macos(interface: &str, domain: &str, server: IpAddr) -> Result<()> {
    let domain = normalize_macos_domain(domain)?;
    let dir = Path::new(MACOS_RESOLVER_DIR);
    std::fs::create_dir_all(dir).context("failed to create /etc/resolver directory")?;
    let path = dir.join(&domain);
    let content = format!(
        "{managed}\n{iface_prefix}{iface}\nnameserver {server}\n",
        managed = MACOS_MANAGED_MARKER,
        iface_prefix = MACOS_INTERFACE_MARKER_PREFIX,
        iface = interface,
        server = server
    );
    std::fs::write(&path, content)
        .with_context(|| format!("failed to write resolver file {}", path.display()))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_resolver_macos(interface: &str) -> Result<()> {
    let dir = Path::new(MACOS_RESOLVER_DIR);
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).context("failed to list /etc/resolver"),
    };
    let interface_marker = format!("{prefix}{iface}", prefix = MACOS_INTERFACE_MARKER_PREFIX, iface = interface);
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let has_managed_marker = content
            .lines()
            .any(|line| line.trim() == MACOS_MANAGED_MARKER);
        let has_interface_marker = content
            .lines()
            .any(|line| line.trim() == interface_marker);
        if has_managed_marker && has_interface_marker {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to remove resolver file {}", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn normalize_macos_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    if domain.is_empty() {
        return Err(anyhow!("dns domain cannot be empty"));
    }
    if domain.contains('/') || domain.contains('\\') {
        return Err(anyhow!("dns domain contains invalid path separator"));
    }
    Ok(domain)
}

fn build_response(request: &Message, state: &Arc<Mutex<NetMap>>) -> Result<Message> {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(false);

    let netmap = state.lock().map_err(|_| anyhow!("dns state poisoned"))?;
    let domain = normalize_name(&netmap.network.dns_domain);
    let mut answered = false;
    let mut any_within_domain = false;
    for query in request.queries() {
        response.add_query(query.clone());
        let name = normalize_name(&query.name().to_ascii());
        let within_domain = name == domain || name.ends_with(&format!(".{}", domain));
        if within_domain {
            any_within_domain = true;
        }
        let Some(addrs) = lookup_name(&netmap, &name) else {
            continue;
        };
        for addr in addrs {
            match (query.query_type(), addr) {
                (RecordType::A, IpAddr::V4(_)) => {
                    response.add_answer(build_record(query.name(), addr));
                    answered = true;
                }
                (RecordType::AAAA, IpAddr::V6(_)) => {
                    response.add_answer(build_record(query.name(), addr));
                    answered = true;
                }
                (RecordType::ANY, IpAddr::V4(_)) => {
                    response.add_answer(build_record(query.name(), addr));
                    answered = true;
                }
                (RecordType::ANY, IpAddr::V6(_)) => {
                    response.add_answer(build_record(query.name(), addr));
                    answered = true;
                }
                _ => {}
            }
        }
    }
    let response_code = if answered {
        ResponseCode::NoError
    } else if any_within_domain {
        ResponseCode::NXDomain
    } else {
        ResponseCode::Refused
    };
    response.set_response_code(response_code);
    response.set_authoritative(true);
    Ok(response)
}

fn build_record(name: &Name, addr: IpAddr) -> Record {
    let rdata = match addr {
        IpAddr::V4(v4) => RData::A(A(v4)),
        IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
    };
    Record::from_rdata(name.clone(), DNS_TTL_SECONDS, rdata)
}

fn lookup_name(netmap: &NetMap, name: &str) -> Option<Vec<IpAddr>> {
    let node_name = normalize_name(&netmap.node.dns_name);
    if name == node_name {
        return Some(vec![
            netmap.node.ipv4.parse().ok()?,
            netmap.node.ipv6.parse().ok()?,
        ]);
    }
    for peer in &netmap.peers {
        let peer_name = normalize_name(&peer.dns_name);
        if name == peer_name {
            return Some(vec![peer.ipv4.parse().ok()?, peer.ipv6.parse().ok()?]);
        }
    }
    None
}

fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}
