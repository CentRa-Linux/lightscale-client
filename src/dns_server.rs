use crate::model::NetMap;
use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

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
    let domain = domain.trim_end_matches('.');
    let routed_domain = format!("~{}", domain);
    run_resolvectl(&["dns", interface, &server.to_string()])?;
    run_resolvectl(&["domain", interface, &routed_domain])?;
    Ok(())
}

fn run_resolvectl(args: &[&str]) -> Result<()> {
    let output = std::process::Command::new("resolvectl").args(args).output();
    let output = match output {
        Ok(output) => output,
        Err(err) => return Err(anyhow!("resolvectl failed: {}", err)),
    };
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(anyhow!("resolvectl failed: {}", stderr.trim()))
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
        let within_domain =
            name == domain || name.ends_with(&format!(".{}", domain));
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
            return Some(vec![
                peer.ipv4.parse().ok()?,
                peer.ipv6.parse().ok()?,
            ]);
        }
    }
    None
}

fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}
