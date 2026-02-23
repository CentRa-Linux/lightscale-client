use crate::model::{NetMap, Route, RouteKind};
use crate::netlink::{Netlink, RouteEntry};
use anyhow::{anyhow, Result};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};

pub struct RouteApplyConfig {
    pub interface: String,
    pub accept_exit_node: bool,
    pub exit_node_id: Option<String>,
    pub exit_node_name: Option<String>,
    pub exit_node_policy: ExitNodePolicy,
    pub exit_node_tag: Option<String>,
    pub exit_node_metric_base: u32,
    pub exit_node_uid_range: Option<UidRange>,
    pub allow_conflicts: bool,
    pub route_table: Option<u32>,
    pub route_rule_priority: u32,
    pub exit_rule_priority: u32,
    pub exit_uid_rule_priority: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct UidRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum ExitNodePolicy {
    First,
    Latest,
    Multi,
}

pub async fn apply_advertised_routes(netmap: &NetMap, cfg: &RouteApplyConfig) -> Result<()> {
    let netlink = Netlink::new().await?;
    let interface_index = netlink
        .link_index(&cfg.interface)
        .await?
        .ok_or_else(|| anyhow!("interface {} not found", cfg.interface))?;
    let existing_routes = netlink.list_routes().await?;
    let selected_exit_peers = select_exit_peers(netmap, cfg);
    let selected_exit_ids: HashSet<String> = selected_exit_peers
        .iter()
        .map(|peer| peer.peer_id.clone())
        .collect();
    let selected_exit_metrics: HashMap<String, u32> = selected_exit_peers
        .iter()
        .filter_map(|peer| peer.metric.map(|metric| (peer.peer_id.clone(), metric)))
        .collect();
    let exit_requested = cfg.exit_node_id.is_some() || cfg.exit_node_name.is_some();
    let tag_filtered = cfg.exit_node_tag.is_some();
    if exit_requested && selected_exit_peers.is_empty() {
        eprintln!("requested exit node not found; skipping exit routes");
    }
    if tag_filtered && selected_exit_peers.is_empty() {
        eprintln!("exit node tag filter matched no peers; skipping exit routes");
    }
    let allow_exit_routes = if exit_requested || tag_filtered {
        !selected_exit_peers.is_empty()
    } else {
        true
    };
    let allow_multiple_exit = matches!(cfg.exit_node_policy, ExitNodePolicy::Multi);
    let mut exit_v4_applied = false;
    let mut exit_v6_applied = false;
    let mut conflict_count = 0;
    let mut skipped_exit = false;
    let mut applied_routes: Vec<IpNet> = Vec::new();
    let mut exit_uid_rule_v4 = false;
    let mut exit_uid_rule_v6 = false;

    for peer in &netmap.peers {
        let is_exit_peer = selected_exit_ids.is_empty() || selected_exit_ids.contains(&peer.id);
        let exit_metric = selected_exit_metrics.get(&peer.id).cloned();
        for route in &peer.routes {
            if !route.enabled {
                continue;
            }
            let apply_prefix = match route_apply_prefix(route) {
                Ok(prefix) => prefix,
                Err(err) => {
                    eprintln!(
                        "skipping route {} for peer {}: {}",
                        route.prefix, peer.id, err
                    );
                    continue;
                }
            };
            match route.kind {
                RouteKind::Subnet => {
                    if route_conflicts(apply_prefix, &existing_routes, interface_index)
                        || route_conflicts_with_applied(apply_prefix, &applied_routes)
                    {
                        conflict_count += 1;
                        if !cfg.allow_conflicts {
                            continue;
                        }
                    }
                    let net = apply_route(
                        apply_prefix,
                        interface_index,
                        &netlink,
                        None,
                        cfg.route_table,
                    )
                    .await?;
                    applied_routes.push(net);
                    if let Some(table) = cfg.route_table {
                        netlink
                            .add_rule_for_prefix(net, table, cfg.route_rule_priority)
                            .await?;
                    }
                }
                RouteKind::Exit => {
                    if !cfg.accept_exit_node || !allow_exit_routes {
                        continue;
                    }
                    if !is_exit_peer {
                        skipped_exit = true;
                        continue;
                    }
                    if is_ipv6(apply_prefix) {
                        if exit_v6_applied && !allow_multiple_exit {
                            continue;
                        }
                        let net = apply_route(
                            apply_prefix,
                            interface_index,
                            &netlink,
                            exit_metric,
                            cfg.route_table,
                        )
                        .await?;
                        applied_routes.push(net);
                        exit_v6_applied = true;
                        if let Some(table) = cfg.route_table {
                            if let Some(uid_range) = cfg.exit_node_uid_range {
                                if !exit_uid_rule_v6 {
                                    netlink
                                        .add_uid_rule_v6(
                                            table,
                                            cfg.exit_uid_rule_priority,
                                            uid_range.start,
                                            uid_range.end,
                                        )
                                        .await?;
                                    exit_uid_rule_v6 = true;
                                }
                            } else {
                                netlink
                                    .add_rule_for_prefix(net, table, cfg.exit_rule_priority)
                                    .await?;
                            }
                        }
                    } else {
                        if exit_v4_applied && !allow_multiple_exit {
                            continue;
                        }
                        let net = apply_route(
                            apply_prefix,
                            interface_index,
                            &netlink,
                            exit_metric,
                            cfg.route_table,
                        )
                        .await?;
                        applied_routes.push(net);
                        exit_v4_applied = true;
                        if let Some(table) = cfg.route_table {
                            if let Some(uid_range) = cfg.exit_node_uid_range {
                                if !exit_uid_rule_v4 {
                                    netlink
                                        .add_uid_rule_v4(
                                            table,
                                            cfg.exit_uid_rule_priority,
                                            uid_range.start,
                                            uid_range.end,
                                        )
                                        .await?;
                                    exit_uid_rule_v4 = true;
                                }
                            } else {
                                netlink
                                    .add_rule_for_prefix(net, table, cfg.exit_rule_priority)
                                    .await?;
                            }
                        }
                    }
                }
            }
        }
    }

    if conflict_count > 0 {
        eprintln!(
            "skipped {} conflicting route(s) (use --allow-route-conflicts to force)",
            conflict_count
        );
    }
    if skipped_exit {
        eprintln!("exit node selection active; routes from other exit nodes were skipped");
    }

    Ok(())
}

pub fn selected_exit_peer_ids(netmap: &NetMap, cfg: &RouteApplyConfig) -> HashSet<String> {
    if !cfg.accept_exit_node {
        return HashSet::new();
    }
    let selected = select_exit_peers(netmap, cfg);
    let exit_requested = cfg.exit_node_id.is_some() || cfg.exit_node_name.is_some();
    let tag_filtered = cfg.exit_node_tag.is_some();
    let allow_exit_routes = if exit_requested || tag_filtered {
        !selected.is_empty()
    } else {
        true
    };
    if !allow_exit_routes {
        return HashSet::new();
    }
    selected.into_iter().map(|peer| peer.peer_id).collect()
}

fn route_apply_prefix(route: &Route) -> Result<&str> {
    let Some(mapped) = route.mapped_prefix.as_deref() else {
        return Ok(&route.prefix);
    };
    let real_net: IpNet = route.prefix.parse()?;
    let mapped_net: IpNet = mapped.parse()?;
    let real_v4 = matches!(real_net, IpNet::V4(_));
    let mapped_v4 = matches!(mapped_net, IpNet::V4(_));
    if real_v4 != mapped_v4 {
        return Err(anyhow!("mapped prefix ip version mismatch"));
    }
    if real_net.prefix_len() != mapped_net.prefix_len() {
        return Err(anyhow!("mapped prefix length mismatch"));
    }
    Ok(mapped)
}

struct ExitPeerSelection {
    peer_id: String,
    metric: Option<u32>,
}

fn select_exit_peers(netmap: &NetMap, cfg: &RouteApplyConfig) -> Vec<ExitPeerSelection> {
    let mut candidates: Vec<&crate::model::PeerInfo> = netmap
        .peers
        .iter()
        .filter(|peer| {
            peer.routes
                .iter()
                .any(|route| matches!(route.kind, RouteKind::Exit))
        })
        .collect();

    if let Some(tag) = cfg.exit_node_tag.as_ref() {
        candidates.retain(|peer| peer.tags.iter().any(|peer_tag| peer_tag == tag));
    }

    if let Some(id) = cfg.exit_node_id.as_ref() {
        return candidates
            .into_iter()
            .find(|peer| &peer.id == id)
            .map(|peer| {
                vec![ExitPeerSelection {
                    peer_id: peer.id.clone(),
                    metric: None,
                }]
            })
            .unwrap_or_default();
    }

    if let Some(name) = cfg.exit_node_name.as_ref() {
        return candidates
            .into_iter()
            .find(|peer| peer.name == *name)
            .map(|peer| {
                vec![ExitPeerSelection {
                    peer_id: peer.id.clone(),
                    metric: None,
                }]
            })
            .unwrap_or_default();
    }

    match cfg.exit_node_policy {
        ExitNodePolicy::Latest => {
            candidates.sort_by_key(|peer| peer.last_seen);
            candidates
                .last()
                .map(|peer| ExitPeerSelection {
                    peer_id: peer.id.clone(),
                    metric: None,
                })
                .into_iter()
                .collect()
        }
        ExitNodePolicy::Multi => candidates
            .into_iter()
            .enumerate()
            .map(|(idx, peer)| ExitPeerSelection {
                peer_id: peer.id.clone(),
                metric: Some(cfg.exit_node_metric_base.saturating_add(idx as u32)),
            })
            .collect(),
        ExitNodePolicy::First => candidates
            .into_iter()
            .next()
            .map(|peer| ExitPeerSelection {
                peer_id: peer.id.clone(),
                metric: None,
            })
            .into_iter()
            .collect(),
    }
}

async fn apply_route(
    prefix: &str,
    interface_index: u32,
    netlink: &Netlink,
    metric: Option<u32>,
    table: Option<u32>,
) -> Result<IpNet> {
    let net: IpNet = prefix.parse()?;
    match table {
        Some(table) => {
            netlink
                .replace_route_with_metric_table(net, interface_index, metric, table)
                .await?;
        }
        None => {
            netlink
                .replace_route_with_metric(net, interface_index, metric)
                .await?;
        }
    }
    Ok(net)
}

fn route_conflicts(prefix: &str, existing: &[RouteEntry], interface_index: u32) -> bool {
    let Ok(net) = prefix.parse::<IpNet>() else {
        return false;
    };
    existing.iter().any(|route| {
        if route.oif == Some(interface_index) {
            return false;
        }
        if route.prefix.prefix_len() == 0 {
            return false;
        }
        nets_overlap(&net, &route.prefix)
    })
}

fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    match (a, b) {
        (IpNet::V4(a4), IpNet::V4(b4)) => ranges_overlap(v4_range(a4), v4_range(b4)),
        (IpNet::V6(a6), IpNet::V6(b6)) => ranges_overlap(v6_range(a6), v6_range(b6)),
        _ => false,
    }
}

fn v4_range(net: &ipnet::Ipv4Net) -> (u64, u64) {
    let base = u64::from(u32::from(net.network()));
    let host_bits = 32u32.saturating_sub(net.prefix_len() as u32);
    let end = if host_bits == 32 {
        u64::from(u32::MAX)
    } else {
        base + ((1u64 << host_bits) - 1)
    };
    (base, end)
}

fn v6_range(net: &ipnet::Ipv6Net) -> (u128, u128) {
    let base = u128::from(net.network());
    let host_bits = 128u32.saturating_sub(net.prefix_len() as u32);
    let end = if host_bits == 128 {
        u128::MAX
    } else {
        base + ((1u128 << host_bits) - 1)
    };
    (base, end)
}

fn ranges_overlap<T: Ord>(a: (T, T), b: (T, T)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

fn route_conflicts_with_applied(prefix: &str, applied: &[IpNet]) -> bool {
    let Ok(net) = prefix.parse::<IpNet>() else {
        return false;
    };
    applied.iter().any(|other| nets_overlap(&net, other))
}

fn is_ipv6(prefix: &str) -> bool {
    prefix.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlaps_detected_for_subnets() {
        let a: IpNet = "10.0.0.0/24".parse().unwrap();
        let b: IpNet = "10.0.0.128/25".parse().unwrap();
        assert!(nets_overlap(&a, &b));
    }

    #[test]
    fn applied_conflict_detects_overlap() {
        let applied: Vec<IpNet> = vec!["10.1.0.0/24".parse().unwrap()];
        assert!(route_conflicts_with_applied("10.1.0.128/25", &applied));
    }
}
