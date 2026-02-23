use crate::firewall;
use crate::netlink::{InterfaceAddress, Netlink, RouteEntry};
use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub async fn resolve_out_interface(out_interface: Option<String>) -> Result<String> {
    if let Some(name) = out_interface {
        return Ok(name);
    }
    default_out_interface().await
}

pub async fn enable_forwarding(wg_interface: &str, out_interface: &str, snat: bool) -> Result<()> {
    write_sysctl("/proc/sys/net/ipv4/ip_forward", "1")?;
    write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;

    let netlink = Netlink::new().await?;
    netlink
        .link_index(wg_interface)
        .await?
        .ok_or_else(|| anyhow!("interface {} not found", wg_interface))?;
    netlink
        .link_index(out_interface)
        .await?
        .ok_or_else(|| anyhow!("interface {} not found", out_interface))?;

    firewall::reset_tables()?;
    firewall::apply_forwarding_rules(wg_interface, out_interface)?;
    if snat {
        firewall::apply_snat(out_interface)?;
    }

    Ok(())
}

pub async fn disable_forwarding(_wg_interface: &str, _out_interface: &str) -> Result<()> {
    firewall::reset_tables()
}

pub async fn apply_route_maps(
    wg_interface: &str,
    out_interface: &str,
    maps: &[(String, String)],
) -> Result<()> {
    let mut parsed = Vec::new();
    for (real, mapped) in maps {
        let real_net: IpNet = real
            .parse()
            .with_context(|| format!("invalid route map prefix {}", real))?;
        let mapped_net: IpNet = mapped
            .parse()
            .with_context(|| format!("invalid route map prefix {}", mapped))?;
        let real_v4 = matches!(real_net, IpNet::V4(_));
        let mapped_v4 = matches!(mapped_net, IpNet::V4(_));
        if real_v4 != mapped_v4 {
            return Err(anyhow!(
                "route map ip versions must match ({} vs {})",
                real,
                mapped
            ));
        }
        if real_net.prefix_len() != mapped_net.prefix_len() {
            return Err(anyhow!(
                "route map prefix lengths must match ({} vs {})",
                real,
                mapped
            ));
        }
        parsed.push((real_net, mapped_net));
    }
    firewall::apply_netmap(wg_interface, out_interface, &parsed)?;
    Ok(())
}

pub async fn interface_ips(out_interface: &str) -> Result<(Option<String>, Option<String>)> {
    let netlink = Netlink::new().await?;
    let index = netlink
        .link_index(out_interface)
        .await?
        .ok_or_else(|| anyhow!("interface {} not found", out_interface))?;
    let addrs = netlink.interface_addresses(index).await?;

    let mut v4 = None;
    let mut v6 = None;
    for InterfaceAddress { addr, .. } in addrs {
        match addr {
            IpAddr::V4(ip) => {
                if v4.is_none() && is_usable_ipv4(ip) {
                    v4 = Some(ip.to_string());
                }
            }
            IpAddr::V6(ip) => {
                if v6.is_none() && is_usable_ipv6(ip) {
                    v6 = Some(ip.to_string());
                }
            }
        }
    }

    Ok((v4, v6))
}

async fn default_out_interface() -> Result<String> {
    let netlink = Netlink::new().await?;
    let routes = netlink.list_routes().await?;
    let index = find_default_oif(&routes)
        .ok_or_else(|| anyhow!("failed to detect default route interface"))?;
    let name = netlink
        .link_name(index)
        .await?
        .ok_or_else(|| anyhow!("default route interface not found"))?;
    Ok(name)
}

fn find_default_oif(routes: &[RouteEntry]) -> Option<u32> {
    for entry in routes {
        if let IpNet::V4(net) = entry.prefix {
            if net.prefix_len() == 0 {
                if let Some(oif) = entry.oif {
                    return Some(oif);
                }
            }
        }
    }
    for entry in routes {
        if let IpNet::V6(net) = entry.prefix {
            if net.prefix_len() == 0 {
                if let Some(oif) = entry.oif {
                    return Some(oif);
                }
            }
        }
    }
    None
}

fn write_sysctl(path: &str, value: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, value).with_context(|| format!("failed to write sysctl {}", path))?;
    Ok(())
}

fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    let octets = ip.octets();
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }
    true
}

fn is_usable_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    let seg0 = ip.segments()[0];
    if (seg0 & 0xffc0) == 0xfe80 {
        return false;
    }
    true
}
