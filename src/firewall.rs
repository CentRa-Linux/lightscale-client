use anyhow::{anyhow, Result};

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use ipnet::IpNet;
    use std::process::Command;

    const FILTER_TABLE: &str = "lightscale";
    const FILTER_CHAIN: &str = "ls-forward";
    const NAT_TABLE: &str = "lightscale-nat";
    const NAT_CHAIN: &str = "ls-postrouting";
    const MAP_PREROUTING_CHAIN: &str = "ls-map-prerouting";
    const MAP_POSTROUTING_CHAIN: &str = "ls-map-postrouting";
    pub fn reset_tables() -> Result<()> {
        if run_nft(&["list", "table", "inet", FILTER_TABLE]).is_ok() {
            run_nft(&["delete", "table", "inet", FILTER_TABLE])?;
        }
        if run_nft(&["list", "table", "ip", NAT_TABLE]).is_ok() {
            run_nft(&["delete", "table", "ip", NAT_TABLE])?;
        }
        Ok(())
    }

    pub fn apply_forwarding_rules(wg_interface: &str, out_interface: &str) -> Result<()> {
        ensure_filter_table()?;
        ensure_filter_chain()?;
        run_nft(&["flush", "chain", "inet", FILTER_TABLE, FILTER_CHAIN])?;
        run_nft(&[
            "add",
            "rule",
            "inet",
            FILTER_TABLE,
            FILTER_CHAIN,
            "iifname",
            wg_interface,
            "oifname",
            out_interface,
            "accept",
        ])?;
        run_nft(&[
            "add",
            "rule",
            "inet",
            FILTER_TABLE,
            FILTER_CHAIN,
            "iifname",
            out_interface,
            "oifname",
            wg_interface,
            "ct",
            "state",
            "established,related",
            "accept",
        ])?;
        Ok(())
    }

    pub fn apply_snat(out_interface: &str) -> Result<()> {
        ensure_nat_table()?;
        ensure_nat_chain(NAT_CHAIN, "postrouting", "100")?;
        run_nft(&["flush", "chain", "ip", NAT_TABLE, NAT_CHAIN])?;
        run_nft(&[
            "add",
            "rule",
            "ip",
            NAT_TABLE,
            NAT_CHAIN,
            "oifname",
            out_interface,
            "masquerade",
        ])?;
        Ok(())
    }

    pub fn apply_netmap(
        wg_interface: &str,
        _out_interface: &str,
        maps: &[(IpNet, IpNet)],
    ) -> Result<()> {
        if maps.is_empty() {
            return Ok(());
        }
        ensure_nat_table()?;
        ensure_nat_chain(MAP_PREROUTING_CHAIN, "prerouting", "-100")?;
        ensure_nat_chain(MAP_POSTROUTING_CHAIN, "postrouting", "90")?;
        run_nft(&["flush", "chain", "ip", NAT_TABLE, MAP_PREROUTING_CHAIN])?;
        run_nft(&["flush", "chain", "ip", NAT_TABLE, MAP_POSTROUTING_CHAIN])?;
        for (real, mapped) in maps {
            let (real, mapped) = match (real, mapped) {
                (IpNet::V4(real), IpNet::V4(mapped)) => (real, mapped),
                _ => {
                    return Err(anyhow!(
                        "netmap only supports IPv4 prefixes in this build"
                    ))
                }
            };
            let prefix_len = mapped.prefix_len();
            let host_mask = ipv4_host_mask(prefix_len);
            let mapped_base = mapped.network();
            let real_base = real.network();
            run_nft(&[
                "add",
                "rule",
                "ip",
                NAT_TABLE,
                MAP_PREROUTING_CHAIN,
                "iifname",
                wg_interface,
                "ip",
                "daddr",
                &mapped.to_string(),
                "dnat",
                "to",
                "ip",
                "daddr",
                "&",
                &host_mask.to_string(),
                "|",
                &real_base.to_string(),
            ])?;
            run_nft(&[
                "add",
                "rule",
                "ip",
                NAT_TABLE,
                MAP_POSTROUTING_CHAIN,
                "oifname",
                wg_interface,
                "ip",
                "saddr",
                &real.to_string(),
                "snat",
                "to",
                "ip",
                "saddr",
                "&",
                &host_mask.to_string(),
                "|",
                &mapped_base.to_string(),
            ])?;
        }
        Ok(())
    }

    fn ensure_filter_table() -> Result<()> {
        if run_nft(&["list", "table", "inet", FILTER_TABLE]).is_ok() {
            return Ok(());
        }
        run_nft(&["add", "table", "inet", FILTER_TABLE])?;
        Ok(())
    }

    fn ensure_filter_chain() -> Result<()> {
        if run_nft(&["list", "chain", "inet", FILTER_TABLE, FILTER_CHAIN]).is_ok() {
            return Ok(());
        }
        run_nft(&[
            "add",
            "chain",
            "inet",
            FILTER_TABLE,
            FILTER_CHAIN,
            "{",
            "type",
            "filter",
            "hook",
            "forward",
            "priority",
            "10",
            ";",
            "policy",
            "drop",
            ";",
            "}",
        ])?;
        Ok(())
    }

    fn ensure_nat_table() -> Result<()> {
        if run_nft(&["list", "table", "ip", NAT_TABLE]).is_ok() {
            return Ok(());
        }
        run_nft(&["add", "table", "ip", NAT_TABLE])?;
        Ok(())
    }

    fn ensure_nat_chain(name: &str, hook: &str, priority: &str) -> Result<()> {
        if run_nft(&["list", "chain", "ip", NAT_TABLE, name]).is_ok() {
            return Ok(());
        }
        run_nft(&[
            "add",
            "chain",
            "ip",
            NAT_TABLE,
            name,
            "{",
            "type",
            "nat",
            "hook",
            hook,
            "priority",
            priority,
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ])?;
        Ok(())
    }

    fn ipv4_host_mask(prefix_len: u8) -> std::net::Ipv4Addr {
        if prefix_len >= 32 {
            return std::net::Ipv4Addr::from(0);
        }
        let mask = if prefix_len == 0 {
            u32::MAX
        } else {
            u32::MAX >> prefix_len
        };
        std::net::Ipv4Addr::from(mask)
    }

    fn run_nft(args: &[&str]) -> Result<()> {
        let output = Command::new("nft").args(args).output();
        let output = match output {
            Ok(output) => output,
            Err(err) => return Err(anyhow!("nft command failed: {}", err)),
        };
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow!(
            "nft command failed: {}",
            stderr.trim().to_string()
        ))
    }
}

#[cfg(target_os = "linux")]
pub use imp::{apply_forwarding_rules, apply_netmap, apply_snat, reset_tables};

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub fn reset_tables() -> Result<()> {
        Err(anyhow!("router firewall is only supported on linux"))
    }

    pub fn apply_forwarding_rules(_wg_interface: &str, _out_interface: &str) -> Result<()> {
        Err(anyhow!("router firewall is only supported on linux"))
    }

    pub fn apply_snat(_out_interface: &str) -> Result<()> {
        Err(anyhow!("router firewall is only supported on linux"))
    }

    pub fn apply_netmap(
        _wg_interface: &str,
        _out_interface: &str,
        _maps: &[(ipnet::IpNet, ipnet::IpNet)],
    ) -> Result<()> {
        Err(anyhow!("router firewall is only supported on linux"))
    }
}

#[cfg(not(target_os = "linux"))]
pub use imp::{apply_forwarding_rules, apply_netmap, apply_snat, reset_tables};
