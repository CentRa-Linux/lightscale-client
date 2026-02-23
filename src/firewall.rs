use anyhow::{anyhow, Result};

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use ipnet::IpNet;
    use nftnl::expr::{CmpOp, InterfaceName, Nat, NatType, Register};
    use nftnl::{nft_expr, Batch, Chain, MsgType, ProtoFamily, Rule, Table};
    use std::ffi::CString;
    use std::net::Ipv4Addr;

    const FILTER_TABLE: &str = "lightscale";
    const FILTER_CHAIN: &str = "ls-forward";
    const NAT_TABLE: &str = "lightscale-nat";
    const NAT_CHAIN: &str = "ls-postrouting";
    const MAP_PREROUTING_CHAIN: &str = "ls-map-prerouting";
    const MAP_POSTROUTING_CHAIN: &str = "ls-map-postrouting";

    fn send_batch(batch: Batch) -> Result<()> {
        let finalized = batch.finalize();
        let socket = mnl::Socket::new(mnl::Bus::Netfilter)
            .map_err(|e| anyhow!("failed to open netlink socket: {}", e))?;
        let portid = socket.portid();

        socket
            .send_all(&finalized)
            .map_err(|e| anyhow!("failed to send nftables batch: {}", e))?;

        let mut buf = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
        let seq_iter = finalized.sequence_numbers();
        for seq in seq_iter {
            let nrecv = socket
                .recv(&mut buf)
                .map_err(|e| anyhow!("failed to receive netlink response: {}", e))?;
            mnl::cb_run(&buf[..nrecv], seq, portid)
                .map_err(|e| anyhow!("nftables batch rejected: {}", e))?;
        }
        Ok(())
    }

    fn cstr(s: &str) -> CString {
        CString::new(s).expect("nftables name must not contain NUL bytes")
    }

    fn iface_name(s: &str) -> InterfaceName {
        InterfaceName::Exact(cstr(s))
    }

    pub fn reset_tables() -> Result<()> {
        // Delete each table in its own batch so that a missing table doesn't
        // prevent deletion of the other one.
        for (name, family) in [
            (FILTER_TABLE, ProtoFamily::Inet),
            (NAT_TABLE, ProtoFamily::Ipv4),
        ] {
            let mut batch = Batch::new();
            let table = Table::new(cstr(name), family);
            batch.add(&table, MsgType::Del);
            let _ = send_batch(batch); // ignore ENOENT
        }
        Ok(())
    }

    pub fn apply_forwarding_rules(wg_interface: &str, out_interface: &str) -> Result<()> {
        // Delete existing table for idempotency (ignore error if not present).
        {
            let mut del = Batch::new();
            let table = Table::new(cstr(FILTER_TABLE), ProtoFamily::Inet);
            del.add(&table, MsgType::Del);
            let _ = send_batch(del);
        }

        let mut batch = Batch::new();

        // Create filter table.
        let table_name = cstr(FILTER_TABLE);
        let table = Table::new(&table_name, ProtoFamily::Inet);
        batch.add(&table, MsgType::Add);

        // Create forward chain with policy drop.
        let chain_name = cstr(FILTER_CHAIN);
        let mut chain = Chain::new(&chain_name, &table);
        chain.set_hook(nftnl::Hook::Forward, 10);
        chain.set_policy(nftnl::Policy::Drop);
        chain.set_type(nftnl::ChainType::Filter);
        batch.add(&chain, MsgType::Add);

        let wg_iface = iface_name(wg_interface);
        let out_iface = iface_name(out_interface);

        // Rule 1: iifname <wg> oifname <out> accept
        {
            let mut rule = Rule::new(&chain);
            rule.add_expr(&nft_expr!(meta iifname));
            rule.add_expr(&nft_expr!(cmp == wg_iface.clone()));
            rule.add_expr(&nft_expr!(meta oifname));
            rule.add_expr(&nft_expr!(cmp == out_iface.clone()));
            rule.add_expr(&nft_expr!(verdict accept));
            batch.add(&rule, MsgType::Add);
        }

        // Rule 2: iifname <out> oifname <wg> ct state established,related accept
        {
            let mut rule = Rule::new(&chain);
            rule.add_expr(&nft_expr!(meta iifname));
            rule.add_expr(&nft_expr!(cmp == out_iface));
            rule.add_expr(&nft_expr!(meta oifname));
            rule.add_expr(&nft_expr!(cmp == wg_iface));
            // Load ct state into Reg1, then mask with established|related (6),
            // then check result != 0.
            rule.add_expr(&nft_expr!(ct state));
            let ct_mask =
                (nftnl::expr::ct::States::ESTABLISHED | nftnl::expr::ct::States::RELATED).bits();
            rule.add_expr(&nft_expr!(bitwise mask ct_mask, xor 0u32));
            rule.add_expr(&nftnl::expr::Cmp::new(CmpOp::Neq, 0u32));
            rule.add_expr(&nft_expr!(verdict accept));
            batch.add(&rule, MsgType::Add);
        }

        send_batch(batch)
    }

    pub fn apply_snat(out_interface: &str) -> Result<()> {
        // Delete existing chain for idempotency (ignore error).
        {
            let mut del = Batch::new();
            let table_name = cstr(NAT_TABLE);
            let table = Table::new(&table_name, ProtoFamily::Ipv4);
            del.add(&table, MsgType::Add); // ensure table exists for del chain
            let chain = Chain::new(cstr(NAT_CHAIN), &table);
            del.add(&chain, MsgType::Del);
            let _ = send_batch(del);
        }

        let mut batch = Batch::new();
        let table_name = cstr(NAT_TABLE);
        let table = Table::new(&table_name, ProtoFamily::Ipv4);
        batch.add(&table, MsgType::Add);

        let chain_name = cstr(NAT_CHAIN);
        let mut chain = Chain::new(&chain_name, &table);
        chain.set_hook(nftnl::Hook::PostRouting, 100);
        chain.set_policy(nftnl::Policy::Accept);
        chain.set_type(nftnl::ChainType::Nat);
        batch.add(&chain, MsgType::Add);

        // Rule: oifname <out> masquerade
        let out_iface = iface_name(out_interface);
        let mut rule = Rule::new(&chain);
        rule.add_expr(&nft_expr!(meta oifname));
        rule.add_expr(&nft_expr!(cmp == out_iface));
        rule.add_expr(&nft_expr!(masquerade));
        batch.add(&rule, MsgType::Add);

        send_batch(batch)
    }

    pub fn apply_netmap(
        wg_interface: &str,
        _out_interface: &str,
        maps: &[(IpNet, IpNet)],
    ) -> Result<()> {
        if maps.is_empty() {
            return Ok(());
        }

        // Delete existing map chains for idempotency (ignore errors).
        {
            let mut del = Batch::new();
            let table_name = cstr(NAT_TABLE);
            let table = Table::new(&table_name, ProtoFamily::Ipv4);
            del.add(&table, MsgType::Add);
            for name in [MAP_PREROUTING_CHAIN, MAP_POSTROUTING_CHAIN] {
                let chain = Chain::new(cstr(name), &table);
                del.add(&chain, MsgType::Del);
            }
            let _ = send_batch(del);
        }

        let mut batch = Batch::new();
        let table_name = cstr(NAT_TABLE);
        let table = Table::new(&table_name, ProtoFamily::Ipv4);
        batch.add(&table, MsgType::Add);

        let pre_chain_name = cstr(MAP_PREROUTING_CHAIN);
        let mut pre_chain = Chain::new(&pre_chain_name, &table);
        pre_chain.set_hook(nftnl::Hook::PreRouting, -100);
        pre_chain.set_policy(nftnl::Policy::Accept);
        pre_chain.set_type(nftnl::ChainType::Nat);
        batch.add(&pre_chain, MsgType::Add);

        let post_chain_name = cstr(MAP_POSTROUTING_CHAIN);
        let mut post_chain = Chain::new(&post_chain_name, &table);
        post_chain.set_hook(nftnl::Hook::PostRouting, 90);
        post_chain.set_policy(nftnl::Policy::Accept);
        post_chain.set_type(nftnl::ChainType::Nat);
        batch.add(&post_chain, MsgType::Add);

        for (real, mapped) in maps {
            let (real, mapped) = match (real, mapped) {
                (IpNet::V4(real), IpNet::V4(mapped)) => (real, mapped),
                _ => return Err(anyhow!("netmap only supports IPv4 prefixes in this build")),
            };
            let prefix_len = mapped.prefix_len();
            let host_mask = ipv4_host_mask(prefix_len);
            let mapped_base = mapped.network();
            let real_base = real.network();
            let net_mask_mapped = ipv4_net_mask(prefix_len);
            let net_mask_real = ipv4_net_mask(real.prefix_len());
            let wg_iface = iface_name(wg_interface);

            // DNAT rule: iifname <wg> ip daddr <mapped_net> dnat to ip daddr & <host_mask> | <real_base>
            {
                let mut rule = Rule::new(&pre_chain);
                // Match on wg interface
                rule.add_expr(&nft_expr!(meta iifname));
                rule.add_expr(&nft_expr!(cmp == wg_iface.clone()));
                // Load ip daddr, mask to network, compare with mapped network
                rule.add_expr(&nft_expr!(payload ipv4 daddr));
                rule.add_expr(&nft_expr!(bitwise mask net_mask_mapped, xor Ipv4Addr::UNSPECIFIED));
                rule.add_expr(&nft_expr!(cmp == mapped.network()));
                // Reload ip daddr, compute translated address: (daddr & host_mask) | real_base
                rule.add_expr(&nft_expr!(payload ipv4 daddr));
                rule.add_expr(&nft_expr!(bitwise mask host_mask, xor real_base));
                // Apply DNAT from Reg1
                rule.add_expr(&Nat {
                    nat_type: NatType::DNat,
                    family: ProtoFamily::Ipv4,
                    ip_register: Register::Reg1,
                    port_register: None,
                });
                batch.add(&rule, MsgType::Add);
            }

            // SNAT rule: oifname <wg> ip saddr <real_net> snat to ip saddr & <host_mask> | <mapped_base>
            {
                let mut rule = Rule::new(&post_chain);
                // Match on wg interface
                rule.add_expr(&nft_expr!(meta oifname));
                rule.add_expr(&nft_expr!(cmp == wg_iface));
                // Load ip saddr, mask to network, compare with real network
                rule.add_expr(&nft_expr!(payload ipv4 saddr));
                rule.add_expr(&nft_expr!(bitwise mask net_mask_real, xor Ipv4Addr::UNSPECIFIED));
                rule.add_expr(&nft_expr!(cmp == real.network()));
                // Reload ip saddr, compute translated address: (saddr & host_mask) | mapped_base
                rule.add_expr(&nft_expr!(payload ipv4 saddr));
                rule.add_expr(&nft_expr!(bitwise mask host_mask, xor mapped_base));
                // Apply SNAT from Reg1
                rule.add_expr(&Nat {
                    nat_type: NatType::SNat,
                    family: ProtoFamily::Ipv4,
                    ip_register: Register::Reg1,
                    port_register: None,
                });
                batch.add(&rule, MsgType::Add);
            }
        }

        send_batch(batch)
    }

    fn ipv4_net_mask(prefix_len: u8) -> Ipv4Addr {
        if prefix_len >= 32 {
            return Ipv4Addr::from(u32::MAX);
        }
        if prefix_len == 0 {
            return Ipv4Addr::UNSPECIFIED;
        }
        Ipv4Addr::from(u32::MAX << (32 - prefix_len))
    }

    fn ipv4_host_mask(prefix_len: u8) -> Ipv4Addr {
        if prefix_len >= 32 {
            return Ipv4Addr::UNSPECIFIED;
        }
        let mask = if prefix_len == 0 {
            u32::MAX
        } else {
            u32::MAX >> prefix_len
        };
        Ipv4Addr::from(mask)
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
