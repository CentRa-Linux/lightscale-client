use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use futures_util::stream::TryStreamExt;
    use netlink_packet_route::address::AddressAttribute;
    use netlink_packet_route::{
        link::LinkAttribute,
        route::{RouteAddress, RouteAttribute, RouteMessage},
        rule::{RuleAttribute, RuleUidRange},
        AddressFamily,
    };
    use rtnetlink::{
        new_connection, AddressMessageBuilder, Handle, LinkUnspec, RouteMessageBuilder,
    };
    use std::time::Instant;
    use tokio::time::sleep;

    #[derive(Clone)]
    pub struct Netlink {
        handle: Handle,
    }

    #[derive(Debug, Clone)]
    pub struct RouteEntry {
        pub prefix: IpNet,
        pub oif: Option<u32>,
    }

    #[derive(Debug, Clone)]
    pub struct InterfaceAddress {
        pub addr: IpAddr,
        pub prefix: u8,
    }

    impl Netlink {
        pub async fn new() -> Result<Self> {
            let (connection, handle, _) =
                new_connection().context("failed to open netlink connection")?;
            tokio::spawn(connection);
            Ok(Netlink { handle })
        }

        pub async fn link_index(&self, name: &str) -> Result<Option<u32>> {
            let mut links = self
                .handle
                .link()
                .get()
                .match_name(name.to_string())
                .execute();
            if let Some(link) = links.try_next().await? {
                return Ok(Some(link.header.index));
            }
            Ok(None)
        }

        pub async fn link_name(&self, index: u32) -> Result<Option<String>> {
            let mut links = self.handle.link().get().match_index(index).execute();
            if let Some(link) = links.try_next().await? {
                for attr in link.attributes {
                    if let LinkAttribute::IfName(name) = attr {
                        return Ok(Some(name));
                    }
                }
            }
            Ok(None)
        }

        pub async fn wait_for_link(&self, name: &str, timeout: Duration) -> Result<u32> {
            let start = Instant::now();
            loop {
                if let Some(index) = self.link_index(name).await? {
                    return Ok(index);
                }
                if start.elapsed() > timeout {
                    return Err(anyhow!("interface {} did not appear", name));
                }
                sleep(Duration::from_millis(100)).await;
            }
        }

        pub async fn set_link_up(&self, index: u32) -> Result<()> {
            let link = LinkUnspec::new_with_index(index).up().build();
            self.handle.link().set(link).execute().await?;
            Ok(())
        }

        pub async fn interface_addresses(&self, index: u32) -> Result<Vec<InterfaceAddress>> {
            let mut addresses = self
                .handle
                .address()
                .get()
                .set_link_index_filter(index)
                .execute();
            let mut results = Vec::new();
            while let Some(msg) = addresses.try_next().await? {
                let mut selected = None;
                for attr in msg.attributes {
                    match attr {
                        AddressAttribute::Local(addr) => {
                            selected = Some(addr);
                            break;
                        }
                        AddressAttribute::Address(addr) => {
                            if selected.is_none() {
                                selected = Some(addr);
                            }
                        }
                        _ => {}
                    }
                }
                let Some(addr) = selected else {
                    continue;
                };
                results.push(InterfaceAddress {
                    addr,
                    prefix: msg.header.prefix_len,
                });
            }
            Ok(results)
        }

        pub async fn replace_address(&self, index: u32, address: IpAddr, prefix: u8) -> Result<()> {
            if let (IpAddr::V4(v4), 32) = (address, prefix) {
                // Ensure old addr attrs (notably broadcast) do not survive
                // replace operations on /32 WireGuard addresses.
                let del_msg = AddressMessageBuilder::<Ipv4Addr>::new()
                    .index(index)
                    .address(v4, prefix)
                    .build();
                let _ = self.handle.address().del(del_msg).execute().await;
            }

            let mut req = self.handle.address().add(index, address, prefix).replace();
            if let (IpAddr::V4(_), 32) = (address, prefix) {
                // rtnetlink's builder always sets IFA_BROADCAST for IPv4,
                // including /32 addresses where it equals the host address.
                // On WireGuard /32 this can cause ICMP echo to be treated as
                // broadcast and ignored.
                req.message_mut().attributes.retain(|attr| {
                    !matches!(
                        attr,
                        AddressAttribute::Broadcast(_) | AddressAttribute::Address(_)
                    )
                });
            }
            req.execute().await?;
            Ok(())
        }

        pub async fn delete_address(&self, index: u32, address: IpAddr, prefix: u8) -> Result<()> {
            match address {
                IpAddr::V4(v4) => {
                    let msg = AddressMessageBuilder::<Ipv4Addr>::new()
                        .index(index)
                        .address(v4, prefix)
                        .build();
                    self.handle.address().del(msg).execute().await?;
                }
                IpAddr::V6(v6) => {
                    let msg = AddressMessageBuilder::<Ipv6Addr>::new()
                        .index(index)
                        .address(v6, prefix)
                        .build();
                    self.handle.address().del(msg).execute().await?;
                }
            }
            Ok(())
        }

        pub async fn replace_route(&self, prefix: IpNet, index: u32) -> Result<()> {
            self.replace_route_with_metric(prefix, index, None).await
        }

        pub async fn replace_route_with_metric(
            &self,
            prefix: IpNet,
            index: u32,
            metric: Option<u32>,
        ) -> Result<()> {
            match prefix {
                IpNet::V4(net) => {
                    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                        .destination_prefix(net.network(), net.prefix_len())
                        .output_interface(index);
                    if let Some(metric) = metric {
                        builder = builder.priority(metric);
                    }
                    let route = builder.build();
                    self.handle.route().add(route).replace().execute().await?;
                }
                IpNet::V6(net) => {
                    let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                        .destination_prefix(net.network(), net.prefix_len())
                        .output_interface(index);
                    if let Some(metric) = metric {
                        builder = builder.priority(metric);
                    }
                    let route = builder.build();
                    self.handle.route().add(route).replace().execute().await?;
                }
            }
            Ok(())
        }

        pub async fn replace_route_with_metric_table(
            &self,
            prefix: IpNet,
            index: u32,
            metric: Option<u32>,
            table: u32,
        ) -> Result<()> {
            match prefix {
                IpNet::V4(net) => {
                    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                        .destination_prefix(net.network(), net.prefix_len())
                        .output_interface(index)
                        .table_id(table);
                    if let Some(metric) = metric {
                        builder = builder.priority(metric);
                    }
                    let route = builder.build();
                    self.handle.route().add(route).replace().execute().await?;
                }
                IpNet::V6(net) => {
                    let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                        .destination_prefix(net.network(), net.prefix_len())
                        .output_interface(index)
                        .table_id(table);
                    if let Some(metric) = metric {
                        builder = builder.priority(metric);
                    }
                    let route = builder.build();
                    self.handle.route().add(route).replace().execute().await?;
                }
            }
            Ok(())
        }

        pub async fn add_rule_for_prefix(
            &self,
            prefix: IpNet,
            table: u32,
            priority: u32,
        ) -> Result<()> {
            match prefix {
                IpNet::V4(net) => {
                    self.handle
                        .rule()
                        .add()
                        .table_id(table)
                        .priority(priority)
                        .v4()
                        .destination_prefix(net.network(), net.prefix_len())
                        .replace()
                        .execute()
                        .await?;
                }
                IpNet::V6(net) => {
                    self.handle
                        .rule()
                        .add()
                        .table_id(table)
                        .priority(priority)
                        .v6()
                        .destination_prefix(net.network(), net.prefix_len())
                        .replace()
                        .execute()
                        .await?;
                }
            }
            Ok(())
        }

        pub async fn add_uid_rule_v4(
            &self,
            table: u32,
            priority: u32,
            start: u32,
            end: u32,
        ) -> Result<()> {
            let mut req = self
                .handle
                .rule()
                .add()
                .table_id(table)
                .priority(priority)
                .v4()
                .replace();
            req.message_mut()
                .attributes
                .push(RuleAttribute::UidRange(RuleUidRange { start, end }));
            req.execute().await?;
            Ok(())
        }

        pub async fn add_uid_rule_v6(
            &self,
            table: u32,
            priority: u32,
            start: u32,
            end: u32,
        ) -> Result<()> {
            let mut req = self
                .handle
                .rule()
                .add()
                .table_id(table)
                .priority(priority)
                .v6()
                .replace();
            req.message_mut()
                .attributes
                .push(RuleAttribute::UidRange(RuleUidRange { start, end }));
            req.execute().await?;
            Ok(())
        }

        pub async fn delete_link(&self, name: &str) -> Result<()> {
            let mut links = self
                .handle
                .link()
                .get()
                .match_name(name.to_string())
                .execute();
            if let Some(link) = links.try_next().await? {
                self.handle.link().del(link.header.index).execute().await?;
            }
            Ok(())
        }

        pub async fn list_link_names(&self) -> Result<Vec<String>> {
            let mut links = self.handle.link().get().execute();
            let mut names = Vec::new();
            while let Some(link) = links.try_next().await? {
                for attr in link.attributes {
                    if let LinkAttribute::IfName(name) = attr {
                        names.push(name);
                        break;
                    }
                }
            }
            Ok(names)
        }

        pub async fn list_routes(&self) -> Result<Vec<RouteEntry>> {
            let mut entries = Vec::new();
            entries.extend(self.list_routes_v4().await?);
            entries.extend(self.list_routes_v6().await?);
            Ok(entries)
        }

        async fn list_routes_v4(&self) -> Result<Vec<RouteEntry>> {
            let mut entries = Vec::new();
            let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
            let mut routes = self.handle.route().get(route).execute();
            while let Some(route) = routes.try_next().await? {
                if let Some(entry) = parse_route_message(route) {
                    entries.push(entry);
                }
            }
            Ok(entries)
        }

        async fn list_routes_v6(&self) -> Result<Vec<RouteEntry>> {
            let mut entries = Vec::new();
            let route = RouteMessageBuilder::<Ipv6Addr>::new().build();
            let mut routes = self.handle.route().get(route).execute();
            while let Some(route) = routes.try_next().await? {
                if let Some(entry) = parse_route_message(route) {
                    entries.push(entry);
                }
            }
            Ok(entries)
        }
    }

    fn parse_route_message(route: RouteMessage) -> Option<RouteEntry> {
        let family = route.header.address_family;
        let prefix_len = route.header.destination_prefix_length;
        let mut destination = None;
        let mut oif = None;

        for attr in route.attributes {
            match attr {
                RouteAttribute::Destination(RouteAddress::Inet(addr)) => {
                    destination = Some(IpAddr::V4(addr));
                }
                RouteAttribute::Destination(RouteAddress::Inet6(addr)) => {
                    destination = Some(IpAddr::V6(addr));
                }
                RouteAttribute::Oif(index) => {
                    oif = Some(index);
                }
                _ => {}
            }
        }

        let addr = match (destination, family) {
            (Some(addr), _) => addr,
            (None, AddressFamily::Inet) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            (None, AddressFamily::Inet6) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => return None,
        };

        let prefix = IpNet::new(addr, prefix_len).ok()?;
        Some(RouteEntry { prefix, oif })
    }
}

#[cfg(target_os = "linux")]
pub use imp::{InterfaceAddress, Netlink, RouteEntry};

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    #[derive(Clone)]
    pub struct Netlink;

    #[derive(Debug, Clone)]
    pub struct RouteEntry {
        pub prefix: IpNet,
        pub oif: Option<u32>,
    }

    #[derive(Debug, Clone)]
    pub struct InterfaceAddress {
        pub addr: IpAddr,
        pub prefix: u8,
    }

    impl Netlink {
        pub async fn new() -> Result<Self> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn link_index(&self, _name: &str) -> Result<Option<u32>> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn link_name(&self, _index: u32) -> Result<Option<String>> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn wait_for_link(&self, _name: &str, _timeout: Duration) -> Result<u32> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn set_link_up(&self, _index: u32) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn interface_addresses(&self, _index: u32) -> Result<Vec<InterfaceAddress>> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn replace_address(
            &self,
            _index: u32,
            _address: IpAddr,
            _prefix: u8,
        ) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn delete_address(
            &self,
            _index: u32,
            _address: IpAddr,
            _prefix: u8,
        ) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn replace_route(&self, _prefix: IpNet, _index: u32) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn replace_route_with_metric(
            &self,
            _prefix: IpNet,
            _index: u32,
            _metric: Option<u32>,
        ) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn replace_route_with_metric_table(
            &self,
            _prefix: IpNet,
            _index: u32,
            _metric: Option<u32>,
            _table: u32,
        ) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn add_rule_for_prefix(
            &self,
            _prefix: IpNet,
            _table: u32,
            _priority: u32,
        ) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn add_uid_rule_v4(
            &self,
            _table: u32,
            _priority: u32,
            _start: u32,
            _end: u32,
        ) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn add_uid_rule_v6(
            &self,
            _table: u32,
            _priority: u32,
            _start: u32,
            _end: u32,
        ) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn delete_link(&self, _name: &str) -> Result<()> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn list_link_names(&self) -> Result<Vec<String>> {
            Err(anyhow!("netlink is only supported on linux"))
        }

        pub async fn list_routes(&self) -> Result<Vec<RouteEntry>> {
            Err(anyhow!("netlink is only supported on linux"))
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use imp::{InterfaceAddress, Netlink, RouteEntry};
