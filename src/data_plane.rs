use crate::dns_server;
use crate::model::NetMap;
use crate::routes;
use crate::state::ClientState;
use crate::wg;
use anyhow::Result;
#[cfg(not(target_os = "linux"))]
use anyhow::anyhow;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[async_trait]
pub trait DataPlane: Send + Sync {
    async fn wg_apply(
        &self,
        netmap: &NetMap,
        state: &ClientState,
        cfg: &wg::WgConfig,
        routes_cfg: Option<&routes::RouteApplyConfig>,
    ) -> Result<()>;

    async fn wg_remove(&self, interface: &str, backend: wg::Backend) -> Result<()>;

    fn wg_probe_peers(&self, netmap: &NetMap, timeout_seconds: u64) -> Result<()>;

    fn wg_refresh_peer_endpoints(
        &self,
        netmap: &NetMap,
        cfg: &wg::WgConfig,
        tracker: &mut wg::EndpointTracker,
        relay_endpoints: &HashMap<String, SocketAddr>,
        stale_after: Duration,
        max_rotations: usize,
        relay_reprobe_after: Duration,
    ) -> Result<()>;

    async fn apply_advertised_routes(
        &self,
        netmap: &NetMap,
        cfg: &routes::RouteApplyConfig,
    ) -> Result<()>;

    fn dns_spawn(&self, addr: SocketAddr, netmap: NetMap) -> Result<Arc<Mutex<NetMap>>>;

    fn dns_apply_resolver(&self, interface: &str, domain: &str, server: IpAddr) -> Result<()>;

    fn dns_clear_resolver(&self, interface: &str) -> Result<()>;
}

pub fn for_current_platform() -> Box<dyn DataPlane> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxDataPlane)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(PortableDataPlane)
    }
}

pub struct LinuxDataPlane;

#[async_trait]
impl DataPlane for LinuxDataPlane {
    async fn wg_apply(
        &self,
        netmap: &NetMap,
        state: &ClientState,
        cfg: &wg::WgConfig,
        routes_cfg: Option<&routes::RouteApplyConfig>,
    ) -> Result<()> {
        wg::apply(netmap, state, cfg, routes_cfg).await
    }

    async fn wg_remove(&self, interface: &str, backend: wg::Backend) -> Result<()> {
        wg::remove(interface, backend).await
    }

    fn wg_probe_peers(&self, netmap: &NetMap, timeout_seconds: u64) -> Result<()> {
        wg::probe_peers(netmap, timeout_seconds)
    }

    fn wg_refresh_peer_endpoints(
        &self,
        netmap: &NetMap,
        cfg: &wg::WgConfig,
        tracker: &mut wg::EndpointTracker,
        relay_endpoints: &HashMap<String, SocketAddr>,
        stale_after: Duration,
        max_rotations: usize,
        relay_reprobe_after: Duration,
    ) -> Result<()> {
        wg::refresh_peer_endpoints(
            netmap,
            cfg,
            tracker,
            relay_endpoints,
            stale_after,
            max_rotations,
            relay_reprobe_after,
        )
    }

    async fn apply_advertised_routes(
        &self,
        netmap: &NetMap,
        cfg: &routes::RouteApplyConfig,
    ) -> Result<()> {
        routes::apply_advertised_routes(netmap, cfg).await
    }

    fn dns_spawn(&self, addr: SocketAddr, netmap: NetMap) -> Result<Arc<Mutex<NetMap>>> {
        dns_server::spawn(addr, netmap)
    }

    fn dns_apply_resolver(&self, interface: &str, domain: &str, server: IpAddr) -> Result<()> {
        dns_server::apply_resolver(interface, domain, server)
    }

    fn dns_clear_resolver(&self, interface: &str) -> Result<()> {
        dns_server::clear_resolver(interface)
    }
}

#[cfg(not(target_os = "linux"))]
pub struct PortableDataPlane;

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl DataPlane for PortableDataPlane {
    async fn wg_apply(
        &self,
        netmap: &NetMap,
        state: &ClientState,
        cfg: &wg::WgConfig,
        routes_cfg: Option<&routes::RouteApplyConfig>,
    ) -> Result<()> {
        wg::apply(netmap, state, cfg, routes_cfg).await
    }

    async fn wg_remove(&self, interface: &str, backend: wg::Backend) -> Result<()> {
        wg::remove(interface, backend).await
    }

    fn wg_probe_peers(&self, netmap: &NetMap, timeout_seconds: u64) -> Result<()> {
        wg::probe_peers(netmap, timeout_seconds)
    }

    fn wg_refresh_peer_endpoints(
        &self,
        netmap: &NetMap,
        cfg: &wg::WgConfig,
        tracker: &mut wg::EndpointTracker,
        relay_endpoints: &HashMap<String, SocketAddr>,
        stale_after: Duration,
        max_rotations: usize,
        relay_reprobe_after: Duration,
    ) -> Result<()> {
        wg::refresh_peer_endpoints(
            netmap,
            cfg,
            tracker,
            relay_endpoints,
            stale_after,
            max_rotations,
            relay_reprobe_after,
        )
    }

    async fn apply_advertised_routes(
        &self,
        _netmap: &NetMap,
        _cfg: &routes::RouteApplyConfig,
    ) -> Result<()> {
        Err(anyhow!(
            "advertised route programming is only supported on linux at the moment"
        ))
    }

    fn dns_spawn(&self, addr: SocketAddr, netmap: NetMap) -> Result<Arc<Mutex<NetMap>>> {
        dns_server::spawn(addr, netmap)
    }

    fn dns_apply_resolver(&self, interface: &str, domain: &str, server: IpAddr) -> Result<()> {
        dns_server::apply_resolver(interface, domain, server)
    }

    fn dns_clear_resolver(&self, interface: &str) -> Result<()> {
        dns_server::clear_resolver(interface)
    }
}
