use crate::dns_server;
use crate::model::NetMap;
use crate::platform::SupportLevel;
use crate::routes;
use crate::state::ClientState;
use crate::wg;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct DataPlaneCapabilities {
    pub wireguard: SupportLevel,
    pub advertised_routes: SupportLevel,
    pub advanced_route_policy: SupportLevel,
    pub router_mode: SupportLevel,
    pub dns_local_server: SupportLevel,
    pub dns_resolver_integration: SupportLevel,
    pub note: &'static str,
}

const LINUX_CAPABILITIES: DataPlaneCapabilities = DataPlaneCapabilities {
    wireguard: SupportLevel::Supported,
    advertised_routes: SupportLevel::Supported,
    advanced_route_policy: SupportLevel::Supported,
    router_mode: SupportLevel::Supported,
    dns_local_server: SupportLevel::Supported,
    dns_resolver_integration: SupportLevel::Supported,
    note: "linux backend: full data-plane with route/dns/service integration",
};

#[cfg(not(target_os = "linux"))]
const PORTABLE_CAPABILITIES: DataPlaneCapabilities = DataPlaneCapabilities {
    wireguard: SupportLevel::Partial,
    advertised_routes: SupportLevel::Unsupported,
    advanced_route_policy: SupportLevel::Unsupported,
    router_mode: SupportLevel::Unsupported,
    dns_local_server: SupportLevel::Supported,
    dns_resolver_integration: SupportLevel::Unsupported,
    note: "portable backend: experimental wireguard only; advanced routing/service integration pending",
};

pub fn ensure_supported(level: SupportLevel, feature: &str, command_name: &str) -> Result<()> {
    if level != SupportLevel::Unsupported {
        return Ok(());
    }
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    Err(anyhow!(
        "{} is unavailable on {}-{}: {} is unsupported on this platform",
        command_name,
        os,
        arch,
        feature
    ))
}

pub fn require_advertised_routes(data_plane: &dyn DataPlane, command_name: &str) -> Result<()> {
    ensure_supported(
        data_plane.capabilities().advertised_routes,
        "advertised route programming",
        command_name,
    )
}

pub fn require_router_mode(data_plane: &dyn DataPlane, command_name: &str) -> Result<()> {
    ensure_supported(
        data_plane.capabilities().router_mode,
        "router mode",
        command_name,
    )
}

pub fn require_dns_resolver_integration(
    data_plane: &dyn DataPlane,
    command_name: &str,
) -> Result<()> {
    ensure_supported(
        data_plane.capabilities().dns_resolver_integration,
        "dns resolver integration",
        command_name,
    )
}

pub fn require_daemon_supervision(data_plane: &dyn DataPlane, command_name: &str) -> Result<()> {
    ensure_supported(
        data_plane.service_manager().daemon_supervision(),
        "daemon supervision",
        command_name,
    )
}

#[async_trait]
pub trait WireGuardManager: Send + Sync {
    async fn apply(
        &self,
        netmap: &NetMap,
        state: &ClientState,
        cfg: &wg::WgConfig,
        routes_cfg: Option<&routes::RouteApplyConfig>,
    ) -> Result<()>;

    async fn remove(&self, interface: &str, backend: wg::Backend) -> Result<()>;

    fn probe_peers(&self, netmap: &NetMap, timeout_seconds: u64) -> Result<()>;

    fn refresh_peer_endpoints(
        &self,
        netmap: &NetMap,
        cfg: &wg::WgConfig,
        tracker: &mut wg::EndpointTracker,
        relay_endpoints: &HashMap<String, SocketAddr>,
        stale_after: Duration,
        max_rotations: usize,
        relay_reprobe_after: Duration,
    ) -> Result<()>;
}

#[async_trait]
pub trait RouteManager: Send + Sync {
    async fn apply_advertised_routes(
        &self,
        netmap: &NetMap,
        cfg: &routes::RouteApplyConfig,
    ) -> Result<()>;
}

pub trait ResolverManager: Send + Sync {
    fn dns_spawn(&self, addr: SocketAddr, netmap: NetMap) -> Result<Arc<Mutex<NetMap>>>;

    fn dns_apply_resolver(&self, interface: &str, domain: &str, server: IpAddr) -> Result<()>;

    fn dns_clear_resolver(&self, interface: &str) -> Result<()>;
}

pub trait ServiceManager: Send + Sync {
    fn daemon_supervision(&self) -> SupportLevel;

    fn os_service_integration(&self) -> SupportLevel;
}

#[async_trait]
pub trait DataPlane: Send + Sync {
    fn capabilities(&self) -> DataPlaneCapabilities;

    fn wireguard_manager(&self) -> &dyn WireGuardManager;

    fn route_manager(&self) -> &dyn RouteManager;

    fn resolver_manager(&self) -> &dyn ResolverManager;

    fn service_manager(&self) -> &dyn ServiceManager;

    async fn wg_apply(
        &self,
        netmap: &NetMap,
        state: &ClientState,
        cfg: &wg::WgConfig,
        routes_cfg: Option<&routes::RouteApplyConfig>,
    ) -> Result<()> {
        self.wireguard_manager()
            .apply(netmap, state, cfg, routes_cfg)
            .await
    }

    async fn wg_remove(&self, interface: &str, backend: wg::Backend) -> Result<()> {
        self.wireguard_manager().remove(interface, backend).await
    }

    fn wg_probe_peers(&self, netmap: &NetMap, timeout_seconds: u64) -> Result<()> {
        self.wireguard_manager().probe_peers(netmap, timeout_seconds)
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
        self.wireguard_manager().refresh_peer_endpoints(
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
        self.route_manager().apply_advertised_routes(netmap, cfg).await
    }

    fn dns_spawn(&self, addr: SocketAddr, netmap: NetMap) -> Result<Arc<Mutex<NetMap>>> {
        self.resolver_manager().dns_spawn(addr, netmap)
    }

    fn dns_apply_resolver(&self, interface: &str, domain: &str, server: IpAddr) -> Result<()> {
        self.resolver_manager()
            .dns_apply_resolver(interface, domain, server)
    }

    fn dns_clear_resolver(&self, interface: &str) -> Result<()> {
        self.resolver_manager().dns_clear_resolver(interface)
    }
}

#[derive(Default)]
struct LinuxWireGuardManager;

#[async_trait]
impl WireGuardManager for LinuxWireGuardManager {
    async fn apply(
        &self,
        netmap: &NetMap,
        state: &ClientState,
        cfg: &wg::WgConfig,
        routes_cfg: Option<&routes::RouteApplyConfig>,
    ) -> Result<()> {
        wg::apply(netmap, state, cfg, routes_cfg).await
    }

    async fn remove(&self, interface: &str, backend: wg::Backend) -> Result<()> {
        wg::remove(interface, backend).await
    }

    fn probe_peers(&self, netmap: &NetMap, timeout_seconds: u64) -> Result<()> {
        wg::probe_peers(netmap, timeout_seconds)
    }

    fn refresh_peer_endpoints(
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
}

#[derive(Default)]
struct LinuxRouteManager;

#[async_trait]
impl RouteManager for LinuxRouteManager {
    async fn apply_advertised_routes(
        &self,
        netmap: &NetMap,
        cfg: &routes::RouteApplyConfig,
    ) -> Result<()> {
        routes::apply_advertised_routes(netmap, cfg).await
    }
}

#[derive(Default)]
struct LinuxResolverManager;

impl ResolverManager for LinuxResolverManager {
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

#[derive(Default)]
struct LinuxServiceManager;

impl ServiceManager for LinuxServiceManager {
    fn daemon_supervision(&self) -> SupportLevel {
        SupportLevel::Supported
    }

    fn os_service_integration(&self) -> SupportLevel {
        SupportLevel::Supported
    }
}

pub struct LinuxDataPlane {
    wg: LinuxWireGuardManager,
    routes: LinuxRouteManager,
    resolver: LinuxResolverManager,
    service: LinuxServiceManager,
}

impl Default for LinuxDataPlane {
    fn default() -> Self {
        Self {
            wg: LinuxWireGuardManager,
            routes: LinuxRouteManager,
            resolver: LinuxResolverManager,
            service: LinuxServiceManager,
        }
    }
}

impl DataPlane for LinuxDataPlane {
    fn capabilities(&self) -> DataPlaneCapabilities {
        LINUX_CAPABILITIES
    }

    fn wireguard_manager(&self) -> &dyn WireGuardManager {
        &self.wg
    }

    fn route_manager(&self) -> &dyn RouteManager {
        &self.routes
    }

    fn resolver_manager(&self) -> &dyn ResolverManager {
        &self.resolver
    }

    fn service_manager(&self) -> &dyn ServiceManager {
        &self.service
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct PortableWireGuardManager;

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl WireGuardManager for PortableWireGuardManager {
    async fn apply(
        &self,
        netmap: &NetMap,
        state: &ClientState,
        cfg: &wg::WgConfig,
        routes_cfg: Option<&routes::RouteApplyConfig>,
    ) -> Result<()> {
        wg::apply(netmap, state, cfg, routes_cfg).await
    }

    async fn remove(&self, interface: &str, backend: wg::Backend) -> Result<()> {
        wg::remove(interface, backend).await
    }

    fn probe_peers(&self, netmap: &NetMap, timeout_seconds: u64) -> Result<()> {
        wg::probe_peers(netmap, timeout_seconds)
    }

    fn refresh_peer_endpoints(
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
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct PortableRouteManager;

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl RouteManager for PortableRouteManager {
    async fn apply_advertised_routes(
        &self,
        _netmap: &NetMap,
        _cfg: &routes::RouteApplyConfig,
    ) -> Result<()> {
        Err(anyhow!(
            "advertised route programming is unsupported on this platform"
        ))
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct PortableResolverManager;

#[cfg(not(target_os = "linux"))]
impl ResolverManager for PortableResolverManager {
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
#[derive(Default)]
struct PortableServiceManager;

#[cfg(not(target_os = "linux"))]
impl ServiceManager for PortableServiceManager {
    fn daemon_supervision(&self) -> SupportLevel {
        SupportLevel::Supported
    }

    fn os_service_integration(&self) -> SupportLevel {
        SupportLevel::Unsupported
    }
}

#[cfg(not(target_os = "linux"))]
pub struct PortableDataPlane {
    wg: PortableWireGuardManager,
    routes: PortableRouteManager,
    resolver: PortableResolverManager,
    service: PortableServiceManager,
}

#[cfg(not(target_os = "linux"))]
impl Default for PortableDataPlane {
    fn default() -> Self {
        Self {
            wg: PortableWireGuardManager,
            routes: PortableRouteManager,
            resolver: PortableResolverManager,
            service: PortableServiceManager,
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl DataPlane for PortableDataPlane {
    fn capabilities(&self) -> DataPlaneCapabilities {
        PORTABLE_CAPABILITIES
    }

    fn wireguard_manager(&self) -> &dyn WireGuardManager {
        &self.wg
    }

    fn route_manager(&self) -> &dyn RouteManager {
        &self.routes
    }

    fn resolver_manager(&self) -> &dyn ResolverManager {
        &self.resolver
    }

    fn service_manager(&self) -> &dyn ServiceManager {
        &self.service
    }
}

pub fn for_current_platform() -> Box<dyn DataPlane> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxDataPlane::default())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(PortableDataPlane::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_supported, for_current_platform};
    use crate::platform::SupportLevel;

    #[test]
    fn ensure_supported_allows_supported_or_partial() {
        ensure_supported(SupportLevel::Supported, "feature", "cmd")
            .expect("supported capability should pass");
        ensure_supported(SupportLevel::Partial, "feature", "cmd")
            .expect("partial capability should pass");
        assert!(ensure_supported(SupportLevel::Unsupported, "feature", "cmd").is_err());
    }

    #[test]
    fn platform_capabilities_are_present() {
        let data_plane = for_current_platform();
        let caps = data_plane.capabilities();
        assert_ne!(caps.wireguard, SupportLevel::Unsupported);
        assert_ne!(caps.dns_local_server, SupportLevel::Unsupported);
    }
}
