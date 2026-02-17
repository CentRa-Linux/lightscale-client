//! Resource Guard for WireGuard interface and nftables rules lifecycle management.
//!
//! Provides RAII pattern for automatic cleanup on drop, ensuring resources are
//! released even on panic or unexpected termination.

use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::RwLock;

/// Marker trait for identifying lightscale-managed resources.
pub trait LightscaleResource {
    /// Returns the resource identifier with lightscale prefix.
    fn lightscale_id(&self) -> String;
}

/// Resource types that can be managed by lightscale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    WireGuardInterface,
    NftablesTable,
    NftablesChain,
    Route,
}

impl ResourceType {
    /// Returns the identifying prefix for this resource type.
    pub const fn prefix(&self) -> &'static str {
        match self {
            ResourceType::WireGuardInterface => "ls-",
            ResourceType::NftablesTable => "lightscale",
            ResourceType::NftablesChain => "ls-",
            ResourceType::Route => "lightscale",
        }
    }

    /// Checks if the given name is managed by lightscale.
    pub fn is_managed(&self, name: &str) -> bool {
        match self {
            ResourceType::WireGuardInterface => name.starts_with(self.prefix()),
            ResourceType::NftablesTable => name.starts_with(self.prefix()),
            ResourceType::NftablesChain => name.starts_with(self.prefix()),
            ResourceType::Route => name.contains(self.prefix()),
        }
    }
}

/// Manages PID file for single-instance enforcement and process tracking.
pub struct PidFileGuard {
    path: std::path::PathBuf,
}

impl PidFileGuard {
    /// Create and lock a PID file, returning None if already locked by another process.
    pub fn acquire(path: &std::path::Path) -> Result<Option<Self>> {
        let pid = std::process::id();

        // Check if PID file exists and process is still running
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            if let Ok(old_pid) = contents.trim().parse::<u32>() {
                if old_pid != pid && Self::process_exists(old_pid) {
                    return Ok(None); // Another instance is running
                }
            }
            // Stale PID file, remove it
            let _ = std::fs::remove_file(path);
        }

        // Write current PID
        std::fs::write(path, format!("{}\n", pid))?;

        Ok(Some(Self {
            path: path.to_path_buf(),
        }))
    }

    /// Release the PID file lock.
    pub fn release(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        use std::process::Command;
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    fn process_exists(_pid: u32) -> bool {
        false // Assume not exists on non-unix
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// Callback type for cleanup operations.
type CleanupFn = Box<dyn FnOnce() + Send + Sync>;

/// Guard that ensures cleanup runs even if the program panics or is interrupted.
pub struct ResourceGuard {
    cleanup: Option<CleanupFn>,
    disabled: bool,
}

impl ResourceGuard {
    /// Create a new guard with the given cleanup function.
    pub fn new<F>(cleanup: F) -> Self
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        Self {
            cleanup: Some(Box::new(cleanup)),
            disabled: false,
        }
    }

    /// Create an empty guard with no cleanup.
    pub fn empty() -> Self {
        Self {
            cleanup: None,
            disabled: false,
        }
    }

    /// Disable cleanup (e.g., on successful completion).
    pub fn disable(&mut self) {
        self.disabled = true;
    }

    /// Enable cleanup.
    pub fn enable(&mut self) {
        self.disabled = false;
    }

    /// Manually trigger cleanup.
    pub fn cleanup(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        if !self.disabled {
            if let Some(cleanup) = self.cleanup.take() {
                cleanup();
            }
        }
    }
}

/// Shared resource guard for async contexts.
pub struct SharedResourceGuard {
    inner: Arc<RwLock<Option<CleanupFn>>>,
}

impl SharedResourceGuard {
    /// Create a new shared guard.
    pub fn new<F>(cleanup: F) -> Self
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        Self {
            inner: Arc::new(RwLock::new(Some(Box::new(cleanup)))),
        }
    }

    /// Create an empty shared guard.
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Disable cleanup.
    pub async fn disable(&self) {
        let mut guard = self.inner.write().await;
        *guard = None;
    }

    /// Trigger cleanup manually.
    pub async fn cleanup(&self) {
        let mut guard = self.inner.write().await;
        if let Some(cleanup) = guard.take() {
            cleanup();
        }
    }
}

impl Clone for SharedResourceGuard {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for SharedResourceGuard {
    fn drop(&mut self) {
        // Only run cleanup if this is the last reference
        if Arc::strong_count(&self.inner) == 1 {
            if let Ok(guard) = self.inner.try_write() {
                if let Some(cleanup) = guard.as_ref() {
                    // We can't call the closure directly here due to lifetime issues,
                    // but since we're the last reference, we can spawn a blocking task
                    // or just log. For now, we rely on explicit cleanup in async contexts.
                }
            }
        }
    }
}

/// Creates a cleanup scope where resources are guaranteed to be cleaned up.
pub async fn with_cleanup<F, Fut, T>(cleanup: F, f: impl FnOnce() -> Fut) -> T
where
    F: FnOnce() + Send + Sync + 'static,
    Fut: Future<Output = T>,
{
    let guard = ResourceGuard::new(cleanup);
    let result = f().await;
    // Cleanup will run on drop even if f() panics
    drop(guard);
    result
}

/// Guard that holds references to managed resources for cleanup on drop.
pub struct ManagedResources {
    interface: Option<String>,
    backend: crate::wg::Backend,
    nftables_enabled: bool,
    disabled: bool,
}

impl ManagedResources {
    /// Create a new managed resources guard.
    pub fn new() -> Self {
        Self {
            interface: None,
            backend: crate::wg::Backend::Kernel,
            nftables_enabled: false,
            disabled: false,
        }
    }

    /// Set the WireGuard interface to manage.
    pub fn set_interface(&mut self, name: String, backend: crate::wg::Backend) {
        self.interface = Some(name);
        self.backend = backend;
    }

    /// Enable nftables cleanup.
    pub fn set_nftables_enabled(&mut self, enabled: bool) {
        self.nftables_enabled = enabled;
    }

    /// Disable cleanup (on successful shutdown).
    pub fn disable_cleanup(&mut self) {
        self.disabled = true;
    }

    /// Perform synchronous cleanup.
    fn do_cleanup(&self) {
        if self.disabled {
            return;
        }

        // Clean up nftables rules
        if self.nftables_enabled {
            if let Err(e) = crate::firewall::reset_tables() {
                eprintln!("cleanup: failed to reset nftables: {}", e);
            } else {
                eprintln!("cleanup: nftables rules removed");
            }
        }

        // Clean up WireGuard interface (using tokio runtime if available, or blocking)
        if let Some(ref iface) = self.interface {
            // Try to use blocking cleanup for sync contexts
            let iface = iface.clone();
            let backend = self.backend;

            // Run in a new tokio runtime if needed, or use blocking approach
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let _ = rt.block_on(async move {
                    if let Err(e) = crate::wg::remove(&iface, backend).await {
                        eprintln!("cleanup: failed to remove wireguard interface: {}", e);
                    } else {
                        eprintln!("cleanup: wireguard interface {} removed", iface);
                    }
                });
            } else {
                // No runtime available, try blocking approach
                eprintln!("cleanup: cannot remove wireguard interface {} (no async runtime)", iface);
            }
        }
    }
}

impl Default for ManagedResources {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ManagedResources {
    fn drop(&mut self) {
        self.do_cleanup();
    }
}

/// Async version of managed resources guard.
pub struct AsyncManagedResources {
    inner: Arc<RwLock<ManagedResources>>,
}

impl AsyncManagedResources {
    /// Create a new async managed resources guard.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ManagedResources::new())),
        }
    }

    /// Set the WireGuard interface.
    pub async fn set_interface(&self, name: String, backend: crate::wg::Backend) {
        let mut guard = self.inner.write().await;
        guard.set_interface(name, backend);
    }

    /// Enable nftables cleanup.
    pub async fn set_nftables_enabled(&self, enabled: bool) {
        let mut guard = self.inner.write().await;
        guard.set_nftables_enabled(enabled);
    }

    /// Disable cleanup (on successful shutdown).
    pub async fn disable_cleanup(&self) {
        let mut guard = self.inner.write().await;
        guard.disable_cleanup();
    }

    /// Perform async cleanup.
    pub async fn cleanup(&self) {
        let inner = self.inner.read().await;
        if inner.disabled {
            return;
        }

        // Clean up nftables rules
        if inner.nftables_enabled {
            if let Err(e) = crate::firewall::reset_tables() {
                eprintln!("cleanup: failed to reset nftables: {}", e);
            } else {
                eprintln!("cleanup: nftables rules removed");
            }
        }

        // Clean up WireGuard interface
        if let Some(ref iface) = inner.interface {
            if let Err(e) = crate::wg::remove(iface, inner.backend).await {
                eprintln!("cleanup: failed to remove wireguard interface: {}", e);
            } else {
                eprintln!("cleanup: wireguard interface {} removed", iface);
            }
        }
    }
}

impl Default for AsyncManagedResources {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AsyncManagedResources {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Clean up any existing lightscale resources before starting.
pub async fn cleanup_existing_resources(interface: Option<&str>) -> Result<()> {
    // Clean up nftables rules
    if let Err(e) = crate::firewall::reset_tables() {
        eprintln!("pre-start: failed to reset nftables (may be expected): {}", e);
    } else {
        eprintln!("pre-start: nftables rules cleaned up");
    }

    // Clean up WireGuard interface if specified
    if let Some(iface) = interface {
        // Try both kernel and boringtun backends
        for backend in [crate::wg::Backend::Kernel, crate::wg::Backend::Boringtun] {
            match crate::wg::remove(iface, backend).await {
                Ok(_) => {
                    eprintln!("pre-start: removed existing wireguard interface {} ({:?})", iface, backend);
                    break;
                }
                Err(_) => {
                    // Interface may not exist or wrong backend, continue
                }
            }
        }
    }

    Ok(())
}

/// Clean up any existing resources by interface name pattern.
pub async fn cleanup_all_lightscale_interfaces() -> Result<()> {
    // List all wireguard interfaces and remove those matching our pattern
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        // Get list of all wireguard interfaces
        let output = Command::new("ip")
            .args(["link", "show", "type", "wireguard"])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                // Look for interface names starting with "ls-"
                if let Some(iface) = line
                    .split(':')
                    .next()
                    .and_then(|s| s.trim().strip_prefix("ls-"))
                    .map(|s| format!("ls-{}", s))
                {
                    eprintln!("pre-start: cleaning up existing interface {}", iface);
                    for backend in [crate::wg::Backend::Kernel, crate::wg::Backend::Boringtun] {
                        let _ = crate::wg::remove(&iface, backend).await;
                    }
                }
            }
        }
    }

    Ok(())
}
