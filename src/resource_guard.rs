//! Resource Guard for WireGuard interface and nftables rules lifecycle management.
//!
//! Provides RAII pattern for automatic cleanup on drop, ensuring resources are
//! released even on panic or unexpected termination.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

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
        let Ok(raw_pid) = i32::try_from(pid) else {
            return false;
        };
        // kill(pid, 0) does not send a signal; it only checks process existence/permissions.
        let rc = unsafe { libc::kill(raw_pid, 0) };
        if rc == 0 {
            return true;
        }
        matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        )
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
pub async fn cleanup_all_lightscale_interfaces(exclude: Option<&str>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let netlink = crate::netlink::Netlink::new().await?;
        let names = netlink.list_link_names().await?;

        for name in names {
            if !name.starts_with("ls-") {
                continue;
            }
            if exclude == Some(name.as_str()) {
                eprintln!("pre-start: skipping current interface {}", name);
                continue;
            }

            eprintln!("pre-start: cleaning up existing interface {}", name);
            if let Err(kernel_err) = crate::wg::remove(&name, crate::wg::Backend::Kernel).await {
                if let Err(userspace_err) =
                    crate::wg::remove(&name, crate::wg::Backend::Boringtun).await
                {
                    eprintln!(
                        "pre-start: failed to remove interface {} (kernel: {}; userspace: {})",
                        name, kernel_err, userspace_err
                    );
                }
            }
        }
    }

    Ok(())
}
