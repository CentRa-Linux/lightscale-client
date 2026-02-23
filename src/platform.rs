use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportLevel {
    Supported,
    Partial,
    Unsupported,
}

impl SupportLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            SupportLevel::Supported => "supported",
            SupportLevel::Partial => "partial",
            SupportLevel::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PlatformProfile {
    pub os: &'static str,
    pub arch: &'static str,
    pub control_plane: SupportLevel,
    pub data_plane: SupportLevel,
    pub service_integration: SupportLevel,
    pub service_managers: &'static [&'static str],
    pub note: &'static str,
}

pub fn current() -> PlatformProfile {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    match os {
        "linux" => PlatformProfile {
            os,
            arch,
            control_plane: SupportLevel::Supported,
            data_plane: SupportLevel::Supported,
            service_integration: SupportLevel::Supported,
            service_managers: &["systemd", "openrc", "procd", "none"],
            note: "linux is the primary supported platform for both control and data plane",
        },
        "windows" | "macos" | "android" | "ios" => PlatformProfile {
            os,
            arch,
            control_plane: SupportLevel::Partial,
            data_plane: SupportLevel::Partial,
            service_integration: SupportLevel::Unsupported,
            service_managers: &["none"],
            note: "control-plane commands are expected to work; non-linux data-plane support is experimental",
        },
        _ => PlatformProfile {
            os,
            arch,
            control_plane: SupportLevel::Partial,
            data_plane: SupportLevel::Unsupported,
            service_integration: SupportLevel::Unsupported,
            service_managers: &["none"],
            note: "this platform is not an official target yet; use control-plane commands only",
        },
    }
}

pub fn require_linux_data_plane(command_name: &str) -> Result<()> {
    require_data_plane_for(current(), command_name)
}

pub fn require_data_plane(command_name: &str) -> Result<()> {
    require_any_data_plane_for(current(), command_name)
}

pub fn require_linux_service_integration(command_name: &str) -> Result<()> {
    require_service_integration_for(current(), command_name)
}

fn require_data_plane_for(profile: PlatformProfile, command_name: &str) -> Result<()> {
    if profile.data_plane == SupportLevel::Supported {
        return Ok(());
    }
    Err(anyhow!(
        "{} is only supported on linux (host: {}-{}); use control-plane commands (init/register/netmap/status) on this platform",
        command_name,
        profile.os,
        profile.arch
    ))
}

fn require_any_data_plane_for(profile: PlatformProfile, command_name: &str) -> Result<()> {
    if profile.data_plane != SupportLevel::Unsupported {
        return Ok(());
    }
    Err(anyhow!(
        "{} data-plane is unsupported on host: {}-{}; use control-plane commands (init/register/netmap/status) on this platform",
        command_name,
        profile.os,
        profile.arch
    ))
}

fn require_service_integration_for(profile: PlatformProfile, command_name: &str) -> Result<()> {
    if profile.service_integration == SupportLevel::Supported {
        return Ok(());
    }
    Err(anyhow!(
        "{} service integration is only supported on linux (host: {}-{})",
        command_name,
        profile.os,
        profile.arch
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        current, require_any_data_plane_for, require_data_plane_for,
        require_service_integration_for, PlatformProfile, SupportLevel,
    };

    fn partial_profile() -> PlatformProfile {
        PlatformProfile {
            os: "macos",
            arch: "x86_64",
            control_plane: SupportLevel::Partial,
            data_plane: SupportLevel::Unsupported,
            service_integration: SupportLevel::Unsupported,
            service_managers: &["none"],
            note: "control-plane only",
        }
    }

    fn experimental_data_plane_profile() -> PlatformProfile {
        PlatformProfile {
            os: "macos",
            arch: "x86_64",
            control_plane: SupportLevel::Partial,
            data_plane: SupportLevel::Partial,
            service_integration: SupportLevel::Unsupported,
            service_managers: &["none"],
            note: "experimental data-plane",
        }
    }

    #[test]
    fn current_platform_has_non_empty_identity() {
        let profile = current();
        assert!(!profile.os.is_empty());
        assert!(!profile.arch.is_empty());
    }

    #[test]
    fn linux_is_expected_to_be_fully_supported() {
        if std::env::consts::OS == "linux" {
            let profile = current();
            assert_eq!(profile.control_plane, SupportLevel::Supported);
            assert_eq!(profile.data_plane, SupportLevel::Supported);
        }
    }

    #[test]
    fn unsupported_data_plane_returns_clear_error() {
        let err = require_data_plane_for(partial_profile(), "wg-up")
            .expect_err("unsupported profile should return an error");
        let text = format!("{}", err);
        assert!(text.contains("wg-up"));
        assert!(text.contains("only supported on linux"));
    }

    #[test]
    fn unsupported_service_integration_returns_clear_error() {
        let err = require_service_integration_for(partial_profile(), "dns-serve --apply-resolver")
            .expect_err("unsupported profile should return an error");
        let text = format!("{}", err);
        assert!(text.contains("dns-serve --apply-resolver"));
        assert!(text.contains("service integration is only supported on linux"));
    }

    #[test]
    fn partial_data_plane_is_accepted_for_experimental_platforms() {
        require_any_data_plane_for(experimental_data_plane_profile(), "wg-up")
            .expect("partial data-plane support should pass generic data-plane requirement");
    }
}
