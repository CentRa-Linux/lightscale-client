use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProfileConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_control_urls",
        alias = "control_url"
    )]
    pub control_urls: Vec<String>,
    #[serde(default)]
    pub tls_pinned_sha256: Option<String>,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    #[serde(default)]
    pub agent_args: Vec<String>,
}

fn deserialize_control_urls<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ControlUrls {
        One(String),
        Many(Vec<String>),
    }

    let raw = Option::<ControlUrls>::deserialize(deserializer)?;
    let mut urls = match raw {
        Some(ControlUrls::One(url)) => vec![url],
        Some(ControlUrls::Many(urls)) => urls,
        None => Vec::new(),
    };
    urls.retain(|url| !url.trim().is_empty());
    Ok(urls)
}

pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("lightscale").join("config.json"))
}

pub fn load_config(path: &Path) -> Result<ClientConfig> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(serde_json::from_str(&contents)?),
        Err(_) => Ok(ClientConfig::default()),
    }
}

pub fn save_config(path: &Path, config: &ClientConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(path, json)?;
    Ok(())
}
