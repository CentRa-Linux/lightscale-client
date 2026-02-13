use crate::model::NetMap;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientState {
    pub profile: String,
    pub network_id: String,
    pub node_id: String,
    pub node_name: String,
    pub machine_private_key: String,
    pub machine_public_key: String,
    pub wg_private_key: String,
    pub wg_public_key: String,
    #[serde(default)]
    pub node_token: Option<String>,
    pub ipv4: String,
    pub ipv6: String,
    pub last_netmap: Option<NetMap>,
    pub updated_at: i64,
}

pub fn default_state_dir(profile: &str) -> Option<PathBuf> {
    // Keep state isolated per profile to allow future multi-network support.
    dirs::data_dir().map(|dir| dir.join("lightscale").join(profile))
}

pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("state.json")
}

pub fn load_state(path: &Path) -> Result<Option<ClientState>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(serde_json::from_str(&contents)?)),
        Err(_) => Ok(None),
    }
}

pub fn save_state(path: &Path, state: &ClientState) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(path, json)?;
    Ok(())
}
