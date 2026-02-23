use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Route {
    pub prefix: String,
    pub kind: RouteKind,
    pub enabled: bool,
    #[serde(default)]
    pub mapped_prefix: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    Subnet,
    Exit,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub id: String,
    pub name: String,
    pub overlay_v4: String,
    pub overlay_v6: String,
    pub dns_domain: String,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default)]
    pub key_rotation_max_age_seconds: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub dns_name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_public_key: String,
    pub machine_public_key: String,
    pub endpoints: Vec<String>,
    pub tags: Vec<String>,
    pub routes: Vec<Route>,
    pub last_seen: i64,
    #[serde(default = "default_true")]
    pub approved: bool,
    #[serde(default)]
    pub key_rotation_required: bool,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub dns_name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_public_key: String,
    pub endpoints: Vec<String>,
    pub tags: Vec<String>,
    pub routes: Vec<Route>,
    pub last_seen: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NetMap {
    pub network: NetworkInfo,
    pub node: NodeInfo,
    pub peers: Vec<PeerInfo>,
    pub relay: Option<RelayConfig>,
    #[serde(default)]
    pub probe_requests: Vec<ProbeRequest>,
    pub generated_at: i64,
    #[serde(default)]
    pub revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub peer_id: String,
    pub endpoints: Vec<String>,
    pub ipv4: String,
    pub ipv6: String,
    pub requested_at: i64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct RelayConfig {
    pub stun_servers: Vec<String>,
    pub turn_servers: Vec<String>,
    #[serde(default)]
    pub stream_relay_servers: Vec<String>,
    #[serde(default)]
    pub udp_relay_servers: Vec<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub token: String,
    pub node_name: String,
    pub machine_public_key: String,
    pub wg_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_token: String,
    pub netmap: NetMap,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterUrlRequest {
    pub network_id: String,
    pub node_name: String,
    pub machine_public_key: String,
    pub wg_public_key: String,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterUrlResponse {
    pub node_id: String,
    pub network_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub auth_path: String,
    pub expires_at: i64,
    pub node_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub token: String,
    pub expires_at: i64,
    pub uses_left: u32,
    pub tags: Vec<String>,
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub ttl_seconds: u64,
    pub uses: u32,
    pub tags: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateTokenResponse {
    pub token: EnrollmentToken,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AdminNodesResponse {
    pub nodes: Vec<NodeInfo>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ApproveNodeResponse {
    pub node_id: String,
    pub approved: bool,
    pub approved_at: Option<i64>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub endpoints: Vec<String>,
    pub listen_port: Option<u16>,
    pub routes: Vec<Route>,
    #[serde(default)]
    pub probe: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub netmap: NetMap,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AclPolicy {
    #[serde(default)]
    pub default_action: AclAction,
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AclSelector {
    #[serde(default)]
    pub any: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub node_ids: Vec<String>,
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub action: AclAction,
    #[serde(default)]
    pub src: AclSelector,
    #[serde(default)]
    pub dst: AclSelector,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct UpdateAclRequest {
    pub policy: AclPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateAclResponse {
    pub policy: AclPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateNodeRequest {
    pub name: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateNodeResponse {
    pub node: NodeInfo,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct KeyRotationPolicy {
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPolicyResponse {
    pub policy: KeyRotationPolicy,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Machine,
    WireGuard,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub key_type: KeyType,
    pub public_key: String,
    pub created_at: i64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    pub machine_public_key: Option<String>,
    pub wg_public_key: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRotationResponse {
    pub node_id: String,
    pub machine_public_key: String,
    pub wg_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyHistoryResponse {
    pub node_id: String,
    pub keys: Vec<KeyRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RevokeNodeResponse {
    pub node_id: String,
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: i64,
    pub network_id: Option<String>,
    pub node_id: Option<String>,
    pub action: String,
    #[serde(default)]
    pub detail: Option<serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditEntry>,
}
