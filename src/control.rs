use crate::model::{
    AclPolicy, AdminNodesResponse, ApproveNodeResponse, AuditLogResponse, CreateTokenRequest,
    CreateTokenResponse, EnrollmentToken, HeartbeatRequest, HeartbeatResponse, KeyHistoryResponse,
    KeyPolicyResponse, KeyRotationPolicy, KeyRotationRequest, KeyRotationResponse, NetMap,
    RegisterRequest, RegisterResponse, RegisterUrlRequest, RegisterUrlResponse, RevokeNodeResponse,
    UpdateAclRequest, UpdateAclResponse, UpdateNodeRequest, UpdateNodeResponse,
};
use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub struct ControlClient {
    base_urls: Vec<String>,
    client: reqwest::Client,
    next_index: AtomicUsize,
    node_token: Option<String>,
    admin_token: Option<String>,
}

impl ControlClient {
    pub fn new(
        base_urls: Vec<String>,
        tls_pin: Option<String>,
        node_token: Option<String>,
        admin_token: Option<String>,
    ) -> Result<Self> {
        let client = build_http_client(tls_pin)?;
        let base_urls = normalize_base_urls(base_urls);
        if base_urls.is_empty() {
            return Err(anyhow!("no control URL configured"));
        }
        Ok(Self {
            base_urls,
            client,
            next_index: AtomicUsize::new(0),
            node_token,
            admin_token,
        })
    }

    async fn send_with_failover<F>(&self, build: F) -> Result<reqwest::Response>
    where
        F: Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
    {
        let total = self.base_urls.len();
        let start = self.next_index.load(Ordering::Relaxed) % total;
        let mut last_err: Option<anyhow::Error> = None;

        for offset in 0..total {
            let index = (start + offset) % total;
            let base = &self.base_urls[index];
            let response = build(&self.client, base).send().await;
            match response {
                Ok(resp) => {
                    if resp.status().is_server_error() {
                        last_err = Some(anyhow!(
                            "control {} returned {}",
                            base,
                            resp.status()
                        ));
                        continue;
                    }
                    self.next_index.store(index, Ordering::Relaxed);
                    return Ok(resp);
                }
                Err(err) => {
                    if should_retry(&err) {
                        last_err = Some(anyhow!("control {} request failed: {}", base, err));
                        continue;
                    }
                    return Err(anyhow!(err).context(format!(
                        "control {} request failed",
                        base
                    )));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("no control servers available")))
    }

    fn endpoint_at(base: &str, path: &str) -> String {
        let base = base.trim_end_matches('/');
        format!("{}{}", base, path)
    }

    fn node_auth(&self) -> Option<&str> {
        self.node_token.as_deref()
    }

    fn admin_auth(&self) -> Option<&str> {
        self.admin_token.as_deref()
    }

    fn node_or_admin_auth(&self) -> Option<&str> {
        self.node_token
            .as_deref()
            .or_else(|| self.admin_token.as_deref())
    }

    pub async fn register(&self, request: RegisterRequest) -> Result<RegisterResponse> {
        let response = self
            .send_with_failover(|client, base| {
                client
                    .post(Self::endpoint_at(base, "/v1/register"))
                    .json(&request)
            })
            .await?
            .error_for_status()
            .context("register request failed")?;
        Ok(response.json().await?)
    }

    pub async fn register_url(&self, request: RegisterUrlRequest) -> Result<RegisterUrlResponse> {
        let response = self
            .send_with_failover(|client, base| {
                client
                    .post(Self::endpoint_at(base, "/v1/register-url"))
                    .json(&request)
            })
            .await?
            .error_for_status()
            .context("register-url request failed")?;
        Ok(response.json().await?)
    }

    pub async fn create_token(
        &self,
        network_id: &str,
        request: CreateTokenRequest,
    ) -> Result<CreateTokenResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client
                        .post(Self::endpoint_at(
                            base,
                            &format!("/v1/networks/{}/tokens", network_id),
                        ))
                        .json(&request),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("create token request failed")?;
        Ok(response.json().await?)
    }

    pub async fn revoke_token(&self, token_id: &str) -> Result<EnrollmentToken> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client.post(Self::endpoint_at(
                        base,
                        &format!("/v1/tokens/{}/revoke", token_id),
                    )),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("revoke token request failed")?;
        Ok(response.json().await?)
    }

    pub async fn approve_node(&self, node_id: &str) -> Result<ApproveNodeResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client.post(Self::endpoint_at(
                        base,
                        &format!("/v1/admin/nodes/{}/approve", node_id),
                    )),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("approve node request failed")?;
        Ok(response.json().await?)
    }

    pub async fn admin_nodes(&self, network_id: &str) -> Result<AdminNodesResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client.get(Self::endpoint_at(
                        base,
                        &format!("/v1/admin/networks/{}/nodes", network_id),
                    )),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("admin nodes request failed")?;
        Ok(response.json().await?)
    }

    pub async fn update_node(
        &self,
        node_id: &str,
        request: UpdateNodeRequest,
    ) -> Result<UpdateNodeResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client
                        .put(Self::endpoint_at(
                            base,
                            &format!("/v1/admin/nodes/{}", node_id),
                        ))
                        .json(&request),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("update node request failed")?;
        Ok(response.json().await?)
    }

    pub async fn get_acl(&self, network_id: &str) -> Result<AclPolicy> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client.get(Self::endpoint_at(
                        base,
                        &format!("/v1/networks/{}/acl", network_id),
                    )),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("acl policy request failed")?;
        Ok(response.json().await?)
    }

    pub async fn update_acl(
        &self,
        network_id: &str,
        request: UpdateAclRequest,
    ) -> Result<UpdateAclResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client
                        .put(Self::endpoint_at(
                            base,
                            &format!("/v1/networks/{}/acl", network_id),
                        ))
                        .json(&request),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("acl policy update failed")?;
        Ok(response.json().await?)
    }

    pub async fn get_key_policy(&self, network_id: &str) -> Result<KeyPolicyResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client.get(Self::endpoint_at(
                        base,
                        &format!("/v1/networks/{}/key-policy", network_id),
                    )),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("key policy request failed")?;
        Ok(response.json().await?)
    }

    pub async fn update_key_policy(
        &self,
        network_id: &str,
        request: KeyRotationPolicy,
    ) -> Result<KeyPolicyResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client
                        .put(Self::endpoint_at(
                            base,
                            &format!("/v1/networks/{}/key-policy", network_id),
                        ))
                        .json(&request),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("key policy update failed")?;
        Ok(response.json().await?)
    }

    pub async fn rotate_keys(
        &self,
        node_id: &str,
        request: KeyRotationRequest,
    ) -> Result<KeyRotationResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client
                        .post(Self::endpoint_at(
                            base,
                            &format!("/v1/nodes/{}/rotate-keys", node_id),
                        ))
                        .json(&request),
                    self.node_or_admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("key rotation failed")?;
        Ok(response.json().await?)
    }

    pub async fn revoke_node(&self, node_id: &str) -> Result<RevokeNodeResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client.post(Self::endpoint_at(
                        base,
                        &format!("/v1/nodes/{}/revoke", node_id),
                    )),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("revoke node failed")?;
        Ok(response.json().await?)
    }

    pub async fn node_keys(&self, node_id: &str) -> Result<KeyHistoryResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client.get(Self::endpoint_at(
                        base,
                        &format!("/v1/nodes/{}/keys", node_id),
                    )),
                    self.node_or_admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("key history request failed")?;
        Ok(response.json().await?)
    }

    pub async fn audit_log(
        &self,
        network_id: Option<&str>,
        node_id: Option<&str>,
        limit: Option<usize>,
    ) -> Result<AuditLogResponse> {
        let mut params = Vec::new();
        if let Some(network_id) = network_id {
            params.push(("network_id", network_id.to_string()));
        }
        if let Some(node_id) = node_id {
            params.push(("node_id", node_id.to_string()));
        }
        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client
                        .get(Self::endpoint_at(base, "/v1/audit"))
                        .query(&params),
                    self.admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("audit log request failed")?;
        Ok(response.json().await?)
    }

    pub async fn heartbeat(&self, request: HeartbeatRequest) -> Result<HeartbeatResponse> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client
                        .post(Self::endpoint_at(base, "/v1/heartbeat"))
                        .json(&request),
                    self.node_or_admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("heartbeat request failed")?;
        Ok(response.json().await?)
    }

    pub async fn netmap(&self, node_id: &str) -> Result<NetMap> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client.get(Self::endpoint_at(
                        base,
                        &format!("/v1/netmap/{}", node_id),
                    )),
                    self.node_or_admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("netmap request failed")?;
        Ok(response.json().await?)
    }

    pub async fn netmap_longpoll(
        &self,
        node_id: &str,
        since: u64,
        timeout_seconds: u64,
    ) -> Result<NetMap> {
        let response = self
            .send_with_failover(|client, base| {
                with_bearer(
                    client
                        .get(Self::endpoint_at(
                            base,
                            &format!("/v1/netmap/{}/longpoll", node_id),
                        ))
                        .query(&[
                            ("since", since.to_string()),
                            ("timeout_seconds", timeout_seconds.to_string()),
                        ]),
                    self.node_or_admin_auth(),
                )
            })
            .await?
            .error_for_status()
            .context("netmap longpoll request failed")?;
        Ok(response.json().await?)
    }
}

fn normalize_base_urls(urls: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for url in urls {
        let trimmed = url.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if !unique.contains(&trimmed) {
            unique.push(trimmed);
        }
    }
    unique
}

fn should_retry(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || err.is_request()
}

fn with_bearer(
    request: reqwest::RequestBuilder,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    if let Some(token) = token {
        request.bearer_auth(token)
    } else {
        request
    }
}

#[derive(Debug)]
struct PinnedServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pin: Vec<u8>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let digest = hasher.finalize();
        if digest.as_slice() != self.pin.as_slice() {
            return Err(rustls::Error::General("tls pin mismatch".to_string()));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn build_http_client(tls_pin: Option<String>) -> Result<reqwest::Client> {
    if let Some(pin) = tls_pin {
        let expected = decode_pin(&pin)?;
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots.clone()))
            .build()
            .map_err(|err| anyhow!("failed to build tls verifier: {}", err))?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut config = config;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(PinnedServerCertVerifier {
                inner: verifier,
                pin: expected,
            }));
        Ok(reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .build()?)
    } else {
        Ok(reqwest::Client::new())
    }
}

fn decode_pin(pin: &str) -> Result<Vec<u8>> {
    let normalized: String = pin
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ':')
        .collect();
    let bytes = hex::decode(normalized).map_err(|_| anyhow!("invalid tls pin hex"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("tls pin must be 32 bytes (sha256)"));
    }
    Ok(bytes)
}
