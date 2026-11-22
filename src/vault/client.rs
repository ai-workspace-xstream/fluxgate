use crate::config::ast::{SecretRef, VaultAuthMode, VaultConfig, VaultSyncSpec};
use crate::error::{FluxgateError, Result};
use crate::metrics::MetricsRegistry;
use crate::vault::store::SecretStore;
use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

const TOKEN_RENEW_LEEWAY_SECS: i64 = 60;
const MIN_BACKOFF_SECS: u64 = 5;
const MIN_MAX_BACKOFF_SECS: u64 = 60;

#[derive(Clone)]
pub struct Kv2ReadResult {
    pub data: HashMap<String, Zeroizing<String>>,
    pub version: u64,
}

impl fmt::Debug for Kv2ReadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys: Vec<&str> = self.data.keys().map(String::as_str).collect();
        keys.sort_unstable();
        f.debug_struct("Kv2ReadResult")
            .field("version", &self.version)
            .field("keys", &keys)
            .finish()
    }
}

struct TokenState {
    token: Zeroizing<String>,
    expires_at_unix: Option<i64>,
    renewable: bool,
}

impl Default for TokenState {
    fn default() -> Self {
        Self {
            token: Zeroizing::new(String::new()),
            expires_at_unix: None,
            renewable: false,
        }
    }
}

impl fmt::Debug for TokenState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenState")
            .field("has_token", &(!self.token.is_empty()))
            .field("expires_at_unix", &self.expires_at_unix)
            .field("renewable", &self.renewable)
            .finish()
    }
}

#[derive(Deserialize)]
struct VaultAuthResponse {
    auth: Option<VaultAuthPayload>,
}

#[derive(Deserialize)]
struct VaultAuthPayload {
    #[serde(default)]
    client_token: String,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

#[derive(Serialize)]
struct AppRoleLoginRequest<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

#[derive(Deserialize)]
struct Kv2ReadEnvelope {
    data: Option<Kv2OuterData>,
}

#[derive(Deserialize)]
struct Kv2OuterData {
    data: Option<serde_json::Value>,
    metadata: Option<Kv2Metadata>,
}

#[derive(Deserialize)]
struct Kv2Metadata {
    version: u64,
}

#[derive(Serialize)]
struct Kv2WriteOptions {
    cas: u64,
}

#[derive(Serialize)]
struct Kv2WriteRequest<'a> {
    options: Kv2WriteOptions,
    data: &'a serde_json::Value,
}

#[derive(Deserialize)]
struct Kv2WriteEnvelope {
    data: Option<Kv2WriteMetadata>,
}

#[derive(Deserialize)]
struct Kv2WriteMetadata {
    version: Option<u64>,
}

#[derive(Clone)]
pub struct VaultClient {
    addr: String,
    namespace: Option<String>,
    auth_mode: VaultAuthMode,
    http: reqwest::Client,
    token_state: Arc<RwLock<TokenState>>,
    auth_lock: Arc<Mutex<()>>,
}

impl fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultClient")
            .field("addr", &self.addr)
            .field("namespace", &self.namespace)
            .field("auth_mode", &self.auth_mode)
            .finish()
    }
}

impl VaultClient {
    pub fn new(
        addr: &str,
        auth_mode: VaultAuthMode,
        namespace: Option<String>,
        ca_cert: Option<&Path>,
    ) -> Result<Self> {
        let trimmed_addr = addr.trim().trim_end_matches('/').to_string();
        if trimmed_addr.is_empty() {
            return Err(FluxgateError::VaultError(
                "Vault address cannot be empty".to_string(),
            ));
        }

        let normalized_ns = namespace
            .map(|ns| ns.trim().to_string())
            .filter(|ns| !ns.is_empty());

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20));

        if let Some(ca_path) = ca_cert {
            let pem_bytes = std::fs::read(ca_path).map_err(|e| {
                FluxgateError::VaultError(format!(
                    "Failed to read Vault CA certificate '{}': {}",
                    ca_path.display(),
                    e
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem_bytes).map_err(|e| {
                FluxgateError::VaultError(format!(
                    "Invalid PEM in Vault CA certificate '{}': {}",
                    ca_path.display(),
                    e
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        let http = builder
            .build()
            .map_err(|e| vault_http_err("client initialization", e))?;

        Ok(Self {
            addr: trimmed_addr,
            namespace: normalized_ns,
            auth_mode,
            http,
            token_state: Arc::new(RwLock::new(TokenState::default())),
            auth_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn new_unauthenticated(cfg: &VaultConfig) -> Result<Self> {
        let addr = resolve_non_vault_ref(&cfg.addr, "addr")?;
        let namespace = match &cfg.namespace {
            Some(ns_ref) => {
                let ns = resolve_non_vault_ref(ns_ref, "namespace")?;
                if ns.is_empty() {
                    None
                } else {
                    Some(ns)
                }
            }
            None => None,
        };
        Self::new(&addr, cfg.auth.clone(), namespace, cfg.ca_cert.as_deref())
    }

    pub async fn from_config(cfg: &VaultConfig) -> Result<Self> {
        let client = Self::new_unauthenticated(cfg)?;
        client.ensure_authenticated().await?;
        Ok(client)
    }

    pub fn set_static_token(&self, token: impl Into<String>) {
        let raw = Zeroizing::new(token.into());
        let trimmed = Zeroizing::new(raw.trim().to_string());
        for _ in 0..1000 {
            if let Ok(mut guard) = self.token_state.try_write() {
                guard.token = trimmed;
                guard.expires_at_unix = None;
                guard.renewable = false;
                return;
            }
            std::thread::yield_now();
        }
        tracing::warn!("VaultClient::set_static_token could not acquire token_state write lock");
    }

    pub async fn ensure_authenticated(&self) -> Result<()> {
        let now_unix = current_unix_secs();
        {
            let (token, expires_at_unix, _) = self.token_snapshot().await;
            if !token.is_empty() && !is_close_to_expiry(expires_at_unix, now_unix) {
                return Ok(());
            }
        }

        let _auth_guard = self.auth_lock.lock().await;
        let now_unix = current_unix_secs();
        let (token, expires_at_unix, renewable) = self.token_snapshot().await;
        if !token.is_empty() && !is_close_to_expiry(expires_at_unix, now_unix) {
            return Ok(());
        }

        match self.auth_mode {
            VaultAuthMode::AppRole => {
                if !token.is_empty() && renewable {
                    match self.renew_self(&token).await {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            tracing::warn!(
                                "Vault renew-self failed ({}); falling back to AppRole login",
                                e
                            );
                        }
                    }
                }
                self.approle_login().await
            }
            VaultAuthMode::Token => {
                if token.is_empty() {
                    let loaded = load_credential("VAULT_TOKEN", "vault_token")?;
                    self.store_token(loaded, None, false).await;
                    return Ok(());
                }

                if renewable {
                    match self.renew_self(&token).await {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            if matches!(expires_at_unix, Some(exp) if exp <= now_unix) {
                                return Err(e);
                            }
                            tracing::warn!(
                                "Vault token renew-self failed while token still valid: {}",
                                e
                            );
                            return Ok(());
                        }
                    }
                }

                if matches!(expires_at_unix, Some(exp) if exp <= now_unix) {
                    return Err(FluxgateError::VaultError(
                        "Vault token has expired and is not renewable".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }

    pub async fn read_kv2(&self, kv_path: &str) -> Result<Kv2ReadResult> {
        let (data_val, version) = self.read_kv2_json(kv_path).await?.ok_or_else(|| {
            FluxgateError::VaultError(format!(
                "Vault KV v2 path '{}' not found or has no active secret data",
                kv_path
            ))
        })?;

        let obj = match data_val {
            serde_json::Value::Object(map) => map,
            _ => {
                return Err(FluxgateError::VaultError(format!(
                    "Vault KV v2 path '{}' returned non-object data payload",
                    kv_path
                )));
            }
        };

        let mut data = HashMap::with_capacity(obj.len());
        for (key, value) in obj {
            match value {
                serde_json::Value::String(s) => {
                    data.insert(key, Zeroizing::new(s));
                }
                serde_json::Value::Number(n) => {
                    data.insert(key, Zeroizing::new(n.to_string()));
                }
                serde_json::Value::Bool(b) => {
                    data.insert(key, Zeroizing::new(b.to_string()));
                }
                serde_json::Value::Null => {}
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                    tracing::debug!(
                        "Skipping non-scalar key '{}' while reading Vault KV v2 path '{}'",
                        key,
                        kv_path
                    );
                }
            }
        }

        Ok(Kv2ReadResult { data, version })
    }

    pub async fn read_kv2_json(&self, kv_path: &str) -> Result<Option<(serde_json::Value, u64)>> {
        let url = self.build_v1_url(kv_path);
        let resp = self.send_authed(|client| client.get(&url)).await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let detail = extract_vault_error(resp).await;
            return Err(FluxgateError::VaultError(format!(
                "Failed to read Vault KV v2 path '{}': {}",
                kv_path, detail
            )));
        }

        let envelope: Kv2ReadEnvelope = resp.json().await.map_err(|e| {
            FluxgateError::VaultError(format!(
                "Failed to parse Vault KV v2 response for '{}': {}",
                kv_path, e
            ))
        })?;

        let outer = envelope.data.ok_or_else(|| {
            FluxgateError::VaultError(format!(
                "Vault KV v2 response for '{}' missing outer 'data' field",
                kv_path
            ))
        })?;

        let metadata = outer.metadata.ok_or_else(|| {
            FluxgateError::VaultError(format!(
                "Vault KV v2 response for '{}' missing 'data.metadata' field",
                kv_path
            ))
        })?;

        match outer.data {
            Some(val) if !val.is_null() => Ok(Some((val, metadata.version))),
            _ => Ok(None),
        }
    }

    pub async fn write_kv2_cas(
        &self,
        kv_path: &str,
        data: &serde_json::Value,
        cas: u64,
    ) -> Result<u64> {
        let url = self.build_v1_url(kv_path);
        let body = Kv2WriteRequest {
            options: Kv2WriteOptions { cas },
            data,
        };

        let resp = self
            .send_authed(|client| client.post(&url).json(&body))
            .await?;

        let status = resp.status();
        if status == StatusCode::BAD_REQUEST || status == StatusCode::CONFLICT {
            let detail = extract_vault_error(resp).await;
            return Err(FluxgateError::VaultError(format!(
                "CAS conflict writing Vault KV v2 path '{}' (cas={}): {}",
                kv_path, cas, detail
            )));
        }

        if !status.is_success() {
            let detail = extract_vault_error(resp).await;
            return Err(FluxgateError::VaultError(format!(
                "Failed to write Vault KV v2 path '{}': {}",
                kv_path, detail
            )));
        }

        let text = resp.text().await.map_err(|e| {
            FluxgateError::VaultError(format!(
                "Failed to read Vault KV v2 write response for '{}': {}",
                kv_path, e
            ))
        })?;
        if text.trim().is_empty() {
            return Ok(cas + 1);
        }

        let envelope: Kv2WriteEnvelope = serde_json::from_str(&text).map_err(|e| {
            FluxgateError::VaultError(format!(
                "Failed to parse Vault KV v2 write response for '{}': {}",
                kv_path, e
            ))
        })?;

        let version = envelope.data.and_then(|m| m.version).unwrap_or(cas + 1);
        Ok(version)
    }

    pub async fn sync_once(
        &self,
        spec: &VaultSyncSpec,
        store: &SecretStore,
        metrics: Option<&MetricsRegistry>,
    ) -> Result<u64> {
        let now_unix = current_unix_secs();
        let existing_version = store.alias_version(&spec.alias);

        match self.read_kv2(&spec.kv_path).await {
            Ok(res) => {
                let version = res.version;
                if existing_version != Some(version) {
                    store.update_alias(&spec.alias, res.data, version, now_unix);
                    tracing::info!(
                        "Synced Vault KV alias '{}' (path '{}') at version {}",
                        spec.alias,
                        spec.kv_path,
                        version
                    );
                } else {
                    tracing::debug!(
                        "Vault KV alias '{}' unchanged at version {}",
                        spec.alias,
                        version
                    );
                }
                if let Some(m) = metrics {
                    m.record_vault_sync(&spec.alias, true, version, now_unix);
                }
                Ok(version)
            }
            Err(e) => {
                tracing::warn!(
                    "Vault sync failed for '{}' ({}): {}; keeping cached version {:?}",
                    spec.alias,
                    spec.kv_path,
                    e,
                    existing_version
                );
                if let Some(m) = metrics {
                    m.record_vault_sync(
                        &spec.alias,
                        false,
                        existing_version.unwrap_or(0),
                        now_unix,
                    );
                }
                Err(e)
            }
        }
    }

    async fn send_authed<F>(&self, mut build_req: F) -> Result<reqwest::Response>
    where
        F: FnMut(&reqwest::Client) -> reqwest::RequestBuilder,
    {
        self.ensure_authenticated().await?;
        let token = self.current_token().await;
        let req = self.with_vault_headers(build_req(&self.http), token.as_str());
        let resp = req
            .send()
            .await
            .map_err(|e| vault_http_err("HTTP request", e))?;

        if (resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN)
            && self.auth_mode == VaultAuthMode::AppRole
        {
            tracing::warn!(
                "Vault returned {} for AppRole token; attempting re-authentication",
                resp.status()
            );
            self.force_reauthenticate(token.as_str()).await?;
            let fresh_token = self.current_token().await;
            let retry_req = self.with_vault_headers(build_req(&self.http), fresh_token.as_str());
            return retry_req
                .send()
                .await
                .map_err(|e| vault_http_err("HTTP retry request", e));
        }

        Ok(resp)
    }

    async fn force_reauthenticate(&self, failed_token: &str) -> Result<()> {
        let _auth_guard = self.auth_lock.lock().await;
        let current = self.current_token().await;
        if !current.is_empty() && current.as_str() != failed_token {
            return Ok(());
        }
        self.approle_login().await
    }

    async fn approle_login(&self) -> Result<()> {
        let role_id = load_credential("VAULT_ROLE_ID", "vault_role_id")?;
        let secret_id = load_credential("VAULT_SECRET_ID", "vault_secret_id")?;

        let url = format!("{}/v1/auth/approle/login", self.addr);
        let payload = AppRoleLoginRequest {
            role_id: role_id.as_str(),
            secret_id: secret_id.as_str(),
        };

        let mut req = self.http.post(&url).json(&payload);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| vault_http_err("AppRole login request", e))?;

        if !resp.status().is_success() {
            let detail = extract_vault_error(resp).await;
            return Err(FluxgateError::VaultError(format!(
                "Vault AppRole login failed: {}",
                detail
            )));
        }

        let parsed: VaultAuthResponse = resp.json().await.map_err(|e| {
            FluxgateError::VaultError(format!(
                "Failed to parse Vault AppRole login response: {}",
                e
            ))
        })?;

        let auth = parsed.auth.ok_or_else(|| {
            FluxgateError::VaultError(
                "Vault AppRole login response missing 'auth' object".to_string(),
            )
        })?;

        if auth.client_token.is_empty() {
            return Err(FluxgateError::VaultError(
                "Vault AppRole login response missing 'auth.client_token'".to_string(),
            ));
        }

        let now_unix = current_unix_secs();
        let expires_at_unix = compute_expiry(auth.lease_duration, now_unix);
        let tok = Zeroizing::new(auth.client_token);
        self.store_token(tok, expires_at_unix, auth.renewable).await;

        tracing::info!(
            "Authenticated to Vault via AppRole (lease_duration={}s, renewable={})",
            auth.lease_duration,
            auth.renewable
        );
        Ok(())
    }

    async fn renew_self(&self, current_token: &Zeroizing<String>) -> Result<()> {
        let url = format!("{}/v1/auth/token/renew-self", self.addr);
        let req = self.with_vault_headers(self.http.post(&url), current_token.as_str());
        let resp = req
            .send()
            .await
            .map_err(|e| vault_http_err("token renew-self request", e))?;

        if !resp.status().is_success() {
            let detail = extract_vault_error(resp).await;
            return Err(FluxgateError::VaultError(format!(
                "Vault token renew-self failed: {}",
                detail
            )));
        }

        let parsed: VaultAuthResponse = resp.json().await.map_err(|e| {
            FluxgateError::VaultError(format!("Failed to parse Vault renew-self response: {}", e))
        })?;

        let auth = parsed.auth.ok_or_else(|| {
            FluxgateError::VaultError("Vault renew-self response missing 'auth' object".to_string())
        })?;

        let tok = if auth.client_token.is_empty() {
            current_token.clone()
        } else {
            Zeroizing::new(auth.client_token)
        };
        let now_unix = current_unix_secs();
        let expires_at_unix = compute_expiry(auth.lease_duration, now_unix);
        self.store_token(tok, expires_at_unix, auth.renewable).await;

        tracing::debug!(
            "Renewed Vault token (lease_duration={}s, renewable={})",
            auth.lease_duration,
            auth.renewable
        );
        Ok(())
    }

    fn build_v1_url(&self, kv_path: &str) -> String {
        let clean = kv_path.trim().trim_start_matches('/');
        format!("{}/v1/{}", self.addr, clean)
    }

    fn with_vault_headers(
        &self,
        mut req: reqwest::RequestBuilder,
        token: &str,
    ) -> reqwest::RequestBuilder {
        if !token.is_empty() {
            req = req.header("X-Vault-Token", token);
        }
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }
        req
    }

    async fn current_token(&self) -> Zeroizing<String> {
        let guard = self.token_state.read().await;
        guard.token.clone()
    }

    async fn token_snapshot(&self) -> (Zeroizing<String>, Option<i64>, bool) {
        let guard = self.token_state.read().await;
        (guard.token.clone(), guard.expires_at_unix, guard.renewable)
    }

    async fn store_token(
        &self,
        token: Zeroizing<String>,
        expires_at_unix: Option<i64>,
        renewable: bool,
    ) {
        let mut guard = self.token_state.write().await;
        guard.token = token;
        guard.expires_at_unix = expires_at_unix;
        guard.renewable = renewable;
    }
}

pub struct VaultSyncService {
    pub client: Arc<VaultClient>,
    pub syncs: Vec<VaultSyncSpec>,
    pub store: Arc<SecretStore>,
    pub metrics: Option<Arc<MetricsRegistry>>,
}

impl fmt::Debug for VaultSyncService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSyncService")
            .field("client", &self.client)
            .field("syncs", &self.syncs)
            .finish()
    }
}

struct AliasSyncState {
    next_due: tokio::time::Instant,
    consecutive_failures: u32,
}

fn update_sync_state(
    state: &mut AliasSyncState,
    spec: &VaultSyncSpec,
    succeeded: bool,
    now: tokio::time::Instant,
) {
    if succeeded {
        state.consecutive_failures = 0;
        let interval_secs = spec.interval_secs.max(1);
        state.next_due = now + Duration::from_secs(interval_secs);
    } else {
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let shift = (state.consecutive_failures - 1).min(10);
        let max_backoff = spec.interval_secs.max(MIN_MAX_BACKOFF_SECS);
        let raw_backoff = MIN_BACKOFF_SECS.saturating_mul(1u64 << shift);
        let backoff_secs = raw_backoff.min(max_backoff);
        state.next_due = now + Duration::from_secs(backoff_secs);
    }
}

#[async_trait]
impl BackgroundService for VaultSyncService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if self.syncs.is_empty() {
            let _ = shutdown.changed().await;
            tracing::info!("VaultSyncService shutting down");
            return;
        }

        let metrics = self.metrics.as_deref();
        let initial_now = tokio::time::Instant::now();
        let mut states: Vec<AliasSyncState> = (0..self.syncs.len())
            .map(|_| AliasSyncState {
                next_due: initial_now,
                consecutive_failures: 0,
            })
            .collect();

        for (spec, state) in self.syncs.iter().zip(states.iter_mut()) {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("VaultSyncService shutting down during initial sync");
                    return;
                }
                res = self.client.sync_once(spec, &self.store, metrics) => {
                    let done = tokio::time::Instant::now();
                    update_sync_state(state, spec, res.is_ok(), done);
                }
            }
        }

        loop {
            let next_wake = states
                .iter()
                .map(|s| s.next_due)
                .min()
                .unwrap_or_else(tokio::time::Instant::now);

            let now = tokio::time::Instant::now();
            if next_wake > now {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => {
                        tracing::info!("VaultSyncService shutting down");
                        break;
                    }
                    _ = tokio::time::sleep_until(next_wake) => {}
                }
            }

            let check_now = tokio::time::Instant::now();
            for (spec, state) in self.syncs.iter().zip(states.iter_mut()) {
                if state.next_due <= check_now {
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => {
                            tracing::info!("VaultSyncService shutting down");
                            return;
                        }
                        res = self.client.sync_once(spec, &self.store, metrics) => {
                            let done = tokio::time::Instant::now();
                            update_sync_state(state, spec, res.is_ok(), done);
                        }
                    }
                }
            }
        }
    }
}

fn load_credential(env_var: &str, cred_filename: &str) -> Result<Zeroizing<String>> {
    if let Ok(val) = std::env::var(env_var) {
        let raw = Zeroizing::new(val);
        let trimmed = Zeroizing::new(raw.trim().to_string());
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if let Ok(cred_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let dir = cred_dir.trim();
        if !dir.is_empty() {
            let path = Path::new(dir).join(cred_filename);
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    let raw = Zeroizing::new(content);
                    let trimmed = Zeroizing::new(raw.trim().to_string());
                    if !trimmed.is_empty() {
                        return Ok(trimmed);
                    }
                    return Err(FluxgateError::VaultError(format!(
                        "Vault credential file '{}' is empty",
                        path.display()
                    )));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(FluxgateError::VaultError(format!(
                        "Failed to read Vault credential file '{}': {}",
                        path.display(),
                        e
                    )));
                }
            }
        }
    }

    Err(FluxgateError::VaultError(format!(
        "Missing Vault credential: set {} or provide $CREDENTIALS_DIRECTORY/{}",
        env_var, cred_filename
    )))
}

fn resolve_non_vault_ref(secret_ref: &SecretRef, field: &str) -> Result<String> {
    match secret_ref {
        SecretRef::Literal(s) => Ok(s.trim().to_string()),
        SecretRef::Env(var) => std::env::var(var)
            .map(|v| v.trim().to_string())
            .map_err(|_| {
                FluxgateError::VaultError(format!(
                    "Environment variable '{}' for Vault {} is not set",
                    var, field
                ))
            }),
        SecretRef::Vault { .. } => Err(FluxgateError::VaultError(format!(
            "Vault {} cannot be a {{vault...}} reference",
            field
        ))),
    }
}

fn vault_http_err(context: &str, err: reqwest::Error) -> FluxgateError {
    FluxgateError::VaultError(format!("Vault {} failed: {}", context, err))
}

fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn is_close_to_expiry(expires_at_unix: Option<i64>, now_unix: i64) -> bool {
    match expires_at_unix {
        Some(exp) => exp.saturating_sub(now_unix) <= TOKEN_RENEW_LEEWAY_SECS,
        None => false,
    }
}

fn compute_expiry(lease_duration: u64, now_unix: i64) -> Option<i64> {
    if lease_duration == 0 {
        None
    } else {
        let ttl = i64::try_from(lease_duration).unwrap_or(i64::MAX);
        Some(now_unix.saturating_add(ttl))
    }
}

async fn extract_vault_error(resp: reqwest::Response) -> String {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(errors) = json.get("errors").and_then(|v| v.as_array()) {
            let msgs: Vec<&str> = errors.iter().filter_map(|v| v.as_str()).collect();
            if !msgs.is_empty() {
                return format!("HTTP {} ({})", status, msgs.join("; "));
            }
        }
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        format!("HTTP {}", status)
    } else {
        let snippet: String = trimmed.chars().take(200).collect();
        format!("HTTP {}: {}", status, snippet)
    }
}
