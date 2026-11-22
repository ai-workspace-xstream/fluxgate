use fluxgate::config::ast::{SecretRef, VaultAuthMode, VaultConfig, VaultSyncSpec};
use fluxgate::metrics::MetricsRegistry;
use fluxgate::vault::{SecretStore, VaultClient, VaultSyncService};
use pingora::services::background::BackgroundService;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex, MutexGuard};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

fn env_mutex() -> &'static Mutex<()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

async fn lock_env() -> MutexGuard<'static, ()> {
    env_mutex().lock().await
}

struct EnvVarGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvVarGuard {
    fn new(vars: &[(&'static str, Option<&str>)]) -> Self {
        let mut saved = Vec::with_capacity(vars.len());
        for &(key, new_val) in vars {
            saved.push((key, std::env::var(key).ok()));
            match new_val {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        Self { saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, old_val) in self.saved.drain(..).rev() {
            match old_val {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[derive(Clone)]
struct MockKvEntry {
    version: u64,
    data: Value,
}

struct MockVaultState {
    valid_tokens: HashSet<String>,
    expected_namespace: Option<String>,
    approle_role_id: String,
    approle_secret_id: String,
    approle_lease_duration: u64,
    approle_login_calls: usize,
    renew_calls: usize,
    kv_entries: HashMap<String, MockKvEntry>,
    force_next_kv_403: bool,
}

impl MockVaultState {
    fn new() -> Self {
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert("hvs.static-root".to_string());
        Self {
            valid_tokens,
            expected_namespace: None,
            approle_role_id: "role-fluxgate".to_string(),
            approle_secret_id: "secret-fluxgate".to_string(),
            approle_lease_duration: 3600,
            approle_login_calls: 0,
            renew_calls: 0,
            kv_entries: HashMap::new(),
            force_next_kv_403: false,
        }
    }

    fn set_kv(&mut self, kv_path: &str, version: u64, data: Value) {
        self.kv_entries.insert(
            kv_path.trim_start_matches('/').to_string(),
            MockKvEntry { version, data },
        );
    }
}

struct MockVaultServer {
    addr: String,
    state: Arc<Mutex<MockVaultState>>,
    shutdown_tx: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
}

impl MockVaultServer {
    async fn start(initial_state: MockVaultState) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let addr = format!("http://{}", local_addr);
        let state = Arc::new(Mutex::new(initial_state));
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let srv_state = state.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let req_state = srv_state.clone();
                            tokio::spawn(async move {
                                handle_http_connection(&mut stream, req_state).await;
                            });
                        }
                    }
                }
            }
            drop(listener);
        });

        Self {
            addr,
            state,
            shutdown_tx,
            handle: Some(handle),
        }
    }

    async fn shutdown(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for MockVaultServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn handle_http_connection(
    stream: &mut tokio::net::TcpStream,
    state: Arc<Mutex<MockVaultState>>,
) {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("/");
    let path = raw_target.split('?').next().unwrap_or("/");

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), val.trim().to_string());
        }
    }

    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let body_end = (body_start + content_length).min(buf.len());
    let body_bytes = &buf[body_start..body_end];

    let (status_line, resp_json) =
        dispatch_request(method, path, &headers, body_bytes, &state).await;
    let resp_body = serde_json::to_string(&resp_json).unwrap();
    let raw_resp = format!(
        "HTTP/1.1 {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        status_line,
        resp_body.len(),
        resp_body
    );

    let _ = stream.write_all(raw_resp.as_bytes()).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

async fn dispatch_request(
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body_bytes: &[u8],
    state: &Arc<Mutex<MockVaultState>>,
) -> (&'static str, Value) {
    let mut st = state.lock().await;

    if let Some(expected_ns) = &st.expected_namespace {
        let got_ns = headers.get("x-vault-namespace").map(String::as_str);
        if got_ns != Some(expected_ns.as_str()) {
            let err = json!({ "errors": ["namespace mismatch"] });
            return ("403 Forbidden", err);
        }
    }

    if method == "POST" && path == "/v1/auth/approle/login" {
        let req_json: Value = serde_json::from_slice(body_bytes).unwrap_or(Value::Null);
        let role_id = req_json.get("role_id").and_then(Value::as_str).unwrap_or("");
        let secret_id = req_json
            .get("secret_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if role_id == st.approle_role_id && secret_id == st.approle_secret_id {
            st.approle_login_calls += 1;
            let issued = format!("hvs.approle-token-{}", st.approle_login_calls);
            st.valid_tokens.insert(issued.clone());
            return (
                "200 OK",
                json!({
                    "auth": {
                        "client_token": issued,
                        "lease_duration": st.approle_lease_duration,
                        "renewable": true
                    }
                }),
            );
        }
        let err = json!({ "errors": ["invalid role or secret ID"] });
        return ("400 Bad Request", err);
    }

    let token = headers
        .get("x-vault-token")
        .map(String::as_str)
        .unwrap_or("");
    if !st.valid_tokens.contains(token) {
        return ("403 Forbidden", json!({ "errors": ["permission denied"] }));
    }

    if method == "POST" && path == "/v1/auth/token/renew-self" {
        st.renew_calls += 1;
        return (
            "200 OK",
            json!({
                "auth": {
                    "client_token": token,
                    "lease_duration": 3600,
                    "renewable": true
                }
            }),
        );
    }

    if let Some(kv_path) = path.strip_prefix("/v1/") {
        if st.force_next_kv_403 {
            st.force_next_kv_403 = false;
            let err = json!({ "errors": ["simulated expired token"] });
            return ("403 Forbidden", err);
        }

        if method == "GET" {
            return match st.kv_entries.get(kv_path) {
                Some(entry) => (
                    "200 OK",
                    json!({
                        "data": {
                            "data": entry.data,
                            "metadata": {
                                "version": entry.version
                            }
                        }
                    }),
                ),
                None => ("404 Not Found", json!({ "errors": [] })),
            };
        }

        if method == "POST" {
            let req_json: Value = serde_json::from_slice(body_bytes).unwrap_or(Value::Null);
            let cas = req_json
                .get("options")
                .and_then(|o| o.get("cas"))
                .and_then(Value::as_u64);
            let data = req_json.get("data").cloned().unwrap_or(Value::Null);

            let current_ver = st.kv_entries.get(kv_path).map(|e| e.version).unwrap_or(0);
            if let Some(expected_cas) = cas {
                if expected_cas != current_ver {
                    let msg = format!(
                        "check-and-set mismatch (expected {}, got {})",
                        current_ver, expected_cas
                    );
                    return ("400 Bad Request", json!({ "errors": [msg] }));
                }
            }

            let new_ver = current_ver + 1;
            let entry = MockKvEntry {
                version: new_ver,
                data,
            };
            st.kv_entries.insert(kv_path.to_string(), entry);
            return ("200 OK", json!({ "data": { "version": new_ver } }));
        }
    }

    ("404 Not Found", json!({ "errors": ["unsupported route"] }))
}

#[tokio::test]
async fn test_token_auth_read_kv2_and_secret_store_resolve() {
    let _lock = lock_env().await;

    let mut state = MockVaultState::new();
    state.expected_namespace = Some("fluxgate-prod".to_string());
    state.set_kv(
        "kv/data/prod/fluxgate/dns",
        3,
        json!({
            "cf_api_token": "cf-token-abc-123",
            "ttl": 120,
            "proxied": false
        }),
    );

    let mut server = MockVaultServer::start(state).await;
    let _env = EnvVarGuard::new(&[
        ("FLUXGATE_TEST_VAULT_ADDR", Some(&server.addr)),
        ("FLUXGATE_TEST_VAULT_NS", Some("fluxgate-prod")),
        ("VAULT_TOKEN", Some("hvs.static-root")),
        ("FLUXGATE_TEST_ENV_SECRET", Some("env-secret-value")),
    ]);

    let cfg = VaultConfig {
        addr: SecretRef::Env("FLUXGATE_TEST_VAULT_ADDR".to_string()),
        namespace: Some(SecretRef::Env("FLUXGATE_TEST_VAULT_NS".to_string())),
        auth: VaultAuthMode::Token,
        ca_cert: None,
        syncs: vec![VaultSyncSpec {
            alias: "dns".to_string(),
            kv_path: "kv/data/prod/fluxgate/dns".to_string(),
            interval_secs: 300,
        }],
    };

    let client = VaultClient::from_config(&cfg).await.unwrap();
    let store = SecretStore::new();
    let version = client.sync_once(&cfg.syncs[0], &store, None).await.unwrap();
    assert_eq!(version, 3);

    let cf_ref = SecretRef::Vault {
        alias: "dns".to_string(),
        key: "cf_api_token".to_string(),
    };
    assert_eq!(
        store.resolve_secret_ref(&cf_ref).unwrap().as_str(),
        "cf-token-abc-123"
    );

    let ttl_ref = SecretRef::Vault {
        alias: "dns".to_string(),
        key: "ttl".to_string(),
    };
    assert_eq!(store.resolve_secret_ref(&ttl_ref).unwrap().as_str(), "120");

    let proxied_ref = SecretRef::Vault {
        alias: "dns".to_string(),
        key: "proxied".to_string(),
    };
    assert_eq!(
        store.resolve_secret_ref(&proxied_ref).unwrap().as_str(),
        "false"
    );

    let literal_ref = SecretRef::Literal("literal-val".to_string());
    assert_eq!(
        store.resolve_secret_ref(&literal_ref).unwrap().as_str(),
        "literal-val"
    );

    let env_ref = SecretRef::Env("FLUXGATE_TEST_ENV_SECRET".to_string());
    assert_eq!(
        store.resolve_secret_ref(&env_ref).unwrap().as_str(),
        "env-secret-value"
    );

    let missing_ref = SecretRef::Vault {
        alias: "dns".to_string(),
        key: "missing_key".to_string(),
    };
    let missing_key_err = store.resolve_secret_ref(&missing_ref).unwrap_err();
    assert!(missing_key_err.to_string().contains("missing_key"));

    let summary = store.snapshot_summary();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].0, "dns");
    assert_eq!(summary[0].1, 3);
    assert_eq!(summary[0].3, 3);

    server.shutdown().await;
}

#[tokio::test]
async fn test_approle_login_renew_and_403_reauth() {
    let _lock = lock_env().await;

    let mut state = MockVaultState::new();
    // Short lease duration (<= 60s leeway) triggers renew-self on the next request
    state.approle_lease_duration = 30;
    state.set_kv(
        "kv/data/prod/fluxgate/dns",
        1,
        json!({
            "alidns_access_key_id": "ak-id-001",
            "alidns_access_key_secret": "ak-secret-002"
        }),
    );

    let mut server = MockVaultServer::start(state).await;
    let _env = EnvVarGuard::new(&[
        ("VAULT_ROLE_ID", Some("role-fluxgate")),
        ("VAULT_SECRET_ID", Some("secret-fluxgate")),
        ("CREDENTIALS_DIRECTORY", None),
    ]);

    let client = VaultClient::new(&server.addr, VaultAuthMode::AppRole, None, None).unwrap();
    client.ensure_authenticated().await.unwrap();

    // Second ensure_authenticated should call renew-self because initial lease was 30s
    client.ensure_authenticated().await.unwrap();

    {
        let mut st = server.state.lock().await;
        assert_eq!(st.approle_login_calls, 1);
        assert_eq!(st.renew_calls, 1);
        st.force_next_kv_403 = true;
    }

    let store = SecretStore::new();
    let spec = VaultSyncSpec {
        alias: "dns".to_string(),
        kv_path: "/kv/data/prod/fluxgate/dns".to_string(),
        interval_secs: 60,
    };
    let ver = client.sync_once(&spec, &store, None).await.unwrap();
    assert_eq!(ver, 1);

    {
        let st = server.state.lock().await;
        assert_eq!(st.approle_login_calls, 2);
    }

    assert_eq!(
        store.get_secret("dns", "alidns_access_key_id").unwrap().as_str(),
        "ak-id-001"
    );
    assert_eq!(
        store
            .get_secret("dns", "alidns_access_key_secret")
            .unwrap()
            .as_str(),
        "ak-secret-002"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_credentials_directory_fallback() {
    let _lock = lock_env().await;

    let cred_dir = tempdir().unwrap();
    let token_path = cred_dir.path().join("vault_token");
    let role_path = cred_dir.path().join("vault_role_id");
    let secret_path = cred_dir.path().join("vault_secret_id");
    std::fs::write(&token_path, "hvs.static-root\n").unwrap();
    std::fs::write(&role_path, "role-fluxgate\n").unwrap();
    std::fs::write(&secret_path, "secret-fluxgate\n").unwrap();

    let mut state = MockVaultState::new();
    let payload = json!({ "api_key": "cred-dir-ok" });
    state.set_kv("kv/data/prod/fluxgate/cred", 1, payload);
    let mut server = MockVaultServer::start(state).await;

    let cred_dir_str = cred_dir.path().to_str().unwrap().to_string();
    let _env = EnvVarGuard::new(&[
        ("VAULT_TOKEN", None),
        ("VAULT_ROLE_ID", None),
        ("VAULT_SECRET_ID", None),
        ("CREDENTIALS_DIRECTORY", Some(&cred_dir_str)),
    ]);

    let token_client = VaultClient::new(&server.addr, VaultAuthMode::Token, None, None).unwrap();
    let res_tok = token_client
        .read_kv2("kv/data/prod/fluxgate/cred")
        .await
        .unwrap();
    assert_eq!(res_tok.data["api_key"].as_str(), "cred-dir-ok");

    let approle_client =
        VaultClient::new(&server.addr, VaultAuthMode::AppRole, None, None).unwrap();
    let res_app = approle_client
        .read_kv2("kv/data/prod/fluxgate/cred")
        .await
        .unwrap();
    assert_eq!(res_app.data["api_key"].as_str(), "cred-dir-ok");

    server.shutdown().await;
}

#[tokio::test]
async fn test_kv2_version_increment_idempotency() {
    let mut state = MockVaultState::new();
    let v1_payload = json!({ "token": "v1-secret-value" });
    state.set_kv("kv/data/prod/fluxgate/tokens", 1, v1_payload);
    let mut server = MockVaultServer::start(state).await;

    let client = VaultClient::new(&server.addr, VaultAuthMode::Token, None, None).unwrap();
    client.set_static_token("hvs.static-root");

    let store = SecretStore::new();
    let spec = VaultSyncSpec {
        alias: "tokens".to_string(),
        kv_path: "kv/data/prod/fluxgate/tokens".to_string(),
        interval_secs: 60,
    };

    let v1 = client.sync_once(&spec, &store, None).await.unwrap();
    assert_eq!(v1, 1);
    assert_eq!(store.alias_version("tokens"), Some(1));
    assert_eq!(
        store.get_secret("tokens", "token").unwrap().as_str(),
        "v1-secret-value"
    );

    // Use a sentinel timestamp to confirm same-version sync leaves the stored entry untouched
    let mut sentinel_map = HashMap::new();
    let sentinel_val = Zeroizing::new("v1-secret-value".to_string());
    sentinel_map.insert("token".to_string(), sentinel_val);
    store.update_alias("tokens", sentinel_map, 1, 1_700_000_001);

    let v1_again = client.sync_once(&spec, &store, None).await.unwrap();
    assert_eq!(v1_again, 1);
    let entry_after_noop = store.get_entry("tokens").unwrap();
    assert_eq!(entry_after_noop.last_sync_unix, 1_700_000_001);

    {
        let mut st = server.state.lock().await;
        let v2_payload = json!({ "token": "v2-secret-value" });
        st.set_kv("kv/data/prod/fluxgate/tokens", 2, v2_payload);
    }

    let v2 = client.sync_once(&spec, &store, None).await.unwrap();
    assert_eq!(v2, 2);
    assert_eq!(store.alias_version("tokens"), Some(2));
    assert_eq!(
        store.get_secret("tokens", "token").unwrap().as_str(),
        "v2-secret-value"
    );
    assert!(store.get_entry("tokens").unwrap().last_sync_unix > 1_700_000_001);

    server.shutdown().await;
}

#[tokio::test]
async fn test_read_kv2_json_404_and_write_kv2_cas() {
    let state = MockVaultState::new();
    let mut server = MockVaultServer::start(state).await;

    let client = VaultClient::new(&server.addr, VaultAuthMode::Token, None, None).unwrap();
    client.set_static_token("hvs.static-root");

    let cert_path = "kv/data/prod/fluxgate/certs/wildcard.svc.plus";

    let missing = client.read_kv2_json(cert_path).await.unwrap();
    assert!(missing.is_none());

    let v1_body = json!({
        "cert_pem": "CERT-PEM-V1",
        "renew_owner": "node-1"
    });
    let ver1 = client.write_kv2_cas(cert_path, &v1_body, 0).await.unwrap();
    assert_eq!(ver1, 1);

    let loaded = client.read_kv2_json(cert_path).await.unwrap().unwrap();
    assert_eq!(loaded.1, 1);
    assert_eq!(loaded.0["cert_pem"], "CERT-PEM-V1");

    let v2_body = json!({
        "cert_pem": "CERT-PEM-V2",
        "renew_owner": "node-1"
    });
    let ver2 = client.write_kv2_cas(cert_path, &v2_body, 1).await.unwrap();
    assert_eq!(ver2, 2);

    let stale_body = json!({
        "cert_pem": "STALE-WRITE",
        "renew_owner": "node-2"
    });
    let cas_err = client
        .write_kv2_cas(cert_path, &stale_body, 1)
        .await
        .unwrap_err();
    assert!(
        cas_err.to_string().contains("CAS conflict"),
        "Unexpected CAS error: {}",
        cas_err
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_vault_outage_fallback_preserves_cache_and_metrics() {
    let mut state = MockVaultState::new();
    let payload = json!({ "cf_api_token": "cached-during-outage" });
    state.set_kv("kv/data/prod/fluxgate/dns", 7, payload);
    let mut server = MockVaultServer::start(state).await;

    let client = VaultClient::new(&server.addr, VaultAuthMode::Token, None, None).unwrap();
    client.set_static_token("hvs.static-root");

    let store = SecretStore::new();
    let metrics = MetricsRegistry::new();
    let spec = VaultSyncSpec {
        alias: "dns".to_string(),
        kv_path: "kv/data/prod/fluxgate/dns".to_string(),
        interval_secs: 60,
    };

    let initial_ver = client
        .sync_once(&spec, &store, Some(&metrics))
        .await
        .unwrap();
    assert_eq!(initial_ver, 7);

    let ok_prom = metrics.render_prometheus();
    assert!(ok_prom.contains("fluxgate_vault_sync_success{alias=\"dns\"} 1"));
    assert!(ok_prom.contains("fluxgate_vault_sync_version{alias=\"dns\"} 7"));

    // Shut down mock Vault completely before syncing again
    server.shutdown().await;

    let err = client
        .sync_once(&spec, &store, Some(&metrics))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Vault"));

    // Cached secret and version remain intact
    assert_eq!(store.alias_version("dns"), Some(7));
    assert_eq!(
        store.get_secret("dns", "cf_api_token").unwrap().as_str(),
        "cached-during-outage"
    );

    let err_prom = metrics.render_prometheus();
    assert!(err_prom.contains("fluxgate_vault_sync_success{alias=\"dns\"} 0"));
    assert!(err_prom.contains("fluxgate_vault_sync_version{alias=\"dns\"} 7"));
}

#[test]
fn test_redacted_debug_never_leaks_secrets() {
    let secret_val = "super-secret-cf-token-do-not-leak";
    let vault_token = "hvs.super-secret-vault-token-987";

    let store = SecretStore::new();
    let mut data = HashMap::new();
    data.insert(
        "cf_api_token".to_string(),
        Zeroizing::new(secret_val.to_string()),
    );
    store.update_alias("dns", data, 4, 1_700_000_123);

    let entry = store.get_entry("dns").unwrap();
    let store_dbg = format!("{:?}", store);
    let entry_dbg = format!("{:?}", entry);

    assert!(!store_dbg.contains(secret_val));
    assert!(store_dbg.contains("dns"));
    assert!(store_dbg.contains("cf_api_token"));

    assert!(!entry_dbg.contains(secret_val));
    assert!(entry_dbg.contains("cf_api_token"));
    assert!(entry_dbg.contains("version: 4"));

    let client =
        VaultClient::new("http://127.0.0.1:8200", VaultAuthMode::Token, None, None).unwrap();
    client.set_static_token(vault_token);
    let client_dbg = format!("{:?}", client);
    assert!(!client_dbg.contains(vault_token));
}

#[tokio::test]
async fn test_vault_sync_service_background_lifecycle() {
    let mut state = MockVaultState::new();
    let payload = json!({ "cf_api_token": "bg-synced-token" });
    state.set_kv("kv/data/prod/fluxgate/dns", 1, payload);
    let mut server = MockVaultServer::start(state).await;

    let raw_client = VaultClient::new(&server.addr, VaultAuthMode::Token, None, None).unwrap();
    let client = Arc::new(raw_client);
    client.set_static_token("hvs.static-root");

    let store = Arc::new(SecretStore::new());
    let metrics = Arc::new(MetricsRegistry::new());
    let service = VaultSyncService {
        client,
        syncs: vec![VaultSyncSpec {
            alias: "dns".to_string(),
            kv_path: "kv/data/prod/fluxgate/dns".to_string(),
            interval_secs: 300,
        }],
        store: store.clone(),
        metrics: Some(metrics.clone()),
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        service.start(shutdown_rx).await;
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if store.alias_version("dns") == Some(1) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Timed out waiting for VaultSyncService initial sync"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        store.get_secret("dns", "cf_api_token").unwrap().as_str(),
        "bg-synced-token"
    );
    assert!(metrics
        .render_prometheus()
        .contains("fluxgate_vault_sync_success{alias=\"dns\"} 1"));

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("VaultSyncService did not stop on shutdown signal")
        .expect("VaultSyncService panicked");

    server.shutdown().await;
}
