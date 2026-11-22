use crate::error::{FluxgateError, Result};
use crate::vault::VaultClient;
use async_trait::async_trait;
use instant_acme::AccountCredentials;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct CertBundle {
    pub domains: Vec<String>,
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
    pub not_after_unix: i64,
}

impl fmt::Debug for CertBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertBundle")
            .field("domains", &self.domains)
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"[REDACTED]")
            .field("not_after_unix", &self.not_after_unix)
            .finish()
    }
}

/// Extract leaf certificate `NotAfter` Unix timestamp (seconds) from a PEM certificate chain.
pub fn parse_cert_not_after(cert_pem: &str) -> Result<i64> {
    let parsed_pem = pem::parse(cert_pem)
        .map_err(|e| FluxgateError::AcmeError(format!("Failed to parse certificate PEM: {}", e)))?;
    if !parsed_pem.tag().contains("CERTIFICATE") {
        return Err(FluxgateError::AcmeError(format!(
            "Unexpected PEM block tag '{}', expected CERTIFICATE",
            parsed_pem.tag()
        )));
    }
    let (_, cert) = x509_parser::parse_x509_certificate(parsed_pem.contents()).map_err(|e| {
        FluxgateError::AcmeError(format!("Failed to parse X.509 certificate: {}", e))
    })?;
    Ok(cert.validity().not_after.timestamp())
}

/// Compute a deterministic, filesystem- and Vault-path-safe key for a SAN group.
pub fn san_group_key(domains: &[String]) -> String {
    let mut normalized: Vec<String> = domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .map(|d| {
            let replaced = d.replace('*', "wildcard");
            let mut safe = String::with_capacity(replaced.len());
            for ch in replaced.chars() {
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                    safe.push(ch);
                } else {
                    safe.push('_');
                }
            }
            while safe.contains("..") {
                safe = safe.replace("..", "_");
            }
            safe.trim_matches('.').to_string()
        })
        .filter(|d| !d.is_empty())
        .collect();

    normalized.sort();
    normalized.dedup();

    if normalized.is_empty() {
        "default".to_string()
    } else {
        normalized.join("__")
    }
}

pub struct LocalCertStorage {
    base_dir: PathBuf,
}

impl LocalCertStorage {
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let storage = Self {
            base_dir: base_dir.into(),
        };
        storage.ensure_dir()?;
        Ok(storage)
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.base_dir)?;
        #[cfg(unix)]
        {
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&self.base_dir, perms)?;
        }
        Ok(())
    }

    fn cert_path(&self, domains: &[String]) -> PathBuf {
        self.base_dir
            .join(format!("{}.crt", san_group_key(domains)))
    }

    fn key_path(&self, domains: &[String]) -> PathBuf {
        self.base_dir
            .join(format!("{}.key", san_group_key(domains)))
    }

    fn account_path(&self) -> PathBuf {
        self.base_dir.join("acme-account.json")
    }

    pub fn save_cert(&self, bundle: &CertBundle) -> Result<()> {
        self.ensure_dir()?;
        let cert_path = self.cert_path(&bundle.domains);
        let key_path = self.key_path(&bundle.domains);
        // Write private key first with strict 0600 permissions before exposing public cert.
        write_atomic_file(&key_path, bundle.key_pem.as_bytes(), 0o600)?;
        write_atomic_file(&cert_path, bundle.cert_pem.as_bytes(), 0o644)?;
        Ok(())
    }

    pub fn load_cert(&self, domains: &[String]) -> Result<Option<CertBundle>> {
        let cert_path = self.cert_path(domains);
        let key_path = self.key_path(domains);

        let cert_pem = match fs::read_to_string(&cert_path) {
            Ok(c) => c,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(FluxgateError::Io(e)),
        };

        let key_pem = match fs::read_to_string(&key_path) {
            Ok(k) => Zeroizing::new(k),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(FluxgateError::Io(e)),
        };

        let not_after_unix = parse_cert_not_after(&cert_pem)?;
        Ok(Some(CertBundle {
            domains: domains.to_vec(),
            cert_pem,
            key_pem,
            not_after_unix,
        }))
    }

    pub fn save_account_credentials(&self, creds: &AccountCredentials) -> Result<()> {
        self.ensure_dir()?;
        let json_str = Zeroizing::new(serde_json::to_string_pretty(creds).map_err(|e| {
            FluxgateError::AcmeError(format!("Failed to serialize ACME credentials: {}", e))
        })?);
        write_atomic_file(&self.account_path(), json_str.as_bytes(), 0o600)?;
        Ok(())
    }

    pub fn load_account_credentials(&self) -> Result<Option<AccountCredentials>> {
        let raw = match fs::read_to_string(self.account_path()) {
            Ok(s) => Zeroizing::new(s),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(FluxgateError::Io(e)),
        };
        let creds = serde_json::from_str::<AccountCredentials>(&raw).map_err(|e| {
            FluxgateError::AcmeError(format!("Failed to parse stored ACME credentials: {}", e))
        })?;
        Ok(Some(creds))
    }

    pub fn load_account_credentials_for_ca(
        &self,
        ca_url: &str,
    ) -> Result<Option<AccountCredentials>> {
        let raw = match fs::read_to_string(self.account_path()) {
            Ok(s) => Zeroizing::new(s),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(FluxgateError::Io(e)),
        };

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(dir) = val.get("directory").and_then(|d| d.as_str()) {
                if dir.trim_end_matches('/') != ca_url.trim_end_matches('/') {
                    tracing::info!(
                        stored_ca = %dir,
                        requested_ca = %ca_url,
                        "Stored ACME account credentials belong to a different CA directory; registering new account"
                    );
                    return Ok(None);
                }
            }
        }

        let creds = serde_json::from_str::<AccountCredentials>(&raw).map_err(|e| {
            FluxgateError::AcmeError(format!("Failed to parse stored ACME credentials: {}", e))
        })?;
        Ok(Some(creds))
    }
}

fn write_atomic_file(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        FluxgateError::AcmeError(format!("Path '{}' has no parent directory", path.display()))
    })?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("fluxgate");
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{}.tmp.{}.{}", file_name, std::process::id(), seq));

    let write_res = (|| -> Result<()> {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        opts.mode(mode);

        let mut file = opts.open(&tmp_path)?;
        file.write_all(content)?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            // Explicitly set permissions so process umask cannot alter the target mode.
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode))?;
        }

        fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

#[async_trait]
pub trait VaultKvStore: Send + Sync {
    async fn read_kv2_json(&self, kv_path: &str) -> Result<Option<(serde_json::Value, u64)>>;
    async fn write_kv2_cas(&self, kv_path: &str, data: &serde_json::Value, cas: u64)
        -> Result<u64>;
}

#[async_trait]
impl VaultKvStore for VaultClient {
    async fn read_kv2_json(&self, kv_path: &str) -> Result<Option<(serde_json::Value, u64)>> {
        self.read_kv2_json(kv_path).await
    }

    async fn write_kv2_cas(
        &self,
        kv_path: &str,
        data: &serde_json::Value,
        cas: u64,
    ) -> Result<u64> {
        self.write_kv2_cas(kv_path, data, cas).await
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct VaultCertRecord {
    domains: Vec<String>,
    cert_pem: String,
    key_pem: String,
    not_after_unix: i64,
    updated_by: String,
    renew_owner: String,
    renew_lock_until: i64,
}

struct ZeroizeVaultCertRecord(VaultCertRecord);

impl std::ops::Deref for ZeroizeVaultCertRecord {
    type Target = VaultCertRecord;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ZeroizeVaultCertRecord {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ZeroizeVaultCertRecord {
    fn drop(&mut self) {
        self.0.key_pem.zeroize();
    }
}

pub struct VaultSharedCertStorage {
    client: Arc<dyn VaultKvStore>,
    base_path: String,
    node_id: String,
}

impl fmt::Debug for VaultSharedCertStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSharedCertStorage")
            .field("base_path", &self.base_path)
            .field("node_id", &self.node_id)
            .finish()
    }
}

impl VaultSharedCertStorage {
    pub fn new(
        client: Arc<VaultClient>,
        base_path: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            base_path: base_path.into(),
            node_id: node_id.into(),
        }
    }

    pub fn with_kv_store(
        client: Arc<dyn VaultKvStore>,
        base_path: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            base_path: base_path.into(),
            node_id: node_id.into(),
        }
    }

    pub fn cert_kv_path(&self, domains: &[String]) -> String {
        format!(
            "{}/{}",
            self.base_path.trim_end_matches('/'),
            san_group_key(domains)
        )
    }

    pub async fn load_shared_cert(&self, domains: &[String]) -> Result<Option<(CertBundle, u64)>> {
        let path = self.cert_kv_path(domains);
        let Some((val, version)) = self.client.read_kv2_json(&path).await? else {
            return Ok(None);
        };

        let mut record = ZeroizeVaultCertRecord(serde_json::from_value(val).map_err(|e| {
            FluxgateError::VaultError(format!("Failed to decode Vault cert record: {}", e))
        })?);

        if record.cert_pem.trim().is_empty() || record.key_pem.trim().is_empty() {
            return Ok(None);
        }

        let not_after_unix = if record.not_after_unix > 0 {
            record.not_after_unix
        } else {
            parse_cert_not_after(&record.cert_pem)?
        };

        let record_domains = if record.domains.is_empty() {
            domains.to_vec()
        } else {
            std::mem::take(&mut record.domains)
        };

        let cert_pem = std::mem::take(&mut record.cert_pem);
        let key_pem = Zeroizing::new(std::mem::take(&mut record.key_pem));

        Ok(Some((
            CertBundle {
                domains: record_domains,
                cert_pem,
                key_pem,
                not_after_unix,
            },
            version,
        )))
    }

    pub async fn try_acquire_renew_lock(
        &self,
        domains: &[String],
        lease_secs: u64,
    ) -> Result<Option<u64>> {
        let path = self.cert_kv_path(domains);
        let now = current_unix_timestamp();
        let lock_until = now.saturating_add(lease_secs as i64);

        let (record, expected_cas) = match self.client.read_kv2_json(&path).await? {
            None => (
                ZeroizeVaultCertRecord(VaultCertRecord {
                    domains: domains.to_vec(),
                    cert_pem: String::new(),
                    key_pem: String::new(),
                    not_after_unix: 0,
                    updated_by: String::new(),
                    renew_owner: self.node_id.clone(),
                    renew_lock_until: lock_until,
                }),
                0,
            ),
            Some((val, version)) => {
                let mut existing =
                    ZeroizeVaultCertRecord(serde_json::from_value(val).map_err(|e| {
                        FluxgateError::VaultError(format!(
                            "Failed to decode Vault cert record: {}",
                            e
                        ))
                    })?);

                if existing.renew_lock_until > now
                    && !existing.renew_owner.is_empty()
                    && existing.renew_owner != self.node_id
                {
                    return Ok(None);
                }

                if existing.domains.is_empty() {
                    existing.domains = domains.to_vec();
                }
                existing.renew_owner = self.node_id.clone();
                existing.renew_lock_until = lock_until;
                (existing, version)
            }
        };

        let payload = serde_json::to_value(&*record).map_err(|e| {
            FluxgateError::VaultError(format!("Failed to encode Vault lock record: {}", e))
        })?;
        drop(record);

        match self
            .client
            .write_kv2_cas(&path, &payload, expected_cas)
            .await
        {
            Ok(new_version) => Ok(Some(new_version)),
            Err(e) if is_cas_conflict_error(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn publish_cert_and_release_lock(
        &self,
        domains: &[String],
        bundle: &CertBundle,
        expected_version: u64,
    ) -> Result<u64> {
        let path = self.cert_kv_path(domains);
        let record_domains = if bundle.domains.is_empty() {
            domains.to_vec()
        } else {
            bundle.domains.clone()
        };

        let record = ZeroizeVaultCertRecord(VaultCertRecord {
            domains: record_domains,
            cert_pem: bundle.cert_pem.clone(),
            key_pem: bundle.key_pem.as_str().to_string(),
            not_after_unix: bundle.not_after_unix,
            updated_by: self.node_id.clone(),
            renew_owner: String::new(),
            renew_lock_until: 0,
        });

        let payload = serde_json::to_value(&*record).map_err(|e| {
            FluxgateError::VaultError(format!("Failed to encode Vault cert record: {}", e))
        })?;
        drop(record);

        match self
            .client
            .write_kv2_cas(&path, &payload, expected_version)
            .await
        {
            Ok(ver) => Ok(ver),
            Err(e) if is_cas_conflict_error(&e) => {
                let latest_ver = match self.client.read_kv2_json(&path).await? {
                    Some((_, ver)) => ver,
                    None => 0,
                };
                self.client.write_kv2_cas(&path, &payload, latest_ver).await
            }
            Err(e) => Err(e),
        }
    }
}

fn is_cas_conflict_error(err: &FluxgateError) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("cas")
        || msg.contains("check-and-set")
        || msg.contains("conflict")
        || msg.contains("did not match")
        || msg.contains("400")
        || msg.contains("409")
}

pub(crate) fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
