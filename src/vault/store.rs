use crate::config::ast::SecretRef;
use crate::error::{FluxgateError, Result};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct VaultSecretEntry {
    pub version: u64,
    pub last_sync_unix: i64,
    pub data: HashMap<String, Zeroizing<String>>,
}

impl fmt::Debug for VaultSecretEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys: Vec<&str> = self.data.keys().map(String::as_str).collect();
        keys.sort_unstable();
        f.debug_struct("VaultSecretEntry")
            .field("version", &self.version)
            .field("last_sync_unix", &self.last_sync_unix)
            .field("keys", &keys)
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct SecretStore {
    inner: Arc<RwLock<HashMap<String, VaultSecretEntry>>>,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut entries: Vec<(&String, &VaultSecretEntry)> = guard.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut dbg = f.debug_struct("SecretStore");
        for (alias, entry) in entries {
            dbg.field(alias, entry);
        }
        dbg.finish()
    }
}

impl SecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_alias(
        &self,
        alias: &str,
        data: HashMap<String, Zeroizing<String>>,
        version: u64,
        synced_at_unix: i64,
    ) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(
            alias.to_string(),
            VaultSecretEntry {
                version,
                last_sync_unix: synced_at_unix,
                data,
            },
        );
    }

    pub fn get_secret(&self, alias: &str, key: &str) -> Option<Zeroizing<String>> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard
            .get(alias)
            .and_then(|entry| entry.data.get(key))
            .cloned()
    }

    pub fn get_entry(&self, alias: &str) -> Option<VaultSecretEntry> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.get(alias).cloned()
    }

    pub fn alias_version(&self, alias: &str) -> Option<u64> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.get(alias).map(|entry| entry.version)
    }

    pub fn resolve_secret_ref(&self, secret_ref: &SecretRef) -> Result<Zeroizing<String>> {
        match secret_ref {
            SecretRef::Literal(s) => Ok(Zeroizing::new(s.clone())),
            SecretRef::Env(var) => match std::env::var(var) {
                Ok(val) => {
                    let secret = Zeroizing::new(val);
                    if secret.is_empty() {
                        Err(FluxgateError::VaultError(format!(
                            "Environment variable '{}' is empty",
                            var
                        )))
                    } else {
                        Ok(secret)
                    }
                }
                Err(_) => Err(FluxgateError::VaultError(format!(
                    "Environment variable '{}' is not set",
                    var
                ))),
            },
            SecretRef::Vault { alias, key } => {
                let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
                let entry = guard.get(alias).ok_or_else(|| {
                    FluxgateError::VaultError(format!(
                        "Vault secret alias '{}' has not been synced yet",
                        alias
                    ))
                })?;
                entry.data.get(key).cloned().ok_or_else(|| {
                    FluxgateError::VaultError(format!(
                        "Vault secret key '{}.{}' not found in synced entry (version {})",
                        alias, key, entry.version
                    ))
                })
            }
        }
    }

    pub fn snapshot_summary(&self) -> Vec<(String, u64, i64, usize)> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut summary = Vec::with_capacity(guard.len());
        for (alias, entry) in guard.iter() {
            let row = (
                alias.clone(),
                entry.version,
                entry.last_sync_unix,
                entry.data.len(),
            );
            summary.push(row);
        }
        summary.sort_by(|a, b| a.0.cmp(&b.0));
        summary
    }
}
