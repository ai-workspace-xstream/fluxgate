use crate::config::TlsConfig;
use crate::error::{FluxgateError, Result};
use async_trait::async_trait;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::NameType;
use pingora::tls::x509::X509;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub fn build_tls_settings(tls: &TlsConfig) -> Result<TlsSettings> {
    match tls {
        TlsConfig::Static {
            cert_path,
            key_path,
        } => {
            let cert = cert_path.to_string_lossy();
            let key = key_path.to_string_lossy();
            let mut settings = TlsSettings::intermediate(&cert, &key).map_err(|e| {
                FluxgateError::TlsError(format!(
                    "Failed to load TLS cert ({}) / key ({}): {}",
                    cert, key, e
                ))
            })?;
            settings.enable_h2();
            Ok(settings)
        }
        TlsConfig::Acme(_) => Err(FluxgateError::TlsError(
            "ACME TLS configuration requires build_dynamic_tls_settings".to_string(),
        )),
    }
}

pub fn build_dynamic_tls_settings(store: Arc<DynamicCertStore>) -> Result<TlsSettings> {
    let mut settings =
        TlsSettings::with_callbacks(Box::new(DynamicTlsAccept::new(store))).map_err(|e| {
            FluxgateError::TlsError(format!("Failed to initialize dynamic TLS callbacks: {}", e))
        })?;
    settings.enable_h2();
    Ok(settings)
}

#[derive(Clone)]
struct CertEntry {
    domains: Vec<String>,
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
    not_after_unix: i64,
}

impl CertEntry {
    fn to_tuple(&self) -> (X509, Vec<X509>, PKey<Private>) {
        (self.leaf.clone(), self.chain.clone(), self.key.clone())
    }
}

#[derive(Default)]
struct CertStoreInner {
    static_entries: Vec<CertEntry>,
    acme_entries: Vec<CertEntry>,
}

#[derive(Default)]
pub struct DynamicCertStore {
    inner: RwLock<CertStoreInner>,
}

impl DynamicCertStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_pem(
        &self,
        domains: &[String],
        cert_pem: &str,
        key_pem: &str,
        not_after_unix: i64,
    ) -> Result<()> {
        let entry = build_cert_entry(domains, cert_pem, key_pem, not_after_unix)?;
        let mut guard = self.inner.write().map_err(|_| {
            FluxgateError::TlsError("Certificate store write lock poisoned".to_string())
        })?;
        upsert_into_vec(&mut guard.acme_entries, entry);
        Ok(())
    }

    pub fn load_static_files(
        &self,
        domains: &[String],
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<()> {
        let entry = load_static_entry(domains, cert_path, key_path)?;
        let mut guard = self.inner.write().map_err(|_| {
            FluxgateError::TlsError("Certificate store write lock poisoned".to_string())
        })?;
        upsert_into_vec(&mut guard.static_entries, entry);
        Ok(())
    }

    pub fn clear_and_reload_static(
        &self,
        entries: Vec<(Vec<String>, PathBuf, PathBuf)>,
    ) -> Result<()> {
        let mut parsed = Vec::with_capacity(entries.len());
        for (domains, cert_path, key_path) in entries {
            let entry = load_static_entry(&domains, &cert_path, &key_path)?;
            upsert_into_vec(&mut parsed, entry);
        }
        let mut guard = self.inner.write().map_err(|_| {
            FluxgateError::TlsError("Certificate store write lock poisoned".to_string())
        })?;
        guard.static_entries = parsed;
        Ok(())
    }

    pub fn lookup_sni(&self, sni: &str) -> Option<(X509, Vec<X509>, PKey<Private>)> {
        let guard = self.inner.read().ok()?;
        let target = normalize_host(sni);

        if target.is_empty() {
            return guard
                .acme_entries
                .first()
                .or_else(|| guard.static_entries.first())
                .map(CertEntry::to_tuple);
        }

        if let Some(entry) = find_exact(&guard.acme_entries, &target)
            .or_else(|| find_exact(&guard.static_entries, &target))
        {
            return Some(entry.to_tuple());
        }

        if let Some(entry) = find_wildcard(&guard.acme_entries, &target)
            .or_else(|| find_wildcard(&guard.static_entries, &target))
        {
            return Some(entry.to_tuple());
        }

        None
    }

    pub fn has_domain(&self, sni: &str) -> bool {
        let target = normalize_host(sni);
        if target.is_empty() {
            return false;
        }
        self.lookup_sni(&target).is_some()
    }

    pub fn domain_count(&self) -> usize {
        let Ok(guard) = self.inner.read() else {
            return 0;
        };
        let mut unique = HashSet::new();
        for entry in guard.acme_entries.iter().chain(guard.static_entries.iter()) {
            for d in &entry.domains {
                unique.insert(d.as_str());
            }
        }
        unique.len()
    }

    pub fn get_expiry(&self, sni: &str) -> Option<i64> {
        let guard = self.inner.read().ok()?;
        let target = normalize_host(sni);
        if target.is_empty() {
            return None;
        }
        find_exact(&guard.acme_entries, &target)
            .or_else(|| find_exact(&guard.static_entries, &target))
            .or_else(|| find_wildcard(&guard.acme_entries, &target))
            .or_else(|| find_wildcard(&guard.static_entries, &target))
            .map(|e| e.not_after_unix)
    }

    pub fn list_expiries(&self) -> Vec<(Vec<String>, i64)> {
        let Ok(guard) = self.inner.read() else {
            return Vec::new();
        };
        guard
            .acme_entries
            .iter()
            .chain(guard.static_entries.iter())
            .map(|e| (e.domains.clone(), e.not_after_unix))
            .collect()
    }
}

pub struct DynamicTlsAccept {
    store: Arc<DynamicCertStore>,
}

impl DynamicTlsAccept {
    pub fn new(store: Arc<DynamicCertStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl TlsAccept for DynamicTlsAccept {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let sni = ssl.servername(NameType::HOST_NAME).unwrap_or("").to_string();

        if let Some((leaf, chain, key)) = self.store.lookup_sni(&sni) {
            if let Err(e) = ext::ssl_use_certificate(ssl, &leaf) {
                tracing::error!("Failed to set TLS certificate for SNI '{}': {}", sni, e);
                return;
            }
            if let Err(e) = ext::ssl_use_private_key(ssl, &key) {
                tracing::error!("Failed to set TLS private key for SNI '{}': {}", sni, e);
                return;
            }
            for cert in chain {
                if let Err(e) = ssl.add_chain_cert(cert) {
                    tracing::warn!(
                        "Failed to append intermediate TLS chain cert for SNI '{}': {}",
                        sni,
                        e
                    );
                }
            }
        } else {
            tracing::warn!("No TLS certificate matched SNI '{}'", sni);
        }
    }
}

fn load_static_entry(domains: &[String], cert_path: &Path, key_path: &Path) -> Result<CertEntry> {
    let cert_pem = fs::read_to_string(cert_path).map_err(|e| {
        FluxgateError::TlsError(format!(
            "Failed to read TLS certificate {}: {}",
            cert_path.display(),
            e
        ))
    })?;
    let key_pem = fs::read_to_string(key_path).map_err(|e| {
        FluxgateError::TlsError(format!(
            "Failed to read TLS private key {}: {}",
            key_path.display(),
            e
        ))
    })?;
    build_cert_entry(domains, &cert_pem, &key_pem, 0)
}

fn build_cert_entry(
    domains: &[String],
    cert_pem: &str,
    key_pem: &str,
    not_after_unix: i64,
) -> Result<CertEntry> {
    let norm_domains = normalize_domains(domains);
    if norm_domains.is_empty() {
        return Err(FluxgateError::TlsError(
            "TLS certificate entry must include at least one domain".to_string(),
        ));
    }

    let mut certs = X509::stack_from_pem(cert_pem.as_bytes()).map_err(|e| {
        FluxgateError::TlsError(format!("Failed to parse certificate PEM chain: {}", e))
    })?;
    if certs.is_empty() {
        return Err(FluxgateError::TlsError(
            "Certificate PEM contains no X.509 certificates".to_string(),
        ));
    }
    let leaf = certs.remove(0);
    let chain = certs;

    let key = PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|e| {
        FluxgateError::TlsError(format!("Failed to parse private key PEM: {}", e))
    })?;

    let effective_not_after = if not_after_unix > 0 {
        not_after_unix
    } else {
        extract_not_after_unix(&leaf)
    };

    Ok(CertEntry {
        domains: norm_domains,
        leaf,
        chain,
        key,
        not_after_unix: effective_not_after,
    })
}

fn extract_not_after_unix(leaf: &X509) -> i64 {
    if let Ok(der) = leaf.to_der() {
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&der) {
            return parsed.validity().not_after.timestamp();
        }
    }
    0
}

fn upsert_into_vec(entries: &mut Vec<CertEntry>, entry: CertEntry) {
    for existing in entries.iter_mut() {
        existing.domains.retain(|d| !entry.domains.contains(d));
    }
    entries.retain(|e| !e.domains.is_empty());
    entries.push(entry);
}

fn normalize_domains(domains: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(domains.len());
    for d in domains {
        let norm = normalize_host(d);
        if !norm.is_empty() && !out.contains(&norm) {
            out.push(norm);
        }
    }
    out
}

fn normalize_host(host: &str) -> String {
    let clean = host.trim().trim_end_matches('.');
    clean.split(':').next().unwrap_or(clean).to_ascii_lowercase()
}

fn find_exact<'a>(entries: &'a [CertEntry], target: &str) -> Option<&'a CertEntry> {
    entries.iter().find(|entry| entry.domains.iter().any(|d| d == target))
}

fn find_wildcard<'a>(entries: &'a [CertEntry], target: &str) -> Option<&'a CertEntry> {
    entries.iter().find(|entry| {
        entry.domains.iter().any(|d| matches_single_level_wildcard(d, target))
    })
}

fn matches_single_level_wildcard(pattern: &str, host: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let dot_suffix = format!(".{}", suffix);
    let Some(prefix) = host.strip_suffix(&dot_suffix) else {
        return false;
    };
    !prefix.is_empty() && !prefix.contains('.')
}
