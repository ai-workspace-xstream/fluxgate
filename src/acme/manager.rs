use crate::acme::dns::{AliDnsProvider, CloudflareDnsProvider, DnsProvider, DnsRecordGuard};
use crate::acme::storage::{
    current_unix_timestamp, parse_cert_not_after, CertBundle, LocalCertStorage,
    VaultSharedCertStorage,
};
use crate::config::{AcmeTlsConfig, DnsProviderConfig};
use crate::error::{FluxgateError, Result};
use crate::metrics::MetricsRegistry;
use crate::tls::DynamicCertStore;
use crate::vault::{SecretStore, VaultClient};
use async_trait::async_trait;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, Order,
    OrderStatus,
};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const DEFAULT_PROPAGATION_DELAY_SECS: u64 = 10;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;
const DEFAULT_POLL_TIMEOUT_SECS: u64 = 120;
const DEFAULT_FOLLOWER_WAIT_SECS: u64 = 5;
const DEFAULT_FOLLOWER_MAX_ATTEMPTS: usize = 6;
const DEFAULT_RENEW_LOCK_LEASE_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalOutcome {
    Reused,
    Renewed,
    SyncedFromPeer,
}

pub struct AcmeCertManager {
    local_storage: LocalCertStorage,
    vault_storage: Option<VaultSharedCertStorage>,
    propagation_delay: Duration,
    poll_interval: Duration,
    poll_timeout: Duration,
    follower_wait_interval: Duration,
    follower_max_attempts: usize,
    renew_lock_lease_secs: u64,
}

impl AcmeCertManager {
    pub fn new(
        local_storage: LocalCertStorage,
        vault_storage: Option<VaultSharedCertStorage>,
    ) -> Self {
        Self {
            local_storage,
            vault_storage,
            propagation_delay: Duration::from_secs(DEFAULT_PROPAGATION_DELAY_SECS),
            poll_interval: Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS),
            poll_timeout: Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECS),
            follower_wait_interval: Duration::from_secs(DEFAULT_FOLLOWER_WAIT_SECS),
            follower_max_attempts: DEFAULT_FOLLOWER_MAX_ATTEMPTS,
            renew_lock_lease_secs: DEFAULT_RENEW_LOCK_LEASE_SECS,
        }
    }

    pub fn with_propagation_delay(mut self, delay: Duration) -> Self {
        self.propagation_delay = delay;
        self
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn with_poll_timeout(mut self, timeout: Duration) -> Self {
        self.poll_timeout = timeout;
        self
    }

    pub fn with_follower_wait(mut self, interval: Duration, max_attempts: usize) -> Self {
        self.follower_wait_interval = interval;
        self.follower_max_attempts = max_attempts;
        self
    }

    pub fn with_renew_lock_lease_secs(mut self, lease_secs: u64) -> Self {
        self.renew_lock_lease_secs = lease_secs;
        self
    }

    pub fn build_dns_provider(
        cfg: &DnsProviderConfig,
        secrets: &SecretStore,
    ) -> Result<Box<dyn DnsProvider>> {
        match cfg {
            DnsProviderConfig::Cloudflare { api_token } => {
                let token = secrets.resolve_secret_ref(api_token)?;
                Ok(Box::new(CloudflareDnsProvider::new(token)?))
            }
            DnsProviderConfig::AliDns {
                access_key_id,
                access_key_secret,
            } => {
                let key_id = secrets.resolve_secret_ref(access_key_id)?;
                let key_secret = secrets.resolve_secret_ref(access_key_secret)?;
                Ok(Box::new(AliDnsProvider::new(key_id, key_secret)?))
            }
        }
    }

    pub fn needs_renewal(not_after_unix: i64, renew_before_days: u64) -> bool {
        let now = current_unix_timestamp();
        not_after_unix <= now || (not_after_unix - now) / 86400 < renew_before_days as i64
    }

    pub async fn ensure_valid_cert(
        &self,
        domains: &[String],
        tls_cfg: &AcmeTlsConfig,
        dns: &dyn DnsProvider,
    ) -> Result<(CertBundle, RenewalOutcome)> {
        if domains.is_empty() {
            return Err(FluxgateError::AcmeError(
                "Cannot issue ACME certificate for an empty domain list".to_string(),
            ));
        }

        if let Some(ref vault) = self.vault_storage {
            return self.ensure_shared_cert(domains, tls_cfg, dns, vault).await;
        }

        if let Some(local) = self.local_storage.load_cert(domains)? {
            if !Self::needs_renewal(local.not_after_unix, tls_cfg.renew_before_days) {
                return Ok((local, RenewalOutcome::Reused));
            }
        }

        let issued = self.issue_certificate(domains, &tls_cfg.email, &tls_cfg.ca_url, dns).await?;
        self.local_storage.save_cert(&issued)?;
        Ok((issued, RenewalOutcome::Renewed))
    }

    async fn ensure_shared_cert(
        &self,
        domains: &[String],
        tls_cfg: &AcmeTlsConfig,
        dns: &dyn DnsProvider,
        vault: &VaultSharedCertStorage,
    ) -> Result<(CertBundle, RenewalOutcome)> {
        if let Some((shared, _version)) = vault.load_shared_cert(domains).await? {
            if !Self::needs_renewal(shared.not_after_unix, tls_cfg.renew_before_days) {
                if let Err(e) = self.local_storage.save_cert(&shared) {
                    tracing::warn!(
                        domains = %domains.join(","),
                        "Failed to cache shared Vault certificate locally: {}",
                        e
                    );
                }
                return Ok((shared, RenewalOutcome::Reused));
            }
        }

        let lease_secs = self.renew_lock_lease_secs;
        if let Some(lock_version) = vault.try_acquire_renew_lock(domains, lease_secs).await? {
            // Re-check once after winning lock in case a peer finished publishing just before us.
            if let Some((fresh, _)) = vault.load_shared_cert(domains).await? {
                if !Self::needs_renewal(fresh.not_after_unix, tls_cfg.renew_before_days) {
                    let _ = vault
                        .publish_cert_and_release_lock(domains, &fresh, lock_version)
                        .await;
                    let _ = self.local_storage.save_cert(&fresh);
                    return Ok((fresh, RenewalOutcome::SyncedFromPeer));
                }
            }

            let issued = self
                .issue_certificate(domains, &tls_cfg.email, &tls_cfg.ca_url, dns)
                .await?;
            vault.publish_cert_and_release_lock(domains, &issued, lock_version).await?;
            if let Err(e) = self.local_storage.save_cert(&issued) {
                tracing::warn!(
                    domains = %domains.join(","),
                    "Failed to cache newly issued certificate locally: {}",
                    e
                );
            }
            return Ok((issued, RenewalOutcome::Renewed));
        }

        // Another node holds the renewal lock; wait briefly for it to publish.
        for _ in 0..self.follower_max_attempts {
            tokio::time::sleep(self.follower_wait_interval).await;
            if let Some((shared, _)) = vault.load_shared_cert(domains).await? {
                if !Self::needs_renewal(shared.not_after_unix, tls_cfg.renew_before_days) {
                    let _ = self.local_storage.save_cert(&shared);
                    return Ok((shared, RenewalOutcome::SyncedFromPeer));
                }
            }
        }

        // Fall back to existing unexpired cert if peer is still renewing so service stays up.
        let now = current_unix_timestamp();
        if let Some((existing, _)) = vault.load_shared_cert(domains).await? {
            if existing.not_after_unix > now {
                let _ = self.local_storage.save_cert(&existing);
                return Ok((existing, RenewalOutcome::Reused));
            }
        }
        if let Some(local) = self.local_storage.load_cert(domains)? {
            if local.not_after_unix > now {
                return Ok((local, RenewalOutcome::Reused));
            }
        }

        Err(FluxgateError::AcmeError(format!(
            "Timed out waiting for peer node to publish ACME certificate for {}",
            domains.join(",")
        )))
    }

    pub async fn issue_certificate(
        &self,
        domains: &[String],
        email: &str,
        ca_url: &str,
        dns: &dyn DnsProvider,
    ) -> Result<CertBundle> {
        if domains.is_empty() {
            return Err(FluxgateError::AcmeError(
                "Domain list cannot be empty".to_string(),
            ));
        }
        if email.trim().is_empty() {
            return Err(FluxgateError::AcmeError(
                "ACME account email cannot be empty".to_string(),
            ));
        }
        if ca_url.trim().is_empty() {
            return Err(FluxgateError::AcmeError(
                "ACME CA directory URL cannot be empty".to_string(),
            ));
        }

        let account = match self.local_storage.load_account_credentials_for_ca(ca_url)? {
            Some(creds) => Account::from_credentials(creds).await.map_err(|e| {
                FluxgateError::AcmeError(format!("Failed to restore ACME account: {}", e))
            })?,
            None => {
                let contact_uri = format!("mailto:{}", email.trim());
                let contact = [contact_uri.as_str()];
                let new_account = NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                };
                let (acc, creds) = Account::create(&new_account, ca_url, None).await.map_err(|e| {
                    FluxgateError::AcmeError(format!("Failed to create ACME account: {}", e))
                })?;
                self.local_storage.save_account_credentials(&creds)?;
                acc
            }
        };

        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let new_order = NewOrder {
            identifiers: &identifiers,
        };
        let mut order = account.new_order(&new_order).await.map_err(|e| {
            FluxgateError::AcmeError(format!("Failed to create ACME order: {}", e))
        })?;

        let mut guards: Vec<DnsRecordGuard> = Vec::new();
        let result = self.complete_order(&mut order, domains, dns, &mut guards).await;

        for guard in &guards {
            if let Err(err) = dns.cleanup(guard).await {
                tracing::warn!(
                    fqdn = %guard.fqdn,
                    record_id = %guard.record_id,
                    "Failed to clean up ACME DNS-01 TXT record: {}",
                    err
                );
            }
        }

        result
    }

    async fn complete_order(
        &self,
        order: &mut Order,
        domains: &[String],
        dns: &dyn DnsProvider,
        guards: &mut Vec<DnsRecordGuard>,
    ) -> Result<CertBundle> {
        let authorizations = order.authorizations().await.map_err(|e| {
            FluxgateError::AcmeError(format!("Failed to fetch ACME authorizations: {}", e))
        })?;

        let mut challenge_urls = Vec::new();
        for auth in &authorizations {
            match auth.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    return Err(FluxgateError::AcmeError(format!(
                        "Unexpected ACME authorization status {:?} for {:?}",
                        other, auth.identifier
                    )));
                }
            }

            let Identifier::Dns(ref auth_domain) = auth.identifier;
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .ok_or_else(|| {
                    FluxgateError::AcmeError(format!(
                        "No DNS-01 challenge offered for '{}'",
                        auth_domain
                    ))
                })?;

            let key_auth = order.key_authorization(challenge);
            let dns_value = key_auth.dns_value();
            let base_domain = auth_domain.trim_start_matches("*.");
            let record_fqdn = format!("_acme-challenge.{}", base_domain);

            let guard = dns.present(base_domain, &record_fqdn, &dns_value).await?;
            guards.push(guard);
            challenge_urls.push(challenge.url.clone());
        }

        if !guards.is_empty() {
            tokio::time::sleep(self.propagation_delay).await;
            for url in &challenge_urls {
                order.set_challenge_ready(url).await.map_err(|e| {
                    FluxgateError::AcmeError(format!(
                        "Failed to mark ACME DNS-01 challenge ready: {}",
                        e
                    ))
                })?;
            }
        }

        let deadline = tokio::time::Instant::now() + self.poll_timeout;
        loop {
            let state = order.refresh().await.map_err(|e| {
                FluxgateError::AcmeError(format!("Failed to refresh ACME order state: {}", e))
            })?;
            match state.status {
                OrderStatus::Ready | OrderStatus::Valid => break,
                OrderStatus::Invalid => {
                    let detail = state
                        .error
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "unknown ACME order error".to_string());
                    return Err(FluxgateError::AcmeError(format!(
                        "ACME order became invalid: {}",
                        detail
                    )));
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(FluxgateError::AcmeError(
                            "Timed out waiting for ACME order validation".to_string(),
                        ));
                    }
                    tokio::time::sleep(self.poll_interval).await;
                }
            }
        }

        let kp = rcgen::KeyPair::generate().map_err(|e| {
            FluxgateError::AcmeError(format!("Failed to generate certificate keypair: {}", e))
        })?;
        let params = rcgen::CertificateParams::new(domains.to_vec()).map_err(|e| {
            FluxgateError::AcmeError(format!("Failed to create CSR parameters: {}", e))
        })?;
        let csr = params.serialize_request(&kp).map_err(|e| {
            FluxgateError::AcmeError(format!("Failed to generate CSR: {}", e))
        })?;
        let key_pem = Zeroizing::new(kp.serialize_pem());

        if order.state().status != OrderStatus::Valid {
            order.finalize(csr.der().as_ref()).await.map_err(|e| {
                FluxgateError::AcmeError(format!("Failed to finalize ACME order: {}", e))
            })?;
        }

        let cert_pem = loop {
            if let Some(pem) = order.certificate().await.map_err(|e| {
                FluxgateError::AcmeError(format!("Failed to fetch ACME certificate: {}", e))
            })? {
                break pem;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(FluxgateError::AcmeError(
                    "Timed out waiting for ACME certificate issuance".to_string(),
                ));
            }
            tokio::time::sleep(self.poll_interval).await;
        };

        let not_after_unix = parse_cert_not_after(&cert_pem)?;
        Ok(CertBundle {
            domains: domains.to_vec(),
            cert_pem,
            key_pem,
            not_after_unix,
        })
    }
}

pub struct CertRenewalService {
    pub sites: Vec<(Vec<String>, AcmeTlsConfig)>,
    pub secret_store: Arc<SecretStore>,
    pub vault_client: Option<Arc<VaultClient>>,
    pub cert_store: Arc<DynamicCertStore>,
    pub metrics: Option<Arc<MetricsRegistry>>,
    pub node_id: String,
}

impl CertRenewalService {
    pub fn new(
        sites: Vec<(Vec<String>, AcmeTlsConfig)>,
        secret_store: Arc<SecretStore>,
        vault_client: Option<Arc<VaultClient>>,
        cert_store: Arc<DynamicCertStore>,
        metrics: Option<Arc<MetricsRegistry>>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            sites,
            secret_store,
            vault_client,
            cert_store,
            metrics,
            node_id: node_id.into(),
        }
    }

    fn preload_local_certs(&self) {
        let now = current_unix_timestamp();
        for (domains, tls_cfg) in &self.sites {
            let Ok(storage) = LocalCertStorage::new(&tls_cfg.storage_dir) else {
                continue;
            };
            if let Ok(Some(bundle)) = storage.load_cert(domains) {
                if bundle.not_after_unix > now {
                    if let Err(e) = self.cert_store.upsert_pem(
                        &bundle.domains,
                        &bundle.cert_pem,
                        bundle.key_pem.as_str(),
                        bundle.not_after_unix,
                    ) {
                        tracing::warn!(
                            domains = %domains.join(","),
                            "Failed to preload local cached certificate into DynamicCertStore: {}",
                            e
                        );
                    } else if let Some(ref reg) = self.metrics {
                        reg.record_tls_cert_expiry(&domains.join(","), bundle.not_after_unix);
                    }
                }
            }
        }
    }

    async fn sync_all_sites(&self) -> bool {
        let mut any_failed = false;
        for (domains, tls_cfg) in &self.sites {
            if !self.sync_one_site(domains, tls_cfg).await {
                any_failed = true;
            }
        }
        any_failed
    }

    async fn sync_one_site(&self, domains: &[String], tls_cfg: &AcmeTlsConfig) -> bool {
        let domains_label = domains.join(",");
        let provider_label = match &tls_cfg.dns_provider {
            DnsProviderConfig::Cloudflare { .. } => "cloudflare",
            DnsProviderConfig::AliDns { .. } => "alidns",
        };

        let local_storage = match LocalCertStorage::new(&tls_cfg.storage_dir) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    domains = %domains_label,
                    storage_dir = %tls_cfg.storage_dir.display(),
                    "Failed to initialize ACME local cert storage: {}",
                    e
                );
                if let Some(ref reg) = self.metrics {
                    reg.record_acme_renew(&domains_label, provider_label, "error");
                }
                return false;
            }
        };

        let dns_res =
            AcmeCertManager::build_dns_provider(&tls_cfg.dns_provider, &self.secret_store);
        let dns = match dns_res {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    domains = %domains_label,
                    provider = provider_label,
                    "ACME DNS credentials not ready yet: {}",
                    e
                );
                if let Some(ref reg) = self.metrics {
                    reg.record_acme_renew(&domains_label, provider_label, "error");
                }
                return false;
            }
        };

        let vault_storage = match (&tls_cfg.vault_storage_path, &self.vault_client) {
            (Some(path), Some(client)) => Some(VaultSharedCertStorage::new(
                client.clone(),
                path.clone(),
                self.node_id.clone(),
            )),
            (Some(path), None) => {
                tracing::warn!(
                    domains = %domains_label,
                    vault_path = %path,
                    "ACME Vault cert sharing configured, but Vault client is unavailable; using local storage only"
                );
                None
            }
            (None, _) => None,
        };

        let manager = AcmeCertManager::new(local_storage, vault_storage);
        match manager.ensure_valid_cert(domains, tls_cfg, dns.as_ref()).await {
            Ok((bundle, outcome)) => {
                if let Err(e) = self.cert_store.upsert_pem(
                    &bundle.domains,
                    &bundle.cert_pem,
                    bundle.key_pem.as_str(),
                    bundle.not_after_unix,
                ) {
                    tracing::error!(
                        domains = %domains_label,
                        "Failed to install certificate into DynamicCertStore: {}",
                        e
                    );
                    if let Some(ref reg) = self.metrics {
                        reg.record_acme_renew(&domains_label, dns.name(), "error");
                    }
                    return false;
                }

                let result_label = match outcome {
                    RenewalOutcome::Renewed => {
                        tracing::info!(
                            domains = %domains_label,
                            provider = dns.name(),
                            not_after_unix = bundle.not_after_unix,
                            "ACME certificate issued/renewed successfully"
                        );
                        "success"
                    }
                    RenewalOutcome::Reused => "skipped",
                    RenewalOutcome::SyncedFromPeer => {
                        tracing::info!(
                            domains = %domains_label,
                            not_after_unix = bundle.not_after_unix,
                            "Synced renewed ACME certificate from Vault peer"
                        );
                        "skipped"
                    }
                };

                if let Some(ref reg) = self.metrics {
                    reg.record_tls_cert_expiry(&domains_label, bundle.not_after_unix);
                    reg.record_acme_renew(&domains_label, dns.name(), result_label);
                }
                true
            }
            Err(e) => {
                tracing::error!(
                    domains = %domains_label,
                    provider = dns.name(),
                    "ACME certificate sync/renewal failed: {}",
                    e
                );
                if let Some(ref reg) = self.metrics {
                    reg.record_acme_renew(&domains_label, dns.name(), "error");
                }
                false
            }
        }
    }
}

#[async_trait]
impl BackgroundService for CertRenewalService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if self.sites.is_empty() {
            tracing::debug!("No ACME TLS sites configured; certificate renewal service idle");
            let _ = shutdown.changed().await;
            return;
        }

        self.preload_local_certs();
        let mut any_failed = self.sync_all_sites().await;
        let mut retry_attempt: u32 = 0;

        loop {
            let delay = if any_failed {
                retry_attempt = retry_attempt.saturating_add(1);
                match retry_attempt {
                    1 => Duration::from_secs(5),
                    2 => Duration::from_secs(15),
                    _ => Duration::from_secs(60),
                }
            } else {
                retry_attempt = 0;
                Duration::from_secs(3600)
            };

            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("Shutting down ACME certificate renewal service");
                    break;
                }
                _ = tokio::time::sleep(delay) => {
                    any_failed = self.sync_all_sites().await;
                }
            }
        }
    }
}
