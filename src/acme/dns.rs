use crate::error::{FluxgateError, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use sha1::Sha1;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const DEFAULT_CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const DEFAULT_ALIDNS_ENDPOINT: &str = "https://alidns.aliyuncs.com";
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecordGuard {
    pub zone_id: String,
    pub record_id: String,
    pub fqdn: String,
    pub value: String,
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    fn name(&self) -> &'static str;

    async fn present(
        &self,
        zone_domain: &str,
        fqdn: &str,
        txt_value: &str,
    ) -> Result<DnsRecordGuard>;

    async fn cleanup(&self, guard: &DnsRecordGuard) -> Result<()>;
}

#[derive(Clone)]
pub struct CloudflareDnsProvider {
    api_base: String,
    api_token: Zeroizing<String>,
    http: Client,
}

impl fmt::Debug for CloudflareDnsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareDnsProvider")
            .field("api_base", &self.api_base)
            .field("api_token", &"[REDACTED]")
            .finish()
    }
}

impl CloudflareDnsProvider {
    pub fn new(api_token: Zeroizing<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                FluxgateError::AcmeError(format!("Failed to build Cloudflare HTTP client: {}", e))
            })?;
        Ok(Self {
            api_base: DEFAULT_CLOUDFLARE_API_BASE.to_string(),
            api_token,
            http,
        })
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.api_base = base_url.into().trim_end_matches('/').to_string();
        self
    }

    /// Extract candidate apex/zone names from longest to shortest
    /// (e.g. `_acme-challenge.sub.svc.plus` -> `["sub.svc.plus", "svc.plus"]`).
    pub fn extract_apex_candidates(domain: &str) -> Vec<String> {
        extract_zone_candidates(domain)
    }

    async fn find_zone_id(&self, candidates: &[String]) -> Result<String> {
        for candidate in candidates {
            let url = format!("{}/zones", self.api_base);
            let resp = self
                .http
                .get(&url)
                .bearer_auth(self.api_token.as_str())
                .query(&[("name", candidate.as_str()), ("status", "active")])
                .send()
                .await
                .map_err(|e| {
                    FluxgateError::AcmeError(format!(
                        "Cloudflare zone lookup request failed for '{}': {}",
                        candidate, e
                    ))
                })?;

            let status = resp.status();
            let body = resp.text().await.map_err(|e| {
                FluxgateError::AcmeError(format!(
                    "Failed to read Cloudflare zone lookup response: {}",
                    e
                ))
            })?;

            if !status.is_success() {
                return Err(FluxgateError::AcmeError(format!(
                    "Cloudflare zone lookup failed with HTTP {} for '{}'",
                    status.as_u16(),
                    candidate
                )));
            }

            let parsed: CloudflareResponse<Vec<CloudflareZone>> = serde_json::from_str(&body)
                .map_err(|e| {
                    FluxgateError::AcmeError(format!(
                        "Failed to parse Cloudflare zone lookup JSON: {}",
                        e
                    ))
                })?;

            if !parsed.success {
                return Err(FluxgateError::AcmeError(format!(
                    "Cloudflare zone lookup unsuccessful for '{}': {}",
                    candidate,
                    format_cf_errors(&parsed.errors)
                )));
            }

            if let Some(zone) = parsed.result.and_then(|zones| zones.into_iter().next()) {
                return Ok(zone.id);
            }
        }

        Err(FluxgateError::AcmeError(format!(
            "No active Cloudflare zone found for candidates: {:?}",
            candidates
        )))
    }
}

#[derive(Deserialize)]
struct CloudflareErrorItem {
    code: Option<i64>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct CloudflareZone {
    id: String,
}

#[derive(Deserialize)]
struct CloudflareDnsRecord {
    id: String,
}

#[derive(Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CloudflareErrorItem>,
    result: Option<T>,
}

fn format_cf_errors(errors: &[CloudflareErrorItem]) -> String {
    if errors.is_empty() {
        return "unknown error".to_string();
    }
    errors
        .iter()
        .map(|e| match (e.code, e.message.as_deref()) {
            (Some(c), Some(m)) => format!("{} ({})", m, c),
            (None, Some(m)) => m.to_string(),
            (Some(c), None) => format!("code {}", c),
            (None, None) => "unknown".to_string(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[async_trait]
impl DnsProvider for CloudflareDnsProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn present(
        &self,
        zone_domain: &str,
        fqdn: &str,
        txt_value: &str,
    ) -> Result<DnsRecordGuard> {
        let fqdn_trimmed = fqdn.trim().trim_end_matches('.');
        let mut candidates = Self::extract_apex_candidates(zone_domain);
        if candidates.is_empty() {
            candidates = Self::extract_apex_candidates(fqdn_trimmed);
        }
        if candidates.is_empty() {
            return Err(FluxgateError::AcmeError(format!(
                "Cannot derive Cloudflare zone candidates from '{}' / '{}'",
                zone_domain, fqdn
            )));
        }

        let zone_id = self.find_zone_id(&candidates).await?;
        let url = format!("{}/zones/{}/dns_records", self.api_base, zone_id);
        let payload = json!({
            "type": "TXT",
            "name": fqdn_trimmed,
            "content": txt_value,
            "ttl": 120
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(self.api_token.as_str())
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                FluxgateError::AcmeError(format!(
                    "Cloudflare TXT record create request failed for '{}': {}",
                    fqdn_trimmed, e
                ))
            })?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| {
            FluxgateError::AcmeError(format!(
                "Failed to read Cloudflare TXT create response: {}",
                e
            ))
        })?;

        if !status.is_success() {
            return Err(FluxgateError::AcmeError(format!(
                "Cloudflare TXT record create failed with HTTP {} for '{}'",
                status.as_u16(),
                fqdn_trimmed
            )));
        }

        let parsed: CloudflareResponse<CloudflareDnsRecord> =
            serde_json::from_str(&body).map_err(|e| {
                FluxgateError::AcmeError(format!(
                    "Failed to parse Cloudflare TXT create JSON: {}",
                    e
                ))
            })?;

        if !parsed.success {
            return Err(FluxgateError::AcmeError(format!(
                "Cloudflare TXT record create unsuccessful for '{}': {}",
                fqdn_trimmed,
                format_cf_errors(&parsed.errors)
            )));
        }

        let record = parsed.result.ok_or_else(|| {
            FluxgateError::AcmeError(format!(
                "Cloudflare TXT record create response missing result for '{}'",
                fqdn_trimmed
            ))
        })?;

        Ok(DnsRecordGuard {
            zone_id,
            record_id: record.id,
            fqdn: fqdn_trimmed.to_string(),
            value: txt_value.to_string(),
        })
    }

    async fn cleanup(&self, guard: &DnsRecordGuard) -> Result<()> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.api_base, guard.zone_id, guard.record_id
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(self.api_token.as_str())
            .send()
            .await
            .map_err(|e| {
                FluxgateError::AcmeError(format!(
                    "Cloudflare TXT record delete request failed for '{}': {}",
                    guard.fqdn, e
                ))
            })?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| {
            FluxgateError::AcmeError(format!(
                "Failed to read Cloudflare TXT delete response: {}",
                e
            ))
        })?;

        if !status.is_success() {
            return Err(FluxgateError::AcmeError(format!(
                "Cloudflare TXT record delete failed with HTTP {} for '{}' (record_id={})",
                status.as_u16(),
                guard.fqdn,
                guard.record_id
            )));
        }

        if !body.trim().is_empty() {
            if let Ok(parsed) = serde_json::from_str::<CloudflareResponse<serde_json::Value>>(&body)
            {
                if !parsed.success {
                    return Err(FluxgateError::AcmeError(format!(
                        "Cloudflare TXT record delete unsuccessful for '{}': {}",
                        guard.fqdn,
                        format_cf_errors(&parsed.errors)
                    )));
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct AliDnsProvider {
    endpoint: String,
    access_key_id: Zeroizing<String>,
    access_key_secret: Zeroizing<String>,
    http: Client,
}

impl fmt::Debug for AliDnsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AliDnsProvider")
            .field("endpoint", &self.endpoint)
            .field("access_key_id", &"[REDACTED]")
            .field("access_key_secret", &"[REDACTED]")
            .finish()
    }
}

impl AliDnsProvider {
    pub fn new(
        access_key_id: Zeroizing<String>,
        access_key_secret: Zeroizing<String>,
    ) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                FluxgateError::AcmeError(format!("Failed to build AliDNS HTTP client: {}", e))
            })?;
        Ok(Self {
            endpoint: DEFAULT_ALIDNS_ENDPOINT.to_string(),
            access_key_id,
            access_key_secret,
            http,
        })
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into().trim_end_matches('/').to_string();
        self
    }

    /// Compute canonical Aliyun POP RPC `HMAC-SHA1` (`SignatureVersion=1.0`) signature.
    pub fn sign_rpc_params(
        http_method: &str,
        params: &BTreeMap<String, String>,
        access_key_secret: &str,
    ) -> String {
        let canonical_query = canonicalize_aliyun_params(params);
        let string_to_sign = format!(
            "{}&{}&{}",
            http_method.to_ascii_uppercase(),
            aliyun_percent_encode("/"),
            aliyun_percent_encode(&canonical_query)
        );
        let signing_key = Zeroizing::new(format!("{}&", access_key_secret));
        let mut mac = Hmac::<Sha1>::new_from_slice(signing_key.as_bytes())
            .expect("HMAC-SHA1 accepts keys of any size");
        mac.update(string_to_sign.as_bytes());
        BASE64_STANDARD.encode(mac.finalize().into_bytes())
    }

    fn base_rpc_params(&self, action: &str) -> BTreeMap<String, String> {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), action.to_string());
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("Version".to_string(), "2015-01-09".to_string());
        params.insert(
            "AccessKeyId".to_string(),
            self.access_key_id.as_str().to_string(),
        );
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert(
            "Timestamp".to_string(),
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("SignatureNonce".to_string(), generate_nonce());
        params
    }

    async fn call_rpc(
        &self,
        action: &str,
        extra_params: &[(&str, &str)],
    ) -> Result<serde_json::Value> {
        let mut params = self.base_rpc_params(action);
        for (k, v) in extra_params {
            params.insert((*k).to_string(), (*v).to_string());
        }

        let canonical_query = canonicalize_aliyun_params(&params);
        let signature = Self::sign_rpc_params("GET", &params, self.access_key_secret.as_str());
        let url = format!(
            "{}/?{}&Signature={}",
            self.endpoint,
            canonical_query,
            aliyun_percent_encode(&signature)
        );

        let resp = self.http.get(&url).send().await.map_err(|e| {
            FluxgateError::AcmeError(format!("AliDNS RPC '{}' request failed: {}", action, e))
        })?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| {
            FluxgateError::AcmeError(format!(
                "Failed to read AliDNS RPC '{}' response: {}",
                action, e
            ))
        })?;

        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| {
            json!({
                "Code": format!("HTTP_{}", status.as_u16()),
                "Message": body
            })
        });

        if !status.is_success() || parsed.get("Code").and_then(|v| v.as_str()).is_some() {
            let code = parsed
                .get("Code")
                .and_then(|v| v.as_str())
                .unwrap_or("UnknownError");
            let msg = parsed
                .get("Message")
                .and_then(|v| v.as_str())
                .unwrap_or("request failed");
            return Err(FluxgateError::AcmeError(format!(
                "AliDNS RPC '{}' failed (HTTP {}, code={}): {}",
                action,
                status.as_u16(),
                code,
                msg
            )));
        }

        Ok(parsed)
    }

    async fn describe_matching_domain(&self, fqdn: &str, keyword: Option<&str>) -> Option<String> {
        let mut extra = vec![("PageSize", "100")];
        if let Some(kw) = keyword {
            extra.push(("KeyWord", kw));
        }

        let resp = self.call_rpc("DescribeDomains", &extra).await.ok()?;
        let domains = resp
            .get("Domains")
            .and_then(|d| d.get("Domain"))
            .and_then(|arr| arr.as_array())?;

        let mut best: Option<String> = None;
        for item in domains {
            if let Some(name) = item.get("DomainName").and_then(|v| v.as_str()) {
                if split_rr_and_domain(fqdn, name).is_some() {
                    let replace = best.as_ref().is_none_or(|prev| name.len() > prev.len());
                    if replace {
                        best = Some(name.to_string());
                    }
                }
            }
        }
        best
    }
}

#[async_trait]
impl DnsProvider for AliDnsProvider {
    fn name(&self) -> &'static str {
        "alidns"
    }

    async fn present(
        &self,
        zone_domain: &str,
        fqdn: &str,
        txt_value: &str,
    ) -> Result<DnsRecordGuard> {
        let fqdn_trimmed = fqdn.trim().trim_end_matches('.');
        let mut candidates = extract_zone_candidates(zone_domain);
        if candidates.is_empty() {
            candidates = extract_zone_candidates(fqdn_trimmed);
        }

        let keyword = candidates.last().map(String::as_str);
        if let Some(matched) = self.describe_matching_domain(fqdn_trimmed, keyword).await {
            if !candidates.iter().any(|c| c.eq_ignore_ascii_case(&matched)) {
                candidates.insert(0, matched);
            } else {
                candidates.retain(|c| !c.eq_ignore_ascii_case(&matched));
                candidates.insert(0, matched);
            }
        }

        if candidates.is_empty() {
            return Err(FluxgateError::AcmeError(format!(
                "Cannot derive AliDNS domain candidates from '{}' / '{}'",
                zone_domain, fqdn
            )));
        }

        let mut last_err: Option<FluxgateError> = None;
        for domain_name in &candidates {
            let Some((rr, domain)) = split_rr_and_domain(fqdn_trimmed, domain_name) else {
                continue;
            };

            let rpc_params = [
                ("DomainName", domain.as_str()),
                ("RR", rr.as_str()),
                ("Type", "TXT"),
                ("Value", txt_value),
                ("TTL", "600"),
            ];
            match self.call_rpc("AddDomainRecord", &rpc_params).await {
                Ok(resp) => {
                    let record_id = resp
                        .get("RecordId")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| {
                            FluxgateError::AcmeError(format!(
                                "AliDNS AddDomainRecord response missing RecordId for '{}'",
                                fqdn_trimmed
                            ))
                        })?;
                    return Ok(DnsRecordGuard {
                        zone_id: domain,
                        record_id,
                        fqdn: fqdn_trimmed.to_string(),
                        value: txt_value.to_string(),
                    });
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            FluxgateError::AcmeError(format!(
                "AliDNS failed to add TXT record for '{}'",
                fqdn_trimmed
            ))
        }))
    }

    async fn cleanup(&self, guard: &DnsRecordGuard) -> Result<()> {
        let rpc_params = [("RecordId", guard.record_id.as_str())];
        self.call_rpc("DeleteDomainRecord", &rpc_params).await?;
        Ok(())
    }
}

fn extract_zone_candidates(domain: &str) -> Vec<String> {
    let mut clean = domain.trim().trim_end_matches('.');
    while let Some(stripped) = clean
        .strip_prefix("*.")
        .or_else(|| clean.strip_prefix("_acme-challenge."))
    {
        clean = stripped;
    }

    if clean.is_empty() {
        return Vec::new();
    }

    let parts: Vec<&str> = clean.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Vec::new();
    }
    if parts.len() == 1 {
        return vec![parts[0].to_string()];
    }

    let mut out = Vec::with_capacity(parts.len() - 1);
    for idx in 0..=parts.len() - 2 {
        out.push(parts[idx..].join("."));
    }
    out
}

fn split_rr_and_domain(fqdn: &str, domain_name: &str) -> Option<(String, String)> {
    let fqdn_clean = fqdn.trim().trim_end_matches('.');
    let domain_clean = domain_name.trim().trim_end_matches('.');
    if fqdn_clean.is_empty() || domain_clean.is_empty() {
        return None;
    }

    if fqdn_clean.eq_ignore_ascii_case(domain_clean) {
        return Some(("@".to_string(), domain_clean.to_string()));
    }

    let fqdn_lower = fqdn_clean.to_ascii_lowercase();
    let suffix = format!(".{}", domain_clean.to_ascii_lowercase());
    if fqdn_lower.ends_with(&suffix) {
        let rr_len = fqdn_clean.len() - suffix.len();
        let rr = &fqdn_clean[..rr_len];
        if !rr.is_empty() {
            return Some((rr.to_string(), domain_clean.to_string()));
        }
    }
    None
}

fn canonicalize_aliyun_params(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .filter(|(k, _)| k.as_str() != "Signature")
        .map(|(k, v)| format!("{}={}", aliyun_percent_encode(k), aliyun_percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encode according to Aliyun POP RPC spec (RFC 3986 unreserved `A-Z a-z 0-9 - _ . ~`;
/// spaces as `%20`, asterisks as `%2A`, tildes unencoded as `~`).
fn aliyun_percent_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

fn generate_nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}", nanos, seq)
}
