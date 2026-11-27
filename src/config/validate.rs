use crate::config::ast::*;
use crate::error::{FluxgateError, Result};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidateOptions {
    pub offline: bool,
    pub strict_gitops: bool,
}

pub fn validate_config(config: &FluxgateConfig) -> Result<()> {
    validate_config_with_options(config, ValidateOptions::default())
}

pub fn validate_config_with_options(config: &FluxgateConfig, opts: ValidateOptions) -> Result<()> {
    let _ = opts.offline;

    if config.sites.is_empty() {
        return Err(FluxgateError::ConfigValidation(
            "Configuration contains no site definitions".to_string(),
        ));
    }

    let mut vault_aliases = HashSet::new();
    if let Some(vault) = &config.global.vault {
        validate_vault(vault, &mut vault_aliases, opts.strict_gitops)?;
    }

    for site in &config.sites {
        validate_site(site, &vault_aliases, opts.strict_gitops)?;
    }

    Ok(())
}

fn validate_vault<'a>(
    vault: &'a VaultConfig,
    vault_aliases: &mut HashSet<&'a str>,
    strict_gitops: bool,
) -> Result<()> {
    validate_vault_endpoint_ref("global.vault.addr", &vault.addr, strict_gitops)?;
    if let Some(ns) = &vault.namespace {
        validate_vault_endpoint_ref("global.vault.namespace", ns, strict_gitops)?;
    }
    if let Some(ca_cert) = &vault.ca_cert {
        if ca_cert.as_os_str().is_empty() {
            return Err(FluxgateError::ConfigValidation(
                "global.vault.ca_cert path cannot be empty".to_string(),
            ));
        }
        let ca_str = ca_cert.to_string_lossy();
        if strict_gitops && looks_like_inline_pem(&ca_str) {
            return Err(FluxgateError::ConfigValidation(
                "--strict-gitops rejected inline PEM material in global.vault.ca_cert".to_string(),
            ));
        }
        if !ca_cert.exists() {
            tracing::warn!(
                "Vault CA cert file does not exist at validate time: {}",
                ca_cert.display()
            );
        }
    }

    for sync in &vault.syncs {
        if sync.alias.trim().is_empty()
            || sync.alias.contains('.')
            || sync.alias.chars().any(char::is_whitespace)
        {
            return Err(FluxgateError::ConfigValidation(format!(
                "Invalid vault sync alias '{}'",
                sync.alias
            )));
        }
        if !vault_aliases.insert(sync.alias.as_str()) {
            return Err(FluxgateError::ConfigValidation(format!(
                "Duplicate vault sync alias '{}'",
                sync.alias
            )));
        }
        if sync.interval_secs < 1 {
            return Err(FluxgateError::ConfigValidation(format!(
                "Vault sync '{}' interval must be at least 1 second",
                sync.alias
            )));
        }
        if !is_valid_kv_v2_path(&sync.kv_path) {
            return Err(FluxgateError::ConfigValidation(format!(
                "Vault sync '{}' kv_path '{}' must match kv/data/<path>",
                sync.alias, sync.kv_path
            )));
        }
    }

    Ok(())
}

fn validate_vault_endpoint_ref(
    field_name: &str,
    sref: &SecretRef,
    strict_gitops: bool,
) -> Result<()> {
    match sref {
        SecretRef::Env(var) => {
            if var.trim().is_empty() {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Empty environment variable name in {}",
                    field_name
                )));
            }
        }
        SecretRef::Literal(val) => {
            if val.trim().is_empty() {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Empty value in {}",
                    field_name
                )));
            }
            if strict_gitops && looks_like_plaintext_secret(val) {
                return Err(FluxgateError::ConfigValidation(format!(
                    "--strict-gitops rejected suspected secret literal in {}",
                    field_name
                )));
            }
        }
        SecretRef::Vault { .. } => {
            return Err(FluxgateError::ConfigValidation(format!(
                "{} cannot reference a Vault secret (must be a URL literal or env(...))",
                field_name
            )));
        }
    }
    Ok(())
}

fn validate_secret_ref(
    field_name: &str,
    sref: &SecretRef,
    is_sensitive: bool,
    vault_aliases: &HashSet<&str>,
    strict_gitops: bool,
) -> Result<()> {
    match sref {
        SecretRef::Env(var) => {
            if var.trim().is_empty() {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Empty environment variable name in {}",
                    field_name
                )));
            }
        }
        SecretRef::Vault { alias, key } => {
            if alias.trim().is_empty() || key.trim().is_empty() {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Invalid Vault secret reference in {}: alias and key must be non-empty",
                    field_name
                )));
            }
            if !vault_aliases.contains(alias.as_str()) {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Unknown Vault sync alias '{}' referenced in {}",
                    alias, field_name
                )));
            }
        }
        SecretRef::Literal(val) => {
            if val.trim().is_empty() {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Empty literal value in {}",
                    field_name
                )));
            }
            if strict_gitops && (is_sensitive || looks_like_plaintext_secret(val)) {
                return Err(FluxgateError::ConfigValidation(format!(
                    "--strict-gitops rejected plaintext credential literal in {}; \
                     use {{vault.<alias>.<key>}} or env(...)",
                    field_name
                )));
            }
        }
    }
    Ok(())
}

fn validate_site(
    site: &SiteConfig,
    vault_aliases: &HashSet<&str>,
    strict_gitops: bool,
) -> Result<()> {
    if site.hosts.is_empty() {
        return Err(FluxgateError::ConfigValidation(
            "Site definition has empty host list".to_string(),
        ));
    }

    // Collect available named matchers
    let matcher_names: HashSet<&str> = site.matchers.iter().map(|m| m.name.as_str()).collect();

    // Validate TLS config if present
    if let Some(tls) = &site.tls {
        validate_tls(tls, vault_aliases, strict_gitops)?;
    }

    // Validate directives
    for directive in &site.directives {
        validate_directive(directive, &matcher_names, vault_aliases, strict_gitops)?;
    }

    Ok(())
}

fn validate_tls(tls: &TlsConfig, vault_aliases: &HashSet<&str>, strict_gitops: bool) -> Result<()> {
    match tls {
        TlsConfig::Static {
            cert_path,
            key_path,
        } => {
            if cert_path.as_os_str().is_empty() || key_path.as_os_str().is_empty() {
                return Err(FluxgateError::ConfigValidation(
                    "Static TLS cert_path and key_path cannot be empty".to_string(),
                ));
            }
            if strict_gitops
                && (looks_like_inline_pem(&cert_path.to_string_lossy())
                    || looks_like_inline_pem(&key_path.to_string_lossy()))
            {
                return Err(FluxgateError::ConfigValidation(
                    "--strict-gitops rejected inline PEM material in static tls directive"
                        .to_string(),
                ));
            }
            if !cert_path.exists() {
                tracing::warn!(
                    "TLS cert file does not exist at validate time: {}",
                    cert_path.display()
                );
            }
            if !key_path.exists() {
                tracing::warn!(
                    "TLS key file does not exist at validate time: {}",
                    key_path.display()
                );
            }
        }
        TlsConfig::Acme(acme) => {
            let valid_email = acme
                .email
                .trim()
                .split_once('@')
                .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty());
            if !valid_email {
                return Err(FluxgateError::ConfigValidation(format!(
                    "ACME TLS email '{}' must be non-empty and contain '@'",
                    acme.email
                )));
            }
            if acme.ca_url.trim().is_empty()
                || (!acme.ca_url.starts_with("https://") && !acme.ca_url.starts_with("http://"))
            {
                return Err(FluxgateError::ConfigValidation(format!(
                    "ACME TLS ca_url '{}' must be a valid http(s) URL",
                    acme.ca_url
                )));
            }
            if acme.renew_before_days < 1 {
                return Err(FluxgateError::ConfigValidation(
                    "ACME TLS renew_before must be at least 1 day".to_string(),
                ));
            }
            if acme.storage_dir.as_os_str().is_empty() {
                return Err(FluxgateError::ConfigValidation(
                    "ACME TLS storage_dir cannot be empty".to_string(),
                ));
            }
            if let Some(vault_path) = &acme.vault_storage_path {
                if !is_valid_kv_v2_path(vault_path) {
                    return Err(FluxgateError::ConfigValidation(format!(
                        "ACME TLS storage vault path '{}' must match kv/data/<path>",
                        vault_path
                    )));
                }
            }
            match &acme.dns_provider {
                DnsProviderConfig::Cloudflare { api_token } => {
                    validate_secret_ref(
                        "tls.dns.cloudflare.api_token",
                        api_token,
                        true,
                        vault_aliases,
                        strict_gitops,
                    )?;
                }
                DnsProviderConfig::AliDns {
                    access_key_id,
                    access_key_secret,
                } => {
                    validate_secret_ref(
                        "tls.dns.alidns.access_key_id",
                        access_key_id,
                        true,
                        vault_aliases,
                        strict_gitops,
                    )?;
                    validate_secret_ref(
                        "tls.dns.alidns.access_key_secret",
                        access_key_secret,
                        true,
                        vault_aliases,
                        strict_gitops,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_directive(
    directive: &Directive,
    matchers: &HashSet<&str>,
    vault_aliases: &HashSet<&str>,
    strict_gitops: bool,
) -> Result<()> {
    match directive {
        Directive::HandlePath { prefix, directives } => {
            if !prefix.starts_with('/') {
                return Err(FluxgateError::ConfigValidation(format!(
                    "handle_path prefix must start with '/', got '{}'",
                    prefix
                )));
            }
            for inner in directives {
                validate_directive(inner, matchers, vault_aliases, strict_gitops)?;
            }
        }
        Directive::Handle {
            matcher,
            directives,
        } => {
            if let Some(m) = matcher {
                if !matchers.contains(m.as_str()) {
                    return Err(FluxgateError::ConfigValidation(format!(
                        "Referenced matcher '{}' in handle block was not declared in site",
                        m
                    )));
                }
            }
            for inner in directives {
                validate_directive(inner, matchers, vault_aliases, strict_gitops)?;
            }
        }
        Directive::Rewrite { matcher, target } => {
            if let Some(m) = matcher {
                if !matchers.contains(m.as_str()) {
                    return Err(FluxgateError::ConfigValidation(format!(
                        "Referenced matcher '{}' in rewrite was not declared in site",
                        m
                    )));
                }
            }
            if !target.starts_with('/') {
                return Err(FluxgateError::ConfigValidation(format!(
                    "rewrite target must start with '/', got '{}'",
                    target
                )));
            }
        }
        Directive::UriQueryRemove { param } => {
            if param.is_empty() {
                return Err(FluxgateError::ConfigValidation(
                    "uri query parameter to remove cannot be empty".to_string(),
                ));
            }
        }
        Directive::ReverseProxy(rp) => {
            validate_upstream_target(&rp.upstream, strict_gitops)?;
            if let Some(rh) = &rp.rewrite_host {
                validate_rewrite_host(rh, strict_gitops)?;
            }
            validate_transport(&rp.transport)?;
        }
        Directive::HybridProxy(hp) => {
            validate_hybrid_proxy(hp, vault_aliases, strict_gitops)?;
        }
        Directive::Respond(resp) => {
            if strict_gitops && has_secret_markers(&resp.body) {
                return Err(FluxgateError::ConfigValidation(
                    "--strict-gitops rejected suspected secret material in respond directive"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_upstream_target(target: &UpstreamTarget, strict_gitops: bool) -> Result<()> {
    match target {
        UpstreamTarget::Uds(p) => {
            if p.as_os_str().is_empty() {
                return Err(FluxgateError::ConfigValidation(
                    "Unix socket upstream path cannot be empty".to_string(),
                ));
            }
        }
        UpstreamTarget::Tcp(addr) => {
            if addr.trim().is_empty() {
                return Err(FluxgateError::ConfigValidation(
                    "TCP upstream address cannot be empty".to_string(),
                ));
            }
        }
        UpstreamTarget::Https {
            addr,
            sni,
            rewrite_host,
        } => {
            if addr.trim().is_empty() {
                return Err(FluxgateError::ConfigValidation(
                    "HTTPS upstream address cannot be empty".to_string(),
                ));
            }
            if sni.trim().is_empty() || sni.chars().any(char::is_whitespace) {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Invalid HTTPS upstream SNI '{}'",
                    sni
                )));
            }
            if let Some(rh) = rewrite_host {
                validate_rewrite_host(rh, strict_gitops)?;
            }
        }
    }
    Ok(())
}

fn validate_rewrite_host(host: &str, strict_gitops: bool) -> Result<()> {
    if host.trim().is_empty() || host.chars().any(char::is_whitespace) {
        return Err(FluxgateError::ConfigValidation(format!(
            "Invalid rewrite_host '{}'",
            host
        )));
    }
    if strict_gitops && looks_like_plaintext_secret(host) {
        return Err(FluxgateError::ConfigValidation(
            "--strict-gitops rejected suspected secret literal in rewrite_host".to_string(),
        ));
    }
    Ok(())
}

fn validate_transport(transport: &TransportConfig) -> Result<()> {
    const MAX_H2_WINDOW_SIZE: u32 = (1u32 << 31) - 1;
    if transport.h2_stream_window_size == 0 || transport.h2_stream_window_size > MAX_H2_WINDOW_SIZE
    {
        return Err(FluxgateError::ConfigValidation(format!(
            "h2_stream_window_size must be between 1 and {} bytes",
            MAX_H2_WINDOW_SIZE
        )));
    }
    if transport.h2_connection_window_size == 0
        || transport.h2_connection_window_size > MAX_H2_WINDOW_SIZE
    {
        return Err(FluxgateError::ConfigValidation(format!(
            "h2_connection_window_size must be between 1 and {} bytes",
            MAX_H2_WINDOW_SIZE
        )));
    }
    if transport.max_h2_streams == 0 {
        return Err(FluxgateError::ConfigValidation(
            "max_h2_streams must be at least 1".to_string(),
        ));
    }
    if transport.h2_ping_interval_secs == 0 {
        return Err(FluxgateError::ConfigValidation(
            "h2_ping_interval must be at least 1s".to_string(),
        ));
    }
    if transport.read_timeout_secs == 0 {
        return Err(FluxgateError::ConfigValidation(
            "read_timeout must be at least 1s".to_string(),
        ));
    }
    if transport.idle_timeout_secs == 0 {
        return Err(FluxgateError::ConfigValidation(
            "idle_timeout must be at least 1s".to_string(),
        ));
    }
    Ok(())
}

fn validate_hybrid_proxy(
    hp: &HybridProxyConfig,
    vault_aliases: &HashSet<&str>,
    strict_gitops: bool,
) -> Result<()> {
    if hp.upstreams.is_empty() {
        return Err(FluxgateError::ConfigValidation(
            "hybrid_proxy requires at least one upstream block".to_string(),
        ));
    }
    if let Some(StickyKeySpec::Header(h)) = &hp.sticky_key {
        if h.trim().is_empty() || h.chars().any(char::is_whitespace) {
            return Err(FluxgateError::ConfigValidation(format!(
                "Invalid sticky_key header name '{}'",
                h
            )));
        }
    }

    let mut names = HashSet::new();
    let mut total_weight = 0u64;
    let mut has_fallback = false;

    for up in &hp.upstreams {
        if up.name.trim().is_empty() || up.name.chars().any(char::is_whitespace) {
            return Err(FluxgateError::ConfigValidation(format!(
                "Invalid hybrid upstream name '{}'",
                up.name
            )));
        }
        if !names.insert(up.name.as_str()) {
            return Err(FluxgateError::ConfigValidation(format!(
                "Duplicate hybrid upstream name '{}'",
                up.name
            )));
        }

        validate_upstream_target(&up.target, strict_gitops)?;
        if let Some(rh) = &up.rewrite_host {
            validate_rewrite_host(rh, strict_gitops)?;
        }
        validate_transport(&up.transport)?;

        if up.connect_timeout_ms == 0 {
            return Err(FluxgateError::ConfigValidation(format!(
                "hybrid upstream '{}' connect_timeout must be >= 1ms",
                up.name
            )));
        }
        if up.read_timeout_ms == 0 {
            return Err(FluxgateError::ConfigValidation(format!(
                "hybrid upstream '{}' read_timeout must be >= 1ms",
                up.name
            )));
        }
        if let Some(budget) = up.daily_budget {
            if budget == 0 {
                return Err(FluxgateError::ConfigValidation(format!(
                    "hybrid upstream '{}' daily_budget must be >= 1 when specified",
                    up.name
                )));
            }
        }
        for &code in &up.fallback_on_status {
            if !(100..=599).contains(&code) {
                return Err(FluxgateError::ConfigValidation(format!(
                    "hybrid upstream '{}' invalid HTTP status code {} in fallback_on_status",
                    up.name, code
                )));
            }
        }
        for (hk, _) in &up.fallback_on_headers {
            if hk.is_empty() || hk.chars().any(char::is_whitespace) {
                return Err(FluxgateError::ConfigValidation(format!(
                    "hybrid upstream '{}' invalid header name '{}' in fallback_on_header",
                    up.name, hk
                )));
            }
        }
        for (h_name, h_ref) in &up.headers_up {
            if h_name.trim().is_empty() || h_name.chars().any(char::is_whitespace) {
                return Err(FluxgateError::ConfigValidation(format!(
                    "hybrid upstream '{}' invalid header_up name '{}'",
                    up.name, h_name
                )));
            }
            let is_auth_header = h_name.eq_ignore_ascii_case("authorization")
                || h_name.to_ascii_lowercase().contains("token")
                || h_name.to_ascii_lowercase().contains("secret")
                || h_name.to_ascii_lowercase().contains("key");
            validate_secret_ref(
                &format!("hybrid_proxy.upstream.{}.header_up.{}", up.name, h_name),
                h_ref,
                is_auth_header,
                vault_aliases,
                strict_gitops,
            )?;
        }

        total_weight += u64::from(up.weight);
        if up.role == HybridUpstreamRole::Fallback {
            has_fallback = true;
        }
    }

    if total_weight == 0 && !has_fallback {
        return Err(FluxgateError::ConfigValidation(
            "hybrid_proxy must have positive total weight or a 'role fallback' upstream"
                .to_string(),
        ));
    }

    Ok(())
}

fn is_valid_kv_v2_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("kv/data/") else {
        return false;
    };
    if rest.is_empty() || rest.starts_with('/') || rest.ends_with('/') || rest.contains("//") {
        return false;
    }
    if rest.split('/').any(|seg| seg == "." || seg == "..") {
        return false;
    }
    rest.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

fn looks_like_inline_pem(val: &str) -> bool {
    val.contains("-----BEGIN ")
        || val.contains("PRIVATE KEY")
        || val.contains('\n')
        || val.contains('\r')
}

fn has_secret_markers(val: &str) -> bool {
    let trimmed = val.trim();
    val.contains("-----BEGIN ")
        || val.contains("PRIVATE KEY")
        || trimmed.starts_with("hvs.")
        || trimmed.starts_with("hvb.")
        || trimmed.starts_with("s.")
}

fn looks_like_plaintext_secret(val: &str) -> bool {
    looks_like_inline_pem(val) || has_secret_markers(val)
}
