use crate::config::ast::*;
use crate::error::{FluxgateError, Result};
use std::collections::HashSet;

pub fn validate_config(config: &FluxgateConfig) -> Result<()> {
    if config.sites.is_empty() {
        return Err(FluxgateError::ConfigValidation(
            "Configuration contains no site definitions".to_string(),
        ));
    }

    for site in &config.sites {
        validate_site(site)?;
    }

    Ok(())
}

fn validate_site(site: &SiteConfig) -> Result<()> {
    if site.hosts.is_empty() {
        return Err(FluxgateError::ConfigValidation(
            "Site definition has empty host list".to_string(),
        ));
    }

    // Collect available named matchers
    let matcher_names: HashSet<&str> = site.matchers.iter().map(|m| m.name.as_str()).collect();

    // Validate TLS paths if present
    if let Some(tls) = &site.tls {
        if !tls.cert_path.exists() {
            tracing::warn!(
                "TLS cert file does not exist at validate time: {}",
                tls.cert_path.display()
            );
        }
        if !tls.key_path.exists() {
            tracing::warn!(
                "TLS key file does not exist at validate time: {}",
                tls.key_path.display()
            );
        }
    }

    // Validate directives
    for directive in &site.directives {
        validate_directive(directive, &matcher_names)?;
    }

    Ok(())
}

fn validate_directive(directive: &Directive, matchers: &HashSet<&str>) -> Result<()> {
    match directive {
        Directive::HandlePath { prefix, directives } => {
            if !prefix.starts_with('/') {
                return Err(FluxgateError::ConfigValidation(format!(
                    "handle_path prefix must start with '/', got '{}'",
                    prefix
                )));
            }
            for inner in directives {
                validate_directive(inner, matchers)?;
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
                validate_directive(inner, matchers)?;
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
        Directive::ReverseProxy(rp) => match &rp.upstream {
            UpstreamTarget::Uds(p) => {
                if p.as_os_str().is_empty() {
                    return Err(FluxgateError::ConfigValidation(
                        "Unix socket upstream path cannot be empty".to_string(),
                    ));
                }
            }
            UpstreamTarget::Tcp(addr) => {
                if addr.is_empty() {
                    return Err(FluxgateError::ConfigValidation(
                        "TCP upstream address cannot be empty".to_string(),
                    ));
                }
            }
        },
        Directive::Respond(_) => {}
    }
    Ok(())
}
