use crate::config::TlsConfig;
use crate::error::{FluxgateError, Result};
use pingora::listeners::tls::TlsSettings;

pub fn build_tls_settings(tls: &TlsConfig) -> Result<TlsSettings> {
    let cert = tls.cert_path.to_string_lossy();
    let key = tls.key_path.to_string_lossy();
    let mut settings = TlsSettings::intermediate(&cert, &key).map_err(|e| {
        FluxgateError::TlsError(format!(
            "Failed to load TLS cert ({}) / key ({}): {}",
            cert, key, e
        ))
    })?;
    settings.enable_h2();
    Ok(settings)
}
