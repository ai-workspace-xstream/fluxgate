use std::fmt;
use std::path::PathBuf;

pub const LETSENCRYPT_PROD_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETSENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const DEFAULT_ACME_STORAGE_DIR: &str = "/var/lib/fluxgate/certs";

#[derive(Debug, Clone, PartialEq)]
pub struct FluxgateConfig {
    pub global: GlobalConfig,
    pub sites: Vec<SiteConfig>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GlobalConfig {
    pub grace_period_secs: u64,
    pub log_level: String,
    pub http_port: u16,
    pub https_port: u16,
    pub metrics_addr: Option<String>,
    pub vault: Option<VaultConfig>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            grace_period_secs: 15,
            log_level: "INFO".to_string(),
            http_port: 80,
            https_port: 443,
            metrics_addr: None,
            vault: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum SecretRef {
    Literal(String),
    Vault { alias: String, key: String },
    Env(String),
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::Literal(_) => f.write_str("SecretRef::Literal([REDACTED])"),
            SecretRef::Vault { alias, key } => f
                .debug_struct("SecretRef::Vault")
                .field("alias", alias)
                .field("key", key)
                .finish(),
            SecretRef::Env(var) => f.debug_tuple("SecretRef::Env").field(var).finish(),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::Literal(_) => f.write_str("[REDACTED]"),
            SecretRef::Vault { alias, key } => write!(f, "{{vault.{}.{}}}", alias, key),
            SecretRef::Env(var) => write!(f, "env({})", var),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultAuthMode {
    Token,
    AppRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSyncSpec {
    pub alias: String,
    pub kv_path: String,
    pub interval_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConfig {
    pub addr: SecretRef,
    pub namespace: Option<SecretRef>,
    pub auth: VaultAuthMode,
    pub ca_cert: Option<PathBuf>,
    pub syncs: Vec<VaultSyncSpec>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteConfig {
    pub hosts: Vec<String>,
    pub tls: Option<TlsConfig>,
    pub matchers: Vec<NamedMatcher>,
    pub directives: Vec<Directive>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsConfig {
    Static {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    Acme(AcmeTlsConfig),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AcmeTlsConfig {
    pub email: String,
    pub ca_url: String,
    pub dns_provider: DnsProviderConfig,
    pub renew_before_days: u64,
    pub storage_dir: PathBuf,
    pub vault_storage_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsProviderConfig {
    Cloudflare {
        api_token: SecretRef,
    },
    AliDns {
        access_key_id: SecretRef,
        access_key_secret: SecretRef,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct NamedMatcher {
    pub name: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Directive {
    HandlePath {
        prefix: String,
        directives: Vec<Directive>,
    },
    Handle {
        matcher: Option<String>,
        directives: Vec<Directive>,
    },
    Rewrite {
        matcher: Option<String>,
        target: String,
    },
    UriQueryRemove {
        param: String,
    },
    ReverseProxy(ReverseProxyConfig),
    Respond(RespondConfig),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReverseProxyConfig {
    pub upstream: UpstreamTarget,
    pub flush_interval: i32,
    pub transport: TransportConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpstreamTarget {
    Tcp(String),
    Uds(PathBuf),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransportConfig {
    pub versions: Vec<String>, // e.g. ["h2c", "2"] or ["1.1"]
    pub h2c: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            versions: vec!["1.1".to_string()],
            h2c: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RespondConfig {
    pub body: String,
    pub status: u16,
}
