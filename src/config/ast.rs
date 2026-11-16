use std::path::PathBuf;

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
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            grace_period_secs: 15,
            log_level: "INFO".to_string(),
            http_port: 80,
            https_port: 443,
            metrics_addr: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteConfig {
    pub hosts: Vec<String>,
    pub tls: Option<TlsConfig>,
    pub matchers: Vec<NamedMatcher>,
    pub directives: Vec<Directive>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
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
