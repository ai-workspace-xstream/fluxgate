use crate::config::{
    HybridMode, HybridProxyConfig, HybridUpstreamConfig, HybridUpstreamRole, SecretRef,
    StickyKeySpec, TransportConfig, UpstreamTarget,
};
use std::sync::atomic::{AtomicU64, Ordering};

const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV1A_64_PRIME: u64 = 0x00000100000001b3;

#[derive(Debug, Clone)]
pub struct CompiledHybridUpstream {
    pub name: String,
    pub target: UpstreamTarget,
    pub weight: u32,
    pub role: HybridUpstreamRole,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub daily_budget: Option<u64>,
    pub fallback_on_status: Vec<u16>,
    pub fallback_on_headers: Vec<(String, String)>,
    pub headers_up: Vec<(String, SecretRef)>,
    pub flush_immediately: bool,
    pub transport: TransportConfig,
    pub rewrite_host: Option<String>,
}

impl CompiledHybridUpstream {
    pub fn from_config(cfg: &HybridUpstreamConfig) -> Self {
        let effective_rewrite_host = cfg.rewrite_host.clone().or_else(|| match &cfg.target {
            UpstreamTarget::Https { rewrite_host, .. } => rewrite_host.clone(),
            _ => None,
        });
        Self {
            name: cfg.name.clone(),
            target: cfg.target.clone(),
            weight: cfg.weight,
            role: cfg.role,
            connect_timeout_ms: cfg.connect_timeout_ms,
            read_timeout_ms: cfg.read_timeout_ms,
            daily_budget: cfg.daily_budget,
            fallback_on_status: cfg.fallback_on_status.clone(),
            fallback_on_headers: cfg.fallback_on_headers.clone(),
            headers_up: cfg.headers_up.clone(),
            flush_immediately: cfg.flush_interval < 0,
            transport: cfg.transport.clone(),
            rewrite_host: effective_rewrite_host,
        }
    }
}

#[derive(Debug)]
pub struct CompiledHybridPool {
    pub mode: HybridMode,
    pub sticky_key: Option<StickyKeySpec>,
    pub retry_safe_methods: Vec<String>,
    pub upstreams: Vec<CompiledHybridUpstream>,
    rr_counter: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct HybridSelection<'a> {
    pub primary_index: usize,
    pub primary: &'a CompiledHybridUpstream,
    pub fallback: Option<&'a CompiledHybridUpstream>,
}

impl CompiledHybridPool {
    pub fn compile(cfg: &HybridProxyConfig) -> Self {
        let retry_safe_methods = if cfg.retry_safe_methods.is_empty() {
            vec!["GET".to_string(), "HEAD".to_string(), "OPTIONS".to_string()]
        } else {
            cfg.retry_safe_methods
                .iter()
                .map(|m| m.to_ascii_uppercase())
                .collect()
        };

        Self {
            mode: cfg.mode,
            sticky_key: cfg.sticky_key.clone(),
            retry_safe_methods,
            upstreams: cfg
                .upstreams
                .iter()
                .map(CompiledHybridUpstream::from_config)
                .collect(),
            rr_counter: AtomicU64::new(0),
        }
    }

    pub fn is_retry_safe_method(&self, method: &str) -> bool {
        self.retry_safe_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    }

    /// Select a primary upstream by GitOps-configured proportional weight, along with an
    /// optional `Fallback` upstream candidate for retry-safe connection failover.
    pub fn select(&self, sticky_value: Option<&str>) -> Option<HybridSelection<'_>> {
        if self.upstreams.is_empty() {
            return None;
        }

        let total_weight: u64 = self.upstreams.iter().map(|u| u64::from(u.weight)).sum();

        let primary_index = if total_weight > 0 {
            let slot = match sticky_value {
                Some(v) if !v.is_empty() => fnv1a_64(v.as_bytes()) % total_weight,
                _ => self.rr_counter.fetch_add(1, Ordering::Relaxed) % total_weight,
            };

            let mut acc = 0u64;
            let mut chosen = 0usize;
            for (idx, up) in self.upstreams.iter().enumerate() {
                if up.weight == 0 {
                    continue;
                }
                acc += u64::from(up.weight);
                if slot < acc {
                    chosen = idx;
                    break;
                }
            }
            chosen
        } else {
            self.upstreams
                .iter()
                .position(|u| u.role == HybridUpstreamRole::Fallback)
                .unwrap_or(0)
        };

        let fallback = self
            .upstreams
            .iter()
            .enumerate()
            .find(|(idx, u)| *idx != primary_index && u.role == HybridUpstreamRole::Fallback)
            .map(|(_, u)| u);

        Some(HybridSelection {
            primary_index,
            primary: &self.upstreams[primary_index],
            fallback,
        })
    }
}

#[inline]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = FNV1A_64_OFFSET_BASIS;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV1A_64_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pool(cf_weight: u32, go_weight: u32) -> CompiledHybridPool {
        let cfg = HybridProxyConfig {
            mode: HybridMode::WeightedFailover,
            sticky_key: Some(StickyKeySpec::Header("Authorization".to_string())),
            retry_safe_methods: Vec::new(),
            upstreams: vec![
                HybridUpstreamConfig {
                    name: "cf_worker".to_string(),
                    target: UpstreamTarget::Https {
                        addr: "edge.example.workers.dev:443".to_string(),
                        sni: "edge.example.workers.dev".to_string(),
                        rewrite_host: Some("edge.example.workers.dev".to_string()),
                    },
                    weight: cf_weight,
                    role: HybridUpstreamRole::Primary,
                    connect_timeout_ms: 800,
                    read_timeout_ms: 2000,
                    daily_budget: Some(85_000),
                    fallback_on_status: vec![429, 501, 502, 503, 504],
                    fallback_on_headers: vec![(
                        "X-XConnect-Fallback".to_string(),
                        "origin-go".to_string(),
                    )],
                    headers_up: Vec::new(),
                    flush_interval: -1,
                    transport: TransportConfig::default(),
                    rewrite_host: None,
                },
                HybridUpstreamConfig {
                    name: "go_origin".to_string(),
                    target: UpstreamTarget::Tcp("127.0.0.1:8080".to_string()),
                    weight: go_weight,
                    role: HybridUpstreamRole::Fallback,
                    connect_timeout_ms: 2000,
                    read_timeout_ms: 15000,
                    daily_budget: None,
                    fallback_on_status: Vec::new(),
                    fallback_on_headers: Vec::new(),
                    headers_up: Vec::new(),
                    flush_interval: -1,
                    transport: TransportConfig::default(),
                    rewrite_host: None,
                },
            ],
        };
        CompiledHybridPool::compile(&cfg)
    }

    #[test]
    fn test_weighted_round_robin_exact_ratio() {
        let pool = sample_pool(80, 20);
        let mut cf_hits = 0usize;
        let mut go_hits = 0usize;

        for _ in 0..100 {
            let sel = pool.select(None).unwrap();
            match sel.primary.name.as_str() {
                "cf_worker" => {
                    cf_hits += 1;
                    assert_eq!(sel.fallback.unwrap().name, "go_origin");
                }
                "go_origin" => {
                    go_hits += 1;
                    assert!(sel.fallback.is_none());
                }
                other => panic!("unexpected upstream {}", other),
            }
        }

        assert_eq!(cf_hits, 80);
        assert_eq!(go_hits, 20);
    }

    #[test]
    fn test_sticky_key_deterministic_bucketing() {
        let pool = sample_pool(80, 20);
        let first = pool
            .select(Some("Bearer tok-user-42"))
            .unwrap()
            .primary
            .name
            .clone();
        for _ in 0..20 {
            let again = pool
                .select(Some("Bearer tok-user-42"))
                .unwrap()
                .primary
                .name
                .clone();
            assert_eq!(first, again);
        }

        let mut cf_count = 0usize;
        for i in 0..1000 {
            let token = format!("Bearer user-session-{}", i);
            if pool.select(Some(&token)).unwrap().primary.name == "cf_worker" {
                cf_count += 1;
            }
        }
        assert!(
            (740..=860).contains(&cf_count),
            "expected ~80% cf_worker distribution, got {}",
            cf_count
        );
    }

    #[test]
    fn test_zero_primary_weight_routes_all_to_fallback() {
        let pool = sample_pool(0, 0);
        for _ in 0..10 {
            let sel = pool.select(Some("Bearer any")).unwrap();
            assert_eq!(sel.primary.name, "go_origin");
        }
    }
}
