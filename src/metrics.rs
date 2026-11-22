use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Default)]
struct RouteSeries {
    count: u64,
    sum_secs: f64,
    buckets: [u64; 12],
}

#[derive(Default, Clone, Copy)]
struct VaultMetricState {
    success: bool,
    last_sync_unix: i64,
    version: u64,
}

pub struct MetricsRegistry {
    start_time: Instant,
    active_connections: AtomicI64,
    requests_by_status: Mutex<HashMap<(String, String, u16), u64>>,
    latency_by_route: Mutex<HashMap<(String, String), RouteSeries>>,
    upstream_errors: Mutex<HashMap<String, u64>>,
    vault_sync: Mutex<HashMap<String, VaultMetricState>>,
    config_reload_success: AtomicI64,
    config_last_reload_unix: AtomicI64,
    config_hash: Mutex<String>,
    tls_cert_expiry: Mutex<HashMap<String, i64>>,
    acme_renews: Mutex<HashMap<(String, String, String), u64>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self {
            start_time: Instant::now(),
            active_connections: AtomicI64::new(0),
            requests_by_status: Mutex::new(HashMap::new()),
            latency_by_route: Mutex::new(HashMap::new()),
            upstream_errors: Mutex::new(HashMap::new()),
            vault_sync: Mutex::new(HashMap::new()),
            config_reload_success: AtomicI64::new(1),
            config_last_reload_unix: AtomicI64::new(now_unix),
            config_hash: Mutex::new(String::new()),
            tls_cert_expiry: Mutex::new(HashMap::new()),
            acme_renews: Mutex::new(HashMap::new()),
        }
    }

    pub fn inc_active(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_request(&self, host: &str, route: &str, status: u16, duration_secs: f64) {
        let h = if host.is_empty() { "unknown" } else { host };
        let host_clean = h.split(':').next().unwrap_or(h).to_ascii_lowercase();

        if let Ok(mut map) = self.requests_by_status.lock() {
            *map.entry((host_clean.clone(), route.to_string(), status))
                .or_insert(0) += 1;
        }

        if let Ok(mut lat) = self.latency_by_route.lock() {
            let entry = lat.entry((host_clean, route.to_string())).or_default();
            entry.count += 1;
            entry.sum_secs += duration_secs;
            for (idx, bound) in DURATION_BUCKETS.iter().enumerate() {
                if duration_secs <= *bound {
                    entry.buckets[idx] += 1;
                }
            }
        }
    }

    pub fn record_upstream_error(&self, upstream: &str) {
        if let Ok(mut map) = self.upstream_errors.lock() {
            *map.entry(upstream.to_string()).or_insert(0) += 1;
        }
    }

    pub fn record_vault_sync(&self, alias: &str, success: bool, version: u64, timestamp_secs: i64) {
        if let Ok(mut map) = self.vault_sync.lock() {
            let entry = map.entry(alias.to_string()).or_default();
            entry.success = success;
            if success {
                entry.last_sync_unix = timestamp_secs;
                entry.version = version;
            }
        }
    }

    pub fn record_config_reload(&self, success: bool, config_hash: &str, timestamp_secs: i64) {
        self.config_reload_success
            .store(if success { 1 } else { 0 }, Ordering::Relaxed);
        if success {
            self.config_last_reload_unix
                .store(timestamp_secs, Ordering::Relaxed);
            if let Ok(mut h) = self.config_hash.lock() {
                *h = config_hash.to_string();
            }
        }
    }

    pub fn record_tls_cert_expiry(&self, domains: &str, not_after_unix: i64) {
        if let Ok(mut map) = self.tls_cert_expiry.lock() {
            map.insert(domains.to_string(), not_after_unix);
        }
    }

    pub fn record_acme_renew(&self, domains: &str, provider: &str, result: &str) {
        if let Ok(mut map) = self.acme_renews.lock() {
            *map.entry((
                domains.to_string(),
                provider.to_string(),
                result.to_string(),
            ))
            .or_insert(0) += 1;
        }
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        let _ = writeln!(out, "# HELP fluxgate_up Whether Fluxgate proxy is up.");
        let _ = writeln!(out, "# TYPE fluxgate_up gauge");
        let _ = writeln!(out, "fluxgate_up 1");

        let uptime = self.start_time.elapsed().as_secs_f64();
        let _ = writeln!(
            out,
            "# HELP fluxgate_process_uptime_seconds Fluxgate uptime in seconds."
        );
        let _ = writeln!(out, "# TYPE fluxgate_process_uptime_seconds gauge");
        let _ = writeln!(out, "fluxgate_process_uptime_seconds {:.3}", uptime);

        if let Some(rss) = read_resident_memory_bytes() {
            let _ = writeln!(
                out,
                "# HELP fluxgate_process_resident_memory_bytes Resident memory size in bytes."
            );
            let _ = writeln!(out, "# TYPE fluxgate_process_resident_memory_bytes gauge");
            let _ = writeln!(out, "fluxgate_process_resident_memory_bytes {}", rss);
        }

        let active = self.active_connections.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "# HELP fluxgate_active_connections Current number of active requests."
        );
        let _ = writeln!(out, "# TYPE fluxgate_active_connections gauge");
        let _ = writeln!(out, "fluxgate_active_connections {}", active.max(0));

        let _ = writeln!(
            out,
            "# HELP fluxgate_http_requests_total Total HTTP requests handled by Fluxgate."
        );
        let _ = writeln!(out, "# TYPE fluxgate_http_requests_total counter");
        if let Ok(map) = self.requests_by_status.lock() {
            for ((host, route, status), count) in map.iter() {
                let _ = writeln!(
                    out,
                    "fluxgate_http_requests_total{{host=\"{}\",route=\"{}\",status=\"{}\"}} {}",
                    escape_label(host),
                    escape_label(route),
                    status,
                    count
                );
            }
        }

        let _ = writeln!(
            out,
            "# HELP fluxgate_http_request_duration_seconds HTTP request duration in seconds."
        );
        let _ = writeln!(
            out,
            "# TYPE fluxgate_http_request_duration_seconds histogram"
        );
        if let Ok(lat) = self.latency_by_route.lock() {
            for ((host, route), series) in lat.iter() {
                let h = escape_label(host);
                let r = escape_label(route);
                for (idx, bound) in DURATION_BUCKETS.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "fluxgate_http_request_duration_seconds_bucket{{host=\"{}\",route=\"{}\",le=\"{}\"}} {}",
                        h, r, bound, series.buckets[idx]
                    );
                }
                let _ = writeln!(
                    out,
                    "fluxgate_http_request_duration_seconds_bucket{{host=\"{}\",route=\"{}\",le=\"+Inf\"}} {}",
                    h, r, series.count
                );
                let _ = writeln!(
                    out,
                    "fluxgate_http_request_duration_seconds_sum{{host=\"{}\",route=\"{}\"}} {:.6}",
                    h, r, series.sum_secs
                );
                let _ = writeln!(
                    out,
                    "fluxgate_http_request_duration_seconds_count{{host=\"{}\",route=\"{}\"}} {}",
                    h, r, series.count
                );
            }
        }

        let _ = writeln!(
            out,
            "# HELP fluxgate_upstream_errors_total Total upstream connection/proxy errors."
        );
        let _ = writeln!(out, "# TYPE fluxgate_upstream_errors_total counter");
        if let Ok(errs) = self.upstream_errors.lock() {
            for (upstream, count) in errs.iter() {
                let _ = writeln!(
                    out,
                    "fluxgate_upstream_errors_total{{upstream=\"{}\"}} {}",
                    escape_label(upstream),
                    count
                );
            }
        }

        let _ = writeln!(
            out,
            "# HELP fluxgate_vault_sync_success Whether the last Vault KV sync succeeded (1=ok, 0=err)."
        );
        let _ = writeln!(out, "# TYPE fluxgate_vault_sync_success gauge");
        let _ = writeln!(
            out,
            "# HELP fluxgate_vault_last_sync_timestamp_seconds Unix timestamp of last successful Vault KV sync."
        );
        let _ = writeln!(
            out,
            "# TYPE fluxgate_vault_last_sync_timestamp_seconds gauge"
        );
        let _ = writeln!(
            out,
            "# HELP fluxgate_vault_sync_version Current KV v2 metadata version cached for Vault alias."
        );
        let _ = writeln!(out, "# TYPE fluxgate_vault_sync_version gauge");
        if let Ok(vaults) = self.vault_sync.lock() {
            for (alias, st) in vaults.iter() {
                let a = escape_label(alias);
                let _ = writeln!(
                    out,
                    "fluxgate_vault_sync_success{{alias=\"{}\"}} {}",
                    a,
                    if st.success { 1 } else { 0 }
                );
                let _ = writeln!(
                    out,
                    "fluxgate_vault_last_sync_timestamp_seconds{{alias=\"{}\"}} {}",
                    a, st.last_sync_unix
                );
                let _ = writeln!(
                    out,
                    "fluxgate_vault_sync_version{{alias=\"{}\"}} {}",
                    a, st.version
                );
            }
        }

        let _ = writeln!(
            out,
            "# HELP fluxgate_config_reload_success Whether the last configuration reload succeeded."
        );
        let _ = writeln!(out, "# TYPE fluxgate_config_reload_success gauge");
        let _ = writeln!(
            out,
            "fluxgate_config_reload_success {}",
            self.config_reload_success.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP fluxgate_config_last_reload_timestamp_seconds Unix timestamp of last successful config reload."
        );
        let _ = writeln!(
            out,
            "# TYPE fluxgate_config_last_reload_timestamp_seconds gauge"
        );
        let _ = writeln!(
            out,
            "fluxgate_config_last_reload_timestamp_seconds {}",
            self.config_last_reload_unix.load(Ordering::Relaxed)
        );

        if let Ok(hash) = self.config_hash.lock() {
            if !hash.is_empty() {
                let _ = writeln!(
                    out,
                    "# HELP fluxgate_config_info Active configuration SHA-256 fingerprint."
                );
                let _ = writeln!(out, "# TYPE fluxgate_config_info gauge");
                let _ = writeln!(
                    out,
                    "fluxgate_config_info{{sha256=\"{}\"}} 1",
                    escape_label(&hash)
                );
            }
        }

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let _ = writeln!(
            out,
            "# HELP fluxgate_tls_cert_expiry_timestamp_seconds Certificate NotAfter Unix timestamp."
        );
        let _ = writeln!(
            out,
            "# TYPE fluxgate_tls_cert_expiry_timestamp_seconds gauge"
        );
        let _ = writeln!(
            out,
            "# HELP fluxgate_tls_cert_days_remaining Remaining certificate validity in days."
        );
        let _ = writeln!(out, "# TYPE fluxgate_tls_cert_days_remaining gauge");
        if let Ok(certs) = self.tls_cert_expiry.lock() {
            for (domains, not_after) in certs.iter() {
                let d = escape_label(domains);
                let days = (*not_after - now_unix) as f64 / 86400.0;
                let _ = writeln!(
                    out,
                    "fluxgate_tls_cert_expiry_timestamp_seconds{{domains=\"{}\"}} {}",
                    d, not_after
                );
                let _ = writeln!(
                    out,
                    "fluxgate_tls_cert_days_remaining{{domains=\"{}\"}} {:.2}",
                    d, days
                );
            }
        }

        let _ = writeln!(
            out,
            "# HELP fluxgate_acme_renew_total Total ACME renewal attempts by result."
        );
        let _ = writeln!(out, "# TYPE fluxgate_acme_renew_total counter");
        if let Ok(renews) = self.acme_renews.lock() {
            for ((domains, provider, result), count) in renews.iter() {
                let _ = writeln!(
                    out,
                    "fluxgate_acme_renew_total{{domains=\"{}\",provider=\"{}\",result=\"{}\"}} {}",
                    escape_label(domains),
                    escape_label(provider),
                    escape_label(result),
                    count
                );
            }
        }

        out
    }
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn read_resident_memory_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

pub struct MetricsService {
    pub addr: String,
    pub registry: Arc<MetricsRegistry>,
}

#[async_trait]
impl BackgroundService for MetricsService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let listener = match TcpListener::bind(&self.addr).await {
            Ok(l) => {
                tracing::info!("Metrics endpoint listening on http://{}/metrics", self.addr);
                l
            }
            Err(e) => {
                tracing::error!("Failed to bind metrics listener {}: {}", self.addr, e);
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("Shutting down metrics listener");
                    break;
                }
                accept_res = listener.accept() => {
                    if let Ok((mut stream, _)) = accept_res {
                        let reg = self.registry.clone();
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            let n = stream.read(&mut buf).await.unwrap_or(0);
                            let req = String::from_utf8_lossy(&buf[..n]);
                            let first_line = req.lines().next().unwrap_or("");
                            let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                            let (status_line, content_type, body) = if path == "/healthz" {
                                (
                                    "HTTP/1.1 200 OK",
                                    "text/plain; charset=utf-8",
                                    "ok\n".to_string(),
                                )
                            } else {
                                (
                                    "HTTP/1.1 200 OK",
                                    "text/plain; version=0.0.4; charset=utf-8",
                                    reg.render_prometheus(),
                                )
                            };

                            let header = format!(
                                "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                status_line,
                                content_type,
                                body.len()
                            );
                            let _ = stream.write_all(header.as_bytes()).await;
                            let _ = stream.write_all(body.as_bytes()).await;
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_rendering() {
        let reg = MetricsRegistry::new();
        reg.inc_active();
        reg.record_request("jp-xconnect-01.svc.plus:443", "xhttp", 200, 0.012);
        reg.record_upstream_error("/dev/shm/xray.sock");
        reg.dec_active();

        let text = reg.render_prometheus();
        assert!(text.contains("fluxgate_up 1"));
        assert!(text.contains("fluxgate_active_connections 0"));
        assert!(text.contains(
            "fluxgate_http_requests_total{host=\"jp-xconnect-01.svc.plus\",route=\"xhttp\",status=\"200\"} 1"
        ));
        assert!(text.contains("fluxgate_upstream_errors_total{upstream=\"/dev/shm/xray.sock\"} 1"));
    }
}
