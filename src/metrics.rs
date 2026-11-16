use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
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

pub struct MetricsRegistry {
    start_time: Instant,
    active_connections: AtomicI64,
    requests_by_status: Mutex<HashMap<(String, String, u16), u64>>,
    latency_by_route: Mutex<HashMap<(String, String), RouteSeries>>,
    upstream_errors: Mutex<HashMap<String, u64>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            active_connections: AtomicI64::new(0),
            requests_by_status: Mutex::new(HashMap::new()),
            latency_by_route: Mutex::new(HashMap::new()),
            upstream_errors: Mutex::new(HashMap::new()),
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
        let _ = writeln!(out, "# TYPE fluxgate_http_request_duration_seconds histogram");
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
        assert!(text.contains(
            "fluxgate_upstream_errors_total{upstream=\"/dev/shm/xray.sock\"} 1"
        ));
    }
}
