use crate::config::{
    SecretRef, StickyKeySpec, TransportConfig, UpstreamTarget, DEFAULT_CONNECT_TIMEOUT_MS,
    DEFAULT_READ_TIMEOUT_SECS,
};
use crate::hybrid::CompiledHybridUpstream;
use crate::metrics::MetricsRegistry;
use crate::proxy::route::{uds_path_string, CompiledRouter, RouteResolution};
use crate::vault::SecretStore;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::protocols::{TcpKeepalive, ALPN};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn default_tcp_keepalive() -> TcpKeepalive {
    TcpKeepalive {
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(15),
        count: 4,
        #[cfg(target_os = "linux")]
        user_timeout: Duration::from_secs(60),
    }
}

async fn resolve_socket_addr(addr: &str) -> pingora::Result<SocketAddr> {
    if let Ok(sock) = addr.parse::<SocketAddr>() {
        return Ok(sock);
    }
    let mut iter = tokio::net::lookup_host(addr).await.map_err(|e| {
        Error::explain(
            ErrorType::ConnectError,
            format!("Failed to resolve upstream '{}': {}", addr, e),
        )
    })?;
    iter.next().ok_or_else(|| {
        Error::explain(
            ErrorType::ConnectError,
            format!("No socket addresses resolved for upstream '{}'", addr),
        )
    })
}

#[derive(Debug, Clone)]
pub struct FallbackCandidate {
    pub name: String,
    pub upstream: UpstreamTarget,
    pub transport: TransportConfig,
    pub rewrite_host: Option<String>,
    pub headers_up: Vec<(String, SecretRef)>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub flush_immediately: bool,
}

impl FallbackCandidate {
    fn from_hybrid(up: &CompiledHybridUpstream) -> Self {
        Self {
            name: up.name.clone(),
            upstream: up.target.clone(),
            transport: up.transport.clone(),
            rewrite_host: up.rewrite_host.clone(),
            headers_up: up.headers_up.clone(),
            connect_timeout: Duration::from_millis(up.connect_timeout_ms),
            read_timeout: Duration::from_millis(up.read_timeout_ms),
            flush_immediately: up.flush_immediately,
        }
    }
}

pub struct FluxgateProxy {
    pub router: Arc<ArcSwap<CompiledRouter>>,
    pub https_enabled: bool,
    pub metrics: Option<Arc<MetricsRegistry>>,
    pub secret_store: Option<Arc<SecretStore>>,
}

pub struct FluxgateCtx {
    pub upstream: Option<UpstreamTarget>,
    pub transport: TransportConfig,
    pub rewrite_host: Option<String>,
    pub headers_up: Vec<(String, SecretRef)>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub flush_immediately: bool,
    pub host: String,
    pub route_label: &'static str,
    pub hybrid_upstream_name: Option<String>,
    pub hybrid_used_fallback: bool,
    pub fallback_candidate: Option<FallbackCandidate>,
    pub start_time: Instant,
    pub active_counted: bool,
}

impl Default for FluxgateCtx {
    fn default() -> Self {
        Self {
            upstream: None,
            transport: TransportConfig::default(),
            rewrite_host: None,
            headers_up: Vec::new(),
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            read_timeout: Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS),
            flush_immediately: false,
            host: String::new(),
            route_label: "unknown",
            hybrid_upstream_name: None,
            hybrid_used_fallback: false,
            fallback_candidate: None,
            start_time: Instant::now(),
            active_counted: false,
        }
    }
}

impl FluxgateProxy {
    pub fn new(
        router: Arc<ArcSwap<CompiledRouter>>,
        https_enabled: bool,
        metrics: Option<Arc<MetricsRegistry>>,
    ) -> Self {
        Self {
            router,
            https_enabled,
            metrics,
            secret_store: None,
        }
    }

    pub fn with_secret_store(mut self, store: Arc<SecretStore>) -> Self {
        self.secret_store = Some(store);
        self
    }

    fn extract_host(session: &Session) -> String {
        if let Some(h) = session.req_header().headers.get("host") {
            if let Ok(s) = h.to_str() {
                return s.to_string();
            }
        }
        if let Some(auth) = session.req_header().uri.authority() {
            return auth.as_str().to_string();
        }
        String::new()
    }

    fn extract_sticky_value(session: &Session, spec: &StickyKeySpec) -> Option<String> {
        match spec {
            StickyKeySpec::Header(name) => session
                .req_header()
                .headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            StickyKeySpec::ClientIp => session
                .client_addr()
                .and_then(|a| a.as_inet())
                .map(|inet| inet.ip().to_string()),
            StickyKeySpec::Path => Some(session.req_header().uri.path().to_string()),
        }
    }

    async fn send_static_response(
        session: &mut Session,
        status: u16,
        body: &str,
    ) -> pingora::Result<bool> {
        let mut resp = ResponseHeader::build(status, Some(2))?;
        let bytes = Bytes::copy_from_slice(body.as_bytes());
        resp.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        resp.insert_header("Content-Length", bytes.len().to_string())?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(bytes), true).await?;
        Ok(true)
    }
}

#[async_trait]
impl ProxyHttp for FluxgateProxy {
    type CTX = FluxgateCtx;

    fn new_ctx(&self) -> Self::CTX {
        FluxgateCtx::default()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        ctx.start_time = Instant::now();
        if let Some(m) = &self.metrics {
            m.inc_active();
            ctx.active_counted = true;
        }

        let host = Self::extract_host(session);
        ctx.host = host.clone();
        let is_tls = session
            .digest()
            .is_some_and(|digest| digest.ssl_digest.is_some());

        // Redirect plain HTTP to HTTPS when TLS is enabled (matching Caddy auto_https)
        if self.https_enabled && !is_tls && !host.is_empty() {
            ctx.route_label = "redirect";
            let host_only = host.split(':').next().unwrap_or(&host);
            let path_and_query = session
                .req_header()
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let location = format!("https://{}{}", host_only, path_and_query);
            let mut resp = ResponseHeader::build(308, Some(2))?;
            resp.insert_header("Location", location)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        let original_uri = session.req_header().uri.clone();
        let router = self.router.load();
        match router.resolve(&host, &original_uri) {
            RouteResolution::Respond { status, body } => {
                ctx.route_label = "static";
                Self::send_static_response(session, status, &body).await
            }
            RouteResolution::NotFound => {
                ctx.route_label = "not_found";
                Self::send_static_response(session, 404, "Not Found").await
            }
            RouteResolution::Proxy {
                upstream,
                flush_immediately,
                transport,
                rewrite_host,
                new_uri,
            } => {
                ctx.route_label = match &upstream {
                    UpstreamTarget::Uds(_) => "uds",
                    UpstreamTarget::Tcp(_) => "tcp",
                    UpstreamTarget::Https { .. } => "https",
                };
                if let Some(uri) = new_uri {
                    session.req_header_mut().set_uri(uri);
                }
                let rw_timeout = Duration::from_secs(transport.read_timeout_secs);
                session.set_read_timeout(Some(rw_timeout));
                session.set_write_timeout(Some(rw_timeout));
                session.set_keepalive(Some(transport.idle_timeout_secs));
                if flush_immediately {
                    session.upstream_compression.adjust_level(0);
                }
                ctx.upstream = Some(upstream);
                ctx.transport = transport;
                ctx.rewrite_host = rewrite_host;
                ctx.connect_timeout = Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS);
                ctx.read_timeout = rw_timeout;
                ctx.flush_immediately = flush_immediately;
                Ok(false)
            }
            RouteResolution::HybridProxy { pool, new_uri } => {
                ctx.route_label = "hybrid";
                if let Some(uri) = new_uri {
                    session.req_header_mut().set_uri(uri);
                }
                let sticky_val = pool
                    .sticky_key
                    .as_ref()
                    .and_then(|spec| Self::extract_sticky_value(session, spec));
                let Some(sel) = pool.select(sticky_val.as_deref()) else {
                    return Self::send_static_response(session, 503, "Service Unavailable").await;
                };

                let chosen = sel.primary;
                let rw_timeout = Duration::from_millis(chosen.read_timeout_ms);
                session.set_read_timeout(Some(rw_timeout));
                session.set_write_timeout(Some(rw_timeout));
                session.set_keepalive(Some(chosen.transport.idle_timeout_secs));
                if chosen.flush_immediately {
                    session.upstream_compression.adjust_level(0);
                }

                let method = session.req_header().method.as_str();
                if pool.is_retry_safe_method(method) {
                    ctx.fallback_candidate = sel.fallback.map(FallbackCandidate::from_hybrid);
                }

                ctx.upstream = Some(chosen.target.clone());
                ctx.transport = chosen.transport.clone();
                ctx.rewrite_host = chosen.rewrite_host.clone();
                ctx.headers_up = chosen.headers_up.clone();
                ctx.connect_timeout = Duration::from_millis(chosen.connect_timeout_ms);
                ctx.read_timeout = rw_timeout;
                ctx.flush_immediately = chosen.flush_immediately;
                ctx.hybrid_upstream_name = Some(chosen.name.clone());
                Ok(false)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let upstream = ctx.upstream.as_ref().ok_or_else(|| {
            Error::explain(
                ErrorType::InternalError,
                "Missing upstream target in context",
            )
        })?;

        let mut peer = match upstream {
            UpstreamTarget::Uds(path) => {
                let path_str = uds_path_string(path);
                HttpPeer::new_uds(&path_str, false, String::new())?
            }
            UpstreamTarget::Tcp(addr) => {
                let sock = resolve_socket_addr(addr).await?;
                HttpPeer::new(sock, false, String::new())
            }
            UpstreamTarget::Https { addr, sni, .. } => {
                let sock = resolve_socket_addr(addr).await?;
                let mut p = HttpPeer::new(sock, true, sni.clone());
                p.options.alpn = ALPN::H2H1;
                p
            }
        };

        if ctx.transport.h2c {
            peer.options.set_http_version(2, 2);
            peer.options.max_h2_streams = ctx.transport.max_h2_streams;
            peer.options.h2_stream_window_size = Some(ctx.transport.h2_stream_window_size);
            peer.options.h2_connection_window_size = Some(ctx.transport.h2_connection_window_size);
            peer.options.h2_ping_interval =
                Some(Duration::from_secs(ctx.transport.h2_ping_interval_secs));
        }

        peer.options.connection_timeout = Some(ctx.connect_timeout);
        peer.options.read_timeout = Some(ctx.read_timeout);
        peer.options.write_timeout = Some(ctx.read_timeout);
        peer.options.idle_timeout = Some(Duration::from_secs(ctx.transport.idle_timeout_secs));
        peer.options.tcp_fast_open = true;
        peer.options.tcp_keepalive = Some(default_tcp_keepalive());

        Ok(Box::new(peer))
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<Duration>> {
        if ctx.flush_immediately {
            return Ok(None);
        }
        Ok(None)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if let Some(rw_host) = &ctx.rewrite_host {
            if !ctx.host.is_empty() && upstream_request.headers.get("x-forwarded-host").is_none() {
                upstream_request.insert_header("X-Forwarded-Host", &ctx.host)?;
            }
            upstream_request.insert_header("Host", rw_host)?;
        } else if !ctx.host.is_empty() && upstream_request.headers.get("host").is_none() {
            upstream_request.insert_header("Host", &ctx.host)?;
        }

        for (h_name, h_ref) in &ctx.headers_up {
            let resolved_opt = if let Some(store) = &self.secret_store {
                store.resolve_secret_ref(h_ref).ok().map(|z| z.to_string())
            } else {
                match h_ref {
                    SecretRef::Literal(s) => Some(s.clone()),
                    SecretRef::Env(var) => std::env::var(var).ok(),
                    SecretRef::Vault { .. } => None,
                }
            };
            if let Some(val) = resolved_opt {
                upstream_request.insert_header(h_name.clone(), val)?;
            }
        }

        if let Some(client_addr) = session.client_addr() {
            if let Some(inet) = client_addr.as_inet() {
                upstream_request.insert_header("X-Forwarded-For", inet.ip().to_string())?;
            }
        }
        let proto = if session.digest().is_some_and(|d| d.ssl_digest.is_some()) {
            "https"
        } else if let Some(existing) = session.req_header().headers.get("x-forwarded-proto") {
            existing.to_str().unwrap_or("http")
        } else {
            "http"
        };
        upstream_request.insert_header("X-Forwarded-Proto", proto)?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if let Some(up_name) = &ctx.hybrid_upstream_name {
            upstream_response.insert_header("X-Fluxgate-Upstream", up_name)?;
            if ctx.hybrid_used_fallback {
                upstream_response.insert_header("X-Fluxgate-Fallback", "connect_error")?;
            }
        }
        Ok(())
    }

    fn fail_to_connect(
        &self,
        session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if session.response_written().is_none() {
            if let Some(fb) = ctx.fallback_candidate.take() {
                tracing::warn!(
                    "Primary hybrid upstream failed to connect ({}), failing over to '{}'",
                    e,
                    fb.name
                );
                ctx.upstream = Some(fb.upstream);
                ctx.transport = fb.transport;
                ctx.rewrite_host = fb.rewrite_host;
                ctx.headers_up = fb.headers_up;
                ctx.connect_timeout = fb.connect_timeout;
                ctx.read_timeout = fb.read_timeout;
                ctx.flush_immediately = fb.flush_immediately;
                ctx.hybrid_upstream_name = Some(fb.name);
                ctx.hybrid_used_fallback = true;
                e.set_retry(true);
                return e;
            }
        }
        e.set_retry(false);
        e
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        let mut e = e.more_context(format!(
            "Peer: {} (h2c={}, reused={})",
            peer, ctx.transport.h2c, client_reused
        ));
        if session.req_header().method.is_idempotent()
            && !session.as_ref().retry_buffer_truncated()
            && session.response_written().is_none()
        {
            e.retry.decide_reuse(client_reused);
        } else {
            e.set_retry(false);
        }
        e
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, error: &Error) -> bool {
        let err_text = error.to_string();
        error.esource() == &ErrorSource::Downstream
            || err_text.contains("Client closed H2")
            || err_text.contains("stream no longer needed")
            || err_text.contains("Broken pipe")
            || err_text.contains("Connection reset by peer")
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        if let Some(m) = &self.metrics {
            if ctx.active_counted {
                m.dec_active();
                ctx.active_counted = false;
            }
            let is_downstream_cancel = e.is_some_and(|err| {
                err.esource() == &ErrorSource::Downstream
                    || err.to_string().contains("stream no longer needed")
                    || err.to_string().contains("Client closed H2")
            });
            let status = session
                .response_written()
                .map(|resp| resp.status.as_u16())
                .unwrap_or(if is_downstream_cancel {
                    499
                } else if e.is_some() {
                    502
                } else {
                    0
                });
            let elapsed = ctx.start_time.elapsed().as_secs_f64();
            m.record_request(&ctx.host, ctx.route_label, status, elapsed);
            if let Some(err) = e {
                if !is_downstream_cancel && err.esource() == &ErrorSource::Upstream {
                    if let Some(up) = &ctx.upstream {
                        let up_label = match up {
                            UpstreamTarget::Uds(p) => p.to_string_lossy().to_string(),
                            UpstreamTarget::Tcp(a) => a.clone(),
                            UpstreamTarget::Https { addr, .. } => addr.clone(),
                        };
                        m.record_upstream_error(&up_label);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DEFAULT_H2_CONNECTION_WINDOW_SIZE, DEFAULT_H2_PING_INTERVAL_SECS,
        DEFAULT_H2_STREAM_WINDOW_SIZE, DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_MAX_H2_STREAMS,
    };

    #[test]
    fn test_default_tcp_keepalive_and_transport_defaults() {
        let ka = default_tcp_keepalive();
        assert_eq!(ka.idle, Duration::from_secs(60));
        assert_eq!(ka.interval, Duration::from_secs(15));
        assert_eq!(ka.count, 4);
        #[cfg(target_os = "linux")]
        assert_eq!(ka.user_timeout, Duration::from_secs(60));

        let transport = TransportConfig::default();
        assert!(!transport.h2c);
        assert_eq!(
            transport.h2_stream_window_size,
            DEFAULT_H2_STREAM_WINDOW_SIZE
        );
        assert_eq!(
            transport.h2_connection_window_size,
            DEFAULT_H2_CONNECTION_WINDOW_SIZE
        );
        assert_eq!(
            transport.h2_ping_interval_secs,
            DEFAULT_H2_PING_INTERVAL_SECS
        );
        assert_eq!(transport.max_h2_streams, DEFAULT_MAX_H2_STREAMS);
        assert_eq!(transport.read_timeout_secs, DEFAULT_READ_TIMEOUT_SECS);
        assert_eq!(transport.idle_timeout_secs, DEFAULT_IDLE_TIMEOUT_SECS);
    }
}
