use crate::config::{TransportConfig, UpstreamTarget};
use crate::metrics::MetricsRegistry;
use crate::proxy::route::{uds_path_string, CompiledRouter, RouteResolution};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::protocols::TcpKeepalive;
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

pub struct FluxgateProxy {
    pub router: Arc<ArcSwap<CompiledRouter>>,
    pub https_enabled: bool,
    pub metrics: Option<Arc<MetricsRegistry>>,
}

pub struct FluxgateCtx {
    pub upstream: Option<UpstreamTarget>,
    pub transport: TransportConfig,
    pub flush_immediately: bool,
    pub host: String,
    pub route_label: &'static str,
    pub start_time: Instant,
    pub active_counted: bool,
}

impl Default for FluxgateCtx {
    fn default() -> Self {
        Self {
            upstream: None,
            transport: TransportConfig::default(),
            flush_immediately: false,
            host: String::new(),
            route_label: "unknown",
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
        }
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
                new_uri,
            } => {
                ctx.route_label = match &upstream {
                    UpstreamTarget::Uds(_) => "uds",
                    UpstreamTarget::Tcp(_) => "tcp",
                };
                if let Some(uri) = new_uri {
                    session.req_header_mut().set_uri(uri);
                }
                let rw_timeout = Duration::from_secs(transport.read_timeout_secs);
                session.set_read_timeout(Some(rw_timeout));
                session.set_write_timeout(Some(rw_timeout));
                session.set_keepalive(Some(transport.idle_timeout_secs));
                if flush_immediately {
                    // Never allow compression buffering to delay small voice/photo frames
                    session.upstream_compression.adjust_level(0);
                }
                ctx.upstream = Some(upstream);
                ctx.transport = transport;
                ctx.flush_immediately = flush_immediately;
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
            UpstreamTarget::Tcp(addr) => HttpPeer::new(addr, false, String::new()),
        };

        if ctx.transport.h2c {
            // Enforce h2c (HTTP/2 cleartext prior knowledge); do not silently downgrade to H1.1
            peer.options.set_http_version(2, 2);
            peer.options.max_h2_streams = ctx.transport.max_h2_streams;
            peer.options.h2_stream_window_size = Some(ctx.transport.h2_stream_window_size);
            peer.options.h2_connection_window_size = Some(ctx.transport.h2_connection_window_size);
            peer.options.h2_ping_interval =
                Some(Duration::from_secs(ctx.transport.h2_ping_interval_secs));
        }

        let rw_timeout = Duration::from_secs(ctx.transport.read_timeout_secs);
        peer.options.connection_timeout = Some(Duration::from_secs(5));
        peer.options.read_timeout = Some(rw_timeout);
        peer.options.write_timeout = Some(rw_timeout);
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
            // Zero flush delay on streaming frames (`flush_interval -1`)
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
        if !ctx.host.is_empty() && upstream_request.headers.get("host").is_none() {
            upstream_request.insert_header("Host", &ctx.host)?;
        }
        if let Some(client_addr) = session.client_addr() {
            if let Some(inet) = client_addr.as_inet() {
                upstream_request.insert_header("X-Forwarded-For", inet.ip().to_string())?;
            }
        }
        let proto = if session.digest().is_some_and(|d| d.ssl_digest.is_some()) {
            "https"
        } else {
            "http"
        };
        upstream_request.insert_header("X-Forwarded-Proto", proto)?;
        Ok(())
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        // Never perform unsafe automatic retries on streaming requests
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
        // Only allow safe retries on idempotent requests before response headers are sent
        // (e.g., GOAWAY/REFUSED_STREAM or stale pooled H2 connections). Never replay
        // non-idempotent streaming uploads or truncated request bodies.
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
        // Downstream client cancellation is normal lifecycle for streaming protocols (e.g. XHTTP)
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
                // Only increment upstream error counter if it is genuinely an upstream failure
                if !is_downstream_cancel && err.esource() == &ErrorSource::Upstream {
                    if let Some(up) = &ctx.upstream {
                        let up_label = match up {
                            UpstreamTarget::Uds(p) => p.to_string_lossy().to_string(),
                            UpstreamTarget::Tcp(a) => a.clone(),
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
        DEFAULT_READ_TIMEOUT_SECS,
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
