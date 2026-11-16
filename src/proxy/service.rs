use crate::config::UpstreamTarget;
use crate::proxy::route::{uds_path_string, CompiledRouter, RouteResolution};
use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use std::sync::Arc;
use std::time::Duration;

pub struct FluxgateProxy {
    pub router: Arc<CompiledRouter>,
    pub https_enabled: bool,
}

#[derive(Default)]
pub struct FluxgateCtx {
    pub upstream: Option<UpstreamTarget>,
    pub h2c: bool,
    pub flush_immediately: bool,
    pub host: String,
}

impl FluxgateProxy {
    pub fn new(router: Arc<CompiledRouter>, https_enabled: bool) -> Self {
        Self {
            router,
            https_enabled,
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
        let host = Self::extract_host(session);
        let is_tls = session
            .digest()
            .is_some_and(|digest| digest.ssl_digest.is_some());

        // Redirect plain HTTP to HTTPS when TLS is enabled (matching Caddy auto_https)
        if self.https_enabled && !is_tls && !host.is_empty() {
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
        match self.router.resolve(&host, &original_uri) {
            RouteResolution::Respond { status, body } => {
                Self::send_static_response(session, status, &body).await
            }
            RouteResolution::NotFound => {
                Self::send_static_response(session, 404, "Not Found").await
            }
            RouteResolution::Proxy {
                upstream,
                h2c,
                flush_immediately,
                new_uri,
            } => {
                if let Some(uri) = new_uri {
                    session.req_header_mut().set_uri(uri);
                }
                ctx.upstream = Some(upstream);
                ctx.h2c = h2c;
                ctx.flush_immediately = flush_immediately;
                ctx.host = host;
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

        if ctx.h2c {
            // Enforce h2c (HTTP/2 cleartext prior knowledge); do not silently downgrade to H1.1
            peer.options.set_http_version(2, 2);
            peer.options.max_h2_streams = 128;
            peer.options.h2_stream_window_size = Some(1024 * 1024);
            peer.options.h2_connection_window_size = Some(4 * 1024 * 1024);
            peer.options.h2_ping_interval = Some(Duration::from_secs(30));
        }

        peer.options.connection_timeout = Some(Duration::from_secs(5));
        peer.options.read_timeout = Some(Duration::from_secs(3600));
        peer.options.write_timeout = Some(Duration::from_secs(3600));
        peer.options.idle_timeout = Some(Duration::from_secs(3600));

        Ok(Box::new(peer))
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
}
