use crate::config::ast::*;
use crate::proxy::rewrite::{rebuild_uri, remove_query_param, strip_path_prefix};
use http::Uri;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CompiledRouter {
    pub sites: Vec<CompiledSite>,
}

#[derive(Debug, Clone)]
pub struct CompiledSite {
    pub hosts: Vec<String>,
    pub tls: Option<TlsConfig>,
    pub matchers: HashMap<String, Vec<String>>,
    pub pre_rewrites: Vec<CompiledRewrite>,
    pub routes: Vec<CompiledRouteBlock>,
    pub fallback: Option<RespondConfig>,
}

#[derive(Debug, Clone)]
pub struct CompiledRewrite {
    pub matcher_paths: Option<Vec<String>>,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct CompiledRouteBlock {
    pub kind: RouteBlockKind,
    pub query_removals: Vec<String>,
    pub inner_rewrites: Vec<String>,
    pub action: RouteAction,
}

#[derive(Debug, Clone)]
pub enum RouteBlockKind {
    HandlePath { prefix: String },
    Handle { matcher_paths: Option<Vec<String>> },
}

#[derive(Debug, Clone)]
pub enum RouteAction {
    ReverseProxy(ReverseProxyConfig),
    Respond(RespondConfig),
}

#[derive(Debug, Clone)]
pub enum RouteResolution {
    Proxy {
        upstream: UpstreamTarget,
        h2c: bool,
        flush_immediately: bool,
        new_uri: Option<Uri>,
    },
    Respond {
        status: u16,
        body: String,
    },
    NotFound,
}

impl CompiledRouter {
    pub fn compile(config: &FluxgateConfig) -> Self {
        let sites = config.sites.iter().map(CompiledSite::compile).collect();
        Self { sites }
    }

    pub fn find_site(&self, host: &str) -> Option<&CompiledSite> {
        let host_clean = host.split(':').next().unwrap_or(host).to_ascii_lowercase();

        // Prefer exact match first, then wildcard match
        for site in &self.sites {
            if site.hosts.iter().any(|h| h.to_ascii_lowercase() == host_clean) {
                return Some(site);
            }
        }
        for site in &self.sites {
            if site.hosts.iter().any(|h| host_matches_wildcard(h, &host_clean)) {
                return Some(site);
            }
        }
        None
    }

    /// Return the primary TLS config if configured on any site.
    pub fn primary_tls(&self) -> Option<&TlsConfig> {
        self.sites.iter().find_map(|s| s.tls.as_ref())
    }

    /// Resolve an incoming request (host + URI) into a concrete proxy or respond decision.
    pub fn resolve(&self, host: &str, original_uri: &Uri) -> RouteResolution {
        let Some(site) = self.find_site(host) else {
            return RouteResolution::NotFound;
        };
        site.resolve(original_uri)
    }
}

impl CompiledSite {
    fn compile(site: &SiteConfig) -> Self {
        let matchers: HashMap<String, Vec<String>> = site
            .matchers
            .iter()
            .map(|m| (m.name.clone(), m.paths.clone()))
            .collect();

        let mut pre_rewrites = Vec::new();
        let mut routes = Vec::new();
        let mut fallback = None;

        for directive in &site.directives {
            match directive {
                Directive::Rewrite { matcher, target } => {
                    let matcher_paths = matcher
                        .as_ref()
                        .and_then(|name| matchers.get(name).cloned());
                    pre_rewrites.push(CompiledRewrite {
                        matcher_paths,
                        target: target.clone(),
                    });
                }
                Directive::HandlePath { prefix, directives } => {
                    if let Some(block) = compile_block(
                        RouteBlockKind::HandlePath {
                            prefix: prefix.clone(),
                        },
                        directives,
                    ) {
                        routes.push(block);
                    }
                }
                Directive::Handle {
                    matcher,
                    directives,
                } => {
                    let matcher_paths = matcher
                        .as_ref()
                        .and_then(|name| matchers.get(name).cloned());
                    if let Some(block) = compile_block(
                        RouteBlockKind::Handle { matcher_paths },
                        directives,
                    ) {
                        routes.push(block);
                    }
                }
                Directive::ReverseProxy(rp) => {
                    routes.push(CompiledRouteBlock {
                        kind: RouteBlockKind::Handle {
                            matcher_paths: None,
                        },
                        query_removals: Vec::new(),
                        inner_rewrites: Vec::new(),
                        action: RouteAction::ReverseProxy(rp.clone()),
                    });
                }
                Directive::Respond(resp) => {
                    fallback = Some(resp.clone());
                }
                Directive::UriQueryRemove { .. } => {}
            }
        }

        Self {
            hosts: site.hosts.clone(),
            tls: site.tls.clone(),
            matchers,
            pre_rewrites,
            routes,
            fallback,
        }
    }

    pub fn resolve(&self, original_uri: &Uri) -> RouteResolution {
        let mut current_path = original_uri.path().to_string();
        let mut current_query = original_uri.query().map(|q| q.to_string());
        let mut uri_mutated = false;

        // Step 1: Apply top-level rewrites (e.g. `rewrite @xhttp_root /split/`)
        for rw in &self.pre_rewrites {
            let matched = match &rw.matcher_paths {
                Some(paths) => paths_match(&current_path, paths),
                None => true,
            };
            if matched && current_path != rw.target {
                current_path = rw.target.clone();
                uri_mutated = true;
            }
        }

        // Step 2: Match first matching `handle_path` / `handle` block (Caddy mutually-exclusive semantics)
        for route in &self.routes {
            let matched = match &route.kind {
                RouteBlockKind::HandlePath { prefix } => path_matches_pattern(&current_path, prefix),
                RouteBlockKind::Handle { matcher_paths } => match matcher_paths {
                    Some(paths) => paths_match(&current_path, paths),
                    None => true,
                },
            };

            if !matched {
                continue;
            }

            if let RouteBlockKind::HandlePath { prefix } = &route.kind {
                let stripped = strip_path_prefix(&current_path, prefix);
                if stripped != current_path {
                    current_path = stripped;
                    uri_mutated = true;
                }
            }

            for target in &route.inner_rewrites {
                if &current_path != target {
                    current_path = target.clone();
                    uri_mutated = true;
                }
            }

            for param in &route.query_removals {
                if let Some(q) = current_query.take() {
                    let cleaned = remove_query_param(&q, param);
                    if cleaned.as_deref() != Some(q.as_str()) {
                        uri_mutated = true;
                    }
                    current_query = cleaned;
                }
            }

            match &route.action {
                RouteAction::ReverseProxy(rp) => {
                    let new_uri = if uri_mutated {
                        rebuild_uri(original_uri, &current_path, current_query.as_deref())
                    } else {
                        None
                    };
                    return RouteResolution::Proxy {
                        upstream: rp.upstream.clone(),
                        h2c: rp.transport.h2c,
                        flush_immediately: rp.flush_interval < 0,
                        new_uri,
                    };
                }
                RouteAction::Respond(resp) => {
                    return RouteResolution::Respond {
                        status: resp.status,
                        body: resp.body.clone(),
                    };
                }
            }
        }

        // Step 3: Default fallback response
        if let Some(resp) = &self.fallback {
            return RouteResolution::Respond {
                status: resp.status,
                body: resp.body.clone(),
            };
        }

        RouteResolution::NotFound
    }
}

fn compile_block(kind: RouteBlockKind, directives: &[Directive]) -> Option<CompiledRouteBlock> {
    let mut query_removals = Vec::new();
    let mut inner_rewrites = Vec::new();
    let mut action = None;

    for d in directives {
        match d {
            Directive::UriQueryRemove { param } => query_removals.push(param.clone()),
            Directive::Rewrite { target, .. } => inner_rewrites.push(target.clone()),
            Directive::ReverseProxy(rp) => action = Some(RouteAction::ReverseProxy(rp.clone())),
            Directive::Respond(resp) => action = Some(RouteAction::Respond(resp.clone())),
            _ => {}
        }
    }

    action.map(|act| CompiledRouteBlock {
        kind,
        query_removals,
        inner_rewrites,
        action: act,
    })
}

fn host_matches_wildcard(pattern: &str, host: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    if p == "*" {
        return true;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        return host.ends_with(&format!(".{}", suffix)) && host.len() > suffix.len() + 1;
    }
    false
}

fn paths_match(req_path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| path_matches_pattern(req_path, p))
}

fn path_matches_pattern(req_path: &str, pattern: &str) -> bool {
    if let Some(prefix_with_slash) = pattern.strip_suffix('*') {
        let trimmed = prefix_with_slash.trim_end_matches('/');
        if trimmed.is_empty() {
            return true;
        }
        req_path == trimmed || req_path.starts_with(&format!("{}/", trimmed))
    } else {
        req_path == pattern
    }
}

pub fn uds_path_string(path: &PathBuf) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::Parser;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_xconnect_route_resolution() {
        let cfg_text = r#"
jp-xconnect-01.svc.plus jp-xconnect-02.svc.plus {
    tls /tmp/cert.crt /tmp/cert.key

    handle_path /xray-exporter/xhttp/* {
        reverse_proxy 127.0.0.1:8080
    }

    handle_path /xray-exporter/tcp/* {
        reverse_proxy 127.0.0.1:8081
    }

    @xhttp {
        path /split /split/*
    }

    @xhttp_root path /split
    rewrite @xhttp_root /split/

    handle @xhttp {
        uri query -x_padding

        reverse_proxy unix//dev/shm/xray.sock {
            flush_interval -1

            transport http {
                versions h2c 2
            }
        }
    }

    respond "Agent Service Plus Node"
}
"#;
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(cfg_text.as_bytes()).unwrap();
        let mut parser = Parser::new();
        let cfg = parser.parse_file(tmp.path()).unwrap();
        let router = CompiledRouter::compile(&cfg);

        // 1. Default respond
        let res = router.resolve("jp-xconnect-01.svc.plus", &"/".parse().unwrap());
        match res {
            RouteResolution::Respond { status, body } => {
                assert_eq!(status, 200);
                assert_eq!(body, "Agent Service Plus Node");
            }
            other => panic!("Expected Respond, got {:?}", other),
        }

        // 2. Exporter xhttp strip prefix
        let res = router.resolve(
            "jp-xconnect-02.svc.plus",
            &"/xray-exporter/xhttp/snapshots?w=1".parse().unwrap(),
        );
        match res {
            RouteResolution::Proxy {
                upstream,
                h2c,
                new_uri,
                ..
            } => {
                assert_eq!(upstream, UpstreamTarget::Tcp("127.0.0.1:8080".to_string()));
                assert!(!h2c);
                assert_eq!(new_uri.unwrap().to_string(), "/snapshots?w=1");
            }
            other => panic!("Expected Proxy, got {:?}", other),
        }

        // 3. /split?x_padding= -> /split/ over h2c UDS
        let res = router.resolve(
            "jp-xconnect-01.svc.plus",
            &"/split?x_padding=".parse().unwrap(),
        );
        match res {
            RouteResolution::Proxy {
                upstream,
                h2c,
                flush_immediately,
                new_uri,
            } => {
                assert_eq!(
                    upstream,
                    UpstreamTarget::Uds(PathBuf::from("/dev/shm/xray.sock"))
                );
                assert!(h2c);
                assert!(flush_immediately);
                assert_eq!(new_uri.unwrap().to_string(), "/split/");
            }
            other => panic!("Expected Proxy, got {:?}", other),
        }

        // 4. /split/sub?x_padding=abc&foo=bar -> /split/sub?foo=bar
        let res = router.resolve(
            "jp-xconnect-01.svc.plus",
            &"/split/sub?x_padding=abc&foo=bar".parse().unwrap(),
        );
        match res {
            RouteResolution::Proxy { new_uri, .. } => {
                assert_eq!(new_uri.unwrap().to_string(), "/split/sub?foo=bar");
            }
            other => panic!("Expected Proxy, got {:?}", other),
        }
    }
}
