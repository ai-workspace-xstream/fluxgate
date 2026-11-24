use crate::config::ast::*;
use crate::config::import::{resolve_imports, ImportTracker};
use crate::config::lexer::{Lexer, Token, TokenKind};
use crate::error::{FluxgateError, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct Parser {
    import_tracker: ImportTracker,
}

impl Parser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_file(&mut self, path: &Path) -> Result<FluxgateConfig> {
        let mut global = GlobalConfig::default();
        let mut sites = Vec::new();

        self.parse_recursive(path, 0, &mut global, &mut sites)?;

        Ok(FluxgateConfig { global, sites })
    }

    fn parse_recursive(
        &mut self,
        path: &Path,
        depth: usize,
        global: &mut GlobalConfig,
        sites: &mut Vec<SiteConfig>,
    ) -> Result<()> {
        let canonical = self.import_tracker.enter_file(path, depth)?;
        let content = fs::read_to_string(&canonical).map_err(|e| {
            FluxgateError::ConfigValidation(format!(
                "Failed to read file {}: {}",
                canonical.display(),
                e
            ))
        })?;

        let lexer = Lexer::new(&canonical, &content);
        let tokens = lexer.tokenize();
        let mut cursor = TokenCursor::new(tokens);

        while !cursor.is_eof() {
            cursor.skip_newlines();
            if cursor.is_eof() {
                break;
            }

            // Check if top-level directive is 'import'
            if let Some(TokenKind::Word(word)) = cursor.peek_kind() {
                if word == "import" {
                    cursor.next(); // consume 'import'
                    let pattern_token = cursor.expect_word("import pattern")?;
                    let pattern = pattern_token.kind_word();
                    let matched_files = resolve_imports(&canonical, &pattern)?;
                    if matched_files.is_empty() && !pattern.contains('*') {
                        return Err(FluxgateError::ConfigSyntax {
                            file: pattern_token.file,
                            line: pattern_token.line,
                            msg: format!("Imported file '{}' not found", pattern),
                        });
                    }
                    for imported in matched_files {
                        self.parse_recursive(&imported, depth + 1, global, sites)?;
                    }
                    continue;
                }
            }

            // Check for global options block: starts with '{' directly
            if cursor.peek_kind() == Some(&TokenKind::OpenBrace) {
                cursor.next(); // consume '{'
                self.parse_global_block(&mut cursor, global)?;
                continue;
            }

            // Otherwise, it's a Site block: `host1 [host2...] { ... }`
            let mut hosts = Vec::new();
            while let Some(kind) = cursor.peek_kind() {
                if *kind == TokenKind::OpenBrace {
                    break;
                }
                if let TokenKind::Word(w) = kind {
                    hosts.push(w.clone());
                    cursor.next();
                } else {
                    let tok = cursor.current().unwrap();
                    return Err(FluxgateError::ConfigSyntax {
                        file: tok.file.clone(),
                        line: tok.line,
                        msg: format!("Unexpected token in site block header: {:?}", kind),
                    });
                }
            }

            if hosts.is_empty() {
                let (err_file, err_line) = if let Some(tok) = cursor.current() {
                    (tok.file.clone(), tok.line)
                } else {
                    (path.to_path_buf(), 1)
                };
                return Err(FluxgateError::ConfigSyntax {
                    file: err_file,
                    line: err_line,
                    msg: "Expected site address before '{'".to_string(),
                });
            }

            cursor.expect(TokenKind::OpenBrace, "open brace '{' for site block")?;
            let site = self.parse_site_block(&mut cursor, hosts)?;
            sites.push(site);
        }

        self.import_tracker.leave_file(&canonical);
        Ok(())
    }

    fn parse_global_block(
        &self,
        cursor: &mut TokenCursor,
        global: &mut GlobalConfig,
    ) -> Result<()> {
        while let Some(kind) = cursor.peek_kind() {
            if *kind == TokenKind::CloseBrace {
                cursor.next();
                return Ok(());
            }
            if *kind == TokenKind::Newline {
                cursor.next();
                continue;
            }

            let tok = cursor.next().unwrap();
            let directive = tok.kind_word();
            match directive.as_str() {
                "grace_period" => {
                    let val_tok = cursor.expect_word("grace_period value (e.g. 15s)")?;
                    let val_str = val_tok.kind_word();
                    let secs = val_str.trim_end_matches('s').parse::<u64>().map_err(|_| {
                        FluxgateError::ConfigSyntax {
                            file: val_tok.file,
                            line: val_tok.line,
                            msg: format!("Invalid grace_period duration '{}'", val_str),
                        }
                    })?;
                    global.grace_period_secs = secs;
                }
                "log" => {
                    // skip/parse log block: log [name] { level INFO }
                    if cursor.peek_kind() == Some(&TokenKind::OpenBrace)
                        || cursor
                            .peek_kind()
                            .is_some_and(|k| matches!(k, TokenKind::Word(_)))
                    {
                        if let Some(TokenKind::Word(_)) = cursor.peek_kind() {
                            cursor.next();
                        }
                        if cursor.peek_kind() == Some(&TokenKind::OpenBrace) {
                            cursor.next();
                            while let Some(k) = cursor.peek_kind() {
                                if *k == TokenKind::CloseBrace {
                                    cursor.next();
                                    break;
                                }
                                if let TokenKind::Word(sub) = k {
                                    if sub == "level" {
                                        cursor.next();
                                        let lvl = cursor.expect_word("log level")?;
                                        global.log_level = lvl.kind_word();
                                    } else {
                                        cursor.next();
                                    }
                                } else {
                                    cursor.next();
                                }
                            }
                        }
                    }
                }
                "metrics" => {
                    let mut addr = "127.0.0.1:9102".to_string();
                    if let Some(TokenKind::Word(w)) = cursor.peek_kind() {
                        addr = w.clone();
                        cursor.next();
                    }
                    if cursor.peek_kind() == Some(&TokenKind::OpenBrace) {
                        cursor.next();
                        while let Some(k) = cursor.peek_kind() {
                            if *k == TokenKind::CloseBrace {
                                cursor.next();
                                break;
                            }
                            if let TokenKind::Word(sub) = k {
                                if sub == "listen" {
                                    cursor.next();
                                    addr =
                                        cursor.expect_word("metrics listen address")?.kind_word();
                                    continue;
                                }
                            }
                            cursor.next();
                        }
                    }
                    global.metrics_addr = Some(addr);
                }
                "vault" => {
                    cursor.expect(TokenKind::OpenBrace, "open brace '{' for vault block")?;
                    global.vault = Some(self.parse_vault_block(cursor, &tok)?);
                }
                other => {
                    return Err(FluxgateError::ConfigSyntax {
                        file: tok.file,
                        line: tok.line,
                        msg: format!("Unrecognized global directive '{}'", other),
                    });
                }
            }
        }

        let tok = cursor.current().unwrap();
        Err(FluxgateError::ConfigSyntax {
            file: tok.file.clone(),
            line: tok.line,
            msg: "Unclosed global block, expected '}'".to_string(),
        })
    }

    fn parse_site_block(&self, cursor: &mut TokenCursor, hosts: Vec<String>) -> Result<SiteConfig> {
        let mut tls = None;
        let mut matchers = Vec::new();
        let mut directives = Vec::new();

        while let Some(kind) = cursor.peek_kind() {
            if *kind == TokenKind::CloseBrace {
                cursor.next();
                return Ok(SiteConfig {
                    hosts,
                    tls,
                    matchers,
                    directives,
                });
            }
            if *kind == TokenKind::Newline {
                cursor.next();
                continue;
            }

            let tok = cursor.next().unwrap();
            let directive = tok.kind_word();

            if directive.starts_with('@') {
                // Named matcher: e.g. `@xhttp { path /split /split/* }` or `@xhttp_root path /split`
                let matcher = self.parse_named_matcher(directive, cursor)?;
                matchers.push(matcher);
                continue;
            }

            match directive.as_str() {
                "tls" => {
                    if cursor.peek_kind() == Some(&TokenKind::OpenBrace) {
                        cursor.next(); // consume '{'
                        tls = Some(TlsConfig::Acme(self.parse_tls_block(cursor, &tok)?));
                    } else {
                        let cert = cursor.expect_word("TLS certificate path")?;
                        let key = cursor.expect_word("TLS private key path")?;
                        tls = Some(TlsConfig::Static {
                            cert_path: PathBuf::from(cert.kind_word()),
                            key_path: PathBuf::from(key.kind_word()),
                        });
                    }
                }
                "handle_path" => {
                    let prefix = cursor.expect_word("handle_path prefix")?.kind_word();
                    cursor.expect(TokenKind::OpenBrace, "open brace '{' for handle_path")?;
                    let inner = self.parse_inner_directives(cursor)?;
                    directives.push(Directive::HandlePath {
                        prefix,
                        directives: inner,
                    });
                }
                "handle" => {
                    let matcher = if let Some(TokenKind::Word(w)) = cursor.peek_kind() {
                        if w.starts_with('@') {
                            let m = w.clone();
                            cursor.next();
                            Some(m)
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    cursor.expect(TokenKind::OpenBrace, "open brace '{' for handle")?;
                    let inner = self.parse_inner_directives(cursor)?;
                    directives.push(Directive::Handle {
                        matcher,
                        directives: inner,
                    });
                }
                "rewrite" => {
                    let (matcher, target) = if let Some(TokenKind::Word(w)) = cursor.peek_kind() {
                        if w.starts_with('@') {
                            let m = w.clone();
                            cursor.next();
                            let tgt = cursor.expect_word("rewrite target path")?.kind_word();
                            (Some(m), tgt)
                        } else {
                            let tgt = cursor.expect_word("rewrite target path")?.kind_word();
                            (None, tgt)
                        }
                    } else {
                        let tgt = cursor.expect_word("rewrite target path")?.kind_word();
                        (None, tgt)
                    };
                    directives.push(Directive::Rewrite { matcher, target });
                }
                "uri" => {
                    let sub = cursor
                        .expect_word("uri sub-directive (e.g. query)")?
                        .kind_word();
                    if sub == "query" {
                        let op = cursor
                            .expect_word("uri query operation (e.g. -param)")?
                            .kind_word();
                        if let Some(param) = op.strip_prefix('-') {
                            directives.push(Directive::UriQueryRemove {
                                param: param.to_string(),
                            });
                        } else {
                            return Err(FluxgateError::ConfigSyntax {
                                file: tok.file,
                                line: tok.line,
                                msg: format!(
                                    "Unsupported uri query operation '{}', expected -param",
                                    op
                                ),
                            });
                        }
                    } else {
                        return Err(FluxgateError::ConfigSyntax {
                            file: tok.file,
                            line: tok.line,
                            msg: format!("Unsupported uri directive '{}'", sub),
                        });
                    }
                }
                "reverse_proxy" => {
                    let rp = self.parse_reverse_proxy(cursor, tok)?;
                    directives.push(Directive::ReverseProxy(rp));
                }
                "respond" => {
                    let body = cursor.expect_word("respond body")?.kind_word();
                    let status = if let Some(TokenKind::Word(s)) = cursor.peek_kind() {
                        if let Ok(code) = s.parse::<u16>() {
                            cursor.next();
                            code
                        } else {
                            200
                        }
                    } else {
                        200
                    };
                    directives.push(Directive::Respond(RespondConfig { body, status }));
                }
                other => {
                    return Err(FluxgateError::ConfigSyntax {
                        file: tok.file,
                        line: tok.line,
                        msg: format!("Unrecognized site directive '{}'", other),
                    });
                }
            }
        }

        let tok = cursor.current().unwrap();
        Err(FluxgateError::ConfigSyntax {
            file: tok.file.clone(),
            line: tok.line,
            msg: "Unclosed site block, expected '}'".to_string(),
        })
    }

    fn parse_named_matcher(&self, name: String, cursor: &mut TokenCursor) -> Result<NamedMatcher> {
        let mut paths = Vec::new();
        if cursor.peek_kind() == Some(&TokenKind::OpenBrace) {
            cursor.next(); // consume '{'
            while let Some(k) = cursor.peek_kind() {
                if *k == TokenKind::CloseBrace {
                    cursor.next();
                    break;
                }
                if *k == TokenKind::Newline {
                    cursor.next();
                    continue;
                }
                if let TokenKind::Word(w) = k {
                    if w == "path" {
                        cursor.next();
                        while let Some(sub_k) = cursor.peek_kind() {
                            if *sub_k == TokenKind::Newline || *sub_k == TokenKind::CloseBrace {
                                break;
                            }
                            if let TokenKind::Word(p) = sub_k {
                                paths.push(p.clone());
                                cursor.next();
                            } else {
                                break;
                            }
                        }
                    } else {
                        cursor.next();
                    }
                }
            }
        } else {
            // single line matcher: @xhttp_root path /split
            let matcher_type = cursor.expect_word("matcher type (e.g. path)")?.kind_word();
            if matcher_type == "path" {
                while let Some(k) = cursor.peek_kind() {
                    if *k == TokenKind::Newline || *k == TokenKind::CloseBrace {
                        break;
                    }
                    if let TokenKind::Word(p) = k {
                        paths.push(p.clone());
                        cursor.next();
                    } else {
                        break;
                    }
                }
            }
        }

        Ok(NamedMatcher { name, paths })
    }

    fn parse_inner_directives(&self, cursor: &mut TokenCursor) -> Result<Vec<Directive>> {
        let mut directives = Vec::new();

        while let Some(kind) = cursor.peek_kind() {
            if *kind == TokenKind::CloseBrace {
                cursor.next();
                return Ok(directives);
            }
            if *kind == TokenKind::Newline {
                cursor.next();
                continue;
            }

            let tok = cursor.next().unwrap();
            let directive = tok.kind_word();

            match directive.as_str() {
                "reverse_proxy" => {
                    let rp = self.parse_reverse_proxy(cursor, tok)?;
                    directives.push(Directive::ReverseProxy(rp));
                }
                "rewrite" => {
                    let target = cursor.expect_word("rewrite target path")?.kind_word();
                    directives.push(Directive::Rewrite {
                        matcher: None,
                        target,
                    });
                }
                "uri" => {
                    let sub = cursor.expect_word("uri sub-directive")?.kind_word();
                    if sub == "query" {
                        let op = cursor.expect_word("uri query op")?.kind_word();
                        if let Some(param) = op.strip_prefix('-') {
                            directives.push(Directive::UriQueryRemove {
                                param: param.to_string(),
                            });
                        }
                    }
                }
                "respond" => {
                    let body = cursor.expect_word("respond body")?.kind_word();
                    directives.push(Directive::Respond(RespondConfig { body, status: 200 }));
                }
                other => {
                    return Err(FluxgateError::ConfigSyntax {
                        file: tok.file,
                        line: tok.line,
                        msg: format!("Unrecognized inner directive '{}'", other),
                    });
                }
            }
        }

        let tok = cursor.current().unwrap();
        Err(FluxgateError::ConfigSyntax {
            file: tok.file.clone(),
            line: tok.line,
            msg: "Unclosed block, expected '}'".to_string(),
        })
    }

    fn parse_reverse_proxy(
        &self,
        cursor: &mut TokenCursor,
        _tok: Token,
    ) -> Result<ReverseProxyConfig> {
        let upstream_str = cursor
            .expect_word("reverse_proxy upstream address")?
            .kind_word();
        let mut transport = TransportConfig::default();
        let upstream = if let Some(rest) = upstream_str.strip_prefix("unix+h2c/") {
            let abs = format!("/{}", rest.trim_start_matches('/'));
            transport.h2c = true;
            transport.versions = vec!["h2c".to_string(), "2".to_string()];
            UpstreamTarget::Uds(PathBuf::from(abs))
        } else if let Some(rest) = upstream_str.strip_prefix("unix/") {
            let abs = format!("/{}", rest.trim_start_matches('/'));
            UpstreamTarget::Uds(PathBuf::from(abs))
        } else if let Some(rest) = upstream_str.strip_prefix("unix:") {
            UpstreamTarget::Uds(PathBuf::from(rest))
        } else {
            UpstreamTarget::Tcp(upstream_str)
        };

        let mut flush_interval = -1;

        if cursor.peek_kind() == Some(&TokenKind::OpenBrace) {
            cursor.next(); // consume '{'
            while let Some(k) = cursor.peek_kind() {
                if *k == TokenKind::CloseBrace {
                    cursor.next();
                    break;
                }
                if *k == TokenKind::Newline {
                    cursor.next();
                    continue;
                }

                let sub_tok = cursor.next().unwrap();
                let sub_word = sub_tok.kind_word();
                match sub_word.as_str() {
                    "flush_interval" => {
                        let val = cursor.expect_word("flush_interval value")?.kind_word();
                        flush_interval = val.parse::<i32>().unwrap_or(-1);
                    }
                    "transport" => {
                        let proto_tok = cursor.expect_word("transport protocol (e.g. http)")?;
                        let proto = proto_tok.kind_word();
                        if proto != "http" {
                            return Err(FluxgateError::ConfigSyntax {
                                file: proto_tok.file,
                                line: proto_tok.line,
                                msg: format!(
                                    "Unsupported transport protocol '{}' (expected 'http')",
                                    proto
                                ),
                            });
                        }
                        cursor.expect(TokenKind::OpenBrace, "open brace '{' for transport")?;
                        while let Some(tk) = cursor.peek_kind() {
                            if *tk == TokenKind::CloseBrace {
                                cursor.next();
                                break;
                            }
                            if *tk == TokenKind::Newline {
                                cursor.next();
                                continue;
                            }
                            let t_tok = cursor.next().unwrap();
                            match t_tok.kind_word().as_str() {
                                "versions" => {
                                    while let Some(vk) = cursor.peek_kind() {
                                        if *vk == TokenKind::Newline || *vk == TokenKind::CloseBrace
                                        {
                                            break;
                                        }
                                        if let TokenKind::Word(ver) = vk {
                                            if ver == "h2c" {
                                                transport.h2c = true;
                                            }
                                            transport.versions.push(ver.clone());
                                            cursor.next();
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                "h2_stream_window_size" => {
                                    let val_tok =
                                        cursor.expect_word("h2_stream_window_size value")?;
                                    transport.h2_stream_window_size =
                                        parse_byte_size_u32(&val_tok)?;
                                }
                                "h2_connection_window_size" => {
                                    let val_tok =
                                        cursor.expect_word("h2_connection_window_size value")?;
                                    transport.h2_connection_window_size =
                                        parse_byte_size_u32(&val_tok)?;
                                }
                                "h2_ping_interval" | "h2_ping_interval_secs" => {
                                    let val_tok = cursor.expect_word("h2_ping_interval value")?;
                                    transport.h2_ping_interval_secs =
                                        parse_duration_secs(&val_tok)?;
                                }
                                "max_h2_streams" => {
                                    let val_tok = cursor.expect_word("max_h2_streams value")?;
                                    let raw = val_tok.kind_word();
                                    transport.max_h2_streams =
                                        raw.parse::<usize>().map_err(|_| {
                                            FluxgateError::ConfigSyntax {
                                                file: val_tok.file,
                                                line: val_tok.line,
                                                msg: format!(
                                                "Invalid max_h2_streams '{}' (expected integer)",
                                                raw
                                            ),
                                            }
                                        })?;
                                }
                                "read_timeout" | "read_timeout_secs" => {
                                    let val_tok = cursor.expect_word("read_timeout value")?;
                                    transport.read_timeout_secs = parse_duration_secs(&val_tok)?;
                                }
                                "idle_timeout" | "idle_timeout_secs" => {
                                    let val_tok = cursor.expect_word("idle_timeout value")?;
                                    transport.idle_timeout_secs = parse_duration_secs(&val_tok)?;
                                }
                                other => {
                                    return Err(FluxgateError::ConfigSyntax {
                                        file: t_tok.file,
                                        line: t_tok.line,
                                        msg: format!(
                                            "Unrecognized transport http sub-directive '{}'",
                                            other
                                        ),
                                    });
                                }
                            }
                        }
                    }
                    other => {
                        return Err(FluxgateError::ConfigSyntax {
                            file: sub_tok.file,
                            line: sub_tok.line,
                            msg: format!("Unrecognized reverse_proxy sub-directive '{}'", other),
                        });
                    }
                }
            }
        }

        Ok(ReverseProxyConfig {
            upstream,
            flush_interval,
            transport,
        })
    }

    fn parse_vault_block(&self, cursor: &mut TokenCursor, open_tok: &Token) -> Result<VaultConfig> {
        let mut addr = SecretRef::Env("VAULT_ADDR".to_string());
        let mut namespace = None;
        let mut auth = VaultAuthMode::AppRole;
        let mut ca_cert = None;
        let mut syncs = Vec::new();

        while let Some(kind) = cursor.peek_kind() {
            if *kind == TokenKind::CloseBrace {
                cursor.next();
                return Ok(VaultConfig {
                    addr,
                    namespace,
                    auth,
                    ca_cert,
                    syncs,
                });
            }
            if *kind == TokenKind::Newline {
                cursor.next();
                continue;
            }

            let sub_tok = cursor.next().unwrap();
            if !matches!(sub_tok.kind, TokenKind::Word(_)) {
                return Err(FluxgateError::ConfigSyntax {
                    file: sub_tok.file,
                    line: sub_tok.line,
                    msg: format!("Expected vault directive, found {:?}", sub_tok.kind),
                });
            }
            let sub_word = sub_tok.kind_word();
            match sub_word.as_str() {
                "addr" => {
                    let val = cursor.expect_word("vault addr")?.kind_word();
                    addr = parse_secret_ref(&val);
                }
                "namespace" => {
                    let val = cursor.expect_word("vault namespace")?.kind_word();
                    namespace = Some(parse_secret_ref(&val));
                }
                "auth" => {
                    let mode_tok = cursor.expect_word("vault auth mode (approle|token)")?;
                    match mode_tok.kind_word().to_ascii_lowercase().as_str() {
                        "approle" => auth = VaultAuthMode::AppRole,
                        "token" => auth = VaultAuthMode::Token,
                        other => {
                            return Err(FluxgateError::ConfigSyntax {
                                file: mode_tok.file,
                                line: mode_tok.line,
                                msg: format!(
                                    "Unsupported vault auth mode '{}': expected approle or token",
                                    other
                                ),
                            });
                        }
                    }
                }
                "ca_cert" => {
                    let path_tok = cursor.expect_word("vault ca_cert path")?;
                    ca_cert = Some(PathBuf::from(path_tok.kind_word()));
                }
                "sync" => {
                    let alias = cursor.expect_word("vault sync alias")?.kind_word();
                    let kv_path = cursor.expect_word("vault sync kv_path")?.kind_word();
                    let dur_tok = cursor.expect_word("vault sync interval (e.g. 5m, 30s, 1h)")?;
                    let interval_secs = parse_duration_secs(&dur_tok)?;
                    syncs.push(VaultSyncSpec {
                        alias,
                        kv_path,
                        interval_secs,
                    });
                }
                other => {
                    return Err(FluxgateError::ConfigSyntax {
                        file: sub_tok.file,
                        line: sub_tok.line,
                        msg: format!("Unrecognized vault directive '{}'", other),
                    });
                }
            }
        }

        Err(FluxgateError::ConfigSyntax {
            file: open_tok.file.clone(),
            line: open_tok.line,
            msg: "Unclosed vault block, expected '}'".to_string(),
        })
    }

    fn parse_tls_block(&self, cursor: &mut TokenCursor, open_tok: &Token) -> Result<AcmeTlsConfig> {
        let mut email = String::new();
        let mut ca_url = LETSENCRYPT_PROD_DIRECTORY.to_string();
        let mut dns_provider: Option<DnsProviderConfig> = None;
        let mut renew_before_days: u64 = 30;
        let mut storage_dir = PathBuf::from(DEFAULT_ACME_STORAGE_DIR);
        let mut vault_storage_path: Option<String> = None;

        while let Some(kind) = cursor.peek_kind() {
            if *kind == TokenKind::CloseBrace {
                cursor.next();
                let dns_provider = dns_provider.ok_or_else(|| FluxgateError::ConfigSyntax {
                    file: open_tok.file.clone(),
                    line: open_tok.line,
                    msg: "tls block requires a 'dns' provider directive".to_string(),
                })?;
                return Ok(AcmeTlsConfig {
                    email,
                    ca_url,
                    dns_provider,
                    renew_before_days,
                    storage_dir,
                    vault_storage_path,
                });
            }
            if *kind == TokenKind::Newline {
                cursor.next();
                continue;
            }

            let sub_tok = cursor.next().unwrap();
            if !matches!(sub_tok.kind, TokenKind::Word(_)) {
                return Err(FluxgateError::ConfigSyntax {
                    file: sub_tok.file,
                    line: sub_tok.line,
                    msg: format!("Expected tls directive, found {:?}", sub_tok.kind),
                });
            }
            let sub_word = sub_tok.kind_word();
            match sub_word.as_str() {
                "issuer" => {
                    let kind_tok = cursor.expect_word("TLS issuer type (acme)")?;
                    let kind_word = kind_tok.kind_word();
                    if kind_word != "acme" {
                        return Err(FluxgateError::ConfigSyntax {
                            file: kind_tok.file,
                            line: kind_tok.line,
                            msg: format!("Unsupported TLS issuer '{}', expected 'acme'", kind_word),
                        });
                    }
                    cursor.expect(TokenKind::OpenBrace, "open brace '{' for issuer acme")?;
                    self.parse_issuer_acme_block(cursor, &kind_tok, &mut email, &mut ca_url)?;
                }
                "dns" => {
                    let prov_tok = cursor.expect_word("DNS provider (cloudflare|alidns)")?;
                    match prov_tok.kind_word().to_ascii_lowercase().as_str() {
                        "cloudflare" => {
                            let tok_ref = cursor
                                .expect_word("Cloudflare API token reference")?
                                .kind_word();
                            dns_provider = Some(DnsProviderConfig::Cloudflare {
                                api_token: parse_secret_ref(&tok_ref),
                            });
                        }
                        "alidns" => {
                            let ak_ref = cursor
                                .expect_word("AliDNS access_key_id reference")?
                                .kind_word();
                            let sk_ref = cursor
                                .expect_word("AliDNS access_key_secret reference")?
                                .kind_word();
                            dns_provider = Some(DnsProviderConfig::AliDns {
                                access_key_id: parse_secret_ref(&ak_ref),
                                access_key_secret: parse_secret_ref(&sk_ref),
                            });
                        }
                        other => {
                            return Err(FluxgateError::ConfigSyntax {
                                file: prov_tok.file,
                                line: prov_tok.line,
                                msg: format!(
                                    "Unsupported DNS provider '{}': expected cloudflare or alidns",
                                    other
                                ),
                            });
                        }
                    }
                }
                "renew_before" => {
                    let dur_tok = cursor.expect_word("renew_before duration (e.g. 30d, 720h)")?;
                    renew_before_days = parse_renew_before_days(&dur_tok)?;
                }
                "storage" => {
                    let backend_tok = cursor.expect_word("tls storage backend (vault)")?;
                    match backend_tok.kind_word().as_str() {
                        "vault" => {
                            let kv_path = cursor
                                .expect_word("Vault KV path for certificate storage")?
                                .kind_word();
                            vault_storage_path = Some(kv_path);
                        }
                        other => {
                            return Err(FluxgateError::ConfigSyntax {
                                file: backend_tok.file,
                                line: backend_tok.line,
                                msg: format!(
                                    "Unsupported tls storage backend '{}', expected 'vault'",
                                    other
                                ),
                            });
                        }
                    }
                }
                "storage_dir" => {
                    let dir_tok = cursor.expect_word("ACME storage_dir path")?;
                    storage_dir = PathBuf::from(dir_tok.kind_word());
                }
                other => {
                    return Err(FluxgateError::ConfigSyntax {
                        file: sub_tok.file,
                        line: sub_tok.line,
                        msg: format!("Unrecognized tls directive '{}'", other),
                    });
                }
            }
        }

        Err(FluxgateError::ConfigSyntax {
            file: open_tok.file.clone(),
            line: open_tok.line,
            msg: "Unclosed tls block, expected '}'".to_string(),
        })
    }

    fn parse_issuer_acme_block(
        &self,
        cursor: &mut TokenCursor,
        open_tok: &Token,
        email: &mut String,
        ca_url: &mut String,
    ) -> Result<()> {
        while let Some(kind) = cursor.peek_kind() {
            if *kind == TokenKind::CloseBrace {
                cursor.next();
                return Ok(());
            }
            if *kind == TokenKind::Newline {
                cursor.next();
                continue;
            }

            let sub_tok = cursor.next().unwrap();
            if !matches!(sub_tok.kind, TokenKind::Word(_)) {
                return Err(FluxgateError::ConfigSyntax {
                    file: sub_tok.file,
                    line: sub_tok.line,
                    msg: format!("Expected issuer acme directive, found {:?}", sub_tok.kind),
                });
            }
            match sub_tok.kind_word().as_str() {
                "email" => {
                    *email = cursor.expect_word("ACME account email")?.kind_word();
                }
                "ca" => {
                    let ca_raw = cursor.expect_word("ACME CA directory")?.kind_word();
                    *ca_url = match ca_raw.as_str() {
                        "letsencrypt" => LETSENCRYPT_PROD_DIRECTORY.to_string(),
                        "letsencrypt-staging" => LETSENCRYPT_STAGING_DIRECTORY.to_string(),
                        custom => custom.to_string(),
                    };
                }
                other => {
                    return Err(FluxgateError::ConfigSyntax {
                        file: sub_tok.file,
                        line: sub_tok.line,
                        msg: format!("Unrecognized issuer acme directive '{}'", other),
                    });
                }
            }
        }

        Err(FluxgateError::ConfigSyntax {
            file: open_tok.file.clone(),
            line: open_tok.line,
            msg: "Unclosed issuer acme block, expected '}'".to_string(),
        })
    }
}

pub fn parse_secret_ref(s: &str) -> SecretRef {
    if let Some(inner) = s
        .strip_prefix("env(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return SecretRef::Env(inner.trim().to_string());
    }
    if let Some(inner) = s
        .strip_prefix("{env.")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return SecretRef::Env(inner.trim().to_string());
    }
    if let Some(inner) = s
        .strip_prefix("{vault.")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return if let Some((alias, key)) = inner.split_once('.') {
            SecretRef::Vault {
                alias: alias.to_string(),
                key: key.to_string(),
            }
        } else {
            SecretRef::Vault {
                alias: inner.to_string(),
                key: String::new(),
            }
        };
    }
    SecretRef::Literal(s.to_string())
}

fn parse_byte_size_u32(tok: &Token) -> Result<u32> {
    let raw = tok.kind_word();
    let lower = raw.to_ascii_lowercase();
    let (num_str, mult): (&str, u64) = if let Some(n) = lower.strip_suffix("mib") {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("mb") {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix('m') {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("kib") {
        (n, 1024)
    } else if let Some(n) = lower.strip_suffix("kb") {
        (n, 1024)
    } else if let Some(n) = lower.strip_suffix('k') {
        (n, 1024)
    } else if let Some(n) = lower.strip_suffix('b') {
        (n, 1)
    } else {
        (lower.as_str(), 1)
    };

    let val = num_str
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .and_then(|n| u32::try_from(n).ok());
    val.ok_or_else(|| FluxgateError::ConfigSyntax {
        file: tok.file.clone(),
        line: tok.line,
        msg: format!(
            "Invalid byte size '{}' (expected e.g. 4194304, 4MiB, 16m)",
            raw
        ),
    })
}

fn parse_duration_secs(tok: &Token) -> Result<u64> {
    let raw = tok.kind_word();
    let (num_str, mult) = if let Some(n) = raw.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = raw.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = raw.strip_suffix('h') {
        (n, 3600u64)
    } else {
        (raw.as_str(), 1u64)
    };

    let val = num_str
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult));
    val.ok_or_else(|| FluxgateError::ConfigSyntax {
        file: tok.file.clone(),
        line: tok.line,
        msg: format!("Invalid duration '{}' (expected e.g. 30s, 5m, 1h)", raw),
    })
}

fn parse_renew_before_days(tok: &Token) -> Result<u64> {
    let raw = tok.kind_word();
    if let Some(n) = raw.strip_suffix('d') {
        if let Ok(days) = n.parse::<u64>() {
            return Ok(days);
        }
    } else if let Some(n) = raw.strip_suffix('h') {
        if let Ok(hours) = n.parse::<u64>() {
            return Ok(if hours == 0 {
                0
            } else {
                hours.saturating_add(23) / 24
            });
        }
    }
    Err(FluxgateError::ConfigSyntax {
        file: tok.file.clone(),
        line: tok.line,
        msg: format!(
            "Invalid renew_before duration '{}' (expected <N>d or <N>h)",
            raw
        ),
    })
}

pub struct TokenCursor {
    tokens: Vec<Token>,
    index: usize,
}

impl TokenCursor {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, index: 0 }
    }

    pub fn current(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    pub fn peek_kind(&self) -> Option<&TokenKind> {
        self.tokens.get(self.index).map(|t| &t.kind)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Token> {
        if self.index < self.tokens.len() {
            let tok = self.tokens[self.index].clone();
            self.index += 1;
            Some(tok)
        } else {
            None
        }
    }

    pub fn is_eof(&self) -> bool {
        self.index >= self.tokens.len()
    }

    pub fn skip_newlines(&mut self) {
        while let Some(TokenKind::Newline) = self.peek_kind() {
            self.index += 1;
        }
    }

    pub fn expect(&mut self, expected: TokenKind, desc: &str) -> Result<Token> {
        self.skip_newlines();
        if let Some(tok) = self.next() {
            if tok.kind == expected {
                return Ok(tok);
            }
            return Err(FluxgateError::ConfigSyntax {
                file: tok.file,
                line: tok.line,
                msg: format!("Expected {}, found {:?}", desc, tok.kind),
            });
        }
        Err(FluxgateError::ConfigSyntax {
            file: PathBuf::from("config"),
            line: 0,
            msg: format!("Unexpected EOF, expected {}", desc),
        })
    }

    pub fn expect_word(&mut self, desc: &str) -> Result<Token> {
        self.skip_newlines();
        if let Some(tok) = self.next() {
            if matches!(tok.kind, TokenKind::Word(_)) {
                return Ok(tok);
            }
            return Err(FluxgateError::ConfigSyntax {
                file: tok.file,
                line: tok.line,
                msg: format!("Expected {}, found {:?}", desc, tok.kind),
            });
        }
        Err(FluxgateError::ConfigSyntax {
            file: PathBuf::from("config"),
            line: 0,
            msg: format!("Unexpected EOF, expected {}", desc),
        })
    }
}

impl Token {
    pub fn kind_word(&self) -> String {
        match &self.kind {
            TokenKind::Word(w) => w.clone(),
            _ => String::new(),
        }
    }
}
