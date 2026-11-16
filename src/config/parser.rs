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
                    let matched_files = resolve_imports(&canonical, &pattern_token.kind_word())?;
                    if matched_files.is_empty() && !pattern_token.kind_word().contains('*') {
                        return Err(FluxgateError::ConfigSyntax {
                            file: pattern_token.file,
                            line: pattern_token.line,
                            msg: format!("Imported file '{}' not found", pattern_token.kind_word()),
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
                let tok = cursor.current().unwrap_or(&Token {
                    kind: TokenKind::Newline,
                    line: 1,
                    file: path.to_path_buf(),
                });
                return Err(FluxgateError::ConfigSyntax {
                    file: tok.file.clone(),
                    line: tok.line,
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
                    // optional block or single token
                    if cursor.peek_kind() == Some(&TokenKind::OpenBrace) {
                        cursor.next();
                        while let Some(k) = cursor.peek_kind() {
                            if *k == TokenKind::CloseBrace {
                                cursor.next();
                                break;
                            }
                            cursor.next();
                        }
                    }
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
                    let cert = cursor.expect_word("TLS certificate path")?;
                    let key = cursor.expect_word("TLS private key path")?;
                    tls = Some(TlsConfig {
                        cert_path: PathBuf::from(cert.kind_word()),
                        key_path: PathBuf::from(key.kind_word()),
                    });
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
        tok: Token,
    ) -> Result<ReverseProxyConfig> {
        let upstream_str = cursor
            .expect_word("reverse_proxy upstream address")?
            .kind_word();
        let upstream = if let Some(rest) = upstream_str.strip_prefix("unix/") {
            let abs = format!("/{}", rest.trim_start_matches('/'));
            UpstreamTarget::Uds(PathBuf::from(abs))
        } else if let Some(rest) = upstream_str.strip_prefix("unix:") {
            UpstreamTarget::Uds(PathBuf::from(rest))
        } else {
            UpstreamTarget::Tcp(upstream_str)
        };

        let mut flush_interval = -1;
        let mut transport = TransportConfig::default();

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
                        let proto = cursor
                            .expect_word("transport protocol (e.g. http)")?
                            .kind_word();
                        if proto == "http" {
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
                                if t_tok.kind_word() == "versions" {
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
