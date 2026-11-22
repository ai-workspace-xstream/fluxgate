use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    Word(String),
    OpenBrace,
    CloseBrace,
    Newline,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub file: PathBuf,
}

pub struct Lexer<'a> {
    file: PathBuf,
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    line: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(file: &Path, input: &'a str) -> Self {
        Self {
            file: file.to_path_buf(),
            chars: input.chars().peekable(),
            line: 1,
        }
    }

    pub fn tokenize(mut self) -> Vec<Token> {
        let mut tokens = Vec::new();

        while let Some(&ch) = self.chars.peek() {
            match ch {
                ' ' | '\t' | '\r' => {
                    self.chars.next();
                }
                '\n' => {
                    tokens.push(Token {
                        kind: TokenKind::Newline,
                        line: self.line,
                        file: self.file.clone(),
                    });
                    self.line += 1;
                    self.chars.next();
                }
                '#' => {
                    // Comment until end of line
                    while let Some(&c) = self.chars.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.chars.next();
                    }
                }
                '{' => {
                    if let Some(placeholder) = self.try_read_placeholder() {
                        tokens.push(Token {
                            kind: TokenKind::Word(placeholder),
                            line: self.line,
                            file: self.file.clone(),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::OpenBrace,
                            line: self.line,
                            file: self.file.clone(),
                        });
                        self.chars.next();
                    }
                }
                '}' => {
                    tokens.push(Token {
                        kind: TokenKind::CloseBrace,
                        line: self.line,
                        file: self.file.clone(),
                    });
                    self.chars.next();
                }
                '"' => {
                    let word = self.read_quoted_string();
                    tokens.push(Token {
                        kind: TokenKind::Word(word),
                        line: self.line,
                        file: self.file.clone(),
                    });
                }
                _ => {
                    let word = self.read_word();
                    if !word.is_empty() {
                        tokens.push(Token {
                            kind: TokenKind::Word(word),
                            line: self.line,
                            file: self.file.clone(),
                        });
                    }
                }
            }
        }

        tokens
    }

    /// Attempt to read an inline placeholder like `{vault.dns.cf_api_token}` or `{env.VAULT_ADDR}`.
    /// Only matches if `{` is immediately followed by non-whitespace, non-`{`, non-`}`, non-`#`
    /// characters containing at least one `.` and closed by `}` on the same line.
    fn try_read_placeholder(&mut self) -> Option<String> {
        let mut lookahead = self.chars.clone();
        if lookahead.next()? != '{' {
            return None;
        }

        let mut buf = String::from("{");
        let mut consumed = 1usize;
        let mut inner_len = 0usize;
        let mut has_dot = false;
        let mut closed = false;

        for ch in lookahead {
            if ch == '}' {
                buf.push('}');
                consumed += 1;
                closed = true;
                break;
            }
            if ch.is_whitespace() || ch == '{' || ch == '#' {
                return None;
            }
            if ch == '.' {
                has_dot = true;
            }
            inner_len += 1;
            consumed += 1;
            buf.push(ch);
        }

        if closed && inner_len > 0 && has_dot {
            for _ in 0..consumed {
                self.chars.next();
            }
            Some(buf)
        } else {
            None
        }
    }

    fn read_quoted_string(&mut self) -> String {
        self.chars.next(); // consume leading quote
        let mut buf = String::new();
        while let Some(ch) = self.chars.next() {
            if ch == '"' {
                break;
            }
            if ch == '\\' {
                if let Some(next_ch) = self.chars.next() {
                    match next_ch {
                        'n' => buf.push('\n'),
                        't' => buf.push('\t'),
                        'r' => buf.push('\r'),
                        '\\' => buf.push('\\'),
                        '"' => buf.push('"'),
                        other => {
                            buf.push('\\');
                            buf.push(other);
                        }
                    }
                    continue;
                }
            }
            if ch == '\n' {
                self.line += 1;
            }
            buf.push(ch);
        }
        buf
    }

    fn read_word(&mut self) -> String {
        let mut buf = String::new();
        while let Some(&ch) = self.chars.peek() {
            if ch.is_whitespace() || ch == '}' || ch == '#' {
                break;
            }
            if ch == '{' {
                if let Some(placeholder) = self.try_read_placeholder() {
                    buf.push_str(&placeholder);
                    continue;
                }
                break;
            }
            buf.push(ch);
            self.chars.next();
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexer_placeholders_and_braces() {
        let input = r#"
{
    vault {
        addr {env.VAULT_ADDR}
        sync dns kv/data/prod/dns 5m
    }
}

*.svc.plus {
    tls {
        dns cloudflare {vault.dns.cf_api_token}
    }
}
"#;
        let tokens = Lexer::new(Path::new("test.conf"), input).tokenize();
        let kinds: Vec<TokenKind> = tokens
            .into_iter()
            .filter(|t| t.kind != TokenKind::Newline)
            .map(|t| t.kind)
            .collect();

        assert_eq!(
            kinds,
            vec![
                TokenKind::OpenBrace,
                TokenKind::Word("vault".to_string()),
                TokenKind::OpenBrace,
                TokenKind::Word("addr".to_string()),
                TokenKind::Word("{env.VAULT_ADDR}".to_string()),
                TokenKind::Word("sync".to_string()),
                TokenKind::Word("dns".to_string()),
                TokenKind::Word("kv/data/prod/dns".to_string()),
                TokenKind::Word("5m".to_string()),
                TokenKind::CloseBrace,
                TokenKind::CloseBrace,
                TokenKind::Word("*.svc.plus".to_string()),
                TokenKind::OpenBrace,
                TokenKind::Word("tls".to_string()),
                TokenKind::OpenBrace,
                TokenKind::Word("dns".to_string()),
                TokenKind::Word("cloudflare".to_string()),
                TokenKind::Word("{vault.dns.cf_api_token}".to_string()),
                TokenKind::CloseBrace,
                TokenKind::CloseBrace,
            ]
        );
    }

    #[test]
    fn test_lexer_non_placeholder_braces() {
        let input = "site.svc.plus{respond \"ok\"}\n{ grace_period 15s }\n{foo}\n{unclosed.brace";
        let tokens = Lexer::new(Path::new("test2.conf"), input).tokenize();
        let kinds: Vec<TokenKind> = tokens
            .into_iter()
            .filter(|t| t.kind != TokenKind::Newline)
            .map(|t| t.kind)
            .collect();

        assert_eq!(
            kinds,
            vec![
                TokenKind::Word("site.svc.plus".to_string()),
                TokenKind::OpenBrace,
                TokenKind::Word("respond".to_string()),
                TokenKind::Word("ok".to_string()),
                TokenKind::CloseBrace,
                TokenKind::OpenBrace,
                TokenKind::Word("grace_period".to_string()),
                TokenKind::Word("15s".to_string()),
                TokenKind::CloseBrace,
                TokenKind::OpenBrace,
                TokenKind::Word("foo".to_string()),
                TokenKind::CloseBrace,
                TokenKind::OpenBrace,
                TokenKind::Word("unclosed.brace".to_string()),
            ]
        );
    }
}
