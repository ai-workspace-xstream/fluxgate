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
                    tokens.push(Token {
                        kind: TokenKind::OpenBrace,
                        line: self.line,
                        file: self.file.clone(),
                    });
                    self.chars.next();
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
            if ch.is_whitespace() || ch == '{' || ch == '}' || ch == '#' {
                break;
            }
            buf.push(ch);
            self.chars.next();
        }
        buf
    }
}
