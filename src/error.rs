use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FluxgateError {
    #[error("Configuration error in {file}:{line} - {msg}")]
    ConfigSyntax {
        file: PathBuf,
        line: usize,
        msg: String,
    },

    #[error("Configuration validation error: {0}")]
    ConfigValidation(String),

    #[error("Circular or invalid import detected: {path} (depth: {depth})")]
    ImportError { path: PathBuf, depth: usize },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Pingora error: {0}")]
    Pingora(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Generic error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, FluxgateError>;
