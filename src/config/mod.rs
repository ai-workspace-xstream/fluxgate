pub mod ast;
pub mod import;
pub mod lexer;
pub mod parser;
pub mod validate;

pub use ast::*;
pub use parser::{parse_secret_ref, Parser};
pub use validate::{validate_config, validate_config_with_options, ValidateOptions};

use crate::error::Result;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn load_config(path: &Path) -> Result<FluxgateConfig> {
    load_config_with_options(path, ValidateOptions::default())
}

pub fn load_config_with_options(path: &Path, opts: ValidateOptions) -> Result<FluxgateConfig> {
    let mut parser = Parser::new();
    let config = parser.parse_file(path)?;
    validate_config_with_options(&config, opts)?;
    Ok(config)
}

pub fn compute_config_hash(config: &FluxgateConfig) -> String {
    let repr = format!("{:#?}", config);
    let digest = Sha256::digest(repr.as_bytes());
    hex::encode(digest)
}
