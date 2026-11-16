pub mod ast;
pub mod import;
pub mod lexer;
pub mod parser;
pub mod validate;

pub use ast::*;
pub use parser::Parser;
pub use validate::validate_config;

use crate::error::Result;
use std::path::Path;

pub fn load_config(path: &Path) -> Result<FluxgateConfig> {
    let mut parser = Parser::new();
    let config = parser.parse_file(path)?;
    validate_config(&config)?;
    Ok(config)
}
