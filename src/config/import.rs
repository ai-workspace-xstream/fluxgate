use crate::error::{FluxgateError, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const MAX_IMPORT_DEPTH: usize = 16;

#[derive(Debug, Default)]
pub struct ImportTracker {
    visited: HashSet<PathBuf>,
}

impl ImportTracker {
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
        }
    }

    pub fn enter_file(&mut self, path: &Path, depth: usize) -> Result<PathBuf> {
        if depth > MAX_IMPORT_DEPTH {
            return Err(FluxgateError::ImportError {
                path: path.to_path_buf(),
                depth,
            });
        }

        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Failed to resolve path {}: {}",
                    path.display(),
                    e
                )));
            }
        };

        if !self.visited.insert(canonical.clone()) {
            return Err(FluxgateError::ImportError {
                path: canonical,
                depth,
            });
        }

        Ok(canonical)
    }

    pub fn leave_file(&mut self, canonical: &Path) {
        self.visited.remove(canonical);
    }
}

pub fn resolve_imports(base_file: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    let base_dir = base_file.parent().unwrap_or_else(|| Path::new("."));
    let full_pattern = if Path::new(pattern).is_absolute() {
        pattern.to_string()
    } else {
        base_dir.join(pattern).to_string_lossy().to_string()
    };

    let mut matches = Vec::new();
    let entries = glob::glob(&full_pattern).map_err(|e| {
        FluxgateError::ConfigValidation(format!("Invalid import glob pattern {}: {}", pattern, e))
    })?;

    for entry in entries {
        match entry {
            Ok(path) => {
                if path.is_file() {
                    matches.push(path);
                }
            }
            Err(e) => {
                return Err(FluxgateError::ConfigValidation(format!(
                    "Failed to read glob entry for {}: {}",
                    pattern, e
                )));
            }
        }
    }

    // Deterministic alphabetical sorting
    matches.sort();

    Ok(matches)
}
