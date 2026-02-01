use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// CRAN (Comprehensive R Archive Network) repository format handler
pub struct CranHandler;

/// Information extracted from a CRAN repository path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CranPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub is_index: bool,
    pub is_binary: bool,
}

impl CranHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a CRAN repository path and extract metadata
    pub fn parse_path(path: &str) -> Result<CranPathInfo> {
        let path = path.trim_start_matches('/');

        // Check for index file: src/contrib/PACKAGES or src/contrib/PACKAGES.gz
        if path == "src/contrib/PACKAGES" || path == "src/contrib/PACKAGES.gz" {
            return Ok(CranPathInfo {
                name: None,
                version: None,
                is_index: true,
                is_binary: false,
            });
        }

        // Check for source package: src/contrib/<name>_<version>.tar.gz
        if path.starts_with("src/contrib/") && path.ends_with(".tar.gz") {
            let filename = path.strip_prefix("src/contrib/").unwrap();
            let basename = filename.strip_suffix(".tar.gz").unwrap();

            if let Some((name, version)) = basename.rsplit_once('_') {
                return Ok(CranPathInfo {
                    name: Some(name.to_string()),
                    version: Some(version.to_string()),
                    is_index: false,
                    is_binary: false,
                });
            }
        }

        // Check for binary package: bin/<platform>/contrib/<rversion>/<name>_<version>.<ext>
        if path.starts_with("bin/") {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 5
                && !parts[1].is_empty()
                && parts[2] == "contrib"
                && !parts[3].is_empty()
            {
                let filename = parts[4..].join("/");
                if let Some((name, rest)) = filename.rsplit_once('_') {
                    if let Some((version, _ext)) = rest.rsplit_once('.') {
                        return Ok(CranPathInfo {
                            name: Some(name.to_string()),
                            version: Some(version.to_string()),
                            is_index: false,
                            is_binary: true,
                        });
                    }
                }
            }
        }

        Err(AppError::Validation(format!(
            "Invalid CRAN path format: {}",
            path
        )))
    }
}

impl Default for CranHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for CranHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Cran
    }

    fn format_key(&self) -> &str {
        "cran"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;
        Ok(serde_json::to_value(info).unwrap_or(serde_json::json!({})))
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_packages_index() {
        let result = CranHandler::parse_path("src/contrib/PACKAGES").unwrap();
        assert!(result.is_index);
        assert!(!result.is_binary);
        assert_eq!(result.name, None);
        assert_eq!(result.version, None);
    }

    #[test]
    fn test_parse_packages_gz_index() {
        let result = CranHandler::parse_path("src/contrib/PACKAGES.gz").unwrap();
        assert!(result.is_index);
        assert!(!result.is_binary);
    }

    #[test]
    fn test_parse_source_package() {
        let result = CranHandler::parse_path("src/contrib/mypackage_1.0.0.tar.gz").unwrap();
        assert!(!result.is_index);
        assert!(!result.is_binary);
        assert_eq!(result.name, Some("mypackage".to_string()));
        assert_eq!(result.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_parse_binary_package() {
        let result =
            CranHandler::parse_path("bin/windows/contrib/4.0/mypackage_1.0.0.zip").unwrap();
        assert!(!result.is_index);
        assert!(result.is_binary);
        assert_eq!(result.name, Some("mypackage".to_string()));
        assert_eq!(result.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_parse_macos_binary() {
        let result = CranHandler::parse_path("bin/macosx/contrib/4.2/mypkg_2.5.1.tgz").unwrap();
        assert!(result.is_binary);
        assert_eq!(result.name, Some("mypkg".to_string()));
    }

    #[test]
    fn test_invalid_path() {
        assert!(CranHandler::parse_path("invalid/path").is_err());
    }

    #[test]
    fn test_format_handler() {
        let handler = CranHandler::new();
        assert_eq!(handler.format_key(), "cran");
        assert_eq!(handler.format(), RepositoryFormat::Cran);
    }
}
