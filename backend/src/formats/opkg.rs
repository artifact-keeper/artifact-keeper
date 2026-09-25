use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Opkg (Lightweight package manager) format handler
pub struct OpkgHandler;

/// Information extracted from an Opkg repository path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpkgPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub arch: Option<String>,
    pub is_index: bool,
}

impl OpkgHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse an Opkg repository path and extract metadata
    pub fn parse_path(path: &str) -> Result<OpkgPathInfo> {
        let path = path.trim_start_matches('/');

        // Check for index files: Packages or Packages.gz
        if path == "Packages" || path == "Packages.gz" {
            return Ok(OpkgPathInfo {
                name: None,
                version: None,
                arch: None,
                is_index: true,
            });
        }

        // Check for package file: <name>_<version>_<arch>.ipk
        if path.ends_with(".ipk") {
            let filename = path;
            let basename = filename.strip_suffix(".ipk").unwrap();

            let parts: Vec<&str> = basename.split('_').collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                let arch = parts[2..].join("_");

                return Ok(OpkgPathInfo {
                    name: Some(name),
                    version: Some(version),
                    arch: Some(arch),
                    is_index: false,
                });
            }
        }

        Err(AppError::Validation(format!(
            "Invalid Opkg path format: {}",
            path
        )))
    }
}

impl Default for OpkgHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for OpkgHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Opkg
    }

    fn format_key(&self) -> &str {
        "opkg"
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

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_packages_index() {
        let result = OpkgHandler::parse_path("Packages").unwrap();
        assert!(result.is_index);
        assert_eq!(result.name, None);
        assert_eq!(result.version, None);
        assert_eq!(result.arch, None);
    }

    #[test]
    fn test_parse_packages_gz_index() {
        let result = OpkgHandler::parse_path("Packages.gz").unwrap();
        assert!(result.is_index);
    }

    #[test]
    fn test_parse_simple_package() {
        let result = OpkgHandler::parse_path("openssh_7.4p1_amd64.ipk").unwrap();
        assert!(!result.is_index);
        assert_eq!(result.name, Some("openssh".to_string()));
        assert_eq!(result.version, Some("7.4p1".to_string()));
        assert_eq!(result.arch, Some("amd64".to_string()));
    }

    #[test]
    fn test_parse_complex_package() {
        let result = OpkgHandler::parse_path("libc6_2.27_armv7l_cortex_a9.ipk").unwrap();
        assert!(!result.is_index);
        assert_eq!(result.name, Some("libc6".to_string()));
        assert_eq!(result.version, Some("2.27".to_string()));
        assert_eq!(result.arch, Some("armv7l_cortex_a9".to_string()));
    }

    #[test]
    fn test_parse_arm_package() {
        let result = OpkgHandler::parse_path("curl_7.64.1_arm_cortex_a9.ipk").unwrap();
        assert_eq!(result.name, Some("curl".to_string()));
        assert_eq!(result.version, Some("7.64.1".to_string()));
        assert_eq!(result.arch, Some("arm_cortex_a9".to_string()));
    }

    #[test]
    fn test_invalid_without_ipk_extension() {
        assert!(OpkgHandler::parse_path("openssh_7.4p1_amd64").is_err());
    }

    #[test]
    fn test_invalid_path() {
        assert!(OpkgHandler::parse_path("invalid/path").is_err());
    }

    #[test]
    fn test_format_handler() {
        let handler = OpkgHandler::new();
        assert_eq!(handler.format_key(), "opkg");
        assert_eq!(handler.format(), RepositoryFormat::Opkg);
    }
}
