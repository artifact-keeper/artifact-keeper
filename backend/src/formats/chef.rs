use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Chef configuration management path information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChefPathInfo {
    pub name: String,
    pub version: Option<String>,
    pub is_api: bool,
}

/// Chef cookbook package handler
pub struct ChefHandler;

impl ChefHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Chef paths like:
    /// - API: `api/v1/cookbooks/<name>/versions/<version>`
    /// - Archive: `cookbooks/<name>-<version>.tar.gz`
    pub fn parse_path(path: &str) -> Result<ChefPathInfo> {
        // Try API path first: api/v1/cookbooks/<name>/versions/<version>
        if path.starts_with("api/v1/cookbooks/") {
            let remainder = path
                .strip_prefix("api/v1/cookbooks/")
                .ok_or_else(|| AppError::Validation(format!("Invalid Chef API path: {}", path)))?;

            let parts: Vec<&str> = remainder.split('/').collect();

            if parts.len() == 3 && parts[1] == "versions" {
                let name = parts[0].to_string();
                let version = parts[2].to_string();

                return Ok(ChefPathInfo {
                    name,
                    version: Some(version),
                    is_api: true,
                });
            }

            if parts.len() == 1 {
                let name = parts[0].to_string();

                return Ok(ChefPathInfo {
                    name,
                    version: None,
                    is_api: true,
                });
            }

            return Err(AppError::Validation(format!(
                "Invalid Chef API path format: {}",
                path
            )));
        }

        // Try archive path: cookbooks/<name>-<version>.tar.gz
        if path.starts_with("cookbooks/") {
            let filename = path.strip_prefix("cookbooks/").ok_or_else(|| {
                AppError::Validation(format!("Invalid Chef archive path: {}", path))
            })?;

            if !filename.ends_with(".tar.gz") {
                return Err(AppError::Validation(format!(
                    "Invalid Chef archive extension: {}",
                    path
                )));
            }

            let name_version = filename.strip_suffix(".tar.gz").ok_or_else(|| {
                AppError::Validation(format!("Invalid Chef archive path: {}", path))
            })?;

            // Split on the last hyphen to separate name from version
            if let Some(last_hyphen) = name_version.rfind('-') {
                let name = name_version[..last_hyphen].to_string();
                let version = name_version[last_hyphen + 1..].to_string();

                return Ok(ChefPathInfo {
                    name,
                    version: Some(version),
                    is_api: false,
                });
            }

            return Err(AppError::Validation(format!(
                "Invalid Chef archive name format: {}",
                path
            )));
        }

        Err(AppError::Validation(format!(
            "Unrecognized Chef path format: {}",
            path
        )))
    }
}

impl Default for ChefHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for ChefHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Chef
    }

    fn format_key(&self) -> &str {
        "chef"
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
    fn test_parse_api_path_with_version() {
        let path = "api/v1/cookbooks/nginx/versions/1.0.0";
        let info = ChefHandler::parse_path(path).expect("Should parse API path with version");

        assert_eq!(info.name, "nginx");
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert!(info.is_api);
    }

    #[test]
    fn test_parse_api_path_without_version() {
        let path = "api/v1/cookbooks/nginx";
        let info = ChefHandler::parse_path(path).expect("Should parse API path without version");

        assert_eq!(info.name, "nginx");
        assert_eq!(info.version, None);
        assert!(info.is_api);
    }

    #[test]
    fn test_parse_archive_path() {
        let path = "cookbooks/nginx-1.0.0.tar.gz";
        let info = ChefHandler::parse_path(path).expect("Should parse archive path");

        assert_eq!(info.name, "nginx");
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert!(!info.is_api);
    }

    #[test]
    fn test_parse_archive_path_with_hyphenated_name() {
        let path = "cookbooks/chef-client-5.2.1.tar.gz";
        let info =
            ChefHandler::parse_path(path).expect("Should parse archive path with hyphenated name");

        assert_eq!(info.name, "chef-client");
        assert_eq!(info.version, Some("5.2.1".to_string()));
        assert!(!info.is_api);
    }

    #[test]
    fn test_invalid_path() {
        let path = "invalid/path";
        assert!(ChefHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_invalid_archive_extension() {
        let path = "cookbooks/nginx-1.0.0.zip";
        assert!(ChefHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_handler_format() {
        let handler = ChefHandler::new();
        assert_eq!(handler.format_key(), "chef");
    }
}
