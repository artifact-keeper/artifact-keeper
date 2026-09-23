use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Information extracted from VS Code extension paths
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VscodePathInfo {
    /// Extension publisher name (optional)
    pub publisher: Option<String>,
    /// Extension name (optional)
    pub name: Option<String>,
    /// Extension version (optional)
    pub version: Option<String>,
    /// Whether this is a marketplace API query
    pub is_query: bool,
    /// Whether this is a download request
    pub is_download: bool,
}

/// Handler for VS Code extensions format
pub struct VscodeHandler;

impl VscodeHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a VS Code extension path
    ///
    /// Supports paths like:
    /// - `/extensions/publisher/name/version` - extension info
    /// - `/extensions/publisher/name/version/download` - VSIX download
    /// - `/extensionquery` - marketplace API query
    pub fn parse_path(path: &str) -> Result<VscodePathInfo> {
        let path = path.trim_start_matches('/');

        // Check for extensionquery API endpoint
        if path == "extensionquery" {
            return Ok(VscodePathInfo {
                is_query: true,
                ..Default::default()
            });
        }

        // Parse extensions paths: extensions/publisher/name/version[/download]
        if path.starts_with("extensions/") {
            let parts: Vec<&str> = path.split('/').collect();

            let is_download = parts.len() > 4 && parts[4] == "download";
            let expected_len = if is_download { 5 } else { 4 };

            if parts.len() < expected_len {
                return Err(AppError::Validation(format!(
                    "Invalid VS Code extension path: {}",
                    path
                )));
            }

            return Ok(VscodePathInfo {
                publisher: Some(parts[1].to_string()),
                name: Some(parts[2].to_string()),
                version: Some(parts[3].to_string()),
                is_download,
                ..Default::default()
            });
        }

        Err(AppError::Validation(format!(
            "Invalid VS Code extension path: {}",
            path
        )))
    }
}

impl Default for VscodeHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for VscodeHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Vscode
    }

    fn format_key(&self) -> &str {
        "vscode"
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
    fn test_parse_extension_info() {
        let path = "/extensions/ms-vscode/cpptools/1.14.0";
        let info = VscodeHandler::parse_path(path).expect("Failed to parse path");

        assert_eq!(info.publisher, Some("ms-vscode".to_string()));
        assert_eq!(info.name, Some("cpptools".to_string()));
        assert_eq!(info.version, Some("1.14.0".to_string()));
        assert!(!info.is_download);
        assert!(!info.is_query);
    }

    #[test]
    fn test_parse_extension_download() {
        let path = "/extensions/ms-vscode/cpptools/1.14.0/download";
        let info = VscodeHandler::parse_path(path).expect("Failed to parse path");

        assert_eq!(info.publisher, Some("ms-vscode".to_string()));
        assert_eq!(info.name, Some("cpptools".to_string()));
        assert_eq!(info.version, Some("1.14.0".to_string()));
        assert!(info.is_download);
        assert!(!info.is_query);
    }

    #[test]
    fn test_parse_extension_query() {
        let path = "/extensionquery";
        let info = VscodeHandler::parse_path(path).expect("Failed to parse path");

        assert!(info.is_query);
        assert!(!info.is_download);
        assert_eq!(info.publisher, None);
        assert_eq!(info.name, None);
        assert_eq!(info.version, None);
    }

    #[test]
    fn test_parse_extension_invalid_path() {
        let path = "/extensions/invalid";
        let result = VscodeHandler::parse_path(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_extension_invalid_root() {
        let path = "/invalid/ms-vscode/cpptools/1.14.0";
        let result = VscodeHandler::parse_path(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_format_key() {
        let handler = VscodeHandler::new();
        assert_eq!(handler.format_key(), "vscode");
    }

    #[test]
    fn test_format() {
        let handler = VscodeHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Vscode);
    }
}
