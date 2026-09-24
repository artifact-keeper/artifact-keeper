use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Information extracted from JetBrains plugin paths
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JetbrainsPathInfo {
    /// Plugin ID (optional)
    pub plugin_id: Option<String>,
    /// Plugin version (optional)
    pub version: Option<String>,
    /// Whether this is a repository index request
    pub is_index: bool,
    /// Whether this is a download request
    pub is_download: bool,
}

/// Handler for JetBrains plugins format
pub struct JetbrainsHandler;

impl JetbrainsHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a JetBrains plugin path
    ///
    /// Supports paths like:
    /// - `/plugins/<id>/updates` - plugin updates
    /// - `/plugins/<id>/versions/<version>` - version info
    /// - `/plugins/<id>/versions/<version>/download` - download
    /// - `/updatePlugins.xml` - repository index
    pub fn parse_path(path: &str) -> Result<JetbrainsPathInfo> {
        let path = path.trim_start_matches('/');

        // Check for repository index
        if path == "updatePlugins.xml" {
            return Ok(JetbrainsPathInfo {
                is_index: true,
                ..Default::default()
            });
        }

        // Parse plugins paths
        if path.starts_with("plugins/") {
            let parts: Vec<&str> = path.split('/').collect();

            if parts.len() < 2 {
                return Err(AppError::Validation(format!(
                    "Invalid JetBrains plugin path: {}",
                    path
                )));
            }

            let plugin_id = parts[1].to_string();

            // Handle /plugins/<id>/updates
            if parts.len() == 3 && parts[2] == "updates" {
                return Ok(JetbrainsPathInfo {
                    plugin_id: Some(plugin_id),
                    ..Default::default()
                });
            }

            // Handle /plugins/<id>/versions/<version> or /plugins/<id>/versions/<version>/download
            if parts.len() >= 4 && parts[2] == "versions" {
                let version = parts[3].to_string();
                let is_download = parts.len() > 4 && parts[4] == "download";

                return Ok(JetbrainsPathInfo {
                    plugin_id: Some(plugin_id),
                    version: Some(version),
                    is_download,
                    ..Default::default()
                });
            }

            return Err(AppError::Validation(format!(
                "Invalid JetBrains plugin path: {}",
                path
            )));
        }

        Err(AppError::Validation(format!(
            "Invalid JetBrains plugin path: {}",
            path
        )))
    }
}

impl Default for JetbrainsHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for JetbrainsHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Jetbrains
    }

    fn format_key(&self) -> &str {
        "jetbrains"
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
    fn test_parse_plugin_updates() {
        let path = "/plugins/com.example.plugin/updates";
        let info = JetbrainsHandler::parse_path(path).expect("Failed to parse path");

        assert_eq!(info.plugin_id, Some("com.example.plugin".to_string()));
        assert_eq!(info.version, None);
        assert!(!info.is_download);
        assert!(!info.is_index);
    }

    #[test]
    fn test_parse_plugin_version_info() {
        let path = "/plugins/com.example.plugin/versions/1.0.0";
        let info = JetbrainsHandler::parse_path(path).expect("Failed to parse path");

        assert_eq!(info.plugin_id, Some("com.example.plugin".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert!(!info.is_download);
        assert!(!info.is_index);
    }

    #[test]
    fn test_parse_plugin_download() {
        let path = "/plugins/com.example.plugin/versions/1.0.0/download";
        let info = JetbrainsHandler::parse_path(path).expect("Failed to parse path");

        assert_eq!(info.plugin_id, Some("com.example.plugin".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert!(info.is_download);
        assert!(!info.is_index);
    }

    #[test]
    fn test_parse_repository_index() {
        let path = "/updatePlugins.xml";
        let info = JetbrainsHandler::parse_path(path).expect("Failed to parse path");

        assert!(info.is_index);
        assert!(!info.is_download);
        assert_eq!(info.plugin_id, None);
        assert_eq!(info.version, None);
    }

    #[test]
    fn test_parse_plugin_invalid_structure() {
        let path = "/plugins/invalid";
        let result = JetbrainsHandler::parse_path(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_plugin_invalid_versions_path() {
        let path = "/plugins/com.example.plugin/versions";
        let result = JetbrainsHandler::parse_path(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_plugin_invalid_root() {
        let path = "/invalid/com.example.plugin/versions/1.0.0";
        let result = JetbrainsHandler::parse_path(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_format_key() {
        let handler = JetbrainsHandler::new();
        assert_eq!(handler.format_key(), "jetbrains");
    }

    #[test]
    fn test_format() {
        let handler = JetbrainsHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Jetbrains);
    }
}
