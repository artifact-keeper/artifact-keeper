use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Bazel module repository format handler
pub struct BazelHandler;

/// Information extracted from a Bazel repository path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BazelPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub filename: Option<String>,
    pub is_index: bool,
}

impl BazelHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Bazel repository path and extract metadata
    pub fn parse_path(path: &str) -> Result<BazelPathInfo> {
        let path = path.trim_start_matches('/');

        // Registry index: bazel_registry.json
        if path == "bazel_registry.json" {
            return Ok(BazelPathInfo {
                name: None,
                version: None,
                filename: None,
                is_index: true,
            });
        }

        // Module descriptor: modules/<name>/<version>/MODULE.bazel
        if path.starts_with("modules/") && path.ends_with("/MODULE.bazel") {
            let trimmed = path.strip_prefix("modules/").unwrap();
            let trimmed = trimmed.strip_suffix("/MODULE.bazel").unwrap();

            let parts: Vec<&str> = trimmed.split('/').collect();
            if parts.len() == 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();

                return Ok(BazelPathInfo {
                    name: Some(name),
                    version: Some(version),
                    filename: Some("MODULE.bazel".to_string()),
                    is_index: false,
                });
            }
        }

        // Source info: modules/<name>/<version>/source.json
        if path.starts_with("modules/") && path.ends_with("/source.json") {
            let trimmed = path.strip_prefix("modules/").unwrap();
            let trimmed = trimmed.strip_suffix("/source.json").unwrap();

            let parts: Vec<&str> = trimmed.split('/').collect();
            if parts.len() == 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();

                return Ok(BazelPathInfo {
                    name: Some(name),
                    version: Some(version),
                    filename: Some("source.json".to_string()),
                    is_index: false,
                });
            }
        }

        // Module files: modules/<name>/<version>/<filename>
        if path.starts_with("modules/") {
            let trimmed = path.strip_prefix("modules/").unwrap();
            let parts: Vec<&str> = trimmed.split('/').collect();

            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                let filename = parts[2..].join("/");

                // Skip MODULE.bazel and source.json as they are handled above
                if filename != "MODULE.bazel" && filename != "source.json" {
                    return Ok(BazelPathInfo {
                        name: Some(name),
                        version: Some(version),
                        filename: Some(filename),
                        is_index: false,
                    });
                }
            }
        }

        Err(AppError::Validation(format!(
            "Invalid Bazel path format: {}",
            path
        )))
    }
}

impl Default for BazelHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for BazelHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Bazel
    }

    fn format_key(&self) -> &str {
        "bazel"
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
    fn test_parse_registry_index() {
        let result = BazelHandler::parse_path("bazel_registry.json").unwrap();
        assert!(result.is_index);
        assert_eq!(result.name, None);
        assert_eq!(result.version, None);
        assert_eq!(result.filename, None);
    }

    #[test]
    fn test_parse_module_descriptor() {
        let result = BazelHandler::parse_path("modules/protobuf/6.0.0/MODULE.bazel").unwrap();
        assert!(!result.is_index);
        assert_eq!(result.name, Some("protobuf".to_string()));
        assert_eq!(result.version, Some("6.0.0".to_string()));
        assert_eq!(result.filename, Some("MODULE.bazel".to_string()));
    }

    #[test]
    fn test_parse_source_info() {
        let result = BazelHandler::parse_path("modules/rules_cc/0.8.0/source.json").unwrap();
        assert!(!result.is_index);
        assert_eq!(result.name, Some("rules_cc".to_string()));
        assert_eq!(result.version, Some("0.8.0".to_string()));
        assert_eq!(result.filename, Some("source.json".to_string()));
    }

    #[test]
    fn test_parse_module_file() {
        let result = BazelHandler::parse_path("modules/rules_java/6.4.0/rules.jar").unwrap();
        assert!(!result.is_index);
        assert_eq!(result.name, Some("rules_java".to_string()));
        assert_eq!(result.version, Some("6.4.0".to_string()));
        assert_eq!(result.filename, Some("rules.jar".to_string()));
    }

    #[test]
    fn test_parse_nested_module_file() {
        let result = BazelHandler::parse_path("modules/skylib/1.3.0/lib/paths.bzl").unwrap();
        assert!(!result.is_index);
        assert_eq!(result.name, Some("skylib".to_string()));
        assert_eq!(result.version, Some("1.3.0".to_string()));
        assert_eq!(result.filename, Some("lib/paths.bzl".to_string()));
    }

    #[test]
    fn test_parse_with_slash_prefix() {
        let result = BazelHandler::parse_path("/modules/protobuf/6.0.0/MODULE.bazel").unwrap();
        assert_eq!(result.name, Some("protobuf".to_string()));
        assert_eq!(result.version, Some("6.0.0".to_string()));
    }

    #[test]
    fn test_invalid_path() {
        assert!(BazelHandler::parse_path("invalid/path").is_err());
    }

    #[test]
    fn test_invalid_modules_path() {
        assert!(BazelHandler::parse_path("modules/incomplete").is_err());
    }

    #[test]
    fn test_format_handler() {
        let handler = BazelHandler::new();
        assert_eq!(handler.format_key(), "bazel");
        assert_eq!(handler.format(), RepositoryFormat::Bazel);
    }
}
