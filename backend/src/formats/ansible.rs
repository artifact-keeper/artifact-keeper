use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Ansible collection path information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsiblePathInfo {
    pub namespace: String,
    pub name: String,
    pub version: Option<String>,
    pub is_api: bool,
}

/// Ansible collection package handler
pub struct AnsibleHandler;

impl AnsibleHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Ansible paths like:
    /// - Collection info: `api/v3/collections/<namespace>/<name>`
    /// - Version info: `api/v3/collections/<namespace>/<name>/versions/<version>`
    /// - Archive: `collections/<namespace>-<name>-<version>.tar.gz`
    pub fn parse_path(path: &str) -> Result<AnsiblePathInfo> {
        // Try API path: api/v3/collections/<namespace>/<name> or api/v3/collections/<namespace>/<name>/versions/<version>
        if path.starts_with("api/v3/collections/") {
            let remainder = path.strip_prefix("api/v3/collections/").ok_or_else(|| {
                AppError::Validation(format!("Invalid Ansible API path: {}", path))
            })?;

            let parts: Vec<&str> = remainder.split('/').collect();

            if parts.len() == 2 {
                let namespace = parts[0].to_string();
                let name = parts[1].to_string();

                return Ok(AnsiblePathInfo {
                    namespace,
                    name,
                    version: None,
                    is_api: true,
                });
            }

            if parts.len() == 4 && parts[2] == "versions" {
                let namespace = parts[0].to_string();
                let name = parts[1].to_string();
                let version = parts[3].to_string();

                return Ok(AnsiblePathInfo {
                    namespace,
                    name,
                    version: Some(version),
                    is_api: true,
                });
            }

            return Err(AppError::Validation(format!(
                "Invalid Ansible API path format: {}",
                path
            )));
        }

        // Try archive path: collections/<namespace>-<name>-<version>.tar.gz
        if path.starts_with("collections/") {
            let filename = path.strip_prefix("collections/").ok_or_else(|| {
                AppError::Validation(format!("Invalid Ansible archive path: {}", path))
            })?;

            if !filename.ends_with(".tar.gz") {
                return Err(AppError::Validation(format!(
                    "Invalid Ansible archive extension: {}",
                    path
                )));
            }

            let namespace_name_version = filename.strip_suffix(".tar.gz").ok_or_else(|| {
                AppError::Validation(format!("Invalid Ansible archive path: {}", path))
            })?;

            // Split on the first hyphen for namespace
            if let Some(first_hyphen) = namespace_name_version.find('-') {
                let namespace = namespace_name_version[..first_hyphen].to_string();
                let remainder = &namespace_name_version[first_hyphen + 1..];

                // Split on the last hyphen for version
                if let Some(last_hyphen) = remainder.rfind('-') {
                    let name = remainder[..last_hyphen].to_string();
                    let version = remainder[last_hyphen + 1..].to_string();

                    return Ok(AnsiblePathInfo {
                        namespace,
                        name,
                        version: Some(version),
                        is_api: false,
                    });
                }
            }

            return Err(AppError::Validation(format!(
                "Invalid Ansible archive name format: {}",
                path
            )));
        }

        Err(AppError::Validation(format!(
            "Unrecognized Ansible path format: {}",
            path
        )))
    }
}

impl Default for AnsibleHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for AnsibleHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Ansible
    }

    fn format_key(&self) -> &str {
        "ansible"
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
    fn test_parse_collection_info_path() {
        let path = "api/v3/collections/community/general";
        let info = AnsibleHandler::parse_path(path).expect("Should parse collection info path");

        assert_eq!(info.namespace, "community");
        assert_eq!(info.name, "general");
        assert_eq!(info.version, None);
        assert!(info.is_api);
    }

    #[test]
    fn test_parse_version_info_path() {
        let path = "api/v3/collections/community/general/versions/7.0.0";
        let info = AnsibleHandler::parse_path(path).expect("Should parse version info path");

        assert_eq!(info.namespace, "community");
        assert_eq!(info.name, "general");
        assert_eq!(info.version, Some("7.0.0".to_string()));
        assert!(info.is_api);
    }

    #[test]
    fn test_parse_archive_path() {
        let path = "collections/community-general-7.0.0.tar.gz";
        let info = AnsibleHandler::parse_path(path).expect("Should parse archive path");

        assert_eq!(info.namespace, "community");
        assert_eq!(info.name, "general");
        assert_eq!(info.version, Some("7.0.0".to_string()));
        assert!(!info.is_api);
    }

    #[test]
    fn test_parse_archive_path_with_hyphenated_name() {
        let path = "collections/community-aws-network-1.2.3.tar.gz";
        let info = AnsibleHandler::parse_path(path)
            .expect("Should parse archive path with hyphenated name");

        assert_eq!(info.namespace, "community");
        assert_eq!(info.name, "aws-network");
        assert_eq!(info.version, Some("1.2.3".to_string()));
        assert!(!info.is_api);
    }

    #[test]
    fn test_invalid_path() {
        let path = "invalid/path";
        assert!(AnsibleHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_invalid_archive_extension() {
        let path = "collections/community-general-7.0.0.zip";
        assert!(AnsibleHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_invalid_api_path() {
        let path = "api/v3/collections/community";
        assert!(AnsibleHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_handler_format() {
        let handler = AnsibleHandler::new();
        assert_eq!(handler.format_key(), "ansible");
    }
}
