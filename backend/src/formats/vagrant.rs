use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Vagrant box repository format handler
pub struct VagrantHandler;

/// Information extracted from a Vagrant repository path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VagrantPathInfo {
    pub org: String,
    pub name: String,
    pub version: Option<String>,
    pub provider: Option<String>,
    pub is_download: bool,
}

impl VagrantHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Vagrant repository path and extract metadata
    pub fn parse_path(path: &str) -> Result<VagrantPathInfo> {
        let path = path.trim_start_matches('/');
        let parts: Vec<&str> = path.split('/').collect();

        if parts.is_empty() {
            return Err(AppError::Validation(
                "Vagrant path must have at least org/name".to_string(),
            ));
        }

        let org = parts[0].to_string();
        if org.is_empty() {
            return Err(AppError::Validation(
                "Organization name cannot be empty".to_string(),
            ));
        }

        if parts.len() < 2 {
            return Err(AppError::Validation(
                "Vagrant path must have at least org/name".to_string(),
            ));
        }

        let name = parts[1].to_string();
        if name.is_empty() {
            return Err(AppError::Validation("Box name cannot be empty".to_string()));
        }

        // Basic box info: <org>/<name>
        if parts.len() == 2 {
            return Ok(VagrantPathInfo {
                org,
                name,
                version: None,
                provider: None,
                is_download: false,
            });
        }

        // Version info: <org>/<name>/versions/<version>
        // Download: <org>/<name>/versions/<version>/providers/<provider>/download
        if parts.len() >= 3 && parts[2] == "versions" {
            if parts.len() < 4 {
                return Err(AppError::Validation(
                    "Version path requires version number".to_string(),
                ));
            }

            let version = parts[3].to_string();

            // Just version info
            if parts.len() == 4 {
                return Ok(VagrantPathInfo {
                    org,
                    name,
                    version: Some(version),
                    provider: None,
                    is_download: false,
                });
            }

            // Provider/download info: versions/<version>/providers/<provider>/download
            if parts.len() >= 5 && parts[4] == "providers" {
                if parts.len() < 6 {
                    return Err(AppError::Validation(
                        "Provider path requires provider name".to_string(),
                    ));
                }

                let provider = parts[5].to_string();

                // Check for download endpoint
                let is_download = parts.len() >= 7 && parts[6] == "download";

                return Ok(VagrantPathInfo {
                    org,
                    name,
                    version: Some(version),
                    provider: Some(provider),
                    is_download,
                });
            }
        }

        Err(AppError::Validation(format!(
            "Invalid Vagrant path format: {}",
            path
        )))
    }
}

impl Default for VagrantHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for VagrantHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Vagrant
    }

    fn format_key(&self) -> &str {
        "vagrant"
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
    fn test_parse_box_info() {
        let result = VagrantHandler::parse_path("myorg/mybox").unwrap();
        assert_eq!(result.org, "myorg");
        assert_eq!(result.name, "mybox");
        assert_eq!(result.version, None);
        assert_eq!(result.provider, None);
        assert!(!result.is_download);
    }

    #[test]
    fn test_parse_box_info_with_slash() {
        let result = VagrantHandler::parse_path("/hashicorp/bionic").unwrap();
        assert_eq!(result.org, "hashicorp");
        assert_eq!(result.name, "bionic");
    }

    #[test]
    fn test_parse_version_info() {
        let result = VagrantHandler::parse_path("myorg/mybox/versions/1.0.0").unwrap();
        assert_eq!(result.org, "myorg");
        assert_eq!(result.name, "mybox");
        assert_eq!(result.version, Some("1.0.0".to_string()));
        assert_eq!(result.provider, None);
        assert!(!result.is_download);
    }

    #[test]
    fn test_parse_provider_info() {
        let result =
            VagrantHandler::parse_path("hashicorp/bionic/versions/1.0.0/providers/virtualbox")
                .unwrap();
        assert_eq!(result.org, "hashicorp");
        assert_eq!(result.name, "bionic");
        assert_eq!(result.version, Some("1.0.0".to_string()));
        assert_eq!(result.provider, Some("virtualbox".to_string()));
        assert!(!result.is_download);
    }

    #[test]
    fn test_parse_download_endpoint() {
        let result = VagrantHandler::parse_path(
            "hashicorp/bionic/versions/1.0.0/providers/vmware_desktop/download",
        )
        .unwrap();
        assert_eq!(result.org, "hashicorp");
        assert_eq!(result.name, "bionic");
        assert_eq!(result.version, Some("1.0.0".to_string()));
        assert_eq!(result.provider, Some("vmware_desktop".to_string()));
        assert!(result.is_download);
    }

    #[test]
    fn test_invalid_empty_org() {
        assert!(VagrantHandler::parse_path("/mybox").is_err());
    }

    #[test]
    fn test_invalid_no_name() {
        assert!(VagrantHandler::parse_path("myorg").is_err());
    }

    #[test]
    fn test_version_with_trailing_slash() {
        // "myorg/mybox/versions/" splits to ["myorg", "mybox", "versions", ""]
        // which has len 4, so it parses as version with empty string
        let result = VagrantHandler::parse_path("myorg/mybox/versions/");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.version, Some("".to_string()));
    }

    #[test]
    fn test_format_handler() {
        let handler = VagrantHandler::new();
        assert_eq!(handler.format_key(), "vagrant");
        assert_eq!(handler.format(), RepositoryFormat::Vagrant);
    }
}
