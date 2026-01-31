use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Puppet module path information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PuppetPathInfo {
    pub author: String,
    pub name: String,
    pub version: Option<String>,
    pub is_api: bool,
}

/// Puppet module package handler
pub struct PuppetHandler;

impl PuppetHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Puppet paths like:
    /// - Module info: `v3/modules/<author>-<name>`
    /// - Release: `v3/releases/<author>-<name>-<version>`
    /// - Archive: `modules/<author>-<name>-<version>.tar.gz`
    pub fn parse_path(path: &str) -> Result<PuppetPathInfo> {
        // Try v3/modules path: v3/modules/<author>-<name>
        if path.starts_with("v3/modules/") {
            let remainder = path.strip_prefix("v3/modules/").ok_or_else(|| {
                AppError::Validation(format!("Invalid Puppet module path: {}", path))
            })?;

            let parts: Vec<&str> = remainder.split('/').collect();

            if parts.is_empty() {
                return Err(AppError::Validation(format!(
                    "Invalid Puppet module path format: {}",
                    path
                )));
            }

            let author_name = parts[0];

            // Split on the first hyphen to separate author from name
            if let Some(first_hyphen) = author_name.find('-') {
                let author = author_name[..first_hyphen].to_string();
                let name = author_name[first_hyphen + 1..].to_string();

                return Ok(PuppetPathInfo {
                    author,
                    name,
                    version: None,
                    is_api: true,
                });
            }

            return Err(AppError::Validation(format!(
                "Invalid Puppet module name format: {}",
                path
            )));
        }

        // Try v3/releases path: v3/releases/<author>-<name>-<version>
        if path.starts_with("v3/releases/") {
            let remainder = path.strip_prefix("v3/releases/").ok_or_else(|| {
                AppError::Validation(format!("Invalid Puppet release path: {}", path))
            })?;

            let parts: Vec<&str> = remainder.split('/').collect();

            if parts.is_empty() {
                return Err(AppError::Validation(format!(
                    "Invalid Puppet release path format: {}",
                    path
                )));
            }

            let author_name_version = parts[0];

            // Split on the first hyphen for author, then last hyphen for version
            if let Some(first_hyphen) = author_name_version.find('-') {
                let author = author_name_version[..first_hyphen].to_string();
                let remainder = &author_name_version[first_hyphen + 1..];

                if let Some(last_hyphen) = remainder.rfind('-') {
                    let name = remainder[..last_hyphen].to_string();
                    let version = remainder[last_hyphen + 1..].to_string();

                    return Ok(PuppetPathInfo {
                        author,
                        name,
                        version: Some(version),
                        is_api: true,
                    });
                }
            }

            return Err(AppError::Validation(format!(
                "Invalid Puppet release name format: {}",
                path
            )));
        }

        // Try archive path: modules/<author>-<name>-<version>.tar.gz
        if path.starts_with("modules/") {
            let filename = path.strip_prefix("modules/").ok_or_else(|| {
                AppError::Validation(format!("Invalid Puppet archive path: {}", path))
            })?;

            if !filename.ends_with(".tar.gz") {
                return Err(AppError::Validation(format!(
                    "Invalid Puppet archive extension: {}",
                    path
                )));
            }

            let author_name_version = filename.strip_suffix(".tar.gz").ok_or_else(|| {
                AppError::Validation(format!("Invalid Puppet archive path: {}", path))
            })?;

            // Split on the first hyphen for author
            if let Some(first_hyphen) = author_name_version.find('-') {
                let author = author_name_version[..first_hyphen].to_string();
                let remainder = &author_name_version[first_hyphen + 1..];

                // Split on the last hyphen for version
                if let Some(last_hyphen) = remainder.rfind('-') {
                    let name = remainder[..last_hyphen].to_string();
                    let version = remainder[last_hyphen + 1..].to_string();

                    return Ok(PuppetPathInfo {
                        author,
                        name,
                        version: Some(version),
                        is_api: false,
                    });
                }
            }

            return Err(AppError::Validation(format!(
                "Invalid Puppet archive name format: {}",
                path
            )));
        }

        Err(AppError::Validation(format!(
            "Unrecognized Puppet path format: {}",
            path
        )))
    }
}

impl Default for PuppetHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for PuppetHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Puppet
    }

    fn format_key(&self) -> &str {
        "puppet"
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
    fn test_parse_module_info_path() {
        let path = "v3/modules/puppetlabs-apache";
        let info = PuppetHandler::parse_path(path).expect("Should parse module info path");

        assert_eq!(info.author, "puppetlabs");
        assert_eq!(info.name, "apache");
        assert_eq!(info.version, None);
        assert!(info.is_api);
    }

    #[test]
    fn test_parse_release_path() {
        let path = "v3/releases/puppetlabs-apache-2.5.0";
        let info = PuppetHandler::parse_path(path).expect("Should parse release path");

        assert_eq!(info.author, "puppetlabs");
        assert_eq!(info.name, "apache");
        assert_eq!(info.version, Some("2.5.0".to_string()));
        assert!(info.is_api);
    }

    #[test]
    fn test_parse_archive_path() {
        let path = "modules/puppetlabs-apache-2.5.0.tar.gz";
        let info = PuppetHandler::parse_path(path).expect("Should parse archive path");

        assert_eq!(info.author, "puppetlabs");
        assert_eq!(info.name, "apache");
        assert_eq!(info.version, Some("2.5.0".to_string()));
        assert!(!info.is_api);
    }

    #[test]
    fn test_parse_archive_path_with_hyphenated_name() {
        let path = "modules/puppetlabs-linux-base-2.1.0.tar.gz";
        let info = PuppetHandler::parse_path(path)
            .expect("Should parse archive path with hyphenated name");

        assert_eq!(info.author, "puppetlabs");
        assert_eq!(info.name, "linux-base");
        assert_eq!(info.version, Some("2.1.0".to_string()));
        assert!(!info.is_api);
    }

    #[test]
    fn test_invalid_path() {
        let path = "invalid/path";
        assert!(PuppetHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_invalid_archive_extension() {
        let path = "modules/puppetlabs-apache-2.5.0.zip";
        assert!(PuppetHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_invalid_module_format() {
        let path = "v3/modules/invalid";
        assert!(PuppetHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_handler_format() {
        let handler = PuppetHandler::new();
        assert_eq!(handler.format_key(), "puppet");
    }
}
