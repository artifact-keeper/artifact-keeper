use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Information about a Hex.pm path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPathInfo {
    pub path_type: HexPathType,
    pub name: String,
    pub version: Option<String>,
    pub otp_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HexPathType {
    /// Package info: packages/<name>
    PackageInfo,
    /// Package tarball: tarballs/<name>-<version>.tar
    Tarball,
    /// Hex install: installs/<otp_version>/hex-<version>.ez
    Install,
}

/// Hex.pm format handler for Elixir/Erlang packages
pub struct HexHandler;

impl HexHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Hex.pm path
    pub fn parse_path(path: &str) -> Result<HexPathInfo> {
        let parts: Vec<&str> = path.split('/').collect();

        if parts.is_empty() {
            return Err(AppError::Validation(format!("Invalid Hex path: {}", path)));
        }

        match parts[0] {
            "packages" => {
                if parts.len() != 2 {
                    return Err(AppError::Validation(format!(
                        "Invalid package info path: {}",
                        path
                    )));
                }

                Ok(HexPathInfo {
                    path_type: HexPathType::PackageInfo,
                    name: parts[1].to_string(),
                    version: None,
                    otp_version: None,
                })
            }
            "tarballs" => {
                if parts.len() != 2 {
                    return Err(AppError::Validation(format!(
                        "Invalid tarball path: {}",
                        path
                    )));
                }

                // Parse filename: <name>-<version>.tar
                let filename = parts[1];
                if !filename.ends_with(".tar") {
                    return Err(AppError::Validation(format!(
                        "Invalid tarball filename: {}",
                        filename
                    )));
                }

                let basename = &filename[..filename.len() - 4]; // Remove .tar
                let last_dash = basename.rfind('-').ok_or_else(|| {
                    AppError::Validation(format!("Invalid tarball filename format: {}", filename))
                })?;

                let name = basename[..last_dash].to_string();
                let version = basename[last_dash + 1..].to_string();

                Ok(HexPathInfo {
                    path_type: HexPathType::Tarball,
                    name,
                    version: Some(version),
                    otp_version: None,
                })
            }
            "installs" => {
                if parts.len() != 3 {
                    return Err(AppError::Validation(format!(
                        "Invalid install path: {}",
                        path
                    )));
                }

                let otp_version = parts[1].to_string();
                let filename = parts[2];

                // Parse filename: hex-<version>.ez
                if !filename.starts_with("hex-") || !filename.ends_with(".ez") {
                    return Err(AppError::Validation(format!(
                        "Invalid hex install filename: {}",
                        filename
                    )));
                }

                let version_with_ez = &filename[4..]; // Remove "hex-"
                let version = version_with_ez[..version_with_ez.len() - 3].to_string(); // Remove .ez

                Ok(HexPathInfo {
                    path_type: HexPathType::Install,
                    name: "hex".to_string(),
                    version: Some(version),
                    otp_version: Some(otp_version),
                })
            }
            _ => Err(AppError::Validation(format!(
                "Unknown Hex path type: {}",
                parts[0]
            ))),
        }
    }
}

impl Default for HexHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for HexHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Hex
    }

    fn format_key(&self) -> &str {
        "hex"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let path_info = Self::parse_path(path)?;
        Ok(serde_json::to_value(path_info).unwrap_or(serde_json::json!({})))
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
    fn test_parse_package_info_path() {
        let path_info = HexHandler::parse_path("packages/phoenix").unwrap();
        assert_eq!(path_info.name, "phoenix");
        assert!(matches!(path_info.path_type, HexPathType::PackageInfo));
        assert_eq!(path_info.version, None);
        assert_eq!(path_info.otp_version, None);
    }

    #[test]
    fn test_parse_tarball_path() {
        let path_info = HexHandler::parse_path("tarballs/phoenix-1.7.0.tar").unwrap();
        assert_eq!(path_info.name, "phoenix");
        assert_eq!(path_info.version, Some("1.7.0".to_string()));
        assert!(matches!(path_info.path_type, HexPathType::Tarball));
        assert_eq!(path_info.otp_version, None);
    }

    #[test]
    fn test_parse_tarball_path_with_dash_in_name() {
        let path_info = HexHandler::parse_path("tarballs/ex-doc-0.30.0.tar").unwrap();
        assert_eq!(path_info.name, "ex-doc");
        assert_eq!(path_info.version, Some("0.30.0".to_string()));
        assert!(matches!(path_info.path_type, HexPathType::Tarball));
    }

    #[test]
    fn test_parse_install_path() {
        let path_info = HexHandler::parse_path("installs/24/hex-1.0.1.ez").unwrap();
        assert_eq!(path_info.name, "hex");
        assert_eq!(path_info.version, Some("1.0.1".to_string()));
        assert_eq!(path_info.otp_version, Some("24".to_string()));
        assert!(matches!(path_info.path_type, HexPathType::Install));
    }

    #[test]
    fn test_parse_invalid_package_path() {
        let result = HexHandler::parse_path("packages/phoenix/invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_tarball_path() {
        let result = HexHandler::parse_path("tarballs/phoenix.zip");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_install_path() {
        let result = HexHandler::parse_path("installs/24/invalid.ez");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_handler_format() {
        let handler = HexHandler::new();
        assert_eq!(handler.format_key(), "hex");
    }
}
