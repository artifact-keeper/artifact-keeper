use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Swift Package Registry handler implementing SE-0292
pub struct SwiftHandler;

/// Parsed information from a Swift package path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftPathInfo {
    /// Package scope (organization or namespace)
    pub scope: String,
    /// Package name
    pub name: String,
    /// Package version (optional)
    pub version: Option<String>,
    /// Whether this is a Package.swift manifest request
    pub is_manifest: bool,
    /// Whether this is a source archive request
    pub is_archive: bool,
}

impl SwiftHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Swift package path
    ///
    /// Supports paths like:
    /// - `<scope>/<name>` - package info
    /// - `<scope>/<name>/<version>` - version info
    /// - `<scope>/<name>/<version>/Package.swift` - manifest
    /// - `<scope>/<name>/<version>.zip` - source archive
    pub fn parse_path(path: &str) -> Result<SwiftPathInfo> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();

        if parts.len() < 2 {
            return Err(AppError::Validation(
                "Swift package path must contain at least scope/name".to_string(),
            ));
        }

        let scope = parts[0].to_string();
        let name = parts[1].to_string();

        // Validate scope and name are not empty
        if scope.is_empty() || name.is_empty() {
            return Err(AppError::Validation(
                "Swift package scope and name must not be empty".to_string(),
            ));
        }

        let mut version = None;
        let mut is_manifest = false;
        let mut is_archive = false;

        match parts.len() {
            2 => {
                // Package info: <scope>/<name>
            }
            3 => {
                let part = parts[2];
                if part.ends_with(".zip") {
                    // Source archive: <scope>/<name>/<version>.zip
                    let version_str = part.trim_end_matches(".zip");
                    if version_str.is_empty() {
                        return Err(AppError::Validation(
                            "Version must not be empty in archive path".to_string(),
                        ));
                    }
                    version = Some(version_str.to_string());
                    is_archive = true;
                } else {
                    // Version info: <scope>/<name>/<version>
                    if part.is_empty() {
                        return Err(AppError::Validation(
                            "Version must not be empty".to_string(),
                        ));
                    }
                    version = Some(part.to_string());
                }
            }
            4 => {
                // Manifest: <scope>/<name>/<version>/Package.swift
                let version_str = parts[2];
                if version_str.is_empty() {
                    return Err(AppError::Validation(
                        "Version must not be empty".to_string(),
                    ));
                }
                version = Some(version_str.to_string());

                let manifest_file = parts[3];
                if manifest_file == "Package.swift" {
                    is_manifest = true;
                } else {
                    return Err(AppError::Validation(format!(
                        "Invalid manifest file: {}",
                        manifest_file
                    )));
                }
            }
            _ => {
                return Err(AppError::Validation(
                    "Invalid Swift package path structure".to_string(),
                ));
            }
        }

        Ok(SwiftPathInfo {
            scope,
            name,
            version,
            is_manifest,
            is_archive,
        })
    }
}

impl Default for SwiftHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for SwiftHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Swift
    }

    fn format_key(&self) -> &str {
        "swift"
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
    fn test_parse_package_info() {
        let result = SwiftHandler::parse_path("apple/swift-nio");
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.scope, "apple");
        assert_eq!(info.name, "swift-nio");
        assert_eq!(info.version, None);
        assert!(!info.is_manifest);
        assert!(!info.is_archive);
    }

    #[test]
    fn test_parse_version_info() {
        let result = SwiftHandler::parse_path("apple/swift-nio/1.0.0");
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.scope, "apple");
        assert_eq!(info.name, "swift-nio");
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert!(!info.is_manifest);
        assert!(!info.is_archive);
    }

    #[test]
    fn test_parse_manifest() {
        let result = SwiftHandler::parse_path("apple/swift-nio/1.0.0/Package.swift");
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.scope, "apple");
        assert_eq!(info.name, "swift-nio");
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert!(info.is_manifest);
        assert!(!info.is_archive);
    }

    #[test]
    fn test_parse_source_archive() {
        let result = SwiftHandler::parse_path("apple/swift-nio/1.0.0.zip");
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.scope, "apple");
        assert_eq!(info.name, "swift-nio");
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert!(!info.is_manifest);
        assert!(info.is_archive);
    }

    #[test]
    fn test_parse_invalid_path_too_short() {
        let result = SwiftHandler::parse_path("apple");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_path_empty_scope() {
        let result = SwiftHandler::parse_path("/swift-nio");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_path_empty_name() {
        let result = SwiftHandler::parse_path("apple/");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_trailing_slash_treated_as_package_info() {
        // Trailing slash gets filtered out by filter(|p| !p.is_empty()),
        // so "apple/swift-nio/" becomes ["apple", "swift-nio"] (package info)
        let result = SwiftHandler::parse_path("apple/swift-nio/");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.scope, "apple");
        assert_eq!(info.name, "swift-nio");
        assert_eq!(info.version, None);
    }

    #[test]
    fn test_parse_invalid_manifest_file() {
        let result = SwiftHandler::parse_path("apple/swift-nio/1.0.0/build.swift");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_too_many_parts() {
        let result = SwiftHandler::parse_path("apple/swift-nio/1.0.0/Package.swift/extra");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_handler_format() {
        let handler = SwiftHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Swift);
    }

    #[test]
    fn test_format_handler_format_key() {
        let handler = SwiftHandler::new();
        assert_eq!(handler.format_key(), "swift");
    }
}
