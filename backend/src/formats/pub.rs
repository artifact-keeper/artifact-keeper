use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Path information extracted from Pub.dev package URLs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubPathInfo {
    pub name: String,
    pub version: Option<String>,
    pub is_api: bool,
}

/// Pub.dev package specification (pubspec.yaml equivalent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubSpec {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_dependencies: Option<HashMap<String, String>>,
}

/// Handler for Pub.dev format (Dart/Flutter packages)
pub struct PubHandler;

impl PubHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Pub.dev package path into structured information
    pub fn parse_path(path: &str) -> Result<PubPathInfo> {
        let path = path.trim_start_matches('/');

        // API endpoint: api/packages/<name>
        if let Some(api_path) = path.strip_prefix("api/packages/") {
            let parts: Vec<&str> = api_path.split('/').collect();
            if parts.is_empty() {
                return Err(AppError::Validation(
                    "Empty package name in Pub path".to_string(),
                ));
            }

            let name = parts[0].to_string();

            // api/packages/<name>/versions/<version>
            if parts.len() >= 3 && parts[1] == "versions" {
                let version = parts[2].to_string();
                return Ok(PubPathInfo {
                    name,
                    version: Some(version),
                    is_api: true,
                });
            }

            // api/packages/<name>
            return Ok(PubPathInfo {
                name,
                version: None,
                is_api: true,
            });
        }

        // Archive endpoint: packages/<name>/versions/<version>.tar.gz
        if let Some(pkg_path) = path.strip_prefix("packages/") {
            let parts: Vec<&str> = pkg_path.split('/').collect();
            if parts.len() < 3 {
                return Err(AppError::Validation(
                    "Invalid Pub archive path: expected packages/<name>/versions/<version>.tar.gz"
                        .to_string(),
                ));
            }

            let name = parts[0].to_string();

            if parts[1] != "versions" {
                return Err(AppError::Validation(
                    "Invalid Pub archive path: expected 'versions' directory".to_string(),
                ));
            }

            let version_file = parts[2];
            if !version_file.ends_with(".tar.gz") {
                return Err(AppError::Validation(
                    "Invalid Pub archive path: expected .tar.gz extension".to_string(),
                ));
            }

            let version = version_file
                .strip_suffix(".tar.gz")
                .unwrap_or(version_file)
                .to_string();

            return Ok(PubPathInfo {
                name,
                version: Some(version),
                is_api: false,
            });
        }

        Err(AppError::Validation(
            "Invalid Pub.dev path format. Expected api/packages/<name>[/versions/<version>] or packages/<name>/versions/<version>.tar.gz".to_string(),
        ))
    }
}

impl Default for PubHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for PubHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Pub
    }

    fn format_key(&self) -> &str {
        "pub"
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
    fn test_parse_api_package_info_path() {
        let result = PubHandler::parse_path("/api/packages/flutter_web");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "flutter_web");
        assert_eq!(info.version, None);
        assert!(info.is_api);
    }

    #[test]
    fn test_parse_api_version_info_path() {
        let result = PubHandler::parse_path("/api/packages/flutter_web/versions/1.2.3");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "flutter_web");
        assert_eq!(info.version, Some("1.2.3".to_string()));
        assert!(info.is_api);
    }

    #[test]
    fn test_parse_archive_path() {
        let result = PubHandler::parse_path("/packages/flutter_web/versions/1.2.3.tar.gz");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "flutter_web");
        assert_eq!(info.version, Some("1.2.3".to_string()));
        assert!(!info.is_api);
    }

    #[test]
    fn test_parse_archive_path_without_leading_slash() {
        let result = PubHandler::parse_path("packages/my_package/versions/2.0.0.tar.gz");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "my_package");
        assert_eq!(info.version, Some("2.0.0".to_string()));
        assert!(!info.is_api);
    }

    #[test]
    fn test_parse_invalid_path() {
        let result = PubHandler::parse_path("/invalid/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_version_in_archive() {
        let result = PubHandler::parse_path("/packages/flutter_web/versions/");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_archive_wrong_extension() {
        let result = PubHandler::parse_path("/packages/flutter_web/versions/1.2.3.zip");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_handler_format() {
        let handler = PubHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Pub);
    }

    #[test]
    fn test_format_handler_format_key() {
        let handler = PubHandler::new();
        assert_eq!(handler.format_key(), "pub");
    }

    #[test]
    fn test_pubspec_serialization() {
        let spec = PubSpec {
            name: "my_package".to_string(),
            version: "1.0.0".to_string(),
            description: Some("A test package".to_string()),
            homepage: Some("https://example.com".to_string()),
            repository: Some("https://github.com/example/my_package".to_string()),
            environment: Some(
                vec![("sdk".to_string(), ">=2.12.0 <3.0.0".to_string())]
                    .into_iter()
                    .collect(),
            ),
            dependencies: Some(
                vec![("http".to_string(), "^0.13.0".to_string())]
                    .into_iter()
                    .collect(),
            ),
            dev_dependencies: Some(
                vec![("test".to_string(), "^1.16.0".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };

        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["name"], "my_package");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["description"], "A test package");
    }

    #[test]
    fn test_pubspec_minimal() {
        let spec = PubSpec {
            name: "minimal_package".to_string(),
            version: "0.1.0".to_string(),
            description: None,
            homepage: None,
            repository: None,
            environment: None,
            dependencies: None,
            dev_dependencies: None,
        };

        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["name"], "minimal_package");
        assert_eq!(json["version"], "0.1.0");
        assert!(!json.as_object().unwrap().contains_key("description"));
        assert!(!json.as_object().unwrap().contains_key("homepage"));
    }

    #[test]
    fn test_parse_api_path_with_trailing_slash() {
        let result = PubHandler::parse_path("/api/packages/flutter_web/");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "flutter_web");
    }

    #[test]
    fn test_parse_complex_package_name() {
        let result = PubHandler::parse_path("/packages/my_awesome_package/versions/1.2.3.tar.gz");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "my_awesome_package");
        assert_eq!(info.version, Some("1.2.3".to_string()));
    }

    #[test]
    fn test_parse_version_with_prerelease() {
        let result = PubHandler::parse_path("/packages/pkg/versions/1.0.0-beta.1.tar.gz");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.version, Some("1.0.0-beta.1".to_string()));
    }
}
