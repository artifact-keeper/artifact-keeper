//! PHP Composer format handler.
//!
//! Implements Composer/Packagist repository support.
//! Handles packages.json index, provider endpoints, and zip archives.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Composer format handler
pub struct ComposerHandler;

impl ComposerHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Composer repository path.
    ///
    /// Formats:
    ///   `packages.json`                     - Root index
    ///   `p2/<vendor>/<package>.json`         - Package metadata (Composer v2)
    ///   `p/<vendor>/<package>$<hash>.json`   - Package metadata (Composer v1)
    ///   `dist/<vendor>/<package>/<version>/<ref>.zip` - Package archive
    pub fn parse_path(path: &str) -> Result<ComposerPathInfo> {
        let path = path.trim_start_matches('/');

        if path == "packages.json" {
            return Ok(ComposerPathInfo {
                kind: ComposerPathKind::Index,
                vendor: None,
                package: None,
                version: None,
            });
        }

        if let Some(rest) = path.strip_prefix("p2/") {
            // Composer v2 metadata: p2/<vendor>/<package>.json
            let rest = rest.trim_end_matches(".json");
            let (vendor, package) = rest.split_once('/').ok_or_else(|| {
                AppError::Validation(format!("Invalid Composer v2 path: {}", path))
            })?;
            return Ok(ComposerPathInfo {
                kind: ComposerPathKind::MetadataV2,
                vendor: Some(vendor.to_string()),
                package: Some(package.to_string()),
                version: None,
            });
        }

        if let Some(rest) = path.strip_prefix("p/") {
            // Composer v1 metadata: p/<vendor>/<package>$<hash>.json
            let rest = rest.trim_end_matches(".json");
            let (vendor_pkg, _hash) = rest.split_once('$').unwrap_or((rest, ""));
            let (vendor, package) = vendor_pkg.split_once('/').ok_or_else(|| {
                AppError::Validation(format!("Invalid Composer v1 path: {}", path))
            })?;
            return Ok(ComposerPathInfo {
                kind: ComposerPathKind::MetadataV1,
                vendor: Some(vendor.to_string()),
                package: Some(package.to_string()),
                version: None,
            });
        }

        if let Some(rest) = path.strip_prefix("dist/") {
            // Distribution archive: dist/<vendor>/<package>/<version>/<ref>.zip
            let parts: Vec<&str> = rest.splitn(4, '/').collect();
            match parts.as_slice() {
                [vendor, package, version, _filename] => {
                    return Ok(ComposerPathInfo {
                        kind: ComposerPathKind::Archive,
                        vendor: Some(vendor.to_string()),
                        package: Some(package.to_string()),
                        version: Some(version.to_string()),
                    });
                }
                _ => {
                    return Err(AppError::Validation(format!(
                        "Invalid Composer dist path: {}",
                        path
                    )));
                }
            }
        }

        Err(AppError::Validation(format!(
            "Invalid Composer path: {}",
            path
        )))
    }

    /// Parse composer.json from a package archive to extract metadata.
    pub fn parse_composer_json(content: &[u8]) -> Result<ComposerJson> {
        // Try to read as zip and find composer.json
        let reader = std::io::Cursor::new(content);
        let mut archive = zip::ZipArchive::new(reader)
            .map_err(|e| AppError::Validation(format!("Invalid zip archive: {}", e)))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| AppError::Validation(format!("Invalid zip entry: {}", e)))?;

            if file.name().ends_with("composer.json") {
                let mut content = String::new();
                std::io::Read::read_to_string(&mut file, &mut content).map_err(|e| {
                    AppError::Validation(format!("Failed to read composer.json: {}", e))
                })?;

                return serde_json::from_str(&content)
                    .map_err(|e| AppError::Validation(format!("Invalid composer.json: {}", e)));
            }
        }

        Err(AppError::Validation(
            "composer.json not found in archive".to_string(),
        ))
    }
}

impl Default for ComposerHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for ComposerHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Composer
    }

    fn format_key(&self) -> &str {
        "composer"
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "kind": match info.kind {
                ComposerPathKind::Index => "index",
                ComposerPathKind::MetadataV1 => "metadata_v1",
                ComposerPathKind::MetadataV2 => "metadata_v2",
                ComposerPathKind::Archive => "archive",
            },
        });

        if let Some(vendor) = &info.vendor {
            metadata["vendor"] = serde_json::Value::String(vendor.clone());
        }
        if let Some(package) = &info.package {
            metadata["package"] = serde_json::Value::String(package.clone());
        }
        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        // Extract composer.json from archive packages
        if matches!(info.kind, ComposerPathKind::Archive) && !content.is_empty() {
            if let Ok(composer_json) = Self::parse_composer_json(content) {
                metadata["composer"] = serde_json::to_value(&composer_json)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // packages.json is generated on demand from DB state
        Ok(None)
    }
}

/// Composer path info
#[derive(Debug)]
pub struct ComposerPathInfo {
    pub kind: ComposerPathKind,
    pub vendor: Option<String>,
    pub package: Option<String>,
    pub version: Option<String>,
}

/// Kind of Composer path
#[derive(Debug)]
pub enum ComposerPathKind {
    Index,
    MetadataV1,
    MetadataV2,
    Archive,
}

/// Parsed composer.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposerJson {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(rename = "type", default)]
    pub package_type: Option<String>,
    #[serde(default)]
    pub license: Option<serde_json::Value>,
    #[serde(default)]
    pub require: Option<HashMap<String, String>>,
    #[serde(rename = "require-dev", default)]
    pub require_dev: Option<HashMap<String, String>>,
    #[serde(default)]
    pub autoload: Option<serde_json::Value>,
    #[serde(default)]
    pub authors: Option<Vec<ComposerAuthor>>,
    #[serde(default)]
    pub keywords: Option<Vec<String>>,
    #[serde(default)]
    pub homepage: Option<String>,
}

/// Composer package author
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposerAuthor {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
}

/// Composer packages.json root
#[derive(Debug, Serialize, Deserialize)]
pub struct PackagesJson {
    pub packages: HashMap<String, HashMap<String, serde_json::Value>>,
    #[serde(rename = "metadata-url", default)]
    pub metadata_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_packages_json() {
        let info = ComposerHandler::parse_path("packages.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::Index));
    }

    #[test]
    fn test_parse_v2_metadata() {
        let info = ComposerHandler::parse_path("p2/laravel/framework.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::MetadataV2));
        assert_eq!(info.vendor, Some("laravel".to_string()));
        assert_eq!(info.package, Some("framework".to_string()));
    }

    #[test]
    fn test_parse_v1_metadata() {
        let info = ComposerHandler::parse_path("p/laravel/framework$abc123def.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::MetadataV1));
        assert_eq!(info.vendor, Some("laravel".to_string()));
    }

    #[test]
    fn test_parse_dist_archive() {
        let info = ComposerHandler::parse_path("dist/laravel/framework/11.0.0/abc123.zip").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::Archive));
        assert_eq!(info.vendor, Some("laravel".to_string()));
        assert_eq!(info.package, Some("framework".to_string()));
        assert_eq!(info.version, Some("11.0.0".to_string()));
    }
}
