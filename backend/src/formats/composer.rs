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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub package_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require: Option<HashMap<String, String>>,
    #[serde(
        rename = "require-dev",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_dev: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoload: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<ComposerAuthor>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

    // ---- ComposerHandler::new / Default ----

    #[test]
    fn test_new_and_default() {
        let _h1 = ComposerHandler::new();
        let _h2 = ComposerHandler;
    }

    // ---- parse_path: packages.json (index) ----

    #[test]
    fn test_parse_packages_json() {
        let info = ComposerHandler::parse_path("packages.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::Index));
        assert!(info.vendor.is_none());
        assert!(info.package.is_none());
        assert!(info.version.is_none());
    }

    #[test]
    fn test_parse_packages_json_leading_slash() {
        let info = ComposerHandler::parse_path("/packages.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::Index));
    }

    // ---- parse_path: v2 metadata ----

    #[test]
    fn test_parse_v2_metadata() {
        let info = ComposerHandler::parse_path("p2/laravel/framework.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::MetadataV2));
        assert_eq!(info.vendor, Some("laravel".to_string()));
        assert_eq!(info.package, Some("framework".to_string()));
        assert!(info.version.is_none());
    }

    #[test]
    fn test_parse_v2_metadata_leading_slash() {
        let info = ComposerHandler::parse_path("/p2/symfony/console.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::MetadataV2));
        assert_eq!(info.vendor, Some("symfony".to_string()));
        assert_eq!(info.package, Some("console".to_string()));
    }

    #[test]
    fn test_parse_v2_metadata_no_package() {
        // p2/<vendor-only>.json - no slash, so split_once('/') fails
        let result = ComposerHandler::parse_path("p2/onlyvendor.json");
        assert!(result.is_err());
    }

    // ---- parse_path: v1 metadata ----

    #[test]
    fn test_parse_v1_metadata() {
        let info = ComposerHandler::parse_path("p/laravel/framework$abc123def.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::MetadataV1));
        assert_eq!(info.vendor, Some("laravel".to_string()));
        assert_eq!(info.package, Some("framework".to_string()));
    }

    #[test]
    fn test_parse_v1_metadata_no_hash() {
        // p/<vendor>/<package>.json without $ hash
        let info = ComposerHandler::parse_path("p/vendor/package.json").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::MetadataV1));
        assert_eq!(info.vendor, Some("vendor".to_string()));
        // When there's no $, split_once('$') returns (rest, ""), so package = the full rest
        assert_eq!(info.package, Some("package".to_string()));
    }

    #[test]
    fn test_parse_v1_metadata_no_package() {
        let result = ComposerHandler::parse_path("p/onlyvendor.json");
        assert!(result.is_err());
    }

    // ---- parse_path: dist archive ----

    #[test]
    fn test_parse_dist_archive() {
        let info = ComposerHandler::parse_path("dist/laravel/framework/11.0.0/abc123.zip").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::Archive));
        assert_eq!(info.vendor, Some("laravel".to_string()));
        assert_eq!(info.package, Some("framework".to_string()));
        assert_eq!(info.version, Some("11.0.0".to_string()));
    }

    #[test]
    fn test_parse_dist_archive_leading_slash() {
        let info = ComposerHandler::parse_path("/dist/symfony/console/7.0.0/deadbeef.zip").unwrap();
        assert!(matches!(info.kind, ComposerPathKind::Archive));
        assert_eq!(info.vendor, Some("symfony".to_string()));
        assert_eq!(info.package, Some("console".to_string()));
        assert_eq!(info.version, Some("7.0.0".to_string()));
    }

    #[test]
    fn test_parse_dist_archive_too_few_parts() {
        // dist/<vendor>/<package> - only 2 segments after "dist/", need 4 for splitn(4, '/')
        let result = ComposerHandler::parse_path("dist/vendor/package");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dist_archive_only_vendor() {
        let result = ComposerHandler::parse_path("dist/vendor");
        assert!(result.is_err());
    }

    // ---- parse_path: invalid ----

    #[test]
    fn test_parse_path_invalid() {
        assert!(ComposerHandler::parse_path("random/path").is_err());
    }

    #[test]
    fn test_parse_path_empty() {
        assert!(ComposerHandler::parse_path("").is_err());
    }

    #[test]
    fn test_parse_path_just_slash() {
        assert!(ComposerHandler::parse_path("/").is_err());
    }

    // ---- parse_composer_json: error cases ----

    #[test]
    fn test_parse_composer_json_not_zip() {
        let result = ComposerHandler::parse_composer_json(b"not a zip file");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_composer_json_empty() {
        let result = ComposerHandler::parse_composer_json(b"");
        assert!(result.is_err());
    }

    // ---- ComposerJson serde ----

    #[test]
    fn test_composer_json_deserialize_full() {
        let json = r#"{
            "name": "laravel/framework",
            "description": "The Laravel Framework.",
            "version": "11.0.0",
            "type": "library",
            "license": "MIT",
            "require": {
                "php": "^8.2",
                "ext-mbstring": "*"
            },
            "require-dev": {
                "phpunit/phpunit": "^10.0"
            },
            "autoload": {
                "psr-4": {"Illuminate\\": "src/Illuminate/"}
            },
            "authors": [
                {"name": "Taylor Otwell", "email": "taylor@laravel.com"}
            ],
            "keywords": ["framework", "laravel"],
            "homepage": "https://laravel.com"
        }"#;
        let cj: ComposerJson = serde_json::from_str(json).unwrap();
        assert_eq!(cj.name, "laravel/framework");
        assert_eq!(cj.description, Some("The Laravel Framework.".to_string()));
        assert_eq!(cj.version, Some("11.0.0".to_string()));
        assert_eq!(cj.package_type, Some("library".to_string()));
        assert!(cj.license.is_some());
        assert!(cj.require.is_some());
        let req = cj.require.unwrap();
        assert_eq!(req.get("php"), Some(&"^8.2".to_string()));
        assert!(cj.require_dev.is_some());
        assert!(cj.autoload.is_some());
        let authors = cj.authors.unwrap();
        assert_eq!(authors.len(), 1);
        assert_eq!(authors[0].name, Some("Taylor Otwell".to_string()));
        assert_eq!(authors[0].email, Some("taylor@laravel.com".to_string()));
        assert_eq!(
            cj.keywords,
            Some(vec!["framework".to_string(), "laravel".to_string()])
        );
        assert_eq!(cj.homepage, Some("https://laravel.com".to_string()));
    }

    #[test]
    fn test_composer_json_minimal() {
        let json = r#"{"name": "vendor/pkg"}"#;
        let cj: ComposerJson = serde_json::from_str(json).unwrap();
        assert_eq!(cj.name, "vendor/pkg");
        assert!(cj.description.is_none());
        assert!(cj.version.is_none());
        assert!(cj.package_type.is_none());
        assert!(cj.license.is_none());
        assert!(cj.require.is_none());
        assert!(cj.require_dev.is_none());
        assert!(cj.authors.is_none());
        assert!(cj.keywords.is_none());
        assert!(cj.homepage.is_none());
    }

    #[test]
    fn test_composer_json_license_as_string() {
        let json = r#"{"name": "v/p", "license": "MIT"}"#;
        let cj: ComposerJson = serde_json::from_str(json).unwrap();
        assert!(cj.license.is_some());
    }

    #[test]
    fn test_composer_json_license_as_array() {
        let json = r#"{"name": "v/p", "license": ["MIT", "Apache-2.0"]}"#;
        let cj: ComposerJson = serde_json::from_str(json).unwrap();
        assert!(cj.license.is_some());
    }

    // ---- ComposerAuthor serde ----

    #[test]
    fn test_composer_author_all_fields() {
        let json = r#"{"name": "Author", "email": "a@b.com", "homepage": "https://example.com"}"#;
        let author: ComposerAuthor = serde_json::from_str(json).unwrap();
        assert_eq!(author.name, Some("Author".to_string()));
        assert_eq!(author.email, Some("a@b.com".to_string()));
        assert_eq!(author.homepage, Some("https://example.com".to_string()));
    }

    #[test]
    fn test_composer_author_minimal() {
        let json = r#"{}"#;
        let author: ComposerAuthor = serde_json::from_str(json).unwrap();
        assert!(author.name.is_none());
        assert!(author.email.is_none());
        assert!(author.homepage.is_none());
    }

    // ---- PackagesJson serde ----

    #[test]
    fn test_packages_json_deserialize() {
        let json = r#"{
            "packages": {
                "vendor/pkg": {
                    "1.0.0": {"name": "vendor/pkg", "version": "1.0.0"}
                }
            },
            "metadata-url": "/p2/%package%.json"
        }"#;
        let pj: PackagesJson = serde_json::from_str(json).unwrap();
        assert!(pj.packages.contains_key("vendor/pkg"));
        assert_eq!(pj.metadata_url, Some("/p2/%package%.json".to_string()));
    }

    #[test]
    fn test_packages_json_empty_packages() {
        let json = r#"{"packages": {}}"#;
        let pj: PackagesJson = serde_json::from_str(json).unwrap();
        assert!(pj.packages.is_empty());
        assert!(pj.metadata_url.is_none());
    }

    // ---- ComposerJson serialization roundtrip ----

    #[test]
    fn test_composer_json_roundtrip() {
        let cj = ComposerJson {
            name: "vendor/pkg".to_string(),
            description: Some("Desc".to_string()),
            version: Some("1.0.0".to_string()),
            package_type: Some("library".to_string()),
            license: Some(serde_json::json!("MIT")),
            require: Some({
                let mut m = HashMap::new();
                m.insert("php".to_string(), "^8.0".to_string());
                m
            }),
            require_dev: None,
            autoload: None,
            authors: Some(vec![ComposerAuthor {
                name: Some("Author".to_string()),
                email: None,
                homepage: None,
            }]),
            keywords: Some(vec!["test".to_string()]),
            homepage: Some("https://example.com".to_string()),
        };
        let json = serde_json::to_string(&cj).unwrap();
        let parsed: ComposerJson = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "vendor/pkg");
        assert_eq!(parsed.version, Some("1.0.0".to_string()));
        assert_eq!(parsed.package_type, Some("library".to_string()));
    }

    // #1781: a minimal composer.json (only name + version) must NOT serialize
    // absent optional fields as JSON null. The Packagist/Composer spec omits
    // them; serializing `"description": null` etc. pollutes stored metadata.
    #[test]
    fn test_composer_json_omits_none_fields_on_serialize() {
        let cj = ComposerJson {
            name: "vendor/minimal".to_string(),
            description: None,
            version: Some("1.0.0".to_string()),
            package_type: None,
            license: None,
            require: None,
            require_dev: None,
            autoload: None,
            authors: None,
            keywords: None,
            homepage: None,
        };
        let value = serde_json::to_value(&cj).unwrap();
        let obj = value.as_object().unwrap();
        // Only the fields that are Some are present.
        assert_eq!(obj.len(), 2, "only name + version should be serialized");
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("version"));
        for absent in [
            "description",
            "type",
            "license",
            "require",
            "require-dev",
            "autoload",
            "authors",
            "keywords",
            "homepage",
        ] {
            assert!(
                !obj.contains_key(absent),
                "absent optional field `{}` must be omitted, not null",
                absent
            );
        }
    }
}
