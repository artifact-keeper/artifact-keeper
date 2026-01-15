//! npm format handler.
//!
//! Implements npm registry protocol for package publishing and retrieval.

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::io::Read;
use tar::Archive;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// npm format handler
pub struct NpmHandler;

impl NpmHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse npm package path
    /// Formats: @scope/package/-/@scope/package-version.tgz
    ///          package/-/package-version.tgz
    pub fn parse_path(path: &str) -> Result<NpmPackageInfo> {
        let path = path.trim_start_matches('/');

        // Check for scoped package
        if path.starts_with('@') {
            Self::parse_scoped_path(path)
        } else {
            Self::parse_unscoped_path(path)
        }
    }

    fn parse_scoped_path(path: &str) -> Result<NpmPackageInfo> {
        // Format: @scope/package/-/@scope/package-version.tgz
        let parts: Vec<&str> = path.split('/').collect();

        if parts.len() < 4 {
            return Err(AppError::Validation(
                "Invalid scoped npm package path".to_string(),
            ));
        }

        let scope = Some(parts[0].trim_start_matches('@').to_string());
        let name = parts[1].to_string();
        let full_name = format!("@{}/{}", scope.as_ref().unwrap(), name);

        // Check if this is a tarball request
        if parts.len() >= 4 && parts[2] == "-" {
            let filename = parts.last().unwrap();
            let version = Self::extract_version_from_filename(filename, &name)?;
            return Ok(NpmPackageInfo {
                scope,
                name,
                full_name,
                version: Some(version),
                is_tarball: true,
            });
        }

        // Metadata request
        Ok(NpmPackageInfo {
            scope,
            name,
            full_name,
            version: None,
            is_tarball: false,
        })
    }

    fn parse_unscoped_path(path: &str) -> Result<NpmPackageInfo> {
        let parts: Vec<&str> = path.split('/').collect();

        if parts.is_empty() {
            return Err(AppError::Validation("Empty npm package path".to_string()));
        }

        let name = parts[0].to_string();
        let full_name = name.clone();

        // Check if this is a tarball request: package/-/package-version.tgz
        if parts.len() >= 3 && parts[1] == "-" {
            let filename = parts.last().unwrap();
            let version = Self::extract_version_from_filename(filename, &name)?;
            return Ok(NpmPackageInfo {
                scope: None,
                name,
                full_name,
                version: Some(version),
                is_tarball: true,
            });
        }

        // Metadata request
        Ok(NpmPackageInfo {
            scope: None,
            name,
            full_name,
            version: None,
            is_tarball: false,
        })
    }

    fn extract_version_from_filename(filename: &str, name: &str) -> Result<String> {
        // Filename format: name-version.tgz
        let prefix = format!("{}-", name);
        let suffix = ".tgz";

        if !filename.starts_with(&prefix) || !filename.ends_with(suffix) {
            return Err(AppError::Validation(format!(
                "Invalid npm tarball filename: {}",
                filename
            )));
        }

        let version = &filename[prefix.len()..filename.len() - suffix.len()];
        Ok(version.to_string())
    }

    /// Extract package.json from npm tarball
    pub fn extract_package_json(tarball: &[u8]) -> Result<PackageJson> {
        let gz = GzDecoder::new(tarball);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid tarball: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid tarball entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in tarball: {}", e)))?;

            // package.json is typically in package/package.json
            if path.ends_with("package.json") {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read package.json: {}", e)))?;

                return serde_json::from_str(&content)
                    .map_err(|e| AppError::Validation(format!("Invalid package.json: {}", e)));
            }
        }

        Err(AppError::Validation(
            "package.json not found in tarball".to_string(),
        ))
    }
}

impl Default for NpmHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for NpmHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Npm
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "name": info.full_name,
            "scope": info.scope,
        });

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        // If it's a tarball, extract package.json metadata
        if info.is_tarball && !content.is_empty() {
            if let Ok(pkg) = Self::extract_package_json(content) {
                metadata["description"] = serde_json::Value::String(pkg.description.unwrap_or_default());
                metadata["keywords"] = serde_json::to_value(&pkg.keywords).unwrap_or_default();
                metadata["author"] = serde_json::to_value(&pkg.author).unwrap_or_default();
                metadata["license"] = serde_json::Value::String(pkg.license.unwrap_or_default());
                metadata["dependencies"] = serde_json::to_value(&pkg.dependencies).unwrap_or_default();
                metadata["devDependencies"] = serde_json::to_value(&pkg.dev_dependencies).unwrap_or_default();
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate tarball contains valid package.json
        if info.is_tarball && !content.is_empty() {
            let pkg = Self::extract_package_json(content)?;

            // Verify package name matches path
            if pkg.name != info.full_name {
                return Err(AppError::Validation(format!(
                    "Package name mismatch: path says '{}' but package.json says '{}'",
                    info.full_name, pkg.name
                )));
            }

            // Verify version matches path
            if let Some(path_version) = &info.version {
                if pkg.version != *path_version {
                    return Err(AppError::Validation(format!(
                        "Version mismatch: path says '{}' but package.json says '{}'",
                        path_version, pkg.version
                    )));
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // npm uses packument (package document) which is generated on demand
        Ok(None)
    }
}

/// npm package path info
#[derive(Debug)]
pub struct NpmPackageInfo {
    pub scope: Option<String>,
    pub name: String,
    pub full_name: String,
    pub version: Option<String>,
    pub is_tarball: bool,
}

/// npm package.json structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageJson {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub main: Option<String>,
    pub module: Option<String>,
    pub types: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub author: Option<PackageAuthor>,
    pub license: Option<String>,
    pub repository: Option<PackageRepository>,
    pub bugs: Option<PackageBugs>,
    pub homepage: Option<String>,
    pub dependencies: Option<std::collections::HashMap<String, String>>,
    pub dev_dependencies: Option<std::collections::HashMap<String, String>>,
    pub peer_dependencies: Option<std::collections::HashMap<String, String>>,
    pub engines: Option<std::collections::HashMap<String, String>>,
    pub scripts: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageAuthor {
    String(String),
    Object {
        name: String,
        email: Option<String>,
        url: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageRepository {
    String(String),
    Object {
        #[serde(rename = "type")]
        repo_type: Option<String>,
        url: String,
        directory: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageBugs {
    pub url: Option<String>,
    pub email: Option<String>,
}

/// npm packument (package document) structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Packument {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "dist-tags")]
    pub dist_tags: std::collections::HashMap<String, String>,
    pub versions: std::collections::HashMap<String, PackumentVersion>,
    pub time: std::collections::HashMap<String, String>,
    pub maintainers: Vec<PackumentMaintainer>,
    pub keywords: Option<Vec<String>>,
    pub license: Option<String>,
    pub readme: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackumentVersion {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub dist: PackumentDist,
    pub dependencies: Option<std::collections::HashMap<String, String>>,
    pub dev_dependencies: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackumentDist {
    pub tarball: String,
    pub shasum: String,
    pub integrity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackumentMaintainer {
    pub name: String,
    pub email: Option<String>,
}

/// Generate packument for a package
pub fn generate_packument(
    name: &str,
    versions: Vec<(String, PackageJson, String, String)>, // (version, pkg, tarball_url, shasum)
) -> Packument {
    let mut dist_tags = std::collections::HashMap::new();
    let mut version_map = std::collections::HashMap::new();
    let mut time_map = std::collections::HashMap::new();

    let mut latest_version = String::new();

    for (version, pkg, tarball_url, shasum) in versions {
        latest_version = version.clone();

        version_map.insert(
            version.clone(),
            PackumentVersion {
                name: name.to_string(),
                version: version.clone(),
                description: pkg.description.clone(),
                dist: PackumentDist {
                    tarball: tarball_url,
                    shasum,
                    integrity: None,
                },
                dependencies: pkg.dependencies,
                dev_dependencies: pkg.dev_dependencies,
            },
        );

        time_map.insert(version, chrono::Utc::now().to_rfc3339());
    }

    dist_tags.insert("latest".to_string(), latest_version);

    Packument {
        name: name.to_string(),
        description: None,
        dist_tags,
        versions: version_map,
        time: time_map,
        maintainers: vec![],
        keywords: None,
        license: None,
        readme: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unscoped_path() {
        let info = NpmHandler::parse_path("lodash/-/lodash-4.17.21.tgz").unwrap();
        assert_eq!(info.name, "lodash");
        assert_eq!(info.full_name, "lodash");
        assert_eq!(info.scope, None);
        assert_eq!(info.version, Some("4.17.21".to_string()));
        assert!(info.is_tarball);
    }

    #[test]
    fn test_parse_scoped_path() {
        let info = NpmHandler::parse_path("@types/node/-/@types/node-18.0.0.tgz").unwrap();
        assert_eq!(info.name, "node");
        assert_eq!(info.full_name, "@types/node");
        assert_eq!(info.scope, Some("types".to_string()));
        assert_eq!(info.version, Some("18.0.0".to_string()));
        assert!(info.is_tarball);
    }

    #[test]
    fn test_parse_metadata_path() {
        let info = NpmHandler::parse_path("lodash").unwrap();
        assert_eq!(info.name, "lodash");
        assert_eq!(info.version, None);
        assert!(!info.is_tarball);
    }
}
