//! Cargo/crates.io format handler.
//!
//! Implements Cargo sparse registry protocol for Rust crates.
//! Supports crate index JSON files and .crate binary packages.

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use tar::Archive;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Cargo format handler
pub struct CargoHandler;

impl CargoHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Cargo registry path
    /// Sparse registry formats:
    ///   config.json                           - Registry configuration
    ///   1/<crate>                             - 1-char crate name index
    ///   2/<crate>                             - 2-char crate name index
    ///   3/<first>/<crate>                     - 3-char crate name index
    ///   <first2>/<second2>/<crate>           - 4+ char crate name index
    ///   crates/<crate>/<crate>-<version>.crate - Crate package
    pub fn parse_path(path: &str) -> Result<CargoPathInfo> {
        let path = path.trim_start_matches('/');

        // Config file
        if path == "config.json" {
            return Ok(CargoPathInfo {
                name: None,
                version: None,
                operation: CargoOperation::Config,
            });
        }

        // Crate package file
        if path.ends_with(".crate") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            let (name, version) = Self::parse_crate_filename(filename)?;
            return Ok(CargoPathInfo {
                name: Some(name),
                version: Some(version),
                operation: CargoOperation::Download,
            });
        }

        // Index path - parse based on crate name length rules
        if let Some(info) = Self::parse_index_path(path) {
            return Ok(info);
        }

        Err(AppError::Validation(format!(
            "Invalid Cargo registry path: {}",
            path
        )))
    }

    /// Parse crate package filename
    /// Format: <name>-<version>.crate
    fn parse_crate_filename(filename: &str) -> Result<(String, String)> {
        let name = filename.trim_end_matches(".crate");
        let parts: Vec<&str> = name.rsplitn(2, '-').collect();

        if parts.len() != 2 {
            return Err(AppError::Validation(format!(
                "Invalid crate filename: {}",
                filename
            )));
        }

        let version = parts[0].to_string();
        let crate_name = parts[1].to_string();

        Ok((crate_name, version))
    }

    /// Parse index path based on crate name length rules
    fn parse_index_path(path: &str) -> Option<CargoPathInfo> {
        let parts: Vec<&str> = path.split('/').collect();

        // 1-char crate: 1/<crate>
        if parts.len() == 2 && parts[0] == "1" {
            return Some(CargoPathInfo {
                name: Some(parts[1].to_string()),
                version: None,
                operation: CargoOperation::Index,
            });
        }

        // 2-char crate: 2/<crate>
        if parts.len() == 2 && parts[0] == "2" {
            return Some(CargoPathInfo {
                name: Some(parts[1].to_string()),
                version: None,
                operation: CargoOperation::Index,
            });
        }

        // 3-char crate: 3/<first>/<crate>
        if parts.len() == 3 && parts[0] == "3" {
            let crate_name = parts[2];
            if crate_name.len() == 3 && crate_name.starts_with(parts[1]) {
                return Some(CargoPathInfo {
                    name: Some(crate_name.to_string()),
                    version: None,
                    operation: CargoOperation::Index,
                });
            }
        }

        // 4+ char crate: <first2>/<second2>/<crate>
        if parts.len() == 3 {
            let first2 = parts[0];
            let second2 = parts[1];
            let crate_name = parts[2];

            if first2.len() == 2
                && second2.len() == 2
                && crate_name.len() >= 4
                && crate_name.starts_with(first2)
                && crate_name[2..].starts_with(second2)
            {
                return Some(CargoPathInfo {
                    name: Some(crate_name.to_string()),
                    version: None,
                    operation: CargoOperation::Index,
                });
            }
        }

        None
    }

    /// Get the index path for a crate name
    pub fn get_index_path(name: &str) -> String {
        let name_lower = name.to_lowercase();

        match name_lower.len() {
            1 => format!("1/{}", name_lower),
            2 => format!("2/{}", name_lower),
            3 => format!("3/{}/{}", &name_lower[..1], name_lower),
            _ => format!(
                "{}/{}/{}",
                &name_lower[..2],
                &name_lower[2..4],
                name_lower
            ),
        }
    }

    /// Parse Cargo.toml content
    pub fn parse_cargo_toml(content: &str) -> Result<CargoToml> {
        toml::from_str(content)
            .map_err(|e| AppError::Validation(format!("Invalid Cargo.toml: {}", e)))
    }

    /// Extract Cargo.toml from .crate package
    pub fn extract_cargo_toml(content: &[u8]) -> Result<CargoToml> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid crate package: {}", e)))?
        {
            let mut entry = entry
                .map_err(|e| AppError::Validation(format!("Invalid crate entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in crate: {}", e)))?;

            if path.ends_with("Cargo.toml") {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read Cargo.toml: {}", e)))?;

                return Self::parse_cargo_toml(&content);
            }
        }

        Err(AppError::Validation(
            "Cargo.toml not found in crate package".to_string(),
        ))
    }

    /// Parse index entry from JSON line
    pub fn parse_index_entry(line: &str) -> Result<IndexEntry> {
        serde_json::from_str(line)
            .map_err(|e| AppError::Validation(format!("Invalid index entry: {}", e)))
    }

    /// Parse all index entries from index file
    pub fn parse_index_file(content: &str) -> Result<Vec<IndexEntry>> {
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(Self::parse_index_entry)
            .collect()
    }
}

impl Default for CargoHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for CargoHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Cargo
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "operation": format!("{:?}", info.operation),
        });

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        // Parse content based on operation
        if !content.is_empty() {
            match info.operation {
                CargoOperation::Download => {
                    // Extract Cargo.toml from crate
                    if let Ok(cargo_toml) = Self::extract_cargo_toml(content) {
                        metadata["cargoToml"] = serde_json::to_value(&cargo_toml)?;
                    }
                }
                CargoOperation::Index => {
                    // Parse index entries
                    if let Ok(content_str) = std::str::from_utf8(content) {
                        if let Ok(entries) = Self::parse_index_file(content_str) {
                            metadata["entries"] = serde_json::to_value(&entries)?;
                        }
                    }
                }
                CargoOperation::Config => {
                    // Parse config.json
                    if let Ok(config) = serde_json::from_slice::<RegistryConfig>(content) {
                        metadata["config"] = serde_json::to_value(&config)?;
                    }
                }
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate crate packages
        if !content.is_empty() && matches!(info.operation, CargoOperation::Download) {
            let cargo_toml = Self::extract_cargo_toml(content)?;

            // Verify name matches
            if let Some(path_name) = &info.name {
                if let Some(package) = &cargo_toml.package {
                    if &package.name != path_name {
                        return Err(AppError::Validation(format!(
                            "Crate name mismatch: path says '{}' but Cargo.toml says '{}'",
                            path_name, package.name
                        )));
                    }
                }
            }

            // Verify version matches
            if let Some(path_version) = &info.version {
                if let Some(package) = &cargo_toml.package {
                    if &package.version != path_version {
                        return Err(AppError::Validation(format!(
                            "Version mismatch: path says '{}' but Cargo.toml says '{}'",
                            path_version, package.version
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Index is generated on demand
        Ok(None)
    }
}

/// Cargo path info
#[derive(Debug)]
pub struct CargoPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub operation: CargoOperation,
}

/// Cargo operation type
#[derive(Debug)]
pub enum CargoOperation {
    Config,
    Index,
    Download,
}

/// Registry config.json structure
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub dl: String,
    #[serde(default)]
    pub api: Option<String>,
    #[serde(default, rename = "auth-required")]
    pub auth_required: Option<bool>,
}

/// Cargo.toml structure
#[derive(Debug, Serialize, Deserialize)]
pub struct CargoToml {
    pub package: Option<CargoPackage>,
    #[serde(default)]
    pub dependencies: Option<HashMap<String, toml::Value>>,
    #[serde(default, rename = "dev-dependencies")]
    pub dev_dependencies: Option<HashMap<String, toml::Value>>,
    #[serde(default, rename = "build-dependencies")]
    pub build_dependencies: Option<HashMap<String, toml::Value>>,
    #[serde(default)]
    pub features: Option<HashMap<String, Vec<String>>>,
    #[serde(default)]
    pub workspace: Option<CargoWorkspace>,
}

/// Cargo package section
#[derive(Debug, Serialize, Deserialize)]
pub struct CargoPackage {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub authors: Option<Vec<String>>,
    #[serde(default)]
    pub edition: Option<String>,
    #[serde(default, rename = "rust-version")]
    pub rust_version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub documentation: Option<String>,
    #[serde(default)]
    pub readme: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default, rename = "license-file")]
    pub license_file: Option<String>,
    #[serde(default)]
    pub keywords: Option<Vec<String>>,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    #[serde(default)]
    pub exclude: Option<Vec<String>>,
    #[serde(default)]
    pub include: Option<Vec<String>>,
    #[serde(default)]
    pub publish: Option<toml::Value>,
    #[serde(default)]
    pub metadata: Option<toml::Value>,
}

/// Cargo workspace section
#[derive(Debug, Serialize, Deserialize)]
pub struct CargoWorkspace {
    #[serde(default)]
    pub members: Option<Vec<String>>,
    #[serde(default)]
    pub exclude: Option<Vec<String>>,
}

/// Sparse registry index entry (one per line, JSON)
#[derive(Debug, Serialize, Deserialize)]
pub struct IndexEntry {
    pub name: String,
    pub vers: String,
    #[serde(default)]
    pub deps: Vec<IndexDependency>,
    pub cksum: String,
    #[serde(default)]
    pub features: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub features2: Option<HashMap<String, Vec<String>>>,
    #[serde(default)]
    pub yanked: bool,
    #[serde(default)]
    pub links: Option<String>,
    #[serde(default, rename = "rust-version")]
    pub rust_version: Option<String>,
    #[serde(default)]
    pub v: Option<u32>,
}

/// Index dependency
#[derive(Debug, Serialize, Deserialize)]
pub struct IndexDependency {
    pub name: String,
    pub req: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default = "default_dep_kind")]
    pub kind: String,
    #[serde(default)]
    pub registry: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
}

fn default_dep_kind() -> String {
    "normal".to_string()
}

/// Generate registry config.json
pub fn generate_config(dl_url: &str, api_url: Option<&str>) -> RegistryConfig {
    RegistryConfig {
        dl: dl_url.to_string(),
        api: api_url.map(|s| s.to_string()),
        auth_required: None,
    }
}

/// Generate index entry for a crate version
pub fn generate_index_entry(
    name: &str,
    version: &str,
    checksum: &str,
    deps: Vec<IndexDependency>,
    features: HashMap<String, Vec<String>>,
) -> IndexEntry {
    IndexEntry {
        name: name.to_string(),
        vers: version.to_string(),
        deps,
        cksum: checksum.to_string(),
        features,
        features2: None,
        yanked: false,
        links: None,
        rust_version: None,
        v: Some(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_index_path() {
        assert_eq!(CargoHandler::get_index_path("a"), "1/a");
        assert_eq!(CargoHandler::get_index_path("ab"), "2/ab");
        assert_eq!(CargoHandler::get_index_path("abc"), "3/a/abc");
        assert_eq!(CargoHandler::get_index_path("serde"), "se/rd/serde");
        assert_eq!(CargoHandler::get_index_path("tokio"), "to/ki/tokio");
    }

    #[test]
    fn test_parse_path_config() {
        let info = CargoHandler::parse_path("config.json").unwrap();
        assert!(matches!(info.operation, CargoOperation::Config));
    }

    #[test]
    fn test_parse_path_index_1char() {
        let info = CargoHandler::parse_path("1/a").unwrap();
        assert!(matches!(info.operation, CargoOperation::Index));
        assert_eq!(info.name, Some("a".to_string()));
    }

    #[test]
    fn test_parse_path_index_4char() {
        let info = CargoHandler::parse_path("se/rd/serde").unwrap();
        assert!(matches!(info.operation, CargoOperation::Index));
        assert_eq!(info.name, Some("serde".to_string()));
    }

    #[test]
    fn test_parse_crate_filename() {
        let (name, version) = CargoHandler::parse_crate_filename("serde-1.0.193.crate").unwrap();
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.193");
    }

    #[test]
    fn test_parse_cargo_toml() {
        let content = r#"
[package]
name = "my-crate"
version = "0.1.0"
edition = "2021"
description = "A test crate"

[dependencies]
serde = "1.0"
"#;
        let cargo_toml = CargoHandler::parse_cargo_toml(content).unwrap();
        let package = cargo_toml.package.unwrap();
        assert_eq!(package.name, "my-crate");
        assert_eq!(package.version, "0.1.0");
        assert_eq!(package.edition, Some("2021".to_string()));
    }

    #[test]
    fn test_parse_index_entry() {
        let entry_json = r#"{"name":"serde","vers":"1.0.193","deps":[],"cksum":"abc123","features":{},"yanked":false}"#;
        let entry = CargoHandler::parse_index_entry(entry_json).unwrap();
        assert_eq!(entry.name, "serde");
        assert_eq!(entry.vers, "1.0.193");
    }
}
