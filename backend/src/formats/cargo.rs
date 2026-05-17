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

        // Find the first hyphen followed by a digit — that's where the version starts.
        // This correctly handles both hyphenated names (my-crate-1.0.0) and
        // pre-release versions (my-crate-1.0.0-beta.1).
        let version_start = name
            .char_indices()
            .zip(name.chars().skip(1))
            .find(|&((_, c), next)| c == '-' && next.is_ascii_digit())
            .map(|((i, _), _)| i);

        match version_start {
            Some(i) => {
                let crate_name = name[..i].to_string();
                let version = name[i + 1..].to_string();
                Ok((crate_name, version))
            }
            None => Err(AppError::Validation(format!(
                "Invalid crate filename: {}",
                filename
            ))),
        }
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
            _ => format!("{}/{}/{}", &name_lower[..2], &name_lower[2..4], name_lower),
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
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid crate entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in crate: {}", e)))?;

            if path.ends_with("Cargo.toml") {
                let mut content = String::new();
                entry.read_to_string(&mut content).map_err(|e| {
                    AppError::Validation(format!("Failed to read Cargo.toml: {}", e))
                })?;

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

/// Parse the crate name out of a `<name>-<version>.crate` filename.
///
/// Returns `None` if the filename does not parse as a crate (no `.crate`
/// extension, no version separator, name fails [`is_valid_cargo_name`]).
/// Used by the cross-format shadowing guard (#1217 follow-up, ak-hv3s):
/// the result is fed to [`crate::api::handlers::proxy_helpers::
/// virtual_non_remote_owns_name`] so a virtual repo cannot let an
/// upstream Remote member serve a `.crate` whose name a local member
/// already owns.
///
/// The current cargo download handler reads the crate name from the URL
/// path parameters and feeds it straight to `virtual_non_remote_owns_name`.
/// This filename-based parser is the symmetric primitive kept for future
/// call sites that arrive only with a `.crate` filename (eg. background
/// revalidation jobs) and matches the shape of the hex / rubygems / npm
/// parsers so all five formats look alike to a reader.
#[allow(dead_code)]
pub(crate) fn package_name_from_crate_filename(filename: &str) -> Option<String> {
    let lowered = filename.to_ascii_lowercase();
    let without_ext = lowered.strip_suffix(".crate")?;
    for (i, _) in without_ext.match_indices('-') {
        if without_ext
            .get(i + 1..)
            .is_some_and(|s| s.starts_with(|c: char| c.is_ascii_digit()))
        {
            let candidate = &without_ext[..i];
            if is_valid_cargo_name(candidate) {
                return Some(candidate.to_string());
            }
            return None;
        }
    }
    None
}

/// Validate a crate name against the cargo registry-name spec
/// (`[a-zA-Z][a-zA-Z0-9_-]*`, at most 64 bytes). Case-insensitive
/// because the shadowing guard runs the candidate through SQL `LOWER()`.
///
/// Cargo's own validator also rejects reserved names (`std`, `core`,
/// etc.) but we deliberately do not replicate that list here: an
/// operator publishing such a name is opting into the consequences, and
/// false positives in the validator weaken (not strengthen) the
/// shadowing guard. The validator only needs to reject path-traversal-
/// shaped inputs, homoglyphs, and other obviously malformed identifiers.
pub(crate) fn is_valid_cargo_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
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

    // ---- CargoHandler::new / Default ----

    #[test]
    fn test_new_and_default() {
        let _h1 = CargoHandler::new();
        let _h2 = CargoHandler;
    }

    // ---- get_index_path ----

    #[test]
    fn test_get_index_path() {
        assert_eq!(CargoHandler::get_index_path("a"), "1/a");
        assert_eq!(CargoHandler::get_index_path("ab"), "2/ab");
        assert_eq!(CargoHandler::get_index_path("abc"), "3/a/abc");
        assert_eq!(CargoHandler::get_index_path("serde"), "se/rd/serde");
        assert_eq!(CargoHandler::get_index_path("tokio"), "to/ki/tokio");
    }

    #[test]
    fn test_get_index_path_uppercase_normalized() {
        // get_index_path lowercases
        assert_eq!(CargoHandler::get_index_path("A"), "1/a");
        assert_eq!(CargoHandler::get_index_path("AB"), "2/ab");
        assert_eq!(CargoHandler::get_index_path("AbC"), "3/a/abc");
        assert_eq!(CargoHandler::get_index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn test_get_index_path_long_name() {
        // A longer crate name (e.g. 10 chars)
        assert_eq!(
            CargoHandler::get_index_path("tokio-core"),
            "to/ki/tokio-core"
        );
    }

    // ---- parse_path: config ----

    #[test]
    fn test_parse_path_config() {
        let info = CargoHandler::parse_path("config.json").unwrap();
        assert!(matches!(info.operation, CargoOperation::Config));
        assert!(info.name.is_none());
        assert!(info.version.is_none());
    }

    #[test]
    fn test_parse_path_config_leading_slash() {
        let info = CargoHandler::parse_path("/config.json").unwrap();
        assert!(matches!(info.operation, CargoOperation::Config));
    }

    // ---- parse_path: index (1-char) ----

    #[test]
    fn test_parse_path_index_1char() {
        let info = CargoHandler::parse_path("1/a").unwrap();
        assert!(matches!(info.operation, CargoOperation::Index));
        assert_eq!(info.name, Some("a".to_string()));
        assert!(info.version.is_none());
    }

    // ---- parse_path: index (2-char) ----

    #[test]
    fn test_parse_path_index_2char() {
        let info = CargoHandler::parse_path("2/ab").unwrap();
        assert!(matches!(info.operation, CargoOperation::Index));
        assert_eq!(info.name, Some("ab".to_string()));
    }

    // ---- parse_path: index (3-char) ----

    #[test]
    fn test_parse_path_index_3char() {
        let info = CargoHandler::parse_path("3/a/abc").unwrap();
        assert!(matches!(info.operation, CargoOperation::Index));
        assert_eq!(info.name, Some("abc".to_string()));
    }

    #[test]
    fn test_parse_path_index_3char_mismatch_returns_none() {
        // If the crate name doesn't start_with the first-char prefix, parse_index_path
        // returns None, falling through to the Err branch.
        let result = CargoHandler::parse_path("3/x/abc");
        assert!(result.is_err());
    }

    // ---- parse_path: index (4+ char) ----

    #[test]
    fn test_parse_path_index_4char() {
        let info = CargoHandler::parse_path("se/rd/serde").unwrap();
        assert!(matches!(info.operation, CargoOperation::Index));
        assert_eq!(info.name, Some("serde".to_string()));
    }

    #[test]
    fn test_parse_path_index_4char_leading_slash() {
        let info = CargoHandler::parse_path("/to/ki/tokio").unwrap();
        assert!(matches!(info.operation, CargoOperation::Index));
        assert_eq!(info.name, Some("tokio".to_string()));
    }

    #[test]
    fn test_parse_path_index_4char_mismatch_first2() {
        // first2 doesn't match crate name prefix
        let result = CargoHandler::parse_path("xx/rd/serde");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_index_4char_mismatch_second2() {
        // second2 doesn't match crate name chars 2..4
        let result = CargoHandler::parse_path("se/xx/serde");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_index_4char_name_too_short() {
        // 3-part path but first2/second2 are 2-char each but crate_name is < 4 chars
        // This doesn't match the 4+ char rule because crate_name.len() < 4
        // AND doesn't match the 3-char rule because parts[0] != "3"
        let result = CargoHandler::parse_path("ab/cd/abc");
        assert!(result.is_err());
    }

    // ---- parse_path: download (.crate) ----

    #[test]
    fn test_parse_path_download() {
        let info = CargoHandler::parse_path("crates/serde/serde-1.0.193.crate").unwrap();
        assert!(matches!(info.operation, CargoOperation::Download));
        assert_eq!(info.name, Some("serde".to_string()));
        assert_eq!(info.version, Some("1.0.193".to_string()));
    }

    #[test]
    fn test_parse_path_download_leading_slash() {
        let info = CargoHandler::parse_path("/crates/tokio/tokio-1.34.0.crate").unwrap();
        assert!(matches!(info.operation, CargoOperation::Download));
        assert_eq!(info.name, Some("tokio".to_string()));
        assert_eq!(info.version, Some("1.34.0".to_string()));
    }

    #[test]
    fn test_parse_path_download_hyphenated_name() {
        let info = CargoHandler::parse_path("crates/my-crate/my-crate-0.1.0.crate").unwrap();
        assert!(matches!(info.operation, CargoOperation::Download));
        assert_eq!(info.name, Some("my-crate".to_string()));
        assert_eq!(info.version, Some("0.1.0".to_string()));
    }

    // ---- parse_path: invalid ----

    #[test]
    fn test_parse_path_invalid() {
        assert!(CargoHandler::parse_path("random/path").is_err());
    }

    #[test]
    fn test_parse_path_empty() {
        assert!(CargoHandler::parse_path("").is_err());
    }

    // ---- parse_crate_filename ----

    #[test]
    fn test_parse_crate_filename() {
        let (name, version) = CargoHandler::parse_crate_filename("serde-1.0.193.crate").unwrap();
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.193");
    }

    #[test]
    fn test_parse_crate_filename_hyphenated() {
        let (name, version) =
            CargoHandler::parse_crate_filename("my-great-crate-2.3.4.crate").unwrap();
        assert_eq!(name, "my-great-crate");
        assert_eq!(version, "2.3.4");
    }

    #[test]
    fn test_parse_crate_filename_prerelease() {
        // Pre-release versions with hyphens (e.g. "1.0.0-beta.1") are correctly parsed
        // by finding the first hyphen followed by a digit as the version boundary.
        let (name, version) = CargoHandler::parse_crate_filename("foo-1.0.0-beta.1.crate").unwrap();
        assert_eq!(name, "foo");
        assert_eq!(version, "1.0.0-beta.1");
    }

    #[test]
    fn test_parse_crate_filename_no_hyphen() {
        // A filename with no hyphen (after stripping .crate) can't be split
        let result = CargoHandler::parse_crate_filename("nohyphen.crate");
        assert!(result.is_err());
    }

    // ---- parse_cargo_toml ----

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
        assert_eq!(package.description, Some("A test crate".to_string()));
        assert!(cargo_toml.dependencies.is_some());
    }

    #[test]
    fn test_parse_cargo_toml_full_fields() {
        let content = r#"
[package]
name = "full-crate"
version = "1.2.3"
edition = "2021"
rust-version = "1.75.0"
description = "Full metadata"
documentation = "https://docs.rs/full-crate"
readme = "README.md"
homepage = "https://example.com"
repository = "https://github.com/user/full-crate"
license = "MIT"
license-file = "LICENSE"
keywords = ["test", "full"]
categories = ["development-tools"]
exclude = ["/tests"]
include = ["/src"]
publish = false

[dependencies]
serde = { version = "1.0", features = ["derive"] }

[dev-dependencies]
tokio = "1.0"

[build-dependencies]
cc = "1.0"

[features]
default = ["std"]
std = []

[workspace]
members = ["crate-a", "crate-b"]
exclude = ["examples"]
"#;
        let cargo_toml = CargoHandler::parse_cargo_toml(content).unwrap();
        let pkg = cargo_toml.package.unwrap();
        assert_eq!(pkg.name, "full-crate");
        assert_eq!(pkg.version, "1.2.3");
        assert_eq!(pkg.rust_version, Some("1.75.0".to_string()));
        assert_eq!(pkg.license, Some("MIT".to_string()));
        assert_eq!(pkg.license_file, Some("LICENSE".to_string()));
        assert_eq!(
            pkg.keywords,
            Some(vec!["test".to_string(), "full".to_string()])
        );
        assert_eq!(pkg.categories, Some(vec!["development-tools".to_string()]));
        assert!(pkg.homepage.is_some());
        assert!(pkg.repository.is_some());
        assert!(pkg.documentation.is_some());
        assert!(pkg.readme.is_some());
        assert!(pkg.exclude.is_some());
        assert!(pkg.include.is_some());
        assert!(pkg.publish.is_some());
        assert!(cargo_toml.dev_dependencies.is_some());
        assert!(cargo_toml.build_dependencies.is_some());
        assert!(cargo_toml.features.is_some());
        let ws = cargo_toml.workspace.unwrap();
        assert_eq!(
            ws.members,
            Some(vec!["crate-a".to_string(), "crate-b".to_string()])
        );
        assert_eq!(ws.exclude, Some(vec!["examples".to_string()]));
    }

    #[test]
    fn test_parse_cargo_toml_minimal_no_package() {
        // A Cargo.toml with no [package] section (e.g. workspace-only)
        let content = r#"
[workspace]
members = ["crate-a"]
"#;
        let cargo_toml = CargoHandler::parse_cargo_toml(content).unwrap();
        assert!(cargo_toml.package.is_none());
    }

    #[test]
    fn test_parse_cargo_toml_invalid() {
        let result = CargoHandler::parse_cargo_toml("not valid toml {{{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_cargo_toml_empty() {
        // Empty string is valid TOML (no keys)
        let cargo_toml = CargoHandler::parse_cargo_toml("").unwrap();
        assert!(cargo_toml.package.is_none());
    }

    // ---- parse_index_entry ----

    #[test]
    fn test_parse_index_entry() {
        let entry_json = r#"{"name":"serde","vers":"1.0.193","deps":[],"cksum":"abc123","features":{},"yanked":false}"#;
        let entry = CargoHandler::parse_index_entry(entry_json).unwrap();
        assert_eq!(entry.name, "serde");
        assert_eq!(entry.vers, "1.0.193");
        assert!(!entry.yanked);
        assert!(entry.deps.is_empty());
        assert!(entry.features.is_empty());
    }

    #[test]
    fn test_parse_index_entry_with_deps() {
        let entry_json = r#"{
            "name": "my-crate",
            "vers": "0.1.0",
            "deps": [
                {
                    "name": "serde",
                    "req": "^1.0",
                    "features": ["derive"],
                    "optional": false,
                    "kind": "normal",
                    "target": null
                }
            ],
            "cksum": "deadbeef",
            "features": {"default": ["serde"]},
            "yanked": true,
            "rust-version": "1.75.0",
            "v": 2
        }"#;
        let entry = CargoHandler::parse_index_entry(entry_json).unwrap();
        assert_eq!(entry.name, "my-crate");
        assert_eq!(entry.vers, "0.1.0");
        assert!(entry.yanked);
        assert_eq!(entry.deps.len(), 1);
        assert_eq!(entry.deps[0].name, "serde");
        assert_eq!(entry.deps[0].req, "^1.0");
        assert_eq!(entry.deps[0].features, vec!["derive".to_string()]);
        assert!(!entry.deps[0].optional);
        assert_eq!(entry.deps[0].kind, "normal");
        assert!(entry.features.contains_key("default"));
        assert_eq!(entry.rust_version, Some("1.75.0".to_string()));
        assert_eq!(entry.v, Some(2));
    }

    #[test]
    fn test_parse_index_entry_dep_defaults() {
        // Test that default_dep_kind provides "normal" when kind is missing
        let entry_json = r#"{
            "name": "x",
            "vers": "0.1.0",
            "deps": [{"name": "y", "req": "^1"}],
            "cksum": "abcd"
        }"#;
        let entry = CargoHandler::parse_index_entry(entry_json).unwrap();
        assert_eq!(entry.deps[0].kind, "normal");
        assert!(!entry.deps[0].optional);
        assert!(entry.deps[0].features.is_empty());
        assert!(entry.deps[0].registry.is_none());
        assert!(entry.deps[0].package.is_none());
        assert!(entry.deps[0].target.is_none());
    }

    #[test]
    fn test_parse_index_entry_with_features2() {
        let entry_json = r#"{
            "name": "x",
            "vers": "0.1.0",
            "deps": [],
            "cksum": "aabb",
            "features": {},
            "features2": {"extra": ["dep:serde"]}
        }"#;
        let entry = CargoHandler::parse_index_entry(entry_json).unwrap();
        assert!(entry.features2.is_some());
        let f2 = entry.features2.unwrap();
        assert!(f2.contains_key("extra"));
    }

    #[test]
    fn test_parse_index_entry_with_links() {
        let entry_json = r#"{
            "name": "x",
            "vers": "0.1.0",
            "deps": [],
            "cksum": "aabb",
            "features": {},
            "links": "openssl"
        }"#;
        let entry = CargoHandler::parse_index_entry(entry_json).unwrap();
        assert_eq!(entry.links, Some("openssl".to_string()));
    }

    #[test]
    fn test_parse_index_entry_invalid_json() {
        assert!(CargoHandler::parse_index_entry("not json").is_err());
    }

    #[test]
    fn test_parse_index_entry_missing_required_fields() {
        // Missing "name" field
        let result = CargoHandler::parse_index_entry(r#"{"vers":"1.0","cksum":"ab"}"#);
        assert!(result.is_err());
    }

    // ---- parse_index_file ----

    #[test]
    fn test_parse_index_file_multiple_entries() {
        let content = concat!(
            r#"{"name":"serde","vers":"1.0.0","deps":[],"cksum":"aa","features":{}}"#,
            "\n",
            r#"{"name":"serde","vers":"1.0.1","deps":[],"cksum":"bb","features":{}}"#,
            "\n",
        );
        let entries = CargoHandler::parse_index_file(content).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].vers, "1.0.0");
        assert_eq!(entries[1].vers, "1.0.1");
    }

    #[test]
    fn test_parse_index_file_empty_lines_skipped() {
        let content = concat!(
            "\n",
            r#"{"name":"serde","vers":"1.0.0","deps":[],"cksum":"aa","features":{}}"#,
            "\n\n",
            r#"{"name":"serde","vers":"1.0.1","deps":[],"cksum":"bb","features":{}}"#,
            "\n\n",
        );
        let entries = CargoHandler::parse_index_file(content).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_index_file_empty_content() {
        let entries = CargoHandler::parse_index_file("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_index_file_invalid_line() {
        let content = "not valid json\n";
        assert!(CargoHandler::parse_index_file(content).is_err());
    }

    // ---- generate_config ----

    #[test]
    fn test_generate_config() {
        let config = generate_config("https://dl.example.com", Some("https://api.example.com"));
        assert_eq!(config.dl, "https://dl.example.com");
        assert_eq!(config.api, Some("https://api.example.com".to_string()));
        assert!(config.auth_required.is_none());
    }

    #[test]
    fn test_generate_config_no_api() {
        let config = generate_config("https://dl.example.com", None);
        assert_eq!(config.dl, "https://dl.example.com");
        assert!(config.api.is_none());
    }

    // ---- generate_index_entry ----

    #[test]
    fn test_generate_index_entry() {
        let deps = vec![IndexDependency {
            name: "serde".to_string(),
            req: "^1.0".to_string(),
            features: vec![],
            optional: false,
            kind: "normal".to_string(),
            registry: None,
            package: None,
            target: None,
        }];
        let mut features = HashMap::new();
        features.insert("default".to_string(), vec!["serde".to_string()]);
        let entry = generate_index_entry("my-crate", "0.1.0", "deadbeef", deps, features);
        assert_eq!(entry.name, "my-crate");
        assert_eq!(entry.vers, "0.1.0");
        assert_eq!(entry.cksum, "deadbeef");
        assert!(!entry.yanked);
        assert_eq!(entry.deps.len(), 1);
        assert!(entry.features.contains_key("default"));
        assert!(entry.features2.is_none());
        assert!(entry.links.is_none());
        assert!(entry.rust_version.is_none());
        assert_eq!(entry.v, Some(2));
    }

    #[test]
    fn test_generate_index_entry_empty_deps_features() {
        let entry = generate_index_entry("x", "1.0.0", "aabb", vec![], HashMap::new());
        assert!(entry.deps.is_empty());
        assert!(entry.features.is_empty());
    }

    // ---- RegistryConfig serde ----

    #[test]
    fn test_registry_config_serialization_roundtrip() {
        let config = RegistryConfig {
            dl: "https://dl.example.com".to_string(),
            api: Some("https://api.example.com".to_string()),
            auth_required: Some(true),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: RegistryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.dl, config.dl);
        assert_eq!(parsed.api, config.api);
        assert_eq!(parsed.auth_required, Some(true));
    }

    #[test]
    fn test_registry_config_defaults() {
        let json = r#"{"dl":"https://example.com"}"#;
        let config: RegistryConfig = serde_json::from_str(json).unwrap();
        assert!(config.api.is_none());
        assert!(config.auth_required.is_none());
    }

    // ---- parse_path: edge cases with parse_index_path ----

    #[test]
    fn test_parse_index_path_single_part_not_1_or_2() {
        // A single-part path that isn't "1" or "2" prefix
        let result = CargoHandler::parse_path("5/crate");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_3char_but_first_char_mismatch() {
        // 3/x/abc -> "abc" starts with "a", not "x"
        assert!(CargoHandler::parse_path("3/x/abc").is_err());
    }

    #[test]
    fn test_parse_path_direct_crate_file() {
        // A .crate filename at root level
        let info = CargoHandler::parse_path("my-crate-1.0.0.crate").unwrap();
        assert!(matches!(info.operation, CargoOperation::Download));
        assert_eq!(info.name, Some("my-crate".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
    }

    // ---- default_dep_kind ----

    #[test]
    fn test_default_dep_kind() {
        assert_eq!(default_dep_kind(), "normal");
    }

    // ---- extract_cargo_toml: invalid content ----

    #[test]
    fn test_extract_cargo_toml_invalid_bytes() {
        // Not a valid gzip
        let result = CargoHandler::extract_cargo_toml(b"not gzip data");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_cargo_toml_empty() {
        let result = CargoHandler::extract_cargo_toml(b"");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------
    // package_name_from_crate_filename / is_valid_cargo_name
    // (#1217 follow-up, ak-hv3s shadowing guard)
    // -----------------------------------------------------------------

    #[test]
    fn test_package_name_from_crate_filename_simple() {
        assert_eq!(
            package_name_from_crate_filename("serde-1.0.197.crate"),
            Some("serde".to_string())
        );
    }

    #[test]
    fn test_package_name_from_crate_filename_hyphenated_name() {
        assert_eq!(
            package_name_from_crate_filename("serde-derive-1.0.197.crate"),
            Some("serde-derive".to_string())
        );
        assert_eq!(
            package_name_from_crate_filename("tokio-stream-0.1.15.crate"),
            Some("tokio-stream".to_string())
        );
    }

    #[test]
    fn test_package_name_from_crate_filename_uppercase_extension() {
        // Case-insensitive `.crate` is load-bearing for the guard.
        assert_eq!(
            package_name_from_crate_filename("SERDE-1.0.crate"),
            Some("serde".to_string())
        );
        assert_eq!(
            package_name_from_crate_filename("serde-1.0.CRATE"),
            Some("serde".to_string())
        );
    }

    #[test]
    fn test_package_name_from_crate_filename_no_extension() {
        assert_eq!(package_name_from_crate_filename("serde-1.0.197"), None);
    }

    #[test]
    fn test_package_name_from_crate_filename_rejects_path_traversal() {
        assert_eq!(package_name_from_crate_filename("../-1.0.0.crate"), None);
        assert_eq!(package_name_from_crate_filename("a/b-1.0.0.crate"), None);
        assert_eq!(package_name_from_crate_filename("..%2f-1.0.0.crate"), None);
    }

    #[test]
    fn test_package_name_from_crate_filename_rejects_unicode() {
        // Cyrillic 'о' homoglyph must not parse: SQL `LOWER()` is ASCII-only.
        assert_eq!(
            package_name_from_crate_filename("s\u{0435}rde-1.0.0.crate"),
            None
        );
    }

    #[test]
    fn test_package_name_from_crate_filename_empty_name_rejected() {
        assert_eq!(package_name_from_crate_filename("-1.0.0.crate"), None);
        assert_eq!(package_name_from_crate_filename(""), None);
    }

    #[test]
    fn test_is_valid_cargo_name_accepts_real_world() {
        assert!(is_valid_cargo_name("serde"));
        assert!(is_valid_cargo_name("serde-derive"));
        assert!(is_valid_cargo_name("rand_chacha"));
        assert!(is_valid_cargo_name("Tokio")); // mixed case allowed
        assert!(is_valid_cargo_name("a"));
    }

    #[test]
    fn test_is_valid_cargo_name_rejects_invalid() {
        assert!(!is_valid_cargo_name("")); // empty
        assert!(!is_valid_cargo_name("1cool")); // leading digit
        assert!(!is_valid_cargo_name("_serde")); // leading underscore
        assert!(!is_valid_cargo_name("-serde")); // leading dash
        assert!(!is_valid_cargo_name("serde.derive")); // dot
        assert!(!is_valid_cargo_name("serde derive")); // space
        assert!(!is_valid_cargo_name("serde/derive")); // slash (traversal)
                                                       // 65 chars
        let too_long = "a".repeat(65);
        assert!(!is_valid_cargo_name(&too_long));
    }
}
