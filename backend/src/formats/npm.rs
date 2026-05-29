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
                entry.read_to_string(&mut content).map_err(|e| {
                    AppError::Validation(format!("Failed to read package.json: {}", e))
                })?;

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

/// Validate an npm package name against the registry's accepted shape.
///
/// npm names are case-insensitive, must be lowercase, may contain
/// hyphens, dots, and underscores, and may be prefixed by `@scope/`.
/// Length is bounded to 214 bytes per npm's published validator. The
/// shadowing guard restricts to ASCII because SQL `LOWER()` is
/// ASCII-only, so a unicode-homoglyph name would case-fold differently
/// in Postgres and Rust, opening a homoglyph-shadowing attack.
///
/// `@scope/name` shape is preserved: the slash is a permitted scope
/// separator, but it must appear at most once and be flanked by valid
/// scope and name segments. A bare `@`, multiple slashes, or empty
/// segments are rejected.
///
/// Cross-format shadowing guard primitive (#1217 follow-up, ak-hv3s).
pub(crate) fn is_valid_npm_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    // Scoped name: `@scope/name`
    if let Some(rest) = name.strip_prefix('@') {
        let mut split = rest.splitn(2, '/');
        let scope = split.next().unwrap_or("");
        let pkg = split.next().unwrap_or("");
        if scope.is_empty() || pkg.is_empty() {
            return false;
        }
        return is_valid_npm_segment(scope) && is_valid_npm_segment(pkg);
    }
    is_valid_npm_segment(name)
}

/// Validate a single scope or unscoped npm name segment.
/// Must start with a lowercase letter or digit; allow `-`, `_`, `.`
/// internally. Path-traversal characters (`/`, `..`, `%`) and any
/// uppercase/non-ASCII characters are rejected.
fn is_valid_npm_segment(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
}

/// Parse the package name out of an npm tarball URL path.
///
/// The two shapes are:
///   - `<name>/-/<name>-<version>.tgz`
///   - `@<scope>/<name>/-/<name>-<version>.tgz`
///
/// The package name we hand to the shadowing guard is the full name
/// (`@scope/name` or `name`): that is what the upstream registry
/// considers the package identity and what `artifacts.name` stores.
/// Returns `None` for any input that does not parse cleanly per
/// [`is_valid_npm_name`].
///
/// Cross-format shadowing guard primitive (#1217 follow-up, ak-hv3s).
///
/// The current npm download handler reads the package name from the URL
/// path parameters and feeds it straight to `virtual_non_remote_owns_name`.
/// This path-based parser is the symmetric primitive kept for future
/// call sites that arrive only with a tarball URL (eg. webhook payloads,
/// background revalidation jobs) and matches the shape of the hex /
/// rubygems / cargo parsers so all five formats look alike to a reader.
#[allow(dead_code)]
pub(crate) fn package_name_from_tarball_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    let parts: Vec<&str> = path.split('/').collect();

    // The trailing segment must look like a tarball: non-empty and ending
    // in `.tgz` (case-insensitive). Without this, paths like `foo/-/`
    // would be accepted with `foo` as the name even though no tarball is
    // actually being requested.
    let last = parts.last().copied().unwrap_or("");
    if last.is_empty() || !last.to_ascii_lowercase().ends_with(".tgz") {
        return None;
    }

    // Scoped: ["@scope", "name", "-", "<file>.tgz"]
    if parts.len() >= 4 && parts[0].starts_with('@') && parts[2] == "-" {
        let scope = parts[0].strip_prefix('@')?;
        let name = parts[1];
        if scope.is_empty() || name.is_empty() {
            return None;
        }
        let candidate = format!(
            "@{}/{}",
            scope.to_ascii_lowercase(),
            name.to_ascii_lowercase()
        );
        if is_valid_npm_name(&candidate) {
            return Some(candidate);
        }
        return None;
    }

    // Unscoped: ["name", "-", "<file>.tgz"]
    if parts.len() >= 3 && parts[1] == "-" {
        let candidate = parts[0].to_ascii_lowercase();
        if is_valid_npm_name(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// Translate the canonical npm tarball URL path that clients ask for
/// (`<name>/-/<name>-<version>.tgz` or `@<scope>/<name>/-/<name>-<version>.tgz`)
/// into the stored DB path used by `store_npm_version` in the publish
/// handler (`<name>/<version>/<name>-<version>.tgz` or
/// `@<scope>/<name>/<version>/<name>-<version>.tgz`).
///
/// Returns `None` if the input does not match the npm tarball URL shape
/// (so a lookup against a path that is already stored verbatim, eg. a
/// `package.json` metadata path or a raw artifact upload, is left
/// untouched).
///
/// This is the inverse of the path written by
/// `api::handlers::npm::store_npm_version`, where the on-disk layout
/// embeds the version segment for de-duplication. The npm download
/// router converts `<name>/<version>/<filename>` back to
/// `<name>/-/<filename>` for tarball URLs, so any external caller that
/// has only the URL form (the management API's lookup-by-path endpoint,
/// the artifact-metadata GET, the release-gate smoke test) needs the
/// same normalisation to round-trip. See #1443.
#[must_use]
pub fn normalize_lookup_path(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    let last = parts.last().copied().unwrap_or("");

    // The trailing segment must look like a tarball. Anything else (eg.
    // `<name>/package.json`, a bare metadata path, an arbitrary raw
    // upload) is stored under its literal path and must not be
    // rewritten.
    if last.is_empty() || !last.to_ascii_lowercase().ends_with(".tgz") {
        return None;
    }

    // Scoped: ["@scope", "name", "-", "<file>.tgz"]
    if parts.len() == 4 && parts[0].starts_with('@') && parts[2] == "-" {
        let scope = parts[0];
        let name = parts[1];
        let filename = parts[3];
        let version = version_from_tarball_filename(filename, name)?;
        return Some(format!("{}/{}/{}/{}", scope, name, version, filename));
    }

    // Unscoped: ["name", "-", "<file>.tgz"]
    if parts.len() == 3 && parts[1] == "-" {
        let name = parts[0];
        let filename = parts[2];
        let version = version_from_tarball_filename(filename, name)?;
        return Some(format!("{}/{}/{}", name, version, filename));
    }

    None
}

/// Extract `<version>` from `<name>-<version>.tgz`. Returns `None` when
/// the prefix or suffix don't match so the caller can fall back to the
/// raw path instead of guessing.
fn version_from_tarball_filename(filename: &str, name: &str) -> Option<String> {
    let prefix = format!("{}-", name);
    let suffix = ".tgz";
    if !filename.starts_with(&prefix) || !filename.ends_with(suffix) {
        return None;
    }
    let version = &filename[prefix.len()..filename.len() - suffix.len()];
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
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
                metadata["description"] =
                    serde_json::Value::String(pkg.description.unwrap_or_default());
                metadata["keywords"] = serde_json::to_value(&pkg.keywords).unwrap_or_default();
                metadata["author"] = serde_json::to_value(&pkg.author).unwrap_or_default();
                metadata["license"] = serde_json::Value::String(pkg.license.unwrap_or_default());
                metadata["dependencies"] =
                    serde_json::to_value(&pkg.dependencies).unwrap_or_default();
                metadata["devDependencies"] =
                    serde_json::to_value(&pkg.dev_dependencies).unwrap_or_default();
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

    // ---- NpmHandler::new / Default ----

    #[test]
    fn test_new_and_default() {
        let _h1 = NpmHandler::new();
        let _h2 = NpmHandler;
    }

    // ---- parse_path: unscoped tarball ----

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
    fn test_parse_unscoped_path_leading_slash() {
        let info = NpmHandler::parse_path("/lodash/-/lodash-4.17.21.tgz").unwrap();
        assert_eq!(info.name, "lodash");
        assert!(info.is_tarball);
    }

    // ---- parse_path: scoped tarball ----

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
    fn test_parse_scoped_path_leading_slash() {
        let info = NpmHandler::parse_path("/@angular/core/-/@angular/core-17.0.0.tgz").unwrap();
        assert_eq!(info.name, "core");
        assert_eq!(info.full_name, "@angular/core");
        assert_eq!(info.scope, Some("angular".to_string()));
        assert_eq!(info.version, Some("17.0.0".to_string()));
        assert!(info.is_tarball);
    }

    // ---- parse_path: metadata (unscoped) ----

    #[test]
    fn test_parse_metadata_path() {
        let info = NpmHandler::parse_path("lodash").unwrap();
        assert_eq!(info.name, "lodash");
        assert_eq!(info.full_name, "lodash");
        assert_eq!(info.version, None);
        assert!(!info.is_tarball);
        assert!(info.scope.is_none());
    }

    // ---- parse_path: metadata (scoped) ----

    #[test]
    fn test_parse_scoped_metadata_path() {
        // Scoped metadata: @scope/package/extra (4 parts)
        let info = NpmHandler::parse_path("@types/node/something/else").unwrap();
        assert_eq!(info.name, "node");
        assert_eq!(info.full_name, "@types/node");
        assert_eq!(info.scope, Some("types".to_string()));
        assert!(!info.is_tarball);
        assert!(info.version.is_none());
    }

    // ---- parse_path: scoped too few parts ----

    #[test]
    fn test_parse_scoped_path_too_few_parts() {
        // Only @scope - not enough parts
        let result = NpmHandler::parse_path("@types");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scoped_path_two_parts_only() {
        // @scope/package - only 2 parts, but the code checks < 4
        // Actually parts.len() < 4 returns error
        let result = NpmHandler::parse_path("@types/node");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scoped_path_three_parts_no_dash() {
        // @scope/package/extra - 3 parts, still < 4
        let result = NpmHandler::parse_path("@types/node/x");
        assert!(result.is_err());
    }

    // ---- extract_version_from_filename ----

    #[test]
    fn test_extract_version_simple() {
        let v = NpmHandler::extract_version_from_filename("lodash-4.17.21.tgz", "lodash").unwrap();
        assert_eq!(v, "4.17.21");
    }

    #[test]
    fn test_extract_version_prerelease() {
        let v =
            NpmHandler::extract_version_from_filename("react-18.0.0-rc.1.tgz", "react").unwrap();
        assert_eq!(v, "18.0.0-rc.1");
    }

    #[test]
    fn test_extract_version_wrong_prefix() {
        let result = NpmHandler::extract_version_from_filename("wrongname-1.0.0.tgz", "lodash");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_version_wrong_suffix() {
        let result = NpmHandler::extract_version_from_filename("lodash-1.0.0.tar.gz", "lodash");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_version_empty_filename() {
        let result = NpmHandler::extract_version_from_filename("", "lodash");
        assert!(result.is_err());
    }

    // ---- parse_path: unscoped with extra subpaths ----

    #[test]
    fn test_parse_unscoped_metadata_only_name() {
        let info = NpmHandler::parse_path("express").unwrap();
        assert_eq!(info.name, "express");
        assert_eq!(info.full_name, "express");
        assert!(!info.is_tarball);
        assert!(info.version.is_none());
    }

    #[test]
    fn test_parse_unscoped_with_non_dash_segment() {
        // package/something where something != "-"
        let info = NpmHandler::parse_path("lodash/latest").unwrap();
        assert_eq!(info.name, "lodash");
        assert!(!info.is_tarball);
        assert!(info.version.is_none());
    }

    // ---- extract_package_json: error cases ----

    #[test]
    fn test_extract_package_json_not_gzip() {
        let result = NpmHandler::extract_package_json(b"not a tarball");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_package_json_empty() {
        let result = NpmHandler::extract_package_json(b"");
        assert!(result.is_err());
    }

    // ---- generate_packument ----

    #[test]
    fn test_generate_packument_single_version() {
        let pkg = PackageJson {
            name: "my-pkg".to_string(),
            version: "1.0.0".to_string(),
            description: Some("A test package".to_string()),
            main: Some("index.js".to_string()),
            module: None,
            types: None,
            keywords: Some(vec!["test".to_string()]),
            author: None,
            license: Some("MIT".to_string()),
            repository: None,
            bugs: None,
            homepage: None,
            dependencies: Some({
                let mut m = std::collections::HashMap::new();
                m.insert("lodash".to_string(), "^4.0.0".to_string());
                m
            }),
            dev_dependencies: None,
            peer_dependencies: None,
            engines: None,
            scripts: None,
        };

        let packument = generate_packument(
            "my-pkg",
            vec![(
                "1.0.0".to_string(),
                pkg,
                "https://example.com/my-pkg-1.0.0.tgz".to_string(),
                "abc123".to_string(),
            )],
        );

        assert_eq!(packument.name, "my-pkg");
        assert_eq!(
            packument.dist_tags.get("latest"),
            Some(&"1.0.0".to_string())
        );
        assert!(packument.versions.contains_key("1.0.0"));
        let v = &packument.versions["1.0.0"];
        assert_eq!(v.name, "my-pkg");
        assert_eq!(v.version, "1.0.0");
        assert_eq!(v.description, Some("A test package".to_string()));
        assert_eq!(v.dist.tarball, "https://example.com/my-pkg-1.0.0.tgz");
        assert_eq!(v.dist.shasum, "abc123");
        assert!(v.dist.integrity.is_none());
        assert!(packument.time.contains_key("1.0.0"));
    }

    #[test]
    fn test_generate_packument_multiple_versions() {
        let make_pkg = |v: &str| PackageJson {
            name: "my-pkg".to_string(),
            version: v.to_string(),
            description: None,
            main: None,
            module: None,
            types: None,
            keywords: None,
            author: None,
            license: None,
            repository: None,
            bugs: None,
            homepage: None,
            dependencies: None,
            dev_dependencies: None,
            peer_dependencies: None,
            engines: None,
            scripts: None,
        };

        let packument = generate_packument(
            "my-pkg",
            vec![
                (
                    "1.0.0".to_string(),
                    make_pkg("1.0.0"),
                    "https://example.com/1.tgz".to_string(),
                    "aaa".to_string(),
                ),
                (
                    "2.0.0".to_string(),
                    make_pkg("2.0.0"),
                    "https://example.com/2.tgz".to_string(),
                    "bbb".to_string(),
                ),
            ],
        );

        // "latest" should be the last version processed
        assert_eq!(
            packument.dist_tags.get("latest"),
            Some(&"2.0.0".to_string())
        );
        assert_eq!(packument.versions.len(), 2);
        assert!(packument.versions.contains_key("1.0.0"));
        assert!(packument.versions.contains_key("2.0.0"));
    }

    #[test]
    fn test_generate_packument_empty_versions() {
        let packument = generate_packument("empty-pkg", vec![]);
        assert_eq!(packument.name, "empty-pkg");
        assert_eq!(packument.dist_tags.get("latest"), Some(&String::new()));
        assert!(packument.versions.is_empty());
    }

    // ---- PackageJson serde ----

    #[test]
    fn test_package_json_deserialize_full() {
        let json = r#"{
            "name": "test-pkg",
            "version": "1.0.0",
            "description": "A test",
            "main": "index.js",
            "module": "index.mjs",
            "types": "index.d.ts",
            "keywords": ["test"],
            "author": "John Doe",
            "license": "MIT",
            "repository": "https://github.com/user/repo",
            "bugs": {"url": "https://github.com/user/repo/issues"},
            "homepage": "https://example.com",
            "dependencies": {"lodash": "^4.0"},
            "devDependencies": {"jest": "^29.0"},
            "peerDependencies": {"react": "^18.0"},
            "engines": {"node": ">=18.0"},
            "scripts": {"test": "jest"}
        }"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert_eq!(pkg.name, "test-pkg");
        assert_eq!(pkg.version, "1.0.0");
        assert_eq!(pkg.description, Some("A test".to_string()));
        assert_eq!(pkg.main, Some("index.js".to_string()));
        assert_eq!(pkg.module, Some("index.mjs".to_string()));
        assert_eq!(pkg.types, Some("index.d.ts".to_string()));
        assert_eq!(pkg.keywords, Some(vec!["test".to_string()]));
        assert_eq!(pkg.license, Some("MIT".to_string()));
        assert_eq!(pkg.homepage, Some("https://example.com".to_string()));
        assert!(pkg.dependencies.is_some());
        assert!(pkg.dev_dependencies.is_some());
        assert!(pkg.peer_dependencies.is_some());
        assert!(pkg.engines.is_some());
        assert!(pkg.scripts.is_some());
    }

    #[test]
    fn test_package_json_author_string() {
        let json = r#"{"name":"p","version":"1.0.0","author":"John"}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert!(matches!(pkg.author, Some(PackageAuthor::String(_))));
    }

    #[test]
    fn test_package_json_author_object() {
        let json = r#"{"name":"p","version":"1.0.0","author":{"name":"John","email":"john@example.com","url":"https://john.com"}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        match pkg.author {
            Some(PackageAuthor::Object { name, email, url }) => {
                assert_eq!(name, "John");
                assert_eq!(email, Some("john@example.com".to_string()));
                assert_eq!(url, Some("https://john.com".to_string()));
            }
            _ => panic!("Expected PackageAuthor::Object"),
        }
    }

    #[test]
    fn test_package_repository_string() {
        let json = r#"{"name":"p","version":"1.0.0","repository":"https://github.com/user/repo"}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert!(matches!(pkg.repository, Some(PackageRepository::String(_))));
    }

    #[test]
    fn test_package_repository_object() {
        let json = r#"{"name":"p","version":"1.0.0","repository":{"type":"git","url":"https://github.com/user/repo","directory":"packages/core"}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        match pkg.repository {
            Some(PackageRepository::Object {
                repo_type,
                url,
                directory,
            }) => {
                assert_eq!(repo_type, Some("git".to_string()));
                assert_eq!(url, "https://github.com/user/repo");
                assert_eq!(directory, Some("packages/core".to_string()));
            }
            _ => panic!("Expected PackageRepository::Object"),
        }
    }

    #[test]
    fn test_package_bugs_deserialize() {
        let json = r#"{"url":"https://github.com/user/repo/issues","email":"bugs@example.com"}"#;
        let bugs: PackageBugs = serde_json::from_str(json).unwrap();
        assert_eq!(
            bugs.url,
            Some("https://github.com/user/repo/issues".to_string())
        );
        assert_eq!(bugs.email, Some("bugs@example.com".to_string()));
    }

    // ---- PackageJson minimal ----

    #[test]
    fn test_package_json_minimal() {
        let json = r#"{"name":"minimal","version":"0.0.1"}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert_eq!(pkg.name, "minimal");
        assert_eq!(pkg.version, "0.0.1");
        assert!(pkg.description.is_none());
        assert!(pkg.main.is_none());
        assert!(pkg.author.is_none());
        assert!(pkg.license.is_none());
        assert!(pkg.dependencies.is_none());
    }

    // ---- Packument serde ----

    #[test]
    fn test_packument_serialization_roundtrip() {
        let packument = Packument {
            name: "test".to_string(),
            description: Some("desc".to_string()),
            dist_tags: {
                let mut m = std::collections::HashMap::new();
                m.insert("latest".to_string(), "1.0.0".to_string());
                m
            },
            versions: std::collections::HashMap::new(),
            time: std::collections::HashMap::new(),
            maintainers: vec![PackumentMaintainer {
                name: "dev".to_string(),
                email: Some("dev@example.com".to_string()),
            }],
            keywords: Some(vec!["test".to_string()]),
            license: Some("MIT".to_string()),
            readme: Some("# Test".to_string()),
        };
        let json = serde_json::to_string(&packument).unwrap();
        let parsed: Packument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.dist_tags.get("latest"), Some(&"1.0.0".to_string()));
        assert_eq!(parsed.maintainers.len(), 1);
    }

    // -----------------------------------------------------------------
    // is_valid_npm_name / package_name_from_tarball_path
    // (#1217 follow-up, ak-hv3s shadowing guard)
    // -----------------------------------------------------------------

    #[test]
    fn test_is_valid_npm_name_accepts_real_world() {
        assert!(is_valid_npm_name("lodash"));
        assert!(is_valid_npm_name("express"));
        assert!(is_valid_npm_name("body-parser"));
        assert!(is_valid_npm_name("source.map"));
        assert!(is_valid_npm_name("@types/node"));
        assert!(is_valid_npm_name("@angular/core"));
        assert!(is_valid_npm_name("a"));
    }

    #[test]
    fn test_is_valid_npm_name_rejects_invalid() {
        assert!(!is_valid_npm_name(""));
        assert!(!is_valid_npm_name("@/foo")); // empty scope
        assert!(!is_valid_npm_name("@scope/")); // empty pkg
        assert!(!is_valid_npm_name("@scope")); // no slash
        assert!(!is_valid_npm_name("Foo")); // uppercase
        assert!(!is_valid_npm_name("foo bar")); // space
        assert!(!is_valid_npm_name("foo/bar")); // unscoped slash
        assert!(!is_valid_npm_name("../foo")); // traversal
                                               // 215 chars
        let too_long = "a".repeat(215);
        assert!(!is_valid_npm_name(&too_long));
    }

    #[test]
    fn test_package_name_from_tarball_path_unscoped() {
        assert_eq!(
            package_name_from_tarball_path("lodash/-/lodash-4.17.21.tgz"),
            Some("lodash".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_path_hyphenated() {
        assert_eq!(
            package_name_from_tarball_path("body-parser/-/body-parser-1.20.2.tgz"),
            Some("body-parser".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_path_scoped() {
        assert_eq!(
            package_name_from_tarball_path("@types/node/-/node-20.0.0.tgz"),
            Some("@types/node".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_path_uppercase_lowered() {
        // npm lower-cases names; the guard must lower the candidate so
        // it matches what `artifacts.name` stores and what SQL `LOWER()`
        // produces.
        assert_eq!(
            package_name_from_tarball_path("LODASH/-/lodash-4.17.21.tgz"),
            Some("lodash".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_path_rejects_malformed() {
        assert_eq!(package_name_from_tarball_path(""), None);
        assert_eq!(package_name_from_tarball_path("foo"), None);
        assert_eq!(package_name_from_tarball_path("foo/-/"), None);
        // Path traversal in the name segment must be rejected.
        assert_eq!(package_name_from_tarball_path("../-/foo-1.0.tgz"), None);
    }

    #[test]
    fn test_package_name_from_tarball_path_rejects_unicode_homoglyphs() {
        // Cyrillic 'о' homoglyph must not parse.
        assert_eq!(
            package_name_from_tarball_path("l\u{043e}dash/-/lodash-4.17.21.tgz"),
            None
        );
    }

    // -----------------------------------------------------------------------
    // #1443: normalize_lookup_path round-trips the npm tarball URL shape
    // (<name>/-/<name>-<ver>.tgz) into the stored DB path shape that the
    // publish handler writes (<name>/<ver>/<name>-<ver>.tgz).
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_lookup_path_unscoped_tarball() {
        assert_eq!(
            normalize_lookup_path("lodash/-/lodash-4.17.21.tgz"),
            Some("lodash/4.17.21/lodash-4.17.21.tgz".to_string())
        );
    }

    #[test]
    fn test_normalize_lookup_path_scoped_tarball() {
        assert_eq!(
            normalize_lookup_path("@angular/core/-/core-17.0.0.tgz"),
            Some("@angular/core/17.0.0/core-17.0.0.tgz".to_string())
        );
    }

    #[test]
    fn test_normalize_lookup_path_strips_leading_slash() {
        assert_eq!(
            normalize_lookup_path("/lodash/-/lodash-4.17.21.tgz"),
            Some("lodash/4.17.21/lodash-4.17.21.tgz".to_string())
        );
    }

    #[test]
    fn test_normalize_lookup_path_prerelease_version() {
        assert_eq!(
            normalize_lookup_path("foo/-/foo-1.0.0-rc.1.tgz"),
            Some("foo/1.0.0-rc.1/foo-1.0.0-rc.1.tgz".to_string())
        );
    }

    #[test]
    fn test_normalize_lookup_path_release_gate_pkg_shape() {
        // Mirrors what test-real-flow-smoke.sh observes: the path npm
        // publishes through is the URL shape; the path that gets stored
        // is the version-segmented shape.
        let url_shape = "rfs-pkg-e2e1779850088106/-/rfs-pkg-e2e1779850088106-1.0.1779850372.tgz";
        let stored =
            "rfs-pkg-e2e1779850088106/1.0.1779850372/rfs-pkg-e2e1779850088106-1.0.1779850372.tgz";
        assert_eq!(normalize_lookup_path(url_shape), Some(stored.to_string()));
    }

    #[test]
    fn test_normalize_lookup_path_returns_none_for_metadata_path() {
        // Non-tarball lookups must not be rewritten; they're already
        // stored verbatim (or simply don't exist as artifact rows).
        assert_eq!(normalize_lookup_path("lodash"), None);
        assert_eq!(normalize_lookup_path("lodash/package.json"), None);
        assert_eq!(normalize_lookup_path("@types/node"), None);
    }

    #[test]
    fn test_normalize_lookup_path_returns_none_for_already_stored_shape() {
        // A path that is already in the stored shape (4 segments
        // unscoped, 5 segments scoped, no `-/` marker) is left alone so
        // the caller can issue an exact-match lookup with it directly.
        assert_eq!(
            normalize_lookup_path("lodash/4.17.21/lodash-4.17.21.tgz"),
            None
        );
        assert_eq!(
            normalize_lookup_path("@angular/core/17.0.0/core-17.0.0.tgz"),
            None
        );
    }

    #[test]
    fn test_normalize_lookup_path_returns_none_when_filename_mismatches_name() {
        // If `<name>-` does not prefix the filename we can't infer the
        // version, so refuse rather than emit a broken path.
        assert_eq!(normalize_lookup_path("foo/-/bar-1.0.0.tgz"), None);
    }

    #[test]
    fn test_normalize_lookup_path_returns_none_for_non_tgz_extension() {
        assert_eq!(normalize_lookup_path("foo/-/foo-1.0.0.zip"), None);
    }
}
