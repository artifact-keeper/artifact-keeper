//! RubyGems format handler.
//!
//! Implements RubyGems repository for Ruby gems.
//! Supports parsing .gem files and generating gem indices.

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::io::Read;
use tar::Archive;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// RubyGems format handler
pub struct RubygemsHandler;

impl RubygemsHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse RubyGems path
    /// Formats:
    ///   gems/<name>-<version>.gem           - Gem package
    ///   quick/Marshal.4.8/<name>-<version>.gemspec.rz  - Quick index
    ///   specs.4.8.gz                        - Specs index
    ///   latest_specs.4.8.gz                 - Latest specs index
    ///   prerelease_specs.4.8.gz             - Prerelease specs index
    ///   api/v1/gems/<name>.json             - Gem info (JSON API)
    ///   api/v1/versions/<name>.json         - Gem versions
    ///   api/v1/dependencies                 - Dependencies query
    pub fn parse_path(path: &str) -> Result<RubygemsPathInfo> {
        let path = path.trim_start_matches('/');

        // Specs indices
        if path.ends_with("specs.4.8.gz") || path.ends_with("specs.4.8") {
            let is_latest = path.contains("latest_");
            let is_prerelease = path.contains("prerelease_");
            return Ok(RubygemsPathInfo {
                name: None,
                version: None,
                platform: None,
                operation: if is_latest {
                    RubygemsOperation::LatestSpecs
                } else if is_prerelease {
                    RubygemsOperation::PrereleaseSpecs
                } else {
                    RubygemsOperation::Specs
                },
            });
        }

        // Gem package
        if path.ends_with(".gem") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            let (name, version, platform) = Self::parse_gem_filename(filename)?;
            return Ok(RubygemsPathInfo {
                name: Some(name),
                version: Some(version),
                platform,
                operation: RubygemsOperation::Gem,
            });
        }

        // Quick index
        if path.contains("quick/Marshal") && path.ends_with(".gemspec.rz") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            let gemspec_name = filename.trim_end_matches(".gemspec.rz");
            let (name, version, platform) = Self::parse_gemspec_name(gemspec_name)?;
            return Ok(RubygemsPathInfo {
                name: Some(name),
                version: Some(version),
                platform,
                operation: RubygemsOperation::QuickIndex,
            });
        }

        // API endpoints
        if path.starts_with("api/v1/") {
            if path.starts_with("api/v1/gems/") {
                let name = path
                    .trim_start_matches("api/v1/gems/")
                    .trim_end_matches(".json");
                return Ok(RubygemsPathInfo {
                    name: Some(name.to_string()),
                    version: None,
                    platform: None,
                    operation: RubygemsOperation::GemInfo,
                });
            }

            if path.starts_with("api/v1/versions/") {
                let name = path
                    .trim_start_matches("api/v1/versions/")
                    .trim_end_matches(".json");
                return Ok(RubygemsPathInfo {
                    name: Some(name.to_string()),
                    version: None,
                    platform: None,
                    operation: RubygemsOperation::Versions,
                });
            }

            if path.starts_with("api/v1/dependencies") {
                return Ok(RubygemsPathInfo {
                    name: None,
                    version: None,
                    platform: None,
                    operation: RubygemsOperation::Dependencies,
                });
            }
        }

        Err(AppError::Validation(format!(
            "Invalid RubyGems path: {}",
            path
        )))
    }

    /// Parse gem filename
    /// Format: <name>-<version>(-<platform>)?.gem
    fn parse_gem_filename(filename: &str) -> Result<(String, String, Option<String>)> {
        let name = filename.trim_end_matches(".gem");
        Self::parse_gemspec_name(name)
    }

    /// Parse gemspec name (also used for gem filename without extension)
    fn parse_gemspec_name(name: &str) -> Result<(String, String, Option<String>)> {
        // Try to find version - it starts with a digit after a hyphen
        let parts: Vec<&str> = name.split('-').collect();

        if parts.len() < 2 {
            return Err(AppError::Validation(format!(
                "Invalid gem name format: {}",
                name
            )));
        }

        // Find where version starts
        let mut name_parts = Vec::new();
        let mut version_parts = Vec::new();
        let mut found_version = false;

        for part in &parts {
            if !found_version
                && part
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
                found_version = true;
            }

            if found_version {
                version_parts.push(*part);
            } else {
                name_parts.push(*part);
            }
        }

        if name_parts.is_empty() || version_parts.is_empty() {
            return Err(AppError::Validation(format!(
                "Invalid gem name format: {}",
                name
            )));
        }

        let gem_name = name_parts.join("-");

        // Check for platform (e.g., "java", "x86_64-linux")
        // Platform can span multiple parts (e.g., "x86_64-linux" = ["x86_64", "linux"])
        let (version, platform) = if version_parts.len() > 1 {
            // Try joining last N parts to check for known platforms
            let mut platform_found = None;
            for n in (1..=std::cmp::min(3, version_parts.len() - 1)).rev() {
                let candidate = version_parts[version_parts.len() - n..].join("-");
                if Self::is_platform(&candidate) {
                    platform_found = Some((n, candidate));
                    break;
                }
            }

            if let Some((n, platform)) = platform_found {
                let version = version_parts[..version_parts.len() - n].join("-");
                (version, Some(platform))
            } else {
                (version_parts.join("-"), None)
            }
        } else {
            (version_parts.join("-"), None)
        };

        Ok((gem_name, version, platform))
    }

    /// Check if a string looks like a platform
    fn is_platform(s: &str) -> bool {
        let known_platforms = [
            "ruby",
            "java",
            "jruby",
            "mswin32",
            "mswin64",
            "mingw32",
            "mingw64",
            "x86-mingw32",
            "x64-mingw32",
            "x86_64-linux",
            "x86-linux",
            "aarch64-linux",
            "arm64-darwin",
            "x86_64-darwin",
        ];

        // Check known platforms
        if known_platforms.iter().any(|&p| s == p || s.contains(p)) {
            return true;
        }

        // Check pattern: arch-os
        if s.contains('-') && !s.chars().next().unwrap_or('_').is_ascii_digit() {
            return true;
        }

        false
    }

    /// Extract gemspec from .gem file
    /// .gem files are tar archives containing metadata.gz and data.tar.gz
    pub fn extract_gemspec(content: &[u8]) -> Result<GemSpec> {
        let mut archive = Archive::new(content);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid gem file: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid gem entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in gem: {}", e)))?;

            if path.to_string_lossy() == "metadata.gz" {
                let mut compressed = Vec::new();
                entry.read_to_end(&mut compressed).map_err(|e| {
                    AppError::Validation(format!("Failed to read metadata.gz: {}", e))
                })?;

                let mut decoder = GzDecoder::new(&compressed[..]);
                let mut yaml_content = String::new();
                decoder.read_to_string(&mut yaml_content).map_err(|e| {
                    AppError::Validation(format!("Failed to decompress metadata: {}", e))
                })?;

                return Self::parse_gemspec_yaml(&yaml_content);
            }
        }

        Err(AppError::Validation(
            "metadata.gz not found in gem file".to_string(),
        ))
    }

    /// Parse gemspec YAML content
    pub fn parse_gemspec_yaml(content: &str) -> Result<GemSpec> {
        // Ruby's gemspec format uses YAML with custom tags like !ruby/object:Gem::Version.
        // The version field is structured as:
        //   version: !ruby/object:Gem::Version
        //     version: 1.0.0
        // We use indentation level to distinguish top-level fields from nested ones.
        let mut gemspec = GemSpec::default();
        let mut expect_nested_version = false;

        for raw_line in content.lines() {
            let indent = raw_line.len() - raw_line.trim_start().len();
            let line = raw_line.trim();

            if line.is_empty() || line.starts_with("---") || line.starts_with('#') {
                continue;
            }

            // Top-level fields have 0 indent in gemspec YAML
            if indent == 0 {
                expect_nested_version = false;
                if let Some(rest) = line.strip_prefix("name:") {
                    gemspec.name = rest.trim().trim_matches('"').to_string();
                } else if let Some(rest) = line.strip_prefix("version:") {
                    let trimmed = rest.trim().trim_matches('"').trim_matches('\'');
                    if trimmed.starts_with("!ruby/") {
                        expect_nested_version = true;
                    } else if !trimmed.is_empty() {
                        gemspec.version = trimmed.to_string();
                    }
                } else if let Some(rest) = line.strip_prefix("platform:") {
                    let platform = rest.trim().trim_matches('"');
                    if platform != "ruby" && !platform.is_empty() {
                        gemspec.platform = Some(platform.to_string());
                    }
                } else if let Some(rest) = line.strip_prefix("summary:") {
                    gemspec.summary = Some(rest.trim().trim_matches('"').to_string());
                } else if let Some(rest) = line.strip_prefix("description:") {
                    gemspec.description = Some(rest.trim().trim_matches('"').to_string());
                } else if let Some(rest) = line.strip_prefix("homepage:") {
                    gemspec.homepage = Some(rest.trim().trim_matches('"').to_string());
                } else if let Some(rest) = line.strip_prefix("license:") {
                    gemspec.license = Some(rest.trim().trim_matches('"').to_string());
                }
            } else if expect_nested_version && gemspec.version.is_empty() {
                // Indented line right after "version: !ruby/object:Gem::Version"
                if let Some(rest) = line.strip_prefix("version:") {
                    let ver = rest.trim().trim_matches('"').trim_matches('\'');
                    if !ver.is_empty() {
                        gemspec.version = ver.to_string();
                        expect_nested_version = false;
                    }
                }
            }
        }

        if gemspec.name.is_empty() {
            return Err(AppError::Validation(
                "Gemspec missing name field".to_string(),
            ));
        }

        Ok(gemspec)
    }
}

/// Parse the gem name out of a `<name>-<version>[-<platform>].gem` filename.
///
/// Returns `None` if the filename does not parse as a gem (no `.gem`
/// extension, no version separator, or the resulting name fails
/// [`is_valid_rubygems_name`]). The case-insensitive `.gem` extension match
/// is load-bearing for the shadowing guard. Without it, an attacker
/// requesting `rails-7.0.gem` vs `rails-7.0.GEM` could bypass the guard.
///
/// Cross-format shadowing guard primitive (#1217 follow-up, ak-hv3s).
/// Mirrors the hex parser shape: parse with fail-closed semantics, then
/// hand the result to [`crate::api::handlers::proxy_helpers::
/// virtual_non_remote_owns_name`].
pub(crate) fn package_name_from_gem_filename(filename: &str) -> Option<String> {
    let lowered = filename.to_ascii_lowercase();
    let without_ext = lowered.strip_suffix(".gem")?;
    for (i, _) in without_ext.match_indices('-') {
        if without_ext
            .get(i + 1..)
            .is_some_and(|s| s.starts_with(|c: char| c.is_ascii_digit()))
        {
            let candidate = &without_ext[..i];
            if is_valid_rubygems_name(candidate) {
                return Some(candidate.to_string());
            }
            return None;
        }
    }
    None
}

/// Validate a gem name. RubyGems names match `[A-Za-z0-9._-]+` and may
/// not start with `.` or `-`. The shadowing guard lowercases via Postgres
/// `LOWER()`, so we restrict to ASCII to avoid homoglyph attacks where
/// SQL `LOWER()` and Rust `to_ascii_lowercase` disagree.
///
/// We deliberately reject the dot character even though it is permitted
/// by the spec: real gem names in the top-million almost never contain
/// dots and accepting them would let `..` slip through the path-traversal
/// gate. Operators publishing dot-named gems will hit the validator on
/// download; they can upload, just not benefit from the shadowing guard
/// on the dot-name. The fail-closed default returns `None` (no guard
/// fires) for dot-named filenames so behavior matches pre-#1217.
pub(crate) fn is_valid_rubygems_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

impl Default for RubygemsHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for RubygemsHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Rubygems
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

        if let Some(platform) = &info.platform {
            metadata["platform"] = serde_json::Value::String(platform.clone());
        }

        // Extract gemspec if this is a gem file
        if !content.is_empty() && matches!(info.operation, RubygemsOperation::Gem) {
            if let Ok(gemspec) = Self::extract_gemspec(content) {
                metadata["gemspec"] = serde_json::to_value(&gemspec)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate gem packages
        if !content.is_empty() && matches!(info.operation, RubygemsOperation::Gem) {
            let gemspec = Self::extract_gemspec(content)?;

            // Verify name matches
            if let Some(path_name) = &info.name {
                if &gemspec.name != path_name {
                    return Err(AppError::Validation(format!(
                        "Gem name mismatch: path says '{}' but gemspec says '{}'",
                        path_name, gemspec.name
                    )));
                }
            }

            // Verify version matches
            if let Some(path_version) = &info.version {
                if &gemspec.version != path_version {
                    return Err(AppError::Validation(format!(
                        "Version mismatch: path says '{}' but gemspec says '{}'",
                        path_version, gemspec.version
                    )));
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Indices are generated on demand
        Ok(None)
    }
}

/// RubyGems path info
#[derive(Debug)]
pub struct RubygemsPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub platform: Option<String>,
    pub operation: RubygemsOperation,
}

/// RubyGems operation type
#[derive(Debug)]
pub enum RubygemsOperation {
    Gem,
    QuickIndex,
    Specs,
    LatestSpecs,
    PrereleaseSpecs,
    GemInfo,
    Versions,
    Dependencies,
}

/// Gemspec structure
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GemSpec {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub authors: Option<Vec<String>>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub licenses: Option<Vec<String>>,
    #[serde(default)]
    pub required_ruby_version: Option<String>,
    #[serde(default)]
    pub dependencies: Option<Vec<GemDependency>>,
}

/// Gem dependency
#[derive(Debug, Serialize, Deserialize)]
pub struct GemDependency {
    pub name: String,
    pub requirements: String,
    #[serde(default)]
    pub dep_type: String,
}

/// Gem info (JSON API response)
#[derive(Debug, Serialize, Deserialize)]
pub struct GemInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub authors: String,
    #[serde(default)]
    pub info: String,
    #[serde(default)]
    pub licenses: Vec<String>,
    #[serde(default)]
    pub homepage_uri: Option<String>,
    #[serde(default)]
    pub source_code_uri: Option<String>,
    #[serde(default)]
    pub documentation_uri: Option<String>,
    pub downloads: u64,
    pub version_downloads: u64,
    #[serde(default)]
    pub sha: Option<String>,
    #[serde(default)]
    pub dependencies: GemDependencies,
}

/// Gem dependencies by type
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GemDependencies {
    #[serde(default)]
    pub runtime: Vec<DependencyInfo>,
    #[serde(default)]
    pub development: Vec<DependencyInfo>,
}

/// Dependency info
#[derive(Debug, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub name: String,
    pub requirements: String,
}

/// Specs entry (for specs.4.8 index)
#[derive(Debug, Serialize, Deserialize)]
pub struct SpecsEntry {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub platform: String,
}

/// Generate gem info JSON
pub fn generate_gem_info(gemspec: &GemSpec, sha256: &str, downloads: u64) -> GemInfo {
    GemInfo {
        name: gemspec.name.clone(),
        version: gemspec.version.clone(),
        platform: gemspec.platform.clone(),
        authors: gemspec
            .authors
            .as_ref()
            .map(|a| a.join(", "))
            .unwrap_or_default(),
        info: gemspec.description.clone().unwrap_or_default(),
        licenses: gemspec.licenses.clone().unwrap_or_default(),
        homepage_uri: gemspec.homepage.clone(),
        source_code_uri: None,
        documentation_uri: None,
        downloads,
        version_downloads: downloads,
        sha: Some(sha256.to_string()),
        dependencies: GemDependencies::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // parse_gem_filename tests
    // ========================================================================

    #[test]
    fn test_parse_gem_filename() {
        let (name, version, platform) =
            RubygemsHandler::parse_gem_filename("rails-7.0.8.gem").unwrap();
        assert_eq!(name, "rails");
        assert_eq!(version, "7.0.8");
        assert_eq!(platform, None);
    }

    #[test]
    fn test_parse_gem_filename_with_platform() {
        let (name, version, platform) =
            RubygemsHandler::parse_gem_filename("nokogiri-1.15.4-x86_64-linux.gem").unwrap();
        assert_eq!(name, "nokogiri");
        assert_eq!(version, "1.15.4");
        assert_eq!(platform, Some("x86_64-linux".to_string()));
    }

    #[test]
    fn test_parse_gem_filename_hyphenated() {
        let (name, version, platform) =
            RubygemsHandler::parse_gem_filename("aws-sdk-s3-1.140.0.gem").unwrap();
        assert_eq!(name, "aws-sdk-s3");
        assert_eq!(version, "1.140.0");
        assert_eq!(platform, None);
    }

    #[test]
    fn test_parse_gem_filename_java_platform() {
        let (name, version, platform) =
            RubygemsHandler::parse_gem_filename("jruby-openssl-0.14.0-java.gem").unwrap();
        assert_eq!(name, "jruby-openssl");
        assert_eq!(version, "0.14.0");
        assert_eq!(platform, Some("java".to_string()));
    }

    #[test]
    fn test_parse_gem_filename_mingw32_platform() {
        let (name, version, platform) =
            RubygemsHandler::parse_gem_filename("ffi-1.15.5-x86-mingw32.gem").unwrap();
        assert_eq!(name, "ffi");
        assert_eq!(version, "1.15.5");
        assert_eq!(platform, Some("x86-mingw32".to_string()));
    }

    #[test]
    fn test_parse_gem_filename_arm64_darwin() {
        let (name, version, platform) =
            RubygemsHandler::parse_gem_filename("grpc-1.50.0-arm64-darwin.gem").unwrap();
        assert_eq!(name, "grpc");
        assert_eq!(version, "1.50.0");
        assert_eq!(platform, Some("arm64-darwin".to_string()));
    }

    #[test]
    fn test_parse_gem_filename_no_hyphen() {
        // Only one part (no hyphen), should fail
        let result = RubygemsHandler::parse_gem_filename("singlename.gem");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gem_filename_no_version_digits() {
        // All parts start with non-digit: name_parts takes everything, version_parts empty
        let result = RubygemsHandler::parse_gem_filename("abc-def-ghi.gem");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gem_filename_simple_version() {
        let (name, version, platform) =
            RubygemsHandler::parse_gem_filename("rake-13.0.6.gem").unwrap();
        assert_eq!(name, "rake");
        assert_eq!(version, "13.0.6");
        assert_eq!(platform, None);
    }

    #[test]
    fn test_parse_gem_filename_prerelease_version() {
        let (name, version, platform) =
            RubygemsHandler::parse_gem_filename("rails-7.1.0.beta1.gem").unwrap();
        assert_eq!(name, "rails");
        // "7.1.0.beta1" - after splitting on '-', "7" starts the version,
        // then "beta1" doesn't match version start so it becomes part of version
        // Actually "7.1.0.beta1" is a single part after "rails" with no extra hyphens
        assert_eq!(version, "7.1.0.beta1");
        assert_eq!(platform, None);
    }

    // ========================================================================
    // parse_gemspec_name tests (indirectly via parse_gem_filename)
    // ========================================================================

    #[test]
    fn test_parse_gemspec_name_version_starts_with_digit() {
        // The version detection looks for a part starting with an ASCII digit
        let (name, version, _) = RubygemsHandler::parse_gem_filename("my-gem-2.0.gem").unwrap();
        assert_eq!(name, "my-gem");
        assert_eq!(version, "2.0");
    }

    // ========================================================================
    // is_platform tests (indirectly via parse_gem_filename)
    // ========================================================================

    #[test]
    fn test_is_platform_known() {
        assert!(RubygemsHandler::is_platform("java"));
        assert!(RubygemsHandler::is_platform("jruby"));
        assert!(RubygemsHandler::is_platform("mswin32"));
        assert!(RubygemsHandler::is_platform("mswin64"));
        assert!(RubygemsHandler::is_platform("mingw32"));
        assert!(RubygemsHandler::is_platform("mingw64"));
        assert!(RubygemsHandler::is_platform("x86-mingw32"));
        assert!(RubygemsHandler::is_platform("x64-mingw32"));
        assert!(RubygemsHandler::is_platform("x86_64-linux"));
        assert!(RubygemsHandler::is_platform("x86-linux"));
        assert!(RubygemsHandler::is_platform("aarch64-linux"));
        assert!(RubygemsHandler::is_platform("arm64-darwin"));
        assert!(RubygemsHandler::is_platform("x86_64-darwin"));
    }

    #[test]
    fn test_is_platform_ruby() {
        // "ruby" is in the known list
        assert!(RubygemsHandler::is_platform("ruby"));
    }

    #[test]
    fn test_is_platform_unknown_no_hyphen() {
        // No hyphen and not in known list, first char doesn't matter
        assert!(!RubygemsHandler::is_platform("something"));
    }

    #[test]
    fn test_is_platform_pattern_match_with_hyphen() {
        // Has a hyphen and first char is not a digit -> treated as platform
        assert!(RubygemsHandler::is_platform("unknown-os"));
    }

    #[test]
    fn test_is_platform_digit_start_with_hyphen() {
        // First char is a digit and has a hyphen; returns false (unless it matches known)
        assert!(!RubygemsHandler::is_platform("1-something"));
    }

    // ========================================================================
    // parse_path tests
    // ========================================================================

    #[test]
    fn test_parse_path_gem() {
        let info = RubygemsHandler::parse_path("gems/rails-7.0.8.gem").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::Gem));
        assert_eq!(info.name, Some("rails".to_string()));
        assert_eq!(info.version, Some("7.0.8".to_string()));
    }

    #[test]
    fn test_parse_path_specs() {
        let info = RubygemsHandler::parse_path("specs.4.8.gz").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::Specs));
        assert!(info.name.is_none());
    }

    #[test]
    fn test_parse_path_specs_uncompressed() {
        let info = RubygemsHandler::parse_path("specs.4.8").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::Specs));
    }

    #[test]
    fn test_parse_path_latest_specs() {
        let info = RubygemsHandler::parse_path("latest_specs.4.8.gz").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::LatestSpecs));
    }

    #[test]
    fn test_parse_path_prerelease_specs() {
        let info = RubygemsHandler::parse_path("prerelease_specs.4.8.gz").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::PrereleaseSpecs));
    }

    #[test]
    fn test_parse_path_prerelease_specs_uncompressed() {
        let info = RubygemsHandler::parse_path("prerelease_specs.4.8").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::PrereleaseSpecs));
    }

    #[test]
    fn test_parse_path_quick_index() {
        let info = RubygemsHandler::parse_path("quick/Marshal.4.8/rails-7.0.8.gemspec.rz").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::QuickIndex));
        assert_eq!(info.name, Some("rails".to_string()));
        assert_eq!(info.version, Some("7.0.8".to_string()));
    }

    #[test]
    fn test_parse_path_quick_index_with_platform() {
        let info = RubygemsHandler::parse_path(
            "quick/Marshal.4.8/nokogiri-1.15.4-x86_64-linux.gemspec.rz",
        )
        .unwrap();
        assert!(matches!(info.operation, RubygemsOperation::QuickIndex));
        assert_eq!(info.name, Some("nokogiri".to_string()));
        assert_eq!(info.version, Some("1.15.4".to_string()));
        assert_eq!(info.platform, Some("x86_64-linux".to_string()));
    }

    #[test]
    fn test_parse_path_api() {
        let info = RubygemsHandler::parse_path("api/v1/gems/rails.json").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::GemInfo));
        assert_eq!(info.name, Some("rails".to_string()));
    }

    #[test]
    fn test_parse_path_api_versions() {
        let info = RubygemsHandler::parse_path("api/v1/versions/rails.json").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::Versions));
        assert_eq!(info.name, Some("rails".to_string()));
    }

    #[test]
    fn test_parse_path_api_dependencies() {
        let info = RubygemsHandler::parse_path("api/v1/dependencies").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::Dependencies));
        assert!(info.name.is_none());
    }

    #[test]
    fn test_parse_path_api_dependencies_with_query() {
        let info = RubygemsHandler::parse_path("api/v1/dependencies?gems=rails").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::Dependencies));
    }

    #[test]
    fn test_parse_path_invalid() {
        let result = RubygemsHandler::parse_path("unknown/path/here");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_leading_slash() {
        let info = RubygemsHandler::parse_path("/gems/rails-7.0.8.gem").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::Gem));
        assert_eq!(info.name, Some("rails".to_string()));
    }

    #[test]
    fn test_parse_path_direct_gem_file() {
        // A path ending in .gem but not under gems/ directory
        let info = RubygemsHandler::parse_path("some/path/rake-13.0.gem").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::Gem));
        assert_eq!(info.name, Some("rake".to_string()));
    }

    // ========================================================================
    // parse_gemspec_yaml tests
    // ========================================================================

    #[test]
    fn test_parse_gemspec_yaml_basic() {
        let content = r#"---
name: rails
version: 7.0.8
summary: Full-stack web framework
description: Ruby on Rails framework
homepage: https://rubyonrails.org
license: MIT
"#;
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.name, "rails");
        assert_eq!(spec.version, "7.0.8");
        assert_eq!(spec.summary, Some("Full-stack web framework".to_string()));
        assert_eq!(
            spec.description,
            Some("Ruby on Rails framework".to_string())
        );
        assert_eq!(spec.homepage, Some("https://rubyonrails.org".to_string()));
        assert_eq!(spec.license, Some("MIT".to_string()));
    }

    #[test]
    fn test_parse_gemspec_yaml_ruby_object_version() {
        let content = r#"---
name: mygem
version: !ruby/object:Gem::Version
  version: 2.3.1
summary: A gem
"#;
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.name, "mygem");
        assert_eq!(spec.version, "2.3.1");
    }

    #[test]
    fn test_parse_gemspec_yaml_quoted_values() {
        let content = r#"---
name: "my-gem"
version: "1.0.0"
summary: "A quoted summary"
"#;
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.name, "my-gem");
        assert_eq!(spec.version, "1.0.0");
        assert_eq!(spec.summary, Some("A quoted summary".to_string()));
    }

    #[test]
    fn test_parse_gemspec_yaml_missing_name() {
        let content = "---\nversion: 1.0.0\nsummary: No name\n";
        let result = RubygemsHandler::parse_gemspec_yaml(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gemspec_yaml_empty() {
        let result = RubygemsHandler::parse_gemspec_yaml("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gemspec_yaml_with_platform() {
        let content = "---\nname: mygem\nversion: 1.0.0\nplatform: x86_64-linux\n";
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.platform, Some("x86_64-linux".to_string()));
    }

    #[test]
    fn test_parse_gemspec_yaml_platform_ruby_ignored() {
        let content = "---\nname: mygem\nversion: 1.0.0\nplatform: ruby\n";
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.platform, None);
    }

    #[test]
    fn test_parse_gemspec_yaml_empty_platform() {
        let content = "---\nname: mygem\nversion: 1.0.0\nplatform: \n";
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.platform, None);
    }

    #[test]
    fn test_parse_gemspec_yaml_comments_and_blank_lines() {
        let content = r#"---
# This is a comment
name: mygem

version: 1.0.0
# Another comment
summary: A summary
"#;
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.name, "mygem");
        assert_eq!(spec.version, "1.0.0");
    }

    #[test]
    fn test_parse_gemspec_yaml_plain_version_no_ruby_object() {
        let content = "---\nname: simplgem\nversion: 3.2.1\n";
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.version, "3.2.1");
    }

    #[test]
    fn test_parse_gemspec_yaml_single_quoted_version() {
        let content = "---\nname: mygem\nversion: '4.5.6'\n";
        let spec = RubygemsHandler::parse_gemspec_yaml(content).unwrap();
        assert_eq!(spec.version, "4.5.6");
    }

    // ========================================================================
    // generate_gem_info tests
    // ========================================================================

    #[test]
    fn test_generate_gem_info_basic() {
        let gemspec = GemSpec {
            name: "mygem".to_string(),
            version: "1.0.0".to_string(),
            platform: None,
            authors: Some(vec!["Alice".to_string(), "Bob".to_string()]),
            email: None,
            summary: Some("A gem".to_string()),
            description: Some("A longer description".to_string()),
            homepage: Some("https://example.com".to_string()),
            license: Some("MIT".to_string()),
            licenses: Some(vec!["MIT".to_string()]),
            required_ruby_version: None,
            dependencies: None,
        };
        let info = generate_gem_info(&gemspec, "sha256hash", 100);
        assert_eq!(info.name, "mygem");
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.authors, "Alice, Bob");
        assert_eq!(info.info, "A longer description");
        assert_eq!(info.licenses, vec!["MIT".to_string()]);
        assert_eq!(info.homepage_uri, Some("https://example.com".to_string()));
        assert_eq!(info.sha, Some("sha256hash".to_string()));
        assert_eq!(info.downloads, 100);
        assert_eq!(info.version_downloads, 100);
    }

    #[test]
    fn test_generate_gem_info_no_authors() {
        let gemspec = GemSpec {
            name: "mygem".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };
        let info = generate_gem_info(&gemspec, "hash", 0);
        assert_eq!(info.authors, "");
        assert_eq!(info.info, "");
        assert!(info.licenses.is_empty());
        assert!(info.homepage_uri.is_none());
    }

    #[test]
    fn test_generate_gem_info_with_platform() {
        let gemspec = GemSpec {
            name: "native-gem".to_string(),
            version: "2.0.0".to_string(),
            platform: Some("x86_64-linux".to_string()),
            ..Default::default()
        };
        let info = generate_gem_info(&gemspec, "h", 50);
        assert_eq!(info.platform, Some("x86_64-linux".to_string()));
    }

    // ========================================================================
    // RubygemsHandler::new / Default tests
    // ========================================================================

    #[test]
    fn test_rubygems_handler_new() {
        let _handler = RubygemsHandler::new();
    }

    #[test]
    fn test_rubygems_handler_default() {
        let _handler = RubygemsHandler;
    }

    // ------------------------------------------------------------------
    // package_name_from_gem_filename / is_valid_rubygems_name
    // (#1217 follow-up, ak-hv3s shadowing guard)
    // ------------------------------------------------------------------

    #[test]
    fn test_package_name_from_gem_filename_simple() {
        assert_eq!(
            package_name_from_gem_filename("rails-7.0.8.gem"),
            Some("rails".to_string())
        );
    }

    #[test]
    fn test_package_name_from_gem_filename_hyphenated_name() {
        assert_eq!(
            package_name_from_gem_filename("aws-sdk-s3-1.140.0.gem"),
            Some("aws-sdk-s3".to_string())
        );
    }

    #[test]
    fn test_package_name_from_gem_filename_uppercase_extension() {
        // Load-bearing case-insensitive match: an attacker requesting
        // `RAILS-7.gem` vs `rails-7.gem` must not bypass the guard.
        assert_eq!(
            package_name_from_gem_filename("rails-7.0.gem"),
            Some("rails".to_string())
        );
        assert_eq!(
            package_name_from_gem_filename("RAILS-7.0.GEM"),
            Some("rails".to_string())
        );
    }

    #[test]
    fn test_package_name_from_gem_filename_no_extension() {
        assert_eq!(package_name_from_gem_filename("rails-7.0.8"), None);
    }

    #[test]
    fn test_package_name_from_gem_filename_empty_name_rejected() {
        assert_eq!(package_name_from_gem_filename("-7.0.0.gem"), None);
        assert_eq!(package_name_from_gem_filename(""), None);
    }

    #[test]
    fn test_package_name_from_gem_filename_rejects_path_traversal() {
        // The path-traversal-shaped names must not parse as gem names.
        assert_eq!(package_name_from_gem_filename("../-1.0.0.gem"), None);
        assert_eq!(package_name_from_gem_filename("a/b-1.0.0.gem"), None);
        assert_eq!(package_name_from_gem_filename("..%2f-1.0.0.gem"), None);
    }

    #[test]
    fn test_package_name_from_gem_filename_rejects_unicode() {
        // Non-ASCII names must be rejected so SQL `LOWER()` (ASCII-only)
        // does not produce a different result than the parser's ASCII
        // lowercasing.
        assert_eq!(
            package_name_from_gem_filename("rails\u{043e}-7.0.gem"),
            None
        );
    }

    #[test]
    fn test_is_valid_rubygems_name_accepts_real_world_gems() {
        assert!(is_valid_rubygems_name("rails"));
        assert!(is_valid_rubygems_name("aws-sdk-s3"));
        assert!(is_valid_rubygems_name("nokogiri"));
        assert!(is_valid_rubygems_name("rubocop_rake"));
        assert!(is_valid_rubygems_name("a"));
    }

    #[test]
    fn test_is_valid_rubygems_name_rejects_invalid() {
        assert!(!is_valid_rubygems_name(""));
        assert!(!is_valid_rubygems_name("-rails"));
        assert!(!is_valid_rubygems_name(".rails"));
        assert!(!is_valid_rubygems_name("rails space"));
        assert!(!is_valid_rubygems_name("rails/slash"));
    }
}
