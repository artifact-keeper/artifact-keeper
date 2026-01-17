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
            if !found_version && part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
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
        // Ruby's gemspec format uses YAML with custom tags
        // We'll parse what we can and ignore unknown fields
        let mut gemspec = GemSpec::default();

        for line in content.lines() {
            let line = line.trim();

            if let Some(rest) = line.strip_prefix("name:") {
                gemspec.name = rest.trim().trim_matches('"').to_string();
            } else if let Some(rest) = line.strip_prefix("version:") {
                // Handle !ruby/object:Gem::Version format
                if rest.contains("version:") {
                    // Multi-line version
                    continue;
                }
                gemspec.version = rest.trim().trim_matches('"').to_string();
            } else if line.starts_with("version:") && gemspec.version.is_empty() {
                // Handle inline version
                if let Some(ver) = line.split("version:").last() {
                    gemspec.version = ver.trim().trim_matches('"').to_string();
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
        }

        // Try to extract version from nested structure if still empty
        if gemspec.version.is_empty() {
            for line in content.lines() {
                if line.trim().starts_with("- ") && line.trim_start_matches("- ").chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    gemspec.version = line.trim().trim_start_matches("- ").to_string();
                    break;
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
        authors: gemspec.authors.as_ref().map(|a| a.join(", ")).unwrap_or_default(),
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

    #[test]
    fn test_parse_gem_filename() {
        let (name, version, platform) = RubygemsHandler::parse_gem_filename("rails-7.0.8.gem").unwrap();
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
    }

    #[test]
    fn test_parse_path_latest_specs() {
        let info = RubygemsHandler::parse_path("latest_specs.4.8.gz").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::LatestSpecs));
    }

    #[test]
    fn test_parse_path_api() {
        let info = RubygemsHandler::parse_path("api/v1/gems/rails.json").unwrap();
        assert!(matches!(info.operation, RubygemsOperation::GemInfo));
        assert_eq!(info.name, Some("rails".to_string()));
    }
}
