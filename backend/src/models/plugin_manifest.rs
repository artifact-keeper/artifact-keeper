//! Plugin manifest model for parsing plugin.toml files.

use serde::{Deserialize, Serialize};

use super::plugin::{PluginCapabilities, PluginResourceLimits};

/// Plugin manifest parsed from plugin.toml.
///
/// This is the structure that plugin developers create to describe their plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin metadata section
    pub plugin: PluginMetadata,
    /// Format handler configuration (required for format_handler plugins)
    pub format: Option<FormatConfig>,
    /// Plugin capabilities
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
    /// Resource requirements and limits
    #[serde(default)]
    pub requirements: RequirementsConfig,
}

/// Plugin metadata from [plugin] section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique plugin identifier (lowercase, hyphens allowed)
    pub name: String,
    /// Semantic version (e.g., "1.0.0")
    pub version: String,
    /// Plugin author (optional)
    pub author: Option<String>,
    /// License identifier (SPDX format, optional)
    pub license: Option<String>,
    /// Plugin description (optional)
    pub description: Option<String>,
    /// Homepage URL (optional)
    pub homepage: Option<String>,
}

/// Format handler configuration from [format] section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatConfig {
    /// Format key used in API (lowercase, hyphens)
    pub key: String,
    /// Human-readable display name
    pub display_name: String,
    /// File extensions this format handles
    #[serde(default)]
    pub extensions: Vec<String>,
}

/// Capabilities configuration from [capabilities] section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilitiesConfig {
    /// Plugin can parse artifact metadata
    #[serde(default = "default_true")]
    pub parse_metadata: bool,
    /// Plugin can generate index/metadata files
    #[serde(default)]
    pub generate_index: bool,
    /// Plugin can validate artifacts before storage
    #[serde(default = "default_true")]
    pub validate_artifact: bool,
}

fn default_true() -> bool {
    true
}

/// Requirements configuration from [requirements] section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementsConfig {
    /// Minimum wasmtime version (optional)
    pub min_wasmtime: Option<String>,
    /// Minimum memory allocation in MB
    #[serde(default = "default_min_memory")]
    pub min_memory_mb: u32,
    /// Maximum memory limit in MB
    #[serde(default = "default_max_memory")]
    pub max_memory_mb: u32,
    /// Execution timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
}

fn default_min_memory() -> u32 {
    32
}

fn default_max_memory() -> u32 {
    64
}

fn default_timeout() -> u32 {
    5
}

impl Default for RequirementsConfig {
    fn default() -> Self {
        Self {
            min_wasmtime: None,
            min_memory_mb: default_min_memory(),
            max_memory_mb: default_max_memory(),
            timeout_secs: default_timeout(),
        }
    }
}

impl PluginManifest {
    /// Parse a plugin manifest from TOML content.
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// Validate the manifest for required fields and constraints.
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        // Validate plugin name format
        if !is_valid_identifier(&self.plugin.name) {
            return Err(ManifestValidationError::InvalidPluginName(
                self.plugin.name.clone(),
            ));
        }

        // Validate version format (basic semver check)
        if !is_valid_semver(&self.plugin.version) {
            return Err(ManifestValidationError::InvalidVersion(
                self.plugin.version.clone(),
            ));
        }

        // Validate format section if present
        if let Some(ref format) = self.format {
            if !is_valid_identifier(&format.key) {
                return Err(ManifestValidationError::InvalidFormatKey(
                    format.key.clone(),
                ));
            }

            if format.display_name.is_empty() {
                return Err(ManifestValidationError::MissingDisplayName);
            }
        }

        // Validate resource limits
        if self.requirements.max_memory_mb < self.requirements.min_memory_mb {
            return Err(ManifestValidationError::InvalidMemoryLimits {
                min: self.requirements.min_memory_mb,
                max: self.requirements.max_memory_mb,
            });
        }

        if self.requirements.timeout_secs == 0 || self.requirements.timeout_secs > 300 {
            return Err(ManifestValidationError::InvalidTimeout(
                self.requirements.timeout_secs,
            ));
        }

        Ok(())
    }

    /// Convert capabilities config to PluginCapabilities.
    pub fn to_capabilities(&self) -> PluginCapabilities {
        PluginCapabilities {
            parse_metadata: self.capabilities.parse_metadata,
            generate_index: self.capabilities.generate_index,
            validate_artifact: self.capabilities.validate_artifact,
        }
    }

    /// Convert requirements config to PluginResourceLimits.
    pub fn to_resource_limits(&self) -> PluginResourceLimits {
        PluginResourceLimits {
            memory_mb: self.requirements.max_memory_mb,
            timeout_secs: self.requirements.timeout_secs,
            fuel: (self.requirements.timeout_secs as u64) * 100_000_000,
        }
    }
}

/// Errors that can occur during manifest validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ManifestValidationError {
    #[error("Invalid plugin name '{0}': must be lowercase letters, numbers, and hyphens, starting with a letter")]
    InvalidPluginName(String),

    #[error("Invalid version '{0}': must be semantic version (e.g., 1.0.0)")]
    InvalidVersion(String),

    #[error("Invalid format key '{0}': must be lowercase letters, numbers, and hyphens, starting with a letter")]
    InvalidFormatKey(String),

    #[error("Missing display_name in format section")]
    MissingDisplayName,

    #[error("Invalid memory limits: min ({min} MB) must be less than or equal to max ({max} MB)")]
    InvalidMemoryLimits { min: u32, max: u32 },

    #[error("Invalid timeout {0}: must be between 1 and 300 seconds")]
    InvalidTimeout(u32),
}

/// Check if a string is a valid identifier (lowercase, hyphens, starts with letter).
fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > 100 {
        return false;
    }

    let mut chars = s.chars();

    // First character must be a lowercase letter
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }

    // Remaining characters must be lowercase letters, digits, or hyphens
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Basic semantic version validation.
fn is_valid_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return false;
    }

    // Check that each part is a valid number (with optional prerelease suffix on last part)
    for (i, part) in parts.iter().enumerate() {
        let numeric_part = if i == parts.len() - 1 {
            // Last part may have -prerelease or +build suffix
            part.split('-').next().unwrap_or(part).split('+').next().unwrap_or(part)
        } else {
            part
        };

        if numeric_part.parse::<u32>().is_err() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_identifier() {
        assert!(is_valid_identifier("maven"));
        assert!(is_valid_identifier("unity-assetbundle"));
        assert!(is_valid_identifier("plugin123"));
        assert!(is_valid_identifier("a"));

        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("Maven")); // uppercase
        assert!(!is_valid_identifier("123plugin")); // starts with number
        assert!(!is_valid_identifier("plugin_name")); // underscore
        assert!(!is_valid_identifier("-plugin")); // starts with hyphen
    }

    #[test]
    fn test_valid_semver() {
        assert!(is_valid_semver("1.0.0"));
        assert!(is_valid_semver("0.1.0"));
        assert!(is_valid_semver("1.0"));
        assert!(is_valid_semver("1.0.0-alpha"));
        assert!(is_valid_semver("1.0.0+build"));

        assert!(!is_valid_semver("1"));
        assert!(!is_valid_semver("v1.0.0"));
        assert!(!is_valid_semver("1.0.0.0"));
    }

    #[test]
    fn test_parse_manifest() {
        let toml = r#"
[plugin]
name = "unity-assetbundle"
version = "1.0.0"
author = "Unity Technologies"
license = "MIT"
description = "Unity AssetBundle format handler"

[format]
key = "unity-assetbundle"
display_name = "Unity AssetBundle"
extensions = [".assetbundle", ".unity3d"]

[capabilities]
parse_metadata = true
generate_index = true
validate_artifact = true

[requirements]
min_memory_mb = 32
max_memory_mb = 128
timeout_secs = 5
"#;

        let manifest = PluginManifest::from_toml(toml).unwrap();
        assert_eq!(manifest.plugin.name, "unity-assetbundle");
        assert_eq!(manifest.plugin.version, "1.0.0");
        assert_eq!(manifest.format.as_ref().unwrap().key, "unity-assetbundle");
        assert!(manifest.capabilities.generate_index);
        assert!(manifest.validate().is_ok());
    }
}
