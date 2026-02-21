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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Plugin can handle native protocol HTTP requests (v2 WIT)
    #[serde(default)]
    pub handle_request: bool,
}

impl Default for CapabilitiesConfig {
    fn default() -> Self {
        Self {
            parse_metadata: true,
            generate_index: false,
            validate_artifact: true,
            handle_request: false,
        }
    }
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
            handle_request: self.capabilities.handle_request,
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
            part.split('-')
                .next()
                .unwrap_or(part)
                .split('+')
                .next()
                .unwrap_or(part)
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

    // -----------------------------------------------------------------------
    // Validation error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_invalid_plugin_name() {
        let toml = r#"
[plugin]
name = "INVALID_NAME"
version = "1.0.0"
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let result = manifest.validate();
        assert!(matches!(
            result,
            Err(ManifestValidationError::InvalidPluginName(_))
        ));
    }

    #[test]
    fn test_validate_invalid_version() {
        let toml = r#"
[plugin]
name = "valid-name"
version = "v1.0.0"
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let result = manifest.validate();
        assert!(matches!(
            result,
            Err(ManifestValidationError::InvalidVersion(_))
        ));
    }

    #[test]
    fn test_validate_invalid_format_key() {
        let toml = r#"
[plugin]
name = "valid-name"
version = "1.0.0"

[format]
key = "INVALID_KEY"
display_name = "Something"
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let result = manifest.validate();
        assert!(matches!(
            result,
            Err(ManifestValidationError::InvalidFormatKey(_))
        ));
    }

    #[test]
    fn test_validate_missing_display_name() {
        let toml = r#"
[plugin]
name = "valid-name"
version = "1.0.0"

[format]
key = "valid-key"
display_name = ""
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let result = manifest.validate();
        assert!(matches!(
            result,
            Err(ManifestValidationError::MissingDisplayName)
        ));
    }

    #[test]
    fn test_validate_invalid_memory_limits() {
        let toml = r#"
[plugin]
name = "valid-name"
version = "1.0.0"

[requirements]
min_memory_mb = 128
max_memory_mb = 32
timeout_secs = 5
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let result = manifest.validate();
        assert!(matches!(
            result,
            Err(ManifestValidationError::InvalidMemoryLimits { .. })
        ));
    }

    #[test]
    fn test_validate_timeout_zero() {
        let toml = r#"
[plugin]
name = "valid-name"
version = "1.0.0"

[requirements]
timeout_secs = 0
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let result = manifest.validate();
        assert!(matches!(
            result,
            Err(ManifestValidationError::InvalidTimeout(0))
        ));
    }

    #[test]
    fn test_validate_timeout_too_large() {
        let toml = r#"
[plugin]
name = "valid-name"
version = "1.0.0"

[requirements]
timeout_secs = 301
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let result = manifest.validate();
        assert!(matches!(
            result,
            Err(ManifestValidationError::InvalidTimeout(301))
        ));
    }

    #[test]
    fn test_validate_timeout_boundary_300() {
        let toml = r#"
[plugin]
name = "valid-name"
version = "1.0.0"

[requirements]
timeout_secs = 300
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_validate_timeout_boundary_1() {
        let toml = r#"
[plugin]
name = "valid-name"
version = "1.0.0"

[requirements]
timeout_secs = 1
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        assert!(manifest.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // to_capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn test_to_capabilities() {
        let toml = r#"
[plugin]
name = "test-plugin"
version = "1.0.0"

[capabilities]
parse_metadata = true
generate_index = true
validate_artifact = false
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let caps = manifest.to_capabilities();
        assert!(caps.parse_metadata);
        assert!(caps.generate_index);
        assert!(!caps.validate_artifact);
        assert!(!caps.handle_request); // defaults to false
    }

    #[test]
    fn test_to_capabilities_with_handle_request() {
        let toml = r#"
[plugin]
name = "protocol-plugin"
version = "2.0.0"

[capabilities]
parse_metadata = true
generate_index = true
validate_artifact = true
handle_request = true
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let caps = manifest.to_capabilities();
        assert!(caps.handle_request);
        assert!(caps.parse_metadata);
        assert!(caps.generate_index);
        assert!(caps.validate_artifact);
    }

    // -----------------------------------------------------------------------
    // to_resource_limits
    // -----------------------------------------------------------------------

    #[test]
    fn test_to_resource_limits() {
        let toml = r#"
[plugin]
name = "test-plugin"
version = "1.0.0"

[requirements]
max_memory_mb = 128
timeout_secs = 10
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        let limits = manifest.to_resource_limits();
        assert_eq!(limits.memory_mb, 128);
        assert_eq!(limits.timeout_secs, 10);
        assert_eq!(limits.fuel, 10 * 100_000_000);
    }

    // -----------------------------------------------------------------------
    // Defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_requirements_config_default() {
        let req = RequirementsConfig::default();
        assert_eq!(req.min_memory_mb, 32);
        assert_eq!(req.max_memory_mb, 64);
        assert_eq!(req.timeout_secs, 5);
        assert!(req.min_wasmtime.is_none());
    }

    #[test]
    fn test_capabilities_config_default() {
        // Default impl now matches serde defaults: parse_metadata and validate_artifact
        // are true, generate_index and handle_request are false.
        let caps = CapabilitiesConfig::default();
        assert!(caps.parse_metadata);
        assert!(!caps.generate_index);
        assert!(caps.validate_artifact);
        assert!(!caps.handle_request);
    }

    #[test]
    fn test_capabilities_config_serde_defaults() {
        // When deserialized from empty object, serde uses default_true
        let caps: CapabilitiesConfig = serde_json::from_str("{}").unwrap();
        assert!(caps.parse_metadata); // true from serde(default = "default_true")
        assert!(!caps.generate_index); // false from serde(default)
        assert!(caps.validate_artifact); // true from serde(default = "default_true")
        assert!(!caps.handle_request); // false from serde(default)
    }

    #[test]
    fn test_parse_minimal_manifest() {
        let toml = r#"
[plugin]
name = "minimal"
version = "0.1"
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        assert_eq!(manifest.plugin.name, "minimal");
        assert!(manifest.format.is_none());
        // When the [capabilities] section is entirely missing, serde uses
        // #[serde(default)] which calls CapabilitiesConfig::default().
        // Our manual Default impl now matches serde field defaults.
        assert!(manifest.capabilities.parse_metadata);
        assert_eq!(manifest.requirements.timeout_secs, 5);
    }

    #[test]
    fn test_parse_manifest_with_empty_capabilities_section() {
        let toml = r#"
[plugin]
name = "test-plugin"
version = "1.0"

[capabilities]
"#;
        let manifest = PluginManifest::from_toml(toml).unwrap();
        // When [capabilities] section exists but fields are missing,
        // serde(default = "default_true") kicks in
        assert!(manifest.capabilities.parse_metadata);
        assert!(!manifest.capabilities.generate_index);
        assert!(manifest.capabilities.validate_artifact);
    }

    // -----------------------------------------------------------------------
    // Identifier validation edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_identifier_max_length() {
        let name = "a".repeat(100);
        assert!(is_valid_identifier(&name));
    }

    #[test]
    fn test_valid_identifier_too_long() {
        let name = "a".repeat(101);
        assert!(!is_valid_identifier(&name));
    }

    #[test]
    fn test_valid_identifier_trailing_hyphen() {
        assert!(is_valid_identifier("name-")); // allowed per implementation
    }

    // -----------------------------------------------------------------------
    // Semver validation edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_semver_two_parts() {
        assert!(is_valid_semver("1.0"));
    }

    #[test]
    fn test_semver_prerelease_with_build() {
        assert!(is_valid_semver("1.0.0-alpha+build123"));
    }

    // -----------------------------------------------------------------------
    // ManifestValidationError Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest_validation_error_display() {
        let err = ManifestValidationError::InvalidPluginName("Bad_Name".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Bad_Name"));

        let err = ManifestValidationError::InvalidVersion("v1".to_string());
        let msg = err.to_string();
        assert!(msg.contains("v1"));

        let err = ManifestValidationError::InvalidMemoryLimits { min: 128, max: 64 };
        let msg = err.to_string();
        assert!(msg.contains("128"));
        assert!(msg.contains("64"));

        let err = ManifestValidationError::InvalidTimeout(500);
        let msg = err.to_string();
        assert!(msg.contains("500"));

        let err = ManifestValidationError::MissingDisplayName;
        assert!(err.to_string().contains("display_name"));
    }
}
