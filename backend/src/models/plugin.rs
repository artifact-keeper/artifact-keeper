//! Plugin and plugin configuration models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Plugin status enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "plugin_status", rename_all = "lowercase")]
pub enum PluginStatus {
    Active,
    Disabled,
    Error,
}

/// Plugin type enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "plugin_type", rename_all = "snake_case")]
pub enum PluginType {
    FormatHandler,
    StorageBackend,
    Authentication,
    Authorization,
    Webhook,
    Custom,
}

/// Plugin source type enum.
///
/// Indicates how the plugin was installed/sourced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "plugin_source_type", rename_all = "snake_case")]
pub enum PluginSourceType {
    /// Compiled-in Rust handler (core format handlers)
    Core,
    /// Installed from Git repository
    WasmGit,
    /// Installed from ZIP file upload
    WasmZip,
    /// Installed from local file path (development)
    WasmLocal,
}

/// Plugin entity for extensibility.
///
/// Plugins extend the artifact registry with custom functionality
/// such as format handlers, webhooks, validators, and integrations.
/// Extended with WASM-specific fields for hot-loadable plugin support.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Plugin {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub display_name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub status: PluginStatus,
    pub plugin_type: PluginType,
    /// How the plugin was installed (core, git, zip, local)
    pub source_type: PluginSourceType,
    /// Git URL or file path for WASM plugins
    pub source_url: Option<String>,
    /// Git ref (tag, branch, commit) for git-sourced plugins
    pub source_ref: Option<String>,
    /// Path to the stored WASM binary
    pub wasm_path: Option<String>,
    /// Full parsed plugin.toml manifest
    pub manifest: Option<serde_json::Value>,
    /// Plugin capabilities (parse_metadata, generate_index, etc.)
    pub capabilities: Option<serde_json::Value>,
    /// Resource limits (memory_mb, timeout_secs, fuel)
    pub resource_limits: Option<serde_json::Value>,
    pub config: Option<serde_json::Value>,
    pub config_schema: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub installed_at: DateTime<Utc>,
    pub enabled_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Resource limits for WASM plugin execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResourceLimits {
    /// Maximum memory in megabytes (default: 64)
    pub memory_mb: u32,
    /// Execution timeout in seconds (default: 5)
    pub timeout_secs: u32,
    /// Fuel units for computation limiting (default: 500_000_000)
    pub fuel: u64,
}

impl Default for PluginResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 64,
            timeout_secs: 5,
            fuel: 500_000_000,
        }
    }
}

/// Plugin capabilities indicating what operations the plugin supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapabilities {
    /// Plugin can parse artifact metadata
    pub parse_metadata: bool,
    /// Plugin can generate index/metadata files
    pub generate_index: bool,
    /// Plugin can validate artifacts
    pub validate_artifact: bool,
    /// Plugin can handle native protocol HTTP requests (v2 WIT)
    #[serde(default)]
    pub handle_request: bool,
}

impl Default for PluginCapabilities {
    fn default() -> Self {
        Self {
            parse_metadata: true,
            generate_index: false,
            validate_artifact: true,
            handle_request: false,
        }
    }
}

/// Plugin hook entity for event handling.
///
/// Hooks register plugin handlers for specific events like
/// artifact upload, download, or deletion.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PluginHook {
    pub id: Uuid,
    pub plugin_id: Uuid,
    pub hook_type: String,
    pub handler_name: String,
    pub priority: i32,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// Plugin event entity for logging.
///
/// Records plugin activity and errors for debugging and auditing.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PluginEvent {
    pub id: Uuid,
    pub plugin_id: Uuid,
    pub event_type: String,
    pub severity: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Plugin configuration entry.
///
/// Stores individual configuration key-value pairs for plugins,
/// with support for secret values that are not exposed via API.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PluginConfig {
    pub id: Uuid,
    pub plugin_id: Uuid,
    pub key: String,
    #[serde(skip_serializing_if = "is_secret_value")]
    pub value: String,
    pub is_secret: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Helper function to skip serializing secret values.
fn is_secret_value(_value: &str) -> bool {
    // This is a placeholder - actual implementation would check is_secret field
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PluginResourceLimits
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_resource_limits_default() {
        let limits = PluginResourceLimits::default();
        assert_eq!(limits.memory_mb, 64);
        assert_eq!(limits.timeout_secs, 5);
        assert_eq!(limits.fuel, 500_000_000);
    }

    #[test]
    fn test_plugin_resource_limits_serialize_deserialize() {
        let limits = PluginResourceLimits {
            memory_mb: 128,
            timeout_secs: 10,
            fuel: 1_000_000_000,
        };
        let json = serde_json::to_string(&limits).unwrap();
        let deserialized: PluginResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.memory_mb, 128);
        assert_eq!(deserialized.timeout_secs, 10);
        assert_eq!(deserialized.fuel, 1_000_000_000);
    }

    // -----------------------------------------------------------------------
    // PluginCapabilities
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_capabilities_default() {
        let caps = PluginCapabilities::default();
        assert!(caps.parse_metadata);
        assert!(!caps.generate_index);
        assert!(caps.validate_artifact);
        assert!(!caps.handle_request);
    }

    #[test]
    fn test_plugin_capabilities_serialize_deserialize() {
        let caps = PluginCapabilities {
            parse_metadata: false,
            generate_index: true,
            validate_artifact: false,
            handle_request: false,
        };
        let json = serde_json::to_string(&caps).unwrap();
        let deserialized: PluginCapabilities = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.parse_metadata);
        assert!(deserialized.generate_index);
        assert!(!deserialized.validate_artifact);
        assert!(!deserialized.handle_request);
    }

    #[test]
    fn test_plugin_capabilities_handle_request_serde() {
        let caps = PluginCapabilities {
            parse_metadata: true,
            generate_index: true,
            validate_artifact: true,
            handle_request: true,
        };
        let json = serde_json::to_string(&caps).unwrap();
        assert!(json.contains("handle_request"));
        let deserialized: PluginCapabilities = serde_json::from_str(&json).unwrap();
        assert!(deserialized.handle_request);
    }

    #[test]
    fn test_plugin_capabilities_handle_request_missing_defaults_false() {
        // Older JSON without handle_request should default to false
        let json = r#"{"parse_metadata":true,"generate_index":false,"validate_artifact":true}"#;
        let caps: PluginCapabilities = serde_json::from_str(json).unwrap();
        assert!(!caps.handle_request);
    }

    // -----------------------------------------------------------------------
    // PluginStatus equality
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_status_equality() {
        assert_eq!(PluginStatus::Active, PluginStatus::Active);
        assert_ne!(PluginStatus::Active, PluginStatus::Disabled);
        assert_ne!(PluginStatus::Active, PluginStatus::Error);
    }

    // -----------------------------------------------------------------------
    // PluginType equality
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_type_equality() {
        assert_eq!(PluginType::FormatHandler, PluginType::FormatHandler);
        assert_ne!(PluginType::FormatHandler, PluginType::Webhook);
    }

    // -----------------------------------------------------------------------
    // PluginSourceType equality
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_source_type_equality() {
        assert_eq!(PluginSourceType::Core, PluginSourceType::Core);
        assert_ne!(PluginSourceType::Core, PluginSourceType::WasmGit);
        assert_eq!(PluginSourceType::WasmGit, PluginSourceType::WasmGit);
        assert_eq!(PluginSourceType::WasmZip, PluginSourceType::WasmZip);
        assert_eq!(PluginSourceType::WasmLocal, PluginSourceType::WasmLocal);
    }

    // -----------------------------------------------------------------------
    // is_secret_value
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_secret_value_always_false() {
        // Current implementation is a placeholder returning false
        assert!(!is_secret_value("any value"));
        assert!(!is_secret_value(""));
        assert!(!is_secret_value("super-secret"));
    }
}
