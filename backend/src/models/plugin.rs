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
}

impl Default for PluginCapabilities {
    fn default() -> Self {
        Self {
            parse_metadata: true,
            generate_index: false,
            validate_artifact: true,
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
