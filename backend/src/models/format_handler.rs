//! Format handler model for tracking all format handlers (core and WASM).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Format handler type enum.
///
/// Indicates whether the handler is compiled-in (core) or loaded from WASM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "format_handler_type", rename_all = "lowercase")]
pub enum FormatHandlerType {
    /// Compiled-in Rust handler
    Core,
    /// WASM plugin handler
    Wasm,
}

/// Format handler entity.
///
/// Tracks all registered format handlers in the system, both core (compiled-in)
/// and WASM (loaded from plugins). This allows unified management of all formats
/// including enable/disable functionality.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FormatHandlerRecord {
    pub id: Uuid,
    /// Unique format key (e.g., "maven", "npm", "unity-assetbundle")
    pub format_key: String,
    /// Associated plugin ID (NULL for core handlers)
    pub plugin_id: Option<Uuid>,
    /// Handler type (core or wasm)
    pub handler_type: FormatHandlerType,
    /// Human-readable display name
    pub display_name: String,
    /// Format description
    pub description: Option<String>,
    /// File extensions this format handles (e.g., [".jar", ".pom"])
    pub extensions: Vec<String>,
    /// Whether this handler is currently enabled
    pub is_enabled: bool,
    /// Priority for format resolution (higher = preferred)
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new format handler record.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateFormatHandler {
    pub format_key: String,
    pub plugin_id: Option<Uuid>,
    pub handler_type: FormatHandlerType,
    pub display_name: String,
    pub description: Option<String>,
    pub extensions: Vec<String>,
    pub priority: Option<i32>,
}

/// Request to update a format handler record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFormatHandler {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub extensions: Option<Vec<String>>,
    pub is_enabled: Option<bool>,
    pub priority: Option<i32>,
}

/// Format handler response with additional computed fields.
#[derive(Debug, Clone, Serialize)]
pub struct FormatHandlerResponse {
    pub id: Uuid,
    pub format_key: String,
    pub plugin_id: Option<Uuid>,
    pub handler_type: FormatHandlerType,
    pub display_name: String,
    pub description: Option<String>,
    pub extensions: Vec<String>,
    pub is_enabled: bool,
    pub priority: i32,
    /// Number of repositories using this format (computed)
    pub repository_count: Option<i64>,
    /// Plugin capabilities if this is a WASM handler
    pub capabilities: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<FormatHandlerRecord> for FormatHandlerResponse {
    fn from(record: FormatHandlerRecord) -> Self {
        Self {
            id: record.id,
            format_key: record.format_key,
            plugin_id: record.plugin_id,
            handler_type: record.handler_type,
            display_name: record.display_name,
            description: record.description,
            extensions: record.extensions,
            is_enabled: record.is_enabled,
            priority: record.priority,
            repository_count: None,
            capabilities: None,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

/// List response for format handlers.
#[derive(Debug, Clone, Serialize)]
pub struct FormatHandlerListResponse {
    pub items: Vec<FormatHandlerResponse>,
    pub total: i64,
}
