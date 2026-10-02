//! Format handler model for tracking all format handlers (core and WASM).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// Format handler type enum.
///
/// Indicates whether the handler is compiled-in (core) or loaded from WASM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "format_handler_type", rename_all = "lowercase")]
pub enum FormatHandlerType {
    /// Compiled-in Rust handler
    Core,
    /// WASM plugin handler
    Wasm,
}

/// Whether scan-on-proxy is enforced for a format's proxied downloads (#4099).
///
/// `scan_configs.scan_on_proxy` is accepted for any repository, but only some
/// handlers gate their Remote/Virtual downloads on the inline scan. Clients
/// read this instead of hand-maintaining the gated-format list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScanOnProxySupport {
    /// Proxied package bytes are scanned inline and blocked per the policy.
    Enforced,
    /// The setting is stored but proxied downloads are served unscanned.
    Accepted,
    /// The handler has no core proxy serve path the setting could apply to
    /// (a WASM plugin handler).
    Unsupported,
}

impl ScanOnProxySupport {
    /// The support level of the handler `format_key` of type `handler_type`.
    pub fn for_handler(handler_type: &FormatHandlerType, format_key: &str) -> Self {
        match handler_type {
            FormatHandlerType::Wasm => Self::Unsupported,
            FormatHandlerType::Core
                if crate::formats::handler_enforces_scan_on_proxy(format_key) =>
            {
                Self::Enforced
            }
            FormatHandlerType::Core => Self::Accepted,
        }
    }
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
#[derive(Debug, Clone, Serialize, ToSchema)]
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
    #[schema(value_type = Option<Object>)]
    pub capabilities: Option<serde_json::Value>,
    /// Whether scan-on-proxy is enforced for this format's proxied downloads
    /// (#4099): `enforced` = proxied package bytes are scanned inline and
    /// withheld per the repository's policy; `accepted` = the setting is
    /// stored but proxied downloads are served unscanned; `unsupported` = a
    /// WASM plugin handler, which has no core proxy serve path the setting
    /// could apply to.
    pub scan_on_proxy: ScanOnProxySupport,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<FormatHandlerRecord> for FormatHandlerResponse {
    fn from(record: FormatHandlerRecord) -> Self {
        let scan_on_proxy =
            ScanOnProxySupport::for_handler(&record.handler_type, &record.format_key);
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
            scan_on_proxy,
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

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_handler_response_from_record() {
        let now = chrono::Utc::now();
        let id = Uuid::new_v4();
        let plugin_id = Uuid::new_v4();

        let record = FormatHandlerRecord {
            id,
            format_key: "custom-format".to_string(),
            plugin_id: Some(plugin_id),
            handler_type: FormatHandlerType::Wasm,
            display_name: "Custom Format".to_string(),
            description: Some("A custom format handler".to_string()),
            extensions: vec![".custom".to_string(), ".cst".to_string()],
            is_enabled: true,
            priority: 10,
            created_at: now,
            updated_at: now,
        };

        let response: FormatHandlerResponse = record.into();

        assert_eq!(response.id, id);
        assert_eq!(response.format_key, "custom-format");
        assert_eq!(response.plugin_id, Some(plugin_id));
        assert_eq!(response.handler_type, FormatHandlerType::Wasm);
        assert_eq!(response.display_name, "Custom Format");
        assert_eq!(
            response.description.as_deref(),
            Some("A custom format handler")
        );
        assert_eq!(response.extensions.len(), 2);
        assert!(response.is_enabled);
        assert_eq!(response.priority, 10);
        // Computed fields should be None
        assert!(response.repository_count.is_none());
        assert!(response.capabilities.is_none());
        // A WASM plugin handler has no core proxy serve path (#4099).
        assert_eq!(response.scan_on_proxy, ScanOnProxySupport::Unsupported);
    }

    #[test]
    fn test_format_handler_response_from_core_record() {
        let now = chrono::Utc::now();
        let record = FormatHandlerRecord {
            id: Uuid::new_v4(),
            format_key: "maven".to_string(),
            plugin_id: None,
            handler_type: FormatHandlerType::Core,
            display_name: "Maven".to_string(),
            description: None,
            extensions: vec![".jar".to_string(), ".pom".to_string()],
            is_enabled: true,
            priority: 100,
            created_at: now,
            updated_at: now,
        };

        let response: FormatHandlerResponse = record.into();
        assert_eq!(response.handler_type, FormatHandlerType::Core);
        assert!(response.plugin_id.is_none());
        assert!(response.description.is_none());
        // Maven gates its proxied package archives since #4100.
        assert_eq!(response.scan_on_proxy, ScanOnProxySupport::Enforced);
    }

    /// #4099: the per-format capability, serialized the way
    /// `GET /api/v1/formats` returns it.
    #[test]
    fn test_scan_on_proxy_support_per_handler() {
        use ScanOnProxySupport::*;
        for key in ["npm", "pypi", "oci", "vscode", "maven", "sbt"] {
            assert_eq!(
                ScanOnProxySupport::for_handler(&FormatHandlerType::Core, key),
                Enforced,
                "{key} gates its proxied downloads"
            );
        }
        for key in ["cargo", "nuget", "go", "generic", "conda"] {
            assert_eq!(
                ScanOnProxySupport::for_handler(&FormatHandlerType::Core, key),
                Accepted,
                "{key} stores scan_on_proxy but does not gate"
            );
        }
        assert_eq!(
            ScanOnProxySupport::for_handler(&FormatHandlerType::Wasm, "unity-assetbundle"),
            Unsupported
        );
        assert_eq!(serde_json::to_value(Enforced).unwrap(), "enforced");
        assert_eq!(serde_json::to_value(Accepted).unwrap(), "accepted");
        assert_eq!(serde_json::to_value(Unsupported).unwrap(), "unsupported");
    }

    #[test]
    fn test_format_handler_type_equality() {
        assert_eq!(FormatHandlerType::Core, FormatHandlerType::Core);
        assert_eq!(FormatHandlerType::Wasm, FormatHandlerType::Wasm);
        assert_ne!(FormatHandlerType::Core, FormatHandlerType::Wasm);
    }
}
