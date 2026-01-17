//! Plugin management handlers.

use axum::{
    extract::{Extension, Multipart, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::format_handler::{FormatHandlerResponse, FormatHandlerType, UpdateFormatHandler};

/// Create plugin routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_plugins).post(install_plugin))
        .route("/:id", get(get_plugin).delete(uninstall_plugin))
        .route("/:id/enable", post(enable_plugin))
        .route("/:id/disable", post(disable_plugin))
        .route("/:id/config", get(get_plugin_config).post(update_plugin_config))
        .route("/:id/events", get(get_plugin_events))
        // WASM plugin endpoints
        .route("/install/git", post(install_from_git))
        .route("/install/zip", post(install_from_zip))
        .route("/install/local", post(install_from_local))
        .route("/:id/reload", post(reload_plugin))
}

/// Create format handler routes
pub fn format_router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_format_handlers))
        .route("/:format_key", get(get_format_handler))
        .route("/:format_key/enable", post(enable_format_handler))
        .route("/:format_key/disable", post(disable_format_handler))
        .route("/:format_key/test", post(test_format_handler))
}

/// Plugin status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "plugin_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PluginStatus {
    Active,
    Disabled,
    Error,
}

/// Plugin type
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "plugin_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    FormatHandler,
    StorageBackend,
    Authentication,
    Authorization,
    Webhook,
    Custom,
}

#[derive(Debug, Deserialize)]
pub struct ListPluginsQuery {
    pub status: Option<String>,
    #[serde(rename = "type")]
    pub plugin_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PluginResponse {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub display_name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub status: String,
    pub plugin_type: String,
    pub config_schema: Option<serde_json::Value>,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub enabled_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct PluginListResponse {
    pub items: Vec<PluginResponse>,
}

fn parse_status(s: &str) -> Option<PluginStatus> {
    match s.to_lowercase().as_str() {
        "active" => Some(PluginStatus::Active),
        "disabled" => Some(PluginStatus::Disabled),
        "error" => Some(PluginStatus::Error),
        _ => None,
    }
}

fn parse_type(s: &str) -> Option<PluginType> {
    match s.to_lowercase().as_str() {
        "format_handler" => Some(PluginType::FormatHandler),
        "storage_backend" => Some(PluginType::StorageBackend),
        "authentication" => Some(PluginType::Authentication),
        "authorization" => Some(PluginType::Authorization),
        "webhook" => Some(PluginType::Webhook),
        "custom" => Some(PluginType::Custom),
        _ => None,
    }
}

/// List installed plugins
pub async fn list_plugins(
    State(state): State<SharedState>,
    Query(query): Query<ListPluginsQuery>,
) -> Result<Json<PluginListResponse>> {
    let status = query.status.as_ref().and_then(|s| parse_status(s));
    let plugin_type = query.plugin_type.as_ref().and_then(|t| parse_type(t));

    let plugins = sqlx::query!(
        r#"
        SELECT
            id, name, version, display_name, description, author, homepage,
            status as "status: PluginStatus",
            plugin_type as "plugin_type: PluginType",
            config_schema, installed_at, enabled_at
        FROM plugins
        WHERE ($1::plugin_status IS NULL OR status = $1)
          AND ($2::plugin_type IS NULL OR plugin_type = $2)
        ORDER BY display_name
        "#,
        status as Option<PluginStatus>,
        plugin_type as Option<PluginType>
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let items = plugins
        .into_iter()
        .map(|p| PluginResponse {
            id: p.id,
            name: p.name,
            version: p.version,
            display_name: p.display_name,
            description: p.description,
            author: p.author,
            homepage: p.homepage,
            status: format!("{:?}", p.status).to_lowercase(),
            plugin_type: format!("{:?}", p.plugin_type).to_lowercase(),
            config_schema: p.config_schema,
            installed_at: p.installed_at,
            enabled_at: p.enabled_at,
        })
        .collect();

    Ok(Json(PluginListResponse { items }))
}

/// Plugin manifest from package
#[derive(Debug, Deserialize)]
struct PluginManifest {
    name: String,
    version: String,
    display_name: String,
    description: Option<String>,
    author: Option<String>,
    homepage: Option<String>,
    plugin_type: String,
    config_schema: Option<serde_json::Value>,
}

/// Install plugin from uploaded package
pub async fn install_plugin(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    mut multipart: Multipart,
) -> Result<Json<PluginResponse>> {
    // Extract plugin package from multipart
    let mut manifest: Option<PluginManifest> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| AppError::Validation(e.to_string()))? {
        let name = field.name().unwrap_or("").to_string();

        if name == "package" || name == "manifest" {
            let data = field.bytes().await.map_err(|e| AppError::Validation(e.to_string()))?;

            // Parse as JSON manifest
            manifest = Some(serde_json::from_slice(&data)
                .map_err(|e| AppError::Validation(format!("Invalid plugin manifest: {}", e)))?);
        }
    }

    let manifest = manifest.ok_or_else(|| AppError::Validation("Missing plugin manifest".to_string()))?;

    let plugin_type = parse_type(&manifest.plugin_type)
        .ok_or_else(|| AppError::Validation(format!("Invalid plugin type: {}", manifest.plugin_type)))?;

    // Insert plugin record
    let plugin = sqlx::query!(
        r#"
        INSERT INTO plugins (name, version, display_name, description, author, homepage, plugin_type, config_schema)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING
            id, name, version, display_name, description, author, homepage,
            status as "status: PluginStatus",
            plugin_type as "plugin_type: PluginType",
            config_schema, installed_at, enabled_at
        "#,
        manifest.name,
        manifest.version,
        manifest.display_name,
        manifest.description,
        manifest.author,
        manifest.homepage,
        plugin_type as PluginType,
        manifest.config_schema
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") {
            AppError::Conflict(format!("Plugin '{}' already installed", manifest.name))
        } else {
            AppError::Database(msg)
        }
    })?;

    Ok(Json(PluginResponse {
        id: plugin.id,
        name: plugin.name,
        version: plugin.version,
        display_name: plugin.display_name,
        description: plugin.description,
        author: plugin.author,
        homepage: plugin.homepage,
        status: format!("{:?}", plugin.status).to_lowercase(),
        plugin_type: format!("{:?}", plugin.plugin_type).to_lowercase(),
        config_schema: plugin.config_schema,
        installed_at: plugin.installed_at,
        enabled_at: plugin.enabled_at,
    }))
}

/// Get plugin details
pub async fn get_plugin(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PluginResponse>> {
    let plugin = sqlx::query!(
        r#"
        SELECT
            id, name, version, display_name, description, author, homepage,
            status as "status: PluginStatus",
            plugin_type as "plugin_type: PluginType",
            config_schema, installed_at, enabled_at
        FROM plugins
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Plugin not found".to_string()))?;

    Ok(Json(PluginResponse {
        id: plugin.id,
        name: plugin.name,
        version: plugin.version,
        display_name: plugin.display_name,
        description: plugin.description,
        author: plugin.author,
        homepage: plugin.homepage,
        status: format!("{:?}", plugin.status).to_lowercase(),
        plugin_type: format!("{:?}", plugin.plugin_type).to_lowercase(),
        config_schema: plugin.config_schema,
        installed_at: plugin.installed_at,
        enabled_at: plugin.enabled_at,
    }))
}

/// Uninstall plugin
pub async fn uninstall_plugin(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let result = sqlx::query!("DELETE FROM plugins WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Plugin not found".to_string()));
    }

    Ok(())
}

/// Enable plugin
pub async fn enable_plugin(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let result = sqlx::query!(
        r#"
        UPDATE plugins
        SET status = 'active', enabled_at = NOW()
        WHERE id = $1 AND status = 'disabled'
        "#,
        id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        // Check if plugin exists
        let exists = sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM plugins WHERE id = $1)", id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if exists != Some(true) {
            return Err(AppError::NotFound("Plugin not found".to_string()));
        }
        // Plugin exists but wasn't disabled - that's fine
    }

    Ok(())
}

/// Disable plugin
pub async fn disable_plugin(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let result = sqlx::query!(
        r#"
        UPDATE plugins
        SET status = 'disabled'
        WHERE id = $1 AND status = 'active'
        "#,
        id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        let exists = sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM plugins WHERE id = $1)", id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if exists != Some(true) {
            return Err(AppError::NotFound("Plugin not found".to_string()));
        }
    }

    Ok(())
}

#[derive(Debug, Serialize)]
pub struct PluginConfigResponse {
    pub plugin_id: Uuid,
    pub config: serde_json::Value,
    pub schema: Option<serde_json::Value>,
}

/// Get plugin configuration
pub async fn get_plugin_config(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PluginConfigResponse>> {
    let plugin = sqlx::query!(
        r#"
        SELECT config, config_schema
        FROM plugins
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Plugin not found".to_string()))?;

    Ok(Json(PluginConfigResponse {
        plugin_id: id,
        config: plugin.config.unwrap_or(serde_json::json!({})),
        schema: plugin.config_schema,
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdatePluginConfigRequest {
    pub config: serde_json::Value,
}

/// Update plugin configuration
pub async fn update_plugin_config(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdatePluginConfigRequest>,
) -> Result<Json<PluginConfigResponse>> {
    let plugin = sqlx::query!(
        r#"
        UPDATE plugins
        SET config = $2
        WHERE id = $1
        RETURNING config_schema
        "#,
        id,
        payload.config
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Plugin not found".to_string()))?;

    Ok(Json(PluginConfigResponse {
        plugin_id: id,
        config: payload.config,
        schema: plugin.config_schema,
    }))
}

// =========================================================================
// T021-T027: WASM Plugin Endpoints
// =========================================================================

/// Request to install a plugin from Git
#[derive(Debug, Deserialize)]
pub struct InstallFromGitRequest {
    /// Git repository URL
    pub url: String,
    /// Git ref (tag, branch, or commit)
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
}

/// Response for plugin installation
#[derive(Debug, Serialize)]
pub struct PluginInstallResponse {
    pub plugin_id: Uuid,
    pub name: String,
    pub version: String,
    pub format_key: String,
    pub message: String,
}

/// Install a plugin from a Git repository (T021)
pub async fn install_from_git(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(payload): Json<InstallFromGitRequest>,
) -> Result<Json<PluginInstallResponse>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    let result = wasm_service
        .install_from_git(&payload.url, payload.git_ref.as_deref())
        .await?;

    Ok(Json(PluginInstallResponse {
        plugin_id: result.plugin_id,
        name: result.name,
        version: result.version,
        format_key: result.format_key,
        message: "Plugin installed successfully".to_string(),
    }))
}

/// Install a plugin from a ZIP file (T034)
pub async fn install_from_zip(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    mut multipart: Multipart,
) -> Result<Json<PluginInstallResponse>> {
    // Extract ZIP file from multipart upload
    let mut zip_data: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" || name == "package" || name == "zip" {
            zip_data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| AppError::Validation(format!("Failed to read file: {}", e)))?
                    .to_vec(),
            );
        }
    }

    let zip_data = zip_data.ok_or_else(|| AppError::Validation("Missing ZIP file".to_string()))?;

    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    let result = wasm_service.install_from_zip(&zip_data).await?;

    Ok(Json(PluginInstallResponse {
        plugin_id: result.plugin_id,
        name: result.name,
        version: result.version,
        format_key: result.format_key,
        message: "Plugin installed successfully from ZIP".to_string(),
    }))
}

/// Get plugin events (T026)
pub async fn get_plugin_events(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Vec<serde_json::Value>>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    let events = wasm_service.get_plugin_events(id, query.limit).await?;

    Ok(Json(events))
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub limit: Option<i64>,
}

/// Reload a plugin (hot-reload) (T048)
pub async fn reload_plugin(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<WasmPluginResponse>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    let plugin = wasm_service.reload_plugin(id).await?;

    Ok(Json(WasmPluginResponse::from(plugin)))
}

/// Request for uninstalling a plugin
#[derive(Debug, Deserialize)]
pub struct UninstallQuery {
    pub force: Option<bool>,
}

/// WASM plugin response with extended fields
#[derive(Debug, Serialize)]
pub struct WasmPluginResponse {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub display_name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub status: String,
    pub plugin_type: String,
    pub source_type: String,
    pub source_url: Option<String>,
    pub source_ref: Option<String>,
    pub capabilities: Option<serde_json::Value>,
    pub resource_limits: Option<serde_json::Value>,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub enabled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<crate::models::plugin::Plugin> for WasmPluginResponse {
    fn from(p: crate::models::plugin::Plugin) -> Self {
        Self {
            id: p.id,
            name: p.name,
            version: p.version,
            display_name: p.display_name,
            description: p.description,
            author: p.author,
            homepage: p.homepage,
            license: p.license,
            status: format!("{:?}", p.status).to_lowercase(),
            plugin_type: format!("{:?}", p.plugin_type).to_lowercase(),
            source_type: format!("{:?}", p.source_type).to_lowercase(),
            source_url: p.source_url,
            source_ref: p.source_ref,
            capabilities: p.capabilities,
            resource_limits: p.resource_limits,
            installed_at: p.installed_at,
            enabled_at: p.enabled_at,
            updated_at: p.updated_at,
        }
    }
}

// =========================================================================
// T039-T043: Format Handler Endpoints
// =========================================================================

#[derive(Debug, Deserialize)]
pub struct ListFormatsQuery {
    #[serde(rename = "type")]
    pub handler_type: Option<String>,
    pub enabled: Option<bool>,
}

/// List all format handlers (T039)
pub async fn list_format_handlers(
    State(state): State<SharedState>,
    Query(query): Query<ListFormatsQuery>,
) -> Result<Json<Vec<FormatHandlerResponse>>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    let handler_type = query.handler_type.as_ref().and_then(|t| {
        match t.to_lowercase().as_str() {
            "core" => Some(FormatHandlerType::Core),
            "wasm" => Some(FormatHandlerType::Wasm),
            _ => None,
        }
    });

    let handlers = wasm_service
        .list_format_handlers(handler_type, query.enabled)
        .await?;

    Ok(Json(handlers))
}

/// Get a format handler by key (T040)
pub async fn get_format_handler(
    State(state): State<SharedState>,
    Path(format_key): Path<String>,
) -> Result<Json<FormatHandlerResponse>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    let handler = wasm_service.get_format_handler(&format_key).await?;

    Ok(Json(handler))
}

/// Enable a format handler (T041)
pub async fn enable_format_handler(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(format_key): Path<String>,
) -> Result<Json<FormatHandlerResponse>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    let handler = wasm_service.enable_format_handler(&format_key).await?;

    Ok(Json(handler))
}

/// Disable a format handler (T042)
pub async fn disable_format_handler(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(format_key): Path<String>,
) -> Result<Json<FormatHandlerResponse>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    let handler = wasm_service.disable_format_handler(&format_key).await?;

    Ok(Json(handler))
}

// =========================================================================
// T062: Test Format Handler Endpoint
// =========================================================================

/// Request for testing a format handler
#[derive(Debug, Deserialize)]
pub struct TestFormatRequest {
    /// Path to simulate for the artifact
    pub path: String,
    /// Base64-encoded content to test, or raw string content
    pub content: String,
    /// Whether content is base64 encoded
    #[serde(default)]
    pub base64: bool,
}

/// Response from format handler test
#[derive(Debug, Serialize)]
pub struct TestFormatResponse {
    /// Whether validation passed
    pub valid: bool,
    /// Validation error message if any
    pub validation_error: Option<String>,
    /// Parsed metadata if parse_metadata succeeded
    pub metadata: Option<TestMetadata>,
    /// Parse error message if any
    pub parse_error: Option<String>,
}

/// Metadata returned from testing
#[derive(Debug, Serialize)]
pub struct TestMetadata {
    pub path: String,
    pub version: Option<String>,
    pub content_type: String,
    pub size_bytes: u64,
}

/// Test a format handler with sample content (T062)
pub async fn test_format_handler(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(format_key): Path<String>,
    Json(request): Json<TestFormatRequest>,
) -> Result<Json<TestFormatResponse>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    // Decode content
    let content = if request.base64 {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&request.content)
            .map_err(|e| AppError::Validation(format!("Invalid base64 content: {}", e)))?
    } else {
        request.content.into_bytes()
    };

    // Test the format handler
    let result = wasm_service
        .test_format_handler(&format_key, &request.path, &content)
        .await;

    match result {
        Ok((metadata, validation_result)) => {
            let (valid, validation_error) = match validation_result {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            };

            Ok(Json(TestFormatResponse {
                valid,
                validation_error,
                metadata: Some(TestMetadata {
                    path: metadata.path,
                    version: metadata.version,
                    content_type: metadata.content_type,
                    size_bytes: metadata.size_bytes,
                }),
                parse_error: None,
            }))
        }
        Err(e) => {
            // Parse or execution error
            Ok(Json(TestFormatResponse {
                valid: false,
                validation_error: None,
                metadata: None,
                parse_error: Some(e.to_string()),
            }))
        }
    }
}

// =========================================================================
// T063: Install Plugin from Local Path (Development)
// =========================================================================

/// Request for installing from local file path
#[derive(Debug, Deserialize)]
pub struct InstallFromLocalRequest {
    /// Local filesystem path to plugin directory
    pub path: String,
}

/// Install a plugin from local filesystem path (T063)
/// This endpoint is intended for development use only.
pub async fn install_from_local(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(request): Json<InstallFromLocalRequest>,
) -> Result<Json<PluginInstallResponse>> {
    let wasm_service = state
        .wasm_plugin_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("WASM plugin service not available".to_string()))?;

    // Verify path exists and is a directory
    let path = std::path::Path::new(&request.path);
    if !path.exists() {
        return Err(AppError::Validation(format!(
            "Path does not exist: {}",
            request.path
        )));
    }
    if !path.is_dir() {
        return Err(AppError::Validation(format!(
            "Path is not a directory: {}",
            request.path
        )));
    }

    let result = wasm_service.install_from_local(&request.path).await?;

    Ok(Json(PluginInstallResponse {
        plugin_id: result.plugin_id,
        name: result.name,
        version: result.version,
        format_key: result.format_key,
        status: "installed".to_string(),
    }))
}
