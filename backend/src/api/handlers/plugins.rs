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

/// Create plugin routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_plugins).post(install_plugin))
        .route("/:id", get(get_plugin).delete(uninstall_plugin))
        .route("/:id/enable", post(enable_plugin))
        .route("/:id/disable", post(disable_plugin))
        .route("/:id/config", get(get_plugin_config).post(update_plugin_config))
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
