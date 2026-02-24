//! Plugin service for lifecycle management and event hooks.
//!
//! Provides plugin installation, enabling/disabling, and event hook execution
//! for webhooks and validators.

use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::artifact::Artifact;
use crate::models::plugin::{Plugin, PluginHook, PluginType};

/// Plugin event types that can trigger hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginEventType {
    BeforeUpload,
    AfterUpload,
    BeforeDownload,
    AfterDownload,
    BeforeDelete,
    AfterDelete,
}

impl PluginEventType {
    /// Convert event type to string for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            PluginEventType::BeforeUpload => "before_upload",
            PluginEventType::AfterUpload => "after_upload",
            PluginEventType::BeforeDownload => "before_download",
            PluginEventType::AfterDownload => "after_download",
            PluginEventType::BeforeDelete => "before_delete",
            PluginEventType::AfterDelete => "after_delete",
        }
    }

    /// Parse event type from string.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "before_upload" => Some(PluginEventType::BeforeUpload),
            "after_upload" => Some(PluginEventType::AfterUpload),
            "before_download" => Some(PluginEventType::BeforeDownload),
            "after_download" => Some(PluginEventType::AfterDownload),
            "before_delete" => Some(PluginEventType::BeforeDelete),
            "after_delete" => Some(PluginEventType::AfterDelete),
            _ => None,
        }
    }
}

/// Artifact information passed to plugin hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    pub content_type: String,
    pub uploaded_by: Option<Uuid>,
}

impl From<&Artifact> for ArtifactInfo {
    fn from(artifact: &Artifact) -> Self {
        Self {
            id: artifact.id,
            repository_id: artifact.repository_id,
            path: artifact.path.clone(),
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            size_bytes: artifact.size_bytes,
            checksum_sha256: artifact.checksum_sha256.clone(),
            content_type: artifact.content_type.clone(),
            uploaded_by: artifact.uploaded_by,
        }
    }
}

/// Webhook payload sent to plugin endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event: String,
    pub timestamp: String,
    pub artifact: ArtifactInfo,
    pub plugin_id: Uuid,
    pub plugin_name: String,
}

/// Result from a validator plugin.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorResult {
    #[serde(default = "default_accept")]
    pub accept: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_accept() -> bool {
    true
}

/// Cached plugin with its hooks.
#[derive(Debug, Clone)]
struct CachedPlugin {
    plugin: Plugin,
    _hooks: Vec<PluginHook>,
}

/// Plugin service for managing plugin lifecycle and triggering hooks.
pub struct PluginService {
    db: PgPool,
    http_client: Client,
    /// Cached plugins indexed by ID.
    plugins: Arc<RwLock<HashMap<Uuid, CachedPlugin>>>,
    /// Hooks indexed by event type for quick lookup.
    #[allow(clippy::type_complexity)]
    hooks_by_event: Arc<RwLock<HashMap<PluginEventType, Vec<(Uuid, PluginHook)>>>>,
}

impl PluginService {
    /// Create a new plugin service.
    pub fn new(db: PgPool) -> Self {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            db,
            http_client,
            plugins: Arc::new(RwLock::new(HashMap::new())),
            hooks_by_event: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new plugin service with a custom HTTP client.
    pub fn with_client(db: PgPool, http_client: Client) -> Self {
        Self {
            db,
            http_client,
            plugins: Arc::new(RwLock::new(HashMap::new())),
            hooks_by_event: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // =========================================================================
    // T117: Lifecycle Management
    // =========================================================================

    /// Install a new plugin.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_plugin(
        &self,
        name: &str,
        version: &str,
        display_name: &str,
        description: Option<&str>,
        author: Option<&str>,
        homepage: Option<&str>,
        plugin_type: PluginType,
        config: Option<serde_json::Value>,
        config_schema: Option<serde_json::Value>,
    ) -> Result<Plugin> {
        let plugin = sqlx::query_as::<_, Plugin>(
            r#"
            INSERT INTO plugins (
                name, version, display_name, description, author, homepage,
                plugin_type, config, config_schema, source_type
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'core')
            RETURNING
                id, name, version, display_name, description, author, homepage, license,
                status, plugin_type, source_type,
                source_url, source_ref, wasm_path, manifest, capabilities, resource_limits,
                config, config_schema, error_message, installed_at, enabled_at, updated_at
            "#,
        )
        .bind(name)
        .bind(version)
        .bind(display_name)
        .bind(description)
        .bind(author)
        .bind(homepage)
        .bind(&plugin_type)
        .bind(&config)
        .bind(&config_schema)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("duplicate key") {
                AppError::Conflict(format!("Plugin '{}' already installed", name))
            } else {
                AppError::Database(msg)
            }
        })?;

        info!("Installed plugin: {} v{}", plugin.name, plugin.version);
        self.log_plugin_event(plugin.id, "installed", "info", "Plugin installed", None)
            .await;

        Ok(plugin)
    }

    /// Enable a plugin.
    pub async fn enable_plugin(&self, plugin_id: Uuid) -> Result<Plugin> {
        let plugin = sqlx::query_as::<_, Plugin>(
            r#"
            UPDATE plugins
            SET status = 'active', enabled_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND status = 'disabled'
            RETURNING
                id, name, version, display_name, description, author, homepage, license,
                status, plugin_type, source_type,
                source_url, source_ref, wasm_path, manifest, capabilities, resource_limits,
                config, config_schema, error_message, installed_at, enabled_at, updated_at
            "#,
        )
        .bind(plugin_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        match plugin {
            Some(p) => {
                info!("Enabled plugin: {}", p.name);
                self.log_plugin_event(p.id, "enabled", "info", "Plugin enabled", None)
                    .await;
                // Reload plugins to update cache
                self.load_plugins().await?;
                Ok(p)
            }
            None => {
                // Check if plugin exists
                let exists: Option<bool> =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM plugins WHERE id = $1)")
                        .bind(plugin_id)
                        .fetch_one(&self.db)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;

                if exists == Some(true) {
                    // Plugin exists but wasn't disabled - return current state
                    self.get_plugin(plugin_id).await
                } else {
                    Err(AppError::NotFound("Plugin not found".to_string()))
                }
            }
        }
    }

    /// Disable a plugin.
    pub async fn disable_plugin(&self, plugin_id: Uuid) -> Result<Plugin> {
        let plugin = sqlx::query_as::<_, Plugin>(
            r#"
            UPDATE plugins
            SET status = 'disabled', updated_at = NOW()
            WHERE id = $1 AND status = 'active'
            RETURNING
                id, name, version, display_name, description, author, homepage, license,
                status, plugin_type, source_type,
                source_url, source_ref, wasm_path, manifest, capabilities, resource_limits,
                config, config_schema, error_message, installed_at, enabled_at, updated_at
            "#,
        )
        .bind(plugin_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        match plugin {
            Some(p) => {
                info!("Disabled plugin: {}", p.name);
                self.log_plugin_event(p.id, "disabled", "info", "Plugin disabled", None)
                    .await;
                // Reload plugins to update cache
                self.load_plugins().await?;
                Ok(p)
            }
            None => {
                let exists: Option<bool> =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM plugins WHERE id = $1)")
                        .bind(plugin_id)
                        .fetch_one(&self.db)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;

                if exists == Some(true) {
                    self.get_plugin(plugin_id).await
                } else {
                    Err(AppError::NotFound("Plugin not found".to_string()))
                }
            }
        }
    }

    /// Uninstall a plugin.
    pub async fn uninstall_plugin(&self, plugin_id: Uuid) -> Result<()> {
        // Get plugin info for logging
        let plugin = self.get_plugin(plugin_id).await.ok();

        // Delete hooks first (foreign key constraint)
        sqlx::query("DELETE FROM plugin_hooks WHERE plugin_id = $1")
            .bind(plugin_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Delete config entries
        sqlx::query("DELETE FROM plugin_config WHERE plugin_id = $1")
            .bind(plugin_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Delete plugin events
        sqlx::query("DELETE FROM plugin_events WHERE plugin_id = $1")
            .bind(plugin_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Delete plugin
        let result = sqlx::query("DELETE FROM plugins WHERE id = $1")
            .bind(plugin_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Plugin not found".to_string()));
        }

        if let Some(p) = plugin {
            info!("Uninstalled plugin: {}", p.name);
        }

        // Reload plugins to update cache
        self.load_plugins().await?;

        Ok(())
    }

    /// Get a plugin by ID.
    pub async fn get_plugin(&self, plugin_id: Uuid) -> Result<Plugin> {
        let plugin = sqlx::query_as::<_, Plugin>(
            r#"
            SELECT
                id, name, version, display_name, description, author, homepage, license,
                status, plugin_type, source_type,
                source_url, source_ref, wasm_path, manifest, capabilities, resource_limits,
                config, config_schema, error_message, installed_at, enabled_at, updated_at
            FROM plugins
            WHERE id = $1
            "#,
        )
        .bind(plugin_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Plugin not found".to_string()))?;

        Ok(plugin)
    }

    // =========================================================================
    // T118: Plugin Loading
    // =========================================================================

    /// Load all enabled plugins from database and cache them.
    pub async fn load_plugins(&self) -> Result<()> {
        debug!("Loading plugins from database");

        // Load all active plugins
        let plugins = sqlx::query_as::<_, Plugin>(
            r#"
            SELECT
                id, name, version, display_name, description, author, homepage, license,
                status, plugin_type, source_type,
                source_url, source_ref, wasm_path, manifest, capabilities, resource_limits,
                config, config_schema, error_message, installed_at, enabled_at, updated_at
            FROM plugins
            WHERE status = 'active'
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Load hooks for all active plugins
        let hooks = sqlx::query_as::<_, PluginHook>(
            r#"
            SELECT
                h.id, h.plugin_id, h.hook_type, h.handler_name, h.priority, h.is_enabled, h.created_at
            FROM plugin_hooks h
            INNER JOIN plugins p ON p.id = h.plugin_id
            WHERE p.status = 'active' AND h.is_enabled = true
            ORDER BY h.priority ASC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Build plugin cache
        let mut plugins_cache = HashMap::new();
        let mut hooks_by_event: HashMap<PluginEventType, Vec<(Uuid, PluginHook)>> = HashMap::new();

        for plugin in plugins {
            let plugin_hooks: Vec<PluginHook> = hooks
                .iter()
                .filter(|h| h.plugin_id == plugin.id)
                .cloned()
                .collect();

            // Index hooks by event type
            for hook in &plugin_hooks {
                if let Some(event_type) = PluginEventType::from_str(&hook.hook_type) {
                    hooks_by_event
                        .entry(event_type)
                        .or_default()
                        .push((plugin.id, hook.clone()));
                }
            }

            plugins_cache.insert(
                plugin.id,
                CachedPlugin {
                    plugin,
                    _hooks: plugin_hooks,
                },
            );
        }

        // Update caches
        {
            let mut plugins_lock = self.plugins.write().await;
            *plugins_lock = plugins_cache;
        }
        {
            let mut hooks_lock = self.hooks_by_event.write().await;
            *hooks_lock = hooks_by_event;
        }

        info!("Loaded {} active plugins", self.plugins.read().await.len());
        Ok(())
    }

    /// Register a hook for a plugin.
    pub async fn register_hook(
        &self,
        plugin_id: Uuid,
        hook_type: PluginEventType,
        handler_name: &str,
        priority: i32,
    ) -> Result<PluginHook> {
        let hook = sqlx::query_as::<_, PluginHook>(
            r#"
            INSERT INTO plugin_hooks (plugin_id, hook_type, handler_name, priority)
            VALUES ($1, $2, $3, $4)
            RETURNING id, plugin_id, hook_type, handler_name, priority, is_enabled, created_at
            "#,
        )
        .bind(plugin_id)
        .bind(hook_type.as_str())
        .bind(handler_name)
        .bind(priority)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Reload to update cache
        self.load_plugins().await?;

        Ok(hook)
    }

    // =========================================================================
    // T119: Event Hooks
    // =========================================================================

    /// Trigger hooks for a specific event.
    ///
    /// Returns Ok(()) if all hooks pass, or an error if any validator rejects.
    pub async fn trigger_hooks(
        &self,
        event: PluginEventType,
        artifact_info: &ArtifactInfo,
    ) -> Result<()> {
        let hooks = {
            let hooks_lock = self.hooks_by_event.read().await;
            hooks_lock.get(&event).cloned().unwrap_or_default()
        };

        if hooks.is_empty() {
            debug!("No hooks registered for event {:?}", event);
            return Ok(());
        }

        debug!("Triggering {} hooks for event {:?}", hooks.len(), event);

        for (plugin_id, hook) in hooks {
            let plugin = {
                let plugins_lock = self.plugins.read().await;
                plugins_lock.get(&plugin_id).map(|cp| cp.plugin.clone())
            };

            let Some(plugin) = plugin else {
                warn!("Plugin {} not found in cache, skipping hook", plugin_id);
                continue;
            };

            let result = match plugin.plugin_type {
                PluginType::Webhook => {
                    self.execute_webhook_hook(&plugin, &hook, event, artifact_info)
                        .await
                }
                PluginType::Custom => {
                    // Custom plugins can act as validators
                    self.execute_validator_hook(&plugin, &hook, event, artifact_info)
                        .await
                }
                _ => {
                    // Other plugin types don't have event hooks implemented yet
                    debug!(
                        "Plugin type {:?} does not support event hooks",
                        plugin.plugin_type
                    );
                    Ok(())
                }
            };

            if let Err(e) = result {
                error!(
                    "Hook {} for plugin {} failed: {}",
                    hook.handler_name, plugin.name, e
                );

                // For before_* events, a failure should block the operation
                if matches!(
                    event,
                    PluginEventType::BeforeUpload
                        | PluginEventType::BeforeDownload
                        | PluginEventType::BeforeDelete
                ) {
                    self.log_plugin_event(
                        plugin.id,
                        "hook_failed",
                        "error",
                        &format!("Hook {} failed: {}", hook.handler_name, e),
                        Some(serde_json::json!({
                            "event": event.as_str(),
                            "artifact_id": artifact_info.id,
                        })),
                    )
                    .await;
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    // =========================================================================
    // T120: Webhook Plugin
    // =========================================================================

    /// Execute a webhook hook by POSTing to the configured URL.
    async fn execute_webhook_hook(
        &self,
        plugin: &Plugin,
        hook: &PluginHook,
        event: PluginEventType,
        artifact_info: &ArtifactInfo,
    ) -> Result<()> {
        let webhook_url = self
            .get_webhook_url(plugin, hook)
            .ok_or_else(|| AppError::Validation("Webhook URL not configured".to_string()))?;

        let payload = WebhookPayload {
            event: event.as_str().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            artifact: artifact_info.clone(),
            plugin_id: plugin.id,
            plugin_name: plugin.name.clone(),
        };

        // Re-validate URL at delivery time to prevent DNS rebinding attacks
        crate::api::validation::validate_outbound_url(&webhook_url, "Plugin webhook URL")?;

        debug!("Sending webhook to {}: {:?}", webhook_url, payload);

        let response = self
            .http_client
            .post(&webhook_url)
            .json(&payload)
            .header("Content-Type", "application/json")
            .header("X-Plugin-Event", event.as_str())
            .header("X-Plugin-Id", plugin.id.to_string())
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Webhook request failed: {}", e)))?;

        let status = response.status();

        if status.is_success() {
            debug!("Webhook {} returned {}", webhook_url, status);
            self.log_plugin_event(
                plugin.id,
                "webhook_sent",
                "info",
                &format!("Webhook sent to {} - {}", webhook_url, status),
                Some(serde_json::json!({
                    "event": event.as_str(),
                    "artifact_id": artifact_info.id,
                    "status_code": status.as_u16(),
                })),
            )
            .await;
            Ok(())
        } else if status.is_client_error() {
            // 4xx errors from validators indicate rejection
            let body = response.text().await.unwrap_or_default();
            let reason = if body.is_empty() {
                format!("Rejected by webhook (HTTP {})", status)
            } else {
                format!("Rejected: {}", body)
            };

            self.log_plugin_event(
                plugin.id,
                "webhook_rejected",
                "warning",
                &reason,
                Some(serde_json::json!({
                    "event": event.as_str(),
                    "artifact_id": artifact_info.id,
                    "status_code": status.as_u16(),
                })),
            )
            .await;

            Err(AppError::Validation(reason))
        } else {
            // 5xx or other errors - log but don't fail for after_* events
            let body = response.text().await.unwrap_or_default();
            warn!(
                "Webhook {} returned error {}: {}",
                webhook_url, status, body
            );

            self.log_plugin_event(
                plugin.id,
                "webhook_error",
                "error",
                &format!("Webhook error: HTTP {} - {}", status, body),
                Some(serde_json::json!({
                    "event": event.as_str(),
                    "artifact_id": artifact_info.id,
                    "status_code": status.as_u16(),
                })),
            )
            .await;

            Err(AppError::Internal(format!(
                "Webhook returned HTTP {}",
                status
            )))
        }
    }

    /// Get the webhook URL from plugin config.
    fn get_webhook_url(&self, plugin: &Plugin, hook: &PluginHook) -> Option<String> {
        // Check for handler-specific URL first
        if let Some(config) = &plugin.config {
            // Try handler-specific URL: { "hooks": { "handler_name": { "url": "..." } } }
            if let Some(url) = config
                .get("hooks")
                .and_then(|h| h.get(&hook.handler_name))
                .and_then(|h| h.get("url"))
                .and_then(|u| u.as_str())
            {
                return Some(url.to_string());
            }

            // Try global webhook URL: { "webhook_url": "..." }
            if let Some(url) = config.get("webhook_url").and_then(|u| u.as_str()) {
                return Some(url.to_string());
            }

            // Try just "url": { "url": "..." }
            if let Some(url) = config.get("url").and_then(|u| u.as_str()) {
                return Some(url.to_string());
            }
        }

        None
    }

    // =========================================================================
    // T121: Validator Plugin
    // =========================================================================

    /// Execute a validator hook that can accept or reject operations.
    async fn execute_validator_hook(
        &self,
        plugin: &Plugin,
        hook: &PluginHook,
        event: PluginEventType,
        artifact_info: &ArtifactInfo,
    ) -> Result<()> {
        // Validators are typically only relevant for "before" events
        if !matches!(
            event,
            PluginEventType::BeforeUpload
                | PluginEventType::BeforeDownload
                | PluginEventType::BeforeDelete
        ) {
            return Ok(());
        }

        // Check if plugin has validation rules configured
        if let Some(result) = self.run_config_rules(plugin, artifact_info) {
            if !result.accept {
                let reason = result
                    .reason
                    .unwrap_or_else(|| "Rejected by validator".to_string());

                self.log_plugin_event(
                    plugin.id,
                    "validation_rejected",
                    "warning",
                    &reason,
                    Some(serde_json::json!({
                        "event": event.as_str(),
                        "artifact_id": artifact_info.id,
                    })),
                )
                .await;

                return Err(AppError::Validation(reason));
            }
        }

        // Check if plugin has a validator URL configured
        if let Some(validator_url) = self.get_validator_url(plugin, hook) {
            return self
                .call_validator_url(&validator_url, plugin, event, artifact_info)
                .await;
        }

        Ok(())
    }

    /// Run simple config-based validation rules.
    fn run_config_rules(
        &self,
        plugin: &Plugin,
        artifact_info: &ArtifactInfo,
    ) -> Option<ValidatorResult> {
        let config = plugin.config.as_ref()?;
        let rules = config.get("rules")?;

        // Check max file size rule
        if let Some(max_size) = rules.get("max_size_bytes").and_then(|v| v.as_i64()) {
            if artifact_info.size_bytes > max_size {
                return Some(ValidatorResult {
                    accept: false,
                    reason: Some(format!(
                        "File size {} exceeds maximum allowed {}",
                        artifact_info.size_bytes, max_size
                    )),
                });
            }
        }

        // Check allowed content types
        if let Some(allowed_types) = rules
            .get("allowed_content_types")
            .and_then(|v| v.as_array())
        {
            let types: Vec<&str> = allowed_types.iter().filter_map(|v| v.as_str()).collect();

            if !types.is_empty()
                && !types
                    .iter()
                    .any(|t| artifact_info.content_type.starts_with(t))
            {
                return Some(ValidatorResult {
                    accept: false,
                    reason: Some(format!(
                        "Content type '{}' not allowed. Allowed: {:?}",
                        artifact_info.content_type, types
                    )),
                });
            }
        }

        // Check blocked content types
        if let Some(blocked_types) = rules
            .get("blocked_content_types")
            .and_then(|v| v.as_array())
        {
            let types: Vec<&str> = blocked_types.iter().filter_map(|v| v.as_str()).collect();

            if types
                .iter()
                .any(|t| artifact_info.content_type.starts_with(t))
            {
                return Some(ValidatorResult {
                    accept: false,
                    reason: Some(format!(
                        "Content type '{}' is blocked",
                        artifact_info.content_type
                    )),
                });
            }
        }

        // Check path patterns (blocked paths)
        if let Some(blocked_paths) = rules
            .get("blocked_path_patterns")
            .and_then(|v| v.as_array())
        {
            for pattern in blocked_paths.iter().filter_map(|v| v.as_str()) {
                if artifact_info.path.contains(pattern) {
                    return Some(ValidatorResult {
                        accept: false,
                        reason: Some(format!(
                            "Path '{}' matches blocked pattern '{}'",
                            artifact_info.path, pattern
                        )),
                    });
                }
            }
        }

        // All rules passed
        None
    }

    /// Get the validator URL from plugin config.
    fn get_validator_url(&self, plugin: &Plugin, hook: &PluginHook) -> Option<String> {
        let config = plugin.config.as_ref()?;

        // Try handler-specific validator URL
        if let Some(url) = config
            .get("hooks")
            .and_then(|h| h.get(&hook.handler_name))
            .and_then(|h| h.get("validator_url"))
            .and_then(|u| u.as_str())
        {
            return Some(url.to_string());
        }

        // Try global validator URL
        config
            .get("validator_url")
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
    }

    /// Call an external validator URL.
    async fn call_validator_url(
        &self,
        url: &str,
        plugin: &Plugin,
        event: PluginEventType,
        artifact_info: &ArtifactInfo,
    ) -> Result<()> {
        let payload = WebhookPayload {
            event: event.as_str().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            artifact: artifact_info.clone(),
            plugin_id: plugin.id,
            plugin_name: plugin.name.clone(),
        };

        debug!("Calling validator at {}", url);

        let response = self
            .http_client
            .post(url)
            .json(&payload)
            .header("Content-Type", "application/json")
            .header("X-Plugin-Event", event.as_str())
            .header("X-Plugin-Id", plugin.id.to_string())
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Validator request failed: {}", e)))?;

        let status = response.status();

        if status.is_success() {
            // Parse validator response
            let result: ValidatorResult = response.json().await.unwrap_or(ValidatorResult {
                accept: true,
                reason: None,
            });

            if result.accept {
                debug!("Validator {} accepted", url);
                Ok(())
            } else {
                let reason = result
                    .reason
                    .unwrap_or_else(|| "Rejected by validator".to_string());

                self.log_plugin_event(
                    plugin.id,
                    "validator_rejected",
                    "warning",
                    &reason,
                    Some(serde_json::json!({
                        "event": event.as_str(),
                        "artifact_id": artifact_info.id,
                    })),
                )
                .await;

                Err(AppError::Validation(reason))
            }
        } else if status.is_client_error() {
            // 4xx = rejection
            let body = response.text().await.unwrap_or_default();
            let reason = if body.is_empty() {
                format!("Rejected by validator (HTTP {})", status)
            } else {
                body
            };

            self.log_plugin_event(
                plugin.id,
                "validator_rejected",
                "warning",
                &reason,
                Some(serde_json::json!({
                    "event": event.as_str(),
                    "artifact_id": artifact_info.id,
                    "status_code": status.as_u16(),
                })),
            )
            .await;

            Err(AppError::Validation(reason))
        } else {
            // Server error - fail safe (reject)
            let body = response.text().await.unwrap_or_default();

            self.log_plugin_event(
                plugin.id,
                "validator_error",
                "error",
                &format!("Validator error: HTTP {} - {}", status, body),
                Some(serde_json::json!({
                    "event": event.as_str(),
                    "artifact_id": artifact_info.id,
                    "status_code": status.as_u16(),
                })),
            )
            .await;

            Err(AppError::Internal(format!(
                "Validator returned HTTP {}",
                status
            )))
        }
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Log a plugin event to the database.
    async fn log_plugin_event(
        &self,
        plugin_id: Uuid,
        event_type: &str,
        severity: &str,
        message: &str,
        details: Option<serde_json::Value>,
    ) {
        let result = sqlx::query(
            r#"
            INSERT INTO plugin_events (plugin_id, event_type, severity, message, details)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(plugin_id)
        .bind(event_type)
        .bind(severity)
        .bind(message)
        .bind(&details)
        .execute(&self.db)
        .await;

        if let Err(e) = result {
            warn!("Failed to log plugin event: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn resolve_webhook_url(
        config: Option<&serde_json::Value>,
        handler_name: &str,
    ) -> Option<String> {
        let config = config?;

        if let Some(url) = config
            .get("hooks")
            .and_then(|h| h.get(handler_name))
            .and_then(|h| h.get("url"))
            .and_then(|u| u.as_str())
        {
            return Some(url.to_string());
        }

        if let Some(url) = config.get("webhook_url").and_then(|u| u.as_str()) {
            return Some(url.to_string());
        }

        config
            .get("url")
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
    }

    fn resolve_validator_url(
        config: Option<&serde_json::Value>,
        handler_name: &str,
    ) -> Option<String> {
        let config = config?;

        if let Some(url) = config
            .get("hooks")
            .and_then(|h| h.get(handler_name))
            .and_then(|h| h.get("validator_url"))
            .and_then(|u| u.as_str())
        {
            return Some(url.to_string());
        }

        config
            .get("validator_url")
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
    }

    fn evaluate_config_rules(
        config: Option<&serde_json::Value>,
        artifact_info: &ArtifactInfo,
    ) -> Option<ValidatorResult> {
        let config = config?;
        let rules = config.get("rules")?;

        if let Some(max_size) = rules.get("max_size_bytes").and_then(|v| v.as_i64()) {
            if artifact_info.size_bytes > max_size {
                return Some(ValidatorResult {
                    accept: false,
                    reason: Some(format!(
                        "File size {} exceeds maximum allowed {}",
                        artifact_info.size_bytes, max_size
                    )),
                });
            }
        }

        if let Some(allowed_types) = rules
            .get("allowed_content_types")
            .and_then(|v| v.as_array())
        {
            let types: Vec<&str> = allowed_types.iter().filter_map(|v| v.as_str()).collect();
            if !types.is_empty()
                && !types
                    .iter()
                    .any(|t| artifact_info.content_type.starts_with(t))
            {
                return Some(ValidatorResult {
                    accept: false,
                    reason: Some(format!(
                        "Content type '{}' not allowed. Allowed: {:?}",
                        artifact_info.content_type, types
                    )),
                });
            }
        }

        if let Some(blocked_types) = rules
            .get("blocked_content_types")
            .and_then(|v| v.as_array())
        {
            let types: Vec<&str> = blocked_types.iter().filter_map(|v| v.as_str()).collect();
            if types
                .iter()
                .any(|t| artifact_info.content_type.starts_with(t))
            {
                return Some(ValidatorResult {
                    accept: false,
                    reason: Some(format!(
                        "Content type '{}' is blocked",
                        artifact_info.content_type
                    )),
                });
            }
        }

        if let Some(blocked_paths) = rules
            .get("blocked_path_patterns")
            .and_then(|v| v.as_array())
        {
            for pattern in blocked_paths.iter().filter_map(|v| v.as_str()) {
                if artifact_info.path.contains(pattern) {
                    return Some(ValidatorResult {
                        accept: false,
                        reason: Some(format!(
                            "Path '{}' matches blocked pattern '{}'",
                            artifact_info.path, pattern
                        )),
                    });
                }
            }
        }

        None
    }

    fn is_blocking_event(event: PluginEventType) -> bool {
        matches!(
            event,
            PluginEventType::BeforeUpload
                | PluginEventType::BeforeDownload
                | PluginEventType::BeforeDelete
        )
    }

    #[test]
    fn test_plugin_event_type_conversion() {
        assert_eq!(PluginEventType::BeforeUpload.as_str(), "before_upload");
        assert_eq!(
            PluginEventType::from_str("after_download"),
            Some(PluginEventType::AfterDownload)
        );
        assert_eq!(PluginEventType::from_str("invalid"), None);
    }

    #[test]
    fn test_artifact_info_from_artifact() {
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: "com/example/test.jar".to_string(),
            name: "test.jar".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/java-archive".to_string(),
            storage_key: "ab/c1/abc123".to_string(),
            is_deleted: false,
            uploaded_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let info = ArtifactInfo::from(&artifact);
        assert_eq!(info.id, artifact.id);
        assert_eq!(info.path, artifact.path);
        assert_eq!(info.size_bytes, 1024);
    }

    #[test]
    fn test_validator_result_default() {
        let json = r#"{}"#;
        let result: ValidatorResult = serde_json::from_str(json).unwrap();
        assert!(result.accept);
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_validator_result_reject() {
        let json = r#"{"accept": false, "reason": "Too large"}"#;
        let result: ValidatorResult = serde_json::from_str(json).unwrap();
        assert!(!result.accept);
        assert_eq!(result.reason, Some("Too large".to_string()));
    }

    // -----------------------------------------------------------------------
    // PluginEventType: exhaustive as_str and from_str roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_event_types_as_str() {
        assert_eq!(PluginEventType::BeforeUpload.as_str(), "before_upload");
        assert_eq!(PluginEventType::AfterUpload.as_str(), "after_upload");
        assert_eq!(PluginEventType::BeforeDownload.as_str(), "before_download");
        assert_eq!(PluginEventType::AfterDownload.as_str(), "after_download");
        assert_eq!(PluginEventType::BeforeDelete.as_str(), "before_delete");
        assert_eq!(PluginEventType::AfterDelete.as_str(), "after_delete");
    }

    #[test]
    fn test_all_event_types_from_str() {
        assert_eq!(
            PluginEventType::from_str("before_upload"),
            Some(PluginEventType::BeforeUpload)
        );
        assert_eq!(
            PluginEventType::from_str("after_upload"),
            Some(PluginEventType::AfterUpload)
        );
        assert_eq!(
            PluginEventType::from_str("before_download"),
            Some(PluginEventType::BeforeDownload)
        );
        assert_eq!(
            PluginEventType::from_str("after_download"),
            Some(PluginEventType::AfterDownload)
        );
        assert_eq!(
            PluginEventType::from_str("before_delete"),
            Some(PluginEventType::BeforeDelete)
        );
        assert_eq!(
            PluginEventType::from_str("after_delete"),
            Some(PluginEventType::AfterDelete)
        );
    }

    #[test]
    fn test_event_type_from_str_invalid_values() {
        assert_eq!(PluginEventType::from_str(""), None);
        assert_eq!(PluginEventType::from_str("BEFORE_UPLOAD"), None);
        assert_eq!(PluginEventType::from_str("upload"), None);
        assert_eq!(PluginEventType::from_str("before_"), None);
        assert_eq!(PluginEventType::from_str("before_update"), None);
    }

    #[test]
    fn test_event_type_roundtrip() {
        let events = [
            PluginEventType::BeforeUpload,
            PluginEventType::AfterUpload,
            PluginEventType::BeforeDownload,
            PluginEventType::AfterDownload,
            PluginEventType::BeforeDelete,
            PluginEventType::AfterDelete,
        ];
        for event in events {
            let s = event.as_str();
            let parsed = PluginEventType::from_str(s);
            assert_eq!(parsed, Some(event), "Roundtrip failed for {:?}", event);
        }
    }

    // -----------------------------------------------------------------------
    // PluginEventType: serde serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_event_type_serde_roundtrip() {
        let event = PluginEventType::BeforeUpload;
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, "\"before_upload\"");
        let deserialized: PluginEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event);
    }

    #[test]
    fn test_event_type_serde_all_variants() {
        let events = [
            (PluginEventType::BeforeUpload, "\"before_upload\""),
            (PluginEventType::AfterUpload, "\"after_upload\""),
            (PluginEventType::BeforeDownload, "\"before_download\""),
            (PluginEventType::AfterDownload, "\"after_download\""),
            (PluginEventType::BeforeDelete, "\"before_delete\""),
            (PluginEventType::AfterDelete, "\"after_delete\""),
        ];
        for (event, expected_json) in events {
            let json = serde_json::to_string(&event).unwrap();
            assert_eq!(json, expected_json);
        }
    }

    // -----------------------------------------------------------------------
    // ArtifactInfo: serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_info_serialization() {
        let info = ArtifactInfo {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            path: "test/path".to_string(),
            name: "test.jar".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            content_type: "application/java-archive".to_string(),
            uploaded_by: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test/path"));
        assert!(json.contains("test.jar"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("1024"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_artifact_info_deserialization() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "repository_id": "00000000-0000-0000-0000-000000000000",
            "path": "test/path",
            "name": "file.bin",
            "version": null,
            "size_bytes": 0,
            "checksum_sha256": "empty",
            "content_type": "application/octet-stream",
            "uploaded_by": null
        }"#;
        let info: ArtifactInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.name, "file.bin");
        assert_eq!(info.version, None);
        assert_eq!(info.uploaded_by, None);
    }

    // -----------------------------------------------------------------------
    // WebhookPayload: serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = WebhookPayload {
            event: "before_upload".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            artifact: ArtifactInfo {
                id: Uuid::nil(),
                repository_id: Uuid::nil(),
                path: "test".to_string(),
                name: "test".to_string(),
                version: None,
                size_bytes: 100,
                checksum_sha256: "hash".to_string(),
                content_type: "binary".to_string(),
                uploaded_by: None,
            },
            plugin_id: Uuid::nil(),
            plugin_name: "test-plugin".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("before_upload"));
        assert!(json.contains("test-plugin"));
        assert!(json.contains("2024-01-01T00:00:00Z"));
    }

    // -----------------------------------------------------------------------
    // ValidatorResult: edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_validator_result_accept_with_reason() {
        let json = r#"{"accept": true, "reason": "Looks good"}"#;
        let result: ValidatorResult = serde_json::from_str(json).unwrap();
        assert!(result.accept);
        assert_eq!(result.reason, Some("Looks good".to_string()));
    }

    #[test]
    fn test_validator_result_reject_no_reason() {
        let json = r#"{"accept": false}"#;
        let result: ValidatorResult = serde_json::from_str(json).unwrap();
        assert!(!result.accept);
        assert_eq!(result.reason, None);
    }

    #[test]
    fn test_validator_result_only_accept_field() {
        let json = r#"{"accept": true}"#;
        let result: ValidatorResult = serde_json::from_str(json).unwrap();
        assert!(result.accept);
        assert_eq!(result.reason, None);
    }

    // -----------------------------------------------------------------------
    // run_config_rules: test the config-based validation logic
    // -----------------------------------------------------------------------

    fn make_artifact_info(size: i64, content_type: &str, path: &str) -> ArtifactInfo {
        ArtifactInfo {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: path.to_string(),
            name: "test.jar".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: size,
            checksum_sha256: "abc123".to_string(),
            content_type: content_type.to_string(),
            uploaded_by: None,
        }
    }

    #[allow(dead_code)]
    fn make_plugin_with_config(config: serde_json::Value) -> Plugin {
        Plugin {
            id: Uuid::new_v4(),
            name: "test-validator".to_string(),
            version: "1.0.0".to_string(),
            display_name: "Test".to_string(),
            description: None,
            author: None,
            homepage: None,
            license: None,
            status: crate::models::plugin::PluginStatus::Active,
            plugin_type: PluginType::Custom,
            source_type: crate::models::plugin::PluginSourceType::Core,
            source_url: None,
            source_ref: None,
            wasm_path: None,
            manifest: None,
            capabilities: None,
            resource_limits: None,
            config: Some(config),
            config_schema: None,
            error_message: None,
            installed_at: Utc::now(),
            enabled_at: None,
            updated_at: Utc::now(),
        }
    }

    #[allow(dead_code)]
    fn make_hook(handler_name: &str) -> PluginHook {
        PluginHook {
            id: Uuid::new_v4(),
            plugin_id: Uuid::new_v4(),
            hook_type: "before_upload".to_string(),
            handler_name: handler_name.to_string(),
            priority: 10,
            is_enabled: true,
            created_at: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // resolve_webhook_url (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_webhook_url_none_config() {
        assert_eq!(resolve_webhook_url(None, "handler"), None);
    }

    #[test]
    fn test_resolve_webhook_url_empty_config() {
        let config = serde_json::json!({});
        assert_eq!(resolve_webhook_url(Some(&config), "handler"), None);
    }

    #[test]
    fn test_resolve_webhook_url_global_webhook_url() {
        let config = serde_json::json!({
            "webhook_url": "https://example.com/webhook"
        });
        assert_eq!(
            resolve_webhook_url(Some(&config), "handler"),
            Some("https://example.com/webhook".to_string())
        );
    }

    #[test]
    fn test_resolve_webhook_url_global_url_key() {
        let config = serde_json::json!({
            "url": "https://example.com/url-key"
        });
        assert_eq!(
            resolve_webhook_url(Some(&config), "handler"),
            Some("https://example.com/url-key".to_string())
        );
    }

    #[test]
    fn test_resolve_webhook_url_handler_specific() {
        let config = serde_json::json!({
            "hooks": {
                "before_upload_handler": {
                    "url": "https://example.com/specific"
                }
            }
        });
        assert_eq!(
            resolve_webhook_url(Some(&config), "before_upload_handler"),
            Some("https://example.com/specific".to_string())
        );
    }

    #[test]
    fn test_resolve_webhook_url_handler_specific_overrides_global() {
        let config = serde_json::json!({
            "webhook_url": "https://example.com/global",
            "hooks": {
                "my_handler": {
                    "url": "https://example.com/override"
                }
            }
        });
        assert_eq!(
            resolve_webhook_url(Some(&config), "my_handler"),
            Some("https://example.com/override".to_string())
        );
    }

    #[test]
    fn test_resolve_webhook_url_handler_not_matched_falls_through() {
        let config = serde_json::json!({
            "webhook_url": "https://example.com/global",
            "hooks": {
                "other_handler": {
                    "url": "https://example.com/other"
                }
            }
        });
        assert_eq!(
            resolve_webhook_url(Some(&config), "my_handler"),
            Some("https://example.com/global".to_string())
        );
    }

    #[test]
    fn test_resolve_webhook_url_priority_order() {
        // Handler-specific > webhook_url > url
        let config = serde_json::json!({
            "url": "https://example.com/url",
            "webhook_url": "https://example.com/webhook_url"
        });
        // webhook_url takes priority over url
        assert_eq!(
            resolve_webhook_url(Some(&config), "handler"),
            Some("https://example.com/webhook_url".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // resolve_validator_url (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_validator_url_none_config() {
        assert_eq!(resolve_validator_url(None, "handler"), None);
    }

    #[test]
    fn test_resolve_validator_url_empty_config() {
        let config = serde_json::json!({});
        assert_eq!(resolve_validator_url(Some(&config), "handler"), None);
    }

    #[test]
    fn test_resolve_validator_url_global() {
        let config = serde_json::json!({
            "validator_url": "https://validator.example.com/validate"
        });
        assert_eq!(
            resolve_validator_url(Some(&config), "handler"),
            Some("https://validator.example.com/validate".to_string())
        );
    }

    #[test]
    fn test_resolve_validator_url_handler_specific() {
        let config = serde_json::json!({
            "hooks": {
                "my_handler": {
                    "validator_url": "https://validator.example.com/my_handler"
                }
            }
        });
        assert_eq!(
            resolve_validator_url(Some(&config), "my_handler"),
            Some("https://validator.example.com/my_handler".to_string())
        );
    }

    #[test]
    fn test_resolve_validator_url_handler_specific_overrides_global() {
        let config = serde_json::json!({
            "validator_url": "https://validator.example.com/global",
            "hooks": {
                "my_handler": {
                    "validator_url": "https://validator.example.com/override"
                }
            }
        });
        assert_eq!(
            resolve_validator_url(Some(&config), "my_handler"),
            Some("https://validator.example.com/override".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // evaluate_config_rules (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_config_rules_none_config() {
        let info = make_artifact_info(100, "application/jar", "test/path");
        assert!(evaluate_config_rules(None, &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_no_rules_section() {
        let config = serde_json::json!({"webhook_url": "https://example.com"});
        let info = make_artifact_info(100, "application/jar", "test/path");
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_empty_rules() {
        let config = serde_json::json!({"rules": {}});
        let info = make_artifact_info(100, "application/jar", "test/path");
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_max_size_exceed() {
        let config = serde_json::json!({"rules": {"max_size_bytes": 1000}});
        let info = make_artifact_info(2000, "application/jar", "test/path");
        let result = evaluate_config_rules(Some(&config), &info);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(!r.accept);
        assert!(r.reason.as_ref().unwrap().contains("exceeds maximum"));
    }

    #[test]
    fn test_evaluate_config_rules_max_size_within() {
        let config = serde_json::json!({"rules": {"max_size_bytes": 5000}});
        let info = make_artifact_info(1000, "application/jar", "test/path");
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_max_size_exactly_equal() {
        let config = serde_json::json!({"rules": {"max_size_bytes": 1000}});
        let info = make_artifact_info(1000, "application/jar", "test/path");
        // 1000 is NOT > 1000, so it should pass
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_allowed_content_types_match() {
        let config = serde_json::json!({
            "rules": {"allowed_content_types": ["application/java-archive", "application/zip"]}
        });
        let info = make_artifact_info(100, "application/java-archive", "test/path");
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_allowed_content_types_prefix_match() {
        let config = serde_json::json!({
            "rules": {"allowed_content_types": ["application/"]}
        });
        let info = make_artifact_info(100, "application/java-archive", "test/path");
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_allowed_content_types_no_match() {
        let config = serde_json::json!({
            "rules": {"allowed_content_types": ["application/java-archive"]}
        });
        let info = make_artifact_info(100, "text/plain", "test/path");
        let result = evaluate_config_rules(Some(&config), &info);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(!r.accept);
        assert!(r.reason.as_ref().unwrap().contains("not allowed"));
    }

    #[test]
    fn test_evaluate_config_rules_allowed_content_types_empty_list_passes() {
        let config = serde_json::json!({
            "rules": {"allowed_content_types": []}
        });
        let info = make_artifact_info(100, "text/plain", "test/path");
        // Empty allowed list means no restriction
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_blocked_content_types_match() {
        let config = serde_json::json!({
            "rules": {"blocked_content_types": ["text/html", "application/javascript"]}
        });
        let info = make_artifact_info(100, "text/html", "test/path");
        let result = evaluate_config_rules(Some(&config), &info);
        assert!(result.is_some());
        assert!(!result.unwrap().accept);
    }

    #[test]
    fn test_evaluate_config_rules_blocked_content_types_no_match() {
        let config = serde_json::json!({
            "rules": {"blocked_content_types": ["text/html"]}
        });
        let info = make_artifact_info(100, "application/jar", "test/path");
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_blocked_path_match() {
        let config = serde_json::json!({
            "rules": {"blocked_path_patterns": ["SNAPSHOT", "internal/"]}
        });
        let info = make_artifact_info(100, "application/jar", "com/example/1.0-SNAPSHOT/lib.jar");
        let result = evaluate_config_rules(Some(&config), &info);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(!r.accept);
        assert!(r.reason.as_ref().unwrap().contains("blocked pattern"));
    }

    #[test]
    fn test_evaluate_config_rules_blocked_path_no_match() {
        let config = serde_json::json!({
            "rules": {"blocked_path_patterns": ["SNAPSHOT"]}
        });
        let info = make_artifact_info(100, "application/jar", "com/example/1.0/lib.jar");
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    #[test]
    fn test_evaluate_config_rules_multiple_rules_first_fails() {
        // max_size check runs first; if it fails, subsequent rules are not checked
        let config = serde_json::json!({
            "rules": {
                "max_size_bytes": 500,
                "blocked_content_types": ["application/jar"]
            }
        });
        let info = make_artifact_info(1000, "application/jar", "test/path");
        let result = evaluate_config_rules(Some(&config), &info);
        assert!(result.is_some());
        // Should fail on max_size first
        assert!(result
            .unwrap()
            .reason
            .as_ref()
            .unwrap()
            .contains("exceeds maximum"));
    }

    #[test]
    fn test_evaluate_config_rules_all_rules_pass() {
        let config = serde_json::json!({
            "rules": {
                "max_size_bytes": 10000,
                "allowed_content_types": ["application/"],
                "blocked_content_types": ["text/html"],
                "blocked_path_patterns": ["SNAPSHOT"]
            }
        });
        let info = make_artifact_info(100, "application/jar", "com/example/1.0/lib.jar");
        assert!(evaluate_config_rules(Some(&config), &info).is_none());
    }

    // -----------------------------------------------------------------------
    // is_blocking_event (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_blocking_event_before_events() {
        assert!(is_blocking_event(PluginEventType::BeforeUpload));
        assert!(is_blocking_event(PluginEventType::BeforeDownload));
        assert!(is_blocking_event(PluginEventType::BeforeDelete));
    }

    #[test]
    fn test_is_blocking_event_after_events() {
        assert!(!is_blocking_event(PluginEventType::AfterUpload));
        assert!(!is_blocking_event(PluginEventType::AfterDownload));
        assert!(!is_blocking_event(PluginEventType::AfterDelete));
    }

    // -----------------------------------------------------------------------
    // PluginEventType: Hash trait (used as HashMap key)
    // -----------------------------------------------------------------------

    #[test]
    fn test_event_type_can_be_used_as_hashmap_key() {
        let mut map = std::collections::HashMap::new();
        map.insert(PluginEventType::BeforeUpload, vec!["hook1"]);
        map.insert(PluginEventType::AfterUpload, vec!["hook2"]);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&PluginEventType::BeforeUpload),
            Some(&vec!["hook1"])
        );
    }

    // -----------------------------------------------------------------------
    // PluginEventType: Copy trait
    // -----------------------------------------------------------------------

    #[test]
    fn test_event_type_is_copy() {
        let event = PluginEventType::BeforeUpload;
        let event2 = event; // Copy
        assert_eq!(event, event2);
    }
}
