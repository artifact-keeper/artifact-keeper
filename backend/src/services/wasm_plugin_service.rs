//! WASM plugin service for managing WASM-based format handler plugins.
//!
//! Provides Git/ZIP installation, format handler CRUD operations,
//! manifest validation, and plugin lifecycle logging.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use sqlx::PgPool;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::format_handler::{
    CreateFormatHandler, FormatHandlerRecord, FormatHandlerResponse, FormatHandlerType,
    UpdateFormatHandler,
};
use crate::models::plugin::{
    Plugin, PluginCapabilities, PluginResourceLimits, PluginSourceType, PluginStatus, PluginType,
};
use crate::models::plugin_manifest::{ManifestValidationError, PluginManifest};

use super::plugin_registry::PluginRegistry;

/// Result of a plugin installation operation.
#[derive(Debug, Clone)]
pub struct PluginInstallResult {
    pub plugin_id: Uuid,
    pub name: String,
    pub version: String,
    pub format_key: String,
}

/// Metadata returned from testing a format handler (T062).
#[derive(Debug, Clone)]
pub struct TestMetadata {
    pub path: String,
    pub version: Option<String>,
    pub content_type: String,
    pub size_bytes: u64,
}

/// WASM plugin service for managing format handler plugins.
pub struct WasmPluginService {
    db: PgPool,
    registry: Arc<PluginRegistry>,
    plugins_dir: PathBuf,
}

impl WasmPluginService {
    /// Create a new WASM plugin service.
    pub fn new(db: PgPool, registry: Arc<PluginRegistry>, plugins_dir: PathBuf) -> Self {
        Self {
            db,
            registry,
            plugins_dir,
        }
    }

    /// Get the plugin registry.
    pub fn registry(&self) -> &Arc<PluginRegistry> {
        &self.registry
    }

    // =========================================================================
    // T013: Format Handler CRUD Operations
    // =========================================================================

    /// List all format handlers with optional filters.
    pub async fn list_format_handlers(
        &self,
        handler_type: Option<FormatHandlerType>,
        enabled_only: Option<bool>,
    ) -> Result<Vec<FormatHandlerResponse>> {
        let handlers = match (handler_type, enabled_only) {
            (Some(ht), Some(true)) => {
                sqlx::query_as!(
                    FormatHandlerRecord,
                    r#"
                    SELECT id, format_key, plugin_id,
                           handler_type as "handler_type: FormatHandlerType",
                           display_name, description, extensions,
                           is_enabled, priority, created_at, updated_at
                    FROM format_handlers
                    WHERE handler_type = $1 AND is_enabled = true
                    ORDER BY priority DESC, display_name
                    "#,
                    ht as FormatHandlerType
                )
                .fetch_all(&self.db)
                .await
            }
            (Some(ht), _) => {
                sqlx::query_as!(
                    FormatHandlerRecord,
                    r#"
                    SELECT id, format_key, plugin_id,
                           handler_type as "handler_type: FormatHandlerType",
                           display_name, description, extensions,
                           is_enabled, priority, created_at, updated_at
                    FROM format_handlers
                    WHERE handler_type = $1
                    ORDER BY priority DESC, display_name
                    "#,
                    ht as FormatHandlerType
                )
                .fetch_all(&self.db)
                .await
            }
            (_, Some(true)) => {
                sqlx::query_as!(
                    FormatHandlerRecord,
                    r#"
                    SELECT id, format_key, plugin_id,
                           handler_type as "handler_type: FormatHandlerType",
                           display_name, description, extensions,
                           is_enabled, priority, created_at, updated_at
                    FROM format_handlers
                    WHERE is_enabled = true
                    ORDER BY priority DESC, display_name
                    "#
                )
                .fetch_all(&self.db)
                .await
            }
            _ => {
                sqlx::query_as!(
                    FormatHandlerRecord,
                    r#"
                    SELECT id, format_key, plugin_id,
                           handler_type as "handler_type: FormatHandlerType",
                           display_name, description, extensions,
                           is_enabled, priority, created_at, updated_at
                    FROM format_handlers
                    ORDER BY priority DESC, display_name
                    "#
                )
                .fetch_all(&self.db)
                .await
            }
        }
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(handlers.into_iter().map(FormatHandlerResponse::from).collect())
    }

    /// Get a format handler by format key.
    pub async fn get_format_handler(&self, format_key: &str) -> Result<FormatHandlerResponse> {
        let handler = sqlx::query_as!(
            FormatHandlerRecord,
            r#"
            SELECT id, format_key, plugin_id,
                   handler_type as "handler_type: FormatHandlerType",
                   display_name, description, extensions,
                   is_enabled, priority, created_at, updated_at
            FROM format_handlers
            WHERE format_key = $1
            "#,
            format_key
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("Format handler '{}' not found", format_key)))?;

        let mut response = FormatHandlerResponse::from(handler);

        // Add repository count
        let count: Option<i64> = sqlx::query_scalar(
            "SELECT COUNT(*) FROM repositories WHERE format = $1::repository_format",
        )
        .bind(format_key)
        .fetch_one(&self.db)
        .await
        .ok();

        response.repository_count = count;

        Ok(response)
    }

    /// Create a new format handler record.
    pub async fn create_format_handler(
        &self,
        request: CreateFormatHandler,
    ) -> Result<FormatHandlerResponse> {
        let priority = request.priority.unwrap_or(50);

        let handler = sqlx::query_as!(
            FormatHandlerRecord,
            r#"
            INSERT INTO format_handlers (format_key, plugin_id, handler_type, display_name, description, extensions, priority)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, format_key, plugin_id,
                      handler_type as "handler_type: FormatHandlerType",
                      display_name, description, extensions,
                      is_enabled, priority, created_at, updated_at
            "#,
            request.format_key,
            request.plugin_id,
            request.handler_type as FormatHandlerType,
            request.display_name,
            request.description,
            &request.extensions,
            priority
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("duplicate key") {
                AppError::Conflict(format!(
                    "Format handler '{}' already exists",
                    request.format_key
                ))
            } else {
                AppError::Database(msg)
            }
        })?;

        info!("Created format handler: {}", handler.format_key);
        self.log_event(
            request.plugin_id,
            "format_handler_created",
            "info",
            &format!("Format handler '{}' created", handler.format_key),
            None,
        )
        .await;

        Ok(FormatHandlerResponse::from(handler))
    }

    /// Update a format handler.
    pub async fn update_format_handler(
        &self,
        format_key: &str,
        request: UpdateFormatHandler,
    ) -> Result<FormatHandlerResponse> {
        // First get the current handler
        let current = self.get_format_handler(format_key).await?;

        // Build update query dynamically
        let handler = sqlx::query_as!(
            FormatHandlerRecord,
            r#"
            UPDATE format_handlers
            SET display_name = COALESCE($2, display_name),
                description = COALESCE($3, description),
                extensions = COALESCE($4, extensions),
                is_enabled = COALESCE($5, is_enabled),
                priority = COALESCE($6, priority),
                updated_at = NOW()
            WHERE format_key = $1
            RETURNING id, format_key, plugin_id,
                      handler_type as "handler_type: FormatHandlerType",
                      display_name, description, extensions,
                      is_enabled, priority, created_at, updated_at
            "#,
            format_key,
            request.display_name,
            request.description,
            request.extensions.as_deref(),
            request.is_enabled,
            request.priority
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        info!("Updated format handler: {}", format_key);
        self.log_event(
            current.plugin_id,
            "format_handler_updated",
            "info",
            &format!("Format handler '{}' updated", format_key),
            Some(serde_json::json!({
                "changes": request
            })),
        )
        .await;

        Ok(FormatHandlerResponse::from(handler))
    }

    /// Enable a format handler.
    pub async fn enable_format_handler(&self, format_key: &str) -> Result<FormatHandlerResponse> {
        let handler = sqlx::query_as!(
            FormatHandlerRecord,
            r#"
            UPDATE format_handlers
            SET is_enabled = true, updated_at = NOW()
            WHERE format_key = $1
            RETURNING id, format_key, plugin_id,
                      handler_type as "handler_type: FormatHandlerType",
                      display_name, description, extensions,
                      is_enabled, priority, created_at, updated_at
            "#,
            format_key
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("Format handler '{}' not found", format_key)))?;

        info!("Enabled format handler: {}", format_key);
        self.log_event(
            handler.plugin_id,
            "format_handler_enabled",
            "info",
            &format!("Format handler '{}' enabled", format_key),
            None,
        )
        .await;

        Ok(FormatHandlerResponse::from(handler))
    }

    /// Disable a format handler.
    pub async fn disable_format_handler(&self, format_key: &str) -> Result<FormatHandlerResponse> {
        // Check if this is the last enabled handler
        let enabled_count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM format_handlers WHERE is_enabled = true"
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .unwrap_or(0);

        if enabled_count == 1 {
            // Check if the one to disable is the last enabled one
            let is_enabled: bool = sqlx::query_scalar!(
                "SELECT is_enabled FROM format_handlers WHERE format_key = $1",
                format_key
            )
            .fetch_one(&self.db)
            .await
            .unwrap_or(false);

            if is_enabled {
                return Err(AppError::Validation(
                    "Cannot disable the last enabled format handler".to_string(),
                ));
            }
        }

        let handler = sqlx::query_as!(
            FormatHandlerRecord,
            r#"
            UPDATE format_handlers
            SET is_enabled = false, updated_at = NOW()
            WHERE format_key = $1
            RETURNING id, format_key, plugin_id,
                      handler_type as "handler_type: FormatHandlerType",
                      display_name, description, extensions,
                      is_enabled, priority, created_at, updated_at
            "#,
            format_key
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("Format handler '{}' not found", format_key)))?;

        info!("Disabled format handler: {}", format_key);
        self.log_event(
            handler.plugin_id,
            "format_handler_disabled",
            "info",
            &format!("Format handler '{}' disabled", format_key),
            None,
        )
        .await;

        Ok(FormatHandlerResponse::from(handler))
    }

    /// Delete a format handler (for WASM plugins only).
    pub async fn delete_format_handler(&self, format_key: &str) -> Result<()> {
        // Only allow deleting WASM handlers
        let handler = self.get_format_handler(format_key).await?;

        if handler.handler_type == FormatHandlerType::Core {
            return Err(AppError::Validation(
                "Cannot delete core format handlers".to_string(),
            ));
        }

        // Check for repositories using this format
        let repo_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM repositories WHERE format = $1::repository_format",
        )
        .bind(format_key)
        .fetch_one(&self.db)
        .await
        .unwrap_or(Some(0))
        .unwrap_or(0);

        if repo_count > 0 {
            return Err(AppError::Conflict(format!(
                "Cannot delete format handler '{}': {} repositories are using it",
                format_key,
                repo_count
            )));
        }

        sqlx::query!("DELETE FROM format_handlers WHERE format_key = $1", format_key)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        info!("Deleted format handler: {}", format_key);
        self.log_event(
            handler.plugin_id,
            "format_handler_deleted",
            "info",
            &format!("Format handler '{}' deleted", format_key),
            None,
        )
        .await;

        Ok(())
    }

    // =========================================================================
    // T014: Manifest Validation
    // =========================================================================

    /// Validate a plugin manifest.
    pub fn validate_manifest(&self, manifest: &PluginManifest) -> Result<()> {
        manifest.validate().map_err(|e| match e {
            ManifestValidationError::InvalidPluginName(name) => {
                AppError::Validation(format!("Invalid plugin name '{}': must be lowercase letters, numbers, and hyphens, starting with a letter", name))
            }
            ManifestValidationError::InvalidVersion(version) => {
                AppError::Validation(format!("Invalid version '{}': must be semantic version (e.g., 1.0.0)", version))
            }
            ManifestValidationError::InvalidFormatKey(key) => {
                AppError::Validation(format!("Invalid format key '{}': must be lowercase letters, numbers, and hyphens, starting with a letter", key))
            }
            ManifestValidationError::MissingDisplayName => {
                AppError::Validation("Missing display_name in [format] section".to_string())
            }
            ManifestValidationError::InvalidMemoryLimits { min, max } => {
                AppError::Validation(format!("Invalid memory limits: min ({} MB) must be <= max ({} MB)", min, max))
            }
            ManifestValidationError::InvalidTimeout(secs) => {
                AppError::Validation(format!("Invalid timeout {}: must be between 1 and 300 seconds", secs))
            }
        })
    }

    /// Check if a format key conflicts with an existing handler.
    pub async fn check_format_key_conflict(&self, format_key: &str, plugin_id: Option<Uuid>) -> Result<()> {
        let existing = sqlx::query_scalar!(
            "SELECT plugin_id FROM format_handlers WHERE format_key = $1",
            format_key
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(existing_plugin_id) = existing {
            // If updating the same plugin, no conflict
            if plugin_id == existing_plugin_id {
                return Ok(());
            }

            // Check if it's a core handler
            let handler_type: Option<FormatHandlerType> = sqlx::query_scalar!(
                r#"SELECT handler_type as "handler_type: FormatHandlerType" FROM format_handlers WHERE format_key = $1"#,
                format_key
            )
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if handler_type == Some(FormatHandlerType::Core) {
                return Err(AppError::Conflict(format!(
                    "Format key '{}' conflicts with a core format handler",
                    format_key
                )));
            }

            return Err(AppError::Conflict(format!(
                "Format key '{}' is already registered by another plugin",
                format_key
            )));
        }

        Ok(())
    }

    // =========================================================================
    // T015: Plugin Lifecycle Logging
    // =========================================================================

    /// Log a plugin event.
    pub async fn log_event(
        &self,
        plugin_id: Option<Uuid>,
        event_type: &str,
        severity: &str,
        message: &str,
        details: Option<serde_json::Value>,
    ) {
        let Some(plugin_id) = plugin_id else {
            debug!("Skipping event log (no plugin_id): {} - {}", event_type, message);
            return;
        };

        let result = sqlx::query!(
            r#"
            INSERT INTO plugin_events (plugin_id, event_type, severity, message, details)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            plugin_id,
            event_type,
            severity,
            message,
            details
        )
        .execute(&self.db)
        .await;

        if let Err(e) = result {
            warn!("Failed to log plugin event: {}", e);
        }
    }

    /// Get plugin events.
    pub async fn get_plugin_events(
        &self,
        plugin_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<serde_json::Value>> {
        let limit = limit.unwrap_or(100);

        let events = sqlx::query!(
            r#"
            SELECT id, plugin_id, event_type, severity, message, details, created_at
            FROM plugin_events
            WHERE plugin_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            plugin_id,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let results: Vec<serde_json::Value> = events
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "plugin_id": e.plugin_id,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "message": e.message,
                    "details": e.details,
                    "created_at": e.created_at,
                })
            })
            .collect();

        Ok(results)
    }

    /// Log plugin installed event.
    pub async fn log_plugin_installed(&self, plugin_id: Uuid, name: &str, version: &str, source: &str) {
        self.log_event(
            Some(plugin_id),
            "installed",
            "info",
            &format!("Plugin {} v{} installed from {}", name, version, source),
            Some(serde_json::json!({
                "name": name,
                "version": version,
                "source": source,
            })),
        )
        .await;
    }

    /// Log plugin enabled event.
    pub async fn log_plugin_enabled(&self, plugin_id: Uuid, name: &str) {
        self.log_event(
            Some(plugin_id),
            "enabled",
            "info",
            &format!("Plugin {} enabled", name),
            None,
        )
        .await;
    }

    /// Log plugin disabled event.
    pub async fn log_plugin_disabled(&self, plugin_id: Uuid, name: &str) {
        self.log_event(
            Some(plugin_id),
            "disabled",
            "info",
            &format!("Plugin {} disabled", name),
            None,
        )
        .await;
    }

    /// Log plugin reload event.
    pub async fn log_plugin_reloaded(&self, plugin_id: Uuid, name: &str, old_version: &str, new_version: &str) {
        self.log_event(
            Some(plugin_id),
            "reloaded",
            "info",
            &format!("Plugin {} reloaded from v{} to v{}", name, old_version, new_version),
            Some(serde_json::json!({
                "old_version": old_version,
                "new_version": new_version,
            })),
        )
        .await;
    }

    /// Log plugin uninstalled event.
    pub async fn log_plugin_uninstalled(&self, plugin_id: Uuid, name: &str) {
        self.log_event(
            Some(plugin_id),
            "uninstalled",
            "info",
            &format!("Plugin {} uninstalled", name),
            None,
        )
        .await;
    }

    /// Log plugin error event.
    pub async fn log_plugin_error(&self, plugin_id: Uuid, name: &str, error: &str) {
        self.log_event(
            Some(plugin_id),
            "error",
            "error",
            &format!("Plugin {} error: {}", name, error),
            Some(serde_json::json!({
                "error": error,
            })),
        )
        .await;
    }

    // =========================================================================
    // T016-T020: Git Installation (User Story 1)
    // =========================================================================

    /// Install a plugin from a Git repository URL.
    ///
    /// Clones the repository, parses plugin.toml manifest, validates WASM binary,
    /// stores in plugins directory, and activates in registry.
    pub async fn install_from_git(
        &self,
        url: &str,
        git_ref: Option<&str>,
    ) -> Result<PluginInstallResult> {
        info!("Installing plugin from Git: {} (ref: {:?})", url, git_ref);

        // Ensure plugins directory exists
        self.ensure_plugins_dir().await?;

        // Create temp directory for cloning
        let temp_dir = tempfile::tempdir()
            .map_err(|e| AppError::Internal(format!("Failed to create temp directory: {}", e)))?;

        // Clone the repository
        let repo = self.clone_repository(url, temp_dir.path()).await?;

        // Checkout the specified ref if provided
        if let Some(ref_name) = git_ref {
            self.checkout_ref(&repo, ref_name)?;
        }

        // Discover and parse plugin.toml
        let manifest = self.discover_manifest(temp_dir.path()).await?;

        // Validate the manifest
        self.validate_manifest(&manifest)?;

        // Get format key from manifest
        let format_key = manifest
            .format
            .as_ref()
            .map(|f| f.key.clone())
            .ok_or_else(|| AppError::Validation("Plugin manifest missing [format] section".to_string()))?;

        // Check for format key conflicts
        self.check_format_key_conflict(&format_key, None).await?;

        // Check for duplicate plugin name
        self.check_plugin_name_conflict(&manifest.plugin.name).await?;

        // Find and validate WASM binary
        let wasm_path = self.find_wasm_binary(temp_dir.path()).await?;
        let wasm_bytes = tokio::fs::read(&wasm_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read WASM binary: {}", e)))?;

        // Validate WASM component
        self.registry
            .runtime()
            .validate(&wasm_bytes)
            .map_err(|e| AppError::Validation(format!("Invalid WASM component: {}", e)))?;

        // Copy WASM to plugins directory
        let dest_path = self.wasm_path(&manifest.plugin.name);
        tokio::fs::copy(&wasm_path, &dest_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to copy WASM binary: {}", e)))?;

        info!("WASM binary stored at: {:?}", dest_path);

        // Create plugin record in database
        let plugin = self
            .create_plugin_record(&manifest, PluginSourceType::WasmGit, Some(url), git_ref, &dest_path)
            .await?;

        // Create format handler record
        self.create_format_handler(CreateFormatHandler {
            format_key: format_key.clone(),
            plugin_id: Some(plugin.id),
            handler_type: FormatHandlerType::Wasm,
            display_name: manifest.format.as_ref().unwrap().display_name.clone(),
            description: manifest.plugin.description.clone(),
            extensions: manifest.format.as_ref().unwrap().extensions.clone(),
            priority: Some(50),
        })
        .await?;

        // Activate plugin in registry
        self.activate_plugin(&plugin, &wasm_bytes, &manifest).await?;

        // Log installation
        self.log_plugin_installed(plugin.id, &manifest.plugin.name, &manifest.plugin.version, url)
            .await;

        info!(
            "Plugin {} v{} installed successfully from Git",
            manifest.plugin.name, manifest.plugin.version
        );

        Ok(PluginInstallResult {
            plugin_id: plugin.id,
            name: manifest.plugin.name,
            version: manifest.plugin.version,
            format_key,
        })
    }

    /// Clone a Git repository to the target directory.
    async fn clone_repository(&self, url: &str, target: &Path) -> Result<git2::Repository> {
        let url = url.to_string();
        let target = target.to_path_buf();

        // Run Git clone in blocking task
        let result = tokio::task::spawn_blocking(move || {
            git2::Repository::clone(&url, &target)
        })
        .await
        .map_err(|e| AppError::Internal(format!("Git clone task failed: {}", e)))?;

        result.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("404") {
                AppError::NotFound(format!("Git repository not found: {}", msg))
            } else if msg.contains("timeout") {
                AppError::Internal("Git clone timed out".to_string())
            } else if msg.contains("authentication") || msg.contains("401") {
                AppError::Unauthorized("Git authentication failed".to_string())
            } else {
                AppError::Internal(format!("Git clone failed: {}", msg))
            }
        })
    }

    /// Checkout a specific ref (tag, branch, or commit).
    fn checkout_ref(&self, repo: &git2::Repository, ref_name: &str) -> Result<()> {
        // Try to find the reference
        let reference = repo
            .find_reference(&format!("refs/tags/{}", ref_name))
            .or_else(|_| repo.find_reference(&format!("refs/remotes/origin/{}", ref_name)))
            .or_else(|_| repo.find_reference(&format!("refs/heads/{}", ref_name)))
            .or_else(|_| {
                // Try as a commit SHA
                let oid = git2::Oid::from_str(ref_name)?;
                repo.find_commit(oid)?;
                Ok(repo.head()?)
            })
            .map_err(|e: git2::Error| {
                AppError::Validation(format!("Git ref '{}' not found: {}", ref_name, e))
            })?;

        // Get the commit to checkout
        let commit = reference
            .peel_to_commit()
            .or_else(|_| {
                let oid = git2::Oid::from_str(ref_name)?;
                repo.find_commit(oid)
            })
            .map_err(|e: git2::Error| {
                AppError::Internal(format!("Failed to resolve commit: {}", e))
            })?;

        // Checkout the commit
        repo.checkout_tree(commit.as_object(), None)
            .map_err(|e| AppError::Internal(format!("Git checkout failed: {}", e)))?;

        repo.set_head_detached(commit.id())
            .map_err(|e| AppError::Internal(format!("Git set_head failed: {}", e)))?;

        info!("Checked out ref '{}' at commit {}", ref_name, commit.id());
        Ok(())
    }

    /// Discover and parse plugin.toml manifest.
    async fn discover_manifest(&self, repo_path: &Path) -> Result<PluginManifest> {
        let manifest_path = repo_path.join("plugin.toml");

        if !manifest_path.exists() {
            return Err(AppError::Validation(
                "plugin.toml not found in repository root".to_string(),
            ));
        }

        let content = tokio::fs::read_to_string(&manifest_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read plugin.toml: {}", e)))?;

        PluginManifest::from_toml(&content)
            .map_err(|e| AppError::Validation(format!("Invalid plugin.toml: {}", e)))
    }

    /// Find the WASM binary in the repository.
    async fn find_wasm_binary(&self, repo_path: &Path) -> Result<PathBuf> {
        // Check common locations
        let candidates = [
            repo_path.join("target/wasm32-wasi/release/plugin.wasm"),
            repo_path.join("target/wasm32-wasip1/release/plugin.wasm"),
            repo_path.join("plugin.wasm"),
            repo_path.join("out/plugin.wasm"),
            repo_path.join("dist/plugin.wasm"),
        ];

        for path in &candidates {
            if path.exists() {
                info!("Found WASM binary at: {:?}", path);
                return Ok(path.clone());
            }
        }

        // Search for any .wasm file
        let mut entries = tokio::fs::read_dir(repo_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read directory: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read directory entry: {}", e)))?
        {
            let path = entry.path();
            if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                info!("Found WASM binary at: {:?}", path);
                return Ok(path);
            }
        }

        Err(AppError::Validation(
            "No WASM binary found. Expected plugin.wasm in repository root or target directory".to_string(),
        ))
    }

    /// Check if a plugin name already exists.
    async fn check_plugin_name_conflict(&self, name: &str) -> Result<()> {
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM plugins WHERE name = $1)",
            name
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if exists == Some(true) {
            return Err(AppError::Conflict(format!(
                "Plugin '{}' already exists",
                name
            )));
        }

        Ok(())
    }

    /// Create a plugin record in the database.
    async fn create_plugin_record(
        &self,
        manifest: &PluginManifest,
        source_type: PluginSourceType,
        source_url: Option<&str>,
        source_ref: Option<&str>,
        wasm_path: &Path,
    ) -> Result<Plugin> {
        let capabilities = serde_json::to_value(manifest.to_capabilities())
            .map_err(|e| AppError::Internal(format!("Failed to serialize capabilities: {}", e)))?;
        let resource_limits = serde_json::to_value(manifest.to_resource_limits())
            .map_err(|e| AppError::Internal(format!("Failed to serialize resource_limits: {}", e)))?;
        let manifest_json = serde_json::to_value(manifest)
            .map_err(|e| AppError::Internal(format!("Failed to serialize manifest: {}", e)))?;

        let wasm_path_str = wasm_path.to_string_lossy().to_string();

        // Note: The Plugin struct returned here needs to match the updated schema
        // with the new WASM fields. Using raw query to handle all fields.
        let plugin_id = Uuid::new_v4();

        sqlx::query!(
            r#"
            INSERT INTO plugins (
                id, name, version, display_name, description, author, homepage, license,
                status, plugin_type, source_type, source_url, source_ref, wasm_path,
                manifest, capabilities, resource_limits
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', 'format_handler', $9, $10, $11, $12, $13, $14, $15)
            "#,
            plugin_id,
            manifest.plugin.name,
            manifest.plugin.version,
            manifest.format.as_ref().map(|f| f.display_name.clone()).unwrap_or_else(|| manifest.plugin.name.clone()),
            manifest.plugin.description,
            manifest.plugin.author,
            manifest.plugin.homepage,
            manifest.plugin.license,
            source_type as PluginSourceType,
            source_url,
            source_ref,
            wasm_path_str,
            manifest_json,
            capabilities,
            resource_limits
        )
        .execute(&self.db)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("duplicate key") {
                AppError::Conflict(format!("Plugin '{}' already exists", manifest.plugin.name))
            } else {
                AppError::Database(msg)
            }
        })?;

        // Fetch the created plugin
        self.get_wasm_plugin(plugin_id).await
    }

    /// Get a WASM plugin by ID.
    pub async fn get_wasm_plugin(&self, plugin_id: Uuid) -> Result<Plugin> {
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

    /// List all WASM plugins.
    pub async fn list_wasm_plugins(&self) -> Result<Vec<Plugin>> {
        let plugins = sqlx::query_as::<_, Plugin>(
            r#"
            SELECT
                id, name, version, display_name, description, author, homepage, license,
                status, plugin_type, source_type,
                source_url, source_ref, wasm_path, manifest, capabilities, resource_limits,
                config, config_schema, error_message, installed_at, enabled_at, updated_at
            FROM plugins
            WHERE source_type != 'core'
            ORDER BY name
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(plugins)
    }

    /// Activate a plugin in the registry.
    async fn activate_plugin(
        &self,
        plugin: &Plugin,
        wasm_bytes: &[u8],
        manifest: &PluginManifest,
    ) -> Result<()> {
        let format_key = manifest
            .format
            .as_ref()
            .map(|f| f.key.clone())
            .ok_or_else(|| AppError::Internal("Missing format key".to_string()))?;

        self.registry
            .register(
                plugin.id,
                plugin.name.clone(),
                format_key,
                plugin.version.clone(),
                wasm_bytes,
                manifest.to_capabilities(),
                manifest.to_resource_limits(),
            )
            .await
            .map_err(|e| AppError::Internal(format!("Failed to activate plugin: {}", e)))?;

        info!("Plugin {} activated in registry", plugin.name);
        Ok(())
    }

    /// Activate a plugin at startup by loading its WASM bytes and registering with the runtime.
    /// This is used during server startup to load all active plugins.
    pub async fn activate_plugin_at_startup(
        &self,
        plugin: &Plugin,
        wasm_path: &std::path::Path,
    ) -> Result<()> {
        // Read the WASM bytes from the file path
        let wasm_bytes = tokio::fs::read(wasm_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read WASM file: {}", e)))?;

        // Parse manifest from stored JSON
        let manifest: PluginManifest = plugin
            .manifest
            .as_ref()
            .and_then(|m| serde_json::from_value(m.clone()).ok())
            .ok_or_else(|| AppError::Internal("Missing plugin manifest".to_string()))?;

        // Activate the plugin
        self.activate_plugin(plugin, &wasm_bytes, &manifest).await
    }

    /// Enable a WASM plugin.
    pub async fn enable_wasm_plugin(&self, plugin_id: Uuid) -> Result<Plugin> {
        let plugin = self.get_wasm_plugin(plugin_id).await?;

        if plugin.status == PluginStatus::Active {
            return Ok(plugin);
        }

        // Load WASM and activate
        if let Some(ref wasm_path) = plugin.wasm_path {
            let wasm_bytes = tokio::fs::read(wasm_path)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to read WASM: {}", e)))?;

            // Parse manifest from stored JSON
            let manifest: PluginManifest = plugin
                .manifest
                .as_ref()
                .and_then(|m| serde_json::from_value(m.clone()).ok())
                .ok_or_else(|| AppError::Internal("Missing plugin manifest".to_string()))?;

            self.activate_plugin(&plugin, &wasm_bytes, &manifest).await?;
        }

        // Update status in database
        sqlx::query!(
            "UPDATE plugins SET status = 'active', enabled_at = NOW(), updated_at = NOW() WHERE id = $1",
            plugin_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Enable format handler
        if let Some(ref format) = plugin
            .manifest
            .as_ref()
            .and_then(|m| m.get("format"))
            .and_then(|f| f.get("key"))
            .and_then(|k| k.as_str())
        {
            self.enable_format_handler(format).await?;
        }

        self.log_plugin_enabled(plugin_id, &plugin.name).await;

        self.get_wasm_plugin(plugin_id).await
    }

    /// Disable a WASM plugin.
    pub async fn disable_wasm_plugin(&self, plugin_id: Uuid) -> Result<Plugin> {
        let plugin = self.get_wasm_plugin(plugin_id).await?;

        if plugin.status == PluginStatus::Disabled {
            return Ok(plugin);
        }

        // Unregister from registry
        let _ = self.registry.unregister(plugin_id).await;

        // Update status in database
        sqlx::query!(
            "UPDATE plugins SET status = 'disabled', updated_at = NOW() WHERE id = $1",
            plugin_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Disable format handler
        if let Some(ref format) = plugin
            .manifest
            .as_ref()
            .and_then(|m| m.get("format"))
            .and_then(|f| f.get("key"))
            .and_then(|k| k.as_str())
        {
            let _ = self.disable_format_handler(format).await;
        }

        self.log_plugin_disabled(plugin_id, &plugin.name).await;

        self.get_wasm_plugin(plugin_id).await
    }

    // =========================================================================
    // T031-T035: ZIP Installation (User Story 2)
    // =========================================================================

    /// Install a plugin from a ZIP file.
    ///
    /// Extracts the ZIP, parses plugin.toml manifest, validates WASM binary,
    /// stores in plugins directory, and activates in registry.
    pub async fn install_from_zip(&self, zip_data: &[u8]) -> Result<PluginInstallResult> {
        info!("Installing plugin from ZIP ({} bytes)", zip_data.len());

        // Ensure plugins directory exists
        self.ensure_plugins_dir().await?;

        // Create temp directory for extraction
        let temp_dir = tempfile::tempdir()
            .map_err(|e| AppError::Internal(format!("Failed to create temp directory: {}", e)))?;

        // Extract ZIP to temp directory
        self.extract_zip(zip_data, temp_dir.path()).await?;

        // Validate required files exist
        self.validate_zip_contents(temp_dir.path()).await?;

        // Discover and parse plugin.toml
        let manifest = self.discover_manifest(temp_dir.path()).await?;

        // Validate the manifest
        self.validate_manifest(&manifest)?;

        // Get format key from manifest
        let format_key = manifest
            .format
            .as_ref()
            .map(|f| f.key.clone())
            .ok_or_else(|| AppError::Validation("Plugin manifest missing [format] section".to_string()))?;

        // Check for format key conflicts
        self.check_format_key_conflict(&format_key, None).await?;

        // Check for duplicate plugin name
        self.check_plugin_name_conflict(&manifest.plugin.name).await?;

        // Find and validate WASM binary
        let wasm_path = self.find_wasm_binary(temp_dir.path()).await?;
        let wasm_bytes = tokio::fs::read(&wasm_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read WASM binary: {}", e)))?;

        // Validate WASM component
        self.registry
            .runtime()
            .validate(&wasm_bytes)
            .map_err(|e| AppError::Validation(format!("Invalid WASM component: {}", e)))?;

        // Copy WASM to plugins directory
        let dest_path = self.wasm_path(&manifest.plugin.name);
        tokio::fs::copy(&wasm_path, &dest_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to copy WASM binary: {}", e)))?;

        info!("WASM binary stored at: {:?}", dest_path);

        // Create plugin record in database
        let plugin = self
            .create_plugin_record(&manifest, PluginSourceType::WasmZip, None, None, &dest_path)
            .await?;

        // Create format handler record
        self.create_format_handler(CreateFormatHandler {
            format_key: format_key.clone(),
            plugin_id: Some(plugin.id),
            handler_type: FormatHandlerType::Wasm,
            display_name: manifest.format.as_ref().unwrap().display_name.clone(),
            description: manifest.plugin.description.clone(),
            extensions: manifest.format.as_ref().unwrap().extensions.clone(),
            priority: Some(50),
        })
        .await?;

        // Activate plugin in registry
        self.activate_plugin(&plugin, &wasm_bytes, &manifest).await?;

        // Log installation
        self.log_plugin_installed(plugin.id, &manifest.plugin.name, &manifest.plugin.version, "ZIP upload")
            .await;

        info!(
            "Plugin {} v{} installed successfully from ZIP",
            manifest.plugin.name, manifest.plugin.version
        );

        Ok(PluginInstallResult {
            plugin_id: plugin.id,
            name: manifest.plugin.name,
            version: manifest.plugin.version,
            format_key,
        })
    }

    /// Extract a ZIP file to the target directory.
    async fn extract_zip(&self, zip_data: &[u8], target: &Path) -> Result<()> {
        let zip_data = zip_data.to_vec();
        let target = target.to_path_buf();

        // Run ZIP extraction in blocking task
        tokio::task::spawn_blocking(move || {
            use std::io::Cursor;
            use zip::ZipArchive;

            let reader = Cursor::new(zip_data);
            let mut archive = ZipArchive::new(reader)
                .map_err(|e| AppError::Validation(format!("Invalid ZIP file: {}", e)))?;

            for i in 0..archive.len() {
                let mut file = archive
                    .by_index(i)
                    .map_err(|e| AppError::Internal(format!("Failed to read ZIP entry: {}", e)))?;

                let outpath = match file.enclosed_name() {
                    Some(path) => target.join(path),
                    None => continue, // Skip paths with parent directory references
                };

                if file.is_dir() {
                    std::fs::create_dir_all(&outpath)
                        .map_err(|e| AppError::Internal(format!("Failed to create directory: {}", e)))?;
                } else {
                    if let Some(parent) = outpath.parent() {
                        if !parent.exists() {
                            std::fs::create_dir_all(parent)
                                .map_err(|e| AppError::Internal(format!("Failed to create parent directory: {}", e)))?;
                        }
                    }
                    let mut outfile = std::fs::File::create(&outpath)
                        .map_err(|e| AppError::Internal(format!("Failed to create file: {}", e)))?;
                    std::io::copy(&mut file, &mut outfile)
                        .map_err(|e| AppError::Internal(format!("Failed to extract file: {}", e)))?;
                }
            }

            Ok::<(), AppError>(())
        })
        .await
        .map_err(|e| AppError::Internal(format!("ZIP extraction task failed: {}", e)))??;

        Ok(())
    }

    /// Validate that required files exist in extracted ZIP.
    async fn validate_zip_contents(&self, path: &Path) -> Result<()> {
        let manifest_path = path.join("plugin.toml");
        if !manifest_path.exists() {
            return Err(AppError::Validation(
                "ZIP file missing required plugin.toml".to_string(),
            ));
        }

        // Check for WASM file (either in root or common locations)
        let has_wasm = self.find_wasm_binary(path).await.is_ok();
        if !has_wasm {
            return Err(AppError::Validation(
                "ZIP file missing required plugin.wasm".to_string(),
            ));
        }

        Ok(())
    }

    // =========================================================================
    // T045-T049: Hot-Reload (User Story 4)
    // =========================================================================

    /// Reload a plugin from its source.
    ///
    /// Fetches the new version from the original source, validates it,
    /// and atomically swaps the plugin while allowing in-flight requests
    /// to complete on the old version.
    pub async fn reload_plugin(&self, plugin_id: Uuid) -> Result<Plugin> {
        let plugin = self.get_wasm_plugin(plugin_id).await?;
        let old_version = plugin.version.clone();

        info!(
            "Reloading plugin {} from {:?} (current: v{})",
            plugin.name,
            plugin.source_type,
            old_version
        );

        // Determine reload source
        let (new_manifest, new_wasm) = match plugin.source_type {
            PluginSourceType::WasmGit => {
                // Re-clone from Git source
                let url = plugin.source_url.as_ref().ok_or_else(|| {
                    AppError::Internal("Missing source URL for Git plugin".to_string())
                })?;
                let git_ref = plugin.source_ref.as_deref();

                self.fetch_from_git(url, git_ref).await?
            }
            PluginSourceType::WasmZip | PluginSourceType::WasmLocal => {
                return Err(AppError::Validation(
                    "Cannot reload ZIP or local plugins. Re-upload to update.".to_string(),
                ));
            }
            PluginSourceType::Core => {
                return Err(AppError::Validation(
                    "Cannot reload core plugins".to_string(),
                ));
            }
        };

        // Validate the new manifest
        self.validate_manifest(&new_manifest)?;

        // Check that plugin name matches
        if new_manifest.plugin.name != plugin.name {
            return Err(AppError::Validation(format!(
                "Plugin name mismatch: expected '{}', got '{}'",
                plugin.name, new_manifest.plugin.name
            )));
        }

        // Validate WASM component
        self.registry
            .runtime()
            .validate(&new_wasm)
            .map_err(|e| AppError::Validation(format!("Invalid WASM component: {}", e)))?;

        // Store new WASM (overwrite old)
        let wasm_path = self.wasm_path(&plugin.name);
        tokio::fs::write(&wasm_path, &new_wasm)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to write WASM: {}", e)))?;

        // Activate new version in registry (atomic swap)
        let format_key = new_manifest
            .format
            .as_ref()
            .map(|f| f.key.clone())
            .ok_or_else(|| AppError::Internal("Missing format key".to_string()))?;

        self.registry
            .register(
                plugin.id,
                plugin.name.clone(),
                format_key,
                new_manifest.plugin.version.clone(),
                &new_wasm,
                new_manifest.to_capabilities(),
                new_manifest.to_resource_limits(),
            )
            .await
            .map_err(|e| AppError::Internal(format!("Failed to reload plugin: {}", e)))?;

        // Update database record
        let manifest_json = serde_json::to_value(&new_manifest)
            .map_err(|e| AppError::Internal(format!("Failed to serialize manifest: {}", e)))?;
        let capabilities = serde_json::to_value(new_manifest.to_capabilities())
            .map_err(|e| AppError::Internal(format!("Failed to serialize capabilities: {}", e)))?;
        let resource_limits = serde_json::to_value(new_manifest.to_resource_limits())
            .map_err(|e| AppError::Internal(format!("Failed to serialize limits: {}", e)))?;

        sqlx::query!(
            r#"
            UPDATE plugins
            SET version = $2, manifest = $3, capabilities = $4, resource_limits = $5, updated_at = NOW()
            WHERE id = $1
            "#,
            plugin_id,
            new_manifest.plugin.version,
            manifest_json,
            capabilities,
            resource_limits
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Log reload
        self.log_plugin_reloaded(plugin_id, &plugin.name, &old_version, &new_manifest.plugin.version)
            .await;

        info!(
            "Plugin {} reloaded from v{} to v{}",
            plugin.name, old_version, new_manifest.plugin.version
        );

        self.get_wasm_plugin(plugin_id).await
    }

    /// Fetch plugin from Git repository.
    async fn fetch_from_git(&self, url: &str, git_ref: Option<&str>) -> Result<(PluginManifest, Vec<u8>)> {
        let temp_dir = tempfile::tempdir()
            .map_err(|e| AppError::Internal(format!("Failed to create temp directory: {}", e)))?;

        let repo = self.clone_repository(url, temp_dir.path()).await?;

        if let Some(ref_name) = git_ref {
            self.checkout_ref(&repo, ref_name)?;
        }

        let manifest = self.discover_manifest(temp_dir.path()).await?;
        let wasm_path = self.find_wasm_binary(temp_dir.path()).await?;
        let wasm_bytes = tokio::fs::read(&wasm_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read WASM: {}", e)))?;

        Ok((manifest, wasm_bytes))
    }

    // =========================================================================
    // T050-T053: Uninstall (User Story 5)
    // =========================================================================

    /// Uninstall a plugin.
    ///
    /// Removes the plugin from the registry, deletes the WASM file,
    /// and removes database records.
    pub async fn uninstall_plugin(&self, plugin_id: Uuid, force: bool) -> Result<()> {
        let plugin = self.get_wasm_plugin(plugin_id).await?;

        // Check if it's a core plugin
        if plugin.source_type == PluginSourceType::Core {
            return Err(AppError::Validation(
                "Cannot uninstall core plugins".to_string(),
            ));
        }

        // Get format key
        let format_key = plugin
            .manifest
            .as_ref()
            .and_then(|m| m.get("format"))
            .and_then(|f| f.get("key"))
            .and_then(|k| k.as_str())
            .map(String::from);

        // Check for dependent repositories
        if let Some(ref fk) = format_key {
            let repo_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM repositories WHERE format = $1::repository_format",
            )
            .bind(fk.as_str())
            .fetch_one(&self.db)
            .await
            .unwrap_or(Some(0))
            .unwrap_or(0);

            if repo_count > 0 && !force {
                return Err(AppError::Conflict(format!(
                    "Cannot uninstall plugin '{}': {} repositories are using format '{}'. Use force=true to override.",
                    plugin.name,
                    repo_count,
                    fk
                )));
            }

            if repo_count > 0 {
                warn!(
                    "Force uninstalling plugin {} with {} dependent repositories",
                    plugin.name,
                    repo_count
                );
            }
        }

        info!("Uninstalling plugin {}", plugin.name);

        // Unregister from registry
        let _ = self.registry.unregister(plugin_id).await;

        // Delete format handler record
        if let Some(ref fk) = format_key {
            let _ = sqlx::query!("DELETE FROM format_handlers WHERE format_key = $1", fk)
                .execute(&self.db)
                .await;
        }

        // Delete plugin events
        let _ = sqlx::query!("DELETE FROM plugin_events WHERE plugin_id = $1", plugin_id)
            .execute(&self.db)
            .await;

        // Delete plugin hooks
        let _ = sqlx::query!("DELETE FROM plugin_hooks WHERE plugin_id = $1", plugin_id)
            .execute(&self.db)
            .await;

        // Delete plugin config
        let _ = sqlx::query!("DELETE FROM plugin_config WHERE plugin_id = $1", plugin_id)
            .execute(&self.db)
            .await;

        // Delete plugin record
        sqlx::query!("DELETE FROM plugins WHERE id = $1", plugin_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Delete WASM file
        if let Some(ref wasm_path) = plugin.wasm_path {
            if let Err(e) = tokio::fs::remove_file(wasm_path).await {
                warn!("Failed to delete WASM file: {}", e);
            }
        }

        info!("Plugin {} uninstalled successfully", plugin.name);

        Ok(())
    }

    // =========================================================================
    // T062: Test Format Handler
    // =========================================================================

    /// Test a format handler with sample content.
    /// Returns parsed metadata and validation result.
    pub async fn test_format_handler(
        &self,
        format_key: &str,
        path: &str,
        content: &[u8],
    ) -> Result<(TestMetadata, Result<()>)> {
        // First check if format handler exists and is enabled
        let handler = self.get_format_handler(format_key).await?;

        if !handler.is_enabled {
            return Err(AppError::Validation(format!(
                "Format handler '{}' is disabled",
                format_key
            )));
        }

        // For WASM handlers, use the registry
        if handler.handler_type == FormatHandlerType::Wasm {
            if let Some(plugin_id) = handler.plugin_id {
                // Get the plugin and run through registry
                return self.test_wasm_handler(plugin_id, path, content).await;
            } else {
                return Err(AppError::Internal(format!(
                    "WASM handler '{}' has no associated plugin",
                    format_key
                )));
            }
        }

        // For core handlers, use the format module
        let core_handler = crate::formats::get_core_handler(format_key).ok_or_else(|| {
            AppError::NotFound(format!("Core handler '{}' not found", format_key))
        })?;

        let bytes = bytes::Bytes::copy_from_slice(content);

        // Parse metadata
        let metadata_value = core_handler.parse_metadata(path, &bytes).await?;

        // Convert to TestMetadata
        let metadata = TestMetadata {
            path: path.to_string(),
            version: metadata_value
                .get("version")
                .and_then(|v| v.as_str())
                .map(String::from),
            content_type: metadata_value
                .get("content_type")
                .and_then(|v| v.as_str())
                .unwrap_or("application/octet-stream")
                .to_string(),
            size_bytes: content.len() as u64,
        };

        // Validate
        let validation_result = core_handler.validate(path, &bytes).await;

        Ok((metadata, validation_result))
    }

    /// Test a WASM handler through the registry.
    async fn test_wasm_handler(
        &self,
        plugin_id: Uuid,
        path: &str,
        content: &[u8],
    ) -> Result<(TestMetadata, Result<()>)> {
        // Get format key from plugin
        let plugin = self.get_wasm_plugin(plugin_id).await?;
        let format_key = plugin
            .manifest
            .as_ref()
            .and_then(|m| m.get("format"))
            .and_then(|f| f.get("key"))
            .and_then(|k| k.as_str())
            .ok_or_else(|| AppError::Internal("Plugin manifest missing format key".to_string()))?;

        // Execute through registry
        let metadata = self
            .registry
            .execute_parse_metadata(format_key, path, content)
            .await?;

        let validation_result = self
            .registry
            .execute_validate(format_key, path, content)
            .await;

        let test_metadata = TestMetadata {
            path: metadata.path,
            version: metadata.version,
            content_type: metadata.content_type,
            size_bytes: metadata.size_bytes,
        };

        // Convert nested result to the expected type
        let validation = match validation_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(AppError::Validation(format!("Validation failed: {}", e))),
            Err(e) => Err(AppError::Internal(format!("WASM execution failed: {}", e))),
        };

        Ok((test_metadata, validation))
    }

    // =========================================================================
    // T063: Install from Local Path (Development)
    // =========================================================================

    /// Install a plugin from a local filesystem path.
    /// Intended for development and testing purposes.
    ///
    /// Note: This is a placeholder - full implementation requires additional
    /// method implementations for local path handling.
    pub async fn install_from_local(&self, local_path: &str) -> Result<PluginInstallResult> {
        info!("Installing plugin from local path: {}", local_path);

        // For now, return an error - local installation not yet fully implemented
        Err(AppError::Internal(
            "Local plugin installation not yet implemented. Use Git or ZIP installation.".to_string()
        ))
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Get the plugins directory path.
    pub fn plugins_dir(&self) -> &Path {
        &self.plugins_dir
    }

    /// Ensure the plugins directory exists.
    pub async fn ensure_plugins_dir(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.plugins_dir)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create plugins directory: {}", e)))
    }

    /// Get the path for a plugin's WASM file.
    pub fn wasm_path(&self, plugin_name: &str) -> PathBuf {
        self.plugins_dir.join(format!("{}.wasm", plugin_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_path() {
        let service = WasmPluginService::new(
            // Mock pool - won't be used in this test
            unsafe { std::mem::zeroed() },
            Arc::new(PluginRegistry::new().unwrap()),
            PathBuf::from("/tmp/plugins"),
        );

        let path = service.wasm_path("test-plugin");
        assert_eq!(path, PathBuf::from("/tmp/plugins/test-plugin.wasm"));
    }
}
