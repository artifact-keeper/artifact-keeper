//! Plugin registry for hot-swap storage of WASM plugins.
//!
//! Provides Arc<RwLock<HashMap>> based storage for active plugins,
//! enabling hot-reload without affecting in-flight requests.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::plugin::{PluginCapabilities, PluginResourceLimits};

use super::wasm_bindings::{
    FormatPlugin, WasmHttpRequest, WasmHttpResponse, WasmRepoContext, WitHttpRequest,
    WitMetadataV2, WitRepoContext,
};
use super::wasm_runtime::{
    CompiledPlugin, WasmError, WasmIndexFile, WasmMetadata, WasmResult, WasmRuntime,
    WasmValidationError,
};

/// Active plugin in the registry.
///
/// Contains the compiled WASM component and metadata needed for execution.
/// Uses Arc for the compiled plugin to allow shared access during hot-reload.
pub struct ActivePlugin {
    /// Plugin database ID
    pub id: Uuid,
    /// Plugin name (unique identifier)
    pub name: String,
    /// Format key this plugin handles
    pub format_key: String,
    /// Plugin version string
    pub version: String,
    /// Internal version counter for hot-reload tracking
    pub internal_version: u64,
    /// Compiled WASM component (v1 world)
    pub compiled: Arc<CompiledPlugin>,
    /// Compiled WASM component for v2 world (handle-request support)
    pub compiled_v2: Option<Arc<CompiledPlugin>>,
    /// Plugin capabilities
    pub capabilities: PluginCapabilities,
    /// Resource limits for execution
    pub limits: PluginResourceLimits,
}

impl std::fmt::Debug for ActivePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivePlugin")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("format_key", &self.format_key)
            .field("version", &self.version)
            .field("internal_version", &self.internal_version)
            .finish()
    }
}

/// Plugin registry for managing active WASM plugins.
///
/// Uses Arc<RwLock<HashMap>> for thread-safe hot-swap storage.
/// New versions are loaded into new Engines; old versions drain naturally.
pub struct PluginRegistry {
    /// Active plugins indexed by format key
    plugins_by_format: Arc<RwLock<HashMap<String, Arc<ActivePlugin>>>>,
    /// Active plugins indexed by plugin ID
    plugins_by_id: Arc<RwLock<HashMap<Uuid, Arc<ActivePlugin>>>>,
    /// Version counter for tracking hot-reload generations
    version_counter: Arc<RwLock<u64>>,
    /// WASM runtime for compilation
    runtime: Arc<WasmRuntime>,
}

impl PluginRegistry {
    /// Create a new plugin registry.
    pub fn new() -> WasmResult<Self> {
        let runtime = WasmRuntime::new()?;

        Ok(Self {
            plugins_by_format: Arc::new(RwLock::new(HashMap::new())),
            plugins_by_id: Arc::new(RwLock::new(HashMap::new())),
            version_counter: Arc::new(RwLock::new(0)),
            runtime: Arc::new(runtime),
        })
    }

    /// Create a plugin registry with a custom runtime.
    pub fn with_runtime(runtime: WasmRuntime) -> Self {
        Self {
            plugins_by_format: Arc::new(RwLock::new(HashMap::new())),
            plugins_by_id: Arc::new(RwLock::new(HashMap::new())),
            version_counter: Arc::new(RwLock::new(0)),
            runtime: Arc::new(runtime),
        }
    }

    /// Get the WASM runtime.
    pub fn runtime(&self) -> &WasmRuntime {
        &self.runtime
    }

    /// Get the next internal version number.
    async fn next_version(&self) -> u64 {
        let mut counter = self.version_counter.write().await;
        *counter += 1;
        *counter
    }

    /// Register a plugin from WASM bytes.
    ///
    /// Compiles the WASM component and adds it to the registry.
    /// If a plugin with the same format key exists, it's atomically replaced
    /// (hot-reload). In-flight requests using the old version will complete
    /// normally due to Arc reference counting.
    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        id: Uuid,
        name: String,
        format_key: String,
        version: String,
        wasm_bytes: &[u8],
        capabilities: PluginCapabilities,
        limits: PluginResourceLimits,
    ) -> WasmResult<()> {
        info!(
            "Registering plugin {} ({}) version {} for format {}",
            name, id, version, format_key
        );

        // Compile the WASM component (v1 world)
        let compiled = self.runtime.compile(wasm_bytes)?;
        let compiled = Arc::new(compiled);

        // Compile v2 world if plugin declares handle_request capability
        let compiled_v2 = if capabilities.handle_request {
            match self.runtime.compile(wasm_bytes) {
                Ok(c) => {
                    info!("Plugin {} compiled for v2 world (handle-request)", name);
                    Some(Arc::new(c))
                }
                Err(e) => {
                    warn!(
                        "Plugin {} declared handle_request but v2 compilation failed: {}",
                        name, e
                    );
                    None
                }
            }
        } else {
            None
        };

        // Get next internal version
        let internal_version = self.next_version().await;

        let plugin = Arc::new(ActivePlugin {
            id,
            name: name.clone(),
            format_key: format_key.clone(),
            version: version.clone(),
            internal_version,
            compiled,
            compiled_v2,
            capabilities,
            limits,
        });

        // Atomically update both indexes
        {
            let mut by_format = self.plugins_by_format.write().await;
            let mut by_id = self.plugins_by_id.write().await;

            // Check for existing plugin with same format key but different ID
            if let Some(existing) = by_format.get(&format_key) {
                if existing.id != id {
                    return Err(WasmError::ValidationFailed(format!(
                        "Format key '{}' is already registered by plugin '{}'",
                        format_key, existing.name
                    )));
                }
                info!(
                    "Hot-reloading plugin {} from v{} (internal {}) to v{} (internal {})",
                    name, existing.version, existing.internal_version, version, internal_version
                );
            }

            by_format.insert(format_key, plugin.clone());
            by_id.insert(id, plugin);
        }

        info!(
            "Plugin {} registered successfully (internal version {})",
            name, internal_version
        );

        Ok(())
    }

    /// Unregister a plugin by ID.
    ///
    /// Removes the plugin from the registry. In-flight requests using the
    /// plugin will complete normally due to Arc reference counting.
    pub async fn unregister(&self, id: Uuid) -> WasmResult<()> {
        let mut by_format = self.plugins_by_format.write().await;
        let mut by_id = self.plugins_by_id.write().await;

        let plugin = by_id.remove(&id);
        if let Some(plugin) = plugin {
            by_format.remove(&plugin.format_key);
            info!("Unregistered plugin {} ({})", plugin.name, id);
            Ok(())
        } else {
            warn!("Attempted to unregister unknown plugin {}", id);
            Err(WasmError::ValidationFailed(format!(
                "Plugin {} not found in registry",
                id
            )))
        }
    }

    /// Get a plugin by format key.
    ///
    /// Returns an Arc reference to the plugin, which keeps it alive
    /// even if it's hot-reloaded during request processing.
    pub async fn get_by_format(&self, format_key: &str) -> Option<Arc<ActivePlugin>> {
        let by_format = self.plugins_by_format.read().await;
        by_format.get(format_key).cloned()
    }

    /// Get a plugin by ID.
    pub async fn get_by_id(&self, id: Uuid) -> Option<Arc<ActivePlugin>> {
        let by_id = self.plugins_by_id.read().await;
        by_id.get(&id).cloned()
    }

    /// Check if a format key is registered.
    pub async fn has_format(&self, format_key: &str) -> bool {
        let by_format = self.plugins_by_format.read().await;
        by_format.contains_key(format_key)
    }

    /// List all registered format keys.
    pub async fn list_formats(&self) -> Vec<String> {
        let by_format = self.plugins_by_format.read().await;
        by_format.keys().cloned().collect()
    }

    /// List all registered plugins.
    pub async fn list_plugins(&self) -> Vec<PluginInfo> {
        let by_id = self.plugins_by_id.read().await;
        by_id
            .values()
            .map(|p| PluginInfo {
                id: p.id,
                name: p.name.clone(),
                format_key: p.format_key.clone(),
                version: p.version.clone(),
                internal_version: p.internal_version,
            })
            .collect()
    }

    /// Get the number of registered plugins.
    pub async fn plugin_count(&self) -> usize {
        let by_id = self.plugins_by_id.read().await;
        by_id.len()
    }

    /// Clear all plugins from the registry.
    ///
    /// Used for testing or shutdown.
    pub async fn clear(&self) {
        let mut by_format = self.plugins_by_format.write().await;
        let mut by_id = self.plugins_by_id.write().await;

        by_format.clear();
        by_id.clear();

        info!("Plugin registry cleared");
    }

    /// Execute parse_metadata on a plugin.
    ///
    /// Looks up the plugin by format key and executes the parse_metadata
    /// function with timeout protection.
    pub async fn execute_parse_metadata(
        &self,
        format_key: &str,
        path: &str,
        data: &[u8],
    ) -> WasmResult<WasmMetadata> {
        let plugin = self.get_by_format(format_key).await.ok_or_else(|| {
            WasmError::ValidationFailed(format!("No plugin registered for format '{}'", format_key))
        })?;

        if !plugin.capabilities.parse_metadata {
            return Err(WasmError::ValidationFailed(format!(
                "Plugin '{}' does not support parse_metadata",
                plugin.name
            )));
        }

        debug!(
            "Executing parse_metadata on plugin {} for path {}",
            plugin.name, path
        );

        let mut store = self.runtime.create_store(
            &plugin.compiled,
            &plugin.id.to_string(),
            &plugin.format_key,
            &plugin.limits,
        )?;

        let instance = FormatPlugin::instantiate_async(
            &mut store,
            plugin.compiled.component(),
            plugin.compiled.linker(),
        )
        .await
        .map_err(|e| WasmError::InstantiationFailed(e.to_string()))?;

        let handler = instance.artifact_keeper_format_handler();
        let result = handler
            .call_parse_metadata(&mut store, path, data)
            .await
            .map_err(|e: wasmtime::Error| WasmError::CallFailed(e.to_string()))?;

        match result {
            Ok(metadata) => Ok(WasmMetadata::from(metadata)),
            Err(msg) => Err(WasmError::PluginError(msg)),
        }
    }

    /// Execute validate on a plugin.
    ///
    /// Looks up the plugin by format key and executes the validate function
    /// with timeout protection.
    pub async fn execute_validate(
        &self,
        format_key: &str,
        path: &str,
        data: &[u8],
    ) -> WasmResult<Result<(), WasmValidationError>> {
        let plugin = self.get_by_format(format_key).await.ok_or_else(|| {
            WasmError::ValidationFailed(format!("No plugin registered for format '{}'", format_key))
        })?;

        if !plugin.capabilities.validate_artifact {
            // If plugin doesn't support validation, treat as valid
            return Ok(Ok(()));
        }

        debug!(
            "Executing validate on plugin {} for path {}",
            plugin.name, path
        );

        let mut store = self.runtime.create_store(
            &plugin.compiled,
            &plugin.id.to_string(),
            &plugin.format_key,
            &plugin.limits,
        )?;

        let instance = FormatPlugin::instantiate_async(
            &mut store,
            plugin.compiled.component(),
            plugin.compiled.linker(),
        )
        .await
        .map_err(|e| WasmError::InstantiationFailed(e.to_string()))?;

        let handler = instance.artifact_keeper_format_handler();
        let result = handler
            .call_validate(&mut store, path, data)
            .await
            .map_err(|e: wasmtime::Error| WasmError::CallFailed(e.to_string()))?;

        match result {
            Ok(()) => Ok(Ok(())),
            Err(msg) => Ok(Err(WasmValidationError {
                message: msg,
                field: None,
            })),
        }
    }

    /// Execute generate_index on a plugin.
    ///
    /// Looks up the plugin by format key and executes the generate_index function
    /// with timeout protection.
    pub async fn execute_generate_index(
        &self,
        format_key: &str,
        artifacts: &[WasmMetadata],
    ) -> WasmResult<Option<Vec<WasmIndexFile>>> {
        let plugin = self.get_by_format(format_key).await.ok_or_else(|| {
            WasmError::ValidationFailed(format!("No plugin registered for format '{}'", format_key))
        })?;

        if !plugin.capabilities.generate_index {
            // If plugin doesn't support index generation, return None
            return Ok(None);
        }

        debug!(
            "Executing generate_index on plugin {} with {} artifacts",
            plugin.name,
            artifacts.len()
        );

        let mut store = self.runtime.create_store(
            &plugin.compiled,
            &plugin.id.to_string(),
            &plugin.format_key,
            &plugin.limits,
        )?;

        let wit_artifacts: Vec<super::wasm_bindings::WitMetadata> =
            artifacts.iter().map(Into::into).collect();

        let instance = FormatPlugin::instantiate_async(
            &mut store,
            plugin.compiled.component(),
            plugin.compiled.linker(),
        )
        .await
        .map_err(|e| WasmError::InstantiationFailed(e.to_string()))?;

        let handler = instance.artifact_keeper_format_handler();
        let result = handler
            .call_generate_index(&mut store, &wit_artifacts)
            .await
            .map_err(|e: wasmtime::Error| WasmError::CallFailed(e.to_string()))?;

        match result {
            Ok(Some(files)) => Ok(Some(super::wasm_bindings::index_files_from_wit(files))),
            Ok(None) => Ok(None),
            Err(msg) => Err(WasmError::PluginError(msg)),
        }
    }

    /// Check if a plugin supports handle_request (v2 protocol serving).
    pub async fn has_handle_request(&self, format_key: &str) -> bool {
        self.get_by_format(format_key)
            .await
            .map(|p| p.capabilities.handle_request && p.compiled_v2.is_some())
            .unwrap_or(false)
    }

    /// Execute handle_request on a v2 plugin.
    ///
    /// Routes an HTTP request to the plugin for native protocol serving
    /// (e.g., PEP 503 for pip, repodata for dnf).
    pub async fn execute_handle_request(
        &self,
        format_key: &str,
        request: &WasmHttpRequest,
        context: &WasmRepoContext,
        artifacts: &[WasmMetadata],
    ) -> WasmResult<WasmHttpResponse> {
        let plugin = self.get_by_format(format_key).await.ok_or_else(|| {
            WasmError::ValidationFailed(format!("No plugin registered for format '{}'", format_key))
        })?;

        let compiled_v2 = plugin.compiled_v2.as_ref().ok_or_else(|| {
            WasmError::ValidationFailed(format!(
                "Plugin '{}' does not support handle_request",
                plugin.name
            ))
        })?;

        debug!(
            "Executing handle_request on plugin {} for {} {}",
            plugin.name, request.method, request.path
        );

        let mut store = self.runtime.create_store(
            compiled_v2,
            &plugin.id.to_string(),
            &plugin.format_key,
            &plugin.limits,
        )?;

        let wit_request: WitHttpRequest = request.into();
        let wit_context: WitRepoContext = context.into();
        let wit_artifacts: Vec<WitMetadataV2> = artifacts.iter().map(Into::into).collect();

        let instance = super::wasm_bindings::v2::FormatPluginV2::instantiate_async(
            &mut store,
            compiled_v2.component(),
            compiled_v2.linker(),
        )
        .await
        .map_err(|e| WasmError::InstantiationFailed(e.to_string()))?;

        let req_handler = instance.artifact_keeper_format_request_handler();
        let result = req_handler
            .call_handle_request(&mut store, &wit_request, &wit_context, &wit_artifacts)
            .await
            .map_err(|e: wasmtime::Error| WasmError::CallFailed(e.to_string()))?;

        match result {
            Ok(response) => Ok(WasmHttpResponse::from(response)),
            Err(msg) => Err(WasmError::PluginError(msg)),
        }
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new().expect("Failed to create default PluginRegistry")
    }
}

/// Summary information about a registered plugin.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub id: Uuid,
    pub name: String,
    pub format_key: String,
    pub version: String,
    pub internal_version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_creation() {
        let registry = PluginRegistry::new();
        assert!(registry.is_ok());
    }

    #[tokio::test]
    async fn test_registry_empty() {
        let registry = PluginRegistry::new().unwrap();
        assert_eq!(registry.plugin_count().await, 0);
        assert!(registry.list_formats().await.is_empty());
        assert!(registry.list_plugins().await.is_empty());
    }

    #[tokio::test]
    async fn test_has_format() {
        let registry = PluginRegistry::new().unwrap();
        assert!(!registry.has_format("test-format").await);
    }

    #[tokio::test]
    async fn test_get_nonexistent_plugin() {
        let registry = PluginRegistry::new().unwrap();
        assert!(registry.get_by_format("nonexistent").await.is_none());
        assert!(registry.get_by_id(Uuid::new_v4()).await.is_none());
    }

    #[tokio::test]
    async fn test_unregister_nonexistent() {
        let registry = PluginRegistry::new().unwrap();
        let result = registry.unregister(Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_clear_registry() {
        let registry = PluginRegistry::new().unwrap();
        registry.clear().await;
        assert_eq!(registry.plugin_count().await, 0);
    }

    #[tokio::test]
    async fn test_execute_parse_metadata_no_plugin() {
        let registry = PluginRegistry::new().unwrap();
        let result = registry
            .execute_parse_metadata("nonexistent", "/test.jar", b"test")
            .await;
        assert!(matches!(result, Err(WasmError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn test_execute_validate_no_plugin() {
        let registry = PluginRegistry::new().unwrap();
        let result = registry
            .execute_validate("nonexistent", "/test.jar", b"test")
            .await;
        assert!(matches!(result, Err(WasmError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn test_execute_generate_index_no_plugin() {
        let registry = PluginRegistry::new().unwrap();
        let result = registry.execute_generate_index("nonexistent", &[]).await;
        assert!(matches!(result, Err(WasmError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn test_version_counter_increments() {
        let registry = PluginRegistry::new().unwrap();
        let v1 = registry.next_version().await;
        let v2 = registry.next_version().await;
        let v3 = registry.next_version().await;
        assert_eq!(v1, 1);
        assert_eq!(v2, 2);
        assert_eq!(v3, 3);
    }
}
