//! WASM plugin format handler wrapper.
//!
//! Provides a FormatHandler implementation that delegates to WASM plugins
//! loaded in the PluginRegistry.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, error};

use crate::error::{AppError, Result};
use crate::models::repository::RepositoryFormat;
use crate::services::plugin_registry::PluginRegistry;

use super::FormatHandler;

/// WASM plugin format handler wrapper.
///
/// Delegates format handling to a WASM plugin loaded in the registry.
/// This allows WASM plugins to implement the same FormatHandler interface
/// as compiled-in Rust handlers.
pub struct WasmFormatHandler {
    /// Format key this handler is for
    format_key: String,
    /// Reference to the plugin registry for execution
    registry: Arc<PluginRegistry>,
}

impl WasmFormatHandler {
    /// Create a new WASM format handler.
    pub fn new(format_key: String, registry: Arc<PluginRegistry>) -> Self {
        Self {
            format_key,
            registry,
        }
    }

    /// Get the format key.
    pub fn format_key(&self) -> &str {
        &self.format_key
    }

    /// Check if the plugin is currently available in the registry.
    pub async fn is_available(&self) -> bool {
        self.registry.has_format(&self.format_key).await
    }
}

#[async_trait]
impl FormatHandler for WasmFormatHandler {
    fn format(&self) -> RepositoryFormat {
        // WASM plugins use Generic format in the database
        // The actual format key is stored separately
        RepositoryFormat::Generic
    }

    fn format_key(&self) -> &str {
        &self.format_key
    }

    fn is_wasm_plugin(&self) -> bool {
        true
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        debug!(
            "WASM handler {} parsing metadata for {}",
            self.format_key, path
        );

        let metadata = self
            .registry
            .execute_parse_metadata(&self.format_key, path, content)
            .await
            .map_err(|e| {
                error!(
                    "WASM plugin {} parse_metadata failed: {}",
                    self.format_key, e
                );
                AppError::Internal(format!("Plugin error: {}", e))
            })?;

        Ok(metadata.to_json())
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        debug!(
            "WASM handler {} validating {}",
            self.format_key, path
        );

        let result = self
            .registry
            .execute_validate(&self.format_key, path, content)
            .await
            .map_err(|e| {
                error!("WASM plugin {} validate failed: {}", self.format_key, e);
                AppError::Internal(format!("Plugin error: {}", e))
            })?;

        match result {
            Ok(()) => Ok(()),
            Err(validation_error) => {
                Err(AppError::Validation(validation_error.to_string()))
            }
        }
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        debug!("WASM handler {} generating index", self.format_key);

        let result = self
            .registry
            .execute_generate_index(&self.format_key, &[])
            .await
            .map_err(|e| {
                error!(
                    "WASM plugin {} generate_index failed: {}",
                    self.format_key, e
                );
                AppError::Internal(format!("Plugin error: {}", e))
            })?;

        match result {
            Some(files) => {
                let converted: Vec<(String, Bytes)> = files
                    .into_iter()
                    .map(|f| (f.path, f.content))
                    .collect();
                Ok(Some(converted))
            }
            None => Ok(None),
        }
    }
}

/// Factory for creating WASM format handlers.
///
/// Provides a way to create handlers for any format key that has a
/// registered WASM plugin.
pub struct WasmFormatHandlerFactory {
    registry: Arc<PluginRegistry>,
}

impl WasmFormatHandlerFactory {
    /// Create a new factory with the given plugin registry.
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self { registry }
    }

    /// Create a handler for a specific format key.
    pub fn create_handler(&self, format_key: &str) -> WasmFormatHandler {
        WasmFormatHandler::new(format_key.to_string(), self.registry.clone())
    }

    /// Create handlers for all registered format keys.
    pub async fn create_all_handlers(&self) -> Vec<WasmFormatHandler> {
        let formats = self.registry.list_formats().await;
        formats
            .into_iter()
            .map(|key| WasmFormatHandler::new(key, self.registry.clone()))
            .collect()
    }

    /// Check if a format key has a registered plugin.
    pub async fn has_format(&self, format_key: &str) -> bool {
        self.registry.has_format(format_key).await
    }

    /// Get the underlying registry reference.
    pub fn registry(&self) -> &Arc<PluginRegistry> {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wasm_handler_format_key() {
        let registry = PluginRegistry::new().unwrap();
        let handler = WasmFormatHandler::new(
            "test-format".to_string(),
            Arc::new(registry),
        );

        assert_eq!(handler.format_key(), "test-format");
        assert!(handler.is_wasm_plugin());
        assert_eq!(handler.format(), RepositoryFormat::Generic);
    }

    #[tokio::test]
    async fn test_wasm_handler_not_available() {
        let registry = PluginRegistry::new().unwrap();
        let handler = WasmFormatHandler::new(
            "nonexistent".to_string(),
            Arc::new(registry),
        );

        assert!(!handler.is_available().await);
    }

    #[tokio::test]
    async fn test_factory_create_handler() {
        let registry = Arc::new(PluginRegistry::new().unwrap());
        let factory = WasmFormatHandlerFactory::new(registry);

        let handler = factory.create_handler("test-format");
        assert_eq!(handler.format_key(), "test-format");
    }

    #[tokio::test]
    async fn test_factory_no_formats() {
        let registry = Arc::new(PluginRegistry::new().unwrap());
        let factory = WasmFormatHandlerFactory::new(registry);

        let handlers = factory.create_all_handlers().await;
        assert!(handlers.is_empty());
    }

    #[tokio::test]
    async fn test_parse_metadata_no_plugin() {
        let registry = Arc::new(PluginRegistry::new().unwrap());
        let handler = WasmFormatHandler::new(
            "nonexistent".to_string(),
            registry,
        );

        let result = handler
            .parse_metadata("/test.bin", &Bytes::from_static(b"test"))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_no_plugin() {
        let registry = Arc::new(PluginRegistry::new().unwrap());
        let handler = WasmFormatHandler::new(
            "nonexistent".to_string(),
            registry,
        );

        let result = handler
            .validate("/test.bin", &Bytes::from_static(b"test"))
            .await;

        assert!(result.is_err());
    }
}
