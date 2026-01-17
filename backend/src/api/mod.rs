//! API module - HTTP handlers and middleware.

pub mod handlers;
pub mod middleware;
pub mod routes;

use crate::config::Config;
use crate::services::plugin_registry::PluginRegistry;
use crate::services::wasm_plugin_service::WasmPluginService;
use sqlx::PgPool;
use std::sync::Arc;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
    pub plugin_registry: Option<Arc<PluginRegistry>>,
    pub wasm_plugin_service: Option<Arc<WasmPluginService>>,
}

impl AppState {
    pub fn new(config: Config, db: PgPool) -> Self {
        Self {
            config,
            db,
            plugin_registry: None,
            wasm_plugin_service: None,
        }
    }

    /// Create state with WASM plugin support
    pub fn with_wasm_plugins(
        config: Config,
        db: PgPool,
        plugin_registry: Arc<PluginRegistry>,
        wasm_plugin_service: Arc<WasmPluginService>,
    ) -> Self {
        Self {
            config,
            db,
            plugin_registry: Some(plugin_registry),
            wasm_plugin_service: Some(wasm_plugin_service),
        }
    }
}

pub type SharedState = Arc<AppState>;
