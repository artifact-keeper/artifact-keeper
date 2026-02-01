//! API module - HTTP handlers and middleware.

pub mod dto;
pub mod handlers;
pub mod middleware;
pub mod routes;

use crate::config::Config;
use crate::services::artifact_service::ArtifactService;
use crate::services::meili_service::MeiliService;
use crate::services::plugin_registry::PluginRegistry;
use crate::services::repository_service::RepositoryService;
use crate::services::scanner_service::ScannerService;
use crate::services::wasm_plugin_service::WasmPluginService;
use crate::storage::StorageBackend;
use sqlx::PgPool;
use std::sync::Arc;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
    pub plugin_registry: Option<Arc<PluginRegistry>>,
    pub wasm_plugin_service: Option<Arc<WasmPluginService>>,
    pub scanner_service: Option<Arc<ScannerService>>,
    pub meili_service: Option<Arc<MeiliService>>,
}

impl AppState {
    pub fn new(config: Config, db: PgPool) -> Self {
        Self {
            config,
            db,
            plugin_registry: None,
            wasm_plugin_service: None,
            scanner_service: None,
            meili_service: None,
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
            scanner_service: None,
            meili_service: None,
        }
    }

    /// Set the scanner service for security scanning.
    pub fn set_scanner_service(&mut self, scanner_service: Arc<ScannerService>) {
        self.scanner_service = Some(scanner_service);
    }

    /// Set the Meilisearch service for search indexing.
    pub fn set_meili_service(&mut self, meili_service: Arc<MeiliService>) {
        self.meili_service = Some(meili_service);
    }

    /// Create an ArtifactService with the shared Meilisearch and scanner services.
    pub fn create_artifact_service(&self, storage: Arc<dyn StorageBackend>) -> ArtifactService {
        let mut svc =
            ArtifactService::new_with_meili(self.db.clone(), storage, self.meili_service.clone());
        if let Some(ref scanner) = self.scanner_service {
            svc.set_scanner_service(scanner.clone());
        }
        svc
    }

    /// Create a RepositoryService with the shared Meilisearch service.
    pub fn create_repository_service(&self) -> RepositoryService {
        RepositoryService::new_with_meili(self.db.clone(), self.meili_service.clone())
    }
}

pub type SharedState = Arc<AppState>;
