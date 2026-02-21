//! API module - HTTP handlers and middleware.

pub mod download_response;
pub mod dto;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod routes;

use crate::config::Config;
use crate::services::artifact_service::ArtifactService;
use crate::services::dependency_track_service::DependencyTrackService;
use crate::services::event_bus::EventBus;
use crate::services::meili_service::MeiliService;
use crate::services::plugin_registry::PluginRegistry;
use crate::services::proxy_service::ProxyService;
use crate::services::quality_check_service::QualityCheckService;
use crate::services::repository_service::RepositoryService;
use crate::services::scanner_service::ScannerService;
use crate::services::wasm_plugin_service::WasmPluginService;
use crate::storage::StorageBackend;
use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
    pub storage: Arc<dyn StorageBackend>,
    pub plugin_registry: Option<Arc<PluginRegistry>>,
    pub wasm_plugin_service: Option<Arc<WasmPluginService>>,
    pub scanner_service: Option<Arc<ScannerService>>,
    pub meili_service: Option<Arc<MeiliService>>,
    pub dependency_track: Option<Arc<DependencyTrackService>>,
    pub quality_check_service: Option<Arc<QualityCheckService>>,
    pub proxy_service: Option<Arc<ProxyService>>,
    pub metrics_handle: Option<Arc<PrometheusHandle>>,
    /// When true, most API endpoints return 403 until the admin changes the default password.
    pub setup_required: Arc<AtomicBool>,
    pub event_bus: Arc<EventBus>,
}

impl AppState {
    pub fn new(config: Config, db: PgPool, storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            config,
            db,
            storage,
            plugin_registry: None,
            wasm_plugin_service: None,
            scanner_service: None,
            quality_check_service: None,
            meili_service: None,
            dependency_track: None,
            proxy_service: None,
            metrics_handle: None,
            setup_required: Arc::new(AtomicBool::new(false)),
            event_bus: Arc::new(EventBus::new(1024)),
        }
    }

    /// Create state with WASM plugin support
    pub fn with_wasm_plugins(
        config: Config,
        db: PgPool,
        storage: Arc<dyn StorageBackend>,
        plugin_registry: Arc<PluginRegistry>,
        wasm_plugin_service: Arc<WasmPluginService>,
    ) -> Self {
        Self {
            config,
            db,
            storage,
            plugin_registry: Some(plugin_registry),
            wasm_plugin_service: Some(wasm_plugin_service),
            scanner_service: None,
            quality_check_service: None,
            meili_service: None,
            dependency_track: None,
            proxy_service: None,
            metrics_handle: None,
            setup_required: Arc::new(AtomicBool::new(false)),
            event_bus: Arc::new(EventBus::new(1024)),
        }
    }

    /// Get the storage backend for a given repository.
    ///
    /// For S3/Azure/GCS, all repos share a single backend instance (artifacts
    /// are keyed by content-addressed SHA-256 hashes). For filesystem, each
    /// repo has its own directory so we create a per-repo instance.
    pub fn storage_for_repo(&self, repo_storage_path: &str) -> Arc<dyn StorageBackend> {
        match self.config.storage_backend.as_str() {
            "s3" | "azure" | "gcs" => self.storage.clone(),
            _ => Arc::new(crate::storage::filesystem::FilesystemStorage::new(
                repo_storage_path,
            )),
        }
    }

    /// Set the scanner service for security scanning.
    pub fn set_scanner_service(&mut self, scanner_service: Arc<ScannerService>) {
        self.scanner_service = Some(scanner_service);
    }

    /// Set the quality check service for health scoring and quality gates.
    pub fn set_quality_check_service(&mut self, qc_service: Arc<QualityCheckService>) {
        self.quality_check_service = Some(qc_service);
    }

    /// Set the Meilisearch service for search indexing.
    pub fn set_meili_service(&mut self, meili_service: Arc<MeiliService>) {
        self.meili_service = Some(meili_service);
    }

    /// Set the Dependency-Track service for security analysis.
    pub fn set_dependency_track(&mut self, dt: Arc<DependencyTrackService>) {
        self.dependency_track = Some(dt);
    }

    /// Set the proxy service for remote repository proxying.
    pub fn set_proxy_service(&mut self, proxy_service: Arc<ProxyService>) {
        self.proxy_service = Some(proxy_service);
    }

    /// Set the Prometheus metrics handle for rendering /metrics output.
    pub fn set_metrics_handle(&mut self, handle: PrometheusHandle) {
        self.metrics_handle = Some(Arc::new(handle));
    }

    /// Create an ArtifactService with the shared Meilisearch and scanner services.
    pub fn create_artifact_service(&self, storage: Arc<dyn StorageBackend>) -> ArtifactService {
        let mut svc =
            ArtifactService::new_with_meili(self.db.clone(), storage, self.meili_service.clone());
        if let Some(ref scanner) = self.scanner_service {
            svc.set_scanner_service(scanner.clone());
        }
        if let Some(ref qc) = self.quality_check_service {
            svc.set_quality_check_service(qc.clone());
        }
        svc
    }

    /// Create a RepositoryService with the shared Meilisearch service.
    pub fn create_repository_service(&self) -> RepositoryService {
        RepositoryService::new_with_meili(self.db.clone(), self.meili_service.clone())
    }
}

pub type SharedState = Arc<AppState>;
