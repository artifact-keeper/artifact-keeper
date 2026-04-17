//! Artifact Keeper - Main Entry Point

use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{header, Method};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use rand::Rng;

use artifact_keeper_backend::{
    api,
    config::Config,
    db,
    error::Result,
    grpc::{
        generated::{
            cve_history_service_server::CveHistoryServiceServer,
            sbom_service_server::SbomServiceServer,
            security_policy_service_server::SecurityPolicyServiceServer,
        },
        sbom_server::{CveHistoryGrpcServer, SbomGrpcServer, SecurityPolicyGrpcServer},
    },
    services::{
        auth_service::AuthService,
        dependency_track_service::DependencyTrackService,
        meili_service::MeiliService,
        metrics_service,
        plugin_registry::PluginRegistry,
        proxy_service::ProxyService,
        scan_config_service::ScanConfigService,
        scan_result_service::ScanResultService,
        scanner_service::{AdvisoryClient, ScannerService},
        scheduler_service,
        smtp_service::SmtpService,
        storage_service::StorageService,
        wasm_plugin_service::WasmPluginService,
    },
};
use tokio_util::sync::CancellationToken;
use tonic::transport::Server as TonicServer;

#[cfg(windows)]
mod windows_service;

/// Wait for a shutdown signal (Ctrl+C or SIGTERM).
///
/// Returns once either signal is received. This allows Kubernetes to send
/// SIGTERM during pod termination while also supporting local Ctrl+C.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("received Ctrl+C, starting graceful shutdown"); },
        _ = terminate => { tracing::info!("received SIGTERM, starting graceful shutdown"); },
    }
}

/// Core server logic extracted so it can be called from both the normal entrypoint
/// and the Windows Service entrypoint with an externally-managed shutdown token.
pub async fn run_server(shutdown_token: Option<CancellationToken>) -> Result<()> {
    // Install a rustls CryptoProvider before any TLS operations.
    // Required by rustls 0.23+ when multiple providers (ring, aws-lc-rs)
    // are compiled in via transitive dependencies (object_store, reqwest, sqlx).
    // Without this, IRSA/STS credential fetches panic at startup.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    // Load environment variables
    if let Ok(env_file) = std::env::var("AK_ENV_FILE") {
        dotenvy::from_path(&env_file).ok();
    } else {
        dotenvy::dotenv().ok();
    }

    // Initialize tracing (with optional OpenTelemetry OTLP export).
    // Read OTel config directly from env since Config::from_env() might fail
    // and we want tracing available to log those errors.
    let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
    let otel_service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "artifact-keeper".into());
    let _otel_guard = artifact_keeper_backend::telemetry::init_tracing(
        otel_endpoint.as_deref(),
        &otel_service_name,
    );

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Starting Artifact Keeper");

    // Connect to database
    let db_pool = db::create_pool(&config).await?;
    tracing::info!("Connected to database");

    // Run migrations (skip with SKIP_MIGRATIONS=true for pre-applied migrations)
    let skip_migrations = std::env::var("SKIP_MIGRATIONS")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");

    if skip_migrations {
        tracing::info!("SKIP_MIGRATIONS=true, skipping automatic database migrations");
    } else {
        tracing::info!("Running database migrations...");
        sqlx::migrate!("./migrations").run(&db_pool).await?;
        tracing::info!("Database migrations complete");
    }

    // Provision admin user on first boot; returns true when setup lock is needed
    let setup_required = provision_admin_user(&db_pool, &config.storage_path).await?;

    // Bootstrap OIDC config from environment variables when no DB configs exist yet.
    // This bridges the gap between env-var-based deployment and the database-backed
    // SSO config that the handlers actually use (fixes #238).
    bootstrap_oidc_from_env(&db_pool).await?;

    // Initialize peer identity for mesh networking
    let peer_id = init_peer_identity(&db_pool, &config).await?;
    tracing::info!("Peer identity: {} ({})", config.peer_instance_name, peer_id);

    // Initialize WASM plugin system (T068)
    let plugins_dir =
        PathBuf::from(std::env::var("PLUGINS_DIR").unwrap_or_else(|_| "./plugins".to_string()));
    let (plugin_registry, wasm_plugin_service) =
        initialize_wasm_plugins(db_pool.clone(), plugins_dir).await?;

    // Initialize Meilisearch (optional, graceful fallback)
    let meili_service = match (&config.meilisearch_url, &config.meilisearch_api_key) {
        (Some(url), Some(api_key)) => {
            tracing::info!("Initializing Meilisearch at {}", url);
            match MeiliService::new(url, api_key) {
                Ok(s) => {
                    let service = Arc::new(s);
                    match service.configure_indexes().await {
                        Ok(()) => {
                            tracing::info!("Meilisearch indexes configured");
                            let svc = service.clone();
                            let pool = db_pool.clone();
                            tokio::spawn(async move {
                                match svc.is_index_empty().await {
                                    Ok(true) => {
                                        tracing::info!(
                                            "Meilisearch index is empty, starting background reindex"
                                        );
                                        if let Err(e) = svc.full_reindex(&pool).await {
                                            tracing::error!("Background reindex failed: {}", e);
                                        }
                                    }
                                    Ok(false) => {
                                        tracing::info!(
                                            "Meilisearch index already populated, skipping reindex"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to check Meilisearch index status: {}",
                                            e
                                        );
                                    }
                                }
                            });
                            Some(service)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to configure Meilisearch indexes, continuing without search: {}",
                                e
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to initialize Meilisearch client, continuing without search: {}",
                        e
                    );
                    None
                }
            }
        }
        _ => {
            tracing::info!("Meilisearch not configured, search indexing disabled");
            None
        }
    };

    // Initialize Prometheus metrics recorder
    let metrics_handle = metrics_service::init_metrics();
    tracing::info!("Prometheus metrics recorder initialized");

    // Create primary storage backend based on STORAGE_BACKEND config
    let primary_storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = match config
        .storage_backend
        .as_str()
    {
        "s3" => {
            let s3 = artifact_keeper_backend::storage::s3::S3Backend::from_env().await?;
            tracing::info!("S3 storage backend initialized");
            Arc::new(s3)
        }
        "azure" => {
            let azure_config = artifact_keeper_backend::storage::azure::AzureConfig::from_env()?;
            let azure =
                artifact_keeper_backend::storage::azure::AzureBackend::new(azure_config).await?;
            tracing::info!("Azure Blob storage backend initialized");
            Arc::new(azure)
        }
        "gcs" => {
            let gcs_config = artifact_keeper_backend::storage::gcs::GcsConfig::from_env()?;
            let gcs = artifact_keeper_backend::storage::gcs::GcsBackend::new(gcs_config).await?;
            tracing::info!("GCS storage backend initialized");
            Arc::new(gcs)
        }
        _ => {
            tracing::info!(
                "Filesystem storage backend initialized at {}",
                config.storage_path
            );
            Arc::new(
                artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(
                    &config.storage_path,
                ),
            )
        }
    };

    // Build the storage registry for per-repo backend routing.
    // The registry maps backend names to initialized StorageBackend instances.
    // "filesystem" is always available (handled dynamically by the registry).
    let storage_registry = {
        use std::collections::HashMap;
        let mut backends: HashMap<
            String,
            Arc<dyn artifact_keeper_backend::storage::StorageBackend>,
        > = HashMap::new();

        // Register the primary backend under its type name if it is not filesystem
        if config.storage_backend != "filesystem" {
            backends.insert(config.storage_backend.clone(), primary_storage.clone());
        }

        // Try to register additional backends if credentials are available and
        // they are not already the primary backend.
        if config.storage_backend != "s3" {
            if let Ok(s3) = artifact_keeper_backend::storage::s3::S3Backend::from_env().await {
                tracing::info!("Additional S3 storage backend registered");
                backends.insert("s3".to_string(), Arc::new(s3));
            }
        }
        if config.storage_backend != "azure" {
            if let Ok(azure_cfg) = artifact_keeper_backend::storage::azure::AzureConfig::from_env()
            {
                if let Ok(azure) =
                    artifact_keeper_backend::storage::azure::AzureBackend::new(azure_cfg).await
                {
                    tracing::info!("Additional Azure storage backend registered");
                    backends.insert("azure".to_string(), Arc::new(azure));
                }
            }
        }
        if config.storage_backend != "gcs" {
            if let Ok(gcs_cfg) = artifact_keeper_backend::storage::gcs::GcsConfig::from_env() {
                if let Ok(gcs) =
                    artifact_keeper_backend::storage::gcs::GcsBackend::new(gcs_cfg).await
                {
                    tracing::info!("Additional GCS storage backend registered");
                    backends.insert("gcs".to_string(), Arc::new(gcs));
                }
            }
        }

        let available: Vec<String> = {
            let mut names = vec!["filesystem".to_string()];
            names.extend(backends.keys().cloned());
            names
        };
        tracing::info!("Storage backends available: {:?}", available);

        Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
            backends,
            config.storage_backend.clone(),
        ))
    };

    // Initialize security scanner service
    let advisory_client = Arc::new(AdvisoryClient::new(std::env::var("GITHUB_TOKEN").ok()));
    let scan_result_service = Arc::new(ScanResultService::new(db_pool.clone()));
    let scan_config_service = Arc::new(ScanConfigService::new(db_pool.clone()));
    let scanner_service = Arc::new(ScannerService::new(
        db_pool.clone(),
        advisory_client,
        scan_result_service,
        scan_config_service,
        config.trivy_url.clone(),
        primary_storage.clone(),
        storage_registry.clone(),
        config.storage_path.clone(),
        config.scan_workspace_path.clone(),
        config.openscap_url.clone(),
        config.openscap_profile.clone(),
    ));

    // Create application state with WASM plugin support
    let scheduler_storage = primary_storage.clone();
    let mut app_state = api::AppState::with_wasm_plugins(
        config.clone(),
        db_pool.clone(),
        primary_storage,
        storage_registry.clone(),
        plugin_registry,
        wasm_plugin_service,
    );
    app_state.set_scanner_service(scanner_service);

    // Initialize quality check service for health scoring and quality gates
    let quality_check_service = Arc::new(
        artifact_keeper_backend::services::quality_check_service::QualityCheckService::new(
            db_pool.clone(),
        ),
    );
    app_state.set_quality_check_service(quality_check_service);
    if let Some(meili) = meili_service {
        app_state.set_meili_service(meili);
    }
    // Initialize Dependency-Track integration
    if let Some(dt_result) = DependencyTrackService::from_env() {
        match dt_result {
            Ok(dt_service) => {
                tracing::info!("Dependency-Track integration enabled");
                app_state.set_dependency_track(Arc::new(dt_service));
            }
            Err(e) => {
                tracing::warn!("Failed to initialize Dependency-Track: {}", e);
            }
        }
    }

    app_state.set_metrics_handle(metrics_handle);

    // Initialize proxy service for remote repository caching
    match StorageService::from_config(&config).await {
        Ok(storage_svc) => {
            let proxy_service = Arc::new(ProxyService::new(db_pool.clone(), Arc::new(storage_svc)));
            app_state.set_proxy_service(proxy_service);
            tracing::info!("Proxy service initialized for remote repositories");
        }
        Err(e) => {
            tracing::warn!(
                "Failed to initialize proxy service, remote repositories disabled: {}",
                e
            );
        }
    }

    // Initialize SMTP service (optional, graceful no-op when SMTP_HOST is absent)
    match SmtpService::new(&config) {
        Ok(smtp) => {
            if smtp.is_configured() {
                tracing::info!("SMTP service initialized");
            } else {
                tracing::info!("SMTP not configured, email delivery disabled");
            }
            app_state.set_smtp_service(Arc::new(smtp));
        }
        Err(e) => {
            tracing::warn!(
                "Failed to initialize SMTP service, email delivery disabled: {}",
                e
            );
        }
    }

    // Start notification dispatcher (subscribes to EventBus for email/webhook delivery)
    artifact_keeper_backend::services::notification_dispatcher::start_dispatcher(
        app_state.event_bus.clone(),
        app_state.db.clone(),
        app_state.smtp_service.clone(),
    );
    tracing::info!("Notification dispatcher started");

    app_state
        .setup_required
        .store(setup_required, std::sync::atomic::Ordering::Relaxed);
    let state = Arc::new(app_state);

    // Spawn background schedulers (metrics snapshots, health monitor, lifecycle)
    scheduler_service::spawn_all(
        db_pool.clone(),
        config.clone(),
        scheduler_storage,
        storage_registry.clone(),
        state.smtp_service.clone(),
    );

    // Keep a handle for the gRPC server before the sync worker consumes db_pool
    let grpc_db_pool = db_pool.clone();

    // Spawn background sync worker for peer replication
    artifact_keeper_backend::services::sync_worker::spawn_sync_worker(db_pool).await;
    tracing::info!("Sync worker started");

    // Conditionally clone state for the metrics listener before the router takes
    // ownership. The clone only happens when METRICS_PORT is actually configured.
    let metrics_state = config.metrics_port.map(|_| state.clone());

    // Build router
    let app = Router::new()
        .merge(api::routes::create_router(state))
        .layer(axum::middleware::from_fn(
            artifact_keeper_backend::api::middleware::metrics::metrics_middleware,
        ))
        .layer({
            // In production the frontend is served from the same origin, so
            // credentials + same-origin work without an explicit allow-origin.
            // In development the Next.js dev server runs on a different port,
            // so we must whitelist that origin and enable credentials.
            // Private-network origins (192.168.x.x, 10.x.x.x, 172.16-31.x.x,
            // 127.x.x.x) are always allowed in development mode.
            if std::env::var("ENVIRONMENT").unwrap_or_default() == "development" {
                let explicit_origins: Vec<String> = std::env::var("CORS_ORIGINS")
                    .unwrap_or_else(|_| "http://localhost:3000".into())
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .collect();
                CorsLayer::new()
                    .allow_origin(AllowOrigin::predicate(
                        move |origin: &axum::http::HeaderValue, _req| {
                            let origin_str = origin.to_str().unwrap_or("");
                            if explicit_origins.iter().any(|o| o == origin_str) {
                                return true;
                            }
                            // Allow any private-network / loopback origin
                            if let Some(host) = origin_str
                                .strip_prefix("http://")
                                .or_else(|| origin_str.strip_prefix("https://"))
                            {
                                let host = host.split(':').next().unwrap_or("");
                                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                                    return ip.is_private() || ip.is_loopback();
                                }
                                return host == "localhost";
                            }
                            false
                        },
                    ))
                    .allow_methods([
                        Method::GET,
                        Method::POST,
                        Method::PUT,
                        Method::PATCH,
                        Method::DELETE,
                        Method::OPTIONS,
                    ])
                    .allow_headers([
                        header::CONTENT_TYPE,
                        header::AUTHORIZATION,
                        header::ACCEPT,
                        header::COOKIE,
                    ])
                    .allow_credentials(true)
            } else {
                // Production: use CORS_ORIGINS env var if set, otherwise same-origin only
                let origins_str = std::env::var("CORS_ORIGINS").unwrap_or_default();
                if origins_str.is_empty() {
                    CorsLayer::new()
                } else {
                    let origins: Vec<_> = origins_str
                        .split(',')
                        .map(|s| s.trim().parse().expect("invalid CORS origin"))
                        .collect();
                    CorsLayer::new()
                        .allow_origin(AllowOrigin::list(origins))
                        .allow_methods([
                            Method::GET,
                            Method::POST,
                            Method::PUT,
                            Method::PATCH,
                            Method::DELETE,
                            Method::OPTIONS,
                        ])
                        .allow_headers([
                            header::CONTENT_TYPE,
                            header::AUTHORIZATION,
                            header::ACCEPT,
                        ])
                }
            }
        })
        .layer(axum::middleware::from_fn(
            artifact_keeper_backend::api::middleware::security_headers::security_headers_middleware,
        ))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
                let uri = request.uri();
                let sanitized =
                    artifact_keeper_backend::api::redact_sensitive_params(uri.path(), uri.query());
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    uri = %sanitized,
                )
            }),
        );

    // Shared cancellation token: when the shutdown signal fires, both the
    // HTTP and gRPC servers are notified to stop accepting new connections
    // and drain in-flight requests before the process exits.
    let shutdown_token = match shutdown_token {
        Some(token) => token,
        None => {
            // No external token provided (console mode). Create our own and
            // spawn the signal listener that cancels it on SIGTERM / Ctrl+C.
            let token = CancellationToken::new();
            let signal_token = token.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                signal_token.cancel();
            });
            token
        }
    };

    // Start HTTP server
    let addr: SocketAddr = config.bind_address.parse()?;
    tracing::info!("HTTP server listening on {}", addr);

    // Start gRPC server on a separate port
    let grpc_port = std::env::var("GRPC_PORT")
        .unwrap_or_else(|_| "9090".to_string())
        .parse::<u16>()
        .unwrap_or(9090);
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", grpc_port).parse()?;

    // Reuse the existing pool instead of creating a second one (PgPool is Arc-backed)
    let sbom_server = SbomGrpcServer::new(grpc_db_pool.clone());
    let cve_history_server = CveHistoryGrpcServer::new(grpc_db_pool.clone());
    let security_policy_server = SecurityPolicyGrpcServer::new(grpc_db_pool);

    // gRPC auth interceptor — validates JWT Bearer tokens
    let grpc_auth =
        artifact_keeper_backend::grpc::auth_interceptor::AuthInterceptor::new(&config.jwt_secret);

    // Include file descriptor for gRPC reflection
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/sbom_descriptor.bin"
        )))
        .build_v1()
        .expect("Failed to build reflection service");

    let grpc_auth_sbom = grpc_auth.clone();
    let grpc_auth_cve = grpc_auth.clone();
    let grpc_auth_policy = grpc_auth;
    let grpc_shutdown_token = shutdown_token.clone();
    tokio::spawn(async move {
        tracing::info!("gRPC server listening on {}", grpc_addr);
        #[allow(clippy::result_large_err)]
        let sbom_interceptor = move |req| grpc_auth_sbom.intercept(req);
        #[allow(clippy::result_large_err)]
        let cve_interceptor = move |req| grpc_auth_cve.intercept(req);
        #[allow(clippy::result_large_err)]
        let policy_interceptor = move |req| grpc_auth_policy.intercept(req);
        if let Err(e) = TonicServer::builder()
            .add_service(reflection_service)
            .add_service(SbomServiceServer::with_interceptor(
                sbom_server,
                sbom_interceptor,
            ))
            .add_service(CveHistoryServiceServer::with_interceptor(
                cve_history_server,
                cve_interceptor,
            ))
            .add_service(SecurityPolicyServiceServer::with_interceptor(
                security_policy_server,
                policy_interceptor,
            ))
            .serve_with_shutdown(grpc_addr, grpc_shutdown_token.cancelled())
            .await
        {
            tracing::error!("gRPC server error: {}", e);
        }
        tracing::info!("gRPC server shut down");
    });

    // Optionally start an unauthenticated metrics-only listener on METRICS_PORT.
    if let (Some(metrics_port), Some(metrics_state)) = (config.metrics_port, metrics_state) {
        tracing::warn!(
            port = metrics_port,
            "Starting unauthenticated metrics listener — \
             ensure this port is not reachable from untrusted networks"
        );
        let metrics_addr: SocketAddr = format!("0.0.0.0:{}", metrics_port).parse()?;
        let metrics_shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let metrics_app = Router::new()
                .route(
                    "/metrics",
                    axum::routing::get(api::handlers::health::metrics),
                )
                .with_state(metrics_state);
            match tokio::net::TcpListener::bind(metrics_addr).await {
                Ok(listener) => {
                    tracing::info!("Metrics listener on {}", metrics_addr);
                    if let Err(e) = axum::serve(listener, metrics_app)
                        .with_graceful_shutdown(async move { metrics_shutdown.cancelled().await })
                        .await
                    {
                        tracing::error!("Metrics listener error: {}", e);
                    }
                    tracing::info!("Metrics listener shut down");
                }
                Err(e) => {
                    tracing::error!("Failed to bind metrics listener on {}: {}", metrics_addr, e);
                }
            }
        });
    }

    let http_shutdown_token = shutdown_token.clone();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { http_shutdown_token.cancelled().await })
        .await?;

    tracing::info!("HTTP server shut down");

    Ok(())
}

// ---------------------------------------------------------------------------
// Platform-specific entrypoints
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
#[tokio::main]
async fn main() -> Result<()> {
    run_server(None).await
}

#[cfg(windows)]
fn main() -> Result<()> {
    use artifact_keeper_backend::error::AppError;

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--service") {
        windows_service::run_as_service().map_err(|e| {
            eprintln!("Service error: {e}");
            AppError::Config(e.to_string())
        })
    } else if args.iter().any(|a| a == "--install") {
        windows_service::install_service(&args).map_err(|e| {
            eprintln!("Install error: {e}");
            AppError::Config(e.to_string())
        })
    } else if args.iter().any(|a| a == "--uninstall") {
        windows_service::uninstall_service().map_err(|e| {
            eprintln!("Uninstall error: {e}");
            AppError::Config(e.to_string())
        })
    } else {
        // Console mode: same as Linux/macOS
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");
        runtime.block_on(run_server(None))
    }
}

/// Initialize the WASM plugin system (T068).
///
/// Creates the plugin registry, loads active plugins from the database,
/// and returns both the registry and the plugin service.
async fn initialize_wasm_plugins(
    db_pool: sqlx::PgPool,
    plugins_dir: PathBuf,
) -> Result<(Arc<PluginRegistry>, Arc<WasmPluginService>)> {
    tracing::info!("Initializing WASM plugin system");

    // Create plugin registry
    let registry = Arc::new(PluginRegistry::new().map_err(|e| {
        artifact_keeper_backend::error::AppError::Internal(format!(
            "Failed to create plugin registry: {}",
            e
        ))
    })?);

    // Create WASM plugin service
    let wasm_service = Arc::new(WasmPluginService::new(
        db_pool.clone(),
        registry.clone(),
        plugins_dir.clone(),
    ));

    // Ensure plugins directory exists
    wasm_service.ensure_plugins_dir().await?;

    // Load active plugins from database
    let active_plugins = load_active_plugins(&db_pool).await?;

    let mut loaded_count = 0;
    let mut error_count = 0;

    for plugin in active_plugins {
        if let Some(ref wasm_path) = plugin.wasm_path {
            match wasm_service
                .activate_plugin_at_startup(&plugin, std::path::Path::new(wasm_path))
                .await
            {
                Ok(_) => {
                    tracing::info!("Loaded plugin: {} v{}", plugin.name, plugin.version);
                    loaded_count += 1;
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to load plugin {}: {}. Marking as error state.",
                        plugin.name,
                        e
                    );
                    // Update plugin status to error
                    let _ = sqlx::query("UPDATE plugins SET status = 'error' WHERE id = $1")
                        .bind(plugin.id)
                        .execute(&db_pool)
                        .await;
                    error_count += 1;
                }
            }
        }
    }

    tracing::info!(
        "WASM plugin system initialized: {} plugins loaded, {} errors",
        loaded_count,
        error_count
    );

    Ok((registry, wasm_service))
}

/// Initialize or retrieve the persistent peer identity for this instance.
async fn init_peer_identity(db: &sqlx::PgPool, config: &Config) -> Result<uuid::Uuid> {
    // Check if identity already exists
    let existing: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT peer_instance_id FROM peer_instance_identity LIMIT 1")
            .fetch_optional(db)
            .await
            .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    if let Some(id) = existing {
        // Update name/endpoint in case config changed
        sqlx::query(
            "UPDATE peer_instance_identity SET name = $1, endpoint_url = $2, updated_at = NOW()",
        )
        .bind(&config.peer_instance_name)
        .bind(&config.peer_public_endpoint)
        .execute(db)
        .await
        .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;
        return Ok(id);
    }

    // Generate new identity
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO peer_instance_identity (peer_instance_id, name, endpoint_url) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(&config.peer_instance_name)
    .bind(&config.peer_public_endpoint)
    .execute(db)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    // Also register this instance in the peer_instances table as is_local=true
    sqlx::query(
        r#"
        INSERT INTO peer_instances (name, endpoint_url, status, api_key, is_local)
        VALUES ($1, $2, 'online', $3, true)
        ON CONFLICT (name) DO UPDATE SET
            endpoint_url = EXCLUDED.endpoint_url,
            api_key = EXCLUDED.api_key,
            status = 'online',
            is_local = true,
            updated_at = NOW()
        "#,
    )
    .bind(&config.peer_instance_name)
    .bind(&config.peer_public_endpoint)
    .bind(&config.peer_api_key)
    .execute(db)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    Ok(id)
}

/// Bootstrap an OIDC provider from environment variables when the database
/// has no OIDC configs yet.  This lets operators configure OIDC entirely via
/// env vars (OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, etc.) without
/// needing admin API access first.
async fn bootstrap_oidc_from_env(db: &sqlx::PgPool) -> Result<()> {
    use artifact_keeper_backend::services::auth_config_service::AuthConfigService;

    let req = match build_oidc_bootstrap_request() {
        Some(r) => r,
        None => return Ok(()),
    };

    // Only bootstrap when no OIDC configs exist in the database
    let existing = AuthConfigService::list_oidc(db).await?;
    if !existing.is_empty() {
        tracing::debug!(
            "OIDC env vars present but {} config(s) already exist in DB, skipping bootstrap",
            existing.len()
        );
        return Ok(());
    }

    let config = AuthConfigService::create_oidc(db, req).await?;
    tracing::info!(
        "Bootstrapped OIDC provider '{}' (id={}) from environment variables",
        config.name,
        config.id
    );

    Ok(())
}

/// Raw OIDC environment variable values for bootstrap.
#[derive(Default)]
struct OidcEnvVars {
    issuer: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Option<String>,
    groups_claim: Option<String>,
    redirect_uri: Option<String>,
    username_claim: Option<String>,
    email_claim: Option<String>,
}

/// Build a CreateOidcConfigRequest from OIDC_* environment variables.
/// Returns None if any of the three required env vars are missing or empty.
fn build_oidc_bootstrap_request(
) -> Option<artifact_keeper_backend::services::auth_config_service::CreateOidcConfigRequest> {
    build_oidc_request_from_values(OidcEnvVars {
        issuer: std::env::var("OIDC_ISSUER").ok(),
        client_id: std::env::var("OIDC_CLIENT_ID").ok(),
        client_secret: std::env::var("OIDC_CLIENT_SECRET").ok(),
        scopes: std::env::var("OIDC_SCOPES").ok(),
        groups_claim: std::env::var("OIDC_GROUPS_CLAIM").ok(),
        redirect_uri: std::env::var("OIDC_REDIRECT_URI").ok(),
        username_claim: std::env::var("OIDC_USERNAME_CLAIM").ok(),
        email_claim: std::env::var("OIDC_EMAIL_CLAIM").ok(),
    })
}

/// Pure function that assembles a CreateOidcConfigRequest from optional values.
/// Returns None if issuer, client_id, or client_secret are missing or empty.
fn build_oidc_request_from_values(
    env: OidcEnvVars,
) -> Option<artifact_keeper_backend::services::auth_config_service::CreateOidcConfigRequest> {
    use artifact_keeper_backend::services::auth_config_service::CreateOidcConfigRequest;

    let issuer = env.issuer.filter(|v| !v.is_empty())?;
    let client_id = env.client_id.filter(|v| !v.is_empty())?;
    let client_secret = env.client_secret.filter(|v| !v.is_empty())?;

    let scopes = env
        .scopes
        .map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>());

    let groups_claim_val = env.groups_claim.unwrap_or_else(|| "groups".to_string());

    let mut attr_map = serde_json::Map::new();
    attr_map.insert(
        "groups_claim".into(),
        serde_json::Value::String(groups_claim_val),
    );
    if let Some(uri) = env.redirect_uri {
        attr_map.insert("redirect_uri".into(), serde_json::Value::String(uri));
    }
    if let Some(claim) = env.username_claim {
        attr_map.insert("username_claim".into(), serde_json::Value::String(claim));
    }
    if let Some(claim) = env.email_claim {
        attr_map.insert("email_claim".into(), serde_json::Value::String(claim));
    }

    Some(CreateOidcConfigRequest {
        name: "default".to_string(),
        issuer_url: issuer,
        client_id,
        client_secret,
        scopes,
        attribute_mapping: Some(serde_json::Value::Object(attr_map)),
        is_enabled: Some(true),
        auto_create_users: Some(true),
    })
}

/// Provision the initial admin user on first boot and determine setup mode.
///
/// Returns `true` when the API should be locked until the admin changes
/// the default password (i.e. `must_change_password` is still set and no
/// explicit `ADMIN_PASSWORD` env var was provided).
async fn provision_admin_user(db: &sqlx::PgPool, storage_path: &str) -> Result<bool> {
    use std::path::Path;

    // Skip admin provisioning when SSO handles admin assignment (issue #211)
    if std::env::var("SKIP_ADMIN_PROVISIONING")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true")
    {
        tracing::info!(
            "SKIP_ADMIN_PROVISIONING=true — skipping built-in admin user creation. \
             Admin access must be granted via SSO group mapping."
        );
        return Ok(false);
    }

    let password_file = Path::new(storage_path).join("admin.password");

    // Check if an admin user already exists
    let admin_row: Option<(bool,)> =
        sqlx::query_as("SELECT must_change_password FROM users WHERE is_admin = true LIMIT 1")
            .fetch_optional(db)
            .await
            .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    let demo_mode = matches!(std::env::var("DEMO_MODE").as_deref(), Ok("true" | "1"));

    if let Some((must_change,)) = admin_row {
        // Ensure existing admin user always has auth_provider = 'local' so
        // password-based login works.  This is a no-op when the column is
        // already correct but fixes installs that ended up with a wrong value.
        sqlx::query(
            "UPDATE users SET auth_provider = 'local' WHERE username = 'admin' AND auth_provider != 'local'"
        )
        .execute(db)
        .await
        .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

        if !must_change && !demo_mode {
            if let Ok(env_pw) = std::env::var("ADMIN_PASSWORD") {
                if is_insecure_default_password(&env_pw) {
                    tracing::warn!("ADMIN_PASSWORD matches a well-known default.");
                    sqlx::query(
                        "UPDATE users SET must_change_password = true WHERE username = 'admin'",
                    )
                    .execute(db)
                    .await
                    .map_err(|e| {
                        artifact_keeper_backend::error::AppError::Database(e.to_string())
                    })?;
                    return Ok(true);
                }
            }
        }

        if must_change {
            tracing::warn!(
                "Admin user has not changed default password. API is locked until password is changed."
            );
            // Ensure the password file still exists for the user to read
            if password_file.exists() {
                tracing::info!("Admin password file: {}", password_file.display());
            }
            return Ok(true);
        }
        return Ok(false);
    }

    let (password, must_change) = match std::env::var("ADMIN_PASSWORD") {
        Ok(p) if !p.is_empty() => {
            if is_insecure_default_password(&p) && !demo_mode {
                tracing::warn!("ADMIN_PASSWORD matches a well-known default.");
                (p, true)
            } else {
                (p, false)
            }
        }
        _ => {
            const CHARSET: &[u8] =
                b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*";
            let mut rng = rand::rng();
            let p: String = (0..20)
                .map(|_| {
                    let idx = rng.random_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect();
            (p, true)
        }
    };

    let password_hash = AuthService::hash_password(&password).await?;

    sqlx::query(
        r#"
        INSERT INTO users (username, email, password_hash, is_admin, must_change_password, auth_provider)
        VALUES ('admin', 'admin@localhost', $1, true, $2, 'local')
        ON CONFLICT (username) DO UPDATE
            SET password_hash = EXCLUDED.password_hash,
                must_change_password = EXCLUDED.must_change_password,
                auth_provider = 'local'
        "#,
    )
    .bind(&password_hash)
    .bind(must_change)
    .execute(db)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    if must_change {
        // Write password + setup instructions to the file
        let file_contents = format!(
            "{}\n\n\
            # ONE-TIME SETUP — this password must be changed before the API unlocks.\n\
            #\n\
            # Step 1: Login to get a JWT token:\n\
            #   curl -s -X POST http://localhost:8080/api/v1/auth/login \\\n\
            #     -H 'Content-Type: application/json' \\\n\
            #     -d '{{\"username\":\"admin\",\"password\":\"<password-above>\"}}'\n\
            #\n\
            # Step 2: Change the password (use the access_token from step 1):\n\
            #   curl -s -X POST http://localhost:8080/api/v1/users/me/password \\\n\
            #     -H 'Authorization: Bearer <access_token>' \\\n\
            #     -H 'Content-Type: application/json' \\\n\
            #     -d '{{\"current_password\":\"<password-above>\",\"new_password\":\"<your-new-password>\"}}'\n\
            #\n\
            # The API is LOCKED until you complete these steps.\n\
            # Do NOT use this password directly in API calls — you must login first.\n",
            password
        );
        if let Err(e) = std::fs::write(&password_file, &file_contents) {
            tracing::error!("Failed to write admin password file: {}", e);
            tracing::error!("Admin password could not be persisted. Re-run the server or check file permissions for: {}", password_file.display());
        } else {
            // Restrict file permissions to owner-only (0600) since this file contains credentials
            #[cfg(unix)]
            if let Err(e) =
                std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600))
            {
                tracing::warn!("Failed to set permissions on admin password file: {}", e);
            }
            tracing::info!("Admin password written to: {}", password_file.display());
        }
        tracing::info!(
            "\n\
            ===========================================================\n\
            \n\
              Initial admin user created.\n\
            \n\
              Username:  admin\n\
              Password:  see file {}\n\
            \n\
              Read it:   docker exec artifact-keeper-backend cat {}\n\
            \n\
              The API is LOCKED until you change this password.\n\
              You MUST login first (POST /api/v1/auth/login) to get\n\
              a token, then change the password. See the file for\n\
              full curl examples.\n\
            \n\
            ===========================================================",
            password_file.display(),
            password_file.display(),
        );
        Ok(true)
    } else {
        tracing::info!("Admin user created with password from ADMIN_PASSWORD env var");
        Ok(false)
    }
}

fn is_insecure_default_password(password: &str) -> bool {
    const INSECURE_DEFAULTS: &[&str] = &[
        "admin",
        "password",
        "changeme",
        "admin123",
        "Password1",
        "letmein",
        "welcome",
        "123456",
        "admin1234",
        "default",
    ];
    INSECURE_DEFAULTS
        .iter()
        .any(|d| d.eq_ignore_ascii_case(password))
}

/// Load active plugins from the database.
async fn load_active_plugins(
    db_pool: &sqlx::PgPool,
) -> Result<Vec<artifact_keeper_backend::models::plugin::Plugin>> {
    use artifact_keeper_backend::models::plugin::Plugin;

    let plugins = sqlx::query_as::<_, Plugin>(
        r#"
        SELECT
            id, name, version, display_name, description, author, homepage, license,
            status, plugin_type, source_type,
            source_url, source_ref, wasm_path, manifest,
            capabilities, resource_limits,
            config, config_schema, error_message,
            installed_at, enabled_at, updated_at
        FROM plugins
        WHERE status = 'active' AND wasm_path IS NOT NULL
        ORDER BY name
        "#,
    )
    .fetch_all(db_pool)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    Ok(plugins)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // build_oidc_request_from_values
    // -----------------------------------------------------------------------

    fn env(
        issuer: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
    ) -> OidcEnvVars {
        OidcEnvVars {
            issuer: issuer.map(String::from),
            client_id: client_id.map(String::from),
            client_secret: client_secret.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_bootstrap_request_all_required_fields() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("my-client"),
            Some("my-secret"),
        ))
        .unwrap();

        assert_eq!(req.name, "default");
        assert_eq!(req.issuer_url, "https://idp.example.com");
        assert_eq!(req.client_id, "my-client");
        assert_eq!(req.client_secret, "my-secret");
        assert_eq!(req.is_enabled, Some(true));
        assert_eq!(req.auto_create_users, Some(true));
    }

    #[test]
    fn test_bootstrap_request_missing_issuer() {
        let req = build_oidc_request_from_values(env(None, Some("client"), Some("secret")));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_missing_client_id() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            None,
            Some("secret"),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_missing_client_secret() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            None,
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_issuer() {
        let req = build_oidc_request_from_values(env(Some(""), Some("client"), Some("secret")));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_client_id() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some(""),
            Some("secret"),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_client_secret() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some(""),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_default_groups_claim() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["groups_claim"], "groups");
    }

    #[test]
    fn test_bootstrap_request_custom_groups_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.groups_claim = Some("roles".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["groups_claim"], "roles");
    }

    #[test]
    fn test_bootstrap_request_scopes_parsing() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.scopes = Some("openid email profile offline_access".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(
            req.scopes.unwrap(),
            vec!["openid", "email", "profile", "offline_access"]
        );
    }

    #[test]
    fn test_bootstrap_request_no_scopes() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        assert!(req.scopes.is_none());
    }

    #[test]
    fn test_bootstrap_request_redirect_uri() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.redirect_uri = Some("https://app.example.com/callback".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["redirect_uri"], "https://app.example.com/callback");
    }

    #[test]
    fn test_bootstrap_request_no_redirect_uri() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert!(attr.get("redirect_uri").is_none());
    }

    #[test]
    fn test_bootstrap_request_custom_username_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.username_claim = Some("upn".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["username_claim"], "upn");
    }

    #[test]
    fn test_bootstrap_request_custom_email_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.email_claim = Some("mail".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["email_claim"], "mail");
    }

    #[test]
    fn test_bootstrap_request_all_optional_fields() {
        let req = build_oidc_request_from_values(OidcEnvVars {
            issuer: Some("https://auth.corp.com/realms/main".into()),
            client_id: Some("artifact-keeper".into()),
            client_secret: Some("super-secret-123".into()),
            scopes: Some("openid email profile".into()),
            groups_claim: Some("roles".into()),
            redirect_uri: Some("https://app.corp.com/sso/callback".into()),
            username_claim: Some("samaccountname".into()),
            email_claim: Some("mail".into()),
        })
        .unwrap();

        assert_eq!(req.issuer_url, "https://auth.corp.com/realms/main");
        assert_eq!(req.client_id, "artifact-keeper");
        assert_eq!(req.client_secret, "super-secret-123");
        assert_eq!(req.scopes.unwrap(), vec!["openid", "email", "profile"]);

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["groups_claim"], "roles");
        assert_eq!(attr["redirect_uri"], "https://app.corp.com/sso/callback");
        assert_eq!(attr["username_claim"], "samaccountname");
        assert_eq!(attr["email_claim"], "mail");
    }

    #[test]
    fn test_bootstrap_request_no_optional_claims_in_attr_map() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        let obj = attr.as_object().unwrap();
        // Only groups_claim should be present (it always has a default)
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("groups_claim"));
        assert!(!obj.contains_key("redirect_uri"));
        assert!(!obj.contains_key("username_claim"));
        assert!(!obj.contains_key("email_claim"));
    }

    #[test]
    fn test_insecure_default_admin() {
        assert!(is_insecure_default_password("admin"));
    }

    #[test]
    fn test_insecure_default_case_insensitive() {
        assert!(is_insecure_default_password("ADMIN"));
        assert!(is_insecure_default_password("PASSWORD"));
    }

    #[test]
    fn test_secure_password_not_flagged() {
        assert!(!is_insecure_default_password("xK9#mP2$vL5nQ8"));
    }

    #[test]
    fn test_all_insecure_defaults_detected() {
        let defaults = [
            "admin",
            "password",
            "changeme",
            "admin123",
            "Password1",
            "letmein",
            "welcome",
            "123456",
            "admin1234",
            "default",
        ];
        for pw in defaults {
            assert!(
                is_insecure_default_password(pw),
                "{pw} should be flagged as insecure"
            );
        }
    }

    #[test]
    fn test_insecure_defaults_mixed_case_variations() {
        assert!(is_insecure_default_password("ChAnGeMe"));
        assert!(is_insecure_default_password("LETMEIN"));
        assert!(is_insecure_default_password("Welcome"));
        assert!(is_insecure_default_password("Default"));
        assert!(is_insecure_default_password("ADMIN123"));
        assert!(is_insecure_default_password("password1"));
    }

    #[test]
    fn test_empty_password_not_flagged() {
        assert!(!is_insecure_default_password(""));
    }

    #[test]
    fn test_near_miss_passwords_not_flagged() {
        // Passwords similar to but not matching the insecure list
        assert!(!is_insecure_default_password("admin2"));
        assert!(!is_insecure_default_password("password!"));
        assert!(!is_insecure_default_password("changeme1"));
        assert!(!is_insecure_default_password("1234567"));
        assert!(!is_insecure_default_password("defaults"));
    }

    #[test]
    fn test_long_secure_password_not_flagged() {
        assert!(!is_insecure_default_password("my-secure-p@ssw0rd-2026"));
        assert!(!is_insecure_default_password(
            "correct-horse-battery-staple"
        ));
        assert!(!is_insecure_default_password("Tr0ub4dor&3"));
    }

    #[test]
    fn test_whitespace_password_not_flagged() {
        // Passwords with leading/trailing whitespace are not in the list
        assert!(!is_insecure_default_password(" admin"));
        assert!(!is_insecure_default_password("admin "));
        assert!(!is_insecure_default_password(" password "));
    }

    // -----------------------------------------------------------------------
    // run_server signature check
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_server_accepts_none_token() {
        // Verify that run_server compiles with None (console mode).
        // We cannot actually run it in a unit test because it needs a database,
        // but confirming the function signature accepts Option<CancellationToken>
        // ensures the refactor is correct.
        fn _assert_callable(token: Option<CancellationToken>) {
            drop(run_server(token));
        }
    }

    #[test]
    fn test_run_server_accepts_some_token() {
        // Verify that run_server compiles with Some(token) (Windows Service mode).
        fn _assert_callable_with_token() {
            let token = CancellationToken::new();
            drop(run_server(Some(token)));
        }
    }

    // -----------------------------------------------------------------------
    // AK_ENV_FILE logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_ak_env_file_var_is_checked() {
        // The AK_ENV_FILE environment variable should be read by the startup
        // logic. We verify the env var lookup works (the actual file loading
        // is tested implicitly by dotenvy).
        let saved = std::env::var("AK_ENV_FILE").ok();

        std::env::set_var("AK_ENV_FILE", "/tmp/nonexistent-test-env-file");
        assert_eq!(
            std::env::var("AK_ENV_FILE").unwrap(),
            "/tmp/nonexistent-test-env-file"
        );

        // dotenvy::from_path on a nonexistent file returns Err, which is
        // handled gracefully by the .ok() call in run_server.
        let result = dotenvy::from_path("/tmp/nonexistent-test-env-file");
        assert!(result.is_err());

        // Restore
        if let Some(v) = saved {
            std::env::set_var("AK_ENV_FILE", v);
        } else {
            std::env::remove_var("AK_ENV_FILE");
        }
    }

    // NOTE: windows_service.rs is behind #[cfg(windows)] and cannot be
    // unit-tested on macOS/Linux. It is compile-checked on Windows CI and
    // tested manually via `--install` / `--uninstall` / `--service` flags.
}

