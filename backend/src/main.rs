//! Artifact Keeper - Main Entry Point

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::http::{header, Method};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use rand::Rng;

use artifact_keeper_backend::{
    api,
    config::Config,
    db,
    error::Result,
    services::{
        auth_service::AuthService,
        meili_service::MeiliService,
        metrics_service,
        plugin_registry::PluginRegistry,
        scan_config_service::ScanConfigService,
        scan_result_service::ScanResultService,
        scanner_service::{AdvisoryClient, ScannerService},
        scheduler_service,
        wasm_plugin_service::WasmPluginService,
    },
};

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "artifact_keeper_backend=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Starting Artifact Keeper");

    // Connect to database
    let db_pool = db::create_pool(&config.database_url).await?;
    tracing::info!("Connected to database");

    // Run migrations
    sqlx::migrate!("./migrations").run(&db_pool).await?;
    tracing::info!("Database migrations complete");

    // Provision admin user on first boot; returns true when setup lock is needed
    let setup_required = provision_admin_user(&db_pool, &config.storage_path).await?;

    // Initialize peer identity for mesh networking
    let peer_id = init_peer_identity(&db_pool, &config).await?;
    tracing::info!("Peer identity: {} ({})", config.peer_instance_name, peer_id);

    // Initialize WASM plugin system (T068)
    let plugins_dir =
        PathBuf::from(std::env::var("PLUGINS_DIR").unwrap_or_else(|_| "./plugins".to_string()));
    let (plugin_registry, wasm_plugin_service) =
        initialize_wasm_plugins(db_pool.clone(), plugins_dir).await?;

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
        config.storage_path.clone(),
        config.scan_workspace_path.clone(),
        config.openscap_url.clone(),
        config.openscap_profile.clone(),
    ));

    // Initialize Meilisearch (optional, graceful fallback)
    let meili_service = match (&config.meilisearch_url, &config.meilisearch_api_key) {
        (Some(url), Some(api_key)) => {
            tracing::info!("Initializing Meilisearch at {}", url);
            let service = Arc::new(MeiliService::new(url, api_key));
            match service.configure_indexes().await {
                Ok(()) => {
                    tracing::info!("Meilisearch indexes configured");
                    // Spawn background reindex if the index is empty
                    let svc = service.clone();
                    let pool = db_pool.clone();
                    tokio::spawn(async move {
                        match svc.is_index_empty().await {
                            Ok(true) => {
                                tracing::info!(
                                    "Meilisearch index is empty, starting background reindex"
                                );
                                if let Err(e) = svc.full_reindex(&pool).await {
                                    tracing::warn!("Background reindex failed: {}", e);
                                }
                            }
                            Ok(false) => {
                                tracing::info!(
                                    "Meilisearch index already populated, skipping reindex"
                                );
                            }
                            Err(e) => {
                                tracing::warn!("Failed to check Meilisearch index status: {}", e);
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
        _ => {
            tracing::info!("Meilisearch not configured, search indexing disabled");
            None
        }
    };

    // Initialize Prometheus metrics recorder
    let metrics_handle = metrics_service::init_metrics();
    tracing::info!("Prometheus metrics recorder initialized");

    // Create application state with WASM plugin support
    let mut app_state = api::AppState::with_wasm_plugins(
        config.clone(),
        db_pool.clone(),
        plugin_registry,
        wasm_plugin_service,
    );
    app_state.set_scanner_service(scanner_service);
    if let Some(meili) = meili_service {
        app_state.set_meili_service(meili);
    }
    app_state.set_metrics_handle(metrics_handle);
    app_state
        .setup_required
        .store(setup_required, std::sync::atomic::Ordering::Relaxed);
    let state = Arc::new(app_state);

    // Spawn background schedulers (metrics snapshots, health monitor, lifecycle)
    scheduler_service::spawn_all(db_pool, config.clone());

    // Build router
    let app = Router::new()
        .merge(api::routes::create_router(state))
        .layer(axum::middleware::from_fn(
            artifact_keeper_backend::services::metrics_service::metrics_middleware,
        ))
        .layer({
            // In production the frontend is served from the same origin, so
            // credentials + same-origin work without an explicit allow-origin.
            // In development the Next.js dev server runs on a different port,
            // so we must whitelist that origin and enable credentials.
            if std::env::var("ENVIRONMENT").unwrap_or_default() == "development" {
                let origins: Vec<_> = std::env::var("CORS_ORIGINS")
                    .unwrap_or_else(|_| "http://localhost:3000".into())
                    .split(',')
                    .map(|s| s.trim().parse().expect("invalid CORS origin"))
                    .collect();
                CorsLayer::new()
                    .allow_origin(AllowOrigin::list(origins))
                    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS])
                    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT, header::COOKIE])
                    .allow_credentials(true)
            } else {
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any)
            }
        })
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr: SocketAddr = config.bind_address.parse()?;
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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

/// Provision the initial admin user on first boot and determine setup mode.
///
/// Returns `true` when the API should be locked until the admin changes
/// the default password (i.e. `must_change_password` is still set and no
/// explicit `ADMIN_PASSWORD` env var was provided).
async fn provision_admin_user(db: &sqlx::PgPool, storage_path: &str) -> Result<bool> {
    use std::path::Path;

    let password_file = Path::new(storage_path).join("admin.password");

    // Check if an admin user already exists
    let admin_row: Option<(bool,)> = sqlx::query_as(
        "SELECT must_change_password FROM users WHERE is_admin = true LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    if let Some((must_change,)) = admin_row {
        // Admin already exists — determine if setup lock is needed
        if must_change {
            tracing::warn!(
                "Admin user has not changed default password. API is locked until password is changed."
            );
            // Ensure the password file still exists for the user to read
            if password_file.exists() {
                tracing::info!(
                    "Admin password file: {}",
                    password_file.display()
                );
            }
            return Ok(true);
        }
        return Ok(false);
    }

    // No admin exists — create one
    let (password, must_change) = match std::env::var("ADMIN_PASSWORD") {
        Ok(p) if !p.is_empty() => (p, false),
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

    let password_hash = AuthService::hash_password(&password)?;

    sqlx::query(
        r#"
        INSERT INTO users (username, email, password_hash, is_admin, must_change_password)
        VALUES ('admin', 'admin@localhost', $1, true, $2)
        ON CONFLICT (username) DO NOTHING
        "#,
    )
    .bind(&password_hash)
    .bind(must_change)
    .execute(db)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    if must_change {
        // Write password to a file so users can retrieve it
        if let Err(e) = std::fs::write(&password_file, format!("{}\n", password)) {
            tracing::error!("Failed to write admin password file: {}", e);
            // Fall back to logging the password directly
            tracing::info!("Generated admin password: {}", password);
        } else {
            tracing::info!(
                "Admin password written to: {}", password_file.display()
            );
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
              Login and call POST /api/v1/users/<id>/password to unlock.\n\
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
