//! Artifact Keeper - Main Entry Point

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{header, Method};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
        scan_config_service::ScanConfigService,
        scan_result_service::ScanResultService,
        scanner_service::{AdvisoryClient, ScannerService},
        scheduler_service,
        wasm_plugin_service::WasmPluginService,
    },
};
use tonic::transport::Server as TonicServer;

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
        .layer(TraceLayer::new_for_http());

    // Start HTTP server
    let addr: SocketAddr = config.bind_address.parse()?;
    tracing::info!("HTTP server listening on {}", addr);

    // Start gRPC server on a separate port
    let grpc_port = std::env::var("GRPC_PORT")
        .unwrap_or_else(|_| "9090".to_string())
        .parse::<u16>()
        .unwrap_or(9090);
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", grpc_port).parse()?;

    let grpc_db = db::create_pool(&config.database_url).await?;
    let sbom_server = SbomGrpcServer::new(grpc_db.clone());
    let cve_history_server = CveHistoryGrpcServer::new(grpc_db.clone());
    let security_policy_server = SecurityPolicyGrpcServer::new(grpc_db);

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
    tokio::spawn(async move {
        tracing::info!("gRPC server listening on {}", grpc_addr);
        if let Err(e) = TonicServer::builder()
            .add_service(reflection_service)
            .add_service(SbomServiceServer::with_interceptor(
                sbom_server,
                move |req| grpc_auth_sbom.intercept(req),
            ))
            .add_service(CveHistoryServiceServer::with_interceptor(
                cve_history_server,
                move |req| grpc_auth_cve.intercept(req),
            ))
            .add_service(SecurityPolicyServiceServer::with_interceptor(
                security_policy_server,
                move |req| grpc_auth_policy.intercept(req),
            ))
            .serve(grpc_addr)
            .await
        {
            tracing::error!("gRPC server error: {}", e);
        }
    });

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
    let admin_row: Option<(bool,)> =
        sqlx::query_as("SELECT must_change_password FROM users WHERE is_admin = true LIMIT 1")
            .fetch_optional(db)
            .await
            .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

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

        // Admin already exists — determine if setup lock is needed
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
            // Fall back to logging the password directly
            tracing::info!("Generated admin password: {}", password);
        } else {
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
