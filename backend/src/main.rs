//! Artifact Keeper - Main Entry Point

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use artifact_keeper_backend::{
    api, config::Config, db, error::Result,
    services::{plugin_registry::PluginRegistry, wasm_plugin_service::WasmPluginService},
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

    // Initialize WASM plugin system (T068)
    let plugins_dir = PathBuf::from(
        std::env::var("PLUGINS_DIR").unwrap_or_else(|_| "./plugins".to_string()),
    );
    let (plugin_registry, wasm_plugin_service) =
        initialize_wasm_plugins(db_pool.clone(), plugins_dir).await?;

    // Create application state with WASM plugin support
    let state = Arc::new(api::AppState::with_wasm_plugins(
        config.clone(),
        db_pool,
        plugin_registry,
        wasm_plugin_service,
    ));

    // Build router
    let app = Router::new()
        .merge(api::routes::create_router(state))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
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
    let registry = Arc::new(
        PluginRegistry::new().map_err(|e| artifact_keeper_backend::error::AppError::Internal(
            format!("Failed to create plugin registry: {}", e),
        ))?,
    );

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
            match wasm_service.activate_plugin_at_startup(&plugin, std::path::Path::new(wasm_path)).await {
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
