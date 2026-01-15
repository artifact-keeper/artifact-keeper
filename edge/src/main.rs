//! Artifact Keeper Edge Node - Distributed caching node.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cache;
mod sync;

#[derive(Clone)]
pub struct EdgeState {
    pub primary_url: String,
    pub api_key: String,
    pub cache: Arc<cache::ArtifactCache>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "artifact_keeper_edge=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let primary_url =
        std::env::var("PRIMARY_URL").expect("PRIMARY_URL must be set");
    let api_key = std::env::var("EDGE_API_KEY").expect("EDGE_API_KEY must be set");
    let bind_address =
        std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let cache_size: usize = std::env::var("CACHE_SIZE_MB")
        .unwrap_or_else(|_| "1024".to_string())
        .parse()
        .unwrap_or(1024);

    tracing::info!("Starting Artifact Keeper Edge Node");
    tracing::info!("Primary registry: {}", primary_url);

    // Create cache
    let cache = Arc::new(cache::ArtifactCache::new(cache_size));

    // Create state
    let state = EdgeState {
        primary_url,
        api_key,
        cache,
    };

    // Start heartbeat task
    let heartbeat_state = state.clone();
    tokio::spawn(async move {
        sync::heartbeat_loop(heartbeat_state).await;
    });

    // Build router
    let app = Router::new()
        // TODO: Add artifact proxy routes
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let addr: SocketAddr = bind_address.parse()?;
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
