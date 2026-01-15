//! API module - HTTP handlers and middleware.

pub mod handlers;
pub mod middleware;
pub mod routes;

use crate::config::Config;
use sqlx::PgPool;
use std::sync::Arc;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
}

impl AppState {
    pub fn new(config: Config, db: PgPool) -> Self {
        Self { config, db }
    }
}

pub type SharedState = Arc<AppState>;
