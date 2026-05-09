//! General (Generic) repository download handler.
//!
//! Provides a native-protocol style download endpoint for Generic format
//! repositories, matching the URL pattern used by other format handlers.
//!
//! Routes are mounted at `/general/{repo_key}/...`:
//!   GET  /general/{repo_key}/*path — Download artifact

use axum::Router;

use crate::api::handlers::repositories::download_artifact;
use crate::api::SharedState;

pub fn router() -> Router<SharedState> {
    Router::new().route("/:repo_key/*path", axum::routing::get(download_artifact))
}
