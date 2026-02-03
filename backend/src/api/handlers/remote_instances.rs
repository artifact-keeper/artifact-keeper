//! Remote-instance CRUD and proxy handlers.
//!
//! Allows the frontend to manage remote Artifact Keeper instances whose API
//! keys are stored encrypted on the backend, and to proxy requests through
//! the backend so that API keys never leave the server.

use axum::{
    body::Body,
    extract::{Extension, Path, State},
    response::Response,
    routing::{delete, get},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::remote_instance_service::{RemoteInstanceResponse, RemoteInstanceService};

/// Build the router for `/api/v1/instances`.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_instances).post(create_instance))
        .route("/:id", delete(delete_instance))
        // Wildcard proxy: forward any sub-path to the remote instance
        .route(
            "/:id/proxy/*path",
            get(proxy_get)
                .post(proxy_post)
                .put(proxy_put)
                .delete(proxy_delete),
        )
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

async fn list_instances(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<RemoteInstanceResponse>>> {
    let instances = RemoteInstanceService::list(&state.db, auth.user_id).await?;
    Ok(Json(instances))
}

#[derive(Debug, Deserialize)]
struct CreateInstanceRequest {
    name: String,
    url: String,
    api_key: String,
}

async fn create_instance(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateInstanceRequest>,
) -> Result<Json<RemoteInstanceResponse>> {
    let instance = RemoteInstanceService::create(
        &state.db,
        auth.user_id,
        &req.name,
        &req.url,
        &req.api_key,
    )
    .await?;
    Ok(Json(instance))
}

async fn delete_instance(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    RemoteInstanceService::delete(&state.db, id, auth.user_id).await
}

// ---------------------------------------------------------------------------
// Proxy helpers
// ---------------------------------------------------------------------------

/// Build the full target URL on the remote instance.
fn build_target_url(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path)
}

/// Convert a reqwest response into an axum response, forwarding status and
/// content-type.
async fn reqwest_to_axum(resp: reqwest::Response) -> Result<Response> {
    let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = resp
        .headers()
        .get("content-type")
        .cloned();
    let body = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read proxy response: {e}")))?;

    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header("content-type", ct);
    }
    builder
        .body(Body::from(body))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))
}

// ---------------------------------------------------------------------------
// Proxy handlers
// ---------------------------------------------------------------------------

async fn proxy_get(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, path)): Path<(Uuid, String)>,
) -> Result<Response> {
    let (url, api_key) =
        RemoteInstanceService::get_decrypted(&state.db, id, auth.user_id).await?;
    let target = build_target_url(&url, &path);

    let resp = reqwest::Client::new()
        .get(&target)
        .bearer_auth(&api_key)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Proxy request failed: {e}")))?;

    reqwest_to_axum(resp).await
}

async fn proxy_post(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, path)): Path<(Uuid, String)>,
    body: axum::body::Bytes,
) -> Result<Response> {
    let (url, api_key) =
        RemoteInstanceService::get_decrypted(&state.db, id, auth.user_id).await?;
    let target = build_target_url(&url, &path);

    let resp = reqwest::Client::new()
        .post(&target)
        .bearer_auth(&api_key)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Proxy request failed: {e}")))?;

    reqwest_to_axum(resp).await
}

async fn proxy_put(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, path)): Path<(Uuid, String)>,
    body: axum::body::Bytes,
) -> Result<Response> {
    let (url, api_key) =
        RemoteInstanceService::get_decrypted(&state.db, id, auth.user_id).await?;
    let target = build_target_url(&url, &path);

    let resp = reqwest::Client::new()
        .put(&target)
        .bearer_auth(&api_key)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Proxy request failed: {e}")))?;

    reqwest_to_axum(resp).await
}

async fn proxy_delete(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, path)): Path<(Uuid, String)>,
) -> Result<Response> {
    let (url, api_key) =
        RemoteInstanceService::get_decrypted(&state.db, id, auth.user_id).await?;
    let target = build_target_url(&url, &path);

    let resp = reqwest::Client::new()
        .delete(&target)
        .bearer_auth(&api_key)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Proxy request failed: {e}")))?;

    reqwest_to_axum(resp).await
}
