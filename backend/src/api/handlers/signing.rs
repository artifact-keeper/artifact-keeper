//! Signing key management API handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::signing_key::{RepositorySigningConfig, SigningKeyPublic};
use crate::services::signing_service::{CreateKeyRequest, SigningService};

/// Create signing key management routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        // Key CRUD
        .route("/keys", get(list_keys).post(create_key))
        .route("/keys/:key_id", get(get_key).delete(delete_key))
        .route("/keys/:key_id/revoke", post(revoke_key))
        .route("/keys/:key_id/rotate", post(rotate_key))
        .route("/keys/:key_id/public", get(get_public_key))
        // Repository signing config
        .route(
            "/repositories/:repo_id/config",
            get(get_repo_signing_config).post(update_repo_signing_config),
        )
        .route("/repositories/:repo_id/public-key", get(get_repo_public_key))
}

// --- Request/Response DTOs ---

#[derive(Debug, Deserialize)]
pub struct ListKeysQuery {
    pub repository_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyPayload {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub key_type: Option<String>,  // default "rsa"
    pub algorithm: Option<String>, // default "rsa4096"
    pub uid_name: Option<String>,
    pub uid_email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSigningConfigPayload {
    pub signing_key_id: Option<Uuid>,
    pub sign_metadata: Option<bool>,
    pub sign_packages: Option<bool>,
    pub require_signatures: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct KeyListResponse {
    pub keys: Vec<SigningKeyPublic>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct SigningConfigResponse {
    pub repository_id: Uuid,
    pub signing_key_id: Option<Uuid>,
    pub sign_metadata: bool,
    pub sign_packages: bool,
    pub require_signatures: bool,
    pub key: Option<SigningKeyPublic>,
}

// --- Handlers ---

/// List all signing keys, optionally filtered by repository.
async fn list_keys(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Query(query): Query<ListKeysQuery>,
) -> Result<Json<KeyListResponse>> {
    let svc = signing_service(&state);
    let keys = svc.list_keys(query.repository_id).await?;
    let total = keys.len();
    Ok(Json(KeyListResponse { keys, total }))
}

/// Create a new signing key.
async fn create_key(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateKeyPayload>,
) -> Result<Json<SigningKeyPublic>> {
    let svc = signing_service(&state);
    let key = svc
        .create_key(CreateKeyRequest {
            repository_id: payload.repository_id,
            name: payload.name,
            key_type: payload.key_type.unwrap_or_else(|| "rsa".to_string()),
            algorithm: payload.algorithm.unwrap_or_else(|| "rsa4096".to_string()),
            uid_name: payload.uid_name,
            uid_email: payload.uid_email,
            created_by: Some(auth.user_id),
        })
        .await?;
    Ok(Json(key))
}

/// Get a signing key by ID.
async fn get_key(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<SigningKeyPublic>> {
    let svc = signing_service(&state);
    let key = svc.get_key(key_id).await?;
    Ok(Json(key))
}

/// Delete a signing key.
async fn delete_key(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let svc = signing_service(&state);
    svc.delete_key(key_id).await?;
    Ok(Json(serde_json::json!({"deleted": true})))
}

/// Revoke (deactivate) a signing key.
async fn revoke_key(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let svc = signing_service(&state);
    svc.revoke_key(key_id, Some(auth.user_id)).await?;
    Ok(Json(serde_json::json!({"revoked": true})))
}

/// Rotate a signing key — generates new key, deactivates old one.
async fn rotate_key(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<SigningKeyPublic>> {
    let svc = signing_service(&state);
    let new_key = svc.rotate_key(key_id, Some(auth.user_id)).await?;
    Ok(Json(new_key))
}

/// Get the public key in PEM format (for client import).
async fn get_public_key(
    State(state): State<SharedState>,
    Path(key_id): Path<Uuid>,
) -> Result<String> {
    let svc = signing_service(&state);
    let key = svc.get_key(key_id).await?;
    Ok(key.public_key_pem)
}

/// Get signing configuration for a repository.
async fn get_repo_signing_config(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(repo_id): Path<Uuid>,
) -> Result<Json<SigningConfigResponse>> {
    let svc = signing_service(&state);
    let config = svc.get_signing_config(repo_id).await?;

    let (signing_key_id, sign_metadata, sign_packages, require_signatures) =
        if let Some(ref c) = config {
            (
                c.signing_key_id,
                c.sign_metadata,
                c.sign_packages,
                c.require_signatures,
            )
        } else {
            (None, false, false, false)
        };

    let key = if let Some(kid) = signing_key_id {
        Some(svc.get_key(kid).await?)
    } else {
        None
    };

    Ok(Json(SigningConfigResponse {
        repository_id: repo_id,
        signing_key_id,
        sign_metadata,
        sign_packages,
        require_signatures,
        key,
    }))
}

/// Update signing configuration for a repository.
async fn update_repo_signing_config(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(repo_id): Path<Uuid>,
    Json(payload): Json<UpdateSigningConfigPayload>,
) -> Result<Json<RepositorySigningConfig>> {
    let svc = signing_service(&state);

    // Get existing config to merge with updates
    let existing = svc.get_signing_config(repo_id).await?;
    let (cur_key, cur_meta, cur_pkg, cur_req) = if let Some(ref c) = existing {
        (
            c.signing_key_id,
            c.sign_metadata,
            c.sign_packages,
            c.require_signatures,
        )
    } else {
        (None, false, false, false)
    };

    let config = svc
        .update_signing_config(
            repo_id,
            payload.signing_key_id.or(cur_key),
            payload.sign_metadata.unwrap_or(cur_meta),
            payload.sign_packages.unwrap_or(cur_pkg),
            payload.require_signatures.unwrap_or(cur_req),
        )
        .await?;
    Ok(Json(config))
}

/// Get the public key for a repository (convenience endpoint).
async fn get_repo_public_key(
    State(state): State<SharedState>,
    Path(repo_id): Path<Uuid>,
) -> Result<String> {
    let svc = signing_service(&state);
    let key = svc.get_repo_public_key(repo_id).await?;
    key.ok_or_else(|| {
        AppError::NotFound("No active signing key configured for this repository".to_string())
    })
}

fn signing_service(state: &SharedState) -> SigningService {
    SigningService::new(state.db.clone(), &state.config.jwt_secret)
}
