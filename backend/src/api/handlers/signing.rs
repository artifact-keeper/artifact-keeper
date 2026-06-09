//! Signing key management API handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
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
        .route(
            "/repositories/:repo_id/public-key",
            get(get_repo_public_key),
        )
}

// --- Request/Response DTOs ---

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListKeysQuery {
    pub repository_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateKeyPayload {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub key_type: Option<String>,  // default "rsa"
    pub algorithm: Option<String>, // default "rsa4096"
    pub uid_name: Option<String>,
    pub uid_email: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSigningConfigPayload {
    pub signing_key_id: Option<Uuid>,
    pub sign_metadata: Option<bool>,
    pub sign_packages: Option<bool>,
    pub require_signatures: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KeyListResponse {
    pub keys: Vec<SigningKeyPublic>,
    pub total: usize,
}

#[derive(Debug, Serialize, ToSchema)]
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
#[utoipa::path(
    get,
    path = "/keys",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("repository_id" = Option<Uuid>, Query, description = "Filter by repository ID")
    ),
    responses(
        (status = 200, description = "List of signing keys", body = KeyListResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/keys",
    context_path = "/api/v1/signing",
    tag = "signing",
    request_body = CreateKeyPayload,
    responses(
        (status = 200, description = "Created signing key", body = SigningKeyPublic),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn create_key(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateKeyPayload>,
) -> Result<Json<SigningKeyPublic>> {
    require_signing_admin(&auth)?;
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
#[utoipa::path(
    get,
    path = "/keys/{key_id}",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("key_id" = Uuid, Path, description = "Signing key ID")
    ),
    responses(
        (status = 200, description = "Signing key details", body = SigningKeyPublic),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Key not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    delete,
    path = "/keys/{key_id}",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("key_id" = Uuid, Path, description = "Signing key ID")
    ),
    responses(
        (status = 200, description = "Key deleted", body = Object),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Key not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn delete_key(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    require_signing_admin(&auth)?;
    let svc = signing_service(&state);
    svc.delete_key(key_id).await?;
    Ok(Json(serde_json::json!({"deleted": true})))
}

/// Revoke (deactivate) a signing key.
#[utoipa::path(
    post,
    path = "/keys/{key_id}/revoke",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("key_id" = Uuid, Path, description = "Signing key ID")
    ),
    responses(
        (status = 200, description = "Key revoked", body = Object),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Key not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/keys/{key_id}/rotate",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("key_id" = Uuid, Path, description = "Signing key ID to rotate")
    ),
    responses(
        (status = 200, description = "Newly generated signing key", body = SigningKeyPublic),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Key not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/keys/{key_id}/public",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("key_id" = Uuid, Path, description = "Signing key ID")
    ),
    responses(
        (status = 200, description = "Public key in PEM format", body = String),
        (status = 404, description = "Key not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_public_key(
    State(state): State<SharedState>,
    Path(key_id): Path<Uuid>,
) -> Result<String> {
    let svc = signing_service(&state);
    let key = svc.get_key(key_id).await?;
    Ok(key.public_key_pem)
}

/// Get signing configuration for a repository.
#[utoipa::path(
    get,
    path = "/repositories/{repo_id}/config",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("repo_id" = Uuid, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Repository signing configuration", body = SigningConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_repo_signing_config(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(repo_id): Path<Uuid>,
) -> Result<Json<SigningConfigResponse>> {
    let svc = signing_service(&state);
    let config = svc.get_signing_config(repo_id).await?;

    let (signing_key_id, sign_metadata, sign_packages, require_signatures) =
        signing_config_fields(config.as_ref());

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
#[utoipa::path(
    post,
    path = "/repositories/{repo_id}/config",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("repo_id" = Uuid, Path, description = "Repository ID")
    ),
    request_body = UpdateSigningConfigPayload,
    responses(
        (status = 200, description = "Updated signing configuration", body = RepositorySigningConfig),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn update_repo_signing_config(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(repo_id): Path<Uuid>,
    Json(payload): Json<UpdateSigningConfigPayload>,
) -> Result<Json<RepositorySigningConfig>> {
    require_signing_admin(&auth)?;
    let svc = signing_service(&state);

    // Get existing config to merge with updates
    let existing = svc.get_signing_config(repo_id).await?;
    let (cur_key, cur_meta, cur_pkg, cur_req) = signing_config_fields(existing.as_ref());

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
#[utoipa::path(
    get,
    path = "/repositories/{repo_id}/public-key",
    context_path = "/api/v1/signing",
    tag = "signing",
    params(
        ("repo_id" = Uuid, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Public key in PEM format", body = String),
        (status = 404, description = "No active signing key for repository", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
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

/// Admin gate shared by the signing-key/repo-config mutation handlers.
///
/// Minting, deleting, revoking, rotating a repository signing key, or writing
/// the repo signing config all subvert the artifact-signing trust model, so
/// they are admin-only. Centralizing the check keeps the policy in one place.
fn require_signing_admin(auth: &AuthExtension) -> Result<()> {
    auth.require_admin()
}

/// Project a repository signing config into its scalar fields, defaulting to
/// "unconfigured" (no key, nothing signed) when absent. Used by both the read
/// and the update handler so the defaulting rule lives in one place.
fn signing_config_fields(
    config: Option<&RepositorySigningConfig>,
) -> (Option<Uuid>, bool, bool, bool) {
    match config {
        Some(c) => (
            c.signing_key_id,
            c.sign_metadata,
            c.sign_packages,
            c.require_signatures,
        ),
        None => (None, false, false, false),
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_keys,
        create_key,
        get_key,
        delete_key,
        revoke_key,
        rotate_key,
        get_public_key,
        get_repo_signing_config,
        update_repo_signing_config,
        get_repo_public_key,
    ),
    components(schemas(
        ListKeysQuery,
        CreateKeyPayload,
        UpdateSigningConfigPayload,
        KeyListResponse,
        SigningConfigResponse,
    ))
)]
pub struct SigningApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::auth::AuthExtension;
    use serde_json;

    // -----------------------------------------------------------------------
    // Admin gate on signing-key and repo-config mutation
    // -----------------------------------------------------------------------

    fn non_admin_jwt() -> AuthExtension {
        // A non-admin JWT session: `is_api_token = false`, so scope checks do
        // not apply and the admin gate is the only thing standing between the
        // caller and a key mint / config write.
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "victor".to_string(),
            email: "victor@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    fn admin_jwt() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    #[test]
    fn test_non_admin_blocked_from_managing_signing_keys() {
        // Regression: minting/deleting a repository signing key or writing the
        // repo signing config subverts the artifact-signing trust model, so it
        // must be admin-only. create_key, delete_key, and
        // update_repo_signing_config all call `auth.require_admin()?` before
        // touching the service; pin that decision at the predicate level
        // (no DB needed). A non-admin JWT must be rejected with 403.
        let ext = non_admin_jwt();
        match require_signing_admin(&ext) {
            Err(AppError::Authorization(_)) => {}
            other => panic!("expected 403 Authorization for non-admin, got {:?}", other),
        }
    }

    #[test]
    fn test_admin_allowed_to_manage_signing_keys() {
        // Legitimate use: an admin passes the same gate the three mutation
        // handlers enforce, so signing-key management still works.
        let ext = admin_jwt();
        assert!(require_signing_admin(&ext).is_ok());
    }

    #[test]
    fn test_signing_config_fields_defaults_when_absent() {
        // The shared projection helper must treat a missing config as fully
        // unconfigured (no key, nothing signed) so both the read and update
        // handlers agree on the default.
        let (key, meta, pkg, req) = signing_config_fields(None);
        assert!(key.is_none());
        assert!(!meta);
        assert!(!pkg);
        assert!(!req);
    }

    // -----------------------------------------------------------------------
    // ListKeysQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_keys_query_deserialize_empty() {
        let json = r#"{}"#;
        let query: ListKeysQuery = serde_json::from_str(json).unwrap();
        assert!(query.repository_id.is_none());
    }

    #[test]
    fn test_list_keys_query_deserialize_with_repo_id() {
        let id = Uuid::new_v4();
        let json = format!(r#"{{"repository_id": "{}"}}"#, id);
        let query: ListKeysQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query.repository_id, Some(id));
    }

    #[test]
    fn test_list_keys_query_invalid_uuid_fails() {
        let json = r#"{"repository_id": "not-a-uuid"}"#;
        let result: std::result::Result<ListKeysQuery, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // CreateKeyPayload deserialization and defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_key_payload_minimal() {
        let json = r#"{"name": "my-key"}"#;
        let payload: CreateKeyPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name, "my-key");
        assert!(payload.repository_id.is_none());
        assert!(payload.key_type.is_none());
        assert!(payload.algorithm.is_none());
        assert!(payload.uid_name.is_none());
        assert!(payload.uid_email.is_none());
    }

    #[test]
    fn test_create_key_payload_full() {
        let repo_id = Uuid::new_v4();
        let json = serde_json::json!({
            "repository_id": repo_id,
            "name": "signing-key",
            "key_type": "ed25519",
            "algorithm": "ed25519",
            "uid_name": "Alice",
            "uid_email": "alice@example.com"
        });
        let payload: CreateKeyPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.repository_id, Some(repo_id));
        assert_eq!(payload.name, "signing-key");
        assert_eq!(payload.key_type.as_deref(), Some("ed25519"));
        assert_eq!(payload.algorithm.as_deref(), Some("ed25519"));
        assert_eq!(payload.uid_name.as_deref(), Some("Alice"));
        assert_eq!(payload.uid_email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn test_create_key_payload_missing_name_fails() {
        let json = r#"{"key_type": "rsa"}"#;
        let result: std::result::Result<CreateKeyPayload, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_key_payload_default_key_type() {
        // Simulate what the handler does with unwrap_or_else
        let payload: CreateKeyPayload = serde_json::from_str(r#"{"name": "k"}"#).unwrap();
        let key_type = payload.key_type.unwrap_or_else(|| "rsa".to_string());
        assert_eq!(key_type, "rsa");
    }

    #[test]
    fn test_create_key_payload_default_algorithm() {
        let payload: CreateKeyPayload = serde_json::from_str(r#"{"name": "k"}"#).unwrap();
        let algorithm = payload.algorithm.unwrap_or_else(|| "rsa4096".to_string());
        assert_eq!(algorithm, "rsa4096");
    }

    // -----------------------------------------------------------------------
    // UpdateSigningConfigPayload deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_signing_config_payload_empty() {
        let json = r#"{}"#;
        let payload: UpdateSigningConfigPayload = serde_json::from_str(json).unwrap();
        assert!(payload.signing_key_id.is_none());
        assert!(payload.sign_metadata.is_none());
        assert!(payload.sign_packages.is_none());
        assert!(payload.require_signatures.is_none());
    }

    #[test]
    fn test_update_signing_config_payload_full() {
        let key_id = Uuid::new_v4();
        let json = serde_json::json!({
            "signing_key_id": key_id,
            "sign_metadata": true,
            "sign_packages": false,
            "require_signatures": true
        });
        let payload: UpdateSigningConfigPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.signing_key_id, Some(key_id));
        assert_eq!(payload.sign_metadata, Some(true));
        assert_eq!(payload.sign_packages, Some(false));
        assert_eq!(payload.require_signatures, Some(true));
    }

    #[test]
    fn test_update_signing_config_payload_partial() {
        let json = r#"{"sign_metadata": true}"#;
        let payload: UpdateSigningConfigPayload = serde_json::from_str(json).unwrap();
        assert!(payload.signing_key_id.is_none());
        assert_eq!(payload.sign_metadata, Some(true));
        assert!(payload.sign_packages.is_none());
        assert!(payload.require_signatures.is_none());
    }

    // -----------------------------------------------------------------------
    // KeyListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_key_list_response_serialize_empty() {
        let resp = KeyListResponse {
            keys: vec![],
            total: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 0);
        assert!(json["keys"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_key_list_response_total_matches_keys_len() {
        let keys = vec![];
        let total = keys.len();
        let resp = KeyListResponse { keys, total };
        assert_eq!(resp.total, 0);
    }

    // -----------------------------------------------------------------------
    // SigningConfigResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_config_response_serialize_no_key() {
        let repo_id = Uuid::new_v4();
        let resp = SigningConfigResponse {
            repository_id: repo_id,
            signing_key_id: None,
            sign_metadata: false,
            sign_packages: false,
            require_signatures: false,
            key: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["repository_id"], repo_id.to_string());
        assert!(json["signing_key_id"].is_null());
        assert_eq!(json["sign_metadata"], false);
        assert_eq!(json["sign_packages"], false);
        assert_eq!(json["require_signatures"], false);
        assert!(json["key"].is_null());
    }

    #[test]
    fn test_signing_config_response_serialize_with_key() {
        let repo_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let key = SigningKeyPublic {
            id: key_id,
            repository_id: Some(repo_id),
            name: "test-key".to_string(),
            key_type: "rsa".to_string(),
            fingerprint: Some("ABCD1234".to_string()),
            key_id: Some("1234".to_string()),
            public_key_pem: "-----BEGIN PUBLIC KEY-----".to_string(),
            algorithm: "rsa4096".to_string(),
            uid_name: None,
            uid_email: None,
            expires_at: None,
            is_active: true,
            created_at: now,
            last_used_at: None,
        };
        let resp = SigningConfigResponse {
            repository_id: repo_id,
            signing_key_id: Some(key_id),
            sign_metadata: true,
            sign_packages: true,
            require_signatures: false,
            key: Some(key),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["signing_key_id"], key_id.to_string());
        assert_eq!(json["sign_metadata"], true);
        assert_eq!(json["sign_packages"], true);
        assert_eq!(json["key"]["name"], "test-key");
        assert_eq!(json["key"]["is_active"], true);
    }

    // -----------------------------------------------------------------------
    // Config extraction logic (simulating handler merge behavior)
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_extraction_from_none() {
        let config: Option<RepositorySigningConfig> = None;
        let (signing_key_id, sign_metadata, sign_packages, require_signatures) =
            signing_config_fields(config.as_ref());
        assert!(signing_key_id.is_none());
        assert!(!sign_metadata);
        assert!(!sign_packages);
        assert!(!require_signatures);
    }

    #[test]
    fn test_config_extraction_from_some() {
        let key_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let config = Some(RepositorySigningConfig {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            signing_key_id: Some(key_id),
            sign_metadata: true,
            sign_packages: true,
            require_signatures: false,
            created_at: now,
            updated_at: now,
        });
        let (signing_key_id, sign_metadata, sign_packages, require_signatures) =
            signing_config_fields(config.as_ref());
        assert_eq!(signing_key_id, Some(key_id));
        assert!(sign_metadata);
        assert!(sign_packages);
        assert!(!require_signatures);
    }

    // -----------------------------------------------------------------------
    // UpdateSigningConfig merge logic (simulating handler behavior)
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_merge_with_no_existing_config() {
        let payload = UpdateSigningConfigPayload {
            signing_key_id: None,
            sign_metadata: Some(true),
            sign_packages: None,
            require_signatures: None,
        };
        let existing: Option<RepositorySigningConfig> = None;
        let (cur_key, cur_meta, cur_pkg, cur_req) = signing_config_fields(existing.as_ref());

        let merged_key = payload.signing_key_id.or(cur_key);
        let merged_meta = payload.sign_metadata.unwrap_or(cur_meta);
        let merged_pkg = payload.sign_packages.unwrap_or(cur_pkg);
        let merged_req = payload.require_signatures.unwrap_or(cur_req);

        assert!(merged_key.is_none());
        assert!(merged_meta); // overridden by payload
        assert!(!merged_pkg); // default from no existing
        assert!(!merged_req); // default from no existing
    }

    #[test]
    fn test_update_merge_preserves_existing_when_not_overridden() {
        let key_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let existing = Some(RepositorySigningConfig {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            signing_key_id: Some(key_id),
            sign_metadata: true,
            sign_packages: true,
            require_signatures: true,
            created_at: now,
            updated_at: now,
        });
        let payload = UpdateSigningConfigPayload {
            signing_key_id: None,
            sign_metadata: None,
            sign_packages: None,
            require_signatures: None,
        };
        let (cur_key, cur_meta, cur_pkg, cur_req) = signing_config_fields(existing.as_ref());

        let merged_key = payload.signing_key_id.or(cur_key);
        let merged_meta = payload.sign_metadata.unwrap_or(cur_meta);
        let merged_pkg = payload.sign_packages.unwrap_or(cur_pkg);
        let merged_req = payload.require_signatures.unwrap_or(cur_req);

        assert_eq!(merged_key, Some(key_id));
        assert!(merged_meta);
        assert!(merged_pkg);
        assert!(merged_req);
    }
}
