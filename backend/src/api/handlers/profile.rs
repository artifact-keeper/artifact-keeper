//! Profile handlers — endpoints scoped to the authenticated user.

use axum::{
    extract::{Extension, Path, State},
    routing::{delete, get},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::auth_service::AuthService;

use super::users::{ApiTokenCreatedResponse, ApiTokenListResponse, ApiTokenResponse};

/// Create profile routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/access-tokens",
            get(list_access_tokens).post(create_access_token),
        )
        .route("/access-tokens/:token_id", delete(revoke_access_token))
}

#[derive(Debug, Deserialize)]
pub struct CreateAccessTokenRequest {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<i64>,
}

/// List the authenticated user's API tokens.
async fn list_access_tokens(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<ApiTokenListResponse>> {
    let tokens = sqlx::query!(
        r#"
        SELECT id, name, token_prefix, scopes, expires_at, last_used_at, created_at
        FROM api_tokens
        WHERE user_id = $1 AND revoked_at IS NULL
        ORDER BY created_at DESC
        "#,
        auth.user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    let items = tokens
        .into_iter()
        .map(|t| ApiTokenResponse {
            id: t.id,
            name: t.name,
            token_prefix: t.token_prefix,
            scopes: t.scopes,
            expires_at: t.expires_at,
            last_used_at: t.last_used_at,
            created_at: t.created_at,
        })
        .collect();

    Ok(Json(ApiTokenListResponse { items }))
}

/// Create an API token for the authenticated user.
async fn create_access_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateAccessTokenRequest>,
) -> Result<Json<ApiTokenCreatedResponse>> {
    let scopes = payload.scopes.unwrap_or_else(|| vec!["read".to_string()]);

    // Refuse admin-class scopes from non-admin callers. Without this
    // check, any logged-in user can mint a token with `*` or `admin`
    // and bypass every scope-only authorization gate via
    // `scopes_grant_access` (which short-circuits on those two values).
    // Other admin-only scopes (`delete:artifacts`, `delete:repositories`,
    // `write:users`) cover destructive/admin-class operations — see
    // `token_service::ADMIN_ONLY_SCOPES`.
    crate::services::token_service::enforce_admin_only_scopes(&scopes, auth.is_admin)
        .map_err(crate::error::AppError::Authorization)?;

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (token, token_id) = auth_service
        .generate_api_token(auth.user_id, &payload.name, scopes, payload.expires_in_days)
        .await?;

    Ok(Json(ApiTokenCreatedResponse {
        id: token_id,
        name: payload.name,
        token,
    }))
}

/// Revoke an API token belonging to the authenticated user.
async fn revoke_access_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(token_id): Path<Uuid>,
) -> Result<()> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    auth_service
        .revoke_api_token(token_id, auth.user_id)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::auth::AuthExtension;

    // ── CreateAccessTokenRequest deserialization tests ───────────────

    #[test]
    fn test_create_access_token_request_full() {
        let json = r#"{
            "name": "ci-token",
            "scopes": ["read", "write", "admin"],
            "expires_in_days": 90
        }"#;
        let req: CreateAccessTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "ci-token");
        assert_eq!(
            req.scopes,
            Some(vec![
                "read".to_string(),
                "write".to_string(),
                "admin".to_string()
            ])
        );
        assert_eq!(req.expires_in_days, Some(90));
    }

    #[test]
    fn test_create_access_token_request_minimal() {
        let json = r#"{"name": "my-token"}"#;
        let req: CreateAccessTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "my-token");
        assert!(req.scopes.is_none());
        assert!(req.expires_in_days.is_none());
    }

    #[test]
    fn test_create_access_token_request_missing_name_fails() {
        let json = r#"{"scopes": ["read"]}"#;
        let result: std::result::Result<CreateAccessTokenRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_access_token_request_empty_scopes() {
        let json = r#"{"name": "token", "scopes": []}"#;
        let req: CreateAccessTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.scopes, Some(vec![]));
    }

    #[test]
    fn test_create_access_token_request_null_scopes() {
        let json = r#"{"name": "token", "scopes": null}"#;
        let req: CreateAccessTokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.scopes.is_none());
    }

    #[test]
    fn test_create_access_token_request_expires_in_days_zero() {
        let json = r#"{"name": "ephemeral", "expires_in_days": 0}"#;
        let req: CreateAccessTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.expires_in_days, Some(0));
    }

    #[test]
    fn test_create_access_token_request_expires_in_days_large() {
        let json = r#"{"name": "long-lived", "expires_in_days": 365}"#;
        let req: CreateAccessTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.expires_in_days, Some(365));
    }

    // ── Default scopes logic tests ──────────────────────────────────

    #[test]
    fn test_default_scopes_when_none() {
        let payload = CreateAccessTokenRequest {
            name: "test".to_string(),
            scopes: None,
            expires_in_days: None,
        };
        let scopes = payload.scopes.unwrap_or_else(|| vec!["read".to_string()]);
        assert_eq!(scopes, vec!["read".to_string()]);
    }

    #[test]
    fn test_provided_scopes_preserved() {
        let payload = CreateAccessTokenRequest {
            name: "test".to_string(),
            scopes: Some(vec!["read".to_string(), "write".to_string()]),
            expires_in_days: None,
        };
        let scopes = payload.scopes.unwrap_or_else(|| vec!["read".to_string()]);
        assert_eq!(scopes, vec!["read".to_string(), "write".to_string()]);
    }

    // ── AuthExtension construction tests ────────────────────────────

    #[test]
    fn test_auth_extension_admin() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        };
        assert!(auth.is_admin);
        assert!(!auth.is_api_token);
    }

    #[test]
    fn test_auth_extension_api_token_user() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "ci-bot".to_string(),
            email: "ci@example.com".to_string(),
            is_admin: false,
            is_api_token: true,
            is_service_account: false,
            scopes: Some(vec!["read".to_string()]),
            allowed_repo_ids: None,
        };
        assert!(!auth.is_admin);
        assert!(auth.is_api_token);
        assert_eq!(auth.scopes.as_ref().unwrap().len(), 1);
    }

    // ── ApiTokenResponse / ApiTokenListResponse tests ───────────────

    #[test]
    fn test_api_token_response_serialization() {
        let now = chrono::Utc::now();
        let resp = ApiTokenResponse {
            id: Uuid::new_v4(),
            name: "deploy-key".to_string(),
            token_prefix: "ak_".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            expires_at: Some(now + chrono::Duration::days(30)),
            last_used_at: Some(now),
            created_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "deploy-key");
        assert_eq!(json["token_prefix"], "ak_");
        assert_eq!(json["scopes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_api_token_list_response_serialization() {
        let resp = ApiTokenListResponse { items: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_api_token_created_response_serialization() {
        let resp = ApiTokenCreatedResponse {
            id: Uuid::new_v4(),
            name: "new-token".to_string(),
            token: "ak_secret_token_value".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "new-token");
        assert_eq!(json["token"], "ak_secret_token_value");
    }
}
