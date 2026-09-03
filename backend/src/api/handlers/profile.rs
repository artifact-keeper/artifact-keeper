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
use crate::services::audit_service::{
    api_token_audit_entry, api_token_mint_audit_entry, audit_fire_and_forget, AuditAction,
};
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
    // Default omitted scopes to the canonical read scope. Bare `read` is not
    // in `ALLOWED_SCOPES` (it granted nothing under exact-match `has_scope`
    // and is now rejected by the mint-primitive vocabulary backstop, #2996),
    // so the default is the fully-qualified `read:artifacts`.
    let scopes = payload
        .scopes
        .unwrap_or_else(|| vec!["read:artifacts".to_string()]);

    // Refuse admin-class scopes from non-admin callers. Without this
    // check, any logged-in user can mint a token with `*` or `admin`
    // and bypass every scope-only authorization gate via
    // `scopes_grant_access` (which short-circuits on those two values).
    // Other admin-only scopes (`delete:artifacts`, `delete:repositories`,
    // `write:users`) cover destructive/admin-class operations — see
    // `token_service::ADMIN_ONLY_SCOPES`.
    crate::services::token_service::enforce_admin_only_scopes(&scopes, auth.is_admin)
        .map_err(crate::error::AppError::Authorization)?;

    // Delegation ceiling (#2996): a scoped credential may not mint a token
    // that exceeds its own scopes. Interactive sessions (`scopes: None`)
    // are unaffected.
    auth.enforce_mint_ceiling(&scopes)?;

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let minted = auth_service
        .generate_api_token_with_policy(
            auth.user_id,
            &payload.name,
            scopes,
            payload.expires_in_days,
        )
        .await?;

    audit_fire_and_forget(
        state.db.clone(),
        api_token_mint_audit_entry(
            auth.user_id,
            minted.id,
            Some(&payload.name),
            "profile",
            minted.expires_at,
            minted.policy_applied,
        ),
    )
    .await;

    Ok(Json(ApiTokenCreatedResponse {
        id: minted.id,
        name: payload.name,
        token: minted.token,
        expires_at: minted.expires_at,
        policy_applied: minted.policy_applied,
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

    audit_fire_and_forget(
        state.db.clone(),
        api_token_audit_entry(
            AuditAction::ApiTokenRevoked,
            auth.user_id,
            token_id,
            None,
            "profile",
        ),
    )
    .await;

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
            "scopes": ["read:artifacts", "write:artifacts", "admin"],
            "expires_in_days": 90
        }"#;
        let req: CreateAccessTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "ci-token");
        assert_eq!(
            req.scopes,
            Some(vec![
                "read:artifacts".to_string(),
                "write:artifacts".to_string(),
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
        let json = r#"{"scopes": ["read:artifacts"]}"#;
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
        // Regression guard (#2996): the default for an omitted `scopes` field
        // must be the canonical `read:artifacts` — bare `read` is not in
        // `ALLOWED_SCOPES` and would be rejected at the mint primitive.
        let payload = CreateAccessTokenRequest {
            name: "test".to_string(),
            scopes: None,
            expires_in_days: None,
        };
        let scopes = payload
            .scopes
            .unwrap_or_else(|| vec!["read:artifacts".to_string()]);
        assert_eq!(scopes, vec!["read:artifacts".to_string()]);
        assert!(crate::services::token_service::validate_scopes_pure(&scopes).is_ok());
    }

    #[test]
    fn test_provided_scopes_preserved() {
        let payload = CreateAccessTokenRequest {
            name: "test".to_string(),
            scopes: Some(vec![
                "read:artifacts".to_string(),
                "write:artifacts".to_string(),
            ]),
            expires_in_days: None,
        };
        let scopes = payload
            .scopes
            .unwrap_or_else(|| vec!["read:artifacts".to_string()]);
        assert_eq!(
            scopes,
            vec!["read:artifacts".to_string(), "write:artifacts".to_string()]
        );
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
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
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
            scopes: Some(vec!["read:artifacts".to_string()]),
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
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
            scopes: vec!["read:artifacts".to_string(), "write:artifacts".to_string()],
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
            expires_at: None,
            policy_applied: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "new-token");
        assert_eq!(json["token"], "ak_secret_token_value");
    }
}

/// Shared plumbing for the DB-backed profile handler test modules
/// (`audit_db_tests`, `mint_scope_validation_db_tests`).
#[cfg(test)]
mod db_test_support {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::Extension as AxumExtension;

    pub(super) fn build_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(auth))
    }

    pub(super) async fn setup() -> Option<(sqlx::PgPool, SharedState, Uuid, String)> {
        let pool = tdh::try_pool().await?;
        let (user_id, username) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        Some((pool, state, user_id, username))
    }

    pub(super) async fn cleanup(pool: &sqlx::PgPool, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }
}

/// DB-backed tests for the token-lifecycle audit trail (#1617 Phase 1).
#[cfg(test)]
mod audit_db_tests {
    use super::db_test_support::{build_app, cleanup, setup};
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::json;

    /// `POST /profile/access-tokens` must emit `API_TOKEN_CREATED`, and the
    /// matching revoke must emit `API_TOKEN_REVOKED`.
    #[tokio::test]
    async fn profile_token_mint_and_revoke_emit_audit_events() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);

        let body = json!({ "name": "profile-audit", "scopes": ["read:artifacts"] }).to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/access-tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body_bytes) = tdh::send(build_app(state.clone(), auth.clone()), req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "profile mint failed: {}",
            String::from_utf8_lossy(&body_bytes)
        );
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let token_id = Uuid::parse_str(v["id"].as_str().unwrap()).unwrap();

        // #2522: audit write is fire-and-forget (spawned) — poll for the row.
        assert_eq!(
            tdh::audit_count_eventually(&pool, token_id, "API_TOKEN_CREATED", 1).await,
            1,
            "profile mint MUST write one API_TOKEN_CREATED row"
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/access-tokens/{}", token_id))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(build_app(state, auth), req).await;
        assert!(
            status.is_success(),
            "profile revoke should succeed: {status}"
        );

        assert_eq!(
            tdh::audit_count_eventually(&pool, token_id, "API_TOKEN_REVOKED", 1).await,
            1,
            "profile revoke MUST write one API_TOKEN_REVOKED row"
        );

        cleanup(&pool, user_id).await;
    }
}

/// DB-backed tests for the #2996 mint-path controls on
/// `POST /profile/access-tokens`: the changed omitted-scopes default and the
/// delegation ceiling.
#[cfg(test)]
mod mint_scope_validation_db_tests {
    use super::db_test_support::{build_app, cleanup, setup};
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::json;

    /// Regression guard (#2996): omitting `scopes` must still succeed (200)
    /// and persist the canonical `read:artifacts` — not the legacy bare
    /// `read`, which is outside `ALLOWED_SCOPES` and would be rejected by the
    /// mint-primitive vocabulary backstop.
    #[tokio::test]
    async fn omitted_scopes_default_persists_read_artifacts() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username); // interactive, non-admin

        let body = json!({ "name": "default-scopes" }).to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/access-tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body_bytes) = tdh::send(build_app(state, auth), req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "no-scopes profile mint MUST 200; body: {}",
            String::from_utf8_lossy(&body_bytes),
        );
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let token_id = Uuid::parse_str(v["id"].as_str().unwrap()).unwrap();

        let persisted: Vec<String> =
            sqlx::query_scalar("SELECT scopes FROM api_tokens WHERE id = $1")
                .bind(token_id)
                .fetch_one(&pool)
                .await
                .expect("fetch persisted scopes");
        assert_eq!(
            persisted,
            vec!["read:artifacts".to_string()],
            "omitted scopes must default to the canonical read:artifacts",
        );

        cleanup(&pool, user_id).await;
    }

    /// The delegation ceiling applies on the profile route too: a read-scoped
    /// presenting token cannot mint `write:artifacts` here (403), while an
    /// interactive session can (200).
    #[tokio::test]
    async fn profile_route_enforces_mint_ceiling_for_scoped_credentials() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };

        let mut scoped = tdh::make_auth(user_id, &username);
        scoped.is_api_token = true;
        scoped.scopes = Some(vec!["read:artifacts".to_string()]);
        let body = json!({ "name": "ceiling-probe", "scopes": ["write:artifacts"] }).to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/access-tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body_bytes) = tdh::send(build_app(state.clone(), scoped), req).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "read-scoped token minting write:artifacts on /profile MUST 403; body: {}",
            String::from_utf8_lossy(&body_bytes),
        );

        let interactive = tdh::make_auth(user_id, &username);
        let body = json!({ "name": "legit", "scopes": ["write:artifacts"] }).to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/access-tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body_bytes) = tdh::send(build_app(state, interactive), req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "interactive non-admin minting write:artifacts MUST stay 200; body: {}",
            String::from_utf8_lossy(&body_bytes),
        );

        cleanup(&pool, user_id).await;
    }
}
