//! Admin CRUD endpoints for CI OIDC provider and identity mapping configuration.
//!
//! All endpoints require admin privileges.
//!
//! ## Route map
//!
//! ```text
//! GET    /                          → list_providers
//! POST   /                          → create_provider
//! GET    /:id                       → get_provider
//! PUT    /:id                       → update_provider
//! DELETE /:id                       → delete_provider
//! PATCH  /:id/toggle                → toggle_provider
//!
//! GET    /:id/mappings              → list_mappings
//! POST   /:id/mappings              → create_mapping
//! GET    /:id/mappings/:mid         → get_mapping
//! PUT    /:id/mappings/:mid         → update_mapping
//! DELETE /:id/mappings/:mid         → delete_mapping
//! PATCH  /:id/mappings/:mid/toggle  → toggle_mapping
//! ```

use axum::{
    extract::{Extension, Path, State},
    routing::{get, patch},
    Json, Router,
};
use std::sync::Arc;

use utoipa::OpenApi;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
use crate::services::auth_service::AuthService;
use crate::services::ci_oidc_service::{
    log_key_source_change, log_provider_type_change, CiOidcMappingResponse, CiOidcProviderResponse,
    CiOidcService, CiOidcToggleRequest, CreateCiOidcMappingRequest, CreateCiOidcProviderRequest,
    GroupBindingReconcileReport, UpdateCiOidcMappingRequest, UpdateCiOidcProviderRequest,
};

/// Create CI OIDC admin routes (auth enforced by the outer admin_middleware).
pub fn router() -> Router<SharedState> {
    Router::new()
        // Provider routes
        .route("/", get(list_providers).post(create_provider))
        .route(
            "/:id",
            get(get_provider)
                .put(update_provider)
                .delete(delete_provider),
        )
        .route("/:id/toggle", patch(toggle_provider))
        // Mapping routes (nested under provider)
        .route("/:id/mappings", get(list_mappings).post(create_mapping))
        .route(
            "/:id/mappings/:mid",
            get(get_mapping).put(update_mapping).delete(delete_mapping),
        )
        .route("/:id/mappings/:mid/toggle", patch(toggle_mapping))
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Revoke every refresh-token family of the service accounts a delete just
/// deactivated, on every replica (#1174). The service already dropped their
/// in-process token caches; the refresh families are DB-backed and need an
/// `AuthService`. Best-effort, as on the admin user-deactivation path: the
/// account is already inactive, which the refresh grant also checks.
async fn revoke_refresh_tokens(state: &SharedState, user_ids: &[Uuid]) {
    if user_ids.is_empty() {
        return;
    }
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    for user_id in user_ids {
        if let Err(e) = auth_service
            .revoke_all_refresh_token_families(*user_id)
            .await
        {
            tracing::warn!(
                user_id = %user_id,
                error = %e,
                "Failed to revoke refresh-token families of a deactivated CI service account"
            );
        }
    }
}

/// After a committed mapping write whose binding reconcile changed the
/// service account's memberships (design D8): drop this replica's cached
/// permissions so a revocation holds from the very next request, and record
/// the change in the audit log. Other replicas are invalidated by the
/// `user_group_members` NOTIFY trigger (migration 142). Auditing is
/// best-effort, as elsewhere: the write has already committed.
async fn after_binding_reconciled(
    state: &SharedState,
    auth: &AuthExtension,
    mapping: &CiOidcMappingResponse,
    report: Option<&GroupBindingReconcileReport>,
) {
    let Some(report) = report else {
        return;
    };
    if report.added.is_empty() && report.removed.is_empty() {
        return;
    }
    state.permission_service.invalidate_cache();

    let entry = AuditEntry::new(
        AuditAction::CiOidcGroupBindingReconciled,
        ResourceType::User,
    )
    .user(auth.user_id)
    .details(serde_json::json!({
        "provider_id": mapping.provider_id,
        "mapping_id": mapping.id,
        "service_account_id": mapping.service_account_id,
        "added": report.added,
        "removed": report.removed,
        "dangling": report.dangling,
    }));
    let entry = match mapping.service_account_id {
        Some(account_id) => entry.resource(account_id),
        None => entry,
    };
    if let Err(e) = AuditService::new(state.db.clone()).log(entry).await {
        tracing::warn!(
            mapping_id = %mapping.id,
            error = %e,
            "Failed to audit a CI OIDC group binding reconcile"
        );
    }
}

fn require_admin(auth: &AuthExtension) -> crate::error::Result<()> {
    auth.require_admin()
}

// ---------------------------------------------------------------------------
// Provider handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    // `""` (not `"/"`): the route is served at the bare collection path
    // `/api/v1/admin/ci-oidc`; `path = "/"` published a trailing-slash URL
    // that the router 404s. Mirrors lifecycle.rs.
    path = "",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    // Explicit id: the default (`list_providers`) collides with the SSO
    // handler of the same name and would fail the api-repo spectral gate.
    operation_id = "ci_oidc_list_providers",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List CI OIDC providers", body = Vec<CiOidcProviderResponse>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn list_providers(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<CiOidcProviderResponse>>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.list().await?))
}

#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "CI OIDC provider ID")),
    responses(
        (status = 200, description = "Get CI OIDC provider", body = CiOidcProviderResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<CiOidcProviderResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.get_response(id).await?))
}

#[utoipa::path(
    post,
    // `""` (not `"/"`): see list_providers above.
    path = "",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    request_body = CreateCiOidcProviderRequest,
    responses(
        (status = 200, description = "Create CI OIDC provider", body = CiOidcProviderResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn create_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateCiOidcProviderRequest>,
) -> Result<Json<CiOidcProviderResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    let created = svc.create(req).await?;
    // Every create sets a key source, even if only the `discovery` default.
    log_key_source_change(&created, auth.user_id, &auth.username);
    Ok(Json(created))
}

#[utoipa::path(
    put,
    path = "/{id}",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "CI OIDC provider ID")),
    request_body = UpdateCiOidcProviderRequest,
    responses(
        (status = 200, description = "Update CI OIDC provider", body = CiOidcProviderResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn update_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCiOidcProviderRequest>,
) -> Result<Json<CiOidcProviderResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    let updated = svc.update(id, req).await?;
    if updated.key_material_changed {
        log_key_source_change(&updated.provider, auth.user_id, &auth.username);
    }
    if let Some(previous) = &updated.previous_provider_type {
        log_provider_type_change(&updated.provider, previous, auth.user_id, &auth.username);
    }
    Ok(Json(updated.provider))
}

#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "CI OIDC provider ID")),
    responses(
        (status = 200, description = "Delete CI OIDC provider"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn delete_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    let deactivated = svc.delete(id).await?;
    revoke_refresh_tokens(&state, &deactivated).await;
    Ok(())
}

#[utoipa::path(
    patch,
    path = "/{id}/toggle",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "CI OIDC provider ID")),
    request_body = CiOidcToggleRequest,
    responses(
        (status = 200, description = "Toggle CI OIDC provider", body = CiOidcProviderResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn toggle_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<CiOidcToggleRequest>,
) -> Result<Json<CiOidcProviderResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.toggle(id, req.enabled).await?))
}

// ---------------------------------------------------------------------------
// Mapping handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/{id}/mappings",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "CI OIDC provider ID")),
    responses(
        (status = 200, description = "List identity mappings for provider", body = Vec<CiOidcMappingResponse>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn list_mappings(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(provider_id): Path<Uuid>,
) -> Result<Json<Vec<CiOidcMappingResponse>>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.list_mappings(provider_id).await?))
}

#[utoipa::path(
    get,
    path = "/{id}/mappings/{mid}",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "CI OIDC provider ID"),
        ("mid" = Uuid, Path, description = "Identity mapping ID")
    ),
    responses(
        (status = 200, description = "Get identity mapping", body = CiOidcMappingResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Mapping not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_mapping(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((provider_id, mapping_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<CiOidcMappingResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.get_mapping(provider_id, mapping_id).await?))
}

#[utoipa::path(
    post,
    path = "/{id}/mappings",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "CI OIDC provider ID")),
    request_body = CreateCiOidcMappingRequest,
    responses(
        (status = 200, description = "Identity mapping created together with its service account", body = CiOidcMappingResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Provider not found", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "The service account username this mapping derives is already taken; nothing was created", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn create_mapping(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(provider_id): Path<Uuid>,
    Json(req): Json<CreateCiOidcMappingRequest>,
) -> Result<Json<CiOidcMappingResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    let (mapping, report) = svc.create_mapping_with_report(provider_id, req).await?;
    after_binding_reconciled(&state, &auth, &mapping, report.as_ref()).await;
    Ok(Json(mapping))
}

#[utoipa::path(
    put,
    path = "/{id}/mappings/{mid}",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "CI OIDC provider ID"),
        ("mid" = Uuid, Path, description = "Identity mapping ID")
    ),
    request_body = UpdateCiOidcMappingRequest,
    responses(
        (status = 200, description = "Update identity mapping", body = CiOidcMappingResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Mapping not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn update_mapping(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((provider_id, mapping_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateCiOidcMappingRequest>,
) -> Result<Json<CiOidcMappingResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    let (mapping, report) = svc
        .update_mapping_with_report(provider_id, mapping_id, req)
        .await?;
    after_binding_reconciled(&state, &auth, &mapping, report.as_ref()).await;
    Ok(Json(mapping))
}

#[utoipa::path(
    delete,
    path = "/{id}/mappings/{mid}",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "CI OIDC provider ID"),
        ("mid" = Uuid, Path, description = "Identity mapping ID")
    ),
    responses(
        (status = 200, description = "Delete identity mapping"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Mapping not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn delete_mapping(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((provider_id, mapping_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    let deactivated = svc.delete_mapping(provider_id, mapping_id).await?;
    revoke_refresh_tokens(&state, &deactivated).await;
    Ok(())
}

#[utoipa::path(
    patch,
    path = "/{id}/mappings/{mid}/toggle",
    context_path = "/api/v1/admin/ci-oidc",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "CI OIDC provider ID"),
        ("mid" = Uuid, Path, description = "Identity mapping ID")
    ),
    request_body = CiOidcToggleRequest,
    responses(
        (status = 200, description = "Toggle identity mapping", body = CiOidcMappingResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Mapping not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn toggle_mapping(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((provider_id, mapping_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<CiOidcToggleRequest>,
) -> Result<Json<CiOidcMappingResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(
        svc.toggle_mapping(provider_id, mapping_id, req.enabled)
            .await?,
    ))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_providers,
        get_provider,
        create_provider,
        update_provider,
        delete_provider,
        toggle_provider,
        list_mappings,
        get_mapping,
        create_mapping,
        update_mapping,
        delete_mapping,
        toggle_mapping
    ),
    components(schemas(
        CreateCiOidcProviderRequest,
        UpdateCiOidcProviderRequest,
        CiOidcProviderResponse,
        CiOidcToggleRequest,
        CreateCiOidcMappingRequest,
        UpdateCiOidcMappingRequest,
        CiOidcMappingResponse
    ))
)]
pub struct CiAuthAdminApiDoc;

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::require_admin;
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::middleware::auth::AuthExtension;
    use axum::extract::{Extension, Path, State};
    use axum::Json;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    fn auth_with_admin(is_admin: bool) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "ci-admin-test".to_string(),
            email: "ci-admin-test@example.com".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    #[test]
    fn require_admin_allows_admin_user() {
        let auth = auth_with_admin(true);
        assert!(require_admin(&auth).is_ok());
    }

    #[test]
    fn require_admin_rejects_non_admin_user() {
        let auth = auth_with_admin(false);
        let err = require_admin(&auth).expect_err("non-admin should be rejected");
        assert!(err.to_string().contains("Admin access required"));
    }

    fn non_admin_state_and_auth() -> (crate::api::SharedState, AuthExtension) {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/artifact_keeper_test")
            .expect("lazy pool should build for auth-guard tests");
        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-admin-tests-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        (
            tdh::build_state(pool, &storage_path),
            auth_with_admin(false),
        )
    }

    async fn assert_admin_required<T: std::fmt::Debug>(result: crate::error::Result<T>) {
        let err = result.expect_err("non-admin should be rejected");
        assert!(err.to_string().contains("Admin access required"));
    }

    #[tokio::test]
    async fn handlers_reject_non_admin_access() {
        let (state, auth) = non_admin_state_and_auth();
        let pid = Uuid::new_v4();
        let mid = Uuid::new_v4();

        assert_admin_required(list_providers(State(state.clone()), Extension(auth.clone())).await)
            .await;
        assert_admin_required(
            get_provider(State(state.clone()), Extension(auth.clone()), Path(pid)).await,
        )
        .await;
        assert_admin_required(
            create_provider(
                State(state.clone()),
                Extension(auth.clone()),
                Json(CreateCiOidcProviderRequest {
                    name: "p".to_string(),
                    provider_type: Some("generic".to_string()),
                    issuer_url: "https://issuer.example.com".to_string(),
                    audience: Some("artifact-keeper".to_string()),
                    is_enabled: Some(true),
                    key_source: None,
                    static_jwks: None,
                }),
            )
            .await,
        )
        .await;
        assert_admin_required(
            update_provider(
                State(state.clone()),
                Extension(auth.clone()),
                Path(pid),
                Json(UpdateCiOidcProviderRequest {
                    name: Some("x".to_string()),
                    provider_type: Some("github".to_string()),
                    issuer_url: Some("https://issuer.example.com".to_string()),
                    audience: Some("artifact-keeper".to_string()),
                    is_enabled: Some(false),
                    key_source: None,
                    static_jwks: None,
                }),
            )
            .await,
        )
        .await;
        assert_admin_required(
            delete_provider(State(state.clone()), Extension(auth.clone()), Path(pid)).await,
        )
        .await;
        assert_admin_required(
            toggle_provider(
                State(state.clone()),
                Extension(auth.clone()),
                Path(pid),
                Json(CiOidcToggleRequest { enabled: true }),
            )
            .await,
        )
        .await;
        assert_admin_required(
            list_mappings(State(state.clone()), Extension(auth.clone()), Path(pid)).await,
        )
        .await;
        assert_admin_required(
            get_mapping(
                State(state.clone()),
                Extension(auth.clone()),
                Path((pid, mid)),
            )
            .await,
        )
        .await;
        assert_admin_required(
            create_mapping(
                State(state.clone()),
                Extension(auth.clone()),
                Path(pid),
                Json(CreateCiOidcMappingRequest {
                    name: "m".to_string(),
                    priority: Some(1),
                    claim_filters: serde_json::json!({"sub": "abc"}),
                    allowed_repo_ids: None,
                    is_enabled: Some(true),
                    group_binding_ids: None,
                }),
            )
            .await,
        )
        .await;
        assert_admin_required(
            update_mapping(
                State(state.clone()),
                Extension(auth.clone()),
                Path((pid, mid)),
                Json(UpdateCiOidcMappingRequest {
                    name: Some("m2".to_string()),
                    priority: Some(2),
                    claim_filters: Some(serde_json::json!({"sub": "def"})),
                    allowed_repo_ids: None,
                    is_enabled: Some(false),
                    group_binding_ids: None,
                }),
            )
            .await,
        )
        .await;
        assert_admin_required(
            delete_mapping(
                State(state.clone()),
                Extension(auth.clone()),
                Path((pid, mid)),
            )
            .await,
        )
        .await;
        assert_admin_required(
            toggle_mapping(
                State(state),
                Extension(auth),
                Path((pid, mid)),
                Json(CiOidcToggleRequest { enabled: true }),
            )
            .await,
        )
        .await;
    }

    #[tokio::test]
    async fn admin_provider_and_mapping_crud_roundtrip() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-admin-tests-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let state = tdh::build_state(pool.clone(), &storage_path);
        let auth = auth_with_admin(true);

        let provider = create_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Json(CreateCiOidcProviderRequest {
                name: "admin-provider-roundtrip".to_string(),
                provider_type: Some("generic".to_string()),
                issuer_url: "https://issuer.example.com".to_string(),
                audience: Some("artifact-keeper".to_string()),
                is_enabled: Some(true),
                key_source: None,
                static_jwks: None,
            }),
        )
        .await
        .expect("admin should create provider")
        .0;

        let listed = list_providers(State(state.clone()), Extension(auth.clone()))
            .await
            .expect("admin should list providers")
            .0;
        assert!(listed.iter().any(|p| p.id == provider.id));

        let got = get_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
        )
        .await
        .expect("admin should get provider")
        .0;
        assert_eq!(got.name, "admin-provider-roundtrip");

        let updated = update_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
            Json(UpdateCiOidcProviderRequest {
                name: Some("admin-provider-updated".to_string()),
                provider_type: Some("github".to_string()),
                issuer_url: Some("https://issuer2.example.com".to_string()),
                audience: Some("artifact-keeper-ci".to_string()),
                is_enabled: Some(true),
                key_source: None,
                static_jwks: None,
            }),
        )
        .await
        .expect("admin should update provider")
        .0;
        assert_eq!(updated.name, "admin-provider-updated");

        let toggled = toggle_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
            Json(CiOidcToggleRequest { enabled: false }),
        )
        .await
        .expect("admin should toggle provider")
        .0;
        assert!(!toggled.is_enabled);

        let mapping = create_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
            Json(CreateCiOidcMappingRequest {
                name: "main-branch".to_string(),
                priority: Some(10),
                claim_filters: serde_json::json!({"ref": "refs/heads/main"}),
                allowed_repo_ids: None,
                is_enabled: Some(true),
                group_binding_ids: None,
            }),
        )
        .await
        .expect("admin should create mapping")
        .0;
        // The service account exists from creation and is reported on every
        // read and write of the mapping, so an operator can grant it access
        // without running a pipeline first.
        let account_id = mapping
            .service_account_id
            .expect("create returns the mapping's service account");
        let account = (
            Some(account_id),
            Some(crate::services::ci_oidc_service::service_account_username(
                mapping.id,
            )),
        );
        assert_eq!(
            (
                mapping.service_account_id,
                mapping.service_account_username.clone()
            ),
            account
        );

        let mappings = list_mappings(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
        )
        .await
        .expect("admin should list mappings")
        .0;
        let listed = mappings
            .iter()
            .find(|m| m.id == mapping.id)
            .expect("mapping is listed");
        assert_eq!(
            (
                listed.service_account_id,
                listed.service_account_username.clone()
            ),
            account
        );

        let mapping_got = get_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path((provider.id, mapping.id)),
        )
        .await
        .expect("admin should get mapping")
        .0;
        assert_eq!(mapping_got.name, "main-branch");
        assert_eq!(
            (
                mapping_got.service_account_id,
                mapping_got.service_account_username.clone()
            ),
            account
        );

        let mapping_updated = update_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path((provider.id, mapping.id)),
            Json(UpdateCiOidcMappingRequest {
                name: Some("release-branch".to_string()),
                priority: Some(20),
                claim_filters: Some(serde_json::json!({"ref": ["refs/heads/release"]})),
                allowed_repo_ids: None,
                is_enabled: Some(true),
                group_binding_ids: None,
            }),
        )
        .await
        .expect("admin should update mapping")
        .0;
        assert_eq!(mapping_updated.name, "release-branch");
        assert_eq!(mapping_updated.priority, 20);
        assert_eq!(
            (
                mapping_updated.service_account_id,
                mapping_updated.service_account_username.clone()
            ),
            account,
            "renaming a mapping does not rotate its identity"
        );

        let mapping_toggled = toggle_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path((provider.id, mapping.id)),
            Json(CiOidcToggleRequest { enabled: false }),
        )
        .await
        .expect("admin should toggle mapping")
        .0;
        assert!(!mapping_toggled.is_enabled);
        assert_eq!(mapping_toggled.service_account_id, Some(account_id));

        delete_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path((provider.id, mapping.id)),
        )
        .await
        .expect("admin should delete mapping");

        delete_provider(State(state), Extension(auth), Path(provider.id))
            .await
            .expect("admin should delete provider");

        let active: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("the account outlives its mapping");
        assert!(!active, "deleting the mapping deactivated its account");
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await;
    }

    /// The published API contract carries the new mapping fields, so the
    /// Terraform provider and SDK consumers can read them.
    #[test]
    fn openapi_mapping_response_carries_the_service_account() {
        use utoipa::OpenApi as _;
        let spec = serde_json::to_value(super::CiAuthAdminApiDoc::openapi()).unwrap();
        let props = &spec["components"]["schemas"]["CiOidcMappingResponse"]["properties"];
        for field in [
            "service_account_id",
            "service_account_username",
            "group_binding_ids",
        ] {
            assert!(props.get(field).is_some(), "{field} missing from {props}");
        }
    }

    /// The published API contract also carries the binding on the request
    /// side, so the Terraform provider and SDK consumers can both read and
    /// write it (design D1, D2).
    #[test]
    fn openapi_mapping_requests_carry_the_group_binding() {
        use utoipa::OpenApi as _;
        let spec = serde_json::to_value(super::CiAuthAdminApiDoc::openapi()).unwrap();
        for schema in ["CreateCiOidcMappingRequest", "UpdateCiOidcMappingRequest"] {
            let props = &spec["components"]["schemas"][schema]["properties"];
            assert!(
                props.get("group_binding_ids").is_some(),
                "group_binding_ids missing from {schema}: {props}"
            );
        }
    }

    /// The provider schemas publish the key source and static JWKS on both
    /// sides, and name `kubernetes` among the provider types (5.1).
    #[test]
    fn openapi_provider_schemas_carry_the_key_source() {
        use utoipa::OpenApi as _;
        let spec = serde_json::to_value(super::CiAuthAdminApiDoc::openapi()).unwrap();
        for schema in [
            "CreateCiOidcProviderRequest",
            "UpdateCiOidcProviderRequest",
            "CiOidcProviderResponse",
        ] {
            let props = &spec["components"]["schemas"][schema]["properties"];
            for field in ["key_source", "static_jwks"] {
                assert!(
                    props.get(field).is_some(),
                    "{field} missing from {schema}: {props}"
                );
            }
        }
        let provider_type = spec["components"]["schemas"]["CreateCiOidcProviderRequest"]
            ["properties"]["provider_type"]["description"]
            .as_str()
            .unwrap_or_default();
        assert!(provider_type.contains("kubernetes"), "{provider_type}");
        // The published contract matches `normalize_provider_type`: an
        // unknown type is refused, not treated as free text.
        assert!(
            provider_type.contains("refused with 400"),
            "{provider_type}"
        );
        assert!(!provider_type.contains("Free text"), "{provider_type}");
        let echoed = spec["components"]["schemas"]["CiOidcProviderResponse"]["properties"]
            ["provider_type"]["description"]
            .as_str()
            .unwrap_or_default();
        assert!(!echoed.contains("echoed as written"), "{echoed}");
    }

    /// 2.4 — setting or changing a key source or static JWKS emits a
    /// `security` line naming the provider, the admin, the key source and the
    /// resulting kid set; an update that leaves them alone emits none.
    #[tokio::test]
    async fn key_source_changes_are_logged_with_the_admin_and_kids() {
        use crate::services::ci_oidc_service::test_public_jwk;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-admin-tests-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let state = tdh::build_state(pool, &storage_path);
        let auth = auth_with_admin(true);
        let update = |static_jwks: Option<serde_json::Value>, name: Option<String>| {
            UpdateCiOidcProviderRequest {
                name,
                provider_type: None,
                issuer_url: None,
                audience: None,
                is_enabled: None,
                key_source: None,
                static_jwks,
            }
        };

        let capture = crate::api::handlers::test_db_helpers::LogCapture::default();
        let _guard = capture.install(tracing::Level::INFO);

        let provider = create_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Json(CreateCiOidcProviderRequest {
                name: format!("k8s-log-{}", Uuid::new_v4()),
                provider_type: Some("kubernetes".to_string()),
                issuer_url: "https://kubernetes.default.svc.cluster.local".to_string(),
                audience: None,
                is_enabled: None,
                key_source: Some("static".to_string()),
                static_jwks: Some(serde_json::json!({"keys": [test_public_jwk("k1")]})),
            }),
        )
        .await
        .expect("create static provider")
        .0;
        let created_line = capture.text();
        assert!(
            created_line.contains("key_source=static") && created_line.contains("kids=k1"),
            "{created_line}"
        );

        let replaced = update_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
            Json(update(
                Some(serde_json::json!({"keys": [test_public_jwk("k1"), test_public_jwk("k2")]})),
                None,
            )),
        )
        .await
        .expect("replace the JWKS")
        .0;
        assert_eq!(replaced.key_source, "static");
        let logs = capture.text();
        let line = logs
            .lines()
            .rfind(|l| l.contains("CI OIDC: provider key source set"))
            .expect("a security line for the replacement");
        for needle in [
            format!("provider_id={}", provider.id),
            format!("admin_id={}", auth.user_id),
            "admin=ci-admin-test".to_string(),
            "key_source=static".to_string(),
            "kids=k1, k2".to_string(),
        ] {
            assert!(line.contains(&needle), "missing {needle} in: {line}");
        }
        assert!(line.contains("security"), "target is security: {line}");

        // Type changes are logged, and an unknown type is refused untouched.
        let widened = update_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
            Json(UpdateCiOidcProviderRequest {
                provider_type: Some("Generic".to_string()),
                ..update(None, None)
            }),
        )
        .await
        .expect("change the provider type")
        .0;
        assert_eq!(widened.provider_type, "generic");
        let logs = capture.text();
        let line = logs
            .lines()
            .rfind(|l| l.contains("CI OIDC: provider type changed"))
            .expect("a security line for the type change");
        for needle in [
            "previous_provider_type=kubernetes",
            "provider_type=generic",
            "admin=ci-admin-test",
        ] {
            assert!(line.contains(needle), "missing {needle} in: {line}");
        }
        let refused = update_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
            Json(UpdateCiOidcProviderRequest {
                provider_type: Some("k8s".to_string()),
                ..update(None, None)
            }),
        )
        .await;
        assert!(refused.is_err(), "k8s must be refused");

        let before = capture.text().matches("provider key source set").count();
        let renamed = update_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
            Json(update(
                None,
                Some(format!("k8s-renamed-{}", Uuid::new_v4())),
            )),
        )
        .await
        .expect("rename")
        .0;
        assert!(renamed.name.starts_with("k8s-renamed-"));
        assert_eq!(
            capture.text().matches("provider key source set").count(),
            before,
            "an update that leaves key material alone logs no key-source line"
        );

        delete_provider(State(state), Extension(auth), Path(provider.id))
            .await
            .expect("delete provider");
    }

    #[tokio::test]
    async fn admin_get_provider_not_found_propagates() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-admin-tests-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let state = tdh::build_state(pool, &storage_path);

        let err = get_provider(
            State(state),
            Extension(auth_with_admin(true)),
            Path(Uuid::new_v4()),
        )
        .await
        .expect_err("missing provider should return not found");

        assert!(err.to_string().to_lowercase().contains("not found"));
    }

    async fn binding_audit_rows(pool: &sqlx::PgPool, mapping_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE action = 'CI_OIDC_GROUP_BINDING_RECONCILED' \
               AND details->>'mapping_id' = $1",
        )
        .bind(mapping_id.to_string())
        .fetch_one(pool)
        .await
        .unwrap()
    }

    fn bind_to(group_binding_ids: Option<Vec<Uuid>>) -> UpdateCiOidcMappingRequest {
        UpdateCiOidcMappingRequest {
            name: None,
            priority: None,
            claim_filters: None,
            allowed_repo_ids: None,
            is_enabled: None,
            group_binding_ids: Some(group_binding_ids),
        }
    }

    /// Design D8: a mapping write that narrows the binding revokes on the
    /// very next permission check, even one this replica has cached, and
    /// leaves an audit row naming what changed. A write that changes no
    /// membership leaves none.
    #[tokio::test]
    async fn narrowing_a_binding_invalidates_cached_permissions_and_is_audited() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-admin-binding-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let state = tdh::build_state(pool.clone(), &storage_path);
        // A real user: `audit_log.user_id` references `users`.
        let (admin_id, _admin_name) = tdh::create_user(&pool).await;
        let auth = AuthExtension {
            user_id: admin_id,
            ..auth_with_admin(true)
        };
        let (repo_id, _key, repo_dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (group_id, _name) = tdh::create_group(&pool).await;
        tdh::grant_permission(&pool, "group", group_id, "repository", repo_id, &["read"]).await;

        let provider = create_provider(
            State(state.clone()),
            Extension(auth.clone()),
            Json(CreateCiOidcProviderRequest {
                name: format!("binding-audit-{}", Uuid::new_v4()),
                provider_type: Some("gitlab".to_string()),
                issuer_url: "https://gitlab.example.com".to_string(),
                audience: None,
                is_enabled: Some(true),
                key_source: None,
                static_jwks: None,
            }),
        )
        .await
        .expect("create provider")
        .0;
        let mapping = create_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
            Json(CreateCiOidcMappingRequest {
                name: "deploy".to_string(),
                priority: None,
                claim_filters: serde_json::json!({"project_path": "group/app"}),
                allowed_repo_ids: None,
                is_enabled: None,
                group_binding_ids: Some(vec![group_id]),
            }),
        )
        .await
        .expect("create mapping")
        .0;
        let account_id = mapping.service_account_id.expect("account exists");
        assert_eq!(
            binding_audit_rows(&pool, mapping.id).await,
            1,
            "the create granted a membership and is audited"
        );

        // Warm this replica's cache with the granted answer.
        let can_read = || async {
            state
                .permission_service
                .check_permission(account_id, "repository", repo_id, "read", false)
                .await
                .unwrap()
        };
        assert!(can_read().await, "the binding grants read");

        let _ = update_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path((provider.id, mapping.id)),
            Json(bind_to(Some(vec![]))),
        )
        .await
        .expect("narrow the binding");
        assert!(
            !can_read().await,
            "the narrowing must not be served from the cache"
        );
        assert_eq!(binding_audit_rows(&pool, mapping.id).await, 2);

        let _ = update_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path((provider.id, mapping.id)),
            Json(bind_to(Some(vec![]))),
        )
        .await
        .expect("repeat the same binding");
        assert_eq!(
            binding_audit_rows(&pool, mapping.id).await,
            2,
            "a write that changes no membership is not audited"
        );

        let svc = CiOidcService::new(pool.clone());
        svc.delete(provider.id).await.expect("delete provider");
        let _ = sqlx::query("DELETE FROM audit_log WHERE details->>'mapping_id' = $1")
            .bind(mapping.id.to_string())
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(vec![account_id, admin_id])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(repo_dir);
    }
}
