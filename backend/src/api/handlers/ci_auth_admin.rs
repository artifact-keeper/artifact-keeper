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
use utoipa::OpenApi;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::ci_oidc_service::{
    CiOidcMappingResponse, CiOidcProviderResponse, CiOidcService, CiOidcToggleRequest,
    CreateCiOidcMappingRequest, CreateCiOidcProviderRequest, UpdateCiOidcMappingRequest,
    UpdateCiOidcProviderRequest,
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

fn require_admin(auth: &AuthExtension) -> crate::error::Result<()> {
    auth.require_admin()
}

// ---------------------------------------------------------------------------
// Provider handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/",
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
    path = "/",
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
    Ok(Json(svc.create(req).await?))
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
    Ok(Json(svc.update(id, req).await?))
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
    svc.delete(id).await
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
        (status = 200, description = "Create identity mapping", body = CiOidcMappingResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Provider not found", body = crate::api::openapi::ErrorResponse),
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
    Ok(Json(svc.create_mapping(provider_id, req).await?))
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
    Ok(Json(
        svc.update_mapping(provider_id, mapping_id, req).await?,
    ))
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
    svc.delete_mapping(provider_id, mapping_id).await
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
            allowed_repo_ids: None,
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
            }),
        )
        .await
        .expect("admin should create mapping")
        .0;

        let mappings = list_mappings(
            State(state.clone()),
            Extension(auth.clone()),
            Path(provider.id),
        )
        .await
        .expect("admin should list mappings")
        .0;
        assert!(mappings.iter().any(|m| m.id == mapping.id));

        let mapping_got = get_mapping(
            State(state.clone()),
            Extension(auth.clone()),
            Path((provider.id, mapping.id)),
        )
        .await
        .expect("admin should get mapping")
        .0;
        assert_eq!(mapping_got.name, "main-branch");

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
            }),
        )
        .await
        .expect("admin should update mapping")
        .0;
        assert_eq!(mapping_updated.name, "release-branch");
        assert_eq!(mapping_updated.priority, 20);

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
}
