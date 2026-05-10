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

pub async fn list_providers(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<CiOidcProviderResponse>>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.list().await?))
}

pub async fn get_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<CiOidcProviderResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.get_response(id).await?))
}

pub async fn create_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateCiOidcProviderRequest>,
) -> Result<Json<CiOidcProviderResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.create(req).await?))
}

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

pub async fn delete_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    svc.delete(id).await
}

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

pub async fn list_mappings(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(provider_id): Path<Uuid>,
) -> Result<Json<Vec<CiOidcMappingResponse>>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.list_mappings(provider_id).await?))
}

pub async fn get_mapping(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((provider_id, mapping_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<CiOidcMappingResponse>> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    Ok(Json(svc.get_mapping(provider_id, mapping_id).await?))
}

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

pub async fn delete_mapping(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((provider_id, mapping_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    require_admin(&auth)?;
    let svc = CiOidcService::new(state.db.clone());
    svc.delete_mapping(provider_id, mapping_id).await
}

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
