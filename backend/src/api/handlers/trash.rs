//! Admin artifact trash API (#2072): list soft-deleted artifacts that storage
//! GC has not reclaimed yet, and restore one.
//!
//! Nested under `/api/v1/admin/trash`, inside the `/admin` block whose
//! `admin_middleware` already requires an admin; the handlers re-check
//! `is_admin` so they stay safe if they are ever mounted elsewhere.
//!
//! How long an artifact stays here is `GC_TRASH_RETENTION_DAYS` (default 0:
//! until the next GC pass). See [`crate::services::trash_service`] for what
//! restore refuses and why.

use axum::extract::{Extension, Path, Query, State};
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::trash_service::{TrashPage, TrashService, TrashedArtifact};

#[derive(OpenApi)]
#[openapi(
    paths(list_trash, restore_trashed_artifact),
    components(schemas(TrashPage, TrashedArtifact, crate::api::dto::Pagination))
)]
pub struct TrashApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_trash))
        .route("/:id/restore", post(restore_trashed_artifact))
}

/// Query parameters for the trash listing.
#[derive(Debug, Deserialize, IntoParams)]
pub struct TrashListQuery {
    /// Only artifacts of the repository with this key.
    pub repository: Option<String>,
    /// Page number, 1-indexed (default 1).
    pub page: Option<u32>,
    /// Items per page, 1 to 500 (default 50).
    pub per_page: Option<u32>,
}

fn trash_service(state: &SharedState) -> TrashService {
    TrashService::new(
        state.db.clone(),
        state.storage_registry.clone(),
        state.config.gc_trash_retention_days,
    )
}

/// GET /api/v1/admin/trash
///
/// Soft-deleted artifacts still held by the trash, most recently deleted
/// first, with when each becomes eligible for GC and whether it can be
/// restored.
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/admin/trash",
    tag = "admin",
    operation_id = "list_trash",
    params(TrashListQuery),
    responses(
        (status = 200, description = "One page of trashed artifacts", body = TrashPage),
        (status = 403, description = "Admin privileges required"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_trash(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<TrashListQuery>,
) -> Result<Json<TrashPage>> {
    auth.require_admin()?;
    let page = trash_service(&state)
        .list(query.repository.as_deref(), query.page, query.per_page)
        .await?;
    Ok(Json(page))
}

/// POST /api/v1/admin/trash/{id}/restore
///
/// Put a soft-deleted artifact back and return its post-restore state.
/// Refused with 409 for proxy-cache rows, OCI manifests and blobs (their tags
/// are not restored), when another live artifact holds the path, or when the
/// stored object is already gone.
#[utoipa::path(
    post,
    path = "/{id}/restore",
    context_path = "/api/v1/admin/trash",
    tag = "admin",
    operation_id = "restore_trashed_artifact",
    params(("id" = Uuid, Path, description = "Artifact ID")),
    responses(
        (status = 200, description = "Artifact restored", body = TrashedArtifact),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Artifact not found or not in the trash"),
        (status = 409, description = "Artifact cannot be restored (OCI or proxy-cache content, path taken, or object gone)"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn restore_trashed_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<TrashedArtifact>> {
    auth.require_admin()?;
    let restored = trash_service(&state).restore(id).await?;

    let entry = AuditEntry::new(AuditAction::ArtifactRestored, ResourceType::Artifact)
        .user(auth.user_id)
        .actor_name(&auth.username)
        .resource(restored.id)
        .resource_name(restored.path.clone())
        .details_typed(crate::services::audit_export::details::ArtifactDetails {
            repository_id: restored.repository_id,
            path: restored.path.clone(),
            name: restored.name.clone(),
            version: restored.version.clone(),
            size_bytes: u64::try_from(restored.size_bytes).ok(),
            digest: Some(format!("sha256:{}", restored.checksum_sha256)),
            uploaded_by: None,
        });
    audit_fire_and_forget(state.db.clone(), entry).await;

    Ok(Json(restored))
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    fn app(fx: &tdh::Fixture, is_admin: bool) -> axum::Router {
        let mut auth = tdh::make_auth(fx.user_id, &fx.username);
        auth.is_admin = is_admin;
        tdh::router_with_auth_ext(router(), fx.state.clone(), auth)
    }

    #[tokio::test]
    async fn trash_endpoints_list_and_restore_for_admins_only() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let path = format!("generic/api-{}", Uuid::new_v4().simple());
        let id = crate::services::trash_service::tests::seed_trashed(&fx, &path, true).await;
        let list_uri = format!("/?repository={}", fx.repo_key);
        let restore_uri = format!("/{id}/restore");
        let get = |uri: &str| Request::get(uri).body(Body::empty()).unwrap();
        let post = |uri: &str| Request::post(uri).body(Body::empty()).unwrap();

        let (denied_list, _) = tdh::send(app(&fx, false), get(&list_uri)).await;
        let (denied_restore, _) = tdh::send(app(&fx, false), post(&restore_uri)).await;
        let (list_status, list_body) = tdh::send(app(&fx, true), get(&list_uri)).await;
        let (restore_status, restore_body) = tdh::send(app(&fx, true), post(&restore_uri)).await;
        let (again_status, _) = tdh::send(app(&fx, true), post(&restore_uri)).await;
        fx.teardown().await;

        assert_eq!(denied_list, StatusCode::FORBIDDEN);
        assert_eq!(denied_restore, StatusCode::FORBIDDEN);
        assert_eq!(list_status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(page["pagination"]["total"], 1, "{page}");
        assert_eq!(page["items"][0]["path"], path);
        assert_eq!(restore_status, StatusCode::OK);
        let restored: serde_json::Value = serde_json::from_slice(&restore_body).unwrap();
        assert_eq!(restored["id"], id.to_string());
        assert_eq!(again_status, StatusCode::NOT_FOUND);
    }
}
