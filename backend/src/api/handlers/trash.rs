//! Admin artifact trash API (#2072): list soft-deleted artifacts that storage
//! GC has not reclaimed yet, restore one, or purge one permanently.
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
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::access_scope::AccessScope;
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::trash_service::{PurgedArtifact, TrashPage, TrashService, TrashedArtifact};

#[derive(OpenApi)]
#[openapi(
    paths(list_trash, restore_trashed_artifact, purge_trashed_artifact),
    components(schemas(
        TrashPage,
        TrashedArtifact,
        PurgedArtifact,
        crate::api::dto::Pagination
    ))
)]
pub struct TrashApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_trash))
        .route("/:id", delete(purge_trashed_artifact))
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

pub(crate) fn trash_service(state: &SharedState) -> TrashService {
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
    extensions(("x-required-permission" = json!("system.maintenance")), ("x-resource" = json!("instance"))),
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
    // A repository-restricted admin token lists only its repositories' trash.
    let page = trash_service(&state)
        .list(
            query.repository.as_deref(),
            &auth.access_scope(),
            query.page,
            query.per_page,
        )
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
    extensions(("x-required-permission" = json!("system.maintenance")), ("x-resource" = json!("instance"))),
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
    require_trashed_in_token_scope(&state, &auth, id).await?;
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

/// DELETE /api/v1/admin/trash/{id}
///
/// Permanently delete a trashed artifact without waiting for storage GC,
/// which frees its path for a re-upload. The stored object is kept when
/// another artifact or revision still references it. Refused with 409 for
/// OCI manifests and blobs.
#[utoipa::path(
    delete,
    extensions(("x-required-permission" = json!("system.maintenance")), ("x-resource" = json!("instance"))),
    path = "/{id}",
    context_path = "/api/v1/admin/trash",
    tag = "admin",
    operation_id = "purge_trashed_artifact",
    params(("id" = Uuid, Path, description = "Artifact ID")),
    responses(
        (status = 200, description = "Artifact purged", body = PurgedArtifact),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Artifact not found or not in the trash"),
        (status = 409, description = "OCI manifests and blobs cannot be purged individually"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn purge_trashed_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<PurgedArtifact>> {
    auth.require_admin()?;
    require_trashed_in_token_scope(&state, &auth, id).await?;
    let purged = trash_service(&state).purge(id).await?;
    audit_purge(&state, &auth, &purged).await;
    Ok(Json(purged))
}

/// A repository-restricted admin token stays restricted (#4225): it may only
/// restore or purge artifacts of repositories in its allow-list (#4813).
/// Out-of-scope ids read as 404, exactly like ids that do not exist, so the
/// token learns nothing about other repositories. Unrestricted principals
/// skip the lookup.
async fn require_trashed_in_token_scope(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
) -> Result<()> {
    if matches!(auth.access_scope(), AccessScope::Admin) {
        return Ok(());
    }
    let repository_id: Option<Uuid> =
        sqlx::query_scalar("SELECT repository_id FROM artifacts WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    match repository_id {
        Some(repo_id) if auth.can_access_repo(repo_id) => Ok(()),
        _ => Err(AppError::NotFound("Artifact not found".to_string())),
    }
}

/// Record an `ARTIFACT_PURGED` audit entry.
pub(crate) async fn audit_purge(
    state: &SharedState,
    auth: &AuthExtension,
    purged: &PurgedArtifact,
) {
    let entry = AuditEntry::new(AuditAction::ArtifactPurged, ResourceType::Artifact)
        .user(auth.user_id)
        .actor_name(&auth.username)
        .resource(purged.id)
        .resource_name(purged.path.clone())
        .details_typed(crate::services::audit_export::details::ArtifactDetails {
            repository_id: purged.repository_id,
            path: purged.path.clone(),
            name: purged.name.clone(),
            version: purged.version.clone(),
            size_bytes: u64::try_from(purged.size_bytes).ok(),
            digest: Some(format!("sha256:{}", purged.checksum_sha256)),
            uploaded_by: None,
        });
    audit_fire_and_forget(state.db.clone(), entry).await;
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
    #[tokio::test]
    async fn purge_endpoint_is_admin_only_and_removes_the_row() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let path = format!("generic/api-purge-{}", Uuid::new_v4().simple());
        let id = crate::services::trash_service::tests::seed_trashed(&fx, &path, true).await;
        let uri = format!("/{id}");
        let delete = |uri: &str| Request::delete(uri).body(Body::empty()).unwrap();

        let (denied, _) = tdh::send(app(&fx, false), delete(&uri)).await;
        let (status, body) = tdh::send(app(&fx, true), delete(&uri)).await;
        let (again, _) = tdh::send(app(&fx, true), delete(&uri)).await;
        fx.teardown().await;

        assert_eq!(denied, StatusCode::FORBIDDEN);
        assert_eq!(status, StatusCode::OK);
        let purged: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(purged["id"], id.to_string());
        assert_eq!(purged["storage_reclaimed"], true);
        assert_eq!(again, StatusCode::NOT_FOUND);
    }

    /// An admin token restricted to other repositories cannot purge this
    /// repository's trash (404, nothing deleted); one restricted to it can.
    #[tokio::test]
    async fn purge_endpoint_honours_a_repository_restricted_admin_token() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let path = format!("generic/api-scoped-{}", Uuid::new_v4().simple());
        let id = crate::services::trash_service::tests::seed_trashed(&fx, &path, true).await;
        let uri = format!("/{id}");
        let scoped_app = |repo_ids: Vec<Uuid>| {
            let mut auth = tdh::make_auth(fx.user_id, &fx.username);
            auth.is_admin = true;
            auth.is_api_token = true;
            auth.allowed_repo_ids = AccessScope::Restricted(repo_ids);
            tdh::router_with_auth_ext(router(), fx.state.clone(), auth)
        };
        let delete = |uri: &str| Request::delete(uri).body(Body::empty()).unwrap();

        let (out_of_scope, _) = tdh::send(scoped_app(vec![Uuid::new_v4()]), delete(&uri)).await;
        let row_kept: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM artifacts WHERE id = $1)")
                .bind(id)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        let (in_scope, _) = tdh::send(scoped_app(vec![fx.repo_id]), delete(&uri)).await;
        fx.teardown().await;

        assert_eq!(out_of_scope, StatusCode::NOT_FOUND);
        assert!(row_kept, "an out-of-scope purge deletes nothing");
        assert_eq!(in_scope, StatusCode::OK);
    }

    /// An admin token restricted to other repositories does not see this
    /// repository's trash in the listing; one restricted to it does.
    #[tokio::test]
    async fn list_endpoint_honours_a_repository_restricted_admin_token() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let path = format!("generic/api-scoped-list-{}", Uuid::new_v4().simple());
        let _id = crate::services::trash_service::tests::seed_trashed(&fx, &path, true).await;
        let scoped_app = |repo_ids: Vec<Uuid>| {
            let mut auth = tdh::make_auth(fx.user_id, &fx.username);
            auth.is_admin = true;
            auth.is_api_token = true;
            auth.allowed_repo_ids = AccessScope::Restricted(repo_ids);
            tdh::router_with_auth_ext(router(), fx.state.clone(), auth)
        };
        let get = |uri: &str| Request::get(uri).body(Body::empty()).unwrap();
        let filtered = format!("/?repository={}", fx.repo_key);

        let (s1, unfiltered_out) = tdh::send(scoped_app(vec![Uuid::new_v4()]), get("/")).await;
        let (s2, filtered_out) = tdh::send(scoped_app(vec![Uuid::new_v4()]), get(&filtered)).await;
        let (s3, filtered_in) = tdh::send(scoped_app(vec![fx.repo_id]), get(&filtered)).await;
        fx.teardown().await;

        assert_eq!(
            (s1, s2, s3),
            (StatusCode::OK, StatusCode::OK, StatusCode::OK)
        );
        let unfiltered_out: serde_json::Value = serde_json::from_slice(&unfiltered_out).unwrap();
        assert!(
            unfiltered_out["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["path"] != path),
            "an out-of-scope token must not list this repository's trash: {unfiltered_out}"
        );
        let filtered_out: serde_json::Value = serde_json::from_slice(&filtered_out).unwrap();
        assert_eq!(filtered_out["pagination"]["total"], 0, "{filtered_out}");
        let filtered_in: serde_json::Value = serde_json::from_slice(&filtered_in).unwrap();
        assert_eq!(filtered_in["pagination"]["total"], 1, "{filtered_in}");
        assert_eq!(filtered_in["items"][0]["path"], path);
    }

    /// An admin token restricted to other repositories cannot restore this
    /// repository's trash (404, still trashed); one restricted to it can.
    #[tokio::test]
    async fn restore_endpoint_honours_a_repository_restricted_admin_token() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let path = format!("generic/api-scoped-restore-{}", Uuid::new_v4().simple());
        let id = crate::services::trash_service::tests::seed_trashed(&fx, &path, true).await;
        let uri = format!("/{id}/restore");
        let scoped_app = |repo_ids: Vec<Uuid>| {
            let mut auth = tdh::make_auth(fx.user_id, &fx.username);
            auth.is_admin = true;
            auth.is_api_token = true;
            auth.allowed_repo_ids = AccessScope::Restricted(repo_ids);
            tdh::router_with_auth_ext(router(), fx.state.clone(), auth)
        };
        let post = |uri: &str| Request::post(uri).body(Body::empty()).unwrap();

        let (out_of_scope, _) = tdh::send(scoped_app(vec![Uuid::new_v4()]), post(&uri)).await;
        let still_trashed: bool =
            sqlx::query_scalar("SELECT is_deleted FROM artifacts WHERE id = $1")
                .bind(id)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        let (in_scope, _) = tdh::send(scoped_app(vec![fx.repo_id]), post(&uri)).await;
        fx.teardown().await;

        assert_eq!(out_of_scope, StatusCode::NOT_FOUND);
        assert!(still_trashed, "an out-of-scope restore changes nothing");
        assert_eq!(in_scope, StatusCode::OK);
    }
}
