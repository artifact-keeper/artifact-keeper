//! Storage garbage collection API handler.

use axum::extract::{Extension, Path, Query};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::repository_service::RepositoryService;
use crate::services::storage_gc_service::{
    OciBlobFootprintReport, OciBlobRepoFootprint, StorageGcResult, StorageGcService,
};

#[derive(OpenApi)]
#[openapi(
    paths(run_storage_gc, run_repository_storage_gc, oci_blob_report),
    components(schemas(
        StorageGcRequest,
        StorageGcResult,
        OciBlobFootprintReport,
        OciBlobRepoFootprint,
    ))
)]
pub struct StorageGcApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", post(run_storage_gc))
        .route("/oci-blob-report", get(oci_blob_report))
}

/// Per-repository GC route, merged into the repositories router so the web
/// UI's per-repo storage panel can reach it at
/// `/api/v1/repositories/{key}/storage-gc` (web #708).
///
/// Kept out of [`router()`] because that router is nested under
/// `/api/v1/admin/storage-gc`; this endpoint lives in the
/// `/api/v1/repositories` namespace and goes through its
/// `optional_auth_middleware`, so the handler takes
/// `Extension<Option<AuthExtension>>` and authenticates explicitly.
pub fn repo_router() -> Router<SharedState> {
    Router::new().route("/:key/storage-gc", post(run_repository_storage_gc))
}

/// Request body for storage GC.
///
/// `dry_run` is **required** and unknown fields are **rejected** (#3501): a
/// live GC pass is irreversible (no tombstone, no restore path short of a
/// backup), so an ambiguous request must fail loudly instead of selecting the
/// destructive branch. Before this, `{}` and any typo'd key
/// (`{"dryRun": true}`, `{"dry_Run": true}`) silently deserialized to
/// `dry_run: false` and performed a real deletion. Callers now say which pass
/// they mean: `{"dry_run": true}` to estimate, `{"dry_run": false}` to
/// delete; anything else is refused with an error naming the missing or
/// unknown field (axum's `Json` rejection, HTTP 422), and nothing is deleted.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageGcRequest {
    /// When true, report what would be deleted without actually deleting.
    /// Required: an absent field is a rejected request, never a live delete.
    pub dry_run: bool,
}

/// POST /api/v1/admin/storage-gc
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/admin/storage-gc",
    tag = "admin",
    operation_id = "run_storage_gc",
    request_body = StorageGcRequest,
    responses(
        (status = 200, description = "GC result", body = StorageGcResult),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn run_storage_gc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<StorageGcRequest>,
) -> Result<Json<StorageGcResult>> {
    require_admin(auth.is_admin)?;

    let service = StorageGcService::new(state.db.clone(), state.storage_registry.clone())
        .with_maven_flat_gc_enabled(state.config.maven_flat_gc_enabled);
    let result = service.run_gc(payload.dry_run).await?;

    // Post-GC storage-stats refresh (#2056/#2601): the *scheduled* GC pass
    // already recomputes the materialized repository/path storage stats right
    // after reclaim (scheduler_service), but the admin-triggered pass left
    // them stale until the next cron tick. Mirror the scheduler here so an
    // operator-initiated GC settles the reported numbers too.
    refresh_stats_after_live_gc(&state, payload.dry_run).await;

    Ok(Json(result))
}

/// Best-effort post-GC storage-stats refresh shared by both GC endpoints
/// (#2056/#2601): settle the materialized repository/path storage stats after
/// a LIVE pass instead of leaving them stale until the next cron tick. A
/// refresh failure must not fail the GC that already ran, so errors are
/// logged and swallowed. A dry run reclaims nothing and refreshes nothing.
async fn refresh_stats_after_live_gc(state: &SharedState, dry_run: bool) {
    if dry_run {
        return;
    }
    let stats_service = crate::services::storage_stats_service::StorageStatsService::new(
        state.db.clone(),
        &state.config.storage_backend,
    );
    if let Err(e) = stats_service.recompute_all().await {
        tracing::warn!("Post-GC storage-stats refresh failed: {}", e);
    }
}

/// Gate an admin-only endpoint.
///
/// Returns `Ok(())` when the caller is an admin and an
/// [`AppError::Unauthorized`] otherwise. Extracted from the handlers so the
/// authorization branch is unit-testable without constructing a full axum
/// request (the handlers themselves require a live DB-backed `SharedState`).
fn require_admin(is_admin: bool) -> Result<()> {
    if is_admin {
        Ok(())
    } else {
        Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ))
    }
}

/// Unwrap the optional auth extension produced by the repositories router's
/// `optional_auth_middleware`, failing closed when no credentials were
/// presented (mirrors the fail-closed `AuthExtension::default` invariant).
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))
}

/// POST /api/v1/repositories/{key}/storage-gc
///
/// Repository-scoped storage garbage collection (web #708): the endpoint the
/// web UI's per-repo storage panel calls with `{dry_run: true}` for its
/// "reclaimable now" estimate.
///
/// Semantics: every candidate sweep of [`StorageGcService::run_gc`] is
/// restricted to rows owned by this repository (soft-deleted artifacts,
/// abandoned OCI upload sessions, orphaned upload cleanup keys, and orphaned
/// Maven flat-object attribution rows), while the orphan *predicates* stay
/// instance-wide — a storage key is only reclaimed (or counted, on a dry
/// run) when no live artifact, tag, blob, or manifest reference exists for
/// it anywhere on the instance. The dry-run estimate is therefore
/// dedup-aware: bytes still shared with another repository are never
/// reported as reclaimable. On shared (cloud) backends a live run
/// hard-deletes every repository's soft-deleted rows for a reclaimed key,
/// exactly as the instance-wide pass would. Admin-gated like the
/// instance-wide endpoint.
#[utoipa::path(
    post,
    path = "/{key}/storage-gc",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    operation_id = "run_repository_storage_gc",
    params(("key" = String, Path, description = "Repository key")),
    request_body = StorageGcRequest,
    responses(
        (status = 200, description = "GC result", body = StorageGcResult),
        (status = 401, description = "Authentication required, or admin privileges required"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn run_repository_storage_gc(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<StorageGcRequest>,
) -> Result<Json<StorageGcResult>> {
    let auth = require_auth(auth)?;
    // Admin gate BEFORE the repository lookup so a non-admin cannot probe
    // repository existence through the 404-vs-401 distinction.
    require_admin(auth.is_admin)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    // Same opt-in gate as the scheduled pass (#3431): this endpoint shares
    // `ORPHAN_MAVEN_FLAT_PREDICATE_SQL` with it, so it must share the gate too
    // — otherwise "GC this one repository" stays a one-click way to delete
    // hand-attributed legacy objects.
    let service = StorageGcService::new(state.db.clone(), state.storage_registry.clone())
        .with_maven_flat_gc_enabled(state.config.maven_flat_gc_enabled);
    let result = service
        .run_gc_for_repository(repo.id, payload.dry_run)
        .await?;

    // Mirror the admin endpoint (#2056/#2601): settle the materialized
    // storage stats after a live pass instead of leaving them stale until
    // the next cron tick. Best-effort — the GC already ran.
    refresh_stats_after_live_gc(&state, payload.dry_run).await;

    Ok(Json(result))
}

/// Resolve the effective grace-window argument for the blob report from the
/// optional `grace_hours` query parameter.
///
/// An absent parameter resolves to `0`, which the service layer then clamps
/// to [`crate::services::storage_gc_service::BLOB_REPORT_GRACE_HOURS_DEFAULT`].
/// Keeping this mapping in a pure helper makes the query-param handling
/// coverable without standing up the HTTP stack.
fn resolve_report_grace_hours(grace_hours: Option<i64>) -> i64 {
    grace_hours.unwrap_or_default()
}

/// Query parameters for the read-only OCI blob footprint report.
#[derive(Debug, Deserialize, IntoParams)]
pub struct OciBlobReportQuery {
    /// Grace window in hours used to compute the `aged_*` figures. Defaults
    /// to 24h; non-positive or out-of-range values are clamped server-side.
    pub grace_hours: Option<i64>,
}

/// GET /api/v1/admin/storage-gc/oci-blob-report
///
/// Read-only report of the OCI blob (`oci_blobs`) storage footprint
/// (issue #1408). Performs no deletion and takes no locks — it only runs
/// aggregate `SELECT`s. Surfaces logical vs dedup-aware physical bytes so
/// operators can see how much un-reclaimed blob storage exists before any
/// garbage-collection sweep is enabled.
#[utoipa::path(
    get,
    path = "/oci-blob-report",
    context_path = "/api/v1/admin/storage-gc",
    tag = "admin",
    operation_id = "oci_blob_report",
    params(OciBlobReportQuery),
    responses(
        (status = 200, description = "OCI blob footprint report", body = OciBlobFootprintReport),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn oci_blob_report(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<OciBlobReportQuery>,
) -> Result<Json<OciBlobFootprintReport>> {
    require_admin(auth.is_admin)?;

    let service = StorageGcService::new(state.db.clone(), state.storage_registry.clone());
    let report = service
        .oci_blob_footprint_report(resolve_report_grace_hours(query.grace_hours))
        .await?;
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::storage_gc_service::StorageGcResult;
    use utoipa::OpenApi;

    // -- StorageGcRequest deserialization tests --

    /// #3501: `{}` must never reach the handler — before this fix an empty
    /// body deserialized to `dry_run: false` and performed a live, irreversible
    /// delete. The request must be refused with an error that names the
    /// missing field, so the caller learns what to say rather than what
    /// happened to their data.
    #[test]
    fn test_storage_gc_request_empty_body_rejected() {
        let result = serde_json::from_str::<StorageGcRequest>("{}");
        let err = result.expect_err("`{}` must not deserialize into a live-delete request");
        assert!(
            err.to_string().contains("dry_run"),
            "rejection must name the missing field so the caller can fix it, got: {err}"
        );
    }

    #[test]
    fn test_storage_gc_request_explicit_dry_run_true() {
        let req: StorageGcRequest = serde_json::from_str(r#"{"dry_run": true}"#).unwrap();
        assert!(req.dry_run);
    }

    #[test]
    fn test_storage_gc_request_explicit_dry_run_false() {
        let req: StorageGcRequest = serde_json::from_str(r#"{"dry_run": false}"#).unwrap();
        assert!(!req.dry_run);
    }

    /// #3501 (inverts the former `test_storage_gc_request_extra_fields_ignored`,
    /// which pinned the lenient parse): an unknown field is now a hard error.
    /// The lenient parse meant a typo'd key silently fell through to the
    /// destructive default — during 1.8.2 verification a typo'd key deleted a
    /// batch of attribution rows this way.
    #[test]
    fn test_storage_gc_request_unknown_field_rejected() {
        let result =
            serde_json::from_str::<StorageGcRequest>(r#"{"dry_run": true, "unknown_field": 42}"#);
        let err = result.expect_err("unknown fields must be rejected, not ignored");
        assert!(
            err.to_string().contains("unknown_field"),
            "rejection must name the unknown field, got: {err}"
        );
    }

    /// #3501: the exact incident shape — the caller *asked for a dry run* with
    /// the wrong key casing, and the old contract answered with a live delete.
    /// `{"dryRun": true}` must be a 400-shaped rejection, and the negative
    /// control is deliberately a payload whose author's INTENT was
    /// non-destructive: if this ever deserializes again, it must not be
    /// allowed to mean `dry_run: false`.
    #[test]
    fn test_storage_gc_request_camel_case_key_rejected() {
        let result = serde_json::from_str::<StorageGcRequest>(r#"{"dryRun": true}"#);
        let err =
            result.expect_err("a typo'd/camelCase key must not select the live-delete branch");
        assert!(
            err.to_string().contains("dryRun"),
            "rejection must name the offending key, got: {err}"
        );
    }

    #[test]
    fn test_storage_gc_request_invalid_dry_run_type() {
        let result = serde_json::from_str::<StorageGcRequest>(r#"{"dry_run": "yes"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_gc_request_debug_formatting() {
        let req: StorageGcRequest = serde_json::from_str(r#"{"dry_run": true}"#).unwrap();
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("StorageGcRequest"));
        assert!(debug_str.contains("dry_run"));
    }

    /// #3501 end-to-end through the REAL admin route (`router()`), not just
    /// the serde layer: an ambiguous request must be REFUSED and must leave
    /// the data untouched, while an explicit `{"dry_run": false}` must still
    /// perform the live pass. Seeds a genuinely orphaned soft-deleted
    /// artifact (row + object) that a live GC pass deletes, so "nothing was
    /// deleted" is observable in storage and in the database — not inferred
    /// from the status code.
    ///
    /// Revert-proofs, per hunk:
    /// - re-add `#[serde(default)]` on `dry_run` → `{}` performs a live
    ///   delete → 200 + the probe object disappears → this test fails;
    /// - drop `#[serde(deny_unknown_fields)]` → `{"dryRun": true}` (the
    ///   1.8.2 incident shape: the caller ASKED for a dry run) deserializes
    ///   to `dry_run: false` and deletes → fails.
    #[tokio::test]
    // Bounded (64 KiB) body reads on an in-process test router (#1608 exempts
    // bounded test-side collection; same pattern as the auth.rs router tests).
    #[allow(clippy::disallowed_methods)]
    async fn storage_gc_route_refuses_ambiguous_requests_without_deleting() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let _gc_guard = crate::services::storage_gc_service::storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: fixture.storage_dir.to_string_lossy().to_string(),
            })
            .expect("filesystem backend");
        let uid = uuid::Uuid::new_v4().simple().to_string();

        // One orphaned, soft-deleted artifact a live pass WILL reclaim: the
        // positive control (explicit live run deletes it) is what keeps the
        // negative controls (ambiguous requests delete nothing) honest.
        let probe_key = format!("generic/gc3501/{uid}/probe.bin");
        storage
            .put(&probe_key, bytes::Bytes::from_static(b"payload"))
            .await
            .expect("seed probe object");
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by, is_deleted) \
             VALUES ($1, $2, 'probe', '1.0', 7, 'cafe', 'application/octet-stream', $2, $3, \
                 true)",
        )
        .bind(fixture.repo_id)
        .bind(&probe_key)
        .bind(fixture.user_id)
        .execute(&fixture.pool)
        .await
        .expect("insert soft-deleted probe row");

        let admin = AuthExtension {
            user_id: fixture.user_id,
            username: fixture.username.clone(),
            is_admin: true,
            ..Default::default()
        };
        let app = router()
            .layer(axum::extract::Extension(admin))
            .with_state(fixture.state.clone());

        let post = |body: &'static str| {
            Request::builder()
                .method("POST")
                .uri("/")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        let probe_rows = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND storage_key = $2",
            )
            .bind(fixture.repo_id)
            .bind(&probe_key)
            .fetch_one(&fixture.pool)
            .await
            .expect("count probe rows")
        };

        // -- `{}`: the pre-fix silent live delete. Must be refused with the
        //    axum Json rejection (422) whose body names the missing field,
        //    and the probe must survive.
        let resp = app.clone().oneshot(post("{}")).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "`{{}}` must be refused, not treated as a live delete"
        );
        let body = axum::body::to_bytes(resp.into_body(), 65_536)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body).to_string();
        assert!(
            body.contains("dry_run"),
            "the refusal must name the missing field so the caller can fix it, got: {body}"
        );

        // -- `{"dryRun": true}`: the 1.8.2 incident shape — the caller asked
        //    for a dry run with the wrong key casing, and the old contract
        //    answered with a live delete. Must be refused, naming the key.
        let resp = app
            .clone()
            .oneshot(post(r#"{"dryRun": true}"#))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a typo'd key must not fall through to the destructive default"
        );
        let body = axum::body::to_bytes(resp.into_body(), 65_536)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body).to_string();
        assert!(
            body.contains("dryRun"),
            "the refusal must name the unknown key, got: {body}"
        );

        // Observable outcome of both refusals: NOTHING was deleted.
        assert!(
            storage.exists(&probe_key).await.expect("probe object"),
            "an ambiguous request must not delete storage objects"
        );
        assert_eq!(
            probe_rows().await,
            1,
            "an ambiguous request must not delete artifact rows"
        );

        // -- Positive control: the explicit destructive request still works,
        //    which also proves the seeded probe was genuinely reclaimable
        //    (i.e. the two assertions above did not pass vacuously).
        let resp = app
            .clone()
            .oneshot(post(r#"{"dry_run": false}"#))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the explicit live pass must keep working"
        );
        assert!(
            !storage.exists(&probe_key).await.expect("probe object"),
            "the explicit live pass must reclaim the orphaned probe object"
        );
    }

    // -- StorageGcApiDoc OpenAPI tests --

    #[test]
    fn test_openapi_doc_has_paths() {
        let doc = StorageGcApiDoc::openapi();
        assert!(
            !doc.paths.paths.is_empty(),
            "Expected at least 1 path, found {}",
            doc.paths.paths.len()
        );
    }

    #[test]
    fn test_openapi_doc_schemas_include_request_and_result() {
        let doc = StorageGcApiDoc::openapi();
        let schemas = &doc
            .components
            .as_ref()
            .expect("components should exist")
            .schemas;
        assert!(
            schemas.contains_key("StorageGcRequest"),
            "Schema should contain StorageGcRequest"
        );
        assert!(
            schemas.contains_key("StorageGcResult"),
            "Schema should contain StorageGcResult"
        );
    }

    #[test]
    fn test_openapi_doc_operation_ids() {
        let doc = StorageGcApiDoc::openapi();
        let json = serde_json::to_string(&doc).unwrap();
        assert!(
            json.contains("run_storage_gc"),
            "OpenAPI doc should contain operation ID 'run_storage_gc'"
        );
    }

    // -- StorageGcResult serialization contract tests --

    #[test]
    fn test_storage_gc_result_field_names_match_api_contract() {
        let result = StorageGcResult {
            dry_run: true,
            storage_keys_deleted: 3,
            artifacts_removed: 7,
            bytes_freed: 2048,
            errors: vec!["some error".to_string()],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(value.get("dry_run").is_some(), "Missing field 'dry_run'");
        assert!(
            value.get("storage_keys_deleted").is_some(),
            "Missing field 'storage_keys_deleted'"
        );
        assert!(
            value.get("artifacts_removed").is_some(),
            "Missing field 'artifacts_removed'"
        );
        assert!(
            value.get("bytes_freed").is_some(),
            "Missing field 'bytes_freed'"
        );
        assert!(value.get("errors").is_some(), "Missing field 'errors'");
    }

    #[test]
    fn test_storage_gc_result_empty_errors() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 10,
            artifacts_removed: 25,
            bytes_freed: 4096,
            errors: vec![],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: StorageGcResult = serde_json::from_str(&json).unwrap();

        assert!(!deserialized.dry_run);
        assert_eq!(deserialized.storage_keys_deleted, 10);
        assert_eq!(deserialized.artifacts_removed, 25);
        assert_eq!(deserialized.bytes_freed, 4096);
        assert!(deserialized.errors.is_empty());
    }

    #[test]
    fn test_storage_gc_result_populated_errors() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 2,
            artifacts_removed: 2,
            bytes_freed: 512,
            errors: vec![
                "Failed to delete key abc: not found".to_string(),
                "Failed to delete key xyz: permission denied".to_string(),
            ],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: StorageGcResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.errors.len(), 2);
        assert!(deserialized.errors[0].contains("abc"));
        assert!(deserialized.errors[1].contains("xyz"));
    }

    #[test]
    fn test_openapi_doc_every_path_has_an_operation() {
        // The router mixes a POST (run GC) and a GET (blob report); each
        // documented path must carry at least one of the two so the spec is
        // never missing a method.
        let doc = StorageGcApiDoc::openapi();
        for (path, item) in &doc.paths.paths {
            assert!(
                item.post.is_some() || item.get.is_some(),
                "Path {path} should have a GET or POST method"
            );
        }
    }

    #[test]
    fn test_openapi_doc_has_post_run_and_get_report() {
        // The merged doc keys paths by their full context path, so match by
        // suffix: there must be exactly two POST-bearing paths (instance-wide
        // run GC + per-repository run GC, #708) and exactly one GET-bearing
        // path ending in /oci-blob-report.
        let doc = StorageGcApiDoc::openapi();
        let post_paths = doc
            .paths
            .paths
            .values()
            .filter(|item| item.post.is_some())
            .count();
        let report_get = doc
            .paths
            .paths
            .iter()
            .filter(|(path, item)| path.ends_with("/oci-blob-report") && item.get.is_some())
            .count();
        assert_eq!(
            post_paths, 2,
            "exactly two POST paths (instance + per-repo run GC) expected"
        );
        assert_eq!(
            report_get, 1,
            "exactly one GET /oci-blob-report path expected"
        );
    }

    // -- Router test --

    #[test]
    fn test_router_returns_valid_router() {
        let _router = router();
    }

    #[test]
    fn test_repo_router_returns_valid_router() {
        let _router = repo_router();
    }

    // -- require_auth (repositories-nest optional auth) --

    #[test]
    fn test_require_auth_unwraps_present_extension() {
        let auth = AuthExtension {
            is_admin: true,
            ..Default::default()
        };
        let unwrapped = require_auth(Some(auth)).expect("present auth must pass");
        assert!(unwrapped.is_admin);
    }

    #[test]
    fn test_require_auth_rejects_absent_extension() {
        let err = require_auth(None).unwrap_err();
        match err {
            AppError::Unauthorized(msg) => {
                assert!(
                    msg.contains("Authentication required"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    // -- Per-repository storage-gc endpoint (web #708) --

    #[test]
    fn test_openapi_doc_includes_repository_storage_gc_operation() {
        let doc = StorageGcApiDoc::openapi();
        let json = serde_json::to_string(&doc).unwrap();
        assert!(
            json.contains("run_repository_storage_gc"),
            "OpenAPI doc should contain operation ID 'run_repository_storage_gc'"
        );
    }

    #[test]
    fn test_openapi_doc_repository_storage_gc_path() {
        // The exact path the web UI has called since the panel shipped —
        // a rename here silently re-breaks web #708.
        let doc = StorageGcApiDoc::openapi();
        let (path, item) = doc
            .paths
            .paths
            .iter()
            .find(|(path, _)| path.ends_with("/repositories/{key}/storage-gc"))
            .expect("doc must contain /api/v1/repositories/{key}/storage-gc");
        assert_eq!(path, "/api/v1/repositories/{key}/storage-gc");
        assert!(item.post.is_some(), "per-repo storage-gc must be a POST");
    }

    #[test]
    fn test_openapi_doc_repository_storage_gc_request_body_and_response() {
        let doc = StorageGcApiDoc::openapi();
        let json = serde_json::to_string(&doc).unwrap();
        // Same request/response contract as the instance-wide endpoint:
        // StorageGcRequest in, StorageGcResult out — the web client depends
        // on `bytes_freed` / `storage_keys_deleted` / `dry_run` / `errors`.
        let op_start = json
            .find("run_repository_storage_gc")
            .expect("operation present");
        let op_region = &json[op_start..];
        assert!(
            op_region.contains("StorageGcRequest"),
            "per-repo endpoint must accept StorageGcRequest"
        );
        assert!(
            op_region.contains("StorageGcResult"),
            "per-repo endpoint must return StorageGcResult"
        );
    }

    // -- OciBlobReportQuery deserialization (issue #1408) --

    #[test]
    fn test_oci_blob_report_query_absent_grace_hours() {
        let q: OciBlobReportQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.grace_hours, None);
    }

    #[test]
    fn test_oci_blob_report_query_explicit_grace_hours() {
        let q: OciBlobReportQuery = serde_json::from_str(r#"{"grace_hours": 48}"#).unwrap();
        assert_eq!(q.grace_hours, Some(48));
    }

    #[test]
    fn test_oci_blob_report_query_negative_grace_hours_parses() {
        // Negative values parse here; the service clamps them. The endpoint
        // must not reject a bad query param with a 4xx.
        let q: OciBlobReportQuery = serde_json::from_str(r#"{"grace_hours": -3}"#).unwrap();
        assert_eq!(q.grace_hours, Some(-3));
    }

    #[test]
    fn test_oci_blob_report_query_invalid_type_errors() {
        let result = serde_json::from_str::<OciBlobReportQuery>(r#"{"grace_hours": "soon"}"#);
        assert!(result.is_err());
    }

    // -- OpenAPI registration for the new report endpoint --

    #[test]
    fn test_openapi_doc_includes_blob_report_operation() {
        let doc = StorageGcApiDoc::openapi();
        let json = serde_json::to_string(&doc).unwrap();
        assert!(
            json.contains("oci_blob_report"),
            "OpenAPI doc should contain operation ID 'oci_blob_report'"
        );
    }

    // -- require_admin authorization gate --

    #[test]
    fn test_require_admin_allows_admin() {
        assert!(require_admin(true).is_ok());
    }

    #[test]
    fn test_require_admin_rejects_non_admin() {
        let err = require_admin(false).unwrap_err();
        match err {
            AppError::Unauthorized(msg) => {
                assert!(
                    msg.contains("Admin privileges required"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    // -- resolve_report_grace_hours query-param mapping --

    #[test]
    fn test_resolve_report_grace_hours_absent_is_zero() {
        // Absent resolves to 0, which the service clamps to the default
        // window; the handler must not itself substitute a default.
        assert_eq!(resolve_report_grace_hours(None), 0);
    }

    #[test]
    fn test_resolve_report_grace_hours_passes_through_value() {
        assert_eq!(resolve_report_grace_hours(Some(48)), 48);
        assert_eq!(resolve_report_grace_hours(Some(0)), 0);
    }

    #[test]
    fn test_resolve_report_grace_hours_passes_through_negative() {
        // Negative values are forwarded unchanged; clamping is the service's
        // responsibility, not the handler's.
        assert_eq!(resolve_report_grace_hours(Some(-7)), -7);
    }

    #[test]
    fn test_openapi_doc_includes_blob_report_schemas() {
        let doc = StorageGcApiDoc::openapi();
        let schemas = &doc
            .components
            .as_ref()
            .expect("components should exist")
            .schemas;
        assert!(
            schemas.contains_key("OciBlobFootprintReport"),
            "Schema should contain OciBlobFootprintReport"
        );
        assert!(
            schemas.contains_key("OciBlobRepoFootprint"),
            "Schema should contain OciBlobRepoFootprint"
        );
    }
}
