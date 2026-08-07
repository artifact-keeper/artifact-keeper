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
#[derive(Debug, Deserialize, ToSchema)]
pub struct StorageGcRequest {
    /// When true, report what would be deleted without actually deleting.
    #[serde(default)]
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

    let service = StorageGcService::new(state.db.clone(), state.storage_registry.clone());
    let result = service.run_gc(payload.dry_run).await?;

    // Post-GC storage-stats refresh (#2056/#2601): the *scheduled* GC pass
    // already recomputes the materialized repository/path storage stats right
    // after reclaim (scheduler_service), but the admin-triggered pass left
    // them stale until the next cron tick. Mirror the scheduler here so an
    // operator-initiated GC settles the reported numbers too. Best-effort:
    // a refresh failure must not fail the GC that already ran.
    if !payload.dry_run {
        let stats_service = crate::services::storage_stats_service::StorageStatsService::new(
            state.db.clone(),
            &state.config.storage_backend,
        );
        if let Err(e) = stats_service.recompute_all().await {
            tracing::warn!("Post-GC storage-stats refresh failed: {}", e);
        }
    }

    Ok(Json(result))
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

    let service = StorageGcService::new(state.db.clone(), state.storage_registry.clone());
    let result = service
        .run_gc_for_repository(repo.id, payload.dry_run)
        .await?;

    // Mirror the admin endpoint (#2056/#2601): settle the materialized
    // storage stats after a live pass instead of leaving them stale until
    // the next cron tick. Best-effort — the GC already ran.
    if !payload.dry_run {
        let stats_service = crate::services::storage_stats_service::StorageStatsService::new(
            state.db.clone(),
            &state.config.storage_backend,
        );
        if let Err(e) = stats_service.recompute_all().await {
            tracing::warn!("Post-GC storage-stats refresh failed: {}", e);
        }
    }

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

    #[test]
    fn test_storage_gc_request_default_dry_run() {
        let req: StorageGcRequest = serde_json::from_str("{}").unwrap();
        assert!(!req.dry_run);
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

    #[test]
    fn test_storage_gc_request_extra_fields_ignored() {
        let req: StorageGcRequest =
            serde_json::from_str(r#"{"dry_run": true, "unknown_field": 42}"#).unwrap();
        assert!(req.dry_run);
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
