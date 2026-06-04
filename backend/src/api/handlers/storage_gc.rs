//! Storage garbage collection API handler.

use axum::extract::{Extension, Query};
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
use crate::services::storage_gc_service::{
    OciBlobFootprintReport, OciBlobRepoFootprint, StorageGcResult, StorageGcService,
};

#[derive(OpenApi)]
#[openapi(
    paths(run_storage_gc, oci_blob_report),
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
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }

    let service = StorageGcService::new(state.db.clone(), state.storage_registry.clone());
    let result = service.run_gc(payload.dry_run).await?;
    Ok(Json(result))
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
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }

    let service = StorageGcService::new(state.db.clone(), state.storage_registry.clone());
    let report = service
        .oci_blob_footprint_report(query.grace_hours.unwrap_or_default())
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
        // suffix: there must be exactly one POST-bearing path (run GC) and
        // exactly one GET-bearing path ending in /oci-blob-report.
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
        assert_eq!(post_paths, 1, "exactly one POST path (run GC) expected");
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
