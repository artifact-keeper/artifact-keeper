//! Storage garbage collection API handler.

use axum::extract::Extension;
use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use utoipa::{OpenApi, ToSchema};

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::storage_gc_service::{StorageGcResult, StorageGcService};

#[derive(OpenApi)]
#[openapi(
    paths(run_storage_gc),
    components(schemas(StorageGcRequest, StorageGcResult))
)]
pub struct StorageGcApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new().route("/", post(run_storage_gc))
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

    let service = StorageGcService::new(
        state.db.clone(),
        state.storage.clone(),
        state.config.storage_backend.clone(),
    );
    let result = service.run_gc(payload.dry_run).await?;
    Ok(Json(result))
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
    fn test_openapi_doc_path_has_post_method() {
        let doc = StorageGcApiDoc::openapi();
        for item in doc.paths.paths.values() {
            assert!(item.post.is_some(), "Path should have POST method");
        }
    }

    // -- Router test --

    #[test]
    fn test_router_returns_valid_router() {
        let _router = router();
    }
}
