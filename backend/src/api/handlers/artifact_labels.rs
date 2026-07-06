//! Artifact label management handlers.

use axum::{
    extract::{Extension, Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::artifacts::check_artifact_visibility;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::artifact_label_service::{ArtifactLabel, ArtifactLabelService};
use crate::services::repository_label_service::LabelEntry;
use crate::services::sync_policy_service::SyncPolicyService;

#[derive(OpenApi)]
#[openapi(
    paths(list_labels, set_labels, add_label, delete_label),
    components(schemas(
        ArtifactLabelResponse,
        ArtifactLabelsListResponse,
        SetArtifactLabelsRequest,
        ArtifactLabelEntrySchema,
        AddArtifactLabelRequest,
    )),
    tags((name = "artifact-labels", description = "Artifact label management"))
)]
pub struct ArtifactLabelsApiDoc;

/// Create artifact label routes (nested under /api/v1/artifacts/:id/labels).
pub fn artifact_labels_router() -> Router<SharedState> {
    Router::new()
        .route("/:id/labels", get(list_labels).put(set_labels))
        .route(
            "/:id/labels/:label_key",
            post(add_label).delete(delete_label),
        )
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactLabelResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub key: String,
    pub value: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactLabelsListResponse {
    pub items: Vec<ArtifactLabelResponse>,
    pub total: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetArtifactLabelsRequest {
    pub labels: Vec<ArtifactLabelEntrySchema>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
pub struct ArtifactLabelEntrySchema {
    pub key: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddArtifactLabelRequest {
    #[serde(default)]
    pub value: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Authorize a label read: require an authenticated caller.
///
/// Repository visibility/scope is enforced separately by
/// [`check_artifact_visibility`] (which needs DB access) at the call site.
fn authorize_label_read(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    require_auth(auth)
}

/// Authorize a label mutation: require an authenticated caller that also holds
/// the `write` scope, mirroring the sibling artifact-mutation handlers.
///
/// Repository visibility/scope is enforced separately by
/// [`check_artifact_visibility`] (which needs DB access) at the call site.
fn authorize_label_write(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    Ok(auth)
}

fn label_to_response(label: ArtifactLabel) -> ArtifactLabelResponse {
    ArtifactLabelResponse {
        id: label.id,
        artifact_id: label.artifact_id,
        key: label.label_key,
        value: label.label_value,
        created_at: label.created_at,
    }
}

fn labels_list_response(labels: Vec<ArtifactLabel>) -> ArtifactLabelsListResponse {
    let items: Vec<ArtifactLabelResponse> = labels.into_iter().map(label_to_response).collect();
    let total = items.len();
    ArtifactLabelsListResponse { items, total }
}

/// Re-evaluate sync policies after an artifact's labels change.
async fn reevaluate_sync_for_artifact(db: &sqlx::PgPool, artifact_id: Uuid) {
    let sync_svc = SyncPolicyService::new(db.clone());
    if let Err(e) = sync_svc.evaluate_for_artifact(artifact_id).await {
        tracing::warn!(
            "Sync policy re-evaluation failed for artifact {}: {}",
            artifact_id,
            e
        );
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all labels on an artifact
#[utoipa::path(
    get,
    operation_id = "list_artifact_labels",
    path = "/{id}/labels",
    context_path = "/api/v1/artifacts",
    tag = "artifact-labels",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Labels retrieved", body = ArtifactLabelsListResponse),
        (status = 404, description = "Artifact not found")
    )
)]
async fn list_labels(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactLabelsListResponse>> {
    let auth = authorize_label_read(auth)?;

    check_artifact_visibility(&Some(auth), id, &state.db).await?;
    verify_artifact_exists(&state.db, id).await?;

    let label_service = ArtifactLabelService::new(state.db.clone());
    let labels = label_service.get_labels(id).await?;

    Ok(Json(labels_list_response(labels)))
}

/// Set all labels on an artifact (replaces existing)
#[utoipa::path(
    put,
    operation_id = "set_artifact_labels",
    path = "/{id}/labels",
    context_path = "/api/v1/artifacts",
    tag = "artifact-labels",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    request_body = SetArtifactLabelsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Labels updated", body = ArtifactLabelsListResponse),
        (status = 404, description = "Artifact not found")
    )
)]
async fn set_labels(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<SetArtifactLabelsRequest>,
) -> Result<Json<ArtifactLabelsListResponse>> {
    let auth = authorize_label_write(auth)?;

    check_artifact_visibility(&Some(auth), id, &state.db).await?;
    verify_artifact_exists(&state.db, id).await?;

    let entries: Vec<LabelEntry> = payload
        .labels
        .into_iter()
        .map(|l| LabelEntry {
            key: l.key,
            value: l.value,
        })
        .collect();

    let label_service = ArtifactLabelService::new(state.db.clone());
    let labels = label_service.set_labels(id, &entries).await?;

    reevaluate_sync_for_artifact(&state.db, id).await;

    Ok(Json(labels_list_response(labels)))
}

/// Add or update a single label on an artifact
#[utoipa::path(
    post,
    operation_id = "add_artifact_label",
    path = "/{id}/labels/{label_key}",
    context_path = "/api/v1/artifacts",
    tag = "artifact-labels",
    params(
        ("id" = Uuid, Path, description = "Artifact ID"),
        ("label_key" = String, Path, description = "Label key to set")
    ),
    request_body = AddArtifactLabelRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Label added/updated", body = ArtifactLabelResponse),
        (status = 404, description = "Artifact not found")
    )
)]
async fn add_label(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((id, label_key)): Path<(Uuid, String)>,
    Json(payload): Json<AddArtifactLabelRequest>,
) -> Result<Json<ArtifactLabelResponse>> {
    let auth = authorize_label_write(auth)?;

    check_artifact_visibility(&Some(auth), id, &state.db).await?;
    verify_artifact_exists(&state.db, id).await?;

    let label_service = ArtifactLabelService::new(state.db.clone());
    let label = label_service
        .add_label(id, &label_key, &payload.value)
        .await?;

    reevaluate_sync_for_artifact(&state.db, id).await;

    Ok(Json(label_to_response(label)))
}

/// Delete a label by key from an artifact
#[utoipa::path(
    delete,
    operation_id = "delete_artifact_label",
    path = "/{id}/labels/{label_key}",
    context_path = "/api/v1/artifacts",
    tag = "artifact-labels",
    params(
        ("id" = Uuid, Path, description = "Artifact ID"),
        ("label_key" = String, Path, description = "Label key to remove")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Label removed"),
        (status = 404, description = "Artifact not found")
    )
)]
async fn delete_label(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((id, label_key)): Path<(Uuid, String)>,
) -> Result<axum::http::StatusCode> {
    let auth = authorize_label_write(auth)?;

    check_artifact_visibility(&Some(auth), id, &state.db).await?;
    verify_artifact_exists(&state.db, id).await?;

    let label_service = ArtifactLabelService::new(state.db.clone());
    label_service.remove_label(id, &label_key).await?;

    reevaluate_sync_for_artifact(&state.db, id).await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Verify an artifact exists (not deleted).
async fn verify_artifact_exists(db: &sqlx::PgPool, artifact_id: Uuid) -> Result<()> {
    let exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = $1 AND is_deleted = false)",
    )
    .bind(artifact_id)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let exists = exists.unwrap_or(false);

    if !exists {
        return Err(AppError::NotFound(format!(
            "Artifact {artifact_id} not found"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_labels_request_deserialization() {
        let json = r#"{"labels": [{"key": "distribution", "value": "production"}, {"key": "support", "value": "ltr"}]}"#;
        let req: SetArtifactLabelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.labels.len(), 2);
        assert_eq!(req.labels[0].key, "distribution");
        assert_eq!(req.labels[0].value, "production");
    }

    #[test]
    fn test_set_labels_request_empty_labels() {
        let json = r#"{"labels": []}"#;
        let req: SetArtifactLabelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.labels.len(), 0);
    }

    #[test]
    fn test_add_label_request_with_value() {
        let json = r#"{"value": "production"}"#;
        let req: AddArtifactLabelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.value, "production");
    }

    #[test]
    fn test_add_label_request_empty_value_default() {
        let json = r#"{}"#;
        let req: AddArtifactLabelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.value, "");
    }

    #[test]
    fn test_label_response_serialization() {
        let resp = ArtifactLabelResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            key: "distribution".to_string(),
            value: "production".to_string(),
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("distribution"));
        assert!(json.contains("production"));
        assert!(json.contains("artifact_id"));
    }

    #[test]
    fn test_labels_list_response_serialization() {
        let resp = ArtifactLabelsListResponse {
            items: vec![ArtifactLabelResponse {
                id: Uuid::nil(),
                artifact_id: Uuid::nil(),
                key: "env".to_string(),
                value: "prod".to_string(),
                created_at: chrono::Utc::now(),
            }],
            total: 1,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"total\":1"));
        assert!(json.contains("\"items\""));
    }

    #[test]
    fn test_label_entry_schema_with_default_value() {
        let json = r#"{"key": "production"}"#;
        let entry: ArtifactLabelEntrySchema = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "production");
        assert_eq!(entry.value, "");
    }

    #[test]
    fn test_label_to_response_mapping() {
        let label = ArtifactLabel {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            label_key: "distribution".to_string(),
            label_value: "production".to_string(),
            created_at: chrono::Utc::now(),
        };
        let resp = label_to_response(label);
        assert_eq!(resp.key, "distribution");
        assert_eq!(resp.value, "production");
    }

    #[test]
    fn test_labels_list_response_helper() {
        let labels = vec![
            ArtifactLabel {
                id: Uuid::nil(),
                artifact_id: Uuid::nil(),
                label_key: "a".to_string(),
                label_value: "1".to_string(),
                created_at: chrono::Utc::now(),
            },
            ArtifactLabel {
                id: Uuid::nil(),
                artifact_id: Uuid::nil(),
                label_key: "b".to_string(),
                label_value: "2".to_string(),
                created_at: chrono::Utc::now(),
            },
        ];
        let resp = labels_list_response(labels);
        assert_eq!(resp.total, 2);
        assert_eq!(resp.items.len(), 2);
    }

    #[test]
    fn test_labels_list_response_empty() {
        let resp = labels_list_response(vec![]);
        assert_eq!(resp.total, 0);
        assert!(resp.items.is_empty());
    }

    #[test]
    fn test_label_response_json_contract() {
        let resp = ArtifactLabelResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            key: "env".to_string(),
            value: "production".to_string(),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-01-15T10:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert!(json.get("id").is_some());
        assert!(json.get("artifact_id").is_some());
        assert!(json.get("key").is_some());
        assert!(json.get("value").is_some());
        assert!(json.get("created_at").is_some());
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 5);
    }

    #[test]
    fn test_set_labels_request_rejects_missing_labels_field() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<SetArtifactLabelsRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // require_auth
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_auth_none_returns_error() {
        let result = require_auth(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_require_auth_some_returns_ok() {
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
        let result = require_auth(Some(auth.clone()));
        assert!(result.is_ok());
        let returned = result.unwrap();
        assert_eq!(returned.user_id, auth.user_id);
        assert_eq!(returned.username, "admin");
    }

    // -----------------------------------------------------------------------
    // authorize_label_read / authorize_label_write
    // -----------------------------------------------------------------------

    fn jwt_auth() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    #[test]
    fn test_authorize_label_read_none_returns_error() {
        let result = authorize_label_read(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorize_label_read_some_returns_ok() {
        let result = authorize_label_read(Some(jwt_auth()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_label_write_none_returns_error() {
        let result = authorize_label_write(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorize_label_write_jwt_session_returns_ok() {
        // JWT session (is_api_token = false) is not scope-restricted.
        let result = authorize_label_write(Some(jwt_auth()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_label_write_unrestricted_token_returns_ok() {
        // API token with no scope restriction (scopes = None) passes write scope.
        let mut auth = jwt_auth();
        auth.is_api_token = true;
        auth.scopes = None;
        let result = authorize_label_write(Some(auth));
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_label_write_read_only_token_returns_error() {
        // Read-only scoped API token must fail the write-scope check.
        let mut auth = jwt_auth();
        auth.is_api_token = true;
        auth.scopes = Some(vec!["read".to_string()]);
        let result = authorize_label_write(Some(auth));
        assert!(result.is_err());
    }

    #[test]
    fn test_authorize_label_write_token_with_write_scope_returns_ok() {
        let mut auth = jwt_auth();
        auth.is_api_token = true;
        auth.scopes = Some(vec!["read".to_string(), "write".to_string()]);
        let result = authorize_label_write(Some(auth));
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // label_to_response field mapping
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_to_response_maps_label_key_to_key() {
        let id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let ts = chrono::Utc::now();
        let label = ArtifactLabel {
            id,
            artifact_id,
            label_key: "environment".to_string(),
            label_value: "staging".to_string(),
            created_at: ts,
        };
        let resp = label_to_response(label);
        assert_eq!(resp.id, id);
        assert_eq!(resp.artifact_id, artifact_id);
        assert_eq!(resp.key, "environment");
        assert_eq!(resp.value, "staging");
        assert_eq!(resp.created_at, ts);
    }

    #[test]
    fn test_label_to_response_empty_value() {
        let label = ArtifactLabel {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            label_key: "flag".to_string(),
            label_value: "".to_string(),
            created_at: chrono::Utc::now(),
        };
        let resp = label_to_response(label);
        assert_eq!(resp.key, "flag");
        assert_eq!(resp.value, "");
    }

    // -----------------------------------------------------------------------
    // labels_list_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_labels_list_response_total_matches_items() {
        let labels = vec![
            ArtifactLabel {
                id: Uuid::new_v4(),
                artifact_id: Uuid::nil(),
                label_key: "x".to_string(),
                label_value: "1".to_string(),
                created_at: chrono::Utc::now(),
            },
            ArtifactLabel {
                id: Uuid::new_v4(),
                artifact_id: Uuid::nil(),
                label_key: "y".to_string(),
                label_value: "2".to_string(),
                created_at: chrono::Utc::now(),
            },
            ArtifactLabel {
                id: Uuid::new_v4(),
                artifact_id: Uuid::nil(),
                label_key: "z".to_string(),
                label_value: "3".to_string(),
                created_at: chrono::Utc::now(),
            },
        ];
        let resp = labels_list_response(labels);
        assert_eq!(resp.total, 3);
        assert_eq!(resp.items.len(), 3);
        assert_eq!(resp.items[0].key, "x");
        assert_eq!(resp.items[1].key, "y");
        assert_eq!(resp.items[2].key, "z");
    }

    #[test]
    fn test_labels_list_response_maps_all_fields() {
        let id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let labels = vec![ArtifactLabel {
            id,
            artifact_id,
            label_key: "env".to_string(),
            label_value: "prod".to_string(),
            created_at: chrono::Utc::now(),
        }];
        let resp = labels_list_response(labels);
        assert_eq!(resp.items[0].id, id);
        assert_eq!(resp.items[0].artifact_id, artifact_id);
        assert_eq!(resp.items[0].key, "env");
        assert_eq!(resp.items[0].value, "prod");
    }

    // -----------------------------------------------------------------------
    // ArtifactLabelEntrySchema
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_entry_schema_with_value() {
        let json = r#"{"key": "env", "value": "prod"}"#;
        let entry: ArtifactLabelEntrySchema = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "env");
        assert_eq!(entry.value, "prod");
    }

    #[test]
    fn test_label_entry_schema_serialization() {
        let entry = ArtifactLabelEntrySchema {
            key: "tier".to_string(),
            value: "critical".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"key\":\"tier\""));
        assert!(json.contains("\"value\":\"critical\""));
    }

    #[test]
    fn test_label_entry_schema_clone() {
        let entry = ArtifactLabelEntrySchema {
            key: "region".to_string(),
            value: "us-east-1".to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.key, entry.key);
        assert_eq!(cloned.value, entry.value);
    }

    // -----------------------------------------------------------------------
    // SetArtifactLabelsRequest -> LabelEntry conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_labels_to_label_entries_conversion() {
        let json =
            r#"{"labels": [{"key": "env", "value": "prod"}, {"key": "tier", "value": "1"}]}"#;
        let req: SetArtifactLabelsRequest = serde_json::from_str(json).unwrap();
        let entries: Vec<LabelEntry> = req
            .labels
            .into_iter()
            .map(|l| LabelEntry {
                key: l.key,
                value: l.value,
            })
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "env");
        assert_eq!(entries[0].value, "prod");
        assert_eq!(entries[1].key, "tier");
        assert_eq!(entries[1].value, "1");
    }

    // -----------------------------------------------------------------------
    // ArtifactLabelsListResponse JSON contract
    // -----------------------------------------------------------------------

    #[test]
    fn test_labels_list_response_json_contract() {
        let resp = ArtifactLabelsListResponse {
            items: vec![ArtifactLabelResponse {
                id: Uuid::nil(),
                artifact_id: Uuid::nil(),
                key: "a".to_string(),
                value: "1".to_string(),
                created_at: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            }],
            total: 1,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("items"));
        assert!(obj.contains_key("total"));
        let items = json["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        let item = &items[0];
        let item_obj = item.as_object().unwrap();
        assert_eq!(item_obj.len(), 5);
    }

    // -----------------------------------------------------------------------
    // AddArtifactLabelRequest edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_label_request_explicit_empty_value() {
        let json = r#"{"value": ""}"#;
        let req: AddArtifactLabelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.value, "");
    }

    #[test]
    fn test_add_label_request_unicode_value() {
        let json = r#"{"value": "production-日本"}"#;
        let req: AddArtifactLabelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.value, "production-日本");
    }

    // -----------------------------------------------------------------------
    // ArtifactLabelResponse serialization field names
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_response_uses_key_not_label_key() {
        let resp = ArtifactLabelResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            key: "test".to_string(),
            value: "val".to_string(),
            created_at: chrono::Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert!(json.get("key").is_some());
        assert!(json.get("value").is_some());
        assert!(json.get("label_key").is_none());
        assert!(json.get("label_value").is_none());
    }
}
