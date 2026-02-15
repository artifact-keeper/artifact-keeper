//! Repository label management handlers.

use axum::{
    extract::{Extension, Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::repository_label_service::{
    LabelEntry, RepositoryLabel, RepositoryLabelService,
};
use crate::services::repository_service::RepositoryService;
use crate::services::sync_policy_service::SyncPolicyService;

#[derive(OpenApi)]
#[openapi(
    paths(list_labels, set_labels, add_label, delete_label),
    components(schemas(LabelResponse, SetLabelsRequest, LabelEntrySchema, AddLabelRequest, LabelsListResponse)),
    tags((name = "repository-labels", description = "Repository label management"))
)]
pub struct RepositoryLabelsApiDoc;

/// Create repository label routes (nested under /api/v1/repositories/:key/labels).
pub fn repo_labels_router() -> Router<SharedState> {
    Router::new()
        .route("/:key/labels", get(list_labels).put(set_labels))
        .route(
            "/:key/labels/:label_key",
            post(add_label).delete(delete_label),
        )
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct LabelResponse {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub key: String,
    pub value: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LabelsListResponse {
    pub items: Vec<LabelResponse>,
    pub total: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetLabelsRequest {
    pub labels: Vec<LabelEntrySchema>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
pub struct LabelEntrySchema {
    pub key: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddLabelRequest {
    #[serde(default)]
    pub value: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

fn label_to_response(label: RepositoryLabel) -> LabelResponse {
    LabelResponse {
        id: label.id,
        repository_id: label.repository_id,
        key: label.label_key,
        value: label.label_value,
        created_at: label.created_at,
    }
}

fn labels_list_response(labels: Vec<RepositoryLabel>) -> LabelsListResponse {
    let items: Vec<LabelResponse> = labels.into_iter().map(label_to_response).collect();
    let total = items.len();
    LabelsListResponse { items, total }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all labels on a repository
#[utoipa::path(
    get,
    operation_id = "list_repo_labels",
    path = "/{key}/labels",
    context_path = "/api/v1/repositories",
    tag = "repository-labels",
    params(
        ("key" = String, Path, description = "Repository key")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Labels retrieved", body = LabelsListResponse),
        (status = 404, description = "Repository not found")
    )
)]
async fn list_labels(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<LabelsListResponse>> {
    let _auth = require_auth(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let label_service = RepositoryLabelService::new(state.db.clone());
    let labels = label_service.get_labels(repo.id).await?;

    Ok(Json(labels_list_response(labels)))
}

/// Set all labels on a repository (replaces existing)
#[utoipa::path(
    put,
    operation_id = "set_repo_labels",
    path = "/{key}/labels",
    context_path = "/api/v1/repositories",
    tag = "repository-labels",
    params(
        ("key" = String, Path, description = "Repository key")
    ),
    request_body = SetLabelsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Labels updated", body = LabelsListResponse),
        (status = 404, description = "Repository not found")
    )
)]
async fn set_labels(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<SetLabelsRequest>,
) -> Result<Json<LabelsListResponse>> {
    let _auth = require_auth(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let entries: Vec<LabelEntry> = payload
        .labels
        .into_iter()
        .map(|l| LabelEntry {
            key: l.key,
            value: l.value,
        })
        .collect();

    let label_service = RepositoryLabelService::new(state.db.clone());
    let labels = label_service.set_labels(repo.id, &entries).await?;

    // Re-evaluate sync policies after label change
    let sync_svc = SyncPolicyService::new(state.db.clone());
    if let Err(e) = sync_svc.evaluate_for_repository(repo.id).await {
        tracing::warn!(
            "Sync policy re-evaluation failed for repo {}: {}",
            repo.id,
            e
        );
    }

    Ok(Json(labels_list_response(labels)))
}

/// Add or update a single label
#[utoipa::path(
    post,
    operation_id = "add_repo_label",
    path = "/{key}/labels/{label_key}",
    context_path = "/api/v1/repositories",
    tag = "repository-labels",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("label_key" = String, Path, description = "Label key to set")
    ),
    request_body = AddLabelRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Label added/updated", body = LabelResponse),
        (status = 404, description = "Repository not found")
    )
)]
async fn add_label(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, label_key)): Path<(String, String)>,
    Json(payload): Json<AddLabelRequest>,
) -> Result<Json<LabelResponse>> {
    let _auth = require_auth(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let label_service = RepositoryLabelService::new(state.db.clone());
    let label = label_service
        .add_label(repo.id, &label_key, &payload.value)
        .await?;

    // Re-evaluate sync policies after label change
    let sync_svc = SyncPolicyService::new(state.db.clone());
    if let Err(e) = sync_svc.evaluate_for_repository(repo.id).await {
        tracing::warn!(
            "Sync policy re-evaluation failed for repo {}: {}",
            repo.id,
            e
        );
    }

    Ok(Json(label_to_response(label)))
}

/// Delete a label by key
#[utoipa::path(
    delete,
    operation_id = "delete_repo_label",
    path = "/{key}/labels/{label_key}",
    context_path = "/api/v1/repositories",
    tag = "repository-labels",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("label_key" = String, Path, description = "Label key to remove")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Label removed"),
        (status = 404, description = "Repository or label not found")
    )
)]
async fn delete_label(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, label_key)): Path<(String, String)>,
) -> Result<axum::http::StatusCode> {
    let _auth = require_auth(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let label_service = RepositoryLabelService::new(state.db.clone());
    label_service.remove_label(repo.id, &label_key).await?;

    // Re-evaluate sync policies after label change
    let sync_svc = SyncPolicyService::new(state.db.clone());
    if let Err(e) = sync_svc.evaluate_for_repository(repo.id).await {
        tracing::warn!(
            "Sync policy re-evaluation failed for repo {}: {}",
            repo.id,
            e
        );
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_labels_request_deserialization() {
        let json =
            r#"{"labels": [{"key": "env", "value": "prod"}, {"key": "tier", "value": "1"}]}"#;
        let req: SetLabelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.labels.len(), 2);
        assert_eq!(req.labels[0].key, "env");
        assert_eq!(req.labels[0].value, "prod");
    }

    #[test]
    fn test_set_labels_request_empty_labels() {
        let json = r#"{"labels": []}"#;
        let req: SetLabelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.labels.len(), 0);
    }

    #[test]
    fn test_add_label_request_with_value() {
        let json = r#"{"value": "production"}"#;
        let req: AddLabelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.value, "production");
    }

    #[test]
    fn test_add_label_request_empty_value_default() {
        let json = r#"{}"#;
        let req: AddLabelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.value, "");
    }

    #[test]
    fn test_label_response_serialization() {
        let resp = LabelResponse {
            id: uuid::Uuid::nil(),
            repository_id: uuid::Uuid::nil(),
            key: "env".to_string(),
            value: "staging".to_string(),
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("env"));
        assert!(json.contains("staging"));
        assert!(json.contains("repository_id"));
    }

    #[test]
    fn test_labels_list_response_serialization() {
        let resp = LabelsListResponse {
            items: vec![LabelResponse {
                id: uuid::Uuid::nil(),
                repository_id: uuid::Uuid::nil(),
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
        let entry: LabelEntrySchema = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "production");
        assert_eq!(entry.value, "");
    }

    #[test]
    fn test_label_entry_schema_roundtrip() {
        let entry = LabelEntrySchema {
            key: "region".to_string(),
            value: "eu-west-1".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: LabelEntrySchema = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "region");
        assert_eq!(deserialized.value, "eu-west-1");
    }

    #[test]
    fn test_label_to_response_mapping() {
        let label = RepositoryLabel {
            id: uuid::Uuid::nil(),
            repository_id: uuid::Uuid::nil(),
            label_key: "env".to_string(),
            label_value: "production".to_string(),
            created_at: chrono::Utc::now(),
        };
        let resp = label_to_response(label);
        assert_eq!(resp.key, "env");
        assert_eq!(resp.value, "production");
        assert_eq!(resp.id, uuid::Uuid::nil());
    }

    #[test]
    fn test_labels_list_response_helper() {
        let labels = vec![
            RepositoryLabel {
                id: uuid::Uuid::nil(),
                repository_id: uuid::Uuid::nil(),
                label_key: "a".to_string(),
                label_value: "1".to_string(),
                created_at: chrono::Utc::now(),
            },
            RepositoryLabel {
                id: uuid::Uuid::nil(),
                repository_id: uuid::Uuid::nil(),
                label_key: "b".to_string(),
                label_value: "2".to_string(),
                created_at: chrono::Utc::now(),
            },
        ];
        let resp = labels_list_response(labels);
        assert_eq!(resp.total, 2);
        assert_eq!(resp.items.len(), 2);
        assert_eq!(resp.items[0].key, "a");
        assert_eq!(resp.items[1].key, "b");
    }

    #[test]
    fn test_labels_list_response_empty() {
        let resp = labels_list_response(vec![]);
        assert_eq!(resp.total, 0);
        assert!(resp.items.is_empty());
    }

    // -----------------------------------------------------------------------
    // JSON contract tests — verify exact field names match API contract
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_response_json_contract() {
        let resp = LabelResponse {
            id: uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            repository_id: uuid::Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap(),
            key: "env".to_string(),
            value: "production".to_string(),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-01-15T10:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();

        // Verify exact field names (clients depend on these)
        assert!(json.get("id").is_some(), "Missing 'id' field");
        assert!(
            json.get("repository_id").is_some(),
            "Missing 'repository_id' field"
        );
        assert!(json.get("key").is_some(), "Missing 'key' field");
        assert!(json.get("value").is_some(), "Missing 'value' field");
        assert!(
            json.get("created_at").is_some(),
            "Missing 'created_at' field"
        );

        // Verify no unexpected fields
        let obj = json.as_object().unwrap();
        assert_eq!(
            obj.len(),
            5,
            "LabelResponse should have exactly 5 fields, got: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_labels_list_response_json_contract() {
        let resp = LabelsListResponse {
            items: vec![],
            total: 0,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();

        assert!(json.get("items").is_some(), "Missing 'items' field");
        assert!(json.get("total").is_some(), "Missing 'total' field");
        assert!(json["items"].is_array());
        assert_eq!(json["total"], 0);
    }

    #[test]
    fn test_set_labels_request_rejects_missing_labels_field() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<SetLabelsRequest>(json);
        assert!(
            result.is_err(),
            "SetLabelsRequest should require 'labels' field"
        );
    }

    #[test]
    fn test_set_labels_request_rejects_invalid_label_entry() {
        // Missing required 'key' field
        let json = r#"{"labels": [{"value": "prod"}]}"#;
        let result = serde_json::from_str::<SetLabelsRequest>(json);
        assert!(
            result.is_err(),
            "LabelEntrySchema should require 'key' field"
        );
    }

    #[test]
    fn test_add_label_request_accepts_null_body() {
        // value has #[serde(default)], so an empty object should work
        let req: AddLabelRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(req.value, "");
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_entry_schema_unicode_key() {
        let json = r#"{"key": "日本語", "value": "テスト"}"#;
        let entry: LabelEntrySchema = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "日本語");
        assert_eq!(entry.value, "テスト");
    }

    #[test]
    fn test_set_labels_large_batch() {
        let labels: Vec<serde_json::Value> = (0..100)
            .map(|i| {
                serde_json::json!({
                    "key": format!("label-{i}"),
                    "value": format!("value-{i}")
                })
            })
            .collect();
        let json = serde_json::json!({ "labels": labels });
        let req: SetLabelsRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.labels.len(), 100);
        assert_eq!(req.labels[99].key, "label-99");
    }

    #[test]
    fn test_label_to_response_maps_db_fields_to_api_fields() {
        // Verify the field name mapping: label_key -> key, label_value -> value
        let label = RepositoryLabel {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            label_key: "db_field_name".to_string(),
            label_value: "db_field_value".to_string(),
            created_at: chrono::Utc::now(),
        };
        let resp = label_to_response(label.clone());

        // API uses 'key'/'value', DB uses 'label_key'/'label_value'
        assert_eq!(resp.key, label.label_key);
        assert_eq!(resp.value, label.label_value);
        assert_eq!(resp.id, label.id);
        assert_eq!(resp.repository_id, label.repository_id);
    }

    #[test]
    fn test_labels_list_response_total_matches_items_count() {
        let labels = vec![
            RepositoryLabel {
                id: uuid::Uuid::new_v4(),
                repository_id: uuid::Uuid::new_v4(),
                label_key: "x".to_string(),
                label_value: "1".to_string(),
                created_at: chrono::Utc::now(),
            },
            RepositoryLabel {
                id: uuid::Uuid::new_v4(),
                repository_id: uuid::Uuid::new_v4(),
                label_key: "y".to_string(),
                label_value: "2".to_string(),
                created_at: chrono::Utc::now(),
            },
            RepositoryLabel {
                id: uuid::Uuid::new_v4(),
                repository_id: uuid::Uuid::new_v4(),
                label_key: "z".to_string(),
                label_value: "3".to_string(),
                created_at: chrono::Utc::now(),
            },
        ];
        let resp = labels_list_response(labels);
        assert_eq!(resp.total, resp.items.len());
        assert_eq!(resp.total, 3);
    }

    #[test]
    fn test_label_entry_schema_value_with_whitespace() {
        let json = r#"{"key": "description", "value": "  spaces and\ttabs  "}"#;
        let entry: LabelEntrySchema = serde_json::from_str(json).unwrap();
        assert_eq!(entry.value, "  spaces and\ttabs  ");
    }

    #[test]
    fn test_label_entry_schema_long_values() {
        let long_key = "k".repeat(128);
        let long_value = "v".repeat(256);
        let entry = LabelEntrySchema {
            key: long_key.clone(),
            value: long_value.clone(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let roundtrip: LabelEntrySchema = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.key.len(), 128);
        assert_eq!(roundtrip.value.len(), 256);
    }
}
