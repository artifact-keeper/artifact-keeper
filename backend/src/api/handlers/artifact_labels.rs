//! Artifact label management handlers.

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
    let _auth = require_auth(auth)?;

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
    let _auth = require_auth(auth)?;

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
    let _auth = require_auth(auth)?;

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
    let _auth = require_auth(auth)?;

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
}
