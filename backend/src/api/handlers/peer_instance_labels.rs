//! Peer instance label management handlers.

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
use crate::error::Result;
use crate::services::peer_instance_label_service::{PeerInstanceLabel, PeerInstanceLabelService};
use crate::services::peer_instance_service::PeerInstanceService;
use crate::services::repository_label_service::LabelEntry;
use crate::services::sync_policy_service::SyncPolicyService;

#[derive(OpenApi)]
#[openapi(
    paths(list_labels, set_labels, add_label, delete_label),
    components(schemas(PeerLabelResponse, SetPeerLabelsRequest, PeerLabelEntrySchema, AddPeerLabelRequest, PeerLabelsListResponse)),
    tags((name = "peer-instance-labels", description = "Peer instance label management"))
)]
pub struct PeerInstanceLabelsApiDoc;

/// Create peer instance label routes (nested under /api/v1/peers/:id/labels).
pub fn peer_labels_router() -> Router<SharedState> {
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
pub struct PeerLabelResponse {
    pub id: Uuid,
    pub peer_instance_id: Uuid,
    pub key: String,
    pub value: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerLabelsListResponse {
    pub items: Vec<PeerLabelResponse>,
    pub total: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetPeerLabelsRequest {
    pub labels: Vec<PeerLabelEntrySchema>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
pub struct PeerLabelEntrySchema {
    pub key: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddPeerLabelRequest {
    #[serde(default)]
    pub value: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn label_to_response(label: PeerInstanceLabel) -> PeerLabelResponse {
    PeerLabelResponse {
        id: label.id,
        peer_instance_id: label.peer_instance_id,
        key: label.label_key,
        value: label.label_value,
        created_at: label.created_at,
    }
}

fn labels_list_response(labels: Vec<PeerInstanceLabel>) -> PeerLabelsListResponse {
    let items: Vec<PeerLabelResponse> = labels.into_iter().map(label_to_response).collect();
    let total = items.len();
    PeerLabelsListResponse { items, total }
}

/// Fire-and-forget sync policy re-evaluation for a peer.
async fn trigger_peer_policy_evaluation(db: &sqlx::PgPool, peer_id: Uuid) {
    let svc = SyncPolicyService::new(db.clone());
    if let Err(e) = svc.evaluate_for_peer(peer_id).await {
        tracing::warn!(
            "Sync policy re-evaluation failed for peer {}: {}",
            peer_id,
            e
        );
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all labels on a peer instance
#[utoipa::path(
    get,
    path = "/{id}/labels",
    context_path = "/api/v1/peers",
    tag = "peer-instance-labels",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Labels retrieved", body = PeerLabelsListResponse),
        (status = 404, description = "Peer instance not found")
    )
)]
async fn list_labels(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<PeerLabelsListResponse>> {
    let peer_service = PeerInstanceService::new(state.db.clone());
    let _peer = peer_service.get_by_id(id).await?;

    let label_service = PeerInstanceLabelService::new(state.db.clone());
    let labels = label_service.get_labels(id).await?;

    Ok(Json(labels_list_response(labels)))
}

/// Set all labels on a peer instance (replaces existing)
#[utoipa::path(
    put,
    path = "/{id}/labels",
    context_path = "/api/v1/peers",
    tag = "peer-instance-labels",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID")
    ),
    request_body = SetPeerLabelsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Labels updated", body = PeerLabelsListResponse),
        (status = 404, description = "Peer instance not found")
    )
)]
async fn set_labels(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<SetPeerLabelsRequest>,
) -> Result<Json<PeerLabelsListResponse>> {
    let peer_service = PeerInstanceService::new(state.db.clone());
    let _peer = peer_service.get_by_id(id).await?;

    let entries: Vec<LabelEntry> = payload
        .labels
        .into_iter()
        .map(|l| LabelEntry {
            key: l.key,
            value: l.value,
        })
        .collect();

    let label_service = PeerInstanceLabelService::new(state.db.clone());
    let labels = label_service.set_labels(id, &entries).await?;

    trigger_peer_policy_evaluation(&state.db, id).await;

    Ok(Json(labels_list_response(labels)))
}

/// Add or update a single label on a peer instance
#[utoipa::path(
    post,
    path = "/{id}/labels/{label_key}",
    context_path = "/api/v1/peers",
    tag = "peer-instance-labels",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("label_key" = String, Path, description = "Label key to set")
    ),
    request_body = AddPeerLabelRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Label added/updated", body = PeerLabelResponse),
        (status = 404, description = "Peer instance not found")
    )
)]
async fn add_label(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path((id, label_key)): Path<(Uuid, String)>,
    Json(payload): Json<AddPeerLabelRequest>,
) -> Result<Json<PeerLabelResponse>> {
    let peer_service = PeerInstanceService::new(state.db.clone());
    let _peer = peer_service.get_by_id(id).await?;

    let label_service = PeerInstanceLabelService::new(state.db.clone());
    let label = label_service
        .add_label(id, &label_key, &payload.value)
        .await?;

    trigger_peer_policy_evaluation(&state.db, id).await;

    Ok(Json(label_to_response(label)))
}

/// Delete a label by key from a peer instance
#[utoipa::path(
    delete,
    path = "/{id}/labels/{label_key}",
    context_path = "/api/v1/peers",
    tag = "peer-instance-labels",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("label_key" = String, Path, description = "Label key to remove")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Label removed"),
        (status = 404, description = "Peer instance or label not found")
    )
)]
async fn delete_label(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path((id, label_key)): Path<(Uuid, String)>,
) -> Result<axum::http::StatusCode> {
    let peer_service = PeerInstanceService::new(state.db.clone());
    let _peer = peer_service.get_by_id(id).await?;

    let label_service = PeerInstanceLabelService::new(state.db.clone());
    label_service.remove_label(id, &label_key).await?;

    trigger_peer_policy_evaluation(&state.db, id).await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_peer_labels_request_deserialization() {
        let json =
            r#"{"labels": [{"key": "region", "value": "us-east"}, {"key": "tier", "value": "1"}]}"#;
        let req: SetPeerLabelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.labels.len(), 2);
        assert_eq!(req.labels[0].key, "region");
        assert_eq!(req.labels[0].value, "us-east");
    }

    #[test]
    fn test_set_peer_labels_request_empty_labels() {
        let json = r#"{"labels": []}"#;
        let req: SetPeerLabelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.labels.len(), 0);
    }

    #[test]
    fn test_add_peer_label_request_with_value() {
        let json = r#"{"value": "us-west-2"}"#;
        let req: AddPeerLabelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.value, "us-west-2");
    }

    #[test]
    fn test_add_peer_label_request_empty_value_default() {
        let json = r#"{}"#;
        let req: AddPeerLabelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.value, "");
    }

    #[test]
    fn test_peer_label_response_serialization() {
        let resp = PeerLabelResponse {
            id: uuid::Uuid::nil(),
            peer_instance_id: uuid::Uuid::nil(),
            key: "region".to_string(),
            value: "eu-west-1".to_string(),
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("region"));
        assert!(json.contains("eu-west-1"));
        assert!(json.contains("peer_instance_id"));
    }

    #[test]
    fn test_peer_labels_list_response_serialization() {
        let resp = PeerLabelsListResponse {
            items: vec![PeerLabelResponse {
                id: uuid::Uuid::nil(),
                peer_instance_id: uuid::Uuid::nil(),
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
    fn test_label_to_response_mapping() {
        let label = PeerInstanceLabel {
            id: uuid::Uuid::nil(),
            peer_instance_id: uuid::Uuid::nil(),
            label_key: "region".to_string(),
            label_value: "us-east-1".to_string(),
            created_at: chrono::Utc::now(),
        };
        let resp = label_to_response(label);
        assert_eq!(resp.key, "region");
        assert_eq!(resp.value, "us-east-1");
        assert_eq!(resp.id, uuid::Uuid::nil());
    }

    #[test]
    fn test_labels_list_response_helper() {
        let labels = vec![
            PeerInstanceLabel {
                id: uuid::Uuid::nil(),
                peer_instance_id: uuid::Uuid::nil(),
                label_key: "a".to_string(),
                label_value: "1".to_string(),
                created_at: chrono::Utc::now(),
            },
            PeerInstanceLabel {
                id: uuid::Uuid::nil(),
                peer_instance_id: uuid::Uuid::nil(),
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

    #[test]
    fn test_peer_label_response_json_contract() {
        let resp = PeerLabelResponse {
            id: uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            peer_instance_id: uuid::Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000")
                .unwrap(),
            key: "region".to_string(),
            value: "us-east-1".to_string(),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-01-15T10:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();

        assert!(json.get("id").is_some(), "Missing 'id' field");
        assert!(
            json.get("peer_instance_id").is_some(),
            "Missing 'peer_instance_id' field"
        );
        assert!(json.get("key").is_some(), "Missing 'key' field");
        assert!(json.get("value").is_some(), "Missing 'value' field");
        assert!(
            json.get("created_at").is_some(),
            "Missing 'created_at' field"
        );

        let obj = json.as_object().unwrap();
        assert_eq!(
            obj.len(),
            5,
            "PeerLabelResponse should have exactly 5 fields, got: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_peer_labels_list_response_json_contract() {
        let resp = PeerLabelsListResponse {
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
    fn test_set_peer_labels_request_rejects_missing_labels_field() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<SetPeerLabelsRequest>(json);
        assert!(
            result.is_err(),
            "SetPeerLabelsRequest should require 'labels' field"
        );
    }

    #[test]
    fn test_peer_label_entry_schema_with_default_value() {
        let json = r#"{"key": "production"}"#;
        let entry: PeerLabelEntrySchema = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "production");
        assert_eq!(entry.value, "");
    }

    #[test]
    fn test_peer_label_entry_schema_roundtrip() {
        let entry = PeerLabelEntrySchema {
            key: "region".to_string(),
            value: "eu-west-1".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: PeerLabelEntrySchema = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "region");
        assert_eq!(deserialized.value, "eu-west-1");
    }

    #[test]
    fn test_label_to_response_maps_db_fields_to_api_fields() {
        let label = PeerInstanceLabel {
            id: uuid::Uuid::new_v4(),
            peer_instance_id: uuid::Uuid::new_v4(),
            label_key: "db_field_name".to_string(),
            label_value: "db_field_value".to_string(),
            created_at: chrono::Utc::now(),
        };
        let resp = label_to_response(label.clone());

        assert_eq!(resp.key, label.label_key);
        assert_eq!(resp.value, label.label_value);
        assert_eq!(resp.id, label.id);
        assert_eq!(resp.peer_instance_id, label.peer_instance_id);
    }
}
