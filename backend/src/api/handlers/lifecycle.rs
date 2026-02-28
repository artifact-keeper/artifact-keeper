//! Lifecycle policy API handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::lifecycle_service::{
    CreatePolicyRequest, LifecyclePolicy, LifecycleService, PolicyExecutionResult,
    UpdatePolicyRequest,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        list_policies,
        create_policy,
        get_policy,
        update_policy,
        delete_policy,
        execute_policy,
        preview_policy,
        execute_all_policies,
    ),
    components(schemas(
        LifecyclePolicy,
        CreatePolicyRequest,
        UpdatePolicyRequest,
        PolicyExecutionResult,
    ))
)]
pub struct LifecycleApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_policies).post(create_policy))
        .route(
            "/:id",
            get(get_policy).patch(update_policy).delete(delete_policy),
        )
        .route("/:id/execute", post(execute_policy))
        .route("/:id/preview", post(preview_policy))
        .route("/execute-all", post(execute_all_policies))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListPoliciesQuery {
    pub repository_id: Option<Uuid>,
}

/// GET /api/v1/admin/lifecycle
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    operation_id = "list_lifecycle_policies",
    params(ListPoliciesQuery),
    responses(
        (status = 200, description = "List lifecycle policies", body = Vec<LifecyclePolicy>),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_policies(
    State(state): State<SharedState>,
    Query(query): Query<ListPoliciesQuery>,
) -> Result<Json<Vec<LifecyclePolicy>>> {
    let service = LifecycleService::new(state.db.clone());
    let policies = service.list_policies(query.repository_id).await?;
    Ok(Json(policies))
}

/// POST /api/v1/admin/lifecycle
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    operation_id = "create_lifecycle_policy",
    request_body = CreatePolicyRequest,
    responses(
        (status = 200, description = "Policy created successfully", body = LifecyclePolicy),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn create_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(payload): Json<CreatePolicyRequest>,
) -> Result<Json<LifecyclePolicy>> {
    let service = LifecycleService::new(state.db.clone());
    let policy = service.create_policy(payload).await?;
    Ok(Json(policy))
}

/// GET /api/v1/admin/lifecycle/:id
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    operation_id = "get_lifecycle_policy",
    params(
        ("id" = Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Lifecycle policy details", body = LifecyclePolicy),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_policy(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<LifecyclePolicy>> {
    let service = LifecycleService::new(state.db.clone());
    let policy = service.get_policy(id).await?;
    Ok(Json(policy))
}

/// PATCH /api/v1/admin/lifecycle/:id
#[utoipa::path(
    patch,
    path = "/{id}",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    operation_id = "update_lifecycle_policy",
    params(
        ("id" = Uuid, Path, description = "Policy ID"),
    ),
    request_body = UpdatePolicyRequest,
    responses(
        (status = 200, description = "Policy updated successfully", body = LifecyclePolicy),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn update_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdatePolicyRequest>,
) -> Result<Json<LifecyclePolicy>> {
    let service = LifecycleService::new(state.db.clone());
    let policy = service.update_policy(id, payload).await?;
    Ok(Json(policy))
}

/// DELETE /api/v1/admin/lifecycle/:id
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    operation_id = "delete_lifecycle_policy",
    params(
        ("id" = Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy deleted"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let service = LifecycleService::new(state.db.clone());
    service.delete_policy(id).await?;
    Ok(())
}

/// POST /api/v1/admin/lifecycle/:id/execute
#[utoipa::path(
    post,
    path = "/{id}/execute",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy executed", body = PolicyExecutionResult),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn execute_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyExecutionResult>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }
    let service = LifecycleService::new(state.db.clone());
    let result = service.execute_policy(id, false).await?;
    Ok(Json(result))
}

/// POST /api/v1/admin/lifecycle/:id/preview - dry-run
#[utoipa::path(
    post,
    path = "/{id}/preview",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy preview (dry-run)", body = PolicyExecutionResult),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn preview_policy(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyExecutionResult>> {
    let service = LifecycleService::new(state.db.clone());
    let result = service.execute_policy(id, true).await?;
    Ok(Json(result))
}

/// POST /api/v1/admin/lifecycle/execute-all
#[utoipa::path(
    post,
    path = "/execute-all",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    responses(
        (status = 200, description = "All enabled policies executed", body = Vec<PolicyExecutionResult>),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn execute_all_policies(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<PolicyExecutionResult>>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }
    let service = LifecycleService::new(state.db.clone());
    let results = service.execute_all_enabled().await?;
    Ok(Json(results))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ListPoliciesQuery deserialization tests ──────────────────────

    #[test]
    fn test_list_policies_query_deserialize_with_repo_id() {
        let json = r#"{"repository_id": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let q: ListPoliciesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(
            q.repository_id,
            Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap())
        );
    }

    #[test]
    fn test_list_policies_query_deserialize_without_repo_id() {
        let json = r#"{}"#;
        let q: ListPoliciesQuery = serde_json::from_str(json).unwrap();
        assert!(q.repository_id.is_none());
    }

    #[test]
    fn test_list_policies_query_deserialize_null_repo_id() {
        let json = r#"{"repository_id": null}"#;
        let q: ListPoliciesQuery = serde_json::from_str(json).unwrap();
        assert!(q.repository_id.is_none());
    }

    // ── CreatePolicyRequest deserialization tests ────────────────────

    #[test]
    fn test_create_policy_request_full() {
        let json = r#"{
            "repository_id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "cleanup-old",
            "description": "Remove old artifacts",
            "policy_type": "max_age_days",
            "config": {"max_age_days": 90},
            "priority": 10
        }"#;
        let req: CreatePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "cleanup-old");
        assert_eq!(req.policy_type, "max_age_days");
        assert_eq!(req.priority, Some(10));
        assert!(req.repository_id.is_some());
        assert!(req.description.is_some());
    }

    #[test]
    fn test_create_policy_request_minimal() {
        let json = r#"{
            "name": "global-policy",
            "policy_type": "max_versions",
            "config": {"max_versions": 5}
        }"#;
        let req: CreatePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "global-policy");
        assert!(req.repository_id.is_none());
        assert!(req.description.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_create_policy_request_missing_name_fails() {
        let json = r#"{"policy_type": "max_age_days", "config": {}}"#;
        let result: std::result::Result<CreatePolicyRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_policy_request_missing_policy_type_fails() {
        let json = r#"{"name": "test", "config": {}}"#;
        let result: std::result::Result<CreatePolicyRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_policy_request_missing_config_fails() {
        let json = r#"{"name": "test", "policy_type": "max_age_days"}"#;
        let result: std::result::Result<CreatePolicyRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ── UpdatePolicyRequest deserialization tests ────────────────────

    #[test]
    fn test_update_policy_request_all_fields() {
        let json = r#"{
            "name": "renamed",
            "description": "updated desc",
            "enabled": false,
            "config": {"max_versions": 10},
            "priority": 5
        }"#;
        let req: UpdatePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("renamed".to_string()));
        assert_eq!(req.description, Some("updated desc".to_string()));
        assert_eq!(req.enabled, Some(false));
        assert!(req.config.is_some());
        assert_eq!(req.priority, Some(5));
    }

    #[test]
    fn test_update_policy_request_empty_body() {
        let json = r#"{}"#;
        let req: UpdatePolicyRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.enabled.is_none());
        assert!(req.config.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_update_policy_request_partial() {
        let json = r#"{"enabled": true}"#;
        let req: UpdatePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.enabled, Some(true));
        assert!(req.name.is_none());
    }

    // ── PolicyExecutionResult serialization tests ───────────────────

    #[test]
    fn test_policy_execution_result_serialization() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            policy_name: "test-policy".to_string(),
            dry_run: true,
            artifacts_matched: 42,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["policy_name"], "test-policy");
        assert_eq!(json["dry_run"], true);
        assert_eq!(json["artifacts_matched"], 42);
        assert_eq!(json["artifacts_removed"], 0);
        assert_eq!(json["bytes_freed"], 0);
        assert!(json["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_policy_execution_result_with_errors() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::new_v4(),
            policy_name: "fail-policy".to_string(),
            dry_run: false,
            artifacts_matched: 10,
            artifacts_removed: 8,
            bytes_freed: 1024 * 1024,
            errors: vec![
                "timeout on artifact A".to_string(),
                "locked artifact B".to_string(),
            ],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["errors"].as_array().unwrap().len(), 2);
        assert_eq!(json["bytes_freed"], 1024 * 1024);
    }

    // ── LifecyclePolicy serialization roundtrip ─────────────────────

    #[test]
    fn test_lifecycle_policy_serialize_roundtrip() {
        let policy = LifecyclePolicy {
            id: Uuid::new_v4(),
            repository_id: Some(Uuid::new_v4()),
            name: "max-age-policy".to_string(),
            description: Some("Delete artifacts older than 90 days".to_string()),
            enabled: true,
            policy_type: "max_age_days".to_string(),
            config: serde_json::json!({"max_age_days": 90}),
            priority: 1,
            last_run_at: None,
            last_run_items_removed: None,
            cron_schedule: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json_str = serde_json::to_string(&policy).unwrap();
        let deserialized: LifecyclePolicy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.name, "max-age-policy");
        assert_eq!(deserialized.policy_type, "max_age_days");
        assert_eq!(deserialized.config["max_age_days"], 90);
    }

    #[test]
    fn test_lifecycle_policy_global_no_repo_id() {
        let policy = LifecyclePolicy {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "global".to_string(),
            description: None,
            enabled: false,
            policy_type: "max_versions".to_string(),
            config: serde_json::json!({"max_versions": 3}),
            priority: 0,
            last_run_at: None,
            last_run_items_removed: None,
            cron_schedule: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&policy).unwrap();
        assert!(json["repository_id"].is_null());
        assert_eq!(json["enabled"], false);
    }
}
