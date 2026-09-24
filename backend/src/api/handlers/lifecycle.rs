//! Lifecycle policy API handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::lifecycle_service::{
    CreateLifecyclePolicyRequest, LifecyclePolicy, LifecycleService, PolicyExecutionResult,
    UpdateLifecyclePolicyRequest,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        capabilities,
        attach_repository,
        detach_repository,
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
        CreateLifecyclePolicyRequest,
        UpdateLifecyclePolicyRequest,
        PolicyExecutionResult,
        LifecycleCapabilities,
    ))
)]
pub struct LifecycleApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_policies).post(create_policy))
        .route("/capabilities", get(capabilities))
        .route(
            "/:id/repositories/:repository_id",
            put(attach_repository).delete(detach_repository),
        )
        .route(
            "/:id",
            get(get_policy).patch(update_policy).delete(delete_policy),
        )
        .route("/:id/execute", post(execute_policy))
        .route("/:id/preview", post(preview_policy))
        .route("/execute-all", post(execute_all_policies))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LifecycleCapabilities {
    pub explicit_repository_assignment: bool,
}

/// Positive capability detection is required before assignment writes:
/// older backends ignore the new fields and interpret missing scope as global.
#[utoipa::path(
    get,
    path = "/capabilities",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    operation_id = "get_lifecycle_capabilities",
    responses(
        (status = 200, description = "Supported lifecycle capabilities", body = LifecycleCapabilities),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Administrator required"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn capabilities() -> Json<LifecycleCapabilities> {
    Json(LifecycleCapabilities {
        explicit_repository_assignment: true,
    })
}

#[utoipa::path(
    put,
    path = "/{id}/repositories/{repository_id}",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    operation_id = "attach_lifecycle_repository",
    params(("id" = Uuid, Path, description = "Policy ID"),
           ("repository_id" = Uuid, Path, description = "Repository ID")),
    responses(
        (status = 200, description = "Repository attached (idempotent)", body = LifecyclePolicy),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Administrator required"),
        (status = 404, description = "Policy or repository not found"),
        (status = 409, description = "Concurrent scope edits; retry the request"),
        (status = 422, description = "Global policy cannot have explicit assignments"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn attach_repository(
    State(state): State<SharedState>,
    Path((id, repository_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<LifecyclePolicy>> {
    let service = LifecycleService::new(state.db.clone());
    Ok(Json(
        service
            .set_repository_assignment(id, repository_id, true)
            .await?,
    ))
}

#[utoipa::path(
    delete,
    path = "/{id}/repositories/{repository_id}",
    context_path = "/api/v1/admin/lifecycle",
    tag = "lifecycle",
    operation_id = "detach_lifecycle_repository",
    params(("id" = Uuid, Path, description = "Policy ID"),
           ("repository_id" = Uuid, Path, description = "Repository ID")),
    responses(
        (status = 200, description = "Repository detached (idempotent)", body = LifecyclePolicy),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Administrator required"),
        (status = 404, description = "Policy or repository not found"),
        (status = 409, description = "Concurrent scope edits; retry the request"),
        (status = 422, description = "Global policy cannot be detached from a repository"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn detach_repository(
    State(state): State<SharedState>,
    Path((id, repository_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<LifecyclePolicy>> {
    let service = LifecycleService::new(state.db.clone());
    Ok(Json(
        service
            .set_repository_assignment(id, repository_id, false)
            .await?,
    ))
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
    request_body = CreateLifecyclePolicyRequest,
    responses(
        (status = 200, description = "Policy created successfully", body = LifecyclePolicy),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn create_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(payload): Json<CreateLifecyclePolicyRequest>,
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
    request_body = UpdateLifecyclePolicyRequest,
    responses(
        (status = 200, description = "Policy updated successfully", body = LifecyclePolicy),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn update_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateLifecyclePolicyRequest>,
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

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_openapi_contract_3794() {
        let document = serde_json::to_value(LifecycleApiDoc::openapi()).unwrap();
        let paths = &document["paths"];
        assert!(paths["/api/v1/admin/lifecycle/capabilities"]["get"].is_object());
        let assignments = &paths["/api/v1/admin/lifecycle/{id}/repositories/{repository_id}"];
        assert!(assignments["put"].is_object());
        assert!(assignments["delete"].is_object());
        let schemas = &document["components"]["schemas"];
        let required = schemas["LifecyclePolicy"]["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::json!("applies_to_all")));
        assert!(required.contains(&serde_json::json!("repository_ids")));
        for name in [
            "LifecyclePolicy",
            "CreateLifecyclePolicyRequest",
            "UpdateLifecyclePolicyRequest",
        ] {
            assert!(
                schemas[name]["properties"]["applies_to_all"].is_object(),
                "{name}"
            );
            assert!(
                schemas[name]["properties"]["repository_ids"].is_object(),
                "{name}"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn assignment_routes_require_admin_and_capability_is_explicit_3794() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::middleware::auth::admin_middleware;
        use crate::services::auth_service::AuthService;
        use axum::{
            body::{to_bytes, Body},
            http::{Method, Request, StatusCode},
            middleware,
        };
        use std::sync::Arc;
        use tower::ServiceExt;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool.clone(), "tmp/lifecycle-handler-3794");
        let (member, _) = tdh::create_user(&pool).await;
        let (admin, _) = tdh::create_user(&pool).await;
        sqlx::query("UPDATE users SET is_admin=true WHERE id=$1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        let member_token = tdh::bearer_for(&state, member).await;
        let admin_token = tdh::bearer_for(&state, admin).await;
        let auth_service = Arc::new(AuthService::new(
            pool.clone(),
            Arc::new(state.config.clone()),
        ));
        let router = Router::new()
            .nest("/api/v1/admin/lifecycle", super::router())
            .layer(middleware::from_fn_with_state(
                auth_service,
                admin_middleware,
            ))
            .with_state(state);
        let service = LifecycleService::new(pool.clone());
        let policy = service
            .create_policy(CreateLifecyclePolicyRequest {
                name: "route-assignment-3794".into(),
                policy_type: "max_versions".into(),
                config: serde_json::json!({"keep":1}),
                ..Default::default()
            })
            .await
            .unwrap();
        let repo_id = Uuid::new_v4();
        sqlx::query("INSERT INTO repositories(id,key,name,repo_type,format,storage_path) VALUES ($1,$2,$2,'local','generic',$2)")
            .bind(repo_id).bind(repo_id.to_string()).execute(&pool).await.unwrap();
        let association = format!(
            "/api/v1/admin/lifecycle/{}/repositories/{repo_id}",
            policy.id
        );
        let routes = [
            (
                Method::GET,
                "/api/v1/admin/lifecycle/capabilities".to_string(),
            ),
            (Method::GET, "/api/v1/admin/lifecycle".to_string()),
            (Method::POST, "/api/v1/admin/lifecycle".to_string()),
            (Method::PUT, association.clone()),
            (Method::DELETE, association.clone()),
            (
                Method::POST,
                format!("/api/v1/admin/lifecycle/{}/preview", policy.id),
            ),
            (
                Method::POST,
                format!("/api/v1/admin/lifecycle/{}/execute", policy.id),
            ),
            (
                Method::PATCH,
                format!("/api/v1/admin/lifecycle/{}", policy.id),
            ),
            (
                Method::DELETE,
                format!("/api/v1/admin/lifecycle/{}", policy.id),
            ),
        ];
        for (method, path) in routes {
            for token in [None, Some(&member_token)] {
                let mut req = Request::builder().method(method.clone()).uri(&path);
                if let Some(token) = token {
                    req = req.header("Authorization", token);
                }
                let response = router
                    .clone()
                    .oneshot(req.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    if token.is_none() {
                        StatusCode::UNAUTHORIZED
                    } else {
                        StatusCode::FORBIDDEN
                    },
                    "{method} {path}"
                );
            }
        }
        assert!(service
            .get_policy(policy.id)
            .await
            .unwrap()
            .repository_ids
            .is_empty());
        for (method, path) in [
            (
                Method::GET,
                "/api/v1/admin/lifecycle/capabilities".to_string(),
            ),
            (Method::PUT, association.clone()),
            (Method::PUT, association.clone()),
            (Method::DELETE, association.clone()),
            (Method::DELETE, association.clone()),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(&path)
                        .header("Authorization", &admin_token)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
            let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if method == Method::GET {
                assert_eq!(
                    json,
                    serde_json::json!({"explicit_repository_assignment":true})
                );
            } else {
                assert_eq!(json["applies_to_all"], false);
                assert_eq!(
                    json["repository_ids"].as_array().unwrap().len(),
                    usize::from(method == Method::PUT)
                );
            }
        }
        service.delete_policy(policy.id).await.unwrap();
        sqlx::query("DELETE FROM repositories WHERE id=$1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=ANY($1)")
            .bind([member, admin])
            .execute(&pool)
            .await
            .unwrap();
    }

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

    // ── CreateLifecyclePolicyRequest deserialization tests ────────────────────

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
        let req: CreateLifecyclePolicyRequest = serde_json::from_str(json).unwrap();
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
        let req: CreateLifecyclePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "global-policy");
        assert!(req.repository_id.is_none());
        assert!(req.description.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_create_policy_request_missing_name_fails() {
        let json = r#"{"policy_type": "max_age_days", "config": {}}"#;
        let result: std::result::Result<CreateLifecyclePolicyRequest, _> =
            serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_policy_request_missing_policy_type_fails() {
        let json = r#"{"name": "test", "config": {}}"#;
        let result: std::result::Result<CreateLifecyclePolicyRequest, _> =
            serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_policy_request_missing_config_fails() {
        let json = r#"{"name": "test", "policy_type": "max_age_days"}"#;
        let result: std::result::Result<CreateLifecyclePolicyRequest, _> =
            serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ── UpdateLifecyclePolicyRequest deserialization tests ────────────────────

    #[test]
    fn test_update_policy_request_all_fields() {
        let json = r#"{
            "name": "renamed",
            "description": "updated desc",
            "enabled": false,
            "config": {"max_versions": 10},
            "priority": 5
        }"#;
        let req: UpdateLifecyclePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("renamed".to_string()));
        assert_eq!(req.description, Some("updated desc".to_string()));
        assert_eq!(req.enabled, Some(false));
        assert!(req.config.is_some());
        assert_eq!(req.priority, Some(5));
    }

    #[test]
    fn test_update_policy_request_empty_body() {
        let json = r#"{}"#;
        let req: UpdateLifecyclePolicyRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.enabled.is_none());
        assert!(req.config.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_update_policy_request_partial() {
        let json = r#"{"enabled": true}"#;
        let req: UpdateLifecyclePolicyRequest = serde_json::from_str(json).unwrap();
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
            bytes_matched: 0,
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
            bytes_matched: 1024 * 1024,
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
            applies_to_all: false,
            repository_ids: vec![],
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
            applies_to_all: false,
            repository_ids: vec![],
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
