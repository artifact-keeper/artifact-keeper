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
    )),
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
