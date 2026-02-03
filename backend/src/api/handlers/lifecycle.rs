//! Lifecycle policy API handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::lifecycle_service::{
    CreatePolicyRequest, LifecyclePolicy, LifecycleService, PolicyExecutionResult,
    UpdatePolicyRequest,
};

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

#[derive(Debug, Deserialize)]
pub struct ListPoliciesQuery {
    pub repository_id: Option<Uuid>,
}

/// GET /api/v1/admin/lifecycle
pub async fn list_policies(
    State(state): State<SharedState>,
    Query(query): Query<ListPoliciesQuery>,
) -> Result<Json<Vec<LifecyclePolicy>>> {
    let service = LifecycleService::new(state.db.clone());
    let policies = service.list_policies(query.repository_id).await?;
    Ok(Json(policies))
}

/// POST /api/v1/admin/lifecycle
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
pub async fn get_policy(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<LifecyclePolicy>> {
    let service = LifecycleService::new(state.db.clone());
    let policy = service.get_policy(id).await?;
    Ok(Json(policy))
}

/// PATCH /api/v1/admin/lifecycle/:id
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
pub async fn preview_policy(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyExecutionResult>> {
    let service = LifecycleService::new(state.db.clone());
    let result = service.execute_policy(id, true).await?;
    Ok(Json(result))
}

/// POST /api/v1/admin/lifecycle/execute-all
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
