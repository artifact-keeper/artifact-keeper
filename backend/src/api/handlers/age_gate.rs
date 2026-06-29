//! Age-gate admin API and per-repository configuration.

use axum::extract::{Extension, Path, Query, State};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::RepositoryType;
use crate::services::age_gate_service::AgeGateReview;
use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
use crate::services::repository_service::RepositoryService as RepoSvc;

fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))
}

pub fn admin_router() -> Router<SharedState> {
    Router::new()
        .route("/reviews", get(list_reviews))
        .route("/reviews/:id", get(get_review))
        .route("/reviews/:id/approve", post(approve_review))
        .route("/reviews/:id/reject", post(reject_review))
}

pub fn repo_config_routes() -> Router<SharedState> {
    Router::new().route(
        "/:key/age-gate",
        get(get_repo_age_gate).put(update_repo_age_gate),
    )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReviewListQuery {
    pub repository_key: Option<String>,
    pub status: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgeGateReviewResponse {
    pub id: Uuid,
    pub repository_key: String,
    pub package_name: String,
    pub package_version: String,
    pub upstream_published_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub review_reason: Option<String>,
    pub request_count: i32,
    pub last_requested_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgeGateReviewListResponse {
    pub items: Vec<AgeGateReviewResponse>,
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReviewActionRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AgeGateConfigResponse {
    pub repository_key: String,
    pub enabled: bool,
    pub min_age_days: i32,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAgeGateConfigRequest {
    pub enabled: bool,
    pub min_age_days: i32,
}

fn review_to_response(review: AgeGateReview) -> AgeGateReviewResponse {
    AgeGateReviewResponse {
        id: review.id,
        repository_key: review.repository_key.unwrap_or_default(),
        package_name: review.package_name,
        package_version: review.package_version,
        upstream_published_at: review.upstream_published_at,
        status: review.status,
        requested_at: review.requested_at,
        reviewed_by: review.reviewed_by,
        reviewed_at: review.reviewed_at,
        review_reason: review.review_reason,
        request_count: review.request_count,
        last_requested_at: review.last_requested_at,
    }
}

fn age_gate_service(
    state: &SharedState,
) -> Result<std::sync::Arc<crate::services::age_gate_service::AgeGateService>> {
    state
        .age_gate_service
        .clone()
        .ok_or_else(|| AppError::Internal("Age gate service not initialized".to_string()))
}

#[utoipa::path(
    get,
    path = "/age-gate/reviews",
    context_path = "/api/v1/admin",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    params(
        ("repository_key" = Option<String>, Query),
        ("status" = Option<String>, Query),
        ("page" = Option<u32>, Query),
        ("per_page" = Option<u32>, Query),
    ),
    responses((status = 200, body = AgeGateReviewListResponse))
)]
pub async fn list_reviews(
    State(state): State<SharedState>,
    Query(query): Query<ReviewListQuery>,
) -> Result<Json<AgeGateReviewListResponse>> {
    let svc = age_gate_service(&state)?;
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = i64::from(page - 1) * i64::from(per_page);

    let (items, total) = svc
        .list_reviews(
            query.repository_key.as_deref(),
            query.status.as_deref(),
            offset,
            i64::from(per_page),
        )
        .await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
    Ok(Json(AgeGateReviewListResponse {
        items: items.into_iter().map(review_to_response).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

#[utoipa::path(
    get,
    path = "/age-gate/reviews/{id}",
    context_path = "/api/v1/admin",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    responses((status = 200, body = AgeGateReviewResponse))
)]
pub async fn get_review(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgeGateReviewResponse>> {
    let svc = age_gate_service(&state)?;
    let review = svc.get_review_by_id(id).await?;
    Ok(Json(review_to_response(review)))
}

#[utoipa::path(
    post,
    path = "/age-gate/reviews/{id}/approve",
    context_path = "/api/v1/admin",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    request_body = ReviewActionRequest,
    responses((status = 200, body = AgeGateReviewResponse))
)]
pub async fn approve_review(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<ReviewActionRequest>,
) -> Result<Json<AgeGateReviewResponse>> {
    auth.require_admin()?;
    let svc = age_gate_service(&state)?;
    let review = svc
        .approve(id, auth.user_id, body.reason.as_deref())
        .await?;

    let audit = AuditService::new(state.db.clone());
    let _ = audit
        .log(
            AuditEntry::new(AuditAction::AgeGateApproved, ResourceType::Repository)
                .user(auth.user_id)
                .resource(review.repository_id)
                .details(serde_json::json!({
                    "review_id": review.id,
                    "package": review.package_name,
                    "version": review.package_version,
                    "reason": body.reason,
                })),
        )
        .await;

    Ok(Json(review_to_response(review)))
}

#[utoipa::path(
    post,
    path = "/age-gate/reviews/{id}/reject",
    context_path = "/api/v1/admin",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    request_body = ReviewActionRequest,
    responses((status = 200, body = AgeGateReviewResponse))
)]
pub async fn reject_review(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<ReviewActionRequest>,
) -> Result<Json<AgeGateReviewResponse>> {
    auth.require_admin()?;
    let svc = age_gate_service(&state)?;
    let review = svc.reject(id, auth.user_id, body.reason.as_deref()).await?;

    let audit = AuditService::new(state.db.clone());
    let _ = audit
        .log(
            AuditEntry::new(AuditAction::AgeGateRejected, ResourceType::Repository)
                .user(auth.user_id)
                .resource(review.repository_id)
                .details(serde_json::json!({
                    "review_id": review.id,
                    "package": review.package_name,
                    "version": review.package_version,
                    "reason": body.reason,
                })),
        )
        .await;

    Ok(Json(review_to_response(review)))
}

#[utoipa::path(
    get,
    path = "/{key}/age-gate",
    context_path = "/api/v1/repositories",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    responses((status = 200, body = AgeGateConfigResponse))
)]
pub async fn get_repo_age_gate(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<AgeGateConfigResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("read")?;
    let service = RepoSvc::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    Ok(Json(AgeGateConfigResponse {
        repository_key: key,
        enabled: repo.age_gate_enabled,
        min_age_days: repo.age_gate_min_age_days,
    }))
}

#[utoipa::path(
    put,
    path = "/{key}/age-gate",
    context_path = "/api/v1/repositories",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    request_body = UpdateAgeGateConfigRequest,
    responses((status = 200, body = AgeGateConfigResponse))
)]
pub async fn update_repo_age_gate(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(body): Json<UpdateAgeGateConfigRequest>,
) -> Result<Json<AgeGateConfigResponse>> {
    let auth = require_auth(auth)?;
    auth.require_admin()?;
    let service = RepoSvc::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    if repo.repo_type != RepositoryType::Remote {
        return Err(AppError::Validation(
            "Age gate applies only to remote (proxy) repositories".to_string(),
        ));
    }

    let svc = age_gate_service(&state)?;
    svc.update_repo_config(repo.id, body.enabled, body.min_age_days)
        .await?;

    let audit = AuditService::new(state.db.clone());
    let _ = audit
        .log(
            AuditEntry::new(AuditAction::RepositoryUpdated, ResourceType::Repository)
                .user(auth.user_id)
                .resource(repo.id)
                .details(serde_json::json!({
                    "age_gate_enabled": body.enabled,
                    "age_gate_min_age_days": body.min_age_days,
                })),
        )
        .await;

    Ok(Json(AgeGateConfigResponse {
        repository_key: key,
        enabled: body.enabled,
        min_age_days: body.min_age_days,
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(list_reviews, get_review, approve_review, reject_review, get_repo_age_gate, update_repo_age_gate),
    components(schemas(
        AgeGateReviewResponse,
        AgeGateReviewListResponse,
        ReviewActionRequest,
        AgeGateConfigResponse,
        UpdateAgeGateConfigRequest,
        ReviewListQuery
    )),
    tags((name = "age-gate", description = "Age-based proxy quality gate"))
)]
pub struct AgeGateApi;
