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

/// Parse a comma-separated `status` query value into a trimmed, non-empty list.
/// Returns `None` when no concrete status is present so the filter is disabled.
fn parse_status_filter(raw: &str) -> Option<Vec<String>> {
    let parsed: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    (!parsed.is_empty()).then_some(parsed)
}

/// Clamp review-list pagination inputs and compute SQL offset.
fn normalize_review_pagination(page: Option<u32>, per_page: Option<u32>) -> (u32, u32, i64) {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).clamp(1, 100);
    let offset = i64::from(page - 1) * i64::from(per_page);
    (page, per_page, offset)
}

/// Compute total pages for a paginated review list.
fn compute_review_total_pages(total: i64, per_page: u32) -> u32 {
    ((total as f64) / (per_page as f64)).ceil() as u32
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

/// Build the audit-log details for an approve/reject action.
fn build_review_audit_details(
    review: &AgeGateReviewResponse,
    reason: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "review_id": review.id,
        "package": review.package_name,
        "version": review.package_version,
        "reason": reason,
    })
}

/// Build the audit-log details for a per-repo age-gate config update.
fn build_repo_config_audit_details(enabled: bool, min_age_days: i32) -> serde_json::Value {
    serde_json::json!({
        "age_gate_enabled": enabled,
        "age_gate_min_age_days": min_age_days,
    })
}

/// Return `Err` when the repository type does not support age-gating.
fn require_remote_repo_for_age_gate(repo_type: &RepositoryType) -> Result<()> {
    if *repo_type != RepositoryType::Remote {
        return Err(AppError::Validation(
            "Age gate applies only to remote (proxy) repositories".to_string(),
        ));
    }
    Ok(())
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
    let (page, per_page, offset) = normalize_review_pagination(query.page, query.per_page);

    // `status` accepts a comma-separated list (e.g. "approved,rejected") so the UI
    // can fetch multiple states in one page while keeping pagination totals honest.
    let statuses: Option<Vec<String>> = query.status.as_deref().and_then(parse_status_filter);

    let (items, total) = svc
        .list_reviews(
            query.repository_key.as_deref(),
            statuses.as_deref(),
            offset,
            i64::from(per_page),
        )
        .await?;

    let total_pages = compute_review_total_pages(total, per_page);
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

    let repository_id = review.repository_id;
    let resp = review_to_response(review);
    let audit = AuditService::new(state.db.clone());
    let _ = audit
        .log(
            AuditEntry::new(AuditAction::AgeGateApproved, ResourceType::Repository)
                .user(auth.user_id)
                .resource(repository_id)
                .details(build_review_audit_details(&resp, body.reason.as_deref())),
        )
        .await;

    Ok(Json(resp))
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

    let repository_id = review.repository_id;
    let resp = review_to_response(review);
    let audit = AuditService::new(state.db.clone());
    let _ = audit
        .log(
            AuditEntry::new(AuditAction::AgeGateRejected, ResourceType::Repository)
                .user(auth.user_id)
                .resource(repository_id)
                .details(build_review_audit_details(&resp, body.reason.as_deref())),
        )
        .await;

    Ok(Json(resp))
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

    crate::services::age_gate_service::validate_min_age_days(body.min_age_days)?;

    let service = RepoSvc::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    require_remote_repo_for_age_gate(&repo.repo_type)?;

    let svc = age_gate_service(&state)?;
    svc.update_repo_config(repo.id, body.enabled, body.min_age_days)
        .await?;

    let audit = AuditService::new(state.db.clone());
    let _ = audit
        .log(
            AuditEntry::new(AuditAction::RepositoryUpdated, ResourceType::Repository)
                .user(auth.user_id)
                .resource(repo.id)
                .details(build_repo_config_audit_details(body.enabled, body.min_age_days)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn parse_status_filter_splits_and_trims() {
        assert_eq!(
            parse_status_filter("approved, rejected"),
            Some(vec!["approved".to_string(), "rejected".to_string()])
        );
    }

    #[test]
    fn parse_status_filter_single_value() {
        assert_eq!(
            parse_status_filter("pending"),
            Some(vec!["pending".to_string()])
        );
    }

    #[test]
    fn parse_status_filter_empty_is_none() {
        assert_eq!(parse_status_filter(""), None);
        assert_eq!(parse_status_filter("  , ,"), None);
    }

    #[test]
    fn normalize_review_pagination_defaults_and_clamps() {
        assert_eq!(normalize_review_pagination(None, None), (1, 20, 0));
        assert_eq!(normalize_review_pagination(Some(0), Some(200)), (1, 100, 0));
        assert_eq!(normalize_review_pagination(Some(3), Some(25)), (3, 25, 50));
    }

    #[test]
    fn compute_review_total_pages_ceil_and_zero() {
        assert_eq!(compute_review_total_pages(45, 20), 3);
        assert_eq!(compute_review_total_pages(0, 20), 0);
    }

    #[test]
    fn require_remote_repo_for_age_gate_rejects_local() {
        assert!(require_remote_repo_for_age_gate(&RepositoryType::Local).is_err());
        assert!(require_remote_repo_for_age_gate(&RepositoryType::Remote).is_ok());
    }

    #[test]
    fn build_review_audit_details_includes_fields() {
        let now = Utc::now();
        let resp = AgeGateReviewResponse {
            id: Uuid::new_v4(),
            repository_key: "npm-remote".to_string(),
            package_name: "react".to_string(),
            package_version: "18.0.0".to_string(),
            upstream_published_at: None,
            status: "pending".to_string(),
            requested_at: now,
            reviewed_by: None,
            reviewed_at: None,
            review_reason: None,
            request_count: 1,
            last_requested_at: now,
        };
        let details = build_review_audit_details(&resp, Some("looks safe"));
        assert_eq!(details["package"], "react");
        assert_eq!(details["version"], "18.0.0");
        assert_eq!(details["reason"], "looks safe");
    }

    #[test]
    fn build_repo_config_audit_details_includes_fields() {
        let d = build_repo_config_audit_details(true, 14);
        assert_eq!(d["age_gate_enabled"], true);
        assert_eq!(d["age_gate_min_age_days"], 14);
    }

    #[test]
    fn review_to_response_maps_fields_and_default_key() {
        let now = Utc::now();
        let review = crate::services::age_gate_service::AgeGateReview {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            package_name: "lodash".to_string(),
            package_version: "4.0.0".to_string(),
            upstream_published_at: None,
            status: "pending".to_string(),
            requested_at: now,
            reviewed_by: None,
            reviewed_at: None,
            review_reason: None,
            request_count: 1,
            last_requested_at: now,
            repository_key: None,
        };
        let resp = review_to_response(review);
        assert_eq!(resp.repository_key, "");
        assert_eq!(resp.package_name, "lodash");
        assert_eq!(resp.status, "pending");
    }
}
