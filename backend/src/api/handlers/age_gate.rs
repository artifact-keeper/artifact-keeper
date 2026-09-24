//! Age-gate admin API and per-repository configuration.

use axum::extract::{Extension, Path, Query, State};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::handlers::repositories::{require_repo_admin, require_repo_write_access};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryType};
use crate::services::age_gate_service::AgeGateReview;
use crate::services::audit_export::details as audit_details;
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
        .route("/reviews/:id/reopen", post(reopen_review))
}

pub fn repo_config_routes() -> Router<SharedState> {
    Router::new().route(
        "/:key/age-gate",
        get(get_repo_age_gate).put(update_repo_age_gate),
    )
}

/// The repository-scoped review queue (#4238).
///
/// These are the same five operations [`admin_router`] exposes, restricted to a
/// single repository and reachable by that repository's admins rather than only
/// by an instance admin. The repository is named by the path segment and the
/// filter is derived from it, never from the query string, so a repository admin
/// can neither see nor act on another repository's reviews.
///
/// `/api/v1/admin/age-gate/*` is deliberately left as it is: it remains the
/// unscoped, instance-wide queue.
pub fn repo_review_routes() -> Router<SharedState> {
    Router::new()
        .route("/:key/age-gate/reviews", get(list_repo_reviews))
        .route("/:key/age-gate/reviews/:id", get(get_repo_review))
        .route(
            "/:key/age-gate/reviews/:id/approve",
            post(approve_repo_review),
        )
        .route(
            "/:key/age-gate/reviews/:id/reject",
            post(reject_repo_review),
        )
        .route(
            "/:key/age-gate/reviews/:id/reopen",
            post(reopen_repo_review),
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
    /// Username of the principal that recorded the current decision, and
    /// whether that principal is a service account (#4238). `reviewed_by` alone
    /// is a bare id: the queue could not say who promoted a package without a
    /// lookup per row, and a CI service account was indistinguishable from a
    /// person. Both are `None` for an automatic (unreviewed) row, and
    /// `reviewed_by_username` is also `None` if the account has since been
    /// deleted — the audit log keeps the decision in that case.
    pub reviewed_by_username: Option<String>,
    pub reviewed_by_is_service_account: Option<bool>,
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
    /// Age-source mode: `upstream_publish_time` or `first_seen` (#2264).
    pub mode: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAgeGateConfigRequest {
    pub enabled: bool,
    pub min_age_days: i32,
    /// Age-source mode. Omitted = keep the repository's current mode, so
    /// pre-mode clients that PUT `{enabled, min_age_days}` stay valid.
    #[serde(default)]
    pub mode: Option<String>,
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
        reviewed_by_username: review.reviewed_by_username,
        reviewed_by_is_service_account: review.reviewed_by_is_service_account,
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
fn build_review_audit_details(review: &AgeGateReview, reason: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "review_id": review.id,
        "package": review.package_name,
        "version": review.package_version,
        "reason": reason,
    })
}

/// Emit the audit entry for a review state change and return the JSON response.
/// Shared by approve/reject/reopen so the audit-logging tail lives in one place.
///
/// The entry carries `actor_name` and `resource_name` as well as the ids
/// (#4238), matching `update_repo_age_gate` below: the DB row records the
/// acting principal as `user_id`, but the exported envelope had no label for
/// it, so an age-gate decision reached a SIEM without naming who made it or
/// which repository it was made on.
async fn log_review_action(
    state: &SharedState,
    auth: &AuthExtension,
    action: AuditAction,
    review: AgeGateReview,
    details: serde_json::Value,
) -> Json<AgeGateReviewResponse> {
    let repository_id = review.repository_id;
    let repository_key = review.repository_key.clone();
    let resp = review_to_response(review);
    let audit = AuditService::new(state.db.clone());
    let mut entry = AuditEntry::new(action, ResourceType::Repository)
        .user(auth.user_id)
        .resource(repository_id)
        .actor_name(auth.username.clone())
        .details(details);
    if let Some(key) = repository_key {
        entry = entry.resource_name(key);
    }
    let _ = audit.log(entry).await;
    Json(resp)
}

/// Build the audit-log details for a reopen action, capturing the prior state.
fn build_reopen_audit_details(
    review: &AgeGateReview,
    previous_status: &str,
    reason: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "review_id": review.id,
        "package": review.package_name,
        "version": review.package_version,
        "previous_status": previous_status,
        "reason": reason,
    })
}

/// Authorize a repository-scoped age-gate operation and resolve its repository.
///
/// This is the single gate for every `/api/v1/repositories/{key}/age-gate*`
/// route, and it is the canonical repository-administration chain the rest of
/// the repository configuration surface already uses (`set_cache_ttl`,
/// `set_routing_rules`, `set_upstream_auth`, `update_repo_security`):
///
/// * `require_repo_write_access` — the tenant gate. TENANT-GATE-ONLY: it admits
///   any grantee, and the capability half is `require_repo_admin` immediately
///   below it.
/// * `require_repo_admin` — the repository `admin` action. A global admin
///   bypasses; every other caller must hold `admin` on this repository, which
///   `PermissionService::check_permission` resolves from a grant held DIRECTLY,
///   through a GROUP the principal belongs to, or inherited from the owning
///   PROJECT. Delegating through a group therefore behaves exactly like
///   delegating to the principal itself, which is how teams are actually
///   granted access (#4238).
///
/// Operating the gate is repository configuration, not artifact publishing, so
/// `write` alone deliberately does not suffice — the same line `require_repo_admin`
/// draws for every other configuration subresource (#2603 area 3).
async fn authorize_repo_age_gate(
    state: &SharedState,
    auth: &AuthExtension,
    key: &str,
) -> Result<Repository> {
    let service = RepoSvc::new(state.db.clone());
    let repo = service.get_by_key(key).await?;
    require_repo_write_access(auth, &repo, &service).await?;
    require_repo_admin(auth, repo.id, &state.permission_service).await?;
    Ok(repo)
}

/// A state change applied to one review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewDecision {
    Approve,
    Reject,
    Reopen,
}

impl ReviewDecision {
    fn audit_action(self) -> AuditAction {
        match self {
            Self::Approve => AuditAction::AgeGateApproved,
            Self::Reject => AuditAction::AgeGateRejected,
            Self::Reopen => AuditAction::AgeGateReopened,
        }
    }
}

/// Load review `id`, confirming it lies inside the caller's authority.
///
/// `scope` is `None` for the instance-wide `/admin` queue and `Some(repo_id)`
/// for a repository admin acting through `/repositories/{key}/age-gate/reviews`.
/// A review belonging to another repository is reported as NotFound rather than
/// Forbidden: a repository admin must not be able to probe which review ids
/// exist elsewhere on the instance.
async fn load_review_in_scope(
    svc: &crate::services::age_gate_service::AgeGateService,
    id: Uuid,
    scope: Option<Uuid>,
) -> Result<AgeGateReview> {
    let review = svc.get_review_by_id(id).await?;
    match scope {
        Some(repo_id) if review.repository_id != repo_id => {
            Err(AppError::NotFound("Age gate review not found".to_string()))
        }
        _ => Ok(review),
    }
}

/// Apply a decision to one review and record who made it.
///
/// Shared by the instance-admin and repository-admin routes so the two surfaces
/// cannot drift: the only difference between them is `scope`, and the
/// authorization that produced it.
async fn apply_review_decision(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
    decision: ReviewDecision,
    reason: Option<&str>,
    scope: Option<Uuid>,
) -> Result<Json<AgeGateReviewResponse>> {
    let svc = age_gate_service(state)?;
    load_review_in_scope(&svc, id, scope).await?;

    let (review, details) = match decision {
        ReviewDecision::Approve => {
            let review = svc.approve(id, auth.user_id, reason).await?;
            let details = build_review_audit_details(&review, reason);
            (review, details)
        }
        ReviewDecision::Reject => {
            let review = svc.reject(id, auth.user_id, reason).await?;
            let details = build_review_audit_details(&review, reason);
            (review, details)
        }
        ReviewDecision::Reopen => {
            let (previous_status, review) = svc.reopen(id, auth.user_id, reason).await?;
            let details = build_reopen_audit_details(&review, &previous_status, reason);
            (review, details)
        }
    };

    Ok(log_review_action(state, auth, decision.audit_action(), review, details).await)
}

/// List reviews, optionally narrowed to one repository.
///
/// `repository_key` is supplied by the caller's authorization, not parsed here:
/// the instance-admin route passes the (optional) query filter through, and the
/// repository-scoped route passes its authorized path segment, so the latter
/// cannot be widened from the query string.
async fn list_reviews_scoped(
    state: &SharedState,
    repository_key: Option<&str>,
    query: &ReviewListQuery,
) -> Result<Json<AgeGateReviewListResponse>> {
    let svc = age_gate_service(state)?;
    let (page, per_page, offset) = normalize_review_pagination(query.page, query.per_page);

    // `status` accepts a comma-separated list (e.g. "approved,rejected") so the UI
    // can fetch multiple states in one page while keeping pagination totals honest.
    let statuses: Option<Vec<String>> = query.status.as_deref().and_then(parse_status_filter);

    let (items, total) = svc
        .list_reviews(
            repository_key,
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
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ReviewListQuery>,
) -> Result<Json<AgeGateReviewListResponse>> {
    // Belt-and-suspenders with the `/admin` `admin_middleware`: gate in-handler
    // too, for parity with approve/reject and the codebase's double-guard posture.
    auth.require_admin()?;
    // Instance-wide queue: the optional `repository_key` filter is a
    // convenience, not an authorization boundary.
    list_reviews_scoped(&state, query.repository_key.as_deref(), &query).await
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgeGateReviewResponse>> {
    // Belt-and-suspenders with the `/admin` `admin_middleware` (see list_reviews).
    auth.require_admin()?;
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
    apply_review_decision(
        &state,
        &auth,
        id,
        ReviewDecision::Approve,
        body.reason.as_deref(),
        None,
    )
    .await
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
    apply_review_decision(
        &state,
        &auth,
        id,
        ReviewDecision::Reject,
        body.reason.as_deref(),
        None,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/age-gate/reviews/{id}/reopen",
    context_path = "/api/v1/admin",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    request_body = ReviewActionRequest,
    responses((status = 200, body = AgeGateReviewResponse))
)]
pub async fn reopen_review(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<ReviewActionRequest>,
) -> Result<Json<AgeGateReviewResponse>> {
    auth.require_admin()?;
    apply_review_decision(
        &state,
        &auth,
        id,
        ReviewDecision::Reopen,
        body.reason.as_deref(),
        None,
    )
    .await
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
    auth.require_scope("read:repositories")?;
    // Repository-administration tier, for parity with the PUT below: gate
    // posture (enabled + threshold) is operator configuration, not package
    // metadata (#2264), so a read-only member still cannot see it and blocked
    // download callers still learn `min_age_days` only from the structured 451
    // body. What changed in #4238 is WHICH administrator: this repository's
    // admins now qualify, not only an instance admin.
    let repo = authorize_repo_age_gate(&state, &auth, &key).await?;

    // `age_gate_mode` is deliberately not on the Repository model; read the
    // full policy from the source of truth.
    let params = crate::services::age_gate_service::resolve_repo_params(&state.db, repo.id).await?;

    Ok(Json(AgeGateConfigResponse {
        repository_key: key,
        enabled: params.age_gate_enabled,
        min_age_days: params.age_gate_min_age_days,
        mode: params.age_gate_mode.as_str().to_string(),
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
    auth.require_scope("write:repositories")?;

    use crate::services::age_gate_service::{self as ags, AgeGateMode, AgeGateService};

    crate::services::age_gate_service::validate_min_age_days(body.min_age_days)?;

    let repo = authorize_repo_age_gate(&state, &auth, &key).await?;

    require_remote_repo_for_age_gate(&repo.repo_type)?;

    // Omitted mode keeps the repository's current one (pre-mode client
    // compatibility); a supplied mode must parse.
    let mode = match &body.mode {
        Some(raw) => AgeGateMode::parse(raw)?,
        None => {
            ags::resolve_repo_params(&state.db, repo.id)
                .await?
                .age_gate_mode
        }
    };

    // Reject ENABLING the gate on a (format, mode) pair this server cannot
    // enforce: a 200 here would record an operator's intent that every
    // download seam then fails closed on (or silently ignores) — the
    // false-assurance gap flagged on #2930. Disabling is always allowed.
    if body.enabled {
        let format = AgeGateService::normalize_format(repo.format.clone());
        if !AgeGateService::supports_format_mode(&format, mode) {
            return Err(AppError::Validation(format!(
                "The age gate cannot be enforced for format {:?} in '{}' mode; \
                 supported today: npm, pypi, and vscode (both modes), go (first_seen), \
                 cargo (upstream_publish_time)",
                repo.format,
                mode.as_str()
            )));
        }
    }

    let svc = age_gate_service(&state)?;
    svc.update_repo_config(repo.id, body.enabled, body.min_age_days, mode)
        .await?;

    let audit = AuditService::new(state.db.clone());
    let _ = audit
        .log(
            AuditEntry::new(AuditAction::RepositoryUpdated, ResourceType::Repository)
                .user(auth.user_id)
                .resource(repo.id)
                .actor_name(auth.username.clone())
                .resource_name(repo.key.clone())
                .details_typed(audit_details::RepositoryDetails {
                    actor_id: auth.user_id,
                    key: repo.key.clone(),
                    is_public: repo.is_public,
                    format: Some(crate::services::repository_service::derive_format_key(
                        &repo.format,
                    )),
                    visibility: Some(if repo.is_public { "public" } else { "private" }.to_owned()),
                    age_gate_enabled: Some(body.enabled),
                    age_gate_min_age_days: Some(body.min_age_days),
                    age_gate_mode: Some(mode.as_str().to_string()),
                }),
        )
        .await;

    Ok(Json(AgeGateConfigResponse {
        repository_key: key,
        enabled: body.enabled,
        min_age_days: body.min_age_days,
        mode: mode.as_str().to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Repository-scoped review queue (#4238)
//
// The same five operations as `/api/v1/admin/age-gate/*`, narrowed to one
// repository and reachable by that repository's admins. Each handler resolves
// its authority through `authorize_repo_age_gate` and then hands the resulting
// repository id to the SAME `list_reviews_scoped` / `apply_review_decision`
// helpers the instance-admin routes use, so the two surfaces cannot drift.
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/{key}/age-gate/reviews",
    context_path = "/api/v1/repositories",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    params(
        ("key" = String, Path, description = "Repository key"),
        ("status" = Option<String>, Query),
        ("page" = Option<u32>, Query),
        ("per_page" = Option<u32>, Query),
    ),
    responses(
        (status = 200, body = AgeGateReviewListResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn list_repo_reviews(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(query): Query<ReviewListQuery>,
) -> Result<Json<AgeGateReviewListResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("read:repositories")?;
    authorize_repo_age_gate(&state, &auth, &key).await?;
    // The filter comes from the authorized path segment. Any `repository_key`
    // in the query string is ignored rather than honoured, so this route cannot
    // be widened to a repository the caller does not administer.
    list_reviews_scoped(&state, Some(&key), &query).await
}

#[utoipa::path(
    get,
    path = "/{key}/age-gate/reviews/{id}",
    context_path = "/api/v1/repositories",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    params(
        ("key" = String, Path, description = "Repository key"),
        ("id" = Uuid, Path, description = "Review id"),
    ),
    responses(
        (status = 200, body = AgeGateReviewResponse),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Repository or review not found"),
    )
)]
pub async fn get_repo_review(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
) -> Result<Json<AgeGateReviewResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("read:repositories")?;
    let repo = authorize_repo_age_gate(&state, &auth, &key).await?;
    let svc = age_gate_service(&state)?;
    let review = load_review_in_scope(&svc, id, Some(repo.id)).await?;
    Ok(Json(review_to_response(review)))
}

/// Shared tail of the three repository-scoped decision routes.
async fn decide_repo_review(
    state: &SharedState,
    auth: Option<AuthExtension>,
    key: &str,
    id: Uuid,
    decision: ReviewDecision,
    reason: Option<&str>,
) -> Result<Json<AgeGateReviewResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write:repositories")?;
    let repo = authorize_repo_age_gate(state, &auth, key).await?;
    apply_review_decision(state, &auth, id, decision, reason, Some(repo.id)).await
}

#[utoipa::path(
    post,
    path = "/{key}/age-gate/reviews/{id}/approve",
    context_path = "/api/v1/repositories",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    params(
        ("key" = String, Path, description = "Repository key"),
        ("id" = Uuid, Path, description = "Review id"),
    ),
    request_body = ReviewActionRequest,
    responses(
        (status = 200, body = AgeGateReviewResponse),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Repository or review not found"),
    )
)]
pub async fn approve_repo_review(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
    Json(body): Json<ReviewActionRequest>,
) -> Result<Json<AgeGateReviewResponse>> {
    decide_repo_review(
        &state,
        auth,
        &key,
        id,
        ReviewDecision::Approve,
        body.reason.as_deref(),
    )
    .await
}

#[utoipa::path(
    post,
    path = "/{key}/age-gate/reviews/{id}/reject",
    context_path = "/api/v1/repositories",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    params(
        ("key" = String, Path, description = "Repository key"),
        ("id" = Uuid, Path, description = "Review id"),
    ),
    request_body = ReviewActionRequest,
    responses(
        (status = 200, body = AgeGateReviewResponse),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Repository or review not found"),
    )
)]
pub async fn reject_repo_review(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
    Json(body): Json<ReviewActionRequest>,
) -> Result<Json<AgeGateReviewResponse>> {
    decide_repo_review(
        &state,
        auth,
        &key,
        id,
        ReviewDecision::Reject,
        body.reason.as_deref(),
    )
    .await
}

#[utoipa::path(
    post,
    path = "/{key}/age-gate/reviews/{id}/reopen",
    context_path = "/api/v1/repositories",
    tag = "age-gate",
    security(("bearer_auth" = [])),
    params(
        ("key" = String, Path, description = "Repository key"),
        ("id" = Uuid, Path, description = "Review id"),
    ),
    request_body = ReviewActionRequest,
    responses(
        (status = 200, body = AgeGateReviewResponse),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Repository or review not found"),
    )
)]
pub async fn reopen_repo_review(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
    Json(body): Json<ReviewActionRequest>,
) -> Result<Json<AgeGateReviewResponse>> {
    decide_repo_review(
        &state,
        auth,
        &key,
        id,
        ReviewDecision::Reopen,
        body.reason.as_deref(),
    )
    .await
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_reviews,
        get_review,
        approve_review,
        reject_review,
        reopen_review,
        get_repo_age_gate,
        update_repo_age_gate,
        list_repo_reviews,
        get_repo_review,
        approve_repo_review,
        reject_repo_review,
        reopen_repo_review
    ),
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

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn auth(is_admin: bool) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "age-gate-admin".to_string(),
            email: "age-gate-admin@example.invalid".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: if is_admin {
                crate::models::access_scope::AccessScope::Admin
            } else {
                crate::models::access_scope::AccessScope::default()
            },
            iat_ms: None,
        }
    }

    /// Every repository-scoped age-gate handler must route its authorization
    /// through `authorize_repo_age_gate` (#4238), which is the only place the
    /// `require_repo_write_access` + `require_repo_admin` chain is applied.
    /// String-grep, mirroring `test_repo_config_handlers_require_repo_admin` in
    /// `repositories.rs`, so a future handler on this surface cannot silently
    /// drop the gate — or re-instate the instance-admin-only check the
    /// delegation exists to replace.
    #[test]
    fn repo_scoped_age_gate_handlers_go_through_the_repo_admin_gate() {
        let source = include_str!("age_gate.rs");
        for handler in [
            "get_repo_age_gate",
            "update_repo_age_gate",
            "list_repo_reviews",
            "get_repo_review",
            "decide_repo_review",
        ] {
            let marker = format!("fn {}(", handler);
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("handler `{}` not found in age_gate.rs", handler));
            let rest = &source[start + marker.len()..];
            let end = rest.find("\n}\n").map_or(rest.len(), |e| e + 2);
            let body = &rest[..end];
            assert!(
                body.contains("authorize_repo_age_gate("),
                "handler `{}` does not call `authorize_repo_age_gate` (#4238). Every \
                 repository-scoped age-gate route must resolve its authority through \
                 that one chain, so the tenant gate and the repository `admin` action \
                 cannot be forgotten on a new route.",
                handler
            );
        }
    }

    #[test]
    fn routers_build_admin_and_repo_config_routes() {
        let _admin = admin_router();
        let _repo = repo_config_routes();
        let _reviews = repo_review_routes();
    }

    #[test]
    fn require_auth_accepts_present_auth_and_rejects_missing() {
        let present = auth(false);
        let accepted = require_auth(Some(present.clone())).expect("auth should pass through");
        assert_eq!(accepted.user_id, present.user_id);
        assert!(require_auth(None).is_err());
    }

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

    /// Build an `AgeGateReview` fixture for the pure detail/mapping tests.
    fn sample_review(name: &str, version: &str, status: &str) -> AgeGateReview {
        let now = Utc::now();
        AgeGateReview {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            package_name: name.to_string(),
            package_version: version.to_string(),
            upstream_published_at: None,
            status: status.to_string(),
            requested_at: now,
            reviewed_by: None,
            reviewed_at: None,
            review_reason: None,
            request_count: 1,
            last_requested_at: now,
            repository_key: None,
            basis_mode: None,
            basis_upstream_fingerprint: None,
            reviewed_by_username: None,
            reviewed_by_is_service_account: None,
        }
    }

    #[test]
    fn build_review_audit_details_includes_fields() {
        let review = sample_review("react", "18.0.0", "pending");
        let details = build_review_audit_details(&review, Some("looks safe"));
        assert_eq!(details["package"], "react");
        assert_eq!(details["version"], "18.0.0");
        assert_eq!(details["reason"], "looks safe");
    }

    #[test]
    fn build_reopen_audit_details_includes_previous_status() {
        let review = sample_review("left-pad", "1.3.0", "pending");
        let details = build_reopen_audit_details(&review, "approved", Some("turned out bad"));
        assert_eq!(details["package"], "left-pad");
        assert_eq!(details["version"], "1.3.0");
        assert_eq!(details["previous_status"], "approved");
        assert_eq!(details["reason"], "turned out bad");
    }

    #[test]
    fn review_to_response_maps_fields_and_default_key() {
        let resp = review_to_response(sample_review("lodash", "4.0.0", "pending"));
        assert_eq!(resp.repository_key, "");
        assert_eq!(resp.package_name, "lodash");
        assert_eq!(resp.status, "pending");
    }

    /// #4238: the reviewer's identity survives the row -> response mapping, and
    /// an unreviewed row carries no identity at all.
    #[test]
    fn review_to_response_carries_reviewer_identity() {
        let mut review = sample_review("left-pad", "1.3.0", "approved");
        let reviewer = Uuid::new_v4();
        review.reviewed_by = Some(reviewer);
        review.reviewed_by_username = Some("ci-approver".to_string());
        review.reviewed_by_is_service_account = Some(true);
        let resp = review_to_response(review);
        assert_eq!(resp.reviewed_by, Some(reviewer));
        assert_eq!(resp.reviewed_by_username.as_deref(), Some("ci-approver"));
        assert_eq!(resp.reviewed_by_is_service_account, Some(true));

        let pending = review_to_response(sample_review("left-pad", "1.3.0", "pending"));
        assert!(pending.reviewed_by_username.is_none());
        assert!(pending.reviewed_by_is_service_account.is_none());
    }

    /// Each decision keeps its own audit action after the three handlers were
    /// collapsed onto one dispatcher — a mix-up here would silently mislabel
    /// every age-gate event in the audit trail.
    #[test]
    fn review_decision_maps_to_its_audit_action() {
        for (decision, expected) in [
            (ReviewDecision::Approve, AuditAction::AgeGateApproved),
            (ReviewDecision::Reject, AuditAction::AgeGateRejected),
            (ReviewDecision::Reopen, AuditAction::AgeGateReopened),
        ] {
            assert_eq!(decision.audit_action().as_str(), expected.as_str());
        }
    }

    // -----------------------------------------------------------------------
    // #2264 low-sev disclosure: GET /repositories/{key}/age-gate is admin-only
    // (parity with the PUT and the /admin review routes). Previously any
    // authenticated caller with the "read" scope could read gate posture for
    // any repository. DB-backed: skips without DATABASE_URL; the CI coverage
    // job runs these against Postgres. The external-vantage twin lives in
    // tests/security_regression_tests.rs.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    fn config_app(state: SharedState, caller: AuthExtension) -> axum::Router {
        tdh::router_with_auth(repo_config_routes(), state, caller)
    }

    /// The exact pre-fix caller: an authenticated API token carrying only the
    /// "read" scope, which passed the old `require_scope("read")` gate.
    fn read_scope_token() -> AuthExtension {
        AuthExtension {
            is_api_token: true,
            scopes: Some(vec!["read".to_string()]),
            ..auth(false)
        }
    }

    #[tokio::test]
    async fn get_repo_age_gate_read_scope_token_forbidden_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let caller = read_scope_token();
        let caller_id = caller.user_id;
        let (status, body) = tdh::send(
            config_app(state, caller),
            tdh::get(format!("/{key}/age-gate")),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        let body = String::from_utf8_lossy(&body).to_string();
        assert!(
            !body.contains("min_age_days") && !body.contains("enabled"),
            "403 body must not leak gate config: {body}"
        );
        tdh::cleanup(&pool, repo_id, caller_id).await;
    }

    #[tokio::test]
    async fn get_repo_age_gate_non_admin_user_forbidden_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // Non-admin session user with unrestricted repo access: repo-access
        // bits must not grant config reads either.
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let caller = auth(false);
        let caller_id = caller.user_id;
        let (status, _body) = tdh::send(
            config_app(state, caller),
            tdh::get(format!("/{key}/age-gate")),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        tdh::cleanup(&pool, repo_id, caller_id).await;
    }

    #[tokio::test]
    async fn get_repo_age_gate_admin_ok_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let caller = auth(true);
        let caller_id = caller.user_id;
        let (status, body) = tdh::send(
            config_app(state, caller),
            tdh::get(format!("/{key}/age-gate")),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let cfg: AgeGateConfigResponse = serde_json::from_slice(&body).expect("valid config body");
        assert_eq!(cfg.repository_key, key);
        // Column defaults from migration 146: disabled, 7-day threshold.
        assert!(!cfg.enabled);
        assert_eq!(cfg.min_age_days, 7);
        tdh::cleanup(&pool, repo_id, caller_id).await;
    }

    /// Enabling the gate on a (format, mode) pair the server cannot enforce
    /// is rejected up front — recording an operator's intent every seam then
    /// fails closed on (or silently ignores) is the #2930 false-assurance
    /// gap. Go has no trustworthy publish-time resolver, so only `first_seen`
    /// is accepted; disabling is always allowed.
    #[tokio::test]
    async fn put_repo_age_gate_rejects_unenforceable_format_mode_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "go").await;
        let storage = dir.to_string_lossy().to_string();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), &storage);
        let state = tdh::build_state_with_proxy_and_age_gate(pool.clone(), &storage, proxy);
        let caller = auth(true);
        let caller_id = caller.user_id;

        let put = |body: serde_json::Value| {
            tdh::put_json(
                format!("/{key}/age-gate"),
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
        };

        let (status, _body) = tdh::send(
            config_app(state.clone(), caller.clone()),
            put(serde_json::json!({
                "enabled": true, "min_age_days": 30, "mode": "upstream_publish_time"
            })),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "go has no publish-time resolver: enabling that mode must be rejected"
        );

        let (status, body) = tdh::send(
            config_app(state.clone(), caller.clone()),
            put(serde_json::json!({
                "enabled": true, "min_age_days": 30, "mode": "first_seen"
            })),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let cfg: AgeGateConfigResponse = serde_json::from_slice(&body).expect("valid config body");
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, "first_seen");

        // Disabling is always allowed, whatever mode rides along.
        let (status, _body) = tdh::send(
            config_app(state, caller),
            put(serde_json::json!({
                "enabled": false, "min_age_days": 30, "mode": "upstream_publish_time"
            })),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);

        tdh::cleanup(&pool, repo_id, caller_id).await;
    }

    // -----------------------------------------------------------------------
    // #4238: repository-scoped operation of the age gate.
    //
    // The gate is configured per repository but could only be OPERATED by an
    // instance admin. These cover the delegated path: who now gets in, who
    // still does not, that a grant held through a GROUP behaves exactly like a
    // direct one, and that a repository admin's authority stops at its own
    // repository. DB-backed: they skip without DATABASE_URL (CI's coverage job
    // runs them against Postgres).
    // -----------------------------------------------------------------------

    /// The repository-scoped review router under a caller, with the age-gate
    /// service wired on (the reviews routes need it; `repo_config_routes` does
    /// not).
    fn review_app(state: SharedState, caller: AuthExtension) -> axum::Router {
        tdh::router_with_auth(repo_review_routes(), state, caller)
    }

    /// State carrying an `AgeGateService`, which the review routes require.
    fn gated_state(pool: sqlx::PgPool, dir: &std::path::Path) -> SharedState {
        let storage = dir.to_string_lossy().to_string();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), &storage);
        tdh::build_state_with_proxy_and_age_gate(pool, &storage, proxy)
    }

    /// Insert one pending review for `repo_id` and return its id.
    async fn seed_review(pool: &sqlx::PgPool, repo_id: Uuid, package: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO age_gate_reviews \
             (repository_id, package_name, package_version, status) \
             VALUES ($1, $2, '1.0.0', 'pending') RETURNING id",
        )
        .bind(repo_id)
        .bind(package)
        .fetch_one(pool)
        .await
        .expect("seed age gate review")
    }

    fn put_config(key: &str, enabled: bool) -> axum::http::Request<axum::body::Body> {
        let body = serde_json::json!({
            "enabled": enabled, "min_age_days": 30, "mode": "first_seen"
        });
        tdh::put_json(
            format!("/{key}/age-gate"),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
    }

    /// A repository admin — the fine-grained `repository:admin` action, no
    /// instance admin bit — can read AND write its own repository's gate
    /// posture. This is the exact call that returned 403 before #4238.
    #[tokio::test]
    async fn repo_admin_operates_own_age_gate_config_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        tdh::grant_repo_admin(&pool, repo_id, user_id).await;
        let state = gated_state(pool.clone(), &dir);
        let caller = tdh::make_auth(user_id, &username);

        let (status, body) = tdh::send(
            config_app(state.clone(), caller.clone()),
            tdh::get(format!("/{key}/age-gate")),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "a repository admin must be able to READ its own gate posture"
        );
        let cfg: AgeGateConfigResponse = serde_json::from_slice(&body).expect("valid config body");
        assert!(!cfg.enabled);

        let (status, body) = tdh::send(config_app(state, caller), put_config(&key, true)).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "a repository admin must be able to ENABLE its own gate"
        );
        let cfg: AgeGateConfigResponse = serde_json::from_slice(&body).expect("valid config body");
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, "first_seen");

        tdh::cleanup(&pool, repo_id, user_id).await;
        tdh::cleanup_user(&pool, user_id).await;
    }

    /// Operating the gate is repository CONFIGURATION, not publishing: a
    /// member holding only `write` is still refused. This is the line
    /// `require_repo_admin` draws for every other configuration subresource
    /// (#2603 area 3), and #4238 must not lower it.
    #[tokio::test]
    async fn repo_write_member_cannot_operate_age_gate_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        // Tenant membership plus an explicit write grant — everything except
        // the `admin` action.
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        tdh::grant_repo_actions(&pool, repo_id, user_id, &["read", "write"]).await;
        let state = gated_state(pool.clone(), &dir);
        let caller = tdh::make_auth(user_id, &username);

        for req in [tdh::get(format!("/{key}/age-gate")), put_config(&key, true)] {
            let (status, body) = tdh::send(config_app(state.clone(), caller.clone()), req).await;
            assert_eq!(
                status,
                axum::http::StatusCode::FORBIDDEN,
                "`write` must not confer gate operation"
            );
            let body = String::from_utf8_lossy(&body).to_string();
            assert!(
                !body.contains("min_age_days"),
                "403 body must not leak gate config: {body}"
            );
        }

        tdh::cleanup(&pool, repo_id, user_id).await;
        tdh::cleanup_user(&pool, user_id).await;
    }

    /// A grant held through a GROUP the principal belongs to is resolved by
    /// the same `check_permission` path as a direct grant, so delegating
    /// repository administration to a team works exactly like delegating it to
    /// a person — the case #4238 is actually about. The principal here is a
    /// SERVICE ACCOUNT, which is what a CI approval flow presents.
    #[tokio::test]
    async fn group_granted_repo_admin_operates_age_gate_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (sa_id, sa_name) = tdh::create_service_account(&pool).await;
        let (group_id, _group_name) = tdh::create_group(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
            .bind(sa_id)
            .bind(group_id)
            .execute(&pool)
            .await
            .expect("add service account to group");
        // The `admin` action is granted to the GROUP, never to the principal.
        tdh::grant_permission(&pool, "group", group_id, "repository", repo_id, &["admin"]).await;

        let state = gated_state(pool.clone(), &dir);
        let caller = AuthExtension {
            is_service_account: true,
            ..tdh::make_auth(sa_id, &sa_name)
        };

        let (status, _body) = tdh::send(config_app(state, caller), put_config(&key, true)).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "a group-held `admin` grant must operate the gate like a direct one"
        );

        let _ = sqlx::query("DELETE FROM user_group_members WHERE group_id = $1")
            .bind(group_id)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo_id, sa_id).await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, sa_id).await;
    }

    /// The repository-scoped queue lists ONLY its own repository's reviews,
    /// ignores a `repository_key` supplied in the query string, and answers
    /// 404 (not 403) for a review id belonging to a repository the caller does
    /// not administer — so it cannot be used to probe ids elsewhere.
    #[tokio::test]
    async fn repo_scoped_review_queue_is_confined_to_its_repository_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (mine_id, mine_key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        let (other_id, other_key, other_dir) = tdh::create_repo(&pool, "remote", "npm").await;
        tdh::grant_repo_admin(&pool, mine_id, user_id).await;
        let my_review = seed_review(&pool, mine_id, "left-pad").await;
        let other_review = seed_review(&pool, other_id, "lodash").await;

        let state = gated_state(pool.clone(), &dir);
        let caller = tdh::make_auth(user_id, &username);

        // Widening the query string must not widen the result.
        let (status, body) = tdh::send(
            review_app(state.clone(), caller.clone()),
            tdh::get(format!(
                "/{mine_key}/age-gate/reviews?repository_key={other_key}"
            )),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        // The response types are Serialize-only, so assert over the JSON the
        // client actually receives.
        let list: serde_json::Value = serde_json::from_slice(&body).expect("valid review list");
        assert_eq!(
            list["pagination"]["total"], 1,
            "queue must be one repository wide"
        );
        assert_eq!(list["items"][0]["id"], my_review.to_string());
        assert_eq!(list["items"][0]["repository_key"], mine_key.as_str());

        // Its own review is readable.
        let (status, _body) = tdh::send(
            review_app(state.clone(), caller.clone()),
            tdh::get(format!("/{mine_key}/age-gate/reviews/{my_review}")),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);

        // Another repository's review id is existence-hidden.
        let (status, _body) = tdh::send(
            review_app(state.clone(), caller.clone()),
            tdh::get(format!("/{mine_key}/age-gate/reviews/{other_review}")),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "a cross-repository review id must be 404, not 403"
        );

        // And it cannot be acted on through the caller's own repository.
        let (status, _body) = tdh::send(
            review_app(state.clone(), caller.clone()),
            tdh::post(
                format!("/{mine_key}/age-gate/reviews/{other_review}/approve"),
                "application/json",
                bytes::Bytes::from_static(b"{}"),
            ),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

        // The other repository itself is refused outright: no `admin` there.
        let (status, _body) = tdh::send(
            review_app(state.clone(), caller.clone()),
            tdh::get(format!("/{other_key}/age-gate/reviews")),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

        tdh::cleanup(&pool, mine_id, user_id).await;
        tdh::cleanup_member_repo(&pool, other_id, &other_dir).await;
        tdh::cleanup_user(&pool, user_id).await;
    }

    /// Approving through the repository-scoped route records WHO approved:
    /// the decision comes back naming the principal and saying whether it is a
    /// machine identity, instead of a bare id (#4238).
    #[tokio::test]
    async fn repo_admin_approval_records_the_approving_principal_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (sa_id, sa_name) = tdh::create_service_account(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        tdh::grant_repo_admin(&pool, repo_id, sa_id).await;
        let review_id = seed_review(&pool, repo_id, "left-pad").await;

        let state = gated_state(pool.clone(), &dir);
        let caller = AuthExtension {
            is_service_account: true,
            ..tdh::make_auth(sa_id, &sa_name)
        };

        let (status, body) = tdh::send(
            review_app(state, caller),
            tdh::post(
                format!("/{key}/age-gate/reviews/{review_id}/approve"),
                "application/json",
                bytes::Bytes::from_static(br#"{"reason":"vetted by the owning team"}"#),
            ),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_slice(&body).expect("valid review");
        assert_eq!(resp["status"], "approved");
        assert_eq!(resp["reviewed_by"], sa_id.to_string());
        assert_eq!(
            resp["reviewed_by_username"],
            sa_name.as_str(),
            "the approval must name the principal that made it"
        );
        assert_eq!(
            resp["reviewed_by_is_service_account"], true,
            "a machine identity must be distinguishable from a person"
        );
        // And the decision reaches the audit trail under the age-gate action.
        assert_eq!(
            tdh::audit_count_eventually(&pool, repo_id, AuditAction::AgeGateApproved.as_str(), 1)
                .await,
            1
        );

        tdh::cleanup(&pool, repo_id, sa_id).await;
        tdh::cleanup_user(&pool, sa_id).await;
    }
}
