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
async fn log_review_action(
    state: &SharedState,
    actor: Uuid,
    action: AuditAction,
    review: AgeGateReview,
    details: serde_json::Value,
) -> Json<AgeGateReviewResponse> {
    let repository_id = review.repository_id;
    let resp = review_to_response(review);
    let audit = AuditService::new(state.db.clone());
    let _ = audit
        .log(
            AuditEntry::new(action, ResourceType::Repository)
                .user(actor)
                .resource(repository_id)
                .details(details),
        )
        .await;
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
    let svc = age_gate_service(&state)?;
    let review = svc
        .approve(id, auth.user_id, body.reason.as_deref())
        .await?;

    let details = build_review_audit_details(&review, body.reason.as_deref());
    Ok(log_review_action(
        &state,
        auth.user_id,
        AuditAction::AgeGateApproved,
        review,
        details,
    )
    .await)
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

    let details = build_review_audit_details(&review, body.reason.as_deref());
    Ok(log_review_action(
        &state,
        auth.user_id,
        AuditAction::AgeGateRejected,
        review,
        details,
    )
    .await)
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
    let svc = age_gate_service(&state)?;
    let (previous_status, review) = svc.reopen(id, auth.user_id, body.reason.as_deref()).await?;

    let details = build_reopen_audit_details(&review, &previous_status, body.reason.as_deref());
    Ok(log_review_action(
        &state,
        auth.user_id,
        AuditAction::AgeGateReopened,
        review,
        details,
    )
    .await)
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
    // Admin-only, for parity with the PUT below and the /admin review routes:
    // gate posture (enabled + threshold) is operator configuration, not
    // package metadata (#2264). Blocked download callers still learn
    // `min_age_days` from the structured 451 body, which is intended.
    auth.require_admin()?;
    let service = RepoSvc::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

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
    auth.require_admin()?;

    use crate::services::age_gate_service::{self as ags, AgeGateMode, AgeGateService};

    crate::services::age_gate_service::validate_min_age_days(body.min_age_days)?;

    let service = RepoSvc::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

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
                 supported today: npm, pypi, and vscode (both modes), go (first_seen)",
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

#[derive(OpenApi)]
#[openapi(
    paths(list_reviews, get_review, approve_review, reject_review, reopen_review, get_repo_age_gate, update_repo_age_gate),
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

    #[test]
    fn routers_build_admin_and_repo_config_routes() {
        let _admin = admin_router();
        let _repo = repo_config_routes();
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
}
