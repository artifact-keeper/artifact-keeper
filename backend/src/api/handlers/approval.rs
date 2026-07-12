//! Promotion approval workflow handlers.
//!
//! Provides endpoints for requesting, reviewing (approve/reject), and querying
//! promotion approvals. When a staging repository has `require_approval = true`,
//! the normal promote endpoint redirects users here instead of promoting
//! immediately.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::handlers::promotion::validate_promotion_repos;
use crate::api::handlers::repositories::{require_repo_id_visible, require_visible};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::promotion_policy_service::PromotionPolicyService;
use crate::services::repository_service::RepositoryService;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/request", post(request_approval))
        .route("/pending", get(list_pending_approvals))
        .route("/:id", get(get_approval))
        .route("/:id/approve", post(approve_promotion))
        .route("/:id/reject", post(reject_promotion))
        .route("/history", get(list_approval_history))
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApprovalRequest {
    /// Source staging repository key
    pub source_repository: String,
    /// Target release repository key
    pub target_repository: String,
    /// Artifact ID to promote
    pub artifact_id: Uuid,
    /// Skip policy evaluation
    #[serde(default)]
    pub skip_policy_check: bool,
    /// Free-text justification
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApprovalResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub source_repository: String,
    pub target_repository: String,
    pub status: String,
    pub requested_by: Uuid,
    pub requested_at: DateTime<Utc>,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_notes: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub policy_result: Option<serde_json::Value>,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApprovalListResponse {
    pub items: Vec<ApprovalResponse>,
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReviewRequest {
    /// Optional reviewer notes
    pub notes: Option<String>,
    /// Admin break-glass override: skip promotion_rules enforcement at approve
    /// time. Mirrors `skip_policy_check` on the single/bulk promote endpoints so
    /// the approval-execute path has the same documented escape hatch.
    #[serde(default)]
    pub skip_policy_check: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApprovalHistoryQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub status: Option<String>,
    pub source_repository: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PendingQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub source_repository: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal row type for SQL mapping
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct ApprovalRow {
    id: Uuid,
    artifact_id: Uuid,
    source_repo_id: Uuid,
    target_repo_id: Uuid,
    requested_by: Uuid,
    requested_at: DateTime<Utc>,
    status: String,
    reviewed_by: Option<Uuid>,
    reviewed_at: Option<DateTime<Utc>>,
    review_notes: Option<String>,
    policy_result: Option<serde_json::Value>,
    notes: Option<String>,
    // Joined columns
    source_repo_key: Option<String>,
    target_repo_key: Option<String>,
}

impl ApprovalRow {
    fn into_response(self) -> ApprovalResponse {
        ApprovalResponse {
            id: self.id,
            artifact_id: self.artifact_id,
            source_repository: self.source_repo_key.unwrap_or_default(),
            target_repository: self.target_repo_key.unwrap_or_default(),
            status: self.status,
            requested_by: self.requested_by,
            requested_at: self.requested_at,
            reviewed_by: self.reviewed_by,
            reviewed_at: self.reviewed_at,
            review_notes: self.review_notes,
            policy_result: self.policy_result,
            notes: self.notes,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Separation-of-duties (four-eyes) decision: may `approver` approve a promotion
/// that was requested by `requester`?
///
/// The promotion approval workflow is a control gate: the principal who requests
/// a promotion must not be the principal who approves it. Without this, a single
/// admin-capable principal can both `POST /approval/request` and
/// `POST /approval/{id}/approve` on their own request, collapsing the four-eyes
/// control into one (the SoD-bypass finding from the 1.2.2 validation campaign).
///
/// There is intentionally NO self-approve override: the whole point of the
/// control is that a second principal signs off, so a break-glass that lets the
/// requester approve their own request would defeat it. A genuine emergency
/// promotion path already exists outside the approval workflow (the admin
/// `skip_policy_check` direct-promote), so this gate stays absolute.
///
/// Pure boolean so it is unit-testable without a database.
fn approval_separation_of_duties_ok(requester: Uuid, approver: Uuid) -> bool {
    requester != approver
}

/// Check whether a repository requires approval for promotions.
pub async fn check_approval_required(db: &sqlx::PgPool, repo_id: Uuid) -> Result<bool> {
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT COALESCE(require_approval, false) FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(row.map(|(v,)| v).unwrap_or(false))
}

/// Outcome of looking for an approved, unconsumed approval that authorizes a
/// promotion of `(artifact, source, target)`.
///
/// Split out as a pure enum so the classify decision (which 409 message to
/// produce) is unit-testable without a DB.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ApprovalConsumeOutcome {
    /// An approved + unconsumed row exists and is ready to be consumed.
    Ready,
    /// No approved row exists, but a pending request is outstanding.
    Pending,
    /// No approved (or pending) row exists for this exact pair.
    Absent,
}

/// Classify the lookup result for an approval-required promotion into the
/// outcome used to build the 409 response. Pure so it is unit-testable.
///
/// `approved_unconsumed` is the count of APPROVED + not-yet-consumed rows for the
/// exact `(artifact, source, target)` pair; `pending` is the count of still
/// outstanding (pending) requests for the same pair.
pub(crate) fn classify_approval_consume(
    approved_unconsumed: i64,
    pending: i64,
) -> ApprovalConsumeOutcome {
    if approved_unconsumed > 0 {
        ApprovalConsumeOutcome::Ready
    } else if pending > 0 {
        ApprovalConsumeOutcome::Pending
    } else {
        ApprovalConsumeOutcome::Absent
    }
}

/// Build the 409 error for an approval-required promotion that has no consumable
/// approved row. Pure so the message wording is unit-testable.
pub(crate) fn approval_required_conflict(outcome: &ApprovalConsumeOutcome) -> AppError {
    let msg = match outcome {
        ApprovalConsumeOutcome::Ready => {
            // Caller should have consumed the row; this branch is only reached on
            // a concurrent double-spend (the claim UPDATE lost the race).
            "This approved promotion request has already been used. \
             Submit a new approval request via POST /api/v1/approval/request."
                .to_string()
        }
        ApprovalConsumeOutcome::Pending => {
            "This repository requires approval for promotions and a request for this \
             artifact and target is still pending review. It must be approved via \
             POST /api/v1/approval/{id}/approve before the artifact can be promoted."
                .to_string()
        }
        ApprovalConsumeOutcome::Absent => {
            "This repository requires approval for promotions. Submit a request via \
             POST /api/v1/approval/request and have it approved before promoting."
                .to_string()
        }
    };
    AppError::Conflict(msg)
}

/// Atomically claim (consume) an APPROVED + unconsumed approval row for the exact
/// `(artifact, source, target)` pair, stamping `consumed_at = NOW()`.
///
/// Returns the number of rows claimed. The single-row UPDATE with the
/// `consumed_at IS NULL` guard is the concurrency boundary: at most one
/// concurrent promotion can win the claim, so an approved request is spent
/// exactly once and cannot be replayed. Callers MUST treat a return of `0` as
/// "no consumable approval" (deny) and `1` as "claimed" (proceed).
pub(crate) async fn try_consume_approval(
    db: &sqlx::PgPool,
    artifact_id: Uuid,
    source_repo_id: Uuid,
    target_repo_id: Uuid,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE promotion_approvals
        SET consumed_at = NOW()
        WHERE id = (
            SELECT id FROM promotion_approvals
            WHERE artifact_id = $1
              AND source_repo_id = $2
              AND target_repo_id = $3
              AND status = 'approved'
              AND consumed_at IS NULL
            ORDER BY reviewed_at DESC NULLS LAST
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        "#,
    )
    .bind(artifact_id)
    .bind(source_repo_id)
    .bind(target_repo_id)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(result.rows_affected())
}

/// Count outstanding PENDING approval requests for the exact pair, used to make
/// the 409 message actionable (pending-vs-absent) when no approved row is
/// consumable.
pub(crate) async fn count_pending_approvals(
    db: &sqlx::PgPool,
    artifact_id: Uuid,
    source_repo_id: Uuid,
    target_repo_id: Uuid,
) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::BIGINT FROM promotion_approvals
        WHERE artifact_id = $1
          AND source_repo_id = $2
          AND target_repo_id = $3
          AND status = 'pending'
        "#,
    )
    .bind(artifact_id)
    .bind(source_repo_id)
    .bind(target_repo_id)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(count)
}

/// Require and consume an approved approval for an approval-required promotion.
///
/// Called from the /promote routes (single + bulk) only inside the
/// `check_approval_required == true` branch. Atomically consumes one APPROVED +
/// unconsumed row for the exact `(artifact, source, target)` pair; on a miss
/// (no approval, only a pending request, or a concurrent double-spend) returns a
/// 409 whose wording distinguishes pending vs absent. On success the row is spent
/// and cannot be replayed.
pub(crate) async fn require_and_consume_approval(
    db: &sqlx::PgPool,
    artifact_id: Uuid,
    source_repo_id: Uuid,
    target_repo_id: Uuid,
) -> Result<()> {
    let claimed = try_consume_approval(db, artifact_id, source_repo_id, target_repo_id).await?;
    if claimed == 1 {
        return Ok(());
    }
    // Nothing claimed: distinguish pending vs absent for an actionable message.
    let pending = count_pending_approvals(db, artifact_id, source_repo_id, target_repo_id).await?;
    let outcome = classify_approval_consume(0, pending);
    Err(approval_required_conflict(&outcome))
}

const SELECT_APPROVAL: &str = r#"
    SELECT
        pa.id,
        pa.artifact_id,
        pa.source_repo_id,
        pa.target_repo_id,
        pa.requested_by,
        pa.requested_at,
        pa.status,
        pa.reviewed_by,
        pa.reviewed_at,
        pa.review_notes,
        pa.policy_result,
        pa.notes,
        sr.key AS source_repo_key,
        tr.key AS target_repo_key
    FROM promotion_approvals pa
    LEFT JOIN repositories sr ON sr.id = pa.source_repo_id
    LEFT JOIN repositories tr ON tr.id = pa.target_repo_id
"#;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Request approval for promoting an artifact from staging to release.
#[utoipa::path(
    post,
    path = "/request",
    context_path = "/api/v1/approval",
    tag = "approval",
    request_body = ApprovalRequest,
    responses(
        (status = 201, description = "Approval request created", body = ApprovalResponse),
        (status = 404, description = "Artifact or repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "Pending approval already exists", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn request_approval(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<ApprovalRequest>,
) -> Result<(axum::http::StatusCode, Json<ApprovalResponse>)> {
    let repo_service = RepositoryService::new(state.db.clone());
    let source_repo = repo_service.get_by_key(&req.source_repository).await?;
    let target_repo = repo_service.get_by_key(&req.target_repository).await?;
    validate_promotion_repos(&source_repo, &target_repo)?;

    // Close the cross-tenant existence oracle. The /approval surface resolves the
    // source repository by key with NO caller visibility filter and then probes
    // it for the artifact below; without this gate a non-member could use that
    // probe as an existence oracle against another tenant's private repo and
    // write a promotion_approvals row referencing it. require_visible derives the
    // gate from is_public + per-repo role-assignment membership (NotFound on a
    // private repo the caller cannot see), so the denial happens BEFORE the probe.
    require_visible(&source_repo, &Some(auth.clone()), &repo_service).await?;

    // Verify the artifact exists in the source repo
    let artifact_exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM artifacts WHERE id = $1 AND repository_id = $2 AND is_deleted = false",
    )
    .bind(req.artifact_id)
    .bind(source_repo.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if artifact_exists.is_none() {
        return Err(AppError::NotFound(
            "Artifact not found in source repository".to_string(),
        ));
    }

    // Check for an existing pending approval for the same artifact + repos
    let existing: Option<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT id FROM promotion_approvals
        WHERE artifact_id = $1
          AND source_repo_id = $2
          AND target_repo_id = $3
          AND status = 'pending'
        "#,
    )
    .bind(req.artifact_id)
    .bind(source_repo.id)
    .bind(target_repo.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if existing.is_some() {
        return Err(AppError::Conflict(
            "A pending approval request already exists for this artifact and repository pair"
                .to_string(),
        ));
    }

    // Optionally evaluate promotion policies
    let policy_result = if !req.skip_policy_check {
        let policy_service = PromotionPolicyService::new(state.db.clone());
        match policy_service
            .evaluate_artifact(req.artifact_id, source_repo.id)
            .await
        {
            Ok(eval) => Some(serde_json::json!({
                "passed": eval.passed,
                "action": format!("{:?}", eval.action).to_lowercase(),
                "violations": eval.violations,
                "cve_summary": eval.cve_summary,
                "license_summary": eval.license_summary,
            })),
            Err(e) => {
                tracing::warn!("Policy evaluation failed during approval request: {}", e);
                None
            }
        }
    } else {
        None
    };

    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO promotion_approvals (
            id, artifact_id, source_repo_id, target_repo_id,
            requested_by, requested_at, status, policy_result,
            skip_policy_check, notes
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)
        "#,
    )
    .bind(id)
    .bind(req.artifact_id)
    .bind(source_repo.id)
    .bind(target_repo.id)
    .bind(auth.user_id)
    .bind(now)
    .bind(&policy_result)
    .bind(req.skip_policy_check)
    .bind(&req.notes)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tracing::info!(
        approval_id = %id,
        artifact = %req.artifact_id,
        source = %req.source_repository,
        target = %req.target_repository,
        requested_by = %auth.user_id,
        "Promotion approval requested"
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ApprovalResponse {
            id,
            artifact_id: req.artifact_id,
            source_repository: req.source_repository,
            target_repository: req.target_repository,
            status: "pending".to_string(),
            requested_by: auth.user_id,
            requested_at: now,
            reviewed_by: None,
            reviewed_at: None,
            review_notes: None,
            policy_result,
            notes: req.notes,
        }),
    ))
}

/// List pending approval requests. Optionally filter by source repository.
#[utoipa::path(
    get,
    path = "/pending",
    context_path = "/api/v1/approval",
    tag = "approval",
    params(
        ("page" = Option<u32>, Query, description = "Page number (1-indexed)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 100)"),
        ("source_repository" = Option<String>, Query, description = "Filter by source repository key"),
    ),
    responses(
        (status = 200, description = "Pending approval requests", body = ApprovalListResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_pending_approvals(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<PendingQuery>,
) -> Result<Json<ApprovalListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    // Cross-repo authorization (#2443): when filtered by source repository, gate
    // on that repo's visibility. The unfiltered form spans every repo, so it is
    // admin-only (mirrors the health dashboard aggregate).
    if query.source_repository.is_none() {
        auth.require_admin()?;
    }

    let (rows, total): (Vec<ApprovalRow>, i64) = if let Some(ref source_key) =
        query.source_repository
    {
        let repo_service = RepositoryService::new(state.db.clone());
        let source = repo_service
            .get_by_key(source_key)
            .await
            .map_err(|e| match e {
                AppError::NotFound(_) => {
                    AppError::NotFound(format!("Repository '{}' not found", source_key))
                }
                other => other,
            })?;
        require_visible(&source, &Some(auth.clone()), &repo_service).await?;

        let rows: Vec<ApprovalRow> = sqlx::query_as(&format!(
                "{} WHERE pa.status = 'pending' AND pa.source_repo_id = $1 ORDER BY pa.requested_at DESC LIMIT $2 OFFSET $3",
                SELECT_APPROVAL
            ))
            .bind(source.id)
            .bind(per_page as i64)
            .bind(offset)
            .fetch_all(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*)::BIGINT FROM promotion_approvals WHERE status = 'pending' AND source_repo_id = $1",
            )
            .bind(source.id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        (rows, total.0)
    } else {
        let rows: Vec<ApprovalRow> = sqlx::query_as(&format!(
            "{} WHERE pa.status = 'pending' ORDER BY pa.requested_at DESC LIMIT $1 OFFSET $2",
            SELECT_APPROVAL
        ))
        .bind(per_page as i64)
        .bind(offset)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT FROM promotion_approvals WHERE status = 'pending'",
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        (rows, total.0)
    };

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(ApprovalListResponse {
        items: rows.into_iter().map(|r| r.into_response()).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get a single approval request by ID.
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/approval",
    tag = "approval",
    params(
        ("id" = Uuid, Path, description = "Approval request ID"),
    ),
    responses(
        (status = 200, description = "Approval request details", body = ApprovalResponse),
        (status = 404, description = "Approval request not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_approval(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(approval_id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let row: ApprovalRow = sqlx::query_as(&format!("{} WHERE pa.id = $1", SELECT_APPROVAL))
        .bind(approval_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Approval request not found".to_string()))?;

    // Cross-repo authorization (#2443): an approval discloses the artifact +
    // source/target repo pairing. Resolve the source repo (the promotion origin
    // the write path `request_approval` already gates on) and apply the same
    // visibility check. A caller who cannot see the source repo gets the SAME
    // 404 as a missing approval so the id is not a cross-tenant existence oracle.
    require_repo_id_visible(
        &state.db,
        &auth,
        row.source_repo_id,
        "Approval request not found",
    )
    .await?;

    Ok(Json(row.into_response()))
}

/// Approve a pending promotion request. Admin-only.
///
/// This copies the artifact from the staging repo to the release repo,
/// inserts the new artifact record, records promotion history, and
/// updates the approval status to "approved".
#[utoipa::path(
    post,
    path = "/{id}/approve",
    context_path = "/api/v1/approval",
    tag = "approval",
    params(
        ("id" = Uuid, Path, description = "Approval request ID"),
    ),
    request_body = ReviewRequest,
    responses(
        (status = 200, description = "Promotion approved and executed", body = ApprovalResponse),
        (status = 403, description = "Admin access required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Approval request not found", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "Approval already reviewed", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_promotion(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(approval_id): Path<Uuid>,
    Json(req): Json<ReviewRequest>,
) -> Result<Json<ApprovalResponse>> {
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Only admins can approve promotions".to_string(),
        ));
    }

    #[derive(sqlx::FromRow)]
    #[allow(dead_code)]
    struct SimpleRow {
        id: Uuid,
        artifact_id: Uuid,
        source_repo_id: Uuid,
        target_repo_id: Uuid,
        requested_by: Uuid,
        status: String,
    }

    let approval: SimpleRow = sqlx::query_as(
        "SELECT id, artifact_id, source_repo_id, target_repo_id, requested_by, status FROM promotion_approvals WHERE id = $1",
    )
    .bind(approval_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Approval request not found".to_string()))?;

    if approval.status != "pending" {
        return Err(AppError::Conflict(format!(
            "Approval request has already been {}",
            approval.status
        )));
    }

    // Separation of duties (four-eyes). The requester of a promotion must not be
    // the principal who approves it. Without this an admin-capable principal can
    // request AND approve their own promotion, collapsing the control gate (the
    // SoD-bypass finding from the 1.2.2 validation campaign). No self-approve
    // override: the second-pair-of-eyes requirement is the whole point.
    if !approval_separation_of_duties_ok(approval.requested_by, auth.user_id) {
        return Err(AppError::Authorization(
            "Separation of duties: you cannot approve a promotion you requested. \
             A different reviewer must approve this request."
                .to_string(),
        ));
    }

    let repo_service = RepositoryService::new(state.db.clone());

    let source_repo_key: (String,) = sqlx::query_as("SELECT key FROM repositories WHERE id = $1")
        .bind(approval.source_repo_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    let target_repo_key: (String,) = sqlx::query_as("SELECT key FROM repositories WHERE id = $1")
        .bind(approval.target_repo_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let source_repo = repo_service.get_by_key(&source_repo_key.0).await?;
    let target_repo = repo_service.get_by_key(&target_repo_key.0).await?;

    // Tenant-ownership gate (campaign-#4 systemic authz). The admin-capability
    // check above does NOT bind the approver to a tenant; without this an
    // admin-capable corp principal could approve a promotion whose target is a
    // globex repository, laundering an artifact across the tenant boundary via
    // the governance workflow. Reject cross-tenant approval on either repo with 403.
    crate::api::handlers::promotion::require_promotion_tenant_access(
        &repo_service,
        auth.user_id,
        &source_repo,
        &target_repo,
    )
    .await?;

    #[derive(sqlx::FromRow)]
    #[allow(dead_code)]
    struct ArtifactRow {
        id: Uuid,
        path: String,
        name: String,
        version: Option<String>,
        size_bytes: i64,
        checksum_sha256: String,
        checksum_md5: Option<String>,
        checksum_sha1: Option<String>,
        content_type: String,
        storage_key: String,
    }

    let artifact: ArtifactRow = sqlx::query_as(
        r#"
        SELECT id, path, name, version, size_bytes,
               checksum_sha256, checksum_md5, checksum_sha1,
               content_type, storage_key
        FROM artifacts
        WHERE id = $1 AND repository_id = $2 AND is_deleted = false
        "#,
    )
    .bind(approval.artifact_id)
    .bind(source_repo.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found in source repository".to_string()))?;

    // Enforce the per-pair promotion_rules (min_staging_hours, require_signature,
    // min_health_score, max_cve_severity, ...) BEFORE copying/inserting. This is
    // the same gate the single and bulk REST promote handlers apply; the approval
    // workflow is just a third promote path, and `promote_artifact` FORCES
    // approval-required repos through it, so without this check governance-ruled
    // repos (exactly the ones likely to carry rules) bypass the gate entirely.
    // Reuses the same evaluator as the advisory /evaluate dry-run so enforcement
    // and dry-run cannot diverge. Honors the `skip_policy_check` admin override.
    //
    // Unlike the REST handlers (which return 200 + promoted:false), the approval
    // execute path returns 403 with the violations: a rule-blocked approval must
    // NOT execute the copy/insert, so it fails like a rejected promotion.
    if !req.skip_policy_check {
        let rule_service =
            crate::services::promotion_rule_service::PromotionRuleService::new(state.db.clone());
        let failing = rule_service
            .evaluate_for_promotion(approval.artifact_id, source_repo.id, target_repo.id)
            .await?;
        if !failing.is_empty() {
            let detail = failing
                .iter()
                .flat_map(|e| {
                    e.violations
                        .iter()
                        .map(move |v| format!("{}: {}", e.rule_name, v))
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(AppError::Authorization(format!(
                "Promotion blocked by promotion rule violations: {}",
                detail
            )));
        }
    }

    // Copy storage content
    let source_storage = state.storage_for_repo(&source_repo.storage_location())?;
    let target_storage = state.storage_for_repo(&target_repo.storage_location())?;

    let content = source_storage
        .get(&artifact.storage_key)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read source artifact: {}", e)))?;
    target_storage
        .put(&artifact.storage_key, content)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write promoted artifact: {}", e)))?;

    super::cleanup_soft_deleted_artifact(&state.db, target_repo.id, &artifact.path).await;

    // Insert artifact in target repo
    let new_artifact_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO artifacts (
            id, repository_id, path, name, version, size_bytes,
            checksum_sha256, checksum_md5, checksum_sha1,
            content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(new_artifact_id)
    .bind(target_repo.id)
    .bind(&artifact.path)
    .bind(&artifact.name)
    .bind(&artifact.version)
    .bind(artifact.size_bytes)
    .bind(&artifact.checksum_sha256)
    .bind(&artifact.checksum_md5)
    .bind(&artifact.checksum_sha1)
    .bind(&artifact.content_type)
    .bind(&artifact.storage_key)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            AppError::Conflict(format!(
                "Artifact already exists in target repository: {}",
                artifact.path
            ))
        } else {
            AppError::Database(e.to_string())
        }
    })?;

    // Record promotion history
    let promotion_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO promotion_history (
            id, artifact_id, source_repo_id, target_repo_id,
            promoted_by, policy_result, notes
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(promotion_id)
    .bind(approval.artifact_id)
    .bind(source_repo.id)
    .bind(target_repo.id)
    .bind(auth.user_id)
    .bind(serde_json::json!({"approved_via": "approval_workflow", "approval_id": approval_id.to_string()}))
    .bind(&req.notes)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Update approval status. Stamp `consumed_at = NOW()` in the same UPDATE so
    // the approve path's own copy/insert above spends the row: an approved
    // request whose promotion was executed here cannot then be re-promoted via
    // the /promote routes (which require an APPROVED + unconsumed row).
    let now = Utc::now();
    sqlx::query(
        r#"
        UPDATE promotion_approvals
        SET status = 'approved', reviewed_by = $1, reviewed_at = $2, review_notes = $3,
            consumed_at = NOW()
        WHERE id = $4
        "#,
    )
    .bind(auth.user_id)
    .bind(now)
    .bind(&req.notes)
    .bind(approval_id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tracing::info!(
        approval_id = %approval_id,
        artifact = %approval.artifact_id,
        source = %source_repo_key.0,
        target = %target_repo_key.0,
        approved_by = %auth.user_id,
        "Promotion approved and executed"
    );

    // Return the updated approval
    let row: ApprovalRow = sqlx::query_as(&format!("{} WHERE pa.id = $1", SELECT_APPROVAL))
        .bind(approval_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(row.into_response()))
}

/// Reject a pending promotion request. Admin-only.
#[utoipa::path(
    post,
    path = "/{id}/reject",
    context_path = "/api/v1/approval",
    tag = "approval",
    params(
        ("id" = Uuid, Path, description = "Approval request ID"),
    ),
    request_body = ReviewRequest,
    responses(
        (status = 200, description = "Promotion rejected", body = ApprovalResponse),
        (status = 403, description = "Admin access required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Approval request not found", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "Approval already reviewed", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_promotion(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(approval_id): Path<Uuid>,
    Json(req): Json<ReviewRequest>,
) -> Result<Json<ApprovalResponse>> {
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Only admins can reject promotions".to_string(),
        ));
    }

    let current_status: Option<(String,)> =
        sqlx::query_as("SELECT status FROM promotion_approvals WHERE id = $1")
            .bind(approval_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    match current_status {
        None => return Err(AppError::NotFound("Approval request not found".to_string())),
        Some((status,)) if status != "pending" => {
            return Err(AppError::Conflict(format!(
                "Approval request has already been {}",
                status
            )))
        }
        _ => {}
    }

    let now = Utc::now();
    sqlx::query(
        r#"
        UPDATE promotion_approvals
        SET status = 'rejected', reviewed_by = $1, reviewed_at = $2, review_notes = $3
        WHERE id = $4
        "#,
    )
    .bind(auth.user_id)
    .bind(now)
    .bind(&req.notes)
    .bind(approval_id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tracing::info!(
        approval_id = %approval_id,
        rejected_by = %auth.user_id,
        "Promotion request rejected"
    );

    let row: ApprovalRow = sqlx::query_as(&format!("{} WHERE pa.id = $1", SELECT_APPROVAL))
        .bind(approval_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(row.into_response()))
}

/// List approval history with optional filtering by status or source repository.
#[utoipa::path(
    get,
    path = "/history",
    context_path = "/api/v1/approval",
    tag = "approval",
    params(
        ("page" = Option<u32>, Query, description = "Page number (1-indexed)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 100)"),
        ("status" = Option<String>, Query, description = "Filter by status (pending, approved, rejected)"),
        ("source_repository" = Option<String>, Query, description = "Filter by source repository key"),
    ),
    responses(
        (status = 200, description = "Approval history", body = ApprovalListResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_approval_history(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ApprovalHistoryQuery>,
) -> Result<Json<ApprovalListResponse>> {
    // Cross-repo authorization (#2443): the unfiltered history spans every repo,
    // so it is admin-only (mirrors the health dashboard aggregate); the
    // per-source-repo form is gated on that repo's visibility below.
    if query.source_repository.is_none() {
        auth.require_admin()?;
    }

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    // Build WHERE clauses dynamically
    let mut conditions: Vec<String> = vec![];
    let mut bind_idx = 1u32;

    if let Some(ref status) = query.status {
        if !["pending", "approved", "rejected"].contains(&status.as_str()) {
            return Err(AppError::Validation(format!(
                "Invalid status '{}'. Must be one of: pending, approved, rejected",
                status
            )));
        }
        conditions.push(format!("pa.status = ${}", bind_idx));
        bind_idx += 1;
    }

    let source_repo_id: Option<Uuid> = if let Some(ref source_key) = query.source_repository {
        let repo_service = RepositoryService::new(state.db.clone());
        let repo = repo_service
            .get_by_key(source_key)
            .await
            .map_err(|e| match e {
                AppError::NotFound(_) => {
                    AppError::NotFound(format!("Repository '{}' not found", source_key))
                }
                other => other,
            })?;
        require_visible(&repo, &Some(auth.clone()), &repo_service).await?;
        conditions.push(format!("pa.source_repo_id = ${}", bind_idx));
        bind_idx += 1;
        Some(repo.id)
    } else {
        None
    };

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let list_sql = format!(
        "{}{} ORDER BY pa.requested_at DESC LIMIT ${} OFFSET ${}",
        SELECT_APPROVAL,
        where_clause,
        bind_idx,
        bind_idx + 1,
    );

    let count_sql = format!(
        "SELECT COUNT(*)::BIGINT FROM promotion_approvals pa{}",
        where_clause
    );

    let mut list_query = sqlx::query_as::<_, ApprovalRow>(&list_sql);
    let mut count_query = sqlx::query_as::<_, (i64,)>(&count_sql);

    if let Some(ref status) = query.status {
        list_query = list_query.bind(status);
        count_query = count_query.bind(status);
    }
    if let Some(repo_id) = source_repo_id {
        list_query = list_query.bind(repo_id);
        count_query = count_query.bind(repo_id);
    }

    list_query = list_query.bind(per_page as i64).bind(offset);

    let rows = list_query
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let (total,) = count_query
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(ApprovalListResponse {
        items: rows.into_iter().map(|r| r.into_response()).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        request_approval,
        list_pending_approvals,
        get_approval,
        approve_promotion,
        reject_promotion,
        list_approval_history,
    ),
    components(schemas(
        ApprovalRequest,
        ApprovalResponse,
        ApprovalListResponse,
        ReviewRequest,
        ApprovalHistoryQuery,
        PendingQuery,
    ))
)]
pub struct ApprovalApiDoc;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-tenant oracle guard (xtenant-write-authz-systemic). `request_approval`
    /// resolves the source repository by key and probes it for the artifact; it
    /// must call `require_visible` on the source repo BEFORE that probe so a
    /// non-member cannot use the probe as an existence oracle against another
    /// tenant's private repo. String-grep because the handler needs a real DB.
    #[test]
    fn test_request_approval_gates_source_repo_before_probe() {
        let source = include_str!("approval.rs");
        let start = source
            .find("pub async fn request_approval(")
            .expect("request_approval not found");
        let rest = &source[start..];
        let end = rest.find("\npub async fn ").unwrap_or(rest.len());
        let body = &rest[..end];
        let gate = body
            .find("require_visible(")
            .expect("request_approval must call require_visible on the source repo (xtenant)");
        let probe = body
            .find("SELECT id FROM artifacts WHERE id = $1")
            .expect("artifact existence probe not found");
        assert!(
            gate < probe,
            "require_visible must run BEFORE the artifact existence probe (xtenant oracle)"
        );
    }

    // -----------------------------------------------------------------------
    // approval_separation_of_duties_ok (four-eyes SoD decision)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sod_requester_cannot_self_approve() {
        let p = Uuid::new_v4();
        // Same principal as requester and approver -> not allowed.
        assert!(!approval_separation_of_duties_ok(p, p));
    }

    #[test]
    fn test_sod_distinct_approver_allowed() {
        let requester = Uuid::new_v4();
        let approver = Uuid::new_v4();
        assert!(approval_separation_of_duties_ok(requester, approver));
    }

    // -----------------------------------------------------------------------
    // Approval consume gate (promotion-approval-gate-bypass)
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_approval_consume_ready() {
        // An approved + unconsumed row beats any pending count.
        assert_eq!(
            classify_approval_consume(1, 0),
            ApprovalConsumeOutcome::Ready
        );
        assert_eq!(
            classify_approval_consume(2, 3),
            ApprovalConsumeOutcome::Ready
        );
    }

    #[test]
    fn test_classify_approval_consume_pending() {
        // No approved row, but a pending request -> Pending (actionable message).
        assert_eq!(
            classify_approval_consume(0, 1),
            ApprovalConsumeOutcome::Pending
        );
    }

    #[test]
    fn test_classify_approval_consume_absent() {
        // Neither approved nor pending -> Absent.
        assert_eq!(
            classify_approval_consume(0, 0),
            ApprovalConsumeOutcome::Absent
        );
    }

    #[test]
    fn test_approval_required_conflict_pending_mentions_pending() {
        // The pending-vs-absent distinction must surface in the 409 wording so a
        // caller knows a request is awaiting review (not that none exists).
        let err = approval_required_conflict(&ApprovalConsumeOutcome::Pending);
        match err {
            AppError::Conflict(msg) => {
                assert!(msg.contains("pending"), "pending message: {msg}");
            }
            other => panic!("expected Conflict (409), got {other:?}"),
        }
    }

    #[test]
    fn test_approval_required_conflict_absent_is_409() {
        let err = approval_required_conflict(&ApprovalConsumeOutcome::Absent);
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[test]
    fn test_approval_required_conflict_reused_mentions_used() {
        // A lost concurrent claim race surfaces the single-use exhaustion.
        let err = approval_required_conflict(&ApprovalConsumeOutcome::Ready);
        match err {
            AppError::Conflict(msg) => {
                assert!(msg.contains("already been used"), "reuse message: {msg}");
            }
            other => panic!("expected Conflict (409), got {other:?}"),
        }
    }

    /// Structural: the approve path must stamp `consumed_at` in the same UPDATE
    /// that sets `status = 'approved'`, so an approved request's own executed
    /// promotion spends the row and cannot be re-promoted via /promote.
    #[test]
    fn test_approve_path_consumes_row() {
        let source = include_str!("approval.rs");
        let start = source
            .find("pub async fn approve_promotion(")
            .expect("approve_promotion not found");
        let rest = &source[start..];
        let end = rest.find("\npub async fn ").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("status = 'approved'") && body.contains("consumed_at = NOW()"),
            "approve_promotion must set consumed_at = NOW() alongside status = 'approved'"
        );
    }

    /// Structural: the consume claim must guard on `consumed_at IS NULL` so an
    /// already-spent approved row cannot be claimed twice (single-use).
    #[test]
    fn test_consume_claim_guards_unconsumed() {
        let source = include_str!("approval.rs");
        let start = source
            .find("pub(crate) async fn try_consume_approval(")
            .expect("try_consume_approval not found");
        let rest = &source[start..];
        let end = rest.find("\npub(crate) async fn ").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("status = 'approved'")
                && body.contains("consumed_at IS NULL")
                && body.contains("SET consumed_at = NOW()"),
            "try_consume_approval must claim an approved+unconsumed row via SET consumed_at"
        );
    }

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Normalize pagination parameters with defaults and bounds.
    fn normalize_approval_pagination(page: Option<u32>, per_page: Option<u32>) -> (u32, u32, i64) {
        let page = page.unwrap_or(1).max(1);
        let per_page = per_page.unwrap_or(20).min(100);
        let offset = ((page - 1) * per_page) as i64;
        (page, per_page, offset)
    }

    /// Compute total pages from total items and per_page.
    fn compute_approval_total_pages(total: i64, per_page: u32) -> u32 {
        ((total as f64) / (per_page as f64)).ceil() as u32
    }

    /// Validate that a status filter is valid for approval queries.
    fn validate_approval_status(status: &str) -> std::result::Result<(), String> {
        if !["pending", "approved", "rejected"].contains(&status) {
            return Err(format!(
                "Invalid status '{}'. Must be one of: pending, approved, rejected",
                status
            ));
        }
        Ok(())
    }

    /// Check if an approval is in a reviewable state (must be "pending").
    fn check_reviewable(current_status: &str) -> std::result::Result<(), String> {
        if current_status != "pending" {
            return Err(format!(
                "Approval request has already been {}",
                current_status
            ));
        }
        Ok(())
    }

    /// Build the policy result JSON from an evaluation result.
    fn build_policy_result_json(
        passed: bool,
        action: &str,
        violations: &[String],
        cve_summary: &serde_json::Value,
        license_summary: &serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "passed": passed,
            "action": action,
            "violations": violations,
            "cve_summary": cve_summary,
            "license_summary": license_summary,
        })
    }

    /// Build the promotion history metadata JSON for an approved promotion.
    fn build_promotion_history_metadata(approval_id: &str) -> serde_json::Value {
        serde_json::json!({
            "approved_via": "approval_workflow",
            "approval_id": approval_id,
        })
    }

    /// Build dynamic WHERE clauses for the approval history query.
    /// Returns (conditions, bind_index_after).
    fn build_history_where_clauses(
        status: &Option<String>,
        has_source_repo: bool,
        start_bind_idx: u32,
    ) -> (Vec<String>, u32) {
        let mut conditions = Vec::new();
        let mut bind_idx = start_bind_idx;

        if status.is_some() {
            conditions.push(format!("pa.status = ${}", bind_idx));
            bind_idx += 1;
        }

        if has_source_repo {
            conditions.push(format!("pa.source_repo_id = ${}", bind_idx));
            bind_idx += 1;
        }

        (conditions, bind_idx)
    }

    /// Combine conditions into a SQL WHERE clause string.
    fn build_where_clause(conditions: &[String]) -> String {
        if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        }
    }

    #[test]
    fn test_approval_request_deserialize() {
        let json = serde_json::json!({
            "source_repository": "staging-maven",
            "target_repository": "release-maven",
            "artifact_id": "00000000-0000-0000-0000-000000000001",
            "notes": "Ready for release"
        });
        let req: ApprovalRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.source_repository, "staging-maven");
        assert_eq!(req.target_repository, "release-maven");
        assert!(!req.skip_policy_check);
        assert_eq!(req.notes.as_deref(), Some("Ready for release"));
    }

    #[test]
    fn test_approval_request_skip_policy_default_false() {
        let json = serde_json::json!({
            "source_repository": "staging",
            "target_repository": "release",
            "artifact_id": "00000000-0000-0000-0000-000000000001"
        });
        let req: ApprovalRequest = serde_json::from_value(json).unwrap();
        assert!(!req.skip_policy_check);
    }

    #[test]
    fn test_approval_request_with_skip_policy() {
        let json = serde_json::json!({
            "source_repository": "staging",
            "target_repository": "release",
            "artifact_id": "00000000-0000-0000-0000-000000000001",
            "skip_policy_check": true
        });
        let req: ApprovalRequest = serde_json::from_value(json).unwrap();
        assert!(req.skip_policy_check);
    }

    #[test]
    fn test_review_request_deserialize() {
        let json = serde_json::json!({ "notes": "Looks good" });
        let req: ReviewRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.notes.as_deref(), Some("Looks good"));
    }

    #[test]
    fn test_review_request_empty() {
        let json = serde_json::json!({});
        let req: ReviewRequest = serde_json::from_value(json).unwrap();
        assert!(req.notes.is_none());
    }

    #[test]
    fn test_approval_response_serialize() {
        let resp = ApprovalResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            source_repository: "staging-npm".to_string(),
            target_repository: "release-npm".to_string(),
            status: "pending".to_string(),
            requested_by: Uuid::nil(),
            requested_at: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reviewed_by: None,
            reviewed_at: None,
            review_notes: None,
            policy_result: None,
            notes: Some("Test".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "pending");
        assert_eq!(json["source_repository"], "staging-npm");
        assert!(json["reviewed_by"].is_null());
    }

    #[test]
    fn test_approval_response_serialize_approved() {
        let reviewer = Uuid::new_v4();
        let resp = ApprovalResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            source_repository: "staging".to_string(),
            target_repository: "release".to_string(),
            status: "approved".to_string(),
            requested_by: Uuid::nil(),
            requested_at: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reviewed_by: Some(reviewer),
            reviewed_at: Some(DateTime::from_timestamp(1700001000, 0).unwrap()),
            review_notes: Some("LGTM".to_string()),
            policy_result: Some(serde_json::json!({"passed": true})),
            notes: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "approved");
        assert_eq!(json["reviewed_by"], reviewer.to_string());
        assert_eq!(json["review_notes"], "LGTM");
    }

    #[test]
    fn test_approval_list_response_serialize() {
        let resp = ApprovalListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 0,
                total_pages: 0,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 0);
        assert_eq!(json["pagination"]["page"], 1);
    }

    #[test]
    fn test_pending_query_deserialize() {
        let json = serde_json::json!({
            "page": 2,
            "per_page": 50,
            "source_repository": "staging-maven"
        });
        let query: PendingQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
        assert_eq!(query.source_repository.as_deref(), Some("staging-maven"));
    }

    #[test]
    fn test_pending_query_defaults() {
        let json = serde_json::json!({});
        let query: PendingQuery = serde_json::from_value(json).unwrap();
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.source_repository.is_none());
    }

    #[test]
    fn test_history_query_deserialize() {
        let json = serde_json::json!({
            "status": "approved",
            "source_repository": "staging-npm",
            "page": 1,
            "per_page": 10
        });
        let query: ApprovalHistoryQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.status.as_deref(), Some("approved"));
        assert_eq!(query.source_repository.as_deref(), Some("staging-npm"));
    }

    #[test]
    fn test_approval_row_into_response() {
        let row = ApprovalRow {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            source_repo_id: Uuid::nil(),
            target_repo_id: Uuid::nil(),
            requested_by: Uuid::nil(),
            requested_at: DateTime::from_timestamp(1700000000, 0).unwrap(),
            status: "pending".to_string(),
            reviewed_by: None,
            reviewed_at: None,
            review_notes: None,
            policy_result: None,
            notes: Some("test notes".to_string()),
            source_repo_key: Some("staging-maven".to_string()),
            target_repo_key: Some("release-maven".to_string()),
        };
        let resp = row.into_response();
        assert_eq!(resp.source_repository, "staging-maven");
        assert_eq!(resp.target_repository, "release-maven");
        assert_eq!(resp.status, "pending");
        assert_eq!(resp.notes.as_deref(), Some("test notes"));
    }

    #[test]
    fn test_approval_row_into_response_missing_keys() {
        let row = ApprovalRow {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            source_repo_id: Uuid::nil(),
            target_repo_id: Uuid::nil(),
            requested_by: Uuid::nil(),
            requested_at: DateTime::from_timestamp(1700000000, 0).unwrap(),
            status: "rejected".to_string(),
            reviewed_by: Some(Uuid::nil()),
            reviewed_at: Some(DateTime::from_timestamp(1700001000, 0).unwrap()),
            review_notes: Some("Not ready".to_string()),
            policy_result: Some(serde_json::json!({"passed": false})),
            notes: None,
            source_repo_key: None,
            target_repo_key: None,
        };
        let resp = row.into_response();
        assert_eq!(resp.source_repository, "");
        assert_eq!(resp.target_repository, "");
        assert_eq!(resp.status, "rejected");
        assert_eq!(resp.review_notes.as_deref(), Some("Not ready"));
    }

    #[test]
    fn test_validate_promotion_repos_staging_to_local() {
        use crate::models::repository::*;
        let source = Repository {
            versioning_enabled: false,
            id: Uuid::nil(),
            key: "staging-maven".to_string(),
            name: "Staging Maven".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Staging,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/staging".to_string(),
            upstream_url: None,
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::LocalOnly,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let target = Repository {
            versioning_enabled: false,
            id: Uuid::nil(),
            key: "release-maven".to_string(),
            name: "Release Maven".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Local,
            storage_path: "/tmp/release".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::Immediate,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(validate_promotion_repos(&source, &target).is_ok());
    }

    #[test]
    fn test_validate_promotion_repos_source_not_hosted() {
        // B12 / #1376: the source-shape check now rejects only non-hosted
        // repositories (Remote/Virtual). A Remote source owns no bytes and
        // cannot be promoted from. (A Local source is now allowed, see
        // promotion.rs `test_validate_promotion_repos_source_local_is_allowed`.)
        use crate::models::repository::*;
        let source = Repository {
            versioning_enabled: false,
            id: Uuid::nil(),
            key: "remote-maven".to_string(),
            name: "Remote Maven".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Remote,
            storage_path: "/tmp/remote".to_string(),
            upstream_url: Some("https://repo1.maven.org/maven2".to_string()),
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::LocalOnly,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let target = Repository {
            versioning_enabled: false,
            id: Uuid::nil(),
            key: "release-maven".to_string(),
            name: "Release Maven".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Local,
            storage_path: "/tmp/release".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::Immediate,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let result = validate_promotion_repos(&source, &target);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("hosted"), "Error: {}", err_msg);
    }

    #[test]
    fn test_validate_promotion_repos_format_mismatch() {
        use crate::models::repository::*;
        let source = Repository {
            versioning_enabled: false,
            id: Uuid::nil(),
            key: "staging-maven".to_string(),
            name: "Staging Maven".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Staging,
            storage_path: "/tmp/staging".to_string(),
            upstream_url: None,
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::LocalOnly,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let target = Repository {
            versioning_enabled: false,
            id: Uuid::nil(),
            key: "release-npm".to_string(),
            name: "Release NPM".to_string(),
            description: None,
            format: RepositoryFormat::Npm,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Local,
            storage_path: "/tmp/release".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::Immediate,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let result = validate_promotion_repos(&source, &target);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("mismatch"), "Error: {}", err_msg);
    }

    #[test]
    fn test_pagination_in_list_response() {
        let resp = ApprovalListResponse {
            items: vec![],
            pagination: Pagination {
                page: 3,
                per_page: 25,
                total: 100,
                total_pages: 4,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["pagination"]["page"], 3);
        assert_eq!(json["pagination"]["per_page"], 25);
        assert_eq!(json["pagination"]["total"], 100);
        assert_eq!(json["pagination"]["total_pages"], 4);
    }

    // -----------------------------------------------------------------------
    // normalize_approval_pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_approval_pagination_defaults() {
        let (page, per_page, offset) = normalize_approval_pagination(None, None);
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_normalize_approval_pagination_custom() {
        let (page, per_page, offset) = normalize_approval_pagination(Some(3), Some(50));
        assert_eq!(page, 3);
        assert_eq!(per_page, 50);
        assert_eq!(offset, 100);
    }

    #[test]
    fn test_normalize_approval_pagination_zero_page_clamps() {
        let (page, _, offset) = normalize_approval_pagination(Some(0), None);
        assert_eq!(page, 1);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_normalize_approval_pagination_per_page_capped() {
        let (_, per_page, _) = normalize_approval_pagination(None, Some(200));
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_normalize_approval_pagination_offset_computation() {
        let (_, _, offset) = normalize_approval_pagination(Some(5), Some(10));
        assert_eq!(offset, 40);
    }

    // -----------------------------------------------------------------------
    // compute_approval_total_pages
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_approval_total_pages_exact() {
        assert_eq!(compute_approval_total_pages(100, 20), 5);
    }

    #[test]
    fn test_compute_approval_total_pages_remainder() {
        assert_eq!(compute_approval_total_pages(101, 20), 6);
    }

    #[test]
    fn test_compute_approval_total_pages_zero() {
        assert_eq!(compute_approval_total_pages(0, 20), 0);
    }

    #[test]
    fn test_compute_approval_total_pages_one_item() {
        assert_eq!(compute_approval_total_pages(1, 100), 1);
    }

    // -----------------------------------------------------------------------
    // validate_approval_status
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_approval_status_pending() {
        assert!(validate_approval_status("pending").is_ok());
    }

    #[test]
    fn test_validate_approval_status_approved() {
        assert!(validate_approval_status("approved").is_ok());
    }

    #[test]
    fn test_validate_approval_status_rejected() {
        assert!(validate_approval_status("rejected").is_ok());
    }

    #[test]
    fn test_validate_approval_status_invalid() {
        assert!(validate_approval_status("unknown").is_err());
        assert!(validate_approval_status("").is_err());
        assert!(validate_approval_status("PENDING").is_err());
    }

    #[test]
    fn test_validate_approval_status_error_contains_value() {
        let err = validate_approval_status("bad").unwrap_err();
        assert!(err.contains("bad"));
    }

    // -----------------------------------------------------------------------
    // check_reviewable
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_reviewable_pending() {
        assert!(check_reviewable("pending").is_ok());
    }

    #[test]
    fn test_check_reviewable_approved() {
        let err = check_reviewable("approved").unwrap_err();
        assert!(err.contains("approved"));
    }

    #[test]
    fn test_check_reviewable_rejected() {
        let err = check_reviewable("rejected").unwrap_err();
        assert!(err.contains("rejected"));
    }

    #[test]
    fn test_check_reviewable_unknown_status() {
        assert!(check_reviewable("unknown").is_err());
    }

    // -----------------------------------------------------------------------
    // build_policy_result_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_policy_result_json_passed() {
        let json = build_policy_result_json(
            true,
            "allow",
            &[],
            &serde_json::json!({}),
            &serde_json::json!({}),
        );
        assert_eq!(json["passed"], true);
        assert_eq!(json["action"], "allow");
        assert!(json["violations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_policy_result_json_failed() {
        let violations = vec!["CVE-2024-1234: critical".to_string()];
        let json = build_policy_result_json(
            false,
            "block",
            &violations,
            &serde_json::json!({"total": 1, "critical": 1}),
            &serde_json::json!({"allowed": ["MIT"]}),
        );
        assert_eq!(json["passed"], false);
        assert_eq!(json["action"], "block");
        assert_eq!(json["violations"].as_array().unwrap().len(), 1);
        assert_eq!(json["cve_summary"]["critical"], 1);
    }

    #[test]
    fn test_build_policy_result_json_all_fields_present() {
        let json = build_policy_result_json(
            true,
            "warn",
            &[],
            &serde_json::json!(null),
            &serde_json::json!(null),
        );
        assert!(json.get("passed").is_some());
        assert!(json.get("action").is_some());
        assert!(json.get("violations").is_some());
        assert!(json.get("cve_summary").is_some());
        assert!(json.get("license_summary").is_some());
    }

    // -----------------------------------------------------------------------
    // build_promotion_history_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_promotion_history_metadata() {
        let json = build_promotion_history_metadata("abc-123");
        assert_eq!(json["approved_via"], "approval_workflow");
        assert_eq!(json["approval_id"], "abc-123");
    }

    #[test]
    fn test_build_promotion_history_metadata_uuid() {
        let id = Uuid::new_v4().to_string();
        let json = build_promotion_history_metadata(&id);
        assert_eq!(json["approval_id"].as_str().unwrap(), id);
    }

    #[test]
    fn test_build_promotion_history_metadata_has_both_fields() {
        let json = build_promotion_history_metadata("x");
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 2);
    }

    // -----------------------------------------------------------------------
    // build_history_where_clauses
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_history_where_clauses_none() {
        let (conditions, bind_idx) = build_history_where_clauses(&None, false, 1);
        assert!(conditions.is_empty());
        assert_eq!(bind_idx, 1);
    }

    #[test]
    fn test_build_history_where_clauses_status_only() {
        let (conditions, bind_idx) =
            build_history_where_clauses(&Some("approved".to_string()), false, 1);
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0], "pa.status = $1");
        assert_eq!(bind_idx, 2);
    }

    #[test]
    fn test_build_history_where_clauses_repo_only() {
        let (conditions, bind_idx) = build_history_where_clauses(&None, true, 1);
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0], "pa.source_repo_id = $1");
        assert_eq!(bind_idx, 2);
    }

    #[test]
    fn test_build_history_where_clauses_both() {
        let (conditions, bind_idx) =
            build_history_where_clauses(&Some("pending".to_string()), true, 1);
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0], "pa.status = $1");
        assert_eq!(conditions[1], "pa.source_repo_id = $2");
        assert_eq!(bind_idx, 3);
    }

    #[test]
    fn test_build_history_where_clauses_custom_start_idx() {
        let (conditions, bind_idx) =
            build_history_where_clauses(&Some("rejected".to_string()), true, 5);
        assert_eq!(conditions[0], "pa.status = $5");
        assert_eq!(conditions[1], "pa.source_repo_id = $6");
        assert_eq!(bind_idx, 7);
    }

    // -----------------------------------------------------------------------
    // build_where_clause
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_where_clause_empty() {
        assert_eq!(build_where_clause(&[]), "");
    }

    #[test]
    fn test_build_where_clause_single() {
        let conditions = vec!["pa.status = $1".to_string()];
        assert_eq!(build_where_clause(&conditions), " WHERE pa.status = $1");
    }

    #[test]
    fn test_build_where_clause_multiple() {
        let conditions = vec![
            "pa.status = $1".to_string(),
            "pa.source_repo_id = $2".to_string(),
        ];
        assert_eq!(
            build_where_clause(&conditions),
            " WHERE pa.status = $1 AND pa.source_repo_id = $2"
        );
    }

    #[test]
    fn test_build_where_clause_starts_with_space() {
        let conditions = vec!["x = 1".to_string()];
        let clause = build_where_clause(&conditions);
        assert!(clause.starts_with(" WHERE"));
    }

    // -----------------------------------------------------------------------
    // DB-backed approve_promotion gate tests (PR #1940).
    //
    // The approval-execute path (`approve_promotion`) is the THIRD manual
    // promote path; `promote_artifact` FORCES approval-required repos through
    // it, so governance-ruled repos bypassed the single/bulk gate entirely
    // until #1940 added this gate. These drive the real handler end to end.
    //
    // Runs under `cargo llvm-cov --lib` with a live DATABASE_URL (CI coverage
    // job); runtime-skips when no DATABASE_URL is set (NOT `#[ignore]`, so the
    // coverage instrument sees the gate path). Mirrors the in-`src` DB-test
    // pattern. Relocated from backend/tests/promotion_rules_gate_tests.rs (an
    // integration target that did not count toward `--lib` coverage).
    // -----------------------------------------------------------------------
    mod gate_db {
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::SharedState;
        use sqlx::PgPool;
        use std::sync::Arc;

        async fn make_repo_key(pool: &PgPool, tag: &str, storage_path: &std::path::Path) -> String {
            let id = Uuid::new_v4();
            let key = format!("pr1940-{}-{}", tag, &id.to_string()[..8]);
            std::fs::create_dir_all(storage_path).expect("create storage dir");
            sqlx::query(
                "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
                 VALUES ($1, $2, $2, $3, 'local', 'generic'::repository_format, false)",
            )
            .bind(id)
            .bind(&key)
            .bind(storage_path.to_string_lossy().as_ref())
            .execute(pool)
            .await
            .expect("insert repo");
            key
        }

        async fn repo_id_for_key(pool: &PgPool, key: &str) -> Uuid {
            let (id,): (Uuid,) = sqlx::query_as("SELECT id FROM repositories WHERE key = $1")
                .bind(key)
                .fetch_one(pool)
                .await
                .expect("repo id");
            id
        }

        async fn make_admin(pool: &PgPool, tag: &str) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
                 VALUES ($1, $2, $3, 'x', 'local', true, true)",
            )
            .bind(id)
            .bind(format!("pr1940-{}-{}", tag, &id.to_string()[..8]))
            .bind(format!("pr1940-{}-{}@test.local", tag, &id.to_string()[..8]))
            .execute(pool)
            .await
            .expect("insert user");
            // Grant a global (NULL-scoped) admin role assignment, mirroring the
            // genuine super-admin seeded by migration 002, so this approver
            // satisfies the promotion tenant-ownership gate for every repo.
            sqlx::query(
                "INSERT INTO role_assignments (user_id, role_id) \
                 SELECT $1, r.id FROM roles r WHERE r.name = 'admin'",
            )
            .bind(id)
            .execute(pool)
            .await
            .expect("grant global admin role");
            id
        }

        /// A second principal that is the REQUESTER of an approval. Distinct from
        /// the approver so the separation-of-duties gate is satisfied in the
        /// rule-gate tests (which predate SoD). Holds no grants; only needs to
        /// exist as the `requested_by` identity.
        async fn make_requester(pool: &PgPool, tag: &str) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
                 VALUES ($1, $2, $3, 'x', 'local', false, true)",
            )
            .bind(id)
            .bind(format!("pr1940-req-{}-{}", tag, &id.to_string()[..8]))
            .bind(format!("pr1940-req-{}-{}@test.local", tag, &id.to_string()[..8]))
            .execute(pool)
            .await
            .expect("insert requester");
            id
        }

        /// Admin-capable but tenant-scoped principal: `is_admin` is true but it
        /// holds NO global NULL-scoped assignment, only the per-repo grants added
        /// via `grant_repo`. Models a tenant admin (e.g. corp) for the
        /// cross-tenant approval test.
        async fn make_tenant_admin(pool: &PgPool, tag: &str) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
                 VALUES ($1, $2, $3, 'x', 'local', true, true)",
            )
            .bind(id)
            .bind(format!("pr1940-tadm-{}-{}", tag, &id.to_string()[..8]))
            .bind(format!("pr1940-tadm-{}-{}@test.local", tag, &id.to_string()[..8]))
            .execute(pool)
            .await
            .expect("insert tenant admin");
            id
        }

        async fn grant_repo(pool: &PgPool, user: Uuid, repo: Uuid) {
            sqlx::query(
                "INSERT INTO role_assignments (user_id, role_id, repository_id) \
                 SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
                 ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
            )
            .bind(user)
            .bind(repo)
            .execute(pool)
            .await
            .expect("grant per-repo developer role");
        }

        fn admin_ext(user_id: Uuid) -> AuthExtension {
            AuthExtension {
                user_id,
                username: "pr1940-admin".to_string(),
                email: "pr1940-admin@test.local".to_string(),
                is_admin: true,
                is_api_token: false,
                is_service_account: false,
                scopes: None,
                allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
                iat_ms: None,
            }
        }

        async fn storage_for(
            state: &SharedState,
            pool: &PgPool,
            repo_id: Uuid,
        ) -> Arc<dyn crate::storage::StorageBackend> {
            let repo = RepositoryService::new(pool.clone())
                .get_by_id(repo_id)
                .await
                .expect("get_by_id");
            state
                .storage_for_repo(&repo.storage_location())
                .expect("storage_for_repo")
        }

        async fn make_artifact(
            pool: &PgPool,
            repo_id: Uuid,
            storage: &Arc<dyn crate::storage::StorageBackend>,
            name: &str,
        ) -> Uuid {
            let id = Uuid::new_v4();
            let path = format!("{}/{}", name, id);
            let bytes = bytes::Bytes::from_static(b"pr1940-artifact-content");
            let checksum = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(&bytes);
                format!("{:x}", h.finalize())
            };
            storage.put(&path, bytes).await.expect("write storage");
            sqlx::query(
                r#"
                INSERT INTO artifacts (id, repository_id, name, path, version, size_bytes,
                                       checksum_sha256, content_type, storage_key, is_deleted)
                VALUES ($1, $2, $3, $4, '1.0.0', 23, $5, 'application/octet-stream', $4, false)
                "#,
            )
            .bind(id)
            .bind(repo_id)
            .bind(name)
            .bind(&path)
            .bind(&checksum)
            .execute(pool)
            .await
            .expect("insert artifact");
            id
        }

        async fn make_rule(
            pool: &PgPool,
            source: Uuid,
            target: Uuid,
            max_cve_severity: Option<&str>,
            min_staging_hours: Option<i32>,
        ) {
            sqlx::query(
                "INSERT INTO promotion_rules (id, name, source_repo_id, target_repo_id, is_enabled, \
                 max_cve_severity, require_signature, min_staging_hours, auto_promote) \
                 VALUES ($1, $2, $3, $4, true, $5, false, $6, false)",
            )
            .bind(Uuid::new_v4())
            .bind(format!("pr1940-rule-{}", &Uuid::new_v4().to_string()[..8]))
            .bind(source)
            .bind(target)
            .bind(max_cve_severity)
            .bind(min_staging_hours)
            .execute(pool)
            .await
            .expect("insert rule");
        }

        async fn make_pending_approval(
            pool: &PgPool,
            artifact_id: Uuid,
            source: Uuid,
            target: Uuid,
            requested_by: Uuid,
        ) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO promotion_approvals (id, artifact_id, source_repo_id, target_repo_id, \
                 requested_by, status, skip_policy_check) \
                 VALUES ($1, $2, $3, $4, $5, 'pending', false)",
            )
            .bind(id)
            .bind(artifact_id)
            .bind(source)
            .bind(target)
            .bind(requested_by)
            .execute(pool)
            .await
            .expect("insert approval");
            id
        }

        async fn target_has_artifact(pool: &PgPool, target: Uuid, path_like: &str) -> bool {
            let (n,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path LIKE $2 AND is_deleted = false",
            )
            .bind(target)
            .bind(format!("%{}%", path_like))
            .fetch_one(pool)
            .await
            .expect("count");
            n > 0
        }

        async fn approval_status(pool: &PgPool, id: Uuid) -> String {
            let (s,): (String,) =
                sqlx::query_as("SELECT status FROM promotion_approvals WHERE id = $1")
                    .bind(id)
                    .fetch_one(pool)
                    .await
                    .expect("status");
            s
        }

        async fn cleanup(pool: &PgPool, repos: &[Uuid], user: Uuid) {
            for r in repos {
                let _ = sqlx::query(
                    "DELETE FROM promotion_approvals WHERE source_repo_id = $1 OR target_repo_id = $1",
                )
                .bind(r)
                .execute(pool)
                .await;
                let _ = sqlx::query(
                    "DELETE FROM promotion_history WHERE source_repo_id = $1 OR target_repo_id = $1",
                )
                .bind(r)
                .execute(pool)
                .await;
                let _ = sqlx::query(
                    "DELETE FROM promotion_rules WHERE source_repo_id = $1 OR target_repo_id = $1",
                )
                .bind(r)
                .execute(pool)
                .await;
                let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
                    .bind(r)
                    .execute(pool)
                    .await;
                let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                    .bind(r)
                    .execute(pool)
                    .await;
            }
            let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
                .bind(user)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user)
                .execute(pool)
                .await;
        }

        /// Delete an auxiliary user (e.g. the requester) and any role assignments
        /// it holds. Used in addition to `cleanup` when a test creates a distinct
        /// requester or a second tenant principal.
        async fn cleanup_user(pool: &PgPool, user: Uuid) {
            let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
                .bind(user)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user)
                .execute(pool)
                .await;
        }

        /// #2443: `get_approval` must gate on the approval's source-repo
        /// visibility. A caller who cannot see the source repo gets the SAME
        /// existence-hiding 404 as a missing approval; a member gets 200.
        #[tokio::test]
        async fn test_get_approval_cross_tenant_authz_db() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr2443-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr2443-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "s2443", &sdir).await;
            let tgt_key = make_repo_key(&pool, "t2443", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let requester = make_requester(&pool, "2443").await;
            let member = make_requester(&pool, "2443m").await;
            let outsider = make_requester(&pool, "2443o").await;
            grant_repo(&pool, member, src).await;
            let state = tdh::build_state(pool.clone(), sdir.to_string_lossy().as_ref());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "pkg2443").await;
            let approval = make_pending_approval(&pool, artifact, src, tgt, requester).await;

            let denied = get_approval(
                State(state.clone()),
                Extension(tdh::make_auth(outsider, "o2443")),
                Path(approval),
            )
            .await;
            assert!(
                matches!(denied, Err(AppError::NotFound(_))),
                "non-member of source repo must 404: {denied:?}"
            );

            let seen = get_approval(
                State(state),
                Extension(tdh::make_auth(member, "m2443")),
                Path(approval),
            )
            .await;
            assert!(
                seen.is_ok(),
                "member of source repo must see approval: {seen:?}"
            );

            cleanup(&pool, &[src, tgt], requester).await;
            cleanup_user(&pool, member).await;
            cleanup_user(&pool, outsider).await;
        }

        /// #2443: the unfiltered pending-approvals aggregate is admin-only; a
        /// non-admin gets 403 while an admin gets 200.
        #[tokio::test]
        async fn test_list_pending_unfiltered_admin_only_db() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let user = make_requester(&pool, "2443lp").await;
            let state = tdh::build_state(pool.clone(), "/tmp");
            let denied = list_pending_approvals(
                State(state.clone()),
                Extension(tdh::make_auth(user, "lp2443")),
                Query(PendingQuery {
                    page: None,
                    per_page: None,
                    source_repository: None,
                }),
            )
            .await;
            assert!(
                matches!(denied, Err(AppError::Authorization(_))),
                "unfiltered pending list must be admin-only: {denied:?}"
            );
            let admin_ok = list_pending_approvals(
                State(state),
                Extension(tdh::admin_auth(user, "lp2443")),
                Query(PendingQuery {
                    page: None,
                    per_page: None,
                    source_repository: None,
                }),
            )
            .await;
            assert!(admin_ok.is_ok(), "admin sees the aggregate: {admin_ok:?}");
            cleanup_user(&pool, user).await;
        }

        /// The gap PR #1940 closed: approving a rule-UNMET promotion must be
        /// BLOCKED (403 Authorization), must NOT copy the artifact, and must
        /// leave the approval pending.
        #[tokio::test]
        async fn test_approval_path_blocks_rule_unmet() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-arej-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-arej-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "arej-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "arej-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "arej").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "arej").await;
            make_rule(&pool, src, tgt, None, Some(720)).await;
            // Distinct requester so the SoD gate (requester != approver) passes
            // and the rule gate is the one under test.
            let requester = make_requester(&pool, "arej").await;
            let approval = make_pending_approval(&pool, artifact, src, tgt, requester).await;

            let res = approve_promotion(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path(approval),
                Json(ReviewRequest {
                    notes: None,
                    skip_policy_check: false,
                }),
            )
            .await;
            match res {
                Err(AppError::Authorization(msg)) => assert!(
                    msg.contains("promotion rule"),
                    "block message should cite the rule; got: {msg}"
                ),
                other => panic!(
                    "expected Authorization (403) block, got ok={:?}",
                    other.is_ok()
                ),
            }
            assert!(
                !target_has_artifact(&pool, tgt, "arej").await,
                "a rule-blocked approval must NOT copy the artifact"
            );
            assert_eq!(
                approval_status(&pool, approval).await,
                "pending",
                "a blocked approval must remain pending"
            );

            cleanup(&pool, &[src, tgt], user).await;
            cleanup_user(&pool, requester).await;
        }

        /// A rule-MET approval still executes: the artifact lands in the target
        /// and the approval is marked approved.
        #[tokio::test]
        async fn test_approval_path_allows_rule_met() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-aok-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-aok-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "aok-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "aok-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "aok").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "aok").await;
            make_rule(&pool, src, tgt, None, Some(0)).await;
            let requester = make_requester(&pool, "aok").await;
            let approval = make_pending_approval(&pool, artifact, src, tgt, requester).await;

            let res = approve_promotion(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path(approval),
                Json(ReviewRequest {
                    notes: Some("ok".to_string()),
                    skip_policy_check: false,
                }),
            )
            .await;
            assert!(res.is_ok(), "a rule-met approval must execute");
            assert!(
                target_has_artifact(&pool, tgt, "aok").await,
                "a rule-met approval must copy the artifact"
            );
            assert_eq!(approval_status(&pool, approval).await, "approved");

            cleanup(&pool, &[src, tgt], user).await;
            cleanup_user(&pool, requester).await;
        }

        /// skip_policy_check admin break-glass still works on the approval path:
        /// a rule-unmet promotion executes when the reviewer overrides.
        #[tokio::test]
        async fn test_approval_path_skip_policy_check_override() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-askip-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-askip-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "askip-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "askip-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "askip").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "askip").await;
            make_rule(&pool, src, tgt, None, Some(720)).await;
            let requester = make_requester(&pool, "askip").await;
            let approval = make_pending_approval(&pool, artifact, src, tgt, requester).await;

            let res = approve_promotion(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path(approval),
                Json(ReviewRequest {
                    notes: None,
                    skip_policy_check: true,
                }),
            )
            .await;
            assert!(res.is_ok(), "skip_policy_check must bypass the rule gate");
            assert!(
                target_has_artifact(&pool, tgt, "askip").await,
                "break-glass approval must execute the promotion"
            );
            assert_eq!(approval_status(&pool, approval).await, "approved");

            cleanup(&pool, &[src, tgt], user).await;
            cleanup_user(&pool, requester).await;
        }

        // ---- separation of duties (four-eyes) on approve_promotion -----------

        /// SoD: the requester of a promotion must NOT be able to approve it.
        /// Self-approval -> 403 Authorization, no copy, approval stays pending.
        #[tokio::test]
        async fn test_approval_self_approval_blocked() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr-sod-self-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr-sod-self-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "sod-self-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "sod-self-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "sod-self").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "sodself").await;
            // No rule, so only the SoD gate can block. Same principal requests
            // AND approves.
            let approval = make_pending_approval(&pool, artifact, src, tgt, user).await;

            let res = approve_promotion(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path(approval),
                Json(ReviewRequest {
                    notes: None,
                    skip_policy_check: false,
                }),
            )
            .await;
            match res {
                Err(AppError::Authorization(msg)) => assert!(
                    msg.contains("Separation of duties"),
                    "self-approval must be denied with an SoD message; got: {msg}"
                ),
                other => panic!(
                    "expected SoD Authorization (403) block, got ok={:?}",
                    other.is_ok()
                ),
            }
            assert!(
                !target_has_artifact(&pool, tgt, "sodself").await,
                "a self-approved promotion must NOT copy the artifact"
            );
            assert_eq!(
                approval_status(&pool, approval).await,
                "pending",
                "a self-approval-blocked request must remain pending"
            );

            cleanup(&pool, &[src, tgt], user).await;
        }

        /// SoD: a DISTINCT approver (different principal from the requester) may
        /// approve, and the promotion executes.
        #[tokio::test]
        async fn test_approval_distinct_approver_allowed() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr-sod-ok-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr-sod-ok-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "sod-ok-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "sod-ok-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let approver = make_admin(&pool, "sod-ok").await;
            let requester = make_requester(&pool, "sod-ok").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "sodok").await;
            let approval = make_pending_approval(&pool, artifact, src, tgt, requester).await;

            let res = approve_promotion(
                State(state.clone()),
                Extension(admin_ext(approver)),
                Path(approval),
                Json(ReviewRequest {
                    notes: Some("second pair of eyes".to_string()),
                    skip_policy_check: false,
                }),
            )
            .await;
            assert!(
                res.is_ok(),
                "a distinct approver must be able to approve the promotion"
            );
            assert!(
                target_has_artifact(&pool, tgt, "sodok").await,
                "a distinct-approver promotion must copy the artifact"
            );
            assert_eq!(approval_status(&pool, approval).await, "approved");

            cleanup(&pool, &[src, tgt], approver).await;
            cleanup_user(&pool, requester).await;
        }

        // ---- tenant-ownership gate on approve_promotion (xtenant) ------------

        /// Cross-tenant approval: an admin-capable principal authorized only for
        /// the corp source repo approves a promotion whose target is a globex
        /// repo it does not own -> 403, no copy, approval stays pending.
        #[tokio::test]
        async fn test_approval_cross_tenant_target_blocked() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr-xta-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr-xta-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "xta-corp-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "xta-globex-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            // Tenant admin owns only the corp source, not the globex target.
            let corp_admin = make_tenant_admin(&pool, "xta-corp").await;
            grant_repo(&pool, corp_admin, src).await;
            // Distinct requester so SoD is not what trips first; the tenant gate is.
            let requester = make_requester(&pool, "xta").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "xta").await;
            let approval = make_pending_approval(&pool, artifact, src, tgt, requester).await;

            let res = approve_promotion(
                State(state.clone()),
                Extension(admin_ext(corp_admin)),
                Path(approval),
                Json(ReviewRequest {
                    notes: None,
                    skip_policy_check: false,
                }),
            )
            .await;
            match res {
                Err(AppError::Authorization(msg)) => assert!(
                    msg.contains("tenant"),
                    "cross-tenant approval must be denied with a tenant message; got: {msg}"
                ),
                other => panic!(
                    "expected tenant Authorization (403) block, got ok={:?}",
                    other.is_ok()
                ),
            }
            assert!(
                !target_has_artifact(&pool, tgt, "xta").await,
                "a cross-tenant approval must NOT copy the artifact"
            );
            assert_eq!(
                approval_status(&pool, approval).await,
                "pending",
                "a tenant-blocked approval must remain pending"
            );

            cleanup(&pool, &[src, tgt], corp_admin).await;
            cleanup_user(&pool, requester).await;
        }

        // -------------------------------------------------------------------
        // require_and_consume_approval / try_consume_approval /
        // count_pending_approvals (promotion-approval-gate-bypass).
        //
        // These exercise the new DB-backed consume gate directly: the
        // single-row `SET consumed_at` claim, its `consumed_at IS NULL` guard,
        // and the pending-vs-absent classification that builds the 409. Each
        // test runs the real SQL against Postgres; they runtime-skip without
        // DATABASE_URL (NOT `#[ignore]`, so the coverage instrument sees the
        // consume path). Shared per-test scaffolding lives in `consume_setup`
        // so the body of each test is one setup call followed by assertions.
        // -------------------------------------------------------------------

        /// Insert an `approved` + unconsumed approval row for the exact pair.
        /// Mirrors what the approve path leaves behind for a request whose
        /// promotion has NOT yet been executed via /promote.
        async fn make_approved_approval(
            pool: &PgPool,
            artifact_id: Uuid,
            source: Uuid,
            target: Uuid,
            requested_by: Uuid,
        ) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO promotion_approvals (id, artifact_id, source_repo_id, target_repo_id, \
                 requested_by, status, skip_policy_check, reviewed_at, consumed_at) \
                 VALUES ($1, $2, $3, $4, $5, 'approved', false, NOW(), NULL)",
            )
            .bind(id)
            .bind(artifact_id)
            .bind(source)
            .bind(target)
            .bind(requested_by)
            .execute(pool)
            .await
            .expect("insert approved approval");
            id
        }

        /// Whether `id`'s approval row has been consumed (`consumed_at` set).
        async fn is_consumed(pool: &PgPool, id: Uuid) -> bool {
            let (consumed,): (Option<DateTime<Utc>>,) =
                sqlx::query_as("SELECT consumed_at FROM promotion_approvals WHERE id = $1")
                    .bind(id)
                    .fetch_one(pool)
                    .await
                    .expect("read consumed_at");
            consumed.is_some()
        }

        /// Per-test scaffolding for the consume-gate tests: a source + target
        /// repo, an admin principal, and a seeded artifact in the source. Keeps
        /// each test body to a single setup call plus assertions (dup-low).
        struct ConsumeSetup {
            pool: PgPool,
            src: Uuid,
            tgt: Uuid,
            user: Uuid,
            requester: Uuid,
            artifact: Uuid,
        }

        async fn consume_setup(tag: &str) -> Option<ConsumeSetup> {
            let pool = tdh::try_pool().await?;
            let sdir = std::env::temp_dir().join(format!("pr2006-{}-s-{}", tag, Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr2006-{}-t-{}", tag, Uuid::new_v4()));
            let src_key = make_repo_key(&pool, &format!("{}-s", tag), &sdir).await;
            let tgt_key = make_repo_key(&pool, &format!("{}-t", tag), &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, tag).await;
            let requester = make_requester(&pool, tag).await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, tag).await;
            Some(ConsumeSetup {
                pool,
                src,
                tgt,
                user,
                requester,
                artifact,
            })
        }

        async fn consume_teardown(s: &ConsumeSetup) {
            cleanup(&s.pool, &[s.src, s.tgt], s.user).await;
            cleanup_user(&s.pool, s.requester).await;
        }

        /// Allow path: an APPROVED + unconsumed row -> consume succeeds once and
        /// the row is marked consumed.
        #[tokio::test]
        async fn test_consume_allows_approved_then_marks_consumed() {
            let Some(s) = consume_setup("allow").await else {
                return;
            };
            let approval =
                make_approved_approval(&s.pool, s.artifact, s.src, s.tgt, s.requester).await;
            assert!(!is_consumed(&s.pool, approval).await, "starts unconsumed");

            let res = require_and_consume_approval(&s.pool, s.artifact, s.src, s.tgt).await;
            assert!(res.is_ok(), "an approved+unconsumed row must be consumable");
            assert!(
                is_consumed(&s.pool, approval).await,
                "a consumed approval must have consumed_at stamped"
            );

            consume_teardown(&s).await;
        }

        /// Reuse path: a second consume of the same (already-spent) approval is
        /// denied with a 409 — single-use enforcement.
        #[tokio::test]
        async fn test_consume_second_use_denied() {
            let Some(s) = consume_setup("reuse").await else {
                return;
            };
            let _approval =
                make_approved_approval(&s.pool, s.artifact, s.src, s.tgt, s.requester).await;

            let first = require_and_consume_approval(&s.pool, s.artifact, s.src, s.tgt).await;
            assert!(first.is_ok(), "first consume must succeed");

            let second = require_and_consume_approval(&s.pool, s.artifact, s.src, s.tgt).await;
            match second {
                Err(AppError::Conflict(_)) => {}
                other => panic!(
                    "replay of a spent approval must be a 409 Conflict, got ok={:?}",
                    other.is_ok()
                ),
            }

            consume_teardown(&s).await;
        }

        /// Pending-only path: no approved row but a pending request exists ->
        /// denied with a 409 whose message says the request is still pending.
        #[tokio::test]
        async fn test_consume_pending_only_denied_with_pending_message() {
            let Some(s) = consume_setup("pending").await else {
                return;
            };
            let _pending =
                make_pending_approval(&s.pool, s.artifact, s.src, s.tgt, s.requester).await;
            assert_eq!(
                count_pending_approvals(&s.pool, s.artifact, s.src, s.tgt)
                    .await
                    .expect("count pending"),
                1,
                "the seeded pending request must be counted"
            );

            let res = require_and_consume_approval(&s.pool, s.artifact, s.src, s.tgt).await;
            match res {
                Err(AppError::Conflict(msg)) => assert!(
                    msg.contains("pending"),
                    "a pending-only deny must mention pending; got: {msg}"
                ),
                other => panic!(
                    "a pending-only promotion must be a 409 Conflict, got ok={:?}",
                    other.is_ok()
                ),
            }

            consume_teardown(&s).await;
        }

        /// Absent path: neither approved nor pending row for the pair -> denied
        /// with a 409.
        #[tokio::test]
        async fn test_consume_absent_denied() {
            let Some(s) = consume_setup("absent").await else {
                return;
            };
            assert_eq!(
                count_pending_approvals(&s.pool, s.artifact, s.src, s.tgt)
                    .await
                    .expect("count pending"),
                0,
                "no approval exists for this pair"
            );

            let res = require_and_consume_approval(&s.pool, s.artifact, s.src, s.tgt).await;
            assert!(
                matches!(res, Err(AppError::Conflict(_))),
                "an absent approval must be a 409 Conflict"
            );

            consume_teardown(&s).await;
        }

        /// Wrong-target path: an approved row exists for (artifact, src, OTHER
        /// target), so a consume for a DIFFERENT target finds nothing and is
        /// denied. Proves the claim is bound to the exact pair.
        #[tokio::test]
        async fn test_consume_wrong_target_denied() {
            let Some(s) = consume_setup("wrongtgt").await else {
                return;
            };
            // Approve the artifact for `src` -> `src` (a target that is not the
            // `tgt` we will attempt to promote into). The exact-pair filter must
            // therefore find no consumable row for (artifact, src, tgt).
            let other_target = s.src;
            let _approval =
                make_approved_approval(&s.pool, s.artifact, s.src, other_target, s.requester).await;

            let res = require_and_consume_approval(&s.pool, s.artifact, s.src, s.tgt).await;
            assert!(
                matches!(res, Err(AppError::Conflict(_))),
                "an approval for a different target must NOT authorize this pair"
            );

            consume_teardown(&s).await;
        }
    }
}
