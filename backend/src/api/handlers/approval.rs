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
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::promotion_policy_service::PromotionPolicyService;
use crate::services::repository_service::RepositoryService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

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
    Query(query): Query<PendingQuery>,
) -> Result<Json<ApprovalListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let (rows, total): (Vec<ApprovalRow>, i64) = if let Some(ref source_key) =
        query.source_repository
    {
        let repo_service = RepositoryService::new(state.db.clone());
        let source = repo_service.get_by_key(source_key).await?;

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
    Path(approval_id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let row: ApprovalRow = sqlx::query_as(&format!("{} WHERE pa.id = $1", SELECT_APPROVAL))
        .bind(approval_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Approval request not found".to_string()))?;

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
        status: String,
    }

    let approval: SimpleRow = sqlx::query_as(
        "SELECT id, artifact_id, source_repo_id, target_repo_id, status FROM promotion_approvals WHERE id = $1",
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

    // Copy storage content
    let source_storage = FilesystemStorage::new(&source_repo.storage_path);
    let target_storage = FilesystemStorage::new(&target_repo.storage_path);

    let content = source_storage
        .get(&artifact.storage_key)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read source artifact: {}", e)))?;
    target_storage
        .put(&artifact.storage_key, content)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write promoted artifact: {}", e)))?;

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

    // Update approval status
    let now = Utc::now();
    sqlx::query(
        r#"
        UPDATE promotion_approvals
        SET status = 'approved', reviewed_by = $1, reviewed_at = $2, review_notes = $3
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
    Query(query): Query<ApprovalHistoryQuery>,
) -> Result<Json<ApprovalListResponse>> {
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
        let repo = repo_service.get_by_key(source_key).await?;
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
            replication_priority: ReplicationPriority::LocalOnly,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let target = Repository {
            id: Uuid::nil(),
            key: "release-maven".to_string(),
            name: "Release Maven".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/release".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            replication_priority: ReplicationPriority::Immediate,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(validate_promotion_repos(&source, &target).is_ok());
    }

    #[test]
    fn test_validate_promotion_repos_source_not_staging() {
        use crate::models::repository::*;
        let source = Repository {
            id: Uuid::nil(),
            key: "local-maven".to_string(),
            name: "Local Maven".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/local".to_string(),
            upstream_url: None,
            is_public: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::LocalOnly,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let target = Repository {
            id: Uuid::nil(),
            key: "release-maven".to_string(),
            name: "Release Maven".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/release".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            replication_priority: ReplicationPriority::Immediate,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let result = validate_promotion_repos(&source, &target);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("staging"), "Error: {}", err_msg);
    }

    #[test]
    fn test_validate_promotion_repos_format_mismatch() {
        use crate::models::repository::*;
        let source = Repository {
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
            replication_priority: ReplicationPriority::LocalOnly,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let target = Repository {
            id: Uuid::nil(),
            key: "release-npm".to_string(),
            name: "Release NPM".to_string(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/release".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            replication_priority: ReplicationPriority::Immediate,
            promotion_target_id: None,
            promotion_policy_id: None,
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
}
