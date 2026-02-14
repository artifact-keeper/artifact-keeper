//! Artifact promotion handlers.
//!
//! Handles promotion of artifacts from staging repositories to release repositories.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::RepositoryType;
use crate::models::sbom::PolicyAction;
use crate::services::promotion_policy_service::PromotionPolicyService;
use crate::services::repository_service::RepositoryService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/repositories/:key/promote", post(promote_artifacts_bulk))
        .route(
            "/repositories/:key/artifacts/:artifact_id/promote",
            post(promote_artifact),
        )
        .route(
            "/repositories/:key/artifacts/:artifact_id/reject",
            post(reject_artifact),
        )
        .route(
            "/repositories/:key/promotion-history",
            get(promotion_history),
        )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PromoteArtifactRequest {
    pub target_repository: String,
    #[serde(default)]
    pub skip_policy_check: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkPromoteRequest {
    pub target_repository: String,
    pub artifact_ids: Vec<Uuid>,
    #[serde(default)]
    pub skip_policy_check: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromotionResponse {
    pub promoted: bool,
    pub source: String,
    pub target: String,
    pub promotion_id: Option<Uuid>,
    pub policy_violations: Vec<PolicyViolation>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BulkPromotionResponse {
    pub total: usize,
    pub promoted: usize,
    pub failed: usize,
    pub results: Vec<PromotionResponse>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RejectArtifactRequest {
    pub reason: String,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RejectionResponse {
    pub rejected: bool,
    pub artifact_id: Uuid,
    pub source: String,
    pub reason: String,
    pub rejection_id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PromotionHistoryQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub artifact_id: Option<Uuid>,
    pub status: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromotionHistoryEntry {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub artifact_path: String,
    pub source_repo_key: String,
    pub target_repo_key: String,
    pub status: String,
    pub rejection_reason: Option<String>,
    pub promoted_by: Option<Uuid>,
    pub promoted_by_username: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub policy_result: Option<serde_json::Value>,
    pub notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromotionHistoryResponse {
    pub items: Vec<PromotionHistoryEntry>,
    pub pagination: Pagination,
}

/// Validate that source is staging and target is local, with matching formats.
pub fn validate_promotion_repos(
    source: &crate::models::repository::Repository,
    target: &crate::models::repository::Repository,
) -> Result<()> {
    if source.repo_type != RepositoryType::Staging {
        return Err(AppError::Validation(
            "Source repository must be a staging repository".to_string(),
        ));
    }
    if target.repo_type != RepositoryType::Local {
        return Err(AppError::Validation(
            "Target repository must be a local (release) repository".to_string(),
        ));
    }
    if source.format != target.format {
        return Err(AppError::Validation(format!(
            "Repository format mismatch: source is {:?}, target is {:?}",
            source.format, target.format
        )));
    }
    Ok(())
}

fn failed_response(source: String, target: String, message: String) -> PromotionResponse {
    PromotionResponse {
        promoted: false,
        source,
        target,
        promotion_id: None,
        policy_violations: vec![],
        message: Some(message),
    }
}

#[utoipa::path(
    post,
    path = "/repositories/{key}/artifacts/{artifact_id}/promote",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Source repository key"),
        ("artifact_id" = Uuid, Path, description = "Artifact ID to promote"),
    ),
    request_body = PromoteArtifactRequest,
    responses(
        (status = 200, description = "Artifact promotion result", body = PromotionResponse),
        (status = 404, description = "Artifact or repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "Artifact already exists in target", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error (repo type/format mismatch)", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn promote_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((repo_key, artifact_id)): Path<(String, Uuid)>,
    Json(req): Json<PromoteArtifactRequest>,
) -> Result<Json<PromotionResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());

    let source_repo = repo_service.get_by_key(&repo_key).await?;
    let target_repo = repo_service.get_by_key(&req.target_repository).await?;
    validate_promotion_repos(&source_repo, &target_repo)?;

    if super::approval::check_approval_required(&state.db, source_repo.id).await? {
        return Ok(Json(PromotionResponse {
            promoted: false,
            source: format!("{}/{}", repo_key, artifact_id),
            target: req.target_repository.clone(),
            promotion_id: None,
            policy_violations: vec![],
            message: Some(
                "This repository requires approval for promotions. \
                 Use POST /api/v1/approval/request to submit an approval request."
                    .to_string(),
            ),
        }));
    }

    let artifact = sqlx::query_as!(
        crate::models::artifact::Artifact,
        r#"
        SELECT
            id, repository_id, path, name, version, size_bytes,
            checksum_sha256, checksum_md5, checksum_sha1,
            content_type, storage_key, is_deleted, uploaded_by,
            created_at, updated_at
        FROM artifacts
        WHERE id = $1 AND repository_id = $2 AND is_deleted = false
        "#,
        artifact_id,
        source_repo.id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found in staging repository".to_string()))?;

    let mut policy_violations: Vec<PolicyViolation> = vec![];
    let mut policy_result_json = serde_json::json!({"passed": true, "violations": []});

    if !req.skip_policy_check {
        let policy_service = PromotionPolicyService::new(state.db.clone());
        let eval_result = policy_service
            .evaluate_artifact(artifact_id, source_repo.id)
            .await?;

        policy_violations = eval_result
            .violations
            .iter()
            .map(|v| PolicyViolation {
                rule: v.rule.clone(),
                severity: v.severity.clone(),
                message: v.message.clone(),
            })
            .collect();

        policy_result_json = serde_json::json!({
            "passed": eval_result.passed,
            "action": format!("{:?}", eval_result.action).to_lowercase(),
            "violations": eval_result.violations,
            "cve_summary": eval_result.cve_summary,
            "license_summary": eval_result.license_summary,
        });

        if !eval_result.passed && eval_result.action == PolicyAction::Block {
            return Ok(Json(PromotionResponse {
                promoted: false,
                source: format!("{}/{}", repo_key, artifact.path),
                target: format!("{}/{}", req.target_repository, artifact.path),
                promotion_id: None,
                policy_violations,
                message: Some("Promotion blocked by policy violations".to_string()),
            }));
        }

        // Evaluate quality gates (if quality check service is available)
        if let Some(ref qc) = state.quality_check_service {
            match qc.evaluate_quality_gate(artifact_id, source_repo.id).await {
                Ok(gate_eval) => {
                    if !gate_eval.passed && gate_eval.action == "block" {
                        let gate_violations: Vec<PolicyViolation> = gate_eval
                            .violations
                            .iter()
                            .map(|v| PolicyViolation {
                                rule: v.rule.clone(),
                                severity: "high".to_string(),
                                message: v.message.clone(),
                            })
                            .collect();
                        return Ok(Json(PromotionResponse {
                            promoted: false,
                            source: format!("{}/{}", repo_key, artifact.path),
                            target: format!("{}/{}", req.target_repository, artifact.path),
                            promotion_id: None,
                            policy_violations: gate_violations,
                            message: Some(format!(
                                "Promotion blocked by quality gate '{}' (health score: {}, grade: {})",
                                gate_eval.gate_name, gate_eval.health_score, gate_eval.health_grade
                            )),
                        }));
                    }
                    // Warn violations get appended but don't block
                    if !gate_eval.passed {
                        for v in &gate_eval.violations {
                            policy_violations.push(PolicyViolation {
                                rule: v.rule.clone(),
                                severity: "medium".to_string(),
                                message: v.message.clone(),
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Quality gate evaluation failed for artifact {}: {}",
                        artifact_id,
                        e
                    );
                }
            }
        }
    }

    let new_artifact_id = Uuid::new_v4();
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

    sqlx::query!(
        r#"
        INSERT INTO artifacts (
            id, repository_id, path, name, version, size_bytes,
            checksum_sha256, checksum_md5, checksum_sha1,
            content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
        new_artifact_id,
        target_repo.id,
        artifact.path,
        artifact.name,
        artifact.version,
        artifact.size_bytes,
        artifact.checksum_sha256,
        artifact.checksum_md5,
        artifact.checksum_sha1,
        artifact.content_type,
        artifact.storage_key,
        auth.user_id
    )
    .execute(&state.db)
    .await
    .map_err(|e: sqlx::Error| {
        if e.to_string().contains("duplicate key") {
            AppError::Conflict(format!(
                "Artifact already exists in target repository: {}",
                artifact.path
            ))
        } else {
            AppError::Database(e.to_string())
        }
    })?;

    let promotion_id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO promotion_history (
            id, artifact_id, source_repo_id, target_repo_id,
            promoted_by, policy_result, notes
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        promotion_id,
        artifact_id,
        source_repo.id,
        target_repo.id,
        auth.user_id,
        policy_result_json,
        req.notes
    )
    .execute(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    tracing::info!(
        source_repo = %repo_key,
        target_repo = %req.target_repository,
        artifact = %artifact.path,
        promoted_by = %auth.user_id,
        "Artifact promoted successfully"
    );

    Ok(Json(PromotionResponse {
        promoted: true,
        source: format!("{}/{}", repo_key, artifact.path),
        target: format!("{}/{}", req.target_repository, artifact.path),
        promotion_id: Some(promotion_id),
        policy_violations: vec![],
        message: Some("Artifact promoted successfully".to_string()),
    }))
}

#[utoipa::path(
    post,
    path = "/repositories/{key}/promote",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Source repository key"),
    ),
    request_body = BulkPromoteRequest,
    responses(
        (status = 200, description = "Bulk promotion results", body = BulkPromotionResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error (repo type/format mismatch)", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn promote_artifacts_bulk(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(repo_key): Path<String>,
    Json(req): Json<BulkPromoteRequest>,
) -> Result<Json<BulkPromotionResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());

    let source_repo = repo_service.get_by_key(&repo_key).await?;
    let target_repo = repo_service.get_by_key(&req.target_repository).await?;
    validate_promotion_repos(&source_repo, &target_repo)?;

    let mut results = Vec::new();
    let mut promoted = 0;
    let mut failed = 0;

    for artifact_id in &req.artifact_ids {
        let artifact = match sqlx::query_as!(
            crate::models::artifact::Artifact,
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                created_at, updated_at
            FROM artifacts
            WHERE id = $1 AND repository_id = $2 AND is_deleted = false
            "#,
            artifact_id,
            source_repo.id
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(a)) => a,
            Ok(None) => {
                failed += 1;
                results.push(failed_response(
                    format!("{}/{}", repo_key, artifact_id),
                    req.target_repository.clone(),
                    "Artifact not found".to_string(),
                ));
                continue;
            }
            Err(e) => {
                failed += 1;
                results.push(failed_response(
                    format!("{}/{}", repo_key, artifact_id),
                    req.target_repository.clone(),
                    format!("Database error: {}", e),
                ));
                continue;
            }
        };

        let source_display = format!("{}/{}", repo_key, artifact.path);
        let target_display = format!("{}/{}", req.target_repository, artifact.path);

        let source_storage = FilesystemStorage::new(&source_repo.storage_path);
        let target_storage = FilesystemStorage::new(&target_repo.storage_path);

        let content = match source_storage.get(&artifact.storage_key).await {
            Ok(c) => c,
            Err(e) => {
                failed += 1;
                results.push(failed_response(
                    source_display,
                    target_display,
                    format!("Failed to read source artifact: {}", e),
                ));
                continue;
            }
        };

        if let Err(e) = target_storage.put(&artifact.storage_key, content).await {
            failed += 1;
            results.push(failed_response(
                source_display,
                target_display,
                format!("Failed to write promoted artifact: {}", e),
            ));
            continue;
        }

        let new_artifact_id = Uuid::new_v4();
        let insert_result: std::result::Result<_, sqlx::Error> = sqlx::query!(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            new_artifact_id,
            target_repo.id,
            artifact.path,
            artifact.name,
            artifact.version,
            artifact.size_bytes,
            artifact.checksum_sha256,
            artifact.checksum_md5,
            artifact.checksum_sha1,
            artifact.content_type,
            artifact.storage_key,
            auth.user_id
        )
        .execute(&state.db)
        .await;

        if let Err(e) = insert_result {
            failed += 1;
            let msg = if e.to_string().contains("duplicate key") {
                "Artifact already exists in target".to_string()
            } else {
                format!("Database error: {}", e)
            };
            results.push(failed_response(source_display, target_display, msg));
            continue;
        }

        let promotion_id = Uuid::new_v4();
        let policy_result = serde_json::json!({"passed": true, "violations": []});

        let _ = sqlx::query!(
            r#"
            INSERT INTO promotion_history (
                id, artifact_id, source_repo_id, target_repo_id,
                promoted_by, policy_result, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            promotion_id,
            artifact_id,
            source_repo.id,
            target_repo.id,
            auth.user_id,
            policy_result,
            req.notes
        )
        .execute(&state.db)
        .await;

        promoted += 1;
        results.push(PromotionResponse {
            promoted: true,
            source: source_display,
            target: target_display,
            promotion_id: Some(promotion_id),
            policy_violations: vec![],
            message: Some("Promoted successfully".to_string()),
        });
    }

    tracing::info!(
        source_repo = %repo_key,
        target_repo = %req.target_repository,
        total = req.artifact_ids.len(),
        promoted = promoted,
        failed = failed,
        "Bulk promotion completed"
    );

    Ok(Json(BulkPromotionResponse {
        total: req.artifact_ids.len(),
        promoted,
        failed,
        results,
    }))
}

#[utoipa::path(
    post,
    path = "/repositories/{key}/artifacts/{artifact_id}/reject",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Source repository key"),
        ("artifact_id" = Uuid, Path, description = "Artifact ID to reject"),
    ),
    request_body = RejectArtifactRequest,
    responses(
        (status = 200, description = "Artifact rejection result", body = RejectionResponse),
        (status = 404, description = "Artifact or repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((repo_key, artifact_id)): Path<(String, Uuid)>,
    Json(req): Json<RejectArtifactRequest>,
) -> Result<Json<RejectionResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let source_repo = repo_service.get_by_key(&repo_key).await?;

    if source_repo.repo_type != RepositoryType::Staging {
        return Err(AppError::Validation(
            "Artifacts can only be rejected from staging repositories".to_string(),
        ));
    }

    // Verify artifact exists
    let artifact_exists: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = $1 AND repository_id = $2 AND is_deleted = false)"#,
    )
    .bind(artifact_id)
    .bind(source_repo.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    if !artifact_exists {
        return Err(AppError::NotFound(
            "Artifact not found in staging repository".to_string(),
        ));
    }

    let rejection_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO promotion_history (
            id, artifact_id, source_repo_id, target_repo_id,
            promoted_by, status, rejection_reason, notes
        )
        VALUES ($1, $2, $3, $3, $4, 'rejected', $5, $6)
        "#,
    )
    .bind(rejection_id)
    .bind(artifact_id)
    .bind(source_repo.id)
    .bind(auth.user_id)
    .bind(&req.reason)
    .bind(&req.notes)
    .execute(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    tracing::info!(
        source_repo = %repo_key,
        artifact_id = %artifact_id,
        rejected_by = %auth.user_id,
        reason = %req.reason,
        "Artifact rejected"
    );

    Ok(Json(RejectionResponse {
        rejected: true,
        artifact_id,
        source: repo_key,
        reason: req.reason,
        rejection_id,
    }))
}

#[utoipa::path(
    get,
    path = "/repositories/{key}/promotion-history",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("page" = Option<u32>, Query, description = "Page number (1-indexed)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 100)"),
        ("artifact_id" = Option<Uuid>, Query, description = "Filter by artifact ID"),
        ("status" = Option<String>, Query, description = "Filter by status (promoted, rejected, pending_approval)"),
    ),
    responses(
        (status = 200, description = "Promotion history for repository", body = PromotionHistoryResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn promotion_history(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(query): Query<PromotionHistoryQuery>,
) -> Result<Json<PromotionHistoryResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&repo_key).await?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    #[derive(sqlx::FromRow)]
    struct HistoryRow {
        id: Uuid,
        artifact_id: Uuid,
        artifact_path: Option<String>,
        source_repo_key: Option<String>,
        target_repo_key: Option<String>,
        status: String,
        rejection_reason: Option<String>,
        promoted_by: Option<Uuid>,
        promoted_by_username: Option<String>,
        policy_result: Option<serde_json::Value>,
        notes: Option<String>,
        created_at: chrono::DateTime<chrono::Utc>,
    }

    let status_filter = query.status.as_deref();

    let rows: Vec<HistoryRow> = sqlx::query_as(
        r#"
        SELECT
            ph.id,
            ph.artifact_id,
            a.path as artifact_path,
            sr.key as source_repo_key,
            tr.key as target_repo_key,
            ph.status,
            ph.rejection_reason,
            ph.promoted_by,
            u.username as promoted_by_username,
            ph.policy_result,
            ph.notes,
            ph.created_at
        FROM promotion_history ph
        LEFT JOIN artifacts a ON a.id = ph.artifact_id
        LEFT JOIN repositories sr ON sr.id = ph.source_repo_id
        LEFT JOIN repositories tr ON tr.id = ph.target_repo_id
        LEFT JOIN users u ON u.id = ph.promoted_by
        WHERE (ph.source_repo_id = $1 OR ph.target_repo_id = $1)
          AND ($4::TEXT IS NULL OR ph.status = $4)
        ORDER BY ph.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(repo.id)
    .bind(per_page as i64)
    .bind(offset)
    .bind(status_filter)
    .fetch_all(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::BIGINT FROM promotion_history
           WHERE (source_repo_id = $1 OR target_repo_id = $1)
             AND ($2::TEXT IS NULL OR status = $2)"#,
    )
    .bind(repo.id)
    .bind(status_filter)
    .fetch_one(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    let items = rows
        .into_iter()
        .map(|row| PromotionHistoryEntry {
            id: row.id,
            artifact_id: row.artifact_id,
            artifact_path: row.artifact_path.unwrap_or_default(),
            source_repo_key: row.source_repo_key.unwrap_or_default(),
            target_repo_key: row.target_repo_key.unwrap_or_default(),
            status: row.status,
            rejection_reason: row.rejection_reason,
            promoted_by: row.promoted_by,
            promoted_by_username: row.promoted_by_username,
            policy_result: row.policy_result,
            notes: row.notes,
            created_at: row.created_at,
        })
        .collect();

    Ok(Json(PromotionHistoryResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        promote_artifact,
        promote_artifacts_bulk,
        reject_artifact,
        promotion_history,
    ),
    components(schemas(
        PromoteArtifactRequest,
        BulkPromoteRequest,
        PromotionResponse,
        PolicyViolation,
        BulkPromotionResponse,
        RejectArtifactRequest,
        RejectionResponse,
        PromotionHistoryQuery,
        PromotionHistoryEntry,
        PromotionHistoryResponse,
    ))
)]
pub struct PromotionApiDoc;
