//! Artifact promotion handlers.
//!
//! Handles promotion of artifacts from staging repositories to release repositories.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::RepositoryType;
use crate::models::sbom::PolicyAction;
use crate::services::promotion_policy_service::PromotionPolicyService;
use crate::services::repository_service::RepositoryService;

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Create promotion routes (nested under /api/v1/promotion)
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/repositories/:key/promote", post(promote_artifacts_bulk))
        .route(
            "/repositories/:key/artifacts/:artifact_id/promote",
            post(promote_artifact),
        )
        .route("/repositories/:key/promotion-history", get(promotion_history))
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PromoteArtifactRequest {
    /// Target repository key (e.g., "release/npm")
    pub target_repository: String,
    /// Skip policy checks (requires admin privileges)
    #[serde(default)]
    pub skip_policy_check: bool,
    /// Optional notes for the promotion record
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BulkPromoteRequest {
    /// Target repository key
    pub target_repository: String,
    /// List of artifact IDs to promote
    pub artifact_ids: Vec<Uuid>,
    /// Skip policy checks (requires admin privileges)
    #[serde(default)]
    pub skip_policy_check: bool,
    /// Optional notes for all promotion records
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PromotionResponse {
    pub promoted: bool,
    pub source: String,
    pub target: String,
    pub promotion_id: Option<Uuid>,
    pub policy_violations: Vec<PolicyViolation>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct BulkPromotionResponse {
    pub total: usize,
    pub promoted: usize,
    pub failed: usize,
    pub results: Vec<PromotionResponse>,
}

#[derive(Debug, Deserialize)]
pub struct PromotionHistoryQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub artifact_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct PromotionHistoryEntry {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub artifact_path: String,
    pub source_repo_key: String,
    pub target_repo_key: String,
    pub promoted_by: Option<Uuid>,
    pub promoted_by_username: Option<String>,
    pub policy_result: Option<serde_json::Value>,
    pub notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct PromotionHistoryResponse {
    pub items: Vec<PromotionHistoryEntry>,
    pub pagination: Pagination,
}

// ============================================================================
// Handlers
// ============================================================================

/// Promote a single artifact from staging to release repository
pub async fn promote_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, artifact_id)): Path<(String, Uuid)>,
    Json(req): Json<PromoteArtifactRequest>,
) -> Result<Json<PromotionResponse>> {
    let auth = require_auth(auth)?;
    let repo_service = RepositoryService::new(state.db.clone());

    // Verify source is a staging repository
    let source_repo = repo_service.get_by_key(&repo_key).await?;
    if source_repo.repo_type != RepositoryType::Staging {
        return Err(AppError::Validation(
            "Source repository must be a staging repository".to_string(),
        ));
    }

    // Verify target repository exists and is local (release)
    let target_repo = repo_service.get_by_key(&req.target_repository).await?;
    if target_repo.repo_type != RepositoryType::Local {
        return Err(AppError::Validation(
            "Target repository must be a local (release) repository".to_string(),
        ));
    }

    // Verify formats match
    if source_repo.format != target_repo.format {
        return Err(AppError::Validation(format!(
            "Repository format mismatch: source is {:?}, target is {:?}",
            source_repo.format, target_repo.format
        )));
    }

    // Get the artifact
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

    // Run policy checks (CVE severity, license compliance)
    let mut policy_violations: Vec<PolicyViolation> = vec![];
    let mut policy_result_json = serde_json::json!({"passed": true, "violations": []});

    if !req.skip_policy_check {
        let policy_service = PromotionPolicyService::new(state.db.clone());
        let eval_result = policy_service
            .evaluate_artifact(artifact_id, source_repo.id)
            .await?;

        // Convert service violations to handler violations
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

        // Block promotion if policy evaluation failed with Block action
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
    }

    // Copy artifact to target repository
    let new_artifact_id = Uuid::new_v4();
    let new_storage_key = format!(
        "{}/{}",
        target_repo.storage_path.trim_end_matches('/'),
        artifact.path
    );

    // Copy the file
    let source_path = format!(
        "{}/{}",
        source_repo.storage_path.trim_end_matches('/'),
        artifact.storage_key
    );
    let dest_path = &new_storage_key;

    // Create parent directories
    if let Some(parent) = std::path::Path::new(dest_path).parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create directories: {}", e)))?;
    }

    tokio::fs::copy(&source_path, dest_path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to copy artifact: {}", e)))?;

    // Insert artifact record in target repo
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
        artifact.path,
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

    // Record promotion history
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

/// Promote multiple artifacts from staging to release repository
pub async fn promote_artifacts_bulk(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    Json(req): Json<BulkPromoteRequest>,
) -> Result<Json<BulkPromotionResponse>> {
    let auth = require_auth(auth)?;
    let repo_service = RepositoryService::new(state.db.clone());

    // Verify source is a staging repository
    let source_repo = repo_service.get_by_key(&repo_key).await?;
    if source_repo.repo_type != RepositoryType::Staging {
        return Err(AppError::Validation(
            "Source repository must be a staging repository".to_string(),
        ));
    }

    // Verify target repository exists and is local (release)
    let target_repo = repo_service.get_by_key(&req.target_repository).await?;
    if target_repo.repo_type != RepositoryType::Local {
        return Err(AppError::Validation(
            "Target repository must be a local (release) repository".to_string(),
        ));
    }

    let mut results = Vec::new();
    let mut promoted = 0;
    let mut failed = 0;

    for artifact_id in &req.artifact_ids {
        // Get the artifact
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
                results.push(PromotionResponse {
                    promoted: false,
                    source: format!("{}/{}", repo_key, artifact_id),
                    target: req.target_repository.clone(),
                    promotion_id: None,
                    policy_violations: vec![],
                    message: Some("Artifact not found".to_string()),
                });
                continue;
            }
            Err(e) => {
                failed += 1;
                results.push(PromotionResponse {
                    promoted: false,
                    source: format!("{}/{}", repo_key, artifact_id),
                    target: req.target_repository.clone(),
                    promotion_id: None,
                    policy_violations: vec![],
                    message: Some(format!("Database error: {}", e)),
                });
                continue;
            }
        };

        // Copy artifact file
        let source_path = format!(
            "{}/{}",
            source_repo.storage_path.trim_end_matches('/'),
            artifact.storage_key
        );
        let dest_path = format!(
            "{}/{}",
            target_repo.storage_path.trim_end_matches('/'),
            artifact.path
        );

        if let Some(parent) = std::path::Path::new(&dest_path).parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                failed += 1;
                results.push(PromotionResponse {
                    promoted: false,
                    source: format!("{}/{}", repo_key, artifact.path),
                    target: format!("{}/{}", req.target_repository, artifact.path),
                    promotion_id: None,
                    policy_violations: vec![],
                    message: Some(format!("Failed to create directories: {}", e)),
                });
                continue;
            }
        }

        if let Err(e) = tokio::fs::copy(&source_path, &dest_path).await {
            failed += 1;
            results.push(PromotionResponse {
                promoted: false,
                source: format!("{}/{}", repo_key, artifact.path),
                target: format!("{}/{}", req.target_repository, artifact.path),
                promotion_id: None,
                policy_violations: vec![],
                message: Some(format!("Failed to copy artifact: {}", e)),
            });
            continue;
        }

        // Insert artifact record
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
            artifact.path,
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
            results.push(PromotionResponse {
                promoted: false,
                source: format!("{}/{}", repo_key, artifact.path),
                target: format!("{}/{}", req.target_repository, artifact.path),
                promotion_id: None,
                policy_violations: vec![],
                message: Some(msg),
            });
            continue;
        }

        // Record promotion history
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
            source: format!("{}/{}", repo_key, artifact.path),
            target: format!("{}/{}", req.target_repository, artifact.path),
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

/// Get promotion history for a repository
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
        promoted_by: Option<Uuid>,
        promoted_by_username: Option<String>,
        policy_result: Option<serde_json::Value>,
        notes: Option<String>,
        created_at: chrono::DateTime<chrono::Utc>,
    }

    let rows: Vec<HistoryRow> = sqlx::query_as(
        r#"
        SELECT
            ph.id,
            ph.artifact_id,
            a.path as artifact_path,
            sr.key as source_repo_key,
            tr.key as target_repo_key,
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
        WHERE ph.source_repo_id = $1 OR ph.target_repo_id = $1
        ORDER BY ph.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(repo.id)
    .bind(per_page as i64)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    let total: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*)::BIGINT as "count!" FROM promotion_history WHERE source_repo_id = $1 OR target_repo_id = $1"#,
        repo.id
    )
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
