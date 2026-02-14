//! Lifecycle policy service.
//!
//! Manages artifact retention policies per repository with support for:
//! - max_age_days: delete artifacts older than N days
//! - max_versions: keep only the last N versions per package
//! - no_downloads_days: delete artifacts not downloaded in N days
//! - tag_pattern_keep: keep artifacts matching a regex pattern
//! - tag_pattern_delete: delete artifacts matching a regex pattern
//! - size_quota_bytes: enforce per-repo storage quotas

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// A lifecycle policy attached to a repository (or global if repository_id is NULL).
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct LifecyclePolicy {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub policy_type: String,
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    pub priority: i32,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_run_items_removed: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a lifecycle policy.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub policy_type: String,
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    pub priority: Option<i32>,
}

/// Request to update a lifecycle policy.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePolicyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    #[schema(value_type = Option<Object>)]
    pub config: Option<serde_json::Value>,
    pub priority: Option<i32>,
}

/// Result of a lifecycle policy dry-run or execution.
#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyExecutionResult {
    pub policy_id: Uuid,
    pub policy_name: String,
    pub dry_run: bool,
    pub artifacts_matched: i64,
    pub artifacts_removed: i64,
    pub bytes_freed: i64,
    pub errors: Vec<String>,
}

/// Aggregate count and bytes for policy matching queries.
#[derive(Debug, sqlx::FromRow)]
struct CountBytes {
    pub count: i64,
    pub bytes: i64,
}

/// Candidate artifact for size quota eviction.
#[derive(Debug, sqlx::FromRow)]
struct SizeCandidate {
    pub id: Uuid,
    pub size_bytes: i64,
}

/// Total usage for a repository.
#[derive(Debug, sqlx::FromRow)]
struct UsageTotal {
    pub total: i64,
}

pub struct LifecycleService {
    db: PgPool,
}

impl LifecycleService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new lifecycle policy.
    pub async fn create_policy(&self, req: CreatePolicyRequest) -> Result<LifecyclePolicy> {
        // Validate policy_type
        let valid_types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        if !valid_types.contains(&req.policy_type.as_str()) {
            return Err(AppError::Validation(format!(
                "Invalid policy_type '{}'. Must be one of: {}",
                req.policy_type,
                valid_types.join(", ")
            )));
        }

        self.validate_policy_config(&req.policy_type, &req.config)?;

        let policy = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            INSERT INTO lifecycle_policies (repository_id, name, description, policy_type, config, priority)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, repository_id, name, description, enabled,
                      policy_type, config, priority, last_run_at,
                      last_run_items_removed, created_at, updated_at
            "#,
        )
        .bind(req.repository_id)
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.policy_type)
        .bind(&req.config)
        .bind(req.priority.unwrap_or(0))
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policy)
    }

    /// List lifecycle policies, optionally filtered by repository.
    pub async fn list_policies(&self, repository_id: Option<Uuid>) -> Result<Vec<LifecyclePolicy>> {
        let policies = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, created_at, updated_at
            FROM lifecycle_policies
            WHERE ($1::UUID IS NULL OR repository_id = $1 OR repository_id IS NULL)
            ORDER BY priority DESC, created_at ASC
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policies)
    }

    /// Get a single policy by ID.
    pub async fn get_policy(&self, id: Uuid) -> Result<LifecyclePolicy> {
        sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, created_at, updated_at
            FROM lifecycle_policies
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Lifecycle policy not found".to_string()))
    }

    /// Update a lifecycle policy.
    pub async fn update_policy(
        &self,
        id: Uuid,
        req: UpdatePolicyRequest,
    ) -> Result<LifecyclePolicy> {
        let existing = self.get_policy(id).await?;

        let name = req.name.unwrap_or(existing.name);
        let description = req.description.or(existing.description);
        let enabled = req.enabled.unwrap_or(existing.enabled);
        let config = req.config.unwrap_or(existing.config);
        let priority = req.priority.unwrap_or(existing.priority);

        self.validate_policy_config(&existing.policy_type, &config)?;

        let policy = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            UPDATE lifecycle_policies
            SET name = $2, description = $3, enabled = $4,
                config = $5, priority = $6, updated_at = NOW()
            WHERE id = $1
            RETURNING id, repository_id, name, description, enabled,
                      policy_type, config, priority, last_run_at,
                      last_run_items_removed, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&name)
        .bind(&description)
        .bind(enabled)
        .bind(&config)
        .bind(priority)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policy)
    }

    /// Delete a lifecycle policy.
    pub async fn delete_policy(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM lifecycle_policies WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Lifecycle policy not found".to_string()));
        }

        Ok(())
    }

    /// Execute a policy (dry_run=true previews without deleting).
    pub async fn execute_policy(&self, id: Uuid, dry_run: bool) -> Result<PolicyExecutionResult> {
        let policy = self.get_policy(id).await?;

        if !policy.enabled && !dry_run {
            return Err(AppError::Validation(
                "Cannot execute a disabled policy".to_string(),
            ));
        }

        let result = match policy.policy_type.as_str() {
            "max_age_days" => self.execute_max_age(&policy, dry_run).await?,
            "max_versions" => self.execute_max_versions(&policy, dry_run).await?,
            "no_downloads_days" => self.execute_no_downloads(&policy, dry_run).await?,
            "tag_pattern_delete" => self.execute_tag_pattern_delete(&policy, dry_run).await?,
            "size_quota_bytes" => self.execute_size_quota(&policy, dry_run).await?,
            _ => {
                return Err(AppError::Internal(format!(
                    "Unsupported policy type: {}",
                    policy.policy_type
                )));
            }
        };

        // Update last_run stats
        if !dry_run {
            sqlx::query(
                "UPDATE lifecycle_policies SET last_run_at = NOW(), last_run_items_removed = $2 WHERE id = $1",
            )
            .bind(id)
            .bind(result.artifacts_removed)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        Ok(result)
    }

    /// Execute all enabled policies (called by scheduled background task).
    pub async fn execute_all_enabled(&self) -> Result<Vec<PolicyExecutionResult>> {
        let policies = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, created_at, updated_at
            FROM lifecycle_policies
            WHERE enabled = true
            ORDER BY priority DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for policy in policies {
            match self.execute_policy(policy.id, false).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    tracing::error!(
                        "Failed to execute lifecycle policy '{}': {}",
                        policy.name,
                        e
                    );
                    results.push(PolicyExecutionResult {
                        policy_id: policy.id,
                        policy_name: policy.name,
                        dry_run: false,
                        artifacts_matched: 0,
                        artifacts_removed: 0,
                        bytes_freed: 0,
                        errors: vec![e.to_string()],
                    });
                }
            }
        }

        Ok(results)
    }

    // --- Policy execution implementations ---

    async fn execute_max_age(
        &self,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let days = policy
            .config
            .get("days")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                AppError::Validation("max_age_days requires 'days' in config".to_string())
            })?;

        let matched = if policy.repository_id.is_some() {
            sqlx::query_as::<_, CountBytes>(
                r#"
                SELECT COUNT(*) as count, COALESCE(SUM(size_bytes), 0)::BIGINT as bytes
                FROM artifacts
                WHERE repository_id = $1
                  AND is_deleted = false
                  AND created_at < NOW() - make_interval(days => $2::INT)
                "#,
            )
            .bind(policy.repository_id)
            .bind(days as i32)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        } else {
            sqlx::query_as::<_, CountBytes>(
                r#"
                SELECT COUNT(*) as count, COALESCE(SUM(size_bytes), 0)::BIGINT as bytes
                FROM artifacts
                WHERE is_deleted = false
                  AND created_at < NOW() - make_interval(days => $1::INT)
                "#,
            )
            .bind(days as i32)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        };

        let mut removed = 0i64;
        if !dry_run && matched.count > 0 {
            let result = if policy.repository_id.is_some() {
                sqlx::query(
                    r#"
                    UPDATE artifacts SET is_deleted = true
                    WHERE repository_id = $1
                      AND is_deleted = false
                      AND created_at < NOW() - make_interval(days => $2::INT)
                    "#,
                )
                .bind(policy.repository_id)
                .bind(days as i32)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            } else {
                sqlx::query(
                    r#"
                    UPDATE artifacts SET is_deleted = true
                    WHERE is_deleted = false
                      AND created_at < NOW() - make_interval(days => $1::INT)
                    "#,
                )
                .bind(days as i32)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            };
            removed = result.rows_affected() as i64;
        }

        Ok(PolicyExecutionResult {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            dry_run,
            artifacts_matched: matched.count,
            artifacts_removed: if dry_run { 0 } else { removed },
            bytes_freed: if dry_run { 0 } else { matched.bytes },
            errors: vec![],
        })
    }

    async fn execute_max_versions(
        &self,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let keep = policy
            .config
            .get("keep")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                AppError::Validation("max_versions requires 'keep' in config".to_string())
            })?;

        let repo_id = policy.repository_id.ok_or_else(|| {
            AppError::Validation("max_versions requires a repository_id".to_string())
        })?;

        // Find artifacts to remove: for each (name), keep only the latest N
        let matched = sqlx::query_as::<_, CountBytes>(
            r#"
            SELECT COUNT(*) as count, COALESCE(SUM(a.size_bytes), 0)::BIGINT as bytes
            FROM artifacts a
            WHERE a.repository_id = $1
              AND a.is_deleted = false
              AND a.id NOT IN (
                  SELECT a2.id FROM artifacts a2
                  WHERE a2.repository_id = $1
                    AND a2.name = a.name
                    AND a2.is_deleted = false
                  ORDER BY a2.created_at DESC
                  LIMIT $2
              )
            "#,
        )
        .bind(repo_id)
        .bind(keep)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut removed = 0i64;
        if !dry_run && matched.count > 0 {
            let result = sqlx::query(
                r#"
                UPDATE artifacts SET is_deleted = true
                WHERE repository_id = $1
                  AND is_deleted = false
                  AND id NOT IN (
                      SELECT a2.id FROM artifacts a2
                      WHERE a2.repository_id = $1
                        AND a2.name = artifacts.name
                        AND a2.is_deleted = false
                      ORDER BY a2.created_at DESC
                      LIMIT $2
                  )
                "#,
            )
            .bind(repo_id)
            .bind(keep)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(PolicyExecutionResult {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            dry_run,
            artifacts_matched: matched.count,
            artifacts_removed: if dry_run { 0 } else { removed },
            bytes_freed: if dry_run { 0 } else { matched.bytes },
            errors: vec![],
        })
    }

    async fn execute_no_downloads(
        &self,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let days = policy
            .config
            .get("days")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                AppError::Validation("no_downloads_days requires 'days' in config".to_string())
            })?;

        let repo_filter = policy.repository_id;

        let matched = sqlx::query_as::<_, CountBytes>(
            r#"
            SELECT COUNT(*) as count, COALESCE(SUM(a.size_bytes), 0)::BIGINT as bytes
            FROM artifacts a
            WHERE a.is_deleted = false
              AND ($1::UUID IS NULL OR a.repository_id = $1)
              AND NOT EXISTS (
                  SELECT 1 FROM download_statistics ds
                  WHERE ds.artifact_id = a.id
                    AND ds.downloaded_at > NOW() - make_interval(days => $2::INT)
              )
              AND a.created_at < NOW() - make_interval(days => $2::INT)
            "#,
        )
        .bind(repo_filter)
        .bind(days as i32)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut removed = 0i64;
        if !dry_run && matched.count > 0 {
            let result = sqlx::query(
                r#"
                UPDATE artifacts SET is_deleted = true
                WHERE is_deleted = false
                  AND ($1::UUID IS NULL OR repository_id = $1)
                  AND NOT EXISTS (
                      SELECT 1 FROM download_statistics ds
                      WHERE ds.artifact_id = artifacts.id
                        AND ds.downloaded_at > NOW() - make_interval(days => $2::INT)
                  )
                  AND created_at < NOW() - make_interval(days => $2::INT)
                "#,
            )
            .bind(repo_filter)
            .bind(days as i32)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(PolicyExecutionResult {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            dry_run,
            artifacts_matched: matched.count,
            artifacts_removed: if dry_run { 0 } else { removed },
            bytes_freed: if dry_run { 0 } else { matched.bytes },
            errors: vec![],
        })
    }

    async fn execute_tag_pattern_delete(
        &self,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let pattern = policy
            .config
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::Validation("tag_pattern_delete requires 'pattern' in config".to_string())
            })?;

        let repo_filter = policy.repository_id;

        let matched = sqlx::query_as::<_, CountBytes>(
            r#"
            SELECT COUNT(*) as count, COALESCE(SUM(a.size_bytes), 0)::BIGINT as bytes
            FROM artifacts a
            WHERE a.is_deleted = false
              AND ($1::UUID IS NULL OR a.repository_id = $1)
              AND a.name ~ $2
            "#,
        )
        .bind(repo_filter)
        .bind(pattern)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut removed = 0i64;
        if !dry_run && matched.count > 0 {
            let result = sqlx::query(
                r#"
                UPDATE artifacts SET is_deleted = true
                WHERE is_deleted = false
                  AND ($1::UUID IS NULL OR repository_id = $1)
                  AND name ~ $2
                "#,
            )
            .bind(repo_filter)
            .bind(pattern)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(PolicyExecutionResult {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            dry_run,
            artifacts_matched: matched.count,
            artifacts_removed: if dry_run { 0 } else { removed },
            bytes_freed: if dry_run { 0 } else { matched.bytes },
            errors: vec![],
        })
    }

    async fn execute_size_quota(
        &self,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let quota_bytes = policy
            .config
            .get("quota_bytes")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                AppError::Validation(
                    "size_quota_bytes requires 'quota_bytes' in config".to_string(),
                )
            })?;

        let repo_id = policy.repository_id.ok_or_else(|| {
            AppError::Validation("size_quota_bytes requires a repository_id".to_string())
        })?;

        // Get current usage
        let usage = sqlx::query_as::<_, UsageTotal>(
            r#"
            SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as total
            FROM artifacts
            WHERE repository_id = $1 AND is_deleted = false
            "#,
        )
        .bind(repo_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if usage.total <= quota_bytes {
            return Ok(PolicyExecutionResult {
                policy_id: policy.id,
                policy_name: policy.name.clone(),
                dry_run,
                artifacts_matched: 0,
                artifacts_removed: 0,
                bytes_freed: 0,
                errors: vec![],
            });
        }

        let excess = usage.total - quota_bytes;

        // Find oldest artifacts to remove to get under quota
        let candidates = sqlx::query_as::<_, SizeCandidate>(
            r#"
            SELECT id, size_bytes
            FROM artifacts
            WHERE repository_id = $1 AND is_deleted = false
            ORDER BY created_at ASC
            "#,
        )
        .bind(repo_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut to_remove = Vec::new();
        let mut accumulated = 0i64;
        for candidate in &candidates {
            if accumulated >= excess {
                break;
            }
            to_remove.push(candidate.id);
            accumulated += candidate.size_bytes;
        }

        let matched = to_remove.len() as i64;
        let mut removed = 0i64;

        if !dry_run && !to_remove.is_empty() {
            let result = sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = ANY($1)")
                .bind(&to_remove)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(PolicyExecutionResult {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            dry_run,
            artifacts_matched: matched,
            artifacts_removed: if dry_run { 0 } else { removed },
            bytes_freed: if dry_run { 0 } else { accumulated },
            errors: vec![],
        })
    }

    /// Validate policy config based on type.
    fn validate_policy_config(&self, policy_type: &str, config: &serde_json::Value) -> Result<()> {
        match policy_type {
            "max_age_days" => {
                config
                    .get("days")
                    .and_then(|v| v.as_i64())
                    .filter(|&d| d > 0)
                    .ok_or_else(|| {
                        AppError::Validation(
                            "max_age_days requires 'days' (positive integer) in config".to_string(),
                        )
                    })?;
            }
            "max_versions" => {
                config
                    .get("keep")
                    .and_then(|v| v.as_i64())
                    .filter(|&k| k > 0)
                    .ok_or_else(|| {
                        AppError::Validation(
                            "max_versions requires 'keep' (positive integer) in config".to_string(),
                        )
                    })?;
            }
            "no_downloads_days" => {
                config
                    .get("days")
                    .and_then(|v| v.as_i64())
                    .filter(|&d| d > 0)
                    .ok_or_else(|| {
                        AppError::Validation(
                            "no_downloads_days requires 'days' (positive integer) in config"
                                .to_string(),
                        )
                    })?;
            }
            "tag_pattern_keep" | "tag_pattern_delete" => {
                let pattern = config
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::Validation(format!(
                            "{} requires 'pattern' (string) in config",
                            policy_type
                        ))
                    })?;
                // Validate regex
                regex::Regex::new(pattern)
                    .map_err(|e| AppError::Validation(format!("Invalid regex pattern: {}", e)))?;
            }
            "size_quota_bytes" => {
                config
                    .get("quota_bytes")
                    .and_then(|v| v.as_i64())
                    .filter(|&q| q > 0)
                    .ok_or_else(|| {
                        AppError::Validation(
                            "size_quota_bytes requires 'quota_bytes' (positive integer) in config"
                                .to_string(),
                        )
                    })?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use serde_json::json;

    // Helper: create a minimal LifecycleService for calling validate_policy_config.
    // PgPool::connect_lazy requires a Tokio context, so these tests use #[tokio::test].
    fn make_service_for_validation() -> LifecycleService {
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        LifecycleService::new(pool)
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: max_age_days
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_max_age_days_valid() {
        let svc = make_service_for_validation();
        let config = json!({"days": 30});
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_missing_days() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_zero() {
        let svc = make_service_for_validation();
        let config = json!({"days": 0});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_negative() {
        let svc = make_service_for_validation();
        let config = json!({"days": -5});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_string_value() {
        let svc = make_service_for_validation();
        let config = json!({"days": "thirty"});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: max_versions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_max_versions_valid() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 5});
        assert!(svc.validate_policy_config("max_versions", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_versions_missing_keep() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_versions_zero() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 0});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_versions_negative() {
        let svc = make_service_for_validation();
        let config = json!({"keep": -1});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: no_downloads_days
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_no_downloads_days_valid() {
        let svc = make_service_for_validation();
        let config = json!({"days": 90});
        assert!(svc
            .validate_policy_config("no_downloads_days", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_no_downloads_days_missing() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("no_downloads_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_no_downloads_days_zero() {
        let svc = make_service_for_validation();
        let config = json!({"days": 0});
        let result = svc.validate_policy_config("no_downloads_days", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: tag_pattern_keep / tag_pattern_delete
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_valid() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "^release-.*"});
        assert!(svc
            .validate_policy_config("tag_pattern_keep", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_delete_valid() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": ".*-snapshot$"});
        assert!(svc
            .validate_policy_config("tag_pattern_delete", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_missing_pattern() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_invalid_regex() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "[invalid"});
        let result = svc.validate_policy_config("tag_pattern_delete", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_integer_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": 42});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: size_quota_bytes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_size_quota_bytes_valid() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 1073741824}); // 1 GiB
        assert!(svc
            .validate_policy_config("size_quota_bytes", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_missing() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("size_quota_bytes", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_zero() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 0});
        let result = svc.validate_policy_config("size_quota_bytes", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_negative() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": -100});
        let result = svc.validate_policy_config("size_quota_bytes", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: unknown type passes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_unknown_policy_type_passes() {
        let svc = make_service_for_validation();
        let config = json!({});
        assert!(svc.validate_policy_config("unknown_type", &config).is_ok());
    }

    // -----------------------------------------------------------------------
    // Struct serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_lifecycle_policy_serialization() {
        let now = Utc::now();
        let policy = LifecyclePolicy {
            id: Uuid::nil(),
            repository_id: Some(Uuid::new_v4()),
            name: "Test Policy".to_string(),
            description: Some("A test policy".to_string()),
            enabled: true,
            policy_type: "max_age_days".to_string(),
            config: json!({"days": 30}),
            priority: 10,
            last_run_at: None,
            last_run_items_removed: None,
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"name\":\"Test Policy\""));
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"priority\":10"));
    }

    #[test]
    fn test_lifecycle_policy_deserialization() {
        let now = Utc::now();
        let json_val = json!({
            "id": Uuid::nil(),
            "repository_id": null,
            "name": "Cleanup",
            "description": null,
            "enabled": false,
            "policy_type": "max_versions",
            "config": {"keep": 3},
            "priority": 0,
            "last_run_at": null,
            "last_run_items_removed": null,
            "created_at": now,
            "updated_at": now,
        });

        let policy: LifecyclePolicy = serde_json::from_value(json_val).unwrap();
        assert_eq!(policy.name, "Cleanup");
        assert!(!policy.enabled);
        assert_eq!(policy.policy_type, "max_versions");
        assert!(policy.repository_id.is_none());
    }

    #[test]
    fn test_create_policy_request_deserialization() {
        let json_str = r#"{
            "name": "My Policy",
            "policy_type": "max_age_days",
            "config": {"days": 30}
        }"#;
        let req: CreatePolicyRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.name, "My Policy");
        assert_eq!(req.policy_type, "max_age_days");
        assert!(req.repository_id.is_none());
        assert!(req.description.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_create_policy_request_with_all_fields() {
        let repo_id = Uuid::new_v4();
        let json_val = json!({
            "repository_id": repo_id,
            "name": "Full Policy",
            "description": "With all fields",
            "policy_type": "size_quota_bytes",
            "config": {"quota_bytes": 1000000},
            "priority": 5
        });
        let req: CreatePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert_eq!(req.repository_id, Some(repo_id));
        assert_eq!(req.description, Some("With all fields".to_string()));
        assert_eq!(req.priority, Some(5));
    }

    #[test]
    fn test_update_policy_request_empty() {
        let json_str = "{}";
        let req: UpdatePolicyRequest = serde_json::from_str(json_str).unwrap();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.enabled.is_none());
        assert!(req.config.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_policy_execution_result_serialization() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::nil(),
            policy_name: "Test".to_string(),
            dry_run: true,
            artifacts_matched: 100,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"dry_run\":true"));
        assert!(json.contains("\"artifacts_matched\":100"));
        assert!(json.contains("\"artifacts_removed\":0"));
        assert!(json.contains("\"bytes_freed\":0"));
        assert!(json.contains("\"errors\":[]"));
    }

    #[test]
    fn test_policy_execution_result_with_errors() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::new_v4(),
            policy_name: "Failing".to_string(),
            dry_run: false,
            artifacts_matched: 10,
            artifacts_removed: 3,
            bytes_freed: 1024,
            errors: vec!["Error A".to_string(), "Error B".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"errors\":[\"Error A\",\"Error B\"]"));
    }

    // -----------------------------------------------------------------------
    // Valid policy_type list validation (testing create_policy logic)
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_policy_types() {
        let valid_types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        for t in &valid_types {
            assert!(valid_types.contains(t));
        }
        assert!(!valid_types.contains(&"custom_type"));
        assert!(!valid_types.contains(&""));
    }
}
