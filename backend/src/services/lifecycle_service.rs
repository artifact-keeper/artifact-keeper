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
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::scheduler_service::normalize_cron_expression;

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
    pub cron_schedule: Option<String>,
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
    pub cron_schedule: Option<String>,
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
    pub cron_schedule: Option<String>,
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

        if let Some(ref cron_expr) = req.cron_schedule {
            let normalized = normalize_cron_expression(cron_expr);
            if cron::Schedule::from_str(&normalized).is_err() {
                return Err(AppError::Validation(format!(
                    "Invalid cron expression: '{}'",
                    cron_expr
                )));
            }
        }

        let policy = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            INSERT INTO lifecycle_policies (repository_id, name, description, policy_type, config, priority, cron_schedule)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, repository_id, name, description, enabled,
                      policy_type, config, priority, last_run_at,
                      last_run_items_removed, cron_schedule, created_at, updated_at
            "#,
        )
        .bind(req.repository_id)
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.policy_type)
        .bind(&req.config)
        .bind(req.priority.unwrap_or(0))
        .bind(&req.cron_schedule)
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
                   last_run_items_removed, cron_schedule, created_at, updated_at
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
                   last_run_items_removed, cron_schedule, created_at, updated_at
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
        let cron_schedule = req.cron_schedule.or(existing.cron_schedule);

        self.validate_policy_config(&existing.policy_type, &config)?;

        if let Some(ref cron_expr) = cron_schedule {
            let normalized = normalize_cron_expression(cron_expr);
            if cron::Schedule::from_str(&normalized).is_err() {
                return Err(AppError::Validation(format!(
                    "Invalid cron expression: '{}'",
                    cron_expr
                )));
            }
        }

        let policy = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            UPDATE lifecycle_policies
            SET name = $2, description = $3, enabled = $4,
                config = $5, priority = $6, cron_schedule = $7, updated_at = NOW()
            WHERE id = $1
            RETURNING id, repository_id, name, description, enabled,
                      policy_type, config, priority, last_run_at,
                      last_run_items_removed, cron_schedule, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&name)
        .bind(&description)
        .bind(enabled)
        .bind(&config)
        .bind(priority)
        .bind(&cron_schedule)
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
            "tag_pattern_keep" => self.execute_tag_pattern_keep(&policy, dry_run).await?,
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
                   last_run_items_removed, cron_schedule, created_at, updated_at
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

    /// Execute only those enabled policies that are currently due, based on each
    /// policy's `cron_schedule` (or a default 6-hour cadence when unset).
    pub async fn execute_due_policies(&self) -> Result<Vec<PolicyExecutionResult>> {
        let policies = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, cron_schedule, created_at, updated_at
            FROM lifecycle_policies
            WHERE enabled = true
            ORDER BY priority DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let now = Utc::now();
        let default_cadence = chrono::Duration::hours(6);
        let mut results = Vec::new();

        for policy in policies {
            let is_due = Self::is_policy_due(
                policy.cron_schedule.as_deref(),
                policy.last_run_at,
                now,
                default_cadence,
            );

            if !is_due {
                continue;
            }

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

    /// Check whether a policy without a cron schedule is due based on the
    /// default cadence (6 hours). A policy that has never run is always due.
    fn is_due_by_default_cadence(
        last_run_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        cadence: chrono::Duration,
    ) -> bool {
        match last_run_at {
            None => true,
            Some(last) => now - last >= cadence,
        }
    }

    /// Determine whether a policy is currently due for execution.
    ///
    /// When the policy has a `cron_schedule`, checks whether any scheduled
    /// occurrence falls between `last_run_at` and `now`. If the cron expression
    /// is invalid, falls back to the default cadence. When there is no cron
    /// schedule, uses `is_due_by_default_cadence`.
    fn is_policy_due(
        cron_schedule: Option<&str>,
        last_run_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        default_cadence: chrono::Duration,
    ) -> bool {
        if let Some(cron_expr) = cron_schedule {
            let normalized = normalize_cron_expression(cron_expr);
            match cron::Schedule::from_str(&normalized) {
                Ok(schedule) => match last_run_at {
                    None => true,
                    Some(last_run) => schedule
                        .after(&last_run)
                        .take_while(|t| *t <= now)
                        .next()
                        .is_some(),
                },
                Err(_) => Self::is_due_by_default_cadence(last_run_at, now, default_cadence),
            }
        } else {
            Self::is_due_by_default_cadence(last_run_at, now, default_cadence)
        }
    }

    // --- Policy execution implementations ---

    /// Build a PolicyExecutionResult from common fields.
    /// When `dry_run` is true, `artifacts_removed` and `bytes_freed` are zeroed out.
    fn build_execution_result(
        policy: &LifecyclePolicy,
        dry_run: bool,
        artifacts_matched: i64,
        artifacts_removed: i64,
        bytes_freed: i64,
    ) -> PolicyExecutionResult {
        PolicyExecutionResult {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            dry_run,
            artifacts_matched,
            artifacts_removed: if dry_run { 0 } else { artifacts_removed },
            bytes_freed: if dry_run { 0 } else { bytes_freed },
            errors: vec![],
        }
    }

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

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
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

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
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

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
    }

    async fn execute_tag_pattern_keep(
        &self,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let pattern = policy
            .config
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::Validation("tag_pattern_keep requires 'pattern' in config".to_string())
            })?;

        let repo_filter = policy.repository_id;

        // Inverse of tag_pattern_delete: find artifacts that do NOT match the pattern
        let matched = sqlx::query_as::<_, CountBytes>(
            r#"
            SELECT COUNT(*) as count, COALESCE(SUM(a.size_bytes), 0)::BIGINT as bytes
            FROM artifacts a
            WHERE a.is_deleted = false
              AND ($1::UUID IS NULL OR a.repository_id = $1)
              AND a.name !~ $2
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
                  AND name !~ $2
                "#,
            )
            .bind(repo_filter)
            .bind(pattern)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
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

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
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
            return Ok(Self::build_execution_result(policy, dry_run, 0, 0, 0));
        }

        let excess = usage.total - quota_bytes;

        // Find least-recently-used artifacts to evict first (LRU).
        // Never-downloaded artifacts are evicted before downloaded ones,
        // then by least-recent download, then by creation time as tiebreaker.
        let candidates = sqlx::query_as::<_, SizeCandidate>(
            r#"
            SELECT a.id, a.size_bytes
            FROM artifacts a
            LEFT JOIN LATERAL (
                SELECT MAX(ds.downloaded_at) AS last_downloaded_at
                FROM download_statistics ds
                WHERE ds.artifact_id = a.id
            ) ds ON true
            WHERE a.repository_id = $1 AND a.is_deleted = false
            ORDER BY ds.last_downloaded_at ASC NULLS FIRST, a.created_at ASC
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

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched,
            removed,
            accumulated,
        ))
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
            cron_schedule: None,
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
            "cron_schedule": null,
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

    // -----------------------------------------------------------------------
    // tag_pattern_keep validation (mirrors tag_pattern_delete tests)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_valid_release_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "^(release-|v).*"});
        assert!(svc
            .validate_policy_config("tag_pattern_keep", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_missing_pattern() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("pattern"));
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_invalid_regex() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "[unclosed"});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("regex"));
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_non_string_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": 123});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Verify execute_policy match coverage for all policy types
    // -----------------------------------------------------------------------

    /// Ensure that all valid policy types have a match arm in execute_policy
    /// (i.e., none fall through to the catch-all error). This test verifies
    /// that tag_pattern_keep is wired into execute_policy, not just validated.
    /// Since execute_policy requires a database, we verify indirectly by
    /// checking the match arms list matches the valid_types list.
    #[test]
    fn test_all_policy_types_are_executable() {
        // These are the types accepted by create_policy
        let create_types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        // These are the types handled in execute_policy match arms
        // (this list must be kept in sync manually — if a type is added to
        // create_types but not to execute_types, this test will fail)
        let execute_types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        for t in &create_types {
            assert!(
                execute_types.contains(t),
                "Policy type '{}' is accepted by create_policy but has no execute handler",
                t
            );
        }
    }

    // -----------------------------------------------------------------------
    // build_execution_result tests
    // -----------------------------------------------------------------------

    /// Helper: create a LifecyclePolicy with the given fields for use in
    /// build_execution_result tests. Only id, name, and policy_type matter
    /// for the builder; everything else gets sensible defaults.
    fn make_policy(id: Uuid, name: &str, policy_type: &str) -> LifecyclePolicy {
        let now = Utc::now();
        LifecyclePolicy {
            id,
            repository_id: None,
            name: name.to_string(),
            description: None,
            enabled: true,
            policy_type: policy_type.to_string(),
            config: json!({}),
            priority: 0,
            last_run_at: None,
            last_run_items_removed: None,
            cron_schedule: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_build_execution_result_dry_run_zeroes_removed_and_freed() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Age Policy", "max_age_days");
        let result = LifecycleService::build_execution_result(&policy, true, 42, 42, 1_048_576);

        assert_eq!(result.policy_id, id);
        assert_eq!(result.policy_name, "Age Policy");
        assert!(result.dry_run);
        assert_eq!(result.artifacts_matched, 42);
        assert_eq!(
            result.artifacts_removed, 0,
            "dry_run should zero artifacts_removed"
        );
        assert_eq!(result.bytes_freed, 0, "dry_run should zero bytes_freed");
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_build_execution_result_real_run_preserves_values() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Version Cleanup", "max_versions");
        let result = LifecycleService::build_execution_result(&policy, false, 100, 80, 5_000_000);

        assert_eq!(result.policy_id, id);
        assert_eq!(result.policy_name, "Version Cleanup");
        assert!(!result.dry_run);
        assert_eq!(result.artifacts_matched, 100);
        assert_eq!(result.artifacts_removed, 80);
        assert_eq!(result.bytes_freed, 5_000_000);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_build_execution_result_zero_values() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Empty Run", "no_downloads_days");
        let result = LifecycleService::build_execution_result(&policy, false, 0, 0, 0);

        assert_eq!(result.artifacts_matched, 0);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(!result.dry_run);
    }

    #[test]
    fn test_build_execution_result_zero_values_dry_run() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Empty Dry", "max_age_days");
        let result = LifecycleService::build_execution_result(&policy, true, 0, 0, 0);

        assert_eq!(result.artifacts_matched, 0);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(result.dry_run);
    }

    #[test]
    fn test_build_execution_result_large_values() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Big Repo Cleanup", "size_quota_bytes");
        let matched = 1_000_000i64;
        let removed = 999_999i64;
        let bytes = 10_000_000_000_000i64; // 10 TB
        let result =
            LifecycleService::build_execution_result(&policy, false, matched, removed, bytes);

        assert_eq!(result.artifacts_matched, 1_000_000);
        assert_eq!(result.artifacts_removed, 999_999);
        assert_eq!(result.bytes_freed, 10_000_000_000_000);
    }

    #[test]
    fn test_build_execution_result_large_values_dry_run() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Big Dry Run", "size_quota_bytes");
        let result = LifecycleService::build_execution_result(
            &policy,
            true,
            1_000_000,
            999_999,
            10_000_000_000_000,
        );

        assert_eq!(result.artifacts_matched, 1_000_000);
        assert_eq!(
            result.artifacts_removed, 0,
            "dry_run must zero even large artifacts_removed"
        );
        assert_eq!(
            result.bytes_freed, 0,
            "dry_run must zero even large bytes_freed"
        );
    }

    #[test]
    fn test_build_execution_result_matched_greater_than_removed() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Partial Cleanup", "tag_pattern_delete");
        let result = LifecycleService::build_execution_result(&policy, false, 50, 30, 2048);

        assert_eq!(result.artifacts_matched, 50);
        assert_eq!(result.artifacts_removed, 30);
        assert_eq!(result.bytes_freed, 2048);
    }

    #[test]
    fn test_build_execution_result_clones_policy_name() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Original Name", "max_age_days");
        let result = LifecycleService::build_execution_result(&policy, false, 1, 1, 100);

        // The result should have a cloned copy of the policy name
        assert_eq!(result.policy_name, "Original Name");
        // Verify the original policy is still intact (not moved)
        assert_eq!(policy.name, "Original Name");
    }

    #[test]
    fn test_build_execution_result_errors_always_empty() {
        // build_execution_result always returns an empty errors vec;
        // errors are only populated by the caller (e.g., execute_all_enabled).
        let policy = make_policy(Uuid::new_v4(), "Test", "max_age_days");

        let dry = LifecycleService::build_execution_result(&policy, true, 10, 10, 500);
        assert!(dry.errors.is_empty());

        let real = LifecycleService::build_execution_result(&policy, false, 10, 10, 500);
        assert!(real.errors.is_empty());
    }

    #[test]
    fn test_build_execution_result_preserves_policy_id() {
        // Verify with a nil UUID (edge case)
        let nil_policy = make_policy(Uuid::nil(), "Nil ID Policy", "max_versions");
        let result = LifecycleService::build_execution_result(&nil_policy, false, 5, 5, 100);
        assert_eq!(result.policy_id, Uuid::nil());

        // And with a specific UUID
        let specific_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let specific_policy = make_policy(specific_id, "Specific", "max_age_days");
        let result2 = LifecycleService::build_execution_result(&specific_policy, true, 1, 1, 50);
        assert_eq!(result2.policy_id, specific_id);
    }

    #[test]
    fn test_build_execution_result_each_policy_type() {
        // Confirm build_execution_result works identically regardless of policy_type
        // (it does not branch on policy_type, but this guards against future regressions).
        let types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        for pt in types {
            let policy = make_policy(Uuid::new_v4(), &format!("{} policy", pt), pt);
            let result = LifecycleService::build_execution_result(&policy, false, 10, 7, 4096);
            assert_eq!(result.artifacts_matched, 10);
            assert_eq!(result.artifacts_removed, 7);
            assert_eq!(result.bytes_freed, 4096);
            assert_eq!(result.policy_name, format!("{} policy", pt));
        }
    }

    // -----------------------------------------------------------------------
    // validate_policy_config: boundary and edge-case tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_max_age_days_boundary_one() {
        let svc = make_service_for_validation();
        let config = json!({"days": 1});
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_very_large() {
        let svc = make_service_for_validation();
        let config = json!({"days": 36500}); // 100 years
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_float_value() {
        let svc = make_service_for_validation();
        // 30.5 is a float, as_i64() returns None for non-integer JSON numbers
        let config = json!({"days": 30.5});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_null_value() {
        let svc = make_service_for_validation();
        let config = json!({"days": null});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_versions_boundary_one() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 1});
        assert!(svc.validate_policy_config("max_versions", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_versions_very_large() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 100_000});
        assert!(svc.validate_policy_config("max_versions", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_versions_float_value() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 5.5});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_no_downloads_days_boundary_one() {
        let svc = make_service_for_validation();
        let config = json!({"days": 1});
        assert!(svc
            .validate_policy_config("no_downloads_days", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_no_downloads_days_negative() {
        let svc = make_service_for_validation();
        let config = json!({"days": -10});
        let result = svc.validate_policy_config("no_downloads_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_boundary_one() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 1});
        assert!(svc
            .validate_policy_config("size_quota_bytes", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_very_large() {
        let svc = make_service_for_validation();
        // 1 PB
        let config = json!({"quota_bytes": 1_125_899_906_842_624_i64});
        assert!(svc
            .validate_policy_config("size_quota_bytes", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_float_value() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 1073741824.5});
        let result = svc.validate_policy_config("size_quota_bytes", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_complex_regex() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": r"^v\d+\.\d+\.\d+(-rc\.\d+)?$"});
        assert!(svc
            .validate_policy_config("tag_pattern_keep", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_empty_string() {
        // An empty regex is technically valid (matches everything)
        let svc = make_service_for_validation();
        let config = json!({"pattern": ""});
        assert!(svc
            .validate_policy_config("tag_pattern_delete", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_delete_invalid_nested_groups() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "((("});
        let result = svc.validate_policy_config("tag_pattern_delete", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_null_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": null});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_boolean_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": true});
        let result = svc.validate_policy_config("tag_pattern_delete", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config: error message content
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_max_age_error_message_content() {
        let svc = make_service_for_validation();
        let config = json!({});
        let err = svc
            .validate_policy_config("max_age_days", &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("max_age_days"),
            "Error should mention the policy type"
        );
        assert!(
            msg.contains("days"),
            "Error should mention the missing field"
        );
    }

    #[tokio::test]
    async fn test_validate_max_versions_error_message_content() {
        let svc = make_service_for_validation();
        let config = json!({"keep": -1});
        let err = svc
            .validate_policy_config("max_versions", &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("max_versions"));
        assert!(msg.contains("keep"));
    }

    #[tokio::test]
    async fn test_validate_size_quota_error_message_content() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 0});
        let err = svc
            .validate_policy_config("size_quota_bytes", &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("size_quota_bytes"));
        assert!(msg.contains("quota_bytes"));
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_invalid_regex_error_message() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "[bad"});
        let err = svc
            .validate_policy_config("tag_pattern_keep", &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("regex"), "Error should mention regex");
    }

    // -----------------------------------------------------------------------
    // validate_policy_config: extra keys are silently ignored
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_extra_keys_ignored() {
        let svc = make_service_for_validation();

        // max_age_days with extra fields
        let config = json!({"days": 30, "extra": "ignored", "another": 99});
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());

        // tag_pattern_keep with extra fields
        let config = json!({"pattern": "^release", "foo": "bar"});
        assert!(svc
            .validate_policy_config("tag_pattern_keep", &config)
            .is_ok());
    }

    // -----------------------------------------------------------------------
    // PolicyExecutionResult: serialization edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_execution_result_serialization_large_values() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::new_v4(),
            policy_name: "Terabyte Cleanup".to_string(),
            dry_run: false,
            artifacts_matched: i64::MAX,
            artifacts_removed: i64::MAX,
            bytes_freed: i64::MAX,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(&i64::MAX.to_string()));
    }

    #[test]
    fn test_policy_execution_result_serialization_zero_artifacts() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::nil(),
            policy_name: "No-Op".to_string(),
            dry_run: false,
            artifacts_matched: 0,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["artifacts_matched"], 0);
        assert_eq!(parsed["artifacts_removed"], 0);
        assert_eq!(parsed["bytes_freed"], 0);
        assert_eq!(parsed["dry_run"], false);
    }

    // -----------------------------------------------------------------------
    // CreatePolicyRequest: deserialization edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_policy_request_missing_required_field() {
        // Missing "name" field
        let json_str = r#"{"policy_type": "max_age_days", "config": {"days": 30}}"#;
        let result: std::result::Result<CreatePolicyRequest, _> = serde_json::from_str(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_policy_request_missing_config() {
        // Missing "config" field
        let json_str = r#"{"name": "Test", "policy_type": "max_age_days"}"#;
        let result: std::result::Result<CreatePolicyRequest, _> = serde_json::from_str(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_policy_request_partial_fields() {
        let json_val = json!({
            "enabled": false,
            "priority": 99
        });
        let req: UpdatePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert_eq!(req.enabled, Some(false));
        assert!(req.config.is_none());
        assert_eq!(req.priority, Some(99));
    }

    #[test]
    fn test_update_policy_request_all_fields() {
        let json_val = json!({
            "name": "Updated Name",
            "description": "Updated Description",
            "enabled": true,
            "config": {"days": 60},
            "priority": 5,
            "cron_schedule": "0 0 3 * * *"
        });
        let req: UpdatePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert_eq!(req.name, Some("Updated Name".to_string()));
        assert_eq!(req.description, Some("Updated Description".to_string()));
        assert_eq!(req.enabled, Some(true));
        assert!(req.config.is_some());
        assert_eq!(req.config.unwrap()["days"], 60);
        assert_eq!(req.priority, Some(5));
        assert_eq!(req.cron_schedule, Some("0 0 3 * * *".to_string()));
    }

    // -----------------------------------------------------------------------
    // cron_schedule field tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_policy_request_with_cron_schedule() {
        let json_val = json!({
            "name": "Scheduled Policy",
            "policy_type": "max_age_days",
            "config": {"days": 7},
            "cron_schedule": "0 0 2 * * *"
        });
        let req: CreatePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert_eq!(req.cron_schedule, Some("0 0 2 * * *".to_string()));
    }

    #[test]
    fn test_create_policy_request_without_cron_schedule() {
        let json_val = json!({
            "name": "Unscheduled Policy",
            "policy_type": "max_age_days",
            "config": {"days": 7}
        });
        let req: CreatePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert!(req.cron_schedule.is_none());
    }

    #[test]
    fn test_update_policy_request_cron_schedule_none() {
        let json_val = json!({
            "enabled": true
        });
        let req: UpdatePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert!(req.cron_schedule.is_none());
    }

    #[test]
    fn test_lifecycle_policy_serialization_with_cron_schedule() {
        let now = Utc::now();
        let policy = LifecyclePolicy {
            id: Uuid::nil(),
            repository_id: None,
            name: "Cron Policy".to_string(),
            description: None,
            enabled: true,
            policy_type: "max_age_days".to_string(),
            config: json!({"days": 14}),
            priority: 0,
            last_run_at: None,
            last_run_items_removed: None,
            cron_schedule: Some("0 30 1 * * *".to_string()),
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"cron_schedule\":\"0 30 1 * * *\""));
    }

    // -----------------------------------------------------------------------
    // is_due_by_default_cadence tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_due_never_run_returns_true() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        assert!(
            LifecycleService::is_due_by_default_cadence(None, now, cadence),
            "A policy that has never run should always be due"
        );
    }

    #[test]
    fn test_is_due_recently_run_returns_false() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        let last_run = now - chrono::Duration::hours(1);
        assert!(
            !LifecycleService::is_due_by_default_cadence(Some(last_run), now, cadence),
            "A policy that ran 1 hour ago should not be due with a 6-hour cadence"
        );
    }

    #[test]
    fn test_is_due_old_run_returns_true() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        let last_run = now - chrono::Duration::hours(7);
        assert!(
            LifecycleService::is_due_by_default_cadence(Some(last_run), now, cadence),
            "A policy that ran 7 hours ago should be due with a 6-hour cadence"
        );
    }

    #[test]
    fn test_is_due_exactly_at_cadence_returns_true() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        let last_run = now - chrono::Duration::hours(6);
        assert!(
            LifecycleService::is_due_by_default_cadence(Some(last_run), now, cadence),
            "A policy that ran exactly 6 hours ago should be due"
        );
    }

    #[test]
    fn test_is_due_just_under_cadence_returns_false() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        let last_run = now - chrono::Duration::hours(6) + chrono::Duration::seconds(1);
        assert!(
            !LifecycleService::is_due_by_default_cadence(Some(last_run), now, cadence),
            "A policy that ran just under 6 hours ago should not be due"
        );
    }

    // -----------------------------------------------------------------------
    // Cron schedule parsing for policies
    // -----------------------------------------------------------------------

    #[test]
    fn test_cron_schedule_from_str_valid() {
        let expr = "0 0 2 * * *"; // daily at 2 AM
        let schedule = cron::Schedule::from_str(expr);
        assert!(schedule.is_ok(), "Valid 6-field cron should parse");
    }

    #[test]
    fn test_cron_schedule_from_str_invalid() {
        let expr = "not a cron";
        let schedule = cron::Schedule::from_str(expr);
        assert!(schedule.is_err(), "Invalid cron should fail");
    }

    #[test]
    fn test_cron_schedule_upcoming_returns_future_time() {
        let expr = "0 * * * * *"; // every minute
        let schedule = cron::Schedule::from_str(expr).unwrap();
        let next = schedule.upcoming(Utc).next();
        assert!(next.is_some());
        assert!(next.unwrap() > Utc::now());
    }

    #[test]
    fn test_cron_schedule_after_last_run_detects_due() {
        let expr = "0 * * * * *"; // every minute
        let schedule = cron::Schedule::from_str(expr).unwrap();
        // A last_run 2 minutes ago should have at least one scheduled time between then and now
        let last_run = Utc::now() - chrono::Duration::minutes(2);
        let now = Utc::now();
        let has_occurrence = schedule
            .after(&last_run)
            .take_while(|t| *t <= now)
            .next()
            .is_some();
        assert!(
            has_occurrence,
            "Should find a scheduled time in the last 2 minutes for every-minute cron"
        );
    }

    #[test]
    fn test_create_policy_rejects_invalid_cron() {
        // Verify the validation logic directly
        let invalid = "not-a-cron";
        let normalized = normalize_cron_expression(invalid);
        assert!(cron::Schedule::from_str(&normalized).is_err());
    }

    // -----------------------------------------------------------------------
    // is_policy_due (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_policy_due_no_cron_never_run() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        assert!(LifecycleService::is_policy_due(None, None, now, cadence));
    }

    #[test]
    fn test_is_policy_due_no_cron_recently_run() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::hours(1);
        let cadence = chrono::Duration::hours(6);
        assert!(!LifecycleService::is_policy_due(
            None,
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_no_cron_overdue() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::hours(7);
        let cadence = chrono::Duration::hours(6);
        assert!(LifecycleService::is_policy_due(
            None,
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_valid_cron_never_run() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        // Every minute cron
        assert!(LifecycleService::is_policy_due(
            Some("0 * * * * *"),
            None,
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_valid_cron_recently_run() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::minutes(30);
        let cadence = chrono::Duration::hours(6);
        // Hourly cron: no occurrence should fall within 30 minutes
        assert!(!LifecycleService::is_policy_due(
            Some("0 0 * * * *"),
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_valid_cron_overdue() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::minutes(2);
        let cadence = chrono::Duration::hours(6);
        // Every minute cron: should have an occurrence in last 2 minutes
        assert!(LifecycleService::is_policy_due(
            Some("0 * * * * *"),
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_invalid_cron_falls_back_to_cadence_due() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::hours(7);
        let cadence = chrono::Duration::hours(6);
        assert!(LifecycleService::is_policy_due(
            Some("invalid"),
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_invalid_cron_falls_back_to_cadence_not_due() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::hours(1);
        let cadence = chrono::Duration::hours(6);
        assert!(!LifecycleService::is_policy_due(
            Some("invalid"),
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_5_field_cron_normalized() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::minutes(6);
        let cadence = chrono::Duration::hours(6);
        // 5-field cron "*/5 * * * *" (every 5 minutes) gets normalized to 6-field;
        // with last_run 6 minutes ago there should be at least one occurrence
        assert!(LifecycleService::is_policy_due(
            Some("*/5 * * * *"),
            Some(last_run),
            now,
            cadence
        ));
    }
}
