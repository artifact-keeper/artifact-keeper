//! Service for evaluating and managing security policies.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{PolicyResult, ScanPolicy, Severity};

pub struct PolicyService {
    db: PgPool,
}

impl PolicyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Evaluate all applicable policies for an artifact download.
    /// Returns whether the download is allowed and any violation reasons.
    pub async fn evaluate_artifact(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<PolicyResult> {
        // Find applicable policies: repo-specific + global (repository_id IS NULL)
        let policies: Vec<ScanPolicy> = sqlx::query_as(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, created_at, updated_at
            FROM scan_policies
            WHERE is_enabled = true
              AND (repository_id = $1 OR repository_id IS NULL)
            ORDER BY repository_id NULLS LAST
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if policies.is_empty() {
            return Ok(PolicyResult {
                allowed: true,
                violations: vec![],
            });
        }

        let mut violations = Vec::new();

        // Check for completed scans on this artifact
        #[derive(sqlx::FromRow)]
        struct ScanRow {
            status: String,
            #[allow(dead_code)]
            findings_count: i32,
            #[allow(dead_code)]
            critical_count: i32,
            #[allow(dead_code)]
            high_count: i32,
            #[allow(dead_code)]
            medium_count: i32,
            #[allow(dead_code)]
            low_count: i32,
        }

        let latest_scan: Option<ScanRow> = sqlx::query_as(
            r#"
            SELECT status, findings_count, critical_count, high_count, medium_count, low_count
            FROM scan_results
            WHERE artifact_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        for policy in &policies {
            // Check: block_unscanned
            if policy.block_unscanned && latest_scan.is_none() {
                violations.push(format!(
                    "Policy '{}': artifact has not been scanned",
                    policy.name
                ));
                continue;
            }

            if let Some(ref scan) = latest_scan {
                // Check: block_on_fail
                if policy.block_on_fail && scan.status == "failed" {
                    violations.push(format!("Policy '{}': latest scan failed", policy.name));
                    continue;
                }

                // Check: max_severity threshold (non-acknowledged findings only)
                if scan.status == "completed" {
                    let _threshold = Severity::from_str_loose(&policy.max_severity)
                        .unwrap_or(Severity::Critical);

                    // Count non-acknowledged findings at or above the threshold
                    let violating_count: i64 = sqlx::query_scalar(
                        r#"
                        SELECT COUNT(*)
                        FROM scan_findings
                        WHERE artifact_id = $1
                          AND NOT is_acknowledged
                          AND severity IN (
                              SELECT unnest(CASE $2
                                  WHEN 'critical' THEN ARRAY['critical']
                                  WHEN 'high' THEN ARRAY['critical', 'high']
                                  WHEN 'medium' THEN ARRAY['critical', 'high', 'medium']
                                  WHEN 'low' THEN ARRAY['critical', 'high', 'medium', 'low']
                              END)
                          )
                        "#,
                    )
                    .bind(artifact_id)
                    .bind(&policy.max_severity)
                    .fetch_one(&self.db)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;

                    if violating_count > 0 {
                        violations.push(format!(
                            "Policy '{}': {} findings at or above {} severity",
                            policy.name, violating_count, policy.max_severity
                        ));
                    }
                }
            }
        }

        Ok(PolicyResult {
            allowed: violations.is_empty(),
            violations,
        })
    }

    // -----------------------------------------------------------------------
    // CRUD
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn create_policy(
        &self,
        name: &str,
        repository_id: Option<Uuid>,
        max_severity: &str,
        block_unscanned: bool,
        block_on_fail: bool,
        min_staging_hours: Option<i32>,
        max_artifact_age_days: Option<i32>,
        require_signature: bool,
    ) -> Result<ScanPolicy> {
        let policy: ScanPolicy = sqlx::query_as(
            r#"
            INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, block_on_fail,
                                       min_staging_hours, max_artifact_age_days, require_signature)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, name, repository_id, max_severity, block_unscanned,
                      block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                      require_signature, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(repository_id)
        .bind(max_severity)
        .bind(block_unscanned)
        .bind(block_on_fail)
        .bind(min_staging_hours)
        .bind(max_artifact_age_days)
        .bind(require_signature)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policy)
    }

    pub async fn list_policies(&self) -> Result<Vec<ScanPolicy>> {
        let policies: Vec<ScanPolicy> = sqlx::query_as(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, created_at, updated_at
            FROM scan_policies
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policies)
    }

    pub async fn get_policy(&self, id: Uuid) -> Result<ScanPolicy> {
        sqlx::query_as::<_, ScanPolicy>(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, created_at, updated_at
            FROM scan_policies
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_policy(
        &self,
        id: Uuid,
        name: &str,
        max_severity: &str,
        block_unscanned: bool,
        block_on_fail: bool,
        is_enabled: bool,
        min_staging_hours: Option<i32>,
        max_artifact_age_days: Option<i32>,
        require_signature: bool,
    ) -> Result<ScanPolicy> {
        let policy: ScanPolicy = sqlx::query_as(
            r#"
            UPDATE scan_policies
            SET name = $2, max_severity = $3, block_unscanned = $4,
                block_on_fail = $5, is_enabled = $6, min_staging_hours = $7,
                max_artifact_age_days = $8, require_signature = $9, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, repository_id, max_severity, block_unscanned,
                      block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                      require_signature, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(max_severity)
        .bind(block_unscanned)
        .bind(block_on_fail)
        .bind(is_enabled)
        .bind(min_staging_hours)
        .bind(max_artifact_age_days)
        .bind(require_signature)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))?;

        Ok(policy)
    }

    pub async fn delete_policy(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM scan_policies WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Policy not found".to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::{PolicyResult, ScanPolicy, Severity};

    // -----------------------------------------------------------------------
    // PolicyResult construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_result_allowed() {
        let result = PolicyResult {
            allowed: true,
            violations: vec![],
        };
        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_policy_result_blocked() {
        let result = PolicyResult {
            allowed: false,
            violations: vec![
                "Policy 'strict': artifact has not been scanned".to_string(),
                "Policy 'no-critical': 3 findings at or above critical severity".to_string(),
            ],
        };
        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 2);
    }

    #[test]
    fn test_policy_result_serialization() {
        let result = PolicyResult {
            allowed: false,
            violations: vec!["test violation".to_string()],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["allowed"], false);
        assert_eq!(json["violations"][0], "test violation");
    }

    // -----------------------------------------------------------------------
    // ScanPolicy construction and serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_policy_construction() {
        let policy = ScanPolicy {
            id: Uuid::new_v4(),
            name: "no-critical-vulns".to_string(),
            repository_id: None,
            max_severity: "critical".to_string(),
            block_unscanned: true,
            block_on_fail: true,
            is_enabled: true,
            min_staging_hours: Some(24),
            max_artifact_age_days: Some(365),
            require_signature: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(policy.name, "no-critical-vulns");
        assert!(policy.block_unscanned);
        assert!(policy.block_on_fail);
        assert!(policy.is_enabled);
        assert_eq!(policy.min_staging_hours, Some(24));
        assert!(policy.repository_id.is_none()); // global policy
    }

    #[test]
    fn test_scan_policy_repo_specific() {
        let repo_id = Uuid::new_v4();
        let policy = ScanPolicy {
            id: Uuid::new_v4(),
            name: "repo-policy".to_string(),
            repository_id: Some(repo_id),
            max_severity: "high".to_string(),
            block_unscanned: false,
            block_on_fail: false,
            is_enabled: true,
            min_staging_hours: None,
            max_artifact_age_days: None,
            require_signature: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(policy.repository_id, Some(repo_id));
        assert!(policy.require_signature);
    }

    #[test]
    fn test_scan_policy_serialization_roundtrip() {
        let policy = ScanPolicy {
            id: Uuid::nil(),
            name: "test-policy".to_string(),
            repository_id: None,
            max_severity: "medium".to_string(),
            block_unscanned: true,
            block_on_fail: false,
            is_enabled: true,
            min_staging_hours: Some(48),
            max_artifact_age_days: None,
            require_signature: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json_str = serde_json::to_string(&policy).unwrap();
        let deserialized: ScanPolicy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.name, "test-policy");
        assert_eq!(deserialized.max_severity, "medium");
        assert!(deserialized.block_unscanned);
        assert_eq!(deserialized.min_staging_hours, Some(48));
        assert!(deserialized.max_artifact_age_days.is_none());
    }

    // -----------------------------------------------------------------------
    // Violation message formatting logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_violation_message_unscanned() {
        let policy_name = "strict-policy";
        let msg = format!("Policy '{}': artifact has not been scanned", policy_name);
        assert_eq!(msg, "Policy 'strict-policy': artifact has not been scanned");
    }

    #[test]
    fn test_violation_message_scan_failed() {
        let policy_name = "default";
        let msg = format!("Policy '{}': latest scan failed", policy_name);
        assert_eq!(msg, "Policy 'default': latest scan failed");
    }

    #[test]
    fn test_violation_message_severity() {
        let policy_name = "no-high";
        let count = 5;
        let severity = "high";
        let msg = format!(
            "Policy '{}': {} findings at or above {} severity",
            policy_name, count, severity
        );
        assert_eq!(
            msg,
            "Policy 'no-high': 5 findings at or above high severity"
        );
    }

    // -----------------------------------------------------------------------
    // Severity::from_str_loose used in policy evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_from_str_loose_for_policy() {
        // The policy evaluation uses from_str_loose with unwrap_or(Critical)
        let threshold = Severity::from_str_loose("high").unwrap_or(Severity::Critical);
        assert_eq!(threshold, Severity::High);

        let unknown = Severity::from_str_loose("unknown").unwrap_or(Severity::Critical);
        assert_eq!(unknown, Severity::Critical);
    }

    // -----------------------------------------------------------------------
    // Policy allowed = violations.is_empty() logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_result_allowed_when_empty_violations() {
        let violations: Vec<String> = vec![];
        let result = PolicyResult {
            allowed: violations.is_empty(),
            violations,
        };
        assert!(result.allowed);
    }

    #[test]
    fn test_policy_result_blocked_when_nonempty_violations() {
        let violations = vec!["test".to_string()];
        let result = PolicyResult {
            allowed: violations.is_empty(),
            violations,
        };
        assert!(!result.allowed);
    }
}
