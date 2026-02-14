//! Promotion rule service.
//!
//! Manages auto-promotion rules and evaluates artifacts against rule criteria
//! to determine if they can be automatically promoted from staging to release.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::promotion::PromotionRule;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePromotionRuleInput {
    pub name: String,
    pub source_repo_id: Uuid,
    pub target_repo_id: Uuid,
    pub is_enabled: bool,
    pub max_cve_severity: Option<String>,
    pub allowed_licenses: Option<Vec<String>>,
    pub require_signature: bool,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    pub min_health_score: Option<i32>,
    pub auto_promote: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePromotionRuleInput {
    pub name: Option<String>,
    pub is_enabled: Option<bool>,
    pub max_cve_severity: Option<String>,
    pub allowed_licenses: Option<Vec<String>>,
    pub require_signature: Option<bool>,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    pub min_health_score: Option<i32>,
    pub auto_promote: Option<bool>,
}

/// Result of evaluating a single artifact against a single rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEvaluationResult {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub passed: bool,
    pub violations: Vec<String>,
}

/// Result of an auto-promotion attempt for one rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPromotionResult {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub artifact_id: Uuid,
    pub promoted: bool,
    pub target_repo_id: Uuid,
    pub violations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Pure evaluation helpers (no DB access, testable in isolation)
// ---------------------------------------------------------------------------

/// Check if the highest severity found in scan results exceeds the max allowed
/// severity from the rule.
///
/// Returns a violation message if any severity level exceeds the threshold.
pub fn check_cve_severity(
    max_cve_severity: &str,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
) -> Option<String> {
    let threshold = severity_to_level(max_cve_severity);

    // Check from most severe to least severe — if any level above threshold
    // has findings, it's a violation.
    if critical_count > 0 && severity_to_level("critical") < threshold {
        return Some(format!(
            "Found {} critical CVEs (max allowed severity: {})",
            critical_count, max_cve_severity
        ));
    }
    if high_count > 0 && severity_to_level("high") < threshold {
        return Some(format!(
            "Found {} high CVEs (max allowed severity: {})",
            high_count, max_cve_severity
        ));
    }
    if medium_count > 0 && severity_to_level("medium") < threshold {
        return Some(format!(
            "Found {} medium CVEs (max allowed severity: {})",
            medium_count, max_cve_severity
        ));
    }
    if low_count > 0 && severity_to_level("low") < threshold {
        return Some(format!(
            "Found {} low CVEs (max allowed severity: {})",
            low_count, max_cve_severity
        ));
    }

    None
}

/// Convert severity string to a numeric level (lower = more severe).
/// critical=0, high=1, medium=2, low=3, info/none=4
fn severity_to_level(severity: &str) -> i32 {
    match severity.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" | "moderate" => 2,
        "low" => 3,
        "info" | "informational" | "none" => 4,
        _ => 2, // default to medium
    }
}

/// Check if the artifact has been in staging long enough.
pub fn check_min_staging_hours(
    min_hours: i32,
    artifact_created_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<String> {
    let hours_in_staging = (now - artifact_created_at).num_hours();
    if hours_in_staging < min_hours as i64 {
        Some(format!(
            "Artifact has only been in staging for {} hours (minimum: {})",
            hours_in_staging, min_hours
        ))
    } else {
        None
    }
}

/// Check if the artifact is too old.
pub fn check_max_artifact_age(
    max_days: i32,
    artifact_created_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<String> {
    let age_days = (now - artifact_created_at).num_days();
    if age_days > max_days as i64 {
        Some(format!(
            "Artifact is {} days old (maximum: {})",
            age_days, max_days
        ))
    } else {
        None
    }
}

/// Check if the artifact health score meets the minimum.
pub fn check_min_health_score(min_score: i32, actual_score: i32) -> Option<String> {
    if actual_score < min_score {
        Some(format!(
            "Health score {} is below minimum required score of {}",
            actual_score, min_score
        ))
    } else {
        None
    }
}

/// Check if the artifact's licenses are in the allowed list.
pub fn check_allowed_licenses(allowed: &[String], found_licenses: &[String]) -> Option<String> {
    let allowed_upper: Vec<String> = allowed.iter().map(|l| l.to_uppercase()).collect();

    let disallowed: Vec<&String> = found_licenses
        .iter()
        .filter(|l| !allowed_upper.contains(&l.to_uppercase()))
        .collect();

    if disallowed.is_empty() {
        None
    } else {
        let names: Vec<&str> = disallowed.iter().map(|s| s.as_str()).collect();
        Some(format!(
            "Found licenses not in allowed list: {}",
            names.join(", ")
        ))
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct PromotionRuleService {
    db: PgPool,
}

impl PromotionRuleService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // -----------------------------------------------------------------------
    // CRUD
    // -----------------------------------------------------------------------

    pub async fn create(&self, input: CreatePromotionRuleInput) -> Result<PromotionRule> {
        let rule: PromotionRule = sqlx::query_as::<_, PromotionRule>(
            r#"
            INSERT INTO promotion_rules (
                name, source_repo_id, target_repo_id, is_enabled,
                max_cve_severity, allowed_licenses, require_signature,
                min_staging_hours, max_artifact_age_days, min_health_score,
                auto_promote
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(&input.name)
        .bind(input.source_repo_id)
        .bind(input.target_repo_id)
        .bind(input.is_enabled)
        .bind(&input.max_cve_severity)
        .bind(&input.allowed_licenses)
        .bind(input.require_signature)
        .bind(input.min_staging_hours)
        .bind(input.max_artifact_age_days)
        .bind(input.min_health_score)
        .bind(input.auto_promote)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rule)
    }

    pub async fn list(&self, source_repo_id: Option<Uuid>) -> Result<Vec<PromotionRule>> {
        let rules: Vec<PromotionRule> = if let Some(repo_id) = source_repo_id {
            sqlx::query_as::<_, PromotionRule>(
                r#"SELECT * FROM promotion_rules WHERE source_repo_id = $1 ORDER BY created_at DESC"#,
            )
            .bind(repo_id)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        } else {
            sqlx::query_as::<_, PromotionRule>(
                r#"SELECT * FROM promotion_rules ORDER BY created_at DESC"#,
            )
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        };

        Ok(rules)
    }

    pub async fn get(&self, id: Uuid) -> Result<PromotionRule> {
        let rule: PromotionRule =
            sqlx::query_as::<_, PromotionRule>(r#"SELECT * FROM promotion_rules WHERE id = $1"#)
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .ok_or_else(|| AppError::NotFound("Promotion rule not found".to_string()))?;

        Ok(rule)
    }

    pub async fn update(&self, id: Uuid, input: UpdatePromotionRuleInput) -> Result<PromotionRule> {
        // Verify exists
        let existing = self.get(id).await?;

        let name = input.name.unwrap_or(existing.name);
        let is_enabled = input.is_enabled.unwrap_or(existing.is_enabled);
        let max_cve_severity = input.max_cve_severity.or(existing.max_cve_severity);
        let require_signature = input
            .require_signature
            .unwrap_or(existing.require_signature);
        let min_staging_hours = input.min_staging_hours.or(existing.min_staging_hours);
        let max_artifact_age_days = input
            .max_artifact_age_days
            .or(existing.max_artifact_age_days);
        let min_health_score = input.min_health_score.or(existing.min_health_score);
        let auto_promote = input.auto_promote.unwrap_or(existing.auto_promote);
        let allowed_licenses = input.allowed_licenses.or(existing.allowed_licenses);

        let rule: PromotionRule = sqlx::query_as::<_, PromotionRule>(
            r#"
            UPDATE promotion_rules
            SET name = $2, is_enabled = $3, max_cve_severity = $4,
                allowed_licenses = $5, require_signature = $6,
                min_staging_hours = $7, max_artifact_age_days = $8,
                min_health_score = $9, auto_promote = $10,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&name)
        .bind(is_enabled)
        .bind(&max_cve_severity)
        .bind(&allowed_licenses)
        .bind(require_signature)
        .bind(min_staging_hours)
        .bind(max_artifact_age_days)
        .bind(min_health_score)
        .bind(auto_promote)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rule)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query(r#"DELETE FROM promotion_rules WHERE id = $1"#)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Promotion rule not found".to_string()));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Evaluation
    // -----------------------------------------------------------------------

    /// Evaluate a single artifact against a promotion rule.
    pub async fn evaluate_artifact(
        &self,
        artifact_id: Uuid,
        rule: &PromotionRule,
    ) -> Result<RuleEvaluationResult> {
        let mut violations: Vec<String> = Vec::new();
        let now = Utc::now();

        // 1. CVE severity check
        if let Some(ref max_severity) = rule.max_cve_severity {
            if let Some(scan) = self.get_latest_scan(artifact_id).await? {
                if let Some(v) = check_cve_severity(
                    max_severity,
                    scan.critical_count,
                    scan.high_count,
                    scan.medium_count,
                    scan.low_count,
                ) {
                    violations.push(v);
                }
            }
            // No scan results => skip CVE check (not a violation)
        }

        // 2. License check
        if let Some(ref allowed) = rule.allowed_licenses {
            if !allowed.is_empty() {
                let licenses = self.get_artifact_licenses(artifact_id).await?;
                if !licenses.is_empty() {
                    if let Some(v) = check_allowed_licenses(allowed, &licenses) {
                        violations.push(v);
                    }
                }
            }
        }

        // 3. Signature check
        if rule.require_signature {
            let has_sig = self
                .check_artifact_signature(artifact_id, rule.source_repo_id)
                .await?;
            if !has_sig {
                violations.push("Artifact does not have a valid signature".to_string());
            }
        }

        // 4. Min staging hours
        if let Some(min_hours) = rule.min_staging_hours {
            if let Some(created_at) = self.get_artifact_created_at(artifact_id).await? {
                if let Some(v) = check_min_staging_hours(min_hours, created_at, now) {
                    violations.push(v);
                }
            }
        }

        // 5. Max artifact age
        if let Some(max_days) = rule.max_artifact_age_days {
            if let Some(created_at) = self.get_artifact_created_at(artifact_id).await? {
                if let Some(v) = check_max_artifact_age(max_days, created_at, now) {
                    violations.push(v);
                }
            }
        }

        // 6. Health score check
        if let Some(min_score) = rule.min_health_score {
            if let Some(score) = self.get_artifact_health_score(artifact_id).await? {
                if let Some(v) = check_min_health_score(min_score, score) {
                    violations.push(v);
                }
            }
        }

        let passed = violations.is_empty();

        Ok(RuleEvaluationResult {
            rule_id: rule.id,
            rule_name: rule.name.clone(),
            passed,
            violations,
        })
    }

    /// Find all enabled rules for a source repository, evaluate each against the
    /// given artifact, and return results. Actual promotion is left to the caller
    /// to avoid coupling storage concerns into this service.
    pub async fn try_auto_promote(
        &self,
        artifact_id: Uuid,
        source_repo_id: Uuid,
    ) -> Result<Vec<AutoPromotionResult>> {
        let rules: Vec<PromotionRule> = sqlx::query_as::<_, PromotionRule>(
            r#"
            SELECT * FROM promotion_rules
            WHERE source_repo_id = $1 AND is_enabled = true AND auto_promote = true
            ORDER BY created_at ASC
            "#,
        )
        .bind(source_repo_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut results = Vec::new();

        for rule in &rules {
            let eval = self.evaluate_artifact(artifact_id, rule).await?;

            results.push(AutoPromotionResult {
                rule_id: rule.id,
                rule_name: rule.name.clone(),
                artifact_id,
                promoted: eval.passed,
                target_repo_id: rule.target_repo_id,
                violations: eval.violations,
            });
        }

        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Internal DB helpers
    // -----------------------------------------------------------------------

    async fn get_latest_scan(&self, artifact_id: Uuid) -> Result<Option<ScanCountsRow>> {
        let row: Option<ScanCountsRow> = sqlx::query_as::<_, ScanCountsRow>(
            r#"
            SELECT critical_count, high_count, medium_count, low_count
            FROM scan_results
            WHERE artifact_id = $1 AND status = 'completed'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(row)
    }

    async fn get_artifact_licenses(&self, artifact_id: Uuid) -> Result<Vec<String>> {
        let licenses: Option<Vec<String>> = sqlx::query_scalar::<_, Option<Vec<String>>>(
            r#"
            SELECT licenses
            FROM sbom_documents
            WHERE artifact_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .flatten();

        Ok(licenses.unwrap_or_default())
    }

    async fn get_artifact_created_at(&self, artifact_id: Uuid) -> Result<Option<DateTime<Utc>>> {
        let ts: Option<DateTime<Utc>> = sqlx::query_scalar::<_, DateTime<Utc>>(
            r#"SELECT created_at FROM artifacts WHERE id = $1"#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(ts)
    }

    async fn check_artifact_signature(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<bool> {
        let signed: bool = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM signing_key_audit ska
                JOIN signing_keys sk ON sk.id = ska.signing_key_id
                WHERE sk.repository_id = $2
                  AND ska.action = 'used_for_signing'
                  AND ska.details->>'artifact_id' = $1::TEXT
            )
            "#,
        )
        .bind(artifact_id)
        .bind(repository_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(signed)
    }

    async fn get_artifact_health_score(&self, artifact_id: Uuid) -> Result<Option<i32>> {
        let score: Option<i32> = sqlx::query_scalar::<_, i32>(
            r#"SELECT health_score FROM artifact_health_scores WHERE artifact_id = $1"#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(score)
    }
}

/// Internal row type for scan count queries.
#[derive(Debug, Clone, sqlx::FromRow)]
struct ScanCountsRow {
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // check_cve_severity
    // =======================================================================

    #[test]
    fn test_cve_severity_all_clean() {
        // No CVEs at all — should always pass
        let result = check_cve_severity("medium", 0, 0, 0, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_cve_severity_critical_allowed_with_critical_threshold() {
        // Max severity "critical" means critical findings are tolerated
        let result = check_cve_severity("critical", 5, 10, 20, 30);
        assert!(result.is_none());
    }

    #[test]
    fn test_cve_severity_high_threshold_blocks_critical() {
        // max_cve_severity=high => critical is above threshold
        let result = check_cve_severity("high", 3, 0, 0, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("critical"));
    }

    #[test]
    fn test_cve_severity_high_threshold_allows_high() {
        // max_cve_severity=high => high is at the threshold, allowed
        let result = check_cve_severity("high", 0, 5, 0, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_cve_severity_medium_threshold_blocks_high() {
        // max_cve_severity=medium => high is above threshold
        let result = check_cve_severity("medium", 0, 3, 0, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("high"));
    }

    #[test]
    fn test_cve_severity_medium_threshold_allows_medium() {
        // max_cve_severity=medium => medium is at threshold, allowed
        let result = check_cve_severity("medium", 0, 0, 10, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_cve_severity_low_threshold_blocks_medium() {
        let result = check_cve_severity("low", 0, 0, 5, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("medium"));
    }

    #[test]
    fn test_cve_severity_low_threshold_allows_low() {
        let result = check_cve_severity("low", 0, 0, 0, 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_cve_severity_info_threshold_blocks_low() {
        let result = check_cve_severity("info", 0, 0, 0, 5);
        assert!(result.is_some());
        assert!(result.unwrap().contains("low"));
    }

    #[test]
    fn test_cve_severity_reports_first_violation_only() {
        // When multiple severity levels violate, the function returns the
        // first violation (most severe).
        let result = check_cve_severity("low", 2, 3, 4, 5);
        assert!(result.is_some());
        assert!(result.unwrap().contains("critical"));
    }

    #[test]
    fn test_cve_severity_case_insensitive() {
        let result = check_cve_severity("HIGH", 3, 0, 0, 0);
        assert!(result.is_some());
    }

    #[test]
    fn test_cve_severity_unknown_defaults_to_medium() {
        // Unknown severity string defaults to level 2 (medium)
        let result = check_cve_severity("unknown-value", 0, 3, 0, 0);
        assert!(result.is_some()); // high > medium threshold
    }

    // =======================================================================
    // check_min_staging_hours
    // =======================================================================

    #[test]
    fn test_staging_hours_passes_when_enough_time() {
        let now = Utc::now();
        let created = now - chrono::Duration::hours(48);
        let result = check_min_staging_hours(24, created, now);
        assert!(result.is_none());
    }

    #[test]
    fn test_staging_hours_fails_when_too_recent() {
        let now = Utc::now();
        let created = now - chrono::Duration::hours(2);
        let result = check_min_staging_hours(24, created, now);
        assert!(result.is_some());
        assert!(result.unwrap().contains("minimum: 24"));
    }

    #[test]
    fn test_staging_hours_boundary_exact() {
        let now = Utc::now();
        let created = now - chrono::Duration::hours(24);
        let result = check_min_staging_hours(24, created, now);
        assert!(result.is_none()); // exactly 24 hours => passes
    }

    #[test]
    fn test_staging_hours_zero_minimum() {
        let now = Utc::now();
        let created = now - chrono::Duration::seconds(1);
        let result = check_min_staging_hours(0, created, now);
        assert!(result.is_none());
    }

    // =======================================================================
    // check_max_artifact_age
    // =======================================================================

    #[test]
    fn test_artifact_age_passes_when_young() {
        let now = Utc::now();
        let created = now - chrono::Duration::days(5);
        let result = check_max_artifact_age(30, created, now);
        assert!(result.is_none());
    }

    #[test]
    fn test_artifact_age_fails_when_too_old() {
        let now = Utc::now();
        let created = now - chrono::Duration::days(60);
        let result = check_max_artifact_age(30, created, now);
        assert!(result.is_some());
        assert!(result.unwrap().contains("maximum: 30"));
    }

    #[test]
    fn test_artifact_age_boundary_exact() {
        let now = Utc::now();
        let created = now - chrono::Duration::days(30);
        let result = check_max_artifact_age(30, created, now);
        assert!(result.is_none()); // exactly 30 days => passes
    }

    // =======================================================================
    // check_min_health_score
    // =======================================================================

    #[test]
    fn test_health_score_passes_when_above() {
        let result = check_min_health_score(75, 90);
        assert!(result.is_none());
    }

    #[test]
    fn test_health_score_fails_when_below() {
        let result = check_min_health_score(75, 50);
        let msg = result.expect("should have a violation message");
        assert!(msg.contains("50"));
    }

    #[test]
    fn test_health_score_boundary_exact() {
        let result = check_min_health_score(75, 75);
        assert!(result.is_none()); // exactly at minimum => passes
    }

    #[test]
    fn test_health_score_zero_minimum() {
        let result = check_min_health_score(0, 0);
        assert!(result.is_none());
    }

    // =======================================================================
    // check_allowed_licenses
    // =======================================================================

    #[test]
    fn test_licenses_all_allowed() {
        let allowed = vec!["MIT".to_string(), "Apache-2.0".to_string()];
        let found = vec!["MIT".to_string(), "Apache-2.0".to_string()];
        let result = check_allowed_licenses(&allowed, &found);
        assert!(result.is_none());
    }

    #[test]
    fn test_licenses_one_disallowed() {
        let allowed = vec!["MIT".to_string(), "Apache-2.0".to_string()];
        let found = vec!["MIT".to_string(), "GPL-3.0".to_string()];
        let result = check_allowed_licenses(&allowed, &found);
        assert!(result.is_some());
        assert!(result.unwrap().contains("GPL-3.0"));
    }

    #[test]
    fn test_licenses_case_insensitive() {
        let allowed = vec!["MIT".to_string()];
        let found = vec!["mit".to_string()];
        let result = check_allowed_licenses(&allowed, &found);
        assert!(result.is_none());
    }

    #[test]
    fn test_licenses_empty_found() {
        let allowed = vec!["MIT".to_string()];
        let found: Vec<String> = vec![];
        let result = check_allowed_licenses(&allowed, &found);
        assert!(result.is_none());
    }

    #[test]
    fn test_licenses_multiple_disallowed() {
        let allowed = vec!["MIT".to_string()];
        let found = vec![
            "MIT".to_string(),
            "GPL-3.0".to_string(),
            "AGPL-3.0".to_string(),
        ];
        let result = check_allowed_licenses(&allowed, &found);
        assert!(result.is_some());
        let msg = result.unwrap();
        assert!(msg.contains("GPL-3.0"));
        assert!(msg.contains("AGPL-3.0"));
    }

    // =======================================================================
    // Rule evaluation with all None criteria
    // =======================================================================

    #[test]
    fn test_rule_all_none_criteria_pass() {
        // A rule with no criteria at all should always pass (nothing to check).
        // We can't call evaluate_artifact without a DB, but we can verify that
        // all the pure check functions return None with empty/zero inputs.
        assert!(check_cve_severity("critical", 0, 0, 0, 0).is_none());
        assert!(check_min_health_score(0, 0).is_none());
        let now = Utc::now();
        let old = now - chrono::Duration::days(1);
        assert!(check_min_staging_hours(0, old, now).is_none());
        assert!(check_max_artifact_age(9999, old, now).is_none());
        assert!(check_allowed_licenses(&[], &[]).is_none());
    }

    // =======================================================================
    // severity_to_level
    // =======================================================================

    #[test]
    fn test_severity_to_level_ordering() {
        assert!(severity_to_level("critical") < severity_to_level("high"));
        assert!(severity_to_level("high") < severity_to_level("medium"));
        assert!(severity_to_level("medium") < severity_to_level("low"));
        assert!(severity_to_level("low") < severity_to_level("info"));
    }

    #[test]
    fn test_severity_to_level_aliases() {
        assert_eq!(severity_to_level("moderate"), severity_to_level("medium"));
        assert_eq!(
            severity_to_level("informational"),
            severity_to_level("info")
        );
        assert_eq!(severity_to_level("none"), severity_to_level("info"));
    }

    // =======================================================================
    // DTO serialization
    // =======================================================================

    #[test]
    fn test_rule_evaluation_result_serialization() {
        let result = RuleEvaluationResult {
            rule_id: Uuid::nil(),
            rule_name: "test-rule".to_string(),
            passed: true,
            violations: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["passed"], true);
        assert!(json["violations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_auto_promotion_result_serialization() {
        let result = AutoPromotionResult {
            rule_id: Uuid::nil(),
            rule_name: "release-gate".to_string(),
            artifact_id: Uuid::nil(),
            promoted: false,
            target_repo_id: Uuid::nil(),
            violations: vec!["CVE threshold exceeded".to_string()],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["promoted"], false);
        assert_eq!(json["violations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_create_input_serialization_roundtrip() {
        let input = CreatePromotionRuleInput {
            name: "staging-to-prod".to_string(),
            source_repo_id: Uuid::nil(),
            target_repo_id: Uuid::nil(),
            is_enabled: true,
            max_cve_severity: Some("high".to_string()),
            allowed_licenses: Some(vec!["MIT".to_string(), "Apache-2.0".to_string()]),
            require_signature: true,
            min_staging_hours: Some(24),
            max_artifact_age_days: Some(90),
            min_health_score: Some(75),
            auto_promote: true,
        };
        let json = serde_json::to_string(&input).unwrap();
        let parsed: CreatePromotionRuleInput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "staging-to-prod");
        assert_eq!(parsed.min_staging_hours, Some(24));
    }
}
