//! Promotion policy service.
//!
//! Evaluates artifacts against security policies before promotion from staging to release.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;
use crate::models::sbom::PolicyAction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub passed: bool,
    pub action: PolicyAction,
    pub violations: Vec<PolicyViolation>,
    pub cve_summary: Option<CveSummary>,
    pub license_summary: Option<LicenseSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveSummary {
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub total_count: i32,
    pub open_cves: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseSummary {
    pub licenses_found: Vec<String>,
    pub denied_licenses: Vec<String>,
    pub unknown_licenses: Vec<String>,
}

/// Evaluate CVE counts against a severity threshold, returning violations for
/// any severity level that exceeds the implied limit.
fn evaluate_cve_thresholds(
    summary: &CveSummary,
    max_severity: &str,
    block_on_fail: bool,
) -> Vec<PolicyViolation> {
    let (max_critical, max_high, max_medium) = match max_severity.to_lowercase().as_str() {
        "critical" => (0, i32::MAX, i32::MAX),
        "high" => (0, 0, i32::MAX),
        "medium" | "low" => (0, 0, 0),
        _ => (0, 0, i32::MAX),
    };

    let checks: &[(&str, i32, i32)] = &[
        ("critical", summary.critical_count, max_critical),
        ("high", summary.high_count, max_high),
        ("medium", summary.medium_count, max_medium),
    ];

    checks
        .iter()
        .filter(|(_, count, max)| count > max)
        .map(|(severity, count, max)| PolicyViolation {
            rule: "cve-severity-threshold".to_string(),
            severity: severity.to_string(),
            message: format!(
                "Found {} {} vulnerabilities (max allowed: {})",
                count,
                if *severity == "high" {
                    "high severity"
                } else {
                    severity
                },
                max
            ),
            details: Some(serde_json::json!({
                "count": count,
                "max_allowed": max,
                "block_on_fail": block_on_fail
            })),
        })
        .collect()
}

/// Evaluate age-based promotion gates, returning violations when the artifact
/// hasn't been in staging long enough or is too old.
fn evaluate_age_gates(
    artifact_created_at: chrono::DateTime<chrono::Utc>,
    min_staging_hours: Option<i32>,
    max_artifact_age_days: Option<i32>,
) -> Vec<PolicyViolation> {
    let now = chrono::Utc::now();
    let mut violations = Vec::new();

    if let Some(min_hours) = min_staging_hours {
        let hours_in_staging = (now - artifact_created_at).num_hours();
        if hours_in_staging < min_hours as i64 {
            violations.push(PolicyViolation {
                rule: "min-staging-time".to_string(),
                severity: "high".to_string(),
                message: format!(
                    "Artifact has only been in staging for {} hours (minimum: {} hours)",
                    hours_in_staging, min_hours
                ),
                details: Some(serde_json::json!({
                    "hours_in_staging": hours_in_staging,
                    "min_staging_hours": min_hours
                })),
            });
        }
    }

    if let Some(max_days) = max_artifact_age_days {
        let age_days = (now - artifact_created_at).num_days();
        if age_days > max_days as i64 {
            violations.push(PolicyViolation {
                rule: "max-artifact-age".to_string(),
                severity: "medium".to_string(),
                message: format!(
                    "Artifact is {} days old (maximum: {} days)",
                    age_days, max_days
                ),
                details: Some(serde_json::json!({
                    "age_days": age_days,
                    "max_artifact_age_days": max_days
                })),
            });
        }
    }

    violations
}

/// Evaluate whether an artifact meets the signature requirement.
fn evaluate_signature_requirement(has_signature: bool) -> Vec<PolicyViolation> {
    if has_signature {
        return vec![];
    }

    vec![PolicyViolation {
        rule: "require-signature".to_string(),
        severity: "high".to_string(),
        message: "Artifact does not have a valid signature".to_string(),
        details: None,
    }]
}

/// Evaluate licenses found in an SBOM against a license policy, returning
/// violations for denied or unrecognized licenses.
fn evaluate_license_policy(
    summary: &LicenseSummary,
    policy: &LicensePolicyConfig,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    let mut denied_found = Vec::new();
    let mut unknown_found = Vec::new();

    for license in &summary.licenses_found {
        let normalized = license.to_uppercase();

        if policy
            .denied_licenses
            .iter()
            .any(|d| d.to_uppercase() == normalized)
        {
            denied_found.push(license.clone());
            continue;
        }

        if !policy.allowed_licenses.is_empty()
            && !policy
                .allowed_licenses
                .iter()
                .any(|a| a.to_uppercase() == normalized)
            && !policy.allow_unknown
        {
            unknown_found.push(license.clone());
        }
    }

    if !denied_found.is_empty() {
        violations.push(PolicyViolation {
            rule: "license-compliance".to_string(),
            severity: match policy.action {
                PolicyAction::Block => "critical".to_string(),
                PolicyAction::Warn => "medium".to_string(),
                PolicyAction::Allow => "low".to_string(),
            },
            message: format!(
                "Found {} denied licenses: {}",
                denied_found.len(),
                denied_found.join(", ")
            ),
            details: Some(serde_json::json!({
                "denied_licenses": denied_found,
                "policy_name": policy.name
            })),
        });
    }

    if !unknown_found.is_empty() {
        violations.push(PolicyViolation {
            rule: "license-compliance".to_string(),
            severity: "medium".to_string(),
            message: format!(
                "Found {} licenses not in allowed list: {}",
                unknown_found.len(),
                unknown_found.join(", ")
            ),
            details: Some(serde_json::json!({
                "unknown_licenses": unknown_found,
                "policy_name": policy.name
            })),
        });
    }

    violations
}

/// Escalate the current action based on a violation's severity.
/// "critical" or "high" severity always escalates to Block; anything else
/// escalates to Warn unless already at Block.
fn escalate_action_by_severity(current: PolicyAction, severity: &str) -> PolicyAction {
    if severity == "critical" || severity == "high" {
        return PolicyAction::Block;
    }
    if current != PolicyAction::Block {
        return PolicyAction::Warn;
    }
    current
}

/// Escalate the current action based on a policy's configured action.
fn escalate_action_by_policy(current: PolicyAction, policy_action: &PolicyAction) -> PolicyAction {
    match policy_action {
        PolicyAction::Block => PolicyAction::Block,
        PolicyAction::Warn if current != PolicyAction::Block => PolicyAction::Warn,
        _ => current,
    }
}

/// Collect violations and escalate the action for each one using a severity-based
/// escalation strategy.
fn collect_with_severity_escalation(
    violations: &mut Vec<PolicyViolation>,
    action: &mut PolicyAction,
    new_violations: Vec<PolicyViolation>,
) {
    for v in new_violations {
        *action = escalate_action_by_severity(*action, &v.severity);
        violations.push(v);
    }
}

/// Evaluate CVEs against a scan policy, or apply the default critical-CVE policy
/// when no scan policy is configured.
fn evaluate_cves_against_policy(
    summary: &CveSummary,
    scan_policy: Option<&ScanPolicyConfig>,
    violations: &mut Vec<PolicyViolation>,
    action: &mut PolicyAction,
) {
    if let Some(policy) = scan_policy {
        let cve_violations =
            evaluate_cve_thresholds(summary, &policy.max_severity, policy.block_on_fail);
        collect_with_severity_escalation(violations, action, cve_violations);
        return;
    }

    // Default policy: block on any critical CVEs
    if summary.critical_count > 0 {
        *action = PolicyAction::Block;
        violations.push(PolicyViolation {
            rule: "default-cve-policy".to_string(),
            severity: "critical".to_string(),
            message: format!(
                "Artifact has {} critical vulnerabilities",
                summary.critical_count
            ),
            details: Some(serde_json::json!({
                "cves": summary.open_cves
            })),
        });
    }
}

/// Evaluate licenses against a license policy.
fn evaluate_licenses_against_policy(
    summary: &LicenseSummary,
    policy: &LicensePolicyConfig,
    violations: &mut Vec<PolicyViolation>,
    action: &mut PolicyAction,
) {
    let license_violations = evaluate_license_policy(summary, policy);
    for v in license_violations {
        *action = escalate_action_by_policy(*action, &policy.action);
        violations.push(v);
    }
}

pub struct PromotionPolicyService {
    db: PgPool,
}

impl PromotionPolicyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn evaluate_artifact(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<PolicyEvaluationResult> {
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        let cve_summary = self.get_cve_summary(artifact_id).await?;
        let license_summary = self.get_license_summary(artifact_id).await?;
        let scan_policy = self.get_scan_policy(repository_id).await?;
        let license_policy = self.get_license_policy(repository_id).await?;

        if let Some(ref summary) = cve_summary {
            evaluate_cves_against_policy(
                summary,
                scan_policy.as_ref(),
                &mut violations,
                &mut action,
            );
        }

        if let (Some(ref summary), Some(ref policy)) = (&license_summary, &license_policy) {
            evaluate_licenses_against_policy(summary, policy, &mut violations, &mut action);
        }

        if let Some(ref policy) = scan_policy {
            self.evaluate_age_and_signature(
                artifact_id,
                repository_id,
                policy,
                &mut violations,
                &mut action,
            )
            .await?;
        }

        let passed = violations.is_empty();

        Ok(PolicyEvaluationResult {
            passed,
            action,
            violations,
            cve_summary,
            license_summary,
        })
    }

    /// Evaluate age gates and signature requirements from a scan policy.
    async fn evaluate_age_and_signature(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        policy: &ScanPolicyConfig,
        violations: &mut Vec<PolicyViolation>,
        action: &mut PolicyAction,
    ) -> Result<()> {
        let has_age_constraints =
            policy.min_staging_hours.is_some() || policy.max_artifact_age_days.is_some();

        if has_age_constraints {
            if let Some(created_at) = self.get_artifact_created_at(artifact_id).await? {
                let age_violations = evaluate_age_gates(
                    created_at,
                    policy.min_staging_hours,
                    policy.max_artifact_age_days,
                );
                collect_with_severity_escalation(violations, action, age_violations);
            }
        }

        if policy.require_signature {
            let has_signature = self
                .check_artifact_signature(artifact_id, repository_id)
                .await?;
            let sig_violations = evaluate_signature_requirement(has_signature);
            for v in sig_violations {
                *action = PolicyAction::Block;
                violations.push(v);
            }
        }

        Ok(())
    }

    async fn get_cve_summary(&self, artifact_id: Uuid) -> Result<Option<CveSummary>> {
        #[derive(sqlx::FromRow)]
        struct ScanRow {
            critical_count: i32,
            high_count: i32,
            medium_count: i32,
            low_count: i32,
            findings_count: i32,
        }

        let scan: Option<ScanRow> = sqlx::query_as(
            r#"
            SELECT critical_count, high_count, medium_count, low_count, findings_count
            FROM scan_results
            WHERE artifact_id = $1 AND status = 'completed'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await?;

        let Some(scan) = scan else {
            return Ok(None);
        };

        let cves: Vec<String> = sqlx::query_scalar(
            r#"SELECT DISTINCT cve_id FROM cve_history WHERE artifact_id = $1 AND status = 'open' AND cve_id IS NOT NULL"#,
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await?;

        Ok(Some(CveSummary {
            critical_count: scan.critical_count,
            high_count: scan.high_count,
            medium_count: scan.medium_count,
            low_count: scan.low_count,
            total_count: scan.findings_count,
            open_cves: cves,
        }))
    }

    async fn get_license_summary(&self, artifact_id: Uuid) -> Result<Option<LicenseSummary>> {
        #[derive(sqlx::FromRow)]
        struct SbomRow {
            licenses: Option<Vec<String>>,
        }

        let sbom: Option<SbomRow> = sqlx::query_as(
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
        .await?;

        Ok(sbom.map(|s| LicenseSummary {
            licenses_found: s.licenses.unwrap_or_default(),
            denied_licenses: vec![],
            unknown_licenses: vec![],
        }))
    }

    async fn get_artifact_created_at(
        &self,
        artifact_id: Uuid,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        Ok(
            sqlx::query_scalar(r#"SELECT created_at FROM artifacts WHERE id = $1"#)
                .bind(artifact_id)
                .fetch_optional(&self.db)
                .await?,
        )
    }

    async fn check_artifact_signature(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<bool> {
        // Check if the repository has a signing config with active signing
        let has_sig: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM repository_signing_config rsc
                JOIN signing_keys sk ON sk.id = rsc.signing_key_id
                WHERE rsc.repository_id = $1 AND sk.is_active = true
            )
            "#,
        )
        .bind(repository_id)
        .fetch_one(&self.db)
        .await?;

        if !has_sig {
            // No signing config means we can't verify — treat as unsigned
            return Ok(false);
        }

        // Check if the artifact has been signed (has a signing audit entry)
        let signed: bool = sqlx::query_scalar(
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
        .await?;

        Ok(signed)
    }

    async fn get_scan_policy(&self, repository_id: Uuid) -> Result<Option<ScanPolicyConfig>> {
        let policy: Option<ScanPolicyConfig> = sqlx::query_as(
            r#"
            SELECT max_severity, block_on_fail,
                   min_staging_hours, max_artifact_age_days, require_signature
            FROM scan_policies
            WHERE (repository_id = $1 OR repository_id IS NULL) AND is_enabled = true
            ORDER BY repository_id DESC NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await?;

        Ok(policy)
    }

    async fn get_license_policy(&self, repository_id: Uuid) -> Result<Option<LicensePolicyConfig>> {
        #[derive(sqlx::FromRow)]
        struct LicensePolicyRow {
            name: String,
            allowed_licenses: Option<Vec<String>>,
            denied_licenses: Option<Vec<String>>,
            allow_unknown: bool,
            action: String,
        }

        let policy: Option<LicensePolicyRow> = sqlx::query_as(
            r#"
            SELECT name, allowed_licenses, denied_licenses, allow_unknown, action
            FROM license_policies
            WHERE (repository_id = $1 OR repository_id IS NULL) AND is_enabled = true
            ORDER BY repository_id DESC NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await?;

        Ok(policy.map(|p| LicensePolicyConfig {
            name: p.name,
            allowed_licenses: p.allowed_licenses.unwrap_or_default(),
            denied_licenses: p.denied_licenses.unwrap_or_default(),
            allow_unknown: p.allow_unknown,
            action: PolicyAction::parse(&p.action).unwrap_or(PolicyAction::Warn),
        }))
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct ScanPolicyConfig {
    max_severity: String,
    block_on_fail: bool,
    min_staging_hours: Option<i32>,
    max_artifact_age_days: Option<i32>,
    require_signature: bool,
}

#[derive(Debug, Clone)]
struct LicensePolicyConfig {
    name: String,
    allowed_licenses: Vec<String>,
    denied_licenses: Vec<String>,
    allow_unknown: bool,
    action: PolicyAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // evaluate_cve_thresholds tests
    // =======================================================================

    #[test]
    fn test_cve_threshold_evaluation() {
        let summary = CveSummary {
            critical_count: 2,
            high_count: 5,
            medium_count: 10,
            low_count: 20,
            total_count: 37,
            open_cves: vec!["CVE-2024-1234".to_string()],
        };

        let violations = evaluate_cve_thresholds(&summary, "high", true);
        assert_eq!(violations.len(), 2);

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_cve_threshold_medium_blocks_all_three() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 2,
            medium_count: 3,
            low_count: 0,
            total_count: 6,
            open_cves: vec![],
        };

        // medium/low threshold: max_critical=0, max_high=0, max_medium=0
        let violations = evaluate_cve_thresholds(&summary, "medium", true);
        assert_eq!(violations.len(), 3);

        let severities: Vec<&str> = violations.iter().map(|v| v.severity.as_str()).collect();
        assert!(severities.contains(&"critical"));
        assert!(severities.contains(&"high"));
        assert!(severities.contains(&"medium"));
    }

    #[test]
    fn test_cve_threshold_low_same_as_medium() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 1,
            medium_count: 1,
            low_count: 10,
            total_count: 13,
            open_cves: vec![],
        };

        // "low" maps to same thresholds as "medium": (0, 0, 0)
        let violations = evaluate_cve_thresholds(&summary, "low", false);
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn test_cve_threshold_unknown_severity_defaults() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 1,
            medium_count: 0,
            low_count: 0,
            total_count: 2,
            open_cves: vec![],
        };

        // Unknown max_severity string defaults to (0, 0, i32::MAX)
        let violations = evaluate_cve_thresholds(&summary, "foobar", true);
        // critical=1 > max_critical=0 => violation
        // high=1 > max_high=0 => violation
        // medium=0 <= i32::MAX => no violation
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn test_cve_threshold_no_violations_when_clean() {
        let summary = CveSummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 5,
            total_count: 5,
            open_cves: vec![],
        };

        // critical threshold: only critical > 0 fails
        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert!(violations.is_empty());

        // high threshold: critical=0 ok, high=0 ok
        let violations = evaluate_cve_thresholds(&summary, "high", true);
        assert!(violations.is_empty());

        // medium threshold: critical=0 ok, high=0 ok, medium=0 ok
        let violations = evaluate_cve_thresholds(&summary, "medium", false);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_cve_threshold_case_insensitive() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 1,
            open_cves: vec![],
        };

        // The function uses .to_lowercase() on max_severity
        let violations = evaluate_cve_thresholds(&summary, "CRITICAL", true);
        assert_eq!(violations.len(), 1);

        let violations = evaluate_cve_thresholds(&summary, "Critical", true);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_cve_threshold_violation_details_include_block_on_fail() {
        let summary = CveSummary {
            critical_count: 5,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 5,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert_eq!(violations.len(), 1);
        let details = violations[0].details.as_ref().unwrap();
        assert_eq!(details["count"], 5);
        assert_eq!(details["max_allowed"], 0);
        assert_eq!(details["block_on_fail"], true);

        let violations = evaluate_cve_thresholds(&summary, "critical", false);
        let details = violations[0].details.as_ref().unwrap();
        assert_eq!(details["block_on_fail"], false);
    }

    #[test]
    fn test_cve_threshold_violation_rule_name() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 1,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert_eq!(violations[0].rule, "cve-severity-threshold");
        assert_eq!(violations[0].severity, "critical");
    }

    #[test]
    fn test_cve_threshold_high_message_formatting() {
        let summary = CveSummary {
            critical_count: 0,
            high_count: 3,
            medium_count: 0,
            low_count: 0,
            total_count: 3,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "high", true);
        assert_eq!(violations.len(), 1);
        // "high" severity gets special message formatting "high severity"
        assert!(violations[0].message.contains("high severity"));
    }

    #[test]
    fn test_cve_threshold_critical_message_formatting() {
        let summary = CveSummary {
            critical_count: 2,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 2,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert_eq!(violations.len(), 1);
        // "critical" does not get the "high severity" special formatting
        assert!(violations[0].message.contains("critical"));
        assert!(!violations[0].message.contains("critical severity"));
    }

    #[test]
    fn test_cve_threshold_critical_only_checks_critical() {
        // "critical" threshold: (0, i32::MAX, i32::MAX)
        // Only critical CVEs cause violations
        let summary = CveSummary {
            critical_count: 0,
            high_count: 100,
            medium_count: 200,
            low_count: 300,
            total_count: 600,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert!(violations.is_empty());
    }

    // =======================================================================
    // evaluate_license_policy tests
    // =======================================================================

    #[test]
    fn test_license_policy_evaluation() {
        let summary = LicenseSummary {
            licenses_found: vec![
                "MIT".to_string(),
                "GPL-3.0".to_string(),
                "Apache-2.0".to_string(),
            ],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "test-policy".to_string(),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("GPL-3.0"));
    }

    #[test]
    fn test_license_policy_no_violations_all_allowed() {
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "permissive".to_string(),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            allow_unknown: false,
            action: PolicyAction::Allow,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_license_policy_denied_takes_precedence_over_allowed() {
        // MIT is in both allowed and denied lists; denied should win
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "contradictory".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["MIT".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "license-compliance");
        assert!(violations[0].message.contains("denied"));
    }

    #[test]
    fn test_license_policy_unknown_license_not_in_allowed_list() {
        let summary = LicenseSummary {
            licenses_found: vec!["BSD-3-Clause".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "strict".to_string(),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            allow_unknown: false,
            action: PolicyAction::Warn,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("not in allowed list"));
        assert!(violations[0].message.contains("BSD-3-Clause"));
        assert_eq!(violations[0].severity, "medium");
    }

    #[test]
    fn test_license_policy_allow_unknown_permits_unlisted() {
        let summary = LicenseSummary {
            licenses_found: vec!["BSD-3-Clause".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "lenient".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec![],
            allow_unknown: true,
            action: PolicyAction::Warn,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_license_policy_empty_allowed_list_skips_unknown_check() {
        // When allowed_licenses is empty, the code has a guard:
        // !policy.allowed_licenses.is_empty() && ...
        // So no unknown violation should be produced.
        let summary = LicenseSummary {
            licenses_found: vec!["WhateverLicense".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "no-allowed-list".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec![],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_license_policy_case_insensitive_matching() {
        let summary = LicenseSummary {
            licenses_found: vec!["mit".to_string(), "gpl-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "case-test".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        // "mit" matches "MIT" via to_uppercase(), "gpl-3.0" matches "GPL-3.0"
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("denied"));
    }

    #[test]
    fn test_license_policy_severity_maps_to_action() {
        let summary = LicenseSummary {
            licenses_found: vec!["AGPL-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        // Block action => "critical" severity
        let policy_block = LicensePolicyConfig {
            name: "block-policy".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };
        let violations = evaluate_license_policy(&summary, &policy_block);
        assert_eq!(violations[0].severity, "critical");

        // Warn action => "medium" severity
        let policy_warn = LicensePolicyConfig {
            name: "warn-policy".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Warn,
        };
        let violations = evaluate_license_policy(&summary, &policy_warn);
        assert_eq!(violations[0].severity, "medium");

        // Allow action => "low" severity
        let policy_allow = LicensePolicyConfig {
            name: "allow-policy".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Allow,
        };
        let violations = evaluate_license_policy(&summary, &policy_allow);
        assert_eq!(violations[0].severity, "low");
    }

    #[test]
    fn test_license_policy_details_include_policy_name() {
        let summary = LicenseSummary {
            licenses_found: vec!["GPL-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "corporate-policy".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        let details = violations[0].details.as_ref().unwrap();
        assert_eq!(details["policy_name"], "corporate-policy");
        let denied = details["denied_licenses"].as_array().unwrap();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0], "GPL-3.0");
    }

    #[test]
    fn test_license_policy_multiple_denied_and_unknown() {
        let summary = LicenseSummary {
            licenses_found: vec![
                "MIT".to_string(),
                "GPL-3.0".to_string(),
                "AGPL-3.0".to_string(),
                "WTFPL".to_string(),
                "Unlicense".to_string(),
            ],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "multi".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        // 2 denied licenses => 1 denied violation
        // WTFPL and Unlicense not in allowed list => 1 unknown violation
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].rule, "license-compliance");
        assert!(violations[0].message.contains("2 denied"));
        assert_eq!(violations[1].rule, "license-compliance");
        assert!(violations[1]
            .message
            .contains("2 licenses not in allowed list"));
    }

    #[test]
    fn test_license_policy_no_licenses_found() {
        let summary = LicenseSummary {
            licenses_found: vec![],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            name: "empty".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert!(violations.is_empty());
    }

    // =======================================================================
    // Data model serialization tests
    // =======================================================================

    #[test]
    fn test_policy_violation_serialization() {
        let violation = PolicyViolation {
            rule: "cve-severity-threshold".to_string(),
            severity: "critical".to_string(),
            message: "Found 5 critical vulnerabilities".to_string(),
            details: Some(serde_json::json!({"count": 5})),
        };

        let json = serde_json::to_value(&violation).unwrap();
        assert_eq!(json["rule"], "cve-severity-threshold");
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["details"]["count"], 5);
    }

    #[test]
    fn test_policy_violation_without_details() {
        let violation = PolicyViolation {
            rule: "test-rule".to_string(),
            severity: "low".to_string(),
            message: "test".to_string(),
            details: None,
        };

        let json = serde_json::to_value(&violation).unwrap();
        assert!(json["details"].is_null());
    }

    #[test]
    fn test_policy_evaluation_result_passed() {
        let result = PolicyEvaluationResult {
            passed: true,
            action: PolicyAction::Allow,
            violations: vec![],
            cve_summary: None,
            license_summary: None,
        };

        assert!(result.passed);
        assert!(result.violations.is_empty());
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["passed"], true);
    }

    #[test]
    fn test_policy_evaluation_result_failed() {
        let result = PolicyEvaluationResult {
            passed: false,
            action: PolicyAction::Block,
            violations: vec![PolicyViolation {
                rule: "cve-severity-threshold".to_string(),
                severity: "critical".to_string(),
                message: "Found critical CVEs".to_string(),
                details: None,
            }],
            cve_summary: Some(CveSummary {
                critical_count: 3,
                high_count: 1,
                medium_count: 0,
                low_count: 0,
                total_count: 4,
                open_cves: vec!["CVE-2024-0001".to_string()],
            }),
            license_summary: None,
        };

        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.cve_summary.as_ref().unwrap().critical_count, 3);
    }

    #[test]
    fn test_cve_summary_serialization_roundtrip() {
        let summary = CveSummary {
            critical_count: 2,
            high_count: 5,
            medium_count: 10,
            low_count: 20,
            total_count: 37,
            open_cves: vec!["CVE-2024-1234".to_string(), "CVE-2024-5678".to_string()],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: CveSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.critical_count, 2);
        assert_eq!(parsed.high_count, 5);
        assert_eq!(parsed.medium_count, 10);
        assert_eq!(parsed.low_count, 20);
        assert_eq!(parsed.total_count, 37);
        assert_eq!(parsed.open_cves.len(), 2);
    }

    #[test]
    fn test_license_summary_serialization_roundtrip() {
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            unknown_licenses: vec!["CustomLicense".to_string()],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: LicenseSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.licenses_found.len(), 2);
        assert_eq!(parsed.denied_licenses.len(), 1);
        assert_eq!(parsed.unknown_licenses.len(), 1);
    }

    #[test]
    fn test_policy_action_serialization() {
        let result = PolicyEvaluationResult {
            passed: true,
            action: PolicyAction::Warn,
            violations: vec![],
            cve_summary: None,
            license_summary: None,
        };

        let json = serde_json::to_value(&result).unwrap();
        // PolicyAction should serialize to its string form
        assert!(json["action"].is_string());
    }

    // =======================================================================
    // evaluate_age_gates tests
    // =======================================================================

    #[test]
    fn test_age_gates_no_constraints() {
        let created = chrono::Utc::now() - chrono::Duration::hours(1);
        let violations = evaluate_age_gates(created, None, None);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_age_gates_min_staging_hours_passes() {
        let created = chrono::Utc::now() - chrono::Duration::hours(25);
        let violations = evaluate_age_gates(created, Some(24), None);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_age_gates_min_staging_hours_fails() {
        let created = chrono::Utc::now() - chrono::Duration::hours(2);
        let violations = evaluate_age_gates(created, Some(24), None);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "min-staging-time");
        assert_eq!(violations[0].severity, "high");
        assert!(violations[0].message.contains("minimum: 24 hours"));
    }

    #[test]
    fn test_age_gates_max_artifact_age_passes() {
        let created = chrono::Utc::now() - chrono::Duration::days(5);
        let violations = evaluate_age_gates(created, None, Some(30));
        assert!(violations.is_empty());
    }

    #[test]
    fn test_age_gates_max_artifact_age_fails() {
        let created = chrono::Utc::now() - chrono::Duration::days(60);
        let violations = evaluate_age_gates(created, None, Some(30));
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "max-artifact-age");
        assert_eq!(violations[0].severity, "medium");
        assert!(violations[0].message.contains("maximum: 30 days"));
    }

    #[test]
    fn test_age_gates_both_constraints_both_fail() {
        let created = chrono::Utc::now() - chrono::Duration::days(60);
        let violations = evaluate_age_gates(created, Some(2000), Some(30));
        // Too old (60 > 30 days) but also not in staging long enough (60 days < 2000 hours)
        assert_eq!(violations.len(), 2);
        let rules: Vec<&str> = violations.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&"min-staging-time"));
        assert!(rules.contains(&"max-artifact-age"));
    }

    #[test]
    fn test_age_gates_both_constraints_pass() {
        let created = chrono::Utc::now() - chrono::Duration::days(5);
        let violations = evaluate_age_gates(created, Some(24), Some(30));
        assert!(violations.is_empty());
    }

    #[test]
    fn test_age_gates_min_staging_boundary() {
        // Exactly at the boundary should pass (>= not >)
        let created = chrono::Utc::now() - chrono::Duration::hours(24);
        let violations = evaluate_age_gates(created, Some(24), None);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_age_gates_max_age_boundary() {
        // Exactly at the boundary should pass (<= not <)
        let created = chrono::Utc::now() - chrono::Duration::days(30);
        let violations = evaluate_age_gates(created, None, Some(30));
        assert!(violations.is_empty());
    }

    #[test]
    fn test_age_gates_details_include_values() {
        let created = chrono::Utc::now() - chrono::Duration::hours(2);
        let violations = evaluate_age_gates(created, Some(24), None);
        let details = violations[0].details.as_ref().unwrap();
        assert_eq!(details["min_staging_hours"], 24);
        assert!(details["hours_in_staging"].as_i64().unwrap() < 24);
    }

    // =======================================================================
    // evaluate_signature_requirement tests
    // =======================================================================

    #[test]
    fn test_signature_requirement_has_signature() {
        let violations = evaluate_signature_requirement(true);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_signature_requirement_no_signature() {
        let violations = evaluate_signature_requirement(false);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "require-signature");
        assert_eq!(violations[0].severity, "high");
        assert!(violations[0]
            .message
            .contains("does not have a valid signature"));
    }

    // =======================================================================
    // escalate_action_by_severity tests
    // =======================================================================

    #[test]
    fn test_escalate_action_by_severity_critical_always_blocks() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, "critical"),
            PolicyAction::Block
        );
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Warn, "critical"),
            PolicyAction::Block
        );
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Block, "critical"),
            PolicyAction::Block
        );
    }

    #[test]
    fn test_escalate_action_by_severity_high_always_blocks() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, "high"),
            PolicyAction::Block
        );
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Warn, "high"),
            PolicyAction::Block
        );
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Block, "high"),
            PolicyAction::Block
        );
    }

    #[test]
    fn test_escalate_action_by_severity_medium_escalates_to_warn() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, "medium"),
            PolicyAction::Warn
        );
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Warn, "medium"),
            PolicyAction::Warn
        );
    }

    #[test]
    fn test_escalate_action_by_severity_medium_does_not_downgrade_block() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Block, "medium"),
            PolicyAction::Block
        );
    }

    #[test]
    fn test_escalate_action_by_severity_low_escalates_to_warn() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, "low"),
            PolicyAction::Warn
        );
    }

    #[test]
    fn test_escalate_action_by_severity_low_does_not_downgrade_block() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Block, "low"),
            PolicyAction::Block
        );
    }

    #[test]
    fn test_escalate_action_by_severity_unknown_severity_escalates_to_warn() {
        // Any severity string that is not "critical" or "high" follows the else branch
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, "unknown"),
            PolicyAction::Warn
        );
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, ""),
            PolicyAction::Warn
        );
    }

    // =======================================================================
    // escalate_action_by_policy tests
    // =======================================================================

    #[test]
    fn test_escalate_action_by_policy_block_always_wins() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Allow, &PolicyAction::Block),
            PolicyAction::Block
        );
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Warn, &PolicyAction::Block),
            PolicyAction::Block
        );
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Block, &PolicyAction::Block),
            PolicyAction::Block
        );
    }

    #[test]
    fn test_escalate_action_by_policy_warn_escalates_from_allow() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Allow, &PolicyAction::Warn),
            PolicyAction::Warn
        );
    }

    #[test]
    fn test_escalate_action_by_policy_warn_keeps_warn() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Warn, &PolicyAction::Warn),
            PolicyAction::Warn
        );
    }

    #[test]
    fn test_escalate_action_by_policy_warn_does_not_downgrade_block() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Block, &PolicyAction::Warn),
            PolicyAction::Block
        );
    }

    #[test]
    fn test_escalate_action_by_policy_allow_preserves_current() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Allow, &PolicyAction::Allow),
            PolicyAction::Allow
        );
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Warn, &PolicyAction::Allow),
            PolicyAction::Warn
        );
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Block, &PolicyAction::Allow),
            PolicyAction::Block
        );
    }

    // =======================================================================
    // collect_with_severity_escalation tests
    // =======================================================================

    #[test]
    fn test_collect_with_severity_escalation_empty_input() {
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;
        collect_with_severity_escalation(&mut violations, &mut action, vec![]);
        assert!(violations.is_empty());
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn test_collect_with_severity_escalation_single_critical() {
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;
        let new = vec![PolicyViolation {
            rule: "test".to_string(),
            severity: "critical".to_string(),
            message: "critical issue".to_string(),
            details: None,
        }];
        collect_with_severity_escalation(&mut violations, &mut action, new);
        assert_eq!(violations.len(), 1);
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn test_collect_with_severity_escalation_single_medium() {
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;
        let new = vec![PolicyViolation {
            rule: "test".to_string(),
            severity: "medium".to_string(),
            message: "medium issue".to_string(),
            details: None,
        }];
        collect_with_severity_escalation(&mut violations, &mut action, new);
        assert_eq!(violations.len(), 1);
        assert_eq!(action, PolicyAction::Warn);
    }

    #[test]
    fn test_collect_with_severity_escalation_mixed_severities() {
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;
        let new = vec![
            PolicyViolation {
                rule: "rule-1".to_string(),
                severity: "low".to_string(),
                message: "low issue".to_string(),
                details: None,
            },
            PolicyViolation {
                rule: "rule-2".to_string(),
                severity: "medium".to_string(),
                message: "medium issue".to_string(),
                details: None,
            },
            PolicyViolation {
                rule: "rule-3".to_string(),
                severity: "high".to_string(),
                message: "high issue".to_string(),
                details: None,
            },
        ];
        collect_with_severity_escalation(&mut violations, &mut action, new);
        assert_eq!(violations.len(), 3);
        // After processing low -> Warn, medium -> Warn (already), high -> Block
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn test_collect_with_severity_escalation_appends_to_existing() {
        let mut violations = vec![PolicyViolation {
            rule: "existing".to_string(),
            severity: "low".to_string(),
            message: "pre-existing violation".to_string(),
            details: None,
        }];
        let mut action = PolicyAction::Warn;
        let new = vec![PolicyViolation {
            rule: "new".to_string(),
            severity: "medium".to_string(),
            message: "new violation".to_string(),
            details: None,
        }];
        collect_with_severity_escalation(&mut violations, &mut action, new);
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].rule, "existing");
        assert_eq!(violations[1].rule, "new");
        // medium with current=Warn stays Warn
        assert_eq!(action, PolicyAction::Warn);
    }

    #[test]
    fn test_collect_with_severity_escalation_does_not_downgrade() {
        let mut violations = Vec::new();
        let mut action = PolicyAction::Block;
        let new = vec![PolicyViolation {
            rule: "test".to_string(),
            severity: "low".to_string(),
            message: "low issue".to_string(),
            details: None,
        }];
        collect_with_severity_escalation(&mut violations, &mut action, new);
        assert_eq!(violations.len(), 1);
        // Block should not be downgraded by a low severity violation
        assert_eq!(action, PolicyAction::Block);
    }

    // =======================================================================
    // evaluate_cves_against_policy tests
    // =======================================================================

    #[test]
    fn test_evaluate_cves_with_scan_policy() {
        let summary = CveSummary {
            critical_count: 2,
            high_count: 3,
            medium_count: 0,
            low_count: 0,
            total_count: 5,
            open_cves: vec!["CVE-2025-001".to_string()],
        };
        let scan_policy = ScanPolicyConfig {
            max_severity: "high".to_string(),
            block_on_fail: true,
            min_staging_hours: None,
            max_artifact_age_days: None,
            require_signature: false,
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_cves_against_policy(&summary, Some(&scan_policy), &mut violations, &mut action);

        // "high" threshold: max_critical=0, max_high=0
        // critical_count=2 > 0, high_count=3 > 0 => 2 violations
        assert_eq!(violations.len(), 2);
        // Both critical and high are >= "high" severity, so action should be Block
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn test_evaluate_cves_with_scan_policy_no_violations() {
        let summary = CveSummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 5,
            low_count: 10,
            total_count: 15,
            open_cves: vec![],
        };
        let scan_policy = ScanPolicyConfig {
            max_severity: "critical".to_string(),
            block_on_fail: false,
            min_staging_hours: None,
            max_artifact_age_days: None,
            require_signature: false,
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_cves_against_policy(&summary, Some(&scan_policy), &mut violations, &mut action);

        assert!(violations.is_empty());
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn test_evaluate_cves_default_policy_blocks_on_critical() {
        let summary = CveSummary {
            critical_count: 3,
            high_count: 10,
            medium_count: 20,
            low_count: 30,
            total_count: 63,
            open_cves: vec!["CVE-2025-100".to_string(), "CVE-2025-101".to_string()],
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_cves_against_policy(&summary, None, &mut violations, &mut action);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "default-cve-policy");
        assert_eq!(violations[0].severity, "critical");
        assert!(violations[0].message.contains("3 critical"));
        assert_eq!(action, PolicyAction::Block);

        // Check that details include the open CVEs
        let details = violations[0].details.as_ref().unwrap();
        let cves = details["cves"].as_array().unwrap();
        assert_eq!(cves.len(), 2);
    }

    #[test]
    fn test_evaluate_cves_default_policy_ignores_non_critical() {
        let summary = CveSummary {
            critical_count: 0,
            high_count: 50,
            medium_count: 100,
            low_count: 200,
            total_count: 350,
            open_cves: vec![],
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_cves_against_policy(&summary, None, &mut violations, &mut action);

        // Default policy only cares about critical CVEs
        assert!(violations.is_empty());
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn test_evaluate_cves_against_policy_preserves_existing_violations() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 1,
            open_cves: vec![],
        };
        let mut violations = vec![PolicyViolation {
            rule: "pre-existing".to_string(),
            severity: "low".to_string(),
            message: "already here".to_string(),
            details: None,
        }];
        let mut action = PolicyAction::Warn;

        evaluate_cves_against_policy(&summary, None, &mut violations, &mut action);

        // Should have the pre-existing + the new default-cve-policy violation
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].rule, "pre-existing");
        assert_eq!(violations[1].rule, "default-cve-policy");
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn test_evaluate_cves_with_medium_threshold_policy() {
        let summary = CveSummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 5,
            low_count: 0,
            total_count: 5,
            open_cves: vec![],
        };
        let scan_policy = ScanPolicyConfig {
            max_severity: "medium".to_string(),
            block_on_fail: true,
            min_staging_hours: None,
            max_artifact_age_days: None,
            require_signature: false,
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_cves_against_policy(&summary, Some(&scan_policy), &mut violations, &mut action);

        // "medium" threshold: (0, 0, 0) - medium_count=5 > 0 => violation
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, "medium");
        // medium severity escalates to Warn (not Block)
        assert_eq!(action, PolicyAction::Warn);
    }

    // =======================================================================
    // evaluate_licenses_against_policy tests
    // =======================================================================

    #[test]
    fn test_evaluate_licenses_against_policy_denied_license_with_block() {
        let summary = LicenseSummary {
            licenses_found: vec!["GPL-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };
        let policy = LicensePolicyConfig {
            name: "strict".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_licenses_against_policy(&summary, &policy, &mut violations, &mut action);

        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("denied"));
        // Policy action is Block, so escalate_action_by_policy should set Block
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn test_evaluate_licenses_against_policy_denied_license_with_warn() {
        let summary = LicenseSummary {
            licenses_found: vec!["GPL-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };
        let policy = LicensePolicyConfig {
            name: "lenient".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Warn,
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_licenses_against_policy(&summary, &policy, &mut violations, &mut action);

        assert_eq!(violations.len(), 1);
        // Policy action is Warn, current is Allow => escalated to Warn
        assert_eq!(action, PolicyAction::Warn);
    }

    #[test]
    fn test_evaluate_licenses_against_policy_no_violations() {
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };
        let policy = LicensePolicyConfig {
            name: "permissive".to_string(),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            allow_unknown: false,
            action: PolicyAction::Block,
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_licenses_against_policy(&summary, &policy, &mut violations, &mut action);

        assert!(violations.is_empty());
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn test_evaluate_licenses_against_policy_preserves_existing_state() {
        let summary = LicenseSummary {
            licenses_found: vec!["AGPL-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };
        let policy = LicensePolicyConfig {
            name: "test".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Warn,
        };
        let mut violations = vec![PolicyViolation {
            rule: "earlier-rule".to_string(),
            severity: "low".to_string(),
            message: "earlier".to_string(),
            details: None,
        }];
        let mut action = PolicyAction::Block;

        evaluate_licenses_against_policy(&summary, &policy, &mut violations, &mut action);

        // Should append the new violation
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].rule, "earlier-rule");
        assert_eq!(violations[1].rule, "license-compliance");
        // Block should not be downgraded by Warn policy
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn test_evaluate_licenses_against_policy_allow_action_preserves_current() {
        let summary = LicenseSummary {
            licenses_found: vec!["GPL-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };
        let policy = LicensePolicyConfig {
            name: "report-only".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Allow,
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_licenses_against_policy(&summary, &policy, &mut violations, &mut action);

        // Violations are still recorded even with Allow policy
        assert_eq!(violations.len(), 1);
        // Allow policy does not escalate the action
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn test_evaluate_licenses_against_policy_multiple_violations_escalate_once() {
        // Both denied and unknown violations with a Block policy
        let summary = LicenseSummary {
            licenses_found: vec!["GPL-3.0".to_string(), "WTFPL".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };
        let policy = LicensePolicyConfig {
            name: "strict-multi".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        evaluate_licenses_against_policy(&summary, &policy, &mut violations, &mut action);

        // 1 denied (GPL-3.0) + 1 unknown (WTFPL not in allowed list)
        assert_eq!(violations.len(), 2);
        assert_eq!(action, PolicyAction::Block);
    }
}
