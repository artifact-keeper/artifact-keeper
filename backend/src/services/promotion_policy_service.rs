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
            if let Some(ref policy) = scan_policy {
                let cve_violations =
                    evaluate_cve_thresholds(summary, &policy.max_severity, policy.block_on_fail);

                for v in cve_violations {
                    if v.severity == "critical" || v.severity == "high" {
                        action = PolicyAction::Block;
                    } else if action != PolicyAction::Block {
                        action = PolicyAction::Warn;
                    }
                    violations.push(v);
                }
            } else if summary.critical_count > 0 {
                // Default policy: block on any critical CVEs
                action = PolicyAction::Block;
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

        if let Some(ref summary) = license_summary {
            if let Some(ref policy) = license_policy {
                let license_violations = evaluate_license_policy(summary, policy);

                for v in license_violations {
                    match policy.action {
                        PolicyAction::Block => action = PolicyAction::Block,
                        PolicyAction::Warn if action != PolicyAction::Block => {
                            action = PolicyAction::Warn
                        }
                        _ => {}
                    }
                    violations.push(v);
                }
            }
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

    async fn get_cve_summary(&self, artifact_id: Uuid) -> Result<Option<CveSummary>> {
        let scan = sqlx::query!(
            r#"
            SELECT
                critical_count, high_count, medium_count, low_count, findings_count
            FROM scan_results
            WHERE artifact_id = $1 AND status = 'completed'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            artifact_id
        )
        .fetch_optional(&self.db)
        .await?;

        let Some(scan) = scan else {
            return Ok(None);
        };

        let cves: Vec<String> = sqlx::query_scalar!(
            r#"SELECT DISTINCT cve_id as "cve_id!" FROM cve_history WHERE artifact_id = $1 AND status = 'open' AND cve_id IS NOT NULL"#,
            artifact_id
        )
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
        let sbom = sqlx::query!(
            r#"
            SELECT licenses
            FROM sbom_documents
            WHERE artifact_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            artifact_id
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(sbom.map(|s| LicenseSummary {
            licenses_found: s.licenses.unwrap_or_default(),
            denied_licenses: vec![],
            unknown_licenses: vec![],
        }))
    }

    async fn get_scan_policy(&self, repository_id: Uuid) -> Result<Option<ScanPolicyConfig>> {
        let policy = sqlx::query!(
            r#"
            SELECT id, name, max_severity, block_unscanned, block_on_fail, is_enabled
            FROM scan_policies
            WHERE (repository_id = $1 OR repository_id IS NULL) AND is_enabled = true
            ORDER BY repository_id DESC NULLS LAST
            LIMIT 1
            "#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(policy.map(|p| ScanPolicyConfig {
            _id: p.id,
            _name: p.name,
            max_severity: p.max_severity,
            _block_unscanned: p.block_unscanned,
            block_on_fail: p.block_on_fail,
        }))
    }

    async fn get_license_policy(&self, repository_id: Uuid) -> Result<Option<LicensePolicyConfig>> {
        let policy = sqlx::query!(
            r#"
            SELECT id, name, allowed_licenses, denied_licenses, allow_unknown, action, is_enabled
            FROM license_policies
            WHERE (repository_id = $1 OR repository_id IS NULL) AND is_enabled = true
            ORDER BY repository_id DESC NULLS LAST
            LIMIT 1
            "#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(policy.map(|p| LicensePolicyConfig {
            _id: p.id,
            name: p.name,
            allowed_licenses: p.allowed_licenses.unwrap_or_default(),
            denied_licenses: p.denied_licenses.unwrap_or_default(),
            allow_unknown: p.allow_unknown,
            action: PolicyAction::parse(&p.action).unwrap_or(PolicyAction::Warn),
        }))
    }
}

#[derive(Debug, Clone)]
struct ScanPolicyConfig {
    _id: Uuid,
    _name: String,
    max_severity: String,
    _block_unscanned: bool,
    block_on_fail: bool,
}

#[derive(Debug, Clone)]
struct LicensePolicyConfig {
    _id: Uuid,
    name: String,
    allowed_licenses: Vec<String>,
    denied_licenses: Vec<String>,
    allow_unknown: bool,
    action: PolicyAction,
}

#[cfg(test)]
mod tests {
    use super::*;

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
            _id: Uuid::new_v4(),
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
}
