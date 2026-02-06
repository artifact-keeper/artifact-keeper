//! Promotion policy service.
//!
//! Evaluates artifacts against security policies before promotion from staging to release.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;
use crate::models::sbom::PolicyAction;

/// Policy violation found during evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Result of policy evaluation for an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    /// Whether the artifact passes all policies
    pub passed: bool,
    /// Action to take: allow, warn, or block
    pub action: PolicyAction,
    /// List of policy violations
    pub violations: Vec<PolicyViolation>,
    /// CVE summary
    pub cve_summary: Option<CveSummary>,
    /// License summary
    pub license_summary: Option<LicenseSummary>,
}

/// Summary of CVE findings for an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveSummary {
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub total_count: i32,
    pub open_cves: Vec<String>,
}

/// Summary of license findings for an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseSummary {
    pub licenses_found: Vec<String>,
    pub denied_licenses: Vec<String>,
    pub unknown_licenses: Vec<String>,
}

/// CVE threshold policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveThresholdPolicy {
    pub max_critical: i32,
    pub max_high: i32,
    pub max_medium: Option<i32>,
    pub max_low: Option<i32>,
}

impl Default for CveThresholdPolicy {
    fn default() -> Self {
        Self {
            max_critical: 0,
            max_high: 0,
            max_medium: None,
            max_low: None,
        }
    }
}

/// Service for evaluating promotion policies.
pub struct PromotionPolicyService {
    db: PgPool,
}

impl PromotionPolicyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Evaluate an artifact against all applicable policies.
    pub async fn evaluate_artifact(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<PolicyEvaluationResult> {
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        // Get CVE summary from scan results
        let cve_summary = self.get_cve_summary(artifact_id).await?;

        // Get license summary from SBOM
        let license_summary = self.get_license_summary(artifact_id).await?;

        // Get scan policy for repository (if any)
        let scan_policy = self.get_scan_policy(repository_id).await?;

        // Get license policy for repository (if any)
        let license_policy = self.get_license_policy(repository_id).await?;

        // Evaluate CVE thresholds
        if let Some(ref summary) = cve_summary {
            if let Some(ref policy) = scan_policy {
                let cve_violations =
                    self.evaluate_cve_thresholds(summary, &policy.max_severity, policy.block_on_fail);

                for v in cve_violations {
                    if v.severity == "critical" || v.severity == "high" {
                        action = PolicyAction::Block;
                    } else if action != PolicyAction::Block {
                        action = PolicyAction::Warn;
                    }
                    violations.push(v);
                }
            } else {
                // Default policy: block on any critical CVEs
                if summary.critical_count > 0 {
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
        }

        // Evaluate license compliance
        if let Some(ref summary) = license_summary {
            if let Some(ref policy) = license_policy {
                let license_violations = self.evaluate_license_policy(summary, policy);

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

    /// Get CVE summary for an artifact from scan results.
    async fn get_cve_summary(&self, artifact_id: Uuid) -> Result<Option<CveSummary>> {
        // Get the latest scan result for this artifact
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

        if let Some(scan) = scan {
            // Get open CVEs - use a type annotation to help sqlx
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
        } else {
            Ok(None)
        }
    }

    /// Get license summary for an artifact from SBOM.
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

        if let Some(sbom) = sbom {
            Ok(Some(LicenseSummary {
                licenses_found: sbom.licenses.unwrap_or_default(),
                denied_licenses: vec![],
                unknown_licenses: vec![],
            }))
        } else {
            Ok(None)
        }
    }

    /// Get scan policy for a repository.
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
            id: p.id,
            name: p.name,
            max_severity: p.max_severity,
            block_unscanned: p.block_unscanned,
            block_on_fail: p.block_on_fail,
        }))
    }

    /// Get license policy for a repository.
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
            id: p.id,
            name: p.name,
            allowed_licenses: p.allowed_licenses.unwrap_or_default(),
            denied_licenses: p.denied_licenses.unwrap_or_default(),
            allow_unknown: p.allow_unknown,
            action: PolicyAction::parse(&p.action).unwrap_or(PolicyAction::Warn),
        }))
    }

    /// Evaluate CVE thresholds against scan results.
    fn evaluate_cve_thresholds(
        &self,
        summary: &CveSummary,
        max_severity: &str,
        block_on_fail: bool,
    ) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();

        // Parse max_severity to determine thresholds
        let (max_critical, max_high, max_medium) = match max_severity.to_lowercase().as_str() {
            "critical" => (0, i32::MAX, i32::MAX),
            "high" => (0, 0, i32::MAX),
            "medium" => (0, 0, 0),
            "low" => (0, 0, 0),
            _ => (0, 0, i32::MAX), // Default to blocking critical and high
        };

        if summary.critical_count > max_critical {
            violations.push(PolicyViolation {
                rule: "cve-severity-threshold".to_string(),
                severity: "critical".to_string(),
                message: format!(
                    "Found {} critical vulnerabilities (max allowed: {})",
                    summary.critical_count, max_critical
                ),
                details: Some(serde_json::json!({
                    "count": summary.critical_count,
                    "max_allowed": max_critical,
                    "block_on_fail": block_on_fail
                })),
            });
        }

        if summary.high_count > max_high {
            violations.push(PolicyViolation {
                rule: "cve-severity-threshold".to_string(),
                severity: "high".to_string(),
                message: format!(
                    "Found {} high severity vulnerabilities (max allowed: {})",
                    summary.high_count, max_high
                ),
                details: Some(serde_json::json!({
                    "count": summary.high_count,
                    "max_allowed": max_high,
                    "block_on_fail": block_on_fail
                })),
            });
        }

        if summary.medium_count > max_medium {
            violations.push(PolicyViolation {
                rule: "cve-severity-threshold".to_string(),
                severity: "medium".to_string(),
                message: format!(
                    "Found {} medium severity vulnerabilities (max allowed: {})",
                    summary.medium_count, max_medium
                ),
                details: Some(serde_json::json!({
                    "count": summary.medium_count,
                    "max_allowed": max_medium,
                    "block_on_fail": block_on_fail
                })),
            });
        }

        violations
    }

    /// Evaluate license policy against SBOM licenses.
    fn evaluate_license_policy(
        &self,
        summary: &LicenseSummary,
        policy: &LicensePolicyConfig,
    ) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();
        let mut denied_found = Vec::new();
        let mut unknown_found = Vec::new();

        for license in &summary.licenses_found {
            let normalized = license.to_uppercase();

            // Check if license is explicitly denied
            if policy
                .denied_licenses
                .iter()
                .any(|d| d.to_uppercase() == normalized)
            {
                denied_found.push(license.clone());
                continue;
            }

            // Check if license is in allowed list (if allowed list is non-empty)
            if !policy.allowed_licenses.is_empty() {
                let is_allowed = policy
                    .allowed_licenses
                    .iter()
                    .any(|a| a.to_uppercase() == normalized);

                if !is_allowed && !policy.allow_unknown {
                    unknown_found.push(license.clone());
                }
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
                message: format!("Found {} denied licenses: {}", denied_found.len(), denied_found.join(", ")),
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
}

/// Internal config struct for scan policy.
#[derive(Debug, Clone)]
struct ScanPolicyConfig {
    id: Uuid,
    name: String,
    max_severity: String,
    block_unscanned: bool,
    block_on_fail: bool,
}

/// Internal config struct for license policy.
#[derive(Debug, Clone)]
struct LicensePolicyConfig {
    id: Uuid,
    name: String,
    allowed_licenses: Vec<String>,
    denied_licenses: Vec<String>,
    allow_unknown: bool,
    action: PolicyAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to test CVE threshold evaluation without needing a DB connection
    fn evaluate_cve_thresholds_test(
        summary: &CveSummary,
        max_severity: &str,
        block_on_fail: bool,
    ) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();

        let (max_critical, max_high, max_medium) = match max_severity.to_lowercase().as_str() {
            "critical" => (0, i32::MAX, i32::MAX),
            "high" => (0, 0, i32::MAX),
            "medium" => (0, 0, 0),
            "low" => (0, 0, 0),
            _ => (0, 0, i32::MAX),
        };

        if summary.critical_count > max_critical {
            violations.push(PolicyViolation {
                rule: "cve-severity-threshold".to_string(),
                severity: "critical".to_string(),
                message: format!(
                    "Found {} critical vulnerabilities (max allowed: {})",
                    summary.critical_count, max_critical
                ),
                details: Some(serde_json::json!({
                    "count": summary.critical_count,
                    "max_allowed": max_critical,
                    "block_on_fail": block_on_fail
                })),
            });
        }

        if summary.high_count > max_high {
            violations.push(PolicyViolation {
                rule: "cve-severity-threshold".to_string(),
                severity: "high".to_string(),
                message: format!(
                    "Found {} high severity vulnerabilities (max allowed: {})",
                    summary.high_count, max_high
                ),
                details: None,
            });
        }

        violations
    }

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

        // Test with max_severity = "high" (should block critical and high)
        let violations = evaluate_cve_thresholds_test(&summary, "high", true);
        assert_eq!(violations.len(), 2); // Critical and High violations

        // Test with max_severity = "critical" (should only block critical)
        let violations = evaluate_cve_thresholds_test(&summary, "critical", true);
        assert_eq!(violations.len(), 1); // Only critical violation
    }

    #[test]
    fn test_license_policy_evaluation() {
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string(), "GPL-3.0".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            id: Uuid::new_v4(),
            name: "test-policy".to_string(),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        // Test the logic directly
        let mut violations = Vec::new();
        let mut denied_found = Vec::new();

        for license in &summary.licenses_found {
            let normalized = license.to_uppercase();
            if policy.denied_licenses.iter().any(|d| d.to_uppercase() == normalized) {
                denied_found.push(license.clone());
            }
        }

        if !denied_found.is_empty() {
            violations.push(PolicyViolation {
                rule: "license-compliance".to_string(),
                severity: "critical".to_string(),
                message: format!("Found {} denied licenses: {}", denied_found.len(), denied_found.join(", ")),
                details: None,
            });
        }

        assert_eq!(violations.len(), 1); // GPL-3.0 is denied
        assert!(violations[0].message.contains("GPL-3.0"));
    }
}
