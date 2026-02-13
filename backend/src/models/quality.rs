//! Quality gate models: check results, issues, health scores, gates, and evaluations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A single quality check execution record for an artifact.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct QualityCheckResult {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub check_type: String,
    pub status: String,
    pub score: Option<i32>,
    pub passed: Option<bool>,
    pub details: Option<serde_json::Value>,
    pub issues_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub checker_version: Option<String>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// An individual issue found during a quality check.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct QualityCheckIssue {
    pub id: Uuid,
    pub check_result_id: Uuid,
    pub artifact_id: Uuid,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub is_suppressed: bool,
    pub suppressed_by: Option<Uuid>,
    pub suppressed_reason: Option<String>,
    pub suppressed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Materialized health score for a single artifact.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ArtifactHealthScore {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub health_score: i32,
    pub health_grade: String,
    pub security_score: Option<i32>,
    pub license_score: Option<i32>,
    pub quality_score: Option<i32>,
    pub metadata_score: Option<i32>,
    pub total_issues: i32,
    pub critical_issues: i32,
    pub checks_passed: i32,
    pub checks_total: i32,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub calculated_at: DateTime<Utc>,
}

/// Materialized health score for a repository.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RepoHealthScore {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub health_score: i32,
    pub health_grade: String,
    pub avg_security_score: Option<i32>,
    pub avg_license_score: Option<i32>,
    pub avg_quality_score: Option<i32>,
    pub avg_metadata_score: Option<i32>,
    pub artifacts_evaluated: i32,
    pub artifacts_passing: i32,
    pub artifacts_failing: i32,
    pub last_evaluated_at: Option<DateTime<Utc>>,
    pub calculated_at: DateTime<Utc>,
}

/// A quality gate defining thresholds and rules for artifact promotion or download.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct QualityGate {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub min_health_score: Option<i32>,
    pub min_security_score: Option<i32>,
    pub min_quality_score: Option<i32>,
    pub min_metadata_score: Option<i32>,
    pub max_critical_issues: Option<i32>,
    pub max_high_issues: Option<i32>,
    pub max_medium_issues: Option<i32>,
    pub required_checks: Vec<String>,
    pub enforce_on_promotion: bool,
    pub enforce_on_download: bool,
    pub action: String,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A raw issue produced by a quality checker before it is persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawQualityIssue {
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
}

/// Output returned from a `QualityChecker::check()` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCheckOutput {
    pub score: i32,
    pub passed: bool,
    pub issues: Vec<RawQualityIssue>,
    pub details: serde_json::Value,
}

/// Result of evaluating an artifact against a quality gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateEvaluation {
    pub passed: bool,
    pub action: String,
    pub gate_name: String,
    pub health_score: i32,
    pub health_grade: String,
    pub violations: Vec<QualityGateViolation>,
    pub component_scores: ComponentScores,
}

/// A single rule violation detected during quality gate evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateViolation {
    pub rule: String,
    pub expected: String,
    pub actual: String,
    pub message: String,
}

/// Component-level scores used in health score calculation and gate evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentScores {
    pub security: Option<i32>,
    pub license: Option<i32>,
    pub quality: Option<i32>,
    pub metadata: Option<i32>,
}
