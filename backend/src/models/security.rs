//! Security scanning models: configs, results, findings, scores, and policies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Type of scan performed on an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    Dependency,
    Image,
    License,
    Malware,
}

/// Current status of a scan execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

/// Severity of a finding. Ordered from most severe to least.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4,
}

impl Severity {
    /// Penalty weight used in security score calculation.
    pub fn penalty_weight(self) -> i32 {
        match self {
            Severity::Critical => 25,
            Severity::High => 10,
            Severity::Medium => 3,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }

    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "moderate" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" | "informational" | "none" => Some(Severity::Info),
            _ => None,
        }
    }

    /// Returns true if this severity is at or above the given threshold.
    pub fn meets_threshold(self, threshold: Severity) -> bool {
        self <= threshold
    }
}

/// Quarantine status for artifacts fetched via proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum QuarantineStatus {
    Unscanned,
    Clean,
    Flagged,
}

/// Security grade derived from numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    pub fn from_score(score: i32) -> Self {
        match score {
            90..=100 => Grade::A,
            75..=89 => Grade::B,
            50..=74 => Grade::C,
            25..=49 => Grade::D,
            _ => Grade::F,
        }
    }

    pub fn as_char(self) -> char {
        match self {
            Grade::A => 'A',
            Grade::B => 'B',
            Grade::C => 'C',
            Grade::D => 'D',
            Grade::F => 'F',
        }
    }
}

// ---------------------------------------------------------------------------
// Database row structs
// ---------------------------------------------------------------------------

/// Per-repository scan configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanConfig {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub scan_enabled: bool,
    pub scan_on_upload: bool,
    pub scan_on_proxy: bool,
    pub block_on_policy_violation: bool,
    pub severity_threshold: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ScanConfig {
    /// Parse the severity_threshold field into a Severity enum.
    pub fn threshold(&self) -> Severity {
        Severity::from_str_loose(&self.severity_threshold).unwrap_or(Severity::High)
    }
}

/// A single scan execution record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub scan_type: String,
    pub status: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub scanner_version: Option<String>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// An individual vulnerability finding within a scan.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanFinding {
    pub id: Uuid,
    pub scan_result_id: Uuid,
    pub artifact_id: Uuid,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub cve_id: Option<String>,
    pub affected_component: Option<String>,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,
    pub source: Option<String>,
    pub source_url: Option<String>,
    pub is_acknowledged: bool,
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_reason: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Materialized security score for a repository.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RepoSecurityScore {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub score: i32,
    pub grade: String,
    pub total_findings: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub acknowledged_count: i32,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub calculated_at: DateTime<Utc>,
}

/// A scan policy that can block downloads based on findings.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanPolicy {
    pub id: Uuid,
    pub name: String,
    pub repository_id: Option<Uuid>,
    pub max_severity: String,
    pub block_unscanned: bool,
    pub block_on_fail: bool,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Non-persisted types used by the scanner service
// ---------------------------------------------------------------------------

/// A raw finding produced by a scanner before it is persisted.
#[derive(Debug, Clone, Serialize)]
pub struct RawFinding {
    pub severity: Severity,
    pub title: String,
    pub description: Option<String>,
    pub cve_id: Option<String>,
    pub affected_component: Option<String>,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,
    pub source: Option<String>,
    pub source_url: Option<String>,
}

/// Result of a policy evaluation for an artifact download.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyResult {
    pub allowed: bool,
    pub violations: Vec<String>,
}

/// Summary statistics for the security dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardSummary {
    pub repos_with_scanning: i64,
    pub total_scans: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub policy_violations_blocked: i64,
    pub repos_grade_a: i64,
    pub repos_grade_f: i64,
}
