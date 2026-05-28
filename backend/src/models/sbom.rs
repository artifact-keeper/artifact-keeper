//! SBOM (Software Bill of Materials) models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// SBOM format types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SbomFormat {
    CycloneDX,
    SPDX,
}

impl SbomFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            SbomFormat::CycloneDX => "cyclonedx",
            SbomFormat::SPDX => "spdx",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cyclonedx" | "cdx" => Some(SbomFormat::CycloneDX),
            "spdx" => Some(SbomFormat::SPDX),
            _ => None,
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            SbomFormat::CycloneDX => "application/vnd.cyclonedx+json",
            SbomFormat::SPDX => "application/spdx+json",
        }
    }
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// SBOM document stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SbomDocument {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub repository_id: Uuid,

    pub format: String,
    pub format_version: String,
    pub spec_version: Option<String>,

    pub content: serde_json::Value,

    pub component_count: i32,
    pub dependency_count: i32,
    pub license_count: i32,

    pub licenses: Vec<String>,

    pub content_hash: String,

    pub generator: Option<String>,
    pub generator_version: Option<String>,

    pub generated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// SBOM component extracted from an SBOM document.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SbomComponent {
    pub id: Uuid,
    pub sbom_id: Uuid,

    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,

    pub component_type: Option<String>,

    pub licenses: Vec<String>,

    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,

    pub supplier: Option<String>,
    pub author: Option<String>,

    pub external_refs: serde_json::Value,

    pub created_at: DateTime<Utc>,
}

/// CVE history entry for tracking vulnerability timeline.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct CveHistoryEntry {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub sbom_id: Option<Uuid>,
    pub component_id: Option<Uuid>,
    pub scan_result_id: Option<Uuid>,

    pub cve_id: String,

    pub affected_component: Option<String>,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,

    pub severity: Option<String>,
    pub cvss_score: Option<f64>,

    pub cve_published_at: Option<DateTime<Utc>>,
    pub first_detected_at: DateTime<Utc>,
    pub last_detected_at: DateTime<Utc>,

    pub status: String,
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_reason: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// CVE status for tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CveStatus {
    Open,
    Fixed,
    Acknowledged,
    FalsePositive,
}

impl CveStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CveStatus::Open => "open",
            CveStatus::Fixed => "fixed",
            CveStatus::Acknowledged => "acknowledged",
            CveStatus::FalsePositive => "false_positive",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "open" => Some(CveStatus::Open),
            "fixed" => Some(CveStatus::Fixed),
            "acknowledged" => Some(CveStatus::Acknowledged),
            "false_positive" => Some(CveStatus::FalsePositive),
            _ => None,
        }
    }
}

/// Policy action for license violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Warn,
    Block,
}

impl PolicyAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyAction::Allow => "allow",
            PolicyAction::Warn => "warn",
            PolicyAction::Block => "block",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "allow" => Some(PolicyAction::Allow),
            "warn" => Some(PolicyAction::Warn),
            "block" => Some(PolicyAction::Block),
            _ => None,
        }
    }
}

/// License policy for a repository or globally.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LicensePolicy {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,

    pub name: String,
    pub description: Option<String>,

    pub allowed_licenses: Vec<String>,
    pub denied_licenses: Vec<String>,

    pub allow_unknown: bool,

    pub action: PolicyAction,

    pub is_enabled: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

// === DTOs for API responses ===

/// Summary of an SBOM for list views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomSummary {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub format: SbomFormat,
    pub format_version: String,
    pub component_count: i32,
    pub dependency_count: i32,
    pub license_count: i32,
    pub licenses: Vec<String>,
    pub generator: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<SbomDocument> for SbomSummary {
    fn from(doc: SbomDocument) -> Self {
        SbomSummary {
            id: doc.id,
            artifact_id: doc.artifact_id,
            format: SbomFormat::parse(&doc.format).unwrap_or(SbomFormat::CycloneDX),
            format_version: doc.format_version,
            component_count: doc.component_count,
            dependency_count: doc.dependency_count,
            license_count: doc.license_count,
            licenses: doc.licenses,
            generator: doc.generator,
            generated_at: doc.generated_at,
            created_at: doc.created_at,
        }
    }
}

/// Request to generate an SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSbomRequest {
    pub artifact_id: Uuid,
    #[serde(default = "default_sbom_format")]
    pub format: String,
    #[serde(default)]
    pub force_regenerate: bool,
}

fn default_sbom_format() -> String {
    "cyclonedx".to_string()
}

/// CVE timeline entry for trending.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CveTimelineEntry {
    pub cve_id: String,
    pub severity: String,
    pub affected_component: String,
    pub cve_published_at: Option<DateTime<Utc>>,
    pub first_detected_at: DateTime<Utc>,
    pub status: CveStatus,
    pub days_exposed: i64,
}

/// CVE trends summary.
///
/// #1446: the security-tests `cve-history` suite probes the trends body for
/// any of `total`, `count`, `critical`, or `high` to confirm the response
/// carries aggregate counts (PR #1385 fixed `cve-history` but the trends
/// shape was not aligned). The original field set (`total_cves`,
/// `critical_count`, ...) is retained for openapi consumers; the bare
/// `total`/`critical`/`high`/`medium`/`low` aliases are added alongside so
/// both shape contracts are satisfied without breaking existing clients.
/// `#[serde(default)]` keeps deserialization working when the alias fields
/// are absent (older payloads, tests that build the struct via field init).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CveTrends {
    pub total_cves: i64,
    pub open_cves: i64,
    pub fixed_cves: i64,
    pub acknowledged_cves: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub avg_days_to_fix: Option<f64>,
    pub timeline: Vec<CveTimelineEntry>,
    /// Alias of `total_cves` (#1446).
    #[serde(default)]
    pub total: i64,
    /// Alias of `critical_count` (#1446).
    #[serde(default)]
    pub critical: i64,
    /// Alias of `high_count` (#1446).
    #[serde(default)]
    pub high: i64,
    /// Alias of `medium_count` (#1446).
    #[serde(default)]
    pub medium: i64,
    /// Alias of `low_count` (#1446).
    #[serde(default)]
    pub low: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SbomFormat
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbom_format_as_str() {
        assert_eq!(SbomFormat::CycloneDX.as_str(), "cyclonedx");
        assert_eq!(SbomFormat::SPDX.as_str(), "spdx");
    }

    #[test]
    fn test_sbom_format_parse_valid() {
        assert_eq!(SbomFormat::parse("cyclonedx"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("cdx"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("spdx"), Some(SbomFormat::SPDX));
    }

    #[test]
    fn test_sbom_format_parse_case_insensitive() {
        assert_eq!(SbomFormat::parse("CycloneDX"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("SPDX"), Some(SbomFormat::SPDX));
        assert_eq!(SbomFormat::parse("CDX"), Some(SbomFormat::CycloneDX));
    }

    #[test]
    fn test_sbom_format_parse_invalid() {
        assert_eq!(SbomFormat::parse("unknown"), None);
        assert_eq!(SbomFormat::parse(""), None);
    }

    #[test]
    fn test_sbom_format_content_type() {
        assert_eq!(
            SbomFormat::CycloneDX.content_type(),
            "application/vnd.cyclonedx+json"
        );
        assert_eq!(SbomFormat::SPDX.content_type(), "application/spdx+json");
    }

    #[test]
    fn test_sbom_format_display() {
        assert_eq!(SbomFormat::CycloneDX.to_string(), "cyclonedx");
        assert_eq!(SbomFormat::SPDX.to_string(), "spdx");
    }

    // -----------------------------------------------------------------------
    // CveStatus
    // -----------------------------------------------------------------------

    #[test]
    fn test_cve_status_as_str() {
        assert_eq!(CveStatus::Open.as_str(), "open");
        assert_eq!(CveStatus::Fixed.as_str(), "fixed");
        assert_eq!(CveStatus::Acknowledged.as_str(), "acknowledged");
        assert_eq!(CveStatus::FalsePositive.as_str(), "false_positive");
    }

    #[test]
    fn test_cve_status_parse_valid() {
        assert_eq!(CveStatus::parse("open"), Some(CveStatus::Open));
        assert_eq!(CveStatus::parse("fixed"), Some(CveStatus::Fixed));
        assert_eq!(
            CveStatus::parse("acknowledged"),
            Some(CveStatus::Acknowledged)
        );
        assert_eq!(
            CveStatus::parse("false_positive"),
            Some(CveStatus::FalsePositive)
        );
    }

    #[test]
    fn test_cve_status_parse_case_insensitive() {
        assert_eq!(CveStatus::parse("OPEN"), Some(CveStatus::Open));
        assert_eq!(CveStatus::parse("Fixed"), Some(CveStatus::Fixed));
    }

    #[test]
    fn test_cve_status_parse_invalid() {
        assert_eq!(CveStatus::parse("unknown"), None);
        assert_eq!(CveStatus::parse(""), None);
    }

    // -----------------------------------------------------------------------
    // PolicyAction
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_action_as_str() {
        assert_eq!(PolicyAction::Allow.as_str(), "allow");
        assert_eq!(PolicyAction::Warn.as_str(), "warn");
        assert_eq!(PolicyAction::Block.as_str(), "block");
    }

    #[test]
    fn test_policy_action_parse_valid() {
        assert_eq!(PolicyAction::parse("allow"), Some(PolicyAction::Allow));
        assert_eq!(PolicyAction::parse("warn"), Some(PolicyAction::Warn));
        assert_eq!(PolicyAction::parse("block"), Some(PolicyAction::Block));
    }

    #[test]
    fn test_policy_action_parse_case_insensitive() {
        assert_eq!(PolicyAction::parse("ALLOW"), Some(PolicyAction::Allow));
        assert_eq!(PolicyAction::parse("Block"), Some(PolicyAction::Block));
    }

    #[test]
    fn test_policy_action_parse_invalid() {
        assert_eq!(PolicyAction::parse("deny"), None);
        assert_eq!(PolicyAction::parse(""), None);
    }

    // -----------------------------------------------------------------------
    // SbomSummary From<SbomDocument>
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbom_summary_from_document() {
        let now = chrono::Utc::now();
        let doc = SbomDocument {
            id: uuid::Uuid::new_v4(),
            artifact_id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            format: "cyclonedx".to_string(),
            format_version: "1.5".to_string(),
            spec_version: Some("1.5".to_string()),
            content: serde_json::json!({}),
            component_count: 42,
            dependency_count: 10,
            license_count: 3,
            licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            content_hash: "abc123".to_string(),
            generator: Some("syft".to_string()),
            generator_version: Some("0.90.0".to_string()),
            generated_at: now,
            created_at: now,
            updated_at: now,
        };

        let summary: SbomSummary = doc.into();
        assert_eq!(summary.format, SbomFormat::CycloneDX);
        assert_eq!(summary.format_version, "1.5");
        assert_eq!(summary.component_count, 42);
        assert_eq!(summary.dependency_count, 10);
        assert_eq!(summary.license_count, 3);
        assert_eq!(summary.licenses.len(), 2);
        assert_eq!(summary.generator.as_deref(), Some("syft"));
    }

    #[test]
    fn test_sbom_summary_from_document_unknown_format_defaults_to_cyclonedx() {
        let now = chrono::Utc::now();
        let doc = SbomDocument {
            id: uuid::Uuid::new_v4(),
            artifact_id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            format: "unknown_format".to_string(),
            format_version: "1.0".to_string(),
            spec_version: None,
            content: serde_json::json!({}),
            component_count: 0,
            dependency_count: 0,
            license_count: 0,
            licenses: vec![],
            content_hash: "".to_string(),
            generator: None,
            generator_version: None,
            generated_at: now,
            created_at: now,
            updated_at: now,
        };

        let summary: SbomSummary = doc.into();
        // Unknown format falls back to CycloneDX
        assert_eq!(summary.format, SbomFormat::CycloneDX);
    }
}
