//! Curation models for package vetting through staging repos.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Recognized `rule_type` values for [`CurationRule`] (#2947).
///
/// - `pattern`: the original glob/version/arch allow-block engine.
/// - `publisher_trust`: publisher reputation evaluation (#2948).
/// - `popularity`: download/adoption-signal evaluation (#2949).
pub const CURATION_RULE_TYPES: [&str; 3] = ["pattern", "publisher_trust", "popularity"];

/// Recognized `scope` values for [`CurationRule`] (#2947).
///
/// - `repository`: attached to one staging repository (`staging_repo_id` set).
/// - `global`: instance-wide baseline policy (`staging_repo_id` is NULL);
///   evaluated for every repository, union-ed with the repo's own rules.
///
/// Invariant: `scope == "global"` ⇔ `staging_repo_id IS NULL`. The service
/// derives `scope` from the presence of `staging_repo_id` at write time so the
/// two can never drift.
pub const CURATION_RULE_SCOPES: [&str; 2] = ["repository", "global"];

/// An explicit rule for package curation.
///
/// `rule_type` selects the evaluation engine (see [`CURATION_RULE_TYPES`]);
/// `config` carries the engine-specific parameters as a JSON object. The
/// legacy `pattern` engine keeps its parameters in the dedicated
/// `package_pattern` / `version_constraint` / `architecture` columns.
/// `scope` records whether the rule is repo-attached or an instance-wide
/// baseline (see [`CURATION_RULE_SCOPES`]).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct CurationRule {
    pub id: Uuid,
    pub staging_repo_id: Option<Uuid>,
    pub package_pattern: String,
    pub version_constraint: String,
    pub architecture: String,
    pub action: String,
    pub priority: i32,
    pub reason: String,
    pub enabled: bool,
    pub rule_type: String,
    pub config: serde_json::Value,
    pub scope: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The outcome a typed curation rule renders for one package (#2947).
///
/// The `String` payload carries the human-readable rationale surfaced to
/// operators (evaluation reason / audit detail).
///
/// - `Allow`: the rule affirmatively passes the package.
/// - `Flag`: the package should be routed to manual review.
/// - `Block`: the package must not be served.
/// - `NotApplicable`: the rule cannot meaningfully judge this package — e.g.
///   a `publisher_trust`/`popularity` rule against a format with no such
///   signal, or a `pattern` rule whose pattern does not match. The evaluator
///   MUST have no effect: the enforcement seam skips it and continues, so a
///   global policy silently passes through everything it cannot judge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurationDecision {
    Allow,
    Flag(String),
    Block(String),
    NotApplicable,
}

/// A package tracked in the curation staging catalog.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct CurationPackage {
    pub id: Uuid,
    pub staging_repo_id: Uuid,
    pub remote_repo_id: Uuid,
    pub format: String,
    pub package_name: String,
    pub version: String,
    pub release: Option<String>,
    pub architecture: Option<String>,
    pub checksum_sha256: Option<String>,
    pub upstream_path: String,
    pub status: String,
    pub evaluated_at: Option<DateTime<Utc>>,
    pub evaluated_by: Option<Uuid>,
    pub evaluation_reason: Option<String>,
    pub rule_id: Option<Uuid>,
    pub metadata: serde_json::Value,
    pub first_seen_at: DateTime<Utc>,
    pub upstream_updated_at: Option<DateTime<Utc>>,
    /// The verbatim `<package type="rpm">…</package>` block this package was
    /// synced from (#2358 RPM Phase-3). Retained so a curated snapshot publish
    /// can re-emit an upstream-faithful `primary.xml`. `NULL` for rows synced
    /// before this column existed (they must be re-synced before a publish can
    /// include them — the publish path fails closed on a missing snippet) and
    /// for non-RPM formats.
    pub primary_xml_snippet: Option<String>,
}
