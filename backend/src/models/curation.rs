//! Curation models for package vetting through staging repos.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An explicit allow/block rule for package curation.
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
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    /// The STRUCTURED, validated primary.xml metadata this package was synced
    /// from (#2358 RPM Phase-3, A-hardened). Stored as JSONB so a curated
    /// snapshot publish re-serializes it CANONICALLY under AK's escaping and
    /// AK-derived `<location>`, instead of re-emitting attacker-influenced
    /// upstream markup. `NULL` for rows synced before this column existed (they
    /// must be re-synced before a publish can include them — the publish path
    /// fails closed on missing metadata) and for non-RPM formats.
    pub primary_metadata: Option<serde_json::Value>,
}
