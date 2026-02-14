//! Promotion rule models for auto-promotion from staging to release.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A rule that defines criteria for auto-promoting artifacts from a source
/// staging repository to a target release repository.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PromotionRule {
    pub id: Uuid,
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
