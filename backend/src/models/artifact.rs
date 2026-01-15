//! Artifact model.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

/// Artifact entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Artifact {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    pub checksum_md5: Option<String>,
    pub checksum_sha1: Option<String>,
    pub content_type: String,
    pub storage_key: String,
    pub is_deleted: bool,
    pub uploaded_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Artifact metadata (format-specific)
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ArtifactMetadata {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub format: String,
    pub metadata: serde_json::Value,
    pub properties: serde_json::Value,
}

/// Download statistic entry
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct DownloadStatistic {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub user_id: Option<Uuid>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub downloaded_at: DateTime<Utc>,
}
