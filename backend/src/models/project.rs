//! Project model (#2472).
//!
//! A project is a metadata grouping of repositories. Membership grants live
//! in the existing `permissions` table under `target_type = 'project'`, so a
//! grant on a project is inherited by every repository assigned to it (see
//! `repository_service::permissions_grant_exists` for the read plane and
//! `permission_service` for the write plane).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// Project entity.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize, ToSchema)]
pub struct Project {
    pub id: Uuid,
    /// Unique, URL-safe project key (e.g. "payments").
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    /// Storage quota in bytes. P1: stored only, NOT enforced (quotas = P3).
    pub quota_bytes: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
