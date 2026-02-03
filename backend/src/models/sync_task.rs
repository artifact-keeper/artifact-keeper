//! Sync task model for peer instance synchronization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Sync task status enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "sync_status", rename_all = "lowercase")]
pub enum SyncStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Sync task entity for artifact replication to peer instances.
///
/// Each sync task represents a single artifact that needs to be
/// synchronized to a peer instance.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SyncTask {
    pub id: Uuid,
    pub peer_instance_id: Uuid,
    pub artifact_id: Uuid,
    pub status: SyncStatus,
    pub priority: i32,
    pub bytes_transferred: i64,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Peer cache entry entity.
///
/// Tracks artifacts cached on peer instances for LRU eviction
/// and access statistics.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PeerCacheEntry {
    pub id: Uuid,
    pub peer_instance_id: Uuid,
    pub artifact_id: Uuid,
    pub size_bytes: i64,
    pub last_accessed_at: DateTime<Utc>,
    pub access_count: i64,
    pub created_at: DateTime<Utc>,
}
