//! Edge node model for distributed caching.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Edge node status enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "edge_status", rename_all = "lowercase")]
pub enum EdgeStatus {
    Online,
    Offline,
    Syncing,
    Degraded,
}

/// Edge node entity for distributed artifact caching.
///
/// Edge nodes are deployed in different regions to provide
/// low-latency artifact access for geographically distributed teams.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct EdgeNode {
    pub id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub status: EdgeStatus,
    pub region: Option<String>,
    pub cache_size_bytes: i64,
    pub cache_used_bytes: i64,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub sync_filter: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Edge repository assignment entity.
///
/// Associates repositories with edge nodes for selective syncing.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct EdgeRepoAssignment {
    pub id: Uuid,
    pub edge_node_id: Uuid,
    pub repository_id: Uuid,
    pub sync_enabled: bool,
    pub created_at: DateTime<Utc>,
}
