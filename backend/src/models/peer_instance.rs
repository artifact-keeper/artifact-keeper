//! Peer instance model for distributed caching.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Peer instance status enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "instance_status", rename_all = "lowercase")]
pub enum InstanceStatus {
    Online,
    Offline,
    Syncing,
    Degraded,
}

/// Peer instance entity for distributed artifact caching.
///
/// Peer instances participate in a decentralized mesh network
/// for low-latency artifact access across geographically distributed teams.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PeerInstance {
    pub id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub status: InstanceStatus,
    pub region: Option<String>,
    pub cache_size_bytes: i64,
    pub cache_used_bytes: i64,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub sync_filter: Option<serde_json::Value>,
    pub max_bandwidth_bps: Option<i64>,
    pub sync_window_start: Option<chrono::NaiveTime>,
    pub sync_window_end: Option<chrono::NaiveTime>,
    pub sync_window_timezone: Option<String>,
    pub concurrent_transfers_limit: Option<i32>,
    pub active_transfers: i32,
    pub backoff_until: Option<DateTime<Utc>>,
    pub consecutive_failures: i32,
    pub bytes_transferred_total: i64,
    pub transfer_failures_total: i32,
    pub api_key: String,
    pub is_local: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Peer repository subscription entity.
///
/// Associates repositories with peer instances for selective syncing.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PeerRepoSubscription {
    pub id: Uuid,
    pub peer_instance_id: Uuid,
    pub repository_id: Uuid,
    pub sync_enabled: bool,
    pub replication_mode: Option<String>,
    pub replication_schedule: Option<String>,
    pub last_replicated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
