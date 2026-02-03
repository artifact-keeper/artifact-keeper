//! Peer connection model for mesh peer discovery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Peer connection status enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "peer_status", rename_all = "lowercase")]
pub enum PeerStatus {
    Active,
    Probing,
    Unreachable,
    Disabled,
}

/// Peer connection entity for mesh topology tracking.
///
/// Represents a unidirectional link from source to target node
/// with measured network metrics used for peer scoring during
/// swarm-based chunk distribution.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PeerConnection {
    pub id: Uuid,
    pub source_peer_id: Uuid,
    pub target_peer_id: Uuid,
    pub status: PeerStatus,
    pub latency_ms: Option<i32>,
    pub bandwidth_estimate_bps: Option<i64>,
    pub shared_artifacts_count: i32,
    pub shared_chunks_count: i32,
    pub last_probed_at: Option<DateTime<Utc>>,
    pub last_transfer_at: Option<DateTime<Utc>>,
    pub bytes_transferred_total: i64,
    pub transfer_success_count: i32,
    pub transfer_failure_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
