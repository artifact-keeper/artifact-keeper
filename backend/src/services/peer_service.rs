//! Mesh peer discovery and connection management service.
//!
//! Manages the peer graph between peer instances, tracking network metrics
//! for optimal swarm-based artifact distribution.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Peer connection status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "peer_status", rename_all = "lowercase")]
pub enum PeerStatus {
    Active,
    Probing,
    Unreachable,
    Disabled,
}

impl std::fmt::Display for PeerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerStatus::Active => write!(f, "active"),
            PeerStatus::Probing => write!(f, "probing"),
            PeerStatus::Unreachable => write!(f, "unreachable"),
            PeerStatus::Disabled => write!(f, "disabled"),
        }
    }
}

/// Peer connection model
#[derive(Debug)]
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

/// Scored peer for swarm selection
#[derive(Debug, serde::Serialize)]
pub struct ScoredPeer {
    pub node_id: Uuid,
    pub endpoint_url: String,
    pub latency_ms: Option<i32>,
    pub bandwidth_estimate_bps: Option<i64>,
    pub available_chunks: i32,
    pub score: f64,
}

/// Probe result from a peer instance
#[derive(Debug)]
pub struct ProbeResult {
    pub target_peer_id: Uuid,
    pub latency_ms: i32,
    pub bandwidth_estimate_bps: Option<i64>,
}

/// Peer announcement from a remote peer
#[derive(Debug, serde::Deserialize)]
pub struct PeerAnnouncement {
    pub peer_id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub api_key: String,
}

/// Peer service for mesh discovery and management
pub struct PeerService {
    db: PgPool,
}

impl PeerService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// List active peers for a given peer instance.
    pub async fn list_peers(
        &self,
        source_peer_id: Uuid,
        status_filter: Option<PeerStatus>,
    ) -> Result<Vec<PeerConnection>> {
        let peers = sqlx::query_as!(
            PeerConnection,
            r#"
            SELECT
                id, source_peer_id, target_peer_id,
                status as "status: PeerStatus",
                latency_ms, bandwidth_estimate_bps,
                shared_artifacts_count, shared_chunks_count,
                last_probed_at, last_transfer_at,
                bytes_transferred_total, transfer_success_count, transfer_failure_count,
                created_at, updated_at
            FROM peer_connections
            WHERE source_peer_id = $1
              AND ($2::peer_status IS NULL OR status = $2)
            ORDER BY latency_ms ASC NULLS LAST
            "#,
            source_peer_id,
            status_filter as Option<PeerStatus>,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(peers)
    }

    /// Create or update a peer connection with probe results.
    pub async fn upsert_probe_result(
        &self,
        source_peer_id: Uuid,
        result: ProbeResult,
    ) -> Result<PeerConnection> {
        let peer = sqlx::query_as!(
            PeerConnection,
            r#"
            INSERT INTO peer_connections
                (source_peer_id, target_peer_id, status, latency_ms,
                 bandwidth_estimate_bps, last_probed_at)
            VALUES ($1, $2, 'active', $3, $4, NOW())
            ON CONFLICT (source_peer_id, target_peer_id) DO UPDATE
                SET status = 'active', latency_ms = $3,
                    bandwidth_estimate_bps = COALESCE($4, peer_connections.bandwidth_estimate_bps),
                    last_probed_at = NOW(), updated_at = NOW()
            RETURNING
                id, source_peer_id, target_peer_id,
                status as "status: PeerStatus",
                latency_ms, bandwidth_estimate_bps,
                shared_artifacts_count, shared_chunks_count,
                last_probed_at, last_transfer_at,
                bytes_transferred_total, transfer_success_count, transfer_failure_count,
                created_at, updated_at
            "#,
            source_peer_id,
            result.target_peer_id,
            result.latency_ms,
            result.bandwidth_estimate_bps,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(peer)
    }

    /// Mark a peer as unreachable.
    pub async fn mark_unreachable(&self, source_peer_id: Uuid, target_peer_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE peer_connections
            SET status = 'unreachable', updated_at = NOW()
            WHERE source_peer_id = $1 AND target_peer_id = $2
            "#,
            source_peer_id,
            target_peer_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Record a successful transfer from a peer.
    pub async fn record_transfer_success(
        &self,
        source_peer_id: Uuid,
        target_peer_id: Uuid,
        bytes: i64,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE peer_connections
            SET transfer_success_count = transfer_success_count + 1,
                bytes_transferred_total = bytes_transferred_total + $3,
                last_transfer_at = NOW(), updated_at = NOW()
            WHERE source_peer_id = $1 AND target_peer_id = $2
            "#,
            source_peer_id,
            target_peer_id,
            bytes,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Record a failed transfer from a peer.
    pub async fn record_transfer_failure(
        &self,
        source_peer_id: Uuid,
        target_peer_id: Uuid,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE peer_connections
            SET transfer_failure_count = transfer_failure_count + 1,
                updated_at = NOW()
            WHERE source_peer_id = $1 AND target_peer_id = $2
            "#,
            source_peer_id,
            target_peer_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get scored peers for swarm chunk download.
    /// Score = (available_chunks_they_have_that_we_need x bandwidth) / latency
    /// Peers with no latency data get a default penalty score.
    pub async fn get_scored_peers_for_artifact(
        &self,
        requesting_peer_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<Vec<ScoredPeer>> {
        let peers = sqlx::query!(
            r#"
            SELECT
                pc.target_peer_id as node_id,
                pi.endpoint_url,
                pc.latency_ms,
                pc.bandwidth_estimate_bps,
                COALESCE(ca.available_chunks, 0) as "available_chunks!: i32"
            FROM peer_connections pc
            JOIN peer_instances pi ON pi.id = pc.target_peer_id
            LEFT JOIN chunk_availability ca
                ON ca.peer_instance_id = pc.target_peer_id AND ca.artifact_id = $2
            WHERE pc.source_peer_id = $1
              AND pc.status = 'active'
              AND pi.status IN ('online', 'syncing')
            ORDER BY pc.latency_ms ASC NULLS LAST
            "#,
            requesting_peer_id,
            artifact_id,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let scored: Vec<ScoredPeer> = peers
            .into_iter()
            .filter(|p| p.available_chunks > 0)
            .map(|p| {
                let bw = p.bandwidth_estimate_bps.unwrap_or(1_000_000) as f64; // 1Mbps default
                let lat = p.latency_ms.unwrap_or(500) as f64; // 500ms default penalty
                let chunks = p.available_chunks as f64;
                let score = (chunks * bw) / lat.max(1.0);

                ScoredPeer {
                    node_id: p.node_id,
                    endpoint_url: p.endpoint_url,
                    latency_ms: p.latency_ms,
                    bandwidth_estimate_bps: p.bandwidth_estimate_bps,
                    available_chunks: p.available_chunks,
                    score,
                }
            })
            .collect();

        Ok(scored)
    }

    /// Discover potential peers for a peer instance.
    /// Returns online peer instances that share at least one repository subscription.
    pub async fn discover_peers(&self, peer_instance_id: Uuid) -> Result<Vec<DiscoverablePeer>> {
        let peers = sqlx::query_as!(
            DiscoverablePeer,
            r#"
            SELECT DISTINCT
                pi.id as node_id,
                pi.name,
                pi.endpoint_url,
                pi.region,
                pi.status as "status!: String"
            FROM peer_instances pi
            JOIN peer_repo_subscriptions prs ON prs.peer_instance_id = pi.id
            WHERE pi.id != $1
              AND pi.status IN ('online', 'syncing')
              AND prs.sync_enabled = true
              AND prs.repository_id IN (
                  SELECT repository_id FROM peer_repo_subscriptions
                  WHERE peer_instance_id = $1 AND sync_enabled = true
              )
            ORDER BY pi.region, pi.name
            "#,
            peer_instance_id,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(peers)
    }

    /// Update shared artifact/chunk counts for a peer connection.
    pub async fn update_shared_counts(
        &self,
        source_peer_id: Uuid,
        target_peer_id: Uuid,
    ) -> Result<()> {
        // Count shared artifacts (both peers have in cache)
        sqlx::query!(
            r#"
            UPDATE peer_connections SET
                shared_artifacts_count = (
                    SELECT COUNT(DISTINCT ec1.artifact_id)
                    FROM peer_cache_entries ec1
                    JOIN peer_cache_entries ec2
                        ON ec1.artifact_id = ec2.artifact_id
                    WHERE ec1.peer_instance_id = $1 AND ec2.peer_instance_id = $2
                ),
                shared_chunks_count = (
                    SELECT COALESCE(SUM(
                        LEAST(ca1.available_chunks, ca2.available_chunks)
                    ), 0)
                    FROM chunk_availability ca1
                    JOIN chunk_availability ca2
                        ON ca1.artifact_id = ca2.artifact_id
                    WHERE ca1.peer_instance_id = $1 AND ca2.peer_instance_id = $2
                ),
                updated_at = NOW()
            WHERE source_peer_id = $1 AND target_peer_id = $2
            "#,
            source_peer_id,
            target_peer_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Handle a peer announcement from a remote peer.
    ///
    /// UPSERTs the remote peer into `peer_instances` and creates a bidirectional
    /// connection entry in `peer_connections`.
    pub async fn handle_peer_announcement(
        &self,
        local_peer_id: Uuid,
        announcement: PeerAnnouncement,
    ) -> Result<()> {
        // UPSERT the announcing peer into peer_instances
        sqlx::query!(
            r#"
            INSERT INTO peer_instances (id, name, endpoint_url, api_key)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (name) DO UPDATE
                SET endpoint_url = $3, api_key = $4, updated_at = NOW()
            "#,
            announcement.peer_id,
            announcement.name,
            announcement.endpoint_url,
            announcement.api_key,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // UPSERT peer connection (local -> remote)
        sqlx::query!(
            r#"
            INSERT INTO peer_connections (source_peer_id, target_peer_id, status)
            VALUES ($1, $2, 'active')
            ON CONFLICT (source_peer_id, target_peer_id) DO NOTHING
            "#,
            local_peer_id,
            announcement.peer_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }
}

/// A discoverable peer instance
#[derive(Debug, serde::Serialize)]
pub struct DiscoverablePeer {
    pub node_id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub status: String,
}
