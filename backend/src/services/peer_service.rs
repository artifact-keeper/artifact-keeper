//! Mesh peer discovery and connection management service.
//!
//! Manages the peer graph between peer instances, tracking network metrics
//! for optimal swarm-based artifact distribution.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// SQLSTATE for a foreign-key violation.
const PG_FOREIGN_KEY_VIOLATION: &str = "23503";
/// SQLSTATE for a check-constraint violation.
const PG_CHECK_VIOLATION: &str = "23514";
/// CHECK constraint forbidding a peer from linking to itself.
const PEER_CONNECTION_NO_SELF_LINK: &str = "peer_connections_no_self_link";

/// Map a database error from `peer_connections` writes to an [`AppError`].
///
/// A foreign-key violation means the supplied `source_peer_id` or
/// `target_peer_id` does not name an existing peer instance — a client error
/// that must surface as [`AppError::NotFound`] (HTTP 404), not an opaque
/// [`AppError::Database`] (HTTP 500). A self-link CHECK violation is a client
/// error too and surfaces as [`AppError::Validation`] (HTTP 400) as a
/// defensive fallback (the handler also rejects self-probes up front). All
/// other database errors fall through to [`AppError::Database`].
fn map_peer_connection_error(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_err) = &err {
        match db_err.code().as_deref() {
            Some(PG_FOREIGN_KEY_VIOLATION) => {
                return AppError::NotFound("Peer instance not found".to_string());
            }
            Some(PG_CHECK_VIOLATION)
                if db_err.constraint() == Some(PEER_CONNECTION_NO_SELF_LINK) =>
            {
                return AppError::Validation(
                    "target_peer_id must differ from the source peer id".to_string(),
                );
            }
            _ => {}
        }
    }
    AppError::Database(err.to_string())
}

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
        .map_err(map_peer_connection_error)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PeerStatus Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_status_display_active() {
        assert_eq!(PeerStatus::Active.to_string(), "active");
    }

    #[test]
    fn test_peer_status_display_probing() {
        assert_eq!(PeerStatus::Probing.to_string(), "probing");
    }

    #[test]
    fn test_peer_status_display_unreachable() {
        assert_eq!(PeerStatus::Unreachable.to_string(), "unreachable");
    }

    #[test]
    fn test_peer_status_display_disabled() {
        assert_eq!(PeerStatus::Disabled.to_string(), "disabled");
    }

    // -----------------------------------------------------------------------
    // PeerStatus equality and clone
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_status_equality() {
        assert_eq!(PeerStatus::Active, PeerStatus::Active);
        assert_ne!(PeerStatus::Active, PeerStatus::Disabled);
        assert_ne!(PeerStatus::Probing, PeerStatus::Unreachable);
    }

    #[test]
    fn test_peer_status_clone_copy() {
        let status = PeerStatus::Active;
        let cloned = status;
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_peer_status_debug() {
        assert_eq!(format!("{:?}", PeerStatus::Active), "Active");
        assert_eq!(format!("{:?}", PeerStatus::Probing), "Probing");
        assert_eq!(format!("{:?}", PeerStatus::Unreachable), "Unreachable");
        assert_eq!(format!("{:?}", PeerStatus::Disabled), "Disabled");
    }

    // -----------------------------------------------------------------------
    // ScoredPeer scoring logic (replicated from get_scored_peers_for_artifact)
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_scoring_logic() {
        // Score = (chunks * bandwidth) / latency
        let bw: f64 = 10_000_000.0; // 10 Mbps
        let lat: f64 = 50.0; // 50ms
        let chunks: f64 = 5.0;
        let score = (chunks * bw) / lat.max(1.0);
        assert_eq!(score, 1_000_000.0);
    }

    #[test]
    fn test_peer_scoring_defaults() {
        // Default bandwidth = 1_000_000 (1Mbps), default latency = 500ms
        let bw: f64 = 1_000_000.0;
        let lat: f64 = 500.0;
        let chunks: f64 = 10.0;
        let score = (chunks * bw) / lat.max(1.0);
        assert_eq!(score, 20_000.0);
    }

    #[test]
    fn test_peer_scoring_zero_latency_clamped() {
        // lat.max(1.0) prevents division by zero
        let bw: f64 = 1_000_000.0;
        let lat: f64 = 0.0;
        let chunks: f64 = 5.0;
        let score = (chunks * bw) / lat.max(1.0);
        assert_eq!(score, 5_000_000.0);
    }

    #[test]
    fn test_peer_scoring_high_latency_low_score() {
        let bw: f64 = 1_000_000.0;
        let lat: f64 = 10_000.0; // 10 seconds
        let chunks: f64 = 5.0;
        let score = (chunks * bw) / lat.max(1.0);
        assert_eq!(score, 500.0);
    }

    // -----------------------------------------------------------------------
    // ScoredPeer serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_scored_peer_serialization() {
        let peer = ScoredPeer {
            node_id: Uuid::nil(),
            endpoint_url: "https://peer1.example.com:8080".to_string(),
            latency_ms: Some(50),
            bandwidth_estimate_bps: Some(10_000_000),
            available_chunks: 5,
            score: 1_000_000.0,
        };
        let json = serde_json::to_value(&peer).unwrap();
        assert_eq!(json["endpoint_url"], "https://peer1.example.com:8080");
        assert_eq!(json["latency_ms"], 50);
        assert_eq!(json["bandwidth_estimate_bps"], 10_000_000);
        assert_eq!(json["available_chunks"], 5);
        assert_eq!(json["score"], 1_000_000.0);
    }

    #[test]
    fn test_scored_peer_no_latency_data() {
        let peer = ScoredPeer {
            node_id: Uuid::nil(),
            endpoint_url: "https://new-peer.example.com".to_string(),
            latency_ms: None,
            bandwidth_estimate_bps: None,
            available_chunks: 3,
            score: 6000.0,
        };
        let json = serde_json::to_value(&peer).unwrap();
        assert!(json["latency_ms"].is_null());
        assert!(json["bandwidth_estimate_bps"].is_null());
    }

    // -----------------------------------------------------------------------
    // PeerAnnouncement deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_announcement_deserialization() {
        let json = r#"{
            "peer_id": "00000000-0000-0000-0000-000000000001",
            "name": "eu-west-1",
            "endpoint_url": "https://eu-west-1.registry.example.com",
            "api_key": "secret-key-123"
        }"#;
        let announcement: PeerAnnouncement = serde_json::from_str(json).unwrap();
        assert_eq!(announcement.name, "eu-west-1");
        assert_eq!(
            announcement.endpoint_url,
            "https://eu-west-1.registry.example.com"
        );
        assert_eq!(announcement.api_key, "secret-key-123");
    }

    // -----------------------------------------------------------------------
    // ProbeResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_probe_result_construction() {
        let result = ProbeResult {
            target_peer_id: Uuid::new_v4(),
            latency_ms: 42,
            bandwidth_estimate_bps: Some(100_000_000),
        };
        assert_eq!(result.latency_ms, 42);
        assert_eq!(result.bandwidth_estimate_bps, Some(100_000_000));
    }

    #[test]
    fn test_probe_result_no_bandwidth() {
        let result = ProbeResult {
            target_peer_id: Uuid::new_v4(),
            latency_ms: 100,
            bandwidth_estimate_bps: None,
        };
        assert!(result.bandwidth_estimate_bps.is_none());
    }

    // -----------------------------------------------------------------------
    // PeerConnection struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_connection_construction() {
        let conn = PeerConnection {
            id: Uuid::new_v4(),
            source_peer_id: Uuid::new_v4(),
            target_peer_id: Uuid::new_v4(),
            status: PeerStatus::Active,
            latency_ms: Some(25),
            bandwidth_estimate_bps: Some(50_000_000),
            shared_artifacts_count: 10,
            shared_chunks_count: 100,
            last_probed_at: Some(Utc::now()),
            last_transfer_at: None,
            bytes_transferred_total: 1_073_741_824,
            transfer_success_count: 50,
            transfer_failure_count: 2,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(conn.status, PeerStatus::Active);
        assert_eq!(conn.shared_artifacts_count, 10);
        assert_eq!(conn.transfer_success_count, 50);
        assert_eq!(conn.transfer_failure_count, 2);
    }

    // -----------------------------------------------------------------------
    // DiscoverablePeer
    // -----------------------------------------------------------------------

    #[test]
    fn test_discoverable_peer_serialization() {
        let peer = DiscoverablePeer {
            node_id: Uuid::nil(),
            name: "us-east-1".to_string(),
            endpoint_url: "https://us-east-1.registry.example.com".to_string(),
            region: Some("us-east-1".to_string()),
            status: "online".to_string(),
        };
        let json = serde_json::to_value(&peer).unwrap();
        assert_eq!(json["name"], "us-east-1");
        assert_eq!(json["region"], "us-east-1");
        assert_eq!(json["status"], "online");
    }

    #[test]
    fn test_discoverable_peer_no_region() {
        let peer = DiscoverablePeer {
            node_id: Uuid::nil(),
            name: "local".to_string(),
            endpoint_url: "http://localhost:8080".to_string(),
            region: None,
            status: "online".to_string(),
        };
        let json = serde_json::to_value(&peer).unwrap();
        assert!(json["region"].is_null());
    }

    // -----------------------------------------------------------------------
    // map_peer_connection_error: SQLSTATE -> AppError mapping.
    //
    // The probe handler rejects self-references up front, so the CHECK
    // (`peer_connections_no_self_link`) arm and the generic 500 fall-through
    // are not reachable through the HTTP path. Exercise the mapper directly
    // against real `sqlx::Error::Database` values produced by the live DB:
    //   * foreign-key violation (23503)            -> NotFound (404)
    //   * self-link CHECK violation (23514)        -> Validation (400)
    //   * any other database error                 -> Database (500)
    //
    // Runtime-skips when no `DATABASE_URL` is set (NOT `#[ignore]`), matching
    // the in-`src` DB-test convention used across this crate.
    // -----------------------------------------------------------------------
    mod map_peer_connection_error_db {
        use super::super::map_peer_connection_error;
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::error::AppError;
        use sqlx::PgPool;
        use uuid::Uuid;

        async fn make_peer(pool: &PgPool, tag: &str) -> Uuid {
            tdh::register_test_peer(pool, "map-err", tag).await
        }

        /// Attempt a `peer_connections` INSERT and return the raw `sqlx::Error`.
        async fn insert_connection_err(pool: &PgPool, source: Uuid, target: Uuid) -> sqlx::Error {
            sqlx::query(
                "INSERT INTO peer_connections \
                 (source_peer_id, target_peer_id, status, last_probed_at) \
                 VALUES ($1, $2, 'active', NOW())",
            )
            .bind(source)
            .bind(target)
            .execute(pool)
            .await
            .expect_err("insert was expected to violate a constraint")
        }

        #[tokio::test]
        async fn test_foreign_key_violation_maps_to_not_found() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            // Non-existent target trips the target FK (23503).
            let source = make_peer(&pool, "fk").await;
            let missing = Uuid::new_v4();
            let err = insert_connection_err(&pool, source, missing).await;

            match map_peer_connection_error(err) {
                AppError::NotFound(_) => {}
                other => panic!("FK violation must map to NotFound, got {other:?}"),
            }

            let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
                .bind(source)
                .execute(&pool)
                .await;
        }

        #[tokio::test]
        async fn test_self_link_check_violation_maps_to_validation() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            // source == target trips the `peer_connections_no_self_link`
            // CHECK (23514). Both ids reference the same existing peer so the
            // FK passes and the CHECK is the failing constraint.
            let peer = make_peer(&pool, "check").await;
            let err = insert_connection_err(&pool, peer, peer).await;

            match map_peer_connection_error(err) {
                AppError::Validation(_) => {}
                other => {
                    panic!("self-link CHECK violation must map to Validation, got {other:?}")
                }
            }

            let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
                .bind(peer)
                .execute(&pool)
                .await;
        }

        #[tokio::test]
        async fn test_other_database_error_maps_to_database() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            // A syntactically invalid statement yields a database error whose
            // SQLSTATE is neither 23503 nor the self-link CHECK, exercising the
            // generic fall-through to AppError::Database (500).
            let err = sqlx::query("SELECT * FROM peer_connections WHERE no_such_column = 1")
                .execute(&pool)
                .await
                .expect_err("query was expected to fail");

            match map_peer_connection_error(err) {
                AppError::Database(_) => {}
                other => panic!("unrelated database error must map to Database, got {other:?}"),
            }
        }
    }
}
