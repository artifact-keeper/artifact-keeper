//! Peer instance management service.
//!
//! Handles peer instance registration, health monitoring, and sync coordination.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Peer instance status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "instance_status", rename_all = "lowercase")]
pub enum InstanceStatus {
    Online,
    Offline,
    Syncing,
    Degraded,
}

/// Replication mode for peer replication policies.
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "replication_mode", rename_all = "lowercase")]
pub enum ReplicationMode {
    Push,
    Pull,
    Mirror,
    None,
}

/// A repository with a mirror replication policy.
#[derive(Debug)]
pub struct MirrorRepo {
    pub repo_id: Uuid,
    pub schedule: Option<String>,
    pub last_replicated_at: Option<DateTime<Utc>>,
}

impl std::fmt::Display for InstanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceStatus::Online => write!(f, "online"),
            InstanceStatus::Offline => write!(f, "offline"),
            InstanceStatus::Syncing => write!(f, "syncing"),
            InstanceStatus::Degraded => write!(f, "degraded"),
        }
    }
}

/// Peer instance model
#[derive(Debug)]
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

/// Request to register a peer instance
#[derive(Debug)]
pub struct RegisterPeerInstanceRequest {
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub cache_size_bytes: i64,
    pub sync_filter: Option<serde_json::Value>,
    pub api_key: String,
}

/// Peer instance service
pub struct PeerInstanceService {
    db: PgPool,
}

impl PeerInstanceService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Register a new peer instance
    pub async fn register(&self, req: RegisterPeerInstanceRequest) -> Result<PeerInstance> {
        let node = sqlx::query_as!(
            PeerInstance,
            r#"
            INSERT INTO peer_instances (name, endpoint_url, region, cache_size_bytes, sync_filter, api_key)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            "#,
            req.name,
            req.endpoint_url,
            req.region,
            req.cache_size_bytes,
            req.sync_filter,
            req.api_key
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Conflict(format!("Peer instance '{}' already exists", req.name))
            } else {
                AppError::Database(e.to_string())
            }
        })?;

        Ok(node)
    }

    /// Get the local peer instance
    pub async fn get_local_instance(&self) -> Result<PeerInstance> {
        let node = sqlx::query_as!(
            PeerInstance,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            FROM peer_instances
            WHERE is_local = true
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Local peer instance not found".to_string()))?;

        Ok(node)
    }

    /// Get a peer instance by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<PeerInstance> {
        let node = sqlx::query_as!(
            PeerInstance,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            FROM peer_instances
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Peer instance not found".to_string()))?;

        Ok(node)
    }

    /// Get a peer instance by name
    pub async fn get_by_name(&self, name: &str) -> Result<PeerInstance> {
        let node = sqlx::query_as!(
            PeerInstance,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            FROM peer_instances
            WHERE name = $1
            "#,
            name
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Peer instance not found".to_string()))?;

        Ok(node)
    }

    /// List all peer instances
    pub async fn list(
        &self,
        status_filter: Option<InstanceStatus>,
        region_filter: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<PeerInstance>, i64)> {
        let nodes = sqlx::query_as!(
            PeerInstance,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            FROM peer_instances
            WHERE ($1::instance_status IS NULL OR status = $1)
              AND ($2::text IS NULL OR region = $2)
            ORDER BY name
            OFFSET $3
            LIMIT $4
            "#,
            status_filter as Option<InstanceStatus>,
            region_filter,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM peer_instances
            WHERE ($1::instance_status IS NULL OR status = $1)
              AND ($2::text IS NULL OR region = $2)
            "#,
            status_filter as Option<InstanceStatus>,
            region_filter
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((nodes, total))
    }

    /// Update heartbeat from peer instance
    pub async fn heartbeat(
        &self,
        node_id: Uuid,
        cache_used_bytes: i64,
        status: Option<InstanceStatus>,
    ) -> Result<()> {
        let new_status = status.unwrap_or(InstanceStatus::Online);

        sqlx::query!(
            r#"
            UPDATE peer_instances
            SET
                last_heartbeat_at = NOW(),
                cache_used_bytes = $2,
                status = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
            node_id,
            cache_used_bytes,
            new_status as InstanceStatus
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update sync status
    pub async fn update_sync_status(&self, node_id: Uuid, completed: bool) -> Result<()> {
        let status = if completed {
            InstanceStatus::Online
        } else {
            InstanceStatus::Syncing
        };

        let query = if completed {
            sqlx::query!(
                r#"
                UPDATE peer_instances
                SET status = $2, last_sync_at = NOW(), updated_at = NOW()
                WHERE id = $1
                "#,
                node_id,
                status as InstanceStatus
            )
        } else {
            sqlx::query!(
                r#"
                UPDATE peer_instances
                SET status = $2, updated_at = NOW()
                WHERE id = $1
                "#,
                node_id,
                status as InstanceStatus
            )
        };

        query
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Unregister a peer instance
    pub async fn unregister(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query!("DELETE FROM peer_instances WHERE id = $1", id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Peer instance not found".to_string()));
        }

        Ok(())
    }

    /// Assign repository to peer instance (subscribe)
    pub async fn assign_repository(
        &self,
        peer_instance_id: Uuid,
        repository_id: Uuid,
        sync_enabled: bool,
        replication_mode: Option<ReplicationMode>,
        replication_schedule: Option<String>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO peer_repo_subscriptions
                (peer_instance_id, repository_id, sync_enabled, replication_mode, replication_schedule)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (peer_instance_id, repository_id) DO UPDATE SET
                sync_enabled = $3,
                replication_mode = $4,
                replication_schedule = $5
            "#,
            peer_instance_id,
            repository_id,
            sync_enabled,
            replication_mode as Option<ReplicationMode>,
            replication_schedule
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Remove repository subscription from peer instance
    pub async fn unassign_repository(
        &self,
        peer_instance_id: Uuid,
        repository_id: Uuid,
    ) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM peer_repo_subscriptions WHERE peer_instance_id = $1 AND repository_id = $2",
            peer_instance_id,
            repository_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Subscription not found".to_string()));
        }

        Ok(())
    }

    /// Get repositories subscribed by a peer instance
    pub async fn get_assigned_repositories(&self, peer_instance_id: Uuid) -> Result<Vec<Uuid>> {
        let repos = sqlx::query_scalar!(
            "SELECT repository_id FROM peer_repo_subscriptions WHERE peer_instance_id = $1 AND sync_enabled = true",
            peer_instance_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(repos)
    }

    /// Mark stale nodes as offline
    pub async fn mark_stale_offline(&self, stale_threshold_minutes: i32) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE peer_instances
            SET status = 'offline'
            WHERE status = 'online'
              AND last_heartbeat_at < NOW() - make_interval(mins => $1)
            "#,
            stale_threshold_minutes
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Queue sync task for an artifact
    pub async fn queue_sync_task(
        &self,
        peer_instance_id: Uuid,
        artifact_id: Uuid,
        priority: i32,
    ) -> Result<Uuid> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO sync_tasks (peer_instance_id, artifact_id, priority)
            VALUES ($1, $2, $3)
            ON CONFLICT (peer_instance_id, artifact_id) DO UPDATE SET priority = GREATEST(sync_tasks.priority, $3)
            RETURNING id
            "#,
            peer_instance_id,
            artifact_id,
            priority
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(id)
    }

    /// Get pending sync tasks for a peer instance
    pub async fn get_pending_sync_tasks(
        &self,
        peer_instance_id: Uuid,
        limit: i64,
    ) -> Result<Vec<SyncTask>> {
        let tasks = sqlx::query_as!(
            SyncTask,
            r#"
            SELECT
                st.id, st.peer_instance_id, st.artifact_id,
                st.status as "status: SyncStatus",
                st.priority, st.bytes_transferred, st.error_message,
                st.started_at, st.completed_at, st.created_at,
                a.storage_key, a.size_bytes as artifact_size
            FROM sync_tasks st
            JOIN artifacts a ON a.id = st.artifact_id
            WHERE st.peer_instance_id = $1
              AND st.status = 'pending'
            ORDER BY st.priority DESC, st.created_at
            LIMIT $2
            "#,
            peer_instance_id,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(tasks)
    }

    /// Update sync task status
    pub async fn update_sync_task(
        &self,
        task_id: Uuid,
        status: SyncStatus,
        bytes_transferred: Option<i64>,
        error_message: Option<&str>,
    ) -> Result<()> {
        let started_at = if status == SyncStatus::InProgress {
            Some(Utc::now())
        } else {
            None
        };

        let completed_at = if matches!(
            status,
            SyncStatus::Completed | SyncStatus::Failed | SyncStatus::Cancelled
        ) {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query!(
            r#"
            UPDATE sync_tasks
            SET
                status = $2,
                bytes_transferred = COALESCE($3, bytes_transferred),
                error_message = $4,
                started_at = COALESCE($5, started_at),
                completed_at = COALESCE($6, completed_at)
            WHERE id = $1
            "#,
            task_id,
            status as SyncStatus,
            bytes_transferred,
            error_message,
            started_at,
            completed_at
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update the replication mode for a repository.
    pub async fn update_replication_mode(
        &self,
        peer_instance_id: Uuid,
        repo_id: Uuid,
        mode: ReplicationMode,
    ) -> Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE peer_repo_subscriptions
            SET replication_mode = $3
            WHERE peer_instance_id = $1 AND repository_id = $2
            "#,
            peer_instance_id,
            repo_id,
            mode as ReplicationMode
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Subscription not found".to_string()));
        }

        Ok(())
    }

    /// Get repositories that require push sync for a given peer instance.
    ///
    /// Returns repo IDs where the effective replication mode (subscription override or
    /// repository default) is `push` and sync is enabled.
    pub async fn get_repos_for_push_sync(&self, peer_instance_id: Uuid) -> Result<Vec<Uuid>> {
        let repos = sqlx::query_scalar!(
            r#"
            SELECT prs.repository_id
            FROM peer_repo_subscriptions prs
            JOIN repositories r ON r.id = prs.repository_id
            WHERE prs.peer_instance_id = $1
              AND prs.sync_enabled = true
              AND prs.replication_mode = 'push'
            "#,
            peer_instance_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(repos)
    }

    /// Get repositories with mirror replication for a given peer instance.
    ///
    /// Returns repo metadata including the cron schedule and last replication
    /// timestamp so callers can determine which repos are due for sync.
    pub async fn get_repos_for_mirror_sync(
        &self,
        peer_instance_id: Uuid,
    ) -> Result<Vec<MirrorRepo>> {
        let repos = sqlx::query_as!(
            MirrorRepo,
            r#"
            SELECT
                prs.repository_id as repo_id,
                prs.replication_schedule as schedule,
                prs.last_replicated_at
            FROM peer_repo_subscriptions prs
            JOIN repositories r ON r.id = prs.repository_id
            WHERE prs.peer_instance_id = $1
              AND prs.sync_enabled = true
              AND prs.replication_mode = 'mirror'
            "#,
            peer_instance_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(repos)
    }

    /// Register a peer bidirectionally.
    ///
    /// 1. Registers the peer locally (calls self.register())
    /// 2. POSTs an announcement to the remote peer's `/api/v1/peers/announce` endpoint
    pub async fn register_peer_bidirectional(
        &self,
        req: RegisterPeerInstanceRequest,
        local_name: &str,
        local_endpoint_url: &str,
        local_api_key: &str,
    ) -> Result<PeerInstance> {
        let remote_endpoint = req.endpoint_url.clone();

        // Register the peer locally
        let peer = self.register(req).await?;

        // Announce ourselves to the remote peer
        let client = reqwest::Client::new();
        let announce_url = format!(
            "{}/api/v1/peers/announce",
            remote_endpoint.trim_end_matches('/')
        );

        let local_instance = self.get_local_instance().await.ok();
        let local_id = local_instance.map(|i| i.id);

        let announcement = serde_json::json!({
            "peer_id": local_id,
            "name": local_name,
            "endpoint_url": local_endpoint_url,
            "api_key": local_api_key,
        });

        client
            .post(&announce_url)
            .json(&announcement)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to announce to remote peer: {}", e)))?;

        Ok(peer)
    }
}

/// Sync task status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "sync_status", rename_all = "snake_case")]
pub enum SyncStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Sync task model
#[derive(Debug)]
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
    pub storage_key: String,
    pub artifact_size: i64,
}
