//! Edge node management service.
//!
//! Handles edge node registration, health monitoring, and sync coordination.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Edge node status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "edge_status", rename_all = "lowercase")]
pub enum EdgeStatus {
    Online,
    Offline,
    Syncing,
    Degraded,
}

impl std::fmt::Display for EdgeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeStatus::Online => write!(f, "online"),
            EdgeStatus::Offline => write!(f, "offline"),
            EdgeStatus::Syncing => write!(f, "syncing"),
            EdgeStatus::Degraded => write!(f, "degraded"),
        }
    }
}

/// Edge node model
#[derive(Debug)]
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

/// Request to register an edge node
#[derive(Debug)]
pub struct RegisterEdgeNodeRequest {
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub cache_size_bytes: i64,
    pub sync_filter: Option<serde_json::Value>,
}

/// Edge node service
pub struct EdgeService {
    db: PgPool,
}

impl EdgeService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Register a new edge node
    pub async fn register(&self, req: RegisterEdgeNodeRequest) -> Result<EdgeNode> {
        let node = sqlx::query_as!(
            EdgeNode,
            r#"
            INSERT INTO edge_nodes (name, endpoint_url, region, cache_size_bytes, sync_filter)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id, name, endpoint_url,
                status as "status: EdgeStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                created_at, updated_at
            "#,
            req.name,
            req.endpoint_url,
            req.region,
            req.cache_size_bytes,
            req.sync_filter
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Conflict(format!("Edge node '{}' already exists", req.name))
            } else {
                AppError::Database(e.to_string())
            }
        })?;

        Ok(node)
    }

    /// Get an edge node by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<EdgeNode> {
        let node = sqlx::query_as!(
            EdgeNode,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: EdgeStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                created_at, updated_at
            FROM edge_nodes
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Edge node not found".to_string()))?;

        Ok(node)
    }

    /// Get an edge node by name
    pub async fn get_by_name(&self, name: &str) -> Result<EdgeNode> {
        let node = sqlx::query_as!(
            EdgeNode,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: EdgeStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                created_at, updated_at
            FROM edge_nodes
            WHERE name = $1
            "#,
            name
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Edge node not found".to_string()))?;

        Ok(node)
    }

    /// List all edge nodes
    pub async fn list(
        &self,
        status_filter: Option<EdgeStatus>,
        region_filter: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<EdgeNode>, i64)> {
        let nodes = sqlx::query_as!(
            EdgeNode,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: EdgeStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                created_at, updated_at
            FROM edge_nodes
            WHERE ($1::edge_status IS NULL OR status = $1)
              AND ($2::text IS NULL OR region = $2)
            ORDER BY name
            OFFSET $3
            LIMIT $4
            "#,
            status_filter as Option<EdgeStatus>,
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
            FROM edge_nodes
            WHERE ($1::edge_status IS NULL OR status = $1)
              AND ($2::text IS NULL OR region = $2)
            "#,
            status_filter as Option<EdgeStatus>,
            region_filter
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((nodes, total))
    }

    /// Update heartbeat from edge node
    pub async fn heartbeat(
        &self,
        node_id: Uuid,
        cache_used_bytes: i64,
        status: Option<EdgeStatus>,
    ) -> Result<()> {
        let new_status = status.unwrap_or(EdgeStatus::Online);

        sqlx::query!(
            r#"
            UPDATE edge_nodes
            SET
                last_heartbeat_at = NOW(),
                cache_used_bytes = $2,
                status = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
            node_id,
            cache_used_bytes,
            new_status as EdgeStatus
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update sync status
    pub async fn update_sync_status(&self, node_id: Uuid, completed: bool) -> Result<()> {
        let status = if completed {
            EdgeStatus::Online
        } else {
            EdgeStatus::Syncing
        };

        let query = if completed {
            sqlx::query!(
                r#"
                UPDATE edge_nodes
                SET status = $2, last_sync_at = NOW(), updated_at = NOW()
                WHERE id = $1
                "#,
                node_id,
                status as EdgeStatus
            )
        } else {
            sqlx::query!(
                r#"
                UPDATE edge_nodes
                SET status = $2, updated_at = NOW()
                WHERE id = $1
                "#,
                node_id,
                status as EdgeStatus
            )
        };

        query
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Unregister an edge node
    pub async fn unregister(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query!("DELETE FROM edge_nodes WHERE id = $1", id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Edge node not found".to_string()));
        }

        Ok(())
    }

    /// Assign repository to edge node
    pub async fn assign_repository(
        &self,
        edge_node_id: Uuid,
        repository_id: Uuid,
        sync_enabled: bool,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO edge_repo_assignments (edge_node_id, repository_id, sync_enabled)
            VALUES ($1, $2, $3)
            ON CONFLICT (edge_node_id, repository_id) DO UPDATE SET sync_enabled = $3
            "#,
            edge_node_id,
            repository_id,
            sync_enabled
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Remove repository assignment from edge node
    pub async fn unassign_repository(&self, edge_node_id: Uuid, repository_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM edge_repo_assignments WHERE edge_node_id = $1 AND repository_id = $2",
            edge_node_id,
            repository_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Assignment not found".to_string()));
        }

        Ok(())
    }

    /// Get repositories assigned to an edge node
    pub async fn get_assigned_repositories(&self, edge_node_id: Uuid) -> Result<Vec<Uuid>> {
        let repos = sqlx::query_scalar!(
            "SELECT repository_id FROM edge_repo_assignments WHERE edge_node_id = $1 AND sync_enabled = true",
            edge_node_id
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
            UPDATE edge_nodes
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
        edge_node_id: Uuid,
        artifact_id: Uuid,
        priority: i32,
    ) -> Result<Uuid> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO sync_tasks (edge_node_id, artifact_id, priority)
            VALUES ($1, $2, $3)
            ON CONFLICT (edge_node_id, artifact_id) DO UPDATE SET priority = GREATEST(sync_tasks.priority, $3)
            RETURNING id
            "#,
            edge_node_id,
            artifact_id,
            priority
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(id)
    }

    /// Get pending sync tasks for an edge node
    pub async fn get_pending_sync_tasks(
        &self,
        edge_node_id: Uuid,
        limit: i64,
    ) -> Result<Vec<SyncTask>> {
        let tasks = sqlx::query_as!(
            SyncTask,
            r#"
            SELECT
                st.id, st.edge_node_id, st.artifact_id,
                st.status as "status: SyncStatus",
                st.priority, st.bytes_transferred, st.error_message,
                st.started_at, st.completed_at, st.created_at,
                a.storage_key, a.size_bytes as artifact_size
            FROM sync_tasks st
            JOIN artifacts a ON a.id = st.artifact_id
            WHERE st.edge_node_id = $1 AND st.status = 'pending'
            ORDER BY st.priority DESC, st.created_at
            LIMIT $2
            "#,
            edge_node_id,
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
    pub edge_node_id: Uuid,
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
