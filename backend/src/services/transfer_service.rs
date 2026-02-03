//! Swarm-based chunked transfer service.
//!
//! Manages artifact transfers using a piece-based distribution model where
//! chunks can be sourced from multiple peers simultaneously.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Sync status reused from peer instance service
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "sync_status", rename_all = "snake_case")]
pub enum SyncStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Transfer session model
#[derive(Debug)]
pub struct TransferSession {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub requesting_peer_id: Uuid,
    pub total_size: i64,
    pub chunk_size: i32,
    pub total_chunks: i32,
    pub completed_chunks: i32,
    pub checksum_algo: String,
    pub artifact_checksum: String,
    pub status: SyncStatus,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Chunk manifest entry returned to requesting peer
#[derive(Debug, serde::Serialize)]
pub struct ChunkManifestEntry {
    pub chunk_index: i32,
    pub byte_offset: i64,
    pub byte_length: i32,
    pub checksum: String,
    pub status: String,
    pub source_peer_id: Option<Uuid>,
}

/// Peer chunk availability for swarm coordination
#[derive(Debug, serde::Serialize)]
pub struct PeerChunkInfo {
    pub peer_instance_id: Uuid,
    pub available_chunks: i32,
    pub total_chunks: i32,
    pub chunk_bitmap: Vec<u8>,
}

/// Request to initialize a transfer
#[derive(Debug)]
pub struct InitTransferRequest {
    pub artifact_id: Uuid,
    pub requesting_peer_id: Uuid,
    pub chunk_size: Option<i32>,
}

/// Transfer service for swarm-based chunked distribution
pub struct TransferService {
    db: PgPool,
}

impl TransferService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Initialize a chunked transfer session.
    /// Splits the artifact into chunks and creates the session + chunk records.
    pub async fn init_transfer(&self, req: InitTransferRequest) -> Result<TransferSession> {
        let chunk_size = req.chunk_size.unwrap_or(1_048_576); // 1MB default

        // Get artifact details
        let artifact = sqlx::query!(
            r#"SELECT id, size_bytes, checksum_sha256, storage_key FROM artifacts WHERE id = $1"#,
            req.artifact_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

        let total_size = artifact.size_bytes;
        let total_chunks = ((total_size as f64) / (chunk_size as f64)).ceil() as i32;

        // Create session
        let session = sqlx::query_as!(
            TransferSession,
            r#"
            INSERT INTO transfer_sessions
                (artifact_id, requesting_peer_id, total_size, chunk_size, total_chunks,
                 checksum_algo, artifact_checksum, status)
            VALUES ($1, $2, $3, $4, $5, 'sha256', $6, 'pending')
            ON CONFLICT (artifact_id, requesting_peer_id) DO UPDATE
                SET status = 'pending', completed_chunks = 0,
                    started_at = NULL, completed_at = NULL, error_message = NULL
            RETURNING
                id, artifact_id, requesting_peer_id, total_size, chunk_size,
                total_chunks, completed_chunks, checksum_algo, artifact_checksum,
                status as "status: SyncStatus",
                error_message, created_at, started_at, completed_at
            "#,
            req.artifact_id,
            req.requesting_peer_id,
            total_size,
            chunk_size,
            total_chunks,
            artifact.checksum_sha256,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Create chunk records
        for i in 0..total_chunks {
            let byte_offset = (i as i64) * (chunk_size as i64);
            let byte_length = if i == total_chunks - 1 {
                (total_size - byte_offset) as i32
            } else {
                chunk_size
            };

            sqlx::query!(
                r#"
                INSERT INTO transfer_chunks
                    (session_id, chunk_index, byte_offset, byte_length, checksum, status)
                VALUES ($1, $2, $3, $4, '', 'pending')
                ON CONFLICT (session_id, chunk_index) DO NOTHING
                "#,
                session.id,
                i,
                byte_offset,
                byte_length,
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        Ok(session)
    }

    /// Get the chunk manifest for a transfer session.
    pub async fn get_chunk_manifest(&self, session_id: Uuid) -> Result<Vec<ChunkManifestEntry>> {
        let chunks = sqlx::query_as!(
            ChunkManifestEntry,
            r#"
            SELECT
                chunk_index, byte_offset, byte_length, checksum,
                status as "status!: String",
                source_peer_id
            FROM transfer_chunks
            WHERE session_id = $1
            ORDER BY chunk_index
            "#,
            session_id,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(chunks)
    }

    /// Get a transfer session by ID.
    pub async fn get_session(&self, session_id: Uuid) -> Result<TransferSession> {
        let session = sqlx::query_as!(
            TransferSession,
            r#"
            SELECT
                id, artifact_id, requesting_peer_id, total_size, chunk_size,
                total_chunks, completed_chunks, checksum_algo, artifact_checksum,
                status as "status: SyncStatus",
                error_message, created_at, started_at, completed_at
            FROM transfer_sessions
            WHERE id = $1
            "#,
            session_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Transfer session not found".to_string()))?;

        Ok(session)
    }

    /// Mark a chunk as completed, recording which peer served it.
    pub async fn complete_chunk(
        &self,
        session_id: Uuid,
        chunk_index: i32,
        checksum: &str,
        source_peer_id: Option<Uuid>,
    ) -> Result<()> {
        // Update chunk status
        let result = sqlx::query!(
            r#"
            UPDATE transfer_chunks
            SET status = 'completed', checksum = $3, source_peer_id = $4,
                downloaded_at = NOW(), attempts = attempts + 1
            WHERE session_id = $1 AND chunk_index = $2 AND status != 'completed'
            "#,
            session_id,
            chunk_index,
            checksum,
            source_peer_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Ok(()); // Already completed
        }

        // Update session completed_chunks count
        sqlx::query!(
            r#"
            UPDATE transfer_sessions
            SET completed_chunks = (
                SELECT COUNT(*) FROM transfer_chunks
                WHERE session_id = $1 AND status = 'completed'
            ),
            started_at = COALESCE(started_at, NOW())
            WHERE id = $1
            "#,
            session_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Mark a chunk as failed.
    pub async fn fail_chunk(&self, session_id: Uuid, chunk_index: i32, error: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE transfer_chunks
            SET status = 'failed', last_error = $3, attempts = attempts + 1
            WHERE session_id = $1 AND chunk_index = $2
            "#,
            session_id,
            chunk_index,
            error,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Reset a failed chunk to pending for retry.
    pub async fn retry_chunk(&self, session_id: Uuid, chunk_index: i32) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE transfer_chunks
            SET status = 'pending', source_peer_id = NULL
            WHERE session_id = $1 AND chunk_index = $2 AND status = 'failed'
            "#,
            session_id,
            chunk_index,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Complete a transfer session after all chunks are verified.
    pub async fn complete_session(&self, session_id: Uuid) -> Result<()> {
        // Verify all chunks are completed
        let pending = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!" FROM transfer_chunks
            WHERE session_id = $1 AND status != 'completed'
            "#,
            session_id,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if pending > 0 {
            return Err(AppError::Validation(format!(
                "{} chunks still pending/failed",
                pending
            )));
        }

        sqlx::query!(
            r#"
            UPDATE transfer_sessions
            SET status = 'completed', completed_at = NOW()
            WHERE id = $1
            "#,
            session_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Fail a transfer session.
    pub async fn fail_session(&self, session_id: Uuid, error: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE transfer_sessions
            SET status = 'failed', error_message = $2, completed_at = NOW()
            WHERE id = $1
            "#,
            session_id,
            error,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update chunk availability for a peer instance/artifact pair.
    /// The bitmap uses big-endian encoding: bit 0 = MSB of byte 0.
    pub async fn update_chunk_availability(
        &self,
        peer_instance_id: Uuid,
        artifact_id: Uuid,
        chunk_bitmap: &[u8],
        total_chunks: i32,
    ) -> Result<()> {
        // Count set bits
        let available_chunks = chunk_bitmap
            .iter()
            .map(|b| b.count_ones() as i32)
            .sum::<i32>();

        sqlx::query!(
            r#"
            INSERT INTO chunk_availability
                (peer_instance_id, artifact_id, chunk_bitmap, total_chunks, available_chunks)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (peer_instance_id, artifact_id) DO UPDATE
                SET chunk_bitmap = $3, available_chunks = $5, updated_at = NOW()
            "#,
            peer_instance_id,
            artifact_id,
            chunk_bitmap,
            total_chunks,
            available_chunks,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get chunk availability for an artifact across all active peers.
    /// Used for swarm peer selection.
    pub async fn get_peers_with_chunks(
        &self,
        artifact_id: Uuid,
        requesting_peer_id: Uuid,
    ) -> Result<Vec<PeerChunkInfo>> {
        let peers = sqlx::query_as!(
            PeerChunkInfo,
            r#"
            SELECT
                ca.peer_instance_id,
                ca.available_chunks,
                ca.total_chunks,
                ca.chunk_bitmap
            FROM chunk_availability ca
            JOIN peer_instances pi ON pi.id = ca.peer_instance_id
            WHERE ca.artifact_id = $1
              AND ca.peer_instance_id != $2
              AND ca.available_chunks > 0
              AND pi.status IN ('online', 'syncing')
            ORDER BY ca.available_chunks DESC
            "#,
            artifact_id,
            requesting_peer_id,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(peers)
    }

    /// Get pending (resumable) transfer sessions for a peer instance.
    pub async fn get_pending_sessions(&self, peer_id: Uuid) -> Result<Vec<TransferSession>> {
        let sessions = sqlx::query_as!(
            TransferSession,
            r#"
            SELECT
                id, artifact_id, requesting_peer_id, total_size, chunk_size,
                total_chunks, completed_chunks, checksum_algo, artifact_checksum,
                status as "status: SyncStatus",
                error_message, created_at, started_at, completed_at
            FROM transfer_sessions
            WHERE requesting_peer_id = $1 AND status IN ('pending', 'in_progress')
            ORDER BY created_at
            "#,
            peer_id,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(sessions)
    }
}
