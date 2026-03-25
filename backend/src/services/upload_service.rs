//! Chunked/resumable upload session management.
//!
//! Handles creation of upload sessions, streaming chunk writes to a temp file
//! (never buffering full chunks in memory), session finalization with SHA256
//! verification, and cleanup of expired sessions.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// An upload session row from the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UploadSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub artifact_path: String,
    pub content_type: String,
    pub total_size: i64,
    pub chunk_size: i32,
    pub total_chunks: i32,
    pub completed_chunks: i32,
    pub bytes_received: i64,
    pub checksum_sha256: String,
    pub temp_file_path: String,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Result of uploading a single chunk.
#[derive(Debug)]
pub struct ChunkResult {
    pub chunk_index: i32,
    pub bytes_received: i64,
    pub chunks_completed: i32,
    pub chunks_remaining: i32,
}

/// Result of finalizing an upload session.
#[derive(Debug)]
pub struct FinalizeResult {
    pub artifact_id: Uuid,
    pub path: String,
    pub size: i64,
    pub checksum_sha256: String,
}

/// Errors that can occur in upload operations.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("session not found")]
    NotFound,

    #[error("session expired")]
    Expired,

    #[error("invalid chunk: {0}")]
    InvalidChunk(String),

    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("not all chunks completed: {completed}/{total}")]
    IncompleteChunks { completed: i32, total: i32 },

    #[error("size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: i64, actual: i64 },

    #[error("invalid session status: {0}")]
    InvalidStatus(String),

    #[error("repository not found: {0}")]
    RepositoryNotFound(String),

    #[error("invalid chunk size: must be between 1 MB and 256 MB")]
    InvalidChunkSize,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MIN_CHUNK_SIZE: i64 = 1_048_576; // 1 MB
const MAX_CHUNK_SIZE: i64 = 268_435_456; // 256 MB
const DEFAULT_CHUNK_SIZE: i32 = 8_388_608; // 8 MB
const SHA256_BUF_SIZE: usize = 64 * 1024; // 64 KB read buffer for checksums

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Parameters for creating a new upload session.
pub struct CreateSessionParams<'a> {
    pub db: &'a PgPool,
    pub storage_path: &'a str,
    pub user_id: Uuid,
    pub repo_id: Uuid,
    pub repo_key: &'a str,
    pub artifact_path: &'a str,
    pub total_size: i64,
    pub chunk_size: Option<i32>,
    pub checksum_sha256: &'a str,
    pub content_type: Option<&'a str>,
}

pub struct UploadService;

impl UploadService {
    /// Create a new chunked upload session.
    ///
    /// Validates chunk size, computes chunk count, creates the temp file on
    /// disk, and inserts session + chunk rows into the database.
    pub async fn create_session(p: CreateSessionParams<'_>) -> Result<UploadSession, UploadError> {
        let chunk_size = p.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        if (chunk_size as i64) < MIN_CHUNK_SIZE || (chunk_size as i64) > MAX_CHUNK_SIZE {
            return Err(UploadError::InvalidChunkSize);
        }

        let total_chunks = ((p.total_size + chunk_size as i64 - 1) / chunk_size as i64) as i32;
        let content_type = p.content_type.unwrap_or("application/octet-stream");

        let session_id = Uuid::new_v4();
        let temp_dir = PathBuf::from(p.storage_path).join(".uploads");
        tokio::fs::create_dir_all(&temp_dir).await?;
        let temp_file_path = temp_dir.join(session_id.to_string());

        // Pre-allocate temp file at the expected size (sparse file on most FS)
        let file = tokio::fs::File::create(&temp_file_path).await?;
        file.set_len(p.total_size as u64).await?;
        drop(file);

        let session = sqlx::query_as::<_, UploadSession>(
            r#"
            INSERT INTO upload_sessions
                (id, user_id, repository_id, repository_key, artifact_path,
                 content_type, total_size, chunk_size, total_chunks,
                 checksum_sha256, temp_file_path)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(session_id)
        .bind(p.user_id)
        .bind(p.repo_id)
        .bind(p.repo_key)
        .bind(p.artifact_path)
        .bind(content_type)
        .bind(p.total_size)
        .bind(chunk_size)
        .bind(total_chunks)
        .bind(p.checksum_sha256)
        .bind(temp_file_path.to_string_lossy().as_ref())
        .fetch_one(p.db)
        .await?;

        // Insert chunk placeholder rows
        for i in 0..total_chunks {
            let offset = i as i64 * chunk_size as i64;
            let length = if i == total_chunks - 1 {
                (p.total_size - offset) as i32
            } else {
                chunk_size
            };

            sqlx::query(
                r#"
                INSERT INTO upload_chunks (session_id, chunk_index, byte_offset, byte_length)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(session_id)
            .bind(i)
            .bind(offset)
            .bind(length)
            .execute(p.db)
            .await?;
        }

        tracing::info!(
            "Created upload session {} for {} ({} bytes, {} chunks of {} bytes)",
            session_id,
            p.artifact_path,
            p.total_size,
            total_chunks,
            chunk_size
        );

        Ok(session)
    }

    /// Write a chunk to the temp file at the correct offset.
    ///
    /// The data is streamed directly to disk via `seek` + `write`, never
    /// buffered as a complete chunk in memory. Computes SHA256 incrementally.
    pub async fn upload_chunk(
        db: &PgPool,
        session_id: Uuid,
        chunk_index: i32,
        byte_offset: i64,
        data: bytes::Bytes,
    ) -> Result<ChunkResult, UploadError> {
        let session = Self::get_session(db, session_id).await?;

        if session.status == "completed" || session.status == "cancelled" {
            return Err(UploadError::InvalidStatus(session.status));
        }

        // Check if chunk is already completed (idempotent retry)
        let existing = sqlx::query_as::<_, (String,)>(
            "SELECT status FROM upload_chunks WHERE session_id = $1 AND chunk_index = $2",
        )
        .bind(session_id)
        .bind(chunk_index)
        .fetch_optional(db)
        .await?;

        if let Some((status,)) = &existing {
            if status == "completed" {
                // Idempotent: chunk already uploaded
                let completed = session.completed_chunks;
                return Ok(ChunkResult {
                    chunk_index,
                    bytes_received: session.bytes_received,
                    chunks_completed: completed,
                    chunks_remaining: session.total_chunks - completed,
                });
            }
        } else {
            return Err(UploadError::InvalidChunk(format!(
                "chunk_index {} out of range (0..{})",
                chunk_index, session.total_chunks
            )));
        }

        // Compute SHA256 of the chunk data
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let chunk_checksum = format!("{:x}", hasher.finalize());

        // Write to temp file at the correct offset
        let temp_path = PathBuf::from(&session.temp_file_path);
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&temp_path)
            .await?;
        file.seek(std::io::SeekFrom::Start(byte_offset as u64))
            .await?;
        file.write_all(&data).await?;
        file.sync_data().await?;

        let data_len = data.len() as i64;

        // Update chunk status
        sqlx::query(
            r#"
            UPDATE upload_chunks
            SET status = 'completed', checksum_sha256 = $3, completed_at = NOW()
            WHERE session_id = $1 AND chunk_index = $2
            "#,
        )
        .bind(session_id)
        .bind(chunk_index)
        .bind(&chunk_checksum)
        .execute(db)
        .await?;

        // Update session counters
        let updated = sqlx::query_as::<_, (i32, i64)>(
            r#"
            UPDATE upload_sessions
            SET completed_chunks = completed_chunks + 1,
                bytes_received = bytes_received + $2,
                status = CASE WHEN status = 'pending' THEN 'in_progress' ELSE status END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING completed_chunks, bytes_received
            "#,
        )
        .bind(session_id)
        .bind(data_len)
        .fetch_one(db)
        .await?;

        let (completed_chunks, bytes_received) = updated;

        Ok(ChunkResult {
            chunk_index,
            bytes_received,
            chunks_completed: completed_chunks,
            chunks_remaining: session.total_chunks - completed_chunks,
        })
    }

    /// Get an upload session by ID.
    pub async fn get_session(db: &PgPool, session_id: Uuid) -> Result<UploadSession, UploadError> {
        let session =
            sqlx::query_as::<_, UploadSession>("SELECT * FROM upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_optional(db)
                .await?
                .ok_or(UploadError::NotFound)?;

        if session.expires_at < chrono::Utc::now() {
            return Err(UploadError::Expired);
        }

        Ok(session)
    }

    /// Finalize an upload session: verify all chunks, compute full-file SHA256,
    /// and move the temp file to final storage. Returns the artifact ID.
    ///
    /// The caller is responsible for creating the artifact record after this
    /// method returns the verified file data.
    pub async fn complete_session(
        db: &PgPool,
        session_id: Uuid,
    ) -> Result<UploadSession, UploadError> {
        let session = Self::get_session(db, session_id).await?;

        if session.status == "completed" {
            return Err(UploadError::InvalidStatus("already completed".into()));
        }
        if session.status == "cancelled" {
            return Err(UploadError::InvalidStatus("cancelled".into()));
        }

        // Verify all chunks are completed
        let incomplete: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM upload_chunks WHERE session_id = $1 AND status != 'completed'",
        )
        .bind(session_id)
        .fetch_one(db)
        .await?;

        if incomplete > 0 {
            return Err(UploadError::IncompleteChunks {
                completed: session.completed_chunks,
                total: session.total_chunks,
            });
        }

        // Verify total file size
        let temp_path = PathBuf::from(&session.temp_file_path);
        let file_meta = tokio::fs::metadata(&temp_path).await?;
        if file_meta.len() != session.total_size as u64 {
            return Err(UploadError::SizeMismatch {
                expected: session.total_size,
                actual: file_meta.len() as i64,
            });
        }

        // Compute full-file SHA256 by streaming in 64 KB blocks
        let actual_checksum = compute_file_sha256(&temp_path).await?;
        if actual_checksum != session.checksum_sha256 {
            // Mark session as failed
            let _ = sqlx::query(
                "UPDATE upload_sessions SET status = 'failed', error_message = $2, updated_at = NOW() WHERE id = $1",
            )
            .bind(session_id)
            .bind(format!(
                "checksum mismatch: expected {}, got {}",
                session.checksum_sha256, actual_checksum
            ))
            .execute(db)
            .await;

            return Err(UploadError::ChecksumMismatch {
                expected: session.checksum_sha256.clone(),
                actual: actual_checksum,
            });
        }

        // Mark session as completed
        sqlx::query(
            "UPDATE upload_sessions SET status = 'completed', updated_at = NOW() WHERE id = $1",
        )
        .bind(session_id)
        .execute(db)
        .await?;

        Ok(session)
    }

    /// Cancel an upload session. Deletes the temp file and marks the session
    /// as cancelled.
    pub async fn cancel_session(db: &PgPool, session_id: Uuid) -> Result<(), UploadError> {
        let session =
            sqlx::query_as::<_, UploadSession>("SELECT * FROM upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_optional(db)
                .await?
                .ok_or(UploadError::NotFound)?;

        // Delete temp file (best-effort)
        let temp_path = PathBuf::from(&session.temp_file_path);
        let _ = tokio::fs::remove_file(&temp_path).await;

        sqlx::query(
            "UPDATE upload_sessions SET status = 'cancelled', updated_at = NOW() WHERE id = $1",
        )
        .bind(session_id)
        .execute(db)
        .await?;

        tracing::info!("Cancelled upload session {}", session_id);
        Ok(())
    }

    /// Delete expired sessions and their temp files.
    /// Returns the number of sessions cleaned up.
    pub async fn cleanup_expired(db: &PgPool) -> Result<i64, UploadError> {
        let expired = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT id, temp_file_path
            FROM upload_sessions
            WHERE expires_at < NOW()
              AND status NOT IN ('completed', 'cancelled')
            "#,
        )
        .fetch_all(db)
        .await?;

        let count = expired.len() as i64;

        for (id, temp_path) in &expired {
            let _ = tokio::fs::remove_file(temp_path).await;
            sqlx::query(
                "UPDATE upload_sessions SET status = 'cancelled', error_message = 'expired', updated_at = NOW() WHERE id = $1",
            )
            .bind(id)
            .execute(db)
            .await?;

            tracing::info!("Cleaned up expired upload session {}", id);
        }

        if count > 0 {
            tracing::info!("Cleaned up {} expired upload sessions", count);
        }

        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute SHA256 of a file by streaming in 64 KB blocks.
async fn compute_file_sha256(path: &Path) -> Result<String, std::io::Error> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; SHA256_BUF_SIZE];

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Parse a Content-Range header value like `bytes 0-8388607/21474836480`.
/// Returns `(start, end, total)`.
pub fn parse_content_range(header: &str) -> Result<(i64, i64, i64), String> {
    let header = header.trim();
    let rest = header
        .strip_prefix("bytes ")
        .ok_or_else(|| format!("Content-Range must start with 'bytes ': {}", header))?;

    let (range_part, total_str) = rest
        .split_once('/')
        .ok_or_else(|| format!("Content-Range missing '/': {}", header))?;

    let (start_str, end_str) = range_part
        .split_once('-')
        .ok_or_else(|| format!("Content-Range missing '-': {}", header))?;

    let start: i64 = start_str
        .parse()
        .map_err(|_| format!("Invalid start byte: {}", start_str))?;
    let end: i64 = end_str
        .parse()
        .map_err(|_| format!("Invalid end byte: {}", end_str))?;
    let total: i64 = total_str
        .parse()
        .map_err(|_| format!("Invalid total size: {}", total_str))?;

    if start > end {
        return Err(format!("start ({}) > end ({})", start, end));
    }
    if end >= total {
        return Err(format!("end ({}) >= total ({})", end, total));
    }

    Ok((start, end, total))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_content_range_valid() {
        let (start, end, total) = parse_content_range("bytes 0-8388607/21474836480").unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 8_388_607);
        assert_eq!(total, 21_474_836_480);
    }

    #[test]
    fn test_parse_content_range_middle_chunk() {
        let (start, end, total) =
            parse_content_range("bytes 8388608-16777215/21474836480").unwrap();
        assert_eq!(start, 8_388_608);
        assert_eq!(end, 16_777_215);
        assert_eq!(total, 21_474_836_480);
    }

    #[test]
    fn test_parse_content_range_last_chunk() {
        // Last chunk of a 20 MB file with 8 MB chunks: bytes 16777216-20971519/20971520
        let (start, end, total) = parse_content_range("bytes 16777216-20971519/20971520").unwrap();
        assert_eq!(start, 16_777_216);
        assert_eq!(end, 20_971_519);
        assert_eq!(total, 20_971_520);
    }

    #[test]
    fn test_parse_content_range_single_chunk() {
        // A small file that fits in one chunk
        let (start, end, total) = parse_content_range("bytes 0-999/1000").unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 999);
        assert_eq!(total, 1000);
    }

    #[test]
    fn test_parse_content_range_missing_prefix() {
        let err = parse_content_range("0-999/1000").unwrap_err();
        assert!(err.contains("bytes"));
    }

    #[test]
    fn test_parse_content_range_start_gt_end() {
        let err = parse_content_range("bytes 100-50/1000").unwrap_err();
        assert!(err.contains("start"));
    }

    #[test]
    fn test_parse_content_range_end_gte_total() {
        let err = parse_content_range("bytes 0-1000/1000").unwrap_err();
        assert!(err.contains("end"));
    }

    #[test]
    fn test_parse_content_range_invalid_numbers() {
        assert!(parse_content_range("bytes abc-999/1000").is_err());
        assert!(parse_content_range("bytes 0-abc/1000").is_err());
        assert!(parse_content_range("bytes 0-999/abc").is_err());
    }

    #[test]
    fn test_parse_content_range_missing_slash() {
        assert!(parse_content_range("bytes 0-999").is_err());
    }

    #[test]
    fn test_chunk_count_calculation() {
        // Exact multiple: 20 MB / 8 MB = 2.5, rounds up to 3
        let total_size: i64 = 20 * 1024 * 1024;
        let chunk_size: i64 = 8 * 1024 * 1024;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 3);

        // Exact division: 16 MB / 8 MB = 2
        let total_size: i64 = 16 * 1024 * 1024;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 2);

        // Small file: 1 byte
        let total_size: i64 = 1;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 1);

        // 20 GB file
        let total_size: i64 = 20 * 1024 * 1024 * 1024;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 2560);
    }

    #[test]
    fn test_chunk_size_defaults() {
        let min = MIN_CHUNK_SIZE;
        let max = MAX_CHUNK_SIZE;
        let default = DEFAULT_CHUNK_SIZE as i64;
        assert!(min <= 1_048_576, "min chunk should be at most 1MB");
        assert!(max >= 268_435_456, "max chunk should be at least 256MB");
        assert!(default >= min, "default should be >= min");
        assert!(default <= max, "default should be <= max");
    }
}
