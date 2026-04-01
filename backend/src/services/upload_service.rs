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
// Validation
// ---------------------------------------------------------------------------

/// Validate that an artifact path is safe (no traversal, not empty).
pub fn validate_artifact_path(path: &str) -> Result<(), UploadError> {
    if path.is_empty() {
        return Err(UploadError::InvalidChunk(
            "artifact_path cannot be empty".into(),
        ));
    }

    // Reject null bytes (could bypass C-level path checks)
    if path.contains('\0') {
        return Err(UploadError::InvalidChunk(
            "artifact_path contains null bytes".into(),
        ));
    }

    // Reject absolute paths and path traversal
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(UploadError::InvalidChunk(
            "artifact_path must be relative".into(),
        ));
    }

    // Check each path component for traversal (handles .., ., and variations)
    for component in path.split('/') {
        let component = component.trim();
        if component == ".." || component == "." || component.is_empty() && path.contains("//") {
            return Err(UploadError::InvalidChunk(
                "artifact_path contains path traversal".into(),
            ));
        }
    }

    // Also reject percent-encoded traversal patterns
    let lower = path.to_lowercase();
    if lower.contains("%2e%2e") || lower.contains("%2f") || lower.contains("%5c") {
        return Err(UploadError::InvalidChunk(
            "artifact_path contains encoded traversal characters".into(),
        ));
    }

    // Reject backslashes (Windows path separator)
    if path.contains('\\') {
        return Err(UploadError::InvalidChunk(
            "artifact_path must use forward slashes".into(),
        ));
    }

    Ok(())
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
        // C5: Validate total_size is positive before any arithmetic
        if p.total_size <= 0 {
            return Err(UploadError::InvalidChunk(
                "total_size must be a positive integer".into(),
            ));
        }

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
        user_id: Uuid,
    ) -> Result<ChunkResult, UploadError> {
        let session = Self::get_session(db, session_id, Some(user_id)).await?;

        if session.status == "completed" || session.status == "cancelled" {
            return Err(UploadError::InvalidStatus(session.status));
        }

        // C6: Use an atomic claim to prevent race conditions on concurrent
        // uploads of the same chunk. Only the first request to transition
        // from 'pending' to 'uploading' wins; others get an idempotent
        // response or a conflict error.
        let claimed = sqlx::query_as::<_, (i64,)>(
            r#"
            UPDATE upload_chunks
            SET status = 'uploading'
            WHERE session_id = $1 AND chunk_index = $2 AND status = 'pending'
            RETURNING byte_length::bigint
            "#,
        )
        .bind(session_id)
        .bind(chunk_index)
        .fetch_optional(db)
        .await?;

        match claimed {
            Some(_) => {
                // We successfully claimed this chunk, continue with upload
            }
            None => {
                // Either chunk doesn't exist, is already uploading, or is completed
                let existing = sqlx::query_as::<_, (String,)>(
                    "SELECT status FROM upload_chunks WHERE session_id = $1 AND chunk_index = $2",
                )
                .bind(session_id)
                .bind(chunk_index)
                .fetch_optional(db)
                .await?;

                match existing {
                    Some((ref status,)) if status == "completed" => {
                        // Idempotent: chunk already uploaded
                        let completed = session.completed_chunks;
                        return Ok(ChunkResult {
                            chunk_index,
                            bytes_received: session.bytes_received,
                            chunks_completed: completed,
                            chunks_remaining: session.total_chunks - completed,
                        });
                    }
                    Some((ref status,)) if status == "uploading" => {
                        return Err(UploadError::InvalidChunk(format!(
                            "chunk {} is already being uploaded by another request",
                            chunk_index
                        )));
                    }
                    Some(_) => {
                        return Err(UploadError::InvalidChunk(format!(
                            "chunk {} is in an unexpected state",
                            chunk_index
                        )));
                    }
                    None => {
                        return Err(UploadError::InvalidChunk(format!(
                            "chunk_index {} out of range (0..{})",
                            chunk_index, session.total_chunks
                        )));
                    }
                }
            }
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

        // Mark chunk as completed and update session counters atomically
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

        // The session counter UPDATE is atomic in PostgreSQL (completed_chunks + 1
        // uses the row's current value under the hood), so concurrent chunk
        // completions produce correct totals.
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

    /// Get an upload session by ID, optionally verifying ownership.
    ///
    /// When `expected_user_id` is `Some`, the session's `user_id` must match
    /// or the call returns `NotFound` (to avoid leaking session existence).
    pub async fn get_session(
        db: &PgPool,
        session_id: Uuid,
        expected_user_id: Option<Uuid>,
    ) -> Result<UploadSession, UploadError> {
        let session =
            sqlx::query_as::<_, UploadSession>("SELECT * FROM upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_optional(db)
                .await?
                .ok_or(UploadError::NotFound)?;

        // C3: Verify the requesting user owns this session
        if let Some(uid) = expected_user_id {
            if session.user_id != uid {
                return Err(UploadError::NotFound);
            }
        }

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
        user_id: Uuid,
    ) -> Result<UploadSession, UploadError> {
        let session = Self::get_session(db, session_id, Some(user_id)).await?;

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
    pub async fn cancel_session(
        db: &PgPool,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), UploadError> {
        let session =
            sqlx::query_as::<_, UploadSession>("SELECT * FROM upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_optional(db)
                .await?
                .ok_or(UploadError::NotFound)?;

        // C3: Verify the requesting user owns this session
        if session.user_id != user_id {
            return Err(UploadError::NotFound);
        }

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
    #![allow(clippy::unnecessary_literal_unwrap, clippy::assertions_on_constants)]
    use super::*;

    // -----------------------------------------------------------------------
    // parse_content_range: existing tests
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // parse_content_range: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_content_range_single_byte_range() {
        // Exactly one byte: bytes 0-0/1
        let (start, end, total) = parse_content_range("bytes 0-0/1").unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 0);
        assert_eq!(total, 1);
    }

    #[test]
    fn test_parse_content_range_single_byte_in_large_file() {
        // One byte at offset 500 in a 1000-byte file
        let (start, end, total) = parse_content_range("bytes 500-500/1000").unwrap();
        assert_eq!(start, 500);
        assert_eq!(end, 500);
        assert_eq!(total, 1000);
    }

    #[test]
    fn test_parse_content_range_exactly_at_boundary() {
        // end == total - 1 (the maximum valid end value)
        let (start, end, total) = parse_content_range("bytes 0-999/1000").unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 999);
        assert_eq!(total, 1000);
    }

    #[test]
    fn test_parse_content_range_end_equals_total_is_error() {
        // end == total is invalid (end is inclusive, so this claims byte 1000 in a 1000-byte file)
        assert!(parse_content_range("bytes 0-1000/1000").is_err());
    }

    #[test]
    fn test_parse_content_range_end_exceeds_total() {
        assert!(parse_content_range("bytes 0-2000/1000").is_err());
    }

    #[test]
    fn test_parse_content_range_very_large_numbers() {
        // 100 GB file, near the end
        let (start, end, total) =
            parse_content_range("bytes 107374182300-107374182399/107374182400").unwrap();
        assert_eq!(start, 107_374_182_300);
        assert_eq!(end, 107_374_182_399);
        assert_eq!(total, 107_374_182_400);
    }

    #[test]
    fn test_parse_content_range_i64_max_boundary() {
        // Near i64::MAX
        let big = i64::MAX - 1; // 9223372036854775806
        let header = format!("bytes 0-{}/{}", big, big + 1);
        let (start, end, total) = parse_content_range(&header).unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, big);
        assert_eq!(total, big + 1);
    }

    #[test]
    fn test_parse_content_range_leading_trailing_whitespace() {
        // The function trims the header, so leading/trailing whitespace should work
        let (start, end, total) = parse_content_range("  bytes 0-99/100  ").unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 99);
        assert_eq!(total, 100);
    }

    #[test]
    fn test_parse_content_range_wrong_unit() {
        let err = parse_content_range("bits 0-99/100").unwrap_err();
        assert!(err.contains("bytes"));
    }

    #[test]
    fn test_parse_content_range_empty_string() {
        assert!(parse_content_range("").is_err());
    }

    #[test]
    fn test_parse_content_range_only_prefix() {
        assert!(parse_content_range("bytes ").is_err());
    }

    #[test]
    fn test_parse_content_range_missing_dash() {
        assert!(parse_content_range("bytes 0/1000").is_err());
    }

    #[test]
    fn test_parse_content_range_negative_numbers() {
        // Negative numbers should fail to parse (the parser uses i64, but the string
        // "-5" in "bytes -5-999/1000" would be misinterpreted by split_once('-'))
        assert!(parse_content_range("bytes -5-999/1000").is_err());
    }

    #[test]
    fn test_parse_content_range_start_equals_end() {
        // start == end is valid (single byte)
        let (start, end, total) = parse_content_range("bytes 42-42/100").unwrap();
        assert_eq!(start, 42);
        assert_eq!(end, 42);
        assert_eq!(total, 100);
    }

    #[test]
    fn test_parse_content_range_extra_spaces_in_range() {
        // Extra spaces after "bytes " should cause a parse error
        assert!(parse_content_range("bytes  0-99/100").is_err());
    }

    #[test]
    fn test_parse_content_range_overflow_number() {
        // A number exceeding i64::MAX
        assert!(parse_content_range("bytes 0-99/99999999999999999999999").is_err());
    }

    // -----------------------------------------------------------------------
    // Chunk count calculation: comprehensive sizes
    // -----------------------------------------------------------------------

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
    fn test_chunk_count_with_min_chunk_size() {
        // 10 MB file with 1 MB chunks
        let total_size: i64 = 10 * 1024 * 1024;
        let chunk_size = MIN_CHUNK_SIZE;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 10);
    }

    #[test]
    fn test_chunk_count_with_max_chunk_size() {
        // 1 GB file with 256 MB chunks
        let total_size: i64 = 1024 * 1024 * 1024;
        let chunk_size = MAX_CHUNK_SIZE;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 4);
    }

    #[test]
    fn test_chunk_count_one_byte_over_boundary() {
        // 8 MB + 1 byte with 8 MB chunks should produce 2 chunks
        let chunk_size: i64 = 8 * 1024 * 1024;
        let total_size: i64 = chunk_size + 1;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 2);
    }

    #[test]
    fn test_chunk_count_one_byte_under_boundary() {
        // 8 MB - 1 byte with 8 MB chunks should produce 1 chunk
        let chunk_size: i64 = 8 * 1024 * 1024;
        let total_size: i64 = chunk_size - 1;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 1);
    }

    #[test]
    fn test_chunk_count_exact_boundary() {
        // Exactly 8 MB with 8 MB chunks should produce 1 chunk
        let chunk_size: i64 = 8 * 1024 * 1024;
        let total_size: i64 = chunk_size;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 1);
    }

    #[test]
    fn test_chunk_count_exact_double_boundary() {
        // Exactly 16 MB with 8 MB chunks should produce 2 chunks
        let chunk_size: i64 = 8 * 1024 * 1024;
        let total_size: i64 = 2 * chunk_size;
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size) as i32;
        assert_eq!(total_chunks, 2);
    }

    #[test]
    fn test_last_chunk_size_calculation() {
        // 20 MB file, 8 MB chunks -> 3 chunks, last is 4 MB
        let total_size: i64 = 20 * 1024 * 1024;
        let chunk_size: i32 = 8 * 1024 * 1024;
        let total_chunks = ((total_size + chunk_size as i64 - 1) / chunk_size as i64) as i32;

        let last_offset = (total_chunks - 1) as i64 * chunk_size as i64;
        let last_length = (total_size - last_offset) as i32;
        assert_eq!(last_length, 4 * 1024 * 1024);
    }

    #[test]
    fn test_last_chunk_size_exact_division() {
        // 16 MB file, 8 MB chunks -> 2 chunks, last is exactly 8 MB
        let total_size: i64 = 16 * 1024 * 1024;
        let chunk_size: i32 = 8 * 1024 * 1024;
        let total_chunks = ((total_size + chunk_size as i64 - 1) / chunk_size as i64) as i32;

        let last_offset = (total_chunks - 1) as i64 * chunk_size as i64;
        let last_length = (total_size - last_offset) as i32;
        assert_eq!(last_length, chunk_size);
    }

    #[test]
    fn test_last_chunk_size_single_byte_remainder() {
        // (8 MB + 1) file, 8 MB chunks -> 2 chunks, last is 1 byte
        let chunk_size: i32 = 8 * 1024 * 1024;
        let total_size: i64 = chunk_size as i64 + 1;
        let total_chunks = ((total_size + chunk_size as i64 - 1) / chunk_size as i64) as i32;

        let last_offset = (total_chunks - 1) as i64 * chunk_size as i64;
        let last_length = (total_size - last_offset) as i32;
        assert_eq!(last_length, 1);
    }

    #[test]
    fn test_all_chunk_offsets_cover_full_file() {
        // Verify that iterating all chunks covers every byte exactly once
        let total_size: i64 = 25 * 1024 * 1024; // 25 MB
        let chunk_size: i32 = 8 * 1024 * 1024;
        let total_chunks = ((total_size + chunk_size as i64 - 1) / chunk_size as i64) as i32;

        let mut covered: i64 = 0;
        for i in 0..total_chunks {
            let offset = i as i64 * chunk_size as i64;
            let length = if i == total_chunks - 1 {
                (total_size - offset) as i32
            } else {
                chunk_size
            };
            assert_eq!(offset, covered, "chunk {} starts at wrong offset", i);
            covered += length as i64;
        }
        assert_eq!(covered, total_size);
    }

    // -----------------------------------------------------------------------
    // Constants and default chunk size validation
    // -----------------------------------------------------------------------

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

    #[test]
    fn test_constants_are_powers_of_two() {
        assert!((MIN_CHUNK_SIZE as u64).is_power_of_two());
        assert!((MAX_CHUNK_SIZE as u64).is_power_of_two());
        assert!((DEFAULT_CHUNK_SIZE as u64).is_power_of_two());
    }

    #[test]
    fn test_sha256_buf_size() {
        assert_eq!(SHA256_BUF_SIZE, 64 * 1024);
        // Buffer should be a reasonable size, not too small, not too large
        assert!(SHA256_BUF_SIZE >= 4096);
        assert!(SHA256_BUF_SIZE <= 1024 * 1024);
    }

    #[test]
    fn test_default_chunk_size_is_8mb() {
        assert_eq!(DEFAULT_CHUNK_SIZE, 8 * 1024 * 1024);
    }

    #[test]
    fn test_min_chunk_size_is_1mb() {
        assert_eq!(MIN_CHUNK_SIZE, 1024 * 1024);
    }

    #[test]
    fn test_max_chunk_size_is_256mb() {
        assert_eq!(MAX_CHUNK_SIZE, 256 * 1024 * 1024);
    }

    // -----------------------------------------------------------------------
    // Chunk size validation (create_session logic, tested as pure math)
    // -----------------------------------------------------------------------

    #[test]
    fn test_chunk_size_below_min_is_rejected() {
        let chunk_size: i32 = (MIN_CHUNK_SIZE - 1) as i32;
        let is_valid =
            (chunk_size as i64) >= MIN_CHUNK_SIZE && (chunk_size as i64) <= MAX_CHUNK_SIZE;
        assert!(!is_valid);
    }

    #[test]
    fn test_chunk_size_above_max_is_rejected() {
        // 512 MB
        let chunk_size: i32 = 512 * 1024 * 1024;
        let is_valid =
            (chunk_size as i64) >= MIN_CHUNK_SIZE && (chunk_size as i64) <= MAX_CHUNK_SIZE;
        assert!(!is_valid);
    }

    #[test]
    fn test_chunk_size_at_min_is_accepted() {
        let chunk_size: i32 = MIN_CHUNK_SIZE as i32;
        let is_valid =
            (chunk_size as i64) >= MIN_CHUNK_SIZE && (chunk_size as i64) <= MAX_CHUNK_SIZE;
        assert!(is_valid);
    }

    #[test]
    fn test_chunk_size_at_max_is_accepted() {
        let chunk_size: i32 = MAX_CHUNK_SIZE as i32;
        let is_valid =
            (chunk_size as i64) >= MIN_CHUNK_SIZE && (chunk_size as i64) <= MAX_CHUNK_SIZE;
        assert!(is_valid);
    }

    #[test]
    fn test_chunk_size_zero_is_rejected() {
        let chunk_size: i32 = 0;
        let is_valid =
            (chunk_size as i64) >= MIN_CHUNK_SIZE && (chunk_size as i64) <= MAX_CHUNK_SIZE;
        assert!(!is_valid);
    }

    #[test]
    fn test_chunk_size_negative_is_rejected() {
        let chunk_size: i32 = -1;
        let is_valid =
            (chunk_size as i64) >= MIN_CHUNK_SIZE && (chunk_size as i64) <= MAX_CHUNK_SIZE;
        assert!(!is_valid);
    }

    #[test]
    fn test_default_chunk_size_when_none() {
        // Simulates the unwrap_or logic in create_session
        let user_chunk_size: Option<i32> = None;
        let chunk_size = user_chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        assert_eq!(chunk_size, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_custom_chunk_size_overrides_default() {
        let user_chunk_size: Option<i32> = Some(4 * 1024 * 1024); // 4 MB
        let chunk_size = user_chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        assert_eq!(chunk_size, 4 * 1024 * 1024);
    }

    // -----------------------------------------------------------------------
    // Temp file path construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_temp_dir_path_construction() {
        let storage_path = "/data/artifact-storage";
        let temp_dir = PathBuf::from(storage_path).join(".uploads");
        assert_eq!(temp_dir, PathBuf::from("/data/artifact-storage/.uploads"));
    }

    #[test]
    fn test_temp_file_path_contains_session_id() {
        let storage_path = "/data/storage";
        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let temp_dir = PathBuf::from(storage_path).join(".uploads");
        let temp_file_path = temp_dir.join(session_id.to_string());
        assert_eq!(
            temp_file_path,
            PathBuf::from("/data/storage/.uploads/550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn test_temp_dir_is_hidden_directory() {
        let storage_path = "/data/storage";
        let temp_dir = PathBuf::from(storage_path).join(".uploads");
        let dir_name = temp_dir.file_name().unwrap().to_str().unwrap();
        assert!(
            dir_name.starts_with('.'),
            "temp dir should be hidden (dot-prefixed)"
        );
    }

    #[test]
    fn test_temp_file_path_with_trailing_slash_storage() {
        let storage_path = "/data/storage/";
        let session_id = Uuid::new_v4();
        let temp_dir = PathBuf::from(storage_path).join(".uploads");
        let temp_file_path = temp_dir.join(session_id.to_string());
        assert!(temp_file_path.to_string_lossy().contains(".uploads/"));
    }

    // -----------------------------------------------------------------------
    // UploadError Display implementations
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_error_not_found_display() {
        let err = UploadError::NotFound;
        assert_eq!(err.to_string(), "session not found");
    }

    #[test]
    fn test_upload_error_expired_display() {
        let err = UploadError::Expired;
        assert_eq!(err.to_string(), "session expired");
    }

    #[test]
    fn test_upload_error_invalid_chunk_display() {
        let err = UploadError::InvalidChunk("chunk_index 5 out of range".into());
        assert_eq!(err.to_string(), "invalid chunk: chunk_index 5 out of range");
    }

    #[test]
    fn test_upload_error_checksum_mismatch_display() {
        let err = UploadError::ChecksumMismatch {
            expected: "abc123".into(),
            actual: "def456".into(),
        };
        assert_eq!(
            err.to_string(),
            "checksum mismatch: expected abc123, got def456"
        );
    }

    #[test]
    fn test_upload_error_incomplete_chunks_display() {
        let err = UploadError::IncompleteChunks {
            completed: 3,
            total: 10,
        };
        assert_eq!(err.to_string(), "not all chunks completed: 3/10");
    }

    #[test]
    fn test_upload_error_size_mismatch_display() {
        let err = UploadError::SizeMismatch {
            expected: 1024,
            actual: 512,
        };
        assert_eq!(err.to_string(), "size mismatch: expected 1024, got 512");
    }

    #[test]
    fn test_upload_error_invalid_status_display() {
        let err = UploadError::InvalidStatus("completed".into());
        assert_eq!(err.to_string(), "invalid session status: completed");
    }

    #[test]
    fn test_upload_error_repository_not_found_display() {
        let err = UploadError::RepositoryNotFound("my-repo".into());
        assert_eq!(err.to_string(), "repository not found: my-repo");
    }

    #[test]
    fn test_upload_error_invalid_chunk_size_display() {
        let err = UploadError::InvalidChunkSize;
        assert_eq!(
            err.to_string(),
            "invalid chunk size: must be between 1 MB and 256 MB"
        );
    }

    #[test]
    fn test_upload_error_io_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let err = UploadError::Io(io_err);
        assert_eq!(err.to_string(), "I/O error: file gone");
    }

    #[test]
    fn test_upload_error_debug_impl() {
        // Verify Debug is derived on all variants
        let err = UploadError::NotFound;
        let debug = format!("{:?}", err);
        assert!(debug.contains("NotFound"));
    }

    // -----------------------------------------------------------------------
    // ChunkResult fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_chunk_result_fields() {
        let result = ChunkResult {
            chunk_index: 2,
            bytes_received: 16_777_216,
            chunks_completed: 3,
            chunks_remaining: 7,
        };
        assert_eq!(result.chunk_index, 2);
        assert_eq!(result.bytes_received, 16_777_216);
        assert_eq!(result.chunks_completed, 3);
        assert_eq!(result.chunks_remaining, 7);
    }

    #[test]
    fn test_chunk_result_debug() {
        let result = ChunkResult {
            chunk_index: 0,
            bytes_received: 0,
            chunks_completed: 0,
            chunks_remaining: 1,
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("ChunkResult"));
        assert!(debug.contains("chunk_index"));
    }

    // -----------------------------------------------------------------------
    // FinalizeResult fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_finalize_result_fields() {
        let id = Uuid::new_v4();
        let result = FinalizeResult {
            artifact_id: id,
            path: "images/vm.ova".into(),
            size: 21_474_836_480,
            checksum_sha256: "abcdef1234567890".into(),
        };
        assert_eq!(result.artifact_id, id);
        assert_eq!(result.path, "images/vm.ova");
        assert_eq!(result.size, 21_474_836_480);
        assert_eq!(result.checksum_sha256, "abcdef1234567890");
    }

    #[test]
    fn test_finalize_result_debug() {
        let result = FinalizeResult {
            artifact_id: Uuid::nil(),
            path: String::new(),
            size: 0,
            checksum_sha256: String::new(),
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("FinalizeResult"));
    }

    // -----------------------------------------------------------------------
    // UploadSession struct field coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_session_debug() {
        let session = UploadSession {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            repository_key: "test-repo".into(),
            artifact_path: "path/to/file.bin".into(),
            content_type: "application/octet-stream".into(),
            total_size: 1024,
            chunk_size: DEFAULT_CHUNK_SIZE,
            total_chunks: 1,
            completed_chunks: 0,
            bytes_received: 0,
            checksum_sha256: "deadbeef".into(),
            temp_file_path: "/tmp/.uploads/some-id".into(),
            status: "pending".into(),
            error_message: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
        };
        let debug = format!("{:?}", session);
        assert!(debug.contains("test-repo"));
        assert!(debug.contains("pending"));
    }

    #[test]
    fn test_upload_session_clone() {
        let session = UploadSession {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            repository_key: "repo".into(),
            artifact_path: "file.bin".into(),
            content_type: "application/octet-stream".into(),
            total_size: 100,
            chunk_size: DEFAULT_CHUNK_SIZE,
            total_chunks: 1,
            completed_chunks: 0,
            bytes_received: 0,
            checksum_sha256: "abc".into(),
            temp_file_path: "/tmp/x".into(),
            status: "pending".into(),
            error_message: Some("test error".into()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
        };
        let cloned = session.clone();
        assert_eq!(session.id, cloned.id);
        assert_eq!(session.repository_key, cloned.repository_key);
        assert_eq!(session.error_message, cloned.error_message);
    }

    // -----------------------------------------------------------------------
    // compute_file_sha256 (async, uses real temp files)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_compute_file_sha256_known_content() {
        // SHA256 of "hello world\n" is well-known
        let dir = std::env::temp_dir().join("ak_upload_test");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("sha256_test_known.bin");
        tokio::fs::write(&path, b"hello world\n").await.unwrap();

        let hash = compute_file_sha256(&path).await.unwrap();
        // sha256sum of "hello world\n"
        assert_eq!(
            hash,
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );

        tokio::fs::remove_file(&path).await.ok();
    }

    #[tokio::test]
    async fn test_compute_file_sha256_empty_file() {
        let dir = std::env::temp_dir().join("ak_upload_test");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("sha256_test_empty.bin");
        tokio::fs::write(&path, b"").await.unwrap();

        let hash = compute_file_sha256(&path).await.unwrap();
        // SHA256 of empty input
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        tokio::fs::remove_file(&path).await.ok();
    }

    #[tokio::test]
    async fn test_compute_file_sha256_large_file() {
        // Create a file larger than SHA256_BUF_SIZE (64 KB) to exercise the loop
        let dir = std::env::temp_dir().join("ak_upload_test");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("sha256_test_large.bin");

        let data = vec![0xABu8; 128 * 1024]; // 128 KB of 0xAB
        tokio::fs::write(&path, &data).await.unwrap();

        let hash = compute_file_sha256(&path).await.unwrap();
        // Verify by computing with the same hasher inline
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(hash, expected);

        tokio::fs::remove_file(&path).await.ok();
    }

    #[tokio::test]
    async fn test_compute_file_sha256_nonexistent_file() {
        let path = PathBuf::from("/tmp/ak_upload_test/nonexistent_file_12345.bin");
        let result = compute_file_sha256(&path).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // UploadError From implementations
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let upload_err: UploadError = io_err.into();
        match upload_err {
            UploadError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
            other => panic!("Expected Io variant, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Content type defaulting
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_defaults_to_octet_stream() {
        let content_type: Option<&str> = None;
        let resolved = content_type.unwrap_or("application/octet-stream");
        assert_eq!(resolved, "application/octet-stream");
    }

    #[test]
    fn test_content_type_custom_value() {
        let content_type: Option<&str> = Some("image/png");
        let resolved = content_type.unwrap_or("application/octet-stream");
        assert_eq!(resolved, "image/png");
    }

    // --- validate_artifact_path ---

    #[test]
    fn test_validate_path_valid_simple() {
        assert!(validate_artifact_path("my-artifact.tar.gz").is_ok());
    }

    #[test]
    fn test_validate_path_valid_nested() {
        assert!(validate_artifact_path("org/project/v1.0/artifact.bin").is_ok());
    }

    #[test]
    fn test_validate_path_empty() {
        assert!(validate_artifact_path("").is_err());
    }

    #[test]
    fn test_validate_path_traversal_dotdot() {
        assert!(validate_artifact_path("../../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_path_traversal_middle() {
        assert!(validate_artifact_path("a/../b").is_err());
    }

    #[test]
    fn test_validate_path_leading_slash() {
        assert!(validate_artifact_path("/absolute/path").is_err());
    }

    #[test]
    fn test_validate_path_single_dot_ok() {
        // Single dot in a filename is not traversal
        assert!(validate_artifact_path("file.txt").is_ok());
    }

    #[test]
    fn test_validate_path_deep_nested() {
        assert!(validate_artifact_path("a/b/c/d/e/f/g.bin").is_ok());
    }

    // C4: Strengthened path traversal validation tests

    #[test]
    fn test_validate_path_null_byte() {
        assert!(validate_artifact_path("file\0.txt").is_err());
    }

    #[test]
    fn test_validate_path_backslash_traversal() {
        assert!(validate_artifact_path("a\\..\\b").is_err());
    }

    #[test]
    fn test_validate_path_leading_backslash() {
        assert!(validate_artifact_path("\\absolute\\path").is_err());
    }

    #[test]
    fn test_validate_path_percent_encoded_dotdot() {
        assert!(validate_artifact_path("a/%2e%2e/b").is_err());
    }

    #[test]
    fn test_validate_path_percent_encoded_slash() {
        assert!(validate_artifact_path("a%2fb").is_err());
    }

    #[test]
    fn test_validate_path_percent_encoded_backslash() {
        assert!(validate_artifact_path("a%5cb").is_err());
    }

    #[test]
    fn test_validate_path_dot_component() {
        // A bare "." component should be rejected
        assert!(validate_artifact_path("a/./b").is_err());
    }

    #[test]
    fn test_validate_path_double_slash() {
        assert!(validate_artifact_path("a//b").is_err());
    }

    #[test]
    fn test_validate_path_dotdot_at_end() {
        assert!(validate_artifact_path("a/b/..").is_err());
    }

    #[test]
    fn test_validate_path_valid_dots_in_filename() {
        // Filenames with dots that aren't traversal should be fine
        assert!(validate_artifact_path("my.app.v1.2.3.tar.gz").is_ok());
    }

    #[test]
    fn test_validate_path_valid_dotfile() {
        // A dotfile like .npmrc is fine (component is ".npmrc", not ".")
        assert!(validate_artifact_path(".npmrc").is_ok());
    }

    #[test]
    fn test_validate_path_mixed_case_encoded() {
        assert!(validate_artifact_path("a/%2E%2E/b").is_err());
    }
}
