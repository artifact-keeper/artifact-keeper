//! Transfer session models for chunked artifact replication.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use super::sync_task::SyncStatus;

/// Transfer session entity for chunked artifact transfers.
///
/// Tracks an artifact being transferred to a requesting peer
/// using swarm-based chunked distribution. Each session breaks
/// an artifact into fixed-size chunks that can be sourced from
/// multiple peers in parallel.
#[derive(Debug, Clone, FromRow, Serialize)]
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

/// Individual chunk within a transfer session.
///
/// Each chunk tracks which peer served it, enabling swarm-based
/// distribution where different chunks come from different sources.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct TransferChunk {
    pub id: Uuid,
    pub session_id: Uuid,
    pub chunk_index: i32,
    pub byte_offset: i64,
    pub byte_length: i32,
    pub checksum: String,
    pub status: SyncStatus,
    pub source_peer_id: Option<Uuid>,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub downloaded_at: Option<DateTime<Utc>>,
}

/// Chunk availability bitmap for an artifact on a peer instance.
///
/// Uses a compact bitfield representation where bit N being set
/// indicates the peer has chunk N. For a 500MB artifact with 1MB
/// chunks, this requires only 63 bytes.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ChunkAvailability {
    pub id: Uuid,
    pub peer_instance_id: Uuid,
    pub artifact_id: Uuid,
    pub chunk_bitmap: Vec<u8>,
    pub total_chunks: i32,
    pub available_chunks: i32,
    pub updated_at: DateTime<Utc>,
}

impl ChunkAvailability {
    /// Creates a zero-filled bitmap large enough to hold `total_chunks` bits.
    pub fn new_bitmap(total_chunks: usize) -> Vec<u8> {
        let byte_count = total_chunks.div_ceil(8);
        vec![0u8; byte_count]
    }

    /// Returns `true` if the chunk at `index` is marked as available.
    pub fn has_chunk(&self, index: usize) -> bool {
        let byte_index = index / 8;
        let bit_index = index % 8;

        if byte_index >= self.chunk_bitmap.len() {
            return false;
        }

        self.chunk_bitmap[byte_index] & (1 << bit_index) != 0
    }

    /// Marks the chunk at `index` as available in the bitmap.
    ///
    /// If the chunk was not already set, increments `available_chunks`.
    pub fn set_chunk(&mut self, index: usize) {
        let byte_index = index / 8;
        let bit_index = index % 8;

        if byte_index >= self.chunk_bitmap.len() {
            return;
        }

        let mask = 1 << bit_index;
        if self.chunk_bitmap[byte_index] & mask == 0 {
            self.chunk_bitmap[byte_index] |= mask;
            self.available_chunks += 1;
        }
    }

    /// Returns the indices of all chunks marked as available.
    pub fn available_chunk_indices(&self) -> Vec<usize> {
        let total = self.total_chunks as usize;
        let mut indices = Vec::with_capacity(self.available_chunks as usize);

        for i in 0..total {
            if self.has_chunk(i) {
                indices.push(i);
            }
        }

        indices
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn make_availability(total_chunks: i32) -> ChunkAvailability {
        ChunkAvailability {
            id: Uuid::new_v4(),
            peer_instance_id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            chunk_bitmap: ChunkAvailability::new_bitmap(total_chunks as usize),
            total_chunks,
            available_chunks: 0,
            updated_at: chrono::Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // new_bitmap
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_bitmap_sizes() {
        assert_eq!(ChunkAvailability::new_bitmap(0).len(), 0);
        assert_eq!(ChunkAvailability::new_bitmap(1).len(), 1);
        assert_eq!(ChunkAvailability::new_bitmap(7).len(), 1);
        assert_eq!(ChunkAvailability::new_bitmap(8).len(), 1);
        assert_eq!(ChunkAvailability::new_bitmap(9).len(), 2);
        assert_eq!(ChunkAvailability::new_bitmap(16).len(), 2);
        assert_eq!(ChunkAvailability::new_bitmap(17).len(), 3);
        assert_eq!(ChunkAvailability::new_bitmap(500).len(), 63);
    }

    #[test]
    fn test_new_bitmap_zeroed() {
        let bitmap = ChunkAvailability::new_bitmap(32);
        assert!(bitmap.iter().all(|&b| b == 0));
    }

    // -----------------------------------------------------------------------
    // has_chunk
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_chunk_empty() {
        let avail = make_availability(16);
        for i in 0..16 {
            assert!(!avail.has_chunk(i));
        }
    }

    #[test]
    fn test_has_chunk_out_of_bounds() {
        let avail = make_availability(8);
        assert!(!avail.has_chunk(100)); // beyond bitmap length
    }

    // -----------------------------------------------------------------------
    // set_chunk
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_chunk_basic() {
        let mut avail = make_availability(16);

        avail.set_chunk(0);
        assert!(avail.has_chunk(0));
        assert_eq!(avail.available_chunks, 1);

        avail.set_chunk(7);
        assert!(avail.has_chunk(7));
        assert_eq!(avail.available_chunks, 2);

        avail.set_chunk(15);
        assert!(avail.has_chunk(15));
        assert_eq!(avail.available_chunks, 3);
    }

    #[test]
    fn test_set_chunk_idempotent() {
        let mut avail = make_availability(16);

        avail.set_chunk(5);
        assert_eq!(avail.available_chunks, 1);

        // Setting the same chunk again should not increment
        avail.set_chunk(5);
        assert_eq!(avail.available_chunks, 1);
    }

    #[test]
    fn test_set_chunk_out_of_bounds() {
        let mut avail = make_availability(8);
        let original_count = avail.available_chunks;
        avail.set_chunk(100); // beyond bitmap, should do nothing
        assert_eq!(avail.available_chunks, original_count);
    }

    #[test]
    fn test_set_chunk_all_bits() {
        let mut avail = make_availability(16);
        for i in 0..16 {
            avail.set_chunk(i);
        }
        assert_eq!(avail.available_chunks, 16);
        for i in 0..16 {
            assert!(avail.has_chunk(i));
        }
    }

    // -----------------------------------------------------------------------
    // available_chunk_indices
    // -----------------------------------------------------------------------

    #[test]
    fn test_available_chunk_indices_empty() {
        let avail = make_availability(16);
        assert!(avail.available_chunk_indices().is_empty());
    }

    #[test]
    fn test_available_chunk_indices_some_set() {
        let mut avail = make_availability(16);
        avail.set_chunk(2);
        avail.set_chunk(5);
        avail.set_chunk(10);

        let indices = avail.available_chunk_indices();
        assert_eq!(indices, vec![2, 5, 10]);
    }

    #[test]
    fn test_available_chunk_indices_all_set() {
        let mut avail = make_availability(8);
        for i in 0..8 {
            avail.set_chunk(i);
        }

        let indices = avail.available_chunk_indices();
        assert_eq!(indices, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_available_chunk_indices_boundary_bits() {
        let mut avail = make_availability(9);
        avail.set_chunk(0); // first bit of byte 0
        avail.set_chunk(7); // last bit of byte 0
        avail.set_chunk(8); // first bit of byte 1

        let indices = avail.available_chunk_indices();
        assert_eq!(indices, vec![0, 7, 8]);
    }
}
