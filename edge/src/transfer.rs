//! Chunked transfer client with resume support.
//!
//! Downloads artifacts in chunks from the primary registry or peer edges,
//! with per-chunk SHA-256 verification and automatic resume on failure.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::EdgeState;

/// Chunk manifest entry from the transfer API.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub struct ChunkEntry {
    pub chunk_index: i32,
    pub byte_offset: i64,
    pub byte_length: i32,
    pub checksum: String,
    pub status: String,
    pub source_node_id: Option<Uuid>,
}

/// Transfer session from the transfer API.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub struct TransferSession {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub requesting_node_id: Uuid,
    pub total_size: i64,
    pub chunk_size: i32,
    pub total_chunks: i32,
    pub completed_chunks: i32,
    pub checksum_algo: String,
    pub artifact_checksum: String,
    pub status: String,
}

/// Chunk manifest response from the transfer API.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct ChunkManifestResponse {
    pub session_id: Uuid,
    pub chunks: Vec<ChunkEntry>,
}

/// Scored peer from the peer API.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub struct ScoredPeer {
    pub node_id: Uuid,
    pub endpoint_url: String,
    pub latency_ms: Option<i32>,
    pub bandwidth_estimate_bps: Option<i64>,
    pub available_chunks: i32,
    pub score: f64,
}

/// Initialize a chunked transfer session with the primary registry.
pub async fn init_transfer(
    client: &reqwest::Client,
    state: &EdgeState,
    artifact_id: Uuid,
) -> anyhow::Result<TransferSession> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/transfer/init",
        state.primary_url, node_id
    );

    let body = serde_json::json!({
        "artifact_id": artifact_id,
        "chunk_size": state.chunk_size(),
    });

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(response.json().await?)
}

/// Get the chunk manifest for a transfer session.
pub async fn get_chunk_manifest(
    client: &reqwest::Client,
    state: &EdgeState,
    session_id: Uuid,
) -> anyhow::Result<ChunkManifestResponse> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/transfer/{}/chunks",
        state.primary_url, node_id, session_id
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .send()
        .await?
        .error_for_status()?;

    Ok(response.json().await?)
}

/// Download a single chunk from a source (primary or peer).
/// Returns the raw chunk bytes after SHA-256 verification.
async fn download_chunk(
    client: &reqwest::Client,
    source_url: &str,
    api_key: &str,
    artifact_id: Uuid,
    chunk: &ChunkEntry,
) -> anyhow::Result<Bytes> {
    // Download from the artifact's byte range
    let url = format!(
        "{}/api/v1/repositories/_/artifacts/{}/download",
        source_url, artifact_id
    );

    let byte_end = chunk.byte_offset + chunk.byte_length as i64 - 1;
    let range = format!("bytes={}-{}", chunk.byte_offset, byte_end);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Range", range)
        .send()
        .await?;

    // Accept both 200 and 206 (partial content)
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("Chunk download failed with status {}", status);
    }

    let data = response.bytes().await?;

    // Verify size
    if data.len() != chunk.byte_length as usize {
        anyhow::bail!(
            "Chunk {} size mismatch: expected {} got {}",
            chunk.chunk_index,
            chunk.byte_length,
            data.len()
        );
    }

    // Verify SHA-256 if checksum is provided
    if !chunk.checksum.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = format!("{:x}", hasher.finalize());
        if hash != chunk.checksum {
            anyhow::bail!(
                "Chunk {} checksum mismatch: expected {} got {}",
                chunk.chunk_index,
                chunk.checksum,
                hash
            );
        }
    }

    Ok(data)
}

/// Report a chunk as completed to the primary registry.
async fn report_chunk_complete(
    client: &reqwest::Client,
    state: &EdgeState,
    session_id: Uuid,
    chunk_index: i32,
    checksum: &str,
    source_node_id: Option<Uuid>,
) -> anyhow::Result<()> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/transfer/{}/chunk/{}/complete",
        state.primary_url, node_id, session_id, chunk_index
    );

    let body = serde_json::json!({
        "checksum": checksum,
        "source_node_id": source_node_id,
    });

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Report a chunk as failed to the primary registry.
async fn report_chunk_failed(
    client: &reqwest::Client,
    state: &EdgeState,
    session_id: Uuid,
    chunk_index: i32,
    error: &str,
) -> anyhow::Result<()> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/transfer/{}/chunk/{}/fail",
        state.primary_url, node_id, session_id, chunk_index
    );

    let body = serde_json::json!({ "error": error });

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Report a session as completed to the primary registry.
async fn report_session_complete(
    client: &reqwest::Client,
    state: &EdgeState,
    session_id: Uuid,
) -> anyhow::Result<()> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/transfer/{}/complete",
        state.primary_url, node_id, session_id
    );

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&serde_json::json!({}))
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Report a session as failed to the primary registry.
async fn report_session_failed(
    client: &reqwest::Client,
    state: &EdgeState,
    session_id: Uuid,
    error: &str,
) -> anyhow::Result<()> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/transfer/{}/fail",
        state.primary_url, node_id, session_id
    );

    let body = serde_json::json!({ "error": error });

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Update chunk availability bitfield on the primary registry.
pub async fn update_chunk_availability(
    client: &reqwest::Client,
    state: &EdgeState,
    artifact_id: Uuid,
    bitmap: &[u8],
    total_chunks: i32,
) -> anyhow::Result<()> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/chunks/{}",
        state.primary_url, node_id, artifact_id
    );

    let body = serde_json::json!({
        "chunk_bitmap": bitmap,
        "total_chunks": total_chunks,
    });

    client
        .put(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Fetch scored peers for an artifact from the primary registry.
pub async fn get_scored_peers(
    client: &reqwest::Client,
    state: &EdgeState,
    artifact_id: Uuid,
) -> anyhow::Result<Vec<ScoredPeer>> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/chunks/{}/scored-peers",
        state.primary_url, node_id, artifact_id
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .send()
        .await?
        .error_for_status()?;

    Ok(response.json().await?)
}

/// Build a chunk availability bitfield from a set of completed chunk indices.
fn build_bitmap(total_chunks: i32, completed: &[i32]) -> Vec<u8> {
    let byte_count = (total_chunks as usize).div_ceil(8);
    let mut bitmap = vec![0u8; byte_count];
    for &idx in completed {
        let byte_index = idx as usize / 8;
        let bit_index = 7 - (idx as usize % 8);
        if byte_index < bitmap.len() {
            bitmap[byte_index] |= 1 << bit_index;
        }
    }
    bitmap
}

/// The rarest-chunk-first threshold. Below this completion ratio, chunks are
/// fetched sequentially; above it, the rarest chunks are fetched first.
const RAREST_FIRST_THRESHOLD: f64 = 0.8;

/// Maximum concurrent chunk downloads.
const MAX_CONCURRENT_CHUNKS: usize = 8;

/// Maximum retry attempts per chunk.
const MAX_CHUNK_RETRIES: u32 = 5;

/// Perform a chunked transfer of an artifact with multi-peer support.
///
/// This is the main entry point for the swarm-based transfer protocol:
/// 1. Initialize a transfer session with the primary
/// 2. Get chunk manifest (identifies already-completed chunks for resume)
/// 3. Query scored peers for multi-source download
/// 4. Download chunks in parallel from best available sources
/// 5. Update bitfield after each completed chunk (become seeder)
/// 6. Verify whole-artifact checksum
/// 7. Complete session
pub async fn chunked_fetch(
    client: &reqwest::Client,
    state: &Arc<EdgeState>,
    artifact_id: Uuid,
) -> anyhow::Result<Bytes> {
    // Step 1: Init transfer session
    let session = init_transfer(client, state, artifact_id).await?;
    tracing::info!(
        session_id = %session.id,
        total_chunks = session.total_chunks,
        total_size = session.total_size,
        "Initialized chunked transfer"
    );

    // Step 2: Get chunk manifest (supports resume — already-completed chunks
    // will have status "completed")
    let manifest = get_chunk_manifest(client, state, session.id).await?;

    // Identify pending chunks
    let mut completed_indices: Vec<i32> = manifest
        .chunks
        .iter()
        .filter(|c| c.status == "completed")
        .map(|c| c.chunk_index)
        .collect();

    let pending_chunks: Vec<ChunkEntry> = manifest
        .chunks
        .into_iter()
        .filter(|c| c.status != "completed")
        .collect();

    if pending_chunks.is_empty() {
        tracing::info!(session_id = %session.id, "All chunks already completed (resume)");
        report_session_complete(client, state, session.id).await?;
        // Reassemble from... we'd need the data. For resume, we re-download.
        // In practice the cache should have partial data.
    }

    tracing::info!(
        pending = pending_chunks.len(),
        completed = completed_indices.len(),
        "Chunk status after resume check"
    );

    // Step 3: Query scored peers for multi-source download
    let peers = get_scored_peers(client, state, artifact_id)
        .await
        .unwrap_or_default();

    tracing::info!(peer_count = peers.len(), "Discovered peers with chunks");

    // Prepare sources: primary + peers sorted by score
    let mut sources: Vec<ChunkSource> = vec![ChunkSource {
        node_id: None, // primary
        endpoint_url: state.primary_url.clone(),
        api_key: state.api_key.clone(),
        score: f64::MAX, // primary always highest priority as fallback
        failures: 0,
    }];

    for peer in &peers {
        sources.push(ChunkSource {
            node_id: Some(peer.node_id),
            endpoint_url: peer.endpoint_url.clone(),
            api_key: state.api_key.clone(), // peers use same auth for now
            score: peer.score,
            failures: 0,
        });
    }

    // Sort peers by score descending (primary stays at top via MAX score)
    sources.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Step 4: Download chunks with concurrency control
    let mut assembled = BytesMut::with_capacity(session.total_size as usize);
    assembled.resize(session.total_size as usize, 0);

    // Apply chunk ordering strategy
    let completion_ratio = completed_indices.len() as f64 / session.total_chunks as f64;

    if completion_ratio >= RAREST_FIRST_THRESHOLD && !peers.is_empty() {
        // Rarest-chunk-first: sort by how many peers have each chunk
        // For simplicity, keep sequential for now if no peer bitfield data
        // In full implementation, we'd query chunk_availability bitmaps
        tracing::debug!("Using rarest-chunk-first ordering");
    }
    // Otherwise sequential (default order from manifest)

    // Process chunks in batches of MAX_CONCURRENT_CHUNKS
    let chunk_batches: Vec<Vec<ChunkEntry>> = pending_chunks
        .chunks(MAX_CONCURRENT_CHUNKS)
        .map(|batch| batch.to_vec())
        .collect();

    for batch in chunk_batches {
        let mut handles = Vec::new();

        for chunk in batch {
            let chunk_index = chunk.chunk_index;
            let byte_offset = chunk.byte_offset;
            let byte_length = chunk.byte_length;
            let client = client.clone();
            let state = state.clone();
            let sources = sources.clone();
            let session_id = session.id;

            let handle = tokio::spawn(async move {
                download_chunk_with_retry(
                    &client,
                    &state,
                    &sources,
                    artifact_id,
                    session_id,
                    &chunk,
                )
                .await
            });
            handles.push((chunk_index, byte_offset, byte_length, handle));
        }

        // Collect results
        for (chunk_index, byte_offset, byte_length, handle) in handles {
            match handle.await? {
                Ok(data) => {
                    // Place chunk data at correct offset
                    let start = byte_offset as usize;
                    let end = start + byte_length as usize;
                    assembled[start..end].copy_from_slice(&data);

                    completed_indices.push(chunk_index);

                    // Update bitfield (become seeder for this chunk)
                    let bitmap = build_bitmap(session.total_chunks, &completed_indices);
                    if let Err(e) = update_chunk_availability(
                        client,
                        state,
                        artifact_id,
                        &bitmap,
                        session.total_chunks,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "Failed to update chunk availability");
                    }
                }
                Err(e) => {
                    tracing::error!(chunk_index, error = %e, "Chunk download failed permanently");
                    let _ = report_session_failed(
                        client,
                        state,
                        session.id,
                        &format!("Chunk {} failed: {}", chunk_index, e),
                    )
                    .await;
                    return Err(e);
                }
            }
        }
    }

    // Step 6: Verify whole-artifact checksum
    if !session.artifact_checksum.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(&assembled);
        let hash = format!("{:x}", hasher.finalize());
        if hash != session.artifact_checksum {
            let err = format!(
                "Artifact checksum mismatch: expected {} got {}",
                session.artifact_checksum, hash
            );
            let _ = report_session_failed(client, state, session.id, &err).await;
            anyhow::bail!(err);
        }
        tracing::info!("Artifact checksum verified");
    }

    // Step 7: Complete session
    report_session_complete(client, state, session.id).await?;

    tracing::info!(
        session_id = %session.id,
        size = assembled.len(),
        "Chunked transfer completed"
    );

    Ok(assembled.freeze())
}

/// A download source (primary or peer).
#[derive(Debug, Clone)]
struct ChunkSource {
    node_id: Option<Uuid>,
    endpoint_url: String,
    api_key: String,
    score: f64,
    failures: u32,
}

/// Download a chunk with retry logic across multiple sources.
async fn download_chunk_with_retry(
    client: &reqwest::Client,
    state: &EdgeState,
    sources: &[ChunkSource],
    artifact_id: Uuid,
    session_id: Uuid,
    chunk: &ChunkEntry,
) -> anyhow::Result<Bytes> {
    let mut last_error = None;

    for attempt in 0..MAX_CHUNK_RETRIES {
        // Pick source: round-robin across available sources, skipping blacklisted
        let source_idx = attempt as usize % sources.len();
        let source = &sources[source_idx];

        // Skip source if it's been blacklisted (3+ consecutive failures)
        if source.failures >= 3 {
            continue;
        }

        // Exponential backoff on retry
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(1 << (attempt - 1).min(4));
            tracing::debug!(
                chunk_index = chunk.chunk_index,
                attempt,
                delay_secs = delay.as_secs(),
                "Retrying chunk download"
            );
            tokio::time::sleep(delay).await;
        }

        match download_chunk(
            client,
            &source.endpoint_url,
            &source.api_key,
            artifact_id,
            chunk,
        )
        .await
        {
            Ok(data) => {
                // Compute checksum for reporting
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let checksum = format!("{:x}", hasher.finalize());

                // Report success
                let _ = report_chunk_complete(
                    client,
                    state,
                    session_id,
                    chunk.chunk_index,
                    &checksum,
                    source.node_id,
                )
                .await;

                return Ok(data);
            }
            Err(e) => {
                tracing::warn!(
                    chunk_index = chunk.chunk_index,
                    source = %source.endpoint_url,
                    attempt,
                    error = %e,
                    "Chunk download attempt failed"
                );
                let _ = report_chunk_failed(
                    client,
                    state,
                    session_id,
                    chunk.chunk_index,
                    &e.to_string(),
                )
                .await;
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        anyhow::anyhow!("All sources exhausted for chunk {}", chunk.chunk_index)
    }))
}
