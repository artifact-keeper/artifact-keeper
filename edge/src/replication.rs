//! Peer-first artifact replication.
//!
//! Implements edge-to-edge replication by trying nearby peers before
//! falling back to the primary registry. This reduces load on the
//! primary and improves fetch latency when a peer already has the
//! artifact cached.

use std::sync::Arc;

use bytes::Bytes;
use uuid::Uuid;

use crate::EdgeState;

/// Fetch an artifact, trying peers first, then falling back to primary.
///
/// Strategy:
/// 1. Check local cache
/// 2. Query scored peers from primary API
/// 3. Try peers in score order (highest first)
/// 4. Fall back to primary (using chunked transfer for large artifacts)
pub async fn fetch_with_peer_fallback(
    client: &reqwest::Client,
    state: &Arc<EdgeState>,
    artifact_id: Uuid,
    artifact_size: i64,
    cache_key: &str,
) -> anyhow::Result<Bytes> {
    // 1. Check local cache
    if let Some(cached) = state.cache.get(cache_key) {
        tracing::debug!(cache_key, "Peer-first fetch: cache hit");
        return Ok(cached);
    }

    // 2. Query scored peers from primary
    let peers = match crate::transfer::get_scored_peers(client, state, artifact_id).await {
        Ok(peers) => peers,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to get scored peers, falling back to primary");
            Vec::new()
        }
    };

    // 3. Try peers in score order (highest first)
    let mut sorted_peers = peers;
    sorted_peers.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for peer in &sorted_peers {
        let peer_url = format!(
            "{}/peer/v1/artifacts/{}/download",
            peer.endpoint_url, artifact_id
        );

        tracing::debug!(
            peer_node_id = %peer.node_id,
            peer_url = %peer.endpoint_url,
            score = peer.score,
            "Trying peer for artifact"
        );

        match client.get(&peer_url).send().await {
            Ok(response) if response.status().is_success() => match response.bytes().await {
                Ok(data) => {
                    tracing::info!(
                        peer_node_id = %peer.node_id,
                        size = data.len(),
                        "Fetched artifact from peer"
                    );
                    state.cache.put(cache_key.to_owned(), data.clone());
                    return Ok(data);
                }
                Err(e) => {
                    tracing::warn!(
                        peer_node_id = %peer.node_id,
                        error = %e,
                        "Failed to read peer response body"
                    );
                }
            },
            Ok(response) => {
                tracing::debug!(
                    peer_node_id = %peer.node_id,
                    status = %response.status(),
                    "Peer did not have artifact"
                );
            }
            Err(e) => {
                tracing::warn!(
                    peer_node_id = %peer.node_id,
                    error = %e,
                    "Failed to connect to peer"
                );
            }
        }
    }

    // 4. Fall back to primary (chunked transfer for large artifacts)
    tracing::info!("All peers exhausted, falling back to primary");
    let data = crate::sync::fetch_artifact_by_id(client, state, artifact_id, artifact_size).await?;
    state.cache.put(cache_key.to_owned(), data.clone());
    Ok(data)
}
