//! Mesh peer discovery and probing.
//!
//! Discovers nearby edge nodes that share repository assignments,
//! probes them for latency/bandwidth, and maintains the peer graph
//! for swarm-based artifact distribution.

use std::sync::Arc;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::EdgeState;

/// A discoverable peer returned by the discovery API.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DiscoverablePeer {
    pub node_id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub status: String,
}

/// Discover peers that share repository assignments with this edge node.
pub async fn discover_peers(
    client: &reqwest::Client,
    state: &EdgeState,
) -> anyhow::Result<Vec<DiscoverablePeer>> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/peers/discover",
        state.primary_url, node_id
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .send()
        .await?
        .error_for_status()?;

    Ok(response.json().await?)
}

/// Probe a peer's latency by sending an HTTP request to its health endpoint.
/// Returns (latency_ms, estimated_bandwidth_bps).
async fn probe_peer_latency(
    client: &reqwest::Client,
    peer: &DiscoverablePeer,
) -> anyhow::Result<(i32, Option<i64>)> {
    let health_url = format!("{}/health", peer.endpoint_url);

    let start = Instant::now();
    let response = client
        .get(&health_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    let latency = start.elapsed();

    // Read response body to estimate bandwidth
    let body = response.bytes().await?;
    let body_size = body.len() as f64;
    let transfer_time = latency.as_secs_f64();

    // Rough bandwidth estimate from health response (very approximate)
    // A more accurate measurement would use a dedicated bandwidth test endpoint
    let bandwidth_bps = if transfer_time > 0.001 && body_size > 0.0 {
        Some((body_size * 8.0 / transfer_time) as i64)
    } else {
        None
    };

    Ok((latency.as_millis() as i32, bandwidth_bps))
}

/// Report probe results back to the primary registry.
async fn report_probe_result(
    client: &reqwest::Client,
    state: &EdgeState,
    target_node_id: Uuid,
    latency_ms: i32,
    bandwidth_estimate_bps: Option<i64>,
) -> anyhow::Result<()> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/peers/probe",
        state.primary_url, node_id
    );

    let body = serde_json::json!({
        "target_node_id": target_node_id,
        "latency_ms": latency_ms,
        "bandwidth_estimate_bps": bandwidth_estimate_bps,
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

/// Report a peer as unreachable to the primary registry.
async fn report_peer_unreachable(
    client: &reqwest::Client,
    state: &EdgeState,
    target_node_id: Uuid,
) -> anyhow::Result<()> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/peers/{}/unreachable",
        state.primary_url, node_id, target_node_id
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

/// Background loop that periodically discovers and probes peers.
///
/// Runs every 60 seconds when online:
/// 1. Discovers peers sharing repository assignments
/// 2. Probes each peer for latency
/// 3. Reports results (or marks unreachable) to the primary registry
pub async fn peer_discovery_loop(state: Arc<EdgeState>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();

    let discovery_interval = Duration::from_secs(60);

    // Initial delay to let heartbeat establish connection first
    tokio::time::sleep(Duration::from_secs(10)).await;

    loop {
        // Only run discovery when online and we have a node ID
        if !state.is_offline.load(std::sync::atomic::Ordering::SeqCst)
            && state.edge_node_id.read().await.is_some()
        {
            if let Err(e) = run_discovery_cycle(&client, &state).await {
                tracing::warn!(error = %e, "Peer discovery cycle failed");
            }
        }

        tokio::time::sleep(discovery_interval).await;
    }
}

/// Run a single discovery and probe cycle.
async fn run_discovery_cycle(client: &reqwest::Client, state: &EdgeState) -> anyhow::Result<()> {
    let peers = discover_peers(client, state).await?;
    tracing::debug!(count = peers.len(), "Discovered peers");

    for peer in &peers {
        match probe_peer_latency(client, peer).await {
            Ok((latency_ms, bandwidth)) => {
                tracing::debug!(
                    peer = %peer.name,
                    latency_ms,
                    bandwidth_bps = ?bandwidth,
                    "Peer probe succeeded"
                );
                if let Err(e) =
                    report_probe_result(client, state, peer.node_id, latency_ms, bandwidth).await
                {
                    tracing::warn!(peer = %peer.name, error = %e, "Failed to report probe result");
                }
            }
            Err(e) => {
                tracing::debug!(peer = %peer.name, error = %e, "Peer probe failed - marking unreachable");
                let _ = report_peer_unreachable(client, state, peer.node_id).await;
            }
        }
    }

    Ok(())
}
