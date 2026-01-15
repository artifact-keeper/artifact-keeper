//! Sync and heartbeat logic.

use std::time::Duration;

use crate::EdgeState;

/// Send heartbeat to primary registry
pub async fn heartbeat_loop(state: EdgeState) {
    let client = reqwest::Client::new();
    let interval = Duration::from_secs(30);

    loop {
        match send_heartbeat(&client, &state).await {
            Ok(_) => tracing::debug!("Heartbeat sent successfully"),
            Err(e) => tracing::warn!("Heartbeat failed: {}", e),
        }

        tokio::time::sleep(interval).await;
    }
}

async fn send_heartbeat(
    client: &reqwest::Client,
    state: &EdgeState,
) -> anyhow::Result<()> {
    let url = format!("{}/api/v1/edge-nodes/heartbeat", state.primary_url);

    let payload = serde_json::json!({
        "cache_size_bytes": state.cache.size(),
        "cache_entries": state.cache.len(),
    });

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Fetch artifact from primary
pub async fn fetch_from_primary(
    client: &reqwest::Client,
    state: &EdgeState,
    repo_key: &str,
    artifact_path: &str,
) -> anyhow::Result<bytes::Bytes> {
    let url = format!(
        "{}/api/v1/repositories/{}/artifacts/{}/download",
        state.primary_url, repo_key, artifact_path
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .send()
        .await?
        .error_for_status()?;

    Ok(response.bytes().await?)
}
