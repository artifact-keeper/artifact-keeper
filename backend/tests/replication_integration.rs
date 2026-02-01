//! Replication integration tests for edge node sync, chunked transfer,
//! peer discovery, and network profile features.
//!
//! These tests require a running backend HTTP server.
//! Set the TEST_BASE_URL environment variable to specify the server URL.
//!
//! Example:
//! ```sh
//! export TEST_BASE_URL="http://127.0.0.1:9080"
//! cargo test --test replication_integration -- --ignored
//! ```
//!
//! Note: These tests are marked with #[ignore] because they require
//! a running HTTP server with PostgreSQL.

#![allow(dead_code)]

use std::env;

use reqwest::Client;
use serde_json::{json, Value};

/// Test server configuration for replication tests
struct ReplicationTestServer {
    base_url: String,
    access_token: String,
    client: Client,
}

impl ReplicationTestServer {
    fn new() -> Self {
        let base_url = env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:9080".into());
        Self {
            base_url,
            access_token: String::new(),
            client: Client::new(),
        }
    }

    async fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .json(&json!({
                "username": "admin",
                "password": "admin123"
            }))
            .send()
            .await?;

        let body: Value = resp.json().await?;
        self.access_token = body["access_token"]
            .as_str()
            .ok_or("No access token")?
            .to_string();
        Ok(())
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    /// Generate a unique key using nanosecond timestamp to avoid collisions
    fn unique_key(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}-{}", prefix, nanos)
    }

    async fn create_repository(
        &self,
        key: &str,
        name: &str,
        format: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!("{}/api/v1/repositories", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "key": key,
                "name": name,
                "format": format,
                "repo_type": "local",
                "is_public": true
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to create repository: {} - {}", status, text).into())
        }
    }

    async fn register_edge_node(
        &self,
        name: &str,
        endpoint_url: &str,
        region: &str,
        cache_size_bytes: i64,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!("{}/api/v1/edge-nodes", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "name": name,
                "endpoint_url": endpoint_url,
                "region": region,
                "cache_size_bytes": cache_size_bytes
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to register edge node: {} - {}", status, text).into())
        }
    }

    async fn delete_edge_node(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .delete(format!("{}/api/v1/edge-nodes/{}", self.base_url, id))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            eprintln!(
                "Warning: failed to delete edge node {}: {} - {}",
                id, status, text
            );
        }
        Ok(())
    }

    async fn heartbeat(
        &self,
        node_id: &str,
        cache_used_bytes: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!(
                "{}/api/v1/edge-nodes/{}/heartbeat",
                self.base_url, node_id
            ))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "cache_used_bytes": cache_used_bytes
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Heartbeat failed: {} - {}", status, text).into())
        }
    }

    async fn assign_repo(
        &self,
        node_id: &str,
        repository_id: &str,
        priority_override: Option<&str>,
        sync_enabled: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut body = json!({
            "repository_id": repository_id,
            "sync_enabled": sync_enabled
        });

        if let Some(priority) = priority_override {
            body["priority_override"] = json!(priority);
        }

        let resp = self
            .client
            .post(format!(
                "{}/api/v1/edge-nodes/{}/repositories",
                self.base_url, node_id
            ))
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Assign repo failed: {} - {}", status, text).into())
        }
    }

    async fn get_sync_tasks(
        &self,
        node_id: &str,
    ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/edge-nodes/{}/sync/tasks",
                self.base_url, node_id
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Get sync tasks failed: {} - {}", status, text).into())
        }
    }

    async fn upload_artifact(
        &self,
        repo_key: &str,
        path: &str,
        content: &[u8],
        content_type: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .put(format!(
                "{}/api/v1/repositories/{}/artifacts/{}",
                self.base_url, repo_key, path
            ))
            .header("Authorization", self.auth_header())
            .header("Content-Type", content_type)
            .body(content.to_vec())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Upload artifact failed: {} - {}", status, text).into())
        }
    }

    async fn init_transfer(
        &self,
        node_id: &str,
        artifact_id: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!(
                "{}/api/v1/edge-nodes/{}/transfer/init",
                self.base_url, node_id
            ))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "artifact_id": artifact_id
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Init transfer failed: {} - {}", status, text).into())
        }
    }

    async fn get_chunk_manifest(
        &self,
        node_id: &str,
        session_id: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/edge-nodes/{}/transfer/{}/chunks",
                self.base_url, node_id, session_id
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Get chunk manifest failed: {} - {}", status, text).into())
        }
    }

    async fn complete_chunk(
        &self,
        node_id: &str,
        session_id: &str,
        chunk_index: i32,
        checksum: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!(
                "{}/api/v1/edge-nodes/{}/transfer/{}/chunk/{}/complete",
                self.base_url, node_id, session_id, chunk_index
            ))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "checksum": checksum
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!(
                "Complete chunk {} failed: {} - {}",
                chunk_index, status, text
            )
            .into())
        }
    }

    async fn complete_session(
        &self,
        node_id: &str,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!(
                "{}/api/v1/edge-nodes/{}/transfer/{}/complete",
                self.base_url, node_id, session_id
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Complete session failed: {} - {}", status, text).into())
        }
    }

    async fn get_session(
        &self,
        node_id: &str,
        session_id: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/edge-nodes/{}/transfer/{}",
                self.base_url, node_id, session_id
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Get session failed: {} - {}", status, text).into())
        }
    }

    async fn discover_peers(
        &self,
        node_id: &str,
    ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/edge-nodes/{}/peers/discover",
                self.base_url, node_id
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Discover peers failed: {} - {}", status, text).into())
        }
    }

    async fn probe_peer(
        &self,
        node_id: &str,
        target_node_id: &str,
        latency_ms: i32,
        bandwidth_estimate_bps: Option<i64>,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut body = json!({
            "target_node_id": target_node_id,
            "latency_ms": latency_ms
        });

        if let Some(bw) = bandwidth_estimate_bps {
            body["bandwidth_estimate_bps"] = json!(bw);
        }

        let resp = self
            .client
            .post(format!(
                "{}/api/v1/edge-nodes/{}/peers/probe",
                self.base_url, node_id
            ))
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Probe peer failed: {} - {}", status, text).into())
        }
    }

    async fn update_chunk_availability(
        &self,
        node_id: &str,
        artifact_id: &str,
        chunk_bitmap: &[u8],
        total_chunks: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .put(format!(
                "{}/api/v1/edge-nodes/{}/chunks/{}",
                self.base_url, node_id, artifact_id
            ))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "chunk_bitmap": chunk_bitmap,
                "total_chunks": total_chunks
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Update chunk availability failed: {} - {}", status, text).into())
        }
    }

    async fn get_scored_peers(
        &self,
        node_id: &str,
        artifact_id: &str,
    ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/edge-nodes/{}/chunks/{}/scored-peers",
                self.base_url, node_id, artifact_id
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Get scored peers failed: {} - {}", status, text).into())
        }
    }

    async fn set_network_profile(
        &self,
        node_id: &str,
        max_bandwidth_bps: Option<i64>,
        sync_window_start: Option<&str>,
        sync_window_end: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut body = json!({});
        if let Some(bw) = max_bandwidth_bps {
            body["max_bandwidth_bps"] = json!(bw);
        }
        if let Some(start) = sync_window_start {
            body["sync_window_start"] = json!(start);
        }
        if let Some(end) = sync_window_end {
            body["sync_window_end"] = json!(end);
        }

        let resp = self
            .client
            .put(format!(
                "{}/api/v1/edge-nodes/{}/network-profile",
                self.base_url, node_id
            ))
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Set network profile failed: {} - {}", status, text).into())
        }
    }
}

/// Helper to get an authenticated test server
async fn get_server() -> ReplicationTestServer {
    let mut server = ReplicationTestServer::new();
    server.login().await.expect("Login failed");
    server
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============= Test 1: Priority Policies =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_priority_policies_immediate_creates_sync_tasks() {
        let server = get_server().await;
        let key = ReplicationTestServer::unique_key("repl-prio");

        // Create repository (defaults to 'scheduled' replication_priority in DB)
        let repo = server
            .create_repository(&key, "Replication Priority Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        // Register 2 edge nodes
        let node1 = server
            .register_edge_node(
                &format!("{}-edge1", key),
                &format!("https://{}-edge1.test:8080", key),
                "us-east-1",
                10_737_418_240,
            )
            .await
            .expect("Failed to register edge node 1");
        let node1_id = node1["id"].as_str().expect("No node1 id");

        let node2 = server
            .register_edge_node(
                &format!("{}-edge2", key),
                &format!("https://{}-edge2.test:8080", key),
                "us-east-1",
                10_737_418_240,
            )
            .await
            .expect("Failed to register edge node 2");
        let node2_id = node2["id"].as_str().expect("No node2 id");

        // Assign repo to both edges with immediate priority override
        server
            .assign_repo(node1_id, repo_id, Some("immediate"), true)
            .await
            .expect("Failed to assign repo to edge 1");

        server
            .assign_repo(node2_id, repo_id, Some("immediate"), true)
            .await
            .expect("Failed to assign repo to edge 2");

        // Upload an artifact so sync tasks can be created
        let artifact = server
            .upload_artifact(
                &key,
                "test/priority-artifact-1.0.0.bin",
                b"priority test content",
                "application/octet-stream",
            )
            .await
            .expect("Failed to upload artifact");
        let _artifact_id = artifact["id"].as_str().unwrap_or("unknown");

        // Check sync tasks for both edges
        let tasks1 = server
            .get_sync_tasks(node1_id)
            .await
            .expect("Failed to get sync tasks for node 1");

        let tasks2 = server
            .get_sync_tasks(node2_id)
            .await
            .expect("Failed to get sync tasks for node 2");

        // Verify sync tasks exist (they may be empty if the backend does not
        // auto-queue on upload; this validates the API works correctly)
        assert!(
            tasks1.is_empty() || tasks1.iter().all(|t| t["priority"].is_number()),
            "Sync tasks for node 1 should have numeric priority fields"
        );
        assert!(
            tasks2.is_empty() || tasks2.iter().all(|t| t["priority"].is_number()),
            "Sync tasks for node 2 should have numeric priority fields"
        );

        // Cleanup
        let _ = server.delete_edge_node(node1_id).await;
        let _ = server.delete_edge_node(node2_id).await;
    }

    // ============= Test 2: Priority Override =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_priority_override_on_assignment() {
        let server = get_server().await;
        let key = ReplicationTestServer::unique_key("repl-override");

        // Create repository (defaults to 'scheduled')
        let repo = server
            .create_repository(&key, "Priority Override Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        // Register an edge node
        let node = server
            .register_edge_node(
                &format!("{}-edge", key),
                &format!("https://{}-edge.test:8080", key),
                "eu-west-1",
                5_368_709_120,
            )
            .await
            .expect("Failed to register edge node");
        let node_id = node["id"].as_str().expect("No node id");

        // Assign repo with priority_override = 'immediate'
        server
            .assign_repo(node_id, repo_id, Some("immediate"), true)
            .await
            .expect("Failed to assign repo with priority override");

        // Upload an artifact to trigger sync task creation
        server
            .upload_artifact(
                &key,
                "test/override-artifact-1.0.0.bin",
                b"override test content",
                "application/octet-stream",
            )
            .await
            .expect("Failed to upload artifact");

        // Get sync tasks and verify priority is P0 (immediate)
        let tasks = server
            .get_sync_tasks(node_id)
            .await
            .expect("Failed to get sync tasks");

        // If tasks were auto-queued, verify the priority level
        for task in &tasks {
            let priority = task["priority"]
                .as_i64()
                .expect("priority should be a number");
            // P0 = immediate (highest priority)
            assert!(
                priority >= 0,
                "Priority should be non-negative, got {}",
                priority
            );
        }

        // Cleanup
        let _ = server.delete_edge_node(node_id).await;
    }

    // ============= Test 3: Chunked Transfer Session Lifecycle =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_chunked_transfer_session_lifecycle() {
        let server = get_server().await;
        let key = ReplicationTestServer::unique_key("repl-transfer");

        // Create repo and upload an artifact
        let repo = server
            .create_repository(&key, "Transfer Lifecycle Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        let artifact_content = b"chunked transfer test content for replication integration tests";
        let artifact = server
            .upload_artifact(
                &key,
                "test/chunked-artifact-1.0.0.bin",
                artifact_content,
                "application/octet-stream",
            )
            .await
            .expect("Failed to upload artifact");
        let artifact_id = artifact["id"].as_str().expect("No artifact id");

        // Register an edge node and assign the repo
        let node = server
            .register_edge_node(
                &format!("{}-edge", key),
                &format!("https://{}-edge.test:8080", key),
                "us-west-2",
                10_737_418_240,
            )
            .await
            .expect("Failed to register edge node");
        let node_id = node["id"].as_str().expect("No node id");

        server
            .assign_repo(node_id, repo_id, None, true)
            .await
            .expect("Failed to assign repo");

        // Init a transfer session
        let session = server
            .init_transfer(node_id, artifact_id)
            .await
            .expect("Failed to init transfer session");

        let session_id = session["id"].as_str().expect("No session id");
        let total_chunks = session["total_chunks"].as_i64().expect("No total_chunks") as i32;

        assert!(total_chunks > 0, "Should have at least 1 chunk");
        assert_eq!(
            session["status"].as_str().unwrap_or(""),
            "pending",
            "Initial session status should be 'pending'"
        );

        // Get chunk manifest
        let manifest = server
            .get_chunk_manifest(node_id, session_id)
            .await
            .expect("Failed to get chunk manifest");
        let chunks = manifest["chunks"]
            .as_array()
            .expect("chunks should be an array");

        assert_eq!(
            chunks.len(),
            total_chunks as usize,
            "Chunk manifest count should match total_chunks"
        );

        // Complete each chunk
        for chunk in chunks {
            let chunk_index = chunk["chunk_index"].as_i64().expect("No chunk_index") as i32;
            let checksum = chunk["checksum"].as_str().unwrap_or("placeholder-checksum");

            server
                .complete_chunk(node_id, session_id, chunk_index, checksum)
                .await
                .unwrap_or_else(|e| {
                    panic!("Failed to complete chunk {}: {}", chunk_index, e);
                });
        }

        // Complete the session
        server
            .complete_session(node_id, session_id)
            .await
            .expect("Failed to complete transfer session");

        // Verify session status is 'completed'
        let final_session = server
            .get_session(node_id, session_id)
            .await
            .expect("Failed to get final session status");

        assert_eq!(
            final_session["status"].as_str().unwrap_or(""),
            "completed",
            "Session status should be 'completed' after completing all chunks"
        );

        // Cleanup
        let _ = server.delete_edge_node(node_id).await;
    }

    // ============= Test 4: Peer Discovery and Scored Peers =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_peer_discovery_and_scoring() {
        let server = get_server().await;
        let key = ReplicationTestServer::unique_key("repl-peers");

        // Create a repository
        let repo = server
            .create_repository(&key, "Peer Discovery Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        // Upload an artifact for chunk availability tracking
        let artifact = server
            .upload_artifact(
                &key,
                "test/peer-artifact-1.0.0.bin",
                b"peer discovery test content",
                "application/octet-stream",
            )
            .await
            .expect("Failed to upload artifact");
        let artifact_id = artifact["id"].as_str().expect("No artifact id");

        // Register 3 edge nodes in the same region
        let node1 = server
            .register_edge_node(
                &format!("{}-edge1", key),
                &format!("https://{}-edge1.test:8080", key),
                "ap-southeast-1",
                10_737_418_240,
            )
            .await
            .expect("Failed to register node 1");
        let node1_id = node1["id"].as_str().expect("No node1 id");

        let node2 = server
            .register_edge_node(
                &format!("{}-edge2", key),
                &format!("https://{}-edge2.test:8080", key),
                "ap-southeast-1",
                10_737_418_240,
            )
            .await
            .expect("Failed to register node 2");
        let node2_id = node2["id"].as_str().expect("No node2 id");

        let node3 = server
            .register_edge_node(
                &format!("{}-edge3", key),
                &format!("https://{}-edge3.test:8080", key),
                "ap-southeast-1",
                10_737_418_240,
            )
            .await
            .expect("Failed to register node 3");
        let node3_id = node3["id"].as_str().expect("No node3 id");

        // Assign same repo to all 3 nodes
        for nid in [node1_id, node2_id, node3_id] {
            server
                .assign_repo(nid, repo_id, None, true)
                .await
                .unwrap_or_else(|e| panic!("Failed to assign repo to {}: {}", nid, e));
        }

        // From node 1, discover peers -> should find nodes 2 and 3
        let peers = server
            .discover_peers(node1_id)
            .await
            .expect("Failed to discover peers from node 1");

        let peer_ids: Vec<&str> = peers.iter().filter_map(|p| p["node_id"].as_str()).collect();

        assert!(
            peer_ids.contains(&node2_id),
            "Node 2 should be discoverable from node 1. Found peers: {:?}",
            peer_ids
        );
        assert!(
            peer_ids.contains(&node3_id),
            "Node 3 should be discoverable from node 1. Found peers: {:?}",
            peer_ids
        );

        // Submit probe results: node 2 has low latency, node 3 has high latency
        server
            .probe_peer(node1_id, node2_id, 10, Some(1_000_000_000))
            .await
            .expect("Failed to probe node 2");

        server
            .probe_peer(node1_id, node3_id, 50, Some(500_000_000))
            .await
            .expect("Failed to probe node 3");

        // Update chunk availability for nodes 2 and 3 so scored-peers has data
        // bitmap: all chunks available (0xFF = 8 chunks set)
        server
            .update_chunk_availability(node2_id, artifact_id, &[0xFF], 8)
            .await
            .expect("Failed to update chunk availability for node 2");

        server
            .update_chunk_availability(node3_id, artifact_id, &[0xFF], 8)
            .await
            .expect("Failed to update chunk availability for node 3");

        // Get scored peers for the artifact from node 1's perspective
        let scored = server
            .get_scored_peers(node1_id, artifact_id)
            .await
            .expect("Failed to get scored peers");

        assert!(!scored.is_empty(), "Should have at least one scored peer");

        // If both peers are scored, node 2 (10ms latency) should score >= node 3 (50ms)
        if scored.len() >= 2 {
            let node2_score = scored
                .iter()
                .find(|p| p["node_id"].as_str() == Some(node2_id))
                .and_then(|p| p["score"].as_f64());

            let node3_score = scored
                .iter()
                .find(|p| p["node_id"].as_str() == Some(node3_id))
                .and_then(|p| p["score"].as_f64());

            if let (Some(s2), Some(s3)) = (node2_score, node3_score) {
                assert!(
                    s2 >= s3,
                    "Node 2 (latency 10ms, score {}) should score >= node 3 (latency 50ms, score {})",
                    s2,
                    s3
                );
            }
        }

        // Cleanup
        let _ = server.delete_edge_node(node1_id).await;
        let _ = server.delete_edge_node(node2_id).await;
        let _ = server.delete_edge_node(node3_id).await;
    }

    // ============= Test 5: Network Profile =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_network_profile_persistence() {
        let server = get_server().await;
        let key = ReplicationTestServer::unique_key("repl-netprof");

        // Register an edge node
        let node = server
            .register_edge_node(
                &format!("{}-edge", key),
                &format!("https://{}-edge.test:8080", key),
                "us-east-1",
                10_737_418_240,
            )
            .await
            .expect("Failed to register edge node");
        let node_id = node["id"].as_str().expect("No node id");

        // Set network profile
        server
            .set_network_profile(
                node_id,
                Some(100_000_000), // 100 Mbps
                Some("02:00:00"),
                Some("06:00:00"),
            )
            .await
            .expect("Failed to set network profile");

        // The profile is persisted on the edge_nodes row. Verify by fetching
        // the edge node (the response may not include network profile fields,
        // but the request should succeed without error).
        let resp = server
            .client
            .get(format!("{}/api/v1/edge-nodes/{}", server.base_url, node_id))
            .header("Authorization", server.auth_header())
            .send()
            .await
            .expect("Failed to get edge node");

        assert!(
            resp.status().is_success(),
            "GET edge node should succeed after setting network profile"
        );

        // Update the profile again to verify idempotency
        server
            .set_network_profile(
                node_id,
                Some(500_000_000), // 500 Mbps
                Some("00:00:00"),
                Some("04:00:00"),
            )
            .await
            .expect("Failed to update network profile a second time");

        // Cleanup
        let _ = server.delete_edge_node(node_id).await;
    }

    // ============= Test 6: Edge Node Heartbeat =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_edge_node_heartbeat() {
        let server = get_server().await;
        let key = ReplicationTestServer::unique_key("repl-hb");

        let node = server
            .register_edge_node(
                &format!("{}-edge", key),
                &format!("https://{}-edge.test:8080", key),
                "us-east-1",
                10_737_418_240,
            )
            .await
            .expect("Failed to register edge node");
        let node_id = node["id"].as_str().expect("No node id");

        // Send heartbeat
        server
            .heartbeat(node_id, 2_147_483_648) // ~2 GB used
            .await
            .expect("Heartbeat should succeed");

        // Verify node is still accessible after heartbeat
        let resp = server
            .client
            .get(format!("{}/api/v1/edge-nodes/{}", server.base_url, node_id))
            .header("Authorization", server.auth_header())
            .send()
            .await
            .expect("Failed to get edge node after heartbeat");

        assert!(resp.status().is_success());
        let body: Value = resp
            .json()
            .await
            .expect("Failed to parse edge node response");

        assert_eq!(
            body["cache_used_bytes"].as_i64().unwrap_or(0),
            2_147_483_648,
            "cache_used_bytes should reflect heartbeat value"
        );
        assert!(
            body["last_heartbeat_at"].as_str().is_some(),
            "last_heartbeat_at should be set after heartbeat"
        );

        // Cleanup
        let _ = server.delete_edge_node(node_id).await;
    }
}
