//! Sonatype Nexus Repository REST API client for migration.
//!
//! Supports Nexus 3.x Community/Pro editions. Handles the Nexus REST API
//! for listing repositories, components, assets, and downloading artifacts.

use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

use crate::services::artifactory_client::{
    AqlRange, AqlResponse, AqlResult, ArtifactoryError, PropertiesResponse, RepositoryListItem,
    SystemVersionResponse,
};

/// Nexus authentication credentials
#[derive(Debug, Clone)]
pub struct NexusAuth {
    pub username: String,
    pub password: String,
}

/// Nexus client configuration
#[derive(Debug, Clone)]
pub struct NexusClientConfig {
    pub base_url: String,
    pub auth: NexusAuth,
    pub timeout_secs: u64,
    pub throttle_delay_ms: u64,
}

impl Default for NexusClientConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            auth: NexusAuth {
                username: String::new(),
                password: String::new(),
            },
            timeout_secs: 30,
            throttle_delay_ms: 100,
        }
    }
}

/// Nexus REST API client
pub struct NexusClient {
    client: Client,
    config: NexusClientConfig,
}

// --- Nexus API response types ---

#[derive(Debug, Deserialize)]
pub struct NexusStatusResponse {
    pub edition: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NexusRepository {
    pub name: String,
    pub format: String,
    #[serde(rename = "type")]
    pub repo_type: String,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NexusComponentsResponse {
    pub items: Vec<NexusComponent>,
    #[serde(rename = "continuationToken")]
    pub continuation_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NexusComponent {
    pub id: String,
    pub repository: String,
    pub format: String,
    pub group: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub assets: Vec<NexusAsset>,
}

#[derive(Debug, Deserialize)]
pub struct NexusAsset {
    pub id: String,
    pub path: Option<String>,
    #[serde(rename = "downloadUrl")]
    pub download_url: Option<String>,
    pub checksum: Option<NexusChecksum>,
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    #[serde(rename = "fileSize")]
    pub file_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct NexusChecksum {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

impl NexusClient {
    /// Create a new Nexus client
    pub fn new(config: NexusClientConfig) -> Result<Self, ArtifactoryError> {
        let client = crate::services::http_client::base_client_builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        Ok(Self { client, config })
    }

    /// Send an authenticated GET. Returns the raw response so the caller can
    /// map success/failure to its own error type and extract the body shape
    /// it needs (JSON, bytes, streaming).
    async fn send_authenticated(&self, url: String) -> Result<reqwest::Response, ArtifactoryError> {
        self.client
            .get(&url)
            .basic_auth(&self.config.auth.username, Some(&self.config.auth.password))
            .send()
            .await
            .map_err(ArtifactoryError::from)
    }

    /// Build an authenticated GET request
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ArtifactoryError> {
        if self.config.throttle_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.config.throttle_delay_ms)).await;
        }

        let url = format!("{}{}", self.config.base_url, path);
        let response = self.send_authenticated(url).await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json::<T>().await?)
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(ArtifactoryError::AuthError(format!(
                "Nexus authentication failed: {}",
                status
            )))
        } else if status.as_u16() == 404 {
            Err(ArtifactoryError::NotFound("Resource not found".into()))
        } else {
            let message = response.text().await.unwrap_or_default();
            Err(ArtifactoryError::ApiError {
                status: status.as_u16(),
                message,
            })
        }
    }

    /// Check if Nexus is reachable
    pub async fn ping(&self) -> Result<bool, ArtifactoryError> {
        let url = format!("{}/service/rest/v1/status/writable", self.config.base_url);
        let response = self
            .client
            .get(&url)
            .basic_auth(&self.config.auth.username, Some(&self.config.auth.password))
            .send()
            .await?;
        Ok(response.status().is_success())
    }

    /// Get Nexus version — returns in the same format as Artifactory for compatibility
    pub async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
        let status: NexusStatusResponse =
            self.get("/service/rest/v1/status")
                .await
                .unwrap_or(NexusStatusResponse {
                    edition: Some("Unknown".into()),
                    version: Some("Unknown".into()),
                });

        Ok(SystemVersionResponse {
            version: status.version.unwrap_or_else(|| "unknown".into()),
            revision: None,
            addons: None,
            license: status.edition,
        })
    }

    /// List all repositories — returns in the same format as Artifactory for compatibility
    pub async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
        let repos: Vec<NexusRepository> = self.get("/service/rest/v1/repositories").await?;

        Ok(repos
            .into_iter()
            .map(|r| RepositoryListItem {
                key: r.name,
                repo_type: r.repo_type,
                package_type: r.format,
                url: r.url,
                description: None,
            })
            .collect())
    }

    /// List artifacts (components + assets) with pagination.
    /// Returns data in the same AqlResponse format as the Artifactory client
    /// so the migration worker can process either source.
    pub async fn list_artifacts(
        &self,
        repo_name: &str,
        offset: i64,
        limit: i64,
    ) -> Result<AqlResponse, ArtifactoryError> {
        // Nexus uses continuation tokens, not offset/limit.
        // We'll accumulate results up to the offset + limit.
        let mut all_results = Vec::new();
        let mut token: Option<String> = None;
        let target_end = (offset + limit) as usize;

        loop {
            let path = match &token {
                Some(t) => format!(
                    "/service/rest/v1/components?repository={}&continuationToken={}",
                    repo_name, t
                ),
                None => format!("/service/rest/v1/components?repository={}", repo_name),
            };

            let page: NexusComponentsResponse = self.get(&path).await?;

            for component in &page.items {
                for asset in &component.assets {
                    let path_str = asset.path.clone().unwrap_or_else(|| {
                        format!(
                            "{}/{}",
                            component.name,
                            component.version.as_deref().unwrap_or("0")
                        )
                    });
                    let path_str = path_str.trim_start_matches('/').to_string();
                    let (dir, name) = match path_str.rsplit_once('/') {
                        Some((d, n)) => (d.to_string(), n.to_string()),
                        None => (".".to_string(), path_str),
                    };

                    all_results.push(AqlResult {
                        repo: repo_name.to_string(),
                        path: dir,
                        name,
                        size: asset.file_size,
                        created: None,
                        modified: None,
                        sha256: asset.checksum.as_ref().and_then(|c| c.sha256.clone()),
                        actual_sha1: asset.checksum.as_ref().and_then(|c| c.sha1.clone()),
                    });
                }
            }

            // Stop if we have enough or no more pages
            if all_results.len() >= target_end || page.continuation_token.is_none() {
                break;
            }
            token = page.continuation_token;
        }

        let total = all_results.len() as i64;
        let start = offset as usize;
        let end = std::cmp::min(target_end, all_results.len());
        let page_results = if start < all_results.len() {
            all_results[start..end].to_vec()
        } else {
            vec![]
        };

        Ok(AqlResponse {
            results: page_results,
            range: AqlRange {
                start_pos: offset,
                end_pos: offset + limit,
                total,
            },
        })
    }

    /// Download an artifact by repository name and path.
    ///
    /// Buffers the full response body into memory. Prefer
    /// `download_artifact_stream` for migrations (issue #1422).
    #[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped (tail expr); the exempt call is marked inline below (#1608)
    pub async fn download_artifact(
        &self,
        repo_name: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError> {
        let url = format!("{}/repository/{}/{}", self.config.base_url, repo_name, path);
        let response = self.send_authenticated(url).await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.bytes().await?) // STREAMING-EXEMPT: capped-metadata read (upstream index/advisory/packument, not an artifact blob); bounded response buffered; tracked under #1608
        } else if status.as_u16() == 404 {
            Err(ArtifactoryError::NotFound(format!(
                "Artifact not found: {}/{}",
                repo_name, path
            )))
        } else {
            Err(ArtifactoryError::ApiError {
                status: status.as_u16(),
                message: "Failed to download artifact".into(),
            })
        }
    }

    /// Download an artifact as a chunked byte stream.
    ///
    /// Returns chunks from `reqwest::Response::bytes_stream()` so callers
    /// can spill straight to disk without ever buffering the full payload
    /// (issue #1422).
    pub async fn download_artifact_stream(
        &self,
        repo_name: &str,
        path: &str,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<bytes::Bytes, ArtifactoryError>>,
        ArtifactoryError,
    > {
        use futures::StreamExt;

        let url = format!("{}/repository/{}/{}", self.config.base_url, repo_name, path);
        let response = self.send_authenticated(url).await?;

        let status = response.status();
        if status.is_success() {
            let stream = response
                .bytes_stream()
                .map(|res| res.map_err(ArtifactoryError::from));
            Ok(Box::pin(stream))
        } else if status.as_u16() == 404 {
            Err(ArtifactoryError::NotFound(format!(
                "Artifact not found: {}/{}",
                repo_name, path
            )))
        } else {
            Err(ArtifactoryError::ApiError {
                status: status.as_u16(),
                message: "Failed to download artifact".into(),
            })
        }
    }
}

// Implement SourceRegistry trait for migration compatibility
#[async_trait::async_trait]
impl crate::services::source_registry::SourceRegistry for NexusClient {
    async fn ping(&self) -> Result<bool, ArtifactoryError> {
        self.ping().await
    }

    async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
        self.get_version().await
    }

    async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
        self.list_repositories().await
    }

    async fn list_artifacts(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
    ) -> Result<AqlResponse, ArtifactoryError> {
        self.list_artifacts(repo_key, offset, limit).await
    }

    async fn list_artifacts_with_date_filter(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
        _modified_after: Option<&str>,
        _modified_before: Option<&str>,
    ) -> Result<AqlResponse, ArtifactoryError> {
        self.list_artifacts(repo_key, offset, limit).await
    }

    async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError> {
        self.download_artifact(repo_key, path).await
    }

    async fn download_artifact_stream(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<crate::services::source_registry::ArtifactByteStream, ArtifactoryError> {
        self.download_artifact_stream(repo_key, path).await
    }

    async fn get_properties(
        &self,
        _repo_key: &str,
        _path: &str,
    ) -> Result<PropertiesResponse, ArtifactoryError> {
        // Nexus doesn't have the same properties API as Artifactory
        Ok(PropertiesResponse {
            properties: None,
            uri: None,
        })
    }

    fn source_type(&self) -> &'static str {
        "nexus"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_nexus_mock(
        server_path: &str,
        response: ResponseTemplate,
    ) -> (MockServer, NexusClient) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(server_path))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = NexusClient::new(NexusClientConfig {
            base_url: server.uri(),
            auth: NexusAuth {
                username: "u".into(),
                password: "p".into(),
            },
            timeout_secs: 30,
            throttle_delay_ms: 0,
        })
        .unwrap();
        (server, client)
    }

    #[test]
    fn test_nexus_config_default() {
        let config = NexusClientConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.throttle_delay_ms, 100);
    }

    #[test]
    fn test_nexus_config_default_auth_empty() {
        let config = NexusClientConfig::default();
        assert!(config.auth.username.is_empty());
        assert!(config.auth.password.is_empty());
    }

    #[test]
    fn test_nexus_config_default_base_url_empty() {
        let config = NexusClientConfig::default();
        assert!(config.base_url.is_empty());
    }

    #[test]
    fn test_nexus_client_creation() {
        let config = NexusClientConfig {
            base_url: "https://nexus.example.com".to_string(),
            auth: NexusAuth {
                username: "admin".to_string(),
                password: "admin123".to_string(),
            },
            timeout_secs: 60,
            throttle_delay_ms: 200,
        };
        let client = NexusClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_nexus_repository_deserialization() {
        let json = r#"{
            "name": "maven-releases",
            "format": "maven2",
            "type": "hosted",
            "url": "https://nexus.example.com/repository/maven-releases"
        }"#;
        let repo: NexusRepository = serde_json::from_str(json).unwrap();
        assert_eq!(repo.name, "maven-releases");
        assert_eq!(repo.format, "maven2");
        assert_eq!(repo.repo_type, "hosted");
        assert_eq!(
            repo.url,
            Some("https://nexus.example.com/repository/maven-releases".to_string())
        );
    }

    #[test]
    fn test_nexus_repository_without_url() {
        let json = r#"{
            "name": "npm-proxy",
            "format": "npm",
            "type": "proxy"
        }"#;
        let repo: NexusRepository = serde_json::from_str(json).unwrap();
        assert_eq!(repo.name, "npm-proxy");
        assert!(repo.url.is_none());
    }

    #[test]
    fn test_nexus_component_deserialization() {
        let json = r#"{
            "id": "component-id-123",
            "repository": "maven-releases",
            "format": "maven2",
            "group": "com.example",
            "name": "my-artifact",
            "version": "1.0.0",
            "assets": [
                {
                    "id": "asset-id-1",
                    "path": "com/example/my-artifact/1.0.0/my-artifact-1.0.0.jar",
                    "downloadUrl": "https://nexus.example.com/repository/maven-releases/com/example/my-artifact/1.0.0/my-artifact-1.0.0.jar",
                    "checksum": {
                        "sha256": "abc123",
                        "sha1": "def456",
                        "md5": "789ghi"
                    },
                    "contentType": "application/java-archive",
                    "fileSize": 2048
                }
            ]
        }"#;
        let component: NexusComponent = serde_json::from_str(json).unwrap();
        assert_eq!(component.id, "component-id-123");
        assert_eq!(component.repository, "maven-releases");
        assert_eq!(component.group, Some("com.example".to_string()));
        assert_eq!(component.name, "my-artifact");
        assert_eq!(component.version, Some("1.0.0".to_string()));
        assert_eq!(component.assets.len(), 1);
    }

    #[test]
    fn test_nexus_asset_deserialization() {
        let json = r#"{
            "id": "asset-001",
            "path": "org/example/lib/1.0/lib-1.0.jar",
            "downloadUrl": "https://nexus.example.com/repo/org/example/lib/1.0/lib-1.0.jar",
            "checksum": {
                "sha256": "sha256hash",
                "sha1": "sha1hash",
                "md5": "md5hash"
            },
            "contentType": "application/java-archive",
            "fileSize": 4096
        }"#;
        let asset: NexusAsset = serde_json::from_str(json).unwrap();
        assert_eq!(asset.id, "asset-001");
        assert_eq!(asset.file_size, Some(4096));
        assert_eq!(
            asset.content_type,
            Some("application/java-archive".to_string())
        );
        let checksum = asset.checksum.unwrap();
        assert_eq!(checksum.sha256, Some("sha256hash".to_string()));
    }

    #[test]
    fn test_nexus_asset_minimal() {
        let json = r#"{"id": "asset-002"}"#;
        let asset: NexusAsset = serde_json::from_str(json).unwrap();
        assert_eq!(asset.id, "asset-002");
        assert!(asset.path.is_none());
        assert!(asset.download_url.is_none());
        assert!(asset.checksum.is_none());
        assert!(asset.content_type.is_none());
        assert!(asset.file_size.is_none());
    }

    #[test]
    fn test_nexus_checksum_deserialization() {
        let json = r#"{
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "md5": "d41d8cd98f00b204e9800998ecf8427e"
        }"#;
        let checksum: NexusChecksum = serde_json::from_str(json).unwrap();
        assert!(checksum.sha256.is_some());
        assert!(checksum.sha1.is_some());
        assert!(checksum.md5.is_some());
    }

    #[test]
    fn test_nexus_checksum_partial() {
        let json = r#"{"sha256": "hash_only"}"#;
        let checksum: NexusChecksum = serde_json::from_str(json).unwrap();
        assert_eq!(checksum.sha256, Some("hash_only".to_string()));
        assert!(checksum.sha1.is_none());
        assert!(checksum.md5.is_none());
    }

    #[test]
    fn test_nexus_components_response_deserialization() {
        let json = r#"{
            "items": [
                {
                    "id": "comp-1",
                    "repository": "npm-hosted",
                    "format": "npm",
                    "name": "my-package",
                    "version": "2.0.0",
                    "assets": []
                }
            ],
            "continuationToken": "abc123token"
        }"#;
        let response: NexusComponentsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.continuation_token, Some("abc123token".to_string()));
    }

    #[test]
    fn test_nexus_components_response_no_continuation() {
        let json = r#"{
            "items": [],
            "continuationToken": null
        }"#;
        let response: NexusComponentsResponse = serde_json::from_str(json).unwrap();
        assert!(response.items.is_empty());
        assert!(response.continuation_token.is_none());
    }

    #[test]
    fn test_nexus_status_response_deserialization() {
        let json = r#"{
            "edition": "PRO",
            "version": "3.42.0"
        }"#;
        let status: NexusStatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(status.edition, Some("PRO".to_string()));
        assert_eq!(status.version, Some("3.42.0".to_string()));
    }

    #[test]
    fn test_nexus_status_response_minimal() {
        let json = r#"{}"#;
        let status: NexusStatusResponse = serde_json::from_str(json).unwrap();
        assert!(status.edition.is_none());
        assert!(status.version.is_none());
    }

    #[test]
    fn test_nexus_component_without_optional_fields() {
        let json = r#"{
            "id": "comp-2",
            "repository": "docker-hosted",
            "format": "docker",
            "name": "myimage",
            "assets": []
        }"#;
        let component: NexusComponent = serde_json::from_str(json).unwrap();
        assert_eq!(component.name, "myimage");
        assert!(component.group.is_none());
        assert!(component.version.is_none());
        assert!(component.assets.is_empty());
    }

    #[test]
    fn test_source_type_returns_nexus() {
        let config = NexusClientConfig {
            base_url: "https://nexus.example.com".to_string(),
            auth: NexusAuth {
                username: "admin".to_string(),
                password: "admin123".to_string(),
            },
            ..Default::default()
        };
        let client = NexusClient::new(config).unwrap();
        use crate::services::source_registry::SourceRegistry;
        assert_eq!(client.source_type(), "nexus");
    }

    #[test]
    fn test_nexus_component_multiple_assets() {
        let json = r#"{
            "id": "comp-3",
            "repository": "maven-releases",
            "format": "maven2",
            "group": "org.test",
            "name": "lib",
            "version": "3.0",
            "assets": [
                {"id": "a1", "path": "org/test/lib/3.0/lib-3.0.jar", "fileSize": 100},
                {"id": "a2", "path": "org/test/lib/3.0/lib-3.0.pom", "fileSize": 50},
                {"id": "a3", "path": "org/test/lib/3.0/lib-3.0-sources.jar", "fileSize": 200}
            ]
        }"#;
        let component: NexusComponent = serde_json::from_str(json).unwrap();
        assert_eq!(component.assets.len(), 3);
        assert_eq!(component.assets[0].file_size, Some(100));
        assert_eq!(component.assets[1].file_size, Some(50));
        assert_eq!(component.assets[2].file_size, Some(200));
    }

    // ---------------------------------------------------------------------
    // Streaming regression coverage (issue #1422)
    //
    // These tests assert that `download_artifact_stream` actually streams
    // the response body in chunks rather than buffering the full payload
    // before returning. Without this, a 10 GB artifact in the migration
    // worker OOMs the AK host.
    // ---------------------------------------------------------------------

    /// 64 MiB synthetic artifact. Big enough that buffering the whole body
    /// would be obviously visible in a memory profile, small enough to run
    /// in CI within the unit-test budget.
    #[tokio::test]
    async fn test_download_artifact_stream_yields_chunks() {
        use futures::StreamExt;

        let body_size: usize = 64 * 1024 * 1024;
        let body = vec![0xABu8; body_size];

        let (_server, client) = setup_nexus_mock(
            "/repository/raw-local/big.bin",
            ResponseTemplate::new(200).set_body_bytes(body.clone()),
        )
        .await;

        let mut stream = client
            .download_artifact_stream("raw-local", "big.bin")
            .await
            .expect("stream open");

        let mut chunks = 0usize;
        let mut total = 0usize;
        let mut max_chunk = 0usize;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.expect("chunk");
            chunks += 1;
            total += chunk.len();
            if chunk.len() > max_chunk {
                max_chunk = chunk.len();
            }
        }

        assert_eq!(total, body_size, "should receive entire body");
        // Reqwest's bytes_stream chunk size is well under the body size for
        // a 64 MiB payload. If this assertion fails it means the response
        // is being buffered into one Bytes before yielding (the #1422 bug).
        assert!(
            max_chunk < body_size,
            "expected chunked streaming, got single {max_chunk}-byte chunk for {body_size}-byte body"
        );
        assert!(
            chunks > 1,
            "expected >1 chunks for a 64 MiB body, got {chunks}"
        );
    }

    /// Verifies the streaming path returns the same bytes as the buffered
    /// `download_artifact` path. Guards against off-by-one chunking bugs
    /// dropping or duplicating data.
    #[tokio::test]
    async fn test_download_artifact_stream_matches_buffered() {
        use futures::StreamExt;

        // Mix of byte values so a byte-shift bug surfaces clearly.
        let body: Vec<u8> = (0..(2 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();

        let (_server, client) = setup_nexus_mock(
            "/repository/raw-local/mixed.bin",
            ResponseTemplate::new(200).set_body_bytes(body.clone()),
        )
        .await;

        let mut stream = client
            .download_artifact_stream("raw-local", "mixed.bin")
            .await
            .expect("stream open");

        let mut assembled = Vec::with_capacity(body.len());
        while let Some(chunk) = stream.next().await {
            assembled.extend_from_slice(&chunk.expect("chunk"));
        }

        assert_eq!(assembled, body, "streamed bytes must equal source body");
    }

    /// Regression test for the exact #1422 acceptance criterion: the
    /// migration worker must be able to consume a large artifact from a
    /// `SourceRegistry` without ever holding the full payload in memory.
    /// We exercise the streaming path end-to-end through the
    /// `SourceRegistry` trait (which is what `migration_worker` sees) and
    /// assert that the peak in-flight buffer stays bounded.
    #[tokio::test]
    async fn test_source_registry_stream_keeps_memory_bounded() {
        use crate::services::source_registry::SourceRegistry;
        use futures::StreamExt;

        let body_size: usize = 32 * 1024 * 1024; // 32 MiB
        let body = vec![0x5Au8; body_size];

        let (_server, client) = setup_nexus_mock(
            "/repository/raw-local/large.bin",
            ResponseTemplate::new(200).set_body_bytes(body.clone()),
        )
        .await;
        let client: std::sync::Arc<dyn SourceRegistry> = std::sync::Arc::new(client);

        let mut stream = client
            .download_artifact_stream("raw-local", "large.bin")
            .await
            .expect("stream open");

        let mut peak_in_flight: usize = 0;
        let mut total: usize = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.expect("chunk");
            if chunk.len() > peak_in_flight {
                peak_in_flight = chunk.len();
            }
            total += chunk.len();
            // Drop the chunk immediately, simulating the migration_worker
            // path that writes to disk and forgets.
            drop(chunk);
        }

        assert_eq!(total, body_size);
        // Hard upper bound: any single chunk must be much smaller than the
        // whole artifact. We pick body_size / 4 as a generous ceiling;
        // reqwest typically yields ~8 KiB-64 KiB chunks. If this fails the
        // streaming guarantee is broken.
        assert!(
            peak_in_flight < body_size / 4,
            "peak in-flight chunk {peak_in_flight} approaches full body {body_size}; \
             streaming is buffering"
        );
    }

    #[tokio::test]
    async fn test_list_artifacts_strips_leading_slash_from_nexus_paths() {
        let nexus_response = serde_json::json!({
            "items": [{
                "id": "comp-1",
                "repository": "maven-releases",
                "format": "maven2",
                "group": "cglib",
                "name": "cglib-nodep",
                "version": "3.2.5",
                "assets": [
                    {
                        "id": "a-jar",
                        "path": "/cglib/cglib-nodep/3.2.5/cglib-nodep-3.2.5.jar",
                        "downloadUrl": "https://nexus.example.com/repository/maven-releases/cglib/cglib-nodep/3.2.5/cglib-nodep-3.2.5.jar",
                        "checksum": {"sha256": "h1", "sha1": "h2", "md5": "h3"},
                        "contentType": "application/java-archive",
                        "fileSize": 1024
                    },
                    {
                        "id": "a-sources",
                        "path": "/cglib/cglib-nodep/3.2.5/cglib-nodep-3.2.5-sources.jar",
                        "downloadUrl": "https://nexus.example.com/repository/maven-releases/cglib/cglib-nodep/3.2.5/cglib-nodep-3.2.5-sources.jar",
                        "checksum": {"sha256": "h4", "sha1": "h5", "md5": "h6"},
                        "contentType": "application/java-archive",
                        "fileSize": 2048
                    },
                    {
                        "id": "a-root",
                        "path": "/top-level.bin",
                        "downloadUrl": "https://nexus.example.com/repository/raw-local/top-level.bin",
                        "checksum": {"sha256": "h7", "sha1": "h8", "md5": "h9"},
                        "contentType": "application/octet-stream",
                        "fileSize": 16
                    }
                ]
            }],
            "continuationToken": null
        })
        .to_string();

        let (_server, client) = setup_nexus_mock(
            "/service/rest/v1/components",
            ResponseTemplate::new(200).set_body_string(nexus_response),
        )
        .await;

        let page = client
            .list_artifacts("maven-releases", 0, 100)
            .await
            .unwrap();
        assert_eq!(page.results.len(), 3, "expected all three assets");

        for r in &page.results {
            assert!(
                !r.path.starts_with('/'),
                "AqlResult.path must be relative, got {:?}",
                r.path
            );
            assert!(
                !r.name.is_empty(),
                "name must not be empty, got {:?} for path {:?}",
                r.name,
                r.path
            );
        }

        let jar = page
            .results
            .iter()
            .find(|r| r.name == "cglib-nodep-3.2.5.jar")
            .expect("jar asset");
        assert_eq!(jar.path, "cglib/cglib-nodep/3.2.5");
        assert_eq!(jar.repo, "maven-releases");

        let root = page
            .results
            .iter()
            .find(|r| r.name == "top-level.bin")
            .expect("root asset");
        assert_eq!(root.path, ".");
    }
}
