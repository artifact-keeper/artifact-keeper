//! Abstraction over source registry clients (Artifactory, Nexus, etc.)
//!
//! The `SourceRegistry` trait provides a uniform interface for the migration
//! worker to pull artifacts from different registry implementations.

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;

use crate::services::artifactory_client::{
    AqlResponse, ArtifactoryError, PropertiesResponse, RepositoryListItem, SystemVersionResponse,
};

/// Boxed byte stream returned by `download_artifact_stream`. Each item is a
/// chunk of the artifact body or a transport error. Holding only one chunk
/// at a time keeps migration memory bounded to O(chunk_size) regardless of
/// artifact size (issue #1422).
pub type ArtifactByteStream = BoxStream<'static, Result<Bytes, ArtifactoryError>>;

/// Trait for source registry clients used during migration.
///
/// Both `ArtifactoryClient` and `NexusClient` implement this trait so the
/// migration worker can process either source identically.
#[async_trait]
pub trait SourceRegistry: Send + Sync {
    /// Check connectivity
    async fn ping(&self) -> Result<bool, ArtifactoryError>;

    /// Get version information
    async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError>;

    /// List all repositories
    async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError>;

    /// List artifacts in a repository with pagination
    async fn list_artifacts(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
    ) -> Result<AqlResponse, ArtifactoryError>;

    /// Download an artifact as raw bytes.
    ///
    /// Prefer `download_artifact_stream` for migrations: this method buffers
    /// the entire artifact body into memory, which OOMs on multi-GB artifacts
    /// (issue #1422). It is retained for callers that genuinely need the
    /// full bytes in memory (small fixtures, test mocks).
    async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError>;

    /// Download an artifact as a chunked byte stream.
    ///
    /// Returns a `Stream<Item = Result<Bytes>>` so the caller can spill
    /// chunks to a temp file (or hash/inspect them) without ever holding
    /// the whole artifact in memory. Used by `migration_worker::transfer_artifact`
    /// to keep per-job memory bounded to one chunk regardless of artifact
    /// size (fix for issue #1422).
    ///
    /// The default implementation falls back to `download_artifact` followed
    /// by wrapping the full body in a single-item stream, so mock/test
    /// registries that only implement the buffered call continue to work
    /// (with the same memory footprint as before). Real registry clients
    /// (`ArtifactoryClient`, `NexusClient`) override this with a true
    /// streaming implementation backed by `reqwest::Response::bytes_stream`.
    async fn download_artifact_stream(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<ArtifactByteStream, ArtifactoryError> {
        let bytes = self.download_artifact(repo_key, path).await?;
        Ok(Box::pin(futures::stream::once(async move { Ok(bytes) })))
    }

    /// Get artifact properties/metadata (optional — returns empty if unsupported)
    async fn get_properties(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<PropertiesResponse, ArtifactoryError>;

    /// Human-readable source type name
    fn source_type(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::artifactory_client::AqlRange;
    use std::collections::HashMap;

    /// Mock source registry for testing trait contracts
    struct MockSourceRegistry {
        source: &'static str,
        ping_result: bool,
    }

    impl MockSourceRegistry {
        fn new(source: &'static str) -> Self {
            Self {
                source,
                ping_result: true,
            }
        }

        fn with_ping(mut self, result: bool) -> Self {
            self.ping_result = result;
            self
        }
    }

    #[async_trait]
    impl SourceRegistry for MockSourceRegistry {
        async fn ping(&self) -> Result<bool, ArtifactoryError> {
            Ok(self.ping_result)
        }

        async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
            Ok(SystemVersionResponse {
                version: "7.55.0".to_string(),
                revision: Some("abc123".to_string()),
                addons: None,
                license: Some("Enterprise".to_string()),
            })
        }

        async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
            Ok(vec![RepositoryListItem {
                key: "libs-release".to_string(),
                repo_type: "local".to_string(),
                package_type: "maven".to_string(),
                url: Some("http://localhost/libs-release".to_string()),
                description: Some("Release repo".to_string()),
            }])
        }

        async fn list_artifacts(
            &self,
            _repo_key: &str,
            offset: i64,
            limit: i64,
        ) -> Result<AqlResponse, ArtifactoryError> {
            Ok(AqlResponse {
                results: vec![],
                range: AqlRange {
                    start_pos: offset,
                    end_pos: offset + limit,
                    total: 0,
                },
            })
        }

        async fn download_artifact(
            &self,
            _repo_key: &str,
            _path: &str,
        ) -> Result<bytes::Bytes, ArtifactoryError> {
            Ok(bytes::Bytes::from_static(b"artifact content"))
        }

        async fn get_properties(
            &self,
            _repo_key: &str,
            _path: &str,
        ) -> Result<PropertiesResponse, ArtifactoryError> {
            Ok(PropertiesResponse {
                properties: Some(HashMap::new()),
                uri: None,
            })
        }

        fn source_type(&self) -> &'static str {
            self.source
        }
    }

    #[tokio::test]
    async fn test_mock_ping_success() {
        let registry = MockSourceRegistry::new("artifactory");
        assert!(registry.ping().await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_ping_failure() {
        let registry = MockSourceRegistry::new("artifactory").with_ping(false);
        assert!(!registry.ping().await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_get_version() {
        let registry = MockSourceRegistry::new("artifactory");
        let version = registry.get_version().await.unwrap();
        assert_eq!(version.version, "7.55.0");
        assert_eq!(version.revision, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_mock_list_repositories() {
        let registry = MockSourceRegistry::new("nexus");
        let repos = registry.list_repositories().await.unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].key, "libs-release");
        assert_eq!(repos[0].package_type, "maven");
    }

    #[tokio::test]
    async fn test_mock_list_artifacts_pagination() {
        let registry = MockSourceRegistry::new("artifactory");
        let response = registry
            .list_artifacts("libs-release", 0, 100)
            .await
            .unwrap();
        assert_eq!(response.range.start_pos, 0);
        assert_eq!(response.range.end_pos, 100);
        assert_eq!(response.results.len(), 0);
    }

    #[tokio::test]
    async fn test_mock_download_artifact() {
        let registry = MockSourceRegistry::new("artifactory");
        let content = registry
            .download_artifact("libs-release", "com/example/test.jar")
            .await
            .unwrap();
        assert_eq!(content, bytes::Bytes::from_static(b"artifact content"));
    }

    /// The default `download_artifact_stream` implementation must wrap
    /// `download_artifact` so registries that only implement the buffered
    /// path keep working (#1422).
    #[tokio::test]
    async fn test_default_download_artifact_stream_falls_back() {
        use futures::StreamExt;
        let registry = MockSourceRegistry::new("artifactory");
        let mut stream = registry
            .download_artifact_stream("libs-release", "com/example/test.jar")
            .await
            .unwrap();
        let mut assembled = Vec::new();
        while let Some(chunk) = stream.next().await {
            assembled.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(assembled, b"artifact content");
    }

    #[tokio::test]
    async fn test_mock_get_properties() {
        let registry = MockSourceRegistry::new("artifactory");
        let props = registry
            .get_properties("libs-release", "test.jar")
            .await
            .unwrap();
        assert!(props.properties.is_some());
        assert!(props.uri.is_none());
    }

    #[test]
    fn test_source_type_artifactory() {
        let registry = MockSourceRegistry::new("artifactory");
        assert_eq!(registry.source_type(), "artifactory");
    }

    #[test]
    fn test_source_type_nexus() {
        let registry = MockSourceRegistry::new("nexus");
        assert_eq!(registry.source_type(), "nexus");
    }

    #[test]
    fn test_source_type_custom() {
        let registry = MockSourceRegistry::new("custom-registry");
        assert_eq!(registry.source_type(), "custom-registry");
    }
}
