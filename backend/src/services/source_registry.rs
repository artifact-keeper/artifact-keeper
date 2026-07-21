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

/// The kind of digest-addressed OCI content to fetch from a source registry.
///
/// A Docker/OCI source enumerates only the *tag* manifests of a repository.
/// The bytes those manifests reference — the image config/layer blobs and
/// (for a multi-arch index) the per-arch child manifests — are addressed by
/// digest and are NOT enumerated. The migration worker's referenced-content
/// walker (#2457) fetches them explicitly by digest through
/// [`SourceRegistry::download_oci_content_stream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciContentKind {
    /// A config or layer blob: `.../blobs/<digest>`.
    Blob,
    /// A child (per-arch) image manifest: `.../manifests/<digest>`.
    Manifest,
}

impl OciContentKind {
    /// The registry-API path segment (`blobs` or `manifests`) for this kind.
    pub fn path_segment(self) -> &'static str {
        match self {
            OciContentKind::Blob => "blobs",
            OciContentKind::Manifest => "manifests",
        }
    }
}

/// Whether `digest` is a canonical `sha256:<64-lowercase-hex>` reference.
///
/// The by-digest fetch path (#2457) interpolates the digest into an OUTBOUND
/// source URL, and the digest originates from an attacker-influenced manifest
/// body. Validate it against the strict grammar before building the URL so a
/// crafted `../`/scheme-injecting value can never reach the request builder
/// (defense-in-depth: the response is also digest-verified and discarded).
pub fn is_valid_oci_digest(digest: &str) -> bool {
    match digest.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

/// Whether `image` is a valid OCI repository name (lowercase path components of
/// `[a-z0-9]` plus `.`, `_`, `-` separators, each component starting and ending
/// alphanumeric). Rejects empty components, leading/trailing separators, `..`
/// traversal segments, and any character outside the grammar — so the value is
/// safe to interpolate into an outbound `v2/<image>/...` URL.
pub fn is_valid_oci_image_name(image: &str) -> bool {
    if image.is_empty() || image.len() > 255 || image.contains("..") {
        return false;
    }
    image.split('/').all(|component| {
        let bytes = component.as_bytes();
        !bytes.is_empty()
            && bytes.iter().all(|&b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
            && bytes
                .first()
                .is_some_and(|&b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes
                .last()
                .is_some_and(|&b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

/// Validate the `(image, digest)` pair used to build an outbound by-digest OCI
/// fetch URL, returning a 400-class `ArtifactoryError` when either is malformed.
pub fn validate_oci_content_ref(image: &str, digest: &str) -> Result<(), ArtifactoryError> {
    if !is_valid_oci_image_name(image) {
        return Err(ArtifactoryError::ApiError {
            status: 400,
            message: format!("refusing to fetch OCI content for invalid image name '{image}'"),
        });
    }
    if !is_valid_oci_digest(digest) {
        return Err(ArtifactoryError::ApiError {
            status: 400,
            message: format!("refusing to fetch OCI content for invalid digest '{digest}'"),
        });
    }
    Ok(())
}

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

    /// List artifacts in a repository with optional modified-date filtering.
    ///
    /// The default implementation ignores the date filters so sources that do
    /// not support incremental listing continue to work unchanged.
    async fn list_artifacts_with_date_filter(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
        modified_after: Option<&str>,
        modified_before: Option<&str>,
    ) -> Result<AqlResponse, ArtifactoryError> {
        let _ = (modified_after, modified_before);
        self.list_artifacts(repo_key, offset, limit).await
    }

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

    /// Download digest-addressed OCI content (a config/layer blob or a child
    /// image manifest) as a chunked byte stream (#2457).
    ///
    /// A Docker/OCI source registry enumerates only the *tag* manifests of a
    /// repository; the config/layer blobs and per-arch child manifests those
    /// manifests reference are addressed by digest and never appear in
    /// `list_artifacts`. The migration worker's referenced-content walker
    /// resolves them by digest through this method so a migrated image lands
    /// with all of its bytes (not a hollow, unpullable tag).
    ///
    /// The default implementation targets the OCI Distribution v2 layout that
    /// Nexus (and any conformant registry) serves under a repository:
    /// `<repo>/v2/<image>/{blobs|manifests}/<digest>`. It delegates to
    /// [`download_artifact_stream`](Self::download_artifact_stream) so the
    /// per-source auth/transport is reused unchanged. Sources whose blob
    /// layout differs (Artifactory) override this.
    async fn download_oci_content_stream(
        &self,
        repo_key: &str,
        image: &str,
        digest: &str,
        kind: OciContentKind,
    ) -> Result<ArtifactByteStream, ArtifactoryError> {
        // Validate the attacker-influenced components before they reach the
        // outbound URL builder (path-traversal / injection defense-in-depth).
        validate_oci_content_ref(image, digest)?;
        let path = format!("v2/{}/{}/{}", image, kind.path_segment(), digest);
        self.download_artifact_stream(repo_key, &path).await
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
                members: vec![],
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

    #[test]
    fn valid_oci_digest_accepts_canonical_sha256() {
        let hex = "a".repeat(64);
        assert!(is_valid_oci_digest(&format!("sha256:{hex}")));
        assert!(is_valid_oci_digest(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn valid_oci_digest_rejects_malformed_and_traversal() {
        assert!(!is_valid_oci_digest("latest"));
        assert!(!is_valid_oci_digest("sha256:short"));
        // wrong length
        assert!(!is_valid_oci_digest(&format!("sha256:{}", "a".repeat(63))));
        // uppercase hex is not canonical
        assert!(!is_valid_oci_digest(&format!("sha256:{}", "A".repeat(64))));
        // traversal / injection attempts must not pass the digest grammar
        assert!(!is_valid_oci_digest("sha256:../../../../etc/passwd"));
        assert!(!is_valid_oci_digest("sha512:aaaa"));
        assert!(!is_valid_oci_digest(""));
    }

    #[test]
    fn valid_oci_image_name_accepts_real_names() {
        assert!(is_valid_oci_image_name("busybox"));
        assert!(is_valid_oci_image_name("library/busybox"));
        assert!(is_valid_oci_image_name("org/team/app"));
        assert!(is_valid_oci_image_name("my-repo.name_1/sub-image"));
    }

    #[test]
    fn valid_oci_image_name_rejects_traversal_and_injection() {
        assert!(!is_valid_oci_image_name(""));
        assert!(!is_valid_oci_image_name("../etc/passwd"));
        assert!(!is_valid_oci_image_name("app/../../secret"));
        assert!(!is_valid_oci_image_name("/leading-slash"));
        assert!(!is_valid_oci_image_name("trailing/"));
        assert!(!is_valid_oci_image_name("double//slash"));
        assert!(!is_valid_oci_image_name("Upper/Case"));
        assert!(!is_valid_oci_image_name("has space"));
        assert!(!is_valid_oci_image_name("scheme:inject"));
        assert!(!is_valid_oci_image_name(".leading-dot"));
    }

    #[test]
    fn validate_oci_content_ref_gates_both_components() {
        let hex = "b".repeat(64);
        assert!(validate_oci_content_ref("app", &format!("sha256:{hex}")).is_ok());
        assert!(validate_oci_content_ref("../app", &format!("sha256:{hex}")).is_err());
        assert!(validate_oci_content_ref("app", "sha256:../bad").is_err());
    }
}
