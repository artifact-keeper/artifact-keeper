//! Abstraction over source registry clients (Artifactory, Nexus, etc.)
//!
//! The `SourceRegistry` trait provides a uniform interface for the migration
//! worker to pull artifacts from different registry implementations.

use async_trait::async_trait;

use crate::services::artifactory_client::{
    AqlResponse, ArtifactoryError, PropertiesResponse, RepositoryListItem, SystemVersionResponse,
};

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

    /// Download an artifact as raw bytes
    async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError>;

    /// Get artifact properties/metadata (optional — returns empty if unsupported)
    async fn get_properties(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<PropertiesResponse, ArtifactoryError>;

    /// Human-readable source type name
    fn source_type(&self) -> &'static str;
}
