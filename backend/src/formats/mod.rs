//! Package format handlers.

pub mod cargo;
pub mod conan;
pub mod debian;
pub mod generic;
pub mod go;
pub mod helm;
pub mod maven;
pub mod npm;
pub mod nuget;
pub mod oci;
pub mod pypi;
pub mod rpm;
pub mod rubygems;

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::Result;
use crate::models::repository::RepositoryFormat;

/// Package format handler trait
#[async_trait]
pub trait FormatHandler: Send + Sync {
    /// Get the format type this handler supports
    fn format(&self) -> RepositoryFormat;

    /// Parse artifact metadata from content
    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value>;

    /// Validate artifact before storage
    async fn validate(&self, path: &str, content: &Bytes) -> Result<()>;

    /// Generate index/metadata files for the repository (if applicable)
    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>>;
}
