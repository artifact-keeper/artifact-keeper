//! Generic binary format handler.

use async_trait::async_trait;
use bytes::Bytes;

use super::FormatHandler;
use crate::error::Result;
use crate::models::repository::RepositoryFormat;

pub struct GenericHandler;

impl GenericHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GenericHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for GenericHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Generic
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        // Generic format has minimal metadata
        Ok(serde_json::json!({
            "path": path,
        }))
    }

    async fn validate(&self, _path: &str, _content: &Bytes) -> Result<()> {
        // Generic format accepts any content
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // No index for generic format
        Ok(None)
    }
}
