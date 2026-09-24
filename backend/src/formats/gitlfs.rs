use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLfsPathInfo {
    pub kind: GitLfsPathKind,
    pub oid: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GitLfsPathKind {
    Batch,
    Object,
    Lock,
    LockVerify,
}

pub struct GitLfsHandler;

impl GitLfsHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_path(path: &str) -> Result<GitLfsPathInfo> {
        let path = path.trim_start_matches('/');

        if path == "objects/batch" {
            return Ok(GitLfsPathInfo {
                kind: GitLfsPathKind::Batch,
                oid: None,
            });
        }

        if let Some(oid) = path.strip_prefix("objects/") {
            if !oid.contains('/') {
                return Ok(GitLfsPathInfo {
                    kind: GitLfsPathKind::Object,
                    oid: Some(oid.to_string()),
                });
            }
        }

        if path == "locks" {
            return Ok(GitLfsPathInfo {
                kind: GitLfsPathKind::Lock,
                oid: None,
            });
        }

        if path == "locks/verify" {
            return Ok(GitLfsPathInfo {
                kind: GitLfsPathKind::LockVerify,
                oid: None,
            });
        }

        Err(AppError::Validation(format!(
            "Invalid Git LFS path: {}",
            path
        )))
    }
}

impl Default for GitLfsHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for GitLfsHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Gitlfs
    }

    fn format_key(&self) -> &str {
        "gitlfs"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;
        Ok(serde_json::to_value(info).unwrap_or(serde_json::json!({})))
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_batch_path() {
        let result = GitLfsHandler::parse_path("/objects/batch");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.kind, GitLfsPathKind::Batch);
        assert_eq!(info.oid, None);
    }

    #[test]
    fn test_parse_object_path() {
        let result = GitLfsHandler::parse_path("/objects/abc123def456");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.kind, GitLfsPathKind::Object);
        assert_eq!(info.oid, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_parse_lock_path() {
        let result = GitLfsHandler::parse_path("/locks");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.kind, GitLfsPathKind::Lock);
        assert_eq!(info.oid, None);
    }

    #[test]
    fn test_parse_lock_verify_path() {
        let result = GitLfsHandler::parse_path("/locks/verify");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.kind, GitLfsPathKind::LockVerify);
        assert_eq!(info.oid, None);
    }

    #[test]
    fn test_parse_invalid_path() {
        let result = GitLfsHandler::parse_path("/invalid/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_format() {
        let handler = GitLfsHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Gitlfs);
    }

    #[test]
    fn test_format_key() {
        let handler = GitLfsHandler::new();
        assert_eq!(handler.format_key(), "gitlfs");
    }
}
