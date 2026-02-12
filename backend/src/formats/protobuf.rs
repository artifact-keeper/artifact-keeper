//! Protobuf/BSR format handler.
//!
//! Implements Buf Schema Registry (BSR) protocol for Protobuf modules.
//! Supports module commits, labels, label indices, and blob storage.

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use tar::Archive;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Protobuf/BSR format handler
pub struct ProtobufHandler;

impl ProtobufHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Protobuf/BSR path.
    ///
    /// Supported formats:
    ///   modules/{owner}/{name}/commits/{digest}  - Module commit
    ///   modules/{owner}/{name}/labels/{label}     - Module label
    ///   modules/{owner}/{name}/_labels             - Label index
    ///   blobs/sha256/{digest}                      - Content blob
    pub fn parse_path(path: &str) -> Result<ProtobufPathInfo> {
        let path = path.trim_start_matches('/');
        let parts: Vec<&str> = path.split('/').collect();

        // blobs/sha256/{digest}
        if parts.len() == 3 && parts[0] == "blobs" && parts[1] == "sha256" {
            let digest = parts[2];
            if digest.is_empty() {
                return Err(AppError::Validation(
                    "Blob digest must not be empty".to_string(),
                ));
            }
            return Ok(ProtobufPathInfo {
                kind: "blob".to_string(),
                owner: None,
                name: None,
                digest: Some(digest.to_string()),
                label: None,
            });
        }

        // All remaining valid paths start with modules/{owner}/{name}/...
        if parts.len() < 4 || parts[0] != "modules" {
            return Err(AppError::Validation(format!(
                "Invalid Protobuf path: {}",
                path
            )));
        }

        let owner = parts[1].to_string();
        let name = parts[2].to_string();

        // modules/{owner}/{name}/_labels
        if parts.len() == 4 && parts[3] == "_labels" {
            return Ok(ProtobufPathInfo {
                kind: "label_index".to_string(),
                owner: Some(owner),
                name: Some(name),
                digest: None,
                label: None,
            });
        }

        // modules/{owner}/{name}/commits/{digest}
        if parts.len() == 5 && parts[3] == "commits" {
            let digest = parts[4];
            if digest.is_empty() {
                return Err(AppError::Validation(
                    "Commit digest must not be empty".to_string(),
                ));
            }
            return Ok(ProtobufPathInfo {
                kind: "commit".to_string(),
                owner: Some(owner),
                name: Some(name),
                digest: Some(digest.to_string()),
                label: None,
            });
        }

        // modules/{owner}/{name}/labels/{label}
        if parts.len() == 5 && parts[3] == "labels" {
            let label = parts[4];
            if label.is_empty() {
                return Err(AppError::Validation("Label must not be empty".to_string()));
            }
            return Ok(ProtobufPathInfo {
                kind: "label".to_string(),
                owner: Some(owner),
                name: Some(name),
                digest: None,
                label: Some(label.to_string()),
            });
        }

        Err(AppError::Validation(format!(
            "Invalid Protobuf path: {}",
            path
        )))
    }

    /// Extract buf.yaml from a tar.gz bundle.
    ///
    /// Searches for a file named `buf.yaml` at any depth within the archive.
    pub fn extract_buf_yaml(content: &[u8]) -> Result<BufYaml> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid protobuf bundle: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid bundle entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in bundle: {}", e)))?;

            if path.ends_with("buf.yaml") {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read buf.yaml: {}", e)))?;

                return serde_yaml::from_str(&content)
                    .map_err(|e| AppError::Validation(format!("Invalid buf.yaml: {}", e)));
            }
        }

        Err(AppError::Validation(
            "buf.yaml not found in protobuf bundle".to_string(),
        ))
    }

    /// Validate that a tar.gz bundle contains at least one .proto file.
    pub fn validate_bundle(content: &[u8]) -> Result<()> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        let entries = archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid protobuf bundle: {}", e)))?;

        for entry in entries {
            let entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid bundle entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in bundle: {}", e)))?;

            if path
                .to_str()
                .map(|s| s.ends_with(".proto"))
                .unwrap_or(false)
            {
                return Ok(());
            }
        }

        Err(AppError::Validation(
            "Protobuf bundle must contain at least one .proto file".to_string(),
        ))
    }

    /// Compute SHA-256 digest of content, returned as a hex string.
    pub fn compute_digest(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for ProtobufHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for ProtobufHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Protobuf
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "kind": info.kind,
        });

        if let Some(owner) = &info.owner {
            metadata["owner"] = serde_json::Value::String(owner.clone());
        }

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }

        if let Some(digest) = &info.digest {
            metadata["digest"] = serde_json::Value::String(digest.clone());
        }

        if let Some(label) = &info.label {
            metadata["label"] = serde_json::Value::String(label.clone());
        }

        // For commit bundles, try to extract buf.yaml metadata
        if info.kind == "commit" && !content.is_empty() {
            if let Ok(buf_yaml) = Self::extract_buf_yaml(content) {
                metadata["buf"] = serde_json::to_value(&buf_yaml)?;
            }

            metadata["content_digest"] = serde_json::Value::String(Self::compute_digest(content));
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Label index and label paths have no content to validate
        if info.kind == "label_index" || info.kind == "label" {
            return Ok(());
        }

        // Commit bundles must be valid tar.gz with at least one .proto file
        if info.kind == "commit" && !content.is_empty() {
            Self::validate_bundle(content)?;
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

/// Parsed Protobuf/BSR path information
#[derive(Debug)]
pub struct ProtobufPathInfo {
    pub kind: String,
    pub owner: Option<String>,
    pub name: Option<String>,
    pub digest: Option<String>,
    pub label: Option<String>,
}

/// buf.yaml configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufYaml {
    pub version: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub deps: Option<Vec<String>>,
    #[serde(default)]
    pub build: Option<serde_yaml::Value>,
    #[serde(default)]
    pub lint: Option<serde_yaml::Value>,
    #[serde(default)]
    pub breaking: Option<serde_yaml::Value>,
}

/// An entry within a Buf module bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufFileEntry {
    pub path: String,
    pub size: u64,
    #[serde(default)]
    pub digest: Option<String>,
}

/// Buf module manifest describing the contents of a commit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufManifest {
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub files: Option<Vec<BufFileEntry>>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_path tests ---

    #[test]
    fn test_parse_path_commit() {
        let info = ProtobufHandler::parse_path("modules/acme/petapis/commits/abc123def").unwrap();
        assert_eq!(info.kind, "commit");
        assert_eq!(info.owner, Some("acme".to_string()));
        assert_eq!(info.name, Some("petapis".to_string()));
        assert_eq!(info.digest, Some("abc123def".to_string()));
        assert!(info.label.is_none());
    }

    #[test]
    fn test_parse_path_label() {
        let info = ProtobufHandler::parse_path("modules/acme/petapis/labels/v1.0.0").unwrap();
        assert_eq!(info.kind, "label");
        assert_eq!(info.owner, Some("acme".to_string()));
        assert_eq!(info.name, Some("petapis".to_string()));
        assert_eq!(info.label, Some("v1.0.0".to_string()));
        assert!(info.digest.is_none());
    }

    #[test]
    fn test_parse_path_label_index() {
        let info = ProtobufHandler::parse_path("modules/acme/petapis/_labels").unwrap();
        assert_eq!(info.kind, "label_index");
        assert_eq!(info.owner, Some("acme".to_string()));
        assert_eq!(info.name, Some("petapis".to_string()));
        assert!(info.digest.is_none());
        assert!(info.label.is_none());
    }

    #[test]
    fn test_parse_path_blob() {
        let info = ProtobufHandler::parse_path("blobs/sha256/deadbeef0123456789").unwrap();
        assert_eq!(info.kind, "blob");
        assert_eq!(info.digest, Some("deadbeef0123456789".to_string()));
        assert!(info.owner.is_none());
        assert!(info.name.is_none());
        assert!(info.label.is_none());
    }

    #[test]
    fn test_parse_path_with_leading_slash() {
        let info = ProtobufHandler::parse_path("/modules/acme/petapis/commits/abc123").unwrap();
        assert_eq!(info.kind, "commit");
        assert_eq!(info.owner, Some("acme".to_string()));
    }

    #[test]
    fn test_parse_path_invalid() {
        assert!(ProtobufHandler::parse_path("invalid/path").is_err());
    }

    #[test]
    fn test_parse_path_invalid_modules_too_short() {
        assert!(ProtobufHandler::parse_path("modules/acme").is_err());
    }

    #[test]
    fn test_parse_path_invalid_unknown_segment() {
        assert!(ProtobufHandler::parse_path("modules/acme/petapis/unknown/thing").is_err());
    }

    // --- compute_digest tests ---

    #[test]
    fn test_compute_digest_empty() {
        let digest = ProtobufHandler::compute_digest(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_digest_hello() {
        let digest = ProtobufHandler::compute_digest(b"hello");
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_compute_digest_deterministic() {
        let a = ProtobufHandler::compute_digest(b"test data");
        let b = ProtobufHandler::compute_digest(b"test data");
        assert_eq!(a, b);
    }

    // --- FormatHandler trait method tests ---

    #[tokio::test]
    async fn test_format() {
        let handler = ProtobufHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Protobuf);
    }

    #[tokio::test]
    async fn test_parse_metadata_commit() {
        let handler = ProtobufHandler::new();
        let content = Bytes::new();
        let metadata = handler
            .parse_metadata("modules/acme/petapis/commits/abc123", &content)
            .await
            .unwrap();

        assert_eq!(metadata["kind"], "commit");
        assert_eq!(metadata["owner"], "acme");
        assert_eq!(metadata["name"], "petapis");
        assert_eq!(metadata["digest"], "abc123");
    }

    #[tokio::test]
    async fn test_parse_metadata_label() {
        let handler = ProtobufHandler::new();
        let content = Bytes::new();
        let metadata = handler
            .parse_metadata("modules/acme/petapis/labels/v1.0.0", &content)
            .await
            .unwrap();

        assert_eq!(metadata["kind"], "label");
        assert_eq!(metadata["label"], "v1.0.0");
    }

    #[tokio::test]
    async fn test_parse_metadata_blob() {
        let handler = ProtobufHandler::new();
        let content = Bytes::new();
        let metadata = handler
            .parse_metadata("blobs/sha256/deadbeef", &content)
            .await
            .unwrap();

        assert_eq!(metadata["kind"], "blob");
        assert_eq!(metadata["digest"], "deadbeef");
    }

    #[tokio::test]
    async fn test_validate_label_no_content() {
        let handler = ProtobufHandler::new();
        let content = Bytes::new();
        let result = handler
            .validate("modules/acme/petapis/labels/v1.0.0", &content)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_label_index_no_content() {
        let handler = ProtobufHandler::new();
        let content = Bytes::new();
        let result = handler
            .validate("modules/acme/petapis/_labels", &content)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_invalid_path() {
        let handler = ProtobufHandler::new();
        let content = Bytes::new();
        let result = handler.validate("completely/invalid", &content).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_generate_index_returns_none() {
        let handler = ProtobufHandler::new();
        let result = handler.generate_index().await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_default_trait() {
        let handler = ProtobufHandler::default();
        assert_eq!(handler.format(), RepositoryFormat::Protobuf);
    }
}
