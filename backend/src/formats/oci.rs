//! Docker/OCI format handler (Registry API v2).
//!
//! Implements OCI Distribution Specification for container images.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// OCI/Docker format handler
pub struct OciHandler;

impl OciHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse OCI path
    /// Formats:
    ///   /v2/<name>/manifests/<reference>
    ///   /v2/<name>/blobs/<digest>
    ///   /v2/<name>/blobs/uploads/
    pub fn parse_path(path: &str) -> Result<OciPathInfo> {
        let path = path.trim_start_matches('/');

        if !path.starts_with("v2/") {
            return Err(AppError::Validation(
                "OCI path must start with v2/".to_string(),
            ));
        }

        let rest = &path[3..];
        let parts: Vec<&str> = rest.split('/').collect();

        if parts.len() < 2 {
            return Err(AppError::Validation("Invalid OCI path".to_string()));
        }

        // Find the operation part (manifests, blobs, etc.)
        let op_index = parts.iter().position(|&p| p == "manifests" || p == "blobs" || p == "tags");

        match op_index {
            Some(idx) => {
                let name = parts[..idx].join("/");
                let operation = parts[idx];

                match operation {
                    "manifests" => {
                        let reference = parts.get(idx + 1).map(|s| s.to_string());
                        Ok(OciPathInfo {
                            name,
                            operation: OciOperation::Manifest,
                            reference,
                            digest: None,
                        })
                    }
                    "blobs" => {
                        if parts.get(idx + 1) == Some(&"uploads") {
                            // Blob upload
                            let upload_id = parts.get(idx + 2).map(|s| s.to_string());
                            Ok(OciPathInfo {
                                name,
                                operation: OciOperation::BlobUpload,
                                reference: upload_id,
                                digest: None,
                            })
                        } else {
                            // Blob fetch
                            let digest = parts.get(idx + 1).map(|s| s.to_string());
                            Ok(OciPathInfo {
                                name,
                                operation: OciOperation::Blob,
                                reference: None,
                                digest,
                            })
                        }
                    }
                    "tags" => {
                        // Tag list
                        Ok(OciPathInfo {
                            name,
                            operation: OciOperation::TagList,
                            reference: None,
                            digest: None,
                        })
                    }
                    _ => Err(AppError::Validation(format!(
                        "Unknown OCI operation: {}",
                        operation
                    ))),
                }
            }
            None => Err(AppError::Validation("Missing OCI operation in path".to_string())),
        }
    }

    /// Parse an OCI manifest
    pub fn parse_manifest(content: &[u8]) -> Result<OciManifest> {
        serde_json::from_slice(content)
            .map_err(|e| AppError::Validation(format!("Invalid OCI manifest: {}", e)))
    }

    /// Validate a digest format
    pub fn validate_digest(digest: &str) -> Result<()> {
        // Format: algorithm:hex
        let parts: Vec<&str> = digest.split(':').collect();
        if parts.len() != 2 {
            return Err(AppError::Validation(
                "Invalid digest format, expected algorithm:hex".to_string(),
            ));
        }

        let algorithm = parts[0];
        let hex_hash = parts[1];

        match algorithm {
            "sha256" => {
                if hex_hash.len() != 64 {
                    return Err(AppError::Validation(
                        "SHA256 digest must be 64 hex characters".to_string(),
                    ));
                }
            }
            "sha512" => {
                if hex_hash.len() != 128 {
                    return Err(AppError::Validation(
                        "SHA512 digest must be 128 hex characters".to_string(),
                    ));
                }
            }
            _ => {
                return Err(AppError::Validation(format!(
                    "Unsupported digest algorithm: {}",
                    algorithm
                )));
            }
        }

        // Validate hex characters
        if !hex_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::Validation(
                "Digest contains non-hex characters".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for OciHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for OciHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Docker
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "name": info.name,
            "operation": format!("{:?}", info.operation),
        });

        if let Some(ref reference) = info.reference {
            metadata["reference"] = serde_json::Value::String(reference.clone());
        }

        if let Some(ref digest) = info.digest {
            metadata["digest"] = serde_json::Value::String(digest.clone());
        }

        // Parse manifest if this is a manifest operation
        if matches!(info.operation, OciOperation::Manifest) && !content.is_empty() {
            if let Ok(manifest) = Self::parse_manifest(content) {
                metadata["schemaVersion"] = serde_json::Value::Number(manifest.schema_version.into());
                if let Some(media_type) = manifest.media_type {
                    metadata["mediaType"] = serde_json::Value::String(media_type);
                }
                if let Some(config) = manifest.config {
                    metadata["config"] = serde_json::json!({
                        "mediaType": config.media_type,
                        "size": config.size,
                        "digest": config.digest,
                    });
                }
                metadata["layerCount"] = serde_json::Value::Number(manifest.layers.len().into());
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate digest format if present
        if let Some(ref digest) = info.digest {
            Self::validate_digest(digest)?;
        }

        // Validate manifest if this is a manifest operation
        if matches!(info.operation, OciOperation::Manifest) && !content.is_empty() {
            let _manifest = Self::parse_manifest(content)?;
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // OCI doesn't use static index files
        Ok(None)
    }
}

/// OCI path info
#[derive(Debug)]
pub struct OciPathInfo {
    pub name: String,
    pub operation: OciOperation,
    pub reference: Option<String>,
    pub digest: Option<String>,
}

/// OCI operation type
#[derive(Debug)]
pub enum OciOperation {
    Manifest,
    Blob,
    BlobUpload,
    TagList,
}

/// OCI manifest (Image Manifest or Index)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciManifest {
    pub schema_version: u32,
    pub media_type: Option<String>,
    pub config: Option<OciDescriptor>,
    #[serde(default)]
    pub layers: Vec<OciDescriptor>,
    #[serde(default)]
    pub manifests: Vec<OciManifestDescriptor>, // For manifest index
    pub annotations: Option<std::collections::HashMap<String, String>>,
}

/// OCI content descriptor
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    pub urls: Option<Vec<String>>,
    pub annotations: Option<std::collections::HashMap<String, String>>,
}

/// OCI manifest descriptor (for index)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciManifestDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    pub platform: Option<OciPlatform>,
    pub annotations: Option<std::collections::HashMap<String, String>>,
}

/// OCI platform specification
#[derive(Debug, Serialize, Deserialize)]
pub struct OciPlatform {
    pub architecture: String,
    pub os: String,
    #[serde(rename = "os.version")]
    pub os_version: Option<String>,
    #[serde(rename = "os.features")]
    pub os_features: Option<Vec<String>>,
    pub variant: Option<String>,
}

// OCI media types
pub mod media_types {
    pub const MANIFEST_V2: &str = "application/vnd.docker.distribution.manifest.v2+json";
    pub const MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
    pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
    pub const CONFIG: &str = "application/vnd.docker.container.image.v1+json";
    pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    pub const LAYER_TAR_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
    pub const OCI_LAYER_TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest_path() {
        let info = OciHandler::parse_path("v2/library/nginx/manifests/latest").unwrap();
        assert_eq!(info.name, "library/nginx");
        assert!(matches!(info.operation, OciOperation::Manifest));
        assert_eq!(info.reference, Some("latest".to_string()));
    }

    #[test]
    fn test_parse_blob_path() {
        let info = OciHandler::parse_path(
            "v2/myrepo/myimage/blobs/sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
        )
        .unwrap();
        assert_eq!(info.name, "myrepo/myimage");
        assert!(matches!(info.operation, OciOperation::Blob));
        assert!(info.digest.is_some());
    }

    #[test]
    fn test_parse_upload_path() {
        let info = OciHandler::parse_path("v2/library/nginx/blobs/uploads/upload-id-123").unwrap();
        assert_eq!(info.name, "library/nginx");
        assert!(matches!(info.operation, OciOperation::BlobUpload));
        assert_eq!(info.reference, Some("upload-id-123".to_string()));
    }

    #[test]
    fn test_validate_digest() {
        // Valid SHA256
        assert!(OciHandler::validate_digest(
            "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
        )
        .is_ok());

        // Invalid length
        assert!(OciHandler::validate_digest("sha256:abc123").is_err());

        // Invalid algorithm
        assert!(OciHandler::validate_digest("md5:abc123").is_err());
    }
}
