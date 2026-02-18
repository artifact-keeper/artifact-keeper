//! Incus/LXC container image format handler.
//!
//! Supports Incus container and VM images distributed via the SimpleStreams
//! protocol. Images can be uploaded as unified tarballs (single `.tar.xz`)
//! or split files (metadata tarball + rootfs squashfs/qcow2).
//!
//! Path layout:
//!   `<product>/<version>/incus.tar.xz`       - Unified image tarball
//!   `<product>/<version>/metadata.tar.xz`    - Split: metadata tarball
//!   `<product>/<version>/rootfs.squashfs`     - Split: container rootfs
//!   `<product>/<version>/rootfs.img`          - Split: VM disk image (qcow2)
//!   `streams/v1/index.json`                  - SimpleStreams index
//!   `streams/v1/images.json`                 - SimpleStreams product catalog

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Incus/LXC format handler
pub struct IncusHandler;

impl IncusHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse an Incus image path into structured components.
    pub fn parse_path(path: &str) -> Result<IncusPathInfo> {
        let path = path.trim_start_matches('/');

        // SimpleStreams index files
        if path == "streams/v1/index.json" || path == "streams/v1/images.json" {
            return Ok(IncusPathInfo {
                product: None,
                version: None,
                file_type: IncusFileType::StreamsIndex,
            });
        }

        let parts: Vec<&str> = path.splitn(3, '/').collect();

        match parts.as_slice() {
            [product, version, filename] => {
                let file_type = Self::classify_file(filename)?;
                Ok(IncusPathInfo {
                    product: Some(product.to_string()),
                    version: Some(version.to_string()),
                    file_type,
                })
            }
            _ => Err(AppError::Validation(format!(
                "Invalid Incus image path: {}. Expected <product>/<version>/<file>",
                path
            ))),
        }
    }

    /// Classify an image filename into its type.
    fn classify_file(filename: &str) -> Result<IncusFileType> {
        match filename {
            "incus.tar.xz" | "lxd.tar.xz" => Ok(IncusFileType::UnifiedTarball),
            "metadata.tar.xz" | "meta.tar.xz" => Ok(IncusFileType::MetadataTarball),
            "rootfs.squashfs" => Ok(IncusFileType::RootfsSquashfs),
            "rootfs.img" => Ok(IncusFileType::RootfsQcow2),
            f if f.ends_with(".tar.xz") || f.ends_with(".tar.gz") => {
                Ok(IncusFileType::UnifiedTarball)
            }
            f if f.ends_with(".squashfs") => Ok(IncusFileType::RootfsSquashfs),
            f if f.ends_with(".qcow2") || f.ends_with(".img") => Ok(IncusFileType::RootfsQcow2),
            _ => Err(AppError::Validation(format!(
                "Unsupported Incus image file: {}. Expected .tar.xz, .squashfs, .qcow2, or .img",
                filename
            ))),
        }
    }

    /// Try to extract metadata.yaml from a tar.xz archive.
    pub fn extract_metadata(content: &[u8]) -> Option<IncusImageMetadata> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        // Try xz first, then gzip
        let reader: Box<dyn Read> = if content.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A]) {
            // XZ magic bytes
            let mut probe = [0u8; 1];
            let mut decoder = xz2::read::XzDecoder::new(content);
            match decoder.read(&mut probe) {
                Ok(1) => {
                    // Valid xz stream; create a fresh decoder for the full content
                    Box::new(xz2::read::XzDecoder::new(content))
                }
                _ => return None,
            }
        } else {
            Box::new(GzDecoder::new(content))
        };

        let mut archive = tar::Archive::new(reader);
        let entries = archive.entries().ok()?;

        for entry in entries {
            let mut entry = entry.ok()?;
            let path = entry.path().ok()?;
            let path_str = path.to_string_lossy();

            if path_str == "metadata.yaml" || path_str == "./metadata.yaml" {
                let mut yaml_content = String::new();
                entry.read_to_string(&mut yaml_content).ok()?;
                return Self::parse_metadata_yaml(&yaml_content);
            }
        }

        None
    }

    /// Parse the metadata.yaml content.
    fn parse_metadata_yaml(content: &str) -> Option<IncusImageMetadata> {
        // Parse YAML manually to avoid adding serde_yaml dependency.
        // metadata.yaml is simple key-value with a properties section.
        let mut metadata = IncusImageMetadata::default();

        let mut in_properties = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed == "properties:" {
                in_properties = true;
                continue;
            }

            if !line.starts_with(' ') && !line.starts_with('\t') {
                in_properties = false;
            }

            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim();
                let value = value.trim().trim_matches('"').trim_matches('\'');

                if in_properties {
                    match key {
                        "os" => metadata.os = Some(value.to_string()),
                        "release" => metadata.release = Some(value.to_string()),
                        "variant" => metadata.variant = Some(value.to_string()),
                        "description" => metadata.description = Some(value.to_string()),
                        "serial" => metadata.serial = Some(value.to_string()),
                        _ => {}
                    }
                } else {
                    match key {
                        "architecture" => metadata.architecture = Some(value.to_string()),
                        "creation_date" => metadata.creation_date = value.parse().ok(),
                        "expiry_date" => metadata.expiry_date = value.parse().ok(),
                        _ => {}
                    }
                }
            }
        }

        if metadata.architecture.is_some() {
            Some(metadata)
        } else {
            None
        }
    }
}

impl Default for IncusHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for IncusHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Incus
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "file_type": info.file_type.as_str(),
        });

        if let Some(product) = &info.product {
            metadata["product"] = serde_json::Value::String(product.clone());
        }
        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        // Try extracting metadata.yaml from tarballs
        if !content.is_empty() && info.file_type.is_tarball() {
            if let Some(image_meta) = Self::extract_metadata(content) {
                metadata["image_metadata"] =
                    serde_json::to_value(&image_meta).unwrap_or(serde_json::Value::Null);
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // SimpleStreams index is generated on demand by the API handler
        Ok(None)
    }
}

/// Parsed Incus image path info
#[derive(Debug)]
pub struct IncusPathInfo {
    pub product: Option<String>,
    pub version: Option<String>,
    pub file_type: IncusFileType,
}

/// Incus image file type
#[derive(Debug, PartialEq, Eq)]
pub enum IncusFileType {
    /// Single tarball containing metadata + rootfs
    UnifiedTarball,
    /// Metadata-only tarball (split format)
    MetadataTarball,
    /// SquashFS rootfs for containers (split format)
    RootfsSquashfs,
    /// QCOW2 disk image for VMs (split format)
    RootfsQcow2,
    /// SimpleStreams index/catalog file
    StreamsIndex,
}

impl IncusFileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnifiedTarball => "unified_tarball",
            Self::MetadataTarball => "metadata_tarball",
            Self::RootfsSquashfs => "rootfs_squashfs",
            Self::RootfsQcow2 => "rootfs_qcow2",
            Self::StreamsIndex => "streams_index",
        }
    }

    pub fn is_tarball(&self) -> bool {
        matches!(self, Self::UnifiedTarball | Self::MetadataTarball)
    }
}

/// Parsed metadata.yaml content from an Incus image
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IncusImageMetadata {
    pub architecture: Option<String>,
    pub creation_date: Option<i64>,
    pub expiry_date: Option<i64>,
    pub os: Option<String>,
    pub release: Option<String>,
    pub variant: Option<String>,
    pub description: Option<String>,
    pub serial: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unified_tarball_path() {
        let info = IncusHandler::parse_path("ubuntu-noble/20240215/incus.tar.xz").unwrap();
        assert_eq!(info.product, Some("ubuntu-noble".to_string()));
        assert_eq!(info.version, Some("20240215".to_string()));
        assert_eq!(info.file_type, IncusFileType::UnifiedTarball);
    }

    #[test]
    fn test_parse_metadata_tarball_path() {
        let info = IncusHandler::parse_path("alpine-edge/20240301/metadata.tar.xz").unwrap();
        assert_eq!(info.product, Some("alpine-edge".to_string()));
        assert_eq!(info.version, Some("20240301".to_string()));
        assert_eq!(info.file_type, IncusFileType::MetadataTarball);
    }

    #[test]
    fn test_parse_rootfs_squashfs_path() {
        let info = IncusHandler::parse_path("debian-bookworm/v1.0/rootfs.squashfs").unwrap();
        assert_eq!(info.product, Some("debian-bookworm".to_string()));
        assert_eq!(info.version, Some("v1.0".to_string()));
        assert_eq!(info.file_type, IncusFileType::RootfsSquashfs);
    }

    #[test]
    fn test_parse_vm_image_path() {
        let info = IncusHandler::parse_path("ubuntu-noble/20240215/rootfs.img").unwrap();
        assert_eq!(info.file_type, IncusFileType::RootfsQcow2);
    }

    #[test]
    fn test_parse_streams_index() {
        let info = IncusHandler::parse_path("streams/v1/index.json").unwrap();
        assert_eq!(info.file_type, IncusFileType::StreamsIndex);
        assert!(info.product.is_none());
    }

    #[test]
    fn test_parse_streams_images() {
        let info = IncusHandler::parse_path("streams/v1/images.json").unwrap();
        assert_eq!(info.file_type, IncusFileType::StreamsIndex);
    }

    #[test]
    fn test_invalid_path() {
        assert!(IncusHandler::parse_path("just-a-file.tar.xz").is_err());
    }

    #[test]
    fn test_unsupported_file_type() {
        assert!(IncusHandler::parse_path("product/version/random.zip").is_err());
    }

    #[test]
    fn test_parse_metadata_yaml() {
        let yaml = r#"
architecture: x86_64
creation_date: 1708000000
expiry_date: 1710000000
properties:
  os: Ubuntu
  release: noble
  variant: default
  description: Ubuntu noble amd64 (20240215)
  serial: "20240215"
"#;
        let meta = IncusHandler::parse_metadata_yaml(yaml).unwrap();
        assert_eq!(meta.architecture, Some("x86_64".to_string()));
        assert_eq!(meta.creation_date, Some(1708000000));
        assert_eq!(meta.expiry_date, Some(1710000000));
        assert_eq!(meta.os, Some("Ubuntu".to_string()));
        assert_eq!(meta.release, Some("noble".to_string()));
        assert_eq!(meta.variant, Some("default".to_string()));
        assert_eq!(meta.serial, Some("20240215".to_string()));
    }

    #[test]
    fn test_parse_metadata_yaml_missing_arch() {
        let yaml = "creation_date: 1708000000\n";
        assert!(IncusHandler::parse_metadata_yaml(yaml).is_none());
    }

    #[test]
    fn test_file_type_as_str() {
        assert_eq!(IncusFileType::UnifiedTarball.as_str(), "unified_tarball");
        assert_eq!(IncusFileType::MetadataTarball.as_str(), "metadata_tarball");
        assert_eq!(IncusFileType::RootfsSquashfs.as_str(), "rootfs_squashfs");
        assert_eq!(IncusFileType::RootfsQcow2.as_str(), "rootfs_qcow2");
        assert_eq!(IncusFileType::StreamsIndex.as_str(), "streams_index");
    }

    #[test]
    fn test_file_type_is_tarball() {
        assert!(IncusFileType::UnifiedTarball.is_tarball());
        assert!(IncusFileType::MetadataTarball.is_tarball());
        assert!(!IncusFileType::RootfsSquashfs.is_tarball());
        assert!(!IncusFileType::RootfsQcow2.is_tarball());
        assert!(!IncusFileType::StreamsIndex.is_tarball());
    }

    #[test]
    fn test_lxd_compat_tarball() {
        let info = IncusHandler::parse_path("product/v1/lxd.tar.xz").unwrap();
        assert_eq!(info.file_type, IncusFileType::UnifiedTarball);
    }

    #[tokio::test]
    async fn test_validate_valid_path() {
        let handler = IncusHandler::new();
        assert!(handler
            .validate("ubuntu/20240215/incus.tar.xz", &Bytes::new())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_invalid_path() {
        let handler = IncusHandler::new();
        assert!(handler.validate("bad-path", &Bytes::new()).await.is_err());
    }

    #[tokio::test]
    async fn test_parse_metadata_empty_content() {
        let handler = IncusHandler::new();
        let result = handler
            .parse_metadata("ubuntu/20240215/rootfs.squashfs", &Bytes::new())
            .await
            .unwrap();
        assert_eq!(result["file_type"], "rootfs_squashfs");
        assert_eq!(result["product"], "ubuntu");
        assert_eq!(result["version"], "20240215");
    }
}
