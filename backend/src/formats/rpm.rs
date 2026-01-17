//! RPM format handler.
//!
//! Implements YUM/DNF repository for RPM packages.
//! Supports parsing RPM headers and generating repodata.

use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::se::to_string as xml_to_string;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// RPM format handler
pub struct RpmHandler;

// RPM header magic numbers
const RPM_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const RPM_HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

// RPM header tags
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_SUMMARY: u32 = 1004;
const RPMTAG_DESCRIPTION: u32 = 1005;
const RPMTAG_SIZE: u32 = 1009;
const RPMTAG_LICENSE: u32 = 1014;
const RPMTAG_GROUP: u32 = 1016;
const RPMTAG_URL: u32 = 1020;
const RPMTAG_ARCH: u32 = 1022;
const RPMTAG_SOURCERPM: u32 = 1044;
const RPMTAG_PROVIDENAME: u32 = 1047;
const RPMTAG_REQUIRENAME: u32 = 1049;

impl RpmHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse RPM path
    /// Formats:
    ///   repodata/repomd.xml           - Repository metadata
    ///   repodata/primary.xml.gz       - Primary package metadata
    ///   repodata/filelists.xml.gz     - File listings
    ///   repodata/other.xml.gz         - Changelogs
    ///   Packages/<name>-<version>-<release>.<arch>.rpm
    ///   <name>-<version>-<release>.<arch>.rpm
    pub fn parse_path(path: &str) -> Result<RpmPathInfo> {
        let path = path.trim_start_matches('/');

        // Repodata files
        if path == "repodata/repomd.xml" || path.ends_with("/repomd.xml") {
            return Ok(RpmPathInfo {
                name: None,
                version: None,
                release: None,
                arch: None,
                operation: RpmOperation::RepoMd,
            });
        }

        if path.contains("repodata/") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            return Ok(RpmPathInfo {
                name: None,
                version: None,
                release: None,
                arch: None,
                operation: Self::parse_repodata_operation(filename),
            });
        }

        // RPM package
        if path.ends_with(".rpm") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            return Self::parse_rpm_filename(filename);
        }

        Err(AppError::Validation(format!(
            "Invalid RPM repository path: {}",
            path
        )))
    }

    /// Parse repodata filename to determine operation
    fn parse_repodata_operation(filename: &str) -> RpmOperation {
        if filename.contains("primary") {
            RpmOperation::Primary
        } else if filename.contains("filelists") {
            RpmOperation::Filelists
        } else if filename.contains("other") {
            RpmOperation::Other
        } else if filename.contains("comps") {
            RpmOperation::Comps
        } else if filename.contains("updateinfo") {
            RpmOperation::UpdateInfo
        } else {
            RpmOperation::RepoMd
        }
    }

    /// Parse RPM filename
    /// Format: <name>-<version>-<release>.<arch>.rpm
    pub fn parse_rpm_filename(filename: &str) -> Result<RpmPathInfo> {
        let name = filename.trim_end_matches(".rpm");

        // Split off architecture
        let (name_ver_rel, arch) = name
            .rsplit_once('.')
            .ok_or_else(|| AppError::Validation(format!("Invalid RPM filename: {}", filename)))?;

        // Split name-version-release
        // Find the last two hyphens
        let parts: Vec<&str> = name_ver_rel.rsplitn(3, '-').collect();

        if parts.len() != 3 {
            return Err(AppError::Validation(format!(
                "Invalid RPM filename format: {}",
                filename
            )));
        }

        let release = parts[0].to_string();
        let version = parts[1].to_string();
        let pkg_name = parts[2].to_string();

        Ok(RpmPathInfo {
            name: Some(pkg_name),
            version: Some(version),
            release: Some(release),
            arch: Some(arch.to_string()),
            operation: RpmOperation::Package,
        })
    }

    /// Parse RPM package header
    pub fn parse_rpm_header(content: &[u8]) -> Result<RpmMetadata> {
        // Verify RPM magic
        if content.len() < 96 {
            return Err(AppError::Validation("RPM file too small".to_string()));
        }

        if content[..4] != RPM_MAGIC {
            return Err(AppError::Validation("Invalid RPM magic number".to_string()));
        }

        // Read lead
        let _major = content[4];
        let _minor = content[5];
        let _type = u16::from_be_bytes([content[6], content[7]]);
        let _archnum = u16::from_be_bytes([content[8], content[9]]);

        // Read package name from lead (66 bytes starting at offset 10)
        let name_bytes = &content[10..76];
        let lead_name = String::from_utf8_lossy(
            &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(66)],
        )
        .to_string();

        // Skip to signature header (at offset 96)
        let mut offset = 96;

        // Skip signature header
        if content.len() > offset + 16 && content[offset..offset + 3] == RPM_HEADER_MAGIC {
            let nindex = u32::from_be_bytes([
                content[offset + 8],
                content[offset + 9],
                content[offset + 10],
                content[offset + 11],
            ]) as usize;
            let hsize = u32::from_be_bytes([
                content[offset + 12],
                content[offset + 13],
                content[offset + 14],
                content[offset + 15],
            ]) as usize;

            offset += 16 + (nindex * 16) + hsize;
            // Align to 8-byte boundary
            offset = (offset + 7) & !7;
        }

        // Parse main header
        let metadata = if content.len() > offset + 16 && content[offset..offset + 3] == RPM_HEADER_MAGIC
        {
            Self::parse_header_section(&content[offset..])?
        } else {
            // Fallback to lead name
            RpmMetadata {
                name: lead_name,
                version: String::new(),
                release: String::new(),
                arch: String::new(),
                summary: None,
                description: None,
                license: None,
                group: None,
                url: None,
                size: None,
                source_rpm: None,
                provides: vec![],
                requires: vec![],
            }
        };

        Ok(metadata)
    }

    /// Parse RPM header section
    fn parse_header_section(data: &[u8]) -> Result<RpmMetadata> {
        if data.len() < 16 || data[..3] != RPM_HEADER_MAGIC {
            return Err(AppError::Validation("Invalid RPM header".to_string()));
        }

        let _version = data[3];
        let nindex = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let hsize = u32::from_be_bytes([data[12], data[13], data[14], data[15]]) as usize;

        let index_start = 16;
        let store_start = index_start + (nindex * 16);

        if data.len() < store_start + hsize {
            return Err(AppError::Validation("RPM header truncated".to_string()));
        }

        let store = &data[store_start..store_start + hsize];
        let mut tags: HashMap<u32, Vec<u8>> = HashMap::new();

        // Parse index entries
        for i in 0..nindex {
            let idx_offset = index_start + (i * 16);
            let tag = u32::from_be_bytes([
                data[idx_offset],
                data[idx_offset + 1],
                data[idx_offset + 2],
                data[idx_offset + 3],
            ]);
            let _data_type = u32::from_be_bytes([
                data[idx_offset + 4],
                data[idx_offset + 5],
                data[idx_offset + 6],
                data[idx_offset + 7],
            ]);
            let data_offset = u32::from_be_bytes([
                data[idx_offset + 8],
                data[idx_offset + 9],
                data[idx_offset + 10],
                data[idx_offset + 11],
            ]) as usize;
            let count = u32::from_be_bytes([
                data[idx_offset + 12],
                data[idx_offset + 13],
                data[idx_offset + 14],
                data[idx_offset + 15],
            ]) as usize;

            if data_offset < store.len() {
                // Read string (null-terminated)
                let end = store[data_offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| data_offset + p)
                    .unwrap_or(store.len().min(data_offset + count));
                tags.insert(tag, store[data_offset..end].to_vec());
            }
        }

        let get_string = |tag: u32| -> String {
            tags.get(&tag)
                .map(|v| String::from_utf8_lossy(v).to_string())
                .unwrap_or_default()
        };

        Ok(RpmMetadata {
            name: get_string(RPMTAG_NAME),
            version: get_string(RPMTAG_VERSION),
            release: get_string(RPMTAG_RELEASE),
            arch: get_string(RPMTAG_ARCH),
            summary: Some(get_string(RPMTAG_SUMMARY)).filter(|s| !s.is_empty()),
            description: Some(get_string(RPMTAG_DESCRIPTION)).filter(|s| !s.is_empty()),
            license: Some(get_string(RPMTAG_LICENSE)).filter(|s| !s.is_empty()),
            group: Some(get_string(RPMTAG_GROUP)).filter(|s| !s.is_empty()),
            url: Some(get_string(RPMTAG_URL)).filter(|s| !s.is_empty()),
            size: tags.get(&RPMTAG_SIZE).and_then(|v| {
                if v.len() >= 4 {
                    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as u64)
                } else {
                    None
                }
            }),
            source_rpm: Some(get_string(RPMTAG_SOURCERPM)).filter(|s| !s.is_empty()),
            provides: vec![get_string(RPMTAG_PROVIDENAME)]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect(),
            requires: vec![get_string(RPMTAG_REQUIRENAME)]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }
}

impl Default for RpmHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for RpmHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Rpm
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "operation": format!("{:?}", info.operation),
        });

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        if let Some(release) = &info.release {
            metadata["release"] = serde_json::Value::String(release.clone());
        }

        if let Some(arch) = &info.arch {
            metadata["arch"] = serde_json::Value::String(arch.clone());
        }

        // Parse RPM header if this is a package
        if !content.is_empty() && matches!(info.operation, RpmOperation::Package) {
            if let Ok(rpm_meta) = Self::parse_rpm_header(content) {
                metadata["rpm"] = serde_json::to_value(&rpm_meta)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate RPM packages
        if !content.is_empty() && matches!(info.operation, RpmOperation::Package) {
            let rpm_meta = Self::parse_rpm_header(content)?;

            // Verify name matches
            if let Some(path_name) = &info.name {
                if !rpm_meta.name.is_empty() && &rpm_meta.name != path_name {
                    return Err(AppError::Validation(format!(
                        "Package name mismatch: path says '{}' but RPM says '{}'",
                        path_name, rpm_meta.name
                    )));
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Repodata is generated on demand
        Ok(None)
    }
}

/// RPM path info
#[derive(Debug)]
pub struct RpmPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub release: Option<String>,
    pub arch: Option<String>,
    pub operation: RpmOperation,
}

/// RPM operation type
#[derive(Debug)]
pub enum RpmOperation {
    RepoMd,
    Primary,
    Filelists,
    Other,
    Comps,
    UpdateInfo,
    Package,
}

/// RPM package metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct RpmMetadata {
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub source_rpm: Option<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
}

/// Repomd.xml structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "repomd")]
pub struct RepoMd {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "@xmlns:rpm")]
    pub xmlns_rpm: String,
    pub revision: String,
    #[serde(rename = "data")]
    pub data: Vec<RepoMdData>,
}

/// Repomd data entry
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoMdData {
    #[serde(rename = "@type")]
    pub data_type: String,
    pub checksum: RepoMdChecksum,
    #[serde(rename = "open-checksum")]
    pub open_checksum: Option<RepoMdChecksum>,
    pub location: RepoMdLocation,
    pub timestamp: i64,
    pub size: u64,
    #[serde(rename = "open-size")]
    pub open_size: Option<u64>,
}

/// Repomd checksum
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoMdChecksum {
    #[serde(rename = "@type")]
    pub checksum_type: String,
    #[serde(rename = "$value")]
    pub value: String,
}

/// Repomd location
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoMdLocation {
    #[serde(rename = "@href")]
    pub href: String,
}

/// Generate repomd.xml
pub fn generate_repomd(data: Vec<RepoMdData>) -> Result<String> {
    let repomd = RepoMd {
        xmlns: "http://linux.duke.edu/metadata/repo".to_string(),
        xmlns_rpm: "http://linux.duke.edu/metadata/rpm".to_string(),
        revision: chrono::Utc::now().timestamp().to_string(),
        data,
    };

    xml_to_string(&repomd).map_err(|e| AppError::Internal(format!("Failed to generate repomd.xml: {}", e)))
}

/// Primary.xml package entry
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimaryPackage {
    #[serde(rename = "@type")]
    pub pkg_type: String,
    pub name: String,
    pub arch: String,
    pub version: PrimaryVersion,
    pub checksum: RepoMdChecksum,
    pub summary: String,
    pub description: String,
    pub packager: Option<String>,
    pub url: Option<String>,
    pub time: PrimaryTime,
    pub size: PrimarySize,
    pub location: RepoMdLocation,
    pub format: PrimaryFormat,
}

/// Primary version
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimaryVersion {
    #[serde(rename = "@epoch")]
    pub epoch: String,
    #[serde(rename = "@ver")]
    pub ver: String,
    #[serde(rename = "@rel")]
    pub rel: String,
}

/// Primary time
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimaryTime {
    #[serde(rename = "@file")]
    pub file: i64,
    #[serde(rename = "@build")]
    pub build: i64,
}

/// Primary size
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimarySize {
    #[serde(rename = "@package")]
    pub package: u64,
    #[serde(rename = "@installed")]
    pub installed: u64,
    #[serde(rename = "@archive")]
    pub archive: u64,
}

/// Primary format section
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrimaryFormat {
    #[serde(rename = "rpm:license")]
    pub license: Option<String>,
    #[serde(rename = "rpm:vendor")]
    pub vendor: Option<String>,
    #[serde(rename = "rpm:group")]
    pub group: Option<String>,
    #[serde(rename = "rpm:buildhost")]
    pub buildhost: Option<String>,
    #[serde(rename = "rpm:sourcerpm")]
    pub sourcerpm: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rpm_filename() {
        let info = RpmHandler::parse_rpm_filename("nginx-1.24.0-1.el9.x86_64.rpm").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.24.0".to_string()));
        assert_eq!(info.release, Some("1.el9".to_string()));
        assert_eq!(info.arch, Some("x86_64".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_complex() {
        let info = RpmHandler::parse_rpm_filename("python3-numpy-1.24.2-4.el9.x86_64.rpm").unwrap();
        assert_eq!(info.name, Some("python3-numpy".to_string()));
        assert_eq!(info.version, Some("1.24.2".to_string()));
        assert_eq!(info.release, Some("4.el9".to_string()));
    }

    #[test]
    fn test_parse_path_repomd() {
        let info = RpmHandler::parse_path("repodata/repomd.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
    }

    #[test]
    fn test_parse_path_primary() {
        let info = RpmHandler::parse_path("repodata/abc123-primary.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Primary));
    }

    #[test]
    fn test_parse_path_package() {
        let info = RpmHandler::parse_path("Packages/nginx-1.24.0-1.el9.x86_64.rpm").unwrap();
        assert!(matches!(info.operation, RpmOperation::Package));
        assert_eq!(info.name, Some("nginx".to_string()));
    }
}
