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
// Scriptlets (#4033). Each body tag has a sibling `*PROG` tag naming the
// interpreter it runs under; all four run as root during `dnf install`.
const RPMTAG_PREIN: u32 = 1023;
const RPMTAG_POSTIN: u32 = 1024;
const RPMTAG_PREUN: u32 = 1025;
const RPMTAG_POSTUN: u32 = 1026;
const RPMTAG_PREINPROG: u32 = 1085;
const RPMTAG_POSTINPROG: u32 = 1086;
const RPMTAG_PREUNPROG: u32 = 1087;
const RPMTAG_POSTUNPROG: u32 = 1088;
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
        let metadata =
            if content.len() > offset + 16 && content[offset..offset + 3] == RPM_HEADER_MAGIC {
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
                    pre_install: None,
                    post_install: None,
                    pre_uninstall: None,
                    post_uninstall: None,
                    pre_install_prog: None,
                    post_install_prog: None,
                    pre_uninstall_prog: None,
                    post_uninstall_prog: None,
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
        let get_optional =
            |tag: u32| -> Option<String> { Some(get_string(tag)).filter(|s| !s.is_empty()) };

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
            pre_install: get_optional(RPMTAG_PREIN),
            post_install: get_optional(RPMTAG_POSTIN),
            pre_uninstall: get_optional(RPMTAG_PREUN),
            post_uninstall: get_optional(RPMTAG_POSTUN),
            pre_install_prog: get_optional(RPMTAG_PREINPROG),
            post_install_prog: get_optional(RPMTAG_POSTINPROG),
            pre_uninstall_prog: get_optional(RPMTAG_PREUNPROG),
            post_uninstall_prog: get_optional(RPMTAG_POSTUNPROG),
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
    // Scriptlet bodies and their interpreters (#4033). Skipped by serde: the
    // whole struct is stored as artifact metadata by `parse_metadata`, and
    // script text belongs in `package_install_scripts`, not there.
    #[serde(skip)]
    pub pre_install: Option<String>,
    #[serde(skip)]
    pub post_install: Option<String>,
    #[serde(skip)]
    pub pre_uninstall: Option<String>,
    #[serde(skip)]
    pub post_uninstall: Option<String>,
    #[serde(skip)]
    pub pre_install_prog: Option<String>,
    #[serde(skip)]
    pub post_install_prog: Option<String>,
    #[serde(skip)]
    pub pre_uninstall_prog: Option<String>,
    #[serde(skip)]
    pub post_uninstall_prog: Option<String>,
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

    xml_to_string(&repomd)
        .map_err(|e| AppError::Internal(format!("Failed to generate repomd.xml: {}", e)))
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

    // ========================================================================
    // parse_rpm_filename tests
    // ========================================================================

    #[test]
    fn test_parse_rpm_filename() {
        let info = RpmHandler::parse_rpm_filename("nginx-1.24.0-1.el9.x86_64.rpm").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.24.0".to_string()));
        assert_eq!(info.release, Some("1.el9".to_string()));
        assert_eq!(info.arch, Some("x86_64".to_string()));
        assert!(matches!(info.operation, RpmOperation::Package));
    }

    #[test]
    fn test_parse_rpm_filename_complex() {
        let info = RpmHandler::parse_rpm_filename("python3-numpy-1.24.2-4.el9.x86_64.rpm").unwrap();
        assert_eq!(info.name, Some("python3-numpy".to_string()));
        assert_eq!(info.version, Some("1.24.2".to_string()));
        assert_eq!(info.release, Some("4.el9".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_noarch() {
        let info = RpmHandler::parse_rpm_filename("bash-completion-2.11-5.el9.noarch.rpm").unwrap();
        assert_eq!(info.name, Some("bash-completion".to_string()));
        assert_eq!(info.version, Some("2.11".to_string()));
        assert_eq!(info.release, Some("5.el9".to_string()));
        assert_eq!(info.arch, Some("noarch".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_src() {
        let info = RpmHandler::parse_rpm_filename("nginx-1.24.0-1.el9.src.rpm").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.arch, Some("src".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_i686() {
        let info = RpmHandler::parse_rpm_filename("glibc-2.34-60.el9.i686.rpm").unwrap();
        assert_eq!(info.name, Some("glibc".to_string()));
        assert_eq!(info.arch, Some("i686".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_aarch64() {
        let info = RpmHandler::parse_rpm_filename("kernel-5.14.0-1.el9.aarch64.rpm").unwrap();
        assert_eq!(info.name, Some("kernel".to_string()));
        assert_eq!(info.arch, Some("aarch64".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_no_arch_dot() {
        // Missing dot before arch means rsplit_once('.') returns None
        let result = RpmHandler::parse_rpm_filename("invalidname.rpm");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rpm_filename_too_few_hyphens() {
        // Only 1 hyphen after removing arch: rsplitn(3, '-') gives 2 parts, not 3
        let result = RpmHandler::parse_rpm_filename("name-1.0.x86_64.rpm");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rpm_filename_many_hyphens_in_name() {
        let info = RpmHandler::parse_rpm_filename("a-b-c-d-1.0-1.el9.x86_64.rpm").unwrap();
        assert_eq!(info.name, Some("a-b-c-d".to_string()));
        assert_eq!(info.version, Some("1.0".to_string()));
        assert_eq!(info.release, Some("1.el9".to_string()));
    }

    // ========================================================================
    // parse_path tests
    // ========================================================================

    #[test]
    fn test_parse_path_repomd() {
        let info = RpmHandler::parse_path("repodata/repomd.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
        assert!(info.name.is_none());
        assert!(info.version.is_none());
        assert!(info.release.is_none());
        assert!(info.arch.is_none());
    }

    #[test]
    fn test_parse_path_repomd_nested() {
        let info = RpmHandler::parse_path("centos/9/repodata/repomd.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
    }

    #[test]
    fn test_parse_path_primary() {
        let info = RpmHandler::parse_path("repodata/abc123-primary.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Primary));
    }

    #[test]
    fn test_parse_path_filelists() {
        let info = RpmHandler::parse_path("repodata/abc123-filelists.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Filelists));
    }

    #[test]
    fn test_parse_path_other() {
        let info = RpmHandler::parse_path("repodata/abc123-other.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Other));
    }

    #[test]
    fn test_parse_path_comps() {
        let info = RpmHandler::parse_path("repodata/comps.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::Comps));
    }

    #[test]
    fn test_parse_path_updateinfo() {
        let info = RpmHandler::parse_path("repodata/updateinfo.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::UpdateInfo));
    }

    #[test]
    fn test_parse_path_repodata_unknown_defaults_to_repomd() {
        let info = RpmHandler::parse_path("repodata/something-unknown.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
    }

    #[test]
    fn test_parse_path_package() {
        let info = RpmHandler::parse_path("Packages/nginx-1.24.0-1.el9.x86_64.rpm").unwrap();
        assert!(matches!(info.operation, RpmOperation::Package));
        assert_eq!(info.name, Some("nginx".to_string()));
    }

    #[test]
    fn test_parse_path_direct_rpm() {
        let info = RpmHandler::parse_path("nginx-1.24.0-1.el9.x86_64.rpm").unwrap();
        assert!(matches!(info.operation, RpmOperation::Package));
        assert_eq!(info.name, Some("nginx".to_string()));
    }

    #[test]
    fn test_parse_path_leading_slash() {
        let info = RpmHandler::parse_path("/repodata/repomd.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
    }

    #[test]
    fn test_parse_path_invalid() {
        let result = RpmHandler::parse_path("some/random/path.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_empty_after_strip() {
        let result = RpmHandler::parse_path("just/a/dir/");
        assert!(result.is_err());
    }

    // ========================================================================
    // parse_repodata_operation tests (indirectly via parse_path)
    // ========================================================================

    #[test]
    fn test_parse_repodata_operation_primary_with_hash() {
        let info = RpmHandler::parse_path("repodata/a1b2c3d4e5f6-primary.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Primary));
    }

    #[test]
    fn test_parse_repodata_operation_filelists_sqlite() {
        let info = RpmHandler::parse_path("repodata/hash-filelists.sqlite.bz2").unwrap();
        assert!(matches!(info.operation, RpmOperation::Filelists));
    }

    // ========================================================================
    // parse_rpm_header tests
    // ========================================================================

    #[test]
    fn test_parse_rpm_header_too_small() {
        let result = RpmHandler::parse_rpm_header(&[0u8; 50]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("too small"));
    }

    #[test]
    fn test_parse_rpm_header_invalid_magic() {
        let mut data = vec![0u8; 200];
        // Wrong magic
        data[0] = 0x00;
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        let result = RpmHandler::parse_rpm_header(&data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid RPM magic"));
    }

    #[test]
    fn test_parse_rpm_header_valid_magic_fallback() {
        // Create a minimal RPM with valid magic but no header section after signature
        let mut data = vec![0u8; 200];
        // RPM magic
        data[0] = 0xed;
        data[1] = 0xab;
        data[2] = 0xee;
        data[3] = 0xdb;
        // Major/minor
        data[4] = 3;
        data[5] = 0;
        // Lead name at offset 10: "test-package"
        let name = b"test-package";
        data[10..10 + name.len()].copy_from_slice(name);
        // No valid signature header at offset 96 (leave as zeros)
        // No valid main header either, so it falls back to lead name
        let metadata = RpmHandler::parse_rpm_header(&data).unwrap();
        assert_eq!(metadata.name, "test-package");
        assert_eq!(metadata.version, "");
    }

    #[test]
    fn test_parse_rpm_header_with_signature_and_main_header() {
        // Build a synthetic RPM with magic, signature header, and main header
        let mut data = vec![0u8; 2048];

        // RPM magic
        data[0] = 0xed;
        data[1] = 0xab;
        data[2] = 0xee;
        data[3] = 0xdb;
        data[4] = 3; // major
        data[5] = 0; // minor

        // Lead name at offset 10
        let lead_name = b"pkg-from-lead";
        data[10..10 + lead_name.len()].copy_from_slice(lead_name);

        // Signature header at offset 96
        let sig_offset = 96;
        data[sig_offset] = 0x8e; // RPM_HEADER_MAGIC
        data[sig_offset + 1] = 0xad;
        data[sig_offset + 2] = 0xe8;
        data[sig_offset + 3] = 1; // version
                                  // nindex = 0 (no signature entries)
        data[sig_offset + 8] = 0;
        data[sig_offset + 9] = 0;
        data[sig_offset + 10] = 0;
        data[sig_offset + 11] = 0;
        // hsize = 0
        data[sig_offset + 12] = 0;
        data[sig_offset + 13] = 0;
        data[sig_offset + 14] = 0;
        data[sig_offset + 15] = 0;

        // After signature: offset = 96 + 16 + 0 + 0 = 112, aligned to 8 = 112
        let main_offset = 112;

        // Main header magic
        data[main_offset] = 0x8e;
        data[main_offset + 1] = 0xad;
        data[main_offset + 2] = 0xe8;
        data[main_offset + 3] = 1; // version

        // nindex = 2 (name and version tags)
        data[main_offset + 8] = 0;
        data[main_offset + 9] = 0;
        data[main_offset + 10] = 0;
        data[main_offset + 11] = 2;

        // Store: "mypackage\0" at offset 0, "2.0.1\0" at offset 10
        let store_data = b"mypackage\x002.0.1\x00";
        let hsize = store_data.len();
        data[main_offset + 12] = 0;
        data[main_offset + 13] = 0;
        data[main_offset + 14] = 0;
        data[main_offset + 15] = hsize as u8;

        let index_start = main_offset + 16;

        // Index entry 0: RPMTAG_NAME (1000), type=6 (STRING), offset=0, count=1
        let tag_name: u32 = 1000;
        data[index_start..index_start + 4].copy_from_slice(&tag_name.to_be_bytes());
        data[index_start + 4..index_start + 8].copy_from_slice(&6u32.to_be_bytes());
        data[index_start + 8..index_start + 12].copy_from_slice(&0u32.to_be_bytes());
        data[index_start + 12..index_start + 16].copy_from_slice(&1u32.to_be_bytes());

        // Index entry 1: RPMTAG_VERSION (1001), type=6, offset=10, count=1
        let idx1_start = index_start + 16;
        let tag_version: u32 = 1001;
        data[idx1_start..idx1_start + 4].copy_from_slice(&tag_version.to_be_bytes());
        data[idx1_start + 4..idx1_start + 8].copy_from_slice(&6u32.to_be_bytes());
        data[idx1_start + 8..idx1_start + 12].copy_from_slice(&10u32.to_be_bytes());
        data[idx1_start + 12..idx1_start + 16].copy_from_slice(&1u32.to_be_bytes());

        // Store starts after index entries
        let store_start = index_start + 2 * 16;
        data[store_start..store_start + store_data.len()].copy_from_slice(store_data);

        let metadata = RpmHandler::parse_rpm_header(&data).unwrap();
        assert_eq!(metadata.name, "mypackage");
        assert_eq!(metadata.version, "2.0.1");
    }

    // ========================================================================
    // parse_header_section tests
    // ========================================================================

    #[test]
    fn test_parse_header_section_too_short() {
        let result = RpmHandler::parse_header_section(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_header_section_invalid_magic() {
        let mut data = vec![0u8; 100];
        data[0] = 0x00;
        let result = RpmHandler::parse_header_section(&data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid RPM header"));
    }

    #[test]
    fn test_parse_header_section_truncated() {
        let mut data = vec![0u8; 20];
        // Valid magic
        data[0] = 0x8e;
        data[1] = 0xad;
        data[2] = 0xe8;
        data[3] = 1;
        // nindex = 1
        data[11] = 1;
        // hsize = 255 (bigger than available data)
        data[15] = 255;
        let result = RpmHandler::parse_header_section(&data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("truncated"));
    }

    #[test]
    fn test_parse_header_section_no_entries() {
        let mut data = vec![0u8; 20];
        data[0] = 0x8e;
        data[1] = 0xad;
        data[2] = 0xe8;
        data[3] = 1;
        // nindex = 0, hsize = 0
        let metadata = RpmHandler::parse_header_section(&data).unwrap();
        assert_eq!(metadata.name, "");
        assert_eq!(metadata.version, "");
    }

    #[test]
    fn test_parse_header_section_with_summary_and_license() {
        // Build a header section with multiple tags
        let store_data = b"pkg\x001.0\x00rel1\x00x86_64\x00A summary\x00MIT\x00";
        let nindex: u32 = 6;
        let hsize = store_data.len() as u32;
        let header_size = 16 + (nindex as usize * 16) + store_data.len();
        let mut data = vec![0u8; header_size];

        // Magic + version
        data[0] = 0x8e;
        data[1] = 0xad;
        data[2] = 0xe8;
        data[3] = 1;
        data[8..12].copy_from_slice(&nindex.to_be_bytes());
        data[12..16].copy_from_slice(&hsize.to_be_bytes());

        // Offsets: "pkg\0" = 0, "1.0\0" = 4, "rel1\0" = 8, "x86_64\0" = 13, "A summary\0" = 20, "MIT\0" = 30
        let offsets = [0u32, 4, 8, 13, 20, 30];
        let tags = [
            RPMTAG_NAME,
            RPMTAG_VERSION,
            RPMTAG_RELEASE,
            RPMTAG_ARCH,
            RPMTAG_SUMMARY,
            RPMTAG_LICENSE,
        ];

        for i in 0..nindex as usize {
            let idx_off = 16 + i * 16;
            data[idx_off..idx_off + 4].copy_from_slice(&tags[i].to_be_bytes());
            data[idx_off + 4..idx_off + 8].copy_from_slice(&6u32.to_be_bytes());
            data[idx_off + 8..idx_off + 12].copy_from_slice(&offsets[i].to_be_bytes());
            data[idx_off + 12..idx_off + 16].copy_from_slice(&1u32.to_be_bytes());
        }

        let store_start = 16 + nindex as usize * 16;
        data[store_start..store_start + store_data.len()].copy_from_slice(store_data);

        let metadata = RpmHandler::parse_header_section(&data).unwrap();
        assert_eq!(metadata.name, "pkg");
        assert_eq!(metadata.version, "1.0");
        assert_eq!(metadata.release, "rel1");
        assert_eq!(metadata.arch, "x86_64");
        assert_eq!(metadata.summary, Some("A summary".to_string()));
        assert_eq!(metadata.license, Some("MIT".to_string()));
    }

    #[test]
    fn test_parse_header_section_empty_optional_fields_become_none() {
        // Only name tag, all others missing -> optional fields should be None
        let store_data = b"mypkg\x00";
        let nindex: u32 = 1;
        let hsize = store_data.len() as u32;
        let header_size = 16 + 16 + store_data.len();
        let mut data = vec![0u8; header_size];

        data[0] = 0x8e;
        data[1] = 0xad;
        data[2] = 0xe8;
        data[3] = 1;
        data[8..12].copy_from_slice(&nindex.to_be_bytes());
        data[12..16].copy_from_slice(&hsize.to_be_bytes());

        let idx_off = 16;
        data[idx_off..idx_off + 4].copy_from_slice(&RPMTAG_NAME.to_be_bytes());
        data[idx_off + 4..idx_off + 8].copy_from_slice(&6u32.to_be_bytes());
        data[idx_off + 8..idx_off + 12].copy_from_slice(&0u32.to_be_bytes());
        data[idx_off + 12..idx_off + 16].copy_from_slice(&1u32.to_be_bytes());

        let store_start = 16 + 16;
        data[store_start..store_start + store_data.len()].copy_from_slice(store_data);

        let metadata = RpmHandler::parse_header_section(&data).unwrap();
        assert_eq!(metadata.name, "mypkg");
        assert!(metadata.summary.is_none());
        assert!(metadata.description.is_none());
        assert!(metadata.license.is_none());
        assert!(metadata.group.is_none());
        assert!(metadata.url.is_none());
        assert!(metadata.size.is_none());
        assert!(metadata.source_rpm.is_none());
        assert!(metadata.provides.is_empty());
        assert!(metadata.requires.is_empty());
    }

    // ========================================================================
    // RpmHandler::new / Default tests
    // ========================================================================

    #[test]
    fn test_rpm_handler_new() {
        let _handler = RpmHandler::new();
    }

    #[test]
    fn test_rpm_handler_default() {
        let _handler = RpmHandler;
    }

    // ========================================================================
    // generate_repomd tests
    // ========================================================================

    #[test]
    fn test_generate_repomd_empty_data() {
        let result = generate_repomd(vec![]);
        assert!(result.is_ok());
        let xml = result.unwrap();
        assert!(xml.contains("repomd"));
    }

    #[test]
    fn test_generate_repomd_with_data() {
        let data = vec![RepoMdData {
            data_type: "primary".to_string(),
            checksum: RepoMdChecksum {
                checksum_type: "sha256".to_string(),
                value: "abc123".to_string(),
            },
            open_checksum: None,
            location: RepoMdLocation {
                href: "repodata/primary.xml.gz".to_string(),
            },
            timestamp: 1700000000,
            size: 1024,
            open_size: Some(4096),
        }];
        let result = generate_repomd(data);
        assert!(result.is_ok());
        let xml = result.unwrap();
        assert!(xml.contains("primary"));
        assert!(xml.contains("abc123"));
    }
}
