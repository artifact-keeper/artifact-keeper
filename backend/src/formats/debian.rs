//! Debian/APT format handler.
//!
//! Implements APT repository for Debian/Ubuntu packages.
//! Supports parsing .deb files and generating Packages/Release files.

use async_trait::async_trait;
use bytes::Bytes;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::Read;
use tar::Archive;
use utoipa::ToSchema;
use xz2::read::XzDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Debian format handler
pub struct DebianHandler;

// ar archive magic
const AR_MAGIC: &[u8] = b"!<arch>\n";

impl DebianHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Debian repository path
    /// Formats:
    ///   dists/<dist>/Release              - Release file
    ///   dists/<dist>/Release.gpg          - GPG signature
    ///   dists/<dist>/InRelease            - Signed release
    ///   dists/<dist>/<comp>/binary-<arch>/Packages(.gz|.xz)
    ///   pool/<comp>/<prefix>/<source>/<package>_<version>_<arch>.deb
    pub fn parse_path(path: &str) -> Result<DebianPathInfo> {
        let path = path.trim_start_matches('/');

        // Release files
        if path.contains("/Release") || path.contains("/InRelease") {
            let parts: Vec<&str> = path.split('/').collect();
            let dist = if parts.len() >= 2 && parts[0] == "dists" {
                Some(parts[1].to_string())
            } else {
                None
            };

            return Ok(DebianPathInfo {
                package: None,
                version: None,
                arch: None,
                component: None,
                distribution: dist,
                operation: DebianOperation::Release,
            });
        }

        // Packages file
        if path.contains("/Packages") {
            let parts: Vec<&str> = path.split('/').collect();
            let mut dist = None;
            let mut comp = None;
            let mut arch = None;

            if parts.len() >= 5 && parts[0] == "dists" {
                dist = Some(parts[1].to_string());
                comp = Some(parts[2].to_string());
                // binary-<arch>/Packages
                if parts[3].starts_with("binary-") {
                    arch = Some(parts[3].trim_start_matches("binary-").to_string());
                }
            }

            return Ok(DebianPathInfo {
                package: None,
                version: None,
                arch,
                component: comp,
                distribution: dist,
                operation: DebianOperation::Packages,
            });
        }

        // Pool package
        if path.starts_with("pool/") || path.ends_with(".deb") || path.ends_with(".udeb") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            let info = Self::parse_deb_filename(filename)?;

            // Extract component from pool path
            let parts: Vec<&str> = path.split('/').collect();
            let component = if parts.len() >= 2 && parts[0] == "pool" {
                Some(parts[1].to_string())
            } else {
                None
            };

            return Ok(DebianPathInfo {
                package: Some(info.0),
                version: Some(info.1),
                arch: Some(info.2),
                component,
                distribution: None,
                operation: DebianOperation::Package,
            });
        }

        Err(AppError::Validation(format!(
            "Invalid Debian repository path: {}",
            path
        )))
    }

    /// Parse .deb filename
    /// Format: <name>_<version>_<arch>.deb
    pub fn parse_deb_filename(filename: &str) -> Result<(String, String, String)> {
        let name = filename
            .strip_suffix(".deb")
            .or_else(|| filename.strip_suffix(".udeb"))
            .ok_or_else(|| {
                AppError::Validation(format!("Invalid Debian package filename: {}", filename))
            })?;

        let parts: Vec<&str> = name.splitn(3, '_').collect();
        if parts.len() != 3 {
            return Err(AppError::Validation(format!(
                "Invalid Debian package filename: {}",
                filename
            )));
        }

        Ok((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ))
    }

    /// Get pool path for a package
    pub fn get_pool_path(component: &str, package: &str, filename: &str) -> String {
        let prefix = Self::get_pool_prefix(package);
        format!("pool/{}/{}/{}/{}", component, prefix, package, filename)
    }

    /// Get pool prefix for a package name
    fn get_pool_prefix(package: &str) -> String {
        if package.starts_with("lib") && package.len() > 4 {
            package[..4].to_string()
        } else {
            package.chars().next().unwrap_or('_').to_string()
        }
    }

    /// Parse control file from .deb package
    pub fn extract_control(content: &[u8]) -> Result<DebControl> {
        // .deb files are ar archives containing:
        // - debian-binary (version)
        // - control.tar.gz or control.tar.xz
        // - data.tar.gz or data.tar.xz

        if content.len() < 8 || &content[..8] != AR_MAGIC {
            return Err(AppError::Validation(
                "Invalid .deb file: not an ar archive".to_string(),
            ));
        }

        let mut offset = 8;

        while offset < content.len() {
            // ar header: 60 bytes
            if offset + 60 > content.len() {
                break;
            }

            let header = &content[offset..offset + 60];
            let name = std::str::from_utf8(&header[..16])
                .unwrap_or("")
                .trim()
                .trim_end_matches('/');
            let size_str = std::str::from_utf8(&header[48..58]).unwrap_or("0").trim();
            let size: usize = size_str.parse().unwrap_or(0);

            offset += 60;

            // Check if this is the control archive
            if name.starts_with("control.tar") {
                if offset + size > content.len() {
                    return Err(AppError::Validation(
                        "Invalid .deb file: truncated ar member".to_string(),
                    ));
                }
                let data = &content[offset..offset + size];
                return Self::parse_control_tar(data, name);
            }

            // Move to next file (aligned to 2 bytes)
            offset += size;
            if offset % 2 == 1 {
                offset += 1;
            }
        }

        Err(AppError::Validation(
            "control.tar not found in .deb file".to_string(),
        ))
    }

    /// Parse control.tar(.gz) to extract control file
    fn parse_control_tar(data: &[u8], member_name: &str) -> Result<DebControl> {
        let reader: Box<dyn Read + '_> = if member_name.ends_with(".gz") {
            Box::new(GzDecoder::new(data))
        } else if member_name.ends_with(".xz") {
            Box::new(XzDecoder::new(data))
        } else if member_name.ends_with(".bz2") {
            Box::new(BzDecoder::new(data))
        } else if member_name.ends_with(".zst") || member_name.ends_with(".zstd") {
            Box::new(ZstdDecoder::new(data).map_err(|e| {
                AppError::Validation(format!("Invalid control.tar zstd stream: {}", e))
            })?)
        } else {
            Box::new(data)
        };

        let mut archive = Archive::new(reader);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid control.tar: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid tar entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path: {}", e)))?;

            if path.ends_with("control") {
                let mut content = String::new();
                entry.read_to_string(&mut content).map_err(|e| {
                    AppError::Validation(format!("Failed to read control file: {}", e))
                })?;

                return Self::parse_control(&content);
            }
        }

        Err(AppError::Validation(
            "control file not found in control.tar".to_string(),
        ))
    }

    /// Parse Debian control file format
    pub fn parse_control(content: &str) -> Result<DebControl> {
        let mut control = DebControl::default();
        let mut current_key: Option<String> = None;
        let mut current_value = String::new();

        for line in content.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation line
                if current_key.is_some() {
                    current_value.push('\n');
                    current_value.push_str(line.trim_start());
                }
            } else if let Some(colon_pos) = line.find(':') {
                // Save previous field
                if let Some(key) = current_key.take() {
                    Self::set_control_field(&mut control, &key, &current_value);
                }

                let key = line[..colon_pos].to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                current_key = Some(key);
                current_value = value;
            }
        }

        // Save last field
        if let Some(key) = current_key {
            Self::set_control_field(&mut control, &key, &current_value);
        }

        if control.package.is_empty() {
            return Err(AppError::Validation(
                "Control file missing Package field".to_string(),
            ));
        }
        if control.version.is_empty() {
            return Err(AppError::Validation(
                "Control file missing Version field".to_string(),
            ));
        }
        if control.architecture.is_empty() {
            return Err(AppError::Validation(
                "Control file missing Architecture field".to_string(),
            ));
        }

        Ok(control)
    }

    fn set_control_field(control: &mut DebControl, key: &str, value: &str) {
        match key.to_lowercase().as_str() {
            "package" => control.package = value.to_string(),
            "version" => control.version = value.to_string(),
            "architecture" => control.architecture = value.to_string(),
            "maintainer" => control.maintainer = Some(value.to_string()),
            "installed-size" => control.installed_size = value.parse().ok(),
            "depends" => control.depends = Some(Self::parse_dependency_list(value)),
            "pre-depends" => control.pre_depends = Some(Self::parse_dependency_list(value)),
            "recommends" => control.recommends = Some(Self::parse_dependency_list(value)),
            "suggests" => control.suggests = Some(Self::parse_dependency_list(value)),
            "conflicts" => control.conflicts = Some(Self::parse_dependency_list(value)),
            "provides" => control.provides = Some(Self::parse_dependency_list(value)),
            "replaces" => control.replaces = Some(Self::parse_dependency_list(value)),
            "section" => control.section = Some(value.to_string()),
            "priority" => control.priority = Some(value.to_string()),
            "homepage" => control.homepage = Some(value.to_string()),
            "description" => control.description = Some(value.to_string()),
            "source" => control.source = Some(value.to_string()),
            _ => {
                control.extra.insert(key.to_string(), value.to_string());
            }
        }
    }

    /// Parse comma-separated dependency list
    fn parse_dependency_list(value: &str) -> Vec<String> {
        value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

impl Default for DebianHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for DebianHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Debian
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "operation": format!("{:?}", info.operation),
        });

        if let Some(package) = &info.package {
            metadata["package"] = serde_json::Value::String(package.clone());
        }

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        if let Some(arch) = &info.arch {
            metadata["architecture"] = serde_json::Value::String(arch.clone());
        }

        if let Some(comp) = &info.component {
            metadata["component"] = serde_json::Value::String(comp.clone());
        }

        if let Some(dist) = &info.distribution {
            metadata["distribution"] = serde_json::Value::String(dist.clone());
        }

        // Extract control if this is a package
        if !content.is_empty() && matches!(info.operation, DebianOperation::Package) {
            if let Ok(control) = Self::extract_control(content) {
                metadata["control"] = serde_json::to_value(&control)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate .deb packages
        if !content.is_empty() && matches!(info.operation, DebianOperation::Package) {
            let control = Self::extract_control(content)?;

            // Verify package name matches
            if let Some(path_package) = &info.package {
                if &control.package != path_package {
                    return Err(AppError::Validation(format!(
                        "Package name mismatch: path says '{}' but control says '{}'",
                        path_package, control.package
                    )));
                }
            }

            // Verify version matches
            if let Some(path_version) = &info.version {
                if &control.version != path_version {
                    return Err(AppError::Validation(format!(
                        "Version mismatch: path says '{}' but control says '{}'",
                        path_version, control.version
                    )));
                }
            }

            // Verify architecture matches.
            if let Some(path_arch) = &info.arch {
                if &control.architecture != path_arch {
                    return Err(AppError::Validation(format!(
                        "Architecture mismatch: path says '{}' but control says '{}'",
                        path_arch, control.architecture
                    )));
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Packages/Release files are generated on demand
        Ok(None)
    }
}

/// Debian path info
#[derive(Debug)]
pub struct DebianPathInfo {
    pub package: Option<String>,
    pub version: Option<String>,
    pub arch: Option<String>,
    pub component: Option<String>,
    pub distribution: Option<String>,
    pub operation: DebianOperation,
}

/// Debian operation type
#[derive(Debug)]
pub enum DebianOperation {
    Release,
    Packages,
    Package,
}

/// Debian control file structure
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DebControl {
    pub package: String,
    pub version: String,
    pub architecture: String,
    #[serde(default)]
    pub maintainer: Option<String>,
    #[serde(default)]
    pub installed_size: Option<u64>,
    #[serde(default)]
    pub depends: Option<Vec<String>>,
    #[serde(default)]
    pub pre_depends: Option<Vec<String>>,
    #[serde(default)]
    pub recommends: Option<Vec<String>>,
    #[serde(default)]
    pub suggests: Option<Vec<String>>,
    #[serde(default)]
    pub conflicts: Option<Vec<String>>,
    #[serde(default)]
    pub provides: Option<Vec<String>>,
    #[serde(default)]
    pub replaces: Option<Vec<String>>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default, flatten)]
    pub extra: HashMap<String, String>,
}

/// Release file structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Release {
    pub origin: Option<String>,
    pub label: Option<String>,
    pub suite: String,
    pub codename: Option<String>,
    pub version: Option<String>,
    pub date: String,
    /// Optional expiry date from the `Valid-Until` field in RFC 2822 / RFC 5322 format.
    pub valid_until: Option<String>,
    pub architectures: Vec<String>,
    pub components: Vec<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub md5sum: Vec<ReleaseHash>,
    #[serde(default)]
    pub sha1: Vec<ReleaseHash>,
    #[serde(default)]
    pub sha256: Vec<ReleaseHash>,
    #[serde(default)]
    pub sha512: Vec<ReleaseHash>,
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}

/// Release file hash entry
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReleaseHash {
    pub hash: String,
    pub size: u64,
    pub path: String,
}

/// Parsed Debian Packages index entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackagesEntry {
    pub control: DebControl,
    pub filename: Option<String>,
    pub size: Option<u64>,
    pub md5sum: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}
/// Source file listed by a Debian Sources index.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceFileEntry {
    pub filename: String,
    pub size: u64,
    pub md5sum: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
}

/// Parsed Debian Sources index entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourcesEntry {
    pub package: String,
    pub version: String,
    pub directory: String,
    pub files: Vec<SourceFileEntry>,
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}

/// Detached Release.gpg metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSignature {
    pub is_armored: bool,
    pub size: usize,
}

/// Minimal abstraction for Release metadata signing.
pub trait DebianReleaseSigner {
    fn sign_in_release(&self, release: &str) -> Result<String>;
    fn sign_release_gpg(&self, release: &[u8]) -> Result<Vec<u8>>;
}

/// Generate clear-signed InRelease metadata through an injected signer.
pub fn generate_in_release(
    signer: &(impl DebianReleaseSigner + ?Sized),
    release: &str,
) -> Result<String> {
    if release.trim().is_empty() {
        return Err(AppError::Validation(
            "Release content must not be empty when signing InRelease".to_string(),
        ));
    }
    signer.sign_in_release(release)
}

/// Generate detached Release.gpg metadata through an injected signer.
pub fn generate_release_gpg(
    signer: &(impl DebianReleaseSigner + ?Sized),
    release: &str,
) -> Result<Vec<u8>> {
    if release.trim().is_empty() {
        return Err(AppError::Validation(
            "Release content must not be empty when signing Release.gpg".to_string(),
        ));
    }
    signer.sign_release_gpg(release.as_bytes())
}

/// Debian package index selected for filtered sync.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct DebianIndexPath {
    pub component: String,
    pub architecture: String,
    pub path: String,
}

/// Soft cap on decompressed Packages/Sources index text (gzip/xz/bz2/zstd/plain).
pub const MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

/// Hard limit on the number of package + source files in a single sync plan.
/// Prevents a misconfigured full-mirror sync from triggering unbounded storage writes.
pub const MAX_DEBIAN_SYNC_SELECTED_FILES: usize = 50_000;

/// Distribution/component/architecture filters for Debian remote sync.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DebianSyncFilter {
    pub distributions: Vec<String>,
    pub components: Vec<String>,
    pub architectures: Vec<String>,
    pub include_source_packages: bool,
    /// Optional package name queries (exact or trailing `*` glob). Empty = all packages.
    pub package_queries: Vec<String>,
    /// When package_queries is non-empty, also include Depends/Pre-Depends closure.
    pub resolve_dependencies: bool,
}

/// Debian sync package download behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebianSyncDownloadPolicy {
    /// Cache package files only when clients request them.
    OnDemand,
    /// Fetch selected package files during sync.
    Immediate,
}

impl DebianSyncDownloadPolicy {
    pub fn from_label(label: Option<&str>) -> Self {
        let label = label.unwrap_or_default().trim().to_ascii_lowercase();
        match label.as_str() {
            "immediate" | "eager" | "full" | "full_mirror" | "full-mirror" => Self::Immediate,
            _ => Self::OnDemand,
        }
    }

    fn downloads_packages(self) -> bool {
        matches!(self, Self::Immediate)
    }
}

/// Package file selected by a filtered Debian mirror sync plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct DebianSyncPackageFile {
    pub index_path: String,
    pub filename: String,
    pub package: String,
    pub version: String,
    pub architecture: String,
    pub download: bool,
}
/// Debian source index selected for filtered sync.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct DebianSourceIndexPath {
    pub component: String,
    pub path: String,
}

/// Source file selected by a filtered Debian mirror sync plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct DebianSyncSourceFile {
    pub index_path: String,
    pub filename: String,
    pub package: String,
    pub version: String,
    pub size: u64,
    pub download: bool,
}

/// Pure filtered-sync plan produced after Release and Packages metadata are parsed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct DebianSyncPlan {
    pub distribution: String,
    pub release_paths: Vec<String>,
    pub package_indexes: Vec<DebianIndexPath>,
    pub source_indexes: Vec<DebianSourceIndexPath>,
    pub package_files: Vec<DebianSyncPackageFile>,
    pub source_files: Vec<DebianSyncSourceFile>,
    pub missing_package_indexes: Vec<String>,
    pub missing_source_indexes: Vec<String>,
}

/// Input used to decide how a Debian remote proxy cache entry should behave.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebianCacheDecisionInput<'a> {
    pub path: &'a str,
    pub upstream_success: bool,
    pub cached_locally: bool,
    pub cache_stale: bool,
    pub checksum_matches: bool,
}

/// Cache behavior for a Debian remote proxy request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DebianCacheAction {
    ServeCached,
    Revalidate,
    FetchAndCache,
    DoNotCache,
}

/// Parse a Debian Release file.
pub fn parse_release(content: &str) -> Result<Release> {
    parse_release_from_payload(content)
}

/// Parse a clear-signed InRelease file.
pub fn parse_in_release(content: &str) -> Result<Release> {
    let payload = clear_signed_payload(content)?;
    parse_release_from_payload(&payload)
}

/// Parse a Debian Release date string (RFC 2822 / `date -R` format).
/// Returns `None` when the string cannot be parsed.
///
/// Tries the most common formats Debian upstreams use:
/// - `Thu, 01 Jan 2026 00:00:00 UTC`
/// - `Thu, 01 Jan 2026 00:00:00 +0000`
pub fn parse_release_date(date: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let date = date.trim();
    // Try RFC 2822 with numeric offset first, then replace UTC/GMT suffix.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(date) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    // Replace textual timezone abbreviations that `parse_from_rfc2822` rejects.
    let normalized = date
        .trim_end_matches("UTC")
        .trim_end_matches("GMT")
        .trim_end()
        .to_string()
        + " +0000";
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(&normalized) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    None
}

/// Return `true` when the release's `Valid-Until` field is present and its parsed date
/// is in the past relative to `now`.
pub fn release_is_expired(release: &Release, now: chrono::DateTime<chrono::Utc>) -> bool {
    let Some(valid_until) = release.valid_until.as_deref() else {
        return false;
    };
    match parse_release_date(valid_until) {
        Some(expiry) => now >= expiry,
        // If we can't parse it, fail-safe: treat as not-expired.
        None => false,
    }
}

/// Validate detached Release.gpg bytes and identify armored signatures.
pub fn parse_release_gpg(content: &[u8]) -> Result<ReleaseSignature> {
    if content.is_empty() {
        return Err(AppError::Validation("Release.gpg is empty".to_string()));
    }

    let is_armored = std::str::from_utf8(content)
        .map(|text| text.contains("-----BEGIN PGP SIGNATURE-----"))
        .unwrap_or(false);

    Ok(ReleaseSignature {
        is_armored,
        size: content.len(),
    })
}

/// Parse an uncompressed Debian Packages file.
pub fn parse_packages(content: &str) -> Result<Vec<PackagesEntry>> {
    split_debian_stanzas(content)
        .into_iter()
        .map(parse_packages_entry)
        .collect()
}

fn decode_debian_index_text(path: &str, content: &[u8], label: &str) -> Result<String> {
    let reject_oversized = |len: usize| -> Result<()> {
        if len as u64 > MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES {
            return Err(AppError::Validation(format!(
                "Decompressed {label} index exceeds maximum allowed size of {MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES} bytes"
            )));
        }
        Ok(())
    };

    if path.ends_with(".gz") {
        let mut decoder = GzDecoder::new(content).take(MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES + 1);
        let mut text = String::new();
        decoder
            .read_to_string(&mut text)
            .map_err(|e| AppError::Validation(format!("Failed to decompress {label}.gz: {e}")))?;
        reject_oversized(text.len())?;
        Ok(text)
    } else if path.ends_with(".xz") {
        let mut decoder = XzDecoder::new(content).take(MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES + 1);
        let mut text = String::new();
        decoder
            .read_to_string(&mut text)
            .map_err(|e| AppError::Validation(format!("Failed to decompress {label}.xz: {e}")))?;
        reject_oversized(text.len())?;
        Ok(text)
    } else if path.ends_with(".bz2") {
        let mut decoder = BzDecoder::new(content).take(MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES + 1);
        let mut text = String::new();
        decoder
            .read_to_string(&mut text)
            .map_err(|e| AppError::Validation(format!("Failed to decompress {label}.bz2: {e}")))?;
        reject_oversized(text.len())?;
        Ok(text)
    } else if path.ends_with(".zst") || path.ends_with(".zstd") {
        let decoder = ZstdDecoder::new(content)
            .map_err(|e| AppError::Validation(format!("Failed to decompress {label}.zst: {e}")))?;
        let mut decoder = decoder.take(MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES + 1);
        let mut text = String::new();
        decoder
            .read_to_string(&mut text)
            .map_err(|e| AppError::Validation(format!("Failed to decompress {label}.zst: {e}")))?;
        reject_oversized(text.len())?;
        Ok(text)
    } else {
        reject_oversized(content.len())?;
        String::from_utf8(content.to_vec())
            .map_err(|e| AppError::Validation(format!("{label} index is not UTF-8: {e}")))
    }
}

/// Parse a Packages index, decompressing `.gz` and `.xz` paths when needed.
pub fn parse_packages_index(path: &str, content: &[u8]) -> Result<Vec<PackagesEntry>> {
    let text = decode_debian_index_text(path, content, "Packages")?;
    parse_packages(&text)
}

/// Parse an uncompressed Debian Sources file.
pub fn parse_sources(content: &str) -> Result<Vec<SourcesEntry>> {
    split_debian_stanzas(content)
        .into_iter()
        .map(parse_sources_entry)
        .collect()
}

/// Parse a Sources index, decompressing `.gz` and `.xz` paths when needed.
pub fn parse_sources_index(path: &str, content: &[u8]) -> Result<Vec<SourcesEntry>> {
    let text = decode_debian_index_text(path, content, "Sources")?;
    parse_sources(&text)
}
/// Return matching binary package index paths from Release metadata.
pub fn filter_release_package_indexes(
    release: &Release,
    filter: &DebianSyncFilter,
) -> Vec<DebianIndexPath> {
    if !filter.distributions.is_empty()
        && !filter.distributions.iter().any(|distribution| {
            distribution == &release.suite
                || release
                    .codename
                    .as_deref()
                    .map(|codename| codename == distribution)
                    .unwrap_or(false)
        })
    {
        return Vec::new();
    }

    let component_filter: BTreeSet<&str> = filter.components.iter().map(String::as_str).collect();
    let arch_filter: BTreeSet<&str> = filter.architectures.iter().map(String::as_str).collect();
    let allowed_component = |component: &str| {
        component_filter.is_empty()
            || component_filter
                .iter()
                .any(|selected| debian_components_equivalent(selected, component))
    };
    let allowed_arch = |arch: &str| arch_filter.is_empty() || arch_filter.contains(arch);

    let mut selected = BTreeMap::<(String, String), DebianIndexPath>::new();
    for hash in release
        .sha256
        .iter()
        .chain(release.sha512.iter())
        .chain(release.sha1.iter())
        .chain(release.md5sum.iter())
    {
        if let Some(index) = parse_release_package_index_path(&hash.path) {
            if allowed_component(&index.component)
                && (index.architecture.is_empty() || allowed_arch(&index.architecture))
            {
                let key = (index.component.clone(), index.architecture.clone());
                match selected.get(&key) {
                    Some(current)
                        if package_index_compression_rank(&current.path)
                            >= package_index_compression_rank(&index.path) => {}
                    _ => {
                        selected.insert(key, index);
                    }
                }
            }
        }
    }

    if selected.is_empty() {
        for component in &release.components {
            if !allowed_component(component) {
                continue;
            }
            for arch in &release.architectures {
                if allowed_arch(arch) {
                    // Prefer the leaf component name for on-disk paths when Release
                    // advertises a prefixed form (e.g. updates/main → main/...).
                    let path_component = component.rsplit('/').next().unwrap_or(component);
                    let path = format!("{path_component}/binary-{arch}/Packages.xz");
                    selected.insert(
                        (path_component.to_string(), arch.clone()),
                        DebianIndexPath {
                            component: path_component.to_string(),
                            architecture: arch.clone(),
                            path,
                        },
                    );
                }
            }
        }
    }

    selected.into_values().collect()
}

/// Return matching source package index paths from Release metadata.
pub fn filter_release_source_indexes(
    release: &Release,
    filter: &DebianSyncFilter,
) -> Vec<DebianSourceIndexPath> {
    if !filter.include_source_packages {
        return Vec::new();
    }
    let component_filter: BTreeSet<&str> = filter.components.iter().map(String::as_str).collect();
    let allowed_component = |component: &str| {
        component_filter.is_empty()
            || component_filter
                .iter()
                .any(|selected| debian_components_equivalent(selected, component))
    };

    let mut selected = BTreeMap::<String, DebianSourceIndexPath>::new();
    for hash in release
        .sha256
        .iter()
        .chain(release.sha512.iter())
        .chain(release.sha1.iter())
        .chain(release.md5sum.iter())
    {
        if let Some(index) = parse_release_source_index_path(&hash.path) {
            if allowed_component(&index.component) {
                match selected.get(&index.component) {
                    Some(current)
                        if package_index_compression_rank(&current.path)
                            >= package_index_compression_rank(&index.path) => {}
                    _ => {
                        selected.insert(index.component.clone(), index);
                    }
                }
            }
        }
    }

    if selected.is_empty() {
        for component in &release.components {
            if allowed_component(component) {
                // Prefer the leaf component name for on-disk paths when Release
                // advertises a prefixed form (e.g. updates/main → main/...).
                let path_component = component.rsplit('/').next().unwrap_or(component);
                selected.insert(
                    component.clone(),
                    DebianSourceIndexPath {
                        component: path_component.to_string(),
                        path: format!("{path_component}/source/Sources.xz"),
                    },
                );
            }
        }
    }

    selected.into_values().collect()
}
pub fn validate_release_filter_selection(
    release: &Release,
    filter: &DebianSyncFilter,
) -> Result<()> {
    let missing_components = missing_release_filter_values(&filter.components, &release.components);
    if !missing_components.is_empty() {
        return Err(AppError::Validation(format!(
            "Selected Debian component(s) not advertised by upstream Release metadata: {}",
            missing_components.join(", ")
        )));
    }

    let missing_architectures =
        missing_release_filter_values(&filter.architectures, &release.architectures);
    if !missing_architectures.is_empty() {
        return Err(AppError::Validation(format!(
            "Selected Debian architecture(s) not advertised by upstream Release metadata: {}",
            missing_architectures.join(", ")
        )));
    }

    Ok(())
}

/// Whether a configured component filter matches an advertised/on-disk component.
///
/// Debian-Security Release files advertise `updates/main` while apt sources and
/// index paths use `main`. Treat the leaf segment as equivalent so configuring
/// `main` (the apt sources.list component) works against those suites.
pub fn debian_components_equivalent(selected: &str, advertised: &str) -> bool {
    if selected == advertised {
        return true;
    }
    let selected_leaf = selected.rsplit('/').next().unwrap_or(selected);
    let advertised_leaf = advertised.rsplit('/').next().unwrap_or(advertised);
    selected_leaf == advertised || selected == advertised_leaf || selected_leaf == advertised_leaf
}

fn missing_release_filter_values(selected: &[String], advertised: &[String]) -> Vec<String> {
    let selected: BTreeSet<String> = selected
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && *value != "*")
        .map(str::to_string)
        .collect();
    if selected.is_empty() {
        return Vec::new();
    }

    selected
        .into_iter()
        .filter(|value| {
            !advertised
                .iter()
                .any(|adv| debian_components_equivalent(value, adv))
        })
        .collect()
}
fn package_index_compression_rank(path: &str) -> u8 {
    if path.ends_with(".xz") {
        4
    } else if path.ends_with(".zst") || path.ends_with(".zstd") {
        3
    } else if path.ends_with(".gz") || path.ends_with(".bz2") {
        2
    } else {
        1
    }
}

/// Return true when `name` matches any package query (exact or trailing `*` prefix glob).
/// Empty `queries` matches all names. Version constraints on `name` are stripped first.
pub fn package_name_matches_queries(name: &str, queries: &[String]) -> bool {
    if queries.is_empty() {
        return true;
    }
    let name = parse_debian_dependency_package_name(name);
    queries.iter().any(|query| {
        let query = query.trim();
        if query.is_empty() {
            return false;
        }
        if let Some(prefix) = query.strip_suffix('*') {
            name.starts_with(prefix)
        } else {
            name == query
        }
    })
}

/// Extract the package name from a Debian dependency expression.
/// Takes the first alternative before `|`, strips a parenthesized version constraint, and trims.
pub fn parse_debian_dependency_package_name(dep: &str) -> &str {
    let dep = dep.split('|').next().unwrap_or(dep).trim();
    match dep.find('(') {
        Some(idx) => dep[..idx].trim(),
        None => dep,
    }
}

/// Filter package index entries by name queries, optionally expanding Depends/Pre-Depends.
pub fn filter_packages_by_query_with_dependencies(
    entries: &[PackagesEntry],
    queries: &[String],
    resolve_deps: bool,
) -> Vec<PackagesEntry> {
    if queries.is_empty() {
        return entries.to_vec();
    }

    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut by_provide: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        by_name
            .entry(entry.control.package.as_str())
            .or_default()
            .push(idx);
        if let Some(provides) = entry.control.provides.as_ref() {
            for provide in provides {
                let provide_name = parse_debian_dependency_package_name(provide);
                if !provide_name.is_empty() {
                    by_provide.entry(provide_name).or_default().push(idx);
                }
            }
        }
    }

    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<usize> = VecDeque::new();
    for (idx, entry) in entries.iter().enumerate() {
        if package_name_matches_queries(&entry.control.package, queries) && selected.insert(idx) {
            queue.push_back(idx);
        }
    }

    if resolve_deps {
        while let Some(idx) = queue.pop_front() {
            let entry = &entries[idx];
            for dep_list in [
                entry.control.depends.as_ref(),
                entry.control.pre_depends.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                for dep in dep_list {
                    let dep_name = parse_debian_dependency_package_name(dep);
                    if dep_name.is_empty() {
                        continue;
                    }
                    for &dep_idx in by_name
                        .get(dep_name)
                        .into_iter()
                        .chain(by_provide.get(dep_name))
                        .flatten()
                    {
                        if selected.insert(dep_idx) {
                            queue.push_back(dep_idx);
                        }
                    }
                }
            }
        }
    }

    entries
        .iter()
        .enumerate()
        .filter(|(idx, _)| selected.contains(idx))
        .map(|(_, entry)| entry.clone())
        .collect()
}

/// Whether a Release-relative metadata path is allowed by component/arch/source filters.
pub fn release_path_allowed_by_filter(path: &str, filter: &DebianSyncFilter) -> bool {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return false;
    }

    let parts: Vec<&str> = path.split('/').collect();
    let component_allowed = |component: &str| {
        filter.components.is_empty()
            || filter
                .components
                .iter()
                .any(|c| debian_components_equivalent(c, component))
    };
    let arch_allowed = |arch: &str| {
        filter.architectures.is_empty() || filter.architectures.iter().any(|a| a == arch)
    };
    fn contents_arch(name: &str) -> Option<&str> {
        let rest = name.strip_prefix("Contents-")?;
        Some(rest.split('.').next().unwrap_or(rest))
    }

    if let Some(by_hash_idx) = parts.iter().position(|part| *part == "by-hash") {
        if by_hash_idx == 0 {
            return filter.components.is_empty();
        }
        return component_allowed(parts[0]);
    }

    if parts.len() >= 3 && parts[1].starts_with("binary-") && parts[2].starts_with("Packages") {
        let arch = parts[1].trim_start_matches("binary-");
        return component_allowed(parts[0]) && arch_allowed(arch);
    }

    if parts.len() >= 3 && parts[1] == "source" && parts[2].starts_with("Sources") {
        return filter.include_source_packages && component_allowed(parts[0]);
    }

    if parts.len() >= 2 {
        if let Some(arch) = contents_arch(parts[1]) {
            return component_allowed(parts[0]) && arch_allowed(arch);
        }
    }

    if parts.len() == 1 {
        if let Some(arch) = contents_arch(parts[0]) {
            return arch_allowed(arch);
        }
    }

    if parts.len() >= 3 && parts[1] == "i18n" && parts[2].starts_with("Translation-") {
        return component_allowed(parts[0]);
    }

    if parts.len() >= 3 && parts[1] == "dep11" {
        return component_allowed(parts[0]);
    }

    false
}

/// Whether a pool package is allowed by component/arch/package-query filters.
/// Whether `filename` looks like a Debian source artifact that is not a binary package.
///
/// Source artifacts have extensions like `.dsc`, `.debian.tar.*`, `.orig.tar.*`,
/// `.diff.gz`, or `.asc` adjacent to source packages. They are not parseable by
/// `parse_deb_filename` and must bypass binary-specific arch/query filters when
/// `include_source_packages` is enabled.
fn is_debian_source_artifact(filename: &str) -> bool {
    filename.ends_with(".dsc")
        || filename.ends_with(".diff.gz")
        || filename.contains(".orig.tar.")
        || filename.contains(".debian.tar.")
        || (filename.ends_with(".asc") && !filename.ends_with(".deb.asc"))
}

pub fn pool_path_allowed_by_filters(
    component: &str,
    filename: &str,
    filter: &DebianSyncFilter,
) -> bool {
    if !filter.components.is_empty()
        && !filter
            .components
            .iter()
            .any(|c| debian_components_equivalent(c, component))
    {
        return false;
    }

    // Source artifacts (.dsc, .orig.tar.*, .debian.tar.*, .diff.gz, .asc) bypass
    // binary-specific arch/query filters when source packages are enabled.
    if is_debian_source_artifact(filename) {
        return filter.include_source_packages;
    }

    let Ok((package, _version, architecture)) = DebianHandler::parse_deb_filename(filename) else {
        return false;
    };

    if architecture != "all"
        && !filter.architectures.is_empty()
        && !filter
            .architectures
            .iter()
            .any(|arch| arch == &architecture)
    {
        return false;
    }

    if !filter.package_queries.is_empty()
        && !package_name_matches_queries(&package, &filter.package_queries)
    {
        return false;
    }

    true
}

/// Reject absolute http(s) URLs and path traversal in index-provided filenames.
pub fn validate_debian_fetch_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(AppError::Validation(
            "Debian fetch path must not be empty".to_string(),
        ));
    }
    if path.starts_with("http://") || path.starts_with("https://") {
        return Err(AppError::Validation(format!(
            "Debian fetch path must be relative, not an absolute URL: {path}"
        )));
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err(AppError::Validation(format!(
            "Debian fetch path must not contain '..' segments: {path}"
        )));
    }
    Ok(())
}

/// True for `.deb`/`.udeb` paths that are not under `pool/` (flat repository layout).
pub fn is_flat_repository_package_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    (path.ends_with(".deb") || path.ends_with(".udeb")) && !path.starts_with("pool/")
}

/// Build a Debian Contents index (`path\\tpackage` lines, sorted).
pub fn build_contents_index(entries: &[(String, String)]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|(path, package)| format!("{path}\t{package}"))
        .collect();
    lines.sort();
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

/// Return a by-hash relative path: `by-hash/{algorithm}/{hash_hex}`.
pub fn by_hash_path(algorithm: &str, hash_hex: &str) -> String {
    format!("by-hash/{algorithm}/{hash_hex}")
}

/// Debian `Architecture: all` packages belong in every selected binary index.
pub fn package_matches_sync_architecture(
    package_arch: &str,
    selected_architectures: &[String],
) -> bool {
    package_arch == "all"
        || selected_architectures.is_empty()
        || selected_architectures
            .iter()
            .any(|arch| arch == package_arch)
}

/// Build the deterministic core of a filtered Debian mirror sync.
pub fn build_debian_sync_plan(
    distribution: &str,
    release: &Release,
    filter: &DebianSyncFilter,
    packages_by_index_path: &BTreeMap<String, Vec<PackagesEntry>>,
    sources_by_index_path: &BTreeMap<String, Vec<SourcesEntry>>,
    download_policy: DebianSyncDownloadPolicy,
) -> DebianSyncPlan {
    let package_indexes = filter_release_package_indexes(release, filter);
    let source_indexes = filter_release_source_indexes(release, filter);
    let mut package_files = Vec::new();
    let mut source_files = Vec::new();
    let mut missing_package_indexes = Vec::new();
    let mut missing_source_indexes = Vec::new();

    if !filter.package_queries.is_empty() && filter.resolve_dependencies {
        // Cross-index dependency closure: build a global package universe from all
        // available indexes, resolve deps across the full set, then emit only those
        // packages that appear in their respective index with the correct arch.
        //
        // This ensures a Depends on a package that lives in a different component or
        // arch index is still included in the sync plan, which per-index resolution
        // misses.
        let mut global_entries: Vec<(&str, &PackagesEntry)> = Vec::new();
        for index in &package_indexes {
            if let Some(entries) = packages_by_index_path.get(&index.path) {
                for entry in entries {
                    global_entries.push((index.path.as_str(), entry));
                }
            } else {
                missing_package_indexes.push(index.path.clone());
            }
        }

        // Build a flat view for dependency resolution (all entries across all indexes).
        let flat_entries: Vec<PackagesEntry> =
            global_entries.iter().map(|(_, e)| (*e).clone()).collect();
        let selected_entries = filter_packages_by_query_with_dependencies(
            &flat_entries,
            &filter.package_queries,
            true,
        );

        // Build a set of (package, version) tuples that were selected globally.
        let selected_set: HashSet<(&str, &str)> = selected_entries
            .iter()
            .map(|e| (e.control.package.as_str(), e.control.version.as_str()))
            .collect();

        // Emit package files per index, restricted to globally-selected packages.
        for index in &package_indexes {
            let Some(entries) = packages_by_index_path.get(&index.path) else {
                continue;
            };
            for entry in entries {
                if !selected_set.contains(&(
                    entry.control.package.as_str(),
                    entry.control.version.as_str(),
                )) {
                    continue;
                }
                if !package_matches_sync_index(
                    &entry.control.architecture,
                    &index.architecture,
                    &filter.architectures,
                ) {
                    continue;
                }
                let Some(filename) = entry
                    .filename
                    .as_deref()
                    .map(str::trim)
                    .filter(|filename| !filename.is_empty())
                else {
                    continue;
                };
                package_files.push(DebianSyncPackageFile {
                    index_path: index.path.clone(),
                    filename: filename.to_string(),
                    package: entry.control.package.clone(),
                    version: entry.control.version.clone(),
                    architecture: entry.control.architecture.clone(),
                    download: download_policy.downloads_packages(),
                });
            }
        }
    } else {
        for index in &package_indexes {
            let Some(entries) = packages_by_index_path.get(&index.path) else {
                missing_package_indexes.push(index.path.clone());
                continue;
            };

            let filtered_entries;
            let entries = if filter.package_queries.is_empty() {
                entries.as_slice()
            } else {
                filtered_entries = filter_packages_by_query_with_dependencies(
                    entries,
                    &filter.package_queries,
                    filter.resolve_dependencies,
                );
                filtered_entries.as_slice()
            };

            for entry in entries {
                if !package_matches_sync_index(
                    &entry.control.architecture,
                    &index.architecture,
                    &filter.architectures,
                ) {
                    continue;
                }
                let Some(filename) = entry
                    .filename
                    .as_deref()
                    .map(str::trim)
                    .filter(|filename| !filename.is_empty())
                else {
                    continue;
                };

                package_files.push(DebianSyncPackageFile {
                    index_path: index.path.clone(),
                    filename: filename.to_string(),
                    package: entry.control.package.clone(),
                    version: entry.control.version.clone(),
                    architecture: entry.control.architecture.clone(),
                    download: download_policy.downloads_packages(),
                });
            }
        }
    }

    for index in &source_indexes {
        let Some(entries) = sources_by_index_path.get(&index.path) else {
            missing_source_indexes.push(index.path.clone());
            continue;
        };

        for entry in entries {
            for file in &entry.files {
                source_files.push(DebianSyncSourceFile {
                    index_path: index.path.clone(),
                    filename: source_file_path(&entry.directory, &file.filename),
                    package: entry.package.clone(),
                    version: entry.version.clone(),
                    size: file.size,
                    download: download_policy.downloads_packages(),
                });
            }
        }
    }

    package_files.sort_by(|left, right| {
        left.index_path
            .cmp(&right.index_path)
            .then_with(|| left.filename.cmp(&right.filename))
            .then_with(|| left.package.cmp(&right.package))
    });
    source_files.sort_by(|left, right| {
        left.index_path
            .cmp(&right.index_path)
            .then_with(|| left.filename.cmp(&right.filename))
            .then_with(|| left.package.cmp(&right.package))
    });
    missing_package_indexes.sort();
    missing_source_indexes.sort();

    let release_prefix = if distribution.is_empty() {
        String::new()
    } else {
        format!("dists/{distribution}/")
    };

    DebianSyncPlan {
        distribution: distribution.to_string(),
        release_paths: vec![
            format!("{release_prefix}InRelease"),
            format!("{release_prefix}Release"),
            format!("{release_prefix}Release.gpg"),
        ],
        package_indexes,
        source_indexes,
        package_files,
        source_files,
        missing_package_indexes,
        missing_source_indexes,
    }
}

pub(crate) fn source_file_path(directory: &str, filename: &str) -> String {
    let directory = directory.trim().trim_matches('/');
    if directory.is_empty() || directory == "." {
        filename.trim_start_matches('/').to_string()
    } else {
        format!("{}/{}", directory, filename.trim_start_matches('/'))
    }
}
fn package_matches_sync_index(
    package_arch: &str,
    index_architecture: &str,
    selected_architectures: &[String],
) -> bool {
    if index_architecture.is_empty() {
        return package_matches_sync_architecture(package_arch, selected_architectures);
    }

    package_arch == "all"
        || (package_arch == index_architecture
            && package_matches_sync_architecture(package_arch, selected_architectures))
}

/// Decide cache behavior for Debian proxy paths without performing I/O.
pub fn decide_debian_cache_action(input: DebianCacheDecisionInput<'_>) -> DebianCacheAction {
    if !input.upstream_success {
        return DebianCacheAction::DoNotCache;
    }

    if input.cached_locally && is_debian_pool_artifact(input.path) && input.checksum_matches {
        return DebianCacheAction::ServeCached;
    }

    if input.cached_locally && is_debian_metadata_path(input.path) {
        return if input.cache_stale {
            DebianCacheAction::Revalidate
        } else {
            DebianCacheAction::ServeCached
        };
    }

    DebianCacheAction::FetchAndCache
}

fn parse_release_from_payload(content: &str) -> Result<Release> {
    let fields = parse_debian_stanza_fields(content)?;
    let suite = required_field(&fields, "Suite")?.to_string();
    let date = required_field(&fields, "Date")?.to_string();
    let architectures = split_words(fields.get("Architectures"));
    let components = split_words(fields.get("Components"));

    if architectures.is_empty() {
        return Err(AppError::Validation(
            "Release file missing Architectures field".to_string(),
        ));
    }

    let known: BTreeSet<&str> = [
        "Origin",
        "Label",
        "Suite",
        "Codename",
        "Version",
        "Date",
        "Valid-Until",
        "Architectures",
        "Components",
        "Description",
        "MD5Sum",
        "SHA1",
        "SHA256",
        "SHA512",
    ]
    .into_iter()
    .collect();
    let extra = fields
        .iter()
        .filter(|(key, _)| !known.contains(key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    Ok(Release {
        origin: fields.get("Origin").cloned(),
        label: fields.get("Label").cloned(),
        suite,
        codename: fields.get("Codename").cloned(),
        version: fields.get("Version").cloned(),
        date,
        valid_until: fields.get("Valid-Until").cloned(),
        architectures,
        components,
        description: fields.get("Description").cloned(),
        md5sum: parse_release_hashes(fields.get("MD5Sum"))?,
        sha1: parse_release_hashes(fields.get("SHA1"))?,
        sha256: parse_release_hashes(fields.get("SHA256"))?,
        sha512: parse_release_hashes(fields.get("SHA512"))?,
        extra,
    })
}

fn clear_signed_payload(content: &str) -> Result<String> {
    if !content.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
        return Ok(content.to_string());
    }

    let mut lines = content.lines();
    let Some(first) = lines.next() else {
        return Err(AppError::Validation("InRelease is empty".to_string()));
    };
    if first != "-----BEGIN PGP SIGNED MESSAGE-----" {
        return Err(AppError::Validation(
            "Invalid InRelease clear-signature header".to_string(),
        ));
    }

    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
    }

    let mut payload = String::new();
    for line in lines {
        if line == "-----BEGIN PGP SIGNATURE-----" {
            break;
        }
        if let Some(unstuffed) = line.strip_prefix("- ") {
            payload.push_str(unstuffed);
        } else {
            payload.push_str(line);
        }
        payload.push('\n');
    }

    if payload.trim().is_empty() {
        return Err(AppError::Validation(
            "InRelease missing signed Release payload".to_string(),
        ));
    }

    Ok(payload)
}

fn parse_packages_entry(stanza: String) -> Result<PackagesEntry> {
    let mut control = DebianHandler::parse_control(&stanza)?;
    let filename = control.extra.remove("Filename");
    let size = control
        .extra
        .remove("Size")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| AppError::Validation(format!("Invalid Packages Size value '{value}'")))
        })
        .transpose()?;
    let md5sum = control.extra.remove("MD5sum");
    let sha1 = control.extra.remove("SHA1");
    let sha256 = control.extra.remove("SHA256");

    Ok(PackagesEntry {
        control,
        filename,
        size,
        md5sum,
        sha1,
        sha256,
    })
}

fn parse_source_file_hashes(
    value: Option<String>,
    field_name: &str,
) -> Result<BTreeMap<String, (String, u64)>> {
    let mut entries = BTreeMap::new();
    let Some(value) = value else {
        return Ok(entries);
    };
    for line in value.lines().filter(|line| !line.trim().is_empty()) {
        let mut parts = line.split_whitespace();
        let hash = parts
            .next()
            .ok_or_else(|| AppError::Validation(format!("{field_name} entry missing hash")))?;
        let size = parts
            .next()
            .ok_or_else(|| AppError::Validation(format!("{field_name} entry missing size")))?
            .parse::<u64>()
            .map_err(|_| AppError::Validation(format!("Invalid {field_name} size in '{line}'")))?;
        let filename = parts
            .next()
            .ok_or_else(|| AppError::Validation(format!("{field_name} entry missing filename")))?;
        entries.insert(filename.to_string(), (hash.to_string(), size));
    }
    Ok(entries)
}

fn parse_sources_entry(stanza: String) -> Result<SourcesEntry> {
    let mut fields = parse_field_map(&stanza)?;
    let package = fields
        .remove("Package")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::Validation("Sources entry missing Package field".to_string()))?;
    let version = fields
        .remove("Version")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::Validation("Sources entry missing Version field".to_string()))?;
    let directory = fields
        .remove("Directory")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::Validation("Sources entry missing Directory field".to_string()))?;

    let md5 = parse_source_file_hashes(fields.remove("Files"), "Files")?;
    let sha1 = parse_source_file_hashes(fields.remove("Checksums-Sha1"), "Checksums-Sha1")?;
    let sha256 = parse_source_file_hashes(fields.remove("Checksums-Sha256"), "Checksums-Sha256")?;
    let sha512 = parse_source_file_hashes(fields.remove("Checksums-Sha512"), "Checksums-Sha512")?;

    let mut filenames = BTreeSet::new();
    filenames.extend(md5.keys().cloned());
    filenames.extend(sha1.keys().cloned());
    filenames.extend(sha256.keys().cloned());
    filenames.extend(sha512.keys().cloned());

    let mut files = Vec::new();
    for filename in filenames {
        let size = sha256
            .get(&filename)
            .or_else(|| sha512.get(&filename))
            .or_else(|| sha1.get(&filename))
            .or_else(|| md5.get(&filename))
            .map(|(_, size)| *size)
            .unwrap_or(0);
        files.push(SourceFileEntry {
            filename: filename.clone(),
            size,
            md5sum: md5.get(&filename).map(|(hash, _)| hash.clone()),
            sha1: sha1.get(&filename).map(|(hash, _)| hash.clone()),
            sha256: sha256.get(&filename).map(|(hash, _)| hash.clone()),
            sha512: sha512.get(&filename).map(|(hash, _)| hash.clone()),
        });
    }

    Ok(SourcesEntry {
        package,
        version,
        directory,
        files,
        extra: fields,
    })
}

fn parse_debian_stanza_fields(content: &str) -> Result<BTreeMap<String, String>> {
    let stanzas = split_debian_stanzas(content);
    if stanzas.is_empty() {
        return Err(AppError::Validation("Debian metadata is empty".to_string()));
    }
    if stanzas.len() > 1 {
        return Err(AppError::Validation(
            "Expected one Debian metadata stanza".to_string(),
        ));
    }
    parse_field_map(&stanzas[0])
}

fn split_debian_stanzas(content: &str) -> Vec<String> {
    let mut stanzas = Vec::new();
    let mut current = String::new();

    for line in content.lines() {
        if line.trim().is_empty() {
            if !current.trim().is_empty() {
                stanzas.push(current.trim_end().to_string());
                current.clear();
            }
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }

    if !current.trim().is_empty() {
        stanzas.push(current.trim_end().to_string());
    }

    stanzas
}

fn parse_field_map(stanza: &str) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    let mut current_key: Option<String> = None;
    let mut current_value = String::new();

    for line in stanza.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if current_key.is_none() {
                return Err(AppError::Validation(
                    "Debian metadata continuation without field".to_string(),
                ));
            }
            current_value.push('\n');
            current_value.push_str(line.trim_start());
            continue;
        }

        let Some(colon_pos) = line.find(':') else {
            return Err(AppError::Validation(format!(
                "Malformed Debian metadata line '{line}'"
            )));
        };

        if let Some(key) = current_key.take() {
            fields.insert(key, current_value.trim().to_string());
            current_value.clear();
        }

        current_key = Some(line[..colon_pos].to_string());
        current_value.push_str(line[colon_pos + 1..].trim());
    }

    if let Some(key) = current_key {
        fields.insert(key, current_value.trim().to_string());
    }

    Ok(fields)
}

fn required_field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::Validation(format!("Release file missing {key} field")))
}

fn split_words(value: Option<&String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_release_hashes(value: Option<&String>) -> Result<Vec<ReleaseHash>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let mut hashes = Vec::new();
    for line in value.lines().filter(|line| !line.trim().is_empty()) {
        let mut parts = line.split_whitespace();
        let hash = parts
            .next()
            .ok_or_else(|| AppError::Validation("Release hash entry missing hash".to_string()))?;
        let size = parts
            .next()
            .ok_or_else(|| AppError::Validation("Release hash entry missing size".to_string()))?
            .parse::<u64>()
            .map_err(|_| AppError::Validation(format!("Invalid Release hash size in '{line}'")))?;
        let path = parts
            .next()
            .ok_or_else(|| AppError::Validation("Release hash entry missing path".to_string()))?;
        hashes.push(ReleaseHash {
            hash: hash.to_string(),
            size,
            path: path.to_string(),
        });
    }

    Ok(hashes)
}

fn parse_release_package_index_path(path: &str) -> Option<DebianIndexPath> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() == 1 {
        let filename = parts[0];
        if !is_packages_index_filename(filename) {
            return None;
        }
        return Some(DebianIndexPath {
            component: String::new(),
            architecture: String::new(),
            path: path.to_string(),
        });
    }

    if parts.len() != 3 || !parts[1].starts_with("binary-") {
        return None;
    }
    let filename = parts[2];
    if !is_packages_index_filename(filename) {
        return None;
    }

    Some(DebianIndexPath {
        component: parts[0].to_string(),
        architecture: parts[1].trim_start_matches("binary-").to_string(),
        path: path.to_string(),
    })
}

fn parse_release_source_index_path(path: &str) -> Option<DebianSourceIndexPath> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() == 1 {
        let filename = parts[0];
        if !is_sources_index_filename(filename) {
            return None;
        }
        return Some(DebianSourceIndexPath {
            component: String::new(),
            path: path.to_string(),
        });
    }

    if parts.len() != 3 || parts[1] != "source" {
        return None;
    }
    let filename = parts[2];
    if !is_sources_index_filename(filename) {
        return None;
    }

    Some(DebianSourceIndexPath {
        component: parts[0].to_string(),
        path: path.to_string(),
    })
}

fn is_packages_index_filename(filename: &str) -> bool {
    matches!(
        filename,
        "Packages"
            | "Packages.gz"
            | "Packages.xz"
            | "Packages.bz2"
            | "Packages.zst"
            | "Packages.zstd"
    )
}

fn is_sources_index_filename(filename: &str) -> bool {
    matches!(
        filename,
        "Sources" | "Sources.gz" | "Sources.xz" | "Sources.bz2" | "Sources.zst" | "Sources.zstd"
    )
}
fn is_debian_metadata_path(path: &str) -> bool {
    matches!(
        path,
        "Release"
            | "InRelease"
            | "Release.gpg"
            | "Packages"
            | "Packages.gz"
            | "Packages.xz"
            | "Sources"
            | "Sources.gz"
            | "Sources.xz"
    ) || (path.starts_with("dists/")
        && (path.ends_with("/Release")
            || path.ends_with("/InRelease")
            || path.ends_with("/Release.gpg")
            || path.ends_with("/Packages")
            || path.ends_with("/Packages.gz")
            || path.ends_with("/Packages.xz")
            || path.ends_with("/Sources")
            || path.ends_with("/Sources.gz")
            || path.ends_with("/Sources.xz")))
}

fn is_debian_pool_artifact(path: &str) -> bool {
    path.starts_with("pool/") && (path.ends_with(".deb") || path.ends_with(".udeb"))
}

/// Stable promotion target path for Debian packages.
///
/// Pool layout (`pool/<component>/…`) and flat `.deb`/`.udeb` paths are kept
/// unchanged so promoted artifacts remain addressable by the same Filename in
/// Packages indexes.
pub fn debian_promotion_target_path(source_path: &str) -> String {
    source_path.to_string()
}

/// True when any Packages index text lists `pool_path` as a `Filename:` entry.
///
/// Used for reference-aware cleanup before deleting a pool artifact: if the
/// path is still referenced by generated or cached Packages indexes, callers
/// should retain the blob (or regenerate indexes first).
pub fn debian_pool_path_still_referenced(packages_index_texts: &[String], pool_path: &str) -> bool {
    let pool_path = pool_path.trim();
    if pool_path.is_empty() {
        return false;
    }
    packages_index_texts.iter().any(|text| {
        text.lines().any(|line| {
            let Some(value) = line.strip_prefix("Filename:") else {
                return false;
            };
            value.trim() == pool_path
        })
    })
}

fn push_packages_field(entry: &mut String, key: &str, value: &str) {
    let mut lines = value.lines();
    let Some(first) = lines.next() else {
        return;
    };
    entry.push_str(key);
    entry.push_str(": ");
    entry.push_str(first);
    entry.push('\n');
    for line in lines {
        entry.push(' ');
        entry.push_str(if line.is_empty() { "." } else { line });
        entry.push('\n');
    }
}

fn push_optional_packages_field(entry: &mut String, key: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        push_packages_field(entry, key, value);
    }
}

fn push_dependency_packages_field(entry: &mut String, key: &str, values: Option<&Vec<String>>) {
    if let Some(values) = values.filter(|values| !values.is_empty()) {
        push_packages_field(entry, key, &values.join(", "));
    }
}

/// Generate Packages file entry
pub fn generate_packages_entry(
    control: &DebControl,
    filename: &str,
    size: u64,
    md5sum: &str,
    sha256: &str,
) -> String {
    let mut entry = String::new();

    push_packages_field(&mut entry, "Package", &control.package);
    push_packages_field(&mut entry, "Version", &control.version);
    push_packages_field(&mut entry, "Architecture", &control.architecture);
    push_optional_packages_field(&mut entry, "Maintainer", control.maintainer.as_deref());
    if let Some(size) = control.installed_size {
        push_packages_field(&mut entry, "Installed-Size", &size.to_string());
    }
    push_dependency_packages_field(&mut entry, "Depends", control.depends.as_ref());
    push_dependency_packages_field(&mut entry, "Pre-Depends", control.pre_depends.as_ref());
    push_dependency_packages_field(&mut entry, "Recommends", control.recommends.as_ref());
    push_dependency_packages_field(&mut entry, "Suggests", control.suggests.as_ref());
    push_dependency_packages_field(&mut entry, "Conflicts", control.conflicts.as_ref());
    push_dependency_packages_field(&mut entry, "Provides", control.provides.as_ref());
    push_dependency_packages_field(&mut entry, "Replaces", control.replaces.as_ref());
    push_optional_packages_field(&mut entry, "Section", control.section.as_deref());
    push_optional_packages_field(&mut entry, "Priority", control.priority.as_deref());
    push_optional_packages_field(&mut entry, "Homepage", control.homepage.as_deref());
    push_optional_packages_field(&mut entry, "Source", control.source.as_deref());
    let mut extra_fields: Vec<_> = control.extra.iter().collect();
    extra_fields.sort_by_key(|(key, _)| *key);
    for (key, value) in extra_fields {
        push_packages_field(&mut entry, key, value);
    }
    push_optional_packages_field(&mut entry, "Description", control.description.as_deref());
    push_packages_field(&mut entry, "Filename", filename);
    push_packages_field(&mut entry, "Size", &size.to_string());
    push_packages_field(&mut entry, "MD5sum", md5sum);
    push_packages_field(&mut entry, "SHA256", sha256);

    entry
}

/// Generate Release file
pub fn generate_release(
    suite: &str,
    codename: Option<&str>,
    architectures: &[String],
    components: &[String],
    hashes: Vec<ReleaseHash>,
) -> String {
    let mut release = String::new();
    let mut architectures = architectures.to_vec();
    let mut components = components.to_vec();
    let mut hashes = hashes;
    architectures.sort();
    components.sort();
    hashes.sort_by(|a, b| a.path.cmp(&b.path));

    release.push_str(&format!("Suite: {}\n", suite));
    if let Some(cn) = codename {
        release.push_str(&format!("Codename: {}\n", cn));
    }
    release.push_str(&format!("Date: {}\n", chrono::Utc::now().to_rfc2822()));
    release.push_str(&format!("Architectures: {}\n", architectures.join(" ")));
    release.push_str(&format!("Components: {}\n", components.join(" ")));

    if !hashes.is_empty() {
        release.push_str("SHA256:\n");
        for h in hashes {
            release.push_str(&format!(" {} {} {}\n", h.hash, h.size, h.path));
        }
    }

    release
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    // ========================================================================
    // parse_deb_filename tests
    // ========================================================================

    #[test]
    fn test_parse_deb_filename() {
        let (pkg, ver, arch) =
            DebianHandler::parse_deb_filename("nginx_1.24.0-1_amd64.deb").unwrap();
        assert_eq!(pkg, "nginx");
        assert_eq!(ver, "1.24.0-1");
        assert_eq!(arch, "amd64");
    }

    #[test]
    fn test_parse_deb_filename_all_arch() {
        let (pkg, ver, arch) =
            DebianHandler::parse_deb_filename("python3-pip_23.0.1-1_all.deb").unwrap();
        assert_eq!(pkg, "python3-pip");
        assert_eq!(ver, "23.0.1-1");
        assert_eq!(arch, "all");
    }

    #[test]
    fn test_parse_deb_filename_arm64() {
        let (pkg, ver, arch) = DebianHandler::parse_deb_filename("libc6_2.36-9_arm64.deb").unwrap();
        assert_eq!(pkg, "libc6");
        assert_eq!(ver, "2.36-9");
        assert_eq!(arch, "arm64");
    }

    #[test]
    fn test_parse_deb_filename_udeb() {
        let (pkg, ver, arch) =
            DebianHandler::parse_deb_filename("base-installer_1.200_amd64.udeb").unwrap();
        assert_eq!(pkg, "base-installer");
        assert_eq!(ver, "1.200");
        assert_eq!(arch, "amd64");
    }

    #[test]
    fn test_parse_deb_filename_epoch_in_version() {
        // Debian allows epoch: "1:1.0-1" but _ separates fields
        let (pkg, ver, arch) =
            DebianHandler::parse_deb_filename("pkg_1%3a2.0-1_amd64.deb").unwrap();
        assert_eq!(pkg, "pkg");
        assert_eq!(ver, "1%3a2.0-1");
        assert_eq!(arch, "amd64");
    }

    #[test]
    fn test_parse_deb_filename_debian_version_special_characters() {
        let (pkg, ver, arch) =
            DebianHandler::parse_deb_filename("nginx_1:1.24.0-1~ubuntu+1_amd64.deb").unwrap();
        assert_eq!(pkg, "nginx");
        assert_eq!(ver, "1:1.24.0-1~ubuntu+1");
        assert_eq!(arch, "amd64");
    }

    #[test]
    fn test_parse_deb_filename_too_few_underscores() {
        let result = DebianHandler::parse_deb_filename("invalid_name.deb");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_deb_filename_no_underscores() {
        let result = DebianHandler::parse_deb_filename("invalidname.deb");
        assert!(result.is_err());
    }

    // ========================================================================
    // parse_path tests
    // ========================================================================

    #[test]
    fn test_parse_path_package() {
        let info = DebianHandler::parse_path("pool/main/n/nginx/nginx_1.24.0-1_amd64.deb").unwrap();
        assert!(matches!(info.operation, DebianOperation::Package));
        assert_eq!(info.package, Some("nginx".to_string()));
        assert_eq!(info.component, Some("main".to_string()));
    }

    #[test]
    fn test_parse_path_release() {
        let info = DebianHandler::parse_path("dists/jammy/Release").unwrap();
        assert!(matches!(info.operation, DebianOperation::Release));
        assert_eq!(info.distribution, Some("jammy".to_string()));
    }

    #[test]
    fn test_parse_path_release_gpg() {
        let info = DebianHandler::parse_path("dists/jammy/Release.gpg").unwrap();
        assert!(matches!(info.operation, DebianOperation::Release));
        assert_eq!(info.distribution, Some("jammy".to_string()));
    }

    #[test]
    fn test_parse_path_inrelease() {
        let info = DebianHandler::parse_path("dists/focal/InRelease").unwrap();
        assert!(matches!(info.operation, DebianOperation::Release));
        assert_eq!(info.distribution, Some("focal".to_string()));
    }

    #[test]
    fn test_parse_path_packages() {
        let info = DebianHandler::parse_path("dists/jammy/main/binary-amd64/Packages.gz").unwrap();
        assert!(matches!(info.operation, DebianOperation::Packages));
        assert_eq!(info.distribution, Some("jammy".to_string()));
        assert_eq!(info.component, Some("main".to_string()));
        assert_eq!(info.arch, Some("amd64".to_string()));
    }

    #[test]
    fn test_parse_path_packages_xz() {
        let info =
            DebianHandler::parse_path("dists/bookworm/main/binary-arm64/Packages.xz").unwrap();
        assert!(matches!(info.operation, DebianOperation::Packages));
        assert_eq!(info.arch, Some("arm64".to_string()));
    }

    #[test]
    fn test_parse_path_packages_uncompressed() {
        let info = DebianHandler::parse_path("dists/jammy/universe/binary-i386/Packages").unwrap();
        assert!(matches!(info.operation, DebianOperation::Packages));
        assert_eq!(info.component, Some("universe".to_string()));
        assert_eq!(info.arch, Some("i386".to_string()));
    }

    #[test]
    fn test_parse_path_pool_with_lib_prefix() {
        let info =
            DebianHandler::parse_path("pool/main/libo/libopenssl/libopenssl_3.0.0-1_amd64.deb")
                .unwrap();
        assert!(matches!(info.operation, DebianOperation::Package));
        assert_eq!(info.component, Some("main".to_string()));
    }

    #[test]
    fn test_parse_path_direct_deb_file() {
        let info = DebianHandler::parse_path("nginx_1.24.0-1_amd64.deb").unwrap();
        assert!(matches!(info.operation, DebianOperation::Package));
        assert_eq!(info.package, Some("nginx".to_string()));
    }

    #[test]
    fn test_parse_path_direct_udeb_file() {
        let info = DebianHandler::parse_path("base_1.0_amd64.udeb").unwrap();
        assert!(matches!(info.operation, DebianOperation::Package));
        assert_eq!(info.package, Some("base".to_string()));
    }

    #[test]
    fn test_parse_path_leading_slash() {
        let info = DebianHandler::parse_path("/dists/jammy/Release").unwrap();
        assert!(matches!(info.operation, DebianOperation::Release));
    }

    #[test]
    fn test_parse_path_invalid() {
        let result = DebianHandler::parse_path("some/random/path.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_release_no_dist_prefix() {
        // Path contains "/Release" but doesn't start with "dists/"
        let info = DebianHandler::parse_path("other/Release").unwrap();
        assert!(matches!(info.operation, DebianOperation::Release));
        assert!(info.distribution.is_none());
    }

    #[test]
    fn test_parse_path_packages_short_path() {
        // Packages file but not enough path segments for dist/comp/arch
        let info = DebianHandler::parse_path("some/Packages").unwrap();
        assert!(matches!(info.operation, DebianOperation::Packages));
        assert!(info.distribution.is_none());
        assert!(info.component.is_none());
        assert!(info.arch.is_none());
    }

    // ========================================================================
    // get_pool_prefix tests
    // ========================================================================

    #[test]
    fn test_get_pool_prefix() {
        assert_eq!(DebianHandler::get_pool_prefix("nginx"), "n");
        assert_eq!(DebianHandler::get_pool_prefix("libc6"), "libc");
        assert_eq!(DebianHandler::get_pool_prefix("libssl3"), "libs");
    }

    #[test]
    fn test_get_pool_prefix_short_lib() {
        // "lib" is only 3 chars, which is not > 4 in length, so just first char
        assert_eq!(DebianHandler::get_pool_prefix("lib"), "l");
    }

    #[test]
    fn test_get_pool_prefix_liba() {
        // "liba" has length 4, not > 4, so just first char
        assert_eq!(DebianHandler::get_pool_prefix("liba"), "l");
    }

    #[test]
    fn test_get_pool_prefix_libab() {
        // "libab" has length 5, which is > 4, so first 4 chars
        assert_eq!(DebianHandler::get_pool_prefix("libab"), "liba");
    }

    #[test]
    fn test_get_pool_prefix_single_char() {
        assert_eq!(DebianHandler::get_pool_prefix("a"), "a");
    }

    #[test]
    fn test_get_pool_prefix_empty() {
        // Empty string: chars().next() is None, so '_'
        assert_eq!(DebianHandler::get_pool_prefix(""), "_");
    }

    // ========================================================================
    // get_pool_path tests
    // ========================================================================

    #[test]
    fn test_get_pool_path_normal() {
        let path = DebianHandler::get_pool_path("main", "nginx", "nginx_1.24.0-1_amd64.deb");
        assert_eq!(path, "pool/main/n/nginx/nginx_1.24.0-1_amd64.deb");
    }

    #[test]
    fn test_get_pool_path_lib_package() {
        let path = DebianHandler::get_pool_path("main", "libssl3", "libssl3_3.0.0-1_amd64.deb");
        assert_eq!(path, "pool/main/libs/libssl3/libssl3_3.0.0-1_amd64.deb");
    }

    #[test]
    fn test_get_pool_path_universe_component() {
        let path = DebianHandler::get_pool_path("universe", "vim", "vim_9.0.1000-1_amd64.deb");
        assert_eq!(path, "pool/universe/v/vim/vim_9.0.1000-1_amd64.deb");
    }

    // ========================================================================
    // parse_control tests
    // ========================================================================

    #[test]
    fn test_parse_control() {
        let content = r#"Package: nginx
Version: 1.24.0-1
Architecture: amd64
Maintainer: Test <test@example.com>
Installed-Size: 1234
Depends: libc6 (>= 2.34), libpcre3
Section: web
Priority: optional
Description: High performance web server
"#;
        let control = DebianHandler::parse_control(content).unwrap();
        assert_eq!(control.package, "nginx");
        assert_eq!(control.version, "1.24.0-1");
        assert_eq!(control.architecture, "amd64");
        assert_eq!(control.depends.as_ref().map(|d| d.len()), Some(2));
    }

    #[test]
    fn test_parse_control_missing_package() {
        let content = "Version: 1.0\nArchitecture: amd64\n";
        let result = DebianHandler::parse_control(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_control_missing_version() {
        let content = "Package: pkg\nArchitecture: amd64\n";
        let result = DebianHandler::parse_control(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_control_missing_architecture() {
        let content = "Package: pkg\nVersion: 1.0\n";
        let result = DebianHandler::parse_control(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_control_empty() {
        let result = DebianHandler::parse_control("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_control_all_fields() {
        let content = r#"Package: full-pkg
Version: 2.0.0-1
Architecture: amd64
Maintainer: Admin <admin@example.com>
Installed-Size: 5678
Depends: libc6, libssl3
Pre-Depends: dpkg (>= 1.17.5)
Recommends: vim
Suggests: emacs
Conflicts: old-pkg
Provides: virtual-pkg
Replaces: old-pkg
Section: admin
Priority: important
Homepage: https://example.com
Description: A full package
Source: full-pkg-src
"#;
        let control = DebianHandler::parse_control(content).unwrap();
        assert_eq!(control.package, "full-pkg");
        assert_eq!(control.version, "2.0.0-1");
        assert_eq!(control.architecture, "amd64");
        assert_eq!(
            control.maintainer,
            Some("Admin <admin@example.com>".to_string())
        );
        assert_eq!(control.installed_size, Some(5678));
        assert_eq!(
            control.depends,
            Some(vec!["libc6".to_string(), "libssl3".to_string()])
        );
        assert_eq!(
            control.pre_depends,
            Some(vec!["dpkg (>= 1.17.5)".to_string()])
        );
        assert_eq!(control.recommends, Some(vec!["vim".to_string()]));
        assert_eq!(control.suggests, Some(vec!["emacs".to_string()]));
        assert_eq!(control.conflicts, Some(vec!["old-pkg".to_string()]));
        assert_eq!(control.provides, Some(vec!["virtual-pkg".to_string()]));
        assert_eq!(control.replaces, Some(vec!["old-pkg".to_string()]));
        assert_eq!(control.section, Some("admin".to_string()));
        assert_eq!(control.priority, Some("important".to_string()));
        assert_eq!(control.homepage, Some("https://example.com".to_string()));
        assert_eq!(control.description, Some("A full package".to_string()));
        assert_eq!(control.source, Some("full-pkg-src".to_string()));
    }

    #[test]
    fn test_parse_control_continuation_lines() {
        let content = "Package: pkg\nVersion: 1.0\nArchitecture: amd64\nDescription: Short desc\n Extended description line 1\n Extended description line 2\n";
        let control = DebianHandler::parse_control(content).unwrap();
        assert!(control
            .description
            .as_ref()
            .unwrap()
            .contains("Short desc\nExtended description line 1\nExtended description line 2"));
    }

    #[test]
    fn test_parse_control_tab_continuation() {
        let content =
            "Package: pkg\nVersion: 1.0\nArchitecture: amd64\nDescription: Desc\n\tMore desc\n";
        let control = DebianHandler::parse_control(content).unwrap();
        assert!(control.description.as_ref().unwrap().contains("More desc"));
    }

    #[test]
    fn test_parse_control_unknown_fields_go_to_extra() {
        let content = "Package: pkg\nVersion: 1.0\nArchitecture: amd64\nX-Custom: custom-value\n";
        let control = DebianHandler::parse_control(content).unwrap();
        assert_eq!(
            control.extra.get("X-Custom"),
            Some(&"custom-value".to_string())
        );
    }

    #[test]
    fn test_parse_control_installed_size_invalid() {
        let content =
            "Package: pkg\nVersion: 1.0\nArchitecture: amd64\nInstalled-Size: not-a-number\n";
        let control = DebianHandler::parse_control(content).unwrap();
        assert!(control.installed_size.is_none());
    }

    #[test]
    fn test_parse_control_empty_depends() {
        let content = "Package: pkg\nVersion: 1.0\nArchitecture: amd64\nDepends: \n";
        let control = DebianHandler::parse_control(content).unwrap();
        // parse_dependency_list on empty string: split(',') gives [""], but filtered empty
        assert_eq!(control.depends, Some(vec![]));
    }

    #[test]
    fn test_parse_control_multiple_depends() {
        let content = "Package: pkg\nVersion: 1.0\nArchitecture: amd64\nDepends: libc6, libm, libpthread, libdl\n";
        let control = DebianHandler::parse_control(content).unwrap();
        let deps = control.depends.unwrap();
        assert_eq!(deps.len(), 4);
        assert_eq!(deps[0], "libc6");
        assert_eq!(deps[3], "libdl");
    }

    // ========================================================================
    // parse_dependency_list tests (indirectly)
    // ========================================================================

    #[test]
    fn test_parse_dependency_list_with_versions() {
        let content = "Package: pkg\nVersion: 1.0\nArchitecture: amd64\nDepends: libc6 (>= 2.34), libssl3 (>= 3.0)\n";
        let control = DebianHandler::parse_control(content).unwrap();
        let deps = control.depends.unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0], "libc6 (>= 2.34)");
        assert_eq!(deps[1], "libssl3 (>= 3.0)");
    }

    #[test]
    fn test_parse_dependency_list_with_alternatives() {
        let content =
            "Package: pkg\nVersion: 1.0\nArchitecture: amd64\nDepends: editor | vim | nano\n";
        let control = DebianHandler::parse_control(content).unwrap();
        let deps = control.depends.unwrap();
        // No comma separation, so entire "editor | vim | nano" is one entry
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], "editor | vim | nano");
    }

    // ========================================================================
    // extract_control tests
    // ========================================================================

    #[test]
    fn test_extract_control_invalid_ar_magic() {
        let result = DebianHandler::extract_control(b"not-an-ar-archive-at-all!!");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("not an ar archive"));
    }

    #[test]
    fn test_extract_control_too_short() {
        let result = DebianHandler::extract_control(b"short");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_control_valid_magic_no_control() {
        // Valid ar magic but no control.tar inside
        let mut data = Vec::new();
        data.extend_from_slice(b"!<arch>\n");
        // Add a dummy member that is NOT control.tar
        // ar header: 60 bytes (name[16], mtime[12], uid[6], gid[6], mode[8], size[10], magic[2])
        let mut header = [b' '; 60];
        header[..12].copy_from_slice(b"debian-binar");
        // size = "0" padded
        header[48] = b'0';
        header[58] = b'`';
        header[59] = b'\n';
        data.extend_from_slice(&header);

        let result = DebianHandler::extract_control(&data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("control.tar not found"));
    }

    fn append_ar_member(out: &mut Vec<u8>, name: &str, content: &[u8]) {
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name,
            0,
            0,
            0,
            "100644",
            content.len()
        );
        assert_eq!(header.len(), 60);
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(content);
        if content.len() % 2 == 1 {
            out.push(b'\n');
        }
    }

    fn control_tar(control: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(control.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "./control", control.as_bytes())
            .expect("append control");
        builder.finish().expect("finish tar");
        builder.into_inner().expect("tar bytes")
    }

    fn deb_with_control_member(member_name: &str, control_member: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"!<arch>\n");
        append_ar_member(&mut data, "debian-binary", b"2.0\n");
        append_ar_member(&mut data, member_name, control_member);
        data
    }

    #[test]
    fn test_extract_control_xz() {
        use std::io::Write;

        let control = "Package: xz-pkg\nVersion: 1.0-1\nArchitecture: amd64\n";
        let tar_bytes = control_tar(control);
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&tar_bytes).expect("write xz");
        let control_tar_xz = encoder.finish().expect("finish xz");
        let deb = deb_with_control_member("control.tar.xz", &control_tar_xz);

        let control = DebianHandler::extract_control(&deb).expect("extract xz control");
        assert_eq!(control.package, "xz-pkg");
        assert_eq!(control.version, "1.0-1");
        assert_eq!(control.architecture, "amd64");
    }

    // ========================================================================
    // generate_packages_entry tests
    // ========================================================================

    #[test]
    fn test_generate_packages_entry_basic() {
        let control = DebControl {
            package: "nginx".to_string(),
            version: "1.24.0-1".to_string(),
            architecture: "amd64".to_string(),
            maintainer: Some("Admin <admin@test.com>".to_string()),
            installed_size: Some(1024),
            depends: Some(vec!["libc6".to_string(), "libssl3".to_string()]),
            section: Some("web".to_string()),
            priority: Some("optional".to_string()),
            homepage: Some("https://nginx.org".to_string()),
            description: Some("Web server".to_string()),
            ..Default::default()
        };
        let entry = generate_packages_entry(
            &control,
            "pool/main/n/nginx/nginx_1.24.0-1_amd64.deb",
            2048,
            "md5hash",
            "sha256hash",
        );
        assert!(entry.contains("Package: nginx\n"));
        assert!(entry.contains("Version: 1.24.0-1\n"));
        assert!(entry.contains("Architecture: amd64\n"));
        assert!(entry.contains("Maintainer: Admin <admin@test.com>\n"));
        assert!(entry.contains("Installed-Size: 1024\n"));
        assert!(entry.contains("Depends: libc6, libssl3\n"));
        assert!(entry.contains("Section: web\n"));
        assert!(entry.contains("Priority: optional\n"));
        assert!(entry.contains("Homepage: https://nginx.org\n"));
        assert!(entry.contains("Description: Web server\n"));
        assert!(entry.contains("Filename: pool/main/n/nginx/nginx_1.24.0-1_amd64.deb\n"));
        assert!(entry.contains("Size: 2048\n"));
        assert!(entry.contains("MD5sum: md5hash\n"));
        assert!(entry.contains("SHA256: sha256hash\n"));
    }

    #[test]
    fn test_generate_packages_entry_minimal() {
        let control = DebControl {
            package: "minimal".to_string(),
            version: "0.1".to_string(),
            architecture: "all".to_string(),
            ..Default::default()
        };
        let entry = generate_packages_entry(&control, "file.deb", 100, "md5", "sha");
        assert!(entry.contains("Package: minimal\n"));
        assert!(entry.contains("Version: 0.1\n"));
        assert!(entry.contains("Architecture: all\n"));
        assert!(!entry.contains("Maintainer:"));
        assert!(!entry.contains("Installed-Size:"));
        assert!(!entry.contains("Depends:"));
        assert!(!entry.contains("Section:"));
        assert!(!entry.contains("Priority:"));
        assert!(!entry.contains("Homepage:"));
        assert!(!entry.contains("Description:"));
    }

    #[test]
    fn test_generate_packages_entry_empty_depends() {
        let control = DebControl {
            package: "pkg".to_string(),
            version: "1.0".to_string(),
            architecture: "amd64".to_string(),
            depends: Some(vec![]),
            ..Default::default()
        };
        let entry = generate_packages_entry(&control, "f.deb", 10, "m", "s");
        // Empty depends should not generate a Depends line
        assert!(!entry.contains("Depends:"));
    }

    // ========================================================================
    // generate_release tests
    // ========================================================================

    #[test]
    fn test_generate_release_basic() {
        let release = generate_release(
            "jammy",
            Some("jammy"),
            &["amd64".to_string(), "arm64".to_string()],
            &["main".to_string(), "universe".to_string()],
            vec![],
        );
        assert!(release.contains("Suite: jammy\n"));
        assert!(release.contains("Codename: jammy\n"));
        assert!(release.contains("Architectures: amd64 arm64\n"));
        assert!(release.contains("Components: main universe\n"));
        assert!(release.contains("Date:"));
        assert!(!release.contains("SHA256:"));
    }

    #[test]
    fn test_generate_release_no_codename() {
        let release = generate_release(
            "stable",
            None,
            &["amd64".to_string()],
            &["main".to_string()],
            vec![],
        );
        assert!(release.contains("Suite: stable\n"));
        assert!(!release.contains("Codename:"));
    }

    #[test]
    fn test_generate_release_with_hashes() {
        let hashes = vec![
            ReleaseHash {
                hash: "abc123".to_string(),
                size: 1024,
                path: "main/binary-amd64/Packages".to_string(),
            },
            ReleaseHash {
                hash: "def456".to_string(),
                size: 512,
                path: "main/binary-amd64/Packages.gz".to_string(),
            },
        ];
        let release = generate_release(
            "jammy",
            None,
            &["amd64".to_string()],
            &["main".to_string()],
            hashes,
        );
        assert!(release.contains("SHA256:\n"));
        assert!(release.contains(" abc123 1024 main/binary-amd64/Packages\n"));
        assert!(release.contains(" def456 512 main/binary-amd64/Packages.gz\n"));
    }

    #[test]
    fn test_parse_release_with_hash_sections() {
        let content = "Origin: Artifact Keeper\nLabel: Artifact Keeper\nSuite: jammy\nCodename: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64 arm64\nComponents: main universe\nDescription: Test repo\nSHA256:\n abc123 1024 main/binary-amd64/Packages\n def456 512 universe/binary-arm64/Packages.gz\nSHA512:\n fedcba 256 main/binary-amd64/Packages.xz\nX-Extra: kept\n";

        let release = parse_release(content).unwrap();
        assert_eq!(release.suite, "jammy");
        assert_eq!(release.codename.as_deref(), Some("jammy"));
        assert_eq!(release.architectures, vec!["amd64", "arm64"]);
        assert_eq!(release.components, vec!["main", "universe"]);
        assert_eq!(release.sha256.len(), 2);
        assert_eq!(release.sha512[0].path, "main/binary-amd64/Packages.xz");
        assert_eq!(
            release.extra.get("X-Extra").map(String::as_str),
            Some("kept")
        );
    }

    #[test]
    fn test_parse_in_release_clear_signed_payload() {
        let content = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSuite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\nSHA256:\n abc123 42 main/binary-amd64/Packages\n-----BEGIN PGP SIGNATURE-----\nignored\n-----END PGP SIGNATURE-----\n";

        let release = parse_in_release(content).unwrap();
        assert_eq!(release.suite, "jammy");
        assert_eq!(release.sha256[0].size, 42);
    }

    #[test]
    fn test_parse_release_gpg_armored() {
        let sig =
            parse_release_gpg(b"-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n")
                .unwrap();
        assert!(sig.is_armored);
        assert!(sig.size > 0);
    }

    #[test]
    fn test_generate_release_signatures_with_mock_signer() {
        struct MockSigner;

        impl DebianReleaseSigner for MockSigner {
            fn sign_in_release(&self, release: &str) -> Result<String> {
                Ok(format!(
                    "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{release}-----BEGIN PGP SIGNATURE-----\nmock\n-----END PGP SIGNATURE-----\n"
                ))
            }

            fn sign_release_gpg(&self, release: &[u8]) -> Result<Vec<u8>> {
                let mut signature = b"mock-detached:".to_vec();
                signature.extend_from_slice(release);
                Ok(signature)
            }
        }

        let release = "Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\n";
        let in_release = generate_in_release(&MockSigner, release).unwrap();
        assert!(in_release.contains("-----BEGIN PGP SIGNED MESSAGE-----"));
        assert!(in_release.contains("Suite: jammy"));

        let release_gpg = generate_release_gpg(&MockSigner, release).unwrap();
        assert!(release_gpg.starts_with(b"mock-detached:"));
        assert!(release_gpg.ends_with(release.as_bytes()));
    }

    #[test]
    fn test_generate_release_signatures_reject_empty_release() {
        struct MockSigner;

        impl DebianReleaseSigner for MockSigner {
            fn sign_in_release(&self, release: &str) -> Result<String> {
                Ok(release.to_string())
            }

            fn sign_release_gpg(&self, release: &[u8]) -> Result<Vec<u8>> {
                Ok(release.to_vec())
            }
        }

        assert!(generate_in_release(&MockSigner, " ").is_err());
        assert!(generate_release_gpg(&MockSigner, "").is_err());
    }

    #[test]
    fn test_parse_packages_index_gz() {
        use flate2::write::GzEncoder;
        use std::io::Write as _;

        let packages = "Package: nginx\nVersion: 1:1.24.0-1~ubuntu+1\nArchitecture: amd64\nDescription: Web server\n extended description\nFilename: pool/main/n/nginx/nginx_1:1.24.0-1~ubuntu+1_amd64.deb\nSize: 2048\nMD5sum: md5\nSHA1: sha1\nSHA256: sha256\n\n";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(packages.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        let parsed = parse_packages_index("main/binary-amd64/Packages.gz", &compressed).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].control.package, "nginx");
        assert_eq!(parsed[0].control.version, "1:1.24.0-1~ubuntu+1");
        assert_eq!(
            parsed[0].control.description.as_deref(),
            Some("Web server\nextended description")
        );
        assert_eq!(
            parsed[0].filename.as_deref(),
            Some("pool/main/n/nginx/nginx_1:1.24.0-1~ubuntu+1_amd64.deb")
        );
        assert_eq!(parsed[0].size, Some(2048));
        assert_eq!(parsed[0].sha1.as_deref(), Some("sha1"));
        assert_eq!(parsed[0].sha256.as_deref(), Some("sha256"));
    }

    #[test]
    fn test_parse_sources_index_preserves_hashes_and_unknown_fields() {
        let sources = "Package: nginx\nBinary: nginx\nVersion: 1.0-1\nMaintainer: Example Maintainer <maintainer@example.invalid>\nDirectory: pool/main/n/nginx\nFiles:\n md5dsc 11 nginx_1.0-1.dsc\n md5tar 22 nginx_1.0.orig.tar.xz\nChecksums-Sha1:\n sha1dsc 11 nginx_1.0-1.dsc\nChecksums-Sha256:\n sha256dsc 11 nginx_1.0-1.dsc\n sha256tar 22 nginx_1.0.orig.tar.xz\nChecksums-Sha512:\n sha512dsc 11 nginx_1.0-1.dsc\nX-Kept: yes\n\n";

        let parsed = parse_sources_index("main/source/Sources", sources.as_bytes()).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].package, "nginx");
        assert_eq!(parsed[0].version, "1.0-1");
        assert_eq!(parsed[0].directory, "pool/main/n/nginx");
        assert_eq!(
            parsed[0].extra.get("Binary").map(String::as_str),
            Some("nginx")
        );
        assert_eq!(
            parsed[0].extra.get("X-Kept").map(String::as_str),
            Some("yes")
        );
        assert_eq!(parsed[0].files.len(), 2);
        assert!(parsed[0].files.iter().any(|file| {
            file.filename == "nginx_1.0-1.dsc"
                && file.size == 11
                && file.md5sum.as_deref() == Some("md5dsc")
                && file.sha1.as_deref() == Some("sha1dsc")
                && file.sha256.as_deref() == Some("sha256dsc")
                && file.sha512.as_deref() == Some("sha512dsc")
        }));
        assert!(parsed[0].files.iter().any(|file| {
            file.filename == "nginx_1.0.orig.tar.xz"
                && file.size == 22
                && file.md5sum.as_deref() == Some("md5tar")
                && file.sha256.as_deref() == Some("sha256tar")
        }));
    }
    #[test]
    fn test_filter_release_package_indexes_by_component_and_architecture() {
        let release = parse_release("Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64 arm64\nComponents: main universe\nSHA256:\n a 1 main/binary-amd64/Packages.xz\n b 1 main/binary-arm64/Packages.xz\n c 1 universe/binary-amd64/Packages.gz\n").unwrap();
        let filter = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };

        let indexes = filter_release_package_indexes(&release, &filter);
        assert_eq!(
            indexes,
            vec![DebianIndexPath {
                component: "main".to_string(),
                architecture: "amd64".to_string(),
                path: "main/binary-amd64/Packages.xz".to_string(),
            }]
        );
    }

    #[test]
    fn test_filter_release_package_indexes_prefers_one_compressed_representation() {
        let release = parse_release("Suite: bookworm\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\nSHA256:\n a 1 main/binary-amd64/Packages\n b 1 main/binary-amd64/Packages.gz\n c 1 main/binary-amd64/Packages.xz\n").unwrap();
        let indexes = filter_release_package_indexes(&release, &DebianSyncFilter::default());
        assert_eq!(indexes.len(), 1);
        assert_eq!(indexes[0].path, "main/binary-amd64/Packages.xz");
    }

    #[test]
    fn test_filter_release_package_indexes_respects_distribution_filter() {
        let release = parse_release("Suite: stable\nCodename: bookworm\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\nSHA256:\n a 1 main/binary-amd64/Packages.xz\n").unwrap();
        let filter = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };

        assert!(filter_release_package_indexes(&release, &filter).is_empty());

        let filter = DebianSyncFilter {
            distributions: vec!["bookworm".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };
        assert_eq!(filter_release_package_indexes(&release, &filter).len(), 1);
    }

    #[test]
    fn test_validate_release_filter_selection_rejects_missing_component() {
        let release = parse_release("Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\n").unwrap();
        let filter = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["universe".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };

        let err = validate_release_filter_selection(&release, &filter).unwrap_err();
        assert!(err
            .to_string()
            .contains("Selected Debian component(s) not advertised"));
    }

    #[test]
    fn test_validate_release_filter_accepts_main_for_debian_security_updates_main() {
        let release = parse_release(
            "Suite: oldstable-security\nCodename: bookworm-security\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: updates/main updates/contrib\nSHA256:\n a 1 main/binary-amd64/Packages.xz\n",
        )
        .unwrap();
        let filter = DebianSyncFilter {
            distributions: vec!["bookworm-security".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };

        validate_release_filter_selection(&release, &filter).unwrap();
        let indexes = filter_release_package_indexes(&release, &filter);
        assert_eq!(indexes.len(), 1);
        assert_eq!(indexes[0].component, "main");
        assert_eq!(indexes[0].path, "main/binary-amd64/Packages.xz");
    }

    #[test]
    fn test_debian_components_equivalent_leaf_matching() {
        assert!(debian_components_equivalent("main", "main"));
        assert!(debian_components_equivalent("main", "updates/main"));
        assert!(debian_components_equivalent("updates/main", "main"));
        assert!(!debian_components_equivalent("main", "updates/contrib"));
        assert!(!debian_components_equivalent("universe", "main"));
    }

    #[test]
    fn test_validate_release_filter_selection_rejects_missing_architecture() {
        let release = parse_release("Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\n").unwrap();
        let filter = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["arm64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };

        let err = validate_release_filter_selection(&release, &filter).unwrap_err();
        assert!(err
            .to_string()
            .contains("Selected Debian architecture(s) not advertised"));
    }
    #[test]
    fn test_filter_release_source_indexes_requires_source_flag() {
        let release = parse_release("Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main universe\nSHA256:\n a 1 main/source/Sources\n b 1 main/source/Sources.gz\n c 1 main/source/Sources.xz\n d 1 universe/source/Sources.xz\n").unwrap();
        let mut filter = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };

        assert!(filter_release_source_indexes(&release, &filter).is_empty());

        filter.include_source_packages = true;
        let indexes = filter_release_source_indexes(&release, &filter);
        assert_eq!(
            indexes,
            vec![DebianSourceIndexPath {
                component: "main".to_string(),
                path: "main/source/Sources.xz".to_string(),
            }]
        );
    }
    #[test]
    fn test_flat_release_indexes_are_selected_without_distribution_filter() {
        let release = parse_release("Suite: stable\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nSHA256:\n a 1 Packages\n b 1 Packages.gz\n c 1 Packages.xz\n d 1 Sources.xz\n").unwrap();
        let filter = DebianSyncFilter {
            distributions: Vec::new(),
            components: Vec::new(),
            architectures: vec!["amd64".to_string()],
            include_source_packages: true,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };

        let package_indexes = filter_release_package_indexes(&release, &filter);
        assert_eq!(
            package_indexes,
            vec![DebianIndexPath {
                component: String::new(),
                architecture: String::new(),
                path: "Packages.xz".to_string(),
            }]
        );

        let source_indexes = filter_release_source_indexes(&release, &filter);
        assert_eq!(
            source_indexes,
            vec![DebianSourceIndexPath {
                component: String::new(),
                path: "Sources.xz".to_string(),
            }]
        );
    }

    #[test]
    fn test_flat_metadata_paths_are_classified_as_debian_metadata() {
        assert!(is_debian_metadata_path("Release"));
        assert!(is_debian_metadata_path("Packages.xz"));
        assert!(is_debian_metadata_path("Sources.gz"));
        assert!(!is_debian_metadata_path(
            "pool/main/n/nginx/nginx_1.0_amd64.deb"
        ));
    }
    #[test]
    fn test_flat_sync_index_filters_package_architectures() {
        assert!(package_matches_sync_index(
            "amd64",
            "",
            &["amd64".to_string()]
        ));
        assert!(package_matches_sync_index(
            "all",
            "",
            &["amd64".to_string()]
        ));
        assert!(!package_matches_sync_index(
            "arm64",
            "",
            &["amd64".to_string()]
        ));
    }
    #[test]
    fn test_architecture_all_matches_selected_indexes() {
        assert!(package_matches_sync_architecture(
            "all",
            &["amd64".to_string()]
        ));
        assert!(package_matches_sync_architecture(
            "amd64",
            &["amd64".to_string()]
        ));
        assert!(!package_matches_sync_architecture(
            "arm64",
            &["amd64".to_string()]
        ));
    }

    fn packages_entry(
        package: &str,
        version: &str,
        architecture: &str,
        filename: &str,
    ) -> PackagesEntry {
        PackagesEntry {
            control: DebControl {
                package: package.to_string(),
                version: version.to_string(),
                architecture: architecture.to_string(),
                ..Default::default()
            },
            filename: Some(filename.to_string()),
            size: Some(128),
            md5sum: None,
            sha1: None,
            sha256: Some("sha256".to_string()),
        }
    }

    #[test]
    fn test_build_debian_sync_plan_filters_indexes_and_package_files() {
        let release = parse_release("Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64 arm64\nComponents: main universe\nSHA256:\n a 1 main/binary-amd64/Packages.xz\n b 1 main/binary-arm64/Packages.xz\n c 1 universe/binary-amd64/Packages.xz\n").unwrap();
        let filter = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string(), "arm64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };
        let mut packages_by_index_path = BTreeMap::new();
        packages_by_index_path.insert(
            "main/binary-amd64/Packages.xz".to_string(),
            vec![
                packages_entry(
                    "nginx",
                    "1.0",
                    "amd64",
                    "pool/main/n/nginx/nginx_1.0_amd64.deb",
                ),
                packages_entry("docs", "1.0", "all", "pool/main/d/docs/docs_1.0_all.deb"),
                packages_entry("bad", "1.0", "arm64", "pool/main/b/bad/bad_1.0_arm64.deb"),
            ],
        );
        packages_by_index_path.insert(
            "main/binary-arm64/Packages.xz".to_string(),
            vec![
                packages_entry(
                    "nginx",
                    "1.0",
                    "arm64",
                    "pool/main/n/nginx/nginx_1.0_arm64.deb",
                ),
                packages_entry("docs", "1.0", "all", "pool/main/d/docs/docs_1.0_all.deb"),
            ],
        );

        let plan = build_debian_sync_plan(
            "jammy",
            &release,
            &filter,
            &packages_by_index_path,
            &BTreeMap::new(),
            DebianSyncDownloadPolicy::OnDemand,
        );

        assert_eq!(
            plan.release_paths,
            vec![
                "dists/jammy/InRelease".to_string(),
                "dists/jammy/Release".to_string(),
                "dists/jammy/Release.gpg".to_string(),
            ]
        );
        assert_eq!(plan.package_indexes.len(), 2);
        assert!(plan.missing_package_indexes.is_empty());
        assert_eq!(plan.package_files.len(), 4);
        assert!(plan.package_files.iter().all(|file| !file.download));
        assert!(plan.package_files.iter().any(|file| {
            file.index_path == "main/binary-amd64/Packages.xz"
                && file.package == "docs"
                && file.architecture == "all"
        }));
        assert!(plan.package_files.iter().any(|file| {
            file.index_path == "main/binary-arm64/Packages.xz"
                && file.package == "docs"
                && file.architecture == "all"
        }));
        assert!(!plan.package_files.iter().any(|file| file.package == "bad"));
    }

    #[test]
    fn test_build_debian_sync_plan_includes_source_files_when_enabled() {
        let release = parse_release("Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\nSHA256:\n a 1 main/binary-amd64/Packages.xz\n b 1 main/source/Sources.xz\n").unwrap();
        let filter = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: true,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };
        let packages_by_index_path = BTreeMap::new();
        let mut sources_by_index_path = BTreeMap::new();
        sources_by_index_path.insert(
            "main/source/Sources.xz".to_string(),
            vec![SourcesEntry {
                package: "nginx".to_string(),
                version: "1.0-1".to_string(),
                directory: "pool/main/n/nginx".to_string(),
                files: vec![SourceFileEntry {
                    filename: "nginx_1.0-1.dsc".to_string(),
                    size: 11,
                    md5sum: Some("md5dsc".to_string()),
                    sha1: None,
                    sha256: Some("sha256dsc".to_string()),
                    sha512: None,
                }],
                extra: BTreeMap::new(),
            }],
        );

        let plan = build_debian_sync_plan(
            "jammy",
            &release,
            &filter,
            &packages_by_index_path,
            &sources_by_index_path,
            DebianSyncDownloadPolicy::Immediate,
        );

        assert_eq!(plan.source_indexes.len(), 1);
        assert_eq!(
            plan.missing_package_indexes,
            vec!["main/binary-amd64/Packages.xz".to_string()]
        );
        assert!(plan.missing_source_indexes.is_empty());
        assert_eq!(plan.source_files.len(), 1);
        assert_eq!(
            plan.source_files[0].filename,
            "pool/main/n/nginx/nginx_1.0-1.dsc"
        );
        assert!(plan.source_files[0].download);
    }
    #[test]
    fn test_build_debian_sync_plan_marks_immediate_downloads_and_missing_indexes() {
        let release = parse_release("Suite: bookworm\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\nSHA256:\n a 1 main/binary-amd64/Packages.gz\n").unwrap();
        let filter = DebianSyncFilter {
            distributions: vec!["bookworm".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };
        let packages_by_index_path = BTreeMap::new();

        let plan = build_debian_sync_plan(
            "bookworm",
            &release,
            &filter,
            &packages_by_index_path,
            &BTreeMap::new(),
            DebianSyncDownloadPolicy::from_label(Some("immediate")),
        );

        assert_eq!(
            plan.missing_package_indexes,
            vec!["main/binary-amd64/Packages.gz".to_string()]
        );
        assert!(plan.package_files.is_empty());
        assert_eq!(
            DebianSyncDownloadPolicy::from_label(Some("on_demand")),
            DebianSyncDownloadPolicy::OnDemand
        );
        assert_eq!(
            DebianSyncDownloadPolicy::from_label(Some("full-mirror")),
            DebianSyncDownloadPolicy::Immediate
        );
    }

    #[test]
    fn test_debian_cache_decision_logic() {
        assert_eq!(
            decide_debian_cache_action(DebianCacheDecisionInput {
                path: "pool/main/n/nginx/nginx_1.0_amd64.deb",
                upstream_success: true,
                cached_locally: true,
                cache_stale: false,
                checksum_matches: true,
            }),
            DebianCacheAction::ServeCached
        );
        assert_eq!(
            decide_debian_cache_action(DebianCacheDecisionInput {
                path: "dists/jammy/Release",
                upstream_success: true,
                cached_locally: true,
                cache_stale: true,
                checksum_matches: false,
            }),
            DebianCacheAction::Revalidate
        );
        assert_eq!(
            decide_debian_cache_action(DebianCacheDecisionInput {
                path: "dists/jammy/main/binary-amd64/Packages.gz",
                upstream_success: true,
                cached_locally: true,
                cache_stale: false,
                checksum_matches: false,
            }),
            DebianCacheAction::ServeCached
        );
        assert_eq!(
            decide_debian_cache_action(DebianCacheDecisionInput {
                path: "dists/jammy/Release",
                upstream_success: false,
                cached_locally: false,
                cache_stale: false,
                checksum_matches: false,
            }),
            DebianCacheAction::DoNotCache
        );
    }

    #[test]
    fn test_malformed_release_returns_error() {
        assert!(parse_release("Suite: jammy\n").is_err());
    }

    // ========================================================================
    // DebianHandler::new / Default tests
    // ========================================================================

    #[test]
    fn test_debian_handler_new() {
        let _handler = DebianHandler::new();
    }

    #[test]
    fn test_debian_handler_default() {
        let _handler = DebianHandler;
    }

    #[test]
    fn test_decode_debian_index_rejects_oversized_plain_text() {
        let oversized = vec![b'a'; (MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES as usize) + 1];
        let err = decode_debian_index_text("Packages", &oversized, "Packages").unwrap_err();
        assert!(err.to_string().contains("exceeds maximum allowed size"));
    }

    #[test]
    fn test_decode_debian_index_rejects_oversized_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let oversized = vec![b'A'; (MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES as usize) + 1024];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&oversized).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < (MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES / 16) as usize);

        let err = decode_debian_index_text("Packages.gz", &compressed, "Packages").unwrap_err();
        assert!(err.to_string().contains("exceeds maximum allowed size"));
    }

    #[test]
    fn test_decode_debian_index_bz2_and_zst() {
        use std::io::Write;

        let plaintext = "Package: nginx\nVersion: 1.0\nArchitecture: amd64\n";

        let mut bz2_encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        bz2_encoder.write_all(plaintext.as_bytes()).unwrap();
        let bz2_bytes = bz2_encoder.finish().unwrap();
        let bz2_text = decode_debian_index_text("Packages.bz2", &bz2_bytes, "Packages").unwrap();
        assert_eq!(bz2_text, plaintext);

        let zst_bytes = zstd::stream::encode_all(plaintext.as_bytes(), 1).unwrap();
        let zst_text = decode_debian_index_text("Packages.zst", &zst_bytes, "Packages").unwrap();
        assert_eq!(zst_text, plaintext);

        let zstd_text = decode_debian_index_text("Packages.zstd", &zst_bytes, "Packages").unwrap();
        assert_eq!(zstd_text, plaintext);
    }

    #[test]
    fn test_package_name_matches_queries_exact_and_glob() {
        assert!(package_name_matches_queries("nginx", &[]));
        assert!(package_name_matches_queries(
            "nginx",
            &["nginx".to_string()]
        ));
        assert!(package_name_matches_queries("nginx", &["ngi*".to_string()]));
        assert!(!package_name_matches_queries(
            "nginx",
            &["apache*".to_string()]
        ));
        assert!(package_name_matches_queries(
            "libc6 (>= 2.28)",
            &["libc6".to_string()]
        ));
        assert_eq!(
            parse_debian_dependency_package_name("vim | neovim (>= 0.5)"),
            "vim"
        );
        assert_eq!(
            parse_debian_dependency_package_name("libc6 (>= 2.28)"),
            "libc6"
        );
    }

    #[test]
    fn test_filter_packages_by_query_with_dependency_resolution() {
        let nginx = PackagesEntry {
            control: DebControl {
                package: "nginx".to_string(),
                version: "1.0".to_string(),
                architecture: "amd64".to_string(),
                depends: Some(vec![
                    "libc6 (>= 2.28)".to_string(),
                    "virtual-ssl".to_string(),
                ]),
                ..Default::default()
            },
            filename: Some("pool/main/n/nginx/nginx_1.0_amd64.deb".to_string()),
            size: Some(10),
            md5sum: None,
            sha1: None,
            sha256: None,
        };
        let libc6 = PackagesEntry {
            control: DebControl {
                package: "libc6".to_string(),
                version: "2.36".to_string(),
                architecture: "amd64".to_string(),
                ..Default::default()
            },
            filename: Some("pool/main/g/glibc/libc6_2.36_amd64.deb".to_string()),
            size: Some(10),
            md5sum: None,
            sha1: None,
            sha256: None,
        };
        let libssl = PackagesEntry {
            control: DebControl {
                package: "libssl3".to_string(),
                version: "3.0".to_string(),
                architecture: "amd64".to_string(),
                provides: Some(vec!["virtual-ssl".to_string()]),
                ..Default::default()
            },
            filename: Some("pool/main/o/openssl/libssl3_3.0_amd64.deb".to_string()),
            size: Some(10),
            md5sum: None,
            sha1: None,
            sha256: None,
        };
        let unrelated = packages_entry(
            "curl",
            "1.0",
            "amd64",
            "pool/main/c/curl/curl_1.0_amd64.deb",
        );
        let entries = vec![nginx, libc6, libssl, unrelated];

        let matched =
            filter_packages_by_query_with_dependencies(&entries, &["nginx".to_string()], false);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].control.package, "nginx");

        let with_deps =
            filter_packages_by_query_with_dependencies(&entries, &["nginx".to_string()], true);
        let names: BTreeSet<_> = with_deps
            .iter()
            .map(|entry| entry.control.package.as_str())
            .collect();
        assert_eq!(names, BTreeSet::from(["nginx", "libc6", "libssl3"]));

        let globbed =
            filter_packages_by_query_with_dependencies(&entries, &["lib*".to_string()], false);
        assert_eq!(globbed.len(), 2);
    }

    #[test]
    fn test_build_debian_sync_plan_applies_package_queries_and_deps() {
        let release = parse_release("Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\nSHA256:\n a 1 main/binary-amd64/Packages.xz\n").unwrap();
        let mut packages_by_index_path = BTreeMap::new();
        packages_by_index_path.insert(
            "main/binary-amd64/Packages.xz".to_string(),
            vec![
                PackagesEntry {
                    control: DebControl {
                        package: "nginx".to_string(),
                        version: "1.0".to_string(),
                        architecture: "amd64".to_string(),
                        depends: Some(vec!["libc6".to_string()]),
                        ..Default::default()
                    },
                    filename: Some("pool/main/n/nginx/nginx_1.0_amd64.deb".to_string()),
                    size: Some(10),
                    md5sum: None,
                    sha1: None,
                    sha256: None,
                },
                packages_entry(
                    "libc6",
                    "2.36",
                    "amd64",
                    "pool/main/g/glibc/libc6_2.36_amd64.deb",
                ),
                packages_entry(
                    "curl",
                    "1.0",
                    "amd64",
                    "pool/main/c/curl/curl_1.0_amd64.deb",
                ),
            ],
        );

        let matched_only = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: vec!["nginx".to_string()],
            resolve_dependencies: false,
        };
        let plan_matched = build_debian_sync_plan(
            "jammy",
            &release,
            &matched_only,
            &packages_by_index_path,
            &BTreeMap::new(),
            DebianSyncDownloadPolicy::OnDemand,
        );
        let matched_names: BTreeSet<_> = plan_matched
            .package_files
            .iter()
            .map(|file| file.package.as_str())
            .collect();
        assert_eq!(
            matched_names,
            BTreeSet::from(["nginx"]),
            "package_queries without resolve_dependencies must select only matching packages"
        );

        let with_deps = DebianSyncFilter {
            resolve_dependencies: true,
            ..matched_only
        };
        let plan = build_debian_sync_plan(
            "jammy",
            &release,
            &with_deps,
            &packages_by_index_path,
            &BTreeMap::new(),
            DebianSyncDownloadPolicy::OnDemand,
        );
        let names: BTreeSet<_> = plan
            .package_files
            .iter()
            .map(|file| file.package.as_str())
            .collect();
        assert_eq!(names, BTreeSet::from(["nginx", "libc6"]));
    }

    #[test]
    fn test_release_path_allowed_by_filter() {
        let filter = DebianSyncFilter {
            distributions: vec!["jammy".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: true,
            package_queries: Vec::new(),
            resolve_dependencies: false,
        };

        assert!(release_path_allowed_by_filter(
            "main/binary-amd64/Packages.xz",
            &filter
        ));
        assert!(!release_path_allowed_by_filter(
            "main/binary-arm64/Packages.xz",
            &filter
        ));
        assert!(!release_path_allowed_by_filter(
            "universe/binary-amd64/Packages.xz",
            &filter
        ));
        assert!(release_path_allowed_by_filter(
            "main/source/Sources.gz",
            &filter
        ));
        assert!(release_path_allowed_by_filter(
            "main/Contents-amd64.gz",
            &filter
        ));
        assert!(!release_path_allowed_by_filter(
            "main/Contents-arm64.gz",
            &filter
        ));
        assert!(release_path_allowed_by_filter("Contents-amd64", &filter));
        assert!(!release_path_allowed_by_filter("Contents-arm64", &filter));
        assert!(release_path_allowed_by_filter(
            "main/i18n/Translation-en.bz2",
            &filter
        ));
        assert!(!release_path_allowed_by_filter(
            "universe/i18n/Translation-en.bz2",
            &filter
        ));
        assert!(release_path_allowed_by_filter(
            "main/dep11/Components-amd64.yml.gz",
            &filter
        ));
        assert!(release_path_allowed_by_filter(
            "main/by-hash/SHA256/abc",
            &filter
        ));
        assert!(!release_path_allowed_by_filter(
            "universe/by-hash/SHA256/abc",
            &filter
        ));
        assert!(!release_path_allowed_by_filter("", &filter));
        assert!(!release_path_allowed_by_filter("README", &filter));

        let no_source = DebianSyncFilter {
            include_source_packages: false,
            ..filter.clone()
        };
        assert!(!release_path_allowed_by_filter(
            "main/source/Sources.xz",
            &no_source
        ));
    }

    #[test]
    fn test_pool_path_allowed_by_filters() {
        let filter = DebianSyncFilter {
            distributions: Vec::new(),
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: vec!["nginx*".to_string()],
            resolve_dependencies: false,
        };

        assert!(pool_path_allowed_by_filters(
            "main",
            "nginx_1.0_amd64.deb",
            &filter
        ));
        assert!(pool_path_allowed_by_filters(
            "main",
            "nginx-common_1.0_all.deb",
            &filter
        ));
        assert!(!pool_path_allowed_by_filters(
            "main",
            "nginx_1.0_arm64.deb",
            &filter
        ));
        assert!(!pool_path_allowed_by_filters(
            "universe",
            "nginx_1.0_amd64.deb",
            &filter
        ));
        assert!(!pool_path_allowed_by_filters(
            "main",
            "curl_1.0_amd64.deb",
            &filter
        ));
        assert!(
            !pool_path_allowed_by_filters("main", "not-a-deb-filename", &filter),
            "unparseable filenames must be rejected"
        );
    }

    #[test]
    fn test_validate_debian_fetch_path_and_flat_package_path() {
        assert!(validate_debian_fetch_path("pool/main/n/nginx/nginx_1.0_amd64.deb").is_ok());
        assert!(validate_debian_fetch_path("nginx_1.0_amd64.deb").is_ok());
        assert!(validate_debian_fetch_path("").is_err());
        assert!(validate_debian_fetch_path("https://evil.example/pkg.deb").is_err());
        assert!(validate_debian_fetch_path("http://evil.example/pkg.deb").is_err());
        assert!(validate_debian_fetch_path("pool/../etc/passwd").is_err());
        assert!(validate_debian_fetch_path("../etc/passwd").is_err());
        assert!(validate_debian_fetch_path("pool/main/../../etc/passwd").is_err());

        assert!(is_flat_repository_package_path("nginx_1.0_amd64.deb"));
        assert!(is_flat_repository_package_path("pkgs/nginx_1.0_amd64.udeb"));
        assert!(!is_flat_repository_package_path(
            "pool/main/n/nginx/nginx_1.0_amd64.deb"
        ));
        assert!(!is_flat_repository_package_path("Release"));
    }

    #[test]
    fn test_debian_promotion_target_path_keeps_pool_layout() {
        assert_eq!(
            debian_promotion_target_path("pool/main/n/nginx/nginx_1.0_amd64.deb"),
            "pool/main/n/nginx/nginx_1.0_amd64.deb"
        );
        assert_eq!(
            debian_promotion_target_path("pool/debian-installer/m/module/module_1_amd64.udeb"),
            "pool/debian-installer/m/module/module_1_amd64.udeb"
        );
        assert_eq!(
            debian_promotion_target_path("nginx_1.0_amd64.deb"),
            "nginx_1.0_amd64.deb"
        );
    }

    #[test]
    fn test_debian_pool_path_still_referenced() {
        let packages = vec![
            "Package: nginx\nFilename: pool/main/n/nginx/nginx_1.0_amd64.deb\n\n".to_string(),
            "Package: curl\nFilename: pool/main/c/curl/curl_1.0_amd64.deb\n\n".to_string(),
        ];
        assert!(debian_pool_path_still_referenced(
            &packages,
            "pool/main/n/nginx/nginx_1.0_amd64.deb"
        ));
        assert!(debian_pool_path_still_referenced(
            &packages,
            "  pool/main/n/nginx/nginx_1.0_amd64.deb  "
        ));
        assert!(!debian_pool_path_still_referenced(
            &packages,
            "pool/main/v/vim/vim_1.0_amd64.deb"
        ));
        assert!(!debian_pool_path_still_referenced(&packages, ""));
        assert!(!debian_pool_path_still_referenced(&packages, "   "));
        assert!(!debian_pool_path_still_referenced(
            &[],
            "pool/main/n/nginx/nginx_1.0_amd64.deb"
        ));
        // Filename value must match exactly after trim — substring matches do not count.
        assert!(!debian_pool_path_still_referenced(
            &packages,
            "nginx_1.0_amd64.deb"
        ));
    }

    #[test]
    fn test_build_contents_index_and_by_hash_path() {
        let index = build_contents_index(&[
            ("usr/bin/nginx".to_string(), "nginx".to_string()),
            ("bin/bash".to_string(), "bash".to_string()),
        ]);
        assert_eq!(index, "bin/bash\tbash\nusr/bin/nginx\tnginx\n");
        assert_eq!(
            by_hash_path("SHA256", "deadbeef"),
            "by-hash/SHA256/deadbeef"
        );
    }

    // -----------------------------------------------------------------------
    // Fix 3: Cross-index dependency closure
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_debian_sync_plan_cross_index_dep_closure() {
        // nginx (in main/amd64) depends on libssl3 which is ONLY in security/amd64.
        // When resolve_dependencies=true, libssl3 must be pulled into the plan
        // even though it lives in a different index.
        let release = parse_release(
            "Suite: bookworm\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main security\nSHA256:\n a 1 main/binary-amd64/Packages\n b 1 security/binary-amd64/Packages\n"
        ).unwrap();

        let nginx = PackagesEntry {
            control: DebControl {
                package: "nginx".to_string(),
                version: "1.0".to_string(),
                architecture: "amd64".to_string(),
                depends: Some(vec!["libssl3".to_string()]),
                ..Default::default()
            },
            filename: Some("pool/main/n/nginx/nginx_1.0_amd64.deb".to_string()),
            size: Some(10),
            md5sum: None,
            sha1: None,
            sha256: None,
        };
        let libssl3 = PackagesEntry {
            control: DebControl {
                package: "libssl3".to_string(),
                version: "3.0.2".to_string(),
                architecture: "amd64".to_string(),
                ..Default::default()
            },
            filename: Some("pool/security/o/openssl/libssl3_3.0.2_amd64.deb".to_string()),
            size: Some(20),
            md5sum: None,
            sha1: None,
            sha256: None,
        };

        let mut packages_by_index_path = BTreeMap::new();
        packages_by_index_path.insert("main/binary-amd64/Packages".to_string(), vec![nginx]);
        packages_by_index_path.insert("security/binary-amd64/Packages".to_string(), vec![libssl3]);

        let filter = DebianSyncFilter {
            distributions: vec!["bookworm".to_string()],
            components: vec!["main".to_string(), "security".to_string()],
            architectures: vec!["amd64".to_string()],
            include_source_packages: false,
            package_queries: vec!["nginx".to_string()],
            resolve_dependencies: true,
        };
        let plan = build_debian_sync_plan(
            "bookworm",
            &release,
            &filter,
            &packages_by_index_path,
            &BTreeMap::new(),
            DebianSyncDownloadPolicy::OnDemand,
        );

        let filenames: BTreeSet<&str> = plan
            .package_files
            .iter()
            .map(|f| f.filename.as_str())
            .collect();
        assert!(
            filenames.contains("pool/main/n/nginx/nginx_1.0_amd64.deb"),
            "nginx must be selected"
        );
        assert!(
            filenames.contains("pool/security/o/openssl/libssl3_3.0.2_amd64.deb"),
            "libssl3 (dep from a different index) must be pulled in by cross-index closure"
        );
    }

    // -----------------------------------------------------------------------
    // Fix 4: Source artifacts allowed when include_source_packages
    // -----------------------------------------------------------------------

    #[test]
    fn test_pool_path_allowed_by_filters_source_artifacts() {
        let filter_with_sources = DebianSyncFilter {
            components: vec!["main".to_string()],
            include_source_packages: true,
            ..Default::default()
        };
        let filter_no_sources = DebianSyncFilter {
            components: vec!["main".to_string()],
            include_source_packages: false,
            ..Default::default()
        };

        // Source artifacts must be allowed when include_source_packages=true.
        assert!(pool_path_allowed_by_filters(
            "main",
            "nginx_1.24.0.orig.tar.gz",
            &filter_with_sources
        ));
        assert!(pool_path_allowed_by_filters(
            "main",
            "nginx_1.24.0-1.debian.tar.xz",
            &filter_with_sources
        ));
        assert!(pool_path_allowed_by_filters(
            "main",
            "nginx_1.24.0-1.dsc",
            &filter_with_sources
        ));
        assert!(pool_path_allowed_by_filters(
            "main",
            "nginx_1.24.0-1.diff.gz",
            &filter_with_sources
        ));

        // Source artifacts must be rejected when include_source_packages=false.
        assert!(!pool_path_allowed_by_filters(
            "main",
            "nginx_1.24.0.orig.tar.gz",
            &filter_no_sources
        ));
        assert!(!pool_path_allowed_by_filters(
            "main",
            "nginx_1.24.0-1.dsc",
            &filter_no_sources
        ));

        // Binary .deb packages still follow normal logic.
        assert!(pool_path_allowed_by_filters(
            "main",
            "nginx_1.24.0-1_amd64.deb",
            &filter_with_sources
        ));

        // Component filter still applies to source artifacts.
        let wrong_component_filter = DebianSyncFilter {
            components: vec!["universe".to_string()],
            include_source_packages: true,
            ..Default::default()
        };
        assert!(!pool_path_allowed_by_filters(
            "main",
            "nginx_1.24.0-1.dsc",
            &wrong_component_filter
        ));
    }

    // -----------------------------------------------------------------------
    // Fix 6: Valid-Until parsing and expiry check
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_release_date_rfc2822_utc() {
        let dt = parse_release_date("Thu, 01 Jan 2026 00:00:00 UTC").unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
    }

    #[test]
    fn test_parse_release_date_rfc2822_numeric_tz() {
        let dt = parse_release_date("Thu, 01 Jan 2026 00:00:00 +0000").unwrap();
        assert_eq!(dt.year(), 2026);
    }

    #[test]
    fn test_parse_release_date_invalid_returns_none() {
        assert!(parse_release_date("not a date").is_none());
        assert!(parse_release_date("").is_none());
    }

    fn make_minimal_release(valid_until: Option<&str>) -> Release {
        Release {
            origin: None,
            label: None,
            suite: "jammy".to_string(),
            codename: None,
            version: None,
            date: "Mon, 01 Jan 2024 00:00:00 UTC".to_string(),
            valid_until: valid_until.map(str::to_string),
            architectures: vec!["amd64".to_string()],
            components: vec!["main".to_string()],
            description: None,
            md5sum: vec![],
            sha1: vec![],
            sha256: vec![],
            sha512: vec![],
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn test_release_is_expired_past_valid_until() {
        let release = make_minimal_release(Some("Mon, 01 Jan 2024 12:00:00 +0000"));
        let now_past = chrono::DateTime::parse_from_rfc3339("2024-01-02T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(
            release_is_expired(&release, now_past),
            "past Valid-Until must be expired"
        );
    }

    #[test]
    fn test_release_is_expired_future_valid_until() {
        let release = make_minimal_release(Some("Mon, 01 Jan 2099 12:00:00 +0000"));
        let now = chrono::Utc::now();
        assert!(
            !release_is_expired(&release, now),
            "future Valid-Until must not be expired"
        );
    }

    #[test]
    fn test_release_is_expired_no_valid_until() {
        let release = make_minimal_release(None);
        let now = chrono::Utc::now();
        assert!(
            !release_is_expired(&release, now),
            "no Valid-Until means never expired"
        );
    }

    #[test]
    fn test_parse_release_stores_valid_until() {
        let content = "Suite: jammy\nDate: Mon, 01 Jan 2024 00:00:00 UTC\nValid-Until: Mon, 08 Jan 2024 00:00:00 UTC\nArchitectures: amd64\nComponents: main\n";
        let release = parse_release(content).unwrap();
        assert_eq!(
            release.valid_until.as_deref(),
            Some("Mon, 08 Jan 2024 00:00:00 UTC")
        );
    }
}
