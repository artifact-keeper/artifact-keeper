//! Debian/APT format handler.
//!
//! Implements APT repository for Debian/Ubuntu packages.
//! Supports parsing .deb files and generating Packages/Release files.

use async_trait::async_trait;
use bytes::Bytes;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use tar::Archive;
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    pub architectures: Vec<String>,
    pub components: Vec<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub md5sum: Vec<ReleaseHash>,
    #[serde(default)]
    pub sha256: Vec<ReleaseHash>,
}

/// Release file hash entry
#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseHash {
    pub hash: String,
    pub size: u64,
    pub path: String,
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

    entry.push_str(&format!("Package: {}\n", control.package));
    entry.push_str(&format!("Version: {}\n", control.version));
    entry.push_str(&format!("Architecture: {}\n", control.architecture));

    if let Some(maintainer) = &control.maintainer {
        entry.push_str(&format!("Maintainer: {}\n", maintainer));
    }

    if let Some(size) = control.installed_size {
        entry.push_str(&format!("Installed-Size: {}\n", size));
    }

    if let Some(depends) = &control.depends {
        if !depends.is_empty() {
            entry.push_str(&format!("Depends: {}\n", depends.join(", ")));
        }
    }

    if let Some(section) = &control.section {
        entry.push_str(&format!("Section: {}\n", section));
    }

    if let Some(priority) = &control.priority {
        entry.push_str(&format!("Priority: {}\n", priority));
    }

    if let Some(homepage) = &control.homepage {
        entry.push_str(&format!("Homepage: {}\n", homepage));
    }

    if let Some(description) = &control.description {
        entry.push_str(&format!("Description: {}\n", description));
    }

    entry.push_str(&format!("Filename: {}\n", filename));
    entry.push_str(&format!("Size: {}\n", size));
    entry.push_str(&format!("MD5sum: {}\n", md5sum));
    entry.push_str(&format!("SHA256: {}\n", sha256));

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
}
