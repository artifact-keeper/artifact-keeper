//! Debian/APT format handler.
//!
//! Implements APT repository for Debian/Ubuntu packages.
//! Supports parsing .deb files and generating Packages/Release files.

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use tar::Archive;

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
    fn parse_deb_filename(filename: &str) -> Result<(String, String, String)> {
        let name = filename
            .trim_end_matches(".deb")
            .trim_end_matches(".udeb");
        let parts: Vec<&str> = name.split('_').collect();

        if parts.len() < 3 {
            return Err(AppError::Validation(format!(
                "Invalid Debian package filename: {}",
                filename
            )));
        }

        let package = parts[0].to_string();
        let version = parts[1].to_string();
        let arch = parts[2..].join("_"); // Handle arch like amd64 or all

        Ok((package, version, arch))
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
            return Err(AppError::Validation("Invalid .deb file: not an ar archive".to_string()));
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
                let data = &content[offset..offset + size];
                return Self::parse_control_tar(data, name.contains(".gz"), name.contains(".xz"));
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
    fn parse_control_tar(data: &[u8], is_gzip: bool, _is_xz: bool) -> Result<DebControl> {
        let reader: Box<dyn Read> = if is_gzip {
            Box::new(GzDecoder::new(data))
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
#[derive(Debug, Default, Serialize, Deserialize)]
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

    #[test]
    fn test_parse_deb_filename() {
        let (pkg, ver, arch) = DebianHandler::parse_deb_filename("nginx_1.24.0-1_amd64.deb").unwrap();
        assert_eq!(pkg, "nginx");
        assert_eq!(ver, "1.24.0-1");
        assert_eq!(arch, "amd64");
    }

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
    fn test_parse_path_packages() {
        let info = DebianHandler::parse_path("dists/jammy/main/binary-amd64/Packages.gz").unwrap();
        assert!(matches!(info.operation, DebianOperation::Packages));
        assert_eq!(info.distribution, Some("jammy".to_string()));
        assert_eq!(info.component, Some("main".to_string()));
        assert_eq!(info.arch, Some("amd64".to_string()));
    }

    #[test]
    fn test_get_pool_prefix() {
        assert_eq!(DebianHandler::get_pool_prefix("nginx"), "n");
        assert_eq!(DebianHandler::get_pool_prefix("libc6"), "libc");
        assert_eq!(DebianHandler::get_pool_prefix("libssl3"), "libs");
    }

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
}
