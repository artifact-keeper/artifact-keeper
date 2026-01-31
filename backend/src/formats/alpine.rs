//! Alpine APK format handler.
//!
//! Implements Alpine Linux APK package repository support.
//! APK packages are tar.gz archives containing PKGINFO metadata.

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::io::Read;
use tar::Archive;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Alpine APK format handler
pub struct AlpineHandler;

impl AlpineHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse APK package path.
    ///
    /// Formats:
    ///   `<arch>/APKINDEX.tar.gz`           - Repository index
    ///   `<arch>/<name>-<version>.apk`      - Package file
    pub fn parse_path(path: &str) -> Result<AlpinePathInfo> {
        let path = path.trim_start_matches('/');
        let parts: Vec<&str> = path.splitn(2, '/').collect();

        match parts.as_slice() {
            [arch, filename] if *filename == "APKINDEX.tar.gz" => Ok(AlpinePathInfo {
                arch: arch.to_string(),
                name: None,
                version: None,
                is_index: true,
            }),
            [arch, filename] if filename.ends_with(".apk") => {
                let stem = filename.trim_end_matches(".apk");
                // APK filename: <name>-<version>-r<revision>.apk
                // Version can contain dots and hyphens; find the pattern
                let (name, version) = Self::parse_apk_filename(stem)?;
                Ok(AlpinePathInfo {
                    arch: arch.to_string(),
                    name: Some(name),
                    version: Some(version),
                    is_index: false,
                })
            }
            _ => Err(AppError::Validation(format!("Invalid APK path: {}", path))),
        }
    }

    /// Parse APK filename to extract name and version.
    /// Format: `<name>-<version>-r<revision>`
    fn parse_apk_filename(stem: &str) -> Result<(String, String)> {
        // Find version boundary: first hyphen followed by a digit
        let mut split_idx = None;
        let chars: Vec<char> = stem.chars().collect();
        for i in 1..chars.len() {
            if chars[i - 1] == '-' && chars[i].is_ascii_digit() {
                split_idx = Some(i - 1);
                break;
            }
        }

        match split_idx {
            Some(idx) => {
                let name = &stem[..idx];
                let version = &stem[idx + 1..];
                Ok((name.to_string(), version.to_string()))
            }
            None => Err(AppError::Validation(format!(
                "Cannot parse APK filename: {}",
                stem
            ))),
        }
    }

    /// Extract PKGINFO from an APK package.
    pub fn extract_pkginfo(content: &[u8]) -> Result<PkgInfo> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid APK package: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid APK entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in APK: {}", e)))?;

            if path.to_string_lossy() == ".PKGINFO" {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read .PKGINFO: {}", e)))?;
                return Self::parse_pkginfo(&content);
            }
        }

        Err(AppError::Validation(
            ".PKGINFO not found in APK package".to_string(),
        ))
    }

    /// Parse PKGINFO key=value format.
    fn parse_pkginfo(content: &str) -> Result<PkgInfo> {
        let mut info = PkgInfo::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(" = ") {
                match key {
                    "pkgname" => info.pkgname = value.to_string(),
                    "pkgver" => info.pkgver = value.to_string(),
                    "pkgdesc" => info.pkgdesc = Some(value.to_string()),
                    "url" => info.url = Some(value.to_string()),
                    "size" => info.size = value.parse().ok(),
                    "arch" => info.arch = value.to_string(),
                    "license" => info.license = Some(value.to_string()),
                    "origin" => info.origin = Some(value.to_string()),
                    "depend" => info.depends.push(value.to_string()),
                    "provides" => info.provides.push(value.to_string()),
                    _ => {}
                }
            }
        }

        if info.pkgname.is_empty() {
            return Err(AppError::Validation("PKGINFO missing pkgname".to_string()));
        }

        Ok(info)
    }
}

impl Default for AlpineHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for AlpineHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Alpine
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "arch": info.arch,
            "is_index": info.is_index,
        });

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }
        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        if !content.is_empty() && !info.is_index {
            if let Ok(pkginfo) = Self::extract_pkginfo(content) {
                metadata["pkginfo"] = serde_json::to_value(&pkginfo)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // APKINDEX is generated on demand from DB state
        Ok(None)
    }
}

/// Alpine package path info
#[derive(Debug)]
pub struct AlpinePathInfo {
    pub arch: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub is_index: bool,
}

/// Parsed .PKGINFO content
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PkgInfo {
    pub pkgname: String,
    pub pkgver: String,
    pub pkgdesc: Option<String>,
    pub url: Option<String>,
    pub size: Option<u64>,
    pub arch: String,
    pub license: Option<String>,
    pub origin: Option<String>,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_apk_path() {
        let info = AlpineHandler::parse_path("x86_64/curl-8.5.0-r0.apk").unwrap();
        assert_eq!(info.arch, "x86_64");
        assert_eq!(info.name, Some("curl".to_string()));
        assert_eq!(info.version, Some("8.5.0-r0".to_string()));
        assert!(!info.is_index);
    }

    #[test]
    fn test_parse_apk_index_path() {
        let info = AlpineHandler::parse_path("x86_64/APKINDEX.tar.gz").unwrap();
        assert_eq!(info.arch, "x86_64");
        assert!(info.is_index);
    }

    #[test]
    fn test_parse_pkginfo() {
        let content = r#"pkgname = curl
pkgver = 8.5.0-r0
pkgdesc = URL retrieval utility and library
url = https://curl.se/
arch = x86_64
license = MIT
depend = libcurl
depend = ca-certificates
provides = cmd:curl"#;
        let info = AlpineHandler::parse_pkginfo(content).unwrap();
        assert_eq!(info.pkgname, "curl");
        assert_eq!(info.pkgver, "8.5.0-r0");
        assert_eq!(info.depends.len(), 2);
        assert_eq!(info.provides.len(), 1);
    }
}
