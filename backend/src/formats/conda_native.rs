//! Conda native format handler.
//!
//! Implements native Conda channel repository support.
//! Handles .conda and .tar.bz2 packages with repodata.json index generation.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Conda native format handler
pub struct CondaNativeHandler;

impl CondaNativeHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Conda channel path.
    ///
    /// Formats:
    ///   `<subdir>/repodata.json`              - Channel index
    ///   `<subdir>/repodata.json.bz2`          - Compressed channel index
    ///   `<subdir>/<name>-<version>-<build>.conda`    - v2 package
    ///   `<subdir>/<name>-<version>-<build>.tar.bz2`  - v1 package
    ///   `channeldata.json`                    - Channel metadata
    pub fn parse_path(path: &str) -> Result<CondaPathInfo> {
        let path = path.trim_start_matches('/');

        if path == "channeldata.json" {
            return Ok(CondaPathInfo {
                subdir: None,
                name: None,
                version: None,
                build: None,
                is_index: true,
                package_format: None,
            });
        }

        let parts: Vec<&str> = path.splitn(2, '/').collect();
        match parts.as_slice() {
            [subdir, filename] => {
                if *filename == "repodata.json" || *filename == "repodata.json.bz2" {
                    return Ok(CondaPathInfo {
                        subdir: Some(subdir.to_string()),
                        name: None,
                        version: None,
                        build: None,
                        is_index: true,
                        package_format: None,
                    });
                }

                let (stem, fmt) = if filename.ends_with(".conda") {
                    (filename.trim_end_matches(".conda"), CondaPackageFormat::V2)
                } else if filename.ends_with(".tar.bz2") {
                    (
                        filename.trim_end_matches(".tar.bz2"),
                        CondaPackageFormat::V1,
                    )
                } else {
                    return Err(AppError::Validation(format!(
                        "Invalid Conda package: {}",
                        filename
                    )));
                };

                let (name, version, build) = Self::parse_conda_filename(stem)?;
                Ok(CondaPathInfo {
                    subdir: Some(subdir.to_string()),
                    name: Some(name),
                    version: Some(version),
                    build: Some(build),
                    is_index: false,
                    package_format: Some(fmt),
                })
            }
            _ => Err(AppError::Validation(format!(
                "Invalid Conda path: {}",
                path
            ))),
        }
    }

    /// Parse Conda package filename: `<name>-<version>-<build_string>`
    fn parse_conda_filename(stem: &str) -> Result<(String, String, String)> {
        // Split from the right: build is last, version is second-to-last
        let parts: Vec<&str> = stem.rsplitn(3, '-').collect();
        if parts.len() != 3 {
            return Err(AppError::Validation(format!(
                "Invalid Conda package filename: {}",
                stem
            )));
        }
        // rsplitn reverses order
        let build = parts[0].to_string();
        let version = parts[1].to_string();
        let name = parts[2].to_string();

        Ok((name, version, build))
    }
}

impl Default for CondaNativeHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for CondaNativeHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::CondaNative
    }

    fn format_key(&self) -> &str {
        "conda_native"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "is_index": info.is_index,
        });

        if let Some(subdir) = &info.subdir {
            metadata["subdir"] = serde_json::Value::String(subdir.clone());
        }
        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }
        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }
        if let Some(build) = &info.build {
            metadata["build"] = serde_json::Value::String(build.clone());
        }
        if let Some(fmt) = &info.package_format {
            metadata["package_format"] = serde_json::Value::String(match fmt {
                CondaPackageFormat::V1 => "v1".to_string(),
                CondaPackageFormat::V2 => "v2".to_string(),
            });
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // repodata.json is generated on demand from DB state
        Ok(None)
    }
}

/// Conda path info
#[derive(Debug)]
pub struct CondaPathInfo {
    pub subdir: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub build: Option<String>,
    pub is_index: bool,
    pub package_format: Option<CondaPackageFormat>,
}

/// Conda package format version
#[derive(Debug, Clone)]
pub enum CondaPackageFormat {
    V1, // .tar.bz2
    V2, // .conda
}

/// Conda repodata.json structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Repodata {
    pub info: RepodataInfo,
    #[serde(default)]
    pub packages: serde_json::Map<String, serde_json::Value>,
    #[serde(default, rename = "packages.conda")]
    pub packages_conda: serde_json::Map<String, serde_json::Value>,
}

/// Repodata info section
#[derive(Debug, Serialize, Deserialize)]
pub struct RepodataInfo {
    pub subdir: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_conda_v2_package() {
        let info =
            CondaNativeHandler::parse_path("linux-64/numpy-1.26.4-py312h02b7e37_0.conda").unwrap();
        assert_eq!(info.subdir, Some("linux-64".to_string()));
        assert_eq!(info.name, Some("numpy".to_string()));
        assert_eq!(info.version, Some("1.26.4".to_string()));
        assert_eq!(info.build, Some("py312h02b7e37_0".to_string()));
        assert!(!info.is_index);
    }

    #[test]
    fn test_parse_conda_v1_package() {
        let info =
            CondaNativeHandler::parse_path("noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2").unwrap();
        assert_eq!(info.subdir, Some("noarch".to_string()));
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.31.0".to_string()));
        assert!(!info.is_index);
    }

    #[test]
    fn test_parse_repodata_path() {
        let info = CondaNativeHandler::parse_path("linux-64/repodata.json").unwrap();
        assert!(info.is_index);
        assert_eq!(info.subdir, Some("linux-64".to_string()));
    }

    #[test]
    fn test_parse_channeldata() {
        let info = CondaNativeHandler::parse_path("channeldata.json").unwrap();
        assert!(info.is_index);
        assert!(info.subdir.is_none());
    }
}
