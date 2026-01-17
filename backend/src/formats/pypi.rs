//! PyPI format handler.
//!
//! Implements PEP 503 Simple Repository API for Python packages.
//! Supports wheel (.whl) and source distribution (.tar.gz) files.

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

/// PyPI format handler
pub struct PypiHandler;

impl PypiHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse PyPI package path
    /// Formats:
    ///   simple/<package>/                    - Package index
    ///   simple/                              - Root index
    ///   packages/<package>/<version>/<filename> - Package file
    ///   <package>/<filename>                 - Direct package file
    pub fn parse_path(path: &str) -> Result<PypiPackageInfo> {
        let path = path.trim_start_matches('/');

        // Root simple index
        if path == "simple" || path == "simple/" {
            return Ok(PypiPackageInfo {
                name: None,
                version: None,
                filename: None,
                is_simple_index: true,
                is_package_index: false,
            });
        }

        // Package simple index: simple/<package>/
        if path.starts_with("simple/") {
            let rest = &path[7..];
            let parts: Vec<&str> = rest.trim_end_matches('/').split('/').collect();
            if parts.len() == 1 && !parts[0].is_empty() {
                return Ok(PypiPackageInfo {
                    name: Some(Self::normalize_name(parts[0])),
                    version: None,
                    filename: None,
                    is_simple_index: false,
                    is_package_index: true,
                });
            }
        }

        // Package file: packages/<package>/<version>/<filename>
        if path.starts_with("packages/") {
            let rest = &path[9..];
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 3 {
                let name = Self::normalize_name(parts[0]);
                let version = parts[1].to_string();
                let filename = parts[2..].join("/");
                return Ok(PypiPackageInfo {
                    name: Some(name),
                    version: Some(version),
                    filename: Some(filename),
                    is_simple_index: false,
                    is_package_index: false,
                });
            }
        }

        // Direct package file with wheel or sdist
        if path.ends_with(".whl") || path.ends_with(".tar.gz") || path.ends_with(".zip") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            let info = Self::parse_filename(filename)?;
            return Ok(info);
        }

        Err(AppError::Validation(format!(
            "Invalid PyPI path format: {}",
            path
        )))
    }

    /// Parse wheel or sdist filename to extract metadata
    pub fn parse_filename(filename: &str) -> Result<PypiPackageInfo> {
        if filename.ends_with(".whl") {
            Self::parse_wheel_filename(filename)
        } else if filename.ends_with(".tar.gz") {
            Self::parse_sdist_filename(filename)
        } else if filename.ends_with(".zip") {
            Self::parse_sdist_zip_filename(filename)
        } else {
            Err(AppError::Validation(format!(
                "Unknown Python package format: {}",
                filename
            )))
        }
    }

    /// Parse wheel filename according to PEP 427
    /// Format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
    fn parse_wheel_filename(filename: &str) -> Result<PypiPackageInfo> {
        let name = filename.trim_end_matches(".whl");
        let parts: Vec<&str> = name.split('-').collect();

        if parts.len() < 5 {
            return Err(AppError::Validation(format!(
                "Invalid wheel filename format: {}",
                filename
            )));
        }

        // First part is distribution name, second is version
        // Then optional build tag, then python tag, abi tag, platform tag
        let distribution = Self::normalize_name(parts[0]);
        let version = parts[1].to_string();

        Ok(PypiPackageInfo {
            name: Some(distribution),
            version: Some(version),
            filename: Some(filename.to_string()),
            is_simple_index: false,
            is_package_index: false,
        })
    }

    /// Parse source distribution filename
    /// Format: {name}-{version}.tar.gz
    fn parse_sdist_filename(filename: &str) -> Result<PypiPackageInfo> {
        let name = filename.trim_end_matches(".tar.gz");
        let parts: Vec<&str> = name.rsplitn(2, '-').collect();

        if parts.len() != 2 {
            return Err(AppError::Validation(format!(
                "Invalid sdist filename format: {}",
                filename
            )));
        }

        let version = parts[0].to_string();
        let distribution = Self::normalize_name(parts[1]);

        Ok(PypiPackageInfo {
            name: Some(distribution),
            version: Some(version),
            filename: Some(filename.to_string()),
            is_simple_index: false,
            is_package_index: false,
        })
    }

    /// Parse zip source distribution filename
    fn parse_sdist_zip_filename(filename: &str) -> Result<PypiPackageInfo> {
        let name = filename.trim_end_matches(".zip");
        let parts: Vec<&str> = name.rsplitn(2, '-').collect();

        if parts.len() != 2 {
            return Err(AppError::Validation(format!(
                "Invalid zip sdist filename format: {}",
                filename
            )));
        }

        let version = parts[0].to_string();
        let distribution = Self::normalize_name(parts[1]);

        Ok(PypiPackageInfo {
            name: Some(distribution),
            version: Some(version),
            filename: Some(filename.to_string()),
            is_simple_index: false,
            is_package_index: false,
        })
    }

    /// Normalize package name according to PEP 503
    /// Replace any runs of non-alphanumeric characters with a single hyphen
    pub fn normalize_name(name: &str) -> String {
        let mut result = String::new();
        let mut last_was_separator = true;

        for c in name.chars() {
            if c.is_ascii_alphanumeric() {
                result.push(c.to_ascii_lowercase());
                last_was_separator = false;
            } else if !last_was_separator {
                result.push('-');
                last_was_separator = true;
            }
        }

        // Remove trailing separator
        if result.ends_with('-') {
            result.pop();
        }

        result
    }

    /// Extract metadata from PKG-INFO or METADATA file in sdist
    pub fn extract_sdist_metadata(content: &[u8]) -> Result<PkgInfo> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid tarball: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid tarball entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in tarball: {}", e)))?;

            // Look for PKG-INFO in the root of the package
            if path.ends_with("PKG-INFO") {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read PKG-INFO: {}", e)))?;

                return Self::parse_pkg_info(&content);
            }
        }

        Err(AppError::Validation(
            "PKG-INFO not found in source distribution".to_string(),
        ))
    }

    /// Extract METADATA from wheel file
    pub fn extract_wheel_metadata(content: &[u8]) -> Result<PkgInfo> {
        // Wheels are ZIP files
        let cursor = std::io::Cursor::new(content);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| AppError::Validation(format!("Invalid wheel file: {}", e)))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| AppError::Validation(format!("Failed to read wheel entry: {}", e)))?;

            let name = file.name().to_string();

            // Look for METADATA file in .dist-info directory
            if name.contains(".dist-info/") && name.ends_with("METADATA") {
                let mut content = String::new();
                file.read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read METADATA: {}", e)))?;

                return Self::parse_pkg_info(&content);
            }
        }

        Err(AppError::Validation(
            "METADATA not found in wheel file".to_string(),
        ))
    }

    /// Parse PKG-INFO or METADATA content (RFC 822 format)
    pub fn parse_pkg_info(content: &str) -> Result<PkgInfo> {
        let mut info = PkgInfo::default();
        let mut current_key: Option<String> = None;
        let mut current_value = String::new();

        for line in content.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation line
                if current_key.is_some() {
                    current_value.push('\n');
                    current_value.push_str(line.trim());
                }
            } else if let Some(colon_pos) = line.find(':') {
                // New field - save previous if exists
                if let Some(key) = current_key.take() {
                    Self::set_pkg_info_field(&mut info, &key, &current_value);
                }

                let key = line[..colon_pos].to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                current_key = Some(key);
                current_value = value;
            }
        }

        // Save the last field
        if let Some(key) = current_key {
            Self::set_pkg_info_field(&mut info, &key, &current_value);
        }

        if info.name.is_empty() {
            return Err(AppError::Validation(
                "PKG-INFO missing required Name field".to_string(),
            ));
        }

        Ok(info)
    }

    fn set_pkg_info_field(info: &mut PkgInfo, key: &str, value: &str) {
        match key.to_lowercase().as_str() {
            "metadata-version" => info.metadata_version = Some(value.to_string()),
            "name" => info.name = value.to_string(),
            "version" => info.version = value.to_string(),
            "summary" => info.summary = Some(value.to_string()),
            "description" => info.description = Some(value.to_string()),
            "description-content-type" => {
                info.description_content_type = Some(value.to_string())
            }
            "keywords" => {
                info.keywords = Some(value.split(',').map(|s| s.trim().to_string()).collect())
            }
            "home-page" => info.home_page = Some(value.to_string()),
            "download-url" => info.download_url = Some(value.to_string()),
            "author" => info.author = Some(value.to_string()),
            "author-email" => info.author_email = Some(value.to_string()),
            "maintainer" => info.maintainer = Some(value.to_string()),
            "maintainer-email" => info.maintainer_email = Some(value.to_string()),
            "license" => info.license = Some(value.to_string()),
            "classifier" => {
                info.classifiers
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
            }
            "platform" => {
                info.platforms
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
            }
            "requires-python" => info.requires_python = Some(value.to_string()),
            "requires-dist" => {
                info.requires_dist
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
            }
            "provides-extra" => {
                info.provides_extra
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
            }
            "project-url" => {
                let parts: Vec<&str> = value.splitn(2, ',').collect();
                if parts.len() == 2 {
                    info.project_urls
                        .get_or_insert_with(HashMap::new)
                        .insert(parts[0].trim().to_string(), parts[1].trim().to_string());
                }
            }
            _ => {}
        }
    }
}

impl Default for PypiHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for PypiHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Pypi
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({});

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        if let Some(filename) = &info.filename {
            metadata["filename"] = serde_json::Value::String(filename.clone());
        }

        metadata["is_simple_index"] = serde_json::Value::Bool(info.is_simple_index);
        metadata["is_package_index"] = serde_json::Value::Bool(info.is_package_index);

        // If it's a package file, try to extract metadata
        if !content.is_empty() && info.filename.is_some() {
            let filename = info.filename.as_ref().unwrap();

            let pkg_info_result = if filename.ends_with(".whl") {
                Self::extract_wheel_metadata(content)
            } else if filename.ends_with(".tar.gz") {
                Self::extract_sdist_metadata(content)
            } else {
                Err(AppError::Validation("Unsupported format".to_string()))
            };

            if let Ok(pkg_info) = pkg_info_result {
                metadata["pkg_info"] = serde_json::to_value(&pkg_info)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate package files
        if !content.is_empty() && info.filename.is_some() {
            let filename = info.filename.as_ref().unwrap();

            // Validate wheel files
            if filename.ends_with(".whl") {
                let pkg_info = Self::extract_wheel_metadata(content)?;

                // Verify name matches
                if let Some(path_name) = &info.name {
                    let normalized_pkg_name = Self::normalize_name(&pkg_info.name);
                    if &normalized_pkg_name != path_name {
                        return Err(AppError::Validation(format!(
                            "Package name mismatch: path says '{}' but metadata says '{}'",
                            path_name, pkg_info.name
                        )));
                    }
                }

                // Verify version matches
                if let Some(path_version) = &info.version {
                    if &pkg_info.version != path_version {
                        return Err(AppError::Validation(format!(
                            "Version mismatch: path says '{}' but metadata says '{}'",
                            path_version, pkg_info.version
                        )));
                    }
                }
            }

            // Validate sdist files
            if filename.ends_with(".tar.gz") {
                let pkg_info = Self::extract_sdist_metadata(content)?;

                // Verify name matches
                if let Some(path_name) = &info.name {
                    let normalized_pkg_name = Self::normalize_name(&pkg_info.name);
                    if &normalized_pkg_name != path_name {
                        return Err(AppError::Validation(format!(
                            "Package name mismatch: path says '{}' but metadata says '{}'",
                            path_name, pkg_info.name
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Simple index is generated on demand based on DB state
        Ok(None)
    }
}

/// PyPI package path info
#[derive(Debug)]
pub struct PypiPackageInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub filename: Option<String>,
    pub is_simple_index: bool,
    pub is_package_index: bool,
}

/// PKG-INFO / METADATA structure
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PkgInfo {
    pub metadata_version: Option<String>,
    pub name: String,
    pub version: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub description_content_type: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub home_page: Option<String>,
    pub download_url: Option<String>,
    pub author: Option<String>,
    pub author_email: Option<String>,
    pub maintainer: Option<String>,
    pub maintainer_email: Option<String>,
    pub license: Option<String>,
    pub classifiers: Option<Vec<String>>,
    pub platforms: Option<Vec<String>>,
    pub requires_python: Option<String>,
    pub requires_dist: Option<Vec<String>>,
    pub provides_extra: Option<Vec<String>>,
    pub project_urls: Option<HashMap<String, String>>,
}

/// Generate simple index HTML for root
pub fn generate_simple_root_index(packages: &[String]) -> String {
    let mut html = String::from(
        "<!DOCTYPE html>\n<html>\n<head>\n<title>Simple Index</title>\n</head>\n<body>\n<h1>Simple Index</h1>\n",
    );

    for package in packages {
        let normalized = PypiHandler::normalize_name(package);
        html.push_str(&format!(
            "<a href=\"/simple/{}/\">{}</a><br/>\n",
            normalized, package
        ));
    }

    html.push_str("</body>\n</html>\n");
    html
}

/// Generate simple index HTML for a package
pub fn generate_simple_package_index(
    package_name: &str,
    files: &[(String, String, Option<String>)], // (filename, url, hash)
) -> String {
    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head>\n<meta name=\"pypi:repository-version\" content=\"1.0\"/>\n");
    html.push_str(&format!("<title>Links for {}</title>\n", package_name));
    html.push_str("</head>\n<body>\n");
    html.push_str(&format!("<h1>Links for {}</h1>\n", package_name));

    for (filename, url, hash) in files {
        let hash_attr = hash
            .as_ref()
            .map(|h| format!(" data-dist-info-metadata=\"sha256={}\"", h))
            .unwrap_or_default();

        html.push_str(&format!(
            "<a href=\"{}\"{}>{}</a><br/>\n",
            url, hash_attr, filename
        ));
    }

    html.push_str("</body>\n</html>\n");
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_name() {
        assert_eq!(PypiHandler::normalize_name("My_Package"), "my-package");
        assert_eq!(PypiHandler::normalize_name("some.package"), "some-package");
        assert_eq!(
            PypiHandler::normalize_name("Package__Name"),
            "package-name"
        );
    }

    #[test]
    fn test_parse_wheel_filename() {
        let info = PypiHandler::parse_filename(
            "requests-2.28.0-py3-none-any.whl",
        )
        .unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
    }

    #[test]
    fn test_parse_sdist_filename() {
        let info = PypiHandler::parse_filename("requests-2.28.0.tar.gz").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
    }

    #[test]
    fn test_parse_simple_path() {
        let info = PypiHandler::parse_path("simple/requests/").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert!(info.is_package_index);
    }

    #[test]
    fn test_parse_root_index() {
        let info = PypiHandler::parse_path("simple/").unwrap();
        assert!(info.is_simple_index);
        assert!(info.name.is_none());
    }

    #[test]
    fn test_parse_pkg_info() {
        let content = r#"Metadata-Version: 2.1
Name: requests
Version: 2.28.0
Summary: Python HTTP for Humans.
Author: Kenneth Reitz
License: Apache 2.0
Requires-Python: >=3.7
Classifier: Development Status :: 5 - Production/Stable
Classifier: Intended Audience :: Developers
Requires-Dist: charset_normalizer (<3,>=2)
Requires-Dist: idna (<4,>=2.5)
"#;
        let info = PypiHandler::parse_pkg_info(content).unwrap();
        assert_eq!(info.name, "requests");
        assert_eq!(info.version, "2.28.0");
        assert_eq!(info.summary, Some("Python HTTP for Humans.".to_string()));
        assert_eq!(info.requires_python, Some(">=3.7".to_string()));
        assert_eq!(info.classifiers.as_ref().map(|c| c.len()), Some(2));
        assert_eq!(info.requires_dist.as_ref().map(|d| d.len()), Some(2));
    }
}
