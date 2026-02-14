//! Conan (C/C++) format handler.
//!
//! Implements Conan v2 API for C/C++ packages.
//! Supports recipe and package references.

use async_trait::async_trait;
use bytes::Bytes;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Conan format handler
pub struct ConanHandler;

// Regex for parsing Conan references
fn conan_ref_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^([^/@]+)/([^/@]+)(?:@([^/@#]+))?(?:/([^/@#]+))?(?:#(.+))?$").unwrap()
    })
}

impl ConanHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Conan v2 API path
    /// Formats:
    ///   v2/conans/<name>/<version>/<user>/<channel>/revisions/<rev>/...
    ///   v2/conans/<name>/<version>/_/_/revisions/<rev>/...
    ///   v2/users/authenticate
    ///   v2/users/check_credentials
    ///   v2/ping
    pub fn parse_path(path: &str) -> Result<ConanPathInfo> {
        let path = path.trim_start_matches('/');

        // Ping endpoint
        if path == "v2/ping" || path == "ping" {
            return Ok(ConanPathInfo {
                name: None,
                version: None,
                user: None,
                channel: None,
                revision: None,
                package_id: None,
                package_revision: None,
                operation: ConanOperation::Ping,
            });
        }

        // Authentication
        if path.contains("authenticate") {
            return Ok(ConanPathInfo {
                name: None,
                version: None,
                user: None,
                channel: None,
                revision: None,
                package_id: None,
                package_revision: None,
                operation: ConanOperation::Authenticate,
            });
        }

        if path.contains("check_credentials") {
            return Ok(ConanPathInfo {
                name: None,
                version: None,
                user: None,
                channel: None,
                revision: None,
                package_id: None,
                package_revision: None,
                operation: ConanOperation::CheckCredentials,
            });
        }

        // Recipe/package paths
        if path.starts_with("v2/conans/") || path.starts_with("conans/") {
            return Self::parse_conans_path(path);
        }

        // Direct conanfile path
        if path.ends_with("conanfile.py")
            || path.ends_with("conanmanifest.txt")
            || path.ends_with("conan_export.tgz")
        {
            return Self::parse_artifact_path(path);
        }

        Err(AppError::Validation(format!(
            "Invalid Conan path: {}",
            path
        )))
    }

    /// Parse /conans/ path
    fn parse_conans_path(path: &str) -> Result<ConanPathInfo> {
        let path = path.trim_start_matches("v2/").trim_start_matches("conans/");
        let parts: Vec<&str> = path.split('/').collect();

        if parts.len() < 4 {
            return Err(AppError::Validation(format!(
                "Invalid Conan conans path: {}",
                path
            )));
        }

        let name = parts[0].to_string();
        let version = parts[1].to_string();
        let user = if parts[2] == "_" {
            None
        } else {
            Some(parts[2].to_string())
        };
        let channel = if parts[3] == "_" {
            None
        } else {
            Some(parts[3].to_string())
        };

        // Parse the rest of the path
        let mut revision = None;
        let mut package_id = None;
        let mut package_revision = None;
        let mut operation = ConanOperation::RecipeLatest;

        let mut i = 4;
        while i < parts.len() {
            match parts[i] {
                "revisions" => {
                    if i + 1 < parts.len() {
                        revision = Some(parts[i + 1].to_string());
                        i += 2;
                    } else {
                        operation = ConanOperation::RecipeRevisions;
                        i += 1;
                    }
                }
                "packages" => {
                    if i + 1 < parts.len() {
                        package_id = Some(parts[i + 1].to_string());
                        i += 2;

                        // Check for package revisions
                        if i < parts.len() && parts[i] == "revisions" {
                            if i + 1 < parts.len() {
                                package_revision = Some(parts[i + 1].to_string());
                                i += 2;
                            } else {
                                operation = ConanOperation::PackageRevisions;
                                i += 1;
                            }
                        }
                    } else {
                        operation = ConanOperation::Packages;
                        i += 1;
                    }
                }
                "files" => {
                    operation = ConanOperation::Files;
                    i += 1;
                }
                "download_urls" => {
                    operation = ConanOperation::DownloadUrls;
                    i += 1;
                }
                "latest" => {
                    if package_id.is_some() {
                        operation = ConanOperation::PackageLatest;
                    } else {
                        operation = ConanOperation::RecipeLatest;
                    }
                    i += 1;
                }
                _ => {
                    // Check if this is a file
                    if parts[i].contains('.') {
                        operation = ConanOperation::File(parts[i].to_string());
                    }
                    i += 1;
                }
            }
        }

        Ok(ConanPathInfo {
            name: Some(name),
            version: Some(version),
            user,
            channel,
            revision,
            package_id,
            package_revision,
            operation,
        })
    }

    /// Parse artifact path (conanfile.py, etc.)
    fn parse_artifact_path(path: &str) -> Result<ConanPathInfo> {
        let filename = path.rsplit('/').next().unwrap_or(path);
        Ok(ConanPathInfo {
            name: None,
            version: None,
            user: None,
            channel: None,
            revision: None,
            package_id: None,
            package_revision: None,
            operation: ConanOperation::File(filename.to_string()),
        })
    }

    /// Parse Conan reference string
    /// Format: name/version@user/channel#revision
    pub fn parse_reference(reference: &str) -> Result<ConanReference> {
        let re = conan_ref_regex();

        if let Some(caps) = re.captures(reference) {
            let name = caps
                .get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let version = caps
                .get(2)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let user = caps.get(3).map(|m| m.as_str().to_string());
            let channel = caps.get(4).map(|m| m.as_str().to_string());
            let revision = caps.get(5).map(|m| m.as_str().to_string());

            return Ok(ConanReference {
                name,
                version,
                user,
                channel,
                revision,
            });
        }

        Err(AppError::Validation(format!(
            "Invalid Conan reference: {}",
            reference
        )))
    }

    /// Parse conanfile.py to extract metadata
    pub fn parse_conanfile_py(content: &str) -> Result<ConanfileMetadata> {
        let mut metadata = ConanfileMetadata::default();

        // Extract class attributes using simple regex patterns
        for line in content.lines() {
            let line = line.trim();

            // Name
            if line.starts_with("name") && line.contains('=') {
                metadata.name = Self::extract_string_value(line);
            }
            // Version
            else if line.starts_with("version") && line.contains('=') {
                metadata.version = Self::extract_string_value(line);
            }
            // Description
            else if line.starts_with("description") && line.contains('=') {
                metadata.description = Self::extract_string_value(line);
            }
            // License
            else if line.starts_with("license") && line.contains('=') {
                metadata.license = Self::extract_string_value(line);
            }
            // Author
            else if line.starts_with("author") && line.contains('=') {
                metadata.author = Self::extract_string_value(line);
            }
            // URL
            else if line.starts_with("url") && line.contains('=') {
                metadata.url = Self::extract_string_value(line);
            }
            // Homepage
            else if line.starts_with("homepage") && line.contains('=') {
                metadata.homepage = Self::extract_string_value(line);
            }
            // Topics
            else if line.starts_with("topics") && line.contains('=') {
                metadata.topics = Self::extract_tuple_values(line);
            }
            // Settings
            else if line.starts_with("settings") && line.contains('=') {
                metadata.settings = Self::extract_tuple_values(line);
            }
            // Options
            else if line.starts_with("options") && line.contains('=') {
                // Options are a dict, just note they exist
                metadata.has_options = true;
            }
            // Requires
            else if line.starts_with("requires") && line.contains('=') {
                metadata.requires = Self::extract_tuple_values(line);
            }
        }

        Ok(metadata)
    }

    /// Extract string value from Python assignment
    fn extract_string_value(line: &str) -> Option<String> {
        let value = line.split('=').nth(1)?.trim();
        // Remove quotes
        let value = value.trim_matches(|c| c == '"' || c == '\'');
        if !value.is_empty() {
            Some(value.to_string())
        } else {
            None
        }
    }

    /// Extract tuple/list values from Python assignment
    fn extract_tuple_values(line: &str) -> Option<Vec<String>> {
        let value = line.split('=').nth(1)?.trim();
        // Match content between parentheses or brackets
        let content = if value.starts_with('(') {
            value.trim_start_matches('(').trim_end_matches(')')
        } else if value.starts_with('[') {
            value.trim_start_matches('[').trim_end_matches(']')
        } else {
            return None;
        };

        let values: Vec<String> = content
            .split(',')
            .map(|s| s.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if values.is_empty() {
            None
        } else {
            Some(values)
        }
    }

    /// Parse conanfile.txt
    pub fn parse_conanfile_txt(content: &str) -> Result<ConanfileTxt> {
        let mut conanfile = ConanfileTxt::default();
        let mut current_section: Option<&str> = None;

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                current_section = Some(&line[1..line.len() - 1]);
                continue;
            }

            match current_section {
                Some("requires") => {
                    conanfile.requires.push(line.to_string());
                }
                Some("tool_requires") | Some("build_requires") => {
                    conanfile.tool_requires.push(line.to_string());
                }
                Some("generators") => {
                    conanfile.generators.push(line.to_string());
                }
                Some("options") => {
                    if let Some((key, value)) = line.split_once('=') {
                        conanfile
                            .options
                            .insert(key.trim().to_string(), value.trim().to_string());
                    }
                }
                _ => {}
            }
        }

        Ok(conanfile)
    }
}

impl Default for ConanHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for ConanHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Conan
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

        if let Some(user) = &info.user {
            metadata["user"] = serde_json::Value::String(user.clone());
        }

        if let Some(channel) = &info.channel {
            metadata["channel"] = serde_json::Value::String(channel.clone());
        }

        if let Some(revision) = &info.revision {
            metadata["revision"] = serde_json::Value::String(revision.clone());
        }

        if let Some(package_id) = &info.package_id {
            metadata["packageId"] = serde_json::Value::String(package_id.clone());
        }

        // Parse conanfile content if present
        if !content.is_empty() {
            if let ConanOperation::File(ref filename) = info.operation {
                if filename == "conanfile.py" {
                    if let Ok(content_str) = std::str::from_utf8(content) {
                        if let Ok(conanfile) = Self::parse_conanfile_py(content_str) {
                            metadata["conanfile"] = serde_json::to_value(&conanfile)?;
                        }
                    }
                } else if filename == "conanfile.txt" {
                    if let Ok(content_str) = std::str::from_utf8(content) {
                        if let Ok(conanfile) = Self::parse_conanfile_txt(content_str) {
                            metadata["conanfile"] = serde_json::to_value(&conanfile)?;
                        }
                    }
                }
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate conanfile.py content
        if !content.is_empty() {
            if let ConanOperation::File(ref filename) = info.operation {
                if filename == "conanfile.py" {
                    let content_str = std::str::from_utf8(content)
                        .map_err(|e| AppError::Validation(format!("Invalid UTF-8: {}", e)))?;
                    let conanfile = Self::parse_conanfile_py(content_str)?;

                    // Verify name matches if specified in path
                    if let Some(path_name) = &info.name {
                        if let Some(file_name) = &conanfile.name {
                            if file_name != path_name {
                                return Err(AppError::Validation(format!(
                                    "Package name mismatch: path says '{}' but conanfile says '{}'",
                                    path_name, file_name
                                )));
                            }
                        }
                    }

                    // Verify version matches if specified in path
                    if let Some(path_version) = &info.version {
                        if let Some(file_version) = &conanfile.version {
                            if file_version != path_version {
                                return Err(AppError::Validation(format!(
                                    "Version mismatch: path says '{}' but conanfile says '{}'",
                                    path_version, file_version
                                )));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Conan v2 uses dynamic API responses
        Ok(None)
    }
}

/// Conan path info
#[derive(Debug)]
pub struct ConanPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub user: Option<String>,
    pub channel: Option<String>,
    pub revision: Option<String>,
    pub package_id: Option<String>,
    pub package_revision: Option<String>,
    pub operation: ConanOperation,
}

/// Conan operation type
#[derive(Debug)]
pub enum ConanOperation {
    Ping,
    Authenticate,
    CheckCredentials,
    RecipeLatest,
    RecipeRevisions,
    Packages,
    PackageLatest,
    PackageRevisions,
    Files,
    DownloadUrls,
    File(String),
}

/// Conan reference
#[derive(Debug, Serialize, Deserialize)]
pub struct ConanReference {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub revision: Option<String>,
}

impl ConanReference {
    /// Convert to string representation
    pub fn to_reference_string(&self) -> String {
        let mut s = format!("{}/{}", self.name, self.version);
        if let (Some(user), Some(channel)) = (&self.user, &self.channel) {
            s.push_str(&format!("@{}/{}", user, channel));
        }
        if let Some(rev) = &self.revision {
            s.push_str(&format!("#{}", rev));
        }
        s
    }

    /// Convert to URL path
    pub fn to_path(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.name,
            self.version,
            self.user.as_deref().unwrap_or("_"),
            self.channel.as_deref().unwrap_or("_")
        )
    }
}

/// Conanfile.py metadata
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConanfileMetadata {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub topics: Option<Vec<String>>,
    #[serde(default)]
    pub settings: Option<Vec<String>>,
    #[serde(default)]
    pub has_options: bool,
    #[serde(default)]
    pub requires: Option<Vec<String>>,
}

/// Conanfile.txt structure
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConanfileTxt {
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub tool_requires: Vec<String>,
    #[serde(default)]
    pub generators: Vec<String>,
    #[serde(default)]
    pub options: HashMap<String, String>,
}

/// Recipe revision info
#[derive(Debug, Serialize, Deserialize)]
pub struct RecipeRevision {
    pub revision: String,
    pub time: String,
}

/// Package info
#[derive(Debug, Serialize, Deserialize)]
pub struct PackageInfo {
    pub package_id: String,
    #[serde(default)]
    pub settings: HashMap<String, String>,
    #[serde(default)]
    pub options: HashMap<String, String>,
    #[serde(default)]
    pub requires: Vec<String>,
}

/// Generate revision list response
pub fn generate_revisions_response(revisions: Vec<RecipeRevision>) -> serde_json::Value {
    serde_json::json!({
        "revisions": revisions
    })
}

/// Generate packages list response
pub fn generate_packages_response(packages: Vec<PackageInfo>) -> serde_json::Value {
    serde_json::json!({
        "packages": packages
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_reference() {
        let reference = ConanHandler::parse_reference("zlib/1.2.13@user/channel#abc123").unwrap();
        assert_eq!(reference.name, "zlib");
        assert_eq!(reference.version, "1.2.13");
        assert_eq!(reference.user, Some("user".to_string()));
        assert_eq!(reference.channel, Some("channel".to_string()));
        assert_eq!(reference.revision, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_reference_simple() {
        let reference = ConanHandler::parse_reference("zlib/1.2.13").unwrap();
        assert_eq!(reference.name, "zlib");
        assert_eq!(reference.version, "1.2.13");
        assert_eq!(reference.user, None);
        assert_eq!(reference.channel, None);
    }

    #[test]
    fn test_parse_path_recipe() {
        let info =
            ConanHandler::parse_path("v2/conans/zlib/1.2.13/_/_/revisions/abc123/files").unwrap();
        assert_eq!(info.name, Some("zlib".to_string()));
        assert_eq!(info.version, Some("1.2.13".to_string()));
        assert_eq!(info.revision, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_path_package() {
        let info = ConanHandler::parse_path(
            "v2/conans/zlib/1.2.13/_/_/revisions/abc123/packages/pkg123/revisions/def456",
        )
        .unwrap();
        assert_eq!(info.name, Some("zlib".to_string()));
        assert_eq!(info.package_id, Some("pkg123".to_string()));
        assert_eq!(info.package_revision, Some("def456".to_string()));
    }

    #[test]
    fn test_parse_path_ping() {
        let info = ConanHandler::parse_path("v2/ping").unwrap();
        assert!(matches!(info.operation, ConanOperation::Ping));
    }

    #[test]
    fn test_parse_conanfile_py() {
        let content = r#"
from conan import ConanFile

class ZlibConan(ConanFile):
    name = "zlib"
    version = "1.2.13"
    description = "A compression library"
    license = "Zlib"
    url = "https://github.com/conan-io/conan-center-index"
    topics = ("compression", "zlib")
    settings = ("os", "compiler", "build_type", "arch")
"#;
        let metadata = ConanHandler::parse_conanfile_py(content).unwrap();
        assert_eq!(metadata.name, Some("zlib".to_string()));
        assert_eq!(metadata.version, Some("1.2.13".to_string()));
        assert_eq!(metadata.license, Some("Zlib".to_string()));
    }

    #[test]
    fn test_parse_conanfile_txt() {
        let content = r#"
[requires]
zlib/1.2.13
openssl/3.0.5

[generators]
CMakeDeps
CMakeToolchain

[options]
zlib*:shared=True
"#;
        let conanfile = ConanHandler::parse_conanfile_txt(content).unwrap();
        assert_eq!(conanfile.requires.len(), 2);
        assert_eq!(conanfile.generators.len(), 2);
        assert!(conanfile.options.contains_key("zlib*:shared"));
    }

    #[test]
    fn test_parse_path_authenticate() {
        let info = ConanHandler::parse_path("v2/users/authenticate").unwrap();
        assert!(matches!(info.operation, ConanOperation::Authenticate));
    }

    #[test]
    fn test_parse_path_check_credentials() {
        let info = ConanHandler::parse_path("v2/users/check_credentials").unwrap();
        assert!(matches!(info.operation, ConanOperation::CheckCredentials));
    }

    #[test]
    fn test_parse_path_with_user_channel() {
        let info = ConanHandler::parse_path("v2/conans/zlib/1.2.13/myuser/stable/revisions/abc123")
            .unwrap();
        assert_eq!(info.name, Some("zlib".to_string()));
        assert_eq!(info.version, Some("1.2.13".to_string()));
        assert_eq!(info.user, Some("myuser".to_string()));
        assert_eq!(info.channel, Some("stable".to_string()));
        assert_eq!(info.revision, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_path_download_urls() {
        let info =
            ConanHandler::parse_path("v2/conans/zlib/1.2.13/_/_/revisions/abc/download_urls")
                .unwrap();
        assert!(matches!(info.operation, ConanOperation::DownloadUrls));
    }

    #[test]
    fn test_parse_path_packages_list() {
        let info =
            ConanHandler::parse_path("v2/conans/zlib/1.2.13/_/_/revisions/abc/packages").unwrap();
        assert!(matches!(info.operation, ConanOperation::Packages));
    }

    #[test]
    fn test_parse_path_recipe_revisions() {
        let info = ConanHandler::parse_path("v2/conans/zlib/1.2.13/_/_/revisions").unwrap();
        assert!(matches!(info.operation, ConanOperation::RecipeRevisions));
    }

    #[test]
    fn test_parse_path_latest() {
        let info = ConanHandler::parse_path("v2/conans/zlib/1.2.13/_/_/latest").unwrap();
        assert!(matches!(info.operation, ConanOperation::RecipeLatest));
    }

    #[test]
    fn test_parse_path_package_latest() {
        let info = ConanHandler::parse_path(
            "v2/conans/zlib/1.2.13/_/_/revisions/abc/packages/pkg123/latest",
        )
        .unwrap();
        assert!(matches!(info.operation, ConanOperation::PackageLatest));
        assert_eq!(info.package_id, Some("pkg123".to_string()));
    }

    #[test]
    fn test_parse_path_invalid() {
        let result = ConanHandler::parse_path("invalid/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_conans_too_short() {
        let result = ConanHandler::parse_path("v2/conans/zlib");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_artifact_conanfile() {
        let info = ConanHandler::parse_path("some/path/conanfile.py").unwrap();
        assert!(matches!(info.operation, ConanOperation::File(ref f) if f == "conanfile.py"));
    }

    #[test]
    fn test_parse_path_artifact_conanmanifest() {
        let info = ConanHandler::parse_path("path/conanmanifest.txt").unwrap();
        assert!(matches!(info.operation, ConanOperation::File(ref f) if f == "conanmanifest.txt"));
    }

    #[test]
    fn test_parse_path_artifact_conan_export() {
        let info = ConanHandler::parse_path("path/conan_export.tgz").unwrap();
        assert!(matches!(info.operation, ConanOperation::File(ref f) if f == "conan_export.tgz"));
    }

    #[test]
    fn test_parse_reference_with_user_no_channel() {
        // name/version@user (no channel)
        let reference = ConanHandler::parse_reference("zlib/1.2.13@user").unwrap();
        assert_eq!(reference.name, "zlib");
        assert_eq!(reference.version, "1.2.13");
        assert_eq!(reference.user, Some("user".to_string()));
        assert_eq!(reference.channel, None);
    }

    #[test]
    fn test_parse_reference_invalid() {
        let result = ConanHandler::parse_reference("");
        assert!(result.is_err());
    }

    #[test]
    fn test_reference_to_string() {
        let reference = ConanReference {
            name: "zlib".to_string(),
            version: "1.2.13".to_string(),
            user: Some("user".to_string()),
            channel: Some("stable".to_string()),
            revision: Some("abc123".to_string()),
        };
        assert_eq!(
            reference.to_reference_string(),
            "zlib/1.2.13@user/stable#abc123"
        );
    }

    #[test]
    fn test_reference_to_string_simple() {
        let reference = ConanReference {
            name: "boost".to_string(),
            version: "1.80.0".to_string(),
            user: None,
            channel: None,
            revision: None,
        };
        assert_eq!(reference.to_reference_string(), "boost/1.80.0");
    }

    #[test]
    fn test_reference_to_path() {
        let reference = ConanReference {
            name: "zlib".to_string(),
            version: "1.2.13".to_string(),
            user: Some("user".to_string()),
            channel: Some("stable".to_string()),
            revision: None,
        };
        assert_eq!(reference.to_path(), "zlib/1.2.13/user/stable");
    }

    #[test]
    fn test_reference_to_path_no_user_channel() {
        let reference = ConanReference {
            name: "zlib".to_string(),
            version: "1.2.13".to_string(),
            user: None,
            channel: None,
            revision: None,
        };
        assert_eq!(reference.to_path(), "zlib/1.2.13/_/_");
    }

    #[test]
    fn test_extract_string_value() {
        assert_eq!(
            ConanHandler::extract_string_value(r#"name = "zlib""#),
            Some("zlib".to_string())
        );
        assert_eq!(
            ConanHandler::extract_string_value("name = 'zlib'"),
            Some("zlib".to_string())
        );
        assert_eq!(ConanHandler::extract_string_value(r#"name = """#), None);
    }

    #[test]
    fn test_extract_tuple_values_parens() {
        let result = ConanHandler::extract_tuple_values(r#"topics = ("compression", "zlib")"#);
        assert_eq!(
            result,
            Some(vec!["compression".to_string(), "zlib".to_string()])
        );
    }

    #[test]
    fn test_extract_tuple_values_brackets() {
        let result = ConanHandler::extract_tuple_values(r#"settings = ["os", "compiler"]"#);
        assert_eq!(result, Some(vec!["os".to_string(), "compiler".to_string()]));
    }

    #[test]
    fn test_extract_tuple_values_no_container() {
        let result = ConanHandler::extract_tuple_values(r#"settings = "os""#);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_conanfile_py_with_options() {
        let content = r#"
class MyConan(ConanFile):
    name = "mylib"
    options = {"shared": [True, False]}
    requires = ("zlib/1.2.13", "openssl/3.0")
"#;
        let metadata = ConanHandler::parse_conanfile_py(content).unwrap();
        assert_eq!(metadata.name, Some("mylib".to_string()));
        assert!(metadata.has_options);
        assert!(metadata.requires.is_some());
        assert_eq!(metadata.requires.unwrap().len(), 2);
    }

    #[test]
    fn test_parse_conanfile_txt_with_tool_requires() {
        let content = r#"
[requires]
zlib/1.2.13

[tool_requires]
cmake/3.22.0

[build_requires]
ninja/1.10.2
"#;
        let conanfile = ConanHandler::parse_conanfile_txt(content).unwrap();
        assert_eq!(conanfile.requires.len(), 1);
        assert_eq!(conanfile.tool_requires.len(), 2);
    }

    #[test]
    fn test_parse_conanfile_txt_empty() {
        let content = "";
        let conanfile = ConanHandler::parse_conanfile_txt(content).unwrap();
        assert!(conanfile.requires.is_empty());
        assert!(conanfile.generators.is_empty());
        assert!(conanfile.options.is_empty());
    }

    #[test]
    fn test_parse_conanfile_txt_with_comments() {
        let content = r#"
# This is a comment
[requires]
zlib/1.2.13

# Another comment
[generators]
CMakeDeps
"#;
        let conanfile = ConanHandler::parse_conanfile_txt(content).unwrap();
        assert_eq!(conanfile.requires.len(), 1);
        assert_eq!(conanfile.generators.len(), 1);
    }

    #[test]
    fn test_generate_revisions_response() {
        let revisions = vec![RecipeRevision {
            revision: "abc123".to_string(),
            time: "2024-01-01T00:00:00Z".to_string(),
        }];
        let response = generate_revisions_response(revisions);
        let revs = response["revisions"].as_array().unwrap();
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0]["revision"], "abc123");
    }

    #[test]
    fn test_generate_packages_response() {
        let packages = vec![PackageInfo {
            package_id: "pkg123".to_string(),
            settings: HashMap::from([("os".to_string(), "Linux".to_string())]),
            options: HashMap::new(),
            requires: vec![],
        }];
        let response = generate_packages_response(packages);
        let pkgs = response["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0]["package_id"], "pkg123");
    }

    #[test]
    fn test_conan_handler_format() {
        let handler = ConanHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Conan);
    }

    #[test]
    fn test_conan_handler_default() {
        let handler = ConanHandler;
        assert_eq!(handler.format(), RepositoryFormat::Conan);
    }

    #[test]
    fn test_conan_handler_format_key() {
        let handler = ConanHandler::new();
        assert_eq!(handler.format_key(), "conan");
    }

    #[test]
    fn test_parse_path_file_in_conans() {
        let info = ConanHandler::parse_path("v2/conans/zlib/1.2.13/_/_/revisions/abc/conanfile.py")
            .unwrap();
        assert!(matches!(info.operation, ConanOperation::File(ref f) if f == "conanfile.py"));
        assert_eq!(info.name, Some("zlib".to_string()));
    }

    #[test]
    fn test_conan_reference_serialization() {
        let reference = ConanReference {
            name: "zlib".to_string(),
            version: "1.2.13".to_string(),
            user: None,
            channel: None,
            revision: None,
        };
        let json = serde_json::to_string(&reference).unwrap();
        let deserialized: ConanReference = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "zlib");
        assert_eq!(deserialized.version, "1.2.13");
    }

    #[test]
    fn test_parse_path_package_revisions_list() {
        let info = ConanHandler::parse_path(
            "v2/conans/zlib/1.2.13/_/_/revisions/abc/packages/pkg123/revisions",
        )
        .unwrap();
        assert!(matches!(info.operation, ConanOperation::PackageRevisions));
        assert_eq!(info.package_id, Some("pkg123".to_string()));
    }
}
