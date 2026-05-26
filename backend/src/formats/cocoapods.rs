use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Handler for CocoaPods package format
pub struct CocoaPodsHandler;

impl CocoaPodsHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a CocoaPods path
    ///
    /// Supports paths like:
    /// - `Specs/<name>/<version>/<name>.podspec.json` (podspec)
    /// - `pods/<name>-<version>.tar.gz` (pod archive)
    pub fn parse_path(path: &str) -> Result<CocoaPodsPathInfo> {
        let path = path.trim_start_matches('/');

        // Try to match podspec pattern: Specs/<name>/<version>/<name>.podspec.json
        if path.starts_with("Specs/") {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 4 && parts[0] == "Specs" && parts[3].ends_with(".podspec.json") {
                let name = parts[1].to_string();
                let version = parts[2].to_string();
                let podspec_name = parts[3].strip_suffix(".podspec.json").unwrap_or("");

                // Validate that the podspec name matches the package name
                if podspec_name == name {
                    return Ok(CocoaPodsPathInfo {
                        name,
                        version,
                        artifact_type: CocoaPodsArtifactType::Podspec,
                    });
                }
            }
        }

        // Try to match pod archive pattern: pods/<name>-<version>.tar.gz
        if path.starts_with("pods/") {
            let filename = path.strip_prefix("pods/").unwrap_or("");
            if filename.ends_with(".tar.gz") {
                let basename = filename.strip_suffix(".tar.gz").unwrap_or("");
                if let Some(last_dash_pos) = basename.rfind('-') {
                    let name = basename[..last_dash_pos].to_string();
                    let version = basename[last_dash_pos + 1..].to_string();

                    if !name.is_empty() && !version.is_empty() {
                        return Ok(CocoaPodsPathInfo {
                            name,
                            version,
                            artifact_type: CocoaPodsArtifactType::Pod,
                        });
                    }
                }
            }
        }

        Err(AppError::Validation(
            "Invalid CocoaPods path format".to_string(),
        ))
    }
}

impl Default for CocoaPodsHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Information extracted from a CocoaPods path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CocoaPodsPathInfo {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Type of artifact (Podspec or Pod)
    pub artifact_type: CocoaPodsArtifactType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CocoaPodsArtifactType {
    /// Podspec file (JSON format)
    Podspec,
    /// Pod archive (tar.gz)
    Pod,
}

/// PodSpec metadata structure.
///
/// Only `name` and `version` are required by Artifact Keeper for indexing and
/// path resolution. Every other field in the original podspec JSON is captured
/// by `extra` so the served `*.podspec.json` is a byte-for-byte preservation of
/// what the publisher uploaded. This matters because the CocoaPods client needs
/// fields like `vendored_frameworks`, `xcconfig`, `preserve_paths`,
/// `requires_arc`, `documentation_url`, `screenshots`, `source_files`,
/// `frameworks`, `swift_version`, `resource_bundles`, etc. to install and link
/// the pod correctly. Hard-coding the schema dropped any field not in the
/// struct (see #1286).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpec {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Short description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Homepage URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// License information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<serde_json::Value>,
    /// Authors information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<serde_json::Value>,
    /// Source information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<serde_json::Value>,
    /// Supported platforms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<HashMap<String, String>>,
    /// Package dependencies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<HashMap<String, serde_json::Value>>,
    /// All other podspec fields the CocoaPods client may rely on
    /// (e.g. `vendored_frameworks`, `xcconfig`, `preserve_paths`,
    /// `requires_arc`, `documentation_url`, `screenshots`, `source_files`,
    /// `frameworks`, `swift_version`, `resource_bundles`, `subspecs`, ...).
    /// Captured as a flattened map so the served podspec JSON is a faithful
    /// round-trip of what was uploaded.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[async_trait]
impl FormatHandler for CocoaPodsHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Cocoapods
    }

    fn format_key(&self) -> &str {
        "cocoapods"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;
        Ok(serde_json::to_value(info).unwrap_or(serde_json::json!({})))
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_podspec_path() {
        let path = "Specs/AFNetworking/4.0.0/AFNetworking.podspec.json";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "AFNetworking");
        assert_eq!(info.version, "4.0.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Podspec);
    }

    #[test]
    fn test_parse_podspec_path_with_leading_slash() {
        let path = "/Specs/Alamofire/5.6.0/Alamofire.podspec.json";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "Alamofire");
        assert_eq!(info.version, "5.6.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Podspec);
    }

    #[test]
    fn test_parse_pod_archive_path() {
        let path = "pods/AFNetworking-4.0.0.tar.gz";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "AFNetworking");
        assert_eq!(info.version, "4.0.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Pod);
    }

    #[test]
    fn test_parse_pod_archive_path_with_leading_slash() {
        let path = "/pods/Alamofire-5.6.0.tar.gz";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "Alamofire");
        assert_eq!(info.version, "5.6.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Pod);
    }

    #[test]
    fn test_parse_invalid_podspec_name_mismatch() {
        let path = "Specs/AFNetworking/4.0.0/DifferentName.podspec.json";
        let result = CocoaPodsHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_format() {
        let path = "invalid/path/format";
        let result = CocoaPodsHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pod_with_hyphen_in_name() {
        let path = "pods/my-package-name-1.2.3.tar.gz";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-package-name");
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Pod);
    }

    #[test]
    fn test_podspec_serialization() {
        let podspec = PodSpec {
            name: "AFNetworking".to_string(),
            version: "4.0.0".to_string(),
            summary: Some("Delightful networking library".to_string()),
            homepage: Some("https://github.com/AFNetworking/AFNetworking".to_string()),
            license: None,
            authors: None,
            source: None,
            platforms: None,
            dependencies: None,
            extra: HashMap::new(),
        };

        let json = serde_json::to_string(&podspec).unwrap();
        assert!(json.contains("AFNetworking"));
        assert!(json.contains("4.0.0"));
    }

    /// Regression test for #1286: the served podspec JSON must preserve every
    /// field the publisher uploaded, not only the ones the struct names. The
    /// CocoaPods client needs fields like `vendored_frameworks`, `xcconfig`,
    /// `preserve_paths`, `requires_arc`, `documentation_url`, and
    /// `screenshots` to successfully link binary frameworks.
    #[test]
    fn test_podspec_preserves_unknown_fields_round_trip() {
        let original = serde_json::json!({
            "name": "MyLibrary",
            "version": "2.8.45",
            "summary": "MyCompany MyLibrary",
            "description": "Library of my company",
            "homepage": "https://github.com/",
            "documentation_url": "https://github.com/",
            "screenshots": "https://github.com/",
            "license": { "type": "Apache 2.0", "file": "LICENSE" },
            "authors": { "My Company": "devteam@my.company" },
            "platforms": { "osx": "10.13", "ios": "11.2" },
            "source": { "http": "https://ak.int.local/cocoapods/repo/pods/MyLibrary-2.8.45.tar.gz" },
            "preserve_paths": ["MyLibrary.xcframework"],
            "vendored_frameworks": "MyLibrary.xcframework",
            "xcconfig": { "LD_RUNPATH_SEARCH_PATHS": "@loader_path/../Frameworks" },
            "requires_arc": true,
        });

        let podspec: PodSpec = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(podspec.name, "MyLibrary");
        assert_eq!(podspec.version, "2.8.45");

        let round_tripped = serde_json::to_value(&podspec).unwrap();

        // Every field present in the uploaded podspec must survive the
        // round-trip into the JSON served at the Specs/<n>/<v>/<n>.podspec.json
        // endpoint. We assert each of the previously-dropped fields explicitly.
        for field in [
            "documentation_url",
            "screenshots",
            "preserve_paths",
            "vendored_frameworks",
            "xcconfig",
            "requires_arc",
            "description",
        ] {
            assert_eq!(
                round_tripped.get(field),
                original.get(field),
                "podspec field {} was lost during round-trip (regression for #1286)",
                field,
            );
        }

        // And the already-supported named fields stay intact too.
        for field in [
            "name",
            "version",
            "summary",
            "homepage",
            "license",
            "authors",
            "platforms",
            "source",
        ] {
            assert_eq!(round_tripped.get(field), original.get(field));
        }
    }
}
