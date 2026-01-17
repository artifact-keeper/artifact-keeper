//! NuGet format handler.
//!
//! Implements NuGet v3 API for .NET packages.
//! Supports .nupkg files (ZIP archives with .nuspec metadata).

use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::de::from_str;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// NuGet format handler
pub struct NugetHandler;

impl NugetHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse NuGet path
    /// V3 API formats:
    ///   v3/index.json                           - Service index
    ///   v3/registration/<id>/index.json         - Package registration
    ///   v3/registration/<id>/<version>.json     - Version registration
    ///   v3/flatcontainer/<id>/index.json        - Package versions list
    ///   v3/flatcontainer/<id>/<version>/<file>  - Package content
    ///   v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg
    pub fn parse_path(path: &str) -> Result<NugetPathInfo> {
        let path = path.trim_start_matches('/');

        // Service index
        if path == "v3/index.json" || path == "index.json" {
            return Ok(NugetPathInfo {
                id: None,
                version: None,
                operation: NugetOperation::ServiceIndex,
                filename: None,
            });
        }

        // Registration paths
        if path.starts_with("v3/registration/") || path.starts_with("registration/") {
            let rest = path
                .trim_start_matches("v3/")
                .trim_start_matches("registration/");
            let parts: Vec<&str> = rest.split('/').collect();

            if parts.len() >= 2 {
                let id = Self::normalize_id(parts[0]);

                if parts[1] == "index.json" {
                    return Ok(NugetPathInfo {
                        id: Some(id),
                        version: None,
                        operation: NugetOperation::PackageRegistration,
                        filename: None,
                    });
                } else if parts[1].ends_with(".json") {
                    let version = parts[1].trim_end_matches(".json").to_string();
                    return Ok(NugetPathInfo {
                        id: Some(id),
                        version: Some(version),
                        operation: NugetOperation::VersionRegistration,
                        filename: None,
                    });
                }
            }
        }

        // Flat container paths
        if path.starts_with("v3/flatcontainer/")
            || path.starts_with("flatcontainer/")
            || path.starts_with("v3-flatcontainer/")
        {
            let rest = path
                .trim_start_matches("v3/")
                .trim_start_matches("v3-")
                .trim_start_matches("flatcontainer/");
            let parts: Vec<&str> = rest.split('/').collect();

            if parts.len() >= 2 {
                let id = Self::normalize_id(parts[0]);

                if parts[1] == "index.json" {
                    return Ok(NugetPathInfo {
                        id: Some(id),
                        version: None,
                        operation: NugetOperation::PackageVersions,
                        filename: None,
                    });
                } else if parts.len() >= 3 {
                    let version = parts[1].to_string();
                    let filename = parts[2..].join("/");
                    return Ok(NugetPathInfo {
                        id: Some(id),
                        version: Some(version),
                        operation: NugetOperation::PackageContent,
                        filename: Some(filename),
                    });
                }
            }
        }

        // Direct nupkg file
        if path.ends_with(".nupkg") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            let (id, version) = Self::parse_nupkg_filename(filename)?;
            return Ok(NugetPathInfo {
                id: Some(id),
                version: Some(version),
                operation: NugetOperation::PackageContent,
                filename: Some(filename.to_string()),
            });
        }

        Err(AppError::Validation(format!(
            "Invalid NuGet path: {}",
            path
        )))
    }

    /// Parse nupkg filename
    /// Format: <id>.<version>.nupkg
    fn parse_nupkg_filename(filename: &str) -> Result<(String, String)> {
        let name = filename.trim_end_matches(".nupkg");

        // Find where version starts (first segment that starts with a digit after dots)
        let parts: Vec<&str> = name.split('.').collect();
        let mut id_parts = Vec::new();
        let mut version_parts = Vec::new();
        let mut found_version = false;

        for part in parts {
            if !found_version && part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                found_version = true;
            }

            if found_version {
                version_parts.push(part);
            } else {
                id_parts.push(part);
            }
        }

        if id_parts.is_empty() || version_parts.is_empty() {
            return Err(AppError::Validation(format!(
                "Invalid NuGet package filename: {}",
                filename
            )));
        }

        let id = id_parts.join(".");
        let version = version_parts.join(".");

        Ok((id, version))
    }

    /// Normalize package ID (lowercase)
    pub fn normalize_id(id: &str) -> String {
        id.to_lowercase()
    }

    /// Extract nuspec from nupkg file
    pub fn extract_nuspec(content: &[u8]) -> Result<NuSpec> {
        let cursor = std::io::Cursor::new(content);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| AppError::Validation(format!("Invalid nupkg file: {}", e)))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| AppError::Validation(format!("Failed to read nupkg entry: {}", e)))?;

            let name = file.name().to_string();

            if name.ends_with(".nuspec") {
                let mut content = String::new();
                file.read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read nuspec: {}", e)))?;

                return Self::parse_nuspec(&content);
            }
        }

        Err(AppError::Validation(
            "nuspec not found in nupkg file".to_string(),
        ))
    }

    /// Parse nuspec XML content
    pub fn parse_nuspec(content: &str) -> Result<NuSpec> {
        // Remove XML declaration if present for easier parsing
        let content = content
            .trim_start_matches(|c: char| c != '<')
            .trim_start_matches("<?xml")
            .find('<')
            .map(|i| &content[i..])
            .unwrap_or(content);

        // Handle namespace prefixes by trying different approaches
        from_str(content).map_err(|e| AppError::Validation(format!("Invalid nuspec XML: {}", e)))
    }
}

impl Default for NugetHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for NugetHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Nuget
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "operation": format!("{:?}", info.operation),
        });

        if let Some(id) = &info.id {
            metadata["id"] = serde_json::Value::String(id.clone());
        }

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        // Extract nuspec if this is a package file
        if !content.is_empty() && matches!(info.operation, NugetOperation::PackageContent) {
            if let Some(filename) = &info.filename {
                if filename.ends_with(".nupkg") {
                    if let Ok(nuspec) = Self::extract_nuspec(content) {
                        metadata["nuspec"] = serde_json::to_value(&nuspec)?;
                    }
                }
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate nupkg files
        if !content.is_empty() && matches!(info.operation, NugetOperation::PackageContent) {
            if let Some(filename) = &info.filename {
                if filename.ends_with(".nupkg") {
                    let nuspec = Self::extract_nuspec(content)?;

                    // Verify ID matches
                    if let Some(path_id) = &info.id {
                        let normalized_nuspec_id = Self::normalize_id(&nuspec.metadata.id);
                        if &normalized_nuspec_id != path_id {
                            return Err(AppError::Validation(format!(
                                "Package ID mismatch: path says '{}' but nuspec says '{}'",
                                path_id, nuspec.metadata.id
                            )));
                        }
                    }

                    // Verify version matches
                    if let Some(path_version) = &info.version {
                        if &nuspec.metadata.version != path_version {
                            return Err(AppError::Validation(format!(
                                "Version mismatch: path says '{}' but nuspec says '{}'",
                                path_version, nuspec.metadata.version
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // NuGet v3 API uses dynamic JSON responses
        Ok(None)
    }
}

/// NuGet path info
#[derive(Debug)]
pub struct NugetPathInfo {
    pub id: Option<String>,
    pub version: Option<String>,
    pub operation: NugetOperation,
    pub filename: Option<String>,
}

/// NuGet operation type
#[derive(Debug)]
pub enum NugetOperation {
    ServiceIndex,
    PackageRegistration,
    VersionRegistration,
    PackageVersions,
    PackageContent,
}

/// NuSpec structure (from .nuspec file)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "package")]
pub struct NuSpec {
    pub metadata: NuSpecMetadata,
}

/// NuSpec metadata
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NuSpecMetadata {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub authors: Option<String>,
    #[serde(default)]
    pub owners: Option<String>,
    #[serde(default)]
    pub license_url: Option<String>,
    #[serde(default)]
    pub project_url: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default, rename = "requireLicenseAcceptance")]
    pub require_license_acceptance: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub release_notes: Option<String>,
    #[serde(default)]
    pub copyright: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub tags: Option<String>,
    #[serde(default)]
    pub dependencies: Option<NuSpecDependencies>,
    #[serde(default)]
    pub framework_assemblies: Option<NuSpecFrameworkAssemblies>,
    #[serde(default)]
    pub repository: Option<NuSpecRepository>,
    #[serde(default)]
    pub license: Option<NuSpecLicense>,
}

/// NuSpec dependencies group
#[derive(Debug, Serialize, Deserialize)]
pub struct NuSpecDependencies {
    #[serde(default, rename = "group")]
    pub groups: Vec<NuSpecDependencyGroup>,
    #[serde(default, rename = "dependency")]
    pub dependencies: Vec<NuSpecDependency>,
}

/// NuSpec dependency group
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NuSpecDependencyGroup {
    #[serde(rename = "@targetFramework")]
    pub target_framework: Option<String>,
    #[serde(default, rename = "dependency")]
    pub dependencies: Vec<NuSpecDependency>,
}

/// NuSpec dependency
#[derive(Debug, Serialize, Deserialize)]
pub struct NuSpecDependency {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "@include")]
    pub include: Option<String>,
    #[serde(rename = "@exclude")]
    pub exclude: Option<String>,
}

/// NuSpec framework assemblies
#[derive(Debug, Serialize, Deserialize)]
pub struct NuSpecFrameworkAssemblies {
    #[serde(default, rename = "frameworkAssembly")]
    pub assemblies: Vec<NuSpecFrameworkAssembly>,
}

/// NuSpec framework assembly
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NuSpecFrameworkAssembly {
    #[serde(rename = "@assemblyName")]
    pub assembly_name: String,
    #[serde(rename = "@targetFramework")]
    pub target_framework: Option<String>,
}

/// NuSpec repository
#[derive(Debug, Serialize, Deserialize)]
pub struct NuSpecRepository {
    #[serde(rename = "@type")]
    pub repo_type: Option<String>,
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "@branch")]
    pub branch: Option<String>,
    #[serde(rename = "@commit")]
    pub commit: Option<String>,
}

/// NuSpec license
#[derive(Debug, Serialize, Deserialize)]
pub struct NuSpecLicense {
    #[serde(rename = "@type")]
    pub license_type: Option<String>,
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

/// NuGet v3 service index
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceIndex {
    pub version: String,
    pub resources: Vec<ServiceResource>,
}

/// NuGet service resource
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceResource {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    pub resource_type: String,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Generate NuGet v3 service index
pub fn generate_service_index(base_url: &str) -> ServiceIndex {
    ServiceIndex {
        version: "3.0.0".to_string(),
        resources: vec![
            ServiceResource {
                id: format!("{}/v3/registration/", base_url),
                resource_type: "RegistrationsBaseUrl/3.6.0".to_string(),
                comment: Some("Package registrations".to_string()),
            },
            ServiceResource {
                id: format!("{}/v3-flatcontainer/", base_url),
                resource_type: "PackageBaseAddress/3.0.0".to_string(),
                comment: Some("Package content".to_string()),
            },
            ServiceResource {
                id: format!("{}/api/v2/package", base_url),
                resource_type: "PackagePublish/2.0.0".to_string(),
                comment: Some("Package publish endpoint".to_string()),
            },
            ServiceResource {
                id: format!("{}/query", base_url),
                resource_type: "SearchQueryService/3.5.0".to_string(),
                comment: Some("Search service".to_string()),
            },
        ],
    }
}

/// Package registration response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageRegistration {
    pub count: i32,
    pub items: Vec<RegistrationPage>,
}

/// Registration page
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationPage {
    pub count: i32,
    pub items: Vec<RegistrationLeaf>,
    pub lower: String,
    pub upper: String,
}

/// Registration leaf
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationLeaf {
    pub catalog_entry: CatalogEntry,
    pub package_content: String,
    pub registration: String,
}

/// Catalog entry
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub authors: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license_url: Option<String>,
    #[serde(default)]
    pub project_url: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nupkg_filename() {
        let (id, version) = NugetHandler::parse_nupkg_filename("Newtonsoft.Json.13.0.1.nupkg").unwrap();
        assert_eq!(id, "Newtonsoft.Json");
        assert_eq!(version, "13.0.1");
    }

    #[test]
    fn test_parse_nupkg_filename_simple() {
        let (id, version) = NugetHandler::parse_nupkg_filename("MyPackage.1.0.0.nupkg").unwrap();
        assert_eq!(id, "MyPackage");
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn test_parse_path_service_index() {
        let info = NugetHandler::parse_path("v3/index.json").unwrap();
        assert!(matches!(info.operation, NugetOperation::ServiceIndex));
    }

    #[test]
    fn test_parse_path_registration() {
        let info = NugetHandler::parse_path("v3/registration/newtonsoft.json/index.json").unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageRegistration));
        assert_eq!(info.id, Some("newtonsoft.json".to_string()));
    }

    #[test]
    fn test_parse_path_flatcontainer() {
        let info = NugetHandler::parse_path("v3-flatcontainer/mypackage/1.0.0/mypackage.1.0.0.nupkg").unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageContent));
        assert_eq!(info.id, Some("mypackage".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_normalize_id() {
        assert_eq!(NugetHandler::normalize_id("Newtonsoft.Json"), "newtonsoft.json");
        assert_eq!(NugetHandler::normalize_id("MyPackage"), "mypackage");
    }
}
