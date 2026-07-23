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
            if !found_version
                && part
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
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

    /// Map an AK-normalized NuGet v3 request path to the **upstream** URL, using
    /// the upstream feed's own service index to discover its resource base URLs.
    ///
    /// NuGet v3 is non-uniform: the configured `upstream_url` is the *service
    /// index*, and the real `PackageBaseAddress` (flat-container) and
    /// `RegistrationsBaseUrl` bases are listed *inside* it and differ per feed
    /// (e.g. nuget.org serves flat-container at `/v3-flatcontainer/` and
    /// registration at `/v3/registration5-*/`). Naively appending the request
    /// path to `upstream_url` produces `.../v3/index.json/v3/flatcontainer/...`
    /// which the upstream rejects with 400 (surfaced to the client as 502).
    /// Resolving the bases from the service index fixes it for any conformant
    /// v3 feed instead of hard-coding nuget.org's layout.
    pub fn resolve_upstream_url(
        service_index: &ServiceIndex,
        upstream_url: &str,
        ak_path: &str,
    ) -> Result<String> {
        let path = ak_path.trim_start_matches('/');

        // The service index itself is fetched from the configured upstream URL.
        if path == "v3/index.json" || path == "index.json" {
            return Ok(upstream_url.to_string());
        }

        // Flat-container: package versions listing + package content (.nupkg).
        for prefix in ["v3/flatcontainer/", "v3-flatcontainer/", "flatcontainer/"] {
            if let Some(rest) = path.strip_prefix(prefix) {
                let base =
                    Self::resource_base(service_index, "PackageBaseAddress").ok_or_else(|| {
                        AppError::BadGateway(
                            "upstream NuGet service index has no PackageBaseAddress resource"
                                .to_string(),
                        )
                    })?;
                return Ok(format!("{}/{}", base.trim_end_matches('/'), rest));
            }
        }

        // Registration: package + version registration.
        for prefix in ["v3/registration/", "registration/"] {
            if let Some(rest) = path.strip_prefix(prefix) {
                let base = Self::resource_base(service_index, "RegistrationsBaseUrl").ok_or_else(
                    || {
                        AppError::BadGateway(
                            "upstream NuGet service index has no RegistrationsBaseUrl resource"
                                .to_string(),
                        )
                    },
                )?;
                return Ok(format!("{}/{}", base.trim_end_matches('/'), rest));
            }
        }

        // Unknown path shape: fall back to joining against the feed root (the
        // configured URL with a trailing `index.json` stripped).
        let root = upstream_url
            .trim_end_matches('/')
            .trim_end_matches("index.json")
            .trim_end_matches('/');
        Ok(format!("{}/{}", root, path))
    }

    /// Base URL of the service-index resource whose `@type` starts with
    /// `type_prefix`, preferring the plainest variant (no gzip / SemVer2, checked
    /// across both `@type` and `@id`) for the widest client compatibility.
    fn resource_base<'a>(index: &'a ServiceIndex, type_prefix: &str) -> Option<&'a str> {
        index
            .resources
            .iter()
            .filter(|r| r.resource_type.starts_with(type_prefix))
            .min_by_key(|r| {
                let s = format!("{} {}", r.resource_type, r.id).to_lowercase();
                (s.contains("gz") as u8, s.contains("semver2") as u8)
            })
            .map(|r| r.id.as_str())
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

    // ---- resolve_upstream_url (remote-proxy v3 resolution) ----

    fn nuget_org_index() -> ServiceIndex {
        ServiceIndex {
            version: "3.0.0".to_string(),
            resources: vec![
                ServiceResource {
                    id: "https://api.nuget.org/v3-flatcontainer/".to_string(),
                    resource_type: "PackageBaseAddress/3.0.0".to_string(),
                    comment: None,
                },
                ServiceResource {
                    id: "https://api.nuget.org/v3/registration5-semver1/".to_string(),
                    resource_type: "RegistrationsBaseUrl".to_string(),
                    comment: None,
                },
                ServiceResource {
                    id: "https://api.nuget.org/v3/registration5-gz-semver2/".to_string(),
                    resource_type: "RegistrationsBaseUrl/3.6.0".to_string(),
                    comment: None,
                },
            ],
        }
    }

    #[test]
    fn test_resolve_upstream_url_flatcontainer() {
        let idx = nuget_org_index();
        let up = "https://api.nuget.org/v3/index.json";
        assert_eq!(
            NugetHandler::resolve_upstream_url(
                &idx,
                up,
                "v3/flatcontainer/newtonsoft.json/index.json"
            )
            .unwrap(),
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
        );
        assert_eq!(
            NugetHandler::resolve_upstream_url(
                &idx,
                up,
                "v3/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
            )
            .unwrap(),
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
        );
    }

    #[test]
    fn test_resolve_upstream_url_registration_prefers_plain() {
        let idx = nuget_org_index();
        let up = "https://api.nuget.org/v3/index.json";
        // Prefer the non-gzip / non-SemVer2 registration base for compatibility.
        assert_eq!(
            NugetHandler::resolve_upstream_url(
                &idx,
                up,
                "v3/registration/newtonsoft.json/index.json"
            )
            .unwrap(),
            "https://api.nuget.org/v3/registration5-semver1/newtonsoft.json/index.json"
        );
    }

    #[test]
    fn test_resolve_upstream_url_service_index_passthrough() {
        let idx = nuget_org_index();
        let up = "https://api.nuget.org/v3/index.json";
        assert_eq!(
            NugetHandler::resolve_upstream_url(&idx, up, "v3/index.json").unwrap(),
            up
        );
    }

    #[test]
    fn test_resolve_upstream_url_missing_resource_is_bad_gateway() {
        let idx = ServiceIndex {
            version: "3.0.0".to_string(),
            resources: vec![],
        };
        let up = "https://api.nuget.org/v3/index.json";
        assert!(
            NugetHandler::resolve_upstream_url(&idx, up, "v3/flatcontainer/x/index.json").is_err()
        );
    }

    // ---- NugetHandler::new / Default ----

    #[test]
    fn test_new_and_default() {
        let _h1 = NugetHandler::new();
        let _h2 = NugetHandler;
    }

    // ---- normalize_id ----

    #[test]
    fn test_normalize_id() {
        assert_eq!(
            NugetHandler::normalize_id("Newtonsoft.Json"),
            "newtonsoft.json"
        );
        assert_eq!(NugetHandler::normalize_id("MyPackage"), "mypackage");
    }

    #[test]
    fn test_normalize_id_already_lower() {
        assert_eq!(NugetHandler::normalize_id("mypackage"), "mypackage");
    }

    #[test]
    fn test_normalize_id_empty() {
        assert_eq!(NugetHandler::normalize_id(""), "");
    }

    // ---- parse_nupkg_filename ----

    #[test]
    fn test_parse_nupkg_filename() {
        let (id, version) =
            NugetHandler::parse_nupkg_filename("Newtonsoft.Json.13.0.1.nupkg").unwrap();
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
    fn test_parse_nupkg_filename_complex_id() {
        let (id, version) = NugetHandler::parse_nupkg_filename(
            "Microsoft.Extensions.DependencyInjection.8.0.0.nupkg",
        )
        .unwrap();
        assert_eq!(id, "Microsoft.Extensions.DependencyInjection");
        assert_eq!(version, "8.0.0");
    }

    #[test]
    fn test_parse_nupkg_filename_prerelease() {
        let (id, version) =
            NugetHandler::parse_nupkg_filename("MyPackage.1.0.0-beta.1.nupkg").unwrap();
        assert_eq!(id, "MyPackage");
        // "1" starts with a digit so the version begins at "1.0.0-beta.1"
        assert_eq!(version, "1.0.0-beta.1");
    }

    #[test]
    fn test_parse_nupkg_filename_no_version() {
        // All parts are alpha - no part starts with a digit
        let result = NugetHandler::parse_nupkg_filename("AllAlpha.Parts.nupkg");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nupkg_filename_no_id() {
        // Starts with digit immediately, so id_parts is empty
        let result = NugetHandler::parse_nupkg_filename("1.0.0.nupkg");
        assert!(result.is_err());
    }

    // ---- parse_path: service index ----

    #[test]
    fn test_parse_path_service_index() {
        let info = NugetHandler::parse_path("v3/index.json").unwrap();
        assert!(matches!(info.operation, NugetOperation::ServiceIndex));
        assert!(info.id.is_none());
        assert!(info.version.is_none());
        assert!(info.filename.is_none());
    }

    #[test]
    fn test_parse_path_service_index_short() {
        let info = NugetHandler::parse_path("index.json").unwrap();
        assert!(matches!(info.operation, NugetOperation::ServiceIndex));
    }

    #[test]
    fn test_parse_path_service_index_leading_slash() {
        let info = NugetHandler::parse_path("/v3/index.json").unwrap();
        assert!(matches!(info.operation, NugetOperation::ServiceIndex));
    }

    // ---- parse_path: registration ----

    #[test]
    fn test_parse_path_registration() {
        let info = NugetHandler::parse_path("v3/registration/newtonsoft.json/index.json").unwrap();
        assert!(matches!(
            info.operation,
            NugetOperation::PackageRegistration
        ));
        assert_eq!(info.id, Some("newtonsoft.json".to_string()));
        assert!(info.version.is_none());
    }

    #[test]
    fn test_parse_path_registration_without_v3_prefix() {
        let info = NugetHandler::parse_path("registration/newtonsoft.json/index.json").unwrap();
        assert!(matches!(
            info.operation,
            NugetOperation::PackageRegistration
        ));
        assert_eq!(info.id, Some("newtonsoft.json".to_string()));
    }

    #[test]
    fn test_parse_path_version_registration() {
        let info = NugetHandler::parse_path("v3/registration/newtonsoft.json/13.0.1.json").unwrap();
        assert!(matches!(
            info.operation,
            NugetOperation::VersionRegistration
        ));
        assert_eq!(info.id, Some("newtonsoft.json".to_string()));
        assert_eq!(info.version, Some("13.0.1".to_string()));
    }

    #[test]
    fn test_parse_path_version_registration_without_v3() {
        let info = NugetHandler::parse_path("registration/mypackage/2.0.0.json").unwrap();
        assert!(matches!(
            info.operation,
            NugetOperation::VersionRegistration
        ));
        assert_eq!(info.id, Some("mypackage".to_string()));
        assert_eq!(info.version, Some("2.0.0".to_string()));
    }

    // ---- parse_path: flatcontainer ----

    #[test]
    fn test_parse_path_flatcontainer() {
        let info =
            NugetHandler::parse_path("v3-flatcontainer/mypackage/1.0.0/mypackage.1.0.0.nupkg")
                .unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageContent));
        assert_eq!(info.id, Some("mypackage".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert_eq!(info.filename, Some("mypackage.1.0.0.nupkg".to_string()));
    }

    #[test]
    fn test_parse_path_flatcontainer_v3_prefix() {
        let info =
            NugetHandler::parse_path("v3/flatcontainer/mypackage/1.0.0/mypackage.1.0.0.nupkg")
                .unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageContent));
        assert_eq!(info.id, Some("mypackage".to_string()));
    }

    #[test]
    fn test_parse_path_flatcontainer_no_prefix() {
        let info = NugetHandler::parse_path("flatcontainer/mypackage/1.0.0/mypackage.1.0.0.nupkg")
            .unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageContent));
    }

    #[test]
    fn test_parse_path_flatcontainer_index() {
        let info = NugetHandler::parse_path("v3/flatcontainer/mypackage/index.json").unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageVersions));
        assert_eq!(info.id, Some("mypackage".to_string()));
        assert!(info.version.is_none());
    }

    #[test]
    fn test_parse_path_flatcontainer_v3_dash_index() {
        let info = NugetHandler::parse_path("v3-flatcontainer/mypackage/index.json").unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageVersions));
        assert_eq!(info.id, Some("mypackage".to_string()));
    }

    // ---- parse_path: direct .nupkg ----

    #[test]
    fn test_parse_path_direct_nupkg() {
        let info = NugetHandler::parse_path("MyPackage.1.0.0.nupkg").unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageContent));
        assert_eq!(info.id, Some("MyPackage".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert_eq!(info.filename, Some("MyPackage.1.0.0.nupkg".to_string()));
    }

    #[test]
    fn test_parse_path_direct_nupkg_in_subdir() {
        let info = NugetHandler::parse_path("some/path/Newtonsoft.Json.13.0.1.nupkg").unwrap();
        assert!(matches!(info.operation, NugetOperation::PackageContent));
        assert_eq!(info.id, Some("Newtonsoft.Json".to_string()));
        assert_eq!(info.version, Some("13.0.1".to_string()));
    }

    // ---- parse_path: invalid ----

    #[test]
    fn test_parse_path_invalid() {
        assert!(NugetHandler::parse_path("random/path/file.txt").is_err());
    }

    #[test]
    fn test_parse_path_empty() {
        assert!(NugetHandler::parse_path("").is_err());
    }

    #[test]
    fn test_parse_path_registration_too_few_parts() {
        // registration/<id> with no second part
        // This falls through because parts.len() < 2
        assert!(NugetHandler::parse_path("v3/registration/").is_err());
    }

    // ---- extract_nuspec: error cases ----

    #[test]
    fn test_extract_nuspec_invalid_bytes() {
        let result = NugetHandler::extract_nuspec(b"not a zip");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_nuspec_empty() {
        let result = NugetHandler::extract_nuspec(b"");
        assert!(result.is_err());
    }

    // ---- generate_service_index ----

    #[test]
    fn test_generate_service_index() {
        let index = generate_service_index("https://nuget.example.com");
        assert_eq!(index.version, "3.0.0");
        assert_eq!(index.resources.len(), 4);

        let reg = &index.resources[0];
        assert_eq!(reg.id, "https://nuget.example.com/v3/registration/");
        assert_eq!(reg.resource_type, "RegistrationsBaseUrl/3.6.0");
        assert!(reg.comment.is_some());

        let flat = &index.resources[1];
        assert_eq!(flat.id, "https://nuget.example.com/v3-flatcontainer/");
        assert_eq!(flat.resource_type, "PackageBaseAddress/3.0.0");

        let publish = &index.resources[2];
        assert_eq!(publish.id, "https://nuget.example.com/api/v2/package");
        assert_eq!(publish.resource_type, "PackagePublish/2.0.0");

        let search = &index.resources[3];
        assert_eq!(search.id, "https://nuget.example.com/query");
        assert_eq!(search.resource_type, "SearchQueryService/3.5.0");
    }

    // ---- ServiceIndex serde roundtrip ----

    #[test]
    fn test_service_index_roundtrip() {
        let index = generate_service_index("https://example.com");
        let json = serde_json::to_string(&index).unwrap();
        let parsed: ServiceIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "3.0.0");
        assert_eq!(parsed.resources.len(), 4);
    }

    // ---- CatalogEntry serde ----

    #[test]
    fn test_catalog_entry_deserialize() {
        let json = r#"{
            "id": "MyPackage",
            "version": "1.0.0",
            "authors": "Author",
            "description": "Desc",
            "licenseUrl": "https://license.example.com",
            "projectUrl": "https://project.example.com",
            "tags": ["tag1", "tag2"]
        }"#;
        let entry: CatalogEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.id, "MyPackage");
        assert_eq!(entry.version, "1.0.0");
        assert_eq!(entry.authors, Some("Author".to_string()));
        assert_eq!(entry.description, Some("Desc".to_string()));
        assert_eq!(
            entry.tags,
            Some(vec!["tag1".to_string(), "tag2".to_string()])
        );
    }

    #[test]
    fn test_catalog_entry_minimal() {
        let json = r#"{"id": "pkg", "version": "1.0.0"}"#;
        let entry: CatalogEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.id, "pkg");
        assert!(entry.authors.is_none());
        assert!(entry.description.is_none());
        assert!(entry.tags.is_none());
    }

    // ---- PackageRegistration / RegistrationPage / RegistrationLeaf serde ----

    #[test]
    fn test_registration_types_roundtrip() {
        let leaf = RegistrationLeaf {
            catalog_entry: CatalogEntry {
                id: "pkg".to_string(),
                version: "1.0.0".to_string(),
                authors: None,
                description: None,
                license_url: None,
                project_url: None,
                tags: None,
            },
            package_content: "https://example.com/pkg.1.0.0.nupkg".to_string(),
            registration: "https://example.com/reg/pkg/1.0.0.json".to_string(),
        };
        let page = RegistrationPage {
            count: 1,
            items: vec![leaf],
            lower: "1.0.0".to_string(),
            upper: "1.0.0".to_string(),
        };
        let reg = PackageRegistration {
            count: 1,
            items: vec![page],
        };
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: PackageRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.count, 1);
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].items[0].catalog_entry.id, "pkg");
    }

    // ---- parse_path: uppercase ID normalization ----

    #[test]
    fn test_parse_path_registration_normalizes_id() {
        let info = NugetHandler::parse_path("v3/registration/Newtonsoft.Json/index.json").unwrap();
        // normalize_id lowercases
        assert_eq!(info.id, Some("newtonsoft.json".to_string()));
    }

    #[test]
    fn test_parse_path_flatcontainer_normalizes_id() {
        let info = NugetHandler::parse_path(
            "v3/flatcontainer/Newtonsoft.Json/13.0.1/Newtonsoft.Json.13.0.1.nupkg",
        )
        .unwrap();
        assert_eq!(info.id, Some("newtonsoft.json".to_string()));
    }

    // ---- NuSpecLicense / NuSpecRepository serde ----

    #[test]
    fn test_nuspec_license_deserialize() {
        let json = r#"{"@type": "expression", "$value": "MIT"}"#;
        let lic: NuSpecLicense = serde_json::from_str(json).unwrap();
        assert_eq!(lic.license_type, Some("expression".to_string()));
        assert_eq!(lic.value, Some("MIT".to_string()));
    }

    #[test]
    fn test_nuspec_repository_deserialize() {
        let json = r#"{"@type": "git", "@url": "https://github.com/user/repo", "@branch": "main", "@commit": "abc123"}"#;
        let repo: NuSpecRepository = serde_json::from_str(json).unwrap();
        assert_eq!(repo.repo_type, Some("git".to_string()));
        assert_eq!(repo.url, Some("https://github.com/user/repo".to_string()));
        assert_eq!(repo.branch, Some("main".to_string()));
        assert_eq!(repo.commit, Some("abc123".to_string()));
    }
}
