//! Terraform/OpenTofu registry format handler.
//!
//! Implements the Terraform Registry Protocol for providers and modules.
//! OpenTofu uses the same protocol.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Terraform format handler
pub struct TerraformHandler;

impl TerraformHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Terraform registry path.
    ///
    /// Providers: `<namespace>/<type>/versions` or `<namespace>/<type>/<version>/download/<os>/<arch>`
    /// Modules: `<namespace>/<name>/<provider>/versions` or `<namespace>/<name>/<provider>/<version>/download`
    pub fn parse_path(path: &str) -> Result<TerraformPathInfo> {
        let path = path.trim_start_matches('/');
        let parts: Vec<&str> = path.split('/').collect();

        match parts.as_slice() {
            // Provider version listing: <namespace>/<type>/versions
            [namespace, type_name, "versions"] => Ok(TerraformPathInfo {
                kind: TerraformArtifactKind::Provider,
                namespace: namespace.to_string(),
                name: type_name.to_string(),
                provider: None,
                version: None,
                os: None,
                arch: None,
                is_version_listing: true,
            }),
            // Provider download: <namespace>/<type>/<version>/download/<os>/<arch>
            [namespace, type_name, version, "download", os, arch] => Ok(TerraformPathInfo {
                kind: TerraformArtifactKind::Provider,
                namespace: namespace.to_string(),
                name: type_name.to_string(),
                provider: None,
                version: Some(version.to_string()),
                os: Some(os.to_string()),
                arch: Some(arch.to_string()),
                is_version_listing: false,
            }),
            // Module version listing: <namespace>/<name>/<provider>/versions
            [namespace, name, provider, "versions"] => Ok(TerraformPathInfo {
                kind: TerraformArtifactKind::Module,
                namespace: namespace.to_string(),
                name: name.to_string(),
                provider: Some(provider.to_string()),
                version: None,
                os: None,
                arch: None,
                is_version_listing: true,
            }),
            // Module download: <namespace>/<name>/<provider>/<version>/download
            [namespace, name, provider, version, "download"] => Ok(TerraformPathInfo {
                kind: TerraformArtifactKind::Module,
                namespace: namespace.to_string(),
                name: name.to_string(),
                provider: Some(provider.to_string()),
                version: Some(version.to_string()),
                os: None,
                arch: None,
                is_version_listing: false,
            }),
            // Direct archive upload: <namespace>/<name>-<version>.zip
            [namespace, filename] if filename.ends_with(".zip") => {
                let stem = filename.trim_end_matches(".zip");
                let (name, version) = stem.rsplit_once('-').ok_or_else(|| {
                    AppError::Validation(format!("Invalid filename: {}", filename))
                })?;
                Ok(TerraformPathInfo {
                    kind: TerraformArtifactKind::Archive,
                    namespace: namespace.to_string(),
                    name: name.to_string(),
                    provider: None,
                    version: Some(version.to_string()),
                    os: None,
                    arch: None,
                    is_version_listing: false,
                })
            }
            _ => Err(AppError::Validation(format!(
                "Invalid Terraform registry path: {}",
                path
            ))),
        }
    }
}

impl Default for TerraformHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for TerraformHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Terraform
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "kind": match info.kind {
                TerraformArtifactKind::Provider => "provider",
                TerraformArtifactKind::Module => "module",
                TerraformArtifactKind::Archive => "archive",
            },
            "namespace": info.namespace,
            "name": info.name,
        });

        if let Some(provider) = &info.provider {
            metadata["provider"] = serde_json::Value::String(provider.clone());
        }
        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }
        if let Some(os) = &info.os {
            metadata["os"] = serde_json::Value::String(os.clone());
        }
        if let Some(arch) = &info.arch {
            metadata["arch"] = serde_json::Value::String(arch.clone());
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

/// Terraform artifact kind
#[derive(Debug, Clone)]
pub enum TerraformArtifactKind {
    Provider,
    Module,
    Archive,
}

/// Terraform path info
#[derive(Debug)]
pub struct TerraformPathInfo {
    pub kind: TerraformArtifactKind,
    pub namespace: String,
    pub name: String,
    pub provider: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub is_version_listing: bool,
}

/// Terraform provider version response
#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderVersions {
    pub versions: Vec<ProviderVersion>,
}

/// Single provider version
#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderVersion {
    pub version: String,
    pub protocols: Vec<String>,
    pub platforms: Vec<ProviderPlatform>,
}

/// Provider platform (os/arch)
#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderPlatform {
    pub os: String,
    pub arch: String,
}

/// Module version listing response
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleVersions {
    pub modules: Vec<ModuleVersionList>,
}

/// Module version list
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleVersionList {
    pub versions: Vec<ModuleVersion>,
}

/// Single module version
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleVersion {
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_provider_versions() {
        let info = TerraformHandler::parse_path("hashicorp/aws/versions").unwrap();
        assert!(matches!(info.kind, TerraformArtifactKind::Provider));
        assert_eq!(info.namespace, "hashicorp");
        assert_eq!(info.name, "aws");
        assert!(info.is_version_listing);
    }

    #[test]
    fn test_parse_provider_download() {
        let info =
            TerraformHandler::parse_path("hashicorp/aws/5.0.0/download/linux/amd64").unwrap();
        assert!(matches!(info.kind, TerraformArtifactKind::Provider));
        assert_eq!(info.namespace, "hashicorp");
        assert_eq!(info.name, "aws");
        assert_eq!(info.version, Some("5.0.0".to_string()));
        assert_eq!(info.os, Some("linux".to_string()));
        assert_eq!(info.arch, Some("amd64".to_string()));
    }

    #[test]
    fn test_parse_module_versions() {
        let info = TerraformHandler::parse_path("hashicorp/consul/aws/versions").unwrap();
        assert!(matches!(info.kind, TerraformArtifactKind::Module));
        assert_eq!(info.namespace, "hashicorp");
        assert_eq!(info.name, "consul");
        assert_eq!(info.provider, Some("aws".to_string()));
    }

    #[test]
    fn test_parse_module_download() {
        let info = TerraformHandler::parse_path("hashicorp/consul/aws/0.1.0/download").unwrap();
        assert!(matches!(info.kind, TerraformArtifactKind::Module));
        assert_eq!(info.version, Some("0.1.0".to_string()));
    }
}
