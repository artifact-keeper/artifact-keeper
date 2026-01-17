//! Package format handlers.

pub mod cargo;
pub mod conan;
pub mod debian;
pub mod generic;
pub mod go;
pub mod helm;
pub mod maven;
pub mod npm;
pub mod nuget;
pub mod oci;
pub mod pypi;
pub mod rpm;
pub mod rubygems;
pub mod wasm;

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::Result;
use crate::models::repository::RepositoryFormat;

/// Package format handler trait.
///
/// Implemented by both compiled-in Rust handlers and WASM plugin wrappers.
/// Services use this trait without knowing the underlying implementation.
#[async_trait]
pub trait FormatHandler: Send + Sync {
    /// Get the format type this handler supports.
    ///
    /// For WASM plugins, this returns Generic since the actual format
    /// is identified by format_key().
    fn format(&self) -> RepositoryFormat;

    /// Get the format key string.
    ///
    /// For core handlers, this matches the RepositoryFormat enum value.
    /// For WASM plugins, this is the custom format key from the manifest.
    fn format_key(&self) -> &str {
        match self.format() {
            RepositoryFormat::Maven => "maven",
            RepositoryFormat::Gradle => "gradle",
            RepositoryFormat::Npm => "npm",
            RepositoryFormat::Pypi => "pypi",
            RepositoryFormat::Nuget => "nuget",
            RepositoryFormat::Go => "go",
            RepositoryFormat::Rubygems => "rubygems",
            RepositoryFormat::Docker => "docker",
            RepositoryFormat::Helm => "helm",
            RepositoryFormat::Rpm => "rpm",
            RepositoryFormat::Debian => "debian",
            RepositoryFormat::Conan => "conan",
            RepositoryFormat::Cargo => "cargo",
            RepositoryFormat::Generic => "generic",
        }
    }

    /// Check if this handler is backed by a WASM plugin.
    fn is_wasm_plugin(&self) -> bool {
        false
    }

    /// Parse artifact metadata from content.
    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value>;

    /// Validate artifact before storage.
    async fn validate(&self, path: &str, content: &Bytes) -> Result<()>;

    /// Generate index/metadata files for the repository (if applicable).
    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>>;
}

/// Get a core format handler by format key.
///
/// Returns None for unknown format keys. For WASM plugins,
/// use the WasmFormatHandlerFactory instead.
pub fn get_core_handler(format_key: &str) -> Option<Box<dyn FormatHandler>> {
    match format_key {
        "maven" => Some(Box::new(maven::MavenHandler::new())),
        "npm" => Some(Box::new(npm::NpmHandler::new())),
        "pypi" => Some(Box::new(pypi::PypiHandler::new())),
        "nuget" => Some(Box::new(nuget::NugetHandler::new())),
        "go" => Some(Box::new(go::GoHandler::new())),
        "rubygems" => Some(Box::new(rubygems::RubygemsHandler::new())),
        "docker" | "oci" => Some(Box::new(oci::OciHandler::new())),
        "helm" => Some(Box::new(helm::HelmHandler::new())),
        "rpm" => Some(Box::new(rpm::RpmHandler::new())),
        "debian" => Some(Box::new(debian::DebianHandler::new())),
        "conan" => Some(Box::new(conan::ConanHandler::new())),
        "cargo" => Some(Box::new(cargo::CargoHandler::new())),
        "generic" => Some(Box::new(generic::GenericHandler::new())),
        _ => None,
    }
}

/// Get a core format handler by RepositoryFormat enum.
pub fn get_handler_for_format(format: &RepositoryFormat) -> Box<dyn FormatHandler> {
    match format {
        RepositoryFormat::Maven | RepositoryFormat::Gradle => Box::new(maven::MavenHandler::new()),
        RepositoryFormat::Npm => Box::new(npm::NpmHandler::new()),
        RepositoryFormat::Pypi => Box::new(pypi::PypiHandler::new()),
        RepositoryFormat::Nuget => Box::new(nuget::NugetHandler::new()),
        RepositoryFormat::Go => Box::new(go::GoHandler::new()),
        RepositoryFormat::Rubygems => Box::new(rubygems::RubygemsHandler::new()),
        RepositoryFormat::Docker => Box::new(oci::OciHandler::new()),
        RepositoryFormat::Helm => Box::new(helm::HelmHandler::new()),
        RepositoryFormat::Rpm => Box::new(rpm::RpmHandler::new()),
        RepositoryFormat::Debian => Box::new(debian::DebianHandler::new()),
        RepositoryFormat::Conan => Box::new(conan::ConanHandler::new()),
        RepositoryFormat::Cargo => Box::new(cargo::CargoHandler::new()),
        RepositoryFormat::Generic => Box::new(generic::GenericHandler::new()),
    }
}

/// List all supported core format keys.
pub fn list_core_formats() -> Vec<&'static str> {
    vec![
        "maven", "npm", "pypi", "nuget", "go", "rubygems",
        "docker", "helm", "rpm", "debian", "conan", "cargo", "generic",
    ]
}
