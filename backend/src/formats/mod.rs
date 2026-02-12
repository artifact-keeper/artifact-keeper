//! Package format handlers.

pub mod alpine;
pub mod ansible;
pub mod bazel;
pub mod cargo;
pub mod chef;
pub mod cocoapods;
pub mod composer;
pub mod conan;
pub mod conda_native;
pub mod cran;
pub mod debian;
pub mod generic;
pub mod gitlfs;
pub mod go;
pub mod helm;
pub mod hex;
pub mod huggingface;
pub mod jetbrains_plugins;
pub mod maven;
pub mod mlmodel;
pub mod npm;
pub mod nuget;
pub mod oci;
pub mod opkg;
pub mod p2;
pub mod protobuf;
pub mod r#pub;
pub mod puppet;
pub mod pypi;
pub mod rpm;
pub mod rubygems;
pub mod sbt;
pub mod swift;
pub mod terraform;
pub mod vagrant;
pub mod vscode_extensions;
pub mod wasm;

#[cfg(test)]
mod format_tests;

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
            RepositoryFormat::Podman => "podman",
            RepositoryFormat::Buildx => "buildx",
            RepositoryFormat::Oras => "oras",
            RepositoryFormat::WasmOci => "wasm_oci",
            RepositoryFormat::HelmOci => "helm_oci",
            RepositoryFormat::Poetry => "poetry",
            RepositoryFormat::Conda => "conda",
            RepositoryFormat::Yarn => "yarn",
            RepositoryFormat::Bower => "bower",
            RepositoryFormat::Pnpm => "pnpm",
            RepositoryFormat::Chocolatey => "chocolatey",
            RepositoryFormat::Powershell => "powershell",
            RepositoryFormat::Terraform => "terraform",
            RepositoryFormat::Opentofu => "opentofu",
            RepositoryFormat::Alpine => "alpine",
            RepositoryFormat::CondaNative => "conda_native",
            RepositoryFormat::Composer => "composer",
            RepositoryFormat::Hex => "hex",
            RepositoryFormat::Cocoapods => "cocoapods",
            RepositoryFormat::Swift => "swift",
            RepositoryFormat::Pub => "pub",
            RepositoryFormat::Sbt => "sbt",
            RepositoryFormat::Chef => "chef",
            RepositoryFormat::Puppet => "puppet",
            RepositoryFormat::Ansible => "ansible",
            RepositoryFormat::Gitlfs => "gitlfs",
            RepositoryFormat::Vscode => "vscode",
            RepositoryFormat::Jetbrains => "jetbrains",
            RepositoryFormat::Huggingface => "huggingface",
            RepositoryFormat::Mlmodel => "mlmodel",
            RepositoryFormat::Cran => "cran",
            RepositoryFormat::Vagrant => "vagrant",
            RepositoryFormat::Opkg => "opkg",
            RepositoryFormat::P2 => "p2",
            RepositoryFormat::Bazel => "bazel",
            RepositoryFormat::Protobuf => "protobuf",
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
        "docker" | "oci" | "podman" | "buildx" | "oras" | "wasm_oci" | "helm_oci" => {
            Some(Box::new(oci::OciHandler::new()))
        }
        "helm" => Some(Box::new(helm::HelmHandler::new())),
        "rpm" => Some(Box::new(rpm::RpmHandler::new())),
        "debian" => Some(Box::new(debian::DebianHandler::new())),
        "conan" => Some(Box::new(conan::ConanHandler::new())),
        "cargo" => Some(Box::new(cargo::CargoHandler::new())),
        "generic" => Some(Box::new(generic::GenericHandler::new())),
        "poetry" | "conda" => Some(Box::new(pypi::PypiHandler::new())),
        "yarn" | "bower" | "pnpm" => Some(Box::new(npm::NpmHandler::new())),
        "chocolatey" | "powershell" => Some(Box::new(nuget::NugetHandler::new())),
        "terraform" | "opentofu" => Some(Box::new(terraform::TerraformHandler::new())),
        "alpine" => Some(Box::new(alpine::AlpineHandler::new())),
        "conda_native" => Some(Box::new(conda_native::CondaNativeHandler::new())),
        "composer" => Some(Box::new(composer::ComposerHandler::new())),
        "hex" => Some(Box::new(hex::HexHandler::new())),
        "cocoapods" => Some(Box::new(cocoapods::CocoaPodsHandler::new())),
        "swift" => Some(Box::new(swift::SwiftHandler::new())),
        "pub" => Some(Box::new(r#pub::PubHandler::new())),
        "sbt" => Some(Box::new(sbt::SbtHandler::new())),
        "chef" => Some(Box::new(chef::ChefHandler::new())),
        "puppet" => Some(Box::new(puppet::PuppetHandler::new())),
        "ansible" => Some(Box::new(ansible::AnsibleHandler::new())),
        "gitlfs" => Some(Box::new(gitlfs::GitLfsHandler::new())),
        "vscode" | "cursor" | "windsurf" | "kiro" => {
            Some(Box::new(vscode_extensions::VscodeHandler::new()))
        }
        "jetbrains" => Some(Box::new(jetbrains_plugins::JetbrainsHandler::new())),
        "huggingface" => Some(Box::new(huggingface::HuggingFaceHandler::new())),
        "mlmodel" => Some(Box::new(mlmodel::MlModelHandler::new())),
        "cran" => Some(Box::new(cran::CranHandler::new())),
        "vagrant" => Some(Box::new(vagrant::VagrantHandler::new())),
        "opkg" => Some(Box::new(opkg::OpkgHandler::new())),
        "p2" => Some(Box::new(p2::P2Handler::new())),
        "bazel" => Some(Box::new(bazel::BazelHandler::new())),
        "protobuf" => Some(Box::new(protobuf::ProtobufHandler::new())),
        _ => None,
    }
}

/// Get a core format handler by RepositoryFormat enum.
pub fn get_handler_for_format(format: &RepositoryFormat) -> Box<dyn FormatHandler> {
    match format {
        RepositoryFormat::Maven | RepositoryFormat::Gradle => Box::new(maven::MavenHandler::new()),
        RepositoryFormat::Npm
        | RepositoryFormat::Yarn
        | RepositoryFormat::Bower
        | RepositoryFormat::Pnpm => Box::new(npm::NpmHandler::new()),
        RepositoryFormat::Pypi | RepositoryFormat::Poetry | RepositoryFormat::Conda => {
            Box::new(pypi::PypiHandler::new())
        }
        RepositoryFormat::Nuget | RepositoryFormat::Chocolatey | RepositoryFormat::Powershell => {
            Box::new(nuget::NugetHandler::new())
        }
        RepositoryFormat::Go => Box::new(go::GoHandler::new()),
        RepositoryFormat::Rubygems => Box::new(rubygems::RubygemsHandler::new()),
        RepositoryFormat::Docker
        | RepositoryFormat::Podman
        | RepositoryFormat::Buildx
        | RepositoryFormat::Oras
        | RepositoryFormat::WasmOci
        | RepositoryFormat::HelmOci => Box::new(oci::OciHandler::new()),
        RepositoryFormat::Helm => Box::new(helm::HelmHandler::new()),
        RepositoryFormat::Rpm => Box::new(rpm::RpmHandler::new()),
        RepositoryFormat::Debian => Box::new(debian::DebianHandler::new()),
        RepositoryFormat::Conan => Box::new(conan::ConanHandler::new()),
        RepositoryFormat::Cargo => Box::new(cargo::CargoHandler::new()),
        RepositoryFormat::Generic => Box::new(generic::GenericHandler::new()),
        RepositoryFormat::Terraform | RepositoryFormat::Opentofu => {
            Box::new(terraform::TerraformHandler::new())
        }
        RepositoryFormat::Alpine => Box::new(alpine::AlpineHandler::new()),
        RepositoryFormat::CondaNative => Box::new(conda_native::CondaNativeHandler::new()),
        RepositoryFormat::Composer => Box::new(composer::ComposerHandler::new()),
        RepositoryFormat::Hex => Box::new(hex::HexHandler::new()),
        RepositoryFormat::Cocoapods => Box::new(cocoapods::CocoaPodsHandler::new()),
        RepositoryFormat::Swift => Box::new(swift::SwiftHandler::new()),
        RepositoryFormat::Pub => Box::new(r#pub::PubHandler::new()),
        RepositoryFormat::Sbt => Box::new(sbt::SbtHandler::new()),
        RepositoryFormat::Chef => Box::new(chef::ChefHandler::new()),
        RepositoryFormat::Puppet => Box::new(puppet::PuppetHandler::new()),
        RepositoryFormat::Ansible => Box::new(ansible::AnsibleHandler::new()),
        RepositoryFormat::Gitlfs => Box::new(gitlfs::GitLfsHandler::new()),
        RepositoryFormat::Vscode => Box::new(vscode_extensions::VscodeHandler::new()),
        RepositoryFormat::Jetbrains => Box::new(jetbrains_plugins::JetbrainsHandler::new()),
        RepositoryFormat::Huggingface => Box::new(huggingface::HuggingFaceHandler::new()),
        RepositoryFormat::Mlmodel => Box::new(mlmodel::MlModelHandler::new()),
        RepositoryFormat::Cran => Box::new(cran::CranHandler::new()),
        RepositoryFormat::Vagrant => Box::new(vagrant::VagrantHandler::new()),
        RepositoryFormat::Opkg => Box::new(opkg::OpkgHandler::new()),
        RepositoryFormat::P2 => Box::new(p2::P2Handler::new()),
        RepositoryFormat::Bazel => Box::new(bazel::BazelHandler::new()),
        RepositoryFormat::Protobuf => Box::new(protobuf::ProtobufHandler::new()),
    }
}

/// List all supported core format keys.
pub fn list_core_formats() -> Vec<&'static str> {
    vec![
        "maven",
        "npm",
        "pypi",
        "nuget",
        "go",
        "rubygems",
        "docker",
        "helm",
        "rpm",
        "debian",
        "conan",
        "cargo",
        "generic",
        "podman",
        "buildx",
        "oras",
        "wasm_oci",
        "helm_oci",
        "poetry",
        "conda",
        "yarn",
        "bower",
        "pnpm",
        "chocolatey",
        "powershell",
        "terraform",
        "opentofu",
        "alpine",
        "conda_native",
        "composer",
        "hex",
        "cocoapods",
        "swift",
        "pub",
        "sbt",
        "chef",
        "puppet",
        "ansible",
        "gitlfs",
        "vscode",
        "jetbrains",
        "huggingface",
        "mlmodel",
        "cran",
        "vagrant",
        "opkg",
        "p2",
        "bazel",
        "protobuf",
    ]
}
