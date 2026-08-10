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
pub mod hex_registry;
pub mod huggingface;
pub mod incus;
pub mod jetbrains_plugins;
pub mod maven;
pub mod maven_version;
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
pub mod pypi_name;
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
        self.format().as_key()
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
        "maven" | "gradle" => Some(Box::new(maven::MavenHandler::new())),
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
        "incus" | "lxc" => Some(Box::new(incus::IncusHandler::new())),
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
        RepositoryFormat::Incus | RepositoryFormat::Lxc => Box::new(incus::IncusHandler::new()),
    }
}

/// List all supported core format keys.
///
/// Derived from [`RepositoryFormat::ALL`] rather than hand-maintained: the
/// previous literal list had silently lost `gradle` (#3157).
pub fn list_core_formats() -> Vec<&'static str> {
    RepositoryFormat::ALL.iter().map(|f| f.as_key()).collect()
}

// ---------------------------------------------------------------------------
// Compiled-in format handler registry (#3157)
// ---------------------------------------------------------------------------

/// A compiled-in ("core") format handler, as advertised by
/// `GET /api/v1/formats`.
///
/// One entry per *handler*, not per format alias: `gradle` is served by the
/// Maven handler and every OCI alias by the `oci` handler, so those collapse
/// onto a single entry — the same granularity the `format_handlers` table is
/// keyed by and the same granularity the enable/disable gate acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreFormatHandler {
    /// Handler key, e.g. `"pub"`. Matches `format_handlers.format_key`.
    pub format_key: &'static str,
    /// Human-readable name for the API/UI.
    pub display_name: &'static str,
    /// One-line description of the format.
    pub description: &'static str,
    /// File extensions the handler recognises. Advisory/display only.
    pub extensions: &'static [&'static str],
}

/// Every format handler compiled into this binary.
///
/// This is the authoritative answer to "which formats does the running
/// backend provide?" — it is *derived* from [`RepositoryFormat::ALL`] via
/// [`RepositoryFormat::handler_key`], so a format cannot be added to the
/// product without appearing here. `format_handlers` rows are synchronised
/// from this registry at startup
/// (`WasmPluginService::sync_core_format_handlers`), which makes the table an
/// enablement overlay on top of the registry instead of a second, hand-written
/// copy of it. Migration 014 seeded that table once with the 13 handlers that
/// existed at the time and it was never extended, so `GET /api/v1/formats` hid
/// ~24 shipped handlers including `pub` (#3157).
pub fn core_format_handlers() -> Vec<CoreFormatHandler> {
    let mut seen = std::collections::HashSet::new();
    let mut handlers = Vec::new();
    for format in RepositoryFormat::ALL {
        let key = format.handler_key();
        if seen.insert(key) {
            let (display_name, description, extensions) = core_handler_metadata(key);
            handlers.push(CoreFormatHandler {
                format_key: key,
                display_name,
                description,
                extensions,
            });
        }
    }
    handlers
}

/// Presentation metadata for a core handler key.
///
/// Deliberately total: an unrecognised key falls back to the key itself rather
/// than being dropped, so forgetting to add a line here can only cost a format
/// its pretty name — never its presence in the registry. Membership is decided
/// by [`RepositoryFormat::ALL`] alone.
fn core_handler_metadata(
    format_key: &'static str,
) -> (&'static str, &'static str, &'static [&'static str]) {
    match format_key {
        "maven" => (
            "Maven",
            "Maven repository format for Java artifacts",
            &[".jar", ".pom", ".war", ".ear"],
        ),
        "npm" => ("npm", "Node.js package manager", &[".tgz"]),
        "pypi" => ("PyPI", "Python Package Index", &[".whl", ".tar.gz"]),
        "nuget" => ("NuGet", ".NET package manager", &[".nupkg"]),
        "cargo" => ("Cargo", "Rust package manager", &[".crate"]),
        "go" => ("Go Modules", "Go module proxy", &[".zip", ".mod"]),
        "oci" => ("OCI/Docker", "Container images (OCI format)", &[]),
        "helm" => ("Helm", "Kubernetes package manager", &[".tgz"]),
        "debian" => ("Debian", "Debian packages", &[".deb"]),
        "rpm" => ("RPM", "Red Hat packages", &[".rpm"]),
        "rubygems" => ("RubyGems", "Ruby gems", &[".gem"]),
        "conan" => ("Conan", "C/C++ package manager", &[".tgz"]),
        "generic" => ("Generic", "Generic artifact storage", &[]),
        "terraform" => (
            "Terraform/OpenTofu",
            "Terraform and OpenTofu modules and providers",
            &[".zip"],
        ),
        "alpine" => ("Alpine", "Alpine Linux apk packages", &[".apk"]),
        "conda_native" => (
            "Conda",
            "Conda packages (native channel layout)",
            &[".conda", ".tar.bz2"],
        ),
        "composer" => ("Composer", "PHP package manager", &[".zip", ".tar"]),
        "hex" => ("Hex", "Elixir/Erlang package manager", &[".tar"]),
        "cocoapods" => ("CocoaPods", "Swift and Objective-C dependency manager", &[]),
        "swift" => ("Swift", "Swift Package Manager registry", &[".zip"]),
        "pub" => ("Pub", "Dart and Flutter package registry", &[".tar.gz"]),
        "sbt" => ("sbt", "Scala build tool plugins and artifacts", &[".jar"]),
        "chef" => ("Chef", "Chef cookbooks", &[".tar.gz"]),
        "puppet" => ("Puppet", "Puppet modules", &[".tar.gz"]),
        "ansible" => ("Ansible", "Ansible collections and roles", &[".tar.gz"]),
        "gitlfs" => ("Git LFS", "Git Large File Storage objects", &[]),
        "vscode" => (
            "VS Code Extensions",
            "Visual Studio Code compatible extensions",
            &[".vsix"],
        ),
        "jetbrains" => ("JetBrains Plugins", "JetBrains IDE plugins", &[".zip"]),
        "huggingface" => ("Hugging Face", "Hugging Face models and datasets", &[]),
        "mlmodel" => ("ML Models", "Machine-learning model artifacts", &[]),
        "cran" => ("CRAN", "R packages", &[".tar.gz"]),
        "vagrant" => ("Vagrant", "Vagrant boxes", &[".box"]),
        "opkg" => ("opkg", "OpenWrt/embedded Linux packages", &[".ipk"]),
        "p2" => ("Eclipse P2", "Eclipse P2 update sites", &[".jar"]),
        "bazel" => ("Bazel", "Bazel modules and rulesets", &[".tar.gz"]),
        "protobuf" => ("Protobuf", "Protocol Buffer schema registry", &[".proto"]),
        "incus" => ("Incus/LXC", "Incus and LXC container images", &[".tar.xz"]),
        // Total fallback -- see the doc comment. A format that reaches this
        // arm is still listed, it just shows its raw key as the display name.
        other => (other, "Compiled-in format handler", &[]),
    }
}

// ---------------------------------------------------------------------------
// Age-gate capability registry (#2264)
// ---------------------------------------------------------------------------

/// Per-format age-gate capability spec: the single registry every age-gate
/// capability decision derives from.
///
/// One spec per protocol family owns:
///   * the canonical format aliases collapse onto (`canonical`);
///   * the bounded metrics label (`label`);
///   * whether the upstream treats a published coordinate as immutable
///     (`immutable_coordinates`) — the trust prerequisite for `first_seen`:
///     a registry that permits overwrite or delete-and-republish can
///     substitute new content under an aged coordinate; and
///   * whether this server can resolve upstream publish times for the format
///     (`publish_time_resolver`) — the prerequisite for
///     `upstream_publish_time`.
///
/// Mode support follows from capabilities
/// (`AgeGateService::supports_format_mode`); the config endpoint and the
/// enforcement seam both read this registry, so there is no second
/// hand-maintained matrix to drift. Package identity is NOT derived here —
/// per the #2962 seam convention, each format's download handler passes the
/// identity it already parses.
pub struct AgeGateFormatSpec {
    pub canonical: RepositoryFormat,
    pub label: &'static str,
    pub immutable_coordinates: bool,
    pub publish_time_resolver: bool,
}

static NPM_AGE_GATE_SPEC: AgeGateFormatSpec = AgeGateFormatSpec {
    canonical: RepositoryFormat::Npm,
    label: "npm",
    // npm forbids republishing a (name, version) once published (even after
    // unpublish, the version number is burned).
    immutable_coordinates: true,
    // Packument `time` map.
    publish_time_resolver: true,
};

static PYPI_AGE_GATE_SPEC: AgeGateFormatSpec = AgeGateFormatSpec {
    canonical: RepositoryFormat::Pypi,
    label: "pypi",
    // PyPI forbids re-uploading a distribution filename once uploaded.
    immutable_coordinates: true,
    // Warehouse JSON `upload-time`.
    publish_time_resolver: true,
};

static GO_AGE_GATE_SPEC: AgeGateFormatSpec = AgeGateFormatSpec {
    canonical: RepositoryFormat::Go,
    label: "go",
    // Module proxies serve immutable, checksum-database-pinned versions: a
    // published (module, version) cannot be replaced with different content
    // without breaking go.sum verification.
    immutable_coordinates: true,
    // `.info` timestamps are VCS tag times the publisher controls — advisory
    // at best — so there is no trustworthy publish-time resolver; `first_seen`
    // is the only supported age source.
    publish_time_resolver: false,
};

/// Look up the age-gate capability spec for a repository format, collapsing
/// protocol aliases (yarn/pnpm speak npm; poetry speaks PyPI) onto the
/// canonical format that owns their policy. `None` means the format has no
/// age-gate support; the config endpoint rejects attempts to enable it.
pub fn age_gate_spec(format: &RepositoryFormat) -> Option<&'static AgeGateFormatSpec> {
    match format {
        RepositoryFormat::Npm | RepositoryFormat::Yarn | RepositoryFormat::Pnpm => {
            Some(&NPM_AGE_GATE_SPEC)
        }
        RepositoryFormat::Pypi | RepositoryFormat::Poetry => Some(&PYPI_AGE_GATE_SPEC),
        RepositoryFormat::Go => Some(&GO_AGE_GATE_SPEC),
        _ => None,
    }
}
