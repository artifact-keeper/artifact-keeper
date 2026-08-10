//! Repository model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Repository format enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "repository_format", rename_all = "lowercase")]
pub enum RepositoryFormat {
    Maven,
    Gradle,
    Npm,
    Pypi,
    Nuget,
    Go,
    Rubygems,
    Docker,
    Helm,
    Rpm,
    Debian,
    Conan,
    Cargo,
    Generic,
    // OCI-based aliases
    Podman,
    Buildx,
    Oras,
    #[sqlx(rename = "wasm_oci")]
    WasmOci,
    #[sqlx(rename = "helm_oci")]
    HelmOci,
    // PyPI-based aliases
    Poetry,
    Conda,
    // npm-based aliases
    Yarn,
    Bower,
    Pnpm,
    // NuGet-based aliases
    Chocolatey,
    Powershell,
    // Native format handlers
    Terraform,
    Opentofu,
    Alpine,
    #[sqlx(rename = "conda_native")]
    CondaNative,
    Composer,
    // Language-specific
    Hex,
    Cocoapods,
    Swift,
    Pub,
    Sbt,
    // Config management
    Chef,
    Puppet,
    Ansible,
    // Git LFS
    Gitlfs,
    // Editor extensions
    Vscode,
    Jetbrains,
    // ML/AI
    Huggingface,
    Mlmodel,
    // Miscellaneous
    Cran,
    Vagrant,
    Opkg,
    P2,
    Bazel,
    // Schema registries
    Protobuf,
    // Container images
    Incus,
    Lxc,
}

impl RepositoryFormat {
    /// Every built-in repository format, in declaration order.
    ///
    /// This is the single enumeration of the variant set: `list_core_formats`,
    /// the compiled-in format-handler registry
    /// ([`crate::formats::core_format_handlers`]) and the test helpers all
    /// derive from it instead of keeping their own copies. Before #3157 there
    /// were four separate hand-written lists of formats and three of them had
    /// silently drifted (the `format_handlers` seed in migration 014 stopped at
    /// the original 13, `list_core_formats` was missing `gradle`, and the test
    /// helper was missing `protobuf`/`incus`/`lxc`).
    ///
    /// A new variant must be added here as well. That is checked, not trusted:
    /// `as_key`/`handler_key` are exhaustive matches (a new variant fails the
    /// build until they are extended), and `test_all_matches_database_enum`
    /// compares this list against `enum_range(NULL::repository_format)` — the
    /// label set the migrations create — so an omission fails CI against an
    /// independently maintained source rather than drifting silently.
    pub const ALL: &'static [RepositoryFormat] = &[
        RepositoryFormat::Maven,
        RepositoryFormat::Gradle,
        RepositoryFormat::Npm,
        RepositoryFormat::Pypi,
        RepositoryFormat::Nuget,
        RepositoryFormat::Go,
        RepositoryFormat::Rubygems,
        RepositoryFormat::Docker,
        RepositoryFormat::Helm,
        RepositoryFormat::Rpm,
        RepositoryFormat::Debian,
        RepositoryFormat::Conan,
        RepositoryFormat::Cargo,
        RepositoryFormat::Generic,
        RepositoryFormat::Podman,
        RepositoryFormat::Buildx,
        RepositoryFormat::Oras,
        RepositoryFormat::WasmOci,
        RepositoryFormat::HelmOci,
        RepositoryFormat::Poetry,
        RepositoryFormat::Conda,
        RepositoryFormat::Yarn,
        RepositoryFormat::Bower,
        RepositoryFormat::Pnpm,
        RepositoryFormat::Chocolatey,
        RepositoryFormat::Powershell,
        RepositoryFormat::Terraform,
        RepositoryFormat::Opentofu,
        RepositoryFormat::Alpine,
        RepositoryFormat::CondaNative,
        RepositoryFormat::Composer,
        RepositoryFormat::Hex,
        RepositoryFormat::Cocoapods,
        RepositoryFormat::Swift,
        RepositoryFormat::Pub,
        RepositoryFormat::Sbt,
        RepositoryFormat::Chef,
        RepositoryFormat::Puppet,
        RepositoryFormat::Ansible,
        RepositoryFormat::Gitlfs,
        RepositoryFormat::Vscode,
        RepositoryFormat::Jetbrains,
        RepositoryFormat::Huggingface,
        RepositoryFormat::Mlmodel,
        RepositoryFormat::Cran,
        RepositoryFormat::Vagrant,
        RepositoryFormat::Opkg,
        RepositoryFormat::P2,
        RepositoryFormat::Bazel,
        RepositoryFormat::Protobuf,
        RepositoryFormat::Incus,
        RepositoryFormat::Lxc,
    ];

    /// The canonical snake_case key for this format.
    ///
    /// This is the label used by the `repository_format` Postgres enum and by
    /// the `FormatHandler::format_key()` contract, so it is deliberately NOT
    /// the lowercased `Debug` form: that drops the underscore in multi-word
    /// variants (`CondaNative` would become `condanative`).
    pub fn as_key(&self) -> &'static str {
        match self {
            Self::Maven => "maven",
            Self::Gradle => "gradle",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Nuget => "nuget",
            Self::Go => "go",
            Self::Rubygems => "rubygems",
            Self::Docker => "docker",
            Self::Helm => "helm",
            Self::Rpm => "rpm",
            Self::Debian => "debian",
            Self::Conan => "conan",
            Self::Cargo => "cargo",
            Self::Generic => "generic",
            Self::Podman => "podman",
            Self::Buildx => "buildx",
            Self::Oras => "oras",
            Self::WasmOci => "wasm_oci",
            Self::HelmOci => "helm_oci",
            Self::Poetry => "poetry",
            Self::Conda => "conda",
            Self::Yarn => "yarn",
            Self::Bower => "bower",
            Self::Pnpm => "pnpm",
            Self::Chocolatey => "chocolatey",
            Self::Powershell => "powershell",
            Self::Terraform => "terraform",
            Self::Opentofu => "opentofu",
            Self::Alpine => "alpine",
            Self::CondaNative => "conda_native",
            Self::Composer => "composer",
            Self::Hex => "hex",
            Self::Cocoapods => "cocoapods",
            Self::Swift => "swift",
            Self::Pub => "pub",
            Self::Sbt => "sbt",
            Self::Chef => "chef",
            Self::Puppet => "puppet",
            Self::Ansible => "ansible",
            Self::Gitlfs => "gitlfs",
            Self::Vscode => "vscode",
            Self::Jetbrains => "jetbrains",
            Self::Huggingface => "huggingface",
            Self::Mlmodel => "mlmodel",
            Self::Cran => "cran",
            Self::Vagrant => "vagrant",
            Self::Opkg => "opkg",
            Self::P2 => "p2",
            Self::Bazel => "bazel",
            Self::Protobuf => "protobuf",
            Self::Incus => "incus",
            Self::Lxc => "lxc",
        }
    }

    /// The key of the *handler* that serves this format.
    ///
    /// Aliases collapse onto the handler they share, mirroring
    /// [`crate::formats::get_handler_for_format`]: `gradle` is served by the
    /// Maven handler, every OCI alias by the `oci` handler, `lxc` by `incus`,
    /// and so on. This is the identity the `format_handlers` table is keyed by
    /// — the enablement gate in `RepositoryService::create` looks the row up by
    /// this key, so it is also the correct granularity for the
    /// enable/disable control surface.
    pub fn handler_key(&self) -> &'static str {
        match self {
            Self::Gradle => "maven",
            Self::Yarn | Self::Bower | Self::Pnpm => "npm",
            Self::Poetry | Self::Conda => "pypi",
            Self::Chocolatey | Self::Powershell => "nuget",
            Self::Docker
            | Self::Podman
            | Self::Buildx
            | Self::Oras
            | Self::WasmOci
            | Self::HelmOci => "oci",
            Self::Opentofu => "terraform",
            Self::Lxc => "incus",
            other => other.as_key(),
        }
    }
}

/// Repository type enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "repository_type", rename_all = "lowercase")]
pub enum RepositoryType {
    Local,
    Remote,
    Virtual,
    Staging,
}

impl RepositoryType {
    /// Return the lowercase string representation matching the database enum.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Virtual => "virtual",
            Self::Staging => "staging",
        }
    }

    /// Parse the lowercase database representation back into a variant, the
    /// inverse of [`RepositoryType::as_str`].
    ///
    /// Returns `None` for anything that is not a known repository type so a
    /// caller reading a raw `repo_type` string can fail closed. Callers that
    /// branch on the type with an `else` arm cannot distinguish "unknown" from
    /// a real variant on their own: `resolve_repo_by_key` yields an empty
    /// string when the column read fails, and a variant added later is unknown
    /// to every existing match.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "local" => Some(Self::Local),
            "remote" => Some(Self::Remote),
            "virtual" => Some(Self::Virtual),
            "staging" => Some(Self::Staging),
            _ => None,
        }
    }

    /// Check if this is a staging repository (requires promotion to release)
    pub fn is_staging(&self) -> bool {
        matches!(self, RepositoryType::Staging)
    }

    /// Check if this is a hosted repository (Local or Staging)
    pub fn is_hosted(&self) -> bool {
        matches!(self, RepositoryType::Local | RepositoryType::Staging)
    }
}

macro_rules! impl_repo_type_eq {
    ($($T:ty),+) => { $(
        impl PartialEq<RepositoryType> for $T {
            fn eq(&self, other: &RepositoryType) -> bool {
                AsRef::<str>::as_ref(self) == other.as_str()
            }
        }
        impl PartialEq<$T> for RepositoryType {
            fn eq(&self, other: &$T) -> bool {
                self.as_str() == AsRef::<str>::as_ref(other)
            }
        }
    )+ };
}

impl_repo_type_eq!(str, &str, String);

/// Replication priority for Borg replication policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "replication_priority", rename_all = "snake_case")]
pub enum ReplicationPriority {
    Immediate,
    Scheduled,
    OnDemand,
    LocalOnly,
}

/// Repository entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Repository {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub storage_backend: String,
    pub storage_path: String,
    pub upstream_url: Option<String>,
    pub is_public: bool,
    pub quota_bytes: Option<i64>,
    /// When true, direct user uploads are rejected for this repository:
    /// artifacts must arrive via the promotion path (staging -> promotion ->
    /// approval). Defaults to false (no behavior change for existing repos).
    pub promotion_only: bool,
    pub replication_priority: ReplicationPriority,
    /// Curation: enable upstream package vetting for this staging repo
    pub curation_enabled: bool,
    /// Curation: the remote repo to sync upstream metadata from
    pub curation_source_repo_id: Option<Uuid>,
    /// Curation: the local repo to promote approved packages into
    pub curation_target_repo_id: Option<Uuid>,
    /// Curation: default action for packages not matching any rule (allow or review)
    pub curation_default_action: String,
    /// Curation: seconds between upstream metadata syncs
    pub curation_sync_interval_secs: i32,
    /// Curation: whether to pre-fetch approved package bytes
    pub curation_auto_fetch: bool,
    /// Age gate: block proxy downloads of upstream versions younger than threshold
    pub age_gate_enabled: bool,
    /// Age gate: minimum package age in days before automatic pass-through
    pub age_gate_min_age_days: i32,
    /// When true, uploads to Generic/Mlmodel repositories append an immutable
    /// revision to `artifact_versions` instead of overwriting (or rejecting)
    /// the prior content at the same path (#2367). Defaults to false: no
    /// behavior change for existing repositories.
    pub versioning_enabled: bool,
    /// Optional project this repository belongs to (#2472). `None` means the
    /// repository is unassigned and behaves exactly as before projects
    /// existed. Grants on the owning project (permissions rows with
    /// `target_type = 'project'`) are inherited by this repository.
    pub project_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Repository {
    /// Build a `StorageLocation` from this repository's configured backend and path.
    pub fn storage_location(&self) -> crate::storage::StorageLocation {
        crate::storage::StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
    }
}

/// Virtual repository member entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct VirtualRepoMember {
    pub id: Uuid,
    pub virtual_repo_id: Uuid,
    pub member_repo_id: Uuid,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repository_type_is_staging() {
        assert!(RepositoryType::Staging.is_staging());
        assert!(!RepositoryType::Local.is_staging());
        assert!(!RepositoryType::Remote.is_staging());
        assert!(!RepositoryType::Virtual.is_staging());
    }

    #[test]
    fn test_repository_type_is_hosted() {
        assert!(RepositoryType::Local.is_hosted());
        assert!(RepositoryType::Staging.is_hosted());
        assert!(!RepositoryType::Remote.is_hosted());
        assert!(!RepositoryType::Virtual.is_hosted());
    }

    #[test]
    fn test_repository_type_as_str() {
        assert_eq!(RepositoryType::Local.as_str(), "local");
        assert_eq!(RepositoryType::Remote.as_str(), "remote");
        assert_eq!(RepositoryType::Virtual.as_str(), "virtual");
        assert_eq!(RepositoryType::Staging.as_str(), "staging");
    }

    #[test]
    fn test_repository_type_from_db_str() {
        assert_eq!(
            RepositoryType::from_db_str("local"),
            Some(RepositoryType::Local)
        );
        assert_eq!(
            RepositoryType::from_db_str("remote"),
            Some(RepositoryType::Remote)
        );
        assert_eq!(
            RepositoryType::from_db_str("virtual"),
            Some(RepositoryType::Virtual)
        );
        assert_eq!(
            RepositoryType::from_db_str("staging"),
            Some(RepositoryType::Staging)
        );
    }

    /// Anything that is not a known type is `None` so callers fail closed
    /// rather than silently treating it as a default variant.
    #[test]
    fn test_repository_type_from_db_str_unknown_is_none() {
        assert_eq!(RepositoryType::from_db_str(""), None);
        assert_eq!(RepositoryType::from_db_str("federated"), None);
        // "hosted" is a predicate over types, not a type of its own.
        assert_eq!(RepositoryType::from_db_str("hosted"), None);
        // The DB enum is lowercase.
        assert_eq!(RepositoryType::from_db_str("Local"), None);
    }

    /// `from_db_str` is the exact inverse of `as_str` for every variant, so the
    /// two cannot drift as variants are added.
    #[test]
    fn test_repository_type_db_str_round_trip() {
        for t in [
            RepositoryType::Local,
            RepositoryType::Remote,
            RepositoryType::Virtual,
            RepositoryType::Staging,
        ] {
            assert_eq!(RepositoryType::from_db_str(t.as_str()), Some(t.clone()));
        }
    }

    #[test]
    fn test_repository_type_string_eq() {
        let s = String::from("remote");
        assert!(s == RepositoryType::Remote);
        assert!(RepositoryType::Remote == s);
        assert!(s != RepositoryType::Local);
    }

    #[test]
    fn test_repository_type_str_eq() {
        assert!("remote" == RepositoryType::Remote);
        assert!("virtual" == RepositoryType::Virtual);
        assert!(RepositoryType::Local == "local");
        assert!(RepositoryType::Staging == "staging");
        assert!("remote" != RepositoryType::Local);
    }
}
