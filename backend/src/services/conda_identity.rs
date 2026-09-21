//! Conda artifact identity: purls that actually identify a build, and the
//! conda -> PyPI alias graph that lets conda content inherit advisory
//! coverage (#4041, #4042).
//!
//! # Why this module exists
//!
//! A conda artifact used to resolve to `pkg:conda/<name>` and nothing else.
//! That matches essentially nothing: OSV has no conda ecosystem, the GitHub
//! Advisory Database has no conda ecosystem, and NVD is CPE-keyed while conda
//! names are not CPEs. So a conda package was queried, matched nothing, and
//! rendered as clean -- a false negative manufactured by asking a question no
//! database can answer.
//!
//! Two separate defects hide in that sentence, and this module fixes them
//! separately.
//!
//! ## 1. The purl did not identify the artifact ([`CondaPurl`])
//!
//! `pkg:conda/numpy@1.26.4` names a *set* of artifacts, not one. The same
//! name and version exist once per subdir and once per build string, with
//! different contents and different vendored native libraries: the `linux-64`
//! build linked against one BLAS is a different binary, with a different CVE
//! surface, from the `osx-arm64` build. A finding attached to the bare purl
//! is a finding attached to all of them.
//!
//! So the emitted purl carries `channel`, `subdir`, `build` and `type`
//! qualifiers, per the purl specification's conda type.
//!
//! The one case that must *not* fan out is `noarch`. A noarch package is a
//! single artifact that every platform installs; it lives in the channel's
//! `noarch/` subdir. A caller that observed it installed on `linux-64` must
//! still produce the noarch identity, or the same artifact acquires one
//! identity per platform it was seen on and every count downstream is wrong.
//! [`CondaPurl::with_noarch`] is the single place that invariant is enforced,
//! which is why the struct's fields are private.
//!
//! ## 2. The name is not the PyPI name ([`AliasMap`])
//!
//! The same software usually *does* have advisory coverage under a PyPI
//! identity -- but the names differ: `py-opencv` vs `opencv-python`,
//! `pytorch` vs `torch`, `pytables` vs `tables`, `matplotlib-base` vs
//! `matplotlib`. No amount of careful parsing recovers that. It needs an
//! explicit mapping.
//!
//! **The mapping is an input we refresh, not something we invent.** This
//! module therefore deliberately does *not* guess:
//!
//! * There is no string-munging heuristic and no identity fallback. `libfoo`
//!   does not resolve to PyPI `libfoo` just because the strings match; a
//!   wrong mapping produces confident findings against the wrong package,
//!   which is strictly worse than no mapping.
//! * A loadable mapping ([`AliasMap::from_json`], and an adapter for the
//!   published conda-forge/grayskull shape, [`AliasMap::from_grayskull_json`])
//!   carries its own [`MappingProvenance`] -- where it came from and when it
//!   was fetched -- and that provenance travels all the way out to each
//!   individual [`PypiAlias`], so a finding can say what claim it rests on.
//! * A small [`BUILTIN_ALIASES`] table is a vendored floor for the well-known
//!   cases, so an air-gapped deployment that never loads a mapping is not
//!   reduced to zero coverage.
//!
//! ## The three-way distinction that is the point of all of this
//!
//! [`AliasCoverage`] separates three states that a `Vec<PypiAlias>` alone
//! cannot -- the same shape as
//! [`Completeness`](crate::services::package_analysis_service::Completeness):
//!
//! * [`AliasCoverage::Mapped`] -- we know the PyPI name(s). Query them.
//! * [`AliasCoverage::NotPythonPackage`] -- the mapping positively records
//!   that this conda package ships no PyPI distribution (`zlib`, `openssl`,
//!   and `python` itself). Finding nothing in PyPI advisories is then a real
//!   answer, not a gap.
//! * [`AliasCoverage::Unmapped`] -- nothing knows this name. This is a known
//!   unknown and must render as one. An unmapped package that produced no
//!   findings is NOT clean; it is unexamined.
//!
//! This module never shells out, never panics on hostile input, and never
//! emits a purl whose qualifiers an attacker-controlled name, version or
//! build string could forge.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Upper bound on any single purl component. Real conda names, versions and
/// build strings are tens of bytes; anything past this is hostile or
/// misidentified input and is rejected before any formatting work.
pub const MAX_COMPONENT_BYTES: usize = 512;

/// Upper bound on a mapping document. The published conda-forge mapping is a
/// few MiB; this leaves room for growth without letting a proxied fetch pin
/// an arbitrary amount of memory.
pub const MAX_MAPPING_BYTES: usize = 32 * 1024 * 1024;

/// Upper bound on entries in one mapping document.
pub const MAX_MAPPING_ENTRIES: usize = 1_000_000;

/// The purl type for conda packages.
pub const CONDA_PURL_TYPE: &str = "conda";

/// The subdir a noarch package lives in, and the only subdir a noarch
/// identity may carry.
pub const NOARCH_SUBDIR: &str = "noarch";

/// Schema tag of the mapping document this module loads and writes.
pub const ALIAS_MAP_SCHEMA_V1: &str = "artifact-keeper/conda-pypi-alias/v1";

// ---------------------------------------------------------------------------
// #4041 -- purl emission
// ---------------------------------------------------------------------------

/// Conda subdirs in use at the time of writing.
///
/// Used only to *recognise* a subdir (so a channel URL's trailing platform
/// segment can be stripped, and so callers can tell a platform apart from a
/// typo). It is deliberately NOT a whitelist: new platforms appear, and
/// rejecting one would silently drop real artifacts. Syntactic validation in
/// [`CondaPurl::from_index`] is what keeps the purl safe.
pub const KNOWN_SUBDIRS: &[&str] = &[
    "emscripten-wasm32",
    "freebsd-64",
    "linux-32",
    "linux-64",
    "linux-aarch64",
    "linux-armv6l",
    "linux-armv7l",
    "linux-ppc64",
    "linux-ppc64le",
    "linux-riscv64",
    "linux-s390x",
    "noarch",
    "osx-64",
    "osx-arm64",
    "wasi-wasm32",
    "win-32",
    "win-64",
    "win-arm64",
    "zos-z",
];

/// Hosts whose channel URLs are the canonical Anaconda ones, where the final
/// path segment is the channel name everyone writes (`conda-forge`, `main`).
const ANACONDA_HOSTS: &[&str] = &[
    "anaconda.org",
    "api.anaconda.org",
    "conda.anaconda.org",
    "repo.anaconda.com",
];

/// True when `subdir` is a conda platform subdir this build knows about.
///
/// A `false` answer means "not recognised", never "invalid" -- see
/// [`KNOWN_SUBDIRS`].
pub fn is_known_subdir(subdir: &str) -> bool {
    KNOWN_SUBDIRS.contains(&subdir)
}

/// `noarch:` as declared by `info/index.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoarchKind {
    /// `noarch: python` -- a pure-Python package installed into `site-packages`.
    Python,
    /// `noarch: generic` -- platform-independent data/scripts. Also what the
    /// legacy boolean `noarch: true` means.
    Generic,
}

impl NoarchKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            NoarchKind::Python => "python",
            NoarchKind::Generic => "generic",
        }
    }

    /// Parse an `info/index.json` `noarch` value. Anything that is not a
    /// recognised noarch marker -- including the explicit `false` and an
    /// absent value rendered as `""` -- is `None`, i.e. "this is a platform
    /// package", which is the safe reading: it keeps the platform subdir.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "python" => Some(NoarchKind::Python),
            "generic" | "true" => Some(NoarchKind::Generic),
            _ => None,
        }
    }
}

/// Which container format the artifact ships in. Both formats exist for the
/// same name/version/build, with the same contents, so this is recorded but
/// is not what distinguishes a build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CondaArchiveType {
    /// The zstd-based `.conda` format.
    CondaV2,
    /// The legacy `.tar.bz2` format.
    TarBz2,
}

impl CondaArchiveType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CondaArchiveType::CondaV2 => "conda",
            CondaArchiveType::TarBz2 => "tar.bz2",
        }
    }

    /// Classify by filename extension. `None` for anything else -- an unknown
    /// extension is not evidence of either format.
    pub fn from_filename(name: &str) -> Option<Self> {
        let lower = name.trim().to_ascii_lowercase();
        if lower.ends_with(".conda") {
            Some(CondaArchiveType::CondaV2)
        } else if lower.ends_with(".tar.bz2") {
            Some(CondaArchiveType::TarBz2)
        } else {
            None
        }
    }
}

/// Why a set of conda coordinates could not become a purl.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CondaPurlError {
    #[error("conda {field} is empty")]
    EmptyField { field: &'static str },
    #[error("conda {field} is {len} bytes, over the {max}-byte ceiling")]
    FieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    #[error("`{name}` is not a valid conda package name")]
    InvalidName { name: String },
    #[error("`{subdir}` is not a valid conda subdir")]
    InvalidSubdir { subdir: String },
}

/// One conda artifact's identity.
///
/// Fields are private on purpose: the noarch invariant (a noarch package
/// carries `subdir == "noarch"`, never the platform it happened to be
/// installed on) is enforced in [`CondaPurl::with_noarch`], and public fields
/// would let a caller reintroduce the per-platform fan-out this type exists
/// to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CondaPurl {
    name: String,
    version: String,
    build: Option<String>,
    subdir: String,
    channel: Option<String>,
    noarch: Option<NoarchKind>,
    archive_type: Option<CondaArchiveType>,
}

impl CondaPurl {
    /// Build an identity from what `info/index.json` states.
    ///
    /// `build` may be empty, in which case no `build` qualifier is emitted.
    /// That widens the identity to every build of this version on this
    /// subdir, which is a real loss -- but an absent qualifier says "unknown"
    /// honestly, where an empty one would assert a build string of `""`.
    ///
    /// The name is lower-cased, because conda itself requires lower-case
    /// package names and the channel index is written that way; a name with
    /// surrounding whitespace is *rejected* rather than trimmed, since an
    /// identity must be exactly the string the index carries.
    pub fn from_index(
        name: &str,
        version: &str,
        build: &str,
        subdir: &str,
    ) -> Result<Self, CondaPurlError> {
        let name = checked_field("name", name, |s| s.trim().is_empty())?;
        if name.trim() != name {
            return Err(CondaPurlError::InvalidName { name });
        }
        let Some(name) = normalize_conda_name(&name) else {
            return Err(CondaPurlError::InvalidName { name });
        };

        let version = checked_field("version", version, |s| s.trim().is_empty())?;
        let version = version.trim().to_string();

        let build = checked_field("build", build, |_| false)?;
        let build = build.trim();
        let build = if build.is_empty() {
            None
        } else {
            Some(build.to_string())
        };

        let subdir = checked_field("subdir", subdir, |s| s.trim().is_empty())?;
        if !is_valid_subdir(&subdir) {
            return Err(CondaPurlError::InvalidSubdir { subdir });
        }

        Ok(CondaPurl {
            name,
            version,
            build,
            subdir,
            channel: None,
            noarch: None,
            archive_type: None,
        })
    }

    /// Record the channel the artifact came from.
    ///
    /// Accepts either a bare channel name (`conda-forge`) or a channel URL,
    /// and normalizes both to the same value so the two spellings cannot
    /// produce two identities for one artifact. A trailing platform segment
    /// is dropped -- it is already the `subdir` qualifier.
    ///
    /// For a non-Anaconda host the host is kept (`mirror.corp/internal`), so
    /// two mirrors publishing a same-named private channel do not collide. A
    /// channel that normalizes to nothing is dropped rather than emitted
    /// empty.
    pub fn with_channel(mut self, channel: &str) -> Self {
        self.channel = normalize_channel(channel);
        self
    }

    /// Declare the artifact noarch, which forces the single cross-platform
    /// identity. Passing `None` declares it a platform package and leaves the
    /// subdir alone.
    pub fn with_noarch(mut self, kind: Option<NoarchKind>) -> Self {
        self.noarch = kind;
        if kind.is_some() {
            self.subdir = NOARCH_SUBDIR.to_string();
        }
        self
    }

    pub fn with_archive_type(mut self, archive_type: CondaArchiveType) -> Self {
        self.archive_type = Some(archive_type);
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn build(&self) -> Option<&str> {
        self.build.as_deref()
    }

    pub fn subdir(&self) -> &str {
        &self.subdir
    }

    pub fn channel(&self) -> Option<&str> {
        self.channel.as_deref()
    }

    pub fn noarch(&self) -> Option<NoarchKind> {
        self.noarch
    }

    pub fn archive_type(&self) -> Option<CondaArchiveType> {
        self.archive_type
    }

    /// True when this identity is the cross-platform one.
    pub fn is_noarch(&self) -> bool {
        self.noarch.is_some() || self.subdir == NOARCH_SUBDIR
    }

    /// Render the purl, qualifiers in the specification's canonical
    /// (alphabetical) order. Every component is percent-encoded, so no
    /// attacker-supplied version or build string can forge a qualifier.
    pub fn to_purl(&self) -> String {
        let mut qualifiers: Vec<(&str, String)> = Vec::with_capacity(4);
        if let Some(build) = &self.build {
            qualifiers.push(("build", purl_encode(build)));
        }
        if let Some(channel) = &self.channel {
            qualifiers.push(("channel", purl_encode(channel)));
        }
        qualifiers.push(("subdir", purl_encode(&self.subdir)));
        if let Some(archive_type) = self.archive_type {
            qualifiers.push(("type", purl_encode(archive_type.as_str())));
        }
        qualifiers.sort_by(|a, b| a.0.cmp(b.0));

        let rendered: Vec<String> = qualifiers
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        format!(
            "pkg:{}/{}@{}?{}",
            CONDA_PURL_TYPE,
            purl_encode(&self.name),
            purl_encode(&self.version),
            rendered.join("&")
        )
    }
}

impl fmt::Display for CondaPurl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_purl())
    }
}

/// Length/emptiness gate shared by every purl component, so the error a
/// caller sees names the field rather than the value.
fn checked_field(
    field: &'static str,
    raw: &str,
    is_empty: impl Fn(&str) -> bool,
) -> Result<String, CondaPurlError> {
    if raw.len() > MAX_COMPONENT_BYTES {
        return Err(CondaPurlError::FieldTooLong {
            field,
            len: raw.len(),
            max: MAX_COMPONENT_BYTES,
        });
    }
    if is_empty(raw) {
        return Err(CondaPurlError::EmptyField { field });
    }
    Ok(raw.to_string())
}

/// Conda subdirs are lower-case `<os>-<arch>` tokens. Validated
/// syntactically rather than against [`KNOWN_SUBDIRS`] so a new platform
/// still produces an identity.
fn is_valid_subdir(subdir: &str) -> bool {
    let bytes = subdir.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_')
}

/// Trim and length-gate a name before any per-flavour validation. Shared by
/// the normalizers below so the ceiling is applied in exactly one place.
fn usable_component(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    (!trimmed.is_empty() && trimmed.len() <= MAX_COMPONENT_BYTES).then_some(trimmed)
}

/// Normalize a channel name or channel URL to one canonical spelling.
fn normalize_channel(raw: &str) -> Option<String> {
    let trimmed = usable_component(raw)?;
    let (host, path) = match trimmed.split_once("://") {
        Some((_scheme, rest)) => match rest.split_once('/') {
            Some((host, path)) => (Some(host.to_ascii_lowercase()), path),
            None => (Some(rest.to_ascii_lowercase()), ""),
        },
        None => (None, trimmed),
    };

    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // A trailing platform segment is the subdir qualifier, not the channel.
    if segments.len() > 1 && is_known_subdir(segments[segments.len() - 1]) {
        segments.pop();
    }

    match host {
        // On the canonical hosts the last segment is the channel name people
        // write: `.../conda-forge` and `.../pkgs/main` -> `conda-forge`, `main`.
        Some(host) if is_anaconda_host(&host) => segments.last().map(|s| (*s).to_string()),
        Some(host) if segments.is_empty() => Some(host),
        Some(host) => Some(format!("{host}/{}", segments.join("/"))),
        None if segments.is_empty() => None,
        None => Some(segments.join("/")),
    }
}

fn is_anaconda_host(host: &str) -> bool {
    let bare = host.split(':').next().unwrap_or(host);
    ANACONDA_HOSTS.contains(&bare)
}

/// Percent-encode everything outside RFC 3986 unreserved.
fn purl_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// #4042 -- conda <-> PyPI alias graph
// ---------------------------------------------------------------------------

/// Vendored floor under any loaded mapping: conda package name -> the PyPI
/// distribution name(s) it ships.
///
/// An **empty** value list is a positive statement -- "this conda package
/// ships no PyPI distribution" -- and resolves to
/// [`AliasCoverage::NotPythonPackage`], not to an unknown. `python` is in
/// that group on purpose: the conda `python` package is CPython itself, and
/// mapping it to a PyPI project named `python` would be a fabricated match.
///
/// This table is small by design. It exists so an air-gapped deployment that
/// never loads a mapping still covers the handful of names that account for
/// most conda content, and so the well-known renames are regression-tested.
/// Breadth comes from [`AliasMap::from_json`]; do not grow this table with
/// entries nobody has verified against the channel.
///
/// Sorted by conda name for human auditing (enforced by a test); the runtime
/// lookup is a `HashMap`.
pub const BUILTIN_ALIASES: &[(&str, &[&str])] = &[
    ("attrs", &["attrs"]),
    ("beautifulsoup4", &["beautifulsoup4"]),
    ("brotli", &[]),
    ("bzip2", &[]),
    ("ca-certificates", &[]),
    ("certifi", &["certifi"]),
    ("cffi", &["cffi"]),
    ("charset-normalizer", &["charset-normalizer"]),
    ("click", &["click"]),
    ("cryptography", &["cryptography"]),
    ("icu", &[]),
    ("idna", &["idna"]),
    ("jinja2", &["jinja2"]),
    ("jupyter_core", &["jupyter-core"]),
    ("libcurl", &[]),
    ("libffi", &[]),
    ("libgcc-ng", &[]),
    ("libjpeg-turbo", &[]),
    ("libpng", &[]),
    ("libstdcxx-ng", &[]),
    ("libwebp", &[]),
    ("libxml2", &[]),
    ("libzlib", &[]),
    ("lxml", &["lxml"]),
    ("markupsafe", &["markupsafe"]),
    ("matplotlib-base", &["matplotlib"]),
    ("msgpack-python", &["msgpack"]),
    ("ncurses", &[]),
    ("numpy", &["numpy"]),
    ("openssl", &[]),
    ("packaging", &["packaging"]),
    ("pandas", &["pandas"]),
    ("pillow", &["pillow"]),
    ("pip", &["pip"]),
    ("prompt_toolkit", &["prompt-toolkit"]),
    ("protobuf", &["protobuf"]),
    ("py-opencv", &["opencv-python"]),
    ("pyarrow", &["pyarrow"]),
    ("pytables", &["tables"]),
    ("python", &[]),
    ("python-dateutil", &["python-dateutil"]),
    ("pytorch", &["torch"]),
    ("pyyaml", &["pyyaml"]),
    ("readline", &[]),
    ("requests", &["requests"]),
    ("scikit-learn", &["scikit-learn"]),
    ("scipy", &["scipy"]),
    ("setuptools", &["setuptools"]),
    ("sqlalchemy", &["sqlalchemy"]),
    ("sqlite", &[]),
    ("tk", &[]),
    ("typing_extensions", &["typing-extensions"]),
    ("urllib3", &["urllib3"]),
    ("xz", &[]),
    ("zlib", &[]),
    ("zstd", &[]),
];

fn builtin_index() -> &'static HashMap<&'static str, &'static [&'static str]> {
    static INDEX: OnceLock<HashMap<&'static str, &'static [&'static str]>> = OnceLock::new();
    INDEX.get_or_init(|| BUILTIN_ALIASES.iter().copied().collect())
}

/// Where a mapping came from and when. Recorded so a finding derived from an
/// alias can state the claim it rests on, and so staleness is measurable
/// rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingProvenance {
    /// Free text identifying the upstream: URL, project, index revision.
    pub source: String,
    /// When this data was fetched (NOT when it was loaded into memory).
    pub fetched_at: DateTime<Utc>,
    /// The conda channel the mapping describes, when it describes only one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

/// What a single alias rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasSource {
    /// A loaded mapping said so.
    Mapping { provenance: Arc<MappingProvenance> },
    /// The vendored [`BUILTIN_ALIASES`] table said so.
    BuiltIn,
}

/// One PyPI distribution a conda package corresponds to. `pypi_name` is PEP
/// 503 normalized, which is the form OSV and the GitHub Advisory Database key
/// their PyPI entries on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PypiAlias {
    pub pypi_name: String,
    pub source: AliasSource,
}

/// How much the alias graph actually knows about one conda package.
///
/// The `Unmapped` / `NotPythonPackage` split is the whole point: both produce
/// zero PyPI names, but only one of them means "nothing to look up". Collapse
/// them and an unexamined package renders as a clean one, which is the defect
/// this module exists to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasCoverage {
    /// At least one PyPI name is known. Query it.
    Mapped,
    /// Positively recorded as shipping no PyPI distribution. Absence of PyPI
    /// findings is a real answer here.
    NotPythonPackage { source: AliasSource },
    /// Nothing knows this conda name. A known unknown: absence of findings
    /// means nothing was asked.
    Unmapped { reason: String },
}

/// The result of one conda -> PyPI lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasResolution {
    /// The normalized lookup key, or a truncated echo of the input when it
    /// could not be normalized.
    pub conda_name: String,
    pub aliases: Vec<PypiAlias>,
    pub coverage: AliasCoverage,
}

impl AliasResolution {
    /// Stable token for persistence and API rendering. Mirrors
    /// [`Completeness::status`](crate::services::package_analysis_service::Completeness)
    /// in `package_analysis_service`.
    pub fn status(&self) -> &'static str {
        match self.coverage {
            AliasCoverage::Mapped => "mapped",
            AliasCoverage::NotPythonPackage { .. } => "not_python",
            AliasCoverage::Unmapped { .. } => "unmapped",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match &self.coverage {
            AliasCoverage::Unmapped { reason } => Some(reason.as_str()),
            _ => None,
        }
    }

    /// True when there is something to query an advisory database with.
    pub fn is_actionable(&self) -> bool {
        matches!(self.coverage, AliasCoverage::Mapped)
    }

    /// True when the empty result means "we did not look", not "nothing is
    /// there". Callers MUST surface this rather than rendering a clean row.
    pub fn is_known_unknown(&self) -> bool {
        matches!(self.coverage, AliasCoverage::Unmapped { .. })
    }

    /// PyPI purls for advisory lookup, one per alias.
    ///
    /// `version` is the conda package's version, carried across unchanged.
    /// For a conda-forge build of a Python package that is the upstream
    /// release version, which is what makes the lookup work -- but conda
    /// versions are not PEP 440 and a repackaged or patched build can differ.
    /// Treat a match found this way as "this version of the same project",
    /// not as a byte-identical artifact.
    ///
    /// An empty `version` yields nothing: a versionless purl matches every
    /// release, which is not a match key.
    pub fn pypi_purls(&self, version: &str) -> Vec<String> {
        let version = version.trim();
        if version.is_empty() {
            return Vec::new();
        }
        self.aliases
            .iter()
            .map(|alias| {
                format!(
                    "pkg:pypi/{}@{}",
                    purl_encode(&alias.pypi_name),
                    purl_encode(version)
                )
            })
            .collect()
    }
}

/// Why a mapping document could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AliasMapError {
    /// The document could not be read at all: a missing path, a permission
    /// error. Distinct from [`Self::Malformed`], which means the bytes
    /// arrived and were not the document they claimed to be.
    #[error("mapping document could not be read: {0}")]
    Unreadable(String),
    #[error("mapping document is {len} bytes, over the {max}-byte ceiling")]
    TooLarge { len: usize, max: usize },
    #[error("mapping document is not valid JSON for this schema: {0}")]
    Malformed(String),
    #[error("unsupported mapping schema `{found}`, expected `{expected}`")]
    UnsupportedSchema {
        found: String,
        expected: &'static str,
    },
    #[error("mapping document has {count} entries, over the {max} ceiling")]
    TooManyEntries { count: usize, max: usize },
    #[error("cannot serialize a mapping that has no recorded provenance")]
    NoProvenance,
}

/// How old a loaded mapping is relative to a caller-chosen budget.
///
/// A stale mapping does not become wrong -- the renames it records stay
/// correct -- it becomes *incomplete*: packages added upstream since the
/// fetch resolve to [`AliasCoverage::Unmapped`]. That is the honest failure
/// mode, and it is why staleness is exposed rather than hidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staleness {
    /// No mapping was ever loaded; only the vendored table is answering.
    BuiltInOnly,
    Fresh {
        age: Duration,
    },
    Stale {
        age: Duration,
        max_age: Duration,
    },
}

/// A loadable conda -> PyPI mapping, plus the vendored fallback table.
#[derive(Debug, Clone)]
pub struct AliasMap {
    provenance: Option<Arc<MappingProvenance>>,
    entries: HashMap<String, Vec<String>>,
    rejected: usize,
    builtin_fallback: bool,
}

/// The canonical on-disk/on-wire mapping document.
#[derive(Debug, Serialize, Deserialize)]
struct AliasDocumentV1 {
    schema: String,
    provenance: MappingProvenance,
    /// conda package name -> PyPI distribution names. An empty list means
    /// "this package ships no PyPI distribution", which is information.
    entries: BTreeMap<String, Vec<String>>,
}

/// One entry of the published conda-forge/grayskull mapping, which is keyed
/// by PyPI name and therefore has to be inverted.
#[derive(Debug, Deserialize)]
struct GrayskullEntry {
    conda_name: Option<String>,
    pypi_name: Option<String>,
}

impl AliasMap {
    /// The vendored table alone. What a deployment that has never fetched a
    /// mapping gets -- narrow, but honest about it via
    /// [`Staleness::BuiltInOnly`].
    pub fn builtin_only() -> Self {
        AliasMap {
            provenance: None,
            entries: HashMap::new(),
            rejected: 0,
            builtin_fallback: true,
        }
    }

    /// Build from already-parsed pairs. Names are normalized on the way in;
    /// anything unusable is dropped and counted in [`Self::rejected_entries`]
    /// rather than silently discarded.
    pub fn from_entries(
        provenance: MappingProvenance,
        entries: impl IntoIterator<Item = (String, Vec<String>)>,
    ) -> Self {
        let mut normalized: HashMap<String, Vec<String>> = HashMap::new();
        let mut rejected = 0usize;

        for (conda_name, pypi_names) in entries {
            let Some(key) = normalize_conda_name(&conda_name) else {
                rejected += 1;
                continue;
            };
            let declared = pypi_names.len();
            let mut values: Vec<String> = Vec::with_capacity(declared);
            for pypi_name in pypi_names {
                match normalize_pypi_name(&pypi_name) {
                    Some(v) => {
                        if !values.contains(&v) {
                            values.push(v);
                        }
                    }
                    None => rejected += 1,
                }
            }
            // An entry that declared names but kept none must NOT be stored:
            // an empty list means "no PyPI counterpart", and we did not learn
            // that -- we failed to read what it said.
            if declared > 0 && values.is_empty() {
                continue;
            }
            normalized.entry(key).or_default().extend(values);
        }

        // Merging two records for one name can reintroduce duplicates.
        for values in normalized.values_mut() {
            let mut seen = HashSet::new();
            values.retain(|v| seen.insert(v.clone()));
        }

        AliasMap {
            provenance: Some(Arc::new(provenance)),
            entries: normalized,
            rejected,
            builtin_fallback: true,
        }
    }

    /// Load the canonical [`ALIAS_MAP_SCHEMA_V1`] document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AliasMapError> {
        if bytes.len() > MAX_MAPPING_BYTES {
            return Err(AliasMapError::TooLarge {
                len: bytes.len(),
                max: MAX_MAPPING_BYTES,
            });
        }
        let doc: AliasDocumentV1 =
            serde_json::from_slice(bytes).map_err(|e| AliasMapError::Malformed(e.to_string()))?;
        if doc.schema != ALIAS_MAP_SCHEMA_V1 {
            return Err(AliasMapError::UnsupportedSchema {
                found: truncate(&doc.schema, 120),
                expected: ALIAS_MAP_SCHEMA_V1,
            });
        }
        if doc.entries.len() > MAX_MAPPING_ENTRIES {
            return Err(AliasMapError::TooManyEntries {
                count: doc.entries.len(),
                max: MAX_MAPPING_ENTRIES,
            });
        }
        Ok(AliasMap::from_entries(doc.provenance, doc.entries))
    }

    /// Load the published conda-forge/grayskull mapping shape -- a JSON object
    /// keyed by PyPI name, each value carrying `conda_name` -- and invert it.
    ///
    /// The upstream file records no fetch time of its own, so the caller
    /// supplies the [`MappingProvenance`]: whoever performed the fetch is the
    /// only party that knows when it happened and from which revision.
    pub fn from_grayskull_json(
        bytes: &[u8],
        provenance: MappingProvenance,
    ) -> Result<Self, AliasMapError> {
        if bytes.len() > MAX_MAPPING_BYTES {
            return Err(AliasMapError::TooLarge {
                len: bytes.len(),
                max: MAX_MAPPING_BYTES,
            });
        }
        let doc: BTreeMap<String, GrayskullEntry> =
            serde_json::from_slice(bytes).map_err(|e| AliasMapError::Malformed(e.to_string()))?;
        if doc.len() > MAX_MAPPING_ENTRIES {
            return Err(AliasMapError::TooManyEntries {
                count: doc.len(),
                max: MAX_MAPPING_ENTRIES,
            });
        }

        let mut inverted: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut unusable = 0usize;
        for (key, entry) in doc {
            // No conda_name means the record cannot be inverted. Inventing one
            // from the PyPI key is exactly the guess this module refuses.
            let Some(conda_name) = entry.conda_name else {
                unusable += 1;
                continue;
            };
            let pypi_name = entry.pypi_name.unwrap_or(key);
            inverted.entry(conda_name).or_default().push(pypi_name);
        }

        let mut map = AliasMap::from_entries(provenance, inverted);
        map.rejected += unusable;
        Ok(map)
    }

    /// Serialize back to the canonical document, for a refresh job that
    /// normalizes an upstream shape once and caches the result.
    pub fn to_json_v1(&self) -> Result<String, AliasMapError> {
        let provenance = self
            .provenance
            .as_ref()
            .ok_or(AliasMapError::NoProvenance)?
            .as_ref()
            .clone();
        let doc = AliasDocumentV1 {
            schema: ALIAS_MAP_SCHEMA_V1.to_string(),
            provenance,
            entries: self
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        serde_json::to_string(&doc).map_err(|e| AliasMapError::Malformed(e.to_string()))
    }

    /// Drop the vendored fallback, so lookups answer only from loaded data.
    /// For an operator who wants coverage to be exactly what they shipped.
    pub fn without_builtin_fallback(mut self) -> Self {
        self.builtin_fallback = false;
        self
    }

    pub fn provenance(&self) -> Option<&MappingProvenance> {
        self.provenance.as_deref()
    }

    /// Entries that came from a loaded mapping. Excludes the vendored table.
    pub fn loaded_entries(&self) -> usize {
        self.entries.len()
    }

    /// Entries or values in the source document that could not be used. A
    /// non-zero count means the loaded mapping is narrower than its source.
    pub fn rejected_entries(&self) -> usize {
        self.rejected
    }

    pub fn has_builtin_fallback(&self) -> bool {
        self.builtin_fallback
    }

    /// Age this mapping against a budget.
    ///
    /// A `fetched_at` in the future (clock skew between the refresh job and
    /// this process) is clamped to zero rather than reported as a negative
    /// age, which would read as absurdly fresh in one direction and underflow
    /// comparisons in the other.
    pub fn staleness(&self, now: DateTime<Utc>, max_age: Duration) -> Staleness {
        let Some(provenance) = &self.provenance else {
            return Staleness::BuiltInOnly;
        };
        let age = (now - provenance.fetched_at).max(Duration::zero());
        if age > max_age {
            Staleness::Stale { age, max_age }
        } else {
            Staleness::Fresh { age }
        }
    }

    /// One line describing what is answering, for the `Unmapped` reason.
    fn describe(&self) -> String {
        match &self.provenance {
            Some(provenance) => format!(
                "mapping `{}` fetched {} carries {} entries",
                truncate(&provenance.source, 120),
                provenance.fetched_at.to_rfc3339(),
                self.entries.len()
            ),
            None => "no mapping is loaded; only the built-in table is answering".to_string(),
        }
    }

    fn mapping_source(&self) -> AliasSource {
        match &self.provenance {
            Some(provenance) => AliasSource::Mapping {
                provenance: Arc::clone(provenance),
            },
            None => AliasSource::BuiltIn,
        }
    }
}

/// Resolve a conda package name to the PyPI distribution name(s) it
/// corresponds to.
///
/// Lookup order is: the loaded mapping, then the vendored table, then
/// [`AliasCoverage::Unmapped`]. There is no fourth step -- in particular no
/// "try the name as-is", which would be a guess.
pub fn pypi_aliases(conda_name: &str, map: &AliasMap) -> AliasResolution {
    let Some(key) = normalize_conda_name(conda_name) else {
        let echo = truncate(conda_name.trim(), 64);
        return AliasResolution {
            conda_name: echo.clone(),
            aliases: Vec::new(),
            coverage: AliasCoverage::Unmapped {
                reason: format!("`{echo}` is not a usable conda package name"),
            },
        };
    };

    if let Some(values) = map.entries.get(&key) {
        return resolve_from(key, values.iter().map(String::as_str), map.mapping_source());
    }

    if map.builtin_fallback {
        if let Some(values) = builtin_index().get(key.as_str()) {
            return resolve_from(key, values.iter().copied(), AliasSource::BuiltIn);
        }
    }

    AliasResolution {
        conda_name: key.clone(),
        aliases: Vec::new(),
        coverage: AliasCoverage::Unmapped {
            reason: format!(
                "no conda->PyPI mapping for `{key}`: {}. \
                 PyPI advisories were not queried for this package",
                map.describe()
            ),
        },
    }
}

fn resolve_from<'a>(
    key: String,
    values: impl Iterator<Item = &'a str>,
    source: AliasSource,
) -> AliasResolution {
    let aliases: Vec<PypiAlias> = values
        .map(|pypi_name| PypiAlias {
            pypi_name: pypi_name.to_string(),
            source: source.clone(),
        })
        .collect();
    let coverage = if aliases.is_empty() {
        AliasCoverage::NotPythonPackage { source }
    } else {
        AliasCoverage::Mapped
    };
    AliasResolution {
        conda_name: key,
        aliases,
        coverage,
    }
}

// ---------------------------------------------------------------------------
// Name normalization
// ---------------------------------------------------------------------------

/// Canonical form of a conda package name for use as a lookup key: trimmed
/// and lower-cased.
///
/// Separators are deliberately NOT collapsed. `jupyter_core` and
/// `jupyter-core` are distinct strings in a conda channel index, and folding
/// them together would let one package's mapping answer for another.
///
/// `None` for anything that is not a conda package name at all.
pub fn normalize_conda_name(raw: &str) -> Option<String> {
    let trimmed = usable_component(raw)?;
    let lowered = trimmed.to_ascii_lowercase();
    let bytes = lowered.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return None;
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(lowered)
}

/// PEP 503 normalized PyPI project name: lower-cased with runs of `-`, `_`
/// and `.` collapsed to a single `-`. This is the form OSV and the GitHub
/// Advisory Database key PyPI entries on, so emitting anything else silently
/// misses.
pub fn normalize_pypi_name(raw: &str) -> Option<String> {
    let trimmed = usable_component(raw)?;
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return None;
    }

    let mut out = String::with_capacity(trimmed.len());
    let mut previous_was_separator = false;
    for ch in trimmed.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !previous_was_separator {
                out.push('-');
                previous_was_separator = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            previous_was_separator = false;
        }
    }

    let bytes = out.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
    {
        return None;
    }
    Some(out)
}

/// Truncate on a char boundary, for echoing untrusted input into a message.
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// #4041/#4042 -- the persisted identity, and the mapping an operator loads
// ---------------------------------------------------------------------------

/// Key the identity document is written under inside a conda artifact's
/// `artifact_metadata.metadata` row.
///
/// The ingest path writes it with [`CondaIdentity::to_document`]; the advisory
/// path reads it back with [`read_identity`]. Both live here so the shape has
/// one definition rather than two that drift.
pub const IDENTITY_METADATA_KEY: &str = "identity";

/// Environment variable naming a canonical [`ALIAS_MAP_SCHEMA_V1`] mapping
/// document on disk, loaded once per process by [`process_alias_map`].
///
/// This is deliberately the *narrow* loading path: only the schema-tagged
/// document, which carries its own [`MappingProvenance`]. The published
/// grayskull shape records no fetch time, so inverting it
/// ([`AliasMap::from_grayskull_json`]) needs provenance from whoever fetched
/// it -- that belongs to a refresh job, not to a process reading a file it
/// knows nothing about.
pub const ALIAS_MAP_PATH_ENV: &str = "AK_CONDA_PYPI_ALIAS_MAP";

/// The coordinates the ingest path knows about one conda artifact.
///
/// `subdir` is where the artifact was published; `noarch`, when the package's
/// own `info/index.json` declares it, overrides that -- see
/// [`CondaPurl::with_noarch`].
#[derive(Debug, Clone, Default)]
pub struct CondaIdentityInput<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub build: &'a str,
    pub subdir: &'a str,
    pub noarch: Option<NoarchKind>,
    pub channel: Option<&'a str>,
    pub archive_type: Option<CondaArchiveType>,
}

/// One conda artifact's resolved identity: the purl that names the build, plus
/// what the alias graph knows about its PyPI counterpart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondaIdentity {
    /// The conda purl, when the coordinates could produce one.
    pub purl: Option<CondaPurl>,
    /// Why not, when they could not. Exactly one of this and `purl` is set.
    pub purl_error: Option<CondaPurlError>,
    /// The conda version, carried into the PyPI purls unchanged.
    pub version: String,
    pub aliases: AliasResolution,
}

impl CondaIdentity {
    /// Resolve an artifact's identity. **Infallible by construction.**
    ///
    /// By the time this runs the artifact row is already committed, so there
    /// is no failure mode available to it: coordinates that cannot produce a
    /// purl are recorded as coordinates that could not produce a purl, and a
    /// name nothing maps resolves to [`AliasCoverage::Unmapped`]. Neither is
    /// allowed to fail an upload, and neither may render as "nothing found".
    pub fn resolve(input: CondaIdentityInput<'_>, map: &AliasMap) -> Self {
        let built = CondaPurl::from_index(input.name, input.version, input.build, input.subdir)
            .map(|purl| {
                let purl = purl.with_noarch(input.noarch);
                let purl = match input.channel {
                    Some(channel) => purl.with_channel(channel),
                    None => purl,
                };
                match input.archive_type {
                    Some(archive_type) => purl.with_archive_type(archive_type),
                    None => purl,
                }
            });
        let (purl, purl_error) = match built {
            Ok(purl) => (Some(purl), None),
            Err(e) => (None, Some(e)),
        };

        CondaIdentity {
            purl,
            purl_error,
            version: input.version.trim().to_string(),
            aliases: pypi_aliases(input.name, map),
        }
    }

    /// The PyPI purls the advisory path should query, one per alias.
    ///
    /// Empty for every coverage state except [`AliasCoverage::Mapped`] -- and
    /// an empty list is NOT interchangeable across those states, which is what
    /// [`AliasResolution::is_known_unknown`] is for.
    pub fn pypi_purls(&self) -> Vec<String> {
        self.aliases.pypi_purls(&self.version)
    }

    /// Render the document persisted into `artifact_metadata.metadata` under
    /// [`IDENTITY_METADATA_KEY`].
    pub fn to_document(&self) -> serde_json::Value {
        let name = self
            .purl
            .as_ref()
            .map(|purl| purl.name().to_string())
            .unwrap_or_else(|| self.aliases.conda_name.clone());

        let mut doc = serde_json::json!({
            "name": name,
            "version": self.version,
            "pypi": self.pypi_document(),
        });

        if let Some(purl) = &self.purl {
            doc["purl"] = serde_json::Value::String(purl.to_purl());
            doc["subdir"] = serde_json::Value::String(purl.subdir().to_string());
            doc["noarch"] = serde_json::Value::Bool(purl.is_noarch());
        }
        if let Some(error) = &self.purl_error {
            doc["purl_error"] = serde_json::Value::String(error.to_string());
        }
        doc
    }

    fn pypi_document(&self) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "status": self.aliases.status(),
            "conda_name": self.aliases.conda_name,
        });

        match &self.aliases.coverage {
            AliasCoverage::Mapped => {
                let purls = self.pypi_purls();
                let aliases: Vec<serde_json::Value> = self
                    .aliases
                    .aliases
                    .iter()
                    .zip(purls.iter().map(Some).chain(std::iter::repeat(None)))
                    .map(|(alias, purl)| {
                        serde_json::json!({
                            "pypi_name": alias.pypi_name,
                            "purl": purl,
                            "source": alias_source_document(&alias.source),
                        })
                    })
                    .collect();
                doc["aliases"] = serde_json::Value::Array(aliases);
            }
            AliasCoverage::NotPythonPackage { source } => {
                doc["source"] = alias_source_document(source);
            }
            AliasCoverage::Unmapped { reason } => {
                doc["reason"] = serde_json::Value::String(reason.clone());
            }
        }
        doc
    }
}

/// What one alias rests on, as persisted. The provenance travels with it so a
/// finding can state the claim it was derived from, and how old that claim is.
fn alias_source_document(source: &AliasSource) -> serde_json::Value {
    match source {
        AliasSource::BuiltIn => serde_json::json!({ "kind": "builtin" }),
        AliasSource::Mapping { provenance } => serde_json::json!({
            "kind": "mapping",
            "provenance": provenance.as_ref(),
        }),
    }
}

/// One PyPI alias as read back out of a stored document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAlias {
    pub pypi_name: String,
    /// The purl recorded at ingest. `None` when the artifact's version was
    /// unusable, which leaves the alias known but not queryable.
    pub purl: Option<String>,
}

/// The PyPI side of a stored identity, preserving the three-way distinction
/// that [`AliasCoverage`] draws -- plus a fourth state for a document this
/// build does not understand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredPypiCoverage {
    /// Query these.
    Mapped { aliases: Vec<StoredAlias> },
    /// Positively recorded as shipping no PyPI distribution. No PyPI advisory
    /// for it is a real answer.
    NotPythonPackage,
    /// Nothing mapped this conda name. Nothing was asked, so nothing being
    /// found means nothing.
    Unmapped { reason: String },
    /// A status written by a newer build than this one. Treated as a known
    /// unknown: an uninterpretable record is not a clean one.
    Unrecognized { status: String },
}

/// A conda artifact's identity as persisted at ingest, in the form the
/// advisory path consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentity {
    /// The conda purl. `None` when the coordinates could not produce one --
    /// see `purl_error` in the document for why.
    pub conda_purl: Option<String>,
    pub name: String,
    pub version: String,
    pub pypi: StoredPypiCoverage,
}

impl StoredIdentity {
    /// Stable token for API rendering; mirrors [`AliasResolution::status`].
    pub fn status(&self) -> &'static str {
        match self.pypi {
            StoredPypiCoverage::Mapped { .. } => "mapped",
            StoredPypiCoverage::NotPythonPackage => "not_python",
            StoredPypiCoverage::Unmapped { .. } => "unmapped",
            StoredPypiCoverage::Unrecognized { .. } => "unrecognized",
        }
    }

    /// `(pypi_name, version)` pairs to query the PyPI ecosystem with.
    ///
    /// The names are PEP 503 normalized, which is the form OSV and the GitHub
    /// Advisory Database key their PyPI entries on.
    pub fn pypi_advisory_targets(&self) -> Vec<(String, String)> {
        let version = self.version.trim();
        if version.is_empty() {
            return Vec::new();
        }
        match &self.pypi {
            StoredPypiCoverage::Mapped { aliases } => aliases
                .iter()
                .map(|alias| (alias.pypi_name.clone(), version.to_string()))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The PyPI purls recorded at ingest, for stamping a finding.
    pub fn pypi_purls(&self) -> Vec<String> {
        match &self.pypi {
            StoredPypiCoverage::Mapped { aliases } => {
                aliases.iter().filter_map(|a| a.purl.clone()).collect()
            }
            _ => Vec::new(),
        }
    }

    /// True when an empty finding list means "we did not look", not "nothing
    /// is there". A caller MUST surface this rather than rendering a clean
    /// row; that conflation is the false negative #4042 exists to remove.
    pub fn is_known_unknown(&self) -> bool {
        match &self.pypi {
            StoredPypiCoverage::NotPythonPackage => false,
            StoredPypiCoverage::Mapped { .. } => self.pypi_advisory_targets().is_empty(),
            StoredPypiCoverage::Unmapped { .. } | StoredPypiCoverage::Unrecognized { .. } => true,
        }
    }
}

/// Read the identity document out of a conda artifact's stored metadata.
///
/// `metadata` is the whole `artifact_metadata.metadata` document; the identity
/// lives under [`IDENTITY_METADATA_KEY`].
///
/// **`None` is itself a known unknown.** It means no identity was ever
/// recorded -- an artifact stored before this path existed, or one whose
/// best-effort enrichment did not run. Such an artifact has not been examined
/// for PyPI advisories and must not render as clean.
pub fn read_identity(metadata: &serde_json::Value) -> Option<StoredIdentity> {
    let doc = metadata.get(IDENTITY_METADATA_KEY)?;
    if !doc.is_object() {
        return None;
    }

    let text = |key: &str| {
        doc.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let absent = serde_json::Value::Null;
    let pypi = doc.get("pypi").unwrap_or(&absent);
    let status = pypi.get("status").and_then(|v| v.as_str()).unwrap_or("");

    let coverage = match status {
        "mapped" => StoredPypiCoverage::Mapped {
            aliases: pypi
                .get("aliases")
                .and_then(|v| v.as_array())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| {
                            let pypi_name = entry.get("pypi_name")?.as_str()?;
                            if pypi_name.is_empty() {
                                return None;
                            }
                            Some(StoredAlias {
                                pypi_name: pypi_name.to_string(),
                                purl: entry
                                    .get("purl")
                                    .and_then(|v| v.as_str())
                                    .map(str::to_string),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
        },
        "not_python" => StoredPypiCoverage::NotPythonPackage,
        "unmapped" => StoredPypiCoverage::Unmapped {
            reason: pypi
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("no conda->PyPI mapping was recorded for this package")
                .to_string(),
        },
        other => StoredPypiCoverage::Unrecognized {
            status: truncate(other, 64),
        },
    };

    Some(StoredIdentity {
        conda_purl: doc
            .get("purl")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        name: text("name"),
        version: text("version"),
        pypi: coverage,
    })
}

/// The qualified purl of the conda artifact whose coordinates live in this
/// `artifact_metadata.metadata` document, for the scanner/SBOM emission
/// paths (#4041).
///
/// Two coordinate sources, in order:
///
/// 1. The identity document written at ingest ([`read_identity`]) — already
///    channel-qualified and noarch-collapsed.
/// 2. The flat coordinate keys (`name`, `version`, `build`, `subdir`,
///    `noarch`, `package_format`) written beside it, for artifacts stored
///    before the identity block existed. No channel is recorded at that
///    level, so a fallback purl carries no `channel` qualifier.
///
/// `None` when the document carries no usable coordinates. That is the only
/// case where `format_to_purl_type`'s bare `conda` type remains the last
/// resort: an artifact whose own build coordinates were never recorded — or
/// were rejected by [`CondaPurl`]'s validation — cannot be identified more
/// precisely than its ecosystem, and an absent qualifier says "unknown"
/// honestly.
pub fn artifact_purl_from_metadata(metadata: &serde_json::Value) -> Option<String> {
    if let Some(stored) = read_identity(metadata) {
        if let Some(purl) = stored.conda_purl {
            return Some(purl);
        }
    }
    flat_coordinate_purl(metadata)
}

/// Build a purl from the flat coordinate keys `build_conda_metadata` writes
/// next to the identity block. `build` is optional (an absent qualifier
/// widens the identity honestly); `name`, `version` and `subdir` are not.
fn flat_coordinate_purl(metadata: &serde_json::Value) -> Option<String> {
    let text = |key: &str| {
        metadata
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
    };
    let (name, version, subdir) = (text("name"), text("version"), text("subdir"));
    if name.is_empty() || version.is_empty() || subdir.is_empty() {
        return None;
    }
    let purl = CondaPurl::from_index(name, version, text("build"), subdir)
        .ok()?
        .with_noarch(NoarchKind::parse(text("noarch")));
    let purl = match text("package_format") {
        "v2" => purl.with_archive_type(CondaArchiveType::CondaV2),
        "v1" => purl.with_archive_type(CondaArchiveType::TarBz2),
        _ => purl,
    };
    Some(purl.to_purl())
}

/// True when a scanner-reported `(row_name, row_version)` names the same
/// conda artifact as the registry row's `(artifact_name, artifact_version)`.
///
/// Names compare through [`normalize_conda_name`] (conda package names are
/// case-insensitive); versions compare exactly. A versionless row can name
/// anything and a versionless artifact row can confirm nothing, so neither
/// may acquire this build's identity: stamping the purl on a row that might
/// name different content would attach the identity to bytes it does not
/// describe.
pub fn row_names_artifact(
    row_name: &str,
    row_version: Option<&str>,
    artifact_name: &str,
    artifact_version: Option<&str>,
) -> bool {
    let Some(artifact_version) = artifact_version else {
        return false;
    };
    if row_version != Some(artifact_version) {
        return false;
    }
    match (
        normalize_conda_name(row_name),
        normalize_conda_name(artifact_name),
    ) {
        (Some(row), Some(artifact)) => row == artifact,
        _ => row_name == artifact_name,
    }
}

/// Load a canonical mapping document from disk.
///
/// The size ceiling is checked against the file's length before any read, so a
/// mis-pointed path cannot pull an arbitrary amount of memory into the
/// process.
pub fn load_alias_map_file(path: &std::path::Path) -> Result<AliasMap, AliasMapError> {
    let unreadable = |e: std::io::Error| {
        AliasMapError::Unreadable(format!(
            "{}: {}",
            truncate(&path.display().to_string(), 200),
            e
        ))
    };

    let len = std::fs::metadata(path).map_err(unreadable)?.len();
    if len > MAX_MAPPING_BYTES as u64 {
        return Err(AliasMapError::TooLarge {
            len: len as usize,
            max: MAX_MAPPING_BYTES,
        });
    }
    let bytes = std::fs::read(path).map_err(unreadable)?;
    AliasMap::from_json(&bytes)
}

/// The alias map this process answers from, loaded once.
///
/// [`ALIAS_MAP_PATH_ENV`] names a mapping document; without it, or when the
/// named document cannot be loaded, the answer is
/// [`AliasMap::builtin_only`] -- narrow, but honest about it via
/// [`Staleness::BuiltInOnly`] and via every `Unmapped` reason naming what was
/// answering. A bad path is logged and falls back rather than failing
/// startup: identity resolution is enrichment, and losing it must not stop
/// uploads.
pub fn process_alias_map() -> &'static AliasMap {
    static MAP: OnceLock<AliasMap> = OnceLock::new();
    MAP.get_or_init(|| alias_map_from_setting(std::env::var(ALIAS_MAP_PATH_ENV).ok()))
}

/// The decision [`process_alias_map`] makes, with the environment lifted into
/// an argument so it is testable without a process-wide `OnceLock` or a
/// mutated environment.
///
/// Every failure lands on [`AliasMap::builtin_only`] rather than propagating:
/// a mis-pointed path must narrow coverage and say so in the log, not refuse
/// uploads. It is never silently empty -- the built-in floor still answers,
/// and every `Unmapped` reason names what was answering.
fn alias_map_from_setting(setting: Option<String>) -> AliasMap {
    let Some(raw) = setting else {
        return AliasMap::builtin_only();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return AliasMap::builtin_only();
    }
    let path = std::path::Path::new(trimmed);

    match load_alias_map_file(path) {
        Ok(map) => {
            tracing::info!(
                path = %path.display(),
                entries = map.loaded_entries(),
                rejected = map.rejected_entries(),
                "loaded conda->PyPI alias mapping"
            );
            map
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "conda->PyPI alias mapping could not be loaded; falling back to \
                 the built-in table, which covers far less"
            );
            AliasMap::builtin_only()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    // -- helpers ------------------------------------------------------------

    fn purl(name: &str, version: &str, build: &str, subdir: &str) -> String {
        CondaPurl::from_index(name, version, build, subdir)
            .expect("fixture should be a valid conda identity")
            .to_purl()
    }

    fn fetched(y: i32, m: u32, d: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0)
            .single()
            .expect("valid instant")
    }

    fn provenance() -> MappingProvenance {
        MappingProvenance {
            source: "parselmouth conda-forge index @ 2026-09-18".to_string(),
            fetched_at: fetched(2026, 9, 19),
            channel: Some("conda-forge".to_string()),
        }
    }

    fn loaded(entries: &[(&str, &[&str])]) -> AliasMap {
        AliasMap::from_entries(
            provenance(),
            entries.iter().map(|(k, vs)| {
                (
                    (*k).to_string(),
                    vs.iter().map(|v| (*v).to_string()).collect::<Vec<_>>(),
                )
            }),
        )
    }

    // =======================================================================
    // #4041 -- purl emission
    // =======================================================================

    #[test]
    fn purl_carries_build_channel_and_subdir_in_canonical_order() {
        let p = CondaPurl::from_index("numpy", "1.26.4", "py311h5f1cd34_0", "linux-64")
            .expect("valid")
            .with_channel("conda-forge")
            .with_archive_type(CondaArchiveType::CondaV2);
        assert_eq!(
            p.to_purl(),
            "pkg:conda/numpy@1.26.4?build=py311h5f1cd34_0&channel=conda-forge&subdir=linux-64&type=conda"
        );
    }

    #[test]
    fn same_name_and_version_on_different_subdirs_are_different_identities() {
        let linux = purl("numpy", "1.26.4", "py311h5f1cd34_0", "linux-64");
        let mac = purl("numpy", "1.26.4", "py311h7aedaa7_0", "osx-arm64");
        assert_ne!(linux, mac);
        assert!(linux.contains("subdir=linux-64"));
        assert!(mac.contains("subdir=osx-arm64"));
    }

    #[test]
    fn same_name_version_and_subdir_but_different_build_are_different_identities() {
        let blas_a = purl("numpy", "1.26.4", "py311h5f1cd34_0", "linux-64");
        let blas_b = purl("numpy", "1.26.4", "py311h64a7726_1", "linux-64");
        assert_ne!(blas_a, blas_b);
    }

    #[test]
    fn noarch_collapses_platform_subdir_to_a_single_identity() {
        // The same noarch artifact seen installed on three platforms must
        // produce ONE purl, not three.
        let seen_on = ["linux-64", "osx-arm64", "win-64"];
        let identities: std::collections::BTreeSet<String> = seen_on
            .iter()
            .map(|s| {
                CondaPurl::from_index("requests", "2.31.0", "pyhd8ed1ab_0", s)
                    .expect("valid")
                    .with_noarch(Some(NoarchKind::Python))
                    .to_purl()
            })
            .collect();
        assert_eq!(identities.len(), 1, "noarch must not fan out per platform");
        let only = identities.into_iter().next().expect("one");
        assert!(only.contains("subdir=noarch"), "{only}");
        assert!(!only.contains("linux-64"), "{only}");
    }

    #[test]
    fn noarch_flag_is_reflected_by_is_noarch() {
        let p =
            CondaPurl::from_index("requests", "2.31.0", "pyhd8ed1ab_0", "noarch").expect("valid");
        assert!(p.is_noarch());
        let q = CondaPurl::from_index("numpy", "1.26.4", "py311_0", "linux-64").expect("valid");
        assert!(!q.is_noarch());
    }

    #[test]
    fn archive_type_distinguishes_the_two_container_formats() {
        let base = CondaPurl::from_index("numpy", "1.26.4", "py311_0", "linux-64").expect("valid");
        let v2 = base
            .clone()
            .with_archive_type(CondaArchiveType::CondaV2)
            .to_purl();
        let v1 = base.with_archive_type(CondaArchiveType::TarBz2).to_purl();
        assert!(v2.ends_with("type=conda"), "{v2}");
        assert!(v1.ends_with("type=tar.bz2"), "{v1}");
        assert_ne!(v1, v2);
    }

    #[test]
    fn absent_optional_qualifiers_are_omitted_not_emitted_empty() {
        assert_eq!(
            purl("numpy", "1.26.4", "", "linux-64"),
            "pkg:conda/numpy@1.26.4?subdir=linux-64"
        );
    }

    #[test]
    fn name_is_lowercased_to_the_canonical_conda_form() {
        assert!(purl("NumPy", "1.26.4", "py311_0", "linux-64").starts_with("pkg:conda/numpy@"));
    }

    #[test]
    fn empty_components_are_rejected() {
        assert_eq!(
            CondaPurl::from_index("", "1.0", "b", "linux-64"),
            Err(CondaPurlError::EmptyField { field: "name" })
        );
        assert_eq!(
            CondaPurl::from_index("numpy", "  ", "b", "linux-64"),
            Err(CondaPurlError::EmptyField { field: "version" })
        );
        assert_eq!(
            CondaPurl::from_index("numpy", "1.0", "b", ""),
            Err(CondaPurlError::EmptyField { field: "subdir" })
        );
    }

    #[test]
    fn names_carrying_purl_delimiters_are_rejected_not_encoded() {
        for hostile in [
            "numpy?channel=evil",
            "numpy@9.9.9",
            "../../etc/passwd",
            "numpy/extra",
            "numpy#frag",
            "num py",
            "numpy\n",
        ] {
            assert!(
                matches!(
                    CondaPurl::from_index(hostile, "1.0", "b", "linux-64"),
                    Err(CondaPurlError::InvalidName { .. })
                ),
                "{hostile:?} should be rejected"
            );
        }
    }

    #[test]
    fn invalid_subdirs_are_rejected() {
        for hostile in ["linux-64&channel=evil", "../noarch", "LINUX-64", "linux 64"] {
            assert!(
                matches!(
                    CondaPurl::from_index("numpy", "1.0", "b", hostile),
                    Err(CondaPurlError::InvalidSubdir { .. })
                ),
                "{hostile:?} should be rejected"
            );
        }
    }

    #[test]
    fn oversize_components_are_rejected_before_any_formatting() {
        let huge = "a".repeat(MAX_COMPONENT_BYTES + 1);
        assert!(matches!(
            CondaPurl::from_index(&huge, "1.0", "b", "linux-64"),
            Err(CondaPurlError::FieldTooLong { .. })
        ));
        assert!(matches!(
            CondaPurl::from_index("numpy", &huge, "b", "linux-64"),
            Err(CondaPurlError::FieldTooLong { .. })
        ));
        assert!(matches!(
            CondaPurl::from_index("numpy", "1.0", &huge, "linux-64"),
            Err(CondaPurlError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn version_and_build_are_percent_encoded_so_they_cannot_forge_qualifiers() {
        // conda epochs use `!`; a build string is attacker-influenced metadata.
        let p = CondaPurl::from_index("foo", "1!2.0", "abc&channel=evil?x=y", "linux-64")
            .expect("valid")
            .to_purl();
        assert!(p.contains("@1%212.0"), "{p}");
        assert!(!p.contains("channel=evil"), "{p}");
        assert!(p.contains("%26channel%3Devil"), "{p}");
    }

    #[test]
    fn control_characters_in_build_do_not_panic_and_do_not_survive_raw() {
        let p = CondaPurl::from_index("foo", "1.0", "a\nb\tc\u{0}", "noarch")
            .expect("valid")
            .to_purl();
        assert!(
            !p.contains('\n') && !p.contains('\t') && !p.contains('\u{0}'),
            "{p}"
        );
    }

    #[test]
    fn channel_urls_normalize_to_the_channel_name() {
        let p = CondaPurl::from_index("numpy", "1.0", "b", "linux-64").expect("valid");
        for url in [
            "https://conda.anaconda.org/conda-forge",
            "https://conda.anaconda.org/conda-forge/",
            "https://conda.anaconda.org/conda-forge/linux-64",
            "conda-forge",
        ] {
            let got = p.clone().with_channel(url).to_purl();
            assert!(got.contains("channel=conda-forge"), "{url} -> {got}");
        }
        let defaults = p
            .clone()
            .with_channel("https://repo.anaconda.com/pkgs/main/linux-64")
            .to_purl();
        assert!(defaults.contains("channel=main"), "{defaults}");
    }

    #[test]
    fn a_private_channel_keeps_its_host_so_two_mirrors_do_not_collide() {
        let p = CondaPurl::from_index("numpy", "1.0", "b", "linux-64").expect("valid");
        let a = p
            .clone()
            .with_channel("https://mirror-a.corp/internal/linux-64")
            .to_purl();
        let b = p
            .with_channel("https://mirror-b.corp/internal/linux-64")
            .to_purl();
        assert_ne!(a, b);
        assert!(a.contains("mirror-a.corp"), "{a}");
    }

    #[test]
    fn an_unusable_channel_is_dropped_rather_than_emitted_empty() {
        let p = CondaPurl::from_index("numpy", "1.0", "b", "linux-64")
            .expect("valid")
            .with_channel("   ")
            .to_purl();
        assert!(!p.contains("channel="), "{p}");
    }

    #[test]
    fn display_matches_to_purl() {
        let p = CondaPurl::from_index("numpy", "1.0", "b", "linux-64").expect("valid");
        assert_eq!(p.to_string(), p.to_purl());
    }

    #[test]
    fn known_subdirs_are_recognised_without_rejecting_future_ones() {
        assert!(is_known_subdir("linux-64"));
        assert!(is_known_subdir("osx-arm64"));
        assert!(is_known_subdir("noarch"));
        assert!(!is_known_subdir("linux-riscv128"));
        // ... but an unknown-yet-syntactically-valid subdir still builds.
        assert!(CondaPurl::from_index("numpy", "1.0", "b", "linux-riscv128").is_ok());
    }

    #[test]
    fn noarch_kind_round_trips() {
        assert_eq!(NoarchKind::parse("python"), Some(NoarchKind::Python));
        assert_eq!(NoarchKind::parse("generic"), Some(NoarchKind::Generic));
        assert_eq!(NoarchKind::parse("true"), Some(NoarchKind::Generic));
        assert_eq!(NoarchKind::parse("false"), None);
        assert_eq!(NoarchKind::parse(""), None);
        assert_eq!(NoarchKind::Python.as_str(), "python");
    }

    // =======================================================================
    // #4042 -- conda <-> PyPI alias graph
    // =======================================================================

    #[test]
    fn builtin_table_knows_the_well_known_renames() {
        let map = AliasMap::builtin_only();
        for (conda, pypi) in [
            ("py-opencv", "opencv-python"),
            ("pytorch", "torch"),
            ("matplotlib-base", "matplotlib"),
            ("pytables", "tables"),
            ("msgpack-python", "msgpack"),
        ] {
            let r = pypi_aliases(conda, &map);
            assert_eq!(r.coverage, AliasCoverage::Mapped, "{conda}");
            assert_eq!(
                r.aliases
                    .iter()
                    .map(|a| a.pypi_name.as_str())
                    .collect::<Vec<_>>(),
                vec![pypi],
                "{conda}"
            );
            assert_eq!(r.aliases[0].source, AliasSource::BuiltIn);
        }
    }

    #[test]
    fn an_unmapped_name_is_a_known_unknown_not_a_guess() {
        let map = AliasMap::builtin_only();
        let r = pypi_aliases("some-vendor-internal-thing", &map);
        assert!(r.aliases.is_empty());
        assert!(matches!(r.coverage, AliasCoverage::Unmapped { .. }));
        assert!(r.is_known_unknown());
        assert!(!r.is_actionable());
        assert!(r.reason().is_some_and(|s| !s.is_empty()));
        assert_eq!(r.status(), "unmapped");
    }

    #[test]
    fn identity_mapping_is_never_assumed() {
        // `libfoo` is not in any table; we must NOT answer `libfoo`.
        let map = AliasMap::builtin_only();
        let r = pypi_aliases("libfoo-internal", &map);
        assert!(
            !r.aliases.iter().any(|a| a.pypi_name == "libfoo-internal"),
            "string identity is a guess, not a mapping"
        );
    }

    #[test]
    fn a_package_with_no_pypi_counterpart_is_a_mapped_negative_not_an_unknown() {
        let map = AliasMap::builtin_only();
        for conda in ["python", "zlib", "libcurl", "openssl"] {
            let r = pypi_aliases(conda, &map);
            assert!(r.aliases.is_empty(), "{conda}");
            assert!(
                matches!(r.coverage, AliasCoverage::NotPythonPackage { .. }),
                "{conda} -> {:?}",
                r.coverage
            );
            assert!(!r.is_known_unknown(), "{conda}");
            assert_eq!(r.status(), "not_python");
        }
    }

    #[test]
    fn a_loaded_mapping_overrides_the_builtin_table() {
        let map = loaded(&[("pytorch", &["torch-nightly"])]);
        let r = pypi_aliases("pytorch", &map);
        assert_eq!(
            r.aliases
                .iter()
                .map(|a| a.pypi_name.as_str())
                .collect::<Vec<_>>(),
            vec!["torch-nightly"]
        );
        assert!(matches!(r.aliases[0].source, AliasSource::Mapping { .. }));
    }

    #[test]
    fn the_builtin_table_is_a_floor_under_a_loaded_mapping() {
        let map = loaded(&[("some-new-pkg", &["some-new-pkg"])]);
        let r = pypi_aliases("py-opencv", &map);
        assert_eq!(r.aliases[0].source, AliasSource::BuiltIn);
        assert_eq!(r.aliases[0].pypi_name, "opencv-python");
    }

    #[test]
    fn builtin_fallback_can_be_switched_off() {
        let map = loaded(&[("some-new-pkg", &["some-new-pkg"])]).without_builtin_fallback();
        let r = pypi_aliases("py-opencv", &map);
        assert!(matches!(r.coverage, AliasCoverage::Unmapped { .. }));
    }

    #[test]
    fn one_conda_package_may_carry_several_pypi_distributions() {
        let map = loaded(&[("some-bundle", &["Foo_Bar", "baz.qux"])]);
        let r = pypi_aliases("some-bundle", &map);
        assert_eq!(
            r.aliases
                .iter()
                .map(|a| a.pypi_name.as_str())
                .collect::<Vec<_>>(),
            vec!["foo-bar", "baz-qux"],
            "PyPI names must be PEP 503 normalized for OSV/GHSA lookup"
        );
    }

    #[test]
    fn duplicate_pypi_names_are_deduped_in_order() {
        // All three spellings are one PEP 503 project; `baz` is another.
        let map = loaded(&[("dupes", &["foo-bar", "Foo_Bar", "foo..bar", "baz"])]);
        let r = pypi_aliases("dupes", &map);
        assert_eq!(
            r.aliases
                .iter()
                .map(|a| a.pypi_name.as_str())
                .collect::<Vec<_>>(),
            vec!["foo-bar", "baz"]
        );
    }

    #[test]
    fn mapping_provenance_reaches_the_lookup_result() {
        let map = loaded(&[("thing", &["thing-py"])]);
        let r = pypi_aliases("thing", &map);
        match &r.aliases[0].source {
            AliasSource::Mapping { provenance } => {
                assert!(provenance.source.contains("parselmouth"));
                assert_eq!(provenance.fetched_at, fetched(2026, 9, 19));
                assert_eq!(provenance.channel.as_deref(), Some("conda-forge"));
            }
            other => panic!("expected mapping provenance, got {other:?}"),
        }
    }

    #[test]
    fn a_mapped_negative_also_carries_its_provenance() {
        let map = loaded(&[("libthing", &[])]);
        let r = pypi_aliases("libthing", &map);
        match &r.coverage {
            AliasCoverage::NotPythonPackage { source } => {
                assert!(matches!(source, AliasSource::Mapping { .. }));
            }
            other => panic!("expected mapped negative, got {other:?}"),
        }
    }

    #[test]
    fn provenance_survives_a_json_round_trip() {
        let map = loaded(&[("thing", &["thing-py"]), ("libthing", &[])]);
        let json = map.to_json_v1().expect("serialize");
        let back = AliasMap::from_json(json.as_bytes()).expect("load");
        assert_eq!(back.provenance(), map.provenance());
        assert_eq!(back.loaded_entries(), 2);
        assert_eq!(
            pypi_aliases("thing", &back).aliases[0].pypi_name,
            "thing-py"
        );
        assert!(matches!(
            pypi_aliases("libthing", &back).coverage,
            AliasCoverage::NotPythonPackage { .. }
        ));
    }

    #[test]
    fn loading_rejects_an_unknown_schema() {
        let doc = r#"{"schema":"something/else","provenance":{"source":"s","fetched_at":"2026-09-19T00:00:00Z"},"entries":{}}"#;
        assert!(matches!(
            AliasMap::from_json(doc.as_bytes()),
            Err(AliasMapError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn loading_rejects_an_oversize_document() {
        let huge = vec![b' '; MAX_MAPPING_BYTES + 1];
        assert!(matches!(
            AliasMap::from_json(&huge),
            Err(AliasMapError::TooLarge { .. })
        ));
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        for bad in [
            &b"{"[..],
            &b"null"[..],
            &b"[]"[..],
            &b"\xff\xfe\x00"[..],
            &b"{\"schema\":\"artifact-keeper/conda-pypi-alias/v1\"}"[..],
        ] {
            assert!(AliasMap::from_json(bad).is_err(), "{bad:?} should error");
        }
    }

    #[test]
    fn unusable_entries_are_skipped_and_counted_never_silently_dropped() {
        let doc = format!(
            r#"{{"schema":"{ALIAS_MAP_SCHEMA_V1}","provenance":{{"source":"s","fetched_at":"2026-09-19T00:00:00Z"}},"entries":{{"good":["fine"],"BAD NAME":["x"],"also-good":["!!!"]}}}}"#
        );
        let map = AliasMap::from_json(doc.as_bytes()).expect("load");
        assert_eq!(map.rejected_entries(), 2, "one bad key, one bad value");
        assert_eq!(pypi_aliases("good", &map).aliases[0].pypi_name, "fine");
        // The entry whose only value was unusable must not read as a
        // mapped negative -- we did not learn that it has no counterpart.
        assert!(matches!(
            pypi_aliases("also-good", &map).coverage,
            AliasCoverage::Unmapped { .. }
        ));
    }

    #[test]
    fn hostile_lookup_names_do_not_panic() {
        let map = AliasMap::builtin_only();
        for name in [
            "",
            "   ",
            "\u{0}",
            "\u{1F600}",
            &"x".repeat(100_000),
            "../../etc",
            "PyTorch",
        ] {
            let _ = pypi_aliases(name, &map);
        }
        // ...and the last one still resolves, because lookup normalizes case.
        assert_eq!(
            pypi_aliases("  PyTorch  ", &map).aliases[0].pypi_name,
            "torch"
        );
    }

    #[test]
    fn an_unnormalizable_lookup_name_is_unmapped_with_a_reason_saying_so() {
        let map = AliasMap::builtin_only();
        let r = pypi_aliases("not a conda name", &map);
        assert!(matches!(r.coverage, AliasCoverage::Unmapped { .. }));
        assert!(r
            .reason()
            .expect("reason")
            .contains("not a usable conda package name"));
    }

    #[test]
    fn staleness_distinguishes_fresh_stale_and_builtin_only() {
        let now = fetched(2026, 10, 25);
        let max_age = Duration::days(30);
        assert_eq!(
            AliasMap::builtin_only().staleness(now, max_age),
            Staleness::BuiltInOnly
        );
        let map = loaded(&[("a", &["a"])]); // fetched 2026-09-19 -> 36 days old
        match map.staleness(now, max_age) {
            Staleness::Stale { age, .. } => assert_eq!(age.num_days(), 36),
            other => panic!("expected stale, got {other:?}"),
        }
        assert!(matches!(
            map.staleness(fetched(2026, 9, 20), max_age),
            Staleness::Fresh { .. }
        ));
    }

    #[test]
    fn a_clock_skewed_mapping_reads_as_fresh_rather_than_negative_age() {
        let map = loaded(&[("a", &["a"])]);
        match map.staleness(fetched(2026, 1, 1), Duration::days(30)) {
            Staleness::Fresh { age } => assert_eq!(age.num_seconds(), 0),
            other => panic!("expected fresh, got {other:?}"),
        }
    }

    #[test]
    fn a_resolution_yields_pypi_purls_for_advisory_lookup() {
        let map = AliasMap::builtin_only();
        let r = pypi_aliases("py-opencv", &map);
        assert_eq!(r.pypi_purls("4.9.0"), vec!["pkg:pypi/opencv-python@4.9.0"]);
        // No version, no purl: a versionless purl matches every release.
        assert!(r.pypi_purls("").is_empty());
        assert!(pypi_aliases("zlib", &map).pypi_purls("1.3").is_empty());
    }

    #[test]
    fn pep503_normalization_matches_the_spec() {
        assert_eq!(normalize_pypi_name("Jinja2").as_deref(), Some("jinja2"));
        assert_eq!(
            normalize_pypi_name("zope.interface").as_deref(),
            Some("zope-interface")
        );
        assert_eq!(normalize_pypi_name("foo__bar").as_deref(), Some("foo-bar"));
        assert_eq!(
            normalize_pypi_name("  Flask-SQLAlchemy ").as_deref(),
            Some("flask-sqlalchemy")
        );
        assert_eq!(normalize_pypi_name("-leading"), None);
        assert_eq!(normalize_pypi_name("bad name"), None);
        assert_eq!(normalize_pypi_name(""), None);
    }

    #[test]
    fn conda_name_normalization_lowercases_but_never_rewrites_separators() {
        assert_eq!(
            normalize_conda_name(" Jupyter_Core ").as_deref(),
            Some("jupyter_core")
        );
        assert_eq!(
            normalize_conda_name("backports.functools_lru_cache").as_deref(),
            Some("backports.functools_lru_cache")
        );
        assert_eq!(normalize_conda_name("has space"), None);
    }

    #[test]
    fn the_grayskull_mapping_shape_inverts_to_conda_to_pypi() {
        let doc = r#"{
          "opencv-python": {"conda_name":"py-opencv","pypi_name":"opencv-python","import_name":"cv2","mapping_source":"regro-bot"},
          "torch": {"conda_name":"pytorch","pypi_name":"torch","import_name":"torch","mapping_source":"regro-bot"},
          "junk": {"pypi_name":"junk"}
        }"#;
        let map = AliasMap::from_grayskull_json(doc.as_bytes(), provenance()).expect("load");
        assert_eq!(
            pypi_aliases("py-opencv", &map).aliases[0].pypi_name,
            "opencv-python"
        );
        assert_eq!(pypi_aliases("pytorch", &map).aliases[0].pypi_name, "torch");
        assert_eq!(
            map.rejected_entries(),
            1,
            "an entry with no conda_name is unusable"
        );
    }

    #[test]
    fn archive_type_is_classified_from_the_filename() {
        assert_eq!(
            CondaArchiveType::from_filename("numpy-1.26.4-py311_0.conda"),
            Some(CondaArchiveType::CondaV2)
        );
        assert_eq!(
            CondaArchiveType::from_filename(" NumPy-1.26.4-py311_0.TAR.BZ2 "),
            Some(CondaArchiveType::TarBz2)
        );
        assert_eq!(CondaArchiveType::from_filename("numpy.whl"), None);
        assert_eq!(CondaArchiveType::TarBz2.as_str(), "tar.bz2");
    }

    #[test]
    fn accessors_report_exactly_what_was_recorded() {
        let p = CondaPurl::from_index("NumPy", "1.26.4", " py311_0 ", "linux-64")
            .expect("valid")
            .with_channel("conda-forge")
            .with_noarch(Some(NoarchKind::Generic))
            .with_archive_type(CondaArchiveType::CondaV2);
        assert_eq!(p.name(), "numpy");
        assert_eq!(p.version(), "1.26.4");
        assert_eq!(p.build(), Some("py311_0"));
        assert_eq!(p.subdir(), NOARCH_SUBDIR);
        assert_eq!(p.channel(), Some("conda-forge"));
        assert_eq!(p.noarch(), Some(NoarchKind::Generic));
        assert_eq!(p.archive_type(), Some(CondaArchiveType::CondaV2));

        // Declaring it a platform package leaves the subdir it was given.
        let q = CondaPurl::from_index("numpy", "1.0", "", "linux-64")
            .expect("valid")
            .with_noarch(None);
        assert_eq!(q.subdir(), "linux-64");
        assert_eq!(q.build(), None);
        assert_eq!(q.channel(), None);
    }

    #[test]
    fn serializing_a_map_with_no_provenance_is_refused_not_faked() {
        assert_eq!(
            AliasMap::builtin_only().to_json_v1(),
            Err(AliasMapError::NoProvenance)
        );
    }

    #[test]
    fn the_grayskull_adapter_enforces_the_same_size_ceiling() {
        let huge = vec![b' '; MAX_MAPPING_BYTES + 1];
        assert!(matches!(
            AliasMap::from_grayskull_json(&huge, provenance()),
            Err(AliasMapError::TooLarge { .. })
        ));
        assert!(AliasMap::from_grayskull_json(b"not json", provenance()).is_err());
    }

    #[test]
    fn errors_render_a_message_that_names_the_problem() {
        assert!(CondaPurlError::EmptyField { field: "name" }
            .to_string()
            .contains("name"));
        assert!(CondaPurlError::FieldTooLong {
            field: "build",
            len: 9,
            max: 4
        }
        .to_string()
        .contains("build"));
        assert!(CondaPurlError::InvalidName { name: "x y".into() }
            .to_string()
            .contains("x y"));
        assert!(CondaPurlError::InvalidSubdir { subdir: "X".into() }
            .to_string()
            .contains('X'));
        assert!(AliasMapError::TooLarge { len: 2, max: 1 }
            .to_string()
            .contains("ceiling"));
        assert!(AliasMapError::Malformed("eof".into())
            .to_string()
            .contains("eof"));
        assert!(AliasMapError::TooManyEntries { count: 2, max: 1 }
            .to_string()
            .contains("entries"));
        assert!(AliasMapError::UnsupportedSchema {
            found: "v9".into(),
            expected: ALIAS_MAP_SCHEMA_V1
        }
        .to_string()
        .contains("v9"));
        assert!(AliasMapError::NoProvenance
            .to_string()
            .contains("provenance"));
    }

    #[test]
    fn a_mapping_that_answers_nothing_still_reports_its_own_shape() {
        let map = loaded(&[]);
        assert_eq!(map.loaded_entries(), 0);
        assert_eq!(map.rejected_entries(), 0);
        assert!(map.has_builtin_fallback());
        assert!(!map
            .clone()
            .without_builtin_fallback()
            .has_builtin_fallback());
        // The Unmapped reason names the mapping, so a stale-but-loaded map is
        // distinguishable from no map at all.
        let reason = pypi_aliases("nothing-here", &map)
            .reason()
            .expect("reason")
            .to_string();
        assert!(reason.contains("parselmouth"), "{reason}");
        assert!(pypi_aliases("nothing-here", &AliasMap::builtin_only())
            .reason()
            .expect("reason")
            .contains("no mapping is loaded"));
    }

    #[test]
    fn an_unset_or_empty_setting_answers_from_the_builtin_table() {
        for setting in [None, Some(String::new()), Some("   ".to_string())] {
            let map = alias_map_from_setting(setting);
            assert!(map.has_builtin_fallback());
            assert_eq!(map.loaded_entries(), 0);
            assert!(map.provenance().is_none());
            assert_eq!(
                map.staleness(Utc::now(), Duration::days(7)),
                Staleness::BuiltInOnly
            );
        }
    }

    #[test]
    fn a_configured_mapping_is_loaded_and_answers_over_the_builtin_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        // Deliberately contradicts the built-in `pytorch -> torch`, so the
        // assertion proves the loaded mapping is consulted first.
        let source = loaded(&[("pytorch", &["torch-nightly"])]);
        std::fs::write(&path, source.to_json_v1().expect("serializes")).expect("writes");

        let map = alias_map_from_setting(Some(path.display().to_string()));
        assert_eq!(map.loaded_entries(), 1);
        let resolved = pypi_aliases("pytorch", &map);
        assert_eq!(resolved.status(), "mapped");
        assert_eq!(resolved.aliases[0].pypi_name, "torch-nightly");
    }

    #[test]
    fn a_mis_pointed_setting_narrows_coverage_instead_of_failing() {
        // A bad path must not take uploads down with it, and must not leave a
        // map that answers nothing -- the built-in floor still answers.
        let map = alias_map_from_setting(Some("/nonexistent/conda-aliases.json".to_string()));
        assert!(map.has_builtin_fallback());
        assert_eq!(map.loaded_entries(), 0);
        assert_eq!(pypi_aliases("pytorch", &map).status(), "mapped");
    }

    #[test]
    fn the_builtin_table_is_internally_consistent() {
        let map = AliasMap::builtin_only();
        assert!(map.has_builtin_fallback());
        for (conda, pypis) in BUILTIN_ALIASES {
            assert_eq!(
                normalize_conda_name(conda).as_deref(),
                Some(*conda),
                "{conda} is not in canonical conda form"
            );
            for p in *pypis {
                assert_eq!(
                    normalize_pypi_name(p).as_deref(),
                    Some(*p),
                    "{p} is not PEP 503 normalized"
                );
            }
        }
    }

    // =======================================================================
    // #4041/#4042 -- the persisted identity document
    //
    // These are the round trip the advisory path depends on: what the conda
    // ingest path writes into `artifact_metadata.metadata` is exactly what the
    // scanner reads back, and the three-way coverage distinction survives it.
    // =======================================================================

    fn input<'a>(
        name: &'a str,
        version: &'a str,
        build: &'a str,
        subdir: &'a str,
    ) -> CondaIdentityInput<'a> {
        CondaIdentityInput {
            name,
            version,
            build,
            subdir,
            ..Default::default()
        }
    }

    #[test]
    fn a_stored_conda_package_gets_a_purl_carrying_subdir_and_build() {
        let identity = CondaIdentity::resolve(
            CondaIdentityInput {
                channel: Some("conda-forge"),
                archive_type: Some(CondaArchiveType::CondaV2),
                ..input("numpy", "1.26.4", "py311h5f1cd34_0", "linux-64")
            },
            &AliasMap::builtin_only(),
        );

        let doc = identity.to_document();
        let purl = doc["purl"].as_str().expect("a stored package has a purl");
        assert_eq!(
            purl,
            "pkg:conda/numpy@1.26.4?build=py311h5f1cd34_0&channel=conda-forge&subdir=linux-64&type=conda"
        );
        assert_eq!(doc["subdir"], "linux-64");
        assert_eq!(doc["noarch"], false);
    }

    #[test]
    fn a_noarch_package_gets_one_identity_whatever_subdir_it_was_published_under() {
        // The same noarch artifact uploaded under three platform subdirs must
        // resolve to ONE purl, or every count downstream doubles.
        let identities: std::collections::BTreeSet<String> = ["linux-64", "osx-arm64", "noarch"]
            .iter()
            .map(|subdir| {
                let identity = CondaIdentity::resolve(
                    CondaIdentityInput {
                        noarch: Some(NoarchKind::Python),
                        ..input("requests", "2.31.0", "pyhd8ed1ab_0", subdir)
                    },
                    &AliasMap::builtin_only(),
                );
                identity.to_document()["purl"]
                    .as_str()
                    .expect("purl")
                    .to_string()
            })
            .collect();

        assert_eq!(identities.len(), 1, "noarch must not fan out per platform");
        let only = identities.into_iter().next().expect("one");
        assert!(only.contains("subdir=noarch"), "{only}");
        assert!(!only.contains("linux-64"), "{only}");
    }

    #[test]
    fn a_known_rename_resolves_to_its_pypi_name_and_a_queryable_pypi_purl() {
        let identity = CondaIdentity::resolve(
            input("py-opencv", "4.9.0", "py312h1234abc_0", "linux-64"),
            &AliasMap::builtin_only(),
        );

        assert_eq!(identity.aliases.status(), "mapped");
        assert_eq!(
            identity.pypi_purls(),
            vec!["pkg:pypi/opencv-python@4.9.0".to_string()],
            "conda `py-opencv` must inherit PyPI `opencv-python` advisory coverage"
        );

        let stored = read_identity(&serde_json::json!({
            IDENTITY_METADATA_KEY: identity.to_document(),
        }))
        .expect("the document is readable");
        assert_eq!(
            stored.pypi_advisory_targets(),
            vec![("opencv-python".to_string(), "4.9.0".to_string())]
        );
        assert!(!stored.is_known_unknown());
    }

    #[test]
    fn an_unmapped_package_records_unmapped_rather_than_silently_nothing() {
        let identity = CondaIdentity::resolve(
            input(
                "some-vendor-internal-lib",
                "1.2.3",
                "h1234567_0",
                "linux-64",
            ),
            &AliasMap::builtin_only(),
        );

        let doc = identity.to_document();
        assert_eq!(doc["pypi"]["status"], "unmapped");
        let reason = doc["pypi"]["reason"]
            .as_str()
            .expect("a reason is recorded");
        assert!(
            reason.contains("some-vendor-internal-lib"),
            "the reason names the package: {reason}"
        );

        let stored =
            read_identity(&serde_json::json!({ IDENTITY_METADATA_KEY: doc })).expect("readable");
        assert!(
            stored.is_known_unknown(),
            "an unmapped package is unexamined, not clean"
        );
        assert!(stored.pypi_advisory_targets().is_empty());
        assert!(matches!(stored.pypi, StoredPypiCoverage::Unmapped { .. }));
    }

    #[test]
    fn a_not_python_package_is_recorded_positively_and_is_not_an_unknown() {
        let identity = CondaIdentity::resolve(
            input("zlib", "1.3.1", "hb9d3cd8_2", "linux-64"),
            &AliasMap::builtin_only(),
        );

        let doc = identity.to_document();
        assert_eq!(doc["pypi"]["status"], "not_python");
        assert!(
            doc["pypi"]["reason"].is_null(),
            "`not_python` is an answer, not a gap, so it carries no gap reason"
        );

        let stored =
            read_identity(&serde_json::json!({ IDENTITY_METADATA_KEY: doc })).expect("readable");
        assert_eq!(stored.pypi, StoredPypiCoverage::NotPythonPackage);
        assert!(
            !stored.is_known_unknown(),
            "zlib ships no PyPI distribution; finding no PyPI advisory for it is a real answer"
        );
        assert!(stored.pypi_advisory_targets().is_empty());
    }

    #[test]
    fn unmapped_and_not_python_stay_distinguishable_through_the_document() {
        // Both produce zero PyPI names. Collapsing them is the false negative
        // this whole module exists to remove, so assert the split explicitly
        // at the persistence boundary.
        let unknown = CondaIdentity::resolve(
            input("never-heard-of-it", "1.0", "0", "linux-64"),
            &AliasMap::builtin_only(),
        );
        let native = CondaIdentity::resolve(
            input("openssl", "3.3.2", "hb9d3cd8_0", "linux-64"),
            &AliasMap::builtin_only(),
        );

        let read = |i: &CondaIdentity| {
            read_identity(&serde_json::json!({ IDENTITY_METADATA_KEY: i.to_document() }))
                .expect("readable")
        };
        let unknown = read(&unknown);
        let native = read(&native);

        assert_eq!(
            unknown.pypi_advisory_targets(),
            native.pypi_advisory_targets()
        );
        assert_ne!(
            unknown.pypi, native.pypi,
            "the same empty target list must not mean the same thing"
        );
        assert!(unknown.is_known_unknown());
        assert!(!native.is_known_unknown());
    }

    #[test]
    fn a_loaded_mappings_provenance_travels_into_the_stored_document() {
        let map = loaded(&[("py-opencv", &["opencv-python-headless"])]);
        let identity = CondaIdentity::resolve(
            input("py-opencv", "4.9.0", "py312h1234abc_0", "linux-64"),
            &map,
        );

        let doc = identity.to_document();
        let alias = &doc["pypi"]["aliases"][0];
        assert_eq!(alias["pypi_name"], "opencv-python-headless");
        assert_eq!(alias["purl"], "pkg:pypi/opencv-python-headless@4.9.0");
        assert_eq!(alias["source"]["kind"], "mapping");
        assert_eq!(
            alias["source"]["provenance"]["source"],
            "parselmouth conda-forge index @ 2026-09-18"
        );
        assert_eq!(
            alias["source"]["provenance"]["fetched_at"], "2026-09-19T00:00:00Z",
            "a finding must be able to say how old the claim it rests on is"
        );
    }

    #[test]
    fn a_builtin_answer_says_so_in_the_document() {
        let identity = CondaIdentity::resolve(
            input("pytorch", "2.3.1", "py3.12_cpu_0", "linux-64"),
            &AliasMap::builtin_only(),
        );
        let doc = identity.to_document();
        assert_eq!(doc["pypi"]["aliases"][0]["pypi_name"], "torch");
        assert_eq!(doc["pypi"]["aliases"][0]["source"]["kind"], "builtin");
    }

    #[test]
    fn a_metadata_document_with_no_identity_reads_as_absent_not_as_clean() {
        // Conda artifacts stored before this path existed have no identity
        // block. `None` is the caller's signal to treat them as unexamined.
        assert!(read_identity(&serde_json::json!({ "name": "numpy" })).is_none());
        assert!(read_identity(&serde_json::json!({ IDENTITY_METADATA_KEY: null })).is_none());
        assert!(read_identity(&serde_json::json!("not an object")).is_none());
    }

    #[test]
    fn an_unrecognized_status_reads_as_a_known_unknown() {
        // Forward compatibility: a newer writer, an older reader. Anything we
        // cannot interpret must not read as "nothing to look up".
        let stored = read_identity(&serde_json::json!({
            IDENTITY_METADATA_KEY: {
                "name": "numpy",
                "version": "1.26.4",
                "pypi": { "status": "resolved-by-some-future-thing" },
            }
        }))
        .expect("readable");
        assert!(stored.is_known_unknown());
        assert!(stored.pypi_advisory_targets().is_empty());
    }

    #[test]
    fn identity_resolution_never_fails_on_hostile_coordinates() {
        // An upload has already been stored by the time identity runs, so this
        // path has no failure mode available to it: it records what it could
        // not do and keeps going.
        for (name, version, build, subdir) in [
            ("", "1.0", "0", "linux-64"),
            ("numpy", "", "0", "linux-64"),
            ("../../etc/passwd", "1.0", "0", "linux-64"),
            ("numpy", "1.0", "0", "not a subdir"),
            ("numpy", "1.0", "0", "../linux-64"),
        ] {
            let identity = CondaIdentity::resolve(
                input(name, version, build, subdir),
                &AliasMap::builtin_only(),
            );
            let doc = identity.to_document();
            assert!(
                doc["purl"].is_null(),
                "{name}/{version}/{subdir} must not produce a purl"
            );
            assert!(
                doc["purl_error"].as_str().is_some_and(|e| !e.is_empty()),
                "{name}/{version}/{subdir} must say why it has no purl"
            );
            let stored = read_identity(&serde_json::json!({ IDENTITY_METADATA_KEY: doc }))
                .expect("readable");
            assert!(
                stored.conda_purl.is_none(),
                "an unresolvable artifact must not carry a purl"
            );
        }
    }

    #[test]
    fn an_attacker_controlled_version_cannot_forge_a_pypi_qualifier() {
        let identity = CondaIdentity::resolve(
            input("numpy", "1.26.4?subdir=noarch", "0", "linux-64"),
            &AliasMap::builtin_only(),
        );
        for purl in identity.pypi_purls() {
            assert!(
                !purl.contains("?subdir="),
                "the version must be percent-encoded, not spliced: {purl}"
            );
        }
    }

    #[test]
    fn the_stored_document_survives_a_json_string_round_trip() {
        let identity = CondaIdentity::resolve(
            CondaIdentityInput {
                channel: Some("https://conda.anaconda.org/conda-forge/linux-64"),
                archive_type: Some(CondaArchiveType::CondaV2),
                ..input("matplotlib-base", "3.8.4", "py312h20ab3a6_0", "linux-64")
            },
            &AliasMap::builtin_only(),
        );
        let wire = serde_json::to_string(&serde_json::json!({
            IDENTITY_METADATA_KEY: identity.to_document(),
        }))
        .expect("serializes");
        let parsed: serde_json::Value = serde_json::from_str(&wire).expect("parses");

        let stored = read_identity(&parsed).expect("readable");
        assert_eq!(
            stored.conda_purl.as_deref(),
            Some("pkg:conda/matplotlib-base@3.8.4?build=py312h20ab3a6_0&channel=conda-forge&subdir=linux-64&type=conda"),
            "the channel URL's trailing platform segment is the subdir, not part of the channel"
        );
        assert_eq!(stored.name, "matplotlib-base");
        assert_eq!(stored.version, "3.8.4");
        assert_eq!(
            stored.pypi_purls(),
            vec!["pkg:pypi/matplotlib@3.8.4".to_string()]
        );
    }

    // =======================================================================
    // #4041 -- the scanner/SBOM emission path reads the artifact's own purl
    // back out of its stored metadata
    // =======================================================================

    /// A metadata document shaped the way `build_conda_metadata` writes it:
    /// the flat coordinate keys plus the identity block under
    /// [`IDENTITY_METADATA_KEY`].
    fn ingest_shaped_metadata(
        name: &str,
        version: &str,
        build: &str,
        subdir: &str,
        noarch: Option<&str>,
        package_format: &str,
        channel: Option<&str>,
    ) -> serde_json::Value {
        let identity = CondaIdentity::resolve(
            CondaIdentityInput {
                name,
                version,
                build,
                subdir,
                noarch: noarch.and_then(NoarchKind::parse),
                channel,
                archive_type: CondaArchiveType::from_filename(if package_format == "v2" {
                    "x.conda"
                } else {
                    "x.tar.bz2"
                }),
            },
            &AliasMap::builtin_only(),
        );
        let mut doc = serde_json::json!({
            "name": name,
            "version": version,
            "build": build,
            "subdir": subdir,
            "package_format": package_format,
        });
        if let Some(n) = noarch {
            doc["noarch"] = serde_json::Value::String(n.to_string());
        }
        doc[IDENTITY_METADATA_KEY] = identity.to_document();
        doc
    }

    #[test]
    fn emission_purl_prefers_the_stored_identity_document() {
        let md = ingest_shaped_metadata(
            "numpy",
            "1.26.4",
            "py311h5f1cd34_0",
            "linux-64",
            None,
            "v2",
            Some("conda-forge"),
        );
        assert_eq!(
            artifact_purl_from_metadata(&md).as_deref(),
            Some(
                "pkg:conda/numpy@1.26.4?build=py311h5f1cd34_0&channel=conda-forge&subdir=linux-64&type=conda"
            )
        );
    }

    #[test]
    fn emission_purl_two_builds_on_different_subdirs_are_distinct_identities() {
        let linux = ingest_shaped_metadata(
            "numpy",
            "1.26.4",
            "py311h5f1cd34_0",
            "linux-64",
            None,
            "v2",
            Some("conda-forge"),
        );
        let mac = ingest_shaped_metadata(
            "numpy",
            "1.26.4",
            "py311h7aedaa7_0",
            "osx-arm64",
            None,
            "v2",
            Some("conda-forge"),
        );
        let a = artifact_purl_from_metadata(&linux).expect("purl");
        let b = artifact_purl_from_metadata(&mac).expect("purl");
        assert_ne!(a, b, "same name/version, different subdir+build");
        assert!(a.contains("subdir=linux-64"), "{a}");
        assert!(b.contains("subdir=osx-arm64"), "{b}");
    }

    #[test]
    fn emission_purl_noarch_is_one_identity_whatever_subdir_it_was_seen_under() {
        // The same noarch artifact stored under three subdirs must read back
        // as ONE purl, or the SBOM counts it once per platform. Mutation
        // check: dropping the noarch collapse fails this loudly.
        let identities: std::collections::BTreeSet<String> = ["linux-64", "osx-arm64", "noarch"]
            .iter()
            .map(|s| {
                artifact_purl_from_metadata(&ingest_shaped_metadata(
                    "requests",
                    "2.31.0",
                    "pyhd8ed1ab_0",
                    s,
                    Some("python"),
                    "v1",
                    Some("conda-forge"),
                ))
                .expect("purl")
            })
            .collect();
        assert_eq!(identities.len(), 1, "noarch must not fan out per subdir");
        let only = identities.into_iter().next().expect("one");
        assert!(only.contains("subdir=noarch"), "{only}");
        assert!(!only.contains("linux-64"), "{only}");
    }

    #[test]
    fn emission_purl_falls_back_to_flat_coordinates_for_pre_identity_metadata() {
        // A document written before the identity block existed has only the
        // flat keys. No channel is recorded at that level, so the fallback
        // purl carries build+subdir (+archive type) and no channel qualifier.
        let md = serde_json::json!({
            "name": "numpy",
            "version": "1.26.4",
            "build": "py311_0",
            "subdir": "linux-64",
            "package_format": "v2",
        });
        assert_eq!(
            artifact_purl_from_metadata(&md).as_deref(),
            Some("pkg:conda/numpy@1.26.4?build=py311_0&subdir=linux-64&type=conda")
        );

        // v1 container, no build qualifier when build is empty.
        let md = serde_json::json!({
            "name": "zlib",
            "version": "1.3",
            "build": "",
            "subdir": "osx-64",
            "package_format": "v1",
        });
        assert_eq!(
            artifact_purl_from_metadata(&md).as_deref(),
            Some("pkg:conda/zlib@1.3?subdir=osx-64&type=tar.bz2")
        );
    }

    #[test]
    fn emission_purl_fallback_still_enforces_the_noarch_invariant() {
        let md = serde_json::json!({
            "name": "requests",
            "version": "2.31.0",
            "build": "pyhd8ed1ab_0",
            "subdir": "linux-64",
            "noarch": "python",
            "package_format": "v1",
        });
        let purl = artifact_purl_from_metadata(&md).expect("purl");
        assert!(purl.contains("subdir=noarch"), "{purl}");
        assert!(!purl.contains("linux-64"), "{purl}");
    }

    #[test]
    fn emission_purl_is_none_only_when_no_usable_coordinates_exist() {
        assert_eq!(artifact_purl_from_metadata(&serde_json::json!({})), None);
        assert_eq!(
            artifact_purl_from_metadata(&serde_json::json!({"name": "numpy"})),
            None
        );
        assert_eq!(
            artifact_purl_from_metadata(&serde_json::json!({"name": "numpy", "version": "1.26.4"})),
            None,
            "no subdir: the artifact's platform is genuinely unknown"
        );
        // Build is the one optional coordinate: an absent build widens the
        // identity honestly instead of asserting a build string of "".
        assert_eq!(
            artifact_purl_from_metadata(&serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "subdir": "linux-64",
            }))
            .as_deref(),
            Some("pkg:conda/numpy@1.26.4?subdir=linux-64")
        );
    }

    #[test]
    fn emission_purl_hostile_build_string_cannot_forge_qualifiers() {
        // The fallback reads attacker-influenced package metadata; a build
        // string carrying purl delimiters must be percent-encoded, never
        // spliced into the qualifier set.
        let md = serde_json::json!({
            "name": "numpy",
            "version": "1.26.4",
            "build": "abc&channel=evil?subdir=fake",
            "subdir": "linux-64",
            "package_format": "v1",
        });
        let purl = artifact_purl_from_metadata(&md).expect("purl");
        assert!(!purl.contains("channel=evil"), "{purl}");
        assert!(!purl.contains("subdir=fake"), "{purl}");
        assert!(purl.contains("subdir=linux-64"), "{purl}");
        assert!(purl.contains("%26channel%3Devil"), "{purl}");
    }

    #[test]
    fn row_names_artifact_matches_on_normalized_name_and_exact_version() {
        assert!(row_names_artifact(
            "NumPy",
            Some("1.26.4"),
            "numpy",
            Some("1.26.4")
        ));
        assert!(row_names_artifact(
            "numpy",
            Some("1.26.4"),
            "NumPy",
            Some("1.26.4")
        ));
        // Version drift in either direction is a different artifact.
        assert!(!row_names_artifact(
            "numpy",
            Some("1.26.3"),
            "numpy",
            Some("1.26.4")
        ));
        // A versionless row can name anything; a versionless artifact row can
        // confirm nothing. Neither may acquire this build's identity.
        assert!(!row_names_artifact("numpy", None, "numpy", Some("1.26.4")));
        assert!(!row_names_artifact("numpy", Some("1.26.4"), "numpy", None));
        // A different package entirely.
        assert!(!row_names_artifact(
            "pandas",
            Some("1.26.4"),
            "numpy",
            Some("1.26.4")
        ));
    }

    // -- the loadable mapping file ------------------------------------------

    #[test]
    fn a_canonical_mapping_file_loads_with_its_provenance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        let source = loaded(&[("py-opencv", &["opencv-python"])]);
        std::fs::write(&path, source.to_json_v1().expect("serializes")).expect("writes");

        let map = load_alias_map_file(&path).expect("loads");
        assert_eq!(map.loaded_entries(), 1);
        assert_eq!(
            map.provenance().expect("provenance").source,
            "parselmouth conda-forge index @ 2026-09-18"
        );
        assert_eq!(pypi_aliases("py-opencv", &map).status(), "mapped");
    }

    #[test]
    fn an_unreadable_mapping_file_is_an_error_not_a_silent_empty_map() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist.json");
        assert!(matches!(
            load_alias_map_file(&missing),
            Err(AliasMapError::Unreadable(_))
        ));

        let garbage = dir.path().join("garbage.json");
        std::fs::write(&garbage, b"not json at all").expect("writes");
        assert!(matches!(
            load_alias_map_file(&garbage),
            Err(AliasMapError::Malformed(_))
        ));
    }
}
