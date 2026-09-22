//! Lockfile ingestion: a solved environment as a per-platform dependency graph
//! (#4052).
//!
//! Nobody deploys a package; they deploy a solved environment. "Are we exposed
//! to CVE-2023-4863" is a question about a lockfile, and a registry that can
//! only answer package-by-package is answering a question nobody asked. This
//! module parses the lockfile itself so the registry holds the *graph* —
//! `dependant -> dependency` — rather than the flat finding list a scanner
//! already produces. "libwebp is vulnerable" is a fact; "libwebp is vulnerable
//! and it is here because you asked for pillow" is a remediation, and only the
//! edges can say that ([`LockedEnvironment::explain`]).
//!
//! # Scopes: N graphs, not one graph with annotations
//!
//! A conda environment is **N graphs, one per platform**. `depends` and
//! `constrains` resolve differently per subdir, so collapsing `linux-64` and
//! `osx-arm64` into one node set produces a document that is wrong for every
//! platform. `pixi.lock` additionally carries several *named environments*
//! (`default`, `test`, …) over the same package pool. Both axes are therefore
//! folded into a [`Scope`] — `(environment, platform)` — and every package
//! membership and every edge carries one. A package that is a member of three
//! platforms appears as three [`LockedPackage`] rows; that is deliberate (see
//! [`LockedEnvironment::packages`]).
//!
//! # Honesty: nothing is ever silently dropped
//!
//! [`LockedEnvironment::unresolved`] exists so that "this environment has 400
//! packages" and "we understood 380 of them" stay distinguishable. Every entry
//! we could not interpret, every requirement that names a package which is not
//! in its scope, and every conda virtual package lands there with a reason.
//! [`UnresolvedKind`] separates a genuine parse failure from a requirement that
//! is *correctly* absent (an unselected extra, an unsatisfied `constrains`), so
//! a caller can compute either number; see [`LockSummary`].
//!
//! # Formats
//!
//! [`LockFormat`] covers `pixi.lock`, `conda-lock.yml`, `package-lock.json`,
//! `Cargo.lock`, `poetry.lock` and `uv.lock`. Which of those record real edges
//! versus only a resolved set is documented on each variant — this is not
//! uniform and a caller must not assume it is. `yarn.lock`, `Gemfile.lock` and
//! friends use custom grammars that need real parsers; they are enumerated in
//! [`UNHANDLED_LOCKFILES`] so "we do not handle this" stays distinguishable
//! from "we tried and produced nothing".
//!
//! # Bounds
//!
//! Input is read through [`crate::util::bounded_archive::read_capped`] against
//! a ceiling clamped to the existing ingest decompression budget — this module
//! raises no ceiling. Entry counts are capped, and a lexical nesting-depth
//! guard runs before any recursive-descent parser sees the bytes. Malformed,
//! truncated, hostile and enormous inputs degrade or error; nothing here
//! panics.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::Read;

use crate::error::{AppError, Result};
use crate::util::bounded_archive::{max_ingest_decompressed_bytes, positive_env_or, read_capped};

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Default ceiling on a single lockfile's decoded size. Lockfiles are text; a
/// very large solved environment (a few thousand packages across a handful of
/// platforms) is single-digit MiB, so 32 MiB is far above any real document
/// while keeping the worst-case parse allocation modest.
pub const DEFAULT_MAX_LOCKFILE_BYTES: u64 = 32 * 1024 * 1024;

/// Env var tuning [`DEFAULT_MAX_LOCKFILE_BYTES`]. Blank/zero/non-numeric falls
/// back to the default, matching `bounded_archive`'s `positive_env_or` idiom.
pub const MAX_LOCKFILE_BYTES_ENV: &str = "MAX_LOCKFILE_BYTES";

/// Maximum number of package *memberships* (scope × package) one lockfile may
/// produce. Breaching it is an error, never a truncation — a truncated graph
/// that still reports a package count would be exactly the silent-loss failure
/// this module exists to prevent.
pub const MAX_LOCK_PACKAGE_ENTRIES: usize = 200_000;

/// Maximum number of edges one lockfile may produce. Same all-or-error rule as
/// [`MAX_LOCK_PACKAGE_ENTRIES`].
pub const MAX_LOCK_EDGES: usize = 2_000_000;

/// Maximum number of [`UnresolvedEntry`] rows one lockfile may produce.
pub const MAX_LOCK_UNRESOLVED: usize = 200_000;

/// Maximum bracket nesting depth accepted before any structured parser is
/// invoked. `serde_json` enforces its own recursion limit, but `toml` and
/// `serde_yaml` build their value trees recursively and a deeply nested
/// document can exhaust the stack — which aborts the process rather than
/// unwinding, so it cannot be caught. This guard runs first.
pub const MAX_LOCK_NESTING_DEPTH: usize = 128;

/// Maximum leading-whitespace columns accepted on any line. YAML block nesting
/// is expressed as indentation, so this is the block-style counterpart to
/// [`MAX_LOCK_NESTING_DEPTH`]. Two columns per level puts the effective block
/// depth limit in the same range.
pub const MAX_LOCK_INDENT_COLUMNS: usize = 512;

/// Effective ceiling on a decoded lockfile, honouring [`MAX_LOCKFILE_BYTES_ENV`]
/// but clamped to the shared ingest decompression budget so this module can
/// never raise an existing ceiling — only sit at or below it.
pub fn max_lockfile_bytes() -> u64 {
    positive_env_or(MAX_LOCKFILE_BYTES_ENV, DEFAULT_MAX_LOCKFILE_BYTES)
        .min(max_ingest_decompressed_bytes())
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// A lockfile format this module can parse.
///
/// The `edges` note on each variant is the load-bearing part: several lockfiles
/// record *resolved versions* without recording *who required them*, and a
/// caller that assumes a populated graph from all six will get an empty one
/// from some.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LockFormat {
    /// `pixi.lock` (prefix.dev). Conda **and** PyPI packages in one document,
    /// per named environment and per platform, with URLs and hashes.
    /// Edges: real, from conda `depends`/`constrains` and PyPI `requires_dist`.
    PixiLock,
    /// `conda-lock.yml`. Per-platform, conda + pip.
    /// Edges: real, from each package's `dependencies` map.
    CondaLock,
    /// `package-lock.json` / `npm-shrinkwrap.json` (lockfileVersion 1/2/3).
    /// Edges: real for v2/v3 (`packages` carries each node's `dependencies`,
    /// `devDependencies`, `optionalDependencies`, `peerDependencies` and the
    /// node-resolution path); for v1 only, `requires` gives edges but the root
    /// project's direct dependencies are not recorded at all.
    NpmPackageLock,
    /// `Cargo.lock`.
    /// Edges: real, from each `[[package]]`'s `dependencies` list — but Cargo
    /// records the *union* of normal/build/dev and no `cfg()` conditionality,
    /// so every edge is [`EdgeKind::Runtime`] and platform-specific
    /// dependencies are indistinguishable from unconditional ones.
    CargoLock,
    /// `poetry.lock`.
    /// Edges: real between packages, but the *project's own* dependencies live
    /// in `pyproject.toml`, not the lockfile — so there is no root node and a
    /// top-level package cannot be told apart from a transitive one.
    PoetryLock,
    /// `uv.lock`.
    /// Edges: real, and the project itself appears as an editable/virtual
    /// package, so the graph does have a root.
    UvLock,
}

impl LockFormat {
    /// Canonical lower-case identifier, suitable for storage and API output.
    pub fn as_str(self) -> &'static str {
        match self {
            LockFormat::PixiLock => "pixi.lock",
            LockFormat::CondaLock => "conda-lock",
            LockFormat::NpmPackageLock => "package-lock.json",
            LockFormat::CargoLock => "Cargo.lock",
            LockFormat::PoetryLock => "poetry.lock",
            LockFormat::UvLock => "uv.lock",
        }
    }

    /// Whether the format expresses a separate graph per platform. `false`
    /// means every [`Scope`] this format produces has `platform: None` — not
    /// that the environment is portable.
    pub fn is_per_platform(self) -> bool {
        matches!(self, LockFormat::PixiLock | LockFormat::CondaLock)
    }
}

impl fmt::Display for LockFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Packaging ecosystem a locked package belongs to. A single lockfile can mix
/// them (`pixi.lock` and `conda-lock.yml` both carry conda and PyPI packages),
/// which is why this is per-package and not per-document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ecosystem {
    Conda,
    PyPi,
    Npm,
    Cargo,
}

impl Ecosystem {
    /// Canonical identifier, matching the purl type where one exists.
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Conda => "conda",
            Ecosystem::PyPi => "pypi",
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "cargo",
        }
    }

    /// Normalise a package name the way this ecosystem compares names, so a
    /// requirement string and a package entry match even when they disagree on
    /// case or separator.
    pub fn normalize(self, name: &str) -> String {
        match self {
            // PEP 503: lower-case, runs of `-`, `_` and `.` collapse to `-`.
            Ecosystem::PyPi => normalize_pypi_name(name),
            // conda and cargo names are case-insensitive in practice and never
            // carry separator ambiguity; npm names are already lower-case.
            _ => name.trim().to_ascii_lowercase(),
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One dependency graph's coordinates: a named environment and a platform.
///
/// Both are optional because not every format has both axes — `Cargo.lock` has
/// neither, `conda-lock.yml` has only a platform, `pixi.lock` has both. Two
/// packages are in the same graph iff their scopes are equal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scope {
    /// Named environment (`pixi.lock`'s `environments` keys). `None` when the
    /// format has no such concept.
    pub environment: Option<String>,
    /// Platform / conda subdir (`linux-64`, `osx-arm64`). `None` when the
    /// format does not resolve per platform.
    pub platform: Option<String>,
}

impl Scope {
    /// The single scope of a format that resolves neither per environment nor
    /// per platform.
    pub fn global() -> Self {
        Scope::default()
    }

    /// A platform-only scope (`conda-lock.yml`).
    pub fn platform(platform: impl Into<String>) -> Self {
        Scope {
            environment: None,
            platform: Some(platform.into()),
        }
    }

    /// A fully-qualified `pixi.lock` scope.
    pub fn env_platform(environment: impl Into<String>, platform: impl Into<String>) -> Self {
        Scope {
            environment: Some(environment.into()),
            platform: Some(platform.into()),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.environment, &self.platform) {
            (Some(e), Some(p)) => write!(f, "{}/{}", e, p),
            (Some(e), None) => write!(f, "{}", e),
            (None, Some(p)) => write!(f, "{}", p),
            (None, None) => f.write_str("(global)"),
        }
    }
}

/// A content hash recorded by the lockfile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageHash {
    /// Lower-case algorithm name (`sha256`, `sha512`, `md5`).
    pub algorithm: String,
    /// Digest exactly as the lockfile spells it — hex for conda/cargo, base64
    /// for an npm `integrity` value. Not re-encoded, because re-encoding would
    /// make it stop matching the document it came from.
    pub value: String,
    /// Distribution file this hash covers, when the format records one per file
    /// (`poetry.lock` lists every wheel and sdist for a package).
    pub file: Option<String>,
}

/// One package as a member of one [`Scope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    /// The graph this membership belongs to.
    pub scope: Scope,
    pub ecosystem: Ecosystem,
    /// Name as the lockfile spells it (not normalised — use
    /// [`Ecosystem::normalize`] to compare).
    pub name: String,
    /// Resolved version. `None` for entries a lockfile records without one
    /// (an npm workspace link, a `uv.lock` virtual root).
    pub version: Option<String>,
    /// Conda build string (`py311h1234_0`), when the format records one.
    pub build: Option<String>,
    /// Download URL, when the format records one.
    pub url: Option<String>,
    /// Registry / channel / index the package came from, when the format
    /// records that separately from the URL (`Cargo.lock`'s `source`).
    pub source: Option<String>,
    /// Every hash the lockfile records for this package.
    pub hashes: Vec<PackageHash>,
    /// Identity of this package *within its scope*. Edges reference it.
    pub key: String,
    /// Whether this node is the project being locked rather than one of its
    /// dependencies. Only `uv.lock` and npm v2/v3 record it.
    pub is_root: bool,
}

/// Why a dependant depends on a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EdgeKind {
    /// Needed at run time.
    Runtime,
    /// Needed only to build the dependant.
    Build,
    /// Needed only for development/testing.
    Dev,
    /// Selected by an extra / optional dependency group.
    Optional,
    /// An npm `peerDependencies` entry.
    Peer,
    /// A conda `constrains` entry: *if* this package is installed it must match
    /// the given spec. Not an install requirement.
    Constrains,
}

impl EdgeKind {
    /// Canonical identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Runtime => "runtime",
            EdgeKind::Build => "build",
            EdgeKind::Dev => "dev",
            EdgeKind::Optional => "optional",
            EdgeKind::Peer => "peer",
            EdgeKind::Constrains => "constrains",
        }
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A resolved `dependant -> dependency` edge inside one [`Scope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEdge {
    /// The graph this edge belongs to. `from` and `to` are keys of packages in
    /// this same scope.
    pub scope: Scope,
    /// [`LockedPackage::key`] of the dependant.
    pub from: String,
    /// [`LockedPackage::key`] of the dependency.
    pub to: String,
    pub kind: EdgeKind,
    /// The requirement text as the lockfile spelled it (`libwebp >=1.3.2`), so
    /// a caller can show *why* the edge exists, not just that it does.
    pub requirement: String,
}

/// Why an entry did not become a package or an edge.
///
/// The split matters: [`UnresolvedKind::Unparsed`] means we failed, while
/// [`UnresolvedKind::ConditionalNotInstalled`] and
/// [`UnresolvedKind::VirtualPackage`] mean we understood the entry perfectly
/// and it correctly has no node. Collapsing them would make "we understood 380
/// of 400" unanswerable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnresolvedKind {
    /// We could not interpret the entry at all: wrong shape, missing name,
    /// unknown package kind, unparseable requirement. A gap in our coverage.
    Unparsed,
    /// Parsed cleanly, names a package that is not in this scope, and nothing
    /// explains the absence. A gap in the *graph* — the lockfile is either
    /// inconsistent or uses a mechanism we do not model.
    MissingDependency,
    /// Parsed cleanly and is absent for a reason the lockfile states: an
    /// unselected extra, an environment marker that did not apply, or a conda
    /// `constrains` on a package that is not installed. Not a gap.
    ConditionalNotInstalled,
    /// Parsed cleanly and names a conda virtual package (`__glibc`, `__unix`),
    /// which describes the host rather than anything installed. Not a gap.
    VirtualPackage,
    /// Parsed cleanly but matched more than one package in scope and the
    /// requirement did not say which. Edges were emitted to every candidate;
    /// this row records that the choice was not ours to make.
    Ambiguous,
}

impl UnresolvedKind {
    /// Canonical identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            UnresolvedKind::Unparsed => "unparsed",
            UnresolvedKind::MissingDependency => "missing_dependency",
            UnresolvedKind::ConditionalNotInstalled => "conditional_not_installed",
            UnresolvedKind::VirtualPackage => "virtual_package",
            UnresolvedKind::Ambiguous => "ambiguous",
        }
    }

    /// Whether this row means *we* did not understand the input, as opposed to
    /// understanding it and correctly producing no node.
    pub fn is_parse_failure(self) -> bool {
        matches!(self, UnresolvedKind::Unparsed)
    }

    /// Whether this row means the graph is missing something it should have.
    pub fn is_graph_gap(self) -> bool {
        matches!(
            self,
            UnresolvedKind::Unparsed
                | UnresolvedKind::MissingDependency
                | UnresolvedKind::Ambiguous
        )
    }
}

impl fmt::Display for UnresolvedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing the lockfile said that did not become a package or an edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedEntry {
    /// Scope the entry was seen in. `Scope::global()` for document-level rows.
    pub scope: Scope,
    pub kind: UnresolvedKind,
    /// What we saw, e.g. `pillow -> libwebp >=1.3.2` or the raw entry text.
    pub subject: String,
    /// Why it did not resolve, in a form a human can act on.
    pub reason: String,
}

impl fmt::Display for UnresolvedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} in {}: {}",
            self.kind, self.subject, self.scope, self.reason
        )
    }
}

/// Counts that let a caller state coverage honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LockSummary {
    /// Package memberships: one per (scope, package).
    pub memberships: usize,
    /// Distinct `(ecosystem, name, version)` triples across all scopes.
    pub distinct_packages: usize,
    /// Number of graphs (distinct scopes).
    pub scopes: usize,
    pub edges: usize,
    /// Rows we failed to interpret.
    pub unparsed: usize,
    /// Requirements naming a package absent from their scope for no stated
    /// reason.
    pub missing_dependencies: usize,
    /// Requirements correctly absent (extras, markers, `constrains`) plus conda
    /// virtual packages.
    pub explained_absences: usize,
    /// Requirements that matched several candidates.
    pub ambiguous: usize,
}

/// A solved environment: its packages, its edges, and everything about it we
/// could not interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedEnvironment {
    pub format: LockFormat,
    /// Format version declared by the document, when it declares one.
    pub format_version: Option<String>,
    /// Named environments, sorted. Empty when the format has no such concept.
    pub environments: Vec<String>,
    /// Platforms / conda subdirs, sorted. Empty when the format does not
    /// resolve per platform.
    pub platforms: Vec<String>,
    /// Package memberships. **One row per (scope, package)** — a package that
    /// is a member of three platforms appears three times, because those are
    /// three different graphs. Use [`LockedEnvironment::summary`] for the
    /// deduplicated count.
    pub packages: Vec<LockedPackage>,
    /// Resolved edges, each inside one scope.
    pub edges: Vec<LockEdge>,
    /// Everything that did not become a package or an edge, with a reason.
    pub unresolved: Vec<UnresolvedEntry>,
}

impl LockedEnvironment {
    /// Every distinct graph in this document, sorted.
    pub fn scopes(&self) -> Vec<Scope> {
        let mut seen: BTreeSet<Scope> = BTreeSet::new();
        for pkg in &self.packages {
            seen.insert(pkg.scope.clone());
        }
        seen.into_iter().collect()
    }

    /// Packages belonging to one graph.
    pub fn packages_in<'a>(&'a self, scope: &Scope) -> impl Iterator<Item = &'a LockedPackage> {
        let scope = scope.clone();
        self.packages.iter().filter(move |p| p.scope == scope)
    }

    /// Edges belonging to one graph.
    pub fn edges_in<'a>(&'a self, scope: &Scope) -> impl Iterator<Item = &'a LockEdge> {
        let scope = scope.clone();
        self.edges.iter().filter(move |e| e.scope == scope)
    }

    /// Look up a package by key within one graph.
    pub fn package(&self, scope: &Scope, key: &str) -> Option<&LockedPackage> {
        self.packages
            .iter()
            .find(|p| &p.scope == scope && p.key == key)
    }

    /// Keys of the packages that depend on `key` in this graph.
    pub fn dependants_of<'a>(&'a self, scope: &Scope, key: &str) -> Vec<&'a str> {
        let mut out: Vec<&str> = self
            .edges_in(scope)
            .filter(|e| e.to == key)
            .map(|e| e.from.as_str())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Keys of the packages `key` depends on in this graph.
    pub fn dependencies_of<'a>(&'a self, scope: &Scope, key: &str) -> Vec<&'a str> {
        let mut out: Vec<&str> = self
            .edges_in(scope)
            .filter(|e| e.from == key)
            .map(|e| e.to.as_str())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Why `key` is in this environment: shortest chains from each package that
    /// nothing else depends on, down to `key`.
    ///
    /// This is the remediation answer — `["pillow", "libwebp"]` says libwebp is
    /// here because you asked for pillow. Each returned chain starts at a node
    /// with no dependants and ends at `key`. Bounded: at most `max_chains`
    /// chains, each at most [`Self::MAX_EXPLAIN_DEPTH`] long, and each node is
    /// visited once, so a cyclic graph terminates.
    pub fn explain(&self, scope: &Scope, key: &str, max_chains: usize) -> Vec<Vec<String>> {
        if max_chains == 0 || self.package(scope, key).is_none() {
            return Vec::new();
        }
        // Breadth-first over *reverse* edges: the first time we reach a node is
        // via a shortest chain, so recording one predecessor per node is enough
        // to reconstruct it.
        let mut predecessor: HashMap<&str, &str> = HashMap::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        let mut roots: Vec<&str> = Vec::new();
        seen.insert(key);
        queue.push_back(key);
        while let Some(node) = queue.pop_front() {
            let dependants = self.dependants_of(scope, node);
            if dependants.is_empty() && node != key {
                roots.push(node);
                if roots.len() >= max_chains {
                    break;
                }
                continue;
            }
            for dependant in dependants {
                if seen.insert(dependant) {
                    predecessor.insert(dependant, node);
                    queue.push_back(dependant);
                }
            }
        }
        // `key` itself is a root when nothing depends on it.
        if roots.is_empty() && self.dependants_of(scope, key).is_empty() {
            return vec![vec![key.to_string()]];
        }
        let mut chains = Vec::new();
        for root in roots {
            let mut chain = vec![root.to_string()];
            let mut cursor = root;
            let mut depth = 0usize;
            while cursor != key && depth < Self::MAX_EXPLAIN_DEPTH {
                match predecessor.get(cursor) {
                    Some(next) => {
                        chain.push((*next).to_string());
                        cursor = next;
                    }
                    None => break,
                }
                depth += 1;
            }
            if cursor == key {
                chains.push(chain);
            }
        }
        chains
    }

    /// Depth ceiling for [`Self::explain`], so a pathological graph cannot
    /// produce an unbounded chain.
    pub const MAX_EXPLAIN_DEPTH: usize = 256;

    /// Coverage counts. The spine of this module: `summary().memberships` and
    /// `summary().unparsed` together say how much of the document we actually
    /// understood.
    pub fn summary(&self) -> LockSummary {
        let mut distinct: BTreeSet<(Ecosystem, &str, Option<&str>)> = BTreeSet::new();
        for pkg in &self.packages {
            distinct.insert((pkg.ecosystem, pkg.name.as_str(), pkg.version.as_deref()));
        }
        let mut summary = LockSummary {
            memberships: self.packages.len(),
            distinct_packages: distinct.len(),
            scopes: self.scopes().len(),
            edges: self.edges.len(),
            ..LockSummary::default()
        };
        for entry in &self.unresolved {
            match entry.kind {
                UnresolvedKind::Unparsed => summary.unparsed += 1,
                UnresolvedKind::MissingDependency => summary.missing_dependencies += 1,
                UnresolvedKind::ConditionalNotInstalled | UnresolvedKind::VirtualPackage => {
                    summary.explained_absences += 1
                }
                UnresolvedKind::Ambiguous => summary.ambiguous += 1,
            }
        }
        summary
    }
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

/// Lockfiles that are deliberately **not** parsed, with the reason.
///
/// These use bespoke grammars (yarn's indentation-and-colon dialect, Bundler's
/// section format) that need real parsers, or are simply out of this issue's
/// scope. Naming them lets a caller say "we do not handle this" instead of
/// reporting an empty environment, which would be indistinguishable from a
/// lockfile with no packages.
pub const UNHANDLED_LOCKFILES: &[(&str, &str)] = &[
    (
        "yarn.lock",
        "yarn's custom indentation-based grammar (v1) and its YAML-ish v2+ \
         dialect both need a dedicated parser; neither is YAML that serde_yaml \
         will accept",
    ),
    (
        "gemfile.lock",
        "Bundler's sectioned custom format (GEM/PATH/DEPENDENCIES blocks with \
         significant indentation) needs a dedicated parser",
    ),
    (
        "pnpm-lock.yaml",
        "YAML, but pnpm's content-addressed key grammar \
         (`/pkg@1.0.0(peer@2.0.0)`) needs its own resolver; out of scope",
    ),
    (
        "composer.lock",
        "JSON and tractable, but PHP is out of this issue's scope",
    ),
    (
        "pipfile.lock",
        "JSON and tractable, but records only hashes and versions per group \
         with no inter-package edges; out of this issue's scope",
    ),
    (
        "go.sum",
        "a checksum database, not a resolved graph; go.mod's build list is the \
         real input and is out of scope",
    ),
    (
        "gradle.lockfile",
        "Gradle's per-configuration flat list records no edges; out of scope",
    ),
];

/// The [`LockFormat`] a file name implies, if any.
///
/// Matching is on the base name, case-insensitively. `conda-lock.yml` is also
/// recognised through its `<name>.conda-lock.yml` multi-environment spelling.
pub fn detect_format(file_name: &str) -> Option<LockFormat> {
    let base = base_name(file_name).to_ascii_lowercase();
    match base.as_str() {
        "pixi.lock" => return Some(LockFormat::PixiLock),
        "conda-lock.yml" | "conda-lock.yaml" => return Some(LockFormat::CondaLock),
        "package-lock.json" | "npm-shrinkwrap.json" => return Some(LockFormat::NpmPackageLock),
        "cargo.lock" => return Some(LockFormat::CargoLock),
        "poetry.lock" => return Some(LockFormat::PoetryLock),
        "uv.lock" => return Some(LockFormat::UvLock),
        _ => {}
    }
    if base.ends_with(".conda-lock.yml") || base.ends_with(".conda-lock.yaml") {
        return Some(LockFormat::CondaLock);
    }
    None
}

/// The reason a known-but-unparsed lockfile is not handled, if `file_name` is
/// one of [`UNHANDLED_LOCKFILES`].
pub fn unhandled_reason(file_name: &str) -> Option<&'static str> {
    let base = base_name(file_name).to_ascii_lowercase();
    UNHANDLED_LOCKFILES
        .iter()
        .find(|(name, _)| *name == base)
        .map(|(_, reason)| *reason)
}

/// Base name of a path, tolerating either separator. Never panics: `rsplit`
/// always yields at least one item.
fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Read a lockfile from `reader` under the size ceiling and parse it.
pub fn parse_lockfile_from_reader<R: Read>(
    format: LockFormat,
    reader: R,
) -> Result<LockedEnvironment> {
    let bytes = read_capped(reader, max_lockfile_bytes(), "lockfile")?;
    parse_lockfile(format, &bytes)
}

/// Read a lockfile from `reader`, choosing the format from `file_name`.
///
/// A name in [`UNHANDLED_LOCKFILES`] is rejected with a message that says so,
/// so "unsupported" never looks like "empty".
pub fn parse_named_lockfile<R: Read>(file_name: &str, reader: R) -> Result<LockedEnvironment> {
    match detect_format(file_name) {
        Some(format) => parse_lockfile_from_reader(format, reader),
        None => match unhandled_reason(file_name) {
            Some(reason) => Err(AppError::Validation(format!(
                "`{}` is a lockfile this build does not parse: {}",
                base_name(file_name),
                reason
            ))),
            None => Err(AppError::Validation(format!(
                "`{}` is not a recognised lockfile name",
                base_name(file_name)
            ))),
        },
    }
}

/// Parse an in-memory lockfile.
pub fn parse_lockfile(format: LockFormat, bytes: &[u8]) -> Result<LockedEnvironment> {
    if bytes.len() as u64 > max_lockfile_bytes() {
        return Err(AppError::Validation(format!(
            "lockfile exceeds the maximum allowed size of {} bytes",
            max_lockfile_bytes()
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| AppError::Validation(format!("lockfile is not valid UTF-8: {}", e)))?;
    guard_structural_depth(text)?;
    match format {
        LockFormat::PixiLock => parse_pixi_lock(text),
        LockFormat::CondaLock => parse_conda_lock(text),
        LockFormat::NpmPackageLock => parse_npm_lock(text),
        LockFormat::CargoLock => parse_cargo_lock(text),
        LockFormat::PoetryLock => parse_poetry_lock(text),
        LockFormat::UvLock => parse_uv_lock(text),
    }
}

/// Reject pathologically nested input before a recursive-descent parser sees
/// it. See [`MAX_LOCK_NESTING_DEPTH`] for why this cannot be left to the
/// parsers themselves.
///
/// The scan skips double-quoted strings (with backslash escapes), which is how
/// JSON, TOML basic strings and YAML double-quoted scalars all spell them.
/// Single quotes are deliberately *not* tracked: a YAML plain scalar may
/// contain an apostrophe, and mis-tracking one would make the guard ignore the
/// rest of the file — which under-counts depth and so can only fail open, never
/// reject a legitimate document.
fn guard_structural_depth(text: &str) -> Result<()> {
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut at_line_start = true;
    let mut indent: usize = 0;
    for ch in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            if ch == '\n' {
                // An unterminated string cannot span a line in any of these
                // formats; resynchronise rather than swallowing the document.
                in_string = false;
                escaped = false;
                at_line_start = true;
                indent = 0;
            }
            continue;
        }
        match ch {
            '\n' => {
                at_line_start = true;
                indent = 0;
            }
            ' ' | '\t' if at_line_start => {
                indent = indent.saturating_add(1);
                if indent > MAX_LOCK_INDENT_COLUMNS {
                    return Err(AppError::Validation(format!(
                        "lockfile indentation exceeds {} columns; refusing suspected \
                         nesting bomb",
                        MAX_LOCK_INDENT_COLUMNS
                    )));
                }
            }
            _ => {
                at_line_start = false;
                match ch {
                    '"' => in_string = true,
                    '[' | '{' => {
                        depth = depth.saturating_add(1);
                        max_depth = max_depth.max(depth);
                        if max_depth > MAX_LOCK_NESTING_DEPTH {
                            return Err(AppError::Validation(format!(
                                "lockfile nests deeper than {} levels; refusing suspected \
                                 nesting bomb",
                                MAX_LOCK_NESTING_DEPTH
                            )));
                        }
                    }
                    ']' | '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Graph builder
// ---------------------------------------------------------------------------

/// A requirement one package states about another, ready to be resolved.
///
/// Grouped into a struct because every format states the same six things and
/// threading them as positional arguments through six parsers is how the
/// argument order silently rots.
struct Requirement<'a> {
    /// Graph the requirement is resolved inside.
    scope: &'a Scope,
    /// Key of the package stating it.
    from: &'a str,
    /// Ecosystem the requirement's name belongs to.
    ecosystem: Ecosystem,
    /// Name being required, before normalisation.
    name: &'a str,
    /// Requirement text exactly as written, for the edge and for diagnostics.
    raw: &'a str,
    kind: EdgeKind,
    /// What to record when nothing in scope matches. A `dependencies` entry
    /// that is absent is a [`UnresolvedKind::MissingDependency`]; an unselected
    /// extra or an unsatisfied `constrains` is a
    /// [`UnresolvedKind::ConditionalNotInstalled`].
    absent: UnresolvedKind,
}

/// Accumulates packages, edges and unresolved rows while a parser walks a
/// document, enforcing the entry caps and keeping the per-scope name index the
/// resolvers need.
struct Builder {
    format: LockFormat,
    format_version: Option<String>,
    environments: BTreeSet<String>,
    platforms: BTreeSet<String>,
    packages: Vec<LockedPackage>,
    edges: Vec<LockEdge>,
    unresolved: Vec<UnresolvedEntry>,
    /// `(scope, ecosystem, normalised name) -> keys in that scope`.
    index: HashMap<(Scope, Ecosystem, String), Vec<String>>,
    /// Keys already used in a scope, so a duplicate natural key is made unique
    /// rather than silently shadowing the earlier package.
    used_keys: HashSet<(Scope, String)>,
}

impl Builder {
    fn new(format: LockFormat) -> Self {
        Builder {
            format,
            format_version: None,
            environments: BTreeSet::new(),
            platforms: BTreeSet::new(),
            packages: Vec::new(),
            edges: Vec::new(),
            unresolved: Vec::new(),
            index: HashMap::new(),
            used_keys: HashSet::new(),
        }
    }

    /// Record a package membership, returning the key it was actually filed
    /// under (which differs from `pkg.key` only on a collision).
    fn add_package(&mut self, mut pkg: LockedPackage) -> Result<String> {
        if self.packages.len() >= MAX_LOCK_PACKAGE_ENTRIES {
            return Err(AppError::Validation(format!(
                "lockfile declares more than {} package entries; refusing to parse",
                MAX_LOCK_PACKAGE_ENTRIES
            )));
        }
        if pkg.key.is_empty() {
            pkg.key = format!("{}:{}", pkg.ecosystem, pkg.name);
        }
        let mut key = pkg.key.clone();
        let mut suffix: usize = 1;
        while self.used_keys.contains(&(pkg.scope.clone(), key.clone())) {
            key = format!("{}#{}", pkg.key, suffix);
            suffix = suffix.saturating_add(1);
        }
        pkg.key = key.clone();
        if let Some(env) = &pkg.scope.environment {
            self.environments.insert(env.clone());
        }
        if let Some(platform) = &pkg.scope.platform {
            self.platforms.insert(platform.clone());
        }
        self.used_keys.insert((pkg.scope.clone(), key.clone()));
        self.index
            .entry((
                pkg.scope.clone(),
                pkg.ecosystem,
                pkg.ecosystem.normalize(&pkg.name),
            ))
            .or_default()
            .push(key.clone());
        self.packages.push(pkg);
        Ok(key)
    }

    /// Keys in `scope` whose name matches, under that ecosystem's rules.
    fn candidates(&self, scope: &Scope, ecosystem: Ecosystem, name: &str) -> &[String] {
        self.index
            .get(&(scope.clone(), ecosystem, ecosystem.normalize(name)))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn add_edge(
        &mut self,
        scope: &Scope,
        from: &str,
        to: &str,
        kind: EdgeKind,
        requirement: &str,
    ) -> Result<()> {
        if self.edges.len() >= MAX_LOCK_EDGES {
            return Err(AppError::Validation(format!(
                "lockfile declares more than {} dependency edges; refusing to parse",
                MAX_LOCK_EDGES
            )));
        }
        self.edges.push(LockEdge {
            scope: scope.clone(),
            from: from.to_string(),
            to: to.to_string(),
            kind,
            requirement: requirement.to_string(),
        });
        Ok(())
    }

    fn note(
        &mut self,
        scope: &Scope,
        kind: UnresolvedKind,
        subject: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<()> {
        if self.unresolved.len() >= MAX_LOCK_UNRESOLVED {
            return Err(AppError::Validation(format!(
                "lockfile produced more than {} unresolved entries; refusing to parse",
                MAX_LOCK_UNRESOLVED
            )));
        }
        self.unresolved.push(UnresolvedEntry {
            scope: scope.clone(),
            kind,
            subject: subject.into(),
            reason: reason.into(),
        });
        Ok(())
    }

    /// Resolve one requirement into edges, or into an honest unresolved row.
    ///
    /// A conda virtual package (`__glibc`) is recorded as such and produces no
    /// edge. Several candidates produce an edge to each *and* an
    /// [`UnresolvedKind::Ambiguous`] row, because picking one silently would be
    /// a guess dressed as a fact.
    fn link(&mut self, req: Requirement<'_>) -> Result<()> {
        let trimmed = req.name.trim();
        if trimmed.is_empty() {
            return self.note(
                req.scope,
                UnresolvedKind::Unparsed,
                format!("{} -> {}", req.from, req.raw),
                "requirement names no package",
            );
        }
        if req.ecosystem == Ecosystem::Conda && trimmed.starts_with("__") {
            return self.note(
                req.scope,
                UnresolvedKind::VirtualPackage,
                format!("{} -> {}", req.from, req.raw),
                format!(
                    "`{}` is a conda virtual package describing the host, not an \
                     installed package",
                    trimmed
                ),
            );
        }
        let matched: Vec<String> = self.candidates(req.scope, req.ecosystem, trimmed).to_vec();
        match matched.len() {
            0 => self.note(
                req.scope,
                req.absent,
                format!("{} -> {}", req.from, req.raw),
                format!(
                    "no {} package named `{}` in this scope",
                    req.ecosystem, trimmed
                ),
            ),
            1 => {
                let to = matched.first().cloned().unwrap_or_default();
                self.add_edge(req.scope, req.from, &to, req.kind, req.raw)
            }
            _ => {
                for to in &matched {
                    self.add_edge(req.scope, req.from, to, req.kind, req.raw)?;
                }
                self.note(
                    req.scope,
                    UnresolvedKind::Ambiguous,
                    format!("{} -> {}", req.from, req.raw),
                    format!(
                        "matches {} packages in this scope ({}); an edge was emitted to each",
                        matched.len(),
                        matched.join(", ")
                    ),
                )
            }
        }
    }

    fn finish(self) -> LockedEnvironment {
        LockedEnvironment {
            format: self.format,
            format_version: self.format_version,
            environments: self.environments.into_iter().collect(),
            platforms: self.platforms.into_iter().collect(),
            packages: self.packages,
            edges: self.edges,
            unresolved: self.unresolved,
        }
    }
}

// ---------------------------------------------------------------------------
// Name and requirement parsing
// ---------------------------------------------------------------------------

/// PEP 503 name normalisation: lower-case, and collapse runs of `-`, `_` and
/// `.` into a single `-`.
fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_sep = false;
    for ch in name.trim().chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !last_was_sep {
                out.push('-');
                last_was_sep = true;
            }
        } else {
            out.extend(ch.to_lowercase());
            last_was_sep = false;
        }
    }
    out
}

/// Characters a package name may contain across every ecosystem here. npm
/// scoped names add `@` and `/`; conda, PyPI and crates.io names do not.
fn is_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | '@' | '/')
}

/// The package name a conda MatchSpec names — the pre-#4040 hand-rolled
/// extractor, retained under `cfg(test)` as the legacy side of the
/// differential harness in `conda_semantics`. Production call sites use
/// `crate::services::conda_semantics::matchspec_name` (the rattler reference
/// parser); the two disagree on `numpy. >=1.0` (trailing-dot name: legacy
/// trimmed the dot and linked the edge to `numpy`, the reference reports
/// `numpy.` as written — which matches no real package, so the edge is
/// recorded unresolved instead of silently linked to the wrong package).
#[cfg(test)]
pub(crate) fn matchspec_name(spec: &str) -> Option<String> {
    let spec = spec.trim();
    // A channel/subdir prefix is separated from the spec by `::`.
    let body = match spec.rfind("::") {
        Some(idx) => spec.get(idx.saturating_add(2)..).unwrap_or(""),
        None => spec,
    };
    let name: String = body
        .trim_start()
        .chars()
        .take_while(|c| is_name_char(*c) && *c != '@')
        .collect();
    let name = name.trim_end_matches('.').to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// The interpreted head of a PEP 508 requirement string.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pep508 {
    name: String,
    /// The requirement carries an environment marker (`; python_version < "3.9"`),
    /// so its absence from the solved set may be correct rather than a gap.
    has_marker: bool,
    /// The marker is an `extra == "..."` guard, i.e. the requirement only
    /// applies when that extra is selected.
    is_extra: bool,
}

/// Parse the *head* of a PEP 508 requirement: its name, whether it is guarded
/// by a marker, and whether that marker is an `extra` guard.
///
/// This deliberately does not evaluate markers or version specifiers — a
/// lockfile has already resolved those, and re-deciding them here would be this
/// module inventing facts. The marker flags exist only to classify an absence.
fn parse_pep508(req: &str) -> Option<Pep508> {
    let req = req.trim();
    let (head, marker) = match req.split_once(';') {
        Some((head, marker)) => (head, marker.trim()),
        None => (req, ""),
    };
    let name: String = head
        .trim_start()
        .trim_start_matches('(')
        .chars()
        .take_while(|c| is_name_char(*c))
        .collect();
    if name.is_empty() {
        return None;
    }
    let lower_marker = marker.to_ascii_lowercase();
    Some(Pep508 {
        name,
        has_marker: !marker.is_empty(),
        is_extra: lower_marker.contains("extra") && lower_marker.contains("=="),
    })
}

/// Parse a hash written as `algo:value` (conda-lock, poetry, uv) or
/// `algo-value` (an npm Subresource Integrity `integrity` field).
fn parse_prefixed_hash(raw: &str, file: Option<String>) -> Option<PackageHash> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let split = raw
        .split_once(':')
        .or_else(|| raw.split_once('-'))
        .filter(|(algo, value)| {
            !value.is_empty() && algo.chars().all(|c| c.is_ascii_alphanumeric())
        });
    let (algorithm, value) = split?;
    Some(PackageHash {
        algorithm: algorithm.to_ascii_lowercase(),
        value: value.to_string(),
        file,
    })
}

/// A bare digest recorded under a key that names its algorithm (conda's
/// `sha256:`/`md5:` fields, Cargo's `checksum`).
fn bare_hash(algorithm: &str, value: &str) -> Option<PackageHash> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(PackageHash {
            algorithm: algorithm.to_ascii_lowercase(),
            value: value.to_string(),
            file: None,
        })
    }
}

/// Derive `(name, version, build)` from a conda artifact file name
/// (`libwebp-1.3.2-h1234_0.conda`), used when an entry records only its URL.
fn conda_name_from_filename(file_name: &str) -> Option<(String, Option<String>, Option<String>)> {
    let stem = file_name
        .strip_suffix(".conda")
        .or_else(|| file_name.strip_suffix(".tar.bz2"))?;
    // `name-version-build`, where only `name` may itself contain `-`.
    let (rest, build) = stem.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    if name.is_empty() {
        return None;
    }
    Some((
        name.to_string(),
        Some(version.to_string()),
        Some(build.to_string()),
    ))
}

/// Derive `(name, version)` from a PyPI distribution file name — a wheel
/// (`pillow-10.0.0-cp311-cp311-manylinux.whl`) or an sdist
/// (`pillow-10.0.0.tar.gz`).
fn pypi_name_from_filename(file_name: &str) -> Option<(String, Option<String>)> {
    if let Some(stem) = file_name.strip_suffix(".whl") {
        let mut parts = stem.splitn(3, '-');
        let name = parts.next().filter(|s| !s.is_empty())?;
        let version = parts.next().map(str::to_string);
        return Some((name.to_string(), version));
    }
    for suffix in [".tar.gz", ".zip", ".tar.bz2", ".tar.xz"] {
        if let Some(stem) = file_name.strip_suffix(suffix) {
            let (name, version) = stem.rsplit_once('-')?;
            if name.is_empty() {
                return None;
            }
            return Some((name.to_string(), Some(version.to_string())));
        }
    }
    None
}

/// Last path segment of a URL, with any query/fragment removed.
fn url_file_name(url: &str) -> &str {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    base_name(without_query)
}

// ---------------------------------------------------------------------------
// Document accessors
//
// Every parser walks an untyped value tree rather than deriving `Deserialize`
// structs. That is deliberate: these formats change shape between versions
// (`pixi.lock` moved its kind discriminator between v5 and v6, `poetry.lock`
// moved file hashes out of `[metadata]`), and a typed deserialiser fails the
// *whole document* on one unexpected entry. Walking the tree lets a single odd
// entry become one `unresolved` row while the other 399 packages still parse.
// ---------------------------------------------------------------------------

/// Text of a scalar YAML value. Versions are frequently unquoted (`version: 1.0`),
/// which YAML types as a number, so this must not be `as_str`.
fn yaml_text(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Text of `value[key]`, if present and scalar.
fn yaml_field(value: &serde_yaml::Value, key: &str) -> Option<String> {
    value.get(key).and_then(yaml_text)
}

/// `value[key]` as a sequence.
fn yaml_seq<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a Vec<serde_yaml::Value>> {
    value.get(key).and_then(serde_yaml::Value::as_sequence)
}

/// `value[key]` as a mapping.
fn yaml_map<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a serde_yaml::Mapping> {
    value.get(key).and_then(serde_yaml::Value::as_mapping)
}

/// Every string in `value[key]` when it is a sequence of scalars, with the
/// index of any element that is not a scalar so the caller can record it.
fn yaml_string_list(value: &serde_yaml::Value, key: &str) -> (Vec<String>, Vec<usize>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    if let Some(seq) = yaml_seq(value, key) {
        for (idx, item) in seq.iter().enumerate() {
            match yaml_text(item) {
                Some(text) => ok.push(text),
                None => bad.push(idx),
            }
        }
    }
    (ok, bad)
}

/// Text of a scalar TOML value.
fn toml_text(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Integer(i) => Some(i.to_string()),
        toml::Value::Float(f) => Some(f.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        toml::Value::Datetime(d) => Some(d.to_string()),
        _ => None,
    }
}

/// Text of `value[key]`, if present and scalar.
fn toml_field(value: &toml::Value, key: &str) -> Option<String> {
    value.get(key).and_then(toml_text)
}

/// Text of a scalar JSON value.
fn json_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Text of `value[key]`, if present and scalar.
fn json_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key).and_then(json_text)
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// pixi.lock
// ---------------------------------------------------------------------------

/// One entry of a `pixi.lock` `packages:` list, normalised across the schema
/// versions. Members of an environment reference these by URL.
struct PixiRecord {
    ecosystem: Ecosystem,
    url: String,
    name: String,
    version: Option<String>,
    build: Option<String>,
    hashes: Vec<PackageHash>,
    /// conda `depends`.
    depends: Vec<String>,
    /// conda `constrains`.
    constrains: Vec<String>,
    /// PyPI `requires_dist`.
    requires_dist: Vec<String>,
    /// Requirement-list elements that were not strings, described for
    /// [`LockedEnvironment::unresolved`].
    malformed: Vec<String>,
}

/// A short, human-readable rendering of an arbitrary document node, for an
/// `unresolved` row about an entry we could not interpret.
fn yaml_label(value: &serde_yaml::Value) -> String {
    let rendered =
        serde_yaml::to_string(value).unwrap_or_else(|_| "<unrenderable entry>".to_string());
    truncate_label(rendered.trim())
}

/// Clamp a diagnostic label to a sane length on a char boundary.
fn truncate_label(text: &str) -> String {
    const MAX: usize = 160;
    if text.chars().count() <= MAX {
        return text.replace('\n', " ");
    }
    let clipped: String = text.chars().take(MAX).collect();
    format!("{}…", clipped.replace('\n', " "))
}

/// Interpret one `pixi.lock` `packages:` entry.
///
/// Handles both spellings of the kind discriminator: v6 puts the URL under a
/// `conda:`/`pypi:` key, earlier versions use `kind:` plus `url:`. Returns
/// `None` when neither applies or no name can be derived — the caller records
/// that rather than skipping it.
fn pixi_record(entry: &serde_yaml::Value) -> Option<PixiRecord> {
    let (ecosystem, url) = if let Some(url) = yaml_field(entry, "conda") {
        (Ecosystem::Conda, url)
    } else if let Some(url) = yaml_field(entry, "pypi") {
        (Ecosystem::PyPi, url)
    } else {
        let url = yaml_field(entry, "url")?;
        match yaml_field(entry, "kind")?.as_str() {
            "conda" => (Ecosystem::Conda, url),
            "pypi" => (Ecosystem::PyPi, url),
            _ => return None,
        }
    };

    let file_name = url_file_name(&url).to_string();
    let mut name = yaml_field(entry, "name");
    let mut version = yaml_field(entry, "version");
    let mut build = yaml_field(entry, "build");
    if name.is_none() {
        match ecosystem {
            Ecosystem::Conda => {
                let (n, v, b) = conda_name_from_filename(&file_name)?;
                name = Some(n);
                version = version.or(v);
                build = build.or(b);
            }
            _ => {
                let (n, v) = pypi_name_from_filename(&file_name)?;
                name = Some(n);
                version = version.or(v);
            }
        }
    }
    let name = name?;

    let mut hashes = Vec::new();
    if let Some(value) = yaml_field(entry, "sha256") {
        hashes.extend(bare_hash("sha256", &value));
    }
    if let Some(value) = yaml_field(entry, "md5") {
        hashes.extend(bare_hash("md5", &value));
    }

    let mut malformed = Vec::new();
    let mut list = |key: &str| {
        let (items, bad) = yaml_string_list(entry, key);
        for idx in bad {
            malformed.push(format!("{}[{}] is not a string", key, idx));
        }
        items
    };
    let depends = list("depends");
    let constrains = list("constrains");
    let requires_dist = list("requires_dist");

    Some(PixiRecord {
        ecosystem,
        url,
        name,
        version,
        build,
        hashes,
        depends,
        constrains,
        requires_dist,
        malformed,
    })
}

fn parse_pixi_lock(text: &str) -> Result<LockedEnvironment> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text)
        .map_err(|e| AppError::Validation(format!("pixi.lock is not valid YAML: {}", e)))?;
    if !doc.is_mapping() {
        return Err(AppError::Validation(
            "pixi.lock must be a YAML mapping".to_string(),
        ));
    }

    let mut builder = Builder::new(LockFormat::PixiLock);
    builder.format_version = yaml_field(&doc, "version");
    let document = Scope::global();

    let entries = yaml_seq(&doc, "packages")
        .ok_or_else(|| AppError::Validation("pixi.lock has no `packages` sequence".to_string()))?;

    let mut records: Vec<PixiRecord> = Vec::with_capacity(entries.len());
    let mut by_url: HashMap<String, usize> = HashMap::new();
    for entry in entries {
        match pixi_record(entry) {
            Some(record) => {
                for issue in &record.malformed {
                    builder.note(
                        &document,
                        UnresolvedKind::Unparsed,
                        format!("{} {}", record.name, issue),
                        "requirement list element is not a string",
                    )?;
                }
                by_url
                    .entry(record.url.clone())
                    .or_insert_with(|| records.len());
                records.push(record);
            }
            None => builder.note(
                &document,
                UnresolvedKind::Unparsed,
                yaml_label(entry),
                "`packages` entry names neither a conda nor a pypi artifact, or carries \
                 no derivable package name",
            )?,
        }
    }

    // Environment membership. A pixi.lock resolves per (environment, platform),
    // and each member is a reference by URL into the shared `packages` pool.
    let mut memberships: Vec<(Scope, Vec<usize>)> = Vec::new();
    match yaml_map(&doc, "environments") {
        Some(environments) => {
            for (env_key, env_value) in environments {
                let Some(env_name) = yaml_text(env_key) else {
                    builder.note(
                        &document,
                        UnresolvedKind::Unparsed,
                        yaml_label(env_key),
                        "environment name is not a scalar",
                    )?;
                    continue;
                };
                builder.environments.insert(env_name.clone());
                let Some(platforms) = yaml_map(env_value, "packages") else {
                    builder.note(
                        &document,
                        UnresolvedKind::Unparsed,
                        env_name.clone(),
                        "environment has no `packages` mapping of platform to members",
                    )?;
                    continue;
                };
                for (platform_key, members) in platforms {
                    let Some(platform) = yaml_text(platform_key) else {
                        builder.note(
                            &document,
                            UnresolvedKind::Unparsed,
                            yaml_label(platform_key),
                            "platform name is not a scalar",
                        )?;
                        continue;
                    };
                    builder.platforms.insert(platform.clone());
                    let scope = Scope::env_platform(&env_name, &platform);
                    let Some(members) = members.as_sequence() else {
                        builder.note(
                            &scope,
                            UnresolvedKind::Unparsed,
                            yaml_label(members),
                            "platform members are not a sequence",
                        )?;
                        continue;
                    };
                    let mut indices = Vec::with_capacity(members.len());
                    for member in members {
                        let url = yaml_field(member, "conda")
                            .or_else(|| yaml_field(member, "pypi"))
                            .or_else(|| match member {
                                serde_yaml::Value::String(s) => Some(s.clone()),
                                _ => None,
                            });
                        match url {
                            None => builder.note(
                                &scope,
                                UnresolvedKind::Unparsed,
                                yaml_label(member),
                                "environment member names neither a conda nor a pypi URL",
                            )?,
                            Some(url) => match by_url.get(&url) {
                                Some(index) => indices.push(*index),
                                None => builder.note(
                                    &scope,
                                    UnresolvedKind::MissingDependency,
                                    truncate_label(&url),
                                    "environment lists a package URL that the `packages` \
                                     section does not define",
                                )?,
                            },
                        }
                    }
                    memberships.push((scope, indices));
                }
            }
        }
        None => {
            // No `environments` block: fall back to grouping by each package's
            // own URL subdir so the document still yields per-platform graphs,
            // and say so rather than pretending this was the declared shape.
            builder.note(
                &document,
                UnresolvedKind::Unparsed,
                "environments",
                "pixi.lock has no `environments` block; membership was inferred from \
                 each package's URL subdir instead",
            )?;
            let mut grouped: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (index, record) in records.iter().enumerate() {
                let subdir = pixi_subdir_from_url(&record.url).unwrap_or("unknown");
                grouped.entry(subdir.to_string()).or_default().push(index);
            }
            for (platform, indices) in grouped {
                builder.platforms.insert(platform.clone());
                memberships.push((Scope::platform(platform), indices));
            }
        }
    }

    // Pass 1: every membership becomes a node, so pass 2 can resolve names
    // against a complete per-scope index.
    for (scope, indices) in &memberships {
        for index in indices {
            let Some(record) = records.get(*index) else {
                continue;
            };
            builder.add_package(LockedPackage {
                scope: scope.clone(),
                ecosystem: record.ecosystem,
                name: record.name.clone(),
                version: record.version.clone(),
                build: record.build.clone(),
                url: Some(record.url.clone()),
                source: None,
                hashes: record.hashes.clone(),
                key: record.url.clone(),
                is_root: false,
            })?;
        }
    }

    // Pass 2: edges, resolved inside each graph.
    for (scope, indices) in &memberships {
        for index in indices {
            let Some(record) = records.get(*index) else {
                continue;
            };
            let from = record.url.clone();
            match record.ecosystem {
                Ecosystem::Conda => {
                    for (specs, kind, absent) in [
                        (
                            &record.depends,
                            EdgeKind::Runtime,
                            UnresolvedKind::MissingDependency,
                        ),
                        (
                            &record.constrains,
                            EdgeKind::Constrains,
                            UnresolvedKind::ConditionalNotInstalled,
                        ),
                    ] {
                        for spec in specs {
                            match crate::services::conda_semantics::matchspec_name(spec) {
                                Some(name) => builder.link(Requirement {
                                    scope,
                                    from: &from,
                                    ecosystem: Ecosystem::Conda,
                                    name: &name,
                                    raw: spec,
                                    kind,
                                    absent,
                                })?,
                                None => builder.note(
                                    scope,
                                    UnresolvedKind::Unparsed,
                                    format!("{} -> {}", record.name, spec),
                                    "no package name could be extracted from this MatchSpec",
                                )?,
                            }
                        }
                    }
                }
                _ => {
                    for requirement in &record.requires_dist {
                        link_pep508(&mut builder, scope, &from, &record.name, requirement)?;
                    }
                }
            }
        }
    }

    Ok(builder.finish())
}

/// The conda subdir a channel URL encodes (`…/conda-forge/linux-64/pkg.conda`).
fn pixi_subdir_from_url(url: &str) -> Option<&str> {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    let (directory, _) = without_query.rsplit_once('/')?;
    directory.rsplit('/').next()
}

/// Resolve one PEP 508 requirement string into an edge, classifying a
/// non-resolving marker-guarded or extra-guarded requirement as a correct
/// absence rather than a gap. Shared by pixi, poetry extras and uv.
fn link_pep508(
    builder: &mut Builder,
    scope: &Scope,
    from: &str,
    from_name: &str,
    requirement: &str,
) -> Result<()> {
    match parse_pep508(requirement) {
        Some(parsed) => {
            let kind = if parsed.is_extra {
                EdgeKind::Optional
            } else {
                EdgeKind::Runtime
            };
            let absent = if parsed.has_marker {
                UnresolvedKind::ConditionalNotInstalled
            } else {
                UnresolvedKind::MissingDependency
            };
            builder.link(Requirement {
                scope,
                from,
                ecosystem: Ecosystem::PyPi,
                name: &parsed.name,
                raw: requirement,
                kind,
                absent,
            })
        }
        None => builder.note(
            scope,
            UnresolvedKind::Unparsed,
            format!("{} -> {}", from_name, truncate_label(requirement)),
            "no package name could be extracted from this PEP 508 requirement",
        ),
    }
}

// ---------------------------------------------------------------------------
// conda-lock.yml
// ---------------------------------------------------------------------------

fn parse_conda_lock(text: &str) -> Result<LockedEnvironment> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text)
        .map_err(|e| AppError::Validation(format!("conda-lock is not valid YAML: {}", e)))?;
    if !doc.is_mapping() {
        return Err(AppError::Validation(
            "conda-lock must be a YAML mapping".to_string(),
        ));
    }

    let mut builder = Builder::new(LockFormat::CondaLock);
    builder.format_version = yaml_field(&doc, "version");
    let document = Scope::global();

    // Declared platforms are registered even when no package lands on them, so
    // "this platform solved to nothing" is visible.
    if let Some(metadata) = doc.get("metadata") {
        let (platforms, _) = yaml_string_list(metadata, "platforms");
        for platform in platforms {
            builder.platforms.insert(platform);
        }
    }

    let entries = doc
        .get("package")
        .or_else(|| doc.get("packages"))
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| AppError::Validation("conda-lock has no `package` sequence".to_string()))?;

    /// One conda-lock package entry, held between the node pass and the edge pass.
    struct Entry {
        scope: Scope,
        key: String,
        ecosystem: Ecosystem,
        dependencies: Vec<(String, String)>,
    }
    let mut pending: Vec<Entry> = Vec::with_capacity(entries.len());

    for entry in entries {
        let Some(name) = yaml_field(entry, "name") else {
            builder.note(
                &document,
                UnresolvedKind::Unparsed,
                yaml_label(entry),
                "package entry has no `name`",
            )?;
            continue;
        };
        let ecosystem = match yaml_field(entry, "manager").as_deref() {
            Some("conda") => Ecosystem::Conda,
            Some("pip") => Ecosystem::PyPi,
            other => {
                builder.note(
                    &document,
                    UnresolvedKind::Unparsed,
                    name,
                    format!(
                        "package entry has an unrecognised `manager` ({})",
                        other.unwrap_or("absent")
                    ),
                )?;
                continue;
            }
        };
        let Some(platform) = yaml_field(entry, "platform") else {
            builder.note(
                &document,
                UnresolvedKind::Unparsed,
                name,
                "package entry has no `platform`, so it belongs to no graph",
            )?;
            continue;
        };
        let scope = Scope::platform(&platform);
        let version = yaml_field(entry, "version");

        let mut hashes = Vec::new();
        if let Some(hash) = entry.get("hash") {
            for algorithm in ["sha256", "md5", "sha512"] {
                if let Some(value) = yaml_field(hash, algorithm) {
                    hashes.extend(bare_hash(algorithm, &value));
                }
            }
        }

        let mut dependencies = Vec::new();
        if let Some(map) = yaml_map(entry, "dependencies") {
            for (dep_key, dep_value) in map {
                match (yaml_text(dep_key), yaml_text(dep_value)) {
                    (Some(dep_name), Some(spec)) => dependencies.push((dep_name, spec)),
                    (Some(dep_name), None) => dependencies.push((dep_name, String::new())),
                    (None, _) => builder.note(
                        &scope,
                        UnresolvedKind::Unparsed,
                        format!("{} -> {}", name, yaml_label(dep_key)),
                        "dependency name is not a scalar",
                    )?,
                }
            }
        }

        let key = format!(
            "{}:{}@{}",
            ecosystem,
            name,
            version.clone().unwrap_or_default()
        );
        let key = builder.add_package(LockedPackage {
            scope: scope.clone(),
            ecosystem,
            name: name.clone(),
            version,
            build: yaml_field(entry, "build"),
            url: yaml_field(entry, "url"),
            source: yaml_field(entry, "channel"),
            hashes,
            key,
            is_root: false,
        })?;
        pending.push(Entry {
            scope,
            key,
            ecosystem,
            dependencies,
        });
    }

    for entry in &pending {
        for (dep_name, spec) in &entry.dependencies {
            let raw = if spec.is_empty() {
                dep_name.clone()
            } else {
                format!("{} {}", dep_name, spec)
            };
            builder.link(Requirement {
                scope: &entry.scope,
                from: &entry.key,
                ecosystem: entry.ecosystem,
                name: dep_name,
                raw: &raw,
                kind: EdgeKind::Runtime,
                absent: UnresolvedKind::MissingDependency,
            })?;
        }
    }

    Ok(builder.finish())
}

// ---------------------------------------------------------------------------
// package-lock.json
// ---------------------------------------------------------------------------

/// The dependency maps an npm lockfile node can carry, with the edge kind each
/// implies and how to classify one that does not resolve. An optional or peer
/// dependency is routinely absent by design; a normal or dev one is not.
const NPM_DEPENDENCY_MAPS: &[(&str, EdgeKind, UnresolvedKind)] = &[
    (
        "dependencies",
        EdgeKind::Runtime,
        UnresolvedKind::MissingDependency,
    ),
    (
        "devDependencies",
        EdgeKind::Dev,
        UnresolvedKind::MissingDependency,
    ),
    (
        "optionalDependencies",
        EdgeKind::Optional,
        UnresolvedKind::ConditionalNotInstalled,
    ),
    (
        "peerDependencies",
        EdgeKind::Peer,
        UnresolvedKind::ConditionalNotInstalled,
    ),
    (
        "requires",
        EdgeKind::Runtime,
        UnresolvedKind::MissingDependency,
    ),
];

/// Resolve `name` from the node at `from_path` using npm's own algorithm: try
/// the nearest `node_modules`, then each ancestor's, then the root's.
///
/// This is what makes a nested pin correct. `node_modules/a` requiring `b`
/// resolves to `node_modules/a/node_modules/b` when that exists, *not* the
/// hoisted `node_modules/b` — they are frequently different versions.
fn npm_resolve(present: &HashSet<String>, from_path: &str, name: &str) -> Option<String> {
    let mut prefix = from_path.to_string();
    loop {
        let candidate = if prefix.is_empty() {
            format!("node_modules/{}", name)
        } else {
            format!("{}/node_modules/{}", prefix, name)
        };
        if present.contains(&candidate) {
            return Some(candidate);
        }
        if prefix.is_empty() {
            return None;
        }
        match prefix.rfind("/node_modules/") {
            Some(index) => prefix.truncate(index),
            None => prefix.clear(),
        }
    }
}

/// Name implied by a lockfile path: everything after the last `node_modules/`,
/// which keeps a scoped name (`@scope/pkg`) intact.
fn npm_name_from_path(path: &str) -> Option<&str> {
    path.rsplit_once("node_modules/")
        .map(|(_, name)| name)
        .filter(|name| !name.is_empty())
}

/// One npm node between the node pass and the edge pass.
struct NpmNode {
    path: String,
    key: String,
    name: String,
    dependencies: Vec<(String, EdgeKind, UnresolvedKind, String)>,
}

/// Collect the dependency maps a node declares.
fn npm_dependencies(node: &serde_json::Value) -> Vec<(String, EdgeKind, UnresolvedKind, String)> {
    let mut out = Vec::new();
    for (field, kind, absent) in NPM_DEPENDENCY_MAPS {
        let Some(map) = node.get(field).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (name, range) in map {
            // A requirement map's values are always range strings. In a
            // lockfileVersion 1 tree the same `dependencies` key instead holds
            // nested *nodes*, which the tree walk has already visited as
            // packages in their own right — so a non-string value here is not
            // a dropped requirement, it is a node seen elsewhere.
            let serde_json::Value::String(range) = range else {
                continue;
            };
            out.push((name.clone(), *kind, *absent, range.clone()));
        }
    }
    out
}

fn parse_npm_lock(text: &str) -> Result<LockedEnvironment> {
    let doc: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| AppError::Validation(format!("package-lock.json is not valid JSON: {}", e)))?;
    let mut builder = Builder::new(LockFormat::NpmPackageLock);
    builder.format_version = json_field(&doc, "lockfileVersion");
    let scope = Scope::global();

    // lockfileVersion 2 carries both shapes; `packages` is the authoritative
    // one and the only one that records the root project's direct dependencies.
    let mut raw_nodes: Vec<(String, serde_json::Value)> = Vec::new();
    if let Some(packages) = doc.get("packages").and_then(serde_json::Value::as_object) {
        for (path, node) in packages {
            raw_nodes.push((path.clone(), node.clone()));
        }
    } else if let Some(tree) = doc
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
    {
        builder.note(
            &scope,
            UnresolvedKind::MissingDependency,
            "(root)",
            "lockfileVersion 1 records no root package entry, so the project's own \
             direct dependencies are absent from this document and no edge from the \
             root could be emitted",
        )?;
        // Iterative walk of the nested v1 tree; recursion here would be a stack
        // depth controlled by the input.
        let mut stack: VecDeque<(String, serde_json::Map<String, serde_json::Value>)> =
            VecDeque::new();
        stack.push_back((String::new(), tree.clone()));
        while let Some((parent, map)) = stack.pop_front() {
            for (name, node) in map {
                let path = if parent.is_empty() {
                    format!("node_modules/{}", name)
                } else {
                    format!("{}/node_modules/{}", parent, name)
                };
                if let Some(nested) = node
                    .get("dependencies")
                    .and_then(serde_json::Value::as_object)
                {
                    stack.push_back((path.clone(), nested.clone()));
                }
                raw_nodes.push((path, node));
            }
        }
    } else {
        return Err(AppError::Validation(
            "package-lock.json has neither a `packages` map nor a `dependencies` tree".to_string(),
        ));
    }

    let present: HashSet<String> = raw_nodes.iter().map(|(path, _)| path.clone()).collect();
    let mut nodes: Vec<NpmNode> = Vec::with_capacity(raw_nodes.len());

    for (path, node) in &raw_nodes {
        let is_root = path.is_empty();
        let name = json_field(node, "name")
            .or_else(|| npm_name_from_path(path).map(str::to_string))
            .unwrap_or_else(|| "(root)".to_string());
        let hashes = json_field(node, "integrity")
            .and_then(|integrity| parse_prefixed_hash(&integrity, None))
            .into_iter()
            .collect();
        let dependencies = npm_dependencies(node);
        let key = if is_root {
            ".".to_string()
        } else {
            path.clone()
        };
        let key = builder.add_package(LockedPackage {
            scope: scope.clone(),
            ecosystem: Ecosystem::Npm,
            name: name.clone(),
            version: json_field(node, "version"),
            build: None,
            url: json_field(node, "resolved"),
            source: None,
            hashes,
            key,
            is_root,
        })?;
        nodes.push(NpmNode {
            path: path.clone(),
            key,
            name,
            dependencies,
        });
    }

    let key_by_path: HashMap<&str, &str> = nodes
        .iter()
        .map(|node| (node.path.as_str(), node.key.as_str()))
        .collect();

    let mut edges: Vec<(String, String, EdgeKind, String)> = Vec::new();
    let mut misses: Vec<(UnresolvedKind, String, String)> = Vec::new();
    for node in &nodes {
        for (name, kind, absent, range) in &node.dependencies {
            let raw = if range.is_empty() {
                name.clone()
            } else {
                format!("{}@{}", name, range)
            };
            match npm_resolve(&present, &node.path, name)
                .and_then(|path| key_by_path.get(path.as_str()).map(|key| key.to_string()))
            {
                Some(to) => edges.push((node.key.clone(), to, *kind, raw)),
                None => misses.push((
                    *absent,
                    format!("{} -> {}", node.name, raw),
                    format!(
                        "no `{}` reachable from `{}` by npm's node resolution",
                        name, node.path
                    ),
                )),
            }
        }
    }
    for (from, to, kind, raw) in edges {
        builder.add_edge(&scope, &from, &to, kind, &raw)?;
    }
    for (kind, subject, reason) in misses {
        builder.note(&scope, kind, subject, reason)?;
    }

    Ok(builder.finish())
}

// ---------------------------------------------------------------------------
// Cargo.lock
// ---------------------------------------------------------------------------

/// A PyPI requirement one package states, held between the node pass and the
/// edge pass. `poetry.lock` and `uv.lock` both spell requirements differently
/// but resolve them identically, so both normalise into this.
struct PyPiRequirement {
    /// Name being required, before PEP 503 normalisation.
    name: String,
    /// Requirement text as the lockfile spelled it.
    raw: String,
    kind: EdgeKind,
    /// How to classify this requirement if nothing in scope matches.
    absent: UnresolvedKind,
}

/// The `name` of a TOML `[[package]]` entry, recording the entry as unparsed
/// and returning `None` when it has none.
fn toml_package_name(
    builder: &mut Builder,
    scope: &Scope,
    entry: &toml::Value,
) -> Result<Option<String>> {
    match toml_field(entry, "name") {
        Some(name) => Ok(Some(name)),
        None => {
            builder.note(
                scope,
                UnresolvedKind::Unparsed,
                truncate_label(&entry.to_string()),
                "`[[package]]` entry has no `name`",
            )?;
            Ok(None)
        }
    }
}

/// Resolve every requirement a PyPI package states into edges inside `scope`.
fn link_pypi_requirements(
    builder: &mut Builder,
    scope: &Scope,
    from: &str,
    requirements: &[PyPiRequirement],
) -> Result<()> {
    for requirement in requirements {
        builder.link(Requirement {
            scope,
            from,
            ecosystem: Ecosystem::PyPi,
            name: &requirement.name,
            raw: &requirement.raw,
            kind: requirement.kind,
            absent: requirement.absent,
        })?;
    }
    Ok(())
}

/// Parse a TOML lockfile, rejecting a document that carries none of the keys
/// the format is recognised by. An unrecognisable document must not parse to an
/// empty environment — "no packages" and "not this format" are different
/// answers and only one of them is safe to report.
fn parse_toml_document(text: &str, format: LockFormat, markers: &[&str]) -> Result<toml::Value> {
    let doc: toml::Value = toml::from_str(text)
        .map_err(|e| AppError::Validation(format!("{} is not valid TOML: {}", format, e)))?;
    if !markers.iter().any(|marker| doc.get(marker).is_some()) {
        return Err(AppError::Validation(format!(
            "document carries none of {:?}, so it is not a {}",
            markers, format
        )));
    }
    Ok(doc)
}

/// `[[package]]` entries of a TOML lockfile.
fn toml_packages(doc: &toml::Value) -> &[toml::Value] {
    doc.get("package")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn parse_cargo_lock(text: &str) -> Result<LockedEnvironment> {
    let doc = parse_toml_document(text, LockFormat::CargoLock, &["package", "version"])?;
    let mut builder = Builder::new(LockFormat::CargoLock);
    builder.format_version = toml_field(&doc, "version");
    let scope = Scope::global();

    /// A crate between the node pass and the edge pass.
    struct Crate {
        key: String,
        dependencies: Vec<String>,
    }
    let mut crates: Vec<Crate> = Vec::new();
    // `name -> [(key, version)]`, because a bare dependency string has to be
    // matched by name alone and may be ambiguous.
    let mut by_name: HashMap<String, Vec<(String, String)>> = HashMap::new();

    for entry in toml_packages(&doc) {
        let Some(name) = toml_field(entry, "name") else {
            builder.note(
                &scope,
                UnresolvedKind::Unparsed,
                truncate_label(&entry.to_string()),
                "`[[package]]` entry has no `name`",
            )?;
            continue;
        };
        let version = toml_field(entry, "version").unwrap_or_default();
        let hashes = toml_field(entry, "checksum")
            .and_then(|checksum| bare_hash("sha256", &checksum))
            .into_iter()
            .collect();
        let mut dependencies = Vec::new();
        if let Some(list) = entry.get("dependencies").and_then(toml::Value::as_array) {
            for item in list {
                match toml_text(item) {
                    Some(text) => dependencies.push(text),
                    None => builder.note(
                        &scope,
                        UnresolvedKind::Unparsed,
                        format!("{} -> {}", name, truncate_label(&item.to_string())),
                        "dependency list element is not a string",
                    )?,
                }
            }
        }
        let key = builder.add_package(LockedPackage {
            scope: scope.clone(),
            ecosystem: Ecosystem::Cargo,
            name: name.clone(),
            version: if version.is_empty() {
                None
            } else {
                Some(version.clone())
            },
            build: None,
            // Cargo.lock records a source, never a download URL. Synthesising
            // one would be inventing a fact the document does not state.
            url: None,
            source: toml_field(entry, "source"),
            hashes,
            key: format!("{} {}", name, version),
            is_root: false,
        })?;
        by_name
            .entry(Ecosystem::Cargo.normalize(&name))
            .or_default()
            .push((key.clone(), version));
        crates.push(Crate { key, dependencies });
    }

    for entry in &crates {
        for dependency in &entry.dependencies {
            let mut parts = dependency.split_whitespace();
            let Some(name) = parts.next() else {
                builder.note(
                    &scope,
                    UnresolvedKind::Unparsed,
                    format!("{} -> {}", entry.key, dependency),
                    "dependency string is empty",
                )?;
                continue;
            };
            let wanted = parts.next().filter(|part| !part.starts_with('('));
            let empty: Vec<(String, String)> = Vec::new();
            let candidates = by_name
                .get(&Ecosystem::Cargo.normalize(name))
                .unwrap_or(&empty);
            let matched: Vec<&(String, String)> = match wanted {
                Some(wanted) => candidates
                    .iter()
                    .filter(|(_, version)| version == wanted)
                    .collect(),
                None => candidates.iter().collect(),
            };
            match matched.len() {
                0 => builder.note(
                    &scope,
                    UnresolvedKind::MissingDependency,
                    format!("{} -> {}", entry.key, dependency),
                    format!("no `{}` in this Cargo.lock", name),
                )?,
                1 => {
                    if let Some((to, _)) = matched.first() {
                        builder.add_edge(&scope, &entry.key, to, EdgeKind::Runtime, dependency)?;
                    }
                }
                _ => {
                    for (to, _) in &matched {
                        builder.add_edge(&scope, &entry.key, to, EdgeKind::Runtime, dependency)?;
                    }
                    builder.note(
                        &scope,
                        UnresolvedKind::Ambiguous,
                        format!("{} -> {}", entry.key, dependency),
                        format!(
                            "`{}` is locked at {} versions and the dependency string names \
                             none of them; an edge was emitted to each",
                            name,
                            matched.len()
                        ),
                    )?;
                }
            }
        }
    }

    Ok(builder.finish())
}

// ---------------------------------------------------------------------------
// poetry.lock
// ---------------------------------------------------------------------------

/// Hashes from a poetry `files = [{file, hash}, …]` array.
fn poetry_file_hashes(files: &toml::Value) -> Vec<PackageHash> {
    let Some(list) = files.as_array() else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|item| {
            let hash = toml_field(item, "hash")?;
            parse_prefixed_hash(&hash, toml_field(item, "file"))
        })
        .collect()
}

fn parse_poetry_lock(text: &str) -> Result<LockedEnvironment> {
    let doc = parse_toml_document(text, LockFormat::PoetryLock, &["package", "metadata"])?;
    let mut builder = Builder::new(LockFormat::PoetryLock);
    builder.format_version = doc
        .get("metadata")
        .and_then(|metadata| toml_field(metadata, "lock-version"));
    let scope = Scope::global();

    // poetry.lock lists what was solved, never what was asked for: the
    // project's own dependencies live in pyproject.toml. Without that file
    // every package looks equally top-level, so say so once, explicitly.
    builder.note(
        &scope,
        UnresolvedKind::MissingDependency,
        "(root)",
        "poetry.lock records no root package; the project's direct dependencies are \
         declared in pyproject.toml, which is not part of this document",
    )?;

    // Pre-2.0 lockfiles keep every file hash in one `[metadata.files]` table
    // keyed by package name instead of on the package entry.
    let legacy_files = doc
        .get("metadata")
        .and_then(|metadata| metadata.get("files"))
        .and_then(toml::Value::as_table);

    /// A poetry package between the node pass and the edge pass.
    struct Entry {
        key: String,
        name: String,
        requirements: Vec<PyPiRequirement>,
        /// Extra requirement strings, in PEP 508 form.
        extras: Vec<String>,
    }
    let mut pending: Vec<Entry> = Vec::new();

    for entry in toml_packages(&doc) {
        let Some(name) = toml_package_name(&mut builder, &scope, entry)? else {
            continue;
        };
        let version = toml_field(entry, "version");
        let mut hashes = entry
            .get("files")
            .map(poetry_file_hashes)
            .unwrap_or_default();
        if hashes.is_empty() {
            if let Some(files) = legacy_files.and_then(|table| table.get(&name)) {
                hashes = poetry_file_hashes(files);
            }
        }

        let mut requirements = Vec::new();
        if let Some(table) = entry.get("dependencies").and_then(toml::Value::as_table) {
            for (dep_name, spec) in table {
                let (rendered, conditional) = poetry_requirement(spec);
                let absent = if conditional {
                    UnresolvedKind::ConditionalNotInstalled
                } else {
                    UnresolvedKind::MissingDependency
                };
                requirements.push(PyPiRequirement {
                    name: dep_name.clone(),
                    raw: format!("{} {}", dep_name, rendered),
                    kind: EdgeKind::Runtime,
                    absent,
                });
            }
        }

        let mut extras = Vec::new();
        if let Some(table) = entry.get("extras").and_then(toml::Value::as_table) {
            for requirement in table.values().filter_map(toml::Value::as_array).flatten() {
                match toml_text(requirement) {
                    Some(text) => extras.push(text),
                    None => builder.note(
                        &scope,
                        UnresolvedKind::Unparsed,
                        format!(
                            "{} extras -> {}",
                            name,
                            truncate_label(&requirement.to_string())
                        ),
                        "extra requirement is not a string",
                    )?,
                }
            }
        }

        let key = builder.add_package(LockedPackage {
            scope: scope.clone(),
            ecosystem: Ecosystem::PyPi,
            name: name.clone(),
            version: version.clone(),
            build: None,
            url: entry
                .get("source")
                .and_then(|source| toml_field(source, "url")),
            source: entry
                .get("source")
                .and_then(|source| toml_field(source, "reference")),
            hashes,
            key: format!("{}@{}", name, version.unwrap_or_default()),
            is_root: false,
        })?;
        pending.push(Entry {
            key,
            name,
            requirements,
            extras,
        });
    }

    for entry in &pending {
        link_pypi_requirements(&mut builder, &scope, &entry.key, &entry.requirements)?;
        for requirement in &entry.extras {
            // An extra is only installed when selected, so its absence from the
            // solved set is expected, never a gap.
            match parse_pep508(requirement) {
                Some(parsed) => builder.link(Requirement {
                    scope: &scope,
                    from: &entry.key,
                    ecosystem: Ecosystem::PyPi,
                    name: &parsed.name,
                    raw: requirement,
                    kind: EdgeKind::Optional,
                    absent: UnresolvedKind::ConditionalNotInstalled,
                })?,
                None => builder.note(
                    &scope,
                    UnresolvedKind::Unparsed,
                    format!("{} -> {}", entry.name, truncate_label(requirement)),
                    "no package name could be extracted from this extra requirement",
                )?,
            }
        }
    }

    Ok(builder.finish())
}

/// Render a poetry dependency value and say whether it is conditional.
///
/// The value is a bare constraint string, a table (which may carry `markers`,
/// `python` or `optional`), or an array of such tables — the array form always
/// means "one of these, depending on the environment".
fn poetry_requirement(spec: &toml::Value) -> (String, bool) {
    match spec {
        toml::Value::String(constraint) => (constraint.clone(), false),
        toml::Value::Table(_) => {
            let constraint = toml_field(spec, "version").unwrap_or_else(|| "*".to_string());
            let conditional = spec.get("markers").is_some()
                || spec.get("python").is_some()
                || toml_field(spec, "optional").as_deref() == Some("true");
            (constraint, conditional)
        }
        toml::Value::Array(items) => {
            let rendered: Vec<String> = items
                .iter()
                .map(|item| poetry_requirement(item).0)
                .collect();
            (rendered.join(" | "), true)
        }
        other => (truncate_label(&other.to_string()), false),
    }
}

// ---------------------------------------------------------------------------
// uv.lock
// ---------------------------------------------------------------------------

/// The dependency arrays a `uv.lock` package can carry.
fn uv_dependency_groups(entry: &toml::Value) -> Vec<(&toml::Value, EdgeKind, UnresolvedKind)> {
    let mut groups: Vec<(&toml::Value, EdgeKind, UnresolvedKind)> = Vec::new();
    if let Some(list) = entry.get("dependencies") {
        groups.push((list, EdgeKind::Runtime, UnresolvedKind::MissingDependency));
    }
    for (field, kind) in [
        ("optional-dependencies", EdgeKind::Optional),
        ("dev-dependencies", EdgeKind::Dev),
    ] {
        let Some(table) = entry.get(field).and_then(toml::Value::as_table) else {
            continue;
        };
        for list in table.values() {
            groups.push((list, kind, UnresolvedKind::ConditionalNotInstalled));
        }
    }
    groups
}

fn parse_uv_lock(text: &str) -> Result<LockedEnvironment> {
    let doc = parse_toml_document(
        text,
        LockFormat::UvLock,
        &["package", "version", "requires-python"],
    )?;
    let mut builder = Builder::new(LockFormat::UvLock);
    builder.format_version = toml_field(&doc, "version");
    let scope = Scope::global();

    /// A uv package between the node pass and the edge pass.
    struct Entry {
        key: String,
        requirements: Vec<PyPiRequirement>,
    }
    let mut pending: Vec<Entry> = Vec::new();

    for entry in toml_packages(&doc) {
        let Some(name) = toml_package_name(&mut builder, &scope, entry)? else {
            continue;
        };
        let version = toml_field(entry, "version");
        let source = entry.get("source");
        // uv records the project being locked as an editable or virtual
        // package, which is what gives this format a real graph root.
        let is_root = source
            .map(|source| source.get("editable").is_some() || source.get("virtual").is_some())
            .unwrap_or(false);

        let mut hashes = Vec::new();
        let mut url = None;
        if let Some(sdist) = entry.get("sdist") {
            url = toml_field(sdist, "url");
            if let Some(hash) = toml_field(sdist, "hash") {
                let file = url.as_deref().map(|u| url_file_name(u).to_string());
                hashes.extend(parse_prefixed_hash(&hash, file));
            }
        }
        if let Some(wheels) = entry.get("wheels").and_then(toml::Value::as_array) {
            for wheel in wheels {
                let wheel_url = toml_field(wheel, "url");
                if url.is_none() {
                    url.clone_from(&wheel_url);
                }
                if let Some(hash) = toml_field(wheel, "hash") {
                    let file = wheel_url.as_deref().map(|u| url_file_name(u).to_string());
                    hashes.extend(parse_prefixed_hash(&hash, file));
                }
            }
        }

        let mut requirements = Vec::new();
        for (list, kind, absent) in uv_dependency_groups(entry) {
            let Some(items) = list.as_array() else {
                builder.note(
                    &scope,
                    UnresolvedKind::Unparsed,
                    format!("{} -> {}", name, truncate_label(&list.to_string())),
                    "dependency group is not an array",
                )?;
                continue;
            };
            for item in items {
                let Some(dep_name) = toml_field(item, "name") else {
                    builder.note(
                        &scope,
                        UnresolvedKind::Unparsed,
                        format!("{} -> {}", name, truncate_label(&item.to_string())),
                        "dependency entry has no `name`",
                    )?;
                    continue;
                };
                let marker = toml_field(item, "marker");
                let raw = match &marker {
                    Some(marker) => format!("{} ; {}", dep_name, marker),
                    None => dep_name.clone(),
                };
                // A marker-guarded requirement that did not survive the
                // resolution is correctly absent, not missing.
                let absent = if marker.is_some() {
                    UnresolvedKind::ConditionalNotInstalled
                } else {
                    absent
                };
                requirements.push(PyPiRequirement {
                    name: dep_name,
                    raw,
                    kind,
                    absent,
                });
            }
        }

        let key = builder.add_package(LockedPackage {
            scope: scope.clone(),
            ecosystem: Ecosystem::PyPi,
            name: name.clone(),
            version: version.clone(),
            build: None,
            url,
            source: source.and_then(|source| {
                ["registry", "editable", "virtual", "directory", "git", "url"]
                    .iter()
                    .find_map(|field| toml_field(source, field))
            }),
            hashes,
            key: format!("{}@{}", name, version.unwrap_or_default()),
            is_root,
        })?;
        pending.push(Entry { key, requirements });
    }

    for entry in &pending {
        link_pypi_requirements(&mut builder, &scope, &entry.key, &entry.requirements)?;
    }

    Ok(builder.finish())
}

// ---------------------------------------------------------------------------
// Tests
//
// Fixtures are built programmatically in-test: no checked-in lockfiles, so a
// reader can see exactly which field drives which assertion.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const CF: &str = "https://conda.anaconda.org/conda-forge";
    const PYPI_FILES: &str = "https://files.pythonhosted.org/packages/ab";

    /// Key of the single package named `name` in `scope`. Panicking here is a
    /// test-harness assertion, not module behaviour.
    fn key_of(env: &LockedEnvironment, scope: &Scope, name: &str) -> String {
        let matches: Vec<&LockedPackage> =
            env.packages_in(scope).filter(|p| p.name == name).collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one `{}` in {}, got {:?}",
            name,
            scope,
            matches.iter().map(|p| &p.key).collect::<Vec<_>>()
        );
        matches
            .first()
            .map(|p| p.key.clone())
            .unwrap_or_else(|| unreachable!())
    }

    /// Names of the packages an edge connects, for readable assertions.
    fn edge_names(env: &LockedEnvironment, edge: &LockEdge) -> (String, String) {
        let name = |key: &str| {
            env.package(&edge.scope, key)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| format!("<missing {}>", key))
        };
        (name(&edge.from), name(&edge.to))
    }

    fn has_edge(env: &LockedEnvironment, scope: &Scope, from: &str, to: &str) -> bool {
        env.edges_in(scope)
            .any(|e| edge_names(env, e) == (from.to_string(), to.to_string()))
    }

    fn notes(env: &LockedEnvironment, kind: UnresolvedKind) -> Vec<&UnresolvedEntry> {
        env.unresolved.iter().filter(|u| u.kind == kind).collect()
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A pixi.lock v6 with two environments over two platforms. `pillow`
    /// depends on `libwebp` on both platforms, through *different builds* —
    /// which is the whole point of keeping one graph per platform.
    fn pixi_v6() -> String {
        format!(
            r#"version: 6
environments:
  default:
    channels:
    - url: {cf}/
    packages:
      linux-64:
      - conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
      - conda: {cf}/linux-64/python-3.11.6-h5678_0_cpython.conda
      - conda: {cf}/linux-64/pillow-10.0.1-py311h1111_0.conda
      - pypi: {pypi}/requests-2.31.0-py3-none-any.whl
      - pypi: {pypi}/urllib3-2.0.7-py3-none-any.whl
      osx-arm64:
      - conda: {cf}/osx-arm64/libwebp-1.3.2-h9999_0.conda
      - conda: {cf}/osx-arm64/pillow-10.0.1-py311h2222_0.conda
  test:
    channels:
    - url: {cf}/
    packages:
      linux-64:
      - conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
packages:
- conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
  sha256: aaaa1111
  md5: bbbb1111
  name: libwebp
  version: 1.3.2
  build: h1234_0
  subdir: linux-64
  depends:
  - __glibc >=2.17
- conda: {cf}/osx-arm64/libwebp-1.3.2-h9999_0.conda
  sha256: aaaa2222
  name: libwebp
  version: 1.3.2
  build: h9999_0
  subdir: osx-arm64
  depends: []
- conda: {cf}/linux-64/python-3.11.6-h5678_0_cpython.conda
  sha256: cccc1111
  name: python
  version: 3.11.6
  build: h5678_0_cpython
  subdir: linux-64
  depends: []
  constrains:
  - pypy <0a0
- conda: {cf}/linux-64/pillow-10.0.1-py311h1111_0.conda
  sha256: dddd1111
  name: pillow
  version: 10.0.1
  build: py311h1111_0
  subdir: linux-64
  depends:
  - libwebp >=1.3.2,<2.0a0
  - python >=3.11,<3.12.0a0
  constrains:
  - pillow-heif >=0.10
- conda: {cf}/osx-arm64/pillow-10.0.1-py311h2222_0.conda
  sha256: dddd2222
  name: pillow
  version: 10.0.1
  build: py311h2222_0
  subdir: osx-arm64
  depends:
  - libwebp >=1.3.2,<2.0a0
  - python >=3.11,<3.12.0a0
- pypi: {pypi}/requests-2.31.0-py3-none-any.whl
  name: requests
  version: 2.31.0
  sha256: eeee1111
  requires_dist:
  - urllib3>=1.21.1,<3
  - chardet>=3.0.2,<6 ; extra == 'use_chardet_on_py3'
- pypi: {pypi}/urllib3-2.0.7-py3-none-any.whl
  name: urllib3
  version: 2.0.7
  sha256: ffff1111
  requires_dist: []
"#,
            cf = CF,
            pypi = PYPI_FILES
        )
    }

    fn conda_lock_v1() -> String {
        format!(
            r#"version: 1
metadata:
  content_hash:
    linux-64: hash-linux
    osx-64: hash-osx
  channels:
  - url: conda-forge
    used_env_vars: []
  platforms:
  - linux-64
  - osx-64
package:
- name: libwebp
  version: 1.3.2
  manager: conda
  platform: linux-64
  dependencies: {{}}
  url: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
  hash:
    md5: bbbb1111
    sha256: aaaa1111
  category: main
  optional: false
- name: pillow
  version: 10.0.1
  manager: conda
  platform: linux-64
  dependencies:
    libwebp: '>=1.3.2,<2.0a0'
    __glibc: '>=2.17'
  url: {cf}/linux-64/pillow-10.0.1-py311h1111_0.conda
  hash:
    sha256: dddd1111
  category: main
  optional: false
- name: libwebp
  version: 1.3.2
  manager: conda
  platform: osx-64
  dependencies: {{}}
  url: {cf}/osx-64/libwebp-1.3.2-h8888_0.conda
  hash:
    sha256: aaaa3333
  category: main
  optional: false
- name: pillow
  version: 10.0.1
  manager: conda
  platform: osx-64
  dependencies:
    libwebp: '>=1.3.2,<2.0a0'
  url: {cf}/osx-64/pillow-10.0.1-py311h3333_0.conda
  hash:
    sha256: dddd3333
  category: main
  optional: false
- name: requests
  version: 2.31.0
  manager: pip
  platform: linux-64
  dependencies:
    urllib3: '>=1.21.1,<3'
  url: {pypi}/requests-2.31.0-py3-none-any.whl
  hash:
    sha256: eeee1111
  category: main
  optional: false
"#,
            cf = CF,
            pypi = PYPI_FILES
        )
    }

    /// npm lockfileVersion 3. `pillow-js` pins an older `libwebp-js` in its own
    /// `node_modules`, so correct node resolution must reach the *nested* copy,
    /// not the hoisted one.
    fn npm_v3() -> &'static str {
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": { "pillow-js": "^1.0.0" },
      "devDependencies": { "tap": "^16.0.0" }
    },
    "node_modules/pillow-js": {
      "version": "1.2.3",
      "resolved": "https://registry.npmjs.org/pillow-js/-/pillow-js-1.2.3.tgz",
      "integrity": "sha512-AAAAAAAA",
      "dependencies": { "libwebp-js": "^1.9.0" },
      "peerDependencies": { "sharp": "^0.33.0" }
    },
    "node_modules/pillow-js/node_modules/libwebp-js": {
      "version": "1.9.0",
      "resolved": "https://registry.npmjs.org/libwebp-js/-/libwebp-js-1.9.0.tgz",
      "integrity": "sha512-CCCCCCCC"
    },
    "node_modules/libwebp-js": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/libwebp-js/-/libwebp-js-2.0.1.tgz",
      "integrity": "sha512-BBBBBBBB"
    },
    "node_modules/tap": {
      "version": "16.0.0",
      "dev": true,
      "resolved": "https://registry.npmjs.org/tap/-/tap-16.0.0.tgz",
      "integrity": "sha512-DDDDDDDD"
    }
  }
}"#
    }

    fn cargo_lock_v3() -> &'static str {
        r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = [
 "libwebp-sys",
 "serde 1.0.100",
]

[[package]]
name = "libwebp-sys"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123abc123"
dependencies = [
 "serde 1.0.100",
]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "def456def456"
"#
    }

    fn poetry_lock_v2() -> &'static str {
        r#"# This file is automatically @generated by Poetry.

[[package]]
name = "pillow"
version = "10.0.1"
description = "Python Imaging Library"
optional = false
python-versions = ">=3.8"
files = [
    {file = "Pillow-10.0.1-cp311-cp311-manylinux_2_17_x86_64.whl", hash = "sha256:aaaa1111"},
    {file = "Pillow-10.0.1.tar.gz", hash = "sha256:bbbb1111"},
]

[package.dependencies]
webp-wrapper = ">=1.3.2"
typing-extensions = {version = ">=4.0", markers = "python_version < \"3.10\""}

[package.extras]
tests = ["pytest (>=7.0)"]

[[package]]
name = "webp_wrapper"
version = "1.3.2"
description = "WebP bindings"
optional = false
python-versions = ">=3.8"
files = [
    {file = "webp_wrapper-1.3.2.tar.gz", hash = "sha256:cccc1111"},
]

[metadata]
lock-version = "2.0"
python-versions = ">=3.8"
content-hash = "xyzxyz"
"#
    }

    fn uv_lock_v1() -> &'static str {
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "pillow" },
]

[[package]]
name = "pillow"
version = "10.0.1"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/ab/pillow-10.0.1.tar.gz", hash = "sha256:aaaa1111", size = 10 }
wheels = [
    { url = "https://files.pythonhosted.org/ab/pillow-10.0.1-cp311-none-any.whl", hash = "sha256:bbbb1111", size = 20 },
]
dependencies = [
    { name = "webp-shim" },
    { name = "olefile", marker = "python_full_version < '3.12'" },
]

[[package]]
name = "webp-shim"
version = "1.3.2"
source = { registry = "https://pypi.org/simple" }
"#
    }

    // -----------------------------------------------------------------------
    // Format detection
    // -----------------------------------------------------------------------

    #[test]
    fn detects_every_supported_lockfile_name() {
        assert_eq!(detect_format("pixi.lock"), Some(LockFormat::PixiLock));
        assert_eq!(
            detect_format("/repo/sub/pixi.lock"),
            Some(LockFormat::PixiLock)
        );
        assert_eq!(detect_format("conda-lock.yml"), Some(LockFormat::CondaLock));
        assert_eq!(
            detect_format("dev.conda-lock.yml"),
            Some(LockFormat::CondaLock)
        );
        assert_eq!(
            detect_format("package-lock.json"),
            Some(LockFormat::NpmPackageLock)
        );
        assert_eq!(
            detect_format("npm-shrinkwrap.json"),
            Some(LockFormat::NpmPackageLock)
        );
        assert_eq!(detect_format("Cargo.lock"), Some(LockFormat::CargoLock));
        assert_eq!(detect_format("poetry.lock"), Some(LockFormat::PoetryLock));
        assert_eq!(detect_format("uv.lock"), Some(LockFormat::UvLock));
        assert_eq!(detect_format("README.md"), None);
    }

    #[test]
    fn known_unhandled_lockfiles_are_named_not_silently_empty() {
        // The distinction that matters: "we do not parse yarn.lock" must never
        // arrive as an environment with zero packages.
        assert!(detect_format("yarn.lock").is_none());
        assert!(unhandled_reason("yarn.lock").is_some());
        assert!(unhandled_reason("Gemfile.lock").is_some());
        assert!(unhandled_reason("pnpm-lock.yaml").is_some());
        let err = parse_named_lockfile("yarn.lock", &b"{}"[..]).unwrap_err();
        assert!(
            err.to_string().contains("does not parse"),
            "unexpected error: {}",
            err
        );
        let err = parse_named_lockfile("something.txt", &b"{}"[..]).unwrap_err();
        assert!(
            err.to_string().contains("not a recognised lockfile"),
            "unexpected error: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // pixi.lock
    // -----------------------------------------------------------------------

    #[test]
    fn pixi_lock_parses_with_correct_edges() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_v6().as_bytes()).unwrap();
        assert_eq!(env.format, LockFormat::PixiLock);
        assert_eq!(env.format_version.as_deref(), Some("6"));
        assert_eq!(env.environments, vec!["default", "test"]);
        assert_eq!(env.platforms, vec!["linux-64", "osx-arm64"]);

        let linux = Scope::env_platform("default", "linux-64");
        assert_eq!(env.packages_in(&linux).count(), 5);
        assert!(has_edge(&env, &linux, "pillow", "libwebp"));
        assert!(has_edge(&env, &linux, "pillow", "python"));
        // A PyPI requirement resolves against PyPI packages in the same scope.
        assert!(has_edge(&env, &linux, "requests", "urllib3"));

        // Hashes and URLs survive.
        let libwebp = env
            .package(&linux, &key_of(&env, &linux, "libwebp"))
            .unwrap();
        assert_eq!(libwebp.ecosystem, Ecosystem::Conda);
        assert_eq!(libwebp.version.as_deref(), Some("1.3.2"));
        assert_eq!(libwebp.build.as_deref(), Some("h1234_0"));
        assert!(libwebp
            .hashes
            .iter()
            .any(|h| h.algorithm == "sha256" && h.value == "aaaa1111"));
        assert!(libwebp
            .hashes
            .iter()
            .any(|h| h.algorithm == "md5" && h.value == "bbbb1111"));
        assert_eq!(
            libwebp.url.as_deref(),
            Some(format!("{}/linux-64/libwebp-1.3.2-h1234_0.conda", CF).as_str())
        );

        // The remediation answer: libwebp is here because you asked for pillow.
        let chains = env.explain(&linux, &libwebp.key, 8);
        let named: Vec<Vec<String>> = chains
            .iter()
            .map(|chain| {
                chain
                    .iter()
                    .map(|k| {
                        env.package(&linux, k)
                            .map(|p| p.name.clone())
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .collect();
        assert_eq!(
            named,
            vec![vec!["pillow".to_string(), "libwebp".to_string()]]
        );
    }

    #[test]
    fn pixi_lock_yields_one_graph_per_platform_and_environment() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_v6().as_bytes()).unwrap();
        let scopes = env.scopes();
        assert_eq!(
            scopes,
            vec![
                Scope::env_platform("default", "linux-64"),
                Scope::env_platform("default", "osx-arm64"),
                Scope::env_platform("test", "linux-64"),
            ]
        );

        let linux = Scope::env_platform("default", "linux-64");
        let osx = Scope::env_platform("default", "osx-arm64");

        // Same package name, different build per platform: two distinct nodes,
        // never one node with a platform annotation.
        let linux_webp = env
            .package(&linux, &key_of(&env, &linux, "libwebp"))
            .unwrap();
        let osx_webp = env.package(&osx, &key_of(&env, &osx, "libwebp")).unwrap();
        assert_ne!(linux_webp.key, osx_webp.key);
        assert_eq!(linux_webp.build.as_deref(), Some("h1234_0"));
        assert_eq!(osx_webp.build.as_deref(), Some("h9999_0"));

        // pillow depends on python on linux-64 only; osx-arm64 has no python,
        // so that edge must not exist there — and must be reported as absent.
        assert!(has_edge(&env, &linux, "pillow", "python"));
        assert!(!has_edge(&env, &osx, "pillow", "python"));
        assert!(notes(&env, UnresolvedKind::MissingDependency)
            .iter()
            .any(|u| u.scope == osx && u.subject.contains("python")));

        // The `test` environment is its own graph with one package, no edges.
        let test = Scope::env_platform("test", "linux-64");
        assert_eq!(env.packages_in(&test).count(), 1);
        assert_eq!(env.edges_in(&test).count(), 0);
    }

    #[test]
    fn pixi_lock_records_virtual_and_conditional_absences_separately() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_v6().as_bytes()).unwrap();
        // `__glibc` is a host property, not a node.
        assert!(notes(&env, UnresolvedKind::VirtualPackage)
            .iter()
            .any(|u| u.subject.contains("__glibc")));
        // An unselected extra and an unsatisfied `constrains` are correct
        // absences, not gaps.
        let conditional = notes(&env, UnresolvedKind::ConditionalNotInstalled);
        assert!(conditional.iter().any(|u| u.subject.contains("chardet")));
        assert!(conditional.iter().any(|u| u.subject.contains("pypy")));
        assert!(conditional
            .iter()
            .any(|u| u.subject.contains("pillow-heif")));

        let summary = env.summary();
        assert_eq!(summary.scopes, 3);
        assert_eq!(summary.unparsed, 0);
        assert!(summary.explained_absences >= 4);
        assert!(summary.memberships > summary.distinct_packages);
    }

    #[test]
    fn pixi_entries_that_cannot_be_interpreted_land_in_unresolved() {
        let doc = format!(
            r#"version: 6
environments:
  default:
    channels:
    - url: {cf}/
    packages:
      linux-64:
      - conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
      - conda: {cf}/linux-64/ghost-9.9.9-h0000_0.conda
      - 42
packages:
- conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
  name: libwebp
  version: 1.3.2
  build: h1234_0
  subdir: linux-64
  depends:
  - nowhere-at-all >=1.0
- this-entry: has-no-recognisable-kind
"#,
            cf = CF
        );
        let env = parse_lockfile(LockFormat::PixiLock, doc.as_bytes()).unwrap();
        let scope = Scope::env_platform("default", "linux-64");
        assert_eq!(env.packages_in(&scope).count(), 1);

        // Nothing vanished: the undeclared URL, the non-mapping member, the
        // uninterpretable package entry and the unsatisfiable dependency are
        // each accounted for.
        let subjects: Vec<String> = env.unresolved.iter().map(|u| u.to_string()).collect();
        let joined = subjects.join("\n");
        assert!(joined.contains("ghost-9.9.9"), "{}", joined);
        assert!(joined.contains("42"), "{}", joined);
        assert!(joined.contains("this-entry"), "{}", joined);
        assert!(joined.contains("nowhere-at-all"), "{}", joined);
        assert_eq!(env.summary().unparsed, 2);
    }

    // -----------------------------------------------------------------------
    // conda-lock.yml
    // -----------------------------------------------------------------------

    #[test]
    fn conda_lock_parses_per_platform_graphs() {
        let env = parse_lockfile(LockFormat::CondaLock, conda_lock_v1().as_bytes()).unwrap();
        assert_eq!(env.format, LockFormat::CondaLock);
        assert_eq!(env.environments, Vec::<String>::new());
        assert_eq!(env.platforms, vec!["linux-64", "osx-64"]);

        let linux = Scope::platform("linux-64");
        let osx = Scope::platform("osx-64");
        assert_eq!(env.packages_in(&linux).count(), 3);
        assert_eq!(env.packages_in(&osx).count(), 2);
        assert!(has_edge(&env, &linux, "pillow", "libwebp"));
        assert!(has_edge(&env, &osx, "pillow", "libwebp"));

        let webp = env
            .package(&linux, &key_of(&env, &linux, "libwebp"))
            .unwrap();
        assert_eq!(webp.ecosystem, Ecosystem::Conda);
        assert!(webp
            .hashes
            .iter()
            .any(|h| h.algorithm == "md5" && h.value == "bbbb1111"));

        // The pip-managed package keeps its own ecosystem, and its unmet
        // requirement is reported rather than dropped.
        let requests = env
            .package(&linux, &key_of(&env, &linux, "requests"))
            .unwrap();
        assert_eq!(requests.ecosystem, Ecosystem::PyPi);
        assert!(notes(&env, UnresolvedKind::MissingDependency)
            .iter()
            .any(|u| u.subject.contains("urllib3")));
        assert!(notes(&env, UnresolvedKind::VirtualPackage)
            .iter()
            .any(|u| u.subject.contains("__glibc")));
    }

    // -----------------------------------------------------------------------
    // package-lock.json
    // -----------------------------------------------------------------------

    #[test]
    fn npm_lock_resolves_nested_node_modules_before_hoisted() {
        let env = parse_lockfile(LockFormat::NpmPackageLock, npm_v3().as_bytes()).unwrap();
        assert_eq!(env.format_version.as_deref(), Some("3"));
        assert!(env.platforms.is_empty());
        let scope = Scope::global();
        assert_eq!(env.packages_in(&scope).count(), 5);

        let root = env.packages_in(&scope).find(|p| p.is_root).unwrap();
        assert_eq!(root.name, "demo");

        // pillow-js pins ^1.9.0, which lives in its OWN node_modules. Resolving
        // to the hoisted 2.0.1 would be a different (and wrong) graph.
        let nested = "node_modules/pillow-js/node_modules/libwebp-js";
        assert!(env
            .edges_in(&scope)
            .any(|e| e.from == "node_modules/pillow-js" && e.to == nested));
        assert_eq!(
            env.package(&scope, nested).and_then(|p| p.version.clone()),
            Some("1.9.0".to_string())
        );

        // Dev dependencies are edges too, and keep their kind.
        assert!(env
            .edges_in(&scope)
            .any(|e| e.to == "node_modules/tap" && e.kind == EdgeKind::Dev));

        // Integrity is recorded as an algorithm/value pair, not a blob.
        let tap = env.package(&scope, "node_modules/tap").unwrap();
        assert_eq!(
            tap.hashes
                .first()
                .map(|h| (h.algorithm.as_str(), h.value.as_str())),
            Some(("sha512", "DDDDDDDD"))
        );

        // An unmet peer dependency is a stated absence, not a silent one.
        assert!(notes(&env, UnresolvedKind::ConditionalNotInstalled)
            .iter()
            .any(|u| u.subject.contains("sharp")));

        let chains = env.explain(&scope, nested, 8);
        assert_eq!(
            chains,
            vec![vec![
                ".".to_string(),
                "node_modules/pillow-js".to_string(),
                nested.to_string()
            ]]
        );
    }

    #[test]
    fn npm_v1_tree_gives_edges_but_no_root_direct_dependencies() {
        let doc = r#"{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "pillow-js": {
      "version": "1.2.3",
      "resolved": "https://registry.npmjs.org/pillow-js/-/pillow-js-1.2.3.tgz",
      "integrity": "sha512-AAAAAAAA",
      "requires": { "libwebp-js": "^1.9.0" },
      "dependencies": {
        "libwebp-js": {
          "version": "1.9.0",
          "resolved": "https://registry.npmjs.org/libwebp-js/-/libwebp-js-1.9.0.tgz",
          "integrity": "sha512-CCCCCCCC"
        }
      }
    },
    "libwebp-js": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/libwebp-js/-/libwebp-js-2.0.1.tgz",
      "integrity": "sha512-BBBBBBBB"
    }
  }
}"#;
        let env = parse_lockfile(LockFormat::NpmPackageLock, doc.as_bytes()).unwrap();
        let scope = Scope::global();
        assert_eq!(env.packages_in(&scope).count(), 3);
        assert!(env
            .edges_in(&scope)
            .any(|e| e.from == "node_modules/pillow-js"
                && e.to == "node_modules/pillow-js/node_modules/libwebp-js"));
        // lockfileVersion 1 records no root node: the project's own direct
        // dependencies simply are not in the document, and inventing them
        // would be this module making facts up.
        assert!(!env.packages_in(&scope).any(|p| p.is_root));
        assert!(env
            .unresolved
            .iter()
            .any(|u| u.reason.contains("lockfileVersion 1")));
    }

    // -----------------------------------------------------------------------
    // Cargo.lock
    // -----------------------------------------------------------------------

    #[test]
    fn cargo_lock_parses_with_edges() {
        let env = parse_lockfile(LockFormat::CargoLock, cargo_lock_v3().as_bytes()).unwrap();
        assert_eq!(env.format_version.as_deref(), Some("3"));
        let scope = Scope::global();
        assert_eq!(env.packages_in(&scope).count(), 3);
        assert!(has_edge(&env, &scope, "demo", "libwebp-sys"));
        assert!(has_edge(&env, &scope, "demo", "serde"));
        assert!(has_edge(&env, &scope, "libwebp-sys", "serde"));

        let serde = env.package(&scope, "serde 1.0.100").unwrap();
        assert_eq!(serde.ecosystem, Ecosystem::Cargo);
        assert_eq!(
            serde.source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        // Cargo.lock records no download URL, only a source. Saying `None` is
        // the honest answer; synthesising a crates.io URL would not be.
        assert_eq!(serde.url, None);
        assert_eq!(
            serde
                .hashes
                .first()
                .map(|h| (h.algorithm.as_str(), h.value.as_str())),
            Some(("sha256", "def456def456"))
        );
    }

    #[test]
    fn cargo_lock_bare_dependency_matching_two_versions_is_ambiguous_not_guessed() {
        let doc = r#"version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaa"

[[package]]
name = "serde"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbb"
"#;
        let env = parse_lockfile(LockFormat::CargoLock, doc.as_bytes()).unwrap();
        let scope = Scope::global();
        let from_demo: Vec<&LockEdge> = env
            .edges_in(&scope)
            .filter(|e| e.from == "demo 0.1.0")
            .collect();
        assert_eq!(from_demo.len(), 2, "an edge to each candidate");
        assert_eq!(env.summary().ambiguous, 1);
    }

    // -----------------------------------------------------------------------
    // poetry.lock
    // -----------------------------------------------------------------------

    #[test]
    fn poetry_lock_parses_with_normalised_edges() {
        let env = parse_lockfile(LockFormat::PoetryLock, poetry_lock_v2().as_bytes()).unwrap();
        let scope = Scope::global();
        assert_eq!(env.packages_in(&scope).count(), 2);
        // `webp-wrapper` in the requirement vs `webp_wrapper` as the package
        // name: PEP 503 normalisation is what makes this edge exist.
        assert!(has_edge(&env, &scope, "pillow", "webp_wrapper"));

        let pillow = env.package(&scope, "pillow@10.0.1").unwrap();
        assert_eq!(pillow.ecosystem, Ecosystem::PyPi);
        assert_eq!(pillow.hashes.len(), 2);
        assert!(pillow
            .hashes
            .iter()
            .any(|h| h.file.as_deref() == Some("Pillow-10.0.1.tar.gz") && h.value == "bbbb1111"));

        // A marker-guarded requirement and an extra are conditional absences.
        let conditional = notes(&env, UnresolvedKind::ConditionalNotInstalled);
        assert!(conditional
            .iter()
            .any(|u| u.subject.contains("typing-extensions")));
        assert!(conditional.iter().any(|u| u.subject.contains("pytest")));
        assert_eq!(env.summary().unparsed, 0);
        // poetry.lock has no root: the project's own dependencies live in
        // pyproject.toml, so every package looks equally top-level.
        assert!(!env.packages_in(&scope).any(|p| p.is_root));
        assert!(env
            .unresolved
            .iter()
            .any(|u| u.reason.contains("pyproject.toml")));
    }

    // -----------------------------------------------------------------------
    // uv.lock
    // -----------------------------------------------------------------------

    #[test]
    fn uv_lock_parses_with_root_and_edges() {
        let env = parse_lockfile(LockFormat::UvLock, uv_lock_v1().as_bytes()).unwrap();
        let scope = Scope::global();
        assert_eq!(env.packages_in(&scope).count(), 3);
        let root = env.packages_in(&scope).find(|p| p.is_root).unwrap();
        assert_eq!(root.name, "demo");
        assert!(has_edge(&env, &scope, "demo", "pillow"));
        assert!(has_edge(&env, &scope, "pillow", "webp-shim"));

        let pillow = env.package(&scope, "pillow@10.0.1").unwrap();
        assert_eq!(pillow.hashes.len(), 2, "sdist and wheel hashes");
        assert_eq!(
            pillow.url.as_deref(),
            Some("https://files.pythonhosted.org/ab/pillow-10.0.1.tar.gz")
        );

        assert!(notes(&env, UnresolvedKind::ConditionalNotInstalled)
            .iter()
            .any(|u| u.subject.contains("olefile")));

        assert_eq!(
            env.explain(&scope, "webp-shim@1.3.2", 4),
            vec![vec![
                "demo@0.1.0".to_string(),
                "pillow@10.0.1".to_string(),
                "webp-shim@1.3.2".to_string()
            ]]
        );
    }

    // -----------------------------------------------------------------------
    // Hostile input
    // -----------------------------------------------------------------------

    #[test]
    fn malformed_input_errors_without_panicking() {
        let formats = [
            LockFormat::PixiLock,
            LockFormat::CondaLock,
            LockFormat::NpmPackageLock,
            LockFormat::CargoLock,
            LockFormat::PoetryLock,
            LockFormat::UvLock,
        ];
        let hostile: [&[u8]; 8] = [
            b"",
            b"\x00\x01\x02\x03",
            b"{",
            b"[[[[",
            b"version: 6\npackages:\n  - conda: ",
            b"name = \"unterminated",
            b"packages: !!python/object/apply:os.system ['echo']",
            &[0xff, 0xfe, 0xfd],
        ];
        for format in formats {
            for bytes in hostile {
                // The contract is only "returns, does not unwind". Some of
                // these are legal-but-empty documents for some formats.
                let _ = parse_lockfile(format, bytes);
            }
        }
    }

    #[test]
    fn truncated_but_well_formed_prefix_errors_rather_than_reporting_a_short_environment() {
        let full = pixi_v6();
        let cut = full.len() / 2;
        let truncated = full.get(..cut).unwrap_or("");
        // Either it fails to parse, or it parses a genuinely shorter document —
        // what it must never do is report the full package count.
        if let Ok(env) = parse_lockfile(LockFormat::PixiLock, truncated.as_bytes()) {
            let full_env = parse_lockfile(LockFormat::PixiLock, full.as_bytes()).unwrap();
            assert!(env.packages.len() < full_env.packages.len());
        }
    }

    #[test]
    fn deeply_nested_input_is_rejected_before_the_parser_recurses() {
        let bomb = format!("{}{}", "[".repeat(5_000), "]".repeat(5_000));
        let err = parse_lockfile(LockFormat::NpmPackageLock, bomb.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("nests deeper"), "{}", err);

        let indent_bomb = format!("a:\n{}b: 1\n", " ".repeat(MAX_LOCK_INDENT_COLUMNS + 1));
        let err = parse_lockfile(LockFormat::PixiLock, indent_bomb.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("indentation"), "{}", err);
    }

    #[test]
    fn a_fifty_megabyte_input_is_bounded() {
        let fifty_mib: u64 = 50 * 1024 * 1024;
        assert!(fifty_mib > max_lockfile_bytes());
        let reader = std::io::repeat(b'a').take(fifty_mib);
        let err = parse_lockfile_from_reader(LockFormat::PixiLock, reader).unwrap_err();
        assert!(
            err.to_string().contains("maximum allowed size"),
            "unexpected error: {}",
            err
        );

        // The in-memory entry point applies the same ceiling.
        let oversized = vec![b'a'; (max_lockfile_bytes() as usize).saturating_add(1)];
        let err = parse_lockfile(LockFormat::PixiLock, &oversized).unwrap_err();
        assert!(err.to_string().contains("maximum allowed size"), "{}", err);
    }

    #[test]
    fn non_utf8_input_is_rejected_cleanly() {
        let err = parse_lockfile(LockFormat::CargoLock, &[0xf0, 0x28, 0x8c, 0x28]).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{}", err);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    #[test]
    fn matchspec_names_are_extracted_from_every_spelling() {
        assert_eq!(matchspec_name("numpy"), Some("numpy".to_string()));
        assert_eq!(matchspec_name("numpy >=1.20"), Some("numpy".to_string()));
        assert_eq!(matchspec_name("numpy>=1.20"), Some("numpy".to_string()));
        assert_eq!(
            matchspec_name("python 3.11.* *_cpython"),
            Some("python".to_string())
        );
        assert_eq!(
            matchspec_name("conda-forge::numpy"),
            Some("numpy".to_string())
        );
        assert_eq!(
            matchspec_name("conda-forge/linux-64::numpy >=1.20"),
            Some("numpy".to_string())
        );
        assert_eq!(
            matchspec_name("numpy[version='>=1.2']"),
            Some("numpy".to_string())
        );
        assert_eq!(
            matchspec_name("__glibc >=2.17"),
            Some("__glibc".to_string())
        );
        assert_eq!(matchspec_name(""), None);
        assert_eq!(matchspec_name(">=1.0"), None);
    }

    #[test]
    fn pep508_heads_are_classified() {
        let plain = parse_pep508("urllib3>=1.21.1,<3").unwrap();
        assert_eq!(plain.name, "urllib3");
        assert!(!plain.has_marker);
        assert!(!plain.is_extra);

        let extra = parse_pep508("chardet>=3.0.2 ; extra == 'use_chardet'").unwrap();
        assert_eq!(extra.name, "chardet");
        assert!(extra.has_marker);
        assert!(extra.is_extra);

        let marked = parse_pep508("olefile ; python_version < \"3.12\"").unwrap();
        assert_eq!(marked.name, "olefile");
        assert!(marked.has_marker);
        assert!(!marked.is_extra);

        assert_eq!(
            parse_pep508("pytest (>=7.0)").map(|p| p.name),
            Some("pytest".to_string())
        );
        assert_eq!(parse_pep508(""), None);
    }

    #[test]
    fn pypi_names_normalise_per_pep503() {
        assert_eq!(normalize_pypi_name("Webp_Wrapper"), "webp-wrapper");
        assert_eq!(normalize_pypi_name("zope.interface"), "zope-interface");
        assert_eq!(normalize_pypi_name("a--_.-b"), "a-b");
        assert_eq!(normalize_pypi_name("  Pillow  "), "pillow");
    }

    #[test]
    fn hashes_parse_from_every_spelling() {
        assert_eq!(
            parse_prefixed_hash("sha256:abc", None),
            Some(PackageHash {
                algorithm: "sha256".to_string(),
                value: "abc".to_string(),
                file: None
            })
        );
        assert_eq!(
            parse_prefixed_hash("sha512-Zm9v", None).map(|h| h.algorithm),
            Some("sha512".to_string())
        );
        assert_eq!(parse_prefixed_hash("", None), None);
        assert_eq!(parse_prefixed_hash("nocolonorhyphen", None), None);
        assert_eq!(bare_hash("sha256", "  "), None);
    }

    #[test]
    fn artifact_file_names_yield_coordinates() {
        assert_eq!(
            conda_name_from_filename("libwebp-base-1.3.2-h1234_0.conda"),
            Some((
                "libwebp-base".to_string(),
                Some("1.3.2".to_string()),
                Some("h1234_0".to_string())
            ))
        );
        assert_eq!(
            conda_name_from_filename("old-pkg-1.0-0.tar.bz2"),
            Some((
                "old-pkg".to_string(),
                Some("1.0".to_string()),
                Some("0".to_string())
            ))
        );
        assert_eq!(conda_name_from_filename("not-an-archive.txt"), None);
        assert_eq!(
            pypi_name_from_filename("pillow-10.0.1-cp311-none-any.whl"),
            Some(("pillow".to_string(), Some("10.0.1".to_string())))
        );
        assert_eq!(
            pypi_name_from_filename("pillow-10.0.1.tar.gz"),
            Some(("pillow".to_string(), Some("10.0.1".to_string())))
        );
        assert_eq!(pypi_name_from_filename("pillow"), None);
        assert_eq!(url_file_name("https://host/a/b/c.conda?x=1"), "c.conda");
    }

    #[test]
    fn pixi_without_environments_falls_back_to_url_subdirs_and_says_so() {
        // The pre-v6 spelling: `kind:` plus `url:`, no `name:` field, and no
        // `environments` block at all.
        let doc = format!(
            r#"version: 5
packages:
- kind: conda
  url: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
  depends:
  - zlib >=1.2
- kind: conda
  url: {cf}/linux-64/zlib-1.2.13-h5555_0.conda
- kind: gopher
  url: https://example.invalid/mystery
"#,
            cf = CF
        );
        let env = parse_lockfile(LockFormat::PixiLock, doc.as_bytes()).unwrap();
        assert_eq!(env.format_version.as_deref(), Some("5"));
        let linux = Scope::platform("linux-64");
        // Coordinates were derived from the artifact file names.
        assert_eq!(
            env.package(&linux, &key_of(&env, &linux, "libwebp"))
                .and_then(|p| p.build.clone()),
            Some("h1234_0".to_string())
        );
        assert!(has_edge(&env, &linux, "libwebp", "zlib"));
        // Both the inferred membership and the uninterpretable entry are stated.
        assert!(env
            .unresolved
            .iter()
            .any(|u| u.reason.contains("inferred from")));
        assert!(notes(&env, UnresolvedKind::Unparsed)
            .iter()
            .any(|u| u.subject.contains("gopher")));
    }

    #[test]
    fn uv_lock_optional_and_dev_groups_keep_their_edge_kinds() {
        let doc = r#"version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "pillow" },
]

[package.optional-dependencies]
imaging = [
    { name = "extra-pkg" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest-uv" },
]

[[package]]
name = "pillow"
version = "10.0.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "extra-pkg"
version = "1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest-uv"
version = "8.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let env = parse_lockfile(LockFormat::UvLock, doc.as_bytes()).unwrap();
        let scope = Scope::global();
        assert!(env
            .packages_in(&scope)
            .any(|p| p.is_root && p.name == "demo"));
        let kind_of = |to: &str| env.edges_in(&scope).find(|e| e.to == to).map(|e| e.kind);
        assert_eq!(kind_of("pillow@10.0.1"), Some(EdgeKind::Runtime));
        assert_eq!(kind_of("extra-pkg@1.0"), Some(EdgeKind::Optional));
        assert_eq!(kind_of("pytest-uv@8.0"), Some(EdgeKind::Dev));
        assert_eq!(
            env.dependencies_of(&scope, "demo@0.1.0"),
            vec!["extra-pkg@1.0", "pillow@10.0.1", "pytest-uv@8.0"]
        );
    }

    #[test]
    fn a_requirement_matching_two_forks_emits_both_edges_and_says_it_guessed_nothing() {
        let doc = r#"version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "pillow" },
]

[[package]]
name = "pillow"
version = "10.0.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pillow"
version = "9.5.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let env = parse_lockfile(LockFormat::UvLock, doc.as_bytes()).unwrap();
        let scope = Scope::global();
        assert_eq!(
            env.edges_in(&scope)
                .filter(|e| e.from == "demo@0.1.0")
                .count(),
            2
        );
        assert_eq!(env.summary().ambiguous, 1);
        assert!(notes(&env, UnresolvedKind::Ambiguous)
            .iter()
            .any(|u| u.reason.contains("an edge was emitted to each")));
    }

    #[test]
    fn poetry_pre_2_0_metadata_files_still_supply_hashes() {
        let doc = r#"[[package]]
name = "pillow"
version = "10.0.1"
optional = false
python-versions = ">=3.8"

[package.dependencies]
multi = [
    {version = "1.0", python = "<3.9"},
    {version = "2.0", python = ">=3.9"},
]

[[package]]
name = "multi"
version = "2.0"
optional = false
python-versions = ">=3.8"

[metadata]
lock-version = "1.1"
content-hash = "abc"

[metadata.files]
pillow = [
    {file = "Pillow-10.0.1.tar.gz", hash = "sha256:aaaa1111"},
]
multi = []
"#;
        let env = parse_lockfile(LockFormat::PoetryLock, doc.as_bytes()).unwrap();
        let scope = Scope::global();
        assert_eq!(env.format_version.as_deref(), Some("1.1"));
        let pillow = env.package(&scope, "pillow@10.0.1").unwrap();
        assert_eq!(
            pillow.hashes.first().map(|h| h.value.clone()),
            Some("aaaa1111".to_string())
        );
        // The multi-constraint array form still resolves to one edge.
        let edge = env
            .edges_in(&scope)
            .find(|e| e.to == "multi@2.0")
            .expect("array-form dependency should resolve");
        assert!(edge.requirement.contains("1.0 | 2.0"), "{:?}", edge);
    }

    #[test]
    fn conda_lock_entries_it_cannot_place_are_all_accounted_for() {
        let doc = r#"version: 1
metadata:
  platforms:
  - linux-64
  - win-64
package:
- version: 1.0
  manager: conda
  platform: linux-64
- name: brewed
  manager: brew
  platform: linux-64
- name: homeless
  manager: conda
- name: ok
  version: 1.0
  manager: conda
  platform: linux-64
  dependencies:
    ? [1, 2]
    : bad
"#;
        let env = parse_lockfile(LockFormat::CondaLock, doc.as_bytes()).unwrap();
        // A platform that solved to nothing is still a declared platform.
        assert_eq!(env.platforms, vec!["linux-64", "win-64"]);
        assert_eq!(env.packages.len(), 1);
        let summary = env.summary();
        assert_eq!(
            summary.unparsed, 4,
            "missing name, unknown manager, missing platform, non-scalar dependency key: {:?}",
            env.unresolved
        );
    }

    #[test]
    fn a_named_lockfile_is_read_through_the_size_ceiling() {
        let bytes = cargo_lock_v3().as_bytes();
        let env = parse_named_lockfile("workspace/Cargo.lock", bytes).unwrap();
        assert_eq!(env.format, LockFormat::CargoLock);
        assert_eq!(env.packages.len(), 3);
    }

    #[test]
    fn model_identifiers_and_graph_accessors_are_stable() {
        assert_eq!(LockFormat::PixiLock.to_string(), "pixi.lock");
        assert!(LockFormat::PixiLock.is_per_platform());
        assert!(LockFormat::CondaLock.is_per_platform());
        assert!(!LockFormat::CargoLock.is_per_platform());
        assert_eq!(Ecosystem::PyPi.to_string(), "pypi");
        assert_eq!(Ecosystem::Conda.normalize("  LibWebP "), "libwebp");
        assert_eq!(
            Ecosystem::PyPi.normalize("Zope.Interface"),
            "zope-interface"
        );
        assert_eq!(EdgeKind::Constrains.to_string(), "constrains");
        assert_eq!(Scope::global().to_string(), "(global)");
        assert_eq!(Scope::platform("linux-64").to_string(), "linux-64");
        assert_eq!(
            Scope::env_platform("default", "linux-64").to_string(),
            "default/linux-64"
        );
        assert_eq!(
            Scope {
                environment: Some("default".to_string()),
                platform: None
            }
            .to_string(),
            "default"
        );

        assert!(UnresolvedKind::Unparsed.is_parse_failure());
        assert!(!UnresolvedKind::MissingDependency.is_parse_failure());
        assert!(UnresolvedKind::MissingDependency.is_graph_gap());
        assert!(!UnresolvedKind::VirtualPackage.is_graph_gap());
        assert!(!UnresolvedKind::ConditionalNotInstalled.is_graph_gap());
        assert_eq!(UnresolvedKind::Ambiguous.to_string(), "ambiguous");
        assert_eq!(
            UnresolvedEntry {
                scope: Scope::platform("linux-64"),
                kind: UnresolvedKind::VirtualPackage,
                subject: "pillow -> __glibc".to_string(),
                reason: "host property".to_string(),
            }
            .to_string(),
            "[virtual_package] pillow -> __glibc in linux-64: host property"
        );
    }

    #[test]
    fn explain_is_bounded_and_total() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_v6().as_bytes()).unwrap();
        let linux = Scope::env_platform("default", "linux-64");
        let libwebp = key_of(&env, &linux, "libwebp");
        assert!(env.explain(&linux, &libwebp, 0).is_empty());
        assert!(env.explain(&linux, "no-such-package", 4).is_empty());
        // A package nothing depends on explains itself.
        let pillow = key_of(&env, &linux, "pillow");
        assert_eq!(env.explain(&linux, &pillow, 4), vec![vec![pillow.clone()]]);
        assert_eq!(env.dependants_of(&linux, &libwebp), vec![pillow.as_str()]);
    }

    #[test]
    fn a_cyclic_graph_terminates_rather_than_looping() {
        // Cargo.lock cannot express a cycle, but a hostile document can.
        let doc = r#"version = 3

[[package]]
name = "a"
version = "1.0.0"
dependencies = ["b 1.0.0"]

[[package]]
name = "b"
version = "1.0.0"
dependencies = ["a 1.0.0"]
"#;
        let env = parse_lockfile(LockFormat::CargoLock, doc.as_bytes()).unwrap();
        let scope = Scope::global();
        assert_eq!(env.edges.len(), 2);
        // Every node has a dependant, so there is no root and no chain — and
        // crucially, asking terminates.
        assert!(env.explain(&scope, "a 1.0.0", 4).is_empty());
    }

    #[test]
    fn duplicate_natural_keys_do_not_shadow_each_other() {
        // Two packages that would produce the same key in the same scope must
        // both survive; losing one would be exactly the silent drop this
        // module refuses to do.
        let mut builder = Builder::new(LockFormat::CargoLock);
        let scope = Scope::global();
        let make = |key: &str| LockedPackage {
            scope: Scope::global(),
            ecosystem: Ecosystem::Cargo,
            name: "dup".to_string(),
            version: Some("1.0.0".to_string()),
            build: None,
            url: None,
            source: None,
            hashes: Vec::new(),
            key: key.to_string(),
            is_root: false,
        };
        let first = builder.add_package(make("dup 1.0.0")).unwrap();
        let second = builder.add_package(make("dup 1.0.0")).unwrap();
        assert_ne!(first, second);
        let env = builder.finish();
        assert_eq!(env.packages_in(&scope).count(), 2);
    }
}
