//! Central proxy-cache correctness classifier (Core Invariant ④, #1611).
//!
//! Cache freshness is a **per-path-pattern property**. Every proxied path is
//! either:
//!
//! * **Immutable** — content-addressed or version-pinned. Once cached it never
//!   changes upstream (a versioned Maven jar, an OCI blob-by-digest, a PyPI
//!   wheel, an npm tarball, a Cargo `.crate`). Immutable entries cache forever
//!   and MUST NEVER contact upstream on a hit.
//! * **Mutable** — an index or pointer that upstream rewrites in place
//!   (`maven-metadata.xml`, the PyPI simple index, an npm packument, an OCI
//!   tag→manifest, the Cargo sparse index). Mutable entries get a short TTL and
//!   conditional revalidation (ETag / `If-None-Match`, `Last-Modified` /
//!   `If-Modified-Since`).
//!
//! ## Why a single central classifier
//!
//! The alternative — a `classify()` method on every format handler — scatters
//! the rules across ~30 handlers and makes the invariant impossible to test as
//! a unit or audit as a whole. One pure module keeps the rules cohesive,
//! table-testable, and free of handler duplication (which also keeps the jscpd
//! gate happy).
//!
//! ## The safe default
//!
//! An UNKNOWN path classifies as [`Mutability::Mutable`] with a conservative
//! TTL. This is the safe direction: misclassifying a *mutable* path as
//! *immutable* serves stale content forever (a silent correctness bug), whereas
//! misclassifying an *immutable* path as *mutable* only costs a cheap
//! conditional revalidation. When in doubt, revalidate.

use chrono::{DateTime, Utc};

use crate::models::repository::RepositoryFormat;

/// Conservative TTL for mutable / unknown paths (5 minutes). Short enough that a
/// stale index is corrected quickly, long enough to coalesce bursts of index
/// reads behind one revalidation.
pub const MUTABLE_DEFAULT_TTL_SECS: i64 = 300;

/// TTL applied to a negative-cached upstream 404 (45 seconds). Long enough to
/// shield upstream from a hot-loop of misses on a not-yet-published artifact,
/// short enough that a freshly published artifact appears promptly.
pub const NEGATIVE_CACHE_TTL_SECS: i64 = 45;

/// Grace window during which a *stale* mutable entry is served when upstream is
/// unreachable (5xx / timeout) — RFC 5861 `stale-if-error` semantics. One hour
/// keeps clients working through a transient upstream outage rather than
/// returning a hard error for a body we already hold.
pub const STALE_IF_ERROR_GRACE_SECS: i64 = 3600;

/// Whether a proxied path's content can change upstream after it is first
/// cached. See the module docs for the immutable-vs-mutable contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    /// Content-addressed / version-pinned. Cache forever; never revalidate.
    Immutable,
    /// Index / pointer. Cache for `default_ttl_secs`, then revalidate.
    Mutable {
        /// Seconds the cached body is served without contacting upstream.
        default_ttl_secs: i64,
    },
}

impl Mutability {
    /// Convenience constructor for the conservative mutable default.
    pub const fn mutable_default() -> Self {
        Mutability::Mutable {
            default_ttl_secs: MUTABLE_DEFAULT_TTL_SECS,
        }
    }

    /// `true` for [`Mutability::Immutable`].
    pub const fn is_immutable(self) -> bool {
        matches!(self, Mutability::Immutable)
    }

    /// The TTL to stamp on a fresh cache write for this path. Immutable paths
    /// get a sentinel "effectively forever" TTL so the existing
    /// `expires_at`-based machinery keeps working unchanged, while
    /// [`evaluate`] short-circuits immutable entries before the expiry ever
    /// matters.
    pub const fn write_ttl_secs(self) -> i64 {
        match self {
            // ~10 years. Immutable hits are short-circuited by `evaluate`, so
            // this is only a backstop for any code path that reads `expires_at`
            // directly; it must be large enough never to expire in practice.
            Mutability::Immutable => 315_360_000,
            Mutability::Mutable { default_ttl_secs } => default_ttl_secs,
        }
    }
}

/// A single cache entry as seen by the pure freshness evaluator. Mirrors the
/// load-bearing fields of the on-disk `CacheMetadata` sidecar without coupling
/// the classifier to storage types, so [`evaluate`] stays a pure function that
/// is trivial to table-test.
#[derive(Debug, Clone, Copy)]
pub struct CacheEntry {
    /// Classification of the path this entry caches.
    pub mutability: Mutability,
    /// When a mutable entry stops being served without revalidation.
    pub expires_at: DateTime<Utc>,
    /// Set when a prior upstream fetch returned 404 and was negative-cached;
    /// the entry holds no body and is a [`Freshness::NegativeHit`] until this
    /// instant passes.
    pub negative_cached_until: Option<DateTime<Utc>>,
}

/// The outcome of evaluating a cache entry against the current time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Serve the cached body directly; no upstream contact.
    Fresh,
    /// A mutable entry is past its TTL: serve only after a successful
    /// conditional revalidation (304 → extend, 200 → refill).
    Stale,
    /// A negative-cache 404 entry is still within its short TTL: respond 404
    /// without contacting upstream.
    NegativeHit,
    /// No usable entry: fetch from upstream.
    Miss,
}

/// Pure freshness decision (#1611 §2.5). No I/O, no clock reads beyond the
/// caller-supplied `now`, so it is exhaustively table-testable.
///
/// Decision order (first match wins):
/// 1. `entry == None` → [`Freshness::Miss`].
/// 2. Negative-cache window active → [`Freshness::NegativeHit`].
/// 3. Immutable → [`Freshness::Fresh`] (never expires, never revalidates).
/// 4. Mutable and `now < expires_at` → [`Freshness::Fresh`].
/// 5. Otherwise (mutable past TTL) → [`Freshness::Stale`].
pub fn evaluate(entry: Option<&CacheEntry>, now: DateTime<Utc>) -> Freshness {
    let Some(entry) = entry else {
        return Freshness::Miss;
    };

    if let Some(until) = entry.negative_cached_until {
        if now < until {
            return Freshness::NegativeHit;
        }
        // Negative window elapsed: nothing positive to serve → Miss.
        return Freshness::Miss;
    }

    match entry.mutability {
        Mutability::Immutable => Freshness::Fresh,
        Mutability::Mutable { .. } => {
            if now < entry.expires_at {
                Freshness::Fresh
            } else {
                Freshness::Stale
            }
        }
    }
}

/// Classify a proxied `path` for a repository `format` into its [`Mutability`]
/// (#1611 §2.1).
///
/// `path` is the artifact path *relative to the repository root* (no leading
/// slash required; both forms are accepted). The rules are purely structural —
/// they inspect the path shape, never the network — so they are cheap and
/// deterministic.
pub fn classify(format: &RepositoryFormat, path: &str) -> Mutability {
    let path = path.trim_start_matches('/');
    let lower = path.to_ascii_lowercase();

    match format {
        // -- Maven / Gradle / sbt -------------------------------------------
        // maven-metadata.xml (and its checksums) is the only mutable file in a
        // Maven layout; SNAPSHOT directories are republished in place. Every
        // versioned artifact (jar/pom/war/aar/...) is immutable.
        RepositoryFormat::Maven | RepositoryFormat::Gradle | RepositoryFormat::Sbt => {
            classify_maven(&lower)
        }

        // -- PyPI family ----------------------------------------------------
        // The simple index (`simple/`, `simple/<pkg>/`) is mutable; the wheels
        // and sdists it points at are immutable.
        RepositoryFormat::Pypi | RepositoryFormat::Poetry | RepositoryFormat::Conda => {
            classify_pypi(&lower)
        }

        // -- npm family -----------------------------------------------------
        // The packument (the metadata JSON at `<pkg>` / `@scope/<pkg>`) is
        // mutable; tarballs under `-/` are immutable.
        RepositoryFormat::Npm
        | RepositoryFormat::Yarn
        | RepositoryFormat::Pnpm
        | RepositoryFormat::Bower => classify_npm(&lower),

        // -- OCI family -----------------------------------------------------
        // Blobs and digest-pinned manifests are immutable; tag manifests and
        // the tag list are mutable.
        RepositoryFormat::Docker
        | RepositoryFormat::Podman
        | RepositoryFormat::Buildx
        | RepositoryFormat::Oras
        | RepositoryFormat::WasmOci
        | RepositoryFormat::HelmOci => classify_oci(&lower),

        // -- Cargo ----------------------------------------------------------
        // The sparse/registry index is mutable; the `.crate` downloads are
        // immutable.
        RepositoryFormat::Cargo => classify_cargo(&lower),

        // -- Debian / APT ---------------------------------------------------
        // by-hash indices are content-addressed (hash in URL). pool/ packages
        // are version-pinned per the Debian Repository Format spec ("A
        // repository must not include different packages (different content)
        // with the same package name, version, and architecture"). dists/
        // index files (Release, Packages, Sources, Translation, Contents) are
        // rewritten in place by upstream.
        RepositoryFormat::Debian => classify_debian(&lower),

        // -- RPM / YUM ------------------------------------------------------
        // repomd.xml(+.asc) is the single mutable entry point; every other
        // repodata file is content-addressed (checksum-prefixed filename) and
        // packages are version-pinned — both immutable.
        RepositoryFormat::Rpm => classify_rpm(&lower),

        // Everything else: conservative default. Revalidate rather than risk
        // serving a stale index forever.
        _ => Mutability::mutable_default(),
    }
}

/// Whether `path` is a *known* mutable index / pointer file for `format` — i.e.
/// a file the format genuinely rewrites in place (a `maven-metadata.xml`, an npm
/// packument, the PyPI simple index, an OCI tag manifest, the Cargo sparse
/// index). This is distinct from the *unknown / conservative* mutable default
/// that [`classify`] returns for paths it does not recognise.
///
/// The release-immutability guard uses this to tell "a genuinely mutable index
/// the format legitimately republishes in place" (allow re-upload of different
/// bytes) apart from "an unrecognised path in a default-format repo such as
/// `Generic`/`Nuget`" (a stored artifact coordinate that must be
/// protected against a delete + re-upload content swap). Conan is a special
/// case: its revision-file coordinates are legitimately rewritten in place
/// within a revision, so it is always reported as a mutable index. For formats
/// whose classifier has real arms, a non-immutable result here means a real
/// index file; for the default formats there are no such index files, so this
/// is always `false` and every coordinate is treated as a release coordinate.
pub fn is_explicitly_mutable_index(format: &RepositoryFormat, path: &str) -> bool {
    let path = path.trim_start_matches('/');
    let lower = path.to_ascii_lowercase();

    match format {
        // Formats with a real classifier: anything they do NOT mark immutable is,
        // by construction of `classify_*`, a recognised mutable index/pointer.
        RepositoryFormat::Maven
        | RepositoryFormat::Gradle
        | RepositoryFormat::Sbt
        | RepositoryFormat::Pypi
        | RepositoryFormat::Poetry
        | RepositoryFormat::Conda
        | RepositoryFormat::Npm
        | RepositoryFormat::Yarn
        | RepositoryFormat::Pnpm
        | RepositoryFormat::Bower
        | RepositoryFormat::Docker
        | RepositoryFormat::Podman
        | RepositoryFormat::Buildx
        | RepositoryFormat::Oras
        | RepositoryFormat::WasmOci
        | RepositoryFormat::HelmOci
        | RepositoryFormat::Cargo
        | RepositoryFormat::Debian
        | RepositoryFormat::Rpm => !classify(format, &lower).is_immutable(),

        // Conan revision-file coordinates
        // (`.../revisions/{rev}/files/{file}`) are legitimately rewritten in
        // place during an upload: a recipe/package file may be re-pushed with
        // different bytes within the SAME revision (deduplication is by
        // revision, not by file content). They therefore behave like a format's
        // in-place index — every conan path is freely re-uploadable and is
        // treated as a mutable coordinate so the release-immutability swap guard
        // is a no-op for conan (matching the conan upload handlers' intent).
        RepositoryFormat::Conan => true,

        // Default-format families (Generic, Nuget, Composer, Go,
        // Helm, ...) have no in-place index files at artifact coordinates:
        // every stored path is a release coordinate.
        _ => false,
    }
}

/// Maven §2.1: only `maven-metadata.xml*` is mutable.
fn classify_maven(lower: &str) -> Mutability {
    let leaf = leaf(lower);
    // maven-metadata.xml plus its .md5/.sha1/.sha256/.sha512/.asc siblings.
    if leaf.starts_with("maven-metadata.xml") {
        return Mutability::mutable_default();
    }
    // A SNAPSHOT path that is NOT a concrete timestamped artifact is mutable
    // (the directory listing / metadata is republished). Concrete timestamped
    // SNAPSHOT artifacts (e.g. `app-1.0-20240101.120000-3.jar`) are immutable.
    if lower.contains("-snapshot/") && !has_artifact_extension(leaf) {
        return Mutability::mutable_default();
    }
    if has_artifact_extension(leaf) {
        return Mutability::Immutable;
    }
    // Unknown Maven leaf (directory listing, unexpected file): be safe.
    Mutability::mutable_default()
}

/// PyPI §2.1: the simple index is mutable; package files are immutable.
fn classify_pypi(lower: &str) -> Mutability {
    if lower == "simple" || lower == "simple/" || lower.starts_with("simple/") {
        // simple/<pkg>/<file>.whl is a package file even though it lives under
        // simple/ on some mirrors; treat concrete package files as immutable.
        let leaf = leaf(lower);
        if is_pypi_package_file(leaf) {
            return Mutability::Immutable;
        }
        return Mutability::mutable_default();
    }
    if is_pypi_package_file(leaf(lower)) {
        return Mutability::Immutable;
    }
    // `packages/`, `pypi/<pkg>/json` (JSON API) and anything unrecognized are
    // mutable-by-default.
    Mutability::mutable_default()
}

/// npm §2.1: packument metadata is mutable; tarballs are immutable.
fn classify_npm(lower: &str) -> Mutability {
    // Only a *real package tarball* is immutable. In the canonical npm registry
    // layout that is `…/<pkg>/-/<pkg>-<ver>.tgz` (scoped: `@scope/<pkg>/-/…`),
    // i.e. a `.tgz` under the package's `/-/` segment. A bare `.tgz` anywhere
    // else is NOT a guaranteed-immutable tarball — it could be a mutable
    // pointer or attachment — so it must fall through to the conservative
    // mutable default rather than being cached forever.
    if lower.contains("/-/") && lower.ends_with(".tgz") {
        return Mutability::Immutable;
    }
    // `<pkg>`, `@scope/<pkg>`, `@scope%2f<pkg>`, dist-tags, the registry root,
    // and any `.tgz` NOT under `/-/` are all packument/metadata/unknown:
    // mutable (revalidate).
    Mutability::mutable_default()
}

/// OCI §2.1: digest-pinned blobs/manifests are immutable; tags are mutable.
fn classify_oci(lower: &str) -> Mutability {
    // `/v2/<name>/blobs/sha256:...` and `/v2/<name>/manifests/sha256:...` are
    // content-addressed → immutable.
    if (lower.contains("/blobs/") || lower.contains("/manifests/")) && lower.contains("sha256:") {
        return Mutability::Immutable;
    }
    // `/v2/<name>/blobs/<digest>` without the `sha256:` scheme is still
    // content-addressed in practice; accept any blobs path as immutable.
    if lower.contains("/blobs/") {
        return Mutability::Immutable;
    }
    // `/v2/<name>/manifests/<tag>` (no digest) and `/v2/<name>/tags/list` are
    // mutable pointers.
    Mutability::mutable_default()
}

/// Cargo §2.1: the registry index is mutable; `.crate` downloads are immutable.
fn classify_cargo(lower: &str) -> Mutability {
    // Only a version-pinned `.crate` file served from the registry's crate
    // store is immutable. In the canonical layout that file lives under a
    // `crates/` path segment (`…/crates/<name>/<name>-<ver>.crate`). Requiring
    // that structural context means a bare `.crate` suffix in some other,
    // possibly mutable, position no longer gets cached forever — it falls
    // through to revalidation. Match `crates/` on a path-segment boundary so a
    // segment that merely *ends* in `crates` (e.g. `mycrates/…`) is not
    // mistaken for the crate store.
    if (lower.starts_with("crates/") || lower.contains("/crates/")) && lower.ends_with(".crate") {
        return Mutability::Immutable;
    }
    // `config.json`, the sparse index files (`<a>/<b>/<crate>`),
    // `/api/v1/crates/<name>/<version>/download` redirects, and any stray
    // `.crate` outside the crate store are mutable / index.
    Mutability::mutable_default()
}

/// Debian §2.1: by-hash indices and pool/ packages are immutable; dists/
/// index files are mutable.
///
/// See <https://wiki.debian.org/DebianRepository/Format>:
/// - **by-hash**: The hash is part of the URL path, making the file
///   content-addressed. A content change produces a different URL.
/// - **pool/**: The Debian Repository Format spec mandates "A repository must
///   not include different packages (different content) with the same package
///   name, version, and architecture." The path encodes name+version+arch, so
///   content is pinned. Covers `.deb`, `.udeb`, `.dsc`, `.orig.tar.*`,
///   `.debian.tar.*`.
/// - **dists/**: Release, InRelease, Packages, Sources, Translation, Contents,
///   dep11, etc. are rewritten in place by upstream on each publish.
fn classify_debian(lower: &str) -> Mutability {
    if lower.contains("/by-hash/") {
        return Mutability::Immutable;
    }
    if lower.starts_with("pool/") || lower.contains("/pool/") {
        return Mutability::Immutable;
    }
    Mutability::mutable_default()
}

/// RPM: `repodata/repomd.xml`(+`.asc`) is the mutable index; all other
/// `repodata/<checksum>-*` files are content-addressed and packages
/// (`.rpm`/`.drpm`) are version-pinned — both immutable.
fn classify_rpm(lower: &str) -> Mutability {
    let leaf = leaf(lower);
    // The mutable pointer and its detached signature.
    if leaf == "repomd.xml" || leaf == "repomd.xml.asc" {
        return Mutability::mutable_default();
    }
    // Packages are immutable.
    if leaf.ends_with(".rpm") || leaf.ends_with(".drpm") {
        return Mutability::Immutable;
    }
    // Content-addressed metadata under repodata/: a checksum-prefixed name such
    // as `<hex>-primary.xml.gz` / `.zck`. Require a hex prefix before the first
    // '-' so a bare `primary.xml.gz` (no unique-filename) stays conservative.
    if lower.contains("repodata/") {
        if let Some((prefix, _rest)) = leaf.split_once('-') {
            let looks_hashed = prefix.len() >= 8 && prefix.chars().all(|c| c.is_ascii_hexdigit());
            if looks_hashed {
                return Mutability::Immutable;
            }
        }
    }
    // Unknown path: revalidate.
    Mutability::mutable_default()
}

/// The final path segment (after the last `/`), or the whole string.
fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// If `path` is a createrepo unique-filename (`repodata/<sha256>-<name>`),
/// return the 64-hex-char checksum prefix. Used to verify a content-addressed
/// body's integrity before caching it as immutable (design S3): the RPM
/// `createrepo --unique-md-filenames` convention embeds the SHA-256 of the
/// file's own content in its name (e.g.
/// `repodata/1a2b...-primary.xml.gz`), so the path itself is an assertion
/// about the body that a proxy can verify before trusting it forever.
///
/// Returns `None` for any path whose leaf does not have a 64-hex-char prefix
/// before the first `-` (e.g. `repomd.xml`, a package file, or a
/// non-checksum-prefixed metadata file) — those paths are not
/// content-addressed and this check does not apply to them.
pub fn expected_sha256_from_path(path: &str) -> Option<&str> {
    let lower = path.to_ascii_lowercase();
    let leaf = leaf(&lower);
    let (prefix, _) = leaf.split_once('-')?;
    if prefix.len() == 64 && prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        // Return the slice from the ORIGINAL path (case-insensitive hex).
        let start = path.len() - leaf.len();
        Some(&path[start..start + 64])
    } else {
        None
    }
}

/// Phase-1 interim over-quota guard for a single object about to be cached
/// (bug artifact-keeper-x70). Returns `true` when `quota_bytes` is set and
/// `object_len` exceeds it, in which case the caller must skip the cache
/// write for this object (still serving the body to the client).
///
/// This is deliberately NOT full per-repo usage accounting: the proxy cache
/// is not recorded in the `artifacts` table (#1278), so there is no running
/// per-repo proxy-cache total to check a request against yet. Full quota
/// enforcement (usage tracking + eviction) is deferred to P4; this is only a
/// cheap guard against a single object that is, by itself, already larger
/// than the whole configured quota.
///
/// `quota_bytes = None` (no quota configured) never exceeds. An object
/// exactly equal to the quota does NOT exceed (the quota is an inclusive
/// ceiling, not an exclusive bound).
pub fn exceeds_single_object_quota(quota_bytes: Option<i64>, object_len: i64) -> bool {
    match quota_bytes {
        Some(quota) => object_len > quota,
        None => false,
    }
}

/// Concrete versioned Maven artifact extensions (immutable). Checksums and
/// signatures of these are immutable too.
fn has_artifact_extension(leaf: &str) -> bool {
    const EXTS: &[&str] = &[
        ".jar", ".pom", ".war", ".ear", ".aar", ".zip", ".tar.gz", ".tgz", ".module", ".klib",
    ];
    const SIDECAR: &[&str] = &[".md5", ".sha1", ".sha256", ".sha512", ".asc"];
    // Strip a trailing checksum/signature suffix, then test the real extension.
    let base = SIDECAR
        .iter()
        .find_map(|s| leaf.strip_suffix(s))
        .unwrap_or(leaf);
    EXTS.iter().any(|e| base.ends_with(e))
}

/// PyPI distribution files: wheels, sdists, eggs (immutable once published).
fn is_pypi_package_file(leaf: &str) -> bool {
    const EXTS: &[&str] = &[
        ".whl", ".tar.gz", ".tar.bz2", ".zip", ".egg", ".tgz", ".conda", ".tar.zst",
    ];
    EXTS.iter().any(|e| leaf.ends_with(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // ----- is_explicitly_mutable_index(): release-immutability oracle ------
    //
    // Only a format's genuine in-place index/pointer is an "explicitly mutable
    // index"; every versioned artifact and every default-format coordinate is a
    // protected release coordinate (NOT an explicit mutable index).
    #[test]
    fn explicitly_mutable_index_only_for_real_index_files() {
        use RepositoryFormat::*;
        // Real mutable index files -> true (re-upload of different bytes allowed).
        assert!(is_explicitly_mutable_index(
            &Maven,
            "com/x/app/maven-metadata.xml"
        ));
        assert!(is_explicitly_mutable_index(&Pypi, "simple/requests/"));
        assert!(is_explicitly_mutable_index(&Npm, "left-pad"));
        // Versioned / content-addressed artifacts -> false (protected).
        assert!(!is_explicitly_mutable_index(
            &Maven,
            "com/x/app/1.0.0/app-1.0.0.jar"
        ));
        assert!(!is_explicitly_mutable_index(
            &Npm,
            "left-pad/-/left-pad-1.0.0.tgz"
        ));
        // Conan revision-file coordinates are rewritten in place within a
        // revision (re-upload of different bytes is legitimate), so they are
        // treated as mutable -> true (the swap guard is a no-op for conan).
        assert!(is_explicitly_mutable_index(
            &Conan,
            "relib/1.0/_/_/revisions/rev1/files/conanfile.py"
        ));
        // Debian: dists/ indices are mutable indexes; pool/ and by-hash/
        // artifacts are protected release coordinates.
        assert!(is_explicitly_mutable_index(
            &Debian,
            "dists/bookworm/main/binary-amd64/Packages"
        ));
        assert!(!is_explicitly_mutable_index(
            &Debian,
            "pool/main/a/apt/apt_2.5.3_amd64.deb"
        ));
        assert!(!is_explicitly_mutable_index(
            &Debian,
            "dists/bookworm/by-hash/SHA256/abc123def"
        ));
        // Default-format families have NO in-place index at a coordinate; every
        // stored path is a release coordinate -> always false (protected).
        for f in [Generic, Nuget, Composer, Go, Helm] {
            assert!(
                !is_explicitly_mutable_index(&f, "anything/1.0.0/file.bin"),
                "{f:?} coordinates must be treated as release coordinates"
            );
        }
    }

    // ----- classify(): per-format immutable-vs-mutable table (#1611 §2.1) ---

    /// `(format, path, expected_immutable)` rows straight from the §2.1 table.
    fn classify_cases() -> Vec<(RepositoryFormat, &'static str, bool)> {
        use RepositoryFormat::*;
        vec![
            // Maven: versioned artifacts immutable, metadata mutable.
            (Maven, "com/example/app/1.0.0/app-1.0.0.jar", true),
            (Maven, "com/example/app/1.0.0/app-1.0.0.pom", true),
            (Maven, "com/example/app/1.0.0/app-1.0.0.jar.sha1", true),
            (Maven, "com/example/app/1.0.0/app-1.0.0.jar.md5", true),
            (Maven, "com/example/app/1.0.0/app-1.0.0-sources.jar", true),
            (Maven, "com/example/app/maven-metadata.xml", false),
            (Maven, "com/example/app/maven-metadata.xml.sha1", false),
            (
                Maven,
                "com/example/app/1.0-SNAPSHOT/app-1.0-20240101.120000-3.jar",
                true,
            ),
            (Gradle, "org/foo/bar/2.1/bar-2.1.jar", true),
            (Sbt, "org/foo/bar/maven-metadata.xml", false),
            // PyPI: index mutable, package files immutable.
            (Pypi, "simple/requests/", false),
            (Pypi, "simple/", false),
            (Pypi, "simple", false),
            (
                Pypi,
                "packages/source/r/requests/requests-2.31.0.tar.gz",
                true,
            ),
            (
                Pypi,
                "simple/requests/requests-2.31.0-py3-none-any.whl",
                true,
            ),
            (Poetry, "simple/black/", false),
            // npm: packument mutable, tarball immutable.
            (Npm, "lodash", false),
            (Npm, "@types/node", false),
            (Npm, "lodash/-/lodash-4.17.21.tgz", true),
            (Npm, "@babel/core/-/core-7.0.0.tgz", true),
            // A `.tgz` NOT under a `/-/` segment is NOT a canonical package
            // tarball: it must fall through to mutable, never cached forever.
            (Npm, "lodash/lodash-4.17.21.tgz", false),
            (Npm, "some/weird/attachment.tgz", false),
            (Yarn, "react/-/react-18.2.0.tgz", true),
            (Yarn, "react", false),
            // OCI: digest immutable, tag mutable.
            (Docker, "v2/library/nginx/blobs/sha256:abc123def456", true),
            (
                Docker,
                "v2/library/nginx/manifests/sha256:abc123def456",
                true,
            ),
            (Docker, "v2/library/nginx/manifests/latest", false),
            (Docker, "v2/library/nginx/manifests/1.25.3", false),
            (Docker, "v2/library/nginx/tags/list", false),
            (Oras, "v2/myorg/chart/blobs/sha256:deadbeef", true),
            // Cargo: index mutable, crate immutable.
            (Cargo, "config.json", false),
            (Cargo, "lo/da/lodash", false),
            (Cargo, "api/v1/crates/serde/1.0.0/download", false),
            (Cargo, "crates/serde/serde-1.0.0.crate", true),
            (Cargo, "registry/crates/tokio/tokio-1.0.0.crate", true),
            // A `.crate` suffix outside the crate store (no `crates/` segment)
            // is no longer blindly immutable: revalidate instead.
            (Cargo, "weird/path/something.crate", false),
            (Cargo, "serde-1.0.0.crate", false),
            // A segment that merely ends in `crates` must not be mistaken for
            // the crate store via a loose substring match: revalidate.
            (Cargo, "mycrates/serde-1.0.0.crate", false),
            // Debian: by-hash and pool immutable; dists indices mutable.
            (Debian, "dists/bookworm/by-hash/SHA256/abc123def456", true),
            (
                Debian,
                "dists/bookworm/main/binary-amd64/by-hash/SHA256/abc",
                true,
            ),
            (Debian, "pool/main/a/apt/apt_2.5.3_amd64.deb", true),
            (Debian, "pool/main/a/apt/apt_2.5.3.dsc", true),
            (Debian, "pool/main/a/apt/apt_2.5.3.orig.tar.xz", true),
            (Debian, "pool/main/a/apt/apt_2.5.3.debian.tar.xz", true),
            (Debian, "dists/bookworm/InRelease", false),
            (Debian, "dists/bookworm/Release", false),
            (Debian, "dists/bookworm/Release.gpg", false),
            (Debian, "dists/bookworm/main/binary-amd64/Packages", false),
            (
                Debian,
                "dists/bookworm/main/binary-amd64/Packages.gz",
                false,
            ),
            (Debian, "dists/bookworm/i18n/Translation-en.bz2", false),
            (Debian, "dists/bookworm/main/source/Sources.xz", false),
            (Debian, "dists/bookworm/main/Contents-amd64.gz", false),
            // Unknown / other formats: conservative mutable default.
            (Generic, "whatever/file.bin", false),
            (Go, "github.com/foo/bar/@v/v1.0.0.zip", false),
        ]
    }

    #[test]
    fn classify_matches_table() {
        for (format, path, expect_immutable) in classify_cases() {
            let m = classify(&format, path);
            assert_eq!(
                m.is_immutable(),
                expect_immutable,
                "classify({format:?}, {path:?}) = {m:?}, expected immutable={expect_immutable}"
            );
        }
    }

    #[test]
    fn classify_leading_slash_is_normalized() {
        assert_eq!(
            classify(&RepositoryFormat::Maven, "/com/example/app/1.0/app-1.0.jar"),
            Mutability::Immutable
        );
    }

    #[test]
    fn classify_unknown_path_defaults_mutable() {
        // An unrecognized Maven leaf must NOT be misclassified immutable.
        assert!(!classify(&RepositoryFormat::Maven, "com/example/app/").is_immutable());
        assert!(!classify(&RepositoryFormat::Cargo, "weird/index/path").is_immutable());
    }

    #[test]
    fn mutable_default_carries_conservative_ttl() {
        match classify(&RepositoryFormat::Npm, "lodash") {
            Mutability::Mutable { default_ttl_secs } => {
                assert_eq!(default_ttl_secs, MUTABLE_DEFAULT_TTL_SECS)
            }
            other => panic!("expected mutable, got {other:?}"),
        }
    }

    #[test]
    fn immutable_write_ttl_is_effectively_forever() {
        assert!(Mutability::Immutable.write_ttl_secs() > 10 * 365 * 24 * 3600 - 1);
        assert_eq!(
            Mutability::mutable_default().write_ttl_secs(),
            MUTABLE_DEFAULT_TTL_SECS
        );
    }

    // ----- evaluate(): full freshness matrix (#1611 §2.5) -------------------

    fn entry(
        mutability: Mutability,
        expires_in: i64,
        neg_in: Option<i64>,
        now: DateTime<Utc>,
    ) -> CacheEntry {
        CacheEntry {
            mutability,
            expires_at: now + Duration::seconds(expires_in),
            negative_cached_until: neg_in.map(|s| now + Duration::seconds(s)),
        }
    }

    #[test]
    fn evaluate_miss_when_no_entry() {
        assert_eq!(evaluate(None, Utc::now()), Freshness::Miss);
    }

    #[test]
    fn evaluate_immutable_always_fresh() {
        let now = Utc::now();
        // Even with an expires_at in the past, immutable is Fresh.
        let e = entry(Mutability::Immutable, -10_000, None, now);
        assert_eq!(evaluate(Some(&e), now), Freshness::Fresh);
    }

    #[test]
    fn evaluate_mutable_fresh_before_ttl() {
        let now = Utc::now();
        let e = entry(Mutability::mutable_default(), 60, None, now);
        assert_eq!(evaluate(Some(&e), now), Freshness::Fresh);
    }

    #[test]
    fn evaluate_mutable_stale_after_ttl() {
        let now = Utc::now();
        let e = entry(Mutability::mutable_default(), -1, None, now);
        assert_eq!(evaluate(Some(&e), now), Freshness::Stale);
    }

    #[test]
    fn evaluate_negative_hit_within_window() {
        let now = Utc::now();
        let e = entry(Mutability::mutable_default(), 60, Some(30), now);
        assert_eq!(evaluate(Some(&e), now), Freshness::NegativeHit);
    }

    #[test]
    fn evaluate_negative_window_elapsed_is_miss() {
        let now = Utc::now();
        let e = entry(Mutability::mutable_default(), 60, Some(-1), now);
        assert_eq!(evaluate(Some(&e), now), Freshness::Miss);
    }

    #[test]
    fn evaluate_negative_takes_precedence_over_immutable() {
        // A negative-cached entry never carries a body, even if classified
        // immutable; the negative window wins.
        let now = Utc::now();
        let e = entry(Mutability::Immutable, 10_000, Some(30), now);
        assert_eq!(evaluate(Some(&e), now), Freshness::NegativeHit);
    }

    #[test]
    fn negative_ttl_constant_is_short() {
        assert!((30..=60).contains(&NEGATIVE_CACHE_TTL_SECS));
    }

    #[test]
    fn test_classify_rpm() {
        use RepositoryFormat::Rpm;
        // repomd.xml and its signature are the mutable entry point.
        assert_eq!(
            classify(&Rpm, "repodata/repomd.xml"),
            Mutability::mutable_default()
        );
        assert_eq!(
            classify(&Rpm, "repodata/repomd.xml.asc"),
            Mutability::mutable_default()
        );
        // Content-addressed metadata (checksum-prefixed) is immutable.
        assert_eq!(
            classify(&Rpm, "repodata/1a2b3c4d-primary.xml.gz"),
            Mutability::Immutable
        );
        assert_eq!(
            classify(&Rpm, "repodata/deadbeef-primary.xml.zck"),
            Mutability::Immutable
        );
        // Packages are immutable.
        assert_eq!(
            classify(&Rpm, "Packages/foo-1.2-3.x86_64.rpm"),
            Mutability::Immutable
        );
        assert_eq!(
            classify(&Rpm, "getPackage/bar-2.0-1.noarch.drpm"),
            Mutability::Immutable
        );
        // Unknown / directory-ish paths stay conservative.
        assert_eq!(classify(&Rpm, "repodata/"), Mutability::mutable_default());
        // A bare, non-checksum-prefixed metadata file stays conservative (mutable).
        assert_eq!(
            classify(&Rpm, "repodata/primary.xml.gz"),
            Mutability::mutable_default()
        );
        // A prefix shorter than 8 hex chars is NOT treated as content-addressed.
        assert_eq!(
            classify(&Rpm, "repodata/1234567-primary.xml.gz"),
            Mutability::mutable_default()
        );
        // Content-addressed metadata nested under a subpath is still immutable.
        assert_eq!(
            classify(&Rpm, "centos/9/repodata/deadbeef12-primary.xml.gz"),
            Mutability::Immutable
        );
    }

    #[test]
    fn test_rpm_explicit_mutable_index() {
        use RepositoryFormat::Rpm;
        assert!(is_explicitly_mutable_index(&Rpm, "repodata/repomd.xml"));
        assert!(!is_explicitly_mutable_index(
            &Rpm,
            "Packages/foo-1.2-3.x86_64.rpm"
        ));
        assert!(!is_explicitly_mutable_index(
            &Rpm,
            "repodata/deadbeef-primary.xml.gz"
        ));
    }

    // ----- expected_sha256_from_path(): content-addressed integrity (S3) ----

    #[test]
    fn test_expected_sha256_from_path() {
        // Full SHA-256 (64 hex) prefix is returned.
        let p = "repodata/9f".to_string() + &"a".repeat(62) + "-primary.xml.gz";
        assert!(expected_sha256_from_path(&p).is_some());
        // repomd.xml and packages have no embedded checksum.
        assert_eq!(expected_sha256_from_path("repodata/repomd.xml"), None);
        assert_eq!(
            expected_sha256_from_path("Packages/foo-1.2-3.x86_64.rpm"),
            None
        );
    }

    #[test]
    fn test_expected_sha256_from_path_returns_exact_slice_of_original_path() {
        let hex = "9f".to_string() + &"a".repeat(62);
        let p = format!("repodata/{hex}-primary.xml.gz");
        assert_eq!(expected_sha256_from_path(&p), Some(hex.as_str()));
    }

    #[test]
    fn test_expected_sha256_from_path_case_insensitive_hex() {
        // Uppercase hex in the path is still recognized as a checksum
        // prefix, and the returned slice is the ORIGINAL (uppercase) bytes so
        // the caller can compare byte-for-byte with a lowercase hex digest
        // using an ascii-case-insensitive comparison.
        let hex_upper = "9F".to_string() + &"A".repeat(62);
        let p = format!("repodata/{hex_upper}-primary.xml.gz");
        assert_eq!(expected_sha256_from_path(&p), Some(hex_upper.as_str()));
    }

    #[test]
    fn test_expected_sha256_from_path_rejects_short_prefix() {
        // A prefix shorter than 64 hex chars is not a full SHA-256 and must
        // not be treated as content-addressed.
        let p = "repodata/deadbeef-primary.xml.gz";
        assert_eq!(expected_sha256_from_path(p), None);
    }

    #[test]
    fn test_expected_sha256_from_path_rejects_non_hex_prefix() {
        // 64 characters but not all hex digits.
        let p = "repodata/".to_string() + &"z".repeat(64) + "-primary.xml.gz";
        assert_eq!(expected_sha256_from_path(&p), None);
    }

    #[test]
    fn test_expected_sha256_from_path_no_dash_in_leaf() {
        // No '-' separator at all -> no checksum prefix to extract.
        assert_eq!(
            expected_sha256_from_path("repodata/primarynodash.xml"),
            None
        );
    }

    // ----- exceeds_single_object_quota(): Phase-1 interim guard (x70) -------

    #[test]
    fn test_exceeds_single_object_quota_table() {
        // (quota_bytes, object_len, expected)
        let cases: Vec<(Option<i64>, i64, bool)> = vec![
            // No quota configured -> never exceeds.
            (None, 0, false),
            (None, i64::MAX, false),
            // Object strictly larger than quota -> exceeds.
            (Some(100), 101, true),
            // Object exactly at quota -> does NOT exceed (quota is a ceiling,
            // not an exclusive bound).
            (Some(100), 100, false),
            // Object smaller than quota -> does not exceed.
            (Some(100), 99, false),
            // Zero-byte object never exceeds any positive quota.
            (Some(100), 0, false),
        ];
        for (quota_bytes, object_len, expected) in cases {
            assert_eq!(
                exceeds_single_object_quota(quota_bytes, object_len),
                expected,
                "exceeds_single_object_quota({quota_bytes:?}, {object_len}) expected {expected}"
            );
        }
    }
}
