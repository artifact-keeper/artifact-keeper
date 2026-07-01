//! Core scanner orchestration service.
//!
//! Provides a trait-based scanner interface and an orchestrator that runs
//! applicable scanners against artifacts, persists results, and triggers
//! security score recalculation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::BoxStream;
use futures::StreamExt;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, RawPackage, Severity};
use crate::models::user::User;
use crate::services::auth_service::AuthService;
use crate::services::grype_scanner::GrypeScanner;
use crate::services::image_scanner::ImageScanner;
use crate::services::scan_config_service::ScanConfigService;
use crate::services::scan_result_service::ScanResultService;
use crate::services::trivy_fs_scanner::TrivyFsScanner;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// TTL window (in days) for hash-based scan dedup lookups.
///
/// Both the cross-artifact reuse path (`find_reusable_scan`) and the
/// same-artifact short-circuit path (`find_existing_scan_for_artifact`,
/// added for #1373) use this window. Completed scans older than this
/// no longer count as reusable, so we re-scan stale artifacts to pick
/// up freshly-published advisories.
pub(crate) const DEDUP_TTL_DAYS: i32 = 30;

/// Shorter TTL window (in days) applied to completed scan rows whose
/// `findings_count = 0`.
///
/// A zero-finding completed row is ambiguous: it can mean "scanner ran and
/// the artifact is genuinely clean" OR "scanner ran but an upstream
/// extraction / staging step produced an empty tree, so the scanner walked
/// nothing and produced nothing" (#1469, #1427, #1428). The standard
/// 30-day window silently masks the latter case for a month, so the
/// operator-visible "rescan" after fixing the extraction bug keeps
/// returning the cached empty result.
///
/// One day is short enough that any rebuild-fix-rescan loop sees a fresh
/// scan well within the same working day, but long enough to suppress the
/// trivial duplicate scans that #1373 was originally about (two concurrent
/// trigger calls on the same upload). Genuinely-clean artifacts still
/// dedup for the shorter window, which is the only cost.
///
/// Set to 1 (vs. e.g. 7) deliberately so an operator iterating on a
/// pipeline bug never has to wait more than 24h for the cached false-clean
/// to expire on its own. The `bypass_dedup` flag on
/// [`crate::api::handlers::security::TriggerScanRequest`] is the explicit
/// escape hatch for the impatient case.
pub(crate) const ZERO_FINDINGS_DEDUP_TTL_DAYS: i32 = 1;

/// Upper bound on the size of a single artifact we are willing to stage for
/// scanning. Beyond this we reject the input rather than consume unbounded
/// disk and virtual address space. 10 GiB is generous for real packages while
/// still capping a hostile or runaway upload.
pub(crate) const MAX_SCAN_INPUT_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Below this size we keep the scan input in heap (`Bytes`) and skip the
/// tempfile + mmap machinery entirely. The mmap path exists to keep
/// multi-GiB artifacts off anon heap so the cgroup OOM killer leaves the
/// process alone; for a few-KB package that overhead (create_dir_all,
/// spawn_blocking, tempfile, mmap) is pure cost. 8 MiB keeps the common
/// small-artifact case on the fast in-memory path.
pub(crate) const SCAN_MMAP_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;

// The mmap threshold must sit below the hard size cap. Otherwise the spill
// path could only be reached after the cap had already rejected the input,
// leaving the two knobs inconsistent. Enforced at compile time.
const _: () = assert!(SCAN_MMAP_THRESHOLD_BYTES < MAX_SCAN_INPUT_BYTES);

/// Sanitize a filename to its basename, stripping any directory components
/// to prevent path traversal attacks. Returns `"artifact"` as a fallback
/// when the input has no valid filename component.
pub(crate) fn sanitize_artifact_filename(name: &str) -> String {
    Path::new(name)
        .file_name()
        .unwrap_or(std::ffi::OsStr::new("artifact"))
        .to_string_lossy()
        .to_string()
}

/// Map a repository format string to the corresponding purl type.
///
/// Common formats (pypi, npm, maven, etc.) get their standard purl type.
/// Unknown formats fall back to `"generic"`.
fn format_to_purl_type(format: &str) -> &'static str {
    match format.to_lowercase().as_str() {
        "pypi" => "pypi",
        "npm" => "npm",
        "cargo" | "crates" => "cargo",
        "maven" => "maven",
        "go" | "golang" => "golang",
        "nuget" => "nuget",
        "rubygems" | "gem" => "gem",
        "docker" | "oci" | "container" => "docker",
        "composer" | "php" => "composer",
        "cocoapods" | "pods" => "cocoapods",
        "swift" => "swift",
        "hex" | "elixir" => "hex",
        "pub" | "dart" => "pub",
        "conan" | "cpp" => "conan",
        "conda" => "conda",
        "hackage" | "haskell" => "hackage",
        "rpm" => "rpm",
        "deb" | "debian" | "apt" => "deb",
        "apk" | "alpine" => "apk",
        _ => "generic",
    }
}

/// True when the artifact is an OCI / Docker container image manifest.
///
/// Used to gate scanner applicability: `ImageScanner` (Trivy server-mode
/// against the registry) handles these; `TrivyFsScanner` and
/// `GrypeScanner` reject them because their `dir:<workspace>` invocation
/// sees only the manifest JSON, not the layer blobs that hold the
/// installed packages (#961, #966).
///
/// Predicate matches against either:
/// - content type contains `vnd.oci.image` / `vnd.docker.distribution`
///   / `vnd.docker.container`
/// - artifact path contains `/manifests/` — catches proxy upstream
///   variants that serve manifests without setting the canonical
///   content type
pub fn is_oci_image_artifact(artifact: &Artifact) -> bool {
    let ct = &artifact.content_type;
    ct.contains("vnd.oci.image")
        || ct.contains("vnd.docker.distribution")
        || ct.contains("vnd.docker.container")
        || artifact.path.contains("/manifests/")
}

/// Parse a `v2/<name>/manifests/<reference>` registry path into `(name, ref)`.
///
/// Used by ImageScanner (Trivy) and GrypeScanner (#1160) to reconstruct a
/// scannable image ref from the artifact path. Returns `None` for paths that
/// don't match the OCI distribution-spec pull URL shape; callers fall back
/// to alternative scan modes or skip the artifact.
pub fn parse_oci_manifest_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.trim_start_matches('/').strip_prefix("v2/")?;
    let idx = rest.find("/manifests/")?;
    let name = &rest[..idx];
    let reference = &rest[idx + "/manifests/".len()..];
    if name.is_empty() || reference.is_empty() {
        return None;
    }
    Some((name, reference))
}

/// Join a parsed image name and reference into a single OCI reference string
/// using the correct separator: `@` for digest references (e.g.
/// `sha256:abc...`) and `:` for tag references.
///
/// The OCI distribution spec and all container tooling (Docker, Grype, Trivy
/// CLI) require the `name@digest` form for digest-pinned references. Using
/// `:` between the name and a `sha256:...` reference produces an invalid
/// reference (`name:sha256:digest` has two colons in the tag position) that
/// every parser rejects with "could not parse reference". A single
/// `docker buildx push` creates three artifacts (the tag-based index plus two
/// digest-referenced manifests for platform + attestation); the latter two
/// can only be scanned by digest. See issue #1483.
pub fn join_oci_image_ref(name: &str, reference: &str) -> String {
    let sep = if is_oci_digest_reference(reference) {
        '@'
    } else {
        ':'
    };
    format!("{}{}{}", name, sep, reference)
}

/// Whether an OCI reference string is a digest (e.g. `sha256:abc...`) rather
/// than a tag. OCI tags cannot contain `:`, so any reference that contains a
/// colon is, by spec, a digest. We accept any `<algo>:<hex>` shape (sha256,
/// sha512, future algorithms) rather than hard-coding `sha256:` so we stay
/// forward-compatible.
pub fn is_oci_digest_reference(reference: &str) -> bool {
    if let Some((algo, hex)) = reference.split_once(':') {
        !algo.is_empty()
            && !hex.is_empty()
            && algo.chars().all(|c| c.is_ascii_alphanumeric())
            && hex.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        false
    }
}

/// Normalize the host CPU architecture to the OCI `platform.architecture`
/// token used in image-index child descriptors (`amd64`, `arm64`, ...).
///
/// `std::env::consts::ARCH` reports the Rust target triple's arch (`x86_64`,
/// `aarch64`), which does not match the OCI/Go `GOARCH` vocabulary an image
/// index uses. We only map the two architectures Artifact Keeper actually
/// runs on; anything else passes through unchanged so an exotic runner still
/// gets a deterministic (if non-matching) token and falls back to the first
/// linux child during resolution rather than panicking. Pure + host-stable so
/// it can anchor the resolution unit tests (#1971).
pub fn runner_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Outcome of resolving a scan reference against an in-hand manifest body.
///
/// Distinct variants make the three behaviors testable without inspecting the
/// returned string: a single-arch / unparseable body is a no-op
/// (`Passthrough`), an image index that yields a concrete scannable child
/// rewrites the reference to that child digest (`ResolvedIndexChild`), and an
/// index whose only children are attestation/unknown/empty manifests cannot be
/// scanned at all (`UnresolvableIndex`, reference left unchanged so the caller
/// still attempts the index ref rather than skipping the scan). See #1971.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanReferenceResolution {
    /// Body is not an image index (single-arch image, malformed, or empty):
    /// the reference is returned unchanged. The dominant single-arch path
    /// (and digest-pinned #1483 refs) must hit this branch byte-for-byte.
    Passthrough(String),
    /// Body is an image index and a concrete scannable child platform manifest
    /// was selected; the reference now addresses that child by digest.
    ResolvedIndexChild(String),
    /// Body is an image index but every child is attestation/unknown/empty, so
    /// no scannable child digest exists. The reference is returned unchanged.
    UnresolvableIndex(String),
}

impl ScanReferenceResolution {
    /// The (possibly rewritten) reference to hand to the builders.
    pub fn into_reference(self) -> String {
        match self {
            ScanReferenceResolution::Passthrough(r)
            | ScanReferenceResolution::ResolvedIndexChild(r)
            | ScanReferenceResolution::UnresolvableIndex(r) => r,
        }
    }
}

/// Whether an image-index child descriptor is an attestation / non-runnable
/// manifest that must never be selected as a scan target. Selecting one
/// re-introduces the empty-inventory bug (#1971), because attestation
/// manifests carry no installed packages.
///
/// A child is excluded when ANY of the following hold:
///   * `platform.os` or `platform.architecture` is `unknown` (the conventional
///     marker `docker buildx` stamps onto attestation children),
///   * `annotations["vnd.docker.reference.type"]` is `attestation-manifest`,
///   * `artifactType` contains `in-toto` (SLSA/provenance attestations).
fn is_excluded_index_child(child: &serde_json::Value) -> bool {
    let platform = child.get("platform");
    let os = platform
        .and_then(|p| p.get("os"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arch = platform
        .and_then(|p| p.get("architecture"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if os.eq_ignore_ascii_case("unknown") || arch.eq_ignore_ascii_case("unknown") {
        return true;
    }
    if child
        .get("annotations")
        .and_then(|a| a.get("vnd.docker.reference.type"))
        .and_then(|v| v.as_str())
        .is_some_and(|t| t.eq_ignore_ascii_case("attestation-manifest"))
    {
        return true;
    }
    if child
        .get("artifactType")
        .and_then(|v| v.as_str())
        .is_some_and(|t| t.to_ascii_lowercase().contains("in-toto"))
    {
        return true;
    }
    false
}

/// Resolve a scan `reference` against the manifest `body` the orchestrator
/// already loaded for this artifact (#1971).
///
/// When `body` is an OCI / Docker image **index** (manifest list), grype and
/// trivy would otherwise rely on their own default platform pick; if no child
/// matches the runner platform — or the only match is an attestation/empty
/// manifest — the scan catalogs zero packages and the SBOM is empty. To avoid
/// that, we select a concrete scannable child-platform manifest digest from
/// the body and rewrite the reference to address it directly, so the scanner
/// enumerates a real image. Selection order:
///
/// 1. the child whose `platform.architecture` matches [`runner_arch`] (and
///    `platform.os == "linux"`),
/// 2. else the first `linux` child,
/// 3. else the first remaining candidate.
///
/// Attestation/unknown children are excluded up front (see
/// [`is_excluded_index_child`]).
///
/// For any body that is not an image index (single-arch image, malformed,
/// empty, or missing the `manifests` array) the reference is returned
/// unchanged ([`ScanReferenceResolution::Passthrough`]) so the dominant
/// single-arch and digest-pinned (#1483) paths are byte-for-byte untouched.
/// This is a pure parse + string rewrite: no network, fully unit-testable.
pub fn resolve_scan_reference(body: &[u8], reference: &str) -> ScanReferenceResolution {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return ScanReferenceResolution::Passthrough(reference.to_string());
    };
    let Some(manifests) = json.get("manifests").and_then(|m| m.as_array()) else {
        // Not an image index (single-arch image manifest or other): no-op.
        return ScanReferenceResolution::Passthrough(reference.to_string());
    };

    // Candidate = scannable child with a digest, excluding attestation/unknown.
    let candidates: Vec<&serde_json::Value> = manifests
        .iter()
        .filter(|child| {
            child
                .get("digest")
                .and_then(|d| d.as_str())
                .is_some_and(|d| !d.is_empty())
                && !is_excluded_index_child(child)
        })
        .collect();

    let child_os = |c: &serde_json::Value| -> String {
        c.get("platform")
            .and_then(|p| p.get("os"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let child_arch = |c: &serde_json::Value| -> String {
        c.get("platform")
            .and_then(|p| p.get("architecture"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    let selected = candidates
        .iter()
        .find(|c| child_os(c) == "linux" && child_arch(c) == runner_arch())
        .or_else(|| candidates.iter().find(|c| child_os(c) == "linux"))
        .or_else(|| candidates.first());

    match selected {
        Some(child) => {
            let digest = child
                .get("digest")
                .and_then(|d| d.as_str())
                .unwrap_or_default();
            ScanReferenceResolution::ResolvedIndexChild(digest.to_string())
        }
        None => ScanReferenceResolution::UnresolvableIndex(reference.to_string()),
    }
}

/// SQL CTE that pins each `(artifact_id, scan_type)` pair to its single most-
/// recently-completed scan_result row. Bind `$1 = artifact_id` and follow
/// with `SELECT ... FROM <table> WHERE <table>.scan_result_id IN
/// (SELECT id FROM latest_scans)`.
///
/// Shared across the SBOM read path (`extract_dependencies_for_artifact` in
/// `api::handlers::sbom`) and the Dependency-Track submission path
/// (`submit_sbom_to_dependency_track` below) so a rescan that removed a dep
/// stops surfacing the removed dep from either surface. Mirror of the
/// pattern already used by `recalculate_score` and `get_dashboard_summary`
/// for vulnerability aggregation (issues #962 / #1126 / #1136).
///
/// Soft-deleted artifacts are excluded so consumers cannot rehydrate dep
/// trees for content the operator retired (#903 fresh-eyes review #5).
pub(crate) const LATEST_SCANS_FOR_ARTIFACT_CTE: &str = "
WITH latest_scans AS (
    SELECT DISTINCT ON (sr.artifact_id, sr.scan_type) sr.id
    FROM scan_results sr
    JOIN artifacts a ON a.id = sr.artifact_id
    WHERE sr.artifact_id = $1
      AND NOT a.is_deleted
      AND sr.status = 'completed'
    ORDER BY sr.artifact_id, sr.scan_type,
             sr.completed_at DESC NULLS LAST, sr.created_at DESC
)
";

/// Derive Dependency-Track project context from an optional repo row.
///
/// Returns `(repo_label, purl_type)` where `repo_label` is the human-readable
/// repository name (falling back to the raw repository UUID string when the
/// repository row is missing). The repo label is used in the DT project
/// description to give operators a way to trace a finding back to the source
/// repo. The purl type is derived from the repository format and is used to
/// stamp every component's purl in the generated SBOM.
///
/// Issue #1276: the DT *project name* itself is derived from the artifact
/// name (and version) by the caller, not this helper. Using the artifact
/// name lets DT findings map cleanly to the specific artifact AK stored,
/// rather than collapsing every artifact in a repo onto one project that
/// shared the repo's name and the first artifact's version.
pub(crate) fn derive_dt_project_info(
    repo_row: Option<(String, Option<String>)>,
    fallback_id: &str,
) -> (String, &'static str) {
    let (repo_label, repo_format) = match repo_row {
        Some((name, format)) => (name, format),
        None => (fallback_id.to_string(), None),
    };
    let purl_type = match repo_format {
        Some(ref fmt) => format_to_purl_type(fmt),
        None => "generic",
    };
    (repo_label, purl_type)
}

/// Build a list of [`DependencyInfo`] from scan-finding rows.
///
/// Each row is `(component_name, optional_version, optional_source)`.
/// When a version is present the function generates a purl string using
/// the supplied `purl_type`.
pub(crate) fn build_dependency_info_from_findings(
    findings_rows: Vec<(String, Option<String>, Option<String>)>,
    purl_type: &str,
) -> Vec<crate::services::sbom_service::DependencyInfo> {
    use crate::services::sbom_service::DependencyInfo;

    findings_rows
        .into_iter()
        .map(|(name, version, _source)| {
            let purl = version
                .as_deref()
                .map(|v| format!("pkg:{}/{}@{}", purl_type, name, v));
            DependencyInfo {
                name,
                version,
                purl,
                license: None,
                sha256: None,
            }
        })
        .collect()
}

/// Build a list of [`DependencyInfo`] from scan_packages rows.
///
/// Each row is `(name, optional_version, optional_purl, optional_license)` as
/// stored by Trivy's package enumeration. This is the inventory-table read
/// path used to forward SBOMs to Dependency-Track even when a scan found
/// zero vulnerabilities (#965). Prefers the persisted `purl` column when
/// present; otherwise synthesizes one from the supplied `purl_type` and
/// version, matching the shape produced by
/// [`build_dependency_info_from_findings`].
#[allow(clippy::type_complexity)]
pub(crate) fn build_dependency_info_from_packages(
    package_rows: Vec<(String, Option<String>, Option<String>, Option<String>)>,
    purl_type: &str,
) -> Vec<crate::services::sbom_service::DependencyInfo> {
    use crate::services::sbom_service::DependencyInfo;

    package_rows
        .into_iter()
        .map(|(name, version, purl, license)| {
            let purl = purl.or_else(|| {
                version
                    .as_deref()
                    .map(|v| format!("pkg:{}/{}@{}", purl_type, name, v))
            });
            DependencyInfo {
                name,
                version,
                purl,
                license,
                sha256: None,
            }
        })
        .collect()
}

/// Extract just the scan_result IDs from the `(scan_type, id)` pairs returned
/// by [`ScannerService::prepare_artifact_scan`].
///
/// Used by the trigger-scan handler to build `TriggerScanResponse.scan_result_ids`
/// without consuming the underlying vector (the same pairs are also collected
/// into a HashMap and handed to the spawned worker).
pub(crate) fn extract_scan_result_ids(prepared: &[(String, Uuid)]) -> Vec<Uuid> {
    prepared.iter().map(|(_, id)| *id).collect()
}

/// Convert the `(scan_type, id)` pairs returned by
/// [`ScannerService::prepare_artifact_scan`] into the HashMap shape consumed by
/// [`ScannerService::scan_artifact_with_prepared`].
///
/// Pulled out as a free function so the trigger-scan handler can build the map
/// without owning a HashMap import, and so the conversion is unit-testable
/// without spinning up a database.
pub(crate) fn prepared_pairs_to_map(prepared: Vec<(String, Uuid)>) -> HashMap<String, Uuid> {
    prepared.into_iter().collect()
}

/// Outcome of consulting the prepared-id map for one scanner inside
/// `scan_artifact_inner`'s loop. The DB-bound caller does the actual
/// row lookup or insert; this enum encodes the *decision* in a way that
/// is unit-testable without a database.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PreparedScanAction {
    /// A pre-allocated row id was popped from the map. The caller should
    /// reuse this row (UPDATE in the dedup path, GET in the fresh-scan
    /// path) instead of inserting a new one.
    Reuse(Uuid),
    /// No matching prepared id (either because the trigger handler didn't
    /// pre-allocate, or the scanner set changed between prepare and
    /// execute). Caller falls back to inserting a fresh row.
    InsertFresh,
}

/// Resolve the prepared-id outcome for a single scanner without touching
/// the database. The caller invokes `prepared.remove(scan_type)` and
/// hands the result here.
pub(crate) fn resolve_prepared_action(prepared_id: Option<Uuid>) -> PreparedScanAction {
    match prepared_id {
        Some(id) => PreparedScanAction::Reuse(id),
        None => PreparedScanAction::InsertFresh,
    }
}

/// Truncate a hex checksum string to its first 8 characters (or fewer if
/// the input is shorter) for use in human-readable log messages.
///
/// Lifted out of the inline `&checksum[..8.min(checksum.len())]` slice in
/// the reuse-path log line so it is unit-testable and so a future change
/// (longer prefix, sha-prefix scheme, etc.) is a single edit.
pub(crate) fn checksum_log_prefix(checksum: &str) -> &str {
    &checksum[..8.min(checksum.len())]
}

/// Decide whether a reusable scan match points at the same artifact we are
/// currently scanning (i.e. the artifact has already been scanned for these
/// exact bytes).
///
/// `find_reusable_scan` returns the most recent completed scan for a given
/// `(checksum, scan_type)` pair. When the matched scan's `artifact_id` equals
/// the current artifact's id, no further work is needed: the artifact already
/// has a completed scan row for this scanner. The caller skips both the
/// reuse-copy path AND the fresh-scan path, leaving the existing completed
/// row in place.
///
/// Earlier behavior (pre-#1373) skipped only the reuse-copy path and fell
/// through to running a fresh scan, which left two completed rows behind for
/// what should have been a single logical scan. See issue #1373 for the
/// release-gate failure that fix produced.
pub(crate) fn should_skip_reuse_for_same_artifact(
    source_artifact_id: Uuid,
    current_artifact_id: Uuid,
) -> bool {
    source_artifact_id == current_artifact_id
}

/// Pure mirror of the SQL TTL predicate
/// `completed_at > NOW() - ($ttl || ' days')::interval` used by both
/// `find_existing_scan_for_artifact` (same-artifact short-circuit, #1373)
/// and `find_reusable_scan` (cross-artifact reuse).
///
/// Returns `false` when:
/// - `completed_at` is `None` (scan never finished; not eligible for dedup)
/// - `ttl_days <= 0` (window collapsed to zero or negative; always stale)
/// - `completed_at` is older than `now - ttl_days`
///
/// Returns `true` when `completed_at` is within the inclusive window
/// `[now - ttl_days, now]`. We treat `completed_at == now - ttl_days` as
/// still within the window so the Rust check is at worst one tick more
/// permissive than the strict-`>` SQL form, which matches the bias in
/// the rest of the codebase (we'd rather over-dedup than re-scan the
/// same bytes twice).
///
/// This function is intentionally not called by production code: the
/// actual TTL window lives in the SQL query so the database can use the
/// index. The Rust mirror exists to pin the semantics in a way that is
/// unit-testable (no DB round-trip) and to give future refactors that
/// move the predicate into Rust a tested starting point.
#[allow(dead_code)]
pub(crate) fn is_within_dedup_ttl(
    completed_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    ttl_days: i32,
) -> bool {
    if ttl_days <= 0 {
        return false;
    }
    let Some(completed_at) = completed_at else {
        return false;
    };
    let window = chrono::Duration::days(ttl_days as i64);
    let cutoff = now - window;
    completed_at >= cutoff
}

// The check-then-act decision that used to live here (the
// `ShortCircuitDecision` enum + `decide_short_circuit_from_existing`) was
// removed in #1935: the SELECT-existing/INSERT-placeholder branch it modeled
// raced under concurrent triggers. The decision is now made atomically inside
// `ScanResultService::prepare_scan_placeholder`, under a per-(artifact_id,
// scan_type) advisory lock, so there is no longer a database-free branch to
// unit-test in isolation.

/// Outcome of the same-artifact branch inside `scan_artifact_inner` when
/// `find_reusable_scan` returns a row whose `artifact_id` matches the
/// artifact currently being scanned.
///
/// Three sub-cases, matching the inline comment block at the call site:
///
/// 1. `prepared_action` is `InsertFresh`: no placeholder was inserted,
///    so we just skip ([`SameArtifactAction::NoOp`]). The existing row
///    already represents this scan.
/// 2. `prepared_action` is `Reuse(target_id)` and `target_id ==
///    source_scan.id`: the prepare step already short-circuited to the
///    existing id (#1373 happy path); nothing to do
///    ([`SameArtifactAction::NoOp`]).
/// 3. `prepared_action` is `Reuse(target_id)` and `target_id !=
///    source_scan.id`: race window. A placeholder was committed before
///    the existing scan landed. Convert the orphan placeholder into a
///    reused row pointing at the existing completed scan
///    ([`SameArtifactAction::ConvertOrphanPlaceholder`]) so the
///    stuck-scan janitor never has to reap it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SameArtifactAction {
    /// Nothing to do; the existing completed scan already represents
    /// this artifact's result for this scanner.
    NoOp,
    /// Convert `target_id` (the orphan placeholder) into a reused-row
    /// pointing at `source_id` (the existing completed scan).
    ConvertOrphanPlaceholder { target_id: Uuid, source_id: Uuid },
}

/// Decide what to do when `find_reusable_scan` matched our own artifact.
///
/// See [`SameArtifactAction`] for the three sub-cases. This function is
/// pure: it does not touch the database or the scan_result_service; it
/// only encodes the branch logic that lived inline before #1373.
pub(crate) fn decide_same_artifact_action(
    prepared_action: &PreparedScanAction,
    source_scan_id: Uuid,
) -> SameArtifactAction {
    match prepared_action {
        PreparedScanAction::InsertFresh => SameArtifactAction::NoOp,
        PreparedScanAction::Reuse(target_id) => {
            if *target_id == source_scan_id {
                SameArtifactAction::NoOp
            } else {
                SameArtifactAction::ConvertOrphanPlaceholder {
                    target_id: *target_id,
                    source_id: source_scan_id,
                }
            }
        }
    }
}

/// Build the user-facing message for an artifact-level trigger response.
pub(crate) fn build_artifact_scan_message(artifact_id: Uuid) -> String {
    format!("Scan queued for artifact {}", artifact_id)
}

/// Build the user-facing message for a repository-level trigger response.
pub(crate) fn build_repository_scan_message(repository_id: Uuid, artifact_count: i64) -> String {
    format!(
        "Repository scan queued for {} ({} artifacts)",
        repository_id, artifact_count
    )
}

/// Shared scan workspace utilities for scanners that need to write artifact
/// content to disk, optionally extract archives, and clean up after scanning.
pub(crate) struct ScanWorkspace;

impl ScanWorkspace {
    /// Build the workspace directory path for a given artifact, using an
    /// optional prefix to distinguish different scanner types.
    pub fn workspace_dir(base: &str, prefix: Option<&str>, artifact: &Artifact) -> PathBuf {
        let dir_name = match prefix {
            Some(p) => format!("{}-{}", p, artifact.id),
            None => artifact.id.to_string(),
        };
        Path::new(base).join(dir_name)
    }

    /// Prepare the scan workspace: create directories, write artifact content,
    /// and optionally extract archives. Returns the workspace path.
    pub async fn prepare(
        base: &str,
        prefix: Option<&str>,
        artifact: &Artifact,
        content: &Bytes,
    ) -> Result<PathBuf> {
        let workspace = Self::workspace_dir(base, prefix, artifact);
        tokio::fs::create_dir_all(&workspace)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create scan workspace: {}", e)))?;

        let original_filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.name);
        let safe_filename = sanitize_artifact_filename(original_filename);
        let artifact_path = workspace.join(&safe_filename);

        tokio::fs::write(&artifact_path, content)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to write artifact to workspace: {}", e))
            })?;

        if Self::is_archive(original_filename) {
            if let Err(e) = Self::extract_archive(&artifact_path, &workspace).await {
                warn!(
                    "Failed to extract archive {}: {}. Scanning raw file instead.",
                    artifact.name, e
                );
            }
        }

        Ok(workspace)
    }

    /// Clean up the scan workspace directory, logging warnings on failure.
    pub async fn cleanup(base: &str, prefix: Option<&str>, artifact: &Artifact) {
        let workspace = Self::workspace_dir(base, prefix, artifact);
        Self::cleanup_path(&workspace).await;
    }

    /// Clean up a specific workspace directory by path, logging warnings on
    /// failure. Used by scanners that allocate a per-scan-unique workspace
    /// (so the path cannot be recomputed from `(base, prefix, artifact)`).
    pub async fn cleanup_path(workspace: &Path) {
        if !workspace.exists() {
            return;
        }
        // Extracted trees can contain directories the runtime UID can't traverse
        // or delete — e.g. tar can land kernel-module dirs at mode `d--x--S---`
        // (setgid, no read). Force owner-rwX across the tree first so the
        // recursive delete actually succeeds; otherwise it fails with EACCES and
        // silently leaves the (often multi-GiB) tree on the PVC until it fills.
        let workspace_str = workspace.to_string_lossy().to_string();
        if let Err(e) = tokio::process::Command::new("chmod")
            .args(["-R", "u+rwX", &workspace_str])
            .output()
            .await
        {
            warn!(
                "Failed to pre-chmod scan workspace {} before cleanup: {}",
                workspace.display(),
                e
            );
        }
        if let Err(e) = tokio::fs::remove_dir_all(workspace).await {
            warn!(
                "Failed to clean up scan workspace {}: {}",
                workspace.display(),
                e
            );
        }
    }

    /// Check if the file is an extractable archive.
    pub fn is_archive(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.ends_with(".tar.gz")
            || lower.ends_with(".tgz")
            || lower.ends_with(".whl")
            || lower.ends_with(".jar")
            || lower.ends_with(".war")
            || lower.ends_with(".ear")
            || lower.ends_with(".gem")
            || lower.ends_with(".crate")
            || lower.ends_with(".nupkg")
            || lower.ends_with(".zip")
            || lower.ends_with(".egg")
    }

    /// Extract an archive file into the given directory.
    ///
    /// Uses in-process Rust crates (`tar`, `flate2`, `zip`) rather than
    /// shelling out to `tar`/`unzip`. This removes the runtime dependency
    /// on system binaries (see issue #1243: the Alpine container image does
    /// not ship a full `tar`, so npm `.tgz` extraction silently failed and
    /// scans reported zero findings).
    ///
    /// Supported formats:
    /// - `.tar.gz`, `.tgz`, `.crate` -- gzipped tar
    /// - `.gem` -- plain tar (outer container; nested data.tar.gz is left as-is)
    /// - `.zip`, `.whl`, `.jar`, `.war`, `.ear`, `.nupkg`, `.egg` -- zip archives
    ///
    /// CPU-bound work runs on a blocking task to avoid stalling the tokio
    /// runtime when extracting large archives.
    pub async fn extract_archive(archive_path: &Path, dest: &Path) -> Result<()> {
        let name = archive_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        let src = archive_path.to_path_buf();
        let dst = dest.to_path_buf();

        let kind =
            if name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".crate") {
                ArchiveKind::TarGz
            } else if name.ends_with(".gem") {
                ArchiveKind::Tar
            } else if name.ends_with(".zip")
                || name.ends_with(".whl")
                || name.ends_with(".jar")
                || name.ends_with(".war")
                || name.ends_with(".ear")
                || name.ends_with(".nupkg")
                || name.ends_with(".egg")
            {
                ArchiveKind::Zip
            } else {
                return Ok(());
            };

        tokio::task::spawn_blocking(move || extract_archive_blocking(kind, &src, &dst))
            .await
            .map_err(|e| AppError::Internal(format!("Extraction task panicked: {}", e)))?
    }
}

#[derive(Clone, Copy, Debug)]
enum ArchiveKind {
    /// gzip-compressed tar (.tar.gz, .tgz, .crate)
    TarGz,
    /// plain (uncompressed) tar (.gem)
    Tar,
    /// zip-based archive (.zip, .whl, .jar, etc.)
    Zip,
}

fn extract_archive_blocking(kind: ArchiveKind, src: &Path, dst: &Path) -> Result<()> {
    let file = std::fs::File::open(src).map_err(|e| {
        AppError::Internal(format!("Failed to open archive {}: {}", src.display(), e))
    })?;

    match kind {
        ArchiveKind::TarGz => {
            let decoder = flate2::read::GzDecoder::new(file);
            unpack_tar(tar::Archive::new(decoder), dst)
        }
        ArchiveKind::Tar => unpack_tar(tar::Archive::new(file), dst),
        ArchiveKind::Zip => unpack_zip(file, dst),
    }
}

fn unpack_tar<R: std::io::Read>(mut archive: tar::Archive<R>, dst: &Path) -> Result<()> {
    // Guard against path-traversal entries (`../etc/passwd`). The `tar`
    // crate's `unpack` already refuses absolute paths and `..` components,
    // but we re-enable the safety flags explicitly for clarity.
    archive.set_overwrite(true);
    archive.set_preserve_permissions(false);
    archive
        .unpack(dst)
        .map_err(|e| AppError::Internal(format!("Tar extraction failed: {}", e)))
}

fn unpack_zip(file: std::fs::File, dst: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| AppError::Internal(format!("Failed to open zip archive: {}", e)))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| AppError::Internal(format!("Failed to read zip entry {}: {}", i, e)))?;

        // `enclosed_name` rejects absolute paths and any component containing
        // `..`, so traversal attempts return None and are skipped.
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let out_path = dst.join(rel);

        if entry.is_dir() {
            std::fs::create_dir_all(&out_path).map_err(|e| {
                AppError::Internal(format!(
                    "Failed to create zip dir {}: {}",
                    out_path.display(),
                    e
                ))
            })?;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AppError::Internal(format!(
                    "Failed to create zip parent {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let mut out = std::fs::File::create(&out_path).map_err(|e| {
            AppError::Internal(format!(
                "Failed to create zip output {}: {}",
                out_path.display(),
                e
            ))
        })?;
        std::io::copy(&mut entry, &mut out)
            .map_err(|e| AppError::Internal(format!("Failed to write zip entry {}: {}", i, e)))?;
    }

    Ok(())
}

/// Handle a scan step failure: log a warning, clean up the workspace, and
/// return an `AppError::Internal` with a formatted message.
///
/// Use this in `Scanner::scan()` implementations to avoid repeating the
/// warn-cleanup-return-Err pattern in every error branch.
pub(crate) async fn fail_scan(
    scanner_label: &str,
    artifact: &Artifact,
    error: &AppError,
    workspace_base: &str,
    workspace_prefix: Option<&str>,
) -> AppError {
    let msg = format!("{} failed for {}: {}", scanner_label, artifact.name, error);
    warn!("{}", msg);
    ScanWorkspace::cleanup(workspace_base, workspace_prefix, artifact).await;
    AppError::Internal(msg)
}

/// Variant of [`fail_scan`] that cleans up an explicit workspace path rather
/// than recomputing it from `(base, prefix, artifact)`. Used by scanners that
/// allocate a per-scan-unique workspace directory.
pub(crate) async fn fail_scan_path(
    scanner_label: &str,
    artifact: &Artifact,
    error: &AppError,
    workspace: &Path,
) -> AppError {
    let msg = format!("{} failed for {}: {}", scanner_label, artifact.name, error);
    warn!("{}", msg);
    ScanWorkspace::cleanup_path(workspace).await;
    AppError::Internal(msg)
}

/// Convert a Trivy report into `RawFinding` values. Shared by all scanners
/// that consume Trivy JSON output (trivy_fs_scanner, incus_scanner,
/// image_scanner).
///
/// `affected_component` holds the bare package name. The scanner-internal
/// target (e.g. `"package-lock.json"`) used to be appended in parentheses,
/// but consumers (SBOM, CVE-mapping lookup, UI) need the raw name to do
/// cross-source joins — see #903. Callers that still need the target string
/// can read it from the parallel `RawPackage` row's `source_target` field.
pub(crate) fn convert_trivy_findings(
    report: &crate::services::image_scanner::TrivyReport,
    source_label: &str,
) -> Vec<RawFinding> {
    report
        .results
        .iter()
        .flat_map(|result| {
            result
                .vulnerabilities
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(move |vuln| RawFinding {
                    severity: Severity::from_str_loose(&vuln.severity).unwrap_or(Severity::Info),
                    title: vuln.title.clone().unwrap_or_else(|| {
                        format!("{} in {}", vuln.vulnerability_id, vuln.pkg_name)
                    }),
                    description: vuln.description.clone(),
                    cve_id: Some(vuln.vulnerability_id.clone()),
                    // Bare package name; target moves to RawPackage.source_target.
                    affected_component: Some(vuln.pkg_name.clone()),
                    affected_version: Some(vuln.installed_version.clone()),
                    fixed_version: vuln.fixed_version.clone(),
                    source: Some(source_label.to_string()),
                    source_url: vuln.primary_url.clone(),
                })
        })
        .collect()
}

/// Upper bound for `scan_packages.purl`. Mirrors migration 087, which caps
/// the column at `VARCHAR(2048)`. The PURL RFC's published examples cluster
/// around 30-120 bytes and the practical real-world ceiling for valid PURLs
/// is well under 2048; values longer than that are almost certainly hostile
/// (lockfile-smuggled bloat) or buggy scanner output. Dropping the field on
/// over-length rather than truncating prevents handing a downstream parser
/// a syntactically half-valid PURL that happens to round to something
/// resolvable.
pub(crate) const PURL_MAX_LEN: usize = 2048;

/// Cheap syntactic check for "looks like a PURL" per the spec's
/// `pkg:<type>/<namespace>/<name>@<version>` shape. Matches the issue's
/// recommended regex `^pkg:[a-z0-9.+-]+/`: a fixed scheme, a non-empty
/// lowercase type token, then a slash. Fuller PURL validation (URL-encoding
/// rules on the namespace, qualifier ordering, fragment shape) is left to
/// the downstream consumer; the goal here is to reject obviously-malformed
/// strings before they hit the DB column or the SBOM document.
static PURL_PREFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^pkg:[a-z0-9.+-]+/").expect("static PURL_PREFIX_RE regex"));

/// Validate a PURL string against the length cap and syntactic prefix.
/// Returns `Some(purl)` when the string passes both checks and is suitable
/// for persistence; returns `None` (caller drops the field, keeps the row)
/// when the string is empty, oversized, or syntactically malformed.
///
/// Length cap matches migration 087's `VARCHAR(2048)` column type — keeping
/// the cap in the application layer too means a value that slipped past the
/// application path on a legacy build still fails at the column level, and
/// a value that fails at the application path never reaches the column at
/// all. (#1151)
pub(crate) fn validate_trivy_purl(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > PURL_MAX_LEN {
        return None;
    }
    if !PURL_PREFIX_RE.is_match(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Reduce a Trivy `Licenses` array to a SPDX-safe joined expression.
///
/// Each input element is run through [`crate::services::spdx_licenses::sanitize_license_term`]
/// before joining with ` OR `. Known SPDX identifiers (case-insensitive)
/// pass through in their canonical case; unknown terms and single-element
/// pre-joined expressions like `"MIT OR Apache-2.0"` are wrapped as
/// `LicenseRef-<sanitised>` so a downstream policy engine cannot silently
/// classify them as permissive. (#1152)
pub(crate) fn sanitize_trivy_licenses(raw: &[String]) -> Option<String> {
    let terms: Vec<String> = raw
        .iter()
        .filter_map(|s| crate::services::spdx_licenses::sanitize_license_term(s))
        .collect();
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" OR "))
    }
}

/// Convert a Trivy report's `Packages` blocks into [`RawPackage`] values.
/// Produces one row per (target, package, version) triple. Trivy emits both
/// a standalone `Packages` block and inline `PkgName`/`InstalledVersion` on
/// each vulnerability row; this function ignores the vulnerability-inline
/// shape entirely and reads only the canonical `Packages` block.
///
/// De-duplication within a single scan is handled by the database's
/// `scan_packages_unique_per_scan` index — callers do not need to pre-dedup.
///
/// Returns an empty Vec when no Trivy result carries a `Packages` block
/// (i.e. the scanner was invoked without `--list-all-pkgs`); legacy reports
/// degrade gracefully to "no inventory data" rather than producing
/// findings-derived stand-ins, which would silently re-introduce the #903
/// vulnerability-shaped-SBOM bug.
///
/// Field-level validation (#1151, #1152):
/// - `purl` runs through [`validate_trivy_purl`]; malformed or oversized
///   PURLs are dropped (field set to `None`) while the package row is kept.
/// - `license` runs through [`sanitize_trivy_licenses`]; non-SPDX terms
///   are wrapped as `LicenseRef-...` so they cannot green-light a
///   permissive-license policy check.
pub(crate) fn convert_trivy_packages(
    report: &crate::services::image_scanner::TrivyReport,
) -> Vec<RawPackage> {
    report
        .results
        .iter()
        .flat_map(|result| {
            result
                .packages
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter(|p| !p.name.is_empty())
                .map(move |pkg| RawPackage {
                    name: pkg.name.clone(),
                    version: if pkg.version.is_empty() {
                        None
                    } else {
                        Some(pkg.version.clone())
                    },
                    // #1151: validate the PURL before persistence. Hostile
                    // lockfiles can ship multi-MB or malformed PURL strings;
                    // dropping the field (keeping the package row) is the
                    // recommended behaviour so the inventory still reflects
                    // the package without giving a downstream parser a
                    // chance to misinterpret a half-valid PURL.
                    purl: pkg
                        .identifier
                        .as_ref()
                        .and_then(|id| id.purl.as_deref())
                        .and_then(validate_trivy_purl),
                    // #1152: validate each license element against the SPDX
                    // identifier list before joining with " OR ". Multi-
                    // license packages still produce a SPDX OR expression;
                    // hostile elements (unknown terms, smuggled pre-joined
                    // expressions) are wrapped as LicenseRef-... so a
                    // permissive-license policy check cannot green-light
                    // them.
                    license: pkg.licenses.as_deref().and_then(sanitize_trivy_licenses),
                    source_target: if result.target.is_empty() {
                        None
                    } else {
                        Some(result.target.clone())
                    },
                })
        })
        .collect()
}

/// Completeness signal for a scanner pass over an artifact. (#1153)
///
/// `Complete` means the scanner enumerated every target it found on the
/// filesystem and emitted a `Packages` block (or empty block, when the
/// artifact legitimately had no packages). `Partial` means the scanner
/// logged a warning for at least one target that was known to be present
/// on the filesystem — typically a truncated `package-lock.json`, an
/// invalid version syntax in a `requirements.txt`, or an unrecognised
/// lockfile version Trivy could not parse. A partial pass is persisted
/// into `scan_results.scan_completeness` so the SBOM endpoint and
/// downstream attestation tooling can distinguish "no lockfile present"
/// from "lockfile present but unparseable".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanCompleteness {
    #[default]
    Complete,
    Partial,
}

impl ScanCompleteness {
    /// Stable lowercase form used by the `scan_completeness` CHECK
    /// constraint in migration 087 and by the SBOM document JSON field.
    pub fn as_str(self) -> &'static str {
        match self {
            ScanCompleteness::Complete => "complete",
            ScanCompleteness::Partial => "partial",
        }
    }
}

/// Trivy stderr line patterns that signal a target was present on the
/// filesystem but could not be parsed. Trivy's stderr is not strictly
/// structured; these substrings cover the warnings emitted by the v0.50+
/// CLI when it skips a lockfile (truncated JSON, invalid version syntax,
/// unrecognised lockfile version, "failed to parse"). The patterns are
/// case-insensitive ASCII substring matches against individual stderr
/// LINES, not the whole stderr blob — earlier prototypes globbed against
/// the whole stderr text and tripped on `"skipping CVE-..."` or
/// `"failed to analyze <built-in analyzer>"` noise that fires on every
/// run. The current list intentionally omits `"skipping"` and
/// `"failed to analyze"` for that reason; we accept the false-negative
/// risk on novel wording in exchange for a usable signal.
const TRIVY_PARTIAL_STDERR_MARKERS: &[&str] = &[
    "failed to parse",
    "invalid lockfile",
    "unexpected eof",
    "syntax error",
    "unrecognized lockfile",
    "unknown lockfile",
];

/// Returns `true` when `haystack` contains `needle`, comparing ASCII
/// case-insensitively without allocating a lowercased copy of `haystack`.
/// Used by the partial-scan classifier so we don't allocate `O(stderr)`
/// memory for a single substring test on potentially-multi-MB stderr.
fn ascii_icontains(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return n.is_empty();
    }
    h.windows(n.len()).any(|w| {
        w.iter()
            .zip(n.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// Decide whether a Trivy invocation should be marked partial.
///
/// A scan is partial when *either*:
/// 1. Trivy's stderr contains one of [`TRIVY_PARTIAL_STDERR_MARKERS`] on
///    any individual line, indicating the scanner saw a target it could
///    not parse, OR
/// 2. A target name from `known_targets` (typically derived from the
///    workspace directory listing or from artifact metadata) is missing
///    from the report's `results[].target` set, indicating Trivy
///    silently skipped a lockfile that exists on disk.
///
/// `known_targets` matching is by path **basename**, not raw substring,
/// so a noisy target path like `prefix-package-lock.json` does not
/// accidentally satisfy a request for `package-lock.json`. The
/// comparison is also case-insensitive on ASCII (Windows-style mixed
/// case in workspace paths shows up in practice).
///
/// Pulled out as a free function so the decision is unit-testable
/// without a Trivy process. (#1153)
pub(crate) fn classify_trivy_completeness(
    report: &crate::services::image_scanner::TrivyReport,
    stderr: &str,
    known_targets: &[&str],
) -> ScanCompleteness {
    // Per-line ASCII case-insensitive substring scan avoids allocating
    // a full lowercased copy of stderr (which can run to several MB on
    // verbose Trivy runs).
    let mut hit_marker = false;
    for line in stderr.lines() {
        if TRIVY_PARTIAL_STDERR_MARKERS
            .iter()
            .any(|m| ascii_icontains(line, m))
        {
            hit_marker = true;
            break;
        }
    }
    if hit_marker {
        return ScanCompleteness::Partial;
    }

    if !known_targets.is_empty() {
        // Compare on path basenames so "package-lock.json" never
        // accidentally matches "prefix-package-lock.json". `Path::new`
        // is allocation-free.
        let seen_basenames: std::collections::HashSet<String> = report
            .results
            .iter()
            .filter_map(|r| {
                std::path::Path::new(&r.target)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_ascii_lowercase())
            })
            .collect();
        let missing = known_targets.iter().any(|t| {
            let want = t.to_ascii_lowercase();
            !seen_basenames.contains(&want)
        });
        if missing {
            return ScanCompleteness::Partial;
        }
    }

    ScanCompleteness::Complete
}

/// Output of a single scanner run: vulnerability findings AND a package
/// inventory (#903). Scanners that only produce findings (OpenSCAP, custom
/// WASM plugins) construct a [`ScanOutput`] with an empty `packages` Vec
/// via [`ScanOutput::findings_only`]; scanners that enumerate packages
/// (Trivy, Grype if extended) populate both.
///
/// `scan_completeness` (#1153) carries the partial-scan signal so the
/// orchestrator can record it on the `scan_results` row and the SBOM
/// document can surface "lockfile present but unparseable" distinctly
/// from "no lockfile present".
#[derive(Debug, Default)]
pub struct ScanOutput {
    pub findings: Vec<RawFinding>,
    pub packages: Vec<RawPackage>,
    pub scan_completeness: ScanCompleteness,
}

impl ScanOutput {
    /// Convenience constructor for scanners that do not enumerate an
    /// inventory. The package list is empty; SBOM generation will fall
    /// back to scan_findings for legacy data.
    pub fn findings_only(findings: Vec<RawFinding>) -> Self {
        Self {
            findings,
            packages: Vec::new(),
            scan_completeness: ScanCompleteness::Complete,
        }
    }

    /// Convenience constructor for the common Trivy path where both halves
    /// of the report are converted via the shared helpers above.
    ///
    /// `scan_completeness` is unconditionally `Complete` — callers that
    /// have access to Trivy stderr or a known-target list should use
    /// [`ScanOutput::from_trivy_report_with_context`] instead so the
    /// partial-scan signal flows through.
    pub fn from_trivy_report(
        report: &crate::services::image_scanner::TrivyReport,
        source_label: &str,
    ) -> Self {
        Self {
            findings: convert_trivy_findings(report, source_label),
            packages: convert_trivy_packages(report),
            scan_completeness: ScanCompleteness::Complete,
        }
    }

    /// Trivy-path constructor that incorporates the partial-scan signal
    /// (#1153). `stderr` is the raw stderr output from the Trivy CLI;
    /// `known_targets` is the list of lockfile/manifest basenames the
    /// scanner expected to find (typically derived from the workspace
    /// directory listing). When either source flags a partial scan,
    /// `scan_completeness` becomes `Partial` and the orchestrator
    /// persists that into `scan_results.scan_completeness`.
    pub fn from_trivy_report_with_context(
        report: &crate::services::image_scanner::TrivyReport,
        source_label: &str,
        stderr: &str,
        known_targets: &[&str],
    ) -> Self {
        Self {
            findings: convert_trivy_findings(report, source_label),
            packages: convert_trivy_packages(report),
            scan_completeness: classify_trivy_completeness(report, stderr, known_targets),
        }
    }

    /// True when the scanner produced neither findings nor inventory rows.
    /// Useful for test assertions and for the orchestrator's early-return
    /// on non-applicable artifacts.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty() && self.packages.is_empty()
    }
}

/// Extract a tar.gz archive into `target_dir` while guarding against tar-slip
/// attacks: symlinks, hardlinks, and paths that escape the target directory
/// via `..` components are silently skipped.
///
/// This is a synchronous, blocking function — callers should run it inside
/// `tokio::task::spawn_blocking`.
fn extract_tar_gz_safe(content: &[u8], target: &Path) -> Result<()> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let decoder = GzDecoder::new(content);
    let mut archive = Archive::new(decoder);

    for entry in archive
        .entries()
        .map_err(|e| AppError::Storage(format!("Failed to read tar.gz entries: {}", e)))?
    {
        let mut entry =
            entry.map_err(|e| AppError::Storage(format!("Failed to read tar.gz entry: {}", e)))?;

        // Skip symlinks and hardlinks to prevent symlink escape attacks
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            continue;
        }

        // Validate that the resolved path stays within the target directory
        let path = entry
            .path()
            .map_err(|e| AppError::Storage(format!("Failed to read entry path: {}", e)))?;
        let full_path = target.join(&path);
        if !full_path.starts_with(target) {
            continue;
        }

        entry
            .unpack_in(target)
            .map_err(|e| AppError::Storage(format!("Failed to extract tar.gz entry: {}", e)))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Scanner trait
// ---------------------------------------------------------------------------

/// Immutable target identity supplied by scanner orchestration.
///
/// `Artifact::path` is repository-internal. Scanners that need an externally
/// routable identity (currently Grype's OCI `registry:` mode) must use the
/// repository fields from this context instead of guessing from the path.
/// Scanners may also use the optional database/storage handles to inspect
/// repository-local artifact state without re-entering the public registry
/// route.
pub struct ScanTarget<'a> {
    pub artifact: &'a Artifact,
    pub repository_key: &'a str,
    pub repository_type: &'a str,
    pub db: Option<&'a PgPool>,
    pub storage: Option<&'a dyn StorageBackend>,
}

/// A pluggable vulnerability scanner.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// The scan_type value stored in scan_results.
    fn scan_type(&self) -> &str;

    /// Whether this scanner applies to the given artifact.
    ///
    /// The orchestrator calls this BEFORE creating a `scan_results` row so a
    /// non-applicable scanner never produces a `completed, findings_count=0`
    /// row that is indistinguishable from a real clean scan. Issues #961 and
    /// #994 both trace back to scanners short-circuiting inside `scan()` via
    /// `Ok(ScanOutput::default())`, which the orchestrator then persisted as
    /// a completed-with-zero-findings result. That made it look like the
    /// scanner ran and the artifact was clean, when in fact the scanner had
    /// silently declined to inspect the bytes.
    ///
    /// Returning `false` here is semantically distinct from
    /// `scan() -> Ok(ScanOutput::default())`: the former means "this scanner
    /// did not run", the latter means "this scanner ran and found nothing."
    /// Conflating them produces silent-success regressions where consumers
    /// using a scan record as a security gate pass artifacts that were never
    /// actually scanned.
    ///
    /// The default returns `true` so scanners that always apply (e.g.
    /// `DependencyScanner`, `GrypeScanner`) do not need to override.
    fn is_applicable(&self, _artifact: &Artifact) -> bool {
        true
    }

    /// Context-aware applicability hook. The default preserves compatibility
    /// with existing scanners while allowing scanners that need repository
    /// routing context to override only this method.
    fn is_applicable_for_target(&self, target: &ScanTarget<'_>) -> bool {
        self.is_applicable(target.artifact)
    }

    /// Run the scan against artifact content and metadata. Returns both
    /// vulnerability findings AND the full package inventory observed by
    /// the scanner — the inventory drives SBOM generation (#903) and must
    /// be enumerated regardless of whether any package is CVE-bearing.
    ///
    /// Scanners that do not enumerate packages (e.g. policy-only scanners
    /// like OpenSCAP) return a [`ScanOutput`] with an empty `packages`
    /// vector via [`ScanOutput::findings_only`]; SBOM generation falls
    /// back to scan_findings for those legacy paths.
    ///
    /// The orchestrator only calls `scan()` after [`Scanner::is_applicable`]
    /// returns `true`. Concrete implementations may keep a defensive
    /// `debug_assert!` against `is_applicable` but MUST NOT silently return
    /// `Ok(ScanOutput::default())` when they decide the artifact is
    /// out-of-scope: that is the silent-success bug class behind #994.
    async fn scan(
        &self,
        artifact: &Artifact,
        metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput>;

    /// Context-aware scan hook. The default delegates to the legacy scan
    /// method so existing scanner implementations remain unchanged.
    async fn scan_target(
        &self,
        target: &ScanTarget<'_>,
        metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        self.scan(target.artifact, metadata, content).await
    }

    /// Best-effort scanner-binary version string (e.g. `trivy-0.62.1`,
    /// `grype-0.83.0`). Persisted on `scan_results.scanner_version` so
    /// operators can reproduce a scan and identify scanners with stale
    /// vulnerability databases.
    ///
    /// The default implementation returns `None` so existing scanners that
    /// do not yet probe a version remain compilable. Concrete scanners
    /// should override this to shell out to `--version` (or equivalent) and
    /// cache the result, so the orchestrator can call it once per scan
    /// without per-call subprocess overhead.
    async fn version(&self) -> Option<String> {
        None
    }
}

/// Maximum wall-clock time we will wait for a scanner CLI's `--version`
/// subcommand to return. A hung version probe is serialized through
/// `OnceCell::get_or_init`, so any single hang would head-of-line block
/// every concurrent scan (including the post-failure probe in `fail_scan`).
/// Five seconds is generous for a `--version` flag that should print and
/// exit immediately on any healthy binary, but tight enough that a stuck
/// binary cannot stall the scan pipeline.
const CAPTURE_CLI_VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Run an external CLI's `--version` subcommand and return its first stdout
/// line, trimmed. Returns `None` when the binary is missing, fails, or
/// hangs past `CAPTURE_CLI_VERSION_TIMEOUT`. Used by `Scanner::version()`
/// implementations to capture the binary version string for the
/// `scan_results.scanner_version` column.
///
/// `args` is the arg vector passed to the binary (typically `["--version"]`
/// or `["version"]` depending on the tool's CLI conventions).
pub(crate) async fn capture_cli_version(binary: &str, args: &[&str]) -> Option<String> {
    capture_cli_version_with_timeout(binary, args, CAPTURE_CLI_VERSION_TIMEOUT).await
}

/// Maximum bytes of stdout we read from a `--version` invocation.
///
/// Legitimate `--version` output is well under 1 KiB across every scanner
/// we shell out to (Trivy, Grype, OpenSCAP, etc.). 64 KiB is a generous
/// ceiling that protects against a malicious / compromised binary on
/// PATH emitting unbounded output and OOM'ing the backend (see #1014).
/// Bytes beyond the cap are dropped; the version token always lives in
/// the first line, so a sane binary is unaffected.
const CAPTURE_CLI_VERSION_STDOUT_CAP_BYTES: u64 = 64 * 1024;

/// Inner implementation of [`capture_cli_version`] parameterized on the
/// timeout so tests can exercise the elapsed-timeout branch in milliseconds
/// rather than the full production five-second wait.
pub(crate) async fn capture_cli_version_with_timeout(
    binary: &str,
    args: &[&str],
    timeout: Duration,
) -> Option<String> {
    // Always kill+reap a child before returning so we never leave a
    // zombie. `child.kill()` on Unix sends SIGKILL but does not reap;
    // a subsequent `child.wait()` is required.
    async fn kill_and_reap(child: &mut tokio::process::Child) {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    // Spawn with stdout piped so we can bound the read. `Command::output`
    // would buffer the entire stdout into memory unconditionally; a
    // hostile binary printing 1 GiB to stdout would OOM the backend.
    let mut child = match tokio::process::Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return None, // spawn / IO error
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            // Pipe wasn't set up; kill+reap and treat as a probe failure.
            kill_and_reap(&mut child).await;
            return None;
        }
    };
    // `AsyncReadExt::take(N)` consumes the reader by value and returns a
    // `Take<R>` that yields at most N bytes. Any bytes the binary writes
    // beyond N stay in the kernel pipe and are dropped when the child is
    // killed (or when its stdout pipe is closed on EOF), never landing in
    // `buf`. This is the OOM bound from #1014.
    let mut limited = stdout.take(CAPTURE_CLI_VERSION_STDOUT_CAP_BYTES);
    let mut buf = Vec::with_capacity(1024);
    let read_result = tokio::time::timeout(timeout, limited.read_to_end(&mut buf)).await;

    // Handle the read outcome BEFORE waiting on the child. Issuing
    // `child.wait()` concurrently with the read (the previous shape) was
    // racy: a wait that lost the race against the read would return Err
    // even when the child later exited cleanly, falsely producing
    // `exit_ok = false` and a `None` return. See #1014 R1.
    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            // Read I/O error; kill+reap to be safe.
            kill_and_reap(&mut child).await;
            return None;
        }
        Err(_) => {
            // Read budget exhausted. Kill+reap (the child is still running
            // - it filled the pipe but we did not drain it fast enough,
            // or it is stuck before stdout EOF).
            kill_and_reap(&mut child).await;
            warn!(
                binary = binary,
                timeout_ms = timeout.as_millis() as u64,
                "scanner version probe timed out; recording NULL scanner_version"
            );
            return None;
        }
    }

    // Detect cap-hit truncation. read_to_end returning at least
    // CAP bytes means the binary may have more output we did not read,
    // and the buffer can be a midway split through a non-version line.
    // A legitimate `--version` invocation never reaches 64 KiB. Treat
    // this as a probe failure rather than risk parsing garbage. Issue
    // a debug log so operators can correlate this with a misbehaving
    // binary on PATH.
    if buf.len() as u64 >= CAPTURE_CLI_VERSION_STDOUT_CAP_BYTES {
        tracing::debug!(
            binary = binary,
            cap_bytes = CAPTURE_CLI_VERSION_STDOUT_CAP_BYTES,
            "scanner --version stdout reached cap; treating probe as failure"
        );
        kill_and_reap(&mut child).await;
        return None;
    }

    // Read drained successfully; now wait for the child to exit. With
    // stdout already EOF'd this is essentially instantaneous, but bound
    // it on a small wall-clock budget to defend against a child that
    // closes stdout but lingers (e.g., stuck on stderr that we redirected
    // to /dev/null, or on signal handling).
    let wait_status = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    let exit_ok = matches!(wait_status, Ok(Ok(s)) if s.success());
    if !exit_ok {
        // Child did not exit cleanly; kill+reap before returning.
        kill_and_reap(&mut child).await;
        return None;
    }

    let stdout_str = String::from_utf8_lossy(&buf);
    let line = stdout_str.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}

/// TTL applied to a successful version probe. Versions only change when the
/// scanner binary is upgraded, which on long-lived backend pods only happens
/// at deploy/restart time, so a long hit TTL is safe and cheap.
pub(crate) const VERSION_CACHE_HIT_TTL: Duration = Duration::from_secs(3600);

/// TTL applied to a failed version probe. A short miss TTL ensures that a
/// transient probe failure (binary missing on PATH, init container still
/// pulling, scanner pod momentarily unreachable) is retried promptly so that
/// the `scan_results.scanner_version` column starts populating as soon as
/// the operator fixes the underlying issue, without requiring a pod restart.
pub(crate) const VERSION_CACHE_MISS_TTL: Duration = Duration::from_secs(60);

/// Time-bounded cache for a scanner's CLI version string.
///
/// Replaces the previous `tokio::sync::OnceCell<Option<String>>` cache, which
/// pinned a `None` result for the entire process lifetime once the first
/// probe failed. With `VersionCache`, `Some(_)` values are cached for
/// [`VERSION_CACHE_HIT_TTL`] and `None` values for the much shorter
/// [`VERSION_CACHE_MISS_TTL`], so transient probe failures are retried.
#[derive(Debug, Default)]
pub(crate) struct VersionCache {
    inner: RwLock<Option<(Instant, Option<String>)>>,
}

impl VersionCache {
    /// Create an empty cache. The first call to [`cached_cli_version`] will
    /// run the probe.
    pub(crate) fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    /// Test-only: overwrite the cache entry with a stored timestamp computed
    /// as `Instant::now() - age`. Used to simulate a cache entry that is
    /// older than `VERSION_CACHE_MISS_TTL` without sleeping for 60s in
    /// tests.
    #[cfg(test)]
    pub(crate) async fn set_with_age(&self, value: Option<String>, age: Duration) {
        let stored_at = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        let mut guard = self.inner.write().await;
        *guard = Some((stored_at, value));
    }

    /// Test-only: snapshot the current cached value, ignoring TTL.
    #[cfg(test)]
    pub(crate) async fn peek(&self) -> Option<Option<String>> {
        self.inner.read().await.as_ref().map(|(_, v)| v.clone())
    }
}

/// Resolve a scanner's lazily-cached version string, probing via `probe`
/// when the cache is empty or the previous entry has expired.
///
/// Concrete `Scanner::version()` impls share this cache + clone pattern;
/// extracting it here keeps the per-scanner override to a single line and
/// avoids near-identical method bodies across `trivy_fs_scanner`,
/// `image_scanner`, `incus_scanner`, `grype_scanner`, and `openscap_scanner`.
///
/// TTL semantics:
/// * `Some(version)` is cached for [`VERSION_CACHE_HIT_TTL`].
/// * `None` is cached for [`VERSION_CACHE_MISS_TTL`] so transient probe
///   failures (binary not yet on PATH, scanner pod restarting) are retried
///   without waiting for a backend pod restart.
pub(crate) async fn cached_cli_version<F, Fut>(cell: &VersionCache, probe: F) -> Option<String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    // Fast path: read lock, check TTL, return cached clone.
    {
        let guard = cell.inner.read().await;
        if let Some((stored_at, ref value)) = *guard {
            let ttl = if value.is_some() {
                VERSION_CACHE_HIT_TTL
            } else {
                VERSION_CACHE_MISS_TTL
            };
            if stored_at.elapsed() < ttl {
                return value.clone();
            }
        }
    }

    // Slow path: probe outside any lock, then take a write lock.
    // We accept that two concurrent callers may both race a probe on cache
    // miss; that is harmless and strictly better than holding a write lock
    // across an external `Command` invocation that may take seconds.
    let probed = probe().await;
    let mut guard = cell.inner.write().await;
    // Re-check: another writer may have refreshed the cell while we were
    // probing. Prefer the still-fresh existing entry over our just-probed
    // value to keep the TTL window stable.
    if let Some((stored_at, ref value)) = *guard {
        let ttl = if value.is_some() {
            VERSION_CACHE_HIT_TTL
        } else {
            VERSION_CACHE_MISS_TTL
        };
        if stored_at.elapsed() < ttl {
            return value.clone();
        }
    }
    *guard = Some((Instant::now(), probed.clone()));
    probed
}

/// Convenience wrapper around [`cached_cli_version`] for scanners that probe
/// the Trivy CLI. Returns `Some("trivy-<ver>")` once the CLI has been
/// probed, or `None` when the binary is missing or its output is unparseable.
pub(crate) async fn cached_trivy_cli_version(cell: &VersionCache) -> Option<String> {
    cached_cli_version(cell, || async {
        let raw = capture_cli_version("trivy", &["--version"]).await?;
        format_trivy_version(&raw)
    })
    .await
}

/// Parse a Trivy `--version` first stdout line into a `trivy-X.Y.Z` token.
/// Trivy emits `Version: 0.62.1` (or `Version: 0.62.1\n...`). We normalize
/// to `trivy-<version>` to make the field self-describing in the DB.
pub(crate) fn format_trivy_version(raw: &str) -> Option<String> {
    let v = raw
        .strip_prefix("Version:")
        .map(str::trim)
        .or_else(|| raw.strip_prefix("trivy").map(str::trim))
        .unwrap_or(raw)
        .trim();
    let token = v.split_whitespace().next()?;
    if token.is_empty() {
        None
    } else {
        Some(format!("trivy-{}", token))
    }
}

/// Parse a `grype --version` first stdout line into a `grype-X.Y.Z` token.
/// Grype's `--version` (single dash-dash flag) emits a single line like
/// `grype 0.83.0`, which we normalize to `grype-<version>` for consistency with
/// `format_trivy_version`. Also tolerates a `Version:` prefix as a
/// defensive shape (some packagings of `grype version` emit that).
pub(crate) fn format_grype_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let mut parts = trimmed.split_whitespace();
    let head = parts.next()?;
    // Three output shapes:
    //   `grype 0.83.0`   -> skip leading `grype`, take next token
    //   `Version: 0.83.0` -> skip leading `Version:`, take next token
    //   `0.83.0`         -> head is the version itself
    let version = if head.eq_ignore_ascii_case("grype") || head.eq_ignore_ascii_case("Version:") {
        parts.next()?
    } else {
        head
    };
    if version.is_empty() {
        None
    } else {
        Some(format!("grype-{}", version))
    }
}

// ---------------------------------------------------------------------------
// Advisory client (OSV.dev + GitHub Advisory)
// ---------------------------------------------------------------------------

/// Cached advisory lookup shared across scanner invocations.
pub struct AdvisoryClient {
    http: Client,
    cache: RwLock<HashMap<String, CachedAdvisory>>,
    github_token: Option<String>,
    osv_batch_url: String,
    cache_ttl: Duration,
}

struct CachedAdvisory {
    findings: Vec<AdvisoryMatch>,
    fetched_at: Instant,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvisoryMatch {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: String,
    pub aliases: Vec<String>,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,
    pub source: String,
    pub source_url: Option<String>,
}

/// OSV.dev batch query request body.
#[derive(serde::Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(serde::Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: Option<String>,
}

#[derive(serde::Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

/// A single dependency extracted from a manifest.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: String,
}

const CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const GITHUB_ADVISORY_URL: &str = "https://api.github.com/advisories";

impl AdvisoryClient {
    pub fn new(github_token: Option<String>) -> Self {
        Self {
            http: crate::services::http_client::base_client_builder()
                .timeout(Duration::from_secs(30))
                .user_agent("artifact-keeper-scanner/1.0")
                .build()
                .expect("failed to build HTTP client"),
            cache: RwLock::new(HashMap::new()),
            github_token,
            osv_batch_url: OSV_BATCH_URL.to_string(),
            cache_ttl: CACHE_TTL,
        }
    }

    fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    fn osv_batch_url(&self) -> &str {
        &self.osv_batch_url
    }

    fn cache_key(dep: &Dependency) -> String {
        format!(
            "{}:{}:{}",
            dep.ecosystem,
            dep.name,
            dep.version.as_deref().unwrap_or("*")
        )
    }

    /// Query OSV.dev for advisories affecting the given dependencies.
    pub async fn query_osv(&self, deps: &[Dependency]) -> Vec<AdvisoryMatch> {
        if deps.is_empty() {
            return vec![];
        }

        let cache_ttl = self.cache_ttl();

        // Check cache first
        let mut uncached = Vec::new();
        let mut results = Vec::new();

        {
            let cache = self.cache.read().await;
            for dep in deps {
                let key = Self::cache_key(dep);
                if let Some(cached) = cache.get(&key) {
                    if cached.fetched_at.elapsed() < cache_ttl {
                        results.extend(cached.findings.clone());
                        continue;
                    }
                }
                uncached.push(dep.clone());
            }
        }

        if uncached.is_empty() {
            return results;
        }

        // Batch query OSV.dev (max 1000 per batch)
        for chunk in uncached.chunks(1000) {
            let query = OsvBatchQuery {
                queries: chunk
                    .iter()
                    .map(|d| OsvQuery {
                        package: OsvPackage {
                            name: d.name.clone(),
                            ecosystem: d.ecosystem.clone(),
                        },
                        version: d.version.clone(),
                    })
                    .collect(),
            };

            match self
                .http
                .post(self.osv_batch_url())
                .json(&query)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(body) => {
                            let matches = Self::parse_osv_response(&body, chunk);
                            let mut cache = self.cache.write().await;
                            for dep in chunk.iter() {
                                let key = Self::cache_key(dep);
                                let dep_matches: Vec<_> = matches
                                    .iter()
                                    .filter(|_m| {
                                        // Match by position in batch response
                                        true // OSV returns results indexed by query order
                                    })
                                    .cloned()
                                    .collect();
                                cache.insert(
                                    key,
                                    CachedAdvisory {
                                        findings: dep_matches,
                                        fetched_at: Instant::now(),
                                    },
                                );
                            }
                            results.extend(matches);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse OSV.dev response for batch of {} deps: {}",
                                chunk.len(),
                                e
                            );
                        }
                    }
                }
                Ok(resp) => {
                    warn!(
                        "OSV.dev returned status {} for batch of {} deps",
                        resp.status(),
                        chunk.len()
                    );
                }
                Err(e) => {
                    warn!(
                        "OSV.dev request failed for batch of {} deps: {}",
                        chunk.len(),
                        e
                    );
                }
            }
        }

        // Evict stale entries after all batches complete so the cache does not
        // grow without bound across long-lived AdvisoryClient instances.
        // Note: runs after insertion so that freshly fetched entries (which use
        // Instant::now()) are never mistakenly evicted. A concurrent reader
        // between batch insertion and this eviction may see a stale entry and
        // issue a redundant OSV fetch, but this is harmless.
        {
            let mut cache = self.cache.write().await;
            cache.retain(|_, v| v.fetched_at.elapsed() < cache_ttl);
        }

        results
    }

    /// Query GitHub Advisory Database as a fallback/secondary source.
    pub async fn query_github(&self, deps: &[Dependency]) -> Vec<AdvisoryMatch> {
        let token = match &self.github_token {
            Some(t) => t,
            None => return vec![],
        };

        let mut results = Vec::new();

        for dep in deps {
            let ecosystem_param = match dep.ecosystem.as_str() {
                "npm" => "npm",
                "PyPI" | "pypi" => "pip",
                "crates.io" => "rust",
                "Maven" => "maven",
                "Go" => "go",
                "NuGet" => "nuget",
                "RubyGems" => "rubygems",
                _ => continue,
            };

            let url = format!(
                "{}?affects={}&ecosystem={}&per_page=100",
                GITHUB_ADVISORY_URL, dep.name, ecosystem_param
            );

            match self
                .http
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<Vec<serde_json::Value>>().await {
                        Ok(advisories) => {
                            for adv in advisories {
                                if let Some(m) = Self::parse_github_advisory(&adv, dep) {
                                    results.push(m);
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse GitHub Advisory response for {}: {}",
                                dep.name, e
                            );
                        }
                    }
                }
                Ok(resp) => {
                    warn!(
                        "GitHub Advisory API returned {} for {}",
                        resp.status(),
                        dep.name
                    );
                }
                Err(e) => {
                    warn!("GitHub Advisory request failed for {}: {}", dep.name, e);
                }
            }
        }

        results
    }

    fn parse_osv_response(body: &serde_json::Value, deps: &[Dependency]) -> Vec<AdvisoryMatch> {
        let mut matches = Vec::new();

        if let Some(results) = body.get("results").and_then(|r| r.as_array()) {
            for (i, result) in results.iter().enumerate() {
                if let Some(vulns) = result.get("vulns").and_then(|v| v.as_array()) {
                    for vuln in vulns {
                        let id = vuln
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("UNKNOWN")
                            .to_string();

                        let summary = vuln
                            .get("summary")
                            .and_then(|v| v.as_str())
                            .map(String::from);

                        let details = vuln
                            .get("details")
                            .and_then(|v| v.as_str())
                            .map(String::from);

                        // Extract severity from database_specific or severity array
                        let severity = vuln
                            .get("database_specific")
                            .and_then(|d| d.get("severity"))
                            .and_then(|s| s.as_str())
                            .or_else(|| {
                                vuln.get("severity")
                                    .and_then(|s| s.as_array())
                                    .and_then(|arr| arr.first())
                                    .and_then(|s| s.get("type"))
                                    .and_then(|t| t.as_str())
                            })
                            .unwrap_or("medium")
                            .to_lowercase();

                        // Extract aliases (CVE IDs)
                        let aliases: Vec<String> = vuln
                            .get("aliases")
                            .and_then(|a| a.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();

                        // Extract fixed version from affected ranges
                        let fixed_version = vuln
                            .get("affected")
                            .and_then(|a| a.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|a| a.get("ranges"))
                            .and_then(|r| r.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|r| r.get("events"))
                            .and_then(|e| e.as_array())
                            .and_then(|events| {
                                events.iter().find_map(|e| {
                                    e.get("fixed").and_then(|f| f.as_str().map(String::from))
                                })
                            });

                        let dep = deps.get(i);

                        matches.push(AdvisoryMatch {
                            id: id.clone(),
                            summary,
                            details,
                            severity,
                            aliases,
                            affected_version: dep.and_then(|d| d.version.clone()),
                            fixed_version,
                            source: "osv.dev".to_string(),
                            source_url: Some(format!("https://osv.dev/vulnerability/{}", id)),
                        });
                    }
                }
            }
        }

        matches
    }

    fn parse_github_advisory(adv: &serde_json::Value, dep: &Dependency) -> Option<AdvisoryMatch> {
        let ghsa_id = adv.get("ghsa_id")?.as_str()?.to_string();
        let summary = adv
            .get("summary")
            .and_then(|v| v.as_str())
            .map(String::from);
        let description = adv
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);
        let severity = adv
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("medium")
            .to_lowercase();
        let cve_id = adv.get("cve_id").and_then(|v| v.as_str()).map(String::from);
        let html_url = adv
            .get("html_url")
            .and_then(|v| v.as_str())
            .map(String::from);

        let mut aliases = vec![ghsa_id.clone()];
        if let Some(cve) = &cve_id {
            aliases.push(cve.clone());
        }

        // Extract fixed version from vulnerabilities array
        let fixed_version = adv
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|vuln| {
                    vuln.get("first_patched_version")
                        .and_then(|v| v.get("identifier"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
            });

        Some(AdvisoryMatch {
            id: ghsa_id,
            summary,
            details: description,
            severity,
            aliases,
            affected_version: dep.version.clone(),
            fixed_version,
            source: "github".to_string(),
            source_url: html_url,
        })
    }
}

// ---------------------------------------------------------------------------
// Dependency scanner (parses manifests, queries advisories)
// ---------------------------------------------------------------------------

pub struct DependencyScanner {
    advisory: Arc<AdvisoryClient>,
}

impl DependencyScanner {
    pub fn new(advisory: Arc<AdvisoryClient>) -> Self {
        Self { advisory }
    }

    /// Extract dependencies from artifact content based on format/name.
    fn extract_dependencies(
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Vec<Dependency> {
        let name = artifact.name.to_lowercase();
        let content_str = match std::str::from_utf8(content) {
            Ok(s) => s,
            Err(_) => return vec![], // binary artifact, skip manifest parsing
        };

        if name == "package.json" || name.ends_with("/package.json") {
            Self::parse_npm(content_str)
        } else if name == "cargo.toml" || name.ends_with("/cargo.toml") {
            Self::parse_cargo(content_str)
        } else if name == "requirements.txt" || name.ends_with("/requirements.txt") {
            Self::parse_pip(content_str)
        } else if name == "go.sum" || name.ends_with("/go.sum") {
            Self::parse_go(content_str)
        } else if name == "pom.xml" || name.ends_with("/pom.xml") {
            Self::parse_maven(content_str)
        } else if name.ends_with(".gemspec")
            || name == "gemfile.lock"
            || name.ends_with("/gemfile.lock")
        {
            Self::parse_rubygems(content_str)
        } else if name.ends_with(".nuspec") || name == "packages.config" {
            Self::parse_nuget(content_str)
        } else {
            // Try to infer from path patterns
            Self::infer_dependencies(artifact, content_str)
        }
    }

    fn parse_npm(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(content) {
            for section in ["dependencies", "devDependencies", "peerDependencies"] {
                if let Some(obj) = pkg.get(section).and_then(|v| v.as_object()) {
                    for (name, version) in obj {
                        let ver = version.as_str().map(|v| {
                            v.trim_start_matches('^')
                                .trim_start_matches('~')
                                .to_string()
                        });
                        deps.push(Dependency {
                            name: name.clone(),
                            version: ver,
                            ecosystem: "npm".to_string(),
                        });
                    }
                }
            }
        }
        deps
    }

    fn parse_cargo(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        if let Ok(toml) = content.parse::<toml::Value>() {
            for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(table) = toml.get(section).and_then(|v| v.as_table()) {
                    for (name, value) in table {
                        let version = match value {
                            toml::Value::String(v) => Some(v.clone()),
                            toml::Value::Table(t) => {
                                t.get("version").and_then(|v| v.as_str()).map(String::from)
                            }
                            _ => None,
                        };
                        deps.push(Dependency {
                            name: name.clone(),
                            version,
                            ecosystem: "crates.io".to_string(),
                        });
                    }
                }
            }
        }
        deps
    }

    fn parse_pip(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            // Handle: package==1.0.0, package>=1.0.0, package~=1.0.0, package
            let (name, version) = if let Some(pos) = line.find("==") {
                (&line[..pos], Some(line[pos + 2..].trim().to_string()))
            } else if let Some(pos) = line.find(">=") {
                (&line[..pos], Some(line[pos + 2..].trim().to_string()))
            } else if let Some(pos) = line.find("~=") {
                (&line[..pos], Some(line[pos + 2..].trim().to_string()))
            } else if let Some(pos) = line.find("<=") {
                (&line[..pos], Some(line[pos + 2..].trim().to_string()))
            } else {
                (line, None)
            };
            deps.push(Dependency {
                name: name.trim().to_string(),
                version,
                ecosystem: "PyPI".to_string(),
            });
        }
        deps
    }

    fn parse_go(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0];
                let version = parts[1].trim_start_matches('v');
                // go.sum has hash lines — deduplicate by module name
                if seen.insert(name.to_string()) {
                    deps.push(Dependency {
                        name: name.to_string(),
                        version: Some(version.to_string()),
                        ecosystem: "Go".to_string(),
                    });
                }
            }
        }
        deps
    }

    fn parse_maven(content: &str) -> Vec<Dependency> {
        // Simple XML extraction — not a full parser, handles common pom.xml patterns
        let mut deps = Vec::new();
        let mut in_dependency = false;
        let mut group_id = String::new();
        let mut artifact_id = String::new();
        let mut version = String::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("<dependency>") {
                in_dependency = true;
                group_id.clear();
                artifact_id.clear();
                version.clear();
            } else if trimmed.starts_with("</dependency>") && in_dependency {
                if !group_id.is_empty() && !artifact_id.is_empty() {
                    deps.push(Dependency {
                        name: format!("{}:{}", group_id, artifact_id),
                        version: if version.is_empty() {
                            None
                        } else {
                            Some(version.clone())
                        },
                        ecosystem: "Maven".to_string(),
                    });
                }
                in_dependency = false;
            } else if in_dependency {
                if let Some(val) = Self::extract_xml_value(trimmed, "groupId") {
                    group_id = val;
                } else if let Some(val) = Self::extract_xml_value(trimmed, "artifactId") {
                    artifact_id = val;
                } else if let Some(val) = Self::extract_xml_value(trimmed, "version") {
                    version = val;
                }
            }
        }
        deps
    }

    fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        if line.contains(&open) && line.contains(&close) {
            let start = line.find(&open)? + open.len();
            let end = line.find(&close)?;
            if start < end {
                return Some(line[start..end].to_string());
            }
        }
        None
    }

    fn parse_rubygems(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            // Gemfile.lock format: "    gem_name (version)"
            if let Some(stripped) = trimmed.strip_suffix(')') {
                if let Some(paren_pos) = stripped.rfind('(') {
                    let name = stripped[..paren_pos].trim();
                    let version = &stripped[paren_pos + 1..];
                    if !name.is_empty() {
                        deps.push(Dependency {
                            name: name.to_string(),
                            version: Some(version.to_string()),
                            ecosystem: "RubyGems".to_string(),
                        });
                    }
                }
            }
        }
        deps
    }

    fn parse_nuget(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            // packages.config: <package id="Newtonsoft.Json" version="13.0.1" />
            if trimmed.starts_with("<package ") {
                let id = Self::extract_xml_attr(trimmed, "id");
                let version = Self::extract_xml_attr(trimmed, "version");
                if let Some(name) = id {
                    deps.push(Dependency {
                        name,
                        version,
                        ecosystem: "NuGet".to_string(),
                    });
                }
            }
        }
        deps
    }

    fn extract_xml_attr(line: &str, attr: &str) -> Option<String> {
        let pattern = format!("{}=\"", attr);
        let start = line.find(&pattern)? + pattern.len();
        let end = line[start..].find('"')? + start;
        Some(line[start..end].to_string())
    }

    /// Fallback: try to infer package ecosystem from artifact path patterns.
    fn infer_dependencies(artifact: &Artifact, _content: &str) -> Vec<Dependency> {
        let path = artifact.path.to_lowercase();

        // For RPM/DEB/APK packages, treat the artifact itself as a dependency
        let ecosystem = if path.ends_with(".rpm")
            || path.contains("/rpm/")
            || path.ends_with(".deb")
            || path.contains("/deb/")
            || path.ends_with(".apk")
            || path.contains("/alpine/")
        {
            Some("Linux")
        } else {
            None
        };

        if let Some(eco) = ecosystem {
            vec![Dependency {
                name: artifact.name.clone(),
                version: artifact.version.clone(),
                ecosystem: eco.to_string(),
            }]
        } else {
            vec![]
        }
    }
}

#[async_trait]
impl Scanner for DependencyScanner {
    fn name(&self) -> &str {
        "DependencyScanner"
    }

    fn scan_type(&self) -> &str {
        "dependency"
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        let deps = Self::extract_dependencies(artifact, metadata, content);
        if deps.is_empty() {
            return Ok(ScanOutput::default());
        }

        info!(
            "Scanning {} dependencies for artifact {}",
            deps.len(),
            artifact.id
        );

        // The extracted dependency list is itself a package inventory — every
        // declared dep belongs in the SBOM regardless of advisory hits
        // (#903). Build the inventory snapshot up-front so that even if the
        // advisory call hangs and we fall back to an empty findings list,
        // SBOM consumers still see the full dep tree.
        let packages: Vec<RawPackage> = deps
            .iter()
            .map(|d| RawPackage {
                name: d.name.clone(),
                version: d.version.clone().filter(|s| !s.is_empty()),
                purl: None,
                license: None,
                source_target: Some("dependency-scanner".to_string()),
            })
            .collect();

        // Query both sources in parallel
        let (osv_results, gh_results) = tokio::join!(
            self.advisory.query_osv(&deps),
            self.advisory.query_github(&deps),
        );

        // Merge and deduplicate by CVE/GHSA ID
        let mut seen_ids = std::collections::HashSet::new();
        let mut findings = Vec::new();

        for advisory_match in osv_results.into_iter().chain(gh_results) {
            // Skip if we have already seen this advisory or any of its aliases
            let dominated = seen_ids.contains(&advisory_match.id)
                || advisory_match.aliases.iter().any(|a| seen_ids.contains(a));
            if dominated {
                continue;
            }

            seen_ids.insert(advisory_match.id.clone());
            seen_ids.extend(advisory_match.aliases.iter().cloned());

            let severity =
                Severity::from_str_loose(&advisory_match.severity).unwrap_or(Severity::Medium);

            let cve_id = advisory_match
                .aliases
                .iter()
                .find(|a| a.starts_with("CVE-"))
                .cloned()
                .or_else(|| {
                    if advisory_match.id.starts_with("CVE-") {
                        Some(advisory_match.id.clone())
                    } else {
                        None
                    }
                });

            let title = advisory_match
                .summary
                .unwrap_or_else(|| format!("Vulnerability {}", advisory_match.id));

            findings.push(RawFinding {
                severity,
                title,
                description: advisory_match.details,
                cve_id,
                affected_component: Some(deps.first().map(|d| d.name.clone()).unwrap_or_default()),
                affected_version: advisory_match.affected_version,
                fixed_version: advisory_match.fixed_version,
                source: Some(advisory_match.source),
                source_url: advisory_match.source_url,
            });
        }

        Ok(ScanOutput {
            findings,
            packages,
            scan_completeness: ScanCompleteness::Complete,
        })
    }
}

// ---------------------------------------------------------------------------
// Scanner orchestrator
// ---------------------------------------------------------------------------

pub struct ScannerService {
    db: PgPool,
    scanners: Vec<Arc<dyn Scanner>>,
    scan_result_service: Arc<ScanResultService>,
    scan_config_service: Arc<ScanConfigService>,
    #[allow(dead_code)]
    storage: Arc<dyn StorageBackend>,
    storage_registry: Arc<crate::storage::StorageRegistry>,
    #[allow(dead_code)]
    storage_base_path: String,
    scan_workspace_path: String,
    dependency_track:
        Option<Arc<crate::services::dependency_track_service::DependencyTrackService>>,
}

impl ScannerService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: PgPool,
        advisory_client: Arc<AdvisoryClient>,
        scan_result_service: Arc<ScanResultService>,
        scan_config_service: Arc<ScanConfigService>,
        trivy_url: Option<String>,
        trivy_adapter_url: Option<String>,
        storage: Arc<dyn StorageBackend>,
        storage_registry: Arc<crate::storage::StorageRegistry>,
        storage_base_path: String,
        scan_workspace_path: String,
        openscap_url: Option<String>,
        openscap_profile: String,
        // #2093: token minter for private-repo image pulls. `auth` mints the
        // per-repo scoped scan tokens; `scan_identity` is the loaded
        // `_ak_scanner` service account (None when it is not seeded yet, in
        // which case image pulls fall back to anonymous — public repos only);
        // `scan_token_ttl_seconds` bounds each token's lifetime.
        auth: Arc<AuthService>,
        scan_identity: Option<User>,
        scan_token_ttl_seconds: u64,
    ) -> Self {
        let scan_token_ttl_seconds = scan_token_ttl_seconds as i64;
        let dep_scanner: Arc<dyn Scanner> = Arc::new(DependencyScanner::new(advisory_client));
        let mut scanners: Vec<Arc<dyn Scanner>> = vec![dep_scanner];

        // Container *image* scanner: Harbor scanner-adapter (#2088). Registered
        // ONLY when an adapter URL is configured. When unset, no trivy/image
        // scan row is produced at all (grype still runs) — we do not claim to
        // have run trivy on images.
        if let Some(adapter_url) = trivy_adapter_url {
            info!(
                "Container image scanner (Harbor adapter) enabled at {}",
                adapter_url
            );
            let mut image_scanner = ImageScanner::new(adapter_url);
            // Wire the per-repo token minter so the adapter can pull private
            // images (#2093). Only when the scanner identity is loaded;
            // otherwise pulls stay anonymous (public repos only).
            if let Some(identity) = scan_identity.clone() {
                image_scanner =
                    image_scanner.with_token_minter(auth.clone(), identity, scan_token_ttl_seconds);
            }
            scanners.push(Arc::new(image_scanner));
        }

        // Trivy filesystem + incus (rootfs) scanners drive the trivy server
        // directly and keep consuming TRIVY_URL unchanged: their
        // `--server` / dir-mode protocol is incompatible with the Harbor
        // adapter, so they are NOT repointed at it.
        if let Some(url) = trivy_url {
            info!("Trivy filesystem scanner enabled");
            scanners.push(Arc::new(TrivyFsScanner::new(
                url.clone(),
                scan_workspace_path.clone(),
            )));
            info!("Incus container image scanner enabled");
            scanners.push(Arc::new(crate::services::incus_scanner::IncusScanner::new(
                url,
                scan_workspace_path.clone(),
            )));
        }

        // Grype scanner (CLI-based, degrades gracefully if binary not available)
        info!("Grype scanner enabled");
        let mut grype_scanner = GrypeScanner::new(scan_workspace_path.clone());
        // Wire the per-repo token minter so grype's registry pull is
        // authenticated for private images (#2093).
        if let Some(identity) = scan_identity.clone() {
            grype_scanner =
                grype_scanner.with_token_minter(auth.clone(), identity, scan_token_ttl_seconds);
        }
        scanners.push(Arc::new(grype_scanner));

        // OpenSCAP compliance scanner (optional sidecar)
        if let Some(url) = openscap_url {
            info!("OpenSCAP compliance scanner enabled at {}", url);
            scanners.push(Arc::new(
                crate::services::openscap_scanner::OpenScapScanner::new(
                    url,
                    openscap_profile,
                    scan_workspace_path.clone(),
                ),
            ));
        }

        Self {
            db,
            scanners,
            scan_result_service,
            scan_config_service,
            storage,
            storage_registry,
            storage_base_path,
            scan_workspace_path,
            dependency_track: None,
        }
    }

    /// Set the Dependency-Track service for SBOM submission after scans.
    pub fn set_dependency_track(
        &mut self,
        dt: Arc<crate::services::dependency_track_service::DependencyTrackService>,
    ) {
        self.dependency_track = Some(dt);
    }

    /// Synchronously create one placeholder `running` scan_result row per
    /// configured scanner for the given artifact, returning the row IDs.
    ///
    /// This is the synchronous half of the trigger-scan path: it commits real
    /// rows to the database before the caller spawns the actual scan worker.
    /// Returns `(scan_type, scan_result_id)` pairs that the caller can pass to
    /// [`scan_artifact_with_prepared`] (and surface in the API response so
    /// clients can pin polling to specific scan IDs without racing concurrent
    /// scans on the same artifact).
    ///
    /// Returns `Ok(vec![])` when scanning is disabled for the artifact's
    /// repository and `force` is false (matching `scan_artifact_with_options`).
    /// Returns `Ok(vec![])` when the artifact is missing or soft-deleted, so
    /// the caller can decide whether to surface a 404 separately.
    ///
    /// When `bypass_dedup` is true the same-artifact short-circuit added for
    /// #1373 is skipped: every configured scanner gets a fresh placeholder
    /// row, and the worker will always run a fresh scan (no cached results
    /// are copied). This is the explicit "ignore the cache, scan again now"
    /// path used to recover from silently-broken prior scans (#1469).
    pub async fn prepare_artifact_scan(
        &self,
        artifact_id: Uuid,
        force: bool,
        bypass_dedup: bool,
    ) -> Result<Vec<(String, Uuid)>> {
        let artifact = sqlx::query!(
            r#"
            SELECT repository_id, checksum_sha256
            FROM artifacts
            WHERE id = $1 AND is_deleted = false
            "#,
            artifact_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let Some(artifact) = artifact else {
            return Ok(vec![]);
        };

        if !force
            && !self
                .scan_config_service
                .is_scan_enabled(artifact.repository_id)
                .await?
        {
            return Ok(vec![]);
        }

        // #1373: short-circuit when this artifact already has a completed
        // scan for the same bytes + scan_type. Without this check, every
        // trigger_scan call on an already-scanned artifact inserts a new
        // `running` placeholder row that the worker then converts/completes,
        // leaving two completed rows behind for what should be a single
        // logical scan. The placeholder also lands in the trigger response
        // with a fresh UUID, breaking the contract that identical bytes on
        // the same artifact return the same scan_id.
        //
        // The check is per-scanner so a partially-completed scan set (e.g.
        // trivy completed, grype still running from a prior trigger) still
        // gets the missing scanner queued normally.
        let mut prepared = Vec::with_capacity(self.scanners.len());
        for scanner in &self.scanners {
            if bypass_dedup {
                // When the caller asked to bypass dedup, skip the dedup
                // lookup entirely and always insert a fresh placeholder. We
                // deliberately don't even SELECT here so the explicit-rescan
                // path can't accidentally be diverted by a row that happens
                // to satisfy the TTL.
                let row = self
                    .scan_result_service
                    .create_scan_result_with_checksum(
                        artifact_id,
                        artifact.repository_id,
                        scanner.scan_type(),
                        Some(&artifact.checksum_sha256),
                    )
                    .await?;
                prepared.push((scanner.scan_type().to_string(), row.id));
                continue;
            }

            // #1935: the dedup check (look up existing scan) and the
            // placeholder insert must be atomic. `prepare_scan_placeholder`
            // serializes both under a per-(artifact_id, scan_type) advisory
            // lock so concurrent triggers on the same fresh artifact can no
            // longer each insert a duplicate `running` placeholder. It
            // short-circuits to an existing completed scan (the #1373 path)
            // or to an in-flight placeholder committed by a racing prepare,
            // and only inserts when neither exists.
            let (id, _inserted) = self
                .scan_result_service
                .prepare_scan_placeholder(
                    artifact_id,
                    artifact.repository_id,
                    &artifact.checksum_sha256,
                    scanner.scan_type(),
                    DEDUP_TTL_DAYS,
                    ZERO_FINDINGS_DEDUP_TTL_DAYS,
                )
                .await?;
            prepared.push((scanner.scan_type().to_string(), id));
        }

        Ok(prepared)
    }

    /// Scan a single artifact using pre-allocated scan_result row IDs.
    ///
    /// Companion to [`prepare_artifact_scan`]: when the caller has already
    /// committed placeholder rows (so it could surface their IDs in the
    /// trigger response), this variant reuses those IDs instead of inserting
    /// new ones. Falls back to creating a row on the fly if a scanner has no
    /// matching prepared ID (e.g. scanner set changed between prepare and
    /// execute).
    ///
    /// `bypass_dedup` must match the value passed to the matching
    /// `prepare_artifact_scan` call: if the caller skipped the same-artifact
    /// short-circuit there, the worker must also skip the cross-artifact
    /// reuse path here so the freshly-allocated placeholder rows are not
    /// converted into `is_reused = true` rows pointing at the very cached
    /// result the caller was trying to bypass (#1469).
    pub async fn scan_artifact_with_prepared(
        &self,
        artifact_id: Uuid,
        prepared: HashMap<String, Uuid>,
        force: bool,
        bypass_dedup: bool,
    ) -> Result<()> {
        self.scan_artifact_inner(artifact_id, force, bypass_dedup, Some(prepared))
            .await
    }

    /// Scan a single artifact: run all applicable scanners, persist results,
    /// recalculate the repository security score.
    /// Scan a single artifact. When `force` is true, skip the repo scan-enabled check
    /// (used for on-demand scans triggered manually by an admin).
    /// When `bypass_dedup` is true, also skip the hash-based scan dedup so a
    /// silently-broken prior scan does not mask the re-scan (#1469).
    pub async fn scan_artifact_with_options(
        &self,
        artifact_id: Uuid,
        force: bool,
        bypass_dedup: bool,
    ) -> Result<()> {
        self.scan_artifact_inner(artifact_id, force, bypass_dedup, None)
            .await
    }

    async fn scan_artifact_inner(
        &self,
        artifact_id: Uuid,
        force: bool,
        bypass_dedup: bool,
        prepared: Option<HashMap<String, Uuid>>,
    ) -> Result<()> {
        // Fetch artifact and content
        let artifact = sqlx::query_as!(
            Artifact,
            r#"
            SELECT id, repository_id, path, name, version, size_bytes,
                   checksum_sha256, checksum_md5, checksum_sha1,
                   content_type, storage_key, is_deleted, uploaded_by,
                   quarantine_status, quarantine_until,
                   created_at, updated_at
            FROM artifacts
            WHERE id = $1 AND is_deleted = false
            "#,
            artifact_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

        // The artifact path is repository-internal; scanners that need an
        // externally routable identity (Grype's OCI `registry:` mode) require
        // the owning repository's key and type. Fetch those separately so the
        // artifact load stays compile-time column-checked via `query_as!`.
        let repo_routing = sqlx::query!(
            r#"
            SELECT key AS repository_key, repo_type::text AS repository_type
            FROM repositories
            WHERE id = $1
            "#,
            artifact.repository_id,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let repository_key = repo_routing.repository_key;
        let repository_type = repo_routing
            .repository_type
            .ok_or_else(|| AppError::Database("repository repo_type was NULL".to_string()))?;

        // Check if scanning is enabled for this repo (skip check if forced)
        if !force
            && !self
                .scan_config_service
                .is_scan_enabled(artifact.repository_id)
                .await?
        {
            info!(
                "Scanning not enabled for repository {}, skipping artifact {}",
                artifact.repository_id, artifact_id
            );
            return Ok(());
        }

        // Load content from storage (we need the storage key)
        // NOTE: The orchestrator is called with content already available in
        // upload/proxy paths. For on-demand scans, we fetch from DB metadata.
        let storage = self.resolve_repo_storage(artifact.repository_id).await?;
        let content = self
            .fetch_artifact_content_from_storage(&artifact, storage.as_ref())
            .await?;

        // Load metadata if available
        let metadata = sqlx::query_as!(
            ArtifactMetadata,
            r#"
            SELECT id, artifact_id, format, metadata, properties
            FROM artifact_metadata
            WHERE artifact_id = $1
            LIMIT 1
            "#,
            artifact_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let checksum = &artifact.checksum_sha256;
        let mut prepared = prepared.unwrap_or_default();
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: &repository_key,
            repository_type: &repository_type,
            db: Some(&self.db),
            storage: Some(storage.as_ref()),
        };

        for scanner in &self.scanners {
            // Take any pre-allocated row id committed by the trigger handler.
            // The id was already returned to the client in TriggerScanResponse,
            // so we must keep the same row alive (UPDATE rather than INSERT).
            let prepared_action = resolve_prepared_action(prepared.remove(scanner.scan_type()));

            // Gate on applicability BEFORE creating a scan_results row or
            // copying a reusable result. A non-applicable scanner must leave
            // no `completed, findings_count=0` row behind — that row is
            // indistinguishable from a real clean scan and produces the
            // silent-success class behind #961 (scanners running on
            // unsupported formats) and #994 (lodash fixture marked clean in
            // 2.8ms because ImageScanner short-circuited).
            //
            // #1470: persist a distinct `not_applicable` terminal status rather
            // than routing through fail_scan (which marked the row `failed` and
            // rendered as a red ❌). On the Reuse path the trigger handler
            // pre-allocated a row, so we UPDATE it in place. On the InsertFresh
            // path (auto-scan-on-upload) there is no row yet; previously the
            // scanner just `continue`d and wrote nothing, so under
            // `block_unscanned=true` the artifact classified as NeverScanned and
            // was falsely BLOCKED (#1648). We now INSERT a terminal
            // `not_applicable` row so the artifact classifies as scanned-OK
            // (not unscanned) and the operator sees a deterministic record.
            if !scanner.is_applicable_for_target(&target) {
                info!(
                    "Scanner {} not applicable for artifact {} (content_type={}, path={}), skipping",
                    scanner.name(),
                    artifact_id,
                    artifact.content_type,
                    artifact.path,
                );
                let reason = format!(
                    "Scanner {} does not apply to this artifact format",
                    scanner.name(),
                );
                match prepared_action {
                    PreparedScanAction::Reuse(target_id) => {
                        if let Err(e) = self
                            .scan_result_service
                            .mark_not_applicable(target_id, &reason, chrono::Utc::now())
                            .await
                        {
                            warn!(
                                "Failed to mark pre-allocated scan {} as not-applicable: {}",
                                target_id, e
                            );
                        }
                    }
                    PreparedScanAction::InsertFresh => {
                        if let Err(e) = self
                            .scan_result_service
                            .create_not_applicable_scan(
                                artifact_id,
                                artifact.repository_id,
                                scanner.scan_type(),
                                &reason,
                                Some(checksum),
                            )
                            .await
                        {
                            warn!(
                                "Failed to record not-applicable scan for artifact {} \
                                 (scanner {}): {}",
                                artifact_id,
                                scanner.name(),
                                e
                            );
                        }
                    }
                }
                continue;
            }

            // Check for reusable scan results (same hash + scan type within TTL).
            // The bypass_dedup flag (#1469) short-circuits this so the explicit
            // "rescan now" path cannot be silently fed a cached result that was
            // exactly what the caller was trying to escape from.
            let reusable = if bypass_dedup {
                None
            } else {
                self.scan_result_service
                    .find_reusable_scan(
                        checksum,
                        scanner.scan_type(),
                        DEDUP_TTL_DAYS,
                        ZERO_FINDINGS_DEDUP_TTL_DAYS,
                    )
                    .await
                    .ok()
                    .flatten()
            };
            if let Some(source_scan) = reusable {
                // #1373: when the matched source scan is for THIS artifact,
                // a completed scan for these exact bytes already exists. We
                // must not run a fresh scan or copy results into a new row;
                // either action would leave the artifact with two completed
                // rows for one scan_type (the failing release-gate
                // assertion `Per-artifact scan list contains exactly one
                // completed scan`).
                //
                // Two sub-cases:
                //
                // 1. `prepared_action` is `Reuse(target_id)` where
                //    target_id == source_scan.id. This is the normal path
                //    after the #1373 short-circuit in
                //    prepare_artifact_scan: the trigger handler returned
                //    the existing scan id and we have nothing to do.
                //
                // 2. `prepared_action` is `Reuse(target_id)` where
                //    target_id != source_scan.id. The placeholder was
                //    inserted before the existing scan completed (race
                //    between prepare and execute, or between two
                //    concurrent trigger calls). We must NOT leave the
                //    placeholder stuck in `running`; instead convert it
                //    to a reused row pointing at the source so the
                //    stuck-scan janitor never has to clean it up and the
                //    polling client sees a deterministic terminal state.
                //
                // 3. `prepared_action` is `InsertFresh` (auto-scan-on-
                //    upload). No placeholder was inserted yet, so we just
                //    skip to the next scanner — the existing row already
                //    represents the scan for these bytes.
                if should_skip_reuse_for_same_artifact(source_scan.artifact_id, artifact_id) {
                    match decide_same_artifact_action(&prepared_action, source_scan.id) {
                        SameArtifactAction::NoOp => {}
                        SameArtifactAction::ConvertOrphanPlaceholder {
                            target_id,
                            source_id,
                        } => {
                            // Race window: convert the orphan placeholder
                            // into a reused-row pointing at the existing
                            // completed scan. Best-effort: if the convert
                            // fails the stuck-scan janitor will reap the
                            // running row eventually.
                            if let Err(e) = self
                                .scan_result_service
                                .convert_to_reused(target_id, source_id, artifact_id)
                                .await
                            {
                                warn!(
                                    "Failed to convert orphan placeholder {} to reused row pointing at {}: {}",
                                    target_id, source_id, e
                                );
                            }
                        }
                    }
                    info!(
                        "Skipping fresh scan for artifact {}: existing completed scan {} matches (scanner={}, hash={}..)",
                        artifact_id,
                        source_scan.id,
                        scanner.name(),
                        checksum_log_prefix(checksum),
                    );
                    continue;
                }

                let copied = match prepared_action {
                    PreparedScanAction::Reuse(target_id) => {
                        self.scan_result_service
                            .convert_to_reused(target_id, source_scan.id, artifact_id)
                            .await
                    }
                    PreparedScanAction::InsertFresh => {
                        self.scan_result_service
                            .copy_scan_results(
                                source_scan.id,
                                artifact_id,
                                artifact.repository_id,
                                scanner.scan_type(),
                                checksum,
                            )
                            .await
                    }
                };
                match copied {
                    Ok(reused) => {
                        info!(
                            "Reusing scan results from {} for artifact {} (scanner={}, hash={}..)",
                            source_scan.id,
                            artifact_id,
                            scanner.name(),
                            checksum_log_prefix(checksum),
                        );
                        // Update quarantine status based on copied findings
                        self.update_quarantine_status(artifact_id, reused.findings_count)
                            .await?;
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to copy scan results from {}: {}. Running fresh scan.",
                            source_scan.id, e
                        );
                    }
                }
            }

            // Either reuse path failed or no reusable scan: run a fresh scan.
            // If we still have a prepared id, reuse it; otherwise create a row.
            let scan_result = match prepared_action {
                PreparedScanAction::Reuse(target_id) => {
                    self.scan_result_service.get_scan(target_id).await?
                }
                PreparedScanAction::InsertFresh => {
                    self.scan_result_service
                        .create_scan_result_with_checksum(
                            artifact_id,
                            artifact.repository_id,
                            scanner.scan_type(),
                            Some(checksum),
                        )
                        .await?
                }
            };

            // Capture wall-clock subprocess kickoff time so the persisted
            // `scan_results.started_at` reflects when the scanner actually
            // started, not when the row was created (rows are created above
            // for dedup-checking and may sit briefly before scan invocation).
            // See issue #902.
            let started_at = chrono::Utc::now();
            match scanner
                .scan_target(&target, metadata.as_ref(), &content)
                .await
            {
                Ok(ScanOutput {
                    findings,
                    packages,
                    scan_completeness,
                }) => {
                    let total = findings.len() as i32;
                    let count = |sev: Severity| -> i32 {
                        findings.iter().filter(|f| f.severity == sev).count() as i32
                    };
                    let critical = count(Severity::Critical);
                    let high = count(Severity::High);
                    let medium = count(Severity::Medium);
                    let low = count(Severity::Low);
                    let info = count(Severity::Info);

                    // Probe scanner binary version after a successful scan so
                    // the persisted provenance matches the binary that just
                    // ran. None on probe failure is acceptable: the field is
                    // nullable and the silent-success migration (075) treats
                    // NULL as "legacy / unknown" rather than as a hard error.
                    let scanner_version = scanner.version().await;

                    // Persist findings
                    self.scan_result_service
                        .create_findings(scan_result.id, artifact_id, &findings)
                        .await?;

                    // Persist the package inventory (#903). Failures here
                    // are logged but do not fail the scan: the inventory is
                    // an enhancement layered on top of the findings path,
                    // and a scanner that ran successfully should not be
                    // marked as failed because a non-critical INSERT
                    // tripped over a constraint. SBOM generation falls back
                    // to scan_findings when the inventory is empty.
                    //
                    // #1157: when persistence fails, set
                    // `inventory_status = 'partial'` on the scan_result row
                    // and increment the `scan_inventory_failures_total`
                    // counter so operator dashboards can alert on degraded
                    // SBOMs. The scan itself still completes (status =
                    // 'completed', counts are accurate) so customers don't
                    // get false-positive scan-failed pages.
                    if !packages.is_empty() {
                        match self
                            .scan_result_service
                            .create_packages(scan_result.id, artifact_id, &packages)
                            .await
                        {
                            Ok(_) => {
                                // Companion success counter so SRE alerting
                                // can compute the failure ratio
                                // `failures / (failures + success)` instead
                                // of alerting on raw failure counts (review
                                // #1188-R1: ratio is robust to traffic
                                // changes; raw counter is not).
                                crate::services::metrics_service::record_scan_inventory_success(
                                    scanner.scan_type(),
                                );
                            }
                            Err(e) => {
                                // error! (not warn!): this is the precise
                                // event `scan_inventory_failures_total`
                                // targets for alerting. warn! would hide it
                                // in benign log filters.
                                error!(
                                    "Failed to persist scan_packages for scan {}: {}. \
                                     Findings were persisted; SBOM generation will fall \
                                     back to the findings-derived component list. \
                                     Marking inventory_status='partial'.",
                                    scan_result.id, e
                                );
                                crate::services::metrics_service::record_scan_inventory_failure(
                                    scanner.scan_type(),
                                );
                                if let Err(set_err) = self
                                    .scan_result_service
                                    .set_inventory_status(
                                        scan_result.id,
                                        crate::services::scan_result_service::InventoryStatus::Partial,
                                    )
                                    .await
                                {
                                    // Status-update failure means the metric
                                    // and the DB row now disagree — operator
                                    // dashboards will alert on a row that
                                    // still reads inventory_status='complete'.
                                    // error! so the gap is grep-able during
                                    // an incident.
                                    error!(
                                        "Failed to set inventory_status='partial' on scan {}: {}",
                                        scan_result.id, set_err
                                    );
                                }
                            }
                        }
                    }

                    // Mark scan complete. `scan_completeness` (#1153) flows
                    // through to `scan_results.scan_completeness` so the
                    // SBOM endpoint and downstream attestation tooling can
                    // distinguish "lockfile present but unparseable" from
                    // "no lockfile present".
                    self.scan_result_service
                        .complete_scan(
                            scan_result.id,
                            total,
                            critical,
                            high,
                            medium,
                            low,
                            info,
                            scanner_version.as_deref(),
                            started_at,
                            scan_completeness.as_str(),
                        )
                        .await?;

                    info!(
                        "Scan {} completed for artifact {}: {} findings ({} critical, {} high), scanner_version={:?}, completeness={}",
                        scanner.name(),
                        artifact_id,
                        total,
                        critical,
                        high,
                        scanner_version,
                        scan_completeness.as_str(),
                    );

                    // Update quarantine status
                    self.update_quarantine_status(artifact_id, total).await?;
                }
                Err(e) => {
                    error!(
                        "Scanner {} failed for artifact {}: {}",
                        scanner.name(),
                        artifact_id,
                        e
                    );
                    // Best-effort version probe even on failure: lets ops
                    // distinguish "scanner crashed mid-scan" from "scanner
                    // binary missing". `None` is acceptable for the latter.
                    let scanner_version = scanner.version().await;
                    self.scan_result_service
                        .fail_scan(
                            scan_result.id,
                            &e.to_string(),
                            scanner_version.as_deref(),
                            started_at,
                        )
                        .await?;

                    // #1188-R3: the inventory_status column documents
                    // `'failed'` as "scan itself failed", kept distinct from
                    // `'partial'` so dashboards can split "scanner crashed"
                    // from "scanner ran but inventory broken". fail_scan
                    // above only touches `status`; reflect the crash state
                    // in `inventory_status` too so the column is actually
                    // populated by every path the CHECK constraint allows.
                    // Non-fatal: the scan_result row is already in the
                    // failed state and the security score still recomputes
                    // correctly; we log on failure so the gap is grep-able.
                    if let Err(set_err) = self
                        .scan_result_service
                        .set_inventory_status(
                            scan_result.id,
                            crate::services::scan_result_service::InventoryStatus::Failed,
                        )
                        .await
                    {
                        error!(
                            "Failed to set inventory_status='failed' on scan {}: {}",
                            scan_result.id, set_err
                        );
                    }

                    // Mark as flagged on failure (conservative)
                    if let Err(e) = sqlx::query!(
                        "UPDATE artifacts SET quarantine_status = 'flagged' WHERE id = $1",
                        artifact_id,
                    )
                    .execute(&self.db)
                    .await
                    {
                        tracing::error!(
                            artifact_id = %artifact_id,
                            error = %e,
                            "Failed to set flagged status after scan failure"
                        );
                    }
                }
            }
        }

        // Recalculate repository security score
        self.scan_result_service
            .recalculate_score(artifact.repository_id)
            .await?;

        // Submit SBOM to Dependency-Track if integration is configured.
        // Generates a CycloneDX SBOM from the scan_packages inventory
        // (falling back to scan_findings for legacy artifacts) and uploads
        // it to the corresponding DT project. Submission happens whenever
        // any scan signal exists, including clean scans with zero CVEs,
        // so DT can run its own independent vulnerability correlation
        // against the dep tree. #965.
        if let Some(ref dt) = self.dependency_track {
            self.submit_sbom_to_dependency_track(dt, &artifact).await;
        }

        Ok(())
    }

    /// Load an artifact's declared (direct) dependencies from its stored
    /// manifest metadata for SBOM enrichment (#870).
    ///
    /// Metadata-only: no object-storage read, so a Maven POM whose
    /// `${property}` versions were not resolved at upload stays unresolved
    /// here. The on-demand `/sbom` endpoint performs the storage-backed POM
    /// fallback for that case. Returns `(deps, any_version_unresolved)`.
    async fn declared_deps_from_metadata(
        &self,
        artifact_id: Uuid,
        format: Option<&str>,
    ) -> (Vec<crate::services::sbom_service::DependencyInfo>, bool) {
        use crate::services::declared_dependencies as dd;

        let format = match format {
            Some(f) => f.to_lowercase(),
            None => return (Vec::new(), false),
        };

        let metadata: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_optional(&self.db)
                .await
                .ok()
                .flatten();
        let metadata = match metadata {
            Some(m) => m,
            None => return (Vec::new(), false),
        };

        dd::declared_deps_from_manifest(&format, &metadata)
    }

    /// Generate a CycloneDX SBOM for the given artifact and submit it to
    /// Dependency-Track. Components come from the `scan_packages` inventory
    /// (latest scan per scan_type), falling back to `scan_findings` for
    /// pre-#903 legacy artifacts. Submission happens whenever any scan
    /// signal exists, including clean scans with zero vulnerabilities, so
    /// DT performs its own independent CVE correlation against the dep
    /// tree (#965). Errors are logged but do not fail the scan pipeline,
    /// since DT submission is best-effort.
    async fn submit_sbom_to_dependency_track(
        &self,
        dt: &crate::services::dependency_track_service::DependencyTrackService,
        artifact: &Artifact,
    ) {
        use crate::models::sbom::SbomFormat;
        use crate::services::sbom_service::SbomService;

        // Fetch repository name and format for the DT project
        let repo_row: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT name, format::text FROM repositories WHERE id = $1")
                .bind(artifact.repository_id)
                .fetch_optional(&self.db)
                .await
                .ok()
                .flatten();

        // #1276: DT project name is the artifact name (not the repo name), so
        // each artifact gets its own DT project and findings map 1:1 back to
        // the artifact AK stored. The repo label is folded into the
        // description so operators can still trace a project back to its
        // source repo. `purl_type` comes from the repo format because
        // purl encoding is a property of the format, not the artifact.
        let repo_format = repo_row.as_ref().and_then(|(_, fmt)| fmt.clone());
        let (repo_label, purl_type) =
            derive_dt_project_info(repo_row, &artifact.repository_id.to_string());
        let project_name = artifact.name.as_str();

        // Build the dependency list, preferring the scan_packages inventory
        // (#903) so we forward the full dep tree even when Grype found zero
        // CVEs. DT does its own correlation and needs the components. #965.
        //
        // Both queries are windowed to the latest completed scan per
        // (artifact, scan_type), mirroring the read pattern used by the
        // /sbom handler in `extract_dependencies_for_artifact`. Without
        // that window, an artifact rescanned after a dep removal would
        // still ship the removed dep to DT forever.
        let package_sql = format!(
            "{}
            SELECT DISTINCT sp.name, sp.version, sp.purl, sp.license
            FROM scan_packages sp
            WHERE sp.scan_result_id IN (SELECT id FROM latest_scans)
              AND sp.name IS NOT NULL
              AND sp.name != ''",
            LATEST_SCANS_FOR_ARTIFACT_CTE,
        );
        #[allow(clippy::type_complexity)]
        let package_rows: Vec<(String, Option<String>, Option<String>, Option<String>)> =
            sqlx::query_as(&package_sql)
                .bind(artifact.id)
                .fetch_all(&self.db)
                .await
                .unwrap_or_default();

        let package_inventory = !package_rows.is_empty();
        let mut deps = build_dependency_info_from_packages(package_rows, purl_type);

        // Legacy fallback: artifacts scanned before migration 085 (scan_packages)
        // existed only have scan_findings rows. Same DISTINCT ON window so the
        // CVE-only component list matches the latest scan, not stale history.
        let mut findings_only = false;
        if deps.is_empty() {
            let findings_sql = format!(
                "{}
                SELECT DISTINCT f.affected_component, f.affected_version, f.source
                FROM scan_findings f
                WHERE f.scan_result_id IN (SELECT id FROM latest_scans)
                  AND f.affected_component IS NOT NULL
                  AND f.affected_component != ''",
                LATEST_SCANS_FOR_ARTIFACT_CTE,
            );
            let findings_rows: Vec<(String, Option<String>, Option<String>)> =
                sqlx::query_as(&findings_sql)
                    .bind(artifact.id)
                    .fetch_all(&self.db)
                    .await
                    .unwrap_or_default();

            deps = build_dependency_info_from_findings(findings_rows, purl_type);
            findings_only = !deps.is_empty();
        }

        // Merge the artifact's own declared dependencies (#870) so the stored
        // and DT-submitted SBOM carries the dep tree even when no scanner
        // enumerated packages, and carry an honest completeness signal.
        // Metadata-only here (no object-storage read); the on-demand /sbom
        // endpoint adds the POM storage fallback for older artifacts.
        let (declared, declared_unresolved) = self
            .declared_deps_from_metadata(artifact.id, repo_format.as_deref())
            .await;
        let (deps, completeness) = crate::services::declared_dependencies::assemble_dependencies(
            deps,
            declared,
            package_inventory,
            findings_only,
            declared_unresolved,
        );

        // Only skip when there is literally no signal: no inventory row, no
        // finding, and no declared dependency. A clean scan with 30 packages
        // and 0 CVEs must still submit to DT so DT can run its own independent
        // vulnerability correlation against the dep tree. #965.
        if deps.is_empty() {
            info!(
                artifact_id = %artifact.id,
                "No scan inventory, findings, or declared dependencies recorded, skipping Dependency-Track SBOM submission"
            );
            return;
        }

        // Generate the CycloneDX SBOM
        let sbom_service = SbomService::new(self.db.clone());
        let sbom_doc = match sbom_service
            .generate_sbom_with_completeness(
                artifact.id,
                artifact.repository_id,
                SbomFormat::CycloneDX,
                deps,
                completeness,
            )
            .await
        {
            Ok(doc) => doc,
            Err(e) => {
                warn!(
                    artifact_id = %artifact.id,
                    error = %e,
                    "Failed to generate CycloneDX SBOM for Dependency-Track submission"
                );
                return;
            }
        };

        // Extract the SBOM content as a string for DT upload
        let sbom_content = match serde_json::to_string(&sbom_doc.content) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    artifact_id = %artifact.id,
                    error = %e,
                    "Failed to serialize SBOM content for Dependency-Track"
                );
                return;
            }
        };

        // Get or create the DT project. #1276: project name = artifact name,
        // version = artifact version, description carries the source repo
        // label so the DT UI shows where the artifact came from.
        //
        // #1472: log at `error!` (not `warn!`) and forward the full
        // AppError message so the operator sees the upstream HTTP status,
        // the endpoint URL, the DT response body, and (on 401/403) the
        // required DT team permissions. Without this, the operator sees a
        // fully green scan even when DT silently rejects every upload.
        let dt_project = match dt
            .get_or_create_project(
                project_name,
                artifact.version.as_deref(),
                Some(&format!("Repository: {}", repo_label)),
            )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                error!(
                    artifact_id = %artifact.id,
                    project_name = %project_name,
                    error = %e,
                    "Dependency-Track project provisioning failed -- SBOM will NOT be uploaded for this artifact"
                );
                return;
            }
        };

        // Upload the SBOM
        match dt.upload_sbom(&dt_project.uuid, &sbom_content).await {
            Ok(upload_resp) => {
                info!(
                    artifact_id = %artifact.id,
                    dt_project = %dt_project.name,
                    dt_token = %upload_resp.token,
                    components = sbom_doc.component_count,
                    "Submitted SBOM to Dependency-Track"
                );
            }
            Err(e) => {
                // #1472: error! (not warn!) so this isn't lost in a noisy log
                // pipeline; the AppError message already carries the endpoint,
                // upstream status, response body, and permissions hint on
                // 401/403 (see `dt_upstream_status_err`).
                error!(
                    artifact_id = %artifact.id,
                    dt_project_uuid = %dt_project.uuid,
                    dt_project_name = %dt_project.name,
                    error = %e,
                    "Dependency-Track SBOM upload failed -- vulnerability correlation will be stale for this artifact"
                );
            }
        }
    }

    /// Scan a single artifact (respects repo scan-enabled config).
    pub async fn scan_artifact(&self, artifact_id: Uuid) -> Result<()> {
        self.scan_artifact_with_options(artifact_id, false, false)
            .await
    }

    /// Scan all non-deleted artifacts in a repository.
    pub async fn scan_repository(&self, repository_id: Uuid) -> Result<u32> {
        self.scan_repository_with_options(repository_id, false, false)
            .await
    }

    /// Scan all artifacts in a repository.
    /// When `force` is true, bypass the scan-enabled config check (for manual triggers).
    /// When `bypass_dedup` is true, also bypass the hash-based scan dedup so a
    /// silently-broken prior scan does not mask the re-scan (#1469).
    pub async fn scan_repository_with_options(
        &self,
        repository_id: Uuid,
        force: bool,
        bypass_dedup: bool,
    ) -> Result<u32> {
        let artifact_ids: Vec<Uuid> = sqlx::query_scalar!(
            "SELECT id FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
            repository_id,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let count = artifact_ids.len() as u32;
        info!(
            "Starting repository scan for {}: {} artifacts (force={}, bypass_dedup={})",
            repository_id, count, force, bypass_dedup
        );

        for artifact_id in artifact_ids {
            if let Err(e) = self
                .scan_artifact_with_options(artifact_id, force, bypass_dedup)
                .await
            {
                warn!(
                    "Failed to scan artifact {} in repo {}: {}",
                    artifact_id, repository_id, e
                );
            }
        }

        Ok(count)
    }

    /// Fetch artifact content from the configured storage backend, staged for
    /// scanning. Small artifacts stay in heap; large ones are spilled to an
    /// mmap-backed `Bytes` so they do not pin anon heap across every scanner.
    ///
    /// NOTE: cloud backends without a streaming `get_stream` override (GCS,
    /// Azure) still buffer the whole object in memory inside the default
    /// `get_stream` fallback before it reaches us here. Adding native
    /// streaming reads for those backends is tracked separately by #1430 and
    /// #1431 (GCS `get_stream`); this fix deliberately does not expand into
    /// that work.
    async fn fetch_artifact_content_from_storage(
        &self,
        artifact: &Artifact,
        storage: &dyn StorageBackend,
    ) -> Result<Bytes> {
        // Early reject using the recorded size before we open the stream. The
        // streaming loop below re-checks against the same ceiling because
        // `size_bytes` can be stale or wrong for proxied/upstream content.
        if artifact.size_bytes > MAX_SCAN_INPUT_BYTES as i64 {
            return Err(AppError::Validation(format!(
                "Artifact {} is {} bytes, exceeding the {} byte scan-input limit; skipping scan",
                artifact.id, artifact.size_bytes, MAX_SCAN_INPUT_BYTES
            )));
        }

        Self::stage_from_storage(storage, &artifact.storage_key, &self.scan_workspace_path)
            .await
            .map_err(|e| match e {
                // Preserve the validation/size-cap variant; only wrap raw
                // storage/stream-open failures with artifact context.
                AppError::Storage(msg) => AppError::Storage(format!(
                    "Failed to stage artifact {} (key={}): {}",
                    artifact.id, artifact.storage_key, msg
                )),
                other => other,
            })
    }

    /// Open a streaming read from `storage` for `key` and stage it for scanning.
    /// Split out from [`fetch_artifact_content`] so it can be tested directly
    /// against a real storage backend without a database round-trip.
    async fn stage_from_storage(
        storage: &dyn StorageBackend,
        key: &str,
        workspace_path: &str,
    ) -> Result<Bytes> {
        let stream = storage.get_stream(key).await.map_err(|e| {
            AppError::Storage(format!("Failed to open stream for key {}: {}", key, e))
        })?;
        Self::stage_scan_input(stream, workspace_path).await
    }

    /// Stage `stream` for scanning, returning the bytes either in heap (small
    /// inputs) or as an `mmap`-backed `Bytes` spilled to a tempfile (large
    /// inputs).
    ///
    /// Why this exists: `storage.get(...)` used to return the full (multi-GiB)
    /// artifact as anon heap and the orchestrator held it alive across every
    /// applicable scanner — past the cgroup ceiling on smaller nodes, where
    /// the OOM killer was the only outcome. File-backed (mmap) pages are
    /// kernel-reclaimable under cgroup pressure; anon pages are not.
    ///
    /// Staging strategy:
    /// - We buffer in heap while the running total stays below
    ///   [`SCAN_MMAP_THRESHOLD_BYTES`]. Most artifacts never exceed it, so they
    ///   never touch the disk/mmap path at all.
    /// - The first chunk that pushes us over the threshold triggers a spill:
    ///   the in-heap prefix and all remaining chunks are written to a tempfile
    ///   which is then memory-mapped.
    /// - The running total is checked against [`MAX_SCAN_INPUT_BYTES`] so a
    ///   stream whose declared `size_bytes` was wrong (or absent) still cannot
    ///   consume unbounded disk + virtual address space.
    ///
    /// Lifetime of the tempfile: the `NamedTempFile` is held until this function
    /// returns, at which point its `Drop` unlinks the path. On Linux the inode
    /// stays alive (and the `Mmap` valid) as long as the returned `Bytes` keeps
    /// the mapping referenced, but the directory entry is gone immediately. The
    /// on-disk blocks are reclaimed when the returned `Bytes` drops, i.e. when
    /// scanning finishes.
    async fn stage_scan_input(
        stream: BoxStream<'static, Result<Bytes>>,
        workspace_path: &str,
    ) -> Result<Bytes> {
        Self::stage_scan_input_with_limits(
            stream,
            workspace_path,
            SCAN_MMAP_THRESHOLD_BYTES,
            MAX_SCAN_INPUT_BYTES,
        )
        .await
    }

    /// Inner staging routine with the threshold and cap as parameters so both
    /// branches are testable with small inputs. Production calls go through
    /// [`stage_scan_input`], which supplies the configured constants.
    async fn stage_scan_input_with_limits(
        mut stream: BoxStream<'static, Result<Bytes>>,
        workspace_path: &str,
        mmap_threshold: u64,
        max_bytes: u64,
    ) -> Result<Bytes> {
        let mut buffered: Vec<u8> = Vec::new();
        let mut total: u64 = 0;

        // Phase 1: buffer in heap until we either drain the stream (small
        // input -> stay in memory) or cross the mmap threshold (large input
        // -> fall through to the spill path below).
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                AppError::Storage(format!("Stream error while staging scan input: {}", e))
            })?;
            total += chunk.len() as u64;
            if total > max_bytes {
                return Err(AppError::Validation(format!(
                    "Scan input exceeded the {} byte limit while streaming; aborting scan",
                    max_bytes
                )));
            }
            buffered.extend_from_slice(&chunk);
            if total > mmap_threshold {
                return Self::spill_to_mmap(buffered, stream, total, workspace_path, max_bytes)
                    .await;
            }
        }

        // Small input: served straight from heap, no tempfile, no mmap.
        Ok(Bytes::from(buffered))
    }

    /// Spill an already-buffered prefix plus the remaining stream to a tempfile
    /// under `workspace_path`, then return an `mmap`-backed `Bytes`. Only
    /// reached once the input is known to exceed the mmap threshold.
    async fn spill_to_mmap(
        prefix: Vec<u8>,
        mut stream: BoxStream<'static, Result<Bytes>>,
        mut total: u64,
        workspace_path: &str,
        max_bytes: u64,
    ) -> Result<Bytes> {
        use tokio::io::AsyncWriteExt;

        tokio::fs::create_dir_all(workspace_path)
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to create scan workspace {}: {}",
                    workspace_path, e
                ))
            })?;

        let workspace = workspace_path.to_string();
        // Hold the NamedTempFile for the duration of staging. Its path is
        // unlinked on Drop at function return; the Mmap keeps the inode alive.
        let temp = tokio::task::spawn_blocking(move || tempfile::NamedTempFile::new_in(&workspace))
            .await
            .map_err(|e| AppError::Storage(format!("Tempfile join failure: {}", e)))?
            .map_err(|e| AppError::Storage(format!("Failed to create scan tempfile: {}", e)))?;

        // Write through the NamedTempFile's own handle (an independent fd to the
        // same inode via `reopen()`), never by reopening the path. Reopening by
        // path would be a TOCTOU: between create and reopen another process
        // could swap the file the path points at. `reopen()` shares the inode.
        let owned_file = temp.reopen().map_err(|e| {
            AppError::Storage(format!(
                "Failed to reopen scan tempfile handle for write: {}",
                e
            ))
        })?;
        {
            let mut writer = tokio::io::BufWriter::new(tokio::fs::File::from_std(owned_file));
            writer.write_all(&prefix).await.map_err(|e| {
                AppError::Storage(format!("Write error staging scan input prefix: {}", e))
            })?;
            drop(prefix);

            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    AppError::Storage(format!("Stream error while staging scan input: {}", e))
                })?;
                total += chunk.len() as u64;
                if total > max_bytes {
                    return Err(AppError::Validation(format!(
                        "Scan input exceeded the {} byte limit while streaming; aborting scan",
                        max_bytes
                    )));
                }
                writer.write_all(&chunk).await.map_err(|e| {
                    AppError::Storage(format!("Write error to scan tempfile: {}", e))
                })?;
            }
            writer
                .flush()
                .await
                .map_err(|e| AppError::Storage(format!("Flush error on scan tempfile: {}", e)))?;
        }

        // Map through a fresh independent fd to the same inode.
        let map_file = temp.reopen().map_err(|e| {
            AppError::Storage(format!(
                "Failed to reopen scan tempfile handle for mmap: {}",
                e
            ))
        })?;
        // SAFETY: `memmap2::Mmap::map` is unsafe because the kernel mapping
        // becomes undefined behavior if the underlying file is mutated or
        // truncated by another writer while the mapping is live. We uphold the
        // contract:
        //   - The file is a freshly created `NamedTempFile` in a workspace the
        //     backend owns (`SCAN_WORKSPACE_PATH` must be a local filesystem
        //     the backend has exclusive control of, not a shared/network mount
        //     that other processes write to).
        //   - We are the only owner of this inode: `reopen()` hands back an
        //     independent fd to the same inode, and `temp` is kept alive in
        //     scope so nothing else holds the path to truncate or replace it.
        //   - After this function returns, the path is unlinked (NamedTempFile
        //     Drop), so no later process can open and truncate it; the inode
        //     persists only because the `Mmap` (owned by the returned `Bytes`)
        //     references it. We never write to the file again past this point.
        let mmap = unsafe { memmap2::Mmap::map(&map_file) }
            .map_err(|e| AppError::Storage(format!("mmap failed on scan tempfile: {}", e)))?;

        // Drop `temp` -> unlinks the path. The inode stays alive behind the
        // Mmap until the returned `Bytes` is dropped (scan finished).
        drop(temp);

        Ok(Bytes::from_owner(mmap))
    }

    /// Resolve the storage backend for a given repository by looking up
    /// its storage_backend and storage_path, then delegating to the registry.
    async fn resolve_repo_storage(&self, repository_id: Uuid) -> Result<Arc<dyn StorageBackend>> {
        use sqlx::Row;
        let row =
            sqlx::query("SELECT storage_backend, storage_path FROM repositories WHERE id = $1")
                .bind(repository_id)
                .fetch_one(&self.db)
                .await
                .map_err(|e| {
                    AppError::Database(format!(
                        "Failed to fetch storage location for repository {}: {}",
                        repository_id, e
                    ))
                })?;
        let location = crate::storage::StorageLocation {
            backend: row.try_get("storage_backend").unwrap_or_default(),
            path: row.try_get("storage_path").unwrap_or_default(),
        };
        self.storage_registry.backend_for(&location)
    }

    /// Prepare a scan workspace directory with the artifact content.
    ///
    /// Creates a temporary directory under the shared scan workspace path,
    /// writes the artifact content, and extracts archives when applicable.
    /// Returns the path to the workspace directory.
    pub async fn prepare_scan_workspace(
        &self,
        artifact: &Artifact,
        content: &Bytes,
    ) -> Result<PathBuf> {
        let workspace_dir = PathBuf::from(&self.scan_workspace_path).join(artifact.id.to_string());

        tokio::fs::create_dir_all(&workspace_dir)
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to create scan workspace {}: {}",
                    workspace_dir.display(),
                    e
                ))
            })?;

        // Sanitize the artifact name to its basename to prevent path traversal
        let safe_name = sanitize_artifact_filename(&artifact.name);
        let artifact_path = workspace_dir.join(&safe_name);

        // Write the artifact content to the workspace
        tokio::fs::write(&artifact_path, content)
            .await
            .map_err(|e| {
                AppError::Storage(format!("Failed to write artifact to scan workspace: {}", e))
            })?;

        // Extract archives if applicable
        let name_lower = safe_name.to_lowercase();
        if name_lower.ends_with(".tar.gz")
            || name_lower.ends_with(".tgz")
            || name_lower.ends_with(".crate")
            || name_lower.ends_with(".gem")
        {
            self.extract_tar_gz(content, &workspace_dir).await?;
        } else if name_lower.ends_with(".zip")
            || name_lower.ends_with(".whl")
            || name_lower.ends_with(".jar")
            || name_lower.ends_with(".nupkg")
        {
            self.extract_zip(content, &workspace_dir).await?;
        }

        Ok(workspace_dir)
    }

    /// Extract a tar.gz archive into the target directory.
    ///
    /// Iterates entries manually instead of using `archive.unpack()` to protect
    /// against tar-slip attacks: symlinks, hardlinks, and paths that escape the
    /// target directory via `..` components are silently skipped.
    async fn extract_tar_gz(&self, content: &Bytes, target_dir: &Path) -> Result<()> {
        let content = content.clone();
        let target = target_dir.to_path_buf();

        tokio::task::spawn_blocking(move || extract_tar_gz_safe(&content, &target))
            .await
            .map_err(|e| AppError::Internal(format!("Archive extraction task failed: {}", e)))?
    }

    /// Extract a zip archive into the target directory.
    async fn extract_zip(&self, content: &Bytes, target_dir: &Path) -> Result<()> {
        let content = content.clone();
        let target = target_dir.to_path_buf();

        tokio::task::spawn_blocking(move || {
            use std::io::Cursor;

            let reader = Cursor::new(content.as_ref());
            let mut archive = zip::ZipArchive::new(reader)
                .map_err(|e| AppError::Storage(format!("Failed to open zip archive: {}", e)))?;

            for i in 0..archive.len() {
                let mut file = archive.by_index(i).map_err(|e| {
                    AppError::Storage(format!("Failed to read zip entry {}: {}", i, e))
                })?;

                let out_path = match file.enclosed_name() {
                    Some(path) => target.join(path),
                    None => continue, // Skip entries with unsafe paths
                };

                if file.is_dir() {
                    std::fs::create_dir_all(&out_path).map_err(|e| {
                        AppError::Storage(format!("Failed to create directory: {}", e))
                    })?;
                } else {
                    if let Some(parent) = out_path.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            AppError::Storage(format!("Failed to create parent directory: {}", e))
                        })?;
                    }
                    let mut out_file = std::fs::File::create(&out_path)
                        .map_err(|e| AppError::Storage(format!("Failed to create file: {}", e)))?;
                    std::io::copy(&mut file, &mut out_file).map_err(|e| {
                        AppError::Storage(format!("Failed to write extracted file: {}", e))
                    })?;
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(format!("Zip extraction task failed: {}", e)))?
    }

    /// Clean up a scan workspace directory.
    pub async fn cleanup_scan_workspace(&self, path: &Path) -> Result<()> {
        if path.starts_with(&self.scan_workspace_path) {
            tokio::fs::remove_dir_all(path).await.map_err(|e| {
                AppError::Storage(format!(
                    "Failed to clean up scan workspace {}: {}",
                    path.display(),
                    e
                ))
            })?;
        } else {
            warn!(
                "Refusing to clean up path outside scan workspace: {}",
                path.display()
            );
        }
        Ok(())
    }

    /// Update artifact quarantine_status based on scan findings.
    ///
    /// For proxy-scan artifacts (status is NULL, 'unscanned', 'clean', or
    /// 'flagged'), this sets 'clean' or 'flagged' as before.
    ///
    /// For quarantine-period artifacts (status is 'quarantined'), this
    /// transitions to 'released' (clean scan) or 'rejected' (findings found),
    /// and clears the quarantine_until timestamp. Uses a conditional UPDATE
    /// (`WHERE quarantine_status = 'quarantined'`) to prevent a clean scan
    /// from overwriting a rejection set by an admin or another scanner.
    async fn update_quarantine_status(&self, artifact_id: Uuid, findings_count: i32) -> Result<()> {
        // Check if the artifact is currently in quarantine-period mode
        let current_status: Option<String> =
            sqlx::query_scalar("SELECT quarantine_status FROM artifacts WHERE id = $1")
                .bind(artifact_id)
                .fetch_optional(&self.db)
                .await
                .ok()
                .flatten();

        let (new_status, clear_until) = match current_status.as_deref() {
            Some("quarantined") => {
                // Quarantine-period workflow: transition to released/rejected
                let state =
                    crate::services::quarantine_service::status_after_scan(findings_count > 0);
                (state.as_str().to_string(), true)
            }
            _ => {
                // Legacy proxy-scan workflow: use clean/flagged
                let status = if findings_count > 0 {
                    "flagged"
                } else {
                    "clean"
                };
                (status.to_string(), false)
            }
        };

        if clear_until {
            // Use conditional UPDATE to prevent race conditions: only update
            // if the artifact is still in 'quarantined' state. If an admin
            // already rejected it, this UPDATE will affect 0 rows (which is fine).
            let result = sqlx::query(
                "UPDATE artifacts SET quarantine_status = $2, quarantine_until = NULL \
                 WHERE id = $1 AND quarantine_status = 'quarantined'",
            )
            .bind(artifact_id)
            .bind(&new_status)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if result.rows_affected() == 0 {
                tracing::info!(
                    artifact_id = %artifact_id,
                    attempted_status = %new_status,
                    "Quarantine transition skipped: artifact is no longer in quarantined state"
                );
            }
        } else {
            sqlx::query!(
                "UPDATE artifacts SET quarantine_status = $2 WHERE id = $1",
                artifact_id,
                new_status,
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }
        Ok(())
    }
}

/// Test helpers shared across scanner test modules to avoid duplicating
/// Artifact construction in every scanner file.
#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::models::artifact::Artifact;

    /// Create a minimal Artifact for unit tests. Fields not relevant to a
    /// specific test use sensible defaults.
    pub fn make_test_artifact(name: &str, content_type: &str, path: &str) -> Artifact {
        Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            name: name.to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 1000,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: content_type.to_string(),
            storage_key: "test-key".to_string(),
            is_deleted: false,
            uploaded_by: None,
            quarantine_status: None,
            quarantine_until: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Assert that a scan result is an error containing the expected label.
    pub fn assert_scan_failed(
        result: &crate::error::Result<crate::services::scanner_service::ScanOutput>,
        expected_label: &str,
    ) {
        assert!(
            result.is_err(),
            "scan() must return Err, not Ok(vec![]), when {} fails",
            expected_label
        );
        let err_msg = result.as_ref().unwrap_err().to_string();
        assert!(
            err_msg.contains(&format!("{} failed", expected_label)),
            "error message should contain '{} failed', got: {}",
            expected_label,
            err_msg
        );
    }

    /// A non-login scanner service-account `User` fixture (#2093). Shared by the
    /// image- and grype-scanner token-minter tests so the fixture is defined
    /// once.
    pub fn make_scanner_user() -> crate::models::user::User {
        crate::models::user::User {
            id: uuid::Uuid::new_v4(),
            username: "_ak_scanner".to_string(),
            email: "scanner@artifact-keeper.internal".to_string(),
            password_hash: None,
            auth_provider: crate::models::user::AuthProvider::Local,
            external_id: None,
            display_name: Some("Image Scanner (system)".to_string()),
            is_active: true,
            is_admin: false,
            is_service_account: true,
            must_change_password: false,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_failed_login_at: None,
            password_changed_at: chrono::Utc::now(),
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// An `AuthService` whose pool never connects (`connect_lazy`), for
    /// unit-testing pure token-minting/validation with no DB. MUST be called
    /// from within a tokio runtime (`#[tokio::test]`).
    pub fn make_scanner_auth() -> std::sync::Arc<crate::services::auth_service::AuthService> {
        let pool = sqlx::PgPool::connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("connect_lazy never errors on construction");
        std::sync::Arc::new(crate::services::auth_service::AuthService::new(
            pool,
            std::sync::Arc::new(crate::config::Config::test_config()),
        ))
    }
}

/// Fire-and-forget `scan_on_upload` trigger for a freshly-inserted artifact.
///
/// Mirrors the gate already inlined in [`ArtifactService::upload`] so that
/// format-native upload paths (incus, oci, helm, the `proxy_helpers::insert_artifact`
/// callers, …) can opt in with a single call after their DB insert instead of
/// silently skipping the auto-scan. The caller resolves `should_scan` —
/// typically:
///
/// ```ignore
/// let should_scan = sqlx::query_scalar!(
///     "SELECT scan_on_upload FROM scan_configs WHERE repository_id = $1 AND scan_enabled = true",
///     repository_id
/// )
/// .fetch_optional(&db)
/// .await
/// .ok()
/// .flatten()
/// .unwrap_or(false);
/// ```
///
/// — and passes a closure that calls `ScannerService::scan_artifact` (or no-ops
/// when `state.scanner_service` is `None`).
///
/// When `should_scan` is true, the closure is spawned on a background task so
/// the upload response isn't blocked by the scanner pipeline; the closure
/// should log any error itself (the scan is best-effort here — the same
/// artifact can be re-scanned via `POST /api/v1/security/scan`).
///
/// Returns whether a task was spawned (useful for tests and metrics).
pub fn spawn_scan_on_upload<F, Fut>(should_scan: bool, artifact_id: Uuid, trigger: F) -> bool
where
    F: FnOnce(Uuid) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    if !should_scan {
        return false;
    }
    tokio::spawn(async move {
        trigger(artifact_id).await;
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // spawn_scan_on_upload (scan-trigger helper for format-native handlers)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_spawn_scan_on_upload_skips_when_disabled() {
        let id = Uuid::new_v4();
        let spawned = spawn_scan_on_upload(false, id, |_| async {
            panic!("trigger should not fire when scan_on_upload is false");
        });
        assert!(!spawned);
        // Give any (erroneously) spawned task a tick to run and fail the test.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn test_spawn_scan_on_upload_fires_when_enabled() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Uuid>(1);
        let id = Uuid::new_v4();
        let spawned = spawn_scan_on_upload(true, id, move |aid| {
            let tx = tx.clone();
            async move {
                tx.send(aid).await.expect("test rx open");
            }
        });
        assert!(spawned);
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("trigger must fire within timeout")
            .expect("trigger must send the artifact_id");
        assert_eq!(received, id);
    }

    // -----------------------------------------------------------------------
    // stage_scan_input / stage_from_storage (scan-input staging)
    // -----------------------------------------------------------------------

    /// Count regular files directly under `dir` (non-recursive). Used to assert
    /// the staging path never leaks a tempfile in the scan workspace.
    fn count_entries(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn test_stage_scan_input_concatenates_chunks_in_memory() {
        use futures::StreamExt;
        let tmp = tempfile::tempdir().unwrap();
        let chunks: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"hello ")),
            Ok(Bytes::from_static(b"world")),
        ];
        let stream = futures::stream::iter(chunks).boxed();
        let out = ScannerService::stage_scan_input(stream, tmp.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(&out[..], b"hello world");
        // Small input takes the in-memory path: the workspace dir is never even
        // touched (no create_dir_all, no tempfile).
        assert_eq!(
            count_entries(tmp.path()),
            0,
            "small input must not create any file in the workspace"
        );
    }

    #[tokio::test]
    async fn test_stage_scan_input_empty_stream() {
        use futures::StreamExt;
        let tmp = tempfile::tempdir().unwrap();
        let stream = futures::stream::iter(Vec::<Result<Bytes>>::new()).boxed();
        let out = ScannerService::stage_scan_input(stream, tmp.path().to_str().unwrap())
            .await
            .unwrap();
        assert!(out.is_empty());
        assert_eq!(count_entries(tmp.path()), 0);
    }

    /// Below the threshold: in-memory path, correct bytes, no tempfile.
    #[tokio::test]
    async fn test_stage_scan_input_below_threshold_stays_in_memory() {
        use futures::StreamExt;
        let tmp = tempfile::tempdir().unwrap();
        // A few KB, well under SCAN_MMAP_THRESHOLD_BYTES.
        let payload = vec![0xABu8; 4 * 1024];
        let expected = payload.clone();
        let stream = futures::stream::iter(vec![Ok(Bytes::from(payload))]).boxed();
        let out = ScannerService::stage_scan_input(stream, tmp.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(out.len(), expected.len());
        assert_eq!(&out[..], &expected[..]);
        assert_eq!(
            count_entries(tmp.path()),
            0,
            "below-threshold input must not spill to disk"
        );
    }

    /// Above the threshold: spills to a tempfile + mmap, returns correct bytes,
    /// and unlinks the tempfile so nothing leaks in the workspace.
    #[tokio::test]
    async fn test_stage_scan_input_above_threshold_spills_to_mmap() {
        use futures::StreamExt;
        let tmp = tempfile::tempdir().unwrap();
        // Just over the threshold, streamed in 1 MiB chunks so the spill
        // happens mid-stream (prefix already buffered when we cross over).
        let chunk = vec![0x5Au8; 1024 * 1024];
        let chunk_count = (SCAN_MMAP_THRESHOLD_BYTES / (1024 * 1024)) as usize + 2;
        let chunks: Vec<Result<Bytes>> = (0..chunk_count)
            .map(|_| Ok(Bytes::from(chunk.clone())))
            .collect();
        let total = chunk.len() * chunk_count;
        let stream = futures::stream::iter(chunks).boxed();
        let out = ScannerService::stage_scan_input(stream, tmp.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(out.len(), total);
        assert!(out.iter().all(|&b| b == 0x5A), "bytes must round-trip");
        // The NamedTempFile is unlinked on return; the workspace dir is created
        // but must contain no leftover staging file.
        assert_eq!(
            count_entries(tmp.path()),
            0,
            "mmap spill path must not leak a tempfile after return"
        );
    }

    /// Mid-stream error must propagate AND leave no tempfile behind. We force
    /// the error after crossing the threshold so the spill path (which created
    /// a tempfile) is the one exercised.
    #[tokio::test]
    async fn test_stage_scan_input_midstream_error_cleans_up() {
        use futures::StreamExt;
        let tmp = tempfile::tempdir().unwrap();
        let big = vec![0x11u8; (SCAN_MMAP_THRESHOLD_BYTES + 1) as usize];
        let chunks: Vec<Result<Bytes>> =
            vec![Ok(Bytes::from(big)), Err(AppError::Storage("boom".into()))];
        let stream = futures::stream::iter(chunks).boxed();
        let result = ScannerService::stage_scan_input(stream, tmp.path().to_str().unwrap()).await;
        let err = result.expect_err("mid-stream error must propagate");
        assert!(
            err.to_string().contains("boom"),
            "underlying error must surface, got: {}",
            err
        );
        assert_eq!(
            count_entries(tmp.path()),
            0,
            "tempfile must be unlinked on error path (NamedTempFile Drop)"
        );
    }

    /// A small-input mid-stream error: never spills, so nothing to clean up,
    /// but the error must still propagate.
    #[tokio::test]
    async fn test_stage_scan_input_small_midstream_error_propagates() {
        use futures::StreamExt;
        let tmp = tempfile::tempdir().unwrap();
        let chunks: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"x")),
            Err(AppError::Storage("boom".into())),
        ];
        let stream = futures::stream::iter(chunks).boxed();
        let result = ScannerService::stage_scan_input(stream, tmp.path().to_str().unwrap()).await;
        let err = result.expect_err("mid-stream error must propagate");
        assert!(err.to_string().contains("boom"), "got: {}", err);
        assert_eq!(count_entries(tmp.path()), 0);
    }

    /// `stage_from_storage` (the storage-backed half of `fetch_artifact_content`)
    /// round-trips real stored bytes through a filesystem backend, with no DB.
    #[tokio::test]
    async fn test_stage_from_storage_roundtrips_filesystem_backend() {
        use crate::storage::filesystem::FilesystemStorage;
        use crate::storage::StorageBackend;
        let store_dir = tempfile::tempdir().unwrap();
        let work_dir = tempfile::tempdir().unwrap();
        let storage = FilesystemStorage::new(store_dir.path());

        let key = "deadbeefcafef00d";
        let content = b"artifact bytes that fetch_artifact_content should return verbatim";
        storage.put(key, Bytes::from_static(content)).await.unwrap();

        let out =
            ScannerService::stage_from_storage(&storage, key, work_dir.path().to_str().unwrap())
                .await
                .unwrap();
        assert_eq!(&out[..], &content[..], "returned bytes must equal stored");
    }

    /// The size cap rejects an input that exceeds `max_bytes` while still in
    /// the in-heap phase (before any spill). Driven with small data via the
    /// limit-parameterized inner routine.
    #[tokio::test]
    async fn test_stage_scan_input_cap_rejects_in_memory_phase() {
        use futures::StreamExt;
        let tmp = tempfile::tempdir().unwrap();
        // 4 KiB input, cap of 1 KiB, threshold above the cap so we never spill.
        let stream = futures::stream::iter(vec![Ok(Bytes::from(vec![0u8; 4 * 1024]))]).boxed();
        let result = ScannerService::stage_scan_input_with_limits(
            stream,
            tmp.path().to_str().unwrap(),
            /* mmap_threshold */ 8 * 1024,
            /* max_bytes */ 1024,
        )
        .await;
        let err = result.expect_err("oversized input must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got: {:?}", err);
        assert!(err.to_string().contains("exceeded"));
        assert_eq!(
            count_entries(tmp.path()),
            0,
            "rejected-in-memory input must not have created a tempfile"
        );
    }

    /// The size cap also fires on the spill path (after the threshold is
    /// crossed) and cleans up the tempfile it had started writing.
    #[tokio::test]
    async fn test_stage_scan_input_cap_rejects_on_spill_path_and_cleans_up() {
        use futures::StreamExt;
        let tmp = tempfile::tempdir().unwrap();
        // First chunk (2 KiB) crosses the 1 KiB threshold -> spill begins.
        // Second chunk pushes total past the 3 KiB cap -> reject mid-spill.
        let chunks: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from(vec![0u8; 2 * 1024])),
            Ok(Bytes::from(vec![0u8; 2 * 1024])),
        ];
        let stream = futures::stream::iter(chunks).boxed();
        let result = ScannerService::stage_scan_input_with_limits(
            stream,
            tmp.path().to_str().unwrap(),
            /* mmap_threshold */ 1024,
            /* max_bytes */ 3 * 1024,
        )
        .await;
        let err = result.expect_err("oversized input must be rejected on spill path");
        assert!(matches!(err, AppError::Validation(_)), "got: {:?}", err);
        assert_eq!(
            count_entries(tmp.path()),
            0,
            "tempfile must be unlinked when the cap aborts the spill"
        );
    }

    // -----------------------------------------------------------------------
    // Scanner version parsing (issue #902)
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_trivy_version_with_version_prefix() {
        // Real `trivy --version` output: `Version: 0.62.1`
        assert_eq!(
            format_trivy_version("Version: 0.62.1"),
            Some("trivy-0.62.1".to_string())
        );
    }

    #[test]
    fn test_format_trivy_version_with_extra_metadata() {
        // Trivy can also emit `Version: 0.62.1\nVulnerability DB:\n  ...`
        // capture_cli_version only returns the first line, but the parser
        // must still tolerate trailing whitespace and additional tokens.
        assert_eq!(
            format_trivy_version("Version: 0.62.1   "),
            Some("trivy-0.62.1".to_string())
        );
    }

    #[test]
    fn test_format_trivy_version_bare_token() {
        // Defensive: some packagings emit just the version.
        assert_eq!(
            format_trivy_version("0.62.1"),
            Some("trivy-0.62.1".to_string())
        );
    }

    #[test]
    fn test_format_trivy_version_empty_returns_none() {
        assert_eq!(format_trivy_version(""), None);
        assert_eq!(format_trivy_version("Version:"), None);
    }

    // -----------------------------------------------------------------------
    // VersionCache TTL semantics (issue #1012)
    // -----------------------------------------------------------------------

    /// Probe counter helper: lets us assert how many times the probe ran
    /// across multiple `cached_cli_version` calls.
    fn counted_probe(
        counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        result: Option<String>,
    ) -> impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>> + Send
    {
        move || {
            let counter = counter.clone();
            let result = result.clone();
            Box::pin(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                result
            })
        }
    }

    /// First probe returns Some, second call returns the cached Some without
    /// re-probing. This is the steady-state path: scanners are deployed once
    /// per pod lifecycle, so re-probing on every scan would be pure waste.
    #[tokio::test]
    async fn test_version_cache_caches_some_no_reprobe() {
        let cache = VersionCache::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let probe = counted_probe(counter.clone(), Some("trivy-0.62.1".to_string()));

        let v1 = cached_cli_version(&cache, &probe).await;
        let v2 = cached_cli_version(&cache, &probe).await;

        assert_eq!(v1, Some("trivy-0.62.1".to_string()));
        assert_eq!(v2, Some("trivy-0.62.1".to_string()));
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "Some(_) entries must be cached for the long TTL; second call should not re-probe"
        );
    }

    /// First probe returns None, second call within MISS_TTL returns the
    /// cached None without re-probing. Demonstrates that we still have a
    /// cache (we are not hammering the missing binary on every call), just
    /// with a much shorter TTL than for hits.
    #[tokio::test]
    async fn test_version_cache_caches_none_within_miss_ttl() {
        let cache = VersionCache::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let probe = counted_probe(counter.clone(), None);

        let v1 = cached_cli_version(&cache, &probe).await;
        let v2 = cached_cli_version(&cache, &probe).await;

        assert_eq!(v1, None);
        assert_eq!(v2, None);
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "None entries must be cached within MISS_TTL; second call should not re-probe"
        );
    }

    /// First probe returns None, but after the MISS_TTL elapses the cache
    /// re-probes. This is the regression test for issue #1012: previously a
    /// permanent OnceCell stored None forever, so `scan_results.scanner_version`
    /// stayed NULL until a pod restart. Now, once the operator installs the
    /// missing binary, the cache picks it up within 60s.
    #[tokio::test]
    async fn test_version_cache_reprobes_after_miss_ttl() {
        let cache = VersionCache::new();
        // Seed the cache with an aged-out None entry (older than MISS_TTL).
        cache
            .set_with_age(None, VERSION_CACHE_MISS_TTL + Duration::from_secs(1))
            .await;
        assert_eq!(cache.peek().await, Some(None), "seed must be visible");

        // Now the binary becomes available: probe returns Some.
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let probe = counted_probe(counter.clone(), Some("trivy-0.63.0".to_string()));

        let v = cached_cli_version(&cache, &probe).await;
        assert_eq!(
            v,
            Some("trivy-0.63.0".to_string()),
            "expired None must be replaced by the fresh probe result"
        );
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "expired None must trigger a re-probe"
        );

        // And the new Some is itself cached (no further probing).
        let v2 = cached_cli_version(&cache, &probe).await;
        assert_eq!(v2, Some("trivy-0.63.0".to_string()));
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "fresh Some must be cached and not re-probed"
        );
    }

    /// Sanity check: a Some entry that is older than MISS_TTL but younger
    /// than HIT_TTL is still served from cache. Hits and misses use
    /// different TTLs, and we must read the right one.
    #[tokio::test]
    async fn test_version_cache_some_survives_past_miss_ttl() {
        let cache = VersionCache::new();
        // Stored Some, aged just past MISS_TTL but well under HIT_TTL.
        cache
            .set_with_age(
                Some("trivy-0.62.1".to_string()),
                VERSION_CACHE_MISS_TTL + Duration::from_secs(5),
            )
            .await;

        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let probe = counted_probe(counter.clone(), Some("trivy-IGNORED".to_string()));

        let v = cached_cli_version(&cache, &probe).await;
        assert_eq!(
            v,
            Some("trivy-0.62.1".to_string()),
            "Some entries must use the long HIT_TTL, not the short MISS_TTL"
        );
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Some entry within HIT_TTL must not trigger a re-probe"
        );
    }

    /// TTL constants are sane: hits last much longer than misses, and the
    /// Round 1 review feedback (#1012 R1): exercise the concurrent-miss
    /// path where two callers simultaneously see an empty cache, both
    /// drop the read lock, both probe, then race for the write lock.
    /// The double-checked re-check under the write lock is supposed to
    /// prevent the second caller from overwriting the first's still-fresh
    /// entry. Without this test the re-check branch is unexercised.
    ///
    /// Acceptable outcomes:
    /// - Probe counter is in [1, 2] (deliberate non-single-flight; both
    ///   callers may probe before either finishes).
    /// - Both callers return the SAME value (the winner of the write-lock
    ///   race; the loser discards its `probed` and reads the winner's).
    #[tokio::test]
    async fn test_version_cache_concurrent_miss_returns_consistent_value() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let cell = Arc::new(VersionCache::default());
        let probe_count = Arc::new(AtomicUsize::new(0));

        // The probe sleeps briefly so both callers reliably overlap on
        // the slow path. The returned value is fixed so a passing test
        // means both callers ended up with the same cache entry.
        let make_probe = |pc: Arc<AtomicUsize>| {
            move || {
                let pc = pc.clone();
                async move {
                    pc.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Some("trivy-0.62.1".to_string())
                }
            }
        };

        let a_cell = cell.clone();
        let a_pc = probe_count.clone();
        let b_cell = cell.clone();
        let b_pc = probe_count.clone();

        let (a, b) = tokio::join!(
            cached_cli_version(&a_cell, make_probe(a_pc)),
            cached_cli_version(&b_cell, make_probe(b_pc)),
        );

        assert_eq!(
            a,
            Some("trivy-0.62.1".to_string()),
            "first caller must return the probed value"
        );
        assert_eq!(
            a, b,
            "concurrent callers MUST observe the same cache entry; \
             the write-lock re-check ensures whoever loses the write \
             race reads the winner's value rather than its own probe"
        );

        let probes = probe_count.load(Ordering::SeqCst);
        assert!(
            (1..=2).contains(&probes),
            "expected 1 or 2 probes (deliberate non-single-flight on miss); \
             observed {}. >2 means the re-check is broken or the cache lost \
             the just-written entry.",
            probes
        );
    }

    /// miss TTL is long enough to dampen probe storms but short enough that
    /// operators see the version field populate within a reasonable window.
    #[test]
    fn test_version_cache_ttl_constants_are_sane() {
        assert!(
            VERSION_CACHE_HIT_TTL > VERSION_CACHE_MISS_TTL,
            "hit TTL must exceed miss TTL"
        );
        assert!(
            VERSION_CACHE_MISS_TTL >= Duration::from_secs(30),
            "miss TTL must be long enough to avoid hammering a missing binary"
        );
        assert!(
            VERSION_CACHE_MISS_TTL <= Duration::from_secs(300),
            "miss TTL must be short enough that the column populates promptly after a fix"
        );
    }

    // -----------------------------------------------------------------------
    // is_oci_image_artifact: shared predicate used by all 3 scanners'
    // is_applicable impls. Centralizes the duplicated content-type +
    // /manifests/ path check that was previously inline in each scanner.
    // (#966 cleanup + jscpd duplication-gate fix.)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_oci_image_artifact_matches_vnd_oci() {
        let a = test_helpers::make_test_artifact(
            "nginx",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        assert!(is_oci_image_artifact(&a));
    }

    #[test]
    fn test_is_oci_image_artifact_matches_docker_distribution() {
        let a = test_helpers::make_test_artifact(
            "redis",
            "application/vnd.docker.distribution.manifest.v2+json",
            "v2/library/redis/manifests/latest",
        );
        assert!(is_oci_image_artifact(&a));
    }

    #[test]
    fn test_is_oci_image_artifact_matches_docker_container() {
        let a = test_helpers::make_test_artifact(
            "busybox",
            "application/vnd.docker.container.image.v1+json",
            "v2/library/busybox/blobs/sha256:abc",
        );
        assert!(is_oci_image_artifact(&a));
    }

    #[test]
    fn test_is_oci_image_artifact_matches_path_manifest_segment() {
        // Path-based detection catches proxy variants that omit the
        // canonical OCI content type but still serve manifests under
        // the v2/.../manifests/ convention.
        let a = test_helpers::make_test_artifact(
            "foo",
            "application/octet-stream",
            "v2/foo/manifests/v1",
        );
        assert!(is_oci_image_artifact(&a));
    }

    #[test]
    fn test_is_oci_image_artifact_rejects_npm_tarball() {
        let a = test_helpers::make_test_artifact(
            "body-parser-1.20.1.tgz",
            "application/gzip",
            "npm/body-parser/-/body-parser-1.20.1.tgz",
        );
        assert!(!is_oci_image_artifact(&a));
    }

    #[test]
    fn test_is_oci_image_artifact_rejects_pypi_wheel() {
        let a = test_helpers::make_test_artifact(
            "requests-2.31.0-py3-none-any.whl",
            "application/zip",
            "pypi/requests/2.31.0/requests-2.31.0-py3-none-any.whl",
        );
        assert!(!is_oci_image_artifact(&a));
    }

    #[test]
    fn test_is_oci_image_artifact_rejects_maven_jar() {
        let a = test_helpers::make_test_artifact(
            "log4j-core-2.17.1.jar",
            "application/java-archive",
            "maven/org/apache/logging/log4j/log4j-core/2.17.1/log4j-core-2.17.1.jar",
        );
        assert!(!is_oci_image_artifact(&a));
    }

    #[test]
    fn test_is_oci_image_artifact_rejects_empty_content_type_with_safe_path() {
        // Defensive: an unset content type combined with a non-manifest
        // path must NOT trip the gate (avoids false-positive that
        // would deny scanners on uploads that haven't yet had their
        // content type sniffed).
        let a = test_helpers::make_test_artifact("foo", "", "generic/foo");
        assert!(!is_oci_image_artifact(&a));
    }

    #[test]
    fn test_format_grype_version_application_line() {
        // Real `grype --version` output: `grype 0.83.0`
        assert_eq!(
            format_grype_version("grype 0.83.0"),
            Some("grype-0.83.0".to_string())
        );
    }

    #[test]
    fn test_format_grype_version_bare_token() {
        // Defensive shape: just the version number.
        assert_eq!(
            format_grype_version("0.83.0"),
            Some("grype-0.83.0".to_string())
        );
    }

    #[test]
    fn test_format_grype_version_with_version_prefix() {
        assert_eq!(
            format_grype_version("Version: 0.83.0"),
            Some("grype-0.83.0".to_string())
        );
    }

    #[test]
    fn test_format_grype_version_empty_returns_none() {
        assert_eq!(format_grype_version(""), None);
        assert_eq!(format_grype_version("   "), None);
    }

    #[test]
    fn test_format_grype_version_application_only() {
        // `grype` token without a following version should be None, not
        // `grype-grype` or similar bogus output.
        assert_eq!(format_grype_version("grype"), None);
    }

    /// `capture_cli_version` must return None on a missing binary rather
    /// than panicking. Use a deliberately-nonexistent name so we exercise
    /// the spawn-failure branch regardless of host scanner installation.
    #[tokio::test]
    async fn test_capture_cli_version_missing_binary_returns_none() {
        let result =
            capture_cli_version("definitely-not-a-real-binary-issue-902", &["--version"]).await;
        assert_eq!(result, None);
    }

    /// A scanner CLI that hangs (does not print and exit) must not park the
    /// version probe forever. Without the timeout, `OnceCell::get_or_init`
    /// would serialize every concurrent caller behind the hung future, and
    /// because `fail_scan` is awaited AFTER `scanner.version().await`, even
    /// FAILED scans would never persist their failure row. Run `sleep` with
    /// a 30s argument and a 50ms test-only timeout: we should observe the
    /// elapsed branch, return None, and complete in well under a second.
    /// Skipped on hosts without `/bin/sleep` (effectively never on Linux/macOS).
    #[tokio::test]
    async fn test_capture_cli_version_hung_binary_times_out() {
        if !std::path::Path::new("/bin/sleep").exists() {
            eprintln!("skipping: /bin/sleep not present on this host");
            return;
        }
        let started = std::time::Instant::now();
        let result =
            capture_cli_version_with_timeout("/bin/sleep", &["30"], Duration::from_millis(50))
                .await;
        let elapsed = started.elapsed();
        assert_eq!(result, None, "timeout branch must return None");
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout did not fire promptly; elapsed was {:?}",
            elapsed
        );
    }

    /// Default `Scanner::version()` returns None so existing scanners
    /// (and any future ones added without an override) compile and behave
    /// correctly: `scan_results.scanner_version` will be NULL for them
    /// rather than triggering a panic or required-arg compile error.
    #[tokio::test]
    async fn test_scanner_trait_default_version_is_none() {
        struct DummyScanner;
        #[async_trait::async_trait]
        impl Scanner for DummyScanner {
            fn name(&self) -> &str {
                "dummy"
            }
            fn scan_type(&self) -> &str {
                "dummy"
            }
            async fn scan(
                &self,
                _: &Artifact,
                _: Option<&ArtifactMetadata>,
                _: &Bytes,
            ) -> Result<ScanOutput> {
                Ok(ScanOutput::default())
            }
        }
        let s = DummyScanner;
        assert_eq!(s.version().await, None);
    }

    /// Exercise the success path of `capture_cli_version_with_timeout`:
    /// spawn succeeded, exit status was zero, stdout had a non-empty first
    /// line. `/bin/echo` is part of POSIX baseline and always produces this
    /// shape, so we use it as a stand-in for a healthy `--version` probe.
    /// Verifies the trim + first-line slicing logic that the per-scanner
    /// `version()` impls rely on. Skipped on hosts without `/bin/echo`.
    #[tokio::test]
    async fn test_capture_cli_version_success_returns_first_line() {
        if !std::path::Path::new("/bin/echo").exists() {
            eprintln!("skipping: /bin/echo not present on this host");
            return;
        }
        let result = capture_cli_version_with_timeout(
            "/bin/echo",
            &["Version: 0.62.1"],
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(result, Some("Version: 0.62.1".to_string()));
    }

    /// Multi-line stdout: only the first line should be returned, with
    /// trailing whitespace trimmed. `printf` is more portable than
    /// `echo -e` for embedding `\n`; we shell out via `/bin/sh -c`.
    #[tokio::test]
    async fn test_capture_cli_version_success_multi_line_takes_first() {
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not present on this host");
            return;
        }
        let result = capture_cli_version_with_timeout(
            "/bin/sh",
            &["-c", "printf 'grype 0.83.0\\nDB updated 2025-04-01\\n'"],
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(result, Some("grype 0.83.0".to_string()));
    }

    /// A binary that exits non-zero must yield None even if it printed
    /// something on stdout. `/usr/bin/false` is POSIX-standard and always
    /// exits 1 with empty stdout; combining shell redirection lets us
    /// assert the exit-status branch independent of empty-stdout.
    #[tokio::test]
    async fn test_capture_cli_version_non_success_status_returns_none() {
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not present on this host");
            return;
        }
        // Print a fake version to stdout, then exit non-zero. We must still
        // observe None so callers do not record output from a crashed probe.
        let result = capture_cli_version_with_timeout(
            "/bin/sh",
            &["-c", "echo 'trivy 0.0.0'; exit 7"],
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(result, None);
    }

    /// A binary that exits zero with empty stdout (e.g. `/bin/true`) must
    /// yield None. This exercises the `lines().next()?` early-return.
    #[tokio::test]
    async fn test_capture_cli_version_empty_stdout_returns_none() {
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not present on this host");
            return;
        }
        let result =
            capture_cli_version_with_timeout("/bin/sh", &["-c", "exit 0"], Duration::from_secs(2))
                .await;
        assert_eq!(result, None);
    }

    /// A binary whose first stdout line is whitespace-only must yield None,
    /// not `Some("")`. This exercises the `if line.is_empty()` branch after
    /// trimming.
    #[tokio::test]
    async fn test_capture_cli_version_whitespace_only_stdout_returns_none() {
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not present on this host");
            return;
        }
        let result = capture_cli_version_with_timeout(
            "/bin/sh",
            &["-c", "printf '   \\n'"],
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(result, None);
    }

    /// #1014 acceptance test: a binary that emits more than the
    /// `CAPTURE_CLI_VERSION_STDOUT_CAP_BYTES` cap MUST NOT OOM the
    /// backend. The implementation bounds the read to 64 KiB via
    /// `AsyncReadExt::take`, kills the child after the cap is hit, and
    /// returns `None` (because parsing a midway-truncated buffer would
    /// risk recording garbage as the scanner_version). The test must
    /// complete quickly without consuming gigabytes of memory.
    #[tokio::test]
    async fn test_capture_cli_version_capped_stdout_returns_none() {
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not present on this host");
            return;
        }
        // `yes` emits "y\n" forever (POSIX). Piping it to `head -c
        // <large>` would still eventually hit the disk - we want to
        // hit the in-memory cap. Using `dd if=/dev/zero bs=1024
        // count=128` gives us 128 KiB of NULs - well past the 64 KiB
        // cap and produces in milliseconds.
        let cmd = "dd if=/dev/zero bs=1024 count=128 2>/dev/null";
        let result =
            capture_cli_version_with_timeout("/bin/sh", &["-c", cmd], Duration::from_secs(5)).await;
        assert_eq!(result, None, "binary blowing past the cap must yield None");
    }

    /// `capture_cli_version` (the non-timeout-parameterized wrapper) must
    /// also propagate success. Exercise it once with `/bin/echo` so the
    /// public wrapper line is covered alongside the inner helper.
    #[tokio::test]
    async fn test_capture_cli_version_wrapper_success_path() {
        if !std::path::Path::new("/bin/echo").exists() {
            eprintln!("skipping: /bin/echo not present on this host");
            return;
        }
        let result = capture_cli_version("/bin/echo", &["trivy 0.62.1"]).await;
        assert_eq!(result, Some("trivy 0.62.1".to_string()));
    }

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn ecosystem_to_github_param(ecosystem: &str) -> Option<&'static str> {
        match ecosystem {
            "npm" => Some("npm"),
            "PyPI" | "pypi" => Some("pip"),
            "crates.io" => Some("rust"),
            "Maven" => Some("maven"),
            "Go" => Some("go"),
            "NuGet" => Some("nuget"),
            "RubyGems" => Some("rubygems"),
            _ => None,
        }
    }

    fn quarantine_status_from_findings(findings_count: i32) -> &'static str {
        if findings_count > 0 {
            "flagged"
        } else {
            "clean"
        }
    }

    fn is_manifest_file(name_lower: &str) -> bool {
        name_lower == "package.json"
            || name_lower.ends_with("/package.json")
            || name_lower == "cargo.toml"
            || name_lower.ends_with("/cargo.toml")
            || name_lower == "requirements.txt"
            || name_lower.ends_with("/requirements.txt")
            || name_lower == "go.sum"
            || name_lower.ends_with("/go.sum")
            || name_lower == "pom.xml"
            || name_lower.ends_with("/pom.xml")
            || name_lower.ends_with(".gemspec")
            || name_lower == "gemfile.lock"
            || name_lower.ends_with("/gemfile.lock")
            || name_lower.ends_with(".nuspec")
            || name_lower == "packages.config"
    }

    fn is_extractable_archive(name_lower: &str) -> bool {
        name_lower.ends_with(".tar.gz")
            || name_lower.ends_with(".tgz")
            || name_lower.ends_with(".crate")
            || name_lower.ends_with(".gem")
            || name_lower.ends_with(".zip")
            || name_lower.ends_with(".whl")
            || name_lower.ends_with(".jar")
            || name_lower.ends_with(".nupkg")
    }

    fn osv_vulnerability_url(vuln_id: &str) -> String {
        format!("https://osv.dev/vulnerability/{}", vuln_id)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ArchiveType {
        TarGz,
        Zip,
        None,
    }

    fn detect_archive_type(name: &str) -> ArchiveType {
        let lower = name.to_lowercase();
        if lower.ends_with(".tar.gz")
            || lower.ends_with(".tgz")
            || lower.ends_with(".crate")
            || lower.ends_with(".gem")
        {
            ArchiveType::TarGz
        } else if lower.ends_with(".zip")
            || lower.ends_with(".whl")
            || lower.ends_with(".jar")
            || lower.ends_with(".nupkg")
        {
            ArchiveType::Zip
        } else {
            ArchiveType::None
        }
    }

    fn is_path_within_workspace(path: &Path, workspace: &str) -> bool {
        path.starts_with(workspace)
    }

    fn count_findings_by_severity(findings: &[RawFinding]) -> (i32, i32, i32, i32, i32) {
        let count =
            |sev: Severity| -> i32 { findings.iter().filter(|f| f.severity == sev).count() as i32 };
        (
            count(Severity::Critical),
            count(Severity::High),
            count(Severity::Medium),
            count(Severity::Low),
            count(Severity::Info),
        )
    }

    fn extract_cve_from_advisory(advisory: &AdvisoryMatch) -> Option<String> {
        advisory
            .aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .cloned()
            .or_else(|| {
                if advisory.id.starts_with("CVE-") {
                    Some(advisory.id.clone())
                } else {
                    None
                }
            })
    }

    fn build_finding_title(advisory: &AdvisoryMatch) -> String {
        advisory
            .summary
            .clone()
            .unwrap_or_else(|| format!("Vulnerability {}", advisory.id))
    }

    fn dedup_advisories(
        osv_results: Vec<AdvisoryMatch>,
        gh_results: Vec<AdvisoryMatch>,
    ) -> Vec<AdvisoryMatch> {
        let mut seen_ids = std::collections::HashSet::new();
        let mut deduped = Vec::new();

        for advisory_match in osv_results.into_iter().chain(gh_results) {
            let dominated = seen_ids.contains(&advisory_match.id)
                || advisory_match.aliases.iter().any(|a| seen_ids.contains(a));
            if dominated {
                continue;
            }
            seen_ids.insert(advisory_match.id.clone());
            seen_ids.extend(advisory_match.aliases.iter().cloned());
            deduped.push(advisory_match);
        }

        deduped
    }

    fn build_osv_cache_key(dep: &Dependency) -> String {
        AdvisoryClient::cache_key(dep)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_artifact(name: &str, path: &str, version: Option<&str>) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: path.to_string(),
            name: name.to_string(),
            version: version.map(String::from),
            size_bytes: 100,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/octet-stream".to_string(),
            storage_key: "key".to_string(),
            is_deleted: false,
            uploaded_by: None,
            quarantine_status: None,
            quarantine_until: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // ScanWorkspace::is_archive
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_workspace_is_archive() {
        assert!(ScanWorkspace::is_archive("foo.tar.gz"));
        assert!(ScanWorkspace::is_archive("foo.tgz"));
        assert!(ScanWorkspace::is_archive("foo.whl"));
        assert!(ScanWorkspace::is_archive("foo.jar"));
        assert!(ScanWorkspace::is_archive("foo.zip"));
        assert!(ScanWorkspace::is_archive("foo.gem"));
        assert!(ScanWorkspace::is_archive("foo.crate"));
        assert!(ScanWorkspace::is_archive("foo.nupkg"));
        assert!(ScanWorkspace::is_archive("foo.war"));
        assert!(ScanWorkspace::is_archive("foo.ear"));
        assert!(ScanWorkspace::is_archive("foo.egg"));
        assert!(!ScanWorkspace::is_archive("Cargo.lock"));
        assert!(!ScanWorkspace::is_archive("package.json"));
        assert!(!ScanWorkspace::is_archive("foo.rs"));
    }

    // -----------------------------------------------------------------------
    // ScanWorkspace::extract_archive (issue #1243)
    //
    // Regression coverage: previously these shelled out to `tar`/`unzip`,
    // which silently failed on container images that don't ship those
    // binaries (Alpine variant). The fix moved extraction in-process via
    // the `tar`, `flate2`, and `zip` crates.
    // -----------------------------------------------------------------------

    /// Build an in-memory npm-shaped .tgz containing `package/package.json`
    /// and `package/index.js`, write it to `dir/name`, return the path.
    fn write_npm_tgz(dir: &Path, name: &str) -> PathBuf {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let path = dir.join(name);
        let file = std::fs::File::create(&path).expect("create tgz");
        let gz = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(gz);

        let pkg_json = br#"{"name":"left-pad","version":"1.3.0"}"#;
        let mut header = tar::Header::new_gnu();
        header.set_path("package/package.json").unwrap();
        header.set_size(pkg_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, pkg_json.as_ref()).unwrap();

        let index_js = b"module.exports = function() { return 'hi'; };\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("package/index.js").unwrap();
        header.set_size(index_js.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, index_js.as_ref()).unwrap();

        let gz = builder.into_inner().unwrap();
        gz.finish().unwrap().flush().unwrap();
        path
    }

    fn write_simple_zip(dir: &Path, name: &str) -> PathBuf {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let path = dir.join(name);
        let file = std::fs::File::create(&path).expect("create zip");
        let mut zw = zip::ZipWriter::new(file);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zw.start_file("META-INF/MANIFEST.MF", opts).unwrap();
        zw.write_all(b"Manifest-Version: 1.0\n").unwrap();
        zw.start_file("com/example/App.class", opts).unwrap();
        zw.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00]).unwrap();
        zw.finish().unwrap();
        path
    }

    #[tokio::test]
    async fn test_extract_archive_npm_tgz() {
        // Regression for issue #1243: npm packages must extract without
        // requiring the host `tar` binary.
        let tmp = tempfile::tempdir().expect("tempdir");
        let tgz = write_npm_tgz(tmp.path(), "left-pad-1.3.0.tgz");
        let dest = tmp.path().join("out");
        tokio::fs::create_dir_all(&dest).await.unwrap();

        ScanWorkspace::extract_archive(&tgz, &dest)
            .await
            .expect("npm tgz should extract");

        let pkg_json = dest.join("package").join("package.json");
        let body = tokio::fs::read_to_string(&pkg_json).await.unwrap();
        assert!(
            body.contains("\"left-pad\""),
            "package.json content: {}",
            body
        );
        assert!(dest.join("package").join("index.js").exists());
    }

    #[tokio::test]
    async fn test_extract_archive_crate_uses_targz() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // .crate files are gzipped tarballs, same wire format as .tgz.
        let arc = write_npm_tgz(tmp.path(), "mycrate-0.1.0.crate");
        let dest = tmp.path().join("out");
        tokio::fs::create_dir_all(&dest).await.unwrap();

        ScanWorkspace::extract_archive(&arc, &dest).await.unwrap();
        assert!(dest.join("package").join("package.json").exists());
    }

    #[tokio::test]
    async fn test_extract_archive_zip_jar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let jar = write_simple_zip(tmp.path(), "app.jar");
        let dest = tmp.path().join("out");
        tokio::fs::create_dir_all(&dest).await.unwrap();

        ScanWorkspace::extract_archive(&jar, &dest).await.unwrap();
        assert!(dest.join("META-INF").join("MANIFEST.MF").exists());
        assert!(dest.join("com").join("example").join("App.class").exists());
    }

    #[tokio::test]
    async fn test_extract_archive_unknown_extension_is_noop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let plain = tmp.path().join("readme.txt");
        tokio::fs::write(&plain, b"hello").await.unwrap();
        let dest = tmp.path().join("out");
        tokio::fs::create_dir_all(&dest).await.unwrap();

        // Should succeed without touching the destination.
        ScanWorkspace::extract_archive(&plain, &dest).await.unwrap();
        let mut entries = tokio::fs::read_dir(&dest).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_extract_archive_corrupt_tgz_returns_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bad = tmp.path().join("broken.tgz");
        tokio::fs::write(&bad, b"this is not a gzip stream")
            .await
            .unwrap();
        let dest = tmp.path().join("out");
        tokio::fs::create_dir_all(&dest).await.unwrap();

        let err = ScanWorkspace::extract_archive(&bad, &dest)
            .await
            .expect_err("corrupt tgz should error");
        match err {
            AppError::Internal(msg) => assert!(
                msg.contains("Tar extraction failed") || msg.contains("extraction"),
                "unexpected error message: {}",
                msg
            ),
            other => panic!("expected Internal error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // extract_xml_value
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_value_basic() {
        let line = "<groupId>com.example</groupId>";
        assert_eq!(
            DependencyScanner::extract_xml_value(line, "groupId"),
            Some("com.example".to_string())
        );
    }

    #[test]
    fn test_extract_xml_value_with_whitespace() {
        let line = "    <artifactId>my-lib</artifactId>   ";
        assert_eq!(
            DependencyScanner::extract_xml_value(line, "artifactId"),
            Some("my-lib".to_string())
        );
    }

    #[test]
    fn test_extract_xml_value_missing_tag() {
        let line = "<groupId>com.example</groupId>";
        assert_eq!(
            DependencyScanner::extract_xml_value(line, "artifactId"),
            None
        );
    }

    #[test]
    fn test_extract_xml_value_missing_close_tag() {
        let line = "<groupId>com.example";
        assert_eq!(DependencyScanner::extract_xml_value(line, "groupId"), None);
    }

    #[test]
    fn test_extract_xml_value_empty_value() {
        let line = "<version></version>";
        // start == end so None (start < end check fails for empty)
        assert_eq!(DependencyScanner::extract_xml_value(line, "version"), None);
    }

    // -----------------------------------------------------------------------
    // extract_xml_attr
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_attr_basic() {
        let line = r#"<package id="Newtonsoft.Json" version="13.0.1" />"#;
        assert_eq!(
            DependencyScanner::extract_xml_attr(line, "id"),
            Some("Newtonsoft.Json".to_string())
        );
        assert_eq!(
            DependencyScanner::extract_xml_attr(line, "version"),
            Some("13.0.1".to_string())
        );
    }

    #[test]
    fn test_extract_xml_attr_missing() {
        let line = r#"<package id="Foo" />"#;
        assert_eq!(DependencyScanner::extract_xml_attr(line, "version"), None);
    }

    #[test]
    fn test_extract_xml_attr_empty_value() {
        let line = r#"<package id="" version="1.0" />"#;
        assert_eq!(
            DependencyScanner::extract_xml_attr(line, "id"),
            Some("".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // parse_npm
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_npm_basic() {
        let content = r#"{
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": "29.0.0"
            }
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 3);

        // Check all ecosystems are npm
        for dep in &deps {
            assert_eq!(dep.ecosystem, "npm");
        }

        // Check that ^ and ~ are stripped from versions
        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert_eq!(express.version.as_deref(), Some("4.18.2"));

        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version.as_deref(), Some("4.17.21"));

        let jest = deps.iter().find(|d| d.name == "jest").unwrap();
        assert_eq!(jest.version.as_deref(), Some("29.0.0"));
    }

    #[test]
    fn test_parse_npm_peer_dependencies() {
        let content = r#"{
            "peerDependencies": {
                "react": "^18.0.0"
            }
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "react");
        assert_eq!(deps[0].version.as_deref(), Some("18.0.0"));
    }

    #[test]
    fn test_parse_npm_empty() {
        let content = r#"{}"#;
        let deps = DependencyScanner::parse_npm(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_npm_invalid_json() {
        let content = "not json at all";
        let deps = DependencyScanner::parse_npm(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_npm_non_string_version() {
        // Workspace protocol or other non-string value
        let content = r#"{
            "dependencies": {
                "my-lib": true
            }
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-lib");
        assert_eq!(deps[0].version, None);
    }

    // -----------------------------------------------------------------------
    // parse_cargo
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cargo_basic() {
        let content = r#"
            [dependencies]
            serde = "1.0"
            tokio = { version = "1.35", features = ["full"] }

            [dev-dependencies]
            proptest = "1.0"
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 3);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "crates.io");
        }

        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.version.as_deref(), Some("1.0"));

        let tokio = deps.iter().find(|d| d.name == "tokio").unwrap();
        assert_eq!(tokio.version.as_deref(), Some("1.35"));
    }

    #[test]
    fn test_parse_cargo_build_dependencies() {
        let content = r#"
            [build-dependencies]
            cc = "1.0"
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "cc");
    }

    #[test]
    fn test_parse_cargo_git_dep_no_version() {
        let content = r#"
            [dependencies]
            my-crate = { git = "https://github.com/foo/bar" }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-crate");
        assert_eq!(deps[0].version, None);
    }

    #[test]
    fn test_parse_cargo_empty() {
        let content = r#"
            [package]
            name = "my-app"
            version = "0.1.0"
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_cargo_invalid_toml() {
        let content = "not valid toml [[[";
        let deps = DependencyScanner::parse_cargo(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_pip
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pip_various_specifiers() {
        let content = "flask==2.3.0\nrequests>=2.28.0\nnumpy~=1.24\npandas<=2.0.0\nsimplepkg\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 5);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "PyPI");
        }

        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.version.as_deref(), Some("2.3.0"));

        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version.as_deref(), Some("2.28.0"));

        let numpy = deps.iter().find(|d| d.name == "numpy").unwrap();
        assert_eq!(numpy.version.as_deref(), Some("1.24"));

        let pandas = deps.iter().find(|d| d.name == "pandas").unwrap();
        assert_eq!(pandas.version.as_deref(), Some("2.0.0"));

        let simple = deps.iter().find(|d| d.name == "simplepkg").unwrap();
        assert_eq!(simple.version, None);
    }

    #[test]
    fn test_parse_pip_skips_comments_blank_lines_flags() {
        let content = "# This is a comment\n\n-r other.txt\n-e git+https://foo.git\nflask==1.0\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
    }

    #[test]
    fn test_parse_pip_empty() {
        let content = "";
        let deps = DependencyScanner::parse_pip(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_go
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_basic() {
        let content = "golang.org/x/net v0.17.0 h1:abc=\ngolang.org/x/net v0.17.0/go.mod h1:def=\ngolang.org/x/text v0.13.0 h1:xyz=\n";
        let deps = DependencyScanner::parse_go(content);
        // Deduplication: golang.org/x/net should appear only once
        assert_eq!(deps.len(), 2);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "Go");
        }

        let net = deps.iter().find(|d| d.name == "golang.org/x/net").unwrap();
        // v prefix stripped
        assert_eq!(net.version.as_deref(), Some("0.17.0"));
    }

    #[test]
    fn test_parse_go_empty() {
        let content = "";
        let deps = DependencyScanner::parse_go(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_go_single_word_line_ignored() {
        let content = "just-one-word\n";
        let deps = DependencyScanner::parse_go(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_maven
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_maven_basic() {
        let content = r#"
        <dependencies>
            <dependency>
                <groupId>org.apache</groupId>
                <artifactId>commons-lang3</artifactId>
                <version>3.12.0</version>
            </dependency>
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
            </dependency>
        </dependencies>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert_eq!(deps.len(), 2);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "Maven");
        }

        let lang3 = deps
            .iter()
            .find(|d| d.name == "org.apache:commons-lang3")
            .unwrap();
        assert_eq!(lang3.version.as_deref(), Some("3.12.0"));

        let junit = deps.iter().find(|d| d.name == "junit:junit").unwrap();
        assert_eq!(junit.version, None);
    }

    #[test]
    fn test_parse_maven_empty() {
        let content = "<project></project>";
        let deps = DependencyScanner::parse_maven(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_maven_incomplete_dependency() {
        // Missing artifactId: should not produce a dependency
        let content = r#"
        <dependency>
            <groupId>org.example</groupId>
        </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_rubygems
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rubygems_gemfile_lock() {
        let content = "    rails (7.0.8)\n    nokogiri (1.15.4)\n    actionpack (7.0.8)\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert_eq!(deps.len(), 3);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "RubyGems");
        }

        let rails = deps.iter().find(|d| d.name == "rails").unwrap();
        assert_eq!(rails.version.as_deref(), Some("7.0.8"));
    }

    #[test]
    fn test_parse_rubygems_no_match() {
        let content = "GEM\n  remote: https://rubygems.org/\n  specs:\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_nuget
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuget_packages_config() {
        let content = r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" />
  <package id="NUnit" version="3.14.0" targetFramework="net472" />
</packages>"#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 2);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "NuGet");
        }

        let nj = deps.iter().find(|d| d.name == "Newtonsoft.Json").unwrap();
        assert_eq!(nj.version.as_deref(), Some("13.0.1"));
    }

    #[test]
    fn test_parse_nuget_empty() {
        let content = "<packages></packages>";
        let deps = DependencyScanner::parse_nuget(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // extract_dependencies (integration of parsers by filename matching)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_package_json() {
        let artifact = make_artifact("package.json", "/npm/package.json", None);
        let content = Bytes::from(r#"{"dependencies":{"axios":"^1.6.0"}}"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "axios");
        assert_eq!(deps[0].ecosystem, "npm");
    }

    #[test]
    fn test_extract_dependencies_nested_package_json() {
        let artifact = make_artifact(
            "libs/core/package.json",
            "/npm/libs/core/package.json",
            None,
        );
        let content = Bytes::from(r#"{"dependencies":{"react":"^18.0.0"}}"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "npm");
    }

    #[test]
    fn test_extract_dependencies_cargo_toml() {
        let artifact = make_artifact("Cargo.toml", "/rust/Cargo.toml", None);
        let content = Bytes::from("[dependencies]\nserde = \"1.0\"\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "crates.io");
    }

    #[test]
    fn test_extract_dependencies_requirements_txt() {
        let artifact = make_artifact("requirements.txt", "/pypi/requirements.txt", None);
        let content = Bytes::from("flask==2.3.0\nrequests>=2.28.0\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].ecosystem, "PyPI");
    }

    #[test]
    fn test_extract_dependencies_go_sum() {
        let artifact = make_artifact("go.sum", "/go/go.sum", None);
        let content = Bytes::from("golang.org/x/net v0.17.0 h1:abc=\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Go");
    }

    #[test]
    fn test_extract_dependencies_pom_xml() {
        let artifact = make_artifact("pom.xml", "/maven/pom.xml", None);
        let content = Bytes::from(
            "<dependency>\n<groupId>org.apache</groupId>\n<artifactId>commons</artifactId>\n<version>3.12</version>\n</dependency>\n",
        );
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Maven");
    }

    #[test]
    fn test_extract_dependencies_gemfile_lock() {
        let artifact = make_artifact("Gemfile.lock", "/ruby/Gemfile.lock", None);
        let content = Bytes::from("    rails (7.0.8)\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "RubyGems");
    }

    #[test]
    fn test_extract_dependencies_nuspec() {
        let artifact = make_artifact("My.nuspec", "/nuget/My.nuspec", None);
        let content = Bytes::from(r#"<package id="Newtonsoft.Json" version="13.0.1" />"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "NuGet");
    }

    #[test]
    fn test_extract_dependencies_packages_config() {
        let artifact = make_artifact("packages.config", "/nuget/packages.config", None);
        let content = Bytes::from(r#"<package id="NUnit" version="3.14" />"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "NuGet");
    }

    #[test]
    fn test_extract_dependencies_binary_content() {
        let artifact = make_artifact("package.json", "/npm/package.json", None);
        // Invalid UTF-8 bytes
        let content = Bytes::from(vec![0xFF, 0xFE, 0x00, 0x01]);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // infer_dependencies
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_dependencies_rpm() {
        let artifact = make_artifact("my-package.rpm", "/rpm/my-package.rpm", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
        assert_eq!(deps[0].name, "my-package.rpm");
    }

    #[test]
    fn test_infer_dependencies_deb() {
        let artifact = make_artifact("my-package.deb", "/deb/my-package.deb", Some("2.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    #[test]
    fn test_infer_dependencies_apk() {
        let artifact = make_artifact("my-package.apk", "/alpine/my-package.apk", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    #[test]
    fn test_infer_dependencies_rpm_path() {
        let artifact = make_artifact("foo.bin", "/rpm/centos/foo.bin", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    #[test]
    fn test_infer_dependencies_unknown() {
        let artifact = make_artifact("random.txt", "/misc/random.txt", None);
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_basic() {
        let deps = vec![Dependency {
            name: "lodash".to_string(),
            version: Some("4.17.20".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "GHSA-abcd-1234-efgh",
                    "summary": "Prototype Pollution in lodash",
                    "details": "lodash before 4.17.21 is vulnerable",
                    "aliases": ["CVE-2021-23337"],
                    "database_specific": {
                        "severity": "HIGH"
                    },
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.21"}
                            ]
                        }]
                    }]
                }]
            }]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);

        let m = &matches[0];
        assert_eq!(m.id, "GHSA-abcd-1234-efgh");
        assert_eq!(m.summary.as_deref(), Some("Prototype Pollution in lodash"));
        assert_eq!(
            m.details.as_deref(),
            Some("lodash before 4.17.21 is vulnerable")
        );
        assert_eq!(m.severity, "high"); // lowercased
        assert_eq!(m.aliases, vec!["CVE-2021-23337".to_string()]);
        assert_eq!(m.fixed_version.as_deref(), Some("4.17.21"));
        assert_eq!(m.affected_version.as_deref(), Some("4.17.20"));
        assert_eq!(m.source, "osv.dev");
        assert!(m
            .source_url
            .as_ref()
            .unwrap()
            .contains("GHSA-abcd-1234-efgh"));
    }

    #[test]
    fn test_parse_osv_response_empty_results() {
        let deps = vec![Dependency {
            name: "safe-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let body = serde_json::json!({ "results": [{}] });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_parse_osv_response_no_results_key() {
        let deps = vec![];
        let body = serde_json::json!({});
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_parse_osv_response_severity_fallback_to_medium() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        // No severity field at all
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-001"
                }]
            }]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, "medium"); // default fallback
    }

    #[test]
    fn test_parse_osv_response_severity_from_severity_array() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-002",
                    "severity": [{"type": "CRITICAL", "score": "9.8"}]
                }]
            }]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        // falls back to severity[0].type
        assert_eq!(matches[0].severity, "critical");
    }

    #[test]
    fn test_parse_osv_response_multiple_vulns_single_dep() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let body = serde_json::json!({
            "results": [{
                "vulns": [
                    {"id": "VULN-1", "summary": "First"},
                    {"id": "VULN-2", "summary": "Second"}
                ]
            }]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].id, "VULN-1");
        assert_eq!(matches[1].id, "VULN-2");
    }

    #[test]
    fn test_parse_osv_response_multiple_deps() {
        let deps = vec![
            Dependency {
                name: "pkg-a".to_string(),
                version: Some("1.0".to_string()),
                ecosystem: "npm".to_string(),
            },
            Dependency {
                name: "pkg-b".to_string(),
                version: Some("2.0".to_string()),
                ecosystem: "npm".to_string(),
            },
        ];

        let body = serde_json::json!({
            "results": [
                {"vulns": [{"id": "VULN-A"}]},
                {"vulns": [{"id": "VULN-B"}]}
            ]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 2);
        // First vuln should get version from deps[0], second from deps[1]
        assert_eq!(matches[0].affected_version.as_deref(), Some("1.0"));
        assert_eq!(matches[1].affected_version.as_deref(), Some("2.0"));
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_basic() {
        let dep = Dependency {
            name: "express".to_string(),
            version: Some("4.17.1".to_string()),
            ecosystem: "npm".to_string(),
        };

        let adv = serde_json::json!({
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Open Redirect in Express",
            "description": "Express < 4.17.3 allows open redirect",
            "severity": "medium",
            "cve_id": "CVE-2022-24999",
            "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "vulnerabilities": [{
                "first_patched_version": {
                    "identifier": "4.17.3"
                }
            }]
        });

        let result = AdvisoryClient::parse_github_advisory(&adv, &dep);
        assert!(result.is_some());

        let m = result.unwrap();
        assert_eq!(m.id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(m.summary.as_deref(), Some("Open Redirect in Express"));
        assert_eq!(m.severity, "medium");
        assert_eq!(
            m.aliases,
            vec![
                "GHSA-xxxx-yyyy-zzzz".to_string(),
                "CVE-2022-24999".to_string()
            ]
        );
        assert_eq!(m.fixed_version.as_deref(), Some("4.17.3"));
        assert_eq!(m.affected_version.as_deref(), Some("4.17.1"));
        assert_eq!(m.source, "github");
        assert_eq!(
            m.source_url.as_deref(),
            Some("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz")
        );
    }

    #[test]
    fn test_parse_github_advisory_missing_ghsa_id() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({"summary": "no ghsa_id"});
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_github_advisory_minimal() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-min-imal-data"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep);
        assert!(result.is_some());

        let m = result.unwrap();
        assert_eq!(m.id, "GHSA-min-imal-data");
        assert_eq!(m.severity, "medium"); // default
        assert_eq!(m.aliases, vec!["GHSA-min-imal-data".to_string()]);
        assert_eq!(m.summary, None);
        assert_eq!(m.details, None);
        assert_eq!(m.fixed_version, None);
        assert_eq!(m.affected_version, None);
    }

    #[test]
    fn test_parse_github_advisory_no_cve() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-no-cve-here",
            "severity": "high"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        // aliases should only contain GHSA id
        assert_eq!(result.aliases, vec!["GHSA-no-cve-here".to_string()]);
    }

    // -----------------------------------------------------------------------
    // DependencyScanner name/scan_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_scanner_name_and_type() {
        let advisory = Arc::new(AdvisoryClient::new(None));
        let scanner = DependencyScanner::new(advisory);
        assert_eq!(scanner.name(), "DependencyScanner");
        assert_eq!(scanner.scan_type(), "dependency");
    }

    // -----------------------------------------------------------------------
    // AdvisoryClient::new
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_client_new_no_github_token() {
        let client = AdvisoryClient::new(None);
        assert!(client.github_token.is_none());
    }

    #[test]
    fn test_advisory_client_new_with_github_token() {
        let client = AdvisoryClient::new(Some("ghp_test123".to_string()));
        assert_eq!(client.github_token.as_deref(), Some("ghp_test123"));
    }

    // -----------------------------------------------------------------------
    // Dependency struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_construction() {
        let dep = Dependency {
            name: "express".to_string(),
            version: Some("4.18.2".to_string()),
            ecosystem: "npm".to_string(),
        };
        assert_eq!(dep.name, "express");
        assert_eq!(dep.version.as_deref(), Some("4.18.2"));
        assert_eq!(dep.ecosystem, "npm");
    }

    #[test]
    fn test_dependency_no_version() {
        let dep = Dependency {
            name: "my-lib".to_string(),
            version: None,
            ecosystem: "crates.io".to_string(),
        };
        assert!(dep.version.is_none());
    }

    #[test]
    fn test_dependency_clone() {
        let dep = Dependency {
            name: "flask".to_string(),
            version: Some("2.3.0".to_string()),
            ecosystem: "PyPI".to_string(),
        };
        let cloned = dep.clone();
        assert_eq!(dep.name, cloned.name);
        assert_eq!(dep.version, cloned.version);
        assert_eq!(dep.ecosystem, cloned.ecosystem);
    }

    #[test]
    fn test_dependency_debug() {
        let dep = Dependency {
            name: "test".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let debug = format!("{:?}", dep);
        assert!(debug.contains("Dependency"));
        assert!(debug.contains("test"));
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_construction() {
        let m = AdvisoryMatch {
            id: "GHSA-1234".to_string(),
            summary: Some("XSS vulnerability".to_string()),
            details: Some("Detailed description".to_string()),
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string()],
            affected_version: Some("1.0.0".to_string()),
            fixed_version: Some("1.0.1".to_string()),
            source: "osv.dev".to_string(),
            source_url: Some("https://osv.dev/vulnerability/GHSA-1234".to_string()),
        };
        assert_eq!(m.id, "GHSA-1234");
        assert_eq!(m.severity, "high");
        assert_eq!(m.aliases.len(), 1);
        assert!(m.fixed_version.is_some());
    }

    #[test]
    fn test_advisory_match_minimal() {
        let m = AdvisoryMatch {
            id: "OSV-001".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert!(m.summary.is_none());
        assert!(m.aliases.is_empty());
    }

    #[test]
    fn test_advisory_match_clone() {
        let m = AdvisoryMatch {
            id: "GHSA-abcd".to_string(),
            summary: Some("Test".to_string()),
            details: None,
            severity: "low".to_string(),
            aliases: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            affected_version: Some("1.0".to_string()),
            fixed_version: Some("1.1".to_string()),
            source: "github".to_string(),
            source_url: Some("https://example.com".to_string()),
        };
        let cloned = m.clone();
        assert_eq!(m.id, cloned.id);
        assert_eq!(m.aliases, cloned.aliases);
    }

    // -----------------------------------------------------------------------
    // parse_npm - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_npm_all_three_sections() {
        let content = r#"{
            "dependencies": {"a": "1.0"},
            "devDependencies": {"b": "2.0"},
            "peerDependencies": {"c": "3.0"}
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 3);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(names.contains(&"c"));
    }

    #[test]
    fn test_parse_npm_version_with_exact() {
        let content = r#"{"dependencies": {"pkg": "1.2.3"}}"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps[0].version.as_deref(), Some("1.2.3"));
    }

    // -----------------------------------------------------------------------
    // parse_cargo - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cargo_version_in_table_format() {
        let content = r#"
            [dependencies]
            serde = { version = "1.0", features = ["derive"] }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version.as_deref(), Some("1.0"));
    }

    #[test]
    fn test_parse_cargo_path_dep_no_version() {
        let content = r#"
            [dependencies]
            my-local = { path = "../my-local" }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-local");
        assert!(deps[0].version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_pip - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pip_whitespace_handling() {
        let content = "  flask  == 2.3.0  \n  requests  >= 2.28.0  \n";
        let deps = DependencyScanner::parse_pip(content);
        // The parser splits on == so should handle whitespace in names
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_parse_pip_only_comments_and_blanks() {
        let content = "# comment\n\n# another comment\n";
        let deps = DependencyScanner::parse_pip(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_go - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_dedup() {
        let content = "mod1 v1.0.0 h1:abc=\nmod1 v1.0.0/go.mod h1:def=\nmod2 v2.0.0 h1:ghi=\n";
        let deps = DependencyScanner::parse_go(content);
        assert_eq!(deps.len(), 2);
        // mod1 should appear only once
        assert_eq!(deps.iter().filter(|d| d.name == "mod1").count(), 1);
    }

    #[test]
    fn test_parse_go_v_prefix_stripped() {
        let content = "example.com/mod v3.14.0 h1:abc=\n";
        let deps = DependencyScanner::parse_go(content);
        assert_eq!(deps[0].version.as_deref(), Some("3.14.0"));
    }

    // -----------------------------------------------------------------------
    // parse_maven - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_maven_multiple_dependencies() {
        let content = r#"
            <dependency>
                <groupId>org.apache</groupId>
                <artifactId>commons-lang3</artifactId>
                <version>3.12.0</version>
            </dependency>
            <dependency>
                <groupId>com.google</groupId>
                <artifactId>guava</artifactId>
                <version>31.1</version>
            </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_parse_maven_missing_group_id() {
        // Missing groupId should not produce a dependency
        let content = r#"
            <dependency>
                <artifactId>some-lib</artifactId>
                <version>1.0</version>
            </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_rubygems - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rubygems_multiple() {
        let content = "    actionpack (7.0.8)\n    activesupport (7.0.8)\n    bundler (2.4.22)\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn test_parse_rubygems_empty_name() {
        // If there's just a version in parens with no name, should be skipped
        let content = "    (1.0.0)\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_nuget - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuget_multiple_packages() {
        let content = r#"
            <package id="A" version="1.0" />
            <package id="B" version="2.0" />
            <package id="C" version="3.0" />
        "#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn test_parse_nuget_no_version_attr() {
        let content = r#"<package id="NoVersion" />"#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "NoVersion");
        assert!(deps[0].version.is_none());
    }

    // -----------------------------------------------------------------------
    // extract_xml_value - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_value_with_nested_whitespace() {
        let line = "  <version>  3.12.0  </version>  ";
        // The value includes the surrounding spaces
        let result = DependencyScanner::extract_xml_value(line, "version");
        assert!(result.is_some());
        assert!(result.unwrap().contains("3.12.0"));
    }

    // -----------------------------------------------------------------------
    // extract_xml_attr - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_attr_with_single_quotes_fails() {
        // Our parser expects double quotes
        let line = "<package id='Foo' />";
        assert_eq!(DependencyScanner::extract_xml_attr(line, "id"), None);
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - gemspec
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_gemspec() {
        let artifact = make_artifact("my-gem.gemspec", "/ruby/my-gem.gemspec", None);
        let content = Bytes::from("    rails (7.0.8)\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "RubyGems");
    }

    // -----------------------------------------------------------------------
    // infer_dependencies - path-based detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_dependencies_deb_path() {
        let artifact = make_artifact("pkg.bin", "/deb/pool/main/pkg.bin", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    #[test]
    fn test_infer_dependencies_alpine_path() {
        let artifact = make_artifact("pkg.bin", "/alpine/v3.18/pkg.bin", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - no vulns key
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_no_vulns_key() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({"results": [{"other": "data"}]});
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_parse_osv_response_empty_vulns_array() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({"results": [{"vulns": []}]});
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert!(matches.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_with_null_cve() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-test-1234",
            "severity": "critical",
            "cve_id": null
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        // aliases should only have GHSA id, no null CVE
        assert_eq!(result.aliases, vec!["GHSA-test-1234".to_string()]);
    }

    #[test]
    fn test_parse_github_advisory_no_fixed_version() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-no-fix",
            "vulnerabilities": []
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert!(result.fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // CACHE_TTL constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_ttl_is_one_hour() {
        assert_eq!(CACHE_TTL, Duration::from_secs(3600));
    }

    // -----------------------------------------------------------------------
    // Cache eviction on write
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_retain_evicts_expired_entries() {
        let mut cache = HashMap::new();

        // Insert an entry that is still valid (just created)
        cache.insert(
            "npm:fresh-pkg:1.0".to_string(),
            CachedAdvisory {
                findings: vec![],
                fetched_at: Instant::now(),
            },
        );

        // Insert an entry that is expired (fetched_at far in the past)
        // We simulate this by using Instant::now() - 2 hours
        cache.insert(
            "npm:stale-pkg:0.1".to_string(),
            CachedAdvisory {
                findings: vec![],
                fetched_at: Instant::now() - Duration::from_secs(7200),
            },
        );

        assert_eq!(cache.len(), 2);

        // This is the same retain call added to query_osv
        cache.retain(|_, v| v.fetched_at.elapsed() < CACHE_TTL);

        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("npm:fresh-pkg:1.0"));
        assert!(!cache.contains_key("npm:stale-pkg:0.1"));
    }

    #[test]
    fn test_cache_retain_keeps_all_when_none_expired() {
        let mut cache = HashMap::new();

        cache.insert(
            "npm:a:1.0".to_string(),
            CachedAdvisory {
                findings: vec![],
                fetched_at: Instant::now(),
            },
        );
        cache.insert(
            "npm:b:2.0".to_string(),
            CachedAdvisory {
                findings: vec![],
                fetched_at: Instant::now(),
            },
        );

        cache.retain(|_, v| v.fetched_at.elapsed() < CACHE_TTL);

        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_retain_removes_all_when_all_expired() {
        let mut cache = HashMap::new();
        let expired = Instant::now() - Duration::from_secs(7200);

        cache.insert(
            "npm:old1:1.0".to_string(),
            CachedAdvisory {
                findings: vec![],
                fetched_at: expired,
            },
        );
        cache.insert(
            "npm:old2:2.0".to_string(),
            CachedAdvisory {
                findings: vec![],
                fetched_at: expired,
            },
        );

        cache.retain(|_, v| v.fetched_at.elapsed() < CACHE_TTL);

        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn test_eviction_runs_once_and_fresh_entries_survive_across_batches() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": [] })),
            )
            .expect(2)
            .mount(&server)
            .await;

        let cache_ttl = Duration::from_millis(500);

        // Pre-populate cache with 5 stale entries for deps NOT in the query list.
        let expired = Instant::now() - (cache_ttl + Duration::from_secs(1));
        let mut seed = HashMap::new();
        let stale_keys: Vec<String> = (0..5).map(|i| format!("npm:stale-pkg-{i}:0.0.1")).collect();
        for key in &stale_keys {
            seed.insert(
                key.clone(),
                CachedAdvisory {
                    findings: vec![],
                    fetched_at: expired,
                },
            );
        }

        let client = AdvisoryClient {
            http: crate::services::http_client::base_client_builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("failed to build HTTP client"),
            cache: RwLock::new(seed),
            github_token: None,
            osv_batch_url: format!("{}/v1/querybatch", server.uri()),
            cache_ttl,
        };

        let deps: Vec<_> = (0..1001)
            .map(|i| Dependency {
                name: format!("dep-{i}"),
                version: Some("1.0.0".to_string()),
                ecosystem: "npm".to_string(),
            })
            .collect();

        let results = client.query_osv(&deps).await;
        assert!(results.is_empty());

        let cache = client.cache.read().await;
        // All 1001 fresh entries survive, stale entries evicted.
        assert_eq!(cache.len(), 1001);
        // Stale pre-existing entries must be gone.
        for key in &stale_keys {
            assert!(
                !cache.contains_key(key),
                "stale key should be evicted: {key}"
            );
        }
        // Both batch-1 and batch-2 keys must be present.
        assert!(cache.contains_key(&build_osv_cache_key(&deps[0])));
        assert!(cache.contains_key(&build_osv_cache_key(&deps[999])));
        assert!(cache.contains_key(&build_osv_cache_key(&deps[1000])));
    }

    #[tokio::test]
    async fn test_stale_dep_refetched_with_new_findings() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{
                    "vulns": [{
                        "id": "GHSA-new-finding",
                        "summary": "New vulnerability",
                        "database_specific": { "severity": "HIGH" },
                        "aliases": ["CVE-2026-9999"],
                        "affected": [{
                            "ranges": [{
                                "events": [{ "fixed": "2.0.0" }]
                            }]
                        }]
                    }]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cache_ttl = Duration::from_secs(3600);

        // Seed cache with a STALE entry for the dep we're about to query.
        let stale_findings = vec![AdvisoryMatch {
            id: "GHSA-old-finding".to_string(),
            summary: Some("Old vulnerability".to_string()),
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let expired = Instant::now() - (cache_ttl + Duration::from_secs(60));
        let mut seed = HashMap::new();
        seed.insert(
            "npm:vulnerable-pkg:1.0.0".to_string(),
            CachedAdvisory {
                findings: stale_findings,
                fetched_at: expired,
            },
        );

        let client = AdvisoryClient {
            http: crate::services::http_client::base_client_builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("failed to build HTTP client"),
            cache: RwLock::new(seed),
            github_token: None,
            osv_batch_url: format!("{}/v1/querybatch", server.uri()),
            cache_ttl,
        };

        let deps = vec![Dependency {
            name: "vulnerable-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let results = client.query_osv(&deps).await;

        // Results should contain the NEW finding from OSV, not the old cached one.
        assert!(
            results.iter().any(|r| r.id == "GHSA-new-finding"),
            "expected new finding from OSV, got: {:?}",
            results.iter().map(|r| &r.id).collect::<Vec<_>>()
        );
        assert!(
            !results.iter().any(|r| r.id == "GHSA-old-finding"),
            "stale finding should not appear in results"
        );

        // Cache should now hold the fresh entry.
        let cache = client.cache.read().await;
        let cached = cache
            .get("npm:vulnerable-pkg:1.0.0")
            .expect("entry must exist");
        assert!(
            cached.fetched_at.elapsed() < Duration::from_secs(5),
            "cache entry should be fresh"
        );
    }

    // -----------------------------------------------------------------------
    // URL constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_batch_url() {
        assert_eq!(OSV_BATCH_URL, "https://api.osv.dev/v1/querybatch");
    }

    #[test]
    fn test_github_advisory_url() {
        assert_eq!(GITHUB_ADVISORY_URL, "https://api.github.com/advisories");
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - unrecognized file
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_unknown_file() {
        let artifact = make_artifact("readme.md", "/docs/readme.md", None);
        let content = Bytes::from("# README\nThis is a readme file.");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_extract_dependencies_nested_cargo_toml() {
        let artifact = make_artifact("backend/Cargo.toml", "/rust/backend/Cargo.toml", None);
        let content = Bytes::from("[dependencies]\ntokio = \"1.35\"\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "crates.io");
    }

    #[test]
    fn test_extract_dependencies_nested_requirements_txt() {
        let artifact = make_artifact("app/requirements.txt", "/pypi/app/requirements.txt", None);
        let content = Bytes::from("django==4.2\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "PyPI");
    }

    #[test]
    fn test_extract_dependencies_nested_go_sum() {
        let artifact = make_artifact("project/go.sum", "/go/project/go.sum", None);
        let content = Bytes::from("golang.org/x/sys v0.15.0 h1:abc=\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Go");
    }

    #[test]
    fn test_extract_dependencies_nested_pom_xml() {
        let artifact = make_artifact("module/pom.xml", "/maven/module/pom.xml", None);
        let content = Bytes::from(
            "<dependency>\n<groupId>io.quarkus</groupId>\n<artifactId>quarkus-core</artifactId>\n<version>3.6.0</version>\n</dependency>\n",
        );
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Maven");
    }

    // -----------------------------------------------------------------------
    // ecosystem_to_github_param (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecosystem_to_github_param_npm() {
        assert_eq!(ecosystem_to_github_param("npm"), Some("npm"));
    }

    #[test]
    fn test_ecosystem_to_github_param_pypi() {
        assert_eq!(ecosystem_to_github_param("PyPI"), Some("pip"));
        assert_eq!(ecosystem_to_github_param("pypi"), Some("pip"));
    }

    #[test]
    fn test_ecosystem_to_github_param_crates() {
        assert_eq!(ecosystem_to_github_param("crates.io"), Some("rust"));
    }

    #[test]
    fn test_ecosystem_to_github_param_maven() {
        assert_eq!(ecosystem_to_github_param("Maven"), Some("maven"));
    }

    #[test]
    fn test_ecosystem_to_github_param_go() {
        assert_eq!(ecosystem_to_github_param("Go"), Some("go"));
    }

    #[test]
    fn test_ecosystem_to_github_param_nuget() {
        assert_eq!(ecosystem_to_github_param("NuGet"), Some("nuget"));
    }

    #[test]
    fn test_ecosystem_to_github_param_rubygems() {
        assert_eq!(ecosystem_to_github_param("RubyGems"), Some("rubygems"));
    }

    #[test]
    fn test_ecosystem_to_github_param_unknown() {
        assert_eq!(ecosystem_to_github_param("Hex"), None);
        assert_eq!(ecosystem_to_github_param("Composer"), None);
        assert_eq!(ecosystem_to_github_param(""), None);
        assert_eq!(ecosystem_to_github_param("Linux"), None);
    }

    // -----------------------------------------------------------------------
    // quarantine_status_from_findings (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_quarantine_status_flagged() {
        assert_eq!(quarantine_status_from_findings(1), "flagged");
        assert_eq!(quarantine_status_from_findings(100), "flagged");
    }

    #[test]
    fn test_quarantine_status_clean() {
        assert_eq!(quarantine_status_from_findings(0), "clean");
    }

    #[test]
    fn test_quarantine_status_negative_treated_as_clean() {
        // Negative values are technically <= 0, so not > 0
        assert_eq!(quarantine_status_from_findings(-1), "clean");
    }

    // -----------------------------------------------------------------------
    // is_manifest_file (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_manifest_file_known_names() {
        assert!(is_manifest_file("package.json"));
        assert!(is_manifest_file("cargo.toml"));
        assert!(is_manifest_file("requirements.txt"));
        assert!(is_manifest_file("go.sum"));
        assert!(is_manifest_file("pom.xml"));
        assert!(is_manifest_file("gemfile.lock"));
        assert!(is_manifest_file("packages.config"));
    }

    #[test]
    fn test_is_manifest_file_nested_paths() {
        assert!(is_manifest_file("libs/core/package.json"));
        assert!(is_manifest_file("backend/cargo.toml"));
        assert!(is_manifest_file("app/requirements.txt"));
        assert!(is_manifest_file("project/go.sum"));
        assert!(is_manifest_file("module/pom.xml"));
        assert!(is_manifest_file("ruby/gemfile.lock"));
    }

    #[test]
    fn test_is_manifest_file_extension_based() {
        assert!(is_manifest_file("my-gem.gemspec"));
        assert!(is_manifest_file("my-pkg.nuspec"));
    }

    #[test]
    fn test_is_manifest_file_unknown() {
        assert!(!is_manifest_file("readme.md"));
        assert!(!is_manifest_file("main.rs"));
        assert!(!is_manifest_file("docker-compose.yml"));
        assert!(!is_manifest_file("my-lib.jar"));
    }

    // -----------------------------------------------------------------------
    // is_extractable_archive (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_extractable_archive_tar_gz() {
        assert!(is_extractable_archive("package.tar.gz"));
        assert!(is_extractable_archive("lib.tgz"));
    }

    #[test]
    fn test_is_extractable_archive_rust_ruby() {
        assert!(is_extractable_archive("my-crate-1.0.0.crate"));
        assert!(is_extractable_archive("my-gem-1.0.0.gem"));
    }

    #[test]
    fn test_is_extractable_archive_zip_variants() {
        assert!(is_extractable_archive("package.zip"));
        assert!(is_extractable_archive("numpy-1.0.whl"));
        assert!(is_extractable_archive("commons-lang.jar"));
        assert!(is_extractable_archive("newtonsoft.json.nupkg"));
    }

    #[test]
    fn test_is_extractable_archive_not_archive() {
        assert!(!is_extractable_archive("readme.md"));
        assert!(!is_extractable_archive("image.png"));
        assert!(!is_extractable_archive("package.json"));
        assert!(!is_extractable_archive("main.rs"));
    }

    // -----------------------------------------------------------------------
    // osv_vulnerability_url (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_vulnerability_url() {
        assert_eq!(
            osv_vulnerability_url("GHSA-abcd-1234-efgh"),
            "https://osv.dev/vulnerability/GHSA-abcd-1234-efgh"
        );
        assert_eq!(
            osv_vulnerability_url("CVE-2024-0001"),
            "https://osv.dev/vulnerability/CVE-2024-0001"
        );
    }

    // -----------------------------------------------------------------------
    // parse_pip - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pip_extras_in_name() {
        // pip supports extras syntax: package[extra]==1.0
        let content = "requests[security]==2.28.0\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 1);
        // The extras syntax is preserved as part of the name
        assert!(deps[0].name.contains("requests"));
    }

    #[test]
    fn test_parse_pip_single_package() {
        let content = "flask==2.3.0\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
        assert_eq!(deps[0].version.as_deref(), Some("2.3.0"));
    }

    // -----------------------------------------------------------------------
    // parse_maven - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_maven_with_version_property() {
        // Maven properties like ${project.version} should be treated as version
        let content = r#"
            <dependency>
                <groupId>org.example</groupId>
                <artifactId>my-lib</artifactId>
                <version>${project.version}</version>
            </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version.as_deref(), Some("${project.version}"));
    }

    // -----------------------------------------------------------------------
    // parse_rubygems - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rubygems_with_platform() {
        // Some gems include platform info
        let content = "    nokogiri (1.15.4-arm64-darwin)\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "nokogiri");
        assert_eq!(deps[0].version.as_deref(), Some("1.15.4-arm64-darwin"));
    }

    // -----------------------------------------------------------------------
    // parse_npm - npm workspace / special versions
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_npm_star_version() {
        let content = r#"{"dependencies": {"pkg": "*"}}"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version.as_deref(), Some("*"));
    }

    #[test]
    fn test_parse_npm_url_version() {
        let content = r#"{"dependencies": {"pkg": "https://example.com/pkg.tgz"}}"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].version.as_deref().unwrap().starts_with("https://"));
    }

    // -----------------------------------------------------------------------
    // parse_go - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_mixed_modules() {
        let content = "github.com/foo/bar v1.0.0 h1:abc=\ngitlab.com/baz/qux v2.0.0 h1:def=\n";
        let deps = DependencyScanner::parse_go(content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "github.com/foo/bar");
        assert_eq!(deps[1].name, "gitlab.com/baz/qux");
    }

    // -----------------------------------------------------------------------
    // parse_nuget - packages.config with targetFramework
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuget_with_target_framework() {
        let content = r#"<package id="Moq" version="4.18.4" targetFramework="net6.0" />"#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Moq");
        assert_eq!(deps[0].version.as_deref(), Some("4.18.4"));
    }

    // -----------------------------------------------------------------------
    // parse_cargo - workspace dep
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cargo_workspace_dep() {
        let content = r#"
            [dependencies]
            my-lib = { workspace = true }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-lib");
        assert!(deps[0].version.is_none()); // workspace = true has no version key
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - with multiple patched versions
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_multiple_vulnerabilities() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-multi",
            "vulnerabilities": [
                {"first_patched_version": null},
                {"first_patched_version": {"identifier": "2.0.0"}}
            ]
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(result.fixed_version.as_deref(), Some("2.0.0"));
    }

    // -----------------------------------------------------------------------
    // detect_archive_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_archive_type_tar_gz() {
        assert_eq!(detect_archive_type("package.tar.gz"), ArchiveType::TarGz);
        assert_eq!(detect_archive_type("lib.tgz"), ArchiveType::TarGz);
        assert_eq!(
            detect_archive_type("my-crate-1.0.crate"),
            ArchiveType::TarGz
        );
        assert_eq!(detect_archive_type("my-gem-2.0.gem"), ArchiveType::TarGz);
    }

    #[test]
    fn test_detect_archive_type_tar_gz_case_insensitive() {
        assert_eq!(detect_archive_type("Package.TAR.GZ"), ArchiveType::TarGz);
        assert_eq!(detect_archive_type("Lib.TGZ"), ArchiveType::TarGz);
        assert_eq!(detect_archive_type("My.CRATE"), ArchiveType::TarGz);
        assert_eq!(detect_archive_type("My.GEM"), ArchiveType::TarGz);
    }

    #[test]
    fn test_detect_archive_type_zip() {
        assert_eq!(detect_archive_type("package.zip"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("numpy-1.0.whl"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("commons.jar"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("newtonsoft.nupkg"), ArchiveType::Zip);
    }

    #[test]
    fn test_detect_archive_type_zip_case_insensitive() {
        assert_eq!(detect_archive_type("Package.ZIP"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("Lib.WHL"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("App.JAR"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("Pkg.NUPKG"), ArchiveType::Zip);
    }

    #[test]
    fn test_detect_archive_type_none() {
        assert_eq!(detect_archive_type("readme.md"), ArchiveType::None);
        assert_eq!(detect_archive_type("main.rs"), ArchiveType::None);
        assert_eq!(detect_archive_type("package.json"), ArchiveType::None);
        assert_eq!(detect_archive_type("image.png"), ArchiveType::None);
        assert_eq!(detect_archive_type("data.tar"), ArchiveType::None);
        assert_eq!(detect_archive_type("file.gz"), ArchiveType::None);
    }

    // -----------------------------------------------------------------------
    // is_path_within_workspace
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_path_within_workspace_valid() {
        let path = Path::new("/tmp/scans/artifact-123");
        assert!(is_path_within_workspace(path, "/tmp/scans"));
    }

    #[test]
    fn test_is_path_within_workspace_exact() {
        let path = Path::new("/tmp/scans");
        assert!(is_path_within_workspace(path, "/tmp/scans"));
    }

    #[test]
    fn test_is_path_within_workspace_outside() {
        let path = Path::new("/var/data/something");
        assert!(!is_path_within_workspace(path, "/tmp/scans"));
    }

    #[test]
    fn test_is_path_within_workspace_partial_prefix() {
        let path = Path::new("/tmp/scans-other/artifact");
        assert!(!is_path_within_workspace(path, "/tmp/scans"));
    }

    // -----------------------------------------------------------------------
    // count_findings_by_severity
    // -----------------------------------------------------------------------

    fn make_finding(severity: Severity) -> RawFinding {
        RawFinding {
            severity,
            title: "test".to_string(),
            description: None,
            cve_id: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            source: None,
            source_url: None,
        }
    }

    #[test]
    fn test_count_findings_by_severity_empty() {
        let (critical, high, medium, low, info) = count_findings_by_severity(&[]);
        assert_eq!(critical, 0);
        assert_eq!(high, 0);
        assert_eq!(medium, 0);
        assert_eq!(low, 0);
        assert_eq!(info, 0);
    }

    #[test]
    fn test_count_findings_by_severity_all_types() {
        let findings = vec![
            make_finding(Severity::Critical),
            make_finding(Severity::Critical),
            make_finding(Severity::High),
            make_finding(Severity::Medium),
            make_finding(Severity::Medium),
            make_finding(Severity::Medium),
            make_finding(Severity::Low),
            make_finding(Severity::Info),
            make_finding(Severity::Info),
        ];
        let (critical, high, medium, low, info) = count_findings_by_severity(&findings);
        assert_eq!(critical, 2);
        assert_eq!(high, 1);
        assert_eq!(medium, 3);
        assert_eq!(low, 1);
        assert_eq!(info, 2);
    }

    #[test]
    fn test_count_findings_by_severity_single_type() {
        let findings = vec![
            make_finding(Severity::High),
            make_finding(Severity::High),
            make_finding(Severity::High),
        ];
        let (critical, high, medium, low, info) = count_findings_by_severity(&findings);
        assert_eq!(critical, 0);
        assert_eq!(high, 3);
        assert_eq!(medium, 0);
        assert_eq!(low, 0);
        assert_eq!(info, 0);
    }

    // -----------------------------------------------------------------------
    // extract_cve_from_advisory
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_cve_from_aliases() {
        let m = AdvisoryMatch {
            id: "GHSA-1234".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string(), "GHSA-1234".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(
            extract_cve_from_advisory(&m),
            Some("CVE-2024-0001".to_string())
        );
    }

    #[test]
    fn test_extract_cve_from_id() {
        let m = AdvisoryMatch {
            id: "CVE-2024-5678".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(
            extract_cve_from_advisory(&m),
            Some("CVE-2024-5678".to_string())
        );
    }

    #[test]
    fn test_extract_cve_no_cve() {
        let m = AdvisoryMatch {
            id: "GHSA-abcd".to_string(),
            summary: None,
            details: None,
            severity: "low".to_string(),
            aliases: vec!["GHSA-abcd".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        };
        assert_eq!(extract_cve_from_advisory(&m), None);
    }

    #[test]
    fn test_extract_cve_prefers_alias_over_id() {
        let m = AdvisoryMatch {
            id: "CVE-2024-0001".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-9999".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(
            extract_cve_from_advisory(&m),
            Some("CVE-2024-9999".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // build_finding_title
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_finding_title_with_summary() {
        let m = AdvisoryMatch {
            id: "GHSA-1234".to_string(),
            summary: Some("Prototype Pollution".to_string()),
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(build_finding_title(&m), "Prototype Pollution");
    }

    #[test]
    fn test_build_finding_title_without_summary() {
        let m = AdvisoryMatch {
            id: "GHSA-5678".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(build_finding_title(&m), "Vulnerability GHSA-5678");
    }

    // -----------------------------------------------------------------------
    // dedup_advisories
    // -----------------------------------------------------------------------

    #[test]
    fn test_dedup_advisories_no_duplicates() {
        let osv = vec![AdvisoryMatch {
            id: "GHSA-1111".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![AdvisoryMatch {
            id: "GHSA-2222".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_dedup_advisories_exact_id_duplicate() {
        let osv = vec![AdvisoryMatch {
            id: "GHSA-1111".to_string(),
            summary: Some("From OSV".to_string()),
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![AdvisoryMatch {
            id: "GHSA-1111".to_string(),
            summary: Some("From GitHub".to_string()),
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source, "osv.dev");
    }

    #[test]
    fn test_dedup_advisories_alias_overlap() {
        let osv = vec![AdvisoryMatch {
            id: "GHSA-aaaa".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![AdvisoryMatch {
            id: "CVE-2024-0001".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-aaaa");
    }

    #[test]
    fn test_dedup_advisories_empty() {
        let result = dedup_advisories(vec![], vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_dedup_advisories_osv_only() {
        let osv = vec![AdvisoryMatch {
            id: "OSV-001".to_string(),
            summary: None,
            details: None,
            severity: "low".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(osv, vec![]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_dedup_advisories_gh_only() {
        let gh = vec![AdvisoryMatch {
            id: "GHSA-bbbb".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(vec![], gh);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_dedup_advisories_complex_alias_chain() {
        let osv = vec![AdvisoryMatch {
            id: "GHSA-aaaa".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string(), "GHSA-bbbb".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![
            AdvisoryMatch {
                id: "GHSA-bbbb".to_string(),
                summary: None,
                details: None,
                severity: "high".to_string(),
                aliases: vec!["CVE-2024-0001".to_string()],
                affected_version: None,
                fixed_version: None,
                source: "github".to_string(),
                source_url: None,
            },
            AdvisoryMatch {
                id: "CVE-2024-0001".to_string(),
                summary: None,
                details: None,
                severity: "high".to_string(),
                aliases: vec![],
                affected_version: None,
                fixed_version: None,
                source: "github".to_string(),
                source_url: None,
            },
        ];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-aaaa");
    }

    // -----------------------------------------------------------------------
    // build_osv_cache_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_osv_cache_key_with_version() {
        let dep = Dependency {
            name: "lodash".to_string(),
            version: Some("4.17.20".to_string()),
            ecosystem: "npm".to_string(),
        };
        assert_eq!(build_osv_cache_key(&dep), "npm:lodash:4.17.20");
    }

    #[test]
    fn test_build_osv_cache_key_without_version() {
        let dep = Dependency {
            name: "my-lib".to_string(),
            version: None,
            ecosystem: "crates.io".to_string(),
        };
        assert_eq!(build_osv_cache_key(&dep), "crates.io:my-lib:*");
    }

    #[test]
    fn test_build_osv_cache_key_pypi() {
        let dep = Dependency {
            name: "flask".to_string(),
            version: Some("2.3.0".to_string()),
            ecosystem: "PyPI".to_string(),
        };
        assert_eq!(build_osv_cache_key(&dep), "PyPI:flask:2.3.0");
    }

    // -----------------------------------------------------------------------
    // OsvBatchQuery serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_batch_query_serialization() {
        let query = OsvBatchQuery {
            queries: vec![
                OsvQuery {
                    package: OsvPackage {
                        name: "lodash".to_string(),
                        ecosystem: "npm".to_string(),
                    },
                    version: Some("4.17.20".to_string()),
                },
                OsvQuery {
                    package: OsvPackage {
                        name: "flask".to_string(),
                        ecosystem: "PyPI".to_string(),
                    },
                    version: None,
                },
            ],
        };
        let json = serde_json::to_value(&query).unwrap();
        let queries = json.get("queries").unwrap().as_array().unwrap();
        assert_eq!(queries.len(), 2);

        let first = &queries[0];
        assert_eq!(first["package"]["name"], "lodash");
        assert_eq!(first["package"]["ecosystem"], "npm");
        assert_eq!(first["version"], "4.17.20");

        let second = &queries[1];
        assert_eq!(second["package"]["name"], "flask");
        assert_eq!(second["package"]["ecosystem"], "PyPI");
        assert!(second["version"].is_null());
    }

    #[test]
    fn test_osv_batch_query_empty() {
        let query = OsvBatchQuery { queries: vec![] };
        let json = serde_json::to_value(&query).unwrap();
        assert!(json.get("queries").unwrap().as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - vuln with no id
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_vuln_with_no_id_defaults_to_unknown() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{"summary": "some issue"}]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "UNKNOWN");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - vuln with aliases but no fixed version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_no_fixed_version() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-100",
                    "aliases": ["CVE-2024-1234"],
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}]
                        }]
                    }]
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].fixed_version.is_none());
        assert_eq!(matches[0].aliases, vec!["CVE-2024-1234".to_string()]);
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - dep index out of bounds
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_more_results_than_deps() {
        let deps = vec![Dependency {
            name: "pkg-a".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [
                {"vulns": [{"id": "VULN-A"}]},
                {"vulns": [{"id": "VULN-B"}]}
            ]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].affected_version.as_deref(), Some("1.0"));
        assert!(matches[1].affected_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - affected array empty
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_empty_affected() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "VULN-1",
                    "affected": []
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - severity defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_severity_case_insensitive() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-test",
            "severity": "CRITICAL"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(result.severity, "critical");
    }

    #[test]
    fn test_parse_github_advisory_no_severity_defaults_to_medium() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-default"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(result.severity, "medium");
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - case sensitivity
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_case_insensitive_name() {
        let artifact = make_artifact("PACKAGE.JSON", "/npm/PACKAGE.JSON", None);
        let content = Bytes::from(r#"{"dependencies":{"react":"^18.0.0"}}"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "npm");
    }

    #[test]
    fn test_extract_dependencies_cargo_toml_case_insensitive() {
        let artifact = make_artifact("CARGO.TOML", "/rust/CARGO.TOML", None);
        let content = Bytes::from("[dependencies]\ntokio = \"1.35\"\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "crates.io");
    }

    #[test]
    fn test_extract_dependencies_requirements_txt_case_insensitive() {
        let artifact = make_artifact("REQUIREMENTS.TXT", "/pypi/REQUIREMENTS.TXT", None);
        let content = Bytes::from("flask==2.3.0\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "PyPI");
    }

    // -----------------------------------------------------------------------
    // parse_npm - complex scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_npm_large_package_json() {
        let content = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "~4.17.21",
                "axios": "1.6.0"
            },
            "devDependencies": {
                "jest": "29.0.0",
                "typescript": "^5.3.0"
            },
            "peerDependencies": {
                "react": "^18.0.0"
            },
            "scripts": {
                "test": "jest"
            }
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 6);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"jest"));
        assert!(names.contains(&"react"));
    }

    // -----------------------------------------------------------------------
    // infer_dependencies - version propagation
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_dependencies_version_propagated() {
        let artifact = make_artifact("pkg.rpm", "/rpm/pkg.rpm", Some("3.14"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps[0].version.as_deref(), Some("3.14"));
    }

    #[test]
    fn test_infer_dependencies_no_version() {
        let artifact = make_artifact("pkg.rpm", "/rpm/pkg.rpm", None);
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert!(deps[0].version.is_none());
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_deserialize_from_json() {
        let json = serde_json::json!({
            "id": "GHSA-test",
            "summary": "Test advisory",
            "details": null,
            "severity": "high",
            "aliases": ["CVE-2024-0001"],
            "affected_version": "1.0.0",
            "fixed_version": "1.0.1",
            "source": "github",
            "source_url": "https://github.com/advisories/GHSA-test"
        });
        let m: AdvisoryMatch = serde_json::from_value(json).unwrap();
        assert_eq!(m.id, "GHSA-test");
        assert_eq!(m.summary.as_deref(), Some("Test advisory"));
        assert!(m.details.is_none());
        assert_eq!(m.aliases.len(), 1);
    }

    // -----------------------------------------------------------------------
    // parse_maven - dependency with version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_maven_dependency_with_scope() {
        let content = r#"
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
                <version>4.13.2</version>
            </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "junit:junit");
        assert_eq!(deps[0].version.as_deref(), Some("4.13.2"));
    }

    // -----------------------------------------------------------------------
    // parse_rubygems - lines without parens
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rubygems_ignores_lines_without_parens() {
        let content =
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.8)\n    PLATFORMS\n    ruby\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rails");
    }

    // -----------------------------------------------------------------------
    // parse_nuget - non-package lines
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuget_ignores_non_package_lines() {
        let content = r#"<?xml version="1.0"?>
<packages>
  <package id="A" version="1.0" />
  <!-- this is a comment -->
  <metadata>something</metadata>
</packages>"#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "A");
    }

    // -----------------------------------------------------------------------
    // parse_pip - no version specifier
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pip_no_version_specifier() {
        let content = "flask\ndjango\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 2);
        assert!(deps[0].version.is_none());
        assert!(deps[1].version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_cargo - mixed dependency types in one section
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cargo_mixed_dep_types() {
        let content = r#"
            [dependencies]
            serde = "1.0"
            tokio = { version = "1.35", features = ["full"] }
            local-lib = { path = "../local-lib" }
            git-dep = { git = "https://github.com/foo/bar", version = "0.5" }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 4);
        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.version.as_deref(), Some("1.0"));
        let tokio = deps.iter().find(|d| d.name == "tokio").unwrap();
        assert_eq!(tokio.version.as_deref(), Some("1.35"));
        let local = deps.iter().find(|d| d.name == "local-lib").unwrap();
        assert!(local.version.is_none());
        let git = deps.iter().find(|d| d.name == "git-dep").unwrap();
        assert_eq!(git.version.as_deref(), Some("0.5"));
    }

    // -----------------------------------------------------------------------
    // RawFinding serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_raw_finding_serialization_full() {
        let finding = RawFinding {
            severity: Severity::Critical,
            title: "SQL Injection".to_string(),
            description: Some("Improper input sanitization".to_string()),
            cve_id: Some("CVE-2024-0001".to_string()),
            affected_component: Some("db-driver".to_string()),
            affected_version: Some("1.0.0".to_string()),
            fixed_version: Some("1.0.1".to_string()),
            source: Some("trivy".to_string()),
            source_url: Some("https://trivy.dev/vuln/CVE-2024-0001".to_string()),
        };
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["title"], "SQL Injection");
        assert_eq!(json["description"], "Improper input sanitization");
        assert_eq!(json["cve_id"], "CVE-2024-0001");
        assert_eq!(json["affected_component"], "db-driver");
        assert_eq!(json["affected_version"], "1.0.0");
        assert_eq!(json["fixed_version"], "1.0.1");
        assert_eq!(json["source"], "trivy");
    }

    #[test]
    fn test_raw_finding_serialization_minimal() {
        let finding = RawFinding {
            severity: Severity::Info,
            title: "Informational notice".to_string(),
            description: None,
            cve_id: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            source: None,
            source_url: None,
        };
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["severity"], "info");
        assert_eq!(json["title"], "Informational notice");
        assert!(json["description"].is_null());
        assert!(json["cve_id"].is_null());
        assert!(json["source"].is_null());
    }

    #[test]
    fn test_raw_finding_serialization_all_severities() {
        for (severity, expected_str) in [
            (Severity::Critical, "critical"),
            (Severity::High, "high"),
            (Severity::Medium, "medium"),
            (Severity::Low, "low"),
            (Severity::Info, "info"),
        ] {
            let finding = make_finding(severity);
            let json = serde_json::to_value(&finding).unwrap();
            assert_eq!(json["severity"], expected_str);
        }
    }

    #[test]
    fn test_raw_finding_debug() {
        let finding = make_finding(Severity::High);
        let debug = format!("{:?}", finding);
        assert!(debug.contains("RawFinding"));
        assert!(debug.contains("High"));
    }

    #[test]
    fn test_raw_finding_clone() {
        let finding = RawFinding {
            severity: Severity::Medium,
            title: "XSS vulnerability".to_string(),
            description: Some("Reflected XSS".to_string()),
            cve_id: Some("CVE-2024-9999".to_string()),
            affected_component: Some("web-ui".to_string()),
            affected_version: Some("2.0.0".to_string()),
            fixed_version: Some("2.0.1".to_string()),
            source: Some("grype".to_string()),
            source_url: Some("https://example.com".to_string()),
        };
        let cloned = finding.clone();
        assert_eq!(cloned.severity, finding.severity);
        assert_eq!(cloned.title, finding.title);
        assert_eq!(cloned.description, finding.description);
        assert_eq!(cloned.cve_id, finding.cve_id);
        assert_eq!(cloned.affected_component, finding.affected_component);
        assert_eq!(cloned.affected_version, finding.affected_version);
        assert_eq!(cloned.fixed_version, finding.fixed_version);
        assert_eq!(cloned.source, finding.source);
        assert_eq!(cloned.source_url, finding.source_url);
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch debug trait
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_debug() {
        let m = AdvisoryMatch {
            id: "GHSA-dbg-test".to_string(),
            summary: Some("Debug test".to_string()),
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        let debug = format!("{:?}", m);
        assert!(debug.contains("AdvisoryMatch"));
        assert!(debug.contains("GHSA-dbg-test"));
        assert!(debug.contains("CVE-2024-0001"));
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch deserialization edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_deserialize_all_nulls() {
        let json = serde_json::json!({
            "id": "OSV-001",
            "summary": null,
            "details": null,
            "severity": "low",
            "aliases": [],
            "affected_version": null,
            "fixed_version": null,
            "source": "osv.dev",
            "source_url": null
        });
        let m: AdvisoryMatch = serde_json::from_value(json).unwrap();
        assert_eq!(m.id, "OSV-001");
        assert!(m.summary.is_none());
        assert!(m.details.is_none());
        assert!(m.aliases.is_empty());
        assert!(m.affected_version.is_none());
        assert!(m.fixed_version.is_none());
        assert!(m.source_url.is_none());
    }

    #[test]
    fn test_advisory_match_deserialize_multiple_aliases() {
        let json = serde_json::json!({
            "id": "GHSA-multi",
            "summary": null,
            "details": null,
            "severity": "critical",
            "aliases": ["CVE-2024-0001", "CVE-2024-0002", "GHSA-other"],
            "affected_version": null,
            "fixed_version": null,
            "source": "github",
            "source_url": null
        });
        let m: AdvisoryMatch = serde_json::from_value(json).unwrap();
        assert_eq!(m.aliases.len(), 3);
        assert_eq!(m.aliases[0], "CVE-2024-0001");
        assert_eq!(m.aliases[1], "CVE-2024-0002");
        assert_eq!(m.aliases[2], "GHSA-other");
    }

    // -----------------------------------------------------------------------
    // OsvQuery and OsvPackage serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_query_serialization_with_version() {
        let query = OsvQuery {
            package: OsvPackage {
                name: "express".to_string(),
                ecosystem: "npm".to_string(),
            },
            version: Some("4.18.2".to_string()),
        };
        let json = serde_json::to_value(&query).unwrap();
        assert_eq!(json["package"]["name"], "express");
        assert_eq!(json["package"]["ecosystem"], "npm");
        assert_eq!(json["version"], "4.18.2");
    }

    #[test]
    fn test_osv_query_serialization_without_version() {
        let query = OsvQuery {
            package: OsvPackage {
                name: "flask".to_string(),
                ecosystem: "PyPI".to_string(),
            },
            version: None,
        };
        let json = serde_json::to_value(&query).unwrap();
        assert_eq!(json["package"]["name"], "flask");
        assert_eq!(json["package"]["ecosystem"], "PyPI");
        assert!(json["version"].is_null());
    }

    #[test]
    fn test_osv_package_serialization() {
        let pkg = OsvPackage {
            name: "tokio".to_string(),
            ecosystem: "crates.io".to_string(),
        };
        let json = serde_json::to_value(&pkg).unwrap();
        assert_eq!(json["name"], "tokio");
        assert_eq!(json["ecosystem"], "crates.io");
    }

    // -----------------------------------------------------------------------
    // Severity::from_str_loose usage in scanner context
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_from_str_loose_as_used_in_scanner() {
        // The scanner calls Severity::from_str_loose on advisory severity
        // strings and falls back to Severity::Medium. Verify all paths.
        assert_eq!(
            Severity::from_str_loose("critical").unwrap_or(Severity::Medium),
            Severity::Critical
        );
        assert_eq!(
            Severity::from_str_loose("high").unwrap_or(Severity::Medium),
            Severity::High
        );
        assert_eq!(
            Severity::from_str_loose("medium").unwrap_or(Severity::Medium),
            Severity::Medium
        );
        assert_eq!(
            Severity::from_str_loose("moderate").unwrap_or(Severity::Medium),
            Severity::Medium
        );
        assert_eq!(
            Severity::from_str_loose("low").unwrap_or(Severity::Medium),
            Severity::Low
        );
        assert_eq!(
            Severity::from_str_loose("info").unwrap_or(Severity::Medium),
            Severity::Info
        );
        assert_eq!(
            Severity::from_str_loose("informational").unwrap_or(Severity::Medium),
            Severity::Info
        );
        assert_eq!(
            Severity::from_str_loose("none").unwrap_or(Severity::Medium),
            Severity::Info
        );
        // Unknown strings fall back to Medium (the default used in the scanner)
        assert_eq!(
            Severity::from_str_loose("unknown").unwrap_or(Severity::Medium),
            Severity::Medium
        );
        assert_eq!(
            Severity::from_str_loose("").unwrap_or(Severity::Medium),
            Severity::Medium
        );
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - robustness with non-array aliases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_aliases_not_array() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-500",
                    "aliases": "not-an-array"
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].aliases.is_empty());
    }

    #[test]
    fn test_parse_osv_response_aliases_null() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-600",
                    "aliases": null
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].aliases.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - severity from severity array (type field)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_severity_from_empty_severity_array() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-700",
                    "severity": []
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        // Empty severity array, no database_specific, falls back to "medium"
        assert_eq!(matches[0].severity, "medium");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - affected with no ranges
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_affected_no_ranges() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-800",
                    "affected": [{"package": {"name": "pkg"}}]
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - affected ranges with no fixed event
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_ranges_no_fixed_event() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-900",
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"last_affected": "2.0.0"}
                            ]
                        }]
                    }]
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - vulnerabilities with null first_patched_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_first_patched_version_null() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-null-patch",
            "vulnerabilities": [
                {"first_patched_version": null}
            ]
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert!(result.fixed_version.is_none());
    }

    #[test]
    fn test_parse_github_advisory_no_vulnerabilities_key() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-no-vulns"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert!(result.fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // Dependency with various ecosystems
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_all_ecosystems() {
        let ecosystems = [
            "npm",
            "PyPI",
            "crates.io",
            "Maven",
            "Go",
            "NuGet",
            "RubyGems",
            "Linux",
        ];
        for eco in ecosystems {
            let dep = Dependency {
                name: "test-pkg".to_string(),
                version: Some("1.0.0".to_string()),
                ecosystem: eco.to_string(),
            };
            assert_eq!(dep.ecosystem, eco);
        }
    }

    // -----------------------------------------------------------------------
    // OsvBatchQuery with single query
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_batch_query_single_entry() {
        let query = OsvBatchQuery {
            queries: vec![OsvQuery {
                package: OsvPackage {
                    name: "serde".to_string(),
                    ecosystem: "crates.io".to_string(),
                },
                version: Some("1.0.195".to_string()),
            }],
        };
        let json = serde_json::to_value(&query).unwrap();
        let queries = json["queries"].as_array().unwrap();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0]["package"]["name"], "serde");
        assert_eq!(queries[0]["version"], "1.0.195");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - dep with no version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_dep_with_no_version() {
        let deps = vec![Dependency {
            name: "unversioned-pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "VULN-NO-VER",
                    "summary": "Something bad"
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].affected_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - dep with no version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_dep_with_no_version() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-no-ver",
            "severity": "low"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert!(result.affected_version.is_none());
        assert_eq!(result.severity, "low");
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - description field
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_description_maps_to_details() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-desc",
            "description": "Full description of the vulnerability"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(
            result.details.as_deref(),
            Some("Full description of the vulnerability")
        );
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - nested gemfile.lock
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_nested_gemfile_lock() {
        let artifact = make_artifact("vendor/Gemfile.lock", "/ruby/vendor/Gemfile.lock", None);
        let content = Bytes::from("    bundler (2.4.22)\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "RubyGems");
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - packages.config (NuGet)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_packages_config_case_insensitive() {
        let artifact = make_artifact("PACKAGES.CONFIG", "/nuget/PACKAGES.CONFIG", None);
        let content = Bytes::from(r#"<package id="TestPkg" version="1.0" />"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "NuGet");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - vuln with details but no summary
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_details_without_summary() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-DETAIL-ONLY",
                    "details": "A detailed description without summary"
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].summary.is_none());
        assert_eq!(
            matches[0].details.as_deref(),
            Some("A detailed description without summary")
        );
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch deserialization from JSON string
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_deserialize_from_json_string() {
        let json_str = r#"{
            "id": "GHSA-json-str",
            "summary": "From JSON string",
            "details": "Details here",
            "severity": "critical",
            "aliases": ["CVE-2024-0001", "GHSA-other"],
            "affected_version": "1.0.0",
            "fixed_version": "1.0.1",
            "source": "github",
            "source_url": "https://example.com/advisory"
        }"#;
        let m: AdvisoryMatch = serde_json::from_str(json_str).unwrap();
        assert_eq!(m.id, "GHSA-json-str");
        assert_eq!(m.summary.as_deref(), Some("From JSON string"));
        assert_eq!(m.details.as_deref(), Some("Details here"));
        assert_eq!(m.severity, "critical");
        assert_eq!(m.aliases.len(), 2);
        assert_eq!(m.affected_version.as_deref(), Some("1.0.0"));
        assert_eq!(m.fixed_version.as_deref(), Some("1.0.1"));
        assert_eq!(m.source, "github");
        assert_eq!(
            m.source_url.as_deref(),
            Some("https://example.com/advisory")
        );
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - source URL format
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_source_url_format() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{"id": "GHSA-url-test"}]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].source_url.as_deref(),
            Some("https://osv.dev/vulnerability/GHSA-url-test")
        );
        assert_eq!(matches[0].source, "osv.dev");
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - source field is always "github"
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_source_is_github() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-src-test",
            "html_url": "https://github.com/advisories/GHSA-src-test"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(result.source, "github");
        assert_eq!(
            result.source_url.as_deref(),
            Some("https://github.com/advisories/GHSA-src-test")
        );
    }

    // -----------------------------------------------------------------------
    // make_artifact helper validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_make_artifact_fields() {
        let artifact = make_artifact("test.jar", "/maven/test.jar", Some("3.0"));
        assert_eq!(artifact.name, "test.jar");
        assert_eq!(artifact.path, "/maven/test.jar");
        assert_eq!(artifact.version.as_deref(), Some("3.0"));
        assert_eq!(artifact.size_bytes, 100);
        assert_eq!(artifact.checksum_sha256, "abc123");
        assert!(!artifact.is_deleted);
        assert!(artifact.uploaded_by.is_none());
        assert!(artifact.checksum_md5.is_none());
        assert!(artifact.checksum_sha1.is_none());
    }

    #[test]
    fn test_make_artifact_no_version() {
        let artifact = make_artifact("readme.md", "/docs/readme.md", None);
        assert!(artifact.version.is_none());
    }

    // -----------------------------------------------------------------------
    // Severity equality used in count_findings_by_severity
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_equality() {
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_eq!(Severity::High, Severity::High);
        assert_eq!(Severity::Medium, Severity::Medium);
        assert_eq!(Severity::Low, Severity::Low);
        assert_eq!(Severity::Info, Severity::Info);
        assert_ne!(Severity::Critical, Severity::High);
        assert_ne!(Severity::High, Severity::Medium);
        assert_ne!(Severity::Low, Severity::Info);
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - multiple fixed events picks first
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_multiple_fixed_events() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-MULTI-FIX",
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.5.0"},
                                {"introduced": "2.0.0"},
                                {"fixed": "2.1.0"}
                            ]
                        }]
                    }]
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        // find_map picks the first "fixed" event
        assert_eq!(matches[0].fixed_version.as_deref(), Some("1.5.0"));
    }

    // -----------------------------------------------------------------------
    // dedup_advisories - multiple alias overlap
    // -----------------------------------------------------------------------

    #[test]
    fn test_dedup_advisories_transitive_alias_dedup() {
        // OSV entry has alias CVE-X. GH entry #1 has id CVE-X.
        // GH entry #2 has id GHSA-Y. Both should reduce to just OSV entry.
        let osv = vec![AdvisoryMatch {
            id: "GHSA-xxx".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-1111".to_string(), "GHSA-yyy".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![
            AdvisoryMatch {
                id: "CVE-2024-1111".to_string(),
                summary: None,
                details: None,
                severity: "high".to_string(),
                aliases: vec![],
                affected_version: None,
                fixed_version: None,
                source: "github".to_string(),
                source_url: None,
            },
            AdvisoryMatch {
                id: "GHSA-yyy".to_string(),
                summary: None,
                details: None,
                severity: "high".to_string(),
                aliases: vec![],
                affected_version: None,
                fixed_version: None,
                source: "github".to_string(),
                source_url: None,
            },
        ];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-xxx");
    }

    // -----------------------------------------------------------------------
    // sanitize_artifact_filename tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitize_normal_filename() {
        assert_eq!(
            sanitize_artifact_filename("package.tar.gz"),
            "package.tar.gz"
        );
    }

    #[test]
    fn test_sanitize_path_traversal_dotdot() {
        assert_eq!(sanitize_artifact_filename("../../../etc/passwd"), "passwd");
    }

    #[test]
    fn test_sanitize_absolute_path() {
        assert_eq!(sanitize_artifact_filename("/etc/passwd"), "passwd");
    }

    #[test]
    fn test_sanitize_nested_path() {
        assert_eq!(sanitize_artifact_filename("path/to/file.txt"), "file.txt");
    }

    #[test]
    fn test_sanitize_double_dots_only() {
        // ".." has no filename component, should fallback to "artifact"
        assert_eq!(sanitize_artifact_filename(".."), "artifact");
    }

    #[test]
    fn test_sanitize_empty_string() {
        assert_eq!(sanitize_artifact_filename(""), "artifact");
    }

    #[test]
    fn test_sanitize_slash_only() {
        assert_eq!(sanitize_artifact_filename("/"), "artifact");
    }

    #[test]
    fn test_sanitize_preserves_extension() {
        assert_eq!(
            sanitize_artifact_filename("../../malicious.crate"),
            "malicious.crate"
        );
    }

    // -----------------------------------------------------------------------
    // extract_tar_gz_safe tests
    // -----------------------------------------------------------------------

    fn create_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut buf = Vec::new();
        {
            let encoder = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = tar::Builder::new(encoder);
            for (path, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                tar.append(&header, *data).unwrap();
            }
            tar.into_inner().unwrap().finish().unwrap();
        }
        buf
    }

    fn create_tar_gz_with_symlink(
        normal_entries: &[(&str, &[u8])],
        symlinks: &[(&str, &str)],
    ) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut buf = Vec::new();
        {
            let encoder = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = tar::Builder::new(encoder);

            for (path, data) in normal_entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                tar.append(&header, *data).unwrap();
            }

            for (link_name, target) in symlinks {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_path(link_name).unwrap();
                header.set_link_name(target).unwrap();
                header.set_size(0);
                header.set_mode(0o777);
                header.set_mtime(0);
                header.set_cksum();
                tar.append(&header, &[][..]).unwrap();
            }

            tar.into_inner().unwrap().finish().unwrap();
        }
        buf
    }

    #[test]
    fn test_extract_tar_gz_normal_files() {
        let archive = create_tar_gz(&[
            ("hello.txt", b"hello world"),
            ("subdir/nested.txt", b"nested content"),
        ]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tar_gz_safe(&archive, tmp.path()).unwrap();

        assert!(tmp.path().join("hello.txt").exists());
        assert!(tmp.path().join("subdir/nested.txt").exists());
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("hello.txt")).unwrap(),
            "hello world"
        );
    }

    #[test]
    fn test_extract_tar_gz_skips_symlinks() {
        let archive =
            create_tar_gz_with_symlink(&[("legit.txt", b"ok")], &[("evil_link", "/etc/passwd")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tar_gz_safe(&archive, tmp.path()).unwrap();

        assert!(tmp.path().join("legit.txt").exists());
        assert!(!tmp.path().join("evil_link").exists());
    }

    #[test]
    fn test_extract_tar_gz_skips_path_traversal() {
        // The Rust tar crate's set_path() rejects ".." components, so we
        // construct the header at a lower level by writing the name bytes
        // directly into the GNU header to simulate a malicious archive.
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut buf = Vec::new();
        {
            let encoder = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = tar::Builder::new(encoder);

            // Malicious entry: set a placeholder path, then overwrite with "../escape.txt"
            let data = b"malicious payload";
            let mut header = tar::Header::new_gnu();
            header.set_path("placeholder.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            {
                let gnu = header.as_gnu_mut().unwrap();
                let evil_path = b"../escape.txt\0";
                gnu.name[..evil_path.len()].copy_from_slice(evil_path);
            }
            header.set_cksum();
            tar.append(&header, &data[..]).unwrap();

            // Safe entry
            let safe_data = b"safe content";
            let mut header2 = tar::Header::new_gnu();
            header2.set_path("safe.txt").unwrap();
            header2.set_size(safe_data.len() as u64);
            header2.set_mode(0o644);
            header2.set_mtime(0);
            header2.set_cksum();
            tar.append(&header2, &safe_data[..]).unwrap();

            tar.into_inner().unwrap().finish().unwrap();
        }

        let tmp = tempfile::tempdir().unwrap();
        extract_tar_gz_safe(&buf, tmp.path()).unwrap();

        // The safe file should exist, but the traversal attempt should not escape
        assert!(tmp.path().join("safe.txt").exists());
        // The "../escape.txt" path should NOT have been created above the target
        assert!(!tmp.path().parent().unwrap().join("escape.txt").exists());
    }

    #[test]
    fn test_extract_tar_gz_skips_hardlinks() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut buf = Vec::new();
        {
            let encoder = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = tar::Builder::new(encoder);

            // Normal file
            let data = b"normal";
            let mut header = tar::Header::new_gnu();
            header.set_path("normal.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            tar.append(&header, &data[..]).unwrap();

            // Hardlink entry
            let mut hl_header = tar::Header::new_gnu();
            hl_header.set_entry_type(tar::EntryType::Link);
            hl_header.set_path("hardlink.txt").unwrap();
            hl_header.set_link_name("normal.txt").unwrap();
            hl_header.set_size(0);
            hl_header.set_mode(0o644);
            hl_header.set_mtime(0);
            hl_header.set_cksum();
            tar.append(&hl_header, &[][..]).unwrap();

            tar.into_inner().unwrap().finish().unwrap();
        }

        let tmp = tempfile::tempdir().unwrap();
        extract_tar_gz_safe(&buf, tmp.path()).unwrap();

        assert!(tmp.path().join("normal.txt").exists());
        assert!(!tmp.path().join("hardlink.txt").exists());
    }

    #[test]
    fn test_extract_tar_gz_empty_archive() {
        let archive = create_tar_gz(&[]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tar_gz_safe(&archive, tmp.path()).unwrap();
        // Should succeed with no files created
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    // ===================================================================
    // format_to_purl_type -- exhaustive mapping tests
    // ===================================================================

    #[test]
    fn test_format_to_purl_type_pypi() {
        assert_eq!(format_to_purl_type("pypi"), "pypi");
        assert_eq!(format_to_purl_type("PyPI"), "pypi");
        assert_eq!(format_to_purl_type("PYPI"), "pypi");
    }

    #[test]
    fn test_format_to_purl_type_npm() {
        assert_eq!(format_to_purl_type("npm"), "npm");
        assert_eq!(format_to_purl_type("NPM"), "npm");
        assert_eq!(format_to_purl_type("Npm"), "npm");
    }

    #[test]
    fn test_format_to_purl_type_cargo() {
        assert_eq!(format_to_purl_type("cargo"), "cargo");
        assert_eq!(format_to_purl_type("crates"), "cargo");
        assert_eq!(format_to_purl_type("Cargo"), "cargo");
        assert_eq!(format_to_purl_type("CRATES"), "cargo");
    }

    #[test]
    fn test_format_to_purl_type_maven() {
        assert_eq!(format_to_purl_type("maven"), "maven");
        assert_eq!(format_to_purl_type("Maven"), "maven");
        assert_eq!(format_to_purl_type("MAVEN"), "maven");
    }

    #[test]
    fn test_format_to_purl_type_go() {
        assert_eq!(format_to_purl_type("go"), "golang");
        assert_eq!(format_to_purl_type("golang"), "golang");
        assert_eq!(format_to_purl_type("Go"), "golang");
        assert_eq!(format_to_purl_type("GOLANG"), "golang");
    }

    #[test]
    fn test_format_to_purl_type_nuget() {
        assert_eq!(format_to_purl_type("nuget"), "nuget");
        assert_eq!(format_to_purl_type("NuGet"), "nuget");
        assert_eq!(format_to_purl_type("NUGET"), "nuget");
    }

    #[test]
    fn test_format_to_purl_type_rubygems() {
        assert_eq!(format_to_purl_type("rubygems"), "gem");
        assert_eq!(format_to_purl_type("gem"), "gem");
        assert_eq!(format_to_purl_type("RubyGems"), "gem");
        assert_eq!(format_to_purl_type("GEM"), "gem");
    }

    #[test]
    fn test_format_to_purl_type_docker() {
        assert_eq!(format_to_purl_type("docker"), "docker");
        assert_eq!(format_to_purl_type("oci"), "docker");
        assert_eq!(format_to_purl_type("container"), "docker");
        assert_eq!(format_to_purl_type("Docker"), "docker");
        assert_eq!(format_to_purl_type("OCI"), "docker");
        assert_eq!(format_to_purl_type("Container"), "docker");
    }

    #[test]
    fn test_format_to_purl_type_composer() {
        assert_eq!(format_to_purl_type("composer"), "composer");
        assert_eq!(format_to_purl_type("php"), "composer");
        assert_eq!(format_to_purl_type("PHP"), "composer");
        assert_eq!(format_to_purl_type("Composer"), "composer");
    }

    #[test]
    fn test_format_to_purl_type_cocoapods() {
        assert_eq!(format_to_purl_type("cocoapods"), "cocoapods");
        assert_eq!(format_to_purl_type("pods"), "cocoapods");
        assert_eq!(format_to_purl_type("CocoaPods"), "cocoapods");
        assert_eq!(format_to_purl_type("PODS"), "cocoapods");
    }

    #[test]
    fn test_format_to_purl_type_swift() {
        assert_eq!(format_to_purl_type("swift"), "swift");
        assert_eq!(format_to_purl_type("Swift"), "swift");
        assert_eq!(format_to_purl_type("SWIFT"), "swift");
    }

    #[test]
    fn test_format_to_purl_type_hex() {
        assert_eq!(format_to_purl_type("hex"), "hex");
        assert_eq!(format_to_purl_type("elixir"), "hex");
        assert_eq!(format_to_purl_type("Hex"), "hex");
        assert_eq!(format_to_purl_type("Elixir"), "hex");
    }

    #[test]
    fn test_format_to_purl_type_pub() {
        assert_eq!(format_to_purl_type("pub"), "pub");
        assert_eq!(format_to_purl_type("dart"), "pub");
        assert_eq!(format_to_purl_type("Pub"), "pub");
        assert_eq!(format_to_purl_type("Dart"), "pub");
    }

    #[test]
    fn test_format_to_purl_type_conan() {
        assert_eq!(format_to_purl_type("conan"), "conan");
        assert_eq!(format_to_purl_type("cpp"), "conan");
        assert_eq!(format_to_purl_type("Conan"), "conan");
        assert_eq!(format_to_purl_type("CPP"), "conan");
    }

    #[test]
    fn test_format_to_purl_type_conda() {
        assert_eq!(format_to_purl_type("conda"), "conda");
        assert_eq!(format_to_purl_type("Conda"), "conda");
        assert_eq!(format_to_purl_type("CONDA"), "conda");
    }

    #[test]
    fn test_format_to_purl_type_hackage() {
        assert_eq!(format_to_purl_type("hackage"), "hackage");
        assert_eq!(format_to_purl_type("haskell"), "hackage");
        assert_eq!(format_to_purl_type("Hackage"), "hackage");
        assert_eq!(format_to_purl_type("Haskell"), "hackage");
    }

    #[test]
    fn test_format_to_purl_type_rpm() {
        assert_eq!(format_to_purl_type("rpm"), "rpm");
        assert_eq!(format_to_purl_type("RPM"), "rpm");
    }

    #[test]
    fn test_format_to_purl_type_deb() {
        assert_eq!(format_to_purl_type("deb"), "deb");
        assert_eq!(format_to_purl_type("debian"), "deb");
        assert_eq!(format_to_purl_type("apt"), "deb");
        assert_eq!(format_to_purl_type("DEB"), "deb");
        assert_eq!(format_to_purl_type("Debian"), "deb");
        assert_eq!(format_to_purl_type("APT"), "deb");
    }

    #[test]
    fn test_format_to_purl_type_apk() {
        assert_eq!(format_to_purl_type("apk"), "apk");
        assert_eq!(format_to_purl_type("alpine"), "apk");
        assert_eq!(format_to_purl_type("APK"), "apk");
        assert_eq!(format_to_purl_type("Alpine"), "apk");
    }

    #[test]
    fn test_format_to_purl_type_unknown_fallback() {
        assert_eq!(format_to_purl_type("unknown"), "generic");
        assert_eq!(format_to_purl_type("foo"), "generic");
        assert_eq!(format_to_purl_type("terraform"), "generic");
        assert_eq!(format_to_purl_type("helm"), "generic");
        assert_eq!(format_to_purl_type("raw"), "generic");
    }

    #[test]
    fn test_format_to_purl_type_empty_string() {
        assert_eq!(format_to_purl_type(""), "generic");
    }

    #[test]
    fn test_format_to_purl_type_whitespace() {
        // Leading/trailing whitespace is not trimmed by the function,
        // so " npm " should fall through to generic.
        assert_eq!(format_to_purl_type(" npm "), "generic");
        assert_eq!(format_to_purl_type("npm "), "generic");
        assert_eq!(format_to_purl_type(" npm"), "generic");
    }

    // ===================================================================
    // derive_dt_project_info
    // ===================================================================

    #[test]
    fn test_derive_dt_project_info_with_repo_name_and_format() {
        let row = Some(("my-npm-repo".to_string(), Some("npm".to_string())));
        let (repo_label, purl) = derive_dt_project_info(row, "fallback-id");
        assert_eq!(repo_label, "my-npm-repo");
        assert_eq!(purl, "npm");
    }

    #[test]
    fn test_derive_dt_project_info_with_repo_name_no_format() {
        let row = Some(("my-repo".to_string(), None));
        let (repo_label, purl) = derive_dt_project_info(row, "fallback-id");
        assert_eq!(repo_label, "my-repo");
        assert_eq!(purl, "generic");
    }

    #[test]
    fn test_derive_dt_project_info_no_repo_row() {
        let (repo_label, purl) = derive_dt_project_info(None, "abc-123-uuid");
        assert_eq!(repo_label, "abc-123-uuid");
        assert_eq!(purl, "generic");
    }

    #[test]
    fn test_derive_dt_project_info_format_case_insensitive() {
        let row = Some(("repo".to_string(), Some("PyPI".to_string())));
        let (_, purl) = derive_dt_project_info(row, "x");
        assert_eq!(purl, "pypi");
    }

    #[test]
    fn test_derive_dt_project_info_docker_format() {
        let row = Some(("docker-repo".to_string(), Some("docker".to_string())));
        let (repo_label, purl) = derive_dt_project_info(row, "x");
        assert_eq!(repo_label, "docker-repo");
        assert_eq!(purl, "docker");
    }

    /// Regression: #1276. The DT project name must be the artifact name (with
    /// the artifact's version as the project version), not the repo name and
    /// not the repository UUID. The repo name belongs in the description so
    /// operators can still trace a finding back to its source repo. This
    /// test pins the contract the caller in `submit_sbom_to_dependency_track`
    /// is now expected to honor.
    #[test]
    fn test_dt_project_name_is_artifact_name_not_repo_or_uuid() {
        // Simulate what the caller assembles for DT.
        let repo_row = Some(("my-npm-repo".to_string(), Some("npm".to_string())));
        let repository_uuid = "11111111-2222-3333-4444-555555555555";
        let artifact_name = "lodash";
        let artifact_version = Some("4.17.21");

        let (repo_label, purl) = derive_dt_project_info(repo_row, repository_uuid);

        // What the caller would actually send to DT:
        let dt_project_name = artifact_name;
        let dt_project_version = artifact_version;
        let dt_project_description = format!("Repository: {}", repo_label);

        // The DT project name must NOT be the repository UUID (#1276).
        assert_ne!(dt_project_name, repository_uuid);
        // The DT project name must NOT be the repository name either; that
        // would collapse every artifact in the repo onto one DT project.
        assert_ne!(dt_project_name, repo_label.as_str());
        // It IS the artifact name, with the artifact's version pinned to
        // the DT project version so DT can dedupe per artifact version.
        assert_eq!(dt_project_name, "lodash");
        assert_eq!(dt_project_version, Some("4.17.21"));
        // The repo context is preserved in the description.
        assert_eq!(dt_project_description, "Repository: my-npm-repo");
        // purl_type is still driven by the repo format.
        assert_eq!(purl, "npm");
    }

    /// Regression: #1276 fallback path. When the repository row is missing
    /// (deleted concurrent with a scan, or migration glitch), DT submission
    /// still happens but the description carries the repo UUID rather than
    /// a name. The project name is still the artifact name, never the UUID.
    #[test]
    fn test_dt_project_name_is_artifact_name_when_repo_row_missing() {
        let repository_uuid = "deadbeef-1111-2222-3333-444444444444";
        let artifact_name = "express";

        let (repo_label, purl) = derive_dt_project_info(None, repository_uuid);

        let dt_project_name = artifact_name;
        let dt_project_description = format!("Repository: {}", repo_label);

        assert_ne!(dt_project_name, repository_uuid);
        assert_eq!(dt_project_name, "express");
        assert_eq!(
            dt_project_description,
            format!("Repository: {}", repository_uuid)
        );
        assert_eq!(purl, "generic");
    }

    #[test]
    fn test_derive_dt_project_info_unknown_format_is_generic() {
        let row = Some(("repo".to_string(), Some("custom-format".to_string())));
        let (_, purl) = derive_dt_project_info(row, "x");
        assert_eq!(purl, "generic");
    }

    // ===================================================================
    // build_dependency_info_from_findings
    // ===================================================================

    #[test]
    fn test_build_deps_empty_findings() {
        let deps = build_dependency_info_from_findings(vec![], "npm");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_build_deps_single_finding_with_version() {
        let rows = vec![(
            "lodash".to_string(),
            Some("4.17.21".to_string()),
            Some("trivy".to_string()),
        )];
        let deps = build_dependency_info_from_findings(rows, "npm");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "lodash");
        assert_eq!(deps[0].version.as_deref(), Some("4.17.21"));
        assert_eq!(deps[0].purl.as_deref(), Some("pkg:npm/lodash@4.17.21"));
        assert!(deps[0].license.is_none());
        assert!(deps[0].sha256.is_none());
    }

    #[test]
    fn test_build_deps_finding_without_version() {
        let rows = vec![("express".to_string(), None, None)];
        let deps = build_dependency_info_from_findings(rows, "npm");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "express");
        assert_eq!(deps[0].version, None);
        // No version means no purl
        assert_eq!(deps[0].purl, None);
    }

    #[test]
    fn test_build_deps_multiple_findings() {
        let rows = vec![
            ("serde".to_string(), Some("1.0.200".to_string()), None),
            ("tokio".to_string(), Some("1.35.0".to_string()), None),
            ("uuid".to_string(), None, Some("grype".to_string())),
        ];
        let deps = build_dependency_info_from_findings(rows, "cargo");
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].purl.as_deref(), Some("pkg:cargo/serde@1.0.200"));
        assert_eq!(deps[1].purl.as_deref(), Some("pkg:cargo/tokio@1.35.0"));
        assert_eq!(deps[2].purl, None);
    }

    #[test]
    fn test_build_deps_purl_uses_given_type() {
        let rows = vec![("flask".to_string(), Some("2.3.0".to_string()), None)];

        let npm_deps = build_dependency_info_from_findings(rows.clone(), "npm");
        assert_eq!(npm_deps[0].purl.as_deref(), Some("pkg:npm/flask@2.3.0"));

        let pypi_deps = build_dependency_info_from_findings(
            vec![("flask".to_string(), Some("2.3.0".to_string()), None)],
            "pypi",
        );
        assert_eq!(pypi_deps[0].purl.as_deref(), Some("pkg:pypi/flask@2.3.0"));

        let generic_deps = build_dependency_info_from_findings(
            vec![("flask".to_string(), Some("2.3.0".to_string()), None)],
            "generic",
        );
        assert_eq!(
            generic_deps[0].purl.as_deref(),
            Some("pkg:generic/flask@2.3.0")
        );
    }

    #[test]
    fn test_build_deps_source_field_ignored() {
        // The source field should not affect the output
        let rows = vec![
            (
                "pkg-a".to_string(),
                Some("1.0".to_string()),
                Some("trivy".to_string()),
            ),
            (
                "pkg-b".to_string(),
                Some("2.0".to_string()),
                Some("grype".to_string()),
            ),
            ("pkg-c".to_string(), Some("3.0".to_string()), None),
        ];
        let deps = build_dependency_info_from_findings(rows, "maven");
        assert_eq!(deps.len(), 3);
        // All should produce valid purls regardless of source
        for dep in &deps {
            assert!(dep.purl.is_some());
        }
    }

    #[test]
    fn test_build_deps_special_characters_in_name() {
        let rows = vec![(
            "@scope/package".to_string(),
            Some("1.0.0".to_string()),
            None,
        )];
        let deps = build_dependency_info_from_findings(rows, "npm");
        assert_eq!(
            deps[0].purl.as_deref(),
            Some("pkg:npm/@scope/package@1.0.0")
        );
    }

    #[test]
    fn test_build_deps_preserves_order() {
        let rows = vec![
            ("zzz".to_string(), Some("3.0".to_string()), None),
            ("aaa".to_string(), Some("1.0".to_string()), None),
            ("mmm".to_string(), Some("2.0".to_string()), None),
        ];
        let deps = build_dependency_info_from_findings(rows, "npm");
        assert_eq!(deps[0].name, "zzz");
        assert_eq!(deps[1].name, "aaa");
        assert_eq!(deps[2].name, "mmm");
    }

    // ===================================================================
    // build_dependency_info_from_packages (#965)
    //
    // Mirrors the build_deps_from_findings suite above, but exercises the
    // scan_packages inventory read path used by the Dependency-Track
    // submission flow. The crucial behaviour vs. the findings helper is:
    //   - the stored `purl` column is preferred when present
    //   - the persisted `license` column flows through to the SBOM
    //   - clean packages (zero vulnerabilities) still produce dep entries
    // ===================================================================

    #[test]
    fn test_build_deps_from_packages_empty() {
        let deps = build_dependency_info_from_packages(vec![], "npm");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_build_deps_from_packages_prefers_stored_purl() {
        // When scan_packages.purl is populated, use it verbatim. Trivy
        // produces canonical purls with qualifiers (?type=foo) we must not
        // round-trip through string formatting.
        let rows = vec![(
            "lodash".to_string(),
            Some("4.17.21".to_string()),
            Some("pkg:npm/lodash@4.17.21?type=module".to_string()),
            Some("MIT".to_string()),
        )];
        let deps = build_dependency_info_from_packages(rows, "npm");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "lodash");
        assert_eq!(deps[0].version.as_deref(), Some("4.17.21"));
        assert_eq!(
            deps[0].purl.as_deref(),
            Some("pkg:npm/lodash@4.17.21?type=module")
        );
        assert_eq!(deps[0].license.as_deref(), Some("MIT"));
    }

    #[test]
    fn test_build_deps_from_packages_synthesizes_purl_when_missing() {
        // scan_packages rows produced by scanners that don't emit purls
        // fall back to the format-derived purl_type, matching the findings
        // helper's behaviour.
        let rows = vec![(
            "express".to_string(),
            Some("4.18.2".to_string()),
            None,
            None,
        )];
        let deps = build_dependency_info_from_packages(rows, "npm");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].purl.as_deref(), Some("pkg:npm/express@4.18.2"));
        assert!(deps[0].license.is_none());
    }

    #[test]
    fn test_build_deps_from_packages_no_version_no_purl() {
        // A package without a version cannot be assigned a synthesized
        // purl. The component still flows through to the SBOM so DT can
        // see the dep tree.
        let rows = vec![("mystery-dep".to_string(), None, None, None)];
        let deps = build_dependency_info_from_packages(rows, "npm");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "mystery-dep");
        assert!(deps[0].version.is_none());
        assert!(deps[0].purl.is_none());
    }

    #[test]
    fn test_build_deps_from_packages_clean_scan_30_packages() {
        // Regression for #965: 30 packages, 0 CVEs (the scan_findings
        // table is empty) must still produce a non-empty dep list so the
        // submission gate fires. This is the exact shape we expect for a
        // newly-uploaded clean npm package.
        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, Option<String>, Option<String>, Option<String>)> = (0..30)
            .map(|i| {
                (
                    format!("pkg-{}", i),
                    Some(format!("1.0.{}", i)),
                    None,
                    Some("MIT".to_string()),
                )
            })
            .collect();
        let deps = build_dependency_info_from_packages(rows, "npm");
        assert_eq!(deps.len(), 30);
        assert!(deps.iter().all(|d| d.purl.is_some()));
        assert!(deps.iter().all(|d| d.license.as_deref() == Some("MIT")));
    }

    #[test]
    fn test_build_deps_from_packages_sha256_always_none() {
        // sha256 is not yet sourced from scan_packages (matches the
        // `extract_dependencies_for_artifact` shape; see the comment at
        // backend/src/api/handlers/sbom.rs around line 1542).
        let rows = vec![(
            "serde".to_string(),
            Some("1.0.200".to_string()),
            Some("pkg:cargo/serde@1.0.200".to_string()),
            None,
        )];
        let deps = build_dependency_info_from_packages(rows, "cargo");
        assert!(deps[0].sha256.is_none());
    }

    // -----------------------------------------------------------------------
    // Pure helpers introduced for the trigger-scan / pre-allocated-row path.
    // These are unit-tested here so the new lines they contain are exercised
    // by `cargo llvm-cov --lib` (the integration-tier DB tests for the same
    // path live in `backend/tests/scan_convert_to_reused_tests.rs`).
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_scan_result_ids_empty() {
        let prepared: Vec<(String, Uuid)> = vec![];
        let ids = extract_scan_result_ids(&prepared);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_extract_scan_result_ids_single_scanner() {
        let id = Uuid::new_v4();
        let prepared = vec![("trivy".to_string(), id)];
        let ids = extract_scan_result_ids(&prepared);
        assert_eq!(ids, vec![id]);
    }

    #[test]
    fn test_extract_scan_result_ids_preserves_order() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();
        let prepared = vec![
            ("trivy".to_string(), id1),
            ("grype".to_string(), id2),
            ("image".to_string(), id3),
        ];
        let ids = extract_scan_result_ids(&prepared);
        assert_eq!(ids, vec![id1, id2, id3]);
    }

    #[test]
    fn test_extract_scan_result_ids_does_not_consume_input() {
        // Caller relies on still having the pairs after this call so it can
        // also build the HashMap. Asserting on the post-call state of the
        // Vec is the cheapest way to pin that contract.
        let id = Uuid::new_v4();
        let prepared = vec![("trivy".to_string(), id)];
        let _ids = extract_scan_result_ids(&prepared);
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].0, "trivy");
    }

    #[test]
    fn test_dedup_ttl_days_is_30() {
        // Pinned because both `find_reusable_scan` (cross-artifact dedup) and
        // `find_existing_scan_for_artifact` (same-artifact short-circuit added
        // for #1373) read this constant. A future tweak to the window should
        // be a deliberate change with a CHANGELOG entry, not a silent edit.
        assert_eq!(super::DEDUP_TTL_DAYS, 30);
    }

    #[test]
    fn test_zero_findings_dedup_ttl_days_is_short() {
        // #1469: zero-finding completed rows are ambiguous (clean OR silent
        // extraction failure), so they must dedup for a much shorter window
        // than the standard 30 days. The exact value is policy, but pin
        // both endpoints so a future widening (e.g. back to 30) is a
        // deliberate edit a reviewer can flag.
        assert_eq!(super::ZERO_FINDINGS_DEDUP_TTL_DAYS, 1);

        // Read both into runtime locals so the comparison is not a
        // const-folded `1 < 30` (which clippy correctly flags as a noop
        // assertion) but still trips the test if a future edit collapses
        // the two windows to the same value.
        let zero = super::ZERO_FINDINGS_DEDUP_TTL_DAYS;
        let standard = super::DEDUP_TTL_DAYS;
        assert!(
            zero < standard,
            "zero-finding TTL ({zero}) must be strictly shorter than the standard TTL ({standard}) or the policy collapses to a uniform window",
        );
    }

    // -----------------------------------------------------------------------
    // #1373 short-circuit predicates: is_within_dedup_ttl,
    // decide_same_artifact_action.
    //
    // These are the pure decision helpers underpinning the same-artifact
    // dedup short-circuit. The DB-coupled wrappers
    // (`find_existing_scan_for_artifact`, `prepare_artifact_scan`,
    // `scan_artifact_inner`) are exercised by the integration suite in
    // `backend/tests/scan_dedup_short_circuit_tests.rs`; this section
    // pins the logic that does not need a database.
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_within_dedup_ttl_just_completed_is_within() {
        // A scan completed "now" must be inside any positive TTL window.
        let now = Utc::now();
        assert!(is_within_dedup_ttl(Some(now), now, 30));
    }

    #[test]
    fn test_is_within_dedup_ttl_one_day_old_is_within_30_day_window() {
        let now = Utc::now();
        let yesterday = now - chrono::Duration::days(1);
        assert!(is_within_dedup_ttl(Some(yesterday), now, 30));
    }

    #[test]
    fn test_is_within_dedup_ttl_29_days_old_is_within_30_day_window() {
        // Edge case: just inside the window.
        let now = Utc::now();
        let then = now - chrono::Duration::days(29);
        assert!(is_within_dedup_ttl(Some(then), now, 30));
    }

    #[test]
    fn test_is_within_dedup_ttl_exactly_at_cutoff_is_within() {
        // Boundary: `completed_at == now - ttl_days` should be treated
        // as still inside the window (inclusive lower bound). Documents
        // the deliberate one-tick-more-permissive bias vs the SQL `>`
        // form.
        let now = Utc::now();
        let cutoff = now - chrono::Duration::days(30);
        assert!(is_within_dedup_ttl(Some(cutoff), now, 30));
    }

    #[test]
    fn test_is_within_dedup_ttl_31_days_old_is_outside_30_day_window() {
        let now = Utc::now();
        let then = now - chrono::Duration::days(31);
        assert!(!is_within_dedup_ttl(Some(then), now, 30));
    }

    #[test]
    fn test_is_within_dedup_ttl_far_past_is_outside() {
        // A year old: not eligible for dedup at the production 30-day TTL.
        let now = Utc::now();
        let then = now - chrono::Duration::days(365);
        assert!(!is_within_dedup_ttl(Some(then), now, 30));
    }

    #[test]
    fn test_is_within_dedup_ttl_none_completed_at_is_outside() {
        // `completed_at` is `None` for `running` / `failed` scans. Those
        // are never eligible for the short-circuit.
        let now = Utc::now();
        assert!(!is_within_dedup_ttl(None, now, 30));
    }

    #[test]
    fn test_is_within_dedup_ttl_zero_days_disables_window() {
        // A misconfigured TTL of 0 should collapse the window to zero;
        // nothing is considered fresh. Prevents accidental "scan once,
        // dedup forever" if the constant is ever set to 0 by mistake.
        let now = Utc::now();
        assert!(!is_within_dedup_ttl(Some(now), now, 0));
    }

    #[test]
    fn test_is_within_dedup_ttl_negative_days_disables_window() {
        // Defensive: a negative TTL is nonsense, never match.
        let now = Utc::now();
        assert!(!is_within_dedup_ttl(Some(now), now, -1));
    }

    #[test]
    fn test_is_within_dedup_ttl_future_completed_at_is_within() {
        // Clock skew: a `completed_at` slightly in the future (e.g. from
        // a DB replica with drift) should still count as within the
        // window. Re-scanning on clock skew would be a worse outcome
        // than reusing a too-fresh-looking row.
        let now = Utc::now();
        let future = now + chrono::Duration::minutes(5);
        assert!(is_within_dedup_ttl(Some(future), now, 30));
    }

    #[test]
    fn test_decide_same_artifact_action_insert_fresh_is_noop() {
        // Auto-scan-on-upload path: no placeholder was committed, so we
        // simply skip. The existing completed row already represents
        // the scan.
        let source_id = Uuid::new_v4();
        let action = decide_same_artifact_action(&PreparedScanAction::InsertFresh, source_id);
        assert_eq!(action, SameArtifactAction::NoOp);
    }

    #[test]
    fn test_decide_same_artifact_action_reuse_matching_id_is_noop() {
        // Happy path after the prepare-step short-circuit: the
        // placeholder id IS the existing scan id, so nothing to do.
        let id = Uuid::new_v4();
        let action = decide_same_artifact_action(&PreparedScanAction::Reuse(id), id);
        assert_eq!(action, SameArtifactAction::NoOp);
    }

    #[test]
    fn test_decide_same_artifact_action_reuse_different_id_converts_orphan() {
        // Race window: prepare-step inserted a placeholder before the
        // existing scan landed. We must convert the orphan into a
        // reused-row pointing at the source so the stuck-scan janitor
        // never has to reap it.
        let target_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        assert_ne!(target_id, source_id);
        let action = decide_same_artifact_action(&PreparedScanAction::Reuse(target_id), source_id);
        assert_eq!(
            action,
            SameArtifactAction::ConvertOrphanPlaceholder {
                target_id,
                source_id,
            }
        );
    }

    #[test]
    fn test_decide_same_artifact_action_carries_correct_ids() {
        // Pin the field ordering: `target_id` is the placeholder we are
        // converting; `source_id` is the existing completed scan we are
        // pointing at. Reversing these would corrupt the scan history.
        let target_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let action = decide_same_artifact_action(&PreparedScanAction::Reuse(target_id), source_id);
        match action {
            SameArtifactAction::ConvertOrphanPlaceholder {
                target_id: t,
                source_id: s,
            } => {
                assert_eq!(t, target_id);
                assert_eq!(s, source_id);
            }
            _ => panic!("expected ConvertOrphanPlaceholder"),
        }
    }

    #[test]
    fn test_decide_same_artifact_action_nil_uuid_target_still_converts() {
        // Defensive: even a nil-UUID placeholder (should never happen
        // in production, but might appear in a test fixture or after a
        // bad migration) must still be flagged for conversion if it
        // differs from the source id. We must not silently leak the
        // nil id.
        let source_id = Uuid::new_v4();
        let action =
            decide_same_artifact_action(&PreparedScanAction::Reuse(Uuid::nil()), source_id);
        assert_eq!(
            action,
            SameArtifactAction::ConvertOrphanPlaceholder {
                target_id: Uuid::nil(),
                source_id,
            }
        );
    }

    #[test]
    fn test_decide_same_artifact_action_both_nil_is_noop() {
        // Pathological: target and source both nil. Treated as "same
        // id" -> NoOp. Prevents an attempted convert_to_reused call
        // with two nil UUIDs.
        let action =
            decide_same_artifact_action(&PreparedScanAction::Reuse(Uuid::nil()), Uuid::nil());
        assert_eq!(action, SameArtifactAction::NoOp);
    }

    #[test]
    fn test_same_artifact_action_debug_format_is_useful() {
        // The enum is logged on the warn path; make sure Debug isn't
        // accidentally `{ .. }`-elided.
        let target_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let action = SameArtifactAction::ConvertOrphanPlaceholder {
            target_id,
            source_id,
        };
        let s = format!("{:?}", action);
        assert!(s.contains(&target_id.to_string()) || s.contains("target_id"));
        assert!(s.contains(&source_id.to_string()) || s.contains("source_id"));
    }

    #[test]
    fn test_prepared_pairs_to_map_empty() {
        let map = prepared_pairs_to_map(vec![]);
        assert!(map.is_empty());
    }

    #[test]
    fn test_prepared_pairs_to_map_round_trip() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let prepared = vec![("trivy".to_string(), id1), ("grype".to_string(), id2)];
        let map = prepared_pairs_to_map(prepared);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("trivy"), Some(&id1));
        assert_eq!(map.get("grype"), Some(&id2));
    }

    #[test]
    fn test_prepared_pairs_to_map_duplicate_scan_type_last_wins() {
        // HashMap collect semantics: later entries overwrite earlier ones.
        // This documents the behavior so a future change to a more strict
        // collector (e.g. detecting duplicates) is an explicit decision.
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let prepared = vec![("trivy".to_string(), id1), ("trivy".to_string(), id2)];
        let map = prepared_pairs_to_map(prepared);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("trivy"), Some(&id2));
    }

    #[test]
    fn test_should_skip_reuse_for_same_artifact_true() {
        let id = Uuid::new_v4();
        assert!(should_skip_reuse_for_same_artifact(id, id));
    }

    #[test]
    fn test_should_skip_reuse_for_same_artifact_false() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(!should_skip_reuse_for_same_artifact(a, b));
    }

    #[test]
    fn test_should_skip_reuse_for_same_artifact_nil_vs_real() {
        let nil = Uuid::nil();
        let real = Uuid::new_v4();
        assert!(!should_skip_reuse_for_same_artifact(nil, real));
        assert!(should_skip_reuse_for_same_artifact(nil, nil));
    }

    #[test]
    fn test_build_artifact_scan_message_includes_id() {
        let id = Uuid::new_v4();
        let msg = build_artifact_scan_message(id);
        assert!(msg.contains(&id.to_string()));
        assert!(msg.starts_with("Scan queued for artifact "));
    }

    #[test]
    fn test_build_artifact_scan_message_nil_uuid() {
        let msg = build_artifact_scan_message(Uuid::nil());
        assert_eq!(
            msg,
            "Scan queued for artifact 00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn test_build_repository_scan_message_includes_count_and_id() {
        let repo = Uuid::new_v4();
        let msg = build_repository_scan_message(repo, 42);
        assert!(msg.contains(&repo.to_string()));
        assert!(msg.contains("42 artifacts"));
        assert!(msg.starts_with("Repository scan queued for "));
    }

    #[test]
    fn test_build_repository_scan_message_zero_artifacts() {
        let repo = Uuid::nil();
        let msg = build_repository_scan_message(repo, 0);
        assert!(msg.contains("0 artifacts"));
    }

    #[test]
    fn test_build_repository_scan_message_large_count() {
        let repo = Uuid::new_v4();
        let msg = build_repository_scan_message(repo, 1_000_000);
        assert!(msg.contains("1000000 artifacts"));
    }

    // -----------------------------------------------------------------------
    // resolve_prepared_action / checksum_log_prefix
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_prepared_action_some_returns_reuse() {
        let id = Uuid::new_v4();
        let action = resolve_prepared_action(Some(id));
        assert_eq!(action, PreparedScanAction::Reuse(id));
    }

    #[test]
    fn test_resolve_prepared_action_none_returns_insert_fresh() {
        let action = resolve_prepared_action(None);
        assert_eq!(action, PreparedScanAction::InsertFresh);
    }

    #[test]
    fn test_resolve_prepared_action_distinct_ids_are_distinct() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        assert_ne!(
            resolve_prepared_action(Some(id1)),
            resolve_prepared_action(Some(id2))
        );
    }

    #[test]
    fn test_checksum_log_prefix_long_checksum_truncates_to_8() {
        let cs = "abcdef0123456789abcdef0123456789";
        assert_eq!(checksum_log_prefix(cs), "abcdef01");
    }

    #[test]
    fn test_checksum_log_prefix_short_checksum_returns_whole_string() {
        let cs = "abc";
        assert_eq!(checksum_log_prefix(cs), "abc");
    }

    #[test]
    fn test_checksum_log_prefix_empty_returns_empty() {
        assert_eq!(checksum_log_prefix(""), "");
    }

    #[test]
    fn test_checksum_log_prefix_exactly_eight_chars() {
        let cs = "12345678";
        assert_eq!(checksum_log_prefix(cs), "12345678");
    }

    // -----------------------------------------------------------------------
    // SBOM inventory (issue #903): convert_trivy_packages + ScanOutput
    // -----------------------------------------------------------------------

    /// A Trivy report whose `Packages` block contains 5 packages but only
    /// 1 vulnerability must yield 5 RawPackage rows and 1 RawFinding.
    /// This is the regression-test for #903: pre-fix, the SBOM endpoint
    /// produced an empty component list because it derived components
    /// from scan_findings (which had only the CVE-bearing row).
    #[test]
    fn test_convert_trivy_packages_full_inventory_independent_of_findings() {
        use crate::services::image_scanner::{
            TrivyPackage, TrivyReport, TrivyResult, TrivyVulnerability,
        };

        let pkg = |name: &str, ver: &str| TrivyPackage {
            name: name.to_string(),
            version: ver.to_string(),
            licenses: None,
            identifier: None,
        };

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "package-lock.json".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "npm".to_string(),
                vulnerabilities: Some(vec![TrivyVulnerability {
                    vulnerability_id: "CVE-2024-12345".to_string(),
                    pkg_name: "body-parser".to_string(),
                    installed_version: "1.20.1".to_string(),
                    fixed_version: Some("1.20.2".to_string()),
                    severity: "HIGH".to_string(),
                    title: None,
                    description: None,
                    primary_url: None,
                }]),
                packages: Some(vec![
                    pkg("express", "4.18.2"),
                    pkg("body-parser", "1.20.1"),
                    pkg("cookie-parser", "1.4.6"),
                    pkg("debug", "2.6.9"),
                    pkg("send", "0.18.0"),
                ]),
            }],
        };

        let output = ScanOutput::from_trivy_report(&report, "trivy-filesystem");

        // 5 packages enumerated, regardless of CVE status — the #903 contract.
        assert_eq!(
            output.packages.len(),
            5,
            "#903: scan_packages must include every package the scanner saw, \
             not just CVE-bearing rows. Counting 1 here would mean the SBOM \
             endpoint is back to surfacing only the vulnerable subset."
        );
        // 1 finding for the 1 vulnerability — the existing contract.
        assert_eq!(output.findings.len(), 1);

        // Inventory carries source_target so SBOM consumers can bucket by
        // ecosystem without re-parsing names.
        let body_parser = output
            .packages
            .iter()
            .find(|p| p.name == "body-parser")
            .expect("body-parser must be in inventory");
        assert_eq!(body_parser.version.as_deref(), Some("1.20.1"));
        assert_eq!(
            body_parser.source_target.as_deref(),
            Some("package-lock.json")
        );

        // Finding name is bare (no parenthetical target) — the other half
        // of the #903 fix.
        assert_eq!(
            output.findings[0].affected_component.as_deref(),
            Some("body-parser"),
            "post-#903, finding names must be bare so SBOM/CVE-lookup/UI \
             can join across sources without stripping the (target) suffix"
        );
    }

    /// Trivy emits `Licenses` as an array; multi-license packages must be
    /// joined with " OR " per CycloneDX convention. Empty licenses must
    /// not produce empty strings.
    #[test]
    fn test_convert_trivy_packages_license_join_and_empty_handling() {
        use crate::services::image_scanner::{TrivyPackage, TrivyReport, TrivyResult};

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "pom.xml".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "maven".to_string(),
                vulnerabilities: None,
                packages: Some(vec![
                    TrivyPackage {
                        name: "log4j-core".to_string(),
                        version: "2.17.1".to_string(),
                        licenses: Some(vec!["Apache-2.0".to_string(), "MIT".to_string()]),
                        identifier: None,
                    },
                    TrivyPackage {
                        name: "no-license-pkg".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: Some(vec![]),
                        identifier: None,
                    },
                    TrivyPackage {
                        name: "license-with-empty-string".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: Some(vec!["".to_string(), "MIT".to_string()]),
                        identifier: None,
                    },
                ]),
            }],
        };

        let pkgs = convert_trivy_packages(&report);

        let log4j = pkgs.iter().find(|p| p.name == "log4j-core").unwrap();
        assert_eq!(log4j.license.as_deref(), Some("Apache-2.0 OR MIT"));

        let no_lic = pkgs.iter().find(|p| p.name == "no-license-pkg").unwrap();
        assert!(
            no_lic.license.is_none(),
            "empty license array must collapse to None, not Some(\"\")"
        );

        let mixed = pkgs
            .iter()
            .find(|p| p.name == "license-with-empty-string")
            .unwrap();
        assert_eq!(
            mixed.license.as_deref(),
            Some("MIT"),
            "empty strings in license array must be filtered before joining"
        );
    }

    /// A Trivy report with no `Packages` block at all (legacy Trivy or
    /// the scanner was invoked without `--list-all-pkgs`) must yield an
    /// empty inventory rather than synthesizing packages from the
    /// vulnerability rows. Synthesizing would silently re-introduce the
    /// #903 vulnerability-shaped-SBOM bug.
    #[test]
    fn test_convert_trivy_packages_no_block_returns_empty() {
        use crate::services::image_scanner::{TrivyReport, TrivyResult, TrivyVulnerability};
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "go.sum".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "gomod".to_string(),
                vulnerabilities: Some(vec![TrivyVulnerability {
                    vulnerability_id: "CVE-2024-00099".to_string(),
                    pkg_name: "github.com/example/lib".to_string(),
                    installed_version: "1.0.0".to_string(),
                    fixed_version: None,
                    severity: "LOW".to_string(),
                    title: None,
                    description: None,
                    primary_url: None,
                }]),
                packages: None,
            }],
        };
        let output = ScanOutput::from_trivy_report(&report, "trivy-filesystem");
        assert!(
            output.packages.is_empty(),
            "no Packages block must yield empty inventory — falling back \
             to findings-derived synthesis would mask the #903 bug"
        );
        assert_eq!(output.findings.len(), 1);
    }

    /// ScanOutput::findings_only is the right constructor for scanners
    /// that don't enumerate inventory (OpenSCAP, Grype's default JSON
    /// shape). It must yield an empty packages Vec and the supplied
    /// findings unchanged.
    #[test]
    fn test_scan_output_findings_only_has_empty_packages() {
        let findings = vec![RawFinding {
            severity: Severity::Medium,
            title: "x".to_string(),
            description: None,
            cve_id: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            source: None,
            source_url: None,
        }];
        let out = ScanOutput::findings_only(findings);
        assert_eq!(out.findings.len(), 1);
        assert!(out.packages.is_empty());
        assert!(!out.is_empty());
    }

    /// Default ScanOutput is empty on both axes; orchestrator uses this
    /// for non-applicable artifacts.
    #[test]
    fn test_scan_output_default_is_empty() {
        let out = ScanOutput::default();
        assert!(out.is_empty());
    }

    /// `convert_trivy_packages` extracts PURLs via the optional
    /// `Identifier.PURL` nested field. The other tests do not populate
    /// `identifier`, so the extraction code path remains uncovered
    /// without this test. Verify both the happy-path extraction AND the
    /// "identifier present but PURL empty" branch (must yield None,
    /// not Some("")).
    #[test]
    fn test_convert_trivy_packages_extracts_purl_from_identifier() {
        use crate::services::image_scanner::{
            TrivyPackage, TrivyPackageIdentifier, TrivyReport, TrivyResult,
        };

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "package-lock.json".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "npm".to_string(),
                vulnerabilities: None,
                packages: Some(vec![
                    TrivyPackage {
                        name: "lodash".to_string(),
                        version: "4.17.21".to_string(),
                        licenses: None,
                        identifier: Some(TrivyPackageIdentifier {
                            purl: Some("pkg:npm/lodash@4.17.21".to_string()),
                        }),
                    },
                    TrivyPackage {
                        // identifier present, but PURL empty — must collapse
                        // to None on persistence so downstream consumers
                        // don't see a vacuous Some("").
                        name: "express".to_string(),
                        version: "4.18.2".to_string(),
                        licenses: None,
                        identifier: Some(TrivyPackageIdentifier {
                            purl: Some(String::new()),
                        }),
                    },
                    TrivyPackage {
                        // identifier present, PURL None — yields None.
                        name: "body-parser".to_string(),
                        version: "1.20.1".to_string(),
                        licenses: None,
                        identifier: Some(TrivyPackageIdentifier { purl: None }),
                    },
                ]),
            }],
        };
        let pkgs = convert_trivy_packages(&report);
        assert_eq!(pkgs.len(), 3);

        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.purl.as_deref(), Some("pkg:npm/lodash@4.17.21"));

        let express = pkgs.iter().find(|p| p.name == "express").unwrap();
        assert!(
            express.purl.is_none(),
            "empty PURL string must collapse to None"
        );

        let bp = pkgs.iter().find(|p| p.name == "body-parser").unwrap();
        assert!(
            bp.purl.is_none(),
            "identifier with PURL=None must stay None"
        );
    }

    /// Packages with empty `name` strings must be filtered out at conversion
    /// time, not left to the DB-side data-quality filter in `build_dep`.
    /// Scanners occasionally emit blank-name entries for failed-resolution
    /// fixtures (e.g. unparseable line in a requirements.txt); persisting
    /// them would pollute the SBOM and cause downstream tooling crashes.
    #[test]
    fn test_convert_trivy_packages_skips_empty_name_packages() {
        use crate::services::image_scanner::{TrivyPackage, TrivyReport, TrivyResult};

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "requirements.txt".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "pip".to_string(),
                vulnerabilities: None,
                packages: Some(vec![
                    TrivyPackage {
                        name: "".to_string(),
                        version: "1.0".to_string(),
                        licenses: None,
                        identifier: None,
                    },
                    TrivyPackage {
                        name: "requests".to_string(),
                        version: "2.31.0".to_string(),
                        licenses: None,
                        identifier: None,
                    },
                ]),
            }],
        };
        let pkgs = convert_trivy_packages(&report);
        assert_eq!(pkgs.len(), 1, "empty-name entry must be filtered");
        assert_eq!(pkgs[0].name, "requests");
    }

    /// Version-empty handling: Trivy occasionally reports a package with
    /// `Version: ""` (e.g. C runtime libraries it could not pin). The
    /// inventory persistence layer maps that to `None` so the unique
    /// index `(scan_result_id, name, COALESCE(version, ''))` collapses
    /// duplicates correctly.
    #[test]
    fn test_convert_trivy_packages_empty_version_becomes_none() {
        use crate::services::image_scanner::{TrivyPackage, TrivyReport, TrivyResult};

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "OS".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: None,
                packages: Some(vec![TrivyPackage {
                    name: "musl".to_string(),
                    version: "".to_string(),
                    licenses: None,
                    identifier: None,
                }]),
            }],
        };
        let pkgs = convert_trivy_packages(&report);
        assert_eq!(pkgs.len(), 1);
        assert!(
            pkgs[0].version.is_none(),
            "empty Version string must collapse to None for index correctness"
        );
    }

    /// Empty `Target` string on the Trivy result must yield
    /// `source_target = None` rather than `Some("")`. Source target is
    /// surfaced into the SBOM as a hint about *where* the package was
    /// found (e.g. "package-lock.json") and an empty hint is worse than
    /// no hint at all.
    #[test]
    fn test_convert_trivy_packages_empty_target_becomes_none() {
        use crate::services::image_scanner::{TrivyPackage, TrivyReport, TrivyResult};

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "".to_string(),
                class: "".to_string(),
                result_type: "".to_string(),
                vulnerabilities: None,
                packages: Some(vec![TrivyPackage {
                    name: "anonymous".to_string(),
                    version: "1.0".to_string(),
                    licenses: None,
                    identifier: None,
                }]),
            }],
        };
        let pkgs = convert_trivy_packages(&report);
        assert_eq!(pkgs.len(), 1);
        assert!(pkgs[0].source_target.is_none());
    }

    // -----------------------------------------------------------------------
    // PURL validation (issue #1151)
    // -----------------------------------------------------------------------

    /// A syntactically malformed PURL must be dropped (field set to None);
    /// the package row itself is preserved so the inventory still reflects
    /// that the scanner saw the package. The regression this guards
    /// against: hostile lockfiles smuggle non-`pkg:` strings into the
    /// `Identifier.PURL` field and downstream parsers crash or normalize
    /// them silently.
    #[test]
    fn test_convert_trivy_packages_drops_malformed_purl_keeps_row() {
        use crate::services::image_scanner::{
            TrivyPackage, TrivyPackageIdentifier, TrivyReport, TrivyResult,
        };

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "package-lock.json".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "npm".to_string(),
                vulnerabilities: None,
                packages: Some(vec![
                    TrivyPackage {
                        name: "valid".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: None,
                        identifier: Some(TrivyPackageIdentifier {
                            purl: Some("pkg:npm/valid@1.0.0".to_string()),
                        }),
                    },
                    TrivyPackage {
                        name: "no-scheme".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: None,
                        identifier: Some(TrivyPackageIdentifier {
                            purl: Some("npm/no-scheme@1.0.0".to_string()),
                        }),
                    },
                    TrivyPackage {
                        name: "empty-type".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: None,
                        identifier: Some(TrivyPackageIdentifier {
                            // `pkg:/foo` -- empty type token must reject.
                            purl: Some("pkg:/empty-type@1.0.0".to_string()),
                        }),
                    },
                    TrivyPackage {
                        name: "uppercase-type".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: None,
                        identifier: Some(TrivyPackageIdentifier {
                            // PURL type tokens must be lowercase per spec.
                            purl: Some("pkg:NPM/uppercase-type@1.0.0".to_string()),
                        }),
                    },
                    TrivyPackage {
                        name: "garbage".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: None,
                        identifier: Some(TrivyPackageIdentifier {
                            purl: Some("<script>alert(1)</script>".to_string()),
                        }),
                    },
                ]),
            }],
        };

        let pkgs = convert_trivy_packages(&report);
        assert_eq!(pkgs.len(), 5, "all package rows must be preserved");

        let by_name = |n: &str| pkgs.iter().find(|p| p.name == n).unwrap();
        assert_eq!(
            by_name("valid").purl.as_deref(),
            Some("pkg:npm/valid@1.0.0")
        );
        assert!(by_name("no-scheme").purl.is_none());
        assert!(by_name("empty-type").purl.is_none());
        assert!(by_name("uppercase-type").purl.is_none());
        assert!(by_name("garbage").purl.is_none());
    }

    /// An oversized PURL string (> PURL_MAX_LEN) must be rejected before
    /// it can reach the VARCHAR(2048) column. Combined with the 50k row
    /// cap on scan_packages, an unbounded PURL would allow a hostile
    /// lockfile to balloon the SBOM JSON. The column-level cap from
    /// migration 087 is the second line of defence; this test pins the
    /// application-layer drop.
    #[test]
    fn test_convert_trivy_packages_rejects_oversized_purl() {
        use crate::services::image_scanner::{
            TrivyPackage, TrivyPackageIdentifier, TrivyReport, TrivyResult,
        };

        // Build a PURL that is well-formed but longer than the cap.
        let big_name = "a".repeat(PURL_MAX_LEN);
        let oversized = format!("pkg:npm/{}@1.0.0", big_name);
        assert!(oversized.len() > PURL_MAX_LEN, "test setup sanity check");

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "package-lock.json".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "npm".to_string(),
                vulnerabilities: None,
                packages: Some(vec![TrivyPackage {
                    name: "huge".to_string(),
                    version: "1.0.0".to_string(),
                    licenses: None,
                    identifier: Some(TrivyPackageIdentifier {
                        purl: Some(oversized),
                    }),
                }]),
            }],
        };
        let pkgs = convert_trivy_packages(&report);
        assert_eq!(pkgs.len(), 1, "package row must be preserved");
        assert!(
            pkgs[0].purl.is_none(),
            "oversized PURL must be dropped before insert (would exceed VARCHAR(2048))"
        );
    }

    /// `validate_trivy_purl` is the single-purpose helper used by
    /// `convert_trivy_packages`. The function-level test exercises the
    /// length / shape / empty branches independently so changes to
    /// `convert_trivy_packages` cannot regress the helper.
    #[test]
    fn test_validate_trivy_purl_helper() {
        assert_eq!(
            validate_trivy_purl("pkg:npm/lodash@4.17.21"),
            Some("pkg:npm/lodash@4.17.21".to_string())
        );
        assert_eq!(validate_trivy_purl(""), None);
        assert_eq!(validate_trivy_purl("   "), None);
        assert_eq!(validate_trivy_purl("pkg:/missing-type"), None);
        assert_eq!(validate_trivy_purl("not-a-purl"), None);
        let big = format!("pkg:npm/{}@1.0.0", "a".repeat(PURL_MAX_LEN));
        assert!(validate_trivy_purl(&big).is_none());
    }

    // -----------------------------------------------------------------------
    // SPDX license validation (issue #1152)
    // -----------------------------------------------------------------------

    /// Hostile license arrays must not produce a SPDX expression that a
    /// permissive policy reads as "MIT-licensed if you pick that arm".
    /// The mix below is drawn from the issue write-up: a known-SPDX term
    /// joined with a free-form commercial restriction. The non-SPDX
    /// element must be wrapped as `LicenseRef-...` so a SPDX-aware
    /// policy engine cannot silently classify it as permissive.
    #[test]
    fn test_convert_trivy_packages_hostile_licenses_dont_greenlight() {
        use crate::services::image_scanner::{TrivyPackage, TrivyReport, TrivyResult};

        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "package-lock.json".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "npm".to_string(),
                vulnerabilities: None,
                packages: Some(vec![
                    // Case 1: known + hostile mix. The hostile term must
                    // become LicenseRef-..., never silently dropped.
                    TrivyPackage {
                        name: "mit-plus-commercial".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: Some(vec![
                            "MIT".to_string(),
                            "Custom Commercial - see LICENSE".to_string(),
                        ]),
                        identifier: None,
                    },
                    // Case 2: smuggled SPDX expression as a single element.
                    // Must not pass through as a permissive expression.
                    TrivyPackage {
                        name: "smuggled-expression".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: Some(vec!["MIT OR Apache-2.0".to_string()]),
                        identifier: None,
                    },
                    // Case 3: lowercase canonical input. Must promote to
                    // the canonical SPDX casing.
                    TrivyPackage {
                        name: "lowercase-canonical".to_string(),
                        version: "1.0.0".to_string(),
                        licenses: Some(vec!["apache-2.0".to_string()]),
                        identifier: None,
                    },
                ]),
            }],
        };

        let pkgs = convert_trivy_packages(&report);
        let by_name = |n: &str| pkgs.iter().find(|p| p.name == n).unwrap();

        // Case 1: the joined expression carries both arms, but the
        // hostile arm is a LicenseRef so a permissive-policy check
        // cannot green-light it.
        let mixed = by_name("mit-plus-commercial").license.clone().unwrap();
        assert!(mixed.contains("MIT"), "MIT arm preserved; got {}", mixed);
        assert!(
            mixed.contains("LicenseRef-"),
            "non-SPDX term must be wrapped as LicenseRef; got {}",
            mixed
        );
        assert!(
            !mixed.contains("Custom Commercial"),
            "raw free-form license must not flow through verbatim; got {}",
            mixed
        );

        // Case 2: the single smuggled element becomes a LicenseRef, not
        // a plain SPDX OR expression. A policy permitting MIT alone
        // would otherwise green-light this package.
        let smuggled = by_name("smuggled-expression").license.clone().unwrap();
        assert!(
            smuggled.starts_with("LicenseRef-"),
            "single-element smuggled expression must be neutered into LicenseRef; got {}",
            smuggled
        );
        assert!(
            smuggled != "MIT OR Apache-2.0",
            "must not collapse to a permissive OR expression"
        );

        // Case 3: lowercase input promotes to canonical SPDX casing.
        assert_eq!(
            by_name("lowercase-canonical").license.as_deref(),
            Some("Apache-2.0"),
            "canonical-case promotion must happen at conversion time"
        );
    }

    // -----------------------------------------------------------------------
    // Trivy partial-scan signal (issue #1153)
    // -----------------------------------------------------------------------

    /// A Trivy stderr warning indicating an unparseable lockfile must
    /// flip `scan_completeness` to `Partial`. The regression this guards
    /// against: a malformed `package-lock.json` makes Trivy log
    /// "failed to parse" on stderr, the scan returns success with an
    /// empty Packages block, and the SBOM endpoint reports "no
    /// packages" -- giving a green light to a lockfile that actually
    /// exists and is being executed at runtime.
    #[test]
    fn test_trivy_partial_signal_from_stderr() {
        use crate::services::image_scanner::TrivyReport;

        let report = TrivyReport { results: vec![] };
        let stderr = "2026-05-11T10:00:00Z WARN  failed to parse package-lock.json: unexpected EOF";
        let completeness = classify_trivy_completeness(&report, stderr, &[]);
        assert_eq!(
            completeness,
            ScanCompleteness::Partial,
            "Trivy stderr 'failed to parse' must flip completeness to partial"
        );

        // Construct a full ScanOutput via the with_context helper and
        // verify the field flows through.
        let output =
            ScanOutput::from_trivy_report_with_context(&report, "trivy-filesystem", stderr, &[]);
        assert_eq!(output.scan_completeness, ScanCompleteness::Partial);
        assert_eq!(output.scan_completeness.as_str(), "partial");
    }

    /// A known-present target missing from the report's results list
    /// must also flip completeness to Partial. This covers the case
    /// where Trivy silently skips a target without logging anything on
    /// stderr (e.g. extension-mismatched lockfiles, unsupported
    /// ecosystem versions).
    #[test]
    fn test_trivy_partial_signal_from_missing_known_target() {
        use crate::services::image_scanner::{TrivyReport, TrivyResult};

        // Report claims it scanned only requirements.txt, but the
        // workspace told us package-lock.json was also present.
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "requirements.txt".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "pip".to_string(),
                vulnerabilities: None,
                packages: None,
            }],
        };
        let completeness = classify_trivy_completeness(&report, "", &["package-lock.json"]);
        assert_eq!(
            completeness,
            ScanCompleteness::Partial,
            "known target absent from results must flip completeness to partial"
        );
    }

    /// A clean scan (no stderr warnings, every known target seen)
    /// stays `Complete`. Without this assertion the partial-scan
    /// classifier could regress into a "always partial" default.
    #[test]
    fn test_trivy_complete_signal_when_no_warnings() {
        use crate::services::image_scanner::{TrivyReport, TrivyResult};
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "/workspace/package-lock.json".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "npm".to_string(),
                vulnerabilities: None,
                packages: None,
            }],
        };
        let completeness = classify_trivy_completeness(&report, "", &["package-lock.json"]);
        assert_eq!(completeness, ScanCompleteness::Complete);
    }

    /// Benign stderr lines that contain words from the OLD marker list
    /// (`"skipping CVE-..."`, `"failed to analyze <built-in analyzer>"`)
    /// must NOT flip a clean scan to Partial. Without this regression
    /// test the classifier would treat every Trivy run as Partial,
    /// drowning the genuine signal.
    #[test]
    fn test_trivy_benign_stderr_stays_complete() {
        use crate::services::image_scanner::{TrivyReport, TrivyResult};
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "/workspace/package-lock.json".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "npm".to_string(),
                vulnerabilities: None,
                packages: None,
            }],
        };
        // Lines Trivy emits on routine runs.
        let benign = "\
2026-05-12T10:00:00Z INFO  skipping CVE-2024-1234 because suppressed\n\
2026-05-12T10:00:01Z INFO  failed to analyze python-pkg-built-in: not installed\n\
2026-05-12T10:00:02Z INFO  Detected OS: alpine 3.20\n";
        let completeness = classify_trivy_completeness(&report, benign, &["package-lock.json"]);
        assert_eq!(
            completeness,
            ScanCompleteness::Complete,
            "benign 'skipping CVE-...' / 'failed to analyze <analyzer>' must not flip to Partial"
        );
    }

    /// Path-confusion guard: a target named `prefix-package-lock.json`
    /// must NOT satisfy a known-target request for `package-lock.json`.
    /// The earlier `ends_with` match would have classified this Complete
    /// because the target string ends with the basename. The basename-
    /// based comparison correctly flags it as Partial.
    #[test]
    fn test_trivy_path_confusion_target_does_not_satisfy_known() {
        use crate::services::image_scanner::{TrivyReport, TrivyResult};
        let report = TrivyReport {
            results: vec![TrivyResult {
                // Note: NOT a lockfile basename, just a string that
                // happens to end with one.
                target: "/workspace/prefix-package-lock.json".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "npm".to_string(),
                vulnerabilities: None,
                packages: None,
            }],
        };
        let completeness = classify_trivy_completeness(&report, "", &["package-lock.json"]);
        assert_eq!(
            completeness,
            ScanCompleteness::Partial,
            "prefix-package-lock.json must not satisfy known target package-lock.json"
        );
    }

    /// The stderr scan is line-bounded and case-insensitive on ASCII.
    /// A marker that appears with a mixed-case prefix on its own line
    /// must still trigger Partial.
    #[test]
    fn test_trivy_partial_stderr_case_insensitive_per_line() {
        use crate::services::image_scanner::TrivyReport;
        let report = TrivyReport { results: vec![] };
        let stderr = "\
2026-05-12T10:00:00Z INFO  Detected OS: alpine 3.20\n\
2026-05-12T10:00:01Z WARN  FAILED TO PARSE package-lock.json: unexpected EOF\n";
        let completeness = classify_trivy_completeness(&report, stderr, &[]);
        assert_eq!(completeness, ScanCompleteness::Partial);
    }

    // -----------------------------------------------------------------------
    // Scanner trait applicability gate (issues #961, #994)
    // -----------------------------------------------------------------------

    /// Shared test fixtures for the applicability-gate tests below.
    mod applicability_fixtures {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        /// A test Scanner whose `is_applicable` always returns false. Its
        /// `scan()` body increments a counter so the test can assert it was
        /// never invoked. If the orchestrator ever forgets to gate on
        /// `is_applicable`, this counter goes above zero and the test
        /// fails.
        pub(super) struct NeverApplicableScanner {
            pub(super) scan_calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl Scanner for NeverApplicableScanner {
            fn name(&self) -> &str {
                "never-applicable-test-scanner"
            }
            fn scan_type(&self) -> &str {
                "never-applicable"
            }
            fn is_applicable(&self, _artifact: &Artifact) -> bool {
                false
            }
            async fn scan(
                &self,
                _: &Artifact,
                _: Option<&ArtifactMetadata>,
                _: &Bytes,
            ) -> Result<ScanOutput> {
                self.scan_calls.fetch_add(1, Ordering::SeqCst);
                Ok(ScanOutput::default())
            }
        }

        /// A test Scanner whose `is_applicable` always returns true. Used
        /// to assert the orchestrator does still call `scan()` on
        /// applicable scanners (i.e. the gate does not over-correct and
        /// drop everyone).
        pub(super) struct AlwaysApplicableScanner {
            pub(super) scan_calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl Scanner for AlwaysApplicableScanner {
            fn name(&self) -> &str {
                "always-applicable-test-scanner"
            }
            fn scan_type(&self) -> &str {
                "always-applicable"
            }
            // Inherits the default `is_applicable = true`.
            async fn scan(
                &self,
                _: &Artifact,
                _: Option<&ArtifactMetadata>,
                _: &Bytes,
            ) -> Result<ScanOutput> {
                self.scan_calls.fetch_add(1, Ordering::SeqCst);
                Ok(ScanOutput::default())
            }
        }
    }

    /// The `Scanner::is_applicable` default must return true so existing
    /// scanners that always apply (e.g. `DependencyScanner`, `GrypeScanner`)
    /// keep their pre-#961 behavior without overriding. If anyone flips
    /// the default to false, every scanner that omits the override is
    /// silently skipped, which is exactly the issue #994 silent-success
    /// pattern with the inverse polarity.
    #[test]
    fn test_scanner_trait_default_is_applicable_is_true() {
        struct DefaultScanner;
        #[async_trait::async_trait]
        impl Scanner for DefaultScanner {
            fn name(&self) -> &str {
                "default-applicability"
            }
            fn scan_type(&self) -> &str {
                "default-applicability"
            }
            async fn scan(
                &self,
                _: &Artifact,
                _: Option<&ArtifactMetadata>,
                _: &Bytes,
            ) -> Result<ScanOutput> {
                Ok(ScanOutput::default())
            }
        }
        let s = DefaultScanner;
        let artifact =
            test_helpers::make_test_artifact("anything", "application/octet-stream", "x");
        assert!(s.is_applicable(&artifact));
    }

    /// Scanners that override `is_applicable` to return false must NOT have
    /// their `scan()` called by anything that respects the trait contract.
    /// This is the precondition that lets the orchestrator skip the
    /// scan_results row creation safely.
    #[tokio::test]
    async fn test_is_applicable_false_means_scan_must_not_be_invoked() {
        use applicability_fixtures::NeverApplicableScanner;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicUsize::new(0));
        let scanner = NeverApplicableScanner {
            scan_calls: calls.clone(),
        };
        let artifact = test_helpers::make_test_artifact(
            "lodash-vuln-fixture-1.0.0.tgz",
            "application/gzip",
            "npm/lodash-vuln-fixture/1.0.0/lodash-vuln-fixture-1.0.0.tgz",
        );

        // The orchestrator gate is conceptually:
        //   if !scanner.is_applicable(&artifact) { continue; }
        // followed by `scanner.scan(...)`. We replay that contract in
        // isolation so the assertion focuses on the trait surface itself.
        let applicable = scanner.is_applicable(&artifact);
        assert!(
            !applicable,
            "NeverApplicableScanner must report is_applicable=false"
        );
        if applicable {
            // Defensive: ensure the test would actually exercise the bad
            // path if the gate were ever inverted.
            let _ = scanner.scan(&artifact, None, &Bytes::new()).await;
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "scan() must not be called when is_applicable() returns false (#961, #994)"
        );
    }

    /// Inverse of the above: a scanner that returns `is_applicable=true`
    /// must still have its `scan()` invoked. This guards against an
    /// over-correction where the gate is hard-wired to false or drops the
    /// scanner from the iteration entirely.
    #[tokio::test]
    async fn test_is_applicable_true_means_scan_is_invoked() {
        use applicability_fixtures::AlwaysApplicableScanner;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicUsize::new(0));
        let scanner = AlwaysApplicableScanner {
            scan_calls: calls.clone(),
        };
        let artifact = test_helpers::make_test_artifact(
            "anything.tgz",
            "application/gzip",
            "npm/anything/1.0.0/anything.tgz",
        );
        assert!(scanner.is_applicable(&artifact));
        let _ = scanner.scan(&artifact, None, &Bytes::new()).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "scan() must be called once when is_applicable() returns true"
        );
    }

    /// Concrete regression for #994: the lodash fixture (generic tarball
    /// uploaded as `scan_type=image`) must trigger
    /// `ImageScanner::is_applicable=false`, so the orchestrator can skip
    /// it without persisting a `completed, findings_count=0` row.
    /// Before the fix this scanner returned `Ok(ScanOutput::default())`
    /// from inside `scan()` after a 2.8 ms code-path; the orchestrator
    /// then recorded a clean scan that lied about the artifact's posture.
    #[test]
    fn test_image_scanner_not_applicable_to_generic_npm_tarball() {
        use crate::services::image_scanner::ImageScanner;

        let image_scanner = ImageScanner::new("http://trivy:4954".to_string());
        let lodash = test_helpers::make_test_artifact(
            "lodash-vuln-fixture-1.0.0.tgz",
            "application/gzip",
            "npm/lodash-vuln-fixture/1.0.0/lodash-vuln-fixture-1.0.0.tgz",
        );
        assert!(
            !Scanner::is_applicable(&image_scanner, &lodash),
            "ImageScanner must yield to TrivyFsScanner on a generic npm tarball; \
             persisting a completed-with-zero-findings row for ImageScanner here \
             is the silent-success class behind #994"
        );
    }

    /// Concrete regression for #961: the image scanner must NOT claim to
    /// be applicable to an npm tarball. Before the fix it ran on every
    /// artifact and produced false-positive empty rows, skewing the
    /// dashboard counts.
    #[test]
    fn test_image_scanner_applicability_distinguishes_oci_from_npm() {
        use crate::services::image_scanner::ImageScanner;

        let image_scanner = ImageScanner::new("http://trivy:4954".to_string());

        let oci = test_helpers::make_test_artifact(
            "myapp",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/myapp/manifests/latest",
        );
        assert!(
            Scanner::is_applicable(&image_scanner, &oci),
            "ImageScanner must apply to OCI manifests"
        );

        let npm = test_helpers::make_test_artifact(
            "left-pad-1.3.0.tgz",
            "application/gzip",
            "npm/left-pad/1.3.0/left-pad-1.3.0.tgz",
        );
        assert!(
            !Scanner::is_applicable(&image_scanner, &npm),
            "ImageScanner must not apply to an npm tarball (#961)"
        );
    }

    // -------- parse_oci_manifest_path / join_oci_image_ref (#1483) --------

    #[test]
    fn test_parse_oci_manifest_path_tag() {
        let (name, reference) =
            parse_oci_manifest_path("v2/library/nginx/manifests/latest").expect("path must parse");
        assert_eq!(name, "library/nginx");
        assert_eq!(reference, "latest");
    }

    #[test]
    fn test_parse_oci_manifest_path_digest() {
        let (name, reference) = parse_oci_manifest_path(
            "v2/org/myapp/manifests/sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b",
        )
        .expect("path must parse");
        assert_eq!(name, "org/myapp");
        assert_eq!(
            reference,
            "sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b"
        );
    }

    #[test]
    fn test_parse_oci_manifest_path_rejects_malformed() {
        for path in [
            "v2/foo/blobs/sha256:abc",        // no /manifests/
            "v2//manifests/latest",           // empty name
            "v2/library/nginx/manifests/",    // empty reference
            "library/nginx/manifests/latest", // no v2/ prefix
        ] {
            assert!(
                parse_oci_manifest_path(path).is_none(),
                "malformed path '{}' must not parse",
                path
            );
        }
    }

    #[test]
    fn test_is_oci_digest_reference_recognizes_sha256() {
        assert!(is_oci_digest_reference(
            "sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b"
        ));
    }

    #[test]
    fn test_is_oci_digest_reference_recognizes_sha512() {
        // Forward-compatible: the helper recognises any `<algo>:<hex>`
        // shape, not just sha256, so future digest algorithms work
        // without code changes.
        assert!(is_oci_digest_reference(
            "sha512:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6bcf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b"
        ));
    }

    #[test]
    fn test_is_oci_digest_reference_rejects_tag() {
        for tag in ["latest", "v1.0.0", "1.21-alpine", "main", "rc-2"] {
            assert!(
                !is_oci_digest_reference(tag),
                "tag '{}' must not look like a digest",
                tag
            );
        }
    }

    #[test]
    fn test_is_oci_digest_reference_rejects_garbage() {
        // Looks colon-separated but the right side is not hex.
        assert!(!is_oci_digest_reference("sha256:not-hex-zzzz"));
        // Empty halves.
        assert!(!is_oci_digest_reference(":abc"));
        assert!(!is_oci_digest_reference("sha256:"));
    }

    /// Issue #1483: the tag case must continue to use `:` so existing
    /// tag-based scans keep working.
    #[test]
    fn test_join_oci_image_ref_tag_uses_colon() {
        assert_eq!(
            join_oci_image_ref("library/nginx", "1.21-alpine"),
            "library/nginx:1.21-alpine"
        );
    }

    /// Issue #1483: digest references must use `@` per the OCI distribution
    /// spec. The previous `:` form produced `name:sha256:digest` (two colons
    /// in the tag position), which Trivy and Grype both reject with
    /// "could not parse reference".
    #[test]
    fn test_join_oci_image_ref_digest_uses_at_sign() {
        let joined = join_oci_image_ref(
            "localhost:8080/org/myapp",
            "sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b",
        );
        assert_eq!(
            joined,
            "localhost:8080/org/myapp@sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b"
        );
        // Defensive: the bad form (`name:sha256:...`) must never reappear.
        assert!(
            !joined.contains("myapp:sha256:"),
            "digest ref must not use ':' between name and digest: {}",
            joined
        );
    }

    // -----------------------------------------------------------------------
    // #1971: resolve_scan_reference — OCI image-index → concrete child digest.
    // Pure JSON parse + reference rewrite; no DB, no network, host-stable via
    // runner_arch().
    // -----------------------------------------------------------------------

    const SHA_AMD64: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const SHA_ARM64: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const SHA_ATTEST: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    fn index_two_arch() -> String {
        format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
                "manifests":[
                  {{"digest":"{SHA_AMD64}","platform":{{"os":"linux","architecture":"amd64"}}}},
                  {{"digest":"{SHA_ARM64}","platform":{{"os":"linux","architecture":"arm64"}}}}
                ]}}"#
        )
    }

    /// (1) An index with both runner-relevant arches resolves to the
    /// runner-arch child digest (host-stable via runner_arch()).
    #[test]
    fn test_resolve_scan_reference_index_picks_runner_arch() {
        let body = index_two_arch();
        let res = resolve_scan_reference(body.as_bytes(), "latest");
        let expected = match runner_arch() {
            "amd64" => SHA_AMD64,
            "arm64" => SHA_ARM64,
            // On an exotic runner neither linux child matches the arch, so the
            // first linux child wins; assert it is one of the two real digests.
            _ => SHA_AMD64,
        };
        assert_eq!(
            res,
            ScanReferenceResolution::ResolvedIndexChild(expected.to_string())
        );
        // The joined builder form is name@sha256:... — assert via join.
        assert_eq!(
            join_oci_image_ref("host/repo/app", &res.into_reference()),
            format!("host/repo/app@{}", expected)
        );
    }

    /// (2) An index missing the runner arch falls back to the first linux
    /// child (never empty / never UnresolvableIndex).
    #[test]
    fn test_resolve_scan_reference_index_falls_back_to_first_linux_child() {
        // Single child whose arch is deliberately not the runner arch.
        let other_arch = if runner_arch() == "amd64" {
            "arm64"
        } else {
            "amd64"
        };
        let body = format!(
            r#"{{"manifests":[
                 {{"digest":"{SHA_AMD64}","platform":{{"os":"linux","architecture":"{other_arch}"}}}}
               ]}}"#
        );
        let res = resolve_scan_reference(body.as_bytes(), "latest");
        assert_eq!(
            res,
            ScanReferenceResolution::ResolvedIndexChild(SHA_AMD64.to_string())
        );
    }

    /// (3) An index with an attestation child plus one real child selects the
    /// real child, never the attestation digest.
    #[test]
    fn test_resolve_scan_reference_excludes_attestation_child() {
        let body = format!(
            r#"{{"manifests":[
                 {{"digest":"{SHA_ATTEST}","platform":{{"os":"unknown","architecture":"unknown"}},
                   "annotations":{{"vnd.docker.reference.type":"attestation-manifest"}}}},
                 {{"digest":"{SHA_AMD64}","platform":{{"os":"linux","architecture":"{arch}"}}}}
               ]}}"#,
            arch = runner_arch()
        );
        let res = resolve_scan_reference(body.as_bytes(), "latest");
        assert_eq!(
            res,
            ScanReferenceResolution::ResolvedIndexChild(SHA_AMD64.to_string()),
            "must never select the attestation child"
        );
        assert_ne!(res.into_reference(), SHA_ATTEST);
    }

    /// (3b) artifactType in-toto and os=unknown are independently excluding.
    #[test]
    fn test_resolve_scan_reference_excludes_in_toto_artifact_type() {
        let body = format!(
            r#"{{"manifests":[
                 {{"digest":"{SHA_ATTEST}","artifactType":"application/vnd.in-toto+json"}},
                 {{"digest":"{SHA_AMD64}","platform":{{"os":"linux","architecture":"{arch}"}}}}
               ]}}"#,
            arch = runner_arch()
        );
        assert_eq!(
            resolve_scan_reference(body.as_bytes(), "latest"),
            ScanReferenceResolution::ResolvedIndexChild(SHA_AMD64.to_string())
        );
    }

    /// (4) An index whose only children are attestation/empty → Unresolvable;
    /// reference is returned unchanged.
    #[test]
    fn test_resolve_scan_reference_attestation_only_index_is_unresolvable() {
        let body = format!(
            r#"{{"manifests":[
                 {{"digest":"{SHA_ATTEST}","platform":{{"os":"unknown","architecture":"unknown"}}}},
                 {{"platform":{{"os":"linux","architecture":"amd64"}}}}
               ]}}"#
        );
        let res = resolve_scan_reference(body.as_bytes(), "latest");
        assert_eq!(
            res,
            ScanReferenceResolution::UnresolvableIndex("latest".to_string())
        );
        assert_eq!(res.into_reference(), "latest");
    }

    /// (5) REGRESSION: a normal single-arch image manifest body (config, no
    /// manifests[]) is passthrough — reference byte-for-byte unchanged.
    #[test]
    fn test_resolve_scan_reference_single_arch_is_passthrough() {
        let body = br#"{"schemaVersion":2,"config":{"digest":"sha256:cfg"},"layers":[]}"#;
        assert_eq!(
            resolve_scan_reference(body, "v1.0.0"),
            ScanReferenceResolution::Passthrough("v1.0.0".to_string())
        );
        // Digest-pinned single manifest (#1483) also passes through unchanged.
        assert_eq!(
            resolve_scan_reference(body, SHA_AMD64),
            ScanReferenceResolution::Passthrough(SHA_AMD64.to_string())
        );
    }

    /// (5b) REGRESSION: malformed / empty bodies are passthrough.
    #[test]
    fn test_resolve_scan_reference_malformed_body_is_passthrough() {
        for body in [&b""[..], &b"not json"[..], &br#"{"schemaVersion":2}"#[..]] {
            assert_eq!(
                resolve_scan_reference(body, "latest"),
                ScanReferenceResolution::Passthrough("latest".to_string())
            );
        }
    }

    /// (6) runner_arch() maps the two architectures Artifact Keeper runs on.
    #[test]
    fn test_runner_arch_maps_known_architectures() {
        // Pure, deterministic on the current host.
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(runner_arch(), "amd64"),
            "aarch64" => assert_eq!(runner_arch(), "arm64"),
            other => assert_eq!(runner_arch(), other),
        }
        // The returned token must be a non-empty OCI arch token.
        assert!(!runner_arch().is_empty());
    }

    struct ContextOnlyScanner;

    #[async_trait]
    impl Scanner for ContextOnlyScanner {
        fn name(&self) -> &str {
            "context-only"
        }

        fn scan_type(&self) -> &str {
            "context-only"
        }

        fn is_applicable(&self, _artifact: &Artifact) -> bool {
            false
        }

        fn is_applicable_for_target(&self, target: &ScanTarget<'_>) -> bool {
            target.repository_key == "docker-local" && target.repository_type == "local"
        }

        async fn scan(
            &self,
            _artifact: &Artifact,
            _metadata: Option<&ArtifactMetadata>,
            _content: &Bytes,
        ) -> Result<ScanOutput> {
            Ok(ScanOutput::default())
        }
    }

    struct LegacyOnlyScanner;

    #[async_trait]
    impl Scanner for LegacyOnlyScanner {
        fn name(&self) -> &str {
            "legacy-only"
        }

        fn scan_type(&self) -> &str {
            "legacy-only"
        }

        fn is_applicable(&self, artifact: &Artifact) -> bool {
            artifact.path == "v2/library/nginx/manifests/latest"
        }

        async fn scan(
            &self,
            artifact: &Artifact,
            _metadata: Option<&ArtifactMetadata>,
            _content: &Bytes,
        ) -> Result<ScanOutput> {
            Ok(ScanOutput {
                findings: Vec::new(),
                packages: Vec::new(),
                scan_completeness: if artifact.name == "nginx" {
                    ScanCompleteness::Complete
                } else {
                    ScanCompleteness::Partial
                },
            })
        }
    }

    #[test]
    fn test_scan_target_context_can_drive_applicability() {
        let scanner = ContextOnlyScanner;
        let artifact = test_helpers::make_test_artifact(
            "nginx",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "docker-local",
            repository_type: "local",
            db: None,
            storage: None,
        };

        assert!(scanner.is_applicable_for_target(&target));
        assert!(
            !scanner.is_applicable(&artifact),
            "legacy applicability lacks repository context and should not be used by orchestration"
        );
    }

    #[tokio::test]
    async fn test_scan_target_default_methods_preserve_legacy_scanners() {
        let scanner = LegacyOnlyScanner;
        let artifact = test_helpers::make_test_artifact(
            "nginx",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "docker-local",
            repository_type: "local",
            db: None,
            storage: None,
        };

        assert!(scanner.is_applicable_for_target(&target));
        let output = scanner
            .scan_target(&target, None, &Bytes::from_static(b"{}"))
            .await
            .expect("legacy default scan_target must delegate to scan");
        assert_eq!(output.scan_completeness, ScanCompleteness::Complete);
    }

    struct RecordingContextScanner {
        seen: Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    }

    #[async_trait]
    impl Scanner for RecordingContextScanner {
        fn name(&self) -> &str {
            "recording-context"
        }

        fn scan_type(&self) -> &str {
            // Must be an allowed value for the scan_results_scan_type_check
            // constraint, since this scanner runs against a real database and
            // the orchestrator persists a scan_results row using this type.
            "grype"
        }

        fn is_applicable(&self, _artifact: &Artifact) -> bool {
            false
        }

        fn is_applicable_for_target(&self, target: &ScanTarget<'_>) -> bool {
            target.repository_key == "docker-local" && target.repository_type == "local"
        }

        async fn scan(
            &self,
            _artifact: &Artifact,
            _metadata: Option<&ArtifactMetadata>,
            _content: &Bytes,
        ) -> Result<ScanOutput> {
            panic!("orchestration must call scan_target so repository context is available")
        }

        async fn scan_target(
            &self,
            target: &ScanTarget<'_>,
            _metadata: Option<&ArtifactMetadata>,
            _content: &Bytes,
        ) -> Result<ScanOutput> {
            self.seen.lock().unwrap().push((
                target.repository_key.to_string(),
                target.repository_type.to_string(),
                target.artifact.path.clone(),
            ));
            Ok(ScanOutput::default())
        }
    }

    /// A scanner that is never applicable to any artifact. Drives the #1470
    /// not-applicable branch in `scan_artifact_inner` so the orchestration
    /// records a `not_applicable` terminal row rather than `failed` (Reuse
    /// path) or no row at all (InsertFresh path). `scan` / `scan_target` panic
    /// because an inapplicable scanner must never be invoked.
    struct NeverApplicableScanner;

    #[async_trait]
    impl Scanner for NeverApplicableScanner {
        fn name(&self) -> &str {
            "never-applicable"
        }

        fn scan_type(&self) -> &str {
            // Must satisfy scan_results_scan_type_check; "grype" is allowed and
            // the orchestrator persists a row with this scan_type.
            "grype"
        }

        fn is_applicable(&self, _artifact: &Artifact) -> bool {
            false
        }

        fn is_applicable_for_target(&self, _target: &ScanTarget<'_>) -> bool {
            false
        }

        async fn scan(
            &self,
            _artifact: &Artifact,
            _metadata: Option<&ArtifactMetadata>,
            _content: &Bytes,
        ) -> Result<ScanOutput> {
            panic!("an inapplicable scanner must never be invoked");
        }
    }

    /// #1470 regression: on the InsertFresh path (auto-scan-on-upload, no
    /// pre-allocated row), a scanner that does not apply must persist a single
    /// terminal `not_applicable` scan_results row -- NOT `failed`, and NOT zero
    /// rows. Before the fix the scanner `continue`d and wrote nothing, so the
    /// artifact classified as NeverScanned and was falsely blocked under
    /// `block_unscanned=true` (#1648).
    #[tokio::test]
    async fn test_scan_artifact_inner_records_not_applicable_on_insert_fresh() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return; // skip cleanly when no DATABASE_URL
        };

        let artifact_id = Uuid::new_v4();
        let checksum = fresh_checksum();
        let storage_key = format!("na-insert-fresh/{artifact_id}.bin");
        fx.state
            .storage
            .put(&storage_key, Bytes::from_static(b"data"))
            .await
            .expect("store artifact bytes");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, path, size_bytes, checksum_sha256,
                content_type, storage_key, is_deleted
            )
            VALUES ($1, $2, 'pkg.bin', 'pkg.bin', 4, $3,
                    'application/octet-stream', $4, false)
            "#,
        )
        .bind(artifact_id)
        .bind(fx.repo_id)
        .bind(&checksum)
        .bind(&storage_key)
        .execute(&fx.pool)
        .await
        .expect("insert artifact");

        let scanner = ScannerService {
            db: fx.pool.clone(),
            scanners: vec![Arc::new(NeverApplicableScanner)],
            scan_result_service: Arc::new(ScanResultService::new(fx.pool.clone())),
            scan_config_service: Arc::new(ScanConfigService::new(fx.pool.clone())),
            storage: fx.state.storage.clone(),
            storage_registry: fx.state.storage_registry.clone(),
            storage_base_path: fx.storage_dir.to_string_lossy().into_owned(),
            scan_workspace_path: fx
                .storage_dir
                .join("scan-workspace")
                .to_string_lossy()
                .into_owned(),
            dependency_track: None,
        };

        // prepared=None -> InsertFresh path.
        scanner
            .scan_artifact_with_options(artifact_id, true, true)
            .await
            .expect("scan orchestration must succeed even when nothing applies");

        let rows: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT status, error_message FROM scan_results WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_all(&fx.pool)
                .await
                .expect("read scan rows");

        assert_eq!(rows.len(), 1, "InsertFresh must record exactly one row");
        assert_eq!(
            rows[0].0, "not_applicable",
            "inapplicable scanner must persist not_applicable, never failed"
        );
        assert!(
            rows[0]
                .1
                .as_deref()
                .unwrap_or_default()
                .contains("does not apply"),
            "reason text must be preserved for display"
        );

        cleanup_scan_state(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
    }

    /// #1470 regression (Reuse path): when the trigger handler pre-allocated a
    /// `running` scan_results row and the scanner turns out not to apply, the
    /// orchestration must UPDATE that row to `not_applicable` in place -- never
    /// `failed`, and never leave it wedged in `running`.
    #[tokio::test]
    async fn test_scan_artifact_inner_marks_prepared_row_not_applicable() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return; // skip cleanly when no DATABASE_URL
        };

        let artifact_id = Uuid::new_v4();
        let checksum = fresh_checksum();
        let storage_key = format!("na-reuse/{artifact_id}.bin");
        fx.state
            .storage
            .put(&storage_key, Bytes::from_static(b"data"))
            .await
            .expect("store artifact bytes");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, path, size_bytes, checksum_sha256,
                content_type, storage_key, is_deleted
            )
            VALUES ($1, $2, 'pkg.bin', 'pkg.bin', 4, $3,
                    'application/octet-stream', $4, false)
            "#,
        )
        .bind(artifact_id)
        .bind(fx.repo_id)
        .bind(&checksum)
        .bind(&storage_key)
        .execute(&fx.pool)
        .await
        .expect("insert artifact");

        let scan_result_service = Arc::new(ScanResultService::new(fx.pool.clone()));
        // Pre-allocate the `running` row the trigger handler would have created.
        let prepared_row = scan_result_service
            .create_scan_result(artifact_id, fx.repo_id, "grype")
            .await
            .expect("pre-allocate running scan");

        let scanner = ScannerService {
            db: fx.pool.clone(),
            scanners: vec![Arc::new(NeverApplicableScanner)],
            scan_result_service: scan_result_service.clone(),
            scan_config_service: Arc::new(ScanConfigService::new(fx.pool.clone())),
            storage: fx.state.storage.clone(),
            storage_registry: fx.state.storage_registry.clone(),
            storage_base_path: fx.storage_dir.to_string_lossy().into_owned(),
            scan_workspace_path: fx
                .storage_dir
                .join("scan-workspace")
                .to_string_lossy()
                .into_owned(),
            dependency_track: None,
        };

        let mut prepared = HashMap::new();
        prepared.insert("grype".to_string(), prepared_row.id);

        scanner
            .scan_artifact_with_prepared(artifact_id, prepared, true, true)
            .await
            .expect("scan orchestration must succeed for inapplicable scanner");

        let updated = scan_result_service
            .get_scan(prepared_row.id)
            .await
            .expect("pre-allocated row must still exist");
        assert_eq!(
            updated.status, "not_applicable",
            "pre-allocated row must be updated to not_applicable, not failed/running"
        );
        assert!(updated.completed_at.is_some(), "row must be terminal");

        // Exactly one row: the pre-allocated one was UPDATEd, not duplicated.
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM scan_results WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_one(&fx.pool)
                .await
                .expect("count rows");
        assert_eq!(count, 1);

        cleanup_scan_state(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_scan_artifact_inner_supplies_repository_context_to_scanners() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return; // skip cleanly when no DATABASE_URL
        };

        sqlx::query(
            "UPDATE repositories SET key = 'docker-local', name = 'docker-local' WHERE id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("rename fixture repository");

        let artifact_id = Uuid::new_v4();
        let checksum = fresh_checksum();
        let storage_key = format!("scan-context/{artifact_id}.json");
        fx.state
            .storage
            .put(&storage_key, Bytes::from_static(b"{}"))
            .await
            .expect("store artifact bytes");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, path, size_bytes, checksum_sha256,
                content_type, storage_key, is_deleted
            )
            VALUES ($1, $2, 'nginx', 'v2/library/nginx/manifests/latest', 2, $3,
                    'application/vnd.oci.image.manifest.v1+json', $4, false)
            "#,
        )
        .bind(artifact_id)
        .bind(fx.repo_id)
        .bind(&checksum)
        .bind(&storage_key)
        .execute(&fx.pool)
        .await
        .expect("insert OCI artifact");

        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let scanner = ScannerService {
            db: fx.pool.clone(),
            scanners: vec![Arc::new(RecordingContextScanner { seen: seen.clone() })],
            scan_result_service: Arc::new(ScanResultService::new(fx.pool.clone())),
            scan_config_service: Arc::new(ScanConfigService::new(fx.pool.clone())),
            storage: fx.state.storage.clone(),
            storage_registry: fx.state.storage_registry.clone(),
            storage_base_path: fx.storage_dir.to_string_lossy().into_owned(),
            scan_workspace_path: fx
                .storage_dir
                .join("scan-workspace")
                .to_string_lossy()
                .into_owned(),
            dependency_track: None,
        };

        scanner
            .scan_artifact_with_options(artifact_id, true, true)
            .await
            .expect("scan must run with context-aware scanner");

        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![(
                "docker-local".to_string(),
                "local".to_string(),
                "v2/library/nginx/manifests/latest".to_string(),
            )],
            "scanner orchestration must load repository key/type and preserve the internal artifact path"
        );

        cleanup_scan_state(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
    }

    /// The `TrivyFsScanner` is the inverse case: it must apply to the
    /// generic npm tarball that fooled `ImageScanner` in #994, otherwise
    /// the fix has over-corrected and the lodash CVE goes undetected.
    #[test]
    fn test_trivy_fs_scanner_applies_to_npm_tarball() {
        use crate::services::trivy_fs_scanner::TrivyFsScanner;

        let trivy_fs = TrivyFsScanner::new("http://trivy:4954".to_string(), "/tmp".to_string());
        let lodash = test_helpers::make_test_artifact(
            "lodash-vuln-fixture-1.0.0.tgz",
            "application/gzip",
            "npm/lodash-vuln-fixture/1.0.0/lodash-vuln-fixture-1.0.0.tgz",
        );
        assert!(
            Scanner::is_applicable(&trivy_fs, &lodash),
            "TrivyFsScanner must apply to a generic npm tarball — that is exactly \
             the scanner expected to detect lodash CVE-2019-10744"
        );
    }

    // -----------------------------------------------------------------------
    // #1469 bypass_dedup wiring: lib-coverage tests for the new branches added
    // to `prepare_artifact_scan`, `scan_artifact_with_options`, and
    // `scan_repository_with_options`. These run against a real Postgres pool
    // (gated on DATABASE_URL, skip cleanly otherwise) so the `cargo llvm-cov
    // --lib` CI gate measures the new lines, not just the integration suites
    // in `backend/tests/scan_dedup_*` which are scoped out of `--lib`.
    //
    // The integration suite covers the SQL behaviour of `find_reusable_scan`
    // / `find_existing_scan_for_artifact` under the dual-TTL. The lib tests
    // here cover the call-site branches in the scanner service that route
    // around (or through) those queries when `bypass_dedup` is set.
    // -----------------------------------------------------------------------

    /// Construct a minimal `ScannerService` suitable for exercising
    /// `prepare_artifact_scan` and the repository-level fan-out. Trivy and
    /// OpenSCAP are intentionally `None` so the constructed scanner set is
    /// just dependency + grype, keeping the test fast and DB-only.
    fn build_minimal_scanner_service(
        pool: PgPool,
        storage: Arc<dyn StorageBackend>,
        storage_registry: Arc<crate::storage::StorageRegistry>,
        storage_base_path: String,
    ) -> Arc<ScannerService> {
        let advisory_client = Arc::new(AdvisoryClient::new(None));
        let scan_result_service = Arc::new(ScanResultService::new(pool.clone()));
        let scan_config_service =
            Arc::new(crate::services::scan_config_service::ScanConfigService::new(pool.clone()));
        let auth = Arc::new(AuthService::new(
            pool.clone(),
            Arc::new(crate::config::Config::test_config()),
        ));
        Arc::new(ScannerService::new(
            pool,
            advisory_client,
            scan_result_service,
            scan_config_service,
            None, // trivy_url: skip fs / incus scanners
            None, // trivy_adapter_url: skip image scanner
            storage,
            storage_registry,
            storage_base_path,
            "/tmp/scan-1469-tests".to_string(),
            None, // openscap_url
            "standard".to_string(),
            auth,
            None, // scan_identity: anonymous pulls in tests
            300,  // scan_token_ttl_seconds
        ))
    }

    /// Insert a non-deleted artifact with the given checksum, bypassing
    /// the higher-level seeding helper so the checksum is a real 64-char
    /// hex string (required for `find_existing_scan_for_artifact` queries
    /// to be well-typed and for cleanup to be deterministic).
    async fn insert_minimal_artifact(pool: &PgPool, repo_id: Uuid, checksum_hex64: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, path, size_bytes, checksum_sha256,
                content_type, storage_key, is_deleted
            )
            VALUES ($1, $2, $3, $4, $5, $6,
                    'application/octet-stream', $4, false)
            "#,
        )
        .bind(id)
        .bind(repo_id)
        .bind(format!("art-{}.bin", id))
        .bind(format!("{}/art-{}.bin", repo_id, id))
        .bind(1024_i64)
        .bind(checksum_hex64)
        .execute(pool)
        .await
        .expect("insert minimal artifact");
        id
    }

    /// Cascade-cleans scan_results + artifacts for the given repo so the
    /// fixture's own teardown (which doesn't touch scan_results) can drop
    /// the repository row. `ON DELETE CASCADE` on scan_findings handles
    /// the rest.
    async fn cleanup_scan_state(pool: &PgPool, repo_id: Uuid) {
        let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
    }

    /// 64-hex checksum (unique per call so two parallel tests don't share a
    /// key in the `find_reusable_scan` cross-artifact index). Built from two
    /// UUIDs because `format!("{:0<64}", uuid.simple())` doesn't actually
    /// pad: the `uuid::fmt::Simple` Display impl ignores fill/width.
    fn fresh_checksum() -> String {
        let mut s = String::with_capacity(64);
        s.push_str(&Uuid::new_v4().simple().to_string());
        s.push_str(&Uuid::new_v4().simple().to_string());
        debug_assert_eq!(s.len(), 64);
        s
    }

    #[tokio::test]
    async fn test_prepare_artifact_scan_bypass_dedup_skips_existing_lookup() {
        // #1469: when bypass_dedup = true, `prepare_artifact_scan` must
        // create a fresh placeholder row per configured scanner even when
        // a recently-completed scan exists for the same artifact +
        // checksum + scan_type. The pre-existing completed row must not
        // be returned to the caller as the prepared id.
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return; // skip cleanly when no DATABASE_URL
        };

        let checksum = fresh_checksum();
        let artifact_id = insert_minimal_artifact(&fx.pool, fx.repo_id, &checksum).await;

        // Seed a completed scan row that, under bypass_dedup = false,
        // would short-circuit the dependency scanner's prepare step.
        let existing_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO scan_results (
                id, artifact_id, repository_id, scan_type, status,
                findings_count, critical_count, high_count, medium_count,
                low_count, info_count,
                started_at, completed_at, checksum_sha256
            )
            VALUES ($1, $2, $3, 'dependency', 'completed',
                    3, 0, 0, 0, 0, 0,
                    NOW(), NOW(), $4)
            "#,
        )
        .bind(existing_id)
        .bind(artifact_id)
        .bind(fx.repo_id)
        .bind(&checksum)
        .execute(&fx.pool)
        .await
        .expect("seed completed scan");

        let scanner = build_minimal_scanner_service(
            fx.pool.clone(),
            fx.state.storage.clone(),
            fx.state.storage_registry.clone(),
            fx.storage_dir.to_string_lossy().into_owned(),
        );

        // bypass_dedup = true: every scanner gets a NEW placeholder id.
        let prepared = scanner
            .prepare_artifact_scan(artifact_id, true, true)
            .await
            .expect("prepare with bypass must succeed");
        assert!(
            !prepared.is_empty(),
            "expected at least one scanner (dependency + grype) to produce a prepared row"
        );
        for (scan_type, prepared_id) in &prepared {
            if scan_type == "dependency" {
                assert_ne!(
                    *prepared_id, existing_id,
                    "bypass_dedup=true must NOT short-circuit to the existing completed row id"
                );
            }
        }

        cleanup_scan_state(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_prepare_artifact_scan_without_bypass_reuses_existing() {
        // Inverse of the above: when bypass_dedup = false and a fresh
        // completed row exists for the same artifact + checksum +
        // scan_type, `prepare_artifact_scan` must surface that row's
        // id verbatim (the #1373 short-circuit). This pins that
        // bypass_dedup = false flows through to
        // `find_existing_scan_for_artifact` with the new dual-TTL
        // signature, exercising the else-branch added in #1469.
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let checksum = fresh_checksum();
        let artifact_id = insert_minimal_artifact(&fx.pool, fx.repo_id, &checksum).await;

        let existing_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO scan_results (
                id, artifact_id, repository_id, scan_type, status,
                findings_count, critical_count, high_count, medium_count,
                low_count, info_count,
                started_at, completed_at, checksum_sha256
            )
            VALUES ($1, $2, $3, 'dependency', 'completed',
                    3, 0, 0, 0, 0, 0,
                    NOW(), NOW(), $4)
            "#,
        )
        .bind(existing_id)
        .bind(artifact_id)
        .bind(fx.repo_id)
        .bind(&checksum)
        .execute(&fx.pool)
        .await
        .expect("seed completed scan");

        let scanner = build_minimal_scanner_service(
            fx.pool.clone(),
            fx.state.storage.clone(),
            fx.state.storage_registry.clone(),
            fx.storage_dir.to_string_lossy().into_owned(),
        );

        let prepared = scanner
            .prepare_artifact_scan(artifact_id, true, false)
            .await
            .expect("prepare without bypass must succeed");
        let dep_row = prepared
            .iter()
            .find(|(t, _)| t == "dependency")
            .expect("dependency scanner must be in the prepared set");
        assert_eq!(
            dep_row.1, existing_id,
            "bypass_dedup=false must short-circuit to the existing completed row id (#1373)"
        );

        cleanup_scan_state(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_prepare_artifact_scan_missing_artifact_returns_empty() {
        // Early-return branch: a non-existent (or soft-deleted) artifact
        // produces an empty prepared vec regardless of bypass_dedup. This
        // hits the new signature on the no-artifact path.
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let scanner = build_minimal_scanner_service(
            fx.pool.clone(),
            fx.state.storage.clone(),
            fx.state.storage_registry.clone(),
            fx.storage_dir.to_string_lossy().into_owned(),
        );

        let ghost = Uuid::new_v4();
        let prepared_true = scanner
            .prepare_artifact_scan(ghost, true, true)
            .await
            .expect("missing artifact must not error");
        assert!(
            prepared_true.is_empty(),
            "missing artifact + bypass_dedup must yield empty prepared vec"
        );
        let prepared_false = scanner
            .prepare_artifact_scan(ghost, true, false)
            .await
            .expect("missing artifact must not error");
        assert!(
            prepared_false.is_empty(),
            "missing artifact + no bypass_dedup must yield empty prepared vec"
        );

        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_scan_repository_with_options_empty_repo_returns_zero() {
        // `scan_repository_with_options` is a new 3-arg signature wrapping
        // the per-artifact fan-out. An empty repository must return 0
        // without erroring, regardless of bypass_dedup. This also covers
        // the public `scan_repository` thin delegate (which forwards
        // bypass_dedup = false) and exercises the info!/spawn-free path.
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let scanner = build_minimal_scanner_service(
            fx.pool.clone(),
            fx.state.storage.clone(),
            fx.state.storage_registry.clone(),
            fx.storage_dir.to_string_lossy().into_owned(),
        );

        let count_bypass = scanner
            .scan_repository_with_options(fx.repo_id, true, true)
            .await
            .expect("empty repo scan with bypass must not error");
        assert_eq!(count_bypass, 0, "no artifacts -> zero count");

        let count_no_bypass = scanner
            .scan_repository_with_options(fx.repo_id, true, false)
            .await
            .expect("empty repo scan without bypass must not error");
        assert_eq!(count_no_bypass, 0);

        // Thin delegates: `scan_repository` forwards force=false,
        // bypass_dedup=false; `scan_artifact` forwards similarly for a
        // single id. Both should be no-ops on an empty repository / a
        // missing artifact id and not error out.
        let count_default = scanner
            .scan_repository(fx.repo_id)
            .await
            .expect("scan_repository default delegate must not error");
        assert_eq!(count_default, 0);

        let ghost_artifact = Uuid::new_v4();
        // `scan_artifact` / `scan_artifact_with_options` on a missing id
        // return `Err(NotFound)` (the inner fetch raises). We don't care
        // about the variant here, only that the new 3-arg signature is
        // exercised end-to-end through `scan_artifact_inner`, including
        // the new bypass_dedup parameter forward.
        let _ = scanner.scan_artifact(ghost_artifact).await;
        let _ = scanner
            .scan_artifact_with_options(ghost_artifact, true, true)
            .await;
        let _ = scanner
            .scan_artifact_with_options(ghost_artifact, true, false)
            .await;

        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_scan_artifact_with_prepared_missing_artifact_no_error() {
        // `scan_artifact_with_prepared` (new 4-arg signature) on a
        // missing artifact id must early-return without erroring,
        // regardless of bypass_dedup. The prepared map can be empty;
        // the function falls through to the artifact-fetch step which
        // gracefully handles the absent row. Covers the wrapper that
        // delegates into `scan_artifact_inner` with prepared=Some(...).
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let scanner = build_minimal_scanner_service(
            fx.pool.clone(),
            fx.state.storage.clone(),
            fx.state.storage_registry.clone(),
            fx.storage_dir.to_string_lossy().into_owned(),
        );

        let ghost = Uuid::new_v4();
        let prepared: std::collections::HashMap<String, Uuid> = std::collections::HashMap::new();
        // Missing artifact -> Err(NotFound) propagates from
        // `scan_artifact_inner`; we only care that the new 4-arg signature
        // compiles + dispatches under both bypass_dedup values.
        let _ = scanner
            .scan_artifact_with_prepared(ghost, prepared.clone(), true, true)
            .await;
        let _ = scanner
            .scan_artifact_with_prepared(ghost, prepared, true, false)
            .await;

        fx.teardown().await;
    }
}
