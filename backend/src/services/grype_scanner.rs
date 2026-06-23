//! Grype vulnerability scanner.
//!
//! Two scan modes:
//!
//! - **dir mode (default)**: writes artifact content to a scan workspace,
//!   optionally extracts archives, and invokes `grype dir:<workspace>`. Used
//!   for npm tarballs, PyPI wheels, lockfiles, etc.
//! - **registry mode (#1160)**: for OCI / Docker image manifests, invokes
//!   `grype registry:<image-ref>` pointing at artifact-keeper's own OCI
//!   registry endpoint. This lets Grype pull the actual layer blobs so it can
//!   surface CVEs in the installed packages, instead of staring at the
//!   manifest JSON and returning 0 findings (the regression #966 worked
//!   around by gating Grype out of OCI artifacts entirely).
//!
//! The registry target host is taken from `AK_GRYPE_REGISTRY_HOST` (explicit
//! override) or `PEER_PUBLIC_ENDPOINT` (already configured for in-cluster
//! distribution). The fallback is `http://localhost:8080`, which is correct
//! for `cargo run` / docker-compose dev.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Deserializer};
use std::path::Path;
use tracing::info;

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, RawPackage, Severity};
use crate::services::scanner_service::{
    cached_cli_version, capture_cli_version, fail_scan, format_grype_version,
    is_oci_image_artifact, join_oci_image_ref, parse_oci_manifest_path, validate_trivy_purl,
    ScanOutput, ScanTarget, ScanWorkspace, Scanner, VersionCache,
};

// ---------------------------------------------------------------------------
// Grype JSON output structures
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GrypeReport {
    #[serde(default)]
    pub matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeMatch {
    pub vulnerability: GrypeVulnerability,
    pub artifact: GrypeArtifact,
    /// Aliases Grype maps the primary match to. For ecosystem advisories
    /// (npm, RubyGems, etc.) Grype's primary `vulnerability.id` is frequently
    /// the GHSA identifier (e.g. `GHSA-jf85-cpcp-j695`) and the NVD `CVE-` id
    /// lives here as a related vulnerability. Consumers and the release-gate
    /// keyed on the canonical CVE id never see it unless we surface the alias.
    ///
    /// CRITICAL (#1375 / B15): in Grype's JSON this array is a TOP-LEVEL field
    /// of the *match* object (a sibling of `vulnerability` and `artifact`),
    /// NOT a field nested inside `vulnerability`. An earlier fix placed it
    /// inside `GrypeVulnerability`, so it deserialized to an empty Vec against
    /// real Grype output and the GHSA->CVE mapping silently never fired. It
    /// must live here on `GrypeMatch`. Verified against grype v0.112.0 output
    /// for lodash 4.17.4: `.matches[].relatedVulnerabilities[].id` ==
    /// "CVE-2019-10744".
    #[serde(default, rename = "relatedVulnerabilities")]
    pub related_vulnerabilities: Vec<GrypeRelatedVulnerability>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeVulnerability {
    pub id: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub fix: Option<GrypeFix>,
    #[serde(default)]
    pub urls: Option<Vec<String>>,
}

/// A cross-referenced vulnerability id Grype attaches to a primary match.
/// We only care about the `id` (the alias identifier); the `namespace`
/// field is captured for completeness but unused.
#[derive(Debug, Deserialize)]
pub struct GrypeRelatedVulnerability {
    pub id: String,
    #[serde(default)]
    pub namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeFix {
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeArtifact {
    pub name: String,
    pub version: String,
    #[serde(rename = "type", default)]
    pub artifact_type: Option<String>,
    /// Package URL emitted by Grype v0.50+ on the matched artifact, e.g.
    /// `pkg:npm/lodash@4.17.20`. When present, this is preferred over a
    /// synthesized PURL because Grype's normalization handles edge cases
    /// (namespaced npm scopes, Maven group/artifact split, Go module
    /// path encoding) that a from-scratch builder would miss.
    #[serde(default)]
    pub purl: Option<String>,
    /// SPDX license expression emitted by some Grype-cataloged ecosystems
    /// (deb, rpm, language packages with declared metadata). Optional;
    /// many Grype matches lack a `licenses` block entirely.
    #[serde(default)]
    pub licenses: Option<Vec<GrypeLicense>>,
}

/// Per-license entry inside `artifact.licenses`.
///
/// Grype serializes this array heterogeneously: an entry is either an object
/// `{"value": "MIT", "spdxExpression": "MIT", "type": "declared"}` or a bare
/// string holding the raw declared license — which may be an SPDX id (`"BSD"`)
/// or even a URL. For example `grype log4j-core-2.14.1.jar -o json` (grype
/// v0.114.0 / syft v1.45.1) emits
/// `"licenses": ["https://www.apache.org/licenses/LICENSE-2.0.txt"]`.
///
/// A struct-only `derive(Deserialize)` rejects the string form with
/// `invalid type: string "...", expected struct GrypeLicense`, and because
/// `licenses` is nested inside the report that aborts the *entire* parse — one
/// string-shaped license turns an otherwise successful scan into a hard
/// failure. The deserializer below accepts both shapes. Only
/// `value`/`spdxExpression` are consumed downstream; the rest is informational.
#[derive(Debug)]
pub struct GrypeLicense {
    pub value: Option<String>,
    pub spdx_expression: Option<String>,
}

impl<'de> Deserialize<'de> for GrypeLicense {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Accept either the bare-string or the object form. `untagged` tries
        // the variants in order, so a string matches `Str` and an object falls
        // through to `Obj`.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            /// Bare string: the raw declared license (an SPDX id or a URL).
            Str(String),
            /// Structured form: `{"value": "MIT", "spdxExpression": "MIT"}`.
            Obj {
                #[serde(default)]
                value: Option<String>,
                #[serde(default, rename = "spdxExpression")]
                spdx_expression: Option<String>,
            },
        }

        Ok(match Raw::deserialize(deserializer)? {
            Raw::Str(value) => GrypeLicense {
                value: Some(value),
                spdx_expression: None,
            },
            Raw::Obj {
                value,
                spdx_expression,
            } => GrypeLicense {
                value,
                spdx_expression,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Scanner implementation
// ---------------------------------------------------------------------------

/// Cap a captured subprocess stream at `max` bytes for inclusion in an error
/// message. Keeps the *tail* (most recent output) because Grype's failure
/// reason is typically the last line it logs before exiting. Adds a
/// `…[truncated]` marker so the caller can tell the message was clipped.
///
/// Returns an owned `String` so the result is safe to interpolate into
/// `format!`. The `s` argument is a `Cow<str>` flavor from
/// `String::from_utf8_lossy`, so an as-ref accepts both arms.
fn truncate_stream(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Slice on a char boundary to avoid panicking on a multibyte split.
    // `floor_char_boundary` is unstable, so walk manually.
    let start = s.len().saturating_sub(max);
    let mut boundary = start;
    while boundary < s.len() && !s.is_char_boundary(boundary) {
        boundary += 1;
    }
    format!("…[truncated]{}", &s[boundary..])
}

/// Classify a `std::io::Error` from spawning `grype` into an `AppError`.
///
/// Issue #1465: the prior implementation used a substring search on the
/// child process's stderr (`"not found" || "No such file"`) to detect "grype
/// is not installed". That heuristic mis-fired whenever grype itself printed
/// "not found" in a normal runtime error, most commonly an HTTP 404 from
/// registry-mode against an image ref the registry didn't recognize. The
/// operator saw "Grype binary not available" when grype was perfectly
/// installed; they patched their Dockerfile and the issue remained.
///
/// The correct signal is `io::ErrorKind::NotFound` returned by the spawn
/// itself, which the kernel sets when `execve()` cannot resolve the program
/// name on PATH. Any other spawn failure (permission denied, fork failure,
/// etc.) is surfaced as a generic "failed to execute Grype" so the operator
/// gets the underlying OS error.
///
/// Returned as a pure helper so the classification has a unit test that does
/// not depend on whether `grype` happens to be installed on the test host.
fn classify_grype_spawn_error(err: &std::io::Error) -> AppError {
    if err.kind() == std::io::ErrorKind::NotFound {
        AppError::Internal(
            "Grype binary not available (the `grype` executable was not \
             found on PATH; install it or use the prebuilt artifact-keeper \
             backend image which bundles grype at /usr/local/bin/grype)"
                .to_string(),
        )
    } else {
        AppError::Internal(format!("Failed to execute Grype: {}", err))
    }
}

/// Resolve the registry host string Grype's `registry:` mode targets. The
/// first non-empty source wins, in priority order:
///   1. `AK_GRYPE_REGISTRY_HOST` — explicit override (full URL accepted).
///   2. `PEER_PUBLIC_ENDPOINT` — reused from the peer/distribution config so
///      operators don't have to set two env vars in the common case.
///   3. `http://localhost:8080` — dev fallback for `cargo run` /
///      docker-compose dev.
///
/// The returned value has any scheme (`https://`, `http://`) stripped and
/// trailing `/` trimmed, because Grype expects `host[:port]`, not a URL.
///
/// `pub(crate)` so `ImageScanner::extract_image_ref_for_repo` reuses the same
/// host-resolution logic when qualifying the Trivy scan target.
pub(crate) fn resolve_registry_host() -> String {
    let raw = std::env::var("AK_GRYPE_REGISTRY_HOST")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("PEER_PUBLIC_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let no_scheme = raw
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    // Drop any `user[:pass]@` prefix in case PEER_PUBLIC_ENDPOINT was set
    // with embedded credentials (Grype reads auth from ~/.docker/config.json,
    // not the target URL; leaving creds in the host string would just
    // confuse the parser and risk leaking the secret into the JSON report's
    // `target` field on error).
    let host = match no_scheme.rsplit_once('@') {
        Some((_creds, host)) => host,
        None => no_scheme,
    };
    host.to_string()
}

/// Grype-based vulnerability scanner for packages and archives.
pub struct GrypeScanner {
    scan_workspace: String,
    /// Lazily-probed version string from `grype --version`, e.g.
    /// `grype-0.83.0`. Successful probes are cached for an hour so each scan
    /// does not pay an extra subprocess; failed probes expire after 60s so
    /// the field starts populating once the binary becomes available.
    cached_version: VersionCache,
}

impl GrypeScanner {
    pub fn new(scan_workspace: String) -> Self {
        Self {
            scan_workspace,
            cached_version: VersionCache::new(),
        }
    }

    /// Build the `<host>/<name><sep><reference>` image ref that Grype's
    /// `registry:` mode expects. `<sep>` is `:` for tags and `@` for digest
    /// references per the OCI distribution spec; see `join_oci_image_ref`.
    /// The host comes from the first non-empty of:
    ///   1. `AK_GRYPE_REGISTRY_HOST` (explicit override; full URL accepted,
    ///      scheme is stripped before Grype sees it).
    ///   2. `PEER_PUBLIC_ENDPOINT` (already configured for in-cluster distribution).
    ///   3. `http://localhost:8080` (dev fallback).
    ///
    /// Returns `None` if the artifact is not at a recognizable
    /// `v2/<name>/manifests/<ref>` path; the caller skips Grype rather than
    /// falling through to dir mode (which would resurrect #966's zero-
    /// findings-on-manifest-JSON bug).
    pub(crate) fn build_registry_image_ref(artifact: &Artifact) -> Option<String> {
        let (name, reference) = parse_oci_manifest_path(&artifact.path)?;
        let host = resolve_registry_host();
        let qualified_name = format!("{}/{}", host, name);
        Some(join_oci_image_ref(&qualified_name, reference))
    }

    /// Build the Grype registry image ref using the owning repository routing
    /// key supplied by scanner orchestration.
    ///
    /// Stored OCI artifact paths intentionally omit the repository key
    /// (`v2/<image>/manifests/<reference>`), while the external Artifact Keeper
    /// route is `/v2/<repo_key>/<image>/manifests/<reference>`. Always
    /// prepending the owning repository key makes direct local/remote scans
    /// routable and also keeps mirror-cache scans deterministic by targeting
    /// the stored artifact's repository instead of relying on default mirror
    /// fallback.
    pub(crate) fn build_registry_image_ref_for_repo(
        artifact: &Artifact,
        repository_key: &str,
        _repository_type: &str,
    ) -> Option<String> {
        let (name, reference) = parse_oci_manifest_path(&artifact.path)?;
        let host = resolve_registry_host();
        let qualified_name = format!("{}/{}/{}", host, repository_key, name);
        Some(join_oci_image_ref(&qualified_name, reference))
    }

    /// Single source of truth for the OCI `registry:` image ref used by the
    /// production scan dispatch (`is_applicable_for_target` and
    /// `scan_target`).
    ///
    /// This intentionally delegates to the **repository-scoped** builder, not
    /// the legacy path-only `build_registry_image_ref`. Stored OCI artifact
    /// paths omit the routing key (`v2/<image>/manifests/<ref>`), but the
    /// external `/v2/` route that Grype pulls from is
    /// `/v2/<repo_key>/<image>/manifests/<ref>` (see `oci_v2::resolve_repo`,
    /// which splits the first path segment as the repository key). Issue #1903:
    /// dispatching through the path-only builder produced
    /// `<host>/<image>:<tag>`, which Grype resolved to `/v2/<image>/manifests/...`
    /// and the registry rejected with `NAME_UNKNOWN` because no repository
    /// named `<image>` exists. Threading the owning repository key restores a
    /// routable `<host>/<repo_key>/<image>:<tag>` ref.
    fn oci_registry_target(artifact: &Artifact, target: &ScanTarget<'_>) -> Option<String> {
        Self::build_registry_image_ref_for_repo(
            artifact,
            target.repository_key,
            target.repository_type,
        )
    }

    async fn scan_oci_registry_ref(
        &self,
        artifact: &Artifact,
        image_ref: String,
    ) -> Result<ScanOutput> {
        let target = format!("registry:{}", image_ref);
        info!("Grype OCI registry scan target: {}", target);

        let report = match self.run_grype_target(&target).await {
            Ok(report) => report,
            Err(e) => {
                return Err(
                    fail_scan("Grype OCI scan", artifact, &e, &self.scan_workspace, None).await,
                );
            }
        };

        let findings = Self::convert_findings(&report);
        let packages = Self::convert_packages(&report);
        info!(
            "Grype OCI scan complete for {}: {} vulnerabilities, {} components",
            artifact.name,
            findings.len(),
            packages.len()
        );
        // #1273: emit a `packages` list (not `findings_only`) so the
        // vulnerable components Grype matched on appear in the SBOM even when
        // Trivy did not enumerate them. ScanCompleteness stays Complete
        // because Grype's catalog of matched packages is the universe it
        // intends to report on; the partial-scan signal is reserved for
        // Trivy's parser-skipped lockfiles.
        Ok(ScanOutput {
            findings,
            packages,
            scan_completeness: crate::services::scanner_service::ScanCompleteness::Complete,
        })
    }

    /// Run grype against the workspace directory.
    async fn run_grype(&self, workspace: &Path) -> Result<GrypeReport> {
        let dir_arg = format!("dir:{}", workspace.to_string_lossy());
        self.run_grype_target(&dir_arg).await
    }

    /// Run grype against an arbitrary target string (e.g. `dir:/path`,
    /// `registry:host/name:tag`). Centralized so both modes share output
    /// parsing and "binary not installed" handling.
    ///
    /// Two behaviors worth calling out:
    ///
    /// 1. We do **not** pass `-q`. Grype's `-q` flag suppresses *all* logging,
    ///    including the messages it writes on a DB-load/refresh failure. With
    ///    `-q`, an exit-1 failure surfaces to the caller as `"Grype scan
    ///    failed (exit status: 1): "` with an empty stderr slot — which is
    ///    exactly what release-gate #1001-followup reported. Letting Grype
    ///    log to stderr keeps the JSON report on stdout (Grype separates
    ///    structured output from logging) while preserving a useful error
    ///    payload on the failure path.
    ///
    /// 2. We pin the DB-update-related env vars defensively. Grype defaults
    ///    `db.auto-update=true` and `db.validate-age=true`. With those
    ///    defaults, after the pre-seeded DB ages past `db.max-allowed-built-
    ///    age` (5 days), Grype tries to fetch a fresh copy from
    ///    grype.anchore.io, which fails in network-restricted environments
    ///    (ARC runner pods, release-gate jobs) and exits 1. The Dockerfile
    ///    also sets these vars, but injecting them here means the scanner
    ///    keeps working under deployment configs that wipe inherited env
    ///    (Helm charts, k8s `env:` blocks that replace rather than append).
    ///    See artifact-keeper#1001 and PR #1002 (commit 23d9743).
    async fn run_grype_target(&self, target: &str) -> Result<GrypeReport> {
        // Issue #1465: detect "grype binary missing from PATH" via the
        // io::ErrorKind of the spawn failure, NOT a substring search on
        // stderr. The previous implementation classified any non-zero exit
        // whose stderr contained "not found" or "No such file" as a missing
        // binary, but those phrases also appear in normal grype runtime
        // errors (registry-mode HTTP 404 "manifest not found", DB cache
        // "no such file" when the seeded DB volume is missing, etc.). The
        // user-visible result was a misleading "Grype binary not available"
        // log on a perfectly-installed grype with an unreachable registry
        // ref, sending operators down a wild-goose chase patching their
        // Docker image. The kernel already gives us a precise NotFound
        // signal when execve() cannot resolve "grype"; use that.
        let output = tokio::process::Command::new("grype")
            .args([target, "-o", "json"])
            .env("GRYPE_DB_AUTO_UPDATE", "false")
            .env("GRYPE_DB_VALIDATE_AGE", "false")
            .env("GRYPE_CHECK_FOR_APP_UPDATE", "false")
            .output()
            .await
            .map_err(|e| classify_grype_spawn_error(&e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Include a stdout tail too: Grype writes its progress/ETUI to
            // stderr, but a hard failure during JSON encoding can leave a
            // partial payload on stdout that is the only clue to the cause.
            // Cap each stream at 4 KiB so a runaway log does not produce a
            // megabyte-class AppError message.
            let stderr_tail = truncate_stream(&stderr, 4096);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stdout_tail = truncate_stream(&stdout, 4096);
            return Err(AppError::Internal(format!(
                "Grype scan failed ({}): stderr={:?} stdout={:?}",
                output.status, stderr_tail, stdout_tail
            )));
        }

        serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Grype output: {}", e)))
    }

    /// Convert Grype matches into `RawFinding` values.
    ///
    /// `affected_component` holds the bare package name. Earlier versions of
    /// this method appended the artifact type in parentheses (e.g. `log4j-core
    /// (java-archive)`), but #1311 aligned the image-scanner code path with
    /// the filesystem-scanner contract from #903: cross-source join keys
    /// (SBOM, CVE-mapping, UI) need the raw name, and any type information
    /// belongs in a separate column rather than smuggled inside the name
    /// string.
    ///
    /// Companion package inventory is emitted by [`convert_packages`] so that
    /// SBOM generation reflects the components Grype matched on even when the
    /// co-resident Trivy filesystem scanner missed them (a transitive
    /// node_module nested deeper than Trivy's lockfile parser walked, an
    /// ecosystem Trivy lacks a parser for, etc. — see #1273).
    fn convert_findings(report: &GrypeReport) -> Vec<RawFinding> {
        report
            .matches
            .iter()
            .map(|m| {
                // B15: Grype's primary `id` for an ecosystem advisory is often
                // the GHSA id, with the canonical NVD CVE in
                // `relatedVulnerabilities`. Surface the CVE id as the finding's
                // `cve_id` so downstream consumers (and the release-gate, which
                // keys on `CVE-2019-10744`) can join on the well-known id. The
                // GHSA id is retained in the title so neither identifier is
                // lost.
                let primary_id = &m.vulnerability.id;
                let canonical_cve = canonical_cve_id(primary_id, &m.related_vulnerabilities);
                RawFinding {
                    severity: Severity::from_str_loose(&m.vulnerability.severity)
                        .unwrap_or(Severity::Info),
                    title: format!("{} in {}", primary_id, m.artifact.name),
                    description: m.vulnerability.description.clone(),
                    cve_id: Some(canonical_cve),
                    // Bare package name; matches scanner_service::convert_trivy_findings
                    // so SBOM / CVE-mapping consumers can join on the raw name.
                    affected_component: Some(m.artifact.name.clone()),
                    affected_version: Some(m.artifact.version.clone()),
                    fixed_version: m
                        .vulnerability
                        .fix
                        .as_ref()
                        .and_then(|f| f.versions.first().cloned()),
                    source: Some("grype".to_string()),
                    source_url: m
                        .vulnerability
                        .urls
                        .as_ref()
                        .and_then(|u| u.first().cloned()),
                }
            })
            .collect()
    }

    /// Convert Grype matches into [`RawPackage`] inventory rows (#1273).
    ///
    /// Grype's JSON output names every package it finds a CVE for inside the
    /// `matches[].artifact` block. Persisting those as `scan_packages` rows
    /// makes the SBOM read path (`extract_dependencies_for_artifact`) surface
    /// the vulnerable component in the CycloneDX/SPDX `components` list, even
    /// when the co-resident Trivy filesystem scanner did not enumerate it —
    /// the bug reported in #1273 where a Grype CVE lands on a transitive
    /// node_module that Trivy's package-lock parser walked past.
    ///
    /// One package can carry multiple CVEs (Grype emits one match per CVE),
    /// so we dedupe by `(name, version)` to keep the inventory list small
    /// and to mirror the database's `scan_packages_unique_per_scan` index:
    /// the DB would reject duplicates anyway, but pre-deduping cuts the
    /// INSERT volume and avoids the per-row metric incrementing on rows
    /// the index drops.
    ///
    /// PURL preference order, mirroring the spec recommendation:
    /// 1. Grype's own `artifact.purl` when present (Grype v0.50+ emits this
    ///    for the catalogued ecosystems; the field is normalized for
    ///    namespaced npm scopes, Maven group/artifact, etc.).
    /// 2. Synthesized from the Grype `artifact.type` token and the
    ///    `(name, version)` pair when the PURL field is absent (legacy
    ///    Grype builds, exotic ecosystems).
    /// 3. `None` when neither path produces a syntactically valid PURL.
    ///
    /// Returns an empty Vec when the report has no matches, which is the
    /// expected output for clean artifacts and preserves the pre-#1273
    /// behaviour of [`ScanOutput::findings_only`] for that case.
    fn convert_packages(report: &GrypeReport) -> Vec<RawPackage> {
        let mut seen: std::collections::HashSet<(String, Option<String>)> =
            std::collections::HashSet::new();
        let mut packages = Vec::new();
        for m in &report.matches {
            if m.artifact.name.is_empty() {
                continue;
            }
            let version_opt = if m.artifact.version.is_empty() {
                None
            } else {
                Some(m.artifact.version.clone())
            };
            let key = (m.artifact.name.clone(), version_opt.clone());
            if !seen.insert(key) {
                continue;
            }
            let purl = grype_artifact_purl(&m.artifact);
            let license = grype_artifact_license(&m.artifact);
            packages.push(RawPackage {
                name: m.artifact.name.clone(),
                version: version_opt,
                purl,
                license,
                // Grype does not name the lockfile/manifest the match came
                // from in a stable field; leaving source_target None mirrors
                // the convention used for image-mode Trivy rows that lack a
                // per-result target string.
                source_target: m.artifact.artifact_type.clone(),
            });
        }
        packages
    }
}

/// Cheap structural check for a `CVE-YYYY-N` identifier. Case-insensitive on
/// the `CVE` prefix; the suffix must be 4+ digits per NVD numbering. Mirrors
/// the validation in the sbom handler (`is_valid_cve_id`) so the alias chosen
/// here is one the CVE-history endpoint will also accept. (#1375 / B15)
fn is_cve_id(id: &str) -> bool {
    let mut parts = id.trim().split('-');
    match parts.next() {
        Some(p) if p.eq_ignore_ascii_case("CVE") => {}
        _ => return false,
    }
    let year = match parts.next() {
        Some(y) => y,
        None => return false,
    };
    let number = match parts.next() {
        Some(n) => n,
        None => return false,
    };
    if parts.next().is_some() {
        return false;
    }
    if year.len() != 4 || !year.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    number.len() >= 4 && number.bytes().all(|b| b.is_ascii_digit())
}

/// Choose the canonical vulnerability id for a finding's `cve_id` field.
///
/// If the primary id is already a `CVE-` id we keep it. Otherwise (the common
/// case for npm/RubyGems advisories where Grype's primary id is a GHSA) we
/// look through `relatedVulnerabilities` for the first NVD CVE id and prefer
/// it, so the well-known CVE identifier is surfaced. If no CVE alias exists we
/// fall back to the primary id unchanged (e.g. a pure GHSA advisory with no
/// assigned CVE). (#1375 / B15)
fn canonical_cve_id(primary_id: &str, related: &[GrypeRelatedVulnerability]) -> String {
    if is_cve_id(primary_id) {
        return primary_id.to_string();
    }
    related
        .iter()
        .map(|r| r.id.as_str())
        .find(|id| is_cve_id(id))
        .map(|id| id.to_string())
        .unwrap_or_else(|| primary_id.to_string())
}

/// Resolve a PURL string for a Grype-matched artifact (#1273).
///
/// Prefers Grype's own `artifact.purl` when it passes the same syntactic
/// validation Trivy PURLs go through ([`validate_trivy_purl`]). Falls back to
/// synthesizing `pkg:<type>/<name>@<version>` from the Grype `artifact.type`
/// token. Returns `None` when neither path produces a valid PURL.
fn grype_artifact_purl(artifact: &GrypeArtifact) -> Option<String> {
    if let Some(raw) = artifact.purl.as_deref() {
        if let Some(valid) = validate_trivy_purl(raw) {
            return Some(valid);
        }
    }
    let purl_type = grype_type_to_purl_type(artifact.artifact_type.as_deref()?)?;
    if artifact.name.is_empty() || artifact.version.is_empty() {
        return None;
    }
    let synthesized = format!("pkg:{}/{}@{}", purl_type, artifact.name, artifact.version);
    validate_trivy_purl(&synthesized)
}

/// Reduce a Grype `licenses` array to a SPDX-safe joined expression.
/// Mirrors the Trivy-side [`crate::services::scanner_service::sanitize_trivy_licenses`]
/// pipeline: each input term passes through the SPDX whitelist so a hostile
/// metadata field cannot smuggle a non-standard identifier into the SBOM.
fn grype_artifact_license(artifact: &GrypeArtifact) -> Option<String> {
    let licenses = artifact.licenses.as_ref()?;
    let terms: Vec<String> = licenses
        .iter()
        .filter_map(|l| {
            l.spdx_expression
                .as_deref()
                .or(l.value.as_deref())
                .map(str::to_string)
        })
        .collect();
    crate::services::scanner_service::sanitize_trivy_licenses(&terms)
}

/// Map a Grype `artifact.type` token to its PURL `type` segment.
///
/// Grype's package types are documented at
/// <https://github.com/anchore/syft/blob/main/syft/pkg/type.go> and follow a
/// stable enumeration: `npm`, `python`, `gem`, `java-archive`, `go-module`,
/// `rust-crate`, `apk`, `deb`, `rpm`, `dotnet`, `php-composer`, etc.
///
/// Returns `None` for unknown types so the caller drops the PURL field rather
/// than minting `pkg:unknown/...` strings that downstream tooling will reject.
/// This mirrors the conservative posture of
/// [`crate::services::scanner_service::format_to_purl_type`] which falls back
/// to `"generic"`, but for inventory rows that already have a name+version we
/// prefer a missing PURL to a wrong-namespace one.
fn grype_type_to_purl_type(grype_type: &str) -> Option<&'static str> {
    match grype_type.to_lowercase().as_str() {
        "npm" => Some("npm"),
        "python" => Some("pypi"),
        "gem" => Some("gem"),
        "java-archive" | "jenkins-plugin" => Some("maven"),
        "go-module" | "go-mod" => Some("golang"),
        "rust-crate" => Some("cargo"),
        "apk" => Some("apk"),
        "deb" => Some("deb"),
        "rpm" => Some("rpm"),
        "dotnet" => Some("nuget"),
        "php-composer" | "composer" => Some("composer"),
        "conan" => Some("conan"),
        "hex" => Some("hex"),
        "dart-pub" => Some("pub"),
        "swift" => Some("swift"),
        "cocoapods" => Some("cocoapods"),
        "hackage" => Some("hackage"),
        _ => None,
    }
}

#[async_trait]
impl Scanner for GrypeScanner {
    fn name(&self) -> &str {
        "grype"
    }

    fn scan_type(&self) -> &str {
        "grype"
    }

    /// Grype handles both filesystem-style artifacts (npm tarballs, PyPI
    /// wheels, lockfiles) via `dir:` mode and OCI / Docker images via
    /// `registry:` mode (#1160). The only artifacts we explicitly reject
    /// are OCI manifests at paths we cannot reconstruct a registry ref
    /// from; everything else is fair game.
    fn is_applicable(&self, artifact: &Artifact) -> bool {
        if is_oci_image_artifact(artifact) {
            // Only route OCI artifacts to Grype if we can derive a registry
            // image ref from the artifact path. Without a valid ref Grype's
            // registry mode has nothing to pull, and falling through to dir
            // mode would resurrect the #966 "0 findings on manifest JSON"
            // bug. Better to skip Grype for malformed OCI paths.
            return Self::build_registry_image_ref(artifact).is_some();
        }
        true
    }

    fn is_applicable_for_target(&self, target: &ScanTarget<'_>) -> bool {
        let artifact = target.artifact;
        if is_oci_image_artifact(artifact) {
            // Production OCI applicability is repository-aware: stored
            // artifact paths omit the routing key, so Grype must validate that
            // a ref can be built with the owning repository key restored.
            return Self::oci_registry_target(artifact, target).is_some();
        }
        self.is_applicable(artifact)
    }

    /// Probe `grype --version` once and cache the parsed version string.
    /// Returns `None` if the binary is missing or its output cannot be
    /// parsed.
    async fn version(&self) -> Option<String> {
        cached_cli_version(&self.cached_version, || async {
            let raw = capture_cli_version("grype", &["--version"]).await?;
            format_grype_version(&raw)
        })
        .await
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        info!(
            "Starting Grype scan for artifact: {} ({})",
            artifact.name, artifact.id
        );

        // #1160: route OCI / Docker image artifacts through `grype registry:`
        // against artifact-keeper's own OCI endpoint. The dir-mode path below
        // would see only the manifest JSON and return 0 findings (the #966
        // regression). `is_applicable` already filtered out OCI paths Grype
        // cannot build a ref for.
        if is_oci_image_artifact(artifact) {
            let image_ref = Self::build_registry_image_ref(artifact).ok_or_else(|| {
                AppError::Internal(
                    "Grype OCI scan: failed to reconstruct registry image ref \
                     (is_applicable should have rejected this artifact)"
                        .to_string(),
                )
            })?;
            return self.scan_oci_registry_ref(artifact, image_ref).await;
        }

        let workspace =
            ScanWorkspace::prepare(&self.scan_workspace, None, artifact, content).await?;

        let report = match self.run_grype(&workspace).await {
            Ok(report) => report,
            Err(e) => {
                return Err(
                    fail_scan("Grype scan", artifact, &e, &self.scan_workspace, None).await,
                );
            }
        };

        let findings = Self::convert_findings(&report);
        let packages = Self::convert_packages(&report);

        info!(
            "Grype scan complete for {}: {} vulnerabilities, {} components",
            artifact.name,
            findings.len(),
            packages.len()
        );

        ScanWorkspace::cleanup(&self.scan_workspace, None, artifact).await;

        // #1273: Grype's default JSON does not enumerate *every* installed
        // package the way Trivy's `--list-all-pkgs` does, but it does name
        // every CVE-matched artifact in the `matches[].artifact` block.
        // Persisting those as scan_packages rows means an artifact whose
        // only inventory signal is Grype (Trivy missed a transitive
        // node_module, or the ecosystem has no Trivy parser at all) still
        // produces an SBOM whose `components` list includes the vulnerable
        // package — the bug reported in #1273. The empty-packages Vec
        // returned for clean artifacts (no matches) preserves the original
        // findings-only semantic, with `extract_dependencies_for_artifact`
        // falling through to Trivy's inventory.
        Ok(ScanOutput {
            findings,
            packages,
            scan_completeness: crate::services::scanner_service::ScanCompleteness::Complete,
        })
    }

    async fn scan_target(
        &self,
        target: &ScanTarget<'_>,
        metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        let artifact = target.artifact;
        if is_oci_image_artifact(artifact) {
            let image_ref = Self::oci_registry_target(artifact, target).ok_or_else(|| {
                AppError::Internal(
                    "Grype OCI scan: failed to reconstruct repository-qualified registry image ref \
                     (is_applicable_for_target should have rejected this artifact)"
                        .to_string(),
                )
            })?;
            return self.scan_oci_registry_ref(artifact, image_ref).await;
        }

        self.scan(artifact, metadata, content).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::scanner_service::test_helpers::{assert_scan_failed, make_test_artifact};

    fn make_artifact(name: &str, content_type: &str) -> Artifact {
        make_test_artifact(name, content_type, &format!("test/{}", name))
    }

    // -----------------------------------------------------------------------
    // is_applicable: #1160. OCI / Docker image manifests now route through
    // `grype registry:` mode against artifact-keeper's own registry, so
    // well-formed OCI paths are applicable. Malformed paths (missing
    // /manifests/ or empty name/ref) remain rejected because we cannot
    // build a registry ref for them and dir-mode would silently regress to
    // 0 findings (the #966 condition).
    // -----------------------------------------------------------------------

    fn grype() -> GrypeScanner {
        GrypeScanner::new("/tmp/grype-applicability-test".to_string())
    }

    /// Serializes env-var mutation across the parallel tests in this module
    /// so the registry-host probe's `AK_GRYPE_REGISTRY_HOST` /
    /// `PEER_PUBLIC_ENDPOINT` reads stay deterministic. Same pattern as
    /// `ldap_service::ENV_MUTEX`.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Snapshot of process-wide env vars touched by the registry-ref tests.
    /// Restored on drop so cross-test isolation does not depend on test
    /// authors remembering to clean up after themselves.
    struct EnvGuard {
        grype_host: Option<String>,
        peer_endpoint: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new() -> Self {
            // `lock().unwrap()` is fine here: a poisoned env mutex means a
            // prior test panicked mid-mutation, and surfacing that as a
            // test failure is the desired behavior.
            let lock = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
            Self::with_lock(lock)
        }

        fn with_lock(lock: std::sync::MutexGuard<'static, ()>) -> Self {
            let grype_host = std::env::var("AK_GRYPE_REGISTRY_HOST").ok();
            let peer_endpoint = std::env::var("PEER_PUBLIC_ENDPOINT").ok();
            std::env::remove_var("AK_GRYPE_REGISTRY_HOST");
            std::env::remove_var("PEER_PUBLIC_ENDPOINT");
            Self {
                grype_host,
                peer_endpoint,
                _lock: lock,
            }
        }

        fn restore_snapshot(&self) {
            match &self.grype_host {
                Some(v) => std::env::set_var("AK_GRYPE_REGISTRY_HOST", v),
                None => std::env::remove_var("AK_GRYPE_REGISTRY_HOST"),
            }
            match &self.peer_endpoint {
                Some(v) => std::env::set_var("PEER_PUBLIC_ENDPOINT", v),
                None => std::env::remove_var("PEER_PUBLIC_ENDPOINT"),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            self.restore_snapshot();
        }
    }

    #[test]
    fn test_is_applicable_accepts_oci_image_manifest_via_registry_mode() {
        let _env = EnvGuard::new();
        let a = make_test_artifact(
            "nginx",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        assert!(
            grype().is_applicable(&a),
            "Well-formed OCI manifest paths must route to Grype (#1160) so \
             Grype scans the image in registry mode alongside ImageScanner/Trivy"
        );
    }

    #[test]
    fn test_is_applicable_accepts_docker_distribution_manifest() {
        let _env = EnvGuard::new();
        let a = make_test_artifact(
            "redis",
            "application/vnd.docker.distribution.manifest.v2+json",
            "v2/library/redis/manifests/latest",
        );
        assert!(grype().is_applicable(&a));
    }

    #[test]
    fn test_is_applicable_rejects_oci_path_without_manifests_segment() {
        let _env = EnvGuard::new();
        // The OCI predicate is true (path starts with v2/) but there is no
        // /manifests/ segment, so we cannot build a registry ref. Reject
        // rather than fall through to dir-mode which would scan the
        // manifest JSON and report 0 findings (#966).
        let a = make_test_artifact(
            "broken",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/foo/blobs/sha256:deadbeef",
        );
        assert!(!grype().is_applicable(&a));
    }

    #[test]
    fn test_build_registry_image_ref_basic_path() {
        let _env = EnvGuard::new();
        let a = make_test_artifact(
            "nginx",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        let r = GrypeScanner::build_registry_image_ref_for_repo(&a, "docker-local", "local")
            .expect("ref must build");
        assert_eq!(r, "localhost:8080/docker-local/library/nginx:latest");
    }

    #[test]
    fn test_build_registry_image_ref_legacy_helper_is_path_only() {
        let _env = EnvGuard::new();
        let a = make_test_artifact(
            "nginx",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        let r = GrypeScanner::build_registry_image_ref(&a).expect("ref must build");
        assert_eq!(
            r, "localhost:8080/library/nginx:latest",
            "legacy callers without ScanTarget context still get the old path-only ref; production uses build_registry_image_ref_for_repo"
        );
    }

    /// Regression test for issue #1483. Digest-pinned OCI artifacts must
    /// use `@` between the qualified name and the `sha256:...` digest, not
    /// `:`. Every `docker buildx push` writes two such digest-referenced
    /// manifests (platform + attestation), so this is the common case for
    /// image scans. With the bug present, Grype rejects every digest scan
    /// with "could not parse reference".
    #[test]
    fn test_build_registry_image_ref_digest_uses_at_separator() {
        let _env = EnvGuard::new();
        let a = make_test_artifact(
            "platform-manifest",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/org/app/manifests/sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b",
        );
        let r = GrypeScanner::build_registry_image_ref_for_repo(&a, "oci-prod", "local")
            .expect("ref must build");
        assert_eq!(
            r,
            "localhost:8080/oci-prod/org/app@sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b"
        );
        // Defensive: the bad form (`name:sha256:...`) must never reappear.
        assert!(
            !r.contains("org/app:sha256:"),
            "digest ref must not use ':' between name and digest: {}",
            r
        );
    }

    #[test]
    fn test_build_registry_image_ref_uses_explicit_override() {
        let _env = EnvGuard::new();
        std::env::set_var(
            "AK_GRYPE_REGISTRY_HOST",
            "https://registry.example.com:5000",
        );
        let a = make_test_artifact(
            "redis",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/redis/manifests/7.2",
        );
        let r = GrypeScanner::build_registry_image_ref_for_repo(&a, "docker-local", "local")
            .expect("ref must build");
        // Scheme stripped, trailing slashes trimmed.
        assert_eq!(
            r,
            "registry.example.com:5000/docker-local/library/redis:7.2"
        );
    }

    #[test]
    fn test_build_registry_image_ref_falls_back_to_peer_public_endpoint() {
        let _env = EnvGuard::new();
        std::env::set_var("PEER_PUBLIC_ENDPOINT", "http://ak.svc.cluster.local:8080/");
        let a = make_test_artifact(
            "alpine",
            "application/vnd.docker.distribution.manifest.v2+json",
            "v2/library/alpine/manifests/3.19",
        );
        let r = GrypeScanner::build_registry_image_ref_for_repo(&a, "docker-mirror", "remote")
            .expect("ref must build");
        assert_eq!(
            r,
            "ak.svc.cluster.local:8080/docker-mirror/library/alpine:3.19"
        );
    }

    #[test]
    fn test_build_registry_image_ref_strips_embedded_credentials() {
        let _env = EnvGuard::new();
        // Operator misconfigures PEER_PUBLIC_ENDPOINT with HTTP basic creds.
        // Stripping them avoids leaking the secret into Grype's JSON report
        // `target` field on error, and avoids confusing Grype's parser
        // (auth comes from ~/.docker/config.json, not the URL).
        std::env::set_var(
            "PEER_PUBLIC_ENDPOINT",
            "https://svcuser:hunter2@registry.example.com:5000",
        );
        let a = make_test_artifact(
            "x",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        let r = GrypeScanner::build_registry_image_ref_for_repo(&a, "docker-local", "local")
            .expect("ref must build");
        assert!(
            !r.contains("hunter2") && !r.contains("svcuser"),
            "credentials must not appear in the registry image ref: {}",
            r
        );
        assert_eq!(
            r,
            "registry.example.com:5000/docker-local/library/nginx:latest"
        );
    }

    #[test]
    fn test_build_registry_image_ref_internal_path_omits_repo_external_ref_includes_it() {
        let _env = EnvGuard::new();
        let a = make_test_artifact(
            "nginx",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        assert!(
            !a.path.contains("docker-local"),
            "stored OCI artifact paths are repository-internal and intentionally omit the repo key"
        );

        let r = GrypeScanner::build_registry_image_ref_for_repo(&a, "docker-local", "local")
            .expect("ref must build");
        assert_eq!(r, "localhost:8080/docker-local/library/nginx:latest");
    }

    #[test]
    fn test_build_registry_image_ref_prepends_mirror_repo_key_explicitly() {
        let _env = EnvGuard::new();
        let a = make_test_artifact(
            "alpine",
            "application/vnd.docker.distribution.manifest.v2+json",
            "v2/library/alpine/manifests/3.19",
        );
        let r = GrypeScanner::build_registry_image_ref_for_repo(&a, "docker-cache", "remote")
            .expect("ref must build");
        assert_eq!(r, "localhost:8080/docker-cache/library/alpine:3.19");
    }

    #[test]
    fn test_build_registry_image_ref_repo_key_collision_is_not_deduped() {
        let _env = EnvGuard::new();
        let a = make_test_artifact(
            "nginx",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/library/nginx/manifests/latest",
        );
        let r = GrypeScanner::build_registry_image_ref_for_repo(&a, "library", "local")
            .expect("ref must build");
        assert_eq!(r, "localhost:8080/library/library/nginx:latest");
    }

    #[test]
    fn test_build_registry_image_ref_rejects_malformed_paths() {
        let _env = EnvGuard::new();
        for path in [
            "v2/foo/blobs/sha256:abc",        // no /manifests/
            "v2//manifests/latest",           // empty name
            "v2/library/nginx/manifests/",    // empty reference
            "library/nginx/manifests/latest", // no v2/ prefix
        ] {
            let a = make_test_artifact("x", "application/octet-stream", path);
            assert!(
                GrypeScanner::build_registry_image_ref_for_repo(&a, "docker-local", "local")
                    .is_none(),
                "malformed path '{}' must not produce a registry ref",
                path
            );
        }
    }

    /// Regression test for issue #1903 ("Cannot run Grype OCI scan on images
    /// in docker repo" / `NAME_UNKNOWN`).
    ///
    /// The production scan dispatch (`scan_target` / `is_applicable_for_target`)
    /// must build the OCI `registry:` ref through the repository-scoped
    /// builder so the ref carries the owning repository key. The exact #1903
    /// scenario: an image pushed to docker repo `docker-repo1` is stored at
    /// `v2/sa-backend/manifests/release-1.4.0` (the routing key is stripped on
    /// store). Grype must be pointed at `/v2/docker-repo1/sa-backend/...`
    /// (host/`<repo_key>`/`<image>`:`<tag>`), because `oci_v2::resolve_repo`
    /// splits the first path segment as the repository key. With the bug, the
    /// path-only ref `<host>/sa-backend:release-1.4.0` made Grype request
    /// `/v2/sa-backend/manifests/...`, which the registry rejected with
    /// `NAME_UNKNOWN: repository not found: sa-backend`.
    #[test]
    fn test_scan_dispatch_uses_repo_scoped_ref_for_docker_repo_issue_1903() {
        let _env = EnvGuard::new();
        let artifact = make_test_artifact(
            "sa-backend",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/sa-backend/manifests/release-1.4.0",
        );
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "docker-repo1",
            repository_type: "local",
        };

        // The scan dispatch resolves a routable, repository-scoped ref.
        let dispatched =
            GrypeScanner::oci_registry_target(&artifact, &target).expect("ref must build");
        assert_eq!(
            dispatched, "localhost:8080/docker-repo1/sa-backend:release-1.4.0",
            "scan dispatch must thread the owning repository key into the OCI ref"
        );

        // Guard: the ref Grype receives must contain the repo key and must NOT
        // be the path-only form that triggered NAME_UNKNOWN in #1903.
        assert!(
            dispatched.contains("/docker-repo1/sa-backend:"),
            "dispatched ref must be repo-scoped (<repo>/<image>): {dispatched}"
        );
        let path_only = GrypeScanner::build_registry_image_ref(&artifact)
            .expect("legacy builder also resolves the path");
        assert_eq!(
            path_only, "localhost:8080/sa-backend:release-1.4.0",
            "sanity: the legacy path-only builder is exactly the broken #1903 ref"
        );
        assert_ne!(
            dispatched, path_only,
            "scan dispatch must NOT fall back to the path-only ref that caused #1903"
        );
    }

    /// Companion to the dispatch test: applicability for a docker-repo OCI
    /// artifact is also computed via the repository-scoped builder, so an
    /// applicable artifact never gets routed to a non-routable scan.
    #[test]
    fn test_is_applicable_for_target_oci_docker_repo_is_repo_scoped_issue_1903() {
        let _env = EnvGuard::new();
        let artifact = make_test_artifact(
            "sa-backend",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/sa-backend/manifests/release-1.4.0",
        );
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "docker-repo1",
            repository_type: "local",
        };
        assert!(
            grype().is_applicable_for_target(&target),
            "an OCI image in a docker repo must be applicable for Grype registry scanning"
        );
        // And the ref applicability validated is the repo-scoped one.
        assert_eq!(
            GrypeScanner::oci_registry_target(&artifact, &target),
            GrypeScanner::build_registry_image_ref_for_repo(&artifact, "docker-repo1", "local"),
            "applicability and dispatch must agree on the repo-scoped ref"
        );
    }

    #[test]
    fn test_is_applicable_accepts_npm_tarball() {
        // The happy path: Grype's existing fs scan does work on lockfiles,
        // SBOMs, language-pkg targets — keep those routing to Grype.
        let a = make_test_artifact(
            "body-parser-1.20.1.tgz",
            "application/gzip",
            "npm/body-parser/-/body-parser-1.20.1.tgz",
        );
        assert!(grype().is_applicable(&a));
    }

    #[test]
    fn test_is_applicable_accepts_pypi_wheel() {
        let a = make_test_artifact(
            "requests-2.31.0.whl",
            "application/zip",
            "pypi/requests/2.31.0/requests-2.31.0-py3-none-any.whl",
        );
        assert!(grype().is_applicable(&a));
    }

    #[test]
    fn test_convert_findings_basic() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "CVE-2023-99999".to_string(),
                    severity: "Critical".to_string(),
                    description: Some("A critical vulnerability".to_string()),
                    fix: Some(GrypeFix {
                        versions: vec!["2.0.0".to_string()],
                        state: Some("fixed".to_string()),
                    }),
                    urls: Some(vec![
                        "https://nvd.nist.gov/vuln/detail/CVE-2023-99999".to_string()
                    ]),
                },
                artifact: GrypeArtifact {
                    name: "vulnerable-pkg".to_string(),
                    version: "1.0.0".to_string(),
                    artifact_type: Some("python".to_string()),
                    purl: None,
                    licenses: None,
                },
                related_vulnerabilities: vec![],
            }],
        };

        let findings = GrypeScanner::convert_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cve_id, Some("CVE-2023-99999".to_string()));
        assert_eq!(findings[0].fixed_version, Some("2.0.0".to_string()));
        assert_eq!(findings[0].source, Some("grype".to_string()));
        // #1311: affected_component is the bare package name, mirroring the
        // filesystem-scanner contract from #903. The artifact type
        // ("python") used to be appended in parentheses but is now dropped
        // so SBOM / CVE-mapping consumers can join on the raw name.
        assert_eq!(
            findings[0].affected_component,
            Some("vulnerable-pkg".to_string()),
            "affected_component must be the bare package name, not '<name> (<type>)'"
        );
        assert_eq!(findings[0].affected_version, Some("1.0.0".to_string()));
        assert!(findings[0]
            .source_url
            .as_ref()
            .unwrap()
            .contains("nvd.nist.gov"));
    }

    /// Regression test for #1311. Grype's image-scanner code path (via
    /// registry mode #1160) historically wrapped `affected_component` as
    /// `"<name> (<artifact_type>)"`, e.g. `"log4j-core (java-archive)"`.
    /// PR #1150 standardized `scan_findings.affected_component` to the
    /// bare package name across all scanners so SBOM CycloneDX/SPDX output
    /// and the `scan_packages` join-table reconcile entries by raw name.
    /// This test pins the bare-name format on a Grype finding that carries
    /// a non-empty `artifact_type`, the exact shape that produced the bug.
    #[test]
    fn test_convert_findings_emits_bare_package_name_for_typed_artifact() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "CVE-2021-44228".to_string(),
                    severity: "Critical".to_string(),
                    description: None,
                    fix: None,
                    urls: None,
                },
                artifact: GrypeArtifact {
                    name: "log4j-core".to_string(),
                    version: "2.14.1".to_string(),
                    artifact_type: Some("java-archive".to_string()),
                    purl: None,
                    licenses: None,
                },
                related_vulnerabilities: vec![],
            }],
        };

        let findings = GrypeScanner::convert_findings(&report);
        assert_eq!(findings.len(), 1);
        let component = findings[0]
            .affected_component
            .as_ref()
            .expect("affected_component must be populated");
        assert_eq!(
            component, "log4j-core",
            "affected_component must be the bare package name; got {:?} \
             (the legacy '<name> (<type>)' format breaks SBOM and CVE-mapping joins, see #1311)",
            component
        );
        assert!(
            !component.contains('('),
            "affected_component must not contain the artifact-type parenthetical (#1311); got {:?}",
            component
        );
    }

    #[test]
    fn test_convert_findings_no_fix() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "GHSA-abcd-1234-efgh".to_string(),
                    severity: "Medium".to_string(),
                    description: None,
                    fix: None,
                    urls: None,
                },
                artifact: GrypeArtifact {
                    name: "some-lib".to_string(),
                    version: "0.5.0".to_string(),
                    artifact_type: None,
                    purl: None,
                    licenses: None,
                },
                related_vulnerabilities: vec![],
            }],
        };

        let findings = GrypeScanner::convert_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].fixed_version, None);
        assert_eq!(findings[0].source_url, None);
        assert_eq!(findings[0].description, None);
        // Without artifact_type, component is just the name
        assert_eq!(findings[0].affected_component, Some("some-lib".to_string()));
        // B15: a pure GHSA advisory with no related CVE keeps the GHSA id as
        // its cve_id (we do not invent a CVE; the alias logic only prefers a
        // CVE that grype actually emitted in relatedVulnerabilities).
        assert_eq!(findings[0].cve_id, Some("GHSA-abcd-1234-efgh".to_string()));
    }

    /// B15: Grype reports the lodash 4.17.4 prototype-pollution advisory under
    /// its GHSA id (`GHSA-jf85-cpcp-j695`) with the NVD `CVE-2019-10744` in
    /// `relatedVulnerabilities`. The release-gate `grype-scanner` suite asserts
    /// a finding with `cve_id == "CVE-2019-10744"` is present. Before this fix
    /// `convert_findings` copied the primary GHSA id verbatim, so the CVE the
    /// gate keys on never appeared. This pins the alias preference.
    #[test]
    fn test_convert_findings_prefers_related_cve_over_ghsa() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "GHSA-jf85-cpcp-j695".to_string(),
                    severity: "Critical".to_string(),
                    description: Some("Prototype pollution in lodash".to_string()),
                    fix: Some(GrypeFix {
                        versions: vec!["4.17.12".to_string()],
                        state: Some("fixed".to_string()),
                    }),
                    urls: Some(vec![
                        "https://github.com/advisories/GHSA-jf85-cpcp-j695".to_string()
                    ]),
                },
                artifact: GrypeArtifact {
                    name: "lodash".to_string(),
                    version: "4.17.4".to_string(),
                    artifact_type: Some("npm".to_string()),
                    purl: None,
                    licenses: None,
                },
                related_vulnerabilities: vec![GrypeRelatedVulnerability {
                    id: "CVE-2019-10744".to_string(),
                    namespace: Some("nvd:cpe".to_string()),
                }],
            }],
        };

        let findings = GrypeScanner::convert_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].cve_id,
            Some("CVE-2019-10744".to_string()),
            "convert_findings must surface the related NVD CVE id when the \
             primary match id is a GHSA (B15)"
        );
        // The GHSA id is not lost: it stays in the human-readable title.
        assert!(
            findings[0].title.contains("GHSA-jf85-cpcp-j695"),
            "title should retain the GHSA id; got {:?}",
            findings[0].title
        );
        // source attribution unchanged.
        assert_eq!(findings[0].source, Some("grype".to_string()));
    }

    /// B15: when the primary match id is already a CVE, the alias logic is a
    /// no-op even if relatedVulnerabilities also carries CVEs. The primary id
    /// wins so we never silently swap a finding's identity.
    #[test]
    fn test_convert_findings_keeps_primary_cve_id() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "CVE-2021-44228".to_string(),
                    severity: "Critical".to_string(),
                    description: None,
                    fix: None,
                    urls: None,
                },
                artifact: GrypeArtifact {
                    name: "log4j-core".to_string(),
                    version: "2.14.1".to_string(),
                    artifact_type: Some("java-archive".to_string()),
                    purl: None,
                    licenses: None,
                },
                related_vulnerabilities: vec![GrypeRelatedVulnerability {
                    id: "CVE-2021-45046".to_string(),
                    namespace: Some("nvd:cpe".to_string()),
                }],
            }],
        };
        let findings = GrypeScanner::convert_findings(&report);
        assert_eq!(findings[0].cve_id, Some("CVE-2021-44228".to_string()));
    }

    /// B15: a GHSA primary with no CVE alias falls back to the GHSA id rather
    /// than dropping the finding's identifier.
    #[test]
    fn test_canonical_cve_id_fallback_to_primary() {
        assert_eq!(
            canonical_cve_id("GHSA-aaaa-bbbb-cccc", &[]),
            "GHSA-aaaa-bbbb-cccc"
        );
        assert_eq!(
            canonical_cve_id(
                "GHSA-aaaa-bbbb-cccc",
                &[GrypeRelatedVulnerability {
                    id: "GHSA-dddd-eeee-ffff".to_string(),
                    namespace: None,
                }]
            ),
            "GHSA-aaaa-bbbb-cccc",
            "no CVE alias present -> keep primary GHSA id"
        );
    }

    #[test]
    fn test_is_cve_id_recognizes_valid_and_rejects_invalid() {
        assert!(is_cve_id("CVE-2019-10744"));
        assert!(is_cve_id("cve-1999-0001")); // case-insensitive, 4-digit suffix
        assert!(is_cve_id("CVE-2024-123456")); // 6-digit suffix
        assert!(!is_cve_id("GHSA-jf85-cpcp-j695"));
        assert!(!is_cve_id("CVE-2019-1")); // sub-4-digit suffix
        assert!(!is_cve_id("CVE-201-10744")); // 3-digit year
        assert!(!is_cve_id("not-a-cve"));
        assert!(!is_cve_id("CVE-2019-10744-extra")); // stray suffix
    }

    /// B15: grype JSON with a `relatedVulnerabilities` block deserializes the
    /// alias ids and the GHSA->CVE mapping fires.
    ///
    /// CRITICAL: this fixture mirrors grype's REAL output shape, where
    /// `relatedVulnerabilities` is a TOP-LEVEL field of the match object (a
    /// sibling of `vulnerability` and `artifact`). Verified against grype
    /// v0.112.0 for lodash 4.17.4. An earlier version of this test nested the
    /// array inside `vulnerability`, which matched the (buggy) struct shape
    /// and made the test pass while real scans produced GHSA ids -- the exact
    /// B15 gate failure. Keep this fixture faithful to grype's wire format.
    #[test]
    fn test_grype_report_deserializes_related_vulnerabilities() {
        let json = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "GHSA-jf85-cpcp-j695",
                    "severity": "High"
                },
                "relatedVulnerabilities": [
                    {"id": "CVE-2019-10744", "namespace": "nvd:cpe"}
                ],
                "artifact": {"name": "lodash", "version": "4.17.4", "type": "npm"}
            }]
        }"#;
        let report: GrypeReport = serde_json::from_str(json).unwrap();
        let related = &report.matches[0].related_vulnerabilities;
        assert_eq!(
            related.len(),
            1,
            "match-level relatedVulnerabilities must deserialize"
        );
        assert_eq!(related[0].id, "CVE-2019-10744");
        let findings = GrypeScanner::convert_findings(&report);
        assert_eq!(
            findings[0].cve_id,
            Some("CVE-2019-10744".to_string()),
            "GHSA->CVE mapping must fire from match-level relatedVulnerabilities"
        );
    }

    /// B15 regression guard: prove the JSON nesting matters. If a future
    /// change moves `related_vulnerabilities` back inside `GrypeVulnerability`,
    /// real grype output (which carries the array at the MATCH level) would
    /// deserialize to an empty Vec and the mapping would silently regress to
    /// the primary GHSA id. This test pins that the array is read from the
    /// match level by feeding grype's real shape and asserting the CVE wins,
    /// and that an array MISplaced inside `vulnerability` is ignored.
    #[test]
    fn test_related_vulnerabilities_is_read_from_match_level_not_vulnerability() {
        // Correct (real grype) shape: array at match level -> CVE surfaces.
        let correct = r#"{
            "matches": [{
                "vulnerability": {"id": "GHSA-jf85-cpcp-j695", "severity": "High"},
                "relatedVulnerabilities": [{"id": "CVE-2019-10744"}],
                "artifact": {"name": "lodash", "version": "4.17.4", "type": "npm"}
            }]
        }"#;
        let report: GrypeReport = serde_json::from_str(correct).unwrap();
        let findings = GrypeScanner::convert_findings(&report);
        assert_eq!(findings[0].cve_id, Some("CVE-2019-10744".to_string()));

        // Misplaced shape: array nested under vulnerability (the old bug's
        // assumption). The match-level field is absent, so the alias is NOT
        // picked up and the primary GHSA id is kept. This documents why the
        // nesting is load-bearing.
        let misplaced = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "GHSA-jf85-cpcp-j695",
                    "severity": "High",
                    "relatedVulnerabilities": [{"id": "CVE-2019-10744"}]
                },
                "artifact": {"name": "lodash", "version": "4.17.4", "type": "npm"}
            }]
        }"#;
        let report2: GrypeReport = serde_json::from_str(misplaced).unwrap();
        assert!(
            report2.matches[0].related_vulnerabilities.is_empty(),
            "a relatedVulnerabilities array nested under vulnerability must NOT \
             populate the match-level field"
        );
        let findings2 = GrypeScanner::convert_findings(&report2);
        assert_eq!(
            findings2[0].cve_id,
            Some("GHSA-jf85-cpcp-j695".to_string()),
            "with no match-level alias, the primary GHSA id is kept"
        );
    }

    #[test]
    fn test_convert_findings_empty() {
        let report = GrypeReport { matches: vec![] };
        let findings = GrypeScanner::convert_findings(&report);
        assert!(findings.is_empty());
    }

    /// Scan failures (workspace creation, missing grype binary) must
    /// propagate as Err, never as Ok(vec![]).
    #[tokio::test]
    async fn test_scan_propagates_errors() {
        let artifact = make_artifact("pkg-1.0.0.tar.gz", "application/gzip");
        let content = Bytes::from_static(b"not a real archive");

        // Impossible workspace path
        let bad_ws = GrypeScanner::new("/dev/null/impossible-workspace".to_string());
        assert!(
            bad_ws.scan(&artifact, None, &content).await.is_err(),
            "scan() must return Err when workspace creation fails"
        );

        // Missing grype binary (skip if grype is installed)
        if std::process::Command::new("grype")
            .arg("version")
            .output()
            .is_ok()
        {
            eprintln!("grype is installed, skipping unavailable-grype test");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let no_grype = GrypeScanner::new(dir.path().to_string_lossy().to_string());
        assert_scan_failed(
            &no_grype.scan(&artifact, None, &content).await,
            "Grype scan",
        );
    }

    // -----------------------------------------------------------------------
    // Issue #1465: classify_grype_spawn_error pins the contract that
    // "Grype binary not available" is reserved for the *spawn* NotFound
    // signal. Prior code substring-matched stderr for "not found" / "No
    // such file", which mis-classified any grype runtime error whose log
    // included those phrases (the common case: a registry-mode HTTP 404
    // "manifest not found" against an unreachable image ref) as a missing
    // binary. Operators saw the misleading "binary not available" log on
    // a perfectly-installed grype and patched their Dockerfile in vain.
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_grype_spawn_error_notfound_maps_to_binary_missing() {
        // The exact std::io::Error::Kind tokio surfaces when execve() fails
        // to resolve the program name on PATH.
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory");
        let app = classify_grype_spawn_error(&io_err);
        let msg = format!("{}", app);
        assert!(
            msg.contains("Grype binary not available"),
            "NotFound spawn errors must surface as the binary-missing diagnostic; got {:?}",
            msg
        );
        // Helpful remediation hint should be present so operators know
        // where to find or install grype.
        assert!(
            msg.contains("PATH") || msg.contains("install"),
            "binary-missing message should hint at remediation; got {:?}",
            msg
        );
    }

    #[test]
    fn test_classify_grype_spawn_error_permission_denied_is_not_binary_missing() {
        // A PermissionDenied error means grype was found on PATH but the
        // process could not exec it (chmod 000, SELinux denial, etc.).
        // The classifier must distinguish this from "binary not available"
        // so the operator does not spend hours hunting for a missing binary
        // when the file is right there but unexecutable.
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let app = classify_grype_spawn_error(&io_err);
        let msg = format!("{}", app);
        assert!(
            !msg.contains("not available"),
            "non-NotFound spawn errors must NOT be labeled 'binary not available'; got {:?}",
            msg
        );
        assert!(
            msg.contains("Failed to execute Grype") && msg.contains("permission denied"),
            "non-NotFound spawn errors must surface the underlying OS error; got {:?}",
            msg
        );
    }

    /// Regression guard for issue #1465: confirm the source no longer
    /// substring-matches "not found" / "No such file" against grype's
    /// stderr. The misleading classification this guarded against silently
    /// turned every registry-mode 404 (a manifest the registry rejected,
    /// auth failure, etc.) into "Grype binary not available", which is the
    /// exact user-facing symptom on #1465. If a future refactor reintroduces
    /// the heuristic this test catches it at the source level.
    #[test]
    fn test_run_grype_target_does_not_substring_match_stderr_for_binary_check() {
        let src = include_str!("grype_scanner.rs");
        // Locate the run_grype_target function body and inspect only it,
        // so the regression-guard fixture (which intentionally mentions the
        // forbidden phrases below in comments and string literals) does
        // not produce a false positive against the tests module.
        let start = src
            .find("async fn run_grype_target")
            .expect("run_grype_target must exist");
        let after = &src[start..];
        // Function body ends at the next top-level `}` at column 4 in this
        // file. Slice up to the next blank-line + `/// ` doc boundary or
        // function start, whichever comes first; covers the body cheaply.
        let end_rel = after.find("\n    /// ").unwrap_or(after.len().min(8192));
        let body = &after[..end_rel];
        assert!(
            !body.contains("stderr.contains(\"not found\")")
                && !body.contains("stderr.contains(\"No such file\")"),
            "run_grype_target must not substring-match stderr to detect a missing \
             binary (#1465). Use io::ErrorKind::NotFound on the spawn result \
             via classify_grype_spawn_error instead. Offending body: {}",
            body
        );
    }

    #[test]
    fn test_grype_report_deserialization() {
        let json = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2021-44228",
                    "severity": "Critical",
                    "description": "Log4Shell",
                    "fix": {
                        "versions": ["2.17.0"],
                        "state": "fixed"
                    },
                    "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
                },
                "artifact": {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "type": "java-archive"
                }
            }]
        }"#;

        let report: GrypeReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].vulnerability.id, "CVE-2021-44228");
        assert_eq!(report.matches[0].artifact.name, "log4j-core");
    }

    /// `version()` exercises the TTL-backed cached `grype --version` probe.
    /// As with the Trivy version test, we accept either Some or None
    /// depending on whether `grype` is installed on the test host: we only
    /// require that repeated calls return the same value (cache fidelity)
    /// and that any returned token starts with `grype-`.
    #[tokio::test]
    async fn test_version_is_cached_and_deterministic() {
        let scanner = GrypeScanner::new("/tmp/grype-version-cov-test".to_string());
        let v1 = scanner.version().await;
        let v2 = scanner.version().await;
        assert_eq!(v1, v2, "VersionCache must return identical value on repeat");
        if let Some(v) = v1 {
            assert!(
                v.starts_with("grype-"),
                "grype version probe must be normalized to 'grype-<ver>'; got {}",
                v
            );
        }
    }

    /// Drop-restore path when `AK_GRYPE_REGISTRY_HOST` was already set
    /// before the guard ran. The previous tests only exercise the `None`
    /// arm because EnvGuard::new() removes the var before snapshotting; this
    /// test pre-sets the var so the captured snapshot is `Some(...)` and
    /// the guard's Drop must restore it on the `Some(v)` branch. Regression
    /// guard against an EnvGuard refactor that silently lost prior values
    /// and broke env isolation for tests further down the file.
    #[test]
    fn test_env_guard_restores_preexisting_grype_registry_host() {
        let lock = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("AK_GRYPE_REGISTRY_HOST", "pre-existing.example.com:5000");
        std::env::remove_var("PEER_PUBLIC_ENDPOINT");

        let mut guard = EnvGuard::with_lock(lock);
        // Inside the guard, the snapshotted var has been removed.
        assert!(std::env::var("AK_GRYPE_REGISTRY_HOST").is_err());
        // Mutate it to confirm the guard's restore replaces our value.
        std::env::set_var("AK_GRYPE_REGISTRY_HOST", "scratch.example.com");
        guard.restore_snapshot();

        assert_eq!(
            std::env::var("AK_GRYPE_REGISTRY_HOST").unwrap(),
            "pre-existing.example.com:5000",
            "EnvGuard Drop must restore the original AK_GRYPE_REGISTRY_HOST \
             value when it was set before the guard captured it"
        );

        // Clean up so we do not leak into the rest of the process.
        guard.grype_host = None;
    }

    /// Symmetric test for the second Some-arm in EnvGuard::drop (the
    /// PEER_PUBLIC_ENDPOINT half). Without exercising both arms the
    /// guard's restore behavior is only half-tested.
    #[test]
    fn test_env_guard_restores_preexisting_peer_public_endpoint() {
        let lock = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("PEER_PUBLIC_ENDPOINT", "http://orig.peer.local:8080/");
        std::env::remove_var("AK_GRYPE_REGISTRY_HOST");

        let mut guard = EnvGuard::with_lock(lock);
        assert!(std::env::var("PEER_PUBLIC_ENDPOINT").is_err());
        std::env::set_var("PEER_PUBLIC_ENDPOINT", "https://scratch.local");
        guard.restore_snapshot();

        assert_eq!(
            std::env::var("PEER_PUBLIC_ENDPOINT").unwrap(),
            "http://orig.peer.local:8080/",
            "EnvGuard Drop must restore the original PEER_PUBLIC_ENDPOINT"
        );

        guard.peer_endpoint = None;
    }

    // -----------------------------------------------------------------------
    // truncate_stream: stderr/stdout payload framing in subprocess error
    // messages. Regression guard for the diagnostic-improvement half of the
    // #1001-followup fix (PR linked to #1002 / commit 23d9743). Without
    // these, an `AppError::Internal` carrying multi-megabyte grype log
    // output could blow up downstream consumers that interpolate the error
    // into a JSON field (audit log, scan_results.error_message column).
    // -----------------------------------------------------------------------

    #[test]
    fn test_truncate_stream_returns_input_when_under_limit() {
        let s = "short message";
        assert_eq!(truncate_stream(s, 4096), "short message");
    }

    #[test]
    fn test_truncate_stream_preserves_tail_when_over_limit() {
        // 100 'a's followed by a distinctive ending. With max=10, only the
        // tail should be kept (the failure reason is the last thing logged).
        let s = format!("{}END", "a".repeat(100));
        let out = truncate_stream(&s, 10);
        assert!(
            out.ends_with("END"),
            "tail must be preserved so the actual failure line survives; got {:?}",
            out
        );
        assert!(
            out.starts_with("…[truncated]"),
            "truncation marker must be present: {:?}",
            out
        );
    }

    #[test]
    fn test_truncate_stream_handles_multibyte_split() {
        // A multibyte UTF-8 char (Greek capital alpha, 2 bytes) repeated
        // enough to force a truncation point in the middle of one. The
        // function must not panic and must produce valid UTF-8.
        let s: String = "\u{0391}".repeat(20); // 40 bytes
        let out = truncate_stream(&s, 15);
        // Result must be valid UTF-8 (String type guarantees this) and the
        // boundary walk must have advanced past any partial multibyte.
        assert!(
            out.is_char_boundary(0) && out.is_char_boundary(out.len()),
            "truncate_stream must not split inside a UTF-8 multibyte sequence"
        );
        assert!(out.contains("[truncated]"));
    }

    /// The fix removes `-q` from the grype invocation so DB-fetch / DB-load
    /// failures surface in stderr. Verifying the *exact* arg vector is the
    /// most direct regression guard against a future refactor that
    /// reintroduces `-q` and silences the next #1001-class failure.
    ///
    /// This test reads the source file rather than instrumenting the
    /// subprocess invocation because `run_grype_target` is private to the
    /// module and the only externally visible behavior here is the args we
    /// pass. Reading the source is acceptable for a single-line invariant.
    #[test]
    fn test_grype_invocation_does_not_pass_quiet_flag() {
        let src = include_str!("grype_scanner.rs");
        // Find the args() line for the grype subprocess. There is exactly
        // one in this module (run_grype_target).
        let args_line = src
            .lines()
            .find(|l| l.contains(".args([target, \"-o\", \"json\""))
            .expect(
                "run_grype_target must invoke grype with .args([target, \"-o\", \"json\", ...]); \
                 the arg-vector shape changed and this test needs updating",
            );
        assert!(
            !args_line.contains("\"-q\"") && !args_line.contains("\"--quiet\""),
            "Grype must be invoked WITHOUT -q / --quiet so DB-load and \
             DB-refresh failures appear in stderr. See artifact-keeper#1001 \
             and the followup that traced 'Grype scan failed (exit status: \
             1): ' with an empty stderr slot back to this flag. Offending \
             line: {}",
            args_line
        );
    }

    /// Regression guard for the env-var defaults applied to the grype
    /// subprocess. The Dockerfile sets these too, but a Helm chart or k8s
    /// deployment that *replaces* the container env (rather than appending)
    /// would lose the Dockerfile values. Pinning them at the `Command`
    /// level keeps the scanner working under either deployment shape.
    #[test]
    fn test_grype_invocation_pins_db_auto_update_env_vars() {
        let src = include_str!("grype_scanner.rs");

        for (var, why) in [
            (
                "GRYPE_DB_AUTO_UPDATE",
                "would let Grype refetch the DB and fail in egress-restricted envs (#1001)",
            ),
            (
                "GRYPE_DB_VALIDATE_AGE",
                "would let Grype reject the seeded DB once it ages past 5 days (#1001 followup)",
            ),
            (
                "GRYPE_CHECK_FOR_APP_UPDATE",
                "would let Grype phone home for self-updates and add a network dependency",
            ),
        ] {
            assert!(
                src.contains(&format!(".env(\"{}\", \"false\")", var)),
                "run_grype_target must pin {}=\"false\" at the subprocess level; \
                 removing it {}",
                var,
                why
            );
        }
    }

    // -----------------------------------------------------------------------
    // #1273: convert_packages produces a scan_packages inventory row for
    // every artifact Grype matched a CVE on, so SBOM generation surfaces the
    // vulnerable component even when Trivy's filesystem inventory missed it
    // (transitive node_module deeper than Trivy walked, ecosystem with no
    // Trivy parser, etc.). The original behaviour was `ScanOutput::findings_
    // only` which left `packages` empty and made the SBOM read path return
    // Trivy's incomplete list with no fallback for the Grype side.
    // -----------------------------------------------------------------------

    /// Regression test for #1273. A Grype match on a package not enumerated
    /// by Trivy must surface as a `scan_packages` inventory row so the SBOM
    /// `components` list includes the vulnerable component. Pre-fix, the
    /// returned packages Vec was unconditionally empty.
    #[test]
    fn test_convert_packages_emits_inventory_for_each_match() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "CVE-2021-44228".to_string(),
                    severity: "Critical".to_string(),
                    description: None,
                    fix: None,
                    urls: None,
                },
                artifact: GrypeArtifact {
                    name: "log4j-core".to_string(),
                    version: "2.14.1".to_string(),
                    artifact_type: Some("java-archive".to_string()),
                    purl: None,
                    licenses: None,
                },
                related_vulnerabilities: vec![],
            }],
        };

        let packages = GrypeScanner::convert_packages(&report);
        assert_eq!(
            packages.len(),
            1,
            "one match must produce one inventory row"
        );
        assert_eq!(packages[0].name, "log4j-core");
        assert_eq!(packages[0].version.as_deref(), Some("2.14.1"));
        assert_eq!(
            packages[0].purl.as_deref(),
            Some("pkg:maven/log4j-core@2.14.1"),
            "java-archive grype type must synthesize a pkg:maven/... PURL"
        );
        assert_eq!(
            packages[0].source_target.as_deref(),
            Some("java-archive"),
            "Grype's artifact.type belongs in source_target so the SBOM \
             writer can surface ecosystem context without smuggling it into \
             the bare name (mirrors the #1311 contract)"
        );
    }

    /// Multiple CVEs on the same (name, version) must collapse to a single
    /// inventory row. Grype emits one match per CVE, so without dedup a
    /// package with 5 CVEs would produce 5 identical scan_packages rows and
    /// the DB's `scan_packages_unique_per_scan` index would reject 4 of them
    /// (counting as inventory failures in the metrics layer).
    #[test]
    fn test_convert_packages_dedupes_by_name_and_version() {
        let mk_match = |cve: &str| GrypeMatch {
            vulnerability: GrypeVulnerability {
                id: cve.to_string(),
                severity: "High".to_string(),
                description: None,
                fix: None,
                urls: None,
            },
            artifact: GrypeArtifact {
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
                artifact_type: Some("npm".to_string()),
                purl: None,
                licenses: None,
            },
            related_vulnerabilities: vec![],
        };
        let report = GrypeReport {
            matches: vec![
                mk_match("CVE-2021-23337"),
                mk_match("CVE-2020-28500"),
                mk_match("CVE-2021-23337"), // exact duplicate, also dedup'd
            ],
        };

        let packages = GrypeScanner::convert_packages(&report);
        assert_eq!(
            packages.len(),
            1,
            "three matches on (lodash, 4.17.20) must collapse to one inventory row"
        );
        assert_eq!(packages[0].purl.as_deref(), Some("pkg:npm/lodash@4.17.20"));
    }

    /// Grype v0.50+ emits `artifact.purl` directly. Prefer it over the
    /// synthesized form because Grype's normalization handles edge cases a
    /// from-scratch builder would miss (namespaced npm scopes, Maven
    /// group/artifact split, Go module path encoding).
    #[test]
    fn test_convert_packages_prefers_native_grype_purl() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "CVE-2024-0001".to_string(),
                    severity: "Medium".to_string(),
                    description: None,
                    fix: None,
                    urls: None,
                },
                artifact: GrypeArtifact {
                    name: "@types/node".to_string(),
                    version: "20.0.0".to_string(),
                    artifact_type: Some("npm".to_string()),
                    purl: Some("pkg:npm/%40types/node@20.0.0".to_string()),
                    licenses: None,
                },
                related_vulnerabilities: vec![],
            }],
        };

        let packages = GrypeScanner::convert_packages(&report);
        assert_eq!(packages.len(), 1);
        assert_eq!(
            packages[0].purl.as_deref(),
            Some("pkg:npm/%40types/node@20.0.0"),
            "Grype's emitted PURL must be preferred over the synthesized form \
             so namespaced npm scopes survive the round-trip"
        );
    }

    /// Empty name rows are dropped (data-quality filter mirroring the Trivy
    /// path's `filter(|p| !p.name.is_empty())`).
    #[test]
    fn test_convert_packages_drops_empty_name() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "CVE-2024-0002".to_string(),
                    severity: "Low".to_string(),
                    description: None,
                    fix: None,
                    urls: None,
                },
                artifact: GrypeArtifact {
                    name: "".to_string(),
                    version: "1.0.0".to_string(),
                    artifact_type: Some("npm".to_string()),
                    purl: None,
                    licenses: None,
                },
                related_vulnerabilities: vec![],
            }],
        };
        assert!(GrypeScanner::convert_packages(&report).is_empty());
    }

    /// Unknown Grype types yield `None` for the PURL field rather than a
    /// `pkg:generic/...` string. A bogus PURL is worse than a missing one
    /// because downstream attestation tooling will reject the whole SBOM,
    /// whereas a missing PURL just drops the field on that one row.
    #[test]
    fn test_convert_packages_unknown_type_drops_purl_keeps_row() {
        let report = GrypeReport {
            matches: vec![GrypeMatch {
                vulnerability: GrypeVulnerability {
                    id: "CVE-2024-0003".to_string(),
                    severity: "Medium".to_string(),
                    description: None,
                    fix: None,
                    urls: None,
                },
                artifact: GrypeArtifact {
                    name: "esoteric-pkg".to_string(),
                    version: "1.2.3".to_string(),
                    artifact_type: Some("not-a-known-grype-type".to_string()),
                    purl: None,
                    licenses: None,
                },
                related_vulnerabilities: vec![],
            }],
        };
        let packages = GrypeScanner::convert_packages(&report);
        assert_eq!(packages.len(), 1, "unknown type must keep the row");
        assert!(
            packages[0].purl.is_none(),
            "unknown grype type must drop the PURL field rather than fabricate one"
        );
        assert_eq!(packages[0].name, "esoteric-pkg");
        assert_eq!(packages[0].version.as_deref(), Some("1.2.3"));
    }

    /// Empty matches list yields an empty packages Vec — preserves the
    /// pre-#1273 behaviour for clean artifacts, with the SBOM read path
    /// falling through to Trivy's inventory exactly as before.
    #[test]
    fn test_convert_packages_empty_report() {
        let report = GrypeReport { matches: vec![] };
        assert!(GrypeScanner::convert_packages(&report).is_empty());
    }

    /// Coverage for `grype_type_to_purl_type` token-by-token. The set is
    /// stable per Syft's `pkg.Type` enum and any change here will surface
    /// in this test as a code-review checkpoint.
    #[test]
    fn test_grype_type_to_purl_type_known_mappings() {
        for (grype_type, expected_purl_type) in [
            ("npm", "npm"),
            ("python", "pypi"),
            ("gem", "gem"),
            ("java-archive", "maven"),
            ("go-module", "golang"),
            ("rust-crate", "cargo"),
            ("apk", "apk"),
            ("deb", "deb"),
            ("rpm", "rpm"),
            ("dotnet", "nuget"),
            ("php-composer", "composer"),
        ] {
            assert_eq!(
                grype_type_to_purl_type(grype_type),
                Some(expected_purl_type),
                "grype type '{}' must map to purl type '{}'",
                grype_type,
                expected_purl_type
            );
        }
        assert_eq!(
            grype_type_to_purl_type("totally-fake-type"),
            None,
            "unknown grype types must return None so the caller drops the PURL"
        );
    }

    /// Grype JSON containing both an `artifact.purl` and a `licenses` block
    /// must round-trip through serde into the new fields. Pins the wire
    /// format we care about so a Grype upgrade that renames either field is
    /// caught by tests rather than at runtime when the SBOM inventory
    /// silently loses license/PURL coverage.
    #[test]
    fn test_grype_report_deserializes_purl_and_licenses() {
        let json = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "severity": "High"
                },
                "artifact": {
                    "name": "openssl",
                    "version": "3.0.0",
                    "type": "deb",
                    "purl": "pkg:deb/debian/openssl@3.0.0",
                    "licenses": [
                        {"value": "Apache-2.0", "spdxExpression": "Apache-2.0", "type": "declared"}
                    ]
                }
            }]
        }"#;

        let report: GrypeReport = serde_json::from_str(json).expect("must parse");
        let artifact = &report.matches[0].artifact;
        assert_eq!(
            artifact.purl.as_deref(),
            Some("pkg:deb/debian/openssl@3.0.0")
        );
        let licenses = artifact.licenses.as_ref().expect("licenses must parse");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].value.as_deref(), Some("Apache-2.0"));
        assert_eq!(licenses[0].spdx_expression.as_deref(), Some("Apache-2.0"));

        let packages = GrypeScanner::convert_packages(&report);
        assert_eq!(packages.len(), 1);
        assert_eq!(
            packages[0].purl.as_deref(),
            Some("pkg:deb/debian/openssl@3.0.0")
        );
        assert_eq!(
            packages[0].license.as_deref(),
            Some("Apache-2.0"),
            "valid SPDX licenses must pass through the sanitizer unchanged"
        );
    }

    /// Regression: Grype emits `artifact.licenses` entries as either an object
    /// or a bare string (an SPDX id or a URL). The struct-only deserialize
    /// aborted the whole report parse on the first string-shaped license
    /// (`invalid type: string "...", expected struct GrypeLicense`), turning a
    /// successful scan into a hard failure. The string below is the literal
    /// value `grype log4j-core-2.14.1.jar -o json` (v0.114.0) produced. Both
    /// shapes — and a mix of the two in one array — must parse.
    #[test]
    fn test_grype_license_accepts_bare_string_and_object() {
        let json = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-0001",
                    "severity": "High"
                },
                "artifact": {
                    "name": "libfoo",
                    "version": "1.0.0",
                    "type": "deb",
                    "licenses": [
                        "https://www.apache.org/licenses/LICENSE-2.0.txt",
                        {"value": "MIT", "spdxExpression": "MIT", "type": "declared"}
                    ]
                }
            }]
        }"#;

        // On `main` this `from_str` fails with `invalid type: string "..."`.
        let report: GrypeReport = serde_json::from_str(json).expect("must parse");
        let licenses = report.matches[0]
            .artifact
            .licenses
            .as_ref()
            .expect("licenses must parse");
        assert_eq!(licenses.len(), 2);

        // Bare string -> value only, no SPDX expression.
        assert_eq!(
            licenses[0].value.as_deref(),
            Some("https://www.apache.org/licenses/LICENSE-2.0.txt")
        );
        assert_eq!(licenses[0].spdx_expression.as_deref(), None);

        // Object form -> both fields preserved.
        assert_eq!(licenses[1].value.as_deref(), Some("MIT"));
        assert_eq!(licenses[1].spdx_expression.as_deref(), Some("MIT"));
    }
}
