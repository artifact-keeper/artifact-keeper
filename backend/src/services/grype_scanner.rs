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
use serde::Deserialize;
use std::path::Path;
use tracing::info;

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::scanner_service::{
    cached_cli_version, capture_cli_version, fail_scan, format_grype_version,
    is_oci_image_artifact, parse_oci_manifest_path, ScanOutput, ScanWorkspace, Scanner,
    VersionCache,
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
fn resolve_registry_host() -> String {
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

    /// Build the `<host>/<name>:<reference>` image ref that Grype's
    /// `registry:` mode expects. The host comes from the first non-empty of:
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
        Some(format!(
            "{}/{}:{}",
            resolve_registry_host(),
            name,
            reference
        ))
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
        let output = tokio::process::Command::new("grype")
            .args([target, "-o", "json"])
            .env("GRYPE_DB_AUTO_UPDATE", "false")
            .env("GRYPE_DB_VALIDATE_AGE", "false")
            .env("GRYPE_CHECK_FOR_APP_UPDATE", "false")
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Grype: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("No such file") {
                return Err(AppError::Internal("Grype binary not available".to_string()));
            }
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
    /// string. Grype's JSON does not emit a package inventory block so the
    /// type/target metadata is dropped here rather than persisted alongside
    /// in a `RawPackage` row; the Trivy filesystem scanner that typically
    /// runs alongside provides the inventory side of the contract.
    fn convert_findings(report: &GrypeReport) -> Vec<RawFinding> {
        report
            .matches
            .iter()
            .map(|m| {
                RawFinding {
                    severity: Severity::from_str_loose(&m.vulnerability.severity)
                        .unwrap_or(Severity::Info),
                    title: format!("{} in {}", m.vulnerability.id, m.artifact.name),
                    description: m.vulnerability.description.clone(),
                    cve_id: Some(m.vulnerability.id.clone()),
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
            let target = format!("registry:{}", image_ref);
            info!("Grype OCI registry scan target: {}", target);

            let report = match self.run_grype_target(&target).await {
                Ok(report) => report,
                Err(e) => {
                    return Err(fail_scan(
                        "Grype OCI scan",
                        artifact,
                        &e,
                        &self.scan_workspace,
                        None,
                    )
                    .await);
                }
            };

            let findings = Self::convert_findings(&report);
            info!(
                "Grype OCI scan complete for {}: {} vulnerabilities found",
                artifact.name,
                findings.len()
            );
            return Ok(ScanOutput::findings_only(findings));
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

        info!(
            "Grype scan complete for {}: {} vulnerabilities found",
            artifact.name,
            findings.len()
        );

        ScanWorkspace::cleanup(&self.scan_workspace, None, artifact).await;

        // Grype's default JSON shape does not enumerate non-vulnerable
        // packages; SBOM generation for Grype-scanned artifacts depends on
        // Trivy's filesystem inventory running alongside. Returning an
        // empty packages Vec is correct rather than misleading.
        Ok(ScanOutput::findings_only(findings))
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
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
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
        let r = GrypeScanner::build_registry_image_ref(&a).expect("ref must build");
        assert_eq!(r, "localhost:8080/library/nginx:latest");
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
        let r = GrypeScanner::build_registry_image_ref(&a).expect("ref must build");
        // Scheme stripped, trailing slashes trimmed.
        assert_eq!(r, "registry.example.com:5000/library/redis:7.2");
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
        let r = GrypeScanner::build_registry_image_ref(&a).expect("ref must build");
        assert_eq!(r, "ak.svc.cluster.local:8080/library/alpine:3.19");
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
        let r = GrypeScanner::build_registry_image_ref(&a).expect("ref must build");
        assert!(
            !r.contains("hunter2") && !r.contains("svcuser"),
            "credentials must not appear in the registry image ref: {}",
            r
        );
        assert_eq!(r, "registry.example.com:5000/library/nginx:latest");
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
                GrypeScanner::build_registry_image_ref(&a).is_none(),
                "malformed path '{}' must not produce a registry ref",
                path
            );
        }
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
                },
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
                },
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
                },
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
        // Cannot share ENV_MUTEX with EnvGuard cleanly: take it manually,
        // do the pre-set + create + drop dance, then release.
        let _outer = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("AK_GRYPE_REGISTRY_HOST", "pre-existing.example.com:5000");
        std::env::remove_var("PEER_PUBLIC_ENDPOINT");

        // Drop _outer so EnvGuard::new() can take it.
        drop(_outer);

        {
            let _g = EnvGuard::new();
            // Inside the guard, the snapshotted var has been removed.
            assert!(std::env::var("AK_GRYPE_REGISTRY_HOST").is_err());
            // Mutate it to confirm the guard's restore replaces our value.
            std::env::set_var("AK_GRYPE_REGISTRY_HOST", "scratch.example.com");
            // _g drops here: must restore pre-existing.example.com:5000.
        }

        assert_eq!(
            std::env::var("AK_GRYPE_REGISTRY_HOST").unwrap(),
            "pre-existing.example.com:5000",
            "EnvGuard Drop must restore the original AK_GRYPE_REGISTRY_HOST \
             value when it was set before the guard captured it"
        );

        // Clean up so we do not leak into the rest of the process.
        std::env::remove_var("AK_GRYPE_REGISTRY_HOST");
    }

    /// Symmetric test for the second Some-arm in EnvGuard::drop (the
    /// PEER_PUBLIC_ENDPOINT half). Without exercising both arms the
    /// guard's restore behavior is only half-tested.
    #[test]
    fn test_env_guard_restores_preexisting_peer_public_endpoint() {
        let _outer = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("PEER_PUBLIC_ENDPOINT", "http://orig.peer.local:8080/");
        std::env::remove_var("AK_GRYPE_REGISTRY_HOST");
        drop(_outer);

        {
            let _g = EnvGuard::new();
            assert!(std::env::var("PEER_PUBLIC_ENDPOINT").is_err());
            std::env::set_var("PEER_PUBLIC_ENDPOINT", "https://scratch.local");
        }

        assert_eq!(
            std::env::var("PEER_PUBLIC_ENDPOINT").unwrap(),
            "http://orig.peer.local:8080/",
            "EnvGuard Drop must restore the original PEER_PUBLIC_ENDPOINT"
        );

        std::env::remove_var("PEER_PUBLIC_ENDPOINT");
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
}
