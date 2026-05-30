use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::services::scanner_service::{
    cached_trivy_cli_version, ScanOutput, Scanner, VersionCache,
};

#[cfg(test)]
use crate::models::security::RawFinding;
#[cfg(test)]
use crate::services::scanner_service::convert_trivy_findings;

// Trivy JSON report structures
#[derive(Debug, Deserialize)]
pub struct TrivyReport {
    #[serde(rename = "Results", default)]
    pub results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
pub struct TrivyResult {
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "Class", default)]
    pub class: String,
    #[serde(rename = "Type", default)]
    pub result_type: String,
    #[serde(rename = "Vulnerabilities", default)]
    pub vulnerabilities: Option<Vec<TrivyVulnerability>>,
    /// Populated when Trivy is invoked with `--list-all-pkgs`. Lists every
    /// package the scanner enumerated for this target, including ones with
    /// no known vulnerabilities, so SBOM generation (#903) can reflect the
    /// full dependency tree rather than only the CVE-bearing subset.
    #[serde(rename = "Packages", default)]
    pub packages: Option<Vec<TrivyPackage>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pub pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    pub installed_version: String,
    #[serde(rename = "FixedVersion")]
    pub fixed_version: Option<String>,
    #[serde(rename = "Severity")]
    pub severity: String,
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "PrimaryURL")]
    pub primary_url: Option<String>,
}

/// A package entry from a Trivy `Packages` block. Only fields used by
/// inventory persistence are deserialized; everything else (DependsOn,
/// SrcVersion, Layer, etc.) is dropped silently via the default
/// `deny_unknown_fields` policy being absent.
#[derive(Debug, Clone, Deserialize)]
pub struct TrivyPackage {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Version", default)]
    pub version: String,
    /// Trivy emits `Licenses` as an array of strings. Multi-license packages
    /// produce multiple entries; persistence joins them with `" OR "` per
    /// CycloneDX convention.
    #[serde(rename = "Licenses", default)]
    pub licenses: Option<Vec<String>>,
    #[serde(rename = "Identifier", default)]
    pub identifier: Option<TrivyPackageIdentifier>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrivyPackageIdentifier {
    #[serde(rename = "PURL", default)]
    pub purl: Option<String>,
}

/// Container image scanner that delegates to a Trivy server instance.
pub struct ImageScanner {
    trivy_url: String,
    http: reqwest::Client,
    /// Lazily-probed version string from `trivy --version`, e.g.
    /// `trivy-0.62.1`. Successful probes are cached for an hour so each scan
    /// does not pay an extra subprocess; failed probes expire after 60s so
    /// the field starts populating once the binary becomes available.
    cached_version: VersionCache,
}

impl ImageScanner {
    pub fn new(trivy_url: String) -> Self {
        Self {
            trivy_url,
            http: crate::services::http_client::base_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .unwrap_or_default(),
            cached_version: VersionCache::new(),
        }
    }

    /// Check if this artifact is an OCI/Docker image manifest. Thin wrapper
    /// around the shared [`crate::services::scanner_service::is_oci_image_artifact`]
    /// helper so the predicate has one source of truth.
    fn is_container_image(artifact: &Artifact) -> bool {
        crate::services::scanner_service::is_oci_image_artifact(artifact)
    }

    /// Extract an image reference from the artifact path.
    /// OCI paths look like: v2/<name>/manifests/<reference>. Parsing is
    /// shared with `GrypeScanner::build_registry_image_ref` via
    /// `parse_oci_manifest_path` so both scanners agree on what counts as
    /// a well-formed image artifact (#1160). The name and reference are
    /// joined via `join_oci_image_ref`, which uses `@` for digest refs and
    /// `:` for tags per the OCI distribution spec (#1483). Using `:` for
    /// digest refs produces a string the Trivy CLI rejects with
    /// "could not parse reference".
    fn extract_image_ref(artifact: &Artifact) -> Option<String> {
        let (name, reference) =
            crate::services::scanner_service::parse_oci_manifest_path(&artifact.path)?;
        Some(crate::services::scanner_service::join_oci_image_ref(
            name, reference,
        ))
    }

    /// Number of `/healthz` attempts before declaring the Trivy server down.
    /// Three attempts with backoff covers a 30-60s pod restart without
    /// permanently failing in-flight scans, which would otherwise flag the
    /// underlying artifacts. See issue #888.
    const HEALTH_CHECK_ATTEMPTS: u32 = 3;
    /// Per-attempt timeout for `/healthz`. Independent of the 300s scan
    /// timeout so a NetworkPolicy-blocked or hung Trivy does not tie up a
    /// worker for five minutes per scan.
    const HEALTH_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    /// Backoff between health-check attempts. Short on purpose: the goal is
    /// to absorb a pod-restart blip, not to wait out a sustained outage.
    const HEALTH_CHECK_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

    /// Check if the Trivy server is available.
    ///
    /// Returns `Ok(())` when `/healthz` responds 2xx. On failure, retries
    /// `HEALTH_CHECK_ATTEMPTS` times with `HEALTH_CHECK_BACKOFF` between
    /// attempts before surfacing an `AppError::BadGateway` so the scan
    /// orchestrator can mark the scan FAILED with a descriptive message
    /// rather than silently completing with zero findings (issue #888).
    ///
    /// Each attempt has its own `HEALTH_CHECK_TIMEOUT` so a hung Trivy does
    /// not block a worker for the full 300s scan timeout.
    async fn check_trivy_health(&self) -> Result<()> {
        let url = format!("{}/healthz", self.trivy_url);
        let mut last_err: Option<AppError> = None;

        for attempt in 1..=Self::HEALTH_CHECK_ATTEMPTS {
            let result = self
                .http
                .get(&url)
                .timeout(Self::HEALTH_CHECK_TIMEOUT)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    let msg = format!(
                        "Trivy server at {} is unhealthy: HTTP {}",
                        self.trivy_url,
                        resp.status()
                    );
                    crate::services::metrics_service::record_scanner_health_check_failure(
                        "trivy",
                        "unhealthy",
                    );
                    warn!("Trivy /healthz attempt {} failed: {}", attempt, msg);
                    last_err = Some(AppError::BadGateway(msg));
                }
                Err(e) => {
                    let msg = format!("Trivy server at {} is unreachable: {}", self.trivy_url, e);
                    crate::services::metrics_service::record_scanner_health_check_failure(
                        "trivy",
                        "unreachable",
                    );
                    warn!("Trivy /healthz attempt {} failed: {}", attempt, msg);
                    last_err = Some(AppError::BadGateway(msg));
                }
            }

            if attempt < Self::HEALTH_CHECK_ATTEMPTS {
                tokio::time::sleep(Self::HEALTH_CHECK_BACKOFF).await;
            }
        }

        Err(last_err.unwrap_or_else(|| {
            AppError::BadGateway(format!(
                "Trivy server at {} health check failed",
                self.trivy_url
            ))
        }))
    }

    /// Scan an image reference using the Trivy CLI with server mode.
    async fn scan_with_trivy(&self, image_ref: &str) -> Result<TrivyReport> {
        // Use tokio::process to call trivy CLI with server mode
        let output = tokio::process::Command::new("trivy")
            .args([
                "image",
                "--server",
                &self.trivy_url,
                "--format",
                "json",
                // #903: enumerate the full package inventory, not just
                // CVE-bearing rows. Adds the `Packages` block to the
                // JSON report which `convert_trivy_packages` consumes.
                "--list-all-pkgs",
                "--quiet",
                "--timeout",
                "5m",
                image_ref,
            ])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Trivy: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // If trivy is not installed, degrade gracefully
            if stderr.contains("not found") || stderr.contains("No such file") {
                warn!("Trivy CLI not available, falling back to HTTP API");
                return self.scan_with_trivy_http(image_ref).await;
            }
            return Err(AppError::Internal(format!(
                "Trivy scan failed (exit {}): {}",
                output.status, stderr
            )));
        }

        serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))
    }

    /// Fallback: scan via Trivy server HTTP API (Twirp).
    async fn scan_with_trivy_http(&self, image_ref: &str) -> Result<TrivyReport> {
        // Trivy server exposes scanning via its REST-like interface
        // POST /twirp/trivy.scanner.v1.Scanner/Scan
        let url = format!("{}/twirp/trivy.scanner.v1.Scanner/Scan", self.trivy_url);

        // `list_all_packages: true` mirrors the `--list-all-pkgs` CLI flag
        // (#903): without it the Twirp endpoint returns no `Packages`
        // block, and any environment that falls through to this HTTP
        // path (ARC runners + demo EC2 without the trivy CLI binary)
        // would silently keep the empty-SBOM bug for image scans.
        let body = serde_json::json!({
            "target": image_ref,
            "artifact_type": "container_image",
            "options": {
                "vuln_type": ["os", "library"],
                "scanners": ["vuln"],
                "list_all_packages": true,
            }
        });

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Trivy HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Trivy server returned {}: {}",
                status, text
            )));
        }

        resp.json::<TrivyReport>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy response: {}", e)))
    }

    /// Convert Trivy vulnerabilities into RawFinding rows. Thin wrapper
    /// around the shared [`convert_trivy_findings`] helper so the existing
    /// tests can call `ImageScanner::convert_findings(report)` as before.
    /// Production code uses `ScanOutput::from_trivy_report` instead, which
    /// also extracts the package inventory (#903).
    #[cfg(test)]
    pub(crate) fn convert_findings(report: &TrivyReport) -> Vec<RawFinding> {
        convert_trivy_findings(report, "trivy")
    }
}

#[async_trait]
impl Scanner for ImageScanner {
    fn name(&self) -> &str {
        "container-image"
    }

    fn scan_type(&self) -> &str {
        "image"
    }

    /// Surface the container-image content-type check through the trait so
    /// the orchestrator can gate on it without creating a `scan_results`
    /// row for non-image artifacts (issues #961, #994). This is the exact
    /// case that produced the lodash silent-success: a generic tarball
    /// uploaded as `scan_type=image` should never have flowed into
    /// `ImageScanner::scan` at all.
    fn is_applicable(&self, artifact: &Artifact) -> bool {
        Self::is_container_image(artifact)
    }

    /// Probe `trivy --version` once and cache the parsed version string.
    /// Returns `None` if the binary is missing or its output cannot be
    /// parsed.
    async fn version(&self) -> Option<String> {
        cached_trivy_cli_version(&self.cached_version).await
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        _content: &Bytes,
    ) -> Result<ScanOutput> {
        debug_assert!(
            Self::is_container_image(artifact),
            "ImageScanner::scan called on a non-container artifact; the orchestrator must gate on is_applicable first"
        );

        // Image reference extraction can still fail even on an applicable
        // (content-type-matching) artifact when the path is malformed.
        // That is a real error, not a "not applicable" case: surface it as
        // a failed scan so the operator sees error_message rather than a
        // silent completed-with-zero-findings row (issue #994).
        let image_ref = match Self::extract_image_ref(artifact) {
            Some(r) => r,
            None => {
                return Err(AppError::Internal(format!(
                    "Could not extract image reference from artifact path: {}",
                    artifact.path
                )));
            }
        };

        // Check if Trivy server is healthy. If it is not reachable we must
        // surface an error so the scan record is marked FAILED. Returning
        // Ok(vec![]) here would silently mark the scan COMPLETED with zero
        // findings even though no scanning ever happened (issue #888).
        if let Err(e) = self.check_trivy_health().await {
            return Err(AppError::BadGateway(format!(
                "Trivy image scan failed for {}: {}",
                image_ref, e
            )));
        }

        info!("Starting Trivy scan for image: {}", image_ref);

        let report = self.scan_with_trivy(&image_ref).await?;
        // Source label is intentionally "trivy" (not "trivy-image") to
        // preserve back-compat with dashboards / filters that group
        // findings by `source = 'trivy'`. The pre-#903 ImageScanner used
        // the same string. Changing it here would silently drop
        // existing image-scanner rows from any operator filter.
        let output = ScanOutput::from_trivy_report(&report, "trivy");

        info!(
            "Trivy scan complete for {}: {} vulnerabilities, {} packages",
            image_ref,
            output.findings.len(),
            output.packages.len()
        );

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::Severity;

    /// Build an Artifact fixture for scanner tests. Most fields are not
    /// load-bearing for the scanner — the scanner only branches on `path`
    /// and `content_type` — so we collapse the boilerplate here.
    fn make_test_artifact(path: &str, content_type: &str) -> Artifact {
        Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            name: "test".to_string(),
            version: None,
            size_bytes: 1000,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: content_type.to_string(),
            storage_key: "test".to_string(),
            is_deleted: false,
            uploaded_by: None,
            quarantine_status: None,
            quarantine_until: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_is_container_image() {
        let mut artifact = make_test_artifact(
            "v2/myapp/manifests/latest",
            "application/vnd.oci.image.manifest.v1+json",
        );
        assert!(ImageScanner::is_container_image(&artifact));

        artifact.content_type = "application/json".to_string();
        artifact.path = "some/other/path".to_string();
        assert!(!ImageScanner::is_container_image(&artifact));
    }

    #[test]
    fn test_extract_image_ref() {
        let artifact = make_test_artifact(
            "v2/myapp/manifests/v1.0.0",
            "application/vnd.oci.image.manifest.v1+json",
        );
        assert_eq!(
            ImageScanner::extract_image_ref(&artifact),
            Some("myapp:v1.0.0".to_string())
        );
    }

    #[test]
    fn test_extract_image_ref_with_namespace_tag() {
        let artifact = make_test_artifact(
            "v2/org/myapp/manifests/v1.0.0",
            "application/vnd.docker.distribution.manifest.v2+json",
        );
        assert_eq!(
            ImageScanner::extract_image_ref(&artifact),
            Some("org/myapp:v1.0.0".to_string())
        );
    }

    /// Regression test for issue #1483. Digest-pinned manifests must use
    /// the `name@sha256:...` form so the Trivy CLI can parse them. The
    /// previous code emitted `name:sha256:...` which Trivy and Grype reject
    /// with "could not parse reference". A single `docker buildx push`
    /// creates two such digest-referenced manifests (platform manifest +
    /// attestation manifest), so this case is the common case for image
    /// scans, not an edge case.
    #[test]
    fn test_extract_image_ref_digest_uses_at_separator() {
        let artifact = make_test_artifact(
            "v2/org/myapp/manifests/sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b",
            "application/vnd.oci.image.manifest.v1+json",
        );
        assert_eq!(
            ImageScanner::extract_image_ref(&artifact),
            Some(
                "org/myapp@sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_extract_image_ref_invalid_path() {
        let artifact = make_test_artifact("some/random/path", "application/json");
        assert_eq!(ImageScanner::extract_image_ref(&artifact), None);
    }

    #[test]
    fn test_convert_findings() {
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "alpine:3.14 (alpine 3.14.2)".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: Some(vec![
                    TrivyVulnerability {
                        vulnerability_id: "CVE-2021-36159".to_string(),
                        pkg_name: "apk-tools".to_string(),
                        installed_version: "2.12.5-r1".to_string(),
                        fixed_version: Some("2.12.6-r0".to_string()),
                        severity: "CRITICAL".to_string(),
                        title: Some("apk-tools: heap overflow in libfetch".to_string()),
                        description: Some("A vulnerability was found in apk-tools".to_string()),
                        primary_url: Some("https://avd.aquasec.com/nvd/cve-2021-36159".to_string()),
                    },
                    TrivyVulnerability {
                        vulnerability_id: "CVE-2021-3711".to_string(),
                        pkg_name: "libssl1.1".to_string(),
                        installed_version: "1.1.1k-r0".to_string(),
                        fixed_version: Some("1.1.1l-r0".to_string()),
                        severity: "HIGH".to_string(),
                        title: None,
                        description: None,
                        primary_url: None,
                    },
                ]),
                packages: None,
            }],
        };

        let findings = ImageScanner::convert_findings(&report);
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cve_id, Some("CVE-2021-36159".to_string()));
        assert_eq!(findings[0].title, "apk-tools: heap overflow in libfetch");
        assert!(findings[0]
            .affected_component
            .as_ref()
            .unwrap()
            .contains("apk-tools"));
        assert_eq!(findings[0].fixed_version, Some("2.12.6-r0".to_string()));
        assert_eq!(findings[0].source, Some("trivy".to_string()));

        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[1].cve_id, Some("CVE-2021-3711".to_string()));
        assert!(findings[1].title.contains("CVE-2021-3711"));
    }

    #[test]
    fn test_convert_findings_empty() {
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "alpine:3.18".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: None,
                packages: None,
            }],
        };

        let findings = ImageScanner::convert_findings(&report);
        assert_eq!(findings.len(), 0);
    }

    /// Regression test for issue #888: when the Trivy server is
    /// unreachable, `scan` must return Err so the orchestrator marks the
    /// scan FAILED. Returning Ok(vec![]) would silently complete the scan
    /// with zero findings even though Trivy never ran.
    #[tokio::test]
    async fn test_scan_fails_when_trivy_unreachable() {
        // Use an unrouteable port so /healthz cannot succeed. Port 1 is
        // reserved and any client binding to it will get a connection error.
        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let artifact = make_test_artifact(
            "v2/myapp/manifests/latest",
            "application/vnd.oci.image.manifest.v1+json",
        );

        let result = scanner.scan(&artifact, None, &Bytes::new()).await;

        assert!(
            result.is_err(),
            "scan() must return Err when Trivy is unreachable, not Ok(vec![]); \
             a silent Ok(vec![]) is what caused the scan to be marked COMPLETED \
             instead of FAILED in issue #888"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Trivy") && err_msg.contains("myapp:latest"),
            "error must identify the failed scanner and image, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_check_trivy_health_returns_err_on_unreachable() {
        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let result = scanner.check_trivy_health().await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("unreachable") || msg.contains("unhealthy"),
            "error message should describe the health-check failure, got: {}",
            msg
        );
    }

    /// `check_trivy_health` retries before declaring failure so a brief
    /// Trivy pod restart does not hard-fail every concurrent scan. Verified
    /// indirectly by elapsed time: with ATTEMPTS=3 and BACKOFF=500ms there
    /// are two backoff sleeps, so a fully-failed run takes >= ~900ms.
    #[tokio::test]
    async fn test_check_trivy_health_retries_before_failing() {
        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let start = std::time::Instant::now();
        let result = scanner.check_trivy_health().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        let expected_min =
            ImageScanner::HEALTH_CHECK_BACKOFF * (ImageScanner::HEALTH_CHECK_ATTEMPTS - 1);
        assert!(
            elapsed >= expected_min - std::time::Duration::from_millis(100),
            "expected at least {:?} of backoff across {} attempts, got {:?}",
            expected_min,
            ImageScanner::HEALTH_CHECK_ATTEMPTS,
            elapsed
        );
    }

    /// `check_trivy_health` returns BadGateway, not Internal. The
    /// orchestrator does not currently translate AppError to HTTP, but
    /// classifying upstream-scanner failures as 502 keeps internal-error
    /// alerting clean. Pinned because we just changed the variant.
    #[tokio::test]
    async fn test_check_trivy_health_error_is_bad_gateway() {
        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let err = scanner.check_trivy_health().await.unwrap_err();
        assert!(
            matches!(err, AppError::BadGateway(_)),
            "expected BadGateway, got {:?}",
            err
        );
    }

    /// Non-container artifacts must report `is_applicable=false` so the
    /// orchestrator never calls `scan()` on them, rather than the scanner
    /// silently swallowing them inside `scan()` and producing a
    /// completed-with-zero-findings row. This is the trait-level contract
    /// behind the fix for issues #961 and #994.
    ///
    /// `scan()` itself is now allowed to panic on a non-applicable artifact
    /// via `debug_assert!`, because the orchestrator is the single gate
    /// point. Asserting on `is_applicable` here keeps the regression-test
    /// pressure on the right surface.
    #[test]
    fn test_is_applicable_rejects_non_container_artifact() {
        use crate::services::scanner_service::Scanner;

        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let artifact = make_test_artifact("pypi/pkg/1.0.0/pkg-1.0.0.tar.gz", "application/gzip");
        assert!(
            !Scanner::is_applicable(&scanner, &artifact),
            "ImageScanner must yield to a filesystem scanner for non-container artifacts (#961, #994)"
        );
    }

    #[test]
    fn test_trivy_report_deserialization() {
        let json = r#"{
            "Results": [{
                "Target": "alpine:3.14",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-36159",
                    "PkgName": "apk-tools",
                    "InstalledVersion": "2.12.5-r1",
                    "FixedVersion": "2.12.6-r0",
                    "Severity": "CRITICAL",
                    "Title": "heap overflow",
                    "Description": "A vulnerability",
                    "PrimaryURL": "https://example.com"
                }]
            }]
        }"#;

        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].vulnerabilities.as_ref().unwrap().len(), 1);
    }

    /// `version()` covers the TTL-backed cached `trivy --version` probe path
    /// for the container-image scanner. As with the Trivy filesystem
    /// scanner, we tolerate hosts both with and without `trivy` installed:
    /// the assertion is that repeated calls are cached and that any
    /// returned token has the normalized `trivy-` prefix.
    #[tokio::test]
    async fn test_version_is_cached_and_deterministic() {
        let scanner = ImageScanner::new("http://localhost:0".to_string());
        let v1 = scanner.version().await;
        let v2 = scanner.version().await;
        assert_eq!(v1, v2, "VersionCache must return identical value on repeat");
        if let Some(v) = v1 {
            assert!(
                v.starts_with("trivy-"),
                "image scanner version must be normalized 'trivy-<ver>'; got {}",
                v
            );
        }
    }
}
