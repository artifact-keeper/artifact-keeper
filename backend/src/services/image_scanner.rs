use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::scanner_service::{capture_cli_version, format_trivy_version, Scanner};

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

/// Container image scanner that delegates to a Trivy server instance.
pub struct ImageScanner {
    trivy_url: String,
    http: reqwest::Client,
    /// Lazily-probed version string from `trivy --version`, e.g.
    /// `trivy-0.62.1`. Cached for the scanner's lifetime so each scan does
    /// not pay an extra subprocess for the version probe.
    cached_version: OnceCell<Option<String>>,
}

impl ImageScanner {
    pub fn new(trivy_url: String) -> Self {
        Self {
            trivy_url,
            http: crate::services::http_client::base_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .unwrap_or_default(),
            cached_version: OnceCell::new(),
        }
    }

    /// Check if this artifact is an OCI/Docker image manifest.
    fn is_container_image(artifact: &Artifact) -> bool {
        let ct = &artifact.content_type;
        ct.contains("vnd.oci.image")
            || ct.contains("vnd.docker.distribution")
            || ct.contains("vnd.docker.container")
            || artifact.path.contains("/manifests/")
    }

    /// Extract an image reference from the artifact path.
    /// OCI paths look like: v2/<name>/manifests/<reference>
    fn extract_image_ref(artifact: &Artifact) -> Option<String> {
        let path = artifact.path.trim_start_matches('/');
        if let Some(rest) = path.strip_prefix("v2/") {
            // v2/<name>/manifests/<ref>
            if let Some(idx) = rest.find("/manifests/") {
                let name = &rest[..idx];
                let reference = &rest[idx + "/manifests/".len()..];
                if !name.is_empty() && !reference.is_empty() {
                    return Some(format!("{}:{}", name, reference));
                }
            }
        }
        None
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

        let body = serde_json::json!({
            "target": image_ref,
            "artifact_type": "container_image",
            "options": {
                "vuln_type": ["os", "library"],
                "scanners": ["vuln"],
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

    /// Convert Trivy vulnerabilities to RawFindings.
    fn convert_findings(report: &TrivyReport) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        for result in &report.results {
            if let Some(ref vulns) = result.vulnerabilities {
                for vuln in vulns {
                    let severity =
                        Severity::from_str_loose(&vuln.severity).unwrap_or(Severity::Info);

                    let title = vuln.title.clone().unwrap_or_else(|| {
                        format!("{} in {}", vuln.vulnerability_id, vuln.pkg_name)
                    });

                    findings.push(RawFinding {
                        severity,
                        title,
                        description: vuln.description.clone(),
                        cve_id: Some(vuln.vulnerability_id.clone()),
                        affected_component: Some(format!("{} ({})", vuln.pkg_name, result.target)),
                        affected_version: Some(vuln.installed_version.clone()),
                        fixed_version: vuln.fixed_version.clone(),
                        source: Some("trivy".to_string()),
                        source_url: vuln.primary_url.clone(),
                    });
                }
            }
        }

        findings
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

    /// Probe `trivy --version` once and cache the parsed version string.
    /// Returns `None` if the binary is missing or its output cannot be
    /// parsed.
    async fn version(&self) -> Option<String> {
        self.cached_version
            .get_or_init(|| async {
                let raw = capture_cli_version("trivy", &["--version"]).await?;
                format_trivy_version(&raw)
            })
            .await
            .clone()
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        _content: &Bytes,
    ) -> Result<Vec<RawFinding>> {
        // Only scan OCI/Docker image manifests
        if !Self::is_container_image(artifact) {
            return Ok(vec![]);
        }

        let image_ref = match Self::extract_image_ref(artifact) {
            Some(r) => r,
            None => {
                info!(
                    "Could not extract image reference from artifact path: {}",
                    artifact.path
                );
                return Ok(vec![]);
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
        let findings = Self::convert_findings(&report);

        info!(
            "Trivy scan complete for {}: {} vulnerabilities found",
            image_ref,
            findings.len()
        );

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_extract_image_ref_with_namespace() {
        let artifact = make_test_artifact(
            "v2/org/myapp/manifests/sha256:abc123",
            "application/vnd.docker.distribution.manifest.v2+json",
        );
        assert_eq!(
            ImageScanner::extract_image_ref(&artifact),
            Some("org/myapp:sha256:abc123".to_string())
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

    /// When the artifact is not a container image, the scanner returns
    /// Ok(vec![]) without ever contacting Trivy. This must remain true
    /// even after the #888 fix — non-applicable artifacts are not failures.
    #[tokio::test]
    async fn test_scan_non_image_returns_ok_empty_without_trivy() {
        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let artifact = make_test_artifact("pypi/pkg/1.0.0/pkg-1.0.0.tar.gz", "application/gzip");
        let result = scanner.scan(&artifact, None, &Bytes::new()).await;
        assert!(
            result.is_ok(),
            "non-container artifacts should not cause the image scanner to error"
        );
        assert!(result.unwrap().is_empty());
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
}
