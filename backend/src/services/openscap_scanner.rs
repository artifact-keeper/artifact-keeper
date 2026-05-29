//! OpenSCAP compliance scanner.
//!
//! Writes artifact content to the shared scan workspace, calls the OpenSCAP
//! HTTP wrapper sidecar to run XCCDF evaluation, and converts results into
//! RawFinding structs.

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Client;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::scanner_service::{
    cached_cli_version, fail_scan, sanitize_artifact_filename, ScanOutput, ScanWorkspace, Scanner,
    VersionCache,
};

/// Response shape from the OpenSCAP wrapper sidecar's `/health` endpoint.
/// Used by `Scanner::version()` to capture the running `oscap` binary
/// version for `scan_results.scanner_version`.
#[derive(Debug, Deserialize)]
struct OpenScapHealth {
    #[serde(default)]
    version: Option<String>,
}

// ---------------------------------------------------------------------------
// OpenSCAP wrapper JSON response structures
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct OpenScapResponse {
    #[serde(default)]
    pub findings: Vec<OpenScapFinding>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OpenScapFinding {
    pub rule_id: String,
    pub result: String,
    pub severity: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

// ---------------------------------------------------------------------------
// Scanner implementation
// ---------------------------------------------------------------------------

pub struct OpenScapScanner {
    http: Client,
    openscap_url: String,
    profile: String,
    scan_workspace: String,
    /// Lazily-probed version string from the wrapper sidecar's `/health`
    /// endpoint, e.g. `openscap-1.4.0`. Successful probes are cached for an
    /// hour; failed probes (sidecar starting up, transient network blip)
    /// expire after 60s so the field starts populating once the sidecar is
    /// reachable.
    cached_version: VersionCache,
}

impl OpenScapScanner {
    pub fn new(openscap_url: String, profile: String, scan_workspace: String) -> Self {
        let http = crate::services::http_client::base_client_builder()
            .timeout(Duration::from_secs(600))
            .build()
            .expect("failed to build HTTP client");

        Self {
            http,
            openscap_url,
            profile,
            scan_workspace,
            cached_version: VersionCache::new(),
        }
    }

    /// Probe the OpenSCAP wrapper's `/health` endpoint to capture the
    /// running `oscap` binary version. Returns `None` on any error so the
    /// scan still completes; the version is metadata, not a scan result.
    async fn probe_version(&self) -> Option<String> {
        let url = format!("{}/health", self.openscap_url);
        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let health: OpenScapHealth = resp.json().await.ok()?;
        let raw = health.version?;
        // `oscap --version` first line is e.g. `OpenSCAP command line tool
        // (oscap) 1.4.0`. Capture just the version token for compactness.
        let token = raw.split_whitespace().last()?.trim();
        if token.is_empty() {
            None
        } else {
            Some(format!("openscap-{}", token))
        }
    }

    /// Returns true if this scanner applies to the given artifact.
    /// OpenSCAP is relevant for container images, RPMs, and DEBs.
    fn is_applicable(artifact: &Artifact) -> bool {
        let ct = artifact.content_type.to_lowercase();
        let name_lower = artifact.name.to_lowercase();
        let path_lower = artifact.path.to_lowercase();

        let is_container = ct.contains("vnd.oci.image")
            || ct.contains("vnd.docker.distribution")
            || ct.contains("vnd.docker.container")
            || path_lower.contains("/manifests/");

        let is_rpm =
            name_lower.ends_with(".rpm") || ct.contains("x-rpm") || path_lower.contains("/rpm/");

        let is_deb =
            name_lower.ends_with(".deb") || ct.contains("debian") || path_lower.contains("/deb/");

        is_container || is_rpm || is_deb
    }

    /// Prepare the scan workspace: create directory and write artifact content.
    /// OpenSCAP does not extract archives (it scans the raw package).
    async fn prepare_workspace(&self, artifact: &Artifact, content: &Bytes) -> Result<PathBuf> {
        let workspace =
            ScanWorkspace::workspace_dir(&self.scan_workspace, Some("openscap"), artifact);
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

        Ok(workspace)
    }

    async fn call_openscap(&self, workspace: &Path) -> Result<OpenScapResponse> {
        let workspace_str = workspace.to_string_lossy().to_string();
        let scan_request = serde_json::json!({
            "path": workspace_str,
            "profile": self.profile,
        });

        let resp = self
            .http
            .post(format!("{}/scan", self.openscap_url))
            .json(&scan_request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("OpenSCAP request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Include the workspace path in the error so operators can match
            // it against the sidecar's OPENSCAP_ALLOWED_SCAN_DIRS allowlist
            // (issue #1466). Without this, debugging the "scan path not
            // found or not allowed" 400 requires turning on wrapper debug
            // logs or guessing which path was sent.
            return Err(AppError::Internal(format!(
                "OpenSCAP scan failed (HTTP {}) for path {}: {}",
                status, workspace_str, body
            )));
        }

        resp.json::<OpenScapResponse>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse OpenSCAP response: {}", e)))
    }

    fn convert_findings(response: &OpenScapResponse) -> Vec<RawFinding> {
        response
            .findings
            .iter()
            .filter(|f| matches!(f.result.as_str(), "fail" | "error" | "unknown"))
            .map(|f| {
                let severity = match f.severity.to_lowercase().as_str() {
                    "high" => Severity::High,
                    "medium" | "moderate" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };

                let source_url = f.references.first().cloned();

                RawFinding {
                    severity,
                    title: f.title.clone(),
                    description: f.description.clone(),
                    cve_id: None,
                    affected_component: Some(f.rule_id.clone()),
                    affected_version: None,
                    fixed_version: None,
                    source: Some("openscap".to_string()),
                    source_url,
                }
            })
            .collect()
    }
}

#[async_trait]
impl Scanner for OpenScapScanner {
    fn name(&self) -> &str {
        "openscap"
    }

    fn scan_type(&self) -> &str {
        "openscap"
    }

    /// Surface the inherent applicability check through the trait so the
    /// orchestrator can gate on it without creating a `scan_results` row
    /// (issues #961, #994).
    fn is_applicable(&self, artifact: &Artifact) -> bool {
        Self::is_applicable(artifact)
    }

    /// Probe the wrapper sidecar's `/health` endpoint once and cache the
    /// `oscap` version string. Returns `None` if the wrapper is unreachable
    /// or its response cannot be parsed.
    async fn version(&self) -> Option<String> {
        cached_cli_version(&self.cached_version, || async {
            self.probe_version().await
        })
        .await
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        debug_assert!(
            Self::is_applicable(artifact),
            "OpenScapScanner::scan called on a non-applicable artifact; the orchestrator must gate on is_applicable first"
        );

        info!(
            "Starting OpenSCAP compliance scan for artifact: {} ({})",
            artifact.name, artifact.id
        );

        let workspace = self.prepare_workspace(artifact, content).await?;

        let response = match self.call_openscap(&workspace).await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(fail_scan(
                    "OpenSCAP scan",
                    artifact,
                    &e,
                    &self.scan_workspace,
                    Some("openscap"),
                )
                .await);
            }
        };

        if let Some(err) = &response.error {
            warn!("OpenSCAP returned error for {}: {}", artifact.name, err);
        }

        let findings = Self::convert_findings(&response);

        info!(
            "OpenSCAP scan complete for {}: {} compliance issues found",
            artifact.name,
            findings.len()
        );

        ScanWorkspace::cleanup(&self.scan_workspace, Some("openscap"), artifact).await;

        // OpenSCAP is a compliance scanner, not an inventory enumerator;
        // packages list intentionally empty.
        Ok(ScanOutput::findings_only(findings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::scanner_service::test_helpers::{assert_scan_failed, make_test_artifact};

    #[test]
    fn test_is_applicable_rpm() {
        let artifact = make_test_artifact(
            "nginx-1.24.0-1.el9.x86_64.rpm",
            "application/x-rpm",
            "rpm/nginx/nginx-1.24.0-1.el9.x86_64.rpm",
        );
        assert!(OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_deb() {
        let artifact = make_test_artifact(
            "nginx_1.24.0-1_amd64.deb",
            "application/vnd.debian.binary-package",
            "deb/nginx/nginx_1.24.0-1_amd64.deb",
        );
        assert!(OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_container() {
        let artifact = make_test_artifact(
            "myapp",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/myapp/manifests/latest",
        );
        assert!(OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_jar() {
        let artifact = make_test_artifact("app.jar", "application/java-archive", "maven/app.jar");
        assert!(!OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_npm() {
        let artifact = make_test_artifact(
            "prelaunch-test-0.1.0.tgz",
            "application/gzip",
            "npm/prelaunch-npm/prelaunch-test/-/prelaunch-test-0.1.0.tgz",
        );
        assert!(!OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_convert_findings() {
        let response = OpenScapResponse {
            findings: vec![
                OpenScapFinding {
                    rule_id: "xccdf_org.ssgproject.content_rule_no_empty_passwords".into(),
                    result: "fail".into(),
                    severity: "high".into(),
                    title: "Prevent Login to Accounts With Empty Password".into(),
                    description: Some("Accounts should not have empty passwords".into()),
                    references: vec!["CCE-27286-2".into()],
                },
                OpenScapFinding {
                    rule_id: "xccdf_org.ssgproject.content_rule_audit_enabled".into(),
                    result: "pass".into(),
                    severity: "medium".into(),
                    title: "Enable auditd Service".into(),
                    description: None,
                    references: vec![],
                },
                OpenScapFinding {
                    rule_id: "xccdf_org.ssgproject.content_rule_sshd_disable_root".into(),
                    result: "error".into(),
                    severity: "medium".into(),
                    title: "Disable SSH Root Login".into(),
                    description: None,
                    references: vec!["CCE-27445-4".into(), "NIST-800-53-IA-2".into()],
                },
            ],
            profile: Some("standard".into()),
            error: None,
        };

        let findings = OpenScapScanner::convert_findings(&response);
        assert_eq!(findings.len(), 2); // only fail + error, not pass
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].source, Some("openscap".to_string()));
        assert_eq!(
            findings[0].affected_component,
            Some("xccdf_org.ssgproject.content_rule_no_empty_passwords".to_string())
        );
        assert_eq!(findings[0].source_url, Some("CCE-27286-2".to_string()));
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    /// When the OpenSCAP sidecar is unreachable, the scanner must return Err
    /// so the orchestrator records the scan as failed. Previously it returned
    /// Ok(vec![]), making the artifact appear clean.
    #[tokio::test]
    async fn test_scan_returns_error_when_sidecar_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = OpenScapScanner::new(
            // Port 0 ensures the connection will be refused
            "http://localhost:0".to_string(),
            "standard".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_test_artifact(
            "nginx-1.24.0-1.el9.x86_64.rpm",
            "application/x-rpm",
            "rpm/nginx/1.24.0/nginx-1.24.0-1.el9.x86_64.rpm",
        );
        let content = bytes::Bytes::from_static(b"fake rootfs tarball");

        let result = scanner.scan(&artifact, None, &content).await;
        assert_scan_failed(&result, "OpenSCAP scan");
    }

    /// Build an `OpenScapScanner` pointing at `url`, using a fresh tempdir
    /// for the scan workspace. The returned `_dir` guard must be kept
    /// in scope for the test's lifetime so the directory is not dropped.
    fn make_probe_scanner(url: String) -> (OpenScapScanner, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let scanner = OpenScapScanner::new(
            url,
            "standard".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        (scanner, dir)
    }

    /// Mount a `GET /health` mock on `server` that responds with `template`,
    /// matching the openscap wrapper sidecar's healthcheck route.
    async fn mount_health_mock(
        server: &wiremock::MockServer,
        template: wiremock::ResponseTemplate,
    ) {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/health"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    /// `probe_version` returns `Some("openscap-<ver>")` when the wrapper's
    /// `/health` endpoint responds 200 with a `version` field shaped like
    /// the real `oscap --version` first line. This is the happy path the
    /// orchestrator relies on for `scan_results.scanner_version`.
    #[tokio::test]
    async fn test_probe_version_success() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(
            &server,
            wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"version": "OpenSCAP command line tool (oscap) 1.4.0"}),
            ),
        )
        .await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        let v = scanner.version().await;
        assert_eq!(v, Some("openscap-1.4.0".to_string()));

        // Second call must hit the cache, not the server. Wiremock would
        // accept additional calls silently, so we instead assert the value
        // is stable across two awaits. The cache populated above must not
        // be re-run.
        let v2 = scanner.version().await;
        assert_eq!(v, v2);
    }

    /// `probe_version` returns `None` when the wrapper responds with a
    /// non-2xx status (e.g. 503 during sidecar startup). The scan must
    /// still proceed; the version field is metadata, not load-bearing.
    #[tokio::test]
    async fn test_probe_version_non_success_status_returns_none() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(&server, wiremock::ResponseTemplate::new(503)).await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        assert_eq!(scanner.version().await, None);
    }

    /// `probe_version` returns `None` when the response body cannot be
    /// parsed as the expected JSON shape. Defensive: a misconfigured
    /// reverse proxy might return HTML.
    #[tokio::test]
    async fn test_probe_version_malformed_body_returns_none() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(
            &server,
            wiremock::ResponseTemplate::new(200)
                .set_body_string("<html>not json</html>")
                .insert_header("content-type", "text/html"),
        )
        .await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        assert_eq!(scanner.version().await, None);
    }

    /// `probe_version` returns `None` when the JSON is well-formed but the
    /// `version` field is absent or null. The wrapper's health response
    /// schema explicitly defaults this field to None.
    #[tokio::test]
    async fn test_probe_version_missing_field_returns_none() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(
            &server,
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
        )
        .await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        assert_eq!(scanner.version().await, None);
    }

    /// `probe_version` returns `None` when the version field is present
    /// but contains only whitespace. The token extraction
    /// (`split_whitespace().last()`) yields nothing, so the function
    /// short-circuits to None instead of producing `openscap-`.
    #[tokio::test]
    async fn test_probe_version_whitespace_only_field_returns_none() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(
            &server,
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"version": "   "})),
        )
        .await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        assert_eq!(scanner.version().await, None);
    }

    /// `probe_version` returns `None` when the URL is unreachable
    /// (connection refused). This exercises the `.send().await.ok()?`
    /// short-circuit. Together with the success/error/missing tests above,
    /// every branch of `probe_version` is covered without requiring a real
    /// OpenSCAP wrapper sidecar.
    #[tokio::test]
    async fn test_probe_version_unreachable_returns_none() {
        // Port 0 is reserved and yields connection refused.
        let (scanner, _dir) = make_probe_scanner("http://127.0.0.1:0".to_string());
        assert_eq!(scanner.version().await, None);
    }

    // -----------------------------------------------------------------------
    // prepare_workspace + call_openscap (issue #1466 regression coverage)
    // -----------------------------------------------------------------------

    /// `prepare_workspace` must place the artifact under a path that begins
    /// with the configured `SCAN_WORKSPACE_PATH` base. The openscap wrapper
    /// sidecar validates incoming paths against an allowlist that, by
    /// default, includes `/scan-workspace/`. If the backend ever produces a
    /// path outside this base, the wrapper rejects with
    /// "scan path not found or not allowed" (issue #1466).
    #[tokio::test]
    async fn test_prepare_workspace_path_is_under_configured_base() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_string_lossy().to_string();
        let scanner = OpenScapScanner::new(
            "http://localhost:0".to_string(),
            "standard".to_string(),
            base.clone(),
        );
        let artifact = make_test_artifact(
            "nginx-1.24.0-1.el9.x86_64.rpm",
            "application/x-rpm",
            "rpm/nginx/1.24.0/nginx-1.24.0-1.el9.x86_64.rpm",
        );
        let workspace = scanner
            .prepare_workspace(&artifact, &bytes::Bytes::from_static(b"fake rpm"))
            .await
            .expect("prepare_workspace must succeed");

        // The workspace must live under the configured base so the sidecar
        // allowlist (which mirrors SCAN_WORKSPACE_PATH) accepts it.
        assert!(
            workspace.starts_with(dir.path()),
            "workspace {:?} must be under base {:?}",
            workspace,
            dir.path()
        );
        // Prefix gives openscap its own subtree, separate from trivy/grype.
        let name = workspace.file_name().and_then(|s| s.to_str()).unwrap();
        assert!(
            name.starts_with("openscap-"),
            "workspace dir name {} must be prefixed with 'openscap-' so concurrent scanners don't collide",
            name
        );
        assert!(workspace.is_dir(), "workspace must exist on disk");
    }

    /// Happy path: when the wrapper sidecar accepts the path and returns
    /// findings, `scan()` converts them into `RawFinding`s and the request
    /// body it sent carries the workspace path (which the wrapper's
    /// `validate_scan_path` matches against `OPENSCAP_ALLOWED_SCAN_DIRS`).
    /// This is the prepare-and-scan flow that breaks in issue #1466.
    #[tokio::test]
    async fn test_scan_happy_path_sends_workspace_path_to_wrapper() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;

        let artifact = make_test_artifact(
            "nginx-1.24.0-1.el9.x86_64.rpm",
            "application/x-rpm",
            "rpm/nginx/1.24.0/nginx-1.24.0-1.el9.x86_64.rpm",
        );
        let expected_workspace = ScanWorkspace::workspace_dir(
            &dir.path().to_string_lossy(),
            Some("openscap"),
            &artifact,
        )
        .to_string_lossy()
        .to_string();
        let expected_body = serde_json::json!({
            "path": expected_workspace,
            "profile": "standard",
        });

        Mock::given(method("POST"))
            .and(path("/scan"))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "findings": [{
                    "rule_id": "xccdf_org.ssgproject.content_rule_no_empty_passwords",
                    "result": "fail",
                    "severity": "high",
                    "title": "Prevent Login to Accounts With Empty Password",
                    "description": "Accounts should not have empty passwords",
                    "references": ["CCE-27286-2"]
                }],
                "profile": "standard"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let scanner = OpenScapScanner::new(
            server.uri(),
            "standard".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        let output = scanner
            .scan(&artifact, None, &bytes::Bytes::from_static(b"fake rpm"))
            .await
            .expect("happy path scan must succeed");

        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.findings[0].severity, Severity::High);
        assert_eq!(output.findings[0].source.as_deref(), Some("openscap"));

        // Verify the wrapper actually received the workspace path we built;
        // wiremock's body_json matcher above gated the 200, but pull the
        // received request explicitly so a regression that changes the
        // request shape produces a useful diff rather than a "no matching
        // request" 404.
        let received: Vec<Request> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.url.path() == "/scan")
            .collect();
        assert_eq!(received.len(), 1, "exactly one /scan request expected");
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(body["path"].as_str(), Some(expected_workspace.as_str()));
        assert_eq!(body["profile"].as_str(), Some("standard"));
    }

    /// When the wrapper rejects the path with HTTP 400 (the exact symptom
    /// in issue #1466), the error returned to the orchestrator must carry
    /// the rejected path so operators can match it against the wrapper's
    /// allowlist without enabling debug logs.
    #[tokio::test]
    async fn test_scan_error_includes_rejected_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/scan"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string("{\"error\": \"scan path not found or not allowed\"}"),
            )
            .mount(&server)
            .await;

        let scanner = OpenScapScanner::new(
            server.uri(),
            "standard".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_test_artifact(
            "nginx-1.24.0-1.el9.x86_64.rpm",
            "application/x-rpm",
            "rpm/nginx/1.24.0/nginx-1.24.0-1.el9.x86_64.rpm",
        );
        let expected_path = ScanWorkspace::workspace_dir(
            &dir.path().to_string_lossy(),
            Some("openscap"),
            &artifact,
        )
        .to_string_lossy()
        .to_string();

        let err = scanner
            .scan(&artifact, None, &bytes::Bytes::from_static(b"fake rpm"))
            .await
            .expect_err("scan must propagate wrapper 400");
        let msg = err.to_string();
        assert!(msg.contains("OpenSCAP scan failed"), "got: {}", msg);
        assert!(
            msg.contains(&expected_path),
            "error must include rejected path {} for operator debugging (issue #1466), got: {}",
            expected_path,
            msg
        );
        assert!(
            msg.contains("scan path not found or not allowed"),
            "wrapper body must be surfaced, got: {}",
            msg
        );
    }
}
