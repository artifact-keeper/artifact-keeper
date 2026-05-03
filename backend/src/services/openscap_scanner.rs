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
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::scanner_service::{
    fail_scan, sanitize_artifact_filename, ScanWorkspace, Scanner,
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
    /// endpoint, e.g. `openscap-1.4.0`. Cached for the scanner's lifetime
    /// so we do not GET `/health` on every scan.
    cached_version: OnceCell<Option<String>>,
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
            cached_version: OnceCell::new(),
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
        let scan_request = serde_json::json!({
            "path": workspace.to_string_lossy(),
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
            return Err(AppError::Internal(format!(
                "OpenSCAP scan failed (HTTP {}): {}",
                status, body
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

    /// Probe the wrapper sidecar's `/health` endpoint once and cache the
    /// `oscap` version string. Returns `None` if the wrapper is unreachable
    /// or its response cannot be parsed.
    async fn version(&self) -> Option<String> {
        self.cached_version
            .get_or_init(|| async { self.probe_version().await })
            .await
            .clone()
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<Vec<RawFinding>> {
        if !Self::is_applicable(artifact) {
            return Ok(vec![]);
        }

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

        Ok(findings)
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
}
