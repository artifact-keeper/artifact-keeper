//! Trivy filesystem scanner for non-container artifacts.
//!
//! Writes artifact content to a scan workspace directory, optionally extracts
//! archives, and invokes `trivy filesystem` via CLI to discover vulnerabilities.

use async_trait::async_trait;
use bytes::Bytes;
use std::path::Path;
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::RawFinding;
use crate::services::image_scanner::TrivyReport;
use crate::services::scanner_service::{
    cached_trivy_cli_version, convert_trivy_findings, fail_scan, ScanWorkspace, Scanner,
};

/// Filesystem-based Trivy scanner for packages, libraries, and archives.
pub struct TrivyFsScanner {
    trivy_url: String,
    scan_workspace: String,
    /// Lazily-probed version string from `trivy --version`, e.g.
    /// `trivy-0.62.1`. Cached for the scanner's lifetime so each scan does
    /// not pay an extra subprocess for the version probe.
    cached_version: OnceCell<Option<String>>,
}

impl TrivyFsScanner {
    pub fn new(trivy_url: String, scan_workspace: String) -> Self {
        Self {
            trivy_url,
            scan_workspace,
            cached_version: OnceCell::new(),
        }
    }

    /// Returns true if this scanner is applicable to the given artifact.
    /// Container image manifests are handled by `ImageScanner`; everything
    /// else that looks like a scannable package is handled here.
    pub fn is_applicable(artifact: &Artifact) -> bool {
        let ct = &artifact.content_type;
        // Skip OCI / Docker image manifests — those belong to ImageScanner.
        if ct.contains("vnd.oci.image")
            || ct.contains("vnd.docker.distribution")
            || ct.contains("vnd.docker.container")
            || artifact.path.contains("/manifests/")
        {
            return false;
        }

        // Use the original filename from the path for extension detection
        let original_filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.name);
        let name_lower = original_filename.to_lowercase();
        let scannable_extensions = [
            ".tar.gz", ".tgz", ".whl", ".jar", ".war", ".ear", ".gem", ".crate", ".nupkg", ".zip",
            ".deb", ".rpm", ".apk", ".egg", ".pex",
            // Lock files and manifests that Trivy can parse directly
            ".lock", ".toml", ".json", ".xml", ".txt", ".cfg", ".ini",
        ];

        scannable_extensions
            .iter()
            .any(|ext| name_lower.ends_with(ext))
    }

    /// Run Trivy filesystem scan, optionally connecting to a server.
    /// When `server_url` is Some, `--server <url>` is added to the command.
    async fn run_trivy(&self, workspace: &Path, server_url: Option<&str>) -> Result<TrivyReport> {
        let ws = workspace.to_string_lossy();
        let mut args = vec!["filesystem"];
        if let Some(url) = server_url {
            args.push("--server");
            args.push(url);
        }
        args.extend_from_slice(&[
            "--format",
            "json",
            "--severity",
            "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
            "--timeout",
            "5m",
            &ws,
        ]);

        let mode_label = if server_url.is_some() {
            "server"
        } else {
            "standalone"
        };

        let output = tokio::process::Command::new("trivy")
            .args(&args)
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Trivy CLI: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if server_url.is_some()
                && (stderr.contains("not found") || stderr.contains("No such file"))
            {
                return Err(AppError::Internal("Trivy CLI not available".to_string()));
            }
            return Err(AppError::Internal(format!(
                "Trivy {} scan failed (exit {}): {}",
                mode_label, output.status, stderr
            )));
        }

        serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))
    }
}

#[async_trait]
impl Scanner for TrivyFsScanner {
    fn name(&self) -> &str {
        "trivy-filesystem"
    }

    fn scan_type(&self) -> &str {
        "filesystem"
    }

    /// Probe `trivy --version` once and cache the parsed version string.
    /// Returns `None` if the binary is missing or its output cannot be
    /// parsed; `scan_results.scanner_version` is nullable for that case.
    async fn version(&self) -> Option<String> {
        cached_trivy_cli_version(&self.cached_version).await
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
            "Starting Trivy filesystem scan for artifact: {} ({})",
            artifact.name, artifact.id
        );

        let workspace =
            ScanWorkspace::prepare(&self.scan_workspace, None, artifact, content).await?;

        // Try CLI with server mode first, then standalone
        let report = match self.run_trivy(&workspace, Some(&self.trivy_url)).await {
            Ok(report) => report,
            Err(e) => {
                warn!(
                    "Trivy server-mode CLI failed for {}: {}. Trying standalone mode.",
                    artifact.name, e
                );
                match self.run_trivy(&workspace, None).await {
                    Ok(report) => report,
                    Err(e) => {
                        return Err(fail_scan(
                            "Trivy filesystem scan",
                            artifact,
                            &e,
                            &self.scan_workspace,
                            None,
                        )
                        .await);
                    }
                }
            }
        };

        let findings = convert_trivy_findings(&report, "trivy-filesystem");

        info!(
            "Trivy filesystem scan complete for {}: {} vulnerabilities found",
            artifact.name,
            findings.len()
        );

        ScanWorkspace::cleanup(&self.scan_workspace, None, artifact).await;

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::Severity;
    use crate::services::scanner_service::test_helpers::{assert_scan_failed, make_test_artifact};

    #[test]
    fn test_is_applicable() {
        // Scannable archive formats
        let applicable = [
            (
                "my-lib-1.0.0.tar.gz",
                "application/gzip",
                "pypi/my-lib/1.0.0/my-lib-1.0.0.tar.gz",
            ),
            (
                "my_lib-1.0.0-py3-none-any.whl",
                "application/zip",
                "pypi/my-lib/1.0.0/my_lib-1.0.0-py3-none-any.whl",
            ),
            (
                "myapp-1.0.0.jar",
                "application/java-archive",
                "maven/com/example/myapp/1.0.0/myapp-1.0.0.jar",
            ),
            (
                "my-crate-1.0.0.crate",
                "application/gzip",
                "crates/my-crate/1.0.0/my-crate-1.0.0.crate",
            ),
        ];
        for (name, ct, path) in applicable {
            let a = make_test_artifact(name, ct, path);
            assert!(
                TrivyFsScanner::is_applicable(&a),
                "expected applicable: {}",
                name
            );
        }

        // Container manifests are scanned by the image scanner, not trivy-fs
        let not_applicable = [
            (
                "myapp",
                "application/vnd.oci.image.manifest.v1+json",
                "v2/myapp/manifests/latest",
            ),
            (
                "myapp",
                "application/vnd.docker.distribution.manifest.v2+json",
                "v2/myapp/manifests/v1.0.0",
            ),
        ];
        for (name, ct, path) in not_applicable {
            let a = make_test_artifact(name, ct, path);
            assert!(
                !TrivyFsScanner::is_applicable(&a),
                "expected not applicable: {}",
                name
            );
        }
    }

    #[test]
    fn test_convert_findings() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "requirements.txt".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "pip".to_string(),
                vulnerabilities: Some(vec![crate::services::image_scanner::TrivyVulnerability {
                    vulnerability_id: "CVE-2023-12345".to_string(),
                    pkg_name: "requests".to_string(),
                    installed_version: "2.28.0".to_string(),
                    fixed_version: Some("2.31.0".to_string()),
                    severity: "HIGH".to_string(),
                    title: Some("SSRF in requests".to_string()),
                    description: Some("A vulnerability in requests allows SSRF".to_string()),
                    primary_url: Some("https://avd.aquasec.com/nvd/cve-2023-12345".to_string()),
                }]),
            }],
        };

        let findings = convert_trivy_findings(&report, "trivy-filesystem");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cve_id, Some("CVE-2023-12345".to_string()));
        assert_eq!(findings[0].source, Some("trivy-filesystem".to_string()));
        assert!(findings[0]
            .affected_component
            .as_ref()
            .unwrap()
            .contains("requests"));
    }

    /// Scan failures (workspace creation, missing Trivy binary) must
    /// propagate as Err, never as Ok(vec![]).
    #[tokio::test]
    async fn test_scan_propagates_errors() {
        let artifact = make_test_artifact(
            "my-lib-1.0.0.tar.gz",
            "application/gzip",
            "pypi/my-lib/1.0.0/my-lib-1.0.0.tar.gz",
        );
        let content = bytes::Bytes::from_static(b"not a real archive");

        // Impossible workspace path: /dev/null cannot contain subdirectories
        let bad_ws = TrivyFsScanner::new(
            "http://localhost:0".to_string(),
            "/dev/null/impossible-workspace".to_string(),
        );
        assert!(
            bad_ws.scan(&artifact, None, &content).await.is_err(),
            "scan() must return Err when workspace creation fails"
        );

        // Missing trivy binary (skip if trivy is installed)
        if std::process::Command::new("trivy")
            .arg("--version")
            .output()
            .is_ok()
        {
            eprintln!("trivy is installed, skipping unavailable-trivy test");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let no_trivy = TrivyFsScanner::new(
            "http://localhost:0".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        assert_scan_failed(
            &no_trivy.scan(&artifact, None, &content).await,
            "Trivy filesystem scan",
        );
    }

    /// `version()` exercises the OnceCell-cached probe path. We do not
    /// require `trivy` to be installed: the test only asserts the call
    /// returns deterministically (`Some("trivy-...")` when installed,
    /// `None` otherwise) and that subsequent calls return the same value
    /// from cache. The point is to cover the per-scanner override body so
    /// the new-code coverage gate sees these lines as executed.
    #[tokio::test]
    async fn test_version_is_cached_and_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = TrivyFsScanner::new(
            "http://localhost:0".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let v1 = scanner.version().await;
        let v2 = scanner.version().await;
        assert_eq!(v1, v2, "OnceCell must return identical value on repeat");
        if let Some(v) = v1 {
            assert!(
                v.starts_with("trivy-"),
                "trivy version probe must be normalized to 'trivy-<ver>'; got {}",
                v
            );
        }
    }
}
