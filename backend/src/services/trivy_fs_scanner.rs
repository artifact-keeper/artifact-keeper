//! Trivy filesystem scanner for non-container artifacts.
//!
//! Writes artifact content to a scan workspace directory, optionally extracts
//! archives, and invokes `trivy filesystem` via CLI to discover vulnerabilities.

use async_trait::async_trait;
use bytes::Bytes;
use std::path::Path;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::RawFinding;
use crate::services::image_scanner::TrivyReport;
use crate::services::scanner_service::{convert_trivy_findings, fail_scan, ScanWorkspace, Scanner};

/// Filesystem-based Trivy scanner for packages, libraries, and archives.
pub struct TrivyFsScanner {
    trivy_url: String,
    scan_workspace: String,
}

impl TrivyFsScanner {
    pub fn new(trivy_url: String, scan_workspace: String) -> Self {
        Self {
            trivy_url,
            scan_workspace,
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

    /// Attempt to scan using the Trivy CLI with server mode.
    async fn scan_with_cli(&self, workspace: &Path) -> Result<TrivyReport> {
        let output = tokio::process::Command::new("trivy")
            .args([
                "filesystem",
                "--server",
                &self.trivy_url,
                "--format",
                "json",
                "--severity",
                "CRITICAL,HIGH,MEDIUM,LOW",
                "--quiet",
                "--timeout",
                "5m",
                &workspace.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Trivy CLI: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("No such file") {
                return Err(AppError::Internal("Trivy CLI not available".to_string()));
            }
            return Err(AppError::Internal(format!(
                "Trivy filesystem scan failed (exit {}): {}",
                output.status, stderr
            )));
        }

        serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))
    }

    /// Fallback: scan using Trivy standalone CLI (no server).
    async fn scan_with_standalone_cli(&self, workspace: &Path) -> Result<TrivyReport> {
        let output = tokio::process::Command::new("trivy")
            .args([
                "filesystem",
                "--format",
                "json",
                "--severity",
                "CRITICAL,HIGH,MEDIUM,LOW",
                "--quiet",
                "--timeout",
                "5m",
                &workspace.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Trivy CLI: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Internal(format!(
                "Trivy standalone scan failed (exit {}): {}",
                output.status, stderr
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
        let report = match self.scan_with_cli(&workspace).await {
            Ok(report) => report,
            Err(e) => {
                warn!(
                    "Trivy server-mode CLI failed for {}: {}. Trying standalone mode.",
                    artifact.name, e
                );
                match self.scan_with_standalone_cli(&workspace).await {
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

    fn make_artifact(name: &str, content_type: &str, path: &str) -> Artifact {
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
    fn test_is_applicable_tar_gz() {
        let artifact = make_artifact(
            "my-lib-1.0.0.tar.gz",
            "application/gzip",
            "pypi/my-lib/1.0.0/my-lib-1.0.0.tar.gz",
        );
        assert!(TrivyFsScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_wheel() {
        let artifact = make_artifact(
            "my_lib-1.0.0-py3-none-any.whl",
            "application/zip",
            "pypi/my-lib/1.0.0/my_lib-1.0.0-py3-none-any.whl",
        );
        assert!(TrivyFsScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_jar() {
        let artifact = make_artifact(
            "myapp-1.0.0.jar",
            "application/java-archive",
            "maven/com/example/myapp/1.0.0/myapp-1.0.0.jar",
        );
        assert!(TrivyFsScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_crate() {
        let artifact = make_artifact(
            "my-crate-1.0.0.crate",
            "application/gzip",
            "crates/my-crate/1.0.0/my-crate-1.0.0.crate",
        );
        assert!(TrivyFsScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_oci_manifest() {
        let artifact = make_artifact(
            "myapp",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/myapp/manifests/latest",
        );
        assert!(!TrivyFsScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_docker_manifest() {
        let artifact = make_artifact(
            "myapp",
            "application/vnd.docker.distribution.manifest.v2+json",
            "v2/myapp/manifests/v1.0.0",
        );
        assert!(!TrivyFsScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_archive() {
        assert!(ScanWorkspace::is_archive("foo.tar.gz"));
        assert!(ScanWorkspace::is_archive("foo.tgz"));
        assert!(ScanWorkspace::is_archive("foo.whl"));
        assert!(ScanWorkspace::is_archive("foo.jar"));
        assert!(ScanWorkspace::is_archive("foo.zip"));
        assert!(ScanWorkspace::is_archive("foo.gem"));
        assert!(ScanWorkspace::is_archive("foo.crate"));
        assert!(ScanWorkspace::is_archive("foo.nupkg"));
        assert!(!ScanWorkspace::is_archive("Cargo.lock"));
        assert!(!ScanWorkspace::is_archive("package.json"));
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

    /// When the scan workspace cannot be created, prepare_workspace fails
    /// and the error propagates to the caller. This exercises the error path
    /// that would previously have been swallowed.
    #[tokio::test]
    async fn test_scan_returns_error_when_workspace_creation_fails() {
        // Use a path under /dev/null which cannot contain subdirectories
        let scanner = TrivyFsScanner::new(
            "http://localhost:0".to_string(),
            "/dev/null/impossible-workspace".to_string(),
        );
        let artifact = make_artifact(
            "my-lib-1.0.0.tar.gz",
            "application/gzip",
            "pypi/my-lib/1.0.0/my-lib-1.0.0.tar.gz",
        );
        let content = bytes::Bytes::from_static(b"not a real archive");

        let result = scanner.scan(&artifact, None, &content).await;
        assert!(
            result.is_err(),
            "scan() must return Err when workspace creation fails"
        );
    }

    /// When both Trivy CLI modes fail, the scanner must return Err so the
    /// orchestrator can record a failed scan with an error message, instead
    /// of recording 0 findings and making the artifact appear clean.
    ///
    /// This test is skipped when Trivy is installed, since Trivy can
    /// legitimately scan the raw file and return 0 findings.
    #[tokio::test]
    async fn test_scan_returns_error_when_trivy_unavailable() {
        // If trivy is installed, the scanner will succeed (legitimately), so skip.
        if std::process::Command::new("trivy")
            .arg("--version")
            .output()
            .is_ok()
        {
            eprintln!("trivy is installed, skipping unavailable-trivy test");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let scanner = TrivyFsScanner::new(
            "http://localhost:0".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_artifact(
            "my-lib-1.0.0.tar.gz",
            "application/gzip",
            "pypi/my-lib/1.0.0/my-lib-1.0.0.tar.gz",
        );
        let content = bytes::Bytes::from_static(b"not a real archive");

        let result = scanner.scan(&artifact, None, &content).await;
        assert!(
            result.is_err(),
            "scan() must return Err when trivy execution fails, not Ok(vec![])"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Trivy filesystem scan failed"),
            "error message should indicate trivy failure, got: {}",
            err_msg
        );
    }
}
