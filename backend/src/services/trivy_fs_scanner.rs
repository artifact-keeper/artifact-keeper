//! Trivy filesystem scanner for non-container artifacts.
//!
//! Writes artifact content to a scan workspace directory, optionally extracts
//! archives, and invokes `trivy filesystem` via CLI to discover vulnerabilities.

use async_trait::async_trait;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::image_scanner::TrivyReport;
use crate::services::scanner_service::Scanner;

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

    /// Build the workspace directory path for a given artifact.
    fn workspace_dir(&self, artifact: &Artifact) -> PathBuf {
        Path::new(&self.scan_workspace).join(artifact.id.to_string())
    }

    /// Prepare the scan workspace: write artifact content and extract archives.
    async fn prepare_workspace(&self, artifact: &Artifact, content: &Bytes) -> Result<PathBuf> {
        let workspace = self.workspace_dir(artifact);
        tokio::fs::create_dir_all(&workspace)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create scan workspace: {}", e)))?;

        // Use the original filename from the path (last segment) for correct extension detection
        let original_filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.name);
        let artifact_path = workspace.join(original_filename);

        tokio::fs::write(&artifact_path, content)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to write artifact to workspace: {}", e))
            })?;

        // Extract archives into the workspace directory
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

    /// Check if the file is an extractable archive.
    fn is_archive(name: &str) -> bool {
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

    /// Extract an archive file into the given directory using system tools.
    async fn extract_archive(archive_path: &Path, dest: &Path) -> Result<()> {
        let name = archive_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        let output =
            if name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".crate") {
                tokio::process::Command::new("tar")
                    .args([
                        "xzf",
                        &archive_path.to_string_lossy(),
                        "-C",
                        &dest.to_string_lossy(),
                    ])
                    .output()
                    .await
            } else if name.ends_with(".zip")
                || name.ends_with(".whl")
                || name.ends_with(".jar")
                || name.ends_with(".war")
                || name.ends_with(".ear")
                || name.ends_with(".nupkg")
                || name.ends_with(".egg")
            {
                tokio::process::Command::new("unzip")
                    .args([
                        "-o",
                        "-q",
                        &archive_path.to_string_lossy(),
                        "-d",
                        &dest.to_string_lossy(),
                    ])
                    .output()
                    .await
            } else if name.ends_with(".gem") {
                // Ruby gems are tar archives with a data.tar.gz inside
                tokio::process::Command::new("tar")
                    .args([
                        "xf",
                        &archive_path.to_string_lossy(),
                        "-C",
                        &dest.to_string_lossy(),
                    ])
                    .output()
                    .await
            } else {
                return Ok(());
            };

        match output {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(AppError::Internal(format!(
                "Archive extraction failed (exit {}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            ))),
            Err(e) => Err(AppError::Internal(format!(
                "Failed to execute extraction command: {}",
                e
            ))),
        }
    }

    /// Clean up the scan workspace directory.
    async fn cleanup_workspace(&self, artifact: &Artifact) {
        let workspace = self.workspace_dir(artifact);
        if let Err(e) = tokio::fs::remove_dir_all(&workspace).await {
            warn!(
                "Failed to clean up scan workspace {}: {}",
                workspace.display(),
                e
            );
        }
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

    /// Convert Trivy report vulnerabilities into `RawFinding` values.
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
                        source: Some("trivy-filesystem".to_string()),
                        source_url: vuln.primary_url.clone(),
                    });
                }
            }
        }

        findings
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

        // Prepare workspace with artifact content
        let workspace = self.prepare_workspace(artifact, content).await?;

        // Try CLI with server mode first, then standalone, then degrade gracefully
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
                        warn!(
                            "Trivy filesystem scan failed for {}: {}. Returning empty findings.",
                            artifact.name, e
                        );
                        self.cleanup_workspace(artifact).await;
                        return Ok(vec![]);
                    }
                }
            }
        };

        let findings = Self::convert_findings(&report);

        info!(
            "Trivy filesystem scan complete for {}: {} vulnerabilities found",
            artifact.name,
            findings.len()
        );

        // Clean up workspace
        self.cleanup_workspace(artifact).await;

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(TrivyFsScanner::is_archive("foo.tar.gz"));
        assert!(TrivyFsScanner::is_archive("foo.tgz"));
        assert!(TrivyFsScanner::is_archive("foo.whl"));
        assert!(TrivyFsScanner::is_archive("foo.jar"));
        assert!(TrivyFsScanner::is_archive("foo.zip"));
        assert!(TrivyFsScanner::is_archive("foo.gem"));
        assert!(TrivyFsScanner::is_archive("foo.crate"));
        assert!(TrivyFsScanner::is_archive("foo.nupkg"));
        assert!(!TrivyFsScanner::is_archive("Cargo.lock"));
        assert!(!TrivyFsScanner::is_archive("package.json"));
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

        let findings = TrivyFsScanner::convert_findings(&report);
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
}
