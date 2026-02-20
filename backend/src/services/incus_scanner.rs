//! Incus/LXC container image vulnerability scanner.
//!
//! Extracts rootfs contents from Incus images (unified tarballs, squashfs)
//! and scans them with `trivy filesystem` to discover OS-level package
//! vulnerabilities (e.g. .deb packages in Ubuntu LXC containers).
//!
//! Supports:
//!   - Unified tarballs (.tar.xz / .tar.gz) containing rootfs + metadata
//!   - Split metadata tarballs (metadata.tar.xz) — skipped (no rootfs)
//!   - SquashFS rootfs images — extracted with `unsquashfs`
//!   - QCOW2/IMG VM disk images — skipped (requires mounting)

use async_trait::async_trait;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::formats::incus::{IncusFileType, IncusHandler};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::image_scanner::TrivyReport;
use crate::services::scanner_service::Scanner;

/// Write content to a temporary file in the workspace, returning an error with the given label.
async fn write_temp_file(path: &Path, content: &Bytes, label: &str) -> Result<()> {
    tokio::fs::write(path, content)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write {} to workspace: {}", label, e)))
}

/// Run an external command, returning an error with the given label on failure.
async fn run_command(program: &str, args: &[&str], label: &str) -> Result<()> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to execute {}: {}", program, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!("{} failed: {}", label, stderr)));
    }

    Ok(())
}

/// Run a Trivy filesystem scan, optionally in server mode. The `label` is used in error messages.
async fn run_trivy_scan(
    rootfs: &Path,
    server_url: Option<&str>,
    label: &str,
) -> Result<TrivyReport> {
    let rootfs_str = rootfs.to_string_lossy();
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
        "10m",
        &rootfs_str,
    ]);

    let output = tokio::process::Command::new("trivy")
        .args(&args)
        .output()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to execute Trivy CLI: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!(
            "{} failed (exit {}): {}",
            label, output.status, stderr
        )));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))
}

/// Vulnerability scanner for Incus/LXC container images.
///
/// Extracts the filesystem contents from container images and runs
/// `trivy filesystem` to find OS package vulnerabilities.
pub struct IncusScanner {
    trivy_url: String,
    scan_workspace: String,
}

impl IncusScanner {
    pub fn new(trivy_url: String, scan_workspace: String) -> Self {
        Self {
            trivy_url,
            scan_workspace,
        }
    }

    /// Check if this scanner is applicable to the given artifact.
    pub fn is_applicable(artifact: &Artifact) -> bool {
        let path = &artifact.path;
        // Only scan Incus image files (not SimpleStreams index files)
        IncusHandler::parse_path(path)
            .map(|info| {
                matches!(
                    info.file_type,
                    IncusFileType::UnifiedTarball
                        | IncusFileType::RootfsSquashfs
                        | IncusFileType::RootfsQcow2
                )
            })
            .unwrap_or(false)
    }

    /// Build the workspace directory path for a given artifact.
    fn workspace_dir(&self, artifact: &Artifact) -> PathBuf {
        Path::new(&self.scan_workspace).join(format!("incus-{}", artifact.id))
    }

    /// Prepare the scan workspace by extracting rootfs from the image.
    async fn prepare_workspace(&self, artifact: &Artifact, content: &Bytes) -> Result<PathBuf> {
        let workspace = self.workspace_dir(artifact);
        let rootfs_dir = workspace.join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create scan workspace: {}", e)))?;

        let info = IncusHandler::parse_path(&artifact.path)
            .map_err(|e| AppError::Internal(format!("Invalid Incus path: {}", e)))?;

        match info.file_type {
            IncusFileType::UnifiedTarball => {
                self.extract_tarball(content, &rootfs_dir).await?;
            }
            IncusFileType::RootfsSquashfs => {
                self.extract_squashfs(content, &workspace, &rootfs_dir)
                    .await?;
            }
            IncusFileType::RootfsQcow2 => {
                // QCOW2/IMG disk images require mounting — not feasible in a scanner context.
                // Return empty workspace; scan will produce no findings.
                warn!(
                    "Skipping QCOW2/IMG scan for {} — disk images cannot be extracted without mounting",
                    artifact.name
                );
                return Err(AppError::Internal(
                    "QCOW2 disk images are not scannable without mounting".to_string(),
                ));
            }
            _ => {
                return Err(AppError::Internal(format!(
                    "Unsupported Incus file type for scanning: {}",
                    info.file_type.as_str()
                )));
            }
        }

        Ok(rootfs_dir)
    }

    /// Extract a unified tarball (tar.xz or tar.gz) into the rootfs directory.
    async fn extract_tarball(&self, content: &Bytes, dest: &Path) -> Result<()> {
        let tarball_path = dest.parent().unwrap_or(dest).join("image.tar.xz");
        write_temp_file(&tarball_path, content, "tarball").await?;

        // Detect compression: XZ magic bytes (0xFD 0x37 0x7A 0x58 0x5A)
        let is_xz = content.len() >= 5 && content[..5] == [0xFD, 0x37, 0x7A, 0x58, 0x5A];
        let decompress_flag = if is_xz { "xJf" } else { "xzf" };

        run_command(
            "tar",
            &[
                decompress_flag,
                &tarball_path.to_string_lossy(),
                "-C",
                &dest.to_string_lossy(),
            ],
            "tar extraction",
        )
        .await?;

        let _ = tokio::fs::remove_file(&tarball_path).await;
        Ok(())
    }

    /// Extract a squashfs image using unsquashfs.
    async fn extract_squashfs(&self, content: &Bytes, workspace: &Path, dest: &Path) -> Result<()> {
        let squashfs_path = workspace.join("rootfs.squashfs");
        write_temp_file(&squashfs_path, content, "squashfs").await?;

        run_command(
            "unsquashfs",
            &[
                "-f",
                "-d",
                &dest.to_string_lossy(),
                &squashfs_path.to_string_lossy(),
            ],
            "unsquashfs extraction",
        )
        .await?;

        let _ = tokio::fs::remove_file(&squashfs_path).await;
        Ok(())
    }

    /// Clean up the scan workspace directory.
    async fn cleanup_workspace(&self, artifact: &Artifact) {
        let workspace = self.workspace_dir(artifact);
        if let Err(e) = tokio::fs::remove_dir_all(&workspace).await {
            warn!(
                "Failed to clean up Incus scan workspace {}: {}",
                workspace.display(),
                e
            );
        }
    }

    /// Run Trivy filesystem scan on the extracted rootfs.
    async fn scan_with_cli(&self, rootfs: &Path) -> Result<TrivyReport> {
        run_trivy_scan(rootfs, Some(&self.trivy_url), "Trivy Incus scan").await
    }

    /// Fallback: scan using Trivy standalone CLI (no server).
    async fn scan_standalone(&self, rootfs: &Path) -> Result<TrivyReport> {
        run_trivy_scan(rootfs, None, "Trivy standalone Incus scan").await
    }

    /// Convert Trivy report into RawFinding values.
    fn convert_findings(report: &TrivyReport) -> Vec<RawFinding> {
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
                        severity: Severity::from_str_loose(&vuln.severity)
                            .unwrap_or(Severity::Info),
                        title: vuln.title.clone().unwrap_or_else(|| {
                            format!("{} in {}", vuln.vulnerability_id, vuln.pkg_name)
                        }),
                        description: vuln.description.clone(),
                        cve_id: Some(vuln.vulnerability_id.clone()),
                        affected_component: Some(format!("{} ({})", vuln.pkg_name, result.target)),
                        affected_version: Some(vuln.installed_version.clone()),
                        fixed_version: vuln.fixed_version.clone(),
                        source: Some("trivy-incus".to_string()),
                        source_url: vuln.primary_url.clone(),
                    })
            })
            .collect()
    }
}

#[async_trait]
impl Scanner for IncusScanner {
    fn name(&self) -> &str {
        "incus-image"
    }

    fn scan_type(&self) -> &str {
        "incus"
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

        if content.is_empty() {
            return Ok(vec![]);
        }

        info!(
            "Starting Incus image scan for artifact: {} ({})",
            artifact.name, artifact.id
        );

        // Prepare workspace: extract rootfs from the image
        let rootfs = match self.prepare_workspace(artifact, content).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "Failed to extract Incus image {}: {}. Skipping scan.",
                    artifact.name, e
                );
                self.cleanup_workspace(artifact).await;
                return Ok(vec![]);
            }
        };

        // Run Trivy filesystem scan on the extracted rootfs
        let report = match self.scan_with_cli(&rootfs).await {
            Ok(report) => report,
            Err(e) => {
                warn!(
                    "Trivy server-mode scan failed for Incus image {}: {}. Trying standalone.",
                    artifact.name, e
                );
                match self.scan_standalone(&rootfs).await {
                    Ok(report) => report,
                    Err(e) => {
                        warn!(
                            "Trivy Incus scan failed for {}: {}. Returning empty findings.",
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
            "Incus image scan complete for {}: {} vulnerabilities found",
            artifact.name,
            findings.len()
        );

        self.cleanup_workspace(artifact).await;

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_incus_artifact(name: &str, path: &str) -> Artifact {
        Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            name: name.to_string(),
            version: Some("20240215".to_string()),
            size_bytes: 100_000_000,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/octet-stream".to_string(),
            storage_key: "test".to_string(),
            is_deleted: false,
            uploaded_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_is_applicable_unified_tarball() {
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_squashfs() {
        let artifact =
            make_incus_artifact("rootfs.squashfs", "debian-bookworm/v1.0/rootfs.squashfs");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_qcow2() {
        let artifact = make_incus_artifact("rootfs.img", "ubuntu-noble/20240215/rootfs.img");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_metadata_only() {
        let artifact =
            make_incus_artifact("metadata.tar.xz", "ubuntu-noble/20240215/metadata.tar.xz");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_streams_index() {
        let artifact = make_incus_artifact("index.json", "streams/v1/index.json");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_non_incus_path() {
        // Path with only one segment is not a valid Incus path (needs product/version/file)
        let artifact = make_incus_artifact("package.tar.gz", "package.tar.gz");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_convert_findings_empty() {
        let report = TrivyReport { results: vec![] };
        let findings = IncusScanner::convert_findings(&report);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_convert_findings_with_vulnerabilities() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "usr/lib/dpkg/status".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "ubuntu".to_string(),
                vulnerabilities: Some(vec![
                    crate::services::image_scanner::TrivyVulnerability {
                        vulnerability_id: "CVE-2024-12345".to_string(),
                        pkg_name: "libssl3".to_string(),
                        installed_version: "3.0.13-0ubuntu3".to_string(),
                        fixed_version: Some("3.0.13-0ubuntu3.1".to_string()),
                        severity: "HIGH".to_string(),
                        title: Some("Buffer overflow in OpenSSL".to_string()),
                        description: Some("A buffer overflow vulnerability exists".to_string()),
                        primary_url: Some("https://avd.aquasec.com/nvd/cve-2024-12345".to_string()),
                    },
                    crate::services::image_scanner::TrivyVulnerability {
                        vulnerability_id: "CVE-2024-67890".to_string(),
                        pkg_name: "libc6".to_string(),
                        installed_version: "2.39-0ubuntu8".to_string(),
                        fixed_version: None,
                        severity: "MEDIUM".to_string(),
                        title: None,
                        description: None,
                        primary_url: None,
                    },
                ]),
            }],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings.len(), 2);

        // First finding
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cve_id, Some("CVE-2024-12345".to_string()));
        assert_eq!(findings[0].title, "Buffer overflow in OpenSSL".to_string());
        assert_eq!(findings[0].source, Some("trivy-incus".to_string()));
        assert!(findings[0]
            .affected_component
            .as_ref()
            .unwrap()
            .contains("libssl3"));
        assert_eq!(
            findings[0].fixed_version,
            Some("3.0.13-0ubuntu3.1".to_string())
        );

        // Second finding (no title → auto-generated)
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[1].title, "CVE-2024-67890 in libc6");
        assert!(findings[1].fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // write_temp_file tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_write_temp_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_file.bin");
        let content = Bytes::from_static(b"hello world");

        write_temp_file(&path, &content, "test").await.unwrap();

        let read_back = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read_back, b"hello world");
    }

    #[tokio::test]
    async fn test_write_temp_file_empty_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        let content = Bytes::new();

        write_temp_file(&path, &content, "empty").await.unwrap();

        let read_back = tokio::fs::read(&path).await.unwrap();
        assert!(read_back.is_empty());
    }

    #[tokio::test]
    async fn test_write_temp_file_invalid_path() {
        // Writing to a path under a nonexistent directory should fail
        let path = PathBuf::from("/nonexistent_dir_abc123/test_file.bin");
        let content = Bytes::from_static(b"data");

        let result = write_temp_file(&path, &content, "bad path").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Failed to write bad path"));
    }

    // -----------------------------------------------------------------------
    // run_command tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_run_command_success() {
        // `true` always exits 0
        run_command("true", &[], "true command").await.unwrap();
    }

    #[tokio::test]
    async fn test_run_command_failure_nonzero_exit() {
        // `false` always exits 1
        let result = run_command("false", &[], "false command").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("false command failed"));
    }

    #[tokio::test]
    async fn test_run_command_nonexistent_program() {
        let result = run_command("nonexistent_program_xyz_12345", &[], "missing program").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Failed to execute nonexistent_program_xyz_12345"));
    }

    #[tokio::test]
    async fn test_run_command_with_args() {
        // `echo hello` should succeed
        run_command("echo", &["hello"], "echo test").await.unwrap();
    }

    // -----------------------------------------------------------------------
    // IncusScanner::new and basic accessors
    // -----------------------------------------------------------------------

    #[test]
    fn test_scanner_new() {
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            "/tmp/scan-workspace".to_string(),
        );
        assert_eq!(scanner.trivy_url, "http://trivy:8090");
        assert_eq!(scanner.scan_workspace, "/tmp/scan-workspace");
    }

    #[test]
    fn test_scanner_name() {
        let scanner = IncusScanner::new("http://trivy:8090".to_string(), "/tmp".to_string());
        assert_eq!(scanner.name(), "incus-image");
    }

    #[test]
    fn test_scanner_scan_type() {
        let scanner = IncusScanner::new("http://trivy:8090".to_string(), "/tmp".to_string());
        assert_eq!(scanner.scan_type(), "incus");
    }

    // -----------------------------------------------------------------------
    // workspace_dir tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_workspace_dir() {
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            "/var/scan-workspace".to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");
        let dir = scanner.workspace_dir(&artifact);
        let expected = format!("/var/scan-workspace/incus-{}", artifact.id);
        assert_eq!(dir, PathBuf::from(expected));
    }

    // -----------------------------------------------------------------------
    // is_applicable: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_applicable_lxd_tarball() {
        let artifact = make_incus_artifact("lxd.tar.xz", "ubuntu-noble/20240215/lxd.tar.xz");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_custom_tarball_name() {
        // Any .tar.xz file under product/version/ is treated as a unified tarball
        let artifact = make_incus_artifact(
            "custom-image.tar.xz",
            "alpine-edge/v3.20/custom-image.tar.xz",
        );
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_tar_gz() {
        let artifact = make_incus_artifact("image.tar.gz", "debian-trixie/v1.0/image.tar.gz");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_qcow2_extension() {
        let artifact = make_incus_artifact("rootfs.qcow2", "fedora-40/v1.0/rootfs.qcow2");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_streams_images() {
        let artifact = make_incus_artifact("images.json", "streams/v1/images.json");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_leading_slash_in_path() {
        // parse_path trims leading slashes, so this should still work
        let artifact = make_incus_artifact("incus.tar.xz", "/ubuntu-noble/20240215/incus.tar.xz");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_meta_tar_xz() {
        let artifact = make_incus_artifact("meta.tar.xz", "ubuntu-noble/20240215/meta.tar.xz");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    // -----------------------------------------------------------------------
    // convert_findings: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_convert_findings_no_vulnerabilities_field() {
        // When vulnerabilities is None, the result should produce no findings
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "usr/lib/dpkg/status".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "ubuntu".to_string(),
                vulnerabilities: None,
            }],
        };
        let findings = IncusScanner::convert_findings(&report);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_convert_findings_empty_vulnerabilities_vec() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "some/target".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "gomod".to_string(),
                vulnerabilities: Some(vec![]),
            }],
        };
        let findings = IncusScanner::convert_findings(&report);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_convert_findings_multiple_results() {
        let report = TrivyReport {
            results: vec![
                crate::services::image_scanner::TrivyResult {
                    target: "dpkg/status".to_string(),
                    class: "os-pkgs".to_string(),
                    result_type: "ubuntu".to_string(),
                    vulnerabilities: Some(vec![
                        crate::services::image_scanner::TrivyVulnerability {
                            vulnerability_id: "CVE-2024-00001".to_string(),
                            pkg_name: "openssl".to_string(),
                            installed_version: "1.0.0".to_string(),
                            fixed_version: Some("1.0.1".to_string()),
                            severity: "CRITICAL".to_string(),
                            title: Some("Critical vuln".to_string()),
                            description: Some("Desc".to_string()),
                            primary_url: None,
                        },
                    ]),
                },
                crate::services::image_scanner::TrivyResult {
                    target: "go.sum".to_string(),
                    class: "lang-pkgs".to_string(),
                    result_type: "gomod".to_string(),
                    vulnerabilities: Some(vec![
                        crate::services::image_scanner::TrivyVulnerability {
                            vulnerability_id: "CVE-2024-00002".to_string(),
                            pkg_name: "github.com/example/lib".to_string(),
                            installed_version: "0.5.0".to_string(),
                            fixed_version: None,
                            severity: "LOW".to_string(),
                            title: None,
                            description: None,
                            primary_url: None,
                        },
                    ]),
                },
            ],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings.len(), 2);

        // First from os-pkgs result
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cve_id, Some("CVE-2024-00001".to_string()));
        assert_eq!(
            findings[0].affected_component,
            Some("openssl (dpkg/status)".to_string())
        );
        assert_eq!(findings[0].fixed_version, Some("1.0.1".to_string()));

        // Second from gomod result
        assert_eq!(findings[1].severity, Severity::Low);
        assert_eq!(
            findings[1].title,
            "CVE-2024-00002 in github.com/example/lib"
        );
        assert_eq!(
            findings[1].affected_component,
            Some("github.com/example/lib (go.sum)".to_string())
        );
        assert!(findings[1].fixed_version.is_none());
        assert!(findings[1].description.is_none());
        assert!(findings[1].source_url.is_none());
    }

    #[test]
    fn test_convert_findings_all_severity_levels() {
        let make_vuln = |id: &str, sev: &str| crate::services::image_scanner::TrivyVulnerability {
            vulnerability_id: id.to_string(),
            pkg_name: "pkg".to_string(),
            installed_version: "1.0".to_string(),
            fixed_version: None,
            severity: sev.to_string(),
            title: None,
            description: None,
            primary_url: None,
        };

        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "test".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "debian".to_string(),
                vulnerabilities: Some(vec![
                    make_vuln("CVE-1", "CRITICAL"),
                    make_vuln("CVE-2", "HIGH"),
                    make_vuln("CVE-3", "MEDIUM"),
                    make_vuln("CVE-4", "LOW"),
                    make_vuln("CVE-5", "UNKNOWN"),
                ]),
            }],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings.len(), 5);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].severity, Severity::Medium);
        assert_eq!(findings[3].severity, Severity::Low);
        // Unknown severity falls back to Info
        assert_eq!(findings[4].severity, Severity::Info);
    }

    #[test]
    fn test_convert_findings_preserves_source_url() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "test".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: Some(vec![crate::services::image_scanner::TrivyVulnerability {
                    vulnerability_id: "CVE-2024-99999".to_string(),
                    pkg_name: "musl".to_string(),
                    installed_version: "1.2.4".to_string(),
                    fixed_version: Some("1.2.5".to_string()),
                    severity: "HIGH".to_string(),
                    title: Some("musl overflow".to_string()),
                    description: Some("Heap overflow in musl libc".to_string()),
                    primary_url: Some("https://avd.aquasec.com/nvd/cve-2024-99999".to_string()),
                }]),
            }],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].source_url,
            Some("https://avd.aquasec.com/nvd/cve-2024-99999".to_string())
        );
        assert_eq!(
            findings[0].description,
            Some("Heap overflow in musl libc".to_string())
        );
        assert_eq!(findings[0].affected_version, Some("1.2.4".to_string()));
    }

    #[test]
    fn test_convert_findings_source_always_trivy_incus() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "t".to_string(),
                class: "".to_string(),
                result_type: "".to_string(),
                vulnerabilities: Some(vec![crate::services::image_scanner::TrivyVulnerability {
                    vulnerability_id: "CVE-X".to_string(),
                    pkg_name: "p".to_string(),
                    installed_version: "1".to_string(),
                    fixed_version: None,
                    severity: "LOW".to_string(),
                    title: None,
                    description: None,
                    primary_url: None,
                }]),
            }],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings[0].source, Some("trivy-incus".to_string()));
    }

    // -----------------------------------------------------------------------
    // scan method: non-applicable artifact and empty content
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_scan_returns_empty_for_non_applicable_artifact() {
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            "/tmp/test-workspace".to_string(),
        );
        // streams/v1/index.json is not applicable
        let artifact = make_incus_artifact("index.json", "streams/v1/index.json");
        let content = Bytes::from_static(b"{}");

        let findings = scanner.scan(&artifact, None, &content).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_scan_returns_empty_for_empty_content() {
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            "/tmp/test-workspace".to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");
        let content = Bytes::new();

        let findings = scanner.scan(&artifact, None, &content).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_scan_returns_empty_for_metadata_only() {
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            "/tmp/test-workspace".to_string(),
        );
        let artifact =
            make_incus_artifact("metadata.tar.xz", "ubuntu-noble/20240215/metadata.tar.xz");
        let content = Bytes::from_static(b"some content");

        let findings = scanner.scan(&artifact, None, &content).await.unwrap();
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // prepare_workspace: QCOW2 returns error (unscannable)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_prepare_workspace_qcow2_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("rootfs.img", "ubuntu-noble/20240215/rootfs.img");
        let content = Bytes::from_static(b"fake qcow2 data");

        let result = scanner.prepare_workspace(&artifact, &content).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("QCOW2"));
    }

    // -----------------------------------------------------------------------
    // prepare_workspace: invalid path yields error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_prepare_workspace_invalid_path() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        // Single-segment path cannot be parsed by IncusHandler::parse_path
        let mut artifact = make_incus_artifact("bad.bin", "bad.bin");
        // Force path to something that fails parse_path but passes is_applicable check
        // Actually parse_path will fail, so prepare_workspace will error
        artifact.path = "single_segment".to_string();

        let content = Bytes::from_static(b"data");
        let result = scanner.prepare_workspace(&artifact, &content).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid Incus path"));
    }

    // -----------------------------------------------------------------------
    // scan gracefully handles prepare_workspace failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_scan_qcow2_returns_empty_findings() {
        // QCOW2 artifacts are applicable but prepare_workspace fails,
        // so scan should return empty findings gracefully.
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("rootfs.img", "ubuntu-noble/20240215/rootfs.img");
        let content = Bytes::from_static(b"fake qcow2 data");

        let findings = scanner.scan(&artifact, None, &content).await.unwrap();
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // extract_tarball: XZ magic bytes detection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extract_tarball_detects_xz_magic() {
        // We cannot produce a valid tar.xz in tests easily, but we can verify
        // the function correctly identifies XZ format via magic bytes and fails
        // gracefully on invalid content.
        let dir = tempfile::tempdir().unwrap();
        let rootfs_dir = dir.path().join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.unwrap();

        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        // XZ magic bytes: 0xFD 0x37 0x7A 0x58 0x5A followed by invalid data
        let mut xz_content = vec![0xFD, 0x37, 0x7A, 0x58, 0x5A];
        xz_content.extend_from_slice(b"not-valid-xz-data");
        let content = Bytes::from(xz_content);

        let result = scanner.extract_tarball(&content, &rootfs_dir).await;
        // Should fail during tar extraction (invalid xz data), not during write
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("tar extraction failed"));
    }

    #[tokio::test]
    async fn test_extract_tarball_detects_gzip_fallback() {
        // Content without XZ magic bytes should be treated as gzip
        let dir = tempfile::tempdir().unwrap();
        let rootfs_dir = dir.path().join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.unwrap();

        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        // Gzip magic: 1F 8B, but followed by garbage
        let content = Bytes::from_static(&[0x1F, 0x8B, 0x08, 0x00, 0x00]);

        let result = scanner.extract_tarball(&content, &rootfs_dir).await;
        // Should fail during tar extraction (invalid gzip)
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("tar extraction failed"));
    }

    // -----------------------------------------------------------------------
    // extract_squashfs: nonexistent unsquashfs binary
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extract_squashfs_writes_file_then_runs_unsquashfs() {
        // This test verifies that the squashfs path is written correctly.
        // unsquashfs is likely not available in CI, so we expect either
        // a "not found" error or a "failed" error from unsquashfs.
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let rootfs_dir = workspace.join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.unwrap();

        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        let content = Bytes::from_static(b"not-a-real-squashfs");
        let result = scanner
            .extract_squashfs(&content, &workspace, &rootfs_dir)
            .await;

        // Should fail (unsquashfs either not found or fails on bad data)
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // cleanup_workspace
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cleanup_workspace_removes_directory() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");

        // Create the workspace dir
        let workspace = scanner.workspace_dir(&artifact);
        tokio::fs::create_dir_all(&workspace).await.unwrap();
        assert!(workspace.exists());

        scanner.cleanup_workspace(&artifact).await;
        assert!(!workspace.exists());
    }

    #[tokio::test]
    async fn test_cleanup_workspace_nonexistent_dir_is_harmless() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");

        // Workspace doesn't exist, cleanup should not panic
        scanner.cleanup_workspace(&artifact).await;
    }

    // -----------------------------------------------------------------------
    // TrivyReport deserialization from JSON
    // -----------------------------------------------------------------------

    #[test]
    fn test_trivy_report_deserialization_full() {
        let json = r#"{
            "Results": [
                {
                    "Target": "usr/lib/dpkg/status",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-11111",
                            "PkgName": "zlib",
                            "InstalledVersion": "1.2.13",
                            "FixedVersion": "1.2.14",
                            "Severity": "HIGH",
                            "Title": "zlib vuln",
                            "Description": "A vuln in zlib",
                            "PrimaryURL": "https://example.com/cve"
                        }
                    ]
                }
            ]
        }"#;

        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].target, "usr/lib/dpkg/status");
        let vulns = report.results[0].vulnerabilities.as_ref().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].vulnerability_id, "CVE-2024-11111");
        assert_eq!(vulns[0].pkg_name, "zlib");
        assert_eq!(vulns[0].severity, "HIGH");
    }

    #[test]
    fn test_trivy_report_deserialization_empty_results() {
        let json = r#"{"Results": []}"#;
        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert!(report.results.is_empty());
    }

    #[test]
    fn test_trivy_report_deserialization_missing_results() {
        // "Results" field is missing entirely; defaults to empty vec
        let json = r#"{}"#;
        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert!(report.results.is_empty());
    }

    #[test]
    fn test_trivy_report_deserialization_no_vulnerabilities() {
        let json = r#"{
            "Results": [
                {
                    "Target": "Gemfile.lock",
                    "Class": "lang-pkgs",
                    "Type": "bundler"
                }
            ]
        }"#;
        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].vulnerabilities.is_none());
    }
}
