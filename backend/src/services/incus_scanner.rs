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
        // Write the tarball to a temp file first
        let tarball_path = dest.parent().unwrap_or(dest).join("image.tar.xz");
        tokio::fs::write(&tarball_path, content)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to write tarball to workspace: {}", e))
            })?;

        // Detect compression: XZ magic bytes (0xFD 0x37 0x7A 0x58 0x5A)
        let is_xz = content.len() >= 5 && content[..5] == [0xFD, 0x37, 0x7A, 0x58, 0x5A];
        let decompress_flag = if is_xz { "xJf" } else { "xzf" };

        let output = tokio::process::Command::new("tar")
            .args([
                decompress_flag,
                &tarball_path.to_string_lossy(),
                "-C",
                &dest.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute tar: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Internal(format!(
                "tar extraction failed: {}",
                stderr
            )));
        }

        // Clean up the tarball file after extraction
        let _ = tokio::fs::remove_file(&tarball_path).await;

        Ok(())
    }

    /// Extract a squashfs image using unsquashfs.
    async fn extract_squashfs(&self, content: &Bytes, workspace: &Path, dest: &Path) -> Result<()> {
        let squashfs_path = workspace.join("rootfs.squashfs");
        tokio::fs::write(&squashfs_path, content)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to write squashfs to workspace: {}", e))
            })?;

        let output = tokio::process::Command::new("unsquashfs")
            .args([
                "-f", // force (overwrite existing)
                "-d", // destination
                &dest.to_string_lossy(),
                &squashfs_path.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute unsquashfs: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Internal(format!(
                "unsquashfs extraction failed: {}",
                stderr
            )));
        }

        // Clean up the squashfs file
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
                "10m", // Larger timeout for container images
                &rootfs.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Trivy CLI: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Internal(format!(
                "Trivy Incus scan failed (exit {}): {}",
                output.status, stderr
            )));
        }

        serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))
    }

    /// Fallback: scan using Trivy standalone CLI (no server).
    async fn scan_standalone(&self, rootfs: &Path) -> Result<TrivyReport> {
        let output = tokio::process::Command::new("trivy")
            .args([
                "filesystem",
                "--format",
                "json",
                "--severity",
                "CRITICAL,HIGH,MEDIUM,LOW",
                "--quiet",
                "--timeout",
                "10m",
                &rootfs.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Trivy CLI: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Internal(format!(
                "Trivy standalone Incus scan failed (exit {}): {}",
                output.status, stderr
            )));
        }

        serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))
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
}
