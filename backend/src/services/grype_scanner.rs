//! Grype vulnerability scanner.
//!
//! Writes artifact content to a scan workspace directory, optionally extracts
//! archives, and invokes `grype` via CLI to discover vulnerabilities.

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::scanner_service::Scanner;

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

/// Grype-based vulnerability scanner for packages and archives.
pub struct GrypeScanner {
    scan_workspace: String,
}

impl GrypeScanner {
    pub fn new(scan_workspace: String) -> Self {
        Self { scan_workspace }
    }

    /// Build the workspace directory path for a given artifact.
    fn workspace_dir(&self, artifact: &Artifact) -> PathBuf {
        Path::new(&self.scan_workspace).join(artifact.id.to_string())
    }

    /// Prepare the scan workspace: write artifact content and extract archives.
    async fn prepare_workspace(
        &self,
        artifact: &Artifact,
        content: &Bytes,
    ) -> Result<PathBuf> {
        let workspace = self.workspace_dir(artifact);
        tokio::fs::create_dir_all(&workspace)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create scan workspace: {}", e)))?;

        let artifact_path = workspace.join(&artifact.name);

        tokio::fs::write(&artifact_path, content)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to write artifact to workspace: {}", e))
            })?;

        // Extract archives into the workspace directory
        if Self::is_archive(&artifact.name) {
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

        let output = if name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".crate") {
            tokio::process::Command::new("tar")
                .args(["xzf", &archive_path.to_string_lossy(), "-C", &dest.to_string_lossy()])
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
            tokio::process::Command::new("tar")
                .args(["xf", &archive_path.to_string_lossy(), "-C", &dest.to_string_lossy()])
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

    /// Run grype against the workspace directory.
    async fn run_grype(&self, workspace: &Path) -> Result<GrypeReport> {
        let dir_arg = format!("dir:{}", workspace.to_string_lossy());

        let output = tokio::process::Command::new("grype")
            .args([&dir_arg, "-o", "json", "-q"])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Grype: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("No such file") {
                return Err(AppError::Internal("Grype binary not available".to_string()));
            }
            return Err(AppError::Internal(format!(
                "Grype scan failed (exit {}): {}",
                output.status, stderr
            )));
        }

        serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Grype output: {}", e)))
    }

    /// Convert Grype matches into `RawFinding` values.
    fn convert_findings(report: &GrypeReport) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        for m in &report.matches {
            let severity =
                Severity::from_str_loose(&m.vulnerability.severity).unwrap_or(Severity::Info);

            let title = format!("{} in {}", m.vulnerability.id, m.artifact.name);

            let fixed_version = m
                .vulnerability
                .fix
                .as_ref()
                .and_then(|f| f.versions.first().cloned());

            let source_url = m
                .vulnerability
                .urls
                .as_ref()
                .and_then(|u| u.first().cloned());

            let affected_component = {
                let comp = if let Some(ref t) = m.artifact.artifact_type {
                    format!("{} ({})", m.artifact.name, t)
                } else {
                    m.artifact.name.clone()
                };
                Some(comp)
            };

            findings.push(RawFinding {
                severity,
                title,
                description: m.vulnerability.description.clone(),
                cve_id: Some(m.vulnerability.id.clone()),
                affected_component,
                affected_version: Some(m.artifact.version.clone()),
                fixed_version,
                source: Some("grype".to_string()),
                source_url,
            });
        }

        findings
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

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<Vec<RawFinding>> {
        info!(
            "Starting Grype scan for artifact: {} ({})",
            artifact.name, artifact.id
        );

        // Prepare workspace with artifact content
        let workspace = self.prepare_workspace(artifact, content).await?;

        let report = match self.run_grype(&workspace).await {
            Ok(report) => report,
            Err(e) => {
                warn!(
                    "Grype scan failed for {}: {}. Returning empty findings.",
                    artifact.name, e
                );
                self.cleanup_workspace(artifact).await;
                return Ok(vec![]);
            }
        };

        let findings = Self::convert_findings(&report);

        info!(
            "Grype scan complete for {}: {} vulnerabilities found",
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

    fn make_artifact(name: &str, content_type: &str) -> Artifact {
        Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: format!("test/{}", name),
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
    fn test_is_archive() {
        assert!(GrypeScanner::is_archive("foo.tar.gz"));
        assert!(GrypeScanner::is_archive("foo.tgz"));
        assert!(GrypeScanner::is_archive("foo.whl"));
        assert!(GrypeScanner::is_archive("foo.jar"));
        assert!(GrypeScanner::is_archive("foo.zip"));
        assert!(GrypeScanner::is_archive("foo.gem"));
        assert!(GrypeScanner::is_archive("foo.crate"));
        assert!(GrypeScanner::is_archive("foo.nupkg"));
        assert!(!GrypeScanner::is_archive("Cargo.lock"));
        assert!(!GrypeScanner::is_archive("package.json"));
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
                    urls: Some(vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-99999".to_string()]),
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
        assert!(findings[0].affected_component.as_ref().unwrap().contains("vulnerable-pkg"));
        assert!(findings[0].affected_component.as_ref().unwrap().contains("python"));
        assert_eq!(findings[0].affected_version, Some("1.0.0".to_string()));
        assert!(findings[0].source_url.as_ref().unwrap().contains("nvd.nist.gov"));
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
}
