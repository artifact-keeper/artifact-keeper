//! Grype vulnerability scanner.
//!
//! Writes artifact content to a scan workspace directory, optionally extracts
//! archives, and invokes `grype` via CLI to discover vulnerabilities.

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use std::path::Path;
use tokio::sync::OnceCell;
use tracing::info;

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::scanner_service::{
    capture_cli_version, fail_scan, format_grype_version, ScanWorkspace, Scanner,
};

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
    /// Lazily-probed version string from `grype --version`, e.g.
    /// `grype-0.83.0`. Cached for the scanner's lifetime so each scan does
    /// not pay an extra subprocess for the version probe.
    cached_version: OnceCell<Option<String>>,
}

impl GrypeScanner {
    pub fn new(scan_workspace: String) -> Self {
        Self {
            scan_workspace,
            cached_version: OnceCell::new(),
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
        report
            .matches
            .iter()
            .map(|m| {
                let affected_component = Some(match &m.artifact.artifact_type {
                    Some(t) => format!("{} ({})", m.artifact.name, t),
                    None => m.artifact.name.clone(),
                });

                RawFinding {
                    severity: Severity::from_str_loose(&m.vulnerability.severity)
                        .unwrap_or(Severity::Info),
                    title: format!("{} in {}", m.vulnerability.id, m.artifact.name),
                    description: m.vulnerability.description.clone(),
                    cve_id: Some(m.vulnerability.id.clone()),
                    affected_component,
                    affected_version: Some(m.artifact.version.clone()),
                    fixed_version: m
                        .vulnerability
                        .fix
                        .as_ref()
                        .and_then(|f| f.versions.first().cloned()),
                    source: Some("grype".to_string()),
                    source_url: m
                        .vulnerability
                        .urls
                        .as_ref()
                        .and_then(|u| u.first().cloned()),
                }
            })
            .collect()
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

    /// Probe `grype --version` once and cache the parsed version string.
    /// Returns `None` if the binary is missing or its output cannot be
    /// parsed.
    async fn version(&self) -> Option<String> {
        self.cached_version
            .get_or_init(|| async {
                let raw = capture_cli_version("grype", &["--version"]).await?;
                format_grype_version(&raw)
            })
            .await
            .clone()
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

        let workspace =
            ScanWorkspace::prepare(&self.scan_workspace, None, artifact, content).await?;

        let report = match self.run_grype(&workspace).await {
            Ok(report) => report,
            Err(e) => {
                return Err(
                    fail_scan("Grype scan", artifact, &e, &self.scan_workspace, None).await,
                );
            }
        };

        let findings = Self::convert_findings(&report);

        info!(
            "Grype scan complete for {}: {} vulnerabilities found",
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
    use crate::services::scanner_service::test_helpers::{assert_scan_failed, make_test_artifact};

    fn make_artifact(name: &str, content_type: &str) -> Artifact {
        make_test_artifact(name, content_type, &format!("test/{}", name))
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
                    urls: Some(vec![
                        "https://nvd.nist.gov/vuln/detail/CVE-2023-99999".to_string()
                    ]),
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
        assert!(findings[0]
            .affected_component
            .as_ref()
            .unwrap()
            .contains("vulnerable-pkg"));
        assert!(findings[0]
            .affected_component
            .as_ref()
            .unwrap()
            .contains("python"));
        assert_eq!(findings[0].affected_version, Some("1.0.0".to_string()));
        assert!(findings[0]
            .source_url
            .as_ref()
            .unwrap()
            .contains("nvd.nist.gov"));
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

    /// Scan failures (workspace creation, missing grype binary) must
    /// propagate as Err, never as Ok(vec![]).
    #[tokio::test]
    async fn test_scan_propagates_errors() {
        let artifact = make_artifact("pkg-1.0.0.tar.gz", "application/gzip");
        let content = Bytes::from_static(b"not a real archive");

        // Impossible workspace path
        let bad_ws = GrypeScanner::new("/dev/null/impossible-workspace".to_string());
        assert!(
            bad_ws.scan(&artifact, None, &content).await.is_err(),
            "scan() must return Err when workspace creation fails"
        );

        // Missing grype binary (skip if grype is installed)
        if std::process::Command::new("grype")
            .arg("version")
            .output()
            .is_ok()
        {
            eprintln!("grype is installed, skipping unavailable-grype test");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let no_grype = GrypeScanner::new(dir.path().to_string_lossy().to_string());
        assert_scan_failed(
            &no_grype.scan(&artifact, None, &content).await,
            "Grype scan",
        );
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

    /// `version()` exercises the OnceCell-cached `grype --version` probe.
    /// As with the Trivy version test, we accept either Some or None
    /// depending on whether `grype` is installed on the test host: we only
    /// require that repeated calls return the same value (cache fidelity)
    /// and that any returned token starts with `grype-`.
    #[tokio::test]
    async fn test_version_is_cached_and_deterministic() {
        let scanner = GrypeScanner::new("/tmp/grype-version-cov-test".to_string());
        let v1 = scanner.version().await;
        let v2 = scanner.version().await;
        assert_eq!(v1, v2, "OnceCell must return identical value on repeat");
        if let Some(v) = v1 {
            assert!(
                v.starts_with("grype-"),
                "grype version probe must be normalized to 'grype-<ver>'; got {}",
                v
            );
        }
    }
}
