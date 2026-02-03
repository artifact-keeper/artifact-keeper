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
use crate::services::scanner_service::Scanner;

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
}

impl OpenScapScanner {
    pub fn new(openscap_url: String, profile: String, scan_workspace: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(600))
            .build()
            .expect("failed to build HTTP client");

        Self {
            http,
            openscap_url,
            profile,
            scan_workspace,
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

    fn workspace_dir(&self, artifact: &Artifact) -> PathBuf {
        Path::new(&self.scan_workspace).join(format!("openscap-{}", artifact.id))
    }

    async fn prepare_workspace(&self, artifact: &Artifact, content: &Bytes) -> Result<PathBuf> {
        let workspace = self.workspace_dir(artifact);
        tokio::fs::create_dir_all(&workspace)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create scan workspace: {}", e)))?;

        let original_filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.name);
        let artifact_path = workspace.join(original_filename);

        tokio::fs::write(&artifact_path, content)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to write artifact to workspace: {}", e))
            })?;

        Ok(workspace)
    }

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
                warn!(
                    "OpenSCAP scan failed for {}: {}. Returning empty findings.",
                    artifact.name, e
                );
                self.cleanup_workspace(artifact).await;
                return Ok(vec![]);
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

        self.cleanup_workspace(artifact).await;

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_artifact(name: &str, content_type: &str, path: &str) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: path.to_string(),
            name: name.to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: String::new(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: content_type.to_string(),
            storage_key: String::new(),
            is_deleted: false,
            uploaded_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_is_applicable_rpm() {
        let artifact = make_artifact(
            "nginx-1.24.0-1.el9.x86_64.rpm",
            "application/x-rpm",
            "rpm/nginx/nginx-1.24.0-1.el9.x86_64.rpm",
        );
        assert!(OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_deb() {
        let artifact = make_artifact(
            "nginx_1.24.0-1_amd64.deb",
            "application/vnd.debian.binary-package",
            "deb/nginx/nginx_1.24.0-1_amd64.deb",
        );
        assert!(OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_container() {
        let artifact = make_artifact(
            "myapp",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/myapp/manifests/latest",
        );
        assert!(OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_jar() {
        let artifact = make_artifact("app.jar", "application/java-archive", "maven/app.jar");
        assert!(!OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_npm() {
        let artifact = make_artifact(
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
}
