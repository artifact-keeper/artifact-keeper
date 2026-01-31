use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::scanner_service::Scanner;

// Trivy JSON report structures
#[derive(Debug, Deserialize)]
pub struct TrivyReport {
    #[serde(rename = "Results", default)]
    pub results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
pub struct TrivyResult {
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "Class", default)]
    pub class: String,
    #[serde(rename = "Type", default)]
    pub result_type: String,
    #[serde(rename = "Vulnerabilities", default)]
    pub vulnerabilities: Option<Vec<TrivyVulnerability>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pub pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    pub installed_version: String,
    #[serde(rename = "FixedVersion")]
    pub fixed_version: Option<String>,
    #[serde(rename = "Severity")]
    pub severity: String,
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "PrimaryURL")]
    pub primary_url: Option<String>,
}

/// Container image scanner that delegates to a Trivy server instance.
pub struct ImageScanner {
    trivy_url: String,
    http: reqwest::Client,
}

impl ImageScanner {
    pub fn new(trivy_url: String) -> Self {
        Self {
            trivy_url,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Check if this artifact is an OCI/Docker image manifest.
    fn is_container_image(artifact: &Artifact) -> bool {
        let ct = &artifact.content_type;
        ct.contains("vnd.oci.image") ||
        ct.contains("vnd.docker.distribution") ||
        ct.contains("vnd.docker.container") ||
        artifact.path.contains("/manifests/")
    }

    /// Extract an image reference from the artifact path.
    /// OCI paths look like: v2/<name>/manifests/<reference>
    fn extract_image_ref(artifact: &Artifact) -> Option<String> {
        let path = artifact.path.trim_start_matches('/');
        if let Some(rest) = path.strip_prefix("v2/") {
            // v2/<name>/manifests/<ref>
            if let Some(idx) = rest.find("/manifests/") {
                let name = &rest[..idx];
                let reference = &rest[idx + "/manifests/".len()..];
                if !name.is_empty() && !reference.is_empty() {
                    return Some(format!("{}:{}", name, reference));
                }
            }
        }
        None
    }

    /// Check if the Trivy server is available.
    async fn check_trivy_health(&self) -> bool {
        match self.http.get(format!("{}/healthz", self.trivy_url)).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Scan an image reference using the Trivy CLI with server mode.
    async fn scan_with_trivy(&self, image_ref: &str) -> Result<TrivyReport> {
        // Use tokio::process to call trivy CLI with server mode
        let output = tokio::process::Command::new("trivy")
            .args([
                "image",
                "--server", &self.trivy_url,
                "--format", "json",
                "--quiet",
                "--timeout", "5m",
                image_ref,
            ])
            .output()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute Trivy: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // If trivy is not installed, degrade gracefully
            if stderr.contains("not found") || stderr.contains("No such file") {
                warn!("Trivy CLI not available, falling back to HTTP API");
                return self.scan_with_trivy_http(image_ref).await;
            }
            return Err(AppError::Internal(format!(
                "Trivy scan failed (exit {}): {}",
                output.status, stderr
            )));
        }

        serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))
    }

    /// Fallback: scan via Trivy server HTTP API (Twirp).
    async fn scan_with_trivy_http(&self, image_ref: &str) -> Result<TrivyReport> {
        // Trivy server exposes scanning via its REST-like interface
        // POST /twirp/trivy.scanner.v1.Scanner/Scan
        let url = format!("{}/twirp/trivy.scanner.v1.Scanner/Scan", self.trivy_url);

        let body = serde_json::json!({
            "target": image_ref,
            "artifact_type": "container_image",
            "options": {
                "vuln_type": ["os", "library"],
                "scanners": ["vuln"],
            }
        });

        let resp = self.http.post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Trivy HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Trivy server returned {}: {}",
                status, text
            )));
        }

        resp.json::<TrivyReport>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy response: {}", e)))
    }

    /// Convert Trivy vulnerabilities to RawFindings.
    fn convert_findings(report: &TrivyReport) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        for result in &report.results {
            if let Some(ref vulns) = result.vulnerabilities {
                for vuln in vulns {
                    let severity = Severity::from_str_loose(&vuln.severity)
                        .unwrap_or(Severity::Info);

                    let title = vuln.title.clone()
                        .unwrap_or_else(|| format!("{} in {}", vuln.vulnerability_id, vuln.pkg_name));

                    findings.push(RawFinding {
                        severity,
                        title,
                        description: vuln.description.clone(),
                        cve_id: Some(vuln.vulnerability_id.clone()),
                        affected_component: Some(format!("{} ({})", vuln.pkg_name, result.target)),
                        affected_version: Some(vuln.installed_version.clone()),
                        fixed_version: vuln.fixed_version.clone(),
                        source: Some("trivy".to_string()),
                        source_url: vuln.primary_url.clone(),
                    });
                }
            }
        }

        findings
    }
}

#[async_trait]
impl Scanner for ImageScanner {
    fn name(&self) -> &str {
        "container-image"
    }

    fn scan_type(&self) -> &str {
        "image"
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        _content: &Bytes,
    ) -> Result<Vec<RawFinding>> {
        // Only scan OCI/Docker image manifests
        if !Self::is_container_image(artifact) {
            return Ok(vec![]);
        }

        let image_ref = match Self::extract_image_ref(artifact) {
            Some(r) => r,
            None => {
                info!(
                    "Could not extract image reference from artifact path: {}",
                    artifact.path
                );
                return Ok(vec![]);
            }
        };

        // Check if Trivy server is healthy
        if !self.check_trivy_health().await {
            warn!(
                "Trivy server at {} is not available, skipping image scan for {}",
                self.trivy_url, image_ref
            );
            return Ok(vec![]);
        }

        info!("Starting Trivy scan for image: {}", image_ref);

        let report = self.scan_with_trivy(&image_ref).await?;
        let findings = Self::convert_findings(&report);

        info!(
            "Trivy scan complete for {}: {} vulnerabilities found",
            image_ref,
            findings.len()
        );

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_container_image() {
        let mut artifact = Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: "v2/myapp/manifests/latest".to_string(),
            name: "myapp".to_string(),
            version: Some("latest".to_string()),
            size_bytes: 1000,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            storage_key: "test".to_string(),
            is_deleted: false,
            uploaded_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(ImageScanner::is_container_image(&artifact));

        artifact.content_type = "application/json".to_string();
        artifact.path = "some/other/path".to_string();
        assert!(!ImageScanner::is_container_image(&artifact));
    }

    #[test]
    fn test_extract_image_ref() {
        let artifact = Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: "v2/myapp/manifests/v1.0.0".to_string(),
            name: "myapp".to_string(),
            version: Some("v1.0.0".to_string()),
            size_bytes: 1000,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            storage_key: "test".to_string(),
            is_deleted: false,
            uploaded_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(
            ImageScanner::extract_image_ref(&artifact),
            Some("myapp:v1.0.0".to_string())
        );
    }

    #[test]
    fn test_extract_image_ref_with_namespace() {
        let artifact = Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: "v2/org/myapp/manifests/sha256:abc123".to_string(),
            name: "myapp".to_string(),
            version: None,
            size_bytes: 1000,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
            storage_key: "test".to_string(),
            is_deleted: false,
            uploaded_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(
            ImageScanner::extract_image_ref(&artifact),
            Some("org/myapp:sha256:abc123".to_string())
        );
    }

    #[test]
    fn test_extract_image_ref_invalid_path() {
        let artifact = Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: "some/random/path".to_string(),
            name: "test".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "abc".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/json".to_string(),
            storage_key: "test".to_string(),
            is_deleted: false,
            uploaded_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(ImageScanner::extract_image_ref(&artifact), None);
    }

    #[test]
    fn test_convert_findings() {
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "alpine:3.14 (alpine 3.14.2)".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: Some(vec![
                    TrivyVulnerability {
                        vulnerability_id: "CVE-2021-36159".to_string(),
                        pkg_name: "apk-tools".to_string(),
                        installed_version: "2.12.5-r1".to_string(),
                        fixed_version: Some("2.12.6-r0".to_string()),
                        severity: "CRITICAL".to_string(),
                        title: Some("apk-tools: heap overflow in libfetch".to_string()),
                        description: Some("A vulnerability was found in apk-tools".to_string()),
                        primary_url: Some("https://avd.aquasec.com/nvd/cve-2021-36159".to_string()),
                    },
                    TrivyVulnerability {
                        vulnerability_id: "CVE-2021-3711".to_string(),
                        pkg_name: "libssl1.1".to_string(),
                        installed_version: "1.1.1k-r0".to_string(),
                        fixed_version: Some("1.1.1l-r0".to_string()),
                        severity: "HIGH".to_string(),
                        title: None,
                        description: None,
                        primary_url: None,
                    },
                ]),
            }],
        };

        let findings = ImageScanner::convert_findings(&report);
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cve_id, Some("CVE-2021-36159".to_string()));
        assert_eq!(findings[0].title, "apk-tools: heap overflow in libfetch");
        assert!(findings[0].affected_component.as_ref().unwrap().contains("apk-tools"));
        assert_eq!(findings[0].fixed_version, Some("2.12.6-r0".to_string()));
        assert_eq!(findings[0].source, Some("trivy".to_string()));

        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[1].cve_id, Some("CVE-2021-3711".to_string()));
        assert!(findings[1].title.contains("CVE-2021-3711"));
    }

    #[test]
    fn test_convert_findings_empty() {
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "alpine:3.18".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: None,
            }],
        };

        let findings = ImageScanner::convert_findings(&report);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_trivy_report_deserialization() {
        let json = r#"{
            "Results": [{
                "Target": "alpine:3.14",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-36159",
                    "PkgName": "apk-tools",
                    "InstalledVersion": "2.12.5-r1",
                    "FixedVersion": "2.12.6-r0",
                    "Severity": "CRITICAL",
                    "Title": "heap overflow",
                    "Description": "A vulnerability",
                    "PrimaryURL": "https://example.com"
                }]
            }]
        }"#;

        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].vulnerabilities.as_ref().unwrap().len(), 1);
    }
}
