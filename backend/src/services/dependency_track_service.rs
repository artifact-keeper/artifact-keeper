//! Dependency-Track integration service.
//!
//! Provides API client for OWASP Dependency-Track to upload SBOMs,
//! retrieve vulnerability findings, and manage policy violations.
//!
//! ## Configuration
//!
//! ```bash
//! DEPENDENCY_TRACK_URL=http://localhost:8092
//! DEPENDENCY_TRACK_API_KEY=your-api-key
//! DEPENDENCY_TRACK_ENABLED=true
//! ```
//!
//! ## API Reference
//!
//! See: https://docs.dependencytrack.org/integrations/rest-api/

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::error::{AppError, Result};

/// Dependency-Track service configuration
#[derive(Debug, Clone)]
pub struct DependencyTrackConfig {
    /// Base URL of the Dependency-Track API server
    pub base_url: String,
    /// API key for authentication (X-Api-Key header)
    pub api_key: String,
    /// Whether integration is enabled
    pub enabled: bool,
}

impl DependencyTrackConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Option<Self> {
        let enabled = std::env::var("DEPENDENCY_TRACK_ENABLED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        if !enabled {
            return None;
        }

        let base_url = std::env::var("DEPENDENCY_TRACK_URL").ok()?;
        let api_key = std::env::var("DEPENDENCY_TRACK_API_KEY").ok()?;

        Some(Self {
            base_url,
            api_key,
            enabled,
        })
    }
}

/// Dependency-Track API client
pub struct DependencyTrackService {
    client: Client,
    config: DependencyTrackConfig,
}

/// Dependency-Track project representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtProject {
    pub uuid: String,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "lastBomImport")]
    pub last_bom_import: Option<i64>,
    #[serde(rename = "lastBomImportFormat")]
    pub last_bom_import_format: Option<String>,
}

/// Request to create a new project
#[derive(Debug, Serialize)]
struct CreateProjectRequest {
    name: String,
    version: Option<String>,
    description: Option<String>,
}

/// BOM upload response
#[derive(Debug, Deserialize)]
pub struct BomUploadResponse {
    pub token: String,
}

/// BOM processing status
#[derive(Debug, Deserialize)]
pub struct BomProcessingStatus {
    pub processing: bool,
}

/// Vulnerability finding from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtFinding {
    pub component: DtComponent,
    pub vulnerability: DtVulnerability,
    pub analysis: Option<DtAnalysis>,
    pub attribution: Option<DtAttribution>,
}

/// Component affected by a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtComponent {
    pub uuid: String,
    pub name: String,
    pub version: Option<String>,
    pub group: Option<String>,
    pub purl: Option<String>,
}

/// Vulnerability details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtVulnerability {
    pub uuid: String,
    #[serde(rename = "vulnId")]
    pub vuln_id: String,
    pub source: String,
    pub severity: String,
    pub title: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "cvssV3BaseScore")]
    pub cvss_v3_base_score: Option<f64>,
    pub cwe: Option<DtCwe>,
}

/// CWE reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtCwe {
    #[serde(rename = "cweId")]
    pub cwe_id: i32,
    pub name: String,
}

/// Analysis state for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtAnalysis {
    pub state: Option<String>,
    pub justification: Option<String>,
    pub response: Option<String>,
    pub details: Option<String>,
    #[serde(rename = "isSuppressed")]
    pub is_suppressed: bool,
}

/// Attribution info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtAttribution {
    #[serde(rename = "analyzerIdentity")]
    pub analyzer_identity: Option<String>,
    #[serde(rename = "attributedOn")]
    pub attributed_on: Option<i64>,
}

/// Policy violation from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtPolicyViolation {
    pub uuid: String,
    #[serde(rename = "type")]
    pub violation_type: String,
    pub component: DtComponent,
    #[serde(rename = "policyCondition")]
    pub policy_condition: DtPolicyCondition,
}

/// Policy condition that was violated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtPolicyCondition {
    pub uuid: String,
    pub subject: String,
    pub operator: String,
    pub value: String,
    pub policy: DtPolicy,
}

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtPolicy {
    pub uuid: String,
    pub name: String,
    #[serde(rename = "violationState")]
    pub violation_state: String,
}

impl DependencyTrackService {
    /// Create a new Dependency-Track service
    pub fn new(config: DependencyTrackConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        info!(
            url = %config.base_url,
            "Dependency-Track integration initialized"
        );

        Ok(Self { client, config })
    }

    /// Create from environment variables, returns None if not enabled
    pub fn from_env() -> Option<Result<Self>> {
        DependencyTrackConfig::from_env().map(Self::new)
    }

    /// Check if the service is available
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/api/version", self.config.base_url);

        match self.client.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                warn!(error = %e, "Dependency-Track health check failed");
                Ok(false)
            }
        }
    }

    /// Get or create a project for a repository
    pub async fn get_or_create_project(
        &self,
        name: &str,
        version: Option<&str>,
        description: Option<&str>,
    ) -> Result<DtProject> {
        // First try to find existing project
        if let Some(project) = self.find_project(name, version).await? {
            return Ok(project);
        }

        // Create new project
        self.create_project(name, version, description).await
    }

    /// Find a project by name and version
    pub async fn find_project(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<DtProject>> {
        let url = match version {
            Some(v) => format!(
                "{}/api/v1/project/lookup?name={}&version={}",
                self.config.base_url,
                urlencoding::encode(name),
                urlencoding::encode(v)
            ),
            None => format!(
                "{}/api/v1/project/lookup?name={}",
                self.config.base_url,
                urlencoding::encode(name)
            ),
        };

        let response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT API request failed: {}", e)))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT project lookup failed: {} - {}",
                status, body
            )));
        }

        let project: DtProject = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse DT project: {}", e)))?;

        Ok(Some(project))
    }

    /// Create a new project
    pub async fn create_project(
        &self,
        name: &str,
        version: Option<&str>,
        description: Option<&str>,
    ) -> Result<DtProject> {
        let url = format!("{}/api/v1/project", self.config.base_url);

        let request = CreateProjectRequest {
            name: name.to_string(),
            version: version.map(String::from),
            description: description.map(String::from),
        };

        let response: reqwest::Response = self
            .client
            .put(&url)
            .header("X-Api-Key", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT create project failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT create project failed: {} - {}",
                status, body
            )));
        }

        let project = response
            .json::<DtProject>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse DT project: {}", e)))?;

        info!(
            project_uuid = %project.uuid,
            project_name = %project.name,
            "Created Dependency-Track project"
        );

        Ok(project)
    }

    /// Upload an SBOM (CycloneDX format) to a project
    pub async fn upload_sbom(
        &self,
        project_uuid: &str,
        sbom_content: &str,
    ) -> Result<BomUploadResponse> {
        let url = format!("{}/api/v1/bom", self.config.base_url);

        // DT expects base64-encoded BOM
        use base64::{engine::general_purpose::STANDARD, Engine};
        let encoded_bom = STANDARD.encode(sbom_content);

        let body = serde_json::json!({
            "project": project_uuid,
            "bom": encoded_bom
        });

        let response: reqwest::Response = self
            .client
            .put(&url)
            .header("X-Api-Key", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT BOM upload failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT BOM upload failed: {} - {}",
                status, body
            )));
        }

        let result = response.json::<BomUploadResponse>().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse BOM upload response: {}", e))
        })?;

        debug!(
            project_uuid = %project_uuid,
            token = %result.token,
            "Uploaded SBOM to Dependency-Track"
        );

        Ok(result)
    }

    /// Check if BOM processing is complete
    pub async fn is_bom_processing(&self, token: &str) -> Result<bool> {
        let url = format!("{}/api/v1/bom/token/{}", self.config.base_url, token);

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT BOM status check failed: {}", e)))?;

        if !response.status().is_success() {
            // Token not found or expired means processing is complete
            return Ok(false);
        }

        let status = response
            .json::<BomProcessingStatus>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse BOM status: {}", e)))?;

        Ok(status.processing)
    }

    /// Wait for BOM processing to complete (with timeout)
    pub async fn wait_for_bom_processing(&self, token: &str, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_secs(2);

        while start.elapsed() < timeout {
            if !self.is_bom_processing(token).await? {
                return Ok(());
            }
            tokio::time::sleep(poll_interval).await;
        }

        Err(AppError::Internal("BOM processing timeout".to_string()))
    }

    /// Get vulnerability findings for a project
    pub async fn get_findings(&self, project_uuid: &str) -> Result<Vec<DtFinding>> {
        let url = format!(
            "{}/api/v1/finding/project/{}",
            self.config.base_url, project_uuid
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get findings failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get findings failed: {} - {}",
                status, body
            )));
        }

        let findings = response
            .json::<Vec<DtFinding>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse findings: {}", e)))?;

        debug!(
            project_uuid = %project_uuid,
            count = findings.len(),
            "Retrieved vulnerability findings from Dependency-Track"
        );

        Ok(findings)
    }

    /// Get policy violations for a project
    pub async fn get_policy_violations(
        &self,
        project_uuid: &str,
    ) -> Result<Vec<DtPolicyViolation>> {
        let url = format!(
            "{}/api/v1/violation/project/{}",
            self.config.base_url, project_uuid
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get violations failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get violations failed: {} - {}",
                status, body
            )));
        }

        let violations = response
            .json::<Vec<DtPolicyViolation>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse violations: {}", e)))?;

        debug!(
            project_uuid = %project_uuid,
            count = violations.len(),
            "Retrieved policy violations from Dependency-Track"
        );

        Ok(violations)
    }

    /// Get all projects
    pub async fn list_projects(&self) -> Result<Vec<DtProject>> {
        let url = format!("{}/api/v1/project", self.config.base_url);

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT list projects failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT list projects failed: {} - {}",
                status, body
            )));
        }

        let projects = response
            .json::<Vec<DtProject>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse projects: {}", e)))?;

        Ok(projects)
    }

    /// Delete a project
    pub async fn delete_project(&self, project_uuid: &str) -> Result<()> {
        let url = format!("{}/api/v1/project/{}", self.config.base_url, project_uuid);

        let response: reqwest::Response = self
            .client
            .delete(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT delete project failed: {}", e)))?;

        if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT delete project failed: {} - {}",
                status, body
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env_disabled() {
        // When DEPENDENCY_TRACK_ENABLED is not set, should return None
        std::env::remove_var("DEPENDENCY_TRACK_ENABLED");
        assert!(DependencyTrackConfig::from_env().is_none());
    }

    #[test]
    fn test_dt_finding_deserialize() {
        let json = r#"{
            "component": {
                "uuid": "test-uuid",
                "name": "lodash",
                "version": "4.17.0",
                "group": null,
                "purl": "pkg:npm/lodash@4.17.0"
            },
            "vulnerability": {
                "uuid": "vuln-uuid",
                "vulnId": "CVE-2021-23337",
                "source": "NVD",
                "severity": "HIGH",
                "title": "Prototype Pollution",
                "description": "Test description",
                "cvssV3BaseScore": 7.5,
                "cwe": {
                    "cweId": 1321,
                    "name": "Improperly Controlled Modification"
                }
            },
            "analysis": null,
            "attribution": null
        }"#;

        let finding: DtFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.vulnerability.vuln_id, "CVE-2021-23337");
        assert_eq!(finding.vulnerability.severity, "HIGH");
        assert_eq!(finding.component.name, "lodash");
    }

    #[test]
    fn test_dt_policy_violation_deserialize() {
        let json = r#"{
            "uuid": "violation-uuid",
            "type": "LICENSE",
            "component": {
                "uuid": "comp-uuid",
                "name": "gpl-lib",
                "version": "1.0.0",
                "group": null,
                "purl": null
            },
            "policyCondition": {
                "uuid": "cond-uuid",
                "subject": "LICENSE",
                "operator": "IS",
                "value": "GPL-3.0",
                "policy": {
                    "uuid": "policy-uuid",
                    "name": "No GPL",
                    "violationState": "FAIL"
                }
            }
        }"#;

        let violation: DtPolicyViolation = serde_json::from_str(json).unwrap();
        assert_eq!(violation.violation_type, "LICENSE");
        assert_eq!(violation.policy_condition.policy.name, "No GPL");
    }
}
