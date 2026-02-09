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

/// Project-level metrics from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtProjectMetrics {
    #[serde(default)]
    pub critical: i64,
    #[serde(default)]
    pub high: i64,
    #[serde(default)]
    pub medium: i64,
    #[serde(default)]
    pub low: i64,
    #[serde(default)]
    pub unassigned: i64,
    #[serde(default)]
    pub vulnerabilities: Option<i64>,
    #[serde(default, rename = "findingsTotal")]
    pub findings_total: i64,
    #[serde(default, rename = "findingsAudited")]
    pub findings_audited: i64,
    #[serde(default, rename = "findingsUnaudited")]
    pub findings_unaudited: i64,
    #[serde(default)]
    pub suppressions: i64,
    #[serde(default, rename = "inheritedRiskScore")]
    pub inherited_risk_score: f64,
    #[serde(default, rename = "policyViolationsFail")]
    pub policy_violations_fail: i64,
    #[serde(default, rename = "policyViolationsWarn")]
    pub policy_violations_warn: i64,
    #[serde(default, rename = "policyViolationsInfo")]
    pub policy_violations_info: i64,
    #[serde(default, rename = "policyViolationsTotal")]
    pub policy_violations_total: i64,
    #[serde(rename = "firstOccurrence")]
    pub first_occurrence: Option<i64>,
    #[serde(rename = "lastOccurrence")]
    pub last_occurrence: Option<i64>,
}

/// Portfolio-level metrics from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtPortfolioMetrics {
    #[serde(default)]
    pub critical: i64,
    #[serde(default)]
    pub high: i64,
    #[serde(default)]
    pub medium: i64,
    #[serde(default)]
    pub low: i64,
    #[serde(default)]
    pub unassigned: i64,
    #[serde(default)]
    pub vulnerabilities: Option<i64>,
    #[serde(default, rename = "findingsTotal")]
    pub findings_total: i64,
    #[serde(default, rename = "findingsAudited")]
    pub findings_audited: i64,
    #[serde(default, rename = "findingsUnaudited")]
    pub findings_unaudited: i64,
    #[serde(default)]
    pub suppressions: i64,
    #[serde(default, rename = "inheritedRiskScore")]
    pub inherited_risk_score: f64,
    #[serde(default, rename = "policyViolationsFail")]
    pub policy_violations_fail: i64,
    #[serde(default, rename = "policyViolationsWarn")]
    pub policy_violations_warn: i64,
    #[serde(default, rename = "policyViolationsInfo")]
    pub policy_violations_info: i64,
    #[serde(default, rename = "policyViolationsTotal")]
    pub policy_violations_total: i64,
    #[serde(default)]
    pub projects: i64,
}

/// Full component representation from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtComponentFull {
    pub uuid: String,
    pub name: String,
    pub version: Option<String>,
    pub group: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    #[serde(rename = "resolvedLicense")]
    pub resolved_license: Option<DtLicense>,
    #[serde(rename = "isInternal")]
    pub is_internal: Option<bool>,
}

/// License information from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtLicense {
    pub uuid: Option<String>,
    #[serde(rename = "licenseId")]
    pub license_id: Option<String>,
    pub name: String,
}

/// Full policy representation with conditions and projects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtPolicyFull {
    pub uuid: String,
    pub name: String,
    #[serde(rename = "violationState")]
    pub violation_state: String,
    #[serde(rename = "includeChildren")]
    pub include_children: Option<bool>,
    #[serde(rename = "policyConditions")]
    pub policy_conditions: Vec<DtPolicyConditionFull>,
    pub projects: Vec<DtProject>,
    pub tags: Vec<serde_json::Value>,
}

/// Full policy condition with all fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtPolicyConditionFull {
    pub uuid: String,
    pub subject: String,
    pub operator: String,
    pub value: String,
}

/// Request to update analysis state for a finding
#[derive(Debug, Serialize)]
pub struct UpdateAnalysisRequest {
    pub project: String,
    pub component: String,
    pub vulnerability: String,
    #[serde(rename = "analysisState")]
    pub analysis_state: String,
    #[serde(
        rename = "analysisJustification",
        skip_serializing_if = "Option::is_none"
    )]
    pub analysis_justification: Option<String>,
    #[serde(rename = "analysisDetails", skip_serializing_if = "Option::is_none")]
    pub analysis_details: Option<String>,
    #[serde(rename = "isSuppressed")]
    pub is_suppressed: bool,
}

/// Response from analysis update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtAnalysisResponse {
    #[serde(rename = "analysisState")]
    pub analysis_state: String,
    #[serde(rename = "analysisJustification")]
    pub analysis_justification: Option<String>,
    #[serde(rename = "analysisDetails")]
    pub analysis_details: Option<String>,
    #[serde(rename = "isSuppressed")]
    pub is_suppressed: bool,
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

    /// Get current metrics for a project
    pub async fn get_project_metrics(&self, project_uuid: &str) -> Result<DtProjectMetrics> {
        let url = format!(
            "{}/api/v1/metrics/project/{}/current",
            self.config.base_url, project_uuid
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get project metrics failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get project metrics failed: {} - {}",
                status, body
            )));
        }

        let metrics = response
            .json::<DtProjectMetrics>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse project metrics: {}", e)))?;

        Ok(metrics)
    }

    /// Get project metrics history for a number of days
    pub async fn get_project_metrics_history(
        &self,
        project_uuid: &str,
        days: u32,
    ) -> Result<Vec<DtProjectMetrics>> {
        let url = format!(
            "{}/api/v1/metrics/project/{}/days/{}",
            self.config.base_url, project_uuid, days
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("DT get project metrics history failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get project metrics history failed: {} - {}",
                status, body
            )));
        }

        let metrics = response
            .json::<Vec<DtProjectMetrics>>()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to parse project metrics history: {}", e))
            })?;

        Ok(metrics)
    }

    /// Get current portfolio-wide metrics
    pub async fn get_portfolio_metrics(&self) -> Result<DtPortfolioMetrics> {
        let url = format!("{}/api/v1/metrics/portfolio/current", self.config.base_url);

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get portfolio metrics failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get portfolio metrics failed: {} - {}",
                status, body
            )));
        }

        let metrics = response
            .json::<DtPortfolioMetrics>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse portfolio metrics: {}", e)))?;

        Ok(metrics)
    }

    /// Refresh metrics for a project (fire-and-forget)
    pub async fn refresh_project_metrics(&self, project_uuid: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/metrics/project/{}/refresh",
            self.config.base_url, project_uuid
        );

        let response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await;

        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(
                        project_uuid = %project_uuid,
                        status = %resp.status(),
                        "DT refresh project metrics returned non-success status"
                    );
                }
            }
            Err(e) => {
                warn!(
                    project_uuid = %project_uuid,
                    error = %e,
                    "DT refresh project metrics request failed"
                );
            }
        }

        Ok(())
    }

    /// Update analysis state for a finding
    #[allow(clippy::too_many_arguments)]
    pub async fn update_analysis(
        &self,
        project_uuid: &str,
        component_uuid: &str,
        vulnerability_uuid: &str,
        state: &str,
        justification: Option<&str>,
        details: Option<&str>,
        suppressed: bool,
    ) -> Result<DtAnalysisResponse> {
        let url = format!("{}/api/v1/analysis", self.config.base_url);

        let request = UpdateAnalysisRequest {
            project: project_uuid.to_string(),
            component: component_uuid.to_string(),
            vulnerability: vulnerability_uuid.to_string(),
            analysis_state: state.to_string(),
            analysis_justification: justification.map(String::from),
            analysis_details: details.map(String::from),
            is_suppressed: suppressed,
        };

        let response: reqwest::Response = self
            .client
            .put(&url)
            .header("X-Api-Key", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT update analysis failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT update analysis failed: {} - {}",
                status, body
            )));
        }

        let analysis = response
            .json::<DtAnalysisResponse>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse analysis response: {}", e)))?;

        Ok(analysis)
    }

    /// Get all policies
    pub async fn get_policies(&self) -> Result<Vec<DtPolicyFull>> {
        let url = format!("{}/api/v1/policy", self.config.base_url);

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get policies failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get policies failed: {} - {}",
                status, body
            )));
        }

        let policies = response
            .json::<Vec<DtPolicyFull>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse policies: {}", e)))?;

        Ok(policies)
    }

    /// Get components for a project
    pub async fn get_components(&self, project_uuid: &str) -> Result<Vec<DtComponentFull>> {
        let url = format!(
            "{}/api/v1/component/project/{}",
            self.config.base_url, project_uuid
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get components failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get components failed: {} - {}",
                status, body
            )));
        }

        let components = response
            .json::<Vec<DtComponentFull>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse components: {}", e)))?;

        Ok(components)
    }

    /// Get the base URL of the Dependency-Track instance
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Check if the integration is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
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

    #[test]
    fn test_dt_project_metrics_deserialize() {
        let json = r#"{
            "critical": 2,
            "high": 5,
            "medium": 12,
            "low": 3,
            "unassigned": 0,
            "vulnerabilities": 22,
            "findingsTotal": 22,
            "findingsAudited": 4,
            "findingsUnaudited": 18,
            "suppressions": 1,
            "inheritedRiskScore": 42.5,
            "policyViolationsFail": 1,
            "policyViolationsWarn": 2,
            "policyViolationsInfo": 0,
            "policyViolationsTotal": 3,
            "firstOccurrence": 1700000000000,
            "lastOccurrence": 1700100000000
        }"#;

        let metrics: DtProjectMetrics = serde_json::from_str(json).unwrap();
        assert_eq!(metrics.critical, 2);
        assert_eq!(metrics.high, 5);
        assert_eq!(metrics.medium, 12);
        assert_eq!(metrics.low, 3);
        assert_eq!(metrics.unassigned, 0);
        assert_eq!(metrics.vulnerabilities, Some(22));
        assert_eq!(metrics.findings_total, 22);
        assert_eq!(metrics.findings_audited, 4);
        assert_eq!(metrics.findings_unaudited, 18);
        assert_eq!(metrics.suppressions, 1);
        assert!((metrics.inherited_risk_score - 42.5).abs() < f64::EPSILON);
        assert_eq!(metrics.policy_violations_fail, 1);
        assert_eq!(metrics.policy_violations_warn, 2);
        assert_eq!(metrics.policy_violations_info, 0);
        assert_eq!(metrics.policy_violations_total, 3);
        assert_eq!(metrics.first_occurrence, Some(1700000000000));
        assert_eq!(metrics.last_occurrence, Some(1700100000000));
    }

    #[test]
    fn test_dt_component_full_deserialize() {
        let json = r#"{
            "uuid": "comp-uuid-123",
            "name": "express",
            "version": "4.18.2",
            "group": "npm",
            "purl": "pkg:npm/express@4.18.2",
            "cpe": null,
            "resolvedLicense": {
                "uuid": "license-uuid",
                "licenseId": "MIT",
                "name": "MIT License"
            },
            "isInternal": false
        }"#;

        let component: DtComponentFull = serde_json::from_str(json).unwrap();
        assert_eq!(component.uuid, "comp-uuid-123");
        assert_eq!(component.name, "express");
        assert_eq!(component.version, Some("4.18.2".to_string()));
        assert_eq!(component.group, Some("npm".to_string()));
        assert_eq!(component.purl, Some("pkg:npm/express@4.18.2".to_string()));
        assert_eq!(component.cpe, None);
        assert!(component.resolved_license.is_some());
        let license = component.resolved_license.unwrap();
        assert_eq!(license.license_id, Some("MIT".to_string()));
        assert_eq!(license.name, "MIT License");
        assert_eq!(component.is_internal, Some(false));
    }
}
