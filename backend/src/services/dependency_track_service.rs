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
use utoipa::ToSchema;

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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtFinding {
    pub component: DtComponent,
    pub vulnerability: DtVulnerability,
    pub analysis: Option<DtAnalysis>,
    pub attribution: Option<DtAttribution>,
}

/// Component affected by a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtComponent {
    pub uuid: String,
    pub name: String,
    pub version: Option<String>,
    pub group: Option<String>,
    pub purl: Option<String>,
}

/// Vulnerability details
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtCwe {
    #[serde(rename = "cweId")]
    pub cwe_id: i32,
    pub name: String,
}

/// Analysis state for a finding
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtAnalysis {
    pub state: Option<String>,
    pub justification: Option<String>,
    pub response: Option<String>,
    pub details: Option<String>,
    #[serde(rename = "isSuppressed")]
    pub is_suppressed: bool,
}

/// Attribution info
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtAttribution {
    #[serde(rename = "analyzerIdentity")]
    pub analyzer_identity: Option<String>,
    #[serde(rename = "attributedOn")]
    pub attributed_on: Option<i64>,
}

/// Policy violation from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicyViolation {
    pub uuid: String,
    #[serde(rename = "type")]
    pub violation_type: String,
    pub component: DtComponent,
    #[serde(rename = "policyCondition")]
    pub policy_condition: DtPolicyCondition,
}

/// Policy condition that was violated
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicyCondition {
    pub uuid: String,
    pub subject: String,
    pub operator: String,
    pub value: String,
    pub policy: DtPolicy,
}

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicy {
    pub uuid: String,
    pub name: String,
    #[serde(rename = "violationState")]
    pub violation_state: String,
}

/// Project-level metrics from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtLicense {
    pub uuid: Option<String>,
    #[serde(rename = "licenseId")]
    pub license_id: Option<String>,
    pub name: String,
}

/// Full policy representation with conditions and projects
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
    #[schema(value_type = Vec<Object>)]
    pub tags: Vec<serde_json::Value>,
}

/// Full policy condition with all fields
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicyConditionFull {
    pub uuid: String,
    pub subject: String,
    pub operator: String,
    pub value: String,
}

/// Request to update analysis state for a finding
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn aggregate_vulnerabilities(findings: &[DtFinding]) -> VulnerabilityAggregate {
        let mut agg = VulnerabilityAggregate {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unassigned: 0,
            total: 0,
        };
        for f in findings {
            agg.total += 1;
            match f.vulnerability.severity.to_uppercase().as_str() {
                "CRITICAL" => agg.critical += 1,
                "HIGH" => agg.high += 1,
                "MEDIUM" => agg.medium += 1,
                "LOW" => agg.low += 1,
                _ => agg.unassigned += 1,
            }
        }
        agg
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct VulnerabilityAggregate {
        pub critical: usize,
        pub high: usize,
        pub medium: usize,
        pub low: usize,
        pub unassigned: usize,
        pub total: usize,
    }

    fn compute_risk_score(metrics: &DtProjectMetrics) -> f64 {
        (metrics.critical as f64 * 10.0)
            + (metrics.high as f64 * 5.0)
            + (metrics.medium as f64 * 3.0)
            + (metrics.low as f64 * 1.0)
    }

    fn risk_level_from_score(score: f64) -> &'static str {
        if score <= 0.0 {
            "none"
        } else if score < 10.0 {
            "low"
        } else if score < 30.0 {
            "medium"
        } else if score < 80.0 {
            "high"
        } else {
            "critical"
        }
    }

    fn filter_unsuppressed_findings(findings: &[DtFinding]) -> Vec<&DtFinding> {
        findings
            .iter()
            .filter(|f| f.analysis.as_ref().map_or(true, |a| !a.is_suppressed))
            .collect()
    }

    fn component_matches_purl_prefix(component: &DtComponent, prefix: &str) -> bool {
        component
            .purl
            .as_ref()
            .is_some_and(|p| p.starts_with(prefix))
    }

    fn compute_audit_ratio(audited: i64, total: i64) -> f64 {
        if total == 0 {
            1.0
        } else {
            audited as f64 / total as f64
        }
    }

    fn total_policy_violations(metrics: &DtProjectMetrics) -> i64 {
        metrics.policy_violations_fail
            + metrics.policy_violations_warn
            + metrics.policy_violations_info
    }

    fn severity_rank(severity: &str) -> u8 {
        match severity.to_uppercase().as_str() {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            "LOW" => 3,
            "INFO" => 4,
            _ => 5,
        }
    }

    // === Helper to create findings ===
    fn make_finding(severity: &str, suppressed: bool) -> DtFinding {
        DtFinding {
            component: DtComponent {
                uuid: "c1".to_string(),
                name: "pkg".to_string(),
                version: Some("1.0".to_string()),
                group: None,
                purl: Some("pkg:npm/pkg@1.0".to_string()),
            },
            vulnerability: DtVulnerability {
                uuid: "v1".to_string(),
                vuln_id: "CVE-2024-0001".to_string(),
                source: "NVD".to_string(),
                severity: severity.to_string(),
                title: None,
                description: None,
                cvss_v3_base_score: None,
                cwe: None,
            },
            analysis: if suppressed {
                Some(DtAnalysis {
                    state: Some("NOT_AFFECTED".to_string()),
                    justification: None,
                    response: None,
                    details: None,
                    is_suppressed: true,
                })
            } else {
                None
            },
            attribution: None,
        }
    }

    fn make_metrics(critical: i64, high: i64, medium: i64, low: i64) -> DtProjectMetrics {
        DtProjectMetrics {
            critical,
            high,
            medium,
            low,
            unassigned: 0,
            vulnerabilities: None,
            findings_total: 0,
            findings_audited: 0,
            findings_unaudited: 0,
            suppressions: 0,
            inherited_risk_score: 0.0,
            policy_violations_fail: 0,
            policy_violations_warn: 0,
            policy_violations_info: 0,
            policy_violations_total: 0,
            first_occurrence: None,
            last_occurrence: None,
        }
    }

    // ===================================================================
    // aggregate_vulnerabilities
    // ===================================================================

    #[test]
    fn test_aggregate_vulnerabilities_empty() {
        let agg = aggregate_vulnerabilities(&[]);
        assert_eq!(agg.total, 0);
        assert_eq!(agg.critical, 0);
        assert_eq!(agg.high, 0);
        assert_eq!(agg.medium, 0);
        assert_eq!(agg.low, 0);
        assert_eq!(agg.unassigned, 0);
    }

    #[test]
    fn test_aggregate_vulnerabilities_mixed() {
        let findings = vec![
            make_finding("CRITICAL", false),
            make_finding("CRITICAL", false),
            make_finding("HIGH", false),
            make_finding("MEDIUM", false),
            make_finding("LOW", false),
            make_finding("LOW", false),
            make_finding("LOW", false),
        ];
        let agg = aggregate_vulnerabilities(&findings);
        assert_eq!(agg.total, 7);
        assert_eq!(agg.critical, 2);
        assert_eq!(agg.high, 1);
        assert_eq!(agg.medium, 1);
        assert_eq!(agg.low, 3);
        assert_eq!(agg.unassigned, 0);
    }

    #[test]
    fn test_aggregate_vulnerabilities_unknown_severity() {
        let findings = vec![make_finding("UNKNOWN", false), make_finding("", false)];
        let agg = aggregate_vulnerabilities(&findings);
        assert_eq!(agg.unassigned, 2);
        assert_eq!(agg.total, 2);
    }

    #[test]
    fn test_aggregate_vulnerabilities_case_insensitive() {
        let findings = vec![
            make_finding("critical", false),
            make_finding("High", false),
            make_finding("medium", false),
            make_finding("low", false),
        ];
        let agg = aggregate_vulnerabilities(&findings);
        assert_eq!(agg.critical, 1);
        assert_eq!(agg.high, 1);
        assert_eq!(agg.medium, 1);
        assert_eq!(agg.low, 1);
    }

    #[test]
    fn test_aggregate_vulnerabilities_includes_suppressed() {
        let findings = vec![make_finding("CRITICAL", true), make_finding("HIGH", false)];
        let agg = aggregate_vulnerabilities(&findings);
        assert_eq!(agg.total, 2);
        assert_eq!(agg.critical, 1);
    }

    // ===================================================================
    // compute_risk_score
    // ===================================================================

    #[test]
    fn test_compute_risk_score_zero() {
        let metrics = make_metrics(0, 0, 0, 0);
        assert!((compute_risk_score(&metrics) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_risk_score_only_critical() {
        let metrics = make_metrics(3, 0, 0, 0);
        assert!((compute_risk_score(&metrics) - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_risk_score_mixed() {
        let metrics = make_metrics(1, 2, 3, 4);
        // 1*10 + 2*5 + 3*3 + 4*1 = 10 + 10 + 9 + 4 = 33
        assert!((compute_risk_score(&metrics) - 33.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_risk_score_only_low() {
        let metrics = make_metrics(0, 0, 0, 5);
        assert!((compute_risk_score(&metrics) - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_risk_score_high_counts() {
        let metrics = make_metrics(10, 20, 30, 40);
        // 10*10 + 20*5 + 30*3 + 40*1 = 100 + 100 + 90 + 40 = 330
        assert!((compute_risk_score(&metrics) - 330.0).abs() < f64::EPSILON);
    }

    // ===================================================================
    // risk_level_from_score
    // ===================================================================

    #[test]
    fn test_risk_level_none() {
        assert_eq!(risk_level_from_score(0.0), "none");
        assert_eq!(risk_level_from_score(-1.0), "none");
    }

    #[test]
    fn test_risk_level_low() {
        assert_eq!(risk_level_from_score(1.0), "low");
        assert_eq!(risk_level_from_score(9.9), "low");
    }

    #[test]
    fn test_risk_level_medium() {
        assert_eq!(risk_level_from_score(10.0), "medium");
        assert_eq!(risk_level_from_score(29.9), "medium");
    }

    #[test]
    fn test_risk_level_high() {
        assert_eq!(risk_level_from_score(30.0), "high");
        assert_eq!(risk_level_from_score(79.9), "high");
    }

    #[test]
    fn test_risk_level_critical() {
        assert_eq!(risk_level_from_score(80.0), "critical");
        assert_eq!(risk_level_from_score(500.0), "critical");
    }

    // ===================================================================
    // filter_unsuppressed_findings
    // ===================================================================

    #[test]
    fn test_filter_unsuppressed_empty() {
        let result = filter_unsuppressed_findings(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_unsuppressed_all_active() {
        let findings = vec![make_finding("HIGH", false), make_finding("MEDIUM", false)];
        let result = filter_unsuppressed_findings(&findings);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_unsuppressed_all_suppressed() {
        let findings = vec![make_finding("HIGH", true), make_finding("CRITICAL", true)];
        let result = filter_unsuppressed_findings(&findings);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_unsuppressed_mixed() {
        let findings = vec![
            make_finding("HIGH", false),
            make_finding("CRITICAL", true),
            make_finding("LOW", false),
        ];
        let result = filter_unsuppressed_findings(&findings);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].vulnerability.severity, "HIGH");
        assert_eq!(result[1].vulnerability.severity, "LOW");
    }

    #[test]
    fn test_filter_unsuppressed_analysis_not_suppressed() {
        // Analysis present but is_suppressed = false
        let mut f = make_finding("MEDIUM", false);
        f.analysis = Some(DtAnalysis {
            state: Some("IN_TRIAGE".to_string()),
            justification: None,
            response: None,
            details: None,
            is_suppressed: false,
        });
        let binding = [f];
        let result = filter_unsuppressed_findings(&binding);
        assert_eq!(result.len(), 1);
    }

    // ===================================================================
    // component_matches_purl_prefix
    // ===================================================================

    #[test]
    fn test_component_matches_purl_prefix_exact() {
        let comp = DtComponent {
            uuid: "c1".to_string(),
            name: "lodash".to_string(),
            version: None,
            group: None,
            purl: Some("pkg:npm/lodash@4.17.21".to_string()),
        };
        assert!(component_matches_purl_prefix(&comp, "pkg:npm/"));
    }

    #[test]
    fn test_component_matches_purl_prefix_no_match() {
        let comp = DtComponent {
            uuid: "c1".to_string(),
            name: "spring".to_string(),
            version: None,
            group: None,
            purl: Some("pkg:maven/org.springframework/spring-core@5.3.0".to_string()),
        };
        assert!(!component_matches_purl_prefix(&comp, "pkg:npm/"));
    }

    #[test]
    fn test_component_matches_purl_prefix_no_purl() {
        let comp = DtComponent {
            uuid: "c1".to_string(),
            name: "unknown".to_string(),
            version: None,
            group: None,
            purl: None,
        };
        assert!(!component_matches_purl_prefix(&comp, "pkg:npm/"));
    }

    #[test]
    fn test_component_matches_purl_prefix_empty_prefix() {
        let comp = DtComponent {
            uuid: "c1".to_string(),
            name: "anything".to_string(),
            version: None,
            group: None,
            purl: Some("pkg:cargo/serde@1.0".to_string()),
        };
        assert!(component_matches_purl_prefix(&comp, ""));
    }

    #[test]
    fn test_component_matches_purl_prefix_full_purl() {
        let comp = DtComponent {
            uuid: "c1".to_string(),
            name: "pkg".to_string(),
            version: None,
            group: None,
            purl: Some("pkg:npm/lodash@4.17.21".to_string()),
        };
        assert!(component_matches_purl_prefix(
            &comp,
            "pkg:npm/lodash@4.17.21"
        ));
    }

    // ===================================================================
    // compute_audit_ratio
    // ===================================================================

    #[test]
    fn test_compute_audit_ratio_all_audited() {
        assert!((compute_audit_ratio(10, 10) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_audit_ratio_none_audited() {
        assert!((compute_audit_ratio(0, 10) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_audit_ratio_partial() {
        assert!((compute_audit_ratio(5, 10) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_audit_ratio_zero_total() {
        assert!((compute_audit_ratio(0, 0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_audit_ratio_large_numbers() {
        assert!((compute_audit_ratio(999, 1000) - 0.999).abs() < 0.001);
    }

    // ===================================================================
    // total_policy_violations
    // ===================================================================

    #[test]
    fn test_total_policy_violations_zero() {
        let mut metrics = make_metrics(0, 0, 0, 0);
        metrics.policy_violations_fail = 0;
        metrics.policy_violations_warn = 0;
        metrics.policy_violations_info = 0;
        assert_eq!(total_policy_violations(&metrics), 0);
    }

    #[test]
    fn test_total_policy_violations_mixed() {
        let mut metrics = make_metrics(0, 0, 0, 0);
        metrics.policy_violations_fail = 3;
        metrics.policy_violations_warn = 5;
        metrics.policy_violations_info = 2;
        assert_eq!(total_policy_violations(&metrics), 10);
    }

    #[test]
    fn test_total_policy_violations_only_fail() {
        let mut metrics = make_metrics(0, 0, 0, 0);
        metrics.policy_violations_fail = 7;
        assert_eq!(total_policy_violations(&metrics), 7);
    }

    #[test]
    fn test_total_policy_violations_only_warn() {
        let mut metrics = make_metrics(0, 0, 0, 0);
        metrics.policy_violations_warn = 4;
        assert_eq!(total_policy_violations(&metrics), 4);
    }

    #[test]
    fn test_total_policy_violations_only_info() {
        let mut metrics = make_metrics(0, 0, 0, 0);
        metrics.policy_violations_info = 12;
        assert_eq!(total_policy_violations(&metrics), 12);
    }

    // ===================================================================
    // severity_rank
    // ===================================================================

    #[test]
    fn test_severity_rank_critical() {
        assert_eq!(severity_rank("CRITICAL"), 0);
        assert_eq!(severity_rank("critical"), 0);
    }

    #[test]
    fn test_severity_rank_high() {
        assert_eq!(severity_rank("HIGH"), 1);
        assert_eq!(severity_rank("high"), 1);
    }

    #[test]
    fn test_severity_rank_medium() {
        assert_eq!(severity_rank("MEDIUM"), 2);
    }

    #[test]
    fn test_severity_rank_low() {
        assert_eq!(severity_rank("LOW"), 3);
    }

    #[test]
    fn test_severity_rank_info() {
        assert_eq!(severity_rank("INFO"), 4);
    }

    #[test]
    fn test_severity_rank_unknown() {
        assert_eq!(severity_rank("UNKNOWN"), 5);
        assert_eq!(severity_rank(""), 5);
        assert_eq!(severity_rank("foo"), 5);
    }

    #[test]
    fn test_severity_rank_ordering() {
        assert!(severity_rank("CRITICAL") < severity_rank("HIGH"));
        assert!(severity_rank("HIGH") < severity_rank("MEDIUM"));
        assert!(severity_rank("MEDIUM") < severity_rank("LOW"));
        assert!(severity_rank("LOW") < severity_rank("INFO"));
        assert!(severity_rank("INFO") < severity_rank("UNKNOWN"));
    }

    // ===================================================================
    // Existing serialization/deserialization tests
    // ===================================================================

    #[test]
    fn test_config_from_env_disabled() {
        unsafe { std::env::remove_var("DEPENDENCY_TRACK_ENABLED") };
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
        assert_eq!(metrics.findings_total, 22);
        assert!((metrics.inherited_risk_score - 42.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dt_project_metrics_defaults() {
        let json = r#"{}"#;
        let metrics: DtProjectMetrics = serde_json::from_str(json).unwrap();
        assert_eq!(metrics.critical, 0);
        assert_eq!(metrics.high, 0);
        assert!(metrics.vulnerabilities.is_none());
    }

    #[test]
    fn test_dependency_track_config_construction() {
        let config = DependencyTrackConfig {
            base_url: "http://localhost:8092".to_string(),
            api_key: "test-api-key".to_string(),
            enabled: true,
        };
        assert_eq!(config.base_url, "http://localhost:8092");
        assert!(config.enabled);
    }

    #[test]
    fn test_dependency_track_config_clone() {
        let config = DependencyTrackConfig {
            base_url: "http://dt.example.com".to_string(),
            api_key: "key-123".to_string(),
            enabled: false,
        };
        let cloned = config.clone();
        assert_eq!(cloned.base_url, "http://dt.example.com");
        assert!(!cloned.enabled);
    }

    #[test]
    fn test_update_analysis_request_serialize() {
        let request = UpdateAnalysisRequest {
            project: "proj-uuid".to_string(),
            component: "comp-uuid".to_string(),
            vulnerability: "vuln-uuid".to_string(),
            analysis_state: "NOT_AFFECTED".to_string(),
            analysis_justification: Some("Protected by WAF".to_string()),
            analysis_details: None,
            is_suppressed: true,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["project"], "proj-uuid");
        assert_eq!(json["analysisState"], "NOT_AFFECTED");
        assert!(json.get("analysisDetails").is_none());
        assert_eq!(json["isSuppressed"], true);
    }
}
