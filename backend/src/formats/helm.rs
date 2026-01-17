//! Helm chart format handler.
//!
//! Implements Helm chart repository for Kubernetes Helm charts.
//! Supports .tgz chart packages and index.yaml generation.

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use tar::Archive;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Helm format handler
pub struct HelmHandler;

impl HelmHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Helm chart path
    /// Formats:
    ///   index.yaml                    - Repository index
    ///   <chart>-<version>.tgz         - Chart package
    ///   charts/<chart>-<version>.tgz  - Chart package in charts dir
    pub fn parse_path(path: &str) -> Result<HelmPathInfo> {
        let path = path.trim_start_matches('/');

        // Repository index
        if path == "index.yaml" || path.ends_with("/index.yaml") {
            return Ok(HelmPathInfo {
                name: None,
                version: None,
                is_index: true,
                filename: Some("index.yaml".to_string()),
            });
        }

        // Chart package
        if path.ends_with(".tgz") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            let (name, version) = Self::parse_chart_filename(filename)?;
            return Ok(HelmPathInfo {
                name: Some(name),
                version: Some(version),
                is_index: false,
                filename: Some(filename.to_string()),
            });
        }

        Err(AppError::Validation(format!(
            "Invalid Helm chart path: {}",
            path
        )))
    }

    /// Parse chart filename to extract name and version
    /// Format: <name>-<version>.tgz
    fn parse_chart_filename(filename: &str) -> Result<(String, String)> {
        let name = filename.trim_end_matches(".tgz");

        // Find the last hyphen that separates name from version
        // Version starts with a digit
        let parts: Vec<&str> = name.rsplitn(2, '-').collect();

        if parts.len() != 2 {
            return Err(AppError::Validation(format!(
                "Invalid Helm chart filename: {}",
                filename
            )));
        }

        let version = parts[0];
        let chart_name = parts[1];

        // Validate version starts with a digit (semver)
        if !version.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return Err(AppError::Validation(format!(
                "Invalid Helm chart version in filename: {}",
                filename
            )));
        }

        Ok((chart_name.to_string(), version.to_string()))
    }

    /// Extract Chart.yaml from chart package
    pub fn extract_chart_yaml(content: &[u8]) -> Result<ChartYaml> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid chart package: {}", e)))?
        {
            let mut entry = entry
                .map_err(|e| AppError::Validation(format!("Invalid chart entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in chart: {}", e)))?;

            // Chart.yaml is typically in <chartname>/Chart.yaml
            if path.ends_with("Chart.yaml") {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read Chart.yaml: {}", e)))?;

                return serde_yaml::from_str(&content)
                    .map_err(|e| AppError::Validation(format!("Invalid Chart.yaml: {}", e)));
            }
        }

        Err(AppError::Validation(
            "Chart.yaml not found in chart package".to_string(),
        ))
    }

    /// Extract values.yaml from chart package (optional)
    pub fn extract_values_yaml(content: &[u8]) -> Result<Option<serde_yaml::Value>> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid chart package: {}", e)))?
        {
            let mut entry = entry
                .map_err(|e| AppError::Validation(format!("Invalid chart entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in chart: {}", e)))?;

            // values.yaml is typically in <chartname>/values.yaml
            if path.ends_with("values.yaml") {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read values.yaml: {}", e)))?;

                let values: serde_yaml::Value = serde_yaml::from_str(&content)
                    .map_err(|e| AppError::Validation(format!("Invalid values.yaml: {}", e)))?;

                return Ok(Some(values));
            }
        }

        Ok(None)
    }
}

impl Default for HelmHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for HelmHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Helm
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({});

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        metadata["is_index"] = serde_json::Value::Bool(info.is_index);

        // If it's a chart package, extract Chart.yaml
        if !content.is_empty() && !info.is_index {
            if let Ok(chart_yaml) = Self::extract_chart_yaml(content) {
                metadata["chart"] = serde_json::to_value(&chart_yaml)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Skip validation for index.yaml
        if info.is_index {
            return Ok(());
        }

        // Validate chart package
        if !content.is_empty() {
            let chart_yaml = Self::extract_chart_yaml(content)?;

            // Verify name matches
            if let Some(path_name) = &info.name {
                if &chart_yaml.name != path_name {
                    return Err(AppError::Validation(format!(
                        "Chart name mismatch: filename says '{}' but Chart.yaml says '{}'",
                        path_name, chart_yaml.name
                    )));
                }
            }

            // Verify version matches
            if let Some(path_version) = &info.version {
                if &chart_yaml.version != path_version {
                    return Err(AppError::Validation(format!(
                        "Chart version mismatch: filename says '{}' but Chart.yaml says '{}'",
                        path_version, chart_yaml.version
                    )));
                }
            }

            // Validate API version
            if !chart_yaml.api_version.starts_with("v1") && !chart_yaml.api_version.starts_with("v2") {
                return Err(AppError::Validation(format!(
                    "Unsupported Chart API version: {}",
                    chart_yaml.api_version
                )));
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Index is generated on demand based on DB state
        Ok(None)
    }
}

/// Helm path info
#[derive(Debug)]
pub struct HelmPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub is_index: bool,
    pub filename: Option<String>,
}

/// Chart.yaml structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChartYaml {
    pub api_version: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub kube_version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "type")]
    pub chart_type: Option<String>,
    #[serde(default)]
    pub keywords: Option<Vec<String>>,
    #[serde(default)]
    pub home: Option<String>,
    #[serde(default)]
    pub sources: Option<Vec<String>>,
    #[serde(default)]
    pub dependencies: Option<Vec<ChartDependency>>,
    #[serde(default)]
    pub maintainers: Option<Vec<ChartMaintainer>>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub app_version: Option<String>,
    #[serde(default)]
    pub deprecated: Option<bool>,
    #[serde(default)]
    pub annotations: Option<HashMap<String, String>>,
}

/// Chart dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartDependency {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default, rename = "import-values")]
    pub import_values: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub alias: Option<String>,
}

/// Chart maintainer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartMaintainer {
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// Helm repository index entry
#[derive(Debug, Serialize, Deserialize)]
pub struct IndexEntry {
    #[serde(flatten)]
    pub chart: ChartYaml,
    pub urls: Vec<String>,
    pub created: String,
    pub digest: String,
}

/// Helm repository index.yaml structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelmIndex {
    pub api_version: String,
    pub generated: String,
    pub entries: HashMap<String, Vec<IndexEntry>>,
}

/// Generate index.yaml content
pub fn generate_index_yaml(charts: Vec<(ChartYaml, String, String, String)>) -> Result<String> {
    // (chart, url, created, digest)
    let mut entries: HashMap<String, Vec<IndexEntry>> = HashMap::new();

    for (chart, url, created, digest) in charts {
        let entry = IndexEntry {
            chart: chart.clone(),
            urls: vec![url],
            created,
            digest,
        };

        entries
            .entry(chart.name.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }

    let index = HelmIndex {
        api_version: "v1".to_string(),
        generated: chrono::Utc::now().to_rfc3339(),
        entries,
    };

    serde_yaml::to_string(&index)
        .map_err(|e| AppError::Internal(format!("Failed to generate index.yaml: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chart_filename() {
        let (name, version) = HelmHandler::parse_chart_filename("nginx-1.2.3.tgz").unwrap();
        assert_eq!(name, "nginx");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn test_parse_chart_filename_with_hyphen() {
        let (name, version) =
            HelmHandler::parse_chart_filename("my-awesome-chart-0.1.0.tgz").unwrap();
        assert_eq!(name, "my-awesome-chart");
        assert_eq!(version, "0.1.0");
    }

    #[test]
    fn test_parse_path_chart() {
        let info = HelmHandler::parse_path("nginx-1.2.3.tgz").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.2.3".to_string()));
        assert!(!info.is_index);
    }

    #[test]
    fn test_parse_path_index() {
        let info = HelmHandler::parse_path("index.yaml").unwrap();
        assert!(info.is_index);
        assert!(info.name.is_none());
    }

    #[test]
    fn test_parse_chart_yaml() {
        let yaml = r#"
apiVersion: v2
name: nginx
version: 1.2.3
description: A Helm chart for Nginx
appVersion: "1.21.0"
keywords:
  - nginx
  - web
maintainers:
  - name: John Doe
    email: john@example.com
"#;
        let chart: ChartYaml = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chart.name, "nginx");
        assert_eq!(chart.version, "1.2.3");
        assert_eq!(chart.api_version, "v2");
        assert_eq!(chart.app_version, Some("1.21.0".to_string()));
    }
}
