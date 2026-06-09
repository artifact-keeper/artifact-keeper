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

    /// Returns true if `segment` looks like a chart version token.
    ///
    /// Accepts plain semver (`1.24.0`) as well as OCI-style `v`-prefixed tags
    /// (`v1.14.0`). To avoid mistaking a chart-name segment such as `2nd` for a
    /// version, the leading numeric run (after an optional `v`/`V`) must be
    /// followed by a version-structural character (`.`, `-`, `+`) or the end of
    /// the token — not an alphabetic continuation like `nd`.
    fn looks_like_version_start(segment: &str) -> bool {
        let bytes = segment.as_bytes();
        let mut i = 0;
        // Optional leading v / V (OCI-style tag).
        if matches!(bytes.first(), Some(b'v') | Some(b'V')) {
            i = 1;
        }
        // Require at least one digit.
        let digits_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == digits_start {
            return false;
        }
        // The numeric run must end the token or be followed by version syntax.
        matches!(bytes.get(i), None | Some(b'.') | Some(b'-') | Some(b'+'))
    }

    /// Parse chart filename to extract name and version.
    ///
    /// Format: `<name>-<version>.tgz`
    ///
    /// The version may contain hyphens itself (semver pre-release / build
    /// metadata such as `1.24.0-rc.1` or `1.0.0-alpha.1+build.5`), so we cannot
    /// simply split on the last hyphen. Instead we scan hyphen boundaries from
    /// left to right and pick the FIRST one whose right-hand side looks like the
    /// start of a version (leading digit, or `v`/`V` + digit). This keeps the
    /// chart name greedy while still capturing the full version, including
    /// pre-release suffixes that the naive last-hyphen split would truncate.
    fn parse_chart_filename(filename: &str) -> Result<(String, String)> {
        let stem = filename.trim_end_matches(".tgz");

        // Candidate split points: every hyphen that is not the first character.
        // Walk left-to-right so the chart name stays as long as possible and the
        // version captures any embedded pre-release hyphens.
        for (idx, _) in stem.match_indices('-') {
            if idx == 0 {
                continue;
            }
            let chart_name = &stem[..idx];
            let version = &stem[idx + 1..];
            if !version.is_empty() && Self::looks_like_version_start(version) {
                return Ok((chart_name.to_string(), version.to_string()));
            }
        }

        Err(AppError::Validation(format!(
            "Invalid Helm chart filename: {}",
            filename
        )))
    }

    /// Extract Chart.yaml from chart package
    pub fn extract_chart_yaml(content: &[u8]) -> Result<ChartYaml> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid chart package: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid chart entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in chart: {}", e)))?;

            // Chart.yaml is typically in <chartname>/Chart.yaml
            if path.ends_with("Chart.yaml") {
                let mut content = String::new();
                entry.read_to_string(&mut content).map_err(|e| {
                    AppError::Validation(format!("Failed to read Chart.yaml: {}", e))
                })?;

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
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid chart entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in chart: {}", e)))?;

            // values.yaml is typically in <chartname>/values.yaml
            if path.ends_with("values.yaml") {
                let mut content = String::new();
                entry.read_to_string(&mut content).map_err(|e| {
                    AppError::Validation(format!("Failed to read values.yaml: {}", e))
                })?;

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
            if !chart_yaml.api_version.starts_with("v1")
                && !chart_yaml.api_version.starts_with("v2")
            {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub chart_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<ChartDependency>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintainers: Option<Vec<ChartMaintainer>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

/// Chart dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartDependency {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(
        default,
        rename = "import-values",
        skip_serializing_if = "Option::is_none"
    )]
    pub import_values: Option<Vec<serde_yaml::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

/// Chart maintainer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartMaintainer {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

        entries.entry(chart.name.clone()).or_default().push(entry);
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

    // ---- HelmHandler::new / Default ----

    #[test]
    fn test_new_and_default() {
        let _h1 = HelmHandler::new();
        let _h2 = HelmHandler;
    }

    // ---- parse_chart_filename ----

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
    fn test_parse_chart_filename_prerelease() {
        // rsplitn(2, '-') splits on the last '-', so "1.0.0" stays together
        // and "alpha" would need to be part of the version in the filename
        // But "chart-1.0.0" -> name="chart", version="1.0.0"
        let (name, version) = HelmHandler::parse_chart_filename("chart-1.0.0.tgz").unwrap();
        assert_eq!(name, "chart");
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn test_parse_chart_filename_no_hyphen() {
        // No hyphen means rsplitn gives only 1 part
        let result = HelmHandler::parse_chart_filename("nohyphen.tgz");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_chart_filename_version_not_starting_with_digit() {
        // "chart-alpha.tgz" -> version = "alpha" which doesn't start with digit
        let result = HelmHandler::parse_chart_filename("chart-alpha.tgz");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_chart_filename_version_empty_after_hyphen() {
        // "chart-.tgz" -> version is empty, first char check fails
        let result = HelmHandler::parse_chart_filename("chart-.tgz");
        assert!(result.is_err());
    }

    // ---- parse_chart_filename: pre-release & v-prefixed versions (#1779) ----

    #[test]
    fn test_parse_chart_filename_prerelease_suffix() {
        // Regression (#1779): a semver pre-release suffix contains its own
        // hyphen. The naive last-hyphen split truncated the version to "rc.1";
        // the version must be captured in full.
        let (name, version) = HelmHandler::parse_chart_filename("nginx-1.24.0-rc.1.tgz").unwrap();
        assert_eq!(name, "nginx");
        assert_eq!(version, "1.24.0-rc.1");
    }

    #[test]
    fn test_parse_chart_filename_prerelease_with_build_metadata() {
        let (name, version) =
            HelmHandler::parse_chart_filename("my-chart-1.0.0-alpha.1+build.5.tgz").unwrap();
        assert_eq!(name, "my-chart");
        assert_eq!(version, "1.0.0-alpha.1+build.5");
    }

    #[test]
    fn test_parse_chart_filename_v_prefixed_version() {
        // Regression (#1779): OCI-style v-prefixed tags were rejected because
        // the version did not start with a digit.
        let (name, version) =
            HelmHandler::parse_chart_filename("cert-manager-v1.14.0.tgz").unwrap();
        assert_eq!(name, "cert-manager");
        assert_eq!(version, "v1.14.0");
    }

    #[test]
    fn test_parse_chart_filename_v_prefixed_prerelease() {
        let (name, version) = HelmHandler::parse_chart_filename("nginx-v1.24.0-rc.1.tgz").unwrap();
        assert_eq!(name, "nginx");
        assert_eq!(version, "v1.24.0-rc.1");
    }

    #[test]
    fn test_parse_chart_filename_digit_leading_name_segment() {
        // A chart-name segment that merely starts with a digit (e.g. "2nd")
        // must NOT be mistaken for the version. Only a proper version token
        // (digit run ending in '.', '-', '+', or end-of-token) splits.
        let (name, version) = HelmHandler::parse_chart_filename("my-2nd-chart-1.0.0.tgz").unwrap();
        assert_eq!(name, "my-2nd-chart");
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn test_parse_path_chart_prerelease_roundtrip() {
        // The download handler relies on parse_path succeeding so it can fall
        // through to the upstream-index proxy lookup (#1779).
        let info = HelmHandler::parse_path("charts/nginx-1.24.0-rc.1.tgz").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.24.0-rc.1".to_string()));
        assert!(!info.is_index);
    }

    // ---- parse_path: index.yaml ----

    #[test]
    fn test_parse_path_index() {
        let info = HelmHandler::parse_path("index.yaml").unwrap();
        assert!(info.is_index);
        assert!(info.name.is_none());
        assert!(info.version.is_none());
        assert_eq!(info.filename, Some("index.yaml".to_string()));
    }

    #[test]
    fn test_parse_path_index_subdir() {
        let info = HelmHandler::parse_path("some/subdir/index.yaml").unwrap();
        assert!(info.is_index);
        assert_eq!(info.filename, Some("index.yaml".to_string()));
    }

    #[test]
    fn test_parse_path_index_leading_slash() {
        let info = HelmHandler::parse_path("/index.yaml").unwrap();
        assert!(info.is_index);
    }

    // ---- parse_path: chart package ----

    #[test]
    fn test_parse_path_chart() {
        let info = HelmHandler::parse_path("nginx-1.2.3.tgz").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.2.3".to_string()));
        assert!(!info.is_index);
        assert_eq!(info.filename, Some("nginx-1.2.3.tgz".to_string()));
    }

    #[test]
    fn test_parse_path_chart_in_charts_dir() {
        let info = HelmHandler::parse_path("charts/nginx-1.2.3.tgz").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.2.3".to_string()));
        assert!(!info.is_index);
        assert_eq!(info.filename, Some("nginx-1.2.3.tgz".to_string()));
    }

    #[test]
    fn test_parse_path_chart_leading_slash() {
        let info = HelmHandler::parse_path("/nginx-1.2.3.tgz").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.2.3".to_string()));
    }

    #[test]
    fn test_parse_path_chart_hyphenated_name() {
        let info = HelmHandler::parse_path("my-chart-name-2.0.0.tgz").unwrap();
        assert_eq!(info.name, Some("my-chart-name".to_string()));
        assert_eq!(info.version, Some("2.0.0".to_string()));
    }

    // ---- parse_path: invalid ----

    #[test]
    fn test_parse_path_invalid() {
        assert!(HelmHandler::parse_path("random.txt").is_err());
    }

    #[test]
    fn test_parse_path_empty() {
        assert!(HelmHandler::parse_path("").is_err());
    }

    #[test]
    fn test_parse_path_no_extension() {
        assert!(HelmHandler::parse_path("filename").is_err());
    }

    // ---- ChartYaml serde ----

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
        assert_eq!(
            chart.description,
            Some("A Helm chart for Nginx".to_string())
        );
        assert_eq!(
            chart.keywords,
            Some(vec!["nginx".to_string(), "web".to_string()])
        );
        let maintainers = chart.maintainers.unwrap();
        assert_eq!(maintainers.len(), 1);
        assert_eq!(maintainers[0].name, "John Doe");
        assert_eq!(maintainers[0].email, Some("john@example.com".to_string()));
    }

    #[test]
    fn test_parse_chart_yaml_v1_minimal() {
        let yaml = r#"
apiVersion: v1
name: my-chart
version: 0.1.0
"#;
        let chart: ChartYaml = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chart.api_version, "v1");
        assert_eq!(chart.name, "my-chart");
        assert_eq!(chart.version, "0.1.0");
        assert!(chart.description.is_none());
        assert!(chart.keywords.is_none());
        assert!(chart.maintainers.is_none());
        assert!(chart.app_version.is_none());
        assert!(chart.home.is_none());
        assert!(chart.sources.is_none());
        assert!(chart.icon.is_none());
        assert!(chart.deprecated.is_none());
        assert!(chart.chart_type.is_none());
        assert!(chart.kube_version.is_none());
        assert!(chart.annotations.is_none());
    }

    #[test]
    fn test_parse_chart_yaml_full() {
        let yaml = r#"
apiVersion: v2
name: full-chart
version: 2.0.0
kubeVersion: ">=1.25.0"
description: Full featured chart
type: application
keywords:
  - test
home: https://example.com
sources:
  - https://github.com/user/repo
dependencies:
  - name: subchart
    version: "1.0.0"
    repository: https://charts.example.com
    condition: subchart.enabled
    tags:
      - frontend
    alias: sc
maintainers:
  - name: Dev
    email: dev@example.com
    url: https://dev.example.com
icon: https://example.com/icon.png
appVersion: "3.0"
deprecated: true
annotations:
  category: database
"#;
        let chart: ChartYaml = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chart.name, "full-chart");
        assert_eq!(chart.version, "2.0.0");
        assert_eq!(chart.kube_version, Some(">=1.25.0".to_string()));
        assert_eq!(chart.chart_type, Some("application".to_string()));
        assert_eq!(chart.home, Some("https://example.com".to_string()));
        assert_eq!(
            chart.sources,
            Some(vec!["https://github.com/user/repo".to_string()])
        );
        assert_eq!(chart.icon, Some("https://example.com/icon.png".to_string()));
        assert_eq!(chart.deprecated, Some(true));

        let deps = chart.dependencies.unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "subchart");
        assert_eq!(deps[0].version, "1.0.0");
        assert_eq!(
            deps[0].repository,
            Some("https://charts.example.com".to_string())
        );
        assert_eq!(deps[0].condition, Some("subchart.enabled".to_string()));
        assert_eq!(deps[0].tags, Some(vec!["frontend".to_string()]));
        assert_eq!(deps[0].alias, Some("sc".to_string()));

        let m = chart.maintainers.unwrap();
        assert_eq!(m[0].url, Some("https://dev.example.com".to_string()));

        let ann = chart.annotations.unwrap();
        assert_eq!(ann.get("category"), Some(&"database".to_string()));
    }

    // ---- index.yaml serialization: omit unset optional fields (#1779) ----

    #[test]
    fn test_chart_yaml_minimal_serializes_without_nulls() {
        // Regression (#1779): a minimal chart (apiVersion/name/version only)
        // must NOT emit explicit `null` for every unset optional field, which
        // violates the ChartMuseum/Helm index.yaml convention.
        let chart = ChartYaml {
            api_version: "v2".to_string(),
            name: "mini".to_string(),
            version: "0.1.0".to_string(),
            kube_version: None,
            description: None,
            chart_type: None,
            keywords: None,
            home: None,
            sources: None,
            dependencies: None,
            maintainers: None,
            icon: None,
            app_version: None,
            deprecated: None,
            annotations: None,
        };

        let yaml = serde_yaml::to_string(&chart).unwrap();
        assert!(!yaml.contains("null"), "unexpected null in:\n{}", yaml);
        for absent in [
            "kubeVersion",
            "description",
            "type",
            "keywords",
            "home",
            "sources",
            "dependencies",
            "maintainers",
            "icon",
            "appVersion",
            "deprecated",
            "annotations",
        ] {
            assert!(
                !yaml.contains(absent),
                "field `{}` should be omitted, got:\n{}",
                absent,
                yaml
            );
        }
        // Required fields are still present.
        assert!(yaml.contains("apiVersion: v2"));
        assert!(yaml.contains("name: mini"));
        assert!(yaml.contains("version: 0.1.0"));

        // JSON serialization is also clean (used by API metadata paths).
        let json = serde_json::to_value(&chart).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.values().any(|v| v.is_null()));
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn test_chart_maintainer_minimal_serializes_without_nulls() {
        let m = ChartMaintainer {
            name: "Dev".to_string(),
            email: None,
            url: None,
        };
        let yaml = serde_yaml::to_string(&m).unwrap();
        assert!(!yaml.contains("null"), "unexpected null in:\n{}", yaml);
        assert!(!yaml.contains("email"));
        assert!(!yaml.contains("url"));
        assert!(yaml.contains("name: Dev"));
    }

    #[test]
    fn test_chart_dependency_minimal_serializes_without_nulls() {
        let dep = ChartDependency {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            repository: None,
            condition: None,
            tags: None,
            import_values: None,
            alias: None,
        };
        let yaml = serde_yaml::to_string(&dep).unwrap();
        assert!(!yaml.contains("null"), "unexpected null in:\n{}", yaml);
        for absent in ["repository", "condition", "tags", "import-values", "alias"] {
            assert!(
                !yaml.contains(absent),
                "field `{}` should be omitted",
                absent
            );
        }
    }

    // ---- ChartDependency serde ----

    #[test]
    fn test_chart_dependency_minimal() {
        let yaml = r#"
name: dep
version: "1.0.0"
"#;
        let dep: ChartDependency = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(dep.name, "dep");
        assert_eq!(dep.version, "1.0.0");
        assert!(dep.repository.is_none());
        assert!(dep.condition.is_none());
        assert!(dep.tags.is_none());
        assert!(dep.import_values.is_none());
        assert!(dep.alias.is_none());
    }

    // ---- extract_chart_yaml: error cases ----

    #[test]
    fn test_extract_chart_yaml_invalid_bytes() {
        let result = HelmHandler::extract_chart_yaml(b"not gzip");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_chart_yaml_empty() {
        let result = HelmHandler::extract_chart_yaml(b"");
        assert!(result.is_err());
    }

    // ---- extract_values_yaml: error cases ----

    #[test]
    fn test_extract_values_yaml_invalid_bytes() {
        let result = HelmHandler::extract_values_yaml(b"not gzip");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_values_yaml_empty() {
        let result = HelmHandler::extract_values_yaml(b"");
        assert!(result.is_err());
    }

    // ---- generate_index_yaml ----

    #[test]
    fn test_generate_index_yaml_empty() {
        let yaml_str = generate_index_yaml(vec![]).unwrap();
        let index: HelmIndex = serde_yaml::from_str(&yaml_str).unwrap();
        assert_eq!(index.api_version, "v1");
        assert!(index.entries.is_empty());
    }

    #[test]
    fn test_generate_index_yaml_single_chart() {
        let chart = ChartYaml {
            api_version: "v2".to_string(),
            name: "nginx".to_string(),
            version: "1.0.0".to_string(),
            kube_version: None,
            description: Some("Test chart".to_string()),
            chart_type: None,
            keywords: None,
            home: None,
            sources: None,
            dependencies: None,
            maintainers: None,
            icon: None,
            app_version: None,
            deprecated: None,
            annotations: None,
        };

        let yaml_str = generate_index_yaml(vec![(
            chart,
            "https://example.com/charts/nginx-1.0.0.tgz".to_string(),
            "2024-01-01T00:00:00Z".to_string(),
            "sha256:abc123".to_string(),
        )])
        .unwrap();

        let index: HelmIndex = serde_yaml::from_str(&yaml_str).unwrap();
        assert_eq!(index.api_version, "v1");
        assert!(index.entries.contains_key("nginx"));
        let entries = &index.entries["nginx"];
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].chart.name, "nginx");
        assert_eq!(entries[0].chart.version, "1.0.0");
        assert_eq!(
            entries[0].urls,
            vec!["https://example.com/charts/nginx-1.0.0.tgz"]
        );
        assert_eq!(entries[0].digest, "sha256:abc123");
    }

    #[test]
    fn test_generate_index_yaml_multiple_versions() {
        let make_chart = |version: &str| ChartYaml {
            api_version: "v2".to_string(),
            name: "nginx".to_string(),
            version: version.to_string(),
            kube_version: None,
            description: None,
            chart_type: None,
            keywords: None,
            home: None,
            sources: None,
            dependencies: None,
            maintainers: None,
            icon: None,
            app_version: None,
            deprecated: None,
            annotations: None,
        };

        let yaml_str = generate_index_yaml(vec![
            (
                make_chart("1.0.0"),
                "https://example.com/nginx-1.0.0.tgz".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                "aaa".to_string(),
            ),
            (
                make_chart("2.0.0"),
                "https://example.com/nginx-2.0.0.tgz".to_string(),
                "2024-06-01T00:00:00Z".to_string(),
                "bbb".to_string(),
            ),
        ])
        .unwrap();

        let index: HelmIndex = serde_yaml::from_str(&yaml_str).unwrap();
        assert_eq!(index.entries["nginx"].len(), 2);
    }

    #[test]
    fn test_generate_index_yaml_multiple_charts() {
        let make_chart = |name: &str, version: &str| ChartYaml {
            api_version: "v2".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            kube_version: None,
            description: None,
            chart_type: None,
            keywords: None,
            home: None,
            sources: None,
            dependencies: None,
            maintainers: None,
            icon: None,
            app_version: None,
            deprecated: None,
            annotations: None,
        };

        let yaml_str = generate_index_yaml(vec![
            (
                make_chart("nginx", "1.0.0"),
                "url1".to_string(),
                "time1".to_string(),
                "d1".to_string(),
            ),
            (
                make_chart("redis", "2.0.0"),
                "url2".to_string(),
                "time2".to_string(),
                "d2".to_string(),
            ),
        ])
        .unwrap();

        let index: HelmIndex = serde_yaml::from_str(&yaml_str).unwrap();
        assert!(index.entries.contains_key("nginx"));
        assert!(index.entries.contains_key("redis"));
    }

    // ---- HelmIndex serde ----

    #[test]
    fn test_helm_index_roundtrip() {
        let index = HelmIndex {
            api_version: "v1".to_string(),
            generated: "2024-01-01T00:00:00Z".to_string(),
            entries: HashMap::new(),
        };
        let yaml = serde_yaml::to_string(&index).unwrap();
        let parsed: HelmIndex = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.api_version, "v1");
        assert!(parsed.entries.is_empty());
    }

    // ---- IndexEntry serde ----

    #[test]
    fn test_index_entry_roundtrip() {
        let entry = IndexEntry {
            chart: ChartYaml {
                api_version: "v2".to_string(),
                name: "test".to_string(),
                version: "1.0.0".to_string(),
                kube_version: None,
                description: None,
                chart_type: None,
                keywords: None,
                home: None,
                sources: None,
                dependencies: None,
                maintainers: None,
                icon: None,
                app_version: None,
                deprecated: None,
                annotations: None,
            },
            urls: vec!["https://example.com/test-1.0.0.tgz".to_string()],
            created: "2024-01-01T00:00:00Z".to_string(),
            digest: "sha256:abc".to_string(),
        };
        let yaml = serde_yaml::to_string(&entry).unwrap();
        let parsed: IndexEntry = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.chart.name, "test");
        assert_eq!(parsed.urls.len(), 1);
        assert_eq!(parsed.digest, "sha256:abc");
    }
}
