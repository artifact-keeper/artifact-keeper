//! Quality checker that validates Helm chart `.tgz` archives for structural
//! correctness. All validation is performed in-process without shelling out to
//! the `helm` CLI.

use bytes::Bytes;
use flate2::read::GzDecoder;
use serde_json::json;
use std::io::Read;
use tar::Archive;

use crate::models::quality::{QualityCheckOutput, RawQualityIssue};

/// Validates Helm chart archives (.tgz) for structural quality.
///
/// Scoring breakdown (100 points total):
///
/// | Check                                  | Points |
/// |----------------------------------------|--------|
/// | Chart.yaml exists and is valid YAML    | 15     |
/// | Chart.yaml has `apiVersion`            |  5     |
/// | Chart.yaml has `name`                  |  5     |
/// | Chart.yaml has `version` (valid semver)| 10     |
/// | Chart.yaml has `description`           |  5     |
/// | values.yaml exists                     | 20     |
/// | templates/ directory has files         | 20     |
/// | Chart.yaml has `appVersion`            |  5     |
/// | Chart.yaml has `maintainers`           |  5     |
/// | No deprecated apiVersion v1            | 10     |
pub struct HelmLintChecker;

impl HelmLintChecker {
    /// Human-readable checker name.
    pub fn name(&self) -> &str {
        "HelmLint"
    }

    /// Machine-readable check type identifier.
    pub fn check_type(&self) -> &str {
        "helm_lint"
    }

    /// Package formats this checker applies to.
    pub fn applicable_formats(&self) -> Option<Vec<&str>> {
        Some(vec!["helm"])
    }

    /// Check a Helm chart `.tgz` archive for structural issues.
    pub fn check(&self, content: &Bytes) -> QualityCheckOutput {
        let mut issues: Vec<RawQualityIssue> = Vec::new();
        let mut score: i32 = 0;
        let mut details = json!({});

        let tar_bytes = match decompress_gzip(content) {
            Ok(bytes) => bytes,
            Err(output) => return output,
        };

        let inventory = match scan_tar_entries(&tar_bytes) {
            Ok(inv) => inv,
            Err(output) => return output,
        };

        let chart_yaml = evaluate_chart_yaml(
            &inventory.chart_yaml_content,
            &mut issues,
            &mut score,
            &mut details,
        );

        if let Some(ref doc) = chart_yaml {
            let map = doc.as_mapping();
            check_api_version(map, &mut issues, &mut score, &mut details);
            check_name(map, &mut issues, &mut score, &mut details);
            check_version(map, &mut issues, &mut score, &mut details);
            check_description(map, &mut issues, &mut score, &mut details);
            check_app_version(map, &mut issues, &mut score, &mut details);
            check_maintainers(map, &mut issues, &mut score, &mut details);
        }

        check_values_yaml(
            inventory.has_values_yaml,
            &mut issues,
            &mut score,
            &mut details,
        );
        check_template_files(
            &inventory.template_files,
            &mut issues,
            &mut score,
            &mut details,
        );

        let passed = score >= 50;
        details["score"] = json!(score);
        details["passed"] = json!(passed);
        details["issues_count"] = json!(issues.len());

        QualityCheckOutput {
            score,
            passed,
            issues,
            details,
        }
    }
}

/// Inventory of files found inside a Helm chart archive.
struct TarInventory {
    chart_yaml_content: Option<String>,
    has_values_yaml: bool,
    template_files: Vec<String>,
}

/// Decompress gzip content, returning the raw tar bytes on success or a
/// critical-failure `QualityCheckOutput` on error.
fn decompress_gzip(content: &Bytes) -> Result<Vec<u8>, QualityCheckOutput> {
    let mut decoder = GzDecoder::new(content.as_ref());
    let mut tar_bytes = Vec::new();
    if let Err(e) = decoder.read_to_end(&mut tar_bytes) {
        return Err(QualityCheckOutput {
            score: 0,
            passed: false,
            issues: vec![RawQualityIssue {
                severity: "critical".to_string(),
                category: "helm-structure".to_string(),
                title: "Not a valid gzip archive".to_string(),
                description: Some(format!("Failed to decompress gzip: {e}")),
                location: None,
            }],
            details: json!({ "error": "Not a valid gzip archive" }),
        });
    }
    Ok(tar_bytes)
}

/// Walk the tar entries and collect Chart.yaml content, values.yaml presence,
/// and template file paths.
fn scan_tar_entries(tar_bytes: &[u8]) -> Result<TarInventory, QualityCheckOutput> {
    let mut archive = Archive::new(tar_bytes);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(e) => {
            return Err(QualityCheckOutput {
                score: 0,
                passed: false,
                issues: vec![RawQualityIssue {
                    severity: "critical".to_string(),
                    category: "helm-structure".to_string(),
                    title: "Not a valid tar archive".to_string(),
                    description: Some(format!("Failed to read tar entries: {e}")),
                    location: None,
                }],
                details: json!({ "error": "Not a valid tar archive" }),
            });
        }
    };

    let mut chart_yaml_content: Option<String> = None;
    let mut has_values_yaml = false;
    let mut template_files: Vec<String> = Vec::new();

    for entry_result in entries {
        let mut entry = match entry_result {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path_str = match entry.path() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        if (path_str.ends_with("/Chart.yaml") || path_str == "Chart.yaml")
            && chart_yaml_content.is_none()
        {
            let mut buf = String::new();
            if entry.read_to_string(&mut buf).is_ok() {
                chart_yaml_content = Some(buf);
            }
        }

        if path_str.ends_with("/values.yaml") || path_str == "values.yaml" {
            has_values_yaml = true;
        }

        if (path_str.contains("/templates/") || path_str.starts_with("templates/"))
            && (path_str.ends_with(".yaml") || path_str.ends_with(".tpl"))
        {
            template_files.push(path_str);
        }
    }

    Ok(TarInventory {
        chart_yaml_content,
        has_values_yaml,
        template_files,
    })
}

/// Parse Chart.yaml content and award the 15-point "exists and valid YAML"
/// score, recording any parse issues.
fn evaluate_chart_yaml(
    raw_content: &Option<String>,
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) -> Option<serde_yaml::Value> {
    let raw = match raw_content {
        Some(r) => r,
        None => {
            issues.push(RawQualityIssue {
                severity: "critical".to_string(),
                category: "helm-structure".to_string(),
                title: "Chart.yaml is missing".to_string(),
                description: Some("Every Helm chart must contain a Chart.yaml file".to_string()),
                location: None,
            });
            details["chart_yaml_found"] = json!(false);
            return None;
        }
    };

    match serde_yaml::from_str(raw) {
        Ok(val) => {
            *score += 15;
            details["chart_yaml_found"] = json!(true);
            details["chart_yaml_valid"] = json!(true);
            Some(val)
        }
        Err(e) => {
            issues.push(RawQualityIssue {
                severity: "critical".to_string(),
                category: "helm-parse".to_string(),
                title: "Chart.yaml contains invalid YAML".to_string(),
                description: Some(format!("YAML parse error: {e}")),
                location: Some("Chart.yaml".to_string()),
            });
            details["chart_yaml_found"] = json!(true);
            details["chart_yaml_valid"] = json!(false);
            None
        }
    }
}

/// Check the `apiVersion` field (5 pts) and whether it is deprecated v1 (10 pts).
fn check_api_version(
    map: Option<&serde_yaml::Mapping>,
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) {
    let Some(av) = yaml_str_field(map, "apiVersion") else {
        issues.push(RawQualityIssue {
            severity: "high".to_string(),
            category: "helm-required-field".to_string(),
            title: "Chart.yaml missing apiVersion".to_string(),
            description: Some("The apiVersion field is required in Chart.yaml".to_string()),
            location: Some("Chart.yaml".to_string()),
        });
        details["api_version"] = json!(null);
        return;
    };

    *score += 5;
    details["api_version"] = json!(av);

    if av == "v1" {
        issues.push(RawQualityIssue {
            severity: "medium".to_string(),
            category: "helm-deprecation".to_string(),
            title: "Deprecated apiVersion v1".to_string(),
            description: Some("apiVersion v1 is deprecated; migrate to v2".to_string()),
            location: Some("Chart.yaml:apiVersion".to_string()),
        });
        details["api_version_deprecated"] = json!(true);
    } else {
        *score += 10;
        details["api_version_deprecated"] = json!(false);
    }
}

/// Check the `name` field (5 pts).
fn check_name(
    map: Option<&serde_yaml::Mapping>,
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) {
    let Some(n) = yaml_str_field(map, "name") else {
        issues.push(RawQualityIssue {
            severity: "high".to_string(),
            category: "helm-required-field".to_string(),
            title: "Chart.yaml missing name".to_string(),
            description: Some("The name field is required in Chart.yaml".to_string()),
            location: Some("Chart.yaml".to_string()),
        });
        details["name"] = json!(null);
        return;
    };

    if n.is_empty() {
        issues.push(RawQualityIssue {
            severity: "high".to_string(),
            category: "helm-required-field".to_string(),
            title: "Chart.yaml has empty name".to_string(),
            description: Some("The name field must not be empty".to_string()),
            location: Some("Chart.yaml:name".to_string()),
        });
        details["name"] = json!(null);
    } else {
        *score += 5;
        details["name"] = json!(n);
    }
}

/// Check the `version` field and its semver validity (10 pts).
fn check_version(
    map: Option<&serde_yaml::Mapping>,
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) {
    let Some(ver) = yaml_str_field(map, "version") else {
        issues.push(RawQualityIssue {
            severity: "high".to_string(),
            category: "helm-required-field".to_string(),
            title: "Chart.yaml missing version".to_string(),
            description: Some("The version field is required in Chart.yaml".to_string()),
            location: Some("Chart.yaml".to_string()),
        });
        details["version"] = json!(null);
        return;
    };

    if is_valid_semver(ver) {
        *score += 10;
        details["version"] = json!(ver);
        details["version_valid_semver"] = json!(true);
    } else {
        issues.push(RawQualityIssue {
            severity: "high".to_string(),
            category: "helm-required-field".to_string(),
            title: "Chart.yaml version is not valid semver".to_string(),
            description: Some(format!(
                "Version '{ver}' does not match semver format (MAJOR.MINOR.PATCH)"
            )),
            location: Some("Chart.yaml:version".to_string()),
        });
        details["version"] = json!(ver);
        details["version_valid_semver"] = json!(false);
    }
}

/// Check the `description` field (5 pts).
fn check_description(
    map: Option<&serde_yaml::Mapping>,
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) {
    if yaml_str_field(map, "description").is_some() {
        *score += 5;
        details["has_description"] = json!(true);
    } else {
        issues.push(RawQualityIssue {
            severity: "low".to_string(),
            category: "helm-recommended-field".to_string(),
            title: "Chart.yaml missing description".to_string(),
            description: Some("Adding a description improves discoverability".to_string()),
            location: Some("Chart.yaml".to_string()),
        });
        details["has_description"] = json!(false);
    }
}

/// Check the `appVersion` field (5 pts).
fn check_app_version(
    map: Option<&serde_yaml::Mapping>,
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) {
    if yaml_str_field(map, "appVersion").is_some() {
        *score += 5;
        details["has_app_version"] = json!(true);
    } else {
        issues.push(RawQualityIssue {
            severity: "low".to_string(),
            category: "helm-recommended-field".to_string(),
            title: "Chart.yaml missing appVersion".to_string(),
            description: Some(
                "appVersion indicates the version of the app the chart deploys".to_string(),
            ),
            location: Some("Chart.yaml".to_string()),
        });
        details["has_app_version"] = json!(false);
    }
}

/// Check the `maintainers` field (5 pts).
fn check_maintainers(
    map: Option<&serde_yaml::Mapping>,
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) {
    let maintainers = map
        .and_then(|m| m.get(serde_yaml::Value::String("maintainers".to_string())))
        .and_then(|v| v.as_sequence());

    match maintainers {
        Some(seq) if !seq.is_empty() => {
            *score += 5;
            details["has_maintainers"] = json!(true);
            details["maintainers_count"] = json!(seq.len());
        }
        Some(_) => {
            issues.push(RawQualityIssue {
                severity: "low".to_string(),
                category: "helm-recommended-field".to_string(),
                title: "Chart.yaml has empty maintainers list".to_string(),
                description: Some("At least one maintainer should be listed".to_string()),
                location: Some("Chart.yaml:maintainers".to_string()),
            });
            details["has_maintainers"] = json!(false);
        }
        None => {
            issues.push(RawQualityIssue {
                severity: "low".to_string(),
                category: "helm-recommended-field".to_string(),
                title: "Chart.yaml missing maintainers".to_string(),
                description: Some("Adding maintainers helps users know who to contact".to_string()),
                location: Some("Chart.yaml".to_string()),
            });
            details["has_maintainers"] = json!(false);
        }
    }
}

/// Check for the presence of values.yaml (20 pts).
fn check_values_yaml(
    has_values_yaml: bool,
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) {
    if has_values_yaml {
        *score += 20;
        details["values_yaml_found"] = json!(true);
    } else {
        issues.push(RawQualityIssue {
            severity: "low".to_string(),
            category: "helm-recommended-field".to_string(),
            title: "values.yaml is missing".to_string(),
            description: Some(
                "A values.yaml file provides default configuration values".to_string(),
            ),
            location: None,
        });
        details["values_yaml_found"] = json!(false);
    }
}

/// Check for template files in the templates/ directory (20 pts).
fn check_template_files(
    template_files: &[String],
    issues: &mut Vec<RawQualityIssue>,
    score: &mut i32,
    details: &mut serde_json::Value,
) {
    if !template_files.is_empty() {
        *score += 20;
        details["template_files_count"] = json!(template_files.len());
        details["template_files"] = json!(template_files);
    } else {
        issues.push(RawQualityIssue {
            severity: "low".to_string(),
            category: "helm-recommended-field".to_string(),
            title: "No template files found".to_string(),
            description: Some(
                "The templates/ directory should contain at least one .yaml or .tpl file"
                    .to_string(),
            ),
            location: Some("templates/".to_string()),
        });
        details["template_files_count"] = json!(0);
    }
}

/// Look up a string field in a YAML mapping by key name.
fn yaml_str_field<'a>(map: Option<&'a serde_yaml::Mapping>, key: &str) -> Option<&'a str> {
    map.and_then(|m| m.get(serde_yaml::Value::String(key.to_string())))
        .and_then(|v| v.as_str())
}

/// Validate that a string looks like a semver version: MAJOR.MINOR.PATCH with
/// optional pre-release and build metadata segments.
///
/// Examples of valid versions: "1.0.0", "0.1.0-alpha.1", "2.3.4+build.567"
fn is_valid_semver(version: &str) -> bool {
    // Regex-free semver validation for the common cases Helm uses.
    // Format: MAJOR.MINOR.PATCH[-prerelease][+buildmeta]
    let version = version.trim();
    if version.is_empty() {
        return false;
    }

    // Strip optional leading 'v' which is common but not strict semver.
    let v = version.strip_prefix('v').unwrap_or(version);

    // Strip build metadata (+...) then pre-release (-...) to isolate MAJOR.MINOR.PATCH
    let before_build = v.split_once('+').map_or(v, |(before, _)| before);
    let core = before_build
        .split_once('-')
        .map_or(before_build, |(c, _)| c);

    // Core must be exactly three dot-separated non-negative integers
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    for part in &parts {
        if part.is_empty() {
            return false;
        }
        // Reject leading zeros on multi-digit numbers (strict semver)
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::Builder;

    /// Helper: build a `.tgz` in memory from a list of (path, content) pairs.
    fn build_tgz(files: &[(&str, &[u8])]) -> Bytes {
        let mut tar_buf = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_buf);
            for (path, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
            builder.finish().unwrap();
        }

        let mut gz_buf = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut gz_buf, Compression::default());
            encoder.write_all(&tar_buf).unwrap();
            encoder.finish().unwrap();
        }

        Bytes::from(gz_buf)
    }

    #[test]
    fn test_minimal_valid_chart() {
        let chart_yaml = r#"
apiVersion: v2
name: my-chart
version: 1.0.0
description: A minimal test chart
appVersion: "1.0.0"
maintainers:
  - name: Test User
    email: test@example.com
"#;
        let values_yaml = b"replicaCount: 1\n";
        let template = b"apiVersion: v1\nkind: ConfigMap\n";

        let tgz = build_tgz(&[
            ("my-chart/Chart.yaml", chart_yaml.as_bytes()),
            ("my-chart/values.yaml", values_yaml),
            ("my-chart/templates/configmap.yaml", template),
        ]);

        let checker = HelmLintChecker;
        let output = checker.check(&tgz);

        // All 100 points: 15 + 5 + 5 + 10 + 5 + 20 + 20 + 5 + 5 + 10
        assert_eq!(output.score, 100);
        assert!(output.passed);
        assert!(
            output.issues.is_empty(),
            "Expected no issues, got: {:?}",
            output.issues
        );
    }

    #[test]
    fn test_empty_bytes() {
        let checker = HelmLintChecker;
        let output = checker.check(&Bytes::new());

        assert_eq!(output.score, 0);
        assert!(!output.passed);
        assert!(!output.issues.is_empty());
        assert_eq!(output.issues[0].severity, "critical");
        assert_eq!(output.issues[0].title, "Not a valid gzip archive");
    }

    #[test]
    fn test_random_bytes() {
        let checker = HelmLintChecker;
        let output = checker.check(&Bytes::from_static(b"this is not a gzip archive"));

        assert_eq!(output.score, 0);
        assert!(!output.passed);
        assert_eq!(output.issues.len(), 1);
        assert_eq!(output.issues[0].severity, "critical");
        assert_eq!(output.issues[0].category, "helm-structure");
    }

    #[test]
    fn test_missing_required_fields() {
        // Chart.yaml with only apiVersion (v2) -- missing name, version
        let chart_yaml = b"apiVersion: v2\n";
        let tgz = build_tgz(&[("my-chart/Chart.yaml", chart_yaml)]);

        let checker = HelmLintChecker;
        let output = checker.check(&tgz);

        // Should earn: 15 (valid Chart.yaml) + 5 (apiVersion) + 10 (not deprecated)
        // = 30 points. Missing name (5), version (10), description (5), appVersion (5),
        // maintainers (5), values.yaml (20), templates (20).
        assert_eq!(output.score, 30);
        assert!(!output.passed); // 30 < 50

        // Verify we have issues for missing fields
        let titles: Vec<&str> = output.issues.iter().map(|i| i.title.as_str()).collect();
        assert!(titles.contains(&"Chart.yaml missing name"));
        assert!(titles.contains(&"Chart.yaml missing version"));
        assert!(titles.contains(&"Chart.yaml missing description"));
        assert!(titles.contains(&"Chart.yaml missing appVersion"));
        assert!(titles.contains(&"Chart.yaml missing maintainers"));
        assert!(titles.contains(&"values.yaml is missing"));
        assert!(titles.contains(&"No template files found"));
    }

    #[test]
    fn test_deprecated_api_version() {
        let chart_yaml = r#"
apiVersion: v1
name: legacy-chart
version: 0.1.0
description: A legacy chart
"#;
        let tgz = build_tgz(&[
            ("legacy-chart/Chart.yaml", chart_yaml.as_bytes()),
            ("legacy-chart/values.yaml", b"{}"),
            ("legacy-chart/templates/deploy.yaml", b"kind: Deployment"),
        ]);

        let checker = HelmLintChecker;
        let output = checker.check(&tgz);

        // 15 (valid) + 5 (apiVersion exists) + 0 (deprecated, no +10)
        // + 5 (name) + 10 (version) + 5 (description) + 20 (values) + 20 (templates)
        // + 0 (no appVersion) + 0 (no maintainers)
        // = 80
        assert_eq!(output.score, 80);
        assert!(output.passed);

        let deprecation_issues: Vec<&RawQualityIssue> = output
            .issues
            .iter()
            .filter(|i| i.category == "helm-deprecation")
            .collect();
        assert_eq!(deprecation_issues.len(), 1);
        assert_eq!(deprecation_issues[0].severity, "medium");
    }

    #[test]
    fn test_invalid_yaml_in_chart() {
        let bad_yaml = b"apiVersion: v2\nname: [invalid yaml\n  broken: {{{\n";
        let tgz = build_tgz(&[("my-chart/Chart.yaml", bad_yaml)]);

        let checker = HelmLintChecker;
        let output = checker.check(&tgz);

        // Chart.yaml found but invalid YAML => 0 points from Chart.yaml fields
        // No values.yaml, no templates => 0 + 0
        assert_eq!(output.score, 0);
        assert!(!output.passed);

        let parse_issues: Vec<&RawQualityIssue> = output
            .issues
            .iter()
            .filter(|i| i.category == "helm-parse")
            .collect();
        assert_eq!(parse_issues.len(), 1);
        assert_eq!(parse_issues[0].severity, "critical");
    }

    #[test]
    fn test_missing_chart_yaml() {
        let tgz = build_tgz(&[
            ("my-chart/values.yaml", b"key: value"),
            ("my-chart/templates/test.yaml", b"kind: Service"),
        ]);

        let checker = HelmLintChecker;
        let output = checker.check(&tgz);

        // 0 (no Chart.yaml) + 20 (values.yaml) + 20 (templates) = 40
        assert_eq!(output.score, 40);
        assert!(!output.passed); // 40 < 50

        let missing: Vec<&RawQualityIssue> = output
            .issues
            .iter()
            .filter(|i| i.title == "Chart.yaml is missing")
            .collect();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].severity, "critical");
    }

    #[test]
    fn test_invalid_semver_version() {
        let chart_yaml = r#"
apiVersion: v2
name: bad-version
version: not-a-version
"#;
        let tgz = build_tgz(&[("chart/Chart.yaml", chart_yaml.as_bytes())]);

        let checker = HelmLintChecker;
        let output = checker.check(&tgz);

        let version_issues: Vec<&RawQualityIssue> = output
            .issues
            .iter()
            .filter(|i| i.title.contains("not valid semver"))
            .collect();
        assert_eq!(version_issues.len(), 1);
        assert_eq!(version_issues[0].severity, "high");
    }

    #[test]
    fn test_empty_name() {
        let chart_yaml = "apiVersion: v2\nname: \"\"\nversion: 1.0.0\n";
        let tgz = build_tgz(&[("chart/Chart.yaml", chart_yaml.as_bytes())]);

        let checker = HelmLintChecker;
        let output = checker.check(&tgz);

        let name_issues: Vec<&RawQualityIssue> = output
            .issues
            .iter()
            .filter(|i| i.title.contains("empty name"))
            .collect();
        assert_eq!(name_issues.len(), 1);
        assert_eq!(name_issues[0].severity, "high");
    }

    #[test]
    fn test_tpl_templates_detected() {
        let chart_yaml = b"apiVersion: v2\nname: tpl-chart\nversion: 0.1.0\n";
        let tgz = build_tgz(&[
            ("tpl-chart/Chart.yaml", chart_yaml),
            ("tpl-chart/templates/_helpers.tpl", b"{{/* helpers */}}"),
        ]);

        let checker = HelmLintChecker;
        let output = checker.check(&tgz);

        assert!(output.details["template_files_count"].as_i64().unwrap() >= 1);
        // templates score should be earned (20 pts)
        // 15 (valid) + 5 (apiVersion) + 10 (not deprecated) + 5 (name) + 10 (version) + 20 (templates) = 65
        assert!(output.score >= 65);
        assert!(output.passed);
    }

    #[test]
    fn test_checker_metadata() {
        let checker = HelmLintChecker;
        assert_eq!(checker.name(), "HelmLint");
        assert_eq!(checker.check_type(), "helm_lint");
        assert_eq!(checker.applicable_formats(), Some(vec!["helm"]));
    }

    // ---- Semver validation unit tests ----

    #[test]
    fn test_semver_valid() {
        assert!(is_valid_semver("1.0.0"));
        assert!(is_valid_semver("0.1.0"));
        assert!(is_valid_semver("10.20.30"));
        assert!(is_valid_semver("1.0.0-alpha"));
        assert!(is_valid_semver("1.0.0-alpha.1"));
        assert!(is_valid_semver("1.0.0+build.123"));
        assert!(is_valid_semver("1.0.0-beta+build"));
        assert!(is_valid_semver("v1.0.0")); // leading v tolerated
    }

    #[test]
    fn test_semver_invalid() {
        assert!(!is_valid_semver(""));
        assert!(!is_valid_semver("1"));
        assert!(!is_valid_semver("1.0"));
        assert!(!is_valid_semver("abc"));
        assert!(!is_valid_semver("1.0.0.0"));
        assert!(!is_valid_semver("01.0.0")); // leading zero
        assert!(!is_valid_semver("1.00.0")); // leading zero
    }

    // ---- decompress_gzip unit tests ----

    #[test]
    fn test_decompress_gzip_valid() {
        let original = b"hello, this is test tar data";
        let mut gz_buf = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut gz_buf, Compression::default());
            encoder.write_all(original).unwrap();
            encoder.finish().unwrap();
        }
        let result = decompress_gzip(&Bytes::from(gz_buf));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), original.to_vec());
    }

    #[test]
    fn test_decompress_gzip_invalid_data() {
        let garbage = Bytes::from_static(b"definitely not gzip");
        let result = decompress_gzip(&garbage);
        assert!(result.is_err());
        let output = result.unwrap_err();
        assert_eq!(output.score, 0);
        assert!(!output.passed);
        assert_eq!(output.issues.len(), 1);
        assert_eq!(output.issues[0].severity, "critical");
        assert_eq!(output.issues[0].title, "Not a valid gzip archive");
        assert_eq!(output.issues[0].category, "helm-structure");
    }

    #[test]
    fn test_decompress_gzip_empty_bytes() {
        let result = decompress_gzip(&Bytes::new());
        assert!(result.is_err());
        let output = result.unwrap_err();
        assert_eq!(output.score, 0);
        assert!(!output.passed);
    }

    // ---- TarInventory struct construction ----

    #[test]
    fn test_tar_inventory_defaults() {
        let inv = TarInventory {
            chart_yaml_content: None,
            has_values_yaml: false,
            template_files: Vec::new(),
        };
        assert!(inv.chart_yaml_content.is_none());
        assert!(!inv.has_values_yaml);
        assert!(inv.template_files.is_empty());
    }

    #[test]
    fn test_tar_inventory_populated() {
        let inv = TarInventory {
            chart_yaml_content: Some("apiVersion: v2\nname: test\n".to_string()),
            has_values_yaml: true,
            template_files: vec![
                "mychart/templates/deployment.yaml".to_string(),
                "mychart/templates/_helpers.tpl".to_string(),
            ],
        };
        assert!(inv.chart_yaml_content.is_some());
        assert!(inv.has_values_yaml);
        assert_eq!(inv.template_files.len(), 2);
    }

    // ---- scan_tar_entries unit tests ----

    /// Helper: build raw tar bytes (not gzipped) from file entries.
    fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_buf);
            for (path, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        tar_buf
    }

    #[test]
    fn test_scan_tar_entries_full_chart() {
        let chart_yaml = b"apiVersion: v2\nname: test\nversion: 1.0.0\n";
        let tar_bytes = build_tar(&[
            ("test/Chart.yaml", chart_yaml),
            ("test/values.yaml", b"key: val"),
            ("test/templates/deploy.yaml", b"kind: Deployment"),
            ("test/templates/_helpers.tpl", b"{{/* helpers */}}"),
        ]);

        let result = scan_tar_entries(&tar_bytes);
        assert!(result.is_ok());
        let inv = result.unwrap();
        assert!(inv.chart_yaml_content.is_some());
        assert_eq!(
            inv.chart_yaml_content.as_deref().unwrap(),
            "apiVersion: v2\nname: test\nversion: 1.0.0\n"
        );
        assert!(inv.has_values_yaml);
        assert_eq!(inv.template_files.len(), 2);
    }

    #[test]
    fn test_scan_tar_entries_no_chart_yaml() {
        let tar_bytes = build_tar(&[
            ("test/values.yaml", b"key: val"),
            ("test/templates/svc.yaml", b"kind: Service"),
        ]);

        let inv = scan_tar_entries(&tar_bytes).unwrap();
        assert!(inv.chart_yaml_content.is_none());
        assert!(inv.has_values_yaml);
        assert_eq!(inv.template_files.len(), 1);
    }

    #[test]
    fn test_scan_tar_entries_root_level_chart_yaml() {
        let tar_bytes = build_tar(&[("Chart.yaml", b"apiVersion: v2\n")]);

        let inv = scan_tar_entries(&tar_bytes).unwrap();
        assert!(inv.chart_yaml_content.is_some());
        assert!(!inv.has_values_yaml);
        assert!(inv.template_files.is_empty());
    }

    #[test]
    fn test_scan_tar_entries_root_level_values_yaml() {
        let tar_bytes = build_tar(&[("values.yaml", b"key: val")]);

        let inv = scan_tar_entries(&tar_bytes).unwrap();
        assert!(inv.has_values_yaml);
    }

    #[test]
    fn test_scan_tar_entries_root_level_templates() {
        let tar_bytes = build_tar(&[("templates/deploy.yaml", b"kind: Deployment")]);

        let inv = scan_tar_entries(&tar_bytes).unwrap();
        assert_eq!(inv.template_files.len(), 1);
        assert_eq!(inv.template_files[0], "templates/deploy.yaml");
    }

    #[test]
    fn test_scan_tar_entries_non_template_files_ignored() {
        let tar_bytes = build_tar(&[
            ("test/templates/notes.txt", b"not a template"),
            ("test/templates/readme.md", b"# readme"),
            ("test/random.yaml", b"not in templates dir"),
        ]);

        let inv = scan_tar_entries(&tar_bytes).unwrap();
        assert!(inv.template_files.is_empty());
    }

    #[test]
    fn test_scan_tar_entries_invalid_tar() {
        let result = scan_tar_entries(b"this is not a tar archive");
        // The tar crate may or may not error on entries() vs iteration,
        // but eventually we should get an empty or errored inventory.
        // With garbage data, Archive::new doesn't fail but entries iteration
        // may just yield nothing or an error.
        match result {
            Ok(inv) => {
                // If it doesn't error, it should at least have empty fields
                assert!(inv.chart_yaml_content.is_none());
                assert!(!inv.has_values_yaml);
                assert!(inv.template_files.is_empty());
            }
            Err(output) => {
                assert_eq!(output.score, 0);
                assert!(!output.passed);
            }
        }
    }

    // ---- evaluate_chart_yaml unit tests ----

    #[test]
    fn test_evaluate_chart_yaml_none() {
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        let result = evaluate_chart_yaml(&None, &mut issues, &mut score, &mut details);

        assert!(result.is_none());
        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml is missing");
        assert_eq!(issues[0].severity, "critical");
        assert_eq!(details["chart_yaml_found"], json!(false));
    }

    #[test]
    fn test_evaluate_chart_yaml_valid() {
        let content = Some("apiVersion: v2\nname: test\n".to_string());
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        let result = evaluate_chart_yaml(&content, &mut issues, &mut score, &mut details);

        assert!(result.is_some());
        assert_eq!(score, 15);
        assert!(issues.is_empty());
        assert_eq!(details["chart_yaml_found"], json!(true));
        assert_eq!(details["chart_yaml_valid"], json!(true));
    }

    #[test]
    fn test_evaluate_chart_yaml_invalid_yaml() {
        let content = Some("apiVersion: v2\nname: [broken\n".to_string());
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        let result = evaluate_chart_yaml(&content, &mut issues, &mut score, &mut details);

        assert!(result.is_none());
        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml contains invalid YAML");
        assert_eq!(issues[0].severity, "critical");
        assert_eq!(issues[0].category, "helm-parse");
        assert_eq!(details["chart_yaml_found"], json!(true));
        assert_eq!(details["chart_yaml_valid"], json!(false));
    }

    // ---- check_api_version unit tests ----

    fn make_yaml_mapping(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn test_check_api_version_v2() {
        let val = make_yaml_mapping("apiVersion: v2\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_api_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 15); // 5 for apiVersion + 10 for not deprecated
        assert!(issues.is_empty());
        assert_eq!(details["api_version"], json!("v2"));
        assert_eq!(details["api_version_deprecated"], json!(false));
    }

    #[test]
    fn test_check_api_version_v1_deprecated() {
        let val = make_yaml_mapping("apiVersion: v1\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_api_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 5); // 5 for apiVersion, no +10 because deprecated
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].category, "helm-deprecation");
        assert_eq!(issues[0].severity, "medium");
        assert_eq!(details["api_version"], json!("v1"));
        assert_eq!(details["api_version_deprecated"], json!(true));
    }

    #[test]
    fn test_check_api_version_missing() {
        let val = make_yaml_mapping("name: something\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_api_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml missing apiVersion");
        assert_eq!(issues[0].severity, "high");
        assert_eq!(details["api_version"], json!(null));
    }

    #[test]
    fn test_check_api_version_none_map() {
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_api_version(None, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml missing apiVersion");
    }

    // ---- check_name unit tests ----

    #[test]
    fn test_check_name_present() {
        let val = make_yaml_mapping("name: my-chart\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_name(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 5);
        assert!(issues.is_empty());
        assert_eq!(details["name"], json!("my-chart"));
    }

    #[test]
    fn test_check_name_empty() {
        let val = make_yaml_mapping("name: \"\"\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_name(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml has empty name");
        assert_eq!(details["name"], json!(null));
    }

    #[test]
    fn test_check_name_missing() {
        let val = make_yaml_mapping("apiVersion: v2\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_name(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml missing name");
        assert_eq!(issues[0].severity, "high");
    }

    // ---- check_version unit tests ----

    #[test]
    fn test_check_version_valid_semver() {
        let val = make_yaml_mapping("version: 1.2.3\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 10);
        assert!(issues.is_empty());
        assert_eq!(details["version"], json!("1.2.3"));
        assert_eq!(details["version_valid_semver"], json!(true));
    }

    #[test]
    fn test_check_version_invalid_semver() {
        let val = make_yaml_mapping("version: not-a-version\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].title.contains("not valid semver"));
        assert_eq!(details["version"], json!("not-a-version"));
        assert_eq!(details["version_valid_semver"], json!(false));
    }

    #[test]
    fn test_check_version_missing() {
        let val = make_yaml_mapping("name: test\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml missing version");
        assert_eq!(details["version"], json!(null));
    }

    #[test]
    fn test_check_version_prerelease() {
        let val = make_yaml_mapping("version: 1.0.0-beta.1\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 10);
        assert!(issues.is_empty());
        assert_eq!(details["version_valid_semver"], json!(true));
    }

    // ---- check_description unit tests ----

    #[test]
    fn test_check_description_present() {
        let val = make_yaml_mapping("description: A Helm chart for testing\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_description(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 5);
        assert!(issues.is_empty());
        assert_eq!(details["has_description"], json!(true));
    }

    #[test]
    fn test_check_description_missing() {
        let val = make_yaml_mapping("name: test\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_description(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml missing description");
        assert_eq!(issues[0].severity, "low");
        assert_eq!(details["has_description"], json!(false));
    }

    // ---- check_app_version unit tests ----

    #[test]
    fn test_check_app_version_present() {
        let val = make_yaml_mapping("appVersion: \"2.0.0\"\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_app_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 5);
        assert!(issues.is_empty());
        assert_eq!(details["has_app_version"], json!(true));
    }

    #[test]
    fn test_check_app_version_missing() {
        let val = make_yaml_mapping("name: test\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_app_version(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml missing appVersion");
        assert_eq!(issues[0].severity, "low");
        assert_eq!(details["has_app_version"], json!(false));
    }

    // ---- check_maintainers unit tests ----

    #[test]
    fn test_check_maintainers_present() {
        let yaml = "maintainers:\n  - name: Alice\n    email: alice@example.com\n";
        let val = make_yaml_mapping(yaml);
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_maintainers(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 5);
        assert!(issues.is_empty());
        assert_eq!(details["has_maintainers"], json!(true));
        assert_eq!(details["maintainers_count"], json!(1));
    }

    #[test]
    fn test_check_maintainers_multiple() {
        let yaml = "maintainers:\n  - name: Alice\n  - name: Bob\n  - name: Charlie\n";
        let val = make_yaml_mapping(yaml);
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_maintainers(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 5);
        assert!(issues.is_empty());
        assert_eq!(details["maintainers_count"], json!(3));
    }

    #[test]
    fn test_check_maintainers_empty_list() {
        let yaml = "maintainers: []\n";
        let val = make_yaml_mapping(yaml);
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_maintainers(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml has empty maintainers list");
        assert_eq!(details["has_maintainers"], json!(false));
    }

    #[test]
    fn test_check_maintainers_missing() {
        let val = make_yaml_mapping("name: test\n");
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_maintainers(map, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml missing maintainers");
        assert_eq!(issues[0].severity, "low");
        assert_eq!(details["has_maintainers"], json!(false));
    }

    #[test]
    fn test_check_maintainers_none_map() {
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_maintainers(None, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "Chart.yaml missing maintainers");
    }

    // ---- check_values_yaml unit tests ----

    #[test]
    fn test_check_values_yaml_present() {
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_values_yaml(true, &mut issues, &mut score, &mut details);

        assert_eq!(score, 20);
        assert!(issues.is_empty());
        assert_eq!(details["values_yaml_found"], json!(true));
    }

    #[test]
    fn test_check_values_yaml_missing() {
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_values_yaml(false, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "values.yaml is missing");
        assert_eq!(issues[0].severity, "low");
        assert_eq!(details["values_yaml_found"], json!(false));
    }

    // ---- check_template_files unit tests ----

    #[test]
    fn test_check_template_files_present() {
        let templates = vec![
            "mychart/templates/deployment.yaml".to_string(),
            "mychart/templates/service.yaml".to_string(),
        ];
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_template_files(&templates, &mut issues, &mut score, &mut details);

        assert_eq!(score, 20);
        assert!(issues.is_empty());
        assert_eq!(details["template_files_count"], json!(2));
        assert_eq!(
            details["template_files"],
            json!([
                "mychart/templates/deployment.yaml",
                "mychart/templates/service.yaml"
            ])
        );
    }

    #[test]
    fn test_check_template_files_single() {
        let templates = vec!["chart/templates/_helpers.tpl".to_string()];
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_template_files(&templates, &mut issues, &mut score, &mut details);

        assert_eq!(score, 20);
        assert!(issues.is_empty());
        assert_eq!(details["template_files_count"], json!(1));
    }

    #[test]
    fn test_check_template_files_empty() {
        let templates: Vec<String> = Vec::new();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_template_files(&templates, &mut issues, &mut score, &mut details);

        assert_eq!(score, 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].title, "No template files found");
        assert_eq!(issues[0].severity, "low");
        assert_eq!(details["template_files_count"], json!(0));
    }

    // ---- Score accumulation tests ----

    #[test]
    fn test_check_functions_accumulate_scores() {
        // Verify that calling multiple check functions accumulates the score
        // on a shared mutable reference, as the production code does.
        let yaml = r#"
apiVersion: v2
name: accumulation-test
version: 2.0.0
description: Testing score accumulation
appVersion: "1.0.0"
maintainers:
  - name: Tester
"#;
        let val = make_yaml_mapping(yaml);
        let map = val.as_mapping();
        let mut issues = Vec::new();
        let mut score = 0;
        let mut details = json!({});

        check_api_version(map, &mut issues, &mut score, &mut details);
        assert_eq!(score, 15); // 5 + 10

        check_name(map, &mut issues, &mut score, &mut details);
        assert_eq!(score, 20); // 15 + 5

        check_version(map, &mut issues, &mut score, &mut details);
        assert_eq!(score, 30); // 20 + 10

        check_description(map, &mut issues, &mut score, &mut details);
        assert_eq!(score, 35); // 30 + 5

        check_app_version(map, &mut issues, &mut score, &mut details);
        assert_eq!(score, 40); // 35 + 5

        check_maintainers(map, &mut issues, &mut score, &mut details);
        assert_eq!(score, 45); // 40 + 5

        check_values_yaml(true, &mut issues, &mut score, &mut details);
        assert_eq!(score, 65); // 45 + 20

        check_template_files(
            &["chart/templates/deploy.yaml".to_string()],
            &mut issues,
            &mut score,
            &mut details,
        );
        assert_eq!(score, 85); // 65 + 20

        // Total without the 15 from evaluate_chart_yaml = 85
        // With evaluate_chart_yaml it would be 100
        assert!(issues.is_empty());
    }
}
