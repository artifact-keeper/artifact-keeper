//! Metadata completeness quality checker.
//!
//! Evaluates how complete an artifact's metadata is across five categories:
//! version, description, license, author/maintainer, and documentation links.
//! Format-agnostic — applies to all artifact types.

use serde_json::{json, Value};

use crate::models::quality::{QualityCheckOutput, RawQualityIssue};

const POINTS_VERSION: i32 = 20;
const POINTS_DESCRIPTION: i32 = 20;
const POINTS_LICENSE: i32 = 30;
const POINTS_AUTHOR: i32 = 15;
const POINTS_DOCS: i32 = 15;

const PASSING_THRESHOLD: i32 = 50;

/// Quality checker that scores an artifact based on the completeness of its
/// metadata fields. Designed to work across all 45+ package formats without
/// format-specific knowledge — it inspects common metadata keys that every
/// well-published package should provide.
pub struct MetadataCompletenessChecker;

impl MetadataCompletenessChecker {
    /// Human-readable checker name.
    pub fn name(&self) -> &str {
        "MetadataCompleteness"
    }

    /// Machine-readable check type stored in quality_check_results.
    pub fn check_type(&self) -> &str {
        "metadata_completeness"
    }

    /// Returns `None` because this checker applies to all formats.
    pub fn applicable_formats(&self) -> Option<Vec<&str>> {
        None
    }

    /// Evaluate metadata completeness for an artifact.
    ///
    /// The checker does **not** need the artifact content bytes — only the
    /// artifact name, optional version string, and the metadata JSON that was
    /// extracted when the artifact was published.
    pub fn check(
        &self,
        artifact_name: &str,
        artifact_version: Option<&str>,
        metadata_json: Option<&Value>,
    ) -> QualityCheckOutput {
        let mut score: i32 = 0;
        let mut issues: Vec<RawQualityIssue> = Vec::new();

        // 1. Version present (20 pts)
        let has_version = artifact_version.is_some_and(|v| !v.is_empty());
        if has_version {
            score += POINTS_VERSION;
        } else {
            issues.push(RawQualityIssue {
                severity: "low".to_string(),
                category: "missing-metadata".to_string(),
                title: "Missing version".to_string(),
                description: Some(format!(
                    "Artifact '{}' has no version. Publish with an explicit version \
                     to enable reproducible builds and dependency resolution.",
                    artifact_name,
                )),
                location: None,
            });
        }

        // 2. Description present (20 pts)
        let has_description = metadata_json
            .and_then(|m| m.get("description"))
            .is_some_and(is_non_empty_string);
        if has_description {
            score += POINTS_DESCRIPTION;
        } else {
            issues.push(RawQualityIssue {
                severity: "low".to_string(),
                category: "missing-metadata".to_string(),
                title: "Missing description".to_string(),
                description: Some(format!(
                    "Artifact '{}' has no description. A short summary helps users \
                     understand the package's purpose when browsing the registry.",
                    artifact_name,
                )),
                location: None,
            });
        }

        // 3. License declared (30 pts)
        let has_license = metadata_json.is_some_and(|m| {
            has_non_empty_field(m, "license") || has_non_empty_field(m, "licenses")
        });
        if has_license {
            score += POINTS_LICENSE;
        } else {
            issues.push(RawQualityIssue {
                severity: "medium".to_string(),
                category: "missing-metadata".to_string(),
                title: "Missing license declaration".to_string(),
                description: Some(format!(
                    "Artifact '{}' does not declare a license. Without a license, \
                     consumers cannot determine whether they are legally permitted to \
                     use this package. Add a 'license' field (e.g., \"MIT\", \"Apache-2.0\").",
                    artifact_name,
                )),
                location: None,
            });
        }

        // 4. Author / maintainer (15 pts)
        let has_author = metadata_json.is_some_and(|m| {
            has_non_empty_field(m, "author")
                || has_non_empty_field(m, "maintainer")
                || has_non_empty_field(m, "authors")
                || has_non_empty_field(m, "maintainers")
        });
        if has_author {
            score += POINTS_AUTHOR;
        } else {
            issues.push(RawQualityIssue {
                severity: "low".to_string(),
                category: "missing-metadata".to_string(),
                title: "Missing author or maintainer".to_string(),
                description: Some(format!(
                    "Artifact '{}' does not specify an author or maintainer. \
                     Including contact information builds trust and helps users \
                     report issues.",
                    artifact_name,
                )),
                location: None,
            });
        }

        // 5. README / documentation link (15 pts)
        let has_docs = metadata_json.is_some_and(|m| {
            has_non_empty_field(m, "readme")
                || has_non_empty_field(m, "homepage")
                || has_non_empty_field(m, "documentation")
                || has_non_empty_field(m, "home")
                || has_non_empty_field(m, "url")
        });
        if has_docs {
            score += POINTS_DOCS;
        } else {
            issues.push(RawQualityIssue {
                severity: "low".to_string(),
                category: "missing-metadata".to_string(),
                title: "Missing documentation or homepage link".to_string(),
                description: Some(format!(
                    "Artifact '{}' has no README, homepage, or documentation URL. \
                     Providing at least one of these helps users get started quickly.",
                    artifact_name,
                )),
                location: None,
            });
        }

        let details = json!({
            "has_version": has_version,
            "has_description": has_description,
            "has_license": has_license,
            "has_author": has_author,
            "has_docs": has_docs,
        });

        QualityCheckOutput {
            score,
            passed: score >= PASSING_THRESHOLD,
            issues,
            details,
        }
    }
}

/// Returns `true` if `val` is a non-empty JSON string.
fn is_non_empty_string(val: &Value) -> bool {
    match val {
        Value::String(s) => !s.trim().is_empty(),
        _ => false,
    }
}

/// Returns `true` if `obj[key]` exists and is "non-empty":
/// - String values must be non-blank.
/// - Arrays must have at least one element.
/// - Objects are considered present.
/// - Null and missing are considered absent.
fn has_non_empty_field(obj: &Value, key: &str) -> bool {
    match obj.get(key) {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Array(arr)) => !arr.is_empty(),
        Some(Value::Object(_)) => true,
        Some(Value::Bool(_)) | Some(Value::Number(_)) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn checker() -> MetadataCompletenessChecker {
        MetadataCompletenessChecker
    }

    #[test]
    fn test_full_metadata_score_100() {
        let metadata = json!({
            "description": "A fantastic library for doing things",
            "license": "MIT",
            "author": "Jane Doe <jane@example.com>",
            "homepage": "https://example.com/my-lib"
        });

        let result = checker().check("my-lib", Some("1.0.0"), Some(&metadata));

        assert_eq!(result.score, 100);
        assert!(result.passed);
        assert!(result.issues.is_empty());

        // Verify details flags
        assert_eq!(result.details["has_version"], json!(true));
        assert_eq!(result.details["has_description"], json!(true));
        assert_eq!(result.details["has_license"], json!(true));
        assert_eq!(result.details["has_author"], json!(true));
        assert_eq!(result.details["has_docs"], json!(true));
    }

    #[test]
    fn test_empty_metadata_score_0() {
        let metadata = json!({});

        let result = checker().check("empty-pkg", None, Some(&metadata));

        assert_eq!(result.score, 0);
        assert!(!result.passed);
        assert_eq!(result.issues.len(), 5);

        // Verify all details flags are false
        assert_eq!(result.details["has_version"], json!(false));
        assert_eq!(result.details["has_description"], json!(false));
        assert_eq!(result.details["has_license"], json!(false));
        assert_eq!(result.details["has_author"], json!(false));
        assert_eq!(result.details["has_docs"], json!(false));

        // Check that license issue is medium severity, others are low
        let license_issue = result
            .issues
            .iter()
            .find(|i| i.title.contains("license"))
            .expect("should have a license issue");
        assert_eq!(license_issue.severity, "medium");

        for issue in &result.issues {
            assert_eq!(issue.category, "missing-metadata");
            if !issue.title.contains("license") {
                assert_eq!(issue.severity, "low");
            }
        }
    }

    #[test]
    fn test_partial_metadata_version_and_license() {
        // version (20) + license (30) = 50 => passes threshold
        let metadata = json!({
            "license": "Apache-2.0"
        });

        let result = checker().check("partial-pkg", Some("0.1.0"), Some(&metadata));

        assert_eq!(result.score, 50);
        assert!(result.passed);
        // Missing: description, author, docs
        assert_eq!(result.issues.len(), 3);

        assert_eq!(result.details["has_version"], json!(true));
        assert_eq!(result.details["has_description"], json!(false));
        assert_eq!(result.details["has_license"], json!(true));
        assert_eq!(result.details["has_author"], json!(false));
        assert_eq!(result.details["has_docs"], json!(false));
    }

    #[test]
    fn test_no_metadata_json() {
        let result = checker().check("bare-pkg", Some("1.0.0"), None);

        // Only version is present (20 pts)
        assert_eq!(result.score, 20);
        assert!(!result.passed);
        assert_eq!(result.issues.len(), 4);
    }

    #[test]
    fn test_empty_version_string_is_missing() {
        let metadata = json!({
            "description": "Has a description",
            "license": "MIT",
            "author": "Someone",
            "homepage": "https://example.com"
        });

        let result = checker().check("pkg", Some(""), Some(&metadata));

        // Everything except version => 80
        assert_eq!(result.score, 80);
        assert!(result.passed);
        assert_eq!(result.issues.len(), 1);
        assert!(result.issues[0].title.contains("version"));
    }

    #[test]
    fn test_licenses_array_is_accepted() {
        let metadata = json!({
            "licenses": [{"type": "MIT"}]
        });

        let result = checker().check("pkg", Some("1.0.0"), Some(&metadata));

        assert_eq!(result.details["has_license"], json!(true));
        // version (20) + license (30) = 50
        assert_eq!(result.score, 50);
    }

    #[test]
    fn test_maintainers_field_is_accepted() {
        let metadata = json!({
            "maintainers": ["alice@example.com"]
        });

        let result = checker().check("pkg", Some("1.0.0"), Some(&metadata));

        assert_eq!(result.details["has_author"], json!(true));
        // version (20) + author (15) = 35
        assert_eq!(result.score, 35);
    }

    #[test]
    fn test_documentation_url_counts_as_docs() {
        let metadata = json!({
            "documentation": "https://docs.rs/my-crate"
        });

        let result = checker().check("pkg", Some("1.0.0"), Some(&metadata));

        assert_eq!(result.details["has_docs"], json!(true));
        // version (20) + docs (15) = 35
        assert_eq!(result.score, 35);
    }

    #[test]
    fn test_whitespace_only_strings_are_empty() {
        let metadata = json!({
            "description": "   ",
            "license": "\t\n",
            "author": "",
        });

        let result = checker().check("pkg", Some("1.0.0"), Some(&metadata));

        // Only version counts (20 pts)
        assert_eq!(result.score, 20);
        assert_eq!(result.details["has_description"], json!(false));
        assert_eq!(result.details["has_license"], json!(false));
        assert_eq!(result.details["has_author"], json!(false));
    }

    #[test]
    fn test_checker_identity() {
        let c = checker();
        assert_eq!(c.name(), "MetadataCompleteness");
        assert_eq!(c.check_type(), "metadata_completeness");
        assert!(c.applicable_formats().is_none());
    }
}
