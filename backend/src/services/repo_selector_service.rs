//! Shared repository selector service.
//!
//! Provides the `RepoSelector` type and resolution logic used by both
//! sync policies (to select which repos to replicate) and service account
//! tokens (to restrict which repos a token can access).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Repository selector: determines which repositories match a set of criteria.
///
/// Used by sync policies and token repository scoping. All non-empty fields
/// are combined with AND semantics (a repo must pass every active filter).
/// Within `match_formats`, items use OR semantics (any format matches).
/// Within `match_labels`, items use AND semantics (all labels must match).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoSelector {
    /// Label key-value pairs that must all match (AND semantics).
    #[serde(default)]
    pub match_labels: HashMap<String, String>,
    /// Repository format types to include (e.g. "docker", "maven"). OR semantics.
    #[serde(default)]
    pub match_formats: Vec<String>,
    /// Glob-like name pattern (e.g. "libs-*"). Only `*` wildcard supported,
    /// translated to SQL `LIKE` with `%`.
    #[serde(default)]
    pub match_pattern: Option<String>,
    /// Explicit repository UUIDs to include.
    #[serde(default)]
    pub match_repos: Vec<Uuid>,
}

/// A repository matched by a selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRepo {
    pub id: Uuid,
    pub key: String,
    pub format: String,
}

// Internal row types for sqlx queries.
#[derive(Debug, sqlx::FromRow)]
struct RepoRow {
    id: Uuid,
    key: String,
    format: String,
}

#[derive(Debug, sqlx::FromRow)]
struct LabelRow {
    repository_id: Uuid,
    label_key: String,
    label_value: String,
}

/// Service for resolving repository selectors to concrete repository lists.
pub struct RepoSelectorService {
    db: PgPool,
}

impl RepoSelectorService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Check if a selector is empty (would match nothing).
    pub fn is_empty(selector: &RepoSelector) -> bool {
        selector.match_labels.is_empty()
            && selector.match_formats.is_empty()
            && selector.match_pattern.is_none()
            && selector.match_repos.is_empty()
    }

    /// Resolve repositories matching a selector. Returns matched repo details.
    pub async fn resolve(&self, selector: &RepoSelector) -> Result<Vec<MatchedRepo>> {
        let rows = self.resolve_rows(selector).await?;
        Ok(rows
            .into_iter()
            .map(|r| MatchedRepo {
                id: r.id,
                key: r.key,
                format: r.format,
            })
            .collect())
    }

    /// Resolve just the IDs (convenience for the auth path).
    pub async fn resolve_ids(&self, selector: &RepoSelector) -> Result<Vec<Uuid>> {
        let rows = self.resolve_rows(selector).await?;
        Ok(rows.into_iter().map(|r| r.id).collect())
    }

    /// Core resolution logic.
    async fn resolve_rows(&self, selector: &RepoSelector) -> Result<Vec<RepoRow>> {
        // If explicit repo IDs are given, use them directly
        if !selector.match_repos.is_empty() {
            let repos: Vec<RepoRow> = sqlx::query_as(
                r#"
                SELECT id, key, format::TEXT
                FROM repositories
                WHERE id = ANY($1)
                "#,
            )
            .bind(&selector.match_repos)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(repos);
        }

        // Start with all repositories
        let mut all_repos: Vec<RepoRow> =
            sqlx::query_as("SELECT id, key, format::TEXT FROM repositories ORDER BY key")
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        let has_any_filter = !selector.match_labels.is_empty()
            || !selector.match_formats.is_empty()
            || selector.match_pattern.is_some();

        // Empty selector with no filters matches nothing
        if !has_any_filter {
            return Ok(vec![]);
        }

        // Filter by format (OR semantics)
        if !selector.match_formats.is_empty() {
            let formats: Vec<String> = selector
                .match_formats
                .iter()
                .map(|f| f.to_lowercase())
                .collect();
            all_repos.retain(|r| formats.contains(&r.format.to_lowercase()));
        }

        // Filter by name pattern (glob: * -> %)
        if let Some(pattern) = &selector.match_pattern {
            let sql_pattern = pattern.replace('*', "%");
            all_repos.retain(|r| sql_like_match(&r.key, &sql_pattern));
        }

        // Filter by labels (AND semantics: all label pairs must match)
        if !selector.match_labels.is_empty() {
            let label_repo_ids = self.resolve_repos_by_labels(&selector.match_labels).await?;
            all_repos.retain(|r| label_repo_ids.contains(&r.id));
        }

        Ok(all_repos)
    }

    /// Find repository IDs that have all the given labels.
    async fn resolve_repos_by_labels(&self, labels: &HashMap<String, String>) -> Result<Vec<Uuid>> {
        if labels.is_empty() {
            return Ok(vec![]);
        }

        let all_labels: Vec<LabelRow> =
            sqlx::query_as("SELECT repository_id, label_key, label_value FROM repository_labels")
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        // Group labels by repository
        let mut repo_labels: HashMap<Uuid, Vec<(&str, &str)>> = HashMap::new();
        for row in &all_labels {
            repo_labels
                .entry(row.repository_id)
                .or_default()
                .push((&row.label_key, &row.label_value));
        }

        // Find repos that have ALL required labels
        let mut matching: Vec<Uuid> = Vec::new();
        for (repo_id, repo_label_list) in &repo_labels {
            let all_match = labels
                .iter()
                .all(|(k, v)| repo_label_list.iter().any(|(lk, lv)| lk == k && lv == v));
            if all_match {
                matching.push(*repo_id);
            }
        }

        Ok(matching)
    }
}

/// Simple SQL LIKE pattern matching for in-memory filtering.
/// Supports `%` as wildcard (matches zero or more characters).
pub fn sql_like_match(value: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('%').collect();

    if parts.len() == 1 {
        // No wildcards: exact match
        return value == pattern;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // Must start with this prefix
            if !value.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Must end with this suffix
            if !value[pos..].ends_with(part) {
                return false;
            }
            pos = value.len();
        } else {
            // Must contain this part somewhere after pos
            match value[pos..].find(part) {
                Some(found) => pos += found + part.len(),
                None => return false,
            }
        }
    }

    true
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn glob_to_sql_pattern(glob: &str) -> String {
        glob.replace('*', "%")
    }

    fn filter_repos_by_format(repo_formats: &[(&str,)], selector_formats: &[String]) -> Vec<usize> {
        let formats: Vec<String> = selector_formats.iter().map(|f| f.to_lowercase()).collect();
        repo_formats
            .iter()
            .enumerate()
            .filter(|(_, (fmt,))| formats.contains(&fmt.to_lowercase()))
            .map(|(i, _)| i)
            .collect()
    }

    fn has_any_filter(selector: &RepoSelector) -> bool {
        !selector.match_labels.is_empty()
            || !selector.match_formats.is_empty()
            || selector.match_pattern.is_some()
    }

    fn match_labels_all(
        repo_label_list: &[(&str, &str)],
        required: &HashMap<String, String>,
    ) -> bool {
        required
            .iter()
            .all(|(k, v)| repo_label_list.iter().any(|(lk, lv)| lk == k && lv == v))
    }

    #[test]
    fn test_empty_selector_is_empty() {
        assert!(RepoSelectorService::is_empty(&RepoSelector::default()));
    }

    #[test]
    fn test_selector_with_formats_is_not_empty() {
        let sel = RepoSelector {
            match_formats: vec!["docker".to_string()],
            ..Default::default()
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_selector_with_labels_is_not_empty() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        let sel = RepoSelector {
            match_labels: labels,
            ..Default::default()
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_selector_with_pattern_is_not_empty() {
        let sel = RepoSelector {
            match_pattern: Some("libs-*".to_string()),
            ..Default::default()
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_selector_with_repos_is_not_empty() {
        let sel = RepoSelector {
            match_repos: vec![Uuid::new_v4()],
            ..Default::default()
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_repo_selector_serde_roundtrip() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "production".to_string());
        labels.insert("team".to_string(), "platform".to_string());

        let sel = RepoSelector {
            match_labels: labels,
            match_formats: vec!["docker".to_string(), "npm".to_string()],
            match_pattern: Some("libs-*".to_string()),
            match_repos: vec![],
        };

        let json = serde_json::to_value(&sel).unwrap();
        let deserialized: RepoSelector = serde_json::from_value(json).unwrap();

        assert_eq!(deserialized.match_labels.len(), 2);
        assert_eq!(deserialized.match_formats.len(), 2);
        assert_eq!(deserialized.match_pattern.as_deref(), Some("libs-*"));
        assert!(deserialized.match_repos.is_empty());
    }

    #[test]
    fn test_sql_like_match_exact() {
        assert!(sql_like_match("hello", "hello"));
        assert!(!sql_like_match("hello", "world"));
    }

    #[test]
    fn test_sql_like_match_prefix() {
        assert!(sql_like_match("libs-docker-prod", "libs-%"));
        assert!(!sql_like_match("test-docker", "libs-%"));
    }

    #[test]
    fn test_sql_like_match_suffix() {
        assert!(sql_like_match("libs-docker-prod", "%-prod"));
        assert!(!sql_like_match("libs-docker-dev", "%-prod"));
    }

    #[test]
    fn test_sql_like_match_contains() {
        assert!(sql_like_match("libs-docker-prod", "%docker%"));
        assert!(!sql_like_match("libs-maven-prod", "%docker%"));
    }

    #[test]
    fn test_sql_like_match_wildcard_all() {
        assert!(sql_like_match("anything", "%"));
    }

    #[test]
    fn test_sql_like_match_multi_wildcard() {
        assert!(sql_like_match("libs-docker-prod", "libs%docker%"));
        assert!(sql_like_match("libs-docker-prod", "%docker%prod"));
        assert!(sql_like_match("a-b-c-d", "a%b%d"));
        assert!(!sql_like_match("a-b-c-d", "a%x%d"));
    }

    #[test]
    fn test_sql_like_match_prefix_and_suffix() {
        assert!(sql_like_match("libs-docker-prod", "libs%prod"));
        assert!(!sql_like_match("libs-docker-dev", "libs%prod"));
    }

    #[test]
    fn test_sql_like_match_empty_value() {
        assert!(sql_like_match("", "%"));
        assert!(sql_like_match("", ""));
        assert!(!sql_like_match("", "a"));
    }

    #[test]
    fn test_sql_like_match_empty_pattern() {
        assert!(sql_like_match("", ""));
        assert!(!sql_like_match("abc", ""));
    }

    #[test]
    fn test_sql_like_match_consecutive_wildcards() {
        assert!(sql_like_match("abc", "%%"));
        assert!(sql_like_match("abc", "%%%"));
        assert!(sql_like_match("", "%%"));
    }

    #[test]
    fn test_sql_like_match_wildcard_at_start_middle_end() {
        assert!(sql_like_match("one-two-three", "%two%"));
        assert!(!sql_like_match("one-two-three", "%four%"));
    }

    #[test]
    fn test_sql_like_match_no_wildcard_mismatch_length() {
        assert!(!sql_like_match("ab", "abc"));
        assert!(!sql_like_match("abc", "ab"));
    }

    #[test]
    fn test_sql_like_match_complex_multi_segment() {
        assert!(sql_like_match("abc-def-ghi-jkl", "abc%ghi%"));
        assert!(sql_like_match("abc-def-ghi-jkl", "%def%jkl"));
        assert!(!sql_like_match("abc-def-ghi-jkl", "%xyz%jkl"));
    }

    #[test]
    fn test_glob_to_sql_pattern() {
        assert_eq!(glob_to_sql_pattern("libs-*"), "libs-%");
        assert_eq!(glob_to_sql_pattern("*-prod"), "%-prod");
        assert_eq!(glob_to_sql_pattern("*docker*"), "%docker%");
        assert_eq!(glob_to_sql_pattern("exact"), "exact");
        assert_eq!(glob_to_sql_pattern("*"), "%");
        assert_eq!(glob_to_sql_pattern("a*b*c"), "a%b%c");
    }

    #[test]
    fn test_has_any_filter_empty() {
        assert!(!has_any_filter(&RepoSelector::default()));
    }

    #[test]
    fn test_has_any_filter_with_labels() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        let sel = RepoSelector {
            match_labels: labels,
            ..Default::default()
        };
        assert!(has_any_filter(&sel));
    }

    #[test]
    fn test_has_any_filter_with_formats() {
        let sel = RepoSelector {
            match_formats: vec!["docker".to_string()],
            ..Default::default()
        };
        assert!(has_any_filter(&sel));
    }

    #[test]
    fn test_has_any_filter_with_pattern() {
        let sel = RepoSelector {
            match_pattern: Some("libs-*".to_string()),
            ..Default::default()
        };
        assert!(has_any_filter(&sel));
    }

    #[test]
    fn test_has_any_filter_with_repos_only() {
        let sel = RepoSelector {
            match_repos: vec![Uuid::new_v4()],
            ..Default::default()
        };
        assert!(!has_any_filter(&sel));
    }

    #[test]
    fn test_filter_repos_by_format_case_insensitive() {
        let repos = vec![("docker",), ("Maven",), ("npm",), ("PyPI",)];
        let formats = vec!["Docker".to_string(), "npm".to_string()];
        let indices = filter_repos_by_format(&repos, &formats);
        assert_eq!(indices, vec![0, 2]);
    }

    #[test]
    fn test_filter_repos_by_format_no_match() {
        let repos = vec![("docker",), ("maven",)];
        let formats = vec!["npm".to_string()];
        let indices = filter_repos_by_format(&repos, &formats);
        assert!(indices.is_empty());
    }

    #[test]
    fn test_filter_repos_by_format_empty_formats() {
        let repos = vec![("docker",)];
        let formats: Vec<String> = vec![];
        let indices = filter_repos_by_format(&repos, &formats);
        assert!(indices.is_empty());
    }

    #[test]
    fn test_filter_repos_by_format_empty_repos() {
        let repos: Vec<(&str,)> = vec![];
        let formats = vec!["docker".to_string()];
        let indices = filter_repos_by_format(&repos, &formats);
        assert!(indices.is_empty());
    }

    #[test]
    fn test_match_labels_all_single_match() {
        let repo_labels = vec![("env", "prod"), ("team", "platform")];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        assert!(match_labels_all(&repo_labels, &required));
    }

    #[test]
    fn test_match_labels_all_multiple_match() {
        let repo_labels = vec![("env", "prod"), ("team", "platform"), ("region", "us-east")];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        required.insert("team".to_string(), "platform".to_string());
        assert!(match_labels_all(&repo_labels, &required));
    }

    #[test]
    fn test_match_labels_all_partial_match() {
        let repo_labels = vec![("env", "prod")];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        required.insert("team".to_string(), "platform".to_string());
        assert!(!match_labels_all(&repo_labels, &required));
    }

    #[test]
    fn test_match_labels_all_wrong_value() {
        let repo_labels = vec![("env", "staging")];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        assert!(!match_labels_all(&repo_labels, &required));
    }

    #[test]
    fn test_match_labels_all_empty_required() {
        let repo_labels = vec![("env", "prod")];
        let required = HashMap::new();
        assert!(match_labels_all(&repo_labels, &required));
    }

    #[test]
    fn test_match_labels_all_empty_repo_labels() {
        let repo_labels: Vec<(&str, &str)> = vec![];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        assert!(!match_labels_all(&repo_labels, &required));
    }

    #[test]
    fn test_match_labels_all_both_empty() {
        let repo_labels: Vec<(&str, &str)> = vec![];
        let required = HashMap::new();
        assert!(match_labels_all(&repo_labels, &required));
    }

    #[test]
    fn test_matched_repo_serde_roundtrip() {
        let id = Uuid::new_v4();
        let repo = MatchedRepo {
            id,
            key: "libs-docker-prod".to_string(),
            format: "docker".to_string(),
        };
        let json = serde_json::to_value(&repo).unwrap();
        let deserialized: MatchedRepo = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.id, id);
        assert_eq!(deserialized.key, "libs-docker-prod");
        assert_eq!(deserialized.format, "docker");
    }

    #[test]
    fn test_matched_repo_clone() {
        let repo = MatchedRepo {
            id: Uuid::new_v4(),
            key: "my-repo".to_string(),
            format: "maven".to_string(),
        };
        let cloned = repo.clone();
        assert_eq!(repo.id, cloned.id);
        assert_eq!(repo.key, cloned.key);
        assert_eq!(repo.format, cloned.format);
    }

    #[test]
    fn test_matched_repo_debug() {
        let repo = MatchedRepo {
            id: Uuid::new_v4(),
            key: "test-repo".to_string(),
            format: "npm".to_string(),
        };
        let debug = format!("{:?}", repo);
        assert!(debug.contains("test-repo"));
        assert!(debug.contains("npm"));
    }

    #[test]
    fn test_repo_selector_deserialize_with_defaults() {
        let json = serde_json::json!({});
        let sel: RepoSelector = serde_json::from_value(json).unwrap();
        assert!(sel.match_labels.is_empty());
        assert!(sel.match_formats.is_empty());
        assert!(sel.match_pattern.is_none());
        assert!(sel.match_repos.is_empty());
    }

    #[test]
    fn test_repo_selector_deserialize_partial_fields() {
        let json = serde_json::json!({
            "match_formats": ["docker"]
        });
        let sel: RepoSelector = serde_json::from_value(json).unwrap();
        assert!(sel.match_labels.is_empty());
        assert_eq!(sel.match_formats, vec!["docker"]);
        assert!(sel.match_pattern.is_none());
        assert!(sel.match_repos.is_empty());
    }

    #[test]
    fn test_repo_selector_deserialize_with_repos() {
        let id = Uuid::new_v4();
        let json = serde_json::json!({
            "match_repos": [id.to_string()]
        });
        let sel: RepoSelector = serde_json::from_value(json).unwrap();
        assert_eq!(sel.match_repos, vec![id]);
    }

    #[test]
    fn test_repo_selector_serialize_default() {
        let sel = RepoSelector::default();
        let json = serde_json::to_value(&sel).unwrap();
        assert!(json
            .get("match_labels")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty());
        assert!(json
            .get("match_formats")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        assert!(json.get("match_pattern").unwrap().is_null());
        assert!(json
            .get("match_repos")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_repo_selector_debug() {
        let sel = RepoSelector {
            match_formats: vec!["npm".to_string()],
            ..Default::default()
        };
        let debug = format!("{:?}", sel);
        assert!(debug.contains("npm"));
    }

    #[test]
    fn test_repo_selector_clone() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        let sel = RepoSelector {
            match_labels: labels,
            match_formats: vec!["docker".to_string()],
            match_pattern: Some("libs-*".to_string()),
            match_repos: vec![Uuid::new_v4()],
        };
        let cloned = sel.clone();
        assert_eq!(sel.match_labels, cloned.match_labels);
        assert_eq!(sel.match_formats, cloned.match_formats);
        assert_eq!(sel.match_pattern, cloned.match_pattern);
        assert_eq!(sel.match_repos, cloned.match_repos);
    }

    #[test]
    fn test_is_empty_all_fields_empty() {
        let sel = RepoSelector {
            match_labels: HashMap::new(),
            match_formats: vec![],
            match_pattern: None,
            match_repos: vec![],
        };
        assert!(RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_is_empty_multiple_fields_set() {
        let mut labels = HashMap::new();
        labels.insert("a".to_string(), "b".to_string());
        let sel = RepoSelector {
            match_labels: labels,
            match_formats: vec!["docker".to_string()],
            match_pattern: Some("*".to_string()),
            match_repos: vec![Uuid::new_v4()],
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_sql_like_match_single_char_pattern() {
        assert!(sql_like_match("a", "a"));
        assert!(!sql_like_match("a", "b"));
    }

    #[test]
    fn test_sql_like_match_prefix_only_no_suffix() {
        assert!(sql_like_match("abc", "a%"));
        assert!(sql_like_match("a", "a%"));
        assert!(!sql_like_match("bc", "a%"));
    }

    #[test]
    fn test_sql_like_match_suffix_only_no_prefix() {
        assert!(sql_like_match("abc", "%c"));
        assert!(sql_like_match("c", "%c"));
        assert!(!sql_like_match("ab", "%c"));
    }

    #[test]
    fn test_sql_like_match_overlapping_segments() {
        assert!(sql_like_match("abab", "ab%ab"));
        assert!(!sql_like_match("ab", "ab%ab"));
    }
}
