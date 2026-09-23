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
    /// Expand every matched virtual repository into its member repositories,
    /// which are added to the match (#4130).
    ///
    /// A token scoped to a virtual repository alone reads nothing through it:
    /// the listing and download paths both resolve the virtual's MEMBERS and
    /// drop the ones outside the token's scope, and the parent being in scope
    /// says nothing about them. This makes "the members of this virtual
    /// repository" a scope a token can be minted with, re-resolved at
    /// authentication time so a member added later is covered without
    /// re-minting.
    ///
    /// Not a filter: on its own it matches nothing, and [`Self::is_empty`]
    /// still reports such a selector as empty. Expansion is one level deep —
    /// a virtual that is itself a member contributes only itself, matching
    /// every read path, none of which recurse into a nested virtual.
    ///
    /// # What this widens, stated plainly
    ///
    /// A token's repository scope is an action-INDEPENDENT ceiling, so this
    /// adds the members for every action the token's scopes already allow,
    /// not only reads: a `read+write` token scoped this way may write and
    /// delete in each member. It is still bounded by the owning account's own
    /// grants — expansion cannot reach a repository the account may not use —
    /// and by the token's action scopes.
    ///
    /// Two consequences follow from resolving at authentication time:
    /// whoever may edit the virtual repository's membership moves this
    /// ceiling, and a member REMOVED from the virtual stays reachable until
    /// the validated-token cache entry expires (`API_TOKEN_CACHE_TTL_SECS`,
    /// 5 minutes) and for the lifetime of any JWT already exchanged from the
    /// token. Revoke the token to cut that short.
    #[serde(default)]
    pub include_virtual_members: bool,
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
            return self.with_virtual_members(selector, repos).await;
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

        self.with_virtual_members(selector, all_repos).await
    }

    /// Add the members of every matched virtual repository when the selector
    /// asks for them (#4130). Applied after the filters, so membership widens
    /// the match rather than being narrowed by `match_formats` — a virtual
    /// repository and its members share a format, but a label or pattern
    /// filter written for the parent will not describe them.
    async fn with_virtual_members(
        &self,
        selector: &RepoSelector,
        matched: Vec<RepoRow>,
    ) -> Result<Vec<RepoRow>> {
        if !selector.include_virtual_members || matched.is_empty() {
            return Ok(matched);
        }
        let matched_ids: Vec<Uuid> = matched.iter().map(|r| r.id).collect();
        let members: Vec<RepoRow> = sqlx::query_as(
            r#"
            SELECT r.id, r.key, r.format::TEXT
            FROM repositories r
            INNER JOIN virtual_repo_members vrm ON vrm.member_repo_id = r.id
            WHERE vrm.virtual_repo_id = ANY($1)
            "#,
        )
        .bind(&matched_ids)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut seen: std::collections::HashSet<Uuid> = matched_ids.into_iter().collect();
        let mut rows = matched;
        for member in members {
            if seen.insert(member.id) {
                rows.push(member);
            }
        }
        Ok(rows)
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

/// Parse a token `repo_selector` strictly: it must be a JSON object that
/// deserializes as a [`RepoSelector`] and carries no key `RepoSelector` does
/// not know.
///
/// Plain `serde_json::from_value` drops an unknown key, so a misspelled
/// criterion (`match_format`, `match_label`) silently leaves the selector
/// broader than written, and an all-misspelled one leaves it empty, which the
/// token path treats as unrestricted (#4219, #4226). Both the mint-time
/// validator and the authentication-time read go through this one parse.
pub fn parse_token_selector_strict(
    value: &serde_json::Value,
) -> std::result::Result<RepoSelector, String> {
    let Some(given) = value.as_object() else {
        return Err("expected a JSON object".to_string());
    };
    let selector: RepoSelector =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    // The known keys are whatever `RepoSelector` serializes, so a criterion
    // added to it later is accepted here without a second list to keep.
    let known = serde_json::to_value(&selector).unwrap_or_default();
    if let Some(unknown) = given.keys().find(|k| known.get(k.as_str()).is_none()) {
        return Err(format!("unknown field `{unknown}`"));
    }
    Ok(selector)
}

/// Refuse a token `repo_selector` that would not restrict (#4219, #4226).
///
/// Shared by every mint that accepts a selector (personal tokens on
/// `POST /auth/tokens`, service-account tokens). A selector that does not
/// parse, that misspells a criterion, or that names no criteria at all would
/// mint a token wider than the one asked for, so each is a 400 at the mint.
pub fn validate_token_repo_selector(value: &serde_json::Value) -> Result<()> {
    let selector = parse_token_selector_strict(value)
        .map_err(|e| AppError::Validation(format!("Invalid repo_selector: {e}")))?;
    if RepoSelectorService::is_empty(&selector) {
        return Err(AppError::Validation(
            "repo_selector names no repositories; set match_repos, match_labels, \
             match_formats or match_pattern, or omit repo_selector for an \
             unrestricted token"
                .to_string(),
        ));
    }
    Ok(())
}

/// The selector stamped on a token minted by a repository-restricted
/// credential (#4225): exactly the repositories the minting credential could
/// reach at mint time.
///
/// Stored as `match_repos` rather than as `api_token_repositories` rows
/// because those rows cascade away when a repository is deleted, and a token
/// with no rows is unrestricted. A `match_repos` entry for a deleted
/// repository simply stops resolving, and a selector that resolves to nothing
/// denies everything. Callers must refuse an empty `ids` (an empty
/// `match_repos` is an empty selector, which is unrestricted).
pub fn inherited_token_selector(ids: &[Uuid]) -> serde_json::Value {
    serde_json::json!({ "match_repos": ids })
}

/// Store `selector` as the `repo_selector` of the freshly minted token
/// `token_id`. Every mint handler writes the restriction through here, after
/// the token row exists and before its plaintext is returned, so a failed
/// write leaves an unrestricted row nobody holds the secret for.
pub async fn store_token_selector(
    db: &PgPool,
    token_id: Uuid,
    selector: &serde_json::Value,
) -> Result<()> {
    sqlx::query("UPDATE api_tokens SET repo_selector = $1 WHERE id = $2")
        .bind(selector)
        .bind(token_id)
        .execute(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
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

    /// #4130: the flag widens a match, it is not a filter. A selector carrying
    /// only the flag must still read as empty — the mint refuses it
    /// (`validate_repo_selector`) rather than this reporting it as a scope.
    #[test]
    fn include_virtual_members_alone_is_still_an_empty_selector() {
        let sel = RepoSelector {
            include_virtual_members: true,
            ..Default::default()
        };
        assert!(RepoSelectorService::is_empty(&sel));
    }

    /// #4130: a selector naming a virtual repository resolves to the virtual
    /// plus its members, and re-resolves at authentication time, so a member
    /// added after the token was minted is covered.
    #[tokio::test]
    async fn include_virtual_members_expands_a_selected_virtual_repository() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (virtual_id, _vkey, vdir) = tdh::create_repo(&pool, "virtual", "nuget").await;
        let (member_id, _mkey, mdir) = tdh::create_repo(&pool, "local", "nuget").await;
        let (outsider_id, _okey, odir) = tdh::create_repo(&pool, "local", "nuget").await;
        tdh::link_virtual_member(&pool, virtual_id, member_id, 1).await;

        let svc = RepoSelectorService::new(pool.clone());
        let without = svc
            .resolve_ids(&RepoSelector {
                match_repos: vec![virtual_id],
                ..Default::default()
            })
            .await
            .expect("resolve without expansion");
        let with = svc
            .resolve_ids(&RepoSelector {
                match_repos: vec![virtual_id],
                include_virtual_members: true,
                ..Default::default()
            })
            .await
            .expect("resolve with expansion");

        for (id, dir) in [(virtual_id, vdir), (member_id, mdir), (outsider_id, odir)] {
            let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
                .bind(virtual_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
            let _ = std::fs::remove_dir_all(dir);
        }

        assert_eq!(without, vec![virtual_id], "unexpanded: the parent only");
        assert!(
            with.contains(&virtual_id),
            "the parent stays in scope: {with:?}"
        );
        assert!(
            with.contains(&member_id),
            "the member must be added to the scope: {with:?}"
        );
        assert!(
            !with.contains(&outsider_id),
            "a repository that is not a member must not be added: {with:?}"
        );
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
            include_virtual_members: false,
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
            include_virtual_members: false,
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
            include_virtual_members: false,
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
            include_virtual_members: false,
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

/// End-to-end tests for `include_virtual_members` on the authentication path
/// (#4213 review): a real minted token, validated the way a request validates
/// it, so the expansion is exercised where it actually runs rather than only
/// in `resolve_ids`.
#[cfg(test)]
mod token_validation_tests {
    use std::sync::Arc;

    use crate::api::handlers::test_db_helpers as tdh;
    use crate::config::Config;
    use crate::models::access_scope::AccessScope;
    use crate::services::auth_service::AuthService;
    use crate::services::permission_service::PermissionService;
    use crate::services::repository_service::{RepoVisibility, RepositoryService};

    use super::*;

    fn config() -> Arc<Config> {
        Arc::new(Config {
            jwt_secret: "test-secret-at-least-32-bytes-long-for-hs256".to_string(),
            ..Config::default()
        })
    }

    /// Mint a service-account token carrying `selector`, then validate it.
    async fn scope_of(pool: &PgPool, user_id: Uuid, selector: serde_json::Value) -> AccessScope {
        let auth = AuthService::new(pool.clone(), config());
        let (token, token_id) = auth
            .generate_api_token(
                user_id,
                "e2e-virtual-members",
                vec!["read:artifacts".into()],
                None,
            )
            .await
            .expect("mint token");
        sqlx::query("UPDATE api_tokens SET repo_selector = $1 WHERE id = $2")
            .bind(&selector)
            .bind(token_id)
            .execute(pool)
            .await
            .expect("store selector");
        auth.validate_api_token(&token)
            .await
            .expect("validate token")
            .allowed_repo_ids
    }

    fn ids(scope: &AccessScope) -> Vec<Uuid> {
        match scope {
            AccessScope::Restricted(ids) => ids.clone(),
            AccessScope::Admin => Vec::new(),
        }
    }

    /// The whole point: the scope a REQUEST sees includes the members, and a
    /// member linked AFTER the token was minted is covered without re-minting,
    /// because the selector is re-resolved at authentication time.
    ///
    /// Each half validates its own freshly minted token on purpose. That is
    /// what the assertion is about — every validation re-resolves — and it
    /// avoids claiming something untrue of production: the SAME token keeps
    /// its cached scope for up to `API_TOKEN_CACHE_TTL_SECS` (5 minutes), so
    /// a membership change reaches an in-flight token only after that window.
    #[tokio::test]
    async fn validated_token_scope_expands_to_members_including_one_added_later() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _name) = tdh::create_user(&pool).await;
        let (virtual_id, _vk, vdir) = tdh::create_repo(&pool, "virtual", "nuget").await;
        let (first_id, _fk, fdir) = tdh::create_repo(&pool, "local", "nuget").await;
        let (late_id, _lk, ldir) = tdh::create_repo(&pool, "local", "nuget").await;
        tdh::link_virtual_member(&pool, virtual_id, first_id, 1).await;

        let selector = serde_json::json!({
            "match_repos": [virtual_id],
            "include_virtual_members": true,
        });
        let before = scope_of(&pool, user_id, selector.clone()).await;

        // The member arrives after the token exists.
        tdh::link_virtual_member(&pool, virtual_id, late_id, 2).await;
        let after = scope_of(&pool, user_id, selector).await;

        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(&pool)
            .await;
        for id in [virtual_id, first_id, late_id] {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
        tdh::cleanup_user(&pool, user_id).await;
        for dir in [vdir, fdir, ldir] {
            let _ = std::fs::remove_dir_all(dir);
        }

        let before = ids(&before);
        assert!(
            before.contains(&virtual_id),
            "the parent stays in scope: {before:?}"
        );
        assert!(
            before.contains(&first_id),
            "its member is added: {before:?}"
        );
        assert!(
            !before.contains(&late_id),
            "a repository that was not a member yet: {before:?}"
        );

        let after = ids(&after);
        assert!(
            after.contains(&late_id),
            "a member linked after minting is covered on the next validation: {after:?}"
        );
    }

    /// The expansion widens the token's SCOPE, never the account's
    /// entitlements: a member the account has no grant on stays unreadable,
    /// and an unrelated repository is never pulled in. Asserted for read and
    /// for write, since the scope is action-independent.
    #[tokio::test]
    async fn expansion_cannot_reach_what_the_account_is_not_granted() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _name) = tdh::create_user(&pool).await;
        let (virtual_id, _vk, vdir) = tdh::create_repo(&pool, "virtual", "nuget").await;
        let (member_id, _mk, mdir) = tdh::create_repo(&pool, "local", "nuget").await;
        let (outsider_id, _ok, odir) = tdh::create_repo(&pool, "local", "nuget").await;
        tdh::link_virtual_member(&pool, virtual_id, member_id, 1).await;
        // No grant of any kind on the member.

        let scope = scope_of(
            &pool,
            user_id,
            serde_json::json!({
                "match_repos": [virtual_id],
                "include_virtual_members": true,
            }),
        )
        .await;

        let readable = RepositoryService::new(pool.clone())
            .filter_visible_repo_ids(&[member_id], &RepoVisibility::User(user_id))
            .await
            .expect("visibility query");
        // `is_admin: false` -- the question is what the ACCOUNT may do.
        let writable = PermissionService::new(pool.clone())
            .check_repository_action(user_id, member_id, "write", false)
            .await
            .unwrap_or(false);

        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(&pool)
            .await;
        for id in [virtual_id, member_id, outsider_id] {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
        tdh::cleanup_user(&pool, user_id).await;
        for dir in [vdir, mdir, odir] {
            let _ = std::fs::remove_dir_all(dir);
        }

        let scope = ids(&scope);
        assert!(scope.contains(&member_id), "scope does expand: {scope:?}");
        assert!(
            !scope.contains(&outsider_id),
            "and only to members: {scope:?}"
        );
        // Scope is a ceiling, not an entitlement. Both halves must still say no.
        assert!(
            readable.is_empty(),
            "an ungranted member stays unreadable despite being in scope"
        );
        assert!(!writable, "and unwritable: the expansion is not a grant");
    }
}
