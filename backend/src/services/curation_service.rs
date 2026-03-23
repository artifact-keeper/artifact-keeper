//! Curation service: rules evaluation, package management, upstream sync.

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::curation::{CurationPackage, CurationRule};

/// Result of evaluating a package against curation rules.
#[derive(Debug, Clone, Serialize)]
pub struct RuleEvaluation {
    pub action: String, // "allow", "block", or "review"
    pub reason: String,
    pub rule_id: Option<Uuid>, // None if decided by default stance
}

pub struct CurationService {
    db: PgPool,
}

impl CurationService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Check if a package name matches a glob pattern.
    /// Supports `*` (any chars) and `?` (single char).
    pub fn pattern_matches(pattern: &str, name: &str) -> bool {
        glob_match(pattern, name)
    }

    /// Check if a version satisfies a constraint string.
    /// Supports: `*` (any), `= 1.0`, `>= 1.0`, `> 1.0`, `<= 1.0`, `< 1.0`.
    /// Falls back to lexicographic comparison for non-semver versions (RPM epochs, etc.).
    pub fn version_matches(constraint: &str, version: &str) -> bool {
        let constraint = constraint.trim();
        if constraint == "*" {
            return true;
        }

        let (op, target) = if let Some(v) = constraint.strip_prefix(">=") {
            (">=", v.trim())
        } else if let Some(v) = constraint.strip_prefix("<=") {
            ("<=", v.trim())
        } else if let Some(v) = constraint.strip_prefix('>') {
            (">", v.trim())
        } else if let Some(v) = constraint.strip_prefix('<') {
            ("<", v.trim())
        } else if let Some(v) = constraint.strip_prefix('=') {
            ("=", v.trim())
        } else {
            ("=", constraint)
        };

        let cmp = version_compare(version, target);
        match op {
            ">=" => cmp >= 0,
            "<=" => cmp <= 0,
            ">" => cmp > 0,
            "<" => cmp < 0,
            "=" => cmp == 0,
            _ => false,
        }
    }

    /// Evaluate a package against all applicable rules (repo-specific + global),
    /// returning the first matching rule's action or the default stance.
    pub async fn evaluate_package(
        &self,
        staging_repo_id: Uuid,
        default_action: &str,
        package_name: &str,
        version: &str,
        architecture: Option<&str>,
    ) -> Result<RuleEvaluation, sqlx::Error> {
        // Fetch all enabled rules for this repo + global, ordered by priority
        let rules: Vec<CurationRule> = sqlx::query_as(
            r#"SELECT * FROM curation_rules
               WHERE enabled = true
                 AND (staging_repo_id = $1 OR staging_repo_id IS NULL)
               ORDER BY priority ASC, created_at ASC"#,
        )
        .bind(staging_repo_id)
        .fetch_all(&self.db)
        .await?;

        Ok(Self::evaluate_package_in_memory(
            &rules,
            default_action,
            package_name,
            version,
            architecture,
        ))
    }

    // ---------------------------------------------------------------------------
    // Rule CRUD
    // ---------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn create_rule(
        &self,
        staging_repo_id: Option<Uuid>,
        package_pattern: &str,
        version_constraint: &str,
        architecture: &str,
        action: &str,
        priority: i32,
        reason: &str,
        created_by: Uuid,
    ) -> Result<CurationRule, sqlx::Error> {
        sqlx::query_as(
            r#"INSERT INTO curation_rules
               (staging_repo_id, package_pattern, version_constraint, architecture, action, priority, reason, created_by)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING *"#,
        )
        .bind(staging_repo_id)
        .bind(package_pattern)
        .bind(version_constraint)
        .bind(architecture)
        .bind(action)
        .bind(priority)
        .bind(reason)
        .bind(created_by)
        .fetch_one(&self.db)
        .await
    }

    pub async fn list_rules(
        &self,
        staging_repo_id: Option<Uuid>,
    ) -> Result<Vec<CurationRule>, sqlx::Error> {
        if let Some(repo_id) = staging_repo_id {
            sqlx::query_as(
                r#"SELECT * FROM curation_rules
                   WHERE staging_repo_id = $1 OR staging_repo_id IS NULL
                   ORDER BY priority ASC, created_at ASC"#,
            )
            .bind(repo_id)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as(
                r#"SELECT * FROM curation_rules
                   ORDER BY priority ASC, created_at ASC"#,
            )
            .fetch_all(&self.db)
            .await
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_rule(
        &self,
        rule_id: Uuid,
        package_pattern: &str,
        version_constraint: &str,
        architecture: &str,
        action: &str,
        priority: i32,
        reason: &str,
        enabled: bool,
    ) -> Result<CurationRule, sqlx::Error> {
        sqlx::query_as(
            r#"UPDATE curation_rules SET
               package_pattern = $2, version_constraint = $3, architecture = $4,
               action = $5, priority = $6, reason = $7, enabled = $8, updated_at = now()
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(rule_id)
        .bind(package_pattern)
        .bind(version_constraint)
        .bind(architecture)
        .bind(action)
        .bind(priority)
        .bind(reason)
        .bind(enabled)
        .fetch_one(&self.db)
        .await
    }

    pub async fn delete_rule(&self, rule_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM curation_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Package catalog
    // ---------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_package(
        &self,
        staging_repo_id: Uuid,
        remote_repo_id: Uuid,
        format: &str,
        package_name: &str,
        version: &str,
        release: Option<&str>,
        architecture: Option<&str>,
        checksum_sha256: Option<&str>,
        upstream_path: &str,
        metadata: &serde_json::Value,
    ) -> Result<CurationPackage, sqlx::Error> {
        sqlx::query_as(
            r#"INSERT INTO curation_packages
               (staging_repo_id, remote_repo_id, format, package_name, version, release,
                architecture, checksum_sha256, upstream_path, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (staging_repo_id, format, package_name, version,
                           COALESCE(release, ''), COALESCE(architecture, ''))
               DO UPDATE SET checksum_sha256 = EXCLUDED.checksum_sha256,
                            upstream_path = EXCLUDED.upstream_path,
                            metadata = EXCLUDED.metadata,
                            upstream_updated_at = now()
               RETURNING *"#,
        )
        .bind(staging_repo_id)
        .bind(remote_repo_id)
        .bind(format)
        .bind(package_name)
        .bind(version)
        .bind(release)
        .bind(architecture)
        .bind(checksum_sha256)
        .bind(upstream_path)
        .bind(metadata)
        .fetch_one(&self.db)
        .await
    }

    pub async fn list_packages(
        &self,
        staging_repo_id: Uuid,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CurationPackage>, sqlx::Error> {
        if let Some(status) = status {
            sqlx::query_as(
                r#"SELECT * FROM curation_packages
                   WHERE staging_repo_id = $1 AND status = $2
                   ORDER BY package_name ASC, version ASC
                   LIMIT $3 OFFSET $4"#,
            )
            .bind(staging_repo_id)
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as(
                r#"SELECT * FROM curation_packages
                   WHERE staging_repo_id = $1
                   ORDER BY package_name ASC, version ASC
                   LIMIT $2 OFFSET $3"#,
            )
            .bind(staging_repo_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
        }
    }

    pub async fn get_package(&self, id: Uuid) -> Result<CurationPackage, sqlx::Error> {
        sqlx::query_as("SELECT * FROM curation_packages WHERE id = $1")
            .bind(id)
            .fetch_one(&self.db)
            .await
    }

    pub async fn set_package_status(
        &self,
        id: Uuid,
        status: &str,
        reason: &str,
        evaluated_by: Option<Uuid>,
        rule_id: Option<Uuid>,
    ) -> Result<CurationPackage, sqlx::Error> {
        sqlx::query_as(
            r#"UPDATE curation_packages SET
               status = $2, evaluation_reason = $3, evaluated_by = $4,
               rule_id = $5, evaluated_at = now()
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(id)
        .bind(status)
        .bind(reason)
        .bind(evaluated_by)
        .bind(rule_id)
        .fetch_one(&self.db)
        .await
    }

    pub async fn bulk_set_status(
        &self,
        ids: &[Uuid],
        status: &str,
        reason: &str,
        evaluated_by: Option<Uuid>,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"UPDATE curation_packages SET
               status = $2, evaluation_reason = $3, evaluated_by = $4, evaluated_at = now()
               WHERE id = ANY($1)"#,
        )
        .bind(ids)
        .bind(status)
        .bind(reason)
        .bind(evaluated_by)
        .execute(&self.db)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn count_by_status(
        &self,
        staging_repo_id: Uuid,
    ) -> Result<Vec<(String, i64)>, sqlx::Error> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT status, COUNT(*) as count
               FROM curation_packages
               WHERE staging_repo_id = $1
               GROUP BY status"#,
        )
        .bind(staging_repo_id)
        .fetch_all(&self.db)
        .await?;
        Ok(rows)
    }

    /// Evaluate a package against a pre-fetched rule set in memory (no DB call).
    fn evaluate_package_in_memory(
        rules: &[CurationRule],
        default_action: &str,
        package_name: &str,
        version: &str,
        architecture: Option<&str>,
    ) -> RuleEvaluation {
        for rule in rules {
            if !Self::pattern_matches(&rule.package_pattern, package_name) {
                continue;
            }
            if !Self::version_matches(&rule.version_constraint, version) {
                continue;
            }
            if rule.architecture != "*" {
                if let Some(arch) = architecture {
                    if rule.architecture != arch {
                        continue;
                    }
                }
            }

            return RuleEvaluation {
                action: rule.action.clone(),
                reason: rule.reason.clone(),
                rule_id: Some(rule.id),
            };
        }

        RuleEvaluation {
            action: default_action.to_string(),
            reason: format!("No matching rule; default action: {default_action}"),
            rule_id: None,
        }
    }

    /// Evaluate all pending packages against current rules and update their status.
    ///
    /// Fetches rules once, evaluates each package in memory, then batches the
    /// status updates to avoid N+1 query overhead.
    pub async fn re_evaluate_pending(
        &self,
        staging_repo_id: Uuid,
        default_action: &str,
    ) -> Result<u64, sqlx::Error> {
        let pending: Vec<CurationPackage> = sqlx::query_as(
            "SELECT * FROM curation_packages WHERE staging_repo_id = $1 AND status = 'pending'",
        )
        .bind(staging_repo_id)
        .fetch_all(&self.db)
        .await?;

        if pending.is_empty() {
            return Ok(0);
        }

        // Fetch all applicable rules once
        let rules: Vec<CurationRule> = sqlx::query_as(
            r#"SELECT * FROM curation_rules
               WHERE enabled = true
                 AND (staging_repo_id = $1 OR staging_repo_id IS NULL)
               ORDER BY priority ASC, created_at ASC"#,
        )
        .bind(staging_repo_id)
        .fetch_all(&self.db)
        .await?;

        // Group packages by (status, reason, rule_id) for batch updates
        let mut groups: std::collections::HashMap<(String, String, Option<Uuid>), Vec<Uuid>> =
            std::collections::HashMap::new();

        for pkg in &pending {
            let eval = Self::evaluate_package_in_memory(
                &rules,
                default_action,
                &pkg.package_name,
                &pkg.version,
                pkg.architecture.as_deref(),
            );

            let new_status = match eval.action.as_str() {
                "allow" => "approved",
                "block" => "blocked",
                _ => "review",
            };

            groups
                .entry((new_status.to_string(), eval.reason, eval.rule_id))
                .or_default()
                .push(pkg.id);
        }

        // Batch update each group
        let mut updated = 0u64;
        for ((status, reason, rule_id), ids) in &groups {
            let result = sqlx::query(
                r#"UPDATE curation_packages SET
                   status = $2, evaluation_reason = $3, evaluated_by = NULL,
                   rule_id = $4, evaluated_at = now()
                   WHERE id = ANY($1)"#,
            )
            .bind(ids)
            .bind(status)
            .bind(reason)
            .bind(rule_id)
            .execute(&self.db)
            .await?;
            updated += result.rows_affected();
        }
        Ok(updated)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple glob matching: `*` matches any sequence, `?` matches one char.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.chars().collect::<Vec<_>>();
    let t = text.chars().collect::<Vec<_>>();
    glob_match_inner(&p, &t, 0, 0)
}

fn glob_match_inner(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() && ti == text.len() {
        return true;
    }
    if pi == pattern.len() {
        return false;
    }

    if pattern[pi] == '*' {
        // Try matching * against 0..n characters
        for skip in 0..=(text.len() - ti) {
            if glob_match_inner(pattern, text, pi + 1, ti + skip) {
                return true;
            }
        }
        return false;
    }

    if ti == text.len() {
        return false;
    }

    if pattern[pi] == '?' || pattern[pi] == text[ti] {
        return glob_match_inner(pattern, text, pi + 1, ti + 1);
    }

    false
}

/// Compare two version strings. Returns -1, 0, or 1.
/// Splits on `.` and `-`, compares segments numerically when possible.
fn version_compare(a: &str, b: &str) -> i32 {
    let seg_a: Vec<&str> = a.split(['.', '-']).collect();
    let seg_b: Vec<&str> = b.split(['.', '-']).collect();

    for i in 0..seg_a.len().max(seg_b.len()) {
        let sa = seg_a.get(i).unwrap_or(&"0");
        let sb = seg_b.get(i).unwrap_or(&"0");

        // Try numeric comparison first
        match (sa.parse::<u64>(), sb.parse::<u64>()) {
            (Ok(na), Ok(nb)) => {
                if na < nb {
                    return -1;
                }
                if na > nb {
                    return 1;
                }
            }
            _ => {
                // Lexicographic fallback
                match sa.cmp(sb) {
                    std::cmp::Ordering::Less => return -1,
                    std::cmp::Ordering::Greater => return 1,
                    std::cmp::Ordering::Equal => {}
                }
            }
        }
    }
    0
}

#[cfg(test)]
#[allow(clippy::cloned_ref_to_slice_refs)]
mod tests {
    use super::*;

    // -- glob matching --

    #[test]
    fn test_glob_exact_match() {
        assert!(CurationService::pattern_matches("nginx", "nginx"));
        assert!(!CurationService::pattern_matches("nginx", "apache"));
    }

    #[test]
    fn test_glob_star_suffix() {
        assert!(CurationService::pattern_matches("telnet*", "telnet"));
        assert!(CurationService::pattern_matches("telnet*", "telnet-server"));
        assert!(!CurationService::pattern_matches("telnet*", "curl"));
    }

    #[test]
    fn test_glob_star_prefix() {
        assert!(CurationService::pattern_matches("*-dev", "libssl-dev"));
        assert!(!CurationService::pattern_matches("*-dev", "libssl"));
    }

    #[test]
    fn test_glob_star_middle() {
        assert!(CurationService::pattern_matches("lib*-dev", "libssl-dev"));
        assert!(CurationService::pattern_matches("lib*-dev", "libcurl-dev"));
        assert!(!CurationService::pattern_matches("lib*-dev", "nginx-dev"));
    }

    #[test]
    fn test_glob_question_mark() {
        assert!(CurationService::pattern_matches("lib?", "liba"));
        assert!(!CurationService::pattern_matches("lib?", "libab"));
    }

    #[test]
    fn test_glob_match_all() {
        assert!(CurationService::pattern_matches("*", "anything"));
        assert!(CurationService::pattern_matches("*", ""));
    }

    // -- version constraint matching --

    #[test]
    fn test_version_wildcard() {
        assert!(CurationService::version_matches("*", "1.2.3"));
        assert!(CurationService::version_matches("*", "0.0.1"));
    }

    #[test]
    fn test_version_exact() {
        assert!(CurationService::version_matches("= 1.2.3", "1.2.3"));
        assert!(!CurationService::version_matches("= 1.2.3", "1.2.4"));
    }

    #[test]
    fn test_version_gte() {
        assert!(CurationService::version_matches(">= 3.0", "3.0"));
        assert!(CurationService::version_matches(">= 3.0", "3.1"));
        assert!(!CurationService::version_matches(">= 3.0", "2.9"));
    }

    #[test]
    fn test_version_lt() {
        assert!(CurationService::version_matches("< 2.17", "2.16"));
        assert!(!CurationService::version_matches("< 2.17", "2.17"));
        assert!(!CurationService::version_matches("< 2.17", "3.0"));
    }

    #[test]
    fn test_version_gt() {
        assert!(CurationService::version_matches("> 1.0", "1.1"));
        assert!(!CurationService::version_matches("> 1.0", "1.0"));
    }

    #[test]
    fn test_version_lte() {
        assert!(CurationService::version_matches("<= 1.0", "1.0"));
        assert!(CurationService::version_matches("<= 1.0", "0.9"));
        assert!(!CurationService::version_matches("<= 1.0", "1.1"));
    }

    #[test]
    fn test_version_rpm_style() {
        // RPM versions like 1.24.0-1.el9
        assert!(CurationService::version_matches(
            ">= 1.24.0",
            "1.24.0-1.el9"
        ));
        assert!(!CurationService::version_matches(
            ">= 1.25.0",
            "1.24.0-1.el9"
        ));
    }

    #[test]
    fn test_version_implicit_equals() {
        // No operator means exact match
        assert!(CurationService::version_matches("1.2.3", "1.2.3"));
        assert!(!CurationService::version_matches("1.2.3", "1.2.4"));
    }

    // -- evaluate_package_in_memory --

    fn make_rule(
        pattern: &str,
        version_constraint: &str,
        arch: &str,
        action: &str,
    ) -> CurationRule {
        CurationRule {
            id: Uuid::new_v4(),
            staging_repo_id: None,
            package_pattern: pattern.to_string(),
            version_constraint: version_constraint.to_string(),
            architecture: arch.to_string(),
            action: action.to_string(),
            priority: 0,
            reason: format!("{action} by test rule"),
            enabled: true,
            created_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_evaluate_in_memory_no_rules_uses_default() {
        let eval =
            CurationService::evaluate_package_in_memory(&[], "allow", "nginx", "1.0.0", None);
        assert_eq!(eval.action, "allow");
        assert!(eval.rule_id.is_none());
        assert!(eval.reason.contains("No matching rule"));
    }

    #[test]
    fn test_evaluate_in_memory_matching_rule_blocks() {
        let rule = make_rule("telnet*", "*", "*", "block");
        let eval = CurationService::evaluate_package_in_memory(
            &[rule.clone()],
            "allow",
            "telnet-server",
            "1.0",
            None,
        );
        assert_eq!(eval.action, "block");
        assert_eq!(eval.rule_id, Some(rule.id));
    }

    #[test]
    fn test_evaluate_in_memory_version_mismatch_skips_rule() {
        let rule = make_rule("nginx", ">= 2.0", "*", "block");
        let eval =
            CurationService::evaluate_package_in_memory(&[rule], "allow", "nginx", "1.5", None);
        // Version 1.5 does not satisfy >= 2.0, so the rule is skipped
        assert_eq!(eval.action, "allow");
        assert!(eval.rule_id.is_none());
    }

    #[test]
    fn test_evaluate_in_memory_architecture_filter() {
        let rule = make_rule("*", "*", "aarch64", "block");
        // Package has x86_64 architecture, rule requires aarch64
        let eval = CurationService::evaluate_package_in_memory(
            &[rule],
            "allow",
            "nginx",
            "1.0",
            Some("x86_64"),
        );
        assert_eq!(eval.action, "allow");
        assert!(eval.rule_id.is_none());
    }

    #[test]
    fn test_evaluate_in_memory_architecture_match() {
        let rule = make_rule("*", "*", "x86_64", "block");
        let eval = CurationService::evaluate_package_in_memory(
            &[rule.clone()],
            "allow",
            "nginx",
            "1.0",
            Some("x86_64"),
        );
        assert_eq!(eval.action, "block");
        assert_eq!(eval.rule_id, Some(rule.id));
    }

    #[test]
    fn test_evaluate_in_memory_wildcard_architecture() {
        // Rule with "*" architecture matches any package architecture
        let rule = make_rule("nginx", "*", "*", "block");
        let eval = CurationService::evaluate_package_in_memory(
            &[rule.clone()],
            "allow",
            "nginx",
            "1.0",
            Some("aarch64"),
        );
        assert_eq!(eval.action, "block");
        assert_eq!(eval.rule_id, Some(rule.id));
    }

    #[test]
    fn test_evaluate_in_memory_first_match_wins() {
        let allow_rule = make_rule("nginx", "*", "*", "allow");
        let block_rule = make_rule("nginx", "*", "*", "block");
        let eval = CurationService::evaluate_package_in_memory(
            &[allow_rule.clone(), block_rule],
            "block",
            "nginx",
            "1.0",
            None,
        );
        // The first matching rule (allow) wins
        assert_eq!(eval.action, "allow");
        assert_eq!(eval.rule_id, Some(allow_rule.id));
    }

    #[test]
    fn test_evaluate_in_memory_default_action_review() {
        let eval = CurationService::evaluate_package_in_memory(
            &[],
            "review",
            "unknown-pkg",
            "0.1.0",
            None,
        );
        assert_eq!(eval.action, "review");
        assert!(eval.reason.contains("review"));
    }
}
