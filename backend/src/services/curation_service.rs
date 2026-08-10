//! Curation service: rules evaluation, package management, upstream sync.

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::curation::{CurationDecision, CurationPackage, CurationRule};

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
        crate::util::glob::glob_match(pattern, name)
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

    /// Fold a package name or glob pattern for PEP 503-insensitive matching:
    /// lowercase, and collapse runs of `-`, `_`, `.` to a single `-`.
    ///
    /// This is the pattern-safe counterpart of `pypi::normalize_pep503`. That
    /// function additionally *drops* every character outside `[A-Za-z0-9._-]`,
    /// which makes it unusable on a glob pattern — it would delete the `*` and `?`
    /// wildcards. On an already-normalized name this fold is the identity, so the
    /// two agree wherever both apply (asserted in tests).
    pub(crate) fn fold_pep503(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        let mut last_was_sep = true;

        for c in value.chars() {
            if c == '-' || c == '_' || c == '.' {
                if !last_was_sep {
                    out.push('-');
                    last_was_sep = true;
                }
            } else {
                out.push(c.to_ascii_lowercase());
                last_was_sep = false;
            }
        }

        if out.ends_with('-') {
            out.pop();
        }
        out
    }

    /// Fetch the enabled rules that apply to a repository (repo-specific +
    /// global), ordered by priority.
    async fn fetch_applicable_rules(
        &self,
        staging_repo_id: Uuid,
    ) -> Result<Vec<CurationRule>, sqlx::Error> {
        sqlx::query_as(
            r#"SELECT * FROM curation_rules
               WHERE enabled = true
                 AND (staging_repo_id = $1 OR staging_repo_id IS NULL)
               ORDER BY priority ASC, created_at ASC"#,
        )
        .bind(staging_repo_id)
        .fetch_all(&self.db)
        .await
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
        let rules = self.fetch_applicable_rules(staging_repo_id).await?;

        Ok(Self::evaluate_package_in_memory(
            &rules,
            default_action,
            package_name,
            version,
            architecture,
        ))
    }

    /// Evaluate a PEP 503 package name against the repository's curation rules.
    ///
    /// Differs from [`Self::evaluate_package`] in the two ways the Python proxy
    /// path requires (#2912):
    ///
    /// 1. Rule patterns are folded with [`Self::fold_pep503`] before matching, so
    ///    a rule written the way PyPI displays the project — `PyYAML`, `Django`,
    ///    `my_package` — matches a request for the normalized `pyyaml` / `django`
    ///    / `my-package`. Without this the proxy silently enforces nothing for the
    ///    spelling operators actually use, while the staging-sync path (which
    ///    passes raw upstream names) enforces the same rule.
    /// 2. `version` is an `Option`. When the request does not carry a version, a
    ///    version-constrained rule is skipped rather than compared against a
    ///    placeholder.
    pub async fn evaluate_pep503_package(
        &self,
        staging_repo_id: Uuid,
        default_action: &str,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<RuleEvaluation, sqlx::Error> {
        let rules = self.fetch_applicable_rules(staging_repo_id).await?;

        Ok(Self::evaluate_rules(
            &rules,
            default_action,
            package_name,
            version,
            None,
            true,
        ))
    }

    // ---------------------------------------------------------------------------
    // Typed rule dispatch (#2947)
    // ---------------------------------------------------------------------------

    /// Evaluate one typed rule against a package context, routing on
    /// `rule.rule_type` (#2947).
    ///
    /// - `"pattern"`: the existing glob/version/arch evaluation, unchanged,
    ///   wrapped to return a [`CurationDecision`]. The architecture is read
    ///   from `metadata["architecture"]` when present. A pattern rule that does
    ///   not match the package returns `NotApplicable` (no effect) — combining
    ///   rules stays the caller's first-match concern, exactly as today.
    /// - `"publisher_trust"`: dispatched to
    ///   [`crate::services::curation::publisher_trust::evaluate`] (#2948);
    ///   `NotApplicable` for formats without a publisher signal.
    /// - `"popularity"`: dispatched to
    ///   [`crate::services::curation::popularity::evaluate`] (#2949);
    ///   `NotApplicable` for formats without a download-count ecosystem — that
    ///   gate runs FIRST, before `popularity_source` is consulted, so
    ///   inapplicable formats never cost a lookup.
    /// - anything else: `Flag` — an unrecognized engine must never silently
    ///   allow (the API rejects unknown types at write time; this is the
    ///   defense-in-depth backstop).
    ///
    /// `popularity_source` is the download-count provider the `popularity`
    /// arm consults (production: a cached
    /// [`HttpPopularitySource`](crate::services::curation::popularity_source::HttpPopularitySource);
    /// tests: [`FakePopularitySource`](crate::services::curation::popularity_source::FakePopularitySource)).
    pub async fn evaluate_typed_rule(
        rule: &CurationRule,
        format: &str,
        name: &str,
        version: &str,
        metadata: &serde_json::Value,
        popularity_source: &dyn crate::services::curation::popularity_source::PopularitySource,
    ) -> CurationDecision {
        match rule.rule_type.as_str() {
            "pattern" => {
                let architecture = metadata.get("architecture").and_then(|v| v.as_str());
                let eval = Self::evaluate_rules(
                    std::slice::from_ref(rule),
                    "allow",
                    name,
                    Some(version),
                    architecture,
                    false,
                );
                match eval.rule_id {
                    None => CurationDecision::NotApplicable, // rule did not match
                    Some(_) => match eval.action.as_str() {
                        "allow" => CurationDecision::Allow,
                        "block" => CurationDecision::Block(eval.reason),
                        _ => CurationDecision::Flag(eval.reason),
                    },
                }
            }
            "publisher_trust" => crate::services::curation::publisher_trust::evaluate(
                &rule.config,
                format,
                name,
                version,
                metadata,
            ),
            "popularity" => {
                // Format-gate FIRST: an inapplicable format must short-circuit
                // without consulting the popularity source (no wasted fetch).
                if !crate::services::curation::popularity::applies_to(format) {
                    return CurationDecision::NotApplicable;
                }
                crate::services::curation::popularity::evaluate(
                    &rule.config,
                    format,
                    name,
                    version,
                    popularity_source,
                )
                .await
            }
            other => CurationDecision::Flag(format!(
                "Unrecognized curation rule_type '{other}' (rule {}): routed to manual review",
                rule.id
            )),
        }
    }

    /// First-applicable-wins typed evaluation over a pre-fetched rule set
    /// (#2947 enforcement seam).
    ///
    /// `rules` is the priority-ordered UNION of the applicable global rules and
    /// the repository's own rules — exactly what
    /// [`Self::fetch_applicable_rules`] returns, since a global rule is stored
    /// with `staging_repo_id IS NULL` (`scope = 'global'`) and that query has
    /// always included the NULL-repo baseline.
    ///
    /// Each rule is dispatched through [`Self::evaluate_typed_rule`]; a
    /// [`CurationDecision::NotApplicable`] result has NO effect (the rule is
    /// skipped and evaluation continues), so a global `publisher_trust` /
    /// `popularity` policy silently passes through formats it cannot judge.
    /// The first `Allow` / `Flag` / `Block` decision wins, mirroring the
    /// legacy first-match semantics. When no rule renders a decision the
    /// caller's `default_decision` applies.
    pub async fn evaluate_typed_rules(
        rules: &[CurationRule],
        default_decision: CurationDecision,
        format: &str,
        name: &str,
        version: &str,
        metadata: &serde_json::Value,
        popularity_source: &dyn crate::services::curation::popularity_source::PopularitySource,
    ) -> (CurationDecision, Option<Uuid>) {
        for rule in rules {
            match Self::evaluate_typed_rule(
                rule,
                format,
                name,
                version,
                metadata,
                popularity_source,
            )
            .await
            {
                CurationDecision::NotApplicable => continue,
                decision => return (decision, Some(rule.id)),
            }
        }
        (default_decision, None)
    }

    /// DB-backed typed evaluation of one package for a staging repository —
    /// the production enforcement entry point for the #2947 typed rules.
    ///
    /// Fetches the priority-ordered union of the repository's rules and the
    /// global (`staging_repo_id IS NULL`) baseline, then runs
    /// [`Self::evaluate_typed_rules`] over the package context. `architecture`
    /// (when known) is threaded into the metadata context so arch-scoped
    /// `pattern` rules keep their legacy semantics. The caller's
    /// `default_action` (`"allow"` / `"block"` / `"review"`) supplies the
    /// stance when no rule renders a decision.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_package_typed(
        &self,
        staging_repo_id: Uuid,
        default_action: &str,
        format: &str,
        package_name: &str,
        version: &str,
        architecture: Option<&str>,
        metadata: &serde_json::Value,
        popularity_source: &dyn crate::services::curation::popularity_source::PopularitySource,
    ) -> Result<(CurationDecision, Option<Uuid>), sqlx::Error> {
        let rules = self.fetch_applicable_rules(staging_repo_id).await?;
        let context = Self::context_metadata(metadata, architecture);
        Ok(Self::evaluate_typed_rules(
            &rules,
            Self::default_decision(default_action),
            format,
            package_name,
            version,
            &context,
            popularity_source,
        )
        .await)
    }

    /// Map a repository's `curation_default_action` onto the decision that
    /// applies when no rule matches.
    fn default_decision(default_action: &str) -> CurationDecision {
        match default_action {
            "allow" => CurationDecision::Allow,
            "block" => CurationDecision::Block(format!(
                "No matching rule; default action: {default_action}"
            )),
            _ => CurationDecision::Flag(format!(
                "No matching rule; default action: {default_action}"
            )),
        }
    }

    /// Build the metadata context handed to the typed dispatch: the package's
    /// registry metadata blob, with the catalog's `architecture` column
    /// injected under `"architecture"` (the key the `pattern` arm reads) when
    /// the blob does not already carry one.
    fn context_metadata(
        metadata: &serde_json::Value,
        architecture: Option<&str>,
    ) -> serde_json::Value {
        match architecture {
            Some(arch) if metadata.get("architecture").is_none() => {
                let mut context = metadata.clone();
                match context.as_object_mut() {
                    Some(map) => {
                        map.insert(
                            "architecture".to_string(),
                            serde_json::Value::String(arch.to_string()),
                        );
                        context
                    }
                    // Non-object metadata: fall back to a fresh object so the
                    // architecture still reaches arch-scoped pattern rules.
                    None => serde_json::json!({"architecture": arch}),
                }
            }
            _ => metadata.clone(),
        }
    }

    /// Render a `(status, reason)` pair for the curation catalog from a typed
    /// decision, mirroring the legacy action mapping
    /// (`allow` → `approved`, `block` → `blocked`, anything else → `review`).
    pub fn decision_to_status_reason(
        decision: &CurationDecision,
        rule_id: Option<Uuid>,
    ) -> (&'static str, String) {
        match decision {
            CurationDecision::Allow => match rule_id {
                Some(id) => ("approved", format!("Allowed by curation rule {id}")),
                None => (
                    "approved",
                    "No matching rule; default action: allow".to_string(),
                ),
            },
            CurationDecision::Block(reason) => ("blocked", reason.clone()),
            CurationDecision::Flag(reason) => ("review", reason.clone()),
            // Unreachable in practice: evaluate_typed_rules never returns
            // NotApplicable and default decisions are Allow/Flag/Block. Fail
            // safe to review if it ever surfaces.
            CurationDecision::NotApplicable => (
                "review",
                "Rule evaluation rendered no decision; routed to manual review".to_string(),
            ),
        }
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
        rule_type: &str,
        config: &serde_json::Value,
        created_by: Uuid,
    ) -> Result<CurationRule, sqlx::Error> {
        // `scope` is DERIVED from the presence of a staging repo, never taken
        // from the caller, so the invariant scope='global' <=> repo IS NULL
        // cannot drift (the API validates the request's declared scope against
        // this same derivation before calling in).
        let scope = if staging_repo_id.is_some() {
            "repository"
        } else {
            "global"
        };
        sqlx::query_as(
            r#"INSERT INTO curation_rules
               (staging_repo_id, package_pattern, version_constraint, architecture, action, priority, reason, rule_type, config, scope, created_by)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
               RETURNING *"#,
        )
        .bind(staging_repo_id)
        .bind(package_pattern)
        .bind(version_constraint)
        .bind(architecture)
        .bind(action)
        .bind(priority)
        .bind(reason)
        .bind(rule_type)
        .bind(config)
        .bind(scope)
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

    /// List only the instance-wide (global) rules, priority-ordered — the
    /// baseline policy view backing `GET /curation/rules?scope=global`.
    /// Served by the `idx_curation_rules_scope_global` partial index.
    pub async fn list_global_rules(&self) -> Result<Vec<CurationRule>, sqlx::Error> {
        sqlx::query_as(
            r#"SELECT * FROM curation_rules
               WHERE scope = 'global'
               ORDER BY priority ASC, created_at ASC"#,
        )
        .fetch_all(&self.db)
        .await
    }

    /// Fetch a single rule by id. Returns `NotFound` when the id is unknown.
    pub async fn get_rule(&self, rule_id: Uuid) -> Result<CurationRule, AppError> {
        let rule: Option<CurationRule> =
            sqlx::query_as("SELECT * FROM curation_rules WHERE id = $1")
                .bind(rule_id)
                .fetch_optional(&self.db)
                .await?;
        rule.ok_or_else(|| AppError::NotFound("Curation rule not found".to_string()))
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
        rule_type: &str,
        config: &serde_json::Value,
    ) -> Result<CurationRule, AppError> {
        let rule: Option<CurationRule> = sqlx::query_as(
            r#"UPDATE curation_rules SET
               package_pattern = $2, version_constraint = $3, architecture = $4,
               action = $5, priority = $6, reason = $7, enabled = $8,
               rule_type = $9, config = $10, updated_at = now()
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
        .bind(rule_type)
        .bind(config)
        .fetch_optional(&self.db)
        .await?;
        rule.ok_or_else(|| AppError::NotFound("Curation rule not found".to_string()))
    }

    pub async fn delete_rule(&self, rule_id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM curation_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&self.db)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Curation rule not found".to_string()));
        }
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
        primary_metadata: Option<&serde_json::Value>,
    ) -> Result<CurationPackage, sqlx::Error> {
        // Every production write of `curation_packages.metadata` lands here, so
        // this is the chokepoint that keeps a registry document from asserting
        // its own attestation verification (#2955). `extract_publisher` treats
        // the marker as a trusted server-side record; a persisted row must never
        // carry one it did not get from our verifier.
        let mut sanitized;
        let metadata = if metadata
            .get(crate::services::curation::publisher_source::VERIFICATION_MARKER)
            .is_some()
        {
            sanitized = metadata.clone();
            crate::services::curation::publisher_source::strip_verification_marker(&mut sanitized);
            tracing::warn!(
                %package_name,
                %version,
                "curation ingest: stripped a self-asserted attestation-verification marker from upstream metadata"
            );
            &sanitized
        } else {
            metadata
        };

        sqlx::query_as(
            r#"INSERT INTO curation_packages
               (staging_repo_id, remote_repo_id, format, package_name, version, release,
                architecture, checksum_sha256, upstream_path, metadata, primary_metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
               ON CONFLICT (staging_repo_id, format, package_name, version,
                           COALESCE(release, ''), COALESCE(architecture, ''))
               DO UPDATE SET checksum_sha256 = EXCLUDED.checksum_sha256,
                            upstream_path = EXCLUDED.upstream_path,
                            metadata = EXCLUDED.metadata,
                            primary_metadata = EXCLUDED.primary_metadata,
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
        .bind(primary_metadata)
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

    /// Search synced packages of one staging repo by name (#2357 WI-6).
    ///
    /// Filters `curation_packages` for `staging_repo_id`, optionally narrowing
    /// by a case-insensitive substring of `package_name` (`q`), an exact
    /// `architecture`, and a `status`. Ordered by name/version and paginated.
    /// This is the user/dnf-facing search over synced metadata, distinct from
    /// [`list_packages`](Self::list_packages) (a status-filtered review listing).
    /// The name filter is served by `idx_curation_pkg_name`.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_packages(
        &self,
        staging_repo_id: Uuid,
        q: Option<&str>,
        arch: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CurationPackage>, sqlx::Error> {
        // `q` becomes a case-insensitive substring match; NULL binds disable the
        // corresponding predicate. A single parameterized query keeps the name
        // ILIKE index-usable and avoids per-filter SQL string assembly.
        let name_like = q.map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| {
            format!(
                "%{}%",
                s.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            )
        });
        let arch = arch.map(|s| s.trim()).filter(|s| !s.is_empty());
        let status = status.map(|s| s.trim()).filter(|s| !s.is_empty());

        sqlx::query_as(
            r#"SELECT * FROM curation_packages
               WHERE staging_repo_id = $1
                 AND ($2::text IS NULL OR package_name ILIKE $2)
                 AND ($3::text IS NULL OR architecture = $3)
                 AND ($4::text IS NULL OR status = $4)
               ORDER BY package_name ASC, version ASC
               LIMIT $5 OFFSET $6"#,
        )
        .bind(staging_repo_id)
        .bind(name_like)
        .bind(arch)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
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

    /// Persist an attestation-verification result (#2955) onto a curation
    /// package. `state` is one of `unverified|verified|failed`; identity /
    /// issuer / owner are the CERTIFICATE-BOUND values (populated on success
    /// only), and `error` the specific failing-check reason otherwise. The
    /// non-macro query API is used deliberately so no offline `.sqlx` cache
    /// regeneration is needed.
    pub async fn record_attestation(
        &self,
        id: Uuid,
        state: &str,
        identity: Option<&str>,
        issuer: Option<&str>,
        owner: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"UPDATE curation_packages SET
               attestation_state = $2, attestation_identity = $3,
               attestation_issuer = $4, attestation_owner = $5,
               attestation_error = $6, attestation_verified_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(state)
        .bind(identity)
        .bind(issuer)
        .bind(owner)
        .bind(error)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Load pending catalog rows for one format under a staging repo — the
    /// on-demand-ingested pypi/npm packages the scheduler evaluates (#2955
    /// Stage 2). Bounded by `limit` so a large backlog is processed in slices.
    pub async fn list_pending_packages_by_format(
        &self,
        staging_repo_id: Uuid,
        format: &str,
        limit: i64,
    ) -> Result<Vec<CurationPackage>, sqlx::Error> {
        sqlx::query_as(
            r#"SELECT * FROM curation_packages
               WHERE staging_repo_id = $1 AND format = $2 AND status = 'pending'
               ORDER BY first_seen_at ASC
               LIMIT $3"#,
        )
        .bind(staging_repo_id)
        .bind(format)
        .bind(limit)
        .fetch_all(&self.db)
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
    ///
    /// Exact-name matching against a known version — the staging/sync semantics.
    /// See [`Self::evaluate_rules`] for the general form.
    fn evaluate_package_in_memory(
        rules: &[CurationRule],
        default_action: &str,
        package_name: &str,
        version: &str,
        architecture: Option<&str>,
    ) -> RuleEvaluation {
        Self::evaluate_rules(
            rules,
            default_action,
            package_name,
            Some(version),
            architecture,
            false,
        )
    }

    /// First-match rule evaluation against a pre-fetched rule set (no DB call).
    ///
    /// `version` is `None` when the caller does not know the version, and
    /// `fold_names` folds both the rule pattern and the package name per PEP 503
    /// before matching (see [`Self::evaluate_pep503_package`]).
    ///
    /// Only `rule_type = "pattern"` rules participate: typed rules
    /// (`publisher_trust`, `popularity`, #2947) default their
    /// `package_pattern` to `*`, so interpreting them here would silently
    /// turn e.g. a global publisher-trust `block` policy into a
    /// block-everything glob on the legacy paths (the PEP 503 proxy gate).
    /// Typed rules are evaluated exclusively by [`Self::evaluate_typed_rules`].
    fn evaluate_rules(
        rules: &[CurationRule],
        default_action: &str,
        package_name: &str,
        version: Option<&str>,
        architecture: Option<&str>,
        fold_names: bool,
    ) -> RuleEvaluation {
        let folded_name = fold_names.then(|| Self::fold_pep503(package_name));

        for rule in rules {
            if rule.rule_type != "pattern" {
                continue;
            }
            let name_matches = match folded_name.as_deref() {
                Some(name) => {
                    Self::pattern_matches(&Self::fold_pep503(&rule.package_pattern), name)
                }
                None => Self::pattern_matches(&rule.package_pattern, package_name),
            };
            if !name_matches {
                continue;
            }

            let constraint = rule.version_constraint.trim();
            match version {
                Some(v) => {
                    if !Self::version_matches(constraint, v) {
                        continue;
                    }
                }
                // The request carries no version, so a version-constrained rule
                // cannot be decided. Skip it rather than comparing the constraint
                // against a placeholder: `version_compare` would treat the
                // placeholder as a literal version, which silently makes `>=` and
                // `=` rules match nothing and `<` rules match *every* version
                // (#2912).
                None if constraint != "*" => {
                    tracing::debug!(
                        rule_id = %rule.id,
                        constraint = %constraint,
                        package = %package_name,
                        "Skipping version-constrained curation rule: request carries no version"
                    );
                    continue;
                }
                None => {}
            }

            if rule.architecture != "*" {
                match architecture {
                    Some(arch) if rule.architecture == arch => {}
                    // Either the request is for a different architecture, or it
                    // carries none and an architecture-scoped rule cannot be
                    // decided. Both must skip the rule. Previously a `None`
                    // request skipped the *check*, so an architecture-scoped rule
                    // matched every request — including an `allow` rule shadowing
                    // a lower-priority `block` (#2912).
                    _ => continue,
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
    /// Fetches rules once, evaluates each package through the typed dispatch
    /// (#2947: `pattern`, `publisher_trust`, `popularity` rules all apply),
    /// then batches the status updates to avoid N+1 query overhead. Popularity
    /// lookups go through one TTL-cached HTTP source for the whole batch, so
    /// re-evaluating a large catalog cannot hammer the public download-count
    /// APIs.
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

        // One cached source for the whole batch: repeated evaluations of the
        // same package hit the in-memory TTL cache, not the public APIs.
        let popularity_source =
            crate::services::curation::popularity_source::HttpPopularitySource::new().cached();

        for pkg in &pending {
            let context = Self::context_metadata(&pkg.metadata, pkg.architecture.as_deref());
            let (decision, rule_id) = Self::evaluate_typed_rules(
                &rules,
                Self::default_decision(default_action),
                &pkg.format,
                &pkg.package_name,
                &pkg.version,
                &context,
                &popularity_source,
            )
            .await;

            let (new_status, reason) = Self::decision_to_status_reason(&decision, rule_id);

            groups
                .entry((new_status.to_string(), reason, rule_id))
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

/// Compare two version strings. Returns -1, 0, or 1.
/// Splits on `.` and `-`, compares segments numerically when possible.
pub(crate) fn version_compare(a: &str, b: &str) -> i32 {
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
            rule_type: "pattern".to_string(),
            config: serde_json::json!({}),
            scope: "global".to_string(),
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

    // -- typed rule dispatch (#2947) ------------------------------------------

    use crate::services::curation::popularity_source::FakePopularitySource;

    fn typed_rule(rule_type: &str, config: serde_json::Value) -> CurationRule {
        let mut rule = make_rule("*", "*", "*", "allow");
        rule.rule_type = rule_type.to_string();
        rule.config = config;
        rule
    }

    /// Empty popularity source for tests that never exercise the popularity
    /// arm (every lookup would return `Unknown`).
    fn no_source() -> FakePopularitySource {
        FakePopularitySource::new()
    }

    #[tokio::test]
    async fn test_dispatch_pattern_block_matches_legacy_evaluation() {
        // Regression: a matching pattern rule renders the same verdict + reason
        // through the typed dispatch as through the legacy in-memory path.
        let rule = make_rule("telnet*", "*", "*", "block");
        let decision = CurationService::evaluate_typed_rule(
            &rule,
            "rpm",
            "telnet-server",
            "1.0",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        assert_eq!(decision, CurationDecision::Block(rule.reason.clone()));

        let legacy = CurationService::evaluate_package_in_memory(
            &[rule.clone()],
            "allow",
            "telnet-server",
            "1.0",
            None,
        );
        assert_eq!(legacy.action, "block");
        assert_eq!(legacy.reason, rule.reason);
    }

    #[tokio::test]
    async fn test_dispatch_pattern_non_match_is_not_applicable() {
        let rule = make_rule("telnet*", "*", "*", "block");
        let decision = CurationService::evaluate_typed_rule(
            &rule,
            "rpm",
            "curl",
            "8.0",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        assert_eq!(decision, CurationDecision::NotApplicable);
    }

    #[tokio::test]
    async fn test_dispatch_pattern_allow_rule_matches() {
        let rule = make_rule("nginx", ">= 1.0", "*", "allow");
        let decision = CurationService::evaluate_typed_rule(
            &rule,
            "rpm",
            "nginx",
            "1.5",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        assert_eq!(decision, CurationDecision::Allow);
    }

    #[tokio::test]
    async fn test_dispatch_pattern_reads_architecture_from_metadata() {
        // The typed context carries architecture inside `metadata`; an
        // arch-scoped pattern rule must honor it in both directions.
        let rule = make_rule("*", "*", "aarch64", "block");
        let mismatched = CurationService::evaluate_typed_rule(
            &rule,
            "rpm",
            "nginx",
            "1.0",
            &serde_json::json!({"architecture": "x86_64"}),
            &no_source(),
        )
        .await;
        assert_eq!(mismatched, CurationDecision::NotApplicable);

        let matched = CurationService::evaluate_typed_rule(
            &rule,
            "rpm",
            "nginx",
            "1.0",
            &serde_json::json!({"architecture": "aarch64"}),
            &no_source(),
        )
        .await;
        assert_eq!(matched, CurationDecision::Block(rule.reason.clone()));
    }

    #[tokio::test]
    async fn test_dispatch_publisher_trust_reaches_real_evaluator() {
        // The #2948 evaluator (not the retired stub): a spoofed self-asserted
        // `author` must NOT satisfy a `match: attestation` allowlist.
        let rule = typed_rule(
            "publisher_trust",
            serde_json::json!({
                "trusted_publishers": ["Microsoft"],
                "match": "attestation",
                "action": "block"
            }),
        );
        let spoofed = serde_json::json!({
            "info": {"author": "Microsoft", "author_email": "attacker@example.com"}
        });
        let decision = CurationService::evaluate_typed_rule(
            &rule,
            "pypi",
            "azure-coore",
            "99.0.0",
            &spoofed,
            &no_source(),
        )
        .await;
        match decision {
            CurationDecision::Block(reason) => {
                assert!(
                    reason.contains("requires registry-verified provenance"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected Block from the real evaluator, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_dispatch_popularity_reaches_real_evaluator() {
        // The #2949 evaluator (not the retired stub): a seeded below-threshold
        // count must Flag, proving the source is threaded through the dispatch.
        let source = FakePopularitySource::new().with("pypi", "obscure-pkg", 42);
        let rule = typed_rule("popularity", serde_json::json!({"min_downloads": 1000}));
        let decision = CurationService::evaluate_typed_rule(
            &rule,
            "pypi",
            "obscure-pkg",
            "0.1.0",
            &serde_json::json!({}),
            &source,
        )
        .await;
        match decision {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("42"), "reason carries the count: {reason}");
                assert!(
                    reason.contains("1000"),
                    "reason carries the threshold: {reason}"
                );
            }
            other => panic!("expected Flag from the real evaluator, got {other:?}"),
        }
        assert_eq!(source.call_count(), 1);
    }

    #[tokio::test]
    async fn test_dispatch_publisher_trust_not_applicable_format() {
        // A format with no publisher concept must have NO effect — a global
        // publisher-trust baseline cannot block/flag e.g. generic artifacts.
        let rule = typed_rule(
            "publisher_trust",
            serde_json::json!({"trusted_publishers": ["acme"]}),
        );
        for format in ["generic", "rpm", "debian", "docker"] {
            let decision = CurationService::evaluate_typed_rule(
                &rule,
                format,
                "some-artifact",
                "1.0",
                &serde_json::json!({}),
                &no_source(),
            )
            .await;
            assert_eq!(
                decision,
                CurationDecision::NotApplicable,
                "publisher_trust must be NotApplicable for {format}"
            );
        }
    }

    #[tokio::test]
    async fn test_dispatch_popularity_not_applicable_format_skips_source() {
        // Format-gate FIRST: an inapplicable format is NotApplicable and the
        // popularity source is never consulted (no wasted fetch).
        let source = no_source();
        let rule = typed_rule("popularity", serde_json::json!({"min_downloads": 1000}));
        for format in ["generic", "rpm", "helm"] {
            let decision = CurationService::evaluate_typed_rule(
                &rule,
                format,
                "some-artifact",
                "1.0",
                &serde_json::json!({}),
                &source,
            )
            .await;
            assert_eq!(
                decision,
                CurationDecision::NotApplicable,
                "popularity must be NotApplicable for {format}"
            );
        }
        assert_eq!(
            source.call_count(),
            0,
            "inapplicable formats must not consult the popularity source"
        );
    }

    #[tokio::test]
    async fn test_evaluate_typed_rules_skips_not_applicable() {
        // A global popularity rule (NotApplicable for rpm) followed by a
        // pattern block: the popularity rule must have no effect and the
        // pattern rule must still decide.
        let popularity = typed_rule("popularity", serde_json::json!({"min_downloads": 10}));
        let block = make_rule("telnet*", "*", "*", "block");
        let (decision, rule_id) = CurationService::evaluate_typed_rules(
            &[popularity, block.clone()],
            CurationDecision::Allow,
            "rpm",
            "telnet-server",
            "1.0",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        assert_eq!(decision, CurationDecision::Block(block.reason.clone()));
        assert_eq!(rule_id, Some(block.id));
    }

    #[tokio::test]
    async fn test_evaluate_typed_rules_default_when_nothing_applies() {
        let popularity = typed_rule("popularity", serde_json::json!({}));
        let miss = make_rule("telnet*", "*", "*", "block");
        let (decision, rule_id) = CurationService::evaluate_typed_rules(
            &[popularity, miss],
            CurationDecision::Allow,
            "rpm",
            "curl",
            "8.0",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        assert_eq!(decision, CurationDecision::Allow);
        assert!(rule_id.is_none());
    }

    #[tokio::test]
    async fn test_evaluate_typed_rules_first_decision_wins() {
        // Legacy parity: an earlier allow shadows a later block.
        let allow = make_rule("nginx", "*", "*", "allow");
        let block = make_rule("nginx", "*", "*", "block");
        let (decision, rule_id) = CurationService::evaluate_typed_rules(
            &[allow.clone(), block],
            CurationDecision::Block("default".into()),
            "rpm",
            "nginx",
            "1.0",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        assert_eq!(decision, CurationDecision::Allow);
        assert_eq!(rule_id, Some(allow.id));
    }

    #[tokio::test]
    async fn test_dispatch_unknown_rule_type_flags_for_review() {
        // Defense-in-depth: an unrecognized engine must never silently allow.
        let rule = typed_rule("mystery", serde_json::json!({}));
        let decision = CurationService::evaluate_typed_rule(
            &rule,
            "rpm",
            "nginx",
            "1.0",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        match decision {
            CurationDecision::Flag(reason) => {
                assert!(
                    reason.contains("mystery"),
                    "reason names the type: {reason}"
                )
            }
            other => panic!("unknown rule_type must Flag, got {other:?}"),
        }
    }

    // -- decision/status mapping (#2947 integration) --------------------------

    #[test]
    fn test_decision_to_status_reason_mapping() {
        let id = Uuid::new_v4();
        assert_eq!(
            CurationService::decision_to_status_reason(&CurationDecision::Allow, Some(id)).0,
            "approved"
        );
        let (status, reason) = CurationService::decision_to_status_reason(
            &CurationDecision::Block("bad publisher".into()),
            Some(id),
        );
        assert_eq!(status, "blocked");
        assert_eq!(reason, "bad publisher");
        let (status, reason) = CurationService::decision_to_status_reason(
            &CurationDecision::Flag("needs review".into()),
            Some(id),
        );
        assert_eq!(status, "review");
        assert_eq!(reason, "needs review");
        // Fail-safe: a stray NotApplicable routes to review, never approval.
        assert_eq!(
            CurationService::decision_to_status_reason(&CurationDecision::NotApplicable, None).0,
            "review"
        );
    }

    #[test]
    fn test_default_decision_mapping() {
        assert_eq!(
            CurationService::default_decision("allow"),
            CurationDecision::Allow
        );
        assert!(matches!(
            CurationService::default_decision("block"),
            CurationDecision::Block(_)
        ));
        assert!(matches!(
            CurationService::default_decision("review"),
            CurationDecision::Flag(_)
        ));
    }

    #[test]
    fn test_context_metadata_injects_architecture() {
        // Column arch threads into the pattern-rule context...
        let ctx = CurationService::context_metadata(&serde_json::json!({"a": 1}), Some("x86_64"));
        assert_eq!(ctx["architecture"], "x86_64");
        assert_eq!(ctx["a"], 1);
        // ...but never overrides one the blob already carries.
        let ctx = CurationService::context_metadata(
            &serde_json::json!({"architecture": "aarch64"}),
            Some("x86_64"),
        );
        assert_eq!(ctx["architecture"], "aarch64");
        // No arch: context is the blob unchanged.
        let ctx = CurationService::context_metadata(&serde_json::json!({"a": 1}), None);
        assert_eq!(ctx, serde_json::json!({"a": 1}));
    }

    #[test]
    fn test_legacy_pattern_engine_skips_typed_rules() {
        // A typed rule's defaulted `*` pattern + block action must NOT be
        // interpreted by the legacy pattern engine (the PEP 503 proxy gate and
        // staging-sync fallback) as a block-everything glob: typed rules are
        // evaluated only by the typed dispatch.
        let mut typed = typed_rule(
            "publisher_trust",
            serde_json::json!({"trusted_publishers": ["acme"]}),
        );
        typed.action = "block".to_string();
        let eval =
            CurationService::evaluate_package_in_memory(&[typed], "allow", "anything", "1.0", None);
        assert_eq!(eval.action, "allow", "typed rule must not decide here");
        assert!(eval.rule_id.is_none());
    }

    // -- by-id not-found mapping (#2020) --------------------------------------
    //
    // get_rule / update_rule / delete_rule must surface an unknown id as
    // `AppError::NotFound` (HTTP 404), not a masked 204 (delete) or a 500 from
    // `RowNotFound` (update). These tests are DB-backed and skip silently when
    // `DATABASE_URL` is unset so offline `cargo test --lib` stays usable.
    async fn try_service() -> Option<CurationService> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::PgPool::connect(&url).await.ok()?;
        Some(CurationService::new(pool))
    }

    // -- typed rule persistence (#2947, DB-backed) ----------------------------

    // A global publisher_trust rule round-trips rule_type + config through
    // create/list/get, derives scope='global' from the absent staging repo,
    // and shows up in the global-baseline listing.
    #[tokio::test]
    async fn test_create_typed_global_rule_round_trip_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _uname) = tdh::create_user(&pool).await;
        let svc = CurationService::new(pool.clone());

        let config = serde_json::json!({"min_trust": 0.9, "trusted_publishers": ["acme"]});
        let rule = svc
            .create_rule(
                None,
                "*",
                "*",
                "*",
                "block",
                50,
                "untrusted publisher (#2947 test)",
                "publisher_trust",
                &config,
                user,
            )
            .await
            .expect("create typed global rule");
        assert_eq!(rule.rule_type, "publisher_trust");
        assert_eq!(rule.config, config);
        assert_eq!(rule.scope, "global", "NULL repo must derive scope=global");
        assert!(rule.staging_repo_id.is_none());

        let fetched = svc.get_rule(rule.id).await.expect("get typed rule");
        assert_eq!(fetched.rule_type, "publisher_trust");
        assert_eq!(fetched.config, config);
        assert_eq!(fetched.scope, "global");

        let global = svc.list_global_rules().await.expect("list global rules");
        assert!(
            global.iter().any(|r| r.id == rule.id),
            "typed global rule must appear in the global-baseline listing"
        );

        // The persisted row reaches the real #2948 evaluator: an applicable
        // format with no extractable publisher fails safe (Flag), a
        // non-applicable format is NotApplicable.
        let dec = CurationService::evaluate_typed_rule(
            &fetched,
            "npm",
            "left-pad",
            "1.3.0",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        assert!(
            matches!(dec, CurationDecision::Flag(ref r) if r.contains("publisher unknown")),
            "expected fail-safe Flag for missing publisher, got {dec:?}"
        );
        let na = CurationService::evaluate_typed_rule(
            &fetched,
            "generic",
            "blob",
            "1.0",
            &serde_json::json!({}),
            &no_source(),
        )
        .await;
        assert_eq!(na, CurationDecision::NotApplicable);

        svc.delete_rule(rule.id).await.expect("delete typed rule");
        tdh::cleanup_user(&pool, user).await;
    }

    // Migration compatibility: a rule inserted the pre-#2947 way (no
    // rule_type/config columns named) defaults to rule_type='pattern' with an
    // empty config and still evaluates exactly as before.
    #[tokio::test]
    async fn test_legacy_insert_defaults_to_pattern_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _uname) = tdh::create_user(&pool).await;
        let rule: CurationRule = sqlx::query_as(
            r#"INSERT INTO curation_rules
               (staging_repo_id, package_pattern, version_constraint, architecture, action, priority, reason, created_by)
               VALUES (NULL, 'telnet*', '*', '*', 'block', 100, 'legacy insert (#2947 test)', $1)
               RETURNING *"#,
        )
        .bind(user)
        .fetch_one(&pool)
        .await
        .expect("legacy-shape insert");
        assert_eq!(
            rule.rule_type, "pattern",
            "rule_type must default to pattern"
        );
        assert_eq!(rule.config, serde_json::json!({}));

        let eval = CurationService::evaluate_package_in_memory(
            &[rule.clone()],
            "allow",
            "telnet-server",
            "1.0",
            None,
        );
        assert_eq!(eval.action, "block");
        assert_eq!(eval.rule_id, Some(rule.id));

        let svc = CurationService::new(pool.clone());
        svc.delete_rule(rule.id).await.expect("delete legacy rule");
        tdh::cleanup_user(&pool, user).await;
    }

    // -- typed enforcement end-to-end (#2947 integration, DB-backed) ----------
    //
    // These exercise the WIRED feature: a persisted GLOBAL typed rule flows
    // through fetch_applicable_rules -> evaluate_typed_rules -> the real
    // #2948/#2949 evaluators, via the production `evaluate_package_typed`
    // entry point.

    /// PyPI JSON-API blob with a merged integrity-API provenance object
    /// naming the Trusted-Publisher org `NumFOCUS`. Presence-only: the
    /// envelope is not cryptographically verified (#2955).
    fn pypi_attested_metadata() -> serde_json::Value {
        serde_json::json!({
            "info": {"author": "NumPy Developers", "name": "numpy", "version": "2.0.0"},
            "provenance": {
                "attestation_bundles": [{
                    "publisher": {"kind": "GitHub", "repository": "NumFOCUS/numpy", "workflow": "wheels.yml"},
                    "attestations": [{"envelope": {}}]
                }]
            }
        })
    }

    #[tokio::test]
    async fn test_integration_global_publisher_trust_rule_end_to_end_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let _guard = tdh::curation_global_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _uname) = tdh::create_user(&pool).await;
        let svc = CurationService::new(pool.clone());

        let config = serde_json::json!({
            "trusted_publishers": ["NumFOCUS"],
            "match": "attestation",
            "action": "block"
        });
        let rule = svc
            .create_rule(
                None,
                "*",
                "*",
                "*",
                "block",
                1,
                "only attested trusted publishers (#2947 integ test)",
                "publisher_trust",
                &config,
                user,
            )
            .await
            .expect("create global publisher_trust rule");

        // Any staging repo sees the global baseline (staging_repo_id IS NULL).
        let probe_repo = Uuid::new_v4();

        // Non-attested package (self-asserted author only) -> Block.
        let spoofed = serde_json::json!({
            "info": {"author": "NumFOCUS", "author_email": "attacker@example.com"}
        });
        let (decision, matched) = svc
            .evaluate_package_typed(
                probe_repo,
                "allow",
                "pypi",
                "numpy-coore",
                "99.0.0",
                None,
                &spoofed,
                &no_source(),
            )
            .await
            .expect("typed evaluation");
        assert_eq!(matched, Some(rule.id), "the global rule must decide");
        assert!(
            matches!(decision, CurationDecision::Block(ref r)
                if r.contains("requires registry-verified provenance")),
            "non-attested package must be blocked, got {decision:?}"
        );

        // Attested package from the trusted publisher -> review (Flag): the
        // attestation is present but not cryptographically verified (#2955),
        // so presence must not buy trust — and must not hard-block either.
        let (decision, matched) = svc
            .evaluate_package_typed(
                probe_repo,
                "allow",
                "pypi",
                "numpy",
                "2.0.0",
                None,
                &pypi_attested_metadata(),
                &no_source(),
            )
            .await
            .expect("typed evaluation");
        assert_eq!(matched, Some(rule.id));
        assert!(
            matches!(decision, CurationDecision::Flag(ref r)
                if r.contains("not cryptographically verified")),
            "attested-but-unverified package must go to review, got {decision:?}"
        );

        // A format with no publisher concept passes through untouched.
        let (decision, matched) = svc
            .evaluate_package_typed(
                probe_repo,
                "allow",
                "raw",
                "some-blob",
                "1.0",
                None,
                &serde_json::json!({}),
                &no_source(),
            )
            .await
            .expect("typed evaluation");
        assert_eq!(matched, None, "global rule must have no effect on raw");
        assert_eq!(decision, CurationDecision::Allow);

        svc.delete_rule(rule.id).await.expect("delete rule");
        tdh::cleanup_user(&pool, user).await;
    }

    #[tokio::test]
    async fn test_integration_global_popularity_rule_end_to_end_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let _guard = tdh::curation_global_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _uname) = tdh::create_user(&pool).await;
        let svc = CurationService::new(pool.clone());

        let config = serde_json::json!({"min_downloads": 500, "action": "block"});
        let rule = svc
            .create_rule(
                None,
                "*",
                "*",
                "*",
                "block",
                1,
                "minimum adoption bar (#2947 integ test)",
                "popularity",
                &config,
                user,
            )
            .await
            .expect("create global popularity rule");

        let probe_repo = Uuid::new_v4();
        let source = FakePopularitySource::new()
            .with("pypi", "obscure-lib", 10)
            .with("pypi", "reqeusts", 900);

        // Below threshold with action=block -> Block.
        let (decision, matched) = svc
            .evaluate_package_typed(
                probe_repo,
                "allow",
                "pypi",
                "obscure-lib",
                "0.0.1",
                None,
                &serde_json::json!({}),
                &source,
            )
            .await
            .expect("typed evaluation");
        assert_eq!(matched, Some(rule.id));
        assert!(
            matches!(decision, CurationDecision::Block(ref r)
                if r.contains("below the configured minimum")),
            "below-threshold package must be blocked, got {decision:?}"
        );

        // Above threshold but one edit from `requests` -> advisory typo-squat
        // Flag (never a block from the lexical signal alone).
        let (decision, matched) = svc
            .evaluate_package_typed(
                probe_repo,
                "allow",
                "pypi",
                "reqeusts",
                "1.0.0",
                None,
                &serde_json::json!({}),
                &source,
            )
            .await
            .expect("typed evaluation");
        assert_eq!(matched, Some(rule.id));
        assert!(
            matches!(decision, CurationDecision::Flag(ref r)
                if r.contains("requests") && r.contains("typo-squat")),
            "typo-squat must flag and name the target, got {decision:?}"
        );

        // A format with no download-count ecosystem passes through untouched —
        // and the source is never consulted for it.
        let calls_before = source.call_count();
        let (decision, matched) = svc
            .evaluate_package_typed(
                probe_repo,
                "allow",
                "raw",
                "some-blob",
                "1.0",
                None,
                &serde_json::json!({}),
                &source,
            )
            .await
            .expect("typed evaluation");
        assert_eq!(matched, None);
        assert_eq!(decision, CurationDecision::Allow);
        assert_eq!(
            source.call_count(),
            calls_before,
            "inapplicable format must not consult the popularity source"
        );

        svc.delete_rule(rule.id).await.expect("delete rule");
        tdh::cleanup_user(&pool, user).await;
    }

    #[tokio::test]
    async fn test_integration_global_union_repo_rules_first_applicable_wins_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let _guard = tdh::curation_global_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _uname) = tdh::create_user(&pool).await;
        let (repo_id, _key, _dir) = tdh::create_repo(&pool, "staging", "pypi").await;
        let svc = CurationService::new(pool.clone());

        // Repo-scoped pattern allow at higher priority (lower number)...
        let repo_allow = svc
            .create_rule(
                Some(repo_id),
                "legit-*",
                "*",
                "*",
                "allow",
                1,
                "vetted internal packages (#2947 integ test)",
                "pattern",
                &serde_json::json!({}),
                user,
            )
            .await
            .expect("create repo pattern rule");
        assert_eq!(repo_allow.scope, "repository");

        // ...union-ed with a global publisher_trust block baseline.
        let global_block = svc
            .create_rule(
                None,
                "*",
                "*",
                "*",
                "block",
                2,
                "untrusted publishers blocked (#2947 integ test)",
                "publisher_trust",
                &serde_json::json!({
                    "trusted_publishers": ["NumFOCUS"],
                    "match": "attestation",
                    "action": "block"
                }),
                user,
            )
            .await
            .expect("create global publisher_trust rule");

        let untrusted_metadata = serde_json::json!({"info": {"author": "somebody"}});

        // The repo allow matches first for its pattern: first-applicable wins
        // over the later global block.
        let (decision, matched) = svc
            .evaluate_package_typed(
                repo_id,
                "review",
                "pypi",
                "legit-tool",
                "1.0.0",
                None,
                &untrusted_metadata,
                &no_source(),
            )
            .await
            .expect("typed evaluation");
        assert_eq!(matched, Some(repo_allow.id));
        assert_eq!(decision, CurationDecision::Allow);

        // Outside the repo pattern, the global baseline decides.
        let (decision, matched) = svc
            .evaluate_package_typed(
                repo_id,
                "review",
                "pypi",
                "random-pkg",
                "1.0.0",
                None,
                &untrusted_metadata,
                &no_source(),
            )
            .await
            .expect("typed evaluation");
        assert_eq!(matched, Some(global_block.id));
        assert!(
            matches!(decision, CurationDecision::Block(_)),
            "global baseline must block untrusted publishers, got {decision:?}"
        );

        // Another repository sees the global baseline but NOT this repo's rule.
        let other_repo = Uuid::new_v4();
        let (decision, matched) = svc
            .evaluate_package_typed(
                other_repo,
                "review",
                "pypi",
                "legit-tool",
                "1.0.0",
                None,
                &untrusted_metadata,
                &no_source(),
            )
            .await
            .expect("typed evaluation");
        assert_eq!(
            matched,
            Some(global_block.id),
            "repo-scoped allow must not leak to other repositories"
        );
        assert!(matches!(decision, CurationDecision::Block(_)));

        svc.delete_rule(repo_allow.id).await.expect("delete rule");
        svc.delete_rule(global_block.id).await.expect("delete rule");
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("delete repo");
        tdh::cleanup_user(&pool, user).await;
    }

    #[tokio::test]
    async fn test_get_rule_missing_id_returns_not_found() {
        let Some(svc) = try_service().await else {
            return;
        };
        let err = svc.get_rule(Uuid::new_v4()).await.unwrap_err();
        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_delete_rule_missing_id_returns_not_found() {
        let Some(svc) = try_service().await else {
            return;
        };
        let err = svc.delete_rule(Uuid::new_v4()).await.unwrap_err();
        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_update_rule_missing_id_returns_not_found() {
        let Some(svc) = try_service().await else {
            return;
        };
        let err = svc
            .update_rule(
                Uuid::new_v4(),
                "pkg-*",
                "*",
                "*",
                "block",
                100,
                "qa",
                true,
                "pattern",
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    // -- #2955 on-demand pypi/npm ingestion + verified path (DB-backed) --------

    /// End-to-end proof that (1) an on-demand-ingested pypi package reaches the
    /// typed evaluator, (2) the attestation-verification columns round-trip, and
    /// (3) a persisted VERIFIED record makes the previously-unreachable
    /// `verified=true` Allow arm fire under `match:attestation, action:allow`.
    #[tokio::test]
    async fn test_ondemand_pypi_ingest_and_verified_path_end_to_end_db() {
        use crate::api::handlers::proxy_helpers::enqueue_curation_on_demand;
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::curation::publisher_source::VERIFICATION_MARKER;
        use crate::services::curation_sync::build_npm_curation_entry;

        let _guard = tdh::curation_global_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _uname) = tdh::create_user(&pool).await;
        let svc = CurationService::new(pool.clone());

        // A remote (proxy) repo and a staging repo that curates it.
        let (remote_id, _rk, _rp) = tdh::create_repo(&pool, "remote", "pypi").await;
        let (staging_id, _sk, _sp) = tdh::create_repo(&pool, "staging", "pypi").await;
        sqlx::query(
            "UPDATE repositories SET curation_enabled = true, curation_source_repo_id = $2, curation_default_action = 'allow' WHERE id = $1",
        )
        .bind(staging_id)
        .bind(remote_id)
        .execute(&pool)
        .await
        .expect("wire staging->remote curation");

        // Global publisher_trust rule: allow only the verified, trusted org.
        let config = serde_json::json!({
            "trusted_publishers": ["sigstore"],
            "match": "attestation",
            "action": "allow"
        });
        let rule = svc
            .create_rule(
                None,
                "*",
                "*",
                "*",
                "allow",
                1,
                "#2955 integ",
                "publisher_trust",
                &config,
                user,
            )
            .await
            .expect("create rule");

        // On-demand ingest via the proxy seam helper (reverse-lookup + upsert).
        let npm_like_pypi = serde_json::json!({
            "name": "sigstore", "version": "4.5.0",
            "_ak_dist": {"filename": "sigstore-4.5.0-py3-none-any.whl"},
            "provenance": {"attestation_bundles": [{"publisher": {"repository": "sigstore/sigstore-python"}}]}
        });
        // Reuse the npm builder only to get a well-formed entry object shape;
        // then coerce format to pypi with our own metadata.
        let mut entry =
            build_npm_curation_entry("sigstore", "4.5.0", &serde_json::json!({"dist": {}}))
                .expect("entry shell");
        entry.format = "pypi".to_string();
        entry.metadata = npm_like_pypi;
        enqueue_curation_on_demand(&pool, remote_id, "remote", entry).await;

        // The scheduler would find exactly this pending row.
        let pending = svc
            .list_pending_packages_by_format(staging_id, "pypi", 100)
            .await
            .expect("list pending");
        let pkg = pending
            .iter()
            .find(|p| p.package_name == "sigstore")
            .expect("ingested pypi row is pending")
            .clone();
        assert_eq!(pkg.status, "pending");

        // Before verification: attested-but-unverified -> review (fail-safe).
        let (decision, _rid) = svc
            .evaluate_package_typed(
                staging_id,
                "allow",
                "pypi",
                "sigstore",
                "4.5.0",
                None,
                &pkg.metadata,
                &no_source(),
            )
            .await
            .expect("pre-verify eval");
        assert!(
            matches!(decision, CurationDecision::Flag(_)),
            "pre-verify must Flag, got {decision:?}"
        );

        // Persist a VERIFIED record (as the scheduler does after the verifier).
        svc.record_attestation(
            pkg.id,
            "verified",
            Some("https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v4.5.0"),
            Some("https://token.actions.githubusercontent.com"),
            Some("sigstore"),
            None,
        )
        .await
        .expect("record attestation");

        // Inject the marker exactly as the scheduler eval loop does, then eval.
        let mut eval_md = pkg.metadata.clone();
        eval_md.as_object_mut().unwrap().insert(
            VERIFICATION_MARKER.to_string(),
            serde_json::json!({"state": "verified", "owner": "sigstore"}),
        );
        let (decision, matched) = svc
            .evaluate_package_typed(
                staging_id,
                "allow",
                "pypi",
                "sigstore",
                "4.5.0",
                None,
                &eval_md,
                &no_source(),
            )
            .await
            .expect("post-verify eval");
        assert_eq!(matched, Some(rule.id));
        assert_eq!(
            decision,
            CurationDecision::Allow,
            "a VERIFIED trusted publisher must finally be Allowed (#2955)"
        );

        // Columns round-trip.
        let row = svc.get_package(pkg.id).await.expect("get pkg");
        let db_state: String =
            sqlx::query_scalar("SELECT attestation_state FROM curation_packages WHERE id = $1")
                .bind(row.id)
                .fetch_one(&pool)
                .await
                .expect("read attestation_state");
        assert_eq!(db_state, "verified");
        let db_owner: Option<String> =
            sqlx::query_scalar("SELECT attestation_owner FROM curation_packages WHERE id = $1")
                .bind(row.id)
                .fetch_one(&pool)
                .await
                .expect("read attestation_owner");
        assert_eq!(db_owner.as_deref(), Some("sigstore"));

        // Cleanup.
        svc.delete_rule(rule.id).await.ok();
        sqlx::query("DELETE FROM curation_packages WHERE staging_repo_id = $1")
            .bind(staging_id)
            .execute(&pool)
            .await
            .ok();
        tdh::cleanup(&pool, staging_id, user).await;
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(remote_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// A registry document must not be able to assert its own attestation
    /// verification. `upsert_package` is the single production write path for
    /// `curation_packages.metadata`, so it is where the marker is stripped;
    /// without that, a hostile upstream blob carrying
    /// `_ak_attestation_verification` is persisted verbatim and
    /// `extract_publisher` hands back `verified = true` for an attacker-chosen
    /// owner on the very next evaluation.
    #[tokio::test]
    async fn test_upsert_package_strips_self_asserted_verification_marker_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::curation::publisher_source::{extract_publisher, VERIFICATION_MARKER};

        let _guard = tdh::curation_global_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _uname) = tdh::create_user(&pool).await;
        let svc = CurationService::new(pool.clone());
        let (remote_id, _rk, _rp) = tdh::create_repo(&pool, "remote", "pypi").await;
        let (staging_id, _sk, _sp) = tdh::create_repo(&pool, "staging", "pypi").await;

        // The blob an upstream would have to serve to forge trust — plus a real,
        // benign field so the row is still a valid publisher record afterwards.
        let hostile = serde_json::json!({
            "info": {"author": "NumFOCUS"},
            VERIFICATION_MARKER: {
                "state": "verified",
                "owner": "Microsoft",
                "issuer": "https://token.actions.githubusercontent.com"
            }
        });
        // Positive control: the blob really would be trusted if it survived.
        let forged = extract_publisher("pypi", &hostile).expect("blob extracts");
        assert!(
            forged.verified && forged.name == "Microsoft",
            "control: an unstripped marker must be trusted, else this proves nothing: {forged:?}"
        );

        let row = svc
            .upsert_package(
                staging_id,
                remote_id,
                "pypi",
                "forgery-probe",
                "1.0.0",
                None,
                None,
                None,
                "forgery_probe-1.0.0-py3-none-any.whl",
                &hostile,
                None,
            )
            .await
            .expect("upsert");

        assert!(
            row.metadata.get(VERIFICATION_MARKER).is_none(),
            "the persisted row must not carry a self-asserted marker: {}",
            row.metadata
        );
        // Re-read from the database, not just the RETURNING value.
        let stored: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM curation_packages WHERE id = $1")
                .bind(row.id)
                .fetch_one(&pool)
                .await
                .expect("read metadata");
        assert!(stored.get(VERIFICATION_MARKER).is_none(), "{stored}");

        // The rest of the blob is untouched, and the publisher falls back to the
        // unverified self-asserted identity — today's fail-safe behaviour.
        let id = extract_publisher("pypi", &stored).expect("publisher still extracts");
        assert!(!id.verified, "{id:?}");
        assert_eq!(id.name, "NumFOCUS");

        sqlx::query("DELETE FROM curation_packages WHERE staging_repo_id = $1")
            .bind(staging_id)
            .execute(&pool)
            .await
            .ok();
        tdh::cleanup(&pool, staging_id, user).await;
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(remote_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// npm is ingested but recorded unsupported — it must never flip to verified.
    #[tokio::test]
    async fn test_ondemand_npm_records_unsupported_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _guard = tdh::curation_global_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _uname) = tdh::create_user(&pool).await;
        let svc = CurationService::new(pool.clone());
        let (remote_id, _rk, _rp) = tdh::create_repo(&pool, "remote", "npm").await;
        let (staging_id, _sk, _sp) = tdh::create_repo(&pool, "staging", "npm").await;
        sqlx::query("UPDATE repositories SET curation_enabled = true, curation_source_repo_id = $2 WHERE id = $1")
            .bind(staging_id)
            .bind(remote_id)
            .execute(&pool)
            .await
            .expect("wire");

        let entry = crate::services::curation_sync::build_npm_curation_entry(
            "left-pad",
            "1.3.0",
            &serde_json::json!({"_npmUser": {"name": "someone"}, "dist": {"integrity": "sha512-x"}}),
        )
        .expect("npm entry");
        crate::api::handlers::proxy_helpers::enqueue_curation_on_demand(
            &pool, remote_id, "remote", entry,
        )
        .await;

        let pending = svc
            .list_pending_packages_by_format(staging_id, "npm", 100)
            .await
            .expect("list pending npm");
        let pkg = pending
            .into_iter()
            .find(|p| p.package_name == "left-pad")
            .expect("npm row");

        let verdict = crate::services::curation::attestation_verify::verify_npm_unsupported();
        assert!(!verdict.is_verified());
        svc.record_attestation(
            pkg.id,
            verdict.state.as_str(),
            None,
            None,
            None,
            verdict.error.as_deref(),
        )
        .await
        .expect("record npm");
        let db_state: String =
            sqlx::query_scalar("SELECT attestation_state FROM curation_packages WHERE id = $1")
                .bind(pkg.id)
                .fetch_one(&pool)
                .await
                .expect("read state");
        assert_eq!(
            db_state, "failed",
            "npm records failed/unsupported, never verified"
        );

        sqlx::query("DELETE FROM curation_packages WHERE staging_repo_id = $1")
            .bind(staging_id)
            .execute(&pool)
            .await
            .ok();
        tdh::cleanup(&pool, staging_id, user).await;
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(remote_id)
            .execute(&pool)
            .await
            .ok();
    }
}
