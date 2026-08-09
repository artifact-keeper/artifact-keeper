//! Service for evaluating and managing security policies.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{PolicyResult, ScanPolicy, Severity};
use crate::services::scan_state::ScanState;

/// Whether the `block_unscanned` gate should fire for an artifact in the given
/// aggregate scan state (#1649).
///
/// Fires when the policy enables it AND the artifact is "genuinely unscanned"
/// per [`ScanState::is_unscanned`] — i.e. it has no completed scan and the
/// reason is not "scanning does not apply". This deliberately fires on
/// `Failed` / `InProgress` / `NeverScanned`, closing the gap where a `failed`
/// or `pending` scan row used to satisfy the old `latest_scan.is_none()` check
/// and let the artifact bypass the gate. Pure / unit-testable.
fn block_unscanned_violated(block_unscanned: bool, scan_state: ScanState) -> bool {
    block_unscanned && scan_state.is_unscanned()
}

/// Which post-scan gates apply to an artifact, derived from its `scan_results`
/// rows.
#[derive(Debug, PartialEq, Eq)]
struct PostScanGates {
    /// At least one scanner's LATEST row is a genuine failure, so
    /// `block_on_fail` may fire (#3142).
    block_on_fail_applies: bool,
    /// Findings are on record for this artifact, so the `max_severity`
    /// threshold check must run.
    severity_applies: bool,
}

/// Decide which post-scan gates apply from the artifact's scan rows.
///
/// The two gates deliberately read DIFFERENT inputs:
///
/// * `block_on_fail` is about whether any engine's most recent attempt crashed,
///   so it keys on the latest row PER `scan_type` (#3142).
/// * `max_severity` is about the findings on record, so it keys on whether
///   there is anything on record to grade — not on "the newest row happens to
///   be completed".
///
/// #3142: `block_on_fail` used to key on a single `ORDER BY created_at DESC
/// LIMIT 1` across ALL `scan_type`s. With more than one engine enabled that is
/// a fail-open: scanner A crashes and writes `failed`, scanner B then finishes
/// clean, the global newest row reads `completed`, and `block_on_fail` never
/// fires. `classify_scan_state` is any-completed-wins, so `block_unscanned`
/// stays quiet too, and an artifact with a crashed scanner is served as fully
/// vetted with `block_on_fail` explicitly enabled. Keying per `scan_type` means
/// a later clean scan by a DIFFERENT engine can no longer mask engine A's
/// crash, while a genuine `completed` RESCAN by engine A itself still clears
/// it. Mirrors `scan_result_service::recalculate_score`'s `has_failed_scan`
/// window, which already had the right shape.
///
/// Both used to read the single newest row of any status, which made the
/// severity gate silently inert whenever the newest row was not `completed`.
/// Any scanner that records a non-terminal row (`pending`/`running`) or a
/// `not_applicable` row AFTER a completed one — an asynchronous or external
/// scanner does this routinely — therefore disabled severity blocking for that
/// artifact entirely, and a download with critical findings on record was
/// served with a 200. Keying on what is on record closes that fail-open.
///
/// Note the consequence for a `failed` newest row with `block_on_fail` off:
/// severity now still evaluates against the findings of the older completed
/// scan, where it previously skipped the check. That is the intended, strictly
/// safer direction — a crashed rescan must not clear an artifact's history.
///
/// `has_unacknowledged_findings` is the second half of that same argument.
/// Findings are persisted BEFORE the scan row is flipped to `completed`
/// (`scanner_service` calls `create_findings` and only then `complete_scan`),
/// so a scanner that dies in between — or is later reaped from `running` to
/// `failed` by the stuck-scan janitor — leaves unacknowledged findings on
/// record with NO completed row anywhere. Keying the gate on `completed`
/// alone would leave exactly the reported fail-open one layer down: an
/// unacknowledged critical on record, served 200. Grading whenever there is
/// something to grade cannot produce a false block, because the threshold
/// query returns zero when no finding meets the policy's severity.
/// Pure / unit-testable.
fn post_scan_gates(
    any_scanner_failed: bool,
    has_completed_scan: bool,
    has_unacknowledged_findings: bool,
) -> PostScanGates {
    PostScanGates {
        block_on_fail_applies: any_scanner_failed,
        severity_applies: has_completed_scan || has_unacknowledged_findings,
    }
}

/// Allowed values for `scan_policies.max_severity`, mirroring the DB CHECK
/// constraint in `migrations/022_security_scanning.sql`.
///
/// Note the set deliberately excludes `info` even though the scanner-side
/// [`Severity`] enum has an `Info` variant: `max_severity` is a blocking
/// threshold, and gating downloads on purely informational findings is never
/// a meaningful policy, so the schema never allowed it.
pub const ALLOWED_MAX_SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// Normalize and validate a client-supplied `max_severity` value (#2320).
///
/// Case-insensitive: `"Critical"` / `"HIGH"` are accepted and canonicalized
/// to lowercase so they satisfy the DB CHECK constraint. Anything outside the
/// allowed set returns [`AppError::Validation`] (400) with an actionable
/// message. Before this existed the raw string went straight into the
/// INSERT/UPDATE and a mis-cased or unknown value surfaced as a
/// CHECK-constraint violation, i.e. an opaque 500 `DATABASE_ERROR`.
fn normalize_max_severity(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if ALLOWED_MAX_SEVERITIES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(AppError::Validation(format!(
            "invalid max_severity '{raw}': must be one of critical, high, medium, low"
        )))
    }
}

/// Decision half of [`PolicyService::ensure_repository_exists`] (#2320): map
/// the `EXISTS` query result onto Ok / 404-NotFound. Split out from the DB
/// query so the contract — a missing FK target must surface as `NotFound`
/// naming the repository id, never a raw FK-violation 500 — is pure and
/// unit-testable.
fn repository_exists_or_not_found(exists: bool, repository_id: Uuid) -> Result<()> {
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound(format!(
            "Repository {repository_id} not found"
        )))
    }
}

pub struct PolicyService {
    db: PgPool,
}

impl PolicyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Evaluate all applicable policies for an artifact download.
    /// Returns whether the download is allowed and any violation reasons.
    pub async fn evaluate_artifact(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<PolicyResult> {
        // Find applicable policies: repo-specific + global (repository_id IS NULL)
        let policies: Vec<ScanPolicy> = sqlx::query_as(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, created_at, updated_at
            FROM scan_policies
            WHERE is_enabled = true
              AND (repository_id = $1 OR repository_id IS NULL)
            ORDER BY repository_id NULLS LAST
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if policies.is_empty() {
            return Ok(PolicyResult {
                allowed: true,
                violations: vec![],
            });
        }

        let mut violations = Vec::new();

        // Post-scan gate inputs. `has_completed_scan` is an existence check
        // (drives `max_severity`). See [`post_scan_gates`] for why these gates
        // must not share a single "newest row" lookup.
        #[derive(sqlx::FromRow)]
        struct ScanGateRow {
            has_completed_scan: bool,
            has_unacknowledged_findings: bool,
        }

        let gate_row: ScanGateRow = sqlx::query_as(
            r#"
            SELECT
                EXISTS (
                    SELECT 1
                      FROM scan_results
                     WHERE artifact_id = $1
                       AND status = 'completed'
                ) AS has_completed_scan,
                EXISTS (
                    SELECT 1
                      FROM scan_findings
                     WHERE artifact_id = $1
                       AND NOT is_acknowledged
                ) AS has_unacknowledged_findings
            "#,
        )
        .bind(artifact_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // #3142: `block_on_fail` reads the latest row PER `scan_type`, not one
        // global newest row, so a clean scan by engine B cannot mask engine A's
        // crash. "Not applicable" rows are excluded by `any_scanner_failed`.
        let latest_per_scan_type: Vec<crate::services::scan_state::ScanStateRow> =
            sqlx::query_as(crate::services::scan_state::LATEST_PER_SCAN_TYPE_SQL)
                .bind(artifact_id)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        let gates = post_scan_gates(
            crate::services::scan_state::any_scanner_failed(&latest_per_scan_type),
            gate_row.has_completed_scan,
            gate_row.has_unacknowledged_findings,
        );

        // #1649: classify the artifact's overall scan state from ALL its
        // scan_results rows (the same precedence the promotion gate uses), not
        // just whether the latest row exists. A `failed` / `pending` / `running`
        // scan still means the artifact was never SUCCESSFULLY scanned, so the
        // `block_unscanned` gate must treat it as unscanned. The old
        // `latest_scan.is_none()` check let those slip through whenever any scan
        // row existed, letting a crashed-scanner artifact bypass the gate when
        // `block_on_fail` was off.
        let scan_state_rows: Vec<crate::services::scan_state::ScanStateRow> =
            sqlx::query_as(crate::services::scan_state::SCAN_STATE_SQL)
                .bind(artifact_id)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let scan_state = crate::services::scan_state::classify_scan_state(&scan_state_rows);

        for policy in &policies {
            // Check: block_unscanned
            if block_unscanned_violated(policy.block_unscanned, scan_state) {
                violations.push(format!(
                    "Policy '{}': artifact has not been scanned ({})",
                    policy.name,
                    scan_state.reason_token()
                ));
                continue;
            }

            // Check: block_on_fail
            if policy.block_on_fail && gates.block_on_fail_applies {
                violations.push(format!("Policy '{}': latest scan failed", policy.name));
                continue;
            }

            // Check: max_severity threshold (non-acknowledged findings only)
            if gates.severity_applies {
                let _threshold =
                    Severity::from_str_loose(&policy.max_severity).unwrap_or(Severity::Critical);

                // Count non-acknowledged findings at or above the threshold
                let violating_count: i64 = sqlx::query_scalar(
                    r#"
                    SELECT COUNT(*)
                    FROM scan_findings
                    WHERE artifact_id = $1
                      AND NOT is_acknowledged
                      AND severity IN (
                          SELECT unnest(CASE $2
                              WHEN 'critical' THEN ARRAY['critical']
                              WHEN 'high' THEN ARRAY['critical', 'high']
                              WHEN 'medium' THEN ARRAY['critical', 'high', 'medium']
                              WHEN 'low' THEN ARRAY['critical', 'high', 'medium', 'low']
                              -- No ELSE would yield NULL -> unnest(NULL) -> zero
                              -- rows -> IN (<empty>) is false -> the gate passes
                              -- an artifact it was asked to block. A value
                              -- outside the four is unreachable today
                              -- (scan_policies_max_severity_check), so this is
                              -- defence in depth: an unknown threshold grades
                              -- against every severity rather than none.
                              ELSE ARRAY['critical', 'high', 'medium', 'low']
                          END)
                      )
                    "#,
                )
                .bind(artifact_id)
                .bind(&policy.max_severity)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

                if violating_count > 0 {
                    violations.push(format!(
                        "Policy '{}': {} findings at or above {} severity",
                        policy.name, violating_count, policy.max_severity
                    ));
                }
            }
        }

        Ok(PolicyResult {
            allowed: violations.is_empty(),
            violations,
        })
    }

    // -----------------------------------------------------------------------
    // CRUD
    // -----------------------------------------------------------------------

    /// Verify a repository id points at an existing repository (#2320).
    ///
    /// Scan policies can be scoped to a repository; a stale or mistyped id
    /// used to fall through to the `scan_policies_repository_id_fkey` FK
    /// violation on INSERT and surface as a 500. Checking first lets us
    /// return a proper 404.
    async fn ensure_repository_exists(&self, repository_id: Uuid) -> Result<()> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM repositories WHERE id = $1)")
                .bind(repository_id)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        repository_exists_or_not_found(exists, repository_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_policy(
        &self,
        name: &str,
        repository_id: Option<Uuid>,
        max_severity: &str,
        block_unscanned: bool,
        block_on_fail: bool,
        min_staging_hours: Option<i32>,
        max_artifact_age_days: Option<i32>,
        require_signature: bool,
    ) -> Result<ScanPolicy> {
        // #2320: validate inputs up front so a bad request comes back as a
        // 4xx instead of tripping the DB CHECK / FK constraint and surfacing
        // as an opaque 500 DATABASE_ERROR.
        let max_severity = normalize_max_severity(max_severity)?;
        if let Some(repo_id) = repository_id {
            self.ensure_repository_exists(repo_id).await?;
        }

        let policy: ScanPolicy = sqlx::query_as(
            r#"
            INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, block_on_fail,
                                       min_staging_hours, max_artifact_age_days, require_signature)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, name, repository_id, max_severity, block_unscanned,
                      block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                      require_signature, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(repository_id)
        .bind(&max_severity)
        .bind(block_unscanned)
        .bind(block_on_fail)
        .bind(min_staging_hours)
        .bind(max_artifact_age_days)
        .bind(require_signature)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policy)
    }

    pub async fn list_policies(&self) -> Result<Vec<ScanPolicy>> {
        let policies: Vec<ScanPolicy> = sqlx::query_as(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, created_at, updated_at
            FROM scan_policies
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policies)
    }

    pub async fn get_policy(&self, id: Uuid) -> Result<ScanPolicy> {
        sqlx::query_as::<_, ScanPolicy>(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, created_at, updated_at
            FROM scan_policies
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))
    }

    /// Apply a partial update to a scan policy. Any argument left as `None`
    /// keeps the existing column value via `COALESCE`. See #1374 -- previously
    /// the handler took every field as required, which (a) rejected legitimate
    /// PATCH-style PUTs from the release-gate `scan-policy-crud` suite with a
    /// 422 and (b) made it impossible to flip `is_enabled` without resubmitting
    /// the entire policy. A single atomic UPDATE statement preserves multi-
    /// field changes (so `max_severity` and `is_enabled` can both move in the
    /// same request) instead of the prior shape where a partial body might
    /// have only persisted whichever field deserialized first.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_policy(
        &self,
        id: Uuid,
        name: Option<&str>,
        max_severity: Option<&str>,
        block_unscanned: Option<bool>,
        block_on_fail: Option<bool>,
        is_enabled: Option<bool>,
        min_staging_hours: Option<i32>,
        max_artifact_age_days: Option<i32>,
        require_signature: Option<bool>,
    ) -> Result<ScanPolicy> {
        // #2320: same normalization as create_policy — a mis-cased or unknown
        // max_severity on update used to trip the DB CHECK constraint (500).
        let max_severity = max_severity.map(normalize_max_severity).transpose()?;

        let policy: ScanPolicy = sqlx::query_as(
            r#"
            UPDATE scan_policies
            SET name = COALESCE($2, name),
                max_severity = COALESCE($3, max_severity),
                block_unscanned = COALESCE($4, block_unscanned),
                block_on_fail = COALESCE($5, block_on_fail),
                is_enabled = COALESCE($6, is_enabled),
                min_staging_hours = COALESCE($7, min_staging_hours),
                max_artifact_age_days = COALESCE($8, max_artifact_age_days),
                require_signature = COALESCE($9, require_signature),
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, repository_id, max_severity, block_unscanned,
                      block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                      require_signature, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(max_severity)
        .bind(block_unscanned)
        .bind(block_on_fail)
        .bind(is_enabled)
        .bind(min_staging_hours)
        .bind(max_artifact_age_days)
        .bind(require_signature)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))?;

        Ok(policy)
    }

    pub async fn delete_policy(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM scan_policies WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Policy not found".to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::{PolicyResult, ScanPolicy, Severity};

    // -----------------------------------------------------------------------
    // block_unscanned gate (#1649)
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_unscanned_fires_on_failed_or_in_progress_scan() {
        // #1649 regression: the old `latest_scan.is_none()` check treated ANY
        // scan row (including a crashed `failed` or still-`pending` one) as
        // "scanned", so block_unscanned silently passed an un-vetted artifact
        // whenever block_on_fail happened to be off. The aggregate scan-state
        // classification must instead fire the gate on every non-completed,
        // applicable state.
        assert!(
            block_unscanned_violated(true, ScanState::Failed),
            "a crashed scan must trip block_unscanned"
        );
        assert!(
            block_unscanned_violated(true, ScanState::InProgress),
            "a pending/running scan must trip block_unscanned"
        );
        assert!(
            block_unscanned_violated(true, ScanState::NeverScanned),
            "no scan at all must trip block_unscanned"
        );
    }

    #[test]
    fn test_block_unscanned_passes_completed_and_not_applicable() {
        // A completed scan, or a format to which scanning does not apply, must
        // never be blocked by this gate.
        assert!(!block_unscanned_violated(true, ScanState::Completed));
        assert!(!block_unscanned_violated(true, ScanState::NotApplicable));
    }

    #[test]
    fn test_block_unscanned_disabled_never_fires() {
        for state in [
            ScanState::Failed,
            ScanState::InProgress,
            ScanState::NeverScanned,
            ScanState::Completed,
            ScanState::NotApplicable,
        ] {
            assert!(
                !block_unscanned_violated(false, state),
                "gate disabled -> never a violation regardless of scan state"
            );
        }
    }

    // -----------------------------------------------------------------------
    // post-scan gate inputs (block_on_fail vs max_severity)
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_gate_survives_a_newer_non_completed_scan_row() {
        // Regression: both gates used to read the single newest scan_results row
        // and the severity check ran only `if that_row.status == "completed"`. A
        // scanner that recorded a non-terminal row AFTER a completed one — the
        // normal shape for an asynchronous/external scanner — therefore turned
        // the max_severity download gate off entirely, and an artifact with
        // critical findings on record was served with a 200.
        // No scanner's latest row is a genuine failure, so block_on_fail stays
        // quiet while severity still grades the completed scan's findings.
        let gates = post_scan_gates(false, true, false);
        assert!(
            gates.severity_applies,
            "a newer non-completed row must NOT disable severity blocking while a completed scan exists"
        );
        assert!(
            !gates.block_on_fail_applies,
            "no scanner failed, so block_on_fail must stay quiet"
        );
    }

    #[test]
    fn test_severity_gate_fires_on_findings_without_any_completed_scan() {
        // `scanner_service` persists findings BEFORE flipping the row to
        // `completed`, so a scanner that dies in between (or is reaped from
        // `running` to `failed` by the stuck-scan janitor) leaves
        // unacknowledged findings on record with no completed row anywhere.
        // Keying the gate on `completed` alone reproduces the very fail-open
        // this module is fixing, one layer down: an unacknowledged critical on
        // record, served 200.
        for any_scanner_failed in [false, true] {
            assert!(
                post_scan_gates(any_scanner_failed, false, true).severity_applies,
                "findings on record must be graded even with no completed scan \
                 (any_scanner_failed={any_scanner_failed})"
            );
        }
    }

    #[test]
    fn test_severity_gate_stays_quiet_with_nothing_on_record() {
        // Nothing completed AND nothing on record -> nothing to grade, so the
        // severity gate must not fire. `block_unscanned` is the gate that
        // covers this case.
        for any_scanner_failed in [false, true] {
            assert!(
                !post_scan_gates(any_scanner_failed, false, false).severity_applies,
                "no completed scan and no findings -> severity gate must not fire \
                 (any_scanner_failed={any_scanner_failed})"
            );
        }
    }

    /// #3142: `block_on_fail` keys on whether ANY scanner's latest row failed,
    /// not on a single global newest row.
    ///
    /// This test replaces `test_block_on_fail_keys_on_the_newest_row_only`,
    /// which asserted the defect: it pinned
    /// `!post_scan_gates(Some("completed"), true, false).block_on_fail_applies`
    /// — i.e. "a global newest row of `completed` means block_on_fail must not
    /// fire" — which is exactly the fail-open where a clean scan by engine B
    /// masks engine A's crash. The old test passed both before and after the
    /// bug was introduced, so it could never have caught it.
    ///
    /// The decision now lives in `scan_state::any_scanner_failed`, which is
    /// tested there against the per-`scan_type` row shape; this pins the
    /// remaining wiring in `post_scan_gates`.
    #[test]
    fn test_block_on_fail_fires_when_any_scanner_failed_3142() {
        assert!(
            post_scan_gates(true, false, false).block_on_fail_applies,
            "a failed scanner with no completed scan must trip block_on_fail"
        );

        // A crashed scanner alongside a completed one still trips the gate, and
        // severity ALSO evaluates against the completed scan's findings rather
        // than being skipped. This is the #3142 shape: pre-fix the completed
        // row won the single global newest-row lookup and the gate went quiet.
        let gates = post_scan_gates(true, true, false);
        assert!(
            gates.block_on_fail_applies,
            "a clean scan by another engine must NOT mask a crashed scanner"
        );
        assert!(
            gates.severity_applies,
            "a crashed rescan must not clear an artifact's finding history"
        );

        // Positive control for the inverse: with no failed scanner the gate
        // stays quiet, so the assertions above cannot pass by blocking
        // unconditionally.
        assert!(
            !post_scan_gates(false, true, false).block_on_fail_applies,
            "all scanners healthy -> block_on_fail must not fire"
        );
        assert!(
            !post_scan_gates(false, false, false).block_on_fail_applies,
            "an artifact with no scan rows has nothing to fail"
        );
    }

    // -----------------------------------------------------------------------
    // max_severity normalization (#2320)
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_max_severity_accepts_canonical_values() {
        for value in ALLOWED_MAX_SEVERITIES {
            assert_eq!(
                normalize_max_severity(value).unwrap(),
                value,
                "canonical lowercase value '{value}' must pass through unchanged"
            );
        }
    }

    #[test]
    fn test_normalize_max_severity_canonicalizes_case_and_whitespace() {
        // #2320 regression: "Critical" used to be forwarded verbatim to the
        // INSERT, violate the lowercase CHECK constraint, and surface as a
        // 500 DATABASE_ERROR. It must now normalize cleanly.
        assert_eq!(normalize_max_severity("Critical").unwrap(), "critical");
        assert_eq!(normalize_max_severity("HIGH").unwrap(), "high");
        assert_eq!(normalize_max_severity("  Medium ").unwrap(), "medium");
        assert_eq!(normalize_max_severity("LoW").unwrap(), "low");
    }

    #[test]
    fn test_normalize_max_severity_rejects_unknown_values() {
        // Unknown values must be a Validation error (400), never reach the DB.
        for bad in ["severe", "none", "", "critical; DROP TABLE", "🔥"] {
            match normalize_max_severity(bad) {
                Err(AppError::Validation(msg)) => {
                    assert!(
                        msg.contains("max_severity"),
                        "validation message should name the offending field, got: {msg}"
                    );
                }
                other => {
                    panic!("expected AppError::Validation for max_severity '{bad}', got: {other:?}")
                }
            }
        }
    }

    #[test]
    fn test_normalize_max_severity_rejects_info() {
        // The Severity enum has an Info variant but the scan_policies CHECK
        // constraint deliberately excludes it — a blocking threshold of
        // "info" would gate on purely informational findings. Keep rejecting
        // it here so the API contract matches the schema.
        assert!(matches!(
            normalize_max_severity("info"),
            Err(AppError::Validation(_))
        ));
    }

    // -----------------------------------------------------------------------
    // repository existence pre-check (#2320)
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_exists_or_not_found_accepts_existing_repository() {
        let repo_id = Uuid::new_v4();
        assert!(
            repository_exists_or_not_found(true, repo_id).is_ok(),
            "an existing repository must pass the pre-check"
        );
    }

    #[test]
    fn test_repository_exists_or_not_found_maps_missing_repo_to_not_found() {
        // #2320 regression: a stale/mistyped repository_id used to fall
        // through to the scan_policies_repository_id_fkey violation on
        // INSERT and surface as an opaque 500. The pre-check must turn it
        // into a NotFound (404) that names the offending id.
        let repo_id = Uuid::new_v4();
        match repository_exists_or_not_found(false, repo_id) {
            Err(AppError::NotFound(msg)) => {
                assert!(
                    msg.contains(&repo_id.to_string()),
                    "NotFound message should name the repository id, got: {msg}"
                );
            }
            other => panic!("expected AppError::NotFound for a missing repository, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // create/update entry-point validation ordering (#2320)
    // -----------------------------------------------------------------------

    /// A pool that never opens a connection (and gives up acquiring almost
    /// immediately). Calling a service method with it proves where the DB
    /// boundary sits: anything that returns `Validation` did so BEFORE any
    /// DB round-trip, and anything that returns `Database` got past
    /// validation and genuinely tried to reach the pool.
    fn disconnected_service() -> PolicyService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("connect_lazy should not fail");
        PolicyService::new(pool)
    }

    #[tokio::test]
    async fn test_create_policy_rejects_invalid_max_severity_before_touching_db() {
        let svc = disconnected_service();
        let err = svc
            .create_policy("p", None, "bogus", false, false, None, None, false)
            .await
            .unwrap_err();
        // Validation (not Database/PoolTimedOut) proves the reject happened
        // before any DB round-trip — the pool cannot serve a connection.
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn test_create_policy_with_valid_severity_proceeds_to_repository_check() {
        let svc = disconnected_service();
        let err = svc
            .create_policy(
                "p",
                Some(Uuid::new_v4()),
                "Critical",
                false,
                false,
                None,
                None,
                false,
            )
            .await
            .unwrap_err();
        // The mis-cased-but-known severity normalizes fine, so create must
        // move on to the repository existence pre-check, whose EXISTS query
        // is the first DB touch — surfacing here as a Database error.
        assert!(matches!(err, AppError::Database(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn test_create_policy_unscoped_valid_input_reaches_insert() {
        let svc = disconnected_service();
        let err = svc
            .create_policy("p", None, "high", true, true, Some(1), Some(30), true)
            .await
            .unwrap_err();
        // No repository scope: nothing to pre-check, so the INSERT itself is
        // the first DB touch.
        assert!(matches!(err, AppError::Database(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn test_update_policy_rejects_invalid_max_severity_before_touching_db() {
        let svc = disconnected_service();
        let err = svc
            .update_policy(
                Uuid::new_v4(),
                None,
                Some("bogus"),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    // -----------------------------------------------------------------------
    // PolicyResult construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_result_allowed() {
        let result = PolicyResult {
            allowed: true,
            violations: vec![],
        };
        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_policy_result_blocked() {
        let result = PolicyResult {
            allowed: false,
            violations: vec![
                "Policy 'strict': artifact has not been scanned".to_string(),
                "Policy 'no-critical': 3 findings at or above critical severity".to_string(),
            ],
        };
        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 2);
    }

    // -----------------------------------------------------------------------
    // #3142: block_on_fail across multiple scan engines (end-to-end vs Postgres)
    // -----------------------------------------------------------------------

    /// Seed a `scan_results` row. Mirrors the production writers: both
    /// `complete_scan` and `fail_scan` stamp `completed_at`, while
    /// `pending`/`running` rows leave it NULL.
    #[cfg(test)]
    async fn seed_scan_3142(
        pool: &PgPool,
        artifact_id: Uuid,
        repo_id: Uuid,
        scan_type: &str,
        status: &str,
        age_seconds: i64,
    ) {
        sqlx::query(
            r#"
            INSERT INTO scan_results (
                id, artifact_id, repository_id, scan_type, status,
                findings_count, critical_count, high_count, medium_count, low_count, info_count,
                completed_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 0, 0, 0,
                    CASE WHEN $5 IN ('completed', 'failed', 'not_applicable')
                         THEN NOW() - make_interval(secs => $6::double precision)
                    END,
                    NOW() - make_interval(secs => $6::double precision))
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(artifact_id)
        .bind(repo_id)
        .bind(scan_type)
        .bind(status)
        .bind(age_seconds as f64)
        .execute(pool)
        .await
        .expect("insert scan_result");
    }

    /// End-to-end regression test for the `block_on_fail` fail-open (#3142).
    ///
    /// Drives the real `evaluate_artifact` against Postgres, because the bug
    /// lived in the SQL that feeds the gate, not in the pure helper — the
    /// pre-existing pure tests passed with the defect in place.
    ///
    /// Shape: scanner A (`dependency`) crashes, scanner B (`grype`) then completes
    /// clean. Pre-fix the single `ORDER BY created_at DESC LIMIT 1` across all
    /// scan_types read `completed`, `block_on_fail` never fired, and because
    /// `classify_scan_state` is any-completed-wins `block_unscanned` stayed
    /// quiet too — the artifact was served as fully vetted.
    #[tokio::test]
    async fn test_block_on_fail_spans_all_scanners_3142() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };

        // block_unscanned OFF and max_severity at 'critical' with zero findings
        // anywhere, so block_on_fail is provably the ONLY gate that can block.
        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'critical', false, true, true)",
        )
        .bind(format!("gate-3142-{}", fx.repo_id))
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("insert block_on_fail policy");

        let svc = PolicyService::new(fx.pool.clone());

        // (1) THE BUG: `dependency` crashed, `grype` then completed clean and newer.
        let masked = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/masked/1.0/masked-1.0.jar",
            "com/example/masked/1.0/masked-1.0.jar",
            "masked",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(&fx.pool, masked, fx.repo_id, "dependency", "failed", 3600).await;
        seed_scan_3142(&fx.pool, masked, fx.repo_id, "grype", "completed", 60).await;
        let masked_result = svc.evaluate_artifact(masked, fx.repo_id).await;

        // (2) Positive control that the gate works at all: only a failed row.
        let lone_fail = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/lonefail/1.0/lonefail-1.0.jar",
            "com/example/lonefail/1.0/lonefail-1.0.jar",
            "lonefail",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(
            &fx.pool,
            lone_fail,
            fx.repo_id,
            "dependency",
            "failed",
            3600,
        )
        .await;
        let lone_fail_result = svc.evaluate_artifact(lone_fail, fx.repo_id).await;

        // (3) Negative control — must NOT over-block: both engines clean.
        let clean = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/clean/1.0/clean-1.0.jar",
            "com/example/clean/1.0/clean-1.0.jar",
            "clean",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(&fx.pool, clean, fx.repo_id, "dependency", "completed", 3600).await;
        seed_scan_3142(&fx.pool, clean, fx.repo_id, "grype", "completed", 60).await;
        let clean_result = svc.evaluate_artifact(clean, fx.repo_id).await;

        // (4) Negative control — a genuine RESCAN by the SAME engine that
        // succeeds must still clear the earlier failure. This is what keys the
        // window per scan_type rather than simply "any failed row ever".
        let rescanned = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/rescan/1.0/rescan-1.0.jar",
            "com/example/rescan/1.0/rescan-1.0.jar",
            "rescan",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(
            &fx.pool,
            rescanned,
            fx.repo_id,
            "dependency",
            "failed",
            3600,
        )
        .await;
        seed_scan_3142(
            &fx.pool,
            rescanned,
            fx.repo_id,
            "dependency",
            "completed",
            60,
        )
        .await;
        let rescanned_result = svc.evaluate_artifact(rescanned, fx.repo_id).await;

        // (5) Negative control — a scanner that does not apply to the format is
        // not a crash. Without the `is_not_applicable` exclusion, widening the
        // gate to "any scanner" would block every artifact in every repo where
        // an enabled engine simply does not apply.
        let na = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/na/1.0/na-1.0.jar",
            "com/example/na/1.0/na-1.0.jar",
            "na",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(&fx.pool, na, fx.repo_id, "dependency", "completed", 3600).await;
        seed_scan_3142(&fx.pool, na, fx.repo_id, "openscap", "not_applicable", 60).await;
        let na_result = svc.evaluate_artifact(na, fx.repo_id).await;

        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        let masked_result = masked_result.expect("evaluate masked");
        assert!(
            !masked_result.allowed,
            "#3142: a crashed `dependency` scan masked by a later clean `grype` scan must still \
             trip block_on_fail, got allowed={} violations={:?}",
            masked_result.allowed, masked_result.violations
        );

        let lone_fail_result = lone_fail_result.expect("evaluate lone_fail");
        assert!(
            !lone_fail_result.allowed,
            "positive control: a lone failed scan must trip block_on_fail"
        );

        let clean_result = clean_result.expect("evaluate clean");
        assert!(
            clean_result.allowed,
            "negative control: two clean scans must download, got violations={:?}",
            clean_result.violations
        );

        let rescanned_result = rescanned_result.expect("evaluate rescanned");
        assert!(
            rescanned_result.allowed,
            "negative control: a successful rescan by the SAME engine must clear its earlier \
             failure, got violations={:?}",
            rescanned_result.violations
        );

        let na_result = na_result.expect("evaluate not-applicable");
        assert!(
            na_result.allowed,
            "negative control: a scanner that does not apply to the format is not a crash, \
             got violations={:?}",
            na_result.violations
        );
    }

    #[test]
    fn test_policy_result_serialization() {
        let result = PolicyResult {
            allowed: false,
            violations: vec!["test violation".to_string()],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["allowed"], false);
        assert_eq!(json["violations"][0], "test violation");
    }

    // -----------------------------------------------------------------------
    // ScanPolicy construction and serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_policy_construction() {
        let policy = ScanPolicy {
            id: Uuid::new_v4(),
            name: "no-critical-vulns".to_string(),
            repository_id: None,
            max_severity: "critical".to_string(),
            block_unscanned: true,
            block_on_fail: true,
            is_enabled: true,
            min_staging_hours: Some(24),
            max_artifact_age_days: Some(365),
            require_signature: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(policy.name, "no-critical-vulns");
        assert!(policy.block_unscanned);
        assert!(policy.block_on_fail);
        assert!(policy.is_enabled);
        assert_eq!(policy.min_staging_hours, Some(24));
        assert!(policy.repository_id.is_none()); // global policy
    }

    #[test]
    fn test_scan_policy_repo_specific() {
        let repo_id = Uuid::new_v4();
        let policy = ScanPolicy {
            id: Uuid::new_v4(),
            name: "repo-policy".to_string(),
            repository_id: Some(repo_id),
            max_severity: "high".to_string(),
            block_unscanned: false,
            block_on_fail: false,
            is_enabled: true,
            min_staging_hours: None,
            max_artifact_age_days: None,
            require_signature: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(policy.repository_id, Some(repo_id));
        assert!(policy.require_signature);
    }

    #[test]
    fn test_scan_policy_serialization_roundtrip() {
        let policy = ScanPolicy {
            id: Uuid::nil(),
            name: "test-policy".to_string(),
            repository_id: None,
            max_severity: "medium".to_string(),
            block_unscanned: true,
            block_on_fail: false,
            is_enabled: true,
            min_staging_hours: Some(48),
            max_artifact_age_days: None,
            require_signature: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json_str = serde_json::to_string(&policy).unwrap();
        let deserialized: ScanPolicy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.name, "test-policy");
        assert_eq!(deserialized.max_severity, "medium");
        assert!(deserialized.block_unscanned);
        assert_eq!(deserialized.min_staging_hours, Some(48));
        assert!(deserialized.max_artifact_age_days.is_none());
    }

    // -----------------------------------------------------------------------
    // Violation message formatting logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_violation_message_unscanned() {
        let policy_name = "strict-policy";
        let msg = format!("Policy '{}': artifact has not been scanned", policy_name);
        assert_eq!(msg, "Policy 'strict-policy': artifact has not been scanned");
    }

    #[test]
    fn test_violation_message_scan_failed() {
        let policy_name = "default";
        let msg = format!("Policy '{}': latest scan failed", policy_name);
        assert_eq!(msg, "Policy 'default': latest scan failed");
    }

    #[test]
    fn test_violation_message_severity() {
        let policy_name = "no-high";
        let count = 5;
        let severity = "high";
        let msg = format!(
            "Policy '{}': {} findings at or above {} severity",
            policy_name, count, severity
        );
        assert_eq!(
            msg,
            "Policy 'no-high': 5 findings at or above high severity"
        );
    }

    // -----------------------------------------------------------------------
    // Severity::from_str_loose used in policy evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_from_str_loose_for_policy() {
        // The policy evaluation uses from_str_loose with unwrap_or(Critical)
        let threshold = Severity::from_str_loose("high").unwrap_or(Severity::Critical);
        assert_eq!(threshold, Severity::High);

        let unknown = Severity::from_str_loose("unknown").unwrap_or(Severity::Critical);
        assert_eq!(unknown, Severity::Critical);
    }

    // -----------------------------------------------------------------------
    // Policy allowed = violations.is_empty() logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_result_allowed_when_empty_violations() {
        let violations: Vec<String> = vec![];
        let result = PolicyResult {
            allowed: violations.is_empty(),
            violations,
        };
        assert!(result.allowed);
    }

    #[test]
    fn test_policy_result_blocked_when_nonempty_violations() {
        let violations = vec!["test".to_string()];
        let result = PolicyResult {
            allowed: violations.is_empty(),
            violations,
        };
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // #1374 regression: PUT /security/policies/{id} must atomically persist
    // every field the client provided in the same request. Previously the
    // strict-shape DTO bounced partial bodies as 422, and even when callers
    // resubmitted the whole policy a multi-field change was not guaranteed
    // to round-trip through the update path. This DB-backed test asserts:
    //
    //  - `update_policy(max_severity, is_enabled)` flips BOTH columns,
    //  - a follow-up `get_policy` confirms both values stuck,
    //  - omitted fields (`name`, `block_unscanned`, ...) are NOT clobbered
    //    by the COALESCE branch.
    //
    // Skips silently when `DATABASE_URL` is unset so `cargo test --lib`
    // without a running Postgres still passes; the CI integration job
    // covers this branch.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_update_policy_persists_multiple_fields_1374() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return, // No DB: skip locally; CI integration covers.
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return, // DB not reachable: skip.
        };

        let svc = PolicyService::new(pool.clone());

        // Seed a global policy. Pre-conditions are deliberately the opposite
        // of the values we PUT below so we can assert both columns actually
        // moved (not just "happened to already match").
        let original = svc
            .create_policy(
                &format!("1374-fixture-{}", &Uuid::new_v4().to_string()[..8]),
                None,
                "low", // will become "critical"
                true,  // block_unscanned: untouched, must stay true
                false,
                None,
                None,
                false,
            )
            .await
            .expect("seed policy");
        assert!(original.is_enabled, "policies default to is_enabled=true");
        assert_eq!(original.max_severity, "low");
        let policy_id = original.id;

        // The exact partial-update the release-gate sends: flip max_severity
        // AND is_enabled in one request. Every other field is `None`, so the
        // COALESCE branches keep their existing values.
        let updated = svc
            .update_policy(
                policy_id,
                None,             // name -- untouched
                Some("critical"), // max_severity: low -> critical
                None,             // block_unscanned -- untouched
                None,
                Some(false), // is_enabled: true -> false (the bug)
                None,
                None,
                None,
            )
            .await
            .expect("partial update must succeed");

        // BOTH fields must have moved in the same UPDATE statement.
        assert_eq!(updated.max_severity, "critical");
        assert!(!updated.is_enabled, "is_enabled must persist false (#1374)");
        // Untouched fields must NOT have been silently reset by the COALESCE.
        assert_eq!(updated.name, original.name);
        assert!(updated.block_unscanned, "block_unscanned must stay true");
        assert!(!updated.block_on_fail);
        assert!(!updated.require_signature);

        // GET-after-PUT: re-read from the DB to prove durability, not just
        // that the RETURNING clause echoed our bind values.
        let after = svc.get_policy(policy_id).await.expect("re-read policy");
        assert_eq!(after.max_severity, "critical");
        assert!(!after.is_enabled, "GET-after-PUT must see is_enabled=false");
        assert!(after.block_unscanned, "GET-after-PUT untouched cols intact");

        // Cleanup so reruns against a long-lived test DB don't accumulate.
        let _ = svc.delete_policy(policy_id).await;
    }

    #[tokio::test]
    async fn test_update_policy_empty_patch_is_a_noop_1374() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let svc = PolicyService::new(pool.clone());

        let original = svc
            .create_policy(
                &format!("1374-noop-{}", &Uuid::new_v4().to_string()[..8]),
                None,
                "medium",
                true,
                true,
                Some(24),
                Some(30),
                true,
            )
            .await
            .expect("seed policy");

        // Empty PATCH: every argument is None, the SET clauses become
        // `col = COALESCE(NULL, col)` which is a no-op for every column
        // except `updated_at = NOW()`.
        let after = svc
            .update_policy(original.id, None, None, None, None, None, None, None, None)
            .await
            .expect("empty patch must succeed, not 422");

        assert_eq!(after.name, original.name);
        assert_eq!(after.max_severity, original.max_severity);
        assert_eq!(after.block_unscanned, original.block_unscanned);
        assert_eq!(after.block_on_fail, original.block_on_fail);
        assert_eq!(after.is_enabled, original.is_enabled);
        assert_eq!(after.min_staging_hours, original.min_staging_hours);
        assert_eq!(after.max_artifact_age_days, original.max_artifact_age_days);
        assert_eq!(after.require_signature, original.require_signature);

        let _ = svc.delete_policy(original.id).await;
    }
}
