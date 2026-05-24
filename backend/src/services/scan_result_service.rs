//! Service for managing scan results and findings.

use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{
    DashboardSummary, Grade, RawFinding, RawPackage, RepoSecurityScore, ScanFinding, ScanResult,
    Severity,
};
use crate::services::audit_service::{AuditAction, AuditEntry, ResourceType};

/// Default cap on rows the stuck-scan janitor reaps in a single tick.
/// Bounds memory for the `UPDATE ... RETURNING` payload and the audit-
/// emission batch so a post-upgrade backlog drains across successive
/// ticks rather than in one large batch. A long-stuck backlog on a
/// normally-healthy install is small; this only matters for pathological
/// cases (deploy after a long outage). Operators with very large backlogs
/// can tune via the `STUCK_SCAN_REAP_LIMIT` env var
/// (see [`crate::config::Config::stuck_scan_reap_limit`]).
pub const STUCK_SCAN_REAP_LIMIT_DEFAULT: i64 = 1000;

/// Clamp bounds for `STUCK_SCAN_REAP_LIMIT`. Lower bound 1 keeps the
/// janitor functional (zero would always reap nothing and silently
/// disable it); upper bound 10_000 caps single-tick memory and audit
/// fan-out so a misconfigured value cannot lock the pool for minutes.
pub const STUCK_SCAN_REAP_LIMIT_MIN: i64 = 1;
pub const STUCK_SCAN_REAP_LIMIT_MAX: i64 = 10_000;

/// Clamp `STUCK_SCAN_REAP_LIMIT` to `[1, 10_000]`. Out-of-range values
/// log a warning and saturate at the nearest bound rather than being
/// rejected, so a typo in operator config does not crash startup.
pub fn clamp_stuck_scan_reap_limit(value: i64) -> i64 {
    if value < STUCK_SCAN_REAP_LIMIT_MIN {
        tracing::warn!(
            value,
            floor = STUCK_SCAN_REAP_LIMIT_MIN,
            "STUCK_SCAN_REAP_LIMIT below floor; clamping to floor"
        );
        STUCK_SCAN_REAP_LIMIT_MIN
    } else if value > STUCK_SCAN_REAP_LIMIT_MAX {
        tracing::warn!(
            value,
            ceiling = STUCK_SCAN_REAP_LIMIT_MAX,
            "STUCK_SCAN_REAP_LIMIT above ceiling; clamping to ceiling"
        );
        STUCK_SCAN_REAP_LIMIT_MAX
    } else {
        value
    }
}

/// System-actor label written to `audit_log.details.actor` for janitor-
/// initiated reap entries. Static so it goes through
/// [`crate::services::audit_service::AuditEntry::system_actor`] rather
/// than the user-input `details(...)` path.
const STUCK_SCAN_AUDIT_ACTOR: &str = "system:stuck_scan_janitor";

/// Postgres advisory-lock key for the stuck-scan janitor (PR #1212 audit,
/// finding H3). The janitor takes `pg_try_advisory_lock(STUCK_SCAN_LOCK_ID)`
/// for the duration of one sweep so only one replica fires per tick;
/// other replicas skip cleanly.
///
/// The integer is chosen from a project-internal block (9000-9099) so it
/// will not collide with application-level advisory locks. Document new
/// scheduler locks in this block. Lock IDs in use:
///
///   * 9001 — stuck-scan janitor (`cleanup_stuck_scans`)
///   * 9002 — lifecycle policy execution
///   * 9003 — storage garbage collection
///   * 9004 — webhook delivery retry sweep
///   * 9005 — chunked-upload session cleanup
///   * 9006 — download-ticket cleanup
///   * 9007 — refresh-token jti cleanup
///   * 9008 — sync policy re-evaluation
///   * 9009 — curation upstream sync
pub const STUCK_SCAN_LOCK_ID: i64 = 9001;

/// Inventory persistence outcome for a scan_result row (#1157, #1188-R1).
///
/// Values mirror the CHECK constraint on `scan_results.inventory_status`
/// (migration 087). Encoding the closed set as an enum at the boundary
/// prevents typos (e.g. `"Partial"` vs `"partial"`) from reaching the DB
/// and surfacing as a generic constraint-violation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryStatus {
    Complete,
    Partial,
    Failed,
}

impl InventoryStatus {
    pub fn as_db_str(self) -> &'static str {
        match self {
            InventoryStatus::Complete => "complete",
            InventoryStatus::Partial => "partial",
            InventoryStatus::Failed => "failed",
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helper functions (no DB, testable in isolation)
// ---------------------------------------------------------------------------

/// Compute a security score from severity counts using the penalty weight model.
///
/// Returns `(score, grade)` where score is clamped to `[0, 100]`.
pub(crate) fn compute_security_score(
    critical: i32,
    high: i32,
    medium: i32,
    low: i32,
) -> (i32, Grade) {
    let penalty = critical * Severity::Critical.penalty_weight()
        + high * Severity::High.penalty_weight()
        + medium * Severity::Medium.penalty_weight()
        + low * Severity::Low.penalty_weight();
    let score = (100 - penalty).clamp(0, 100);
    let grade = Grade::from_score(score);
    (score, grade)
}

/// Convert a `Severity` enum value into the string that gets stored in the DB.
pub(crate) fn severity_to_db_string(severity: Severity) -> String {
    serde_json::to_value(severity)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "info".to_string())
}

/// Extract the six severity-count columns from a `ScanResult` in the order
/// they are bound to the `convert_to_reused` UPDATE statement.
///
/// Pulled out of `convert_to_reused` so the count-projection from the source
/// scan can be unit-tested without a live database. Order is
/// `(findings, critical, high, medium, low, info)` and matches the SQL
/// parameter binding `($2, $3, $4, $5, $6, $7)`.
pub(crate) fn target_counts_from_source(source: &ScanResult) -> (i32, i32, i32, i32, i32, i32) {
    (
        source.findings_count,
        source.critical_count,
        source.high_count,
        source.medium_count,
        source.low_count,
        source.info_count,
    )
}

/// Whether the no-op rollback branch of `convert_to_reused` should fire.
///
/// The UPDATE in `convert_to_reused` is guarded by `WHERE status = 'running'`.
/// When the row is already in a terminal state (or another caller raced
/// ahead), the UPDATE matches zero rows and `fetch_optional` returns `None`.
/// In that case the caller rolls back the (no-op) transaction and returns
/// the current row instead of inserting duplicate findings.
///
/// This helper exists so the branch decision can be unit-tested without a
/// live database; the caller maps the boolean to the actual rollback path.
pub(crate) fn convert_should_noop(updated_row_present: bool) -> bool {
    !updated_row_present
}

/// Dedupe a slice of `RawPackage` by `(name, version)` so a single UNNEST
/// INSERT does not land two rows that collide on the
/// `(scan_result_id, name, COALESCE(version, ''))` unique index (#1158).
///
/// Postgres rejects `ON CONFLICT DO UPDATE` if the same target row is
/// affected twice within one statement (`command cannot affect row a
/// second time`), and the per-row insert path used to paper over this by
/// running each INSERT in its own statement. With a batched UNNEST the
/// dedup has to happen Rust-side. The merge rule mirrors the SQL
/// `DO UPDATE ... COALESCE(scan_packages.col, EXCLUDED.col)`: the first
/// payload wins on every column, except where a later payload supplies a
/// non-null value for a column the first payload left as None. This
/// preserves the "more specific wins" behaviour without inventing an
/// ordering rule.
///
/// Pulled out of `create_packages` so the merge semantics can be
/// unit-tested without a live database.
pub(crate) fn merge_packages_for_batch(packages: &[RawPackage]) -> Vec<RawPackage> {
    use std::collections::HashMap;
    // (name, version_for_dedup) -> index into the output Vec. The
    // dedup key matches the SQL unique index: COALESCE(version, '').
    let mut index: HashMap<(&str, &str), usize> = HashMap::new();
    let mut out: Vec<RawPackage> = Vec::with_capacity(packages.len());
    for pkg in packages {
        let key = (pkg.name.as_str(), pkg.version.as_deref().unwrap_or(""));
        match index.get(&key) {
            Some(&idx) => {
                let existing = &mut out[idx];
                // COALESCE first non-null wins on each optional column.
                if existing.purl.is_none() {
                    existing.purl = pkg.purl.clone();
                }
                if existing.license.is_none() {
                    existing.license = pkg.license.clone();
                }
                if existing.source_target.is_none() {
                    existing.source_target = pkg.source_target.clone();
                }
            }
            None => {
                index.insert(key, out.len());
                out.push(pkg.clone());
            }
        }
    }
    out
}

/// Build a DashboardSummary from raw count values.
pub(crate) fn build_dashboard_summary(
    repos_with_scanning: i64,
    total_scans: i64,
    total_findings: i64,
    critical_findings: i64,
    high_findings: i64,
    repos_grade_a: i64,
    repos_grade_f: i64,
) -> DashboardSummary {
    DashboardSummary {
        repos_with_scanning,
        total_scans,
        total_findings,
        critical_findings,
        high_findings,
        policy_violations_blocked: 0,
        repos_grade_a,
        repos_grade_f,
    }
}

/// Build the `details` JSON payload for a `SCAN_REAPED` audit entry (#1063).
///
/// Pure: takes the reaped row's identifiers and timestamps and returns the
/// `serde_json::Value` ready to attach to an `AuditEntry`. Kept separate
/// from `cleanup_stuck_scans` so the details schema (field names, JSON
/// shape) can be locked down by unit tests without needing a Postgres
/// connection. SIEM rules in production parse these fields, so accidental
/// renames are a silent regression we want a fast guard on.
///
/// The `actor` key is intentionally NOT emitted here (PR #1212 audit,
/// finding H1). `AuditEntry::details` strips user-controlled `actor`
/// values, so the janitor sets the system-actor label via
/// [`AuditEntry::system_actor`] after attaching this payload. Keeping
/// the actor out of the pure builder makes the trust boundary obvious:
/// the actor is set by the call site, not by a value the row carries.
pub(crate) fn build_scan_reaped_audit_details(
    scan_id: Uuid,
    artifact_id: Uuid,
    repository_id: Uuid,
    started_at: impl serde::Serialize,
    reaped_at: impl serde::Serialize,
    threshold_secs: i64,
) -> serde_json::Value {
    serde_json::json!({
        "scan_id": scan_id,
        "artifact_id": artifact_id,
        "repository_id": repository_id,
        "started_at": started_at,
        "reaped_at": reaped_at,
        "threshold_secs": threshold_secs,
        "reason": "stuck_running_janitor",
    })
}

pub struct ScanResultService {
    db: PgPool,
}

impl ScanResultService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // -----------------------------------------------------------------------
    // Stuck-scan janitor (#1015, #1061, #1063)
    // -----------------------------------------------------------------------

    /// Reap scan_results rows wedged in `status='running'` past the supplied
    /// threshold. Pre-allocated rows can get stuck if the scan worker crashes
    /// (OOM, pod evicted, panic, deploy mid-scan) before reaching its terminal
    /// UPDATE; those rows then accumulate forever and pollute dashboards
    /// (issue #1015).
    ///
    /// Transitions matching rows to `status='failed'`, sets `completed_at` to
    /// now, and writes a diagnostic `error_message`. Rows already in a terminal
    /// state (`completed`, `failed`) are not touched, so this is safe to run
    /// concurrently with an in-flight scan that completes mid-tick.
    ///
    /// Emits one `SCAN_REAPED` audit-log entry per reaped row (#1063) so a
    /// running -> failed transition is visible to operators investigating an
    /// incident. Audit-log writes are best-effort: a failure to record the
    /// event is logged at warn level but does not roll back the reap, since
    /// leaving the row wedged in `running` is the worse outcome. Within the
    /// audit retention window, operators should reconcile audit entries
    /// against `scan_results` rows whose `error_message` begins with
    /// `janitor:`. Together these are the in-DB evidence pair.
    ///
    /// Durability caveats: neither half of the pair is a long-term
    /// compliance store:
    ///   * `audit_log.action='SCAN_REAPED'` entries are deleted by the
    ///     `audit_retention_days` retention sweep (default 90 days, see
    ///     `AuditService::cleanup`).
    ///   * The `scan_results` row itself is `ON DELETE CASCADE` from
    ///     `artifacts` and `repositories`, so deleting a repo destroys
    ///     its reaped-row evidence independently of audit retention.
    ///
    /// For SOC 2 / FedRAMP / ISO 27001 long-term retention requirements,
    /// export `SCAN_REAPED` audit entries to durable SIEM storage.
    ///
    /// Each tick caps reap count at the configured `reap_limit` rows via
    /// `FOR UPDATE SKIP LOCKED` so a deploy-day backlog drains across
    /// successive ticks instead of in one large in-memory batch, and so
    /// concurrent janitor replicas do not block on each other.
    ///
    /// Backwards-compatible wrapper: defaults to [`STUCK_SCAN_REAP_LIMIT_DEFAULT`].
    /// Operators tune via the `STUCK_SCAN_REAP_LIMIT` env var
    /// (see [`crate::config::Config::stuck_scan_reap_limit`]) and the
    /// scheduler calls [`Self::cleanup_stuck_scans_with_limit`] directly.
    pub async fn cleanup_stuck_scans(&self, stuck_threshold: Duration) -> Result<u64> {
        self.cleanup_stuck_scans_with_limit(stuck_threshold, STUCK_SCAN_REAP_LIMIT_DEFAULT)
            .await
    }

    /// Reap-with-limit variant. See [`Self::cleanup_stuck_scans`].
    ///
    /// PR #1212 audit hardening (findings H2, H3, M1):
    ///
    ///   * **Transactional emission (H2)**: the `UPDATE ... RETURNING`
    ///     reap and the audit-log INSERTs run inside a single
    ///     `self.db.begin()` transaction. Previously the standalone UPDATE
    ///     auto-committed before any audit row was written; a SIGKILL or
    ///     OOM between commit and audit insert left reaped rows with no
    ///     audit trail. Now the transaction commits only after every
    ///     audit row is queued, so either both halves of the evidence
    ///     pair land or neither does.
    ///
    ///   * **Leader election (H3)**: takes `pg_try_advisory_lock(STUCK_SCAN_LOCK_ID)`
    ///     for the duration of the sweep. With `replicaCount > 1`, only
    ///     one replica holds the lock per tick; the rest skip and return
    ///     `Ok(0)`. `FOR UPDATE SKIP LOCKED` keeps correctness even
    ///     without the advisory lock, but the lock prevents audit fan-out
    ///     and metric triple-counting.
    ///
    ///   * **Batched audit INSERT (M1)**: a single
    ///     `INSERT ... SELECT ... FROM UNNEST(...)` writes all audit rows
    ///     in one round trip instead of N. At 1000 reaps per tick this
    ///     drops ~1 s of pure RTT to a single statement.
    pub async fn cleanup_stuck_scans_with_limit(
        &self,
        stuck_threshold: Duration,
        reap_limit: i64,
    ) -> Result<u64> {
        // Cap at i64::MAX seconds so the cast is well-defined for any sane
        // threshold; in practice operators configure minutes or hours here.
        let secs = stuck_threshold.as_secs().min(i64::MAX as u64) as i64;
        let error_message = format!(
            "janitor: scan worker did not complete within {}s (stuck in 'running')",
            secs
        );
        let reap_limit = clamp_stuck_scan_reap_limit(reap_limit);

        // Single-replica leader election (PR #1212 audit, H3). Advisory
        // locks are session-scoped; the lock is automatically released
        // when the transaction's connection is returned to the pool
        // (`tx.commit()` / `tx.rollback()` / drop). We take it on the
        // transaction connection so the lifetimes line up without a
        // manual unlock branch.
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let lock_acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(STUCK_SCAN_LOCK_ID)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if !lock_acquired {
            tracing::debug!(
                "stuck-scan janitor: another replica holds the advisory lock (id={}); skipping tick",
                STUCK_SCAN_LOCK_ID
            );
            // Transaction-scoped lock will auto-release on rollback.
            let _ = tx.rollback().await;
            return Ok(0);
        }

        // Reap rows. SQL uses `sqlx::query` (runtime) instead of `sqlx::query!`
        // (macro) so the `.sqlx/` offline cache does not need to be
        // regenerated for this PR. The schema is unchanged; only the
        // bind path differs.
        #[derive(sqlx::FromRow)]
        struct ReapRow {
            id: Uuid,
            artifact_id: Uuid,
            repository_id: Uuid,
            started_at: Option<chrono::DateTime<chrono::Utc>>,
            completed_at: Option<chrono::DateTime<chrono::Utc>>,
        }

        let reaped: Vec<ReapRow> = sqlx::query_as::<_, ReapRow>(
            r#"
            WITH reap AS (
                SELECT id FROM scan_results
                WHERE status = 'running'
                  AND started_at IS NOT NULL
                  AND started_at < NOW() - make_interval(secs => $2::double precision)
                ORDER BY started_at
                LIMIT $3
                FOR UPDATE SKIP LOCKED
            )
            UPDATE scan_results
            SET status = 'failed',
                error_message = $1,
                completed_at = NOW()
            WHERE id IN (SELECT id FROM reap)
            RETURNING id, artifact_id, repository_id, started_at, completed_at
            "#,
        )
        .bind(&error_message)
        .bind(secs as f64)
        .bind(reap_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if reaped.is_empty() {
            tx.commit()
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(0);
        }

        // Build the UNNEST arrays for a single batched audit INSERT
        // (PR #1212 audit, M1). One statement instead of N.
        let mut user_ids: Vec<Option<Uuid>> = Vec::with_capacity(reaped.len());
        let mut actions: Vec<String> = Vec::with_capacity(reaped.len());
        let mut resource_types: Vec<String> = Vec::with_capacity(reaped.len());
        let mut resource_ids: Vec<Option<Uuid>> = Vec::with_capacity(reaped.len());
        let mut details_blobs: Vec<serde_json::Value> = Vec::with_capacity(reaped.len());
        let mut correlation_ids: Vec<Uuid> = Vec::with_capacity(reaped.len());
        for row in &reaped {
            let entry = AuditEntry::new(AuditAction::ScanReaped, ResourceType::ScanResult)
                .resource(row.id)
                .details(build_scan_reaped_audit_details(
                    row.id,
                    row.artifact_id,
                    row.repository_id,
                    row.started_at,
                    row.completed_at,
                    secs,
                ))
                .system_actor(STUCK_SCAN_AUDIT_ACTOR);
            user_ids.push(entry.user_id());
            actions.push(entry.action().as_str().to_string());
            resource_types.push(entry.resource_type().as_str().to_string());
            resource_ids.push(entry.resource_id());
            details_blobs.push(
                entry
                    .details_ref()
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            );
            correlation_ids.push(entry.correlation_id());
        }

        // Per-row audit emission (#1063). A scan transitioning running -> failed
        // without operator action is security-relevant: an in-flight vulnerability
        // scan never completed, so the artifact may have undisclosed CVEs.
        // Operators looking at the audit log to investigate an incident need to
        // see this transition rather than only the prometheus counter.
        //
        // Wrapped in a SAVEPOINT so an audit-INSERT failure (e.g. a CHECK
        // constraint, a transient index error) does not poison the parent
        // transaction. PostgreSQL aborts the whole transaction on the first
        // statement error, after which `COMMIT` silently downgrades to
        // `ROLLBACK` — without the savepoint, a broken audit insert would
        // leave the reaped rows wedged in 'running', defeating the janitor.
        sqlx::query("SAVEPOINT audit_emit")
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let audit_result = sqlx::query(
            r#"
            INSERT INTO audit_log
                (user_id, action, resource_type, resource_id, details,
                 ip_address, correlation_id)
            SELECT * FROM UNNEST(
                $1::uuid[], $2::text[], $3::text[], $4::uuid[],
                $5::jsonb[], $6::text[], $7::uuid[]
            )
            "#,
        )
        .bind(&user_ids)
        .bind(&actions)
        .bind(&resource_types)
        .bind(&resource_ids)
        .bind(&details_blobs)
        // ip_address: per-row Option<String>, all None for system-initiated.
        .bind(vec![None::<String>; reaped.len()])
        .bind(&correlation_ids)
        .execute(&mut *tx)
        .await;

        match audit_result {
            Ok(_) => {
                sqlx::query("RELEASE SAVEPOINT audit_emit")
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
            }
            Err(e) => {
                // Batched insert failed: log loudly so operators see the
                // gap, then unwind the savepoint so the parent transaction
                // is usable again and the reap UPDATE can still commit
                // (leaving rows wedged in 'running' is worse than a missing
                // audit row).
                tracing::warn!(
                    reaped = reaped.len(),
                    error = %e,
                    "stuck-scan janitor: batched audit-log INSERT failed; reap will still commit"
                );
                crate::services::metrics_service::record_cleanup("stuck_scans_audit_failed", 1);
                sqlx::query("ROLLBACK TO SAVEPOINT audit_emit")
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(reaped.len() as u64)
    }

    // -----------------------------------------------------------------------
    // Scan results
    // -----------------------------------------------------------------------

    /// Create a new pending scan result.
    pub async fn create_scan_result(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        scan_type: &str,
    ) -> Result<ScanResult> {
        self.create_scan_result_with_checksum(artifact_id, repository_id, scan_type, None)
            .await
    }

    /// Create a new pending scan result with an optional checksum for dedup.
    pub async fn create_scan_result_with_checksum(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        scan_type: &str,
        checksum_sha256: Option<&str>,
    ) -> Result<ScanResult> {
        let result = sqlx::query_as!(
            ScanResult,
            r#"
            INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, started_at, checksum_sha256)
            VALUES ($1, $2, $3, 'running', NOW(), $4)
            RETURNING id, artifact_id, repository_id, scan_type, status,
                      findings_count, critical_count, high_count, medium_count, low_count, info_count,
                      scanner_version, error_message, started_at, completed_at, created_at,
                      is_reused, source_scan_id
            "#,
            artifact_id,
            repository_id,
            scan_type,
            checksum_sha256,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Find a completed scan result for the same checksum + scan_type within a TTL window.
    /// Returns None if no reusable scan exists.
    pub async fn find_reusable_scan(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        ttl_days: i32,
    ) -> Result<Option<ScanResult>> {
        let result = sqlx::query_as!(
            ScanResult,
            r#"
            SELECT id, artifact_id, repository_id, scan_type, status,
                   findings_count, critical_count, high_count, medium_count, low_count, info_count,
                   scanner_version, error_message, started_at, completed_at, created_at,
                   is_reused, source_scan_id
            FROM scan_results
            WHERE checksum_sha256 = $1
              AND scan_type = $2
              AND status = 'completed'
              AND completed_at > NOW() - ($3 || ' days')::interval
            ORDER BY completed_at DESC
            LIMIT 1
            "#,
            checksum_sha256,
            scan_type,
            ttl_days.to_string(),
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Find an existing completed scan for THIS artifact_id with the given
    /// checksum + scan_type within a TTL window.
    ///
    /// This is the short-circuit path for issue #1373: when a caller triggers
    /// a scan on an artifact that already has a completed scan for the same
    /// bytes, we must return the existing scan id rather than create a new
    /// `running` placeholder row that goes on to run a redundant fresh scan
    /// (or, worse, gets converted into an `is_reused=true` row that points at
    /// the same artifact's own prior scan, leaving two completed rows for the
    /// same artifact+scan_type pair).
    ///
    /// The query is scoped to a single `artifact_id` so it cannot return a
    /// row belonging to a different artifact; cross-artifact dedup is the job
    /// of `find_reusable_scan` and the `copy_scan_results` / `convert_to_reused`
    /// path it feeds. This method only answers "has THIS artifact already been
    /// scanned for these bytes?", which is the question `prepare_artifact_scan`
    /// needs to answer before inserting a placeholder.
    pub async fn find_existing_scan_for_artifact(
        &self,
        artifact_id: Uuid,
        checksum_sha256: &str,
        scan_type: &str,
        ttl_days: i32,
    ) -> Result<Option<ScanResult>> {
        let result = sqlx::query_as!(
            ScanResult,
            r#"
            SELECT id, artifact_id, repository_id, scan_type, status,
                   findings_count, critical_count, high_count, medium_count, low_count, info_count,
                   scanner_version, error_message, started_at, completed_at, created_at,
                   is_reused, source_scan_id
            FROM scan_results
            WHERE artifact_id = $1
              AND checksum_sha256 = $2
              AND scan_type = $3
              AND status = 'completed'
              AND completed_at > NOW() - ($4 || ' days')::interval
            ORDER BY completed_at DESC
            LIMIT 1
            "#,
            artifact_id,
            checksum_sha256,
            scan_type,
            ttl_days.to_string(),
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Copy scan results from a source scan to a new artifact.
    /// Creates a new completed scan_result and duplicates all findings.
    pub async fn copy_scan_results(
        &self,
        source_scan_id: Uuid,
        artifact_id: Uuid,
        repository_id: Uuid,
        scan_type: &str,
        checksum_sha256: &str,
    ) -> Result<ScanResult> {
        // Wrap the SELECT and both INSERTs in a single transaction:
        //
        // - The two INSERTs (scan_results, then scan_findings) must commit
        //   atomically; a failure of the second must roll back the first.
        //   See #1035/#1060.
        // - The source-scan SELECT runs inside the txn with `FOR SHARE` so
        //   a concurrent DELETE on the source row cannot land between the
        //   count read and the INSERT INTO scan_findings ... SELECT, which
        //   would otherwise leave the new row claiming N findings while the
        //   SELECT copied 0 rows. See #1058.
        //
        // Invariant relied upon: scan_findings rows are only ever deleted
        // via the `ON DELETE CASCADE` from scan_results(id) (migration 022).
        // A direct `DELETE FROM scan_findings WHERE scan_result_id = $X`
        // would NOT be blocked by FOR SHARE on the parent row and would
        // re-open this race. Don't add such a path without taking
        // FOR SHARE on the parent here too.
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let source = sqlx::query_as!(
            ScanResult,
            r#"
            SELECT id, artifact_id, repository_id, scan_type, status,
                   findings_count, critical_count, high_count, medium_count, low_count, info_count,
                   scanner_version, error_message, started_at, completed_at, created_at,
                   is_reused, source_scan_id
            FROM scan_results
            WHERE id = $1
            FOR SHARE
            "#,
            source_scan_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Source scan result not found".to_string()))?;

        // Create new scan result marked as reused.
        //
        // Provenance fields propagate from the source scan so the dedup-copy
        // row honors the PR #1006 invariant ("every newly-completed scan has
        // scanner_version set going forward") and so migration 075's
        // `IS NULL` legacy criterion stays accurate. `started_at` and
        // `completed_at` are copied from the source for honest measurement:
        // the reused row reflects when the original scan actually executed,
        // which is more useful than NOW()/NOW() (the latter would suggest
        // an instantaneous scan that never really happened). The dedup
        // event itself is recoverable from `created_at`, which Postgres
        // sets at INSERT time, plus `is_reused` and `source_scan_id`.
        let new_scan = sqlx::query_as!(
            ScanResult,
            r#"
            INSERT INTO scan_results (
                artifact_id, repository_id, scan_type, status, started_at, completed_at,
                findings_count, critical_count, high_count, medium_count, low_count, info_count,
                scanner_version, checksum_sha256, source_scan_id, is_reused
            )
            VALUES ($1, $2, $3, 'completed', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true)
            RETURNING id, artifact_id, repository_id, scan_type, status,
                      findings_count, critical_count, high_count, medium_count, low_count, info_count,
                      scanner_version, error_message, started_at, completed_at, created_at,
                      is_reused, source_scan_id
            "#,
            artifact_id,
            repository_id,
            scan_type,
            source.started_at,
            source.completed_at,
            source.findings_count,
            source.critical_count,
            source.high_count,
            source.medium_count,
            source.low_count,
            source.info_count,
            source.scanner_version,
            checksum_sha256,
            source_scan_id,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Copy all findings from source scan to new scan
        sqlx::query!(
            r#"
            INSERT INTO scan_findings (
                scan_result_id, artifact_id, severity, title, description,
                cve_id, affected_component, affected_version, fixed_version,
                source, source_url
            )
            SELECT $1, $2, severity, title, description,
                   cve_id, affected_component, affected_version, fixed_version,
                   source, source_url
            FROM scan_findings
            WHERE scan_result_id = $3
            "#,
            new_scan.id,
            artifact_id,
            source_scan_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(new_scan)
    }

    /// Convert a pre-allocated `running` scan_result row into a reused row
    /// whose counts and findings are copied from `source_scan_id`.
    ///
    /// Used by the trigger-scan path when scan_result rows are created
    /// synchronously (so their IDs can be returned in the trigger response)
    /// before the dedup decision is made. UPDATEs the target row in place
    /// rather than INSERTing a new one, so the IDs already returned to the
    /// client remain valid.
    ///
    /// Behavior:
    /// - The UPDATE is guarded by `status = 'running'` so a re-run on an
    ///   already-converted row is a no-op (returns the existing row without
    ///   inserting duplicate findings).
    /// - The UPDATE and the findings INSERT run in a single transaction so a
    ///   findings-INSERT failure does not leave the parent row marked
    ///   `is_reused = true` with zero finding rows.
    pub async fn convert_to_reused(
        &self,
        target_scan_id: Uuid,
        source_scan_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<ScanResult> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Pull source counts so we can copy them onto the target. The SELECT
        // runs inside the txn with `FOR SHARE` to close the TOCTOU window
        // (#1058): without the lock, a concurrent DELETE on the source row
        // could land between the count read here and the findings INSERT
        // below, leaving the converted target row claiming N findings while
        // the INSERT ... SELECT copies 0 rows.
        let source = sqlx::query_as!(
            ScanResult,
            r#"
            SELECT id, artifact_id, repository_id, scan_type, status,
                   findings_count, critical_count, high_count, medium_count, low_count, info_count,
                   scanner_version, error_message, started_at, completed_at, created_at,
                   is_reused, source_scan_id
            FROM scan_results
            WHERE id = $1
            FOR SHARE
            "#,
            source_scan_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Source scan result not found".to_string()))?;
        let (findings, critical, high, medium, low, info) = target_counts_from_source(&source);

        // Status guard: only convert a row that is still 'running'. If another
        // caller already converted this row, the UPDATE matches zero rows and
        // we treat it as a no-op (idempotent).
        // #1019: propagate `scanner_version` from the source row alongside the
        // findings counts. Without this, dedup-via-prepare-then-convert rows
        // were left with scanner_version=NULL (the placeholder's value),
        // breaking the #1006 invariant that every completed scan records its
        // scanner version. Mirrors the analogous fix in copy_scan_results.
        let updated = sqlx::query_as!(
            ScanResult,
            r#"
            UPDATE scan_results
            SET status = 'completed',
                completed_at = NOW(),
                findings_count = $2,
                critical_count = $3,
                high_count = $4,
                medium_count = $5,
                low_count = $6,
                info_count = $7,
                is_reused = true,
                source_scan_id = $8,
                scanner_version = $9
            WHERE id = $1 AND status = 'running'
            RETURNING id, artifact_id, repository_id, scan_type, status,
                      findings_count, critical_count, high_count, medium_count, low_count, info_count,
                      scanner_version, error_message, started_at, completed_at, created_at,
                      is_reused, source_scan_id
            "#,
            target_scan_id,
            findings,
            critical,
            high,
            medium,
            low,
            info,
            source_scan_id,
            source.scanner_version,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if convert_should_noop(updated.is_some()) {
            // Already converted (or in a non-running terminal state). Roll
            // back the (no-op) transaction and return the current row
            // without inserting duplicate findings.
            tx.rollback()
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            return self.get_scan(target_scan_id).await;
        }
        // Safe: convert_should_noop returned false, so updated is Some.
        let updated = updated.expect("updated row present after no-op check");

        // Copy findings from the source scan into the target scan id. This
        // runs inside the same transaction so a failure here rolls back the
        // status/counts UPDATE above.
        sqlx::query!(
            r#"
            INSERT INTO scan_findings (
                scan_result_id, artifact_id, severity, title, description,
                cve_id, affected_component, affected_version, fixed_version,
                source, source_url
            )
            SELECT $1, $2, severity, title, description,
                   cve_id, affected_component, affected_version, fixed_version,
                   source, source_url
            FROM scan_findings
            WHERE scan_result_id = $3
            "#,
            target_scan_id,
            artifact_id,
            source_scan_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(updated)
    }

    /// Mark a scan as completed with severity counts and provenance.
    ///
    /// `scanner_version` is the binary version that produced the report
    /// (e.g. `trivy-0.62.1`). `started_at` is the wall-clock timestamp of
    /// when the scanner subprocess was kicked off (captured by the
    /// orchestrator just before invoking `Scanner::scan`). Both fields are
    /// persisted so consumers (E2E tests, operators) can verify a scan
    /// actually ran and reproduce its result against the same scanner
    /// version. See issue #902.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_scan(
        &self,
        scan_id: Uuid,
        findings_count: i32,
        critical: i32,
        high: i32,
        medium: i32,
        low: i32,
        info: i32,
        scanner_version: Option<&str>,
        started_at: chrono::DateTime<chrono::Utc>,
        scan_completeness: &str,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE scan_results
            SET status = 'completed', findings_count = $2,
                critical_count = $3, high_count = $4, medium_count = $5,
                low_count = $6, info_count = $7, completed_at = NOW(),
                scanner_version = COALESCE($8, scanner_version),
                started_at = $9,
                scan_completeness = $10
            WHERE id = $1
            "#,
            scan_id,
            findings_count,
            critical,
            high,
            medium,
            low,
            info,
            scanner_version,
            started_at,
            scan_completeness,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Mark a scan as failed with an error message and (when known) the
    /// scanner binary version + start timestamp. `scanner_version` is
    /// `None` when the scanner crashed before its version could be
    /// captured (e.g. binary missing); `started_at` is always set to when
    /// the orchestrator kicked off the scan attempt.
    pub async fn fail_scan(
        &self,
        scan_id: Uuid,
        error: &str,
        scanner_version: Option<&str>,
        started_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE scan_results
            SET status = 'failed', error_message = $2, completed_at = NOW(),
                scanner_version = COALESCE($3, scanner_version),
                started_at = $4
            WHERE id = $1
            "#,
            scan_id,
            error,
            scanner_version,
            started_at,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get a scan result by ID.
    pub async fn get_scan(&self, scan_id: Uuid) -> Result<ScanResult> {
        sqlx::query_as!(
            ScanResult,
            r#"
            SELECT id, artifact_id, repository_id, scan_type, status,
                   findings_count, critical_count, high_count, medium_count, low_count, info_count,
                   scanner_version, error_message, started_at, completed_at, created_at,
                   is_reused, source_scan_id
            FROM scan_results
            WHERE id = $1
            "#,
            scan_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Scan result not found".to_string()))
    }

    /// List scan results with optional filters.
    pub async fn list_scans(
        &self,
        repository_id: Option<Uuid>,
        artifact_id: Option<Uuid>,
        status: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<ScanResult>, i64)> {
        let results = sqlx::query_as!(
            ScanResult,
            r#"
            SELECT id, artifact_id, repository_id, scan_type, status,
                   findings_count, critical_count, high_count, medium_count, low_count, info_count,
                   scanner_version, error_message, started_at, completed_at, created_at,
                   is_reused, source_scan_id
            FROM scan_results
            WHERE ($1::uuid IS NULL OR repository_id = $1)
              AND ($2::uuid IS NULL OR artifact_id = $2)
              AND ($3::text IS NULL OR status = $3)
            ORDER BY created_at DESC
            LIMIT $4 OFFSET $5
            "#,
            repository_id,
            artifact_id,
            status,
            limit,
            offset,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM scan_results
            WHERE ($1::uuid IS NULL OR repository_id = $1)
              AND ($2::uuid IS NULL OR artifact_id = $2)
              AND ($3::text IS NULL OR status = $3)
            "#,
            repository_id,
            artifact_id,
            status,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((results, total))
    }

    // -----------------------------------------------------------------------
    // Findings
    // -----------------------------------------------------------------------

    /// Batch insert the full package inventory for a completed scan (#903).
    /// Each row is one package the scanner saw, vulnerable or not, so the
    /// SBOM read path can return the complete dep tree.
    ///
    /// Implementation (#1158): a single
    /// `INSERT ... SELECT * FROM UNNEST($1::text[], $2::text[], ...) ...`
    /// statement replaces the per-row loop. One round-trip regardless of
    /// package count (300+ for express-style lockfiles, 1000+ for Java
    /// multi-modules), and the statement is atomic: either all surviving
    /// rows (after ON CONFLICT dedup) commit or none do, which closes the
    /// "partial-write on row N" hole the original per-row implementation
    /// left open.
    ///
    /// Conflict handling: the unique index is
    /// `(scan_result_id, name, COALESCE(version, ''))`. When a scanner
    /// emits the same `(name, version)` twice within a single report (e.g.
    /// Trivy listing a Maven artifact both in its standalone Packages
    /// block AND inline on a vulnerability row, often with one PURL set
    /// and the other empty) the conflict resolution uses
    /// `DO UPDATE ... COALESCE(scan_packages.col, EXCLUDED.col)` so any
    /// newly-supplied `purl`, `license`, or `source_target` value promotes
    /// over a previously-NULL row. `ON CONFLICT DO NOTHING` would lose
    /// whichever value lost the race; this keeps the first non-null value,
    /// the closest thing to "more specific wins" without inventing an
    /// ordering rule.
    pub async fn create_packages(
        &self,
        scan_result_id: Uuid,
        artifact_id: Uuid,
        packages: &[RawPackage],
    ) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        // Postgres rejects ON CONFLICT DO UPDATE that would touch the
        // same row twice in one statement, so dedupe the input before
        // building the UNNEST arrays. See `merge_packages_for_batch`
        // for the COALESCE-first-non-null-wins merge rule.
        let deduped = merge_packages_for_batch(packages);

        // Build parallel arrays for UNNEST. Postgres expects each unnest
        // column as its own array; `name` is NOT NULL but `version`,
        // `purl`, `license`, and `source_target` are nullable. UNNEST over
        // `text[]` propagates NULL elements correctly so Option<String>
        // values pass through unchanged.
        let names: Vec<&str> = deduped.iter().map(|p| p.name.as_str()).collect();
        let versions: Vec<Option<&str>> = deduped.iter().map(|p| p.version.as_deref()).collect();
        let purls: Vec<Option<&str>> = deduped.iter().map(|p| p.purl.as_deref()).collect();
        let licenses: Vec<Option<&str>> = deduped.iter().map(|p| p.license.as_deref()).collect();
        let source_targets: Vec<Option<&str>> =
            deduped.iter().map(|p| p.source_target.as_deref()).collect();

        sqlx::query!(
            r#"
            INSERT INTO scan_packages (scan_result_id, artifact_id, name,
                version, purl, license, source_target)
            SELECT $1, $2, name, version, purl, license, source_target
            FROM UNNEST(
                $3::text[],
                $4::text[],
                $5::text[],
                $6::text[],
                $7::text[]
            ) AS t(name, version, purl, license, source_target)
            ON CONFLICT (scan_result_id, name, COALESCE(version, ''))
                DO UPDATE SET
                    purl = COALESCE(scan_packages.purl, EXCLUDED.purl),
                    license = COALESCE(scan_packages.license, EXCLUDED.license),
                    source_target = COALESCE(scan_packages.source_target,
                                             EXCLUDED.source_target)
            "#,
            scan_result_id,
            artifact_id,
            &names as &[&str],
            &versions as &[Option<&str>],
            &purls as &[Option<&str>],
            &licenses as &[Option<&str>],
            &source_targets as &[Option<&str>],
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Batch insert findings for a completed scan.
    ///
    /// Implementation (#1158): single-statement UNNEST insert, same shape
    /// as `create_packages`. Atomic: row N+1 cannot land while row N
    /// failed, so the `findings_count` written by `complete_scan` and the
    /// actual `scan_findings` row count stay in lockstep.
    pub async fn create_findings(
        &self,
        scan_result_id: Uuid,
        artifact_id: Uuid,
        findings: &[RawFinding],
    ) -> Result<()> {
        if findings.is_empty() {
            return Ok(());
        }

        let severities: Vec<String> = findings
            .iter()
            .map(|f| severity_to_db_string(f.severity))
            .collect();
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        let descriptions: Vec<Option<&str>> =
            findings.iter().map(|f| f.description.as_deref()).collect();
        let cve_ids: Vec<Option<&str>> = findings.iter().map(|f| f.cve_id.as_deref()).collect();
        let affected_components: Vec<Option<&str>> = findings
            .iter()
            .map(|f| f.affected_component.as_deref())
            .collect();
        let affected_versions: Vec<Option<&str>> = findings
            .iter()
            .map(|f| f.affected_version.as_deref())
            .collect();
        let fixed_versions: Vec<Option<&str>> = findings
            .iter()
            .map(|f| f.fixed_version.as_deref())
            .collect();
        let sources: Vec<Option<&str>> = findings.iter().map(|f| f.source.as_deref()).collect();
        let source_urls: Vec<Option<&str>> =
            findings.iter().map(|f| f.source_url.as_deref()).collect();

        sqlx::query!(
            r#"
            INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title,
                description, cve_id, affected_component, affected_version, fixed_version,
                source, source_url)
            SELECT $1, $2, severity, title, description,
                   cve_id, affected_component, affected_version, fixed_version,
                   source, source_url
            FROM UNNEST(
                $3::text[],
                $4::text[],
                $5::text[],
                $6::text[],
                $7::text[],
                $8::text[],
                $9::text[],
                $10::text[],
                $11::text[]
            ) AS t(severity, title, description, cve_id, affected_component,
                   affected_version, fixed_version, source, source_url)
            "#,
            scan_result_id,
            artifact_id,
            &severities as &[String],
            &titles as &[&str],
            &descriptions as &[Option<&str>],
            &cve_ids as &[Option<&str>],
            &affected_components as &[Option<&str>],
            &affected_versions as &[Option<&str>],
            &fixed_versions as &[Option<&str>],
            &sources as &[Option<&str>],
            &source_urls as &[Option<&str>],
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update the `inventory_status` column on a scan_results row (#1157).
    ///
    /// Called by the scanner orchestrator when `create_packages` returns
    /// an error: the scan itself succeeded, the SBOM is degraded, and the
    /// operator-visible state needs to reflect that without rewriting any
    /// of the count fields owned by `complete_scan`. Taking a typed
    /// `InventoryStatus` rather than `&str` rules out typo-class bugs at
    /// the call site; the CHECK constraint on the column remains the
    /// belt-and-suspenders defence against schema drift.
    pub async fn set_inventory_status(
        &self,
        scan_id: Uuid,
        inventory_status: InventoryStatus,
    ) -> Result<()> {
        let status_str = inventory_status.as_db_str();
        let result = sqlx::query!(
            r#"
            UPDATE scan_results
            SET inventory_status = $2
            WHERE id = $1
            "#,
            scan_id,
            status_str,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Surface missing-row writes as an error rather than silent
        // success (#1188-R3): the orchestrator's failure-then-status
        // path depends on this UPDATE landing; a row deleted between
        // create_packages failure and set_inventory_status would
        // otherwise lose the partial state silently.
        if result.rows_affected() != 1 {
            return Err(AppError::NotFound(format!(
                "scan_result {scan_id} not found while setting inventory_status"
            )));
        }

        Ok(())
    }

    /// Find artifact IDs whose latest completed scan predates the
    /// `scan_packages` table creation (migration 085), so an admin caller
    /// can enqueue rescans to populate the inventory (#1155).
    ///
    /// Semantics: an artifact is "missing inventory" when its LATEST
    /// completed scan has no `scan_packages` rows tied to it (#1188-R3).
    /// Earlier versions of this query looked at `scan_packages` across
    /// all scans of the artifact, which incorrectly excluded artifacts
    /// whose old scan had rows but whose most recent rescan failed to
    /// persist packages -- exactly the degraded state the backfill is
    /// for.
    ///
    /// Legitimate empty-inventory scanners (e.g. OpenSCAP) will still
    /// surface here; that is acceptable because rescanning them is a
    /// no-op for the package list and runs cheap.
    ///
    /// The query is bounded by `limit` because operator endpoints are
    /// dispatch-and-return: a 100k-artifact backfill that streams every
    /// row inline would tie up an HTTP worker thread. The handler chunks
    /// the work by re-calling this method until it returns < limit.
    /// Results are ordered by `artifact_id` for stable iteration across
    /// polled calls.
    pub async fn list_artifacts_missing_inventory(&self, limit: i64) -> Result<Vec<Uuid>> {
        let rows = sqlx::query_scalar!(
            r#"
            WITH latest_scan AS (
                SELECT DISTINCT ON (sr.artifact_id)
                    sr.artifact_id, sr.id
                FROM scan_results sr
                JOIN artifacts a ON a.id = sr.artifact_id
                WHERE sr.status = 'completed' AND NOT a.is_deleted
                ORDER BY sr.artifact_id, sr.created_at DESC
            )
            SELECT artifact_id AS "artifact_id!"
            FROM latest_scan ls
            WHERE NOT EXISTS (
                SELECT 1 FROM scan_packages sp WHERE sp.scan_result_id = ls.id
            )
            ORDER BY artifact_id
            LIMIT $1
            "#,
            limit,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows)
    }

    /// Get findings for a scan result with pagination.
    pub async fn list_findings(
        &self,
        scan_result_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<ScanFinding>, i64)> {
        let findings = sqlx::query_as!(
            ScanFinding,
            r#"
            SELECT id, scan_result_id, artifact_id, severity, title, description,
                   cve_id, affected_component, affected_version, fixed_version,
                   source, source_url, is_acknowledged, acknowledged_by,
                   acknowledged_reason, acknowledged_at, created_at
            FROM scan_findings
            WHERE scan_result_id = $1
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    WHEN 'info' THEN 4
                END,
                created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            scan_result_id,
            limit,
            offset,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM scan_findings WHERE scan_result_id = $1"#,
            scan_result_id,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((findings, total))
    }

    /// Acknowledge a finding (accept risk).
    pub async fn acknowledge_finding(
        &self,
        finding_id: Uuid,
        user_id: Uuid,
        reason: &str,
    ) -> Result<ScanFinding> {
        let finding = sqlx::query_as!(
            ScanFinding,
            r#"
            UPDATE scan_findings
            SET is_acknowledged = true, acknowledged_by = $2,
                acknowledged_reason = $3, acknowledged_at = NOW()
            WHERE id = $1
            RETURNING id, scan_result_id, artifact_id, severity, title, description,
                      cve_id, affected_component, affected_version, fixed_version,
                      source, source_url, is_acknowledged, acknowledged_by,
                      acknowledged_reason, acknowledged_at, created_at
            "#,
            finding_id,
            user_id,
            reason,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;

        Ok(finding)
    }

    /// Revoke acknowledgment of a finding.
    pub async fn revoke_acknowledgment(&self, finding_id: Uuid) -> Result<ScanFinding> {
        let finding = sqlx::query_as!(
            ScanFinding,
            r#"
            UPDATE scan_findings
            SET is_acknowledged = false, acknowledged_by = NULL,
                acknowledged_reason = NULL, acknowledged_at = NULL
            WHERE id = $1
            RETURNING id, scan_result_id, artifact_id, severity, title, description,
                      cve_id, affected_component, affected_version, fixed_version,
                      source, source_url, is_acknowledged, acknowledged_by,
                      acknowledged_reason, acknowledged_at, created_at
            "#,
            finding_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;

        Ok(finding)
    }

    // -----------------------------------------------------------------------
    // Security scores
    // -----------------------------------------------------------------------

    /// Recalculate and materialize the security score for a repository.
    pub async fn recalculate_score(&self, repository_id: Uuid) -> Result<RepoSecurityScore> {
        // Wrap the three sequential queries (counts, last_scan_at, upsert)
        // in a single REPEATABLE READ transaction so all three statements
        // observe the same snapshot. The default sqlx transaction is
        // READ COMMITTED, where each statement re-evaluates the snapshot,
        // so a concurrent writer that commits between the first and second
        // SELECT remains visible to the second - the very interleaving
        // #1059 was filed to close. REPEATABLE READ pins the snapshot at
        // the first statement and forces the whole tx to read from there.
        // Same race pattern as #1035 (copy_scan_results); see #1059.
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        // Use runtime sqlx::query (not the compile-checked macro): the
        // statement has no parameters and returns no rows, so we don't
        // need a cached entry under SQLX_OFFLINE.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Count non-acknowledged findings by severity, but only from the
        // LATEST completed scan per (artifact_id, scan_type) within the
        // repository (#962). Without this restriction, rescanning the
        // same artifact N times multiplied the repo's finding counts by
        // N because every scan_results row owns its own set of
        // scan_findings rows. See #1126 for the matching fix applied
        // to get_dashboard_summary; #1127 forward-ports it here.
        //
        // Note: the `legacy_unverified = false` filter present on
        // release/1.1.x is omitted because main lacks that column
        // (migration 075 on main is the unrelated `075_quarantine_period.sql`).
        // Re-add when migration 080 lands.
        let counts = sqlx::query!(
            r#"
            WITH latest_scans AS (
                SELECT DISTINCT ON (sr.artifact_id, sr.scan_type) sr.id
                FROM scan_results sr
                JOIN artifacts a ON a.id = sr.artifact_id
                WHERE a.repository_id = $1
                  AND NOT a.is_deleted
                  AND sr.status = 'completed'
                ORDER BY sr.artifact_id, sr.scan_type,
                         sr.completed_at DESC NULLS LAST, sr.created_at DESC
            )
            SELECT
                COUNT(*) FILTER (WHERE severity = 'critical' AND NOT is_acknowledged) as "critical!",
                COUNT(*) FILTER (WHERE severity = 'high' AND NOT is_acknowledged) as "high!",
                COUNT(*) FILTER (WHERE severity = 'medium' AND NOT is_acknowledged) as "medium!",
                COUNT(*) FILTER (WHERE severity = 'low' AND NOT is_acknowledged) as "low!",
                COUNT(*) FILTER (WHERE is_acknowledged) as "acknowledged!",
                COUNT(*) as "total!"
            FROM scan_findings
            WHERE scan_result_id IN (SELECT id FROM latest_scans)
            "#,
            repository_id,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let critical = counts.critical as i32;
        let high = counts.high as i32;
        let medium = counts.medium as i32;
        let low = counts.low as i32;
        let acknowledged = counts.acknowledged as i32;
        let total = counts.total as i32;

        let (score, grade) = compute_security_score(critical, high, medium, low);

        let last_scan_at = sqlx::query_scalar!(
            r#"
            SELECT MAX(completed_at) as "last_scan_at"
            FROM scan_results
            WHERE repository_id = $1 AND status = 'completed'
            "#,
            repository_id,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let result = sqlx::query_as!(
            RepoSecurityScore,
            r#"
            INSERT INTO repo_security_scores (repository_id, score, grade, total_findings,
                critical_count, high_count, medium_count, low_count,
                acknowledged_count, last_scan_at, calculated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
            ON CONFLICT (repository_id)
            DO UPDATE SET
                score = EXCLUDED.score,
                grade = EXCLUDED.grade,
                total_findings = EXCLUDED.total_findings,
                critical_count = EXCLUDED.critical_count,
                high_count = EXCLUDED.high_count,
                medium_count = EXCLUDED.medium_count,
                low_count = EXCLUDED.low_count,
                acknowledged_count = EXCLUDED.acknowledged_count,
                last_scan_at = EXCLUDED.last_scan_at,
                calculated_at = NOW()
            RETURNING id, repository_id, score, grade, total_findings,
                      critical_count, high_count, medium_count, low_count,
                      acknowledged_count, last_scan_at, calculated_at
            "#,
            repository_id,
            score,
            grade.as_char().to_string(),
            total,
            critical,
            high,
            medium,
            low,
            acknowledged,
            last_scan_at,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Get the current security score for a repository.
    pub async fn get_score(&self, repository_id: Uuid) -> Result<Option<RepoSecurityScore>> {
        let score = sqlx::query_as!(
            RepoSecurityScore,
            r#"
            SELECT id, repository_id, score, grade, total_findings,
                   critical_count, high_count, medium_count, low_count,
                   acknowledged_count, last_scan_at, calculated_at
            FROM repo_security_scores
            WHERE repository_id = $1
            "#,
            repository_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(score)
    }

    /// Get all repository scores for the leaderboard.
    pub async fn get_all_scores(&self) -> Result<Vec<RepoSecurityScore>> {
        let scores = sqlx::query_as!(
            RepoSecurityScore,
            r#"
            SELECT id, repository_id, score, grade, total_findings,
                   critical_count, high_count, medium_count, low_count,
                   acknowledged_count, last_scan_at, calculated_at
            FROM repo_security_scores
            ORDER BY score ASC, critical_count DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(scores)
    }

    /// Get aggregate dashboard summary across all repositories.
    ///
    /// #962: the finding totals are restricted to the LATEST completed scan
    /// per (artifact_id, scan_type) tuple. Without this windowing, scanning
    /// the same Docker image ten times multiplied the dashboard's
    /// vulnerability count tenfold ("150 vulns" instead of the actual 15)
    /// because every scan_results row owns its own `scan_findings`.
    ///
    /// Soft-deleted artifacts are excluded so users do not see deleted-
    /// artifact CVE counts mixed into the live dashboard; this matches the
    /// per-repo score recompute query.
    ///
    /// FILTER aggregates collapse the three finding subqueries into one
    /// scan of the `latest_findings` CTE.
    pub async fn get_dashboard_summary(&self) -> Result<DashboardSummary> {
        let summary = sqlx::query!(
            r#"
            WITH latest_scans AS (
                SELECT DISTINCT ON (sr.artifact_id, sr.scan_type) sr.id
                FROM scan_results sr
                JOIN artifacts a ON a.id = sr.artifact_id
                WHERE sr.status = 'completed'
                  AND NOT a.is_deleted
                ORDER BY sr.artifact_id, sr.scan_type,
                         sr.completed_at DESC NULLS LAST, sr.created_at DESC
            ),
            latest_findings AS (
                SELECT sf.severity, sf.is_acknowledged
                FROM scan_findings sf
                JOIN latest_scans ls ON ls.id = sf.scan_result_id
            )
            SELECT
                (SELECT COUNT(*) FROM scan_configs WHERE scan_enabled = true) as "repos_with_scanning!",
                (SELECT COUNT(*) FROM scan_results) as "total_scans!",
                COUNT(*) FILTER (WHERE NOT is_acknowledged) as "total_findings!",
                COUNT(*) FILTER (
                    WHERE severity = 'critical' AND NOT is_acknowledged
                ) as "critical_findings!",
                COUNT(*) FILTER (
                    WHERE severity = 'high' AND NOT is_acknowledged
                ) as "high_findings!",
                (SELECT COUNT(*) FROM repo_security_scores WHERE grade = 'A') as "repos_grade_a!",
                (SELECT COUNT(*) FROM repo_security_scores WHERE grade = 'F') as "repos_grade_f!"
            FROM latest_findings
            "#,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(build_dashboard_summary(
            summary.repos_with_scanning,
            summary.total_scans,
            summary.total_findings,
            summary.critical_findings,
            summary.high_findings,
            summary.repos_grade_a,
            summary.repos_grade_f,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::{Grade, RawFinding, ScanFinding, ScanResult, Severity};

    // =======================================================================
    // compute_security_score (extracted pure function)
    // =======================================================================

    #[test]
    fn test_compute_security_score_no_findings() {
        let (score, grade) = compute_security_score(0, 0, 0, 0);
        assert_eq!(score, 100);
        assert_eq!(grade, Grade::A);
    }

    #[test]
    fn test_compute_security_score_one_critical() {
        let (score, grade) = compute_security_score(1, 0, 0, 0);
        assert_eq!(score, 75);
        assert_eq!(grade, Grade::B);
    }

    #[test]
    fn test_compute_security_score_mixed() {
        // critical=1 (25) + high=2 (20) + medium=5 (15) + low=10 (10) = 70
        let (score, grade) = compute_security_score(1, 2, 5, 10);
        assert_eq!(score, 30);
        assert_eq!(grade, Grade::D);
    }

    #[test]
    fn test_compute_security_score_overflow_clamped_to_zero() {
        let (score, grade) = compute_security_score(5, 0, 0, 0);
        assert_eq!(score, 0);
        assert_eq!(grade, Grade::F);
    }

    #[test]
    fn test_compute_security_score_grade_a_boundary() {
        // penalty = 10 (1 high) -> score = 90 -> A
        let (score, grade) = compute_security_score(0, 1, 0, 0);
        assert_eq!(score, 90);
        assert_eq!(grade, Grade::A);
    }

    #[test]
    fn test_compute_security_score_grade_b_boundary() {
        // penalty = 11 -> score = 89 -> B (just below A)
        // 1 high (10) + 1 low (1) = 11
        let (score, grade) = compute_security_score(0, 1, 0, 1);
        assert_eq!(score, 89);
        assert_eq!(grade, Grade::B);
    }

    #[test]
    fn test_compute_security_score_only_low() {
        // 50 low findings -> penalty = 50 -> score = 50 -> C
        let (score, grade) = compute_security_score(0, 0, 0, 50);
        assert_eq!(score, 50);
        assert_eq!(grade, Grade::C);
    }

    #[test]
    fn test_compute_security_score_only_medium() {
        // 10 medium findings -> penalty = 30 -> score = 70 -> C (C range is 50..=74)
        let (score, grade) = compute_security_score(0, 0, 10, 0);
        assert_eq!(score, 70);
        assert_eq!(grade, Grade::C);
    }

    #[test]
    fn test_compute_security_score_all_max() {
        // large values -> clamped at 0
        let (score, grade) = compute_security_score(100, 100, 100, 100);
        assert_eq!(score, 0);
        assert_eq!(grade, Grade::F);
    }

    // =======================================================================
    // severity_to_db_string (extracted pure function)
    // =======================================================================

    #[test]
    fn test_severity_to_db_string_critical() {
        assert_eq!(severity_to_db_string(Severity::Critical), "critical");
    }

    #[test]
    fn test_severity_to_db_string_high() {
        assert_eq!(severity_to_db_string(Severity::High), "high");
    }

    #[test]
    fn test_severity_to_db_string_medium() {
        assert_eq!(severity_to_db_string(Severity::Medium), "medium");
    }

    #[test]
    fn test_severity_to_db_string_low() {
        assert_eq!(severity_to_db_string(Severity::Low), "low");
    }

    #[test]
    fn test_severity_to_db_string_info() {
        assert_eq!(severity_to_db_string(Severity::Info), "info");
    }

    // =======================================================================
    // build_dashboard_summary (extracted pure function)
    // =======================================================================

    #[test]
    fn test_build_dashboard_summary_basic() {
        let summary = build_dashboard_summary(5, 100, 250, 3, 15, 3, 1);
        assert_eq!(summary.repos_with_scanning, 5);
        assert_eq!(summary.total_scans, 100);
        assert_eq!(summary.total_findings, 250);
        assert_eq!(summary.critical_findings, 3);
        assert_eq!(summary.high_findings, 15);
        assert_eq!(summary.repos_grade_a, 3);
        assert_eq!(summary.repos_grade_f, 1);
        assert_eq!(summary.policy_violations_blocked, 0);
    }

    #[test]
    fn test_build_dashboard_summary_zeroes() {
        let summary = build_dashboard_summary(0, 0, 0, 0, 0, 0, 0);
        assert_eq!(summary.repos_with_scanning, 0);
        assert_eq!(summary.total_scans, 0);
        assert_eq!(summary.total_findings, 0);
    }

    #[test]
    fn test_build_dashboard_summary_large_values() {
        let summary = build_dashboard_summary(1000, 50000, 100000, 500, 2000, 800, 50);
        assert_eq!(summary.repos_with_scanning, 1000);
        assert_eq!(summary.total_scans, 50000);
        assert_eq!(summary.critical_findings, 500);
    }

    #[test]
    fn test_build_dashboard_summary_serialization() {
        let summary = build_dashboard_summary(10, 500, 1000, 5, 20, 7, 0);
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["repos_with_scanning"], 10);
        assert_eq!(json["total_scans"], 500);
        assert_eq!(json["repos_grade_a"], 7);
        assert_eq!(json["policy_violations_blocked"], 0);
    }

    // =======================================================================
    // ScanResult construction and serialization
    // =======================================================================

    #[test]
    fn test_scan_result_construction() {
        let result = ScanResult {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "dependency".to_string(),
            status: "completed".to_string(),
            findings_count: 10,
            critical_count: 1,
            high_count: 2,
            medium_count: 3,
            low_count: 3,
            info_count: 1,
            scanner_version: Some("trivy-0.50.0".to_string()),
            error_message: None,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            is_reused: false,
            source_scan_id: None,
        };
        assert_eq!(result.scan_type, "dependency");
        assert_eq!(result.status, "completed");
        assert_eq!(result.findings_count, 10);
        assert_eq!(result.critical_count, 1);
        assert!(result.error_message.is_none());
        assert!(!result.is_reused);
        assert!(result.source_scan_id.is_none());
    }

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            scan_type: "image".to_string(),
            status: "running".to_string(),
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            scanner_version: None,
            error_message: None,
            started_at: None,
            completed_at: None,
            created_at: chrono::Utc::now(),
            is_reused: false,
            source_scan_id: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["scan_type"], "image");
        assert_eq!(json["status"], "running");
        assert_eq!(json["findings_count"], 0);
        assert_eq!(json["is_reused"], false);
        assert!(json["source_scan_id"].is_null());
    }

    #[test]
    fn test_scan_result_failed_with_error() {
        let result = ScanResult {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "malware".to_string(),
            status: "failed".to_string(),
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            scanner_version: None,
            error_message: Some("Scanner timed out".to_string()),
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            is_reused: false,
            source_scan_id: None,
        };
        assert_eq!(result.status, "failed");
        assert_eq!(result.error_message.as_deref(), Some("Scanner timed out"));
    }

    #[test]
    fn test_scan_result_reused_marks_source() {
        let source_id = Uuid::new_v4();
        let result = ScanResult {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "trivy".to_string(),
            status: "completed".to_string(),
            findings_count: 5,
            critical_count: 0,
            high_count: 1,
            medium_count: 2,
            low_count: 2,
            info_count: 0,
            scanner_version: None,
            error_message: None,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            is_reused: true,
            source_scan_id: Some(source_id),
        };
        assert!(result.is_reused);
        assert_eq!(result.source_scan_id, Some(source_id));
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["is_reused"], true);
        assert_eq!(json["source_scan_id"], source_id.to_string());
    }

    // =======================================================================
    // Grade char and score boundary tests
    // =======================================================================

    #[test]
    fn test_grade_as_char_to_string() {
        assert_eq!(Grade::A.as_char().to_string(), "A");
        assert_eq!(Grade::B.as_char().to_string(), "B");
        assert_eq!(Grade::C.as_char().to_string(), "C");
        assert_eq!(Grade::D.as_char().to_string(), "D");
        assert_eq!(Grade::F.as_char().to_string(), "F");
    }

    #[test]
    fn test_grade_from_score_boundaries() {
        // A: 90..
        assert_eq!(Grade::from_score(100), Grade::A);
        assert_eq!(Grade::from_score(90), Grade::A);
        // B: 75..=89
        assert_eq!(Grade::from_score(89), Grade::B);
        assert_eq!(Grade::from_score(75), Grade::B);
        // C: 50..=74
        assert_eq!(Grade::from_score(74), Grade::C);
        assert_eq!(Grade::from_score(50), Grade::C);
        // D: 25..=49
        assert_eq!(Grade::from_score(49), Grade::D);
        assert_eq!(Grade::from_score(25), Grade::D);
        // F: ..25
        assert_eq!(Grade::from_score(24), Grade::F);
        assert_eq!(Grade::from_score(0), Grade::F);
    }

    // =======================================================================
    // ScanFinding construction
    // =======================================================================

    #[test]
    fn test_scan_finding_construction() {
        let finding = ScanFinding {
            id: Uuid::new_v4(),
            scan_result_id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            severity: "critical".to_string(),
            title: "SQL Injection".to_string(),
            description: Some("User input not sanitized".to_string()),
            cve_id: Some("CVE-2024-5678".to_string()),
            affected_component: Some("webapp".to_string()),
            affected_version: Some("2.0".to_string()),
            fixed_version: Some("2.1".to_string()),
            source: Some("scanner".to_string()),
            source_url: None,
            is_acknowledged: false,
            acknowledged_by: None,
            acknowledged_reason: None,
            acknowledged_at: None,
            created_at: chrono::Utc::now(),
        };
        assert!(!finding.is_acknowledged);
        assert_eq!(finding.severity, "critical");
    }

    #[test]
    fn test_scan_finding_acknowledged() {
        let user_id = Uuid::new_v4();
        let finding = ScanFinding {
            id: Uuid::new_v4(),
            scan_result_id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            severity: "low".to_string(),
            title: "Deprecated function used".to_string(),
            description: None,
            cve_id: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            source: None,
            source_url: None,
            is_acknowledged: true,
            acknowledged_by: Some(user_id),
            acknowledged_reason: Some("Accepted risk for legacy code".to_string()),
            acknowledged_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
        };
        assert!(finding.is_acknowledged);
        assert_eq!(finding.acknowledged_by, Some(user_id));
    }

    // =======================================================================
    // RawFinding
    // =======================================================================

    #[test]
    fn test_raw_finding_construction() {
        let finding = RawFinding {
            severity: Severity::Critical,
            title: "CVE-2024-1234".to_string(),
            description: Some("Remote code execution".to_string()),
            cve_id: Some("CVE-2024-1234".to_string()),
            affected_component: Some("openssl".to_string()),
            affected_version: Some("1.0.2".to_string()),
            fixed_version: Some("1.0.3".to_string()),
            source: Some("trivy".to_string()),
            source_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2024-1234".to_string()),
        };
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.title, "CVE-2024-1234");
    }

    #[test]
    fn test_raw_finding_minimal() {
        let finding = RawFinding {
            severity: Severity::Info,
            title: "Informational finding".to_string(),
            description: None,
            cve_id: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            source: None,
            source_url: None,
        };
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.description.is_none());
    }

    // =======================================================================
    // target_counts_from_source / convert_should_noop
    //
    // These cover the pure projections lifted out of `convert_to_reused` so
    // the count-binding and no-op decision can be unit-tested without a
    // live database. The DB-roundtrip happy path and idempotency are covered
    // separately in tests/scan_convert_to_reused_tests.rs (#[ignore] +
    // requires Postgres).
    // =======================================================================

    fn fixture_scan(
        findings: i32,
        critical: i32,
        high: i32,
        medium: i32,
        low: i32,
        info: i32,
    ) -> ScanResult {
        ScanResult {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "trivy".to_string(),
            status: "completed".to_string(),
            findings_count: findings,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            scanner_version: None,
            error_message: None,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            is_reused: false,
            source_scan_id: None,
        }
    }

    #[test]
    fn test_target_counts_from_source_zero() {
        let s = fixture_scan(0, 0, 0, 0, 0, 0);
        assert_eq!(target_counts_from_source(&s), (0, 0, 0, 0, 0, 0));
    }

    #[test]
    fn test_target_counts_from_source_mixed() {
        let s = fixture_scan(15, 1, 2, 4, 5, 3);
        assert_eq!(target_counts_from_source(&s), (15, 1, 2, 4, 5, 3));
    }

    #[test]
    fn test_target_counts_from_source_preserves_order() {
        // Ensures the tuple ordering matches the SQL parameter binding
        // ($2..$7 = findings, critical, high, medium, low, info).
        // A swap would break the UPDATE silently.
        let s = fixture_scan(7, 1, 2, 3, 4, 5);
        let (findings, critical, high, medium, low, info) = target_counts_from_source(&s);
        assert_eq!(findings, 7);
        assert_eq!(critical, 1);
        assert_eq!(high, 2);
        assert_eq!(medium, 3);
        assert_eq!(low, 4);
        assert_eq!(info, 5);
    }

    #[test]
    fn test_target_counts_from_source_only_critical() {
        let s = fixture_scan(3, 3, 0, 0, 0, 0);
        let (findings, critical, high, medium, low, info) = target_counts_from_source(&s);
        assert_eq!(findings, 3);
        assert_eq!(critical, 3);
        assert_eq!(high, 0);
        assert_eq!(medium, 0);
        assert_eq!(low, 0);
        assert_eq!(info, 0);
    }

    #[test]
    fn test_target_counts_from_source_ignores_other_fields() {
        // Even with is_reused=true on the source (unusual but possible if the
        // dedup chain is two hops), we still copy the count fields.
        let mut s = fixture_scan(4, 0, 1, 1, 1, 1);
        s.is_reused = true;
        s.source_scan_id = Some(Uuid::new_v4());
        s.error_message = Some("ignored".into());
        assert_eq!(target_counts_from_source(&s), (4, 0, 1, 1, 1, 1));
    }

    // =======================================================================
    // merge_packages_for_batch (#1158)
    //
    // Pure dedup helper that prevents the UNNEST INSERT from violating the
    // Postgres "ON CONFLICT cannot affect a row twice" rule. The merge rule
    // mirrors the SQL `DO UPDATE ... COALESCE(scan_packages.col, EXCLUDED.col)`.
    // =======================================================================

    #[test]
    fn test_merge_packages_empty_input_returns_empty() {
        let out = merge_packages_for_batch(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn test_merge_packages_no_duplicates_preserves_order() {
        let pkgs = vec![
            RawPackage {
                name: "a".into(),
                version: Some("1".into()),
                purl: None,
                license: None,
                source_target: None,
            },
            RawPackage {
                name: "b".into(),
                version: Some("2".into()),
                purl: None,
                license: None,
                source_target: None,
            },
        ];
        let out = merge_packages_for_batch(&pkgs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "a");
        assert_eq!(out[1].name, "b");
    }

    #[test]
    fn test_merge_packages_dedupes_by_name_and_version() {
        let pkgs = vec![
            RawPackage {
                name: "express".into(),
                version: Some("4.18.2".into()),
                purl: None,
                license: Some("MIT".into()),
                source_target: None,
            },
            RawPackage {
                name: "express".into(),
                version: Some("4.18.2".into()),
                purl: Some("pkg:npm/express@4.18.2".into()),
                license: None,
                source_target: Some("package-lock.json".into()),
            },
        ];
        let out = merge_packages_for_batch(&pkgs);
        assert_eq!(out.len(), 1);
        // First payload supplied license; survives.
        assert_eq!(out[0].license.as_deref(), Some("MIT"));
        // First payload had None for purl/source_target; second payload
        // promotes those values via COALESCE-on-merge.
        assert_eq!(out[0].purl.as_deref(), Some("pkg:npm/express@4.18.2"));
        assert_eq!(out[0].source_target.as_deref(), Some("package-lock.json"));
    }

    #[test]
    fn test_merge_packages_null_version_dedupes_against_empty_string() {
        // SQL unique index is on COALESCE(version, ''). The Rust helper
        // must match: two rows with version=None collapse, just as two
        // rows with version=Some("") would have under the SQL constraint.
        let pkgs = vec![
            RawPackage {
                name: "noversion".into(),
                version: None,
                purl: None,
                license: Some("BSD".into()),
                source_target: None,
            },
            RawPackage {
                name: "noversion".into(),
                version: None,
                purl: Some("pkg:generic/noversion".into()),
                license: None,
                source_target: None,
            },
        ];
        let out = merge_packages_for_batch(&pkgs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].license.as_deref(), Some("BSD"));
        assert_eq!(out[0].purl.as_deref(), Some("pkg:generic/noversion"));
    }

    #[test]
    fn test_merge_packages_first_non_null_wins_on_every_column() {
        // Three duplicate payloads, each supplying a different optional
        // column. Final merged row carries the first non-null seen for
        // every column.
        let pkgs = vec![
            RawPackage {
                name: "p".into(),
                version: Some("1".into()),
                purl: Some("first-purl".into()),
                license: None,
                source_target: None,
            },
            RawPackage {
                name: "p".into(),
                version: Some("1".into()),
                purl: Some("second-purl".into()),
                license: Some("first-license".into()),
                source_target: None,
            },
            RawPackage {
                name: "p".into(),
                version: Some("1".into()),
                purl: None,
                license: Some("second-license".into()),
                source_target: Some("first-source".into()),
            },
        ];
        let out = merge_packages_for_batch(&pkgs);
        assert_eq!(out.len(), 1);
        // First non-null per column from the input order.
        assert_eq!(out[0].purl.as_deref(), Some("first-purl"));
        assert_eq!(out[0].license.as_deref(), Some("first-license"));
        assert_eq!(out[0].source_target.as_deref(), Some("first-source"));
    }

    #[test]
    fn test_merge_packages_different_versions_kept_separate() {
        let pkgs = vec![
            RawPackage {
                name: "p".into(),
                version: Some("1".into()),
                purl: None,
                license: None,
                source_target: None,
            },
            RawPackage {
                name: "p".into(),
                version: Some("2".into()),
                purl: None,
                license: None,
                source_target: None,
            },
        ];
        let out = merge_packages_for_batch(&pkgs);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn test_convert_should_noop_returns_true_when_update_missed() {
        // updated.is_some() == false means the WHERE status='running' guard
        // matched zero rows: another caller already converted this row.
        assert!(convert_should_noop(false));
    }

    #[test]
    fn test_convert_should_noop_returns_false_when_update_matched() {
        // updated.is_some() == true means the row was in 'running' state and
        // the UPDATE fired; the caller proceeds with the findings INSERT.
        assert!(!convert_should_noop(true));
    }

    // =======================================================================
    // build_scan_reaped_audit_details (extracted pure function, #1063)
    //
    // SIEM rules in production parse the `details` JSON shape, so accidental
    // field renames are a silent regression. These tests lock the schema.
    // =======================================================================

    fn sample_reaped_details(threshold_secs: i64) -> (Uuid, Uuid, Uuid, serde_json::Value) {
        let scan_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let started_at = chrono::Utc::now() - chrono::Duration::minutes(45);
        let reaped_at = chrono::Utc::now();
        let details = build_scan_reaped_audit_details(
            scan_id,
            artifact_id,
            repository_id,
            Some(started_at),
            Some(reaped_at),
            threshold_secs,
        );
        (scan_id, artifact_id, repository_id, details)
    }

    #[test]
    fn test_build_scan_reaped_audit_details_carries_row_ids() {
        let (scan_id, artifact_id, repository_id, details) = sample_reaped_details(1800);
        assert_eq!(
            details["scan_id"].as_str(),
            Some(scan_id.to_string().as_str()),
            "scan_id must round-trip so operators can join back to scan_results"
        );
        assert_eq!(
            details["artifact_id"].as_str(),
            Some(artifact_id.to_string().as_str())
        );
        assert_eq!(
            details["repository_id"].as_str(),
            Some(repository_id.to_string().as_str())
        );
    }

    #[test]
    fn test_build_scan_reaped_audit_details_carries_timestamps() {
        let (_, _, _, details) = sample_reaped_details(1800);
        assert!(
            details.get("started_at").is_some() && !details["started_at"].is_null(),
            "details.started_at must be populated when the row had a started_at"
        );
        assert!(
            details.get("reaped_at").is_some() && !details["reaped_at"].is_null(),
            "details.reaped_at must be populated"
        );
        assert_eq!(details["threshold_secs"], 1800);
    }

    #[test]
    fn test_build_scan_reaped_audit_details_marks_reason() {
        // SIEM/SOAR rules distinguish janitor-initiated reaps from human-
        // initiated state changes by `details.reason`. The `actor` key is
        // no longer embedded by the pure builder (PR #1212 audit H1); it
        // is stamped on by `AuditEntry::system_actor` in the call site so
        // that user-input-controlled `details.actor` values are stripped
        // by `AuditEntry::details` instead of trusted.
        let (_, _, _, details) = sample_reaped_details(900);
        assert_eq!(details["reason"], "stuck_running_janitor");
        assert!(
            details.get("actor").is_none(),
            "actor must not be embedded by the pure builder; system_actor() owns it"
        );
    }

    #[test]
    fn test_build_scan_reaped_audit_details_null_timestamps_serialize() {
        // sqlx returns started_at / completed_at as Option<DateTime>; an
        // Option::None must serialize as JSON null rather than panic, so a
        // race where completed_at hasn't been set is recorded honestly.
        let details = build_scan_reaped_audit_details(
            Uuid::nil(),
            Uuid::nil(),
            Uuid::nil(),
            None::<chrono::DateTime<chrono::Utc>>,
            None::<chrono::DateTime<chrono::Utc>>,
            3600,
        );
        assert!(details["started_at"].is_null());
        assert!(details["reaped_at"].is_null());
        assert_eq!(details["threshold_secs"], 3600);
    }

    #[test]
    fn test_build_scan_reaped_audit_details_carries_threshold_value() {
        // threshold_secs roundtrips so an audit reader can correlate the
        // reaped row's started_at-vs-reaped_at gap against the threshold
        // that was in effect at the time of the reap.
        let details = build_scan_reaped_audit_details(
            Uuid::nil(),
            Uuid::nil(),
            Uuid::nil(),
            Some(chrono::Utc::now()),
            Some(chrono::Utc::now()),
            i64::MAX,
        );
        assert_eq!(details["threshold_secs"], i64::MAX);
    }

    #[test]
    fn test_build_scan_reaped_audit_details_has_exactly_expected_fields() {
        // Future field additions are fine, but they must come with explicit
        // test updates rather than slipping in unnoticed. Operators relying
        // on the audit schema (or downstream SIEM/SOAR rules that parse it)
        // need a single source of truth for the allowed shape.
        let (_, _, _, details) = sample_reaped_details(120);
        let obj = details.as_object().expect("details must be a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "artifact_id",
                "reaped_at",
                "reason",
                "repository_id",
                "scan_id",
                "started_at",
                "threshold_secs",
            ],
            "schema lock: future additions need an explicit test update; \
             `actor` lives on the AuditEntry (via system_actor), not in this payload"
        );
    }

    // =======================================================================
    // clamp_stuck_scan_reap_limit (#1212 audit M1 follow-up)
    //
    // Operators tune via `STUCK_SCAN_REAP_LIMIT`. Out-of-range values must
    // saturate at [1, 10_000] rather than disable the janitor (0) or run
    // unbounded (negative or huge positive).
    // =======================================================================

    #[test]
    fn test_clamp_stuck_scan_reap_limit_default_passes_through() {
        assert_eq!(
            clamp_stuck_scan_reap_limit(STUCK_SCAN_REAP_LIMIT_DEFAULT),
            STUCK_SCAN_REAP_LIMIT_DEFAULT
        );
    }

    #[test]
    fn test_clamp_stuck_scan_reap_limit_below_floor_saturates() {
        assert_eq!(clamp_stuck_scan_reap_limit(0), STUCK_SCAN_REAP_LIMIT_MIN);
        assert_eq!(
            clamp_stuck_scan_reap_limit(-1_000),
            STUCK_SCAN_REAP_LIMIT_MIN
        );
        assert_eq!(
            clamp_stuck_scan_reap_limit(i64::MIN),
            STUCK_SCAN_REAP_LIMIT_MIN
        );
    }

    #[test]
    fn test_clamp_stuck_scan_reap_limit_above_ceiling_saturates() {
        assert_eq!(
            clamp_stuck_scan_reap_limit(50_000),
            STUCK_SCAN_REAP_LIMIT_MAX
        );
        assert_eq!(
            clamp_stuck_scan_reap_limit(i64::MAX),
            STUCK_SCAN_REAP_LIMIT_MAX
        );
    }

    #[test]
    fn test_clamp_stuck_scan_reap_limit_boundary_values() {
        assert_eq!(
            clamp_stuck_scan_reap_limit(STUCK_SCAN_REAP_LIMIT_MIN),
            STUCK_SCAN_REAP_LIMIT_MIN
        );
        assert_eq!(
            clamp_stuck_scan_reap_limit(STUCK_SCAN_REAP_LIMIT_MAX),
            STUCK_SCAN_REAP_LIMIT_MAX
        );
    }

    // =======================================================================
    // cleanup_stuck_scans (#1015) — janitor entry point exercises function
    // body and the i64::MAX clamp on the seconds cast. Uses an unreachable
    // PgPool: pool exists but every SQL execute returns a connection error
    // which is mapped to AppError::Database. Gives lib-level coverage of
    // cast/clamp/format/sqlx::query!/map_err lines without standing up
    // Postgres in CI.
    // =======================================================================

    fn unreachable_pool() -> PgPool {
        PgPool::connect_lazy("postgres://fake:fake@127.0.0.1:1/none")
            .expect("connect_lazy never fails for a syntactically valid URL")
    }

    #[tokio::test]
    async fn test_cleanup_stuck_scans_returns_database_error_on_connection_failure() {
        let service = ScanResultService::new(unreachable_pool());
        let result = service.cleanup_stuck_scans(Duration::from_secs(1800)).await;
        assert!(matches!(result, Err(AppError::Database(_))));
    }

    #[tokio::test]
    async fn test_cleanup_stuck_scans_handles_zero_threshold() {
        let service = ScanResultService::new(unreachable_pool());
        let result = service.cleanup_stuck_scans(Duration::from_secs(0)).await;
        // Without a real database the SQL execute fails; what matters here is
        // that the zero-threshold path successfully constructs the query
        // (no panic in the cast/format) before hitting the connection error.
        assert!(matches!(result, Err(AppError::Database(_))));
    }

    #[tokio::test]
    async fn test_cleanup_stuck_scans_clamps_overflow_threshold() {
        // Duration::MAX would overflow an i64-seconds cast without the
        // explicit `.min(i64::MAX as u64)` clamp; this test exercises that
        // saturating branch.
        let service = ScanResultService::new(unreachable_pool());
        let result = service.cleanup_stuck_scans(Duration::MAX).await;
        assert!(matches!(result, Err(AppError::Database(_))));
    }

    // =======================================================================
    // DB-backed tests for the transaction-wrapping fixes in #1058 / #1059.
    //
    // These opt into a real Postgres via test_db_helpers::try_pool(): when
    // DATABASE_URL is unset they no-op so `cargo test --lib` stays usable
    // without a database. The coverage CI job provisions Postgres and runs
    // migrations, so these tests execute there and the new transaction
    // lines (`tx.begin`, `&mut *tx`, `tx.commit`) are exercised.
    // =======================================================================

    mod db {
        use super::*;
        use crate::api::handlers::test_db_helpers as db_helpers;
        use sqlx::PgPool;

        /// Serializes the `cleanup_stuck_scans_*` tests against each other.
        /// All four touch `pg_try_advisory_xact_lock(STUCK_SCAN_LOCK_ID)`,
        /// and `cleanup_stuck_scans_skips_when_advisory_lock_held` holds the
        /// lock for the duration of its assertions. Under `cargo llvm-cov`
        /// the instrumented binary is slow enough that parallel tests
        /// invoking the janitor see the held lock and silently return 0,
        /// breaking their reap-count assertions. The mutex below forces the
        /// four tests to run sequentially so only one of them interacts
        /// with the advisory lock at a time. Other unrelated tests in the
        /// suite are unaffected.
        static CLEANUP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        async fn insert_test_repo(pool: &PgPool) -> Uuid {
            let id = Uuid::new_v4();
            let key = format!("scan-svc-{}", id.as_simple());
            let storage_path = format!("/tmp/test-artifacts/{}", id);
            sqlx::query(
                "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
                 VALUES ($1, $2, $2, $3, 'local', 'generic')",
            )
            .bind(id)
            .bind(&key)
            .bind(&storage_path)
            .execute(pool)
            .await
            .expect("insert repo");
            id
        }

        async fn insert_test_artifact(
            pool: &PgPool,
            repo_id: Uuid,
            suffix: &str,
        ) -> (Uuid, String) {
            let id = Uuid::new_v4();
            let path = format!("{}/{}/pkg.tar.gz", id.as_simple(), suffix);
            let checksum = format!("{:0>56}{:0>8}", id.as_simple(), suffix)
                .chars()
                .take(64)
                .collect::<String>();
            sqlx::query(
                "INSERT INTO artifacts (id, repository_id, name, path, size_bytes, \
                    checksum_sha256, content_type, storage_key, is_deleted) \
                 VALUES ($1, $2, 'pkg.tar.gz', $3, 1024, $4, \
                    'application/octet-stream', $3, false)",
            )
            .bind(id)
            .bind(repo_id)
            .bind(&path)
            .bind(&checksum)
            .execute(pool)
            .await
            .expect("insert artifact");
            (id, checksum)
        }

        async fn cleanup_repo(pool: &PgPool, repo_id: Uuid) {
            // Order matters because of FK constraints. scan_findings ->
            // scan_results -> artifacts -> repositories, plus the
            // repo_security_scores side-table.
            let _ = sqlx::query(
                "DELETE FROM scan_findings WHERE scan_result_id IN \
                 (SELECT id FROM scan_results WHERE repository_id = $1)",
            )
            .bind(repo_id)
            .execute(pool)
            .await;
            let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_security_scores WHERE repository_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
        }

        /// Build a completed source scan with one High finding.
        async fn seed_completed_source_scan(
            svc: &ScanResultService,
            artifact_id: Uuid,
            repo_id: Uuid,
        ) -> Uuid {
            let scan = svc
                .create_scan_result(artifact_id, repo_id, "dependency")
                .await
                .expect("create source scan");
            svc.create_findings(
                scan.id,
                artifact_id,
                &[RawFinding {
                    severity: Severity::High,
                    title: "CVE-test".to_string(),
                    description: None,
                    cve_id: Some("CVE-2024-0000".to_string()),
                    affected_component: Some("libtest".to_string()),
                    affected_version: Some("1.0.0".to_string()),
                    fixed_version: Some("1.0.1".to_string()),
                    source: Some("test".to_string()),
                    source_url: None,
                }],
            )
            .await
            .expect("create finding");
            svc.complete_scan(
                scan.id,
                1,
                0,
                1,
                0,
                0,
                0,
                Some("test-scanner-1.0"),
                chrono::Utc::now(),
                "complete",
            )
            .await
            .expect("complete source scan");
            scan.id
        }

        /// #1058 coverage: copy_scan_results runs end-to-end inside the
        /// transaction wrap. Exercises tx.begin, the FOR SHARE SELECT on
        /// scan_results, both INSERTs against `&mut *tx`, and tx.commit.
        #[tokio::test]
        async fn copy_scan_results_commits_transaction() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (src_aid, _) = insert_test_artifact(&pool, repo_id, "src").await;
            let (dst_aid, dst_checksum) = insert_test_artifact(&pool, repo_id, "dst").await;
            let src_scan_id = seed_completed_source_scan(&svc, src_aid, repo_id).await;

            let copied = svc
                .copy_scan_results(src_scan_id, dst_aid, repo_id, "dependency", &dst_checksum)
                .await
                .expect("copy_scan_results");

            assert_eq!(copied.artifact_id, dst_aid);
            assert!(copied.is_reused);
            assert_eq!(copied.source_scan_id, Some(src_scan_id));
            assert_eq!(copied.findings_count, 1);

            // Verify the second INSERT actually committed the finding row.
            let findings: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM scan_findings WHERE scan_result_id = $1")
                    .bind(copied.id)
                    .fetch_one(&pool)
                    .await
                    .expect("count findings");
            assert_eq!(findings, 1);

            cleanup_repo(&pool, repo_id).await;
        }

        /// #1058 coverage: convert_to_reused runs end-to-end with the
        /// source-scan SELECT moved inside the transaction. Exercises
        /// tx.begin, the FOR SHARE SELECT, the UPDATE, the findings
        /// INSERT, and tx.commit.
        #[tokio::test]
        async fn convert_to_reused_commits_transaction() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (src_aid, _) = insert_test_artifact(&pool, repo_id, "src").await;
            let (dst_aid, _) = insert_test_artifact(&pool, repo_id, "dst").await;

            let src_scan_id = seed_completed_source_scan(&svc, src_aid, repo_id).await;
            let target = svc
                .create_scan_result(dst_aid, repo_id, "dependency")
                .await
                .expect("create target running scan");

            let converted = svc
                .convert_to_reused(target.id, src_scan_id, dst_aid)
                .await
                .expect("convert_to_reused");

            assert_eq!(converted.id, target.id);
            assert!(converted.is_reused);
            assert_eq!(converted.source_scan_id, Some(src_scan_id));
            assert_eq!(converted.status, "completed");
            assert_eq!(converted.findings_count, 1);

            let findings: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM scan_findings WHERE scan_result_id = $1")
                    .bind(target.id)
                    .fetch_one(&pool)
                    .await
                    .expect("count findings");
            assert_eq!(findings, 1);

            cleanup_repo(&pool, repo_id).await;
        }

        /// #1059 coverage: recalculate_score runs end-to-end inside the
        /// transaction wrap. Exercises tx.begin, the three queries that
        /// each take `&mut *tx`, and tx.commit.
        #[tokio::test]
        async fn recalculate_score_commits_transaction() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;

            // Empty repo (no artifacts, no findings) is a valid input - the
            // counts query returns zeros, last_scan_at is None, and the
            // upsert lands a 100/A score row. That fully traverses the
            // transaction's three queries plus the commit.
            let score = svc
                .recalculate_score(repo_id)
                .await
                .expect("recalculate_score");

            assert_eq!(score.repository_id, repo_id);
            assert_eq!(score.score, 100);
            assert_eq!(score.grade, "A");
            assert_eq!(score.total_findings, 0);
            assert_eq!(score.critical_count, 0);
            assert!(score.last_scan_at.is_none());

            // Calling a second time should hit the ON CONFLICT branch of the
            // upsert and still commit cleanly through the transaction.
            let score2 = svc
                .recalculate_score(repo_id)
                .await
                .expect("recalculate_score idempotent");
            assert_eq!(score2.repository_id, repo_id);
            assert_eq!(score2.id, score.id);
            let repo_id = insert_test_repo(&pool).await;

            // Empty repo (no artifacts, no findings) is a valid input — the
            // counts query returns zeros, last_scan_at is None, and the
            // upsert lands a 100/A score row. That fully traverses the
            // transaction's three queries plus the commit.
            let score = svc
                .recalculate_score(repo_id)
                .await
                .expect("recalculate_score");

            assert_eq!(score.repository_id, repo_id);
            assert_eq!(score.score, 100);
            assert_eq!(score.grade, "A");
            assert_eq!(score.total_findings, 0);
            assert_eq!(score.critical_count, 0);
            assert!(score.last_scan_at.is_none());

            // Calling a second time should hit the ON CONFLICT branch of the
            // upsert and still commit cleanly through the transaction.
            let score2 = svc
                .recalculate_score(repo_id)
                .await
                .expect("recalculate_score idempotent");
            assert_eq!(score2.repository_id, repo_id);
            assert_eq!(score2.id, score.id);

            cleanup_repo(&pool, repo_id).await;
        }

        // ===================================================================
        // #1158: UNNEST batch insert correctness for create_packages and
        // create_findings. Each test seeds a scan, batch-inserts via the
        // new code path, and verifies the row count + dedup behaviour.
        // ===================================================================

        /// Inserting N packages in a single UNNEST call lands N rows.
        #[tokio::test]
        async fn create_packages_batch_inserts_all_rows() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "pkgs").await;
            let scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create scan");

            // 250 packages is enough to be obviously batched, while staying
            // well under any Postgres parameter limits (UNNEST sends each
            // column as a single array param, so we use 5 params total
            // regardless of N).
            let pkgs: Vec<RawPackage> = (0..250)
                .map(|i| RawPackage {
                    name: format!("pkg-{i}"),
                    version: Some(format!("1.0.{i}")),
                    purl: Some(format!("pkg:generic/pkg-{i}@1.0.{i}")),
                    license: Some("MIT".to_string()),
                    source_target: Some("test".to_string()),
                })
                .collect();

            svc.create_packages(scan.id, aid, &pkgs)
                .await
                .expect("batch insert");

            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM scan_packages WHERE scan_result_id = $1")
                    .bind(scan.id)
                    .fetch_one(&pool)
                    .await
                    .expect("count packages");
            assert_eq!(count, 250);

            cleanup_repo(&pool, repo_id).await;
        }

        /// Calling create_packages with an empty slice is a no-op (no query
        /// executed, no error). Guards against UNNEST behaviour on
        /// zero-length arrays, which can otherwise insert a stray row.
        #[tokio::test]
        async fn create_packages_empty_slice_is_noop() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "empty").await;
            let scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create scan");

            svc.create_packages(scan.id, aid, &[])
                .await
                .expect("empty insert");

            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM scan_packages WHERE scan_result_id = $1")
                    .bind(scan.id)
                    .fetch_one(&pool)
                    .await
                    .expect("count packages");
            assert_eq!(count, 0);

            cleanup_repo(&pool, repo_id).await;
        }

        /// ON CONFLICT DO UPDATE on (scan_result_id, name, COALESCE(version, ''))
        /// dedupes duplicates within the same batch. The COALESCE-on-update
        /// branch promotes the previously-NULL purl/license/source_target.
        #[tokio::test]
        async fn create_packages_dedupes_within_batch() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "dedup").await;
            let scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create scan");

            // Three rows, all the same (name, version). Mimics Trivy
            // emitting the same package both in its Packages block and
            // inline on a vulnerability row.
            let pkgs = vec![
                RawPackage {
                    name: "express".into(),
                    version: Some("4.18.2".into()),
                    purl: None,
                    license: Some("MIT".into()),
                    source_target: None,
                },
                RawPackage {
                    name: "express".into(),
                    version: Some("4.18.2".into()),
                    purl: Some("pkg:npm/express@4.18.2".into()),
                    license: None,
                    source_target: Some("package-lock.json".into()),
                },
                RawPackage {
                    name: "express".into(),
                    version: Some("4.18.2".into()),
                    purl: None,
                    license: None,
                    source_target: None,
                },
            ];
            svc.create_packages(scan.id, aid, &pkgs)
                .await
                .expect("dedup insert");

            let row: (i64, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
                "SELECT COUNT(*)::BIGINT, MAX(purl), MAX(license), MAX(source_target) \
                 FROM scan_packages WHERE scan_result_id = $1",
            )
            .bind(scan.id)
            .fetch_one(&pool)
            .await
            .expect("aggregate");
            // Exactly one row landed after dedup; the COALESCE merge
            // surfaces all three fields from whichever payload supplied them.
            assert_eq!(row.0, 1);
            assert_eq!(row.1.as_deref(), Some("pkg:npm/express@4.18.2"));
            assert_eq!(row.2.as_deref(), Some("MIT"));
            assert_eq!(row.3.as_deref(), Some("package-lock.json"));

            cleanup_repo(&pool, repo_id).await;
        }

        /// Empty findings slice is a no-op. Same shape as the package
        /// guard; protects against accidentally inserting a phantom row.
        #[tokio::test]
        async fn create_findings_empty_slice_is_noop() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "no-finds").await;
            let scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create scan");

            svc.create_findings(scan.id, aid, &[])
                .await
                .expect("empty insert");

            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM scan_findings WHERE scan_result_id = $1")
                    .bind(scan.id)
                    .fetch_one(&pool)
                    .await
                    .expect("count findings");
            assert_eq!(count, 0);

            cleanup_repo(&pool, repo_id).await;
        }

        /// 100 findings in one UNNEST call lands 100 rows. Verifies the
        /// batched path doesn't truncate or short-write.
        #[tokio::test]
        async fn create_findings_batch_inserts_all_rows() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "finds").await;
            let scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create scan");

            let findings: Vec<RawFinding> = (0..100)
                .map(|i| RawFinding {
                    severity: Severity::Medium,
                    title: format!("CVE-{i}"),
                    description: Some(format!("desc {i}")),
                    cve_id: Some(format!("CVE-2024-{i:04}")),
                    affected_component: Some(format!("lib-{i}")),
                    affected_version: Some(format!("1.{i}")),
                    fixed_version: Some(format!("2.{i}")),
                    source: Some("trivy".into()),
                    source_url: None,
                })
                .collect();

            svc.create_findings(scan.id, aid, &findings)
                .await
                .expect("batch insert");

            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM scan_findings WHERE scan_result_id = $1")
                    .bind(scan.id)
                    .fetch_one(&pool)
                    .await
                    .expect("count findings");
            assert_eq!(count, 100);

            cleanup_repo(&pool, repo_id).await;
        }

        // ===================================================================
        // #1154: composite FK enforcement.
        // ===================================================================

        /// Attempting to insert a scan_packages row whose artifact_id does
        /// not match the parent scan_results.artifact_id must fail with a
        /// FK violation. This is exactly the drift the composite FK closes.
        #[tokio::test]
        async fn scan_packages_composite_fk_rejects_mismatched_artifact() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (real_aid, _) = insert_test_artifact(&pool, repo_id, "owner").await;
            let (other_aid, _) = insert_test_artifact(&pool, repo_id, "drift").await;
            let scan = svc
                .create_scan_result(real_aid, repo_id, "dependency")
                .await
                .expect("create scan");

            // Direct INSERT bypassing the service so we drive the constraint
            // rather than the application-layer caller. Bound parameters
            // are (scan_result_id, artifact_id) where artifact_id is the
            // *wrong* artifact for this scan.
            let result = sqlx::query(
                "INSERT INTO scan_packages (scan_result_id, artifact_id, name) \
                 VALUES ($1, $2, 'drifted-pkg')",
            )
            .bind(scan.id)
            .bind(other_aid)
            .execute(&pool)
            .await;

            assert!(
                result.is_err(),
                "INSERT with mismatched artifact_id must fail FK check"
            );
            let err = result.unwrap_err().to_string().to_lowercase();
            assert!(
                err.contains("scan_packages_scan_result_artifact_fk")
                    || err.contains("foreign key")
                    || err.contains("violates"),
                "expected FK violation, got: {err}"
            );

            cleanup_repo(&pool, repo_id).await;
        }

        // ===================================================================
        // #1157: inventory_status column + set_inventory_status helper.
        // ===================================================================

        /// New scan rows default to inventory_status = 'complete'; the
        /// service helper flips it to 'partial' and the value persists.
        #[tokio::test]
        async fn set_inventory_status_partial_updates_row() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "inv").await;
            let scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create scan");

            // Default value from migration 087.
            let initial: String =
                sqlx::query_scalar("SELECT inventory_status FROM scan_results WHERE id = $1")
                    .bind(scan.id)
                    .fetch_one(&pool)
                    .await
                    .expect("read inventory_status default");
            assert_eq!(initial, "complete");

            svc.set_inventory_status(scan.id, InventoryStatus::Partial)
                .await
                .expect("set partial");

            let after: String =
                sqlx::query_scalar("SELECT inventory_status FROM scan_results WHERE id = $1")
                    .bind(scan.id)
                    .fetch_one(&pool)
                    .await
                    .expect("read inventory_status after");
            assert_eq!(after, "partial");

            cleanup_repo(&pool, repo_id).await;
        }

        /// The CHECK constraint on inventory_status rejects unknown values
        /// even when the service helper is bypassed (defence in depth for
        /// any code path that writes the column via raw SQL).
        #[tokio::test]
        async fn inventory_status_check_constraint_rejects_unknown_value() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "bad-inv").await;
            let scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create scan");

            // The typed helper rules out the typo case at compile time
            // (see InventoryStatus), so this test goes around it to verify
            // the DB-level CHECK still catches direct writes.
            let result = sqlx::query("UPDATE scan_results SET inventory_status = $2 WHERE id = $1")
                .bind(scan.id)
                .bind("garbage")
                .execute(&pool)
                .await;
            assert!(result.is_err(), "CHECK must reject unknown value");

            cleanup_repo(&pool, repo_id).await;
        }

        // ===================================================================
        // #1155: list_artifacts_missing_inventory.
        // ===================================================================

        /// An artifact with a completed scan but no scan_packages rows is
        /// returned by the backfill query; an artifact with packages is not.
        #[tokio::test]
        async fn list_artifacts_missing_inventory_finds_only_empty_inventory() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (legacy_aid, _) = insert_test_artifact(&pool, repo_id, "legacy").await;
            let (modern_aid, _) = insert_test_artifact(&pool, repo_id, "modern").await;

            // Legacy scan: completed, no packages.
            let legacy_scan = svc
                .create_scan_result(legacy_aid, repo_id, "dependency")
                .await
                .expect("create legacy scan");
            svc.complete_scan(
                legacy_scan.id,
                0,
                0,
                0,
                0,
                0,
                0,
                Some("v1"),
                chrono::Utc::now(),
                "complete",
            )
            .await
            .expect("complete legacy");

            // Modern scan: completed AND has at least one package row.
            let modern_scan = svc
                .create_scan_result(modern_aid, repo_id, "dependency")
                .await
                .expect("create modern scan");
            svc.create_packages(
                modern_scan.id,
                modern_aid,
                &[RawPackage {
                    name: "express".into(),
                    version: Some("4.18.2".into()),
                    purl: None,
                    license: None,
                    source_target: None,
                }],
            )
            .await
            .expect("inventory");
            svc.complete_scan(
                modern_scan.id,
                0,
                0,
                0,
                0,
                0,
                0,
                Some("v1"),
                chrono::Utc::now(),
                "complete",
            )
            .await
            .expect("complete modern");

            let missing = svc
                .list_artifacts_missing_inventory(100)
                .await
                .expect("list missing");

            assert!(
                missing.contains(&legacy_aid),
                "legacy artifact should be in backfill candidates"
            );
            assert!(
                !missing.contains(&modern_aid),
                "modern artifact must not be flagged as missing inventory"
            );

            cleanup_repo(&pool, repo_id).await;
        }

        /// #1188-R3: an artifact whose older scan had packages but whose
        /// most recent rescan did not (e.g. inventory persistence failed)
        /// must still be flagged. The earlier implementation looked at
        /// scan_packages across all scans of the artifact and would
        /// incorrectly exclude this case.
        #[tokio::test]
        async fn list_artifacts_missing_inventory_uses_latest_scan_semantics() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());

            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "regressed").await;

            // Older scan: completed AND has a package row.
            let old_scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create old scan");
            svc.create_packages(
                old_scan.id,
                aid,
                &[RawPackage {
                    name: "lodash".into(),
                    version: Some("4.17.21".into()),
                    purl: None,
                    license: None,
                    source_target: None,
                }],
            )
            .await
            .expect("old inventory");
            svc.complete_scan(
                old_scan.id,
                0,
                0,
                0,
                0,
                0,
                0,
                Some("v1"),
                chrono::Utc::now() - chrono::Duration::days(30),
                "complete",
            )
            .await
            .expect("complete old scan");

            // Newer scan: completed but no scan_packages rows (simulates
            // a degraded post-#1157 rescan that flipped inventory_status
            // to 'partial' without persisting any package rows).
            let new_scan = svc
                .create_scan_result(aid, repo_id, "dependency")
                .await
                .expect("create new scan");
            svc.complete_scan(
                new_scan.id,
                0,
                0,
                0,
                0,
                0,
                0,
                Some("v1"),
                chrono::Utc::now(),
                "complete",
            )
            .await
            .expect("complete new scan");

            let missing = svc
                .list_artifacts_missing_inventory(100)
                .await
                .expect("list missing");

            assert!(
                missing.contains(&aid),
                "artifact with degraded latest scan must be flagged \
                 even though an older scan still has package rows"
            );

            cleanup_repo(&pool, repo_id).await;
        }

        // ===================================================================
        // PR #1212 audit follow-ups (H2, H3, M1, M2).
        //
        // These all need a real Postgres because the behavior under test
        // is the interaction between the reap transaction, the advisory
        // lock, and the batched audit INSERT. They no-op when `DATABASE_URL`
        // is unset, matching the surrounding suite.
        // ===================================================================

        /// Insert a `scan_results` row in `status='running'` whose
        /// `started_at` is `age_secs` seconds in the past. Returns the
        /// scan id so the caller can assert on its post-reap state.
        async fn insert_stuck_running_scan(
            pool: &PgPool,
            artifact_id: Uuid,
            repo_id: Uuid,
            age_secs: i64,
        ) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO scan_results \
                 (id, artifact_id, repository_id, scan_type, status, started_at) \
                 VALUES ($1, $2, $3, 'dependency', 'running', NOW() - make_interval(secs => $4::double precision))",
            )
            .bind(id)
            .bind(artifact_id)
            .bind(repo_id)
            .bind(age_secs as f64)
            .execute(pool)
            .await
            .expect("insert stuck running scan");
            id
        }

        /// H2 coverage: a successful reap commits both the row UPDATE and
        /// the batched audit INSERT in the same transaction.
        #[tokio::test]
        async fn cleanup_stuck_scans_writes_audit_row_in_same_transaction() {
            let _serial = CLEANUP_TEST_LOCK.lock().await;
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());
            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "h2").await;
            let stuck_id = insert_stuck_running_scan(&pool, aid, repo_id, 3600).await;

            let reaped = svc
                .cleanup_stuck_scans(Duration::from_secs(60))
                .await
                .expect("janitor returned Ok");
            assert!(reaped >= 1, "expected at least one reap");

            // Row transitioned to failed.
            let status: String =
                sqlx::query_scalar("SELECT status FROM scan_results WHERE id = $1")
                    .bind(stuck_id)
                    .fetch_one(&pool)
                    .await
                    .expect("read status");
            assert_eq!(status, "failed");

            // Exactly one audit row landed for this scan, and it carries
            // the system-actor label set via `AuditEntry::system_actor`.
            // Postgres has no `max(jsonb)` aggregate, so we query count and
            // details separately rather than collapsing the two.
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM audit_log \
                 WHERE resource_id = $1 AND action = 'SCAN_REAPED'",
            )
            .bind(stuck_id)
            .fetch_one(&pool)
            .await
            .expect("count audit rows");
            assert_eq!(
                count, 1,
                "exactly one SCAN_REAPED audit row per reaped scan"
            );
            let details: serde_json::Value = sqlx::query_scalar(
                "SELECT details FROM audit_log \
                 WHERE resource_id = $1 AND action = 'SCAN_REAPED' LIMIT 1",
            )
            .bind(stuck_id)
            .fetch_one(&pool)
            .await
            .expect("read audit details");
            assert_eq!(
                details.get("actor").and_then(|v| v.as_str()),
                Some(STUCK_SCAN_AUDIT_ACTOR),
                "audit details.actor must be the system-actor label set by system_actor()"
            );
            assert_eq!(
                details.get("reason").and_then(|v| v.as_str()),
                Some("stuck_running_janitor"),
                "audit details.reason must match the pure-builder schema"
            );

            // Cleanup.
            let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
                .bind(stuck_id)
                .execute(&pool)
                .await;
            cleanup_repo(&pool, repo_id).await;
        }

        /// H3 coverage: when another transaction already holds the
        /// `STUCK_SCAN_LOCK_ID` advisory lock, the janitor skips cleanly
        /// (returns Ok(0)) instead of triple-counting on multi-replica
        /// deployments.
        #[tokio::test]
        async fn cleanup_stuck_scans_skips_when_advisory_lock_held() {
            let _serial = CLEANUP_TEST_LOCK.lock().await;
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());
            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "h3").await;
            let stuck_id = insert_stuck_running_scan(&pool, aid, repo_id, 3600).await;

            // Hold the advisory lock in a separate transaction. This
            // mimics another replica running `cleanup_stuck_scans` in
            // parallel.
            let mut holder_tx = pool.begin().await.expect("begin holder tx");
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
                .bind(STUCK_SCAN_LOCK_ID)
                .fetch_one(&mut *holder_tx)
                .await
                .expect("acquire advisory lock");
            assert!(acquired, "holder must acquire lock first");

            // Janitor runs while the lock is held; expect Ok(0).
            let reaped = svc
                .cleanup_stuck_scans(Duration::from_secs(60))
                .await
                .expect("janitor returned Ok");
            assert_eq!(reaped, 0, "lock-contended tick must reap nothing");

            // Row is still `running` because the janitor skipped.
            let status: String =
                sqlx::query_scalar("SELECT status FROM scan_results WHERE id = $1")
                    .bind(stuck_id)
                    .fetch_one(&pool)
                    .await
                    .expect("read status");
            assert_eq!(status, "running", "skipped tick must not transition rows");

            // No audit rows written.
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM audit_log \
                 WHERE resource_id = $1 AND action = 'SCAN_REAPED'",
            )
            .bind(stuck_id)
            .fetch_one(&pool)
            .await
            .expect("count audit rows");
            assert_eq!(count, 0);

            // Release holder.
            holder_tx.commit().await.expect("release advisory lock");

            // After release, a second sweep should reap the row.
            let reaped2 = svc
                .cleanup_stuck_scans(Duration::from_secs(60))
                .await
                .expect("janitor returned Ok");
            assert!(reaped2 >= 1, "post-release sweep must reap the row");

            let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
                .bind(stuck_id)
                .execute(&pool)
                .await;
            cleanup_repo(&pool, repo_id).await;
        }

        /// M1 coverage: batched audit INSERT lands all rows in a single
        /// statement. Seed multiple stuck rows, run one sweep, assert
        /// every audit row exists and carries the system actor.
        #[tokio::test]
        async fn cleanup_stuck_scans_batched_audit_insert_lands_all_rows() {
            let _serial = CLEANUP_TEST_LOCK.lock().await;
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());
            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "m1").await;
            let mut stuck_ids = Vec::with_capacity(5);
            for _ in 0..5 {
                stuck_ids.push(insert_stuck_running_scan(&pool, aid, repo_id, 3600).await);
            }

            let reaped = svc
                .cleanup_stuck_scans(Duration::from_secs(60))
                .await
                .expect("janitor returned Ok");
            assert!(reaped >= 5, "expected at least 5 reaps, got {}", reaped);

            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM audit_log \
                 WHERE resource_id = ANY($1) AND action = 'SCAN_REAPED' \
                   AND details->>'actor' = $2",
            )
            .bind(&stuck_ids)
            .bind(STUCK_SCAN_AUDIT_ACTOR)
            .fetch_one(&pool)
            .await
            .expect("count audit rows");
            assert_eq!(count, 5, "all 5 audit rows must land via the UNNEST INSERT");

            let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = ANY($1)")
                .bind(&stuck_ids)
                .execute(&pool)
                .await;
            cleanup_repo(&pool, repo_id).await;
        }

        /// M1 coverage: configurable reap limit. With limit=2 and 5 stuck
        /// rows, one tick reaps at most 2.
        #[tokio::test]
        async fn cleanup_stuck_scans_respects_configured_reap_limit() {
            let _serial = CLEANUP_TEST_LOCK.lock().await;
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let svc = ScanResultService::new(pool.clone());
            let repo_id = insert_test_repo(&pool).await;
            let (aid, _) = insert_test_artifact(&pool, repo_id, "m1lim").await;
            let mut stuck_ids = Vec::with_capacity(5);
            for _ in 0..5 {
                stuck_ids.push(insert_stuck_running_scan(&pool, aid, repo_id, 3600).await);
            }

            let reaped = svc
                .cleanup_stuck_scans_with_limit(Duration::from_secs(60), 2)
                .await
                .expect("janitor returned Ok");
            assert_eq!(reaped, 2, "explicit limit must cap reaps");

            // Remaining 3 rows are still `running`.
            let still_running: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM scan_results \
                 WHERE id = ANY($1) AND status = 'running'",
            )
            .bind(&stuck_ids)
            .fetch_one(&pool)
            .await
            .expect("count still running");
            assert_eq!(
                still_running, 3,
                "exactly 3 rows must remain stuck for the next tick"
            );

            let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = ANY($1)")
                .bind(&stuck_ids)
                .execute(&pool)
                .await;
            cleanup_repo(&pool, repo_id).await;
        }
    }
}
