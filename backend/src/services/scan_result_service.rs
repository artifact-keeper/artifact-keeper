//! Service for managing scan results and findings.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{
    DashboardSummary, Grade, RawFinding, RawPackage, RepoSecurityScore, ScanFinding, ScanResult,
    Severity,
};

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

pub struct ScanResultService {
    db: PgPool,
}

impl ScanResultService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
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
                source_scan_id = $8
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
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE scan_results
            SET status = 'completed', findings_count = $2,
                critical_count = $3, high_count = $4, medium_count = $5,
                low_count = $6, info_count = $7, completed_at = NOW(),
                scanner_version = COALESCE($8, scanner_version),
                started_at = $9
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
    /// Each row is one package the scanner saw — vulnerable or not — so
    /// the SBOM read path can return the complete dep tree.
    ///
    /// Conflict handling: the unique index is
    /// `(scan_result_id, name, COALESCE(version, ''))`. When a scanner
    /// emits the same `(name, version)` twice within a single report (e.g.
    /// Trivy listing a Maven artifact both in its standalone Packages
    /// block AND inline on a vulnerability row, often with one PURL set
    /// and the other empty) the second insert promotes any newly-supplied
    /// `purl`, `license`, or `source_target` value over a previously-NULL
    /// row. `ON CONFLICT DO NOTHING` would lose whichever value lost the
    /// race; `DO UPDATE ... COALESCE(scan_packages.col, EXCLUDED.col)`
    /// keeps the first non-null value, which is the closest thing to
    /// "more specific wins" without inventing an ordering rule.
    pub async fn create_packages(
        &self,
        scan_result_id: Uuid,
        artifact_id: Uuid,
        packages: &[RawPackage],
    ) -> Result<()> {
        for pkg in packages {
            sqlx::query!(
                r#"
                INSERT INTO scan_packages (scan_result_id, artifact_id, name,
                    version, purl, license, source_target)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (scan_result_id, name, COALESCE(version, ''))
                    DO UPDATE SET
                        purl = COALESCE(scan_packages.purl, EXCLUDED.purl),
                        license = COALESCE(scan_packages.license, EXCLUDED.license),
                        source_target = COALESCE(scan_packages.source_target,
                                                 EXCLUDED.source_target)
                "#,
                scan_result_id,
                artifact_id,
                pkg.name,
                pkg.version,
                pkg.purl,
                pkg.license,
                pkg.source_target,
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }
        Ok(())
    }

    /// Batch insert findings for a completed scan.
    pub async fn create_findings(
        &self,
        scan_result_id: Uuid,
        artifact_id: Uuid,
        findings: &[RawFinding],
    ) -> Result<()> {
        for finding in findings {
            let severity_str = severity_to_db_string(finding.severity);

            sqlx::query!(
                r#"
                INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title,
                    description, cve_id, affected_component, affected_version, fixed_version,
                    source, source_url)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                "#,
                scan_result_id,
                artifact_id,
                severity_str,
                finding.title,
                finding.description,
                finding.cve_id,
                finding.affected_component,
                finding.affected_version,
                finding.fixed_version,
                finding.source,
                finding.source_url,
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        Ok(())
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
    pub async fn get_dashboard_summary(&self) -> Result<DashboardSummary> {
        // The three finding counts (total / critical / high) all draw from
        // the same `scan_findings JOIN latest_scans` set, so they are
        // collapsed into one subquery using FILTER aggregates rather than
        // three near-identical IN-subqueries.
        let summary = sqlx::query!(
            r#"
            WITH latest_scans AS (
                SELECT DISTINCT ON (artifact_id, scan_type) id
                FROM scan_results
                WHERE status = 'completed'
                ORDER BY artifact_id, scan_type,
                         completed_at DESC NULLS LAST, created_at DESC
            ),
            latest_findings AS (
                SELECT sf.severity, sf.is_acknowledged
                FROM scan_findings sf
                JOIN latest_scans ls ON ls.id = sf.scan_result_id
            )
            SELECT
                (SELECT COUNT(*) FROM scan_configs WHERE scan_enabled = true) as "repos_with_scanning!",
                (SELECT COUNT(*) FROM scan_results) as "total_scans!",
                (SELECT COUNT(*) FROM latest_findings WHERE NOT is_acknowledged) as "total_findings!",
                (SELECT COUNT(*) FROM latest_findings
                   WHERE severity = 'critical' AND NOT is_acknowledged) as "critical_findings!",
                (SELECT COUNT(*) FROM latest_findings
                   WHERE severity = 'high' AND NOT is_acknowledged) as "high_findings!",
                (SELECT COUNT(*) FROM repo_security_scores WHERE grade = 'A') as "repos_grade_a!",
                (SELECT COUNT(*) FROM repo_security_scores WHERE grade = 'F') as "repos_grade_f!"
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
    }
}
