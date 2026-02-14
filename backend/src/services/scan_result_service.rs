//! Service for managing scan results and findings.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{
    DashboardSummary, Grade, RawFinding, RepoSecurityScore, ScanFinding, ScanResult, Severity,
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
                      scanner_version, error_message, started_at, completed_at, created_at
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
                   scanner_version, error_message, started_at, completed_at, created_at
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
        // Get source scan counts
        let source = self.get_scan(source_scan_id).await?;

        // Create new scan result marked as reused
        let new_scan = sqlx::query_as!(
            ScanResult,
            r#"
            INSERT INTO scan_results (
                artifact_id, repository_id, scan_type, status, started_at, completed_at,
                findings_count, critical_count, high_count, medium_count, low_count, info_count,
                checksum_sha256, source_scan_id, is_reused
            )
            VALUES ($1, $2, $3, 'completed', NOW(), NOW(), $4, $5, $6, $7, $8, $9, $10, $11, true)
            RETURNING id, artifact_id, repository_id, scan_type, status,
                      findings_count, critical_count, high_count, medium_count, low_count, info_count,
                      scanner_version, error_message, started_at, completed_at, created_at
            "#,
            artifact_id,
            repository_id,
            scan_type,
            source.findings_count,
            source.critical_count,
            source.high_count,
            source.medium_count,
            source.low_count,
            source.info_count,
            checksum_sha256,
            source_scan_id,
        )
        .fetch_one(&self.db)
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
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(new_scan)
    }

    /// Mark a scan as completed with severity counts.
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
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE scan_results
            SET status = 'completed', findings_count = $2,
                critical_count = $3, high_count = $4, medium_count = $5,
                low_count = $6, info_count = $7, completed_at = NOW()
            WHERE id = $1
            "#,
            scan_id,
            findings_count,
            critical,
            high,
            medium,
            low,
            info,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Mark a scan as failed with an error message.
    pub async fn fail_scan(&self, scan_id: Uuid, error: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE scan_results
            SET status = 'failed', error_message = $2, completed_at = NOW()
            WHERE id = $1
            "#,
            scan_id,
            error,
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
                   scanner_version, error_message, started_at, completed_at, created_at
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
                   scanner_version, error_message, started_at, completed_at, created_at
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
        // Count non-acknowledged findings by severity across all completed scans
        // for this repository's artifacts.
        let counts = sqlx::query!(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE severity = 'critical' AND NOT is_acknowledged) as "critical!",
                COUNT(*) FILTER (WHERE severity = 'high' AND NOT is_acknowledged) as "high!",
                COUNT(*) FILTER (WHERE severity = 'medium' AND NOT is_acknowledged) as "medium!",
                COUNT(*) FILTER (WHERE severity = 'low' AND NOT is_acknowledged) as "low!",
                COUNT(*) FILTER (WHERE is_acknowledged) as "acknowledged!",
                COUNT(*) as "total!"
            FROM scan_findings
            WHERE artifact_id IN (
                SELECT id FROM artifacts WHERE repository_id = $1 AND NOT is_deleted
            )
            "#,
            repository_id,
        )
        .fetch_one(&self.db)
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
        .fetch_one(&self.db)
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
        .fetch_one(&self.db)
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
        let summary = sqlx::query!(
            r#"
            SELECT
                (SELECT COUNT(*) FROM scan_configs WHERE scan_enabled = true) as "repos_with_scanning!",
                (SELECT COUNT(*) FROM scan_results) as "total_scans!",
                (SELECT COUNT(*) FROM scan_findings WHERE NOT is_acknowledged) as "total_findings!",
                (SELECT COUNT(*) FROM scan_findings WHERE severity = 'critical' AND NOT is_acknowledged) as "critical_findings!",
                (SELECT COUNT(*) FROM scan_findings WHERE severity = 'high' AND NOT is_acknowledged) as "high_findings!",
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
        };
        assert_eq!(result.scan_type, "dependency");
        assert_eq!(result.status, "completed");
        assert_eq!(result.findings_count, 10);
        assert_eq!(result.critical_count, 1);
        assert!(result.error_message.is_none());
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
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["scan_type"], "image");
        assert_eq!(json["status"], "running");
        assert_eq!(json["findings_count"], 0);
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
        };
        assert_eq!(result.status, "failed");
        assert_eq!(result.error_message.as_deref(), Some("Scanner timed out"));
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
}
