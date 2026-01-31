//! Service for managing scan results and findings.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{
    DashboardSummary, Grade, RawFinding, RepoSecurityScore, ScanFinding, ScanResult, Severity,
};

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
        let result = sqlx::query_as!(
            ScanResult,
            r#"
            INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, started_at)
            VALUES ($1, $2, $3, 'running', NOW())
            RETURNING id, artifact_id, repository_id, scan_type, status,
                      findings_count, critical_count, high_count, medium_count, low_count, info_count,
                      scanner_version, error_message, started_at, completed_at, created_at
            "#,
            artifact_id,
            repository_id,
            scan_type,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Mark a scan as completed with severity counts.
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
            let severity_str = serde_json::to_value(&finding.severity)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "info".to_string());

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

        let penalty = critical * Severity::Critical.penalty_weight()
            + high * Severity::High.penalty_weight()
            + medium * Severity::Medium.penalty_weight()
            + low * Severity::Low.penalty_weight();
        let score = (100 - penalty).clamp(0, 100);
        let grade = Grade::from_score(score);

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

        Ok(DashboardSummary {
            repos_with_scanning: summary.repos_with_scanning,
            total_scans: summary.total_scans,
            total_findings: summary.total_findings,
            critical_findings: summary.critical_findings,
            high_findings: summary.high_findings,
            policy_violations_blocked: 0, // TODO: track in a counter table
            repos_grade_a: summary.repos_grade_a,
            repos_grade_f: summary.repos_grade_f,
        })
    }
}
