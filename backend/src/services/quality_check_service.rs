//! Quality check orchestration service.
//!
//! Runs pluggable quality checkers against artifacts, persists results,
//! computes composite health scores, and evaluates quality gates.

use bytes::Bytes;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::quality::{
    ArtifactHealthScore, ComponentScores, QualityCheckIssue, QualityCheckOutput,
    QualityCheckResult, QualityGate, QualityGateEvaluation, QualityGateViolation, RepoHealthScore,
};
use crate::models::security::Grade;
use crate::services::helm_lint_checker::HelmLintChecker;
use crate::services::metadata_checker::MetadataCompletenessChecker;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

pub struct CreateQualityGateInput {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub min_health_score: Option<i32>,
    pub min_security_score: Option<i32>,
    pub min_quality_score: Option<i32>,
    pub min_metadata_score: Option<i32>,
    pub max_critical_issues: Option<i32>,
    pub max_high_issues: Option<i32>,
    pub max_medium_issues: Option<i32>,
    pub required_checks: Vec<String>,
    pub enforce_on_promotion: bool,
    pub enforce_on_download: bool,
    pub action: String,
}

pub struct UpdateQualityGateInput {
    pub name: Option<String>,
    pub description: Option<String>,
    pub min_health_score: Option<i32>,
    pub min_security_score: Option<i32>,
    pub min_quality_score: Option<i32>,
    pub min_metadata_score: Option<i32>,
    pub max_critical_issues: Option<i32>,
    pub max_high_issues: Option<i32>,
    pub max_medium_issues: Option<i32>,
    pub required_checks: Option<Vec<String>>,
    pub enforce_on_promotion: Option<bool>,
    pub enforce_on_download: Option<bool>,
    pub action: Option<String>,
    pub is_enabled: Option<bool>,
}

const WEIGHT_SECURITY: i32 = 40;
const WEIGHT_LICENSE: i32 = 20;
const WEIGHT_QUALITY: i32 = 25;
const WEIGHT_METADATA: i32 = 15;

pub struct QualityCheckService {
    db: PgPool,
}

impl QualityCheckService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Run all applicable quality checks against an artifact, persist results,
    /// and recalculate the artifact health score.
    pub async fn check_artifact(&self, artifact_id: Uuid) -> Result<()> {
        // 1. Fetch artifact
        let artifact: Artifact = sqlx::query_as(
            r#"
            SELECT id, repository_id, path, name, version, size_bytes,
                   checksum_sha256, checksum_md5, checksum_sha1,
                   content_type, storage_key, is_deleted, uploaded_by,
                   created_at, updated_at
            FROM artifacts
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

        // 2. Fetch artifact metadata
        let metadata: Option<ArtifactMetadata> = sqlx::query_as(
            r#"
            SELECT id, artifact_id, format, metadata, properties
            FROM artifact_metadata
            WHERE artifact_id = $1
            LIMIT 1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // 3. Get repository format
        let format: String = sqlx::query_scalar("SELECT format FROM repositories WHERE id = $1")
            .bind(artifact.repository_id)
            .fetch_one(&self.db)
            .await
            .map_err(|e| {
                AppError::Database(format!(
                    "Failed to fetch format for repository {}: {}",
                    artifact.repository_id, e
                ))
            })?;

        // 4. Fetch artifact content from storage
        let content = self.fetch_artifact_content(&artifact).await?;

        // 5. Run MetadataCompletenessChecker
        let meta_checker = MetadataCompletenessChecker;
        let meta_output = meta_checker.check(
            &artifact.name,
            artifact.version.as_deref(),
            metadata.as_ref().map(|m| &m.metadata),
        );

        info!(
            artifact_id = %artifact_id,
            check_type = meta_checker.check_type(),
            score = meta_output.score,
            passed = meta_output.passed,
            issues = meta_output.issues.len(),
            "Quality check completed"
        );

        self.persist_check_result(
            artifact_id,
            artifact.repository_id,
            meta_checker.check_type(),
            "1.0.0",
            &meta_output,
        )
        .await?;

        // 6. If format is "helm", run HelmLintChecker
        if format == "helm" {
            let helm_checker = HelmLintChecker;
            let helm_output = helm_checker.check(&content);

            info!(
                artifact_id = %artifact_id,
                check_type = helm_checker.check_type(),
                score = helm_output.score,
                passed = helm_output.passed,
                issues = helm_output.issues.len(),
                "Quality check completed"
            );

            self.persist_check_result(
                artifact_id,
                artifact.repository_id,
                helm_checker.check_type(),
                "1.0.0",
                &helm_output,
            )
            .await?;
        }

        // 7. Recalculate artifact health
        self.recalculate_artifact_health(artifact_id).await?;

        Ok(())
    }

    /// Run quality checks for all artifacts in a repository.
    pub async fn check_repository(&self, repository_id: Uuid) -> Result<u32> {
        let artifact_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
        )
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let count = artifact_ids.len() as u32;
        for id in artifact_ids {
            if let Err(e) = self.check_artifact(id).await {
                warn!("Quality check failed for artifact {}: {}", id, e);
            }
        }
        Ok(count)
    }

    /// Insert a completed quality check result and its associated issues.
    async fn persist_check_result(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        check_type: &str,
        checker_version: &str,
        output: &QualityCheckOutput,
    ) -> Result<Uuid> {
        // Count severities from the issues list
        let mut critical_count: i32 = 0;
        let mut high_count: i32 = 0;
        let mut medium_count: i32 = 0;
        let mut low_count: i32 = 0;
        let mut info_count: i32 = 0;

        for issue in &output.issues {
            match issue.severity.as_str() {
                "critical" => critical_count += 1,
                "high" => high_count += 1,
                "medium" => medium_count += 1,
                "low" => low_count += 1,
                "info" => info_count += 1,
                _ => info_count += 1,
            }
        }

        let issues_count = output.issues.len() as i32;
        let details = serde_json::to_value(&output.details)
            .map_err(|e| AppError::Internal(format!("Failed to serialize details: {}", e)))?;

        let check_result_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO quality_check_results (
                artifact_id, repository_id, check_type, status, score, passed,
                details, issues_count, critical_count, high_count, medium_count,
                low_count, info_count, checker_version, started_at, completed_at
            ) VALUES ($1, $2, $3, 'completed', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
            RETURNING id
            "#,
        )
        .bind(artifact_id)
        .bind(repository_id)
        .bind(check_type)
        .bind(output.score)
        .bind(output.passed)
        .bind(&details)
        .bind(issues_count)
        .bind(critical_count)
        .bind(high_count)
        .bind(medium_count)
        .bind(low_count)
        .bind(info_count)
        .bind(checker_version)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Persist individual issues
        for issue in &output.issues {
            sqlx::query(
                r#"
                INSERT INTO quality_check_issues (
                    check_result_id, artifact_id, severity, category, title, description, location
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(check_result_id)
            .bind(artifact_id)
            .bind(&issue.severity)
            .bind(&issue.category)
            .bind(&issue.title)
            .bind(&issue.description)
            .bind(&issue.location)
            .execute(&self.db)
            .await
            .map_err(|e| {
                error!(
                    check_result_id = %check_result_id,
                    title = %issue.title,
                    "Failed to persist quality check issue: {}",
                    e
                );
                AppError::Database(e.to_string())
            })?;
        }

        Ok(check_result_id)
    }

    /// Recalculate the composite health score for a single artifact.
    pub async fn recalculate_artifact_health(&self, artifact_id: Uuid) -> Result<()> {
        // 1. Get all completed quality check results for this artifact
        //    (deduplicate by check_type, keeping latest)
        let rows: Vec<CheckScoreRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (check_type)
                check_type, score, passed, critical_count, high_count, medium_count, low_count
            FROM quality_check_results
            WHERE artifact_id = $1 AND status = 'completed'
            ORDER BY check_type, created_at DESC
            "#,
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // 2. Get security score from repo_security_scores (if exists)
        let security_score: Option<i32> = sqlx::query_scalar(
            r#"
            SELECT score FROM repo_security_scores WHERE repository_id = (
                SELECT repository_id FROM artifacts WHERE id = $1
            )
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // 3. Compute component scores
        let metadata_score: Option<i32> = rows
            .iter()
            .find(|r| r.check_type == "metadata_completeness")
            .and_then(|r| r.score);

        // quality_score = average of non-metadata quality check scores (e.g. helm_lint)
        let quality_checks: Vec<i32> = rows
            .iter()
            .filter(|r| r.check_type != "metadata_completeness")
            .filter_map(|r| r.score)
            .collect();

        let quality_score: Option<i32> = if quality_checks.is_empty() {
            None
        } else {
            let sum: i32 = quality_checks.iter().sum();
            Some(sum / quality_checks.len() as i32)
        };

        let license_score: Option<i32> = None; // Future: integrate DTrack data

        // 4. Compute weighted composite health score
        let component_scores = ComponentScores {
            security: security_score,
            license: license_score,
            quality: quality_score,
            metadata: metadata_score,
        };

        let health_score = compute_weighted_health_score(&component_scores);
        let health_grade = Grade::from_score(health_score).as_char().to_string();

        // 5. Total issues = sum of all check critical+high+medium+low counts
        let mut total_issues: i32 = 0;
        let mut critical_issues: i32 = 0;
        let mut checks_passed: i32 = 0;
        let checks_total = rows.len() as i32;

        for row in &rows {
            total_issues += row.critical_count + row.high_count + row.medium_count + row.low_count;
            critical_issues += row.critical_count;
            if row.passed.unwrap_or(false) {
                checks_passed += 1;
            }
        }

        // 6. UPSERT into artifact_health_scores
        sqlx::query(
            r#"
            INSERT INTO artifact_health_scores (
                artifact_id, health_score, health_grade,
                security_score, license_score, quality_score, metadata_score,
                total_issues, critical_issues, checks_passed, checks_total,
                last_checked_at, calculated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
            ON CONFLICT (artifact_id) DO UPDATE SET
                health_score = EXCLUDED.health_score,
                health_grade = EXCLUDED.health_grade,
                security_score = EXCLUDED.security_score,
                license_score = EXCLUDED.license_score,
                quality_score = EXCLUDED.quality_score,
                metadata_score = EXCLUDED.metadata_score,
                total_issues = EXCLUDED.total_issues,
                critical_issues = EXCLUDED.critical_issues,
                checks_passed = EXCLUDED.checks_passed,
                checks_total = EXCLUDED.checks_total,
                last_checked_at = NOW(),
                calculated_at = NOW()
            "#,
        )
        .bind(artifact_id)
        .bind(health_score)
        .bind(&health_grade)
        .bind(security_score)
        .bind(license_score)
        .bind(quality_score)
        .bind(metadata_score)
        .bind(total_issues)
        .bind(critical_issues)
        .bind(checks_passed)
        .bind(checks_total)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        info!(
            artifact_id = %artifact_id,
            health_score = health_score,
            health_grade = %health_grade,
            "Artifact health score recalculated"
        );

        Ok(())
    }

    /// Recalculate the aggregate health score for a repository.
    pub async fn recalculate_repo_health(&self, repository_id: Uuid) -> Result<()> {
        let row: Option<RepoAggregateRow> = sqlx::query_as(
            r#"
            SELECT
                COALESCE(AVG(health_score), 100)::int4 as avg_score,
                AVG(security_score)::int4 as avg_security,
                AVG(license_score)::int4 as avg_license,
                AVG(quality_score)::int4 as avg_quality,
                AVG(metadata_score)::int4 as avg_metadata,
                COUNT(*)::int4 as total,
                (COUNT(*) FILTER (WHERE health_score >= 50))::int4 as passing,
                (COUNT(*) FILTER (WHERE health_score < 50))::int4 as failing
            FROM artifact_health_scores ahs
            JOIN artifacts a ON a.id = ahs.artifact_id
            WHERE a.repository_id = $1 AND a.is_deleted = false
            "#,
        )
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let agg = row.unwrap_or(RepoAggregateRow {
            avg_score: 100,
            avg_security: None,
            avg_license: None,
            avg_quality: None,
            avg_metadata: None,
            total: 0,
            passing: 0,
            failing: 0,
        });

        let health_grade = Grade::from_score(agg.avg_score).as_char().to_string();

        sqlx::query(
            r#"
            INSERT INTO repo_health_scores (
                repository_id, health_score, health_grade,
                avg_security_score, avg_license_score, avg_quality_score, avg_metadata_score,
                artifacts_evaluated, artifacts_passing, artifacts_failing,
                last_evaluated_at, calculated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
            ON CONFLICT (repository_id) DO UPDATE SET
                health_score = EXCLUDED.health_score,
                health_grade = EXCLUDED.health_grade,
                avg_security_score = EXCLUDED.avg_security_score,
                avg_license_score = EXCLUDED.avg_license_score,
                avg_quality_score = EXCLUDED.avg_quality_score,
                avg_metadata_score = EXCLUDED.avg_metadata_score,
                artifacts_evaluated = EXCLUDED.artifacts_evaluated,
                artifacts_passing = EXCLUDED.artifacts_passing,
                artifacts_failing = EXCLUDED.artifacts_failing,
                last_evaluated_at = NOW(),
                calculated_at = NOW()
            "#,
        )
        .bind(repository_id)
        .bind(agg.avg_score)
        .bind(&health_grade)
        .bind(agg.avg_security)
        .bind(agg.avg_license)
        .bind(agg.avg_quality)
        .bind(agg.avg_metadata)
        .bind(agg.total)
        .bind(agg.passing)
        .bind(agg.failing)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        info!(
            repository_id = %repository_id,
            health_score = agg.avg_score,
            health_grade = %health_grade,
            artifacts_evaluated = agg.total,
            "Repository health score recalculated"
        );

        Ok(())
    }

    /// Evaluate an artifact against the applicable quality gate.
    pub async fn evaluate_quality_gate(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<QualityGateEvaluation> {
        // 1. Get enabled quality gate for this repository (or global fallback)
        let gate: QualityGate = sqlx::query_as(
            r#"
            SELECT id, repository_id, name, description,
                   min_health_score, min_security_score, min_quality_score, min_metadata_score,
                   max_critical_issues, max_high_issues, max_medium_issues,
                   required_checks, enforce_on_promotion, enforce_on_download,
                   action, is_enabled, created_at, updated_at
            FROM quality_gates
            WHERE is_enabled = true AND (repository_id = $1 OR repository_id IS NULL)
            ORDER BY repository_id NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| {
            AppError::NotFound("No enabled quality gate found for this repository".to_string())
        })?;

        // 2. Get artifact health score
        let health: ArtifactHealthScore = sqlx::query_as(
            r#"
            SELECT id, artifact_id, health_score, health_grade,
                   security_score, license_score, quality_score, metadata_score,
                   total_issues, critical_issues, checks_passed, checks_total,
                   last_checked_at, calculated_at
            FROM artifact_health_scores
            WHERE artifact_id = $1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| {
            AppError::NotFound(
                "No health score found for artifact; run quality checks first".to_string(),
            )
        })?;

        // 3. Check each gate condition, collecting violations
        let mut violations: Vec<QualityGateViolation> = Vec::new();

        check_min_score(
            &mut violations,
            "min_health_score",
            "Health",
            gate.min_health_score,
            health.health_score,
        );
        check_min_score(
            &mut violations,
            "min_security_score",
            "Security",
            gate.min_security_score,
            health.security_score.unwrap_or(0),
        );
        check_min_score(
            &mut violations,
            "min_quality_score",
            "Quality",
            gate.min_quality_score,
            health.quality_score.unwrap_or(0),
        );
        check_min_score(
            &mut violations,
            "min_metadata_score",
            "Metadata",
            gate.min_metadata_score,
            health.metadata_score.unwrap_or(0),
        );

        check_max_issues(
            &mut violations,
            "max_critical_issues",
            "Critical",
            gate.max_critical_issues,
            health.critical_issues,
        );
        check_max_issues(
            &mut violations,
            "max_high_issues",
            "High",
            gate.max_high_issues,
            health.total_issues - health.critical_issues,
        );
        check_max_issues(
            &mut violations,
            "max_medium_issues",
            "Total",
            gate.max_medium_issues,
            health.total_issues,
        );

        // Check required_checks: verify each check_type exists in completed results
        if !gate.required_checks.is_empty() {
            let completed_check_types: Vec<String> = sqlx::query_scalar(
                r#"
                SELECT DISTINCT check_type
                FROM quality_check_results
                WHERE artifact_id = $1 AND status = 'completed'
                "#,
            )
            .bind(artifact_id)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            for required in &gate.required_checks {
                if !completed_check_types.contains(required) {
                    violations.push(QualityGateViolation {
                        rule: "required_checks".to_string(),
                        expected: format!("check '{}' completed", required),
                        actual: "not found".to_string(),
                        message: format!("Required check '{}' has not been completed", required),
                    });
                }
            }
        }

        // 4. Determine pass/fail
        let passed = violations.is_empty();

        let component_scores = ComponentScores {
            security: health.security_score,
            license: health.license_score,
            quality: health.quality_score,
            metadata: health.metadata_score,
        };

        let evaluation = QualityGateEvaluation {
            passed,
            action: gate.action.clone(),
            gate_name: gate.name.clone(),
            health_score: health.health_score,
            health_grade: health.health_grade.clone(),
            violations,
            component_scores,
        };

        // 5. Persist evaluation record
        let details_json = serde_json::to_value(&evaluation)
            .map_err(|e| AppError::Internal(format!("Failed to serialize evaluation: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO quality_gate_evaluations (
                artifact_id, quality_gate_id, passed, action, health_score, details, evaluated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
            "#,
        )
        .bind(artifact_id)
        .bind(gate.id)
        .bind(passed)
        .bind(&gate.action)
        .bind(health.health_score)
        .bind(&details_json)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        info!(
            artifact_id = %artifact_id,
            gate_name = %gate.name,
            passed = passed,
            violations = evaluation.violations.len(),
            "Quality gate evaluated"
        );

        Ok(evaluation)
    }

    /// Fetch artifact content from filesystem storage.
    async fn fetch_artifact_content(&self, artifact: &Artifact) -> Result<Bytes> {
        let storage_path: String =
            sqlx::query_scalar("SELECT storage_path FROM repositories WHERE id = $1")
                .bind(artifact.repository_id)
                .fetch_one(&self.db)
                .await
                .map_err(|e| {
                    AppError::Database(format!(
                        "Failed to fetch storage_path for repository {}: {}",
                        artifact.repository_id, e
                    ))
                })?;

        let storage = FilesystemStorage::new(&storage_path);
        storage.get(&artifact.storage_key).await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to read artifact {} (key={}): {}",
                artifact.id, artifact.storage_key, e
            ))
        })
    }

    /// Get artifact health score by artifact ID.
    pub async fn get_artifact_health(
        &self,
        artifact_id: Uuid,
    ) -> Result<Option<ArtifactHealthScore>> {
        sqlx::query_as(
            r#"
            SELECT id, artifact_id, health_score, health_grade,
                   security_score, license_score, quality_score, metadata_score,
                   total_issues, critical_issues, checks_passed, checks_total,
                   last_checked_at, calculated_at
            FROM artifact_health_scores
            WHERE artifact_id = $1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Get repository health score.
    pub async fn get_repo_health(&self, repository_id: Uuid) -> Result<Option<RepoHealthScore>> {
        sqlx::query_as(
            r#"
            SELECT id, repository_id, health_score, health_grade,
                   avg_security_score, avg_license_score, avg_quality_score, avg_metadata_score,
                   artifacts_evaluated, artifacts_passing, artifacts_failing,
                   last_evaluated_at, calculated_at
            FROM repo_health_scores
            WHERE repository_id = $1
            "#,
        )
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// List all repo health scores (for dashboard).
    pub async fn list_repo_health_scores(&self) -> Result<Vec<RepoHealthScore>> {
        sqlx::query_as(
            r#"
            SELECT id, repository_id, health_score, health_grade,
                   avg_security_score, avg_license_score, avg_quality_score, avg_metadata_score,
                   artifacts_evaluated, artifacts_passing, artifacts_failing,
                   last_evaluated_at, calculated_at
            FROM repo_health_scores
            ORDER BY health_score ASC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// List quality check results for an artifact.
    pub async fn list_checks(&self, artifact_id: Uuid) -> Result<Vec<QualityCheckResult>> {
        sqlx::query_as(
            r#"
            SELECT id, artifact_id, repository_id, check_type, status,
                   score, passed, details, issues_count,
                   critical_count, high_count, medium_count, low_count, info_count,
                   checker_version, error_message, started_at, completed_at, created_at
            FROM quality_check_results
            WHERE artifact_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Get a specific quality check result by ID.
    pub async fn get_check(&self, check_id: Uuid) -> Result<QualityCheckResult> {
        sqlx::query_as(
            r#"
            SELECT id, artifact_id, repository_id, check_type, status,
                   score, passed, details, issues_count,
                   critical_count, high_count, medium_count, low_count, info_count,
                   checker_version, error_message, started_at, completed_at, created_at
            FROM quality_check_results
            WHERE id = $1
            "#,
        )
        .bind(check_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Quality check result not found".to_string()))
    }

    /// List issues for a specific check result.
    pub async fn list_check_issues(&self, check_result_id: Uuid) -> Result<Vec<QualityCheckIssue>> {
        sqlx::query_as(
            r#"
            SELECT id, check_result_id, artifact_id, severity, category,
                   title, description, location, is_suppressed,
                   suppressed_by, suppressed_reason, suppressed_at, created_at
            FROM quality_check_issues
            WHERE check_result_id = $1
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    WHEN 'info' THEN 4
                    ELSE 5
                END,
                created_at ASC
            "#,
        )
        .bind(check_result_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Suppress a quality issue.
    pub async fn suppress_issue(&self, issue_id: Uuid, user_id: Uuid, reason: &str) -> Result<()> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE quality_check_issues
            SET is_suppressed = true, suppressed_by = $2, suppressed_reason = $3, suppressed_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(issue_id)
        .bind(user_id)
        .bind(reason)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(AppError::NotFound(
                "Quality check issue not found".to_string(),
            ));
        }

        info!(issue_id = %issue_id, user_id = %user_id, "Quality issue suppressed");
        Ok(())
    }

    /// Unsuppress a quality issue.
    pub async fn unsuppress_issue(&self, issue_id: Uuid) -> Result<()> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE quality_check_issues
            SET is_suppressed = false, suppressed_by = NULL, suppressed_reason = NULL, suppressed_at = NULL
            WHERE id = $1
            "#,
        )
        .bind(issue_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(AppError::NotFound(
                "Quality check issue not found".to_string(),
            ));
        }

        info!(issue_id = %issue_id, "Quality issue unsuppressed");
        Ok(())
    }

    /// List quality gates, optionally filtered by repository.
    pub async fn list_gates(&self, repository_id: Option<Uuid>) -> Result<Vec<QualityGate>> {
        match repository_id {
            Some(repo_id) => {
                sqlx::query_as(
                    r#"
                    SELECT id, repository_id, name, description,
                           min_health_score, min_security_score, min_quality_score, min_metadata_score,
                           max_critical_issues, max_high_issues, max_medium_issues,
                           required_checks, enforce_on_promotion, enforce_on_download,
                           action, is_enabled, created_at, updated_at
                    FROM quality_gates
                    WHERE repository_id = $1 OR repository_id IS NULL
                    ORDER BY repository_id NULLS LAST, name
                    "#,
                )
                .bind(repo_id)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))
            }
            None => {
                sqlx::query_as(
                    r#"
                    SELECT id, repository_id, name, description,
                           min_health_score, min_security_score, min_quality_score, min_metadata_score,
                           max_critical_issues, max_high_issues, max_medium_issues,
                           required_checks, enforce_on_promotion, enforce_on_download,
                           action, is_enabled, created_at, updated_at
                    FROM quality_gates
                    ORDER BY repository_id NULLS LAST, name
                    "#,
                )
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))
            }
        }
    }

    /// Get a single quality gate by ID.
    pub async fn get_gate(&self, gate_id: Uuid) -> Result<QualityGate> {
        sqlx::query_as(
            r#"
            SELECT id, repository_id, name, description,
                   min_health_score, min_security_score, min_quality_score, min_metadata_score,
                   max_critical_issues, max_high_issues, max_medium_issues,
                   required_checks, enforce_on_promotion, enforce_on_download,
                   action, is_enabled, created_at, updated_at
            FROM quality_gates
            WHERE id = $1
            "#,
        )
        .bind(gate_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Quality gate not found".to_string()))
    }

    /// Create a new quality gate.
    pub async fn create_gate(&self, gate: CreateQualityGateInput) -> Result<QualityGate> {
        sqlx::query_as(
            r#"
            INSERT INTO quality_gates (
                repository_id, name, description,
                min_health_score, min_security_score, min_quality_score, min_metadata_score,
                max_critical_issues, max_high_issues, max_medium_issues,
                required_checks, enforce_on_promotion, enforce_on_download,
                action, is_enabled
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true)
            RETURNING id, repository_id, name, description,
                      min_health_score, min_security_score, min_quality_score, min_metadata_score,
                      max_critical_issues, max_high_issues, max_medium_issues,
                      required_checks, enforce_on_promotion, enforce_on_download,
                      action, is_enabled, created_at, updated_at
            "#,
        )
        .bind(gate.repository_id)
        .bind(&gate.name)
        .bind(&gate.description)
        .bind(gate.min_health_score)
        .bind(gate.min_security_score)
        .bind(gate.min_quality_score)
        .bind(gate.min_metadata_score)
        .bind(gate.max_critical_issues)
        .bind(gate.max_high_issues)
        .bind(gate.max_medium_issues)
        .bind(&gate.required_checks)
        .bind(gate.enforce_on_promotion)
        .bind(gate.enforce_on_download)
        .bind(&gate.action)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Update an existing quality gate.
    pub async fn update_gate(
        &self,
        gate_id: Uuid,
        input: UpdateQualityGateInput,
    ) -> Result<QualityGate> {
        // Fetch existing gate first
        let existing = self.get_gate(gate_id).await?;

        let name = input.name.unwrap_or(existing.name);
        let description = input.description.or(existing.description);
        let min_health_score = input.min_health_score.or(existing.min_health_score);
        let min_security_score = input.min_security_score.or(existing.min_security_score);
        let min_quality_score = input.min_quality_score.or(existing.min_quality_score);
        let min_metadata_score = input.min_metadata_score.or(existing.min_metadata_score);
        let max_critical_issues = input.max_critical_issues.or(existing.max_critical_issues);
        let max_high_issues = input.max_high_issues.or(existing.max_high_issues);
        let max_medium_issues = input.max_medium_issues.or(existing.max_medium_issues);
        let required_checks = input.required_checks.unwrap_or(existing.required_checks);
        let enforce_on_promotion = input
            .enforce_on_promotion
            .unwrap_or(existing.enforce_on_promotion);
        let enforce_on_download = input
            .enforce_on_download
            .unwrap_or(existing.enforce_on_download);
        let action = input.action.unwrap_or(existing.action);
        let is_enabled = input.is_enabled.unwrap_or(existing.is_enabled);

        sqlx::query_as(
            r#"
            UPDATE quality_gates SET
                name = $2,
                description = $3,
                min_health_score = $4,
                min_security_score = $5,
                min_quality_score = $6,
                min_metadata_score = $7,
                max_critical_issues = $8,
                max_high_issues = $9,
                max_medium_issues = $10,
                required_checks = $11,
                enforce_on_promotion = $12,
                enforce_on_download = $13,
                action = $14,
                is_enabled = $15,
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, repository_id, name, description,
                      min_health_score, min_security_score, min_quality_score, min_metadata_score,
                      max_critical_issues, max_high_issues, max_medium_issues,
                      required_checks, enforce_on_promotion, enforce_on_download,
                      action, is_enabled, created_at, updated_at
            "#,
        )
        .bind(gate_id)
        .bind(&name)
        .bind(&description)
        .bind(min_health_score)
        .bind(min_security_score)
        .bind(min_quality_score)
        .bind(min_metadata_score)
        .bind(max_critical_issues)
        .bind(max_high_issues)
        .bind(max_medium_issues)
        .bind(&required_checks)
        .bind(enforce_on_promotion)
        .bind(enforce_on_download)
        .bind(&action)
        .bind(is_enabled)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Delete a quality gate by ID.
    pub async fn delete_gate(&self, gate_id: Uuid) -> Result<()> {
        let rows_affected = sqlx::query("DELETE FROM quality_gates WHERE id = $1")
            .bind(gate_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected();

        if rows_affected == 0 {
            return Err(AppError::NotFound("Quality gate not found".to_string()));
        }

        info!(gate_id = %gate_id, "Quality gate deleted");
        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct CheckScoreRow {
    check_type: String,
    score: Option<i32>,
    passed: Option<bool>,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct RepoAggregateRow {
    avg_score: i32,
    avg_security: Option<i32>,
    avg_license: Option<i32>,
    avg_quality: Option<i32>,
    avg_metadata: Option<i32>,
    total: i32,
    passing: i32,
    failing: i32,
}

/// Push a violation if `actual` is below `threshold`.
fn check_min_score(
    violations: &mut Vec<QualityGateViolation>,
    rule: &str,
    label: &str,
    threshold: Option<i32>,
    actual: i32,
) {
    if let Some(min) = threshold {
        if actual < min {
            violations.push(QualityGateViolation {
                rule: rule.to_string(),
                expected: format!(">= {min}"),
                actual: actual.to_string(),
                message: format!("{label} score {actual} is below minimum {min}"),
            });
        }
    }
}

/// Push a violation if `actual` exceeds `threshold`.
fn check_max_issues(
    violations: &mut Vec<QualityGateViolation>,
    rule: &str,
    label: &str,
    threshold: Option<i32>,
    actual: i32,
) {
    if let Some(max) = threshold {
        if actual > max {
            violations.push(QualityGateViolation {
                rule: rule.to_string(),
                expected: format!("<= {max}"),
                actual: actual.to_string(),
                message: format!("{label} issues count {actual} exceeds maximum {max}"),
            });
        }
    }
}

/// Compute a weighted composite health score from component scores.
///
/// Weights: security=40, license=20, quality=25, metadata=15.
/// Components with no data (None) are excluded and the denominator is reduced
/// accordingly. If all components are None, returns 100 (no data = healthy).
fn compute_weighted_health_score(scores: &ComponentScores) -> i32 {
    let components: [(Option<i32>, i32); 4] = [
        (scores.security, WEIGHT_SECURITY),
        (scores.license, WEIGHT_LICENSE),
        (scores.quality, WEIGHT_QUALITY),
        (scores.metadata, WEIGHT_METADATA),
    ];

    let (weighted_sum, weight_sum) =
        components
            .iter()
            .fold((0, 0), |(ws, wt), (score, weight)| match score {
                Some(s) => (ws + s * weight, wt + weight),
                None => (ws, wt),
            });

    if weight_sum == 0 {
        return 100;
    }

    weighted_sum / weight_sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_components_present() {
        let scores = ComponentScores {
            security: Some(80),
            license: Some(100),
            quality: Some(60),
            metadata: Some(40),
        };
        // (80*40 + 100*20 + 60*25 + 40*15) / (40+20+25+15)
        // = (3200 + 2000 + 1500 + 600) / 100
        // = 7300 / 100 = 73
        assert_eq!(compute_weighted_health_score(&scores), 73);
    }

    #[test]
    fn test_all_components_perfect() {
        let scores = ComponentScores {
            security: Some(100),
            license: Some(100),
            quality: Some(100),
            metadata: Some(100),
        };
        // (100*40 + 100*20 + 100*25 + 100*15) / 100 = 10000 / 100 = 100
        assert_eq!(compute_weighted_health_score(&scores), 100);
    }

    #[test]
    fn test_all_components_zero() {
        let scores = ComponentScores {
            security: Some(0),
            license: Some(0),
            quality: Some(0),
            metadata: Some(0),
        };
        assert_eq!(compute_weighted_health_score(&scores), 0);
    }

    #[test]
    fn test_no_components_returns_100() {
        let scores = ComponentScores {
            security: None,
            license: None,
            quality: None,
            metadata: None,
        };
        // No data = assume healthy
        assert_eq!(compute_weighted_health_score(&scores), 100);
    }

    #[test]
    fn test_only_security() {
        let scores = ComponentScores {
            security: Some(80),
            license: None,
            quality: None,
            metadata: None,
        };
        // (80*40) / 40 = 80
        assert_eq!(compute_weighted_health_score(&scores), 80);
    }

    #[test]
    fn test_only_metadata() {
        let scores = ComponentScores {
            security: None,
            license: None,
            quality: None,
            metadata: Some(60),
        };
        // (60*15) / 15 = 60
        assert_eq!(compute_weighted_health_score(&scores), 60);
    }

    #[test]
    fn test_security_and_quality() {
        let scores = ComponentScores {
            security: Some(90),
            license: None,
            quality: Some(70),
            metadata: None,
        };
        // (90*40 + 70*25) / (40+25) = (3600 + 1750) / 65 = 5350 / 65 = 82
        assert_eq!(compute_weighted_health_score(&scores), 82);
    }

    #[test]
    fn test_security_and_metadata() {
        let scores = ComponentScores {
            security: Some(100),
            license: None,
            quality: None,
            metadata: Some(50),
        };
        // (100*40 + 50*15) / (40+15) = (4000 + 750) / 55 = 4750 / 55 = 86
        assert_eq!(compute_weighted_health_score(&scores), 86);
    }

    #[test]
    fn test_license_and_quality() {
        let scores = ComponentScores {
            security: None,
            license: Some(100),
            quality: Some(80),
            metadata: None,
        };
        // (100*20 + 80*25) / (20+25) = (2000 + 2000) / 45 = 4000 / 45 = 88
        assert_eq!(compute_weighted_health_score(&scores), 88);
    }

    #[test]
    fn test_three_components() {
        let scores = ComponentScores {
            security: Some(90),
            license: Some(70),
            quality: None,
            metadata: Some(100),
        };
        // (90*40 + 70*20 + 100*15) / (40+20+15) = (3600 + 1400 + 1500) / 75 = 6500 / 75 = 86
        assert_eq!(compute_weighted_health_score(&scores), 86);
    }

    #[test]
    fn test_grade_from_health_score() {
        // Verify Grade::from_score works correctly with health scores
        assert_eq!(Grade::from_score(100).as_char(), 'A');
        assert_eq!(Grade::from_score(90).as_char(), 'A');
        assert_eq!(Grade::from_score(89).as_char(), 'B');
        assert_eq!(Grade::from_score(75).as_char(), 'B');
        assert_eq!(Grade::from_score(74).as_char(), 'C');
        assert_eq!(Grade::from_score(50).as_char(), 'C');
        assert_eq!(Grade::from_score(49).as_char(), 'D');
        assert_eq!(Grade::from_score(25).as_char(), 'D');
        assert_eq!(Grade::from_score(24).as_char(), 'F');
        assert_eq!(Grade::from_score(0).as_char(), 'F');
    }

    #[test]
    fn test_weighted_score_integer_truncation() {
        // Verify integer division behavior is consistent
        let scores = ComponentScores {
            security: Some(33),
            license: None,
            quality: Some(67),
            metadata: None,
        };
        // (33*40 + 67*25) / (40+25) = (1320 + 1675) / 65 = 2995 / 65 = 46 (integer division)
        assert_eq!(compute_weighted_health_score(&scores), 46);
    }

    #[test]
    fn test_single_component_boundary_values() {
        // Score of 1
        let scores = ComponentScores {
            security: Some(1),
            license: None,
            quality: None,
            metadata: None,
        };
        assert_eq!(compute_weighted_health_score(&scores), 1);

        // Score of 99
        let scores = ComponentScores {
            security: None,
            license: None,
            quality: Some(99),
            metadata: None,
        };
        assert_eq!(compute_weighted_health_score(&scores), 99);
    }
}
