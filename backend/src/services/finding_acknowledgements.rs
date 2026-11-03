//! Acknowledgement decisions (#5153).
//!
//! Acknowledging a finding is how an administrator accepts a known risk so the
//! scan policy stops blocking it. That decision is about an advisory in a
//! component of specific bytes, so it cannot live on a `scan_findings` row:
//! a rescan, a dedup copy or a promotion writes new rows for the same facts.
//!
//! A decision is one row of `finding_acknowledgements` (migration 312), keyed on
//!
//! * the **bytes** (`checksum_sha256`): a new build under the same coordinate
//!   is not what the operator looked at, and a re-upload of the same bytes is;
//! * the **repository**: accepting a risk in one repository does not accept it
//!   in another. [`AcknowledgementScope::AllRepositories`] says otherwise, and
//!   only an explicit request writes it;
//! * the **finding identity**: class, advisory, component and component version.
//!   A new advisory, or the same advisory on another component or version, is a
//!   different identity and stays open. Which engine reported it is not part of
//!   the identity: two engines reporting one CVE in one component are one fact;
//! * a **severity ceiling**: a re-grade above what was accepted reopens it.
//!
//! Decisions are applied at read time by the `scan_findings_effective` view,
//! which every reader of acknowledged state selects from, so no writer of
//! findings has to know about them and an expiry takes effect by itself.
//! [`FindingAcknowledgementService::record_expired`] only writes the audit trail
//! and refreshes the stored scores.
//!
//! A revoke applies to the decision's whole lineage: the copies a promotion made
//! and the decisions that superseded it. A revoked row stays as the record.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::policy_service::PolicyService;
use crate::services::quarantine_service;
use crate::services::scan_result_service::ScanResultService;

/// Where a decision applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AcknowledgementScope {
    /// The repository of the finding the operator acknowledged.
    #[default]
    Repository,
    /// Every repository holding the same bytes. Never implied.
    AllRepositories,
}

/// The optional parts of an acknowledgement.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcknowledgeOptions {
    /// When the decision stops applying. `None`: until revoked.
    pub expires_at: Option<DateTime<Utc>>,
    pub scope: AcknowledgementScope,
}

/// One decision, as the listing reports it.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FindingAcknowledgement {
    pub id: Uuid,
    pub lineage_id: Uuid,
    pub repository_id: Option<Uuid>,
    pub checksum_sha256: String,
    pub finding_class: String,
    pub advisory_key: String,
    pub component_key: String,
    pub component_version_key: String,
    pub max_severity_rank: i16,
    pub reason: Option<String>,
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_via: String,
    pub carried_by: Option<Uuid>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Uuid>,
    pub revoked_reason: Option<String>,
    /// `active`, `expired` or `revoked`, as of the read.
    pub state: String,
}

const ACKNOWLEDGEMENT_COLUMNS: &str = "id, lineage_id, repository_id, \
     checksum_sha256::text AS checksum_sha256, \
     finding_class, advisory_key, component_key, component_version_key, max_severity_rank, \
     reason, acknowledged_by, acknowledged_at, expires_at, created_via, carried_by, \
     revoked_at, revoked_by, revoked_reason, \
     CASE WHEN revoked_at IS NOT NULL THEN 'revoked' \
          WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired' \
          ELSE 'active' END AS state";

/// Filters of [`FindingAcknowledgementService::list`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AcknowledgementFilter<'a> {
    pub repository_id: Option<Uuid>,
    pub checksum_sha256: Option<&'a str>,
    pub advisory: Option<&'a str>,
    /// Include expired and revoked decisions.
    pub include_inactive: bool,
}

/// The identity of one finding, with the facts a decision about it needs.
#[derive(Debug, Clone, FromRow)]
struct FindingKey {
    repository_id: Uuid,
    checksum_sha256: String,
    finding_class: String,
    advisory_key: String,
    component_key: String,
    component_version_key: String,
    severity_rank: i32,
}

const FINDING_KEY_COLUMNS: &str = "a.repository_id, a.checksum_sha256::text AS checksum_sha256, \
     sf.finding_class, \
     finding_advisory_key(sf.cve_id, sf.title) AS advisory_key, \
     finding_component_key(sf.affected_component) AS component_key, \
     finding_component_key(sf.affected_version) AS component_version_key";

/// The audit `details` of a decision. Names what was decided, never more than
/// the operator typed.
fn decision_audit_details(d: &FindingAcknowledgement) -> serde_json::Value {
    serde_json::json!({
        "acknowledgement_id": d.id,
        "lineage_id": d.lineage_id,
        "repository_id": d.repository_id,
        "checksum_sha256": d.checksum_sha256,
        "finding_class": d.finding_class,
        "advisory": d.advisory_key,
        "component": d.component_key,
        "component_version": d.component_version_key,
        "reason": d.reason,
        "expires_at": d.expires_at,
        "created_via": d.created_via,
    })
}

/// Refuse an expiry that would make the decision lapse the moment it is made.
fn validate_expiry(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Result<()> {
    match expires_at {
        Some(ts) if ts <= now => Err(AppError::Validation(
            "expires_at must be in the future".to_string(),
        )),
        _ => Ok(()),
    }
}

/// The severity ceiling of a decision that supersedes `previous`: what is being
/// accepted now, or what was already accepted if that is higher. An expired
/// previous decision accepts nothing any more.
fn ceiling_after_supersede(accepted_now: i32, previous_live: Option<i16>) -> i16 {
    let now = i16::try_from(accepted_now).unwrap_or(i16::MAX);
    previous_live.map_or(now, |prev| prev.max(now))
}

#[derive(Clone)]
pub struct FindingAcknowledgementService {
    db: PgPool,
}

impl FindingAcknowledgementService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // -----------------------------------------------------------------------
    // Decide
    // -----------------------------------------------------------------------

    /// Record a decision from one finding row: its identity, at its severity.
    /// Returns the decision. `NotFound` when the finding does not exist.
    pub async fn acknowledge_finding(
        &self,
        finding_id: Uuid,
        actor: Option<Uuid>,
        reason: Option<&str>,
        options: AcknowledgeOptions,
    ) -> Result<FindingAcknowledgement> {
        let key = self
            .finding_key(finding_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;
        let mut decisions = self
            .decide(std::slice::from_ref(&key), actor, reason, options)
            .await?;
        decisions
            .pop()
            .ok_or_else(|| AppError::Internal("acknowledgement was not recorded".to_string()))
    }

    /// Record a decision for one advisory on one artifact, across the components
    /// its current scans report it for (the Security tab's by-CVE action). A
    /// component reported later is not covered. When no current scan reports the
    /// advisory any more, the components it was last reported for are used.
    /// Returns the number of decisions; zero when the artifact has no such finding.
    pub async fn acknowledge_advisory(
        &self,
        artifact_id: Uuid,
        cve_id: &str,
        actor: Option<Uuid>,
        reason: Option<&str>,
        options: AcknowledgeOptions,
    ) -> Result<usize> {
        let keys = self.advisory_keys(artifact_id, cve_id).await?;
        if keys.is_empty() {
            return Ok(0);
        }
        Ok(self.decide(&keys, actor, reason, options).await?.len())
    }

    async fn finding_key(&self, finding_id: Uuid) -> Result<Option<FindingKey>> {
        let sql = format!(
            "SELECT {FINDING_KEY_COLUMNS}, finding_severity_rank(sf.severity) AS severity_rank \
             FROM scan_findings sf JOIN artifacts a ON a.id = sf.artifact_id \
             WHERE sf.id = $1"
        );
        sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(finding_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))
    }

    async fn advisory_keys(&self, artifact_id: Uuid, cve_id: &str) -> Result<Vec<FindingKey>> {
        let sql = format!(
            "SELECT {FINDING_KEY_COLUMNS}, \
                    MAX(finding_severity_rank(sf.severity)) AS severity_rank \
             FROM scan_findings sf JOIN artifacts a ON a.id = sf.artifact_id \
             WHERE sf.artifact_id = $1 \
               AND sf.cve_id IS NOT NULL \
               AND UPPER(BTRIM(sf.cve_id)) = UPPER(BTRIM($2)) \
               AND ($3 = false OR sf.scan_result_id IN \
                    (SELECT scan_result_id FROM artifact_current_scan_ids($1))) \
             GROUP BY 1, 2, 3, 4, 5, 6"
        );
        for current_only in [true, false] {
            let keys: Vec<FindingKey> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(artifact_id)
                .bind(cve_id)
                .bind(current_only)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            if !keys.is_empty() {
                return Ok(keys);
            }
        }
        Ok(Vec::new())
    }

    /// Write one decision per key, atomically, then apply what follows from it.
    async fn decide(
        &self,
        keys: &[FindingKey],
        actor: Option<Uuid>,
        reason: Option<&str>,
        options: AcknowledgeOptions,
    ) -> Result<Vec<FindingAcknowledgement>> {
        validate_expiry(options.expires_at, Utc::now())?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let mut decisions = Vec::with_capacity(keys.len());
        for key in keys {
            decisions.push(Self::decide_one(&mut tx, key, actor, reason, options).await?);
        }
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        for decision in &decisions {
            let mut entry =
                AuditEntry::new(AuditAction::FindingAcknowledged, ResourceType::ScanResult)
                    .resource(decision.id)
                    .details(decision_audit_details(decision));
            if let Some(actor) = actor {
                entry = entry.user(actor);
            }
            audit_fire_and_forget(self.db.clone(), entry).await;
        }
        for decision in &decisions {
            self.apply_change(&decision.checksum_sha256, decision.repository_id)
                .await;
            self.release_cleared_holds(&decision.checksum_sha256, decision.repository_id, actor)
                .await;
        }
        Ok(decisions)
    }

    async fn decide_one(
        tx: &mut Transaction<'_, Postgres>,
        key: &FindingKey,
        actor: Option<Uuid>,
        reason: Option<&str>,
        options: AcknowledgeOptions,
    ) -> Result<FindingAcknowledgement> {
        let repository_id = match options.scope {
            AcknowledgementScope::Repository => Some(key.repository_id),
            AcknowledgementScope::AllRepositories => None,
        };
        // Serialize decisions on one identity, so the supersede below cannot
        // race another acknowledgement into the live-decision unique index.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5153))")
            .bind(format!(
                "{:?}|{}|{}|{}|{}|{}",
                repository_id,
                key.checksum_sha256,
                key.finding_class,
                key.advisory_key,
                key.component_key,
                key.component_version_key
            ))
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // A new decision on a live identity replaces it and joins its lineage,
        // so a later revoke still reaches what the old one was carried to.
        let previous: Option<(Uuid, i16, bool)> = sqlx::query_as(
            "UPDATE finding_acknowledgements fa \
             SET revoked_at = NOW(), revoked_by = $7, revoked_reason = 'superseded' \
             FROM (SELECT id, (expires_at IS NULL OR expires_at > NOW()) AS live \
                   FROM finding_acknowledgements \
                   WHERE repository_id IS NOT DISTINCT FROM $1 \
                     AND checksum_sha256 = $2 AND finding_class = $3 \
                     AND advisory_key = $4 AND component_key = $5 \
                     AND component_version_key = $6 AND revoked_at IS NULL) old \
             WHERE fa.id = old.id \
             RETURNING fa.lineage_id, fa.max_severity_rank, old.live",
        )
        .bind(repository_id)
        .bind(&key.checksum_sha256)
        .bind(&key.finding_class)
        .bind(&key.advisory_key)
        .bind(&key.component_key)
        .bind(&key.component_version_key)
        .bind(actor)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let id = Uuid::new_v4();
        let lineage_id = previous.as_ref().map_or(id, |(lineage, _, _)| *lineage);
        let previous_live = previous
            .as_ref()
            .filter(|(_, _, live)| *live)
            .map(|(_, rank, _)| *rank);
        let sql = format!(
            "INSERT INTO finding_acknowledgements (\
                 id, lineage_id, repository_id, checksum_sha256, finding_class, advisory_key, \
                 component_key, component_version_key, max_severity_rank, reason, \
                 acknowledged_by, expires_at, created_via) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'api') \
             RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
        );
        sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(id)
            .bind(lineage_id)
            .bind(repository_id)
            .bind(&key.checksum_sha256)
            .bind(&key.finding_class)
            .bind(&key.advisory_key)
            .bind(&key.component_key)
            .bind(&key.component_version_key)
            .bind(ceiling_after_supersede(key.severity_rank, previous_live))
            .bind(reason)
            .bind(actor)
            .bind(options.expires_at)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Revoke
    // -----------------------------------------------------------------------

    /// Revoke every decision covering this finding's identity in its repository,
    /// and each of their lineages. Returns the number of decisions revoked;
    /// revoking a finding with no decision is a no-op. `NotFound` when the
    /// finding does not exist.
    pub async fn revoke_finding(&self, finding_id: Uuid, actor: Option<Uuid>) -> Result<usize> {
        let key = self
            .finding_key(finding_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;
        let lineages: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT lineage_id FROM finding_acknowledgements \
             WHERE revoked_at IS NULL \
               AND (repository_id = $1 OR repository_id IS NULL) \
               AND checksum_sha256 = $2 AND finding_class = $3 AND advisory_key = $4 \
               AND component_key = $5 AND component_version_key = $6",
        )
        .bind(key.repository_id)
        .bind(&key.checksum_sha256)
        .bind(&key.finding_class)
        .bind(&key.advisory_key)
        .bind(&key.component_key)
        .bind(&key.component_version_key)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        self.revoke_lineages(&lineages, actor).await
    }

    /// Revoke every decision on one advisory of one artifact's bytes in its
    /// repository, on any component (the Security tab's by-CVE action).
    /// Returns `None` when the artifact has no finding with that advisory.
    pub async fn revoke_advisory(
        &self,
        artifact_id: Uuid,
        cve_id: &str,
        actor: Option<Uuid>,
    ) -> Result<Option<usize>> {
        let keys = self.advisory_keys(artifact_id, cve_id).await?;
        let Some(key) = keys.first() else {
            return Ok(None);
        };
        let lineages: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT lineage_id FROM finding_acknowledgements \
             WHERE revoked_at IS NULL \
               AND (repository_id = $1 OR repository_id IS NULL) \
               AND checksum_sha256 = $2 AND advisory_key = $3",
        )
        .bind(key.repository_id)
        .bind(&key.checksum_sha256)
        .bind(&key.advisory_key)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(Some(self.revoke_lineages(&lineages, actor).await?))
    }

    /// Revoke one decision by id, and its lineage. For a decision with no finding
    /// row to reach it through. `NotFound` when the decision does not exist.
    pub async fn revoke(&self, id: Uuid, actor: Option<Uuid>) -> Result<usize> {
        let lineage: Option<Uuid> =
            sqlx::query_scalar("SELECT lineage_id FROM finding_acknowledgements WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let lineage =
            lineage.ok_or_else(|| AppError::NotFound("Acknowledgement not found".into()))?;
        self.revoke_lineages(&[lineage], actor).await
    }

    async fn revoke_lineages(&self, lineages: &[Uuid], actor: Option<Uuid>) -> Result<usize> {
        if lineages.is_empty() {
            return Ok(0);
        }
        let sql = format!(
            "UPDATE finding_acknowledgements \
             SET revoked_at = NOW(), revoked_by = $2, revoked_reason = 'revoked' \
             WHERE lineage_id = ANY($1) AND revoked_at IS NULL \
             RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
        );
        let revoked: Vec<FindingAcknowledgement> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(lineages)
            .bind(actor)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        for decision in &revoked {
            let mut entry = AuditEntry::new(
                AuditAction::FindingAcknowledgementRevoked,
                ResourceType::ScanResult,
            )
            .resource(decision.id)
            .details(decision_audit_details(decision));
            if let Some(actor) = actor {
                entry = entry.user(actor);
            }
            audit_fire_and_forget(self.db.clone(), entry).await;
            // No hold is written back: the policy half of the download gate
            // reads the decisions live, so the artifact is refused from here on.
            self.apply_change(&decision.checksum_sha256, decision.repository_id)
                .await;
        }
        Ok(revoked.len())
    }

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    /// List decisions, newest first. `total` counts the filtered set.
    pub async fn list(
        &self,
        filter: AcknowledgementFilter<'_>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<FindingAcknowledgement>, i64)> {
        const WHERE: &str =
            "WHERE ($1::uuid IS NULL OR repository_id = $1 OR repository_id IS NULL) \
               AND ($2::text IS NULL OR checksum_sha256 = $2) \
               AND ($3::text IS NULL OR advisory_key = UPPER(BTRIM($3)) OR advisory_key = $3) \
               AND ($4 OR (revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())))";
        let list_sql = format!(
            "SELECT {ACKNOWLEDGEMENT_COLUMNS} FROM finding_acknowledgements {WHERE} \
             ORDER BY acknowledged_at DESC, id LIMIT $5 OFFSET $6"
        );
        let rows: Vec<FindingAcknowledgement> = sqlx::query_as(sqlx::AssertSqlSafe(list_sql))
            .bind(filter.repository_id)
            .bind(filter.checksum_sha256)
            .bind(filter.advisory)
            .bind(filter.include_inactive)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let count_sql = format!("SELECT COUNT(*) FROM finding_acknowledgements {WHERE}");
        let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(count_sql))
            .bind(filter.repository_id)
            .bind(filter.checksum_sha256)
            .bind(filter.advisory)
            .bind(filter.include_inactive)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok((rows, total))
    }

    // -----------------------------------------------------------------------
    // Promotion
    // -----------------------------------------------------------------------

    /// Carry a promoted artifact's scan state into the target repository.
    ///
    /// The copy is a new artifact with no scan rows, which a target policy would
    /// treat as never scanned, and its findings would be new rows. The promotion
    /// is an explicit act on these exact bytes, so:
    ///
    /// * each decision live in the source repository for these bytes is copied
    ///   into the target, unchanged (actor, reason, expiry, severity ceiling) and
    ///   in the same lineage, so a revoke on either side reaches both;
    /// * the latest completed scan of each scan type is copied with its
    ///   provenance, exactly as a dedup copy of those bytes would be. The findings
    ///   are then graded by the TARGET repository's own policy.
    ///
    /// A scan type whose latest row is not `completed` is not carried. A decision
    /// live on the target already stays as it is. Nothing here can make the
    /// target more permissive than a dedup scan plus the source's decisions.
    pub async fn carry_to_promoted_artifact(
        &self,
        source_artifact_id: Uuid,
        new_artifact_id: Uuid,
        promoted_by: Uuid,
    ) -> Result<()> {
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT id, repository_id, checksum_sha256::text FROM artifacts WHERE id = ANY($1)",
        )
        .bind(vec![source_artifact_id, new_artifact_id])
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let find = |id: Uuid| rows.iter().find(|(row_id, _, _)| *row_id == id);
        let (Some((_, source_repo, source_digest)), Some((_, target_repo, target_digest))) =
            (find(source_artifact_id), find(new_artifact_id))
        else {
            return Err(AppError::NotFound(
                "Promoted artifact not found".to_string(),
            ));
        };
        if source_digest != target_digest {
            return Err(AppError::Internal(
                "a promoted copy must hold the bytes of its source".to_string(),
            ));
        }

        let sql = format!(
            "INSERT INTO finding_acknowledgements (\
                 lineage_id, repository_id, checksum_sha256, finding_class, advisory_key, \
                 component_key, component_version_key, max_severity_rank, reason, \
                 acknowledged_by, acknowledged_at, expires_at, created_via, carried_by) \
             SELECT lineage_id, $2, checksum_sha256, finding_class, advisory_key, \
                    component_key, component_version_key, max_severity_rank, reason, \
                    acknowledged_by, acknowledged_at, expires_at, 'promotion', $4 \
             FROM finding_acknowledgements \
             WHERE repository_id = $1 AND checksum_sha256 = $3 AND revoked_at IS NULL \
               AND (expires_at IS NULL OR expires_at > NOW()) \
             ON CONFLICT (\
                 COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid), \
                 checksum_sha256, finding_class, md5(advisory_key), md5(component_key), \
                 md5(component_version_key)) WHERE revoked_at IS NULL \
             DO NOTHING \
             RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
        );
        let carried: Vec<FindingAcknowledgement> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(source_repo)
            .bind(target_repo)
            .bind(source_digest)
            .bind(promoted_by)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        for decision in &carried {
            let entry = AuditEntry::new(
                AuditAction::FindingAcknowledgementCarried,
                ResourceType::ScanResult,
            )
            .user(promoted_by)
            .resource(decision.id)
            .details(serde_json::json!({
                "acknowledgement": decision_audit_details(decision),
                "source_repository_id": source_repo,
                "source_artifact_id": source_artifact_id,
                "artifact_id": new_artifact_id,
            }));
            audit_fire_and_forget(self.db.clone(), entry).await;
        }

        let latest: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
            "SELECT id, scan_type, pin_identity FROM ( \
                 SELECT DISTINCT ON (scan_type) id, scan_type, pin_identity, status \
                 FROM scan_results WHERE artifact_id = $1 \
                 ORDER BY scan_type, completed_at DESC NULLS LAST, created_at DESC \
             ) latest WHERE status = 'completed'",
        )
        .bind(source_artifact_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let scans = ScanResultService::new(self.db.clone());
        for (scan_id, scan_type, pin_identity) in &latest {
            scans
                .copy_scan_results(
                    *scan_id,
                    new_artifact_id,
                    *target_repo,
                    scan_type,
                    target_digest,
                    pin_identity.as_deref(),
                )
                .await?;
        }

        self.apply_change(target_digest, Some(*target_repo)).await;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Expiry
    // -----------------------------------------------------------------------

    /// Record lapsed decisions: one audit row each, and the stored scores of the
    /// repositories they applied in. Every gate and listing already reads the
    /// decision's `expires_at` itself, so a missed tick costs only freshness.
    /// A lapse is claimed by one UPDATE, so several replicas record it once.
    /// Returns the number recorded.
    pub async fn record_expired(&self) -> Result<u64> {
        let sql = format!(
            "UPDATE finding_acknowledgements SET expiry_recorded_at = NOW() \
             WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= NOW() \
               AND expiry_recorded_at IS NULL \
             RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
        );
        let lapsed: Vec<FindingAcknowledgement> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let mut applied: HashSet<(String, Option<Uuid>)> = HashSet::new();
        for decision in &lapsed {
            let entry = AuditEntry::new(
                AuditAction::FindingAcknowledgementExpired,
                ResourceType::ScanResult,
            )
            .resource(decision.id)
            .details(decision_audit_details(decision))
            .system_actor("finding-acknowledgement-expiry");
            audit_fire_and_forget(self.db.clone(), entry).await;
            if applied.insert((decision.checksum_sha256.clone(), decision.repository_id)) {
                self.apply_change(&decision.checksum_sha256, decision.repository_id)
                    .await;
            }
        }
        Ok(lapsed.len() as u64)
    }

    // -----------------------------------------------------------------------
    // What follows from a decision
    // -----------------------------------------------------------------------

    /// Refresh what is derived from decisions: the stored score of each repository
    /// holding these bytes in scope, and the cached listing decisions. Best-effort,
    /// because the decision is committed either way; the next scan repairs a score.
    async fn apply_change(&self, checksum_sha256: &str, repository_id: Option<Uuid>) {
        quarantine_service::invalidate_listing_decisions();
        let repositories: Vec<Uuid> = match sqlx::query_scalar(
            "SELECT DISTINCT repository_id FROM artifacts \
             WHERE checksum_sha256 = $1 AND NOT is_deleted \
               AND ($2::uuid IS NULL OR repository_id = $2)",
        )
        .bind(checksum_sha256)
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        {
            Ok(repositories) => repositories,
            Err(e) => {
                tracing::warn!(error = %e, "acknowledgement: affected repository lookup failed");
                return;
            }
        };
        let scans = ScanResultService::new(self.db.clone());
        for repository_id in repositories {
            if let Err(e) = scans.recalculate_score(repository_id).await {
                tracing::warn!(%repository_id, error = %e, "security score refresh failed");
            }
        }
    }

    /// Release the scan-policy holds that the new decision cleared.
    ///
    /// A scan-policy hold (`quarantine_source = 'scan_policy'`, written by the
    /// scanner when a policy refused the artifact) exists only because of the
    /// policy, so once the policy allows the artifact it has no reason left. Before
    /// this, the policy passed and the stamp remained: the download answered 409
    /// until an administrator released it by hand.
    ///
    /// Only that source is released: see
    /// [`quarantine_service::release_cleared_scan_policy_hold`].
    async fn release_cleared_holds(
        &self,
        checksum_sha256: &str,
        repository_id: Option<Uuid>,
        actor: Option<Uuid>,
    ) {
        let held: Vec<(Uuid, Uuid)> = match sqlx::query_as(
            "SELECT id, repository_id FROM artifacts \
             WHERE checksum_sha256 = $1 AND NOT is_deleted \
               AND ($2::uuid IS NULL OR repository_id = $2) \
               AND quarantine_status = 'quarantined' AND quarantine_until IS NULL \
               AND quarantine_source = 'scan_policy'",
        )
        .bind(checksum_sha256)
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        {
            Ok(held) => held,
            Err(e) => {
                tracing::warn!(error = %e, "acknowledgement: held artifact lookup failed");
                return;
            }
        };
        let policies = PolicyService::new(self.db.clone());
        for (artifact_id, repository_id) in held {
            let cleared = match policies.evaluate_artifact(artifact_id, repository_id).await {
                Ok(result) => result.allowed,
                Err(e) => {
                    tracing::warn!(%artifact_id, error = %e, "acknowledgement: policy evaluation failed; hold kept");
                    false
                }
            };
            if !cleared {
                continue;
            }
            if let Err(e) = quarantine_service::release_cleared_scan_policy_hold(
                &self.db,
                artifact_id,
                actor,
                "finding_acknowledgement",
            )
            .await
            {
                tracing::warn!(%artifact_id, error = %e, "acknowledgement: hold release failed");
            }
        }
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn expiry_must_be_in_the_future() {
        let now = Utc::now();
        assert!(validate_expiry(None, now).is_ok());
        assert!(validate_expiry(Some(now + Duration::seconds(1)), now).is_ok());
        assert!(matches!(
            validate_expiry(Some(now), now),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            validate_expiry(Some(now - Duration::days(1)), now),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn superseding_never_lowers_a_live_ceiling_and_an_expired_one_counts_for_nothing() {
        assert_eq!(ceiling_after_supersede(3, None), 3);
        assert_eq!(ceiling_after_supersede(3, Some(4)), 4);
        assert_eq!(ceiling_after_supersede(4, Some(3)), 4);
    }

    #[test]
    fn audit_details_name_the_decision() {
        let now = Utc::now();
        let d = FindingAcknowledgement {
            id: Uuid::nil(),
            lineage_id: Uuid::nil(),
            repository_id: None,
            checksum_sha256: "abc".to_string(),
            finding_class: "vulnerability".to_string(),
            advisory_key: "CVE-1".to_string(),
            component_key: "lodash".to_string(),
            component_version_key: "4".to_string(),
            max_severity_rank: 3,
            reason: Some("accepted".to_string()),
            acknowledged_by: None,
            acknowledged_at: now,
            expires_at: None,
            created_via: "api".to_string(),
            carried_by: None,
            revoked_at: None,
            revoked_by: None,
            revoked_reason: None,
            state: "active".to_string(),
        };
        let json = decision_audit_details(&d);
        assert_eq!(json["advisory"], "CVE-1");
        assert_eq!(json["component"], "lodash");
        assert_eq!(json["reason"], "accepted");
        assert!(json["repository_id"].is_null());
    }
}
