//! Acknowledgement decisions (#5153).
//!
//! Acknowledging a finding is how an administrator accepts a known risk so the
//! scan policy stops blocking it. That decision is about an advisory in a
//! component of specific bytes, so it cannot live on a `scan_findings` row:
//! a rescan, a dedup copy or a promotion writes new rows for the same facts.
//!
//! A decision is one row of `finding_acknowledgements`, keyed on
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
//!
//! Every decision and revoke goes through one authority check here, so the REST
//! routes, the by-CVE route and anything added later ask the same question: see
//! [`FindingAcknowledgementService::authorize_repository`].

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::access_scope::AccessScope;
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, AuditService, ResourceType,
};
use crate::services::policy_service::PolicyService;
use crate::services::quarantine_service;
use crate::services::scan_result_service::{ScanResultService, FIND_CARRYABLE_SCAN_SQL};
use crate::services::scan_state::ScanStateRow;
use crate::services::scanner_service::{
    hosted_upload_pin, DEDUP_TTL_DAYS, ZERO_FINDINGS_DEDUP_TTL_DAYS,
};

/// Where a decision applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AcknowledgementScope {
    /// One repository: see [`AcknowledgeOptions::repository_id`].
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
    /// The repository a repository-scoped decision applies in. It must hold
    /// these bytes. `None`: the finding's own repository, which is refused when
    /// the finding's scan has copies in other repositories, because the scan
    /// listing reports a copy under its source's id and the caller may be looking
    /// at any of them.
    pub repository_id: Option<Uuid>,
}

/// Who is making or undoing a decision.
#[derive(Debug, Clone)]
pub struct AckActor {
    /// `None` only for [`Self::system`].
    pub user_id: Option<Uuid>,
    /// The repositories the credential covers.
    pub credential: AccessScope,
}

impl AckActor {
    pub fn new(user_id: Uuid, credential: AccessScope) -> Self {
        Self {
            user_id: Some(user_id),
            credential,
        }
    }

    /// A caller with no user to name, authorized outside this service. No request
    /// path uses this: REST and gRPC both name their user.
    pub fn system() -> Self {
        Self {
            user_id: None,
            credential: AccessScope::Admin,
        }
    }
}

/// Who is promoting, for what a promotion may carry.
#[derive(Debug, Clone, Copy)]
pub struct CarryPrincipal {
    pub user_id: Uuid,
    /// Whether this principal could itself acknowledge in the target.
    pub may_acknowledge: bool,
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

/// `checksum_sha256` is `CHAR(64)` and sqlx binds a `&str` as `text`, so without
/// the cast Postgres compares `checksum_sha256::text = $1` and cannot use the
/// index on the column (#4426). `artifacts` is the table that matters: this runs
/// on every decision, against every artifact.
const AFFECTED_REPOSITORIES_SQL: &str = "SELECT DISTINCT repository_id FROM artifacts \
     WHERE checksum_sha256 = $1::bpchar AND NOT is_deleted \
       AND ($2::uuid IS NULL OR repository_id = $2)";

const HELD_ARTIFACTS_SQL: &str = "SELECT id, repository_id FROM artifacts \
     WHERE checksum_sha256 = $1::bpchar AND NOT is_deleted \
       AND ($2::uuid IS NULL OR repository_id = $2) \
       AND quarantine_status = 'quarantined' AND quarantine_until IS NULL \
       AND quarantine_source = 'scan_policy'";

/// Live every-repository decisions on the same identity as this repository-scoped
/// decision, outside its lineage.
const OTHER_EVERY_REPOSITORY_DECISIONS_SQL: &str = "SELECT COUNT(*) \
     FROM finding_acknowledgements this \
     JOIN finding_acknowledgements other \
       ON other.checksum_sha256 = this.checksum_sha256 \
      AND other.finding_class = this.finding_class \
      AND other.advisory_key = this.advisory_key \
      AND other.component_key = this.component_key \
      AND other.component_version_key = this.component_version_key \
      AND other.lineage_id <> this.lineage_id \
     WHERE this.id = $1 AND this.repository_id IS NOT NULL \
       AND other.repository_id IS NULL AND other.revoked_at IS NULL \
       AND (other.expires_at IS NULL OR other.expires_at > NOW())";

/// Whether the scan a finding belongs to has a copy in this repository.
const COPY_IN_REPOSITORY_SQL: &str = "SELECT EXISTS (SELECT 1 FROM scan_findings sf \
     JOIN scan_results copy ON copy.source_scan_id = sf.scan_result_id \
     WHERE sf.id = $1 AND copy.repository_id = $2)";

const REPOSITORY_HOLDS_BYTES_SQL: &str = "SELECT EXISTS (SELECT 1 FROM artifacts \
     WHERE repository_id = $1 AND checksum_sha256 = $2::bpchar AND NOT is_deleted)";

/// Clears the frozen `scan_findings` flag of the rows a decision covered. A 1.11
/// replica still running during a rolling upgrade reads that flag, so without this
/// a revoked or lapsed decision that was migrated from a flag would read as
/// acknowledged again there.
const CLEAR_FROZEN_FLAG_SQL: &str = "UPDATE scan_findings sf \
     SET is_acknowledged = false, acknowledged_by = NULL, \
         acknowledged_reason = NULL, acknowledged_at = NULL \
     FROM artifacts a \
     WHERE a.id = sf.artifact_id AND sf.is_acknowledged \
       AND a.checksum_sha256 = $1::bpchar \
       AND ($2::uuid IS NULL OR a.repository_id = $2) \
       AND sf.finding_class = $3 \
       AND finding_advisory_key(sf.cve_id, sf.title) = $4 \
       AND finding_component_key(sf.affected_component) = $5 \
       AND finding_component_key(sf.affected_version) = $6";

/// The one answer for a finding that does not exist and one the caller cannot
/// reach, so the first request cannot be used to tell them apart.
fn not_found() -> AppError {
    AppError::NotFound("Finding not found".to_string())
}

/// What a revoke did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RevokeOutcome {
    pub revoked: usize,
    /// Decisions still in force on this finding that the revoke did not undo: copies
    /// in repositories the caller has no authority over and, for a revoke by id, a
    /// separate decision for every repository. Lapsed decisions are not counted.
    pub left_effective: i64,
}

/// What a promotion carried.
#[derive(Debug, Clone, Default)]
pub struct CarryOutcome {
    pub verdict_carried: bool,
    /// Why not, when it was not.
    pub verdict_not_carried_reason: Option<String>,
    pub acknowledgements_carried: usize,
    pub acknowledgements_left_behind: usize,
}

/// The decision covering a finding in one repository, for answering about that
/// repository when the row asked through belongs to another.
#[derive(Debug, Clone, FromRow)]
pub struct DecisionInRepository {
    pub id: Uuid,
    pub acknowledged_by: Option<Uuid>,
    pub reason: Option<String>,
    pub acknowledged_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_severity_rank: i16,
}

/// The severity name of a `finding_severity_rank`.
pub(crate) fn severity_for_rank(rank: i16) -> &'static str {
    match rank {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "info",
    }
}

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
        "max_severity": severity_for_rank(d.max_severity_rank),
        "reason": d.reason,
        "expires_at": d.expires_at,
        "created_via": d.created_via,
        "revoked_reason": d.revoked_reason,
    })
}

/// An audit entry about a decision, naming who acted or that nobody did.
fn decision_audit_entry(
    action: AuditAction,
    decision: &FindingAcknowledgement,
    actor: Option<Uuid>,
) -> AuditEntry {
    let entry = AuditEntry::new(action, ResourceType::ScanResult)
        .resource(decision.id)
        .details(decision_audit_details(decision));
    match actor {
        Some(actor) => entry.user(actor),
        None => entry.system_actor("finding-acknowledgement"),
    }
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

/// One row of the scans the source's gate grades, as a promotion judges it.
#[derive(Debug, Clone, FromRow)]
struct GradedScan {
    id: Uuid,
    scan_type: String,
    status: String,
    error_message: Option<String>,
    pin_identity: Option<String>,
}

/// Which rows a promoted copy may take, or why it takes none.
///
/// The target must grade what the source grades, so this is all or nothing. Every
/// row the source's gate reads (`artifact_current_scan_ids`) must be one a dedup
/// could reuse as a complete verdict. One that is not (a later crashed, running,
/// partial or `not_cataloged` row, a verdict past its age limit or from another
/// pin, an external vendor's submission) means the copied set would say less than
/// the source does, and a target that sees any completed row treats the artifact
/// as scanned. A row saying the scanner does not apply to this format says nothing
/// about the artifact, and is not copied.
fn carry_plan(graded: &[(GradedScan, bool)]) -> std::result::Result<Vec<&GradedScan>, String> {
    let mut plan: Vec<&GradedScan> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for (scan, reusable) in graded {
        let state = ScanStateRow {
            status: scan.status.clone(),
            error_message: scan.error_message.clone(),
        };
        if state.is_not_applicable() {
            continue;
        }
        if scan.scan_type == "external" {
            return Err("an external scanner's submission is on record".to_string());
        }
        if !reusable {
            return Err(format!(
                "the {} scan {} is not a complete verdict a dedup could reuse: it is \
                 incomplete, or past its age limit (1 day for a clean verdict, 30 for one \
                 with findings), or under another pin, or followed by a scan that did not \
                 finish",
                scan.scan_type, scan.id
            ));
        }
        if !seen.insert(scan.scan_type.as_str()) {
            return Err(format!("more than one current {} scan", scan.scan_type));
        }
        plan.push(scan);
    }
    if plan.is_empty() {
        return Err("no completed scan to carry".to_string());
    }
    Ok(plan)
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
    // Authority
    // -----------------------------------------------------------------------

    /// Every caller of this service has already established the admin capability:
    /// the REST routes with `require_admin`, where `is_admin` is gated on an
    /// `admin`-granting scope; the by-CVE route with `enforce_admin_audited`; the gRPC
    /// method with an `admin`-granting scope; promotion before it asks. What is decided
    /// here is how far the credential reaches: an unrestricted credential reaches every
    /// repository, and a restricted one only those it lists. The repository roles the
    /// user holds play no part.
    fn may_act_in(actor: &AckActor, repository_id: Uuid) -> bool {
        actor.credential.grants(repository_id)
    }

    fn may_act_everywhere(actor: &AckActor) -> bool {
        matches!(actor.credential, AccessScope::Admin)
    }

    /// Whether `actor` may decide for one repository. A credential that does not
    /// cover it is told it does not exist (404), like every other route.
    pub async fn authorize_repository(&self, actor: &AckActor, repository_id: Uuid) -> Result<()> {
        if Self::may_act_in(actor, repository_id) {
            Ok(())
        } else {
            Err(not_found())
        }
    }

    /// Whether `actor` may make or undo a decision for every repository: an
    /// unrestricted credential.
    pub async fn authorize_every_repository(&self, actor: &AckActor) -> Result<()> {
        if Self::may_act_everywhere(actor) {
            Ok(())
        } else {
            Err(AppError::Authorization(
                "Deciding for every repository needs an unrestricted credential".to_string(),
            ))
        }
    }

    /// Split what a revoke would undo into what `actor` may undo and how much it
    /// may not.
    ///
    /// A caller withdrawing a risk in their own repository is not stopped by a copy
    /// a promotion made somewhere they have no authority: the copy stays, and the
    /// answer says so (`acknowledgements_left_effective`), so nobody believes it is
    /// gone. The exception is a decision that also applies where the caller is
    /// asking (`applies_in_request`): an every-repository decision the caller cannot
    /// undo would leave the finding acknowledged in their own repository, which is
    /// the thing they asked to end, so that is refused rather than half-done.
    async fn partition_reach(
        &self,
        actor: &AckActor,
        lineages: &[Uuid],
        applies_in_request: &[Uuid],
    ) -> Result<(Vec<Uuid>, i64)> {
        #[derive(FromRow)]
        struct Reach {
            id: Uuid,
            repository_id: Option<Uuid>,
            live: bool,
        }
        let reach: Vec<Reach> = sqlx::query_as(
            "SELECT id, repository_id, (expires_at IS NULL OR expires_at > NOW()) AS live \
             FROM finding_acknowledgements \
             WHERE lineage_id = ANY($1) AND revoked_at IS NULL",
        )
        .bind(lineages)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let mut allowed = Vec::with_capacity(reach.len());
        let mut left_effective = 0;
        for row in reach {
            let may = match row.repository_id {
                Some(repository_id) => Self::may_act_in(actor, repository_id),
                None => Self::may_act_everywhere(actor),
            };
            if may {
                allowed.push(row.id);
            } else if !row.live {
                // Lapsed: it covers nothing, wherever it is, so nothing is left in
                // force and there is nothing to refuse over.
            } else if applies_in_request.contains(&row.id) {
                return Err(AppError::Authorization(
                    "This finding is covered by a decision for every repository, which this \
                     credential cannot revoke, so it would stay acknowledged here. Ask an \
                     administrator with an unrestricted credential to revoke it"
                        .to_string(),
                ));
            } else {
                left_effective += 1;
            }
        }
        Ok((allowed, left_effective))
    }

    // -----------------------------------------------------------------------
    // Decide
    // -----------------------------------------------------------------------

    /// Record a decision from one finding row: its identity, at its severity.
    /// Returns the decision. `NotFound` when the finding does not exist or the
    /// credential does not cover its repository.
    pub async fn acknowledge_finding(
        &self,
        finding_id: Uuid,
        actor: &AckActor,
        reason: Option<&str>,
        options: AcknowledgeOptions,
    ) -> Result<FindingAcknowledgement> {
        let mut key = self.finding_key(finding_id).await?.ok_or_else(not_found)?;
        match options.scope {
            AcknowledgementScope::AllRepositories => {
                self.authorize_repository(actor, key.repository_id).await?;
                self.authorize_every_repository(actor).await?;
            }
            AcknowledgementScope::Repository => {
                key.repository_id = self
                    .request_repository(finding_id, &key, actor, options.repository_id)
                    .await?;
            }
        }
        let mut decisions = self
            .decide(std::slice::from_ref(&key), actor, reason, options)
            .await?;
        decisions
            .pop()
            .ok_or_else(|| AppError::Internal("acknowledgement was not recorded".to_string()))
    }

    /// The repository a request about this finding row means.
    ///
    /// `ScanResponse.id` reports a reused row under its source's id, so a caller
    /// looking at one repository is handed the rows of another. Acting on the row's
    /// repository would open or close a gate the caller was not looking at, so when
    /// the row's scan has copies elsewhere the caller has to say which one they mean.
    ///
    /// A named repository need not be the row's, which is the point, but the caller
    /// must be able to reach the row through it: it holds a copy of the row's scan,
    /// or the caller may act where the row is. Anything else answers as if the
    /// finding did not exist.
    async fn request_repository(
        &self,
        finding_id: Uuid,
        key: &FindingKey,
        actor: &AckActor,
        requested: Option<Uuid>,
    ) -> Result<Uuid> {
        let copy_in = |repository_id: Uuid| async move {
            sqlx::query_scalar::<_, bool>(COPY_IN_REPOSITORY_SQL)
                .bind(finding_id)
                .bind(repository_id)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))
        };
        if let Some(repository_id) = requested {
            if repository_id != key.repository_id
                && !copy_in(repository_id).await?
                && !Self::may_act_in(actor, key.repository_id)
            {
                return Err(not_found());
            }
            self.authorize_repository(actor, repository_id).await?;
            let holds: bool = sqlx::query_scalar(REPOSITORY_HOLDS_BYTES_SQL)
                .bind(repository_id)
                .bind(&key.checksum_sha256)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            if !holds {
                return Err(not_found());
            }
            return Ok(repository_id);
        }
        self.authorize_repository(actor, key.repository_id).await?;
        let copied_elsewhere: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM scan_findings sf \
             JOIN scan_results copy ON copy.source_scan_id = sf.scan_result_id \
             WHERE sf.id = $1 AND copy.repository_id <> $2)",
        )
        .bind(finding_id)
        .bind(key.repository_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if copied_elsewhere {
            return Err(AppError::Conflict(
                "This finding's scan has copies in other repositories; \
                 say which one is meant with repository_id"
                    .to_string(),
            ));
        }
        Ok(key.repository_id)
    }

    /// The decision covering this finding's identity in `repository_id`, if one is
    /// live, under the same rule the view applies.
    pub async fn decision_in_repository(
        &self,
        finding_id: Uuid,
        repository_id: Uuid,
    ) -> Result<Option<DecisionInRepository>> {
        let key = self.finding_key(finding_id).await?.ok_or_else(not_found)?;
        sqlx::query_as(
            "SELECT id, acknowledged_by, reason, acknowledged_at, expires_at, max_severity_rank \
             FROM finding_acknowledgements \
             WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) \
               AND (repository_id = $1 OR repository_id IS NULL) \
               AND checksum_sha256 = $2::bpchar AND finding_class = $3 AND advisory_key = $4 \
               AND component_key = $5 AND component_version_key = $6 \
             ORDER BY (repository_id IS NULL), acknowledged_at DESC LIMIT 1",
        )
        .bind(repository_id)
        .bind(&key.checksum_sha256)
        .bind(&key.finding_class)
        .bind(&key.advisory_key)
        .bind(&key.component_key)
        .bind(&key.component_version_key)
        .fetch_optional(&self.db)
        .await
        .map(|decision: Option<DecisionInRepository>| {
            decision.filter(|d| i32::from(d.max_severity_rank) >= key.severity_rank)
        })
        .map_err(|e| AppError::Database(e.to_string()))
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
        actor: &AckActor,
        reason: Option<&str>,
        options: AcknowledgeOptions,
    ) -> Result<usize> {
        let keys = self.advisory_keys(artifact_id, cve_id).await?;
        let Some(first) = keys.first() else {
            return Ok(0);
        };
        self.authorize_repository(actor, first.repository_id)
            .await?;
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
    /// The caller has authorized the keys' repository.
    async fn decide(
        &self,
        keys: &[FindingKey],
        actor: &AckActor,
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
        let mut superseded = Vec::new();
        for key in keys {
            let (decision, previous) =
                Self::decide_one(&mut tx, key, actor.user_id, reason, options).await?;
            decisions.push(decision);
            superseded.extend(previous);
        }
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        for previous in &superseded {
            audit_fire_and_forget(
                self.db.clone(),
                decision_audit_entry(
                    AuditAction::FindingAcknowledgementRevoked,
                    previous,
                    actor.user_id,
                ),
            )
            .await;
        }
        for decision in &decisions {
            audit_fire_and_forget(
                self.db.clone(),
                decision_audit_entry(AuditAction::FindingAcknowledged, decision, actor.user_id),
            )
            .await;
        }
        for decision in &decisions {
            self.apply_change(&decision.checksum_sha256, decision.repository_id)
                .await;
            self.release_cleared_holds(
                &decision.checksum_sha256,
                decision.repository_id,
                actor.user_id,
            )
            .await;
        }
        Ok(decisions)
    }

    /// One decision, and the one it replaced if any.
    async fn decide_one(
        tx: &mut Transaction<'_, Postgres>,
        key: &FindingKey,
        actor: Option<Uuid>,
        reason: Option<&str>,
        options: AcknowledgeOptions,
    ) -> Result<(FindingAcknowledgement, Option<FindingAcknowledgement>)> {
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
        // so a later revoke still reaches what the old one was carried to. An
        // expired one is replaced too but accepts nothing any more.
        let previous_sql = format!(
            "SELECT {ACKNOWLEDGEMENT_COLUMNS} FROM finding_acknowledgements \
             WHERE repository_id IS NOT DISTINCT FROM $1 \
               AND checksum_sha256 = $2::bpchar AND finding_class = $3 \
               AND advisory_key = $4 AND component_key = $5 \
               AND component_version_key = $6 AND revoked_at IS NULL"
        );
        let previous: Option<FindingAcknowledgement> =
            sqlx::query_as(sqlx::AssertSqlSafe(previous_sql))
                .bind(repository_id)
                .bind(&key.checksum_sha256)
                .bind(&key.finding_class)
                .bind(&key.advisory_key)
                .bind(&key.component_key)
                .bind(&key.component_version_key)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let superseded = match previous {
            Some(old) => {
                let update_sql = format!(
                    "UPDATE finding_acknowledgements \
                     SET revoked_at = NOW(), revoked_by = $2, revoked_reason = 'superseded' \
                     WHERE id = $1 RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
                );
                let closed: FindingAcknowledgement =
                    sqlx::query_as(sqlx::AssertSqlSafe(update_sql))
                        .bind(old.id)
                        .bind(actor)
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;
                let was_live = old.state == "active";
                Some((closed, was_live))
            }
            None => None,
        };

        let id = Uuid::new_v4();
        let lineage_id = superseded.as_ref().map_or(id, |(old, _)| old.lineage_id);
        let previous_live = superseded
            .as_ref()
            .filter(|(_, live)| *live)
            .map(|(old, _)| old.max_severity_rank);
        let sql = format!(
            "INSERT INTO finding_acknowledgements (\
                 id, lineage_id, repository_id, checksum_sha256, finding_class, advisory_key, \
                 component_key, component_version_key, max_severity_rank, reason, \
                 acknowledged_by, expires_at, created_via) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'api') \
             RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
        );
        let decision = sqlx::query_as(sqlx::AssertSqlSafe(sql))
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
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok((decision, superseded.map(|(old, _)| old)))
    }

    // -----------------------------------------------------------------------
    // Revoke
    // -----------------------------------------------------------------------

    /// Revoke every decision covering this finding's identity in `repository_id`,
    /// and each of their lineages as far as the actor has authority: see
    /// [`Self::partition_reach`]. With no `repository_id`, the finding's own
    /// repository, which like an acknowledgement is refused when the finding's scan
    /// has copies elsewhere. Revoking a finding with no decision is a no-op.
    /// `NotFound` when the finding does not exist or the actor cannot reach it.
    pub async fn revoke_finding(
        &self,
        finding_id: Uuid,
        repository_id: Option<Uuid>,
        actor: &AckActor,
    ) -> Result<RevokeOutcome> {
        let key = self.finding_key(finding_id).await?.ok_or_else(not_found)?;
        let repository_id = self
            .request_repository(finding_id, &key, actor, repository_id)
            .await?;
        let covering: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, lineage_id FROM finding_acknowledgements \
             WHERE revoked_at IS NULL \
               AND (repository_id = $1 OR repository_id IS NULL) \
               AND checksum_sha256 = $2::bpchar AND finding_class = $3 AND advisory_key = $4 \
               AND component_key = $5 AND component_version_key = $6",
        )
        .bind(repository_id)
        .bind(&key.checksum_sha256)
        .bind(&key.finding_class)
        .bind(&key.advisory_key)
        .bind(&key.component_key)
        .bind(&key.component_version_key)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        self.revoke_covering(&covering, actor).await
    }

    /// Revoke every decision on one advisory of one artifact's bytes in its
    /// repository, on any component (the Security tab's by-CVE action).
    /// Returns `None` when the artifact has no finding with that advisory.
    pub async fn revoke_advisory(
        &self,
        artifact_id: Uuid,
        cve_id: &str,
        actor: &AckActor,
    ) -> Result<Option<RevokeOutcome>> {
        let keys = self.advisory_keys(artifact_id, cve_id).await?;
        let Some(key) = keys.first() else {
            return Ok(None);
        };
        self.authorize_repository(actor, key.repository_id).await?;
        let covering: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, lineage_id FROM finding_acknowledgements \
             WHERE revoked_at IS NULL \
               AND (repository_id = $1 OR repository_id IS NULL) \
               AND checksum_sha256 = $2::bpchar AND advisory_key = $3",
        )
        .bind(key.repository_id)
        .bind(&key.checksum_sha256)
        .bind(&key.advisory_key)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(Some(self.revoke_covering(&covering, actor).await?))
    }

    /// Revoke one decision by id, and its lineage as far as the actor has authority.
    /// For a decision with no finding row to reach it through. The decision named
    /// must itself be one the actor may undo. `NotFound` when it does not exist.
    pub async fn revoke(&self, id: Uuid, actor: &AckActor) -> Result<RevokeOutcome> {
        let lineage: Option<Uuid> =
            sqlx::query_scalar("SELECT lineage_id FROM finding_acknowledgements WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let lineage =
            lineage.ok_or_else(|| AppError::NotFound("Acknowledgement not found".into()))?;
        let (allowed, left_effective) = self.partition_reach(actor, &[lineage], &[]).await?;
        if !allowed.contains(&id) && left_effective > 0 {
            return Err(AppError::Authorization(
                "This decision applies in a repository this credential does not cover".to_string(),
            ));
        }
        // A separate decision for every repository still covers this finding where
        // the revoked one applied. A revoke by id does not reach it, so count it.
        let also_covering: i64 = sqlx::query_scalar(OTHER_EVERY_REPOSITORY_DECISIONS_SQL)
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        self.revoke_ids(&allowed, left_effective + also_covering, actor.user_id)
            .await
    }

    async fn revoke_covering(
        &self,
        covering: &[(Uuid, Uuid)],
        actor: &AckActor,
    ) -> Result<RevokeOutcome> {
        let (ids, lineages): (Vec<Uuid>, Vec<Uuid>) = covering.iter().copied().unzip();
        let (allowed, left_effective) = self.partition_reach(actor, &lineages, &ids).await?;
        self.revoke_ids(&allowed, left_effective, actor.user_id)
            .await
    }

    async fn revoke_ids(
        &self,
        ids: &[Uuid],
        left_effective: i64,
        actor: Option<Uuid>,
    ) -> Result<RevokeOutcome> {
        if ids.is_empty() {
            return Ok(RevokeOutcome {
                revoked: 0,
                left_effective,
            });
        }
        let sql = format!(
            "UPDATE finding_acknowledgements \
             SET revoked_at = NOW(), revoked_by = $2, revoked_reason = 'revoked' \
             WHERE id = ANY($1) AND revoked_at IS NULL \
             RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
        );
        let revoked: Vec<FindingAcknowledgement> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(ids)
            .bind(actor)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        for decision in &revoked {
            let mut details = decision_audit_details(decision);
            details["left_effective"] = serde_json::json!(left_effective);
            audit_fire_and_forget(
                self.db.clone(),
                decision_audit_entry(AuditAction::FindingAcknowledgementRevoked, decision, actor)
                    .details(details),
            )
            .await;
            self.clear_frozen_flag(decision).await;
            // No hold is written back: the policy half of the download gate
            // reads the decisions live, so the artifact is refused from here on.
            self.apply_change(&decision.checksum_sha256, decision.repository_id)
                .await;
        }
        Ok(RevokeOutcome {
            revoked: revoked.len(),
            left_effective,
        })
    }

    /// See [`CLEAR_FROZEN_FLAG_SQL`]. Best-effort: nothing in this version reads
    /// the flag, so a failure costs only the case it exists for.
    async fn clear_frozen_flag(&self, decision: &FindingAcknowledgement) {
        if let Err(e) = sqlx::query(CLEAR_FROZEN_FLAG_SQL)
            .bind(&decision.checksum_sha256)
            .bind(decision.repository_id)
            .bind(&decision.finding_class)
            .bind(&decision.advisory_key)
            .bind(&decision.component_key)
            .bind(&decision.component_version_key)
            .execute(&self.db)
            .await
        {
            tracing::warn!(acknowledgement = %decision.id, error = %e, "frozen acknowledgement flag not cleared");
        }
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
               AND ($2::text IS NULL OR checksum_sha256 = $2::bpchar) \
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

    /// Carry a promoted artifact's scan state into the target repository, in one
    /// transaction.
    ///
    /// The copy is a new artifact with no scan rows. Two things may follow it:
    ///
    /// * **The verdict**, only if the target would grade exactly what the source
    ///   grades: see [`carry_plan`]. Otherwise nothing is copied and the target
    ///   sees an unscanned artifact, as it did before verdicts travelled. A target
    ///   policy with `block_unscanned` refuses that; a target policy without it
    ///   serves it, which is what that policy asks for.
    /// * **The decisions** live in the source repository for these bytes, unchanged
    ///   (actor, reason, expiry, severity ceiling) and in the same lineage, so a
    ///   revoke on either side reaches both. Only when the principal could
    ///   acknowledge in the target: a `promote:artifacts` token cannot carry a
    ///   risk acceptance past a stricter target. What stays behind is audited, and
    ///   the finding is then open there. A decision live on the target stays, and one
    ///   that has lapsed there is replaced.
    ///
    /// A failure leaves the target with neither. A clean verdict inherits the 1-day
    /// limit dedup gives it, so one older than that is not carried: the answer says so.
    pub async fn carry_to_promoted_artifact(
        &self,
        source_artifact_id: Uuid,
        new_artifact_id: Uuid,
        principal: CarryPrincipal,
    ) -> Result<CarryOutcome> {
        #[derive(FromRow)]
        struct CopyRow {
            id: Uuid,
            repository_id: Uuid,
            checksum_sha256: String,
            path: String,
            name: String,
            version: Option<String>,
            format: String,
        }
        let rows: Vec<CopyRow> = sqlx::query_as(
            "SELECT a.id, a.repository_id, a.checksum_sha256::text AS checksum_sha256, \
                    a.path, a.name, a.version, r.format::text AS format \
             FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
             WHERE a.id = ANY($1)",
        )
        .bind(vec![source_artifact_id, new_artifact_id])
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let find = |id: Uuid| rows.iter().find(|row| row.id == id);
        let (Some(source), Some(target)) = (find(source_artifact_id), find(new_artifact_id)) else {
            return Err(AppError::NotFound(
                "Promoted artifact not found".to_string(),
            ));
        };
        if source.checksum_sha256 != target.checksum_sha256 {
            return Err(AppError::Internal(
                "a promoted copy must hold the bytes of its source".to_string(),
            ));
        }

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let mut superseded_in_target: Vec<FindingAcknowledgement> = Vec::new();
        let (carried, left_behind) = if principal.may_acknowledge {
            // A lapsed decision still holds its place in the live-decision index,
            // and decides nothing. A new decision replaces it, and so does this one.
            let close_sql = format!(
                "UPDATE finding_acknowledgements \
                 SET revoked_at = NOW(), revoked_by = $3, revoked_reason = 'superseded' \
                 WHERE id IN ( \
                     SELECT old.id FROM finding_acknowledgements old \
                     JOIN finding_acknowledgements incoming \
                       ON incoming.checksum_sha256 = old.checksum_sha256 \
                      AND incoming.finding_class = old.finding_class \
                      AND incoming.advisory_key = old.advisory_key \
                      AND incoming.component_key = old.component_key \
                      AND incoming.component_version_key = old.component_version_key \
                     WHERE old.repository_id = $2 AND old.revoked_at IS NULL \
                       AND old.expires_at IS NOT NULL AND old.expires_at <= NOW() \
                       AND incoming.repository_id = $1 AND incoming.revoked_at IS NULL \
                       AND (incoming.expires_at IS NULL OR incoming.expires_at > NOW()) \
                       AND incoming.checksum_sha256 = $4::bpchar \
                 ) \
                 RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
            );
            superseded_in_target = sqlx::query_as(sqlx::AssertSqlSafe(close_sql))
                .bind(source.repository_id)
                .bind(target.repository_id)
                .bind(principal.user_id)
                .bind(&source.checksum_sha256)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            let sql = format!(
                "INSERT INTO finding_acknowledgements (\
                     lineage_id, repository_id, checksum_sha256, finding_class, advisory_key, \
                     component_key, component_version_key, max_severity_rank, reason, \
                     acknowledged_by, acknowledged_at, expires_at, created_via, carried_by) \
                 SELECT lineage_id, $2, checksum_sha256, finding_class, advisory_key, \
                        component_key, component_version_key, max_severity_rank, reason, \
                        acknowledged_by, acknowledged_at, expires_at, 'promotion', $4 \
                 FROM finding_acknowledgements \
                 WHERE repository_id = $1 AND checksum_sha256 = $3::bpchar AND revoked_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > NOW()) \
                 ON CONFLICT (\
                     COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid), \
                     checksum_sha256, finding_class, md5(advisory_key), md5(component_key), \
                     md5(component_version_key)) WHERE revoked_at IS NULL \
                 DO NOTHING \
                 RETURNING {ACKNOWLEDGEMENT_COLUMNS}"
            );
            let carried: Vec<FindingAcknowledgement> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(source.repository_id)
                .bind(target.repository_id)
                .bind(&source.checksum_sha256)
                .bind(principal.user_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            (carried, Vec::new())
        } else {
            let sql = format!(
                "SELECT {ACKNOWLEDGEMENT_COLUMNS} FROM finding_acknowledgements \
                 WHERE repository_id = $1 AND checksum_sha256 = $2::bpchar AND revoked_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > NOW())"
            );
            let left_behind: Vec<FindingAcknowledgement> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(source.repository_id)
                .bind(&source.checksum_sha256)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            (Vec::new(), left_behind)
        };

        let graded: Vec<GradedScan> = sqlx::query_as(
            "SELECT sr.id, sr.scan_type, sr.status, sr.error_message, sr.pin_identity \
             FROM scan_results sr \
             WHERE sr.artifact_id = $1 \
               AND sr.id IN (SELECT scan_result_id FROM artifact_current_scan_ids($1)) \
             ORDER BY sr.scan_type, sr.created_at \
             FOR SHARE OF sr",
        )
        .bind(source_artifact_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // The pin the artifact's own bytes would be scanned under, computed the
        // way the scanner computes it, as the dedup lookup requires. A pinned
        // row's pin is the current request's in the scanner; here it is the
        // artifact's, which is the same coordinate on both sides of a promotion.
        let filename = source.path.rsplit('/').next().unwrap_or(&source.name);
        let pin = hosted_upload_pin(
            &target.format,
            filename,
            &source.name,
            source.version.as_deref(),
        )
        .map(|pin| pin.pin_identity());
        let mut judged = Vec::with_capacity(graded.len());
        for scan in graded {
            let reusable: bool = sqlx::query_scalar(FIND_CARRYABLE_SCAN_SQL)
                .bind(&source.checksum_sha256)
                .bind(&scan.scan_type)
                .bind(DEDUP_TTL_DAYS.to_string())
                .bind(ZERO_FINDINGS_DEDUP_TTL_DAYS.to_string())
                .bind(pin.as_deref())
                .bind(source_artifact_id)
                .bind(scan.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            judged.push((scan, reusable));
        }
        let mut verdict_not_carried_reason = None;
        match carry_plan(&judged) {
            Ok(plan) => {
                for scan in plan {
                    ScanResultService::copy_scan_results_in_tx(
                        &mut tx,
                        scan.id,
                        new_artifact_id,
                        target.repository_id,
                        &scan.scan_type,
                        &target.checksum_sha256,
                        scan.pin_identity.as_deref(),
                    )
                    .await?;
                }
            }
            Err(reason) => {
                tracing::info!(
                    source_artifact = %source_artifact_id,
                    new_artifact = %new_artifact_id,
                    %reason,
                    "Promoted copy takes no verdict: the target sees it as unscanned"
                );
                verdict_not_carried_reason = Some(reason);
            }
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let context = serde_json::json!({
            "source_repository_id": source.repository_id,
            "source_artifact_id": source_artifact_id,
            "artifact_id": new_artifact_id,
            "target_repository_id": target.repository_id,
        });
        for decision in &superseded_in_target {
            audit_fire_and_forget(
                self.db.clone(),
                decision_audit_entry(
                    AuditAction::FindingAcknowledgementRevoked,
                    decision,
                    Some(principal.user_id),
                ),
            )
            .await;
        }
        for (action, decisions) in [
            (AuditAction::FindingAcknowledgementCarried, &carried),
            (AuditAction::FindingAcknowledgementNotCarried, &left_behind),
        ] {
            for decision in decisions {
                let entry = AuditEntry::new(action, ResourceType::ScanResult)
                    .user(principal.user_id)
                    .resource(decision.id)
                    .details(serde_json::json!({
                        "acknowledgement": decision_audit_details(decision),
                        "promotion": context,
                    }));
                audit_fire_and_forget(self.db.clone(), entry).await;
            }
        }

        self.apply_change(&target.checksum_sha256, Some(target.repository_id))
            .await;
        Ok(CarryOutcome {
            verdict_carried: verdict_not_carried_reason.is_none(),
            verdict_not_carried_reason,
            acknowledgements_carried: carried.len(),
            acknowledgements_left_behind: left_behind.len(),
        })
    }

    // -----------------------------------------------------------------------
    // Expiry
    // -----------------------------------------------------------------------

    /// Record lapsed decisions: one audit row each, the frozen flag, and the stored
    /// scores of the repositories they applied in. Every gate and listing already
    /// reads the decision's `expires_at` itself, so a missed tick costs only
    /// freshness.
    ///
    /// The audit row is written before the lapse is marked recorded, so a crash in
    /// between repeats the row on the next tick rather than losing it, and one that
    /// could not be written stays unmarked and is tried again. `SKIP LOCKED` keeps
    /// replicas off each other's rows. Returns the number recorded.
    pub async fn record_expired(&self) -> Result<u64> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let sql = format!(
            "SELECT {ACKNOWLEDGEMENT_COLUMNS} FROM finding_acknowledgements \
             WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= NOW() \
               AND expiry_recorded_at IS NULL \
             ORDER BY expires_at LIMIT 500 \
             FOR UPDATE SKIP LOCKED"
        );
        let lapsed: Vec<FindingAcknowledgement> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let audit = AuditService::new(self.db.clone());
        let mut recorded = Vec::with_capacity(lapsed.len());
        for decision in &lapsed {
            let entry =
                decision_audit_entry(AuditAction::FindingAcknowledgementExpired, decision, None);
            match audit.log(entry).await {
                Ok(_) => recorded.push(decision),
                Err(e) => {
                    tracing::warn!(acknowledgement = %decision.id, error = %e, "lapse not audited; will retry");
                }
            }
        }
        let ids: Vec<Uuid> = recorded.iter().map(|d| d.id).collect();
        sqlx::query(
            "UPDATE finding_acknowledgements SET expiry_recorded_at = NOW() WHERE id = ANY($1)",
        )
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let mut applied: HashSet<(String, Option<Uuid>)> = HashSet::new();
        for decision in &recorded {
            self.clear_frozen_flag(decision).await;
            if applied.insert((decision.checksum_sha256.clone(), decision.repository_id)) {
                self.apply_change(&decision.checksum_sha256, decision.repository_id)
                    .await;
            }
        }
        Ok(recorded.len() as u64)
    }

    // -----------------------------------------------------------------------
    // What follows from a decision
    // -----------------------------------------------------------------------

    /// Refresh what is derived from decisions: the stored score of each repository
    /// holding these bytes in scope, and the cached listing decisions. Best-effort,
    /// because the decision is committed either way; the next scan repairs a score.
    async fn apply_change(&self, checksum_sha256: &str, repository_id: Option<Uuid>) {
        quarantine_service::invalidate_listing_decisions();
        let repositories: Vec<Uuid> = match sqlx::query_scalar(AFFECTED_REPOSITORIES_SQL)
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
        let held: Vec<(Uuid, Uuid)> = match sqlx::query_as(HELD_ARTIFACTS_SQL)
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
    fn digest_lookups_can_use_the_artifacts_index_4426() {
        for sql in [
            AFFECTED_REPOSITORIES_SQL,
            HELD_ARTIFACTS_SQL,
            REPOSITORY_HOLDS_BYTES_SQL,
            CLEAR_FROZEN_FLAG_SQL,
        ] {
            assert!(
                sql.contains("$1::bpchar") || sql.contains("$2::bpchar"),
                "{sql}"
            );
        }
    }

    fn scan(scan_type: &str, status: &str, error: Option<&str>) -> GradedScan {
        GradedScan {
            id: Uuid::new_v4(),
            scan_type: scan_type.to_string(),
            status: status.to_string(),
            error_message: error.map(str::to_string),
            pin_identity: None,
        }
    }

    #[test]
    fn a_carry_is_all_or_nothing() {
        let clean = (scan("dependency", "completed", None), true);
        let alone = [clean.clone()];
        assert_eq!(carry_plan(&alone).unwrap().len(), 1);

        // A row saying the scanner does not apply says nothing about the artifact.
        for not_applicable in [
            scan("image", "not_applicable", None),
            scan(
                "image",
                "failed",
                Some("scanner does not apply to this format"),
            ),
        ] {
            let graded = [clean.clone(), (not_applicable, false)];
            assert_eq!(carry_plan(&graded).unwrap().len(), 1);
        }

        for (label, other) in [
            (
                "a rescan that is not reusable",
                (scan("dependency", "completed", None), false),
            ),
            ("a crash", (scan("image", "failed", Some("boom")), false)),
            ("a running scan", (scan("image", "running", None), false)),
            (
                "an external verdict",
                (scan("external", "completed", None), true),
            ),
            (
                "two current scans",
                (scan("dependency", "completed", None), true),
            ),
        ] {
            assert!(carry_plan(&[clean.clone(), other]).is_err(), "{label}");
        }
        assert!(carry_plan(&[]).is_err(), "nothing to carry");
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
            revoked_reason: Some("superseded".to_string()),
            state: "revoked".to_string(),
        };
        let json = decision_audit_details(&d);
        assert_eq!(json["advisory"], "CVE-1");
        assert_eq!(json["component"], "lodash");
        assert_eq!(json["reason"], "accepted");
        assert_eq!(json["max_severity"], "high");
        assert_eq!(json["revoked_reason"], "superseded");
        assert!(json["repository_id"].is_null());
    }

    /// #5153: triage needs an `admin`-granting scope, as on REST.
    #[tokio::test]
    async fn test_update_cve_status_requires_the_admin_scope_5153() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::grpc::auth_interceptor::GrpcPrincipal;
        use crate::grpc::generated::cve_history_service_server::CveHistoryService;
        use crate::grpc::generated::UpdateCveStatusRequest;
        use crate::grpc::sbom_server::CveHistoryGrpcServer;
        use crate::models::access_scope::AccessScope;
        use tonic::Request;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;
        let (repo, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let artifact = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO artifacts (id, repository_id, name, path, size_bytes, checksum_sha256, \
                                    content_type, storage_key) \
             VALUES ($1, $2, 'a', $3, 1, $4, 'application/octet-stream', $3)",
        )
        .bind(artifact)
        .bind(repo)
        .bind(format!("grpc/{artifact}"))
        .bind(format!("{:064x}", artifact.as_u128()))
        .execute(&pool)
        .await
        .expect("artifact");
        let scan: Uuid = sqlx::query_scalar(
            "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, completed_at) \
             VALUES ($1, $2, 'dependency', 'completed', NOW()) RETURNING id",
        )
        .bind(artifact)
        .bind(repo)
        .fetch_one(&pool)
        .await
        .expect("scan");
        sqlx::query(
            "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, cve_id) \
             VALUES ($1, $2, 'high', 't', 'CVE-2031-5156')",
        )
        .bind(scan)
        .bind(artifact)
        .execute(&pool)
        .await
        .expect("finding");
        let server = CveHistoryGrpcServer::new(pool.clone());
        let call = |scopes: Option<Vec<String>>| {
            let mut request = Request::new(UpdateCveStatusRequest {
                id: crate::services::sbom_service::synth_cve_id(artifact, "CVE-2031-5156")
                    .to_string(),
                status: crate::grpc::generated::CveStatus::Acknowledged as i32,
                reason: "accepted".to_string(),
            });
            request.extensions_mut().insert(GrpcPrincipal {
                is_admin: true,
                scopes,
                user_id,
                allowed_repo_ids: AccessScope::Admin,
            });
            request
        };
        let refused = server
            .update_cve_status(call(Some(vec!["write:artifacts".to_string()])))
            .await
            .expect_err("a narrow token is refused");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);
        let decided: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finding_acknowledgements WHERE repository_id = $1",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(decided, 0);
        server
            .update_cve_status(call(Some(vec!["admin".to_string()])))
            .await
            .expect("an admin-scoped token");
        server
            .update_cve_status(call(None))
            .await
            .expect("an interactive token");
        tdh::cleanup_member_repo(&pool, repo, &std::env::temp_dir().join("none")).await;
        tdh::cleanup_user(&pool, user_id).await;
    }

    /// #5153: a decision stays inside the token's repository restriction, and the
    /// audit trail names who acted.
    #[tokio::test]
    async fn test_update_cve_status_honours_the_token_5153() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::grpc::auth_interceptor::GrpcPrincipal;
        use crate::grpc::generated::cve_history_service_server::CveHistoryService;
        use crate::grpc::generated::UpdateCveStatusRequest;
        use crate::grpc::sbom_server::CveHistoryGrpcServer;
        use crate::models::access_scope::AccessScope;
        use tonic::Request;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;
        let (inside, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let (outside, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let mut seeded = Vec::new();
        for repo in [inside, outside] {
            let artifact = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO artifacts (id, repository_id, name, path, size_bytes, checksum_sha256, \
                                        content_type, storage_key) \
                 VALUES ($1, $2, 'a', $3, 1, $4, 'application/octet-stream', $3)",
            )
            .bind(artifact)
            .bind(repo)
            .bind(format!("grpc/{artifact}"))
            .bind(format!("{:064x}", artifact.as_u128()))
            .execute(&pool)
            .await
            .expect("artifact");
            let scan: Uuid = sqlx::query_scalar(
                "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, completed_at) \
                 VALUES ($1, $2, 'dependency', 'completed', NOW()) RETURNING id",
            )
            .bind(artifact)
            .bind(repo)
            .fetch_one(&pool)
            .await
            .expect("scan");
            sqlx::query(
                "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, cve_id) \
                 VALUES ($1, $2, 'high', 't', 'CVE-2031-5153')",
            )
            .bind(scan)
            .bind(artifact)
            .execute(&pool)
            .await
            .expect("finding");
            seeded.push(artifact);
        }
        let (in_artifact, out_artifact) = (seeded[0], seeded[1]);
        let server = CveHistoryGrpcServer::new(pool.clone());
        let call = |artifact: Uuid| {
            let mut request = Request::new(UpdateCveStatusRequest {
                id: crate::services::sbom_service::synth_cve_id(artifact, "CVE-2031-5153")
                    .to_string(),
                status: crate::grpc::generated::CveStatus::Acknowledged as i32,
                reason: "accepted".to_string(),
            });
            request.extensions_mut().insert(GrpcPrincipal {
                is_admin: true,
                scopes: None,
                user_id,
                allowed_repo_ids: AccessScope::Restricted(vec![inside]),
            });
            request
        };

        assert!(
            server.update_cve_status(call(out_artifact)).await.is_err(),
            "a token restricted to one repository cannot decide for another"
        );
        let decided: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finding_acknowledgements WHERE repository_id = $1",
        )
        .bind(outside)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(decided, 0);

        server
            .update_cve_status(call(in_artifact))
            .await
            .expect("inside the token");
        let (by,): (Option<Uuid>,) = sqlx::query_as(
            "SELECT acknowledged_by FROM finding_acknowledgements WHERE repository_id = $1",
        )
        .bind(inside)
        .fetch_one(&pool)
        .await
        .expect("decision");
        assert_eq!(by, Some(user_id), "the decision names who made it");

        for repo in [inside, outside] {
            tdh::cleanup_member_repo(&pool, repo, &std::env::temp_dir().join("none")).await;
        }
        tdh::cleanup_user(&pool, user_id).await;
    }
}
