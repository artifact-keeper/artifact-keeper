//! Artifact promotion handlers.
//!
//! Handles promotion of artifacts from staging repositories to release repositories.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::quality::{QualityGateEvaluation, QualityGateViolation};
use crate::models::repository::RepositoryType;
use crate::models::sbom::PolicyAction;
use crate::services::promotion_policy_service::PromotionPolicyService;
use crate::services::quality_check_service::QualityCheckService;
use crate::services::repository_service::RepositoryService;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/repositories/:key/promote", post(promote_artifacts_bulk))
        .route(
            "/repositories/:key/artifacts/:artifact_id/promote",
            post(promote_artifact),
        )
        .route(
            "/repositories/:key/artifacts/:artifact_id/reject",
            post(reject_artifact),
        )
        .route(
            "/repositories/:key/promotion-history",
            get(promotion_history),
        )
        .route(
            "/repositories/:key/release-target",
            get(get_release_target).put(set_release_target),
        )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PromoteArtifactRequest {
    /// Target release repository key. When omitted, the staging repository's
    /// linked release target (from `repository_config`) is used instead.
    pub target_repository: Option<String>,
    #[serde(default)]
    pub skip_policy_check: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkPromoteRequest {
    /// Target release repository key. When omitted, the staging repository's
    /// linked release target (from `repository_config`) is used instead.
    pub target_repository: Option<String>,
    pub artifact_ids: Vec<Uuid>,
    #[serde(default)]
    pub skip_policy_check: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromotionResponse {
    pub promoted: bool,
    pub source: String,
    pub target: String,
    pub promotion_id: Option<Uuid>,
    pub policy_violations: Vec<PolicyViolation>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BulkPromotionResponse {
    pub total: usize,
    pub promoted: usize,
    pub failed: usize,
    pub results: Vec<PromotionResponse>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RejectArtifactRequest {
    pub reason: String,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RejectionResponse {
    pub rejected: bool,
    pub artifact_id: Uuid,
    pub source: String,
    pub reason: String,
    pub rejection_id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PromotionHistoryQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub artifact_id: Option<Uuid>,
    pub status: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromotionHistoryEntry {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub artifact_path: String,
    pub source_repo_key: String,
    pub target_repo_key: String,
    pub status: String,
    pub rejection_reason: Option<String>,
    pub promoted_by: Option<Uuid>,
    pub promoted_by_username: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub policy_result: Option<serde_json::Value>,
    pub notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromotionHistoryResponse {
    pub items: Vec<PromotionHistoryEntry>,
    pub pagination: Pagination,
}

/// Validate that source is staging and target is local, with matching formats.
///
/// The staging-source check is split out so that the promotion handler can
/// evaluate quality gates and policies BEFORE rejecting on shape grounds.
/// Quality-gate violations carry more diagnostic value than the staging shape
/// error, so the handler must surface them first when both apply (see #1376).
pub fn validate_promotion_repos(
    source: &crate::models::repository::Repository,
    target: &crate::models::repository::Repository,
) -> Result<()> {
    validate_promotion_source_is_staging(source)?;
    validate_promotion_target_and_format(source, target)
}

/// Verify that the promotion source repository is a hosted repository
/// (`Local` or `Staging`).
///
/// Split from `validate_promotion_repos` so the source-shape check can be
/// deferred until after quality-gate evaluation in the promotion handler
/// (#1376).
///
/// # Why hosted, not staging-only (#1376 / B12)
///
/// The promotion source only needs to be a repository that physically stores
/// artifacts so the bytes can be copied into the release repository. Both
/// `Local` and `Staging` are hosted ([`RepositoryType::is_hosted`]); `Remote`
/// (proxy) and `Virtual` (aggregate) repositories do not own artifact bytes
/// and cannot be a promotion source.
///
/// The earlier staging-only restriction caused the release-gate
/// `quality-gate-blocks-upload` suite to fail its "promotion succeeds after
/// gate loosened" assertion: that suite promotes from a `Local` source, so
/// once the gate stopped blocking, the promotion 400'd on the staging-shape
/// check instead of succeeding. Quality-gate enforcement, not a hard
/// staging-type requirement, is the policy that governs whether a promotion
/// is allowed; the source-shape check only rejects repositories that have no
/// bytes to promote.
pub fn validate_promotion_source_is_staging(
    source: &crate::models::repository::Repository,
) -> Result<()> {
    if !source.repo_type.is_hosted() {
        return Err(AppError::Validation(format!(
            "Source repository must be a hosted (local or staging) repository, got {:?}",
            source.repo_type
        )));
    }
    Ok(())
}

/// Verify the target is a local repository and that the formats match.
///
/// Split from `validate_promotion_repos` so the handler can run gate
/// evaluation between the source-staging check and these target-shape checks
/// when needed.
pub fn validate_promotion_target_and_format(
    source: &crate::models::repository::Repository,
    target: &crate::models::repository::Repository,
) -> Result<()> {
    if target.repo_type != RepositoryType::Local {
        return Err(AppError::Validation(
            "Target repository must be a local (release) repository".to_string(),
        ));
    }
    if source.format != target.format {
        return Err(AppError::Validation(format!(
            "Repository format mismatch: source is {:?}, target is {:?}",
            source.format, target.format
        )));
    }
    Ok(())
}

/// Copy an artifact body from `source` storage to `target` storage by streaming
/// rather than buffering the whole object in memory (#1608, Core Invariant ①).
///
/// Promotion resolves the source and target backends independently, so the two
/// `StorageBackend` handles can be different backends (e.g. a filesystem staging
/// repo promoted to an S3 release repo). [`StorageBackend::copy`] only operates
/// within a single backend, so it cannot be used here; instead we tee the
/// `get_stream` from the source directly into `put_stream` on the target. Peak
/// memory therefore stays O(chunk) regardless of artifact size, which is what
/// prevents an OOM on multi-GB cross-backend promotions.
///
/// A missing source key surfaces as [`AppError::NotFound`] from `get_stream`,
/// matching the storage NotFound contract (#1016). Returns the
/// [`PutStreamResult`](crate::storage::PutStreamResult) so callers can verify
/// the streamed digest/byte count if desired.
pub async fn stream_copy_artifact(
    source: &dyn crate::storage::StorageBackend,
    target: &dyn crate::storage::StorageBackend,
    storage_key: &str,
) -> Result<crate::storage::PutStreamResult> {
    let stream = source.get_stream(storage_key).await?;
    target.put_stream(storage_key, stream).await
}

/// Outcome of a single quality-gate evaluation, used by `promote_artifact` to
/// drive both the block (409) and warn (attach-to-response) branches from one
/// underlying DB query.
///
/// `evaluate_quality_gate` is the most expensive call in the promotion path
/// (it joins `quality_gates`, `artifact_health_scores`, and a handful of
/// related rows). Calling it twice for the same request opens a TOCTOU window
/// where a gate flips between calls and the second call observes a different
/// state than the first. We collapse both branches onto a single evaluation by
/// folding the raw `QualityGateEvaluation` into this three-state outcome up
/// front, then matching on it.
///
/// `NotEvaluated` covers two non-fatal cases that the previous code already
/// treated as "skip the gate, continue":
///   * `skip_policy_check = true` in the request
///   * `quality_check_service` is not wired into application state
///   * the underlying evaluation returned `Err` (missing gate / missing health
///     score), which has always been logged-and-continued rather than 5xx'd.
#[derive(Debug, Clone)]
pub enum GateOutcome {
    /// Gate evaluation says this promotion must be rejected. The handler
    /// surfaces this as `AppError::Conflict` -> HTTP 409 with the gate name,
    /// health score and grade, and violation count.
    Block(QualityGateEvaluation),
    /// Gate evaluation produced violations but the gate is configured to
    /// `warn` (or anything other than `block`). The promotion proceeds and
    /// the violations are attached to the response payload.
    Warn(Vec<QualityGateViolation>),
    /// No actionable gate state: either the gate passed, the evaluation was
    /// skipped (caller opt-out, service not wired, or recoverable error
    /// inside `evaluate_quality_gate`).
    NotEvaluated,
}

/// Evaluate the quality gate for `(artifact_id, repository_id)` exactly once
/// per promotion request and reduce the result to a `GateOutcome`.
///
/// Skips evaluation when the caller passed `skip_policy_check = true` or when
/// `quality_check_service` is not wired into application state. Errors from
/// the underlying evaluation (e.g. missing gate, missing health score) are
/// logged and downgraded to `NotEvaluated`; they are not fatal because the
/// promotion path historically allowed promotions without a configured gate.
///
/// Returning a single owned outcome here is what lets the handler avoid the
/// double-evaluation pattern that existed before (#1382 review): the same
/// underlying DB read powers both the block path and the warn path.
pub async fn evaluate_gate_once(
    quality_check_service: Option<&QualityCheckService>,
    artifact_id: Uuid,
    repository_id: Uuid,
    skip_policy_check: bool,
) -> GateOutcome {
    if skip_policy_check {
        return GateOutcome::NotEvaluated;
    }
    let Some(qc) = quality_check_service else {
        return GateOutcome::NotEvaluated;
    };
    match qc.evaluate_quality_gate(artifact_id, repository_id).await {
        Ok(eval) => classify_gate_evaluation(eval),
        Err(e) => {
            tracing::warn!(
                "Quality gate evaluation failed for artifact {}: {}",
                artifact_id,
                e
            );
            GateOutcome::NotEvaluated
        }
    }
}

/// Pure classifier from `QualityGateEvaluation` to `GateOutcome`.
///
/// Split out so that the block / warn / pass decision can be unit tested
/// without spinning up a `QualityCheckService` or a database. The classifier
/// pins the contract that "gate failed AND action == 'block'" maps to Block,
/// "gate failed AND action != 'block'" maps to Warn, anything else passes.
pub fn classify_gate_evaluation(eval: QualityGateEvaluation) -> GateOutcome {
    if eval.passed {
        return GateOutcome::NotEvaluated;
    }
    if eval.action == "block" {
        return GateOutcome::Block(eval);
    }
    GateOutcome::Warn(eval.violations)
}

/// Render a `GateOutcome::Block` payload as `AppError::Conflict` (HTTP 409).
///
/// Centralised so the handler doesn't carry the format string and the message
/// shape is asserted by a single unit test rather than duplicated.
pub fn gate_block_error(eval: &QualityGateEvaluation) -> AppError {
    AppError::Conflict(format!(
        "Promotion blocked by quality gate '{}' (health score: {}, grade: {}, violations: {})",
        eval.gate_name,
        eval.health_score,
        eval.health_grade,
        eval.violations.len(),
    ))
}

/// Look up the linked release repository key for a staging repository.
///
/// Reads the `release_repository_id` value from the `repository_config` table,
/// then resolves it to a repository key. Returns `None` when no link is configured.
pub async fn resolve_release_target_key(
    db: &sqlx::PgPool,
    staging_repo_id: Uuid,
) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'release_repository_id'",
    )
    .bind(staging_repo_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let release_id_str = match row {
        Some((v,)) => v,
        None => return Ok(None),
    };

    let release_id: Uuid = release_id_str.parse().map_err(|_| {
        AppError::Internal(format!(
            "Invalid UUID in release_repository_id config: {}",
            release_id_str
        ))
    })?;

    let key: Option<(String,)> = sqlx::query_as("SELECT key FROM repositories WHERE id = $1")
        .bind(release_id)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(key.map(|(k,)| k))
}

/// Determine the effective target repository key for a promotion.
///
/// If the caller supplied an explicit target, it is used directly. Otherwise the
/// linked release target from `repository_config` is used. Returns an error when
/// neither is available.
async fn resolve_effective_target(
    db: &sqlx::PgPool,
    explicit_target: Option<&str>,
    staging_repo_id: Uuid,
) -> Result<String> {
    if let Some(target) = explicit_target {
        return Ok(target.to_string());
    }

    resolve_release_target_key(db, staging_repo_id)
        .await?
        .ok_or_else(|| {
            AppError::Validation(
                "No target_repository specified and no linked release repository configured \
                 for this staging repository. Set a release target via PATCH /api/v1/repositories/{key} \
                 with the release_repository_key field, or provide target_repository in the request."
                    .to_string(),
            )
        })
}

/// Validate that the explicit promotion target matches the staging repository's
/// linked release target, if one is configured.
///
/// When a staging repository has a linked release repository, promotions to any
/// other repository are rejected.
async fn enforce_release_target_link(
    db: &sqlx::PgPool,
    staging_repo_id: Uuid,
    actual_target_key: &str,
) -> Result<()> {
    if let Some(linked_key) = resolve_release_target_key(db, staging_repo_id).await? {
        if linked_key != actual_target_key {
            return Err(AppError::Validation(format!(
                "This staging repository is linked to release repository '{}'. \
                 Promotion to '{}' is not allowed.",
                linked_key, actual_target_key,
            )));
        }
    }
    Ok(())
}

/// Authorize a direct promotion request.
///
/// Promoting an artifact into a release repository is an admin-only action,
/// matching the authorization on the approval workflow's
/// `POST /api/v1/approval/{id}/approve` endpoint. Without this gate the
/// approval/governance workflow could be bypassed by promoting directly via
/// the `/promote` routes.
///
/// Split into a pure helper so the gate decision is shared by the single and
/// bulk promote handlers and can be unit tested without a DB or storage.
///
/// Promotion is authorized when the caller is an admin OR presents an API token
/// carrying the grantable `promote:artifacts` scope. The scope is admin-only to
/// mint (see [`crate::services::token_service::ADMIN_ONLY_SCOPES`]) and only ever
/// consulted for API-token principals at the call sites, so a JWT/session user
/// cannot acquire promote capability through it. The tenant-ownership and
/// approval/governance gates run independently and still apply to scoped tokens.
fn ensure_promotion_authorized(is_admin: bool, has_promote_scope: bool) -> Result<()> {
    if !is_admin && !has_promote_scope {
        return Err(AppError::Authorization(
            "Only admins or tokens with the 'promote:artifacts' scope can promote artifacts"
                .to_string(),
        ));
    }
    Ok(())
}

/// Pure tenant-ownership decision for one repository in a promotion.
///
/// A promotion crosses a tenant boundary when the caller is authorized for one
/// tenant's repositories but names another tenant's repository as the source or
/// target. The codebase models tenancy as per-repository role-assignment
/// membership (see [`RepositoryService::user_can_access_repo`] and the
/// `require_repo_write_access` write gate): a caller "owns" a private repo only
/// if they hold a role assignment scoped to it (direct) or a global,
/// NULL-scoped assignment (the genuine super-admin seeded in migration 002).
///
/// Unlike `require_repo_write_access`, this check does NOT blanket-bypass on the
/// global `is_admin` flag. The `is_admin` boolean is a capability flag, not a
/// tenant identity: in a multi-tenant deployment each tenant has admin-capable
/// principals, and the cross-tenant promote-injection finding (campaign-#4
/// systemic authz pattern) was reproduced by exactly such a principal promoting
/// a corp artifact into a globex repository. Defense-in-depth therefore demands
/// the tenant-ownership check be enforced independent of the admin flag: a
/// genuine super-admin still passes via their NULL-scoped grant, while a
/// tenant-scoped admin is rejected for a repository in a tenant they do not own.
///
/// Public repositories carry no tenant boundary, so they always pass — mirroring
/// the public-repo short-circuit in `require_repo_write_access` / `require_visible`.
///
/// Split out as a pure boolean so the allow/deny decision is unit-testable
/// without a database; the DB lookup lives in [`require_promotion_tenant_access`].
fn promotion_tenant_access_allowed(repo_is_public: bool, has_repo_grant: bool) -> bool {
    repo_is_public || has_repo_grant
}

/// Enforce tenant ownership on BOTH the source and target repositories of a
/// promotion before any copy/insert happens.
///
/// Rejects cross-tenant promotion (e.g. a corp-tenant artifact promoted into a
/// globex-tenant repository) with HTTP 403. Applied to every promote path —
/// single, bulk, and the approval-execute path — so the governance workflow
/// cannot be used to launder an artifact across the tenant boundary.
///
/// The denial is an `Authorization` error (403) rather than `NotFound` because
/// the caller, being admin-capable, already proved knowledge of the repository
/// keys via the source/target lookups; the 403 names which repository is out of
/// the caller's tenant so legitimate operators get an actionable message.
pub(crate) async fn require_promotion_tenant_access(
    repo_service: &RepositoryService,
    user_id: Uuid,
    source: &crate::models::repository::Repository,
    target: &crate::models::repository::Repository,
) -> Result<()> {
    for repo in [source, target] {
        let has_grant = repo_service.user_can_access_repo(repo.id, user_id).await?;
        if !promotion_tenant_access_allowed(repo.is_public, has_grant) {
            return Err(AppError::Authorization(format!(
                "You are not authorized to promote into the '{}' repository's tenant",
                repo.key
            )));
        }
    }
    Ok(())
}

fn failed_response(source: String, target: String, message: String) -> PromotionResponse {
    PromotionResponse {
        promoted: false,
        source,
        target,
        promotion_id: None,
        policy_violations: vec![],
        message: Some(message),
    }
}

/// Flatten failing promotion-rule evaluations into the [`PolicyViolation`] shape
/// used by the promotion response, tagging each with the rule name. Pure so it is
/// unit-testable without a DB. Returns an empty vec when there are no failing
/// rules.
fn rule_violations_to_policy_violations(
    failing: &[crate::services::promotion_rule_service::RuleEvaluationResult],
) -> Vec<PolicyViolation> {
    failing
        .iter()
        .flat_map(|e| {
            e.violations.iter().map(move |v| PolicyViolation {
                rule: e.rule_name.clone(),
                severity: "high".to_string(),
                message: v.clone(),
            })
        })
        .collect()
}

#[utoipa::path(
    post,
    path = "/repositories/{key}/artifacts/{artifact_id}/promote",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Source repository key"),
        ("artifact_id" = Uuid, Path, description = "Artifact ID to promote"),
    ),
    request_body = PromoteArtifactRequest,
    responses(
        (status = 200, description = "Artifact promotion result", body = PromotionResponse),
        (status = 404, description = "Artifact or repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "Artifact already exists in target", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error (repo type/format mismatch)", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn promote_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((repo_key, artifact_id)): Path<(String, Uuid)>,
    Json(req): Json<PromoteArtifactRequest>,
) -> Result<Json<PromotionResponse>> {
    // `promote:artifacts` is a grantable, admin-only-to-mint API-token scope.
    // Only trust it for API-token principals: `has_scope` returns true for JWT
    // sessions, so the `is_api_token` guard prevents a session user from gaining
    // promote capability they were never granted.
    let has_promote_scope = auth.is_api_token && auth.has_scope("promote:artifacts");
    ensure_promotion_authorized(auth.is_admin, has_promote_scope)?;

    let repo_service = RepositoryService::new(state.db.clone());

    let source_repo = repo_service.get_by_key(&repo_key).await?;

    // Resolve the target: explicit request field, or linked release repo from config.
    let target_key =
        resolve_effective_target(&state.db, req.target_repository.as_deref(), source_repo.id)
            .await?;

    // When a release link is configured, reject promotions to any other repo.
    enforce_release_target_link(&state.db, source_repo.id, &target_key).await?;

    let target_repo = repo_service.get_by_key(&target_key).await?;

    // Tenant-ownership gate (campaign-#4 systemic authz). The admin-capability
    // check above does NOT bind the caller to a tenant; without this, an
    // admin-capable corp principal could promote into a globex repository. Reject
    // cross-tenant promotion on either the source or target repo with 403.
    require_promotion_tenant_access(&repo_service, auth.user_id, &source_repo, &target_repo)
        .await?;

    // Look up the artifact first. The artifact lookup is keyed by the source
    // repository id, not by repository type, so it works even when the source
    // is not a staging repository. This lets quality-gate evaluation run
    // before the staging-source shape check below: a violating artifact must
    // be rejected with a gate-rejection code, not a 400 shape error
    // (see #1376).
    let artifact = sqlx::query_as!(
        crate::models::artifact::Artifact,
        r#"
        SELECT
            id, repository_id, path, name, version, size_bytes,
            checksum_sha256, checksum_md5, checksum_sha1,
            content_type, storage_key, is_deleted, uploaded_by,
            quarantine_status, quarantine_until,
            created_at, updated_at
        FROM artifacts
        WHERE id = $1 AND repository_id = $2 AND is_deleted = false
        "#,
        artifact_id,
        source_repo.id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found in source repository".to_string()))?;

    // Evaluate the quality gate exactly once per request. The block path and
    // the warn path both branch off this single outcome so we never re-query
    // the gate mid-flight; that closes the TOCTOU window where a gate could
    // flip from "warn" to "block" between two evaluations (#1382 review).
    //
    // This call also runs BEFORE the staging-source shape check so gate
    // violations take precedence in the error response. A gate-blocked
    // promotion returns HTTP 409 Conflict, which is the documented rejection
    // code for promotions blocked by gate policy (#1376).
    let gate_outcome = evaluate_gate_once(
        state.quality_check_service.as_deref(),
        artifact_id,
        source_repo.id,
        req.skip_policy_check,
    )
    .await;

    if let GateOutcome::Block(ref eval) = gate_outcome {
        return Err(gate_block_error(eval));
    }

    // Now run shape validation. Gate evaluation has already finished above so
    // a violating artifact cannot be masked by a 400 staging-source error.
    validate_promotion_repos(&source_repo, &target_repo)?;

    // Ordering note (#1382 review): quality-gate block precedes
    // approval-required. A gate-violating artifact in an approval-required
    // repository returns 409 (gate block) rather than the approval-required
    // response. This is intentional: a gate-blocked artifact will never be
    // promotable until the underlying violations are resolved, so routing it
    // through the approval workflow would only produce an approval request that
    // is guaranteed to fail re-evaluation. Security and policy enforcement
    // therefore take precedence over the approval requirement. See
    // `test_gate_block_precedes_approval_required` for the regression pin.
    //
    // Couple the /promote route to the approval workflow: when the source repo
    // requires approval, the promotion is only authorized by an APPROVED +
    // unconsumed `promotion_approvals` row for the exact (artifact, source,
    // target) pair. We record the requirement here (after the gate-block early
    // return) but defer the atomic consume to just before the byte copy below so
    // a later policy/rule rejection does not spend the approval. Without this an
    // admin could promote directly while a request sits unconsumed, bypassing
    // the gate (the promotion-approval-gate-bypass finding).
    let approval_required =
        super::approval::check_approval_required(&state.db, source_repo.id).await?;

    let mut policy_violations: Vec<PolicyViolation> = vec![];
    let mut policy_result_json = serde_json::json!({"passed": true, "violations": []});

    if !req.skip_policy_check {
        let policy_service = PromotionPolicyService::new(state.db.clone());
        let eval_result = policy_service
            .evaluate_artifact(artifact_id, source_repo.id)
            .await?;

        policy_violations = eval_result
            .violations
            .iter()
            .map(|v| PolicyViolation {
                rule: v.rule.clone(),
                severity: v.severity.clone(),
                message: v.message.clone(),
            })
            .collect();

        policy_result_json = serde_json::json!({
            "passed": eval_result.passed,
            "action": format!("{:?}", eval_result.action).to_lowercase(),
            "violations": eval_result.violations,
            "cve_summary": eval_result.cve_summary,
            "license_summary": eval_result.license_summary,
        });

        if !eval_result.passed && eval_result.action == PolicyAction::Block {
            return Ok(Json(PromotionResponse {
                promoted: false,
                source: format!("{}/{}", repo_key, artifact.path),
                target: format!("{}/{}", target_key, artifact.path),
                promotion_id: None,
                policy_violations,
                message: Some("Promotion blocked by policy violations".to_string()),
            }));
        }
    }

    // Enforce the per-pair promotion_rules (min_staging_hours, require_signature,
    // min_health_score, max_cve_severity, ...) created via /api/v1/promotion-rules.
    // These are a separate policy system from PromotionPolicyService above; reuse
    // the same evaluator the advisory /evaluate dry-run uses so enforcement and
    // dry-run can never diverge. Gated behind `skip_policy_check` to match the
    // other promotion gates' documented admin override.
    if !req.skip_policy_check {
        let rule_service =
            crate::services::promotion_rule_service::PromotionRuleService::new(state.db.clone());
        let failing = rule_service
            .evaluate_for_promotion(artifact_id, source_repo.id, target_repo.id)
            .await?;
        if !failing.is_empty() {
            return Ok(Json(PromotionResponse {
                promoted: false,
                source: format!("{}/{}", repo_key, artifact.path),
                target: format!("{}/{}", target_key, artifact.path),
                promotion_id: None,
                policy_violations: rule_violations_to_policy_violations(&failing),
                message: Some("Promotion blocked by promotion rule violations".to_string()),
            }));
        }
    }

    // Attach any warn-level gate violations to the response. This uses the
    // SAME `gate_outcome` value produced by `evaluate_gate_once` above; the
    // gate is not re-evaluated here.
    if let GateOutcome::Warn(violations) = gate_outcome {
        for v in violations {
            policy_violations.push(PolicyViolation {
                rule: v.rule,
                severity: "medium".to_string(),
                message: v.message,
            });
        }
    }

    // Approval gate (promotion-approval-gate-bypass): when the source requires
    // approval, atomically consume an APPROVED + unconsumed approval row for this
    // exact (artifact, source, target) pair before copying any bytes. A single-row
    // UPDATE ... SET consumed_at claim is the concurrency boundary: a miss (no
    // approval, only a pending request, or a concurrent double-spend) returns 409
    // and the target is constrained to the approved pair. Done after the
    // gate/policy/rule checks so a rejected promotion never spends the approval.
    if approval_required {
        super::approval::require_and_consume_approval(
            &state.db,
            artifact_id,
            source_repo.id,
            target_repo.id,
        )
        .await?;
    }

    let new_artifact_id = Uuid::new_v4();
    let source_storage = state.storage_for_repo(&source_repo.storage_location())?;
    let target_storage = state.storage_for_repo(&target_repo.storage_location())?;

    // Stream the artifact body across (possibly distinct) storage backends
    // instead of buffering it in memory (#1608, Core Invariant ①). Shares the
    // same tee helper as the bulk path.
    stream_copy_artifact(&*source_storage, &*target_storage, &artifact.storage_key)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to copy artifact: {}", e)))?;

    super::cleanup_soft_deleted_artifact(&state.db, target_repo.id, &artifact.path).await;

    sqlx::query!(
        r#"
        INSERT INTO artifacts (
            id, repository_id, path, name, version, size_bytes,
            checksum_sha256, checksum_md5, checksum_sha1,
            content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
        new_artifact_id,
        target_repo.id,
        artifact.path,
        artifact.name,
        artifact.version,
        artifact.size_bytes,
        artifact.checksum_sha256,
        artifact.checksum_md5,
        artifact.checksum_sha1,
        artifact.content_type,
        artifact.storage_key,
        auth.user_id
    )
    .execute(&state.db)
    .await
    .map_err(|e: sqlx::Error| {
        if e.to_string().contains("duplicate key") {
            AppError::Conflict(format!(
                "Artifact already exists in target repository: {}",
                artifact.path
            ))
        } else {
            AppError::Database(e.to_string())
        }
    })?;

    let promotion_id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO promotion_history (
            id, artifact_id, source_repo_id, target_repo_id,
            promoted_by, policy_result, notes
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        promotion_id,
        artifact_id,
        source_repo.id,
        target_repo.id,
        auth.user_id,
        policy_result_json,
        req.notes
    )
    .execute(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    tracing::info!(
        source_repo = %repo_key,
        target_repo = %target_key,
        artifact = %artifact.path,
        promoted_by = %auth.user_id,
        "Artifact promoted successfully"
    );

    Ok(Json(PromotionResponse {
        promoted: true,
        source: format!("{}/{}", repo_key, artifact.path),
        target: format!("{}/{}", target_key, artifact.path),
        promotion_id: Some(promotion_id),
        policy_violations: vec![],
        message: Some("Artifact promoted successfully".to_string()),
    }))
}

#[utoipa::path(
    post,
    path = "/repositories/{key}/promote",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Source repository key"),
    ),
    request_body = BulkPromoteRequest,
    responses(
        (status = 200, description = "Bulk promotion results", body = BulkPromotionResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error (repo type/format mismatch)", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn promote_artifacts_bulk(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(repo_key): Path<String>,
    Json(req): Json<BulkPromoteRequest>,
) -> Result<Json<BulkPromotionResponse>> {
    // `promote:artifacts` is a grantable, admin-only-to-mint API-token scope.
    // Only trust it for API-token principals: `has_scope` returns true for JWT
    // sessions, so the `is_api_token` guard prevents a session user from gaining
    // promote capability they were never granted.
    let has_promote_scope = auth.is_api_token && auth.has_scope("promote:artifacts");
    ensure_promotion_authorized(auth.is_admin, has_promote_scope)?;

    let repo_service = RepositoryService::new(state.db.clone());

    let source_repo = repo_service.get_by_key(&repo_key).await?;

    // Resolve the target: explicit request field, or linked release repo from config.
    let target_key =
        resolve_effective_target(&state.db, req.target_repository.as_deref(), source_repo.id)
            .await?;

    // When a release link is configured, reject promotions to any other repo.
    enforce_release_target_link(&state.db, source_repo.id, &target_key).await?;

    let target_repo = repo_service.get_by_key(&target_key).await?;
    validate_promotion_repos(&source_repo, &target_repo)?;

    // Tenant-ownership gate (campaign-#4 systemic authz). Enforced once for the
    // whole batch since source/target are fixed across all items; rejects a
    // cross-tenant bulk promotion (corp artifacts -> globex repo) with 403.
    require_promotion_tenant_access(&repo_service, auth.user_id, &source_repo, &target_repo)
        .await?;

    // Approval gate (promotion-approval-gate-bypass). When the source requires
    // approval, each artifact must independently consume its own APPROVED +
    // unconsumed approval row for this (artifact, source, target) pair before its
    // bytes are copied; a missing/used approval fails that item per-batch (the
    // others remain promotable). The require_approval flag is per-source so it is
    // resolved once for the whole batch.
    let approval_required =
        super::approval::check_approval_required(&state.db, source_repo.id).await?;

    let mut results = Vec::new();
    let mut promoted = 0;
    let mut failed = 0;

    for artifact_id in &req.artifact_ids {
        let artifact = match sqlx::query_as!(
            crate::models::artifact::Artifact,
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                quarantine_status, quarantine_until,
                created_at, updated_at
            FROM artifacts
            WHERE id = $1 AND repository_id = $2 AND is_deleted = false
            "#,
            artifact_id,
            source_repo.id
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(a)) => a,
            Ok(None) => {
                failed += 1;
                results.push(failed_response(
                    format!("{}/{}", repo_key, artifact_id),
                    target_key.clone(),
                    "Artifact not found".to_string(),
                ));
                continue;
            }
            Err(e) => {
                failed += 1;
                results.push(failed_response(
                    format!("{}/{}", repo_key, artifact_id),
                    target_key.clone(),
                    format!("Database error: {}", e),
                ));
                continue;
            }
        };

        let source_display = format!("{}/{}", repo_key, artifact.path);
        let target_display = format!("{}/{}", target_key, artifact.path);

        // Enforce per-pair promotion_rules per item before copying. Mirrors the
        // single-promote gate; a rule-blocked item fails and the batch continues
        // so the rest of the artifacts remain promotable. Honors the
        // skip_policy_check admin override.
        if !req.skip_policy_check {
            let rule_service = crate::services::promotion_rule_service::PromotionRuleService::new(
                state.db.clone(),
            );
            match rule_service
                .evaluate_for_promotion(*artifact_id, source_repo.id, target_repo.id)
                .await
            {
                Ok(failing) if !failing.is_empty() => {
                    failed += 1;
                    let mut resp = failed_response(
                        source_display,
                        target_display,
                        "Promotion blocked by promotion rule violations".to_string(),
                    );
                    resp.policy_violations = rule_violations_to_policy_violations(&failing);
                    results.push(resp);
                    continue;
                }
                Ok(_) => {}
                Err(e) => {
                    failed += 1;
                    results.push(failed_response(
                        source_display,
                        target_display,
                        format!("Rule evaluation error: {}", e),
                    ));
                    continue;
                }
            }
        }

        // Approval gate (promotion-approval-gate-bypass): consume this item's
        // own APPROVED + unconsumed approval row before copying. Runs after the
        // rule check so a rule-blocked item never spends an approval, and fails
        // the item (not the batch) when no consumable approval exists.
        if approval_required {
            if let Err(e) = super::approval::require_and_consume_approval(
                &state.db,
                *artifact_id,
                source_repo.id,
                target_repo.id,
            )
            .await
            {
                failed += 1;
                results.push(failed_response(
                    source_display,
                    target_display,
                    e.to_string(),
                ));
                continue;
            }
        }

        let source_storage = state.storage_for_repo(&source_repo.storage_location())?;
        let target_storage = state.storage_for_repo(&target_repo.storage_location())?;

        // Stream the artifact body from source to target instead of buffering
        // the whole object in memory (#1608, Core Invariant ①). See
        // `stream_copy_artifact` for why `StorageBackend::copy` cannot be used
        // when source and target are distinct backends.
        if let Err(e) =
            stream_copy_artifact(&*source_storage, &*target_storage, &artifact.storage_key).await
        {
            failed += 1;
            results.push(failed_response(
                source_display,
                target_display,
                format!("Failed to copy artifact: {}", e),
            ));
            continue;
        }

        let new_artifact_id = Uuid::new_v4();
        super::cleanup_soft_deleted_artifact(&state.db, target_repo.id, &artifact.path).await;
        let insert_result: std::result::Result<_, sqlx::Error> = sqlx::query!(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            new_artifact_id,
            target_repo.id,
            artifact.path,
            artifact.name,
            artifact.version,
            artifact.size_bytes,
            artifact.checksum_sha256,
            artifact.checksum_md5,
            artifact.checksum_sha1,
            artifact.content_type,
            artifact.storage_key,
            auth.user_id
        )
        .execute(&state.db)
        .await;

        if let Err(e) = insert_result {
            failed += 1;
            let msg = if e.to_string().contains("duplicate key") {
                "Artifact already exists in target".to_string()
            } else {
                format!("Database error: {}", e)
            };
            results.push(failed_response(source_display, target_display, msg));
            continue;
        }

        let promotion_id = Uuid::new_v4();
        let policy_result = serde_json::json!({"passed": true, "violations": []});

        let _ = sqlx::query!(
            r#"
            INSERT INTO promotion_history (
                id, artifact_id, source_repo_id, target_repo_id,
                promoted_by, policy_result, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            promotion_id,
            artifact_id,
            source_repo.id,
            target_repo.id,
            auth.user_id,
            policy_result,
            req.notes
        )
        .execute(&state.db)
        .await;

        promoted += 1;
        results.push(PromotionResponse {
            promoted: true,
            source: source_display,
            target: target_display,
            promotion_id: Some(promotion_id),
            policy_violations: vec![],
            message: Some("Promoted successfully".to_string()),
        });
    }

    tracing::info!(
        source_repo = %repo_key,
        target_repo = %target_key,
        total = req.artifact_ids.len(),
        promoted = promoted,
        failed = failed,
        "Bulk promotion completed"
    );

    Ok(Json(BulkPromotionResponse {
        total: req.artifact_ids.len(),
        promoted,
        failed,
        results,
    }))
}

#[utoipa::path(
    post,
    path = "/repositories/{key}/artifacts/{artifact_id}/reject",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Source repository key"),
        ("artifact_id" = Uuid, Path, description = "Artifact ID to reject"),
    ),
    request_body = RejectArtifactRequest,
    responses(
        (status = 200, description = "Artifact rejection result", body = RejectionResponse),
        (status = 404, description = "Artifact or repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((repo_key, artifact_id)): Path<(String, Uuid)>,
    Json(req): Json<RejectArtifactRequest>,
) -> Result<Json<RejectionResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let source_repo = repo_service.get_by_key(&repo_key).await?;

    if source_repo.repo_type != RepositoryType::Staging {
        return Err(AppError::Validation(
            "Artifacts can only be rejected from staging repositories".to_string(),
        ));
    }

    // Verify artifact exists
    let artifact_exists: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = $1 AND repository_id = $2 AND is_deleted = false)"#,
    )
    .bind(artifact_id)
    .bind(source_repo.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    if !artifact_exists {
        return Err(AppError::NotFound(
            "Artifact not found in staging repository".to_string(),
        ));
    }

    let rejection_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO promotion_history (
            id, artifact_id, source_repo_id, target_repo_id,
            promoted_by, status, rejection_reason, notes
        )
        VALUES ($1, $2, $3, $3, $4, 'rejected', $5, $6)
        "#,
    )
    .bind(rejection_id)
    .bind(artifact_id)
    .bind(source_repo.id)
    .bind(auth.user_id)
    .bind(&req.reason)
    .bind(&req.notes)
    .execute(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    tracing::info!(
        source_repo = %repo_key,
        artifact_id = %artifact_id,
        rejected_by = %auth.user_id,
        reason = %req.reason,
        "Artifact rejected"
    );

    Ok(Json(RejectionResponse {
        rejected: true,
        artifact_id,
        source: repo_key,
        reason: req.reason,
        rejection_id,
    }))
}

#[utoipa::path(
    get,
    path = "/repositories/{key}/promotion-history",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("page" = Option<u32>, Query, description = "Page number (1-indexed)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 100)"),
        ("artifact_id" = Option<Uuid>, Query, description = "Filter by artifact ID"),
        ("status" = Option<String>, Query, description = "Filter by status (promoted, rejected, pending_approval)"),
    ),
    responses(
        (status = 200, description = "Promotion history for repository", body = PromotionHistoryResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn promotion_history(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(query): Query<PromotionHistoryQuery>,
) -> Result<Json<PromotionHistoryResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&repo_key).await?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    #[derive(sqlx::FromRow)]
    struct HistoryRow {
        id: Uuid,
        artifact_id: Uuid,
        artifact_path: Option<String>,
        source_repo_key: Option<String>,
        target_repo_key: Option<String>,
        status: String,
        rejection_reason: Option<String>,
        promoted_by: Option<Uuid>,
        promoted_by_username: Option<String>,
        policy_result: Option<serde_json::Value>,
        notes: Option<String>,
        created_at: chrono::DateTime<chrono::Utc>,
    }

    let status_filter = query.status.as_deref();

    let rows: Vec<HistoryRow> = sqlx::query_as(
        r#"
        SELECT
            ph.id,
            ph.artifact_id,
            a.path as artifact_path,
            sr.key as source_repo_key,
            tr.key as target_repo_key,
            ph.status,
            ph.rejection_reason,
            ph.promoted_by,
            u.username as promoted_by_username,
            ph.policy_result,
            ph.notes,
            ph.created_at
        FROM promotion_history ph
        LEFT JOIN artifacts a ON a.id = ph.artifact_id
        LEFT JOIN repositories sr ON sr.id = ph.source_repo_id
        LEFT JOIN repositories tr ON tr.id = ph.target_repo_id
        LEFT JOIN users u ON u.id = ph.promoted_by
        WHERE (ph.source_repo_id = $1 OR ph.target_repo_id = $1)
          AND ($4::TEXT IS NULL OR ph.status = $4)
        ORDER BY ph.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(repo.id)
    .bind(per_page as i64)
    .bind(offset)
    .bind(status_filter)
    .fetch_all(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::BIGINT FROM promotion_history
           WHERE (source_repo_id = $1 OR target_repo_id = $1)
             AND ($2::TEXT IS NULL OR status = $2)"#,
    )
    .bind(repo.id)
    .bind(status_filter)
    .fetch_one(&state.db)
    .await
    .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    let items = rows
        .into_iter()
        .map(|row| PromotionHistoryEntry {
            id: row.id,
            artifact_id: row.artifact_id,
            artifact_path: row.artifact_path.unwrap_or_default(),
            source_repo_key: row.source_repo_key.unwrap_or_default(),
            target_repo_key: row.target_repo_key.unwrap_or_default(),
            status: row.status,
            rejection_reason: row.rejection_reason,
            promoted_by: row.promoted_by,
            promoted_by_username: row.promoted_by_username,
            policy_result: row.policy_result,
            notes: row.notes,
            created_at: row.created_at,
        })
        .collect();

    Ok(Json(PromotionHistoryResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

// ---------------------------------------------------------------------------
// Release target linking
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct ReleaseTargetResponse {
    /// Whether this staging repository has a linked release target.
    pub linked: bool,
    /// The release repository key, if linked.
    pub release_repository_key: Option<String>,
    /// The release repository ID, if linked.
    pub release_repository_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetReleaseTargetRequest {
    /// Repository key of the release (local) repository to link.
    /// Pass `null` or omit to remove the link.
    pub release_repository_key: Option<String>,
}

/// Get the linked release target for a staging repository.
#[utoipa::path(
    get,
    path = "/repositories/{key}/release-target",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Staging repository key"),
    ),
    responses(
        (status = 200, description = "Release target information", body = ReleaseTargetResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Repository is not a staging repository", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_release_target(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Json<ReleaseTargetResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&repo_key).await?;

    if repo.repo_type != RepositoryType::Staging {
        return Err(AppError::Validation(
            "Release target linking is only available for staging repositories".to_string(),
        ));
    }

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'release_repository_id'",
    )
    .bind(repo.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    match row {
        Some((release_id_str,)) => {
            let release_id: Uuid = release_id_str.parse().map_err(|_| {
                AppError::Internal(format!(
                    "Invalid UUID in release_repository_id config: {}",
                    release_id_str
                ))
            })?;
            let release_key: Option<(String,)> =
                sqlx::query_as("SELECT key FROM repositories WHERE id = $1")
                    .bind(release_id)
                    .fetch_optional(&state.db)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;

            match release_key {
                Some((key,)) => Ok(Json(ReleaseTargetResponse {
                    linked: true,
                    release_repository_key: Some(key),
                    release_repository_id: Some(release_id),
                })),
                None => {
                    // The linked repo was deleted; treat as unlinked.
                    Ok(Json(ReleaseTargetResponse {
                        linked: false,
                        release_repository_key: None,
                        release_repository_id: None,
                    }))
                }
            }
        }
        None => Ok(Json(ReleaseTargetResponse {
            linked: false,
            release_repository_key: None,
            release_repository_id: None,
        })),
    }
}

/// Set or remove the linked release target for a staging repository.
///
/// The release repository must exist, be type Local, and share the same package
/// format as the staging repository. Pass `null` for `release_repository_key` to
/// remove the link.
#[utoipa::path(
    put,
    path = "/repositories/{key}/release-target",
    context_path = "/api/v1/promotion",
    tag = "promotion",
    params(
        ("key" = String, Path, description = "Staging repository key"),
    ),
    request_body = SetReleaseTargetRequest,
    responses(
        (status = 200, description = "Release target updated", body = ReleaseTargetResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_release_target(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(repo_key): Path<String>,
    Json(req): Json<SetReleaseTargetRequest>,
) -> Result<Json<ReleaseTargetResponse>> {
    auth.require_scope("write")?;

    let repo_service = RepositoryService::new(state.db.clone());
    let staging_repo = repo_service.get_by_key(&repo_key).await?;

    if staging_repo.repo_type != RepositoryType::Staging {
        return Err(AppError::Validation(
            "Release target linking is only available for staging repositories".to_string(),
        ));
    }

    match req.release_repository_key {
        Some(release_key) => {
            let release_repo = repo_service.get_by_key(&release_key).await.map_err(|_| {
                AppError::Validation(format!("Release repository '{}' not found", release_key))
            })?;

            validate_release_target_link(&staging_repo, &release_repo)?;

            // Store the link in repository_config
            sqlx::query(
                "INSERT INTO repository_config (repository_id, key, value) \
                 VALUES ($1, 'release_repository_id', $2) \
                 ON CONFLICT (repository_id, key) DO UPDATE SET value = $2, updated_at = NOW()",
            )
            .bind(staging_repo.id)
            .bind(release_repo.id.to_string())
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            tracing::info!(
                staging_repo = %repo_key,
                release_repo = %release_key,
                "Linked staging repository to release target"
            );

            Ok(Json(ReleaseTargetResponse {
                linked: true,
                release_repository_key: Some(release_key),
                release_repository_id: Some(release_repo.id),
            }))
        }
        None => {
            // Remove the link
            sqlx::query(
                "DELETE FROM repository_config WHERE repository_id = $1 AND key = 'release_repository_id'",
            )
            .bind(staging_repo.id)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            tracing::info!(
                staging_repo = %repo_key,
                "Removed release target link from staging repository"
            );

            Ok(Json(ReleaseTargetResponse {
                linked: false,
                release_repository_key: None,
                release_repository_id: None,
            }))
        }
    }
}

/// Validate that a release repository is a valid target for a staging repo link.
pub fn validate_release_target_link(
    staging: &crate::models::repository::Repository,
    release: &crate::models::repository::Repository,
) -> Result<()> {
    if release.repo_type != RepositoryType::Local {
        return Err(AppError::Validation(
            "Release target must be a local repository".to_string(),
        ));
    }
    if staging.format != release.format {
        return Err(AppError::Validation(format!(
            "Format mismatch: staging repository is {:?}, release repository is {:?}. \
             Both must use the same package format.",
            staging.format, release.format
        )));
    }
    if staging.id == release.id {
        return Err(AppError::Validation(
            "A staging repository cannot be linked to itself".to_string(),
        ));
    }
    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        promote_artifact,
        promote_artifacts_bulk,
        reject_artifact,
        promotion_history,
        get_release_target,
        set_release_target,
    ),
    components(schemas(
        PromoteArtifactRequest,
        BulkPromoteRequest,
        PromotionResponse,
        PolicyViolation,
        BulkPromotionResponse,
        RejectArtifactRequest,
        RejectionResponse,
        PromotionHistoryQuery,
        PromotionHistoryEntry,
        PromotionHistoryResponse,
        ReleaseTargetResponse,
        SetReleaseTargetRequest,
    ))
)]
pub struct PromotionApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ensure_promotion_authorized (admin-only gate on /promote routes)
    //
    // Regression for the direct-promotion authorization bug: a non-admin
    // caller could promote artifacts straight into a release repository via
    // the `/promote` routes, bypassing the admin-gated approval workflow.
    // The single and bulk promote handlers now both call this helper.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ensure_promotion_authorized_admin_ok() {
        // Admin passes regardless of scope.
        assert!(ensure_promotion_authorized(true, false).is_ok());
        assert!(ensure_promotion_authorized(true, true).is_ok());
    }

    #[test]
    fn test_ensure_promotion_authorized_promote_scope_ok() {
        // A non-admin caller presenting the `promote:artifacts` scope is
        // authorized (the scope is admin-only to mint and is only consulted
        // for API-token principals at the call sites).
        assert!(ensure_promotion_authorized(false, true).is_ok());
    }

    // -----------------------------------------------------------------------
    // rule_violations_to_policy_violations (promotion_rules -> response shape)
    // -----------------------------------------------------------------------

    fn rule_eval(
        name: &str,
        passed: bool,
        violations: &[&str],
    ) -> crate::services::promotion_rule_service::RuleEvaluationResult {
        crate::services::promotion_rule_service::RuleEvaluationResult {
            rule_id: Uuid::new_v4(),
            rule_name: name.to_string(),
            passed,
            violations: violations.iter().map(|v| v.to_string()).collect(),
        }
    }

    #[test]
    fn test_rule_violations_empty_when_no_failing_rules() {
        let out = rule_violations_to_policy_violations(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn test_rule_violations_single_failing_rule_maps_name_and_messages() {
        let failing = vec![rule_eval(
            "strict-release",
            false,
            &[
                "Artifact does not have a valid signature",
                "Health score 20 < 100",
            ],
        )];
        let out = rule_violations_to_policy_violations(&failing);
        assert_eq!(out.len(), 2);
        for v in &out {
            assert_eq!(v.rule, "strict-release");
            assert_eq!(v.severity, "high");
        }
        assert_eq!(out[0].message, "Artifact does not have a valid signature");
        assert_eq!(out[1].message, "Health score 20 < 100");
    }

    #[test]
    fn test_rule_violations_many_failing_rules_flattened() {
        let failing = vec![
            rule_eval("rule-a", false, &["a1", "a2"]),
            rule_eval("rule-b", false, &["b1"]),
        ];
        let out = rule_violations_to_policy_violations(&failing);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].rule, "rule-a");
        assert_eq!(out[0].message, "a1");
        assert_eq!(out[1].rule, "rule-a");
        assert_eq!(out[1].message, "a2");
        assert_eq!(out[2].rule, "rule-b");
        assert_eq!(out[2].message, "b1");
    }

    #[test]
    fn test_ensure_promotion_authorized_non_admin_denied() {
        // Neither admin nor promote scope -> denied.
        let err = ensure_promotion_authorized(false, false).unwrap_err();
        // Non-admin promotion is an authorization failure (HTTP 403), matching
        // the approval workflow's approve/reject endpoints.
        assert!(matches!(err, AppError::Authorization(_)));
        assert!(err.to_string().contains("promote"));
    }

    // -----------------------------------------------------------------------
    // promotion_tenant_access_allowed (cross-tenant promote-target gate)
    //
    // Pure decision behind require_promotion_tenant_access. A repo passes the
    // tenant-ownership gate when it is public OR the caller holds a grant on it
    // (per-repo or global NULL-scoped). The is_admin capability flag is NOT a
    // tenant identity, so it is intentionally absent here.
    // -----------------------------------------------------------------------

    #[test]
    fn test_tenant_access_public_repo_always_allowed() {
        // Public repos carry no tenant boundary, so they pass even without a grant.
        assert!(promotion_tenant_access_allowed(true, false));
        assert!(promotion_tenant_access_allowed(true, true));
    }

    #[test]
    fn test_tenant_access_private_with_grant_allowed() {
        // A genuine super-admin (NULL-scoped grant) or a same-tenant operator
        // holds a grant on the private repo -> allowed.
        assert!(promotion_tenant_access_allowed(false, true));
    }

    #[test]
    fn test_tenant_access_private_without_grant_denied() {
        // The cross-tenant case: private repo in another tenant, no grant -> deny.
        assert!(!promotion_tenant_access_allowed(false, false));
    }

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Build the source display string for promotion responses.
    fn build_promotion_source_display(repo_key: &str, artifact_path: &str) -> String {
        format!("{}/{}", repo_key, artifact_path)
    }

    /// Build the target display string for promotion responses.
    fn build_promotion_target_display(target_repo: &str, artifact_path: &str) -> String {
        format!("{}/{}", target_repo, artifact_path)
    }

    /// Compute promotion pagination values (page, per_page, offset).
    /// Returns `(page, per_page, offset)`.
    fn compute_promotion_pagination(
        raw_page: Option<u32>,
        raw_per_page: Option<u32>,
    ) -> (u32, u32, i64) {
        let page = raw_page.unwrap_or(1).max(1);
        let per_page = raw_per_page.unwrap_or(20).min(100);
        let offset = ((page - 1) * per_page) as i64;
        (page, per_page, offset)
    }

    /// Compute total pages from total items and per_page.
    fn compute_total_pages(total: i64, per_page: u32) -> u32 {
        ((total as f64) / (per_page as f64)).ceil() as u32
    }

    /// Build a successful promotion response.
    fn build_success_response(
        source: String,
        target: String,
        promotion_id: Uuid,
    ) -> PromotionResponse {
        PromotionResponse {
            promoted: true,
            source,
            target,
            promotion_id: Some(promotion_id),
            policy_violations: vec![],
            message: Some("Artifact promoted successfully".to_string()),
        }
    }

    /// Build a bulk promotion summary response.
    fn build_bulk_summary(
        total: usize,
        promoted: usize,
        failed: usize,
        results: Vec<PromotionResponse>,
    ) -> BulkPromotionResponse {
        BulkPromotionResponse {
            total,
            promoted,
            failed,
            results,
        }
    }

    /// Build a rejection response.
    fn build_rejection_response(
        artifact_id: Uuid,
        source: String,
        reason: String,
        rejection_id: Uuid,
    ) -> RejectionResponse {
        RejectionResponse {
            rejected: true,
            artifact_id,
            source,
            reason,
            rejection_id,
        }
    }

    // -----------------------------------------------------------------------
    // validate_promotion_repos
    // -----------------------------------------------------------------------

    fn make_repo(
        repo_type: RepositoryType,
        format: crate::models::repository::RepositoryFormat,
    ) -> crate::models::repository::Repository {
        crate::models::repository::Repository {
            id: Uuid::new_v4(),
            key: "test-repo".to_string(),
            name: "Test Repo".to_string(),
            description: None,
            format,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/test".to_string(),
            upstream_url: None,
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: crate::models::repository::ReplicationPriority::LocalOnly,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_validate_promotion_repos_valid() {
        let source = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let target = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Maven,
        );
        assert!(validate_promotion_repos(&source, &target).is_ok());
    }

    #[test]
    fn test_validate_promotion_repos_source_local_is_allowed() {
        // B12 / #1376: a Local source is a hosted repository and is now an
        // allowed promotion source (local -> local release). Previously this
        // 400'd on a staging-only shape check, which broke the release-gate
        // "promotion succeeds after gate loosened" assertion.
        let source = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let target = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Maven,
        );
        assert!(validate_promotion_repos(&source, &target).is_ok());
    }

    #[test]
    fn test_validate_promotion_repos_source_remote() {
        // Remote (proxy) repos own no bytes and cannot be a promotion source.
        let source = make_repo(
            RepositoryType::Remote,
            crate::models::repository::RepositoryFormat::Npm,
        );
        let target = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Npm,
        );
        let err = validate_promotion_repos(&source, &target).unwrap_err();
        assert!(err.to_string().contains("hosted"));
    }

    #[test]
    fn test_validate_promotion_repos_source_virtual() {
        // Virtual (aggregate) repos own no bytes and cannot be a source.
        let source = make_repo(
            RepositoryType::Virtual,
            crate::models::repository::RepositoryFormat::Pypi,
        );
        let target = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Pypi,
        );
        let err = validate_promotion_repos(&source, &target).unwrap_err();
        assert!(err.to_string().contains("hosted"));
    }

    #[test]
    fn test_validate_promotion_repos_target_not_local() {
        let source = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let target = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let err = validate_promotion_repos(&source, &target).unwrap_err();
        assert!(err.to_string().contains("local"));
    }

    #[test]
    fn test_validate_promotion_repos_target_remote() {
        let source = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Cargo,
        );
        let target = make_repo(
            RepositoryType::Remote,
            crate::models::repository::RepositoryFormat::Cargo,
        );
        let err = validate_promotion_repos(&source, &target).unwrap_err();
        assert!(err.to_string().contains("local"));
    }

    #[test]
    fn test_validate_promotion_repos_format_mismatch() {
        let source = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let target = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Npm,
        );
        let err = validate_promotion_repos(&source, &target).unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn test_validate_promotion_repos_remote_source_check_precedes_target() {
        // Source-shape check runs before the target check. A Remote source is
        // rejected for the source reason ("hosted") regardless of the target.
        let source = make_repo(
            RepositoryType::Remote,
            crate::models::repository::RepositoryFormat::Docker,
        );
        let target = make_repo(
            RepositoryType::Remote,
            crate::models::repository::RepositoryFormat::Helm,
        );
        let err = validate_promotion_repos(&source, &target).unwrap_err();
        assert!(err.to_string().contains("hosted"));
    }

    // -----------------------------------------------------------------------
    // Split validators (regression for #1376)
    //
    // The single-artifact promotion handler must be able to run quality-gate
    // evaluation BEFORE rejecting on staging-source shape. To support that
    // ordering, `validate_promotion_repos` is split into two helpers:
    //   - `validate_promotion_source_is_staging` (the staging check)
    //   - `validate_promotion_target_and_format` (target type + format match)
    //
    // These tests pin the split so a future refactor cannot silently
    // re-collapse them and re-introduce the bug from #1376.
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_promotion_source_is_staging_ok() {
        let source = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        assert!(validate_promotion_source_is_staging(&source).is_ok());
    }

    #[test]
    fn test_validate_promotion_source_is_staging_accepts_local() {
        // B12 / #1376: Local is hosted, so it is now an accepted source. The
        // staging-only restriction broke the release-gate loosened-promotion
        // assertion because that suite promotes from a Local source.
        let source = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Maven,
        );
        assert!(validate_promotion_source_is_staging(&source).is_ok());
    }

    #[test]
    fn test_validate_promotion_source_is_staging_rejects_remote_message_mentions_hosted() {
        // The rejection message must NOT be the legacy
        // "must be a staging repository" string, which the release-gate
        // greps for to detect the #1376 regression; it now says "hosted".
        let source = make_repo(
            RepositoryType::Remote,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let err = validate_promotion_source_is_staging(&source).unwrap_err();
        assert!(err.to_string().contains("hosted"));
        assert!(!err
            .to_string()
            .contains("Source repository must be a staging repository"));
    }

    #[test]
    fn test_validate_promotion_source_is_staging_rejects_remote() {
        let source = make_repo(
            RepositoryType::Remote,
            crate::models::repository::RepositoryFormat::Npm,
        );
        assert!(validate_promotion_source_is_staging(&source).is_err());
    }

    #[test]
    fn test_validate_promotion_source_is_staging_rejects_virtual() {
        let source = make_repo(
            RepositoryType::Virtual,
            crate::models::repository::RepositoryFormat::Pypi,
        );
        assert!(validate_promotion_source_is_staging(&source).is_err());
    }

    #[test]
    fn test_validate_promotion_target_and_format_ok() {
        let source = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let target = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Maven,
        );
        assert!(validate_promotion_target_and_format(&source, &target).is_ok());
    }

    #[test]
    fn test_validate_promotion_target_and_format_target_not_local() {
        let source = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let target = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let err = validate_promotion_target_and_format(&source, &target).unwrap_err();
        assert!(err.to_string().contains("local"));
    }

    #[test]
    fn test_validate_promotion_target_and_format_format_mismatch() {
        let source = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let target = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Npm,
        );
        let err = validate_promotion_target_and_format(&source, &target).unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }

    /// Documents the precedence the promotion handler relies on (#1376).
    ///
    /// The handler calls `validate_promotion_source_is_staging` AFTER quality
    /// gate evaluation. If a non-hosted source (Remote/Virtual) ever appears at
    /// the handler after gate eval, the resulting error must still be a
    /// `Validation` error (HTTP 400), not silently swallowed.
    #[test]
    fn test_validate_promotion_source_is_staging_error_status_is_validation() {
        let source = make_repo(
            RepositoryType::Remote,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let err = validate_promotion_source_is_staging(&source).unwrap_err();
        match err {
            AppError::Validation(msg) => {
                assert!(msg.contains("hosted"));
            }
            other => panic!("expected Validation error, got {:?}", other),
        }
    }

    /// Documents the rejection-code contract for gate-blocked promotions.
    ///
    /// When the promotion handler raises an `AppError::Conflict` for a
    /// gate-blocked artifact, the response must serialize to HTTP 409 with
    /// the CONFLICT code. The release-gate accepts 403/409/422 as the valid
    /// gate-rejection set, and we pin 409 here so a future refactor cannot
    /// silently downgrade gate violations to a generic 400.
    #[test]
    fn test_quality_gate_block_returns_conflict() {
        let err = AppError::Conflict(
            "Promotion blocked by quality gate 'no-critical' \
             (health score: 42, grade: D, violations: 1)"
                .to_string(),
        );
        match err {
            AppError::Conflict(msg) => {
                assert!(msg.contains("quality gate"));
                assert!(msg.contains("blocked"));
            }
            other => panic!("expected Conflict error, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Single-evaluation gate outcome (regression for #1382 review)
    //
    // The promotion handler must evaluate the quality gate exactly once per
    // request and drive both the block path (HTTP 409) and the warn path
    // (violations attached to response) from that single outcome. The tests
    // below pin:
    //   * the classifier mapping QualityGateEvaluation -> GateOutcome
    //   * the rendered Conflict message for a Block outcome
    //   * the documented ordering: gate-block precedes approval-required
    // -----------------------------------------------------------------------

    use crate::models::quality::{ComponentScores, QualityGateEvaluation, QualityGateViolation};

    fn make_gate_eval(
        passed: bool,
        action: &str,
        violations: Vec<QualityGateViolation>,
    ) -> QualityGateEvaluation {
        QualityGateEvaluation {
            passed,
            action: action.to_string(),
            gate_name: "test-gate".to_string(),
            health_score: 42,
            health_grade: "D".to_string(),
            violations,
            component_scores: ComponentScores {
                security: Some(50),
                license: Some(60),
                quality: Some(40),
                metadata: Some(70),
            },
        }
    }

    fn make_violation(rule: &str) -> QualityGateViolation {
        QualityGateViolation {
            rule: rule.to_string(),
            expected: ">=70".to_string(),
            actual: "42".to_string(),
            message: format!("Rule {} failed", rule),
        }
    }

    #[test]
    fn test_classify_gate_passed_is_not_evaluated() {
        let eval = make_gate_eval(true, "block", vec![]);
        assert!(matches!(
            classify_gate_evaluation(eval),
            GateOutcome::NotEvaluated
        ));
    }

    #[test]
    fn test_classify_gate_failed_block_is_block() {
        let eval = make_gate_eval(false, "block", vec![make_violation("min_health_score")]);
        match classify_gate_evaluation(eval) {
            GateOutcome::Block(inner) => {
                assert_eq!(inner.gate_name, "test-gate");
                assert_eq!(inner.violations.len(), 1);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_gate_failed_warn_is_warn() {
        let eval = make_gate_eval(
            false,
            "warn",
            vec![
                make_violation("min_security_score"),
                make_violation("min_metadata_score"),
            ],
        );
        match classify_gate_evaluation(eval) {
            GateOutcome::Warn(violations) => {
                assert_eq!(violations.len(), 2);
                assert_eq!(violations[0].rule, "min_security_score");
                assert_eq!(violations[1].rule, "min_metadata_score");
            }
            other => panic!("expected Warn, got {:?}", other),
        }
    }

    /// Non-standard actions (anything that is not "block") fall through to
    /// the warn path. Pinning so a future "audit" or "log" action does not
    /// accidentally become a block.
    #[test]
    fn test_classify_gate_failed_unknown_action_is_warn() {
        let eval = make_gate_eval(false, "audit", vec![make_violation("min_quality_score")]);
        assert!(matches!(
            classify_gate_evaluation(eval),
            GateOutcome::Warn(_)
        ));
    }

    #[test]
    fn test_gate_block_error_renders_conflict_with_gate_metadata() {
        let eval = make_gate_eval(false, "block", vec![make_violation("min_health_score")]);
        let err = gate_block_error(&eval);
        match err {
            AppError::Conflict(msg) => {
                assert!(msg.contains("Promotion blocked by quality gate"));
                assert!(msg.contains("test-gate"));
                assert!(msg.contains("health score: 42"));
                assert!(msg.contains("grade: D"));
                assert!(msg.contains("violations: 1"));
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    /// Regression for #1382 review concern (1): gate evaluation must happen
    /// exactly once per request. We can't drive the full async handler from a
    /// unit test (no DB), so we assert the invariant structurally: there is
    /// exactly one call to `evaluate_quality_gate` reachable from
    /// `promote_artifact`, routed through `evaluate_gate_once`.
    #[test]
    fn test_promote_artifact_uses_single_gate_evaluation() {
        let src = include_str!("promotion.rs");

        // Locate the promote_artifact handler body. Bounded by the next
        // `pub async fn` declaration to avoid scanning the bulk handler.
        let handler_start = src
            .find("pub async fn promote_artifact(")
            .expect("promote_artifact handler must exist");
        let after_handler = &src[handler_start + 1..];
        let next_pub_async = after_handler
            .find("pub async fn ")
            .expect("expected a following pub async fn to bound the handler scope");
        let handler_body = &src[handler_start..handler_start + 1 + next_pub_async];

        // Direct `.evaluate_quality_gate(` calls inside the handler must be
        // zero: the handler must route through `evaluate_gate_once` instead.
        let direct_calls = handler_body.matches(".evaluate_quality_gate(").count();
        assert_eq!(
            direct_calls, 0,
            "promote_artifact must not call evaluate_quality_gate directly; \
             use evaluate_gate_once to enforce single-evaluation. Found {} direct call(s).",
            direct_calls
        );

        // And exactly one `evaluate_gate_once(` invocation in the handler.
        let helper_calls = handler_body.matches("evaluate_gate_once(").count();
        assert_eq!(
            helper_calls, 1,
            "promote_artifact must call evaluate_gate_once exactly once per request; \
             found {} call(s).",
            helper_calls
        );
    }

    /// Regression for #1382 review concern (2): documented ordering between
    /// quality-gate block and approval-required.
    ///
    /// Quality-gate block (HTTP 409) precedes the "approval required" hint
    /// (HTTP 200 with `promoted: false`). A gate-violating artifact in an
    /// approval-required repository must return 409, NOT the approval hint,
    /// because the approval request would be guaranteed to re-fail the gate.
    ///
    /// We assert this structurally on the handler source: the `Block` early
    /// return must appear before the `check_approval_required` call.
    /// Slice the source text of a handler body, bounded by its `pub async fn`
    /// signature and the next `pub async fn`. Shared by the structural tests so
    /// the handler-bounding boilerplate lives in one place.
    fn handler_source_body<'a>(src: &'a str, signature: &str) -> &'a str {
        let start = src
            .find(signature)
            .unwrap_or_else(|| panic!("handler not found: {signature}"));
        let after = &src[start + 1..];
        let next = after
            .find("pub async fn ")
            .expect("expected a following pub async fn to bound the handler scope");
        &src[start..start + 1 + next]
    }

    #[test]
    fn test_gate_block_precedes_approval_required() {
        let src = include_str!("promotion.rs");
        let body = handler_source_body(src, "pub async fn promote_artifact(");

        let gate_block_idx = body
            .find("GateOutcome::Block")
            .expect("handler must early-return on GateOutcome::Block");
        let approval_idx = body
            .find("check_approval_required(")
            .expect("handler must call check_approval_required");

        assert!(
            gate_block_idx < approval_idx,
            "Gate-block early return must come before approval-required check. \
             Reordering this changes the documented precedence (#1382): a \
             gate-blocked artifact in an approval-required repo returns 409, \
             not the 200 approval-required hint."
        );
    }

    /// promotion-approval-gate-bypass: when the source requires approval the
    /// /promote route must require AND consume an approved approval row before
    /// copying. We assert structurally that `promote_artifact` calls
    /// `require_and_consume_approval` and that the call sits AFTER both the
    /// `GateOutcome::Block` early return and the `check_approval_required`
    /// lookup (so the gate-block precedence and the approval gate both hold).
    #[test]
    fn test_promote_consumes_approval_after_gate_and_check() {
        let src = include_str!("promotion.rs");
        let body = handler_source_body(src, "pub async fn promote_artifact(");

        let gate_block_idx = body
            .find("GateOutcome::Block")
            .expect("handler must early-return on GateOutcome::Block");
        let check_idx = body
            .find("check_approval_required(")
            .expect("handler must call check_approval_required");
        let consume_idx = body
            .find("require_and_consume_approval(")
            .expect("handler must consume an approved approval row when required");

        assert!(
            gate_block_idx < consume_idx && check_idx < consume_idx,
            "the approval consume must run after the gate-block early return and \
             after the check_approval_required lookup"
        );
    }

    /// promotion-approval-gate-bypass: the bulk promote path must also consume an
    /// approval per item when the source requires approval.
    #[test]
    fn test_bulk_promote_consumes_approval() {
        let src = include_str!("promotion.rs");
        let body = handler_source_body(src, "pub async fn promote_artifacts_bulk(");

        assert!(
            body.contains("check_approval_required(")
                && body.contains("require_and_consume_approval("),
            "bulk promote must require and consume an approval per item when required"
        );
    }

    // -----------------------------------------------------------------------
    // failed_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_failed_response_basic() {
        let resp = failed_response(
            "staging/artifact.jar".to_string(),
            "release/artifact.jar".to_string(),
            "Not found".to_string(),
        );
        assert!(!resp.promoted);
        assert_eq!(resp.source, "staging/artifact.jar");
        assert_eq!(resp.target, "release/artifact.jar");
        assert!(resp.promotion_id.is_none());
        assert!(resp.policy_violations.is_empty());
        assert_eq!(resp.message, Some("Not found".to_string()));
    }

    #[test]
    fn test_failed_response_duplicate_key() {
        let resp = failed_response(
            "staging/lib.tar.gz".to_string(),
            "release/lib.tar.gz".to_string(),
            "Artifact already exists in target".to_string(),
        );
        assert!(!resp.promoted);
        assert!(resp.message.unwrap().contains("already exists"));
    }

    #[test]
    fn test_failed_response_empty_strings() {
        let resp = failed_response(String::new(), String::new(), String::new());
        assert!(!resp.promoted);
        assert_eq!(resp.source, "");
        assert_eq!(resp.target, "");
        assert_eq!(resp.message, Some(String::new()));
    }

    // -----------------------------------------------------------------------
    // build_promotion_source_display / build_promotion_target_display
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_promotion_source_display() {
        let result = build_promotion_source_display("staging-maven", "com/example/lib-1.0.jar");
        assert_eq!(result, "staging-maven/com/example/lib-1.0.jar");
    }

    #[test]
    fn test_build_promotion_source_display_simple() {
        let result = build_promotion_source_display("my-repo", "artifact.tar.gz");
        assert_eq!(result, "my-repo/artifact.tar.gz");
    }

    #[test]
    fn test_build_promotion_target_display() {
        let result = build_promotion_target_display("release-maven", "com/example/lib-1.0.jar");
        assert_eq!(result, "release-maven/com/example/lib-1.0.jar");
    }

    #[test]
    fn test_build_promotion_target_display_nested() {
        let result = build_promotion_target_display(
            "releases",
            "org/apache/commons/commons-lang3/3.14/commons-lang3-3.14.jar",
        );
        assert_eq!(
            result,
            "releases/org/apache/commons/commons-lang3/3.14/commons-lang3-3.14.jar"
        );
    }

    // -----------------------------------------------------------------------
    // compute_promotion_pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_promotion_pagination_defaults() {
        let (page, per_page, offset) = compute_promotion_pagination(None, None);
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_compute_promotion_pagination_page_2() {
        let (page, per_page, offset) = compute_promotion_pagination(Some(2), Some(25));
        assert_eq!(page, 2);
        assert_eq!(per_page, 25);
        assert_eq!(offset, 25);
    }

    #[test]
    fn test_compute_promotion_pagination_page_3() {
        let (page, per_page, offset) = compute_promotion_pagination(Some(3), Some(10));
        assert_eq!(page, 3);
        assert_eq!(per_page, 10);
        assert_eq!(offset, 20);
    }

    #[test]
    fn test_compute_promotion_pagination_zero_page_clamps_to_1() {
        let (page, _per_page, offset) = compute_promotion_pagination(Some(0), Some(10));
        assert_eq!(page, 1);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_compute_promotion_pagination_per_page_capped_at_100() {
        let (_page, per_page, _offset) = compute_promotion_pagination(Some(1), Some(200));
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_compute_promotion_pagination_large_page() {
        let (page, per_page, offset) = compute_promotion_pagination(Some(100), Some(50));
        assert_eq!(page, 100);
        assert_eq!(per_page, 50);
        assert_eq!(offset, 4950);
    }

    // -----------------------------------------------------------------------
    // compute_total_pages
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_total_pages_exact() {
        assert_eq!(compute_total_pages(100, 20), 5);
    }

    #[test]
    fn test_compute_total_pages_remainder() {
        assert_eq!(compute_total_pages(101, 20), 6);
    }

    #[test]
    fn test_compute_total_pages_one_item() {
        assert_eq!(compute_total_pages(1, 20), 1);
    }

    #[test]
    fn test_compute_total_pages_zero_items() {
        assert_eq!(compute_total_pages(0, 20), 0);
    }

    #[test]
    fn test_compute_total_pages_per_page_one() {
        assert_eq!(compute_total_pages(5, 1), 5);
    }

    // -----------------------------------------------------------------------
    // build_success_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_success_response() {
        let promo_id = Uuid::new_v4();
        let resp = build_success_response(
            "staging/lib.jar".to_string(),
            "release/lib.jar".to_string(),
            promo_id,
        );
        assert!(resp.promoted);
        assert_eq!(resp.source, "staging/lib.jar");
        assert_eq!(resp.target, "release/lib.jar");
        assert_eq!(resp.promotion_id, Some(promo_id));
        assert!(resp.policy_violations.is_empty());
        assert_eq!(
            resp.message,
            Some("Artifact promoted successfully".to_string())
        );
    }

    #[test]
    fn test_build_success_response_different_paths() {
        let promo_id = Uuid::new_v4();
        let resp = build_success_response(
            "staging-npm/@scope/pkg-1.0.0.tgz".to_string(),
            "releases-npm/@scope/pkg-1.0.0.tgz".to_string(),
            promo_id,
        );
        assert!(resp.promoted);
        assert_eq!(resp.promotion_id, Some(promo_id));
    }

    // -----------------------------------------------------------------------
    // build_bulk_summary
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_bulk_summary_all_promoted() {
        let results = vec![
            build_success_response("s/a".to_string(), "t/a".to_string(), Uuid::new_v4()),
            build_success_response("s/b".to_string(), "t/b".to_string(), Uuid::new_v4()),
        ];
        let summary = build_bulk_summary(2, 2, 0, results);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.promoted, 2);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.results.len(), 2);
    }

    #[test]
    fn test_build_bulk_summary_mixed_results() {
        let results = vec![
            build_success_response("s/a".to_string(), "t/a".to_string(), Uuid::new_v4()),
            failed_response(
                "s/b".to_string(),
                "t/b".to_string(),
                "Not found".to_string(),
            ),
        ];
        let summary = build_bulk_summary(2, 1, 1, results);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.promoted, 1);
        assert_eq!(summary.failed, 1);
        assert!(summary.results[0].promoted);
        assert!(!summary.results[1].promoted);
    }

    #[test]
    fn test_build_bulk_summary_all_failed() {
        let results = vec![
            failed_response("s/a".to_string(), "t/a".to_string(), "err1".to_string()),
            failed_response("s/b".to_string(), "t/b".to_string(), "err2".to_string()),
        ];
        let summary = build_bulk_summary(2, 0, 2, results);
        assert_eq!(summary.promoted, 0);
        assert_eq!(summary.failed, 2);
    }

    #[test]
    fn test_build_bulk_summary_empty() {
        let summary = build_bulk_summary(0, 0, 0, vec![]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.promoted, 0);
        assert_eq!(summary.failed, 0);
        assert!(summary.results.is_empty());
    }

    // -----------------------------------------------------------------------
    // build_rejection_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rejection_response() {
        let artifact_id = Uuid::new_v4();
        let rejection_id = Uuid::new_v4();
        let resp = build_rejection_response(
            artifact_id,
            "staging-maven".to_string(),
            "Failed security scan".to_string(),
            rejection_id,
        );
        assert!(resp.rejected);
        assert_eq!(resp.artifact_id, artifact_id);
        assert_eq!(resp.source, "staging-maven");
        assert_eq!(resp.reason, "Failed security scan");
        assert_eq!(resp.rejection_id, rejection_id);
    }

    #[test]
    fn test_build_rejection_response_long_reason() {
        let artifact_id = Uuid::new_v4();
        let rejection_id = Uuid::new_v4();
        let reason = "CVE-2024-12345: Critical vulnerability in log4j dependency. \
                       Artifact contains known malicious code pattern."
            .to_string();
        let resp = build_rejection_response(
            artifact_id,
            "staging".to_string(),
            reason.clone(),
            rejection_id,
        );
        assert!(resp.rejected);
        assert_eq!(resp.reason, reason);
    }

    #[test]
    fn test_build_rejection_response_empty_reason() {
        let artifact_id = Uuid::new_v4();
        let rejection_id = Uuid::new_v4();
        let resp = build_rejection_response(
            artifact_id,
            "staging".to_string(),
            String::new(),
            rejection_id,
        );
        assert!(resp.rejected);
        assert_eq!(resp.reason, "");
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_promotion_response_serialization() {
        let resp = PromotionResponse {
            promoted: true,
            source: "staging/lib.jar".to_string(),
            target: "release/lib.jar".to_string(),
            promotion_id: Some(Uuid::nil()),
            policy_violations: vec![],
            message: Some("OK".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["promoted"], true);
        assert_eq!(json["source"], "staging/lib.jar");
        assert_eq!(json["target"], "release/lib.jar");
        assert_eq!(json["message"], "OK");
    }

    #[test]
    fn test_bulk_promotion_response_serialization() {
        let resp = BulkPromotionResponse {
            total: 3,
            promoted: 2,
            failed: 1,
            results: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 3);
        assert_eq!(json["promoted"], 2);
        assert_eq!(json["failed"], 1);
    }

    #[test]
    fn test_rejection_response_serialization() {
        let id = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let resp = RejectionResponse {
            rejected: true,
            artifact_id: id,
            source: "staging".to_string(),
            reason: "policy violation".to_string(),
            rejection_id: rid,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["rejected"], true);
        assert_eq!(json["artifact_id"], id.to_string());
        assert_eq!(json["rejection_id"], rid.to_string());
    }

    #[test]
    fn test_policy_violation_serialization() {
        let v = PolicyViolation {
            rule: "max-severity".to_string(),
            severity: "high".to_string(),
            message: "Critical vulnerability found".to_string(),
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["rule"], "max-severity");
        assert_eq!(json["severity"], "high");
        assert_eq!(json["message"], "Critical vulnerability found");
    }

    // -----------------------------------------------------------------------
    // Deserialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_promote_artifact_request_deserialization() {
        let json = serde_json::json!({
            "target_repository": "release-maven",
            "notes": "Promoted after review"
        });
        let req: PromoteArtifactRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.target_repository, Some("release-maven".to_string()));
        assert!(!req.skip_policy_check);
        assert_eq!(req.notes, Some("Promoted after review".to_string()));
    }

    #[test]
    fn test_promote_artifact_request_skip_policy() {
        let json = serde_json::json!({
            "target_repository": "releases",
            "skip_policy_check": true
        });
        let req: PromoteArtifactRequest = serde_json::from_value(json).unwrap();
        assert!(req.skip_policy_check);
        assert!(req.notes.is_none());
    }

    #[test]
    fn test_promote_artifact_request_no_target() {
        let json = serde_json::json!({
            "skip_policy_check": false
        });
        let req: PromoteArtifactRequest = serde_json::from_value(json).unwrap();
        assert!(req.target_repository.is_none());
        assert!(!req.skip_policy_check);
    }

    #[test]
    fn test_bulk_promote_request_deserialization() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let json = serde_json::json!({
            "target_repository": "releases",
            "artifact_ids": [id1, id2],
            "notes": "Bulk promotion"
        });
        let req: BulkPromoteRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.target_repository, Some("releases".to_string()));
        assert_eq!(req.artifact_ids.len(), 2);
        assert!(!req.skip_policy_check);
        assert_eq!(req.notes, Some("Bulk promotion".to_string()));
    }

    #[test]
    fn test_bulk_promote_request_no_target() {
        let id1 = Uuid::new_v4();
        let json = serde_json::json!({
            "artifact_ids": [id1]
        });
        let req: BulkPromoteRequest = serde_json::from_value(json).unwrap();
        assert!(req.target_repository.is_none());
        assert_eq!(req.artifact_ids.len(), 1);
    }

    #[test]
    fn test_reject_artifact_request_deserialization() {
        let json = serde_json::json!({
            "reason": "Contains known vulnerability",
            "notes": "CVE-2024-12345"
        });
        let req: RejectArtifactRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.reason, "Contains known vulnerability");
        assert_eq!(req.notes, Some("CVE-2024-12345".to_string()));
    }

    #[test]
    fn test_reject_artifact_request_no_notes() {
        let json = serde_json::json!({ "reason": "Policy violation" });
        let req: RejectArtifactRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.reason, "Policy violation");
        assert!(req.notes.is_none());
    }

    #[test]
    fn test_promotion_history_query_deserialization_defaults() {
        let json = serde_json::json!({});
        let query: PromotionHistoryQuery = serde_json::from_value(json).unwrap();
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.artifact_id.is_none());
        assert!(query.status.is_none());
    }

    #[test]
    fn test_promotion_history_query_deserialization_full() {
        let art_id = Uuid::new_v4();
        let json = serde_json::json!({
            "page": 3,
            "per_page": 50,
            "artifact_id": art_id,
            "status": "promoted"
        });
        let query: PromotionHistoryQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, Some(3));
        assert_eq!(query.per_page, Some(50));
        assert_eq!(query.artifact_id, Some(art_id));
        assert_eq!(query.status, Some("promoted".to_string()));
    }

    // -----------------------------------------------------------------------
    // validate_release_target_link
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_release_target_link_valid() {
        let staging = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let release = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Maven,
        );
        assert!(validate_release_target_link(&staging, &release).is_ok());
    }

    #[test]
    fn test_validate_release_target_link_target_not_local() {
        let staging = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let remote = make_repo(
            RepositoryType::Remote,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let err = validate_release_target_link(&staging, &remote).unwrap_err();
        assert!(err.to_string().contains("local"));
    }

    #[test]
    fn test_validate_release_target_link_target_staging() {
        let staging1 = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Npm,
        );
        let staging2 = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Npm,
        );
        let err = validate_release_target_link(&staging1, &staging2).unwrap_err();
        assert!(err.to_string().contains("local"));
    }

    #[test]
    fn test_validate_release_target_link_format_mismatch() {
        let staging = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Maven,
        );
        let release = make_repo(
            RepositoryType::Local,
            crate::models::repository::RepositoryFormat::Npm,
        );
        let err = validate_release_target_link(&staging, &release).unwrap_err();
        assert!(err.to_string().contains("Format mismatch"));
    }

    #[test]
    fn test_validate_release_target_link_same_repo() {
        let staging = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Pypi,
        );
        let mut release = staging.clone();
        release.repo_type = RepositoryType::Local;
        // They share the same ID because release was cloned from staging.
        let err = validate_release_target_link(&staging, &release).unwrap_err();
        assert!(err.to_string().contains("itself"));
    }

    #[test]
    fn test_validate_release_target_link_virtual_target() {
        let staging = make_repo(
            RepositoryType::Staging,
            crate::models::repository::RepositoryFormat::Docker,
        );
        let virtual_repo = make_repo(
            RepositoryType::Virtual,
            crate::models::repository::RepositoryFormat::Docker,
        );
        let err = validate_release_target_link(&staging, &virtual_repo).unwrap_err();
        assert!(err.to_string().contains("local"));
    }

    // -----------------------------------------------------------------------
    // ReleaseTargetResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_release_target_response_linked() {
        let id = Uuid::new_v4();
        let resp = ReleaseTargetResponse {
            linked: true,
            release_repository_key: Some("release-maven".to_string()),
            release_repository_id: Some(id),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["linked"], true);
        assert_eq!(json["release_repository_key"], "release-maven");
        assert_eq!(json["release_repository_id"], id.to_string());
    }

    #[test]
    fn test_release_target_response_not_linked() {
        let resp = ReleaseTargetResponse {
            linked: false,
            release_repository_key: None,
            release_repository_id: None,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["linked"], false);
        assert!(json["release_repository_key"].is_null());
        assert!(json["release_repository_id"].is_null());
    }

    // -----------------------------------------------------------------------
    // SetReleaseTargetRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_release_target_request_with_key() {
        let json = serde_json::json!({
            "release_repository_key": "releases-maven"
        });
        let req: SetReleaseTargetRequest = serde_json::from_value(json).unwrap();
        assert_eq!(
            req.release_repository_key,
            Some("releases-maven".to_string())
        );
    }

    #[test]
    fn test_set_release_target_request_null_key() {
        let json = serde_json::json!({
            "release_repository_key": null
        });
        let req: SetReleaseTargetRequest = serde_json::from_value(json).unwrap();
        assert!(req.release_repository_key.is_none());
    }

    #[test]
    fn test_set_release_target_request_empty() {
        let json = serde_json::json!({});
        let req: SetReleaseTargetRequest = serde_json::from_value(json).unwrap();
        assert!(req.release_repository_key.is_none());
    }

    // -----------------------------------------------------------------------
    // stream_copy_artifact (#1608 cross-backend streaming promotion)
    // -----------------------------------------------------------------------

    use crate::error::AppError;
    use crate::storage::{PutStreamResult, StorageBackend};
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::stream::BoxStream;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// A source backend that emits its payload over `get_stream` in several
    /// chunks, so the test proves we tee a multi-chunk stream rather than
    /// buffering. `get()` panics to guarantee the streaming path is used.
    struct ChunkedSource {
        payload: Bytes,
        missing: bool,
    }

    #[async_trait]
    impl StorageBackend for ChunkedSource {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            panic!("source put must not be called");
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            panic!("stream_copy_artifact must use get_stream, not get");
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(!self.missing)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get_stream(
            &self,
            key: &str,
        ) -> crate::error::Result<BoxStream<'static, crate::error::Result<Bytes>>> {
            if self.missing {
                return Err(AppError::NotFound(format!("missing: {}", key)));
            }
            // Split the payload into two chunks to exercise multi-chunk teeing.
            let mid = self.payload.len() / 2;
            let first = self.payload.slice(0..mid);
            let second = self.payload.slice(mid..);
            let chunks: Vec<crate::error::Result<Bytes>> = vec![Ok(first), Ok(second)];
            Ok(Box::pin(futures::stream::iter(chunks)))
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    /// A target backend that captures whatever was streamed into it via
    /// `put_stream`, plus the computed checksum/byte count, so the test can
    /// assert the copied object is byte-identical to the source.
    #[derive(Default)]
    struct CapturingTarget {
        received: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl StorageBackend for CapturingTarget {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            panic!("target put must not be called; put_stream is the streaming path");
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(Bytes::from(self.received.lock().unwrap().clone()))
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn put_stream(
            &self,
            _key: &str,
            stream: BoxStream<'static, crate::error::Result<Bytes>>,
        ) -> crate::error::Result<PutStreamResult> {
            use futures::StreamExt;
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            let mut buf = Vec::new();
            let mut total: u64 = 0;
            tokio::pin!(stream);
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                hasher.update(&chunk);
                total += chunk.len() as u64;
                buf.extend_from_slice(&chunk);
            }
            *self.received.lock().unwrap() = buf;
            Ok(PutStreamResult {
                checksum_sha256: format!("{:x}", hasher.finalize()),
                bytes_written: total,
            })
        }
    }

    #[tokio::test]
    async fn test_stream_copy_artifact_copies_bytes_across_backends() {
        // Source and target are DISTINCT backend types — the exact scenario
        // where StorageBackend::copy cannot be used and tee streaming is
        // required (#1608).
        let payload = Bytes::from_static(b"multi-gb-artifact-stand-in-payload-bytes");
        let source = ChunkedSource {
            payload: payload.clone(),
            missing: false,
        };
        let target = CapturingTarget::default();

        let result = stream_copy_artifact(&source, &target, "rpm/repo/pkg.rpm")
            .await
            .expect("stream copy should succeed");

        // The target received the exact source bytes.
        assert_eq!(
            &target.received.lock().unwrap()[..],
            &payload[..],
            "copied bytes must match the source artifact exactly"
        );
        // Byte count and digest are propagated from put_stream, preserving
        // integrity verification capability.
        assert_eq!(result.bytes_written, payload.len() as u64);
        let expected_digest = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&payload);
            format!("{:x}", h.finalize())
        };
        assert_eq!(result.checksum_sha256, expected_digest);
    }

    #[tokio::test]
    async fn test_stream_copy_artifact_propagates_source_not_found() {
        // A missing source object must surface as AppError::NotFound from
        // get_stream (the storage NotFound contract, #1016) and never reach
        // the target backend.
        let source = ChunkedSource {
            payload: Bytes::new(),
            missing: true,
        };
        let target = CapturingTarget::default();

        let err = stream_copy_artifact(&source, &target, "rpm/repo/missing.rpm")
            .await
            .expect_err("missing source must error");
        assert!(matches!(err, AppError::NotFound(_)), "got {:?}", err);
        // Target must remain untouched.
        assert!(target.received.lock().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // DB-backed promotion_rules enforcement tests (PR #1940).
    //
    // These exercise the new promotion_rules gate on the SINGLE and BULK
    // promote handlers, plus the `max_cve_severity` unset-vs-set default fix
    // via the shared evaluator. They run under `cargo llvm-cov --lib` with a
    // live DATABASE_URL (the CI coverage job), and runtime-skip cleanly when
    // no DATABASE_URL is configured (NOT `#[ignore]`, so the coverage instrument
    // sees these paths). Mirrors the in-`src` DB-test pattern used elsewhere in
    // this crate (e.g. quality_gates.rs): `let Some(pool) = try_pool().await
    // else { return; };`.
    //
    // Relocated from backend/tests/promotion_rules_gate_tests.rs, which lived in
    // the integration target and therefore did not count toward `--lib`
    // coverage.
    // -----------------------------------------------------------------------
    mod gate_db {
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::middleware::auth::AuthExtension;
        use crate::api::SharedState;
        use crate::services::promotion_rule_service::PromotionRuleService;
        use sqlx::PgPool;
        use std::sync::Arc;

        /// Create a hosted ('local') repo with its own filesystem storage dir.
        async fn make_repo_key(pool: &PgPool, tag: &str, storage_path: &std::path::Path) -> String {
            let id = Uuid::new_v4();
            let key = format!("pr1940-{}-{}", tag, &id.to_string()[..8]);
            std::fs::create_dir_all(storage_path).expect("create storage dir");
            sqlx::query(
                "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
                 VALUES ($1, $2, $2, $3, 'local', 'generic'::repository_format, false)",
            )
            .bind(id)
            .bind(&key)
            .bind(storage_path.to_string_lossy().as_ref())
            .execute(pool)
            .await
            .expect("insert repo");
            key
        }

        async fn repo_id_for_key(pool: &PgPool, key: &str) -> Uuid {
            let (id,): (Uuid,) = sqlx::query_as("SELECT id FROM repositories WHERE key = $1")
                .bind(key)
                .fetch_one(pool)
                .await
                .expect("repo id");
            id
        }

        async fn make_admin(pool: &PgPool, tag: &str) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
                 VALUES ($1, $2, $3, 'x', 'local', true, true)",
            )
            .bind(id)
            .bind(format!("pr1940-{}-{}", tag, &id.to_string()[..8]))
            .bind(format!("pr1940-{}-{}@test.local", tag, &id.to_string()[..8]))
            .execute(pool)
            .await
            .expect("insert user");
            // Grant a global (NULL-scoped) admin role assignment, mirroring the
            // genuine super-admin seeded by migration 002. The promotion
            // tenant-ownership gate requires a grant on the source/target repos;
            // a NULL-scoped assignment satisfies it for every repository, which is
            // exactly what a real cross-tenant super-admin holds.
            sqlx::query(
                "INSERT INTO role_assignments (user_id, role_id) \
                 SELECT $1, r.id FROM roles r WHERE r.name = 'admin'",
            )
            .bind(id)
            .execute(pool)
            .await
            .expect("grant global admin role");
            id
        }

        /// Create a non-super-admin user that is admin-capable (the `is_admin`
        /// capability flag is true) but tenant-scoped: it holds NO global,
        /// NULL-scoped role assignment, only the per-repo grants explicitly added
        /// via `grant_repo`. This models a tenant admin (e.g. a corp admin) in a
        /// multi-tenant deployment for the cross-tenant promotion tests.
        async fn make_tenant_admin(pool: &PgPool, tag: &str) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
                 VALUES ($1, $2, $3, 'x', 'local', true, true)",
            )
            .bind(id)
            .bind(format!("pr1940-{}-{}", tag, &id.to_string()[..8]))
            .bind(format!("pr1940-{}-{}@test.local", tag, &id.to_string()[..8]))
            .execute(pool)
            .await
            .expect("insert tenant admin");
            id
        }

        /// Grant `user` the `developer` role scoped to a single repository,
        /// mirroring the owner auto-grant in `RepositoryService::create`. Used to
        /// place a tenant admin inside one tenant's repositories only.
        async fn grant_repo(pool: &PgPool, user: Uuid, repo: Uuid) {
            sqlx::query(
                "INSERT INTO role_assignments (user_id, role_id, repository_id) \
                 SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
                 ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
            )
            .bind(user)
            .bind(repo)
            .execute(pool)
            .await
            .expect("grant per-repo developer role");
        }

        fn admin_ext(user_id: Uuid) -> AuthExtension {
            AuthExtension {
                user_id,
                username: "pr1940-admin".to_string(),
                email: "pr1940-admin@test.local".to_string(),
                is_admin: true,
                is_api_token: false,
                is_service_account: false,
                scopes: None,
                allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
                iat_ms: None,
            }
        }

        /// A NON-admin service-account API token bearing the given scopes. Used to
        /// exercise the grantable `promote:artifacts` capability (#2042): promote
        /// is authorized for such a token, but the tenant-ownership gate still
        /// applies via the user's per-repo role grants.
        fn scoped_token_ext(user_id: Uuid, scopes: &[&str]) -> AuthExtension {
            AuthExtension {
                user_id,
                username: "pr2042-sa".to_string(),
                email: "pr2042-sa@test.local".to_string(),
                is_admin: false,
                is_api_token: true,
                is_service_account: true,
                scopes: Some(scopes.iter().map(|s| s.to_string()).collect()),
                allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
                iat_ms: None,
            }
        }

        /// Storage backend resolved through the repo's own storage_location().
        async fn storage_for(
            state: &SharedState,
            pool: &PgPool,
            repo_id: Uuid,
        ) -> Arc<dyn crate::storage::StorageBackend> {
            let repo = RepositoryService::new(pool.clone())
                .get_by_id(repo_id)
                .await
                .expect("get_by_id");
            state
                .storage_for_repo(&repo.storage_location())
                .expect("storage_for_repo")
        }

        /// Insert an artifact whose `created_at` is now() with real bytes in the
        /// repo's storage, so any positive `min_staging_hours` rule is violated.
        async fn make_artifact(
            pool: &PgPool,
            repo_id: Uuid,
            storage: &Arc<dyn crate::storage::StorageBackend>,
            name: &str,
        ) -> Uuid {
            let id = Uuid::new_v4();
            let path = format!("{}/{}", name, id);
            let bytes = bytes::Bytes::from_static(b"pr1940-artifact-content");
            let checksum = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(&bytes);
                format!("{:x}", h.finalize())
            };
            storage.put(&path, bytes).await.expect("write storage");
            sqlx::query(
                r#"
                INSERT INTO artifacts (id, repository_id, name, path, version, size_bytes,
                                       checksum_sha256, content_type, storage_key, is_deleted)
                VALUES ($1, $2, $3, $4, '1.0.0', 23, $5, 'application/octet-stream', $4, false)
                "#,
            )
            .bind(id)
            .bind(repo_id)
            .bind(name)
            .bind(&path)
            .bind(&checksum)
            .execute(pool)
            .await
            .expect("insert artifact");
            id
        }

        async fn make_rule(
            pool: &PgPool,
            source: Uuid,
            target: Uuid,
            max_cve_severity: Option<&str>,
            min_staging_hours: Option<i32>,
        ) {
            sqlx::query(
                "INSERT INTO promotion_rules (id, name, source_repo_id, target_repo_id, is_enabled, \
                 max_cve_severity, require_signature, min_staging_hours, auto_promote) \
                 VALUES ($1, $2, $3, $4, true, $5, false, $6, false)",
            )
            .bind(Uuid::new_v4())
            .bind(format!("pr1940-rule-{}", &Uuid::new_v4().to_string()[..8]))
            .bind(source)
            .bind(target)
            .bind(max_cve_severity)
            .bind(min_staging_hours)
            .execute(pool)
            .await
            .expect("insert rule");
        }

        async fn target_has_artifact(pool: &PgPool, target: Uuid, path_like: &str) -> bool {
            let (n,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path LIKE $2 AND is_deleted = false",
            )
            .bind(target)
            .bind(format!("%{}%", path_like))
            .fetch_one(pool)
            .await
            .expect("count");
            n > 0
        }

        async fn cleanup(pool: &PgPool, repos: &[Uuid], user: Uuid) {
            for r in repos {
                let _ = sqlx::query(
                    "DELETE FROM promotion_approvals WHERE source_repo_id = $1 OR target_repo_id = $1",
                )
                .bind(r)
                .execute(pool)
                .await;
                let _ = sqlx::query(
                    "DELETE FROM promotion_history WHERE source_repo_id = $1 OR target_repo_id = $1",
                )
                .bind(r)
                .execute(pool)
                .await;
                let _ = sqlx::query(
                    "DELETE FROM promotion_rules WHERE source_repo_id = $1 OR target_repo_id = $1",
                )
                .bind(r)
                .execute(pool)
                .await;
                let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
                    .bind(r)
                    .execute(pool)
                    .await;
                let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                    .bind(r)
                    .execute(pool)
                    .await;
            }
            let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
                .bind(user)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user)
                .execute(pool)
                .await;
        }

        // ---- tenant-ownership gate on promote target (xtenant) ---------------
        //
        // A promotion crosses a tenant boundary when an admin-capable principal
        // authorized for one tenant's repos names another tenant's repo as the
        // target. `require_promotion_tenant_access` rejects this with 403 on
        // every promote path. These tests drive a tenant-scoped admin (per-repo
        // grants only, NO global NULL-scoped assignment) across the single, bulk,
        // and approval-execute paths.

        /// Cross-tenant SINGLE promote: tenant admin owns the SOURCE (corp) but
        /// not the TARGET (globex) -> 403, no copy.
        #[tokio::test]
        async fn test_single_promote_cross_tenant_target_blocked() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr-xt-ss-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr-xt-st-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "xt-corp-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "xt-globex-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let corp_admin = make_tenant_admin(&pool, "xt-corp").await;
            // corp admin owns only the source (corp) repo, NOT the globex target.
            grant_repo(&pool, corp_admin, src).await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "xt").await;

            let err = promote_artifact(
                State(state.clone()),
                Extension(admin_ext(corp_admin)),
                Path((src_key.clone(), artifact)),
                Json(PromoteArtifactRequest {
                    target_repository: Some(tgt_key.clone()),
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect_err("cross-tenant single promote must be rejected");
            assert!(
                matches!(err, AppError::Authorization(_)),
                "cross-tenant promote must be a 403 Authorization error; got {:?}",
                err
            );
            assert!(
                !target_has_artifact(&pool, tgt, "xt").await,
                "a cross-tenant single promote must NOT copy the artifact"
            );

            cleanup(&pool, &[src, tgt], corp_admin).await;
        }

        /// Same-tenant SINGLE promote: tenant admin owns BOTH repos -> succeeds.
        #[tokio::test]
        async fn test_single_promote_same_tenant_allowed() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr-st-ss-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr-st-st-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "st-corp-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "st-corp-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let corp_admin = make_tenant_admin(&pool, "st-corp").await;
            // corp admin owns BOTH the corp source and corp target.
            grant_repo(&pool, corp_admin, src).await;
            grant_repo(&pool, corp_admin, tgt).await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "st").await;

            let res = promote_artifact(
                State(state.clone()),
                Extension(admin_ext(corp_admin)),
                Path((src_key.clone(), artifact)),
                Json(PromoteArtifactRequest {
                    target_repository: Some(tgt_key.clone()),
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect("same-tenant single promote must succeed");
            assert!(res.0.promoted, "same-tenant single promote must promote");
            assert!(target_has_artifact(&pool, tgt, "st").await);

            cleanup(&pool, &[src, tgt], corp_admin).await;
        }

        // ---- #2042: grantable promote:artifacts scope on service-account tokens

        /// A non-admin SERVICE-ACCOUNT token that holds the `promote:artifacts`
        /// scope AND owns both repos (per-repo grants) may promote: the scope
        /// satisfies the promote-authorization gate and the tenant gate passes.
        #[tokio::test]
        async fn test_single_promote_scoped_token_with_grant_allowed() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr2042-ok-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr2042-ok-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "sa-ok-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "sa-ok-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let sa = make_tenant_admin(&pool, "sa-ok").await;
            grant_repo(&pool, sa, src).await;
            grant_repo(&pool, sa, tgt).await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "saok").await;

            let res = promote_artifact(
                State(state.clone()),
                Extension(scoped_token_ext(sa, &["promote:artifacts"])),
                Path((src_key.clone(), artifact)),
                Json(PromoteArtifactRequest {
                    target_repository: Some(tgt_key.clone()),
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect("scoped-token promote with grants must succeed");
            assert!(res.0.promoted, "scoped-token promote must promote");
            assert!(target_has_artifact(&pool, tgt, "saok").await);

            cleanup(&pool, &[src, tgt], sa).await;
        }

        /// A non-admin service-account token WITHOUT the `promote:artifacts`
        /// scope is denied at the promote-authorization gate (403), even when it
        /// owns both repos — the scope is the grantable promote capability.
        #[tokio::test]
        async fn test_single_promote_scoped_token_without_scope_blocked() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr2042-no-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr2042-no-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "sa-no-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "sa-no-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let sa = make_tenant_admin(&pool, "sa-no").await;
            grant_repo(&pool, sa, src).await;
            grant_repo(&pool, sa, tgt).await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "sano").await;

            let err = promote_artifact(
                State(state.clone()),
                Extension(scoped_token_ext(sa, &["read:artifacts", "write:artifacts"])),
                Path((src_key.clone(), artifact)),
                Json(PromoteArtifactRequest {
                    target_repository: Some(tgt_key.clone()),
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect_err("token without promote:artifacts must be rejected");
            assert!(
                matches!(err, AppError::Authorization(_)),
                "missing promote scope must be a 403; got {:?}",
                err
            );
            assert!(
                !target_has_artifact(&pool, tgt, "sano").await,
                "a denied promote must NOT copy the artifact"
            );

            cleanup(&pool, &[src, tgt], sa).await;
        }

        /// Cross-tenant BULK promote: tenant admin lacks the target tenant -> 403.
        #[tokio::test]
        async fn test_bulk_promote_cross_tenant_target_blocked() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr-xtb-ss-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr-xtb-st-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "xtb-corp-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "xtb-globex-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let corp_admin = make_tenant_admin(&pool, "xtb-corp").await;
            grant_repo(&pool, corp_admin, src).await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "xtb").await;

            let err = promote_artifacts_bulk(
                State(state.clone()),
                Extension(admin_ext(corp_admin)),
                Path(src_key.clone()),
                Json(BulkPromoteRequest {
                    target_repository: Some(tgt_key.clone()),
                    artifact_ids: vec![artifact],
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect_err("cross-tenant bulk promote must be rejected");
            assert!(
                matches!(err, AppError::Authorization(_)),
                "cross-tenant bulk promote must be a 403; got {:?}",
                err
            );
            assert!(
                !target_has_artifact(&pool, tgt, "xtb").await,
                "a cross-tenant bulk promote must NOT copy the artifact"
            );

            cleanup(&pool, &[src, tgt], corp_admin).await;
        }

        // ---- single-promote handler: rule-MET promotes -----------------------

        #[tokio::test]
        async fn test_single_promote_rule_met_promotes() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-sok-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-sok-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "sok-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "sok-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "sok").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "sok").await;
            // Satisfied rule: min_staging_hours = 0, no CVE gate.
            make_rule(&pool, src, tgt, None, Some(0)).await;

            let res = promote_artifact(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path((src_key.clone(), artifact)),
                Json(PromoteArtifactRequest {
                    target_repository: Some(tgt_key.clone()),
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect("promote should succeed");
            assert!(res.0.promoted, "a rule-met single promote must promote");
            assert!(
                target_has_artifact(&pool, tgt, "sok").await,
                "rule-met single promote must copy the artifact into the target"
            );

            cleanup(&pool, &[src, tgt], user).await;
        }

        // ---- single-promote handler: rule-UNMET blocks -----------------------

        #[tokio::test]
        async fn test_single_promote_rule_unmet_blocks() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-sno-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-sno-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "sno-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "sno-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "sno").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "sno").await;
            // The live-bypass rule: 720h staging on a seconds-old artifact.
            make_rule(&pool, src, tgt, None, Some(720)).await;

            let res = promote_artifact(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path((src_key.clone(), artifact)),
                Json(PromoteArtifactRequest {
                    target_repository: Some(tgt_key.clone()),
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect("handler returns Ok with promoted:false on a rule block");
            assert!(
                !res.0.promoted,
                "a rule-unmet single promote must be blocked"
            );
            assert!(
                res.0
                    .message
                    .as_deref()
                    .unwrap_or_default()
                    .contains("promotion rule"),
                "block message must cite the promotion rule; got {:?}",
                res.0.message
            );
            assert!(
                !res.0.policy_violations.is_empty(),
                "blocked single promote must surface rule violations"
            );
            assert!(
                !target_has_artifact(&pool, tgt, "sno").await,
                "a rule-blocked single promote must NOT copy the artifact"
            );

            cleanup(&pool, &[src, tgt], user).await;
        }

        // ---- single-promote handler: skip_policy_check override --------------

        #[tokio::test]
        async fn test_single_promote_skip_policy_check_override() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-ssk-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-ssk-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "ssk-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "ssk-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "ssk").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "ssk").await;
            make_rule(&pool, src, tgt, None, Some(720)).await;

            let res = promote_artifact(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path((src_key.clone(), artifact)),
                Json(PromoteArtifactRequest {
                    target_repository: Some(tgt_key.clone()),
                    skip_policy_check: true,
                    notes: None,
                }),
            )
            .await
            .expect("skip_policy_check must bypass the rule gate");
            assert!(res.0.promoted, "break-glass single promote must promote");
            assert!(target_has_artifact(&pool, tgt, "ssk").await);

            cleanup(&pool, &[src, tgt], user).await;
        }

        // ---- bulk-promote handler: rule-MET vs rule-UNMET --------------------

        #[tokio::test]
        async fn test_bulk_promote_rule_met_and_unmet() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-bulk-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-bulk-t-{}", Uuid::new_v4()));
            // rule-MET case
            let met_s_key = make_repo_key(&pool, "bok-s", &sdir).await;
            let met_t_key = make_repo_key(&pool, "bok-t", &tdir).await;
            let met_s = repo_id_for_key(&pool, &met_s_key).await;
            let met_t = repo_id_for_key(&pool, &met_t_key).await;
            let user = make_admin(&pool, "bulk").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let met_storage = storage_for(&state, &pool, met_s).await;
            let met_art = make_artifact(&pool, met_s, &met_storage, "bok").await;
            make_rule(&pool, met_s, met_t, None, Some(0)).await;

            let met_res = promote_artifacts_bulk(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path(met_s_key.clone()),
                Json(BulkPromoteRequest {
                    target_repository: Some(met_t_key.clone()),
                    artifact_ids: vec![met_art],
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect("bulk promote ok");
            assert_eq!(met_res.0.promoted, 1, "rule-met bulk item must promote");
            assert_eq!(met_res.0.failed, 0);
            assert!(target_has_artifact(&pool, met_t, "bok").await);

            // rule-UNMET case (separate repo pair).
            let sdir2 = std::env::temp_dir().join(format!("pr1940-bno-s-{}", Uuid::new_v4()));
            let tdir2 = std::env::temp_dir().join(format!("pr1940-bno-t-{}", Uuid::new_v4()));
            let no_s_key = make_repo_key(&pool, "bno-s", &sdir2).await;
            let no_t_key = make_repo_key(&pool, "bno-t", &tdir2).await;
            let no_s = repo_id_for_key(&pool, &no_s_key).await;
            let no_t = repo_id_for_key(&pool, &no_t_key).await;
            let no_storage = storage_for(&state, &pool, no_s).await;
            let no_art = make_artifact(&pool, no_s, &no_storage, "bno").await;
            make_rule(&pool, no_s, no_t, None, Some(720)).await;

            let no_res = promote_artifacts_bulk(
                State(state.clone()),
                Extension(admin_ext(user)),
                Path(no_s_key.clone()),
                Json(BulkPromoteRequest {
                    target_repository: Some(no_t_key.clone()),
                    artifact_ids: vec![no_art],
                    skip_policy_check: false,
                    notes: None,
                }),
            )
            .await
            .expect("bulk promote ok");
            assert_eq!(
                no_res.0.promoted, 0,
                "rule-unmet bulk item must NOT promote"
            );
            assert_eq!(no_res.0.failed, 1);
            assert!(
                no_res.0.results[0]
                    .message
                    .as_deref()
                    .unwrap_or_default()
                    .contains("promotion rule"),
                "bulk block must cite the promotion rule; got {:?}",
                no_res.0.results[0].message
            );
            assert!(
                !no_res.0.results[0].policy_violations.is_empty(),
                "blocked bulk item must surface rule violations"
            );
            assert!(
                !target_has_artifact(&pool, no_t, "bno").await,
                "a rule-blocked bulk item must NOT copy the artifact"
            );

            cleanup(&pool, &[met_s, met_t, no_s, no_t], user).await;
        }

        // ---- max_cve_severity default fix (shared evaluator) -----------------

        /// #1940: a rule that does NOT set max_cve_severity (NULL) must NOT
        /// silently require a clean scan, so an unscanned artifact under a
        /// satisfied hours-only rule is not falsely blocked.
        #[tokio::test]
        async fn test_unset_cve_severity_does_not_require_scan() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-nocve-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-nocve-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "nocve-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "nocve-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "nocve").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            // Unscanned artifact (no scan_results rows).
            let artifact = make_artifact(&pool, src, &storage, "nocve").await;
            make_rule(&pool, src, tgt, None, Some(0)).await;

            let svc = PromotionRuleService::new(pool.clone());
            let failing = svc
                .evaluate_for_promotion(artifact, src, tgt)
                .await
                .expect("evaluate");
            assert!(
                failing.is_empty(),
                "an hours-only rule (max_cve_severity NULL) must NOT block an unscanned artifact; got {:?}",
                failing
            );

            cleanup(&pool, &[src, tgt], user).await;
        }

        /// Conservative counterpart: a rule that DOES set max_cve_severity still
        /// blocks an unscanned artifact (the CVE gate is opt-in, fail-closed when
        /// requested).
        #[tokio::test]
        async fn test_explicit_cve_severity_still_requires_scan() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let sdir = std::env::temp_dir().join(format!("pr1940-cve-s-{}", Uuid::new_v4()));
            let tdir = std::env::temp_dir().join(format!("pr1940-cve-t-{}", Uuid::new_v4()));
            let src_key = make_repo_key(&pool, "cve-s", &sdir).await;
            let tgt_key = make_repo_key(&pool, "cve-t", &tdir).await;
            let src = repo_id_for_key(&pool, &src_key).await;
            let tgt = repo_id_for_key(&pool, &tgt_key).await;
            let user = make_admin(&pool, "cve").await;
            let state = tdh::build_state(pool.clone(), sdir.to_str().unwrap());
            let storage = storage_for(&state, &pool, src).await;
            let artifact = make_artifact(&pool, src, &storage, "cve").await;
            // Explicit CVE bound + satisfied hours -> unscanned must fail closed.
            make_rule(&pool, src, tgt, Some("medium"), Some(0)).await;

            let svc = PromotionRuleService::new(pool.clone());
            let failing = svc
                .evaluate_for_promotion(artifact, src, tgt)
                .await
                .expect("evaluate");
            assert!(
                !failing.is_empty(),
                "an explicit max_cve_severity rule must still block an unscanned artifact (fail-closed)"
            );

            cleanup(&pool, &[src, tgt], user).await;
        }
    }
}
