//! Age-based quality gate for supported remote proxy registries.
//!
//! npm and PyPI support upstream publish time and first-seen policy; Go
//! supports first-seen policy. Direct Remote repositories are evaluated
//! directly. Virtual repositories apply the policy of the Remote member that
//! supplied metadata or content, while Local members remain ungated.

use std::borrow::Cow;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::event_bus::EventBus;
use crate::services::metrics_service;
use crate::services::upstream_metadata::UpstreamMetadataCache;

pub const AUTO_APPROVE_REASON: &str = "auto-approved: crossed age threshold";

/// Debounce window (seconds) for re-bumping a review's `request_count` /
/// `last_requested_at` on the metadata listing path. Within this window, repeat
/// listings of the same package skip the per-version write
const REQUEST_COUNT_DEBOUNCE_SECS: i64 = 3600;

/// Where a repository's cooldown clock starts (#2264 / #1558 follow-up).
///
/// The mode is part of the gate's policy identity: a basis measured under one
/// mode (or against one upstream) never satisfies a policy configured with the
/// other — see [`review_identity_match`]. Keeping the two sources distinct
/// means a repository configured for `first_seen` never quietly reverts to
/// publish time because an upstream timestamp happens to be available, and a
/// repository configured for `upstream_publish_time` blocks (rather than
/// substituting a local observation) when that timestamp is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgeGateMode {
    /// The upstream registry's reported publish timestamp (the #2066 model).
    /// Only as trustworthy as the registry serving it.
    #[default]
    UpstreamPublishTime,
    /// The first time this server observed the version for this repository.
    /// Needs no upstream metadata and cannot be backdated by a publisher, at
    /// the cost of measuring local freshness rather than true package age:
    /// every version of a package is "new" the first time the repository
    /// sees it, including versions that are objectively ancient.
    FirstSeen,
}

impl AgeGateMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamPublishTime => "upstream_publish_time",
            Self::FirstSeen => "first_seen",
        }
    }

    /// Parse the DB/API representation. Unknown values are a client error,
    /// never a silent fall back to the default mode.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "upstream_publish_time" => Ok(Self::UpstreamPublishTime),
            "first_seen" => Ok(Self::FirstSeen),
            other => Err(AppError::Validation(format!(
                "Unknown age gate mode '{other}': expected 'upstream_publish_time' or 'first_seen'"
            ))),
        }
    }
}

/// Minimal repository view for age-gate decisions (avoids handler ↔ service coupling).
#[derive(Debug, Clone)]
pub struct AgeGateRepoParams {
    pub id: Uuid,
    /// Repository key, used as the bounded `repository` label on age-gate metrics.
    pub key: String,
    pub repo_type: RepositoryType,
    pub format: RepositoryFormat,
    pub age_gate_enabled: bool,
    pub age_gate_min_age_days: i32,
    pub age_gate_mode: AgeGateMode,
    /// The upstream this repository proxies. Identifies which registry a
    /// `first_seen` observation was made against (see [`upstream_fingerprint`]).
    pub upstream_url: Option<String>,
}

impl AgeGateRepoParams {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: Uuid,
        key: impl Into<String>,
        repo_type: RepositoryType,
        format: RepositoryFormat,
        age_gate_enabled: bool,
        age_gate_min_age_days: i32,
        age_gate_mode: AgeGateMode,
        upstream_url: Option<String>,
    ) -> Self {
        Self {
            id,
            key: key.into(),
            repo_type,
            format,
            age_gate_enabled,
            age_gate_min_age_days,
            age_gate_mode,
            upstream_url,
        }
    }
}

/// Resolve a repository's age-gate policy inputs from the database, by id.
///
/// For callers holding a `Repository` model rather than a resolved `RepoInfo`
/// row (e.g. the npm virtual-member metadata loop): the model deliberately
/// does NOT carry `age_gate_mode`, so policy inputs are re-read from the
/// source of truth instead of being derived from whatever struct is in hand.
/// A missing row or a failed read is an error: a repository whose
/// configuration cannot be read must fail the request, never impersonate
/// `enabled = false`.
pub async fn resolve_repo_params(db: &PgPool, repository_id: Uuid) -> Result<AgeGateRepoParams> {
    use sqlx::Row as _;

    let row = sqlx::query(
        "SELECT key, repo_type, format, \
         age_gate_enabled, age_gate_min_age_days, age_gate_mode, upstream_url \
         FROM repositories WHERE id = $1",
    )
    .bind(repository_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| {
        AppError::NotFound(format!(
            "Repository {repository_id} not found for age-gate resolution"
        ))
    })?;

    let column = |e: sqlx::Error| AppError::Database(e.to_string());

    Ok(AgeGateRepoParams::from_parts(
        repository_id,
        row.try_get::<String, _>("key").map_err(column)?,
        row.try_get::<RepositoryType, _>("repo_type")
            .map_err(column)?,
        AgeGateService::normalize_format(
            row.try_get::<RepositoryFormat, _>("format")
                .map_err(column)?,
        ),
        row.try_get::<bool, _>("age_gate_enabled").map_err(column)?,
        row.try_get::<i32, _>("age_gate_min_age_days")
            .map_err(column)?,
        AgeGateMode::parse(&row.try_get::<String, _>("age_gate_mode").map_err(column)?)?,
        row.try_get::<Option<String>, _>("upstream_url")
            .map_err(column)?,
    ))
}

/// Identify the upstream a `first_seen` observation was made against.
///
/// Part of the observation's primary key: an observation says "this server
/// first saw version V of package P *from this upstream* at time T", and that
/// statement is void if the repository is later repointed at a different
/// registry. Binding the identity to the upstream means a repoint starts a
/// fresh clock by construction, instead of requiring every repository-update
/// path to remember to invalidate observations.
pub fn upstream_fingerprint(upstream_url: Option<&str>) -> String {
    let normalized = normalize_upstream_url(upstream_url.unwrap_or_default());
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

/// Normalize an upstream URL so that cosmetically different spellings of the
/// same registry (trailing slash, upper-case host, explicit default port)
/// share one fingerprint. Paths keep their case: most registries are
/// case-sensitive there. An unparseable value is fingerprinted as-is rather
/// than being coerced into a shared bucket.
pub(crate) fn normalize_upstream_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    match url::Url::parse(trimmed) {
        // `Url` lower-cases the scheme and host and drops a default port; its
        // serialization re-adds the root path, which we trim back off.
        Ok(parsed) => parsed.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.to_string(),
    }
}

/// Review queue status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgeGateReviewStatus {
    Pending,
    Approved,
    Rejected,
}

impl AgeGateReviewStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

/// How an existing review row's recorded basis identity relates to the
/// repository's current policy (mode + normalized upstream fingerprint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewIdentityMatch {
    /// Recorded under exactly the current (mode, upstream) identity.
    Matches,
    /// Recorded under a different mode or upstream. A basis or decision from
    /// a different identity must never satisfy the current policy.
    Differs,
    /// Pre-identity row (both columns NULL, written before migration 191).
    /// Manual decisions from that era keep their effect — administrators made
    /// them and there is no recorded identity to contradict; automatic
    /// approvals do not, because they are recomputable bookkeeping.
    Legacy,
}

/// Policy-relevant view of an existing review row, decoupled from the row
/// shape so [`decide_age_gate_check`] stays a pure function.
#[derive(Debug, Clone)]
pub(crate) struct ReviewPolicyView {
    pub status: String,
    /// `reviewed_by IS NULL`: approved by the automatic threshold machinery
    /// (request path or background sweep), not an administrator. Automatic
    /// approvals are never sticky — they are re-derived from the current
    /// basis, threshold, and upstream on every decision.
    pub is_automatic: bool,
    pub identity: ReviewIdentityMatch,
}

/// Compare a review row's recorded basis identity against the current policy.
pub(crate) fn review_identity_match(
    basis_mode: Option<&str>,
    basis_fingerprint: Option<&str>,
    current_mode: AgeGateMode,
    current_fingerprint: &str,
) -> ReviewIdentityMatch {
    match (basis_mode, basis_fingerprint) {
        (None, None) => ReviewIdentityMatch::Legacy,
        (Some(mode), Some(fp)) if mode == current_mode.as_str() && fp == current_fingerprint => {
            ReviewIdentityMatch::Matches
        }
        _ => ReviewIdentityMatch::Differs,
    }
}

/// Side-effect-free outcome of evaluating a single-version age gate check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgeGateCheckAction {
    Allow,
    BlockRejected,
    AllowAndAutoApprovePending,
    AllowAlreadyApproved,
    BlockAndRequestReview,
    /// The row carries a decision the current policy must not honor (an
    /// automatic approval, or a manual approval bound to a different
    /// identity): void it back to pending under the current basis and
    /// identity, and block.
    BlockAndResetReview,
}

/// Pure state machine for [`AgeGateService::check`]: maps the existing review
/// row (if any) and whether the version meets the age threshold *on the
/// current clock* to the action the impure wrapper should take (DB writes,
/// metrics, LKG lookup).
///
/// The rules, in order:
///
/// * a rejection blocks coordinate-wide — deliberately conservative: an
///   administrator said "not this version", and a mode switch or repoint
///   should not quietly unblock it (since #2968, `reopen` is the sanctioned
///   unblock path);
/// * a version that meets the threshold on the current basis is allowed —
///   the basis passed in was resolved under the current policy, so this is
///   the authoritative recomputation that makes automatic approvals inert as
///   status (a pending row is retired to `approved` on the way through);
/// * below the threshold, only a *manual* approval whose identity matches the
///   current policy (or a pre-identity legacy manual approval) still allows;
/// * a manual approval under a different identity, or any automatic
///   approval that no longer holds (raised threshold, switched mode,
///   repointed upstream, legacy row), is voided back to pending and blocks;
/// * anything else blocks and records/bumps the pending review.
pub(crate) fn decide_age_gate_check(
    existing: Option<&ReviewPolicyView>,
    meets_threshold: bool,
) -> AgeGateCheckAction {
    if let Some(review) = existing {
        if review.status == AgeGateReviewStatus::Rejected.as_str() {
            return AgeGateCheckAction::BlockRejected;
        }
    }
    if meets_threshold {
        if existing.is_some_and(|r| r.status == AgeGateReviewStatus::Pending.as_str()) {
            return AgeGateCheckAction::AllowAndAutoApprovePending;
        }
        return AgeGateCheckAction::Allow;
    }
    match existing {
        Some(review) if review.status == AgeGateReviewStatus::Approved.as_str() => {
            if !review.is_automatic && review.identity != ReviewIdentityMatch::Differs {
                AgeGateCheckAction::AllowAlreadyApproved
            } else {
                AgeGateCheckAction::BlockAndResetReview
            }
        }
        _ => AgeGateCheckAction::BlockAndRequestReview,
    }
}

/// Per-version classification output for metadata listing (npm packument / PyPI simple index).
#[derive(Debug, Clone, Default)]
pub(crate) struct MetadataListingClassification {
    pub blocked: std::collections::HashSet<String>,
    pub request_versions: Vec<String>,
    pub request_times: Vec<Option<DateTime<Utc>>>,
}

/// One existing review row as loaded for a whole-package batch evaluation.
#[derive(Debug, Clone)]
pub(crate) struct PackageReviewRow {
    pub status: String,
    /// `reviewed_by IS NULL` — see [`ReviewPolicyView::is_automatic`].
    pub is_automatic: bool,
    pub basis_mode: Option<String>,
    pub basis_upstream_fingerprint: Option<String>,
}

/// Classify every version in a metadata document without I/O. Used by
/// [`AgeGateService::evaluate_versions_batch`].
///
/// Applies the same rules as [`decide_age_gate_check`], so a version withheld
/// from a listing is refused on direct download and vice versa: rejections
/// block coordinate-wide; the current-clock threshold decides; below the
/// threshold only an identity-bound (or legacy) *manual* approval still
/// lists. A stale approval — automatic, or manual under a different identity
/// — is withheld and re-requested; the batch upsert voids it back to pending.
pub(crate) fn classify_versions_for_metadata_listing(
    versions: &[(String, Option<DateTime<Utc>>)],
    existing_reviews: &std::collections::HashMap<String, PackageReviewRow>,
    min_age_days: i32,
    current_mode: AgeGateMode,
    current_fingerprint: &str,
    now: DateTime<Utc>,
) -> MetadataListingClassification {
    let mut out = MetadataListingClassification::default();
    for (version, published_at) in versions {
        let existing_review = existing_reviews.get(version);

        if let Some(review) = existing_review {
            if review.status == AgeGateReviewStatus::Rejected.as_str() {
                out.blocked.insert(version.clone());
                continue;
            }
        }

        if AgeGateService::meets_age_threshold(*published_at, min_age_days, now) {
            continue;
        }

        if let Some(review) = existing_review {
            if review.status == AgeGateReviewStatus::Approved.as_str()
                && !review.is_automatic
                && review_identity_match(
                    review.basis_mode.as_deref(),
                    review.basis_upstream_fingerprint.as_deref(),
                    current_mode,
                    current_fingerprint,
                ) != ReviewIdentityMatch::Differs
            {
                continue;
            }
        }

        out.blocked.insert(version.clone());
        out.request_versions.push(version.clone());
        out.request_times.push(*published_at);
    }
    out
}

/// Validate `min_age_days` is within the allowed range (mirrors DB CHECK).
pub fn validate_min_age_days(min_age_days: i32) -> Result<()> {
    // 0 is the trusted-remote setting from #1558: no age delay, but explicit
    // rejections still block and the review queue stays under admin control —
    // which `age_gate_enabled = false` does NOT provide (a disabled gate also
    // stops honoring rejections).
    if !(0..=3650).contains(&min_age_days) {
        return Err(AppError::Validation(
            "min_age_days must be between 0 and 3650".to_string(),
        ));
    }
    Ok(())
}

/// Guard a review state transition. Errors when the review is already in the
/// requested target state (a no-op transition), otherwise allows the change.
///
/// Reviews are no longer terminal: an admin can approve, reject, or reopen a
/// review from ANY current state (e.g. re-block a previously-approved package
/// by rejecting it, or re-approve a previously-rejected one). The only refused
/// transition is one that would not change anything.
pub(crate) fn require_distinct_status(current: &str, target: AgeGateReviewStatus) -> Result<()> {
    if current == target.as_str() {
        return Err(AppError::Validation(format!(
            "Review is already {}",
            target.as_str()
        )));
    }
    Ok(())
}

/// Outcome of an age-gate check for a single package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgeGateDecision {
    Allow,
    Block {
        review_id: Uuid,
        last_known_good: Option<LastKnownGood>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastKnownGood {
    pub version: String,
    pub artifact_path: String,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AgeGateReview {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub package_name: String,
    pub package_version: String,
    pub upstream_published_at: Option<DateTime<Utc>>,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_reason: Option<String>,
    pub request_count: i32,
    pub last_requested_at: DateTime<Utc>,
    /// The (mode, upstream) identity the recorded basis was resolved under
    /// (migration 191). NULL on pre-identity rows; see [`ReviewIdentityMatch`].
    #[sqlx(default)]
    pub basis_mode: Option<String>,
    #[sqlx(default)]
    pub basis_upstream_fingerprint: Option<String>,
    #[sqlx(default)]
    pub repository_key: Option<String>,
}

pub struct AgeGateService {
    db: PgPool,
    event_bus: Arc<EventBus>,
    metadata_cache: UpstreamMetadataCache,
}

impl AgeGateService {
    pub fn new(db: PgPool, event_bus: Arc<EventBus>) -> Self {
        Self {
            db,
            event_bus,
            metadata_cache: UpstreamMetadataCache::new(),
        }
    }

    pub fn metadata_cache(&self) -> &UpstreamMetadataCache {
        &self.metadata_cache
    }

    /// Whether an operator has asked for gating on this repository at
    /// all: a Remote repository with the gate enabled.
    ///
    /// Deliberately separate from [`Self::supports_format_mode`]. Supported
    /// handlers use [`Self::require_enforceable`] after this check so an
    /// invalid mode cannot silently bypass policy. Formats outside the
    /// capability matrix have no age-gate handler hook, and the config
    /// endpoint rejects attempts to enable them.
    pub fn gating_requested(repo: &AgeGateRepoParams) -> bool {
        repo.repo_type == RepositoryType::Remote && repo.age_gate_enabled
    }

    /// Fail closed when a repository's enabled gate cannot actually be
    /// enforced for its (format, mode) pair. Callers check
    /// [`Self::gating_requested`] first; a repository that never asked for
    /// gating is simply not applicable.
    pub fn require_enforceable(repo: &AgeGateRepoParams) -> Result<()> {
        if Self::supports_format_mode(&repo.format, repo.age_gate_mode) {
            return Ok(());
        }
        Err(AppError::Internal(format!(
            "age gate is enabled for repository '{}' but cannot be enforced for \
             format {:?} in '{}' mode; failing closed",
            repo.key,
            repo.format,
            repo.age_gate_mode.as_str()
        )))
    }

    /// Whether the age gate applies to this repository (requested AND
    /// enforceable). Read-only helpers use this; enforcement paths must use
    /// [`Self::gating_requested`] + [`Self::require_enforceable`] so an
    /// enabled-but-unenforceable configuration errors instead of passing.
    pub fn is_applicable(repo: &AgeGateRepoParams) -> bool {
        Self::gating_requested(repo) && Self::supports_format_mode(&repo.format, repo.age_gate_mode)
    }

    /// The enforceable (format, mode) matrix, derived from the single
    /// per-format capability registry ([`crate::formats::age_gate_spec`]):
    ///
    /// - `first_seen` requires immutable upstream coordinates — an
    ///   observation binds elapsed time to a (package, version) name, which
    ///   only means something when the upstream cannot substitute new content
    ///   under that name;
    /// - `upstream_publish_time` requires a publish-time resolver for the
    ///   format.
    ///
    /// A format with no registry entry supports nothing. The config endpoint
    /// and the enforcement seam both derive from this one function, so they
    /// cannot drift.
    pub fn supports_format_mode(format: &RepositoryFormat, mode: AgeGateMode) -> bool {
        match crate::formats::age_gate_spec(format) {
            Some(spec) => match mode {
                AgeGateMode::FirstSeen => spec.immutable_coordinates,
                AgeGateMode::UpstreamPublishTime => spec.publish_time_resolver,
            },
            None => false,
        }
    }

    /// Collapse protocol aliases onto the format whose age-gate policy
    /// governs them (Yarn/pnpm speak the npm registry protocol, Poetry the
    /// PyPI one), via the capability registry.
    pub fn normalize_format(format: RepositoryFormat) -> RepositoryFormat {
        match crate::formats::age_gate_spec(&format) {
            Some(spec) => spec.canonical.clone(),
            None => format,
        }
    }

    /// Compute package age in whole days from upstream publish time.
    pub fn package_age_days(published_at: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
        let delta = now.signed_duration_since(published_at);
        delta.num_days().max(0)
    }

    /// Whether a version meets the minimum age threshold.
    pub fn meets_age_threshold(
        published_at: Option<DateTime<Utc>>,
        min_age_days: i32,
        now: DateTime<Utc>,
    ) -> bool {
        match published_at {
            Some(ts) => Self::package_age_days(ts, now) >= i64::from(min_age_days),
            None => false,
        }
    }

    /// Core decision for a single package version.
    ///
    /// `published_at` is the basis resolved under the repository's *current*
    /// policy (publish time or first-seen observation — see
    /// [`Self::download_basis`]), so the threshold comparison here is the
    /// authoritative recomputation: an `approved` row written by the
    /// automatic machinery grants nothing by status alone. Existing review
    /// rows are interpreted through their recorded basis identity
    /// ([`review_identity_match`]); a decision recorded under a different
    /// mode or upstream is voided back to pending rather than honored.
    pub async fn check(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        version: &str,
        published_at: Option<DateTime<Utc>>,
    ) -> Result<AgeGateDecision> {
        if !Self::gating_requested(repo) {
            return Ok(AgeGateDecision::Allow);
        }
        Self::require_enforceable(repo)?;

        let now = Utc::now();
        let current_fingerprint = upstream_fingerprint(repo.upstream_url.as_deref());
        let existing = self.get_review(repo.id, package_name, version).await?;
        let view = existing.as_ref().map(|r| ReviewPolicyView {
            status: r.status.clone(),
            is_automatic: r.reviewed_by.is_none(),
            identity: review_identity_match(
                r.basis_mode.as_deref(),
                r.basis_upstream_fingerprint.as_deref(),
                repo.age_gate_mode,
                &current_fingerprint,
            ),
        });
        let meets_threshold =
            Self::meets_age_threshold(published_at, repo.age_gate_min_age_days, now);

        let block = |review_id: Uuid, lkg: Option<LastKnownGood>| {
            metrics_service::record_age_gate_blocked_request(&repo.key, format_label(&repo.format));
            Ok(AgeGateDecision::Block {
                review_id,
                last_known_good: lkg,
            })
        };

        match decide_age_gate_check(view.as_ref(), meets_threshold) {
            AgeGateCheckAction::Allow => Ok(AgeGateDecision::Allow),
            AgeGateCheckAction::AllowAlreadyApproved => Ok(AgeGateDecision::Allow),
            AgeGateCheckAction::AllowAndAutoApprovePending => {
                let review = existing.as_ref().expect("pending implies existing review");
                self.auto_approve(review.id, repo.id, repo.age_gate_mode, &current_fingerprint)
                    .await?;
                Ok(AgeGateDecision::Allow)
            }
            AgeGateCheckAction::BlockRejected => {
                let review = existing.as_ref().expect("rejected implies existing review");
                let lkg = self
                    .find_last_known_good(repo.id, package_name, version)
                    .await?;
                block(review.id, lkg)
            }
            AgeGateCheckAction::BlockAndResetReview => {
                let review = existing.as_ref().expect("reset implies existing review");
                let review_id = self
                    .reset_review_to_pending(
                        review.id,
                        repo.id,
                        published_at,
                        repo.age_gate_mode,
                        &current_fingerprint,
                    )
                    .await?;
                let lkg = self
                    .find_last_known_good(repo.id, package_name, version)
                    .await?;
                block(review_id, lkg)
            }
            AgeGateCheckAction::BlockAndRequestReview => {
                let review_id = self
                    .request_review(
                        repo,
                        package_name,
                        version,
                        published_at,
                        existing.is_none(),
                        &current_fingerprint,
                    )
                    .await?;
                let lkg = self
                    .find_last_known_good(repo.id, package_name, version)
                    .await?;
                block(review_id, lkg)
            }
        }
    }

    /// Record first-sight observations for a batch of versions and return
    /// each version's (possibly pre-existing) first-seen time.
    ///
    /// Callers own the evidence contract: only versions that verifiably exist
    /// may be observed (the listing filters observe versions parsed out of an
    /// upstream-served document; the download path proves existence via the
    /// same upstream metadata it already fetches — see
    /// [`Self::download_basis`]). Deciding from an existing observation never
    /// starts a clock; only positive existence evidence may do that.
    ///
    /// Insert-once (`ON CONFLICT DO NOTHING`): concurrent requests and replicas
    /// race benignly because whoever inserts first fixes the timestamp and
    /// every later observation reads that same value back. Repeated listings of
    /// a package can therefore never push a version's clock forward, which is
    /// what makes the elapsed time a usable age.
    ///
    /// Observations are keyed by the repository's *current* upstream
    /// ([`upstream_fingerprint`]), so a repointed remote starts a fresh clock
    /// instead of inheriting the previous registry's elapsed age.
    pub async fn observe_versions_first_seen(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        versions: &[String],
    ) -> Result<std::collections::HashMap<String, DateTime<Utc>>> {
        if versions.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let fingerprint = upstream_fingerprint(repo.upstream_url.as_deref());

        sqlx::query(
            "INSERT INTO age_gate_version_observations (
                 repository_id, upstream_fingerprint, package_name, package_version
             )
             SELECT $1, $2, $3, v FROM UNNEST($4::text[]) AS t(v)
             ON CONFLICT (repository_id, upstream_fingerprint, package_name, package_version)
             DO NOTHING",
        )
        .bind(repo.id)
        .bind(&fingerprint)
        .bind(package_name)
        .bind(versions)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let rows: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT package_version, first_seen_at
             FROM age_gate_version_observations
             WHERE repository_id = $1 AND upstream_fingerprint = $2 AND package_name = $3
               AND package_version = ANY($4::text[])",
        )
        .bind(repo.id)
        .bind(&fingerprint)
        .bind(package_name)
        .bind(versions)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().collect())
    }

    /// Read back one version's first-seen time WITHOUT recording anything.
    pub async fn lookup_first_seen(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        version: &str,
    ) -> Result<Option<DateTime<Utc>>> {
        let fingerprint = upstream_fingerprint(repo.upstream_url.as_deref());
        sqlx::query_scalar(
            "SELECT first_seen_at FROM age_gate_version_observations
             WHERE repository_id = $1 AND upstream_fingerprint = $2
               AND package_name = $3 AND package_version = $4",
        )
        .bind(repo.id)
        .bind(&fingerprint)
        .bind(package_name)
        .bind(version)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Observe (or read back) one version's first-seen time. Same evidence
    /// contract as [`Self::observe_versions_first_seen`].
    pub async fn observe_first_seen(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        version: &str,
    ) -> Result<Option<DateTime<Utc>>> {
        let observed = self
            .observe_versions_first_seen(repo, package_name, &[version.to_string()])
            .await?;
        Ok(observed.get(version).copied())
    }

    /// Resolve the download-path age basis for one version under the
    /// repository's configured mode — the single place the download seam
    /// consults the mode, so it always agrees with the listing filters
    /// (which share the same clock via [`Self::observe_versions_first_seen`]).
    ///
    /// * `upstream_publish_time`: the caller's resolved publish timestamp,
    ///   verbatim. A missing timestamp stays missing (blocks; #2066).
    /// * `first_seen`: an existing observation wins; otherwise a new
    ///   observation is recorded ONLY when the caller holds positive
    ///   existence evidence for the version (`version_exists_upstream` —
    ///   e.g. the version appears in the upstream metadata document the
    ///   handler already fetched). Without evidence no clock starts and the
    ///   version blocks, so an attacker cannot pre-age a version name by
    ///   requesting it before it is published.
    pub async fn download_basis(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        version: &str,
        upstream_published_at: Option<DateTime<Utc>>,
        version_exists_upstream: bool,
    ) -> Result<Option<DateTime<Utc>>> {
        match repo.age_gate_mode {
            AgeGateMode::UpstreamPublishTime => Ok(upstream_published_at),
            AgeGateMode::FirstSeen => {
                if let Some(seen) = self.lookup_first_seen(repo, package_name, version).await? {
                    return Ok(Some(seen));
                }
                if version_exists_upstream {
                    self.observe_first_seen(repo, package_name, version).await
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Resolve the age basis of every version in a metadata listing according
    /// to the repository's configured mode.
    ///
    /// Publish-time mode borrows the timestamps the caller already parsed out
    /// of the document; `first_seen` mode ignores them (they are the
    /// upstream's claim, which is precisely what this mode declines to trust)
    /// and substitutes this server's own observations.
    async fn listing_basis_times<'a>(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        versions: &'a [(String, Option<DateTime<Utc>>)],
    ) -> Result<Cow<'a, [(String, Option<DateTime<Utc>>)]>> {
        match repo.age_gate_mode {
            AgeGateMode::UpstreamPublishTime => Ok(Cow::Borrowed(versions)),
            AgeGateMode::FirstSeen => {
                let names: Vec<String> = versions.iter().map(|(v, _)| v.clone()).collect();
                let observed = self
                    .observe_versions_first_seen(repo, package_name, &names)
                    .await?;
                Ok(Cow::Owned(
                    names
                        .into_iter()
                        .map(|v| {
                            let seen = observed.get(&v).copied();
                            (v, seen)
                        })
                        .collect(),
                ))
            }
        }
    }

    /// Filter npm packument JSON, removing versions blocked by the age gate.
    pub async fn filter_npm_packument(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        packument: &mut serde_json::Value,
    ) -> Result<()> {
        if !Self::gating_requested(repo) {
            return Ok(());
        }
        Self::require_enforceable(repo)?;

        let publish_times = UpstreamMetadataCache::parse_npm_publish_times(packument);
        let versions = collect_npm_packument_versions(packument, &publish_times);

        if versions.is_empty() {
            return Ok(());
        }

        let blocked = self
            .evaluate_versions_batch(repo, package_name, &versions)
            .await?;

        if !blocked.is_empty() {
            metrics_service::record_age_gate_filtered_metadata(
                &repo.key,
                format_label(&repo.format),
            );
        }

        apply_npm_packument_blocks(packument, &blocked);

        Ok(())
    }

    /// Filter PyPI simple index HTML, removing links for blocked versions.
    pub async fn filter_pypi_simple_index(
        &self,
        repo: &AgeGateRepoParams,
        project: &str,
        publish_times: &std::collections::HashMap<String, DateTime<Utc>>,
        html: &str,
    ) -> Result<String> {
        if !Self::gating_requested(repo) {
            return Ok(html.to_string());
        }
        Self::require_enforceable(repo)?;

        let (spans, mut versions) = parse_pypi_simple_index_anchors(html);
        attach_pypi_publish_times(&mut versions, publish_times);

        let blocked = self
            .evaluate_versions_batch(repo, project, &versions)
            .await?;

        if !blocked.is_empty() {
            metrics_service::record_age_gate_filtered_metadata(
                &repo.key,
                format_label(&repo.format),
            );
        }

        Ok(rebuild_pypi_simple_index_html(html, &spans, &blocked))
    }

    /// Filter a proxied PEP 691 JSON simple index, removing `files` entries
    /// and PEP 700 `versions` entries for versions blocked by the age gate.
    ///
    /// This is the JSON twin of [`Self::filter_pypi_simple_index`]: the proxy
    /// path negotiates `application/vnd.pypi.simple.v1+json` (#1944) and
    /// modern pip prefers it, so an HTML-only filter would withhold a young
    /// version from the HTML index while serving it to every JSON client.
    /// Publish times come from the document's own PEP 700 `upload-time`
    /// fields where present (a version is as old as its earliest file); only
    /// versions with no `upload-time` fall back to the upstream JSON metadata
    /// fetch the HTML path always pays. A fallback fetch failure leaves those
    /// versions timeless, and [`Self::meets_age_threshold`] treats a missing
    /// publish time as not meeting the threshold, so they are withheld rather
    /// than leaked.
    pub async fn filter_pypi_simple_json(
        &self,
        repo: &AgeGateRepoParams,
        project: &str,
        upstream_url: &str,
        index: &mut serde_json::Value,
    ) -> Result<()> {
        if !Self::gating_requested(repo) {
            return Ok(());
        }
        Self::require_enforceable(repo)?;

        let mut versions = collect_pypi_simple_json_versions(index);
        if versions.is_empty() {
            return Ok(());
        }

        // `first_seen` substitutes this server's own observations for the
        // document's timestamps in `listing_basis_times`, so the fallback
        // fetch would be both wasted and contrary to the mode's premise.
        if repo.age_gate_mode == AgeGateMode::UpstreamPublishTime
            && versions.iter().any(|(_, ts)| ts.is_none())
        {
            if let Ok(client) = crate::services::upstream_metadata::metadata_http_client() {
                if let Ok(times) = self
                    .metadata_cache
                    .fetch_pypi_publish_times(&client, repo.id, upstream_url, project)
                    .await
                {
                    fill_missing_publish_times(&mut versions, &times);
                }
            }
        }

        let blocked = self
            .evaluate_versions_batch(repo, project, &versions)
            .await?;

        if !blocked.is_empty() {
            metrics_service::record_age_gate_filtered_metadata(
                &repo.key,
                format_label(&repo.format),
            );
        }

        apply_pypi_simple_json_blocks(index, &blocked);
        Ok(())
    }

    /// Batch age-gate evaluation for every version in a package metadata document.
    /// Returns the set of versions to withhold from clients.
    ///
    /// This is the metadata *listing* path (npm packument / PyPI simple index),
    /// where the client fetches the whole version list rather than asking for a
    /// specific version. It is deliberately near read-only: a single
    /// existing-review read, then at most one debounced review-request upsert for
    /// versions that are newly withheld. It does NOT auto-approve aged versions —
    /// that bookkeeping runs off the request path in the background sweep
    /// [`Self::auto_approve_aged_reviews`]. A version that has crossed the
    /// threshold is served immediately (decided from its timestamp here) even
    /// before its review row is flipped to `approved`.
    pub(crate) async fn evaluate_versions_batch(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        versions: &[(String, Option<DateTime<Utc>>)],
    ) -> Result<std::collections::HashSet<String>> {
        let blocked = std::collections::HashSet::new();
        if !Self::gating_requested(repo) || versions.is_empty() {
            return Ok(blocked);
        }
        Self::require_enforceable(repo)?;

        let now = Utc::now();
        let current_fingerprint = upstream_fingerprint(repo.upstream_url.as_deref());
        let existing = self.get_reviews_for_package(repo.id, package_name).await?;
        let versions = self
            .listing_basis_times(repo, package_name, versions)
            .await?;

        let classification = classify_versions_for_metadata_listing(
            &versions,
            &existing,
            repo.age_gate_min_age_days,
            repo.age_gate_mode,
            &current_fingerprint,
            now,
        );

        if !classification.request_versions.is_empty() {
            self.request_reviews_batch(
                repo,
                package_name,
                &classification.request_versions,
                &classification.request_times,
                &current_fingerprint,
            )
            .await?;
        }

        Ok(classification.blocked)
    }

    pub async fn list_reviews(
        &self,
        repository_key: Option<&str>,
        statuses: Option<&[String]>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<AgeGateReview>, i64)> {
        let total: i64 = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)::bigint
            FROM age_gate_reviews r
            INNER JOIN repositories repo ON repo.id = r.repository_id
            WHERE ($1::text IS NULL OR repo.key = $1)
              AND ($2::text[] IS NULL OR r.status = ANY($2))
            "#,
            repository_key,
            statuses
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .unwrap_or(0);

        // Non-macro sqlx (like every query touching the migration-185 columns)
        // so the change needs no `.sqlx` offline-metadata regeneration.
        let rows = sqlx::query_as::<_, AgeGateReview>(
            r#"
            SELECT
                r.id, r.repository_id, r.package_name, r.package_version,
                r.upstream_published_at, r.status, r.requested_at,
                r.reviewed_by, r.reviewed_at, r.review_reason,
                r.request_count, r.last_requested_at,
                r.basis_mode, r.basis_upstream_fingerprint,
                repo.key as repository_key
            FROM age_gate_reviews r
            INNER JOIN repositories repo ON repo.id = r.repository_id
            WHERE ($1::text IS NULL OR repo.key = $1)
              AND ($2::text[] IS NULL OR r.status = ANY($2))
            ORDER BY r.last_requested_at DESC
            OFFSET $3 LIMIT $4
            "#,
        )
        .bind(repository_key)
        .bind(statuses)
        .bind(offset)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((rows, total))
    }

    pub async fn get_review_by_id(&self, id: Uuid) -> Result<AgeGateReview> {
        sqlx::query_as::<_, AgeGateReview>(
            r#"
            SELECT
                r.id, r.repository_id, r.package_name, r.package_version,
                r.upstream_published_at, r.status, r.requested_at,
                r.reviewed_by, r.reviewed_at, r.review_reason,
                r.request_count, r.last_requested_at,
                r.basis_mode, r.basis_upstream_fingerprint,
                repo.key as repository_key
            FROM age_gate_reviews r
            INNER JOIN repositories repo ON repo.id = r.repository_id
            WHERE r.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Age gate review not found".to_string()))
    }

    pub async fn approve(
        &self,
        id: Uuid,
        reviewer_id: Uuid,
        reason: Option<&str>,
    ) -> Result<AgeGateReview> {
        let review = self.get_review_by_id(id).await?;
        require_distinct_status(&review.status, AgeGateReviewStatus::Approved)?;
        let expected_status = review.status.clone();

        let params = resolve_repo_params(&self.db, review.repository_id).await?;
        let fingerprint = upstream_fingerprint(params.upstream_url.as_deref());
        let res = sqlx::query(
            "UPDATE age_gate_reviews
             SET status = 'approved', reviewed_by = $2, reviewed_at = NOW(),
                 review_reason = $3, basis_mode = $4,
                 basis_upstream_fingerprint = $5
             WHERE id = $1 AND status = $6",
        )
        .bind(id)
        .bind(reviewer_id)
        .bind(reason)
        .bind(params.age_gate_mode.as_str())
        .bind(&fingerprint)
        .bind(&expected_status)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if res.rows_affected() != 1 {
            return Err(AppError::Conflict(
                "Age gate review changed concurrently; retry".to_string(),
            ));
        }
        self.event_bus.emit_for_repo(
            "age_gate.approved",
            id,
            review.repository_id,
            Some(reviewer_id.to_string()),
        );

        self.get_review_by_id(id).await
    }

    pub async fn reject(
        &self,
        id: Uuid,
        reviewer_id: Uuid,
        reason: Option<&str>,
    ) -> Result<AgeGateReview> {
        let review = self.get_review_by_id(id).await?;
        require_distinct_status(&review.status, AgeGateReviewStatus::Rejected)?;
        let expected_status = review.status.clone();

        let params = resolve_repo_params(&self.db, review.repository_id).await?;
        let fingerprint = upstream_fingerprint(params.upstream_url.as_deref());
        let res = sqlx::query(
            "UPDATE age_gate_reviews
             SET status = 'rejected', reviewed_by = $2, reviewed_at = NOW(),
                 review_reason = $3, basis_mode = $4,
                 basis_upstream_fingerprint = $5
             WHERE id = $1 AND status = $6",
        )
        .bind(id)
        .bind(reviewer_id)
        .bind(reason)
        .bind(params.age_gate_mode.as_str())
        .bind(&fingerprint)
        .bind(&expected_status)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if res.rows_affected() != 1 {
            return Err(AppError::Conflict(
                "Age gate review changed concurrently; retry".to_string(),
            ));
        }
        self.event_bus.emit_for_repo(
            "age_gate.rejected",
            id,
            review.repository_id,
            Some(reviewer_id.to_string()),
        );

        self.get_review_by_id(id).await
    }

    /// Reopen a decided review, moving it back to `pending` so the age gate can
    /// be revisited. Allowed from any non-`pending` state; a review that is
    /// already pending is refused as a no-op. The download path re-reads the
    /// review status on every request, so reopening a young package's review
    /// re-blocks subsequent pulls until it is decided again (or ages out).
    ///
    /// Returns `(previous_status, updated_review)` so callers can record the
    /// prior state in the audit trail.
    pub async fn reopen(
        &self,
        id: Uuid,
        reviewer_id: Uuid,
        reason: Option<&str>,
    ) -> Result<(String, AgeGateReview)> {
        let review = self.get_review_by_id(id).await?;
        require_distinct_status(&review.status, AgeGateReviewStatus::Pending)?;
        let previous_status = review.status.clone();

        let res = sqlx::query(
            "UPDATE age_gate_reviews
             SET status = 'pending', reviewed_by = $2, reviewed_at = NOW(),
                 review_reason = $3
             WHERE id = $1 AND status = $4",
        )
        .bind(id)
        .bind(reviewer_id)
        .bind(reason)
        .bind(&previous_status)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if res.rows_affected() != 1 {
            return Err(AppError::Conflict(
                "Age gate review changed concurrently; retry".to_string(),
            ));
        }
        self.event_bus.emit_for_repo(
            "age_gate.reopened",
            id,
            review.repository_id,
            Some(reviewer_id.to_string()),
        );

        let updated = self.get_review_by_id(id).await?;
        Ok((previous_status, updated))
    }

    pub async fn update_repo_config(
        &self,
        repo_id: Uuid,
        enabled: bool,
        min_age_days: i32,
        mode: AgeGateMode,
    ) -> Result<()> {
        validate_min_age_days(min_age_days)?;

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let current: Option<String> =
            sqlx::query_scalar("SELECT age_gate_mode FROM repositories WHERE id = $1 FOR UPDATE")
                .bind(repo_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        let current =
            current.ok_or_else(|| AppError::NotFound(format!("Repository {repo_id} not found")))?;

        sqlx::query(
            "UPDATE repositories
             SET age_gate_enabled = $2, age_gate_min_age_days = $3,
                 age_gate_mode = $4, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(repo_id)
        .bind(enabled)
        .bind(min_age_days)
        .bind(mode.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if current != mode.as_str() {
            sqlx::query(
                "UPDATE age_gate_reviews
                 SET upstream_published_at = NULL, basis_mode = NULL,
                     basis_upstream_fingerprint = NULL
                 WHERE repository_id = $1 AND status = 'pending'",
            )
            .bind(repo_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn find_last_known_good(
        &self,
        repository_id: Uuid,
        package_name: &str,
        exclude_version: &str,
    ) -> Result<Option<LastKnownGood>> {
        let rows = sqlx::query!(
            r#"
            SELECT a.version, a.path
            FROM artifacts a
            LEFT JOIN age_gate_reviews r
              ON r.repository_id = a.repository_id
             AND r.package_name = $2
             AND r.package_version = a.version
            WHERE a.repository_id = $1
              AND a.is_deleted = false
              AND a.version IS NOT NULL
              AND a.version <> $3
              AND LOWER(a.name) = LOWER($2)
              AND (r.status IS NULL OR r.status = 'approved')
            "#,
            repository_id,
            package_name,
            exclude_version
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(select_newest_approved_artifact(
            &rows
                .into_iter()
                .filter_map(|row| Some((row.version?, row.path)))
                .collect::<Vec<_>>(),
        ))
    }

    async fn get_review(
        &self,
        repository_id: Uuid,
        package_name: &str,
        version: &str,
    ) -> Result<Option<AgeGateReview>> {
        sqlx::query_as::<_, AgeGateReview>(
            r#"
            SELECT
                id, repository_id, package_name, package_version,
                upstream_published_at, status, requested_at,
                reviewed_by, reviewed_at, review_reason,
                request_count, last_requested_at,
                basis_mode, basis_upstream_fingerprint,
                NULL::text as repository_key
            FROM age_gate_reviews
            WHERE repository_id = $1 AND package_name = $2 AND package_version = $3
            "#,
        )
        .bind(repository_id)
        .bind(package_name)
        .bind(version)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Upsert a pending review for one version, stamped with the current
    /// policy identity.
    ///
    /// When the existing row's identity differs from the current policy, its
    /// recorded basis answers a different question, so the basis is
    /// OVERWRITTEN (not COALESCEd) and the identity re-stamped. This also
    /// bounds the in-flight-write race: a request resolved under the old
    /// policy that lands after a mode switch re-populates the row *with the
    /// old identity*, which the background sweep then refuses to honor.
    /// A stale automatic approval racing in here is likewise demoted back to
    /// pending rather than left standing.
    async fn request_review(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        version: &str,
        published_at: Option<DateTime<Utc>>,
        is_new: bool,
        fingerprint: &str,
    ) -> Result<Uuid> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO age_gate_reviews (
                repository_id, package_name, package_version,
                upstream_published_at, status, basis_mode, basis_upstream_fingerprint
            )
            VALUES ($1, $2, $3, $4, 'pending', $5, $6)
            ON CONFLICT (repository_id, package_name, package_version)
            DO UPDATE SET
                request_count = age_gate_reviews.request_count + 1,
                last_requested_at = NOW(),
                upstream_published_at = CASE
                    WHEN age_gate_reviews.basis_mode IS DISTINCT FROM EXCLUDED.basis_mode
                      OR age_gate_reviews.basis_upstream_fingerprint IS DISTINCT FROM EXCLUDED.basis_upstream_fingerprint
                    THEN EXCLUDED.upstream_published_at
                    ELSE COALESCE(EXCLUDED.upstream_published_at, age_gate_reviews.upstream_published_at)
                END,
                status = CASE
                    WHEN age_gate_reviews.status = 'rejected' THEN age_gate_reviews.status
                    WHEN age_gate_reviews.basis_mode IS DISTINCT FROM EXCLUDED.basis_mode
                      OR age_gate_reviews.basis_upstream_fingerprint IS DISTINCT FROM EXCLUDED.basis_upstream_fingerprint
                      OR (age_gate_reviews.reviewed_by IS NULL AND age_gate_reviews.status = 'approved')
                    THEN 'pending'
                    ELSE age_gate_reviews.status
                END,
                reviewed_by = CASE
                    WHEN age_gate_reviews.status = 'rejected' THEN age_gate_reviews.reviewed_by
                    WHEN age_gate_reviews.basis_mode IS DISTINCT FROM EXCLUDED.basis_mode
                      OR age_gate_reviews.basis_upstream_fingerprint IS DISTINCT FROM EXCLUDED.basis_upstream_fingerprint
                      OR (age_gate_reviews.reviewed_by IS NULL AND age_gate_reviews.status = 'approved')
                    THEN NULL
                    ELSE age_gate_reviews.reviewed_by
                END,
                basis_mode = EXCLUDED.basis_mode,
                basis_upstream_fingerprint = EXCLUDED.basis_upstream_fingerprint
            RETURNING id
            "#,
        )
        .bind(repo.id)
        .bind(package_name)
        .bind(version)
        .bind(published_at)
        .bind(repo.age_gate_mode.as_str())
        .bind(fingerprint)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if is_new {
            self.event_bus
                .emit_for_repo("age_gate.queued", id, repo.id, None);
        }

        Ok(id)
    }

    /// Void a review decision the current policy must not honor (an automatic
    /// approval whose eligibility no longer holds, or a manual approval bound
    /// to a different identity): back to pending under the current basis and
    /// identity. The old decision is not preserved — it answered a different
    /// question — and the version re-enters the review queue.
    async fn reset_review_to_pending(
        &self,
        review_id: Uuid,
        repository_id: Uuid,
        published_at: Option<DateTime<Utc>>,
        mode: AgeGateMode,
        fingerprint: &str,
    ) -> Result<Uuid> {
        sqlx::query(
            r#"
            UPDATE age_gate_reviews
            SET status = 'pending', reviewed_by = NULL, reviewed_at = NULL,
                review_reason = NULL, upstream_published_at = $2,
                basis_mode = $3, basis_upstream_fingerprint = $4,
                request_count = request_count + 1, last_requested_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(review_id)
        .bind(published_at)
        .bind(mode.as_str())
        .bind(fingerprint)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        self.event_bus
            .emit_for_repo("age_gate.queued", review_id, repository_id, None);

        Ok(review_id)
    }

    /// Retire a pending review whose version now meets the threshold on the
    /// current clock. The row is stamped with the identity the eligibility
    /// was computed under; the resulting `approved` status is bookkeeping,
    /// not authority — [`decide_age_gate_check`] recomputes automatic
    /// eligibility from the live basis on every decision.
    async fn auto_approve(
        &self,
        review_id: Uuid,
        repository_id: Uuid,
        mode: AgeGateMode,
        fingerprint: &str,
    ) -> Result<()> {
        let res = sqlx::query(
            r#"
            UPDATE age_gate_reviews
            SET status = 'approved', reviewed_by = NULL, reviewed_at = NOW(),
                review_reason = $2, basis_mode = $3,
                basis_upstream_fingerprint = $4
            WHERE id = $1 AND status = 'pending'
            "#,
        )
        .bind(review_id)
        .bind(AUTO_APPROVE_REASON)
        .bind(mode.as_str())
        .bind(fingerprint)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if res.rows_affected() == 1 {
            self.event_bus
                .emit_for_repo("age_gate.approved", review_id, repository_id, None);
        }
        Ok(())
    }

    /// Load all existing reviews for a package keyed by version, so a batch
    /// evaluation can classify every version with a single read.
    async fn get_reviews_for_package(
        &self,
        repository_id: Uuid,
        package_name: &str,
    ) -> Result<std::collections::HashMap<String, PackageReviewRow>> {
        use sqlx::Row as _;
        let rows = sqlx::query(
            r#"
            SELECT package_version, status, (reviewed_by IS NULL) AS is_automatic,
                   basis_mode, basis_upstream_fingerprint
            FROM age_gate_reviews
            WHERE repository_id = $1 AND package_name = $2
            "#,
        )
        .bind(repository_id)
        .bind(package_name)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                let column = |e: sqlx::Error| AppError::Database(e.to_string());
                Ok((
                    r.try_get::<String, _>("package_version").map_err(column)?,
                    PackageReviewRow {
                        status: r.try_get("status").map_err(column)?,
                        is_automatic: r.try_get("is_automatic").map_err(column)?,
                        basis_mode: r.try_get("basis_mode").map_err(column)?,
                        basis_upstream_fingerprint: r
                            .try_get("basis_upstream_fingerprint")
                            .map_err(column)?,
                    },
                ))
            })
            .collect()
    }

    /// Upsert pending review requests for many versions in a single statement.
    ///
    /// The per-version `request_count` / `last_requested_at` bump is *debounced*:
    /// an existing row is only re-bumped when its last request predates the
    /// [`REQUEST_COUNT_DEBOUNCE_SECS`] cutoff. This turns "write on every metadata
    /// fetch" into "write at most once per version per window" — the bulk of the
    /// age-gate write traffic, since popular packages are re-listed constantly —
    /// while still keeping an approximate demand signal for reviewers. Rows whose
    /// bump is debounced away are simply not returned by `RETURNING`.
    ///
    /// A freshly inserted row keeps the default `request_count = 1` (its INSERT is
    /// never gated by the debounce `WHERE`, which only applies to the UPDATE
    /// action); a bumped row is >= 2. So `request_count = 1` among the returned
    /// rows reliably marks brand-new reviews for `age_gate.queued` emission.
    /// The debounce NEVER defers a policy correction: a row whose recorded
    /// identity differs from the current policy, or a stale automatic
    /// approval, is rewritten immediately (basis overwritten, status demoted
    /// back to pending) even inside the debounce window — otherwise a
    /// recently touched row could carry its old basis through a mode switch
    /// or repoint and be auto-approved by the sweep under the new policy.
    async fn request_reviews_batch(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        versions: &[String],
        published_ats: &[Option<DateTime<Utc>>],
        fingerprint: &str,
    ) -> Result<()> {
        use sqlx::Row as _;
        let stale_before = Utc::now() - chrono::Duration::seconds(REQUEST_COUNT_DEBOUNCE_SECS);
        let rows = sqlx::query(
            r#"
            INSERT INTO age_gate_reviews (
                repository_id, package_name, package_version,
                upstream_published_at, status, basis_mode, basis_upstream_fingerprint
            )
            SELECT $1, $2, v, p, 'pending', $6, $7
            FROM UNNEST($3::text[], $4::timestamptz[]) AS t(v, p)
            ON CONFLICT (repository_id, package_name, package_version)
            DO UPDATE SET
                request_count = age_gate_reviews.request_count + 1,
                last_requested_at = NOW(),
                upstream_published_at = CASE
                    WHEN age_gate_reviews.basis_mode IS DISTINCT FROM EXCLUDED.basis_mode
                      OR age_gate_reviews.basis_upstream_fingerprint IS DISTINCT FROM EXCLUDED.basis_upstream_fingerprint
                    THEN EXCLUDED.upstream_published_at
                    ELSE COALESCE(EXCLUDED.upstream_published_at, age_gate_reviews.upstream_published_at)
                END,
                status = CASE
                    WHEN age_gate_reviews.status = 'rejected' THEN age_gate_reviews.status
                    WHEN age_gate_reviews.basis_mode IS DISTINCT FROM EXCLUDED.basis_mode
                      OR age_gate_reviews.basis_upstream_fingerprint IS DISTINCT FROM EXCLUDED.basis_upstream_fingerprint
                      OR (age_gate_reviews.reviewed_by IS NULL AND age_gate_reviews.status = 'approved')
                    THEN 'pending'
                    ELSE age_gate_reviews.status
                END,
                reviewed_by = CASE
                    WHEN age_gate_reviews.status = 'rejected' THEN age_gate_reviews.reviewed_by
                    WHEN age_gate_reviews.basis_mode IS DISTINCT FROM EXCLUDED.basis_mode
                      OR age_gate_reviews.basis_upstream_fingerprint IS DISTINCT FROM EXCLUDED.basis_upstream_fingerprint
                      OR (age_gate_reviews.reviewed_by IS NULL AND age_gate_reviews.status = 'approved')
                    THEN NULL
                    ELSE age_gate_reviews.reviewed_by
                END,
                basis_mode = EXCLUDED.basis_mode,
                basis_upstream_fingerprint = EXCLUDED.basis_upstream_fingerprint
            WHERE age_gate_reviews.last_requested_at < $5
               OR age_gate_reviews.basis_mode IS DISTINCT FROM EXCLUDED.basis_mode
               OR age_gate_reviews.basis_upstream_fingerprint IS DISTINCT FROM EXCLUDED.basis_upstream_fingerprint
               OR (age_gate_reviews.reviewed_by IS NULL AND age_gate_reviews.status = 'approved')
            RETURNING id, (request_count = 1) AS is_new
            "#,
        )
        .bind(repo.id)
        .bind(package_name)
        .bind(versions)
        .bind(published_ats)
        .bind(stale_before)
        .bind(repo.age_gate_mode.as_str())
        .bind(fingerprint)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        for row in rows {
            let column = |e: sqlx::Error| AppError::Database(e.to_string());
            let id: Uuid = row.try_get("id").map_err(column)?;
            let is_new: bool = row.try_get("is_new").map_err(column)?;
            if is_new {
                self.event_bus
                    .emit_for_repo("age_gate.queued", id, repo.id, None);
            }
        }
        Ok(())
    }

    /// Auto-approve every pending review whose version has crossed its
    /// repository's age threshold. This runs on the background scheduler rather
    /// than on the metadata/download fetch paths, keeping listing reads free of
    /// the pending→approved UPDATE. A single statement transitions all eligible
    /// rows across every age-gate-enabled repository, and an approval event is
    /// emitted per row actually transitioned. Returns the number approved.
    ///
    /// The age predicate mirrors [`Self::meets_age_threshold`] exactly: for an
    /// integer threshold `n`, `floor(age_days) >= n` is equivalent to
    /// `age >= n days`, so the served-vs-blocked decision on the read path and
    /// the row's persisted status never disagree once this sweep has run.
    ///
    /// Concurrency-safe across replicas: `WHERE status = 'pending'` plus row
    /// locking means each row is transitioned (and returned) by exactly one
    /// runner, so no duplicate `age_gate.approved` events are emitted.
    /// The sweep only honors a basis whose recorded identity matches the
    /// repository's CURRENT policy (mode + normalized upstream fingerprint).
    /// That closes both stale-row and in-flight-write races: a basis recorded
    /// before a mode switch or repoint — or written by a request that
    /// resolved the old policy and landed after the switch — carries the old
    /// identity and is never swept. Because the fingerprint normalization is
    /// Rust-side, each gated repository's policy is resolved here and the
    /// sweep runs per repository.
    ///
    /// Legacy pre-identity rows (both columns NULL, written before migration
    /// 185) are swept only while the repository still runs
    /// `upstream_publish_time` — the only mode that existed when they were
    /// written — preserving their pre-upgrade behavior without reopening the
    /// race: post-upgrade writes always stamp a full identity, so NULL cannot
    /// be minted anew.
    pub async fn auto_approve_aged_reviews(&self) -> Result<u64> {
        use sqlx::Row as _;
        let column = |e: sqlx::Error| AppError::Database(e.to_string());

        let repos = sqlx::query(
            "SELECT id, age_gate_mode, age_gate_min_age_days, upstream_url
             FROM repositories WHERE age_gate_enabled = true",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut approved: u64 = 0;
        for repo in repos {
            let repo_id: Uuid = repo.try_get("id").map_err(column)?;
            let mode =
                AgeGateMode::parse(&repo.try_get::<String, _>("age_gate_mode").map_err(column)?)?;
            let min_age_days: i32 = repo.try_get("age_gate_min_age_days").map_err(column)?;
            let upstream_url: Option<String> = repo.try_get("upstream_url").map_err(column)?;
            let fingerprint = upstream_fingerprint(upstream_url.as_deref());

            let rows = sqlx::query(
                r#"
                UPDATE age_gate_reviews
                SET status = 'approved', reviewed_by = NULL, reviewed_at = NOW(),
                    review_reason = $2
                WHERE repository_id = $1
                  AND status = 'pending'
                  AND upstream_published_at IS NOT NULL
                  AND NOW() - upstream_published_at >= make_interval(days => $3)
                  AND ((basis_mode = $4 AND basis_upstream_fingerprint = $5)
                       OR (basis_mode IS NULL AND basis_upstream_fingerprint IS NULL
                           AND $4 = 'upstream_publish_time'))
                RETURNING id
                "#,
            )
            .bind(repo_id)
            .bind(AUTO_APPROVE_REASON)
            .bind(min_age_days)
            .bind(mode.as_str())
            .bind(&fingerprint)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            approved += rows.len() as u64;
            for row in rows {
                let id: Uuid = row.try_get("id").map_err(column)?;
                self.event_bus
                    .emit_for_repo("age_gate.approved", id, repo_id, None);
            }
        }
        Ok(approved)
    }
}

/// Collect version keys and publish times from an npm packument for batch evaluation.
pub(crate) fn collect_npm_packument_versions(
    packument: &serde_json::Value,
    publish_times: &std::collections::HashMap<String, DateTime<Utc>>,
) -> Vec<(String, Option<DateTime<Utc>>)> {
    packument
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .map(|v| (v.clone(), publish_times.get(&v).copied()))
        .collect()
}

/// Remove blocked versions from a packument and reconcile `dist-tags`.
pub(crate) fn apply_npm_packument_blocks(
    packument: &mut serde_json::Value,
    blocked: &std::collections::HashSet<String>,
) -> Vec<String> {
    let version_keys: Vec<String> = packument
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    let mut allowed: Vec<String> = Vec::new();
    for version in version_keys {
        if blocked.contains(&version) {
            if let Some(versions_obj) = packument
                .get_mut("versions")
                .and_then(|v| v.as_object_mut())
            {
                versions_obj.remove(&version);
            }
            if let Some(time_map) = packument.get_mut("time").and_then(|t| t.as_object_mut()) {
                time_map.remove(&version);
            }
        } else {
            allowed.push(version);
        }
    }

    allowed.sort_by(|a, b| version_compare_desc(a, b));
    reconcile_dist_tags(packument, &allowed);
    allowed
}

/// One anchor span in a PyPI simple-index HTML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PypiAnchorSpan {
    pub start: usize,
    pub end: usize,
    pub version: Option<String>,
}

type PypiSimpleIndexParseResult = (Vec<PypiAnchorSpan>, Vec<(String, Option<DateTime<Utc>>)>);

/// First pass over PyPI simple-index HTML: locate anchors and dedupe versions.
pub(crate) fn parse_pypi_simple_index_anchors(html: &str) -> PypiSimpleIndexParseResult {
    let mut spans: Vec<PypiAnchorSpan> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut versions: Vec<(String, Option<DateTime<Utc>>)> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = html[cursor..].find("<a ") {
        let start = cursor + rel;
        let Some(end_rel) = html[start..].find("</a>") else {
            break;
        };
        let end = start + end_rel + 4;
        let version = pypi_anchor_version(&html[start..end]);
        if let Some(ref ver) = version {
            if seen.insert(ver.clone()) {
                versions.push((ver.clone(), None));
            }
        }
        spans.push(PypiAnchorSpan {
            start,
            end,
            version,
        });
        cursor = end;
    }
    (spans, versions)
}

/// Attach publish times to parsed simple-index versions.
pub(crate) fn attach_pypi_publish_times(
    versions: &mut [(String, Option<DateTime<Utc>>)],
    publish_times: &std::collections::HashMap<String, DateTime<Utc>>,
) {
    for (ver, ts) in versions {
        *ts = publish_times.get(ver).copied();
    }
}

/// Second pass: rebuild HTML, dropping anchors for blocked versions.
pub(crate) fn rebuild_pypi_simple_index_html(
    html: &str,
    spans: &[PypiAnchorSpan],
    blocked: &std::collections::HashSet<String>,
) -> String {
    let mut out = String::with_capacity(html.len());
    let mut cursor = 0usize;
    for span in spans {
        out.push_str(&html[cursor..span.start]);
        let keep = match &span.version {
            None => true,
            Some(ver) => !blocked.contains(ver),
        };
        if keep {
            out.push_str(&html[span.start..span.end]);
        }
        cursor = span.end;
    }
    out.push_str(&html[cursor..]);
    out
}

/// Pick the newest approved artifact from pre-filtered candidate rows.
pub(crate) fn select_newest_approved_artifact(
    candidates: &[(String, String)],
) -> Option<LastKnownGood> {
    candidates
        .iter()
        .max_by(|a, b| version_compare(&a.0, &b.0).cmp(&0))
        .map(|(version, path)| LastKnownGood {
            version: version.clone(),
            artifact_path: path.clone(),
        })
}

fn extract_href_filename(anchor: &str) -> Option<String> {
    let href_start = anchor.find("href=\"")? + 6;
    let rest = &anchor[href_start..];
    let href_end = rest.find('"')?;
    let href = &rest[..href_end];
    let basename = href.rsplit('/').next()?;
    // PEP 503 simple-index anchors always carry a `#sha256=...` hash fragment
    // (and may carry a query string). Strip both before the basename is handed
    // to `parse_filename`, which otherwise rejects the whole anchor and the
    // age-gate listing filter silently no-ops. Proxy-rewritten hrefs also carry
    // a repo path prefix, but `rsplit('/')` already removes that.
    let filename = basename.split(['#', '?']).next().unwrap_or(basename);
    if filename.is_empty() {
        None
    } else {
        Some(filename.to_string())
    }
}

/// Extract the package version a PyPI simple-index anchor links to, if any.
fn pypi_anchor_version(anchor: &str) -> Option<String> {
    extract_href_filename(anchor)
        .as_deref()
        .and_then(pypi_filename_version)
}

/// Extract the package version encoded in a PyPI distribution filename, if
/// any. Shared by the HTML anchor parser and the PEP 691 JSON `files` walker
/// so both representations classify a filename identically.
fn pypi_filename_version(filename: &str) -> Option<String> {
    crate::formats::pypi::PypiHandler::parse_filename(filename)
        .ok()
        .and_then(|info| info.version)
}

/// Collect deduped `(version, earliest upload-time)` pairs from a PEP 691
/// JSON simple index's `files` array. A version is as old as its earliest
/// file's PEP 700 `upload-time`; files without one contribute `None` (to be
/// filled from a fallback source). Files whose names don't parse to a
/// version are skipped here and kept by [`apply_pypi_simple_json_blocks`],
/// matching the HTML path's treatment of unparseable anchors.
pub(crate) fn collect_pypi_simple_json_versions(
    index: &serde_json::Value,
) -> Vec<(String, Option<DateTime<Utc>>)> {
    let Some(files) = index.get("files").and_then(|f| f.as_array()) else {
        return Vec::new();
    };

    let mut order: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut times: std::collections::HashMap<String, DateTime<Utc>> =
        std::collections::HashMap::new();

    for file in files {
        let Some(version) = file
            .get("filename")
            .and_then(|f| f.as_str())
            .and_then(pypi_filename_version)
        else {
            continue;
        };
        if let Some(ts) = file
            .get("upload-time")
            .and_then(|t| t.as_str())
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        {
            let ts = ts.with_timezone(&Utc);
            times
                .entry(version.clone())
                .and_modify(|earliest| {
                    if ts < *earliest {
                        *earliest = ts;
                    }
                })
                .or_insert(ts);
        }
        if seen.insert(version.clone()) {
            order.push(version);
        }
    }

    order
        .into_iter()
        .map(|version| {
            let ts = times.get(&version).copied();
            (version, ts)
        })
        .collect()
}

/// Fill publish times that are still `None` from a fallback map, without
/// overwriting times the document itself carried.
pub(crate) fn fill_missing_publish_times(
    versions: &mut [(String, Option<DateTime<Utc>>)],
    fallback: &std::collections::HashMap<String, DateTime<Utc>>,
) {
    for (version, ts) in versions {
        if ts.is_none() {
            *ts = fallback.get(version).copied();
        }
    }
}

/// Remove blocked versions from a PEP 691 JSON simple index: their `files`
/// entries and their PEP 700 `versions` list entries. Files that don't parse
/// to a version are kept, matching [`rebuild_pypi_simple_index_html`]'s
/// treatment of unparseable anchors.
pub(crate) fn apply_pypi_simple_json_blocks(
    index: &mut serde_json::Value,
    blocked: &std::collections::HashSet<String>,
) {
    if let Some(files) = index.get_mut("files").and_then(|f| f.as_array_mut()) {
        files.retain(|file| {
            file.get("filename")
                .and_then(|f| f.as_str())
                .and_then(pypi_filename_version)
                .map(|version| !blocked.contains(&version))
                .unwrap_or(true)
        });
    }
    if let Some(versions) = index.get_mut("versions").and_then(|v| v.as_array_mut()) {
        versions.retain(|v| v.as_str().map(|s| !blocked.contains(s)).unwrap_or(true));
    }
}

/// Map a repository format to the bounded Prometheus label used on age-gate
/// metrics. [`AgeGateService::is_applicable`] restricts the gate to npm/PyPI, so
/// other formats are never expected here; they collapse to `"other"` rather than
/// widening the label set.
fn format_label(format: &RepositoryFormat) -> &'static str {
    match format {
        RepositoryFormat::Npm => "npm",
        RepositoryFormat::Pypi => "pypi",
        _ => "other",
    }
}

/// Drop any `dist-tags` entry whose target version is no longer present in the
/// filtered packument, then re-point `latest` to the newest surviving version.
///
/// `allowed` is the set of versions that survived age-gate filtering and must be
/// sorted newest-first. When `allowed` is empty every tag is removed, leaving an
/// empty (but consistent) `dist-tags` object.
fn reconcile_dist_tags(packument: &mut serde_json::Value, allowed: &[String]) {
    let allowed_set: std::collections::HashSet<&str> = allowed.iter().map(String::as_str).collect();
    let Some(dist_tags) = packument
        .get_mut("dist-tags")
        .and_then(|d| d.as_object_mut())
    else {
        return;
    };
    dist_tags.retain(|_tag, target| target.as_str().is_some_and(|v| allowed_set.contains(v)));
    if let Some(latest) = allowed.first() {
        dist_tags.insert(
            "latest".to_string(),
            serde_json::Value::String(latest.clone()),
        );
    }
}

fn version_compare_desc(a: &str, b: &str) -> std::cmp::Ordering {
    match version_compare(a, b).cmp(&0) {
        std::cmp::Ordering::Equal => std::cmp::Ordering::Equal,
        std::cmp::Ordering::Less => std::cmp::Ordering::Greater,
        std::cmp::Ordering::Greater => std::cmp::Ordering::Less,
    }
}

fn version_compare(a: &str, b: &str) -> i32 {
    let (main_a, pre_a) = split_version_prerelease(a);
    let (main_b, pre_b) = split_version_prerelease(b);

    let main_cmp = compare_dot_segments(main_a, main_b);
    if main_cmp != 0 {
        return main_cmp;
    }

    match (pre_a, pre_b) {
        (None, None) => 0,
        (None, Some(_)) => 1,
        (Some(_), None) => -1,
        (Some(pa), Some(pb)) => compare_dot_segments(pa, pb),
    }
}

fn split_version_prerelease(version: &str) -> (&str, Option<&str>) {
    version
        .split_once('-')
        .map_or((version, None), |(main, pre)| (main, Some(pre)))
}

/// Compare two dot-separated version segment lists (the numeric core such as
/// `1.2.3`, or a prerelease tail such as `alpha.1`). Each segment is compared
/// numerically when both sides parse as integers, otherwise lexically. Missing
/// trailing segments default to `0`. Returns -1, 0, or 1.
fn compare_dot_segments(a: &str, b: &str) -> i32 {
    let seg_a: Vec<&str> = a.split('.').collect();
    let seg_b: Vec<&str> = b.split('.').collect();

    for i in 0..seg_a.len().max(seg_b.len()) {
        let sa = seg_a.get(i).unwrap_or(&"0");
        let sb = seg_b.get(i).unwrap_or(&"0");

        match (sa.parse::<u64>(), sb.parse::<u64>()) {
            (Ok(na), Ok(nb)) => {
                if na < nb {
                    return -1;
                }
                if na > nb {
                    return 1;
                }
            }
            _ => match sa.cmp(sb) {
                std::cmp::Ordering::Less => return -1,
                std::cmp::Ordering::Greater => return 1,
                std::cmp::Ordering::Equal => {}
            },
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    async fn try_db_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect(&url)
            .await
            .ok()
    }

    fn lazy_pool() -> sqlx::PgPool {
        sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not contact the database")
    }

    async fn create_age_gate_repo(
        pool: &sqlx::PgPool,
        format: RepositoryFormat,
        min_age_days: i32,
    ) -> (Uuid, String) {
        create_age_gate_repo_with(
            pool,
            format,
            min_age_days,
            AgeGateMode::default(),
            TEST_UPSTREAM,
        )
        .await
    }

    async fn create_age_gate_repo_with(
        pool: &sqlx::PgPool,
        format: RepositoryFormat,
        min_age_days: i32,
        mode: AgeGateMode,
        upstream_url: &str,
    ) -> (Uuid, String) {
        let id = Uuid::new_v4();
        let key = format!("age-gate-lib-{}-{}", format_label(&format), id);
        let format_sql = match format {
            RepositoryFormat::Npm => "npm",
            RepositoryFormat::Pypi => "pypi",
            _ => "generic",
        };
        sqlx::query(
            "INSERT INTO repositories (
                id, key, name, storage_path, repo_type, format, upstream_url,
                age_gate_enabled, age_gate_min_age_days, age_gate_mode
             )
             VALUES ($1, $2, $2, $3, 'remote', $4::repository_format, $5, true, $6, $7)",
        )
        .bind(id)
        .bind(&key)
        .bind(format!("/tmp/age-gate-lib/{id}"))
        .bind(format_sql)
        .bind(upstream_url)
        .bind(min_age_days)
        .bind(mode.as_str())
        .execute(pool)
        .await
        .expect("create age-gate repo");
        (id, key)
    }

    async fn create_reviewer(pool: &sqlx::PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let username = format!("age-gate-reviewer-{id}");
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
             VALUES ($1, $2, $3, 'unused', 'local', true, true)",
        )
        .bind(id)
        .bind(&username)
        .bind(format!("{username}@test.local"))
        .execute(pool)
        .await
        .expect("create reviewer");
        id
    }

    async fn insert_review_row(
        pool: &sqlx::PgPool,
        repository_id: Uuid,
        package_name: &str,
        version: &str,
        status: &str,
        published_at: Option<DateTime<Utc>>,
    ) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO age_gate_reviews (
                repository_id, package_name, package_version, upstream_published_at, status
             )
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id",
        )
        .bind(repository_id)
        .bind(package_name)
        .bind(version)
        .bind(published_at)
        .bind(status)
        .fetch_one(pool)
        .await
        .expect("insert review row")
    }

    /// Insert a review row with an explicit basis identity and reviewer
    /// (None = automatic), for the F2 state-transition tests.
    #[allow(clippy::too_many_arguments)]
    async fn insert_review_row_with_identity(
        pool: &sqlx::PgPool,
        repository_id: Uuid,
        package_name: &str,
        version: &str,
        status: &str,
        published_at: Option<DateTime<Utc>>,
        reviewed_by: Option<Uuid>,
        basis_mode: Option<&str>,
        basis_fingerprint: Option<&str>,
    ) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO age_gate_reviews (
                repository_id, package_name, package_version, upstream_published_at,
                status, reviewed_by, basis_mode, basis_upstream_fingerprint
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id",
        )
        .bind(repository_id)
        .bind(package_name)
        .bind(version)
        .bind(published_at)
        .bind(status)
        .bind(reviewed_by)
        .bind(basis_mode)
        .bind(basis_fingerprint)
        .fetch_one(pool)
        .await
        .expect("insert review row with identity")
    }

    async fn insert_artifact(
        pool: &sqlx::PgPool,
        repository_id: Uuid,
        package_name: &str,
        version: &str,
        path: &str,
    ) {
        sqlx::query(
            "INSERT INTO artifacts (
                repository_id, path, name, version, size_bytes, checksum_sha256,
                content_type, storage_key, is_deleted
             )
             VALUES ($1, $2, $3, $4, 128, $5, 'application/octet-stream', $2, false)",
        )
        .bind(repository_id)
        .bind(path)
        .bind(package_name)
        .bind(version)
        .bind("a".repeat(64))
        .execute(pool)
        .await
        .expect("insert artifact");
    }

    const TEST_UPSTREAM: &str = "https://upstream.example.test";

    fn npm_params(id: Uuid, key: String, min_age_days: i32) -> AgeGateRepoParams {
        params_with_mode(
            id,
            key,
            RepositoryFormat::Npm,
            min_age_days,
            AgeGateMode::UpstreamPublishTime,
        )
    }

    fn pypi_params(id: Uuid, key: String, min_age_days: i32) -> AgeGateRepoParams {
        params_with_mode(
            id,
            key,
            RepositoryFormat::Pypi,
            min_age_days,
            AgeGateMode::UpstreamPublishTime,
        )
    }

    fn params_with_mode(
        id: Uuid,
        key: String,
        format: RepositoryFormat,
        min_age_days: i32,
        mode: AgeGateMode,
    ) -> AgeGateRepoParams {
        AgeGateRepoParams::from_parts(
            id,
            key,
            RepositoryType::Remote,
            format,
            true,
            min_age_days,
            mode,
            Some(TEST_UPSTREAM.to_string()),
        )
    }

    #[test]
    fn package_age_days_at_threshold() {
        let published = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let now = published + Duration::days(7);
        assert_eq!(AgeGateService::package_age_days(published, now), 7);
        assert!(AgeGateService::meets_age_threshold(Some(published), 7, now));
        assert!(!AgeGateService::meets_age_threshold(
            Some(published),
            8,
            now
        ));
    }

    #[test]
    fn missing_timestamp_does_not_meet_threshold() {
        let now = Utc::now();
        assert!(!AgeGateService::meets_age_threshold(None, 7, now));
    }

    #[tokio::test]
    async fn service_constructs_and_exposes_metadata_cache() {
        let svc = AgeGateService::new(lazy_pool(), Arc::new(EventBus::new(4)));
        let packument = serde_json::json!({
            "time": { "1.0.0": "2024-01-01T00:00:00.000Z" }
        });

        let _cache = svc.metadata_cache();
        let parsed = UpstreamMetadataCache::parse_npm_publish_times(&packument);
        assert_eq!(parsed.len(), 1);
    }

    #[tokio::test]
    async fn disabled_or_unsupported_filters_return_without_db_access() {
        let svc = AgeGateService::new(lazy_pool(), Arc::new(EventBus::new(4)));
        let disabled = AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "npm-disabled",
            RepositoryType::Remote,
            RepositoryFormat::Npm,
            false,
            7,
            AgeGateMode::UpstreamPublishTime,
            Some(TEST_UPSTREAM.to_string()),
        );

        assert_eq!(
            svc.check(&disabled, "pkg", "1.0.0", None).await.unwrap(),
            AgeGateDecision::Allow
        );

        let mut packument = serde_json::json!({
            "versions": { "1.0.0": {} },
            "time": { "1.0.0": "2024-01-01T00:00:00.000Z" }
        });
        svc.filter_npm_packument(&disabled, "pkg", &mut packument)
            .await
            .unwrap();
        assert!(packument["versions"].get("1.0.0").is_some());
    }

    #[tokio::test]
    async fn db_check_review_crud_lkg_and_config_paths() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let bus = Arc::new(EventBus::new(64));
        let svc = AgeGateService::new(pool.clone(), bus);
        let (repo_id, repo_key) = create_age_gate_repo(&pool, RepositoryFormat::Npm, 7).await;
        let params = npm_params(repo_id, repo_key.clone(), 7);
        let reviewer = create_reviewer(&pool).await;

        insert_artifact(&pool, repo_id, "pkg", "1.0.0", "pkg/-/pkg-1.0.0.tgz").await;

        let young = Utc::now() - Duration::days(1);
        let decision = svc
            .check(&params, "pkg", "2.0.0", Some(young))
            .await
            .expect("young version should create pending review");
        let pending_id = match decision {
            AgeGateDecision::Block {
                review_id,
                last_known_good,
            } => {
                let lkg = last_known_good.expect("old cached artifact is last-known-good");
                assert_eq!(lkg.version, "1.0.0");
                assert_eq!(lkg.artifact_path, "pkg/-/pkg-1.0.0.tgz");
                review_id
            }
            AgeGateDecision::Allow => panic!("young version should be blocked"),
        };

        let pending = svc
            .get_review_by_id(pending_id)
            .await
            .expect("pending review");
        assert_eq!(pending.repository_key.as_deref(), Some(repo_key.as_str()));
        let (items, total) = svc
            .list_reviews(Some(&repo_key), Some(&["pending".to_string()]), 0, 10)
            .await
            .expect("list reviews");
        assert!(total >= 1);
        assert!(items.iter().any(|r| r.id == pending_id));

        let approved = svc
            .approve(pending_id, reviewer, Some("unit test approval"))
            .await
            .expect("approve pending review");
        assert_eq!(approved.status, "approved");
        assert_eq!(
            approved.review_reason.as_deref(),
            Some("unit test approval")
        );
        assert!(matches!(
            svc.check(&params, "pkg", "2.0.0", Some(young))
                .await
                .expect("approved review allows"),
            AgeGateDecision::Allow
        ));

        let reject_id =
            insert_review_row(&pool, repo_id, "pkg", "3.0.0", "pending", Some(young)).await;
        let rejected = svc
            .reject(reject_id, reviewer, Some("unit test rejection"))
            .await
            .expect("reject pending review");
        assert_eq!(rejected.status, "rejected");
        assert!(matches!(
            svc.check(
                &params,
                "pkg",
                "3.0.0",
                Some(Utc::now() - Duration::days(30))
            )
            .await
            .expect("rejected review stays blocked"),
            AgeGateDecision::Block { .. }
        ));

        insert_review_row(
            &pool,
            repo_id,
            "pkg",
            "4.0.0",
            "pending",
            Some(Utc::now() - Duration::days(30)),
        )
        .await;
        assert!(matches!(
            svc.check(
                &params,
                "pkg",
                "4.0.0",
                Some(Utc::now() - Duration::days(30))
            )
            .await
            .expect("old pending auto-approves"),
            AgeGateDecision::Allow
        ));

        svc.update_repo_config(repo_id, false, 14, AgeGateMode::UpstreamPublishTime)
            .await
            .expect("update repo config");
        let min_age_days: i32 =
            sqlx::query_scalar("SELECT age_gate_min_age_days FROM repositories WHERE id = $1")
                .bind(repo_id)
                .fetch_one(&pool)
                .await
                .expect("config row");
        assert_eq!(min_age_days, 14);

        assert!(svc.get_review_by_id(Uuid::new_v4()).await.is_err());
    }

    #[tokio::test]
    async fn db_reopen_and_redecide_flips_enforcement() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let bus = Arc::new(EventBus::new(64));
        let svc = AgeGateService::new(pool.clone(), bus);
        let (repo_id, repo_key) = create_age_gate_repo(&pool, RepositoryFormat::Npm, 7).await;
        let params = npm_params(repo_id, repo_key, 7);
        let reviewer = create_reviewer(&pool).await;

        // A young version is blocked and creates a pending review.
        let young = Utc::now() - Duration::days(1);
        let review_id = match svc.check(&params, "reopen-pkg", "1.0.0", Some(young)).await {
            Ok(AgeGateDecision::Block { review_id, .. }) => review_id,
            other => panic!("young version should block, got {other:?}"),
        };

        // Admin approves -> pulls are now allowed.
        let approved = svc
            .approve(review_id, reviewer, Some("looked fine"))
            .await
            .expect("approve pending");
        assert_eq!(approved.status, "approved");
        assert!(matches!(
            svc.check(&params, "reopen-pkg", "1.0.0", Some(young)).await,
            Ok(AgeGateDecision::Allow)
        ));

        // Re-approving an already-approved review is a refused no-op.
        assert!(svc.approve(review_id, reviewer, None).await.is_err());

        // Reopen the terminal review -> back to pending, and the young version is
        // re-blocked on the very next pull.
        let (prev, reopened) = svc
            .reopen(review_id, reviewer, Some("turned out bad"))
            .await
            .expect("reopen approved review");
        assert_eq!(prev, "approved");
        assert_eq!(reopened.status, "pending");
        assert!(matches!(
            svc.check(&params, "reopen-pkg", "1.0.0", Some(young)).await,
            Ok(AgeGateDecision::Block { .. })
        ));

        // Reject the reopened review -> hard block regardless of age.
        let rejected = svc
            .reject(review_id, reviewer, Some("confirmed bad"))
            .await
            .expect("reject reopened review");
        assert_eq!(rejected.status, "rejected");
        assert!(matches!(
            svc.check(
                &params,
                "reopen-pkg",
                "1.0.0",
                Some(Utc::now() - Duration::days(90))
            )
            .await,
            Ok(AgeGateDecision::Block { .. })
        ));

        // Directly re-approve the rejected review (no reopen step) -> unblocked.
        let reapproved = svc
            .approve(review_id, reviewer, Some("now fine"))
            .await
            .expect("re-approve rejected review");
        assert_eq!(reapproved.status, "approved");
        assert!(matches!(
            svc.check(&params, "reopen-pkg", "1.0.0", Some(young)).await,
            Ok(AgeGateDecision::Allow)
        ));

        // Direct re-decide the other way: reject an approved review -> re-blocked.
        let reblocked = svc
            .reject(review_id, reviewer, Some("re-block"))
            .await
            .expect("reject approved review");
        assert_eq!(reblocked.status, "rejected");
        assert!(matches!(
            svc.check(&params, "reopen-pkg", "1.0.0", Some(young)).await,
            Ok(AgeGateDecision::Block { .. })
        ));

        // Reopening an already-pending review is a refused no-op.
        let pending_id = insert_review_row(
            &pool,
            repo_id,
            "reopen-pkg",
            "2.0.0",
            "pending",
            Some(young),
        )
        .await;
        assert!(svc.reopen(pending_id, reviewer, None).await.is_err());
    }

    #[tokio::test]
    async fn db_metadata_filters_batch_reviews_and_sweep() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let bus = Arc::new(EventBus::new(64));
        let svc = AgeGateService::new(pool.clone(), bus);
        let (npm_id, npm_key) = create_age_gate_repo(&pool, RepositoryFormat::Npm, 7).await;
        let (pypi_id, pypi_key) = create_age_gate_repo(&pool, RepositoryFormat::Pypi, 7).await;
        let npm = npm_params(npm_id, npm_key, 7);
        let pypi = pypi_params(pypi_id, pypi_key, 7);

        let young = (Utc::now() - Duration::days(1)).to_rfc3339();
        let old = (Utc::now() - Duration::days(30)).to_rfc3339();
        let mut packument = serde_json::json!({
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": { "name": "batch-pkg", "version": "1.0.0" },
                "2.0.0": { "name": "batch-pkg", "version": "2.0.0" }
            },
            "time": {
                "1.0.0": old,
                "2.0.0": young
            }
        });
        svc.filter_npm_packument(&npm, "batch-pkg", &mut packument)
            .await
            .expect("filter npm packument");
        assert!(packument["versions"].get("1.0.0").is_some());
        assert!(packument["versions"].get("2.0.0").is_none());
        assert_eq!(packument["dist-tags"]["latest"], serde_json::json!("1.0.0"));

        let request_count: i32 = sqlx::query_scalar(
            "SELECT request_count FROM age_gate_reviews
             WHERE repository_id = $1 AND package_name = 'batch-pkg' AND package_version = '2.0.0'",
        )
        .bind(npm_id)
        .fetch_one(&pool)
        .await
        .expect("batch review row");
        assert_eq!(request_count, 1);

        let old_ts = Utc::now() - Duration::days(30);
        let young_ts = Utc::now() - Duration::days(1);
        let times = std::collections::HashMap::from([
            ("1.0.0".to_string(), old_ts),
            ("9.9.9".to_string(), young_ts),
        ]);
        let html = r#"<html><body>
<a href="/packages/demo-1.0.0.tar.gz#sha256=old">demo-1.0.0.tar.gz</a>
<a href="/packages/demo-9.9.9-py3-none-any.whl#sha256=young">demo-9.9.9-py3-none-any.whl</a>
</body></html>"#;
        let filtered = svc
            .filter_pypi_simple_index(&pypi, "demo", &times, html)
            .await
            .expect("filter pypi simple index");
        assert!(filtered.contains("demo-1.0.0.tar.gz"));
        assert!(!filtered.contains("demo-9.9.9"));

        insert_review_row(&pool, pypi_id, "sweep", "1.0.0", "pending", Some(old_ts)).await;
        insert_review_row(&pool, pypi_id, "sweep", "2.0.0", "pending", Some(young_ts)).await;
        svc.auto_approve_aged_reviews()
            .await
            .expect("sweep aged reviews");
        // Assert on row state, not the returned count: the sweep is global,
        // so a concurrently running test's sweep may legitimately get to the
        // aged row first.
        let status: String = sqlx::query_scalar(
            "SELECT status FROM age_gate_reviews
             WHERE repository_id = $1 AND package_name = 'sweep' AND package_version = '1.0.0'",
        )
        .bind(pypi_id)
        .fetch_one(&pool)
        .await
        .expect("aged sweep row");
        assert_eq!(status, "approved");
        let status: String = sqlx::query_scalar(
            "SELECT status FROM age_gate_reviews
             WHERE repository_id = $1 AND package_name = 'sweep' AND package_version = '2.0.0'",
        )
        .bind(pypi_id)
        .fetch_one(&pool)
        .await
        .expect("young sweep row");
        assert_eq!(status, "pending");
    }

    #[test]
    fn version_compare_orders_semverish() {
        assert!(version_compare("2.0.0", "1.0.0") > 0);
        assert!(version_compare("1.0.0", "2.0.0") < 0);
        assert_eq!(version_compare("1.0.0", "1.0.0"), 0);
    }

    #[test]
    fn format_label_maps_to_bounded_set() {
        assert_eq!(format_label(&RepositoryFormat::Npm), "npm");
        assert_eq!(format_label(&RepositoryFormat::Pypi), "pypi");
        // Anything outside the gate's supported formats collapses to "other"
        // so the metric label set stays bounded.
        assert_eq!(format_label(&RepositoryFormat::Generic), "other");
    }

    #[test]
    fn extract_href_filename_parses_anchor() {
        let html = r#"<a href="/packages/requests/2.31.0/requests-2.31.0.tar.gz">link</a>"#;
        assert_eq!(
            extract_href_filename(html),
            Some("requests-2.31.0.tar.gz".to_string())
        );
    }

    #[test]
    fn extract_href_filename_strips_sha256_fragment() {
        // Real PEP 503 anchors always carry a `#sha256=...` hash fragment; the
        // proxy also rewrites the href to a repo-relative path. Both must reduce
        // to the bare filename, otherwise `parse_filename` rejects every anchor
        // and the simple-index age-gate filter silently passes everything.
        let html = r#"<a href="/pypi/pypi-proxy/simple/click/click-8.4.2-py3-none-any.whl#sha256=deadbeef">click-8.4.2-py3-none-any.whl</a>"#;
        assert_eq!(
            extract_href_filename(html),
            Some("click-8.4.2-py3-none-any.whl".to_string())
        );
        assert_eq!(pypi_anchor_version(html), Some("8.4.2".to_string()));
    }

    #[test]
    fn extract_href_filename_strips_query_string() {
        let html = r#"<a href="../requests-2.31.0.tar.gz?foo=bar">link</a>"#;
        assert_eq!(
            extract_href_filename(html),
            Some("requests-2.31.0.tar.gz".to_string())
        );
    }

    #[test]
    fn reconcile_dist_tags_repoints_latest_to_newest_allowed() {
        // `latest` pointed at 3.0.0, which was blocked/removed.
        let mut packument = serde_json::json!({
            "dist-tags": { "latest": "3.0.0" },
            "versions": { "1.0.0": {}, "2.0.0": {} },
        });
        reconcile_dist_tags(&mut packument, &["2.0.0".to_string(), "1.0.0".to_string()]);
        assert_eq!(packument["dist-tags"]["latest"], serde_json::json!("2.0.0"));
    }

    #[test]
    fn reconcile_dist_tags_removes_dangling_non_latest_tag() {
        // A prerelease `beta` tag points at a blocked version; it must be dropped so
        // `npm install pkg@beta` does not resolve to a missing manifest.
        let mut packument = serde_json::json!({
            "dist-tags": { "latest": "1.0.0", "beta": "2.0.0-beta.1" },
            "versions": { "1.0.0": {} },
        });
        reconcile_dist_tags(&mut packument, &["1.0.0".to_string()]);
        let tags = packument["dist-tags"].as_object().unwrap();
        assert_eq!(tags.get("latest"), Some(&serde_json::json!("1.0.0")));
        assert!(!tags.contains_key("beta"));
    }

    #[test]
    fn reconcile_dist_tags_empties_when_all_versions_blocked() {
        // Every version was blocked: dist-tags must end up empty rather than dangling.
        let mut packument = serde_json::json!({
            "dist-tags": { "latest": "1.0.0", "next": "1.1.0" },
            "versions": {},
        });
        reconcile_dist_tags(&mut packument, &[]);
        assert!(packument["dist-tags"].as_object().unwrap().is_empty());
    }

    fn view(status: &str, is_automatic: bool, identity: ReviewIdentityMatch) -> ReviewPolicyView {
        ReviewPolicyView {
            status: status.to_string(),
            is_automatic,
            identity,
        }
    }

    #[test]
    fn decide_age_gate_check_truth_table() {
        use ReviewIdentityMatch::{Differs, Legacy, Matches};
        // Rejections block coordinate-wide, regardless of threshold,
        // identity, or who recorded them.
        for identity in [Matches, Differs, Legacy] {
            for meets in [false, true] {
                assert_eq!(
                    decide_age_gate_check(Some(&view("rejected", false, identity)), meets),
                    AgeGateCheckAction::BlockRejected
                );
            }
        }
        // The current-clock threshold decides; pending rows are retired on
        // the way through.
        assert_eq!(
            decide_age_gate_check(Some(&view("pending", true, Matches)), true),
            AgeGateCheckAction::AllowAndAutoApprovePending
        );
        assert_eq!(decide_age_gate_check(None, true), AgeGateCheckAction::Allow);
        assert_eq!(
            decide_age_gate_check(Some(&view("approved", true, Differs)), true),
            AgeGateCheckAction::Allow,
            "meeting the threshold on the current basis allows regardless of row state"
        );
        // Below the threshold, only an identity-bound (or legacy) MANUAL
        // approval still allows.
        assert_eq!(
            decide_age_gate_check(Some(&view("approved", false, Matches)), false),
            AgeGateCheckAction::AllowAlreadyApproved
        );
        assert_eq!(
            decide_age_gate_check(Some(&view("approved", false, Legacy)), false),
            AgeGateCheckAction::AllowAlreadyApproved,
            "pre-identity manual approvals keep their effect"
        );
        assert_eq!(
            decide_age_gate_check(Some(&view("approved", false, Differs)), false),
            AgeGateCheckAction::BlockAndResetReview,
            "a manual approval under a different identity is voided"
        );
        // Automatic approvals are never sticky.
        for identity in [Matches, Differs, Legacy] {
            assert_eq!(
                decide_age_gate_check(Some(&view("approved", true, identity)), false),
                AgeGateCheckAction::BlockAndResetReview,
                "an automatic approval that no longer holds is voided ({identity:?})"
            );
        }
        assert_eq!(
            decide_age_gate_check(None, false),
            AgeGateCheckAction::BlockAndRequestReview
        );
        assert_eq!(
            decide_age_gate_check(Some(&view("pending", true, Matches)), false),
            AgeGateCheckAction::BlockAndRequestReview
        );
    }

    #[test]
    fn review_identity_match_rules() {
        use ReviewIdentityMatch::{Differs, Legacy, Matches};
        let fp = "aaaa";
        assert_eq!(
            review_identity_match(Some("first_seen"), Some(fp), AgeGateMode::FirstSeen, fp),
            Matches
        );
        assert_eq!(
            review_identity_match(None, None, AgeGateMode::FirstSeen, fp),
            Legacy
        );
        assert_eq!(
            review_identity_match(
                Some("upstream_publish_time"),
                Some(fp),
                AgeGateMode::FirstSeen,
                fp
            ),
            Differs,
            "mode changed"
        );
        assert_eq!(
            review_identity_match(Some("first_seen"), Some("bbbb"), AgeGateMode::FirstSeen, fp),
            Differs,
            "upstream changed"
        );
        assert_eq!(
            review_identity_match(Some("first_seen"), None, AgeGateMode::FirstSeen, fp),
            Differs,
            "half-recorded identity is not legacy"
        );
    }

    fn package_review(
        status: &str,
        is_automatic: bool,
        identity_fp: Option<&str>,
    ) -> PackageReviewRow {
        PackageReviewRow {
            status: status.to_string(),
            is_automatic,
            basis_mode: identity_fp.map(|_| "upstream_publish_time".to_string()),
            basis_upstream_fingerprint: identity_fp.map(str::to_string),
        }
    }

    #[test]
    fn classify_versions_for_metadata_listing_classifies_correctly() {
        let now = Utc.with_ymd_and_hms(2024, 7, 1, 0, 0, 0).unwrap();
        let young = now - Duration::days(1);
        let old = now - Duration::days(30);
        let fp = "current-fp";
        let mut existing = std::collections::HashMap::new();
        // Rejected: blocked, no re-request.
        existing.insert(
            "1.0.0".to_string(),
            package_review("rejected", false, Some(fp)),
        );
        // Manual approval bound to the current identity: listed while young.
        existing.insert(
            "2.0.0".to_string(),
            package_review("approved", false, Some(fp)),
        );
        // Manual approval bound to a DIFFERENT identity: withheld + re-requested.
        existing.insert(
            "5.0.0".to_string(),
            package_review("approved", false, Some("other-fp")),
        );
        // AUTOMATIC approval (same identity) whose eligibility no longer
        // holds on the current clock: withheld + re-requested.
        existing.insert(
            "6.0.0".to_string(),
            package_review("approved", true, Some(fp)),
        );
        // Legacy (pre-identity) manual approval: listed.
        existing.insert("7.0.0".to_string(), package_review("approved", false, None));

        let versions = vec![
            ("1.0.0".to_string(), Some(young)),
            ("2.0.0".to_string(), Some(young)),
            ("3.0.0".to_string(), Some(old)),
            ("4.0.0".to_string(), Some(young)),
            ("5.0.0".to_string(), Some(young)),
            ("6.0.0".to_string(), Some(young)),
            ("7.0.0".to_string(), Some(young)),
        ];
        let out = classify_versions_for_metadata_listing(
            &versions,
            &existing,
            7,
            AgeGateMode::UpstreamPublishTime,
            fp,
            now,
        );
        assert!(out.blocked.contains("1.0.0"));
        assert!(!out.blocked.contains("2.0.0"));
        assert!(!out.blocked.contains("3.0.0"));
        assert!(out.blocked.contains("4.0.0"));
        assert!(
            out.blocked.contains("5.0.0"),
            "stale-identity manual approval"
        );
        assert!(
            out.blocked.contains("6.0.0"),
            "automatic approval recomputed"
        );
        assert!(
            !out.blocked.contains("7.0.0"),
            "legacy manual approval honored"
        );
        let mut requested = out.request_versions.clone();
        requested.sort();
        assert_eq!(
            requested,
            vec![
                "4.0.0".to_string(),
                "5.0.0".to_string(),
                "6.0.0".to_string()
            ],
            "stale approvals re-enter the queue; rejections do not"
        );
    }

    #[test]
    fn validate_min_age_days_range() {
        assert!(
            validate_min_age_days(0).is_ok(),
            "0 is the trusted-remote setting: no delay, rejections still block"
        );
        assert!(validate_min_age_days(1).is_ok());
        assert!(validate_min_age_days(3650).is_ok());
        assert!(validate_min_age_days(-1).is_err());
        assert!(validate_min_age_days(3651).is_err());
    }

    #[test]
    fn require_distinct_status_refuses_only_noop_transitions() {
        // Approve is allowed from pending and rejected, refused from approved.
        assert!(require_distinct_status("pending", AgeGateReviewStatus::Approved).is_ok());
        assert!(require_distinct_status("rejected", AgeGateReviewStatus::Approved).is_ok());
        assert!(require_distinct_status("approved", AgeGateReviewStatus::Approved).is_err());
        // Reject is allowed from pending and approved, refused from rejected.
        assert!(require_distinct_status("approved", AgeGateReviewStatus::Rejected).is_ok());
        assert!(require_distinct_status("rejected", AgeGateReviewStatus::Rejected).is_err());
        // Reopen is allowed from any terminal state, refused when already pending.
        assert!(require_distinct_status("approved", AgeGateReviewStatus::Pending).is_ok());
        assert!(require_distinct_status("rejected", AgeGateReviewStatus::Pending).is_ok());
        assert!(require_distinct_status("pending", AgeGateReviewStatus::Pending).is_err());
    }

    #[test]
    fn collect_and_apply_npm_packument_blocks() {
        let mut packument = serde_json::json!({
            "dist-tags": { "latest": "2.0.0" },
            "versions": { "1.0.0": {}, "2.0.0": {} },
            "time": { "1.0.0": "2024-01-01T00:00:00.000Z", "2.0.0": "2024-06-01T00:00:00.000Z" }
        });
        let mut blocked = std::collections::HashSet::new();
        blocked.insert("2.0.0".to_string());
        let allowed = apply_npm_packument_blocks(&mut packument, &blocked);
        assert_eq!(allowed, vec!["1.0.0".to_string()]);
        assert!(packument["versions"].get("2.0.0").is_none());
        assert!(packument["time"].get("2.0.0").is_none());
        assert_eq!(packument["dist-tags"]["latest"], serde_json::json!("1.0.0"));

        let times = UpstreamMetadataCache::parse_npm_publish_times(&packument);
        let collected = collect_npm_packument_versions(&packument, &times);
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].0, "1.0.0");
    }

    #[test]
    fn collect_and_apply_npm_handles_missing_shapes() {
        let mut packument = serde_json::json!({ "name": "empty" });
        let blocked = std::collections::HashSet::from(["1.0.0".to_string()]);
        assert!(
            collect_npm_packument_versions(&packument, &std::collections::HashMap::new())
                .is_empty()
        );
        assert!(apply_npm_packument_blocks(&mut packument, &blocked).is_empty());
        assert_eq!(packument["name"], "empty");
    }

    #[test]
    fn parse_and_rebuild_pypi_simple_index() {
        let html = r#"<html><body>
<a href="/pkg/requests-1.0.0.tar.gz">1.0.0</a>
<a href="/pkg/requests-2.0.0.tar.gz">2.0.0</a>
<a href="/pkg/readme">readme</a>
</body></html>"#;
        let (spans, mut versions) = parse_pypi_simple_index_anchors(html);
        assert_eq!(spans.len(), 3);
        assert_eq!(versions.len(), 2);
        let mut blocked = std::collections::HashSet::new();
        blocked.insert("2.0.0".to_string());
        let out = rebuild_pypi_simple_index_html(html, &spans, &blocked);
        assert!(out.contains("requests-1.0.0.tar.gz"));
        assert!(!out.contains("requests-2.0.0.tar.gz"));
        assert!(out.contains("readme"));

        attach_pypi_publish_times(&mut versions, &std::collections::HashMap::new());
        assert!(versions.iter().all(|(_, ts)| ts.is_none()));
    }

    #[test]
    fn parse_pypi_simple_index_dedupes_and_attaches_publish_times() {
        let html = r#"<a href="/pkg/demo-1.0.0.tar.gz">sdist</a>
<a href="/pkg/demo-1.0.0-py3-none-any.whl#sha256=abc">wheel</a>
<a href="">empty</a>
<a href="/pkg/demo-2.0.0.tar.gz">missing close"#;
        let (spans, mut versions) = parse_pypi_simple_index_anchors(html);
        assert_eq!(spans.len(), 3);
        assert_eq!(versions, vec![("1.0.0".to_string(), None)]);

        let published = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        attach_pypi_publish_times(
            &mut versions,
            &std::collections::HashMap::from([("1.0.0".to_string(), published)]),
        );
        assert_eq!(versions[0].1, Some(published));

        let rebuilt = rebuild_pypi_simple_index_html(
            html,
            &spans,
            &std::collections::HashSet::from(["1.0.0".to_string()]),
        );
        assert!(!rebuilt.contains("demo-1.0.0"));
        assert!(rebuilt.contains("missing close"));
    }

    #[test]
    fn collect_pypi_simple_json_versions_dedupes_and_takes_earliest_upload_time() {
        let early = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let late = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();
        let index = serde_json::json!({
            "meta": { "api-version": "1.1" },
            "name": "demo",
            "files": [
                { "filename": "demo-1.0.0.tar.gz",
                  "upload-time": late.to_rfc3339() },
                { "filename": "demo-1.0.0-py3-none-any.whl",
                  "upload-time": early.to_rfc3339() },
                { "filename": "demo-2.0.0.tar.gz" },
                { "filename": "not-a-parseable-dist" },
            ],
            "versions": ["1.0.0", "2.0.0"],
        });

        let versions = collect_pypi_simple_json_versions(&index);
        assert_eq!(
            versions,
            vec![
                ("1.0.0".to_string(), Some(early)),
                ("2.0.0".to_string(), None),
            ],
            "one entry per version, earliest file upload-time wins, \
             unparseable filenames are skipped"
        );

        // Documents with no files array contribute nothing.
        assert!(collect_pypi_simple_json_versions(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn fill_missing_publish_times_never_overwrites_document_times() {
        let doc_time = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let fallback_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let mut versions = vec![
            ("1.0.0".to_string(), Some(doc_time)),
            ("2.0.0".to_string(), None),
            ("3.0.0".to_string(), None),
        ];
        let fallback = std::collections::HashMap::from([
            ("1.0.0".to_string(), fallback_time),
            ("2.0.0".to_string(), fallback_time),
        ]);
        fill_missing_publish_times(&mut versions, &fallback);
        assert_eq!(versions[0].1, Some(doc_time), "document time kept");
        assert_eq!(versions[1].1, Some(fallback_time), "gap filled");
        assert_eq!(versions[2].1, None, "absent from fallback stays None");
    }

    #[test]
    fn apply_pypi_simple_json_blocks_removes_files_and_versions_entries() {
        let mut index = serde_json::json!({
            "name": "demo",
            "files": [
                { "filename": "demo-1.0.0.tar.gz", "url": "u1" },
                { "filename": "demo-2.0.0.tar.gz", "url": "u2" },
                { "filename": "demo-2.0.0-py3-none-any.whl", "url": "u3" },
                { "filename": "not-a-parseable-dist", "url": "u4" },
            ],
            "versions": ["1.0.0", "2.0.0"],
        });
        let blocked = std::collections::HashSet::from(["2.0.0".to_string()]);
        apply_pypi_simple_json_blocks(&mut index, &blocked);

        let files: Vec<&str> = index["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["filename"].as_str().unwrap())
            .collect();
        assert_eq!(
            files,
            vec!["demo-1.0.0.tar.gz", "not-a-parseable-dist"],
            "blocked version's files removed, unparseable filename kept"
        );
        assert_eq!(
            index["versions"],
            serde_json::json!(["1.0.0"]),
            "PEP 700 versions entry for the blocked version removed"
        );
    }

    #[test]
    fn select_newest_approved_artifact_picks_highest_version() {
        let candidates = vec![
            ("1.0.0".to_string(), "path/a".to_string()),
            ("2.0.0".to_string(), "path/b".to_string()),
            ("1.5.0".to_string(), "path/c".to_string()),
        ];
        let lkg = select_newest_approved_artifact(&candidates).unwrap();
        assert_eq!(lkg.version, "2.0.0");
        assert_eq!(lkg.artifact_path, "path/b");
        assert!(select_newest_approved_artifact(&[]).is_none());
    }

    #[test]
    fn is_applicable_matrix() {
        let npm_remote = AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "npm-remote",
            RepositoryType::Remote,
            RepositoryFormat::Npm,
            true,
            7,
            Default::default(),
            None,
        );
        assert!(AgeGateService::is_applicable(&npm_remote));

        let disabled = AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "npm-off",
            RepositoryType::Remote,
            RepositoryFormat::Npm,
            false,
            7,
            Default::default(),
            None,
        );
        assert!(!AgeGateService::is_applicable(&disabled));

        let local = AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "local",
            RepositoryType::Local,
            RepositoryFormat::Npm,
            true,
            7,
            Default::default(),
            None,
        );
        assert!(!AgeGateService::is_applicable(&local));
    }

    #[test]
    fn version_compare_prerelease_segments() {
        assert!(version_compare("1.0.0-beta.1", "1.0.0") < 0);
        assert!(version_compare("2.0.0-alpha", "2.0.0-beta") < 0);
    }

    #[test]
    fn version_compare_desc_inverts_ascending_order() {
        use std::cmp::Ordering;
        // Descending: the newer version sorts first.
        assert_eq!(version_compare_desc("1.0.0", "2.0.0"), Ordering::Greater);
        assert_eq!(version_compare_desc("2.0.0", "1.0.0"), Ordering::Less);
        assert_eq!(version_compare_desc("1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn version_compare_non_numeric_segments_fall_back_to_lexical() {
        // Core segments that do not parse as integers compare lexically.
        assert!(version_compare("1.0.x", "1.0.y") < 0);
        assert!(version_compare("1.0.y", "1.0.x") > 0);
        // An equal non-numeric segment advances to the next differing segment.
        assert!(version_compare("1.x.0", "1.x.1") < 0);
    }

    #[test]
    fn version_compare_prerelease_numeric_and_release_precedence() {
        // Numeric prerelease identifiers compare numerically, not lexically.
        assert!(version_compare("1.0.0-1", "1.0.0-2") < 0);
        assert!(version_compare("1.0.0-2", "1.0.0-1") > 0);
        // A release outranks any prerelease of the same core version.
        assert!(version_compare("1.0.0", "1.0.0-rc.1") > 0);
        // A higher alphanumeric prerelease sorts after a lower one.
        assert!(version_compare("2.0.0-beta", "2.0.0-alpha") > 0);
        // Identical prerelease tails are equal.
        assert_eq!(version_compare("1.0.0-alpha.1", "1.0.0-alpha.1"), 0);
    }

    #[test]
    fn pypi_anchor_version_parses_wheel() {
        let anchor =
            r#"<a href="/packages/requests/2.31.0/requests-2.31.0-py3-none-any.whl">link</a>"#;
        assert_eq!(pypi_anchor_version(anchor), Some("2.31.0".to_string()));
    }

    #[test]
    fn mode_round_trips_through_its_wire_form() {
        for mode in [AgeGateMode::UpstreamPublishTime, AgeGateMode::FirstSeen] {
            assert_eq!(AgeGateMode::parse(mode.as_str()).unwrap(), mode);
        }
        assert_eq!(AgeGateMode::default(), AgeGateMode::UpstreamPublishTime);
        // An unknown mode is a client error, never a silent default: a typo
        // must not quietly downgrade a repository to publish-time trust.
        assert!(matches!(
            AgeGateMode::parse("firstseen"),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn upstream_fingerprint_is_stable_across_cosmetic_spellings() {
        let canonical = upstream_fingerprint(Some("https://registry.npmjs.org"));
        // Trailing slash, upper-case host and an explicit default port all
        // name the same registry.
        assert_eq!(
            canonical,
            upstream_fingerprint(Some("https://registry.npmjs.org/"))
        );
        assert_eq!(
            canonical,
            upstream_fingerprint(Some("https://Registry.NPMJS.org"))
        );
        assert_eq!(
            canonical,
            upstream_fingerprint(Some("https://registry.npmjs.org:443"))
        );
        // A different registry — or none at all — must not share the bucket,
        // or a repoint would inherit the previous upstream's elapsed age.
        assert_ne!(
            canonical,
            upstream_fingerprint(Some("https://evil.example.test"))
        );
        assert_ne!(canonical, upstream_fingerprint(None));
        // Paths stay case-sensitive: most registries treat them that way.
        assert_ne!(
            upstream_fingerprint(Some("https://example.test/Repo")),
            upstream_fingerprint(Some("https://example.test/repo"))
        );
    }

    #[test]
    fn normalize_format_collapses_registry_protocol_aliases() {
        use RepositoryFormat as F;
        assert_eq!(AgeGateService::normalize_format(F::Yarn), F::Npm);
        assert_eq!(AgeGateService::normalize_format(F::Pnpm), F::Npm);
        assert_eq!(AgeGateService::normalize_format(F::Poetry), F::Pypi);
        assert_eq!(AgeGateService::normalize_format(F::Npm), F::Npm);
        assert_eq!(AgeGateService::normalize_format(F::Pypi), F::Pypi);
        assert_eq!(AgeGateService::normalize_format(F::Generic), F::Generic);
    }

    #[test]
    fn supported_format_mode_matrix() {
        for mode in [AgeGateMode::UpstreamPublishTime, AgeGateMode::FirstSeen] {
            assert!(AgeGateService::supports_format_mode(
                &RepositoryFormat::Npm,
                mode
            ));
            assert!(AgeGateService::supports_format_mode(
                &RepositoryFormat::Pypi,
                mode
            ));
            // No registry entry -> not gateable in any mode. NuGet stays
            // here until its enforcement seam lands.
            assert!(!AgeGateService::supports_format_mode(
                &RepositoryFormat::Cargo,
                mode
            ));
            assert!(!AgeGateService::supports_format_mode(
                &RepositoryFormat::Maven,
                mode
            ));
            assert!(!AgeGateService::supports_format_mode(
                &RepositoryFormat::Nuget,
                mode
            ));
        }
        // Go: immutable module-proxy coordinates support first_seen, but
        // .info VCS timestamps are publisher-controlled — no publish-time
        // resolver, so that mode stays unsupported.
        assert!(AgeGateService::supports_format_mode(
            &RepositoryFormat::Go,
            AgeGateMode::FirstSeen
        ));
        assert!(!AgeGateService::supports_format_mode(
            &RepositoryFormat::Go,
            AgeGateMode::UpstreamPublishTime
        ));
    }

    /// F3: an ENABLED gate on a format/mode pair the server cannot enforce is
    /// a fail-closed configuration error on every policy path — check and
    /// listing filters alike — never a silent no-op that reports an enabled
    /// gate while serving everything. (A DISABLED unsupported repo simply
    /// isn't gated; see the test above.)
    #[tokio::test]
    async fn enabled_unsupported_configuration_fails_closed() {
        let svc = AgeGateService::new(lazy_pool(), Arc::new(EventBus::new(4)));
        let cargo = AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "cargo-remote",
            RepositoryType::Remote,
            RepositoryFormat::Cargo,
            true,
            7,
            AgeGateMode::UpstreamPublishTime,
            Some(TEST_UPSTREAM.to_string()),
        );

        assert!(matches!(
            svc.check(&cargo, "pkg", "1.0.0", None).await,
            Err(AppError::Internal(_))
        ));

        let html = "<a href=\"pkg-1.0.0.tar.gz\">pkg-1.0.0.tar.gz</a>";
        assert!(matches!(
            svc.filter_pypi_simple_index(&cargo, "pkg", &std::collections::HashMap::new(), html)
                .await,
            Err(AppError::Internal(_))
        ));

        let mut packument = serde_json::json!({
            "versions": { "1.0.0": {} },
            "time": { "1.0.0": "2024-01-01T00:00:00.000Z" }
        });
        assert!(matches!(
            svc.filter_npm_packument(&cargo, "pkg", &mut packument)
                .await,
            Err(AppError::Internal(_))
        ));
    }

    /// Gate policy comes from the repository row, on every request.
    #[tokio::test]
    async fn db_resolve_repo_params_reads_policy_from_the_row() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let (repo_id, repo_key) = create_age_gate_repo_with(
            &pool,
            RepositoryFormat::Pypi,
            21,
            AgeGateMode::FirstSeen,
            "https://pypi.example.test/simple",
        )
        .await;

        let params = resolve_repo_params(&pool, repo_id).await.expect("resolve");
        assert_eq!(params.key, repo_key);
        assert_eq!(params.format, RepositoryFormat::Pypi);
        assert_eq!(params.repo_type, RepositoryType::Remote);
        assert!(params.age_gate_enabled);
        assert_eq!(params.age_gate_min_age_days, 21);
        assert_eq!(params.age_gate_mode, AgeGateMode::FirstSeen);
        assert_eq!(
            params.upstream_url.as_deref(),
            Some("https://pypi.example.test/simple")
        );
        assert!(AgeGateService::is_applicable(&params));

        // A repository that cannot be read fails the request rather than
        // impersonating a disabled gate.
        assert!(matches!(
            resolve_repo_params(&pool, Uuid::new_v4()).await,
            Err(AppError::NotFound(_))
        ));
    }

    /// Observations are insert-once, and they belong to the upstream they were
    /// made against: repointing a remote at a different registry must not let
    /// a same-named version inherit the age of the version it replaces.
    #[tokio::test]
    async fn db_first_seen_observations_are_insert_once_and_upstream_bound() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let svc = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        let (repo_id, repo_key) = create_age_gate_repo_with(
            &pool,
            RepositoryFormat::Npm,
            7,
            AgeGateMode::FirstSeen,
            "https://registry-a.example.test",
        )
        .await;
        let mut params = params_with_mode(
            repo_id,
            repo_key,
            RepositoryFormat::Npm,
            7,
            AgeGateMode::FirstSeen,
        );
        params.upstream_url = Some("https://registry-a.example.test".to_string());

        let versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
        let first = svc
            .observe_versions_first_seen(&params, "pkg", &versions)
            .await
            .expect("first observation");
        assert_eq!(first.len(), 2);

        // Re-observing reads the original timestamps back rather than moving
        // the clock forward — otherwise a version would never age while it was
        // being listed.
        let again = svc
            .observe_versions_first_seen(&params, "pkg", &versions)
            .await
            .expect("second observation");
        assert_eq!(first, again);

        // Repointed upstream: same repository, same coordinates, different
        // registry -> a fresh clock, with the original observation preserved.
        let mut repointed = params.clone();
        repointed.upstream_url = Some("https://registry-b.example.test".to_string());
        let after_repoint = svc
            .observe_versions_first_seen(&repointed, "pkg", &versions)
            .await
            .expect("observation after repoint");
        assert_ne!(after_repoint["1.0.0"], first["1.0.0"]);
        assert!(after_repoint["1.0.0"] > first["1.0.0"]);

        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM age_gate_version_observations WHERE repository_id = $1",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("count observations");
        assert_eq!(rows, 4, "two versions on each of two upstreams");
    }

    /// The `first_seen` clock starts at first contact and needs no upstream
    /// metadata: a version nobody has asked for before is blocked on sight,
    /// and the same version allowed once its observation has aged past the
    /// threshold.
    #[tokio::test]
    async fn db_first_seen_blocks_on_first_sight_and_allows_once_aged() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let svc = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        let (repo_id, repo_key) = create_age_gate_repo_with(
            &pool,
            RepositoryFormat::Npm,
            7,
            AgeGateMode::FirstSeen,
            TEST_UPSTREAM,
        )
        .await;
        let params = params_with_mode(
            repo_id,
            repo_key,
            RepositoryFormat::Npm,
            7,
            AgeGateMode::FirstSeen,
        );

        // No publish time is consulted anywhere in this flow. A lookup
        // before any evidence records nothing; the observation is created
        // only once existence is proven.
        assert!(svc
            .lookup_first_seen(&params, "pkg", "1.0.0")
            .await
            .expect("lookup before evidence")
            .is_none());
        let basis = svc
            .observe_first_seen(&params, "pkg", "1.0.0")
            .await
            .expect("observe with evidence");
        assert!(basis.is_some());

        let decision = svc
            .check(&params, "pkg", "1.0.0", basis)
            .await
            .expect("first sight decides");
        let review_id = match decision {
            AgeGateDecision::Block { review_id, .. } => review_id,
            AgeGateDecision::Allow => panic!("a just-observed version must not pass a 7-day gate"),
        };

        // The review records the basis the decision was made from.
        let recorded: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT upstream_published_at FROM age_gate_reviews WHERE id = $1")
                .bind(review_id)
                .fetch_one(&pool)
                .await
                .expect("review row");
        assert_eq!(recorded, basis);

        // Age the observation past the threshold; the same request now passes
        // (and retires the pending review).
        sqlx::query(
            "UPDATE age_gate_version_observations SET first_seen_at = NOW() - INTERVAL '30 days'
             WHERE repository_id = $1 AND package_name = 'pkg'",
        )
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("backdate observation");

        let aged = svc
            .lookup_first_seen(&params, "pkg", "1.0.0")
            .await
            .expect("read back aged observation");
        assert!(matches!(
            svc.check(&params, "pkg", "1.0.0", aged).await.unwrap(),
            AgeGateDecision::Allow
        ));
    }

    /// In `first_seen` mode the listing filter ignores the upstream's own
    /// timestamps — that claim is exactly what the mode declines to trust — so
    /// even objectively ancient versions are withheld until this server has
    /// watched them for the threshold. Listing and download therefore agree.
    #[tokio::test]
    async fn db_first_seen_listing_filter_ignores_upstream_publish_times() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let svc = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        let (repo_id, repo_key) = create_age_gate_repo_with(
            &pool,
            RepositoryFormat::Npm,
            7,
            AgeGateMode::FirstSeen,
            TEST_UPSTREAM,
        )
        .await;
        let params = params_with_mode(
            repo_id,
            repo_key,
            RepositoryFormat::Npm,
            7,
            AgeGateMode::FirstSeen,
        );

        let packument = || {
            serde_json::json!({
                "versions": { "1.0.0": {}, "2.0.0": {} },
                "time": {
                    // The registry says these are years old.
                    "1.0.0": "2019-01-01T00:00:00.000Z",
                    "2.0.0": "2020-01-01T00:00:00.000Z"
                }
            })
        };

        let mut doc = packument();
        svc.filter_npm_packument(&params, "pkg", &mut doc)
            .await
            .expect("filter on first sight");
        assert!(
            doc["versions"].as_object().unwrap().is_empty(),
            "first_seen must withhold every unobserved version regardless of \
             the publish times the upstream reports"
        );

        // Once the observations themselves have aged, the versions appear.
        sqlx::query(
            "UPDATE age_gate_version_observations SET first_seen_at = NOW() - INTERVAL '30 days'
             WHERE repository_id = $1 AND package_name = 'pkg'",
        )
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("backdate observations");

        let mut doc = packument();
        svc.filter_npm_packument(&params, "pkg", &mut doc)
            .await
            .expect("filter once aged");
        assert_eq!(doc["versions"].as_object().unwrap().len(), 2);
    }

    /// A pending review's basis timestamp means something different under each
    /// mode, so switching the mode invalidates it: those versions block until
    /// re-observed on the new clock. Reviewed rows are not rewritten by the
    /// switch itself — their staleness is enforced at decision time through
    /// the basis identity.
    #[tokio::test]
    async fn db_mode_switch_invalidates_pending_review_basis() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let svc = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        let (repo_id, _key) = create_age_gate_repo(&pool, RepositoryFormat::Npm, 7).await;

        let published = Utc::now() - Duration::days(1);
        let pending =
            insert_review_row(&pool, repo_id, "pkg", "1.0.0", "pending", Some(published)).await;
        let approved =
            insert_review_row(&pool, repo_id, "pkg", "0.9.0", "approved", Some(published)).await;

        svc.update_repo_config(repo_id, true, 7, AgeGateMode::FirstSeen)
            .await
            .expect("switch to first_seen");

        let pending_basis: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT upstream_published_at FROM age_gate_reviews WHERE id = $1")
                .bind(pending)
                .fetch_one(&pool)
                .await
                .expect("pending row");
        assert!(
            pending_basis.is_none(),
            "a publish-time basis must not survive a switch to first_seen: the \
             sweep would auto-approve on a clock the repository no longer runs"
        );

        let approved_basis: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT upstream_published_at FROM age_gate_reviews WHERE id = $1")
                .bind(approved)
                .fetch_one(&pool)
                .await
                .expect("approved row");
        assert!(approved_basis.is_some());

        // The mode is persisted and visible to the next request.
        let params = resolve_repo_params(&pool, repo_id)
            .await
            .expect("resolve after switch");
        assert_eq!(params.age_gate_mode, AgeGateMode::FirstSeen);

        // Re-applying the same mode is not a switch: it must not wipe a basis
        // that was just re-observed.
        sqlx::query("UPDATE age_gate_reviews SET upstream_published_at = $2 WHERE id = $1")
            .bind(pending)
            .bind(published)
            .execute(&pool)
            .await
            .expect("restore basis");
        svc.update_repo_config(repo_id, true, 14, AgeGateMode::FirstSeen)
            .await
            .expect("threshold-only change");
        let untouched: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT upstream_published_at FROM age_gate_reviews WHERE id = $1")
                .bind(pending)
                .fetch_one(&pool)
                .await
                .expect("pending row");
        assert!(untouched.is_some());
    }

    /// F2: an automatic approval is bookkeeping, not authority. Switching the
    /// age source must not let a publish-time auto-approval keep allowing the
    /// version under `first_seen`; the row is voided back to pending under
    /// the new identity and the version blocks until its new clock ages.
    #[tokio::test]
    async fn db_auto_approval_does_not_bypass_mode_switch() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let svc = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        let (repo_id, repo_key) = create_age_gate_repo(&pool, RepositoryFormat::Npm, 7).await;
        let fingerprint = upstream_fingerprint(Some(TEST_UPSTREAM));

        // Publish-time auto-approval: aged basis, correct identity for the
        // OLD policy.
        let review_id = insert_review_row_with_identity(
            &pool,
            repo_id,
            "pkg",
            "1.0.0",
            "approved",
            Some(Utc::now() - Duration::days(30)),
            None,
            Some("upstream_publish_time"),
            Some(&fingerprint),
        )
        .await;

        svc.update_repo_config(repo_id, true, 7, AgeGateMode::FirstSeen)
            .await
            .expect("switch to first_seen");
        let params = params_with_mode(
            repo_id,
            repo_key,
            RepositoryFormat::Npm,
            7,
            AgeGateMode::FirstSeen,
        );

        // Under first_seen the basis is a fresh observation: below threshold.
        let basis = svc
            .observe_first_seen(&params, "pkg", "1.0.0")
            .await
            .expect("observe under new mode");
        assert!(matches!(
            svc.check(&params, "pkg", "1.0.0", basis)
                .await
                .expect("check under new mode"),
            AgeGateDecision::Block { .. }
        ));

        let (status, basis_mode): (String, Option<String>) =
            sqlx::query_as("SELECT status, basis_mode FROM age_gate_reviews WHERE id = $1")
                .bind(review_id)
                .fetch_one(&pool)
                .await
                .expect("review row");
        assert_eq!(status, "pending", "stale automatic approval is voided");
        assert_eq!(basis_mode.as_deref(), Some("first_seen"));
    }

    /// F2: repointing the upstream voids recorded approvals — manual and
    /// automatic alike — because they answered a question about a different
    /// registry. Rejections deliberately stay coordinate-wide.
    #[tokio::test]
    async fn db_repointing_upstream_voids_approvals_but_not_rejections() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let svc = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        let (repo_id, repo_key) = create_age_gate_repo(&pool, RepositoryFormat::Npm, 7).await;
        let reviewer = create_reviewer(&pool).await;
        let old_fingerprint = upstream_fingerprint(Some(TEST_UPSTREAM));
        let young = Utc::now() - Duration::days(1);

        let manual = insert_review_row_with_identity(
            &pool,
            repo_id,
            "pkg",
            "1.0.0",
            "approved",
            Some(young),
            Some(reviewer),
            Some("upstream_publish_time"),
            Some(&old_fingerprint),
        )
        .await;
        insert_review_row_with_identity(
            &pool,
            repo_id,
            "pkg",
            "2.0.0",
            "rejected",
            Some(young),
            Some(reviewer),
            Some("upstream_publish_time"),
            Some(&old_fingerprint),
        )
        .await;

        // Sanity: under the original upstream the manual approval allows.
        let params = npm_params(repo_id, repo_key.clone(), 7);
        assert!(matches!(
            svc.check(&params, "pkg", "1.0.0", Some(young))
                .await
                .unwrap(),
            AgeGateDecision::Allow
        ));

        // Repoint: same coordinates, different registry.
        let mut repointed = npm_params(repo_id, repo_key, 7);
        repointed.upstream_url = Some("https://registry-b.example.test".to_string());
        assert!(matches!(
            svc.check(&repointed, "pkg", "1.0.0", Some(young))
                .await
                .unwrap(),
            AgeGateDecision::Block { .. }
        ));
        let status: String =
            sqlx::query_scalar("SELECT status FROM age_gate_reviews WHERE id = $1")
                .bind(manual)
                .fetch_one(&pool)
                .await
                .expect("manual row");
        assert_eq!(
            status, "pending",
            "stale manual approval re-enters the queue"
        );

        // The rejection still blocks under the new upstream.
        assert!(matches!(
            svc.check(&repointed, "pkg", "2.0.0", Some(young))
                .await
                .unwrap(),
            AgeGateDecision::Block { .. }
        ));
    }

    /// F2: raising the threshold restrains versions carrying an earlier
    /// automatic approval — eligibility is recomputed against the current
    /// threshold, never read off the row's status.
    #[tokio::test]
    async fn db_raising_threshold_restrains_automatic_approvals() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let svc = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        let (repo_id, repo_key) = create_age_gate_repo(&pool, RepositoryFormat::Npm, 7).await;
        let fingerprint = upstream_fingerprint(Some(TEST_UPSTREAM));
        let basis = Utc::now() - Duration::days(10);

        insert_review_row_with_identity(
            &pool,
            repo_id,
            "pkg",
            "1.0.0",
            "approved",
            Some(basis),
            None,
            Some("upstream_publish_time"),
            Some(&fingerprint),
        )
        .await;

        // 10 days old, threshold 7: allowed (recomputed, identity matches).
        let params = npm_params(repo_id, repo_key.clone(), 7);
        assert!(matches!(
            svc.check(&params, "pkg", "1.0.0", Some(basis))
                .await
                .unwrap(),
            AgeGateDecision::Allow
        ));

        // Threshold raised to 30: the same auto-approved row must block.
        svc.update_repo_config(repo_id, true, 30, AgeGateMode::UpstreamPublishTime)
            .await
            .expect("raise threshold");
        let params = npm_params(repo_id, repo_key, 30);
        assert!(matches!(
            svc.check(&params, "pkg", "1.0.0", Some(basis))
                .await
                .unwrap(),
            AgeGateDecision::Block { .. }
        ));
    }

    /// F2: the background sweep honors only a basis recorded under the
    /// repository's CURRENT policy identity. Stale rows and in-flight writes
    /// carrying the old identity are never swept; pre-identity legacy rows
    /// are swept only while the repository still runs publish-time mode.
    #[tokio::test]
    async fn db_sweep_requires_current_identity() {
        let Some(pool) = try_db_pool().await else {
            return;
        };
        let svc = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        let (repo_id, _key) = create_age_gate_repo(&pool, RepositoryFormat::Npm, 7).await;
        let current = upstream_fingerprint(Some(TEST_UPSTREAM));
        let aged = Some(Utc::now() - Duration::days(30));

        let current_identity = insert_review_row_with_identity(
            &pool,
            repo_id,
            "pkg",
            "1.0.0",
            "pending",
            aged,
            None,
            Some("upstream_publish_time"),
            Some(&current),
        )
        .await;
        let stale_identity = insert_review_row_with_identity(
            &pool,
            repo_id,
            "pkg",
            "2.0.0",
            "pending",
            aged,
            None,
            Some("upstream_publish_time"),
            Some("stale-fingerprint"),
        )
        .await;
        let stale_mode = insert_review_row_with_identity(
            &pool,
            repo_id,
            "pkg",
            "3.0.0",
            "pending",
            aged,
            None,
            Some("first_seen"),
            Some(&current),
        )
        .await;
        let legacy = insert_review_row_with_identity(
            &pool, repo_id, "pkg", "4.0.0", "pending", aged, None, None, None,
        )
        .await;

        svc.auto_approve_aged_reviews().await.expect("sweep");

        let status = |id: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, String>("SELECT status FROM age_gate_reviews WHERE id = $1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .expect("row status")
            }
        };
        assert_eq!(status(current_identity).await, "approved");
        assert_eq!(
            status(stale_identity).await,
            "pending",
            "a basis recorded against a different upstream is never swept"
        );
        assert_eq!(
            status(stale_mode).await,
            "pending",
            "a basis recorded under a different mode is never swept"
        );
        assert_eq!(
            status(legacy).await,
            "approved",
            "legacy pre-identity rows keep sweeping while the repo runs publish-time"
        );

        // Under first_seen the legacy arm closes too: a fresh legacy-shaped
        // row (as an in-flight pre-upgrade write would leave) is not swept.
        let svc2 = AgeGateService::new(pool.clone(), Arc::new(EventBus::new(16)));
        svc2.update_repo_config(repo_id, true, 7, AgeGateMode::FirstSeen)
            .await
            .expect("switch to first_seen");
        let legacy_after_switch = insert_review_row_with_identity(
            &pool, repo_id, "pkg", "5.0.0", "pending", aged, None, None, None,
        )
        .await;
        svc2.auto_approve_aged_reviews().await.expect("sweep 2");
        assert_eq!(
            status(legacy_after_switch).await,
            "pending",
            "legacy rows are not swept under first_seen"
        );
    }
}
