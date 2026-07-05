//! Age-based quality gate for remote NPM and PyPI proxy registries.
//!
//! # v1 scope limitation
//!
//! The gate applies **only to direct Remote repositories** (npm and PyPI).
//! Virtual repositories whose members include Remote repositories are not
//! age-gated on the download path — only the Direct Remote branch is checked.
//! Consumers fetching through a Virtual repo receive unfiltered pass-through.
//! This is intentional for v1 and should be addressed before extending the
//! gate to other repository types.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
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
}

impl AgeGateRepoParams {
    pub fn from_parts(
        id: Uuid,
        key: impl Into<String>,
        repo_type: RepositoryType,
        format: RepositoryFormat,
        age_gate_enabled: bool,
        age_gate_min_age_days: i32,
    ) -> Self {
        Self {
            id,
            key: key.into(),
            repo_type,
            format,
            age_gate_enabled,
            age_gate_min_age_days,
        }
    }

    pub fn from_repository(repo: &crate::models::repository::Repository) -> Self {
        Self::from_parts(
            repo.id,
            repo.key.clone(),
            repo.repo_type.clone(),
            repo.format.clone(),
            repo.age_gate_enabled,
            repo.age_gate_min_age_days,
        )
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

/// Side-effect-free outcome of evaluating a single-version age gate check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgeGateCheckAction {
    Allow,
    BlockRejected,
    AllowAndAutoApprovePending,
    AllowAlreadyApproved,
    BlockAndRequestReview,
}

/// Pure state machine for [`AgeGateService::check`]: maps existing review status
/// and whether the version meets the age threshold to the action the impure
/// wrapper should take (DB writes, metrics, LKG lookup).
pub(crate) fn decide_age_gate_check(
    existing_status: Option<&str>,
    meets_threshold: bool,
) -> AgeGateCheckAction {
    if existing_status == Some(AgeGateReviewStatus::Rejected.as_str()) {
        return AgeGateCheckAction::BlockRejected;
    }
    if meets_threshold {
        if existing_status == Some(AgeGateReviewStatus::Pending.as_str()) {
            return AgeGateCheckAction::AllowAndAutoApprovePending;
        }
        return AgeGateCheckAction::Allow;
    }
    if existing_status == Some(AgeGateReviewStatus::Approved.as_str()) {
        return AgeGateCheckAction::AllowAlreadyApproved;
    }
    AgeGateCheckAction::BlockAndRequestReview
}

/// Per-version classification output for metadata listing (npm packument / PyPI simple index).
#[derive(Debug, Clone, Default)]
pub(crate) struct MetadataListingClassification {
    pub blocked: std::collections::HashSet<String>,
    pub request_versions: Vec<String>,
    pub request_times: Vec<Option<DateTime<Utc>>>,
}

/// Classify every version in a metadata document without I/O. Used by
/// [`AgeGateService::evaluate_versions_batch`].
pub(crate) fn classify_versions_for_metadata_listing(
    versions: &[(String, Option<DateTime<Utc>>)],
    existing_reviews: &std::collections::HashMap<String, (Uuid, String)>,
    min_age_days: i32,
    now: DateTime<Utc>,
) -> MetadataListingClassification {
    let mut out = MetadataListingClassification::default();
    for (version, published_at) in versions {
        let existing_review = existing_reviews.get(version);

        if let Some((_, status)) = existing_review {
            if status == AgeGateReviewStatus::Rejected.as_str() {
                out.blocked.insert(version.clone());
                continue;
            }
        }

        if AgeGateService::meets_age_threshold(*published_at, min_age_days, now) {
            continue;
        }

        if let Some((_, status)) = existing_review {
            if status == AgeGateReviewStatus::Approved.as_str() {
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

/// Reject approve/reject on a review that is no longer pending.
pub(crate) fn require_pending_review(status: &str) -> Result<()> {
    if status != AgeGateReviewStatus::Pending.as_str() {
        return Err(AppError::Validation(format!(
            "Review is already {}",
            status
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

    /// Whether the age gate applies to this repository.
    pub fn is_applicable(repo: &AgeGateRepoParams) -> bool {
        repo.repo_type == RepositoryType::Remote
            && repo.age_gate_enabled
            && matches!(repo.format, RepositoryFormat::Npm | RepositoryFormat::Pypi)
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
    pub async fn check(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        version: &str,
        published_at: Option<DateTime<Utc>>,
    ) -> Result<AgeGateDecision> {
        if !Self::is_applicable(repo) {
            return Ok(AgeGateDecision::Allow);
        }

        let now = Utc::now();
        let existing = self.get_review(repo.id, package_name, version).await?;
        let existing_status = existing.as_ref().map(|r| r.status.as_str());
        let meets_threshold =
            Self::meets_age_threshold(published_at, repo.age_gate_min_age_days, now);

        match decide_age_gate_check(existing_status, meets_threshold) {
            AgeGateCheckAction::Allow => return Ok(AgeGateDecision::Allow),
            AgeGateCheckAction::BlockRejected => {
                let review = existing.as_ref().expect("rejected implies existing review");
                let lkg = self
                    .find_last_known_good(repo.id, package_name, version)
                    .await?;
                metrics_service::record_age_gate_blocked_request(
                    &repo.key,
                    format_label(&repo.format),
                );
                return Ok(AgeGateDecision::Block {
                    review_id: review.id,
                    last_known_good: lkg,
                });
            }
            AgeGateCheckAction::AllowAndAutoApprovePending => {
                let review = existing.as_ref().expect("pending implies existing review");
                self.auto_approve(review.id, repo.id).await?;
                return Ok(AgeGateDecision::Allow);
            }
            AgeGateCheckAction::AllowAlreadyApproved => return Ok(AgeGateDecision::Allow),
            AgeGateCheckAction::BlockAndRequestReview => {}
        }

        let review_id = self
            .request_review(
                repo.id,
                package_name,
                version,
                published_at,
                existing.is_none(),
            )
            .await?;
        let lkg = self
            .find_last_known_good(repo.id, package_name, version)
            .await?;
        metrics_service::record_age_gate_blocked_request(&repo.key, format_label(&repo.format));
        Ok(AgeGateDecision::Block {
            review_id,
            last_known_good: lkg,
        })
    }

    /// Filter npm packument JSON, removing versions blocked by the age gate.
    pub async fn filter_npm_packument(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        packument: &mut serde_json::Value,
    ) -> Result<()> {
        if !Self::is_applicable(repo) {
            return Ok(());
        }

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
        if !Self::is_applicable(repo) {
            return Ok(html.to_string());
        }

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
        if !Self::is_applicable(repo) {
            return Ok(());
        }

        let mut versions = collect_pypi_simple_json_versions(index);
        if versions.is_empty() {
            return Ok(());
        }

        if versions.iter().any(|(_, ts)| ts.is_none()) {
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
    async fn evaluate_versions_batch(
        &self,
        repo: &AgeGateRepoParams,
        package_name: &str,
        versions: &[(String, Option<DateTime<Utc>>)],
    ) -> Result<std::collections::HashSet<String>> {
        let blocked = std::collections::HashSet::new();
        if !Self::is_applicable(repo) || versions.is_empty() {
            return Ok(blocked);
        }

        let now = Utc::now();
        let existing = self.get_reviews_for_package(repo.id, package_name).await?;

        let classification = classify_versions_for_metadata_listing(
            versions,
            &existing,
            repo.age_gate_min_age_days,
            now,
        );

        if !classification.request_versions.is_empty() {
            self.request_reviews_batch(
                repo.id,
                package_name,
                &classification.request_versions,
                &classification.request_times,
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

        let rows = sqlx::query_as!(
            AgeGateReview,
            r#"
            SELECT
                r.id, r.repository_id, r.package_name, r.package_version,
                r.upstream_published_at, r.status, r.requested_at,
                r.reviewed_by, r.reviewed_at, r.review_reason,
                r.request_count, r.last_requested_at,
                repo.key as repository_key
            FROM age_gate_reviews r
            INNER JOIN repositories repo ON repo.id = r.repository_id
            WHERE ($1::text IS NULL OR repo.key = $1)
              AND ($2::text[] IS NULL OR r.status = ANY($2))
            ORDER BY r.last_requested_at DESC
            OFFSET $3 LIMIT $4
            "#,
            repository_key,
            statuses,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((rows, total))
    }

    pub async fn get_review_by_id(&self, id: Uuid) -> Result<AgeGateReview> {
        sqlx::query_as!(
            AgeGateReview,
            r#"
            SELECT
                r.id, r.repository_id, r.package_name, r.package_version,
                r.upstream_published_at, r.status, r.requested_at,
                r.reviewed_by, r.reviewed_at, r.review_reason,
                r.request_count, r.last_requested_at,
                repo.key as repository_key
            FROM age_gate_reviews r
            INNER JOIN repositories repo ON repo.id = r.repository_id
            WHERE r.id = $1
            "#,
            id
        )
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
        require_pending_review(&review.status)?;

        sqlx::query!(
            r#"
            UPDATE age_gate_reviews
            SET status = 'approved', reviewed_by = $2, reviewed_at = NOW(),
                review_reason = $3
            WHERE id = $1
            "#,
            id,
            reviewer_id,
            reason
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

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
        require_pending_review(&review.status)?;

        sqlx::query!(
            r#"
            UPDATE age_gate_reviews
            SET status = 'rejected', reviewed_by = $2, reviewed_at = NOW(),
                review_reason = $3
            WHERE id = $1
            "#,
            id,
            reviewer_id,
            reason
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        self.event_bus.emit_for_repo(
            "age_gate.rejected",
            id,
            review.repository_id,
            Some(reviewer_id.to_string()),
        );

        self.get_review_by_id(id).await
    }

    pub async fn update_repo_config(
        &self,
        repo_id: Uuid,
        enabled: bool,
        min_age_days: i32,
    ) -> Result<()> {
        validate_min_age_days(min_age_days)?;

        sqlx::query!(
            r#"
            UPDATE repositories
            SET age_gate_enabled = $2, age_gate_min_age_days = $3, updated_at = NOW()
            WHERE id = $1
            "#,
            repo_id,
            enabled,
            min_age_days
        )
        .execute(&self.db)
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
        sqlx::query_as!(
            AgeGateReview,
            r#"
            SELECT
                id, repository_id, package_name, package_version,
                upstream_published_at, status, requested_at,
                reviewed_by, reviewed_at, review_reason,
                request_count, last_requested_at,
                NULL::text as repository_key
            FROM age_gate_reviews
            WHERE repository_id = $1 AND package_name = $2 AND package_version = $3
            "#,
            repository_id,
            package_name,
            version
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    async fn request_review(
        &self,
        repository_id: Uuid,
        package_name: &str,
        version: &str,
        published_at: Option<DateTime<Utc>>,
        is_new: bool,
    ) -> Result<Uuid> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO age_gate_reviews (
                repository_id, package_name, package_version,
                upstream_published_at, status
            )
            VALUES ($1, $2, $3, $4, 'pending')
            ON CONFLICT (repository_id, package_name, package_version)
            DO UPDATE SET
                request_count = age_gate_reviews.request_count + 1,
                last_requested_at = NOW(),
                upstream_published_at = COALESCE(EXCLUDED.upstream_published_at, age_gate_reviews.upstream_published_at)
            RETURNING id
            "#,
            repository_id,
            package_name,
            version,
            published_at
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if is_new {
            self.event_bus
                .emit_for_repo("age_gate.queued", id, repository_id, None);
        }

        Ok(id)
    }

    async fn auto_approve(&self, review_id: Uuid, repository_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE age_gate_reviews
            SET status = 'approved', reviewed_by = NULL, reviewed_at = NOW(),
                review_reason = $2
            WHERE id = $1 AND status = 'pending'
            "#,
            review_id,
            AUTO_APPROVE_REASON
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        self.event_bus
            .emit_for_repo("age_gate.approved", review_id, repository_id, None);
        Ok(())
    }

    /// Load all existing reviews for a package keyed by version, so a batch
    /// evaluation can classify every version with a single read.
    async fn get_reviews_for_package(
        &self,
        repository_id: Uuid,
        package_name: &str,
    ) -> Result<std::collections::HashMap<String, (Uuid, String)>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, package_version, status
            FROM age_gate_reviews
            WHERE repository_id = $1 AND package_name = $2
            "#,
            repository_id,
            package_name
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| (r.package_version, (r.id, r.status)))
            .collect())
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
    async fn request_reviews_batch(
        &self,
        repository_id: Uuid,
        package_name: &str,
        versions: &[String],
        published_ats: &[Option<DateTime<Utc>>],
    ) -> Result<()> {
        let stale_before = Utc::now() - chrono::Duration::seconds(REQUEST_COUNT_DEBOUNCE_SECS);
        let rows = sqlx::query!(
            r#"
            INSERT INTO age_gate_reviews (
                repository_id, package_name, package_version,
                upstream_published_at, status
            )
            SELECT $1, $2, v, p, 'pending'
            FROM UNNEST($3::text[], $4::timestamptz[]) AS t(v, p)
            ON CONFLICT (repository_id, package_name, package_version)
            DO UPDATE SET
                request_count = age_gate_reviews.request_count + 1,
                last_requested_at = NOW(),
                upstream_published_at = COALESCE(EXCLUDED.upstream_published_at, age_gate_reviews.upstream_published_at)
            WHERE age_gate_reviews.last_requested_at < $5
            RETURNING id AS "id!", (request_count = 1) AS "is_new!"
            "#,
            repository_id,
            package_name,
            versions,
            published_ats as &[Option<DateTime<Utc>>],
            stale_before
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        for row in rows {
            if row.is_new {
                self.event_bus
                    .emit_for_repo("age_gate.queued", row.id, repository_id, None);
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
    pub async fn auto_approve_aged_reviews(&self) -> Result<u64> {
        let rows = sqlx::query!(
            r#"
            UPDATE age_gate_reviews r
            SET status = 'approved', reviewed_by = NULL, reviewed_at = NOW(),
                review_reason = $1
            FROM repositories repo
            WHERE r.repository_id = repo.id
              AND r.status = 'pending'
              AND repo.age_gate_enabled = true
              AND r.upstream_published_at IS NOT NULL
              AND NOW() - r.upstream_published_at >= make_interval(days => repo.age_gate_min_age_days)
            RETURNING r.id AS "id!", r.repository_id AS "repository_id!"
            "#,
            AUTO_APPROVE_REASON
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let approved = rows.len() as u64;
        for row in rows {
            self.event_bus
                .emit_for_repo("age_gate.approved", row.id, row.repository_id, None);
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
    use crate::models::repository::ReplicationPriority;
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

    fn test_repo(
        format: RepositoryFormat,
        repo_type: RepositoryType,
    ) -> crate::models::repository::Repository {
        let now = Utc::now();
        crate::models::repository::Repository {
            id: Uuid::new_v4(),
            key: "age-gate-test".to_string(),
            name: "Age Gate Test".to_string(),
            description: Some("unit test repository".to_string()),
            format,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/age-gate-test".to_string(),
            upstream_url: Some("https://example.invalid".to_string()),
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: true,
            age_gate_min_age_days: 14,
            created_at: now,
            updated_at: now,
        }
    }

    async fn create_age_gate_repo(
        pool: &sqlx::PgPool,
        format: RepositoryFormat,
        min_age_days: i32,
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
                age_gate_enabled, age_gate_min_age_days
             )
             VALUES ($1, $2, $2, $3, 'remote', $4::repository_format, $5, true, $6)",
        )
        .bind(id)
        .bind(&key)
        .bind(format!("/tmp/age-gate-lib/{id}"))
        .bind(format_sql)
        .bind("https://upstream.example.test")
        .bind(min_age_days)
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

    fn npm_params(id: Uuid, key: String, min_age_days: i32) -> AgeGateRepoParams {
        AgeGateRepoParams::from_parts(
            id,
            key,
            RepositoryType::Remote,
            RepositoryFormat::Npm,
            true,
            min_age_days,
        )
    }

    fn pypi_params(id: Uuid, key: String, min_age_days: i32) -> AgeGateRepoParams {
        AgeGateRepoParams::from_parts(
            id,
            key,
            RepositoryType::Remote,
            RepositoryFormat::Pypi,
            true,
            min_age_days,
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

    #[test]
    fn repo_params_from_repository_copies_age_gate_fields() {
        let repo = test_repo(RepositoryFormat::Pypi, RepositoryType::Remote);
        let params = AgeGateRepoParams::from_repository(&repo);
        assert_eq!(params.id, repo.id);
        assert_eq!(params.key, repo.key);
        assert_eq!(params.repo_type, RepositoryType::Remote);
        assert_eq!(params.format, RepositoryFormat::Pypi);
        assert!(params.age_gate_enabled);
        assert_eq!(params.age_gate_min_age_days, 14);
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
        );
        let cargo = AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "cargo-remote",
            RepositoryType::Remote,
            RepositoryFormat::Cargo,
            true,
            7,
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

        let html = "<a href=\"pkg-1.0.0.tar.gz\">pkg-1.0.0.tar.gz</a>";
        let unchanged = svc
            .filter_pypi_simple_index(&cargo, "pkg", &std::collections::HashMap::new(), html)
            .await
            .unwrap();
        assert_eq!(unchanged, html);
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

        svc.update_repo_config(repo_id, false, 14)
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
        let approved = svc
            .auto_approve_aged_reviews()
            .await
            .expect("sweep aged reviews");
        assert!(approved >= 1);
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

    #[test]
    fn decide_age_gate_check_truth_table() {
        assert_eq!(
            decide_age_gate_check(Some("rejected"), false),
            AgeGateCheckAction::BlockRejected
        );
        assert_eq!(
            decide_age_gate_check(Some("rejected"), true),
            AgeGateCheckAction::BlockRejected
        );
        assert_eq!(
            decide_age_gate_check(Some("pending"), true),
            AgeGateCheckAction::AllowAndAutoApprovePending
        );
        assert_eq!(decide_age_gate_check(None, true), AgeGateCheckAction::Allow);
        assert_eq!(
            decide_age_gate_check(Some("approved"), false),
            AgeGateCheckAction::AllowAlreadyApproved
        );
        assert_eq!(
            decide_age_gate_check(None, false),
            AgeGateCheckAction::BlockAndRequestReview
        );
        assert_eq!(
            decide_age_gate_check(Some("pending"), false),
            AgeGateCheckAction::BlockAndRequestReview
        );
    }

    #[test]
    fn classify_versions_for_metadata_listing_classifies_correctly() {
        let now = Utc.with_ymd_and_hms(2024, 7, 1, 0, 0, 0).unwrap();
        let young = now - Duration::days(1);
        let old = now - Duration::days(30);
        let mut existing = std::collections::HashMap::new();
        existing.insert(
            "1.0.0".to_string(),
            (Uuid::new_v4(), "rejected".to_string()),
        );
        existing.insert(
            "2.0.0".to_string(),
            (Uuid::new_v4(), "approved".to_string()),
        );

        let versions = vec![
            ("1.0.0".to_string(), Some(young)),
            ("2.0.0".to_string(), Some(young)),
            ("3.0.0".to_string(), Some(old)),
            ("4.0.0".to_string(), Some(young)),
        ];
        let out = classify_versions_for_metadata_listing(&versions, &existing, 7, now);
        assert!(out.blocked.contains("1.0.0"));
        assert!(!out.blocked.contains("2.0.0"));
        assert!(!out.blocked.contains("3.0.0"));
        assert!(out.blocked.contains("4.0.0"));
        assert_eq!(out.request_versions, vec!["4.0.0".to_string()]);
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
    fn require_pending_review_rejects_non_pending() {
        assert!(require_pending_review("pending").is_ok());
        assert!(require_pending_review("approved").is_err());
        assert!(require_pending_review("rejected").is_err());
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
        );
        assert!(AgeGateService::is_applicable(&npm_remote));

        let disabled = AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "npm-off",
            RepositoryType::Remote,
            RepositoryFormat::Npm,
            false,
            7,
        );
        assert!(!AgeGateService::is_applicable(&disabled));

        let local = AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "local",
            RepositoryType::Local,
            RepositoryFormat::Npm,
            true,
            7,
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
}
