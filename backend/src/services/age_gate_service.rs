//! Age-based quality gate for remote NPM and PyPI proxy registries.

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

        if let Some(ref review) = existing {
            if review.status == AgeGateReviewStatus::Rejected.as_str() {
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
        }

        if Self::meets_age_threshold(published_at, repo.age_gate_min_age_days, now) {
            if let Some(ref review) = existing {
                if review.status == AgeGateReviewStatus::Pending.as_str() {
                    self.auto_approve(review.id, repo.id).await?;
                }
            }
            return Ok(AgeGateDecision::Allow);
        }

        if let Some(ref review) = existing {
            if review.status == AgeGateReviewStatus::Approved.as_str() {
                return Ok(AgeGateDecision::Allow);
            }
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
        let version_keys: Vec<String> = packument
            .get("versions")
            .and_then(|v| v.as_object())
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();

        if version_keys.is_empty() {
            return Ok(());
        }

        let versions: Vec<(String, Option<DateTime<Utc>>)> = version_keys
            .iter()
            .map(|v| (v.clone(), publish_times.get(v).copied()))
            .collect();

        let blocked = self
            .evaluate_versions_batch(repo, package_name, &versions)
            .await?;

        if !blocked.is_empty() {
            metrics_service::record_age_gate_filtered_metadata(
                &repo.key,
                format_label(&repo.format),
            );
        }

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

        // Reconcile dist-tags so none point at a version we just removed. A dangling
        // tag (e.g. `latest`, `beta`, `next`) makes npm resolve the tag to a manifest
        // that is absent from `versions`, breaking `npm install <pkg>` and
        // `npm install <pkg>@<tag>`. When every version is blocked this empties
        // dist-tags, yielding a consistent "no acceptable version" packument instead
        // of a `latest` that points at nothing.
        allowed.sort_by(|a, b| version_compare_desc(a, b));
        reconcile_dist_tags(packument, &allowed);

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

        // First pass: locate anchors and the distinct versions they reference, so the
        // age gate is evaluated in a single batch rather than once per file link.
        let mut spans: Vec<(usize, usize, Option<String>)> = Vec::new();
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
                    versions.push((ver.clone(), publish_times.get(ver).copied()));
                }
            }
            spans.push((start, end, version));
            cursor = end;
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

        // Second pass: rebuild the document, dropping links for blocked versions.
        let mut out = String::with_capacity(html.len());
        let mut cursor = 0usize;
        for (start, end, version) in spans {
            out.push_str(&html[cursor..start]);
            let keep = match version {
                None => true,
                Some(ref ver) => !blocked.contains(ver),
            };
            if keep {
                out.push_str(&html[start..end]);
            }
            cursor = end;
        }
        out.push_str(&html[cursor..]);
        Ok(out)
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
        let mut blocked = std::collections::HashSet::new();
        if !Self::is_applicable(repo) || versions.is_empty() {
            return Ok(blocked);
        }

        let now = Utc::now();
        let existing = self.get_reviews_for_package(repo.id, package_name).await?;

        let mut request_versions: Vec<String> = Vec::new();
        let mut request_times: Vec<Option<DateTime<Utc>>> = Vec::new();

        for (version, published_at) in versions {
            let existing_review = existing.get(version);

            // A rejected version stays blocked regardless of age.
            if let Some((_, status)) = existing_review {
                if status == AgeGateReviewStatus::Rejected.as_str() {
                    blocked.insert(version.clone());
                    continue;
                }
            }

            // Crossed the threshold: serve it. The pending→approved flip is left
            // to the background sweep so this read path performs no UPDATE.
            if Self::meets_age_threshold(*published_at, repo.age_gate_min_age_days, now) {
                continue;
            }

            // Already approved versions are served even while young.
            if let Some((_, status)) = existing_review {
                if status == AgeGateReviewStatus::Approved.as_str() {
                    continue;
                }
            }

            blocked.insert(version.clone());
            request_versions.push(version.clone());
            request_times.push(*published_at);
        }

        if !request_versions.is_empty() {
            self.request_reviews_batch(repo.id, package_name, &request_versions, &request_times)
                .await?;
        }

        Ok(blocked)
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
        if review.status != AgeGateReviewStatus::Pending.as_str() {
            return Err(AppError::Validation(format!(
                "Review is already {}",
                review.status
            )));
        }

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
        if review.status != AgeGateReviewStatus::Pending.as_str() {
            return Err(AppError::Validation(format!(
                "Review is already {}",
                review.status
            )));
        }

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
        if !(1..=3650).contains(&min_age_days) {
            return Err(AppError::Validation(
                "min_age_days must be between 1 and 3650".to_string(),
            ));
        }

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

        let best = rows.into_iter().max_by(|a, b| {
            version_compare_desc(
                a.version.as_deref().unwrap_or(""),
                b.version.as_deref().unwrap_or(""),
            )
        });

        Ok(best.and_then(|row| {
            Some(LastKnownGood {
                version: row.version?,
                artifact_path: row.path,
            })
        }))
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
}

fn extract_href_filename(anchor: &str) -> Option<String> {
    let href_start = anchor.find("href=\"")? + 6;
    let rest = &anchor[href_start..];
    let href_end = rest.find('"')?;
    let href = &rest[..href_end];
    href.rsplit('/').next().map(|s| s.to_string())
}

fn version_compare_desc(a: &str, b: &str) -> std::cmp::Ordering {
    match version_compare(a, b).cmp(&0) {
        std::cmp::Ordering::Equal => std::cmp::Ordering::Equal,
        std::cmp::Ordering::Less => std::cmp::Ordering::Greater,
        std::cmp::Ordering::Greater => std::cmp::Ordering::Less,
    }
}

fn version_compare(a: &str, b: &str) -> i32 {
    let seg_a: Vec<&str> = a.split(['.', '-']).collect();
    let seg_b: Vec<&str> = b.split(['.', '-']).collect();

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

    #[test]
    fn version_compare_orders_semverish() {
        assert!(version_compare("2.0.0", "1.0.0") > 0);
        assert!(version_compare("1.0.0", "2.0.0") < 0);
        assert_eq!(version_compare("1.0.0", "1.0.0"), 0);
    }

    #[test]
    fn extract_href_filename_parses_anchor() {
        let html = r#"<a href="/packages/requests/2.31.0/requests-2.31.0.tar.gz">link</a>"#;
        assert_eq!(
            extract_href_filename(html),
            Some("requests-2.31.0.tar.gz".to_string())
        );
    }
}
