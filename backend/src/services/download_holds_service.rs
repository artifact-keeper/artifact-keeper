//! Admin observability for packages that currently cannot be downloaded.
//!
//! Two independent control planes refuse bytes for different reasons:
//!
//! * **Age gate** — too-new upstream versions (`age_gate_reviews`, HTTP 451).
//! * **Quarantine** — timed upload/age holds and admin blocks (`artifacts`
//!   status, plus proxy-cache `quarantine_until` / `quarantine_released_at`).
//!
//! A scan-policy hold is stored as a quarantine stamp
//! (`quarantine_status = 'quarantined'`), so it appears in the quarantine
//! queue as `source: hosted, kind: active`. Since #4510 the hold also records
//! its origin in `artifacts.quarantine_source` (`upload`, `admin`,
//! `scan_policy`; NULL for a hold written before migration 299, by a 1.11
//! replica, or by a scanner before #5153 recorded its own), which the queue
//! reports as `hold_source` and can filter on. What a scan policy refuses
//! right now, held or not, is the separate policy-blocks queue
//! ([`DownloadHoldsService::list_policy_blocks`]), derived from the gate's
//! own decision rather than from the stored stamp.
//!
//! Proxy-cache rows mirror the hold recorded in the cache sidecar, which is
//! the read path's authority; the catalog columns are a best-effort mirror of
//! it (an entry cached before migration 236 is not listed until it is
//! re-fetched).

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::{AppError, Result};

/// How a quarantine row currently behaves at the download gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldKind {
    /// Still held: hosted `quarantined` with a future/NULL until, or a
    /// proxy-cache row whose `quarantine_until` has not lapsed and has not
    /// been released.
    Active,
    /// Still labelled held, but `quarantine_until` has lapsed — downloads work.
    Expired,
    /// Terminal admin/scan rejection on a hosted artifact — downloads stay 403.
    Rejected,
}

/// Classify a stored quarantine row the same way
/// [`crate::services::quarantine_service::check_download_allowed`] does, plus
/// the expired-but-still-labelled case the queue needs to show as "Expired".
pub fn classify_hold(
    status: &str,
    until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<HoldKind> {
    match status {
        "rejected" => Some(HoldKind::Rejected),
        "quarantined" => match until {
            Some(ts) if ts <= now => Some(HoldKind::Expired),
            _ => Some(HoldKind::Active),
        },
        _ => None,
    }
}

impl HoldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "expired" => Some(Self::Expired),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// Seconds until a timed hold lapses. `None` for permanent holds and for
/// rejected rows (they do not expire). Negative means already expired.
pub fn remaining_seconds(until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<i64> {
    until.map(|ts| ts.signed_duration_since(now).num_seconds())
}

/// Parse a comma-separated `kind` query into a de-duplicated, validated set.
/// Empty / omitted → the currently-blocking kinds (`active` + `rejected`).
pub fn parse_hold_kinds(raw: Option<&str>) -> Result<Vec<HoldKind>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(vec![HoldKind::Active, HoldKind::Rejected]);
    };
    let mut kinds = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let kind = HoldKind::parse(token).ok_or_else(|| {
            AppError::Validation(format!(
                "Unknown hold kind '{token}'. Expected active, expired, or rejected."
            ))
        })?;
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    if kinds.is_empty() {
        return Ok(vec![HoldKind::Active, HoldKind::Rejected]);
    }
    Ok(kinds)
}

#[derive(Debug, Clone, FromRow)]
pub struct QuarantineHoldRow {
    pub source: String,
    pub artifact_id: Option<Uuid>,
    pub name: String,
    pub version: Option<String>,
    pub path: String,
    pub repository_key: String,
    pub repository_format: String,
    pub quarantine_status: String,
    pub quarantine_until: Option<DateTime<Utc>>,
    pub quarantine_reason: Option<String>,
    /// `artifacts.quarantine_source` (#4510); always NULL for proxy-cache rows.
    pub hold_source: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Parse the `hold_source` filter of the quarantine queue (#4510).
pub fn parse_hold_source(raw: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    crate::services::quarantine_service::HoldSource::parse(raw)
        .map(|s| Some(s.as_str().to_string()))
        .ok_or_else(|| {
            AppError::Validation(format!(
                "Unknown hold source '{raw}'. Expected upload, admin, or scan_policy."
            ))
        })
}

#[derive(Debug, Clone, Default)]
pub struct HoldsSummary {
    pub age_gate_pending: i64,
    pub quarantine_active: i64,
    pub quarantine_rejected: i64,
}

pub struct DownloadHoldsService {
    db: PgPool,
}

/// Hosted artifacts + proxy-cache catalog rows that currently match `kind`.
/// `$1` repository key, `$2` want_active, `$3` want_expired, `$4` want_rejected,
/// `$5` hold source (#4510; a set filter excludes proxy-cache rows, which
/// record none).
///
/// `hold_id` is the row's own primary key in either table. It is not part of
/// the response; it only makes the listing order total, so OFFSET paging
/// neither repeats nor drops rows that tie on every other sort key.
const QUARANTINE_FROM_SQL: &str = r#"
SELECT
    a.id AS hold_id,
    'hosted'::text AS source,
    a.id AS artifact_id,
    a.name,
    a.version,
    a.path,
    repo.key AS repository_key,
    repo.format::text AS repository_format,
    a.quarantine_status,
    a.quarantine_until,
    a.quarantine_reason,
    a.quarantine_source AS hold_source,
    a.created_at
FROM artifacts a
INNER JOIN repositories repo ON repo.id = a.repository_id
WHERE a.is_deleted = false
  AND ($1::text IS NULL OR repo.key = $1)
  AND ($5::text IS NULL OR a.quarantine_source = $5)
  AND (
        ($2::bool AND a.quarantine_status = 'quarantined'
            AND (a.quarantine_until IS NULL OR a.quarantine_until > NOW()))
     OR ($3::bool AND a.quarantine_status = 'quarantined'
            AND a.quarantine_until IS NOT NULL AND a.quarantine_until <= NOW())
     OR ($4::bool AND a.quarantine_status = 'rejected')
  )
UNION ALL
SELECT
    pca.id AS hold_id,
    'proxy-cache'::text AS source,
    NULL::uuid AS artifact_id,
    COALESCE(NULLIF(regexp_replace(pca.path, '.*/', ''), ''), pca.path) AS name,
    NULL::text AS version,
    pca.path,
    repo.key AS repository_key,
    repo.format::text AS repository_format,
    'quarantined'::text AS quarantine_status,
    pca.quarantine_until,
    NULL::text AS quarantine_reason,
    NULL::text AS hold_source,
    pca.cached_at AS created_at
FROM proxy_cache_artifacts pca
INNER JOIN repositories repo ON repo.id = pca.repository_id
WHERE pca.quarantine_released_at IS NULL
  AND pca.quarantine_until IS NOT NULL
  AND ($1::text IS NULL OR repo.key = $1)
  AND $5::text IS NULL
  AND (
        ($2::bool AND pca.quarantine_until > NOW())
     OR ($3::bool AND pca.quarantine_until <= NOW())
  )
"#;

impl DownloadHoldsService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn summary(&self) -> Result<HoldsSummary> {
        let age_gate_pending = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM age_gate_reviews WHERE status = 'pending'",
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let quarantine_active = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT (
                (SELECT COUNT(*)::bigint FROM artifacts
                 WHERE is_deleted = false
                   AND quarantine_status = 'quarantined'
                   AND (quarantine_until IS NULL OR quarantine_until > NOW()))
              + (SELECT COUNT(*)::bigint FROM proxy_cache_artifacts
                 WHERE quarantine_released_at IS NULL
                   AND quarantine_until IS NOT NULL
                   AND quarantine_until > NOW())
            )
            "#,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let quarantine_rejected = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)::bigint FROM artifacts
            WHERE is_deleted = false
              AND quarantine_status = 'rejected'
            "#,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(HoldsSummary {
            age_gate_pending,
            quarantine_active,
            quarantine_rejected,
        })
    }

    pub async fn list_quarantine(
        &self,
        repository_key: Option<&str>,
        kinds: &[HoldKind],
        hold_source: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<QuarantineHoldRow>, i64)> {
        let want_active = kinds.contains(&HoldKind::Active);
        let want_expired = kinds.contains(&HoldKind::Expired);
        let want_rejected = kinds.contains(&HoldKind::Rejected);

        let total = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*)::bigint FROM ({QUARANTINE_FROM_SQL}) holds"
        )))
        .bind(repository_key)
        .bind(want_active)
        .bind(want_expired)
        .bind(want_rejected)
        .bind(hold_source)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // PostgreSQL only accepts bare output-column names in an ORDER BY
        // attached directly to a UNION, so the union is wrapped in a derived
        // table and ordered there. `hold_id` last makes the order total.
        let rows = sqlx::query_as::<_, QuarantineHoldRow>(sqlx::AssertSqlSafe(format!(
            "SELECT holds.* FROM ({QUARANTINE_FROM_SQL}) holds
             ORDER BY
                CASE holds.quarantine_status
                    WHEN 'quarantined' THEN 0
                    WHEN 'rejected' THEN 1
                    ELSE 2
                END,
                holds.quarantine_until ASC NULLS LAST,
                holds.created_at DESC,
                holds.hold_id
             OFFSET $6 LIMIT $7"
        )))
        .bind(repository_key)
        .bind(want_active)
        .bind(want_expired)
        .bind(want_rejected)
        .bind(hold_source)
        .bind(offset)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((rows, total))
    }
}

/// One item of the policy-blocks queue (#4510): content the download gate's
/// scan-policy decision refuses right now.
#[derive(Debug, Clone)]
pub struct PolicyBlock {
    /// `hosted` (an `artifacts` row, refused by a scan policy) or
    /// `proxy-cache` (a cached path whose stored `vulnerable` verdict the
    /// repository's proxy scan gate refuses).
    pub source: &'static str,
    pub artifact_id: Option<Uuid>,
    pub repository_key: String,
    pub repository_format: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub checksum_sha256: String,
    /// Hosted only: the stored quarantine stamp and where it came from.
    pub quarantine_status: Option<String>,
    pub hold_source: Option<String>,
    /// Hosted only: the violated policy rules, as the gate evaluated them.
    pub violations: Vec<String>,
    /// Proxy only: the verdict's highest severity and when it was scanned.
    pub max_severity: Option<String>,
    pub scanned_at: Option<DateTime<Utc>>,
}

/// One page of the policy-blocks queue.
#[derive(Debug, Clone, Default)]
pub struct PolicyBlockPage {
    pub items: Vec<PolicyBlock>,
    /// Opaque cursor for the next page; `None` once both sources are done.
    pub next_cursor: Option<String>,
    /// Hosted artifacts whose scan policy this page evaluated.
    pub evaluated: i64,
}

/// Where a policy-blocks page resumes: proxy-cache rows first (an offset into
/// the ordered listing), then hosted artifacts newest first (a keyset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBlockCursor {
    Proxy { offset: usize },
    Hosted { created_at: DateTime<Utc>, id: Uuid },
}

impl PolicyBlockCursor {
    pub fn encode(&self) -> String {
        match self {
            Self::Proxy { offset } => format!("p.{offset}"),
            Self::Hosted { created_at, id } => {
                format!("h.{}.{id}", created_at.timestamp_micros())
            }
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let bad = || AppError::Validation(format!("invalid policy-blocks cursor '{raw}'"));
        let mut parts = raw.splitn(3, '.');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("p"), Some(offset), None) => Ok(Self::Proxy {
                offset: offset.parse().map_err(|_| bad())?,
            }),
            (Some("h"), Some(micros), Some(id)) => Ok(Self::Hosted {
                created_at: DateTime::from_timestamp_micros(micros.parse().map_err(|_| bad())?)
                    .ok_or_else(bad)?,
                id: id.parse().map_err(|_| bad())?,
            }),
            _ => Err(bad()),
        }
    }
}

/// How many hosted candidates one page may evaluate at most, so a page of a
/// repository with a broad policy (a global `block_unscanned`) stays bounded;
/// the cursor carries on from where the budget ran out.
pub(crate) fn hosted_evaluation_budget(limit: i64) -> i64 {
    (limit * 20).clamp(200, 2_000)
}

/// Hosted candidates for the policy-blocks queue: live artifacts of every
/// repository that at least one enabled scan policy applies to (the set
/// `PolicyService::load_applicable_policies` loads from), newest first.
const POLICY_BLOCK_CANDIDATES_SQL: &str = r#"
SELECT a.id, a.repository_id, a.name, a.version, a.path, a.checksum_sha256,
       a.created_at, a.quarantine_status, a.quarantine_source,
       r.key AS repository_key, r.format::text AS repository_format
FROM artifacts a
JOIN repositories r ON r.id = a.repository_id
WHERE a.is_deleted = false
  AND ($1::text IS NULL OR r.key = $1)
  AND EXISTS (
        SELECT 1 FROM scan_policies p
         WHERE p.is_enabled
           AND (p.repository_id = a.repository_id OR p.repository_id IS NULL))
  AND ($2::timestamptz IS NULL OR (a.created_at, a.id) < ($2, $3))
ORDER BY a.created_at DESC, a.id DESC
LIMIT $4
"#;

#[derive(Debug, Clone, FromRow)]
struct PolicyBlockCandidate {
    id: Uuid,
    repository_id: Uuid,
    name: String,
    version: Option<String>,
    path: String,
    checksum_sha256: String,
    created_at: DateTime<Utc>,
    quarantine_status: Option<String>,
    quarantine_source: Option<String>,
    repository_key: String,
    repository_format: String,
}

/// The display name of a proxied path: its last segment.
fn proxy_path_name(path: &str) -> String {
    path.rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

impl DownloadHoldsService {
    /// The policy-blocks queue (#4510): what the download gate's scan-policy
    /// decision refuses right now, never a separate SQL approximation of it.
    ///
    /// * Proxy-cache rows come from
    ///   [`ScanResultService::list_blocked_proxy_entries`](crate::services::scan_result_service::ScanResultService::list_blocked_proxy_entries):
    ///   a cached path is listed only where THAT repository's proxy scan gate
    ///   refuses its digest's verdict (verdicts are shared by digest).
    /// * Hosted artifacts are evaluated with `PolicyService::evaluate_artifact`,
    ///   the function the gate itself calls (`block_unscanned`,
    ///   `block_on_fail`, severity thresholds, predicate policies), so the
    ///   queue lists exactly what a download would refuse with the policy 403.
    ///
    /// Paged by an opaque cursor because the hosted half cannot be counted
    /// without evaluating every candidate: each page evaluates at most
    /// [`hosted_evaluation_budget`] hosted candidates and may come back short
    /// with a cursor; a `None` cursor means both sources are exhausted.
    pub async fn list_policy_blocks(
        &self,
        repository_key: Option<&str>,
        cursor: Option<&PolicyBlockCursor>,
        limit: i64,
    ) -> Result<PolicyBlockPage> {
        let limit = limit.max(1);
        let mut page = PolicyBlockPage::default();
        let mut keyset: Option<(DateTime<Utc>, Uuid)> = None;

        let proxy_offset = match cursor {
            None => Some(0),
            Some(PolicyBlockCursor::Proxy { offset }) => Some(*offset),
            Some(PolicyBlockCursor::Hosted { created_at, id }) => {
                keyset = Some((*created_at, *id));
                None
            }
        };
        if let Some(offset) = proxy_offset {
            let entries =
                crate::services::scan_result_service::ScanResultService::new(self.db.clone())
                    .list_blocked_proxy_entries(repository_key)
                    .await?;
            let take = (limit as usize).min(entries.len().saturating_sub(offset));
            for e in entries.iter().skip(offset).take(take) {
                page.items.push(PolicyBlock {
                    source: "proxy-cache",
                    artifact_id: None,
                    repository_key: e.repository_key.clone(),
                    repository_format: e.repository_format.clone(),
                    name: proxy_path_name(&e.path),
                    path: e.path.clone(),
                    version: None,
                    checksum_sha256: e.checksum_sha256.clone(),
                    quarantine_status: None,
                    hold_source: None,
                    violations: Vec::new(),
                    max_severity: e.max_severity.clone(),
                    scanned_at: Some(e.scanned_at),
                });
            }
            if offset + take < entries.len() {
                page.next_cursor = Some(
                    PolicyBlockCursor::Proxy {
                        offset: offset + take,
                    }
                    .encode(),
                );
                return Ok(page);
            }
        }

        // Hosted half: evaluate candidates newest first until the page is
        // full, the evaluation budget is spent, or there are none left.
        let budget = hosted_evaluation_budget(limit);
        let policy = crate::services::policy_service::PolicyService::new(self.db.clone());
        loop {
            if page.items.len() as i64 >= limit || page.evaluated >= budget {
                page.next_cursor = keyset
                    .map(|(created_at, id)| PolicyBlockCursor::Hosted { created_at, id }.encode());
                return Ok(page);
            }
            let batch = (budget - page.evaluated).min(200);
            let candidates: Vec<PolicyBlockCandidate> = sqlx::query_as(POLICY_BLOCK_CANDIDATES_SQL)
                .bind(repository_key)
                .bind(keyset.map(|k| k.0))
                .bind(keyset.map(|k| k.1))
                .bind(batch)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            if candidates.is_empty() {
                page.next_cursor = None;
                return Ok(page);
            }
            for c in candidates {
                if page.items.len() as i64 >= limit {
                    break;
                }
                keyset = Some((c.created_at, c.id));
                page.evaluated += 1;
                let result = policy.evaluate_artifact(c.id, c.repository_id).await?;
                if result.allowed {
                    continue;
                }
                page.items.push(PolicyBlock {
                    source: "hosted",
                    artifact_id: Some(c.id),
                    repository_key: c.repository_key,
                    repository_format: c.repository_format,
                    path: c.path,
                    name: c.name,
                    version: c.version,
                    checksum_sha256: c.checksum_sha256,
                    quarantine_status: c.quarantine_status,
                    hold_source: c.quarantine_source,
                    violations: result.violations,
                    max_severity: None,
                    scanned_at: None,
                });
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
    fn classify_active_permanent_and_future() {
        let now = Utc::now();
        assert_eq!(
            classify_hold("quarantined", None, now),
            Some(HoldKind::Active)
        );
        assert_eq!(
            classify_hold("quarantined", Some(now + Duration::hours(2)), now),
            Some(HoldKind::Active)
        );
    }

    #[test]
    fn classify_expired_and_rejected() {
        let now = Utc::now();
        assert_eq!(
            classify_hold("quarantined", Some(now - Duration::minutes(1)), now),
            Some(HoldKind::Expired)
        );
        assert_eq!(
            classify_hold("rejected", None, now),
            Some(HoldKind::Rejected)
        );
        assert_eq!(classify_hold("clean", None, now), None);
        assert_eq!(classify_hold("released", None, now), None);
    }

    #[test]
    fn remaining_seconds_permanent_is_none() {
        let now = Utc::now();
        assert_eq!(remaining_seconds(None, now), None);
        let until = now + Duration::seconds(90);
        assert_eq!(remaining_seconds(Some(until), now), Some(90));
        let past = now - Duration::seconds(5);
        assert_eq!(remaining_seconds(Some(past), now), Some(-5));
    }

    #[test]
    fn parse_hold_kinds_defaults_to_blocking() {
        assert_eq!(
            parse_hold_kinds(None).unwrap(),
            vec![HoldKind::Active, HoldKind::Rejected]
        );
        assert_eq!(
            parse_hold_kinds(Some("  ")).unwrap(),
            vec![HoldKind::Active, HoldKind::Rejected]
        );
    }

    #[test]
    fn parse_hold_kinds_splits_and_dedupes() {
        assert_eq!(
            parse_hold_kinds(Some("expired, active, expired")).unwrap(),
            vec![HoldKind::Expired, HoldKind::Active]
        );
    }

    #[test]
    fn parse_hold_kinds_rejects_unknown() {
        let err = parse_hold_kinds(Some("pending")).unwrap_err();
        assert!(err.to_string().contains("Unknown hold kind"));
    }

    #[test]
    fn hold_kind_roundtrip() {
        for kind in [HoldKind::Active, HoldKind::Expired, HoldKind::Rejected] {
            assert_eq!(HoldKind::parse(kind.as_str()), Some(kind));
        }
    }
}
