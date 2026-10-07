//! Admin observability for packages that currently cannot be downloaded.
//!
//! Two independent control planes refuse bytes for different reasons:
//!
//! * **Age gate** — too-new upstream versions (`age_gate_reviews`, HTTP 451).
//! * **Quarantine** — timed upload/age holds and admin blocks (`artifacts`
//!   status, plus proxy-cache `quarantine_until` / `quarantine_released_at`).
//!
//! Scan-policy blocks are currently stored as a quarantine stamp
//! (`quarantine_status = 'quarantined'` with a `Policy '...'` reason), so they
//! DO appear in the quarantine queue, as `source: hosted, kind: active`. They
//! cannot be told apart from other holds until the hold records its origin
//! (a `quarantine_source` column, #4510).
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
    pub created_at: DateTime<Utc>,
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
/// `$1` repository key, `$2` want_active, `$3` want_expired, `$4` want_rejected.
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
    a.created_at
FROM artifacts a
INNER JOIN repositories repo ON repo.id = a.repository_id
WHERE a.is_deleted = false
  AND ($1::text IS NULL OR repo.key = $1)
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
    pca.cached_at AS created_at
FROM proxy_cache_artifacts pca
INNER JOIN repositories repo ON repo.id = pca.repository_id
WHERE pca.quarantine_released_at IS NULL
  AND pca.quarantine_until IS NOT NULL
  AND ($1::text IS NULL OR repo.key = $1)
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
             OFFSET $5 LIMIT $6"
        )))
        .bind(repository_key)
        .bind(want_active)
        .bind(want_expired)
        .bind(want_rejected)
        .bind(offset)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((rows, total))
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
