//! Admin observability for packages that currently cannot be downloaded.
//!
//! Three independent control planes refuse bytes for different reasons:
//!
//! * **Age gate** — too-new upstream versions (`age_gate_reviews`, HTTP 451).
//! * **Quarantine** — timed upload/age holds and admin blocks (`artifacts`, HTTP 409/403).
//! * **Scan policy** — unacknowledged findings at/above a policy threshold, plus
//!   proxy-cache verdicts (`scan_policies` / `proxy_scan_results`, HTTP 403).
//!
//! This module lists the last two (age-gate already has its own queue) and
//! rolls the three into a single summary so the UI can show counts at a glance.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::{AppError, Result};

/// How a quarantine row currently behaves at the download gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldKind {
    /// `quarantined` and the window is still open (or permanent: `until` is NULL).
    Active,
    /// Still labelled `quarantined`, but `quarantine_until` has lapsed — downloads work.
    Expired,
    /// Terminal admin/scan rejection — downloads stay 403.
    Rejected,
}

/// Classify a stored quarantine row the same way [`crate::services::quarantine_service::check_download_allowed`]
/// does, plus the expired-but-still-labelled case the queue needs to show remaining time as "Expired".
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

/// Count of unacknowledged findings at or above a policy's `max_severity`.
pub fn violating_finding_count(
    max_severity: &str,
    critical: i32,
    high: i32,
    medium: i32,
    low: i32,
) -> i32 {
    match max_severity {
        "critical" => critical,
        "high" => critical + high,
        "medium" => critical + high + medium,
        _ => critical + high + medium + low,
    }
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

pub fn normalize_pagination(page: Option<u32>, per_page: Option<u32>) -> (u32, u32, i64) {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).clamp(1, 100);
    let offset = i64::from(page - 1) * i64::from(per_page);
    (page, per_page, offset)
}

pub fn total_pages(total: i64, per_page: u32) -> u32 {
    if total <= 0 {
        0
    } else {
        ((total as f64) / (per_page as f64)).ceil() as u32
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct QuarantineHoldRow {
    pub artifact_id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub repository_key: String,
    pub repository_format: String,
    pub quarantine_status: String,
    pub quarantine_until: Option<DateTime<Utc>>,
    pub quarantine_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PolicyBlockRow {
    pub id: String,
    pub source: String,
    pub artifact_id: Option<Uuid>,
    pub package_name: String,
    pub package_version: Option<String>,
    pub path: String,
    pub repository_key: String,
    pub repository_format: String,
    pub uploaded_at: Option<DateTime<Utc>>,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub findings_count: i32,
    pub max_severity: Option<String>,
    pub policy_name: Option<String>,
    pub block_reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct HoldsSummary {
    pub age_gate_pending: i64,
    pub quarantine_active: i64,
    pub quarantine_rejected: i64,
    pub policy_blocked: i64,
}

pub struct DownloadHoldsService {
    db: PgPool,
}

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
            SELECT COUNT(*)::bigint FROM artifacts
            WHERE is_deleted = false
              AND quarantine_status = 'quarantined'
              AND (quarantine_until IS NULL OR quarantine_until > NOW())
              AND (quarantine_reason IS NULL OR quarantine_reason NOT LIKE '%Policy ''%')
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

        let policy_blocked =
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(policy_block_count_sql()))
                .bind(None::<String>)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(HoldsSummary {
            age_gate_pending,
            quarantine_active,
            quarantine_rejected,
            policy_blocked,
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

        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)::bigint
            FROM artifacts a
            INNER JOIN repositories repo ON repo.id = a.repository_id
            WHERE a.is_deleted = false
              AND ($1::text IS NULL OR repo.key = $1)
              AND (a.quarantine_reason IS NULL OR a.quarantine_reason NOT LIKE '%Policy ''%')
              AND (
                    ($2::bool AND a.quarantine_status = 'quarantined'
                        AND (a.quarantine_until IS NULL OR a.quarantine_until > NOW()))
                 OR ($3::bool AND a.quarantine_status = 'quarantined'
                        AND a.quarantine_until IS NOT NULL AND a.quarantine_until <= NOW())
                 OR ($4::bool AND a.quarantine_status = 'rejected')
              )
            "#,
        )
        .bind(repository_key)
        .bind(want_active)
        .bind(want_expired)
        .bind(want_rejected)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let rows = sqlx::query_as::<_, QuarantineHoldRow>(
            r#"
            SELECT
                a.id AS artifact_id,
                a.name,
                a.version,
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
              AND (a.quarantine_reason IS NULL OR a.quarantine_reason NOT LIKE '%Policy ''%')
              AND (
                    ($2::bool AND a.quarantine_status = 'quarantined'
                        AND (a.quarantine_until IS NULL OR a.quarantine_until > NOW()))
                 OR ($3::bool AND a.quarantine_status = 'quarantined'
                        AND a.quarantine_until IS NOT NULL AND a.quarantine_until <= NOW())
                 OR ($4::bool AND a.quarantine_status = 'rejected')
              )
            ORDER BY
                CASE a.quarantine_status
                    WHEN 'quarantined' THEN 0
                    WHEN 'rejected' THEN 1
                    ELSE 2
                END,
                a.quarantine_until ASC NULLS LAST,
                a.created_at DESC
            OFFSET $5 LIMIT $6
            "#,
        )
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

    pub async fn list_policy_blocks(
        &self,
        repository_key: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<PolicyBlockRow>, i64)> {
        let total = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(policy_block_count_sql()))
            .bind(repository_key)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let rows = sqlx::query_as::<_, PolicyBlockRow>(sqlx::AssertSqlSafe(format!(
            "{POLICY_BLOCK_FROM_SQL}
             ORDER BY uploaded_at DESC NULLS LAST, package_name
             OFFSET $2 LIMIT $3"
        )))
        .bind(repository_key)
        .bind(offset)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((rows, total))
    }
}

/// Shared FROM/WHERE for policy-blocked hosted + proxy rows.
/// `$1` is an optional repository key.
const POLICY_BLOCK_FROM_SQL: &str = r#"
WITH finding_counts AS (
    SELECT
        artifact_id,
        COUNT(*) FILTER (WHERE NOT is_acknowledged AND severity = 'critical')::int AS critical_count,
        COUNT(*) FILTER (WHERE NOT is_acknowledged AND severity = 'high')::int AS high_count,
        COUNT(*) FILTER (WHERE NOT is_acknowledged AND severity = 'medium')::int AS medium_count,
        COUNT(*) FILTER (WHERE NOT is_acknowledged AND severity = 'low')::int AS low_count,
        COUNT(*) FILTER (WHERE NOT is_acknowledged)::int AS findings_count
    FROM scan_findings
    GROUP BY artifact_id
),
hosted_raw AS (
    SELECT
        a.id,
        a.name,
        a.version,
        a.path,
        repo.key AS repository_key,
        repo.format::text AS repository_format,
        a.created_at,
        fc.critical_count,
        fc.high_count,
        fc.medium_count,
        fc.low_count,
        fc.findings_count,
        p.max_severity,
        p.name AS policy_name,
        p.repository_id IS NOT NULL AS repo_scoped,
        CASE p.max_severity
            WHEN 'critical' THEN fc.critical_count
            WHEN 'high' THEN fc.critical_count + fc.high_count
            WHEN 'medium' THEN fc.critical_count + fc.high_count + fc.medium_count
            ELSE fc.critical_count + fc.high_count + fc.medium_count + fc.low_count
        END AS violating_count
    FROM artifacts a
    INNER JOIN repositories repo ON repo.id = a.repository_id
    INNER JOIN finding_counts fc ON fc.artifact_id = a.id
    INNER JOIN scan_policies p
        ON p.is_enabled
       AND (p.repository_id = repo.id OR p.repository_id IS NULL)
    WHERE a.is_deleted = false
      AND ($1::text IS NULL OR repo.key = $1)
),
hosted AS (
    SELECT DISTINCT ON (id)
        id::text AS id,
        'hosted'::text AS source,
        id AS artifact_id,
        name AS package_name,
        version AS package_version,
        path,
        repository_key,
        repository_format,
        created_at AS uploaded_at,
        critical_count,
        high_count,
        medium_count,
        low_count,
        findings_count,
        max_severity,
        policy_name,
        format(
            'Policy ''%s'': %s findings at or above %s',
            policy_name, violating_count, max_severity
        ) AS block_reason
    FROM hosted_raw
    WHERE violating_count > 0
    ORDER BY id, repo_scoped DESC, violating_count DESC
),
proxy AS (
    SELECT DISTINCT ON (pca.id)
        pca.id::text AS id,
        'proxy'::text AS source,
        NULL::uuid AS artifact_id,
        COALESCE(NULLIF(regexp_replace(pca.path, '.*/', ''), ''), pca.path) AS package_name,
        NULL::text AS package_version,
        pca.path AS path,
        repo.key AS repository_key,
        repo.format::text AS repository_format,
        pca.cached_at AS uploaded_at,
        psr.critical_count,
        psr.high_count,
        psr.medium_count,
        psr.low_count,
        psr.findings_count,
        psr.max_severity,
        NULL::text AS policy_name,
        'Vulnerable according to proxy scan'::text AS block_reason
    FROM proxy_cache_artifacts pca
    INNER JOIN repositories repo ON repo.id = pca.repository_id
    INNER JOIN proxy_scan_results psr
        ON psr.checksum_sha256 = pca.checksum_sha256
       AND psr.verdict = 'vulnerable'
    WHERE pca.size_bytes > 0
      AND pca.checksum_sha256 IS NOT NULL
      AND ($1::text IS NULL OR repo.key = $1)
    ORDER BY pca.id, psr.scanned_at DESC
),
stamped AS (
    SELECT
        a.id::text AS id,
        'hosted'::text AS source,
        a.id AS artifact_id,
        COALESCE(NULLIF(a.name, ''), a.path) AS package_name,
        a.version AS package_version,
        a.path,
        repo.key AS repository_key,
        repo.format::text AS repository_format,
        a.created_at AS uploaded_at,
        0::int AS critical_count,
        0::int AS high_count,
        0::int AS medium_count,
        0::int AS low_count,
        0::int AS findings_count,
        NULL::text AS max_severity,
        NULL::text AS policy_name,
        COALESCE(a.quarantine_reason, 'Blocked by scan policy') AS block_reason
    FROM artifacts a
    INNER JOIN repositories repo ON repo.id = a.repository_id
    WHERE a.is_deleted = false
      AND a.quarantine_status = 'policy_blocked'
      AND ($1::text IS NULL OR repo.key = $1)
)
SELECT * FROM hosted
UNION ALL
SELECT s.* FROM stamped s
LEFT JOIN hosted h ON h.artifact_id = s.artifact_id
WHERE h.artifact_id IS NULL
UNION ALL
SELECT * FROM proxy
"#;

fn policy_block_count_sql() -> String {
    format!("SELECT COUNT(*)::bigint FROM ({POLICY_BLOCK_FROM_SQL}) policy_blocks")
}

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
    fn violating_count_matches_policy_threshold() {
        assert_eq!(violating_finding_count("critical", 1, 9, 9, 9), 1);
        assert_eq!(violating_finding_count("high", 1, 2, 9, 9), 3);
        assert_eq!(violating_finding_count("medium", 0, 0, 4, 1), 4);
        assert_eq!(violating_finding_count("low", 0, 0, 0, 2), 2);
        assert_eq!(violating_finding_count("unknown", 1, 1, 1, 1), 4);
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
    fn pagination_clamps() {
        assert_eq!(normalize_pagination(None, None), (1, 20, 0));
        assert_eq!(normalize_pagination(Some(0), Some(500)), (1, 100, 0));
        assert_eq!(normalize_pagination(Some(3), Some(10)), (3, 10, 20));
        assert_eq!(total_pages(0, 20), 0);
        assert_eq!(total_pages(45, 20), 3);
    }

    #[test]
    fn hold_kind_roundtrip() {
        for kind in [HoldKind::Active, HoldKind::Expired, HoldKind::Rejected] {
            assert_eq!(HoldKind::parse(kind.as_str()), Some(kind));
        }
    }
}
