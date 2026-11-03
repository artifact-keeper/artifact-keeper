//! The one definition of "open findings by severity" (#4338).
//!
//! Every place that shows a severity count reads it from here: the security
//! dashboard tiles (`GET /api/v1/security/dashboard`), the per-repository
//! scores (`repo_security_scores`, recomputed by
//! [`ScanResultService::recalculate_score`](super::scan_result_service::ScanResultService::recalculate_score)),
//! and the Overview dashboard's CVE summary (`GET /api/v1/sbom/cve/trends`).
//! Before #4338 each of them counted something different on the same data:
//!
//! * the security tiles and the per-repository scores counted finding ROWS,
//!   so one CVE reported for two packages of an image, or by two scanners,
//!   counted two or more times;
//! * the per-repository scores were only recomputed when a scan finished, so
//!   acknowledging a finding changed the tiles but not the repository row;
//! * the Overview summary counted every (artifact, CVE) ever recorded,
//!   including CVEs a later rescan no longer reports, and put acknowledged
//!   CVEs in its severity buckets.
//!
//! The shared definition:
//!
//! 1. **Which scans.** For each artifact that is not deleted, the latest
//!    completed scan of each scan type, and every external submission. A rescan
//!    that no longer reports a vulnerability removes it. The download gate also
//!    keeps a complete scan's verdict past a later incomplete or crashed scan
//!    (`artifact_current_scan_ids`); these counts do not, so in that one case a
//!    tile can read clear while the gate refuses.
//! 2. **What is counted.** One vulnerability per (artifact, advisory). The
//!    advisory is the CVE id, case-insensitively, or the finding title when a
//!    scanner reported no CVE id (GHSA/OSV-only advisories, OpenSCAP rules).
//!    The same advisory reported for several packages of one artifact, or by
//!    several scanners, is one vulnerability.
//! 3. **Severity.** The highest severity any of those scans reported for it.
//! 4. **Open or acknowledged.** Acknowledged only when a decision covers every
//!    finding row behind it (#5153, `scan_findings_effective`). The severity counts are of OPEN
//!    vulnerabilities; acknowledged ones are counted separately.

use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Which artifacts a count covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingScope {
    /// Every artifact (dashboards).
    All,
    /// The artifacts of one repository.
    Repository(Uuid),
    /// One artifact.
    Artifact(Uuid),
}

impl FindingScope {
    fn filter(self) -> &'static str {
        match self {
            FindingScope::All => "",
            FindingScope::Repository(_) => "AND a.repository_id = $1",
            FindingScope::Artifact(_) => "AND a.id = $1",
        }
    }

    fn bind(self) -> Option<Uuid> {
        match self {
            FindingScope::All => None,
            FindingScope::Repository(id) | FindingScope::Artifact(id) => Some(id),
        }
    }
}

/// The severity rank used to pick "the highest severity reported". Also the
/// table the CVE-history projections use, so the two cannot disagree on order.
pub(crate) const SEVERITY_RANK_SQL: &str = "CASE LOWER(sf.severity) \
     WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 \
     WHEN 'low' THEN 1 ELSE 0 END";

/// The advisory key: the CVE id (case-insensitive) or, without one, the title.
pub(crate) const ADVISORY_KEY_SQL: &str = "COALESCE(NULLIF(UPPER(BTRIM(sf.cve_id)), ''), sf.title)";

/// `WITH latest_scans AS (...), vulnerabilities AS (...)` for `scope`: one row
/// per (artifact, advisory) with its `severity_rank` (4 critical .. 0 info)
/// and whether it is `acknowledged`. Bind the scope's id as `$1` when it has
/// one (see [`FindingScope`]).
pub fn vulnerabilities_cte(scope: FindingScope) -> String {
    format!(
        r#"WITH latest_scans AS (
    SELECT DISTINCT ON (sr.artifact_id, sr.scan_type,
                        CASE WHEN sr.scan_type = 'external' THEN sr.id END) sr.id
    FROM scan_results sr
    JOIN artifacts a ON a.id = sr.artifact_id
    WHERE sr.status = 'completed'
      AND NOT a.is_deleted
      {filter}
    ORDER BY sr.artifact_id, sr.scan_type,
             CASE WHEN sr.scan_type = 'external' THEN sr.id END,
             sr.completed_at DESC NULLS LAST, sr.created_at DESC
),
vulnerabilities AS (
    SELECT sf.artifact_id,
           {key} AS advisory,
           MAX({rank}) AS severity_rank,
           BOOL_AND(sf.is_acknowledged) AS acknowledged
    FROM scan_findings_effective sf
    JOIN latest_scans ls ON ls.id = sf.scan_result_id
    GROUP BY sf.artifact_id, {key}
)"#,
        filter = scope.filter(),
        key = ADVISORY_KEY_SQL,
        rank = SEVERITY_RANK_SQL,
    )
}

/// The full counting statement for `scope`.
pub fn severity_counts_sql(scope: FindingScope) -> String {
    format!(
        r#"{cte}
SELECT
    COUNT(*) FILTER (WHERE NOT acknowledged AND severity_rank = 4) AS critical,
    COUNT(*) FILTER (WHERE NOT acknowledged AND severity_rank = 3) AS high,
    COUNT(*) FILTER (WHERE NOT acknowledged AND severity_rank = 2) AS medium,
    COUNT(*) FILTER (WHERE NOT acknowledged AND severity_rank = 1) AS low,
    COUNT(*) FILTER (WHERE NOT acknowledged AND severity_rank = 0) AS info,
    COUNT(*) FILTER (WHERE NOT acknowledged) AS open,
    COUNT(*) FILTER (WHERE acknowledged) AS acknowledged
FROM vulnerabilities"#,
        cte = vulnerabilities_cte(scope)
    )
}

/// Open vulnerabilities by severity, plus the acknowledged ones, under the
/// shared definition (see the module docs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, FromRow, Serialize)]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    /// Open vulnerabilities of every severity (`critical + .. + info`).
    pub open: i64,
    /// Vulnerabilities whose every finding row is acknowledged.
    pub acknowledged: i64,
}

impl SeverityCounts {
    /// Open plus acknowledged.
    pub fn total(&self) -> i64 {
        self.open + self.acknowledged
    }
}

/// Count open vulnerabilities by severity for `scope`. Runs on `executor`, so
/// a caller holding a transaction (the score recompute's REPEATABLE READ
/// snapshot) counts inside it.
pub async fn severity_counts<'e, E>(executor: E, scope: FindingScope) -> Result<SeverityCounts>
where
    E: sqlx::PgExecutor<'e>,
{
    let sql = severity_counts_sql(scope);
    let query = sqlx::query_as::<_, SeverityCounts>(sqlx::AssertSqlSafe(sql));
    let query = match scope.bind() {
        Some(id) => query.bind(id),
        None => query,
    };
    query
        .fetch_one(executor)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_come_from_the_latest_completed_scan_per_artifact_and_scan_type() {
        let sql = severity_counts_sql(FindingScope::All);
        assert!(sql.contains("DISTINCT ON (sr.artifact_id, sr.scan_type,"));
        assert!(sql.contains("sr.status = 'completed'"));
        assert!(sql.contains("NOT a.is_deleted"));
        assert!(sql.contains("sr.completed_at DESC NULLS LAST, sr.created_at DESC"));
        // Every external submission counts, as at the download gate: they share
        // one scan type and one vendor's cannot supersede another's (#5153).
        assert!(sql.contains("CASE WHEN sr.scan_type = 'external' THEN sr.id END"));
    }

    #[test]
    fn one_vulnerability_per_artifact_and_advisory_at_its_highest_severity() {
        let sql = severity_counts_sql(FindingScope::All);
        assert!(sql.contains(&format!("GROUP BY sf.artifact_id, {ADVISORY_KEY_SQL}")));
        assert!(sql.contains(&format!("MAX({SEVERITY_RANK_SQL})")));
        assert!(sql.contains("BOOL_AND(sf.is_acknowledged)"));
        for (label, rank) in [("critical", 4), ("high", 3), ("medium", 2), ("low", 1)] {
            assert!(SEVERITY_RANK_SQL.contains(&format!("WHEN '{label}' THEN {rank}")));
        }
    }

    #[test]
    fn severity_buckets_count_open_vulnerabilities_only() {
        let sql = severity_counts_sql(FindingScope::All);
        for (rank, column) in [
            (4, "critical"),
            (3, "high"),
            (2, "medium"),
            (1, "low"),
            (0, "info"),
        ] {
            assert!(
                sql.contains(&format!(
                    "FILTER (WHERE NOT acknowledged AND severity_rank = {rank}) AS {column}"
                )),
                "{column}"
            );
        }
        assert!(sql.contains("FILTER (WHERE acknowledged) AS acknowledged"));
    }

    #[test]
    fn scope_binds_exactly_one_filter() {
        let all = severity_counts_sql(FindingScope::All);
        assert!(!all.contains("$1"));
        let repo = severity_counts_sql(FindingScope::Repository(Uuid::nil()));
        assert!(repo.contains("AND a.repository_id = $1"));
        let artifact = severity_counts_sql(FindingScope::Artifact(Uuid::nil()));
        assert!(artifact.contains("AND a.id = $1"));
        assert_eq!(FindingScope::All.bind(), None);
        assert_eq!(
            FindingScope::Repository(Uuid::nil()).bind(),
            Some(Uuid::nil())
        );
    }

    #[test]
    fn total_is_open_plus_acknowledged() {
        let c = SeverityCounts {
            open: 4,
            acknowledged: 2,
            ..Default::default()
        };
        assert_eq!(c.total(), 6);
    }
}
