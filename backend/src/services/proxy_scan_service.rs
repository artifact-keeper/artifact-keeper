//! Digest-keyed proxy scan verdict store (#2954).
//!
//! Proxy-cached bytes are deliberately NOT written to `artifacts` (#1278/#1280),
//! so the `artifact_id`-keyed `scan_results` pipeline cannot hold a verdict for
//! a proxied object. This service persists a content-addressed
//! (`checksum_sha256`) verdict in `proxy_scan_results`, independent of
//! `artifacts`, so that:
//!
//!   * a repeat pull of a known-vulnerable digest is blocked WITHOUT re-fetching
//!     upstream or re-scanning (the fast path), and
//!   * a verdict is shared across repos/tenants pulling identical bytes (same
//!     bytes = same CVEs) and survives proxy-cache eviction.
//!
//! The freshness and fail-open/closed decision logic lives in pure functions so
//! it is unit-testable without a database.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// A persisted proxy scan verdict row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProxyScanRow {
    pub checksum_sha256: String,
    pub scan_type: String,
    pub verdict: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub max_severity: Option<String>,
    pub scanner_version: Option<String>,
    pub scanned_at: DateTime<Utc>,
}

/// The three terminal verdicts stored in `proxy_scan_results.verdict`.
pub const VERDICT_CLEAN: &str = "clean";
pub const VERDICT_VULNERABLE: &str = "vulnerable";
pub const VERDICT_ERROR: &str = "error";

/// Whether a stored verdict means the artifact must be blocked when the repo's
/// scan policy blocks. Only a `vulnerable` verdict blocks; `clean` serves and
/// `error` is inconclusive (handled by the fail-open/closed decision, not here).
pub fn verdict_blocks(verdict: &str) -> bool {
    verdict == VERDICT_VULNERABLE
}

/// Whether a cached verdict may be reused for a fresh pull.
///
/// A verdict is reusable while it is within the TTL window AND (when both the
/// stored and the live scanner version strings are known) the scanner version
/// matches. A CVE-DB bump changes the version string, so a `clean` verdict from
/// yesterday's DB is naturally ignored and the bytes are re-scanned against
/// today's CVEs. When either version string is unknown (probe failed / legacy
/// row) we fall back to the TTL alone rather than forcing an unbounded re-scan.
pub fn verdict_is_fresh(
    scanned_at: DateTime<Utc>,
    stored_version: Option<&str>,
    current_version: Option<&str>,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> bool {
    let within_ttl = now < scanned_at + Duration::days(ttl_days);
    let version_ok = match (stored_version, current_version) {
        (Some(a), Some(b)) => a == b,
        // Unknown on either side: cannot prove a mismatch, rely on TTL.
        _ => true,
    };
    within_ttl && version_ok
}

/// Per-repo action for the inline proxy scan on a first pull of an unknown
/// digest (reuses the `block_unscanned` semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScanAction {
    /// Latency-first (default): serve the first pull immediately and scan
    /// asynchronously; the NEXT pull of that digest is blocked if vulnerable.
    /// Must be loud (warn + audit + `X-AK-Scan: pending`).
    FailOpen,
    /// Never serve unscanned bytes: scan inline before serving; a vulnerable
    /// verdict is a 403, and an over-cap / budget-exceeded / scan-error object
    /// returns 423 rather than a 200 of unscanned bytes.
    FailClosed,
}

impl ProxyScanAction {
    /// Map the `scan_configs.proxy_scan_action` column onto the enum. Unknown /
    /// legacy values default to the safe-for-availability fail-open behavior,
    /// matching the column default.
    pub fn from_db(value: &str) -> Self {
        match value {
            "fail_closed" => ProxyScanAction::FailClosed,
            _ => ProxyScanAction::FailOpen,
        }
    }

    pub fn is_fail_closed(self) -> bool {
        matches!(self, ProxyScanAction::FailClosed)
    }
}

/// Outcome when the inline scan could NOT produce a conclusive clean/vulnerable
/// verdict before serve time: the object was over the byte cap, the inline scan
/// budget was exceeded, or the scanner errored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InconclusiveOutcome {
    /// Serve now with `X-AK-Scan: pending` + warn + audit; scan asynchronously.
    ServePending,
    /// 423 Locked, never a 200 of unscanned bytes.
    Locked,
}

/// Pure decision for the inconclusive branch (over-cap / budget / scan error):
/// fail-open serves-with-pending, fail-closed locks.
pub fn decide_inconclusive(action: ProxyScanAction) -> InconclusiveOutcome {
    match action {
        ProxyScanAction::FailOpen => InconclusiveOutcome::ServePending,
        ProxyScanAction::FailClosed => InconclusiveOutcome::Locked,
    }
}

pub struct ProxyScanService {
    db: PgPool,
}

impl ProxyScanService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Look up a stored verdict for `(checksum_sha256, scan_type)`.
    pub async fn lookup_verdict(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
    ) -> Result<Option<ProxyScanRow>> {
        let row = sqlx::query_as!(
            ProxyScanRow,
            r#"
            SELECT checksum_sha256, scan_type, verdict,
                   findings_count, critical_count, high_count, medium_count, low_count,
                   max_severity, scanner_version, scanned_at
            FROM proxy_scan_results
            WHERE checksum_sha256 = $1 AND scan_type = $2
            "#,
            checksum_sha256,
            scan_type,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(row)
    }

    /// Upsert a verdict keyed on `(checksum_sha256, scan_type)`. A newer scan of
    /// the same bytes (e.g. against a bumped CVE-DB) replaces the prior row.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_verdict(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        verdict: &str,
        findings_count: i32,
        critical_count: i32,
        high_count: i32,
        medium_count: i32,
        low_count: i32,
        max_severity: Option<&str>,
        scanner_version: Option<&str>,
        repository_id: Option<Uuid>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO proxy_scan_results (
                checksum_sha256, scan_type, verdict,
                findings_count, critical_count, high_count, medium_count, low_count,
                max_severity, scanner_version, repository_id, scanned_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
            ON CONFLICT (checksum_sha256, scan_type) DO UPDATE SET
                verdict = EXCLUDED.verdict,
                findings_count = EXCLUDED.findings_count,
                critical_count = EXCLUDED.critical_count,
                high_count = EXCLUDED.high_count,
                medium_count = EXCLUDED.medium_count,
                low_count = EXCLUDED.low_count,
                max_severity = EXCLUDED.max_severity,
                scanner_version = EXCLUDED.scanner_version,
                repository_id = EXCLUDED.repository_id,
                scanned_at = now()
            "#,
            checksum_sha256,
            scan_type,
            verdict,
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            max_severity,
            scanner_version,
            repository_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_blocks_only_vulnerable() {
        assert!(verdict_blocks(VERDICT_VULNERABLE));
        assert!(!verdict_blocks(VERDICT_CLEAN));
        assert!(!verdict_blocks(VERDICT_ERROR));
        assert!(!verdict_blocks("something-else"));
    }

    #[test]
    fn fresh_within_ttl_same_version() {
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        assert!(verdict_is_fresh(
            scanned,
            Some("grype-0.83.0"),
            Some("grype-0.83.0"),
            30,
            now
        ));
    }

    #[test]
    fn stale_past_ttl() {
        let now = Utc::now();
        let scanned = now - Duration::days(31);
        assert!(!verdict_is_fresh(
            scanned,
            Some("grype-0.83.0"),
            Some("grype-0.83.0"),
            30,
            now
        ));
    }

    #[test]
    fn stale_on_version_mismatch_even_within_ttl() {
        // A CVE-DB bump changes the version string: a yesterday-clean verdict
        // must be re-evaluated against today's CVEs.
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        assert!(!verdict_is_fresh(
            scanned,
            Some("grype-0.83.0"),
            Some("grype-0.84.0"),
            30,
            now
        ));
    }

    #[test]
    fn unknown_version_falls_back_to_ttl() {
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        // Either side unknown => cannot prove a mismatch, rely on TTL.
        assert!(verdict_is_fresh(
            scanned,
            None,
            Some("grype-0.84.0"),
            30,
            now
        ));
        assert!(verdict_is_fresh(
            scanned,
            Some("grype-0.83.0"),
            None,
            30,
            now
        ));
        assert!(!verdict_is_fresh(
            now - Duration::days(31),
            None,
            None,
            30,
            now
        ));
    }

    #[test]
    fn action_from_db_defaults_fail_open() {
        assert_eq!(
            ProxyScanAction::from_db("fail_closed"),
            ProxyScanAction::FailClosed
        );
        assert_eq!(
            ProxyScanAction::from_db("fail_open"),
            ProxyScanAction::FailOpen
        );
        // Unknown / legacy => fail-open (matches the column default).
        assert_eq!(
            ProxyScanAction::from_db("garbage"),
            ProxyScanAction::FailOpen
        );
        assert!(ProxyScanAction::FailClosed.is_fail_closed());
        assert!(!ProxyScanAction::FailOpen.is_fail_closed());
    }

    #[test]
    fn inconclusive_is_pending_open_locked_closed() {
        // Over-cap / budget / scan-error: fail-open serves-with-pending,
        // fail-closed never serves unscanned bytes.
        assert_eq!(
            decide_inconclusive(ProxyScanAction::FailOpen),
            InconclusiveOutcome::ServePending
        );
        assert_eq!(
            decide_inconclusive(ProxyScanAction::FailClosed),
            InconclusiveOutcome::Locked
        );
    }
}
