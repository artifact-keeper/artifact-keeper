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

/// Whether a cached verdict may SHORT-CIRCUIT the serve path for this repo's
/// scan action — the policy-aware gate the serve path actually asks.
///
/// [`verdict_is_fresh`] answers the narrower, policy-free question "can we
/// prove this verdict is stale?", and deliberately fails OPEN when a version
/// string is unknown on either side (probe failed / legacy row): it cannot
/// prove a mismatch, so it relies on the TTL. That default is right for
/// fail-open, but on a `fail_closed` repo it is a hole: the freshness check
/// runs BEFORE the inline scan, so an unprovable `clean` verdict short-circuits
/// the whole fail-closed gate (including the #2954 "the CVE engine actually
/// ran" condition) and serves cached-clean bytes that nothing on this node can
/// currently vouch for.
///
/// That unknown-version window is common exactly when it matters most: a Grype
/// UPGRADE — the CVE-DB advance #2976 is about — transiently fails
/// `grype --version` (a >=60s [`VERSION_CACHE_MISS_TTL`] window), a missing
/// binary makes it permanent, and a loaded host can push the probe past its
/// 5s timeout. A node that 423s a FRESH pull (provably fail-closed) must not
/// serve a stale `clean` digest through the same policy.
///
/// So under `fail_closed` a CLEAN verdict is reusable only when its provenance
/// is PROVEN current — both version strings known and equal. Otherwise the
/// verdict is treated as stale and the caller falls through to the re-scan
/// branch, whose inconclusive outcome correctly fail-closes (423). This
/// self-heals: the re-scan records the live version, so the next pull of that
/// digest hits the cache normally.
///
/// Everything else is unchanged: `fail_open` keeps the TTL-only fallback (its
/// re-scan branch serves-with-pending anyway, so availability is unaffected),
/// and non-`clean` verdicts keep their existing handling — a cached
/// `vulnerable` verdict still blocks via [`verdict_blocks`].
///
/// [`VERSION_CACHE_MISS_TTL`]: crate::services::scanner_service
pub fn verdict_is_reusable(
    verdict: &str,
    scanned_at: DateTime<Utc>,
    stored_version: Option<&str>,
    current_version: Option<&str>,
    action: ProxyScanAction,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> bool {
    if !verdict_is_fresh(scanned_at, stored_version, current_version, ttl_days, now) {
        return false;
    }
    if action.is_fail_closed() && verdict == VERDICT_CLEAN {
        // Fail-closed: "not provably stale" is not good enough for a clean
        // verdict; require provably-current provenance.
        return matches!((stored_version, current_version), (Some(_), Some(_)));
    }
    true
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

/// What the proxy serve path must do for one pull, given the stored verdict
/// row (if any), the LIVE CVE-scanner version, and the repo's scan action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeDecision {
    /// Fresh reusable clean verdict: serve the buffered bytes (`X-AK-Scan:
    /// clean`), no re-scan.
    ServeCached,
    /// Fresh reusable vulnerable verdict: block (403) without re-scanning.
    BlockCached,
    /// Fail-closed with no reusable verdict: scan inline before serving a
    /// single byte; the scan outcome then serves / blocks / 423s.
    ScanInline,
    /// Fail-open with no reusable verdict: serve now (`X-AK-Scan: pending`)
    /// and scan asynchronously so the NEXT pull of this digest is gated.
    ServePendingScanAsync,
}

/// The freshness + fail-open/closed serve state machine, single-sourced for
/// every proxy format (PyPI wheels, npm tarballs, OCI manifests). Lifted from
/// the PyPI serve path so per-format handlers cannot re-implement — and
/// silently drift on — the two carried defenses:
///
/// * #2976: an UNKNOWN live CVE-scanner version (`current_version = None`)
///   under `fail_closed` must NOT reuse a cached `clean` verdict — the pull
///   falls through to the re-scan branch ([`verdict_is_reusable`]).
/// * #2954: the re-scan branch under `fail_closed` is [`ServeDecision::
///   ScanInline`], whose inconclusive outcome the caller fail-closes (423)
///   rather than serving unscanned bytes.
///
/// Pure over the row + versions + clock (the one `warn!` is observability,
/// not behavior), so the regression cases are unit-testable without a DB or a
/// live scanner.
pub fn decide_serve(
    row: Option<&ProxyScanRow>,
    current_version: Option<&str>,
    action: ProxyScanAction,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> ServeDecision {
    if let Some(row) = row {
        let reusable = verdict_is_reusable(
            &row.verdict,
            row.scanned_at,
            row.scanner_version.as_deref(),
            current_version,
            action,
            ttl_days,
            now,
        );
        if !reusable && current_version.is_none() && action.is_fail_closed() {
            tracing::warn!(
                stored_version = ?row.scanner_version,
                "live CVE-scanner version unknown; not reusing the cached verdict \
                 on a fail-closed repo (re-scanning)"
            );
        }
        if reusable {
            return if verdict_blocks(&row.verdict) {
                ServeDecision::BlockCached
            } else {
                ServeDecision::ServeCached
            };
        }
    }
    if action.is_fail_closed() {
        ServeDecision::ScanInline
    } else {
        ServeDecision::ServePendingScanAsync
    }
}

// ---------------------------------------------------------------------------
// Proxy scan visibility (#3348): pure state-mapping + staleness helpers
// ---------------------------------------------------------------------------
//
// GET /api/v1/repositories/:key/security/proxy-scans reads this same table
// but must never invent a state the write path cannot produce. These helpers
// are the single source for that mapping so the handler and its tests share
// one definition instead of re-deriving it inline.

/// The three states the read endpoint may report. `error` is deliberately
/// excluded: `VERDICT_ERROR` has zero production writers (see module docs on
/// [`decide_inconclusive`]), so surfacing it as a fourth state would document
/// dead code as a real UI affordance.
pub const STATE_CLEAN: &str = "clean";
pub const STATE_VULNERABLE: &str = "vulnerable";
pub const STATE_NOT_SCANNED: &str = "not_scanned";

/// `not_scanned` reason: `scan_configs.scan_on_proxy` is `false`, INCLUDING
/// when the row is absent (the default state — see
/// [`ScanConfigService::is_proxy_scan_enabled`](crate::services::scan_config_service::ScanConfigService::is_proxy_scan_enabled)).
pub const NOT_SCANNED_REASON_SCANNING_DISABLED: &str = "scanning_disabled";
/// `not_scanned` reason: everything else — over the size cap, identity
/// unestablished, a failed scan, or (defensively) an unrecognized verdict
/// token. Must never be worded to imply the content is safe.
pub const NOT_SCANNED_REASON_UNKNOWN: &str = "unknown";

/// Derive `(state, reason)` for one proxy-cached digest from its verdict (if
/// any row was found by the `checksum_sha256 + scan_type` join) and whether
/// proxy scanning is enabled for the calling repository.
///
/// `reason` is `Some` iff `state == STATE_NOT_SCANNED`; `None` for `clean` /
/// `vulnerable`. A naive `WHERE scan_on_proxy = false` join on an absent
/// `scan_configs` row would return no rows at all and misfile the repo's
/// default (never-configured) state as `unknown` instead of
/// `scanning_disabled` — callers must resolve `scan_on_proxy` via
/// `is_proxy_scan_enabled`'s `unwrap_or(false)` BEFORE calling this, not via
/// a raw join, so that default is captured correctly.
pub fn derive_proxy_scan_state(
    verdict: Option<&str>,
    scan_on_proxy: bool,
) -> (&'static str, Option<&'static str>) {
    match verdict {
        Some(VERDICT_CLEAN) => (STATE_CLEAN, None),
        Some(VERDICT_VULNERABLE) => (STATE_VULNERABLE, None),
        // VERDICT_ERROR or any other unrecognized token: no writer produces
        // this today, but fold defensively into not_scanned/unknown rather
        // than panicking or fabricating a fourth state.
        Some(_) => (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN)),
        None if !scan_on_proxy => (
            STATE_NOT_SCANNED,
            Some(NOT_SCANNED_REASON_SCANNING_DISABLED),
        ),
        None => (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN)),
    }
}

/// Age-based staleness for the read endpoint: `scanned_at < now - ttl_days`.
///
/// Deliberately NOT [`verdict_is_reusable`]: that function is policy-
/// contaminated (factors in `fail_closed`, so the same row would render stale
/// in one repository and fresh in another) and needs a live scanner-version
/// probe, neither of which a read-only summary aggregate can do.
///
/// Boundary: the serve-path freshness gate ([`verdict_is_fresh`]) tests
/// `now < scanned_at + ttl` (strict). The equivalent strict form of this
/// staleness test is `now > scanned_at + ttl`, so at exact equality
/// (`scanned_at + ttl == now`) a verdict is reported as neither fresh nor
/// stale by either function — consistent, not a gap.
///
/// A digest with no verdict row (`not_scanned`) is never stale: there is
/// nothing to have gone stale. Callers with a nullable `scanned_at` from a
/// `LEFT JOIN` must route it through this function (or an equivalent
/// `COALESCE(..., false)`) rather than a raw SQL comparison — a raw
/// `scanned_at < now() - interval` against a NULL `scanned_at` evaluates to
/// SQL NULL, which — if ever used as a `GROUP BY` key — creates a spurious
/// third group alongside `true`/`false`.
pub fn is_proxy_scan_stale(
    scanned_at: Option<DateTime<Utc>>,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> bool {
    match scanned_at {
        Some(t) => t < now - Duration::days(ttl_days),
        None => false,
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

    /// #2976 follow-up: `verdict_is_fresh` fails OPEN on an unknown version
    /// (it cannot prove a mismatch). `verdict_is_reusable` must NOT let that
    /// default short-circuit a fail-closed repo for a CLEAN verdict — the
    /// freshness check runs before the inline scan, so an unprovable clean
    /// verdict would otherwise serve bytes nothing on this node can vouch for.
    #[test]
    fn unknown_version_is_not_reusable_for_clean_under_fail_closed() {
        let now = Utc::now();
        let scanned = now - Duration::days(1); // well within TTL
        let cases = [
            (None, Some("grype-0.84.0")), // live probe known, legacy row
            (Some("grype-0.84.0"), None), // stored known, probe failed
            (None, None),                 // neither known
        ];
        for (stored, current) in cases {
            assert!(
                verdict_is_fresh(scanned, stored, current, 30, now),
                "precondition: the policy-free check still fails open"
            );
            assert!(
                !verdict_is_reusable(
                    VERDICT_CLEAN,
                    scanned,
                    stored,
                    current,
                    ProxyScanAction::FailClosed,
                    30,
                    now
                ),
                "fail-closed + clean + unprovable provenance ({stored:?}/{current:?}) \
                 must re-scan, never serve from cache"
            );
            // Fail-open is unchanged: its re-scan branch serves-with-pending
            // anyway, so the TTL-only fallback costs no availability.
            assert!(verdict_is_reusable(
                VERDICT_CLEAN,
                scanned,
                stored,
                current,
                ProxyScanAction::FailOpen,
                30,
                now
            ));
            // Non-clean verdicts keep their existing handling under both
            // actions: a cached `vulnerable` row must still short-circuit to
            // the block path rather than being re-fetched/re-scanned.
            assert!(verdict_is_reusable(
                VERDICT_VULNERABLE,
                scanned,
                stored,
                current,
                ProxyScanAction::FailClosed,
                30,
                now
            ));
        }
    }

    /// The working paths are untouched: a PROVEN version match is reusable
    /// under both actions, a proven mismatch is not, and an expired TTL is
    /// never reusable regardless of provenance.
    #[test]
    fn reusable_matches_fresh_when_both_versions_known() {
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        for action in [ProxyScanAction::FailClosed, ProxyScanAction::FailOpen] {
            assert!(verdict_is_reusable(
                VERDICT_CLEAN,
                scanned,
                Some("grype-0.83.0"),
                Some("grype-0.83.0"),
                action,
                30,
                now
            ));
            assert!(!verdict_is_reusable(
                VERDICT_CLEAN,
                scanned,
                Some("grype-0.83.0"),
                Some("grype-0.84.0"),
                action,
                30,
                now
            ));
            assert!(!verdict_is_reusable(
                VERDICT_CLEAN,
                now - Duration::days(31),
                Some("grype-0.83.0"),
                Some("grype-0.83.0"),
                action,
                30,
                now
            ));
        }
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

    /// DB-backed round trip: record → lookup → upsert-on-conflict → lookup.
    /// Covers the two sqlx paths (`record_verdict`, `lookup_verdict`) against
    /// the real `proxy_scan_results` schema (unique key + CHECK vocabulary).
    /// Skips cleanly when DATABASE_URL is unset.
    #[tokio::test]
    async fn record_and_lookup_verdict_roundtrip_and_upsert() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = ProxyScanService::new(pool.clone());
        // Unique digest per run so parallel/repeat runs never collide.
        let digest = format!("{:0>64}", uuid::Uuid::new_v4().simple());

        // Missing digest: no row.
        let missing = svc.lookup_verdict(&digest, "grype").await.expect("lookup");
        assert!(missing.is_none(), "unknown digest must have no verdict");

        // First record: clean.
        svc.record_verdict(
            &digest,
            "grype",
            VERDICT_CLEAN,
            0,
            0,
            0,
            0,
            0,
            None,
            Some("grype-0.99.0-test"),
            None,
        )
        .await
        .expect("record clean");
        let row = svc
            .lookup_verdict(&digest, "grype")
            .await
            .expect("lookup")
            .expect("row after record");
        assert_eq!(row.verdict, VERDICT_CLEAN);
        assert_eq!(row.findings_count, 0);
        assert_eq!(row.max_severity, None);
        assert_eq!(row.scanner_version.as_deref(), Some("grype-0.99.0-test"));

        // Re-record the SAME digest (e.g. re-scan against a bumped CVE-DB
        // that now flags it): the upsert must replace, not duplicate/err.
        svc.record_verdict(
            &digest,
            "grype",
            VERDICT_VULNERABLE,
            2,
            1,
            1,
            0,
            0,
            Some("critical"),
            Some("grype-1.0.0-test"),
            None,
        )
        .await
        .expect("upsert vulnerable");
        let row = svc
            .lookup_verdict(&digest, "grype")
            .await
            .expect("lookup")
            .expect("row after upsert");
        assert_eq!(row.verdict, VERDICT_VULNERABLE);
        assert_eq!(row.findings_count, 2);
        assert_eq!(row.critical_count, 1);
        assert_eq!(row.high_count, 1);
        assert_eq!(row.max_severity.as_deref(), Some("critical"));
        assert_eq!(row.scanner_version.as_deref(), Some("grype-1.0.0-test"));
        // A different scan_type is a distinct verdict slot.
        assert!(svc
            .lookup_verdict(&digest, "trivy")
            .await
            .expect("lookup other type")
            .is_none());

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    fn row(
        verdict: &str,
        scanned_at: DateTime<Utc>,
        scanner_version: Option<&str>,
    ) -> ProxyScanRow {
        ProxyScanRow {
            checksum_sha256: "0".repeat(64),
            scan_type: "grype".to_string(),
            verdict: verdict.to_string(),
            findings_count: i32::from(verdict == VERDICT_VULNERABLE),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            max_severity: None,
            scanner_version: scanner_version.map(str::to_string),
            scanned_at,
        }
    }

    /// The serve state machine truth table, single-sourced for every proxy
    /// format: fresh-clean serves, fresh-vulnerable blocks, and every
    /// no-reusable-verdict case forks on the action (fail-closed scans
    /// inline, fail-open serves pending + async scan).
    #[test]
    fn decide_serve_truth_table() {
        let now = Utc::now();
        let fresh = now - Duration::days(1);
        let live = Some("grype-0.84.0");

        // Fresh reusable clean -> serve from cache (both actions).
        for action in [ProxyScanAction::FailClosed, ProxyScanAction::FailOpen] {
            assert_eq!(
                decide_serve(
                    Some(&row(VERDICT_CLEAN, fresh, live)),
                    live,
                    action,
                    30,
                    now
                ),
                ServeDecision::ServeCached
            );
            // Fresh reusable vulnerable -> block from cache, no re-scan.
            assert_eq!(
                decide_serve(
                    Some(&row(VERDICT_VULNERABLE, fresh, live)),
                    live,
                    action,
                    30,
                    now
                ),
                ServeDecision::BlockCached
            );
        }

        // No row at all: first pull of this digest.
        assert_eq!(
            decide_serve(None, live, ProxyScanAction::FailClosed, 30, now),
            ServeDecision::ScanInline
        );
        assert_eq!(
            decide_serve(None, live, ProxyScanAction::FailOpen, 30, now),
            ServeDecision::ServePendingScanAsync
        );

        // Stale rows fall through to the same first-pull fork: past-TTL...
        let expired = now - Duration::days(31);
        assert_eq!(
            decide_serve(
                Some(&row(VERDICT_CLEAN, expired, live)),
                live,
                ProxyScanAction::FailClosed,
                30,
                now
            ),
            ServeDecision::ScanInline
        );
        // ...and a scanner/CVE-DB version bump within the TTL (#2976).
        assert_eq!(
            decide_serve(
                Some(&row(VERDICT_CLEAN, fresh, Some("grype-0.83.0"))),
                live,
                ProxyScanAction::FailClosed,
                30,
                now
            ),
            ServeDecision::ScanInline
        );
        assert_eq!(
            decide_serve(
                Some(&row(VERDICT_CLEAN, fresh, Some("grype-0.83.0"))),
                live,
                ProxyScanAction::FailOpen,
                30,
                now
            ),
            ServeDecision::ServePendingScanAsync
        );
    }

    /// THE #2976 case, pinned at the decision seam every format now shares:
    /// a cached `clean` verdict whose provenance cannot be proven current
    /// (live version probe returned `None`) must NOT short-circuit a
    /// fail-closed repo — the pull re-scans inline. Fail-open keeps the
    /// TTL-only fallback (its re-scan branch serves-with-pending anyway).
    #[test]
    fn decide_serve_probe_none_fail_closed_rescans_clean() {
        let now = Utc::now();
        let fresh = now - Duration::days(1);
        let clean = row(VERDICT_CLEAN, fresh, Some("grype-0.83.0"));

        assert_eq!(
            decide_serve(Some(&clean), None, ProxyScanAction::FailClosed, 30, now),
            ServeDecision::ScanInline,
            "probe-None + fail_closed must re-scan, never serve stale-clean"
        );
        assert_eq!(
            decide_serve(Some(&clean), None, ProxyScanAction::FailOpen, 30, now),
            ServeDecision::ServeCached,
            "fail-open keeps the TTL-only fallback on an unknown live version"
        );
        // A cached vulnerable verdict still blocks even with no live version:
        // never re-fetch/re-scan bytes already known bad.
        let vuln = row(VERDICT_VULNERABLE, fresh, Some("grype-0.83.0"));
        assert_eq!(
            decide_serve(Some(&vuln), None, ProxyScanAction::FailClosed, 30, now),
            ServeDecision::BlockCached
        );
    }

    // -----------------------------------------------------------------
    // Proxy scan visibility (#3348): state mapping + staleness
    // -----------------------------------------------------------------

    #[test]
    fn derive_state_clean_and_vulnerable_have_no_reason() {
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_CLEAN), true),
            (STATE_CLEAN, None)
        );
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_CLEAN), false),
            (STATE_CLEAN, None),
            "a stored clean verdict is reported as clean regardless of the \
             calling repo's current scan_on_proxy setting (verdicts are global)"
        );
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_VULNERABLE), true),
            (STATE_VULNERABLE, None)
        );
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_VULNERABLE), false),
            (STATE_VULNERABLE, None)
        );
    }

    #[test]
    fn derive_state_no_row_scanning_disabled() {
        assert_eq!(
            derive_proxy_scan_state(None, false),
            (
                STATE_NOT_SCANNED,
                Some(NOT_SCANNED_REASON_SCANNING_DISABLED)
            )
        );
    }

    /// The absent-`scan_configs` row case: the caller resolves
    /// `scan_on_proxy` via `is_proxy_scan_enabled`'s `unwrap_or(false)`
    /// BEFORE calling this function, so "no config row ever saved" arrives
    /// here as `scan_on_proxy = false` — identical to an explicit disable —
    /// and must resolve to `scanning_disabled`, matching what the proxy gate
    /// actually does for that repository.
    #[test]
    fn derive_state_absent_config_row_resolves_scanning_disabled() {
        let never_configured_default = false; // is_proxy_scan_enabled().unwrap_or(false)
        assert_eq!(
            derive_proxy_scan_state(None, never_configured_default),
            (
                STATE_NOT_SCANNED,
                Some(NOT_SCANNED_REASON_SCANNING_DISABLED)
            )
        );
    }

    #[test]
    fn derive_state_no_row_scanning_enabled_is_unknown() {
        assert_eq!(
            derive_proxy_scan_state(None, true),
            (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN))
        );
    }

    #[test]
    fn derive_state_unrecognized_verdict_token_folds_to_unknown() {
        // Defensive: VERDICT_ERROR (and anything else unrecognized) has zero
        // production writers but must not panic or invent a fourth state.
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_ERROR), true),
            (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN))
        );
        assert_eq!(
            derive_proxy_scan_state(Some("garbage"), false),
            (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN))
        );
    }

    #[test]
    fn stale_not_scanned_row_is_never_stale() {
        assert!(!is_proxy_scan_stale(None, 30, Utc::now()));
    }

    #[test]
    fn stale_age_based_boundary() {
        let now = Utc::now();
        // Well within the TTL: fresh.
        assert!(!is_proxy_scan_stale(Some(now - Duration::days(1)), 30, now));
        // Well past the TTL: stale.
        assert!(is_proxy_scan_stale(Some(now - Duration::days(31)), 30, now));
        // Exact boundary (`scanned_at == now - ttl_days`): the formula is a
        // strict `<`, so equality is NOT stale. Pick a side, per the design
        // doc, matching the serve-path gate's strict `now < scanned_at + ttl`.
        assert!(!is_proxy_scan_stale(
            Some(now - Duration::days(30)),
            30,
            now
        ));
        // One nanosecond past the boundary: stale.
        assert!(is_proxy_scan_stale(
            Some(now - Duration::days(30) - Duration::nanoseconds(1)),
            30,
            now
        ));
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
