//! Shared scan-state classification for promotion gating.
//!
//! Both promotion paths must agree on whether an artifact is "scanned" before
//! it may be promoted:
//!
//! * the **manual / policy** path ([`super::promotion_policy_service`]) enforces
//!   the `block_unscanned` gate (#1643), and
//! * the **auto-promotion / rule** path ([`super::promotion_rule_service`])
//!   evaluates `max_cve_severity` rules.
//!
//! Previously each path classified scan state on its own, and the rule path
//! failed open: a `max_cve_severity` rule with no completed scan skipped the CVE
//! check and auto-promoted the artifact. Hoisting the classifier here lets both
//! paths share one table-tested definition of "unscanned" and deny by default.

/// Terminal status persisted (#1470) when a scanner reports
/// `is_applicable() == false` for an artifact (see
/// `scanner_service::scan_artifact_inner`). A `not_applicable` row means the
/// scanner genuinely does not apply to the artifact's format; it is NOT a
/// failure and must NOT be treated as fail-open/unscanned for promotion gating.
const NOT_APPLICABLE_STATUS: &str = "not_applicable";

/// Sentinel substring written into `scan_results.error_message` on the legacy
/// (pre-#1470) "does not apply" path, where the row was stored as
/// `status = 'failed'` with this phrase in `error_message`. We still recognize
/// it so historical rows persisted before migration 124 keep classifying as
/// "not applicable" rather than as genuine crashes.
pub(crate) const NOT_APPLICABLE_MARKER: &str = "does not apply";

/// All `scan_results` statuses for an artifact, used to classify scan state.
pub(crate) const SCAN_STATE_SQL: &str = r#"
    SELECT status, error_message
    FROM scan_results
    WHERE artifact_id = $1
"#;

/// One `scan_results` row reduced to the only fields that matter for deciding
/// whether an artifact is "scanned" for gating: its status and whether the row
/// is a "not applicable" marker (a `failed` row whose `error_message` says the
/// scanner does not apply to this format).
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct ScanStateRow {
    pub(crate) status: String,
    pub(crate) error_message: Option<String>,
}

impl ScanStateRow {
    /// A row is "not applicable" (the scanner does not apply to this format,
    /// rather than a genuine crash) when:
    ///
    /// * its status is the dedicated `not_applicable` terminal status (#1470,
    ///   the canonical path for rows persisted from migration 124 onward), or
    /// * (legacy) its status is `failed` and its error message carries the
    ///   [`NOT_APPLICABLE_MARKER`] sentinel — historical rows written before the
    ///   dedicated status existed.
    fn is_not_applicable(&self) -> bool {
        if self.status == NOT_APPLICABLE_STATUS {
            return true;
        }
        self.status == "failed"
            && self
                .error_message
                .as_deref()
                .map(|m| m.contains(NOT_APPLICABLE_MARKER))
                .unwrap_or(false)
    }
}

/// Classification of an artifact's overall scan state for promotion gating.
///
/// Derived from the full set of `scan_results` rows (not just the latest), so a
/// recent dependency scan does not mask the fact that a malware scan never
/// completed. The ordering of the checks encodes precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanState {
    /// At least one scan completed. The artifact is vetted; CVE/threshold gates
    /// (which read the latest completed scan) take over from here.
    Completed,
    /// No completed scan, but at least one scan is still pending/running. The
    /// artifact is mid-vetting and must not be promoted as if it were clean.
    InProgress,
    /// No completed scan and at least one scanner crashed/errored (a `failed`
    /// row that is NOT a "not applicable" marker).
    Failed,
    /// No `scan_results` rows at all -- the artifact was never scanned.
    NeverScanned,
    /// Scans exist but every one is a "not applicable" marker: no applicable
    /// scanner produced a result. Scanning genuinely does not apply to this
    /// artifact's format, so this is treated as scanned-OK (pass), never block.
    NotApplicable,
}

impl ScanState {
    /// True when the artifact is "genuinely unscanned" for gating purposes:
    /// no completed scan exists and the reason is not "scanning does not apply".
    /// [`ScanState::NotApplicable`] and [`ScanState::Completed`] both return
    /// false (they must never be blocked by the `block_unscanned` gate).
    pub(crate) fn is_unscanned(self) -> bool {
        matches!(
            self,
            ScanState::InProgress | ScanState::Failed | ScanState::NeverScanned
        )
    }

    /// A short, stable token describing the unscanned reason, for the violation
    /// detail payload and the allowed-unscanned WARN log.
    pub(crate) fn reason_token(self) -> &'static str {
        match self {
            ScanState::Completed => "completed",
            ScanState::InProgress => "scan_in_progress",
            ScanState::Failed => "scan_failed",
            ScanState::NeverScanned => "never_scanned",
            ScanState::NotApplicable => "not_applicable",
        }
    }
}

/// Classify an artifact's scan state from the full set of its `scan_results`
/// rows. Pure (no DB) so the precedence rules are unit-testable.
///
/// Precedence: any completed scan -> `Completed`; else any in-progress
/// (pending/running) -> `InProgress`; else any genuine failure -> `Failed`;
/// else if rows exist and they are all "not applicable" markers ->
/// `NotApplicable`; else (no rows) -> `NeverScanned`.
pub(crate) fn classify_scan_state(rows: &[ScanStateRow]) -> ScanState {
    if rows.iter().any(|r| r.status == "completed") {
        return ScanState::Completed;
    }
    if rows
        .iter()
        .any(|r| r.status == "pending" || r.status == "running")
    {
        return ScanState::InProgress;
    }
    // Remaining rows are terminal-but-not-completed: either genuine failures or
    // "not applicable" rows (the dedicated `not_applicable` status from #1470,
    // or a legacy `failed` row carrying the does-not-apply marker). A genuine
    // failure outranks not-applicable because a crashed scanner means the
    // artifact is NOT vetted.
    let has_genuine_failure = rows
        .iter()
        .any(|r| r.status == "failed" && !r.is_not_applicable());
    if has_genuine_failure {
        return ScanState::Failed;
    }
    if rows.is_empty() {
        return ScanState::NeverScanned;
    }
    // Rows exist, none completed, none in-progress, none a genuine failure ->
    // every row is "not applicable".
    ScanState::NotApplicable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, error_message: Option<&str>) -> ScanStateRow {
        ScanStateRow {
            status: status.to_string(),
            error_message: error_message.map(|s| s.to_string()),
        }
    }

    fn not_applicable_row() -> ScanStateRow {
        row(
            "failed",
            Some("Scanner ImageScanner does not apply to this artifact format"),
        )
    }

    #[test]
    fn test_is_not_applicable_marker_detected() {
        assert!(not_applicable_row().is_not_applicable());
    }

    #[test]
    fn test_is_not_applicable_genuine_failure_is_not_marker() {
        // A failed row whose message is a real crash must NOT read as
        // not-applicable -- otherwise a crashed scanner would silently pass.
        assert!(!row("failed", Some("scanner timed out after 300s")).is_not_applicable());
        assert!(!row("failed", None).is_not_applicable());
    }

    #[test]
    fn test_is_not_applicable_requires_failed_status() {
        // Only `failed` rows carry the not-applicable marker; a completed or
        // running row is never a marker regardless of message contents.
        assert!(!row("completed", Some("does not apply")).is_not_applicable());
        assert!(!row("running", Some("does not apply")).is_not_applicable());
    }

    #[test]
    fn test_classify_never_scanned_when_no_rows() {
        assert_eq!(classify_scan_state(&[]), ScanState::NeverScanned);
    }

    #[test]
    fn test_classify_completed_wins() {
        // Any completed scan means the artifact is vetted, even alongside a
        // failed or in-progress scan of another type.
        let rows = vec![
            row("failed", Some("crashed")),
            row("completed", None),
            row("running", None),
        ];
        assert_eq!(classify_scan_state(&rows), ScanState::Completed);
    }

    #[test]
    fn test_classify_in_progress_when_no_completed() {
        assert_eq!(
            classify_scan_state(&[row("pending", None)]),
            ScanState::InProgress
        );
        assert_eq!(
            classify_scan_state(&[row("running", None)]),
            ScanState::InProgress
        );
        // In-progress outranks a genuine failure of another scan type.
        let rows = vec![row("failed", Some("crashed")), row("running", None)];
        assert_eq!(classify_scan_state(&rows), ScanState::InProgress);
    }

    #[test]
    fn test_classify_failed_genuine_crash() {
        assert_eq!(
            classify_scan_state(&[row("failed", Some("scanner crashed"))]),
            ScanState::Failed
        );
    }

    #[test]
    fn test_classify_genuine_failure_outranks_not_applicable() {
        // One scanner did not apply, another genuinely crashed: the artifact is
        // NOT vetted, so the state must be Failed (unscanned), not NotApplicable.
        let rows = vec![not_applicable_row(), row("failed", Some("OOM killed"))];
        assert_eq!(classify_scan_state(&rows), ScanState::Failed);
    }

    #[test]
    fn test_classify_not_applicable_when_all_rows_are_markers() {
        let rows = vec![not_applicable_row(), not_applicable_row()];
        assert_eq!(classify_scan_state(&rows), ScanState::NotApplicable);
    }

    /// #1470: a row carrying the dedicated `not_applicable` status (no error
    /// message text required) is recognized as not-applicable, just like the
    /// legacy `failed` + marker rows.
    #[test]
    fn test_is_not_applicable_dedicated_status() {
        assert!(row("not_applicable", None).is_not_applicable());
        assert!(row("not_applicable", Some("does not apply")).is_not_applicable());
    }

    /// #1470: an artifact whose every scan is the dedicated `not_applicable`
    /// status classifies as NotApplicable (scanned-OK), NOT Failed and NOT
    /// unscanned. This is the regression guard that such scans no longer block
    /// promotion under block_unscanned.
    #[test]
    fn test_classify_not_applicable_dedicated_status_rows() {
        let rows = vec![
            row("not_applicable", Some("Scanner Grype does not apply")),
            row(
                "not_applicable",
                Some("Scanner ImageScanner does not apply"),
            ),
        ];
        assert_eq!(classify_scan_state(&rows), ScanState::NotApplicable);
    }

    /// #1470: the dedicated status and the legacy marker can coexist (mixed
    /// historical + fresh rows) and still classify as NotApplicable.
    #[test]
    fn test_classify_mixed_dedicated_and_legacy_not_applicable() {
        let rows = vec![row("not_applicable", None), not_applicable_row()];
        assert_eq!(classify_scan_state(&rows), ScanState::NotApplicable);
    }

    /// #1470: a genuine crash still outranks a dedicated `not_applicable` row,
    /// so a half-vetted artifact is never silently passed.
    #[test]
    fn test_classify_genuine_failure_outranks_dedicated_not_applicable() {
        let rows = vec![
            row("not_applicable", None),
            row("failed", Some("OOM killed")),
        ];
        assert_eq!(classify_scan_state(&rows), ScanState::Failed);
    }

    #[test]
    fn test_is_unscanned_matrix() {
        // The gate must fire for these three states...
        assert!(ScanState::NeverScanned.is_unscanned());
        assert!(ScanState::InProgress.is_unscanned());
        assert!(ScanState::Failed.is_unscanned());
        // ...and must NOT fire for these two (they pass).
        assert!(!ScanState::Completed.is_unscanned());
        assert!(!ScanState::NotApplicable.is_unscanned());
    }

    #[test]
    fn test_reason_token_stable_values() {
        assert_eq!(ScanState::Completed.reason_token(), "completed");
        assert_eq!(ScanState::InProgress.reason_token(), "scan_in_progress");
        assert_eq!(ScanState::Failed.reason_token(), "scan_failed");
        assert_eq!(ScanState::NeverScanned.reason_token(), "never_scanned");
        assert_eq!(ScanState::NotApplicable.reason_token(), "not_applicable");
    }

    #[test]
    fn test_marker_constant_matches_scanner_phrase() {
        // Guards the coupling to scanner_service's "does not apply to this
        // artifact format" message. If that phrasing changes, this and the
        // not-applicable detection must change together.
        assert_eq!(NOT_APPLICABLE_MARKER, "does not apply");
        assert!(not_applicable_row()
            .error_message
            .unwrap()
            .contains(NOT_APPLICABLE_MARKER));
    }
}
