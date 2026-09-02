//! Security scanning models: configs, results, findings, scores, and policies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Type of scan performed on an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    Dependency,
    Image,
    License,
    Malware,
}

/// Current status of a scan execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    /// Terminal status for "this scanner does not apply to the artifact's
    /// format" (#1470). Distinct from `Failed`, which is reserved for a scanner
    /// that started running and crashed / timed out / errored. A
    /// `NotApplicable` scan is a benign terminal state: neither a
    /// pass-with-findings nor a failure, and it must never be treated as an
    /// error when statuses are interpreted (promotion gating, findings display,
    /// "did the scan fail" predicates).
    NotApplicable,
}

/// Severity of a finding. Ordered from most severe to least.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, sqlx::Type,
)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4,
}

impl Severity {
    /// Penalty weight used in security score calculation.
    pub fn penalty_weight(self) -> i32 {
        match self {
            Severity::Critical => 25,
            Severity::High => 10,
            Severity::Medium => 3,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }

    /// Parse from string (case-insensitive).
    ///
    /// Strict: returns `None` for anything it does not recognise. This is the
    /// right parser for an *operator-configured* value (a policy threshold),
    /// where the caller must decide for itself what an unparseable
    /// configuration means. It is NOT the right parser for a severity token
    /// coming off a scanner — use [`Severity::from_scanner_token`] for that,
    /// so the "unrecognised" decision is made in exactly one place (#3243).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "moderate" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" | "informational" | "none" => Some(Severity::Info),
            _ => None,
        }
    }

    /// The bucket an **unrecognised** scanner severity token lands in.
    ///
    /// `High` — the minimal bucket that fails SAFE (#3306). A vulnerability
    /// whose severity a scanner could not classify is an *ungraded*
    /// vulnerability, not a harmless one. Before #3306 this constant sat at
    /// `Info`, the floor every adapter's private fallback used pre-#3294, and
    /// that was a fail-open: `'info'` is in NO `scan_policies.max_severity`
    /// block set at any threshold (`policy_service`), the promotion gate reads
    /// only `critical/high/medium/low` counts, and `Info.penalty_weight() == 0`
    /// — so precisely the findings nobody had triaged yet were invisible to
    /// every severity-aware gate.
    ///
    /// Why `High` and not `Medium`: a `max_severity = 'high'` policy — the
    /// default posture (`scan_configs.severity_threshold DEFAULT 'high'`) —
    /// blocks only `{critical, high}`. A `Medium`-bucketed ungraded finding
    /// would still be served under it, leaving the fail-open intact. `High` is
    /// blocked by `high`/`medium`/`low` policies while staying below
    /// `Critical`, so ungraded findings do not masquerade as known-critical.
    ///
    /// `High` needs no schema change: `'high'` satisfies the CHECK constraints
    /// on `scan_findings.severity`, `scan_configs.severity_threshold`, and
    /// `scan_policies.max_severity` (`migrations/022_security_scanning.sql`),
    /// and the `SeverityThreshold` unions in the web and CLI clients are
    /// untouched — see #3306 for why a distinct `Unknown` variant was
    /// rejected.
    ///
    /// **This constant governs the three scanner ADAPTERS only, and is not the
    /// only unrecognised-severity fallback in the crate.** The OSV/GitHub
    /// advisory ingestion path in `scanner_service::scan_dependencies` has its
    /// own, independent, and *different* one:
    /// `from_str_loose(&advisory_match.severity).unwrap_or(Severity::Medium)`.
    /// The #3306 decision, made explicitly: the advisory fallback stays
    /// independent at `Medium`. Advisory feeds (OSV/GHSA) are a different
    /// producer with a graded vocabulary that rarely emits a truly ungraded
    /// severity, so a neutral guess is defensible there; this constant answers
    /// the different question of what an ungraded SCANNER finding must do at a
    /// configured gate, which is fail closed.
    pub const UNRECOGNIZED_SCANNER_SEVERITY: Severity = Severity::High;

    /// Bucket a severity token **as emitted by a vulnerability scanner**.
    ///
    /// This is the single classification point for every scanner adapter
    /// (Trivy, Grype, OpenSCAP, and everything that funnels through
    /// `convert_trivy_findings`). Before #3294 each adapter carried its own
    /// `unwrap_or(Severity::Info)` / `_ => Severity::Info` fallback, and the
    /// three drifted apart: the OpenSCAP one had no `critical` arm at all, so
    /// a wrapper emitting `critical` had its most severe result downgraded to
    /// `info`, and nothing anywhere recognised Grype's `Negligible` — it
    /// reached the lowest bucket by falling off the end of a match, so nothing
    /// recorded that it was a decision rather than a parse miss.
    ///
    /// Vocabulary handled here on top of [`Severity::from_str_loose`]:
    ///   * `negligible` — Grype's Debian/Ubuntu OVAL feeds (and Harbor) emit
    ///     this for CVEs the distro has triaged as not worth fixing. It is a
    ///     RECOGNISED token that maps to the lowest bucket **on purpose**, not
    ///     a parse miss. Matches Harbor, which documents `negligible` as never
    ///     blocking a pull.
    ///   * anything else, including Trivy's `UNKNOWN` and XCCDF's `unknown`
    ///     (the OpenSCAP default when a rule declares no severity) — bucketed
    ///     at [`Severity::UNRECOGNIZED_SCANNER_SEVERITY`], which is `High` as
    ///     of #3306 so that ungraded findings fail closed at severity gates.
    ///
    /// The token is lowercased but **not trimmed**, matching
    /// `from_str_loose` and therefore every adapter's pre-#3294 behaviour: a
    /// whitespace-padded token classifies as unrecognised and therefore now
    /// fails safe at `High` rather than being quietly graded.
    ///
    /// Total, not `Option`: an ingestion path has no sensible "no answer".
    pub fn from_scanner_token(token: &str) -> Self {
        match token.to_lowercase().as_str() {
            "negligible" => Severity::Info,
            other => Severity::from_str_loose(other).unwrap_or(Self::UNRECOGNIZED_SCANNER_SEVERITY),
        }
    }

    /// Canonical lowercase form, matching the `scan_configs_severity_threshold_check`
    /// database CHECK constraint (`critical|high|medium|low|info`). Use this when
    /// persisting a severity so a normalized value (e.g. "High" -> "high",
    /// "moderate" -> "medium") is what reaches Postgres.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// Returns true if this severity is at or above the given threshold.
    pub fn meets_threshold(self, threshold: Severity) -> bool {
        self <= threshold
    }
}

/// Quarantine status for artifacts fetched via proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum QuarantineStatus {
    Unscanned,
    Clean,
    Flagged,
}

/// Security grade derived from numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    pub fn from_score(score: i32) -> Self {
        match score {
            90.. => Grade::A,
            75..=89 => Grade::B,
            50..=74 => Grade::C,
            25..=49 => Grade::D,
            _ => Grade::F,
        }
    }

    pub fn as_char(self) -> char {
        match self {
            Grade::A => 'A',
            Grade::B => 'B',
            Grade::C => 'C',
            Grade::D => 'D',
            Grade::F => 'F',
        }
    }
}

// ---------------------------------------------------------------------------
// Database row structs
// ---------------------------------------------------------------------------

/// Per-repository scan configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanConfig {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub scan_enabled: bool,
    pub scan_on_upload: bool,
    pub scan_on_proxy: bool,
    /// The explicit per-repo opt-in that makes `severity_threshold` enforced
    /// on the proxy/OCI inline scan gate (#3243 stage 3 / #3246, resolving the
    /// #3144 disposition question by WIRING it). Default `false`: the gate
    /// keeps its historical block-on-any-finding posture. When `true`, a
    /// `vulnerable` verdict blocks only at-or-above `severity_threshold` —
    /// see `ProxySeverityGate`. Hosted-artifact enforcement remains the
    /// separate `scan_policies` table (`PolicyService::evaluate_artifact`).
    pub block_on_policy_violation: bool,
    /// The severity floor the inline proxy scan gate blocks at, LIVE only when
    /// `block_on_policy_violation` is set (#3243 stage 3 / #3246); inert on
    /// the default-`false` opt-out, so the column default (`'high'`) cannot
    /// silently weaken a gate nobody configured.
    pub severity_threshold: String,
    /// #2954: fail-open (default) vs fail-closed action for the inline proxy
    /// scan-on-fetch. `'fail_open'` | `'fail_closed'`.
    pub proxy_scan_action: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ScanConfig {
    /// Parse the severity_threshold field into a Severity enum.
    pub fn threshold(&self) -> Severity {
        Severity::from_str_loose(&self.severity_threshold).unwrap_or(Severity::High)
    }
}

/// A single scan execution record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub scan_type: String,
    pub status: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub scanner_version: Option<String>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// True when this row was synthesized by `copy_scan_results` because
    /// `find_reusable_scan` matched a prior scan with the same checksum.
    /// No scanner was actually invoked; counts and findings were copied.
    pub is_reused: bool,
    /// When `is_reused` is true, the id of the source scan whose results
    /// were copied. None for original (non-reused) scans.
    pub source_scan_id: Option<Uuid>,
}

/// An individual vulnerability finding within a scan.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanFinding {
    pub id: Uuid,
    pub scan_result_id: Uuid,
    pub artifact_id: Uuid,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub cve_id: Option<String>,
    pub affected_component: Option<String>,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,
    pub source: Option<String>,
    pub source_url: Option<String>,
    pub is_acknowledged: bool,
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_reason: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Materialized security score for a repository.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RepoSecurityScore {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub score: i32,
    pub grade: String,
    pub total_findings: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub acknowledged_count: i32,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub calculated_at: DateTime<Utc>,
    /// True when the LATEST applicable scan for some artifact in this repo is
    /// `status='failed'` (a scanner errored) and no newer `completed` scan
    /// supersedes it (#2167). While set, the repo fails closed: the persisted
    /// `grade` is floored to `F` so a scan error can never present as clean.
    /// A repo with zero scan rows is NOT flagged (absence of scans is not a
    /// failure).
    pub has_failed_scan: bool,
}

/// A scan policy that can block downloads based on findings.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanPolicy {
    pub id: Uuid,
    pub name: String,
    pub repository_id: Option<Uuid>,
    pub max_severity: String,
    pub block_unscanned: bool,
    pub block_on_fail: bool,
    pub is_enabled: bool,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    pub require_signature: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Non-persisted types used by the scanner service
// ---------------------------------------------------------------------------

/// A raw finding produced by a scanner before it is persisted.
#[derive(Debug, Clone, Serialize)]
pub struct RawFinding {
    pub severity: Severity,
    pub title: String,
    pub description: Option<String>,
    pub cve_id: Option<String>,
    pub affected_component: Option<String>,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,
    pub source: Option<String>,
    pub source_url: Option<String>,
}

/// A CVE-identified finding retained from an inline proxy scan so it can be
/// persisted into `proxy_scan_findings` and answered back to an operator
/// asking "which CVE blocked my build?" (#3395).
///
/// Deliberately narrower than [`RawFinding`]: only the columns the digest-keyed
/// table stores. `description`, `source` and `source_url` are dropped because
/// they are scanner prose that would bloat a row written on every proxied
/// download, and because none of them identify the vulnerability.
///
/// `cve_id` is non-optional here while it is optional on [`RawFinding`]: a
/// finding a scanner could not attach a CVE id to has nothing to look up, and
/// the table's identity key is the CVE. Such findings are dropped on the way
/// in — they still count toward `findings_count` on the verdict, which is
/// computed from the raw list before this projection runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProxyFinding {
    /// Canonical vulnerability id, e.g. `CVE-2021-44228` or `GHSA-...`.
    pub cve_id: String,
    /// Lowercase severity token (`critical`/`high`/`medium`/`low`/`info`),
    /// matching the tokens stored on `proxy_scan_results.max_severity`.
    pub severity: String,
    /// Component the vulnerability was matched against.
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    /// Version that resolves it, when the scanner reported one — the single
    /// most actionable field for an operator whose build was just blocked.
    pub fixed_version: Option<String>,
    pub title: Option<String>,
}

/// A package observed by a scanner during inventory enumeration, regardless
/// of whether it has any active CVEs. Persisted into `scan_packages` and
/// consumed by SBOM generation so an artifact's component list reflects
/// the full dependency tree, not just the CVE-bearing subset (#903).
///
/// `name` is the bare package identifier (e.g. `"body-parser"`); the
/// scanner-internal context where it was discovered lives in `source_target`
/// (e.g. `"package-lock.json"`, `"requirements.txt"`, `"Java"`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RawPackage {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub license: Option<String>,
    pub source_target: Option<String>,
}

/// Result of a policy evaluation for an artifact download.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyResult {
    pub allowed: bool,
    pub violations: Vec<String>,
}

/// Summary statistics for the security dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardSummary {
    pub repos_with_scanning: i64,
    pub total_scans: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub policy_violations_blocked: i64,
    pub repos_grade_a: i64,
    pub repos_grade_f: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Severity
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // ScanStatus (#1470)
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_status_not_applicable_serializes_snake_case() {
        // The DB CHECK constraint (migration 124) and every status-string
        // consumer use the literal `not_applicable`; the serde wire form must
        // match so API responses round-trip cleanly.
        let json = serde_json::to_string(&ScanStatus::NotApplicable).expect("serialize");
        assert_eq!(json, "\"not_applicable\"");
    }

    #[test]
    fn test_scan_status_not_applicable_round_trips() {
        for status in [
            ScanStatus::Pending,
            ScanStatus::Running,
            ScanStatus::Completed,
            ScanStatus::Failed,
            ScanStatus::NotApplicable,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let back: ScanStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, back);
        }
    }

    #[test]
    fn test_scan_status_not_applicable_is_distinct_from_failed() {
        assert_ne!(ScanStatus::NotApplicable, ScanStatus::Failed);
        assert_ne!(ScanStatus::NotApplicable, ScanStatus::Completed);
    }

    #[test]
    fn test_severity_penalty_weights() {
        assert_eq!(Severity::Critical.penalty_weight(), 25);
        assert_eq!(Severity::High.penalty_weight(), 10);
        assert_eq!(Severity::Medium.penalty_weight(), 3);
        assert_eq!(Severity::Low.penalty_weight(), 1);
        assert_eq!(Severity::Info.penalty_weight(), 0);
    }

    #[test]
    fn test_severity_from_str_loose_standard() {
        assert_eq!(
            Severity::from_str_loose("critical"),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::from_str_loose("high"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("low"), Some(Severity::Low));
        assert_eq!(Severity::from_str_loose("info"), Some(Severity::Info));
    }

    #[test]
    fn test_severity_from_str_loose_aliases() {
        assert_eq!(Severity::from_str_loose("moderate"), Some(Severity::Medium));
        assert_eq!(
            Severity::from_str_loose("informational"),
            Some(Severity::Info)
        );
        assert_eq!(Severity::from_str_loose("none"), Some(Severity::Info));
    }

    #[test]
    fn test_severity_from_str_loose_case_insensitive() {
        assert_eq!(
            Severity::from_str_loose("CRITICAL"),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::from_str_loose("High"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("MEDIUM"), Some(Severity::Medium));
    }

    #[test]
    fn test_severity_from_str_loose_unknown() {
        assert_eq!(Severity::from_str_loose("unknown"), None);
        assert_eq!(Severity::from_str_loose(""), None);
        assert_eq!(Severity::from_str_loose("very-high"), None);
    }

    // -----------------------------------------------------------------------
    // #3294: scanner-token classification.
    //
    // These assert the *classifier*. The test that gates the behaviour change
    // is the adapter-level one (`openscap_scanner`), because the missing
    // `critical` arm lived in that adapter's own private match, not in this
    // function. Expected values are written out literally rather than derived
    // from `from_str_loose` + the constant, so the assertions cannot agree
    // with the implementation by construction.
    //
    // Scope note: #3294 consolidated three per-adapter fallbacks onto this
    // one classifier without moving where an unrecognised token lands; #3306
    // then moved that bucket to `High` so ungraded findings fail closed. The
    // `..._fail_closed_at_high` test below is the deliberate rewrite of the
    // stage-1a pinning test (`..._still_classify_at_the_floor`) that guarded
    // the un-moved behaviour.
    // -----------------------------------------------------------------------

    /// Positive control: every token the strict parser already recognised must
    /// classify to exactly the same bucket it does today, in both cases.
    #[test]
    fn test_from_scanner_token_preserves_every_recognized_token() {
        for (token, expected) in [
            ("critical", Severity::Critical),
            ("CRITICAL", Severity::Critical),
            ("Critical", Severity::Critical),
            ("high", Severity::High),
            ("HIGH", Severity::High),
            ("medium", Severity::Medium),
            ("MEDIUM", Severity::Medium),
            ("moderate", Severity::Medium),
            ("low", Severity::Low),
            ("LOW", Severity::Low),
            ("info", Severity::Info),
            ("informational", Severity::Info),
            ("none", Severity::Info),
        ] {
            assert_eq!(
                Severity::from_scanner_token(token),
                expected,
                "recognized token {token:?} must classify unchanged"
            );
        }
    }

    /// `Negligible` is a token the classifier KNOWS, not one it fails to
    /// parse. Behaviourally it lands where it always did (Info) — it is
    /// Grype's/Harbor's explicit "distro says not worth fixing" grade, not a
    /// parse miss, so it must NOT be swept up to `High` with the genuinely
    /// unrecognised tokens.
    ///
    /// As of #3306 this arm is load-bearing and revert-proved: with
    /// `UNRECOGNIZED_SCANNER_SEVERITY == Severity::High`, deleting
    /// `"negligible" => Severity::Info` would send it to `High` and turn this
    /// test red.
    #[test]
    fn test_negligible_is_recognized_and_maps_to_the_lowest_bucket() {
        for token in ["negligible", "Negligible", "NEGLIGIBLE"] {
            assert_eq!(
                Severity::from_scanner_token(token),
                Severity::Info,
                "{token:?} is Grype's/Harbor's explicit 'not worth fixing' \
                 grade and belongs in the lowest bucket"
            );
        }
    }

    /// #3306: an unrecognised scanner severity token is an UNGRADED finding
    /// and must fail closed at `High` — the minimal bucket a `'high'`
    /// max_severity policy (the default posture) actually blocks. This is the
    /// deliberate rewrite of the stage-1a (#3294) pinning test
    /// `test_unrecognized_tokens_still_classify_at_the_floor`, which pinned
    /// the pre-fix fail-open at `Info` so it could only move on purpose.
    #[test]
    fn test_unrecognized_tokens_fail_closed_at_high() {
        for token in [
            "unknown",
            "UNKNOWN",
            "Unknown",
            "",
            "   ",
            " high ",
            "very-high",
            "sev:9",
            "important",
        ] {
            assert_eq!(
                Severity::from_scanner_token(token),
                Severity::High,
                "unrecognised token {token:?} must fail closed at High — at \
                 Info it is invisible to every severity-aware gate (#3306)"
            );
        }

        // The one-line proof the bucket now blocks a HIGH-threshold gate:
        // true at High, false at Info (Info(4) <= High(1) does not hold).
        assert!(
            Severity::UNRECOGNIZED_SCANNER_SEVERITY.meets_threshold(Severity::High),
            "the unrecognised bucket must meet a `high` threshold, or a \
             HIGH-configured gate still serves ungraded findings"
        );

        // Positive controls in the SAME test. Without these the assertions
        // above are satisfied in full by `from_scanner_token` rewritten as
        // `|_| Severity::High`, which is the exact failure mode this test is
        // supposed to detect. Every graded token must still reach its own
        // bucket — `info` included, so the floor is still reachable by an
        // explicit grade.
        for (token, expected) in [
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
            ("info", Severity::Info),
        ] {
            assert_eq!(
                Severity::from_scanner_token(token),
                expected,
                "graded token {token:?} must still classify as {expected:?} — \
                 the fail-closed assertions above are only meaningful if the \
                 classifier still discriminates"
            );
        }
    }

    #[test]
    fn test_severity_as_str_canonical_lowercase() {
        // as_str() must match the scan_configs_severity_threshold_check set so a
        // normalized value can be persisted safely (#2953).
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::Low.as_str(), "low");
        assert_eq!(Severity::Info.as_str(), "info");
    }

    #[test]
    fn test_severity_as_str_roundtrips_through_from_str_loose() {
        for s in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            assert_eq!(Severity::from_str_loose(s.as_str()), Some(s));
        }
    }

    #[test]
    fn test_severity_meets_threshold() {
        // Critical meets all thresholds
        assert!(Severity::Critical.meets_threshold(Severity::Critical));
        assert!(Severity::Critical.meets_threshold(Severity::High));
        assert!(Severity::Critical.meets_threshold(Severity::Info));

        // High meets High and below but not Critical
        assert!(!Severity::High.meets_threshold(Severity::Critical));
        assert!(Severity::High.meets_threshold(Severity::High));
        assert!(Severity::High.meets_threshold(Severity::Info));

        // Info only meets Info
        assert!(!Severity::Info.meets_threshold(Severity::Critical));
        assert!(!Severity::Info.meets_threshold(Severity::Low));
        assert!(Severity::Info.meets_threshold(Severity::Info));
    }

    #[test]
    fn test_severity_ordering() {
        // Critical < High < Medium < Low < Info (by discriminant values)
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }

    // -----------------------------------------------------------------------
    // Grade
    // -----------------------------------------------------------------------

    #[test]
    fn test_grade_from_score_boundaries() {
        assert_eq!(Grade::from_score(100), Grade::A);
        assert_eq!(Grade::from_score(90), Grade::A);
        assert_eq!(Grade::from_score(89), Grade::B);
        assert_eq!(Grade::from_score(75), Grade::B);
        assert_eq!(Grade::from_score(74), Grade::C);
        assert_eq!(Grade::from_score(50), Grade::C);
        assert_eq!(Grade::from_score(49), Grade::D);
        assert_eq!(Grade::from_score(25), Grade::D);
        assert_eq!(Grade::from_score(24), Grade::F);
        assert_eq!(Grade::from_score(0), Grade::F);
    }

    #[test]
    fn test_grade_from_score_negative() {
        assert_eq!(Grade::from_score(-1), Grade::F);
        assert_eq!(Grade::from_score(-100), Grade::F);
    }

    #[test]
    fn test_grade_from_score_above_100() {
        // Scores > 100 clamp to A via the unbounded 90.. range
        assert_eq!(Grade::from_score(101), Grade::A);
        assert_eq!(Grade::from_score(200), Grade::A);
    }

    #[test]
    fn test_grade_as_char() {
        assert_eq!(Grade::A.as_char(), 'A');
        assert_eq!(Grade::B.as_char(), 'B');
        assert_eq!(Grade::C.as_char(), 'C');
        assert_eq!(Grade::D.as_char(), 'D');
        assert_eq!(Grade::F.as_char(), 'F');
    }

    // -----------------------------------------------------------------------
    // ScanConfig::threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_config_threshold_known() {
        let config = ScanConfig {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            scan_enabled: true,
            scan_on_upload: true,
            scan_on_proxy: false,
            block_on_policy_violation: true,
            severity_threshold: "critical".to_string(),
            proxy_scan_action: "fail_open".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(config.threshold(), Severity::Critical);
    }

    #[test]
    fn test_scan_config_threshold_unknown_defaults_to_high() {
        let config = ScanConfig {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            scan_enabled: true,
            scan_on_upload: false,
            scan_on_proxy: false,
            block_on_policy_violation: false,
            severity_threshold: "garbage".to_string(),
            proxy_scan_action: "fail_open".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(config.threshold(), Severity::High);
    }
}
