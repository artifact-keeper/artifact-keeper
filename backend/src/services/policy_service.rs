//! Service for evaluating and managing security policies.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{
    CondaPolicyPredicates, OriginPolicyPredicates, PolicyPredicates, PolicyResult, ScanPolicy,
    Severity,
};
use crate::services::artifact_origin::{ArtifactOrigin, ALL_KINDS};
use crate::services::scan_state::ScanState;

/// Whether the `block_unscanned` gate should fire for an artifact in the given
/// aggregate scan state (#1649).
///
/// Fires when the policy enables it AND the artifact is "genuinely unscanned"
/// per [`ScanState::is_unscanned`] — i.e. it has no completed scan and the
/// reason is not "scanning does not apply". This deliberately fires on
/// `Failed` / `InProgress` / `NeverScanned`, closing the gap where a `failed`
/// or `pending` scan row used to satisfy the old `latest_scan.is_none()` check
/// and let the artifact bypass the gate. Pure / unit-testable.
fn block_unscanned_violated(block_unscanned: bool, scan_state: ScanState) -> bool {
    block_unscanned && scan_state.is_unscanned()
}

/// Which post-scan gates apply to an artifact, derived from its `scan_results`
/// rows.
#[derive(Debug, PartialEq, Eq)]
struct PostScanGates {
    /// At least one scanner's LATEST row is a genuine failure, so
    /// `block_on_fail` may fire (#3142).
    block_on_fail_applies: bool,
    /// Findings are on record for this artifact, so the `max_severity`
    /// threshold check must run.
    severity_applies: bool,
}

/// Decide which post-scan gates apply from the artifact's scan rows.
///
/// The two gates deliberately read DIFFERENT inputs:
///
/// * `block_on_fail` is about whether any engine's most recent attempt crashed,
///   so it keys on the latest row PER `scan_type` (#3142).
/// * `max_severity` is about the findings on record, so it keys on whether
///   there is anything on record to grade — not on "the newest row happens to
///   be completed".
///
/// #3142: `block_on_fail` used to key on a single `ORDER BY created_at DESC
/// LIMIT 1` across ALL `scan_type`s. With more than one engine enabled that is
/// a fail-open: scanner A crashes and writes `failed`, scanner B then finishes
/// clean, the global newest row reads `completed`, and `block_on_fail` never
/// fires. `classify_scan_state` is any-completed-wins, so `block_unscanned`
/// stays quiet too, and an artifact with a crashed scanner is served as fully
/// vetted with `block_on_fail` explicitly enabled. Keying per `scan_type` means
/// a later clean scan by a DIFFERENT engine can no longer mask engine A's
/// crash, while a genuine `completed` RESCAN by engine A itself still clears
/// it. Mirrors `scan_result_service::recalculate_score`'s `has_failed_scan`
/// window, which already had the right shape.
///
/// Both used to read the single newest row of any status, which made the
/// severity gate silently inert whenever the newest row was not `completed`.
/// Any scanner that records a non-terminal row (`pending`/`running`) or a
/// `not_applicable` row AFTER a completed one — an asynchronous or external
/// scanner does this routinely — therefore disabled severity blocking for that
/// artifact entirely, and a download with critical findings on record was
/// served with a 200. Keying on what is on record closes that fail-open.
///
/// Note the consequence for a `failed` newest row with `block_on_fail` off:
/// severity now still evaluates against the findings of the older completed
/// scan, where it previously skipped the check. That is the intended, strictly
/// safer direction — a crashed rescan must not clear an artifact's history.
///
/// `has_unacknowledged_findings` is the second half of that same argument.
/// Findings are persisted BEFORE the scan row is flipped to `completed`
/// (`scanner_service` calls `create_findings` and only then `complete_scan`),
/// so a scanner that dies in between — or is later reaped from `running` to
/// `failed` by the stuck-scan janitor — leaves unacknowledged findings on
/// record with NO completed row anywhere. Keying the gate on `completed`
/// alone would leave exactly the reported fail-open one layer down: an
/// unacknowledged critical on record, served 200. Grading whenever there is
/// something to grade cannot produce a false block, because the threshold
/// query returns zero when no finding meets the policy's severity.
/// Pure / unit-testable.
fn post_scan_gates(
    any_scanner_failed: bool,
    has_completed_scan: bool,
    has_unacknowledged_findings: bool,
) -> PostScanGates {
    PostScanGates {
        block_on_fail_applies: any_scanner_failed,
        severity_applies: has_completed_scan || has_unacknowledged_findings,
    }
}

/// Allowed values for `scan_policies.max_severity`, mirroring the DB CHECK
/// constraint in `migrations/022_security_scanning.sql`.
///
/// Note the set deliberately excludes `info` even though the scanner-side
/// [`Severity`] enum has an `Info` variant: `max_severity` is a blocking
/// threshold, and gating downloads on purely informational findings is never
/// a meaningful policy, so the schema never allowed it.
pub const ALLOWED_MAX_SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// Normalize and validate a client-supplied `max_severity` value (#2320).
///
/// Case-insensitive: `"Critical"` / `"HIGH"` are accepted and canonicalized
/// to lowercase so they satisfy the DB CHECK constraint. Anything outside the
/// allowed set returns [`AppError::Validation`] (400) with an actionable
/// message. Before this existed the raw string went straight into the
/// INSERT/UPDATE and a mis-cased or unknown value surfaced as a
/// CHECK-constraint violation, i.e. an opaque 500 `DATABASE_ERROR`.
fn normalize_max_severity(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if ALLOWED_MAX_SEVERITIES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(AppError::Validation(format!(
            "invalid max_severity '{raw}': must be one of critical, high, medium, low"
        )))
    }
}

/// Decision half of [`PolicyService::ensure_repository_exists`] (#2320): map
/// the `EXISTS` query result onto Ok / 404-NotFound. Split out from the DB
/// query so the contract — a missing FK target must surface as `NotFound`
/// naming the repository id, never a raw FK-violation 500 — is pure and
/// unit-testable.
fn repository_exists_or_not_found(exists: bool, repository_id: Uuid) -> Result<()> {
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound(format!(
            "Repository {repository_id} not found"
        )))
    }
}

// ---------------------------------------------------------------------------
// Conda policy predicates (#4058)
// ---------------------------------------------------------------------------

/// Severity tokens the install-script analyzer persists in
/// `package_install_scripts.findings[].severity`, ordered low to high. They
/// mirror `conda_scripts::ScriptSeverity` — which has no `critical` variant —
/// so this is deliberately NOT [`ALLOWED_MAX_SEVERITIES`].
const SCRIPT_SEVERITY_NAMES: [&str; 4] = ["info", "low", "medium", "high"];

/// Ordered rank of a persisted script-finding severity token. Unknown tokens
/// return `None`; the SQL that computes the artifact's max rank maps anything
/// unrecognized to 0 (`info`), failing toward more blocking, never less.
fn script_severity_rank(severity: &str) -> Option<i32> {
    SCRIPT_SEVERITY_NAMES
        .iter()
        .position(|s| *s == severity)
        .map(|p| p as i32)
}

/// Allowed values for `predicates.conda.min_attestation_state`, mirroring the
/// fact vocabulary of the issue: a publish attestation is `absent`,
/// `present`-but-unverified, or `verified`.
const ALLOWED_MIN_ATTESTATION_STATES: [&str; 2] = ["present", "verified"];

/// The artifact's attestation fact, folded from the strongest-to-weakest
/// `curation_packages.attestation_state` record for the artifact's
/// (repository, name, version).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum CondaAttestationFact {
    /// No attestation record exists for this package at all.
    #[default]
    Absent,
    /// A record exists but is `unverified` or `failed`.
    PresentUnverified,
    /// A record exists and verification passed.
    Verified,
}

/// The conda facts one artifact carries, assembled once per
/// `evaluate_artifact` call and only when an applicable policy actually
/// configures conda predicates (so policy-free repos pay zero extra queries).
#[derive(Debug, Clone, Default)]
struct CondaFacts {
    /// True when the artifact lives in a conda-format repository or carries
    /// conda-format metadata. Conda predicates never fire for other formats.
    is_conda: bool,
    /// Channel of origin: the `channel` qualifier of the identity purl
    /// recorded at ingest (a remote repo's upstream URL, or the owning repo's
    /// key for a hosted upload), falling back to the owning repository's key
    /// for artifacts stored before the identity block existed.
    channel: Option<String>,
    license: Option<String>,
    license_family: Option<String>,
    install_script_count: i64,
    /// Highest severity rank (index into [`SCRIPT_SEVERITY_NAMES`]) across all
    /// script findings. `None` when no finding is on record — including when
    /// scripts exist but were never examined (`findings IS NULL`): unexamined
    /// is not "clean at info", it is simply ungraded here.
    max_script_finding_rank: Option<i32>,
    attestation: CondaAttestationFact,
}

/// Parse the stored `scan_policies.predicates` JSONB document.
///
/// An unparseable document degrades to "no predicates" with an error log —
/// the same defence-in-depth direction as the unknown-`max_severity` fallback
/// — because writes are validated by [`normalize_predicates`] before they are
/// ever persisted, so a corrupt value can only arrive by hand-editing the row.
fn parse_policy_predicates(value: &serde_json::Value) -> PolicyPredicates {
    serde_json::from_value(value.clone()).unwrap_or_else(|e| {
        tracing::error!(
            error = %e,
            "scan_policies.predicates failed to parse; treating the policy as having no predicates"
        );
        PolicyPredicates::default()
    })
}

/// Validate and canonicalize a client-supplied predicate document (#4058),
/// the predicates twin of [`normalize_max_severity`]: list entries are trimmed
/// and lowercased (channel names, license tokens and families all compare
/// case-insensitively), empty entries and unknown enum values are rejected as
/// 400s before any DB round-trip.
fn normalize_predicates(raw: &PolicyPredicates) -> Result<PolicyPredicates> {
    fn normalize_list(field: &str, values: &[String]) -> Result<Vec<String>> {
        values
            .iter()
            .map(|v| {
                let normalized = v.trim().to_ascii_lowercase();
                if normalized.is_empty() {
                    Err(AppError::Validation(format!(
                        "invalid predicates.{field}: entries must be non-empty"
                    )))
                } else {
                    Ok(normalized)
                }
            })
            .collect()
    }

    let conda = &raw.conda;
    let max_script_severity = conda
        .max_install_script_severity
        .as_deref()
        .map(|s| {
            let normalized = s.trim().to_ascii_lowercase();
            if script_severity_rank(&normalized).is_some() {
                Ok(normalized)
            } else {
                Err(AppError::Validation(format!(
                    "invalid predicates.conda.max_install_script_severity '{s}': \
                     must be one of info, low, medium, high"
                )))
            }
        })
        .transpose()?;
    let min_attestation = conda
        .min_attestation_state
        .as_deref()
        .map(|s| {
            let normalized = s.trim().to_ascii_lowercase();
            if ALLOWED_MIN_ATTESTATION_STATES.contains(&normalized.as_str()) {
                Ok(normalized)
            } else {
                Err(AppError::Validation(format!(
                    "invalid predicates.conda.min_attestation_state '{s}': \
                     must be one of present, verified"
                )))
            }
        })
        .transpose()?;

    Ok(PolicyPredicates {
        conda: CondaPolicyPredicates {
            allowed_channels: normalize_list("conda.allowed_channels", &conda.allowed_channels)?,
            denied_channels: normalize_list("conda.denied_channels", &conda.denied_channels)?,
            denied_licenses: normalize_list("conda.denied_licenses", &conda.denied_licenses)?,
            denied_license_families: normalize_list(
                "conda.denied_license_families",
                &conda.denied_license_families,
            )?,
            block_install_scripts: conda.block_install_scripts,
            max_install_script_severity: max_script_severity,
            min_attestation_state: min_attestation,
        },
        origin: normalize_origin_predicates(&raw.origin)?,
    })
}

/// Validate and canonicalize the cross-format origin block (#4050): the
/// same trim/lowercase list treatment as the conda lists (upstream URLs
/// and repository keys compare case-insensitively), plus an enum check on
/// `allowed_kinds` so a misspelled kind is a 400 at write time rather than
/// a policy that silently matches nothing.
fn normalize_origin_predicates(raw: &OriginPolicyPredicates) -> Result<OriginPolicyPredicates> {
    fn normalize_list(field: &str, values: &[String]) -> Result<Vec<String>> {
        values
            .iter()
            .map(|v| {
                let normalized = v.trim().to_ascii_lowercase();
                if normalized.is_empty() {
                    Err(AppError::Validation(format!(
                        "invalid predicates.{field}: entries must be non-empty"
                    )))
                } else {
                    Ok(normalized)
                }
            })
            .collect()
    }

    let allowed_kinds = raw
        .allowed_kinds
        .iter()
        .map(|k| {
            let normalized = k.trim().to_ascii_lowercase();
            if ALL_KINDS.contains(&normalized.as_str()) {
                Ok(normalized)
            } else {
                Err(AppError::Validation(format!(
                    "invalid predicates.origin.allowed_kinds '{k}': \
                     must be one of {}",
                    ALL_KINDS.join(", ")
                )))
            }
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(OriginPolicyPredicates {
        allowed_upstreams: normalize_list("origin.allowed_upstreams", &raw.allowed_upstreams)?,
        denied_upstreams: normalize_list("origin.denied_upstreams", &raw.denied_upstreams)?,
        allowed_repositories: normalize_list(
            "origin.allowed_repositories",
            &raw.allowed_repositories,
        )?,
        denied_repositories: normalize_list(
            "origin.denied_repositories",
            &raw.denied_repositories,
        )?,
        allowed_kinds,
    })
}

/// Percent-decode with malformed sequences passed through literally (the
/// forgiving variant `egress_proxy` already sets precedent for).
fn percent_decode_loose(s: &str) -> String {
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract the `channel` qualifier from a conda purl
/// (`pkg:conda/name@version?build=…&channel=…&subdir=…&type=…`), the same
/// qualifier `CondaPurl::with_channel` writes at ingest. `None` when the purl
/// carries no channel — an honest "origin unknown", which the allowlist
/// predicate fails closed on.
fn channel_from_purl(purl: &str) -> Option<String> {
    let (_, qualifiers) = purl.split_once('?')?;
    for pair in qualifiers.split('&') {
        if let Some(value) = pair.strip_prefix("channel=") {
            let decoded = percent_decode_loose(value);
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
    }
    None
}

/// Evaluate one policy's conda predicates against one artifact's facts (#4058).
///
/// Returns one violation per fired predicate, each tagged with the predicate's
/// stable token (`[conda.channel]`, `[conda.license]`, …) so the decision
/// record — the `PolicyResult.violations` list that callers persist into
/// `quarantine_reason` and audit logs — states WHICH predicate fired, not just
/// that one did. Pure / unit-testable; the DB-facing half is
/// [`PolicyService::load_conda_facts`].
fn evaluate_conda_predicates(
    policy_name: &str,
    preds: &CondaPolicyPredicates,
    facts: &CondaFacts,
) -> Vec<String> {
    let mut violations = Vec::new();
    // Conda predicates are conda-specific: a policy scoped to (or global
    // across) non-conda artifacts must not fire them.
    if preds.is_inert() || !facts.is_conda {
        return violations;
    }

    let channel = facts.channel.as_deref().map(str::to_ascii_lowercase);
    if !preds.allowed_channels.is_empty() {
        match &channel {
            Some(c) if preds.allowed_channels.iter().any(|a| a == c) => {}
            Some(c) => violations.push(format!(
                "Policy '{policy_name}' [conda.channel]: channel of origin '{c}' \
                 is not in the policy's allowed channels"
            )),
            None => violations.push(format!(
                "Policy '{policy_name}' [conda.channel]: channel of origin is unknown \
                 and the policy restricts allowed channels"
            )),
        }
    }
    if let Some(c) = &channel {
        if preds.denied_channels.iter().any(|d| d == c) {
            violations.push(format!(
                "Policy '{policy_name}' [conda.channel]: channel of origin '{c}' is denied"
            ));
        }
    }

    if let Some(license) = facts.license.as_deref().map(str::to_ascii_lowercase) {
        if preds.denied_licenses.iter().any(|d| d == &license) {
            violations.push(format!(
                "Policy '{policy_name}' [conda.license]: declared license '{license}' is denied"
            ));
        }
    }
    if let Some(family) = facts.license_family.as_deref().map(str::to_ascii_lowercase) {
        if preds.denied_license_families.iter().any(|d| d == &family) {
            violations.push(format!(
                "Policy '{policy_name}' [conda.license_family]: declared license family \
                 '{family}' is denied"
            ));
        }
    }

    if preds.block_install_scripts && facts.install_script_count > 0 {
        violations.push(format!(
            "Policy '{policy_name}' [conda.install_scripts]: package carries {} \
             install-time script(s)",
            facts.install_script_count
        ));
    }
    if let Some(threshold) = &preds.max_install_script_severity {
        let threshold_rank = script_severity_rank(threshold).unwrap_or(0);
        if let Some(rank) = facts.max_script_finding_rank {
            if rank >= threshold_rank {
                violations.push(format!(
                    "Policy '{policy_name}' [conda.install_scripts]: install-script finding \
                     severity '{}' meets or exceeds the policy threshold '{threshold}'",
                    SCRIPT_SEVERITY_NAMES[rank.clamp(0, 3) as usize]
                ));
            }
        }
    }

    match preds.min_attestation_state.as_deref() {
        Some("present") if facts.attestation == CondaAttestationFact::Absent => {
            violations.push(format!(
                "Policy '{policy_name}' [conda.attestation]: no publish attestation is on \
                 record, but the policy requires one"
            ));
        }
        Some("verified") if facts.attestation != CondaAttestationFact::Verified => {
            let state = match facts.attestation {
                CondaAttestationFact::Absent => "absent",
                CondaAttestationFact::PresentUnverified => "present but unverified",
                CondaAttestationFact::Verified => unreachable!("guarded by the match arm"),
            };
            violations.push(format!(
                "Policy '{policy_name}' [conda.attestation]: attestation is {state}, but \
                 the policy requires a verified attestation"
            ));
        }
        _ => {}
    }

    violations
}

// ---------------------------------------------------------------------------
// Origin policy predicates (#4050)
// ---------------------------------------------------------------------------

/// The origin facts one artifact carries, read from its immutable
/// `artifacts.origin` record. Unlike [`CondaFacts`] this needs no
/// assembly: origin is a single JSONB column on the artifact row itself,
/// so the load is one PK lookup — and only when an applicable policy
/// configures origin predicates at all.
///
/// All-`None` means "origin unknown" (a missing artifact row or a
/// hand-damaged document), which every allowlist predicate fails closed
/// on — the same posture as the conda channel predicate.
#[derive(Debug, Clone, Default)]
struct OriginFacts {
    kind: Option<String>,
    repository_key: Option<String>,
    upstream_url: Option<String>,
}

/// Evaluate one policy's origin predicates against one artifact's origin
/// facts (#4050). Cross-format: these fire for every artifact, whatever
/// its format, because where the bytes came from is format-independent.
///
/// One violation per fired predicate, tagged with the predicate's stable
/// token (`[origin.upstream]`, `[origin.repository]`, `[origin.kind]`) so
/// the decision record states WHICH predicate fired. Pure / unit-testable;
/// the DB-facing half is [`PolicyService::load_origin_facts`].
fn evaluate_origin_predicates(
    policy_name: &str,
    preds: &OriginPolicyPredicates,
    facts: &OriginFacts,
) -> Vec<String> {
    let mut violations = Vec::new();
    if preds.is_inert() {
        return violations;
    }

    let upstream = facts.upstream_url.as_deref().map(str::to_ascii_lowercase);
    if !preds.allowed_upstreams.is_empty() {
        match &upstream {
            Some(u) if preds.allowed_upstreams.iter().any(|a| a == u) => {}
            Some(u) => violations.push(format!(
                "Policy '{policy_name}' [origin.upstream]: upstream of origin '{u}' \
                 is not in the policy's allowed upstreams"
            )),
            None => violations.push(format!(
                "Policy '{policy_name}' [origin.upstream]: upstream of origin is unknown \
                 and the policy restricts allowed upstreams"
            )),
        }
    }
    if let Some(u) = &upstream {
        if preds.denied_upstreams.iter().any(|d| d == u) {
            violations.push(format!(
                "Policy '{policy_name}' [origin.upstream]: upstream of origin '{u}' is denied"
            ));
        }
    }

    let repository = facts.repository_key.as_deref().map(str::to_ascii_lowercase);
    if !preds.allowed_repositories.is_empty() {
        match &repository {
            Some(r) if preds.allowed_repositories.iter().any(|a| a == r) => {}
            Some(r) => violations.push(format!(
                "Policy '{policy_name}' [origin.repository]: recording repository '{r}' \
                 is not in the policy's allowed repositories"
            )),
            None => violations.push(format!(
                "Policy '{policy_name}' [origin.repository]: recording repository is unknown \
                 and the policy restricts allowed repositories"
            )),
        }
    }
    if let Some(r) = &repository {
        if preds.denied_repositories.iter().any(|d| d == r) {
            violations.push(format!(
                "Policy '{policy_name}' [origin.repository]: recording repository '{r}' is denied"
            ));
        }
    }

    let kind = facts.kind.as_deref().map(str::to_ascii_lowercase);
    if !preds.allowed_kinds.is_empty() {
        match &kind {
            Some(k) if preds.allowed_kinds.iter().any(|a| a == k) => {}
            Some(k) => violations.push(format!(
                "Policy '{policy_name}' [origin.kind]: ingest kind '{k}' \
                 is not in the policy's allowed kinds"
            )),
            None => violations.push(format!(
                "Policy '{policy_name}' [origin.kind]: ingest kind is unknown \
                 and the policy restricts allowed kinds"
            )),
        }
    }

    violations
}

pub struct PolicyService {
    db: PgPool,
}

impl PolicyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Evaluate all applicable policies for an artifact download.
    /// Returns whether the download is allowed and any violation reasons.
    pub async fn evaluate_artifact(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<PolicyResult> {
        // Find applicable policies: repo-specific + global (repository_id IS NULL)
        let policies: Vec<ScanPolicy> = sqlx::query_as(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, predicates, created_at, updated_at
            FROM scan_policies
            WHERE is_enabled = true
              AND (repository_id = $1 OR repository_id IS NULL)
            ORDER BY repository_id NULLS LAST
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if policies.is_empty() {
            return Ok(PolicyResult {
                allowed: true,
                violations: vec![],
            });
        }

        let mut violations = Vec::new();

        // Post-scan gate inputs. `has_completed_scan` is an existence check
        // (drives `max_severity`). See [`post_scan_gates`] for why these gates
        // must not share a single "newest row" lookup.
        #[derive(sqlx::FromRow)]
        struct ScanGateRow {
            has_completed_scan: bool,
            has_unacknowledged_findings: bool,
        }

        let gate_row: ScanGateRow = sqlx::query_as(
            r#"
            SELECT
                EXISTS (
                    SELECT 1
                      FROM scan_results
                     WHERE artifact_id = $1
                       AND status = 'completed'
                ) AS has_completed_scan,
                EXISTS (
                    SELECT 1
                      FROM scan_findings
                     WHERE artifact_id = $1
                       AND NOT is_acknowledged
                ) AS has_unacknowledged_findings
            "#,
        )
        .bind(artifact_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // #3142: `block_on_fail` reads the latest row PER `scan_type`, not one
        // global newest row, so a clean scan by engine B cannot mask engine A's
        // crash. "Not applicable" rows are excluded by `any_scanner_failed`.
        let latest_per_scan_type: Vec<crate::services::scan_state::ScanStateRow> =
            sqlx::query_as(crate::services::scan_state::LATEST_PER_SCAN_TYPE_SQL)
                .bind(artifact_id)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        let gates = post_scan_gates(
            crate::services::scan_state::any_scanner_failed(&latest_per_scan_type),
            gate_row.has_completed_scan,
            gate_row.has_unacknowledged_findings,
        );

        // #1649: classify the artifact's overall scan state from ALL its
        // scan_results rows (the same precedence the promotion gate uses), not
        // just whether the latest row exists. A `failed` / `pending` / `running`
        // scan still means the artifact was never SUCCESSFULLY scanned, so the
        // `block_unscanned` gate must treat it as unscanned. The old
        // `latest_scan.is_none()` check let those slip through whenever any scan
        // row existed, letting a crashed-scanner artifact bypass the gate when
        // `block_on_fail` was off.
        let scan_state_rows: Vec<crate::services::scan_state::ScanStateRow> =
            sqlx::query_as(crate::services::scan_state::SCAN_STATE_SQL)
                .bind(artifact_id)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let scan_state = crate::services::scan_state::classify_scan_state(&scan_state_rows);

        // #4058: load the conda fact set only when at least one applicable
        // policy configures conda predicates — a repo whose policies carry no
        // predicates pays zero extra queries on the download path.
        let conda_facts = if policies
            .iter()
            .any(|p| !parse_policy_predicates(&p.predicates).conda.is_inert())
        {
            Some(self.load_conda_facts(artifact_id).await?)
        } else {
            None
        };

        // #4050: same lazy gating for the cross-format origin facts — one PK
        // lookup of the immutable `artifacts.origin` document, only when an
        // applicable policy configures origin predicates.
        let origin_facts = if policies
            .iter()
            .any(|p| !parse_policy_predicates(&p.predicates).origin.is_inert())
        {
            Some(self.load_origin_facts(artifact_id).await?)
        } else {
            None
        };

        for policy in &policies {
            // Check: block_unscanned
            if block_unscanned_violated(policy.block_unscanned, scan_state) {
                violations.push(format!(
                    "Policy '{}': artifact has not been scanned ({})",
                    policy.name,
                    scan_state.reason_token()
                ));
                continue;
            }

            // Check: block_on_fail
            if policy.block_on_fail && gates.block_on_fail_applies {
                violations.push(format!("Policy '{}': latest scan failed", policy.name));
                continue;
            }

            // Check: max_severity threshold (non-acknowledged findings only)
            if gates.severity_applies {
                let _threshold =
                    Severity::from_str_loose(&policy.max_severity).unwrap_or(Severity::Critical);

                // Count non-acknowledged findings at or above the threshold
                let violating_count: i64 = sqlx::query_scalar(
                    r#"
                    SELECT COUNT(*)
                    FROM scan_findings
                    WHERE artifact_id = $1
                      AND NOT is_acknowledged
                      AND severity IN (
                          SELECT unnest(CASE $2
                              WHEN 'critical' THEN ARRAY['critical']
                              WHEN 'high' THEN ARRAY['critical', 'high']
                              WHEN 'medium' THEN ARRAY['critical', 'high', 'medium']
                              WHEN 'low' THEN ARRAY['critical', 'high', 'medium', 'low']
                              -- No ELSE would yield NULL -> unnest(NULL) -> zero
                              -- rows -> IN (<empty>) is false -> the gate passes
                              -- an artifact it was asked to block. A value
                              -- outside the four is unreachable today
                              -- (scan_policies_max_severity_check), so this is
                              -- defence in depth: an unknown threshold grades
                              -- against every severity rather than none.
                              ELSE ARRAY['critical', 'high', 'medium', 'low']
                          END)
                      )
                    "#,
                )
                .bind(artifact_id)
                .bind(&policy.max_severity)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

                if violating_count > 0 {
                    violations.push(format!(
                        "Policy '{}': {} findings at or above {} severity",
                        policy.name, violating_count, policy.max_severity
                    ));
                }
            }

            // #4058: conda predicates compose with the scan gates above — a
            // policy can carry both, and a violation from either blocks.
            let predicates = parse_policy_predicates(&policy.predicates);
            if let (Some(facts), false) = (&conda_facts, predicates.conda.is_inert()) {
                violations.extend(evaluate_conda_predicates(
                    &policy.name,
                    &predicates.conda,
                    facts,
                ));
            }

            // #4050: cross-format origin predicates compose the same way.
            if let (Some(facts), false) = (&origin_facts, predicates.origin.is_inert()) {
                violations.extend(evaluate_origin_predicates(
                    &policy.name,
                    &predicates.origin,
                    facts,
                ));
            }
        }

        Ok(PolicyResult {
            allowed: violations.is_empty(),
            violations,
        })
    }

    // -----------------------------------------------------------------------
    // Conda fact loading (#4058)
    // -----------------------------------------------------------------------

    /// Assemble the [`CondaFacts`] for one artifact from the three in-tree
    /// sources: `artifact_metadata` (channel / license facts, written at
    /// ingest by `build_conda_metadata`), `package_install_scripts` (migration
    /// 222, install-script presence and analysis findings), and
    /// `curation_packages.attestation_state` (migration 195, CEP-27
    /// verification record).
    ///
    /// The attestation lookup folds possibly-multiple build rows to the
    /// WEAKEST state on record (`failed` < `unverified` < `verified`): a
    /// policy that requires verification must not be satisfied by one verified
    /// build while a sibling build of the same name/version failed.
    async fn load_conda_facts(&self, artifact_id: Uuid) -> Result<CondaFacts> {
        #[derive(sqlx::FromRow)]
        struct ArtifactFactRow {
            repo_format: String,
            repo_key: String,
            meta_format: Option<String>,
            metadata: Option<serde_json::Value>,
        }

        let row: Option<ArtifactFactRow> = sqlx::query_as(
            r#"
            SELECT r.format::text AS repo_format,
                   r.key AS repo_key,
                   m.format AS meta_format,
                   m.metadata AS metadata
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            LEFT JOIN artifact_metadata m ON m.artifact_id = a.id
            WHERE a.id = $1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let Some(row) = row else {
            // Artifact gone between the gate and here: no facts, and
            // `is_conda = false` keeps every predicate quiet — the same no-op
            // posture `enforce_download_gate` takes for a missing artifact row.
            return Ok(CondaFacts::default());
        };

        let is_conda = row.repo_format == "conda" || row.meta_format.as_deref() == Some("conda");

        let metadata = row.metadata.unwrap_or(serde_json::Value::Null);
        let meta_str = |key: &str| {
            metadata
                .get(key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let channel = metadata
            .get(crate::services::conda_identity::IDENTITY_METADATA_KEY)
            .and_then(|doc| doc.get("purl"))
            .and_then(|v| v.as_str())
            .and_then(channel_from_purl)
            // Pre-identity artifacts recorded no channel; what ingest would
            // have written for them is the owning repository's key.
            .or(Some(row.repo_key));

        #[derive(sqlx::FromRow)]
        struct ScriptFactRow {
            script_count: i64,
            max_finding_rank: Option<i32>,
        }
        let scripts: ScriptFactRow = sqlx::query_as(
            r#"
            SELECT COUNT(*) AS script_count,
                   (SELECT MAX(CASE f.value ->> 'severity'
                                 WHEN 'high' THEN 3
                                 WHEN 'medium' THEN 2
                                 WHEN 'low' THEN 1
                                 ELSE 0 END)
                      FROM package_install_scripts s2
                      CROSS JOIN LATERAL jsonb_array_elements(s2.findings) AS f
                     WHERE s2.artifact_id = $1) AS max_finding_rank
            FROM package_install_scripts s
            WHERE s.artifact_id = $1
            "#,
        )
        .bind(artifact_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let attestation_state: Option<String> = sqlx::query_scalar(
            r#"
            SELECT cp.attestation_state
            FROM curation_packages cp
            JOIN artifacts a ON a.id = $1
            WHERE cp.staging_repo_id = a.repository_id
              AND cp.format = 'conda'
              AND cp.package_name = a.name
              AND cp.version = a.version
            ORDER BY CASE cp.attestation_state
                       WHEN 'failed' THEN 0
                       WHEN 'unverified' THEN 1
                       ELSE 2 END
            LIMIT 1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let attestation = match attestation_state.as_deref() {
            None => CondaAttestationFact::Absent,
            Some("verified") => CondaAttestationFact::Verified,
            // 'unverified' and 'failed' are both "present but unverified":
            // the predicate vocabulary distinguishes absence from a record
            // that exists but did not (or did not yet) pass verification.
            Some(_) => CondaAttestationFact::PresentUnverified,
        };

        Ok(CondaFacts {
            is_conda,
            channel,
            license: meta_str("license"),
            license_family: meta_str("license_family"),
            install_script_count: scripts.script_count,
            max_script_finding_rank: scripts.max_finding_rank,
            attestation,
        })
    }

    // -----------------------------------------------------------------------
    // Origin fact loading (#4050)
    // -----------------------------------------------------------------------

    /// Read the artifact's immutable origin record for predicate evaluation.
    /// One PK lookup; a missing row (artifact gone between the gate and here)
    /// or an unparseable document degrades to "origin unknown", which the
    /// allowlist predicates fail closed on — never a panic on the download
    /// path.
    async fn load_origin_facts(&self, artifact_id: Uuid) -> Result<OriginFacts> {
        let origin: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT origin FROM artifacts WHERE id = $1")
                .bind(artifact_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .flatten();

        let Some(origin) = origin.and_then(|v| ArtifactOrigin::from_json(&v)) else {
            return Ok(OriginFacts::default());
        };
        Ok(OriginFacts {
            kind: Some(origin.kind),
            repository_key: Some(origin.repository_key),
            upstream_url: origin.upstream_url,
        })
    }

    // -----------------------------------------------------------------------
    // CRUD
    // -----------------------------------------------------------------------

    /// Verify a repository id points at an existing repository (#2320).
    ///
    /// Scan policies can be scoped to a repository; a stale or mistyped id
    /// used to fall through to the `scan_policies_repository_id_fkey` FK
    /// violation on INSERT and surface as a 500. Checking first lets us
    /// return a proper 404.
    async fn ensure_repository_exists(&self, repository_id: Uuid) -> Result<()> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM repositories WHERE id = $1)")
                .bind(repository_id)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        repository_exists_or_not_found(exists, repository_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_policy(
        &self,
        name: &str,
        repository_id: Option<Uuid>,
        max_severity: &str,
        block_unscanned: bool,
        block_on_fail: bool,
        min_staging_hours: Option<i32>,
        max_artifact_age_days: Option<i32>,
        require_signature: bool,
        predicates: Option<PolicyPredicates>,
    ) -> Result<ScanPolicy> {
        // #2320: validate inputs up front so a bad request comes back as a
        // 4xx instead of tripping the DB CHECK / FK constraint and surfacing
        // as an opaque 500 DATABASE_ERROR.
        let max_severity = normalize_max_severity(max_severity)?;
        // #4058: same up-front validation for the predicate document.
        let predicates = predicates
            .as_ref()
            .map(normalize_predicates)
            .transpose()?
            .map(|p| serde_json::to_value(&p).unwrap_or_else(|_| serde_json::json!({})))
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(repo_id) = repository_id {
            self.ensure_repository_exists(repo_id).await?;
        }

        let policy: ScanPolicy = sqlx::query_as(
            r#"
            INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, block_on_fail,
                                       min_staging_hours, max_artifact_age_days, require_signature, predicates)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, name, repository_id, max_severity, block_unscanned,
                      block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                      require_signature, predicates, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(repository_id)
        .bind(&max_severity)
        .bind(block_unscanned)
        .bind(block_on_fail)
        .bind(min_staging_hours)
        .bind(max_artifact_age_days)
        .bind(require_signature)
        .bind(&predicates)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policy)
    }

    pub async fn list_policies(&self) -> Result<Vec<ScanPolicy>> {
        let policies: Vec<ScanPolicy> = sqlx::query_as(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, predicates, created_at, updated_at
            FROM scan_policies
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policies)
    }

    pub async fn get_policy(&self, id: Uuid) -> Result<ScanPolicy> {
        sqlx::query_as::<_, ScanPolicy>(
            r#"
            SELECT id, name, repository_id, max_severity, block_unscanned,
                   block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                   require_signature, predicates, created_at, updated_at
            FROM scan_policies
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))
    }

    /// Apply a partial update to a scan policy. Any argument left as `None`
    /// keeps the existing column value via `COALESCE`. See #1374 -- previously
    /// the handler took every field as required, which (a) rejected legitimate
    /// PATCH-style PUTs from the release-gate `scan-policy-crud` suite with a
    /// 422 and (b) made it impossible to flip `is_enabled` without resubmitting
    /// the entire policy. A single atomic UPDATE statement preserves multi-
    /// field changes (so `max_severity` and `is_enabled` can both move in the
    /// same request) instead of the prior shape where a partial body might
    /// have only persisted whichever field deserialized first.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_policy(
        &self,
        id: Uuid,
        name: Option<&str>,
        max_severity: Option<&str>,
        block_unscanned: Option<bool>,
        block_on_fail: Option<bool>,
        is_enabled: Option<bool>,
        min_staging_hours: Option<i32>,
        max_artifact_age_days: Option<i32>,
        require_signature: Option<bool>,
        predicates: Option<PolicyPredicates>,
    ) -> Result<ScanPolicy> {
        // #2320: same normalization as create_policy — a mis-cased or unknown
        // max_severity on update used to trip the DB CHECK constraint (500).
        let max_severity = max_severity.map(normalize_max_severity).transpose()?;
        // #4058: predicate document validated before the UPDATE; an omitted
        // field (None) leaves the column untouched via COALESCE, matching
        // every other partial-update field.
        let predicates = predicates
            .as_ref()
            .map(normalize_predicates)
            .transpose()?
            .map(|p| serde_json::to_value(&p).unwrap_or_else(|_| serde_json::json!({})));

        let policy: ScanPolicy = sqlx::query_as(
            r#"
            UPDATE scan_policies
            SET name = COALESCE($2, name),
                max_severity = COALESCE($3, max_severity),
                block_unscanned = COALESCE($4, block_unscanned),
                block_on_fail = COALESCE($5, block_on_fail),
                is_enabled = COALESCE($6, is_enabled),
                min_staging_hours = COALESCE($7, min_staging_hours),
                max_artifact_age_days = COALESCE($8, max_artifact_age_days),
                require_signature = COALESCE($9, require_signature),
                predicates = COALESCE($10, predicates),
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, repository_id, max_severity, block_unscanned,
                      block_on_fail, is_enabled, min_staging_hours, max_artifact_age_days,
                      require_signature, predicates, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(max_severity)
        .bind(block_unscanned)
        .bind(block_on_fail)
        .bind(is_enabled)
        .bind(min_staging_hours)
        .bind(max_artifact_age_days)
        .bind(require_signature)
        .bind(&predicates)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))?;

        Ok(policy)
    }

    pub async fn delete_policy(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM scan_policies WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Policy not found".to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::{PolicyResult, ScanPolicy, Severity};

    // -----------------------------------------------------------------------
    // block_unscanned gate (#1649)
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_unscanned_fires_on_failed_or_in_progress_scan() {
        // #1649 regression: the old `latest_scan.is_none()` check treated ANY
        // scan row (including a crashed `failed` or still-`pending` one) as
        // "scanned", so block_unscanned silently passed an un-vetted artifact
        // whenever block_on_fail happened to be off. The aggregate scan-state
        // classification must instead fire the gate on every non-completed,
        // applicable state.
        assert!(
            block_unscanned_violated(true, ScanState::Failed),
            "a crashed scan must trip block_unscanned"
        );
        assert!(
            block_unscanned_violated(true, ScanState::InProgress),
            "a pending/running scan must trip block_unscanned"
        );
        assert!(
            block_unscanned_violated(true, ScanState::NeverScanned),
            "no scan at all must trip block_unscanned"
        );
    }

    #[test]
    fn test_block_unscanned_passes_completed_and_not_applicable() {
        // A completed scan, or a format to which scanning does not apply, must
        // never be blocked by this gate.
        assert!(!block_unscanned_violated(true, ScanState::Completed));
        assert!(!block_unscanned_violated(true, ScanState::NotApplicable));
    }

    #[test]
    fn test_block_unscanned_disabled_never_fires() {
        for state in [
            ScanState::Failed,
            ScanState::InProgress,
            ScanState::NeverScanned,
            ScanState::Completed,
            ScanState::NotApplicable,
        ] {
            assert!(
                !block_unscanned_violated(false, state),
                "gate disabled -> never a violation regardless of scan state"
            );
        }
    }

    // -----------------------------------------------------------------------
    // post-scan gate inputs (block_on_fail vs max_severity)
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_gate_survives_a_newer_non_completed_scan_row() {
        // Regression: both gates used to read the single newest scan_results row
        // and the severity check ran only `if that_row.status == "completed"`. A
        // scanner that recorded a non-terminal row AFTER a completed one — the
        // normal shape for an asynchronous/external scanner — therefore turned
        // the max_severity download gate off entirely, and an artifact with
        // critical findings on record was served with a 200.
        // No scanner's latest row is a genuine failure, so block_on_fail stays
        // quiet while severity still grades the completed scan's findings.
        let gates = post_scan_gates(false, true, false);
        assert!(
            gates.severity_applies,
            "a newer non-completed row must NOT disable severity blocking while a completed scan exists"
        );
        assert!(
            !gates.block_on_fail_applies,
            "no scanner failed, so block_on_fail must stay quiet"
        );
    }

    #[test]
    fn test_severity_gate_fires_on_findings_without_any_completed_scan() {
        // `scanner_service` persists findings BEFORE flipping the row to
        // `completed`, so a scanner that dies in between (or is reaped from
        // `running` to `failed` by the stuck-scan janitor) leaves
        // unacknowledged findings on record with no completed row anywhere.
        // Keying the gate on `completed` alone reproduces the very fail-open
        // this module is fixing, one layer down: an unacknowledged critical on
        // record, served 200.
        for any_scanner_failed in [false, true] {
            assert!(
                post_scan_gates(any_scanner_failed, false, true).severity_applies,
                "findings on record must be graded even with no completed scan \
                 (any_scanner_failed={any_scanner_failed})"
            );
        }
    }

    #[test]
    fn test_severity_gate_stays_quiet_with_nothing_on_record() {
        // Nothing completed AND nothing on record -> nothing to grade, so the
        // severity gate must not fire. `block_unscanned` is the gate that
        // covers this case.
        for any_scanner_failed in [false, true] {
            assert!(
                !post_scan_gates(any_scanner_failed, false, false).severity_applies,
                "no completed scan and no findings -> severity gate must not fire \
                 (any_scanner_failed={any_scanner_failed})"
            );
        }
    }

    /// #3142: `block_on_fail` keys on whether ANY scanner's latest row failed,
    /// not on a single global newest row.
    ///
    /// This test replaces `test_block_on_fail_keys_on_the_newest_row_only`,
    /// which asserted the defect: it pinned
    /// `!post_scan_gates(Some("completed"), true, false).block_on_fail_applies`
    /// — i.e. "a global newest row of `completed` means block_on_fail must not
    /// fire" — which is exactly the fail-open where a clean scan by engine B
    /// masks engine A's crash. The old test passed both before and after the
    /// bug was introduced, so it could never have caught it.
    ///
    /// The decision now lives in `scan_state::any_scanner_failed`, which is
    /// tested there against the per-`scan_type` row shape; this pins the
    /// remaining wiring in `post_scan_gates`.
    #[test]
    fn test_block_on_fail_fires_when_any_scanner_failed_3142() {
        assert!(
            post_scan_gates(true, false, false).block_on_fail_applies,
            "a failed scanner with no completed scan must trip block_on_fail"
        );

        // A crashed scanner alongside a completed one still trips the gate, and
        // severity ALSO evaluates against the completed scan's findings rather
        // than being skipped. This is the #3142 shape: pre-fix the completed
        // row won the single global newest-row lookup and the gate went quiet.
        let gates = post_scan_gates(true, true, false);
        assert!(
            gates.block_on_fail_applies,
            "a clean scan by another engine must NOT mask a crashed scanner"
        );
        assert!(
            gates.severity_applies,
            "a crashed rescan must not clear an artifact's finding history"
        );

        // Positive control for the inverse: with no failed scanner the gate
        // stays quiet, so the assertions above cannot pass by blocking
        // unconditionally.
        assert!(
            !post_scan_gates(false, true, false).block_on_fail_applies,
            "all scanners healthy -> block_on_fail must not fire"
        );
        assert!(
            !post_scan_gates(false, false, false).block_on_fail_applies,
            "an artifact with no scan rows has nothing to fail"
        );
    }

    // -----------------------------------------------------------------------
    // max_severity normalization (#2320)
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_max_severity_accepts_canonical_values() {
        for value in ALLOWED_MAX_SEVERITIES {
            assert_eq!(
                normalize_max_severity(value).unwrap(),
                value,
                "canonical lowercase value '{value}' must pass through unchanged"
            );
        }
    }

    #[test]
    fn test_normalize_max_severity_canonicalizes_case_and_whitespace() {
        // #2320 regression: "Critical" used to be forwarded verbatim to the
        // INSERT, violate the lowercase CHECK constraint, and surface as a
        // 500 DATABASE_ERROR. It must now normalize cleanly.
        assert_eq!(normalize_max_severity("Critical").unwrap(), "critical");
        assert_eq!(normalize_max_severity("HIGH").unwrap(), "high");
        assert_eq!(normalize_max_severity("  Medium ").unwrap(), "medium");
        assert_eq!(normalize_max_severity("LoW").unwrap(), "low");
    }

    #[test]
    fn test_normalize_max_severity_rejects_unknown_values() {
        // Unknown values must be a Validation error (400), never reach the DB.
        for bad in ["severe", "none", "", "critical; DROP TABLE", "🔥"] {
            match normalize_max_severity(bad) {
                Err(AppError::Validation(msg)) => {
                    assert!(
                        msg.contains("max_severity"),
                        "validation message should name the offending field, got: {msg}"
                    );
                }
                other => {
                    panic!("expected AppError::Validation for max_severity '{bad}', got: {other:?}")
                }
            }
        }
    }

    #[test]
    fn test_normalize_max_severity_rejects_info() {
        // The Severity enum has an Info variant but the scan_policies CHECK
        // constraint deliberately excludes it — a blocking threshold of
        // "info" would gate on purely informational findings. Keep rejecting
        // it here so the API contract matches the schema.
        assert!(matches!(
            normalize_max_severity("info"),
            Err(AppError::Validation(_))
        ));
    }

    // -----------------------------------------------------------------------
    // repository existence pre-check (#2320)
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_exists_or_not_found_accepts_existing_repository() {
        let repo_id = Uuid::new_v4();
        assert!(
            repository_exists_or_not_found(true, repo_id).is_ok(),
            "an existing repository must pass the pre-check"
        );
    }

    #[test]
    fn test_repository_exists_or_not_found_maps_missing_repo_to_not_found() {
        // #2320 regression: a stale/mistyped repository_id used to fall
        // through to the scan_policies_repository_id_fkey violation on
        // INSERT and surface as an opaque 500. The pre-check must turn it
        // into a NotFound (404) that names the offending id.
        let repo_id = Uuid::new_v4();
        match repository_exists_or_not_found(false, repo_id) {
            Err(AppError::NotFound(msg)) => {
                assert!(
                    msg.contains(&repo_id.to_string()),
                    "NotFound message should name the repository id, got: {msg}"
                );
            }
            other => panic!("expected AppError::NotFound for a missing repository, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // create/update entry-point validation ordering (#2320)
    // -----------------------------------------------------------------------

    /// A pool that never opens a connection (and gives up acquiring almost
    /// immediately). Calling a service method with it proves where the DB
    /// boundary sits: anything that returns `Validation` did so BEFORE any
    /// DB round-trip, and anything that returns `Database` got past
    /// validation and genuinely tried to reach the pool.
    fn disconnected_service() -> PolicyService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("connect_lazy should not fail");
        PolicyService::new(pool)
    }

    #[tokio::test]
    async fn test_create_policy_rejects_invalid_max_severity_before_touching_db() {
        let svc = disconnected_service();
        let err = svc
            .create_policy("p", None, "bogus", false, false, None, None, false, None)
            .await
            .unwrap_err();
        // Validation (not Database/PoolTimedOut) proves the reject happened
        // before any DB round-trip — the pool cannot serve a connection.
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn test_create_policy_with_valid_severity_proceeds_to_repository_check() {
        let svc = disconnected_service();
        let err = svc
            .create_policy(
                "p",
                Some(Uuid::new_v4()),
                "Critical",
                false,
                false,
                None,
                None,
                false,
                None,
            )
            .await
            .unwrap_err();
        // The mis-cased-but-known severity normalizes fine, so create must
        // move on to the repository existence pre-check, whose EXISTS query
        // is the first DB touch — surfacing here as a Database error.
        assert!(matches!(err, AppError::Database(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn test_create_policy_unscoped_valid_input_reaches_insert() {
        let svc = disconnected_service();
        let err = svc
            .create_policy("p", None, "high", true, true, Some(1), Some(30), true, None)
            .await
            .unwrap_err();
        // No repository scope: nothing to pre-check, so the INSERT itself is
        // the first DB touch.
        assert!(matches!(err, AppError::Database(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn test_update_policy_rejects_invalid_max_severity_before_touching_db() {
        let svc = disconnected_service();
        let err = svc
            .update_policy(
                Uuid::new_v4(),
                None,
                Some("bogus"),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    // -----------------------------------------------------------------------
    // PolicyResult construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_result_allowed() {
        let result = PolicyResult {
            allowed: true,
            violations: vec![],
        };
        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_policy_result_blocked() {
        let result = PolicyResult {
            allowed: false,
            violations: vec![
                "Policy 'strict': artifact has not been scanned".to_string(),
                "Policy 'no-critical': 3 findings at or above critical severity".to_string(),
            ],
        };
        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 2);
    }

    // -----------------------------------------------------------------------
    // #3142: block_on_fail across multiple scan engines (end-to-end vs Postgres)
    // -----------------------------------------------------------------------

    /// Seed a `scan_results` row. Mirrors the production writers: both
    /// `complete_scan` and `fail_scan` stamp `completed_at`, while
    /// `pending`/`running` rows leave it NULL.
    #[cfg(test)]
    async fn seed_scan_3142(
        pool: &PgPool,
        artifact_id: Uuid,
        repo_id: Uuid,
        scan_type: &str,
        status: &str,
        age_seconds: i64,
    ) {
        sqlx::query(
            r#"
            INSERT INTO scan_results (
                id, artifact_id, repository_id, scan_type, status,
                findings_count, critical_count, high_count, medium_count, low_count, info_count,
                completed_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 0, 0, 0,
                    CASE WHEN $5 IN ('completed', 'failed', 'not_applicable')
                         THEN NOW() - make_interval(secs => $6::double precision)
                    END,
                    NOW() - make_interval(secs => $6::double precision))
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(artifact_id)
        .bind(repo_id)
        .bind(scan_type)
        .bind(status)
        .bind(age_seconds as f64)
        .execute(pool)
        .await
        .expect("insert scan_result");
    }

    /// End-to-end regression test for the `block_on_fail` fail-open (#3142).
    ///
    /// Drives the real `evaluate_artifact` against Postgres, because the bug
    /// lived in the SQL that feeds the gate, not in the pure helper — the
    /// pre-existing pure tests passed with the defect in place.
    ///
    /// Shape: scanner A (`dependency`) crashes, scanner B (`grype`) then completes
    /// clean. Pre-fix the single `ORDER BY created_at DESC LIMIT 1` across all
    /// scan_types read `completed`, `block_on_fail` never fired, and because
    /// `classify_scan_state` is any-completed-wins `block_unscanned` stayed
    /// quiet too — the artifact was served as fully vetted.
    #[tokio::test]
    async fn test_block_on_fail_spans_all_scanners_3142() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };

        // block_unscanned OFF and max_severity at 'critical' with zero findings
        // anywhere, so block_on_fail is provably the ONLY gate that can block.
        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'critical', false, true, true)",
        )
        .bind(format!("gate-3142-{}", fx.repo_id))
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("insert block_on_fail policy");

        let svc = PolicyService::new(fx.pool.clone());

        // (1) THE BUG: `dependency` crashed, `grype` then completed clean and newer.
        let masked = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/masked/1.0/masked-1.0.jar",
            "com/example/masked/1.0/masked-1.0.jar",
            "masked",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(&fx.pool, masked, fx.repo_id, "dependency", "failed", 3600).await;
        seed_scan_3142(&fx.pool, masked, fx.repo_id, "grype", "completed", 60).await;
        let masked_result = svc.evaluate_artifact(masked, fx.repo_id).await;

        // (2) Positive control that the gate works at all: only a failed row.
        let lone_fail = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/lonefail/1.0/lonefail-1.0.jar",
            "com/example/lonefail/1.0/lonefail-1.0.jar",
            "lonefail",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(
            &fx.pool,
            lone_fail,
            fx.repo_id,
            "dependency",
            "failed",
            3600,
        )
        .await;
        let lone_fail_result = svc.evaluate_artifact(lone_fail, fx.repo_id).await;

        // (3) Negative control — must NOT over-block: both engines clean.
        let clean = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/clean/1.0/clean-1.0.jar",
            "com/example/clean/1.0/clean-1.0.jar",
            "clean",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(&fx.pool, clean, fx.repo_id, "dependency", "completed", 3600).await;
        seed_scan_3142(&fx.pool, clean, fx.repo_id, "grype", "completed", 60).await;
        let clean_result = svc.evaluate_artifact(clean, fx.repo_id).await;

        // (4) Negative control — a genuine RESCAN by the SAME engine that
        // succeeds must still clear the earlier failure. This is what keys the
        // window per scan_type rather than simply "any failed row ever".
        let rescanned = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/rescan/1.0/rescan-1.0.jar",
            "com/example/rescan/1.0/rescan-1.0.jar",
            "rescan",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(
            &fx.pool,
            rescanned,
            fx.repo_id,
            "dependency",
            "failed",
            3600,
        )
        .await;
        seed_scan_3142(
            &fx.pool,
            rescanned,
            fx.repo_id,
            "dependency",
            "completed",
            60,
        )
        .await;
        let rescanned_result = svc.evaluate_artifact(rescanned, fx.repo_id).await;

        // (5) Negative control — a scanner that does not apply to the format is
        // not a crash. Without the `is_not_applicable` exclusion, widening the
        // gate to "any scanner" would block every artifact in every repo where
        // an enabled engine simply does not apply.
        let na = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/na/1.0/na-1.0.jar",
            "com/example/na/1.0/na-1.0.jar",
            "na",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scan_3142(&fx.pool, na, fx.repo_id, "dependency", "completed", 3600).await;
        seed_scan_3142(&fx.pool, na, fx.repo_id, "openscap", "not_applicable", 60).await;
        let na_result = svc.evaluate_artifact(na, fx.repo_id).await;

        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        let masked_result = masked_result.expect("evaluate masked");
        assert!(
            !masked_result.allowed,
            "#3142: a crashed `dependency` scan masked by a later clean `grype` scan must still \
             trip block_on_fail, got allowed={} violations={:?}",
            masked_result.allowed, masked_result.violations
        );

        let lone_fail_result = lone_fail_result.expect("evaluate lone_fail");
        assert!(
            !lone_fail_result.allowed,
            "positive control: a lone failed scan must trip block_on_fail"
        );

        let clean_result = clean_result.expect("evaluate clean");
        assert!(
            clean_result.allowed,
            "negative control: two clean scans must download, got violations={:?}",
            clean_result.violations
        );

        let rescanned_result = rescanned_result.expect("evaluate rescanned");
        assert!(
            rescanned_result.allowed,
            "negative control: a successful rescan by the SAME engine must clear its earlier \
             failure, got violations={:?}",
            rescanned_result.violations
        );

        let na_result = na_result.expect("evaluate not-applicable");
        assert!(
            na_result.allowed,
            "negative control: a scanner that does not apply to the format is not a crash, \
             got violations={:?}",
            na_result.violations
        );
    }

    // -----------------------------------------------------------------------
    // #3306: ungraded scanner severities must fail closed at the max_severity
    // gate (end-to-end vs Postgres)
    // -----------------------------------------------------------------------

    /// Persist findings for `artifact_id` through the REAL classification
    /// path: a Trivy-shaped report carrying `severity_token` runs through
    /// `convert_trivy_findings`, and `scan_findings.severity` is written from
    /// the resulting `RawFinding.severity` — exactly as the scan pipeline
    /// writes it. Also seeds the completed `scan_results` row the severity
    /// gate keys on. Returns nothing; the caller asserts via
    /// `evaluate_artifact`.
    #[cfg(test)]
    async fn seed_scanned_finding_3306(
        pool: &PgPool,
        artifact_id: Uuid,
        repo_id: Uuid,
        severity_token: &str,
    ) {
        let report = crate::services::image_scanner::TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "registry/app:latest".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "debian".to_string(),
                vulnerabilities: Some(vec![crate::services::image_scanner::TrivyVulnerability {
                    vulnerability_id: format!("CVE-2026-3306-{severity_token}"),
                    pkg_name: "libexample".to_string(),
                    installed_version: "1.0.0".to_string(),
                    fixed_version: None,
                    severity: severity_token.to_string(),
                    title: None,
                    description: None,
                    primary_url: None,
                }]),
                packages: None,
            }],
        };
        let findings =
            crate::services::scanner_service::convert_trivy_findings(&report, "trivy-image");
        assert_eq!(findings.len(), 1, "fixture must yield exactly one finding");

        let scan_result_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO scan_results (
                id, artifact_id, repository_id, scan_type, status,
                findings_count, critical_count, high_count, medium_count, low_count, info_count,
                completed_at, created_at
            )
            VALUES ($1, $2, $3, 'image', 'completed', 1, 0, 0, 0, 0, 0, NOW(), NOW())
            RETURNING id
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(artifact_id)
        .bind(repo_id)
        .fetch_one(pool)
        .await
        .expect("insert completed scan_results row");

        for finding in &findings {
            sqlx::query(
                "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(scan_result_id)
            .bind(artifact_id)
            .bind(finding.severity.as_str())
            .bind(&finding.title)
            .execute(pool)
            .await
            .expect("insert scan_finding through the classified severity");
        }
    }

    /// End-to-end regression test for the ungraded-severity fail-open
    /// (#3306), driven through the real classifier AND the real gate SQL.
    ///
    /// A Trivy `UNKNOWN` finding — a CVE nobody has graded yet — used to
    /// persist as `severity='info'`, which is in NO `max_severity` block set
    /// at any threshold, so a `'high'` policy served it. With
    /// `UNRECOGNIZED_SCANNER_SEVERITY` at `High` it persists as `'high'` and
    /// the same policy blocks it. Pre-fix this test reds: `allowed == true`
    /// with zero violations.
    #[tokio::test]
    async fn test_ungraded_finding_blocked_by_high_policy_3306() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };

        // block_unscanned/block_on_fail OFF so max_severity is provably the
        // only gate that can block.
        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'high', false, false, true)",
        )
        .bind(format!("gate-3306-{}", fx.repo_id))
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("insert max_severity='high' policy");

        let svc = PolicyService::new(fx.pool.clone());

        // (1) THE BUG: an ungraded (UNKNOWN) finding under a 'high' policy.
        let ungraded = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/ungraded/1.0/ungraded-1.0.jar",
            "com/example/ungraded/1.0/ungraded-1.0.jar",
            "ungraded",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scanned_finding_3306(&fx.pool, ungraded, fx.repo_id, "UNKNOWN").await;
        let ungraded_result = svc.evaluate_artifact(ungraded, fx.repo_id).await;

        // (2) Positive control — must NOT over-block: a graded 'low' finding
        // under the same 'high' policy stays allowed.
        let low = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "com/example/lowgraded/1.0/lowgraded-1.0.jar",
            "com/example/lowgraded/1.0/lowgraded-1.0.jar",
            "lowgraded",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        seed_scanned_finding_3306(&fx.pool, low, fx.repo_id, "LOW").await;
        let low_result = svc.evaluate_artifact(low, fx.repo_id).await;

        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        let ungraded_result = ungraded_result.expect("evaluate ungraded");
        assert!(
            !ungraded_result.allowed,
            "#3306: an ungraded (UNKNOWN) finding must be blocked by a \
             max_severity='high' policy — at 'info' it was invisible to every \
             threshold, got allowed={} violations={:?}",
            ungraded_result.allowed, ungraded_result.violations
        );
        assert!(
            ungraded_result
                .violations
                .iter()
                .any(|v| v.contains("at or above high")),
            "the violation must come from the max_severity gate, got: {:?}",
            ungraded_result.violations
        );

        let low_result = low_result.expect("evaluate low");
        assert!(
            low_result.allowed,
            "positive control: a graded 'low' finding must still be served \
             under a 'high' policy, got violations={:?}",
            low_result.violations
        );
    }

    #[test]
    fn test_policy_result_serialization() {
        let result = PolicyResult {
            allowed: false,
            violations: vec!["test violation".to_string()],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["allowed"], false);
        assert_eq!(json["violations"][0], "test violation");
    }

    // -----------------------------------------------------------------------
    // ScanPolicy construction and serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_policy_construction() {
        let policy = ScanPolicy {
            id: Uuid::new_v4(),
            name: "no-critical-vulns".to_string(),
            repository_id: None,
            max_severity: "critical".to_string(),
            block_unscanned: true,
            block_on_fail: true,
            is_enabled: true,
            min_staging_hours: Some(24),
            max_artifact_age_days: Some(365),
            require_signature: false,
            predicates: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(policy.name, "no-critical-vulns");
        assert!(policy.block_unscanned);
        assert!(policy.block_on_fail);
        assert!(policy.is_enabled);
        assert_eq!(policy.min_staging_hours, Some(24));
        assert!(policy.repository_id.is_none()); // global policy
    }

    #[test]
    fn test_scan_policy_repo_specific() {
        let repo_id = Uuid::new_v4();
        let policy = ScanPolicy {
            id: Uuid::new_v4(),
            name: "repo-policy".to_string(),
            repository_id: Some(repo_id),
            max_severity: "high".to_string(),
            block_unscanned: false,
            block_on_fail: false,
            is_enabled: true,
            min_staging_hours: None,
            max_artifact_age_days: None,
            require_signature: true,
            predicates: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(policy.repository_id, Some(repo_id));
        assert!(policy.require_signature);
    }

    #[test]
    fn test_scan_policy_serialization_roundtrip() {
        let policy = ScanPolicy {
            id: Uuid::nil(),
            name: "test-policy".to_string(),
            repository_id: None,
            max_severity: "medium".to_string(),
            block_unscanned: true,
            block_on_fail: false,
            is_enabled: true,
            min_staging_hours: Some(48),
            max_artifact_age_days: None,
            require_signature: false,
            predicates: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json_str = serde_json::to_string(&policy).unwrap();
        let deserialized: ScanPolicy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.name, "test-policy");
        assert_eq!(deserialized.max_severity, "medium");
        assert!(deserialized.block_unscanned);
        assert_eq!(deserialized.min_staging_hours, Some(48));
        assert!(deserialized.max_artifact_age_days.is_none());
    }

    // -----------------------------------------------------------------------
    // Violation message formatting logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_violation_message_unscanned() {
        let policy_name = "strict-policy";
        let msg = format!("Policy '{}': artifact has not been scanned", policy_name);
        assert_eq!(msg, "Policy 'strict-policy': artifact has not been scanned");
    }

    #[test]
    fn test_violation_message_scan_failed() {
        let policy_name = "default";
        let msg = format!("Policy '{}': latest scan failed", policy_name);
        assert_eq!(msg, "Policy 'default': latest scan failed");
    }

    #[test]
    fn test_violation_message_severity() {
        let policy_name = "no-high";
        let count = 5;
        let severity = "high";
        let msg = format!(
            "Policy '{}': {} findings at or above {} severity",
            policy_name, count, severity
        );
        assert_eq!(
            msg,
            "Policy 'no-high': 5 findings at or above high severity"
        );
    }

    // -----------------------------------------------------------------------
    // Severity::from_str_loose used in policy evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_from_str_loose_for_policy() {
        // The policy evaluation uses from_str_loose with unwrap_or(Critical)
        let threshold = Severity::from_str_loose("high").unwrap_or(Severity::Critical);
        assert_eq!(threshold, Severity::High);

        let unknown = Severity::from_str_loose("unknown").unwrap_or(Severity::Critical);
        assert_eq!(unknown, Severity::Critical);
    }

    // -----------------------------------------------------------------------
    // Policy allowed = violations.is_empty() logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_result_allowed_when_empty_violations() {
        let violations: Vec<String> = vec![];
        let result = PolicyResult {
            allowed: violations.is_empty(),
            violations,
        };
        assert!(result.allowed);
    }

    #[test]
    fn test_policy_result_blocked_when_nonempty_violations() {
        let violations = vec!["test".to_string()];
        let result = PolicyResult {
            allowed: violations.is_empty(),
            violations,
        };
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // #1374 regression: PUT /security/policies/{id} must atomically persist
    // every field the client provided in the same request. Previously the
    // strict-shape DTO bounced partial bodies as 422, and even when callers
    // resubmitted the whole policy a multi-field change was not guaranteed
    // to round-trip through the update path. This DB-backed test asserts:
    //
    //  - `update_policy(max_severity, is_enabled)` flips BOTH columns,
    //  - a follow-up `get_policy` confirms both values stuck,
    //  - omitted fields (`name`, `block_unscanned`, ...) are NOT clobbered
    //    by the COALESCE branch.
    //
    // Skips silently when `DATABASE_URL` is unset so `cargo test --lib`
    // without a running Postgres still passes; the CI integration job
    // covers this branch.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_update_policy_persists_multiple_fields_1374() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return, // No DB: skip locally; CI integration covers.
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return, // DB not reachable: skip.
        };

        let svc = PolicyService::new(pool.clone());

        // Seed a global policy. Pre-conditions are deliberately the opposite
        // of the values we PUT below so we can assert both columns actually
        // moved (not just "happened to already match").
        let original = svc
            .create_policy(
                &format!("1374-fixture-{}", &Uuid::new_v4().to_string()[..8]),
                None,
                "low", // will become "critical"
                true,  // block_unscanned: untouched, must stay true
                false,
                None,
                None,
                false,
                None,
            )
            .await
            .expect("seed policy");
        assert!(original.is_enabled, "policies default to is_enabled=true");
        assert_eq!(original.max_severity, "low");
        let policy_id = original.id;

        // The exact partial-update the release-gate sends: flip max_severity
        // AND is_enabled in one request. Every other field is `None`, so the
        // COALESCE branches keep their existing values.
        let updated = svc
            .update_policy(
                policy_id,
                None,             // name -- untouched
                Some("critical"), // max_severity: low -> critical
                None,             // block_unscanned -- untouched
                None,
                Some(false), // is_enabled: true -> false (the bug)
                None,
                None,
                None,
                None,
            )
            .await
            .expect("partial update must succeed");

        // BOTH fields must have moved in the same UPDATE statement.
        assert_eq!(updated.max_severity, "critical");
        assert!(!updated.is_enabled, "is_enabled must persist false (#1374)");
        // Untouched fields must NOT have been silently reset by the COALESCE.
        assert_eq!(updated.name, original.name);
        assert!(updated.block_unscanned, "block_unscanned must stay true");
        assert!(!updated.block_on_fail);
        assert!(!updated.require_signature);

        // GET-after-PUT: re-read from the DB to prove durability, not just
        // that the RETURNING clause echoed our bind values.
        let after = svc.get_policy(policy_id).await.expect("re-read policy");
        assert_eq!(after.max_severity, "critical");
        assert!(!after.is_enabled, "GET-after-PUT must see is_enabled=false");
        assert!(after.block_unscanned, "GET-after-PUT untouched cols intact");

        // Cleanup so reruns against a long-lived test DB don't accumulate.
        let _ = svc.delete_policy(policy_id).await;
    }

    #[tokio::test]
    async fn test_update_policy_empty_patch_is_a_noop_1374() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let svc = PolicyService::new(pool.clone());

        let original = svc
            .create_policy(
                &format!("1374-noop-{}", &Uuid::new_v4().to_string()[..8]),
                None,
                "medium",
                true,
                true,
                Some(24),
                Some(30),
                true,
                None,
            )
            .await
            .expect("seed policy");

        // Empty PATCH: every argument is None, the SET clauses become
        // `col = COALESCE(NULL, col)` which is a no-op for every column
        // except `updated_at = NOW()`.
        let after = svc
            .update_policy(
                original.id,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("empty patch must succeed, not 422");

        assert_eq!(after.name, original.name);
        assert_eq!(after.max_severity, original.max_severity);
        assert_eq!(after.block_unscanned, original.block_unscanned);
        assert_eq!(after.block_on_fail, original.block_on_fail);
        assert_eq!(after.is_enabled, original.is_enabled);
        assert_eq!(after.min_staging_hours, original.min_staging_hours);
        assert_eq!(after.max_artifact_age_days, original.max_artifact_age_days);
        assert_eq!(after.require_signature, original.require_signature);

        let _ = svc.delete_policy(original.id).await;
    }

    // -----------------------------------------------------------------------
    // #4058: conda policy predicates
    // -----------------------------------------------------------------------

    fn conda_facts_4058() -> CondaFacts {
        CondaFacts {
            is_conda: true,
            channel: Some("my-channel".to_string()),
            license: Some("MIT".to_string()),
            license_family: Some("MIT".to_string()),
            install_script_count: 0,
            max_script_finding_rank: None,
            attestation: CondaAttestationFact::Absent,
        }
    }

    fn preds_4058(preds: CondaPolicyPredicates) -> CondaPolicyPredicates {
        assert!(!preds.is_inert(), "test predicate set must not be inert");
        preds
    }

    // -- channel of origin ---------------------------------------------------

    #[test]
    fn test_conda_channel_allowlist_blocks_unlisted_channel() {
        let preds = preds_4058(CondaPolicyPredicates {
            allowed_channels: vec!["my-channel".to_string()],
            ..Default::default()
        });
        let facts = CondaFacts {
            channel: Some("evil-channel".to_string()),
            ..conda_facts_4058()
        };
        let violations = evaluate_conda_predicates("p", &preds, &facts);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("[conda.channel]") && violations[0].contains("evil-channel"),
            "the decision must name the fired predicate and the offending channel, got: {:?}",
            violations
        );
    }

    #[test]
    fn test_conda_channel_allowlist_passes_listed_channel_case_insensitively() {
        // Normalization lowercases the configured list; evaluation lowercases
        // the fact. A channel recorded as `My-Channel` satisfies
        // `allowed_channels: ["my-channel"]`.
        let preds = preds_4058(CondaPolicyPredicates {
            allowed_channels: vec!["my-channel".to_string()],
            ..Default::default()
        });
        let facts = CondaFacts {
            channel: Some("My-Channel".to_string()),
            ..conda_facts_4058()
        };
        assert!(
            evaluate_conda_predicates("p", &preds, &facts).is_empty(),
            "a listed channel must pass, case-insensitively"
        );
    }

    #[test]
    fn test_conda_channel_allowlist_fails_closed_on_unknown_origin() {
        // The predicate exists to PROVE origin; an artifact whose channel was
        // never recorded proves nothing and must be blocked, not waved through.
        let preds = preds_4058(CondaPolicyPredicates {
            allowed_channels: vec!["my-channel".to_string()],
            ..Default::default()
        });
        let facts = CondaFacts {
            channel: None,
            ..conda_facts_4058()
        };
        let violations = evaluate_conda_predicates("p", &preds, &facts);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[conda.channel]"));
        assert!(violations[0].contains("unknown"));
    }

    #[test]
    fn test_conda_channel_denylist_blocks_only_matching_channels() {
        let preds = preds_4058(CondaPolicyPredicates {
            denied_channels: vec!["conda-forg".to_string()],
            ..Default::default()
        });
        let squatted = CondaFacts {
            channel: Some("conda-forg".to_string()),
            ..conda_facts_4058()
        };
        let violations = evaluate_conda_predicates("p", &preds, &squatted);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[conda.channel]"));

        // Positive control: a non-matching channel is unaffected (a denylist
        // entry must not become a block-everything).
        let legit = CondaFacts {
            channel: Some("conda-forge".to_string()),
            ..conda_facts_4058()
        };
        assert!(evaluate_conda_predicates("p", &preds, &legit).is_empty());
    }

    // -- license / license family ---------------------------------------------

    #[test]
    fn test_conda_license_and_family_denied() {
        let preds = preds_4058(CondaPolicyPredicates {
            denied_licenses: vec!["gpl-3.0-only".to_string()],
            denied_license_families: vec!["agpl".to_string()],
            ..Default::default()
        });
        let by_license = CondaFacts {
            license: Some("GPL-3.0-only".to_string()),
            license_family: Some("GPL".to_string()),
            ..conda_facts_4058()
        };
        let violations = evaluate_conda_predicates("p", &preds, &by_license);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("[conda.license]"),
            "license match must fire the license predicate, got: {violations:?}"
        );

        let by_family = CondaFacts {
            license: Some("AGPL-3.0".to_string()),
            license_family: Some("AGPL".to_string()),
            ..conda_facts_4058()
        };
        let violations = evaluate_conda_predicates("p", &preds, &by_family);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[conda.license_family]"));

        // Positive control: an allowed license under the same policy.
        assert!(evaluate_conda_predicates("p", &preds, &conda_facts_4058()).is_empty());
    }

    #[test]
    fn test_conda_undeclared_license_is_not_a_denied_license() {
        // A denylist can only judge what is declared; "about.json named no
        // license" is a different fact (and would be its own predicate).
        let preds = preds_4058(CondaPolicyPredicates {
            denied_licenses: vec!["gpl-3.0-only".to_string()],
            denied_license_families: vec!["gpl".to_string()],
            ..Default::default()
        });
        let facts = CondaFacts {
            license: None,
            license_family: None,
            ..conda_facts_4058()
        };
        assert!(evaluate_conda_predicates("p", &preds, &facts).is_empty());
    }

    // -- install scripts --------------------------------------------------------

    #[test]
    fn test_conda_install_script_presence_blocks() {
        let preds = preds_4058(CondaPolicyPredicates {
            block_install_scripts: true,
            ..Default::default()
        });
        let facts = CondaFacts {
            install_script_count: 2,
            ..conda_facts_4058()
        };
        let violations = evaluate_conda_predicates("p", &preds, &facts);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[conda.install_scripts]"));
        assert!(violations[0].contains('2'));

        // Positive control: no scripts, nothing to block.
        assert!(evaluate_conda_predicates("p", &preds, &conda_facts_4058()).is_empty());
    }

    #[test]
    fn test_conda_install_script_finding_severity_threshold() {
        let preds = preds_4058(CondaPolicyPredicates {
            max_install_script_severity: Some("medium".to_string()),
            ..Default::default()
        });
        // A high finding meets the medium threshold.
        let high = CondaFacts {
            install_script_count: 1,
            max_script_finding_rank: Some(script_severity_rank("high").unwrap()),
            ..conda_facts_4058()
        };
        let violations = evaluate_conda_predicates("p", &preds, &high);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[conda.install_scripts]"));
        assert!(violations[0].contains("high") && violations[0].contains("medium"));

        // A low finding stays under the medium threshold.
        let low = CondaFacts {
            install_script_count: 1,
            max_script_finding_rank: Some(script_severity_rank("low").unwrap()),
            ..conda_facts_4058()
        };
        assert!(evaluate_conda_predicates("p", &preds, &low).is_empty());

        // Unexamined scripts (findings NULL -> no rank) are NOT graded clean
        // at info; they are simply ungraded by this gate. The presence
        // predicate is the one that covers them.
        let unexamined = CondaFacts {
            install_script_count: 1,
            max_script_finding_rank: None,
            ..conda_facts_4058()
        };
        assert!(evaluate_conda_predicates("p", &preds, &unexamined).is_empty());
    }

    // -- attestation -------------------------------------------------------------

    #[test]
    fn test_conda_attestation_present_requires_a_record() {
        let preds = preds_4058(CondaPolicyPredicates {
            min_attestation_state: Some("present".to_string()),
            ..Default::default()
        });
        let absent = evaluate_conda_predicates("p", &preds, &conda_facts_4058());
        assert_eq!(absent.len(), 1);
        assert!(absent[0].contains("[conda.attestation]"));

        for state in [
            CondaAttestationFact::PresentUnverified,
            CondaAttestationFact::Verified,
        ] {
            let facts = CondaFacts {
                attestation: state,
                ..conda_facts_4058()
            };
            assert!(
                evaluate_conda_predicates("p", &preds, &facts).is_empty(),
                "'present' must accept {state:?}"
            );
        }
    }

    #[test]
    fn test_conda_attestation_verified_requires_verification() {
        let preds = preds_4058(CondaPolicyPredicates {
            min_attestation_state: Some("verified".to_string()),
            ..Default::default()
        });
        for state in [
            CondaAttestationFact::Absent,
            CondaAttestationFact::PresentUnverified,
        ] {
            let facts = CondaFacts {
                attestation: state,
                ..conda_facts_4058()
            };
            let violations = evaluate_conda_predicates("p", &preds, &facts);
            assert_eq!(violations.len(), 1, "'verified' must reject {state:?}");
            assert!(violations[0].contains("[conda.attestation]"));
        }
        let facts = CondaFacts {
            attestation: CondaAttestationFact::Verified,
            ..conda_facts_4058()
        };
        assert!(evaluate_conda_predicates("p", &preds, &facts).is_empty());
    }

    // -- scope and parsing -------------------------------------------------------

    #[test]
    fn test_conda_predicates_never_fire_for_non_conda_artifacts() {
        // Every predicate configured, every fact offending — but the artifact
        // is not conda, so the policy's conda block must be silent.
        let preds = preds_4058(CondaPolicyPredicates {
            allowed_channels: vec!["other".to_string()],
            denied_channels: vec!["my-channel".to_string()],
            denied_licenses: vec!["mit".to_string()],
            denied_license_families: vec!["mit".to_string()],
            block_install_scripts: true,
            max_install_script_severity: Some("info".to_string()),
            min_attestation_state: Some("verified".to_string()),
        });
        let facts = CondaFacts {
            is_conda: false,
            install_script_count: 3,
            max_script_finding_rank: Some(3),
            ..conda_facts_4058()
        };
        assert!(evaluate_conda_predicates("p", &preds, &facts).is_empty());
    }

    #[test]
    fn test_channel_from_purl_extracts_and_decodes_the_qualifier() {
        assert_eq!(
            channel_from_purl(
                "pkg:conda/numpy@1.26.4?build=py311h5f1cd34_0&channel=conda-forge&subdir=linux-64&type=conda"
            ),
            Some("conda-forge".to_string())
        );
        // An upstream URL recorded as the channel arrives percent-encoded.
        assert_eq!(
            channel_from_purl(
                "pkg:conda/x@1?channel=https%3A%2F%2Fconda.anaconda.org%2Fconda-forge&subdir=noarch"
            ),
            Some("https://conda.anaconda.org/conda-forge".to_string())
        );
        // Channel first among qualifiers, and a purl with no channel at all.
        assert_eq!(
            channel_from_purl("pkg:conda/x@1?channel=my-channel&subdir=linux-64"),
            Some("my-channel".to_string())
        );
        assert_eq!(channel_from_purl("pkg:conda/x@1?subdir=linux-64"), None);
        assert_eq!(channel_from_purl("pkg:conda/x@1"), None);
    }

    #[test]
    fn test_normalize_predicates_lowercases_and_validates() {
        let raw = PolicyPredicates {
            conda: CondaPolicyPredicates {
                allowed_channels: vec![" My-Channel ".to_string()],
                denied_licenses: vec!["GPL-3.0-Only".to_string()],
                max_install_script_severity: Some("HIGH".to_string()),
                min_attestation_state: Some(" Verified ".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let normalized = normalize_predicates(&raw).expect("valid predicates must normalize");
        assert_eq!(normalized.conda.allowed_channels, ["my-channel"]);
        assert_eq!(normalized.conda.denied_licenses, ["gpl-3.0-only"]);
        assert_eq!(
            normalized.conda.max_install_script_severity.as_deref(),
            Some("high")
        );
        assert_eq!(
            normalized.conda.min_attestation_state.as_deref(),
            Some("verified")
        );
    }

    #[test]
    fn test_normalize_predicates_rejects_bad_values() {
        let bad_severity = PolicyPredicates {
            conda: CondaPolicyPredicates {
                max_install_script_severity: Some("critical".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        // Script findings have no 'critical' rank (ScriptSeverity tops out at
        // High), so accepting it would silently never fire.
        assert!(matches!(
            normalize_predicates(&bad_severity),
            Err(AppError::Validation(_))
        ));

        let bad_state = PolicyPredicates {
            conda: CondaPolicyPredicates {
                min_attestation_state: Some("signed".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(matches!(
            normalize_predicates(&bad_state),
            Err(AppError::Validation(_))
        ));

        let empty_entry = PolicyPredicates {
            conda: CondaPolicyPredicates {
                denied_channels: vec!["  ".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(matches!(
            normalize_predicates(&empty_entry),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn test_parse_policy_predicates_tolerates_legacy_and_unknown_shapes() {
        assert!(parse_policy_predicates(&serde_json::json!({})).is_inert());
        // Unknown keys (a NEWER binary's fields, read by this older one) are
        // ignored rather than failing the whole policy evaluation.
        assert!(parse_policy_predicates(&serde_json::json!({"future": {"x": 1}})).is_inert());
        // A hand-corrupted document degrades to "no predicates" instead of
        // failing every download in the repo.
        assert!(parse_policy_predicates(&serde_json::json!([1, 2, 3])).is_inert());
    }

    // -----------------------------------------------------------------------
    // #4058 DB-backed: expressible, enforced, composed, recorded
    // -----------------------------------------------------------------------

    /// Seed a conda artifact: the `artifacts` row plus the `artifact_metadata`
    /// row `build_conda_metadata` would have written at ingest.
    #[cfg(test)]
    async fn seed_conda_artifact_4058(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        name: &str,
        version: &str,
        metadata: serde_json::Value,
    ) -> Uuid {
        use crate::api::handlers::test_db_helpers as tdh;
        let path = format!("linux-64/{name}-{version}-py311_0.tar.bz2");
        let artifact_id = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            &path,
            &path,
            name,
            version,
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
             VALUES ($1, 'conda', $2)",
        )
        .bind(artifact_id)
        .bind(&metadata)
        .execute(&fx.pool)
        .await
        .expect("seed conda artifact_metadata");
        artifact_id
    }

    /// The metadata document for a package whose about.json declared `license`
    /// / `license_family` and whose ingest recorded `channel` in its identity
    /// purl (exactly the shape `build_conda_metadata` persists).
    fn conda_metadata_4058(
        channel: &str,
        license: &str,
        license_family: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "license": license,
            "license_family": license_family,
            "identity": {
                "purl": format!(
                    "pkg:conda/pkg@1.0.0?build=py311_0&channel={channel}&subdir=linux-64&type=conda"
                )
            }
        })
    }

    async fn delete_repo_policies_4058(pool: &PgPool, repo_id: Uuid) {
        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn test_conda_channel_predicate_expressible_and_enforced_db_4058() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let svc = PolicyService::new(fx.pool.clone());

        // EXPRESSIBLE: create through the real service API (the path the HTTP
        // handler drives) with a mixed-case list; normalization lowercases.
        let policy = svc
            .create_policy(
                &format!("4058-channel-{}", fx.repo_id),
                Some(fx.repo_id),
                "critical",
                false,
                false,
                None,
                None,
                false,
                Some(PolicyPredicates {
                    conda: CondaPolicyPredicates {
                        allowed_channels: vec!["Trusted-Channel".to_string()],
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            )
            .await
            .expect("create policy with conda predicates");
        let stored = parse_policy_predicates(&policy.predicates);
        assert_eq!(stored.conda.allowed_channels, ["trusted-channel"]);

        // GET-after-PUT durability, same as the #1374 contract.
        let reread = svc.get_policy(policy.id).await.expect("re-read policy");
        assert_eq!(
            parse_policy_predicates(&reread.predicates)
                .conda
                .allowed_channels,
            ["trusted-channel"]
        );

        // ENFORCED: an artifact from an unlisted channel is blocked, and the
        // decision RECORDS the fired predicate.
        let blocked = seed_conda_artifact_4058(
            &fx,
            "squat",
            "1.0.0",
            conda_metadata_4058("evil-channel", "MIT", "MIT"),
        )
        .await;
        let blocked_result = svc
            .evaluate_artifact(blocked, fx.repo_id)
            .await
            .expect("evaluate blocked");

        // Positive control: an artifact from the allowed channel passes.
        let allowed = seed_conda_artifact_4058(
            &fx,
            "legit",
            "1.0.0",
            conda_metadata_4058("trusted-channel", "MIT", "MIT"),
        )
        .await;
        let allowed_result = svc
            .evaluate_artifact(allowed, fx.repo_id)
            .await
            .expect("evaluate allowed");

        // Fallback control: no identity block at all -> the channel fact is
        // the owning repository's key (what ingest records for a hosted
        // upload), which is not on the allowlist here, so this must block.
        let no_identity =
            seed_conda_artifact_4058(&fx, "old", "1.0.0", serde_json::json!({"license": "MIT"}))
                .await;
        let no_identity_result = svc
            .evaluate_artifact(no_identity, fx.repo_id)
            .await
            .expect("evaluate no-identity");

        delete_repo_policies_4058(&fx.pool, fx.repo_id).await;
        fx.teardown().await;

        assert!(
            !blocked_result.allowed,
            "an unlisted channel of origin must be blocked, got: {:?}",
            blocked_result
        );
        assert!(
            blocked_result
                .violations
                .iter()
                .any(|v| v.contains("[conda.channel]") && v.contains("evil-channel")),
            "the decision must record the fired predicate, got: {:?}",
            blocked_result.violations
        );
        assert!(
            allowed_result.allowed,
            "an allowlisted channel must pass, got: {:?}",
            allowed_result.violations
        );
        assert!(
            !no_identity_result.allowed
                && no_identity_result
                    .violations
                    .iter()
                    .any(|v| v.contains("[conda.channel]")),
            "the repo-key fallback channel must drive the same predicate, got: {:?}",
            no_identity_result.violations
        );
    }

    #[tokio::test]
    async fn test_conda_license_predicates_enforced_db_4058() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let svc = PolicyService::new(fx.pool.clone());
        svc.create_policy(
            &format!("4058-license-{}", fx.repo_id),
            Some(fx.repo_id),
            "critical",
            false,
            false,
            None,
            None,
            false,
            Some(PolicyPredicates {
                conda: CondaPolicyPredicates {
                    denied_licenses: vec!["GPL-3.0-Only".to_string()],
                    denied_license_families: vec!["AGPL".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .await
        .expect("create license policy");

        let by_license = seed_conda_artifact_4058(
            &fx,
            "gplpkg",
            "1.0.0",
            conda_metadata_4058("my-channel", "gpl-3.0-only", "GPL"),
        )
        .await;
        let by_family = seed_conda_artifact_4058(
            &fx,
            "agplpkg",
            "1.0.0",
            conda_metadata_4058("my-channel", "AGPL-3.0", "agpl"),
        )
        .await;
        let clean = seed_conda_artifact_4058(
            &fx,
            "mitpkg",
            "1.0.0",
            conda_metadata_4058("my-channel", "MIT", "MIT"),
        )
        .await;

        let license_result = svc.evaluate_artifact(by_license, fx.repo_id).await;
        let family_result = svc.evaluate_artifact(by_family, fx.repo_id).await;
        let clean_result = svc.evaluate_artifact(clean, fx.repo_id).await;

        delete_repo_policies_4058(&fx.pool, fx.repo_id).await;
        fx.teardown().await;

        let license_result = license_result.expect("evaluate license");
        assert!(
            !license_result.allowed
                && license_result
                    .violations
                    .iter()
                    .any(|v| v.contains("[conda.license]")),
            "a denied license must block and be recorded, got: {license_result:?}"
        );
        let family_result = family_result.expect("evaluate family");
        assert!(
            !family_result.allowed
                && family_result
                    .violations
                    .iter()
                    .any(|v| v.contains("[conda.license_family]")),
            "a denied license family must block and be recorded, got: {family_result:?}"
        );
        let clean_result = clean_result.expect("evaluate clean");
        assert!(
            clean_result.allowed,
            "an allowed license must pass, got: {:?}",
            clean_result.violations
        );
    }

    #[tokio::test]
    async fn test_conda_install_script_predicates_enforced_db_4058() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let svc = PolicyService::new(fx.pool.clone());

        // Policy 1: mere presence blocks. Policy 2 (same repo): a finding at
        // or above 'medium' blocks. Both apply to every artifact below, so
        // each assertion isolates its predicate by the finding content.
        for (tag, preds) in [
            (
                "presence",
                serde_json::json!({"conda": {"block_install_scripts": true}}),
            ),
            (
                "severity",
                serde_json::json!({"conda": {"max_install_script_severity": "medium"}}),
            ),
        ] {
            sqlx::query(
                "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                            block_on_fail, is_enabled, predicates) \
                 VALUES ($1, $2, 'critical', false, false, true, $3)",
            )
            .bind(format!("4058-scripts-{tag}-{}", fx.repo_id))
            .bind(fx.repo_id)
            .bind(preds)
            .execute(&fx.pool)
            .await
            .expect("insert script policy");
        }

        // A script WITH a high finding: both policies must fire.
        let flagged = seed_conda_artifact_4058(
            &fx,
            "scripted",
            "1.0.0",
            conda_metadata_4058("my-channel", "MIT", "MIT"),
        )
        .await;
        sqlx::query(
            "INSERT INTO package_install_scripts \
                 (artifact_id, path, kind, size_bytes, sha256, body, findings) \
             VALUES ($1, 'bin/.pkg-post-link.sh', 'post-link', 42, 'deadbeef', 'curl http://x', \
                     $2::jsonb)",
        )
        .bind(flagged)
        .bind(serde_json::json!([
            {"rule_id": "network-egress", "severity": "high", "title": "Network egress",
             "line": 1, "snippet": "curl http://x"}
        ]))
        .execute(&fx.pool)
        .await
        .expect("seed install script with finding");

        // A script whose analysis found only a LOW finding: the presence
        // policy fires, the severity policy must not.
        let low_only = seed_conda_artifact_4058(
            &fx,
            "lowscript",
            "1.0.0",
            conda_metadata_4058("my-channel", "MIT", "MIT"),
        )
        .await;
        sqlx::query(
            "INSERT INTO package_install_scripts \
                 (artifact_id, path, kind, size_bytes, sha256, body, findings) \
             VALUES ($1, 'bin/.pkg-post-link.sh', 'post-link', 42, 'deadbeef', 'echo hi', \
                     $2::jsonb)",
        )
        .bind(low_only)
        .bind(serde_json::json!([
            {"rule_id": "writes-outside-prefix", "severity": "low", "title": "Writes",
             "line": 1, "snippet": "echo hi"}
        ]))
        .execute(&fx.pool)
        .await
        .expect("seed install script with low finding");

        // No scripts at all: neither policy may fire.
        let scriptless = seed_conda_artifact_4058(
            &fx,
            "plain",
            "1.0.0",
            conda_metadata_4058("my-channel", "MIT", "MIT"),
        )
        .await;

        let flagged_result = svc.evaluate_artifact(flagged, fx.repo_id).await;
        let low_result = svc.evaluate_artifact(low_only, fx.repo_id).await;
        let scriptless_result = svc.evaluate_artifact(scriptless, fx.repo_id).await;

        delete_repo_policies_4058(&fx.pool, fx.repo_id).await;
        fx.teardown().await;

        let flagged_result = flagged_result.expect("evaluate flagged");
        let fired: Vec<&str> = flagged_result
            .violations
            .iter()
            .filter(|v| v.contains("[conda.install_scripts]"))
            .map(|v| v.as_str())
            .collect();
        assert!(
            !flagged_result.allowed && fired.len() == 2,
            "both script predicates must fire and be recorded, got: {:?}",
            flagged_result.violations
        );
        assert!(
            fired.iter().any(|v| v.contains("install-time script")),
            "presence predicate recorded, got: {fired:?}"
        );
        assert!(
            fired.iter().any(|v| v.contains("threshold 'medium'")),
            "severity predicate recorded, got: {fired:?}"
        );

        let low_result = low_result.expect("evaluate low-only");
        assert!(
            !low_result.allowed
                && low_result
                    .violations
                    .iter()
                    .any(|v| v.contains("[conda.install_scripts]")
                        && v.contains("install-time script"))
                && !low_result
                    .violations
                    .iter()
                    .any(|v| v.contains("threshold")),
            "a low finding must trip presence but NOT the medium threshold, got: {:?}",
            low_result.violations
        );

        let scriptless_result = scriptless_result.expect("evaluate scriptless");
        assert!(
            scriptless_result.allowed,
            "no scripts -> neither script predicate may fire, got: {:?}",
            scriptless_result.violations
        );
    }

    #[tokio::test]
    async fn test_conda_attestation_predicate_enforced_db_4058() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let svc = PolicyService::new(fx.pool.clone());
        svc.create_policy(
            &format!("4058-attestation-{}", fx.repo_id),
            Some(fx.repo_id),
            "critical",
            false,
            false,
            None,
            None,
            false,
            Some(PolicyPredicates {
                conda: CondaPolicyPredicates {
                    min_attestation_state: Some("verified".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .await
        .expect("create attestation policy");

        // (1) ABSENT: no curation record at all -> blocked.
        let unattested = seed_conda_artifact_4058(
            &fx,
            "unsigned-pkg",
            "1.0.0",
            conda_metadata_4058("my-channel", "MIT", "MIT"),
        )
        .await;

        // (2) PRESENT-UNVERIFIED: a record exists but verification failed.
        let failed = seed_conda_artifact_4058(
            &fx,
            "failed-pkg",
            "1.0.0",
            conda_metadata_4058("my-channel", "MIT", "MIT"),
        )
        .await;
        sqlx::query(
            "INSERT INTO curation_packages \
                 (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path, \
                  status, attestation_state) \
             VALUES ($1, $1, 'conda', 'failed-pkg', '1.0.0', '/linux-64/failed-pkg.tar.bz2', \
                     'approved', 'failed')",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("seed failed attestation record");

        // (3) VERIFIED: full CEP-27 chain verified -> allowed.
        let verified = seed_conda_artifact_4058(
            &fx,
            "verified-pkg",
            "1.0.0",
            conda_metadata_4058("my-channel", "MIT", "MIT"),
        )
        .await;
        sqlx::query(
            "INSERT INTO curation_packages \
                 (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path, \
                  status, attestation_state) \
             VALUES ($1, $1, 'conda', 'verified-pkg', '1.0.0', '/linux-64/verified-pkg.tar.bz2', \
                     'approved', 'verified')",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("seed verified attestation record");

        let absent_result = svc.evaluate_artifact(unattested, fx.repo_id).await;
        let failed_result = svc.evaluate_artifact(failed, fx.repo_id).await;
        let verified_result = svc.evaluate_artifact(verified, fx.repo_id).await;

        delete_repo_policies_4058(&fx.pool, fx.repo_id).await;
        fx.teardown().await;

        let absent_result = absent_result.expect("evaluate absent");
        assert!(
            !absent_result.allowed
                && absent_result
                    .violations
                    .iter()
                    .any(|v| v.contains("[conda.attestation]") && v.contains("absent")),
            "absent attestation must block under 'verified' and be recorded, got: {absent_result:?}"
        );
        let failed_result = failed_result.expect("evaluate failed");
        assert!(
            !failed_result.allowed
                && failed_result
                    .violations
                    .iter()
                    .any(|v| v.contains("[conda.attestation]") && v.contains("unverified")),
            "a failed attestation is present-but-unverified and must block, got: {failed_result:?}"
        );
        let verified_result = verified_result.expect("evaluate verified");
        assert!(
            verified_result.allowed,
            "a verified attestation must satisfy the policy, got: {:?}",
            verified_result.violations
        );
    }

    #[tokio::test]
    async fn test_conda_predicates_compose_with_cve_condition_db_4058() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let svc = PolicyService::new(fx.pool.clone());

        // ONE policy carrying both a classic CVE/severity condition and a
        // conda predicate: both must evaluate, and the decision must record
        // both reasons.
        svc.create_policy(
            &format!("4058-composed-{}", fx.repo_id),
            Some(fx.repo_id),
            "low",
            false,
            false,
            None,
            None,
            false,
            Some(PolicyPredicates {
                conda: CondaPolicyPredicates {
                    denied_licenses: vec!["mit".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .await
        .expect("create composed policy");

        let artifact = seed_conda_artifact_4058(
            &fx,
            "composed",
            "1.0.0",
            conda_metadata_4058("my-channel", "MIT", "MIT"),
        )
        .await;
        // A completed scan with one low finding satisfies the severity gate's
        // inputs (mirrors the #3306 seeder, minus the Trivy round trip).
        let scan_result_id: Uuid = sqlx::query_scalar(
            "INSERT INTO scan_results (id, artifact_id, repository_id, scan_type, status, \
                                       findings_count, critical_count, high_count, medium_count, \
                                       low_count, info_count, completed_at, created_at) \
             VALUES ($1, $2, $3, 'dependency', 'completed', 1, 0, 0, 0, 1, 0, NOW(), NOW()) \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(artifact)
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("seed completed scan");
        sqlx::query(
            "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title) \
             VALUES ($1, $2, 'low', 'CVE-2026-4058')",
        )
        .bind(scan_result_id)
        .bind(artifact)
        .execute(&fx.pool)
        .await
        .expect("seed low finding");

        // Positive control: same scan shape, license NOT denied -> the conda
        // predicate stays quiet while the CVE condition still blocks alone.
        let cve_only = seed_conda_artifact_4058(
            &fx,
            "cveonly",
            "1.0.0",
            conda_metadata_4058("my-channel", "BSD-3-Clause", "BSD"),
        )
        .await;
        let scan_result_id: Uuid = sqlx::query_scalar(
            "INSERT INTO scan_results (id, artifact_id, repository_id, scan_type, status, \
                                       findings_count, critical_count, high_count, medium_count, \
                                       low_count, info_count, completed_at, created_at) \
             VALUES ($1, $2, $3, 'dependency', 'completed', 1, 0, 0, 0, 1, 0, NOW(), NOW()) \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(cve_only)
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("seed completed scan");
        sqlx::query(
            "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title) \
             VALUES ($1, $2, 'low', 'CVE-2026-4058')",
        )
        .bind(scan_result_id)
        .bind(cve_only)
        .execute(&fx.pool)
        .await
        .expect("seed low finding");

        let composed_result = svc.evaluate_artifact(artifact, fx.repo_id).await;
        let cve_only_result = svc.evaluate_artifact(cve_only, fx.repo_id).await;

        delete_repo_policies_4058(&fx.pool, fx.repo_id).await;
        fx.teardown().await;

        let composed_result = composed_result.expect("evaluate composed");
        assert!(!composed_result.allowed);
        assert!(
            composed_result
                .violations
                .iter()
                .any(|v| v.contains("at or above low")),
            "the CVE/severity condition must still fire, got: {:?}",
            composed_result.violations
        );
        assert!(
            composed_result
                .violations
                .iter()
                .any(|v| v.contains("[conda.license]")),
            "the conda predicate must compose in the same decision, got: {:?}",
            composed_result.violations
        );

        let cve_only_result = cve_only_result.expect("evaluate cve-only");
        assert!(
            !cve_only_result.allowed
                && cve_only_result
                    .violations
                    .iter()
                    .any(|v| v.contains("at or above low"))
                && !cve_only_result
                    .violations
                    .iter()
                    .any(|v| v.contains("[conda.")),
            "with a clean conda fact only the CVE condition may fire, got: {:?}",
            cve_only_result.violations
        );
    }

    // -----------------------------------------------------------------------
    // #4050: cross-format origin policy predicates
    // -----------------------------------------------------------------------

    fn origin_facts_4050() -> OriginFacts {
        OriginFacts {
            kind: Some("proxy".to_string()),
            repository_key: Some("maven-central".to_string()),
            upstream_url: Some("https://repo1.maven.org/maven2".to_string()),
        }
    }

    fn origin_preds_4050(preds: OriginPolicyPredicates) -> OriginPolicyPredicates {
        assert!(!preds.is_inert(), "test predicate set must not be inert");
        preds
    }

    #[test]
    fn test_origin_upstream_denylist_blocks_matching_upstream() {
        let preds = origin_preds_4050(OriginPolicyPredicates {
            denied_upstreams: vec!["https://repo1.maven.org/maven2".to_string()],
            ..Default::default()
        });
        let violations = evaluate_origin_predicates("p", &preds, &origin_facts_4050());
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("[origin.upstream]"),
            "the decision must name the fired predicate, got: {violations:?}"
        );

        // Positive control: a different upstream is unaffected — a denylist
        // entry must not become a block-everything.
        let other = OriginFacts {
            upstream_url: Some("https://pypi.org/simple".to_string()),
            ..origin_facts_4050()
        };
        assert!(evaluate_origin_predicates("p", &preds, &other).is_empty());
    }

    #[test]
    fn test_origin_upstream_allowlist_fails_closed_on_unknown_upstream() {
        // The predicate exists to PROVE which upstream supplied the bytes; a
        // hosted upload (no upstream facet) proves nothing and must be
        // blocked, not waved through — the conda channel predicate's posture.
        let preds = origin_preds_4050(OriginPolicyPredicates {
            allowed_upstreams: vec!["https://repo1.maven.org/maven2".to_string()],
            ..Default::default()
        });
        let hosted = OriginFacts {
            kind: Some("hosted".to_string()),
            upstream_url: None,
            ..origin_facts_4050()
        };
        let violations = evaluate_origin_predicates("p", &preds, &hosted);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[origin.upstream]"));
        assert!(violations[0].contains("unknown"));

        // A listed upstream passes, case-insensitively (normalization
        // lowercases the configured list; evaluation lowercases the fact).
        let mixed_case = OriginFacts {
            upstream_url: Some("HTTPS://Repo1.Maven.ORG/maven2".to_string()),
            ..origin_facts_4050()
        };
        assert!(evaluate_origin_predicates("p", &preds, &mixed_case).is_empty());
    }

    #[test]
    fn test_origin_repository_predicates() {
        // The shadowing defence: content that should only ever come from the
        // trusted repository must be blocked when a lower-trust one recorded
        // it.
        let preds = origin_preds_4050(OriginPolicyPredicates {
            denied_repositories: vec!["untrusted-mirror".to_string()],
            ..Default::default()
        });
        let shadowed = OriginFacts {
            repository_key: Some("untrusted-mirror".to_string()),
            ..origin_facts_4050()
        };
        let violations = evaluate_origin_predicates("p", &preds, &shadowed);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[origin.repository]"));
        assert!(evaluate_origin_predicates("p", &preds, &origin_facts_4050()).is_empty());

        let allow = origin_preds_4050(OriginPolicyPredicates {
            allowed_repositories: vec!["libs-release".to_string()],
            ..Default::default()
        });
        let violations = evaluate_origin_predicates("p", &allow, &origin_facts_4050());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[origin.repository]"));
    }

    #[test]
    fn test_origin_kind_allowlist() {
        let preds = origin_preds_4050(OriginPolicyPredicates {
            allowed_kinds: vec!["hosted".to_string()],
            ..Default::default()
        });
        let violations = evaluate_origin_predicates("p", &preds, &origin_facts_4050());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("[origin.kind]"));

        let hosted = OriginFacts {
            kind: Some("hosted".to_string()),
            ..origin_facts_4050()
        };
        assert!(evaluate_origin_predicates("p", &preds, &hosted).is_empty());
    }

    #[test]
    fn test_origin_predicates_inert_set_is_a_noop() {
        assert!(evaluate_origin_predicates(
            "p",
            &OriginPolicyPredicates::default(),
            &OriginFacts::default()
        )
        .is_empty());
    }

    #[test]
    fn test_normalize_origin_predicates_validates_kinds_and_lists() {
        let raw = PolicyPredicates {
            origin: OriginPolicyPredicates {
                allowed_upstreams: vec![" HTTPS://Repo1.Maven.ORG/maven2 ".to_string()],
                allowed_kinds: vec!["Hosted".to_string(), "migration".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let normalized = normalize_predicates(&raw).expect("valid origin predicates");
        assert_eq!(
            normalized.origin.allowed_upstreams,
            ["https://repo1.maven.org/maven2"]
        );
        assert_eq!(normalized.origin.allowed_kinds, ["hosted", "migration"]);

        let bad_kind = PolicyPredicates {
            origin: OriginPolicyPredicates {
                allowed_kinds: vec!["sideloaded".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        // A misspelled kind must be a 400 at write time, not a policy that
        // silently matches nothing.
        assert!(matches!(
            normalize_predicates(&bad_kind),
            Err(AppError::Validation(_))
        ));

        let empty_entry = PolicyPredicates {
            origin: OriginPolicyPredicates {
                denied_upstreams: vec!["  ".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(matches!(
            normalize_predicates(&empty_entry),
            Err(AppError::Validation(_))
        ));
    }

    /// DB-backed: an origin policy is expressible through the service API and
    /// enforced by `evaluate_artifact` against the origin the ingest trigger
    /// stamped — denied upstream blocks, matching allowlist passes, and a
    /// hosted artifact fails closed under an upstream allowlist.
    #[tokio::test]
    async fn test_origin_predicates_enforced_db_4050() {
        use crate::api::handlers::test_db_helpers as tdh;
        // The remote fixture is wired to https://upstream.example.test.
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };
        let svc = PolicyService::new(fx.pool.clone());

        let artifact = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("remote", Some("https://upstream.example.test")),
            "org/origin/1.0/origin-1.0.bin",
            "org/origin/1.0/origin-1.0.bin",
            "origin",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;

        // DENY: the artifact's recorded upstream is the denied one.
        svc.create_policy(
            &format!("4050-deny-upstream-{}", fx.repo_id),
            Some(fx.repo_id),
            "critical",
            false,
            false,
            None,
            None,
            false,
            Some(PolicyPredicates {
                origin: OriginPolicyPredicates {
                    denied_upstreams: vec!["HTTPS://Upstream.Example.TEST".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .await
        .expect("create denied-upstream policy");
        let denied = svc
            .evaluate_artifact(artifact, fx.repo_id)
            .await
            .expect("evaluate denied");
        assert!(
            !denied.allowed
                && denied
                    .violations
                    .iter()
                    .any(|v| v.contains("[origin.upstream]")),
            "a denied upstream must block, got: {denied:?}"
        );
        delete_repo_policies_4058(&fx.pool, fx.repo_id).await;

        // ALLOW: the recorded upstream is in the allowlist (and the kind is).
        svc.create_policy(
            &format!("4050-allow-upstream-{}", fx.repo_id),
            Some(fx.repo_id),
            "critical",
            false,
            false,
            None,
            None,
            false,
            Some(PolicyPredicates {
                origin: OriginPolicyPredicates {
                    allowed_upstreams: vec!["https://upstream.example.test".to_string()],
                    allowed_kinds: vec!["proxy".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .await
        .expect("create allowed-upstream policy");
        let allowed = svc
            .evaluate_artifact(artifact, fx.repo_id)
            .await
            .expect("evaluate allowed");
        // Assert on the ABSENCE of an origin violation, not on
        // `allowed`: evaluate_artifact aggregates every enabled policy,
        // and other suites' leaked global policies (e.g. block-unscanned)
        // can independently block this artifact — the origin predicate's
        // pass case is that it contributes no violation of its own.
        assert!(
            !allowed.violations.iter().any(|v| v.contains("[origin.")),
            "a listed upstream and kind must produce no origin violation, got: {allowed:?}"
        );
        delete_repo_policies_4058(&fx.pool, fx.repo_id).await;
        fx.teardown().await;

        // FAIL CLOSED: a hosted artifact (no upstream facet) under an
        // upstream allowlist policy must be blocked as origin-unknown.
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let svc = PolicyService::new(fx.pool.clone());
        let hosted = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            "org/hosted/1.0/hosted-1.0.bin",
            "org/hosted/1.0/hosted-1.0.bin",
            "hosted",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"payload"),
            fx.user_id,
        )
        .await;
        svc.create_policy(
            &format!("4050-closed-{}", fx.repo_id),
            Some(fx.repo_id),
            "critical",
            false,
            false,
            None,
            None,
            false,
            Some(PolicyPredicates {
                origin: OriginPolicyPredicates {
                    allowed_upstreams: vec!["https://upstream.example.test".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .await
        .expect("create fail-closed policy");
        let closed = svc
            .evaluate_artifact(hosted, fx.repo_id)
            .await
            .expect("evaluate fail-closed");
        assert!(
            !closed.allowed
                && closed
                    .violations
                    .iter()
                    .any(|v| v.contains("[origin.upstream]") && v.contains("unknown")),
            "a hosted artifact under an upstream allowlist must fail closed, got: {closed:?}"
        );
        delete_repo_policies_4058(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
    }
}
