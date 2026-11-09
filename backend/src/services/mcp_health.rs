//! Server health roll-up of an MCP server version (#5253, Phase 3): one
//! status from the scan results of the packages it pins, their backing
//! gates, and the version's own lint verdict.
//!
//! Precedence: `critical` > `warning` > `unknown` > `ok`.
//!
//! - a package is `critical` when its gate holds it (quarantine, scan
//!   policy, unresolvable) or it has an unacknowledged critical finding;
//!   `warning` for an unacknowledged high/medium finding or an age-gate
//!   hold; `unknown` when it has no completed scan or its gate cannot be
//!   evaluated; `ok` otherwise;
//! - the lint is `critical` with an unacknowledged `block` finding,
//!   `warning` with a `review` finding, `unknown` when it never ran;
//! - a version with packages but no pins (published under `open`) is at
//!   best `unknown`: AK cannot vouch for packages it does not hold.

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::formats::mcp::{GateOutcome, PackagePin, StoredVersion};
use crate::services::mcp_lint::{self, LintSummary};
use crate::services::mcp_packages::{self, GateCtx};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Unknown,
    Warning,
    Critical,
}

/// Unacknowledged findings of a package's current scans, per severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageHealth {
    pub index: usize,
    /// `"npm:@acme/x@1.0.0"`, as refusals name it.
    pub package: String,
    pub registry_type: String,
    /// Backing repository key.
    pub repository: String,
    /// Whether any pinned artifact has a completed scan.
    pub scanned: bool,
    /// `100 - penalties` over the unacknowledged findings (AK's repository
    /// score formula), `None` when unscanned.
    pub score: Option<i32>,
    pub grade: Option<char>,
    #[serde(flatten)]
    pub counts: SeverityCounts,
    /// `allowed | quarantine | scan_policy | age_gate | unresolvable |
    /// unavailable`.
    pub gate: &'static str,
    pub status: HealthStatus,
    /// The pin's warnings (`foreign_coordinates_replaced`, `oci_floating_tag`,
    /// `oci_tag_digest_mismatch`); empty for an unpinned package.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerHealth {
    pub name: String,
    pub version: String,
    pub artifact_id: Uuid,
    pub status: HealthStatus,
    pub package_policy: &'static str,
    pub packages: Vec<PackageHealth>,
    pub lint: LintSummary,
}

pub fn gate_token(g: &GateOutcome) -> &'static str {
    match g {
        GateOutcome::Allowed => "allowed",
        GateOutcome::Quarantine => "quarantine",
        GateOutcome::ScanPolicy => "scan_policy",
        GateOutcome::AgeGate { .. } => "age_gate",
        GateOutcome::Unresolvable => "unresolvable",
        GateOutcome::Shadowed => "shadowed",
        GateOutcome::Unavailable => "unavailable",
    }
}

/// One package's status (pure).
pub fn package_status(gate: &GateOutcome, scanned: bool, c: &SeverityCounts) -> HealthStatus {
    match gate {
        GateOutcome::Quarantine
        | GateOutcome::ScanPolicy
        | GateOutcome::Unresolvable
        | GateOutcome::Shadowed => return HealthStatus::Critical,
        _ if c.critical > 0 => return HealthStatus::Critical,
        GateOutcome::AgeGate { .. } => return HealthStatus::Warning,
        _ => {}
    }
    if c.high > 0 || c.medium > 0 {
        HealthStatus::Warning
    } else if !scanned || *gate == GateOutcome::Unavailable {
        HealthStatus::Unknown
    } else {
        HealthStatus::Ok
    }
}

/// The lint's contribution (pure).
pub fn lint_status(lint: &LintSummary) -> HealthStatus {
    if lint.block > 0 {
        HealthStatus::Critical
    } else if lint.review > 0 {
        HealthStatus::Warning
    } else if !lint.ran {
        HealthStatus::Unknown
    } else {
        HealthStatus::Ok
    }
}

/// The version's status (pure): the worst of its parts. A package with no
/// pin holds the version (`unresolvable`), so it is critical.
pub fn roll_up(packages: &[PackageHealth], lint: &LintSummary, unpinned: bool) -> HealthStatus {
    let floor = if unpinned {
        HealthStatus::Critical
    } else {
        HealthStatus::Ok
    };
    packages
        .iter()
        .map(|p| p.status)
        .chain([lint_status(lint), floor])
        .max()
        .unwrap_or(HealthStatus::Ok)
}

/// `(scanned, counts)` over the current scans of `artifact_ids`.
async fn package_counts(db: &PgPool, artifact_ids: &[Uuid]) -> Result<(bool, SeverityCounts)> {
    if artifact_ids.is_empty() {
        return Ok((false, SeverityCounts::default()));
    }
    let row: (bool, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           EXISTS (SELECT 1 FROM scan_results s WHERE s.artifact_id = ANY($1) \
                     AND s.status = 'completed'), \
           COUNT(*) FILTER (WHERE f.severity = 'critical'), \
           COUNT(*) FILTER (WHERE f.severity = 'high'), \
           COUNT(*) FILTER (WHERE f.severity = 'medium'), \
           COUNT(*) FILTER (WHERE f.severity = 'low'), \
           COUNT(*) FILTER (WHERE f.severity = 'info') \
         FROM scan_findings_effective f \
         WHERE f.artifact_id = ANY($1) AND NOT f.is_acknowledged \
           AND f.scan_result_id IN \
               (SELECT scan_result_id FROM artifact_current_scan_ids(f.artifact_id))",
    )
    .bind(artifact_ids)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok((
        row.0,
        SeverityCounts {
            critical: row.1,
            high: row.2,
            medium: row.3,
            low: row.4,
            info: row.5,
        },
    ))
}

/// The gate of `pin` among `gates` (the backing gates of the version, in
/// pin order after an optional `unresolvable` entry for unpinned packages).
fn gate_of<'a>(gates: &'a [crate::formats::mcp::BackingGate], pin: &PackagePin) -> &'a GateOutcome {
    gates
        .iter()
        .rev()
        .find(|g| g.package == pin.label())
        .map(|g| &g.outcome)
        .unwrap_or(&GateOutcome::Allowed)
}

async fn package_health(
    db: &PgPool,
    pin: &PackagePin,
    gate: &GateOutcome,
) -> Result<PackageHealth> {
    let (scanned, counts) = package_counts(db, &pin.resolved.artifact_ids).await?;
    let (score, grade) = if scanned {
        let (s, g) = crate::services::scan_result_service::compute_security_score(
            counts.critical as i32,
            counts.high as i32,
            counts.medium as i32,
            counts.low as i32,
        );
        (Some(s), Some(g.as_char()))
    } else {
        (None, None)
    };
    Ok(PackageHealth {
        index: pin.index,
        package: pin.label(),
        registry_type: pin.registry_type.clone(),
        repository: pin.resolved.repository.clone(),
        scanned,
        score,
        grade,
        counts,
        gate: gate_token(gate),
        status: package_status(gate, scanned, &counts),
        warnings: pin.resolved.warnings.clone(),
    })
}

/// The entry of a `packages[]` entry no pin covers (#5452): it holds the
/// version `unresolvable`, so it is critical; nothing was resolved, so it
/// names no backing repository and has no scan.
fn unpinned_health(index: usize, package: String, registry_type: &str) -> PackageHealth {
    let gate = GateOutcome::Unresolvable;
    PackageHealth {
        index,
        package,
        registry_type: registry_type.to_string(),
        repository: String::new(),
        scanned: false,
        score: None,
        grade: None,
        counts: SeverityCounts::default(),
        gate: gate_token(&gate),
        status: package_status(&gate, false, &SeverityCounts::default()),
        warnings: Vec::new(),
    }
}

/// The health of the stored server version `artifact_id`.
pub async fn server_health(
    ctx: GateCtx<'_>,
    artifact_id: Uuid,
    stored: &StoredVersion,
) -> Result<ServerHealth> {
    let db = ctx.db;
    let gates = mcp_packages::backing_gates(ctx, stored).await;
    let mut packages = Vec::with_capacity(stored.pins.len());
    for pin in &stored.pins {
        packages.push(package_health(db, pin, gate_of(&gates, pin)).await?);
    }
    let unpinned = stored.unpinned_packages();
    for (index, label) in &unpinned {
        let ty = label.split_once(':').map_or("", |(t, _)| t);
        packages.push(unpinned_health(*index, label.clone(), ty));
    }
    packages.sort_by_key(|p| p.index);
    let lint = mcp_lint::lint_summary(db, artifact_id).await?;
    let unpinned = !unpinned.is_empty();
    Ok(ServerHealth {
        name: stored
            .server
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        version: stored
            .server
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        artifact_id,
        status: roll_up(&packages, &lint, unpinned),
        package_policy: stored.policy.as_str(),
        packages,
        lint,
    })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn counts(critical: i64, high: i64, medium: i64) -> SeverityCounts {
        SeverityCounts {
            critical,
            high,
            medium,
            ..Default::default()
        }
    }

    #[test]
    fn package_statuses() {
        use GateOutcome::*;
        let age = AgeGate {
            review_id: None,
            min_age_days: 7,
            requested_age_days: None,
        };
        let c0 = counts(0, 0, 0);
        for (gate, scanned, c, want) in [
            (Allowed, true, c0, HealthStatus::Ok),
            (Allowed, false, c0, HealthStatus::Unknown),
            (Unavailable, true, c0, HealthStatus::Unknown),
            (Allowed, true, counts(0, 0, 1), HealthStatus::Warning),
            (Allowed, true, counts(0, 2, 0), HealthStatus::Warning),
            (Allowed, true, counts(1, 0, 0), HealthStatus::Critical),
            (age.clone(), true, c0, HealthStatus::Warning),
            (age.clone(), true, counts(1, 0, 0), HealthStatus::Critical),
            (Quarantine, true, c0, HealthStatus::Critical),
            (ScanPolicy, false, c0, HealthStatus::Critical),
            (Unresolvable, false, c0, HealthStatus::Critical),
        ] {
            assert_eq!(
                package_status(&gate, scanned, &c),
                want,
                "{gate:?} {scanned} {c:?}"
            );
        }
        for (g, t) in [
            (Allowed, "allowed"),
            (Quarantine, "quarantine"),
            (ScanPolicy, "scan_policy"),
            (age, "age_gate"),
            (Unresolvable, "unresolvable"),
            (Unavailable, "unavailable"),
        ] {
            assert_eq!(gate_token(&g), t);
        }
    }

    fn pkg(status: HealthStatus) -> PackageHealth {
        PackageHealth {
            index: 0,
            package: "npm:a@1".into(),
            registry_type: "npm".into(),
            repository: "npm-local".into(),
            scanned: true,
            score: Some(100),
            grade: Some('A'),
            counts: SeverityCounts::default(),
            gate: "allowed",
            status,
            warnings: Vec::new(),
        }
    }

    /// #5452: a package with no pin is an `unresolvable`, critical entry and
    /// floors the version at critical.
    #[test]
    fn an_unpinned_package_is_critical() {
        let p = unpinned_health(2, "npm:@evil/x@1.0.0".into(), "npm");
        assert_eq!(
            (p.index, p.gate, p.status, p.repository.as_str()),
            (2, "unresolvable", HealthStatus::Critical, "")
        );
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("warnings").is_none());
        let mut warned = pkg(HealthStatus::Ok);
        warned.warnings = vec!["foreign_coordinates_replaced".into()];
        assert_eq!(
            serde_json::to_value(&warned).unwrap()["warnings"],
            serde_json::json!(["foreign_coordinates_replaced"])
        );
    }

    #[test]
    fn roll_up_takes_the_worst() {
        let ran = LintSummary {
            ran: true,
            ..Default::default()
        };
        assert_eq!(lint_status(&LintSummary::default()), HealthStatus::Unknown);
        assert_eq!(lint_status(&ran), HealthStatus::Ok);
        let review = LintSummary {
            review: 1,
            ..ran.clone()
        };
        let block = LintSummary {
            block: 1,
            ..review.clone()
        };
        assert_eq!(lint_status(&review), HealthStatus::Warning);
        assert_eq!(lint_status(&block), HealthStatus::Critical);

        assert_eq!(roll_up(&[], &ran, false), HealthStatus::Ok);
        assert_eq!(roll_up(&[], &ran, true), HealthStatus::Critical);
        assert_eq!(
            roll_up(&[pkg(HealthStatus::Ok)], &review, false),
            HealthStatus::Warning
        );
        assert_eq!(
            roll_up(
                &[pkg(HealthStatus::Unknown), pkg(HealthStatus::Warning)],
                &ran,
                false
            ),
            HealthStatus::Warning
        );
        assert_eq!(
            roll_up(&[pkg(HealthStatus::Critical)], &ran, true),
            HealthStatus::Critical
        );
        assert_eq!(
            serde_json::to_value(pkg(HealthStatus::Ok)).unwrap()["critical"],
            0,
            "counts are flattened"
        );
    }
}
