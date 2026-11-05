//! Repository-level serve holds of MCP registries (#5253): the server deny
//! list (every repository type) and, on a Remote, the curation decision
//! (`curation_packages` rows of format `mcp`) and the server-version age gate.
//!
//! The read path (`api::handlers::mcp`) asks [`repo_holds`] for the hold of
//! each row it is about to serve, and feeds the answer to
//! [`decide_mcp_serve`](crate::formats::mcp::decide_mcp_serve) as the
//! version's own hold. Nothing here opens an outbound connection.
//!
//! Curation rows of a Remote MCP registry: one row per server name with
//! `version = '*'` (the name-level decision), plus one row per
//! `name@version` that has a decision of its own (an administrator's pin,
//! or a content-drift re-queue). Precedence, strongest first:
//!
//! 1. a `mcp_server_deny` glob match: denied, whatever was approved;
//! 2. a blocked name: denied;
//! 3. the version's own row: approved serves, blocked denies, a recorded
//!    content drift not yet re-approved holds as drift, anything else is
//!    pending;
//! 4. the name row: approved serves, pending serves only under
//!    `allow_with_gates`, review (flagged) and a missing row are pending.

use std::collections::HashMap;

use sqlx::PgPool;
use uuid::Uuid;

use crate::formats::mcp::{GateOutcome, HoldKind};
use crate::services::age_gate_service::AgeGateRepoParams;
use crate::services::mcp_packages::GateCtx;
use crate::services::mcp_settings;

/// `curation_packages.format` of MCP rows.
pub const FORMAT: &str = "mcp";
/// `curation_packages.version` of a name-level row.
pub const NAME_ROW_VERSION: &str = "*";
/// `curation_packages.metadata` member recording a content drift.
pub const DRIFT_KEY: &str = "contentDrift";

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_APPROVED: &str = "approved";
pub const STATUS_BLOCKED: &str = "blocked";
pub const STATUS_REVIEW: &str = "review";

/// `mcp_remote_posture`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    ApprovalRequired,
    AllowWithGates,
}

impl Posture {
    pub fn parse(s: Option<&str>) -> Self {
        match s {
            Some("allow_with_gates") => Posture::AllowWithGates,
            _ => Posture::ApprovalRequired,
        }
    }
}

/// What a repository's serve holds are evaluated with, loaded once per
/// request (or listing batch).
#[derive(Debug, Clone)]
pub struct ServePolicy {
    /// A Remote repository: curation and the server age gate apply.
    pub remote: bool,
    pub posture: Posture,
    pub deny: Vec<String>,
    /// The Remote's own age-gate parameters (server versions, `first_seen`).
    pub age: Option<AgeGateRepoParams>,
}

impl ServePolicy {
    /// The policy of a hosted repository with this deny list.
    pub fn hosted(deny: Vec<String>) -> Self {
        Self {
            remote: false,
            posture: Posture::ApprovalRequired,
            deny,
            age: None,
        }
    }
}

/// Load the serve policy of repository `repo_id`. `Err` when a setting
/// cannot be read: the caller fails closed.
pub(crate) async fn load_serve_policy(db: &PgPool, repo_id: Uuid) -> Result<ServePolicy, ()> {
    let repo_type: String =
        sqlx::query_scalar("SELECT repo_type::text FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_one(db)
            .await
            .map_err(|_| ())?;
    let settings = mcp_settings::load(db, repo_id, &repo_type)
        .await
        .map_err(|_| ())?;
    let deny = settings.mcp_server_deny.unwrap_or_default();
    if repo_type != "remote" {
        return Ok(ServePolicy::hosted(deny));
    }
    let age = crate::services::age_gate_service::resolve_repo_params(db, repo_id)
        .await
        .map_err(|_| ())?;
    Ok(ServePolicy {
        remote: true,
        posture: Posture::parse(settings.mcp_remote_posture.as_deref()),
        deny,
        age: Some(age),
    })
}

/// One curation row of a server name, as the hold decision reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurationRow {
    pub id: Uuid,
    pub version: String,
    pub status: String,
    /// The row records a content drift (`metadata.contentDrift`).
    pub drift: bool,
}

/// Whether `name` matches the deny list (deny always wins).
pub fn is_denied(deny: &[String], name: &str) -> bool {
    mcp_settings::any_glob_matches(deny, name)
}

/// The curation hold of `name@version` given every curation row of `name`.
/// Pure; see the module docs for the precedence.
pub fn curation_hold(
    policy: &ServePolicy,
    name: &str,
    version: &str,
    rows: &[CurationRow],
) -> Option<HoldKind> {
    let name_row = rows.iter().find(|r| r.version == NAME_ROW_VERSION);
    let name_id = name_row.map(|r| r.id);
    if is_denied(&policy.deny, name) {
        return Some(HoldKind::Denied { review_id: name_id });
    }
    if !policy.remote {
        return None;
    }
    if name_row.is_some_and(|r| r.status == STATUS_BLOCKED) {
        return Some(HoldKind::Denied { review_id: name_id });
    }
    if let Some(v) = rows.iter().find(|r| r.version == version) {
        let review_id = Some(v.id);
        return match v.status.as_str() {
            STATUS_APPROVED => None,
            STATUS_BLOCKED => Some(HoldKind::Denied { review_id }),
            _ if v.drift => Some(HoldKind::ContentDrift { review_id }),
            _ => Some(HoldKind::PendingApproval { review_id }),
        };
    }
    match name_row.map(|r| r.status.as_str()) {
        Some(STATUS_APPROVED) => None,
        Some(STATUS_PENDING) if policy.posture == Posture::AllowWithGates => None,
        _ => Some(HoldKind::PendingApproval { review_id: name_id }),
    }
}

type RowTuple = (Uuid, String, String, String, bool);

/// Every MCP curation row of `names` in `repo_id`, grouped by name.
pub(crate) async fn load_curation_rows(
    db: &PgPool,
    repo_id: Uuid,
    names: &[String],
) -> Result<HashMap<String, Vec<CurationRow>>, ()> {
    let rows: Vec<RowTuple> = sqlx::query_as(
        "SELECT id, package_name, version, status, metadata ? 'contentDrift' \
         FROM curation_packages \
         WHERE staging_repo_id = $1 AND format = 'mcp' AND package_name = ANY($2)",
    )
    .bind(repo_id)
    .bind(names)
    .fetch_all(db)
    .await
    .map_err(|_| ())?;
    let mut out: HashMap<String, Vec<CurationRow>> = HashMap::new();
    for (id, name, version, status, drift) in rows {
        out.entry(name).or_default().push(CurationRow {
            id,
            version,
            status,
            drift,
        });
    }
    Ok(out)
}

/// The server-version age gate's hold for one Remote row.
async fn age_hold(
    ctx: GateCtx<'_>,
    params: &AgeGateRepoParams,
    name: &str,
    version: &str,
) -> Result<Option<HoldKind>, ()> {
    Ok(
        match crate::services::mcp_packages::server_version_age_gate(ctx, params, name, version)
            .await?
        {
            Some(GateOutcome::AgeGate {
                review_id,
                min_age_days,
                requested_age_days,
            }) => Some(HoldKind::AgeGate {
                review_id,
                min_age_days,
                requested_age_days,
            }),
            Some(_) => return Err(()),
            None => None,
        },
    )
}

/// One row the read path is about to serve: `(artifact id, name, version)`.
pub type ServeRow<'a> = (Uuid, &'a str, &'a str);

/// The repository-level hold of each row (absent = none). `Err` when a hold
/// cannot be evaluated: the caller fails closed (`503` on a detail read, the
/// batch omitted from a listing).
pub(crate) async fn repo_holds(
    ctx: GateCtx<'_>,
    policy: &ServePolicy,
    repo_id: Uuid,
    rows: &[ServeRow<'_>],
) -> Result<HashMap<Uuid, HoldKind>, ()> {
    let mut out = HashMap::new();
    if rows.is_empty() {
        return Ok(out);
    }
    let curation = if policy.remote {
        let mut names: Vec<String> = rows.iter().map(|r| r.1.to_string()).collect();
        names.sort();
        names.dedup();
        load_curation_rows(ctx.db, repo_id, &names).await?
    } else {
        HashMap::new()
    };
    for (id, name, version) in rows {
        let found = curation.get(*name).map(Vec::as_slice).unwrap_or_default();
        let mut hold = curation_hold(policy, name, version, found);
        if hold.is_none() {
            if let Some(params) = &policy.age {
                hold = age_hold(ctx, params, name, version).await?;
            }
        }
        if let Some(h) = hold {
            out.insert(*id, h);
        }
    }
    Ok(out)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn remote(posture: Posture, deny: &[&str]) -> ServePolicy {
        ServePolicy {
            remote: true,
            posture,
            deny: deny.iter().map(|s| s.to_string()).collect(),
            age: None,
        }
    }

    fn row(version: &str, status: &str, drift: bool) -> CurationRow {
        CurationRow {
            id: Uuid::new_v4(),
            version: version.into(),
            status: status.into(),
            drift,
        }
    }

    #[test]
    fn posture_parses_with_a_safe_default() {
        assert_eq!(
            Posture::parse(Some("allow_with_gates")),
            Posture::AllowWithGates
        );
        assert_eq!(Posture::parse(Some("x")), Posture::ApprovalRequired);
        assert_eq!(Posture::parse(None), Posture::ApprovalRequired);
    }

    #[test]
    fn deny_wins_everywhere() {
        let approved = [
            row("*", STATUS_APPROVED, false),
            row("1.0.0", STATUS_APPROVED, false),
        ];
        let p = remote(Posture::AllowWithGates, &["com.evil/*"]);
        assert!(matches!(
            curation_hold(&p, "com.evil/x", "1.0.0", &approved),
            Some(HoldKind::Denied { review_id: Some(_) })
        ));
        let hosted = ServePolicy::hosted(vec!["com.evil/*".into()]);
        assert!(matches!(
            curation_hold(&hosted, "Com.Evil/x", "1.0.0", &[]),
            Some(HoldKind::Denied { review_id: None })
        ));
        assert_eq!(curation_hold(&hosted, "com.good/x", "1.0.0", &[]), None);
    }

    #[test]
    fn name_level_decisions_follow_the_posture() {
        let strict = remote(Posture::ApprovalRequired, &[]);
        let gates = remote(Posture::AllowWithGates, &[]);
        let name = |s: &str| vec![row("*", s, false)];
        assert_eq!(
            curation_hold(&strict, "a/b", "1", &name(STATUS_APPROVED)),
            None
        );
        assert!(matches!(
            curation_hold(&strict, "a/b", "1", &name(STATUS_PENDING)),
            Some(HoldKind::PendingApproval { .. })
        ));
        assert_eq!(
            curation_hold(&gates, "a/b", "1", &name(STATUS_PENDING)),
            None
        );
        // A flagged name is held under either posture.
        assert!(matches!(
            curation_hold(&gates, "a/b", "1", &name(STATUS_REVIEW)),
            Some(HoldKind::PendingApproval { .. })
        ));
        assert!(matches!(
            curation_hold(&gates, "a/b", "1", &name(STATUS_BLOCKED)),
            Some(HoldKind::Denied { .. })
        ));
        // No row at all fails closed.
        assert!(matches!(
            curation_hold(&gates, "a/b", "1", &[]),
            Some(HoldKind::PendingApproval { review_id: None })
        ));
    }

    #[test]
    fn version_rows_pin_and_drift() {
        let strict = remote(Posture::ApprovalRequired, &[]);
        // A pin serves one version of an unapproved name.
        let pinned = [
            row("*", STATUS_PENDING, false),
            row("1.0.0", STATUS_APPROVED, false),
        ];
        assert_eq!(curation_hold(&strict, "a/b", "1.0.0", &pinned), None);
        assert!(matches!(
            curation_hold(&strict, "a/b", "2.0.0", &pinned),
            Some(HoldKind::PendingApproval { .. })
        ));
        // Drift revokes a version of an approved name until re-approved.
        let drift = row("1.0.0", STATUS_REVIEW, true);
        let drift_id = drift.id;
        let rows = [row("*", STATUS_APPROVED, false), drift];
        assert_eq!(
            curation_hold(&strict, "a/b", "1.0.0", &rows),
            Some(HoldKind::ContentDrift {
                review_id: Some(drift_id)
            })
        );
        assert_eq!(curation_hold(&strict, "a/b", "1.1.0", &rows), None);
        let reapproved = [
            row("*", STATUS_APPROVED, false),
            row("1.0.0", STATUS_APPROVED, true),
        ];
        assert_eq!(curation_hold(&strict, "a/b", "1.0.0", &reapproved), None);
        // A blocked version, and a blocked name over a pin.
        let blocked = [
            row("*", STATUS_APPROVED, false),
            row("1.0.0", STATUS_BLOCKED, false),
        ];
        assert!(matches!(
            curation_hold(&strict, "a/b", "1.0.0", &blocked),
            Some(HoldKind::Denied { .. })
        ));
        let name_blocked = [
            row("*", STATUS_BLOCKED, false),
            row("1.0.0", STATUS_APPROVED, false),
        ];
        assert!(matches!(
            curation_hold(&strict, "a/b", "1.0.0", &name_blocked),
            Some(HoldKind::Denied { .. })
        ));
        // A version row pending review without drift.
        let pending = [
            row("*", STATUS_APPROVED, false),
            row("1.0.0", STATUS_PENDING, false),
        ];
        assert!(matches!(
            curation_hold(&strict, "a/b", "1.0.0", &pending),
            Some(HoldKind::PendingApproval { .. })
        ));
    }
}
