//! Virtual MCP registries (#5253, Phase 2): `/mcp/{virtual}/v0.1/...`
//! answered from the members' stored server versions.
//!
//! A Virtual resolves nothing itself and never contacts an upstream: every
//! row is a member's stored row, decided by that member's own gates through
//! the same per-repository functions the hosted and Remote read paths use
//! ([`mcp::walk_candidates`] for a detail, [`mcp::servable`] for a listing),
//! so a hold expressed there applies through a Virtual unchanged.
//!
//! Serving order: the hosted members (Local, Staging) in priority order, then
//! the Remote members in priority order.
//!
//! - **Detail** (`/versions/{v}`, `latest`): the first member in that order
//!   that serves the name/version answers. A name any hosted member holds
//!   (any version, any state, whether or not this caller may read that
//!   member) is never answered from a Remote member: hosted shadows remote,
//!   the dependency-confusion rule.
//! - **Listing**: each `(name, version)` once, from the member a detail read
//!   would answer it from, member by member in serving order, each member's
//!   rows in its own `name, version` keyset order. The cursor is
//!   `base64url("m:{member_key}:{member_cursor}")`.
//! - **Writes**: `405 mcp_read_only`; publish to a hosted member.

use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use axum::response::Response;
use base64::Engine as _;
use uuid::Uuid;

use super::mcp::{self, CandidateWalk, ListQuery, VersionRow};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::formats::mcp::{
    self as fmt, GateAudience, HoldKind, McpError, ServeDecision, ServerStatus, VersionState,
};
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::mcp_packages::GateCtx;

type HandlerResult = Result<Response, Response>;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Stable partition into serving order: hosted members first, then the rest,
/// each keeping its priority order.
pub fn serving_order<T>(members: Vec<T>, is_hosted: impl Fn(&T) -> bool) -> Vec<T> {
    let (mut hosted, remote): (Vec<T>, Vec<T>) = members.into_iter().partition(|m| is_hosted(m));
    hosted.extend(remote);
    hosted
}

/// `base64url("m:{member_key}:{member_cursor}")`; an empty member cursor
/// resumes at the start of that member.
pub fn encode_member_cursor(member_key: &str, member_cursor: Option<&str>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("m:{member_key}:{}", member_cursor.unwrap_or("")))
}

/// Inverse of [`encode_member_cursor`]: the member key and its own cursor
/// (`None` = start of that member). Anything else is the listing's `400`.
pub fn decode_member_cursor(cursor: &str) -> Result<(String, Option<String>), McpError> {
    let bad = || McpError::invalid("cursor", "invalid cursor");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.trim_end_matches('='))
        .map_err(|_| bad())?;
    let text = String::from_utf8(raw).map_err(|_| bad())?;
    let rest = text.strip_prefix("m:").ok_or_else(bad)?;
    // A member cursor is base64url (no `:`), so the last `:` separates it.
    let (key, inner) = rest.rsplit_once(':').ok_or_else(bad)?;
    if key.is_empty() {
        return Err(bad());
    }
    Ok((
        key.to_string(),
        (!inner.is_empty()).then(|| inner.to_string()),
    ))
}

/// Where a listing starts: the member index and that member's keyset
/// position. An unknown member key (a member removed between pages, or a
/// forged cursor) is the listing's `400`.
pub fn start_position(
    keys: &[&str],
    cursor: Option<(String, Option<String>)>,
) -> Result<(usize, Option<(String, String)>), McpError> {
    let Some((key, inner)) = cursor else {
        return Ok((0, None));
    };
    let idx = keys
        .iter()
        .position(|k| *k == key)
        .ok_or_else(|| McpError::invalid("cursor", "invalid cursor"))?;
    let inner = inner.map(|c| fmt::decode_cursor(&c)).transpose()?;
    Ok((idx, inner))
}

/// Indices of the members that may answer `name`: the hosted ones when any
/// hosted member (readable by this caller or not) holds the name, otherwise
/// the Remote ones.
pub fn owner_indices(hosted: &[bool], hosted_owns_name: bool) -> Vec<usize> {
    hosted
        .iter()
        .enumerate()
        .filter(|(_, h)| **h == hosted_owns_name)
        .map(|(i, _)| i)
        .collect()
}

/// Add the Virtual's key to a member's served entry (`_meta` source block).
pub fn mark_virtual(mut entry: serde_json::Value, virtual_key: &str) -> serde_json::Value {
    if let Some(src) = entry
        .get_mut("_meta")
        .and_then(|m| m.get_mut(fmt::AK_SOURCE_META_KEY))
        .and_then(|s| s.as_object_mut())
    {
        src.insert("virtualRepository".into(), virtual_key.into());
    }
    entry
}

/// A Virtual accepts no write.
pub(crate) fn reject_write_if_virtual(repo: &RepoInfo) -> Result<(), Response> {
    if repo.repo_type != "virtual" {
        return Ok(());
    }
    Err(mcp::problem(
        405,
        "mcp_read_only",
        "This repository does not accept writes (virtual repository); publish to one of its \
         hosted members",
        serde_json::json!({}),
    ))
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

/// A Virtual's MCP members for one caller.
pub(crate) struct Members {
    /// Members this caller may read, in serving order.
    pub(crate) order: Vec<RepoInfo>,
    /// Parallel to `order`: whether the member is hosted.
    pub(crate) hosted: Vec<bool>,
    /// Every hosted member, readable by this caller or not: the
    /// shadowing set (an enforcement walk is never narrowed by the caller).
    pub(crate) hosted_all: Vec<Uuid>,
    /// The Virtual's own `mcp_server_deny`.
    pub(crate) deny: Vec<String>,
}

fn is_hosted_type(t: &RepositoryType) -> bool {
    matches!(t, RepositoryType::Local | RepositoryType::Staging)
}

pub(crate) async fn load_members(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_repo: &RepoInfo,
) -> Result<Members, Response> {
    let all: Vec<_> = proxy_helpers::fetch_virtual_members(&state.db, virtual_repo.id)
        .await
        .map_err(mcp::reproblem)?
        .into_iter()
        .filter(|m| m.format == RepositoryFormat::Mcp)
        .collect();
    let hosted_all = all
        .iter()
        .filter(|m| is_hosted_type(&m.repo_type))
        .map(|m| m.id)
        .collect();
    let readable =
        proxy_helpers::try_authorize_virtual_members(&state.db, auth, virtual_repo.id, all)
            .await
            .map_err(mcp::reproblem)?;
    let readable = serving_order(readable, |m| is_hosted_type(&m.repo_type));
    let hosted = readable
        .iter()
        .map(|m| is_hosted_type(&m.repo_type))
        .collect();
    let order = readable
        .iter()
        .map(proxy_helpers::repo_info_from_member)
        .collect();
    let deny = crate::services::mcp_settings::load(&state.db, virtual_repo.id, "virtual")
        .await
        .map_err(|e| mcp::internal(e.to_string()))?
        .mcp_server_deny
        .unwrap_or_default();
    Ok(Members {
        order,
        hosted,
        hosted_all,
        deny,
    })
}

impl Members {
    fn denies(&self, name: &str) -> bool {
        crate::services::mcp_settings::any_glob_matches(&self.deny, name)
    }

    fn keys(&self) -> Vec<&str> {
        self.order.iter().map(|m| m.key.as_str()).collect()
    }
}

/// The names among `names` some hosted member holds (any live row).
async fn hosted_owned_names(
    state: &SharedState,
    members: &Members,
    names: &[String],
) -> Result<HashSet<String>, Response> {
    if members.hosted_all.is_empty() || names.is_empty() {
        return Ok(HashSet::new());
    }
    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT a.name FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = ANY($1) AND a.name = ANY($2) AND a.is_deleted = false \
           AND m.format = 'mcp'",
    )
    .bind(&members.hosted_all)
    .bind(names)
    .fetch_all(&state.db)
    .await
    .map_err(mcp::internal)?;
    Ok(owned.into_iter().collect())
}

async fn owners_of(
    state: &SharedState,
    members: &Members,
    name: &str,
) -> Result<Vec<usize>, Response> {
    let owned = hosted_owned_names(state, members, &[name.to_string()]).await?;
    Ok(owner_indices(&members.hosted, owned.contains(name)))
}

/// The member and row `latest` answers for `name` through the Virtual: the
/// first owning member with a servable newest version (reader-only gate),
/// and how many members were evaluated.
async fn virtual_latest(
    state: &SharedState,
    members: &Members,
    owners: &[usize],
    name: &str,
) -> Result<(Option<(usize, VersionRow)>, usize), Response> {
    let ctx = GateCtx::of(state, false);
    let mut walked = 0;
    for &idx in owners {
        let m = &members.order[idx];
        walked += 1;
        let rows = mcp::versions_of(&state.db, m.id, name).await?;
        if rows.is_empty() {
            continue;
        }
        let policy = mcp::current_policy(&state.db, m.id).await;
        if let (Some(row), _) = mcp::newest_servable(ctx, m.id, rows, &HashSet::new(), policy).await
        {
            return Ok((Some((idx, row)), walked));
        }
    }
    Ok((None, walked))
}

/// The refusal for a name the Virtual's own `mcp_server_deny` matches.
async fn denied_refusal(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_repo: &RepoInfo,
    name: &str,
    version: &str,
    base: &str,
) -> Response {
    let audience = mcp::audience(&state.db, auth, virtual_repo.id).await;
    let decision = fmt::decide_mcp_serve(
        &VersionState {
            name: name.to_string(),
            version: version.to_string(),
            status: ServerStatus::Active,
            own_hold: Some(HoldKind::Denied { review_id: None }),
            include_deleted: false,
            instance: mcp::instance_url(base, &virtual_repo.key, name, version),
        },
        &[],
        audience,
    );
    match decision {
        ServeDecision::Refuse { status, body, .. } if audience == GateAudience::ReasonGated => {
            mcp::refusal_bytes(status, serde_json::to_vec(&body).unwrap_or_default())
        }
        _ => mcp::not_found(),
    }
}

// ---------------------------------------------------------------------------
// GET /servers/{name}/versions/{version}
// ---------------------------------------------------------------------------

pub(crate) async fn get_version(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_repo: &RepoInfo,
    name: &str,
    version: &str,
    include_deleted: bool,
    base: &str,
) -> HandlerResult {
    let members = load_members(state, auth, virtual_repo).await?;
    if members.denies(name) {
        return Err(denied_refusal(state, auth, virtual_repo, name, version, base).await);
    }
    let owners = owners_of(state, &members, name).await?;
    let is_latest = version == "latest";
    let mut first_refusal: Option<Response> = None;
    for &idx in &owners {
        let m = &members.order[idx];
        let audience = mcp::audience(&state.db, auth, m.id).await;
        let walk = mcp::walk_candidates(
            state,
            auth,
            m,
            name,
            version,
            include_deleted,
            audience,
            base,
        )
        .await?;
        match walk {
            CandidateWalk::Served { row, .. } => {
                let latest = is_latest
                    || virtual_latest(state, &members, &owners, name)
                        .await?
                        .0
                        .is_some_and(|(_, l)| l.artifact_id == row.artifact_id);
                let mut entry = mcp::served_entry(&row, m, base, latest);
                super::mcp_write::ticket_bundle_urls(state, auth, &row.stored, &mut entry, base)
                    .await;
                return Ok(mcp::json_ok(
                    StatusCode::OK,
                    &mark_virtual(entry, &virtual_repo.key),
                ));
            }
            // An unevaluable gate fails closed: never fall past it to a
            // lower-priority member.
            CandidateWalk::Refused(resp) if resp.status() == StatusCode::SERVICE_UNAVAILABLE => {
                return Err(resp)
            }
            // A reader's refusal is byte for byte the unknown-name answer;
            // only a reason a member's holder may read is kept.
            CandidateWalk::Refused(resp) => {
                let keep = audience == GateAudience::ReasonGated
                    && !(is_latest && first_refusal.is_some());
                if keep && first_refusal.is_none() {
                    first_refusal = Some(resp);
                }
            }
            CandidateWalk::NotFound => {}
        }
    }
    Err(first_refusal.unwrap_or_else(mcp::not_found))
}

// ---------------------------------------------------------------------------
// GET /servers/{name}/versions
// ---------------------------------------------------------------------------

pub(crate) async fn list_versions(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_repo: &RepoInfo,
    name: &str,
    include_deleted: bool,
    base: &str,
) -> HandlerResult {
    let members = load_members(state, auth, virtual_repo).await?;
    if members.denies(name) {
        return Err(mcp::not_found());
    }
    let owners = owners_of(state, &members, name).await?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut picked: Vec<(usize, VersionRow)> = Vec::new();
    let mut latest: Option<Uuid> = None;
    for &idx in &owners {
        let served =
            mcp::servable_versions(state, &members.order[idx], name, include_deleted).await?;
        if latest.is_none() {
            latest = mcp::latest_candidates(served.clone())
                .first()
                .map(|r| r.artifact_id);
        }
        for row in served {
            if seen.insert(row.version.clone()) {
                picked.push((idx, row));
            }
        }
    }
    if picked.is_empty() {
        return Err(mcp::not_found());
    }
    picked.sort_by(|a, b| a.1.version.cmp(&b.1.version));
    let entries = picked
        .iter()
        .map(|(idx, r)| {
            let entry =
                mcp::served_entry(r, &members.order[*idx], base, Some(r.artifact_id) == latest);
            mark_virtual(entry, &virtual_repo.key)
        })
        .collect();
    Ok(mcp::json_ok(
        StatusCode::OK,
        &fmt::list_envelope(entries, None),
    ))
}

// ---------------------------------------------------------------------------
// GET /servers
// ---------------------------------------------------------------------------

pub(crate) async fn list_servers(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_repo: &RepoInfo,
    query: &HashMap<String, String>,
    base: &str,
) -> HandlerResult {
    // The composite cursor is the Virtual's own; the rest of the query is
    // parsed with the hosted rules.
    let mut rest = query.clone();
    let cursor = rest
        .remove("cursor")
        .filter(|c| !c.is_empty())
        .map(|c| decode_member_cursor(&c))
        .transpose()
        .map_err(mcp::mcp_error)?;
    let q = mcp::parse_list_query(&rest).map_err(mcp::mcp_error)?;
    let members = load_members(state, auth, virtual_repo).await?;
    let start = start_position(&members.keys(), cursor).map_err(mcp::mcp_error)?;
    let page = if q.version.as_deref() == Some("latest") {
        list_latest(state, &members, &q, start).await?
    } else {
        list_page(state, &members, &q, start).await?
    };
    let latest = page_latest_ids(state, &members, &page.rows, page.all_latest).await?;
    let entries = page
        .rows
        .iter()
        .map(|(idx, r)| {
            let entry = mcp::served_entry(
                r,
                &members.order[*idx],
                base,
                latest.contains(&r.artifact_id),
            );
            mark_virtual(entry, &virtual_repo.key)
        })
        .collect();
    Ok(mcp::json_ok(
        StatusCode::OK,
        &fmt::list_envelope(entries, page.next),
    ))
}

/// One listing page: rows with the index of the member each came from.
struct Page {
    rows: Vec<(usize, VersionRow)>,
    next: Option<String>,
    /// Every row is its server's latest (`version=latest`).
    all_latest: bool,
}

/// Where the next page resumes: a member and its own cursor.
fn resume_cursor(members: &Members, idx: usize, after: Option<&(String, String)>) -> String {
    let inner = after.map(|(n, v)| fmt::encode_cursor(n, v));
    encode_member_cursor(&members.order[idx].key, inner.as_deref())
}

/// The artifact ids among `rows` that are their server's latest through
/// the Virtual.
async fn page_latest_ids(
    state: &SharedState,
    members: &Members,
    rows: &[(usize, VersionRow)],
    all_latest: bool,
) -> Result<HashSet<Uuid>, Response> {
    if all_latest {
        return Ok(rows.iter().map(|(_, r)| r.artifact_id).collect());
    }
    let names: Vec<String> = rows
        .iter()
        .map(|(_, r)| r.name.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let owned = hosted_owned_names(state, members, &names).await?;
    let mut out = HashSet::new();
    for name in &names {
        let owners = owner_indices(&members.hosted, owned.contains(name));
        if let (Some((_, row)), _) = virtual_latest(state, members, &owners, name).await? {
            out.insert(row.artifact_id);
        }
    }
    Ok(out)
}

/// Rows of `repo_id` with one of `pairs` as `(name, version)`, `deleted`
/// excluded unless `include_deleted`.
async fn rows_matching(
    state: &SharedState,
    repo_id: Uuid,
    pairs: &[(String, String)],
    include_deleted: bool,
) -> Result<Vec<VersionRow>, Response> {
    let names: Vec<&str> = pairs.iter().map(|p| p.0.as_str()).collect();
    let versions: Vec<&str> = pairs.iter().map(|p| p.1.as_str()).collect();
    let sql = format!(
        "SELECT {} FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.is_deleted = false AND m.format = 'mcp' \
           AND (a.name, a.version) IN (SELECT * FROM UNNEST($2::text[], $3::text[])) \
           AND ($4 OR COALESCE(m.metadata->'registry'->>'status', 'active') <> 'deleted')",
        mcp::ROW_COLUMNS
    );
    let raw: Vec<mcp::RawRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(repo_id)
        .bind(&names)
        .bind(&versions)
        .bind(include_deleted)
        .fetch_all(&state.db)
        .await
        .map_err(mcp::internal)?;
    Ok(mcp::rows_from_raw(raw))
}

/// Drop the rows of member `idx` a detail read would answer from another
/// member: a name a hosted member holds (for a Remote member), and a
/// `(name, version)` an earlier member of the same kind serves. Names the
/// Virtual denies go too.
async fn drop_shadowed(
    state: &SharedState,
    members: &Members,
    idx: usize,
    rows: Vec<VersionRow>,
    include_deleted: bool,
) -> Result<Vec<VersionRow>, Response> {
    let mut rows: Vec<VersionRow> = rows
        .into_iter()
        .filter(|r| !members.denies(&r.name))
        .collect();
    if rows.is_empty() {
        return Ok(rows);
    }
    let hosted = members.hosted[idx];
    if !hosted {
        let names: Vec<String> = rows.iter().map(|r| r.name.clone()).collect();
        let owned = hosted_owned_names(state, members, &names).await?;
        rows.retain(|r| !owned.contains(&r.name));
    }
    let ctx = GateCtx::of(state, false);
    for earlier in (0..idx).filter(|&j| members.hosted[j] == hosted) {
        if rows.is_empty() {
            break;
        }
        let pairs: Vec<(String, String)> = rows
            .iter()
            .map(|r| (r.name.clone(), r.version.clone()))
            .collect();
        let m = &members.order[earlier];
        let theirs = rows_matching(state, m.id, &pairs, include_deleted).await?;
        if theirs.is_empty() {
            continue;
        }
        let policy = mcp::current_policy(&state.db, m.id).await;
        let served: HashSet<(String, String)> = mcp::servable(ctx, m.id, theirs, policy)
            .await
            .into_iter()
            .map(|r| (r.name, r.version))
            .collect();
        rows.retain(|r| !served.contains(&(r.name.clone(), r.version.clone())));
    }
    Ok(rows)
}

async fn list_page(
    state: &SharedState,
    members: &Members,
    q: &ListQuery,
    start: (usize, Option<(String, String)>),
) -> Result<Page, Response> {
    let want = q.limit as usize;
    let ctx = GateCtx::of(state, false);
    let mut out: Vec<(usize, VersionRow)> = Vec::new();
    let mut read = 0usize;
    let mut resume: Option<String> = None;
    'members: for idx in start.0..members.order.len() {
        let m = &members.order[idx];
        let policy = mcp::current_policy(&state.db, m.id).await;
        let mut after = if idx == start.0 {
            start.1.clone()
        } else {
            None
        };
        loop {
            let batch =
                mcp::fetch_listing_batch(&state.db, m.id, q, after.as_ref(), q.limit + 1).await?;
            read += batch.raw_len;
            let exhausted = (batch.raw_len as i64) <= q.limit;
            if let Some(last) = batch.last {
                after = Some(last);
            }
            let rows = mcp::servable(ctx, m.id, batch.rows, policy).await;
            let rows = drop_shadowed(state, members, idx, rows, q.include_deleted).await?;
            out.extend(rows.into_iter().map(|r| (idx, r)));
            if out.len() > want {
                break 'members;
            }
            if read >= mcp::MAX_LISTING_ROWS {
                // The row bound stopped the scan: resume where it stopped
                // rather than presenting a short last page.
                if !exhausted {
                    resume = Some(resume_cursor(members, idx, after.as_ref()));
                } else if idx + 1 < members.order.len() {
                    resume = Some(resume_cursor(members, idx + 1, None));
                }
                break 'members;
            }
            if exhausted {
                break;
            }
        }
    }
    let next = if out.len() > want {
        let (idx, last) = &out[want - 1];
        Some(resume_cursor(
            members,
            *idx,
            Some(&(last.name.clone(), last.version.clone())),
        ))
    } else {
        resume
    };
    out.truncate(want);
    Ok(Page {
        rows: out,
        next,
        all_latest: false,
    })
}

/// `version=latest`: one entry per name, from the member `latest` answers it
/// from, emitted in that member's phase.
async fn list_latest(
    state: &SharedState,
    members: &Members,
    q: &ListQuery,
    start: (usize, Option<(String, String)>),
) -> Result<Page, Response> {
    let want = q.limit as usize;
    let mut out: Vec<(usize, VersionRow)> = Vec::new();
    let mut budget = mcp::MAX_LATEST_BUDGET;
    let mut next: Option<String> = None;
    'members: for idx in start.0..members.order.len() {
        let m = &members.order[idx];
        let mut name_after = if idx == start.0 {
            start.1.as_ref().map(|(n, _)| n.clone())
        } else {
            None
        };
        loop {
            let names = mcp::fetch_server_names(
                &state.db,
                m.id,
                q.search.as_deref(),
                name_after.as_deref(),
                (want + 1) as i64,
            )
            .await?;
            let names_exhausted = names.len() <= want;
            let owned = hosted_owned_names(state, members, &names).await?;
            for name in names {
                if out.len() == want || budget == 0 {
                    let after = name_after.as_ref().map(|n| (n.clone(), "-".to_string()));
                    next = Some(resume_cursor(members, idx, after.as_ref()));
                    break 'members;
                }
                if !members.denies(&name) {
                    let owners = owner_indices(&members.hosted, owned.contains(&name));
                    let (picked, walked) = virtual_latest(state, members, &owners, &name).await?;
                    budget = budget.saturating_sub(walked.max(1));
                    if let Some((owner, row)) = picked.filter(|(owner, r)| {
                        *owner == idx
                            && q.updated_since
                                .is_none_or(|since| r.stored.registry.updated_at >= since)
                    }) {
                        out.push((owner, row));
                    }
                }
                name_after = Some(name);
            }
            if names_exhausted {
                break;
            }
        }
    }
    Ok(Page {
        rows: out,
        next,
        all_latest: true,
    })
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serving_order_puts_hosted_first_and_keeps_priority() {
        let members = vec![("r1", false), ("l1", true), ("r2", false), ("l2", true)];
        let ordered: Vec<&str> = serving_order(members, |m| m.1)
            .into_iter()
            .map(|m| m.0)
            .collect();
        assert_eq!(ordered, vec!["l1", "l2", "r1", "r2"]);
    }

    #[test]
    fn member_cursor_round_trips_and_rejects_garbage() {
        let inner = fmt::encode_cursor("com.acme/x", "1.0.0");
        let c = encode_member_cursor("mcp-local", Some(&inner));
        assert_eq!(
            decode_member_cursor(&c).unwrap(),
            ("mcp-local".to_string(), Some(inner.clone()))
        );
        let start = encode_member_cursor("mcp-remote", None);
        assert_eq!(
            decode_member_cursor(&start).unwrap(),
            ("mcp-remote".to_string(), None)
        );
        for garbage in [
            "!!!",
            "bm90LWEtY3Vyc29y",
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("m::abc"),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("m:nokey"),
            &inner,
        ] {
            assert!(decode_member_cursor(garbage).is_err(), "{garbage}");
        }
    }

    #[test]
    fn start_position_finds_the_member_and_its_keyset() {
        let keys = ["a", "b"];
        assert_eq!(start_position(&keys, None).unwrap(), (0, None));
        let inner = fmt::encode_cursor("n/x", "2");
        assert_eq!(
            start_position(&keys, Some(("b".into(), Some(inner)))).unwrap(),
            (1, Some(("n/x".to_string(), "2".to_string())))
        );
        assert_eq!(
            start_position(&keys, Some(("b".into(), None))).unwrap(),
            (1, None)
        );
        assert!(start_position(&keys, Some(("gone".into(), None))).is_err());
        assert!(start_position(&keys, Some(("a".into(), Some("%%".into())))).is_err());
    }

    #[test]
    fn owners_are_hosted_when_a_hosted_member_holds_the_name() {
        let hosted = [true, true, false];
        assert_eq!(owner_indices(&hosted, true), vec![0, 1]);
        assert_eq!(owner_indices(&hosted, false), vec![2]);
        assert!(owner_indices(&[false], true).is_empty());
    }

    #[test]
    fn mark_virtual_annotates_the_source_block_only() {
        let entry = serde_json::json!({
            "server": {"name": "a/b"},
            "_meta": {fmt::AK_SOURCE_META_KEY: {"repository": "m1"}},
        });
        let out = mark_virtual(entry, "v1");
        assert_eq!(
            out["_meta"][fmt::AK_SOURCE_META_KEY]["virtualRepository"],
            "v1"
        );
        assert_eq!(out["_meta"][fmt::AK_SOURCE_META_KEY]["repository"], "m1");
        let bare = mark_virtual(serde_json::json!({"server": {}}), "v1");
        assert!(bare.get("_meta").is_none());
    }

    // -----------------------------------------------------------------------
    // DB-backed: a Virtual over hosted and Remote members
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::{Body, Bytes};
    use axum::http::{HeaderMap, Request};
    use axum::Router;

    struct Env {
        fx: tdh::Fixture,
        members: Vec<(Uuid, String, std::path::PathBuf)>,
    }

    fn server_doc(name: &str, version: &str, description: &str) -> serde_json::Value {
        serde_json::json!({
            "$schema": fmt::SCHEMA_URL,
            "name": name,
            "description": description,
            "version": version,
            "remotes": [{"type": "streamable-http", "url": "https://mcp.acme.test/mcp"}],
        })
    }

    fn body_json(b: &Bytes) -> serde_json::Value {
        serde_json::from_slice(b).unwrap_or(serde_json::Value::Null)
    }

    impl Env {
        async fn new() -> Option<Self> {
            Some(Self {
                fx: tdh::Fixture::setup("virtual", "mcp").await?,
                members: Vec::new(),
            })
        }

        /// A member of `repo_type` at `priority`, readable by the fixture
        /// user when `readable`, with the `open` package policy.
        async fn member(&mut self, repo_type: &str, priority: i32, readable: bool) -> usize {
            let pool = &self.fx.pool;
            let (id, key, dir) = tdh::create_repo(pool, repo_type, "mcp").await;
            sqlx::query(
                "INSERT INTO repository_config (repository_id, key, value) \
                 VALUES ($1, 'mcp_package_policy', 'open')",
            )
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
            if readable {
                tdh::grant_repo_access(pool, id, self.fx.user_id).await;
            }
            tdh::link_virtual_member(pool, self.fx.repo_id, id, priority).await;
            self.members.push((id, key, dir));
            self.members.len() - 1
        }

        fn app(&self) -> Router {
            self.fx.router_with_auth(super::super::mcp::router())
        }

        async fn call(
            &self,
            method: &str,
            uri: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, Bytes, HeaderMap) {
            let mut b = Request::builder().method(method).uri(uri);
            if body.is_some() {
                b = b.header("content-type", "application/json");
            }
            let body = body
                .map(|v| Body::from(serde_json::to_vec(&v).unwrap()))
                .unwrap_or_else(Body::empty);
            tdh::send_with_headers(self.app(), b.body(body).unwrap()).await
        }

        /// Store `name@version` in member `m`. A Remote member's rows are
        /// written by its sync in production; here a hosted publish into a
        /// scratch repository is moved under it.
        async fn store(&self, m: usize, name: &str, version: &str, description: &str) -> Uuid {
            let (id, key, _) = &self.members[m];
            let remote: bool = sqlx::query_scalar(
                "SELECT repo_type::text = 'remote' FROM repositories WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&self.fx.pool)
            .await
            .unwrap();
            if remote {
                self.set_type(*id, "local").await;
            }
            // Seeded as an instance administrator: the fixture user may hold
            // no grant on the member (an unreadable member), and the namespace
            // write gate refuses a role-less publish.
            let admin = tdh::router_with_auth(
                super::super::mcp::router(),
                self.fx.state.clone(),
                tdh::admin_auth(self.fx.user_id, &self.fx.username),
            );
            let req = Request::builder()
                .method("POST")
                .uri(format!("/{key}/v0.1/publish"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&server_doc(name, version, description)).unwrap(),
                ))
                .unwrap();
            let (s, b, _) = tdh::send_with_headers(admin, req).await;
            if remote {
                self.set_type(*id, "remote").await;
                // A Remote serves only names its curation approved.
                sqlx::query(
                    "INSERT INTO curation_packages \
                       (staging_repo_id, remote_repo_id, format, package_name, version, \
                        upstream_path, status, evaluated_at) \
                     VALUES ($1, $1, 'mcp', $2, '*', $2, 'approved', now()) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(id)
                .bind(name)
                .execute(&self.fx.pool)
                .await
                .unwrap();
            }
            assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            tdh::artifact_id_at(&self.fx.pool, *id, &fmt::storage_path(name, version)).await
        }

        async fn set_type(&self, id: Uuid, repo_type: &str) {
            sqlx::query("UPDATE repositories SET repo_type = $2::repository_type WHERE id = $1")
                .bind(id)
                .bind(repo_type)
                .execute(&self.fx.pool)
                .await
                .unwrap();
        }

        async fn get(&self, tail: &str) -> (StatusCode, serde_json::Value) {
            let (s, b, _) = self
                .call("GET", &format!("/{}/v0.1{tail}", self.fx.repo_key), None)
                .await;
            (s, body_json(&b))
        }

        async fn hold(&self, artifact_id: Uuid) {
            sqlx::query(
                "UPDATE artifacts SET quarantine_status = 'quarantined', \
                 quarantine_source = 'admin', quarantine_until = NULL WHERE id = $1",
            )
            .bind(artifact_id)
            .execute(&self.fx.pool)
            .await
            .unwrap();
        }

        async fn teardown(self) {
            for (id, _, dir) in &self.members {
                let _ = sqlx::query("DELETE FROM packages WHERE repository_id = $1")
                    .bind(id)
                    .execute(&self.fx.pool)
                    .await;
                tdh::cleanup_member_repo(&self.fx.pool, *id, dir).await;
            }
            self.fx.teardown().await;
        }
    }

    fn descriptions(list: &serde_json::Value) -> Vec<String> {
        list["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}@{}={}",
                    e["server"]["name"].as_str().unwrap(),
                    e["server"]["version"].as_str().unwrap(),
                    e["server"]["description"].as_str().unwrap()
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn detail_is_first_member_that_serves() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let l1 = env.member("local", 1, true).await;
        let l2 = env.member("local", 2, true).await;
        let held = env.store(l1, "com.acme/x", "1.0.0", "from-l1").await;
        env.store(l2, "com.acme/x", "1.0.0", "from-l2").await;
        env.store(l2, "com.acme/x", "2.0.0", "from-l2").await;

        let (s, b) = env.get("/servers/com.acme%2Fx/versions/1.0.0").await;
        assert_eq!(
            (s, b["server"]["description"].as_str()),
            (StatusCode::OK, Some("from-l1"))
        );
        let src = &b["_meta"][fmt::AK_SOURCE_META_KEY];
        assert_eq!(src["repository"], env.members[l1].1);
        assert_eq!(src["virtualRepository"], env.fx.repo_key);

        // First match by priority, not newest across members.
        let (s, b) = env.get("/servers/com.acme/x/versions/latest").await;
        assert_eq!(
            (s, b["server"]["version"].as_str()),
            (StatusCode::OK, Some("1.0.0"))
        );
        assert_eq!(b["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"], true);

        // A held version falls through to the next member that serves it.
        env.hold(held).await;
        let (s, b) = env.get("/servers/com.acme/x/versions/1.0.0").await;
        assert_eq!(
            (s, b["server"]["description"].as_str()),
            (StatusCode::OK, Some("from-l2"))
        );
        let (_, b) = env.get("/servers/com.acme/x/versions/latest").await;
        assert_eq!(b["server"]["version"], "2.0.0");

        // /versions: the union, each version once, latest marked.
        let (s, b) = env.get("/servers/com.acme/x/versions").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            descriptions(&b),
            vec!["com.acme/x@1.0.0=from-l2", "com.acme/x@2.0.0=from-l2"]
        );
        assert_eq!(
            b["servers"][1]["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"],
            true
        );

        let (s, b) = env.get("/servers/com.acme/x/versions/9.9.9").await;
        assert_eq!((s, b), (StatusCode::NOT_FOUND, fmt::not_found_value()));
        let (s, _) = env.get("/servers/com.acme/none/versions").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        env.teardown().await;
    }

    #[tokio::test]
    async fn hosted_shadows_remote_even_when_unreadable() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let r1 = env.member("remote", 1, true).await;
        let hidden = env.member("local", 2, false).await;
        let l1 = env.member("local", 3, true).await;
        env.store(r1, "com.acme/x", "9.0.0", "upstream").await;
        env.store(r1, "io.public/y", "1.0.0", "upstream").await;
        env.store(r1, "com.acme/z", "1.0.0", "upstream").await;
        env.store(hidden, "com.acme/z", "0.1.0", "internal").await;
        env.store(l1, "com.acme/x", "1.0.0", "internal").await;

        let (s, b) = env.get("/servers").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            descriptions(&b),
            vec!["com.acme/x@1.0.0=internal", "io.public/y@1.0.0=upstream"]
        );
        for tail in [
            "/servers/com.acme/x/versions/9.0.0",
            "/servers/com.acme/z/versions/1.0.0",
            "/servers/com.acme/z/versions/latest",
            "/servers/com.acme/z/versions",
        ] {
            assert_eq!(env.get(tail).await.0, StatusCode::NOT_FOUND, "{tail}");
        }
        let (s, b) = env.get("/servers/io.public/y/versions/latest").await;
        assert_eq!(
            (s, b["server"]["version"].as_str()),
            (StatusCode::OK, Some("1.0.0"))
        );

        let (s, b) = env.get("/servers?version=latest").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            descriptions(&b),
            vec!["com.acme/x@1.0.0=internal", "io.public/y@1.0.0=upstream"]
        );
        env.teardown().await;
    }

    #[tokio::test]
    async fn listing_pages_across_members_with_a_composite_cursor() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let l1 = env.member("local", 1, true).await;
        let l2 = env.member("local", 2, true).await;
        env.store(l1, "com.acme/a", "1.0.0", "l1").await;
        env.store(l1, "com.acme/b", "1.0.0", "l1").await;
        env.store(l2, "com.acme/a", "1.0.0", "l2").await;
        env.store(l2, "com.acme/c", "1.0.0", "l2").await;

        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..5 {
            let tail = match &cursor {
                Some(c) => format!("/servers?limit=1&cursor={c}"),
                None => "/servers?limit=1".to_string(),
            };
            let (s, b) = env.get(&tail).await;
            assert_eq!(s, StatusCode::OK, "{b}");
            seen.extend(descriptions(&b));
            match b["metadata"]["nextCursor"].as_str() {
                Some(c) => {
                    let (key, _) = decode_member_cursor(c).unwrap();
                    assert!(env.members.iter().any(|m| m.1 == key));
                    cursor = Some(c.to_string());
                }
                None => break,
            }
        }
        assert_eq!(
            seen,
            vec![
                "com.acme/a@1.0.0=l1",
                "com.acme/b@1.0.0=l1",
                "com.acme/c@1.0.0=l2"
            ]
        );
        let (s, b) = env.get("/servers?cursor=garbage").await;
        assert_eq!(
            (s, b["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("mcp_invalid_server_json"))
        );
        let gone = encode_member_cursor("not-a-member", None);
        assert_eq!(
            env.get(&format!("/servers?cursor={gone}")).await.0,
            StatusCode::BAD_REQUEST
        );
        env.teardown().await;
    }

    #[tokio::test]
    async fn virtual_refuses_writes_and_applies_its_own_deny() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let l1 = env.member("local", 1, true).await;
        env.store(l1, "com.evil/x", "1.0.0", "l1").await;
        env.store(l1, "com.acme/ok", "1.0.0", "l1").await;
        let (s, b, h) = env
            .call(
                "POST",
                &format!("/{}/v0.1/publish", env.fx.repo_key),
                Some(server_doc("com.acme/new", "1.0.0", "d")),
            )
            .await;
        assert_eq!(
            (s, body_json(&b)["error"].as_str()),
            (StatusCode::METHOD_NOT_ALLOWED, Some("mcp_read_only"))
        );
        assert_eq!(h["cache-control"], "no-store");
        let (s, _, _) = env
            .call(
                "PATCH",
                &format!(
                    "/{}/v0.1/servers/com.acme%2Fok/versions/1.0.0/status",
                    env.fx.repo_key
                ),
                Some(serde_json::json!({"status": "deprecated"})),
            )
            .await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);

        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) \
             VALUES ($1, 'mcp_server_deny', '[\"com.evil/*\"]')",
        )
        .bind(env.fx.repo_id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let (_, b) = env.get("/servers").await;
        assert_eq!(descriptions(&b), vec!["com.acme/ok@1.0.0=l1"]);
        // The fixture user holds the Virtual (a grant): the reason is shown.
        let (s, b) = env.get("/servers/com.evil/x/versions/1.0.0").await;
        assert_eq!(
            (s, b["error"].as_str()),
            (StatusCode::NOT_FOUND, Some("mcp_rejected"))
        );
        assert_eq!(
            env.get("/servers/com.evil/x/versions").await.0,
            StatusCode::NOT_FOUND
        );
        for tail in ["/ping", "/version"] {
            assert_eq!(env.get(tail).await.0, StatusCode::OK, "{tail}");
        }
        env.teardown().await;
    }
}
