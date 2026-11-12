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
//!   rows in its own `name, version` keyset order. The cursor is opaque: the
//!   member key and its keyset position, sealed ([`fmt::CursorSeal`]).
//! - **Deny lists**: the Virtual's own `mcp_server_deny` hides a name
//!   everywhere; a nested Virtual's hides it from the members reached
//!   through that nested Virtual (the union along each member's path).
//! - **Writes**: `405 mcp_read_only`; publish to a hosted member.

use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use axum::response::Response;
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

/// A member and where that member's listing resumes
/// ([`fmt::ListingResume::default`]: its first row).
pub type MemberPosition = (String, fmt::ListingResume);

/// The Virtual `scope`'s cursor resuming member `member_key` at `at`,
/// sealed: opaque to a client, and a cursor nobody issued is refused. Like a
/// hosted listing's, it names only a row the listing served (#5453).
pub fn encode_member_cursor(
    seal: &fmt::CursorSeal,
    scope: Uuid,
    member_key: &str,
    at: &fmt::ListingResume,
) -> String {
    let (name, version) = at
        .after
        .as_ref()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .unwrap_or(("", ""));
    let read = fmt::encode_read(at.read);
    seal.seal(
        scope,
        &[fmt::cursor_kind::VIRTUAL, member_key, name, version, &read],
    )
}

/// Inverse of [`encode_member_cursor`]: the member key and where it
/// resumes. A cursor issued before #5453 (no row id) resumes after its
/// position. Anything else is the listing's `400`.
pub fn decode_member_cursor(
    seal: &fmt::CursorSeal,
    scope: Uuid,
    cursor: &str,
) -> Result<MemberPosition, McpError> {
    let bad = || McpError::invalid_query("cursor", "invalid cursor");
    let parts = seal.open(scope, cursor)?;
    let (kind, key, name, version, read) = match parts.as_slice() {
        [k, key, n, v] => (k, key, n, v, None),
        [k, key, n, v, read] => (k, key, n, v, fmt::decode_read(read).ok_or_else(bad)?),
        _ => return Err(bad()),
    };
    if kind != fmt::cursor_kind::VIRTUAL || key.is_empty() {
        return Err(bad());
    }
    let after = match (name.is_empty(), version.is_empty()) {
        (true, true) => None,
        (false, false) => Some((name.clone(), version.clone())),
        _ => return Err(bad()),
    };
    Ok((key.clone(), fmt::ListingResume { after, read }))
}

/// Where a listing starts: the member index and where that member resumes.
/// An unknown member key (a member removed between pages) is the listing's
/// `400`.
pub fn start_position(
    keys: &[&str],
    cursor: Option<MemberPosition>,
) -> Result<(usize, fmt::ListingResume), McpError> {
    let Some((key, inner)) = cursor else {
        return Ok((0, fmt::ListingResume::default()));
    };
    let idx = keys
        .iter()
        .position(|k| *k == key)
        .ok_or_else(|| McpError::invalid_query("cursor", "invalid cursor"))?;
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
    /// Parallel to `order`: the union of the `mcp_server_deny` lists of the
    /// nested Virtuals on the member's path (empty for a direct member). A
    /// name one of them denies is not served from that member.
    pub(crate) path_deny: Vec<Vec<String>>,
    /// The Virtual's id: the scope of its cursors.
    pub(crate) virtual_id: Uuid,
    pub(crate) seal: fmt::CursorSeal,
}

fn is_hosted_type(t: &RepositoryType) -> bool {
    matches!(t, RepositoryType::Local | RepositoryType::Staging)
}

pub(crate) async fn load_members(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_repo: &RepoInfo,
) -> Result<Members, Response> {
    let expansion = proxy_helpers::fetch_virtual_expansion(&state.db, virtual_repo.id)
        .await
        .map_err(mcp::reproblem)?;
    let mut via: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    let all: Vec<_> = expansion
        .members
        .into_iter()
        .filter(|m| m.repo.format == RepositoryFormat::Mcp)
        .map(|m| {
            via.insert(m.repo.id, m.via);
            m.repo
        })
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
    let load_deny = |id: Uuid| async move {
        crate::services::mcp_settings::load(&state.db, id, "virtual")
            .await
            .map_err(|e| mcp::internal(e.to_string()))
            .map(|s| s.mcp_server_deny.unwrap_or_default())
    };
    let mut nested_deny: HashMap<Uuid, Vec<String>> = HashMap::new();
    let mut path_deny = Vec::with_capacity(readable.len());
    for m in &readable {
        let mut union = Vec::new();
        for v in via.get(&m.id).map(Vec::as_slice).unwrap_or_default() {
            if !nested_deny.contains_key(v) {
                nested_deny.insert(*v, load_deny(*v).await?);
            }
            union.extend(nested_deny[v].iter().cloned());
        }
        path_deny.push(union);
    }
    let hosted = readable
        .iter()
        .map(|m| is_hosted_type(&m.repo_type))
        .collect();
    let order = readable
        .iter()
        .map(proxy_helpers::repo_info_from_member)
        .collect();
    let deny = load_deny(virtual_repo.id).await?;
    Ok(Members {
        order,
        hosted,
        hosted_all,
        deny,
        path_deny,
        virtual_id: virtual_repo.id,
        seal: mcp::cursor_seal(state),
    })
}

impl Members {
    fn denies(&self, name: &str) -> bool {
        crate::services::mcp_settings::any_glob_matches(&self.deny, name)
    }

    /// Whether a nested Virtual on member `idx`'s path denies `name`.
    fn path_denies(&self, idx: usize, name: &str) -> bool {
        crate::services::mcp_settings::any_glob_matches(&self.path_deny[idx], name)
    }

    /// The members that may answer `name` ([`owner_indices`]), less those
    /// reached through a nested Virtual that denies it.
    fn owners(&self, hosted_owns_name: bool, name: &str) -> Vec<usize> {
        owner_indices(&self.hosted, hosted_owns_name)
            .into_iter()
            .filter(|&i| !self.path_denies(i, name))
            .collect()
    }

    fn keys(&self) -> Vec<&str> {
        self.order.iter().map(|m| m.key.as_str()).collect()
    }
}

/// The server names some hosted member holds, compared case-insensitively
/// (#5394), as the deny lists and namespace allowlists compare them: a
/// hosted `io.acme/tool` shadows a Remote's `io.Acme/tool`.
#[derive(Debug, Default)]
pub(crate) struct OwnedNames(HashSet<String>);

impl OwnedNames {
    /// The comparison key of a server name.
    pub(crate) fn key(name: &str) -> String {
        name.to_lowercase()
    }

    pub(crate) fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        Self(names.into_iter().map(Self::key).collect())
    }

    /// Whether a hosted member holds `name` in any letter case.
    pub(crate) fn owns(&self, name: &str) -> bool {
        self.0.contains(&Self::key(name))
    }
}

/// The names among `names` some hosted member holds (any live row, any
/// letter case).
async fn hosted_owned_names(
    state: &SharedState,
    members: &Members,
    names: &[String],
) -> Result<OwnedNames, Response> {
    if members.hosted_all.is_empty() || names.is_empty() {
        return Ok(OwnedNames::default());
    }
    let keys: Vec<String> = names.iter().map(|n| OwnedNames::key(n)).collect();
    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT a.name FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = ANY($1) AND lower(a.name) = ANY($2) AND a.is_deleted = false \
           AND m.format = 'mcp'",
    )
    .bind(&members.hosted_all)
    .bind(&keys)
    .fetch_all(&state.db)
    .await
    .map_err(mcp::internal)?;
    Ok(OwnedNames::from_names(owned.iter().map(String::as_str)))
}

async fn owners_of(
    state: &SharedState,
    members: &Members,
    name: &str,
) -> Result<Vec<usize>, Response> {
    let owned = hosted_owned_names(state, members, &[name.to_string()]).await?;
    Ok(members.owners(owned.owns(name), name))
}

/// The member and row `latest` answers for `name` through the Virtual: the
/// first owning member with a servable newest version (reader-only gate),
/// and how many members were evaluated. A member whose gate cannot be
/// evaluated ends the walk with no answer: never a lower-priority member's.
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
        match mcp::newest_servable(ctx, m.id, rows, &HashSet::new())
            .await
            .0
        {
            Ok(Some(row)) => return Ok((Some((idx, row)), walked)),
            Ok(None) => {}
            Err(_) => return Ok((None, walked)),
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
    for &idx in &owners {
        let m = &members.order[idx];
        match mcp::servable_versions(state, m, name, include_deleted).await? {
            Ok(served) => {
                for row in served {
                    if seen.insert(row.version.clone()) {
                        picked.push((idx, row));
                    }
                }
            }
            // A gate of this member cannot be evaluated: the versions it
            // stores are left out, never answered from a lower-priority
            // member (a detail read answers 503 for them).
            Err(_) => {
                for row in mcp::versions_of(&state.db, m.id, name).await? {
                    if include_deleted || row.stored.registry.status != ServerStatus::Deleted {
                        seen.insert(row.version);
                    }
                }
            }
        }
    }
    if picked.is_empty() {
        return Err(mcp::not_found());
    }
    // `isLatest` marks what `latest` answers through the Virtual.
    let latest = virtual_latest(state, &members, &owners, name)
        .await?
        .0
        .map(|(_, r)| r.artifact_id);
    picked.sort_by(|a, b| a.1.version.cmp(&b.1.version));
    let entries = picked
        .iter()
        .map(|(idx, r)| {
            let entry =
                mcp::served_entry(r, &members.order[*idx], base, Some(r.artifact_id) == latest);
            mark_virtual(entry, &virtual_repo.key)
        })
        .collect();
    Ok(mcp::json_listing(&fmt::list_envelope(entries, None)))
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
    let seal = mcp::cursor_seal(state);
    let cursor = rest
        .remove("cursor")
        .filter(|c| !c.is_empty())
        .map(|c| decode_member_cursor(&seal, virtual_repo.id, &c))
        .transpose()
        .map_err(mcp::mcp_error)?;
    let q = mcp::parse_list_query(&rest, |_| {
        Err(McpError::invalid_query("cursor", "invalid cursor"))
    })
    .map_err(mcp::mcp_error)?;
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
    Ok(mcp::json_listing(&fmt::list_envelope(entries, page.next)))
}

/// One listing page: rows with the index of the member each came from.
struct Page {
    rows: Vec<(usize, VersionRow)>,
    next: Option<String>,
    /// Every row is its server's latest (`version=latest`).
    all_latest: bool,
}

/// Where the next page resumes: a member and its own position.
fn resume_cursor(members: &Members, idx: usize, at: &fmt::ListingResume) -> String {
    encode_member_cursor(
        &members.seal,
        members.virtual_id,
        &members.order[idx].key,
        at,
    )
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
        let owners = members.owners(owned.owns(name), name);
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
/// `(name, version)` an earlier member of the same kind serves (or whose
/// gate cannot be evaluated there: the pair is left out, never answered
/// from this lower-priority member). Names the Virtual denies, or a nested
/// Virtual on this member's path denies, go too.
async fn drop_shadowed(
    state: &SharedState,
    members: &Members,
    idx: usize,
    rows: Vec<VersionRow>,
    include_deleted: bool,
) -> Result<Vec<VersionRow>, Response> {
    let mut rows: Vec<VersionRow> = rows
        .into_iter()
        .filter(|r| !members.denies(&r.name) && !members.path_denies(idx, &r.name))
        .collect();
    if rows.is_empty() {
        return Ok(rows);
    }
    let hosted = members.hosted[idx];
    if !hosted {
        let names: Vec<String> = rows.iter().map(|r| r.name.clone()).collect();
        let owned = hosted_owned_names(state, members, &names).await?;
        rows.retain(|r| !owned.owns(&r.name));
    }
    let ctx = GateCtx::of(state, false);
    for earlier in (0..idx).filter(|&j| members.hosted[j] == hosted) {
        if rows.is_empty() {
            break;
        }
        // A name a nested Virtual on the earlier member's path denies is not
        // served from it, so it shadows nothing.
        let pairs: Vec<(String, String)> = rows
            .iter()
            .filter(|r| !members.path_denies(earlier, &r.name))
            .map(|r| (r.name.clone(), r.version.clone()))
            .collect();
        if pairs.is_empty() {
            continue;
        }
        let m = &members.order[earlier];
        let theirs = rows_matching(state, m.id, &pairs, include_deleted).await?;
        if theirs.is_empty() {
            continue;
        }
        let all_theirs: HashSet<(String, String)> = theirs
            .iter()
            .map(|r| (r.name.clone(), r.version.clone()))
            .collect();
        let served: HashSet<(String, String)> = match mcp::servable_checked(ctx, m.id, theirs).await
        {
            Ok(served) => served.into_iter().map(|r| (r.name, r.version)).collect(),
            Err(_) => all_theirs,
        };
        rows.retain(|r| !served.contains(&(r.name.clone(), r.version.clone())));
    }
    Ok(rows)
}

async fn list_page(
    state: &SharedState,
    members: &Members,
    q: &ListQuery,
    start: (usize, fmt::ListingResume),
) -> Result<Page, Response> {
    let want = q.limit as usize;
    let ctx = GateCtx::of(state, false);
    let mut out: Vec<(usize, VersionRow)> = Vec::new();
    let mut read = 0usize;
    let mut resume: Option<String> = None;
    'members: for idx in start.0..members.order.len() {
        let m = &members.order[idx];
        // The scan's own position (internal, may be a held row) and the
        // resume point a cursor may carry (the last row served from this
        // member, and the id of the last row read past it).
        let mut at = if idx == start.0 {
            start.1.clone()
        } else {
            fmt::ListingResume::default()
        };
        let mut after = mcp::resume_after(&state.db, m.id, &at).await?;
        loop {
            let batch =
                mcp::fetch_listing_batch(&state.db, m.id, q, after.as_ref(), q.limit + 1).await?;
            read += batch.raw_len;
            let exhausted = (batch.raw_len as i64) <= q.limit;
            if let Some(last) = batch.last.clone() {
                after = Some(last);
            }
            let rows = mcp::servable(ctx, m.id, batch.rows).await;
            let rows = drop_shadowed(state, members, idx, rows, q.include_deleted).await?;
            mcp::advance_resume(&mut at, &batch.read, &rows);
            out.extend(rows.into_iter().map(|r| (idx, r)));
            if out.len() > want {
                break 'members;
            }
            if read >= mcp::MAX_LISTING_ROWS {
                // The row bound stopped the scan: resume past the rows read
                // rather than presenting a short last page, naming the last
                // one by its id only (#5453).
                if !exhausted {
                    resume = Some(resume_cursor(members, idx, &at));
                } else if idx + 1 < members.order.len() {
                    resume = Some(resume_cursor(
                        members,
                        idx + 1,
                        &fmt::ListingResume::default(),
                    ));
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
            &fmt::ListingResume::after(&last.name, &last.version),
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
    start: (usize, fmt::ListingResume),
) -> Result<Page, Response> {
    let want = q.limit as usize;
    let mut out: Vec<(usize, VersionRow)> = Vec::new();
    let mut budget = mcp::MAX_LATEST_BUDGET;
    let mut next: Option<String> = None;
    'members: for idx in start.0..members.order.len() {
        let m = &members.order[idx];
        // As in `list_page`: the scan's own position, and the resume point
        // (the last server emitted from this member, and the id of a row of
        // the last server decided past it).
        let mut at = if idx == start.0 {
            start.1.clone()
        } else {
            fmt::ListingResume::default()
        };
        let mut name_after = mcp::resume_after(&state.db, m.id, &at)
            .await?
            .map(|(n, _)| n);
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
            let just_names: Vec<String> = names.iter().map(|(n, _)| n.clone()).collect();
            let owned = hosted_owned_names(state, members, &just_names).await?;
            for (name, id) in names {
                if out.len() == want || budget == 0 {
                    next = Some(resume_cursor(members, idx, &at));
                    break 'members;
                }
                let mut emitted = false;
                if !members.denies(&name) {
                    let owners = members.owners(owned.owns(&name), &name);
                    let (picked, walked) = virtual_latest(state, members, &owners, &name).await?;
                    budget = budget.saturating_sub(walked.max(1));
                    if let Some((owner, row)) = picked.filter(|(owner, r)| {
                        *owner == idx
                            && q.updated_since
                                .is_none_or(|since| r.stored.registry.updated_at >= since)
                    }) {
                        out.push((owner, row));
                        emitted = true;
                    }
                }
                at.advance_one(id, (name.clone(), mcp::LATEST_POSITION.into()), emitted);
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
    use base64::Engine as _;

    #[test]
    fn serving_order_puts_hosted_first_and_keeps_priority() {
        let members = vec![("r1", false), ("l1", true), ("r2", false), ("l2", true)];
        let ordered: Vec<&str> = serving_order(members, |m| m.1)
            .into_iter()
            .map(|m| m.0)
            .collect();
        assert_eq!(ordered, vec!["l1", "l2", "r1", "r2"]);
    }

    fn test_seal() -> fmt::CursorSeal {
        fmt::CursorSeal::from_secret("mcp-virtual-tests-secret-0123456789abcdef")
    }

    #[test]
    fn member_cursor_round_trips_and_rejects_garbage() {
        let seal = test_seal();
        let scope = Uuid::new_v4();
        let at = fmt::ListingResume::after("com.acme/x", "1.0.0");
        let c = encode_member_cursor(&seal, scope, "mcp-local", &at);
        assert_eq!(
            decode_member_cursor(&seal, scope, &c).unwrap(),
            ("mcp-local".to_string(), at.clone())
        );
        let start = encode_member_cursor(&seal, scope, "mcp-remote", &Default::default());
        assert_eq!(
            decode_member_cursor(&seal, scope, &start).unwrap(),
            ("mcp-remote".to_string(), Default::default())
        );
        // #5453: a resume past unserved rows names none of them.
        let past = fmt::ListingResume {
            after: None,
            read: Some(Uuid::new_v4()),
        };
        let c = encode_member_cursor(&seal, scope, "mcp-local", &past);
        assert_eq!(
            decode_member_cursor(&seal, scope, &c).unwrap(),
            ("mcp-local".to_string(), past)
        );
        // A cursor issued before #5453 (no skip) still resumes.
        let legacy = seal.seal(
            scope,
            &[
                fmt::cursor_kind::VIRTUAL,
                "mcp-local",
                "com.acme/x",
                "1.0.0",
            ],
        );
        assert_eq!(
            decode_member_cursor(&seal, scope, &legacy).unwrap(),
            ("mcp-local".to_string(), at)
        );
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        // The pre-seal format, which a client could build by hand.
        let hand_made = b64(&format!("m:mcp-local:{}", b64("com.acme/x:1.0.0")));
        let other_scope =
            encode_member_cursor(&seal, Uuid::new_v4(), "mcp-local", &Default::default());
        let bad_read = seal.seal(scope, &[fmt::cursor_kind::VIRTUAL, "k", "a/b", "1", "-1"]);
        let hosted = seal.encode_position(scope, fmt::cursor_kind::SERVERS, "a/b", "1");
        let no_key = seal.seal(scope, &[fmt::cursor_kind::VIRTUAL, "", "", ""]);
        let half = seal.seal(scope, &[fmt::cursor_kind::VIRTUAL, "k", "a/b", ""]);
        for garbage in [
            "!!!",
            "bm90LWEtY3Vyc29y",
            &b64("m::abc"),
            &b64("m:nokey"),
            &hand_made,
            &other_scope,
            &hosted,
            &no_key,
            &half,
            &bad_read,
        ] {
            // D4: a malformed composite cursor is a query error.
            assert_eq!(
                decode_member_cursor(&seal, scope, garbage)
                    .unwrap_err()
                    .code(),
                "mcp_invalid_query",
                "{garbage}"
            );
        }
    }

    #[test]
    fn start_position_finds_the_member_and_its_keyset() {
        let keys = ["a", "b"];
        assert_eq!(
            start_position(&keys, None).unwrap(),
            (0, Default::default())
        );
        let at = fmt::ListingResume::after("n/x", "2");
        assert_eq!(
            start_position(&keys, Some(("b".into(), at.clone()))).unwrap(),
            (1, at)
        );
        assert_eq!(
            start_position(&keys, Some(("b".into(), Default::default()))).unwrap(),
            (1, Default::default())
        );
        assert_eq!(
            start_position(&keys, Some(("gone".into(), Default::default())))
                .unwrap_err()
                .code(),
            "mcp_invalid_query"
        );
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
            let root = self.fx.repo_id;
            self.member_of(root, repo_type, priority, readable).await
        }

        /// [`Self::member`] of the (nested) Virtual `parent`.
        async fn member_of(
            &mut self,
            parent: Uuid,
            repo_type: &str,
            priority: i32,
            readable: bool,
        ) -> usize {
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
            tdh::link_virtual_member(pool, parent, id, priority).await;
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
            self.store_doc(m, &server_doc(name, version, description))
                .await
        }

        /// [`Self::store`] of a whole server.json.
        async fn store_doc(&self, m: usize, doc: &serde_json::Value) -> Uuid {
            let name = doc["name"].as_str().unwrap();
            let version = doc["version"].as_str().unwrap();
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
                .body(Body::from(serde_json::to_vec(doc).unwrap()))
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
            for (id, _, _) in &self.members {
                let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
                    .bind(id)
                    .execute(&self.fx.pool)
                    .await;
            }
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

    /// #5452: a Virtual serves an `open` member's version only as the
    /// member's own serve decision allows. A version whose package carries
    /// no AK pin (as `open` stored them before the fix) is never served
    /// through the Virtual: the read falls through to the next member, and
    /// the listing does not carry it. A member's pinned `open` package is
    /// served at its AK coordinates, not the submitted foreign registry.
    #[tokio::test]
    async fn open_members_serve_only_pinned_packages() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let l1 = env.member("local", 1, true).await;
        let l2 = env.member("local", 2, true).await;
        let (npm_id, npm_key, npm_dir) = tdh::create_repo(&env.fx.pool, "local", "npm").await;
        let mut npm = tdh::make_repo_info(npm_id, &npm_key, &npm_dir, "local", None);
        npm.format = "npm".into();
        tdh::seed_artifact_with_checksum(
            &env.fx.state,
            &env.fx.pool,
            &npm,
            "npm/echo-1.0.0.tgz",
            "@acme/echo/-/echo-1.0.0.tgz",
            "@acme/echo",
            "1.0.0",
            "application/octet-stream",
            Bytes::from_static(b"tgz"),
            env.fx.user_id,
            &"e".repeat(64),
        )
        .await;
        env.members.push((npm_id, npm_key.clone(), npm_dir));
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) \
             VALUES ($1, 'mcp_package_repos', $2)",
        )
        .bind(env.members[l2].0)
        .bind(serde_json::json!({"npm": npm_key}).to_string())
        .execute(&env.fx.pool)
        .await
        .unwrap();

        let unpinned = env.store(l1, "com.acme/x", "1.0.0", "from-l1").await;
        let mut pinned = server_doc("com.acme/x", "1.0.0", "from-l2");
        pinned["packages"] = serde_json::json!([{
            "registryType": "npm", "identifier": "@acme/echo", "version": "1.0.0",
            "registryBaseUrl": "https://npm.evil.test", "transport": {"type": "stdio"},
        }]);
        env.store_doc(l2, &pinned).await;
        // l1's version as `open` stored it before #5452: a package, no pin.
        sqlx::query(
            "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{server,packages}', $2) \
             WHERE artifact_id = $1",
        )
        .bind(unpinned)
        .bind(serde_json::json!([{
            "registryType": "npm", "identifier": "@evil/pkg", "version": "3.0.0",
            "registryBaseUrl": "https://npm.evil.test", "transport": {"type": "stdio"},
        }]))
        .execute(&env.fx.pool)
        .await
        .unwrap();

        let (s, b) = env.get("/servers/com.acme%2Fx/versions/1.0.0").await;
        assert_eq!(
            (s, b["server"]["description"].as_str()),
            (StatusCode::OK, Some("from-l2")),
            "{b}"
        );
        assert_eq!(
            b["server"]["packages"][0]["registryBaseUrl"],
            format!("http://localhost/npm/{npm_key}")
        );
        let (s, b) = env.get("/servers").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(descriptions(&b), vec!["com.acme/x@1.0.0=from-l2"]);
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
                    let seal = super::super::mcp::cursor_seal(&env.fx.state);
                    let (key, _) = decode_member_cursor(&seal, env.fx.repo_id, c).unwrap();
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
        // D4: a malformed composite cursor is a query error, as on a hosted
        // repository.
        let (s, b) = env.get("/servers?cursor=garbage").await;
        assert_eq!(
            (s, b["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("mcp_invalid_query"))
        );
        let seal = super::super::mcp::cursor_seal(&env.fx.state);
        let gone = encode_member_cursor(&seal, env.fx.repo_id, "not-a-member", &Default::default());
        assert_eq!(
            env.get(&format!("/servers?cursor={gone}")).await.0,
            StatusCode::BAD_REQUEST
        );
        // Finding 4: the cursor is opaque (it names neither the member nor a
        // row) and one built by hand is refused, so a client can neither
        // read a held row out of a cursor nor probe with a made-up one.
        let (_, b) = env.get("/servers?limit=1").await;
        let issued = b["metadata"]["nextCursor"].as_str().unwrap().to_string();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&issued)
            .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text.contains("com.acme") && !text.contains(&env.members[l1].1),
            "{text}"
        );
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        for hand_made in [
            b64(&format!("m:{}:", env.members[l2].1)),
            b64(&format!(
                "m:{}:{}",
                env.members[l1].1,
                b64("com.acme/a:1.0.0")
            )),
        ] {
            let (s, b) = env.get(&format!("/servers?cursor={hand_made}")).await;
            assert_eq!(
                (s, b["error"].as_str()),
                (StatusCode::BAD_REQUEST, Some("mcp_invalid_query")),
                "{hand_made}"
            );
        }
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

    /// Finding 3: a nested Virtual's `mcp_server_deny` applies to the
    /// members reached through it when its parent is read, as the union of
    /// the deny lists along the member's path. A member outside the nested
    /// Virtual still serves the name.
    #[tokio::test]
    async fn nested_virtual_deny_applies_along_the_path() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let nested = env.member("virtual", 1, true).await;
        let nested_id = env.members[nested].0;
        let inner = env.member_of(nested_id, "local", 1, true).await;
        let direct = env.member("local", 2, true).await;
        env.store(inner, "com.evil/x", "1.0.0", "inner").await;
        env.store(inner, "com.acme/ok", "1.0.0", "inner").await;
        env.store(inner, "com.evil/y", "1.0.0", "inner").await;
        env.store(direct, "com.evil/y", "1.0.0", "direct").await;
        let (_, b) = env.get("/servers").await;
        assert_eq!(
            descriptions(&b),
            vec![
                "com.acme/ok@1.0.0=inner",
                "com.evil/x@1.0.0=inner",
                "com.evil/y@1.0.0=inner"
            ],
            "before the deny"
        );
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) \
             VALUES ($1, 'mcp_server_deny', '[\"com.evil/*\"]')",
        )
        .bind(nested_id)
        .execute(&env.fx.pool)
        .await
        .unwrap();

        let (s, b) = env.get("/servers").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            descriptions(&b),
            vec!["com.acme/ok@1.0.0=inner", "com.evil/y@1.0.0=direct"]
        );
        let (_, b) = env.get("/servers?version=latest").await;
        assert_eq!(
            descriptions(&b),
            vec!["com.acme/ok@1.0.0=inner", "com.evil/y@1.0.0=direct"]
        );
        for tail in [
            "/servers/com.evil%2Fx/versions/1.0.0",
            "/servers/com.evil%2Fx/versions/latest",
            "/servers/com.evil%2Fx/versions",
        ] {
            assert_eq!(
                env.get(tail).await,
                (StatusCode::NOT_FOUND, fmt::not_found_value()),
                "{tail}"
            );
        }
        for tail in [
            "/servers/com.evil%2Fy/versions/1.0.0",
            "/servers/com.evil%2Fy/versions/latest",
        ] {
            let (s, b) = env.get(tail).await;
            assert_eq!(
                (s, b["server"]["description"].as_str()),
                (StatusCode::OK, Some("direct")),
                "{tail}"
            );
        }
        let (_, b) = env.get("/servers/com.evil%2Fy/versions").await;
        assert_eq!(descriptions(&b), vec!["com.evil/y@1.0.0=direct"]);
        assert_eq!(
            b["servers"][0]["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"],
            true
        );
        env.teardown().await;
    }

    /// Finding 14: a `(name, version)` whose gate cannot be evaluated on the
    /// member that would answer it is left out of the listings, never
    /// listed from a lower-priority member, and a `latest` that cannot be
    /// decided there is not taken from the next member.
    #[tokio::test]
    async fn listings_do_not_fall_past_an_unevaluable_gate() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let r1 = env.member("remote", 1, true).await;
        let r2 = env.member("remote", 2, true).await;
        env.store(r1, "io.public/y", "1.0.0", "r1").await;
        env.store(r2, "io.public/y", "1.0.0", "r2").await;
        env.store(r2, "io.public/y", "2.0.0", "r2").await;
        env.store(r2, "io.public/z", "1.0.0", "r2").await;
        let (_, b) = env.get("/servers").await;
        assert_eq!(
            descriptions(&b),
            vec![
                "io.public/y@1.0.0=r1",
                "io.public/y@2.0.0=r2",
                "io.public/z@1.0.0=r2"
            ]
        );
        // r1's gate cannot be evaluated: an age gate it cannot enforce
        // (MCP has no upstream publish time) fails closed.
        sqlx::query("UPDATE repositories SET age_gate_enabled = true WHERE id = $1")
            .bind(env.members[r1].0)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        for tail in [
            "/servers/io.public%2Fy/versions/1.0.0",
            "/servers/io.public%2Fy/versions/latest",
        ] {
            assert_eq!(
                env.get(tail).await.0,
                StatusCode::SERVICE_UNAVAILABLE,
                "{tail}"
            );
        }
        let (s, b) = env.get("/servers").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            descriptions(&b),
            vec!["io.public/y@2.0.0=r2", "io.public/z@1.0.0=r2"]
        );
        let (_, b) = env.get("/servers?version=latest").await;
        assert_eq!(descriptions(&b), vec!["io.public/z@1.0.0=r2"]);
        let (s, b) = env.get("/servers/io.public%2Fy/versions").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(descriptions(&b), vec!["io.public/y@2.0.0=r2"]);
        assert_eq!(
            b["servers"][0]["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"],
            false
        );
        env.teardown().await;
    }

    /// #5394: hosted shadows remote whatever the letter case. A hosted
    /// `io.acme/tool` hides a Remote's `io.Acme/tool` from every read
    /// through the Virtual, as the deny lists (case-insensitive) would.
    #[tokio::test]
    async fn hosted_shadows_remote_whatever_the_letter_case() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let r1 = env.member("remote", 1, true).await;
        let l1 = env.member("local", 2, true).await;
        env.store(r1, "io.Acme/tool", "9.0.0", "upstream").await;
        env.store(r1, "io.public/y", "1.0.0", "upstream").await;
        env.store(l1, "io.acme/tool", "1.0.0", "internal").await;
        for tail in ["/servers", "/servers?version=latest"] {
            let (s, b) = env.get(tail).await;
            assert_eq!(s, StatusCode::OK, "{tail}");
            assert_eq!(
                descriptions(&b),
                vec!["io.acme/tool@1.0.0=internal", "io.public/y@1.0.0=upstream"],
                "{tail}"
            );
        }
        for tail in [
            "/servers/io.Acme%2Ftool/versions/9.0.0",
            "/servers/io.Acme%2Ftool/versions/latest",
            "/servers/io.Acme%2Ftool/versions",
        ] {
            assert_eq!(
                env.get(tail).await,
                (StatusCode::NOT_FOUND, fmt::not_found_value()),
                "{tail}"
            );
        }
        let (s, b) = env.get("/servers/io.acme%2Ftool/versions/latest").await;
        assert_eq!(
            (s, b["server"]["description"].as_str()),
            (StatusCode::OK, Some("internal"))
        );
        env.teardown().await;
    }

    #[test]
    fn owned_names_compare_case_insensitively() {
        let owned = OwnedNames::from_names(["io.acme/tool"]);
        assert!(owned.owns("io.Acme/tool"));
        assert!(owned.owns("IO.ACME/TOOL"));
        assert!(!owned.owns("io.acme/tools"));
        assert!(!OwnedNames::default().owns("io.acme/tool"));
    }
}
