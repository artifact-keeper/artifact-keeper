//! Which member of a Virtual backing repository the native download route
//! serves an MCP-pinned npm, PyPI, NuGet or Cargo coordinate from (#5456).
//!
//! These pins are served as `registryBaseUrl` = the mapped repository, so a
//! client following an approved server.json downloads whatever the
//! repository's own download route serves for the coordinate. For a Virtual
//! that is decided by a member walk. The model here walks the same member
//! list (recursive expansion in resolution order, equal priorities broken by
//! key: [`fetch_virtual_expansion`]) through the same per-format guards, so
//! the pin taken at publish and the check made at every read answer the
//! same question the route answers:
//!
//! * **npm**: the shadowing guard and scope policy of the tarball route,
//!   called through [`npm_virtual_eligible_members`] (isolate mode, the
//!   version- and priority-aware owner guard, per-member scope policy).
//! * **Cargo**: a non-Remote member holding the exact `name@version`
//!   anywhere in the Virtual withholds every Remote member
//!   ([`virtual_non_remote_owns_name_exact_version`]).
//! * **NuGet**: strict priority; no guard.
//! * **PyPI** is per file. The simple index merges the files of every hosted
//!   member, a download matches the file name alone, and even a Remote
//!   member the PEP 708 guard suppresses still serves platform wheels of an
//!   owned version (#2937 Case A). So every hosted file of the version is
//!   part of the pin, and any Remote member with an upstream can serve a
//!   distribution of it that nobody approved.
//!
//! A Remote member that may serve is treated as serving whether or not its
//! proxy cache holds the coordinate: the walk fetches upstream for it, and
//! the catalog of what a Remote has cached lags storage.
//!
//! Not modelled, each only ever making the model hold MORE than the route
//! would: PyPI curation, and an age gate's answer that a Remote's upstream
//! does not host the version.
//!
//! Not modelled either, an availability caveat only: the npm tarball route's
//! hosted lookup falls back to a member's rows by storage path
//! (`{pkg}/%/{filename}`, `npm_local_fetch`), while this model matches the
//! `name` / `version` columns. A generic upload at
//! `@acme/echo/9.9.9/echo-1.0.0.tgz` in a member walked before the pinned one
//! is served for `echo-1.0.0.tgz` without the pin being held. npm checks the
//! tarball against the packument's `dist.integrity`, so the client fails
//! with `EINTEGRITY` rather than installing other bytes (#5537).
//!
//! The PyPI per-file rule is the format's, not the Virtual's: a directly
//! mapped Local's pin also covers every file of the version
//! (`mcp_packages::pin_shadowed`, through [`repo_rows`]), so uploading
//! another wheel of a pinned version there holds the MCP version too.
//!
//! One decision expands the Virtual once ([`serve_model`],
//! [`fill_remote`]): every guard reads that expansion (#5537).
//!
//! Per-caller member visibility (#5536). The route drops the members a
//! caller cannot read, so for a caller who can read the Virtual but not the
//! winning member, the next member that holds or proxies the coordinate
//! serves it. The model therefore also records the members after the
//! winner that would serve ([`ServeModel::later`]), and when the winning
//! member is not readable by everyone who can read the Virtual
//! ([`member_covers_virtual`]), any of them counts as shadowing
//! ([`hidden_member_shadow`]). The format guards are not per caller (npm
//! and Cargo ownership is decided over every member), so a Remote the guard
//! withholds stays withheld for every caller. PyPI needs no extra rule: every
//! hosted file of the version is already part of the pin and every Remote
//! with an upstream already shadows it, so a caller who cannot read a member
//! is served fewer pinned files, never other bytes.
//!
//! [`fetch_virtual_expansion`]: crate::api::handlers::proxy_helpers::fetch_virtual_expansion
//! [`npm_virtual_eligible_members`]: crate::api::handlers::npm::npm_virtual_eligible_members
//! [`virtual_non_remote_owns_name_exact_version`]: crate::api::handlers::proxy_helpers::virtual_non_remote_owns_name_exact_version

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::ExpandedMember;
use crate::api::handlers::{escape_like_literal, proxy_helpers};
use crate::formats::mcp::{McpError, PackagePin};
use crate::formats::pypi::PypiHandler;
use crate::models::repository::{Repository, RepositoryType};
use crate::services::mcp_packages::{lookup_name, lookup_version, name_predicate};

/// One `artifacts` row of a pinned coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedRow {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub checksum: String,
}

/// The member a walk serves a coordinate from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Winner {
    /// A hosted member, and its rows of the coordinate.
    Hosted { key: String, rows: Vec<HostedRow> },
    /// A Remote member (from its cache or its upstream).
    Remote { id: Uuid, key: String },
}

/// What the native route of a Virtual serves for one coordinate.
#[derive(Debug, Clone, Default)]
pub struct ServeModel {
    /// npm, NuGet, Cargo: the serving member (`None`: nothing serves).
    pub winner: Option<Winner>,
    /// PyPI: every hosted file of the version, in walk order.
    pub files: Vec<HostedRow>,
    /// PyPI: every Remote member with an upstream, `(id, key)`.
    pub remotes: Vec<(Uuid, String)>,
    /// The key of the first hosted member holding the coordinate.
    pub first_holder: Option<String>,
    /// npm, NuGet, Cargo: the members after the winner, in walk order, that
    /// would serve the coordinate to a caller who cannot read the members
    /// before them (a hosted member holding it, or a Remote member the
    /// format's guard keeps, with an upstream): `(id, key)` (#5536).
    pub later: Vec<(Uuid, String)>,
}

impl Winner {
    /// The serving member's id: a hosted member's rows all live in it.
    fn member_id(&self) -> Option<Uuid> {
        match self {
            Winner::Hosted { rows, .. } => rows.first().map(|r| r.repository_id),
            Winner::Remote { id, .. } => Some(*id),
        }
    }

    fn key(&self) -> &str {
        match self {
            Winner::Hosted { key, .. } | Winner::Remote { key, .. } => key,
        }
    }
}

fn walk_err(_: axum::response::Response) -> McpError {
    McpError::Internal("virtual member walk failed".into())
}

fn db_err(e: sqlx::Error) -> McpError {
    McpError::Internal(e.to_string())
}

/// The source-distribution extensions the PyPI download route serves a file
/// under (`version_from_pypi_filename`'s list): the modern `.tar.gz` and
/// `.zip`, and the legacy `.tar.bz2`, `.tar.xz`, `.tgz` and `.tar` (#5537).
const PYPI_SDIST_EXTS: [&str; 6] = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"];

/// `(distribution, version)` of a PyPI file name: a wheel
/// (`{dist}-{version}-...whl`), a legacy egg (`{dist}-{version}(-...)?.egg`)
/// or an sdist (`{name}-{version}` plus one of [`PYPI_SDIST_EXTS`]).
pub fn pypi_file_parts(file: &str) -> Option<(&str, &str)> {
    if let Some(stem) = file
        .strip_suffix(".whl")
        .or_else(|| file.strip_suffix(".egg"))
    {
        let mut parts = stem.splitn(3, '-');
        return match (parts.next(), parts.next()) {
            (Some(d), Some(v)) => Some((d, v)),
            _ => None,
        };
    }
    PYPI_SDIST_EXTS
        .iter()
        .find_map(|ext| file.strip_suffix(ext))?
        .rsplit_once('-')
}

/// PEP 440 equality, falling back to a case-insensitive comparison of a
/// version that does not parse.
pub fn pep440_eq(a: &str, b: &str) -> bool {
    match (
        PypiHandler::canonical_version(a),
        PypiHandler::canonical_version(b),
    ) {
        (Some(x), Some(y)) => x == y,
        _ => a.eq_ignore_ascii_case(b),
    }
}

/// Whether an `artifacts` row is a file of PyPI project `project`
/// (normalised) at `version`, as the download route would hand it out: by
/// its file name (the route matches the name alone, whatever project the row
/// was uploaded under), or, for a row whose path is not a distribution file
/// name, by its `name` and `version` columns.
fn pypi_row_matches(
    path: &str,
    name: &str,
    row_version: &str,
    project: &str,
    version: &str,
) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    match pypi_file_parts(file) {
        Some((dist, v)) => PypiHandler::normalize_name(dist) == project && pep440_eq(v, version),
        None => PypiHandler::normalize_name(name) == project && pep440_eq(row_version, version),
    }
}

/// The hosted files of PyPI `project@version` in `repo_ids`, in the order of
/// `repo_ids`, then by path.
async fn pypi_files(
    db: &PgPool,
    repo_ids: &[Uuid],
    project: &str,
    version: &str,
) -> Result<Vec<HostedRow>, McpError> {
    // Candidates: the project's rows, plus any row whose file name carries
    // the project's normalised name (a file uploaded under another project
    // is still served for this one's file name). Filtered exactly in Rust.
    let rows: Vec<(Uuid, Uuid, String, String, String, String)> = sqlx::query_as(
        "SELECT a.id, a.repository_id, a.checksum_sha256::text, a.path, a.name, \
                COALESCE(a.version, '') \
         FROM artifacts a \
         WHERE a.repository_id = ANY($1) AND a.is_deleted = false \
           AND (lower(regexp_replace(a.name, '[-_.]+', '-', 'g')) = $2 \
                OR lower(regexp_replace(substring(a.path from '[^/]*$'), '[-_.]+', '-', 'g')) \
                   LIKE $3 ESCAPE '\\') \
         ORDER BY array_position($1, a.repository_id), a.path",
    )
    .bind(repo_ids)
    .bind(project)
    .bind(format!("{}-%", escape_like_literal(project)))
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(rows
        .into_iter()
        .filter(|(_, _, _, path, name, v)| pypi_row_matches(path, name, v, project, version))
        .map(|(id, repository_id, checksum, ..)| HostedRow {
            id,
            repository_id,
            checksum,
        })
        .collect())
}

/// The rows of npm, NuGet or Cargo `name@version` in `repo_ids`, matched as
/// each format's download route matches them.
async fn coordinate_rows(
    db: &PgPool,
    repo_ids: &[Uuid],
    registry_type: &str,
    name: &str,
    version: &str,
) -> Result<Vec<HostedRow>, McpError> {
    let sql = format!(
        "SELECT a.id, a.repository_id, a.checksum_sha256::text FROM artifacts a \
         WHERE a.repository_id = ANY($1) AND a.is_deleted = false AND {} \
         ORDER BY array_position($1, a.repository_id), a.path",
        name_predicate(registry_type)
    );
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(repo_ids)
        .bind(name)
        .bind(version)
        .fetch_all(db)
        .await
        .map_err(db_err)?;
    Ok(rows
        .into_iter()
        .map(|(id, repository_id, checksum)| HostedRow {
            id,
            repository_id,
            checksum,
        })
        .collect())
}

/// The rows a pin of `registry_type` `identifier@version` (as submitted)
/// covers in `repo_ids` (PyPI: every file of the version).
pub async fn repo_rows(
    db: &PgPool,
    repo_ids: &[Uuid],
    registry_type: &str,
    identifier: &str,
    version: &str,
) -> Result<Vec<HostedRow>, McpError> {
    let name = lookup_name(registry_type, identifier);
    let Some(lookup) = lookup_version(registry_type, version) else {
        return Ok(Vec::new());
    };
    if registry_type == "pypi" {
        pypi_files(db, repo_ids, &name, &lookup).await
    } else {
        coordinate_rows(db, repo_ids, registry_type, &name, &lookup).await
    }
}

/// The npm tarball file name a client requests for `name@version`.
fn npm_tarball(name: &str, version: &str) -> String {
    format!("{}-{version}.tgz", name.rsplit('/').next().unwrap_or(name))
}

/// The leaf members of Virtual `virtual_id` a Remote may serve from:
/// `members` with the format's guard applied. Hosted members are always
/// kept.
async fn guarded_members(
    db: &PgPool,
    virtual_id: Uuid,
    leaves: &[ExpandedMember],
    registry_type: &str,
    name: &str,
    version: &str,
) -> Result<Vec<Repository>, McpError> {
    let members: Vec<Repository> = leaves.iter().map(|m| m.repo.clone()).collect();
    match registry_type {
        "npm" => {
            let tarball = npm_tarball(name, version);
            let (ownership, members) = crate::api::handlers::npm::npm_virtual_eligible_members(
                db, virtual_id, leaves, members, name, &tarball,
            )
            .await
            .map_err(walk_err)?;
            if crate::api::handlers::npm::npm_virtual_remotes_allowed(ownership, &members) {
                Ok(members)
            } else {
                Ok(without_remotes(members))
            }
        }
        "cargo" => {
            let name_lower = name.to_ascii_lowercase();
            let owned = crate::formats::cargo::is_valid_cargo_name(&name_lower)
                && proxy_helpers::non_remote_ids_own_name_exact_version(
                    db,
                    virtual_id,
                    &proxy_helpers::non_remote_leaf_ids(leaves),
                    &name_lower,
                    version,
                    "cargo",
                )
                .await
                .map_err(walk_err)?;
            Ok(if owned {
                without_remotes(members)
            } else {
                members
            })
        }
        _ => Ok(members),
    }
}

fn without_remotes(members: Vec<Repository>) -> Vec<Repository> {
    members
        .into_iter()
        .filter(|m| m.repo_type != RepositoryType::Remote)
        .collect()
}

fn serves_upstream(m: &Repository) -> bool {
    m.repo_type == RepositoryType::Remote && m.upstream_url.is_some()
}

/// The leaf members of Virtual `virtual_id` in walk order (the one
/// expansion a decision reads, #5537).
async fn leaves_of(db: &PgPool, virtual_id: Uuid) -> Result<Vec<ExpandedMember>, McpError> {
    Ok(proxy_helpers::fetch_virtual_expansion(db, virtual_id)
        .await
        .map_err(walk_err)?
        .members)
}

/// The Remote member of Virtual `virtual_id` a missing `registry_type`
/// `identifier@version` (as submitted) is filled through: the Remote the
/// Virtual's route would serve it from, so the fill and the pin's shadowing
/// check agree (#5537). npm, NuGet and Cargo: the model's Remote winner
/// (`None` when a hosted member serves the version, or the format's guard
/// withholds every Remote member). PyPI, and a registry type the model does
/// not cover (OCI): the first Remote member with an upstream in walk order.
pub async fn fill_remote(
    db: &PgPool,
    virtual_id: Uuid,
    registry_type: &str,
    identifier: &str,
    version: Option<&str>,
) -> Result<Option<(Uuid, String)>, McpError> {
    let leaves = leaves_of(db, virtual_id).await?;
    match (registry_type, version) {
        ("npm" | "nuget" | "cargo", Some(version)) => {
            let model =
                serve_model_of(db, virtual_id, &leaves, registry_type, identifier, version).await?;
            Ok(match model.winner {
                Some(Winner::Remote { id, key }) => Some((id, key)),
                _ => None,
            })
        }
        _ => Ok(leaves
            .iter()
            .map(|m| &m.repo)
            .find(|m| serves_upstream(m))
            .map(|m| (m.id, m.key.clone()))),
    }
}

/// The serve model of `registry_type` `identifier@version` (as submitted) in
/// Virtual `virtual_id`.
pub async fn serve_model(
    db: &PgPool,
    virtual_id: Uuid,
    registry_type: &str,
    identifier: &str,
    version: &str,
) -> Result<ServeModel, McpError> {
    let leaves = leaves_of(db, virtual_id).await?;
    serve_model_of(db, virtual_id, &leaves, registry_type, identifier, version).await
}

/// [`serve_model`] over the Virtual's expansion `leaves`: every guard reads
/// that one expansion.
async fn serve_model_of(
    db: &PgPool,
    virtual_id: Uuid,
    leaves: &[ExpandedMember],
    registry_type: &str,
    identifier: &str,
    version: &str,
) -> Result<ServeModel, McpError> {
    let members: Vec<&Repository> = leaves.iter().map(|m| &m.repo).collect();
    let ids: Vec<Uuid> = members.iter().map(|m| m.id).collect();
    let key_of = |id: Uuid| {
        members
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.key.clone())
            .unwrap_or_default()
    };
    if registry_type == "pypi" {
        let hosted: Vec<Uuid> = members
            .iter()
            .filter(|m| m.repo_type != RepositoryType::Remote)
            .map(|m| m.id)
            .collect();
        let files = repo_rows(db, &hosted, registry_type, identifier, version).await?;
        return Ok(ServeModel {
            first_holder: files.first().map(|f| key_of(f.repository_id)),
            remotes: members
                .iter()
                .filter(|m| serves_upstream(m))
                .map(|m| (m.id, m.key.clone()))
                .collect(),
            files,
            winner: None,
            later: Vec::new(),
        });
    }
    let rows = repo_rows(db, &ids, registry_type, identifier, version).await?;
    let name = lookup_name(registry_type, identifier);
    let first_holder = rows
        .iter()
        .find(|r| {
            members
                .iter()
                .any(|m| m.id == r.repository_id && m.repo_type != RepositoryType::Remote)
        })
        .map(|r| key_of(r.repository_id));
    let mut winner = None;
    let mut later = Vec::new();
    for m in guarded_members(db, virtual_id, leaves, registry_type, &name, version).await? {
        let serving = if m.repo_type == RepositoryType::Remote {
            serves_upstream(&m).then(|| Winner::Remote {
                id: m.id,
                key: m.key.clone(),
            })
        } else {
            let held: Vec<HostedRow> = rows
                .iter()
                .filter(|r| r.repository_id == m.id)
                .cloned()
                .collect();
            (!held.is_empty()).then(|| Winner::Hosted {
                key: m.key.clone(),
                rows: held,
            })
        };
        // The walk goes on past the winner: a caller who cannot read it is
        // served by the next member that serves (#5536).
        match serving {
            Some(w) if winner.is_none() => winner = Some(w),
            Some(_) => later.push((m.id, m.key.clone())),
            None => {}
        }
    }
    Ok(ServeModel {
        winner,
        files: Vec::new(),
        remotes: Vec::new(),
        first_holder,
        later,
    })
}

/// Whether every principal that can read Virtual `virtual_id` can also read
/// its member `member_id` (#5536). Decided conservatively, so that `false`
/// is the answer whenever coverage cannot be shown:
///
/// * a public member covers any Virtual; a public Virtual (or one with an
///   anonymous rule) is covered only by a public member;
/// * otherwise every active, non-administrator user who may be a reader of
///   the Virtual (any user when it is `internal`; otherwise one holding a
///   role carrying `read` or `admin` on it or instance-wide, or named by a
///   `permissions` rule on it or its project carrying `read` or `admin`,
///   whatever the rule's conditions) must certainly read the member: through a role carrying
///   `admin`, an unconditioned rule on the member (or its project) carrying
///   `read` or `admin`, or, when no rule on the member names the user, a
///   role carrying `read` or `admin`. These are the arms of the read action
///   gate the Virtual walk applies to each member
///   (`try_authorize_virtual_members`), each taken only where it grants for
///   every request; a rule with conditions (a CIDR or MCP namespace list)
///   is never relied on.
///
/// Instance administrators read every repository and are left out.
pub async fn member_covers_virtual(
    db: &PgPool,
    virtual_id: Uuid,
    member_id: Uuid,
) -> Result<bool, McpError> {
    const NAMES_USER: &str = "((p.principal_type IN ('user', 'service_account') \
         AND p.principal_id = u.id) \
        OR (p.principal_type = 'group' AND p.principal_id IN \
            (SELECT g.group_id FROM user_group_members g WHERE g.user_id = u.id)))";
    let on = |r: &str| {
        format!(
            "((p.target_type = 'repository' AND p.target_id = {r}.id) \
              OR (p.target_type = 'project' AND p.target_id = {r}.project_id))"
        )
    };
    let (on_v, on_m) = (on("v"), on("m"));
    let role_on = |repo: &str, perms: &str| {
        format!(
            "EXISTS (SELECT 1 FROM role_assignments ra JOIN roles r ON r.id = ra.role_id \
             WHERE ra.user_id = u.id AND (ra.repository_id = {repo}.id OR ra.repository_id IS NULL) \
               AND ({perms}))"
        )
    };
    const READS: &str = "'read' = ANY(r.permissions) OR 'admin' = ANY(r.permissions)";
    let admin_role = role_on("m", "'admin' = ANY(r.permissions)");
    let read_role_m = role_on("m", READS);
    let read_role_v = role_on("v", READS);
    let sql = format!(
        "SELECT CASE \
           WHEN m.visibility = 'public' THEN true \
           WHEN v.visibility = 'public' THEN false \
           WHEN EXISTS (SELECT 1 FROM permissions p \
                        WHERE p.principal_type = 'anonymous' AND {on_v}) THEN false \
           ELSE NOT EXISTS ( \
             SELECT 1 FROM users u \
             WHERE u.is_active AND NOT u.is_admin \
               AND (v.visibility = 'internal' \
                    OR {read_role_v} \
                    OR EXISTS (SELECT 1 FROM permissions p WHERE {on_v} AND {NAMES_USER} \
                               AND ('read' = ANY(p.actions) OR 'admin' = ANY(p.actions)))) \
               AND NOT ({admin_role} \
                    OR EXISTS (SELECT 1 FROM permissions p WHERE {on_m} AND {NAMES_USER} \
                               AND ('read' = ANY(p.actions) OR 'admin' = ANY(p.actions)) \
                               AND p.conditions = '{{}}'::jsonb) \
                    OR (NOT EXISTS (SELECT 1 FROM permissions p WHERE {on_m} AND {NAMES_USER}) \
                        AND {read_role_m}))) \
         END \
         FROM repositories v, repositories m WHERE v.id = $1 AND m.id = $2"
    );
    let covers: Option<bool> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(virtual_id)
        .bind(member_id)
        .fetch_optional(db)
        .await
        .map_err(db_err)?;
    Ok(covers.unwrap_or(false))
}

/// Why a reader of Virtual `virtual_id` who cannot read the winning member
/// would be served other bytes (#5536): `Some` when a member after the
/// winner serves the coordinate ([`ServeModel::later`]) and the winner is
/// not readable by everyone who can read the Virtual
/// ([`member_covers_virtual`]). `covers` memoises the coverage answers.
/// `None` for PyPI (see the module docs) and when nothing serves.
pub async fn hidden_member_shadow(
    db: &PgPool,
    virtual_id: Uuid,
    model: &ServeModel,
    covers: &mut std::collections::HashMap<(Uuid, Uuid), bool>,
) -> Result<Option<String>, McpError> {
    let (Some(winner), Some((_, next))) = (&model.winner, model.later.first()) else {
        return Ok(None);
    };
    let Some(member) = winner.member_id() else {
        return Ok(None);
    };
    let covered = match covers.get(&(virtual_id, member)) {
        Some(c) => *c,
        None => {
            let c = member_covers_virtual(db, virtual_id, member).await?;
            covers.insert((virtual_id, member), c);
            c
        }
    };
    Ok((!covered).then(|| {
        format!(
            "member '{}' is not readable by every reader of the Virtual, and member '{next}' \
             serves this version to a reader who cannot read it",
            winner.key()
        )
    }))
}

/// Why the advertised Virtual URL would not deliver a pin, as the one line a
/// refusal names (never an artifact id).
pub fn shadow_reason(
    model: &ServeModel,
    pin: &PackagePin,
    live: &[HostedRow],
    cached: bool,
) -> Option<String> {
    let r = &pin.resolved;
    let pinned_repos: HashSet<Uuid> = if cached {
        HashSet::from([r.repository_id])
    } else {
        live.iter().map(|row| row.repository_id).collect()
    };
    if pin.registry_type == "pypi" {
        if let Some((_, key)) = model
            .remotes
            .iter()
            .find(|(id, _)| !pinned_repos.contains(id))
        {
            return Some(format!(
                "Remote member '{key}' can serve other distributions of this version from its \
                 upstream"
            ));
        }
        let live_ids: HashSet<Uuid> = live.iter().map(|row| row.id).collect();
        if !cached && r.artifact_ids.iter().any(|id| !live_ids.contains(id)) {
            return Some("a pinned distribution file is gone".into());
        }
        if model.files.iter().any(|f| !r.artifact_ids.contains(&f.id)) {
            return Some("another distribution file of this version is served".into());
        }
        return None;
    }
    match &model.winner {
        Some(Winner::Remote { id, key }) if !pinned_repos.contains(id) => Some(format!(
            "Remote member '{key}' outranks the pinned member and serves this version from its \
             upstream"
        )),
        Some(Winner::Hosted { key, rows })
            if !rows
                .iter()
                .any(|row| pinned_repos.contains(&row.repository_id)) =>
        {
            Some(format!("member '{key}' serves this version"))
        }
        None => Some("no member of the Virtual serves this version".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pypi_file_names_and_versions() {
        assert_eq!(
            pypi_file_parts("acme_echo-1.0-py3-none-any.whl"),
            Some(("acme_echo", "1.0"))
        );
        assert_eq!(
            pypi_file_parts("Acme.Echo-1.0.0.tar.gz"),
            Some(("Acme.Echo", "1.0.0"))
        );
        assert_eq!(pypi_file_parts("x-2.zip"), Some(("x", "2")));
        assert_eq!(pypi_file_parts("readme.txt"), None);
        assert_eq!(pypi_file_parts("nodash.whl"), None);
        assert!(pep440_eq("1.0", "1.0.0"));
        assert!(pep440_eq("1.0.0RC1", "1.0.0rc1"));
        assert!(!pep440_eq("1.0.1", "1.0.0"));
        assert!(pep440_eq("not a version", "NOT A VERSION"));
        // The file name decides, whatever project the row was uploaded under.
        assert!(pypi_row_matches(
            "zzz/acme_echo-1.0.tar.gz",
            "zzz",
            "9",
            "acme-echo",
            "1.0.0"
        ));
        assert!(!pypi_row_matches(
            "acme-echo/acme_echo-1.0.1.tar.gz",
            "acme-echo",
            "1.0.0",
            "acme-echo",
            "1.0.0"
        ));
        assert!(pypi_row_matches(
            "acme-echo/blob",
            "Acme_Echo",
            "1.0",
            "acme-echo",
            "1.0.0"
        ));
        assert_eq!(npm_tarball("@acme/echo", "1.0.0"), "echo-1.0.0.tgz");
    }

    /// #5537: the legacy distribution types the PyPI download route still
    /// serves are files of their version too, so a same-named legacy file
    /// uploaded under another project is seen.
    #[test]
    fn pypi_legacy_file_names_and_versions_5537() {
        for (file, parts) in [
            ("acme_echo-1.0.tar.bz2", ("acme_echo", "1.0")),
            ("acme_echo-1.0.tar.xz", ("acme_echo", "1.0")),
            ("acme_echo-1.0.tgz", ("acme_echo", "1.0")),
            ("acme_echo-1.0.tar", ("acme_echo", "1.0")),
            ("acme_echo-1.0-py3.12.egg", ("acme_echo", "1.0")),
            ("acme_echo-1.0.egg", ("acme_echo", "1.0")),
        ] {
            assert_eq!(pypi_file_parts(file), Some(parts), "{file}");
            assert!(
                pypi_row_matches(&format!("zzz/{file}"), "zzz", "9", "acme-echo", "1.0.0"),
                "{file}"
            );
            assert!(
                crate::services::mcp_resolver::pypi_file_matches(file, "Acme-Echo", "1.0"),
                "{file}"
            );
        }
        assert_eq!(pypi_file_parts("nodash.egg"), None);
        assert_eq!(pypi_file_parts("acme_echo-1.0.tar.zst"), None);
    }
}
