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
//! Known caveat (#5536): per-caller member visibility is not modelled
//! either. The route drops the members a caller cannot read, so for such a
//! caller a member the model ranks below the pinned one can serve the
//! coordinate while the pin stands.
//!
//! [`fetch_virtual_expansion`]: crate::api::handlers::proxy_helpers::fetch_virtual_expansion
//! [`npm_virtual_eligible_members`]: crate::api::handlers::npm::npm_virtual_eligible_members
//! [`virtual_non_remote_owns_name_exact_version`]: crate::api::handlers::proxy_helpers::virtual_non_remote_owns_name_exact_version

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

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
}

fn walk_err(_: axum::response::Response) -> McpError {
    McpError::Internal("virtual member walk failed".into())
}

fn db_err(e: sqlx::Error) -> McpError {
    McpError::Internal(e.to_string())
}

/// `(distribution, version)` of a PyPI file name: a wheel
/// (`{dist}-{version}-...whl`) or an sdist (`{name}-{version}.tar.gz`,
/// `.zip`).
pub fn pypi_file_parts(file: &str) -> Option<(&str, &str)> {
    if let Some(stem) = file.strip_suffix(".whl") {
        let mut parts = stem.splitn(3, '-');
        return match (parts.next(), parts.next()) {
            (Some(d), Some(v)) => Some((d, v)),
            _ => None,
        };
    }
    file.strip_suffix(".tar.gz")
        .or_else(|| file.strip_suffix(".zip"))?
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
    members: Vec<Repository>,
    registry_type: &str,
    name: &str,
    version: &str,
) -> Result<Vec<Repository>, McpError> {
    match registry_type {
        "npm" => {
            let tarball = npm_tarball(name, version);
            let (ownership, members) = crate::api::handlers::npm::npm_virtual_eligible_members(
                db, virtual_id, members, name, &tarball,
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
                && proxy_helpers::virtual_non_remote_owns_name_exact_version(
                    db,
                    virtual_id,
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

/// The serve model of `registry_type` `identifier@version` (as submitted) in
/// Virtual `virtual_id`.
pub async fn serve_model(
    db: &PgPool,
    virtual_id: Uuid,
    registry_type: &str,
    identifier: &str,
    version: &str,
) -> Result<ServeModel, McpError> {
    let members: Vec<Repository> = proxy_helpers::fetch_virtual_expansion(db, virtual_id)
        .await
        .map_err(walk_err)?
        .members
        .into_iter()
        .map(|m| m.repo)
        .collect();
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
    for m in guarded_members(
        db,
        virtual_id,
        members.clone(),
        registry_type,
        &name,
        version,
    )
    .await?
    {
        if m.repo_type == RepositoryType::Remote {
            if serves_upstream(&m) {
                winner = Some(Winner::Remote {
                    id: m.id,
                    key: m.key.clone(),
                });
                break;
            }
            continue;
        }
        let held: Vec<HostedRow> = rows
            .iter()
            .filter(|r| r.repository_id == m.id)
            .cloned()
            .collect();
        if !held.is_empty() {
            winner = Some(Winner::Hosted {
                key: m.key.clone(),
                rows: held,
            });
            break;
        }
    }
    Ok(ServeModel {
        winner,
        files: Vec::new(),
        remotes: Vec::new(),
        first_holder,
    })
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
}
