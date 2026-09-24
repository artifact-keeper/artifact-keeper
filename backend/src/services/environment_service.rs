//! Stored environments and the component -> environment reverse index (#4054).
//!
//! #4052 parses a lockfile into a [`LockedEnvironment`]; #4053 renders it as
//! SBOM documents but persists nothing. The incident question this module
//! answers — "what do we have to fix?" — is asked against *environments*, not
//! packages, and answering it by re-parsing every lockfile ever uploaded on
//! each request is not a design, it is a hope. This module stores the parsed
//! graph and answers the reverse question from an index.
//!
//! # Storage: rows, not a document
//!
//! Three tables (migration 226): `environments` (one row per stored
//! environment), `environment_packages` (one row per (scope, package)
//! membership, carrying the component's purl) and `environment_edges` (one
//! row per resolved edge). The alternative — one JSONB document per
//! environment with membership rows extracted on the side — was rejected: the
//! document would duplicate the rows (the rows ARE the graph; there is no
//! other content worth storing), and a blob invites future readers that
//! bypass the index and rescan. Membership rows keyed by `purl_base` make
//! "which environments contain component X" an indexed lookup, and
//! per-platform answers fall out of the scope columns every row carries.
//!
//! # Environment identity: (repository, name)
//!
//! A stored environment is identified by `(repository_id, name)`. It is
//! repo-scoped because everything tenant-visible in this registry is: the
//! repository is the unit of ACL and of lifecycle (deleting the repository
//! cascades). Re-ingesting the same name REPLACES the stored graph — an
//! environment that has been re-solved is a new fact, and keeping the stale
//! membership would answer "are we exposed?" with an environment nobody runs
//! anymore. The lockfile's content digest is stored alongside so a caller can
//! tell a no-op re-upload from a re-solve.
//!
//! # Component identity: the purl base
//!
//! Membership rows store the full purl (the #4041-qualified identity for
//! conda) AND its base — the purl with qualifiers stripped
//! (`pkg:conda/libwebp@1.3.2?build=…&subdir=…` -> `pkg:conda/libwebp@1.3.2`).
//! The index is on the base, because that is the identity an advisory
//! carries: OSV/GHSA advisories name a package and a version range, not a
//! conda build string, so keying the lookup on the full qualified purl would
//! miss exactly the builds an advisory covers. A qualified lookup purl is
//! reduced to its base before querying; the full stored purl is returned per
//! hit so the caller sees precisely which builds are present.
//!
//! # Inclusion path
//!
//! A hit is not actionable without the chain that pulls the component in. On
//! a hit the scope's rows are reloaded into a [`LockedEnvironment`] and the
//! reverse-BFS of [`LockedEnvironment::explain`] reconstructs the chains from
//! a root down to the component — bounded by `max_paths` per hit and by
//! [`MAX_LOOKUP_HITS`] scope hits per query, so a component present
//! everywhere cannot turn one request into an unbounded graph walk.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::environment_lock::{
    Ecosystem, EdgeKind, LockEdge, LockFormat, LockSummary, LockedEnvironment, LockedPackage, Scope,
};
use crate::services::environment_sbom;
use crate::services::repository_service::{build_member_visibility_clause, MemberVisibility};

/// Maximum scope hits one lookup returns. A ubiquitous component (glibc,
/// openssl) is a member of every environment; the answer to "what do we have
/// to fix" is still bounded work per request, and `truncated` tells the
/// caller the answer was clipped.
pub const MAX_LOOKUP_HITS: i64 = 500;

/// Default cap on inclusion paths returned per hit.
pub const DEFAULT_MAX_PATHS: usize = 8;

/// Hard ceiling on the caller-supplied `max_paths`.
pub const MAX_PATHS: usize = 64;

/// Environment names are human labels; cap them like other tenant-supplied
/// names in this registry.
pub const MAX_ENVIRONMENT_NAME_BYTES: usize = 200;

/// Rows per multi-row INSERT during ingest. Large enough that a few-thousand
/// membership environment is a handful of statements, small enough to stay
/// well under the PostgreSQL bind-parameter limit (10 binds per row).
const INSERT_BATCH_SIZE: usize = 500;

pub struct EnvironmentService {
    db: PgPool,
}

/// A stored environment row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEnvironment {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub name: String,
    pub lockfile_format: String,
    pub content_sha256: String,
    pub summary: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One scope's membership and edge counts within a stored environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeCount {
    pub environment: Option<String>,
    pub platform: Option<String>,
    pub memberships: i64,
    pub edges: i64,
}

/// The result of ingesting a lockfile.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    pub id: Uuid,
    /// An environment of this name already existed and its stored graph was
    /// replaced.
    pub replaced: bool,
    pub summary: LockSummary,
}

/// One scope of one stored environment that contains the queried component,
/// with the inclusion chains that pull it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentHit {
    pub environment_id: Uuid,
    pub environment_name: String,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub scope: Scope,
    /// Lockfile key of the matched package within its scope.
    pub package_key: String,
    pub package_name: String,
    pub package_version: Option<String>,
    /// The full stored purl (qualified for conda), so the caller sees the
    /// exact builds present even though the lookup matched on the base.
    pub package_purl: Option<String>,
    /// Chains from a root (a package nothing else depends on) down to the
    /// component, rendered as `name@version`. At most `max_paths` entries.
    pub paths: Vec<Vec<String>>,
}

/// The answer to "which stored environments contain this component?".
#[derive(Debug, Clone)]
pub struct LookupOutcome {
    pub purl: String,
    pub purl_base: String,
    pub hits: Vec<EnvironmentHit>,
    /// More than [`MAX_LOOKUP_HITS`] scopes matched; the answer was clipped.
    pub truncated: bool,
}

/// The purl with its qualifier string removed — the identity an advisory
/// carries. Lookup keys and stored rows are both reduced through this, so a
/// fully-qualified conda purl and the bare purl from an OSV entry resolve to
/// the same index key.
pub fn purl_base(purl: &str) -> &str {
    purl.split('?').next().unwrap_or(purl).trim()
}

/// Clamp a caller-supplied path cap into `[1, MAX_PATHS]`, defaulting to
/// [`DEFAULT_MAX_PATHS`]. A caller asking for 0 paths is asking for the hit
/// without chains, but a cap of 0 would also silently disable the bound —
/// treat it as 1, never as unlimited.
pub fn clamp_max_paths(raw: Option<u64>) -> usize {
    match raw {
        None => DEFAULT_MAX_PATHS,
        Some(0) => 1,
        Some(n) => (n as usize).min(MAX_PATHS),
    }
}

/// Validate a tenant-supplied environment name.
fn validate_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::Validation(
            "environment name must not be empty".to_string(),
        ));
    }
    if name.len() > MAX_ENVIRONMENT_NAME_BYTES {
        return Err(AppError::Validation(format!(
            "environment name exceeds {} bytes",
            MAX_ENVIRONMENT_NAME_BYTES
        )));
    }
    Ok(name)
}

/// Render a package for an inclusion path: `name@version`, or `name` when the
/// lockfile recorded no version.
fn display_name(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("{}@{}", name, version),
        _ => name.to_string(),
    }
}

impl EnvironmentService {
    pub fn new(db: PgPool) -> Self {
        EnvironmentService { db }
    }

    /// Store a parsed lockfile as `(repository_id, name)`, replacing any
    /// stored graph of the same name. The whole write is one transaction, so
    /// a reader never observes a half-replaced environment.
    pub async fn ingest(
        &self,
        repository_id: Uuid,
        name: &str,
        content_sha256: &str,
        env: &LockedEnvironment,
    ) -> Result<IngestOutcome> {
        let name = validate_name(name)?;
        let summary = env.summary();
        let summary_json = serde_json::json!({
            "scopes": summary.scopes,
            "memberships": summary.memberships,
            "distinctPackages": summary.distinct_packages,
            "edges": summary.edges,
            "unparsed": summary.unparsed,
            "missingDependencies": summary.missing_dependencies,
            "explainedAbsences": summary.explained_absences,
            "ambiguous": summary.ambiguous,
        });

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // SELECT ... FOR UPDATE serializes a concurrent re-ingest of the same
        // name; a brand-new name still races the unique constraint, which
        // surfaces as a Database error rather than a silent double store.
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM environments WHERE repository_id = $1 AND name = $2 FOR UPDATE",
        )
        .bind(repository_id)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let (id, replaced) = match existing {
            Some(id) => {
                sqlx::query(
                    "UPDATE environments \
                     SET lockfile_format = $2, content_sha256 = $3, summary = $4, updated_at = now() \
                     WHERE id = $1",
                )
                .bind(id)
                .bind(env.format.as_str())
                .bind(content_sha256)
                .bind(&summary_json)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
                sqlx::query("DELETE FROM environment_packages WHERE environment_id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
                sqlx::query("DELETE FROM environment_edges WHERE environment_id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
                (id, true)
            }
            None => {
                let id: Uuid = sqlx::query_scalar(
                    "INSERT INTO environments \
                     (repository_id, name, lockfile_format, content_sha256, summary) \
                     VALUES ($1, $2, $3, $4, $5) RETURNING id",
                )
                .bind(repository_id)
                .bind(name)
                .bind(env.format.as_str())
                .bind(content_sha256)
                .bind(&summary_json)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
                (id, false)
            }
        };

        for chunk in env.packages.chunks(INSERT_BATCH_SIZE) {
            let mut qb = sqlx::QueryBuilder::new(
                "INSERT INTO environment_packages \
                 (environment_id, scope_environment, scope_platform, ecosystem, name, version, \
                  purl, purl_base, package_key, is_root) ",
            );
            qb.push_values(chunk, |mut b, pkg| {
                // The same purl the SBOM renderer emits, so an advisory that
                // matches a rendered component matches the stored membership.
                let purl = environment_sbom::package_purl(pkg, &pkg.scope);
                b.push_bind(id)
                    .push_bind(&pkg.scope.environment)
                    .push_bind(&pkg.scope.platform)
                    .push_bind(pkg.ecosystem.as_str())
                    .push_bind(&pkg.name)
                    .push_bind(&pkg.version)
                    .push_bind(&purl)
                    .push_bind(purl.as_deref().map(purl_base))
                    .push_bind(&pkg.key)
                    .push_bind(pkg.is_root);
            });
            qb.build()
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        }

        for chunk in env.edges.chunks(INSERT_BATCH_SIZE) {
            let mut qb = sqlx::QueryBuilder::new(
                "INSERT INTO environment_edges \
                 (environment_id, scope_environment, scope_platform, from_key, to_key, kind, requirement) ",
            );
            qb.push_values(chunk, |mut b, edge| {
                b.push_bind(id)
                    .push_bind(&edge.scope.environment)
                    .push_bind(&edge.scope.platform)
                    .push_bind(&edge.from)
                    .push_bind(&edge.to)
                    .push_bind(edge.kind.as_str())
                    .push_bind(&edge.requirement);
            });
            qb.build()
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(IngestOutcome {
            id,
            replaced,
            summary,
        })
    }

    /// Every environment stored in one repository, by name.
    pub async fn list(&self, repository_id: Uuid) -> Result<Vec<StoredEnvironment>> {
        let rows = sqlx::query_as::<_, EnvironmentRow>(
            "SELECT id, repository_id, name, lockfile_format, content_sha256, summary, created_at, updated_at \
             FROM environments WHERE repository_id = $1 ORDER BY name",
        )
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(EnvironmentRow::into_model).collect())
    }

    /// One stored environment and its per-scope counts. Scoped to the
    /// repository so an id from another tenant's repository is a 404, not a
    /// read.
    pub async fn get(
        &self,
        repository_id: Uuid,
        id: Uuid,
    ) -> Result<(StoredEnvironment, Vec<ScopeCount>)> {
        let row = sqlx::query_as::<_, EnvironmentRow>(
            "SELECT id, repository_id, name, lockfile_format, content_sha256, summary, created_at, updated_at \
             FROM environments WHERE id = $1 AND repository_id = $2",
        )
        .bind(id)
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Environment not found".to_string()))?;

        let scopes = sqlx::query_as::<_, ScopeCountRow>(
            "SELECT p.scope_environment, p.scope_platform, \
                    COUNT(p.id) AS memberships, \
                    (SELECT COUNT(*) FROM environment_edges e \
                     WHERE e.environment_id = p.environment_id \
                       AND e.scope_environment IS NOT DISTINCT FROM p.scope_environment \
                       AND e.scope_platform IS NOT DISTINCT FROM p.scope_platform) AS edges \
             FROM environment_packages p \
             WHERE p.environment_id = $1 \
             GROUP BY p.environment_id, p.scope_environment, p.scope_platform \
             ORDER BY p.scope_environment NULLS FIRST, p.scope_platform NULLS FIRST",
        )
        .bind(id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((
            row.into_model(),
            scopes
                .into_iter()
                .map(|s| ScopeCount {
                    environment: s.scope_environment,
                    platform: s.scope_platform,
                    memberships: s.memberships,
                    edges: s.edges,
                })
                .collect(),
        ))
    }

    /// Delete a stored environment (memberships and edges cascade). Returns
    /// whether a row existed.
    pub async fn delete(&self, repository_id: Uuid, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM environments WHERE id = $1 AND repository_id = $2")
            .bind(id)
            .bind(repository_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    /// The reverse index: which stored environments contain the component
    /// `purl` names, per platform, with the inclusion chains.
    ///
    /// The membership predicate is `purl_base = $1` — an index scan, never a
    /// graph scan. `visibility` restricts the answer to repositories the
    /// caller may read, rendered by
    /// [`build_member_visibility_clause`] exactly as `require_visible` would
    /// decide row by row. Inclusion paths come from re-running
    /// [`LockedEnvironment::explain`] over the stored edges of each hit
    /// scope, bounded by `max_paths` and [`MAX_LOOKUP_HITS`].
    pub async fn lookup_by_purl(
        &self,
        purl: &str,
        visibility: &MemberVisibility,
        max_paths: usize,
    ) -> Result<LookupOutcome> {
        let base = purl_base(purl);
        if base.is_empty() {
            return Err(AppError::Validation("purl must not be empty".to_string()));
        }
        let max_paths = max_paths.clamp(1, MAX_PATHS);

        // The clause references $2 (user) and $3 (repo-scope ids); binds that
        // a variant does not reference are sent as typed NULLs (see
        // build_member_visibility_clause for why the shape is fixed).
        let (clause, user_bind, scope_bind) = build_member_visibility_clause(visibility, "r", 2);
        let sql = format!(
            r#"SELECT e.id AS environment_id, e.name AS environment_name,
                      e.repository_id, e.lockfile_format, r.key AS repository_key,
                      p.scope_environment, p.scope_platform, p.package_key,
                      p.purl AS package_purl, p.name AS package_name, p.version AS package_version
               FROM environment_packages p
               JOIN environments e ON e.id = p.environment_id
               JOIN repositories r ON r.id = e.repository_id
               WHERE p.purl_base = $1 AND {clause}
               ORDER BY r.key, e.name,
                        p.scope_environment NULLS FIRST, p.scope_platform NULLS FIRST
               LIMIT $4"#
        );
        // One extra row distinguishes "exactly MAX hits" from "clipped".
        // AssertSqlSafe: the only interpolated value is `clause`, rendered by
        // build_member_visibility_clause from fixed SQL fragments — every
        // caller-controlled value travels as a bind parameter ($1..$4).
        let rows = sqlx::query_as::<_, HitRow>(sqlx::AssertSqlSafe(&*sql))
            .bind(base)
            .bind(user_bind)
            .bind(scope_bind)
            .bind(MAX_LOOKUP_HITS + 1)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let truncated = rows.len() as i64 > MAX_LOOKUP_HITS;
        let rows: Vec<HitRow> = rows.into_iter().take(MAX_LOOKUP_HITS as usize).collect();

        // Group the hit scopes by environment so each environment's graph is
        // reloaded once, no matter how many of its scopes matched.
        let mut by_environment: HashMap<Uuid, (String, Vec<usize>)> = HashMap::new();
        for (index, row) in rows.iter().enumerate() {
            by_environment
                .entry(row.environment_id)
                .or_insert_with(|| (row.lockfile_format.clone(), Vec::new()))
                .1
                .push(index);
        }

        let mut graphs: HashMap<Uuid, LockedEnvironment> = HashMap::new();
        for (environment_id, (lockfile_format, indices)) in &by_environment {
            let scopes: Vec<Scope> = indices.iter().map(|i| rows[*i].scope()).collect();
            let graph = self
                .load_scope_graph(*environment_id, lockfile_format, &scopes)
                .await?;
            graphs.insert(*environment_id, graph);
        }

        let mut hits = Vec::with_capacity(rows.len());
        for row in rows {
            let scope = row.scope();
            let paths = match graphs.get(&row.environment_id) {
                Some(graph) => {
                    let display = display_names(graph, &scope);
                    graph
                        .explain(&scope, &row.package_key, max_paths)
                        .into_iter()
                        .map(|chain| {
                            chain
                                .iter()
                                .map(|key| {
                                    display
                                        .get(key.as_str())
                                        .cloned()
                                        .unwrap_or_else(|| key.clone())
                                })
                                .collect()
                        })
                        .collect()
                }
                // The membership row that produced this hit always reloads;
                // a miss would be a bug, not a state to render.
                None => Vec::new(),
            };
            hits.push(EnvironmentHit {
                environment_id: row.environment_id,
                environment_name: row.environment_name,
                repository_id: row.repository_id,
                repository_key: row.repository_key,
                scope,
                package_key: row.package_key,
                package_name: row.package_name,
                package_version: row.package_version,
                package_purl: row.package_purl,
                paths,
            });
        }

        Ok(LookupOutcome {
            purl: purl.to_string(),
            purl_base: base.to_string(),
            hits,
            truncated,
        })
    }

    /// Reload the requested scopes of one stored environment as a
    /// [`LockedEnvironment`], so the parser's own reverse-BFS
    /// ([`LockedEnvironment::explain`]) answers the inclusion path from the
    /// *stored* edges — the same algorithm over the same data as the
    /// parse-time answer, never a re-derivation that could disagree with it.
    ///
    /// Scope columns are compared with `IS NOT DISTINCT FROM` so a NULL axis
    /// (a format with no environment or platform concept) matches its NULL.
    async fn load_scope_graph(
        &self,
        environment_id: Uuid,
        lockfile_format: &str,
        scopes: &[Scope],
    ) -> Result<LockedEnvironment> {
        let scope_envs: Vec<Option<String>> =
            scopes.iter().map(|s| s.environment.clone()).collect();
        let scope_plats: Vec<Option<String>> = scopes.iter().map(|s| s.platform.clone()).collect();

        let packages = sqlx::query_as::<_, PackageRow>(
            "SELECT p.scope_environment, p.scope_platform, p.ecosystem, p.name, p.version, \
                    p.package_key, p.is_root \
             FROM environment_packages p \
             JOIN unnest($2::text[], $3::text[]) AS s(se, sp) \
               ON p.scope_environment IS NOT DISTINCT FROM s.se \
              AND p.scope_platform IS NOT DISTINCT FROM s.sp \
             WHERE p.environment_id = $1",
        )
        .bind(environment_id)
        .bind(&scope_envs)
        .bind(&scope_plats)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let edges = sqlx::query_as::<_, EdgeRow>(
            "SELECT e.scope_environment, e.scope_platform, e.from_key, e.to_key, e.kind, e.requirement \
             FROM environment_edges e \
             JOIN unnest($2::text[], $3::text[]) AS s(se, sp) \
               ON e.scope_environment IS NOT DISTINCT FROM s.se \
              AND e.scope_platform IS NOT DISTINCT FROM s.sp \
             WHERE e.environment_id = $1",
        )
        .bind(environment_id)
        .bind(&scope_envs)
        .bind(&scope_plats)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(LockedEnvironment {
            format: lock_format(lockfile_format),
            format_version: None,
            environments: Vec::new(),
            platforms: Vec::new(),
            packages: packages
                .into_iter()
                .map(|p| LockedPackage {
                    scope: Scope {
                        environment: p.scope_environment,
                        platform: p.scope_platform,
                    },
                    // Only the fields `explain` reads are faithfully
                    // restored; the rest never leave the row again.
                    ecosystem: ecosystem(&p.ecosystem),
                    name: p.name,
                    version: p.version,
                    build: None,
                    subdir: None,
                    url: None,
                    source: None,
                    hashes: Vec::new(),
                    key: p.package_key,
                    is_root: p.is_root,
                })
                .collect(),
            edges: edges
                .into_iter()
                .map(|e| LockEdge {
                    scope: Scope {
                        environment: e.scope_environment,
                        platform: e.scope_platform,
                    },
                    from: e.from_key,
                    to: e.to_key,
                    kind: edge_kind(&e.kind),
                    requirement: e.requirement,
                })
                .collect(),
            unresolved: Vec::new(),
        })
    }
}

/// The `key -> name@version` rendering map for one scope's packages, used to
/// turn `explain`'s chains of lockfile keys into chains a human can act on.
fn display_names(env: &LockedEnvironment, scope: &Scope) -> HashMap<String, String> {
    env.packages_in(scope)
        .map(|p| (p.key.clone(), display_name(&p.name, p.version.as_deref())))
        .collect()
}

/// The stored format string back to its enum. Display-only on this read path
/// — `explain` never consults it — so an unrecognized stored value degrades
/// to an arbitrary variant rather than failing the lookup.
fn lock_format(raw: &str) -> LockFormat {
    match raw {
        "pixi.lock" => LockFormat::PixiLock,
        "conda-lock" => LockFormat::CondaLock,
        "package-lock.json" => LockFormat::NpmPackageLock,
        "Cargo.lock" => LockFormat::CargoLock,
        "poetry.lock" => LockFormat::PoetryLock,
        "uv.lock" => LockFormat::UvLock,
        _ => LockFormat::CondaLock,
    }
}

/// The stored ecosystem string back to its enum. `explain` only needs a
/// value to carry, never to resolve against, so an unrecognized stored value
/// degrades rather than failing the lookup.
fn ecosystem(raw: &str) -> Ecosystem {
    match raw {
        "pypi" => Ecosystem::PyPi,
        "npm" => Ecosystem::Npm,
        "cargo" => Ecosystem::Cargo,
        _ => Ecosystem::Conda,
    }
}

/// The stored edge-kind string back to its enum. Only `Constrains` changes
/// behavior downstream (it is not an install requirement), and it is spelled
/// exactly; anything unrecognized was a runtime edge by construction.
fn edge_kind(raw: &str) -> EdgeKind {
    match raw {
        "build" => EdgeKind::Build,
        "dev" => EdgeKind::Dev,
        "optional" => EdgeKind::Optional,
        "peer" => EdgeKind::Peer,
        "constrains" => EdgeKind::Constrains,
        _ => EdgeKind::Runtime,
    }
}

#[derive(sqlx::FromRow)]
struct EnvironmentRow {
    id: Uuid,
    repository_id: Uuid,
    name: String,
    lockfile_format: String,
    content_sha256: String,
    summary: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl EnvironmentRow {
    fn into_model(self) -> StoredEnvironment {
        StoredEnvironment {
            id: self.id,
            repository_id: self.repository_id,
            name: self.name,
            lockfile_format: self.lockfile_format,
            content_sha256: self.content_sha256,
            summary: self.summary,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ScopeCountRow {
    scope_environment: Option<String>,
    scope_platform: Option<String>,
    memberships: i64,
    edges: i64,
}

#[derive(sqlx::FromRow)]
struct HitRow {
    environment_id: Uuid,
    environment_name: String,
    repository_id: Uuid,
    lockfile_format: String,
    repository_key: String,
    scope_environment: Option<String>,
    scope_platform: Option<String>,
    package_key: String,
    package_purl: Option<String>,
    package_name: String,
    package_version: Option<String>,
}

impl HitRow {
    fn scope(&self) -> Scope {
        Scope {
            environment: self.scope_environment.clone(),
            platform: self.scope_platform.clone(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct PackageRow {
    scope_environment: Option<String>,
    scope_platform: Option<String>,
    ecosystem: String,
    name: String,
    version: Option<String>,
    package_key: String,
    is_root: bool,
}

#[derive(sqlx::FromRow)]
struct EdgeRow {
    scope_environment: Option<String>,
    scope_platform: Option<String>,
    from_key: String,
    to_key: String,
    kind: String,
    requirement: String,
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::environment_lock;

    /// Env "data-science": pillow -> libwebp on TWO platforms, plus a
    /// linux-only package (the per-platform isolation probe) and a pip
    /// package both environments share.
    const ENV_A: &str = r#"
version: 1
metadata:
  platforms:
    - linux-64
    - osx-arm64
package:
  - name: pillow
    version: 10.0.0
    manager: conda
    platform: linux-64
    dependencies:
      libwebp: ">=1.3.2"
  - name: libwebp
    version: 1.3.2
    manager: conda
    platform: linux-64
    dependencies: {}
  - name: linux-only-pkg
    version: 0.1.0
    manager: conda
    platform: linux-64
    dependencies: {}
  - name: requests
    version: 2.31.0
    manager: pip
    platform: linux-64
    dependencies: {}
  - name: pillow
    version: 10.0.0
    manager: conda
    platform: osx-arm64
    dependencies:
      libwebp: ">=1.3.2"
  - name: libwebp
    version: 1.3.2
    manager: conda
    platform: osx-arm64
    dependencies: {}
  - name: requests
    version: 2.31.0
    manager: pip
    platform: osx-arm64
    dependencies: {}
"#;

    /// Env "web-serving": image-service -> pillow -> libwebp, linux-64 only.
    /// Same transitive component as ENV_A, DIFFERENT inclusion path.
    const ENV_B: &str = r#"
version: 1
metadata:
  platforms:
    - linux-64
package:
  - name: image-service
    version: 2.0.0
    manager: conda
    platform: linux-64
    dependencies:
      pillow: ">=10"
  - name: pillow
    version: 10.0.0
    manager: conda
    platform: linux-64
    dependencies:
      libwebp: ">=1.3.2"
  - name: libwebp
    version: 1.3.2
    manager: conda
    platform: linux-64
    dependencies: {}
  - name: requests
    version: 2.31.0
    manager: pip
    platform: linux-64
    dependencies: {}
"#;

    /// Five roots converging on one shared component: the path-cap probe.
    const ENV_C: &str = r#"
version: 1
metadata:
  platforms:
    - linux-64
package:
  - name: root-a
    version: 1.0.0
    manager: conda
    platform: linux-64
    dependencies:
      shared-lib: ""
  - name: root-b
    version: 1.0.0
    manager: conda
    platform: linux-64
    dependencies:
      shared-lib: ""
  - name: root-c
    version: 1.0.0
    manager: conda
    platform: linux-64
    dependencies:
      shared-lib: ""
  - name: root-d
    version: 1.0.0
    manager: conda
    platform: linux-64
    dependencies:
      shared-lib: ""
  - name: root-e
    version: 1.0.0
    manager: conda
    platform: linux-64
    dependencies:
      shared-lib: ""
  - name: shared-lib
    version: 3.1.0
    manager: conda
    platform: linux-64
    dependencies: {}
"#;

    /// ENV_A re-solved without libwebp: re-ingest must remove the stale
    /// membership rather than answer "exposed" forever.
    const ENV_A_RESOLVED: &str = r#"
version: 1
metadata:
  platforms:
    - linux-64
package:
  - name: pillow
    version: 10.1.0
    manager: conda
    platform: linux-64
    dependencies: {}
"#;

    /// One `noarch` build solved onto two platforms. `platform:` names the
    /// graph; only the channel URL says what the artifact actually is.
    const ENV_NOARCH: &str = r#"
version: 1
metadata:
  platforms:
    - linux-64
    - osx-arm64
package:
  - name: tzdata
    version: 2024a
    build: h0c530f3_0
    manager: conda
    platform: linux-64
    url: https://conda.anaconda.org/conda-forge/noarch/tzdata-2024a-h0c530f3_0.conda
    dependencies: {}
  - name: tzdata
    version: 2024a
    build: h0c530f3_0
    manager: conda
    platform: osx-arm64
    url: https://conda.anaconda.org/conda-forge/noarch/tzdata-2024a-h0c530f3_0.conda
    dependencies: {}
"#;

    fn parse(bytes: &str) -> LockedEnvironment {
        environment_lock::parse_named_lockfile("conda-lock.yml", bytes.as_bytes())
            .expect("fixture lockfile parses")
    }

    async fn ingest(
        svc: &EnvironmentService,
        repo_id: Uuid,
        name: &str,
        bytes: &str,
    ) -> IngestOutcome {
        svc.ingest(repo_id, name, &format!("sha256-{name}"), &parse(bytes))
            .await
            .expect("ingest")
    }

    /// The hits a lookup returned for THIS test's repository — the shared
    /// test database may legitimately hold other suites' environments.
    fn hits_in(out: &LookupOutcome, repo_id: Uuid) -> Vec<&EnvironmentHit> {
        out.hits
            .iter()
            .filter(|h| h.repository_id == repo_id)
            .collect()
    }

    #[test]
    fn purl_base_strips_qualifiers() {
        assert_eq!(
            purl_base("pkg:conda/libwebp@1.3.2?build=h1234_0&channel=conda-forge&subdir=linux-64"),
            "pkg:conda/libwebp@1.3.2"
        );
        assert_eq!(
            purl_base("pkg:pypi/requests@2.31.0"),
            "pkg:pypi/requests@2.31.0"
        );
        assert_eq!(purl_base("  pkg:pypi/x@1 ?a=b"), "pkg:pypi/x@1");
    }

    #[test]
    fn clamp_max_paths_bounds() {
        assert_eq!(clamp_max_paths(None), DEFAULT_MAX_PATHS);
        assert_eq!(clamp_max_paths(Some(0)), 1);
        assert_eq!(clamp_max_paths(Some(3)), 3);
        assert_eq!(clamp_max_paths(Some(u64::MAX)), MAX_PATHS);
    }

    /// The acceptance test: two environments sharing a transitive component,
    /// different inclusion paths, two platforms.
    #[tokio::test]
    async fn lookup_names_both_environments_per_platform_with_inclusion_paths() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let svc = EnvironmentService::new(fx.pool.clone());
        ingest(&svc, fx.repo_id, "data-science", ENV_A).await;
        ingest(&svc, fx.repo_id, "web-serving", ENV_B).await;

        let out = svc
            .lookup_by_purl(
                "pkg:conda/libwebp@1.3.2",
                &MemberVisibility::Unfiltered,
                DEFAULT_MAX_PATHS,
            )
            .await
            .expect("lookup");
        let hits = hits_in(&out, fx.repo_id);
        assert_eq!(
            hits.len(),
            3,
            "data-science x2 platforms + web-serving x1: {hits:?}"
        );

        let mut seen: Vec<(&str, Option<&str>)> = hits
            .iter()
            .map(|h| (h.environment_name.as_str(), h.scope.platform.as_deref()))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                ("data-science", Some("linux-64")),
                ("data-science", Some("osx-arm64")),
                ("web-serving", Some("linux-64")),
            ]
        );

        for hit in hits {
            let expected = if hit.environment_name == "data-science" {
                vec![vec![
                    "pillow@10.0.0".to_string(),
                    "libwebp@1.3.2".to_string(),
                ]]
            } else {
                vec![vec![
                    "image-service@2.0.0".to_string(),
                    "pillow@10.0.0".to_string(),
                    "libwebp@1.3.2".to_string(),
                ]]
            };
            assert_eq!(
                hit.paths, expected,
                "inclusion path for {}/{}",
                hit.environment_name, hit.scope
            );
            // The full qualified purl travels with the hit: platform builds
            // are distinguishable even though the lookup matched the base.
            let purl = hit.package_purl.as_deref().expect("stored purl");
            assert!(
                purl.contains("subdir="),
                "conda hit carries the qualified purl: {purl}"
            );
        }
        fx.teardown().await;
    }

    /// The lookup is keyed the way an advisory names a component: the bare
    /// purl out of the advisory JSON, no build or channel qualifiers.
    #[tokio::test]
    async fn advisory_purl_query_names_affected_environments() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let svc = EnvironmentService::new(fx.pool.clone());
        ingest(&svc, fx.repo_id, "data-science", ENV_A).await;
        ingest(&svc, fx.repo_id, "web-serving", ENV_B).await;

        // The component identity an advisory carries: a bare pypi purl.
        let advisory = serde_json::json!({
            "id": "GHSA-j8r2-6p8f-2345",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "requests", "purl": "pkg:pypi/requests@2.31.0"},
                "versions": ["2.31.0"]
            }]
        });
        let purl = advisory["affected"][0]["package"]["purl"]
            .as_str()
            .expect("advisory purl");

        let out = svc
            .lookup_by_purl(purl, &MemberVisibility::Unfiltered, DEFAULT_MAX_PATHS)
            .await
            .expect("lookup");
        let hits = hits_in(&out, fx.repo_id);
        assert_eq!(hits.len(), 3, "requests is in both environments: {hits:?}");
        // Nothing depends on requests in either environment: it IS the root
        // layer, so the inclusion path is the component itself.
        for hit in hits {
            assert_eq!(hit.paths, vec![vec!["requests@2.31.0".to_string()]]);
        }
        fx.teardown().await;
    }

    /// A fully-qualified conda purl reduces to its base for the index lookup
    /// (advisories are name/version-scoped; see the module docs).
    #[tokio::test]
    async fn qualified_conda_purl_matches_on_base() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let svc = EnvironmentService::new(fx.pool.clone());
        ingest(&svc, fx.repo_id, "data-science", ENV_A).await;

        let out = svc
            .lookup_by_purl(
                "pkg:conda/libwebp@1.3.2?build=h1234_0&channel=conda-forge&subdir=linux-64",
                &MemberVisibility::Unfiltered,
                DEFAULT_MAX_PATHS,
            )
            .await
            .expect("lookup");
        assert_eq!(out.purl_base, "pkg:conda/libwebp@1.3.2");
        assert_eq!(hits_in(&out, fx.repo_id).len(), 2);
        fx.teardown().await;
    }

    /// A `noarch` member is stored under the identity its *artifact* has
    /// (#4151), so the reverse index joins the two. Before the fix the
    /// membership borrowed the scope's platform and the same build produced
    /// one purl per platform it was resolved onto, none of them the
    /// artifact's.
    #[tokio::test]
    async fn noarch_member_is_stored_under_its_own_subdir() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        const NOARCH_PURL: &str =
            "pkg:conda/tzdata@2024a?build=h0c530f3_0&channel=conda-forge&subdir=noarch";
        let svc = EnvironmentService::new(fx.pool.clone());
        ingest(&svc, fx.repo_id, "tz-env", ENV_NOARCH).await;

        let out = svc
            .lookup_by_purl(
                NOARCH_PURL,
                &MemberVisibility::Unfiltered,
                DEFAULT_MAX_PATHS,
            )
            .await
            .expect("lookup");
        let hits = hits_in(&out, fx.repo_id);
        assert_eq!(
            hits.len(),
            2,
            "one membership per solved platform: {hits:?}"
        );
        for hit in hits {
            assert_eq!(
                hit.package_purl.as_deref(),
                Some(NOARCH_PURL),
                "{} borrowed its scope platform instead of the package subdir",
                hit.scope
            );
        }
        fx.teardown().await;
    }

    /// Per-platform isolation: a package present only in the linux-64 graph
    /// must not produce an osx-arm64 hit. This is the assertion the #4088
    /// mutation (scope leakage) has to fail.
    #[tokio::test]
    async fn lookup_respects_platform_isolation() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let svc = EnvironmentService::new(fx.pool.clone());
        ingest(&svc, fx.repo_id, "data-science", ENV_A).await;

        let out = svc
            .lookup_by_purl(
                "pkg:conda/linux-only-pkg@0.1.0",
                &MemberVisibility::Unfiltered,
                DEFAULT_MAX_PATHS,
            )
            .await
            .expect("lookup");
        let hits = hits_in(&out, fx.repo_id);
        assert_eq!(hits.len(), 1, "linux-only package: {hits:?}");
        assert_eq!(hits[0].scope.platform.as_deref(), Some("linux-64"));
        fx.teardown().await;
    }

    /// The path cap is honoured per hit: five roots converge on shared-lib,
    /// and max_paths=2 must clip the chains to two.
    #[tokio::test]
    async fn lookup_respects_path_cap() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let svc = EnvironmentService::new(fx.pool.clone());
        ingest(&svc, fx.repo_id, "many-roots", ENV_C).await;

        let out = svc
            .lookup_by_purl(
                "pkg:conda/shared-lib@3.1.0",
                &MemberVisibility::Unfiltered,
                clamp_max_paths(Some(2)),
            )
            .await
            .expect("lookup");
        let hits = hits_in(&out, fx.repo_id);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].paths.len(), 2, "capped at max_paths");
        for chain in &hits[0].paths {
            assert_eq!(chain.len(), 2, "root -> shared-lib");
            assert_eq!(chain.last().map(String::as_str), Some("shared-lib@3.1.0"));
        }
        fx.teardown().await;
    }

    /// Re-ingesting a re-solved environment under the same name replaces the
    /// stored graph: the removed component no longer answers.
    #[tokio::test]
    async fn reingest_replaces_stale_membership() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let svc = EnvironmentService::new(fx.pool.clone());
        let first = ingest(&svc, fx.repo_id, "data-science", ENV_A).await;
        assert!(!first.replaced);
        let second = ingest(&svc, fx.repo_id, "data-science", ENV_A_RESOLVED).await;
        assert!(second.replaced);
        assert_eq!(first.id, second.id, "identity is (repository, name)");

        let out = svc
            .lookup_by_purl(
                "pkg:conda/libwebp@1.3.2",
                &MemberVisibility::Unfiltered,
                DEFAULT_MAX_PATHS,
            )
            .await
            .expect("lookup");
        assert!(
            hits_in(&out, fx.repo_id).is_empty(),
            "the re-solved environment no longer contains libwebp"
        );
        let listed = svc.list(fx.repo_id).await.expect("list");
        assert_eq!(listed.len(), 1, "replace, not duplicate");
        let (_, scopes) = svc.get(fx.repo_id, first.id).await.expect("get");
        assert_eq!(scopes.len(), 1, "the re-solve dropped osx-arm64");
        fx.teardown().await;
    }

    /// Empty and oversized names are rejected before any storage write.
    #[tokio::test]
    async fn ingest_validates_name() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let svc = EnvironmentService::new(fx.pool.clone());
        assert!(
            svc.ingest(fx.repo_id, "  ", "sha", &parse(ENV_A))
                .await
                .is_err(),
            "blank name rejected"
        );
        let long = "x".repeat(MAX_ENVIRONMENT_NAME_BYTES + 1);
        assert!(
            svc.ingest(fx.repo_id, &long, "sha", &parse(ENV_A))
                .await
                .is_err(),
            "oversized name rejected"
        );
        fx.teardown().await;
    }

    /// Performance acceptance: with hundreds of stored environments the
    /// membership lookup is an index scan over the purl index, not a table
    /// scan that degrades linearly with stored rows. Asserts the query shape
    /// via EXPLAIN (with the sequential scan disabled, so the assertion is
    /// about the index being *usable for this predicate*, not about the
    /// planner's row-count estimate on a test-sized table), then runs the
    /// real lookup against the seeded set.
    #[tokio::test]
    async fn lookup_is_an_index_scan_at_realistic_environment_counts() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        // 300 stored environments x 20 packages: a realistic deployment.
        for i in 0..300 {
            let env_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO environments (id, repository_id, name, lockfile_format, content_sha256, summary) \
                 VALUES ($1, $2, $3, 'conda-lock', $4, '{}')",
            )
            .bind(env_id)
            .bind(fx.repo_id)
            .bind(format!("perf-env-{i:04}"))
            .bind(format!("sha-{i}"))
            .execute(&fx.pool)
            .await
            .expect("seed environment");
            let mut qb = sqlx::QueryBuilder::new(
                "INSERT INTO environment_packages \
                 (environment_id, ecosystem, name, version, purl, purl_base, package_key) ",
            );
            qb.push_values(0..20usize, |mut b, j| {
                b.push_bind(env_id)
                    .push_bind("pypi")
                    .push_bind(format!("perfpkg{j}"))
                    .push_bind("1.0.0")
                    .push_bind(format!("pkg:pypi/perfpkg{j}@1.0.0"))
                    .push_bind(format!("pkg:pypi/perfpkg{j}@1.0.0"))
                    .push_bind(format!("pypi:perfpkg{j}@1.0.0"));
            });
            qb.build().execute(&fx.pool).await.expect("seed packages");
        }
        let svc = EnvironmentService::new(fx.pool.clone());
        ingest(&svc, fx.repo_id, "needle-env", ENV_A).await;

        let mut tx = fx.pool.begin().await.expect("tx");
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *tx)
            .await
            .expect("seqscan off");
        let plan: Vec<(String,)> = sqlx::query_as(
            "EXPLAIN SELECT p.environment_id FROM environment_packages p \
             WHERE p.purl_base = 'pkg:pypi/perfpkg3@1.0.0'",
        )
        .fetch_all(&mut *tx)
        .await
        .expect("explain");
        tx.rollback().await.expect("rollback");
        let plan_text = plan
            .iter()
            .map(|(line,)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            plan_text.contains("idx_environment_packages_purl_base"),
            "membership lookup must scan the purl index:\n{plan_text}"
        );

        let started = std::time::Instant::now();
        let out = svc
            .lookup_by_purl(
                "pkg:conda/libwebp@1.3.2",
                &MemberVisibility::Unfiltered,
                DEFAULT_MAX_PATHS,
            )
            .await
            .expect("lookup");
        let elapsed = started.elapsed();
        let hits = hits_in(&out, fx.repo_id);
        assert_eq!(hits.len(), 2, "the needle among 300 environments");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "lookup over 301 environments took {elapsed:?}; the index is not doing its job"
        );
        fx.teardown().await;
    }
}
