//! Repository service.
//!
//! Handles repository CRUD operations, virtual repository management, and quota enforcement.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::api::validation::validate_outbound_url;
use crate::error::{AppError, Result};
#[allow(unused_imports)] // Used by sqlx query macros
use crate::models::repository::{
    ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use crate::services::opensearch_service::{OpenSearchService, RepositoryDocument};

/// Request to create a new repository
#[derive(Debug)]
pub struct CreateRepositoryRequest {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub storage_backend: String,
    pub storage_path: String,
    pub upstream_url: Option<String>,
    pub is_public: bool,
    pub quota_bytes: Option<i64>,
    /// When true, direct user uploads are rejected (artifacts must arrive via
    /// the promotion path). Defaults to false.
    pub promotion_only: bool,
    /// Custom format key for WASM plugin handlers (e.g. "rpm-custom").
    pub format_key: Option<String>,
    /// User who is creating this repository. When set, the repository records
    /// this user as `created_by` and the creator is auto-granted the
    /// `developer` role scoped to the new repository (owner auto-grant), so the
    /// creator retains access under per-repo authorization.
    pub created_by: Option<Uuid>,
}

/// Request to update a repository
#[derive(Debug)]
pub struct UpdateRepositoryRequest {
    pub key: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_public: Option<bool>,
    pub quota_bytes: Option<Option<i64>>,
    pub upstream_url: Option<String>,
    /// When `Some`, sets the `promotion_only` flag; `None` leaves it unchanged.
    pub promotion_only: Option<bool>,
}

/// Controls which repositories a caller can see in listing results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoVisibility {
    /// Unauthenticated caller: only public repositories.
    PublicOnly,
    /// Admin caller: all repositories, regardless of visibility or grants.
    All,
    /// Authenticated non-admin caller: public repositories plus any private
    /// repositories where the user holds a role assignment (direct or global).
    User(Uuid),
    /// Repo-scoped API token: visibility is restricted to exactly the set of
    /// repository IDs the token is allowed to access. Unlike [`Self::User`],
    /// this does NOT widen to public repos or to all of the owner's grants —
    /// the listing must reflect only the token's scope. The IDs were already
    /// validated against the owner's access when the token was minted.
    Ids(Vec<Uuid>),
}

/// Value bound at the visibility parameter (`$3`) of repository listing
/// queries. The concrete type depends on the [`RepoVisibility`] variant:
/// `PublicOnly`/`All` bind NULL, `User` binds a single `Uuid`, and `Ids`
/// binds a `Uuid[]` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VisibilityBind {
    /// Bind a single user id (or NULL when `None`).
    User(Option<Uuid>),
    /// Bind an array of repository ids.
    Ids(Vec<Uuid>),
}

// ---------------------------------------------------------------------------
// Pure helper functions (no DB, testable in isolation)
// ---------------------------------------------------------------------------

/// Validate that a remote repository has an upstream URL and that the URL is
/// safe to contact (anti-SSRF). Returns an error if validation fails.
pub(crate) fn validate_remote_upstream(
    repo_type: &RepositoryType,
    upstream_url: &Option<String>,
) -> Result<()> {
    if *repo_type == RepositoryType::Remote {
        match upstream_url {
            None => {
                return Err(AppError::Validation(
                    "Remote repository must have an upstream URL".to_string(),
                ))
            }
            Some(url) => validate_outbound_url(url, "Upstream URL")?,
        }
    } else if let Some(url) = upstream_url {
        validate_outbound_url(url, "Upstream URL")?;
    }
    Ok(())
}

/// Derive a format key string from a RepositoryFormat enum.
///
/// Returns the canonical snake_case format key matching the database enum
/// value and the `FormatHandler::format_key()` contract. Using `Debug`
/// formatting followed by `to_lowercase()` is insufficient because it
/// drops underscores from multi-word variants (e.g., `CondaNative` becomes
/// `"condanative"` instead of `"conda_native"`).
pub(crate) fn derive_format_key(format: &RepositoryFormat) -> String {
    match format {
        RepositoryFormat::Maven => "maven",
        RepositoryFormat::Gradle => "gradle",
        RepositoryFormat::Npm => "npm",
        RepositoryFormat::Pypi => "pypi",
        RepositoryFormat::Nuget => "nuget",
        RepositoryFormat::Go => "go",
        RepositoryFormat::Rubygems => "rubygems",
        RepositoryFormat::Docker => "docker",
        RepositoryFormat::Helm => "helm",
        RepositoryFormat::Rpm => "rpm",
        RepositoryFormat::Debian => "debian",
        RepositoryFormat::Conan => "conan",
        RepositoryFormat::Cargo => "cargo",
        RepositoryFormat::Generic => "generic",
        RepositoryFormat::Podman => "podman",
        RepositoryFormat::Buildx => "buildx",
        RepositoryFormat::Oras => "oras",
        RepositoryFormat::WasmOci => "wasm_oci",
        RepositoryFormat::HelmOci => "helm_oci",
        RepositoryFormat::Poetry => "poetry",
        RepositoryFormat::Conda => "conda",
        RepositoryFormat::Yarn => "yarn",
        RepositoryFormat::Bower => "bower",
        RepositoryFormat::Pnpm => "pnpm",
        RepositoryFormat::Chocolatey => "chocolatey",
        RepositoryFormat::Powershell => "powershell",
        RepositoryFormat::Terraform => "terraform",
        RepositoryFormat::Opentofu => "opentofu",
        RepositoryFormat::Alpine => "alpine",
        RepositoryFormat::CondaNative => "conda_native",
        RepositoryFormat::Composer => "composer",
        RepositoryFormat::Hex => "hex",
        RepositoryFormat::Cocoapods => "cocoapods",
        RepositoryFormat::Swift => "swift",
        RepositoryFormat::Pub => "pub",
        RepositoryFormat::Sbt => "sbt",
        RepositoryFormat::Chef => "chef",
        RepositoryFormat::Puppet => "puppet",
        RepositoryFormat::Ansible => "ansible",
        RepositoryFormat::Gitlfs => "gitlfs",
        RepositoryFormat::Vscode => "vscode",
        RepositoryFormat::Jetbrains => "jetbrains",
        RepositoryFormat::Huggingface => "huggingface",
        RepositoryFormat::Mlmodel => "mlmodel",
        RepositoryFormat::Cran => "cran",
        RepositoryFormat::Vagrant => "vagrant",
        RepositoryFormat::Opkg => "opkg",
        RepositoryFormat::P2 => "p2",
        RepositoryFormat::Bazel => "bazel",
        RepositoryFormat::Protobuf => "protobuf",
        RepositoryFormat::Incus => "incus",
        RepositoryFormat::Lxc => "lxc",
    }
    .to_string()
}

/// Build a SQL LIKE search pattern from a user query string.
pub(crate) fn build_search_pattern(query: Option<&str>) -> Option<String> {
    query.map(|q| format!("%{}%", q.to_lowercase()))
}

/// Build the SQL visibility clause and optional user_id bind value for
/// repository listing queries.
///
/// The returned clause references `$3` as the user_id parameter.
///
/// - `PublicOnly` -> only public repos, user_id bound as NULL.
/// - `All`        -> no visibility restriction (always true), user_id bound as NULL.
/// - `User(id)`   -> public repos OR repos the user has a role_assignment for.
/// - `Ids(ids)`   -> only repos whose id is in `ids` (repo-scoped token).
pub(crate) fn build_visibility_clause(visibility: &RepoVisibility) -> (String, VisibilityBind) {
    match visibility {
        RepoVisibility::PublicOnly => ("is_public = true".to_string(), VisibilityBind::User(None)),
        RepoVisibility::All => ("true".to_string(), VisibilityBind::User(None)),
        RepoVisibility::User(user_id) => {
            let clause = r#"(
                is_public = true
                OR EXISTS (
                    SELECT 1 FROM role_assignments ra
                    WHERE ra.user_id = $3
                      AND (ra.repository_id = repositories.id OR ra.repository_id IS NULL)
                )
            )"#
            .to_string();
            (clause, VisibilityBind::User(Some(*user_id)))
        }
        RepoVisibility::Ids(ids) => {
            // Restrict strictly to the token's allowed set. An empty set must
            // match no rows (not "all rows") — `id = ANY('{}')` is correctly
            // false for every row in Postgres.
            (
                "repositories.id = ANY($3)".to_string(),
                VisibilityBind::Ids(ids.clone()),
            )
        }
    }
}

/// Check whether a format_enabled value should cause repo creation to be rejected.
/// Returns true if the format handler is explicitly disabled.
pub(crate) fn should_reject_disabled_format(format_enabled: Option<bool>) -> bool {
    format_enabled == Some(false)
}

/// Pure parse of a user-supplied format string into a built-in
/// [`RepositoryFormat`] variant. Returns `None` for strings that do not match
/// any built-in variant; callers are expected to fall back to the
/// `format_handlers` table to resolve plugin-provided formats.
///
/// Case-insensitive. The accepted strings are the canonical snake_case keys
/// produced by [`derive_format_key`], so this is the inverse of that function
/// on the built-in domain.
pub(crate) fn parse_format_str(s: &str) -> Option<RepositoryFormat> {
    match s.to_lowercase().as_str() {
        "maven" => Some(RepositoryFormat::Maven),
        "gradle" => Some(RepositoryFormat::Gradle),
        "npm" => Some(RepositoryFormat::Npm),
        "pypi" => Some(RepositoryFormat::Pypi),
        "nuget" => Some(RepositoryFormat::Nuget),
        "go" => Some(RepositoryFormat::Go),
        "rubygems" => Some(RepositoryFormat::Rubygems),
        "docker" => Some(RepositoryFormat::Docker),
        "helm" => Some(RepositoryFormat::Helm),
        "rpm" => Some(RepositoryFormat::Rpm),
        "debian" => Some(RepositoryFormat::Debian),
        "conan" => Some(RepositoryFormat::Conan),
        "cargo" => Some(RepositoryFormat::Cargo),
        "generic" => Some(RepositoryFormat::Generic),
        "podman" => Some(RepositoryFormat::Podman),
        "buildx" => Some(RepositoryFormat::Buildx),
        "oras" => Some(RepositoryFormat::Oras),
        "wasm_oci" => Some(RepositoryFormat::WasmOci),
        "helm_oci" => Some(RepositoryFormat::HelmOci),
        "poetry" => Some(RepositoryFormat::Poetry),
        "conda" => Some(RepositoryFormat::Conda),
        "yarn" => Some(RepositoryFormat::Yarn),
        "bower" => Some(RepositoryFormat::Bower),
        "pnpm" => Some(RepositoryFormat::Pnpm),
        "chocolatey" => Some(RepositoryFormat::Chocolatey),
        "powershell" => Some(RepositoryFormat::Powershell),
        "terraform" => Some(RepositoryFormat::Terraform),
        "opentofu" => Some(RepositoryFormat::Opentofu),
        "alpine" => Some(RepositoryFormat::Alpine),
        "conda_native" => Some(RepositoryFormat::CondaNative),
        "composer" => Some(RepositoryFormat::Composer),
        "hex" => Some(RepositoryFormat::Hex),
        "cocoapods" => Some(RepositoryFormat::Cocoapods),
        "swift" => Some(RepositoryFormat::Swift),
        "pub" => Some(RepositoryFormat::Pub),
        "sbt" => Some(RepositoryFormat::Sbt),
        "chef" => Some(RepositoryFormat::Chef),
        "puppet" => Some(RepositoryFormat::Puppet),
        "ansible" => Some(RepositoryFormat::Ansible),
        "gitlfs" => Some(RepositoryFormat::Gitlfs),
        "vscode" => Some(RepositoryFormat::Vscode),
        "jetbrains" => Some(RepositoryFormat::Jetbrains),
        "huggingface" => Some(RepositoryFormat::Huggingface),
        "mlmodel" => Some(RepositoryFormat::Mlmodel),
        "cran" => Some(RepositoryFormat::Cran),
        "vagrant" => Some(RepositoryFormat::Vagrant),
        "opkg" => Some(RepositoryFormat::Opkg),
        "p2" => Some(RepositoryFormat::P2),
        "bazel" => Some(RepositoryFormat::Bazel),
        "protobuf" => Some(RepositoryFormat::Protobuf),
        "incus" => Some(RepositoryFormat::Incus),
        "lxc" => Some(RepositoryFormat::Lxc),
        _ => None,
    }
}

/// Calculate quota usage as a fraction (0.0 to 1.0+).
pub(crate) fn quota_usage_percentage(used_bytes: i64, quota_bytes: i64) -> f64 {
    if quota_bytes <= 0 {
        return 0.0;
    }
    used_bytes as f64 / quota_bytes as f64
}

/// Check whether quota usage exceeds the warning threshold (80%).
pub(crate) fn exceeds_quota_warning_threshold(used_bytes: i64, quota_bytes: i64) -> bool {
    quota_usage_percentage(used_bytes, quota_bytes) > 0.8
}

/// Check whether a database error message indicates a duplicate key violation.
///
/// PostgreSQL unique-constraint violations contain the phrase "duplicate key"
/// in their error text. This helper centralises that check so both `create`
/// (idempotent upsert under concurrency) and `update` (friendly 409 Conflict)
/// paths share the same detection logic.
pub(crate) fn is_duplicate_key_error(error_message: &str) -> bool {
    error_message.contains("duplicate key")
}

/// Maximum depth the virtual-membership graph walk will descend before
/// giving up. A registry that legitimately needs more than 32 layers of
/// virtual nesting has bigger problems; the bound exists so a corrupted
/// graph (e.g. cycles already persisted in the database) cannot cause
/// unbounded work in `would_create_cycle_in_graph`.
pub(crate) const MAX_VIRTUAL_DEPTH: usize = 32;

/// Advisory-lock key used to serialize all mutations of the virtual
/// membership graph (`add_virtual_member` and friends).
///
/// Concurrent `add_virtual_member` calls that race the cycle check would
/// otherwise be able to bypass it: A reads at T, B reads at T, both pass,
/// both INSERT, the resulting graph has the cycle the algorithm guarantees
/// against. Taking this single transaction-scoped advisory lock at the
/// start of every `add_virtual_member` tx makes the check + INSERT
/// effectively atomic without forcing SERIALIZABLE on the whole codepath
/// or trying to row-lock a graph subset.
///
/// The constant is arbitrary, just needs to be stable across processes.
/// Chosen as a 64-bit hash of "artifact_keeper.virtual_repo_members.write".
pub(crate) const VIRTUAL_MEMBER_GRAPH_LOCK_KEY: i64 = 0x4b56_4d47_5752_5445; // "KVMGWRTE"

/// Pure cycle-detection on a virtual-membership graph.
///
/// Determines whether adding the edge `virtual_id -> candidate_member_id`
/// would close a cycle in the directed graph defined by
/// `virtual_repo_members`. The walk only considers edges whose source is a
/// virtual repository (non-virtual leaves cannot extend the path), so the
/// `virtual_members` lookup must already restrict its result to virtual
/// member ids.
///
/// Returns `Ok(true)` if the proposed edge would create a cycle (including
/// the trivial self-loop `virtual_id == candidate_member_id`), `Ok(false)`
/// if it is safe. Returns `Err(_)` only if the underlying lookup errors.
///
/// The walk is breadth-first and bounded by [`MAX_VIRTUAL_DEPTH`]; if the
/// bound is reached without resolving the question, the function
/// conservatively returns `Ok(true)` to refuse the insert. This matches
/// the safety contract the issue calls for: when in doubt, refuse.
pub(crate) async fn would_create_cycle_in_graph<F, Fut>(
    virtual_id: Uuid,
    candidate_member_id: Uuid,
    mut virtual_members: F,
) -> Result<bool>
where
    F: FnMut(Uuid) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<Uuid>>>,
{
    // Self-membership: a virtual repository cannot contain itself.
    if virtual_id == candidate_member_id {
        return Ok(true);
    }

    // BFS from the candidate. If we ever reach `virtual_id`, the proposed
    // edge would close the cycle `virtual_id -> candidate -> ... -> virtual_id`.
    let mut visited = std::collections::HashSet::new();
    let mut frontier: std::collections::VecDeque<(Uuid, usize)> = std::collections::VecDeque::new();
    frontier.push_back((candidate_member_id, 0));
    visited.insert(candidate_member_id);

    while let Some((node, depth)) = frontier.pop_front() {
        if depth >= MAX_VIRTUAL_DEPTH {
            // Refuse rather than risk unbounded work on a corrupted graph.
            return Ok(true);
        }
        let children = virtual_members(node).await?;
        for child in children {
            if child == virtual_id {
                return Ok(true);
            }
            if visited.insert(child) {
                frontier.push_back((child, depth + 1));
            }
        }
    }

    Ok(false)
}

/// Repository service
pub struct RepositoryService {
    db: PgPool,
    search_service: Option<Arc<OpenSearchService>>,
}

impl RepositoryService {
    /// Create a new repository service
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            search_service: None,
        }
    }

    /// Create a new repository service with search indexing support.
    pub fn new_with_search(db: PgPool, search_service: Option<Arc<OpenSearchService>>) -> Self {
        Self { db, search_service }
    }

    /// Set the search service for search indexing.
    pub fn set_search_service(&mut self, search_service: Arc<OpenSearchService>) {
        self.search_service = Some(search_service);
    }

    /// Get the custom format_key for a repository (if set for WASM plugins).
    pub async fn get_format_key(&self, repo_id: Uuid) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT format_key FROM repositories WHERE id = $1")
                .bind(repo_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(row.and_then(|r| r.0))
    }

    /// Resolve a user-supplied format string to a [`RepositoryFormat`] plus
    /// an optional canonical plugin key.
    ///
    /// Resolution order:
    ///
    /// 1. If `s` matches a built-in variant (see [`parse_format_str`]), return
    ///    `(variant, None)`.
    /// 2. Otherwise look up `s` in `format_handlers` (lower-cased). If the row
    ///    exists and `is_enabled = true`, return
    ///    `(RepositoryFormat::Generic, Some(format_key))`: the repo is stored
    ///    as Generic but the custom plugin key is preserved so the runtime
    ///    plugin dispatcher can route requests to it.
    /// 3. If the row exists but is disabled, or no row exists, return an
    ///    `AppError::Validation`. The disabled error message mirrors the
    ///    wording used by [`Self::create`] for built-in disabled formats so
    ///    the HTTP surface is consistent.
    ///
    /// This is the single source of truth for "is this format string usable
    /// for repository creation?" — the HTTP handler must not perform the
    /// `format_handlers` query itself.
    pub async fn resolve_format(&self, s: &str) -> Result<(RepositoryFormat, Option<String>)> {
        if let Some(builtin) = parse_format_str(s) {
            return Ok((builtin, None));
        }
        let format_lower = s.to_lowercase();
        let is_enabled: Option<bool> =
            sqlx::query_scalar("SELECT is_enabled FROM format_handlers WHERE format_key = $1")
                .bind(&format_lower)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        match is_enabled {
            Some(true) => Ok((RepositoryFormat::Generic, Some(format_lower))),
            Some(false) => Err(AppError::Validation(format!(
                "Format handler '{}' is disabled. Enable it before creating repositories.",
                format_lower
            ))),
            None => Err(AppError::Validation(format!("Invalid format: {}", s))),
        }
    }

    /// Create a new repository
    pub async fn create(&self, req: CreateRepositoryRequest) -> Result<Repository> {
        // Validate remote repository has upstream URL and it is safe to contact
        validate_remote_upstream(&req.repo_type, &req.upstream_url)?;

        // Check if format handler is enabled (T044).
        //
        // Two cases:
        //  * Built-in format (req.format_key = None): check the row keyed by
        //    the canonical enum name (e.g. "maven").
        //  * Plugin format (req.format_key = Some(plugin_key)): the caller
        //    resolved this via `resolve_format`, which already issued its own
        //    SELECT against `format_handlers`. The re-check below is
        //    intentional: we re-read `is_enabled` under our own SELECT to
        //    narrow the TOCTOU window opened by resolve_format.
        //
        // Note: this re-check NARROWS but does not eliminate the TOCTOU window
        // between resolve_format() and insert. A plugin disabled between the two
        // SELECTs could still produce a repo bound to a now-disabled plugin, but
        // (1) request-time format dispatch reads `format_handlers` per request, so
        // the bound repo fails subsequent operations cleanly, and (2) plugin
        // install/disable is admin-only, so the race is bounded by admin actions.
        // A true single-tx fix with SELECT FOR SHARE is tracked as a v1.2.1
        // hardening follow-up.
        let format_key = req
            .format_key
            .clone()
            .unwrap_or_else(|| derive_format_key(&req.format));
        let format_enabled: Option<bool> =
            sqlx::query_scalar("SELECT is_enabled FROM format_handlers WHERE format_key = $1")
                .bind(&format_key)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        // If format handler exists and is disabled, reject repository creation
        if should_reject_disabled_format(format_enabled) {
            return Err(AppError::Validation(format!(
                "Format handler '{}' is disabled. Enable it before creating repositories.",
                format_key
            )));
        }

        // ak-4q87: wrap INSERT + optional `format_key` UPDATE in a single
        // transaction so a failure of the UPDATE rolls back the INSERT.
        // Without this a WASM-plugin-handler repo could end up persisted
        // without its custom format_key, leaving the row in an inconsistent
        // state that the caller never sees committed.
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let insert_result = sqlx::query_as!(
            Repository,
            r#"
            INSERT INTO repositories (
                key, name, description, format, repo_type,
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                created_at, updated_at
            "#,
            req.key,
            req.name,
            req.description,
            req.format as RepositoryFormat,
            req.repo_type as RepositoryType,
            req.storage_backend,
            req.storage_path,
            req.upstream_url,
            req.is_public,
            req.quota_bytes,
            req.promotion_only,
        )
        .fetch_one(&mut *tx)
        .await;

        let repo = match insert_result {
            Ok(repo) => {
                // Set custom format_key for WASM plugin handlers. Runs inside
                // the same tx so an UPDATE failure rolls back the INSERT.
                if let Some(ref fk) = req.format_key {
                    sqlx::query("UPDATE repositories SET format_key = $1 WHERE id = $2")
                        .bind(fk)
                        .bind(repo.id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;
                }
                // Owner auto-grant: record the creator and grant them the
                // `developer` role scoped to this repository, so the creator
                // retains access under per-repo authorization. Runs inside the
                // same tx as the INSERT so creator-grant is atomic with create.
                if let Some(creator_id) = req.created_by {
                    sqlx::query("UPDATE repositories SET created_by = $1 WHERE id = $2")
                        .bind(creator_id)
                        .bind(repo.id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;
                    sqlx::query(
                        "INSERT INTO role_assignments (user_id, role_id, repository_id) \
                         SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
                         ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
                    )
                    .bind(creator_id)
                    .bind(repo.id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
                }
                tx.commit()
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
                repo
            }
            Err(e) if is_duplicate_key_error(&e.to_string()) => {
                // A repository with this key already exists. Roll back our
                // (failed) INSERT and surface a 409 Conflict. Previously this
                // path silently returned the existing row with HTTP 200, which
                // masked the conflict: a second POST with a *different* payload
                // (name/format/type) appeared to succeed while its payload was
                // discarded. 409 is the correct semantics for both sequential
                // duplicate requests and the concurrent-insert race (the unique
                // constraint still serializes concurrent creators; the loser
                // now gets a clean conflict instead of a phantom success).
                tracing::debug!(
                    key = %req.key,
                    "Duplicate repository key on create, returning 409 Conflict"
                );
                let _ = tx.rollback().await;
                return Err(AppError::Conflict(format!(
                    "Repository with key '{}' already exists",
                    req.key
                )));
            }
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(AppError::Database(e.to_string()));
            }
        };

        // Index repository in search engine (non-blocking)
        if let Some(ref search) = self.search_service {
            let search = search.clone();
            let doc = Self::repo_to_search_doc(&repo);
            tokio::spawn(async move {
                if let Err(e) = search.index_repository(&doc).await {
                    tracing::warn!(
                        "Failed to index repository {} in search engine: {}",
                        doc.id,
                        e
                    );
                }
            });
        }

        Ok(repo)
    }

    /// Check whether a single user may access a private repository.
    ///
    /// Mirrors the `RepoVisibility::User` branch of [`build_visibility_clause`]
    /// for one repository: the user has access if they hold any role assignment
    /// scoped to that repository OR a global (NULL-scoped) role assignment.
    ///
    /// This is the per-repo authorization predicate. Callers are responsible for
    /// short-circuiting the cases this method does NOT cover: admins bypass it
    /// entirely and public repositories are accessible to everyone.
    pub async fn user_can_access_repo(&self, repo_id: Uuid, user_id: Uuid) -> Result<bool> {
        let granted: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM role_assignments ra \
                 WHERE ra.user_id = $1 \
                   AND (ra.repository_id = $2 OR ra.repository_id IS NULL) \
             )",
        )
        .bind(user_id)
        .bind(repo_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(granted)
    }

    /// Get a repository by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<Repository> {
        let repo = sqlx::query_as!(
            Repository,
            r#"
            SELECT
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                created_at, updated_at
            FROM repositories
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

        Ok(repo)
    }

    /// Get a repository by key
    pub async fn get_by_key(&self, key: &str) -> Result<Repository> {
        let repo = sqlx::query_as!(
            Repository,
            r#"
            SELECT
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                created_at, updated_at
            FROM repositories
            WHERE key = $1
            "#,
            key
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

        Ok(repo)
    }

    /// List repositories with pagination, filtered by caller visibility.
    ///
    /// - `PublicOnly`: only public repositories (unauthenticated callers).
    /// - `All`: every repository (admin callers).
    /// - `User(id)`: public repositories plus private repositories where the
    ///   user holds at least one role assignment (direct or global).
    pub async fn list(
        &self,
        offset: i64,
        limit: i64,
        format_filter: Option<RepositoryFormat>,
        type_filter: Option<RepositoryType>,
        visibility: RepoVisibility,
        search_query: Option<&str>,
    ) -> Result<(Vec<Repository>, i64)> {
        let search_pattern = build_search_pattern(search_query);
        let (visibility_clause, visibility_bind) = build_visibility_clause(&visibility);

        // Split the visibility bind into the two concrete `$3` shapes. Exactly
        // one is `Some` per call; the unused one stays `None` and binds as a
        // typed NULL, which the clause never references.
        let (user_id_bind, ids_bind): (Option<Uuid>, Option<Vec<Uuid>>) = match visibility_bind {
            VisibilityBind::User(uid) => (uid, None),
            VisibilityBind::Ids(ids) => (None, Some(ids)),
        };

        // -- fetch page --
        let select_sql = format!(
            r#"
            SELECT
                id, key, name, description,
                format, repo_type,
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only,
                replication_priority,
                promotion_target_id, promotion_policy_id,
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                created_at, updated_at
            FROM repositories
            WHERE ($1::repository_format IS NULL OR format = $1)
              AND ($2::repository_type IS NULL OR repo_type = $2)
              AND ({visibility_clause})
              AND ($4::text IS NULL OR LOWER(key) LIKE $4 OR LOWER(name) LIKE $4 OR LOWER(COALESCE(description, '')) LIKE $4)
            ORDER BY name
            OFFSET $5
            LIMIT $6
            "#
        );

        let page_query = sqlx::query_as::<_, Repository>(&select_sql)
            .bind(format_filter.clone())
            .bind(type_filter.clone());
        // $3 shape depends on the visibility variant (single uuid vs uuid[]).
        let page_query = match &ids_bind {
            Some(ids) => page_query.bind(ids.clone()),
            None => page_query.bind(user_id_bind),
        };
        let repos = page_query
            .bind(search_pattern.clone())
            .bind(offset)
            .bind(limit)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // -- fetch total count --
        let count_sql = format!(
            r#"
            SELECT COUNT(*)
            FROM repositories
            WHERE ($1::repository_format IS NULL OR format = $1)
              AND ($2::repository_type IS NULL OR repo_type = $2)
              AND ({visibility_clause})
              AND ($4::text IS NULL OR LOWER(key) LIKE $4 OR LOWER(name) LIKE $4 OR LOWER(COALESCE(description, '')) LIKE $4)
            "#
        );

        let count_query = sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(format_filter)
            .bind(type_filter);
        let count_query = match &ids_bind {
            Some(ids) => count_query.bind(ids.clone()),
            None => count_query.bind(user_id_bind),
        };
        let total: i64 = count_query
            .bind(search_pattern)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((repos, total))
    }

    /// Update a repository
    pub async fn update(&self, id: Uuid, req: UpdateRepositoryRequest) -> Result<Repository> {
        // Validate upstream_url is safe to contact if it is being updated
        if let Some(ref url) = req.upstream_url {
            validate_outbound_url(url, "Upstream URL")?;
        }

        let repo = sqlx::query_as!(
            Repository,
            r#"
            UPDATE repositories
            SET
                key = COALESCE($2, key),
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                is_public = COALESCE($5, is_public),
                quota_bytes = COALESCE($6, quota_bytes),
                upstream_url = COALESCE($7, upstream_url),
                promotion_only = COALESCE($8, promotion_only),
                updated_at = NOW()
            WHERE id = $1
            RETURNING
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                created_at, updated_at
            "#,
            id,
            req.key,
            req.name,
            req.description,
            req.is_public,
            req.quota_bytes.flatten(),
            req.upstream_url,
            req.promotion_only,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| {
            if is_duplicate_key_error(&e.to_string()) {
                AppError::Conflict("Repository with that key already exists".to_string())
            } else {
                AppError::Database(e.to_string())
            }
        })?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

        // Index updated repository in search engine (non-blocking)
        if let Some(ref search) = self.search_service {
            let search = search.clone();
            let doc = Self::repo_to_search_doc(&repo);
            tokio::spawn(async move {
                if let Err(e) = search.index_repository(&doc).await {
                    tracing::warn!(
                        "Failed to index updated repository {} in search engine: {}",
                        doc.id,
                        e
                    );
                }
            });
        }

        Ok(repo)
    }

    /// Delete a repository
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query!("DELETE FROM repositories WHERE id = $1", id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Repository not found".to_string()));
        }

        // Remove repository from search index (non-blocking)
        if let Some(ref search) = self.search_service {
            let search = search.clone();
            let repo_id_str = id.to_string();
            tokio::spawn(async move {
                if let Err(e) = search.remove_repository(&repo_id_str).await {
                    tracing::warn!(
                        "Failed to remove repository {} from search index: {}",
                        repo_id_str,
                        e
                    );
                }
            });
        }

        Ok(())
    }

    /// Add a member repository to a virtual repository.
    ///
    /// Rejects:
    /// - self-membership (a virtual repository cannot contain itself)
    /// - any addition that would close a cycle in the membership graph
    /// - mismatched formats between the virtual repository and the member
    /// - members whose graph descent would exceed [`MAX_VIRTUAL_DEPTH`]
    ///
    /// Cycle detection runs only when the candidate member is itself a
    /// virtual repository (non-virtual leaves cannot extend a cycle).
    ///
    /// When `priority` is `None`, the next priority value is computed as
    /// `MAX(priority) + 1` *inside* the advisory-locked transaction so that
    /// concurrent `add_virtual_member` calls cannot observe the same MAX
    /// and assign duplicate priorities (ak-jhdq).
    pub async fn add_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
        priority: Option<i32>,
    ) -> Result<i32> {
        // Reject self-membership unconditionally before opening the
        // transaction. The cycle check below would also catch this, but
        // the dedicated error message is more useful at the API boundary
        // and we can return without paying for the advisory lock.
        if virtual_repo_id == member_repo_id {
            return Err(AppError::Validation(
                "A virtual repository cannot be a member of itself".to_string(),
            ));
        }

        // TOCTOU fix (issue #915 second-pass review): wrap the cycle
        // check + INSERT in one transaction guarded by a transaction-
        // scoped advisory lock. Without this, two concurrent admins
        // could each pass the cycle check at T, each INSERT at T+1, and
        // produce the cycle the algorithm is supposed to prevent
        // (e.g. A: V1 -> V2, B: V2 -> V1; both checks see no cycle).
        //
        // The advisory lock is held for the duration of this tx and
        // automatically released on commit or rollback. It serializes
        // *all* `add_virtual_member` calls process-wide and across
        // application instances backed by the same database. Throughput
        // impact is negligible because the critical section is a few
        // small reads and one INSERT, and membership mutation is a
        // rare administrative action.
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(VIRTUAL_MEMBER_GRAPH_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Re-fetch both repositories *inside* the locked tx so we observe
        // a consistent snapshot of types/formats. A racing UPDATE that
        // changed `repo_type` would have to wait for our advisory lock if
        // it also goes through this path; direct admin updates of
        // `repo_type` are out of scope for membership-graph integrity.
        let virtual_repo = self.get_by_id(virtual_repo_id).await?;
        if virtual_repo.repo_type != RepositoryType::Virtual {
            return Err(AppError::Validation(
                "Target repository must be a virtual repository".to_string(),
            ));
        }

        let member_repo = self.get_by_id(member_repo_id).await?;

        if virtual_repo.format != member_repo.format {
            return Err(AppError::Validation(
                "Member repository format must match virtual repository format".to_string(),
            ));
        }

        // Cycle check: only meaningful when the candidate is itself
        // virtual. Non-virtual repositories are leaves in the membership
        // graph and cannot participate in a cycle. Reads use `&self.db`,
        // not the tx, but the advisory lock guarantees no other
        // `add_virtual_member` tx can be mutating `virtual_repo_members`
        // concurrently, so any committed state we read is stable for the
        // remainder of this tx.
        if member_repo.repo_type == RepositoryType::Virtual
            && self
                .would_create_cycle(virtual_repo_id, member_repo_id)
                .await?
        {
            return Err(AppError::Validation(format!(
                "Adding repository {} as a member of virtual repository {} would create a cycle",
                member_repo.key, virtual_repo.key
            )));
        }

        // Resolve priority inside the locked tx. ak-jhdq: doing the MAX read
        // outside the tx allowed two concurrent POSTs to observe the same
        // value and INSERT identical priorities. The advisory lock above
        // already serializes membership mutations, so reading MAX here is
        // race-free relative to other `add_virtual_member` tx.
        let resolved_priority = match priority {
            Some(p) => p,
            None => {
                let max: Option<i32> = sqlx::query_scalar(
                    "SELECT MAX(priority) FROM virtual_repo_members WHERE virtual_repo_id = $1",
                )
                .bind(virtual_repo_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
                max.unwrap_or(0) + 1
            }
        };

        sqlx::query(
            r#"
            INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(virtual_repo_id)
        .bind(member_repo_id)
        .bind(resolved_priority)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            map_virtual_member_insert_error(e, virtual_repo.key.as_str(), member_repo.key.as_str())
        })?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(resolved_priority)
    }

    /// Return true if inserting the edge
    /// `virtual_id -> candidate_member_id` into `virtual_repo_members`
    /// would create a cycle (including a trivial self-loop).
    ///
    /// Walks the existing membership graph starting from
    /// `candidate_member_id` and following only edges whose source is
    /// itself a virtual repository. The walk is bounded by
    /// [`MAX_VIRTUAL_DEPTH`] as a defensive limit; on overflow this
    /// conservatively returns `Ok(true)` so the caller refuses the
    /// insert.
    ///
    /// Worst-case cost is O(V + E) over the virtual-only subgraph
    /// reachable from the candidate.
    pub async fn would_create_cycle(
        &self,
        virtual_id: Uuid,
        candidate_member_id: Uuid,
    ) -> Result<bool> {
        would_create_cycle_in_graph(virtual_id, candidate_member_id, |node| {
            self.virtual_member_children(node)
        })
        .await
    }

    /// Return the ids of every member of `repo_id` whose own type is
    /// `virtual`. Non-virtual members are filtered out because they
    /// cannot extend a path in the cycle search.
    ///
    /// Uses the dynamic query API (not the macro) so the cycle-detection
    /// path does not depend on an updated offline SQLx cache; the schema
    /// of `repositories.repo_type` is static enough that the JOIN is
    /// trivially correct.
    async fn virtual_member_children(&self, repo_id: Uuid) -> Result<Vec<Uuid>> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT vrm.member_repo_id
            FROM virtual_repo_members vrm
            INNER JOIN repositories r ON r.id = vrm.member_repo_id
            WHERE vrm.virtual_repo_id = $1
              AND r.repo_type = 'virtual'
            "#,
        )
        .bind(repo_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Remove a member from a virtual repository
    pub async fn remove_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
    ) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 AND member_repo_id = $2",
            virtual_repo_id,
            member_repo_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(
                "Member not found in virtual repository".to_string(),
            ));
        }

        Ok(())
    }

    /// Bulk-update the priorities of existing members of a virtual repository.
    ///
    /// `members` is a list of `(member_repo_id, priority)` pairs. Only rows
    /// that already exist as members of `virtual_repo_id` are updated; rows are
    /// neither inserted nor deleted. Returns the set of `member_repo_id`s that
    /// actually matched so the caller can detect a TOCTOU miss (a member that
    /// was removed between resolution and this UPDATE) and surface a 404.
    ///
    /// # Concurrency (B2)
    ///
    /// The UNNEST UPDATE acquires row locks on the matched rows in whatever
    /// order the planner scans them. Two concurrent PUTs whose member sets
    /// overlap (e.g. `{A,B}` vs `{B,C}`) can therefore each grab one shared
    /// row and then block on the row the other holds, which Postgres only
    /// resolves after `deadlock_timeout` by aborting one side. Under a tight
    /// race loop that surfaces as repeated multi-second stalls / 500s that
    /// blow the client timeout budget.
    ///
    /// Taking the same process-wide transaction-scoped advisory lock that
    /// `add_virtual_member` uses serialises every member-graph mutation, so
    /// no two of these UPDATEs ever contend for the same rows. The lock is
    /// released automatically on commit/rollback. The critical section is a
    /// single small UPDATE, so throughput impact on this rare administrative
    /// action is negligible.
    pub async fn update_virtual_member_priorities(
        &self,
        virtual_repo_id: Uuid,
        member_repo_ids: &[Uuid],
        priorities: &[i32],
    ) -> Result<Vec<Uuid>> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(VIRTUAL_MEMBER_GRAPH_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let updated: Vec<Uuid> = sqlx::query_scalar(
            r#"
            UPDATE virtual_repo_members
               SET priority = c.priority
              FROM (
                SELECT * FROM UNNEST($2::uuid[], $3::int4[])
                         AS t(member_repo_id, priority)
              ) AS c
             WHERE virtual_repo_members.virtual_repo_id = $1
               AND virtual_repo_members.member_repo_id = c.member_repo_id
            RETURNING virtual_repo_members.member_repo_id
            "#,
        )
        .bind(virtual_repo_id)
        .bind(member_repo_ids)
        .bind(priorities)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(updated)
    }

    /// Get virtual repository members
    pub async fn get_virtual_members(&self, virtual_repo_id: Uuid) -> Result<Vec<Repository>> {
        let repos = sqlx::query_as!(
            Repository,
            r#"
            SELECT
                r.id, r.key, r.name, r.description,
                r.format as "format: RepositoryFormat",
                r.repo_type as "repo_type: RepositoryType",
                r.storage_backend, r.storage_path, r.upstream_url,
                r.is_public, r.quota_bytes, r.promotion_only,
                r.replication_priority as "replication_priority: ReplicationPriority",
                r.promotion_target_id, r.promotion_policy_id,
                r.curation_enabled, r.curation_source_repo_id, r.curation_target_repo_id,
                r.curation_default_action, r.curation_sync_interval_secs, r.curation_auto_fetch,
                r.created_at, r.updated_at
            FROM repositories r
            INNER JOIN virtual_repo_members vrm ON r.id = vrm.member_repo_id
            WHERE vrm.virtual_repo_id = $1
            ORDER BY vrm.priority
            "#,
            virtual_repo_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(repos)
    }

    /// Get repository storage usage
    pub async fn get_storage_usage(&self, repo_id: Uuid) -> Result<i64> {
        let usage = sqlx::query_scalar!(
            r#"
            SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as "usage!"
            FROM artifacts
            WHERE repository_id = $1 AND is_deleted = false
            "#,
            repo_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(usage)
    }

    /// Check if upload would exceed quota
    pub async fn check_quota(&self, repo_id: Uuid, additional_bytes: i64) -> Result<bool> {
        let repo = self.get_by_id(repo_id).await?;

        match repo.quota_bytes {
            Some(quota) => {
                let current_usage = self.get_storage_usage(repo_id).await?;
                Ok(current_usage + additional_bytes <= quota)
            }
            None => Ok(true), // No quota set
        }
    }

    /// Convert a Repository model to a search RepositoryDocument.
    fn repo_to_search_doc(repo: &Repository) -> RepositoryDocument {
        RepositoryDocument {
            id: repo.id.to_string(),
            name: repo.name.clone(),
            key: repo.key.clone(),
            description: repo.description.clone(),
            format: format!("{:?}", repo.format).to_lowercase(),
            repo_type: format!("{:?}", repo.repo_type).to_lowercase(),
            is_public: repo.is_public,
            created_at: repo.created_at.timestamp(),
        }
    }
}

/// PostgreSQL SQLSTATE for unique constraint violations.
const PG_UNIQUE_VIOLATION: &str = "23505";

/// Auto-generated PostgreSQL constraint name for
/// `UNIQUE(virtual_repo_id, member_repo_id)` declared in
/// `backend/migrations/003_repositories.sql`. This is the only unique
/// constraint on `virtual_repo_members` whose violation should map to a 409
/// "already a member" error. If a future migration adds another UNIQUE on
/// this table (e.g. `(virtual_repo_id, priority)`), violations of that
/// constraint must NOT be surfaced as "already a member" -- they fall
/// through to [`AppError::Database`] instead.
const VIRTUAL_REPO_MEMBERS_PAIR_UNIQUE_CONSTRAINT: &str =
    "virtual_repo_members_virtual_repo_id_member_repo_id_key";

/// Map an `INSERT` error from `virtual_repo_members` to an [`AppError`].
///
/// Only a unique-constraint violation (`23505`) on the
/// `(virtual_repo_id, member_repo_id)` pair-uniqueness constraint is mapped
/// to [`AppError::Conflict`] (HTTP 409). Other 23505 violations (from
/// constraints added by future migrations) and all other database errors
/// fall through to [`AppError::Database`] to avoid producing misleading
/// "already a member" messages.
fn map_virtual_member_insert_error(
    err: sqlx::Error,
    virtual_key: &str,
    member_key: &str,
) -> AppError {
    if let sqlx::Error::Database(db_err) = &err {
        if db_err.code().as_deref() == Some(PG_UNIQUE_VIOLATION)
            && db_err.constraint() == Some(VIRTUAL_REPO_MEMBERS_PAIR_UNIQUE_CONSTRAINT)
        {
            return AppError::Conflict(format!(
                "repository '{}' is already a member of '{}'",
                member_key, virtual_key
            ));
        }
    }
    AppError::Database(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::repository::{
        ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
    };

    // -----------------------------------------------------------------------
    // repo_to_search_doc tests
    // -----------------------------------------------------------------------

    fn make_test_repo(format: RepositoryFormat, repo_type: RepositoryType) -> Repository {
        let now = chrono::Utc::now();
        Repository {
            id: Uuid::new_v4(),
            key: "test-repo".to_string(),
            name: "Test Repository".to_string(),
            description: Some("A test repository".to_string()),
            format,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/repos/test-repo".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: Some(1024 * 1024 * 1024),
            promotion_only: false,
            replication_priority: ReplicationPriority::Scheduled,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_repo_to_search_doc_maven_local() {
        let repo = make_test_repo(RepositoryFormat::Maven, RepositoryType::Local);
        let doc = RepositoryService::repo_to_search_doc(&repo);

        assert_eq!(doc.id, repo.id.to_string());
        assert_eq!(doc.name, "Test Repository");
        assert_eq!(doc.key, "test-repo");
        assert_eq!(doc.description, Some("A test repository".to_string()));
        assert_eq!(doc.format, "maven");
        assert_eq!(doc.repo_type, "local");
        assert!(doc.is_public);
        assert_eq!(doc.created_at, repo.created_at.timestamp());
    }

    #[test]
    fn test_repo_to_search_doc_docker_remote() {
        let repo = make_test_repo(RepositoryFormat::Docker, RepositoryType::Remote);
        let doc = RepositoryService::repo_to_search_doc(&repo);
        assert_eq!(doc.format, "docker");
        assert_eq!(doc.repo_type, "remote");
    }

    #[test]
    fn test_repo_to_search_doc_npm_virtual() {
        let repo = make_test_repo(RepositoryFormat::Npm, RepositoryType::Virtual);
        let doc = RepositoryService::repo_to_search_doc(&repo);
        assert_eq!(doc.format, "npm");
        assert_eq!(doc.repo_type, "virtual");
    }

    #[test]
    fn test_repo_to_search_doc_pypi_staging() {
        let repo = make_test_repo(RepositoryFormat::Pypi, RepositoryType::Staging);
        let doc = RepositoryService::repo_to_search_doc(&repo);
        assert_eq!(doc.format, "pypi");
        assert_eq!(doc.repo_type, "staging");
    }

    #[test]
    fn test_repo_to_search_doc_no_description() {
        let now = chrono::Utc::now();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: "no-desc".to_string(),
            name: "No Description".to_string(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data".to_string(),
            upstream_url: None,
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::LocalOnly,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: now,
            updated_at: now,
        };
        let doc = RepositoryService::repo_to_search_doc(&repo);
        assert!(doc.description.is_none());
        assert!(!doc.is_public);
        assert_eq!(doc.format, "generic");
    }

    #[test]
    fn test_repo_to_search_doc_various_formats() {
        let formats_and_expected: Vec<(RepositoryFormat, &str)> = vec![
            (RepositoryFormat::Cargo, "cargo"),
            (RepositoryFormat::Nuget, "nuget"),
            (RepositoryFormat::Go, "go"),
            (RepositoryFormat::Rubygems, "rubygems"),
            (RepositoryFormat::Helm, "helm"),
            (RepositoryFormat::Rpm, "rpm"),
            (RepositoryFormat::Debian, "debian"),
            (RepositoryFormat::Conan, "conan"),
            (RepositoryFormat::Terraform, "terraform"),
            (RepositoryFormat::Alpine, "alpine"),
            (RepositoryFormat::Composer, "composer"),
            (RepositoryFormat::Hex, "hex"),
            (RepositoryFormat::Swift, "swift"),
            (RepositoryFormat::Pub, "pub"),
            (RepositoryFormat::Cran, "cran"),
        ];

        for (format, expected) in formats_and_expected {
            let repo = make_test_repo(format, RepositoryType::Local);
            let doc = RepositoryService::repo_to_search_doc(&repo);
            assert_eq!(
                doc.format, expected,
                "Format mismatch for {:?}",
                repo.format
            );
        }
    }

    // -----------------------------------------------------------------------
    // CreateRepositoryRequest construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_repository_request_construction() {
        let req = CreateRepositoryRequest {
            key: "my-repo".to_string(),
            name: "My Repository".to_string(),
            description: Some("Test repo".to_string()),
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/my-repo".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: Some(1_000_000_000),
            promotion_only: false,
            format_key: None,
            created_by: None,
        };
        assert_eq!(req.key, "my-repo");
        assert_eq!(req.format, RepositoryFormat::Maven);
        assert_eq!(req.repo_type, RepositoryType::Local);
        assert!(req.upstream_url.is_none());
        assert_eq!(req.quota_bytes, Some(1_000_000_000));
    }

    #[test]
    fn test_create_repository_request_remote_with_upstream() {
        let req = CreateRepositoryRequest {
            key: "npm-remote".to_string(),
            name: "NPM Remote".to_string(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/npm-remote".to_string(),
            upstream_url: Some("https://registry.npmjs.org".to_string()),
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            format_key: None,
            created_by: None,
        };
        assert_eq!(
            req.upstream_url,
            Some("https://registry.npmjs.org".to_string())
        );
        assert!(!req.is_public);
    }

    // -----------------------------------------------------------------------
    // UpdateRepositoryRequest construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_repository_request_all_none() {
        let req = UpdateRepositoryRequest {
            key: None,
            name: None,
            description: None,
            is_public: None,
            quota_bytes: None,
            upstream_url: None,
            promotion_only: None,
        };
        assert!(req.key.is_none());
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.is_public.is_none());
        assert!(req.quota_bytes.is_none());
        assert!(req.upstream_url.is_none());
    }

    #[test]
    fn test_update_repository_request_partial() {
        let req = UpdateRepositoryRequest {
            key: None,
            name: Some("Updated Name".to_string()),
            description: Some("Updated Description".to_string()),
            is_public: Some(false),
            quota_bytes: Some(Some(2_000_000_000)),
            upstream_url: None,
            promotion_only: None,
        };
        assert_eq!(req.name, Some("Updated Name".to_string()));
        assert_eq!(req.is_public, Some(false));
        assert_eq!(req.quota_bytes, Some(Some(2_000_000_000)));
    }

    #[test]
    fn test_update_repository_request_clear_quota() {
        // quota_bytes: Some(None) should clear the quota
        let req = UpdateRepositoryRequest {
            key: None,
            name: None,
            description: None,
            is_public: None,
            quota_bytes: Some(None),
            upstream_url: None,
            promotion_only: None,
        };
        assert_eq!(req.quota_bytes, Some(None));
    }

    // -----------------------------------------------------------------------
    // validate_remote_upstream (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_remote_upstream_remote_without_url_fails() {
        let result = validate_remote_upstream(&RepositoryType::Remote, &None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("upstream URL"));
    }

    #[test]
    fn test_validate_remote_upstream_remote_with_url_passes() {
        let result = validate_remote_upstream(
            &RepositoryType::Remote,
            &Some("https://upstream.example.com".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remote_upstream_local_without_url_passes() {
        let result = validate_remote_upstream(&RepositoryType::Local, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remote_upstream_virtual_without_url_passes() {
        let result = validate_remote_upstream(&RepositoryType::Virtual, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remote_upstream_staging_without_url_passes() {
        let result = validate_remote_upstream(&RepositoryType::Staging, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remote_upstream_rejects_ssrf_loopback() {
        let result = validate_remote_upstream(
            &RepositoryType::Remote,
            &Some("http://127.0.0.1:8080/".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_remote_upstream_rejects_ssrf_metadata() {
        let result = validate_remote_upstream(
            &RepositoryType::Remote,
            &Some("http://169.254.169.254/latest/meta-data/".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_remote_upstream_rejects_ssrf_on_local_type() {
        // Even non-Remote types with an upstream URL get SSRF validation
        let result = validate_remote_upstream(
            &RepositoryType::Local,
            &Some("http://10.0.0.1/internal".to_string()),
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // build_search_pattern (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_search_pattern_basic() {
        assert_eq!(
            build_search_pattern(Some("maven")),
            Some("%maven%".to_string())
        );
    }

    #[test]
    fn test_build_search_pattern_mixed_case() {
        assert_eq!(
            build_search_pattern(Some("MyRepo")),
            Some("%myrepo%".to_string())
        );
    }

    #[test]
    fn test_build_search_pattern_none() {
        assert!(build_search_pattern(None).is_none());
    }

    #[test]
    fn test_build_search_pattern_empty_string() {
        assert_eq!(build_search_pattern(Some("")), Some("%%".to_string()));
    }

    #[test]
    fn test_build_search_pattern_with_spaces() {
        assert_eq!(
            build_search_pattern(Some("my repo")),
            Some("%my repo%".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // should_reject_disabled_format (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_reject_disabled_format_disabled() {
        assert!(should_reject_disabled_format(Some(false)));
    }

    #[test]
    fn test_should_reject_disabled_format_enabled() {
        assert!(!should_reject_disabled_format(Some(true)));
    }

    #[test]
    fn test_should_reject_disabled_format_not_found() {
        assert!(!should_reject_disabled_format(None));
    }

    // -----------------------------------------------------------------------
    // parse_format_str (extracted pure function)
    //
    // The inverse of `derive_format_key` on the built-in domain. Unknown
    // strings (plugin formats, garbage) return `None` — the caller falls
    // back to the `format_handlers` table.
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_format_str_known_builtins() {
        assert_eq!(parse_format_str("maven"), Some(RepositoryFormat::Maven));
        assert_eq!(parse_format_str("npm"), Some(RepositoryFormat::Npm));
        assert_eq!(parse_format_str("docker"), Some(RepositoryFormat::Docker));
        assert_eq!(parse_format_str("generic"), Some(RepositoryFormat::Generic));
    }

    #[test]
    fn test_parse_format_str_case_insensitive() {
        assert_eq!(parse_format_str("MAVEN"), Some(RepositoryFormat::Maven));
        assert_eq!(parse_format_str("Docker"), Some(RepositoryFormat::Docker));
    }

    #[test]
    fn test_parse_format_str_snake_case_multiword() {
        // Multi-word variants must match the snake_case key produced by
        // `derive_format_key`, NOT the lowercased Debug form.
        assert_eq!(
            parse_format_str("conda_native"),
            Some(RepositoryFormat::CondaNative)
        );
        assert_eq!(
            parse_format_str("wasm_oci"),
            Some(RepositoryFormat::WasmOci)
        );
        assert_eq!(
            parse_format_str("helm_oci"),
            Some(RepositoryFormat::HelmOci)
        );
        // The lowercased-Debug form must NOT match — these are the cases the
        // old `Debug + to_lowercase` approach silently mishandled.
        assert_eq!(parse_format_str("condanative"), None);
        assert_eq!(parse_format_str("wasmoci"), None);
    }

    #[test]
    fn test_parse_format_str_unknown_returns_none() {
        // Plugin-name-looking strings: the caller is expected to consult
        // `format_handlers` after `None` is returned.
        assert_eq!(parse_format_str("my-wasm-plugin"), None);
        assert_eq!(parse_format_str("totally-unknown-zzz"), None);
        assert_eq!(parse_format_str(""), None);
    }

    #[test]
    fn test_parse_format_str_round_trip_with_derive_format_key() {
        // Every built-in variant must round-trip through derive_format_key →
        // parse_format_str. Guards against silent drift between the two
        // mapping tables.
        let variants = [
            RepositoryFormat::Maven,
            RepositoryFormat::Gradle,
            RepositoryFormat::Npm,
            RepositoryFormat::Pypi,
            RepositoryFormat::Docker,
            RepositoryFormat::CondaNative,
            RepositoryFormat::WasmOci,
            RepositoryFormat::HelmOci,
            RepositoryFormat::Generic,
            RepositoryFormat::Lxc,
        ];
        for v in variants {
            let key = derive_format_key(&v);
            let parsed = parse_format_str(&key);
            assert_eq!(
                parsed,
                Some(v.clone()),
                "round-trip failed for {:?} (key={})",
                v,
                key
            );
        }
    }

    // -----------------------------------------------------------------------
    // derive_format_key (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_derive_format_key_maven() {
        assert_eq!(derive_format_key(&RepositoryFormat::Maven), "maven");
    }

    #[test]
    fn test_derive_format_key_docker() {
        assert_eq!(derive_format_key(&RepositoryFormat::Docker), "docker");
    }

    #[test]
    fn test_derive_format_key_npm() {
        assert_eq!(derive_format_key(&RepositoryFormat::Npm), "npm");
    }

    #[test]
    fn test_derive_format_key_wasm_oci() {
        assert_eq!(derive_format_key(&RepositoryFormat::WasmOci), "wasm_oci");
    }

    #[test]
    fn test_derive_format_key_helm_oci() {
        assert_eq!(derive_format_key(&RepositoryFormat::HelmOci), "helm_oci");
    }

    #[test]
    fn test_derive_format_key_conda_native() {
        assert_eq!(
            derive_format_key(&RepositoryFormat::CondaNative),
            "conda_native"
        );
    }

    #[test]
    fn test_derive_format_key_various_formats() {
        let cases: Vec<(RepositoryFormat, &str)> = vec![
            (RepositoryFormat::Cargo, "cargo"),
            (RepositoryFormat::Nuget, "nuget"),
            (RepositoryFormat::Go, "go"),
            (RepositoryFormat::Rubygems, "rubygems"),
            (RepositoryFormat::Helm, "helm"),
            (RepositoryFormat::Rpm, "rpm"),
            (RepositoryFormat::Debian, "debian"),
            (RepositoryFormat::Pypi, "pypi"),
            (RepositoryFormat::Generic, "generic"),
        ];
        for (format, expected) in cases {
            assert_eq!(derive_format_key(&format), expected, "Format {:?}", format);
        }
    }

    // -----------------------------------------------------------------------
    // quota_usage_percentage (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_quota_usage_percentage() {
        assert!((quota_usage_percentage(80, 100) - 0.8).abs() < f64::EPSILON);
        assert!((quota_usage_percentage(100, 100) - 1.0).abs() < f64::EPSILON);
        assert!((quota_usage_percentage(0, 100) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quota_usage_percentage_zero_quota() {
        assert!((quota_usage_percentage(50, 0) - 0.0).abs() < f64::EPSILON);
        assert!((quota_usage_percentage(50, -1) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quota_warning_threshold_check() {
        let threshold = 0.8;
        assert!(quota_usage_percentage(85, 100) > threshold);
        assert!(quota_usage_percentage(70, 100) <= threshold);
    }

    // -----------------------------------------------------------------------
    // exceeds_quota_warning_threshold (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_exceeds_quota_threshold_at_90_percent() {
        assert!(exceeds_quota_warning_threshold(900, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_at_80_percent() {
        // Exactly 0.8 is not > 0.8
        assert!(!exceeds_quota_warning_threshold(800, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_at_81_percent() {
        assert!(exceeds_quota_warning_threshold(810, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_at_50_percent() {
        assert!(!exceeds_quota_warning_threshold(500, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_at_100_percent() {
        assert!(exceeds_quota_warning_threshold(1000, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_over_quota() {
        assert!(exceeds_quota_warning_threshold(1500, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_zero_quota() {
        // Zero quota returns 0.0 from quota_usage_percentage, which is not > 0.8
        assert!(!exceeds_quota_warning_threshold(500, 0));
    }

    #[test]
    fn test_exceeds_quota_threshold_empty() {
        assert!(!exceeds_quota_warning_threshold(0, 1000));
    }

    // -----------------------------------------------------------------------
    // is_duplicate_key_error (extracted pure function, issue #692)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_duplicate_key_error_postgres_message() {
        let msg = r#"error returned from database: duplicate key value violates unique constraint "repositories_key_key""#;
        assert!(is_duplicate_key_error(msg));
    }

    #[test]
    fn test_is_duplicate_key_error_other_error() {
        let msg = "connection refused";
        assert!(!is_duplicate_key_error(msg));
    }

    #[test]
    fn test_is_duplicate_key_error_empty() {
        assert!(!is_duplicate_key_error(""));
    }

    #[test]
    fn test_is_duplicate_key_error_partial_match() {
        // Only "duplicate key" substring matters, not partial fragments
        assert!(!is_duplicate_key_error("duplicate"));
        assert!(!is_duplicate_key_error("key"));
        assert!(is_duplicate_key_error("duplicate key"));
    }

    #[test]
    fn test_is_duplicate_key_error_case_sensitive() {
        // PostgreSQL always emits lowercase; we only match lowercase
        assert!(!is_duplicate_key_error("Duplicate Key"));
        assert!(!is_duplicate_key_error("DUPLICATE KEY"));
    }

    // -----------------------------------------------------------------------
    // build_visibility_clause tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_visibility_public_only_returns_is_public_clause() {
        let (clause, bind) = build_visibility_clause(&RepoVisibility::PublicOnly);
        assert_eq!(clause, "is_public = true");
        assert_eq!(bind, VisibilityBind::User(None));
    }

    #[test]
    fn test_visibility_all_returns_true_clause() {
        let (clause, bind) = build_visibility_clause(&RepoVisibility::All);
        assert_eq!(clause, "true");
        assert_eq!(bind, VisibilityBind::User(None));
    }

    #[test]
    fn test_visibility_user_returns_subquery_and_user_id() {
        let uid = Uuid::new_v4();
        let (clause, bind) = build_visibility_clause(&RepoVisibility::User(uid));
        assert!(clause.contains("is_public = true"));
        assert!(clause.contains("role_assignments"));
        assert!(clause.contains("$3"));
        assert_eq!(bind, VisibilityBind::User(Some(uid)));
    }

    #[test]
    fn test_visibility_ids_restricts_to_id_set_only() {
        // Repo-scoped token: the clause must filter strictly on the allowed id
        // set ($3 = uuid[]) and must NOT widen to public repos or role grants.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let (clause, bind) = build_visibility_clause(&RepoVisibility::Ids(vec![a, b]));
        assert_eq!(clause, "repositories.id = ANY($3)");
        assert!(!clause.contains("is_public"));
        assert!(!clause.contains("role_assignments"));
        assert_eq!(bind, VisibilityBind::Ids(vec![a, b]));
    }

    #[test]
    fn test_visibility_ids_empty_set_matches_no_rows() {
        // An empty allowed set must not degrade to "all rows". The clause is
        // `id = ANY('{}')`, which Postgres evaluates to false for every row.
        let (clause, bind) = build_visibility_clause(&RepoVisibility::Ids(vec![]));
        assert_eq!(clause, "repositories.id = ANY($3)");
        assert_eq!(bind, VisibilityBind::Ids(vec![]));
    }

    #[test]
    fn test_visibility_user_clause_checks_both_direct_and_global_assignments() {
        let uid = Uuid::new_v4();
        let (clause, _) = build_visibility_clause(&RepoVisibility::User(uid));
        // Direct repo assignment
        assert!(clause.contains("ra.repository_id = repositories.id"));
        // Global assignment (repository_id IS NULL)
        assert!(clause.contains("ra.repository_id IS NULL"));
    }

    #[test]
    fn test_repo_visibility_enum_equality() {
        let uid = Uuid::new_v4();
        assert_eq!(RepoVisibility::PublicOnly, RepoVisibility::PublicOnly);
        assert_eq!(RepoVisibility::All, RepoVisibility::All);
        assert_eq!(RepoVisibility::User(uid), RepoVisibility::User(uid));
        assert_ne!(RepoVisibility::PublicOnly, RepoVisibility::All);
        assert_ne!(
            RepoVisibility::User(uid),
            RepoVisibility::User(Uuid::new_v4())
        );
    }

    // -----------------------------------------------------------------------
    // would_create_cycle_in_graph (issue #915)
    //
    // Tests use an in-memory adjacency map so the algorithm can be exercised
    // without a database. The map intentionally contains only virtual ->
    // virtual edges, mirroring what `virtual_member_children` returns from
    // PostgreSQL.
    // -----------------------------------------------------------------------

    use std::collections::HashMap;

    /// Helper: build an async lookup closure from a static graph.
    fn make_graph_lookup(
        graph: HashMap<Uuid, Vec<Uuid>>,
    ) -> impl FnMut(Uuid) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Uuid>>>>>
    {
        move |node: Uuid| {
            let children = graph.get(&node).cloned().unwrap_or_default();
            Box::pin(async move { Ok(children) })
                as std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Uuid>>>>>
        }
    }

    #[tokio::test]
    async fn test_cycle_self_membership_rejected() {
        // V trying to add itself as a member is the trivial self-loop.
        let v = Uuid::new_v4();
        let graph: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        let result = would_create_cycle_in_graph(v, v, make_graph_lookup(graph))
            .await
            .unwrap();
        assert!(result, "self-membership must be detected as a cycle");
    }

    #[tokio::test]
    async fn test_cycle_direct_two_node_cycle_rejected() {
        // V1 already contains V2. Adding V1 as a member of V2 closes
        // V1 -> V2 -> V1.
        let v1 = Uuid::new_v4();
        let v2 = Uuid::new_v4();
        let mut graph: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        graph.insert(v1, vec![v2]);
        // Insert V2 as a key with no children so the lookup terminates cleanly.
        graph.insert(v2, vec![]);
        let result = would_create_cycle_in_graph(v2, v1, make_graph_lookup(graph))
            .await
            .unwrap();
        assert!(result, "V2 -> V1 must be rejected when V1 -> V2 exists");
    }

    #[tokio::test]
    async fn test_cycle_indirect_three_node_cycle_rejected() {
        // V1 -> V2 -> V3, then trying V3 -> V1 closes a 3-node cycle.
        let v1 = Uuid::new_v4();
        let v2 = Uuid::new_v4();
        let v3 = Uuid::new_v4();
        let mut graph: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        graph.insert(v1, vec![v2]);
        graph.insert(v2, vec![v3]);
        graph.insert(v3, vec![]);
        let result = would_create_cycle_in_graph(v3, v1, make_graph_lookup(graph))
            .await
            .unwrap();
        assert!(result, "V3 -> V1 must close the V1 -> V2 -> V3 chain");
    }

    #[tokio::test]
    async fn test_cycle_independent_virtuals_allowed() {
        // V1 and V2 are unrelated, both empty. Adding V2 to V1 is safe.
        let v1 = Uuid::new_v4();
        let v2 = Uuid::new_v4();
        let mut graph: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        graph.insert(v1, vec![]);
        graph.insert(v2, vec![]);
        let result = would_create_cycle_in_graph(v1, v2, make_graph_lookup(graph))
            .await
            .unwrap();
        assert!(
            !result,
            "independent virtuals must not be flagged as cyclic"
        );
    }

    #[tokio::test]
    async fn test_cycle_local_only_subgraph_allowed() {
        // The candidate has no virtual children at all (its children would
        // be local repos, which `virtual_member_children` filters out).
        // The lookup therefore returns an empty list.
        let v1 = Uuid::new_v4();
        let candidate = Uuid::new_v4();
        let graph: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        let result = would_create_cycle_in_graph(v1, candidate, make_graph_lookup(graph))
            .await
            .unwrap();
        assert!(
            !result,
            "candidate with only non-virtual descendants must be safe"
        );
    }

    #[tokio::test]
    async fn test_cycle_diamond_no_cycle_allowed() {
        // V1 -> V2, V1 -> V3, V2 -> V4, V3 -> V4 (diamond). Two
        // assertions exercise the algorithm against this shape:
        //
        // 1. (v4, v1, graph): proposing V4 -> V1 must be rejected
        //    because the BFS from V1 reaches V4 via *both* paths
        //    (v1 -> v2 -> v4 and v1 -> v3 -> v4); the visited-set
        //    must dedupe v4 reached via v2 and v3 without the BFS
        //    looping or double-reporting, and ultimately the walk
        //    reaches v4 == virtual_id, returning true.
        //
        // 2. (v_new, v1, graph): proposing V_new -> V1 where V_new
        //    is not in the graph must be allowed. The BFS from V1
        //    walks the full diamond (v2, v3, v4) without ever
        //    reaching v_new, so the result is false. This is the
        //    canonical "diamond DAG remains acyclic" case and the
        //    one the original test author intended.
        //
        // The previous version of this test queried (v4, v_new, graph)
        // where v_new had no graph entry, so the BFS terminated
        // immediately and never traversed the diamond at all. That
        // gave a false sense of coverage. (Issue #915 second-pass review.)
        let v1 = Uuid::new_v4();
        let v2 = Uuid::new_v4();
        let v3 = Uuid::new_v4();
        let v4 = Uuid::new_v4();
        let v_new = Uuid::new_v4();
        let mut graph: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        graph.insert(v1, vec![v2, v3]);
        graph.insert(v2, vec![v4]);
        graph.insert(v3, vec![v4]);
        graph.insert(v4, vec![]);

        // Assertion 1: closing the diamond by adding V4 -> V1 is a cycle.
        // The visited set must dedupe v4 (reached via both v2 and v3).
        let result_close = would_create_cycle_in_graph(v4, v1, make_graph_lookup(graph.clone()))
            .await
            .unwrap();
        assert!(
            result_close,
            "v4 -> v1 closes the diamond and must be rejected; \
             also exercises the visited-set dedupe of v4"
        );

        // Assertion 2: extending the diamond with V_new -> V1 is acyclic.
        // The BFS traverses v1 -> v2/v3 -> v4 without reaching v_new.
        let result_extend = would_create_cycle_in_graph(v_new, v1, make_graph_lookup(graph))
            .await
            .unwrap();
        assert!(
            !result_extend,
            "v_new -> v1 extends the diamond DAG without creating a cycle"
        );
    }

    #[tokio::test]
    async fn test_cycle_visited_set_prevents_revisit() {
        // V1 -> V2, V2 -> V3, V3 -> V2 (a cycle that does NOT include V1).
        // Trying to add V1 -> V2 again must terminate (visited set) and
        // return false because the existing cycle does not touch V1.
        let v1 = Uuid::new_v4();
        let v2 = Uuid::new_v4();
        let v3 = Uuid::new_v4();
        let mut graph: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        graph.insert(v1, vec![v2]);
        graph.insert(v2, vec![v3]);
        graph.insert(v3, vec![v2]);
        let result = would_create_cycle_in_graph(v1, v2, make_graph_lookup(graph))
            .await
            .unwrap();
        assert!(
            !result,
            "pre-existing cycle not touching v1 must not falsely reject"
        );
    }

    #[tokio::test]
    async fn test_cycle_depth_bound_refuses_pathological_chain() {
        // Build a linear chain v0 -> v1 -> ... -> v(N) where N exceeds
        // MAX_VIRTUAL_DEPTH. The walk must short-circuit and refuse.
        let nodes: Vec<Uuid> = (0..(MAX_VIRTUAL_DEPTH + 5))
            .map(|_| Uuid::new_v4())
            .collect();
        let mut graph: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for window in nodes.windows(2) {
            graph.insert(window[0], vec![window[1]]);
        }
        graph.insert(*nodes.last().unwrap(), vec![]);

        let head = nodes[0];
        let new_root = Uuid::new_v4();
        let result = would_create_cycle_in_graph(new_root, head, make_graph_lookup(graph))
            .await
            .unwrap();
        assert!(
            result,
            "walks deeper than MAX_VIRTUAL_DEPTH must be refused defensively"
        );
    }

    #[tokio::test]
    async fn test_cycle_lookup_error_propagates() {
        // The lookup closure is the only fallible step in the BFS. If it
        // returns Err, the helper must surface the error rather than
        // returning a stale Ok(false). Covers the `?`-operator's Err arm
        // on the `virtual_members(node).await?` call so the failure path
        // is exercised by unit tests rather than relying on DB-backed
        // integration runs.
        let v_target = Uuid::new_v4();
        let candidate = Uuid::new_v4();
        let lookup = |_node: Uuid| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<Uuid>>>>,
        > {
            Box::pin(async {
                Err(AppError::Database(
                    "simulated pool-closed lookup failure".to_string(),
                )) as Result<Vec<Uuid>>
            })
        };
        let result = would_create_cycle_in_graph(v_target, candidate, lookup).await;
        assert!(
            matches!(result, Err(AppError::Database(_))),
            "lookup error must propagate, got {result:?}"
        );
    }

    // Compile-time sanity check on the depth bound: small enough to
    // terminate fast, large enough to allow legitimate nesting. Encoded
    // as a `const _` so clippy does not flag it as a constant assertion.
    const _: () = {
        assert!(MAX_VIRTUAL_DEPTH >= 8);
        assert!(MAX_VIRTUAL_DEPTH <= 128);
    };

    // -----------------------------------------------------------------------
    // map_virtual_member_insert_error tests
    // -----------------------------------------------------------------------

    use sqlx::error::{DatabaseError, ErrorKind};
    use std::borrow::Cow;
    use std::error::Error as StdError;
    use std::fmt;

    /// Minimal in-memory `DatabaseError` impl for unit-testing the error
    /// mapping helper. Lets us simulate a Postgres unique-violation without a
    /// live database connection.
    #[derive(Debug)]
    struct MockDbError {
        message: String,
        code: Option<String>,
        constraint: Option<String>,
        kind: ErrorKind,
    }

    impl fmt::Display for MockDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl StdError for MockDbError {}

    impl DatabaseError for MockDbError {
        fn message(&self) -> &str {
            &self.message
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.as_deref().map(Cow::Borrowed)
        }

        fn constraint(&self) -> Option<&str> {
            self.constraint.as_deref()
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            // ErrorKind is non_exhaustive and lacks Copy/Clone, so re-construct it
            // by matching on the stored variant.
            match self.kind {
                ErrorKind::UniqueViolation => ErrorKind::UniqueViolation,
                ErrorKind::ForeignKeyViolation => ErrorKind::ForeignKeyViolation,
                ErrorKind::NotNullViolation => ErrorKind::NotNullViolation,
                ErrorKind::CheckViolation => ErrorKind::CheckViolation,
                _ => ErrorKind::Other,
            }
        }
    }

    fn make_unique_violation() -> sqlx::Error {
        sqlx::Error::Database(Box::new(MockDbError {
            message: "duplicate key value violates unique constraint \"virtual_repo_members_virtual_repo_id_member_repo_id_key\""
                .to_string(),
            code: Some("23505".to_string()),
            constraint: Some(
                VIRTUAL_REPO_MEMBERS_PAIR_UNIQUE_CONSTRAINT.to_string(),
            ),
            kind: ErrorKind::UniqueViolation,
        }))
    }

    fn make_unique_violation_other_constraint(constraint: &str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(MockDbError {
            message: format!(
                "duplicate key value violates unique constraint \"{}\"",
                constraint
            ),
            code: Some("23505".to_string()),
            constraint: Some(constraint.to_string()),
            kind: ErrorKind::UniqueViolation,
        }))
    }

    fn make_foreign_key_violation() -> sqlx::Error {
        sqlx::Error::Database(Box::new(MockDbError {
            message: "violates foreign key constraint".to_string(),
            code: Some("23503".to_string()),
            constraint: Some("fk_virtual_repo_members_virtual_repo_id".to_string()),
            kind: ErrorKind::ForeignKeyViolation,
        }))
    }

    #[test]
    fn test_map_virtual_member_insert_error_unique_violation_returns_conflict() {
        let err = make_unique_violation();
        let mapped = map_virtual_member_insert_error(err, "virtual-key", "member-key");
        match mapped {
            AppError::Conflict(msg) => {
                assert!(
                    msg.contains("member-key"),
                    "message should include member key: {msg}"
                );
                assert!(
                    msg.contains("virtual-key"),
                    "message should include virtual key: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn test_map_virtual_member_insert_error_other_db_error_returns_database() {
        let err = make_foreign_key_violation();
        let mapped = map_virtual_member_insert_error(err, "virtual-key", "member-key");
        assert!(
            matches!(mapped, AppError::Database(_)),
            "non-23505 errors should map to Database, got {mapped:?}"
        );
    }

    #[test]
    fn test_map_virtual_member_insert_error_pool_closed_returns_database() {
        let err = sqlx::Error::PoolClosed;
        let mapped = map_virtual_member_insert_error(err, "virtual-key", "member-key");
        assert!(
            matches!(mapped, AppError::Database(_)),
            "non-database sqlx errors should map to Database, got {mapped:?}"
        );
    }

    #[test]
    fn test_map_virtual_member_insert_error_db_error_without_code_returns_database() {
        let err = sqlx::Error::Database(Box::new(MockDbError {
            message: "some unexpected error".to_string(),
            code: None,
            constraint: None,
            kind: ErrorKind::Other,
        }));
        let mapped = map_virtual_member_insert_error(err, "v", "m");
        assert!(
            matches!(mapped, AppError::Database(_)),
            "missing code should not be treated as conflict, got {mapped:?}"
        );
    }

    /// A 23505 unique-violation on a constraint other than the
    /// `(virtual_repo_id, member_repo_id)` pair-uniqueness one (for example,
    /// a hypothetical future `UNIQUE(virtual_repo_id, priority)`) must NOT
    /// produce a misleading "already a member" 409. It must fall through to
    /// `AppError::Database` so the underlying cause is logged and surfaced
    /// as a 500.
    #[test]
    fn test_map_virtual_member_insert_error_wrong_unique_constraint_returns_database() {
        let err = make_unique_violation_other_constraint(
            "virtual_repo_members_virtual_repo_id_priority_key",
        );
        let mapped = map_virtual_member_insert_error(err, "virtual-key", "member-key");
        assert!(
            matches!(mapped, AppError::Database(_)),
            "23505 on a non-pair-unique constraint must not be Conflict, got {mapped:?}"
        );
    }

    /// A 23505 with no constraint name attached (defensive: the Postgres
    /// driver always populates this field, but the trait default returns
    /// `None`) must also fall through to Database -- we will not guess.
    #[test]
    fn test_map_virtual_member_insert_error_unique_violation_without_constraint_returns_database() {
        let err = sqlx::Error::Database(Box::new(MockDbError {
            message: "duplicate key".to_string(),
            code: Some("23505".to_string()),
            constraint: None,
            kind: ErrorKind::UniqueViolation,
        }));
        let mapped = map_virtual_member_insert_error(err, "v", "m");
        assert!(
            matches!(mapped, AppError::Database(_)),
            "23505 without constraint name must not be Conflict, got {mapped:?}"
        );
    }

    // =========================================================================
    // DB-backed tests for the ak-4q87 transaction-wrapped `create` path.
    //
    // These exercise the begin/commit/rollback arms that pure unit tests can't
    // reach. They use `tdh::try_pool()` to opt into a real Postgres connection
    // when DATABASE_URL is set, and skip silently otherwise. The coverage CI
    // job provisions Postgres and runs migrations, so these tests instrument
    // the transaction body during the lib-coverage measurement.
    // =========================================================================

    mod db {
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;

        fn make_create_req(suffix: &str, format: RepositoryFormat) -> CreateRepositoryRequest {
            CreateRepositoryRequest {
                key: format!("acs-repo-{suffix}"),
                name: format!("acs repo {suffix}"),
                description: None,
                format,
                repo_type: RepositoryType::Local,
                storage_backend: "filesystem".to_string(),
                storage_path: format!("/tmp/acs-{suffix}"),
                upstream_url: None,
                is_public: false,
                quota_bytes: None,
                promotion_only: false,
                format_key: None,
                created_by: None,
            }
        }

        async fn cleanup_repo(pool: &PgPool, id: Uuid) {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;
        }

        /// Happy-path: create commits the INSERT inside a transaction and
        /// the resulting repo is visible after the commit.
        #[tokio::test]
        async fn test_create_commits_insert_in_transaction() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let service = RepositoryService::new(pool.clone());
            let req = make_create_req(&suffix, RepositoryFormat::Generic);
            let repo = service.create(req).await.expect("create should commit");
            assert_eq!(repo.key, format!("acs-repo-{suffix}"));

            // Visible to a fresh fetch through the same pool: confirms commit
            // landed (a non-committed INSERT would be invisible to a new
            // connection because the transaction would have rolled back on
            // drop).
            let fetched = service.get_by_key(&repo.key).await.expect("fetched");
            assert_eq!(fetched.id, repo.id);

            cleanup_repo(&pool, repo.id).await;
        }

        /// `format_key` set: exercises the inner UPDATE + commit branch.
        #[tokio::test]
        async fn test_create_with_format_key_commits_inner_update() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let service = RepositoryService::new(pool.clone());
            let mut req = make_create_req(&suffix, RepositoryFormat::Generic);
            req.format_key = Some("wasm:custom-handler".to_string());
            let repo = service
                .create(req)
                .await
                .expect("create with format_key should commit");

            let stored: Option<String> =
                sqlx::query_scalar("SELECT format_key FROM repositories WHERE id = $1")
                    .bind(repo.id)
                    .fetch_one(&pool)
                    .await
                    .expect("fetch format_key");
            assert_eq!(stored.as_deref(), Some("wasm:custom-handler"));

            cleanup_repo(&pool, repo.id).await;
        }

        /// Regression (#1783 HIGH): a duplicate key on create must roll back the
        /// failed INSERT and return `409 Conflict`, NOT a silent 200 echoing the
        /// existing row. A second create with a DIFFERENT payload must not be
        /// reported as success while its payload is discarded.
        #[tokio::test]
        async fn test_create_duplicate_key_returns_conflict() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let service = RepositoryService::new(pool.clone());
            let first = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("first create");

            // Second create with the same key but a deliberately different
            // format — the old code returned 200 with the first row's payload.
            let second = service
                .create(make_create_req(&suffix, RepositoryFormat::Pypi))
                .await;
            match second {
                Err(AppError::Conflict(msg)) => {
                    assert!(
                        msg.contains(&suffix),
                        "conflict message should name the duplicate key, got: {msg}"
                    );
                }
                other => panic!("expected 409 Conflict on duplicate key, got: {other:?}"),
            }

            // The original row is untouched (payload not silently overwritten).
            let fetched = service.get_by_key(&first.key).await.expect("fetch first");
            assert_eq!(fetched.id, first.id);
            assert_eq!(fetched.format, RepositoryFormat::Generic);

            cleanup_repo(&pool, first.id).await;
        }

        /// Regression (authz-private-repo-membership): per-repo authorization
        /// for a PRIVATE repository.
        ///
        /// Before the fix, any authenticated user could access any private
        /// repository (the handlers never consulted the grant model). This
        /// asserts the corrected predicate: the owner (auto-granted on create)
        /// can access the repo, while a different user with no grant cannot —
        /// and that an explicit grant restores access.
        #[tokio::test]
        async fn test_user_can_access_repo_private_grant_enforced() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());

            let (owner_id, _) = tdh::create_user(&pool).await;
            let (other_id, _) = tdh::create_user(&pool).await;

            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let mut req = make_create_req(&suffix, RepositoryFormat::Generic);
            // Owner auto-grant: the creator is recorded and granted access.
            req.created_by = Some(owner_id);
            let repo = service.create(req).await.expect("create private repo");

            // Owner (auto-granted developer role scoped to the repo) -> allowed.
            assert!(
                service
                    .user_can_access_repo(repo.id, owner_id)
                    .await
                    .expect("owner access check"),
                "owner should retain access via auto-grant"
            );

            // Different user with no grant -> denied (this is the bug being fixed).
            assert!(
                !service
                    .user_can_access_repo(repo.id, other_id)
                    .await
                    .expect("other access check"),
                "ungranted user must NOT access a private repo"
            );

            // Explicit grant scoped to the repo -> access restored.
            sqlx::query(
                "INSERT INTO role_assignments (user_id, role_id, repository_id) \
                 SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
                 ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
            )
            .bind(other_id)
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("grant developer role");
            assert!(
                service
                    .user_can_access_repo(repo.id, other_id)
                    .await
                    .expect("granted access check"),
                "explicitly granted user should now have access"
            );

            cleanup_repo(&pool, repo.id).await;
            for uid in [owner_id, other_id] {
                let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(uid)
                    .execute(&pool)
                    .await;
            }
        }

        /// Regression (#1783 MEDIUM): `list` with `RepoVisibility::Ids` (the
        /// shape a repo-scoped token produces) must return ONLY the repos in
        /// the allowed id set — not every repo the owning user can reach.
        ///
        /// Before the fix, the list handler mapped any authenticated principal
        /// (including scoped tokens) to `RepoVisibility::User`, so a token
        /// scoped to repo A still listed repo B when the owner had access to B.
        #[tokio::test]
        async fn test_list_ids_visibility_restricts_to_allowed_set() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());

            let (owner_id, _) = tdh::create_user(&pool).await;

            // Two PRIVATE repos, both owned (granted) by the same user.
            let tag = format!("{}", uuid::Uuid::new_v4().simple());
            let mut req_a = make_create_req(&format!("{tag}a"), RepositoryFormat::Pypi);
            req_a.created_by = Some(owner_id);
            let repo_a = service.create(req_a).await.expect("create repo a");
            let mut req_b = make_create_req(&format!("{tag}b"), RepositoryFormat::Npm);
            req_b.created_by = Some(owner_id);
            let repo_b = service.create(req_b).await.expect("create repo b");

            let search = Some(format!("acs-repo-{tag}"));

            // Sanity: as the owning user, BOTH repos are visible.
            let (user_repos, user_total) = service
                .list(
                    0,
                    50,
                    None,
                    None,
                    RepoVisibility::User(owner_id),
                    search.as_deref(),
                )
                .await
                .expect("user list");
            assert_eq!(user_total, 2, "owner should see both private repos");
            assert_eq!(user_repos.len(), 2);

            // Scoped to repo_a only: repo_b must NOT appear.
            let (ids_repos, ids_total) = service
                .list(
                    0,
                    50,
                    None,
                    None,
                    RepoVisibility::Ids(vec![repo_a.id]),
                    search.as_deref(),
                )
                .await
                .expect("ids list");
            assert_eq!(ids_total, 1, "scoped token must see only the allowed repo");
            assert_eq!(ids_repos.len(), 1);
            assert_eq!(ids_repos[0].id, repo_a.id);
            assert!(
                !ids_repos.iter().any(|r| r.id == repo_b.id),
                "repo outside allowed_repo_ids must not leak into the listing"
            );

            // Empty allowed set: matches no rows (must not degrade to "all").
            let (empty_repos, empty_total) = service
                .list(
                    0,
                    50,
                    None,
                    None,
                    RepoVisibility::Ids(vec![]),
                    search.as_deref(),
                )
                .await
                .expect("empty ids list");
            assert_eq!(empty_total, 0);
            assert!(empty_repos.is_empty());

            cleanup_repo(&pool, repo_a.id).await;
            cleanup_repo(&pool, repo_b.id).await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(owner_id)
                .execute(&pool)
                .await;
        }
    }
}
