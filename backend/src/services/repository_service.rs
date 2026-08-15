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

/// What a [`RepositoryService::user_can_access_repo`] call is actually asking
/// (#3331).
///
/// Before this existed the function took no action at all, so it could only
/// answer *"does this principal hold ANY grant on this repository"* — and every
/// caller, including the ones serving artifact BYTES, got that answer. A
/// principal whose only entitlement was `{write}` (or a role carrying no
/// `read`, or a fine-grained rule with an unrecognised action string, since the
/// grant fragment tests only `actions <> '{}'`) therefore passed the gate on a
/// private repository's content reads, while the equivalent OCI `/v2` and
/// native-format reads correctly refused.
///
/// Making the action a REQUIRED parameter is the point. An added variant or a
/// new call site cannot silently inherit the action-blind behaviour: the author
/// has to name which question they mean, and [`TenantOnly`](Self::TenantOnly)
/// — the one that keeps the old semantics — is greppable and is required by
/// `every_user_can_access_repo_call_names_its_action` to carry a written
/// justification.
///
/// This is the #3326 shape (`try_authorize_virtual_members`) applied to the
/// REST content paths: the tenant gate is kept and the canonical ACTION
/// choke-point, [`PermissionService::check_repository_action`], is layered on
/// top of it — the SAME function, with the same arguments, that the direct
/// `/v2` read gate (`oci_v2::require_oci_repo_read_access`) and
/// `repo_visibility_middleware` call. The two cannot drift, because they are
/// one function.
///
/// [`PermissionService::check_repository_action`]: crate::services::permission_service::PermissionService::check_repository_action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoAccess {
    /// The TENANT gate only: "does this principal hold any grant on this
    /// repository", with no action term.
    ///
    /// Correct exactly where an action gate is enforced separately (the REST
    /// write/delete handlers layer `require_repo_action` on top of it) or where
    /// the question genuinely is tenant membership rather than a capability
    /// (cross-tenant promotion, webhook ownership). It is NOT correct in front
    /// of anything that returns a private repository's contents — that is the
    /// defect this enum exists to make un-writable by accident.
    TenantOnly,
    /// The tenant gate AND the named action, resolved through
    /// [`PermissionService::check_repository_action`].
    ///
    /// [`PermissionService::check_repository_action`]: crate::services::permission_service::PermissionService::check_repository_action
    Action(&'static str),
}

impl RepoAccess {
    /// The `read` action — the gate for every path that returns a private
    /// repository's bytes, metadata, or configuration.
    pub const READ: Self = Self::Action("read");
}

/// Outcome of an atomic, in-transaction quota admission check
/// ([`RepositoryService::check_quota_locked`]).
#[derive(Debug, Clone, Copy)]
pub struct QuotaAdmission {
    /// Whether the upload is permitted under the repository's storage quota.
    pub allowed: bool,
    /// The repository's ledger-tracked usage (`hosted + proxy + oci`
    /// counters from `repository_usage_ledger`, read under the admission
    /// row lock) EXCLUDING the row currently being written at the target
    /// path (so an overwrite is charged only its net size delta). `None`
    /// when the repository has no finite quota, in which case usage is
    /// neither computed nor enforced.
    pub base_usage: Option<i64>,
}

/// Summary of a [`RepositoryService::reconcile_all_usage_ledgers`] pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct UsageLedgerReconcileReport {
    /// Repositories whose ledger row was recomputed.
    pub repositories_checked: usize,
    /// Repositories whose ledger total changed (drift that was repaired).
    pub repositories_repaired: usize,
    /// Sum of the absolute per-repository drift that was corrected, in bytes.
    pub total_drift_bytes: i64,
}

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
    /// When true, uploads to Generic/Mlmodel repos append immutable revisions
    /// to `artifact_versions` instead of overwriting (#2367). Defaults to false.
    pub versioning_enabled: bool,
    /// Custom format key for WASM plugin handlers (e.g. "rpm-custom").
    pub format_key: Option<String>,
    /// Optional project to assign the repository to at creation (#2472).
    /// `None` leaves the repository unassigned (legacy behavior).
    pub project_id: Option<Uuid>,
    /// Trusted upstream OpenPGP public key for RPM curation signature
    /// verification (#2568). `None` leaves the column NULL ("unverified
    /// upstream"). Validated by the handler before it reaches the service.
    pub trusted_gpg_key: Option<String>,
    /// Opt into ingesting UNVERIFIED upstream metadata on the keyless RPM
    /// curation-sync path (#2569). `None`/`Some(false)` keep the fail-closed
    /// default (a keyless sync refuses to ingest); `Some(true)` reverts to the
    /// legacy unverified-ingest behavior. Persisted in the create tx.
    pub curation_allow_unverified: Option<bool>,
    /// User who is creating this repository. When set, the repository records
    /// this user as `created_by` and the creator is auto-granted the durable
    /// `repository-owner` role scoped to the new repository. The legacy
    /// `developer` grant is retained during the staged authorization rollout.
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
    /// When `Some`, sets the `versioning_enabled` flag (#2367); `None` leaves
    /// it unchanged.
    pub versioning_enabled: Option<bool>,
    /// When `Some`, sets the repository's project assignment (#2472);
    /// `None` leaves it unchanged. Mirrors `quota_bytes`: the outer `Option`
    /// is the "field present" marker and the inner value is what is stored
    /// (P1 exposes set-only, so handlers pass `Some(Some(id))`).
    pub project_id: Option<Option<Uuid>>,
    /// When `Some`, updates the trusted upstream GPG key (#2568): the outer
    /// `Option` is the "field present" marker and the inner value is stored
    /// (`Some(None)` clears the column, `Some(Some(key))` sets it). `None`
    /// leaves the stored key unchanged. Validated by the handler before it
    /// reaches the service.
    pub trusted_gpg_key: Option<Option<String>>,
    /// When `Some`, sets the keyless-sync unverified-ingest opt-in (#2569);
    /// `None` leaves it unchanged. `Some(false)` restores the fail-closed
    /// default; `Some(true)` opts into legacy unverified ingest.
    pub curation_allow_unverified: Option<bool>,
    /// When `Some`, enables/disables curation-rule enforcement on this
    /// repository's proxy paths (#2912); `None` leaves it
    /// unchanged.
    pub curation_enabled: Option<bool>,
    /// When `Some`, sets the default curation action applied when no rule
    /// matches (`allow` or `review`; `block` is rejected by the handler
    /// since the DB CHECK constraint from migration 071 does not allow it
    /// as a default action). `None` leaves it unchanged. Validated by the
    /// handler before it reaches the service.
    pub curation_default_action: Option<String>,
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

/// Controls which repositories a caller can see when they are reached
/// *through* an already-authorized parent — today, a virtual repository's
/// members, whose bytes are folded into the parent's storage total (#3081).
///
/// This is a DIFFERENT question from [`RepoVisibility`], which answers "which
/// repositories may this principal LIST". `RepoVisibility` has no variant that
/// can express the member question, because the handler's canonical gate
///
/// ```text
/// require_visible(repo) = is_public
///                         OR (in_scope AND (is_admin OR grants))
/// ```
///
/// conjoins TWO independent facts — the token's repo scope and the user's
/// entitlement — inside the `is_public` disjunction, and each
/// `RepoVisibility` variant carries only one of them
/// ([`RepoVisibility::Ids`] is `in_scope` alone; [`RepoVisibility::User`] is
/// `is_public OR grants` alone). Composing them by intersecting two
/// `RepoVisibility` results does not work either: the `is_public` arm must
/// bypass scope, not be intersected with it.
///
/// So the member question gets its own type carrying the whole principal, and
/// [`build_member_visibility_clause`] renders `require_visible` verbatim.
/// `RepoVisibility::Ids` keeps its existing "scope only" listing contract
/// untouched.
///
/// This is exactly the predicate PR #3173 composes row-wise for the member
/// LISTING paths (`member_grant_visibility` in SQL AND `member_passes_token_scope`
/// per row); the aggregate cannot filter row-wise — its rows are summed inside
/// the database — so it renders the same predicate as one clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberVisibility {
    /// Unauthenticated caller: only public members, matching
    /// `require_visible`'s `None` arm (public early-return, otherwise 404).
    Anonymous,
    /// An authenticated principal, carrying both halves of `require_visible`.
    Principal {
        /// The caller's user id, consulted by the grant half.
        user_id: Uuid,
        /// Global admin: satisfies the entitlement half for every repository.
        /// Does NOT bypass `allowed_repo_ids` — `require_visible` checks token
        /// scope BEFORE the admin bypass, so an admin's repo-scoped token is
        /// still confined to its allowed set.
        is_admin: bool,
        /// The token's repository scope: `None` is unrestricted
        /// ([`crate::models::access_scope::AccessScope::Admin`]), `Some(ids)`
        /// is the allowlist — and `Some(vec![])` grants nothing, never
        /// everything.
        allowed_repo_ids: Option<Vec<Uuid>>,
    },
    /// No principal: internal callers (reconcilers, ledger oracles, tests
    /// asserting the true union) that must see the unfiltered total. Never
    /// reachable from a request path.
    Unfiltered,
}

// ---------------------------------------------------------------------------
// Pure helper functions (no DB, testable in isolation)
// ---------------------------------------------------------------------------

/// Validate that a remote repository has an upstream URL and that the URL is
/// safe to contact (anti-SSRF). Returns an error if validation fails.
pub(crate) fn validate_remote_upstream(
    repo_type: &RepositoryType,
    upstream_url: &Option<String>,
    format: &RepositoryFormat,
) -> Result<()> {
    if *repo_type == RepositoryType::Remote {
        match upstream_url {
            None => {
                return Err(AppError::Validation(
                    "Remote repository must have an upstream URL".to_string(),
                ));
            }
            Some(url) => {
                validate_outbound_url(url, "Upstream URL")?;
                if *format == RepositoryFormat::Rpm && is_mirrorlist_or_metalink(url) {
                    return Err(AppError::Validation(
                        "RPM remote upstream must be a concrete baseurl, not a mirrorlist/metalink \
                         URL. Point it at a resolved repo root (e.g. .../BaseOS/x86_64/os/)."
                            .to_string(),
                    ));
                }
                if *format == RepositoryFormat::Debian && is_debian_flat_or_mirrorlist(url) {
                    return Err(AppError::Validation(
                        "Debian remote upstream must be a concrete archive root (apt expands \
                         `dists/<suite>/...` beneath it), not a flat repository, mirrorlist, or \
                         `mirror://` URL. Point it at the archive root (e.g. \
                         http://deb.debian.org/debian)."
                            .to_string(),
                    ));
                }
            }
        }
    } else if let Some(url) = upstream_url {
        validate_outbound_url(url, "Upstream URL")?;
    }
    Ok(())
}

/// Heuristic: a URL whose path or query names a mirrorlist/metalink endpoint.
fn is_mirrorlist_or_metalink(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.contains("mirrorlist") || lower.contains("metalink")
}

/// Heuristic: a Debian remote upstream that is a flat repository, a
/// mirrorlist, or the apt `mirror://` method rather than a concrete archive
/// root. apt expands `dists/<suite>/...` beneath a proper archive root
/// (e.g. `http://deb.debian.org/debian`), which this must NOT reject; it
/// rejects the shapes the remote-proxy trust model cannot verify against a
/// signed Release:
///   * the apt mirror method (`mirror://`, `mirror+http(s)://`) and any
///     mirrorlist/metalink naming,
///   * a baseurl aimed straight at a dists index file (`.../Packages`,
///     `.../Release`, `.../InRelease`, `.../Release.gpg`) — the flat-repo /
///     misconfiguration shape, and
///   * an explicit flat-repo distribution component (`deb <url> ./`).
fn is_debian_flat_or_mirrorlist(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("mirror://")
        || lower.starts_with("mirror+http://")
        || lower.starts_with("mirror+https://")
    {
        return true;
    }
    if lower.contains("mirrorlist") || lower.contains("metalink") {
        return true;
    }
    let path = lower.split(['?', '#']).next().unwrap_or(&lower);
    // Explicit flat-repo component (`deb <url> ./`).
    if path.ends_with("/./") || path.ends_with(" ./") || path.ends_with("/.") {
        return true;
    }
    let trimmed = path.trim_end_matches('/');
    trimmed.ends_with("/packages")
        || trimmed.ends_with("/packages.gz")
        || trimmed.ends_with("/packages.xz")
        || trimmed.ends_with("/inrelease")
        || trimmed.ends_with("/release")
        || trimmed.ends_with("/release.gpg")
}

/// Derive a format key string from a RepositoryFormat enum.
///
/// Returns the canonical snake_case format key matching the database enum
/// value and the `FormatHandler::format_key()` contract. Using `Debug`
/// formatting followed by `to_lowercase()` is insufficient because it
/// drops underscores from multi-word variants (e.g., `CondaNative` becomes
/// `"condanative"` instead of `"conda_native"`).
///
/// The mapping itself lives on [`RepositoryFormat::as_key`] so the format
/// registry has one definition rather than one per consumer (#3157).
pub(crate) fn derive_format_key(format: &RepositoryFormat) -> String {
    format.as_key().to_string()
}

/// Handler key a format gates on; aliases collapse to their core handler (mirrors get_handler_for_format).
pub(crate) fn format_handler_key(format: &RepositoryFormat) -> String {
    format.handler_key().to_string()
}

/// Build a SQL LIKE search pattern from a user query string.
pub(crate) fn build_search_pattern(query: Option<&str>) -> Option<String> {
    query.map(|q| format!("%{}%", q.to_lowercase()))
}

/// SQL fragment: true when the user bound at `$user_param` holds a non-empty
/// fine-grained `permissions` grant on `target_type = 'repository'` /
/// `target_id = repo_id_expr`, either directly (`principal_type IN ('user',
/// 'service_account')`, both referencing `users(id)` by the caller's own
/// `user_id`) or via
/// a group they belong to (`principal_type = 'group'`, resolved through
/// `user_group_members`).
///
/// This mirrors [`crate::services::permission_service::PermissionService`]'s
/// `query_actions` predicate exactly (same principal/group UNION semantics,
/// same target scoping), so repository *visibility* stays consistent with the
/// data-plane permission check that already governs uploads/updates.
///
/// `repo_id_expr` is a SQL expression naming the repository id in the caller's
/// query (e.g. `"r.id"` for a joined listing, or `"$2"` for a single-repo
/// lookup). `user_param` is the 1-based positional bind index (`$N`) of the
/// `user_id` value; this fragment introduces NO new bind — it reuses the same
/// `user_id` the caller already binds for the role-assignment predicate.
///
/// `actions <> '{}'` keeps the fragment failing CLOSED for rows that exist but
/// carry no actions, matching the data plane's "rules present but empty =>
/// denied" rule. The repository scoping deliberately excludes any
/// `target_type = 'system'` arm so visibility never widens beyond what the data
/// plane honours for repository access.
///
/// Projects (#2472): a grant on the repository's owning project
/// (`target_type = 'project'`, `target_id = repositories.project_id`) is
/// honoured alongside the direct repository grant. When the repository has no
/// project (`project_id IS NULL`) the project arm's subquery yields NULL and
/// `p.target_id = NULL` is never true, so unassigned repositories behave
/// exactly as before. The subquery aliases `repositories` as `rp` to avoid
/// colliding with any `r`/`repositories` reference in the caller's query.
fn permissions_grant_exists(repo_id_expr: &str, user_param: usize) -> String {
    // The positional-bind instantiation used by the listing/visibility callers:
    // the user principal is a single bound value `$user_param`. Delegates to the
    // expression-based builder so the generated SQL stays byte-identical.
    permissions_grant_exists_for(repo_id_expr, &format!("${user_param}"))
}

/// Expression-based variant of [`permissions_grant_exists`]: `user_ref` is any
/// SQL expression naming the candidate principal id (e.g. a positional bind
/// `"$3"` for a single-user check, or a correlated column `"u.id"` when
/// enumerating over `users u`). The blast-radius accessible-users enumeration
/// (#2386) inverts the read predicate over the whole users table, so it needs
/// the correlated-column form; every other caller passes a `"$N"` bind and gets
/// output identical to the historical `permissions_grant_exists` string.
///
/// Kept `pub(crate)` so the enumeration reuses this EXACT fragment (the project
/// arm, the group UNION, and the `actions <> '{}'` fail-closed rule) instead of
/// hand-rolling a copy that would drift from the data-plane read predicate.
pub(crate) fn permissions_grant_exists_for(repo_id_expr: &str, user_ref: &str) -> String {
    format!(
        r#"EXISTS (
            SELECT 1 FROM permissions p
            WHERE (
                  (p.target_type = 'repository' AND p.target_id = {repo_id_expr})
                  OR (p.target_type = 'project' AND p.target_id = (
                      SELECT rp.project_id FROM repositories rp WHERE rp.id = {repo_id_expr}
                  ))
              )
              AND p.actions <> '{{}}'
              AND (
                  (p.principal_type IN ('user', 'service_account') AND p.principal_id = {user_ref})
                  OR (p.principal_type = 'group' AND p.principal_id IN (
                      SELECT group_id FROM user_group_members WHERE user_id = {user_ref}
                  ))
              )
        )"#
    )
}

/// The GRANT half of repository visibility, WITHOUT the `is_public` disjunct:
/// the user holds a `role_assignments` row (repo-scoped or global) or a
/// fine-grained `permissions` rule (direct or via a group).
///
/// Factored out of [`build_visibility_clause_for`]'s `User` arm so the
/// member-visibility predicate (#3081) composes the identical grant SQL rather
/// than a second copy that could drift. `build_visibility_clause_for` is
/// `is_public = true OR <this>`; [`build_member_visibility_clause`] needs the
/// grant half on its own because `require_visible` conjoins token scope with
/// it *inside* the `is_public` disjunction.
pub(crate) fn build_grant_predicate(table_alias: &str, user_param: usize) -> String {
    // Visibility honours BOTH authz stores: the legacy `role_assignments`
    // grant (creator auto-grant + seeded admin) AND fine-grained `permissions`
    // grants written by `POST /api/v1/permissions` (including group grants).
    // The shared fragment reuses the same `$user_param` bind, so no extra bind
    // is introduced for any caller.
    let perms = permissions_grant_exists(&format!("{table_alias}.id"), user_param);
    format!(
        r#"(
                EXISTS (
                    SELECT 1 FROM role_assignments ra
                    WHERE ra.user_id = ${user_param}
                      AND (ra.repository_id = {table_alias}.id OR ra.repository_id IS NULL)
                )
                OR {perms}
            )"#
    )
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
    // Canonical instantiation for repository listing: the `repositories` table
    // is referenced unaliased and the visibility parameter is bound at `$3`.
    build_visibility_clause_for(visibility, "repositories", 3)
}

/// Alias- and parameter-index-aware variant of [`build_visibility_clause`].
///
/// Produces the same per-user grant predicate but lets the caller control:
/// - `table_alias`: the alias under which the `repositories` table is referenced
///   (e.g. `r` when the table is joined into a packages query); only the `.id`
///   references in the `User`/`Ids` arms are qualified, since `is_public` is
///   unique to `repositories` and resolves unambiguously even in a join.
/// - `user_param`: the positional bind index (`$N`) for the `user_id`/`ids`
///   value, so the generated `$N` lines up with the caller's `.bind()` order
///   (this differs per query).
///
/// [`build_visibility_clause`] is the canonical `("repositories", $3)`
/// instantiation used by repository listing.
pub(crate) fn build_visibility_clause_for(
    visibility: &RepoVisibility,
    table_alias: &str,
    user_param: usize,
) -> (String, VisibilityBind) {
    match visibility {
        RepoVisibility::PublicOnly => ("is_public = true".to_string(), VisibilityBind::User(None)),
        RepoVisibility::All => ("true".to_string(), VisibilityBind::User(None)),
        RepoVisibility::User(user_id) => {
            let grants = build_grant_predicate(table_alias, user_param);
            let clause = format!(
                r#"(
                is_public = true
                OR {grants}
            )"#
            );
            (clause, VisibilityBind::User(Some(*user_id)))
        }
        RepoVisibility::Ids(ids) => {
            // Restrict strictly to the token's allowed set. An empty set must
            // match no rows (not "all rows") — `id = ANY('{}')` is correctly
            // false for every row in Postgres.
            (
                format!("{table_alias}.id = ANY(${user_param})"),
                VisibilityBind::Ids(ids.clone()),
            )
        }
    }
}

/// Render [`MemberVisibility`] as `require_visible` verbatim, plus BOTH
/// positional binds (#3081).
///
/// Returns `(clause, user_bind, scope_bind)`. Unlike
/// [`build_visibility_clause_for`], whose bind SHAPE varies by variant (a
/// `Uuid` for some arms, a `Uuid[]` for others, so the caller must branch on
/// which one to `.bind()`), the shape here is fixed: the caller always binds
/// `$first_param` as `Option<Uuid>` and `$first_param + 1` as
/// `Option<Vec<Uuid>>`, in that order, for every variant. A bind the generated
/// clause does not reference is sent as a typed NULL, which is harmless
/// because sqlx supplies the parameter's type OID at Parse time. Fixing the
/// shape is deliberate: a variant-dependent bind order is how a future arm
/// silently binds the scope list into the user slot.
///
/// The `Principal` clause is
///
/// ```text
/// (is_public = true OR (<scope> AND <entitlement>))
/// ```
///
/// with `<scope>` = `true` for an unrestricted token or
/// `{alias}.id = ANY($scope)` for a repo-scoped one (an empty allowlist
/// correctly matches nothing), and `<entitlement>` = `true` for a global admin
/// or [`build_grant_predicate`] otherwise — the same grant SQL the listing's
/// `User` arm uses.
pub(crate) fn build_member_visibility_clause(
    visibility: &MemberVisibility,
    table_alias: &str,
    first_param: usize,
) -> (String, Option<Uuid>, Option<Vec<Uuid>>) {
    match visibility {
        MemberVisibility::Unfiltered => ("true".to_string(), None, None),
        MemberVisibility::Anonymous => ("is_public = true".to_string(), None, None),
        MemberVisibility::Principal {
            user_id,
            is_admin,
            allowed_repo_ids,
        } => {
            let scope_param = first_param + 1;
            let scope = match allowed_repo_ids {
                None => "true".to_string(),
                Some(_) => format!("{table_alias}.id = ANY(${scope_param})"),
            };
            let entitlement = if *is_admin {
                "true".to_string()
            } else {
                build_grant_predicate(table_alias, first_param)
            };
            let clause = format!(
                r#"(
                is_public = true
                OR ({scope} AND {entitlement})
            )"#
            );
            // The user bind is only referenced by the non-admin entitlement
            // half; it is still SENT for an admin (as a typed NULL) so the
            // bind order never depends on the variant.
            let user_bind = if *is_admin { None } else { Some(*user_id) };
            (clause, user_bind, allowed_repo_ids.clone())
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
        validate_remote_upstream(&req.repo_type, &req.upstream_url, &req.format)?;

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
            .unwrap_or_else(|| format_handler_key(&req.format));
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
                is_public, quota_bytes, promotion_only, versioning_enabled,
                project_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only,
                replication_priority as "replication_priority: ReplicationPriority",
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                age_gate_enabled, age_gate_min_age_days, versioning_enabled,
                project_id, created_at, updated_at
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
            req.versioning_enabled,
            req.project_id,
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
                // Trusted upstream GPG key for RPM curation (#2568). Persisted
                // inside the same tx as the INSERT so it is atomic with create.
                // The column is not on the `Repository` model (the sync reads it
                // via a targeted query, #2567); the handler exposes only a
                // boolean, never the key, so a separate write keeps it off the
                // model and out of any serialized `Repository`.
                if let Some(ref gpg_key) = req.trusted_gpg_key {
                    sqlx::query("UPDATE repositories SET trusted_gpg_key = $1 WHERE id = $2")
                        .bind(gpg_key)
                        .bind(repo.id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;
                }
                // Keyless-sync unverified-ingest opt-in (#2569). Persisted in the
                // same tx as the INSERT. Off the `Repository` model (the sync
                // reads it via its own targeted query, like `trusted_gpg_key`);
                // the column defaults false (fail-closed) so only an explicit
                // value needs a write.
                if let Some(allow_unverified) = req.curation_allow_unverified {
                    sqlx::query(
                        "UPDATE repositories SET curation_allow_unverified = $1 WHERE id = $2",
                    )
                    .bind(allow_unverified)
                    .bind(repo.id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
                }
                // Owner auto-grant: dual-write the durable repository-owner
                // and legacy developer roles during the staged rollout. Both
                // grants land in the same transaction as the repository.
                if let Some(creator_id) = req.created_by {
                    sqlx::query("UPDATE repositories SET created_by = $1 WHERE id = $2")
                        .bind(creator_id)
                        .bind(repo.id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;
                    sqlx::query(
                        "INSERT INTO role_assignments (user_id, role_id, repository_id) \
                         SELECT $1, r.id, $2 FROM roles r \
                         WHERE r.name IN ('repository-owner', 'developer') \
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

    /// Check whether a single user may perform `access` on a private repository.
    ///
    /// The TENANT half mirrors the `RepoVisibility::User` branch of
    /// [`build_visibility_clause`] for one repository: the user holds any role
    /// assignment scoped to that repository OR a global (NULL-scoped) one, or a
    /// fine-grained `permissions` rule (direct or via a group).
    ///
    /// The ACTION half (#3331) is `access`. [`RepoAccess::TenantOnly`] stops at
    /// the tenant gate — the historical behaviour, correct only where an action
    /// gate is layered separately or where the question really is tenant
    /// membership. [`RepoAccess::Action`] additionally requires that action
    /// through [`PermissionService::check_repository_action`], the canonical
    /// choke-point the OCI `/v2` and native-format read gates already use, so a
    /// `{write}`-only principal can no longer read a private repository's bytes
    /// through a REST content path while a direct `/v2` read of the same
    /// repository refuses.
    ///
    /// The two halves are ANDed, and the tenant half is evaluated FIRST: a
    /// principal with no grant at all still costs exactly one round trip, and
    /// the action lookup is only reached by principals who already hold
    /// something.
    ///
    /// This is the per-repo authorization predicate. Callers are responsible for
    /// short-circuiting the cases this method does NOT cover: admins bypass it
    /// entirely (so the action check is asked with `is_admin = false`, matching
    /// `try_authorize_virtual_members`) and public repositories are accessible
    /// to everyone.
    ///
    /// [`PermissionService::check_repository_action`]: crate::services::permission_service::PermissionService::check_repository_action
    pub async fn user_can_access_repo(
        &self,
        repo_id: Uuid,
        user_id: Uuid,
        access: RepoAccess,
    ) -> Result<bool> {
        // Access is granted via EITHER authz store, in a single round trip:
        // the legacy `role_assignments` predicate OR a fine-grained
        // `permissions` grant (direct or via group), mirroring the
        // `RepoVisibility::User` listing arm so direct GET and listing agree.
        let granted: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS ( \
                 SELECT 1 FROM role_assignments ra \
                 WHERE ra.user_id = $1 \
                   AND (ra.repository_id = $2 OR ra.repository_id IS NULL) \
             ) OR {}",
            permissions_grant_exists("$2", 1)
        ))
        .bind(user_id)
        .bind(repo_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if !granted {
            return Ok(false);
        }
        match access {
            RepoAccess::TenantOnly => Ok(granted),
            // Action gate (#3331), the #2603 G1 / #3326 idiom: the predicate
            // above admits ANY grantee, so without this a `{write}` grant on a
            // private repository bought that repository's bytes through every
            // REST content path. `is_admin` is passed as `false` because every
            // caller short-circuits admins before reaching here; passing the
            // caller's flag would be a second, redundant bypass.
            RepoAccess::Action(action) => {
                crate::services::permission_service::PermissionService::new(self.db.clone())
                    .check_repository_action(user_id, repo_id, action, false)
                    .await
            }
        }
    }

    /// Narrow `candidate_ids` to the repositories this caller is allowed to
    /// SEE, preserving the caller's input order (issue #3163).
    ///
    /// This is the set-shaped counterpart to [`Self::user_can_access_repo`],
    /// for the paths that aggregate over a list of OTHER repositories on the
    /// caller's behalf — today a virtual repository's members, which are
    /// separate repositories with their own ACLs. It evaluates the SAME
    /// predicate the repository listing uses ([`build_visibility_clause_for`]),
    /// so "which members does this caller see through the virtual" and "which
    /// repositories does this caller see in `GET /repositories`" cannot drift
    /// apart.
    ///
    /// It is deliberately NOT [`crate::api::middleware::auth::AuthExtension::can_access_repo`],
    /// which answers a different question — "is this repository within my
    /// TOKEN's scope?" — and returns `true` for every repository in the
    /// instance whenever the principal is unscoped (a browser JWT session, an
    /// unrestricted API token, an admin).
    ///
    /// Order is preserved because callers depend on it: virtual members are
    /// resolved in priority order.
    pub async fn filter_visible_repo_ids(
        &self,
        candidate_ids: &[Uuid],
        visibility: &RepoVisibility,
    ) -> Result<Vec<Uuid>> {
        if candidate_ids.is_empty() {
            return Ok(Vec::new());
        }
        // `All` (admins, and internal oracles/reconcilers) is the literal
        // `true` clause, so the admin path costs no extra round trip and is
        // byte-identical to the pre-#3163 unfiltered set.
        if matches!(visibility, RepoVisibility::All) {
            return Ok(candidate_ids.to_vec());
        }

        let (visibility_clause, visibility_bind) = build_visibility_clause_for(visibility, "r", 2);
        // Split the visibility bind into the two concrete `$2` shapes. Exactly
        // one is `Some` per call; the unused one stays `None` and binds as a
        // typed NULL, which the generated clause never references.
        let (user_id_bind, ids_bind): (Option<Uuid>, Option<Vec<Uuid>>) = match visibility_bind {
            VisibilityBind::User(uid) => (uid, None),
            VisibilityBind::Ids(ids) => (None, Some(ids)),
        };
        let sql = format!(
            "SELECT r.id FROM repositories r \
             WHERE r.id = ANY($1) AND ({visibility_clause})"
        );
        let query = sqlx::query_scalar(&sql).bind(candidate_ids);
        let query = match &ids_bind {
            Some(ids) => query.bind(ids.clone()),
            None => query.bind(user_id_bind),
        };
        let visible: Vec<Uuid> = query
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let visible: std::collections::HashSet<Uuid> = visible.into_iter().collect();
        Ok(candidate_ids
            .iter()
            .copied()
            .filter(|id| visible.contains(id))
            .collect())
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
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                age_gate_enabled, age_gate_min_age_days, versioning_enabled,
                project_id, created_at, updated_at
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
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                age_gate_enabled, age_gate_min_age_days, versioning_enabled,
                project_id, created_at, updated_at
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
    ///
    /// `project_filter` narrows the listing to repositories assigned to the
    /// given project (#2472); `None` applies no project restriction.
    #[allow(clippy::too_many_arguments)] // mirrors the listing filter surface 1:1
    pub async fn list(
        &self,
        offset: i64,
        limit: i64,
        format_filter: Option<RepositoryFormat>,
        type_filter: Option<RepositoryType>,
        visibility: RepoVisibility,
        search_query: Option<&str>,
        project_filter: Option<Uuid>,
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
        // NOTE: the project-filter bind index differs between the page query
        // ($7: offset/limit occupy $5/$6) and the count query ($5: no
        // offset/limit); each `$N` matches its own query's positional order.
        let select_sql = format!(
            r#"
            SELECT
                id, key, name, description,
                format, repo_type,
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only,
                replication_priority,
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                age_gate_enabled, age_gate_min_age_days, versioning_enabled,
                project_id, created_at, updated_at
            FROM repositories
            WHERE ($1::repository_format IS NULL OR format = $1)
              AND ($2::repository_type IS NULL OR repo_type = $2)
              AND ({visibility_clause})
              AND ($4::text IS NULL OR LOWER(key) LIKE $4 OR LOWER(name) LIKE $4 OR LOWER(COALESCE(description, '')) LIKE $4)
              AND ($7::uuid IS NULL OR project_id = $7)
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
            .bind(project_filter)
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
              AND ($5::uuid IS NULL OR project_id = $5)
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
            .bind(project_filter)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((repos, total))
    }

    /// Update a repository
    pub async fn update(&self, id: Uuid, req: UpdateRepositoryRequest) -> Result<Repository> {
        // Validate upstream_url is safe to contact if it is being updated.
        // `UpdateRepositoryRequest` carries neither `repo_type` nor `format`
        // (both are immutable after creation), so load the existing row to
        // source them for the mirrorlist/metalink check on RPM remotes.
        if req.upstream_url.is_some() {
            let existing = self.get_by_id(id).await?;
            validate_remote_upstream(&existing.repo_type, &req.upstream_url, &existing.format)?;
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
                versioning_enabled = COALESCE($9, versioning_enabled),
                project_id = COALESCE($10, project_id),
                curation_enabled = COALESCE($11, curation_enabled),
                curation_default_action = COALESCE($12, curation_default_action),
                updated_at = NOW()
            WHERE id = $1
            RETURNING
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, promotion_only,
                replication_priority as "replication_priority: ReplicationPriority",
                curation_enabled, curation_source_repo_id, curation_target_repo_id,
                curation_default_action, curation_sync_interval_secs, curation_auto_fetch,
                age_gate_enabled, age_gate_min_age_days, versioning_enabled,
                project_id, created_at, updated_at
            "#,
            id,
            req.key,
            req.name,
            req.description,
            req.is_public,
            req.quota_bytes.flatten(),
            req.upstream_url,
            req.promotion_only,
            req.versioning_enabled,
            req.project_id.flatten(),
            req.curation_enabled,
            req.curation_default_action,
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

        // Trusted upstream GPG key (#2568). Applied as a targeted write after
        // the main COALESCE update because COALESCE cannot express "clear to
        // NULL": `Some(None)` must be able to null the column. The column is
        // deliberately off the `Repository` model (the sync reads it via its
        // own query, #2567) and the handler exposes only a boolean, never the
        // key. `None` leaves the stored value unchanged.
        if let Some(ref gpg_key) = req.trusted_gpg_key {
            sqlx::query(
                "UPDATE repositories SET trusted_gpg_key = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(gpg_key.as_deref())
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        // Keyless-sync unverified-ingest opt-in (#2569). `None` leaves it
        // unchanged; `Some(v)` sets it (false restores the fail-closed default,
        // true opts into legacy unverified ingest).
        if let Some(allow_unverified) = req.curation_allow_unverified {
            sqlx::query(
                "UPDATE repositories SET curation_allow_unverified = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(allow_unverified)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        // #2516 S2: quota admission trusts the usage-ledger counters. While a
        // repository sits at unlimited quota the admission fast path never
        // touches the ledger, so its counters can be stale when a finite
        // quota is first configured. True the ledger up synchronously so
        // enforcement starts from the live figure instead of waiting for the
        // background reconciler's next pass. Best-effort: the repository
        // update above has already committed, so a reconcile failure must not
        // fail the request — the background reconciler repairs the row on its
        // interval.
        if let Some(Some(quota)) = req.quota_bytes {
            if quota > 0 {
                if let Err(e) = self.reconcile_usage_ledger(id).await {
                    tracing::warn!(
                        repository_id = %id,
                        error = %e,
                        "failed to reconcile usage ledger after quota change; \
                         background reconciler will repair it"
                    );
                }
            }
        }

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
                r.curation_enabled, r.curation_source_repo_id, r.curation_target_repo_id,
                r.curation_default_action, r.curation_sync_interval_secs, r.curation_auto_fetch,
                r.age_gate_enabled, r.age_gate_min_age_days, r.versioning_enabled,
                r.project_id, r.created_at, r.updated_at
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
        // #2218: single-repo sibling of the list-endpoint UNION. Proxy-cached
        // bytes come from the `proxy_cache_artifacts` catalog (remote repos have
        // no `artifacts` rows); legacy `proxy-cache/%` leftovers in `artifacts`
        // are excluded so a backfilled object is never double counted. Hosted
        // repos are unaffected (no proxy keys, empty catalog).
        //
        // OCI layer/config blobs live in `oci_blobs`, not `artifacts` (only
        // manifests land there), so without the third branch a docker repo
        // reports a few KiB of manifests while holding GiBs of layers.
        // `oci_blobs` is UNIQUE(repository_id, digest), so this sum counts
        // each stored blob once per repo — the same per-repo logical figure
        // the stats refresher computes. A blob cross-repo-mounted into N
        // repos counts in each of them; physical-footprint dedup on shared
        // cloud backends is the refresher's `DedupScope` concern, not this
        // SUM's.
        let usage = sqlx::query_scalar!(
            r#"
            SELECT COALESCE(SUM(bytes), 0)::BIGINT as "usage!"
            FROM (
                SELECT size_bytes AS bytes
                  FROM artifacts
                 WHERE repository_id = $1 AND is_deleted = false
                   AND storage_key NOT LIKE 'proxy-cache/%'
                UNION ALL
                SELECT size_bytes AS bytes
                  FROM proxy_cache_artifacts
                 WHERE repository_id = $1
                UNION ALL
                SELECT size_bytes AS bytes
                  FROM oci_blobs
                 WHERE repository_id = $1
            ) t
            "#,
            repo_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(usage)
    }

    /// Storage figure to DISPLAY for `repo` (issue #2785).
    ///
    /// A virtual repository owns no `artifacts` / `proxy_cache_artifacts` /
    /// `oci_blobs` rows of its own — its content is whatever resolves through
    /// its members. A plain `get_storage_usage(virtual_id)` therefore reports
    /// the virtual's *own* rows (effectively zero) even though browsing the
    /// virtual surfaces real member data, so the detail view showed a total
    /// that did not match the combined total of its child repos. For a virtual
    /// repo we instead sum over the union of its resolvable member contents;
    /// every other repo type keeps the existing per-repo figure unchanged.
    ///
    /// `visibility` is the CALLER's member visibility (issue #3081): the
    /// virtual total is aggregated only over the members that caller is
    /// allowed to see. It is unused for non-virtual repositories, whose own
    /// figure is already gated by the handler's `require_visible` check.
    pub async fn get_display_storage_usage(
        &self,
        repo: &Repository,
        visibility: &MemberVisibility,
    ) -> Result<i64> {
        if repo.repo_type == RepositoryType::Virtual {
            self.get_virtual_storage_usage(repo.id, visibility).await
        } else {
            self.get_storage_usage(repo.id).await
        }
    }

    /// Combined storage figure for a virtual repository: the union of the
    /// contents of every non-virtual member reachable through the membership
    /// graph (issue #2785).
    ///
    /// The membership graph is walked with a recursive CTE bounded by
    /// [`MAX_VIRTUAL_DEPTH`] so a nested virtual member contributes its own
    /// leaves. Leaf (non-virtual) repositories are collected DISTINCT, so a
    /// repository reachable through two different members is counted once
    /// (union semantics) rather than double-counted. The per-leaf sum reuses
    /// the same three components as [`Self::get_storage_usage`]
    /// (`artifacts` + `proxy_cache_artifacts` + `oci_blobs`), keeping the
    /// virtual total consistent with the sum of what each member reports on
    /// its own.
    ///
    /// Uses the dynamic query API (not the `query!` macro) so this path does
    /// not depend on an updated offline SQLx cache, matching the convention
    /// used by the cycle-detection walk.
    ///
    /// # Caller-scoped (issue #3081)
    ///
    /// The leaf set is filtered through [`build_member_visibility_clause`],
    /// which is `require_visible` verbatim — BOTH the caller's entitlement and
    /// their token's repository scope. So a caller who reaches the virtual
    /// parent but could not `GET` a member never sees that member's bytes
    /// folded into the total. Without it the aggregate was a byte-size oracle
    /// for repositories whose direct `GET` correctly 404s — including, because
    /// `require_visible` early-returns on `is_public` without consulting
    /// `can_access_repo` and `get_repository` carries no `require_repo_access`,
    /// for a repo-scoped token that reached a PUBLIC virtual outside its scope.
    /// [`MemberVisibility::Unfiltered`] (internal oracles/reconcilers) produces
    /// the literal `true` clause, i.e. the unfiltered pre-#3081 sum.
    ///
    /// Only the LEAVES are filtered — the membership walk itself is unchanged,
    /// so an invisible intermediate virtual still contributes the leaves the
    /// caller *can* see.
    pub async fn get_virtual_storage_usage(
        &self,
        virtual_repo_id: Uuid,
        visibility: &MemberVisibility,
    ) -> Result<i64> {
        // `$2` = user id, `$3` = token scope, `$4` = depth. The bind order is
        // the same for every variant; an unreferenced bind is a typed NULL.
        let (visibility_clause, user_id_bind, scope_bind) =
            build_member_visibility_clause(visibility, "leaf", 2);
        let sql = format!(
            r#"
            WITH RECURSIVE reachable(repo_id, depth) AS (
                SELECT vrm.member_repo_id, 1
                  FROM virtual_repo_members vrm
                 WHERE vrm.virtual_repo_id = $1
              UNION
                SELECT vrm.member_repo_id, reachable.depth + 1
                  FROM reachable
                  JOIN repositories parent
                    ON parent.id = reachable.repo_id
                   AND parent.repo_type = 'virtual'
                  JOIN virtual_repo_members vrm
                    ON vrm.virtual_repo_id = reachable.repo_id
                 WHERE reachable.depth < $4
            ),
            leaves AS (
                SELECT DISTINCT reachable.repo_id AS id
                  FROM reachable
                  JOIN repositories leaf ON leaf.id = reachable.repo_id
                 WHERE leaf.repo_type <> 'virtual'
                   AND ({visibility_clause})
            )
            SELECT COALESCE(SUM(bytes), 0)::BIGINT
            FROM (
                SELECT size_bytes AS bytes
                  FROM artifacts
                 WHERE repository_id IN (SELECT id FROM leaves)
                   AND is_deleted = false
                   AND storage_key NOT LIKE 'proxy-cache/%'
                UNION ALL
                SELECT size_bytes AS bytes
                  FROM proxy_cache_artifacts
                 WHERE repository_id IN (SELECT id FROM leaves)
                UNION ALL
                SELECT size_bytes AS bytes
                  FROM oci_blobs
                 WHERE repository_id IN (SELECT id FROM leaves)
            ) t
            "#
        );
        let usage: i64 = sqlx::query_scalar(&sql)
            .bind(virtual_repo_id)
            .bind(user_id_bind)
            .bind(scope_bind)
            .bind(MAX_VIRTUAL_DEPTH as i32)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(usage)
    }

    /// Batched sibling of [`Self::get_virtual_storage_usage`] for the listing
    /// endpoint (issue #3078): resolve the reachable non-virtual leaves of
    /// EVERY requested virtual root in ONE query (the listing used to call the
    /// per-repo method once per virtual on the page — an N+1 whose every call
    /// also re-scanned every reachable member's artifact rows).
    ///
    /// The recursion is the per-repo CTE with the root id threaded through it,
    /// so roots stay independent: two virtuals sharing a leaf each count it,
    /// under their own root. `UNION` (not `UNION ALL`) plus the
    /// `depth < MAX_VIRTUAL_DEPTH` bound keeps the same cycle/nesting
    /// termination, and `SELECT DISTINCT root_id, repo_id` keeps the #2785
    /// union semantics — a leaf reachable through two paths under one root is
    /// counted once.
    ///
    /// Per-leaf bytes come from the trigger-maintained
    /// `repository_usage_ledger` (migrations 171/182), which is byte-for-byte
    /// equivalent to the live 3-way SUM the per-repo method computes (same
    /// `is_deleted` / `proxy-cache/%` predicates in 182's triggers), so the
    /// aggregation input shrinks from O(artifacts under all members) to
    /// O(member repositories). `LEFT JOIN` + `COALESCE` make a leaf with no
    /// ledger row contribute 0 rather than poisoning the SUM with NULL. A root
    /// with no resolvable members has no row in the returned map — the caller
    /// renders 0 for it.
    pub async fn get_virtual_storage_usage_batch(
        &self,
        virtual_ids: &[Uuid],
        visibility: &MemberVisibility,
    ) -> Result<std::collections::HashMap<Uuid, i64>> {
        if virtual_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        // #3081: the SAME caller-scoped leaf filter as the per-repo walk — the
        // listing must not disclose the byte size of a member the caller could
        // not `GET`. `MemberVisibility::Unfiltered` yields the literal `true`
        // clause, so an internal read is byte-identical to the pre-#3081
        // aggregate. `$2` = user id, `$3` = token scope, `$4` = depth.
        let (visibility_clause, user_id_bind, scope_bind) =
            build_member_visibility_clause(visibility, "leaf", 2);
        let sql = format!(
            r#"
            WITH RECURSIVE reachable(root_id, repo_id, depth) AS (
                SELECT vrm.virtual_repo_id, vrm.member_repo_id, 1
                  FROM virtual_repo_members vrm
                 WHERE vrm.virtual_repo_id = ANY($1)
              UNION
                SELECT reachable.root_id, vrm.member_repo_id, reachable.depth + 1
                  FROM reachable
                  JOIN repositories parent
                    ON parent.id = reachable.repo_id
                   AND parent.repo_type = 'virtual'
                  JOIN virtual_repo_members vrm
                    ON vrm.virtual_repo_id = reachable.repo_id
                 WHERE reachable.depth < $4
            ),
            leaves AS (
                SELECT DISTINCT reachable.root_id AS root_id, reachable.repo_id AS id
                  FROM reachable
                  JOIN repositories leaf ON leaf.id = reachable.repo_id
                 WHERE leaf.repo_type <> 'virtual'
                   AND ({visibility_clause})
            )
            SELECT leaves.root_id,
                   COALESCE(SUM(l.hosted_bytes + l.proxy_bytes + l.oci_bytes), 0)::BIGINT
              FROM leaves
              LEFT JOIN repository_usage_ledger l ON l.repository_id = leaves.id
             GROUP BY leaves.root_id
            "#
        );
        let rows: Vec<(Uuid, i64)> = sqlx::query_as(&sql)
            .bind(virtual_ids)
            .bind(user_id_bind)
            .bind(scope_bind)
            .bind(MAX_VIRTUAL_DEPTH as i32)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().collect())
    }

    /// Reconcile the FULL member set of a virtual repository to exactly
    /// `desired` (issue #2785 defect B).
    ///
    /// # Contract: full-set replace, not a partial update
    ///
    /// `desired` is the COMPLETE desired membership. This replaces the
    /// membership with exactly the `(member_repo_id, priority)` pairs it
    /// contains, in a single transaction guarded by the same process-wide
    /// member-graph advisory lock that `add_virtual_member` and
    /// `update_virtual_member_priorities` take (so it never contends with a
    /// concurrent membership mutation):
    ///
    ///   * members NOT present in `desired` are REMOVED;
    ///   * members already present have their priority UPDATED;
    ///   * members present in `desired` but not yet in the table are INSERTED;
    ///   * an empty `desired` removes every member.
    ///
    /// This is destructive by design. A caller that passes a partial list in
    /// order to reorder priorities will DELETE the members it omitted, so
    /// callers must always assemble the full member list first.
    ///
    /// Editing a virtual repository after creation must be able to add and
    /// remove members, not merely reorder the ones added at create time, which
    /// is why PR #2795 (issue #2785) changed
    /// `PUT /api/v1/repositories/{key}/members` from a priorities-only
    /// update to this replace. Issue #2899 reviewed the
    /// resulting breaking API-semantics change and RATIFIED it: replace
    /// semantics are the intended, supported contract of this function and of
    /// that endpoint. Do not narrow it back to a priorities-only update; the
    /// removal arm is covered by
    /// `test_set_virtual_members_edits_after_create_2785`.
    ///
    /// Caller-side authorization (repo-admin on the virtual parent +
    /// token-scope / cycle / format checks per member) is enforced by the
    /// handler before this runs.
    pub async fn set_virtual_members(
        &self,
        virtual_repo_id: Uuid,
        desired: &[(Uuid, i32)],
    ) -> Result<()> {
        let member_ids: Vec<Uuid> = desired.iter().map(|(id, _)| *id).collect();
        let priorities: Vec<i32> = desired.iter().map(|(_, p)| *p).collect();

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

        // Remove members that are no longer in the desired set. `<> ALL($2)`
        // over an empty array is TRUE for every row, so an empty desired set
        // clears the membership.
        sqlx::query(
            r#"
            DELETE FROM virtual_repo_members
             WHERE virtual_repo_id = $1
               AND member_repo_id <> ALL($2::uuid[])
            "#,
        )
        .bind(virtual_repo_id)
        .bind(&member_ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Upsert the desired members: insert the new ones, refresh the
        // priority of the ones that already existed.
        sqlx::query(
            r#"
            INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority)
            SELECT $1, m.member_repo_id, m.priority
              FROM UNNEST($2::uuid[], $3::int4[]) AS m(member_repo_id, priority)
            ON CONFLICT (virtual_repo_id, member_repo_id)
            DO UPDATE SET priority = EXCLUDED.priority
            "#,
        )
        .bind(virtual_repo_id)
        .bind(&member_ids)
        .bind(&priorities)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Check if an upload of `additional_bytes` would be permitted under the
    /// repository's storage quota.
    ///
    /// Quota semantics (matching the convention used by `quota_usage_percentage`
    /// and the wider artifact-registry ecosystem):
    ///
    /// * `quota_bytes = NULL`  -> no quota configured -> **unlimited**
    /// * `quota_bytes <= 0`    -> non-positive sentinel -> **unlimited**
    ///   (`0` historically meant "no limit"; persisting it as a literal
    ///   zero-byte hard cap silently rejected *every* write to the repo,
    ///   surfacing as a `507 QUOTA_EXCEEDED` on the very first non-empty
    ///   upload even though the host had ample free disk.)
    /// * `quota_bytes > 0`     -> a real, finite limit, checked against the
    ///   repository's usage-ledger counters (#2516 S2) — an O(1) read that is
    ///   invariant to repository size. This is the unlocked best-effort
    ///   preflight; the authoritative, race-free admission is
    ///   [`Self::check_quota_locked`].
    pub async fn check_quota(&self, repo_id: Uuid, additional_bytes: i64) -> Result<bool> {
        let repo = self.get_by_id(repo_id).await?;
        Ok(Self::quota_allows(
            repo.quota_bytes,
            // Only hit the DB for usage when a finite quota is actually set.
            match repo.quota_bytes {
                Some(quota) if quota > 0 => self.get_ledger_usage(repo_id).await?,
                _ => 0,
            },
            additional_bytes,
        ))
    }

    /// Unlocked O(1) usage read for quota preflight (#2516 S2): the sum of
    /// the `repository_usage_ledger` counters, falling back to the live
    /// 3-way SUM ([`Self::get_storage_usage`]) only when the repository has
    /// no ledger row yet (pre-ledger repo whose first quota-checked upload
    /// has not lazily seeded it). Display paths keep using the live
    /// [`Self::get_storage_usage`] figure.
    async fn get_ledger_usage(&self, repo_id: Uuid) -> Result<i64> {
        let total: Option<i64> = sqlx::query_scalar!(
            r#"SELECT (hosted_bytes + proxy_bytes + oci_bytes)::BIGINT as "total!"
                 FROM repository_usage_ledger WHERE repository_id = $1"#,
            repo_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        match total {
            Some(total) => Ok(total),
            None => self.get_storage_usage(repo_id).await,
        }
    }

    /// Pure quota-admission decision, factored out so it can be unit-tested
    /// without a database. Returns `true` when the upload is permitted.
    ///
    /// A `None` quota, or any non-positive quota (`<= 0`), means unlimited.
    pub(crate) fn quota_allows(
        quota_bytes: Option<i64>,
        current_usage: i64,
        additional_bytes: i64,
    ) -> bool {
        match quota_bytes {
            Some(quota) if quota > 0 => current_usage + additional_bytes <= quota,
            // NULL or a non-positive sentinel (0 / negative) => unlimited.
            _ => true,
        }
    }

    /// Atomically admit (or reject) an upload of `new_size` bytes to `path`
    /// under the repository's storage quota, **inside the caller's
    /// transaction**.
    ///
    /// This closes the over-admission race (#2523). `check_quota` alone reads
    /// the live sum without any lock, so two concurrent near-limit uploads can
    /// both read the pre-upload usage and both be admitted beyond the quota.
    /// Here we `SELECT ... FOR UPDATE` the repository's
    /// `repository_usage_ledger` row, so uploads into the same repository
    /// serialize on that row. Because the caller performs the artifact INSERT
    /// in the *same* transaction, the second admission observes the first
    /// upload's committed bytes and is rejected when the quota would be
    /// exceeded.
    ///
    /// O(1) admission (#2516 S2): usage is read from the locked ledger row's
    /// maintained counters (`hosted_bytes + proxy_bytes + oci_bytes`) instead
    /// of re-aggregating the live source tables under the lock, so the work
    /// inside the critical section is a primary-key lookup plus one
    /// unique-index lookup — invariant to repository size. The previous
    /// implementation re-ran the full 3-way `SUM` while holding the row lock,
    /// which was exact but O(repository rows) per upload and serialized every
    /// same-repo upload behind that scan (#2516 F1). This function does NOT
    /// charge the ledger itself: migration 182's row-level triggers on the
    /// source tables apply the delta when the caller performs its artifact
    /// INSERT, inside this same transaction. Because the caller's INSERT runs
    /// while the `FOR UPDATE` lock taken here is still held, commit applies
    /// the trigger's charge together with the artifact row and rollback
    /// discards both — a subsequent admission that waited on the lock always
    /// observes the charge. Callers must therefore keep the INSERT in the
    /// same transaction as this admission check.
    ///
    /// Counter coverage / freshness contract: the ledger tracks all three
    /// usage components (hosted, proxy-cache, OCI blobs), so nothing is
    /// dropped from enforcement. Migration 182's triggers maintain every
    /// component on every INSERT/UPDATE/DELETE of the source tables
    /// (`artifacts`, `proxy_cache_artifacts`, `oci_blobs`) in the mutating
    /// statement's own transaction, so the counters read here are exact for
    /// all write paths — including format handlers inserting `artifacts` rows
    /// directly, proxy-cache fills, OCI blob pushes, deletes, lifecycle and
    /// GC. The background reconciler ([`Self::reconcile_usage_ledger`])
    /// remains as a drift safety net only.
    ///
    /// NOTE on migration 182's header comment (#3080): it claims
    /// "`check_quota_locked` still reads the authoritative live sum". That
    /// was true when 182 shipped but is stale — quota admission has read the
    /// `repository_usage_ledger` row under `FOR UPDATE` (the query below)
    /// since #2516/#2992. The migration file cannot be corrected because
    /// sqlx validates checksums of applied migrations, so THIS comment is
    /// the authoritative statement of how admission reads usage.
    ///
    /// Usage at the target `path` is netted out (unique-index lookup on
    /// `(repository_id, path)`), so an in-place overwrite is charged only its
    /// size delta rather than double-counting the bytes it replaces.
    ///
    /// A `None`/non-positive quota means unlimited: the call returns
    /// `allowed = true` without locking or touching the ledger.
    pub async fn check_quota_locked(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: Uuid,
        path: &str,
        new_size: i64,
    ) -> Result<QuotaAdmission> {
        let quota_bytes: Option<i64> = sqlx::query_scalar!(
            "SELECT quota_bytes FROM repositories WHERE id = $1",
            repo_id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let quota = match quota_bytes {
            Some(quota) if quota > 0 => quota,
            // NULL or a non-positive sentinel => unlimited: nothing to lock or
            // count.
            _ => {
                return Ok(QuotaAdmission {
                    allowed: true,
                    base_usage: None,
                })
            }
        };

        // Serialize same-repo admissions on the ledger row and read the
        // maintained counters under that lock: a primary-key lookup, O(1) in
        // repository size. The lock is held until the caller commits (after
        // its artifact INSERT).
        let locked = sqlx::query!(
            "SELECT hosted_bytes, proxy_bytes, oci_bytes \
               FROM repository_usage_ledger \
              WHERE repository_id = $1 FOR UPDATE",
            repo_id
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total: i64 = match locked {
            Some(row) => row.hosted_bytes + row.proxy_bytes + row.oci_bytes,
            // Pre-ledger repository (no row yet): lazy-create it seeded from
            // the authoritative live sums, NOT from column defaults — a
            // zero-seeded row would admit everything until the first
            // reconcile pass. One-time O(rows) for the first quota-checked
            // upload; every later admission takes the O(1) branch above. The
            // helper locks the row first and leaves it locked in `tx`.
            None => {
                let (hosted, proxy, oci) = Self::reconcile_usage_ledger_in_tx(tx, repo_id).await?;
                hosted + proxy + oci
            }
        };

        // Net-delta accounting for overwrites: subtract the bytes already
        // charged for the (repository_id, path) row we are about to replace.
        let existing_at_path: i64 = sqlx::query_scalar!(
            r#"
            SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as "bytes!"
              FROM artifacts
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false
               AND storage_key NOT LIKE 'proxy-cache/%'
            "#,
            repo_id,
            path
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let base_usage = total - existing_at_path;
        let allowed = Self::quota_allows(Some(quota), base_usage, new_size);
        // No manual charge here: the caller's artifact INSERT (same
        // transaction, made while the row lock taken above is still held)
        // fires migration 182's trigger, which applies the exact delta to
        // `hosted_bytes` before the transaction commits.
        Ok(QuotaAdmission {
            allowed,
            base_usage: Some(base_usage),
        })
    }

    /// Recompute one repository's usage-ledger components from the
    /// authoritative source tables and write them, inside `tx`, holding the
    /// ledger row's `FOR UPDATE` lock for the remainder of the transaction.
    /// Creates the row if the repository predates the ledger.
    ///
    /// Lock ordering matters: the row is locked BEFORE the source tables are
    /// read. Locking first blocks behind any in-flight quota admission, so
    /// the sums computed here include that admission's committed rows;
    /// computing the sums first and upserting after (as the pre-#2516
    /// reconciler did, unlocked on the pool) could overwrite a concurrent
    /// admission's just-committed charge with stale values.
    ///
    /// Returns the reconciled `(hosted, proxy, oci)` components.
    async fn reconcile_usage_ledger_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: Uuid,
    ) -> Result<(i64, i64, i64)> {
        sqlx::query!(
            "INSERT INTO repository_usage_ledger (repository_id) VALUES ($1) \
             ON CONFLICT (repository_id) DO NOTHING",
            repo_id
        )
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        sqlx::query_scalar!(
            "SELECT hosted_bytes FROM repository_usage_ledger \
             WHERE repository_id = $1 FOR UPDATE",
            repo_id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let hosted: i64 = sqlx::query_scalar!(
            r#"
            SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as "bytes!"
              FROM artifacts
             WHERE repository_id = $1 AND is_deleted = false
               AND storage_key NOT LIKE 'proxy-cache/%'
            "#,
            repo_id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let proxy: i64 = sqlx::query_scalar!(
            r#"SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as "bytes!"
                 FROM proxy_cache_artifacts WHERE repository_id = $1"#,
            repo_id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let oci: i64 = sqlx::query_scalar!(
            r#"SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as "bytes!"
                 FROM oci_blobs WHERE repository_id = $1"#,
            repo_id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        sqlx::query!(
            "UPDATE repository_usage_ledger \
                SET hosted_bytes = $2, proxy_bytes = $3, oci_bytes = $4, \
                    updated_at = now() \
              WHERE repository_id = $1",
            repo_id,
            hosted,
            proxy,
            oci
        )
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((hosted, proxy, oci))
    }

    /// Recompute one repository's usage-ledger components from the
    /// authoritative source tables and upsert them, in a transaction that
    /// takes the same per-repository ledger-row lock quota admission holds
    /// (see [`Self::reconcile_usage_ledger_in_tx`] for the lock-ordering
    /// rationale). Returns the reconciled total (`hosted + proxy + oci`).
    /// Used by the background reconciler, by quota configuration, and by
    /// tests.
    pub async fn reconcile_usage_ledger(&self, repo_id: Uuid) -> Result<i64> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let (hosted, proxy, oci) = Self::reconcile_usage_ledger_in_tx(&mut tx, repo_id).await?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(hosted + proxy + oci)
    }

    /// True up every repository's usage ledger against the authoritative live
    /// sums, repairing drift from any write path that did not maintain the
    /// ledger. Runs on the background scheduler; safe to run at any time.
    pub async fn reconcile_all_usage_ledgers(&self) -> Result<UsageLedgerReconcileReport> {
        let ids: Vec<Uuid> = sqlx::query_scalar!("SELECT id FROM repositories")
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let mut report = UsageLedgerReconcileReport::default();
        for id in ids {
            let before: i64 = sqlx::query_scalar!(
                r#"SELECT COALESCE(hosted_bytes + proxy_bytes + oci_bytes, 0)::BIGINT as "t!"
                     FROM repository_usage_ledger WHERE repository_id = $1"#,
                id
            )
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .unwrap_or(0);

            // Per-repository failures are non-fatal: a repository can be
            // deleted between the id snapshot above and this upsert (the FK
            // then rejects the write), and one bad row must not abort the whole
            // pass. Skip and continue.
            match self.reconcile_usage_ledger(id).await {
                Ok(after) => {
                    report.repositories_checked += 1;
                    if after != before {
                        report.repositories_repaired += 1;
                        report.total_drift_bytes += (after - before).abs();
                    }
                }
                Err(e) => {
                    tracing::debug!("skipping usage-ledger reconcile for {}: {}", id, e);
                }
            }
        }
        Ok(report)
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

/// #3331: the CLASS-level gate on action-blind repository access checks.
///
/// The defect was never one careless handler. `user_can_access_repo` took no
/// action at all, so all ~11 of its call sites — the ones serving artifact
/// bytes and the ones asking a genuine tenant question alike — got the same
/// any-grant answer, and nothing in the code said which was which. A test
/// pinned to the sites fixed in one PR would go green while the next new
/// content path re-opened the hole, exactly as #3399 found for the virtual
/// member walks.
///
/// Two mechanisms, deliberately layered:
///
/// 1. **The compiler.** [`RepoAccess`] is a REQUIRED parameter, so a new call
///    site cannot inherit the action-blind behaviour by omission. It has to
///    name a variant.
/// 2. **This module.** Naming [`RepoAccess::TenantOnly`] is still allowed —
///    four call sites legitimately want it — but it must be justified in the
///    source with a `TENANT-GATE-ONLY` marker, the same greppable-exemption
///    shape #3399 used for `UNFILTERED-ENFORCEMENT`. That keeps the judgement
///    in review rather than in a test allowlist that drifts.
///
/// The scan walks the source tree at test time rather than taking a fixed list
/// of files, so a call site added in a NEW module is covered without anyone
/// remembering to extend a constant. It needs no database and runs in the
/// offline lib suite.
#[cfg(test)]
mod action_gate_structural_tests {
    /// Bytes after a `.user_can_access_repo(` call in which its arguments — and
    /// so its `RepoAccess` variant — must appear. Comfortably spans the
    /// explanatory comment these call sites carry, while staying far short of
    /// the next unrelated call.
    const ARG_WINDOW: usize = 1400;

    /// Bytes BEFORE the call in which a `TENANT-GATE-ONLY` justification may
    /// appear. A marker inside the argument list itself also counts, since
    /// rustfmt puts the explanatory comment next to the variant it explains.
    const MARKER_WINDOW: usize = 1200;

    const CALL: &str = ".user_can_access_repo(";
    const MARKER: &str = "TENANT-GATE-ONLY";

    /// Largest index `<= at` that is a UTF-8 char boundary of `src` — the
    /// sources carry em dashes, and slicing mid-codepoint would panic.
    fn floor_boundary(src: &str, at: usize) -> usize {
        let mut at = at.min(src.len());
        while at > 0 && !src.is_char_boundary(at) {
            at -= 1;
        }
        at
    }

    /// Every `.rs` file under `backend/src`, read at test time.
    fn rust_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    if let Ok(src) = std::fs::read_to_string(&path) {
                        out.push((path.display().to_string(), src));
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        assert!(
            !out.is_empty(),
            "#3331: the source scan found no files; the structural gate would \
             pass vacuously"
        );
        out
    }

    /// A real call site, as opposed to a doc-comment or string mention of the
    /// name (this module's own text included).
    fn is_call_site(src: &str, at: usize) -> bool {
        let line_start = src[..at].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let line_prefix = &src[line_start..at];
        !line_prefix.trim_start().starts_with("//") && !line_prefix.contains('"')
    }

    /// The gate. Every call must name its action, and every `TenantOnly` must
    /// say why it is not asking for one.
    #[test]
    fn every_user_can_access_repo_call_names_its_action() {
        let mut unnamed: Vec<String> = Vec::new();
        let mut unjustified: Vec<String> = Vec::new();
        let mut seen = 0usize;

        for (name, src) in rust_sources() {
            let mut from = 0usize;
            while let Some(rel) = src[from..].find(CALL) {
                let at = from + rel;
                from = at + CALL.len();
                if !is_call_site(&src, at) {
                    continue;
                }
                seen += 1;

                let args_end = floor_boundary(&src, (at + ARG_WINDOW).min(src.len()));
                let args = &src[at..args_end];
                let line_no = src[..at].bytes().filter(|b| *b == b'\n').count() + 1;
                let site = format!("{name}:{line_no}");

                if !args.contains("RepoAccess::") {
                    unnamed.push(site);
                    continue;
                }
                if args.contains("RepoAccess::TenantOnly") {
                    let before = &src[floor_boundary(&src, at.saturating_sub(MARKER_WINDOW))..at];
                    if !before.contains(MARKER) && !args.contains(MARKER) {
                        unjustified.push(site);
                    }
                }
            }
        }

        assert!(
            seen > 0,
            "#3331: no `{CALL}` call sites found at all — the scan is broken, \
             not the code"
        );
        assert!(
            unnamed.is_empty(),
            "#3331: these repository access checks do not name a `RepoAccess` \
             variant: {unnamed:?}. Every call must state whether it is asking a \
             tenant question or a capability one."
        );
        assert!(
            unjustified.is_empty(),
            "#3331: these call sites take the ACTION-BLIND `RepoAccess::TenantOnly` \
             without saying why: {unjustified:?}. `TenantOnly` answers only \
             \"does this principal hold any grant\", so it must never front a path \
             that returns a private repository's contents — that is the bug this \
             gate exists to stop from coming back. If the tenant gate really is \
             what you want (a separate `require_repo_action` layers the capability \
             on top, or the question is genuinely tenant ownership), write a \
             `TENANT-GATE-ONLY` comment at the call saying so."
        );
    }

    /// The signature must keep the action parameter. Deleting it would restore
    /// the action-blind function and silently re-open every content path,
    /// while the gate above kept passing (it would find no `RepoAccess::` to
    /// demand, because there would be nothing to name).
    #[test]
    fn user_can_access_repo_still_requires_an_action_parameter() {
        let src = include_str!("repository_service.rs");
        let at = src
            .find("pub async fn user_can_access_repo")
            .expect("user_can_access_repo must exist");
        let sig_end = at + src[at..].find(") -> ").expect("signature must terminate");
        assert!(
            src[at..sig_end].contains("access: RepoAccess"),
            "#3331: `user_can_access_repo` must TAKE the intended action, so that a \
             caller who has not decided cannot compile. Making it optional (a \
             default, an `Option`, a second action-blind overload) is the exact \
             shape of the original defect."
        );
    }

    /// `require_visible` is the single widest blast radius in this fix: ~23
    /// production read surfaces fan out through it, and it holds the `read`
    /// action as a constant rather than threading an argument each of them
    /// would pass identically. That constant is therefore load-bearing, and is
    /// pinned here rather than left to review.
    #[test]
    fn the_rest_visibility_gate_asks_for_the_read_action() {
        let src = include_str!("../api/handlers/repositories.rs");
        let at = src
            .find("pub(crate) async fn require_visible")
            .expect("require_visible must exist");
        let body_end = at
            + src[at..]
                .find("\n}\n")
                .expect("require_visible must terminate");
        let body = &src[at..body_end];
        assert!(
            body.contains("RepoAccess::READ"),
            "#3331: `require_visible` fronts the REST read surfaces (repository \
             metadata, artifact listings and downloads, storage trees, security \
             and SBOM and curation reads). It must require the `read` ACTION, not \
             merely any grant, or a write-only principal reads private \
             repositories it is refused by the OCI /v2 and native-format gates."
        );
        assert!(
            !body.contains("RepoAccess::TenantOnly"),
            "#3331: `require_visible` must not fall back to the tenant gate"
        );
    }
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
            versioning_enabled: false,
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
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            project_id: None,
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
            versioning_enabled: false,
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
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            project_id: None,
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
            versioning_enabled: false,
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
            project_id: None,
            trusted_gpg_key: None,
            curation_allow_unverified: None,
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
            versioning_enabled: false,
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
            project_id: None,
            trusted_gpg_key: None,
            curation_allow_unverified: None,
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
            versioning_enabled: None,
            key: None,
            name: None,
            description: None,
            is_public: None,
            quota_bytes: None,
            upstream_url: None,
            promotion_only: None,
            project_id: None,
            trusted_gpg_key: None,
            curation_allow_unverified: None,
            curation_enabled: None,
            curation_default_action: None,
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
            versioning_enabled: None,
            key: None,
            name: Some("Updated Name".to_string()),
            description: Some("Updated Description".to_string()),
            is_public: Some(false),
            quota_bytes: Some(Some(2_000_000_000)),
            upstream_url: None,
            promotion_only: None,
            project_id: None,
            trusted_gpg_key: None,
            curation_allow_unverified: None,
            curation_enabled: None,
            curation_default_action: None,
        };
        assert_eq!(req.name, Some("Updated Name".to_string()));
        assert_eq!(req.is_public, Some(false));
        assert_eq!(req.quota_bytes, Some(Some(2_000_000_000)));
    }

    #[test]
    fn test_update_repository_request_clear_quota() {
        // quota_bytes: Some(None) should clear the quota
        let req = UpdateRepositoryRequest {
            versioning_enabled: None,
            key: None,
            name: None,
            description: None,
            is_public: None,
            quota_bytes: Some(None),
            upstream_url: None,
            promotion_only: None,
            project_id: None,
            trusted_gpg_key: None,
            curation_allow_unverified: None,
            curation_enabled: None,
            curation_default_action: None,
        };
        assert_eq!(req.quota_bytes, Some(None));
    }

    // -----------------------------------------------------------------------
    // validate_remote_upstream (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_remote_upstream_remote_without_url_fails() {
        let result =
            validate_remote_upstream(&RepositoryType::Remote, &None, &RepositoryFormat::Generic);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("upstream URL"));
    }

    #[test]
    fn test_validate_remote_upstream_remote_with_url_passes() {
        let result = validate_remote_upstream(
            &RepositoryType::Remote,
            &Some("https://upstream.example.com".to_string()),
            &RepositoryFormat::Generic,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remote_upstream_local_without_url_passes() {
        let result =
            validate_remote_upstream(&RepositoryType::Local, &None, &RepositoryFormat::Generic);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remote_upstream_virtual_without_url_passes() {
        let result =
            validate_remote_upstream(&RepositoryType::Virtual, &None, &RepositoryFormat::Generic);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remote_upstream_staging_without_url_passes() {
        let result =
            validate_remote_upstream(&RepositoryType::Staging, &None, &RepositoryFormat::Generic);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remote_upstream_rejects_ssrf_loopback() {
        let result = validate_remote_upstream(
            &RepositoryType::Remote,
            &Some("http://127.0.0.1:8080/".to_string()),
            &RepositoryFormat::Generic,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_remote_upstream_rejects_ssrf_metadata() {
        let result = validate_remote_upstream(
            &RepositoryType::Remote,
            &Some("http://169.254.169.254/latest/meta-data/".to_string()),
            &RepositoryFormat::Generic,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_remote_upstream_rejects_ssrf_on_local_type() {
        // Even non-Remote types with an upstream URL get SSRF validation
        let result = validate_remote_upstream(
            &RepositoryType::Local,
            &Some("http://10.0.0.1/internal".to_string()),
            &RepositoryFormat::Generic,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_rpm_remote_rejects_mirrorlist_and_metalink() {
        let ml = Some("https://mirrors.example.org/mirrorlist?repo=epel-9&arch=x86_64".to_string());
        let mt = Some("https://mirrors.example.org/metalink?repo=epel-9".to_string());
        let base = Some("https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/".to_string());
        assert!(
            validate_remote_upstream(&RepositoryType::Remote, &ml, &RepositoryFormat::Rpm).is_err()
        );
        assert!(
            validate_remote_upstream(&RepositoryType::Remote, &mt, &RepositoryFormat::Rpm).is_err()
        );
        assert!(
            validate_remote_upstream(&RepositoryType::Remote, &base, &RepositoryFormat::Rpm)
                .is_ok()
        );
    }

    #[test]
    fn test_debian_remote_rejects_flat_repo_and_mirrorlist() {
        let mirror = Some("mirror://mirrors.ubuntu.com/mirrors.txt".to_string());
        let mirrorlist = Some("https://mirrors.example.org/mirrorlist?dist=bookworm".to_string());
        let flat_index = Some(
            "http://apt.example.com/debian/dists/stable/main/binary-amd64/Packages".to_string(),
        );
        let flat_component = Some("http://apt.example.com/flat/ ./".to_string());
        // A well-formed archive root (apt expands `dists/<suite>/...` beneath).
        let base = Some("http://deb.debian.org/debian".to_string());
        let ubuntu = Some("http://archive.ubuntu.com/ubuntu".to_string());

        for bad in [&mirror, &mirrorlist, &flat_index, &flat_component] {
            assert!(
                validate_remote_upstream(&RepositoryType::Remote, bad, &RepositoryFormat::Debian)
                    .is_err(),
                "expected rejection for {:?}",
                bad
            );
        }
        assert!(validate_remote_upstream(
            &RepositoryType::Remote,
            &base,
            &RepositoryFormat::Debian
        )
        .is_ok());
        assert!(validate_remote_upstream(
            &RepositoryType::Remote,
            &ubuntu,
            &RepositoryFormat::Debian
        )
        .is_ok());
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

    #[test]
    fn test_format_handler_key_collapses_aliases_to_core_handler() {
        // Aliases gate on their core handler's key (see get_handler_for_format).
        let cases = [
            (RepositoryFormat::Docker, "oci"),
            (RepositoryFormat::Podman, "oci"),
            (RepositoryFormat::Oras, "oci"),
            (RepositoryFormat::WasmOci, "oci"),
            (RepositoryFormat::HelmOci, "oci"),
            (RepositoryFormat::Gradle, "maven"),
            (RepositoryFormat::Yarn, "npm"),
            (RepositoryFormat::Bower, "npm"),
            (RepositoryFormat::Pnpm, "npm"),
            (RepositoryFormat::Poetry, "pypi"),
            (RepositoryFormat::Conda, "pypi"),
            (RepositoryFormat::Chocolatey, "nuget"),
            (RepositoryFormat::Powershell, "nuget"),
            (RepositoryFormat::Opentofu, "terraform"),
            (RepositoryFormat::Lxc, "incus"),
            // 1:1 formats gate on their own key.
            (RepositoryFormat::Maven, "maven"),
            (RepositoryFormat::Npm, "npm"),
            (RepositoryFormat::Pypi, "pypi"),
            (RepositoryFormat::Generic, "generic"),
        ];
        for (f, expected) in cases {
            assert_eq!(format_handler_key(&f), expected, "{:?}", f);
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
    // quota_allows (pure admission decision behind check_quota)
    //
    // Covers the two reported quota defects:
    //   1. quota_bytes = 0 (and NULL) must mean UNLIMITED, not a literal
    //      zero-byte hard cap that 507s every write.
    //   2. A repo without a finite quota must never be falsely capped, while a
    //      repo WITH a finite quota is still correctly enforced (over -> reject,
    //      at/under -> allow), and usage that frees up (post-delete) is admitted
    //      again -- the accounting is the live SUM passed as `current_usage`.
    // -----------------------------------------------------------------------

    #[test]
    fn test_quota_allows_table() {
        // (label, quota_bytes, current_usage, additional_bytes, expect_allowed)
        let cases: &[(&str, Option<i64>, i64, i64, bool)] = &[
            // Unlimited: NULL quota always admits, regardless of size.
            ("null_quota_empty", None, 0, 0, true),
            ("null_quota_huge", None, 0, 1_000_000_000_000, true),
            ("null_quota_with_usage", None, 5_000, 9_999, true),
            // Unlimited: 0 sentinel must NOT behave as a zero-byte cap (bug #1).
            ("zero_quota_one_byte", Some(0), 0, 1, true),
            ("zero_quota_huge", Some(0), 123, 1_000_000_000, true),
            // Unlimited: negative sentinel is also treated as no limit.
            ("negative_quota", Some(-1), 0, 500, true),
            // Finite quota, fresh repo: under and exactly-at the limit pass.
            ("finite_under", Some(1_000), 0, 999, true),
            ("finite_exact", Some(1_000), 0, 1_000, true),
            // Finite quota: one byte over the limit is rejected (-> 507).
            ("finite_over_by_one", Some(1_000), 0, 1_001, false),
            // Finite quota with existing usage: enforced against the sum.
            ("finite_sum_at_limit", Some(1_000), 600, 400, true),
            ("finite_sum_over", Some(1_000), 600, 401, false),
            // Mid-session: a repo near its finite cap rejects the next write
            // (the genuine, intended QUOTA_EXCEEDED path) ...
            ("finite_full_rejects", Some(1_000), 1_000, 1, false),
            // ... and once usage is freed (e.g. after a delete shrinks the
            // live SUM), the same write is admitted again.
            ("finite_freed_admits", Some(1_000), 500, 500, true),
            // A zero-byte upload is always admitted, even at a finite limit.
            ("finite_zero_byte_upload", Some(1_000), 1_000, 0, true),
        ];

        for (label, quota, usage, additional, expected) in cases {
            assert_eq!(
                RepositoryService::quota_allows(*quota, *usage, *additional),
                *expected,
                "quota_allows mismatch for case `{label}` (quota={quota:?}, usage={usage}, add={additional})",
            );
        }
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
    fn test_visibility_user_clause_consults_permissions_and_groups() {
        // #1996: the User listing arm must also honour fine-grained
        // `permissions` grants (direct + group via user_group_members) while
        // still honouring the legacy `role_assignments` store.
        let uid = Uuid::new_v4();
        let (clause, _) = build_visibility_clause(&RepoVisibility::User(uid));
        assert!(clause.contains("permissions"), "must consult permissions");
        assert!(
            clause.contains("user_group_members"),
            "must resolve group grants via user_group_members"
        );
        assert!(
            clause.contains("role_assignments"),
            "must still honour the legacy role_assignments store"
        );
        // Scoped to repository targets only, failing closed on empty actions.
        assert!(clause.contains("p.target_type = 'repository'"));
        assert!(clause.contains("p.actions <> '{}'"));
        // No system-wide widening (would over-grant beyond the data plane).
        assert!(
            !clause.contains("'system'"),
            "visibility must not widen via system-scoped grants"
        );
        // The permissions predicate reuses the SAME user bind ($3); no new bind.
        assert!(clause.contains("p.principal_id = $3"));
    }

    #[test]
    fn test_permissions_grant_exists_has_repository_and_project_arms() {
        // #2472: the shared grant fragment must honour BOTH the direct
        // repository grant and the project-inherited grant, and nothing else.
        let sql = permissions_grant_exists("r.id", 3);
        assert!(
            sql.contains("p.target_type = 'repository' AND p.target_id = r.id"),
            "direct repository arm missing: {sql}"
        );
        assert!(
            sql.contains("p.target_type = 'project'"),
            "project inheritance arm missing: {sql}"
        );
        assert!(
            sql.contains("SELECT rp.project_id FROM repositories rp WHERE rp.id = r.id"),
            "project arm must resolve the repo's project_id via the rp alias: {sql}"
        );
        // Still fails closed on empty action lists and never widens to
        // system-scoped grants.
        assert!(sql.contains("p.actions <> '{}'"));
        assert!(!sql.contains("'system'"));
        // #2433: the direct-principal arm honours service accounts alongside
        // human users (both reference `users(id)` by the caller's own id),
        // while keeping the principal_id equality that prevents over-granting.
        assert!(
            sql.contains("p.principal_type IN ('user', 'service_account') AND p.principal_id = $3"),
            "direct-principal arm must accept service_account without relaxing the id match: {sql}"
        );
    }

    #[test]
    fn test_permissions_grant_exists_project_arm_uses_caller_repo_expr() {
        // The single-repo instantiation (`$2`, as used by
        // `user_can_access_repo`) must thread the same expression into the
        // project subquery so both arms describe the same repository.
        let sql = permissions_grant_exists("$2", 1);
        assert!(sql.contains("p.target_type = 'repository' AND p.target_id = $2"));
        assert!(sql.contains("SELECT rp.project_id FROM repositories rp WHERE rp.id = $2"));
        assert!(sql.contains("p.principal_id = $1"));
    }

    #[test]
    fn test_visibility_ids_public_all_do_not_consult_permissions() {
        // The repo-scoped token (`Ids`, #1783) and the `PublicOnly`/`All` arms
        // must stay strict — they must NOT pick up the permissions predicate.
        for v in [
            RepoVisibility::Ids(vec![Uuid::new_v4()]),
            RepoVisibility::Ids(vec![]),
            RepoVisibility::PublicOnly,
            RepoVisibility::All,
        ] {
            let (clause, _) = build_visibility_clause(&v);
            assert!(
                !clause.contains("permissions"),
                "{v:?} clause must not consult permissions: {clause}"
            );
            assert!(
                !clause.contains("user_group_members"),
                "{v:?} clause must not consult user_group_members: {clause}"
            );
        }
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

    // -----------------------------------------------------------------------
    // build_visibility_clause_for tests (alias + param-index aware variant)
    // -----------------------------------------------------------------------

    #[test]
    fn test_visibility_for_delegates_match_canonical_wrapper() {
        // The wrapper must be an exact ("repositories", 3) instantiation of the
        // variant, so the two agree for every arm.
        let uid = Uuid::new_v4();
        for v in [
            RepoVisibility::PublicOnly,
            RepoVisibility::All,
            RepoVisibility::User(uid),
            RepoVisibility::Ids(vec![Uuid::new_v4()]),
        ] {
            assert_eq!(
                build_visibility_clause(&v),
                build_visibility_clause_for(&v, "repositories", 3)
            );
        }
    }

    #[test]
    fn test_visibility_for_applies_alias_and_param_index() {
        let uid = Uuid::new_v4();
        let (clause, bind) = build_visibility_clause_for(&RepoVisibility::User(uid), "r", 6);
        // Alias is applied to the `.id` reference in the EXISTS subquery.
        assert!(clause.contains("ra.repository_id = r.id"));
        assert!(!clause.contains("repositories.id"));
        // Global assignments still honoured.
        assert!(clause.contains("ra.repository_id IS NULL"));
        // user_id bound at the requested positional index.
        assert!(clause.contains("ra.user_id = $6"));
        assert!(!clause.contains("$3"));
        // is_public stays unqualified (unique to repositories, unambiguous in a join).
        assert!(clause.contains("is_public = true"));
        assert_eq!(bind, VisibilityBind::User(Some(uid)));
    }

    #[test]
    fn test_visibility_for_public_only_and_all_ignore_alias_and_param() {
        let (clause, bind) = build_visibility_clause_for(&RepoVisibility::PublicOnly, "r", 6);
        assert_eq!(clause, "is_public = true");
        assert_eq!(bind, VisibilityBind::User(None));

        let (clause, bind) = build_visibility_clause_for(&RepoVisibility::All, "r", 6);
        assert_eq!(clause, "true");
        assert_eq!(bind, VisibilityBind::User(None));
    }

    #[test]
    fn test_visibility_for_ids_uses_alias_and_param_index() {
        let a = Uuid::new_v4();
        let (clause, bind) = build_visibility_clause_for(&RepoVisibility::Ids(vec![a]), "r", 2);
        assert_eq!(clause, "r.id = ANY($2)");
        assert_eq!(bind, VisibilityBind::Ids(vec![a]));
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
                versioning_enabled: false,
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
                project_id: None,
                trusted_gpg_key: None,
                curation_allow_unverified: None,
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

        /// A minimal valid ASCII-armored OpenPGP public key (ed25519), used to
        /// exercise the `trusted_gpg_key` create/update write path (#2568).
        const TEST_TRUSTED_PUB_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEalhDshYJKwYBBAHaRw8BAQdACzr46aD+QjHsSShzXFU7UyTBcfkr3V0B5QbC\nuHNwPaG0LEFLIFRlc3QgQ3VyYXRpb24gPGN1cmF0aW9uLXRlc3RAZXhhbXBsZS5j\nb20+iJMEExYKADsWIQR0avJEHEsDJgM2tIhMkudvlQGn6AUCalhDsgIbIwULCQgH\nAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRBMkudvlQGn6NbIAQD8FUordTijk/cv\nJXJF2Z4uU6pGzePlVjV66sMDeCrKeAD/buTRceKb+lc9GJaZTG0Nn0OpXuXFSzYY\njK6gqQU8eAO4OARqWEOyEgorBgEEAZdVAQUBAQdAR27xDvtQLrO+SDzbLNgOSuvF\nob14dCYHAudLwThyCBIDAQgHiHgEGBYKACAWIQR0avJEHEsDJgM2tIhMkudvlQGn\n6AUCalhDsgIbDAAKCRBMkudvlQGn6POzAP9NNEWgre36i/Ig+fphD4cwlcsvW6+v\ny54TTJUA3J4JyQEAgkLBwMrNA4LkzW2pYv8Cc/jK8GpSa1IAOPdsgPCcmQ0=\n=NyW4\n-----END PGP PUBLIC KEY BLOCK-----\n";

        /// #2568: `trusted_gpg_key` round-trips through create -> update-set ->
        /// update-clear. Create with no key leaves the column NULL; an update
        /// that supplies a key sets it; an update that clears it (`Some(None)`)
        /// nulls it again. The column is read directly (it is intentionally off
        /// the `Repository` model).
        #[tokio::test]
        async fn test_trusted_gpg_key_create_update_clear_roundtrip() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let service = RepositoryService::new(pool.clone());

            let read_key = |pool: PgPool, id: Uuid| async move {
                sqlx::query_scalar::<_, Option<String>>(
                    "SELECT trusted_gpg_key FROM repositories WHERE id = $1",
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read trusted_gpg_key")
            };

            // Create WITH a key -> persisted in the create tx.
            let mut req = make_create_req(&suffix, RepositoryFormat::Rpm);
            req.trusted_gpg_key = Some(TEST_TRUSTED_PUB_KEY.to_string());
            let repo = service.create(req).await.expect("create with gpg key");
            assert_eq!(
                read_key(pool.clone(), repo.id).await.as_deref(),
                Some(TEST_TRUSTED_PUB_KEY),
                "create should persist the trusted key"
            );

            // update-clear (Some(None)) -> column nulled.
            let clear_req = UpdateRepositoryRequest {
                key: None,
                name: None,
                description: None,
                is_public: None,
                quota_bytes: None,
                upstream_url: None,
                promotion_only: None,
                versioning_enabled: None,
                project_id: None,
                trusted_gpg_key: Some(None),
                curation_allow_unverified: None,
                curation_enabled: None,
                curation_default_action: None,
            };
            service.update(repo.id, clear_req).await.expect("clear gpg");
            assert!(
                read_key(pool.clone(), repo.id).await.is_none(),
                "Some(None) update should clear the key"
            );

            // update-set (Some(Some(key))) -> column set again.
            let set_req = UpdateRepositoryRequest {
                key: None,
                name: None,
                description: None,
                is_public: None,
                quota_bytes: None,
                upstream_url: None,
                promotion_only: None,
                versioning_enabled: None,
                project_id: None,
                trusted_gpg_key: Some(Some(TEST_TRUSTED_PUB_KEY.to_string())),
                curation_allow_unverified: None,
                curation_enabled: None,
                curation_default_action: None,
            };
            service.update(repo.id, set_req).await.expect("set gpg");
            assert_eq!(
                read_key(pool.clone(), repo.id).await.as_deref(),
                Some(TEST_TRUSTED_PUB_KEY),
                "Some(Some(key)) update should set the key"
            );

            // update with trusted_gpg_key: None -> column left unchanged.
            let noop_req = UpdateRepositoryRequest {
                key: None,
                name: Some("renamed".to_string()),
                description: None,
                is_public: None,
                quota_bytes: None,
                upstream_url: None,
                promotion_only: None,
                versioning_enabled: None,
                project_id: None,
                trusted_gpg_key: None,
                curation_allow_unverified: None,
                curation_enabled: None,
                curation_default_action: None,
            };
            service.update(repo.id, noop_req).await.expect("noop gpg");
            assert_eq!(
                read_key(pool.clone(), repo.id).await.as_deref(),
                Some(TEST_TRUSTED_PUB_KEY),
                "omitted field must leave the stored key unchanged"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// #2569: the `curation_allow_unverified` opt-in round-trips through
        /// create and update, and the column defaults false (fail-closed) when
        /// the field is omitted. The column is read directly (it is off the
        /// `Repository` model, like `trusted_gpg_key`) — the keyless sync path
        /// consults it to decide whether to refuse or ingest unverified upstream.
        #[tokio::test]
        async fn test_curation_allow_unverified_create_update_roundtrip() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let service = RepositoryService::new(pool.clone());

            let read_flag = |pool: PgPool, id: Uuid| async move {
                sqlx::query_scalar::<_, bool>(
                    "SELECT curation_allow_unverified FROM repositories WHERE id = $1",
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read curation_allow_unverified")
            };

            // Create with the field omitted -> column defaults false (fail-closed).
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Rpm))
                .await
                .expect("create rpm curation repo");
            assert!(
                !read_flag(pool.clone(), repo.id).await,
                "default must be fail-closed (curation_allow_unverified = false)"
            );

            // A builder for an all-omitted update carrying only the opt-in flag,
            // so each call gets its own owned request (update takes ownership).
            let allow_update = |flag: Option<bool>| UpdateRepositoryRequest {
                key: None,
                name: None,
                description: None,
                is_public: None,
                quota_bytes: None,
                upstream_url: None,
                promotion_only: None,
                versioning_enabled: None,
                project_id: None,
                trusted_gpg_key: None,
                curation_allow_unverified: flag,
                curation_enabled: None,
                curation_default_action: None,
            };

            // Update -> Some(true) opts into unverified ingest.
            service
                .update(repo.id, allow_update(Some(true)))
                .await
                .expect("set allow_unverified");
            assert!(
                read_flag(pool.clone(), repo.id).await,
                "Some(true) update must set the opt-in"
            );

            // Update -> Some(false) restores the fail-closed default.
            service
                .update(repo.id, allow_update(Some(false)))
                .await
                .expect("clear allow_unverified");
            assert!(
                !read_flag(pool.clone(), repo.id).await,
                "Some(false) update must restore fail-closed default"
            );

            // Update with the field omitted (None) -> unchanged. First set it
            // true, then a no-op update (opt-in omitted), and assert it stays true.
            service
                .update(repo.id, allow_update(Some(true)))
                .await
                .expect("re-set allow_unverified");
            service
                .update(repo.id, allow_update(None))
                .await
                .expect("noop update");
            assert!(
                read_flag(pool.clone(), repo.id).await,
                "omitted field must leave the opt-in unchanged"
            );

            // Create with Some(true) -> persisted in the create tx.
            let suffix2 = format!("{}", uuid::Uuid::new_v4().simple());
            let mut create_true = make_create_req(&suffix2, RepositoryFormat::Rpm);
            create_true.curation_allow_unverified = Some(true);
            let repo2 = service
                .create(create_true)
                .await
                .expect("create with opt-in");
            assert!(
                read_flag(pool.clone(), repo2.id).await,
                "create with Some(true) must persist the opt-in"
            );

            cleanup_repo(&pool, repo.id).await;
            cleanup_repo(&pool, repo2.id).await;
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

            let creator_roles: Vec<String> = sqlx::query_scalar(
                "SELECT r.name::text FROM role_assignments ra \
                 JOIN roles r ON r.id = ra.role_id \
                 WHERE ra.user_id = $1 AND ra.repository_id = $2 \
                   AND r.name IN ('developer', 'repository-owner') \
                 ORDER BY r.name",
            )
            .bind(owner_id)
            .bind(repo.id)
            .fetch_all(&pool)
            .await
            .expect("creator role lookup");
            assert_eq!(
                creator_roles,
                vec!["developer", "repository-owner"],
                "creator must receive owner and retain developer during staged rollout"
            );

            // Owner (auto-granted repository-owner role) -> allowed.
            assert!(
                service
                    .user_can_access_repo(
                        repo.id,
                        owner_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("owner access check"),
                "owner should retain access via auto-grant"
            );

            // Different user with no grant -> denied (this is the bug being fixed).
            assert!(
                !service
                    .user_can_access_repo(
                        repo.id,
                        other_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
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
                    .user_can_access_repo(
                        repo.id,
                        other_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
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

        /// #1996: `user_can_access_repo` must also honour a fine-grained
        /// `permissions` grant (the table written by `POST /api/v1/permissions`),
        /// not only `role_assignments`. A non-empty user-scoped repository grant
        /// restores access; a row with empty `actions '{}'` must fail closed.
        #[tokio::test]
        async fn test_user_can_access_repo_permissions_grant_direct() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());

            let (owner_id, _) = tdh::create_user(&pool).await;
            let (grantee_id, _) = tdh::create_user(&pool).await;

            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let mut req = make_create_req(&suffix, RepositoryFormat::Generic);
            req.created_by = Some(owner_id);
            let repo = service.create(req).await.expect("create private repo");

            // No grant of any kind -> denied.
            assert!(
                !service
                    .user_can_access_repo(
                        repo.id,
                        grantee_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("no-grant access check"),
                "ungranted user must NOT access a private repo"
            );

            // A permissions row with EMPTY actions must fail closed.
            sqlx::query(
                "INSERT INTO permissions \
                   (principal_type, principal_id, target_type, target_id, actions) \
                 VALUES ('user', $1, 'repository', $2, '{}')",
            )
            .bind(grantee_id)
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("insert empty-actions permission");
            assert!(
                !service
                    .user_can_access_repo(
                        repo.id,
                        grantee_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("empty-actions access check"),
                "empty-actions permission must not grant access"
            );

            // Populate the actions -> access via the permissions store.
            sqlx::query(
                "UPDATE permissions SET actions = ARRAY['read'] \
                 WHERE principal_type = 'user' AND principal_id = $1 \
                   AND target_type = 'repository' AND target_id = $2",
            )
            .bind(grantee_id)
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("populate permission actions");
            assert!(
                service
                    .user_can_access_repo(
                        repo.id,
                        grantee_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("permissions-grant access check"),
                "user with a non-empty permissions grant must have access"
            );

            cleanup_repo(&pool, repo.id).await;
            for uid in [owner_id, grantee_id] {
                let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(uid)
                    .execute(&pool)
                    .await;
            }
        }

        /// #2433: a service-account principal must be honoured exactly like a
        /// user principal. A grant written with `principal_type='service_account'`
        /// naming the SA's `users.id` restores access on the granted repo; the
        /// same SA stays denied with no grant, with empty `actions '{}'`, and on
        /// a *different* private repo it holds no grant for (per-repo scoping).
        #[tokio::test]
        async fn test_user_can_access_repo_service_account_grant_honored() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());

            let (owner_id, _) = tdh::create_user(&pool).await;

            // A service-account-typed principal (own `users` row, SA flag set).
            let sa_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO users \
                   (id, username, email, password_hash, auth_provider, is_admin, \
                    is_active, is_service_account) \
                 VALUES ($1, $2, $3, 'unused', 'local', false, true, true)",
            )
            .bind(sa_id)
            .bind(format!("sa-{}", sa_id.simple()))
            .bind(format!("sa-{}@test.local", sa_id.simple()))
            .execute(&pool)
            .await
            .expect("create service account");

            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let mut req_a = make_create_req(&format!("{suffix}a"), RepositoryFormat::Generic);
            req_a.created_by = Some(owner_id);
            let repo_a = service.create(req_a).await.expect("create private repo A");
            let mut req_b = make_create_req(&format!("{suffix}b"), RepositoryFormat::Generic);
            req_b.created_by = Some(owner_id);
            let repo_b = service.create(req_b).await.expect("create private repo B");

            // Case: SA WITHOUT a grant -> denied.
            assert!(
                !service
                    .user_can_access_repo(
                        repo_a.id,
                        sa_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("no-grant SA access check"),
                "service account without a grant must NOT access a private repo"
            );

            // Case: SA grant with EMPTY actions -> fail closed (denied).
            sqlx::query(
                "INSERT INTO permissions \
                   (principal_type, principal_id, target_type, target_id, actions) \
                 VALUES ('service_account', $1, 'repository', $2, '{}')",
            )
            .bind(sa_id)
            .bind(repo_a.id)
            .execute(&pool)
            .await
            .expect("insert empty-actions SA permission");
            assert!(
                !service
                    .user_can_access_repo(
                        repo_a.id,
                        sa_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("empty-actions SA access check"),
                "empty-actions service-account grant must fail closed"
            );

            // Case: SA WITH an explicit non-empty grant on repo A -> allowed.
            sqlx::query(
                "UPDATE permissions SET actions = ARRAY['read'] \
                 WHERE principal_type = 'service_account' AND principal_id = $1 \
                   AND target_type = 'repository' AND target_id = $2",
            )
            .bind(sa_id)
            .bind(repo_a.id)
            .execute(&pool)
            .await
            .expect("populate SA permission actions");
            assert!(
                service
                    .user_can_access_repo(
                        repo_a.id,
                        sa_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("granted SA access check"),
                "service account WITH an explicit grant must access the repo"
            );

            // Case: per-repo scoping — SA granted on A is still denied on B.
            assert!(
                !service
                    .user_can_access_repo(
                        repo_b.id,
                        sa_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("other-repo SA access check"),
                "SA granted on repo A must NOT reach a different private repo B"
            );

            // The grant also surfaces the repo in the SA's own listing, and
            // never leaks the un-granted repo B.
            let search = Some(format!("acs-repo-{suffix}"));
            let (repos, total) = service
                .list(
                    0,
                    50,
                    None,
                    None,
                    RepoVisibility::User(sa_id),
                    search.as_deref(),
                    None,
                )
                .await
                .expect("SA list");
            assert_eq!(total, 1, "SA should see only the granted private repo");
            assert_eq!(repos.len(), 1);
            assert_eq!(repos[0].id, repo_a.id);
            assert!(
                !repos.iter().any(|r| r.id == repo_b.id),
                "un-granted private repo must not leak into the SA's listing"
            );

            cleanup_repo(&pool, repo_a.id).await;
            cleanup_repo(&pool, repo_b.id).await;
            for uid in [owner_id, sa_id] {
                let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(uid)
                    .execute(&pool)
                    .await;
            }
        }

        /// #1996 (group path): a `permissions` grant to a GROUP the user belongs
        /// to (resolved via `user_group_members`) must also grant access — and
        /// removing the membership revokes it.
        #[tokio::test]
        async fn test_user_can_access_repo_permissions_grant_via_group() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());

            let (owner_id, _) = tdh::create_user(&pool).await;
            let (member_id, _) = tdh::create_user(&pool).await;

            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let mut req = make_create_req(&suffix, RepositoryFormat::Generic);
            req.created_by = Some(owner_id);
            let repo = service.create(req).await.expect("create private repo");

            let group_id: Uuid =
                sqlx::query_scalar("INSERT INTO groups (name) VALUES ($1) RETURNING id")
                    .bind(format!("grp-{suffix}"))
                    .fetch_one(&pool)
                    .await
                    .expect("create group");

            // Group holds the grant, but the user is not yet a member -> denied.
            sqlx::query(
                "INSERT INTO permissions \
                   (principal_type, principal_id, target_type, target_id, actions) \
                 VALUES ('group', $1, 'repository', $2, ARRAY['read'])",
            )
            .bind(group_id)
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("insert group permission");
            assert!(
                !service
                    .user_can_access_repo(
                        repo.id,
                        member_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("non-member access check"),
                "non-member must NOT inherit a group grant"
            );

            // Add the user to the group -> access via the group grant.
            sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
                .bind(member_id)
                .bind(group_id)
                .execute(&pool)
                .await
                .expect("add group member");
            assert!(
                service
                    .user_can_access_repo(
                        repo.id,
                        member_id,
                        // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                        // this test was written to assert; the read-action narrowing has its own tests.
                        crate::services::repository_service::RepoAccess::TenantOnly
                    )
                    .await
                    .expect("group-member access check"),
                "group member must inherit the group's repository grant"
            );

            cleanup_repo(&pool, repo.id).await;
            let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
                .bind(group_id)
                .execute(&pool)
                .await;
            for uid in [owner_id, member_id] {
                let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(uid)
                    .execute(&pool)
                    .await;
            }
        }

        /// #3331: the defect itself. A principal whose ONLY entitlement on a
        /// private repository is `{write}` holds a grant, so the tenant
        /// predicate admits them — and before this fix that was the entire
        /// gate in front of the REST content paths, so they were served the
        /// repository's artifact bytes while the equivalent OCI `/v2` read of
        /// the same repository correctly refused.
        ///
        /// Asserted as a matrix on ONE grant so the two halves cannot be
        /// confused: the same `{write}` rule must be admitted by `TenantOnly`
        /// and refused by `READ`. A regression that reverts the action gate
        /// fails the second assertion; a regression that over-narrows the
        /// tenant gate (and would collaterally break the write/delete
        /// handlers, which layer their own action check on top of it) fails
        /// the first.
        #[tokio::test]
        async fn user_can_access_repo_read_refuses_a_write_only_grant() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());

            let (owner_id, _) = tdh::create_user(&pool).await;
            let (writer_id, _) = tdh::create_user(&pool).await;

            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let mut req = make_create_req(&suffix, RepositoryFormat::Generic);
            req.created_by = Some(owner_id);
            let repo = service.create(req).await.expect("create private repo");
            assert!(!repo.is_public, "the gate under test is the PRIVATE one");

            // A fine-grained rule carrying `write` and nothing else.
            tdh::grant_repo_actions(&pool, repo.id, writer_id, &["write"]).await;

            assert!(
                service
                    .user_can_access_repo(
                        repo.id,
                        writer_id,
                        // TENANT-GATE-ONLY (#3331): asserting the tenant half is
                        // UNCHANGED is half the point of this test.
                        RepoAccess::TenantOnly
                    )
                    .await
                    .expect("tenant gate query"),
                "the tenant gate must still admit a write-only grantee: the REST \
                 write/delete handlers depend on it and layer their own action check"
            );
            assert!(
                !service
                    .user_can_access_repo(repo.id, writer_id, RepoAccess::READ)
                    .await
                    .expect("read gate query"),
                "#3331: a {{write}}-only grant must NOT satisfy the read action, or \
                 the REST content paths hand this principal a private repository's \
                 bytes that a direct /v2 read of the same repository refuses"
            );

            // A second principal on the SAME repository, granted `read`, IS
            // admitted — so the gate narrows by ACTION and not by accident.
            // (A distinct principal rather than a re-grant: `permissions` is
            // unique per (principal, target), so the write-only rule above
            // cannot be added to without replacing it.)
            let (reader_id, _) = tdh::create_user(&pool).await;
            tdh::grant_repo_actions(&pool, repo.id, reader_id, &["read"]).await;
            assert!(
                service
                    .user_can_access_repo(repo.id, reader_id, RepoAccess::READ)
                    .await
                    .expect("read gate query for read grant"),
                "a grant carrying `read` must pass the read gate"
            );

            tdh::cleanup(&pool, repo.id, owner_id).await;
            for uid in [writer_id, reader_id] {
                let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(uid)
                    .execute(&pool)
                    .await;
            }
        }

        /// #3331: a principal holding NO grant at all is refused by both forms,
        /// and the read form costs no extra round trip to say so (the tenant
        /// half short-circuits). The negative case matters because the action
        /// gate is ANDed on top: an implementation that consulted only
        /// `check_repository_action` would WIDEN access for a principal whose
        /// role carries `read` globally but who holds nothing on this
        /// repository.
        #[tokio::test]
        async fn user_can_access_repo_read_still_refuses_a_principal_with_no_grant() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());

            let (owner_id, _) = tdh::create_user(&pool).await;
            let (stranger_id, _) = tdh::create_user(&pool).await;

            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let mut req = make_create_req(&suffix, RepositoryFormat::Generic);
            req.created_by = Some(owner_id);
            let repo = service.create(req).await.expect("create private repo");

            for access in [RepoAccess::TenantOnly, RepoAccess::READ] {
                assert!(
                    !service
                        .user_can_access_repo(repo.id, stranger_id, access)
                        .await
                        .expect("gate query"),
                    "a principal with no grant must be refused under {access:?}"
                );
            }

            // The repository owner, whose `repository-owner` role carries
            // `read`, still passes — the fix must not lock owners out.
            assert!(
                service
                    .user_can_access_repo(repo.id, owner_id, RepoAccess::READ)
                    .await
                    .expect("owner read gate query"),
                "the auto-granted repository owner must keep read access"
            );

            tdh::cleanup(&pool, repo.id, owner_id).await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(stranger_id)
                .execute(&pool)
                .await;
        }

        /// #1996: `list(RepoVisibility::User(..))` must return a private repo the
        /// user can reach ONLY through a `permissions` grant (no role_assignment),
        /// and must still exclude a private repo they hold no grant for.
        #[tokio::test]
        async fn test_list_user_visibility_includes_permissions_grant() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());

            let (owner_id, _) = tdh::create_user(&pool).await;
            let (grantee_id, _) = tdh::create_user(&pool).await;

            let tag = format!("{}", uuid::Uuid::new_v4().simple());
            // repo_granted: grantee gets a permissions grant only.
            let mut req_g = make_create_req(&format!("{tag}g"), RepositoryFormat::Pypi);
            req_g.created_by = Some(owner_id);
            let repo_granted = service.create(req_g).await.expect("create granted repo");
            // repo_other: grantee has no grant at all.
            let mut req_o = make_create_req(&format!("{tag}o"), RepositoryFormat::Npm);
            req_o.created_by = Some(owner_id);
            let repo_other = service.create(req_o).await.expect("create other repo");

            sqlx::query(
                "INSERT INTO permissions \
                   (principal_type, principal_id, target_type, target_id, actions) \
                 VALUES ('user', $1, 'repository', $2, ARRAY['read'])",
            )
            .bind(grantee_id)
            .bind(repo_granted.id)
            .execute(&pool)
            .await
            .expect("insert permissions grant");

            let search = Some(format!("acs-repo-{tag}"));
            let (repos, total) = service
                .list(
                    0,
                    50,
                    None,
                    None,
                    RepoVisibility::User(grantee_id),
                    search.as_deref(),
                    None,
                )
                .await
                .expect("grantee list");

            assert_eq!(total, 1, "grantee should see only the granted private repo");
            assert_eq!(repos.len(), 1);
            assert_eq!(repos[0].id, repo_granted.id);
            assert!(
                !repos.iter().any(|r| r.id == repo_other.id),
                "ungranted private repo must not leak into the listing"
            );

            cleanup_repo(&pool, repo_granted.id).await;
            cleanup_repo(&pool, repo_other.id).await;
            for uid in [owner_id, grantee_id] {
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
                    None,
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
                    None,
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
                    None,
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

        // ---------------------------------------------------------------
        // get_storage_usage (#2625): the live SUM must include `oci_blobs`
        // ---------------------------------------------------------------

        async fn insert_artifact(pool: &PgPool, repo: Uuid, path: &str, key: &str, size: i64) {
            sqlx::query(
                "INSERT INTO artifacts \
                   (id, repository_id, path, name, size_bytes, checksum_sha256, \
                    content_type, storage_key, is_deleted) \
                 VALUES ($1, $2, $3, $3, $4, repeat('a', 64), \
                         'application/octet-stream', $5, false)",
            )
            .bind(Uuid::new_v4())
            .bind(repo)
            .bind(path)
            .bind(size)
            .bind(key)
            .execute(pool)
            .await
            .expect("insert artifact row");
        }

        async fn insert_oci_blob(pool: &PgPool, repo: Uuid, digest: &str, size: i64) {
            sqlx::query(
                "INSERT INTO oci_blobs (id, repository_id, digest, size_bytes, storage_key) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(Uuid::new_v4())
            .bind(repo)
            .bind(digest)
            .bind(size)
            .bind(format!("oci-blobs/{digest}"))
            .execute(pool)
            .await
            .expect("insert oci_blobs row");
        }

        async fn insert_proxy_cache(pool: &PgPool, repo: Uuid, path: &str, size: i64) {
            sqlx::query(
                "INSERT INTO proxy_cache_artifacts \
                   (id, repository_id, path, storage_key, metadata_key, size_bytes) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(Uuid::new_v4())
            .bind(repo)
            .bind(path)
            .bind(format!("proxy-cache/{repo}/{path}/__content__"))
            .bind(format!("proxy-cache/{repo}/{path}/__cache_meta__.json"))
            .bind(size)
            .execute(pool)
            .await
            .expect("insert proxy cache row");
        }

        /// Regression for the "3.42 MB docker repo" display bug (#2625): OCI
        /// layer/config blobs live in `oci_blobs`, not `artifacts` (only
        /// manifests land there), so the live usage SUM behind
        /// `storage_used_bytes` must include them. On unfixed code this
        /// returns 700 (manifest only).
        #[tokio::test]
        async fn test_get_storage_usage_counts_oci_blobs() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Docker))
                .await
                .expect("create repo");

            // Manifest as an `artifacts` row + two layers in `oci_blobs`.
            insert_artifact(
                &pool,
                repo.id,
                "img/manifests/1.0",
                "oci-manifests/sha256:aa",
                700,
            )
            .await;
            let d1 = format!("sha256:{}", Uuid::new_v4().simple());
            let d2 = format!("sha256:{}", Uuid::new_v4().simple());
            insert_oci_blob(&pool, repo.id, &d1, 500_000).await;
            insert_oci_blob(&pool, repo.id, &d2, 250_000).await;

            let usage = service
                .get_storage_usage(repo.id)
                .await
                .expect("storage usage");
            assert_eq!(usage, 750_700, "manifest (700) + layers (500k + 250k)");

            cleanup_repo(&pool, repo.id).await;
        }

        /// Intended semantics pin: `storage_used_bytes` is a per-repo
        /// *logical* figure. A blob cross-repo-mounted into two repos (same
        /// digest, one `oci_blobs` row per repo) counts in EACH repo's total
        /// — it is never globally deduped here. Physical-footprint dedup is
        /// the stats refresher's job (`DedupScope`), not this SUM's.
        #[tokio::test]
        async fn test_get_storage_usage_counts_shared_blob_in_each_repo() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo_a = service
                .create(make_create_req(
                    &format!("{suffix}a"),
                    RepositoryFormat::Docker,
                ))
                .await
                .expect("create repo a");
            let repo_b = service
                .create(make_create_req(
                    &format!("{suffix}b"),
                    RepositoryFormat::Docker,
                ))
                .await
                .expect("create repo b");

            let shared = format!("sha256:{}", Uuid::new_v4().simple());
            insert_oci_blob(&pool, repo_a.id, &shared, 40_000).await;
            insert_oci_blob(&pool, repo_b.id, &shared, 40_000).await;
            // Distinct second blob in A so its total discriminates from B's.
            let only_a = format!("sha256:{}", Uuid::new_v4().simple());
            insert_oci_blob(&pool, repo_a.id, &only_a, 5_000).await;

            let usage_a = service.get_storage_usage(repo_a.id).await.expect("usage a");
            let usage_b = service.get_storage_usage(repo_b.id).await.expect("usage b");
            assert_eq!(usage_a, 45_000, "repo A: shared blob + its own blob");
            assert_eq!(usage_b, 40_000, "repo B: shared blob counts here too");

            cleanup_repo(&pool, repo_a.id).await;
            cleanup_repo(&pool, repo_b.id).await;
        }

        /// Non-OCI repos have no `oci_blobs` rows; the added UNION branch must
        /// not disturb their totals. Also re-pins the #2218 semantics the SUM
        /// already had: proxy catalog rows count, legacy `proxy-cache/%`
        /// leftovers in `artifacts` stay excluded.
        #[tokio::test]
        async fn test_get_storage_usage_without_oci_rows_unchanged() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");

            insert_artifact(
                &pool,
                repo.id,
                "a/1",
                &format!("cas/ee/ff/{}", Uuid::new_v4()),
                1_000,
            )
            .await;
            insert_proxy_cache(&pool, repo.id, "cached/pkg.tgz", 2_500).await;
            // Legacy backfilled leftover: must NOT be double counted (#2218).
            insert_artifact(
                &pool,
                repo.id,
                "cached/pkg.tgz",
                &format!("proxy-cache/{}/cached/pkg.tgz/__content__", repo.id),
                9_999,
            )
            .await;

            let usage = service
                .get_storage_usage(repo.id)
                .await
                .expect("storage usage");
            assert_eq!(usage, 3_500, "artifacts + proxy catalog only");

            cleanup_repo(&pool, repo.id).await;
        }

        /// Build a `create` request for a VIRTUAL repository of the given
        /// format (the shared `make_create_req` builds a Local repo).
        fn make_virtual_req(suffix: &str, format: RepositoryFormat) -> CreateRepositoryRequest {
            CreateRepositoryRequest {
                repo_type: RepositoryType::Virtual,
                ..make_create_req(suffix, format)
            }
        }

        /// #2785 defect A: a virtual repository's displayed storage total must
        /// equal the combined total of its member (child) repositories. The
        /// pre-fix per-repo figure is computed from the virtual's OWN rows,
        /// which are empty, so it reported 0 while the members held real data.
        #[tokio::test]
        async fn test_virtual_storage_usage_sums_members_2785() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());

            let virt = service
                .create(make_virtual_req(
                    &format!("{suffix}v"),
                    RepositoryFormat::Docker,
                ))
                .await
                .expect("create virtual");
            let m1 = service
                .create(make_create_req(
                    &format!("{suffix}m1"),
                    RepositoryFormat::Docker,
                ))
                .await
                .expect("create m1");
            let m2 = service
                .create(make_create_req(
                    &format!("{suffix}m2"),
                    RepositoryFormat::Docker,
                ))
                .await
                .expect("create m2");

            // m1: a manifest artifact (700) + a 500k layer. m2: a 250k layer.
            insert_artifact(
                &pool,
                m1.id,
                "img/manifests/1.0",
                "oci-manifests/sha256:aa",
                700,
            )
            .await;
            insert_oci_blob(
                &pool,
                m1.id,
                &format!("sha256:{}", Uuid::new_v4().simple()),
                500_000,
            )
            .await;
            insert_oci_blob(
                &pool,
                m2.id,
                &format!("sha256:{}", Uuid::new_v4().simple()),
                250_000,
            )
            .await;

            service
                .add_virtual_member(virt.id, m1.id, Some(1))
                .await
                .expect("add m1");
            service
                .add_virtual_member(virt.id, m2.id, Some(2))
                .await
                .expect("add m2");

            let m1_usage = service.get_storage_usage(m1.id).await.expect("m1 usage");
            let m2_usage = service.get_storage_usage(m2.id).await.expect("m2 usage");
            assert_eq!(m1_usage, 500_700);
            assert_eq!(m2_usage, 250_000);

            // Pre-fix behaviour the customer saw: the virtual owns no artifact
            // rows, so the plain per-repo figure is 0 despite the members
            // holding 750,700 bytes of resolvable content.
            assert_eq!(
                service.get_storage_usage(virt.id).await.expect("virt own"),
                0,
                "virtual repo owns no artifact/blob rows of its own"
            );

            // Fix: the combined figure equals the sum of the members, and the
            // display helper routes a virtual repo through that union.
            let combined = service
                .get_virtual_storage_usage(virt.id, &MemberVisibility::Unfiltered)
                .await
                .expect("virtual combined");
            assert_eq!(
                combined,
                m1_usage + m2_usage,
                "virtual total = sum of members"
            );
            assert_eq!(
                service
                    .get_display_storage_usage(&virt, &MemberVisibility::Unfiltered)
                    .await
                    .expect("display"),
                combined,
                "display helper unions members for a virtual repo"
            );
            // A non-virtual repo keeps its own per-repo figure via the helper.
            assert_eq!(
                service
                    .get_display_storage_usage(&m1, &MemberVisibility::Unfiltered)
                    .await
                    .expect("display m1"),
                m1_usage
            );

            cleanup_repo(&pool, virt.id).await;
            cleanup_repo(&pool, m1.id).await;
            cleanup_repo(&pool, m2.id).await;
        }

        /// #2785 defect A (union semantics): a leaf repository reachable through
        /// more than one path in a nested membership graph is counted ONCE, and
        /// nested virtual members contribute their own leaves.
        #[tokio::test]
        async fn test_virtual_storage_usage_dedups_diamond_2785() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());

            // leaf B holds 1000 bytes; A is a virtual containing B; V is a
            // virtual containing BOTH A and B (a diamond: V -> A -> B, V -> B).
            let leaf = service
                .create(make_create_req(
                    &format!("{suffix}b"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create leaf");
            let a = service
                .create(make_virtual_req(
                    &format!("{suffix}a"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create a");
            let v = service
                .create(make_virtual_req(
                    &format!("{suffix}v"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create v");

            insert_artifact(
                &pool,
                leaf.id,
                "pkg/1",
                &format!("cas/ab/cd/{}", Uuid::new_v4()),
                1_000,
            )
            .await;

            service
                .add_virtual_member(a.id, leaf.id, Some(1))
                .await
                .expect("a->b");
            service
                .add_virtual_member(v.id, a.id, Some(1))
                .await
                .expect("v->a");
            service
                .add_virtual_member(v.id, leaf.id, Some(2))
                .await
                .expect("v->b");

            // B counted once despite two reachable paths.
            assert_eq!(
                service
                    .get_virtual_storage_usage(v.id, &MemberVisibility::Unfiltered)
                    .await
                    .expect("v combined"),
                1_000,
                "leaf reachable via two paths counts once (union)"
            );

            cleanup_repo(&pool, v.id).await;
            cleanup_repo(&pool, a.id).await;
            cleanup_repo(&pool, leaf.id).await;
        }

        /// #3078: the batched ledger-backed virtual read
        /// (`get_virtual_storage_usage_batch`) must agree exactly with the
        /// per-repo live-SUM walk (`get_virtual_storage_usage`, the oracle)
        /// for every root: a diamond overlap is counted once, a nested virtual
        /// (depth 2) contributes its leaves, and two independent roots sharing
        /// a leaf each count it under their own root. The leaves are seeded by
        /// real source-table INSERTs so migration 182's triggers populate the
        /// ledger — the test exercises trigger↔read equivalence end-to-end.
        #[tokio::test]
        async fn test_virtual_storage_batch_matches_live_oracle_3078() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());

            // leaf1: 1_000 hosted + 2_500 proxy-cached. leaf2: 500_000 OCI.
            let leaf1 = service
                .create(make_create_req(
                    &format!("{suffix}l1"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create leaf1");
            let leaf2 = service
                .create(make_create_req(
                    &format!("{suffix}l2"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create leaf2");
            insert_artifact(
                &pool,
                leaf1.id,
                "p/1",
                &format!("cas/aa/{}", Uuid::new_v4()),
                1_000,
            )
            .await;
            insert_proxy_cache(&pool, leaf1.id, "cached/x.tgz", 2_500).await;
            insert_oci_blob(
                &pool,
                leaf2.id,
                &format!("sha256:{}", Uuid::new_v4().simple()),
                500_000,
            )
            .await;

            // Diamond: v -> a -> leaf1 and v -> leaf1 (leaf1 reachable twice
            // under v, and a is a nested virtual member at depth 2).
            let a = service
                .create(make_virtual_req(
                    &format!("{suffix}a"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create a");
            let v = service
                .create(make_virtual_req(
                    &format!("{suffix}v"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create v");
            // Independent root sharing leaf1 with the diamond, plus leaf2.
            let w = service
                .create(make_virtual_req(
                    &format!("{suffix}w"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create w");
            // No resolvable members: must be ABSENT from the batch result.
            let hollow = service
                .create(make_virtual_req(
                    &format!("{suffix}h"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create hollow");
            service
                .add_virtual_member(a.id, leaf1.id, Some(1))
                .await
                .expect("a->leaf1");
            service
                .add_virtual_member(v.id, a.id, Some(1))
                .await
                .expect("v->a");
            service
                .add_virtual_member(v.id, leaf1.id, Some(2))
                .await
                .expect("v->leaf1");
            service
                .add_virtual_member(w.id, leaf1.id, Some(1))
                .await
                .expect("w->leaf1");
            service
                .add_virtual_member(w.id, leaf2.id, Some(2))
                .await
                .expect("w->leaf2");

            let roots = [v.id, a.id, w.id, hollow.id];
            let batch = service
                .get_virtual_storage_usage_batch(&roots, &MemberVisibility::Unfiltered)
                .await
                .expect("batch read");
            for (label, root) in [("v", v.id), ("a", a.id), ("w", w.id)] {
                let oracle = service
                    .get_virtual_storage_usage(root, &MemberVisibility::Unfiltered)
                    .await
                    .expect("per-repo oracle");
                assert_eq!(
                    batch.get(&root).copied(),
                    Some(oracle),
                    "batched ledger read must equal the live-SUM oracle for {label}"
                );
            }
            assert_eq!(
                batch[&v.id], 3_500,
                "diamond: leaf1 reachable via two paths counts ONCE under v"
            );
            assert_eq!(
                batch[&w.id], 503_500,
                "independent roots each count a shared leaf under their own root"
            );
            assert!(
                !batch.contains_key(&hollow.id),
                "root with no resolvable members is absent (caller renders 0)"
            );
            assert!(
                service
                    .get_virtual_storage_usage_batch(&[], &MemberVisibility::Unfiltered)
                    .await
                    .expect("empty batch")
                    .is_empty(),
                "empty input short-circuits to an empty map"
            );

            for repo in [v, a, w, hollow, leaf1, leaf2] {
                cleanup_repo(&pool, repo.id).await;
            }
        }

        /// #3078: an A→B→A membership cycle (forced via direct INSERTs — the
        /// API's cycle guard refuses to create one) must terminate under the
        /// depth-bounded `UNION` recursion and count each reachable leaf once,
        /// with the batched ledger read agreeing with the per-repo live-SUM
        /// oracle for both roots.
        #[tokio::test]
        async fn test_virtual_storage_batch_cycle_terminates_3078() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());

            let leaf = service
                .create(make_create_req(
                    &format!("{suffix}cl"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create leaf");
            insert_artifact(
                &pool,
                leaf.id,
                "c/1",
                &format!("cas/cc/{}", Uuid::new_v4()),
                1_000,
            )
            .await;
            let a = service
                .create(make_virtual_req(
                    &format!("{suffix}ca"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create a");
            let b = service
                .create(make_virtual_req(
                    &format!("{suffix}cb"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create b");
            service
                .add_virtual_member(a.id, b.id, Some(1))
                .await
                .expect("a->b");
            service
                .add_virtual_member(b.id, leaf.id, Some(1))
                .await
                .expect("b->leaf");
            // Close the cycle behind the API's guard.
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, 9)",
            )
            .bind(b.id)
            .bind(a.id)
            .execute(&pool)
            .await
            .expect("force b->a cycle edge");

            let batch = service
                .get_virtual_storage_usage_batch(&[a.id, b.id], &MemberVisibility::Unfiltered)
                .await
                .expect("batch read under cycle");
            for (label, root) in [("a", a.id), ("b", b.id)] {
                let oracle = service
                    .get_virtual_storage_usage(root, &MemberVisibility::Unfiltered)
                    .await
                    .expect("per-repo oracle under cycle");
                assert_eq!(oracle, 1_000, "cycle walk reaches the leaf once ({label})");
                assert_eq!(
                    batch.get(&root).copied(),
                    Some(oracle),
                    "batched read equals the oracle under a cycle ({label})"
                );
            }

            for repo in [a, b, leaf] {
                cleanup_repo(&pool, repo.id).await;
            }
        }

        /// #2785 defect B: a virtual repository's member list is editable after
        /// creation — `set_virtual_members` adds, removes, and reorders members
        /// to match exactly the supplied set (the pre-fix PUT endpoint only
        /// reordered members that already existed).
        ///
        /// #2899 ratified the resulting full-set REPLACE semantics as the
        /// intended contract of `PUT /api/v1/repositories/{key}/members`.
        /// This test pins that contract: a call whose `desired` list omits a
        /// current member REMOVES that member. That is destructive on purpose,
        /// so the removal arm is asserted explicitly here (members A, B, C then
        /// a reconcile with only [A, B] must leave exactly A and B). If a
        /// future change reverts to a priorities-only update, or makes the
        /// reconcile merge rather than replace, this test must fail rather than
        /// be relaxed.
        #[tokio::test]
        async fn test_set_virtual_members_edits_after_create_2785() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());

            let virt = service
                .create(make_virtual_req(
                    &format!("{suffix}v"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create virtual");
            let a = service
                .create(make_create_req(
                    &format!("{suffix}a"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create a");
            let b = service
                .create(make_create_req(
                    &format!("{suffix}b"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create b");
            let c = service
                .create(make_create_req(
                    &format!("{suffix}c"),
                    RepositoryFormat::Generic,
                ))
                .await
                .expect("create c");

            // Created with member A only.
            service
                .add_virtual_member(virt.id, a.id, Some(1))
                .await
                .expect("add a");

            let ids = |repos: &[Repository]| repos.iter().map(|r| r.id).collect::<Vec<_>>();

            // Edit: add B and reprioritise A. get_virtual_members orders by priority.
            service
                .set_virtual_members(virt.id, &[(a.id, 5), (b.id, 2)])
                .await
                .expect("reconcile add");
            assert_eq!(
                ids(&service.get_virtual_members(virt.id).await.expect("list")),
                vec![b.id, a.id],
                "B (prio 2) then A (prio 5) after add + reprioritise"
            );

            // #2899 replace semantics, the destructive arm. Bring the set to
            // exactly {A, B, C}, then reconcile with a PARTIAL list [A, B].
            // C is absent from the request, so C must be removed: a caller
            // that sends a subset to reorder loses the members it omitted.
            service
                .set_virtual_members(virt.id, &[(a.id, 1), (b.id, 2), (c.id, 3)])
                .await
                .expect("reconcile to A, B, C");
            assert_eq!(
                ids(&service.get_virtual_members(virt.id).await.expect("list")),
                vec![a.id, b.id, c.id],
                "precondition: membership is exactly {{A, B, C}}"
            );

            service
                .set_virtual_members(virt.id, &[(a.id, 1), (b.id, 2)])
                .await
                .expect("reconcile to the partial list A, B");
            let after_partial = service.get_virtual_members(virt.id).await.expect("list");
            assert_eq!(
                ids(&after_partial),
                vec![a.id, b.id],
                "PUT with only [A, B] leaves exactly A and B: C, omitted from the \
                 request, is REMOVED (full-set replace, #2795/#2899)"
            );
            assert!(
                !ids(&after_partial).contains(&c.id),
                "C is gone, not merely reordered behind A and B"
            );

            // Edit: replace the whole set with C only (removes A and B).
            service
                .set_virtual_members(virt.id, &[(c.id, 1)])
                .await
                .expect("reconcile replace");
            assert_eq!(
                ids(&service.get_virtual_members(virt.id).await.expect("list")),
                vec![c.id],
                "membership replaced with exactly {{C}}"
            );

            // Edit: empty set clears every member.
            service
                .set_virtual_members(virt.id, &[])
                .await
                .expect("reconcile empty");
            assert!(
                service
                    .get_virtual_members(virt.id)
                    .await
                    .expect("list")
                    .is_empty(),
                "empty desired set clears membership"
            );

            cleanup_repo(&pool, virt.id).await;
            cleanup_repo(&pool, a.id).await;
            cleanup_repo(&pool, b.id).await;
            cleanup_repo(&pool, c.id).await;
        }

        /// PF-007 (#2523): after inserts across all three components the
        /// reconciled ledger must equal the authoritative 3-way sum, split into
        /// the correct per-component columns.
        #[tokio::test]
        async fn test_usage_ledger_reconcile_matches_union() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Docker))
                .await
                .expect("create repo");

            insert_artifact(
                &pool,
                repo.id,
                "a/1",
                &format!("cas/aa/bb/{}", Uuid::new_v4()),
                1_000,
            )
            .await;
            insert_proxy_cache(&pool, repo.id, "cached/pkg.tgz", 2_500).await;
            let digest = format!("sha256:{}", Uuid::new_v4().simple());
            insert_oci_blob(&pool, repo.id, &digest, 500_000).await;

            let total = service
                .reconcile_usage_ledger(repo.id)
                .await
                .expect("reconcile ledger");
            assert_eq!(total, 503_500, "hosted 1000 + proxy 2500 + oci 500000");

            let (hosted, proxy, oci): (i64, i64, i64) = sqlx::query_as::<_, (i64, i64, i64)>(
                "SELECT hosted_bytes, proxy_bytes, oci_bytes \
                 FROM repository_usage_ledger WHERE repository_id = $1",
            )
            .bind(repo.id)
            .fetch_one(&pool)
            .await
            .expect("ledger row");
            assert_eq!((hosted, proxy, oci), (1_000, 2_500, 500_000));

            // Ledger total agrees with the authoritative live sum.
            let union_usage = service
                .get_storage_usage(repo.id)
                .await
                .expect("storage usage");
            assert_eq!(hosted + proxy + oci, union_usage);

            cleanup_repo(&pool, repo.id).await;
        }

        /// PF-007 (#2523): the reconciler is the drift safety net — an injected
        /// bad ledger value is repaired back to the true sum and reported.
        #[tokio::test]
        async fn test_usage_ledger_reconciler_repairs_drift() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");

            insert_artifact(
                &pool,
                repo.id,
                "a/1",
                &format!("cas/cc/dd/{}", Uuid::new_v4()),
                7_000,
            )
            .await;
            service
                .reconcile_usage_ledger(repo.id)
                .await
                .expect("initial reconcile");

            // Inject drift: pretend a write path miscounted.
            sqlx::query(
                "UPDATE repository_usage_ledger SET hosted_bytes = 999_999 \
                 WHERE repository_id = $1",
            )
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("inject drift");

            let report = service
                .reconcile_all_usage_ledgers()
                .await
                .expect("reconcile all");
            assert!(
                report.repositories_repaired >= 1,
                "the drifted repo must be counted as repaired"
            );

            let hosted: i64 = sqlx::query_scalar::<_, i64>(
                "SELECT hosted_bytes FROM repository_usage_ledger WHERE repository_id = $1",
            )
            .bind(repo.id)
            .fetch_one(&pool)
            .await
            .expect("ledger row");
            assert_eq!(hosted, 7_000, "drift repaired back to the true sum");

            cleanup_repo(&pool, repo.id).await;
        }

        // =================================================================
        // #2992: trigger-maintained usage ledger (migration 183). Every
        // INSERT/UPDATE/DELETE on artifacts / proxy_cache_artifacts /
        // oci_blobs must charge or decrement the matching ledger component
        // inside the mutating statement's own transaction, with no
        // application code involved.
        // =================================================================

        async fn ledger_row(pool: &PgPool, repo: Uuid) -> (i64, i64, i64) {
            sqlx::query_as::<_, (i64, i64, i64)>(
                "SELECT hosted_bytes, proxy_bytes, oci_bytes \
                 FROM repository_usage_ledger WHERE repository_id = $1",
            )
            .bind(repo)
            .fetch_optional(pool)
            .await
            .expect("ledger query")
            .unwrap_or((0, 0, 0))
        }

        /// F1 (#2992): a raw `INSERT INTO artifacts` — the shape every format
        /// handler that bypasses the enforced admission path uses — must
        /// charge `hosted_bytes` immediately (trigger, same tx), and the next
        /// enforced admission must observe the real usage. On pre-183 code
        /// the ledger stays 0 here until the background reconciler runs.
        #[tokio::test]
        async fn test_usage_ledger_trigger_charges_bypassing_artifact_insert() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(CreateRepositoryRequest {
                    quota_bytes: Some(1_000),
                    ..make_create_req(&suffix, RepositoryFormat::Generic)
                })
                .await
                .expect("create repo");

            // No admission call, no reconcile: the trigger alone must charge.
            insert_artifact(
                &pool,
                repo.id,
                "bypass/a-1.0.jar",
                &format!("cas/aa/{}", Uuid::new_v4()),
                5_000,
            )
            .await;
            let (hosted, _, _) = ledger_row(&pool, repo.id).await;
            assert_eq!(
                hosted, 5_000,
                "bypassing insert must be charged by the trigger in its own tx"
            );

            // Enforced admission (unchanged behaviour) sees the usage and
            // rejects a further upload over the 1000-byte quota.
            let mut tx = pool.begin().await.expect("begin");
            let admission = service
                .check_quota_locked(&mut tx, repo.id, "p2", 300)
                .await
                .expect("admission");
            tx.rollback().await.expect("rollback");
            assert!(
                !admission.allowed,
                "admission after the bypassing insert must see 5000 used"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// F2 (#2992): deletes return the ledger to its prior value exactly.
        /// A soft-delete decrements once; a later hard DELETE of the already
        /// soft-deleted row must not decrement again; and the counter is
        /// floored at zero even against injected under-count drift.
        #[tokio::test]
        async fn test_usage_ledger_trigger_delete_returns_to_prior_value() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");

            insert_artifact(&pool, repo.id, "f2/a", "cas/f2/a", 600).await;
            assert_eq!(ledger_row(&pool, repo.id).await.0, 600);

            // Soft-delete (the dominant delete shape in the handlers).
            sqlx::query(
                "UPDATE artifacts SET is_deleted = true \
                 WHERE repository_id = $1 AND path = $2",
            )
            .bind(repo.id)
            .bind("f2/a")
            .execute(&pool)
            .await
            .expect("soft delete");
            assert_eq!(
                ledger_row(&pool, repo.id).await.0,
                0,
                "soft-delete must decrement exactly the charged bytes"
            );

            // Hard-deleting the already soft-deleted row contributes nothing
            // (old contribution is 0), so no double decrement.
            sqlx::query("DELETE FROM artifacts WHERE repository_id = $1 AND path = $2")
                .bind(repo.id)
                .bind("f2/a")
                .execute(&pool)
                .await
                .expect("hard delete of soft-deleted row");
            assert_eq!(ledger_row(&pool, repo.id).await.0, 0);

            // Hard delete of a live row decrements exactly its size.
            insert_artifact(&pool, repo.id, "f2/b", "cas/f2/b", 400).await;
            insert_artifact(&pool, repo.id, "f2/c", "cas/f2/c", 250).await;
            assert_eq!(ledger_row(&pool, repo.id).await.0, 650);
            sqlx::query("DELETE FROM artifacts WHERE repository_id = $1 AND path = $2")
                .bind(repo.id)
                .bind("f2/b")
                .execute(&pool)
                .await
                .expect("hard delete");
            assert_eq!(ledger_row(&pool, repo.id).await.0, 250);

            // Injected under-count drift: the floor keeps the counter at 0
            // rather than going negative (phantom free quota).
            sqlx::query(
                "UPDATE repository_usage_ledger SET hosted_bytes = 0 \
                 WHERE repository_id = $1",
            )
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("inject drift");
            sqlx::query("DELETE FROM artifacts WHERE repository_id = $1 AND path = $2")
                .bind(repo.id)
                .bind("f2/c")
                .execute(&pool)
                .await
                .expect("hard delete under drift");
            assert_eq!(
                ledger_row(&pool, repo.id).await.0,
                0,
                "decrement must clamp at zero, never negative"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// #2992: the charge lives in the mutation's own transaction, so a
        /// rolled-back INSERT leaves the ledger unchanged (inside the tx the
        /// charge is visible; after ROLLBACK it is gone).
        #[tokio::test]
        async fn test_usage_ledger_trigger_rollback_uncharges() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");

            insert_artifact(&pool, repo.id, "rb/base", "cas/rb/base", 300).await;
            assert_eq!(ledger_row(&pool, repo.id).await.0, 300);

            let mut tx = pool.begin().await.expect("begin");
            sqlx::query(
                "INSERT INTO artifacts \
                   (id, repository_id, path, name, size_bytes, checksum_sha256, \
                    content_type, storage_key, is_deleted) \
                 VALUES ($1, $2, 'rb/tx', 'rb/tx', 900, repeat('a', 64), \
                         'application/octet-stream', 'cas/rb/tx', false)",
            )
            .bind(Uuid::new_v4())
            .bind(repo.id)
            .execute(&mut *tx)
            .await
            .expect("insert inside tx");
            let in_tx: i64 = sqlx::query_scalar::<_, i64>(
                "SELECT hosted_bytes FROM repository_usage_ledger WHERE repository_id = $1",
            )
            .bind(repo.id)
            .fetch_one(&mut *tx)
            .await
            .expect("ledger inside tx");
            assert_eq!(in_tx, 1_200, "charge is visible inside the transaction");
            tx.rollback().await.expect("rollback");

            assert_eq!(
                ledger_row(&pool, repo.id).await.0,
                300,
                "ROLLBACK must un-charge the aborted insert"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// #2992: in-place overwrites (the `ON CONFLICT (repository_id, path)
        /// DO UPDATE` upsert shape) charge the net size delta, and a
        /// reclassification to a proxy-cache storage key removes the row from
        /// `hosted_bytes` entirely.
        #[tokio::test]
        async fn test_usage_ledger_trigger_update_charges_net_delta() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");

            insert_artifact(&pool, repo.id, "ow/a", "cas/ow/a", 900).await;
            sqlx::query(
                "UPDATE artifacts SET size_bytes = 1000 \
                 WHERE repository_id = $1 AND path = $2",
            )
            .bind(repo.id)
            .bind("ow/a")
            .execute(&pool)
            .await
            .expect("overwrite size");
            assert_eq!(
                ledger_row(&pool, repo.id).await.0,
                1_000,
                "overwrite must charge the +100 delta, not another +1000"
            );

            sqlx::query(
                "UPDATE artifacts SET storage_key = 'proxy-cache/x/__content__' \
                 WHERE repository_id = $1 AND path = $2",
            )
            .bind(repo.id)
            .bind("ow/a")
            .execute(&pool)
            .await
            .expect("reclassify to proxy-cache key");
            assert_eq!(
                ledger_row(&pool, repo.id).await.0,
                0,
                "proxy-cache-keyed rows must not count toward hosted_bytes"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// #2992: each source table feeds exactly its own ledger component;
        /// the OCI dedup re-push upsert (`DO UPDATE SET pending_delete_at =
        /// NULL`) is a zero-delta no-op; deletes drain each component back to
        /// zero.
        #[tokio::test]
        async fn test_usage_ledger_trigger_components_isolated() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Docker))
                .await
                .expect("create repo");

            insert_proxy_cache(&pool, repo.id, "cached/pkg.tgz", 2_500).await;
            assert_eq!(ledger_row(&pool, repo.id).await, (0, 2_500, 0));

            let digest = format!("sha256:{}", Uuid::new_v4().simple());
            insert_oci_blob(&pool, repo.id, &digest, 500_000).await;
            assert_eq!(ledger_row(&pool, repo.id).await, (0, 2_500, 500_000));

            // Dedup re-push of the same blob: fires only the
            // pending_delete_at column, so the trigger must not run and the
            // blob stays counted exactly once.
            sqlx::query(
                "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (repository_id, digest) DO UPDATE SET pending_delete_at = NULL",
            )
            .bind(repo.id)
            .bind(&digest)
            .bind(500_000_i64)
            .bind(format!("oci-blobs/{digest}"))
            .execute(&pool)
            .await
            .expect("dedup re-push upsert");
            assert_eq!(
                ledger_row(&pool, repo.id).await,
                (0, 2_500, 500_000),
                "dedup re-push must not double-count the blob"
            );

            // artifacts rows carrying a proxy-cache storage key contribute 0.
            insert_artifact(
                &pool,
                repo.id,
                "legacy/proxy-row",
                &format!("proxy-cache/{}/legacy/__content__", repo.id),
                700,
            )
            .await;
            assert_eq!(ledger_row(&pool, repo.id).await, (0, 2_500, 500_000));

            sqlx::query("DELETE FROM proxy_cache_artifacts WHERE repository_id = $1")
                .bind(repo.id)
                .execute(&pool)
                .await
                .expect("proxy invalidate");
            sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1")
                .bind(repo.id)
                .execute(&pool)
                .await
                .expect("oci purge");
            assert_eq!(
                ledger_row(&pool, repo.id).await,
                (0, 0, 0),
                "component deletes must drain exactly their own counters"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// #2992: migration 183's one-time true-up sets every ledger row to
        /// the authoritative live sums (DO UPDATE, unlike 171's DO NOTHING),
        /// erasing pre-trigger drift. Exercises the same statement scoped to
        /// one repository so concurrently running DB tests are untouched.
        #[tokio::test]
        async fn test_usage_ledger_migration_true_up_repairs_drift() {
            let _serial = tdh::usage_ledger_serial_lock().await;
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Docker))
                .await
                .expect("create repo");

            insert_artifact(&pool, repo.id, "tu/a", "cas/tu/a", 1_000).await;
            insert_proxy_cache(&pool, repo.id, "tu/p.tgz", 2_500).await;
            let digest = format!("sha256:{}", Uuid::new_v4().simple());
            insert_oci_blob(&pool, repo.id, &digest, 4_000).await;

            // Simulate pre-trigger drift the migration must erase.
            sqlx::query(
                "UPDATE repository_usage_ledger \
                 SET hosted_bytes = 1, proxy_bytes = 2, oci_bytes = 3 \
                 WHERE repository_id = $1",
            )
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("inject drift");

            // The 183 true-up statement, scoped to this repository.
            sqlx::query(
                "INSERT INTO repository_usage_ledger \
                     (repository_id, hosted_bytes, proxy_bytes, oci_bytes, updated_at) \
                 SELECT r.id, \
                     COALESCE((SELECT SUM(a.size_bytes) FROM artifacts a \
                                WHERE a.repository_id = r.id AND a.is_deleted = false \
                                  AND a.storage_key NOT LIKE 'proxy-cache/%'), 0), \
                     COALESCE((SELECT SUM(p.size_bytes) FROM proxy_cache_artifacts p \
                                WHERE p.repository_id = r.id), 0), \
                     COALESCE((SELECT SUM(o.size_bytes) FROM oci_blobs o \
                                WHERE o.repository_id = r.id), 0), \
                     now() \
                 FROM repositories r WHERE r.id = $1 \
                 ON CONFLICT (repository_id) DO UPDATE SET \
                     hosted_bytes = EXCLUDED.hosted_bytes, \
                     proxy_bytes  = EXCLUDED.proxy_bytes, \
                     oci_bytes    = EXCLUDED.oci_bytes, \
                     updated_at   = now()",
            )
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("true-up");

            assert_eq!(
                ledger_row(&pool, repo.id).await,
                (1_000, 2_500, 4_000),
                "true-up must restore the exact live sums"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        // -------------------------------------------------------------------
        // O(1) ledger-based quota admission (#2516 S2)
        // -------------------------------------------------------------------

        async fn set_quota(pool: &PgPool, repo: Uuid, quota: Option<i64>) {
            sqlx::query("UPDATE repositories SET quota_bytes = $1 WHERE id = $2")
                .bind(quota)
                .bind(repo)
                .execute(pool)
                .await
                .expect("set quota");
        }

        async fn ledger_hosted(pool: &PgPool, repo: Uuid) -> Option<i64> {
            sqlx::query_scalar::<_, i64>(
                "SELECT hosted_bytes FROM repository_usage_ledger WHERE repository_id = $1",
            )
            .bind(repo)
            .fetch_optional(pool)
            .await
            .expect("ledger query")
        }

        /// Mimic `finalize_upload`'s admission flow: check quota under the
        /// ledger-row lock and, when admitted, perform the artifact upsert in
        /// the SAME transaction and commit. A rejected admission drops the
        /// transaction (rollback), exactly like the production caller.
        async fn admit_and_insert(
            service: &RepositoryService,
            pool: &PgPool,
            repo: Uuid,
            path: &str,
            size: i64,
        ) -> bool {
            let mut tx = pool.begin().await.expect("begin");
            let adm = service
                .check_quota_locked(&mut tx, repo, path, size)
                .await
                .expect("admission");
            if adm.allowed {
                sqlx::query(
                    "INSERT INTO artifacts \
                       (repository_id, path, name, size_bytes, checksum_sha256, \
                        content_type, storage_key) \
                     VALUES ($1, $2, $2, $3, repeat('a', 64), \
                             'application/octet-stream', $4) \
                     ON CONFLICT (repository_id, path) DO UPDATE SET \
                         size_bytes = EXCLUDED.size_bytes, \
                         storage_key = EXCLUDED.storage_key, \
                         is_deleted = false, updated_at = now()",
                )
                .bind(repo)
                .bind(path)
                .bind(size)
                .bind(format!("keys/{path}"))
                .execute(&mut *tx)
                .await
                .expect("artifact upsert");
                tx.commit().await.expect("commit");
            }
            adm.allowed
        }

        /// (a)/(b): an under-quota upload is admitted, an upload that would
        /// exceed the quota is rejected, and the admission path keeps the
        /// ledger counters exact along the way.
        #[tokio::test]
        async fn test_quota_admission_o1_under_then_over() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");
            set_quota(&pool, repo.id, Some(1000)).await;

            assert!(admit_and_insert(&service, &pool, repo.id, "q/a", 600).await);
            assert!(
                !admit_and_insert(&service, &pool, repo.id, "q/b", 600).await,
                "600 committed + 600 new must exceed the 1000-byte quota"
            );
            assert!(admit_and_insert(&service, &pool, repo.id, "q/b", 300).await);
            assert_eq!(
                ledger_hosted(&pool, repo.id).await,
                Some(900),
                "hosted_bytes must end exact (600 + 300), charged once by the \
                 insert trigger — not double-counted by admission"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// (c): two concurrent uploads that would jointly exceed the quota —
        /// exactly one succeeds. The first admission holds the ledger-row
        /// `FOR UPDATE` lock; the second blocks on it and, once the first
        /// commits, observes the charged bytes and is rejected.
        #[tokio::test]
        async fn test_quota_admission_concurrent_joint_excess_admits_exactly_one() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");
            set_quota(&pool, repo.id, Some(1000)).await;
            let repo_id = repo.id;

            // First admission: take and HOLD the ledger-row lock.
            let mut tx1 = pool.begin().await.expect("begin tx1");
            let adm1 = service
                .check_quota_locked(&mut tx1, repo_id, "race/one", 600)
                .await
                .expect("admission 1");
            assert!(adm1.allowed);

            // Second admission starts while the first still holds the lock,
            // so it must wait for tx1's commit and then see its bytes.
            let pool2 = pool.clone();
            let contender = tokio::spawn(async move {
                let service2 = RepositoryService::new(pool2.clone());
                admit_and_insert(&service2, &pool2, repo_id, "race/two", 600).await
            });

            // Give the contender time to reach (and block on) the row lock,
            // then land the first upload.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            sqlx::query(
                "INSERT INTO artifacts \
                   (repository_id, path, name, size_bytes, checksum_sha256, \
                    content_type, storage_key) \
                 VALUES ($1, $2, $2, $3, repeat('a', 64), \
                         'application/octet-stream', $4)",
            )
            .bind(repo_id)
            .bind("race/one")
            .bind(600_i64)
            .bind("keys/race/one")
            .execute(&mut *tx1)
            .await
            .expect("artifact insert tx1");
            tx1.commit().await.expect("commit tx1");

            let second_allowed = contender.await.expect("contender task");
            assert!(
                !second_allowed,
                "the second of two jointly-over-quota concurrent uploads must be rejected"
            );

            let live: i64 = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
            )
            .bind(repo_id)
            .fetch_one(&pool)
            .await
            .expect("count");
            assert_eq!(live, 1, "exactly one upload may land");
            assert_eq!(ledger_hosted(&pool, repo_id).await, Some(600));

            cleanup_repo(&pool, repo_id).await;
        }

        /// (d): freed space becomes admissible immediately — a delete outside
        /// the admission path (lifecycle/GC/handlers) is decremented by
        /// migration 182's trigger in the delete's own transaction, so the
        /// ledger returns to the exact live value (no reconcile pass needed)
        /// and never drops below reality (no phantom free space).
        #[tokio::test]
        async fn test_quota_admission_frees_space_after_delete() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");
            set_quota(&pool, repo.id, Some(1000)).await;

            assert!(admit_and_insert(&service, &pool, repo.id, "gc/full", 900).await);
            assert!(!admit_and_insert(&service, &pool, repo.id, "gc/next", 600).await);

            // Delete outside the admission path (as lifecycle/GC/handlers do).
            sqlx::query(
                "UPDATE artifacts SET is_deleted = true \
                 WHERE repository_id = $1 AND path = 'gc/full'",
            )
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("soft delete");

            // The trigger decremented exactly the deleted bytes: the ledger
            // matches the live sum (0), no more and no less.
            assert_eq!(
                ledger_hosted(&pool, repo.id).await,
                Some(0),
                "delete must return the ledger to the exact live value"
            );

            // Freed space is admissible by the very next upload; the ledger
            // ends at exactly the newly-admitted bytes (no phantom credit).
            assert!(admit_and_insert(&service, &pool, repo.id, "gc/next", 600).await);
            assert_eq!(ledger_hosted(&pool, repo.id).await, Some(600));

            cleanup_repo(&pool, repo.id).await;
        }

        /// (e): proxy-cache and OCI-blob bytes keep counting against the
        /// quota (they did before, via the live 3-way SUM; now via the
        /// ledger's `proxy_bytes`/`oci_bytes` components).
        #[tokio::test]
        async fn test_quota_admission_counts_proxy_and_oci_components() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Docker))
                .await
                .expect("create repo");
            set_quota(&pool, repo.id, Some(1000)).await;

            insert_proxy_cache(&pool, repo.id, "prox/pkg.tgz", 300).await;
            let digest = format!("sha256:{}", Uuid::new_v4().simple());
            insert_oci_blob(&pool, repo.id, &digest, 300).await;
            service
                .reconcile_usage_ledger(repo.id)
                .await
                .expect("reconcile");

            assert!(
                !admit_and_insert(&service, &pool, repo.id, "img/manifest", 500).await,
                "300 proxy + 300 oci + 500 hosted must exceed the 1000-byte quota"
            );
            assert!(admit_and_insert(&service, &pool, repo.id, "img/manifest", 300).await);

            cleanup_repo(&pool, repo.id).await;
        }

        /// A pre-ledger repository (no `repository_usage_ledger` row) must
        /// have its row lazy-created FROM THE LIVE SUMS, not from zero
        /// defaults — a zero-seeded row would admit everything until the
        /// first reconcile pass.
        #[tokio::test]
        async fn test_quota_admission_lazy_seed_reads_live_sums_not_zero() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");
            set_quota(&pool, repo.id, Some(1000)).await;

            // Bytes landed via a path that never touched the ledger, and no
            // ledger row exists at all.
            insert_artifact(&pool, repo.id, "seed/big", "keys/seed/big", 900).await;
            sqlx::query("DELETE FROM repository_usage_ledger WHERE repository_id = $1")
                .bind(repo.id)
                .execute(&pool)
                .await
                .expect("drop ledger row");

            assert!(
                !admit_and_insert(&service, &pool, repo.id, "seed/next", 600).await,
                "lazy-seeded admission must see the 900 live bytes, not zero"
            );
            assert!(admit_and_insert(&service, &pool, repo.id, "seed/next", 50).await);
            assert_eq!(
                ledger_hosted(&pool, repo.id).await,
                Some(950),
                "seed (900) + admitted charge (50)"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// Overwrites are charged only their net size delta (no
        /// double-counting of the bytes they replace).
        #[tokio::test]
        async fn test_quota_admission_overwrite_charges_net_delta() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");
            set_quota(&pool, repo.id, Some(1000)).await;

            assert!(admit_and_insert(&service, &pool, repo.id, "ow/a", 800).await);
            // Overwriting the same path with 900 nets out the existing 800:
            // base usage 0 + 900 <= 1000.
            assert!(admit_and_insert(&service, &pool, repo.id, "ow/a", 900).await);
            assert_eq!(
                ledger_hosted(&pool, repo.id).await,
                Some(900),
                "the overwrite must be charged +100, not +900"
            );
            assert!(!admit_and_insert(&service, &pool, repo.id, "ow/b", 200).await);
            assert!(admit_and_insert(&service, &pool, repo.id, "ow/b", 100).await);
            assert_eq!(ledger_hosted(&pool, repo.id).await, Some(1000));

            cleanup_repo(&pool, repo.id).await;
        }

        /// The unlimited-quota fast path stays lock-free: no ledger row is
        /// created or locked, and no usage is computed.
        #[tokio::test]
        async fn test_quota_admission_unlimited_skips_ledger() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");

            for quota in [None, Some(0_i64), Some(-1_i64)] {
                set_quota(&pool, repo.id, quota).await;
                let mut tx = pool.begin().await.expect("begin");
                let adm = service
                    .check_quota_locked(&mut tx, repo.id, "unl/x", i64::MAX / 2)
                    .await
                    .expect("admission");
                assert!(adm.allowed, "quota {quota:?} means unlimited");
                assert_eq!(adm.base_usage, None, "unlimited computes no usage");
                drop(tx);
            }
            assert_eq!(
                ledger_hosted(&pool, repo.id).await,
                None,
                "the unlimited fast path must never create the ledger row"
            );

            cleanup_repo(&pool, repo.id).await;
        }

        /// Configuring a finite quota on `update()` synchronously trues up
        /// the ledger, so enforcement starts from the live figure instead of
        /// stale counters accumulated while the repository was unlimited.
        #[tokio::test]
        async fn test_update_with_finite_quota_reconciles_ledger() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let service = RepositoryService::new(pool.clone());
            let suffix = format!("{}", uuid::Uuid::new_v4().simple());
            let repo = service
                .create(make_create_req(&suffix, RepositoryFormat::Generic))
                .await
                .expect("create repo");

            // 900 live bytes, then inject under-count drift directly into the
            // ledger row (a direct ledger write bypasses the source-table
            // triggers, mimicking pre-182 counters or manual surgery): the
            // quota update below must not begin enforcement from the stale
            // zero.
            insert_artifact(&pool, repo.id, "stale/one", "keys/stale/one", 900).await;
            sqlx::query(
                "UPDATE repository_usage_ledger SET hosted_bytes = 0 \
                 WHERE repository_id = $1",
            )
            .bind(repo.id)
            .execute(&pool)
            .await
            .expect("inject stale ledger row");

            service
                .update(
                    repo.id,
                    UpdateRepositoryRequest {
                        key: None,
                        name: None,
                        description: None,
                        is_public: None,
                        quota_bytes: Some(Some(1000)),
                        upstream_url: None,
                        promotion_only: None,
                        versioning_enabled: None,
                        project_id: None,
                        trusted_gpg_key: None,
                        curation_allow_unverified: None,
                        curation_enabled: None,
                        curation_default_action: None,
                    },
                )
                .await
                .expect("update quota");

            assert_eq!(
                ledger_hosted(&pool, repo.id).await,
                Some(900),
                "setting a finite quota must true the ledger up synchronously"
            );
            assert!(!admit_and_insert(&service, &pool, repo.id, "stale/two", 200).await);
            assert!(admit_and_insert(&service, &pool, repo.id, "stale/two", 100).await);

            cleanup_repo(&pool, repo.id).await;
        }

        /// O(1) contract pin (#2516 S2): the admission critical section must
        /// not re-aggregate the live source tables. The 3-way UNION aggregate
        /// (`artifacts` + `proxy_cache_artifacts` + `oci_blobs`) is the
        /// O(repository rows) shape this slice removed; reintroducing it
        /// inside `check_quota_locked` re-serializes every same-repo upload
        /// behind a full scan. The per-path netting SUM (unique-index lookup)
        /// and the ledger-row lock are expected to remain.
        #[test]
        fn test_check_quota_locked_has_no_live_union_aggregate() {
            let src = include_str!("repository_service.rs");
            let fn_start = src
                .find("pub async fn check_quota_locked(")
                .expect("check_quota_locked must exist");
            let fn_end_rel = src[fn_start..]
                .find("async fn reconcile_usage_ledger_in_tx(")
                .expect("reconcile_usage_ledger_in_tx must follow check_quota_locked");
            let body = &src[fn_start..fn_start + fn_end_rel];

            // Built at runtime so this test's own text does not match.
            let union_aggregate = format!("{} {}", "UNION", "ALL");
            assert!(
                !body.contains(&union_aggregate),
                "check_quota_locked must stay O(1): read the locked \
                 repository_usage_ledger counters, never re-run the live \
                 3-way aggregate under the admission lock (#2516 F1)"
            );
            assert!(
                body.contains("repository_usage_ledger") && body.contains("FOR UPDATE"),
                "admission must keep serializing on the locked ledger row"
            );
        }
    }
}
