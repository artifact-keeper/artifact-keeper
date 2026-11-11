//! Phase 2/3 settings of MCP registries (#5253), flattened into the
//! repository create/update requests and the repository response.
//!
//! Each field is one `repository_config` key of the same name. The Phase 1
//! keys (`mcp_package_policy`, `mcp_package_repos`, `mcp_namespace_allow`)
//! stay in [`crate::services::mcp_packages`]. Behaviour lives with the code
//! that reads the setting; this module validates, stores and echoes.
//!
//! Instance locks: `mcp_remote_posture_locked` and `mcp_probe_remotes_locked`
//! can only be written by an instance administrator. While a lock is set,
//! nobody else may change the locked setting (or the lock), so a repository
//! administrator cannot relax the posture an instance administrator chose.
//! The posture lock also covers `mcp_auto_approve_namespaces` (a standing
//! approval is posture by another name) and namespace-spanning bulk
//! approvals ([`spans_namespaces`]); the probe lock also covers
//! `mcp_sandbox_introspection`.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::RepositoryFormat;

pub const SERVER_DENY_KEY: &str = "mcp_server_deny";
pub const REMOTE_POSTURE_KEY: &str = "mcp_remote_posture";
pub const REMOTE_POSTURE_LOCKED_KEY: &str = "mcp_remote_posture_locked";
pub const AUTO_APPROVE_KEY: &str = "mcp_auto_approve_namespaces";
pub const FLOATING_TAG_KEY: &str = "mcp_oci_floating_tag_policy";
pub const PROBE_KEY: &str = "mcp_probe_remotes";
pub const PROBE_LOCKED_KEY: &str = "mcp_probe_remotes_locked";
pub const REQUIRE_OCI_LABEL_KEY: &str = "mcp_require_oci_label";
pub const REQUIRE_NAMESPACE_GRANT_KEY: &str = "mcp_require_namespace_grant";
pub const REMOTE_MODE_KEY: &str = "mcp_remote_mode";
pub const SANDBOX_KEY: &str = "mcp_sandbox_introspection";
pub const REQUIRE_BUNDLE_SIGNATURE_KEY: &str = "mcp_require_bundle_signature";
pub const REMOTE_SYNC_PAUSED_KEY: &str = "mcp_remote_sync_paused";

/// Every key this module owns, for one `repository_config` read.
pub const ALL_KEYS: &[&str] = &[
    SERVER_DENY_KEY,
    REMOTE_POSTURE_KEY,
    REMOTE_POSTURE_LOCKED_KEY,
    AUTO_APPROVE_KEY,
    FLOATING_TAG_KEY,
    PROBE_KEY,
    PROBE_LOCKED_KEY,
    REQUIRE_OCI_LABEL_KEY,
    REQUIRE_NAMESPACE_GRANT_KEY,
    REMOTE_MODE_KEY,
    SANDBOX_KEY,
    REQUIRE_BUNDLE_SIGNATURE_KEY,
    REMOTE_SYNC_PAUSED_KEY,
];

/// Remote posture: `approval_required` (default) serves only approved names;
/// `allow_with_gates` serves every name whose version passes the gates.
pub const POSTURES: &[&str] = &["approval_required", "allow_with_gates"];
/// OCI `latest`/tagless entries in upstream documents: `pin` (default,
/// warn and pin the digest at sync) or `hide`.
pub const FLOATING_TAG_POLICIES: &[&str] = &["pin", "hide"];
/// Remote `tools/list` probe from the isolated introspector: `off` (default).
pub const PROBE_MODES: &[&str] = &["off", "hosted_only", "all"];
/// Remote sync scope: `allowlist` (default, ingest approved names only) or
/// `mirror` (ingest every upstream name; serving is still curated).
pub const REMOTE_MODES: &[&str] = &["allowlist", "mirror"];
/// Sandboxed stdio introspection: `off` (default) or `on`.
pub const SANDBOX_MODES: &[&str] = &["off", "on"];

/// Glob lists are capped so one setting cannot become a DoS vector.
pub const MAX_GLOBS: usize = 256;
pub const MAX_GLOB_LEN: usize = 200;

/// The Phase 2/3 MCP settings. On a request, `None` leaves the stored value
/// unchanged; on a response, `None` means "not an MCP repository" or "not
/// applicable to this repository type" (effective defaults are echoed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct McpRepoSettings {
    /// Glob list on the full server name (`com.evil/*`, `*.typo/*`). A match
    /// is refused on publish and hidden on serve; deny always wins, even over
    /// an approval. Any repository type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server_deny: Option<Vec<String>>,
    /// Remote only: `approval_required` (default) | `allow_with_gates`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_remote_posture: Option<String>,
    /// Remote only: instance-administrator lock on `mcp_remote_posture`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_remote_posture_locked: Option<bool>,
    /// Remote only: globs over the FULL server name whose names are approved
    /// on sync (`io.github.modelcontextprotocol/*`, `com.acme.*/*`,
    /// `com.acme/weather`). `*` matches any run of characters including `/`;
    /// ASCII case-insensitive. An entry with neither `/` nor `*` (a bare
    /// namespace such as `com.acme`) matches no name and is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_auto_approve_namespaces: Option<Vec<String>>,
    /// Remote only: `pin` (default) | `hide`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_oci_floating_tag_policy: Option<String>,
    /// Hosted and Remote: `off` (default) | `hosted_only` | `all`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_probe_remotes: Option<String>,
    /// Instance-administrator lock on `mcp_probe_remotes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_probe_remotes_locked: Option<bool>,
    /// Refuse an OCI package whose image lacks a matching
    /// `io.modelcontextprotocol.server.name` label (default `false`: warn).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_require_oci_label: Option<bool>,
    /// Publishing needs a namespace-conditioned grant
    /// (`PermissionConditions.mcp_namespaces`), not just repository write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_require_namespace_grant: Option<bool>,
    /// Remote only: `allowlist` (default) | `mirror`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_remote_mode: Option<String>,
    /// Hosted and Remote: `off` (default) | `on` (queue sandboxed stdio
    /// introspection runs for the isolated worker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_sandbox_introspection: Option<String>,
    /// Refuse MCPB bundle uploads whose signature does not verify (default
    /// `false`: unsigned bundles are accepted and labelled unsigned; a
    /// signature that is present but invalid is always refused).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_require_bundle_signature: Option<bool>,
    /// Remote only: the scheduled sync skips this repository (default
    /// `false`, #5402). Set it on create to configure the Remote before its
    /// first sync; a manual `POST .../mcp/sync` still runs a pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_remote_sync_paused: Option<bool>,
}

impl McpRepoSettings {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

fn one_of(key: &str, v: &str, allowed: &[&str]) -> Result<String> {
    if allowed.contains(&v) {
        Ok(v.to_string())
    } else {
        Err(AppError::Validation(format!(
            "{key} must be one of: {}",
            allowed.join(", ")
        )))
    }
}

/// Validate a glob list (server names or namespaces): non-empty entries of
/// `[A-Za-z0-9._/*-]`, bounded in count and length. Returns the trimmed,
/// de-duplicated list as stored JSON.
pub fn validate_globs(key: &str, globs: &[String]) -> Result<Vec<String>> {
    if globs.len() > MAX_GLOBS {
        return Err(AppError::Validation(format!(
            "{key} accepts at most {MAX_GLOBS} entries"
        )));
    }
    let mut out: Vec<String> = Vec::new();
    for g in globs {
        let g = g.trim();
        let ok = !g.is_empty()
            && g.len() <= MAX_GLOB_LEN
            && g.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '*'));
        if !ok {
            return Err(AppError::Validation(format!(
                "{key}: `{g}` is not a valid pattern (letters, digits, `.`, `_`, `-`, `/` and `*`, \
                 at most {MAX_GLOB_LEN} characters)"
            )));
        }
        if !out.iter().any(|o| o == g) {
            out.push(g.to_string());
        }
    }
    Ok(out)
}

/// [`validate_globs`] for globs over the full server name
/// (`mcp_server_deny`, `mcp_auto_approve_namespaces`): an entry without `/`
/// or `*` (a bare namespace) could never match a name, so it is refused with
/// the spelling that would.
pub fn validate_name_globs(key: &str, globs: &[String]) -> Result<Vec<String>> {
    let out = validate_globs(key, globs)?;
    if let Some(msg) = bare_namespace_refusal(key, &out) {
        return Err(AppError::UnprocessableEntity(msg));
    }
    Ok(out)
}

/// The refusal of the first bare namespace (an entry with neither `/` nor
/// `*`) in `globs`, with the spelling that would match its servers; `None`
/// when every entry is a full-name glob. Shared by [`validate_name_globs`]
/// and the catalog's bulk decisions so both apply one rule.
pub fn bare_namespace_refusal(key: &str, globs: &[String]) -> Option<String> {
    globs
        .iter()
        .find(|g| !g.contains('/') && !g.contains('*'))
        .map(|g| {
            format!(
                "{key}: `{g}` matches no server name (patterns match the full name \
                 `namespace/name`); use `{g}/*` for every server in the namespace"
            )
        })
}

/// `*` matches any run of characters (including `/`); everything else is
/// literal, ASCII case-insensitive (server names are case-insensitive for
/// policy purposes so `Com.Evil/x` cannot dodge `com.evil/*`).
///
/// Iterative two-pointer matcher: on a mismatch it resumes after the last
/// `*`, one character further into the name, so the work is bounded by
/// `pattern.len() * name.len()` (no exponential backtracking).
pub fn glob_matches(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0usize, 0usize);
    // The position after the last `*` seen, and the name position it was
    // tried against.
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] == b'*' {
            pi += 1;
            star = Some((pi, ni));
        } else if pi < p.len() && p[pi].eq_ignore_ascii_case(&n[ni]) {
            pi += 1;
            ni += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// Whether a glob's namespace part (before the first `/`, or the whole glob
/// when it has none) contains `*`: it then spans namespaces nobody named
/// (`*`, `*/x`, `com.*`, `*.acme/*`), which a posture lock forbids to
/// non-instance administrators.
pub fn spans_namespaces(glob: &str) -> bool {
    glob.split('/').next().unwrap_or_default().contains('*')
}

/// Whether any glob in `globs` matches `name`.
pub fn any_glob_matches(globs: &[String], name: &str) -> bool {
    globs.iter().any(|g| glob_matches(g, name))
}

/// Settings that apply only to Remote MCP repositories.
fn remote_only(s: &McpRepoSettings) -> Vec<&'static str> {
    let mut v = Vec::new();
    if s.mcp_remote_posture.is_some() {
        v.push(REMOTE_POSTURE_KEY);
    }
    if s.mcp_remote_posture_locked.is_some() {
        v.push(REMOTE_POSTURE_LOCKED_KEY);
    }
    if s.mcp_auto_approve_namespaces.is_some() {
        v.push(AUTO_APPROVE_KEY);
    }
    if s.mcp_oci_floating_tag_policy.is_some() {
        v.push(FLOATING_TAG_KEY);
    }
    if s.mcp_remote_mode.is_some() {
        v.push(REMOTE_MODE_KEY);
    }
    if s.mcp_remote_sync_paused.is_some() {
        v.push(REMOTE_SYNC_PAUSED_KEY);
    }
    v
}

/// The stored locks, read before a write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Locks {
    pub posture: bool,
    pub probe: bool,
}

/// Validate `s` for `format`/`repo_type` and return the `repository_config`
/// rows to upsert. Pure: `locks` are the currently stored locks and
/// `instance_admin` whether the caller is an instance administrator.
pub fn to_store(
    s: &McpRepoSettings,
    format: &RepositoryFormat,
    repo_type: &str,
    instance_admin: bool,
    locks: Locks,
) -> Result<Vec<(&'static str, String)>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if format != &RepositoryFormat::Mcp {
        return Err(AppError::Validation(
            "mcp_* settings are only valid for MCP repositories".to_string(),
        ));
    }
    if repo_type != "remote" {
        if let Some(k) = remote_only(s).first() {
            return Err(AppError::Validation(format!(
                "{k} is only valid for Remote MCP repositories"
            )));
        }
    }
    if repo_type == "virtual"
        && (s.mcp_probe_remotes.is_some()
            || s.mcp_probe_remotes_locked.is_some()
            || s.mcp_sandbox_introspection.is_some()
            || s.mcp_require_namespace_grant.is_some()
            || s.mcp_require_bundle_signature.is_some())
    {
        return Err(AppError::Validation(
            "a Virtual MCP repository serves what its members serve; set this on the members"
                .to_string(),
        ));
    }
    let lock_refusal = |what: &str| {
        AppError::Authorization(format!(
            "{what} is locked by an instance administrator for this repository"
        ))
    };
    if !instance_admin {
        if s.mcp_remote_posture_locked.is_some() || s.mcp_probe_remotes_locked.is_some() {
            return Err(AppError::Authorization(
                "only an instance administrator can lock or unlock MCP settings".to_string(),
            ));
        }
        if locks.posture && s.mcp_remote_posture.is_some() {
            return Err(lock_refusal(REMOTE_POSTURE_KEY));
        }
        if locks.posture && s.mcp_auto_approve_namespaces.is_some() {
            return Err(lock_refusal(AUTO_APPROVE_KEY));
        }
        if locks.probe && s.mcp_probe_remotes.is_some() {
            return Err(lock_refusal(PROBE_KEY));
        }
        if locks.probe && s.mcp_sandbox_introspection.is_some() {
            return Err(lock_refusal(SANDBOX_KEY));
        }
    }
    let mut out = Vec::new();
    let json = |v: &Vec<String>| serde_json::to_string(v).expect("string list serialises");
    if let Some(g) = &s.mcp_server_deny {
        out.push((
            SERVER_DENY_KEY,
            json(&validate_name_globs(SERVER_DENY_KEY, g)?),
        ));
    }
    if let Some(v) = &s.mcp_remote_posture {
        out.push((REMOTE_POSTURE_KEY, one_of(REMOTE_POSTURE_KEY, v, POSTURES)?));
    }
    if let Some(b) = s.mcp_remote_posture_locked {
        out.push((REMOTE_POSTURE_LOCKED_KEY, b.to_string()));
    }
    if let Some(g) = &s.mcp_auto_approve_namespaces {
        out.push((
            AUTO_APPROVE_KEY,
            json(&validate_name_globs(AUTO_APPROVE_KEY, g)?),
        ));
    }
    if let Some(v) = &s.mcp_oci_floating_tag_policy {
        out.push((
            FLOATING_TAG_KEY,
            one_of(FLOATING_TAG_KEY, v, FLOATING_TAG_POLICIES)?,
        ));
    }
    if let Some(v) = &s.mcp_probe_remotes {
        out.push((PROBE_KEY, one_of(PROBE_KEY, v, PROBE_MODES)?));
    }
    if let Some(b) = s.mcp_probe_remotes_locked {
        out.push((PROBE_LOCKED_KEY, b.to_string()));
    }
    for (key, v) in [
        (REQUIRE_OCI_LABEL_KEY, s.mcp_require_oci_label),
        (REQUIRE_NAMESPACE_GRANT_KEY, s.mcp_require_namespace_grant),
        (REQUIRE_BUNDLE_SIGNATURE_KEY, s.mcp_require_bundle_signature),
        (REMOTE_SYNC_PAUSED_KEY, s.mcp_remote_sync_paused),
    ] {
        if let Some(b) = v {
            out.push((key, b.to_string()));
        }
    }
    if let Some(v) = &s.mcp_remote_mode {
        out.push((REMOTE_MODE_KEY, one_of(REMOTE_MODE_KEY, v, REMOTE_MODES)?));
    }
    if let Some(v) = &s.mcp_sandbox_introspection {
        out.push((SANDBOX_KEY, one_of(SANDBOX_KEY, v, SANDBOX_MODES)?));
    }
    Ok(out)
}

/// Raw `(key, value)` rows of this module's keys for one repository.
pub async fn load_rows(db: &PgPool, repo_id: Uuid) -> Result<Vec<(String, Option<String>)>> {
    sqlx::query_as(
        "SELECT key, value FROM repository_config WHERE repository_id = $1 AND key = ANY($2)",
    )
    .bind(repo_id)
    .bind(ALL_KEYS)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// The effective settings of one repository from its stored rows: defaults
/// filled in for the keys that apply to `repo_type`, `None` for the rest.
/// Pure (see [`load_rows`]).
pub fn effective(rows: &[(String, Option<String>)], repo_type: &str) -> McpRepoSettings {
    let get = |k: &str| {
        rows.iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| v.as_deref())
    };
    let list = |k: &str| {
        Some(
            get(k)
                .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
                .unwrap_or_default(),
        )
    };
    let flag = |k: &str| Some(get(k) == Some("true"));
    let pick = |k: &str, allowed: &[&str], default: &str| {
        Some(
            get(k)
                .filter(|v| allowed.contains(v))
                .unwrap_or(default)
                .to_string(),
        )
    };
    let remote = repo_type == "remote";
    let virtual_ = repo_type == "virtual";
    McpRepoSettings {
        mcp_server_deny: list(SERVER_DENY_KEY),
        mcp_remote_posture: remote
            .then(|| pick(REMOTE_POSTURE_KEY, POSTURES, "approval_required"))
            .flatten(),
        mcp_remote_posture_locked: remote.then(|| flag(REMOTE_POSTURE_LOCKED_KEY)).flatten(),
        mcp_auto_approve_namespaces: remote.then(|| list(AUTO_APPROVE_KEY)).flatten(),
        mcp_oci_floating_tag_policy: remote
            .then(|| pick(FLOATING_TAG_KEY, FLOATING_TAG_POLICIES, "pin"))
            .flatten(),
        mcp_probe_remotes: (!virtual_)
            .then(|| pick(PROBE_KEY, PROBE_MODES, "off"))
            .flatten(),
        mcp_probe_remotes_locked: (!virtual_).then(|| flag(PROBE_LOCKED_KEY)).flatten(),
        mcp_require_oci_label: flag(REQUIRE_OCI_LABEL_KEY),
        mcp_require_namespace_grant: (!virtual_)
            .then(|| flag(REQUIRE_NAMESPACE_GRANT_KEY))
            .flatten(),
        mcp_remote_mode: remote
            .then(|| pick(REMOTE_MODE_KEY, REMOTE_MODES, "allowlist"))
            .flatten(),
        mcp_sandbox_introspection: (!virtual_)
            .then(|| pick(SANDBOX_KEY, SANDBOX_MODES, "off"))
            .flatten(),
        mcp_require_bundle_signature: (!virtual_)
            .then(|| flag(REQUIRE_BUNDLE_SIGNATURE_KEY))
            .flatten(),
        mcp_remote_sync_paused: remote.then(|| flag(REMOTE_SYNC_PAUSED_KEY)).flatten(),
    }
}

/// Effective settings of one repository.
pub async fn load(db: &PgPool, repo_id: Uuid, repo_type: &str) -> Result<McpRepoSettings> {
    Ok(effective(&load_rows(db, repo_id).await?, repo_type))
}

/// The stored locks (for [`to_store`]).
pub fn locks_of(rows: &[(String, Option<String>)]) -> Locks {
    let on = |k: &str| {
        rows.iter()
            .any(|(key, v)| key == k && v.as_deref() == Some("true"))
    };
    Locks {
        posture: on(REMOTE_POSTURE_LOCKED_KEY),
        probe: on(PROBE_LOCKED_KEY),
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn mcp() -> RepositoryFormat {
        RepositoryFormat::Mcp
    }

    #[test]
    fn globs_match_case_insensitively_and_across_slashes() {
        assert!(glob_matches("com.evil/*", "com.evil/x"));
        assert!(glob_matches("com.evil/*", "Com.Evil/X"));
        assert!(glob_matches("*.typo/*", "io.github.typo/y"));
        assert!(glob_matches("io.github.acme-*", "io.github.acme-labs"));
        let names = |g: &[&str]| {
            validate_name_globs(
                AUTO_APPROVE_KEY,
                &g.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        };
        assert!(names(&["io.github.modelcontextprotocol/*", "com.acme.*/*", "*"]).is_ok());
        let err = names(&["com.acme"]).unwrap_err();
        // A bare namespace is `422`, as in the bulk routes; bad syntax `400`.
        assert!(matches!(err, AppError::UnprocessableEntity(_)), "{err:?}");
        assert!(err.to_string().contains("com.acme/*"), "{err}");
        assert!(matches!(
            names(&["a b"]).unwrap_err(),
            AppError::Validation(_)
        ));
        assert!(glob_matches("a/b", "a/b"));
        assert!(!glob_matches("a/b", "a/bc"));
        assert!(!glob_matches("com.evil/*", "com.evilx/y"));
        assert!(glob_matches("***", ""));
        assert!(any_glob_matches(&["x/*".into(), "y/*".into()], "y/z"));
        assert!(!any_glob_matches(&[], "y/z"));
    }

    #[test]
    fn glob_lists_are_validated_and_deduplicated() {
        assert_eq!(
            validate_globs("k", &[" a/* ".into(), "a/*".into()]).unwrap(),
            vec!["a/*".to_string()]
        );
        assert!(validate_globs("k", &["".into()]).is_err());
        assert!(validate_globs("k", &["a b".into()]).is_err());
        assert!(validate_globs("k", &["x".repeat(MAX_GLOB_LEN + 1)]).is_err());
        assert!(validate_globs("k", &vec!["a".to_string(); MAX_GLOBS + 1]).is_err());
    }

    #[test]
    fn to_store_validates_values_and_repo_types() {
        let posture = McpRepoSettings {
            mcp_remote_posture: Some("allow_with_gates".into()),
            ..Default::default()
        };
        assert_eq!(
            to_store(&posture, &mcp(), "remote", false, Locks::default()).unwrap(),
            vec![(REMOTE_POSTURE_KEY, "allow_with_gates".to_string())]
        );
        assert!(to_store(&posture, &mcp(), "local", false, Locks::default()).is_err());
        assert!(to_store(
            &posture,
            &RepositoryFormat::Npm,
            "remote",
            true,
            Locks::default()
        )
        .is_err());
        let bad = McpRepoSettings {
            mcp_remote_posture: Some("open".into()),
            ..Default::default()
        };
        assert!(to_store(&bad, &mcp(), "remote", true, Locks::default()).is_err());
        let probe = McpRepoSettings {
            mcp_probe_remotes: Some("all".into()),
            ..Default::default()
        };
        assert!(to_store(&probe, &mcp(), "virtual", true, Locks::default()).is_err());
        assert!(to_store(&probe, &mcp(), "local", false, Locks::default()).is_ok());
        assert!(to_store(
            &McpRepoSettings::default(),
            &RepositoryFormat::Npm,
            "local",
            false,
            Locks::default()
        )
        .unwrap()
        .is_empty());
        let all = McpRepoSettings {
            mcp_server_deny: Some(vec!["com.evil/*".into()]),
            mcp_require_oci_label: Some(true),
            mcp_require_namespace_grant: Some(true),
            mcp_require_bundle_signature: Some(false),
            mcp_sandbox_introspection: Some("on".into()),
            mcp_remote_mode: Some("mirror".into()),
            mcp_oci_floating_tag_policy: Some("hide".into()),
            mcp_auto_approve_namespaces: Some(vec!["com.acme/*".into()]),
            mcp_remote_sync_paused: Some(true),
            ..Default::default()
        };
        let rows = to_store(&all, &mcp(), "remote", false, Locks::default()).unwrap();
        assert_eq!(rows.len(), 9);
        assert!(rows.contains(&(REMOTE_SYNC_PAUSED_KEY, "true".to_string())));
        assert!(rows.contains(&(SERVER_DENY_KEY, "[\"com.evil/*\"]".to_string())));
    }

    #[test]
    fn locks_bind_everyone_but_instance_admins() {
        let lock = McpRepoSettings {
            mcp_remote_posture_locked: Some(true),
            ..Default::default()
        };
        assert!(to_store(&lock, &mcp(), "remote", false, Locks::default()).is_err());
        assert!(to_store(&lock, &mcp(), "remote", true, Locks::default()).is_ok());
        let relax = McpRepoSettings {
            mcp_remote_posture: Some("allow_with_gates".into()),
            ..Default::default()
        };
        let locked = Locks {
            posture: true,
            probe: false,
        };
        assert!(matches!(
            to_store(&relax, &mcp(), "remote", false, locked),
            Err(AppError::Authorization(_))
        ));
        assert!(to_store(&relax, &mcp(), "remote", true, locked).is_ok());
        let probe = McpRepoSettings {
            mcp_probe_remotes: Some("all".into()),
            ..Default::default()
        };
        let probe_locked = Locks {
            posture: false,
            probe: true,
        };
        assert!(to_store(&probe, &mcp(), "local", false, probe_locked).is_err());
    }

    /// Review finding 6: the posture lock also covers the auto-approve list
    /// (`["*"]` would otherwise approve everything under a locked
    /// `approval_required`), and the probe lock covers sandbox runs.
    #[test]
    fn locks_cover_auto_approve_and_sandbox() {
        let locked = Locks {
            posture: true,
            probe: true,
        };
        let auto = McpRepoSettings {
            mcp_auto_approve_namespaces: Some(vec!["*".into()]),
            ..Default::default()
        };
        assert!(matches!(
            to_store(&auto, &mcp(), "remote", false, locked),
            Err(AppError::Authorization(_))
        ));
        assert!(to_store(&auto, &mcp(), "remote", true, locked).is_ok());
        assert!(to_store(&auto, &mcp(), "remote", false, Locks::default()).is_ok());
        let sandbox = McpRepoSettings {
            mcp_sandbox_introspection: Some("on".into()),
            ..Default::default()
        };
        assert!(matches!(
            to_store(&sandbox, &mcp(), "local", false, locked),
            Err(AppError::Authorization(_))
        ));
        assert!(to_store(&sandbox, &mcp(), "local", true, locked).is_ok());
        for (g, spans) in [
            ("*", true),
            ("*/x", true),
            ("com.*", true),
            ("*.acme/*", true),
            ("com.acme", false),
            ("com.acme/*", false),
            ("com.acme/weather*", false),
        ] {
            assert_eq!(spans_namespaces(g), spans, "{g}");
        }
    }

    /// Review finding 16: the matcher is linear-ish, not exponential, on a
    /// pathological pattern, and keeps the old semantics.
    #[test]
    fn glob_matching_does_not_backtrack_exponentially() {
        let pattern = format!("{}b", "*a".repeat(40));
        let name = "a".repeat(200);
        let start = std::time::Instant::now();
        assert!(!glob_matches(&pattern, &name));
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        assert!(glob_matches("*a*b*", "xxaYYbzz"));
        assert!(glob_matches("a*", "a"));
        assert!(glob_matches("*", ""));
        assert!(!glob_matches("a", ""));
        assert!(!glob_matches("", "a"));
        assert!(glob_matches("a*c", "abbbc"));
        assert!(!glob_matches("a*c", "abbbd"));
        assert!(glob_matches("A*/X", "a.b/x"));
    }

    #[test]
    fn effective_fills_defaults_per_repo_type() {
        let rows = vec![
            (REMOTE_POSTURE_KEY.to_string(), Some("bogus".to_string())),
            (SERVER_DENY_KEY.to_string(), Some("[\"a/*\"]".to_string())),
            (PROBE_LOCKED_KEY.to_string(), Some("true".to_string())),
        ];
        let r = effective(&rows, "remote");
        assert_eq!(r.mcp_remote_posture.as_deref(), Some("approval_required"));
        assert_eq!(r.mcp_server_deny, Some(vec!["a/*".to_string()]));
        assert_eq!(r.mcp_remote_mode.as_deref(), Some("allowlist"));
        assert_eq!(r.mcp_oci_floating_tag_policy.as_deref(), Some("pin"));
        assert_eq!(r.mcp_probe_remotes_locked, Some(true));
        assert_eq!(r.mcp_remote_sync_paused, Some(false));
        let l = effective(&rows, "local");
        assert_eq!(l.mcp_remote_posture, None);
        assert_eq!(l.mcp_remote_sync_paused, None);
        assert_eq!(l.mcp_probe_remotes.as_deref(), Some("off"));
        let v = effective(&[], "virtual");
        assert_eq!(v.mcp_probe_remotes, None);
        assert_eq!(v.mcp_require_oci_label, Some(false));
        assert_eq!(
            locks_of(&rows),
            Locks {
                posture: false,
                probe: true
            }
        );
    }
}
