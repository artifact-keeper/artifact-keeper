//! Config-as-code document (#5292): one versioned JSON document describing an
//! instance's repositories and their per-repository settings.
//!
//! This module is the pure half: the document types, the `schema_version`
//! gate, the per-repository diff behind `plan`, the `secret_ref` placeholders
//! that stand in for every credential, and the request bodies `apply` sends
//! through the existing repository handlers. Reading and writing the instance
//! happens in `api::handlers::admin_config`, which calls the same handlers the
//! per-setting routes use, so the document cannot drift from the API.
//!
//! Determinism: repositories are sorted by `key`, virtual members by
//! `(priority, key)`, maps are `BTreeMap`s and every struct serializes its
//! fields in declaration order, so two exports of the same configuration are
//! byte-identical apart from `exported_at` and `producer`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{AppError, Result};
use crate::models::repository::RepositoryVisibility;
use crate::services::routing_rules::RoutingRule;
use crate::services::upstream_filter::UpstreamFilter;
use crate::services::upstream_mode::UpstreamMode;
use crate::services::upstream_not_found_policy::OnUpstreamNotFound;

/// The only `schema_version` this server reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// Secret namespaces. A placeholder is `{"secret_ref": "<namespace>/<key>"}`.
pub const SECRET_UPSTREAM_AUTH: &str = "upstream_auth";
pub const SECRET_UPSTREAM_URL: &str = "upstream_url";
pub const SECRET_EGRESS_PROXY: &str = "egress_proxy";

/// Fields that cannot be changed on an existing repository; an import that
/// would change one is refused in `plan`.
const IMMUTABLE_FIELDS: [&str; 3] = ["format", "format_key", "repo_type"];

/// Fields `apply` writes through `PATCH /api/v1/repositories/{key}`.
const PATCH_FIELDS: [&str; 12] = [
    "name",
    "description",
    "visibility",
    "upstream_url",
    "upstream_url_credentials",
    "allow_public_with_upstream_credentials",
    "quota_bytes",
    "promotion_only",
    "versioning_enabled",
    "custom_user_agent",
    "curation_enabled",
    "curation_default_action",
];

/// Placeholder for a credential the export never carries. The import takes
/// the value from the request's `secrets` map under the same name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigSecretRef {
    /// `<namespace>/<repository key>`, e.g. `upstream_auth/npm-remote`.
    pub secret_ref: String,
}

impl ConfigSecretRef {
    pub fn new(namespace: &str, key: &str) -> Self {
        Self {
            secret_ref: format!("{namespace}/{key}"),
        }
    }
}

/// The whole document.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    /// Always `1` for this format. Any other value is refused on import.
    pub schema_version: u32,
    /// When the export was taken. Ignored on import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<chrono::DateTime<chrono::Utc>>,
    /// `artifact-keeper <version>` of the exporting server. Ignored on import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer: Option<String>,
    /// Repositories, sorted by `key`.
    #[serde(default)]
    pub repositories: Vec<ConfigRepository>,
}

/// One repository and its per-repository settings, keyed by `key`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigRepository {
    pub key: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Format key (`maven`, `npm`, ...). Immutable after create.
    pub format: String,
    /// WASM plugin format key, when the repository uses one. Immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_key: Option<String>,
    /// `local`, `remote`, `virtual` or `staging`. Immutable after create.
    pub repo_type: String,
    pub visibility: RepositoryVisibility,
    /// Remote upstream URL with any userinfo removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_url: Option<String>,
    /// Present when the stored upstream URL embeds `user:password@`; the
    /// secret is that userinfo, spliced back into `upstream_url` on import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_url_credentials: Option<ConfigSecretRef>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_public_with_upstream_credentials: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<i64>,
    #[serde(default)]
    pub promotion_only: bool,
    #[serde(default)]
    pub versioning_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_user_agent: Option<String>,
    #[serde(default)]
    pub curation_enabled: bool,
    #[serde(default = "default_curation_action")]
    pub curation_default_action: String,
    /// Virtual repositories: member keys in resolution order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ConfigVirtualMember>,
    /// Remote repositories: the stored upstream mode (#5282). Absent means
    /// `online` (the default); only `cache_only` is exported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_mode: Option<UpstreamMode>,
    /// Remote repositories: freshness lifetime of mutable paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_upstream_not_found: Option<OnUpstreamNotFound>,
    /// The per-repository override; absent means the instance default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_if_error_grace_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_filter: Option<UpstreamFilter>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing_rules: Vec<RoutingRule>,
    /// Absent means `inherit` (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_proxy: Option<ConfigEgressProxy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_auth: Option<ConfigUpstreamAuth>,
    /// npm Remote repositories: absent means no restriction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_scope_policy: Option<ConfigNpmScopePolicy>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn default_curation_action() -> String {
    "allow".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigVirtualMember {
    pub key: String,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigEgressProxy {
    /// `direct` or `explicit`.
    pub mode: String,
    /// Proxy endpoint without userinfo (`explicit` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Present when the proxy URL carries `user:password@`; the secret is
    /// that userinfo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_credentials: Option<ConfigSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_proxy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigUpstreamAuth {
    /// `basic`, `bearer`, `aws_ecr` or `aws_codeartifact`.
    pub auth_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password (basic) or token (bearer); never exported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<ConfigSecretRef>,
    /// Non-secret provider settings of the AWS auth types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<ConfigAwsUpstreamAuth>,
}

/// The AWS provider settings (#1559). They carry no secret: the identity
/// comes from the process's AWS credential chain.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigAwsUpstreamAuth {
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigNpmScopePolicy {
    pub allowed_scopes: Vec<String>,
    pub allow_unscoped: bool,
}

/// One repository `plan` would change, and the top-level fields that differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ConfigPlanUpdate {
    pub key: String,
    pub changes: Vec<String>,
}

/// What an import does (or, with `mode=apply`, did).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct ConfigPlan {
    /// Repositories in the document that the target does not have.
    pub create: Vec<String>,
    /// Repositories whose settings differ, with the differing fields.
    pub update: Vec<ConfigPlanUpdate>,
    /// Repositories already as the document describes them.
    pub unchanged: Vec<String>,
    /// Repositories on the target the document does not mention. Never
    /// deleted by this version.
    pub not_in_document: Vec<String>,
    /// `secret_ref` names the import needs but the request's `secrets` map
    /// does not supply.
    pub missing_secrets: Vec<String>,
    /// Changes an import cannot make (an immutable field, a value the API
    /// cannot clear, a member that exists nowhere).
    pub errors: Vec<String>,
    /// Whether `mode=apply` would proceed: no missing secrets and no errors.
    pub applicable: bool,
    /// `true` once `mode=apply` has written the changes.
    pub applied: bool,
}

impl ConfigPlan {
    /// The 400 message `apply` answers when the plan is not applicable.
    pub fn refusal_message(&self) -> String {
        let mut parts = Vec::new();
        if !self.missing_secrets.is_empty() {
            parts.push(format!(
                "missing secrets: {}",
                self.missing_secrets.join(", ")
            ));
        }
        parts.extend(self.errors.iter().cloned());
        format!("config import refused: {}", parts.join("; "))
    }
}

/// Wrap exported repositories in a document: sorted, versioned, stamped.
pub fn document(mut repositories: Vec<ConfigRepository>) -> ConfigDocument {
    repositories.sort_by(|a, b| a.key.cmp(&b.key));
    for repo in &mut repositories {
        sort_members(&mut repo.members);
    }
    ConfigDocument {
        schema_version: SCHEMA_VERSION,
        exported_at: Some(chrono::Utc::now()),
        producer: Some(format!("artifact-keeper {}", env!("CARGO_PKG_VERSION"))),
        repositories,
    }
}

/// Members in resolution order: priority, then key for a stable tie-break.
pub fn sort_members(members: &mut [ConfigVirtualMember]) {
    members.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.key.cmp(&b.key)));
}

/// Parse an import document, refusing any `schema_version` but [`SCHEMA_VERSION`]
/// before looking at the rest, so a newer document fails with a clear message
/// rather than a field-level parse error.
pub fn parse_document(value: serde_json::Value) -> Result<ConfigDocument> {
    let version = value
        .get("schema_version")
        .ok_or_else(|| AppError::Validation("config document has no schema_version".into()))?;
    if version.as_u64() != Some(u64::from(SCHEMA_VERSION)) {
        return Err(AppError::Validation(format!(
            "unsupported config document schema_version {version}; this server reads {SCHEMA_VERSION}"
        )));
    }
    let mut doc: ConfigDocument = serde_json::from_value(value)
        .map_err(|e| AppError::Validation(format!("invalid config document: {e}")))?;
    for repo in &mut doc.repositories {
        sort_members(&mut repo.members);
    }
    Ok(doc)
}

/// Export the upstream-auth settings from the stored auth type and the
/// decrypted credential JSON. Only an allow-list of non-secret fields is
/// copied (the basic-auth `username` and the AWS provider settings); every
/// password and token becomes a `secret_ref`.
pub fn upstream_auth_from_stored(
    key: &str,
    auth_type: Option<&str>,
    credentials_json: Option<&str>,
) -> Option<ConfigUpstreamAuth> {
    let auth_type = auth_type?;
    let stored: serde_json::Value = credentials_json
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or(serde_json::Value::Null);
    let secret = || Some(ConfigSecretRef::new(SECRET_UPSTREAM_AUTH, key));
    let (username, password, aws) = match auth_type {
        "basic" => (
            stored
                .get("username")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            secret(),
            None,
        ),
        "bearer" => (None, secret(), None),
        _ if crate::services::aws_upstream_auth::is_aws_auth_type(auth_type) => {
            (None, None, serde_json::from_value(stored).ok())
        }
        // An auth type this version does not know: export the type alone and
        // treat its credential as a secret, never the stored payload.
        _ => (None, secret(), None),
    };
    Some(ConfigUpstreamAuth {
        auth_type: auth_type.to_string(),
        username,
        password,
        aws,
    })
}

/// Export the egress proxy from the redacted read-back of
/// `GET .../egress-proxy`. `inherit` (the default) exports as absent.
pub fn egress_proxy_from_read(
    key: &str,
    mode: &str,
    redacted_proxy_url: Option<&str>,
    no_proxy: Option<String>,
    credentials_configured: bool,
) -> Option<ConfigEgressProxy> {
    if mode == "inherit" {
        return None;
    }
    Some(ConfigEgressProxy {
        mode: mode.to_string(),
        proxy_url: redacted_proxy_url
            .map(|url| crate::services::proxy_service::strip_url_userinfo(url).0),
        proxy_credentials: credentials_configured
            .then(|| ConfigSecretRef::new(SECRET_EGRESS_PROXY, key)),
        no_proxy,
    })
}

/// Export the stored upstream mode read back by `GET .../upstream-mode`.
/// `online` (the default) exports as absent.
pub fn upstream_mode_from_read(stored: UpstreamMode) -> Option<UpstreamMode> {
    (stored != UpstreamMode::Online).then_some(stored)
}

/// The mode `PUT .../upstream-mode` writes for `desired`; absent is `online`.
pub fn upstream_mode_body(desired: &ConfigRepository) -> UpstreamMode {
    desired.upstream_mode.unwrap_or_default()
}

/// The upstream-URL pair of a repository: the userinfo-free URL the API
/// returns, and a `secret_ref` when the stored URL embeds credentials.
pub fn upstream_url_fields(
    key: &str,
    stripped_url: Option<String>,
    has_credentials: bool,
) -> (Option<String>, Option<ConfigSecretRef>) {
    let credentials = (has_credentials && stripped_url.is_some())
        .then(|| ConfigSecretRef::new(SECRET_UPSTREAM_URL, key));
    (stripped_url, credentials)
}

fn to_object(repo: &ConfigRepository) -> serde_json::Map<String, serde_json::Value> {
    match serde_json::to_value(repo) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    }
}

/// The top-level fields of `desired` that differ from `current`, sorted. An
/// absent field equals an absent field; two `secret_ref`s with the same name
/// are equal (the import cannot see either value).
pub fn changed_fields(desired: &ConfigRepository, current: &ConfigRepository) -> Vec<String> {
    let a = to_object(desired);
    let b = to_object(current);
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    keys.into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect()
}

/// The `secret_ref` names `desired` needs supplied when `changes` are written.
fn needed_secrets(desired: &ConfigRepository, changes: &BTreeSet<String>) -> Vec<String> {
    let mut needed = Vec::new();
    if changes.contains("upstream_url") || changes.contains("upstream_url_credentials") {
        needed.extend(desired.upstream_url_credentials.clone());
    }
    if changes.contains("upstream_auth") {
        needed.extend(
            desired
                .upstream_auth
                .as_ref()
                .and_then(|a| a.password.clone()),
        );
    }
    if changes.contains("egress_proxy") {
        needed.extend(
            desired
                .egress_proxy
                .as_ref()
                .and_then(|e| e.proxy_credentials.clone()),
        );
    }
    needed.into_iter().map(|s| s.secret_ref).collect()
}

/// Every field of `desired`, for a repository that does not exist yet.
fn all_fields(desired: &ConfigRepository) -> BTreeSet<String> {
    to_object(desired).keys().cloned().collect()
}

/// Diff `doc` against the target's current state. `current` holds the export
/// of every target repository the document names; `target_keys` every key on
/// the target.
pub fn plan(
    doc: &ConfigDocument,
    current: &BTreeMap<String, ConfigRepository>,
    target_keys: &BTreeSet<String>,
    secrets: &BTreeMap<String, String>,
) -> ConfigPlan {
    let mut out = ConfigPlan::default();
    let mut missing = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let doc_keys: BTreeSet<&str> = doc.repositories.iter().map(|r| r.key.as_str()).collect();

    for desired in &doc.repositories {
        if !seen.insert(desired.key.as_str()) {
            out.errors
                .push(format!("repository {} appears twice", desired.key));
            continue;
        }
        let changes: BTreeSet<String> = match current.get(&desired.key) {
            None => {
                out.create.push(desired.key.clone());
                all_fields(desired)
            }
            Some(now) => {
                let changes: BTreeSet<String> = changed_fields(desired, now).into_iter().collect();
                for field in IMMUTABLE_FIELDS {
                    if changes.contains(field) {
                        out.errors.push(format!(
                            "repository {}: {field} cannot be changed by an import",
                            desired.key
                        ));
                    }
                }
                if desired.stale_if_error_grace_seconds.is_none()
                    && now.stale_if_error_grace_seconds.is_some()
                {
                    out.errors.push(format!(
                        "repository {}: the stale_if_error_grace_seconds override cannot be removed by an import",
                        desired.key
                    ));
                }
                if changes.is_empty() {
                    out.unchanged.push(desired.key.clone());
                } else {
                    out.update.push(ConfigPlanUpdate {
                        key: desired.key.clone(),
                        changes: changes.iter().cloned().collect(),
                    });
                }
                changes
            }
        };
        for member in &desired.members {
            if !doc_keys.contains(member.key.as_str()) && !target_keys.contains(&member.key) {
                out.errors.push(format!(
                    "repository {}: member {} is neither in the document nor on the target",
                    desired.key, member.key
                ));
            }
        }
        for name in needed_secrets(desired, &changes) {
            if !secrets.contains_key(&name) {
                missing.insert(name);
            }
        }
    }

    out.not_in_document = target_keys
        .iter()
        .filter(|k| !doc_keys.contains(k.as_str()))
        .cloned()
        .collect();
    out.create.sort();
    out.unchanged.sort();
    out.update.sort_by(|a, b| a.key.cmp(&b.key));
    out.missing_secrets = missing.into_iter().collect();
    out.applicable = out.missing_secrets.is_empty() && out.errors.is_empty();
    out
}

/// The order `apply` visits repositories: every non-virtual repository, then
/// the virtual ones (whose members must exist first), each by key.
pub fn apply_order(doc: &ConfigDocument) -> Vec<&ConfigRepository> {
    let mut ordered: Vec<&ConfigRepository> = doc.repositories.iter().collect();
    ordered.sort_by(|a, b| {
        (a.repo_type == "virtual", &a.key).cmp(&(b.repo_type == "virtual", &b.key))
    });
    ordered
}

/// Look up a `secret_ref` in the request's `secrets` map.
pub fn resolve_secret<'a>(
    secrets: &'a BTreeMap<String, String>,
    secret: &ConfigSecretRef,
) -> Result<&'a str> {
    secrets
        .get(&secret.secret_ref)
        .map(String::as_str)
        .ok_or_else(|| AppError::Validation(format!("missing secret {}", secret.secret_ref)))
}

/// Splice `userinfo` (`user:password`, already percent-encoded) into `url`.
pub fn with_userinfo(url: &str, userinfo: &str) -> Result<String> {
    if userinfo.is_empty() || userinfo.contains(['@', '/', '?', '#']) {
        return Err(AppError::Validation(
            "a URL credential secret must be percent-encoded `user:password` userinfo".into(),
        ));
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| AppError::Validation(format!("invalid URL {url}")))?;
    Ok(format!("{scheme}://{userinfo}@{rest}"))
}

/// The repository's upstream URL with its credentials restored, if any.
fn upstream_url_value(
    desired: &ConfigRepository,
    secrets: &BTreeMap<String, String>,
) -> Result<Option<String>> {
    let Some(url) = desired.upstream_url.as_deref() else {
        return Ok(None);
    };
    match &desired.upstream_url_credentials {
        Some(secret) => with_userinfo(url, resolve_secret(secrets, secret)?).map(Some),
        None => Ok(Some(url.to_string())),
    }
}

/// `POST /api/v1/repositories` body that creates `desired`. Settings the
/// create route does not take are written by the update pass that follows.
pub fn create_body(
    desired: &ConfigRepository,
    secrets: &BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let mut map = serde_json::Map::new();
    let mut set = |field: &str, value: serde_json::Value| {
        map.insert(field.to_string(), value);
    };
    set("key", desired.key.clone().into());
    set("name", desired.name.clone().into());
    set(
        "format",
        desired
            .format_key
            .as_deref()
            .unwrap_or(&desired.format)
            .into(),
    );
    set("repo_type", desired.repo_type.clone().into());
    set("visibility", desired.visibility.as_str().into());
    if let Some(description) = &desired.description {
        set("description", description.clone().into());
    }
    if let Some(url) = upstream_url_value(desired, secrets)? {
        set("upstream_url", url.into());
    }
    if let Some(quota) = desired.quota_bytes {
        set("quota_bytes", quota.into());
    }
    if let Some(ua) = &desired.custom_user_agent {
        set("custom_user_agent", ua.clone().into());
    }
    for (field, value) in [
        ("promotion_only", desired.promotion_only),
        ("versioning_enabled", desired.versioning_enabled),
        (
            "allow_public_with_upstream_credentials",
            desired.allow_public_with_upstream_credentials,
        ),
    ] {
        if value {
            set(field, true.into());
        }
    }
    Ok(serde_json::Value::Object(map))
}

/// `PATCH /api/v1/repositories/{key}` body for the changed repository-row
/// fields, or `None` when none of them changed.
pub fn patch_body(
    desired: &ConfigRepository,
    changes: &BTreeSet<String>,
    secrets: &BTreeMap<String, String>,
) -> Result<Option<serde_json::Value>> {
    if !PATCH_FIELDS.iter().any(|f| changes.contains(*f)) {
        return Ok(None);
    }
    let mut map = serde_json::Map::new();
    let changed = |f: &str| changes.contains(f);
    if changed("name") {
        map.insert("name".into(), desired.name.clone().into());
    }
    if changed("description") {
        map.insert("description".into(), serde_json::json!(desired.description));
    }
    if changed("visibility") {
        map.insert("visibility".into(), serde_json::json!(desired.visibility));
    }
    if changed("upstream_url") || changed("upstream_url_credentials") {
        if let Some(url) = upstream_url_value(desired, secrets)? {
            map.insert("upstream_url".into(), url.into());
        }
    }
    if changed("quota_bytes") {
        map.insert("quota_bytes".into(), serde_json::json!(desired.quota_bytes));
    }
    if changed("custom_user_agent") {
        let ua = desired.custom_user_agent.clone().unwrap_or_default();
        map.insert("custom_user_agent".into(), ua.into());
    }
    if changed("curation_default_action") {
        map.insert(
            "curation_default_action".into(),
            desired.curation_default_action.clone().into(),
        );
    }
    for (field, value) in [
        ("promotion_only", desired.promotion_only),
        ("versioning_enabled", desired.versioning_enabled),
        ("curation_enabled", desired.curation_enabled),
    ] {
        if changed(field) {
            map.insert(field.into(), value.into());
        }
    }
    // Carried on every write: a public repository with credentials is
    // refused unless the document accepted that state (#4662).
    if desired.allow_public_with_upstream_credentials
        || changed("allow_public_with_upstream_credentials")
    {
        map.insert(
            "allow_public_with_upstream_credentials".into(),
            desired.allow_public_with_upstream_credentials.into(),
        );
    }
    Ok(Some(serde_json::Value::Object(map)))
}

/// `PUT .../upstream-auth` body for the desired upstream auth; `none` removes it.
pub fn upstream_auth_body(
    desired: &ConfigRepository,
    secrets: &BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let mut body = match &desired.upstream_auth {
        None => serde_json::json!({ "auth_type": "none" }),
        Some(auth) => {
            let password = match &auth.password {
                Some(secret) => Some(resolve_secret(secrets, secret)?),
                None => None,
            };
            serde_json::json!({
                "auth_type": auth.auth_type,
                "username": auth.username,
                "password": password,
                "aws": auth.aws,
            })
        }
    };
    if desired.allow_public_with_upstream_credentials {
        body["allow_public_with_upstream_credentials"] = true.into();
    }
    Ok(body)
}

/// `(mode, proxy_url, no_proxy)` for `PUT .../egress-proxy`; absent is `inherit`.
pub fn egress_proxy_body(
    desired: &ConfigRepository,
    secrets: &BTreeMap<String, String>,
) -> Result<(String, Option<String>, Option<String>)> {
    let Some(egress) = &desired.egress_proxy else {
        return Ok(("inherit".to_string(), None, None));
    };
    let proxy_url = match (&egress.proxy_url, &egress.proxy_credentials) {
        (Some(url), Some(secret)) => Some(with_userinfo(url, resolve_secret(secrets, secret)?)?),
        (url, _) => url.clone(),
    };
    Ok((egress.mode.clone(), proxy_url, egress.no_proxy.clone()))
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn remote(key: &str) -> ConfigRepository {
        serde_json::from_value(serde_json::json!({
            "key": key,
            "name": key,
            "format": "npm",
            "repo_type": "remote",
            "visibility": "private",
            "upstream_url": "https://registry.example.com/",
            "cache_ttl_seconds": 600,
            "on_upstream_not_found": "keep",
        }))
        .expect("remote fixture")
    }

    fn doc(repos: Vec<ConfigRepository>) -> ConfigDocument {
        ConfigDocument {
            schema_version: SCHEMA_VERSION,
            exported_at: None,
            producer: None,
            repositories: repos,
        }
    }

    fn by_key(repos: &[ConfigRepository]) -> BTreeMap<String, ConfigRepository> {
        repos.iter().map(|r| (r.key.clone(), r.clone())).collect()
    }

    fn keys(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn serialization_is_deterministic_and_sorted() {
        let mut v = remote("v");
        v.repo_type = "virtual".into();
        v.members = vec![
            ConfigVirtualMember {
                key: "b".into(),
                priority: 2,
            },
            ConfigVirtualMember {
                key: "z".into(),
                priority: 1,
            },
            ConfigVirtualMember {
                key: "a".into(),
                priority: 2,
            },
        ];
        let first = document(vec![remote("b"), v.clone(), remote("a")]);
        let second = document(vec![v, remote("a"), remote("b")]);
        let strip = |d: &ConfigDocument| {
            let mut d = d.clone();
            d.exported_at = None;
            serde_json::to_string(&d).unwrap()
        };
        assert_eq!(strip(&first), strip(&second));
        let keys: Vec<&str> = first.repositories.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["a", "b", "v"]);
        let members: Vec<&str> = first.repositories[2]
            .members
            .iter()
            .map(|m| m.key.as_str())
            .collect();
        assert_eq!(members, ["z", "a", "b"]);
        assert_eq!(first.schema_version, 1);
        assert!(first.producer.unwrap().starts_with("artifact-keeper "));
    }

    #[test]
    fn unknown_schema_version_is_refused() {
        for bad in [
            serde_json::json!({ "schema_version": 2, "repositories": [] }),
            serde_json::json!({ "schema_version": "1", "repositories": [] }),
            serde_json::json!({ "repositories": [] }),
        ] {
            let err = parse_document(bad).expect_err("must refuse");
            assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        }
        let ok = parse_document(serde_json::json!({ "schema_version": 1 })).unwrap();
        assert!(ok.repositories.is_empty());
        // A typo in a field name is refused rather than silently ignored.
        let typo = serde_json::json!({
            "schema_version": 1,
            "repositories": [{
                "key": "a", "name": "a", "format": "npm", "repo_type": "local",
                "visibility": "private", "cache_tll_seconds": 5
            }]
        });
        assert!(parse_document(typo).is_err());
    }

    #[test]
    fn plan_classifies_create_update_unchanged_and_not_in_document() {
        let same = remote("same");
        let mut changed = remote("changed");
        let mut changed_target = changed.clone();
        changed_target.cache_ttl_seconds = Some(60);
        changed.upstream_filter = Some(UpstreamFilter {
            include_patterns: vec!["^@acme/".into()],
            exclude_patterns: vec![],
        });
        let current = by_key(&[same.clone(), changed_target]);
        let target = keys(&["same", "changed", "extra"]);
        let p = plan(
            &doc(vec![same, changed, remote("new")]),
            &current,
            &target,
            &BTreeMap::new(),
        );
        assert_eq!(p.create, ["new"]);
        assert_eq!(
            p.update,
            [ConfigPlanUpdate {
                key: "changed".into(),
                changes: vec!["cache_ttl_seconds".into(), "upstream_filter".into()],
            }]
        );
        assert_eq!(p.unchanged, ["same"]);
        assert_eq!(p.not_in_document, ["extra"]);
        assert!(p.applicable && p.errors.is_empty() && p.missing_secrets.is_empty());
    }

    /// #5407: `cache_only` is exported and diffed; `online` is the absent default.
    #[test]
    fn upstream_mode_is_exported_only_when_cache_only_and_planned_as_a_change() {
        assert_eq!(upstream_mode_from_read(UpstreamMode::Online), None);
        assert_eq!(
            upstream_mode_from_read(UpstreamMode::CacheOnly),
            Some(UpstreamMode::CacheOnly)
        );
        let mut sealed = remote("sealed");
        sealed.upstream_mode = upstream_mode_from_read(UpstreamMode::CacheOnly);
        let json = serde_json::to_value(&sealed).unwrap();
        assert_eq!(json["upstream_mode"], "cache_only");
        assert!(serde_json::to_value(remote("online"))
            .unwrap()
            .get("upstream_mode")
            .is_none());
        let parsed: ConfigRepository = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.upstream_mode, Some(UpstreamMode::CacheOnly));

        let current = by_key(&[remote("sealed")]);
        let p = plan(
            &doc(vec![sealed.clone()]),
            &current,
            &keys(&["sealed"]),
            &BTreeMap::new(),
        );
        assert_eq!(
            p.update,
            [ConfigPlanUpdate {
                key: "sealed".into(),
                changes: vec!["upstream_mode".into()],
            }]
        );
        assert_eq!(upstream_mode_body(&sealed), UpstreamMode::CacheOnly);
        // Absent in the document puts a cache-only Remote back online.
        assert_eq!(upstream_mode_body(&remote("sealed")), UpstreamMode::Online);
    }

    #[test]
    fn plan_refuses_immutable_changes_unknown_members_and_duplicates() {
        let mut desired = remote("r");
        desired.format = "maven".into();
        desired.stale_if_error_grace_seconds = None;
        let mut now = remote("r");
        now.stale_if_error_grace_seconds = Some(30);
        let mut v = remote("v");
        v.repo_type = "virtual".into();
        v.members = vec![ConfigVirtualMember {
            key: "ghost".into(),
            priority: 1,
        }];
        let p = plan(
            &doc(vec![desired, v.clone(), v]),
            &by_key(&[now]),
            &keys(&["r"]),
            &BTreeMap::new(),
        );
        assert!(!p.applicable);
        let all = p.errors.join("\n");
        assert!(all.contains("format cannot be changed"), "{all}");
        assert!(all.contains("stale_if_error_grace_seconds"), "{all}");
        assert!(all.contains("member ghost"), "{all}");
        assert!(all.contains("appears twice"), "{all}");
        assert!(p.refusal_message().starts_with("config import refused"));
    }

    #[test]
    fn secret_refs_compare_equal_and_missing_secrets_fail_the_plan() {
        let mut desired = remote("r");
        desired.upstream_auth = upstream_auth_from_stored(
            "r",
            Some("basic"),
            Some(r#"{"username":"svc","password":"pw"}"#),
        );
        // The target already holds the same credential: nothing to supply.
        let p = plan(
            &doc(vec![desired.clone()]),
            &by_key(&[desired.clone()]),
            &keys(&["r"]),
            &BTreeMap::new(),
        );
        assert_eq!(p.unchanged, ["r"]);
        assert!(p.applicable);

        // The target lacks it: the plan names the secret and is not applicable.
        let p = plan(
            &doc(vec![desired.clone()]),
            &by_key(&[remote("r")]),
            &keys(&["r"]),
            &BTreeMap::new(),
        );
        assert_eq!(p.missing_secrets, ["upstream_auth/r"]);
        assert!(!p.applicable);
        assert!(p.refusal_message().contains("upstream_auth/r"));

        // Supplied: applicable, and the body carries the value.
        let secrets: BTreeMap<String, String> =
            [("upstream_auth/r".to_string(), "pw".to_string())].into();
        let p = plan(
            &doc(vec![desired.clone()]),
            &BTreeMap::new(),
            &keys(&[]),
            &secrets,
        );
        assert!(p.applicable, "{p:?}");
        let body = upstream_auth_body(&desired, &secrets).unwrap();
        assert_eq!(body["password"], "pw");
        assert_eq!(body["username"], "svc");
        assert!(upstream_auth_body(&desired, &BTreeMap::new()).is_err());
        let mut none = desired;
        none.upstream_auth = None;
        assert_eq!(
            upstream_auth_body(&none, &secrets).unwrap()["auth_type"],
            "none"
        );
    }

    #[test]
    fn url_credentials_round_trip_through_secrets() {
        let (url, creds) = upstream_url_fields("r", Some("https://h.example/x".into()), true);
        let mut desired = remote("r");
        desired.upstream_url = url;
        desired.upstream_url_credentials = creds;
        desired.egress_proxy = egress_proxy_from_read(
            "r",
            "explicit",
            Some("http://***@proxy.corp:3128/"),
            Some("internal.example".into()),
            true,
        );
        let secrets: BTreeMap<String, String> = [
            ("upstream_url/r".to_string(), "u:p%40ss".to_string()),
            ("egress_proxy/r".to_string(), "svc:pw".to_string()),
        ]
        .into();
        let body = create_body(&desired, &secrets).unwrap();
        assert_eq!(body["upstream_url"], "https://u:p%40ss@h.example/x");
        assert_eq!(body["format"], "npm");
        let (mode, proxy, no_proxy) = egress_proxy_body(&desired, &secrets).unwrap();
        assert_eq!(mode, "explicit");
        assert_eq!(proxy.as_deref(), Some("http://svc:pw@proxy.corp:3128/"));
        assert_eq!(no_proxy.as_deref(), Some("internal.example"));
        assert!(create_body(&desired, &BTreeMap::new()).is_err());
        assert!(with_userinfo("https://h/", "a@b").is_err());
        assert!(with_userinfo("no-scheme", "a:b").is_err());
        let mut inherit = desired.clone();
        inherit.egress_proxy = None;
        assert_eq!(egress_proxy_body(&inherit, &secrets).unwrap().0, "inherit");
        assert!(egress_proxy_from_read("r", "inherit", None, None, false).is_none());

        let changes = keys(&["upstream_url_credentials", "description", "quota_bytes"]);
        let patch = patch_body(&desired, &changes, &secrets).unwrap().unwrap();
        assert_eq!(patch["upstream_url"], "https://u:p%40ss@h.example/x");
        assert!(patch["description"].is_null() && patch["quota_bytes"].is_null());
        assert!(
            patch_body(&desired, &keys(&["cache_ttl_seconds"]), &secrets)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn apply_order_puts_virtual_repositories_last() {
        let mut v = remote("a-virtual");
        v.repo_type = "virtual".into();
        let d = doc(vec![v, remote("z"), remote("b")]);
        let order: Vec<&str> = apply_order(&d).iter().map(|r| r.key.as_str()).collect();
        assert_eq!(order, ["b", "z", "a-virtual"]);
    }

    /// Red team (#5292): a repository with every credential-bearing field set
    /// exports no secret value anywhere in the JSON.
    #[test]
    fn export_never_contains_a_secret_value() {
        const SECRETS: [&str; 5] = [
            "s3cr3t-basic-pw",
            "s3cr3t-bearer-token",
            "s3cr3t-url-pw",
            "s3cr3t-proxy-pw",
            "s3cr3t-unknown-type",
        ];
        // Credentials are assembled at run time so secret scanners do not
        // take these fixtures for real ones.
        let userinfo = |user: &str, pw: &str| format!("{user}:{pw}@");
        let stored_url = format!(
            "https://{}registry.example.com/npm",
            userinfo("svc", SECRETS[2])
        );
        let stored_url = stored_url.as_str();
        let redacted = crate::services::egress_proxy::redact_proxy_url(&format!(
            "http://{}proxy.corp:3128",
            userinfo("proxyuser", SECRETS[3])
        ));
        let mut repos = Vec::new();
        for (auth_type, stored) in [
            (
                "basic",
                serde_json::json!({"username": "svc", "pass\u{77}ord": SECRETS[0]}).to_string(),
            ),
            ("bearer", serde_json::json!({"token": SECRETS[1]}).to_string()),
            ("future", serde_json::json!({"anything": SECRETS[4]}).to_string()),
            (
                "aws_ecr",
                r#"{"region":"us-east-1","registry_id":"123456789012","secret":"s3cr3t-unknown-type"}"#
                    .to_string(),
            ),
        ] {
            let mut repo = remote(auth_type);
            let (stripped, has) = crate::services::proxy_service::strip_url_userinfo(stored_url);
            let (upstream_url, upstream_url_credentials) =
                upstream_url_fields(auth_type, Some(stripped), has);
            repo.upstream_url = upstream_url;
            repo.upstream_url_credentials = upstream_url_credentials;
            repo.egress_proxy =
                egress_proxy_from_read(auth_type, "explicit", Some(&redacted), None, true);
            repo.upstream_auth =
                upstream_auth_from_stored(auth_type, Some(auth_type), Some(stored.as_str()));
            repos.push(repo);
        }
        let json = serde_json::to_string(&document(repos)).unwrap();
        for secret in SECRETS {
            assert!(!json.contains(secret), "{secret} leaked into {json}");
        }
        assert!(
            !json.contains("proxyuser") && !json.contains("***"),
            "{json}"
        );
        assert!(json.contains(r#""secret_ref":"upstream_auth/basic""#));
        assert!(json.contains(r#""secret_ref":"upstream_url/basic""#));
        assert!(json.contains(r#""secret_ref":"egress_proxy/basic""#));
        assert!(json.contains(r#""username":"svc""#));
        assert!(json.contains(r#""region":"us-east-1""#));
    }
}
