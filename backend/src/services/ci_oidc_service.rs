//! CI OIDC provider service.
//!
//! Manages trusted CI/CD identity providers (GitLab, GitHub Actions, generic
//! OIDC) and validates CI-issued JWTs so pipelines can exchange them for
//! short-lived Artifact Keeper access tokens without storing static secrets.
//!
//! ## Identity Mapping model
//!
//! Each provider holds a priority-ordered list of **identity mappings**.
//! On token exchange the service evaluates mappings in priority order (lower
//! number = higher priority); the first enabled mapping whose `claim_filters`
//! all match the incoming JWT wins.  The mapping determines:
//!
//! * A **stable service account** keyed on the mapping itself — the same
//!   pipeline configuration always authenticates as the same service account
//!   regardless of the branch/ref, giving a clean audit trail.
//!
//! ## Service-account identity (#4031)
//!
//! The account is keyed on the mapping, never on the token: its `external_id`
//! is `ci:<provider_id>:<mapping_id>` and its username `ci-<12 hex of the
//! mapping UUID>`. The JWT `sub` embeds the ref (GitLab:
//! `project_path:{group}/{project}:ref_type:{type}:ref:{ref}`), so keying on
//! it gave every branch and tag its own identity while they all derived the
//! same username — the second ref to reach a mapping failed with
//! `409 "Username already exists"`. The subject now only feeds `display_name`
//! and the `security` log line of the exchange.
//!
//! The account is created together with its mapping, so it can be granted
//! access before any pipeline has run, and is deactivated (never deleted)
//! when the mapping is. Accounts minted by earlier versions (`ci-<8 hex>`,
//! keyed on a raw subject) are rewritten by migration 232 and, where the
//! migration could not attribute them, adopted on first use by
//! [`CiOidcService::resolve_service_account`].

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::RwLock;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::escape_like_literal;
use crate::error::{AppError, Result};
use crate::models::user::AuthProvider;
use crate::services::auth_service::{
    invalidate_user_token_cache_entries, invalidate_user_tokens, FederatedCredentials,
};

// ---------------------------------------------------------------------------
// DB models
// ---------------------------------------------------------------------------

/// Column list of `ci_oidc_providers`, in [`CiOidcProvider`] field order.
///
/// A macro, not a `const`: sqlx 0.9 accepts only `&'static str` as a
/// statement, so the fragments have to be spliced by `concat!` at compile
/// time. Mirrors `lifecycle_service::exclusion_predicate!`.
macro_rules! provider_columns {
    () => {
        "id, name, provider_type, issuer_url, audience, is_enabled, created_at, updated_at, \
         key_source, static_jwks"
    };
}

/// Column list of `ci_oidc_identity_mappings`, in [`CiOidcIdentityMapping`]
/// field order. Shared by every statement that selects or returns a mapping,
/// so a column added to one cannot go missing from another.
macro_rules! mapping_columns {
    () => {
        "id, provider_id, name, priority, claim_filters, allowed_repo_ids, \
         is_enabled, created_at, updated_at, group_binding_ids"
    };
}

/// Projection behind [`ProviderResponseRow`]: a provider joined with its
/// mapping count. The two provider read paths differ only in the filter and
/// ordering they append to it.
macro_rules! provider_response_select {
    () => {
        concat!(
            "SELECT p.id, p.name, p.provider_type, p.issuer_url, p.audience, ",
            "p.is_enabled, p.created_at, p.updated_at, p.key_source, p.static_jwks, ",
            "COUNT(m.id) AS mapping_count ",
            "FROM ci_oidc_providers p ",
            "LEFT JOIN ci_oidc_identity_mappings m ON m.provider_id = p.id "
        )
    };
}

/// Load one mapping by `(id, provider_id)`. The `provider_id` conjunct is
/// load-bearing: it is what stops a mapping being read or edited through a
/// sibling provider's route.
macro_rules! select_mapping_by_id {
    () => {
        concat!(
            "SELECT ",
            mapping_columns!(),
            " FROM ci_oidc_identity_mappings WHERE id = $1 AND provider_id = $2"
        )
    };
}

/// A row from `ci_oidc_providers` (provider-level claim columns dropped in
/// migration 087).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CiOidcProvider {
    pub id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub issuer_url: String,
    pub audience: String,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// [`KEY_SOURCE_DISCOVERY`] or [`KEY_SOURCE_STATIC`] (migration 257).
    pub key_source: String,
    /// The JWKS a `static` provider verifies against; `None` otherwise.
    pub static_jwks: Option<serde_json::Value>,
}

/// Keys are found through `{issuer_url}/.well-known/openid-configuration`.
pub const KEY_SOURCE_DISCOVERY: &str = "discovery";
/// Keys are the JWKS stored on the provider; the issuer is never contacted.
pub const KEY_SOURCE_STATIC: &str = "static";

/// Members of a JWK that carry private key material (RFC 7518 §6.2.2, §6.3.2,
/// §6.4.1). A trust anchor needs none of them, and an operator who pasted one
/// has leaked the key, so storing it would only make things worse.
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Most keys a static JWKS may hold. A cluster publishes one or two (two
/// during a rotation overlap); the set is echoed in every provider response
/// and scanned on every exchange, so a bound keeps a paste mistake small.
pub const MAX_STATIC_JWKS_KEYS: usize = 16;

/// Largest static JWKS accepted, serialized. A 4096-bit RSA JWK is under
/// 1 KiB, so this leaves room for certificate chains (`x5c`) on every key.
pub const MAX_STATIC_JWKS_BYTES: usize = 64 * 1024;

/// Throttles the WARN for a token whose `kid` is not in a static JWKS to one
/// per provider per minute; repeats within the window log at DEBUG. The
/// exchange endpoint is unauthenticated and a forged token only needs the
/// provider's issuer, so without this anyone could flood the `security` log.
/// Keyed by provider id, of which there are few, so the map stays small.
static UNKNOWN_KID_WARNINGS: std::sync::LazyLock<crate::api::middleware::rate_limit::RateLimiter> =
    std::sync::LazyLock::new(|| crate::api::middleware::rate_limit::RateLimiter::new(1, 60));

/// `iss` / `aud` read out of an assertion that has NOT been verified yet,
/// used only to choose which configured provider to verify it against (#3548).
struct UnverifiedAssertionHints {
    issuer: String,
    audiences: Vec<String>,
}

/// Compare issuer URLs ignoring a trailing slash.
///
/// The same normalisation [`CiOidcService::fetch_discovery`] applies before
/// appending `/.well-known/openid-configuration`, so a row configured as
/// `https://gitlab.example.com/` resolves the assertions its own discovery
/// document covers. Resolution is deliberately the only place this is
/// relaxed: `validate_ci_jwt` still requires the exact configured `iss`, so
/// normalising here can select a provider but never accept a token.
fn normalize_issuer(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

/// Resolve one `claim_filters` key against verified claims.
///
/// A key beginning with `/` is an RFC 6901 JSON Pointer
/// (`/kubernetes.io/namespace`), so claims nested inside objects can be
/// matched. Any other key names a top-level claim, as it always has: dot paths
/// would be ambiguous, because `kubernetes.io` and URL-shaped claim names
/// contain dots themselves. A top-level claim whose own name starts with `/`
/// stays reachable as `/~1name`.
pub fn claim_value<'a>(claims: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    if key.starts_with('/') {
        claims.pointer(key)
    } else {
        claims.get(key)
    }
}

/// Refuse a `claim_filters` key that starts with `/` but is not a valid JSON
/// Pointer. `serde_json::Value::pointer` does not reject a stray `~` (it
/// would look up a member literally named `~2bad`), so without this check a
/// typo would save fine and then silently never match.
fn validate_claim_filter_keys(claim_filters: &serde_json::Value) -> Result<()> {
    let Some(map) = claim_filters.as_object() else {
        return Ok(());
    };
    for key in map.keys().filter(|k| k.starts_with('/')) {
        let mut chars = key.chars();
        while let Some(c) = chars.next() {
            if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                return Err(AppError::Validation(format!(
                    "claim_filters key '{key}' is not a valid JSON Pointer: \
                     '~' must be followed by '0' or '1'"
                )));
            }
        }
    }
    Ok(())
}

/// A row from `ci_oidc_identity_mappings`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CiOidcIdentityMapping {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub name: String,
    pub priority: i32,
    /// JSONB claim-filter map.  Each key is a top-level claim name, or a JSON
    /// Pointer into nested claims when it starts with `/`; the value is either
    /// a single value (exact match) or an array (any-of match).
    pub claim_filters: serde_json::Value,
    /// Optional repository restriction for this mapping.
    /// `None` = unrestricted, `Some(vec![])` = deny all repos.
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// The mapping's group binding (design D2 of add-ci-oidc-mapping-grants).
    /// Three states, not two:
    /// `None` = absent, the mapping makes no claim and nothing reconciles;
    /// `Some(vec![])` = empty, declared "no memberships", reconciles and
    /// strips everything; `Some(ids)` = declared exactly these groups.
    pub group_binding_ids: Option<Vec<Uuid>>,
}

// ---------------------------------------------------------------------------
// API request / response types — providers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCiOidcProviderRequest {
    pub name: String,
    /// One of `gitlab`, `github`, `kubernetes` or `generic` (the default),
    /// matched case-insensitively and stored lowercase; any other value, a
    /// typo such as `k8s` included, is refused with 400. `kubernetes` mints a
    /// read-only access token with no refresh token and logs the workload of
    /// each exchange. On update, a provider created before the type was
    /// checked may send its stored value back unchanged.
    pub provider_type: Option<String>,
    pub issuer_url: String,
    pub audience: Option<String>,
    pub is_enabled: Option<bool>,
    /// `discovery` (the default) finds signing keys through the issuer's
    /// OIDC discovery document. `static` verifies only against
    /// `static_jwks` and never contacts the issuer; use it when the issuer is
    /// not reachable from Artifact Keeper, such as an on-prem Kubernetes
    /// cluster.
    pub key_source: Option<String>,
    /// The JWKS a `static` provider verifies against (`{"keys": [...]}`, for
    /// example the output of `kubectl get --raw /openid/v1/jwks`). Required
    /// with `key_source: static`, refused otherwise. Public RSA or EC keys
    /// only, with unique `kid`s.
    #[schema(value_type = Option<Object>)]
    pub static_jwks: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCiOidcProviderRequest {
    pub name: Option<String>,
    /// See [`CreateCiOidcProviderRequest::provider_type`].
    pub provider_type: Option<String>,
    pub issuer_url: Option<String>,
    pub audience: Option<String>,
    pub is_enabled: Option<bool>,
    /// Omit to keep the current key source. Switching to `discovery`
    /// discards the stored JWKS; switching to `static` requires
    /// `static_jwks`.
    pub key_source: Option<String>,
    /// Replaces the stored JWKS as a whole. Omit to keep it. Only accepted
    /// when the resulting key source is `static`.
    #[schema(value_type = Option<Object>)]
    pub static_jwks: Option<serde_json::Value>,
}

/// A `ci_oidc_providers` row joined with its mapping count, as both
/// [`CiOidcService::list`] and [`CiOidcService::get_response`] select it.
/// One type and one conversion, so the two cannot drift apart.
#[derive(sqlx::FromRow)]
struct ProviderResponseRow {
    id: Uuid,
    name: String,
    provider_type: String,
    issuer_url: String,
    audience: String,
    is_enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    key_source: String,
    static_jwks: Option<serde_json::Value>,
    mapping_count: i64,
}

impl From<ProviderResponseRow> for CiOidcProviderResponse {
    fn from(r: ProviderResponseRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            provider_type: r.provider_type,
            issuer_url: r.issuer_url,
            audience: r.audience,
            is_enabled: r.is_enabled,
            key_source: r.key_source,
            static_jwks: r.static_jwks,
            mapping_count: r.mapping_count,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct CiOidcProviderResponse {
    pub id: Uuid,
    pub name: String,
    /// The stored type: `gitlab`, `github`, `kubernetes` or `generic`. A
    /// provider created before the type was checked may still hold another
    /// value, which acts as `generic`.
    pub provider_type: String,
    pub issuer_url: String,
    pub audience: String,
    pub is_enabled: bool,
    /// `discovery` or `static`.
    pub key_source: String,
    /// The stored JWKS of a `static` provider; `null` for `discovery`.
    #[schema(value_type = Option<Object>)]
    pub static_jwks: Option<serde_json::Value>,
    pub mapping_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Result of [`CiOidcService::update`]: the provider as stored, and whether
/// its key source or static JWKS changed, so the caller, which knows the
/// acting admin, can emit [`log_key_source_change`].
pub struct ProviderUpdate {
    pub provider: CiOidcProviderResponse,
    pub key_material_changed: bool,
    /// The previous `provider_type` when this update changed it, so the
    /// caller can emit [`log_provider_type_change`].
    pub previous_provider_type: Option<String>,
}

/// Provider types a create or update accepts. Only `kubernetes` changes the
/// credentials minted (read-only, no refresh token), so an unrecognised value
/// is refused instead of silently behaving as `generic`.
pub const PROVIDER_TYPES: &[&str] = &["gitlab", "github", "kubernetes", "generic"];

/// Trim and lowercase a requested `provider_type`, then require it to be one
/// of [`PROVIDER_TYPES`]. `Kubernetes` is stored as `kubernetes`; `k8s` is a
/// 400 rather than a push-capable, renewable `generic` provider.
fn normalize_provider_type(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if PROVIDER_TYPES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(AppError::Validation(format!(
            "Unknown provider_type '{raw}': expected one of {}",
            PROVIDER_TYPES.join(", ")
        )))
    }
}

/// The `provider_type` an update stores: the stored one when the request
/// omits it or sends the stored value back unchanged, else the normalised
/// request. Echoing the stored value is accepted even when it is not one of
/// [`PROVIDER_TYPES`], because a provider created while the type was free text
/// may hold such a value and a client (the web UI included) re-sends the whole
/// provider on every edit; only a create or a change of type is checked.
fn resolve_updated_provider_type(requested: Option<&str>, stored: &str) -> Result<String> {
    match requested {
        None => Ok(stored.to_string()),
        Some(raw) if raw == stored => Ok(stored.to_string()),
        Some(raw) => normalize_provider_type(raw),
    }
}

/// The `security` line for an update that changed a provider's
/// `provider_type`. Moving off `kubernetes` lifts the read-only ceiling and
/// the no-refresh rule for every credential the provider mints from then on.
pub fn log_provider_type_change(
    provider: &CiOidcProviderResponse,
    previous: &str,
    admin_id: Uuid,
    admin_username: &str,
) {
    tracing::info!(
        target: "security",
        provider_id = %provider.id,
        provider_name = %provider.name,
        admin_id = %admin_id,
        admin = %admin_username,
        previous_provider_type = %previous,
        provider_type = %provider.provider_type,
        "CI OIDC: provider type changed"
    );
}

/// `kid`s of a JWKS, in order; a key without one is shown as `-`.
fn jwks_kids(jwks: &serde_json::Value) -> Vec<String> {
    jwks["keys"]
        .as_array()
        .map(|keys| {
            keys.iter()
                .map(|k| k["kid"].as_str().unwrap_or("-").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The `security` line for a create or update that set or changed a
/// provider's key source or static JWKS (spec "Key-source changes are
/// logged"). CI OIDC admin actions write no audit records, and a static JWKS
/// is a hand-entered trust anchor, so this line is what makes a change to it
/// attributable.
pub fn log_key_source_change(
    provider: &CiOidcProviderResponse,
    admin_id: Uuid,
    admin_username: &str,
) {
    let kids = provider
        .static_jwks
        .as_ref()
        .map(jwks_kids)
        .unwrap_or_default()
        .join(", ");
    tracing::info!(
        target: "security",
        provider_id = %provider.id,
        provider_name = %provider.name,
        admin_id = %admin_id,
        admin = %admin_username,
        key_source = %provider.key_source,
        kids = %kids,
        "CI OIDC: provider key source set"
    );
}

/// Decide the key source and static JWKS a create or update stores, and
/// validate them. `existing` is the stored `(key_source, static_jwks)` on
/// update and `None` on create.
///
/// A JWKS sent with a resulting `discovery` source is refused rather than
/// silently dropped; switching to `discovery` discards the stored one.
fn resolve_key_material(
    key_source: Option<String>,
    static_jwks: Option<serde_json::Value>,
    existing: Option<(&str, Option<&serde_json::Value>)>,
) -> Result<(String, Option<serde_json::Value>)> {
    let source = key_source
        .or_else(|| existing.map(|(s, _)| s.to_owned()))
        .unwrap_or_else(|| KEY_SOURCE_DISCOVERY.to_owned());
    match source.as_str() {
        KEY_SOURCE_DISCOVERY => {
            if static_jwks.is_some() {
                return Err(AppError::Validation(
                    "static_jwks is only accepted with key_source 'static'".into(),
                ));
            }
            Ok((source, None))
        }
        KEY_SOURCE_STATIC => {
            let jwks = static_jwks
                .or_else(|| existing.and_then(|(_, j)| j.cloned()))
                .ok_or_else(|| {
                    AppError::Validation("key_source 'static' requires static_jwks".into())
                })?;
            validate_static_jwks(&jwks)?;
            Ok((source, Some(jwks)))
        }
        other => Err(AppError::Validation(format!(
            "Unknown key_source '{other}': expected 'discovery' or 'static'"
        ))),
    }
}

/// Refuse a static JWKS that could not serve as a trust anchor: not an
/// object with a non-empty `keys` array, a key that is not a parseable
/// public RSA or EC key, private key material, or two keys sharing a `kid`
/// (which would make strict `kid` selection ambiguous).
fn validate_static_jwks(jwks: &serde_json::Value) -> Result<()> {
    let invalid = |why: String| AppError::Validation(format!("Invalid static_jwks: {why}"));
    let size = serde_json::to_vec(jwks).map_or(usize::MAX, |bytes| bytes.len());
    if size > MAX_STATIC_JWKS_BYTES {
        return Err(invalid(format!(
            "{size} bytes exceeds the limit of {MAX_STATIC_JWKS_BYTES}"
        )));
    }
    let keys = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or_else(|| invalid("expected a JSON object with a non-empty \"keys\" array".into()))?;
    if keys.len() > MAX_STATIC_JWKS_KEYS {
        return Err(invalid(format!(
            "{} keys exceeds the limit of {MAX_STATIC_JWKS_KEYS}",
            keys.len()
        )));
    }

    let mut seen = std::collections::HashSet::new();
    for (i, key) in keys.iter().enumerate() {
        let kid = key.get("kid").and_then(serde_json::Value::as_str);
        let label = kid.map_or_else(|| format!("key {i}"), |k| format!("key '{k}'"));
        if !key.is_object() {
            return Err(invalid(format!("{label} is not a JSON object")));
        }
        if let Some(member) = PRIVATE_JWK_MEMBERS.iter().find(|m| key.get(**m).is_some()) {
            return Err(invalid(format!(
                "{label} contains the private member '{member}'; private key material is \
                 not accepted, supply the public key only"
            )));
        }
        CiOidcService::decoding_key_from_jwk(key)
            .map_err(|e| invalid(format!("{label} is not a supported public key: {e}")))?;
        if !seen.insert(kid) {
            return Err(invalid(format!(
                "two keys share the kid {}",
                kid.map_or_else(|| "(none)".to_owned(), |k| format!("'{k}'"))
            )));
        }
    }
    Ok(())
}

/// Body for toggle endpoint.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CiOidcToggleRequest {
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// API request / response types — identity mappings
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCiOidcMappingRequest {
    pub name: String,
    pub priority: Option<i32>,
    pub claim_filters: serde_json::Value,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: Option<bool>,
    /// The mapping's group binding: the groups its service account SHALL
    /// hold membership of (design D1, D2). Omit or send `null` for no
    /// binding at all — the mapping confers nothing and nothing reconciles,
    /// exactly today's behaviour. Send `[]` to declare "no memberships"
    /// (reconciles, strips any hand-wired membership). Send a non-empty list
    /// to declare exactly those groups. Every id must already exist; an
    /// unknown id refuses the whole create (design D5, "A binding names
    /// existing groups only").
    pub group_binding_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCiOidcMappingRequest {
    pub name: Option<String>,
    pub priority: Option<i32>,
    pub claim_filters: Option<serde_json::Value>,
    /// Repository restriction update. Three-way semantics (#4198): omit the
    /// field to leave the restriction unchanged; send `null` to clear it
    /// (the mapping becomes unrestricted — all repositories); send an array
    /// to restrict (`[]` denies every repository).
    #[serde(
        default,
        deserialize_with = "crate::api::extractors::deserialize_double_option"
    )]
    #[schema(value_type = Option<Vec<Uuid>>)]
    pub allowed_repo_ids: Option<Option<Vec<Uuid>>>,
    pub is_enabled: Option<bool>,
    /// Three-way semantics via `Option<Option<Vec<Uuid>>>` (mirrors
    /// `trusted_gpg_key` in `repositories.rs`): omit the field to leave the
    /// stored binding unchanged; send `null` to clear it back to absent (the
    /// mapping stops reconciling); send `[]` or a list of group ids to
    /// declare that binding (validated the same way as on create).
    #[serde(
        default,
        deserialize_with = "crate::api::extractors::deserialize_double_option"
    )]
    #[schema(value_type = Option<Vec<Uuid>>)]
    pub group_binding_ids: Option<Option<Vec<Uuid>>>,
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct CiOidcMappingResponse {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub name: String,
    pub priority: i32,
    pub claim_filters: serde_json::Value,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// `users.id` of the service account every exchange matching this mapping
    /// authenticates as. Grant it access (e.g. a group membership) directly;
    /// there is no need to run a pipeline first or read it out of a job log.
    ///
    /// `null` only for a mapping created by an earlier version whose account
    /// has not been attributed to it yet; it is filled in on first use.
    pub service_account_id: Option<Uuid>,
    /// Username of that service account (`ci-<hex>`), as returned in the
    /// token exchange's `username` field.
    pub service_account_username: Option<String>,
    /// The mapping's group binding, so what a pipeline may do is answerable
    /// from the mapping alone. `null` = no binding declared (this mapping
    /// confers nothing beyond whatever RBAC the account otherwise holds);
    /// `[]` = binding declared empty; a list = the groups it confers.
    pub group_binding_ids: Option<Vec<Uuid>>,
}

impl CiOidcMappingResponse {
    fn new(m: CiOidcIdentityMapping, account: Option<ServiceAccountRow>) -> Self {
        let (service_account_id, service_account_username) = match account {
            Some(a) => (Some(a.id), Some(a.username)),
            None => (None, None),
        };
        Self {
            id: m.id,
            provider_id: m.provider_id,
            name: m.name,
            priority: m.priority,
            claim_filters: m.claim_filters,
            allowed_repo_ids: m.allowed_repo_ids,
            is_enabled: m.is_enabled,
            created_at: m.created_at,
            updated_at: m.updated_at,
            service_account_id,
            service_account_username,
            group_binding_ids: m.group_binding_ids,
        }
    }
}

/// Outcome of reconciling one CI service account's group memberships to its
/// mapping's binding (design D3, D4, D5). Returned for logging and tests;
/// not part of the public API response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupBindingReconcileReport {
    pub added: Vec<Uuid>,
    pub removed: Vec<Uuid>,
    /// Ids in the binding that no longer exist in `groups`.
    pub dangling: Vec<Uuid>,
}

// ---------------------------------------------------------------------------
// Service-account identity
// ---------------------------------------------------------------------------

/// Hex characters of the mapping UUID in a newly derived service-account
/// username. Accounts minted before the identity key moved to the mapping
/// carry [`LEGACY_SHORT_ID_LEN`] and keep it: the username is a display and
/// lookup handle now, not an identity key, so it is never rewritten.
const SHORT_ID_LEN: usize = 12;
/// Short-id length of the `ci-<hex>` usernames earlier versions derived. It is
/// exactly the first group of the UUID's text form, which is what makes the
/// reverse lookup `id::text LIKE '<8hex>-%'` exact (migration 232).
const LEGACY_SHORT_ID_LEN: usize = 8;

fn username_with_short_id(mapping_id: Uuid, len: usize) -> String {
    let hex = mapping_id.simple().to_string();
    format!("ci-{}", &hex[..len])
}

/// Username of the service account a mapping provisions.
pub fn service_account_username(mapping_id: Uuid) -> String {
    username_with_short_id(mapping_id, SHORT_ID_LEN)
}

/// Username earlier versions derived for the same mapping.
fn legacy_service_account_username(mapping_id: Uuid) -> String {
    username_with_short_id(mapping_id, LEGACY_SHORT_ID_LEN)
}

/// `users.external_id` of a mapping's service account: the identity key.
///
/// Derived from the mapping alone, so no claim of a presented token can
/// select a different account. The provider prefix is not needed for
/// uniqueness; it keeps the stored value self-describing and textually
/// distinct from the SSO keys sharing the column.
pub fn service_account_external_id(provider_id: Uuid, mapping_id: Uuid) -> String {
    format!("ci:{provider_id}:{mapping_id}")
}

/// Exchange refused because the mapping's account cannot be told apart.
fn ambiguous_account(mapping_id: Uuid, candidates: usize) -> AppError {
    tracing::warn!(
        target: "security",
        mapping_id = %mapping_id,
        candidates,
        "CI OIDC: several accounts could belong to this identity mapping; refusing \
         rather than guessing. Resolve by re-keying or removing the wrong ones"
    );
    AppError::Authentication(
        "The service account for this CI identity mapping is ambiguous; \
         an administrator must resolve it"
            .into(),
    )
}

/// Exchange refused because the mapping's account has been deactivated.
///
/// Deactivation is the kill switch for a CI principal: deleting the mapping
/// sets it, and so can an administrator. The exchange must neither mint for
/// the account nor fall through to creating a fresh one, which would hand the
/// pipeline a new principal and undo the deactivation (#4031).
fn inactive_account(mapping_id: Uuid, user_id: Uuid) -> AppError {
    tracing::warn!(
        target: "security",
        mapping_id = %mapping_id,
        user_id = %user_id,
        "CI OIDC: the service account for this identity mapping is deactivated; \
         refusing the exchange"
    );
    AppError::Authentication(
        "The service account for this CI identity mapping is deactivated".into(),
    )
}

/// Mapping creation refused because its derived account name is in use.
fn username_taken(username: &str) -> AppError {
    AppError::Conflict(format!(
        "Cannot create identity mapping: its service account username '{username}' \
         is already taken by an existing account"
    ))
}

fn service_account_email(username: &str) -> String {
    format!("{username}@ci.artifact-keeper.internal")
}

/// The slice of a `users` row the mapping API and the exchange need.
#[derive(Debug, Clone, sqlx::FromRow)]
struct ServiceAccountRow {
    id: Uuid,
    username: String,
    email: String,
    external_id: Option<String>,
    is_active: bool,
}

// ---------------------------------------------------------------------------
// JWKS cache entry
// ---------------------------------------------------------------------------

struct JwksCacheEntry {
    keys: serde_json::Value,
    fetched_at: Instant,
}

const JWKS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// How long to wait for OIDC discovery and JWKS endpoint responses before
/// treating the request as failed. Prevents a slow or unreachable provider
/// from holding an Axum worker indefinitely.
const OIDC_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Process-wide JWKS cache shared across all `CiOidcService` instances.
///
/// Keyed by JWKS URI; entries expire after [`JWKS_CACHE_TTL`].  Using a
/// global avoids the per-request cache-miss that occurred when the cache
/// was a field on the short-lived `CiOidcService` struct.
static JWKS_CACHE: OnceLock<RwLock<HashMap<String, JwksCacheEntry>>> = OnceLock::new();

fn jwks_cache() -> &'static RwLock<HashMap<String, JwksCacheEntry>> {
    JWKS_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// CI OIDC provider service.
pub struct CiOidcService {
    db: PgPool,
    http: reqwest::Client,
}

/// The claim checks every exchanged CI assertion must pass, whatever the
/// provider type and key source: signature algorithm, `iss`, `aud`, `exp`,
/// and `nbf` (#4511). `jsonwebtoken` leaves `nbf` unchecked by default, so a
/// token that is not valid yet used to be accepted. Both time claims share the
/// library's default leeway (60 s), so ordinary clock skew between the issuer
/// and this server is tolerated in both directions.
fn ci_jwt_validation(alg: Algorithm, provider: &CiOidcProvider) -> Validation {
    let mut validation = Validation::new(alg);
    validation.set_audience(&[provider.audience.as_str()]);
    validation.set_issuer(&[provider.issuer_url.as_str()]);
    validation.validate_nbf = true;
    validation
}

impl CiOidcService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            // SSO trust class: CI-OIDC discovery/JWKS fetches target an
            // operator-configured identity provider (the same class as the
            // SSO/OIDC login path), so the connect-time SSRF check honors
            // SSO_ALLOW_PRIVATE_IPS / AK_SSRF_ALLOW_PRIVATE_CIDRS instead of
            // the fail-closed upstream default (issue #2405). Cloud-metadata,
            // loopback and link-local addresses stay hard-blocked regardless.
            http: crate::services::http_client::sso_client(),
        }
    }

    // -----------------------------------------------------------------------
    // Provider CRUD
    // -----------------------------------------------------------------------

    pub async fn list(&self) -> Result<Vec<CiOidcProviderResponse>> {
        let rows = sqlx::query_as::<_, ProviderResponseRow>(concat!(
            provider_response_select!(),
            "GROUP BY p.id ORDER BY p.created_at ASC"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<CiOidcProvider> {
        sqlx::query_as::<_, CiOidcProvider>(concat!(
            "SELECT ",
            provider_columns!(),
            " FROM ci_oidc_providers WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("CI OIDC provider not found".into()))
    }

    /// Get a provider as a `CiOidcProviderResponse` (includes mapping_count).
    pub async fn get_response(&self, id: Uuid) -> Result<CiOidcProviderResponse> {
        sqlx::query_as::<_, ProviderResponseRow>(concat!(
            provider_response_select!(),
            "WHERE p.id = $1 GROUP BY p.id"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .map(Into::into)
        .ok_or_else(|| AppError::NotFound("CI OIDC provider not found".into()))
    }

    pub async fn create(&self, req: CreateCiOidcProviderRequest) -> Result<CiOidcProviderResponse> {
        let provider_type = match req.provider_type.as_deref() {
            Some(raw) => normalize_provider_type(raw)?,
            None => "generic".to_string(),
        };
        let audience = req.audience.unwrap_or_else(|| "artifact-keeper".into());
        let is_enabled = req.is_enabled.unwrap_or(true);
        let (key_source, static_jwks) =
            resolve_key_material(req.key_source, req.static_jwks, None)?;

        let id = sqlx::query_scalar::<_, Uuid>(
            r#"INSERT INTO ci_oidc_providers
                    (name, provider_type, issuer_url, audience, is_enabled, key_source, static_jwks)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id"#,
        )
        .bind(&req.name)
        .bind(&provider_type)
        .bind(&req.issuer_url)
        .bind(&audience)
        .bind(is_enabled)
        .bind(&key_source)
        .bind(&static_jwks)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        self.get_response(id).await
    }

    /// Update a provider. Key material is resolved and validated before
    /// anything is written, so a refused JWKS leaves the provider unchanged.
    ///
    /// The read and the write share one transaction with the row locked, so
    /// two concurrent updates serialise: each merges its fields onto the
    /// other's result, and `key_material_changed` / `previous_provider_type`
    /// (which drive the `security` log lines) compare against the row this
    /// update actually replaced.
    pub async fn update(
        &self,
        id: Uuid,
        req: UpdateCiOidcProviderRequest,
    ) -> Result<ProviderUpdate> {
        let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
        let mut tx = self.db.begin().await.map_err(db_err)?;
        let existing = sqlx::query_as::<_, CiOidcProvider>(concat!(
            "SELECT ",
            provider_columns!(),
            " FROM ci_oidc_providers WHERE id = $1 FOR UPDATE"
        ))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AppError::NotFound("CI OIDC provider not found".into()))?;
        let provider_type =
            resolve_updated_provider_type(req.provider_type.as_deref(), &existing.provider_type)?;
        let previous_provider_type =
            (provider_type != existing.provider_type).then(|| existing.provider_type.clone());
        let (key_source, static_jwks) = resolve_key_material(
            req.key_source,
            req.static_jwks,
            Some((&existing.key_source, existing.static_jwks.as_ref())),
        )?;
        let key_material_changed =
            key_source != existing.key_source || static_jwks != existing.static_jwks;

        sqlx::query(
            r#"UPDATE ci_oidc_providers
               SET name          = $2,
                   provider_type = $3,
                   issuer_url    = $4,
                   audience      = $5,
                   is_enabled    = $6,
                   key_source    = $7,
                   static_jwks   = $8,
                   updated_at    = NOW()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(req.name.unwrap_or(existing.name))
        .bind(&provider_type)
        .bind(req.issuer_url.unwrap_or(existing.issuer_url))
        .bind(req.audience.unwrap_or(existing.audience))
        .bind(req.is_enabled.unwrap_or(existing.is_enabled))
        .bind(&key_source)
        .bind(&static_jwks)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;

        Ok(ProviderUpdate {
            provider: self.get_response(id).await?,
            key_material_changed,
            previous_provider_type,
        })
    }

    /// Delete a provider. Its mappings go with it (`ON DELETE CASCADE`), so
    /// their service accounts are deactivated exactly as
    /// [`Self::delete_mapping`] would; the ids are returned for the same
    /// refresh-token revocation.
    pub async fn delete(&self, id: Uuid) -> Result<Vec<Uuid>> {
        self.delete_and_deactivate(
            "DELETE FROM ci_oidc_providers WHERE id = $1",
            &[id],
            format!("{}%", escape_like_literal(&format!("ci:{id}:"))),
            "CI OIDC provider not found",
        )
        .await
    }

    pub async fn toggle(&self, id: Uuid, enabled: bool) -> Result<CiOidcProviderResponse> {
        let result = sqlx::query(
            "UPDATE ci_oidc_providers SET is_enabled = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(enabled)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("CI OIDC provider not found".into()));
        }
        self.get_response(id).await
    }

    // -----------------------------------------------------------------------
    // Mapping CRUD
    // -----------------------------------------------------------------------

    pub async fn list_mappings(&self, provider_id: Uuid) -> Result<Vec<CiOidcMappingResponse>> {
        self.get(provider_id).await?;
        let rows = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "SELECT ",
            mapping_columns!(),
            " FROM ci_oidc_identity_mappings WHERE provider_id = $1 ",
            "ORDER BY priority ASC, created_at ASC"
        ))
        .bind(provider_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let keys: Vec<String> = rows
            .iter()
            .map(|m| service_account_external_id(m.provider_id, m.id))
            .collect();
        let mut accounts: HashMap<String, ServiceAccountRow> = self
            .fetch_service_accounts(&keys)
            .await?
            .into_iter()
            .filter_map(|a| a.external_id.clone().map(|k| (k, a)))
            .collect();
        Ok(rows
            .into_iter()
            .map(|m| {
                let account = accounts.remove(&service_account_external_id(m.provider_id, m.id));
                CiOidcMappingResponse::new(m, account)
            })
            .collect())
    }

    /// Load one mapping by `(mapping_id, provider_id)`, or 404. Shared by the
    /// read endpoint and the update path, which need exactly this.
    async fn fetch_mapping_row(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
    ) -> Result<CiOidcIdentityMapping> {
        sqlx::query_as::<_, CiOidcIdentityMapping>(select_mapping_by_id!())
            .bind(mapping_id)
            .bind(provider_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("CI OIDC identity mapping not found".into()))
    }

    /// CI accounts carrying any of `external_ids`.
    async fn fetch_service_accounts(
        &self,
        external_ids: &[String],
    ) -> Result<Vec<ServiceAccountRow>> {
        sqlx::query_as::<_, ServiceAccountRow>(
            "SELECT id, username, email, external_id, is_active FROM users \
             WHERE auth_provider = 'ci' AND external_id = ANY($1)",
        )
        .bind(external_ids)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Pair a mapping row with its service account for an API response.
    async fn mapping_response(&self, m: CiOidcIdentityMapping) -> Result<CiOidcMappingResponse> {
        let key = service_account_external_id(m.provider_id, m.id);
        let account = self
            .fetch_service_accounts(std::slice::from_ref(&key))
            .await?
            .into_iter()
            .next();
        Ok(CiOidcMappingResponse::new(m, account))
    }

    pub async fn get_mapping(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
    ) -> Result<CiOidcMappingResponse> {
        let row = self.fetch_mapping_row(provider_id, mapping_id).await?;
        self.mapping_response(row).await
    }

    /// Refuse a group binding naming a group that does not exist (design D5,
    /// "A binding names existing groups only"). Called before any write, so a
    /// bad id creates neither a mapping nor a group.
    async fn validate_group_binding_ids(&self, ids: &[Uuid]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let existing: std::collections::HashSet<Uuid> =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM groups WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .into_iter()
                .collect();
        let missing: Vec<Uuid> = ids
            .iter()
            .filter(|id| !existing.contains(id))
            .copied()
            .collect();
        if !missing.is_empty() {
            let ids = missing
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(AppError::Validation(format!(
                "Cannot save identity mapping: its group binding names a group id \
                 that does not exist: {ids}"
            )));
        }
        Ok(())
    }

    /// Reconcile a CI service account's `user_group_members` rows to exactly
    /// its mapping's binding (design D3, D4, D7), in its own transaction.
    ///
    /// The token-exchange entry point; mapping writes reconcile inside their
    /// own transaction through [`Self::reconcile_mapping_binding_in`].
    pub async fn reconcile_mapping_binding(
        &self,
        mapping_id: Uuid,
        service_account_id: Uuid,
    ) -> Result<Option<GroupBindingReconcileReport>> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let report =
            Self::reconcile_mapping_binding_in(&mut tx, mapping_id, service_account_id).await?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(report)
    }

    /// Reconcile inside the caller's transaction, to the binding as it is
    /// stored NOW (design D7). Returns `None`, touching nothing, when the
    /// mapping declares no binding (design D2), and `NotFound` when the
    /// mapping no longer exists.
    ///
    /// The binding is read here under `FOR SHARE` rather than taken from the
    /// caller: an exchange that resolved the mapping before a concurrent
    /// narrowing would otherwise restore the memberships the narrowing just
    /// removed. The share lock waits for the narrowing's row lock and then
    /// sees the committed binding; exchanges do not block one another.
    ///
    /// Dedicated to CI rather than sharing
    /// `sso.rs::sync_federated_groups_to_local_groups`'s core: see
    /// design.md D4 for why the two don't separate cleanly (that reconciler
    /// resolves group NAMES with auto-create and a per-name ownership tag; a
    /// CI binding names group IDS the mapping already validated at write
    /// time and never creates a group). A CI mapping's service account
    /// exists only for that one mapping
    /// (`fix-ci-oidc-identity-key`), so reconciling its ENTIRE membership set
    /// — not a tag-scoped subset — is safe: nothing else has a legitimate
    /// reason to hold membership on it (design D4.1). A membership added by
    /// any other means does not survive reconciliation.
    ///
    /// Performs no writes when the account's memberships already match the
    /// target set (D3: reconciliation runs on every token exchange, so this
    /// is the overwhelmingly common case on that hot path). A target id that
    /// no longer exists in `groups` is skipped and reported rather than
    /// silently dropped (D5) — the mapping keeps saying what the operator
    /// wrote even though reconciliation could not reach all of it.
    pub async fn reconcile_mapping_binding_in(
        conn: &mut sqlx::PgConnection,
        mapping_id: Uuid,
        service_account_id: Uuid,
    ) -> Result<Option<GroupBindingReconcileReport>> {
        let binding: Option<Option<Vec<Uuid>>> = sqlx::query_scalar(
            "SELECT group_binding_ids FROM ci_oidc_identity_mappings WHERE id = $1 FOR SHARE",
        )
        .bind(mapping_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let Some(binding) = binding else {
            return Err(AppError::NotFound(
                "CI OIDC identity mapping not found".to_string(),
            ));
        };
        let Some(target_group_ids) = binding else {
            return Ok(None);
        };

        let current: std::collections::HashSet<Uuid> =
            sqlx::query_scalar("SELECT group_id FROM user_group_members WHERE user_id = $1")
                .bind(service_account_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .into_iter()
                .collect();

        let existing_targets: std::collections::HashSet<Uuid> = if target_group_ids.is_empty() {
            std::collections::HashSet::new()
        } else {
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM groups WHERE id = ANY($1)")
                .bind(&target_group_ids)
                .fetch_all(&mut *conn)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .into_iter()
                .collect()
        };
        let dangling: Vec<Uuid> = target_group_ids
            .iter()
            .filter(|id| !existing_targets.contains(id))
            .copied()
            .collect();
        if !dangling.is_empty() {
            tracing::warn!(
                target: "security",
                service_account_id = %service_account_id,
                dangling = ?dangling,
                "CI OIDC: mapping's group binding names a group that no longer \
                 exists; skipping it rather than silently dropping it from the \
                 mapping's own declared binding"
            );
        }

        // Sorted, so two exchanges writing the same rows take their index
        // locks in the same order and cannot deadlock on each other.
        let mut to_add: Vec<Uuid> = existing_targets.difference(&current).copied().collect();
        let mut to_remove: Vec<Uuid> = current.difference(&existing_targets).copied().collect();
        to_add.sort_unstable();
        to_remove.sort_unstable();

        if !to_add.is_empty() {
            sqlx::query(
                "INSERT INTO user_group_members (user_id, group_id) \
                 SELECT $1, g FROM UNNEST($2::uuid[]) AS g \
                 ON CONFLICT (user_id, group_id) DO NOTHING",
            )
            .bind(service_account_id)
            .bind(&to_add)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }
        if !to_remove.is_empty() {
            sqlx::query("DELETE FROM user_group_members WHERE user_id = $1 AND group_id = ANY($2)")
                .bind(service_account_id)
                .bind(&to_remove)
                .execute(&mut *conn)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        }
        if !to_add.is_empty() || !to_remove.is_empty() {
            tracing::info!(
                target: "security",
                service_account_id = %service_account_id,
                added = to_add.len(),
                removed = to_remove.len(),
                "CI OIDC: reconciled service account's group memberships to its mapping's binding"
            );
        }
        Ok(Some(GroupBindingReconcileReport {
            added: to_add,
            removed: to_remove,
            dangling,
        }))
    }

    /// Create a mapping together with its service account, in one
    /// transaction: a mapping without an account is never observable, and an
    /// account that cannot be created leaves no mapping behind.
    pub async fn create_mapping(
        &self,
        provider_id: Uuid,
        req: CreateCiOidcMappingRequest,
    ) -> Result<CiOidcMappingResponse> {
        Ok(self.create_mapping_with_report(provider_id, req).await?.0)
    }

    /// [`Self::create_mapping`], also returning what the binding's
    /// reconciliation changed (`None` when the mapping declares no binding),
    /// for the caller to audit and to invalidate cached permissions on.
    pub async fn create_mapping_with_report(
        &self,
        provider_id: Uuid,
        req: CreateCiOidcMappingRequest,
    ) -> Result<(CiOidcMappingResponse, Option<GroupBindingReconcileReport>)> {
        self.create_mapping_with_id(provider_id, Uuid::new_v4(), req)
            .await
    }

    /// [`Self::create_mapping`] with the mapping UUID chosen by the caller.
    /// The id is generated up front, not by the database, because the account
    /// username derives from it and is checked before anything is written.
    async fn create_mapping_with_id(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
        req: CreateCiOidcMappingRequest,
    ) -> Result<(CiOidcMappingResponse, Option<GroupBindingReconcileReport>)> {
        let provider = self.get(provider_id).await?;
        let priority = req.priority.unwrap_or(100);
        let is_enabled = req.is_enabled.unwrap_or(true);
        let username = service_account_username(mapping_id);
        let email = service_account_email(&username);

        validate_claim_filter_keys(&req.claim_filters)?;
        if let Some(ids) = &req.group_binding_ids {
            self.validate_group_binding_ids(ids).await?;
        }

        // Refuse here, where the operator can act on it, rather than at the
        // first pipeline run. The INSERT below is still the authority: a
        // name taken between this check and it fails the whole transaction.
        let taken = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        if taken.is_some() {
            return Err(username_taken(&username));
        }

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "INSERT INTO ci_oidc_identity_mappings ",
            "(id, provider_id, name, priority, claim_filters, allowed_repo_ids, is_enabled, group_binding_ids) ",
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING ",
            mapping_columns!()
        ))
        .bind(mapping_id)
        .bind(provider_id)
        .bind(req.name)
        .bind(priority)
        .bind(req.claim_filters)
        .bind(req.allowed_repo_ids)
        .bind(is_enabled)
        .bind(req.group_binding_ids)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Same shape the federated path has always minted CI accounts with,
        // so an exchange finds nothing to create and only syncs the row.
        let account = sqlx::query_as::<_, ServiceAccountRow>(
            "INSERT INTO users (username, email, display_name, auth_provider, external_id, \
                                is_admin, is_active, is_service_account, must_change_password) \
             VALUES ($1, $2, $3, 'ci', $4, false, true, false, false) \
             RETURNING id, username, email, external_id, is_active",
        )
        .bind(&username)
        .bind(&email)
        .bind(format!("CI [{}] {}", provider.name, row.name))
        .bind(service_account_external_id(provider_id, mapping_id))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("duplicate key") {
                AppError::Conflict(format!(
                    "Cannot create identity mapping: its service account '{username}' \
                     ({email}) conflicts with an existing account"
                ))
            } else {
                AppError::Database(msg)
            }
        })?;

        // Reconcile immediately (design D3), in the same transaction (D7): a
        // mapping created with a binding has an access-conferring account
        // from the very first read, and a reconcile that fails leaves no
        // mapping and no account behind for a retry to collide with.
        let report = Self::reconcile_mapping_binding_in(&mut tx, mapping_id, account.id).await?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok((CiOidcMappingResponse::new(row, Some(account)), report))
    }

    pub async fn update_mapping(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
        req: UpdateCiOidcMappingRequest,
    ) -> Result<CiOidcMappingResponse> {
        Ok(self
            .update_mapping_with_report(provider_id, mapping_id, req)
            .await?
            .0)
    }

    /// [`Self::update_mapping`], also returning what the binding's
    /// reconciliation changed (`None` when nothing was reconciled).
    pub async fn update_mapping_with_report(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
        req: UpdateCiOidcMappingRequest,
    ) -> Result<(CiOidcMappingResponse, Option<GroupBindingReconcileReport>)> {
        let existing = self.fetch_mapping_row(provider_id, mapping_id).await?;
        if let Some(filters) = &req.claim_filters {
            validate_claim_filter_keys(filters)?;
        }

        let group_binding_ids = match req.group_binding_ids {
            None => existing.group_binding_ids.clone(),
            Some(None) => None,
            Some(Some(ids)) => {
                self.validate_group_binding_ids(&ids).await?;
                Some(ids)
            }
        };

        // The account is keyed on the mapping and never changes, so it is
        // looked up before the transaction opens.
        let account = self
            .fetch_service_accounts(std::slice::from_ref(&service_account_external_id(
                provider_id,
                mapping_id,
            )))
            .await?
            .into_iter()
            .next();

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "UPDATE ci_oidc_identity_mappings SET name = $3, priority = $4, ",
            "claim_filters = $5, allowed_repo_ids = $6, is_enabled = $7, ",
            "group_binding_ids = $8, updated_at = NOW() ",
            "WHERE id = $1 AND provider_id = $2 RETURNING ",
            mapping_columns!()
        ))
        .bind(mapping_id)
        .bind(provider_id)
        .bind(req.name.unwrap_or(existing.name))
        .bind(req.priority.unwrap_or(existing.priority))
        .bind(req.claim_filters.unwrap_or(existing.claim_filters))
        .bind(req.allowed_repo_ids.unwrap_or(existing.allowed_repo_ids))
        .bind(req.is_enabled.unwrap_or(existing.is_enabled))
        .bind(group_binding_ids)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Reconcile immediately (design D3): narrowing a binding revokes
        // without waiting for the next pipeline run. In the same transaction
        // as the row (D7), so a reconcile that fails rolls the row back too
        // and the stored binding never runs ahead of the memberships. An
        // absent binding reconciles nothing — an unbound mapping's account
        // keeps whatever memberships it holds (design D2, D3).
        let report = match &account {
            Some(account) => {
                Self::reconcile_mapping_binding_in(&mut tx, mapping_id, account.id).await?
            }
            None => None,
        };

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok((self.mapping_response(row).await?, report))
    }

    /// Delete a mapping and deactivate — never delete — its service account,
    /// so the account can no longer authenticate while everything it did
    /// stays attributable (`users` deletions carry FK history, #2878).
    ///
    /// Returns the deactivated account ids so the caller can revoke their
    /// refresh-token families, which needs an `AuthService`.
    pub async fn delete_mapping(&self, provider_id: Uuid, mapping_id: Uuid) -> Result<Vec<Uuid>> {
        // An escaped key with no wildcard: the pattern matches it exactly.
        self.delete_and_deactivate(
            "DELETE FROM ci_oidc_identity_mappings WHERE id = $1 AND provider_id = $2",
            &[mapping_id, provider_id],
            escape_like_literal(&service_account_external_id(provider_id, mapping_id)),
            "CI OIDC identity mapping not found",
        )
        .await
    }

    /// Shared body of [`Self::delete`] and [`Self::delete_mapping`]: delete
    /// the row and deactivate the service accounts whose `external_id` is
    /// `LIKE account_pattern ESCAPE '\'`, atomically. The caller escapes the
    /// literal part of the pattern with [`escape_like_literal`] (#3557).
    ///
    /// The token caches are marked BEFORE the transaction, as the admin
    /// user-deactivation path does (#931): pre-marking is fail-secure, costing
    /// at worst one extra DB re-validation if the transaction then fails.
    async fn delete_and_deactivate(
        &self,
        delete_sql: &'static str,
        delete_binds: &[Uuid],
        account_pattern: String,
        not_found: &'static str,
    ) -> Result<Vec<Uuid>> {
        let affected: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM users \
             WHERE auth_provider = 'ci' AND is_active AND external_id LIKE $1 ESCAPE '\\'",
        )
        .bind(&account_pattern)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        for user_id in &affected {
            invalidate_user_token_cache_entries(*user_id);
            invalidate_user_tokens(*user_id);
        }

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let mut delete = sqlx::query(delete_sql);
        for id in delete_binds {
            delete = delete.bind(*id);
        }
        let result = delete
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(not_found.into()));
        }
        let deactivated: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE users SET is_active = false, updated_at = NOW() \
             WHERE auth_provider = 'ci' AND is_active AND external_id LIKE $1 ESCAPE '\\' \
             RETURNING id",
        )
        .bind(&account_pattern)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(deactivated)
    }

    pub async fn toggle_mapping(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
        enabled: bool,
    ) -> Result<CiOidcMappingResponse> {
        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "UPDATE ci_oidc_identity_mappings SET is_enabled = $3, updated_at = NOW() ",
            "WHERE id = $1 AND provider_id = $2 RETURNING ",
            mapping_columns!()
        ))
        .bind(mapping_id)
        .bind(provider_id)
        .bind(enabled)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("CI OIDC identity mapping not found".into()))?;
        self.mapping_response(row).await
    }

    // -----------------------------------------------------------------------
    // Provider resolution (issue #3548)
    // -----------------------------------------------------------------------

    /// Pick the provider an incoming assertion should be verified against.
    ///
    /// Before #3548 the caller had to name the `ci_oidc_providers` row by
    /// UUID, and the only endpoint publishing that UUID is admin-only — so a
    /// "keyless" CI job had to start by using the admin password. The issuer
    /// is already part of what the verifier checks, so it is enough to select
    /// on: read the **unverified** `iss` (and `aud`) out of the assertion, use
    /// them only to choose a configured row, then run the unchanged full
    /// verification in [`Self::validate_ci_jwt`] against that row. Nothing is
    /// trusted from the peeked claims — a forged `iss` can at most select a
    /// provider whose JWKS will then refuse the signature.
    ///
    /// `provider_id_override` keeps the pre-#3548 request shape working. When
    /// it is supplied it wins, but it must agree with the assertion's `iss`:
    /// a request naming a provider the assertion was not issued for is a
    /// configuration mistake, and answering it with the verifier's generic
    /// "validation failed" would send the operator looking in the wrong place.
    pub async fn resolve_provider_for_assertion(
        &self,
        jwt_str: &str,
        provider_id_override: Option<Uuid>,
    ) -> Result<CiOidcProvider> {
        if let Some(id) = provider_id_override {
            let provider = self.get(id).await?;
            if !provider.is_enabled {
                return Err(AppError::Authentication(
                    "CI OIDC provider is disabled".into(),
                ));
            }
            // A malformed assertion is deliberately NOT rejected here: the
            // override path only cross-checks what it can read, and
            // `validate_ci_jwt` is the single place that decides whether an
            // assertion is acceptable.
            if let Some(hints) = Self::peek_assertion_hints(jwt_str) {
                if normalize_issuer(&hints.issuer) != normalize_issuer(&provider.issuer_url) {
                    return Err(AppError::Validation(format!(
                        "provider_id names a provider for issuer {}, but the presented                          assertion was issued by {}. Omit provider_id to resolve the                          provider from the assertion's iss claim.",
                        provider.issuer_url, hints.issuer
                    )));
                }
            }
            return Ok(provider);
        }

        let hints = Self::peek_assertion_hints(jwt_str).ok_or_else(|| {
            AppError::Authentication(
                "Could not read the iss claim from the presented CI assertion".into(),
            )
        })?;

        // Enabled providers are a handful of operator-created rows, so the
        // whole set is fetched and matched in Rust rather than in SQL: the
        // trailing-slash normalisation below has no index-friendly SQL form,
        // and keeping it in one pure function is what makes it testable.
        let candidates = self.list_enabled_providers().await?;
        Self::select_provider_by_issuer(candidates, &hints)
    }

    /// Read `iss` and `aud` out of an **unverified** assertion.
    ///
    /// Returns `None` for anything that is not a decodable JWT carrying a
    /// string `iss`. `aud` is accepted in both RFC 7519 §4.1.3 shapes (a
    /// single string or an array of strings) and is only ever used to break a
    /// tie between providers that share an issuer.
    fn peek_assertion_hints(jwt_str: &str) -> Option<UnverifiedAssertionHints> {
        // `dangerous::insecure_decode` skips signature AND claim validation,
        // which is exactly what is wanted: the assertion has not been verified
        // yet and an expired or wrong-audience one must still be routed to its
        // provider so the verifier can produce the accurate error.
        let claims = jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(jwt_str)
            .ok()?
            .claims;
        let issuer = claims.get("iss")?.as_str()?.to_owned();
        let audiences = match claims.get("aud") {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(vs)) => vs
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        Some(UnverifiedAssertionHints { issuer, audiences })
    }

    async fn list_enabled_providers(&self) -> Result<Vec<CiOidcProvider>> {
        sqlx::query_as::<_, CiOidcProvider>(concat!(
            "SELECT ",
            provider_columns!(),
            " FROM ci_oidc_providers WHERE is_enabled = true ORDER BY created_at ASC"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Select the one enabled provider that matches the assertion's issuer.
    ///
    /// `ci_oidc_providers` has no uniqueness constraint on `issuer_url`
    /// (migration 145 indexes it, but does not make it unique), so two enabled
    /// rows may legitimately share an issuer — the same GitLab instance
    /// configured twice for two audiences, for example. The tie is broken on
    /// the audience the assertion actually declares, because that is the other
    /// value the verifier checks; if that still leaves a choice, the request is
    /// refused with a 400 telling the caller to name the provider explicitly
    /// rather than guessing which configuration was meant.
    fn select_provider_by_issuer(
        candidates: Vec<CiOidcProvider>,
        hints: &UnverifiedAssertionHints,
    ) -> Result<CiOidcProvider> {
        let issuer = normalize_issuer(&hints.issuer);
        let mut matched: Vec<CiOidcProvider> = candidates
            .into_iter()
            .filter(|p| p.is_enabled && normalize_issuer(&p.issuer_url) == issuer)
            .collect();

        if matched.len() > 1 {
            let by_audience: Vec<CiOidcProvider> = matched
                .iter()
                .filter(|p| hints.audiences.iter().any(|a| a == &p.audience))
                .cloned()
                .collect();
            if by_audience.len() == 1 {
                matched = by_audience;
            }
        }

        match matched.len() {
            1 => Ok(matched.remove(0)),
            0 => Err(AppError::NotFound(format!(
                "No enabled CI OIDC provider is configured for issuer {issuer}"
            ))),
            _ => Err(AppError::Validation(format!(
                "{} enabled CI OIDC providers are configured for issuer {issuer};                  supply provider_id to choose one",
                matched.len()
            ))),
        }
    }

    // -----------------------------------------------------------------------
    // JWT validation
    // -----------------------------------------------------------------------

    /// Validate a CI-issued JWT against the provider's JWKS (signature,
    /// audience, issuer).  Returns the validated claims on success.
    ///
    /// Where the keys come from depends on the provider's key source: a
    /// `static` provider uses the JWKS stored on its row and makes no network
    /// request at all, so its issuer need not be reachable; a `discovery`
    /// provider fetches them through the issuer's discovery document. The
    /// `iss`, `aud` and algorithm checks below are the same for both.
    ///
    /// Claim-filter matching is deferred to [`Self::resolve_mapping`].
    pub async fn validate_ci_jwt(
        &self,
        provider: &CiOidcProvider,
        jwt_str: &str,
    ) -> Result<serde_json::Value> {
        let header = decode_header(jwt_str)
            .map_err(|e| AppError::Authentication(format!("Invalid CI JWT header: {e}")))?;

        let decoding_key = if provider.key_source == KEY_SOURCE_STATIC {
            let keys = provider
                .static_jwks
                .as_ref()
                .and_then(|jwks| jwks["keys"].as_array())
                .ok_or_else(|| AppError::Internal("Static CI OIDC provider has no JWKS".into()))?;
            Self::select_static_jwk_key(provider, keys, header.kid.as_deref()).await?
        } else {
            let discovery = self.fetch_discovery(&provider.issuer_url).await?;
            let jwks_uri = discovery["jwks_uri"]
                .as_str()
                .ok_or_else(|| AppError::Internal("OIDC discovery missing jwks_uri".into()))?
                .to_owned();

            let jwks = self.fetch_jwks(&jwks_uri).await?;
            let keys = jwks["keys"]
                .as_array()
                .ok_or_else(|| AppError::Internal("JWKS missing keys array".into()))?;
            Self::select_jwk_key(keys, header.kid.as_deref())?
        };

        let alg = match header.alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
            jsonwebtoken::Algorithm::PS256 => Algorithm::PS256,
            jsonwebtoken::Algorithm::PS384 => Algorithm::PS384,
            jsonwebtoken::Algorithm::PS512 => Algorithm::PS512,
            other => {
                return Err(AppError::Authentication(format!(
                    "Unsupported CI JWT algorithm: {other:?}"
                )))
            }
        };

        let validation = ci_jwt_validation(alg, provider);
        let token_data = decode::<serde_json::Value>(jwt_str, &decoding_key, &validation)
            .map_err(|e| AppError::Authentication(format!("CI JWT validation failed: {e}")))?;

        Ok(token_data.claims)
    }

    // -----------------------------------------------------------------------
    // Identity mapping resolution
    // -----------------------------------------------------------------------

    /// Find the first enabled mapping (ordered by priority ASC) whose
    /// `claim_filters` all match the provided JWT claims.
    ///
    /// Returns `Err(AppError::Authentication)` when no mapping matches.
    pub async fn resolve_mapping(
        &self,
        provider_id: Uuid,
        claims: &serde_json::Value,
    ) -> Result<CiOidcIdentityMapping> {
        let mappings = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "SELECT ",
            mapping_columns!(),
            " FROM ci_oidc_identity_mappings WHERE provider_id = $1 AND is_enabled = true ",
            "ORDER BY priority ASC, created_at ASC"
        ))
        .bind(provider_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if mappings.is_empty() {
            return Err(AppError::Authentication(
                "No CI OIDC identity mappings configured for this provider".into(),
            ));
        }

        for mapping in mappings {
            if self
                .check_claim_policy(&mapping.claim_filters, claims)
                .is_ok()
            {
                return Ok(mapping);
            }
        }

        Err(AppError::Authentication(
            "CI JWT did not match any identity mapping".into(),
        ))
    }

    /// Derive stable `FederatedCredentials` from the resolved mapping.
    ///
    /// Identity comes from the mapping alone: `external_id` is
    /// [`service_account_external_id`] and the username
    /// [`service_account_username`], for every ref, job and matched project.
    /// The claims only shape `display_name`.
    pub fn extract_identity_from_mapping(
        provider: &CiOidcProvider,
        mapping: &CiOidcIdentityMapping,
        claims: &serde_json::Value,
    ) -> FederatedCredentials {
        let username = service_account_username(mapping.id);

        let display_name = match provider.provider_type.as_str() {
            "gitlab" => {
                let project = claims["project_path"]
                    .as_str()
                    .unwrap_or(claims["namespace_path"].as_str().unwrap_or("unknown"));
                format!("CI [GitLab] {} — {}", mapping.name, project)
            }
            "github" => {
                let repo = claims["repository"].as_str().unwrap_or("unknown");
                format!("CI [GitHub] {} — {}", mapping.name, repo)
            }
            // Provider and mapping only (design D5): one mapping serves many
            // workloads, and this name is rewritten on every exchange, so a
            // per-token value here would flap between them. The workload is
            // in the exchange's `security` line instead.
            "kubernetes" => format!("CI [Kubernetes] {} — {}", provider.name, mapping.name),
            _ => format!("CI [{}] {}", provider.name, mapping.name),
        };

        FederatedCredentials {
            external_id: service_account_external_id(mapping.provider_id, mapping.id),
            email: service_account_email(&username),
            username,
            display_name: Some(display_name),
            groups: vec!["ci".to_string()],
            required_admin_group: None,
            // The account is provisioned with its mapping; creating it here
            // only happens for a mapping made by an earlier version that
            // never had one. The admin-configured mapping is the opt-in.
            auto_create_users: true,
        }
    }

    /// Point `credentials` at the mapping's existing service account, so the
    /// federated sync that follows updates that row instead of inserting one.
    ///
    /// 1. The account keyed on the mapping ([`service_account_external_id`])
    ///    is the normal case: its username and email are carried over, so an
    ///    account minted with an 8-hex name keeps it.
    /// 2. On a miss, an account minted by an earlier version — keyed on a raw
    ///    token subject — is **adopted**: its `external_id` is rewritten to
    ///    the mapping key and the prior value recorded in
    ///    `ci_oidc_service_account_rekey_log`, as migration 232 does. This
    ///    covers rows the migration skipped, rows an old replica minted during
    ///    a rolling upgrade, and a database restored from before it.
    ///    Adoption requires exactly one candidate row, and a legacy 8-hex name
    ///    only counts when exactly one mapping carries that UUID prefix, so it
    ///    can no more mis-bind than the migration can. Several candidates
    ///    refuse the exchange rather than pick one.
    /// 3. With neither, `credentials` is returned unchanged and the sync
    ///    creates the account under the mapping key.
    ///
    /// A deactivated account, keyed or adoptable, refuses the exchange: the
    /// sync never reactivates a CI account, and creating a new one in its
    /// place would undo the deactivation.
    pub async fn resolve_service_account(
        &self,
        mapping: &CiOidcIdentityMapping,
        mut credentials: FederatedCredentials,
    ) -> Result<FederatedCredentials> {
        let key = service_account_external_id(mapping.provider_id, mapping.id);
        let mut keyed = self
            .fetch_service_accounts(std::slice::from_ref(&key))
            .await?;
        if keyed.len() > 1 {
            return Err(ambiguous_account(mapping.id, keyed.len()));
        }
        if let Some(account) = keyed.pop() {
            if !account.is_active {
                return Err(inactive_account(mapping.id, account.id));
            }
            credentials.username = account.username;
            credentials.email = account.email;
            return Ok(credentials);
        }

        let legacy = legacy_service_account_username(mapping.id);
        let prefix_owners: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ci_oidc_identity_mappings WHERE id::text LIKE $1 ESCAPE '\\'",
        )
        .bind(format!("{}-%", escape_like_literal(&legacy["ci-".len()..])))
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let mut names = vec![service_account_username(mapping.id)];
        if prefix_owners == 1 {
            names.push(legacy);
        }

        let mut candidates = sqlx::query_as::<_, ServiceAccountRow>(
            "SELECT id, username, email, external_id, is_active FROM users \
             WHERE auth_provider = 'ci' AND username = ANY($1) \
               AND COALESCE(external_id, '') NOT LIKE 'ci:%'",
        )
        .bind(&names)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if candidates.len() > 1 {
            return Err(ambiguous_account(mapping.id, candidates.len()));
        }
        let Some(account) = candidates.pop() else {
            return Ok(credentials);
        };
        // A deactivated pre-upgrade account is neither adopted nor bypassed:
        // returning the credentials unchanged would create a fresh account.
        if !account.is_active {
            return Err(inactive_account(mapping.id, account.id));
        }

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        // Re-checks the legacy shape, so a concurrent adoption of the same
        // row makes this a no-op rather than a second rewrite.
        let adopted = sqlx::query(
            "UPDATE users SET external_id = $2 \
             WHERE id = $1 AND auth_provider = 'ci' \
               AND COALESCE(external_id, '') NOT LIKE 'ci:%'",
        )
        .bind(account.id)
        .bind(&key)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();
        if adopted == 1 {
            sqlx::query(
                "INSERT INTO ci_oidc_service_account_rekey_log \
                     (user_id, username, previous_external_id, new_external_id, mapping_id, outcome) \
                 VALUES ($1, $2, $3, $4, $5, 'adopted')",
            )
            .bind(account.id)
            .bind(&account.username)
            .bind(&account.external_id)
            .bind(&key)
            .bind(mapping.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        tracing::info!(
            target: "security",
            user_id = %account.id,
            username = %account.username,
            mapping_id = %mapping.id,
            "CI OIDC: adopted a pre-upgrade service account for its identity mapping"
        );

        credentials.username = account.username;
        credentials.email = account.email;
        Ok(credentials)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn fetch_discovery(&self, issuer_url: &str) -> Result<serde_json::Value> {
        // SSRF protection: reject blocked addresses and non-HTTPS schemes.
        // The issuer_url is admin-controlled DB data; validating here (not just at
        // write time) provides defence-in-depth for values already in the database.
        // Validated in the SSO trust class (issue #2405) to match the connect-time
        // check of the SSO client: a private-IP identity provider is reachable when
        // the operator opts in via SSO_ALLOW_PRIVATE_IPS / AK_SSRF_ALLOW_PRIVATE_CIDRS,
        // while metadata / loopback / link-local targets stay hard-blocked.
        if !issuer_url.starts_with("https://") {
            return Err(AppError::Validation(
                "CI OIDC issuer URL must use HTTPS".into(),
            ));
        }
        crate::api::validation::validate_outbound_sso_url(issuer_url, "CI OIDC issuer URL")?;

        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let response = self
            .http
            .get(&url)
            .timeout(OIDC_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("CI OIDC discovery fetch failed: {e}")))?;
        let discovery: serde_json::Value = crate::services::http_client::read_json_capped(
            response,
            crate::services::http_client::MAX_OIDC_RESPONSE_BYTES,
        )
        .await
        .map_err(|e| AppError::Internal(format!("CI OIDC discovery parse failed: {e}")))?;
        Ok(discovery)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<serde_json::Value> {
        {
            let cache = jwks_cache().read().await;
            if let Some(entry) = cache.get(jwks_uri) {
                if entry.fetched_at.elapsed() < JWKS_CACHE_TTL {
                    return Ok(entry.keys.clone());
                }
            }
        }

        let response = self
            .http
            .get(jwks_uri)
            .timeout(OIDC_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("CI JWKS fetch failed: {e}")))?;
        let jwks: serde_json::Value = crate::services::http_client::read_json_capped(
            response,
            crate::services::http_client::MAX_OIDC_RESPONSE_BYTES,
        )
        .await
        .map_err(|e| AppError::Internal(format!("CI JWKS parse failed: {e}")))?;

        let mut cache = jwks_cache().write().await;
        cache.insert(
            jwks_uri.to_owned(),
            JwksCacheEntry {
                keys: jwks.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok(jwks)
    }

    /// Key selection for `discovery` providers. An unknown `kid` falls back to
    /// the first key: harmless, because the signature check then fails, and
    /// deliberately left as it was (design D3). `static` providers select
    /// strictly through [`Self::select_static_jwk_key`].
    fn select_jwk_key(keys: &[serde_json::Value], kid: Option<&str>) -> Result<DecodingKey> {
        let key = match kid {
            Some(kid) => keys
                .iter()
                .find(|k| k["kid"].as_str() == Some(kid))
                .or_else(|| keys.first()),
            None => keys.first(),
        }
        .ok_or_else(|| AppError::Internal("No matching JWK found".into()))?;

        Self::decoding_key_from_jwk(key).map_err(AppError::Internal)
    }

    /// Strict key selection for `static` providers (design D3): a `kid` the
    /// set does not hold is refused by name rather than tried against another
    /// key, which is what turns a missed cluster key rotation into a
    /// diagnosable error instead of a generic "signature invalid". A token
    /// without a `kid` is accepted only when the set holds exactly one key.
    ///
    /// The refusal's WARN is throttled per provider by
    /// [`UNKNOWN_KID_WARNINGS`]; repeats within the window log at DEBUG.
    async fn select_static_jwk_key(
        provider: &CiOidcProvider,
        keys: &[serde_json::Value],
        kid: Option<&str>,
    ) -> Result<DecodingKey> {
        let key = match kid {
            Some(kid) => keys.iter().find(|k| k["kid"].as_str() == Some(kid)),
            None if keys.len() == 1 => keys.first(),
            None => None,
        };
        let Some(key) = key else {
            if UNKNOWN_KID_WARNINGS
                .check_rate_limit(&provider.id.to_string())
                .await
                .is_err()
            {
                tracing::debug!(
                    target: "security",
                    provider_id = %provider.id,
                    kid = kid.unwrap_or("(none)"),
                    "CI OIDC: token key id is not in the provider's static JWKS; refusing \
                     (repeat within a minute, WARN suppressed)"
                );
            } else {
                tracing::warn!(
                    target: "security",
                    provider_id = %provider.id,
                    provider_name = %provider.name,
                    kid = kid.unwrap_or("(none)"),
                    static_kids = %keys
                        .iter()
                        .map(|k| k["kid"].as_str().unwrap_or("-"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    "CI OIDC: token key id is not in the provider's static JWKS; refusing. \
                     If the cluster rotated its signing key, add the new key to the provider. \
                     Further refusals for this provider within a minute log at DEBUG"
                );
            }
            return Err(AppError::Authentication(match kid {
                Some(kid) => format!("CI JWT key id '{kid}' is not in this provider's static JWKS"),
                None => "CI JWT has no key id and this provider's static JWKS holds several \
                         keys"
                    .into(),
            }));
        };
        Self::decoding_key_from_jwk(key).map_err(AppError::Internal)
    }

    /// Parse one public JWK into a verification key. Shared by verification
    /// and by save-time validation of a static JWKS, so a set that validates
    /// is a set that verifies.
    fn decoding_key_from_jwk(key: &serde_json::Value) -> std::result::Result<DecodingKey, String> {
        let component = |name: &str, kty: &str| {
            key[name]
                .as_str()
                .ok_or_else(|| format!("JWK {kty} missing '{name}'"))
        };
        match key["kty"].as_str().unwrap_or("") {
            "RSA" => {
                DecodingKey::from_rsa_components(component("n", "RSA")?, component("e", "RSA")?)
                    .map_err(|e| format!("Invalid RSA JWK: {e}"))
            }
            "EC" => DecodingKey::from_ec_components(component("x", "EC")?, component("y", "EC")?)
                .map_err(|e| format!("Invalid EC JWK: {e}")),
            other => Err(format!("Unsupported JWK kty: {other}")),
        }
    }

    /// Enforce that every key/value pair in `policy` appears in `claims`.
    ///
    /// Array values use any-of semantics:
    /// `"namespace_path": ["group-a", "group-b"]` passes if the claim equals
    /// either "group-a" or "group-b". A key with a leading `/` is a JSON
    /// Pointer into nested claims (see [`claim_value`]); matching is exact
    /// either way.
    ///
    /// The error returned to the caller is deliberately generic — it does not
    /// name which claim failed so that mapping configuration is not leaked to
    /// the CI pipeline.  The detail is emitted via `tracing::debug!` for
    /// operator visibility without exposing it in API responses.
    fn check_claim_policy(
        &self,
        policy: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> Result<()> {
        let map = policy
            .as_object()
            .ok_or_else(|| AppError::Internal("claim_filters must be a JSON object".into()))?;

        for (key, expected) in map {
            let actual = claim_value(claims, key).unwrap_or(&serde_json::Value::Null);
            let matches = match expected {
                serde_json::Value::Array(allowed_values) => {
                    allowed_values.iter().any(|v| v == actual)
                }
                _ => actual == expected,
            };
            if !matches {
                tracing::debug!(
                    claim = %key,
                    "CI JWT claim did not match required value(s) for this mapping"
                );
                return Err(AppError::Authentication(
                    "CI JWT did not match any configured identity mapping".into(),
                ));
            }
        }
        Ok(())
    }

    /// Returns the `AuthProvider` constant used when provisioning CI service
    /// accounts via `authenticate_federated`.
    pub fn auth_provider() -> AuthProvider {
        AuthProvider::Ci
    }
}

/// A syntactically valid public RSA JWK under `kid`, for tests of save-time
/// JWKS handling, which parse keys but verify nothing with them.
#[cfg(test)]
pub(crate) fn test_public_jwk(kid: &str) -> serde_json::Value {
    serde_json::json!({"kty": "RSA", "kid": kid, "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw", "e": "AQAB"})
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    #[test]
    fn provider_type_is_normalised_and_unknown_values_refused() {
        assert_eq!(
            super::normalize_provider_type("Kubernetes").unwrap(),
            "kubernetes"
        );
        assert_eq!(
            super::normalize_provider_type(" GitLab ").unwrap(),
            "gitlab"
        );
        for bad in ["k8s", "", "kube", "custom"] {
            assert!(
                matches!(
                    super::normalize_provider_type(bad),
                    Err(crate::error::AppError::Validation(_))
                ),
                "{bad:?} should be refused"
            );
        }
    }

    use super::{
        normalize_issuer, CiOidcIdentityMapping, CiOidcProvider, CiOidcService,
        UnverifiedAssertionHints,
    };
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::models::user::AuthProvider;
    use chrono::Utc;
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    /// GitLab's real ID-token `sub` shape: it embeds the ref type and the ref,
    /// so every branch and tag of one project presents a different subject.
    const GITLAB_MAIN_SUB: &str = "project_path:group/repo:ref_type:branch:ref:main";
    /// GitHub Actions' `sub` for a branch push: `repo:{org}/{repo}:ref:{ref}`.
    const GITHUB_MAIN_SUB: &str = "repo:org/repo:ref:refs/heads/main";

    fn test_service() -> CiOidcService {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/artifact_keeper_test")
            .expect("lazy pool creation should succeed for unit tests");
        CiOidcService::new(pool)
    }

    fn sample_provider(provider_type: &str) -> CiOidcProvider {
        let now = Utc::now();
        CiOidcProvider {
            id: Uuid::new_v4(),
            name: "CI Provider".to_string(),
            provider_type: provider_type.to_string(),
            issuer_url: "https://issuer.example.com".to_string(),
            audience: "artifact-keeper".to_string(),
            is_enabled: true,
            created_at: now,
            updated_at: now,
            key_source: super::KEY_SOURCE_DISCOVERY.to_string(),
            static_jwks: None,
        }
    }

    fn sample_mapping(name: &str) -> CiOidcIdentityMapping {
        let now = Utc::now();
        CiOidcIdentityMapping {
            id: Uuid::parse_str("11111111-2222-3333-4444-555555555555")
                .expect("static UUID should be valid"),
            provider_id: Uuid::new_v4(),
            name: name.to_string(),
            priority: 10,
            claim_filters: json!({"sub": "ci:example"}),
            allowed_repo_ids: None,
            is_enabled: true,
            created_at: now,
            updated_at: now,
            group_binding_ids: None,
        }
    }

    /// #4198: `allowed_repo_ids` is tri-state on PATCH — an absent key means
    /// "unchanged", an explicit `null` means "clear the restriction", and an
    /// empty array stays deny-all.
    #[test]
    fn update_mapping_request_allowed_repo_ids_is_tri_state() {
        let absent: super::UpdateCiOidcMappingRequest =
            serde_json::from_value(json!({})).expect("empty body should deserialize");
        assert_eq!(absent.allowed_repo_ids, None);

        let null: super::UpdateCiOidcMappingRequest =
            serde_json::from_value(json!({"allowed_repo_ids": null}))
                .expect("explicit null should deserialize");
        assert_eq!(null.allowed_repo_ids, Some(None));

        let empty: super::UpdateCiOidcMappingRequest =
            serde_json::from_value(json!({"allowed_repo_ids": []}))
                .expect("empty array should deserialize");
        assert_eq!(empty.allowed_repo_ids, Some(Some(vec![])));
    }

    #[tokio::test]
    async fn check_claim_policy_accepts_exact_and_array_matches() {
        let svc = test_service();
        let policy = json!({
            "project_path": ["group/repo", "other/repo"],
            "ref_type": "branch"
        });
        let claims = json!({
            "project_path": "group/repo",
            "ref_type": "branch"
        });

        assert!(svc.check_claim_policy(&policy, &claims).is_ok());
    }

    #[tokio::test]
    async fn check_claim_policy_rejects_non_object_policy() {
        let svc = test_service();
        let policy = json!("not-an-object");
        let claims = json!({"sub": "ci:job"});

        let err = svc
            .check_claim_policy(&policy, &claims)
            .expect_err("non-object policy must fail");
        assert!(err
            .to_string()
            .contains("claim_filters must be a JSON object"));
    }

    #[tokio::test]
    async fn check_claim_policy_rejects_mismatched_claim_value() {
        let svc = test_service();
        let policy = json!({"ref": "refs/heads/main"});
        let claims = json!({"ref": "refs/heads/feature"});

        let err = svc
            .check_claim_policy(&policy, &claims)
            .expect_err("mismatched claims must fail");
        assert!(err
            .to_string()
            .contains("did not match any configured identity mapping"));
    }

    // -----------------------------------------------------------------------
    // JSON Pointer claim filters (add-ci-oidc-kubernetes-provider D1)
    // -----------------------------------------------------------------------

    /// A kubelet-issued ServiceAccount token's claims, in the shape the API
    /// server emits them.
    fn k8s_claims(namespace: &str, sa: &str) -> serde_json::Value {
        json!({
            "sub": format!("system:serviceaccount:{namespace}:{sa}"),
            "kubernetes.io": {
                "namespace": namespace,
                "serviceaccount": {"name": sa, "uid": "0b8e7b36-0000-4000-8000-000000000001"},
                "pod": {"name": format!("{sa}-7d9f"), "uid": "0b8e7b36-0000-4000-8000-000000000002"},
                "node": {"name": "node-3", "uid": "0b8e7b36-0000-4000-8000-000000000003"}
            }
        })
    }

    fn matches(policy: serde_json::Value, claims: &serde_json::Value) -> bool {
        test_service().check_claim_policy(&policy, claims).is_ok()
    }

    #[tokio::test]
    async fn pointer_filter_matches_every_serviceaccount_of_a_namespace() {
        let policy = json!({"/kubernetes.io/namespace": "payments"});
        assert!(matches(policy.clone(), &k8s_claims("payments", "api")));
        assert!(matches(policy.clone(), &k8s_claims("payments", "worker")));
        assert!(!matches(policy, &k8s_claims("billing", "api")));
    }

    #[tokio::test]
    async fn pointer_filter_matches_one_serviceaccount() {
        let policy = json!({
            "/kubernetes.io/namespace": "payments",
            "/kubernetes.io/serviceaccount/name": "api"
        });
        assert!(matches(policy.clone(), &k8s_claims("payments", "api")));
        assert!(!matches(policy, &k8s_claims("payments", "worker")));
    }

    #[tokio::test]
    async fn pointer_filter_to_a_missing_member_does_not_match() {
        let policy = json!({"/kubernetes.io/namespace": "payments"});
        assert!(!matches(
            policy,
            &json!({"sub": "system:serviceaccount:payments:api"})
        ));
    }

    #[tokio::test]
    async fn pointer_filter_honours_rfc6901_escapes() {
        assert!(matches(json!({"/a~1b": "x"}), &json!({"a/b": "x"})));
        assert!(matches(json!({"/a~0b": "x"}), &json!({"a~b": "x"})));
        assert!(!matches(json!({"/a~1b": "x"}), &json!({"a": {"b": "x"}})));
    }

    #[tokio::test]
    async fn pointer_filter_is_exact_not_a_prefix() {
        let policy = json!({"/kubernetes.io/namespace": "prod"});
        assert!(!matches(policy, &k8s_claims("prod-sandbox", "api")));
    }

    #[tokio::test]
    async fn pointer_filter_keeps_any_of_semantics() {
        let policy = json!({"/kubernetes.io/namespace": ["payments", "billing"]});
        assert!(matches(policy.clone(), &k8s_claims("billing", "worker")));
        assert!(!matches(policy, &k8s_claims("other", "api")));

        let policy = json!({"sub": [
            "system:serviceaccount:payments:api",
            "system:serviceaccount:billing:worker"
        ]});
        assert!(matches(policy.clone(), &k8s_claims("payments", "api")));
        assert!(matches(policy.clone(), &k8s_claims("billing", "worker")));
        assert!(!matches(policy, &k8s_claims("payments", "other")));
    }

    /// A key without a leading `/` names a top-level claim, dots and all: the
    /// whole `kubernetes.io` object is compared, so a partial object does not
    /// match a token carrying more members.
    #[tokio::test]
    async fn dotted_key_is_a_claim_name_not_a_path() {
        let policy = json!({"kubernetes.io": {"namespace": "payments"}});
        assert!(!matches(policy, &k8s_claims("payments", "api")));

        let policy = json!({"project_path": "group/app"});
        assert!(matches(policy, &json!({"project_path": "group/app"})));
    }

    #[test]
    fn validate_claim_filter_keys_refuses_a_bad_escape_by_name() {
        let err = super::validate_claim_filter_keys(&json!({"/kubernetes.io/~2bad": "x"}))
            .expect_err("~2 is not an RFC 6901 escape");
        assert!(
            err.to_string().contains("/kubernetes.io/~2bad"),
            "the error names the key: {err}"
        );
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::BAD_REQUEST
        );
        assert!(super::validate_claim_filter_keys(&json!({"/trailing~": "x"})).is_err());

        for ok in [
            json!({"/kubernetes.io/namespace": "x", "/a~0b~1c": "y"}),
            json!({"not/a/pointer~2": "x"}),
            json!({"/": "x"}),
        ] {
            super::validate_claim_filter_keys(&ok).expect("valid keys pass");
        }
    }

    #[test]
    fn select_jwk_key_rejects_empty_key_set() {
        let keys = vec![];
        let err = CiOidcService::select_jwk_key(&keys, None).expect_err("empty keys must fail");
        assert!(err.to_string().contains("No matching JWK found"));
    }

    #[test]
    fn select_jwk_key_rejects_missing_rsa_n() {
        let keys = vec![json!({"kid": "k1", "kty": "RSA", "e": "AQAB"})];
        let err = CiOidcService::select_jwk_key(&keys, Some("k1"))
            .expect_err("RSA key without modulus must fail");
        assert!(err.to_string().contains("JWK RSA missing 'n'"));
    }

    #[test]
    fn select_jwk_key_rejects_missing_ec_x() {
        let keys = vec![json!({"kid": "k1", "kty": "EC", "y": "abc"})];
        let err = CiOidcService::select_jwk_key(&keys, Some("k1"))
            .expect_err("EC key without x must fail");
        assert!(err.to_string().contains("JWK EC missing 'x'"));
    }

    #[test]
    fn select_jwk_key_rejects_unsupported_kty() {
        let keys = vec![json!({"kid": "k1", "kty": "OKP"})];
        let err = CiOidcService::select_jwk_key(&keys, Some("k1"))
            .expect_err("unsupported kty must fail");
        assert!(err.to_string().contains("Unsupported JWK kty"));
    }

    #[test]
    fn extract_identity_from_mapping_formats_gitlab_identity() {
        let provider = sample_provider("gitlab");
        let mapping = sample_mapping("Deploy Main");
        let claims = json!({
            "project_path": "group/repo",
            "sub": GITLAB_MAIN_SUB
        });

        let identity = CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);
        assert_eq!(
            identity.external_id,
            format!(
                "ci:{}:11111111-2222-3333-4444-555555555555",
                mapping.provider_id
            ),
            "the identity key is the mapping, never the token subject"
        );
        assert_eq!(identity.username, "ci-111111112222");
        assert_eq!(
            identity.email,
            format!("{}@ci.artifact-keeper.internal", identity.username)
        );
        assert_eq!(
            identity.display_name,
            Some("CI [GitLab] Deploy Main — group/repo".to_string())
        );
    }

    #[test]
    fn extract_identity_from_mapping_formats_github_identity() {
        let provider = sample_provider("github");
        let mapping = sample_mapping("Release Job");
        let claims = json!({
            "repository": "org/repo",
            "sub": GITHUB_MAIN_SUB
        });

        let identity = CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);
        assert_eq!(
            identity.external_id,
            super::service_account_external_id(mapping.provider_id, mapping.id)
        );
        assert_eq!(
            identity.display_name,
            Some("CI [GitHub] Release Job — org/repo".to_string())
        );
    }

    /// Every ref, tag and matched project of one mapping must derive the same
    /// identity: the subject may vary, the account may not.
    #[test]
    fn extract_identity_from_mapping_ignores_the_subject() {
        let provider = sample_provider("gitlab");
        let mapping = sample_mapping("Deploy");
        let identities: Vec<_> = [
            GITLAB_MAIN_SUB,
            "project_path:group/repo:ref_type:branch:ref:feature/x",
            "project_path:group/repo:ref_type:tag:ref:v1.2.0",
            "project_path:group/fork:ref_type:branch:ref:main",
        ]
        .into_iter()
        .map(|sub| {
            let claims = json!({"project_path": "group/repo", "sub": sub});
            CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims)
        })
        .collect();
        for identity in &identities[1..] {
            assert_eq!(identity.external_id, identities[0].external_id);
            assert_eq!(identity.username, identities[0].username);
            assert_eq!(identity.email, identities[0].email);
        }
    }

    /// New usernames carry 12 hex characters (D3); the 8-character form
    /// earlier versions derived is still exactly the UUID's first group, which
    /// is what migration 232's `id::text LIKE '<8hex>-%'` resolves against.
    #[test]
    fn service_account_username_widens_to_12_hex_and_keeps_legacy_resolvable() {
        let id = Uuid::parse_str("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9").unwrap();
        let name = super::service_account_username(id);
        assert_eq!(name, "ci-0a1b2c3d4e5f");
        assert_eq!(name.len(), "ci-".len() + 12);

        let legacy = super::legacy_service_account_username(id);
        assert_eq!(legacy, "ci-0a1b2c3d");
        let first_group = id.to_string().split('-').next().unwrap().to_string();
        assert_eq!(&legacy["ci-".len()..], first_group);
    }

    /// Design D5: the display name of a Kubernetes mapping's account names
    /// provider and mapping only, so two workloads cannot flap it.
    #[test]
    fn extract_identity_from_mapping_names_kubernetes_by_provider_and_mapping() {
        let provider = sample_provider("kubernetes");
        let mapping = sample_mapping("payments");
        let names: Vec<_> = [
            k8s_claims("payments", "api"),
            k8s_claims("payments", "worker"),
        ]
        .iter()
        .map(|c| CiOidcService::extract_identity_from_mapping(&provider, &mapping, c))
        .map(|identity| identity.display_name.unwrap())
        .collect();
        assert_eq!(names[0], names[1]);
        assert_eq!(names[0], "CI [Kubernetes] CI Provider — payments");
    }

    #[test]
    fn extract_identity_from_mapping_uses_defaults_for_unknown_provider() {
        let provider = sample_provider("custom");
        let mapping = sample_mapping("Any Pipeline");
        let claims = json!({});

        let identity = CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);
        assert_eq!(
            identity.display_name,
            Some("CI [CI Provider] Any Pipeline".to_string())
        );
        assert_eq!(identity.groups, vec!["ci".to_string()]);
        assert_eq!(identity.required_admin_group, None);
    }

    #[test]
    fn auth_provider_is_ci() {
        assert_eq!(CiOidcService::auth_provider(), AuthProvider::Ci);
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_non_https_url() {
        let svc = test_service();
        let err = svc
            .fetch_discovery("http://issuer.example.com")
            .await
            .expect_err("non-https issuer must be rejected");
        assert!(err.to_string().contains("must use HTTPS"));
    }

    /// Serializes the SSRF-toggle tests below: they mutate process-wide env
    /// vars that must stay in place across an `.await`, so this is a tokio
    /// mutex (held across the awaited fetch) rather than a std one. Without
    /// it, `cargo test`'s parallel threads could flip a toggle under another
    /// test's nose. (Under `cargo nextest`, per-test process isolation makes
    /// this a no-op safety net.) Mirrors the `ssrf_dns` test pattern.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Await `fut()` with ONLY the given env toggles set (all other
    /// private-IP allow knobs cleared), restoring the prior values
    /// afterwards. The env must be manipulated around the *await* (not just
    /// future construction): an async fn body runs on poll.
    async fn with_ssrf_toggles<F, Fut, R>(set: &[(&str, &str)], fut: F) -> R
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        const VARS: [&str; 5] = [
            "WEBHOOK_ALLOW_PRIVATE_IPS",
            "SSO_ALLOW_PRIVATE_IPS",
            "UPSTREAM_ALLOW_PRIVATE_IPS",
            "AK_SSRF_ALLOW_PRIVATE_CIDRS",
            "UPSTREAM_PRIVATE_IP_ALLOWLIST",
        ];
        let _lock = ENV_LOCK.lock().await;
        let prev: Vec<(&str, Option<String>)> =
            VARS.iter().map(|v| (*v, std::env::var(v).ok())).collect();
        for v in VARS {
            std::env::remove_var(v);
        }
        for (k, val) in set {
            std::env::set_var(k, val);
        }
        let out = fut().await;
        for (k, val) in prev {
            match val {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        out
    }

    /// With no toggle set, a private-IP issuer stays blocked (fail-closed
    /// default), and the error names the SSO-surface knobs — discriminating
    /// for the #2405 fix: the old `Upstream`-context validation produced a
    /// block message with no `SSO_ALLOW_PRIVATE_IPS` guidance.
    #[tokio::test]
    async fn fetch_discovery_blocks_private_issuer_by_default_with_sso_guidance() {
        let svc = test_service();
        let err = with_ssrf_toggles(&[], || svc.fetch_discovery("https://10.10.0.8"))
            .await
            .expect_err("private-IP issuer must be blocked with no toggle set");
        let msg = err.to_string();
        assert!(
            msg.contains("SSO_ALLOW_PRIVATE_IPS") && msg.contains("AK_SSRF_ALLOW_PRIVATE_CIDRS"),
            "block error must name the SSO-surface opt-in knobs (#2405), got: {msg}"
        );
    }

    /// Cloud-metadata and loopback issuers stay hard-blocked even in the
    /// MOST permissive configuration (`SSO_ALLOW_PRIVATE_IPS=true`) — the
    /// toggle relaxes only the RFC1918/CGNAT/ULA class, never the SSRF
    /// hard-block class.
    #[tokio::test]
    async fn fetch_discovery_hard_blocks_metadata_and_loopback_even_with_toggle_on() {
        let svc = test_service();
        for issuer in [
            "https://169.254.169.254",
            "https://127.0.0.1",
            "https://[::1]",
        ] {
            let err = with_ssrf_toggles(&[("SSO_ALLOW_PRIVATE_IPS", "true")], || {
                svc.fetch_discovery(issuer)
            })
            .await
            .expect_err(
                "metadata/loopback issuer must stay blocked even with SSO_ALLOW_PRIVATE_IPS=true",
            );
            let msg = err.to_string();
            assert!(
                !msg.contains("discovery fetch failed"),
                "{issuer} must be rejected by validation, not attempted, got: {msg}"
            );
        }
    }

    /// With `SSO_ALLOW_PRIVATE_IPS=true`, a private-IP issuer passes the
    /// SSRF validation (the #2405 fix) — the fetch proceeds to the network
    /// layer and fails there (nothing listens at the unroutable target),
    /// NOT with a validation block. Asserts on the error class only, so no
    /// live endpoint is required.
    #[tokio::test]
    async fn fetch_discovery_private_issuer_passes_validation_when_toggle_on() {
        let svc = test_service();
        let err = with_ssrf_toggles(&[("SSO_ALLOW_PRIVATE_IPS", "true")], || {
            svc.fetch_discovery("https://10.255.255.1")
        })
        .await
        .expect_err("no IdP is listening at 10.255.255.1, so the fetch itself must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("discovery fetch failed"),
            "with the toggle on, a private-IP issuer must get past SSRF validation \
             and fail at the connection layer, got: {msg}"
        );
    }

    #[tokio::test]
    async fn provider_crud_roundtrip() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let svc = CiOidcService::new(pool.clone());

        let created = svc
            .create(super::CreateCiOidcProviderRequest {
                name: "test-provider-crud".to_string(),
                provider_type: None,
                issuer_url: "https://issuer.example.com".to_string(),
                audience: None,
                is_enabled: None,
                key_source: None,
                static_jwks: None,
            })
            .await
            .expect("provider should be created");

        assert_eq!(created.provider_type, "generic");
        assert_eq!(created.audience, "artifact-keeper");
        assert!(created.is_enabled);
        assert_eq!(created.key_source, "discovery", "the default key source");
        assert_eq!(created.static_jwks, None);

        let listed = svc.list().await.expect("providers should list");
        assert!(listed.iter().any(|p| p.id == created.id));

        let got = svc
            .get_response(created.id)
            .await
            .expect("provider should be readable");
        assert_eq!(got.name, "test-provider-crud");

        let updated = svc
            .update(
                created.id,
                super::UpdateCiOidcProviderRequest {
                    name: Some("test-provider-crud-updated".to_string()),
                    provider_type: Some("github".to_string()),
                    issuer_url: Some("https://issuer2.example.com".to_string()),
                    audience: Some("artifact-keeper-ci".to_string()),
                    is_enabled: Some(true),
                    key_source: None,
                    static_jwks: None,
                },
            )
            .await
            .expect("provider should update")
            .provider;
        assert_eq!(updated.name, "test-provider-crud-updated");
        assert_eq!(updated.provider_type, "github");

        let toggled = svc
            .toggle(created.id, false)
            .await
            .expect("provider should toggle");
        assert!(!toggled.is_enabled);

        svc.delete(created.id)
            .await
            .expect("provider should be deleted");

        let err = svc
            .get_response(created.id)
            .await
            .expect_err("deleted provider should not exist");
        assert!(err.to_string().contains("provider not found"));
    }

    #[test]
    fn an_update_may_echo_the_stored_provider_type() {
        use super::resolve_updated_provider_type as resolve;
        assert_eq!(resolve(None, "circleci").unwrap(), "circleci");
        assert_eq!(resolve(Some("circleci"), "circleci").unwrap(), "circleci");
        assert_eq!(
            resolve(Some("Kubernetes"), "circleci").unwrap(),
            "kubernetes"
        );
        assert_eq!(resolve(Some("GitLab"), "gitlab").unwrap(), "gitlab");
        for bad in ["jenkins", "CircleCI", "k8s"] {
            assert!(
                matches!(
                    resolve(Some(bad), "circleci"),
                    Err(crate::error::AppError::Validation(_))
                ),
                "{bad:?} changes the type to an unknown one"
            );
        }
    }

    /// A provider stored while `provider_type` was free text keeps working
    /// with a client that re-sends the whole provider on edit (the web UI
    /// does), while a create or a change to an unknown type is still 400.
    #[tokio::test]
    async fn a_legacy_provider_type_round_trips_on_update() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let request = |provider_type: &str, name: &str| super::UpdateCiOidcProviderRequest {
            name: Some(name.to_string()),
            provider_type: Some(provider_type.to_string()),
            issuer_url: None,
            audience: None,
            is_enabled: None,
            key_source: None,
            static_jwks: None,
        };

        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO ci_oidc_providers (name, provider_type, issuer_url, audience) \
             VALUES ($1, 'circleci', 'https://oidc.circleci.example.com', 'artifact-keeper') \
             RETURNING id",
        )
        .bind(format!("legacy-{}", uuid::Uuid::new_v4()))
        .fetch_one(&pool)
        .await
        .expect("seed a legacy provider");

        let renamed = format!("legacy-renamed-{}", uuid::Uuid::new_v4());
        let updated = svc
            .update(id, request("circleci", &renamed))
            .await
            .expect("echoing the stored type is accepted");
        assert_eq!(updated.provider.provider_type, "circleci");
        assert_eq!(updated.provider.name, renamed);
        assert_eq!(updated.previous_provider_type, None);

        let err = svc
            .update(id, request("jenkins", &renamed))
            .await
            .err()
            .expect("an unknown new type is refused");
        assert!(matches!(err, crate::error::AppError::Validation(_)));

        let err = svc
            .create(super::CreateCiOidcProviderRequest {
                name: format!("legacy-create-{}", uuid::Uuid::new_v4()),
                provider_type: Some("circleci".to_string()),
                issuer_url: "https://oidc.circleci.example.com".to_string(),
                audience: None,
                is_enabled: None,
                key_source: None,
                static_jwks: None,
            })
            .await
            .expect_err("a create with an unknown type is refused");
        assert!(matches!(err, crate::error::AppError::Validation(_)));

        let moved = svc
            .update(id, request("Generic", &renamed))
            .await
            .expect("a legacy provider can move to a known type");
        assert_eq!(moved.provider.provider_type, "generic");
        assert_eq!(moved.previous_provider_type.as_deref(), Some("circleci"));

        svc.delete(id).await.expect("cleanup");
    }

    /// An update reads the row it replaces under a lock: one that starts
    /// while another transaction is changing the key material waits for it,
    /// then reports the change against the committed row rather than the
    /// stale one it would have read first.
    #[tokio::test]
    async fn provider_update_serialises_with_a_concurrent_writer() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let created = svc
            .create(super::CreateCiOidcProviderRequest {
                name: format!("rmw-{}", uuid::Uuid::new_v4()),
                provider_type: Some("kubernetes".to_string()),
                issuer_url: "https://kubernetes.default.svc.cluster.local".to_string(),
                audience: None,
                is_enabled: None,
                key_source: None,
                static_jwks: None,
            })
            .await
            .expect("create a discovery provider");

        let mut writer = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE ci_oidc_providers SET key_source = 'static', static_jwks = $2 WHERE id = $1",
        )
        .bind(created.id)
        .bind(json!({"keys": [super::test_public_jwk("k1")]}))
        .execute(&mut *writer)
        .await
        .unwrap();

        let update = tokio::spawn({
            let svc = CiOidcService::new(pool.clone());
            let id = created.id;
            async move {
                svc.update(
                    id,
                    super::UpdateCiOidcProviderRequest {
                        name: None,
                        provider_type: None,
                        issuer_url: None,
                        audience: None,
                        is_enabled: None,
                        key_source: Some("discovery".to_string()),
                        static_jwks: None,
                    },
                )
                .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!update.is_finished(), "the update waits for the row lock");
        writer.commit().await.unwrap();

        let updated = update.await.unwrap().expect("update after the writer");
        assert!(
            updated.key_material_changed,
            "compared against the committed static set, not the stale discovery row"
        );
        assert_eq!(updated.provider.key_source, "discovery");
        assert_eq!(updated.provider.static_jwks, None);

        svc.delete(created.id).await.expect("cleanup");
    }

    #[tokio::test]
    async fn mapping_crud_and_resolve_mapping_roundtrip() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let svc = CiOidcService::new(pool.clone());
        let provider = svc
            .create(super::CreateCiOidcProviderRequest {
                name: "test-provider-mapping".to_string(),
                provider_type: Some("gitlab".to_string()),
                issuer_url: "https://issuer.example.com".to_string(),
                audience: Some("artifact-keeper".to_string()),
                is_enabled: Some(true),
                key_source: None,
                static_jwks: None,
            })
            .await
            .expect("provider should be created");

        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();

        let created = svc
            .create_mapping(
                provider.id,
                super::CreateCiOidcMappingRequest {
                    name: "main-branch".to_string(),
                    priority: None,
                    claim_filters: json!({"ref": "refs/heads/main"}),
                    allowed_repo_ids: Some(vec![repo_a]),
                    is_enabled: None,
                    group_binding_ids: None,
                },
            )
            .await
            .expect("mapping should be created");
        assert_eq!(created.priority, 100);
        assert!(created.is_enabled);
        assert_eq!(created.allowed_repo_ids, Some(vec![repo_a]));

        let listed = svc
            .list_mappings(provider.id)
            .await
            .expect("mappings should list");
        assert!(listed.iter().any(|m| m.id == created.id));

        let got = svc
            .get_mapping(provider.id, created.id)
            .await
            .expect("mapping should be readable");
        assert_eq!(got.name, "main-branch");
        assert_eq!(got.allowed_repo_ids, Some(vec![repo_a]));

        let updated = svc
            .update_mapping(
                provider.id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: Some("release-branch".to_string()),
                    priority: Some(5),
                    claim_filters: Some(json!({"ref": ["refs/heads/main", "refs/heads/release"]})),
                    allowed_repo_ids: Some(Some(vec![repo_a, repo_b])),
                    is_enabled: Some(true),
                    group_binding_ids: None,
                },
            )
            .await
            .expect("mapping should update");
        assert_eq!(updated.name, "release-branch");
        assert_eq!(updated.priority, 5);
        assert_eq!(updated.allowed_repo_ids, Some(vec![repo_a, repo_b]));

        let unchanged_scope = svc
            .update_mapping(
                provider.id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: None,
                    is_enabled: Some(true),
                    group_binding_ids: None,
                },
            )
            .await
            .expect("missing repo scope field should preserve existing scope");
        assert_eq!(unchanged_scope.allowed_repo_ids, Some(vec![repo_a, repo_b]));

        let deny_all = svc
            .update_mapping(
                provider.id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: Some(Some(vec![])),
                    is_enabled: Some(true),
                    group_binding_ids: None,
                },
            )
            .await
            .expect("explicit empty repo scope should be persisted as deny-all");
        assert_eq!(deny_all.allowed_repo_ids, Some(vec![]));

        // #4198: an explicit `null` (decoded to `Some(None)`) clears the
        // restriction entirely; a subsequent read must show it unrestricted.
        let reset = svc
            .update_mapping(
                provider.id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: Some(None),
                    is_enabled: Some(true),
                    group_binding_ids: None,
                },
            )
            .await
            .expect("explicit null repo scope should clear the restriction");
        assert_eq!(reset.allowed_repo_ids, None);

        let reread = svc
            .get_mapping(provider.id, created.id)
            .await
            .expect("mapping should be readable after scope reset");
        assert_eq!(reread.allowed_repo_ids, None);

        // Restrict again so the resolve assertion below stays a deny-all pin.
        svc.update_mapping(
            provider.id,
            created.id,
            super::UpdateCiOidcMappingRequest {
                name: None,
                priority: None,
                claim_filters: None,
                allowed_repo_ids: Some(Some(vec![])),
                is_enabled: Some(true),
                group_binding_ids: None,
            },
        )
        .await
        .expect("re-restricting should update");

        let resolved = svc
            .resolve_mapping(provider.id, &json!({"ref": "refs/heads/release"}))
            .await
            .expect("matching claims should resolve mapping");
        assert_eq!(resolved.id, created.id);
        assert_eq!(resolved.allowed_repo_ids, Some(vec![]));

        let toggled = svc
            .toggle_mapping(provider.id, created.id, false)
            .await
            .expect("mapping should toggle");
        assert!(!toggled.is_enabled);

        let err = svc
            .resolve_mapping(provider.id, &json!({"ref": "refs/heads/release"}))
            .await
            .expect_err("disabled mapping should not resolve");
        assert!(err
            .to_string()
            .contains("No CI OIDC identity mappings configured"));

        svc.delete_mapping(provider.id, created.id)
            .await
            .expect("mapping should delete");
        svc.delete(provider.id)
            .await
            .expect("provider should delete");
    }
    // -----------------------------------------------------------------------
    // Mapping-provisioned service accounts (fix-ci-oidc-identity-key)
    // -----------------------------------------------------------------------

    async fn gitlab_provider(svc: &CiOidcService) -> Uuid {
        svc.create(super::CreateCiOidcProviderRequest {
            name: format!("gitlab-{}", Uuid::new_v4()),
            provider_type: Some("gitlab".to_string()),
            issuer_url: "https://gitlab.example.com".to_string(),
            audience: None,
            is_enabled: Some(true),
            key_source: None,
            static_jwks: None,
        })
        .await
        .expect("provider should be created")
        .id
    }

    fn deploy_mapping() -> super::CreateCiOidcMappingRequest {
        super::CreateCiOidcMappingRequest {
            name: "deploy".to_string(),
            priority: None,
            claim_filters: json!({"project_path": "group/app"}),
            allowed_repo_ids: None,
            is_enabled: None,
            group_binding_ids: None,
        }
    }

    async fn seed_user(pool: &sqlx::PgPool, username: &str, email: &str) -> Uuid {
        sqlx::query_scalar("INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id")
            .bind(username)
            .bind(email)
            .fetch_one(pool)
            .await
            .expect("seed user")
    }

    async fn mapping_exists(pool: &sqlx::PgPool, id: Uuid) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_oidc_identity_mappings WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn drop_users(pool: &sqlx::PgPool, ids: &[Uuid]) {
        for sql in [
            "DELETE FROM user_group_members WHERE user_id = ANY($1)",
            "DELETE FROM ci_oidc_service_account_rekey_log WHERE user_id = ANY($1)",
            "DELETE FROM users WHERE id = ANY($1)",
        ] {
            let _ = sqlx::query(sql).bind(ids).execute(pool).await;
        }
    }

    /// 4.2 — a mapping whose derived username is taken is refused, naming
    /// the account, and nothing is written.
    #[tokio::test]
    async fn create_mapping_refuses_a_taken_username() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let mapping_id = Uuid::new_v4();
        let username = super::service_account_username(mapping_id);
        let squatter =
            seed_user(&pool, &username, &format!("{}@example.com", Uuid::new_v4())).await;

        let err = svc
            .create_mapping_with_id(provider_id, mapping_id, deploy_mapping())
            .await
            .expect_err("a taken service-account name must refuse the mapping");
        assert!(
            matches!(err, crate::error::AppError::Conflict(_)),
            "got: {err}"
        );
        assert!(
            err.to_string().contains(&username),
            "the error names the account: {err}"
        );
        assert!(
            !mapping_exists(&pool, mapping_id).await,
            "no mapping row written"
        );

        drop_users(&pool, &[squatter]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    /// A malformed pointer key refuses the create with a 400 naming the key,
    /// before anything is written: no mapping and no service account. An
    /// update carrying one leaves the stored filters untouched.
    #[tokio::test]
    async fn mapping_with_an_invalid_pointer_key_writes_nothing() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let mapping_id = Uuid::new_v4();
        let mut req = deploy_mapping();
        req.claim_filters = json!({"/kubernetes.io/~2bad": "x"});

        let err = svc
            .create_mapping_with_id(provider_id, mapping_id, req)
            .await
            .expect_err("an invalid pointer must refuse the create");
        assert!(
            matches!(err, crate::error::AppError::Validation(_)),
            "got: {err}"
        );
        assert!(err.to_string().contains("/kubernetes.io/~2bad"), "{err}");
        assert!(!mapping_exists(&pool, mapping_id).await, "no mapping row");
        let accounts = svc
            .fetch_service_accounts(&[super::service_account_external_id(provider_id, mapping_id)])
            .await
            .unwrap();
        assert!(accounts.is_empty(), "no service account");
        let by_name: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(super::service_account_username(mapping_id))
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert_eq!(by_name, None, "no service account under the derived name");

        let created = svc
            .create_mapping(provider_id, deploy_mapping())
            .await
            .unwrap();
        let err = svc
            .update_mapping(
                provider_id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: Some(json!({"/ns~": "x"})),
                    allowed_repo_ids: None,
                    is_enabled: None,
                    group_binding_ids: None,
                },
            )
            .await
            .expect_err("an invalid pointer must refuse the update");
        assert!(err.to_string().contains("/ns~"), "{err}");
        let stored = svc.get_mapping(provider_id, created.id).await.unwrap();
        assert_eq!(stored.claim_filters, deploy_mapping().claim_filters);

        drop_users(&pool, &[created.service_account_id.unwrap()]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    /// 3.1 — mapping and account are one transaction: when the account
    /// INSERT itself fails (here on the email, which the username pre-check
    /// does not cover) the mapping is rolled back with it.
    #[tokio::test]
    async fn create_mapping_is_atomic_with_its_account() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let mapping_id = Uuid::new_v4();
        let email = super::service_account_email(&super::service_account_username(mapping_id));
        let squatter = seed_user(&pool, &format!("squatter-{}", Uuid::new_v4()), &email).await;

        let err = svc
            .create_mapping_with_id(provider_id, mapping_id, deploy_mapping())
            .await
            .expect_err("an account that cannot be created must fail the mapping");
        assert!(
            matches!(err, crate::error::AppError::Conflict(_)),
            "got: {err}"
        );
        assert!(
            err.to_string().contains(&email),
            "the error names the conflict: {err}"
        );
        assert!(
            !mapping_exists(&pool, mapping_id).await,
            "the mapping was rolled back"
        );

        drop_users(&pool, &[squatter]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    // -----------------------------------------------------------------------
    // Group bindings (add-ci-oidc-mapping-grants)
    // -----------------------------------------------------------------------

    async fn seed_group(pool: &sqlx::PgPool) -> Uuid {
        crate::api::handlers::test_db_helpers::create_group(pool)
            .await
            .0
    }

    async fn drop_groups(pool: &sqlx::PgPool, ids: &[Uuid]) {
        let _ = sqlx::query("DELETE FROM groups WHERE id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await;
    }

    async fn member_group_ids(
        pool: &sqlx::PgPool,
        user_id: Uuid,
    ) -> std::collections::HashSet<Uuid> {
        sqlx::query_scalar::<_, Uuid>("SELECT group_id FROM user_group_members WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .collect()
    }

    /// Design D5 / spec "A binding names existing groups only": an unknown
    /// group id refuses the whole create, naming the offending group, and
    /// writes neither a mapping nor a group.
    #[tokio::test]
    async fn create_mapping_refuses_unknown_group_in_binding() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let ghost = Uuid::new_v4();
        let mut req = deploy_mapping();
        req.group_binding_ids = Some(vec![ghost]);

        let err = svc
            .create_mapping(provider_id, req)
            .await
            .expect_err("an unknown group id must refuse the create");
        assert!(
            matches!(err, crate::error::AppError::Validation(_)),
            "got: {err}"
        );
        assert!(
            err.to_string().contains(&ghost.to_string()),
            "the error names the offending group: {err}"
        );

        let mappings = svc.list_mappings(provider_id).await.unwrap();
        assert!(mappings.is_empty(), "no mapping was written");

        svc.delete(provider_id).await.expect("delete provider");
    }

    /// 3.1/3.3 — a mapping created with a binding reads it back unchanged
    /// and its account is already a member of the bound groups, with no
    /// token exchange having occurred.
    #[tokio::test]
    async fn create_mapping_with_binding_reconciles_immediately() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let group_a = seed_group(&pool).await;
        let group_b = seed_group(&pool).await;
        let mut req = deploy_mapping();
        req.group_binding_ids = Some(vec![group_a, group_b]);

        let created = svc
            .create_mapping(provider_id, req)
            .await
            .expect("mapping with a valid binding should be created");
        assert_eq!(
            created.group_binding_ids.as_ref().map(|v| {
                let mut v = v.clone();
                v.sort();
                v
            }),
            Some({
                let mut v = vec![group_a, group_b];
                v.sort();
                v
            })
        );
        let account_id = created.service_account_id.expect("account exists");
        let members = member_group_ids(&pool, account_id).await;
        assert_eq!(
            members,
            [group_a, group_b].into_iter().collect(),
            "the account is already a member before any exchange"
        );

        let got = svc.get_mapping(provider_id, created.id).await.unwrap();
        assert!(
            got.group_binding_ids.is_some(),
            "a mapping without a create-time binding would report None; this one must not"
        );

        drop_users(&pool, &[account_id]).await;
        drop_groups(&pool, &[group_a, group_b]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    /// Design D2 — absent, empty and non-empty are three states, not two, and
    /// they round-trip distinctly through create and update: omitting the
    /// field leaves a stored binding unchanged, `null` clears it back to
    /// absent, and `[]` is a declared-empty binding, never confused with "no
    /// claim".
    #[tokio::test]
    async fn mapping_binding_round_trips_absent_empty_and_set() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let group_a = seed_group(&pool).await;

        // Created with no binding at all: absent.
        let created = svc
            .create_mapping(provider_id, deploy_mapping())
            .await
            .unwrap();
        assert_eq!(created.group_binding_ids, None);
        let account_id = created.service_account_id.unwrap();

        // Omitted on update: stays absent.
        let unchanged = svc
            .update_mapping(
                provider_id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: None,
                    is_enabled: None,
                    group_binding_ids: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(unchanged.group_binding_ids, None);

        // Declared empty: reconciles (no-op here, nothing to strip) and is
        // reported as `Some(vec![])`, distinct from absent.
        let emptied = svc
            .update_mapping(
                provider_id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: None,
                    is_enabled: None,
                    group_binding_ids: Some(Some(vec![])),
                },
            )
            .await
            .unwrap();
        assert_eq!(emptied.group_binding_ids, Some(vec![]));

        // Declared with a group.
        let set = svc
            .update_mapping(
                provider_id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: None,
                    is_enabled: None,
                    group_binding_ids: Some(Some(vec![group_a])),
                },
            )
            .await
            .unwrap();
        assert_eq!(set.group_binding_ids, Some(vec![group_a]));
        assert_eq!(member_group_ids(&pool, account_id).await, [group_a].into());

        // Explicit null clears back to absent, and reconciliation leaves the
        // account's memberships exactly where they were — clearing the
        // binding stops reconciling, it does not strip anything itself.
        let cleared = svc
            .update_mapping(
                provider_id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: None,
                    is_enabled: None,
                    group_binding_ids: Some(None),
                },
            )
            .await
            .unwrap();
        assert_eq!(cleared.group_binding_ids, None);
        assert_eq!(
            member_group_ids(&pool, account_id).await,
            [group_a].into(),
            "clearing the binding to absent must not itself touch memberships"
        );

        drop_users(&pool, &[account_id]).await;
        drop_groups(&pool, &[group_a]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    /// Store a binding on a mapping row directly, bypassing the write path's
    /// own reconcile, so a test controls exactly what the reconciler reads.
    async fn store_binding(pool: &sqlx::PgPool, mapping_id: Uuid, binding: Option<&[Uuid]>) {
        sqlx::query("UPDATE ci_oidc_identity_mappings SET group_binding_ids = $2 WHERE id = $1")
            .bind(mapping_id)
            .bind(binding)
            .execute(pool)
            .await
            .unwrap();
    }

    /// An unbound mapping with its service account, for reconciler tests.
    async fn unbound_mapping(svc: &CiOidcService, provider_id: Uuid) -> (Uuid, Uuid) {
        let created = svc
            .create_mapping(provider_id, deploy_mapping())
            .await
            .expect("create mapping");
        (
            created.id,
            created.service_account_id.expect("account exists"),
        )
    }

    /// 4.1 — the reconciler over add-only, remove-only, mixed and dangling
    /// cases, and 4.4 — an in-sync reconciliation performs no writes. The
    /// target is always the binding stored on the mapping row (design D7).
    #[tokio::test]
    async fn reconcile_mapping_binding_add_remove_mixed_dangling_and_noop() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let (mapping_id, account_id) = unbound_mapping(&svc, provider_id).await;
        let (group_a, group_b, group_c) = (
            seed_group(&pool).await,
            seed_group(&pool).await,
            seed_group(&pool).await,
        );
        let ghost = Uuid::new_v4();
        let reconcile = || async {
            svc.reconcile_mapping_binding(mapping_id, account_id)
                .await
                .unwrap()
                .expect("a declared binding reconciles")
        };

        // Add-only: nothing -> {a, b}.
        store_binding(&pool, mapping_id, Some(&[group_a, group_b])).await;
        let report = reconcile().await;
        assert_eq!(report.added.len(), 2);
        assert!(report.removed.is_empty());
        assert!(report.dangling.is_empty());
        assert_eq!(
            member_group_ids(&pool, account_id).await,
            [group_a, group_b].into_iter().collect()
        );

        // In-sync: same target set again performs no writes.
        let noop = reconcile().await;
        assert!(noop.added.is_empty() && noop.removed.is_empty(), "{noop:?}");

        // Mixed: {a, b} -> {b, c} adds c, removes a.
        store_binding(&pool, mapping_id, Some(&[group_b, group_c])).await;
        let mixed = reconcile().await;
        assert_eq!(mixed.added, vec![group_c]);
        assert_eq!(mixed.removed, vec![group_a]);
        assert_eq!(
            member_group_ids(&pool, account_id).await,
            [group_b, group_c].into_iter().collect()
        );

        // Remove-only: {b, c} -> {} strips everything.
        store_binding(&pool, mapping_id, Some(&[])).await;
        let removed_all = reconcile().await;
        assert_eq!(
            removed_all.removed.len(),
            2,
            "an empty target set removes every membership"
        );
        assert!(member_group_ids(&pool, account_id).await.is_empty());

        // Dangling: a target naming a group that no longer exists is skipped
        // and reported, not silently dropped from the attempted set, and the
        // still-valid target alongside it is still applied.
        store_binding(&pool, mapping_id, Some(&[group_a, ghost])).await;
        let dangling = reconcile().await;
        assert_eq!(dangling.added, vec![group_a]);
        assert_eq!(dangling.dangling, vec![ghost]);
        assert_eq!(member_group_ids(&pool, account_id).await, [group_a].into());

        // Absent: no binding, no reconcile, the membership stays (D2).
        store_binding(&pool, mapping_id, None).await;
        assert_eq!(
            svc.reconcile_mapping_binding(mapping_id, account_id)
                .await
                .unwrap(),
            None
        );
        assert_eq!(member_group_ids(&pool, account_id).await, [group_a].into());

        // A mapping that no longer exists is an error, not an empty binding.
        let err = svc
            .reconcile_mapping_binding(Uuid::new_v4(), account_id)
            .await
            .expect_err("a missing mapping must not reconcile");
        assert!(
            matches!(err, crate::error::AppError::NotFound(_)),
            "got: {err}"
        );

        drop_users(&pool, &[account_id]).await;
        drop_groups(&pool, &[group_a, group_b, group_c]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    /// Design D7, spec "An exchange in flight cannot undo a narrowing": the
    /// reconciler applies the binding as stored, not the wider one a caller
    /// resolved earlier. The account holds {a, b} from the old binding; the
    /// row now says {b}; reconciling leaves {b} and nothing else.
    #[tokio::test]
    async fn reconcile_mapping_binding_ignores_a_stale_snapshot() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let (mapping_id, account_id) = unbound_mapping(&svc, provider_id).await;
        let (group_a, group_b) = (seed_group(&pool).await, seed_group(&pool).await);

        store_binding(&pool, mapping_id, Some(&[group_a, group_b])).await;
        let stale = svc.get_mapping(provider_id, mapping_id).await.unwrap();
        svc.reconcile_mapping_binding(mapping_id, account_id)
            .await
            .unwrap();
        store_binding(&pool, mapping_id, Some(&[group_b])).await;

        assert_eq!(
            stale.group_binding_ids.map(|v| v.len()),
            Some(2),
            "the caller's copy still names both groups"
        );
        let report = svc
            .reconcile_mapping_binding(mapping_id, account_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.removed, vec![group_a]);
        assert_eq!(member_group_ids(&pool, account_id).await, [group_b].into());

        drop_users(&pool, &[account_id]).await;
        drop_groups(&pool, &[group_a, group_b]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    /// Make every membership write naming `group_id` fail, so a reconcile
    /// that has to touch it errors mid-transaction. Scoped to a group the
    /// calling test seeded, so concurrent tests are unaffected. Returns the
    /// trigger's name for [`allow_membership_writes`].
    async fn fail_membership_writes(pool: &sqlx::PgPool, group_id: Uuid) -> String {
        let name = format!("ci_test_fail_{}", group_id.simple());
        sqlx::query(sqlx::AssertSqlSafe(&*format!(
            "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF COALESCE(NEW.group_id, OLD.group_id) = '{group_id}'::uuid THEN \
                 RAISE EXCEPTION 'injected membership write failure'; \
               END IF; \
               RETURN COALESCE(NEW, OLD); \
             END $$"
        )))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(&*format!(
            "CREATE TRIGGER {name} BEFORE INSERT OR DELETE ON user_group_members \
             FOR EACH ROW EXECUTE FUNCTION {name}()"
        )))
        .execute(pool)
        .await
        .unwrap();
        name
    }

    async fn allow_membership_writes(pool: &sqlx::PgPool, name: &str) {
        sqlx::query(sqlx::AssertSqlSafe(&*format!(
            "DROP TRIGGER IF EXISTS {name} ON user_group_members"
        )))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(&*format!(
            "DROP FUNCTION IF EXISTS {name}()"
        )))
        .execute(pool)
        .await
        .unwrap();
    }

    /// Design D7, spec "A mapping update that cannot reconcile changes
    /// nothing": the row update and the reconcile are one transaction, so
    /// a failed reconcile leaves the stored binding AND the memberships as
    /// they were — the binding never claims a narrowing that did not happen.
    #[tokio::test]
    async fn update_mapping_that_cannot_reconcile_changes_nothing() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let (group_a, group_b) = (seed_group(&pool).await, seed_group(&pool).await);
        let mut req = deploy_mapping();
        req.group_binding_ids = Some(vec![group_a, group_b]);
        let created = svc.create_mapping(provider_id, req).await.unwrap();
        let account_id = created.service_account_id.expect("account exists");

        let trigger = fail_membership_writes(&pool, group_a).await;
        let result = svc
            .update_mapping(
                provider_id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: None,
                    is_enabled: None,
                    group_binding_ids: Some(Some(vec![group_b])),
                },
            )
            .await;
        allow_membership_writes(&pool, &trigger).await;

        result.expect_err("a narrowing whose reconcile fails must report an error");
        let mut stored = svc
            .get_mapping(provider_id, created.id)
            .await
            .unwrap()
            .group_binding_ids
            .expect("still bound");
        stored.sort();
        let mut before = vec![group_a, group_b];
        before.sort();
        assert_eq!(stored, before, "the row was rolled back with the reconcile");
        assert_eq!(
            member_group_ids(&pool, account_id).await,
            [group_a, group_b].into_iter().collect(),
            "the memberships are unchanged"
        );

        drop_users(&pool, &[account_id]).await;
        drop_groups(&pool, &[group_a, group_b]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    /// Design D7, spec "A mapping create that cannot reconcile creates
    /// nothing": mapping, account and reconcile are one transaction, so a
    /// failed reconcile leaves nothing behind and a retry of the same create
    /// is not refused as a conflict with its own leftovers.
    #[tokio::test]
    async fn create_mapping_that_cannot_reconcile_creates_nothing() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let group_id = seed_group(&pool).await;
        let mapping_id = Uuid::new_v4();
        let username = super::service_account_username(mapping_id);
        let bound = || {
            let mut req = deploy_mapping();
            req.group_binding_ids = Some(vec![group_id]);
            req
        };

        let trigger = fail_membership_writes(&pool, group_id).await;
        let result = svc
            .create_mapping_with_id(provider_id, mapping_id, bound())
            .await;
        allow_membership_writes(&pool, &trigger).await;

        result.expect_err("a create whose reconcile fails must report an error");
        assert!(!mapping_exists(&pool, mapping_id).await, "no mapping row");
        let account: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert_eq!(account, None, "no service account");

        let (created, report) = svc
            .create_mapping_with_id(provider_id, mapping_id, bound())
            .await
            .expect("retrying the same create succeeds");
        assert_eq!(report.map(|r| r.added), Some(vec![group_id]));
        let account_id = created.service_account_id.expect("account exists");

        drop_users(&pool, &[account_id]).await;
        drop_groups(&pool, &[group_id]).await;
        svc.delete(provider_id).await.expect("delete provider");
    }

    /// A mapping created before mappings provisioned their own account has no
    /// attributed account until its first exchange. Binding it still saves:
    /// there is nothing to reconcile yet, and the first exchange applies the
    /// binding (design D3).
    #[tokio::test]
    async fn binding_a_mapping_without_an_account_saves_and_reconciles_nothing() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let provider_id = gitlab_provider(&svc).await;
        let group_id = seed_group(&pool).await;
        let mapping_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ci_oidc_identity_mappings (id, provider_id, name) \
             VALUES ($1, $2, 'legacy')",
        )
        .bind(mapping_id)
        .bind(provider_id)
        .execute(&pool)
        .await
        .expect("seed legacy mapping");

        let updated = svc
            .update_mapping(
                provider_id,
                mapping_id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: None,
                    is_enabled: None,
                    group_binding_ids: Some(Some(vec![group_id])),
                },
            )
            .await
            .expect("binding a mapping with no account yet still saves");

        assert_eq!(updated.group_binding_ids, Some(vec![group_id]));
        assert_eq!(updated.service_account_id, None);
        let members: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_group_members WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(members, 0, "no account exists to reconcile");

        svc.delete(provider_id).await.expect("delete provider");
        drop_groups(&pool, &[group_id]).await;
    }

    // -----------------------------------------------------------------------
    // Migration 232: re-keying pre-upgrade CI accounts
    //
    // The migration visits every legacy-shaped CI row in the database, so
    // these tests are in the `db-serial` group (`ci_rekey_`) and assert only
    // on the rows they seeded.
    // -----------------------------------------------------------------------

    const REKEY_MIGRATION: &str =
        include_str!("../../migrations/232_ci_oidc_service_account_key.sql");

    struct RekeyFixture {
        provider_id: Uuid,
        /// Attributable to exactly one mapping.
        owned: (Uuid, Uuid),
        /// Its mapping is gone.
        orphaned: Uuid,
        /// Two mappings share its 8-hex prefix.
        ambiguous: Uuid,
        group_id: Uuid,
    }

    impl RekeyFixture {
        fn users(&self) -> Vec<Uuid> {
            vec![self.owned.0, self.orphaned, self.ambiguous]
        }
    }

    async fn seed_rekey_fixture(pool: &sqlx::PgPool, svc: &CiOidcService) -> RekeyFixture {
        let provider_id = gitlab_provider(svc).await;
        let legacy_mapping = |id: Uuid| {
            sqlx::query(
                "INSERT INTO ci_oidc_identity_mappings (id, provider_id, name) \
                 VALUES ($1, $2, 'legacy')",
            )
            .bind(id)
            .bind(provider_id)
            .execute(pool)
        };
        let legacy_account = |short: String, sub: &'static str| async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO users (username, email, auth_provider, external_id) \
                 VALUES ($1, $2, 'ci', $3) RETURNING id",
            )
            .bind(format!("ci-{short}"))
            .bind(format!("ci-{short}@ci.artifact-keeper.internal"))
            .bind(sub)
            .fetch_one(pool)
            .await
            .expect("seed legacy account")
        };
        let prefix = || Uuid::new_v4().simple().to_string()[..8].to_string();

        let owned_mapping = Uuid::new_v4();
        legacy_mapping(owned_mapping).await.unwrap();
        let owned = legacy_account(
            owned_mapping.simple().to_string()[..8].to_string(),
            "project_path:group/app:ref_type:branch:ref:main",
        )
        .await;

        let orphaned =
            legacy_account(prefix(), "project_path:group/gone:ref_type:branch:ref:main").await;

        let shared = prefix();
        for tail in ["000000000001", "000000000002"] {
            legacy_mapping(Uuid::parse_str(&format!("{shared}-0000-4000-8000-{tail}")).unwrap())
                .await
                .unwrap();
        }
        let ambiguous =
            legacy_account(shared, "project_path:group/twin:ref_type:branch:ref:main").await;

        let group_id: Uuid =
            sqlx::query_scalar("INSERT INTO groups (name) VALUES ($1) RETURNING id")
                .bind(format!("ci-deployers-{}", Uuid::new_v4()))
                .fetch_one(pool)
                .await
                .unwrap();
        sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
            .bind(owned)
            .bind(group_id)
            .execute(pool)
            .await
            .unwrap();

        RekeyFixture {
            provider_id,
            owned: (owned, owned_mapping),
            orphaned,
            ambiguous,
            group_id,
        }
    }

    /// Each seeded row, whole, as JSON — the byte-for-byte comparison basis.
    async fn snapshot(pool: &sqlx::PgPool, ids: &[Uuid]) -> Vec<serde_json::Value> {
        sqlx::query_scalar("SELECT row_to_json(u) FROM users u WHERE id = ANY($1) ORDER BY id")
            .bind(ids)
            .fetch_all(pool)
            .await
            .unwrap()
    }

    async fn cleanup_rekey(pool: &sqlx::PgPool, svc: &CiOidcService, fx: &RekeyFixture) {
        drop_users(pool, &fx.users()).await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(fx.group_id)
            .execute(pool)
            .await;
        let _ = svc.delete(fx.provider_id).await;
    }

    /// 5.1 / 5.2 / 5.3 — one match is rewritten in place, zero and several
    /// matches are left alone, every decision is in the report, and the
    /// rewritten principal keeps its group membership.
    #[tokio::test]
    async fn ci_rekey_migration_rewrites_only_unambiguous_rows() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let fx = seed_rekey_fixture(&pool, &svc).await;
        let before = snapshot(&pool, &fx.users()).await;

        sqlx::raw_sql(REKEY_MIGRATION)
            .execute(&pool)
            .await
            .expect("migration 232 applies");

        let pool_ref = &pool;
        let key = |id: Uuid| async move {
            sqlx::query_scalar::<_, Option<String>>("SELECT external_id FROM users WHERE id = $1")
                .bind(id)
                .fetch_one(pool_ref)
                .await
                .unwrap()
        };
        let (owned, owned_mapping) = fx.owned;
        let new_key = super::service_account_external_id(fx.provider_id, owned_mapping);
        assert_eq!(key(owned).await.as_deref(), Some(new_key.as_str()));
        assert_eq!(
            key(fx.orphaned).await.as_deref(),
            Some("project_path:group/gone:ref_type:branch:ref:main")
        );
        assert_eq!(
            key(fx.ambiguous).await.as_deref(),
            Some("project_path:group/twin:ref_type:branch:ref:main")
        );
        let after = snapshot(&pool, &fx.users()).await;
        assert_eq!(after.len(), 3, "no row was deleted or recreated");
        for (b, a) in before.iter().zip(&after) {
            assert_eq!(b["id"], a["id"]);
            if b["id"] != json!(owned) {
                assert_eq!(b, a, "a skipped row is untouched");
            }
        }

        // 5.2: the membership now resolves through the new key to the same
        // principal it always named.
        let member: Uuid = sqlx::query_scalar(
            "SELECT u.id FROM user_group_members g JOIN users u ON u.id = g.user_id \
             WHERE g.group_id = $1 AND u.auth_provider = 'ci' AND u.external_id = $2",
        )
        .bind(fx.group_id)
        .bind(&new_key)
        .fetch_one(&pool)
        .await
        .expect("the group membership survives the re-key");
        assert_eq!(member, owned);

        // 5.3: the report.
        let report: Vec<(Uuid, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT user_id, outcome, previous_external_id, new_external_id \
             FROM ci_oidc_service_account_rekey_log WHERE user_id = ANY($1) ORDER BY id",
        )
        .bind(fx.users())
        .fetch_all(&pool)
        .await
        .unwrap();
        let outcome = |id: Uuid| {
            report
                .iter()
                .filter(|r| r.0 == id)
                .map(|r| (r.1.as_str(), r.2.as_deref(), r.3.as_deref()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            outcome(owned),
            vec![(
                "rewritten",
                Some("project_path:group/app:ref_type:branch:ref:main"),
                Some(new_key.as_str())
            )]
        );
        assert_eq!(
            outcome(fx.orphaned),
            vec![(
                "skipped_orphaned",
                Some("project_path:group/gone:ref_type:branch:ref:main"),
                None
            )]
        );
        assert_eq!(
            outcome(fx.ambiguous),
            vec![(
                "skipped_ambiguous",
                Some("project_path:group/twin:ref_type:branch:ref:main"),
                None
            )]
        );

        cleanup_rekey(&pool, &svc, &fx).await;
    }

    /// 5.4 — the rollback documented in the migration restores every row to
    /// its pre-migration state byte for byte.
    #[tokio::test]
    async fn ci_rekey_migration_rolls_back_byte_for_byte() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let fx = seed_rekey_fixture(&pool, &svc).await;
        let before = snapshot(&pool, &fx.users()).await;

        sqlx::raw_sql(REKEY_MIGRATION)
            .execute(&pool)
            .await
            .expect("migration 232 applies");
        assert_ne!(
            snapshot(&pool, &fx.users()).await,
            before,
            "something was rewritten"
        );

        // The rollback statement from the migration's header, scoped to the
        // fixture so it cannot touch rows another test owns.
        sqlx::query(
            "UPDATE users u SET external_id = l.previous_external_id \
             FROM ci_oidc_service_account_rekey_log l \
             WHERE l.user_id = u.id \
               AND l.outcome IN ('rewritten', 'adopted') \
               AND u.external_id = l.new_external_id \
               AND u.id = ANY($1)",
        )
        .bind(fx.users())
        .execute(&pool)
        .await
        .expect("rollback applies");

        assert_eq!(snapshot(&pool, &fx.users()).await, before);
        cleanup_rekey(&pool, &svc, &fx).await;
    }

    // -----------------------------------------------------------------------
    // Provider resolution from the assertion's issuer (#3548)
    // -----------------------------------------------------------------------

    /// Build a syntactically valid but unsigned JWT carrying `claims`.
    ///
    /// Resolution reads the claims WITHOUT verifying the signature, so an
    /// unsigned token is exactly the right input here: it proves the peek
    /// works and — because `validate_ci_jwt` still runs afterwards in the
    /// handler — that a forged `iss` buys nothing but a provider whose JWKS
    /// then refuses it.
    fn unsigned_jwt(claims: serde_json::Value) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(b"not-a-real-signature");
        format!("{header}.{payload}.{signature}")
    }

    fn provider_at(issuer: &str, audience: &str, is_enabled: bool) -> CiOidcProvider {
        CiOidcProvider {
            issuer_url: issuer.to_string(),
            audience: audience.to_string(),
            is_enabled,
            ..sample_provider("generic")
        }
    }

    fn hints(issuer: &str, audiences: &[&str]) -> UnverifiedAssertionHints {
        UnverifiedAssertionHints {
            issuer: issuer.to_string(),
            audiences: audiences.iter().map(|a| (*a).to_string()).collect(),
        }
    }

    #[test]
    fn peek_assertion_hints_reads_iss_and_both_aud_shapes() {
        let single = CiOidcService::peek_assertion_hints(&unsigned_jwt(serde_json::json!({
            "iss": "https://gitlab.example.com",
            "aud": "artifact-keeper",
        })))
        .expect("a JWT with a string iss must be peekable");
        assert_eq!(single.issuer, "https://gitlab.example.com");
        assert_eq!(single.audiences, vec!["artifact-keeper".to_string()]);

        // RFC 7519 §4.1.3 also permits an array of audiences.
        let multi = CiOidcService::peek_assertion_hints(&unsigned_jwt(serde_json::json!({
            "iss": "https://gitlab.example.com",
            "aud": ["artifact-keeper", "other"],
        })))
        .expect("array aud must be peekable");
        assert_eq!(
            multi.audiences,
            vec!["artifact-keeper".to_string(), "other".to_string()]
        );
    }

    /// The peek must not reject an assertion for being expired or
    /// wrong-audience: routing it to its provider is what lets
    /// `validate_ci_jwt` return the accurate error instead of "no provider".
    #[test]
    fn peek_assertion_hints_ignores_claim_validity() {
        let expired = CiOidcService::peek_assertion_hints(&unsigned_jwt(serde_json::json!({
            "iss": "https://gitlab.example.com",
            "aud": "artifact-keeper",
            "exp": 1_000_000_000i64,
        })))
        .expect("an expired assertion must still resolve to its provider");
        assert_eq!(expired.issuer, "https://gitlab.example.com");
    }

    #[test]
    fn peek_assertion_hints_rejects_garbage_and_missing_iss() {
        assert!(CiOidcService::peek_assertion_hints("ci.jwt.token").is_none());
        assert!(CiOidcService::peek_assertion_hints("not-a-jwt-at-all").is_none());
        assert!(
            CiOidcService::peek_assertion_hints(&unsigned_jwt(serde_json::json!({"sub": "x"})))
                .is_none(),
            "an assertion with no iss cannot select a provider"
        );
    }

    #[test]
    fn select_provider_by_issuer_matches_the_configured_issuer() {
        let wanted = provider_at("https://gitlab.example.com", "artifact-keeper", true);
        let candidates = vec![
            provider_at("https://token.actions.githubusercontent.com", "ak", true),
            wanted.clone(),
        ];

        let picked = CiOidcService::select_provider_by_issuer(
            candidates,
            &hints("https://gitlab.example.com", &["artifact-keeper"]),
        )
        .expect("the matching issuer must resolve");
        assert_eq!(picked.id, wanted.id);
    }

    /// A row configured with a trailing slash and an `iss` without one (or the
    /// reverse) are the same issuer — the normalisation `fetch_discovery`
    /// already applies before building the discovery URL.
    #[test]
    fn select_provider_by_issuer_normalises_trailing_slashes() {
        assert_eq!(
            normalize_issuer("https://gitlab.example.com/"),
            normalize_issuer("https://gitlab.example.com")
        );

        let stored_with_slash = provider_at("https://gitlab.example.com/", "artifact-keeper", true);
        let picked = CiOidcService::select_provider_by_issuer(
            vec![stored_with_slash.clone()],
            &hints("https://gitlab.example.com", &["artifact-keeper"]),
        )
        .expect("a trailing slash on the stored row must not hide it");
        assert_eq!(picked.id, stored_with_slash.id);

        let stored_bare = provider_at("https://gitlab.example.com", "artifact-keeper", true);
        let picked = CiOidcService::select_provider_by_issuer(
            vec![stored_bare.clone()],
            &hints("https://gitlab.example.com/", &["artifact-keeper"]),
        )
        .expect("a trailing slash on the assertion's iss must not hide the row");
        assert_eq!(picked.id, stored_bare.id);
    }

    #[test]
    fn select_provider_by_issuer_ignores_disabled_providers() {
        let disabled = provider_at("https://gitlab.example.com", "artifact-keeper", false);
        let err = CiOidcService::select_provider_by_issuer(
            vec![disabled],
            &hints("https://gitlab.example.com", &["artifact-keeper"]),
        )
        .expect_err("a disabled provider must not be resolvable");
        assert!(
            err.to_string().contains("No enabled CI OIDC provider"),
            "got: {err}"
        );
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::NOT_FOUND,
            "an unconfigured issuer is a 404, not a 500"
        );
    }

    #[test]
    fn select_provider_by_issuer_reports_an_unconfigured_issuer() {
        let err = CiOidcService::select_provider_by_issuer(
            vec![provider_at("https://gitlab.example.com", "ak", true)],
            &hints("https://token.actions.githubusercontent.com", &["ak"]),
        )
        .expect_err("an issuer nobody configured must not resolve");
        assert!(
            err.to_string().contains("No enabled CI OIDC provider"),
            "got: {err}"
        );
    }

    /// `ci_oidc_providers` has no UNIQUE constraint on `issuer_url`, so two
    /// enabled rows may share an issuer. The declared audience breaks the tie
    /// when it can.
    #[test]
    fn select_provider_by_issuer_breaks_a_tie_on_the_declared_audience() {
        let for_ci = provider_at("https://gitlab.example.com", "artifact-keeper-ci", true);
        let candidates = vec![
            provider_at("https://gitlab.example.com", "artifact-keeper", true),
            for_ci.clone(),
        ];

        let picked = CiOidcService::select_provider_by_issuer(
            candidates,
            &hints("https://gitlab.example.com", &["artifact-keeper-ci"]),
        )
        .expect("the audience must disambiguate two rows on one issuer");
        assert_eq!(picked.id, for_ci.id);
    }

    /// When the audience cannot break the tie either, refuse with a 400 that
    /// asks for `provider_id` — guessing which of two configurations an
    /// operator meant is exactly the wrong thing for an auth endpoint to do.
    #[test]
    fn select_provider_by_issuer_rejects_an_ambiguous_issuer() {
        let candidates = vec![
            provider_at("https://gitlab.example.com", "artifact-keeper", true),
            provider_at("https://gitlab.example.com", "artifact-keeper", true),
        ];

        let err = CiOidcService::select_provider_by_issuer(
            candidates,
            &hints("https://gitlab.example.com", &["artifact-keeper"]),
        )
        .expect_err("two providers on one issuer and one audience must not be guessed between");
        let msg = err.to_string();
        assert!(msg.contains("supply provider_id"), "got: {msg}");
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    /// DB-backed: an assertion carrying only its `iss` resolves the provider
    /// with no `provider_id` at all — the whole point of #3548 — and a
    /// `provider_id` naming a different issuer is refused with a 400 rather
    /// than silently verified against the wrong configuration.
    #[tokio::test]
    async fn resolve_provider_for_assertion_roundtrip() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());

        // Unique issuers so concurrent tests on a shared database cannot make
        // this one ambiguous.
        let tag = &Uuid::new_v4().to_string()[..8];
        let issuer = format!("https://issuer-{tag}.example.com");
        let other_issuer = format!("https://other-{tag}.example.com");

        let wanted = svc
            .create(super::CreateCiOidcProviderRequest {
                name: format!("resolve-by-issuer-{tag}"),
                provider_type: None,
                // Stored WITH a trailing slash; the assertion's iss has none.
                issuer_url: format!("{issuer}/"),
                audience: None,
                is_enabled: Some(true),
                key_source: None,
                static_jwks: None,
            })
            .await
            .expect("provider should be created");
        let other = svc
            .create(super::CreateCiOidcProviderRequest {
                name: format!("resolve-other-{tag}"),
                provider_type: None,
                issuer_url: other_issuer.clone(),
                audience: None,
                is_enabled: Some(true),
                key_source: None,
                static_jwks: None,
            })
            .await
            .expect("second provider should be created");

        let jwt = unsigned_jwt(serde_json::json!({
            "iss": issuer,
            "aud": "artifact-keeper",
            "sub": "ci:job",
        }));

        let resolved = svc
            .resolve_provider_for_assertion(&jwt, None)
            .await
            .expect("iss alone must resolve the provider");
        assert_eq!(resolved.id, wanted.id);

        // The explicit override still works (backward compatibility).
        let resolved = svc
            .resolve_provider_for_assertion(&jwt, Some(wanted.id))
            .await
            .expect("an agreeing provider_id override must still work");
        assert_eq!(resolved.id, wanted.id);

        // ... but only when it agrees with the assertion.
        let err = svc
            .resolve_provider_for_assertion(&jwt, Some(other.id))
            .await
            .expect_err("a provider_id for a different issuer must be refused");
        assert!(
            err.to_string().contains("Omit provider_id"),
            "the error must say how to fix it, got: {err}"
        );
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::BAD_REQUEST
        );

        // A disabled row is invisible to issuer resolution.
        svc.toggle(wanted.id, false)
            .await
            .expect("provider should toggle");
        let err = svc
            .resolve_provider_for_assertion(&jwt, None)
            .await
            .expect_err("a disabled provider must not be resolvable by issuer");
        assert!(
            err.to_string().contains("No enabled CI OIDC provider"),
            "got: {err}"
        );
        // ... and naming it explicitly still reports it as disabled.
        let err = svc
            .resolve_provider_for_assertion(&jwt, Some(wanted.id))
            .await
            .expect_err("a disabled provider must be refused via the override too");
        assert!(
            err.to_string().contains("provider is disabled"),
            "got: {err}"
        );

        svc.delete(wanted.id).await.expect("cleanup wanted");
        svc.delete(other.id).await.expect("cleanup other");
    }

    // -----------------------------------------------------------------------
    // Key source (add-ci-oidc-kubernetes-provider D2, D3)
    // -----------------------------------------------------------------------

    /// kubeadm's default issuer: not resolvable from here, so any attempt at
    /// discovery fails the exchange.
    const ONPREM_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";

    /// An RSA signing key and its public JWK under `kid`.
    struct TestKey {
        encoding: jsonwebtoken::EncodingKey,
        jwk: serde_json::Value,
    }

    /// Two distinct 2048-bit keys, generated once per test process: keygen
    /// dominates the wall clock otherwise.
    fn test_keys() -> &'static [rsa::RsaPrivateKey; 2] {
        static KEYS: std::sync::OnceLock<[rsa::RsaPrivateKey; 2]> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            let gen = || rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
            [gen(), gen()]
        })
    }

    fn test_key(index: usize, kid: Option<&str>) -> TestKey {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::traits::PublicKeyParts;
        let private = &test_keys()[index];
        let pem = private.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let mut jwk = json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
        });
        if let Some(kid) = kid {
            jwk["kid"] = json!(kid);
        }
        TestKey {
            encoding: jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            jwk,
        }
    }

    fn sign(key: &TestKey, kid: Option<&str>, claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = kid.map(str::to_owned);
        jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
    }

    fn k8s_token_claims(issuer: &str) -> serde_json::Value {
        let now = Utc::now().timestamp();
        let mut claims = k8s_claims("payments", "api");
        claims["iss"] = json!(issuer);
        claims["aud"] = json!(["artifact-keeper"]);
        claims["iat"] = json!(now);
        claims["nbf"] = json!(now);
        claims["exp"] = json!(now + 600);
        claims
    }

    fn static_provider(keys: &[&TestKey]) -> CiOidcProvider {
        CiOidcProvider {
            issuer_url: ONPREM_ISSUER.to_string(),
            key_source: super::KEY_SOURCE_STATIC.to_string(),
            static_jwks: Some(
                json!({"keys": keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()}),
            ),
            ..sample_provider("kubernetes")
        }
    }

    /// #4511: `nbf` is checked like `exp`, with the same leeway, whatever
    /// the key source. A token not valid for another five minutes is
    /// refused; one 30 s ahead (clock skew, inside the 60 s leeway) verifies.
    #[tokio::test]
    async fn a_token_whose_nbf_is_in_the_future_is_refused_4511() {
        let validation =
            super::ci_jwt_validation(jsonwebtoken::Algorithm::RS256, &sample_provider("gitlab"));
        assert!(validation.validate_nbf && validation.validate_exp);
        assert_eq!(validation.leeway, 60);

        let k1 = test_key(0, Some("k1"));
        let provider = static_provider(&[&k1]);
        let now = Utc::now().timestamp();
        let with_nbf = |nbf: i64| {
            let mut claims = k8s_token_claims(ONPREM_ISSUER);
            claims["nbf"] = json!(nbf);
            sign(&k1, Some("k1"), &claims)
        };

        let err = test_service()
            .validate_ci_jwt(&provider, &with_nbf(now + 300))
            .await
            .expect_err("a token that is not valid yet is refused");
        assert!(
            matches!(&err, crate::error::AppError::Authentication(m) if m.contains("ImmatureSignature")),
            "{err:?}"
        );
        test_service()
            .validate_ci_jwt(&provider, &with_nbf(now + 30))
            .await
            .expect("an nbf within the clock-skew leeway still verifies");
        test_service()
            .validate_ci_jwt(&provider, &with_nbf(now - 30))
            .await
            .expect("an nbf in the past verifies");
    }

    /// 3.1 — a static provider verifies against its stored set and never
    /// contacts the issuer: kubeadm's in-cluster issuer is not resolvable
    /// here, so a discovery attempt would fail the call.
    #[tokio::test]
    async fn static_provider_verifies_without_contacting_the_issuer() {
        let k1 = test_key(0, Some("k1"));
        let provider = static_provider(&[&k1]);
        let jwt = sign(&k1, Some("k1"), &k8s_token_claims(ONPREM_ISSUER));

        let claims = test_service()
            .validate_ci_jwt(&provider, &jwt)
            .await
            .expect("a token signed by a stored key verifies with no network");
        assert_eq!(claims["kubernetes.io"]["namespace"], "payments");

        // The same provider on `discovery` does try the issuer, and fails.
        let discovering = CiOidcProvider {
            key_source: super::KEY_SOURCE_DISCOVERY.to_string(),
            static_jwks: None,
            ..provider
        };
        assert!(test_service()
            .validate_ci_jwt(&discovering, &jwt)
            .await
            .is_err());
    }

    /// `iss`, `aud` and expiry checks are shared with discovery.
    #[tokio::test]
    async fn static_provider_still_checks_issuer_audience_and_expiry() {
        let k1 = test_key(0, Some("k1"));
        let provider = static_provider(&[&k1]);
        let svc = test_service();
        let refused = |claims: serde_json::Value| {
            let jwt = sign(&k1, Some("k1"), &claims);
            let svc = &svc;
            let provider = &provider;
            async move {
                let err = svc.validate_ci_jwt(provider, &jwt).await.unwrap_err();
                assert_eq!(
                    axum::response::IntoResponse::into_response(err).status(),
                    axum::http::StatusCode::UNAUTHORIZED
                );
            }
        };

        let mut claims = k8s_token_claims("https://other-cluster.example.com");
        refused(claims.clone()).await;
        claims = k8s_token_claims(ONPREM_ISSUER);
        claims["aud"] = json!("https://kubernetes.default.svc");
        refused(claims.clone()).await;
        claims = k8s_token_claims(ONPREM_ISSUER);
        claims["exp"] = json!(Utc::now().timestamp() - 3600);
        refused(claims).await;
    }

    /// 3.2 — an unknown `kid` is refused by name and logged, and never
    /// retried against another key in the set.
    #[tokio::test]
    async fn static_provider_refuses_an_unknown_kid_by_name() {
        let k1 = test_key(0, Some("k1"));
        let provider = static_provider(&[&k1]);
        // Signed with the stored key under a kid the set does not hold: a
        // fall-back to the first key would verify it.
        let jwt = sign(&k1, Some("k2"), &k8s_token_claims(ONPREM_ISSUER));

        let capture = crate::api::handlers::test_db_helpers::LogCapture::default();
        let err = {
            let _guard = capture.install(tracing::Level::INFO);
            test_service()
                .validate_ci_jwt(&provider, &jwt)
                .await
                .expect_err("an unknown kid must be refused")
        };
        assert!(err.to_string().contains("'k2'"), "names the kid: {err}");
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::UNAUTHORIZED
        );
        let logs = capture.text();
        assert!(
            logs.contains(&format!("provider_id={}", provider.id)) && logs.contains("kid=\"k2\""),
            "the security line names provider and kid: {logs}"
        );
    }

    /// The unauthenticated exchange cannot flood the `security` log: a
    /// second unknown-kid refusal for the same provider within the window
    /// is still refused, but logs at DEBUG instead of WARN.
    #[tokio::test]
    async fn unknown_kid_warning_is_throttled_per_provider() {
        let k1 = test_key(0, Some("k1"));
        let provider = static_provider(&[&k1]);
        let other = static_provider(&[&k1]);
        let jwt = sign(&k1, Some("forged"), &k8s_token_claims(ONPREM_ISSUER));

        let capture = crate::api::handlers::test_db_helpers::LogCapture::default();
        {
            let _guard = capture.install(tracing::Level::DEBUG);
            for provider in [&provider, &provider, &provider, &other] {
                let err = test_service()
                    .validate_ci_jwt(provider, &jwt)
                    .await
                    .expect_err("an unknown kid is always refused");
                assert_eq!(
                    axum::response::IntoResponse::into_response(err).status(),
                    axum::http::StatusCode::UNAUTHORIZED
                );
            }
        }
        let logs = capture.text();
        let lines = |level: &str, id: Uuid| {
            let prefix = format!("{level} security: CI OIDC: token key id");
            logs.lines()
                .filter(|l| l.contains(&prefix) && l.contains(&format!("provider_id={id}")))
                .count()
        };
        assert_eq!(lines("WARN", provider.id), 1, "{logs}");
        assert_eq!(lines("DEBUG", provider.id), 2, "{logs}");
        assert_eq!(
            lines("WARN", other.id),
            1,
            "another provider has its own window"
        );
    }

    /// The algorithm checks are shared with discovery but pinned here for
    /// the static path too: `alg: none`, an HMAC token keyed with the public
    /// key (the classic confusion attack) and an algorithm whose family does
    /// not match the stored key are each refused with 401, all under a `kid`
    /// the set holds.
    #[tokio::test]
    async fn static_provider_refuses_none_hmac_and_mismatched_algorithms() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let k1 = test_key(0, Some("k1"));
        let provider = static_provider(&[&k1]);
        let claims = k8s_token_claims(ONPREM_ISSUER);
        let segment = |v: serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let body = segment(claims.clone());

        let none = format!(
            "{}.{body}.",
            segment(json!({"alg": "none", "typ": "JWT", "kid": "k1"}))
        );

        let mut hs_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        hs_header.kid = Some("k1".into());
        let public_n = k1.jwk["n"].as_str().unwrap().as_bytes().to_vec();
        let hmac = jsonwebtoken::encode(
            &hs_header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&public_n),
        )
        .unwrap();

        // An RSA key in the set, an EC algorithm in the header.
        let rs = sign(&k1, Some("k1"), &claims);
        let signature = rs.rsplit('.').next().unwrap();
        let mismatched = format!(
            "{}.{body}.{signature}",
            segment(json!({"alg": "ES256", "typ": "JWT", "kid": "k1"}))
        );

        for (case, jwt) in [
            ("alg none", none),
            ("HS256", hmac),
            ("ES256 on RSA", mismatched),
        ] {
            let err = test_service()
                .validate_ci_jwt(&provider, &jwt)
                .await
                .expect_err(case);
            assert_eq!(
                axum::response::IntoResponse::into_response(err).status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "{case}"
            );
        }
        // Control: the same claims, properly signed, verify.
        test_service()
            .validate_ci_jwt(&provider, &rs)
            .await
            .expect("control token verifies");
    }

    /// Rotation overlap: both keys of the set verify their own tokens.
    #[tokio::test]
    async fn static_provider_accepts_either_key_during_rotation() {
        let (k1, k2) = (test_key(0, Some("k1")), test_key(1, Some("k2")));
        let provider = static_provider(&[&k1, &k2]);
        let claims = k8s_token_claims(ONPREM_ISSUER);
        for (key, kid) in [(&k1, "k1"), (&k2, "k2")] {
            test_service()
                .validate_ci_jwt(&provider, &sign(key, Some(kid), &claims))
                .await
                .unwrap_or_else(|e| panic!("{kid} must verify: {e}"));
        }
        // And a kid names its key strictly: k2's token under k1's kid fails.
        assert!(test_service()
            .validate_ci_jwt(&provider, &sign(&k2, Some("k1"), &claims))
            .await
            .is_err());
    }

    /// A token without a `kid` verifies only against a single-key set.
    #[tokio::test]
    async fn static_provider_accepts_a_missing_kid_only_with_one_key() {
        let (k1, k2) = (test_key(0, Some("k1")), test_key(1, Some("k2")));
        let claims = k8s_token_claims(ONPREM_ISSUER);
        let jwt = sign(&k1, None, &claims);

        test_service()
            .validate_ci_jwt(&static_provider(&[&k1]), &jwt)
            .await
            .expect("one key: a kid-less token uses it");

        let err = test_service()
            .validate_ci_jwt(&static_provider(&[&k1, &k2]), &jwt)
            .await
            .expect_err("two keys: a kid-less token is ambiguous");
        assert!(err.to_string().contains("no key id"), "{err}");
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::UNAUTHORIZED
        );
    }

    /// The discovery path keeps its fall-back-to-first selection (D3).
    #[test]
    fn discovery_key_selection_still_falls_back_to_the_first_key() {
        let keys = vec![test_key(0, Some("k1")).jwk];
        assert!(CiOidcService::select_jwk_key(&keys, Some("unknown")).is_ok());
        assert!(CiOidcService::select_jwk_key(&keys, None).is_ok());
    }

    // -- Save-time JWKS validation (2.3) ------------------------------------

    fn assert_refused(jwks: serde_json::Value, needle: &str) {
        let err = super::validate_static_jwks(&jwks).expect_err("must be refused");
        assert!(
            err.to_string().contains(needle),
            "expected '{needle}' in: {err}"
        );
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn static_jwks_size_and_key_count_are_capped() {
        let keys = |n: usize| -> Vec<serde_json::Value> {
            (0..n)
                .map(|i| super::test_public_jwk(&format!("k{i}")))
                .collect()
        };
        super::validate_static_jwks(&json!({ "keys": keys(super::MAX_STATIC_JWKS_KEYS) }))
            .expect("exactly the maximum number of keys is accepted");
        assert_refused(
            json!({ "keys": keys(super::MAX_STATIC_JWKS_KEYS + 1) }),
            "exceeds the limit of 16",
        );

        let mut padded = super::test_public_jwk("k1");
        padded["x5c"] = json!(["A".repeat(super::MAX_STATIC_JWKS_BYTES)]);
        assert_refused(json!({ "keys": [padded] }), "bytes exceeds the limit");
    }

    #[test]
    fn static_jwks_validation_refuses_each_unusable_set() {
        super::validate_static_jwks(
            &json!({"keys": [super::test_public_jwk("k1"), super::test_public_jwk("k2")]}),
        )
        .expect("two public keys with unique kids are a valid set");

        assert_refused(json!({"keys": []}), "non-empty \"keys\"");
        assert_refused(json!([super::test_public_jwk("k1")]), "non-empty \"keys\"");
        assert_refused(json!({"keys": "k1"}), "non-empty \"keys\"");
        assert_refused(json!({"keys": ["k1"]}), "not a JSON object");
        assert_refused(
            json!({"keys": [{"kty": "oct", "kid": "k1", "alg": "HS256"}]}),
            "not a supported public key",
        );
        assert_refused(
            json!({"keys": [{"kty": "RSA", "kid": "k1", "e": "AQAB"}]}),
            "missing 'n'",
        );
        assert_refused(
            json!({"keys": [super::test_public_jwk("k1"), super::test_public_jwk("k1")]}),
            "share the kid 'k1'",
        );

        let mut private = super::test_public_jwk("k1");
        private["d"] = json!("c2VjcmV0");
        assert_refused(
            json!({"keys": [private]}),
            "private key material is not accepted",
        );
        let mut symmetric = super::test_public_jwk("k1");
        symmetric["k"] = json!("c2VjcmV0");
        assert_refused(json!({"keys": [symmetric]}), "private member 'k'");
    }

    #[test]
    fn resolve_key_material_enforces_the_source_jwks_pairing() {
        use super::resolve_key_material as resolve;
        let jwks = json!({"keys": [super::test_public_jwk("k1")]});

        // Create: default discovery; static requires a JWKS; unknown refused.
        assert_eq!(
            resolve(None, None, None).unwrap(),
            ("discovery".into(), None)
        );
        assert!(resolve(Some("static".into()), None, None)
            .unwrap_err()
            .to_string()
            .contains("requires static_jwks"));
        assert!(resolve(None, Some(jwks.clone()), None)
            .unwrap_err()
            .to_string()
            .contains("only accepted with key_source 'static'"));
        assert!(resolve(Some("pinned".into()), None, None)
            .unwrap_err()
            .to_string()
            .contains("Unknown key_source 'pinned'"));

        // Update: omitted fields keep the stored pair; switching to discovery
        // discards the stored JWKS.
        let stored = Some(("static", Some(&jwks)));
        assert_eq!(
            resolve(None, None, stored).unwrap(),
            ("static".into(), Some(jwks.clone()))
        );
        assert_eq!(
            resolve(Some("discovery".into()), None, stored).unwrap(),
            ("discovery".into(), None)
        );
        let replacement =
            json!({"keys": [super::test_public_jwk("k1"), super::test_public_jwk("k2")]});
        assert_eq!(
            resolve(None, Some(replacement.clone()), stored).unwrap(),
            ("static".into(), Some(replacement))
        );
    }

    /// 2.2 / 2.3 — the key source round-trips through create, update and
    /// both read paths; a refused update leaves the provider unchanged;
    /// switching back to discovery discards the stored set.
    #[tokio::test]
    async fn provider_key_source_crud_roundtrip() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());
        let jwks = json!({"keys": [super::test_public_jwk("k1")]});

        let err = svc
            .create(super::CreateCiOidcProviderRequest {
                name: format!("k8s-static-{}", Uuid::new_v4()),
                provider_type: Some("kubernetes".into()),
                issuer_url: ONPREM_ISSUER.into(),
                audience: None,
                is_enabled: None,
                key_source: Some("static".into()),
                static_jwks: None,
            })
            .await
            .expect_err("static without a JWKS is refused");
        assert!(
            matches!(err, crate::error::AppError::Validation(_)),
            "{err}"
        );

        let created = svc
            .create(super::CreateCiOidcProviderRequest {
                name: format!("k8s-static-{}", Uuid::new_v4()),
                provider_type: Some("kubernetes".into()),
                issuer_url: ONPREM_ISSUER.into(),
                audience: None,
                is_enabled: None,
                key_source: Some("static".into()),
                static_jwks: Some(jwks.clone()),
            })
            .await
            .expect("static provider with a valid JWKS");
        assert_eq!(created.provider_type, "kubernetes");
        assert_eq!(created.key_source, "static");
        assert_eq!(created.static_jwks.as_ref(), Some(&jwks));
        let row = svc.get(created.id).await.unwrap();
        assert_eq!(row.static_jwks.as_ref(), Some(&jwks));
        let listed = svc.list().await.unwrap();
        let from_list = listed.iter().find(|p| p.id == created.id).unwrap();
        assert_eq!(from_list.key_source, "static");

        let empty_update = || super::UpdateCiOidcProviderRequest {
            name: None,
            provider_type: None,
            issuer_url: None,
            audience: None,
            is_enabled: None,
            key_source: None,
            static_jwks: None,
        };

        // A private key is refused and the stored set is unchanged.
        let mut private = super::test_public_jwk("k2");
        private["d"] = json!("c2VjcmV0");
        let err = svc
            .update(
                created.id,
                super::UpdateCiOidcProviderRequest {
                    static_jwks: Some(json!({"keys": [private]})),
                    ..empty_update()
                },
            )
            .await
            .err()
            .expect("private material is refused");
        assert!(err.to_string().contains("private key material"), "{err}");
        assert_eq!(svc.get(created.id).await.unwrap().static_jwks, Some(jwks));

        // Replacing the set reports a key-material change; an unrelated
        // edit does not.
        let rotated = json!({"keys": [super::test_public_jwk("k1"), super::test_public_jwk("k2")]});
        let update = svc
            .update(
                created.id,
                super::UpdateCiOidcProviderRequest {
                    static_jwks: Some(rotated.clone()),
                    ..empty_update()
                },
            )
            .await
            .unwrap();
        assert!(update.key_material_changed);
        assert_eq!(update.provider.static_jwks, Some(rotated));
        let rename = svc
            .update(
                created.id,
                super::UpdateCiOidcProviderRequest {
                    name: Some(format!("k8s-renamed-{}", Uuid::new_v4())),
                    ..empty_update()
                },
            )
            .await
            .unwrap();
        assert!(!rename.key_material_changed);

        // Back to discovery: the stored set is discarded.
        let back = svc
            .update(
                created.id,
                super::UpdateCiOidcProviderRequest {
                    key_source: Some("discovery".into()),
                    ..empty_update()
                },
            )
            .await
            .unwrap();
        assert!(back.key_material_changed);
        assert_eq!(back.provider.key_source, "discovery");
        assert_eq!(back.provider.static_jwks, None);

        svc.delete(created.id).await.expect("delete provider");
    }
}
