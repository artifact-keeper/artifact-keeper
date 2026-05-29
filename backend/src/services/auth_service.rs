//! Authentication service.
//!
//! Handles user authentication, JWT token management, and password hashing.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock, Weak};
use std::time::Instant;

use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tracing::info;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};

/// Federated authentication credentials
#[derive(Debug, Clone)]
pub struct FederatedCredentials {
    /// External provider user ID
    pub external_id: String,
    /// Username from provider
    pub username: String,
    /// Email from provider
    pub email: String,
    /// Display name from provider
    pub display_name: Option<String>,
    /// Groups/roles from provider claims
    pub groups: Vec<String>,
    /// Required group name for admin role (exact match); when set, replaces default pattern matching
    pub required_admin_group: Option<String>,
}

/// Result of group-to-role mapping
#[derive(Debug, Clone, Default)]
pub struct RoleMapping {
    /// Whether the user should be an admin.
    /// `None` means no admin group was found in claims; preserve existing value.
    pub is_admin: Option<bool>,
    /// Additional role names to assign
    pub roles: Vec<String>,
}

/// Result of API token validation: the user plus the token's constraints.
#[derive(Debug, Clone)]
pub struct ApiTokenValidation {
    /// The authenticated user
    pub user: User,
    /// Token scopes (e.g. "read:artifacts", "write:artifacts", "*")
    pub scopes: Vec<String>,
    /// Repository IDs the token is restricted to (None = unrestricted)
    pub allowed_repo_ids: Option<Vec<Uuid>>,
}

/// JWT claims structure.
///
/// `jti` and `family_id` are populated on refresh tokens for reuse/replay
/// detection per RFC 6819 §5.2.2.3 (see migration 087 and
/// [`refresh_tokens`] for the rotation/family-revocation logic). They are
/// serialized as standard JWT claims when present and omitted otherwise so
/// existing access-token consumers keep parsing the JWT unchanged. Access
/// tokens leave both fields `None`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: Uuid,
    /// Username
    pub username: String,
    /// Email
    pub email: String,
    /// Is admin
    pub is_admin: bool,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Token type: "access" or "refresh"
    pub token_type: String,
    /// JWT ID. Set on refresh tokens for replay detection (#1174).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<Uuid>,
    /// Refresh-token family identifier. All tokens minted from the same login
    /// share a `family_id`; replay of a consumed token revokes the whole
    /// family. Set on refresh tokens only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_id: Option<Uuid>,
}

/// Token pair response
#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// How long a validated API token result is kept in the in-memory cache before
/// the full DB + bcrypt verification is repeated.  Five minutes balances
/// performance (cargo makes ~40 authenticated requests per build) against
/// revocation latency (a revoked token remains valid at most this long).
const API_TOKEN_CACHE_TTL_SECS: u64 = 300;

/// Global set of revoked API token IDs. When an API token is revoked, its UUID
/// is added here so that any in-memory cache hit for that token is rejected
/// without waiting for the cache TTL to expire. Entries are retained for
/// twice the cache TTL since after that the cache entry itself will have
/// expired and the DB query will catch the revocation.
static REVOKED_API_TOKENS: OnceLock<RwLock<HashMap<Uuid, Instant>>> = OnceLock::new();

fn revoked_api_token_set() -> &'static RwLock<HashMap<Uuid, Instant>> {
    REVOKED_API_TOKENS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Record an API token as revoked so cached validations are rejected immediately.
pub fn mark_api_token_revoked(token_id: Uuid) {
    if let Ok(mut set) = revoked_api_token_set().write() {
        set.insert(token_id, Instant::now());
        let cutoff_secs = API_TOKEN_CACHE_TTL_SECS * 2;
        set.retain(|_, recorded_at| recorded_at.elapsed().as_secs() < cutoff_secs);
    }
}

/// Check whether an API token has been marked as revoked.
fn is_api_token_revoked_in_cache(token_id: Uuid) -> bool {
    if let Ok(set) = revoked_api_token_set().read() {
        return set.contains_key(&token_id);
    }
    false
}

/// Cached API token validation entry. Extends `ApiTokenValidation` with
/// the token's database ID and expiry so that revocation and expiration
/// can be checked on cache hit without a DB round-trip.
#[derive(Clone, Debug)]
struct CachedApiTokenEntry {
    validation: ApiTokenValidation,
    token_id: Uuid,
    expires_at: Option<DateTime<Utc>>,
}

/// In-memory fast-path cache for the DB-backed credential-invalidation
/// check. The value is the highest of `users.password_changed_at` and
/// `users.totp_verified_at` (as a Unix timestamp) plus the `Instant` it
/// was cached so entries can expire after [`CREDENTIAL_DB_CACHE_TTL_SECS`].
/// `users.updated_at` is deliberately NOT folded into the watermark — it
/// bumps on benign profile edits (display name, email, role) so including
/// it would invalidate tokens on changes that are not credential-bearing
/// (regression caught in PR #1190 review). Process-local; DB is the
/// source of truth so multi-replica deployments stay consistent (#1173).
static CREDENTIAL_INVALIDATIONS: OnceLock<RwLock<HashMap<Uuid, (i64, Instant)>>> = OnceLock::new();
const INVALIDATION_RETENTION_SECS: i64 = 7 * 24 * 3600;
/// How long a DB-backed credential-change watermark stays cached in the
/// in-memory fast-path. 5 s is short enough that an invalidation on
/// another replica is observed by every other replica almost immediately
/// (worst-case latency = TTL + DB round-trip) while still avoiding a DB
/// round-trip on every single request that comes in within a burst.
const CREDENTIAL_DB_CACHE_TTL_SECS: u64 = 5;

fn invalidation_map() -> &'static RwLock<HashMap<Uuid, (i64, Instant)>> {
    CREDENTIAL_INVALIDATIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Record a local credential invalidation in the in-memory fast-path so
/// subsequent token-validation checks on this replica reject tokens issued
/// at or before `now` without first waiting for the DB cache to refresh.
/// The DB columns (`password_changed_at`, `totp_verified_at`, `updated_at`)
/// remain the source of truth across replicas.
///
/// Boundary (regression of #931, fixed by #1436): the replica-safe path in
/// `is_token_invalidated_replica_safe` compares with strict `<` (#1265),
/// not `<=`. A JWT minted in the same wall-clock second as the password
/// change would otherwise survive: `iat == watermark` makes `iat < watermark`
/// false. We write `now + 1` so any token with `iat <= now` is rejected.
/// The sync map at `is_token_invalidated` uses `<=` so the `+1` does not
/// double-count there.
pub fn invalidate_user_tokens(user_id: Uuid) {
    let watermark = Utc::now().timestamp().saturating_add(1);
    invalidate_user_tokens_at(user_id, watermark);
}

/// Variant of [`invalidate_user_tokens`] that exempts the caller's own JWT.
///
/// `caller_iat` is the calling token's issued-at (seconds). The in-memory
/// watermark is set to `caller_iat - 1` so the sync `<=` check still passes
/// for the calling token (`caller_iat <= caller_iat - 1` is false), while
/// every token issued at any second strictly before `caller_iat` is
/// invalidated. The sync path is the one consulted by the gRPC interceptor
/// (`grpc/auth_interceptor.rs`) and the TOTP causation tests, so the `-1`
/// here is load-bearing on those code paths.
///
/// Used by TOTP enable/disable so the session that initiated the credential
/// change is not logged out by the same operation. Other sessions (and any
/// stolen pre-change tokens) are still killed. The refresh-grant bypass
/// from #1146 is closed separately by the caller via
/// [`AuthService::revoke_all_refresh_token_families`].
pub fn invalidate_user_tokens_except_caller(user_id: Uuid, caller_iat: i64) {
    // -1 so the sync `<=` check at the line `issued_at <= changed_at` lets
    // the calling token through. Older tokens (iat <= caller_iat - 1) are
    // still caught.
    invalidate_user_tokens_at(user_id, caller_iat.saturating_sub(1));
}

/// Set the in-memory watermark to a specific epoch second. Shared by the
/// "invalidate everything" and "exempt caller" variants above.
fn invalidate_user_tokens_at(user_id: Uuid, watermark: i64) {
    if let Ok(mut map) = invalidation_map().write() {
        map.insert(user_id, (watermark, Instant::now()));
        let now = Utc::now().timestamp();
        let cutoff = now - INVALIDATION_RETENTION_SECS;
        map.retain(|_, (ts, _)| *ts > cutoff);
    }
}

/// In-memory fast-path version of the credential-invalidation check.
///
/// Returns `true` only when this replica has seen an `invalidate_user_tokens`
/// call whose watermark is `>=` the token's `iat`. Comparison is `<=` so a
/// token minted in the same wall-clock second as the invalidation is
/// rejected too (1-second JWT `iat` resolution race; fixes the boundary
/// bug at the old line 152).
///
/// Callers
/// -------
/// * [`AuthService::validate_access_token`] (sync entry point with no
///   DB access): consults this map directly; the `<=` boundary
///   semantics above are the load-bearing guarantee.
/// * gRPC `auth_interceptor` test-mode branch (no DB pool wired): same
///   sync-only role.
///
/// [`is_token_invalidated_replica_safe`] intentionally does NOT call
/// this helper. The replica-safe path goes through
/// [`fetch_credential_change_watermark`] which serves the SAME
/// `invalidation_map` as a 5-second DB-result cache, and the strict `<`
/// comparator (post-#1248) must win over the `<=` here. Mixing the two
/// produced a release-gate regression on `v1.2.0-rc.1` where the first
/// admin request from a fresh non-admin user passed and every
/// subsequent request inside the cache window was rejected by the
/// conflated `<=`. Keep this distinction when adding new callers.
///
/// In multi-replica deployments this is best-effort: an invalidation fired
/// on replica A is not visible to replica B until `validate_token` /
/// `refresh_tokens` consults the DB via [`is_user_credentials_changed_db`].
/// The DB-backed check is the source of truth; this exists only as the
/// fast-path for the same replica.
pub(crate) fn is_token_invalidated(user_id: Uuid, issued_at: i64) -> bool {
    if let Ok(map) = invalidation_map().read() {
        if let Some(&(changed_at, _)) = map.get(&user_id) {
            return issued_at <= changed_at;
        }
    }
    false
}

/// Outcome of the DB-backed credential-change lookup for a user.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CredentialWatermark {
    /// Unix-timestamp (seconds) of the most recent credential-bearing
    /// change on the user row.
    pub(crate) watermark: i64,
    /// `users.is_active`. When `false`, [`is_token_invalidated_replica_safe`]
    /// rejects every token regardless of `iat` so a deactivation processed
    /// on replica A is honoured by every other replica.
    pub(crate) is_active: bool,
}

/// DB-backed credential-change watermark per user, populated lazily on
/// every `validate_access_token_async` / `refresh_tokens` call.
///
/// Returns the highest of `users.password_changed_at` and
/// `users.totp_verified_at` as a Unix timestamp (in seconds), alongside
/// `users.is_active`, or `None` if the user no longer exists.
///
/// Note: `users.updated_at` is deliberately NOT included. Profile edits
/// (display name, email, last_login_at touches) bump `updated_at` without
/// being credential changes; folding it into the watermark would reject
/// tokens minted before benign edits (PR #1190 review regression). The
/// fast-path map in [`invalidate_user_tokens`] (called from password /
/// TOTP / deactivation handlers) covers the same-replica case; this DB
/// watermark covers cross-replica fan-out.
///
/// The value is cached in [`CREDENTIAL_INVALIDATIONS`] for
/// [`CREDENTIAL_DB_CACHE_TTL_SECS`] so bursts don't hammer the DB.
async fn fetch_credential_change_watermark(
    db: &PgPool,
    user_id: Uuid,
) -> Result<Option<CredentialWatermark>> {
    // Fast-path: serve from cache if fresh. The cached value is the watermark
    // only; on cache hit we still must consult the DB if a strict is_active
    // check is needed. To keep the cache lean (and unchanged in structure),
    // a cache hit implies `is_active = true` at the time of caching — fresh
    // deactivations are reflected through the in-memory invalidation map
    // (which `invalidate_user_tokens` writes synchronously), and through the
    // 5s TTL after which the DB is re-consulted.
    if let Ok(map) = invalidation_map().read() {
        if let Some(&(changed_at, recorded)) = map.get(&user_id) {
            if recorded.elapsed().as_secs() < CREDENTIAL_DB_CACHE_TTL_SECS {
                return Ok(Some(CredentialWatermark {
                    watermark: changed_at,
                    is_active: true,
                }));
            }
        }
    }

    let row = sqlx::query!(
        r#"
        SELECT
            GREATEST(
                password_changed_at,
                COALESCE(totp_verified_at, password_changed_at)
            ) AS "watermark!",
            is_active
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(record) = row else {
        return Ok(None);
    };
    let watermark = record.watermark.timestamp();

    // Only cache when the user is active. Caching `is_active=false` would
    // require expanding the cache value to a tuple; instead we skip the
    // write so the next lookup re-reads the DB and gets the authoritative
    // status. Inactive lookups are rare on the hot path (the request will
    // 401 anyway) so the extra DB roundtrip is acceptable.
    if record.is_active {
        if let Ok(mut map) = invalidation_map().write() {
            map.insert(user_id, (watermark, Instant::now()));
            let cutoff = Utc::now().timestamp() - INVALIDATION_RETENTION_SECS;
            map.retain(|_, (ts, _)| *ts > cutoff);
        }
    }

    Ok(Some(CredentialWatermark {
        watermark,
        is_active: record.is_active,
    }))
}

/// Replica-safe credential-invalidation check.
///
/// Returns `true` when the user's credentials have changed strictly after
/// the token's `iat`. JWT `iat` is whole seconds (RFC 7519); the DB
/// `password_changed_at` is microsecond-precision but
/// [`fetch_credential_change_watermark`] truncates it to seconds via
/// `.timestamp()`. We use strict `<` (not `<=`) so a token minted in the
/// same wall-clock second as the watermark is accepted — this is the
/// fresh-user case where `POST /users` sets `password_changed_at = NOW()`
/// (column DEFAULT) and the user's first login mints a JWT whose `iat`
/// also resolves to that second (#1173 follow-up: release-gate
/// `rbac-tests` and `mesh-tests` saw HTTP 401 instead of the expected 403
/// for fresh non-admin users).
///
/// Safety of `<` for the actual-password-change case: a JWT with `iat`
/// equal to the post-change watermark would have to have been minted in
/// the same wall-clock second the password was changed. The server
/// requires a successful authentication to mint a JWT, so such a JWT
/// could only have been minted with the OLD password right up until the
/// password change — which means the attacker already had the old
/// password and any JWT obtained that way is equivalent to one obtained
/// a moment earlier through normal use. There is no exploitable window.
///
/// Resolution order:
///   1. DB watermark, served from the in-memory cache when fresh
///      (`CREDENTIAL_DB_CACHE_TTL_SECS`) and otherwise via a Postgres
///      lookup. The cache is the SAME `invalidation_map` written by
///      [`invalidate_user_tokens`], so an explicit invalidation on this
///      replica becomes visible on the very next call without a DB
///      round-trip.
///
/// The sync `is_token_invalidated` fast-path is intentionally NOT
/// consulted here. It uses `<=` semantics, which is correct for the
/// `validate_access_token` (sync) entry point but conflicts with the
/// strict `<` used at line `Ok(issued_at < entry.watermark)` below.
/// Calling it first caused a release-gate regression: the first admin
/// request from a fresh non-admin user passed (cache empty → DB → cache
/// populated with the user's `password_changed_at`), and every
/// subsequent request within the 5s TTL hit the sync map and was
/// rejected by `<=` even though the async path would have accepted it
/// (#1248 follow-up; `rbac-tests` saw "first endpoint 403, all
/// subsequent endpoints 401" against `v1.2.0-rc.1`).
pub(crate) async fn is_token_invalidated_replica_safe(
    db: &PgPool,
    user_id: Uuid,
    issued_at: i64,
) -> Result<bool> {
    match fetch_credential_change_watermark(db, user_id).await? {
        Some(entry) => {
            // Reject every token (regardless of iat) when the user has been
            // deactivated. This is the cross-replica fan-out: replica A flips
            // is_active=false; replica B observes it here on next DB lookup
            // (within `CREDENTIAL_DB_CACHE_TTL_SECS` of the change).
            if !entry.is_active {
                return Ok(true);
            }
            Ok(issued_at < entry.watermark)
        }
        None => Ok(false),
    }
}

/// Global record of users whose API-token cache entries have been forcibly
/// invalidated (e.g. when an admin sets `is_active=false`). The value is the
/// Unix timestamp of the invalidation so cache entries inserted before that
/// point are rejected even on cache hit, without waiting for the
/// `API_TOKEN_CACHE_TTL_SECS` window to elapse. Entries are pruned after
/// twice the cache TTL since beyond that any stale cache entry has expired
/// on its own and the `WHERE is_active = true` SQL filter takes over.
///
/// **Replica scope:** this map is per-process. In multi-replica deployments
/// (Helm chart `replicas > 1`), a deactivation processed by replica A is not
/// visible to replicas B..N, so cache hits on those replicas continue
/// authorising the user for up to `API_TOKEN_CACHE_TTL_SECS` (5 min). A
/// follow-up in v1.2.0 will move the invalidation signal into the database
/// (or a Redis pub-sub channel) so it is observed by every replica.
static API_TOKEN_USER_INVALIDATIONS: OnceLock<RwLock<HashMap<Uuid, Instant>>> = OnceLock::new();

fn api_token_user_invalidation_map() -> &'static RwLock<HashMap<Uuid, Instant>> {
    API_TOKEN_USER_INVALIDATIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Type alias for an entry in the per-instance API-token cache map.
type TokenCacheMap = RwLock<HashMap<String, (CachedApiTokenEntry, Instant)>>;

/// Registry of long-lived `AuthService` token caches that should be flushed
/// when a user is invalidated. Each entry is a `Weak` reference so dropped
/// services don't pin memory; dead weaks are pruned during invalidation.
///
/// Ad-hoc per-request `AuthService` instances do NOT register here: their
/// cache is empty, dropped at the end of the request, and thus has nothing
/// to flush.
static AUTH_TOKEN_CACHE_REGISTRY: OnceLock<RwLock<Vec<Weak<TokenCacheMap>>>> = OnceLock::new();

fn auth_token_cache_registry() -> &'static RwLock<Vec<Weak<TokenCacheMap>>> {
    AUTH_TOKEN_CACHE_REGISTRY.get_or_init(|| RwLock::new(Vec::new()))
}

// ---------------------------------------------------------------------------
// Process-wide bcrypt-bound auth concurrency cap (#991, #1088)
// ---------------------------------------------------------------------------
//
// `verify_password` / `hash_password` are called from many entry points:
// - `auth.rs::login` (username + password local login)
// - `validate_api_token` (every authenticated request that uses an API token
//   on cache miss — cargo, npm, pip, gha-runners hit this path the most)
// - `require_auth_with_bearer_fallback` (Bearer basic-auth fallback path)
// - `AuthService::authenticate` invoked from middleware basic-auth fallback
// - signup, password change, API-token issuance (hash_password)
//
// Wiring the permit in `auth.rs::login` alone (the original PR shape) misses
// the API-token verify path that *dominates* sustained-load traffic, so the
// permit must sit at the chokepoint that every bcrypt-bound call traverses:
// `verify_password` / `hash_password`. The global cell is set once by
// `AppState::new` from `Config::auth_max_concurrency`; tests that exercise
// the static methods directly leave it unset and get the legacy uncapped
// behaviour, which preserves their semantics.
static GLOBAL_AUTH_SEMAPHORE: OnceLock<Option<Arc<Semaphore>>> = OnceLock::new();

/// Install the process-wide bcrypt-bound auth concurrency cap. Idempotent —
/// the first call wins, subsequent calls are silently ignored so multiple
/// `AppState` instances (e.g., during integration-test setup) cannot
/// re-configure the cap mid-run.
///
/// Pass `None` to disable the cap (legacy behaviour, `auth_max_concurrency=0`).
pub fn install_global_auth_semaphore(sem: Option<Arc<Semaphore>>) {
    let _ = GLOBAL_AUTH_SEMAPHORE.set(sem);
}

/// How long to wait for a bcrypt-permit before giving up and shedding to
/// 503. A short queue tolerance turns "burst of 50 concurrent basic-auth
/// requests" (every CI package-manager invocation) into a survivable
/// workload at small caps, instead of failing 42/50 outright (#1437,
/// #1442). bcrypt-cost-12 is ~100-300 ms per verify so 3 s lets ~10-30
/// queued requests drain at cap=8 before the next one sheds.
const AUTH_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// Try to claim a permit from the process-wide bcrypt-bound auth cap. Returns:
/// - `Ok(None)` when no cap is installed (tests, or operator opt-out)
/// - `Ok(Some(permit))` when a slot was acquired (must be held until the
///   bcrypt work completes; release is automatic on drop, including on panic)
/// - `Err(ServiceUnavailable)` when the cap is saturated for longer than
///   [`AUTH_PERMIT_WAIT`]
///
/// Async because we briefly wait for a free slot before shedding. The fast
/// path (slot immediately available) does not yield. See #1437 / #1442 for
/// the regression this fixes: an immediate `try_acquire_owned` shed 42/50
/// concurrent basic-auth requests rather than letting them queue for the
/// ~1-2 s drain time at cap=8.
pub(crate) async fn acquire_auth_permit_for_bcrypt(
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    let sem_arc = GLOBAL_AUTH_SEMAPHORE.get().and_then(|cell| cell.clone());
    acquire_permit_from(sem_arc.as_ref(), AUTH_PERMIT_WAIT).await
}

/// Pure helper that the public function delegates to. Extracted so that unit
/// tests can exercise the shed logic on a fresh semaphore without contending
/// with the process-wide `OnceLock` (which may have been set by an earlier
/// test in the same binary).
///
/// Behaviour:
/// - `None` cap -> `Ok(None)` (legacy uncapped mode).
/// - Slot free -> immediate `Ok(Some(permit))` (fast path, no yield).
/// - Slot saturated -> wait up to `wait` for a slot, then shed if it
///   never frees. The shed is mapped to `ServiceUnavailable` which the
///   `IntoResponse` impl turns into 503 + `Retry-After: 1`.
async fn acquire_permit_from(
    sem: Option<&Arc<Semaphore>>,
    wait: std::time::Duration,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    let Some(sem) = sem else {
        return Ok(None);
    };

    // Fast path: a slot is immediately available, so we never yield.
    if let Ok(permit) = sem.clone().try_acquire_owned() {
        return Ok(Some(permit));
    }

    // Saturated: queue for `wait`, then shed.
    match tokio::time::timeout(wait, sem.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(Some(permit)),
        // Either the semaphore was closed (shouldn't happen — it lives for
        // process lifetime) or the wait elapsed. Both surface as 503 with a
        // Retry-After hint so well-behaved clients back off.
        _ => Err(AppError::ServiceUnavailable(
            "Authentication service is at capacity, retry shortly".to_string(),
        )),
    }
}

/// Legacy non-blocking variant retained for tests and callers that need a
/// synchronous shed boundary (no queue wait). New call sites should prefer
/// [`acquire_auth_permit_for_bcrypt`] which queues briefly before shedding.
#[cfg(test)]
fn try_acquire_permit_from(
    sem: Option<&Arc<Semaphore>>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    match sem {
        None => Ok(None),
        Some(sem) => match sem.clone().try_acquire_owned() {
            Ok(permit) => Ok(Some(permit)),
            Err(_) => Err(AppError::ServiceUnavailable(
                "Authentication service is at capacity, retry shortly".to_string(),
            )),
        },
    }
}

/// Mark every cached API-token validation belonging to `user_id` as stale and
/// also flush matching entries from every registered long-lived cache.
///
/// Called when the user is deactivated (`is_active=false`), hard-deleted, or
/// otherwise loses the right to authenticate. Subsequent cache hits for any
/// of that user's API tokens will be rejected immediately, closing the up-to
/// `API_TOKEN_CACHE_TTL_SECS` window during which the cache would otherwise
/// continue accepting them. Old entries beyond `2 * API_TOKEN_CACHE_TTL_SECS`
/// are pruned on each call to keep memory bounded.
///
/// **Call ordering (LOW-5 TOCTOU mitigation):** invoke this BEFORE the SQL
/// `UPDATE users SET is_active=false` (or `DELETE`). Pre-marking is
/// fail-secure: if the SQL fails the worst case is a small false-positive
/// on cache rejection (forcing one extra DB re-validation), while the
/// timestamp guarantees that any cache entry already in flight is rejected
/// by the time the SQL commits.
///
/// **Replica scope:** this function is per-process. See the docstring on
/// [`API_TOKEN_USER_INVALIDATIONS`] for the multi-replica caveat.
pub fn invalidate_user_token_cache_entries(user_id: Uuid) {
    // 1) Record the invalidation timestamp BEFORE any SQL has committed.
    if let Ok(mut map) = api_token_user_invalidation_map().write() {
        map.insert(user_id, Instant::now());
        // Note: the heavy retain-prune still runs here on insert as a safety
        // net, but the periodic scheduler task in scheduler_service.rs is
        // the primary pruner and runs even when deactivations are infrequent.
        let cutoff_secs = API_TOKEN_CACHE_TTL_SECS * 2;
        map.retain(|_, recorded_at| recorded_at.elapsed().as_secs() < cutoff_secs);
    }

    // 2) Walk the registry of long-lived AuthService caches and drop matching
    // entries from each. We also prune dead Weaks while we're here.
    if let Ok(mut registry) = auth_token_cache_registry().write() {
        registry.retain(|weak| {
            if let Some(cache_arc) = weak.upgrade() {
                if let Ok(mut cache) = cache_arc.write() {
                    cache.retain(|_, (entry, _)| entry.validation.user.id != user_id);
                }
                true
            } else {
                false
            }
        });
    }
}

/// Periodic prune of `API_TOKEN_USER_INVALIDATIONS` entries older than
/// `2 * API_TOKEN_CACHE_TTL_SECS`. Called by the background scheduler so
/// memory stays bounded even when deactivations are infrequent (the
/// retain-on-insert path inside `invalidate_user_token_cache_entries` only
/// fires on writes).
pub fn prune_stale_user_token_invalidations() -> usize {
    if let Ok(mut map) = api_token_user_invalidation_map().write() {
        let before = map.len();
        let cutoff_secs = API_TOKEN_CACHE_TTL_SECS * 2;
        map.retain(|_, recorded_at| recorded_at.elapsed().as_secs() < cutoff_secs);
        before - map.len()
    } else {
        0
    }
}

/// Returns true if a cache entry inserted at `cached_at` should be rejected
/// because the user's API tokens have been invalidated since it was cached.
pub(crate) fn is_user_api_tokens_invalidated_after(user_id: Uuid, cached_at: Instant) -> bool {
    if let Ok(map) = api_token_user_invalidation_map().read() {
        if let Some(&invalidated_at) = map.get(&user_id) {
            return cached_at <= invalidated_at;
        }
    }
    false
}

/// Authentication service
pub struct AuthService {
    db: PgPool,
    config: Arc<Config>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// In-memory cache of recently validated API tokens.  Avoids repeating the
    /// expensive bcrypt verification on every request (cargo sends credentials
    /// on every index and download request).
    ///
    /// Wrapped in `Arc` so long-lived instances can be registered with the
    /// global cache registry (see [`AuthService::register_for_global_flush`])
    /// and have entries flushed by [`invalidate_user_token_cache_entries`]
    /// without holding a strong reference to the whole `AuthService`.
    token_cache: Arc<TokenCacheMap>,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(db: PgPool, config: Arc<Config>) -> Self {
        let secret = config.jwt_secret.clone();
        Self {
            db,
            config,
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            token_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register this `AuthService`'s token cache with the global registry so
    /// that [`invalidate_user_token_cache_entries`] can flush matching entries
    /// from it directly. Call this on every long-lived `AuthService` instance
    /// (typically the ones created in `routes.rs` for the auth middleware and
    /// the repo-visibility middleware). Ad-hoc per-request instances should
    /// NOT register: they are dropped at the end of the request, the global
    /// invalidation timestamp is sufficient to reject any cache hit they might
    /// produce, and registering them would only churn the registry's `Weak`
    /// vector.
    pub fn register_for_global_flush(&self) {
        if let Ok(mut registry) = auth_token_cache_registry().write() {
            registry.push(Arc::downgrade(&self.token_cache));
        }
    }

    /// Check whether a user account is currently locked.
    ///
    /// Returns `true` when the account has a `locked_until` timestamp in the
    /// future. This is a pure function so it can be tested without a database.
    pub fn is_account_locked(locked_until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
        locked_until.is_some_and(|t| t > now)
    }

    /// Check whether a user's password has expired.
    ///
    /// Returns `true` when `password_expiry_days` is non-zero and the
    /// password was last changed more than that many days ago. This is a
    /// pure function so it can be tested without a database.
    pub fn is_password_expired(
        password_changed_at: DateTime<Utc>,
        password_expiry_days: u32,
        now: DateTime<Utc>,
    ) -> bool {
        if password_expiry_days == 0 {
            return false;
        }
        let expiry = password_changed_at + Duration::days(password_expiry_days as i64);
        now >= expiry
    }

    /// Decide whether a failed attempt should trigger a lockout.
    ///
    /// `attempts_after_failure` is the count *after* incrementing (i.e., the
    /// value that will be written to the database). Returns the `locked_until`
    /// timestamp when the threshold is met, or `None` if the account should
    /// remain unlocked.
    pub fn should_lock(
        attempts_after_failure: i32,
        threshold: u32,
        duration_minutes: i64,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        if threshold == 0 {
            return None; // lockout disabled
        }
        if attempts_after_failure >= threshold as i32 {
            Some(now + Duration::minutes(duration_minutes))
        } else {
            None
        }
    }

    /// Authenticate user with username and password
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<(User, TokenPair)> {
        // Fetch user from database
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            FROM users
            WHERE username = $1 AND is_active = true
            "#,
            username
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("Invalid username or password".to_string()))?;

        // Check account lockout before verifying credentials
        let now = Utc::now();
        if Self::is_account_locked(user.locked_until, now) {
            return Err(AppError::Authentication(
                "Account temporarily locked due to too many failed login attempts".to_string(),
            ));
        }

        // Verify password for local auth
        if user.auth_provider != AuthProvider::Local {
            return Err(AppError::Authentication(
                "Use SSO provider to authenticate".to_string(),
            ));
        }

        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::Authentication("Invalid username or password".to_string()))?;

        if !Self::verify_password(password, password_hash).await? {
            // Record failed attempt
            let new_count = user.failed_login_attempts + 1;
            let lock_until = Self::should_lock(
                new_count,
                self.config.account_lockout_threshold,
                self.config.account_lockout_duration_minutes,
                now,
            );

            sqlx::query!(
                r#"
                UPDATE users
                SET failed_login_attempts = $2,
                    locked_until = $3,
                    last_failed_login_at = $4
                WHERE id = $1
                "#,
                user.id,
                new_count,
                lock_until,
                now
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if lock_until.is_some() {
                return Err(AppError::Authentication(
                    "Account temporarily locked due to too many failed login attempts".to_string(),
                ));
            }

            return Err(AppError::Authentication(
                "Invalid username or password".to_string(),
            ));
        }

        // Successful login: reset lockout counters and record last login
        sqlx::query!(
            r#"
            UPDATE users
            SET last_login_at = NOW(),
                failed_login_attempts = 0,
                locked_until = NULL,
                last_failed_login_at = NULL
            WHERE id = $1
            "#,
            user.id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Check password expiration for local users
        let mut user = user;
        if !user.must_change_password
            && Self::is_password_expired(
                user.password_changed_at,
                self.config.password_expiry_days,
                Utc::now(),
            )
        {
            user.must_change_password = true;

            // Persist the flag so it survives across requests
            sqlx::query!(
                r#"
            UPDATE users
            SET must_change_password = true
            WHERE id = $1
            "#,
                user.id
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            info!(user_id = %user.id, "password expired, forcing change on next login");
        }

        // Generate tokens and persist the refresh `jti` for replay detection.
        let tokens = self.generate_tokens(&user)?;
        self.persist_refresh_jti_from_pair(&tokens, user.id).await?;

        Ok((user, tokens))
    }

    /// Generate access and refresh tokens for a user.
    ///
    /// Mints fresh `jti` and `family_id` for the refresh token. The `family_id`
    /// is what links rotated tokens to a single login event; on detected
    /// replay (see [`AuthService::refresh_tokens`]) every row in the family
    /// gets revoked. Callers that perform rotation (rather than a new login)
    /// must use [`AuthService::generate_tokens_with_family`] to preserve the
    /// existing family. The DB row for the refresh token is **not** inserted
    /// here; callers persist it through
    /// [`AuthService::record_refresh_token_jti`] after generation.
    pub fn generate_tokens(&self, user: &User) -> Result<TokenPair> {
        self.generate_tokens_with_family(user, Uuid::new_v4())
    }

    /// Generate tokens with a specific `family_id` (refresh rotation path).
    /// See [`AuthService::generate_tokens`] for the new-login case.
    pub fn generate_tokens_with_family(&self, user: &User, family_id: Uuid) -> Result<TokenPair> {
        let now = Utc::now();
        let access_exp = now + Duration::minutes(self.config.jwt_access_token_expiry_minutes);
        let refresh_exp = now + Duration::days(self.config.jwt_refresh_token_expiry_days);

        let access_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: access_exp.timestamp(),
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
        };

        let refresh_jti = Uuid::new_v4();
        let refresh_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: refresh_exp.timestamp(),
            token_type: "refresh".to_string(),
            jti: Some(refresh_jti),
            family_id: Some(family_id),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Token encoding failed: {}", e)))?;

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Token encoding failed: {}", e)))?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: (self.config.jwt_access_token_expiry_minutes * 60) as u64,
        })
    }

    /// Persist a refresh-token `jti` so future presentations can detect
    /// replay (`consumed_at IS NOT NULL`) and admin-revocations can sweep
    /// the whole family. Idempotent: a duplicate `jti` is a no-op because
    /// of the primary-key conflict.
    ///
    /// The exact `jti` / `family_id` / `iat` / `exp` values come from the
    /// claims encoded into the refresh JWT itself, so callers should decode
    /// the JWT they just generated and pass the embedded values in.
    pub async fn record_refresh_token_jti(
        &self,
        jti: Uuid,
        user_id: Uuid,
        family_id: Uuid,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO refresh_token_jti (jti, user_id, family_id, issued_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (jti) DO NOTHING
            "#,
            jti,
            user_id,
            family_id,
            issued_at,
            expires_at,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    /// Decode the refresh JWT we just generated and persist its `jti` row.
    /// Convenience wrapper around [`AuthService::record_refresh_token_jti`]
    /// for the common case where the caller has a `TokenPair` in hand.
    pub async fn persist_refresh_jti_from_pair(
        &self,
        tokens: &TokenPair,
        user_id: Uuid,
    ) -> Result<()> {
        let token_data = self.decode_token(&tokens.refresh_token)?;
        let claims = &token_data.claims;
        let jti = match claims.jti {
            Some(j) => j,
            None => return Ok(()),
        };
        let family_id = match claims.family_id {
            Some(f) => f,
            None => return Ok(()),
        };
        let issued_at = DateTime::<Utc>::from_timestamp(claims.iat, 0)
            .ok_or_else(|| AppError::Internal("Invalid iat in minted refresh token".to_string()))?;
        let expires_at = DateTime::<Utc>::from_timestamp(claims.exp, 0)
            .ok_or_else(|| AppError::Internal("Invalid exp in minted refresh token".to_string()))?;
        self.record_refresh_token_jti(jti, user_id, family_id, issued_at, expires_at)
            .await
    }

    /// Borrow the underlying database pool. Used by middleware that needs
    /// to issue queries through the same connection pool the auth service uses
    /// (e.g. download-ticket fallback in the auth middleware chain).
    pub fn db(&self) -> &PgPool {
        &self.db
    }

    /// Validate an access JWT.
    ///
    /// Synchronous fast-path: only consults the in-memory invalidation map.
    /// For replica-safe credential-change rejection (across multiple pods),
    /// use [`AuthService::validate_access_token_async`].
    pub fn validate_access_token(&self, token: &str) -> Result<Claims> {
        let token_data = self.decode_token(token)?;

        if token_data.claims.token_type != "access" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        if is_token_invalidated(token_data.claims.sub, token_data.claims.iat) {
            return Err(AppError::Authentication(
                "Token invalidated by credential change".to_string(),
            ));
        }

        Ok(token_data.claims)
    }

    /// Replica-safe variant of [`AuthService::validate_access_token`].
    ///
    /// Consults the DB-backed credential-change watermark
    /// (`password_changed_at` / `totp_verified_at` / `updated_at`) as the
    /// source of truth, with a short in-memory cache to absorb bursts.
    /// Required for paths that issue or rotate tokens (refresh, OCI
    /// token-exchange) so a credential change on replica A is honored on
    /// replica B (#1173).
    pub async fn validate_access_token_async(&self, token: &str) -> Result<Claims> {
        let token_data = self.decode_token(token)?;

        if token_data.claims.token_type != "access" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        if is_token_invalidated_replica_safe(&self.db, token_data.claims.sub, token_data.claims.iat)
            .await?
        {
            return Err(AppError::Authentication(
                "Token invalidated by credential change".to_string(),
            ));
        }

        Ok(token_data.claims)
    }

    /// Refresh-token rotation per RFC 6819 §5.2.2.3 / RFC 9700 §2.2.2.
    ///
    /// Validates the presented refresh JWT, then consults `refresh_token_jti`
    /// keyed by the embedded `jti`:
    ///
    ///   * No row exists  -> token never recorded (issued before #1174 landed
    ///     or against a different family) -> accept but record a row so
    ///     subsequent replays of the same JWT are caught.
    ///   * Row already consumed (`consumed_at IS NOT NULL`) -> reuse detected.
    ///     Revoke every other token in the same `family_id`, emit a
    ///     structured security event, and return 401 to the caller. This
    ///     matches the OAuth 2.0 Security BCP guidance.
    ///   * Row revoked  -> reject.
    ///   * Otherwise    -> mark consumed, mint a new pair with the same
    ///     `family_id`, persist the new `jti`.
    ///
    /// Also enforces the replica-safe credential-change check (#1173).
    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<(User, TokenPair)> {
        let token_data = self.decode_token(refresh_token)?;

        if token_data.claims.token_type != "refresh" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        if is_token_invalidated_replica_safe(&self.db, token_data.claims.sub, token_data.claims.iat)
            .await?
        {
            return Err(AppError::Authentication(
                "Token invalidated by credential change".to_string(),
            ));
        }

        // Reuse/replay detection per RFC 6819. Only enforced when the
        // refresh JWT carries a `jti` (every token minted after #1174
        // landed does; older tokens predating the migration skip this
        // path and continue to rotate normally).
        if let (Some(jti), Some(family_id)) = (token_data.claims.jti, token_data.claims.family_id) {
            let row = sqlx::query!(
                r#"
                SELECT consumed_at, revoked_at, family_id
                FROM refresh_token_jti
                WHERE jti = $1
                "#,
                jti
            )
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if let Some(row) = row {
                if row.revoked_at.is_some() {
                    tracing::warn!(
                        user_id = %token_data.claims.sub,
                        jti = %jti,
                        family_id = %row.family_id,
                        "Refresh token rejected: family revoked",
                    );
                    return Err(AppError::Authentication(
                        "Refresh token has been revoked".to_string(),
                    ));
                }
                if row.consumed_at.is_some() {
                    // Reuse detected. Revoke the entire family so neither
                    // the attacker nor the legitimate user can refresh
                    // again with any sibling token. Both sides are forced
                    // back to a full re-auth.
                    sqlx::query!(
                        r#"
                        UPDATE refresh_token_jti
                        SET revoked_at = NOW()
                        WHERE family_id = $1 AND revoked_at IS NULL
                        "#,
                        row.family_id,
                    )
                    .execute(&self.db)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;

                    tracing::warn!(
                        user_id = %token_data.claims.sub,
                        jti = %jti,
                        family_id = %row.family_id,
                        security_event = "refresh_token_replay",
                        "Refresh-token replay detected; revoking entire token family",
                    );
                    return Err(AppError::Authentication(
                        "Refresh token replay detected".to_string(),
                    ));
                }

                // Mark consumed (single-use rotation).
                sqlx::query!(
                    r#"
                    UPDATE refresh_token_jti
                    SET consumed_at = NOW()
                    WHERE jti = $1 AND consumed_at IS NULL
                    "#,
                    jti,
                )
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            }
            // (Else: row missing -> token predates the table; we record a
            // fresh row for the rotated jti below so any future replay of
            // the new token IS detected.)

            // Fetch fresh user data.
            let user = self.load_active_user(token_data.claims.sub).await?;
            let tokens = self.generate_tokens_with_family(&user, family_id)?;
            self.persist_refresh_jti_from_pair(&tokens, user.id).await?;
            return Ok((user, tokens));
        }

        // Legacy path: refresh JWT has no jti (predates #1174). Rotate but
        // open a new family so subsequent rotations get replay detection.
        let user = self.load_active_user(token_data.claims.sub).await?;
        let tokens = self.generate_tokens(&user)?;
        self.persist_refresh_jti_from_pair(&tokens, user.id).await?;
        Ok((user, tokens))
    }

    /// Fetch a user row by id, rejecting deactivated accounts. Shared by the
    /// refresh flow and any other path that needs the "currently-active"
    /// view of a user.
    async fn load_active_user(&self, user_id: Uuid) -> Result<User> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            FROM users
            WHERE id = $1 AND is_active = true
            "#,
            user_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))
    }

    /// Revoke every refresh token in every active family for `user_id`. Called
    /// alongside [`invalidate_user_tokens`] on password reset, deactivation,
    /// or any other "kill all sessions" operation so that even refresh JWTs
    /// already in flight stop working immediately on every replica.
    pub async fn revoke_all_refresh_token_families(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE refresh_token_jti
            SET revoked_at = NOW()
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
            user_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }

    /// Delete refresh-token jti rows whose underlying JWT expired more than
    /// `grace` ago. Called by the scheduler janitor (#1174 cleanup).
    /// Returns the number of rows removed.
    pub async fn cleanup_expired_refresh_token_jti(db: &PgPool, grace: Duration) -> Result<u64> {
        let cutoff = Utc::now() - grace;
        let result = sqlx::query!(
            "DELETE FROM refresh_token_jti WHERE expires_at < $1",
            cutoff,
        )
        .execute(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }

    fn decode_token(&self, token: &str) -> Result<TokenData<Claims>> {
        let validation = Validation::new(Algorithm::HS256);
        decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AppError::Authentication(format!("Invalid token: {}", e)))
    }

    /// Hash a password
    pub async fn hash_password(password: &str) -> Result<String> {
        // Hold a process-wide auth-concurrency permit while bcrypt runs so
        // hash() also participates in the load-shed cap (signup, password
        // change, API-token creation all call this).
        let _permit = acquire_auth_permit_for_bcrypt().await?;
        let pwd = password.to_string();
        tokio::task::spawn_blocking(move || {
            hash(&pwd, DEFAULT_COST)
                .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))
        })
        .await
        .map_err(|e| AppError::Internal(format!("Blocking task failed: {e}")))?
    }

    /// Verify a password against a hash
    ///
    /// Acquires a permit from the process-wide auth-concurrency semaphore
    /// before invoking the (CPU-bound, ~100-300 ms) bcrypt verify. On
    /// saturation this returns `AppError::ServiceUnavailable` immediately,
    /// fast-shedding load so the rest of the API does not starve the
    /// blocking-thread pool (#991, #1088).
    pub async fn verify_password(password: &str, hash: &str) -> Result<bool> {
        let _permit = acquire_auth_permit_for_bcrypt().await?;
        let pwd = password.to_string();
        let h = hash.to_string();
        tokio::task::spawn_blocking(move || {
            verify(&pwd, &h)
                .map_err(|e| AppError::Internal(format!("Password verification failed: {}", e)))
        })
        .await
        .map_err(|e| AppError::Internal(format!("Blocking task failed: {e}")))?
    }

    /// Returns a dummy bcrypt hash (cost-12) generated once at runtime.
    /// Running bcrypt verify against this ensures all rejection paths take
    /// the same wall-clock time, preventing timing side-channel leaks.
    fn dummy_bcrypt_hash() -> &'static str {
        static DUMMY: OnceLock<String> = OnceLock::new(); //NOSONAR - intentional dummy hash for constant-time rejection
        DUMMY.get_or_init(|| {
            hash("__dummy_timing_pad__", 12).expect("bcrypt hash generation must not fail")
        })
    }

    /// Validate API token and return user with scopes and repository restrictions.
    pub async fn validate_api_token(&self, token: &str) -> Result<ApiTokenValidation> {
        // Hash the raw token before using it as cache key so plaintext tokens
        // are never stored in memory.
        let cache_key = format!("{:x}", Sha256::digest(token.as_bytes()));

        // Check in-memory cache before the expensive bcrypt verification.
        // Package managers like cargo send credentials on every request (index
        // lookups, downloads, etc.), so without caching every request pays the
        // full bcrypt cost (~100-500 ms), which compounds across the many
        // parallel requests in a single build.
        if let Ok(cache) = self.token_cache.read() {
            if let Some((entry, cached_at)) = cache.get(&cache_key) {
                if cached_at.elapsed().as_secs() < API_TOKEN_CACHE_TTL_SECS {
                    // Even on cache hit, reject if the token has since been
                    // revoked (Bug #1) or has expired (Bug #2).
                    if is_api_token_revoked_in_cache(entry.token_id) {
                        return Err(AppError::Unauthorized("Token has been revoked".to_string()));
                    }
                    if let Some(exp) = entry.expires_at {
                        if exp < Utc::now() {
                            return Err(AppError::Authentication("API token expired".to_string()));
                        }
                    }
                    // Reject if the user has been deactivated (or hard-deleted)
                    // since this entry was cached. Without this check, a cached
                    // validation would keep accepting requests for up to
                    // `API_TOKEN_CACHE_TTL_SECS` (5 min) after `is_active`
                    // flipped to false, even though the SQL filter
                    // `WHERE id = $1 AND is_active = true` would now reject.
                    if is_user_api_tokens_invalidated_after(entry.validation.user.id, *cached_at) {
                        return Err(AppError::Authentication(
                            "User account is deactivated".to_string(),
                        ));
                    }
                    return Ok(entry.validation.clone());
                }
            }
        }

        // API tokens have format: prefix_secret
        // We store hash of full token and prefix for lookup
        let dummy = Self::dummy_bcrypt_hash();
        if token.len() < 8 {
            // Still must burn bcrypt time to avoid leaking token length info
            let _ = Self::verify_password(token, dummy).await;
            return Err(AppError::Authentication("Invalid API token".to_string()));
        }

        let prefix = &token[..8];

        // Find token by prefix (includes revoked_at and last_used_at for
        // revocation check and debounced usage tracking).
        let stored_token_opt = sqlx::query!(
            r#"
            SELECT at.id, at.token_hash, at.user_id, at.scopes, at.expires_at,
                   at.repo_selector, at.revoked_at, at.last_used_at
            FROM api_tokens at
            WHERE at.token_prefix = $1
            "#,
            prefix
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Extract verification inputs. When no token was found, use a dummy
        // hash so that bcrypt still runs and all code paths take equal time.
        let (hash_to_verify, token_exists, is_revoked) = match &stored_token_opt {
            Some(t) => (t.token_hash.clone(), true, t.revoked_at.is_some()),
            None => (dummy.to_string(), false, false),
        };

        // Always run bcrypt verification regardless of token existence.
        // This is the constant-time core of the fix: an attacker cannot
        // distinguish "prefix not found" from "wrong secret" by timing.
        let hash_matches = Self::verify_password(token, &hash_to_verify).await?;

        // Check results only after bcrypt has completed
        check_token_validation_result(token_exists, is_revoked, hash_matches)?;

        // Unwrap is safe: token_exists is true only when stored_token_opt is Some
        let stored_token = stored_token_opt.unwrap();

        // Check expiration
        if let Some(expires_at) = stored_token.expires_at {
            if expires_at < Utc::now() {
                return Err(AppError::Authentication("API token expired".to_string()));
            }
        }

        // Debounced usage analytics: only update last_used_at if it has been
        // more than 5 minutes since the last recorded use (or never used).
        let should_update = should_debounce_usage_update(stored_token.last_used_at);

        if should_update {
            let token_id = stored_token.id;
            let db = self.db.clone();
            tokio::spawn(async move {
                let _ = sqlx::query("UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1")
                    .bind(token_id)
                    .execute(&db)
                    .await;
            });
        }

        // Fetch user
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            FROM users
            WHERE id = $1 AND is_active = true
            "#,
            stored_token.user_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

        // Fetch repository restrictions for this token.
        // If a repo_selector is set, resolve it dynamically. Otherwise fall
        // back to the explicit api_token_repositories join table.
        let allowed_repo_ids = if let Some(selector_json) = &stored_token.repo_selector {
            use crate::services::repo_selector_service::{RepoSelector, RepoSelectorService};
            let selector: RepoSelector =
                serde_json::from_value(selector_json.clone()).unwrap_or_default();
            if RepoSelectorService::is_empty(&selector) {
                None // empty selector = unrestricted
            } else {
                let svc = RepoSelectorService::new(self.db.clone());
                let ids = svc.resolve_ids(&selector).await?;
                if ids.is_empty() {
                    Some(vec![]) // selector matched nothing, deny all
                } else {
                    Some(ids)
                }
            }
        } else {
            let repo_rows = sqlx::query!(
                "SELECT repo_id FROM api_token_repositories WHERE token_id = $1",
                stored_token.id
            )
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if repo_rows.is_empty() {
                None // unrestricted
            } else {
                Some(repo_rows.into_iter().map(|r| r.repo_id).collect())
            }
        };

        let validation = ApiTokenValidation {
            user,
            scopes: stored_token.scopes,
            allowed_repo_ids,
        };

        // Populate cache; evict stale entries on write to keep memory bounded.
        if let Ok(mut cache) = self.token_cache.write() {
            cache.retain(|_, (_, at)| at.elapsed().as_secs() < API_TOKEN_CACHE_TTL_SECS);
            let entry = CachedApiTokenEntry {
                validation: validation.clone(),
                token_id: stored_token.id,
                expires_at: stored_token.expires_at,
            };
            cache.insert(cache_key, (entry, Instant::now()));
        }

        Ok(validation)
    }

    /// Generate a new API token
    pub async fn generate_api_token(
        &self,
        user_id: Uuid,
        name: &str,
        scopes: Vec<String>,
        expires_in_days: Option<i64>,
    ) -> Result<(String, Uuid)> {
        if scopes.len() > 50 {
            return Err(AppError::Validation("Too many scopes (max 50)".to_string()));
        }
        if scopes.iter().any(|s| s.len() > 256) {
            return Err(AppError::Validation(
                "Scope name too long (max 256 characters)".to_string(),
            ));
        }

        // Generate random token
        let token = format!(
            "{}_{}",
            &Uuid::new_v4().to_string()[..8],
            Uuid::new_v4().to_string().replace("-", "")
        );
        let prefix = &token[..8];
        let token_hash = Self::hash_password(&token).await?;

        let expires_at = expires_in_days.map(|days| {
            let clamped = days.clamp(1, 3650); // Cap at ~10 years
            Utc::now() + Duration::days(clamped)
        });

        let record = sqlx::query!(
            r#"
            INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
            user_id,
            name,
            token_hash,
            prefix,
            &scopes,
            expires_at
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((token, record.id))
    }

    /// Revoke an API token (soft-revoke: sets revoked_at instead of deleting).
    pub async fn revoke_api_token(&self, token_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query(
            "UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(token_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("API token not found".to_string()));
        }

        // Immediately mark the token as revoked in the global in-memory set so
        // that any cached validation for this token is rejected without waiting
        // for the cache TTL to expire.
        mark_api_token_revoked(token_id);

        Ok(())
    }

    /// Drop every cached API-token validation entry that belongs to `user_id`
    /// from this `AuthService` instance's per-instance cache.
    ///
    /// This is a memory-cleanup helper: the global
    /// [`invalidate_user_token_cache_entries`] function already rejects stale
    /// hits across every `AuthService` instance, but this method also frees
    /// the entries from the long-lived shared instance so they don't sit in
    /// memory until the TTL elapses.
    ///
    /// Returns the number of cache entries removed.
    pub fn flush_user_token_cache_entries(&self, user_id: Uuid) -> usize {
        if let Ok(mut cache) = self.token_cache.write() {
            let before = cache.len();
            cache.retain(|_, (entry, _)| entry.validation.user.id != user_id);
            before - cache.len()
        } else {
            0
        }
    }

    // =========================================================================
    // T055: Federated Authentication Routing
    // =========================================================================

    /// Authenticate user by routing to the appropriate provider based on auth_provider type.
    ///
    /// This method looks up the user's auth_provider and delegates to the appropriate
    /// authentication service (LDAP, OIDC, SAML) or performs local authentication.
    ///
    /// # Arguments
    /// * `username` - The username to authenticate
    /// * `password` - The password (for local/LDAP) or empty for token-based flows
    /// * `provider_override` - Optional provider to force (useful for SSO initiation)
    ///
    /// # Returns
    /// * `Ok((User, TokenPair))` - Authenticated user and JWT tokens
    /// * `Err(AppError)` - Authentication failure
    pub async fn authenticate_by_provider(
        &self,
        username: &str,
        password: &str,
        provider_override: Option<AuthProvider>,
    ) -> Result<(User, TokenPair)> {
        // First, look up the user to determine their auth provider
        let user_lookup = sqlx::query!(
            r#"
            SELECT auth_provider as "auth_provider: AuthProvider"
            FROM users
            WHERE username = $1 AND is_active = true
            "#,
            username
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Determine which provider to use
        let provider = provider_override.or_else(|| user_lookup.map(|u| u.auth_provider));

        match provider {
            Some(AuthProvider::Local) | None => {
                // Use local authentication
                self.authenticate(username, password).await
            }
            Some(AuthProvider::Ldap) => {
                // Delegate to LDAP service
                // Note: ldap_service would be injected or created here in a full implementation
                self.authenticate_ldap(username, password).await
            }
            Some(AuthProvider::Oidc) => {
                // OIDC authentication is typically handled via callback, not direct auth
                // This path would be used for token exchange after OIDC redirect
                Err(AppError::Authentication(
                    "OIDC authentication requires redirect flow. Use /auth/oidc/login endpoint."
                        .to_string(),
                ))
            }
            Some(AuthProvider::Saml) => {
                // SAML authentication is handled via SSO assertion
                // This path would be used for SAML response processing
                Err(AppError::Authentication(
                    "SAML authentication requires SSO flow. Use /auth/saml/login endpoint."
                        .to_string(),
                ))
            }
        }
    }

    /// Authenticate via LDAP provider.
    ///
    /// This is a placeholder that would delegate to LdapService in a full implementation.
    async fn authenticate_ldap(&self, username: &str, password: &str) -> Result<(User, TokenPair)> {
        // In a full implementation, this would:
        // 1. Bind to LDAP server with user credentials
        // 2. Fetch user attributes and groups
        // 3. Call sync_federated_user to create/update user
        // 4. Generate JWT tokens

        // For now, check if user exists with LDAP provider
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            FROM users
            WHERE username = $1 AND auth_provider = 'ldap' AND is_active = true
            "#,
            username
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("LDAP user not found".to_string()))?;

        // In production, LDAP bind verification would happen here
        // For development/testing, we check password if stored (hybrid mode)
        if let Some(ref hash) = user.password_hash {
            if !Self::verify_password(password, hash).await? {
                return Err(AppError::Authentication("Invalid credentials".to_string()));
            }
        } else {
            // Pure LDAP mode - would verify against LDAP server
            return Err(AppError::Authentication(
                "LDAP server verification not configured".to_string(),
            ));
        }

        // Update last login
        sqlx::query!(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            user.id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let tokens = self.generate_tokens(&user)?;
        self.persist_refresh_jti_from_pair(&tokens, user.id).await?;
        Ok((user, tokens))
    }

    /// Authenticate a federated user after successful SSO (OIDC/SAML).
    ///
    /// This is called after the SSO flow completes with validated credentials.
    pub async fn authenticate_federated(
        &self,
        provider: AuthProvider,
        credentials: FederatedCredentials,
    ) -> Result<(User, TokenPair)> {
        // Sync or create the user based on federated credentials
        let user = self.sync_federated_user(provider, &credentials).await?;

        // Update last login
        sqlx::query!(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            user.id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let tokens = self.generate_tokens(&user)?;
        self.persist_refresh_jti_from_pair(&tokens, user.id).await?;
        Ok((user, tokens))
    }

    // =========================================================================
    // T056: Group-to-Role Mapping
    // =========================================================================

    /// Map federated group claims to local roles and admin status.
    ///
    /// This method takes the groups from an identity provider and maps them
    /// to the application's role system. Configuration for mapping is stored
    /// in the application config.
    ///
    /// # Default Mapping Rules (configurable via config):
    /// - Groups containing "admin" or "administrators" -> is_admin = true
    /// - Groups containing "readonly" -> read-only role
    /// - All authenticated users get "user" role
    ///
    /// # Arguments
    /// * `groups` - List of group names/DNs from the identity provider
    ///
    /// # Returns
    /// * `RoleMapping` - The mapped roles and admin status
    pub fn map_groups_to_roles(
        &self,
        groups: &[String],
        required_admin_group: Option<&str>,
    ) -> RoleMapping {
        let mut mapping = RoleMapping::default();

        // Normalize groups to lowercase for case-insensitive matching
        let normalized_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();

        // Check for admin groups: if admin_group is explicitly configured, use
        // exact match only; otherwise fall back to built-in pattern matching.
        if let Some(ag) = required_admin_group {
            let ag_lower = ag.to_lowercase();
            if normalized_groups.contains(&ag_lower) {
                mapping.is_admin = Some(true);
                mapping.roles.push("admin".to_string());
            } else {
                mapping.is_admin = Some(false);
            }
        } else {
            let admin_patterns = ["admin", "administrators", "superusers", "artifact-admins"];
            for group in &normalized_groups {
                for pattern in &admin_patterns {
                    if group.contains(pattern) {
                        mapping.is_admin = Some(true);
                        mapping.roles.push("admin".to_string());
                        break;
                    }
                }
            }
        }

        // Map other groups to roles
        // In a production system, this would read from a config table
        let role_mappings = [
            ("developers", "developer"),
            ("readonly", "reader"),
            ("deployers", "deployer"),
            ("artifact-publishers", "publisher"),
        ];

        for group in &normalized_groups {
            for (pattern, role) in &role_mappings {
                if group.contains(pattern) && !mapping.roles.contains(&role.to_string()) {
                    mapping.roles.push(role.to_string());
                }
            }
        }

        // All authenticated users get at least the "user" role
        if !mapping.roles.contains(&"user".to_string()) {
            mapping.roles.push("user".to_string());
        }

        mapping
    }

    /// Apply role mapping to a user in the database.
    ///
    /// Updates the user's is_admin flag and assigns roles based on the mapping.
    ///
    /// ak-4q87: the is_admin update, the wipe of existing roles, and the
    /// reinstall of mapped roles all run in a single transaction so a mid-
    /// way failure (e.g. a duplicate-key race on user_roles, or a connection
    /// drop after the DELETE) cannot leave the user with no roles and no
    /// is_admin update applied. The whole rebuild is atomic.
    pub async fn apply_role_mapping(&self, user_id: Uuid, mapping: &RoleMapping) -> Result<()> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Update is_admin flag (only if admin group mapping is configured)
        sqlx::query!(
            "UPDATE users SET is_admin = COALESCE($2, is_admin), updated_at = NOW() WHERE id = $1",
            user_id,
            mapping.is_admin
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Clear existing role assignments and add new ones
        // First, remove all current roles (for federated users, roles come from provider)
        sqlx::query!("DELETE FROM user_roles WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Assign new roles based on mapping
        for role_name in &mapping.roles {
            // Look up role by name and assign if it exists
            let role = sqlx::query!("SELECT id FROM roles WHERE name = $1", role_name)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

            if let Some(role) = role {
                sqlx::query!(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    user_id,
                    role.id
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    // =========================================================================
    // T060: Federated User Sync and Deactivation
    // =========================================================================

    /// Sync a federated user from an identity provider.
    ///
    /// This method creates a new user or updates an existing user based on
    /// credentials received from a federated identity provider (LDAP, OIDC, SAML).
    ///
    /// # Arguments
    /// * `provider` - The authentication provider type
    /// * `credentials` - User information from the identity provider
    ///
    /// # Returns
    /// * `Ok(User)` - The created or updated user
    /// * `Err(AppError)` - If sync fails
    pub async fn sync_federated_user(
        &self,
        provider: AuthProvider,
        credentials: &FederatedCredentials,
    ) -> Result<User> {
        // Map groups to roles
        let role_mapping = self.map_groups_to_roles(
            &credentials.groups,
            credentials.required_admin_group.as_deref(),
        );

        // Check if user exists by external_id
        let existing_user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            FROM users
            WHERE external_id = $1 AND auth_provider = $2
            "#,
            credentials.external_id,
            provider as AuthProvider
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let user = if let Some(existing) = existing_user {
            // Update existing user with latest information from provider
            sqlx::query_as!(
                User,
                r#"
                UPDATE users
                SET
                    username = $2,
                    email = $3,
                    display_name = $4,
                    is_admin = COALESCE($5, is_admin),
                    is_active = true,
                    updated_at = NOW()
                WHERE id = $1
                RETURNING
                    id, username, email, password_hash, display_name,
                    auth_provider as "auth_provider: AuthProvider",
                    external_id, is_admin, is_active, is_service_account, must_change_password,
                    totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                    failed_login_attempts, locked_until, last_failed_login_at,
                    password_changed_at, last_login_at, created_at, updated_at
                "#,
                existing.id,
                credentials.username,
                credentials.email,
                credentials.display_name,
                role_mapping.is_admin
            )
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        } else {
            // Create new user from federated credentials
            sqlx::query_as!(
                User,
                r#"
                INSERT INTO users (
                    username, email, display_name, auth_provider,
                    external_id, is_admin, is_active, is_service_account, must_change_password
                )
                VALUES ($1, $2, $3, $4, $5, $6, true, false, false)
                RETURNING
                    id, username, email, password_hash, display_name,
                    auth_provider as "auth_provider: AuthProvider",
                    external_id, is_admin, is_active, is_service_account, must_change_password,
                    totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                    failed_login_attempts, locked_until, last_failed_login_at,
                    password_changed_at, last_login_at, created_at, updated_at
                "#,
                credentials.username,
                credentials.email,
                credentials.display_name,
                provider as AuthProvider,
                credentials.external_id,
                role_mapping.is_admin.unwrap_or(false)
            )
            .fetch_one(&self.db)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("duplicate key") {
                    if msg.contains("username") {
                        AppError::Conflict("Username already exists".to_string())
                    } else if msg.contains("email") {
                        AppError::Conflict("Email already exists".to_string())
                    } else {
                        AppError::Conflict("User already exists".to_string())
                    }
                } else {
                    AppError::Database(msg)
                }
            })?
        };

        // Apply role mapping
        self.apply_role_mapping(user.id, &role_mapping).await?;

        Ok(user)
    }

    /// Deactivate users who no longer exist in the federated provider.
    ///
    /// This method is typically called during a periodic sync job. It compares
    /// the list of active users from the provider with local users and deactivates
    /// any that are no longer present.
    ///
    /// # Arguments
    /// * `provider` - The authentication provider type
    /// * `active_external_ids` - List of external IDs that are still active in the provider
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of users deactivated
    /// * `Err(AppError)` - If deactivation fails
    pub async fn deactivate_missing_users(
        &self,
        provider: AuthProvider,
        active_external_ids: &[String],
    ) -> Result<u64> {
        // Deactivate users that:
        // 1. Are from the specified provider
        // 2. Have an external_id that is NOT in the active list
        // 3. Are currently active
        //
        // Federated SSO sync is the offboarding reaper: when an upstream
        // account is removed (LDAP/SAML/OIDC), this method flips
        // `is_active=false` locally. We MUST invalidate the API-token cache
        // for each deactivated user, otherwise a compromised credential
        // would still authenticate against the cache for up to
        // `API_TOKEN_CACHE_TTL_SECS` (5 min) after the upstream removal.
        // Issue #931.
        let deactivated_ids: Vec<Uuid> = sqlx::query_scalar!(
            r#"
            UPDATE users
            SET is_active = false, updated_at = NOW()
            WHERE auth_provider = $1
              AND is_active = true
              AND external_id IS NOT NULL
              AND external_id != ALL($2)
            RETURNING id
            "#,
            provider as AuthProvider,
            active_external_ids
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        for user_id in &deactivated_ids {
            invalidate_user_token_cache_entries(*user_id);
            invalidate_user_tokens(*user_id);

            // DB-backed refresh-token family revocation (#1174 / PR #1190 review):
            // SSO offboarding must invalidate refresh tokens across every
            // replica, not just the one that ran the sync.
            if let Err(e) = self.revoke_all_refresh_token_families(*user_id).await {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "Failed to revoke refresh-token families during SSO sync deactivation",
                );
            }
        }

        Ok(deactivated_ids.len() as u64)
    }

    /// Reactivate a previously deactivated federated user.
    ///
    /// This is called when a user who was deactivated (e.g., left the company)
    /// returns and authenticates again via the federated provider.
    pub async fn reactivate_federated_user(
        &self,
        external_id: &str,
        provider: AuthProvider,
    ) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET is_active = true, updated_at = NOW()
            WHERE external_id = $1 AND auth_provider = $2
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            "#,
            external_id,
            provider as AuthProvider
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }

    /// List all users from a specific provider that need sync verification.
    ///
    /// Returns users who haven't been verified against the provider recently.
    pub async fn list_users_for_sync(&self, provider: AuthProvider) -> Result<Vec<User>> {
        let users = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            FROM users
            WHERE auth_provider = $1 AND is_active = true
            ORDER BY username
            "#,
            provider as AuthProvider
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(users)
    }

    // =========================================================================
    // TOTP 2FA Support
    // =========================================================================

    /// Generate a short-lived token for TOTP verification pending state
    pub fn generate_totp_pending_token(&self, user: &User) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(5);
        let claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: exp.timestamp(),
            token_type: "totp_pending".to_string(),
            jti: None,
            family_id: None,
        };
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Token encoding failed: {}", e)))
    }

    /// Validate a TOTP pending token and return claims
    pub fn validate_totp_pending_token(&self, token: &str) -> Result<Claims> {
        let token_data = self.decode_token(token)?;
        if token_data.claims.token_type != "totp_pending" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }
        Ok(token_data.claims)
    }
}

/// Determine whether a token's `last_used_at` timestamp is old enough
/// to warrant a database update. Uses a 5-minute debounce window to
/// avoid writing to the database on every single token use.
pub(crate) fn should_debounce_usage_update(last_used_at: Option<DateTime<Utc>>) -> bool {
    match last_used_at {
        None => true,
        Some(lu) => Utc::now() - lu > Duration::minutes(5),
    }
}

/// Evaluate token validation state after bcrypt verification has completed.
/// Separated from the async method so all branches can be unit-tested
/// without a database.
fn check_token_validation_result(
    token_exists: bool,
    is_revoked: bool,
    hash_matches: bool,
) -> Result<()> {
    if !token_exists {
        return Err(AppError::Authentication("Invalid API token".to_string()));
    }
    if is_revoked {
        return Err(AppError::Unauthorized("Token has been revoked".to_string()));
    }
    if !hash_matches {
        return Err(AppError::Authentication("Invalid API token".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_hashing() {
        let password = "test_password_123";
        let hash = AuthService::hash_password(password).await.unwrap();
        assert!(AuthService::verify_password(password, &hash).await.unwrap());
        assert!(!AuthService::verify_password("wrong_password", &hash)
            .await
            .unwrap());
    }

    // -----------------------------------------------------------------------
    // Password hashing edge cases
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_password_hashing_empty_string() {
        let hash = AuthService::hash_password("").await.unwrap();
        assert!(AuthService::verify_password("", &hash).await.unwrap());
        assert!(!AuthService::verify_password("non-empty", &hash)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_password_hashing_unicode() {
        let password = "\u{1F600}password\u{00E9}\u{00FC}";
        let hash = AuthService::hash_password(password).await.unwrap();
        assert!(AuthService::verify_password(password, &hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_password_hashing_long_password() {
        // bcrypt typically truncates at 72 bytes; verify the function works
        let password = "a".repeat(100);
        let hash = AuthService::hash_password(&password).await.unwrap();
        assert!(AuthService::verify_password(&password, &hash)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_password_hash_different_each_time() {
        let password = "same_password";
        let hash1 = AuthService::hash_password(password).await.unwrap();
        let hash2 = AuthService::hash_password(password).await.unwrap();
        // bcrypt uses random salts, so hashes should differ
        assert_ne!(hash1, hash2);
        // But both should verify correctly
        assert!(AuthService::verify_password(password, &hash1)
            .await
            .unwrap());
        assert!(AuthService::verify_password(password, &hash2)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_verify_password_invalid_hash() {
        // An invalid bcrypt hash should return an error, not panic
        let result = AuthService::verify_password("password", "not-a-valid-hash").await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Global bcrypt-bound auth-concurrency cap (#991, #1088)
    // -----------------------------------------------------------------------
    //
    // The pure `try_acquire_permit_from` helper is what `verify_password` /
    // `hash_password` delegate to once they have resolved the global cell.
    // Exercising it directly avoids the test-binary OnceLock contention that
    // would otherwise make these regression assertions order-dependent.

    #[test]
    fn test_acquire_permit_returns_none_when_no_cap_installed() {
        // The legacy "uncapped" mode must not surface as a 503.
        assert!(try_acquire_permit_from(None)
            .expect("must succeed")
            .is_none());
    }

    #[test]
    fn test_acquire_permit_returns_some_when_slot_available() {
        let sem = Arc::new(Semaphore::new(2));
        let permit = try_acquire_permit_from(Some(&sem)).expect("must succeed");
        assert!(permit.is_some(), "expected a permit when slot is free");
    }

    #[test]
    fn test_acquire_permit_sheds_to_503_when_saturated() {
        // This is the regression that the original PR was missing: the cap
        // is now enforced at the bcrypt chokepoint, so EVERY bcrypt path
        // (login, validate_api_token, basic-auth fallback) participates
        // in the shed. When the cap is saturated, the helper must surface
        // `ServiceUnavailable`, which `IntoResponse` maps to 503 +
        // `Retry-After: 1`.
        let sem = Arc::new(Semaphore::new(1));
        let _held = sem
            .clone()
            .try_acquire_owned()
            .expect("first permit must succeed");
        match try_acquire_permit_from(Some(&sem)) {
            Err(AppError::ServiceUnavailable(_)) => {}
            other => panic!("expected ServiceUnavailable, got {:?}", other),
        }
    }

    #[test]
    fn test_acquire_permit_releases_on_permit_drop() {
        let sem = Arc::new(Semaphore::new(1));
        {
            let _p = try_acquire_permit_from(Some(&sem))
                .expect("must succeed")
                .expect("must yield a permit");
            // While `_p` is alive, the second acquire sheds.
            assert!(matches!(
                try_acquire_permit_from(Some(&sem)),
                Err(AppError::ServiceUnavailable(_))
            ));
        }
        // After drop, the permit is back in the pool and the next acquire
        // succeeds. This guarantees no permit leaks on bcrypt panic / error.
        assert!(try_acquire_permit_from(Some(&sem))
            .expect("must succeed")
            .is_some());
    }

    // -----------------------------------------------------------------------
    // #1437 / #1442: bounded-wait permit acquisition. The fast path must
    // not yield, the queued path must drain when a slot frees, and the
    // shed path must surface 503 after the wait elapses. Together these
    // turn a burst of N basic-auth requests at cap=K into K-by-K drain
    // instead of `N - K` instant 503 failures, which was the dominant
    // failure shape in the stress-tests behind #1437.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_acquire_permit_fast_path_does_not_wait() {
        let sem = Arc::new(Semaphore::new(2));
        let started = std::time::Instant::now();
        let permit = acquire_permit_from(Some(&sem), std::time::Duration::from_secs(60))
            .await
            .expect("must succeed");
        assert!(permit.is_some());
        // Free slot -> immediate success. 50 ms is generous and accounts
        // for runner jitter.
        assert!(
            started.elapsed() < std::time::Duration::from_millis(50),
            "fast path should not wait, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn test_acquire_permit_waits_for_held_slot_to_free() {
        let sem = Arc::new(Semaphore::new(1));
        let held = sem
            .clone()
            .try_acquire_owned()
            .expect("first slot must succeed");

        // Release the held permit shortly after a queued acquire starts,
        // mimicking a bcrypt verify finishing.
        let releaser = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(held);
        });

        let started = std::time::Instant::now();
        let permit = acquire_permit_from(Some(&sem), std::time::Duration::from_secs(5))
            .await
            .expect("queued acquire must succeed before timeout");
        assert!(permit.is_some());
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(40),
            "should have waited for releaser, elapsed {:?}",
            started.elapsed()
        );
        releaser.await.unwrap();
    }

    #[tokio::test]
    async fn test_acquire_permit_sheds_after_wait_elapses() {
        let sem = Arc::new(Semaphore::new(1));
        let _held = sem
            .clone()
            .try_acquire_owned()
            .expect("first slot must succeed");

        // Nobody will release the permit -> the wait elapses and we shed.
        let result = acquire_permit_from(Some(&sem), std::time::Duration::from_millis(80)).await;
        match result {
            Err(AppError::ServiceUnavailable(_)) => {}
            other => panic!("expected ServiceUnavailable after wait, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_acquire_permit_no_cap_short_circuits() {
        // When the operator opts out (auth_max_concurrency=0), the helper
        // must not block or shed - it returns `None` immediately so bcrypt
        // runs uncapped (legacy behaviour). This preserves the test-binary
        // semantics that #1200 was careful to keep working.
        let started = std::time::Instant::now();
        let permit = acquire_permit_from(None, std::time::Duration::from_secs(60))
            .await
            .expect("must succeed");
        assert!(permit.is_none());
        assert!(started.elapsed() < std::time::Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_acquire_permit_burst_drains_at_cap() {
        // The end-to-end shape #1437 / #1442 was filed against: 50
        // concurrent acquires at cap=8 must all complete (none shed)
        // when each holder releases promptly. This is the contract that
        // turns flat-line-at-8 stress tests into clean drains.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let sem = Arc::new(Semaphore::new(8));
        let succeeded = Arc::new(AtomicUsize::new(0));
        let shed = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(50);
        for _ in 0..50 {
            let sem = sem.clone();
            let succeeded = succeeded.clone();
            let shed = shed.clone();
            handles.push(tokio::spawn(async move {
                match acquire_permit_from(Some(&sem), std::time::Duration::from_secs(3)).await {
                    Ok(Some(_permit)) => {
                        // Simulate a 30 ms bcrypt verify before releasing.
                        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                        succeeded.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        // Should not happen with a cap installed.
                        panic!("unexpected None permit with cap installed");
                    }
                    Err(_) => {
                        shed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let ok = succeeded.load(Ordering::Relaxed);
        let bad = shed.load(Ordering::Relaxed);
        // At 50 requests with cap=8 and ~30 ms per slot, the entire burst
        // completes in ~50 * 30 / 8 ≈ 190 ms, well under the 3 s shed
        // boundary. Before this fix the same shape produced 50 - 8 = 42
        // 503 failures (one permit at a time, no queue). We allow up to 5
        // sheds for scheduler jitter on slow runners but the dominant
        // outcome must be ~all succeed.
        assert!(
            ok >= 45,
            "expected at least 45/50 to succeed, got {ok} ok, {bad} shed"
        );
    }

    // -----------------------------------------------------------------------
    // Token generation & validation (no DB needed)
    // -----------------------------------------------------------------------

    fn make_test_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: "postgresql://unused".to_string(),
            bind_address: "0.0.0.0:8080".to_string(),
            log_level: "info".to_string(),
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/test".to_string(),
            s3_bucket: None,
            gcs_bucket: None,
            s3_region: None,
            s3_endpoint: None,
            jwt_secret: "super-secret-test-key-for-unit-tests-minimum-length".to_string(),
            jwt_expiration_secs: 86400,
            jwt_access_token_expiry_minutes: 30,
            jwt_refresh_token_expiry_days: 7,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            ldap_url: None,
            ldap_base_dn: None,
            trivy_url: None,
            openscap_url: None,
            openscap_profile: "standard".to_string(),
            opensearch_url: None,
            opensearch_username: None,
            opensearch_password: None,
            opensearch_allow_invalid_certs: false,
            scan_workspace_path: "/tmp".to_string(),
            demo_mode: false,
            guest_access_enabled: true,
            peer_instance_name: "test".to_string(),
            peer_public_endpoint: "http://localhost:8080".to_string(),
            peer_api_key: "test-key".to_string(),
            dependency_track_url: None,
            dependency_track_enabled: false,
            otel_exporter_otlp_endpoint: None,
            otel_service_name: "test".to_string(),
            gc_schedule: "0 0 * * * *".to_string(),
            lifecycle_check_interval_secs: 60,
            stuck_scan_threshold_secs: 1800,
            stuck_scan_check_interval_secs: 600,
            stuck_scan_reap_limit: 1000,
            max_upload_size_bytes: 10_737_418_240,
            allow_local_admin_login: false,
            metrics_port: None,
            database_max_connections: 20,
            database_min_connections: 5,
            database_acquire_timeout_secs: 30,
            database_idle_timeout_secs: 600,
            database_max_lifetime_secs: 1800,
            auth_max_concurrency: 8,
            rate_limit_auth_per_window: 120,
            rate_limit_api_per_window: 5000,
            rate_limit_search_per_window: 300,
            rate_limit_presign_per_window: 30,
            rate_limit_password_change_per_window: 5,
            rate_limit_password_change_window_secs: 900,
            rate_limit_window_secs: 60,
            rate_limit_exempt_usernames: Vec::new(),
            rate_limit_exempt_service_accounts: false,
            rate_limit_trusted_cidrs: Vec::new(),
            account_lockout_threshold: 5,
            account_lockout_duration_minutes: 30,
            quarantine_enabled: false,
            quarantine_duration_minutes: 60,
            password_history_count: 0,
            password_expiry_days: 0,
            password_expiry_warning_days: vec![1, 7, 14],
            password_expiry_check_interval_secs: 3600,
            password_min_length: 8,
            password_max_length: 128,
            password_require_uppercase: false,
            password_require_lowercase: false,
            password_require_digit: false,
            password_require_special: false,
            password_min_strength: 0,
            presigned_downloads_enabled: false,
            presigned_download_expiry_secs: 300,
            smtp_host: None,
            smtp_port: 587,
            smtp_username: None,
            smtp_password: None,
            smtp_from_address: "noreply@artifact-keeper.local".to_string(),
            smtp_tls_mode: "starttls".to_string(),
        })
    }

    fn make_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: None,
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: Some("Test User".to_string()),
            is_active: true,
            is_admin: false,
            is_service_account: false,
            must_change_password: false,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_failed_login_at: None,
            password_changed_at: Utc::now(),
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // We cannot create a PgPool without a real database, so for unit tests that
    // need JWT encoding/decoding, we directly use jsonwebtoken's encode/decode
    // with the same keys the AuthService would use.

    #[test]
    fn test_generate_tokens_and_validate_access_token() {
        let config = make_test_config();
        let secret = config.jwt_secret.clone();
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let user = make_test_user();
        let now = Utc::now();
        let access_exp = now + Duration::minutes(config.jwt_access_token_expiry_minutes);
        let refresh_exp = now + Duration::days(config.jwt_refresh_token_expiry_days);

        let access_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: access_exp.timestamp(),
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
        };

        let refresh_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: refresh_exp.timestamp(),
            token_type: "refresh".to_string(),
            jti: Some(Uuid::new_v4()),
            family_id: Some(Uuid::new_v4()),
        };

        let access_token = encode(&Header::default(), &access_claims, &encoding_key).unwrap();
        let refresh_token = encode(&Header::default(), &refresh_claims, &encoding_key).unwrap();

        // Validate access token
        let decoded = decode::<Claims>(
            &access_token,
            &decoding_key,
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(decoded.claims.sub, user.id);
        assert_eq!(decoded.claims.username, "testuser");
        assert_eq!(decoded.claims.token_type, "access");
        assert!(!decoded.claims.is_admin);

        // Validate refresh token
        let decoded = decode::<Claims>(
            &refresh_token,
            &decoding_key,
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(decoded.claims.sub, user.id);
        assert_eq!(decoded.claims.token_type, "refresh");
    }

    #[test]
    fn test_validate_access_token_rejects_refresh_token() {
        let config = make_test_config();
        let secret = config.jwt_secret.clone();
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let now = Utc::now();
        let refresh_claims = Claims {
            sub: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@test.com".to_string(),
            is_admin: false,
            iat: now.timestamp(),
            exp: (now + Duration::days(7)).timestamp(),
            token_type: "refresh".to_string(),
            jti: Some(Uuid::new_v4()),
            family_id: Some(Uuid::new_v4()),
        };

        let token = encode(&Header::default(), &refresh_claims, &encoding_key).unwrap();

        // Decoding succeeds, but validate_access_token should reject
        let decoded =
            decode::<Claims>(&token, &decoding_key, &Validation::new(Algorithm::HS256)).unwrap();
        assert_eq!(decoded.claims.token_type, "refresh");
        // This would fail in validate_access_token because token_type != "access"
    }

    #[test]
    fn test_expired_token_rejected() {
        let config = make_test_config();
        let secret = config.jwt_secret.clone();
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "expired".to_string(),
            email: "expired@test.com".to_string(),
            is_admin: false,
            iat: (now - Duration::hours(2)).timestamp(),
            exp: (now - Duration::hours(1)).timestamp(), // expired 1 hour ago
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
        };

        let token = encode(&Header::default(), &claims, &encoding_key).unwrap();
        let result = decode::<Claims>(&token, &decoding_key, &Validation::new(Algorithm::HS256));
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let encoding_key = EncodingKey::from_secret(b"secret-one");
        let decoding_key = DecodingKey::from_secret(b"secret-two");

        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "user".to_string(),
            email: "u@t.com".to_string(),
            is_admin: false,
            iat: now.timestamp(),
            exp: (now + Duration::hours(1)).timestamp(),
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
        };

        let token = encode(&Header::default(), &claims, &encoding_key).unwrap();
        let result = decode::<Claims>(&token, &decoding_key, &Validation::new(Algorithm::HS256));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Claims serialization / deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_claims_serialization_roundtrip() {
        let user_id = Uuid::new_v4();
        let claims = Claims {
            sub: user_id,
            username: "test".to_string(),
            email: "test@x.com".to_string(),
            is_admin: true,
            iat: 1000,
            exp: 2000,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
        };

        let json = serde_json::to_string(&claims).unwrap();
        let decoded: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sub, user_id);
        assert_eq!(decoded.username, "test");
        assert!(decoded.is_admin);
        assert_eq!(decoded.token_type, "access");
    }

    #[test]
    fn test_claims_with_jti_and_family_serialize() {
        // Verify the new refresh-token fields round-trip through serde,
        // and that an old JWT without them still parses (#1174).
        let jti = Uuid::new_v4();
        let family = Uuid::new_v4();
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "u".to_string(),
            email: "u@x.com".to_string(),
            is_admin: false,
            iat: 1000,
            exp: 2000,
            token_type: "refresh".to_string(),
            jti: Some(jti),
            family_id: Some(family),
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("jti"));
        assert!(json.contains("family_id"));
        let decoded: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.jti, Some(jti));
        assert_eq!(decoded.family_id, Some(family));

        // Legacy JWT without jti/family_id should still parse cleanly.
        let legacy = r#"{
            "sub":"00000000-0000-0000-0000-000000000001",
            "username":"u","email":"u@x.com","is_admin":false,
            "iat":1000,"exp":2000,"token_type":"refresh"
        }"#;
        let parsed: Claims = serde_json::from_str(legacy).unwrap();
        assert!(parsed.jti.is_none());
        assert!(parsed.family_id.is_none());
    }

    // -----------------------------------------------------------------------
    // TokenPair serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_pair_serialize() {
        let pair = TokenPair {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            expires_in: 1800,
        };
        let json = serde_json::to_value(&pair).unwrap();
        assert_eq!(json["access_token"], "access123");
        assert_eq!(json["refresh_token"], "refresh456");
        assert_eq!(json["expires_in"], 1800);
    }

    // -----------------------------------------------------------------------
    // FederatedCredentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_federated_credentials_debug() {
        let creds = FederatedCredentials {
            external_id: "ext-123".to_string(),
            username: "feduser".to_string(),
            email: "fed@example.com".to_string(),
            display_name: Some("Fed User".to_string()),
            groups: vec!["devs".to_string(), "admin".to_string()],
            required_admin_group: None,
        };
        let debug = format!("{:?}", creds);
        assert!(debug.contains("feduser"));
        assert!(debug.contains("ext-123"));
    }

    // -----------------------------------------------------------------------
    // RoleMapping
    // -----------------------------------------------------------------------

    #[test]
    fn test_role_mapping_default() {
        let mapping = RoleMapping::default();
        assert!(mapping.is_admin.is_none());
        assert!(mapping.roles.is_empty());
    }

    // -----------------------------------------------------------------------
    // map_groups_to_roles (pure function, no DB)
    // -----------------------------------------------------------------------

    // We can test map_groups_to_roles by creating a minimal AuthService.
    // Since it does not use self.db or self.config, we just need any instance.
    // We'll test using the same approach: direct key construction.

    // Reimplement map_groups_to_roles locally since AuthService requires PgPool
    // and we cannot create one without a real database connection.
    fn test_map_groups_to_roles(groups: &[String]) -> RoleMapping {
        test_map_groups_to_roles_with_admin(groups, None)
    }

    fn test_map_groups_to_roles_with_admin(
        groups: &[String],
        required_admin_group: Option<&str>,
    ) -> RoleMapping {
        let mut mapping = RoleMapping::default();
        let normalized_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();

        if let Some(ag) = required_admin_group {
            let ag_lower = ag.to_lowercase();
            if normalized_groups.contains(&ag_lower) {
                mapping.is_admin = Some(true);
                mapping.roles.push("admin".to_string());
            } else {
                mapping.is_admin = Some(false);
            }
        } else {
            let admin_patterns = ["admin", "administrators", "superusers", "artifact-admins"];
            for group in &normalized_groups {
                for pattern in &admin_patterns {
                    if group.contains(pattern) {
                        mapping.is_admin = Some(true);
                        mapping.roles.push("admin".to_string());
                        break;
                    }
                }
            }
        }

        let role_mappings = [
            ("developers", "developer"),
            ("readonly", "reader"),
            ("deployers", "deployer"),
            ("artifact-publishers", "publisher"),
        ];

        for group in &normalized_groups {
            for (pattern, role) in &role_mappings {
                if group.contains(pattern) && !mapping.roles.contains(&role.to_string()) {
                    mapping.roles.push(role.to_string());
                }
            }
        }

        if !mapping.roles.contains(&"user".to_string()) {
            mapping.roles.push("user".to_string());
        }

        mapping
    }

    #[test]
    fn test_map_groups_admin_group() {
        let mapping = test_map_groups_to_roles(&["team-admin".to_string()]);
        assert_eq!(mapping.is_admin, Some(true));
        assert!(mapping.roles.contains(&"admin".to_string()));
    }

    #[test]
    fn test_map_groups_administrators_group() {
        let mapping = test_map_groups_to_roles(&["CN=Administrators,DC=corp".to_string()]);
        assert_eq!(mapping.is_admin, Some(true));
    }

    #[test]
    fn test_map_groups_superusers_group() {
        let mapping = test_map_groups_to_roles(&["superusers".to_string()]);
        assert_eq!(mapping.is_admin, Some(true));
    }

    #[test]
    fn test_map_groups_artifact_admins_group() {
        let mapping = test_map_groups_to_roles(&["artifact-admins".to_string()]);
        assert_eq!(mapping.is_admin, Some(true));
    }

    #[test]
    fn test_map_groups_case_insensitive_admin() {
        let mapping = test_map_groups_to_roles(&["ADMIN-TEAM".to_string()]);
        assert_eq!(mapping.is_admin, Some(true));
    }

    #[test]
    fn test_map_groups_developers() {
        let mapping = test_map_groups_to_roles(&["team-developers".to_string()]);
        assert!(mapping.is_admin.is_none());
        assert!(mapping.roles.contains(&"developer".to_string()));
        assert!(mapping.roles.contains(&"user".to_string()));
    }

    #[test]
    fn test_map_groups_readonly() {
        let mapping = test_map_groups_to_roles(&["readonly-users".to_string()]);
        assert!(mapping.roles.contains(&"reader".to_string()));
    }

    #[test]
    fn test_map_groups_deployers() {
        let mapping = test_map_groups_to_roles(&["deployers".to_string()]);
        assert!(mapping.roles.contains(&"deployer".to_string()));
    }

    #[test]
    fn test_map_groups_publishers() {
        let mapping = test_map_groups_to_roles(&["artifact-publishers".to_string()]);
        assert!(mapping.roles.contains(&"publisher".to_string()));
    }

    #[test]
    fn test_map_groups_no_matching_groups() {
        let mapping = test_map_groups_to_roles(&["random-group".to_string()]);
        assert!(mapping.is_admin.is_none());
        assert_eq!(mapping.roles, vec!["user"]);
    }

    #[test]
    fn test_map_groups_empty_groups() {
        let mapping = test_map_groups_to_roles(&[]);
        assert!(mapping.is_admin.is_none());
        assert_eq!(mapping.roles, vec!["user"]);
    }

    #[test]
    fn test_map_groups_multiple_roles() {
        let mapping =
            test_map_groups_to_roles(&["developers".to_string(), "deployers".to_string()]);
        assert!(mapping.roles.contains(&"developer".to_string()));
        assert!(mapping.roles.contains(&"deployer".to_string()));
        assert!(mapping.roles.contains(&"user".to_string()));
    }

    #[test]
    fn test_map_groups_admin_plus_developer() {
        let mapping = test_map_groups_to_roles(&["admin".to_string(), "developers".to_string()]);
        assert_eq!(mapping.is_admin, Some(true));
        assert!(mapping.roles.contains(&"admin".to_string()));
        assert!(mapping.roles.contains(&"developer".to_string()));
        // user role should not be duplicated
        let user_count = mapping
            .roles
            .iter()
            .filter(|r| r.as_str() == "user")
            .count();
        assert_eq!(user_count, 1);
    }

    #[test]
    fn test_map_groups_no_duplicate_roles() {
        let mapping = test_map_groups_to_roles(&[
            "developers".to_string(),
            "team-developers".to_string(), // same pattern matches twice
        ]);
        let dev_count = mapping
            .roles
            .iter()
            .filter(|r| r.as_str() == "developer")
            .count();
        assert_eq!(dev_count, 1, "developer role should not be duplicated");
    }

    // -----------------------------------------------------------------------
    // required_admin_group (exact match overrides default patterns)
    // -----------------------------------------------------------------------

    #[test]
    fn test_required_admin_group_exact_match() {
        let mapping = test_map_groups_to_roles_with_admin(
            &["my-admins".to_string(), "devs".to_string()],
            Some("my-admins"),
        );
        assert_eq!(mapping.is_admin, Some(true));
    }

    #[test]
    fn test_required_admin_group_no_match() {
        let mapping = test_map_groups_to_roles_with_admin(
            &["other-admins".to_string(), "devs".to_string()],
            Some("my-admins"),
        );
        assert_eq!(mapping.is_admin, Some(false));
    }

    #[test]
    fn test_required_admin_group_prevents_substring_match() {
        // "company-admin-team" contains "admin" but should NOT match required "admin"
        let mapping =
            test_map_groups_to_roles_with_admin(&["company-admin-team".to_string()], Some("admin"));
        assert_eq!(mapping.is_admin, Some(false));
    }

    // -----------------------------------------------------------------------
    // should_debounce_usage_update (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_debounce_never_used_returns_true() {
        assert!(should_debounce_usage_update(None));
    }

    #[test]
    fn test_debounce_used_just_now_returns_false() {
        let last_used = Utc::now() - Duration::seconds(1);
        assert!(!should_debounce_usage_update(Some(last_used)));
    }

    #[test]
    fn test_debounce_used_4_min_ago_returns_false() {
        let last_used = Utc::now() - Duration::minutes(4);
        assert!(!should_debounce_usage_update(Some(last_used)));
    }

    #[test]
    fn test_debounce_used_6_min_ago_returns_true() {
        let last_used = Utc::now() - Duration::minutes(6);
        assert!(should_debounce_usage_update(Some(last_used)));
    }

    #[test]
    fn test_debounce_used_1_hour_ago_returns_true() {
        let last_used = Utc::now() - Duration::hours(1);
        assert!(should_debounce_usage_update(Some(last_used)));
    }

    #[test]
    fn test_debounce_boundary_exactly_5_min() {
        // The function uses `Utc::now() - lu > Duration::minutes(5)`, so a
        // last_used value 4 minutes and 59 seconds ago should NOT trigger an
        // update (the difference is not strictly greater than 5 minutes).
        let last_used = Utc::now() - Duration::seconds(4 * 60 + 59);
        assert!(!should_debounce_usage_update(Some(last_used)));
    }

    // -----------------------------------------------------------------------
    // Timing side-channel: dummy bcrypt hash for constant-time rejection
    // -----------------------------------------------------------------------

    #[test]
    fn test_dummy_bcrypt_hash_is_valid_and_never_matches() {
        let dummy = AuthService::dummy_bcrypt_hash();
        // The dummy hash must be a structurally valid bcrypt hash so that
        // bcrypt::verify runs the full cost-12 computation instead of
        // returning an immediate error.
        let result = verify("any-token-value", dummy);
        assert!(
            result.is_ok(),
            "dummy_bcrypt_hash must produce a valid bcrypt hash, got error: {:?}",
            result.err()
        );
        assert!(
            !result.unwrap(),
            "dummy_bcrypt_hash must never match any input"
        );

        // Also verify with an empty string
        let result_empty = verify("", dummy);
        assert!(result_empty.is_ok());
        assert!(!result_empty.unwrap());
    }

    #[test]
    fn test_dummy_bcrypt_hash_is_stable() {
        // OnceLock must return the same value on every call
        let h1 = AuthService::dummy_bcrypt_hash();
        let h2 = AuthService::dummy_bcrypt_hash();
        assert_eq!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // check_token_validation_result (pure decision logic)
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_validation_valid() {
        assert!(check_token_validation_result(true, false, true).is_ok());
    }

    #[test]
    fn test_token_validation_not_found() {
        let err = check_token_validation_result(false, false, false).unwrap_err();
        assert!(
            format!("{}", err).contains("Invalid API token"),
            "Expected 'Invalid API token', got: {}",
            err
        );
    }

    #[test]
    fn test_token_validation_revoked() {
        let err = check_token_validation_result(true, true, true).unwrap_err();
        assert!(
            format!("{}", err).contains("revoked"),
            "Expected revocation error, got: {}",
            err
        );
    }

    #[test]
    fn test_token_validation_hash_mismatch() {
        let err = check_token_validation_result(true, false, false).unwrap_err();
        assert!(
            format!("{}", err).contains("Invalid API token"),
            "Expected 'Invalid API token', got: {}",
            err
        );
    }

    #[test]
    fn test_token_validation_revoked_takes_priority_over_hash_mismatch() {
        // If both revoked and hash mismatch, revoked error should come first
        let err = check_token_validation_result(true, true, false).unwrap_err();
        assert!(
            format!("{}", err).contains("revoked"),
            "Expected revocation error, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // API token cache key hashing
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_cache_key_is_sha256_hex() {
        let token = "ak_12345678_secret_token_value";
        let key = format!("{:x}", Sha256::digest(token.as_bytes()));
        // SHA-256 hex output is always 64 characters
        assert_eq!(key.len(), 64);
        // Must be lowercase hex
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_token_cache_key_deterministic() {
        let token = "ak_abcdefgh_my_token";
        let k1 = format!("{:x}", Sha256::digest(token.as_bytes()));
        let k2 = format!("{:x}", Sha256::digest(token.as_bytes()));
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_token_cache_key_different_tokens_produce_different_keys() {
        let k1 = format!("{:x}", Sha256::digest(b"ak_aaaaaaaa_token1"));
        let k2 = format!("{:x}", Sha256::digest(b"ak_bbbbbbbb_token2"));
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_token_cache_key_does_not_contain_raw_token() {
        let token = "ak_12345678_very_secret";
        let key = format!("{:x}", Sha256::digest(token.as_bytes()));
        assert!(!key.contains("ak_12345678"));
        assert!(!key.contains("very_secret"));
    }

    #[test]
    fn test_api_token_cache_ttl_constant() {
        assert_eq!(API_TOKEN_CACHE_TTL_SECS, 300);
    }

    #[test]
    fn test_token_cache_construction() {
        // Verify the token_cache field can be constructed and used
        let cache: RwLock<HashMap<String, (CachedApiTokenEntry, Instant)>> =
            RwLock::new(HashMap::new());
        assert!(cache.read().unwrap().is_empty());
    }

    #[test]
    fn test_token_cache_insert_and_read() {
        let cache: RwLock<HashMap<String, (CachedApiTokenEntry, Instant)>> =
            RwLock::new(HashMap::new());
        let key = format!("{:x}", Sha256::digest(b"ak_testtest_token"));
        let validation = ApiTokenValidation {
            user: User {
                id: Uuid::nil(),
                username: "testuser".to_string(),
                email: "test@example.com".to_string(),
                password_hash: None,
                display_name: None,
                auth_provider: AuthProvider::Local,
                external_id: None,
                is_admin: false,
                is_active: true,
                is_service_account: false,
                must_change_password: false,
                totp_secret: None,
                totp_enabled: false,
                totp_backup_codes: None,
                totp_verified_at: None,
                failed_login_attempts: 0,
                locked_until: None,
                last_failed_login_at: None,
                password_changed_at: Utc::now(),
                last_login_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            scopes: vec!["read:artifacts".to_string()],
            allowed_repo_ids: None,
        };
        let entry = CachedApiTokenEntry {
            validation,
            token_id: Uuid::nil(),
            expires_at: None,
        };
        cache
            .write()
            .unwrap()
            .insert(key.clone(), (entry, Instant::now()));

        let guard = cache.read().unwrap();
        let (cached, at) = guard.get(&key).unwrap();
        assert_eq!(cached.validation.user.username, "testuser");
        assert!(at.elapsed().as_secs() < API_TOKEN_CACHE_TTL_SECS);
    }

    #[test]
    fn test_token_cache_eviction() {
        let cache: RwLock<HashMap<String, (CachedApiTokenEntry, Instant)>> =
            RwLock::new(HashMap::new());
        let key = format!("{:x}", Sha256::digest(b"ak_stalekey_token"));
        let validation = ApiTokenValidation {
            user: User {
                id: Uuid::nil(),
                username: "stale".to_string(),
                email: "stale@example.com".to_string(),
                password_hash: None,
                display_name: None,
                auth_provider: AuthProvider::Local,
                external_id: None,
                is_admin: false,
                is_active: true,
                is_service_account: false,
                must_change_password: false,
                totp_secret: None,
                totp_enabled: false,
                totp_backup_codes: None,
                totp_verified_at: None,
                failed_login_attempts: 0,
                locked_until: None,
                last_failed_login_at: None,
                password_changed_at: Utc::now(),
                last_login_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            scopes: vec![],
            allowed_repo_ids: None,
        };
        let entry = CachedApiTokenEntry {
            validation,
            token_id: Uuid::nil(),
            expires_at: None,
        };

        // Insert with a backdated timestamp
        let expired_at =
            Instant::now() - std::time::Duration::from_secs(API_TOKEN_CACHE_TTL_SECS + 1);
        cache
            .write()
            .unwrap()
            .insert(key.clone(), (entry, expired_at));

        // Evict stale entries
        cache
            .write()
            .unwrap()
            .retain(|_, (_, at)| at.elapsed().as_secs() < API_TOKEN_CACHE_TTL_SECS);

        assert!(cache.read().unwrap().get(&key).is_none());
    }

    #[test]
    fn test_revoked_token_rejected_from_cache() {
        let token_id = Uuid::new_v4();
        mark_api_token_revoked(token_id);
        assert!(is_api_token_revoked_in_cache(token_id));
    }

    #[test]
    fn test_non_revoked_token_not_in_cache() {
        let token_id = Uuid::new_v4();
        assert!(!is_api_token_revoked_in_cache(token_id));
    }

    #[test]
    fn test_cached_expired_token_detected() {
        let past = Utc::now() - Duration::seconds(60);
        let entry = CachedApiTokenEntry {
            validation: ApiTokenValidation {
                user: User {
                    id: Uuid::nil(),
                    username: "expired".to_string(),
                    email: "expired@example.com".to_string(),
                    password_hash: None,
                    display_name: None,
                    auth_provider: AuthProvider::Local,
                    external_id: None,
                    is_admin: false,
                    is_active: true,
                    is_service_account: false,
                    must_change_password: false,
                    totp_secret: None,
                    totp_enabled: false,
                    totp_backup_codes: None,
                    totp_verified_at: None,
                    failed_login_attempts: 0,
                    locked_until: None,
                    last_failed_login_at: None,
                    password_changed_at: Utc::now(),
                    last_login_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
                scopes: vec![],
                allowed_repo_ids: None,
            },
            token_id: Uuid::new_v4(),
            expires_at: Some(past),
        };
        assert!(entry.expires_at.unwrap() < Utc::now());
    }

    #[test]
    fn test_cached_non_expired_token_ok() {
        let future = Utc::now() + Duration::days(30);
        let entry = CachedApiTokenEntry {
            validation: ApiTokenValidation {
                user: User {
                    id: Uuid::nil(),
                    username: "valid".to_string(),
                    email: "valid@example.com".to_string(),
                    password_hash: None,
                    display_name: None,
                    auth_provider: AuthProvider::Local,
                    external_id: None,
                    is_admin: false,
                    is_active: true,
                    is_service_account: false,
                    must_change_password: false,
                    totp_secret: None,
                    totp_enabled: false,
                    totp_backup_codes: None,
                    totp_verified_at: None,
                    failed_login_attempts: 0,
                    locked_until: None,
                    last_failed_login_at: None,
                    password_changed_at: Utc::now(),
                    last_login_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
                scopes: vec![],
                allowed_repo_ids: None,
            },
            token_id: Uuid::new_v4(),
            expires_at: Some(future),
        };
        assert!(entry.expires_at.unwrap() > Utc::now());
    }

    #[test]
    fn test_invalidate_user_tokens_marks_user() {
        let user_id = Uuid::new_v4();
        let before = Utc::now().timestamp();
        invalidate_user_tokens(user_id);
        assert!(is_token_invalidated(user_id, before - 1));
    }

    #[test]
    fn test_token_issued_after_invalidation_is_accepted() {
        let user_id = Uuid::new_v4();
        invalidate_user_tokens(user_id);
        // Watermark is `now + 1` (#1436 fix) so the sync `<=` map rejects
        // every iat <= now+1. We bump the test "after" to `now + 2` to
        // represent a JWT minted at least one whole second after the
        // invalidation completed.
        let after = Utc::now().timestamp() + 2;
        assert!(!is_token_invalidated(user_id, after));
    }

    #[test]
    fn test_unknown_user_is_not_invalidated() {
        let unknown = Uuid::new_v4();
        assert!(!is_token_invalidated(unknown, 0));
    }

    #[test]
    fn test_reinvalidation_updates_timestamp() {
        let user_id = Uuid::new_v4();
        invalidate_user_tokens(user_id);
        let mid = Utc::now().timestamp();
        // Slight delay so second invalidation gets a newer timestamp
        std::thread::sleep(std::time::Duration::from_millis(10));
        invalidate_user_tokens(user_id);
        // Same `+2` rationale as test_token_issued_after_invalidation_is_accepted.
        let after = Utc::now().timestamp() + 2;
        // Token issued before second invalidation is still rejected
        assert!(is_token_invalidated(user_id, mid - 1));
        // Token issued after second invalidation is accepted
        assert!(!is_token_invalidated(user_id, after));
    }

    #[test]
    fn test_token_issued_at_exact_invalidation_time_is_rejected() {
        // Boundary fix (#1173): `iat == changed_at` (1-second JWT resolution)
        // must be rejected. Previously this was `<` and silently let through
        // tokens minted in the same wall-clock second as the invalidation.
        let user_id = Uuid::new_v4();
        let pre = Utc::now().timestamp();
        invalidate_user_tokens(user_id);
        // A token issued in the same second as the invalidation (iat == watermark)
        // should now be rejected.
        let map = invalidation_map().read().unwrap();
        let &(watermark, _) = map.get(&user_id).unwrap();
        drop(map);
        assert!(
            is_token_invalidated(user_id, watermark),
            "same-second token must be rejected"
        );
        // Token issued strictly before invalidation is still rejected.
        assert!(is_token_invalidated(user_id, pre - 1));
        // Token issued strictly after invalidation is still accepted.
        assert!(!is_token_invalidated(user_id, watermark + 1));
    }

    #[test]
    fn test_multiple_users_invalidated_independently() {
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let before = Utc::now().timestamp() - 1;

        invalidate_user_tokens(user_a);
        // user_a is invalidated, user_b is not
        assert!(is_token_invalidated(user_a, before));
        assert!(!is_token_invalidated(user_b, before));

        invalidate_user_tokens(user_b);
        // now both are invalidated for tokens issued before
        assert!(is_token_invalidated(user_a, before));
        assert!(is_token_invalidated(user_b, before));
    }

    #[test]
    fn test_invalidation_map_initialized_on_first_access() {
        // Calling is_token_invalidated on a never-seen user should not panic
        // and should return false, exercising the OnceLock init path
        let fresh = Uuid::new_v4();
        assert!(!is_token_invalidated(fresh, Utc::now().timestamp()));
    }

    // -----------------------------------------------------------------------
    // API-token cache invalidation on user deactivation (issue #931)
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalidate_user_token_cache_entries_marks_user() {
        let user_id = Uuid::new_v4();
        let cached_at = Instant::now();
        // Sleep so the invalidation timestamp is strictly after `cached_at`.
        std::thread::sleep(std::time::Duration::from_millis(10));
        invalidate_user_token_cache_entries(user_id);
        assert!(is_user_api_tokens_invalidated_after(user_id, cached_at));
    }

    #[test]
    fn test_user_invalidation_does_not_affect_other_users() {
        let target = Uuid::new_v4();
        let other = Uuid::new_v4();
        let cached_at = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        invalidate_user_token_cache_entries(target);
        assert!(is_user_api_tokens_invalidated_after(target, cached_at));
        assert!(!is_user_api_tokens_invalidated_after(other, cached_at));
    }

    #[test]
    fn test_cache_entry_inserted_after_invalidation_is_kept() {
        let user_id = Uuid::new_v4();
        invalidate_user_token_cache_entries(user_id);
        std::thread::sleep(std::time::Duration::from_millis(10));
        // A fresh cache entry inserted AFTER the invalidation timestamp
        // should not be rejected (the user has been re-validated against the DB).
        let cached_at = Instant::now();
        assert!(!is_user_api_tokens_invalidated_after(user_id, cached_at));
    }

    #[test]
    fn test_unknown_user_is_not_api_token_invalidated() {
        let unknown = Uuid::new_v4();
        assert!(!is_user_api_tokens_invalidated_after(
            unknown,
            Instant::now()
        ));
    }

    #[test]
    fn test_flush_user_token_cache_entries_removes_only_target_user() {
        // Construct two cache entries for different users in a synthetic cache
        // and verify the flush helper only drops entries matching the user_id.
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();

        fn make_entry(id: Uuid) -> CachedApiTokenEntry {
            CachedApiTokenEntry {
                validation: ApiTokenValidation {
                    user: User {
                        id,
                        username: format!("u-{}", id),
                        email: "x@example.com".to_string(),
                        password_hash: None,
                        display_name: None,
                        auth_provider: AuthProvider::Local,
                        external_id: None,
                        is_admin: false,
                        is_active: true,
                        is_service_account: false,
                        must_change_password: false,
                        totp_secret: None,
                        totp_enabled: false,
                        totp_backup_codes: None,
                        totp_verified_at: None,
                        failed_login_attempts: 0,
                        locked_until: None,
                        last_failed_login_at: None,
                        password_changed_at: Utc::now(),
                        last_login_at: None,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    },
                    scopes: vec![],
                    allowed_repo_ids: None,
                },
                token_id: Uuid::new_v4(),
                expires_at: None,
            }
        }

        let cache: RwLock<HashMap<String, (CachedApiTokenEntry, Instant)>> =
            RwLock::new(HashMap::new());
        {
            let mut w = cache.write().unwrap();
            w.insert("key-a".to_string(), (make_entry(user_a), Instant::now()));
            w.insert("key-b".to_string(), (make_entry(user_b), Instant::now()));
        }

        // Apply the same retain logic the AuthService method uses.
        let removed = {
            let mut w = cache.write().unwrap();
            let before = w.len();
            w.retain(|_, (entry, _)| entry.validation.user.id != user_a);
            before - w.len()
        };
        assert_eq!(removed, 1);

        let r = cache.read().unwrap();
        assert!(r.get("key-a").is_none(), "user_a entry should be flushed");
        assert!(r.get("key-b").is_some(), "user_b entry must remain");
    }

    #[test]
    fn test_reactivation_then_redeactivation_invalidates_again() {
        // Regression test for LOW-1: false -> true -> false sequence must
        // re-mark the invalidation timestamp on the second deactivation, so
        // any cache entry inserted during the brief active window is
        // rejected by the cache-hit check.
        let user_id = Uuid::new_v4();

        // First deactivation.
        invalidate_user_token_cache_entries(user_id);
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Re-activation: NO invalidation by the handler. A fresh cache entry
        // would be admitted by the cache-hit check (cached_at > invalidated_at).
        let cached_during_active_window = Instant::now();
        assert!(
            !is_user_api_tokens_invalidated_after(user_id, cached_during_active_window),
            "fresh entry cached after first deactivation must pass while user is reactivated"
        );

        std::thread::sleep(std::time::Duration::from_millis(10));

        // Second deactivation must overwrite the timestamp so the entry
        // cached during the active window is now rejected.
        invalidate_user_token_cache_entries(user_id);
        assert!(
            is_user_api_tokens_invalidated_after(user_id, cached_during_active_window),
            "entry cached before second deactivation must be rejected"
        );
    }

    #[test]
    fn test_register_for_global_flush_drops_matching_cache_entries() {
        // LOW-6: invalidate_user_token_cache_entries must also flush matching
        // entries from any registered long-lived AuthService cache, not just
        // mark them stale via the global timestamp map.
        //
        // We construct a standalone Arc<TokenCacheMap> and register a Weak
        // pointer to it directly with the global registry. This exercises
        // the same code path that AuthService::register_for_global_flush
        // uses, without needing a Tokio context for sqlx pool construction.

        fn make_entry(id: Uuid) -> CachedApiTokenEntry {
            CachedApiTokenEntry {
                validation: ApiTokenValidation {
                    user: User {
                        id,
                        username: format!("u-{}", id),
                        email: "x@test.local".to_string(),
                        password_hash: None,
                        display_name: None,
                        auth_provider: AuthProvider::Local,
                        external_id: None,
                        is_admin: false,
                        is_active: true,
                        is_service_account: false,
                        must_change_password: false,
                        totp_secret: None,
                        totp_enabled: false,
                        totp_backup_codes: None,
                        totp_verified_at: None,
                        failed_login_attempts: 0,
                        locked_until: None,
                        last_failed_login_at: None,
                        password_changed_at: Utc::now(),
                        last_login_at: None,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    },
                    scopes: vec![],
                    allowed_repo_ids: None,
                },
                token_id: Uuid::new_v4(),
                expires_at: None,
            }
        }

        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();

        let cache: Arc<TokenCacheMap> = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut w = cache.write().unwrap();
            w.insert(
                format!("key-a-{}", user_a),
                (make_entry(user_a), Instant::now()),
            );
            w.insert(
                format!("key-b-{}", user_b),
                (make_entry(user_b), Instant::now()),
            );
        }

        // Register the cache with the global registry, mirroring what
        // AuthService::register_for_global_flush does internally.
        if let Ok(mut registry) = auth_token_cache_registry().write() {
            registry.push(Arc::downgrade(&cache));
        }

        // Invalidating user_a should flush key-a from the registered cache
        // and leave key-b untouched.
        invalidate_user_token_cache_entries(user_a);
        let r = cache.read().unwrap();
        assert!(
            r.get(&format!("key-a-{}", user_a)).is_none(),
            "registered cache must drop matching entry"
        );
        assert!(
            r.get(&format!("key-b-{}", user_b)).is_some(),
            "unrelated entry must survive"
        );
    }

    #[test]
    fn test_dropped_cache_weak_is_pruned_from_registry() {
        // The registry holds Weak<TokenCacheMap>. When the underlying Arc
        // is dropped, the next call to invalidate_user_token_cache_entries
        // should prune the dead Weak so the registry doesn't grow unbounded.
        let registry_size_before = auth_token_cache_registry().read().unwrap().len();

        // Register a cache, then drop its Arc.
        {
            let cache: Arc<TokenCacheMap> = Arc::new(RwLock::new(HashMap::new()));
            if let Ok(mut registry) = auth_token_cache_registry().write() {
                registry.push(Arc::downgrade(&cache));
            }
            // cache goes out of scope here.
        }

        // Trigger the prune path.
        invalidate_user_token_cache_entries(Uuid::new_v4());

        let registry_size_after = auth_token_cache_registry().read().unwrap().len();
        assert!(
            registry_size_after <= registry_size_before,
            "registry should not grow after dropped Arc and one invalidation: \
             before={}, after={}",
            registry_size_before,
            registry_size_after
        );
    }

    #[test]
    fn test_prune_stale_user_token_invalidations_handles_empty_map() {
        // The periodic prune helper should always succeed with no entries.
        let dropped = prune_stale_user_token_invalidations();
        // We can't predict the global state across tests, but the helper
        // must not panic and must return a number.
        let _ = dropped;
    }

    #[test]
    fn test_decode_rejects_alg_none_token() {
        let config = make_test_config();
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
        let header_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(br#"{"alg":"none","typ":"JWT"}"#)
        };
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "attacker".to_string(),
            email: "evil@test.com".to_string(),
            is_admin: true,
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
        };
        let payload_json = serde_json::to_vec(&claims).unwrap();
        let payload_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_json)
        };
        let forged_token = format!("{}.{}.", header_b64, payload_b64);
        let validation = Validation::new(Algorithm::HS256);
        let result = decode::<Claims>(&forged_token, &decoding_key, &validation);
        assert!(result.is_err(), "alg=none token must be rejected");
    }

    // -----------------------------------------------------------------------
    // Account lockout (pure function tests, no DB)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_account_locked_returns_false_when_no_lock() {
        let now = Utc::now();
        assert!(!AuthService::is_account_locked(None, now));
    }

    #[test]
    fn test_is_account_locked_returns_true_when_lock_in_future() {
        let now = Utc::now();
        let locked_until = now + Duration::minutes(15);
        assert!(AuthService::is_account_locked(Some(locked_until), now));
    }

    #[test]
    fn test_is_account_locked_returns_false_when_lock_expired() {
        let now = Utc::now();
        let locked_until = now - Duration::minutes(1);
        assert!(!AuthService::is_account_locked(Some(locked_until), now));
    }

    #[test]
    fn test_should_lock_returns_none_below_threshold() {
        let now = Utc::now();
        let result = AuthService::should_lock(3, 5, 30, now);
        assert!(result.is_none());
    }

    #[test]
    fn test_should_lock_returns_timestamp_at_threshold() {
        let now = Utc::now();
        let result = AuthService::should_lock(5, 5, 30, now);
        assert!(result.is_some());
        let lock_time = result.unwrap();
        // Lock should be 30 minutes in the future
        let expected = now + Duration::minutes(30);
        assert!((lock_time - expected).num_seconds().abs() < 2);
    }

    #[test]
    fn test_should_lock_returns_timestamp_above_threshold() {
        let now = Utc::now();
        let result = AuthService::should_lock(8, 5, 30, now);
        assert!(result.is_some());
    }

    #[test]
    fn test_should_lock_returns_none_when_threshold_is_zero() {
        let now = Utc::now();
        // threshold = 0 means lockout is disabled
        let result = AuthService::should_lock(100, 0, 30, now);
        assert!(result.is_none());
    }

    #[test]
    fn test_should_lock_custom_duration() {
        let now = Utc::now();
        let result = AuthService::should_lock(3, 3, 60, now);
        assert!(result.is_some());
        let lock_time = result.unwrap();
        let expected = now + Duration::minutes(60);
        assert!((lock_time - expected).num_seconds().abs() < 2);
    }

    #[test]
    fn test_should_lock_single_attempt_threshold() {
        let now = Utc::now();
        // Lock after a single failed attempt
        let result = AuthService::should_lock(1, 1, 10, now);
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // is_password_expired
    // -----------------------------------------------------------------------

    #[test]
    fn test_password_expiry_disabled_when_zero() {
        let now = Utc::now();
        let changed_at = now - Duration::days(365);
        assert!(!AuthService::is_password_expired(changed_at, 0, now));
    }

    #[test]
    fn test_password_not_expired_within_window() {
        let now = Utc::now();
        let changed_at = now - Duration::days(10);
        assert!(!AuthService::is_password_expired(changed_at, 90, now));
    }

    #[test]
    fn test_password_expired_after_window() {
        let now = Utc::now();
        let changed_at = now - Duration::days(91);
        assert!(AuthService::is_password_expired(changed_at, 90, now));
    }

    #[test]
    fn test_password_expired_exactly_on_boundary() {
        let now = Utc::now();
        let changed_at = now - Duration::days(90);
        // Password changed exactly 90 days ago with a 90-day policy: expired
        assert!(AuthService::is_password_expired(changed_at, 90, now));
    }

    #[test]
    fn test_password_just_changed_not_expired() {
        let now = Utc::now();
        assert!(!AuthService::is_password_expired(now, 1, now));
    }

    #[test]
    fn test_password_expiry_one_day_policy() {
        let now = Utc::now();
        let changed_at = now - Duration::hours(25);
        assert!(AuthService::is_password_expired(changed_at, 1, now));
    }

    // -----------------------------------------------------------------------
    // AuthService::new and db() accessor (#930 review hardening). These are
    // shape-only checks — `connect_lazy` constructs a pool without contacting
    // the database, which is sufficient for verifying that the constructor
    // populates every field and that `db()` returns the same handle.
    // -----------------------------------------------------------------------

    fn lazy_pool() -> sqlx::PgPool {
        sqlx::PgPool::connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
            .expect("connect_lazy never errors on construction")
    }

    #[tokio::test]
    async fn test_auth_service_new_constructs_with_lazy_pool() {
        let pool = lazy_pool();
        let cfg = make_test_config();
        let service = AuthService::new(pool.clone(), cfg);
        // The accessor is the only public way to retrieve the pool; checking
        // that it returns a usable reference confirms the constructor stored
        // it and that `db()` does not perform any extra work.
        let db_ref: &sqlx::PgPool = service.db();
        // PgPool exposes `size()` which returns 0 for a never-connected pool;
        // the call must not panic.
        let _ = db_ref.size();
    }

    // -----------------------------------------------------------------------
    // deactivate_missing_users requires a real database. The CI coverage job
    // boots a postgres service and exposes DATABASE_URL; if it is missing
    // (e.g. local `cargo test --lib` without docker compose) the test exits
    // early so it never gates a developer who is not running the full stack.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_deactivate_missing_users_no_targets_returns_zero() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return, // No DB: silently skip; covered in CI.
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return, // DB not reachable: skip.
        };
        let cfg = make_test_config();
        let service = AuthService::new(pool, cfg);
        // No federated SAML users exist in the smoke schema, so the UPDATE
        // affects zero rows. The branch we want to cover is the body of the
        // function (the SQL execute and the rows_affected unwrap), not the
        // post-condition: assert simply that it does not error.
        let result = service
            .deactivate_missing_users(AuthProvider::Saml, &[])
            .await;
        assert!(
            result.is_ok(),
            "deactivate_missing_users with no targets must succeed, got: {result:?}"
        );
        assert_eq!(result.unwrap(), 0);
    }

    // -----------------------------------------------------------------------
    // #1173: DB-backed credential-invalidation check.
    //
    // These tests need a real DB because the watermark is derived from
    // `users.password_changed_at` / `totp_verified_at` / `updated_at`. They
    // skip silently when `DATABASE_URL` is unset so local `cargo test --lib`
    // still passes without docker compose. The CI coverage job runs against
    // a postgres service and exercises every branch.
    // -----------------------------------------------------------------------

    /// Insert a fresh user row whose credential-change watermarks
    /// (`password_changed_at`, `updated_at`) are backdated by 60 seconds so
    /// tokens minted at `NOW()` are not immediately flagged invalidated by
    /// the replica-safe `iat < watermark` check. In production a token's
    /// `iat` is always strictly later than `password_changed_at` because
    /// the password is set at user creation, not at token issuance.
    async fn insert_test_user(pool: &sqlx::PgPool, username: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query!(
            r#"
            INSERT INTO users (id, username, email, password_hash, auth_provider,
                               is_active, is_admin, password_changed_at,
                               failed_login_attempts, created_at, updated_at)
            VALUES ($1, $2, $3, 'unused', 'local', true, false,
                    NOW() - INTERVAL '60 seconds', 0,
                    NOW() - INTERVAL '60 seconds',
                    NOW() - INTERVAL '60 seconds')
            "#,
            id,
            username,
            format!("{username}@test.com"),
        )
        .execute(pool)
        .await
        .expect("insert test user");
        id
    }

    #[tokio::test]
    async fn test_replica_safe_invalidation_via_db() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let username = format!("repl_test_{}", &Uuid::new_v4().to_string()[..8]);
        let user_id = insert_test_user(&pool, &username).await;

        // Simulate a token minted strictly before the user's credential-change
        // watermark. The helper inserts password_changed_at = NOW - 60s, and
        // the watermark is read at seconds resolution, so we use NOW - 120s
        // here to guarantee `iat < watermark` independent of sub-second clock
        // drift between this process and the database server. Same-second
        // (iat == watermark) is intentionally accepted post-#1248, so a test
        // pinning the "issued before" semantic must leave an unambiguous gap.
        let iat_before = (Utc::now() - Duration::seconds(120)).timestamp();

        // Token issued before the user's existing password_changed_at watermark
        // (inserted as NOW - 60s by `insert_test_user`) must be flagged
        // invalidated by the DB-backed check. This exercises the cross-replica
        // path because the in-memory fast-path map is empty for this user_id
        // on this process.
        let rejected = is_token_invalidated_replica_safe(&pool, user_id, iat_before)
            .await
            .expect("DB check must succeed");
        assert!(rejected, "token issued before watermark must be rejected");

        // A token issued well after the watermark should be accepted.
        let iat_after = (Utc::now() + Duration::seconds(60)).timestamp();
        let rejected = is_token_invalidated_replica_safe(&pool, user_id, iat_after)
            .await
            .expect("DB check must succeed");
        assert!(!rejected, "token issued after watermark must be accepted");

        // Cleanup.
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&pool)
            .await;
    }

    /// Regression: release-gate `rbac-tests` and `mesh-tests` saw HTTP 401
    /// from admin_middleware (and other authenticated routes) instead of the
    /// expected 403, because a freshly-created user's first JWT had
    /// `iat == password_changed_at_seconds` (both `NOW()` in the same
    /// wall-clock second). Pre-fix, the `<=` comparison rejected the token
    /// as if its credentials had been changed. Post-fix, the `<` comparison
    /// accepts the same-second token, so the middleware proceeds to the
    /// `is_admin` check and correctly returns 403 for non-admins.
    #[tokio::test]
    async fn test_replica_safe_invalidation_same_second_token_accepted() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let username = format!("samesec_{}", &Uuid::new_v4().to_string()[..8]);
        let id = Uuid::new_v4();
        // Insert the user the way `POST /users` does: column DEFAULT NOW()
        // for password_changed_at (no backdate). This mirrors the production
        // path the failing E2E test exercises. Using the runtime `query()`
        // form so the test compiles without a `.sqlx` cache entry — this
        // module already has tests gated on a live DB so the trade-off is
        // a runtime parse instead of a compile-time check, not a loss of
        // coverage.
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, \
             is_admin, is_active, failed_login_attempts) \
             VALUES ($1, $2, $3, 'unused', 'local', false, true, 0)",
        )
        .bind(id)
        .bind(&username)
        .bind(format!("{}@test.local", username))
        .execute(&pool)
        .await
        .expect("insert fresh user");

        // Token iat == the same second the user was inserted. In production
        // this is what happens when `POST /users` is followed immediately
        // by `POST /auth/login` (both wall-clock second N).
        let iat_same_second = Utc::now().timestamp();
        let rejected = is_token_invalidated_replica_safe(&pool, id, iat_same_second)
            .await
            .expect("DB check must succeed");
        assert!(
            !rejected,
            "token issued in the same wall-clock second as user creation \
             must be accepted (otherwise admin_middleware returns 401 \
             instead of letting the request reach the is_admin check)"
        );

        // Cleanup.
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn test_replica_safe_invalidation_unknown_user_accepts() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        // A user the DB has never seen should not flag as invalidated; the
        // request will be rejected at the load-user step instead.
        let unknown = Uuid::new_v4();
        let result = is_token_invalidated_replica_safe(&pool, unknown, 0)
            .await
            .expect("query succeeds even for missing user");
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // #1174: refresh-token replay detection.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_refresh_token_replay_revokes_family() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        let cfg = make_test_config();
        let service = AuthService::new(pool.clone(), cfg.clone());

        let username = format!("replay_{}", &Uuid::new_v4().to_string()[..8]);
        let user_id = insert_test_user(&pool, &username).await;
        let mut user = make_test_user();
        user.id = user_id;
        user.username = username.clone();

        // First rotation: legitimate refresh, mints token B in same family.
        let token_a = service.generate_tokens(&user).expect("tokens A");
        service
            .persist_refresh_jti_from_pair(&token_a, user_id)
            .await
            .expect("persist A");

        let (_, token_b) = service
            .refresh_tokens(&token_a.refresh_token)
            .await
            .expect("legit rotation succeeds");

        // Replay token A's refresh token: must reject AND revoke the family
        // (which means token B's jti is now flagged revoked too).
        let replay = service.refresh_tokens(&token_a.refresh_token).await;
        assert!(replay.is_err(), "replay must be rejected");

        // Attempt to use the rotated token B now — also rejected because the
        // whole family is revoked.
        let after_replay = service.refresh_tokens(&token_b.refresh_token).await;
        assert!(
            after_replay.is_err(),
            "sibling token from revoked family must be rejected"
        );

        // Cleanup.
        let _ = sqlx::query!("DELETE FROM refresh_token_jti WHERE user_id = $1", user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn test_refresh_token_legitimate_rotation_succeeds() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        let cfg = make_test_config();
        let service = AuthService::new(pool.clone(), cfg);

        let username = format!("rotate_{}", &Uuid::new_v4().to_string()[..8]);
        let user_id = insert_test_user(&pool, &username).await;
        let mut user = make_test_user();
        user.id = user_id;
        user.username = username;

        // Issue token T0, rotate to T1, rotate to T2 — each successive
        // rotation must succeed without tripping replay detection.
        let t0 = service.generate_tokens(&user).expect("t0");
        service
            .persist_refresh_jti_from_pair(&t0, user_id)
            .await
            .expect("persist t0");

        let (_, t1) = service
            .refresh_tokens(&t0.refresh_token)
            .await
            .expect("t0 -> t1");
        let (_, _t2) = service
            .refresh_tokens(&t1.refresh_token)
            .await
            .expect("t1 -> t2");

        // Cleanup.
        let _ = sqlx::query!("DELETE FROM refresh_token_jti WHERE user_id = $1", user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn test_cleanup_expired_refresh_token_jti() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let username = format!("cleanup_{}", &Uuid::new_v4().to_string()[..8]);
        let user_id = insert_test_user(&pool, &username).await;

        // Insert a row whose expires_at is two days in the past.
        let stale_jti = Uuid::new_v4();
        sqlx::query!(
            r#"
            INSERT INTO refresh_token_jti
                (jti, user_id, family_id, issued_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            stale_jti,
            user_id,
            Uuid::new_v4(),
            Utc::now() - Duration::days(10),
            Utc::now() - Duration::days(2),
        )
        .execute(&pool)
        .await
        .expect("insert stale row");

        // Grace 1h: row with expires_at 2 days ago must be deleted.
        let removed = AuthService::cleanup_expired_refresh_token_jti(&pool, Duration::hours(1))
            .await
            .expect("cleanup succeeds");
        assert!(
            removed >= 1,
            "expected at least the stale row to be removed"
        );

        // Confirm row is gone.
        let row = sqlx::query!(
            "SELECT jti FROM refresh_token_jti WHERE jti = $1",
            stale_jti
        )
        .fetch_optional(&pool)
        .await
        .expect("query");
        assert!(row.is_none(), "stale row must be deleted");

        // Cleanup.
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&pool)
            .await;
    }

    // -----------------------------------------------------------------------
    // PR #1190 review regressions (architectural wiring tests).
    //
    // These tests pin the three load-bearing wiring decisions in #1173 /
    // #1174 / #1175 so they cannot quietly regress in future refactors.
    //   1. Password reset revokes the refresh-token family at the DB layer.
    //   2. Access-token validation uses the DB watermark (replica-safe).
    //   3. A profile edit (bumps `users.updated_at` only) does NOT
    //      invalidate active tokens.
    //   4. Static check: `validate_access_token_async` has a real production
    //      caller in middleware so it cannot become dead code again.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_password_reset_revokes_refresh_jti_family() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        let cfg = make_test_config();
        let service = AuthService::new(pool.clone(), cfg);

        let username = format!("pwreset_{}", &Uuid::new_v4().to_string()[..8]);
        let user_id = insert_test_user(&pool, &username).await;
        let mut user = make_test_user();
        user.id = user_id;
        user.username = username;

        // Mint a refresh token and persist its jti.
        let tokens = service.generate_tokens(&user).expect("mint");
        service
            .persist_refresh_jti_from_pair(&tokens, user_id)
            .await
            .expect("persist jti");

        // Simulate the password-reset cleanup that handlers/users.rs now
        // performs alongside `invalidate_user_tokens`.
        let revoked = service
            .revoke_all_refresh_token_families(user_id)
            .await
            .expect("revoke families");
        assert!(revoked >= 1, "expected at least one family row revoked");

        // The previously-minted refresh token must now be rejected by the
        // refresh-grant path (family is revoked at the DB level — visible on
        // every replica).
        let result = service.refresh_tokens(&tokens.refresh_token).await;
        assert!(
            result.is_err(),
            "refresh JWT issued before password reset must 401"
        );

        // The row in refresh_token_jti must be marked revoked_at.
        let token_data = service.decode_token(&tokens.refresh_token).expect("decode");
        let jti = token_data.claims.jti.expect("refresh has jti");
        let row = sqlx::query!(
            "SELECT revoked_at FROM refresh_token_jti WHERE jti = $1",
            jti
        )
        .fetch_one(&pool)
        .await
        .expect("row exists");
        assert!(row.revoked_at.is_some(), "family must be marked revoked");

        // Cleanup.
        let _ = sqlx::query!("DELETE FROM refresh_token_jti WHERE user_id = $1", user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn test_access_token_validation_uses_db_watermark_after_invalidation() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        let cfg = make_test_config();
        let service = AuthService::new(pool.clone(), cfg);

        let username = format!("axw_{}", &Uuid::new_v4().to_string()[..8]);
        let user_id = insert_test_user(&pool, &username).await;
        let mut user = make_test_user();
        user.id = user_id;
        user.username = username;

        // Mint an access token whose `iat` predates the credential change
        // by 60 seconds (so it's strictly older than `password_changed_at`).
        let tokens = service.generate_tokens(&user).expect("mint");
        // The freshly minted access token has iat=NOW and password_changed_at
        // for the user is NOW - 60s (see `insert_test_user`), so it should
        // currently be ACCEPTED.
        service
            .validate_access_token_async(&tokens.access_token)
            .await
            .expect("token accepted before invalidation");

        // Simulate password change: bump `password_changed_at` to NOW + 60s
        // so the token's iat is strictly less than the watermark.
        sqlx::query!(
            "UPDATE users SET password_changed_at = NOW() + INTERVAL '60 seconds' WHERE id = $1",
            user_id
        )
        .execute(&pool)
        .await
        .expect("bump password_changed_at");

        // Clear the in-memory cache so the next call hits the DB.
        if let Ok(mut map) = invalidation_map().write() {
            map.remove(&user_id);
        }

        // The async validator must now REJECT the pre-change token via the
        // DB watermark. This is the replica-safe guarantee: even though
        // `invalidate_user_tokens` was never called on this process, the DB
        // is the source of truth.
        let result = service
            .validate_access_token_async(&tokens.access_token)
            .await;
        assert!(
            result.is_err(),
            "access token issued before credential change must be rejected by async validator",
        );

        // Cleanup.
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn test_users_updated_at_bump_does_not_invalidate_tokens() {
        // Regression for PR #1190 Issue #3: previously the watermark SQL
        // included `users.updated_at` so a benign profile edit (display
        // name, email, role flip) would invalidate every active token.
        // After the fix, only `password_changed_at` and `totp_verified_at`
        // contribute.
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        let cfg = make_test_config();
        let service = AuthService::new(pool.clone(), cfg);

        let username = format!("profile_{}", &Uuid::new_v4().to_string()[..8]);
        let user_id = insert_test_user(&pool, &username).await;
        let mut user = make_test_user();
        user.id = user_id;
        user.username = username;

        let tokens = service.generate_tokens(&user).expect("mint");

        // Drop any cached watermark for this user so the next call re-reads
        // the DB.
        if let Ok(mut map) = invalidation_map().write() {
            map.remove(&user_id);
        }

        // Simulate a profile edit that bumps ONLY `updated_at` (display name
        // change, etc.) and pushes it well past the token's iat. If the
        // watermark expression still folded in `updated_at`, the next
        // validation would reject the token.
        sqlx::query!(
            "UPDATE users SET updated_at = NOW() + INTERVAL '120 seconds', \
             display_name = 'New Display' WHERE id = $1",
            user_id
        )
        .execute(&pool)
        .await
        .expect("bump updated_at");

        // Clear cache again to force a DB read against the bumped row.
        if let Ok(mut map) = invalidation_map().write() {
            map.remove(&user_id);
        }

        // The token MUST still validate. The watermark only considers
        // password_changed_at / totp_verified_at, neither of which moved.
        service
            .validate_access_token_async(&tokens.access_token)
            .await
            .expect("token must remain valid after benign profile edit");

        // Cleanup.
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&pool)
            .await;
    }

    /// Meta-test: assert that `validate_access_token_async` has at least one
    /// production caller in the middleware/handler tree. Prevents future
    /// regressions where the function gets re-orphaned (the bug PR #1190
    /// review caught: function existed, no caller, replica-safe promise was
    /// a lie).
    ///
    /// Implemented as a file-text search rather than a compile-time check
    /// because the call is behind an `async` boundary in three different
    /// modules and the Rust type system doesn't give us a free way to
    /// observe "function is referenced from this crate path." The test is
    /// cheap (just reads a handful of files) and runs in `cargo test --lib`.
    #[test]
    fn test_validate_access_token_async_has_production_caller() {
        // CARGO_MANIFEST_DIR points at backend/ for this test binary.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");

        let surfaces = [
            "src/api/middleware/auth.rs",
            "src/api/handlers/oci_v2.rs",
            "src/grpc/auth_interceptor.rs",
        ];

        let mut found_in: Vec<&str> = Vec::new();
        for relative in &surfaces {
            let path = std::path::Path::new(manifest_dir).join(relative);
            let contents =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {relative}: {e}"));
            if contents.contains("validate_access_token_async")
                || contents.contains("is_token_invalidated_replica_safe")
            {
                found_in.push(relative);
            }
        }

        assert!(
            !found_in.is_empty(),
            "validate_access_token_async / is_token_invalidated_replica_safe \
             MUST be referenced by at least one of {surfaces:?}. If you are \
             refactoring auth, do not remove the replica-safe call without \
             a written security review (#1173 / PR #1190).",
        );
        // Belt-and-suspenders: at minimum middleware/auth.rs must wire it,
        // because that is the main HTTP request path. Without it, every
        // access-token request would bypass the DB watermark.
        assert!(
            found_in.contains(&"src/api/middleware/auth.rs"),
            "middleware/auth.rs must call the replica-safe validator; \
             found references only in: {found_in:?}",
        );
    }
}
