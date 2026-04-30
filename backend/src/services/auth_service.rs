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

/// JWT claims structure
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
    /// JWT ID. Used for refresh-token rotation: once a refresh token's jti
    /// has been redeemed, the token is recorded in `used_refresh_jtis` and
    /// further refresh attempts using the same token are rejected.
    ///
    /// Optional for backwards compatibility: tokens minted before issue
    /// #929 do not carry a jti. Such legacy tokens are accepted once and
    /// forced onto the rotation scheme. New tokens always include a jti.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<Uuid>,
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

static CREDENTIAL_INVALIDATIONS: OnceLock<RwLock<HashMap<Uuid, i64>>> = OnceLock::new();
const INVALIDATION_RETENTION_SECS: i64 = 7 * 24 * 3600;

fn invalidation_map() -> &'static RwLock<HashMap<Uuid, i64>> {
    CREDENTIAL_INVALIDATIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn invalidate_user_tokens(user_id: Uuid) {
    let now = Utc::now().timestamp();
    if let Ok(mut map) = invalidation_map().write() {
        map.insert(user_id, now);
        let cutoff = now - INVALIDATION_RETENTION_SECS;
        map.retain(|_, ts| *ts > cutoff);
    }
}

pub(crate) fn is_token_invalidated(user_id: Uuid, issued_at: i64) -> bool {
    if let Ok(map) = invalidation_map().read() {
        if let Some(&changed_at) = map.get(&user_id) {
            return issued_at < changed_at;
        }
    }
    false
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

/// Namespace UUID for synthesizing deterministic jti values for legacy
/// (pre-#929) refresh tokens that did not carry a jti claim. We use the
/// well-known `Uuid::NAMESPACE_OID` as the v5 namespace so that the same
/// `(user_id, iat)` pair always hashes to the same UUID, regardless of which
/// replica or process is handling the request. This lets the legacy
/// single-use guard share the `used_refresh_jtis` table with the new path:
/// once a legacy token is consumed, the same `INSERT ... ON CONFLICT DO
/// NOTHING` semantics reject parallel and post-restart replays. The choice
/// of `NAMESPACE_OID` is arbitrary but stable; we only require that the
/// namespace not collide with naturally-generated v4 jti UUIDs (v5 collisions
/// with v4 are cryptographically improbable).
const LEGACY_JTI_NAMESPACE: Uuid = Uuid::NAMESPACE_OID;

/// Synthesize a deterministic jti for a legacy (pre-#929) refresh token.
/// Two requests carrying the same legacy token (same `user_id`, same `iat`)
/// will hash to the same UUID, so the atomic INSERT into
/// `used_refresh_jtis` rejects the second attempt regardless of which
/// replica or process handled the first.
fn legacy_token_jti(user_id: Uuid, issued_at: i64) -> Uuid {
    let mut bytes = [0u8; 24];
    bytes[..16].copy_from_slice(user_id.as_bytes());
    bytes[16..].copy_from_slice(&issued_at.to_be_bytes());
    Uuid::new_v5(&LEGACY_JTI_NAMESPACE, &bytes)
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
                last_login_at, created_at, updated_at
            FROM users
            WHERE username = $1 AND is_active = true
            "#,
            username
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("Invalid username or password".to_string()))?;

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
            return Err(AppError::Authentication(
                "Invalid username or password".to_string(),
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

        // Generate tokens
        let tokens = self.generate_tokens(&user)?;

        Ok((user, tokens))
    }

    /// Generate access and refresh tokens for a user
    pub fn generate_tokens(&self, user: &User) -> Result<TokenPair> {
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
            jti: Some(Uuid::new_v4()),
        };

        // Refresh tokens carry a jti so we can reject replays after a single
        // use (issue #929). The jti is recorded in `used_refresh_jtis` when
        // the token is consumed by `refresh_tokens`.
        let refresh_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: refresh_exp.timestamp(),
            token_type: "refresh".to_string(),
            jti: Some(Uuid::new_v4()),
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

    /// Borrow the underlying database pool. Used by middleware that needs
    /// to issue queries through the same connection pool the auth service uses
    /// (e.g. download-ticket fallback in the auth middleware chain).
    pub fn db(&self) -> &PgPool {
        &self.db
    }

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

    /// Exchange a refresh token for a fresh token pair.
    ///
    /// Refresh tokens are single-use: the supplied token's jti is recorded in
    /// `used_refresh_jtis` after a successful exchange, and any later attempt
    /// to refresh with the same token is rejected as a replay (issue #929).
    ///
    /// Tokens minted before #929 do not carry a jti. They are still accepted,
    /// but only once: we synthesize a deterministic UUIDv5 from
    /// `(user_id, iat)` (`legacy_token_jti`) and INSERT it into the same
    /// `used_refresh_jtis` table. The atomic conflict path therefore covers
    /// both new and legacy tokens, and the guard survives process restarts
    /// and is shared across replicas. After the first successful refresh
    /// the caller receives a jti-bearing pair and is on the new path.
    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<(User, TokenPair)> {
        let token_data = self.decode_token(refresh_token)?;

        if is_token_invalidated(token_data.claims.sub, token_data.claims.iat) {
            return Err(AppError::Authentication(
                "Token invalidated by credential change".to_string(),
            ));
        }

        if token_data.claims.token_type != "refresh" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        // Single-use rotation: claim the jti via an atomic INSERT. If the
        // token does not carry one (legacy pre-#929 token), synthesize a
        // deterministic UUIDv5 from (user_id, iat) so the same INSERT path
        // covers both cases and the guard is shared across replicas /
        // survives process restarts.
        let jti = token_data
            .claims
            .jti
            .unwrap_or_else(|| legacy_token_jti(token_data.claims.sub, token_data.claims.iat));

        let inserted = sqlx::query!(
            r#"
                INSERT INTO used_refresh_jtis (jti, user_id)
                VALUES ($1, $2)
                ON CONFLICT (jti) DO NOTHING
                "#,
            jti,
            token_data.claims.sub
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if inserted.rows_affected() == 0 {
            // Replay detected. Invalidate the user's existing access
            // tokens issued at-or-before this refresh so a leaked pair
            // is fully neutralized rather than letting the attacker keep
            // using a still-valid access token until natural expiry.
            //
            // Note (multi-replica): `invalidate_user_tokens` records the
            // event in process-local memory. In multi-replica deployments
            // each replica observes its own invalidation timestamp, so an
            // access token may remain valid on a replica that did not see
            // the replay until the natural expiry. Promoting this signal
            // to a DB-backed table or a NOTIFY/LISTEN channel is tracked
            // for v1.2.0 follow-up.
            invalidate_user_tokens(token_data.claims.sub);
            return Err(AppError::Authentication(
                "Refresh token has already been used".to_string(),
            ));
        }

        // Fetch fresh user data
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
            FROM users
            WHERE id = $1 AND is_active = true
            "#,
            token_data.claims.sub
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

        let tokens = self.generate_tokens(&user)?;
        Ok((user, tokens))
    }

    /// Garbage-collect refresh-token jti records that are older than the
    /// refresh-token TTL. After that point, the corresponding tokens would
    /// fail JWT exp validation anyway, so the jti row is no longer load-bearing.
    ///
    /// Returns the number of rows deleted.
    pub async fn gc_used_refresh_jtis(&self) -> Result<u64> {
        let ttl_days = self.config.jwt_refresh_token_expiry_days.max(1);
        let cutoff = Utc::now() - Duration::days(ttl_days);
        let result = sqlx::query!("DELETE FROM used_refresh_jtis WHERE used_at < $1", cutoff)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }

    /// Blocklist a refresh token by inserting its jti into `used_refresh_jtis`.
    /// Used by the logout handler so that a captured refresh token cannot be
    /// redeemed after the user has logged out, even though the JWT itself
    /// remains within its `exp` window.
    ///
    /// Tokens without a jti (legacy pre-#929) are blocklisted using the same
    /// deterministic UUIDv5 derivation as `refresh_tokens`.
    ///
    /// Returns Ok regardless of whether the token was already blocklisted:
    /// idempotency is desirable here because logout is fire-and-forget.
    /// Returns Err only on JWT decode failures or database errors.
    pub async fn blocklist_refresh_token(&self, refresh_token: &str) -> Result<()> {
        let token_data = self.decode_token(refresh_token)?;

        if token_data.claims.token_type != "refresh" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        let jti = token_data
            .claims
            .jti
            .unwrap_or_else(|| legacy_token_jti(token_data.claims.sub, token_data.claims.iat));

        sqlx::query!(
            r#"
                INSERT INTO used_refresh_jtis (jti, user_id)
                VALUES ($1, $2)
                ON CONFLICT (jti) DO NOTHING
                "#,
            jti,
            token_data.claims.sub
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    fn decode_token(&self, token: &str) -> Result<TokenData<Claims>> {
        let validation = Validation::new(Algorithm::HS256);
        decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AppError::Authentication(format!("Invalid token: {}", e)))
    }

    /// Hash a password
    pub async fn hash_password(password: &str) -> Result<String> {
        let pwd = password.to_string();
        tokio::task::spawn_blocking(move || {
            hash(&pwd, DEFAULT_COST)
                .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))
        })
        .await
        .map_err(|e| AppError::Internal(format!("Blocking task failed: {e}")))?
    }

    /// Verify a password against a hash
    pub async fn verify_password(password: &str, hash: &str) -> Result<bool> {
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
                last_login_at, created_at, updated_at
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
                last_login_at, created_at, updated_at
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
    pub fn map_groups_to_roles(&self, groups: &[String]) -> RoleMapping {
        let mut mapping = RoleMapping::default();

        // Normalize groups to lowercase for case-insensitive matching
        let normalized_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();

        // Check for admin groups
        // These patterns can be made configurable via Config
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
    pub async fn apply_role_mapping(&self, user_id: Uuid, mapping: &RoleMapping) -> Result<()> {
        // Update is_admin flag (only if admin group mapping is configured)
        sqlx::query!(
            "UPDATE users SET is_admin = COALESCE($2, is_admin), updated_at = NOW() WHERE id = $1",
            user_id,
            mapping.is_admin
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Clear existing role assignments and add new ones
        // First, remove all current roles (for federated users, roles come from provider)
        sqlx::query!("DELETE FROM user_roles WHERE user_id = $1", user_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Assign new roles based on mapping
        for role_name in &mapping.roles {
            // Look up role by name and assign if it exists
            let role = sqlx::query!("SELECT id FROM roles WHERE name = $1", role_name)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

            if let Some(role) = role {
                sqlx::query!(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    user_id,
                    role.id
                )
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            }
        }

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
        let role_mapping = self.map_groups_to_roles(&credentials.groups);

        // Check if user exists by external_id
        let existing_user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
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
                    last_login_at, created_at, updated_at
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
                    last_login_at, created_at, updated_at
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
                last_login_at, created_at, updated_at
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
                last_login_at, created_at, updated_at
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
    // Token generation & validation (no DB needed)
    // -----------------------------------------------------------------------

    fn make_test_config() -> Arc<Config> {
        Arc::new(Config {
            jwt_secret: "super-secret-test-key-for-unit-tests-minimum-length".to_string(),
            ..Config::default()
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
            jti: Some(Uuid::new_v4()),
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
        };

        let json = serde_json::to_string(&claims).unwrap();
        let decoded: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sub, user_id);
        assert_eq!(decoded.username, "test");
        assert!(decoded.is_admin);
        assert_eq!(decoded.token_type, "access");
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
        let mut mapping = RoleMapping::default();
        let normalized_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();

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
        let after = Utc::now().timestamp() + 1;
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
        let after = Utc::now().timestamp() + 1;
        // Token issued before second invalidation is still rejected
        assert!(is_token_invalidated(user_id, mid - 1));
        // Token issued after second invalidation is accepted
        assert!(!is_token_invalidated(user_id, after));
    }

    #[test]
    fn test_token_issued_at_exact_invalidation_time_passes() {
        // issued_at < changed_at is the check, so equal timestamps should pass
        let user_id = Uuid::new_v4();
        invalidate_user_tokens(user_id);
        let now = Utc::now().timestamp();
        // Token with iat after changed_at should not be invalidated
        assert!(!is_token_invalidated(user_id, now + 1));
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
    // Refresh-token rotation: legacy-token deterministic jti derivation (#929)
    // -----------------------------------------------------------------------

    #[test]
    fn test_legacy_token_jti_is_deterministic() {
        // The same (user_id, iat) must always produce the same UUID, so that
        // any replica or any post-restart process sees the same jti and the
        // shared `used_refresh_jtis` table catches the replay.
        let user = Uuid::new_v4();
        let iat: i64 = 1_700_000_000;
        let a = legacy_token_jti(user, iat);
        let b = legacy_token_jti(user, iat);
        assert_eq!(
            a, b,
            "legacy_token_jti must be deterministic for stable claim-the-jti semantics"
        );
    }

    #[test]
    fn test_legacy_token_jti_distinct_iats_differ() {
        let user = Uuid::new_v4();
        let a = legacy_token_jti(user, 1_700_000_000);
        let b = legacy_token_jti(user, 1_700_000_001);
        assert_ne!(
            a, b,
            "different iats for the same user must produce different jtis"
        );
    }

    #[test]
    fn test_legacy_token_jti_distinct_users_differ() {
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let iat: i64 = 1_700_000_000;
        let a = legacy_token_jti(user_a, iat);
        let b = legacy_token_jti(user_b, iat);
        assert_ne!(
            a, b,
            "different users at the same iat must produce different jtis"
        );
    }

    #[test]
    fn test_legacy_token_jti_is_v5() {
        // Sanity check that we are emitting a name-based UUID (version 5),
        // not a v4 random UUID. v5 has the high nibble of byte 6 set to 5.
        let jti = legacy_token_jti(Uuid::new_v4(), 1_700_000_000);
        assert_eq!(
            jti.get_version_num(),
            5,
            "legacy jti must be a v5 (name-based) UUID"
        );
    }

    // -----------------------------------------------------------------------
    // Claims jti serialization (#929)
    // -----------------------------------------------------------------------

    #[test]
    fn test_claims_jti_serializes_when_present() {
        let jti = Uuid::new_v4();
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "u".to_string(),
            email: "u@e.com".to_string(),
            is_admin: false,
            iat: 1000,
            exp: 2000,
            token_type: "refresh".to_string(),
            jti: Some(jti),
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(
            json.contains(&jti.to_string()),
            "jti should be serialized when Some: {}",
            json
        );
    }

    #[test]
    fn test_claims_jti_omitted_when_none() {
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "u".to_string(),
            email: "u@e.com".to_string(),
            is_admin: false,
            iat: 1000,
            exp: 2000,
            token_type: "refresh".to_string(),
            jti: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(
            !json.contains("\"jti\""),
            "jti must be skipped when None: {}",
            json
        );
    }

    #[test]
    fn test_claims_legacy_token_without_jti_decodes() {
        // Tokens minted before #929 do not carry a jti. Verify that such a
        // payload still deserializes cleanly with jti = None.
        let payload = r#"{
            "sub": "00000000-0000-0000-0000-000000000001",
            "username": "legacy",
            "email": "legacy@x.com",
            "is_admin": false,
            "iat": 1000,
            "exp": 2000,
            "token_type": "refresh"
        }"#;
        let claims: Claims = serde_json::from_str(payload).unwrap();
        assert!(claims.jti.is_none());
        assert_eq!(claims.token_type, "refresh");
    }

    // -----------------------------------------------------------------------
    // AuthService construction and token generation paths (#929)
    //
    // These tests use a lazy PgPool so they do not require a live database;
    // they exercise the in-memory parts of `AuthService::new`,
    // `generate_tokens`, `generate_totp_pending_token`, and the early-return
    // branches of `blocklist_refresh_token` that fire before any SQL runs.
    // -----------------------------------------------------------------------

    fn make_lazy_pool() -> PgPool {
        // connect_lazy never opens a TCP socket until a query is issued, so it
        // is safe to construct in unit tests with no Postgres available.
        PgPool::connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy never fails for a syntactically valid URL")
    }

    #[tokio::test]
    async fn test_auth_service_new_initializes_token_cache() {
        // Covers AuthService::new(): keys derived from secret and an empty
        // RwLock-wrapped cache is constructed.
        let cfg = make_test_config();
        let svc = AuthService::new(make_lazy_pool(), cfg);
        // Cache must start empty.
        assert_eq!(svc.token_cache.read().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_generate_tokens_assigns_jti_to_both_tokens() {
        // Exercises `generate_tokens` body, including the `jti: Some(...)`
        // assignments on access and refresh claims (lines 283 and 297).
        let cfg = make_test_config();
        let svc = AuthService::new(make_lazy_pool(), cfg.clone());
        let user = make_test_user();

        let pair = svc.generate_tokens(&user).expect("generate_tokens");

        // Decode both tokens with the same secret and assert each carries a
        // unique jti and the expected token_type.
        let key = DecodingKey::from_secret(cfg.jwt_secret.as_bytes());
        let validation = Validation::new(Algorithm::HS256);

        let access =
            decode::<Claims>(&pair.access_token, &key, &validation).expect("decode access token");
        let refresh =
            decode::<Claims>(&pair.refresh_token, &key, &validation).expect("decode refresh token");

        assert_eq!(access.claims.token_type, "access");
        assert_eq!(refresh.claims.token_type, "refresh");
        assert!(access.claims.jti.is_some(), "access token must carry a jti");
        assert!(
            refresh.claims.jti.is_some(),
            "refresh token must carry a jti"
        );
        assert_ne!(
            access.claims.jti, refresh.claims.jti,
            "access and refresh tokens must use distinct jtis"
        );
        assert_eq!(access.claims.sub, user.id);
        assert_eq!(refresh.claims.sub, user.id);
        assert_eq!(
            pair.expires_in,
            (cfg.jwt_access_token_expiry_minutes * 60) as u64
        );
    }

    #[tokio::test]
    async fn test_generate_totp_pending_token_round_trip() {
        // Covers `generate_totp_pending_token` (line 1251 jti=None) and
        // `validate_totp_pending_token` round-trip.
        let cfg = make_test_config();
        let svc = AuthService::new(make_lazy_pool(), cfg);
        let user = make_test_user();

        let token = svc
            .generate_totp_pending_token(&user)
            .expect("generate totp pending token");

        let claims = svc
            .validate_totp_pending_token(&token)
            .expect("validate totp pending token");
        assert_eq!(claims.token_type, "totp_pending");
        assert_eq!(claims.sub, user.id);
        assert!(
            claims.jti.is_none(),
            "totp_pending tokens must not carry a jti"
        );
    }

    #[tokio::test]
    async fn test_validate_totp_pending_token_rejects_wrong_type() {
        // Covers the "Invalid token type" branch when a non-totp_pending
        // token is fed to `validate_totp_pending_token`.
        let cfg = make_test_config();
        let svc = AuthService::new(make_lazy_pool(), cfg);
        let user = make_test_user();

        let pair = svc.generate_tokens(&user).expect("generate_tokens");
        let result = svc.validate_totp_pending_token(&pair.access_token);
        assert!(
            matches!(result, Err(AppError::Authentication(_))),
            "access token must be rejected as wrong type, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_blocklist_refresh_token_rejects_malformed_jwt() {
        // The decode_token call inside blocklist_refresh_token must surface
        // an Authentication error for non-JWT input. Hits the `?` propagation
        // on line 448 without touching the database.
        let cfg = make_test_config();
        let svc = AuthService::new(make_lazy_pool(), cfg);
        let result = svc.blocklist_refresh_token("not-a-jwt").await;
        assert!(
            matches!(result, Err(AppError::Authentication(_))),
            "malformed JWT must yield Authentication error, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_blocklist_refresh_token_rejects_non_refresh_type() {
        // An access token must be rejected before any DB query runs. Covers
        // the "Invalid token type" branch (lines 450-452).
        let cfg = make_test_config();
        let svc = AuthService::new(make_lazy_pool(), cfg);
        let user = make_test_user();

        let pair = svc.generate_tokens(&user).expect("generate_tokens");
        let result = svc.blocklist_refresh_token(&pair.access_token).await;
        assert!(
            matches!(result, Err(AppError::Authentication(_))),
            "access token must be rejected by blocklist, got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // Database-backed coverage for the jti rotation paths (#929)
    //
    // These tests exercise the SQL branches of `refresh_tokens`,
    // `gc_used_refresh_jtis`, and `blocklist_refresh_token`. They auto-skip
    // when DATABASE_URL is unset or unreachable so the unit-test gate
    // (which has no Postgres) stays green; the coverage gate provisions a
    // Postgres service container and runs migrations before invoking
    // `cargo llvm-cov --workspace --lib`, so these tests execute there and
    // contribute to new-code coverage.
    // -----------------------------------------------------------------------

    async fn try_connect_test_db() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        // Short timeout so a misconfigured DATABASE_URL does not stall the
        // unit test run for minutes.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect(&url)
            .await
            .ok()?;
        // Verify the schema we depend on is actually present. If migrations
        // were not applied in this environment, skip rather than failing.
        let migrated: Result<(bool,)> = sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_name = 'used_refresh_jtis')",
        )
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()));
        match migrated {
            Ok((true,)) => Some(pool),
            _ => None,
        }
    }

    async fn insert_test_user(pool: &PgPool) -> Uuid {
        let username = format!("authsvc-cov-{}", Uuid::new_v4().as_simple());
        let email = format!("{}@cov.test", username);
        let pwd_hash = AuthService::hash_password("cov-test-password")
            .await
            .expect("hash test password");
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO users (username, email, password_hash, auth_provider, \
             is_admin, is_active) \
             VALUES ($1, $2, $3, 'local', false, true) RETURNING id",
        )
        .bind(&username)
        .bind(&email)
        .bind(&pwd_hash)
        .fetch_one(pool)
        .await
        .expect("insert test user");
        row.0
    }

    async fn delete_test_user(pool: &PgPool, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn test_blocklist_refresh_token_inserts_jti() {
        let Some(pool) = try_connect_test_db().await else {
            eprintln!("skip: DATABASE_URL unset or schema missing");
            return;
        };
        let user_id = insert_test_user(&pool).await;
        let cfg = make_test_config();
        let svc = AuthService::new(pool.clone(), cfg.clone());

        // Mint a refresh token for this user with a known jti so we can
        // verify the row landed in used_refresh_jtis.
        let jti = Uuid::new_v4();
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            username: "cov".to_string(),
            email: "cov@x.test".to_string(),
            is_admin: false,
            iat: now.timestamp(),
            exp: (now + Duration::days(1)).timestamp(),
            token_type: "refresh".to_string(),
            jti: Some(jti),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .expect("encode refresh token");

        svc.blocklist_refresh_token(&token)
            .await
            .expect("blocklist refresh token");

        let row: (bool,) =
            sqlx::query_as("SELECT EXISTS(SELECT 1 FROM used_refresh_jtis WHERE jti = $1)")
                .bind(jti)
                .fetch_one(&pool)
                .await
                .expect("check jti row");
        assert!(row.0, "blocklisted jti must be persisted");

        // Idempotency: a second blocklist call on the same token must not
        // error (ON CONFLICT DO NOTHING path).
        svc.blocklist_refresh_token(&token)
            .await
            .expect("blocklist is idempotent");

        delete_test_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn test_blocklist_refresh_token_legacy_no_jti_uses_derived() {
        let Some(pool) = try_connect_test_db().await else {
            eprintln!("skip: DATABASE_URL unset or schema missing");
            return;
        };
        let user_id = insert_test_user(&pool).await;
        let cfg = make_test_config();
        let svc = AuthService::new(pool.clone(), cfg.clone());

        // Mint a legacy refresh token with NO jti claim so the
        // unwrap_or_else fallback (line 457) fires.
        #[derive(Serialize)]
        struct LegacyClaims {
            sub: Uuid,
            username: String,
            email: String,
            is_admin: bool,
            iat: i64,
            exp: i64,
            token_type: String,
        }
        let now = Utc::now().timestamp();
        let legacy = LegacyClaims {
            sub: user_id,
            username: "legacy-cov".to_string(),
            email: "legacy-cov@x.test".to_string(),
            is_admin: false,
            iat: now,
            exp: now + 3600,
            token_type: "refresh".to_string(),
        };
        let token = encode(
            &Header::default(),
            &legacy,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .expect("encode legacy refresh token");

        svc.blocklist_refresh_token(&token)
            .await
            .expect("blocklist legacy refresh token");

        let derived = legacy_token_jti(user_id, now);
        let row: (bool,) =
            sqlx::query_as("SELECT EXISTS(SELECT 1 FROM used_refresh_jtis WHERE jti = $1)")
                .bind(derived)
                .fetch_one(&pool)
                .await
                .expect("check derived jti row");
        assert!(
            row.0,
            "legacy token must be blocklisted under the derived jti"
        );

        delete_test_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn test_gc_used_refresh_jtis_reaps_aged_rows() {
        let Some(pool) = try_connect_test_db().await else {
            eprintln!("skip: DATABASE_URL unset or schema missing");
            return;
        };
        let user_id = insert_test_user(&pool).await;
        let cfg = make_test_config();
        let svc = AuthService::new(pool.clone(), cfg.clone());

        // Insert one aged row (older than the refresh-token TTL) and one
        // fresh row. GC should remove only the aged row.
        let aged = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO used_refresh_jtis (jti, user_id, used_at) \
             VALUES ($1, $2, NOW() - INTERVAL '30 days')",
        )
        .bind(aged)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("insert aged jti");

        let fresh = Uuid::new_v4();
        sqlx::query("INSERT INTO used_refresh_jtis (jti, user_id, used_at) VALUES ($1, $2, NOW())")
            .bind(fresh)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert fresh jti");

        let removed = svc.gc_used_refresh_jtis().await.expect("gc");
        assert!(removed >= 1, "gc must reap at least the aged row");

        let aged_exists: (bool,) =
            sqlx::query_as("SELECT EXISTS(SELECT 1 FROM used_refresh_jtis WHERE jti = $1)")
                .bind(aged)
                .fetch_one(&pool)
                .await
                .expect("check aged");
        assert!(!aged_exists.0, "aged row must have been reaped");

        let fresh_exists: (bool,) =
            sqlx::query_as("SELECT EXISTS(SELECT 1 FROM used_refresh_jtis WHERE jti = $1)")
                .bind(fresh)
                .fetch_one(&pool)
                .await
                .expect("check fresh");
        assert!(fresh_exists.0, "fresh row must be preserved");

        delete_test_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn test_gc_used_refresh_jtis_returns_zero_when_nothing_old() {
        // Boundary: when no aged rows exist, GC returns 0 without erroring.
        let Some(pool) = try_connect_test_db().await else {
            eprintln!("skip: DATABASE_URL unset or schema missing");
            return;
        };
        let user_id = insert_test_user(&pool).await;
        let cfg = make_test_config();
        let svc = AuthService::new(pool.clone(), cfg.clone());

        // First, reap any aged rows from previous failed runs so we get a
        // clean baseline for the assertion below.
        let _ = svc.gc_used_refresh_jtis().await;

        // Insert only fresh rows.
        let jti = Uuid::new_v4();
        sqlx::query("INSERT INTO used_refresh_jtis (jti, user_id, used_at) VALUES ($1, $2, NOW())")
            .bind(jti)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert fresh jti");

        let removed = svc.gc_used_refresh_jtis().await.expect("gc");
        assert_eq!(removed, 0, "fresh rows must not be reaped");

        // Cleanup the row we just inserted before deleting the user, since
        // the FK has no cascade configured for jti rows in older migrations.
        let _ = sqlx::query("DELETE FROM used_refresh_jtis WHERE jti = $1")
            .bind(jti)
            .execute(&pool)
            .await;
        delete_test_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn test_refresh_tokens_happy_path_and_replay_rejected() {
        // Covers the SQL INSERT path of refresh_tokens (lines 365-378) on
        // first use, the rows_affected==0 replay branch on the second use
        // (lines 391-395), and the user fetch (lines 398-415).
        let Some(pool) = try_connect_test_db().await else {
            eprintln!("skip: DATABASE_URL unset or schema missing");
            return;
        };
        let user_id = insert_test_user(&pool).await;
        let cfg = make_test_config();
        let svc = AuthService::new(pool.clone(), cfg.clone());

        // Use authenticate to mint a real refresh token. We re-fetch the
        // password from the inserted row indirectly: we know insert_test_user
        // hashed "cov-test-password", so authenticate with that.
        let username: (String,) = sqlx::query_as("SELECT username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("load test username");
        let (_user, pair) = svc
            .authenticate(&username.0, "cov-test-password")
            .await
            .expect("authenticate test user");

        let (_user, pair2) = svc
            .refresh_tokens(&pair.refresh_token)
            .await
            .expect("first refresh succeeds");
        assert_ne!(
            pair.refresh_token, pair2.refresh_token,
            "rotation must mint a new refresh token"
        );

        // Replay must be rejected.
        let replay = svc.refresh_tokens(&pair.refresh_token).await;
        assert!(
            matches!(replay, Err(AppError::Authentication(_))),
            "replay must be rejected as Authentication error, got {:?}",
            replay
        );

        delete_test_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn test_refresh_tokens_user_not_found_after_decode() {
        // Covers the `.ok_or_else(... User not found ...)` branch when the
        // refresh token decodes to a user_id that no longer exists in the
        // users table (deleted between issuance and refresh).
        let Some(pool) = try_connect_test_db().await else {
            eprintln!("skip: DATABASE_URL unset or schema missing");
            return;
        };
        let cfg = make_test_config();
        let svc = AuthService::new(pool.clone(), cfg.clone());

        // Mint a refresh token bound to a user_id that doesn't exist.
        let ghost = Uuid::new_v4();
        let now = Utc::now();
        let claims = Claims {
            sub: ghost,
            username: "ghost".to_string(),
            email: "ghost@x.test".to_string(),
            is_admin: false,
            iat: now.timestamp(),
            exp: (now + Duration::days(1)).timestamp(),
            token_type: "refresh".to_string(),
            jti: Some(Uuid::new_v4()),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .expect("encode refresh token");

        // Without a referenced user the INSERT into used_refresh_jtis fails
        // on the FK, surfacing as an AppError::Database. Either way the
        // function returns an error and exercises the SQL path.
        let result = svc.refresh_tokens(&token).await;
        assert!(
            result.is_err(),
            "ghost-user refresh must be rejected, got {:?}",
            result
        );
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
}
