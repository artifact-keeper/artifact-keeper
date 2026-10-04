//! Runtime guest-access policy (#867).
//!
//! `AK_GUEST_ACCESS_ENABLED` (#850 / #866) used to be read once at startup, so
//! turning anonymous access off -- the "we just found exposed data, lock it
//! down now" move -- needed a redeploy. This module makes the setting
//! changeable at runtime through `PATCH /api/v1/admin/settings/system`, with
//! the value stored in the existing `system_settings` table, and gives every
//! consumer (the guest-access guard, `/api/v1/system/config`, the public-repo
//! refusal, the anonymous OCI token mint) one accessor to ask.
//!
//! # Precedence
//!
//! 1. **Environment, when set explicitly.** `AK_GUEST_ACCESS_ENABLED` set to
//!    one of `true` / `1` / `false` / `0` pins the effective value, exactly as
//!    `TOTP_POLICY` pins the TOTP policy. That keeps the env var a working
//!    break-glass (fix the value in the deployment, restart, done -- no login
//!    needed) and keeps IaC-managed instances authoritative over a UI click.
//! 2. **Database**, the `security.guest_access_enabled` row, otherwise.
//! 3. **Default** `true` (the historical default) when neither is present.
//!
//! An unset, empty or unrecognised env value does not pin; it behaves as the
//! historical parser did (guests enabled) unless the database says otherwise.
//!
//! A stored value can be written while the env var pins the setting. It has no
//! effect until the pin is removed, and the read endpoint reports it as
//! `stored`, so an operator can move from `AK_GUEST_ACCESS_ENABLED=false` to
//! UI management without a window in which anonymous access is back on: store
//! `false` first, then drop the env var.
//!
//! # Caching
//!
//! The guard asks on every request, so the resolved value is cached in process
//! for [`DEFAULT_CACHE_TTL`]. A write through this handle caches the written
//! value immediately, so the replica that served the `PATCH` enforces it on
//! the very next request; other replicas converge within one TTL. Refreshes
//! are single-flight: on expiry one request reads the row and concurrent ones
//! keep serving the previous value.
//!
//! # Failing closed
//!
//! * A failed read keeps the last value this handle resolved (a database blip
//!   must not flip anonymous access back on).
//! * With no previous value -- a cold cache on a fresh pod -- a failed read
//!   resolves to **guests refused** (source `unavailable`), retried after
//!   [`RETRY_AFTER_READ_FAILURE`], never to the default. Startup primes the
//!   handle and refuses to start if that first read fails, so this is a
//!   last-resort path.
//! * A row that exists but is not a JSON boolean resolves to guests refused
//!   (source `invalid`).
//! * The env pin needs no database and is never affected.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;

use crate::config::Config;

/// The `system_settings` key the stored value lives under.
pub const GUEST_ACCESS_SETTING_KEY: &str = "security.guest_access_enabled";

/// The environment variable that pins (and break-glass overrides) the setting.
pub const GUEST_ACCESS_ENV_VAR: &str = "AK_GUEST_ACCESS_ENABLED";

/// How long a resolved value is served from memory before the next read.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(5);

/// Where the effective guest-access value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuestAccessSource {
    /// Pinned by `AK_GUEST_ACCESS_ENABLED`; a stored value has no effect.
    Environment,
    /// Read from the `system_settings` table (managed through the admin API).
    Database,
    /// Neither is set: the built-in default (`true`).
    Default,
    /// A row exists but is not a JSON boolean: guests refused until fixed.
    Invalid,
    /// The row could not be read and nothing was resolved before (cold
    /// cache): guests refused until a read succeeds.
    Unavailable,
}

/// The effective setting together with its provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedGuestAccess {
    pub enabled: bool,
    pub source: GuestAccessSource,
    /// The value in `system_settings`, if any -- reported even when the env
    /// pin overrides it, so an operator can see what takes over once the pin
    /// is removed.
    pub stored: Option<bool>,
}

/// Parse the env var into a pin. Only the spellings the historical parser
/// treated specially pin the value: `false`/`0` (guests off) and `true`/`1`
/// (guests on). Anything else -- unset, empty, a typo -- is not a pin, and the
/// stored value or the default governs, which for an instance with no stored
/// value is the historical "guests enabled" reading of that input.
pub fn parse_env_pin(raw: Option<&str>) -> Option<bool> {
    match raw {
        Some("false" | "0") => Some(false),
        Some("true" | "1") => Some(true),
        _ => None,
    }
}

/// What the `system_settings` row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredValue {
    /// No row: nothing stored.
    Absent,
    /// A JSON boolean.
    Value(bool),
    /// A row exists but is not a JSON boolean. Fails closed.
    Invalid,
}

impl StoredValue {
    fn as_bool(self) -> Option<bool> {
        match self {
            StoredValue::Value(b) => Some(b),
            _ => None,
        }
    }
}

/// Decode a stored `system_settings.value`. Only a JSON boolean is accepted.
/// Anything else is [`StoredValue::Invalid`], which [`resolve`] treats as
/// "guests off": a row that exists says someone meant to manage the setting,
/// and the safe reading of an unreadable intent is closed.
pub fn decode_stored(value: Option<&serde_json::Value>) -> StoredValue {
    let Some(value) = value else {
        return StoredValue::Absent;
    };
    match value.as_bool() {
        Some(b) => StoredValue::Value(b),
        None => {
            tracing::warn!(
                %value,
                "unrecognized {GUEST_ACCESS_SETTING_KEY} value (expected a JSON boolean); \
                 refusing guest access until it is fixed"
            );
            StoredValue::Invalid
        }
    }
}

/// Pure precedence: env pin, then stored value (an undecodable row is
/// closed), then `default_enabled`.
pub fn resolve(
    env_pin: Option<bool>,
    stored: StoredValue,
    default_enabled: bool,
) -> ResolvedGuestAccess {
    let (enabled, source) = match (env_pin, stored) {
        (Some(pinned), _) => (pinned, GuestAccessSource::Environment),
        (None, StoredValue::Value(db)) => (db, GuestAccessSource::Database),
        (None, StoredValue::Invalid) => (false, GuestAccessSource::Invalid),
        (None, StoredValue::Absent) => (default_enabled, GuestAccessSource::Default),
    };
    ResolvedGuestAccess {
        enabled,
        source,
        stored: stored.as_bool(),
    }
}

/// What to serve when the stored row cannot be read. The env pin still
/// governs when set (it never needed the database). Otherwise the last value
/// this handle resolved is kept; with none -- a cold cache on a fresh pod --
/// the answer is **closed**, never the default: an instance an admin locked
/// down through the API must not reopen because its first read timed out.
pub fn fallback_after_read_failure(
    env_pin: Option<bool>,
    previous: Option<ResolvedGuestAccess>,
) -> ResolvedGuestAccess {
    if env_pin.is_some() {
        return resolve(env_pin, StoredValue::Absent, false);
    }
    previous.unwrap_or(ResolvedGuestAccess {
        enabled: false,
        source: GuestAccessSource::Unavailable,
        stored: None,
    })
}

/// How long a fallback served after a failed read is cached before the next
/// attempt: short, so recovery is quick, but long enough that a dead database
/// is not asked once per request.
pub const RETRY_AFTER_READ_FAILURE: Duration = Duration::from_millis(250);

/// Whether a cache entry stamped `at` is still fresh at `now`.
fn is_fresh(at: Instant, now: Instant, ttl: Duration) -> bool {
    now.saturating_duration_since(at) < ttl
}

#[derive(Debug, Clone, Copy)]
struct CachedValue {
    resolved: ResolvedGuestAccess,
    at: Instant,
    ttl: Duration,
}

/// Process-wide handle to the runtime guest-access setting. Cheap to share
/// behind an `Arc`; see the module docs for precedence and caching.
#[derive(Debug)]
pub struct GuestAccessPolicy {
    db: Option<PgPool>,
    setting_key: String,
    env_pin: Option<bool>,
    default_enabled: bool,
    ttl: Duration,
    cache: RwLock<Option<CachedValue>>,
    /// Single-flight for refreshes: on expiry one request reads the row while
    /// the others keep serving the (briefly stale) cached value, instead of
    /// every in-flight request taking a pool connection for the same SELECT.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl GuestAccessPolicy {
    /// Build the production handle: pin and default from `config`, stored
    /// value from `db` under [`GUEST_ACCESS_SETTING_KEY`].
    pub fn from_config(db: Option<PgPool>, config: &Config) -> Self {
        Self::new(
            db,
            GUEST_ACCESS_SETTING_KEY,
            config
                .guest_access_env_pinned
                .then_some(config.guest_access_enabled),
            config.guest_access_enabled,
        )
    }

    /// A handle with no database: always resolves to `enabled` (source
    /// `default`). For callers and tests that have no stored setting to read.
    pub fn fixed(enabled: bool) -> Self {
        Self::new(None, GUEST_ACCESS_SETTING_KEY, None, enabled)
    }

    /// Fully explicit constructor. `setting_key` is a parameter so DB-backed
    /// tests can each use a private row instead of racing on the real one.
    pub fn new(
        db: Option<PgPool>,
        setting_key: impl Into<String>,
        env_pin: Option<bool>,
        default_enabled: bool,
    ) -> Self {
        Self {
            db,
            setting_key: setting_key.into(),
            env_pin,
            default_enabled,
            ttl: DEFAULT_CACHE_TTL,
            cache: RwLock::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Whether the environment pins the value (writes are stored but inert).
    pub fn is_env_pinned(&self) -> bool {
        self.env_pin.is_some()
    }

    /// The effective value, served from cache when fresh. The hot path for
    /// the guard: no lock and no I/O when the env var pins the value.
    pub async fn is_enabled(&self) -> bool {
        if let Some(pinned) = self.env_pin {
            return pinned;
        }
        self.effective().await.enabled
    }

    /// The effective value with its provenance (cached, single-flight).
    pub async fn effective(&self) -> ResolvedGuestAccess {
        if let Some(hit) = self.cached(Instant::now()) {
            return hit;
        }
        if let Ok(_guard) = self.refresh_lock.try_lock() {
            // Someone may have refreshed between the check and the lock.
            if let Some(hit) = self.cached(Instant::now()) {
                return hit;
            }
            return self.refresh_locked().await;
        }
        // Another task is refreshing: serve what we have, even if stale.
        if let Some(stale) = self.last() {
            return stale;
        }
        // Cold cache: wait for the in-flight read rather than guess.
        let _guard = self.refresh_lock.lock().await;
        match self.last() {
            Some(v) => v,
            None => self.refresh_locked().await,
        }
    }

    fn cached(&self, now: Instant) -> Option<ResolvedGuestAccess> {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        guard
            .filter(|c| is_fresh(c.at, now, c.ttl))
            .map(|c| c.resolved)
    }

    /// The last cached value, fresh or not.
    fn last(&self) -> Option<ResolvedGuestAccess> {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        guard.map(|c| c.resolved)
    }

    fn store_cache(&self, resolved: ResolvedGuestAccess, ttl: Duration) {
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(CachedValue {
            resolved,
            at: Instant::now(),
            ttl,
        });
    }

    /// Drop the cached value so the next read goes to the database.
    #[cfg(test)]
    fn invalidate(&self) {
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }

    /// Read the stored row, bypassing the cache, and cache the result. Never
    /// fails: on a read error see [`fallback_after_read_failure`] (closed on
    /// a cold cache), cached for [`RETRY_AFTER_READ_FAILURE`].
    pub async fn refresh(&self) -> ResolvedGuestAccess {
        let _guard = self.refresh_lock.lock().await;
        self.refresh_locked().await
    }

    /// Like [`Self::refresh`] but surfaces a read error instead of falling
    /// back, leaving the cache untouched. For startup priming and the admin
    /// endpoints, where a stale or guessed answer would mislead.
    pub async fn try_refresh(&self) -> Result<ResolvedGuestAccess, sqlx::Error> {
        let _guard = self.refresh_lock.lock().await;
        let stored = self.read_stored().await?;
        let resolved = resolve(self.env_pin, stored, self.default_enabled);
        self.store_cache(resolved, self.ttl);
        Ok(resolved)
    }

    /// Refresh body; the caller holds `refresh_lock`.
    async fn refresh_locked(&self) -> ResolvedGuestAccess {
        match self.read_stored().await {
            Ok(stored) => {
                let resolved = resolve(self.env_pin, stored, self.default_enabled);
                self.store_cache(resolved, self.ttl);
                resolved
            }
            Err(e) => {
                let previous = self.last();
                let fallback = fallback_after_read_failure(self.env_pin, previous);
                tracing::warn!(
                    error = %e,
                    kept_previous = previous.is_some(),
                    guest_access_enabled = fallback.enabled,
                    "failed to read {}; serving the last known guest-access value \
                     (closed if there is none)",
                    self.setting_key
                );
                self.store_cache(fallback, RETRY_AFTER_READ_FAILURE);
                fallback
            }
        }
    }

    async fn read_stored(&self) -> Result<StoredValue, sqlx::Error> {
        let Some(db) = &self.db else {
            return Ok(StoredValue::Absent);
        };
        let value: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
                .bind(&self.setting_key)
                .fetch_optional(db)
                .await?;
        Ok(decode_stored(value.as_ref()))
    }

    /// Persist `enabled` and return the new effective value, cached at once.
    /// Stored even while the env var pins the setting (see module docs).
    pub async fn store(
        &self,
        enabled: bool,
        updated_by: uuid::Uuid,
    ) -> crate::error::Result<ResolvedGuestAccess> {
        let Some(db) = &self.db else {
            return Err(crate::error::AppError::Internal(
                "guest-access policy has no database to store into".to_string(),
            ));
        };
        sqlx::query(
            r#"
            INSERT INTO system_settings (key, value, description, updated_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (key) DO UPDATE
                SET value = $2, updated_by = $4, updated_at = NOW()
            "#,
        )
        .bind(&self.setting_key)
        .bind(serde_json::Value::Bool(enabled))
        .bind("Whether anonymous (guest) access is allowed; AK_GUEST_ACCESS_ENABLED overrides it when set")
        .bind(updated_by)
        .execute(db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
        // Cache what was just written rather than re-reading it: the next
        // request through this handle enforces it with no TTL wait.
        let resolved = resolve(
            self.env_pin,
            StoredValue::Value(enabled),
            self.default_enabled,
        );
        self.store_cache(resolved, self.ttl);
        Ok(resolved)
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_pin_only_for_the_explicit_spellings() {
        assert_eq!(parse_env_pin(Some("false")), Some(false));
        assert_eq!(parse_env_pin(Some("0")), Some(false));
        assert_eq!(parse_env_pin(Some("true")), Some(true));
        assert_eq!(parse_env_pin(Some("1")), Some(true));
        for raw in [None, Some(""), Some("yes"), Some("FALSE"), Some(" false")] {
            assert_eq!(parse_env_pin(raw), None, "{raw:?} must not pin");
        }
    }

    #[test]
    fn env_pin_wins_over_stored_in_both_directions() {
        let r = resolve(Some(false), StoredValue::Value(true), true);
        assert_eq!(
            (r.enabled, r.source),
            (false, GuestAccessSource::Environment)
        );
        assert_eq!(r.stored, Some(true));
        let r = resolve(Some(true), StoredValue::Value(false), true);
        assert_eq!(
            (r.enabled, r.source),
            (true, GuestAccessSource::Environment)
        );
    }

    #[test]
    fn stored_wins_over_default() {
        let r = resolve(None, StoredValue::Value(false), true);
        assert_eq!((r.enabled, r.source), (false, GuestAccessSource::Database));
        let r = resolve(None, StoredValue::Value(true), false);
        assert_eq!((r.enabled, r.source), (true, GuestAccessSource::Database));
    }

    #[test]
    fn default_applies_when_nothing_is_set() {
        let r = resolve(None, StoredValue::Absent, true);
        assert_eq!(
            r,
            ResolvedGuestAccess {
                enabled: true,
                source: GuestAccessSource::Default,
                stored: None
            }
        );
    }

    #[test]
    fn only_json_booleans_decode() {
        assert_eq!(decode_stored(None), StoredValue::Absent);
        assert_eq!(
            decode_stored(Some(&serde_json::json!(false))),
            StoredValue::Value(false)
        );
        assert_eq!(
            decode_stored(Some(&serde_json::json!(true))),
            StoredValue::Value(true)
        );
        assert_eq!(
            decode_stored(Some(&serde_json::json!("false"))),
            StoredValue::Invalid
        );
        assert_eq!(
            decode_stored(Some(&serde_json::json!(0))),
            StoredValue::Invalid
        );
    }

    #[test]
    fn an_undecodable_row_fails_closed_unless_pinned() {
        let r = resolve(None, StoredValue::Invalid, true);
        assert_eq!(
            (r.enabled, r.source, r.stored),
            (false, GuestAccessSource::Invalid, None)
        );
        let r = resolve(Some(true), StoredValue::Invalid, true);
        assert_eq!(
            (r.enabled, r.source),
            (true, GuestAccessSource::Environment)
        );
    }

    #[test]
    fn read_failure_fallback_is_closed_on_a_cold_cache() {
        let cold = fallback_after_read_failure(None, None);
        assert_eq!(
            (cold.enabled, cold.source),
            (false, GuestAccessSource::Unavailable)
        );
        let prev = resolve(None, StoredValue::Value(true), true);
        assert_eq!(fallback_after_read_failure(None, Some(prev)), prev);
        let pinned = fallback_after_read_failure(Some(true), None);
        assert_eq!(
            (pinned.enabled, pinned.source),
            (true, GuestAccessSource::Environment)
        );
    }

    #[test]
    fn freshness_respects_the_ttl() {
        let t0 = Instant::now();
        let ttl = Duration::from_secs(5);
        assert!(is_fresh(t0, t0, ttl));
        assert!(is_fresh(t0, t0 + Duration::from_secs(4), ttl));
        assert!(!is_fresh(t0, t0 + Duration::from_secs(5), ttl));
    }

    #[test]
    fn source_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&GuestAccessSource::Environment).unwrap(),
            "\"environment\""
        );
        assert_eq!(
            serde_json::to_string(&GuestAccessSource::Default).unwrap(),
            "\"default\""
        );
    }

    #[tokio::test]
    async fn fixed_handle_needs_no_database() {
        let p = GuestAccessPolicy::fixed(false);
        assert!(!p.is_enabled().await);
        assert!(!p.is_env_pinned());
        assert_eq!(p.effective().await.source, GuestAccessSource::Default);
        assert!(p.store(true, uuid::Uuid::nil()).await.is_err());
        assert!(GuestAccessPolicy::fixed(true).is_enabled().await);
    }

    #[tokio::test]
    async fn from_config_pins_only_when_the_env_was_explicit() {
        let mut config = Config::test_config();
        config.guest_access_enabled = false;
        config.guest_access_env_pinned = true;
        let p = GuestAccessPolicy::from_config(None, &config);
        assert!(p.is_env_pinned());
        assert_eq!(p.effective().await.source, GuestAccessSource::Environment);
        config.guest_access_env_pinned = false;
        let p = GuestAccessPolicy::from_config(None, &config);
        assert!(!p.is_env_pinned());
        assert!(!p.is_enabled().await);
    }

    fn unreachable_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgresql://localhost:1/__guest_access_policy_unit__")
            .expect("lazy pool")
    }

    #[tokio::test]
    async fn a_read_that_fails_before_any_success_is_closed() {
        // The cold-cache case: a fresh pod whose first read times out must not
        // serve anonymous traffic on the default.
        let p = GuestAccessPolicy::new(Some(unreachable_pool()), "test.unreachable", None, true);
        assert!(!p.is_enabled().await, "cold cache + failed read = closed");
        let r = p.refresh().await;
        assert_eq!(
            (r.enabled, r.source),
            (false, GuestAccessSource::Unavailable)
        );
        assert!(
            p.try_refresh().await.is_err(),
            "the fallible read surfaces it"
        );
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_last_known_value() {
        let p = GuestAccessPolicy::new(Some(unreachable_pool()), "test.unreachable", None, true);
        // Seed values as if earlier reads had succeeded; each is kept.
        for stored in [false, true] {
            p.store_cache(
                resolve(None, StoredValue::Value(stored), true),
                DEFAULT_CACHE_TTL,
            );
            let kept = p.refresh().await;
            assert_eq!(kept.enabled, stored);
            assert_eq!(kept.source, GuestAccessSource::Database);
        }
        // try_refresh leaves the cache alone on failure.
        assert!(p.try_refresh().await.is_err());
        assert!(p.effective().await.enabled);
    }

    #[tokio::test]
    async fn the_failure_fallback_is_cached_only_briefly() {
        let p = GuestAccessPolicy::new(Some(unreachable_pool()), "test.unreachable", None, true);
        p.refresh().await;
        let now = Instant::now();
        assert!(p.cached(now).is_some());
        assert!(p.cached(now + RETRY_AFTER_READ_FAILURE).is_none());
        p.invalidate();
        assert!(p.last().is_none());
    }

    #[tokio::test]
    async fn a_concurrent_reader_serves_stale_while_a_refresh_is_in_flight() {
        let p = GuestAccessPolicy::fixed(true);
        p.store_cache(
            resolve(None, StoredValue::Value(false), true),
            Duration::ZERO,
        );
        let _held = p.refresh_lock.lock().await;
        // Expired and the lock is busy: the stale value is served, no wait.
        let v = tokio::time::timeout(Duration::from_millis(500), p.effective())
            .await
            .expect("must not block behind the in-flight refresh");
        assert!(!v.enabled);
    }

    /// DB-backed: a write is visible on the next read through the same handle
    /// (cache refreshed with the written value, no TTL wait), and the env pin
    /// still wins.
    #[tokio::test]
    async fn store_refreshes_and_env_pin_wins() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let key = format!("test.guest_access.{}", uuid::Uuid::new_v4());
        let (admin, _) = crate::api::handlers::test_db_helpers::create_user(&pool).await;

        let p = GuestAccessPolicy::new(Some(pool.clone()), key.clone(), None, true);
        assert_eq!(p.effective().await.source, GuestAccessSource::Default);
        assert!(p.is_enabled().await);

        let after = p.store(false, admin).await.expect("store");
        assert_eq!(
            (after.enabled, after.source),
            (false, GuestAccessSource::Database)
        );
        assert!(!p.is_enabled().await, "no TTL wait after a write");

        // A second handle over the same row (another replica) reads it too.
        let other = GuestAccessPolicy::new(Some(pool.clone()), key.clone(), None, true);
        assert!(!other.is_enabled().await);

        // Pinned handle: stored value is reported, but the pin governs.
        let pinned = GuestAccessPolicy::new(Some(pool.clone()), key.clone(), Some(true), true);
        let r = pinned.effective().await;
        assert_eq!(
            (r.enabled, r.source, r.stored),
            (true, GuestAccessSource::Environment, Some(false))
        );

        // A corrupt row fails closed.
        sqlx::query("UPDATE system_settings SET value = $2 WHERE key = $1")
            .bind(&key)
            .bind(serde_json::json!("nope"))
            .execute(&pool)
            .await
            .expect("corrupt");
        let corrupt = p.refresh().await;
        assert_eq!(
            (corrupt.enabled, corrupt.source),
            (false, GuestAccessSource::Invalid)
        );

        sqlx::query("DELETE FROM system_settings WHERE key = $1")
            .bind(&key)
            .execute(&pool)
            .await
            .expect("cleanup row");
        crate::api::handlers::test_db_helpers::cleanup_user(&pool, admin).await;
    }
}
