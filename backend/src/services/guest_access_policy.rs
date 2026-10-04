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
//! for [`DEFAULT_CACHE_TTL`]. A write through this handle invalidates the cache
//! immediately, so the replica that served the `PATCH` enforces the new value
//! on the very next request; other replicas converge within one TTL. A failed
//! refresh keeps the last value it resolved (a database blip must not flip
//! anonymous access back on) and falls back to the env/default only when it
//! has never resolved one.

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

/// Decode a stored `system_settings.value`. Only a JSON boolean is accepted; a
/// corrupt row is logged and ignored so the env/default governs.
pub fn decode_stored(value: Option<&serde_json::Value>) -> Option<bool> {
    let value = value?;
    match value.as_bool() {
        Some(b) => Some(b),
        None => {
            tracing::warn!(
                %value,
                "unrecognized {GUEST_ACCESS_SETTING_KEY} value (expected a JSON boolean); ignoring it"
            );
            None
        }
    }
}

/// Pure precedence: env pin, then stored value, then `default_enabled`.
pub fn resolve(
    env_pin: Option<bool>,
    stored: Option<bool>,
    default_enabled: bool,
) -> ResolvedGuestAccess {
    let (enabled, source) = match (env_pin, stored) {
        (Some(pinned), _) => (pinned, GuestAccessSource::Environment),
        (None, Some(db)) => (db, GuestAccessSource::Database),
        (None, None) => (default_enabled, GuestAccessSource::Default),
    };
    ResolvedGuestAccess {
        enabled,
        source,
        stored,
    }
}

/// Whether a cache entry stamped `at` is still fresh at `now`.
fn is_fresh(at: Instant, now: Instant, ttl: Duration) -> bool {
    now.saturating_duration_since(at) < ttl
}

#[derive(Debug, Clone, Copy)]
struct CachedValue {
    resolved: ResolvedGuestAccess,
    at: Instant,
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

    /// The effective value with its provenance (cached).
    pub async fn effective(&self) -> ResolvedGuestAccess {
        if let Some(hit) = self.cached(Instant::now()) {
            return hit;
        }
        self.refresh().await
    }

    fn cached(&self, now: Instant) -> Option<ResolvedGuestAccess> {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        guard
            .filter(|c| is_fresh(c.at, now, self.ttl))
            .map(|c| c.resolved)
    }

    fn store_cache(&self, resolved: ResolvedGuestAccess) {
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(CachedValue {
            resolved,
            at: Instant::now(),
        });
    }

    /// Drop the cached value so the next read goes to the database.
    pub fn invalidate(&self) {
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }

    /// Read the stored row, bypassing the cache, and cache the result. On a
    /// read failure the last resolved value is kept (re-stamped so a dead
    /// database is not hammered once per request).
    pub async fn refresh(&self) -> ResolvedGuestAccess {
        let resolved = match self.read_stored().await {
            Ok(stored) => resolve(self.env_pin, stored, self.default_enabled),
            Err(e) => {
                let previous = self
                    .cache
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .map(|c| c.resolved);
                tracing::warn!(
                    error = %e,
                    kept_previous = previous.is_some(),
                    "failed to read {}; keeping the last known guest-access value",
                    self.setting_key
                );
                previous.unwrap_or_else(|| resolve(self.env_pin, None, self.default_enabled))
            }
        };
        self.store_cache(resolved);
        resolved
    }

    async fn read_stored(&self) -> Result<Option<bool>, sqlx::Error> {
        let Some(db) = &self.db else {
            return Ok(None);
        };
        let value: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
                .bind(&self.setting_key)
                .fetch_optional(db)
                .await?;
        Ok(decode_stored(value.as_ref()))
    }

    /// Persist `enabled`, invalidate the cache, and return the new effective
    /// value. Stored even while the env var pins the setting (see module docs).
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
        // request through this handle enforces it with no TTL wait, and a read
        // failure right after a successful write cannot resurrect the default.
        let resolved = resolve(self.env_pin, Some(enabled), self.default_enabled);
        self.store_cache(resolved);
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
        let r = resolve(Some(false), Some(true), true);
        assert_eq!(
            (r.enabled, r.source),
            (false, GuestAccessSource::Environment)
        );
        assert_eq!(r.stored, Some(true));
        let r = resolve(Some(true), Some(false), true);
        assert_eq!(
            (r.enabled, r.source),
            (true, GuestAccessSource::Environment)
        );
    }

    #[test]
    fn stored_wins_over_default() {
        let r = resolve(None, Some(false), true);
        assert_eq!((r.enabled, r.source), (false, GuestAccessSource::Database));
        let r = resolve(None, Some(true), false);
        assert_eq!((r.enabled, r.source), (true, GuestAccessSource::Database));
    }

    #[test]
    fn default_applies_when_nothing_is_set() {
        let r = resolve(None, None, true);
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
        assert_eq!(decode_stored(None), None);
        assert_eq!(decode_stored(Some(&serde_json::json!(false))), Some(false));
        assert_eq!(decode_stored(Some(&serde_json::json!(true))), Some(true));
        assert_eq!(decode_stored(Some(&serde_json::json!("false"))), None);
        assert_eq!(decode_stored(Some(&serde_json::json!(0))), None);
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

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_last_known_value() {
        // A pool that can never connect: every read fails.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgresql://localhost:1/__guest_access_policy_unit__")
            .expect("lazy pool");
        let p = GuestAccessPolicy::new(Some(pool), "test.unreachable", None, true);
        // No previous value: the default governs.
        assert!(p.refresh().await.enabled);
        // Seed a "false" as if a previous read had succeeded, then expire it.
        p.store_cache(resolve(None, Some(false), true));
        p.invalidate();
        assert!(p.refresh().await.enabled, "invalidated: nothing to keep");
        p.store_cache(resolve(None, Some(false), true));
        // Force a refresh while a previous value exists: it is kept.
        let kept = p.refresh().await;
        assert!(!kept.enabled, "a DB blip must not re-enable guests");
        assert_eq!(kept.source, GuestAccessSource::Database);
    }

    /// DB-backed: a write is visible on the next read through the same handle
    /// (cache invalidated, no TTL wait), and the env pin still wins.
    #[tokio::test]
    async fn store_invalidates_and_env_pin_wins() {
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

        // A corrupt row is ignored, the default governs.
        sqlx::query("UPDATE system_settings SET value = $2 WHERE key = $1")
            .bind(&key)
            .bind(serde_json::json!("nope"))
            .execute(&pool)
            .await
            .expect("corrupt");
        assert_eq!(p.refresh().await.source, GuestAccessSource::Default);

        sqlx::query("DELETE FROM system_settings WHERE key = $1")
            .bind(&key)
            .execute(&pool)
            .await
            .expect("cleanup row");
        crate::api::handlers::test_db_helpers::cleanup_user(&pool, admin).await;
    }
}
