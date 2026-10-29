//! Opt-in LDAP/AD Basic-auth passthrough for package-manager clients (#3830).
//!
//! Local accounts and API tokens have always worked in `.npmrc`, Composer's
//! `auth.json`, `nuget.config` and the other package-manager credential files.
//! A directory (LDAP/AD) user's real username and password did not: the
//! format routes only offered bcrypt local login and token fallback, so a team
//! migrating from Nexus had to mint every developer a personal API token.
//!
//! This module adds a **disabled-by-default** passthrough. It runs only after
//! the ordinary format-route credential resolution has already failed
//! (bcrypt local login, a short-lived JWT in the Basic password, and an API
//! token in the Basic password), and only on the format/registry surfaces that
//! opt in through [`try_authenticate`].
//!
//! # Security posture (review conditions on #3830)
//!
//! * [`LDAP_BASIC_AUTH_PASSTHROUGH_ENV`] defaults to off.
//! * A bind only happens after every cheaper credential form was tried.
//! * Binds share the `/v2/token` per-`(username, IP)` budget and global
//!   backstop through [`install_rate_limit`]; the format routes had no login
//!   budget at all before this.
//! * A per-username cap on *distinct* failed passwords below a typical AD
//!   lockout threshold fails fast without another bind. Distinct passwords
//!   are tracked by HMAC tag, never by password.
//! * Success and failure caches are keyed by a domain-separated,
//!   length-prefixed HMAC of `username || password`, use a per-process random
//!   key, store only tags, and are bounded.
//! * `users.is_active` is re-read from the database on every success-cache
//!   hit, and cache entries are cleared for a user when deactivation calls
//!   [`crate::services::auth_service::invalidate_user_token_cache_entries`].
//!   Reconcile and admin deactivations therefore take effect immediately.
//! * Successful and failed passthrough logins are audited (`LOGIN` /
//!   `LOGIN_FAILED`) with no credential material.
//!
//! The caches are process-local. A multi-replica deployment clears the cache
//! on the replica that performs a deactivation and re-reads `is_active` on
//! every hit, so a stale positive entry cannot keep working on another replica
//! after the next hit reaches the database.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::middleware::client_ip::current_client_ip;
use crate::api::middleware::rate_limit::{login_rate_limit_key, LoginRateLimitState};
use crate::error::AppError;
use crate::models::user::{AuthProvider, User};
use crate::services::audit_export::details::AuthDetails;
use crate::services::audit_service::{
    audit_fire_and_forget, federated_login_details, AuditAction, AuditEntry, ResourceType,
};
use crate::services::auth_config_service::{AuthConfigService, LdapConfigRow};
use crate::services::auth_service::{AuthService, FederatedCredentials};
use crate::services::ldap_service::{LdapService, LdapUserInfo};

/// Opt-in switch for the passthrough. Unset or false (the default) keeps the
/// historical format-route contract: directory passwords do not authenticate
/// package-manager clients.
pub const LDAP_BASIC_AUTH_PASSTHROUGH_ENV: &str = "LDAP_BASIC_AUTH_PASSTHROUGH";
/// How long a successful bind credential may be reused without binding again.
pub const LDAP_BASIC_AUTH_CACHE_TTL_ENV: &str = "LDAP_BASIC_AUTH_CACHE_TTL_SECS";
/// How long a rejected credential may be reused without binding again.
pub const LDAP_BASIC_AUTH_FAILURE_TTL_ENV: &str = "LDAP_BASIC_AUTH_FAILURE_TTL_SECS";
/// Maximum distinct failed passwords per username inside the failure window.
pub const LDAP_BASIC_AUTH_MAX_FAILED_PASSWORDS_ENV: &str = "LDAP_BASIC_AUTH_MAX_FAILED_PASSWORDS";
/// Window in which distinct failed passwords are counted.
pub const LDAP_BASIC_AUTH_FAILED_WINDOW_ENV: &str = "LDAP_BASIC_AUTH_FAILED_WINDOW_SECS";
/// Bound on each in-process cache (success and failure).
pub const LDAP_BASIC_AUTH_CACHE_MAX_ENTRIES_ENV: &str = "LDAP_BASIC_AUTH_CACHE_MAX_ENTRIES";

/// Five minutes matches the documented window in which a changed AD password
/// may still be accepted from the cache. Short enough that a directory-side
/// revocation is re-observed quickly, long enough that a CI job doing many
/// downloads does not bind on every request.
pub const DEFAULT_SUCCESS_TTL_SECS: u64 = 300;
/// A rejected credential is remembered briefly so a password guess is not
/// replayed against the directory on every request. Deliberately much shorter
/// than the success TTL: a user who mistypes then corrects should not wait
/// five minutes.
pub const DEFAULT_FAILURE_TTL_SECS: u64 = 60;
/// Typical AD lockout thresholds start at 10; three distinct failures stays
/// below the common deployments and leaves room for the cached-failure path.
pub const DEFAULT_MAX_FAILED_PASSWORDS: usize = 3;
/// AD's bad-password observation window ("reset account lockout counter
/// after") is commonly 30 minutes. The AK window must be at least as long as
/// the directory's, otherwise AK forgets failures the directory still counts
/// and a fresh set of binds lands inside the same directory window.
pub const DEFAULT_FAILED_WINDOW_SECS: u64 = 1800;
/// Per-cache entry bound. At the limit the success and exact-credential
/// failure caches are cleared wholesale, exactly like the repository miss
/// cache: a predictable bound without an LRU. The per-username failure ledger
/// is never cleared wholesale (see [`FAILURE_LEDGER_BOUND_FACTOR`]).
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 4096;

/// The per-username failure ledger holds this many times
/// `max_cache_entries` usernames before it evicts. Clearing it would hand
/// every username a fresh failure budget, so it is sized above what the
/// shared login backstop lets through in one failure window, and at the
/// bound it evicts the usernames whose last failure is oldest instead.
pub const FAILURE_LEDGER_BOUND_FACTOR: usize = 16;

/// Effective settings for one passthrough attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub success_ttl: Duration,
    pub failure_ttl: Duration,
    pub max_failed_passwords: usize,
    pub failed_window: Duration,
    pub max_cache_entries: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            success_ttl: Duration::from_secs(DEFAULT_SUCCESS_TTL_SECS),
            failure_ttl: Duration::from_secs(DEFAULT_FAILURE_TTL_SECS),
            max_failed_passwords: DEFAULT_MAX_FAILED_PASSWORDS,
            failed_window: Duration::from_secs(DEFAULT_FAILED_WINDOW_SECS),
            max_cache_entries: DEFAULT_CACHE_MAX_ENTRIES,
        }
    }
}

fn truthy(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        let v = v.trim();
        v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
            || v == "1"
    })
}

fn positive<T: std::str::FromStr + PartialOrd + Default>(value: Option<&str>) -> Option<T> {
    value
        .and_then(|v| v.trim().parse::<T>().ok())
        .filter(|v| *v > T::default())
}

/// Parse the passthrough settings from raw values.
///
/// Pure so the defaults and the zero semantics are testable without mutating
/// the process environment (which tests run in parallel):
/// * unset/unparseable/zero TTL disables that cache;
/// * zero `max_failed_passwords` disables the per-username cap;
/// * zero/unparseable window or entry bound keeps the default.
pub fn parse_settings(
    passthrough: Option<&str>,
    success_ttl_secs: Option<&str>,
    failure_ttl_secs: Option<&str>,
    max_failed_passwords: Option<&str>,
    failed_window_secs: Option<&str>,
    max_cache_entries: Option<&str>,
) -> Settings {
    let default = Settings::default();
    Settings {
        enabled: truthy(passthrough),
        success_ttl: success_ttl_secs
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(default.success_ttl),
        failure_ttl: failure_ttl_secs
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(default.failure_ttl),
        max_failed_passwords: max_failed_passwords
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(default.max_failed_passwords),
        failed_window: positive(failed_window_secs)
            .map(Duration::from_secs)
            .unwrap_or(default.failed_window),
        max_cache_entries: positive(max_cache_entries).unwrap_or(default.max_cache_entries),
    }
}

impl Settings {
    /// Read the settings from the process environment once per attempt.
    ///
    /// Deliberately not cached: an operator can flip the switch without a
    /// restart (the same contract as the directory reconcile settings), and
    /// tests that set the variable see it immediately.
    pub fn from_env() -> Self {
        let value = |name: &str| std::env::var(name).ok();
        Self::parse(
            value(LDAP_BASIC_AUTH_PASSTHROUGH_ENV).as_deref(),
            value(LDAP_BASIC_AUTH_CACHE_TTL_ENV).as_deref(),
            value(LDAP_BASIC_AUTH_FAILURE_TTL_ENV).as_deref(),
            value(LDAP_BASIC_AUTH_MAX_FAILED_PASSWORDS_ENV).as_deref(),
            value(LDAP_BASIC_AUTH_FAILED_WINDOW_ENV).as_deref(),
            value(LDAP_BASIC_AUTH_CACHE_MAX_ENTRIES_ENV).as_deref(),
        )
    }

    fn parse(
        passthrough: Option<&str>,
        success_ttl_secs: Option<&str>,
        failure_ttl_secs: Option<&str>,
        max_failed_passwords: Option<&str>,
        failed_window_secs: Option<&str>,
        max_cache_entries: Option<&str>,
    ) -> Self {
        parse_settings(
            passthrough,
            success_ttl_secs,
            failure_ttl_secs,
            max_failed_passwords,
            failed_window_secs,
            max_cache_entries,
        )
    }
}

/// A credential tag. The HMAC input is exactly
/// `"ldap-basic" || len(user) || user || pass` with a 32-bit big-endian
/// length, so `("ab", "c")` and `("a", "bc")` cannot collide even before the
/// HMAC key is applied.
type Tag = [u8; 32];

fn credential_tag_with_key(key: &[u8], username: &str, password: &str) -> Tag {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(b"ldap-basic");
    mac.update(&(username.len() as u32).to_be_bytes());
    mac.update(username.as_bytes());
    mac.update(password.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&digest);
    tag
}

fn hmac_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        // Per-process random key: a process restart cannot replay old tags,
        // and the key never leaves memory.
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    })
}

fn credential_tag(username: &str, password: &str) -> Tag {
    credential_tag_with_key(hmac_key(), username, password)
}

#[derive(Debug, Clone, Copy)]
struct SuccessEntry {
    user_id: Uuid,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct FailureEntry {
    username: String,
    user_id: Option<Uuid>,
    expires_at: Instant,
}

#[derive(Debug)]
struct UserFailures {
    user_id: Option<Uuid>,
    /// `(tag, expires_at)`. The tag is the only representation of the
    /// rejected password retained.
    entries: Vec<(Tag, Instant)>,
}

/// Bounded in-process cache. Public within the crate for unit tests that need
/// deterministic `Instant`s.
#[derive(Debug, Default)]
pub(crate) struct Cache {
    success: HashMap<Tag, SuccessEntry>,
    failure: HashMap<Tag, FailureEntry>,
    failures_by_username: HashMap<String, UserFailures>,
    /// Binds in flight, by credential tag. Concurrent requests carrying the
    /// same credential wait for the one bind instead of each binding, and
    /// in-flight distinct credentials count toward the per-username cap, so
    /// a burst of parallel guesses cannot outrun it.
    pending: HashMap<Tag, PendingBind>,
}

#[derive(Debug)]
struct PendingBind {
    failure_key: String,
    gate: std::sync::Arc<tokio::sync::Mutex<()>>,
}

/// Result of [`Cache::claim`].
#[derive(Debug)]
pub(crate) enum Claim {
    /// This caller owns the bind for the credential. Dropping the
    /// [`BindFlight`] releases waiters.
    Bind(BindFlight),
    /// Another request is binding the same credential; wait on the gate, then
    /// re-run the precheck.
    Wait(std::sync::Arc<tokio::sync::Mutex<()>>),
    /// Failed plus in-flight distinct credentials already reach the cap.
    TooManyFailures,
}

/// Ownership of one in-flight bind. On drop (including cancellation of the
/// request future) the pending entry is removed and waiters are released.
#[derive(Debug)]
pub(crate) struct BindFlight {
    tag: Tag,
    _guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for BindFlight {
    fn drop(&mut self) {
        // Remove the pending entry before the guard is released (fields drop
        // after this body), so a woken waiter re-runs the precheck against
        // the recorded result rather than finding the flight still pending.
        cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .remove(&self.tag);
    }
}

/// Result of the cache/cap check that runs before any network I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Precheck {
    /// A still-valid successful bind for this exact credential.
    Cached(Uuid),
    /// This exact credential already failed and the negative entry is live.
    CachedFailure,
    /// The per-username distinct-failure cap is reached; do not bind.
    TooManyFailures,
    /// No usable cache entry; proceed to the rate limiter and bind.
    Proceed,
}

impl Cache {
    /// AD treats usernames case-insensitively, so the failure budget must too:
    /// otherwise `alice`, `Alice`, and `ALICE` would each get a fresh three
    /// binds against the same lockout counter. The success cache remains keyed
    /// on the exact submitted credential.
    fn failure_key(username: &str) -> String {
        username.to_ascii_lowercase()
    }

    fn prune(&mut self, now: Instant) {
        self.success.retain(|_, entry| entry.expires_at > now);
        self.failure.retain(|_, entry| entry.expires_at > now);
        self.failures_by_username.retain(|_, failures| {
            failures.entries.retain(|(_, expires_at)| *expires_at > now);
            !failures.entries.is_empty()
        });
    }

    fn bound(&mut self, max_entries: usize) {
        if self.success.len() > max_entries {
            self.success.clear();
        }
        if self.failure.len() > max_entries {
            self.failure.clear();
        }
        let ledger_bound = max_entries.saturating_mul(FAILURE_LEDGER_BOUND_FACTOR);
        if self.failures_by_username.len() > ledger_bound {
            let mut by_age: Vec<(String, Instant)> = self
                .failures_by_username
                .iter()
                .map(|(key, failures)| {
                    let newest = failures
                        .entries
                        .iter()
                        .map(|(_, expires_at)| *expires_at)
                        .max()
                        .unwrap_or_else(Instant::now);
                    (key.clone(), newest)
                })
                .collect();
            by_age.sort_by_key(|(_, newest)| *newest);
            let excess = self.failures_by_username.len() - ledger_bound;
            for (key, _) in by_age.into_iter().take(excess) {
                self.failures_by_username.remove(&key);
            }
        }
    }

    /// Distinct failed credentials recorded for `username` that are still
    /// inside the failure window.
    fn distinct_failures(&self, username: &str, now: Instant) -> usize {
        self.failures_by_username
            .get(&Self::failure_key(username))
            .map(|failures| {
                failures
                    .entries
                    .iter()
                    .filter(|(_, expires_at)| *expires_at > now)
                    .count()
            })
            .unwrap_or(0)
    }

    fn cap_enabled(settings: &Settings) -> bool {
        settings.max_failed_passwords > 0 && !settings.failed_window.is_zero()
    }

    /// Claim the bind for `tag` after [`Self::precheck`] answered
    /// [`Precheck::Proceed`].
    pub(crate) fn claim(
        &mut self,
        tag: &Tag,
        username: &str,
        settings: &Settings,
        now: Instant,
    ) -> Claim {
        if let Some(pending) = self.pending.get(tag) {
            return Claim::Wait(pending.gate.clone());
        }
        let failure_key = Self::failure_key(username);
        if Self::cap_enabled(settings) {
            let in_flight = self
                .pending
                .values()
                .filter(|pending| pending.failure_key == failure_key)
                .count();
            if self.distinct_failures(username, now) + in_flight >= settings.max_failed_passwords {
                return Claim::TooManyFailures;
            }
        }
        let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let guard = gate.clone().try_lock_owned().ok();
        self.pending.insert(*tag, PendingBind { failure_key, gate });
        Claim::Bind(BindFlight {
            tag: *tag,
            _guard: guard,
        })
    }

    pub(crate) fn precheck(
        &mut self,
        tag: &Tag,
        username: &str,
        settings: &Settings,
        now: Instant,
    ) -> Precheck {
        self.prune(now);
        if let Some(entry) = self.success.get(tag) {
            return Precheck::Cached(entry.user_id);
        }
        if self.failure.contains_key(tag) {
            return Precheck::CachedFailure;
        }
        if Self::cap_enabled(settings) {
            if let Some(failures) = self.failures_by_username.get(&Self::failure_key(username)) {
                // A credential the directory already rejected inside the
                // window is never bound again in that window. Without this,
                // one wrong password re-binds every time the short failure
                // TTL lapses and walks the account into directory lockout
                // without ever reaching the distinct-password cap.
                if failures
                    .entries
                    .iter()
                    .any(|(seen, expires_at)| seen == tag && *expires_at > now)
                {
                    return Precheck::CachedFailure;
                }
            }
            if self.distinct_failures(username, now) >= settings.max_failed_passwords {
                return Precheck::TooManyFailures;
            }
        }
        Precheck::Proceed
    }

    pub(crate) fn record_success(
        &mut self,
        tag: Tag,
        user_id: Uuid,
        settings: &Settings,
        now: Instant,
    ) {
        if settings.success_ttl.is_zero() {
            return;
        }
        self.prune(now);
        self.success.insert(
            tag,
            SuccessEntry {
                user_id,
                expires_at: now + settings.success_ttl,
            },
        );
        self.bound(settings.max_cache_entries);
    }

    pub(crate) fn record_failure(
        &mut self,
        tag: Tag,
        username: &str,
        user_id: Option<Uuid>,
        settings: &Settings,
        now: Instant,
    ) {
        self.prune(now);
        if !settings.failure_ttl.is_zero() {
            self.failure.insert(
                tag,
                FailureEntry {
                    username: username.to_string(),
                    user_id,
                    expires_at: now + settings.failure_ttl,
                },
            );
        }
        if Self::cap_enabled(settings) {
            let failures = self
                .failures_by_username
                .entry(Self::failure_key(username))
                .or_insert_with(|| UserFailures {
                    user_id,
                    entries: Vec::new(),
                });
            if failures.user_id.is_none() {
                failures.user_id = user_id;
            }
            if !failures.entries.iter().any(|(seen, _)| *seen == tag) {
                failures.entries.push((tag, now + settings.failed_window));
            }
            // Concurrent guesses can outrun the precheck by a little; keep the
            // per-username vector bounded even then.
            let cap = settings.max_failed_passwords.saturating_mul(4).max(8);
            if failures.entries.len() > cap {
                failures.entries.sort_by_key(|(_, expires_at)| *expires_at);
                let excess = failures.entries.len() - cap;
                failures.entries.drain(0..excess);
            }
        }
        self.bound(settings.max_cache_entries);
    }

    pub(crate) fn remove_success(&mut self, tag: &Tag) {
        self.success.remove(tag);
    }

    pub(crate) fn clear_failures_for_username(&mut self, username: &str) {
        self.failures_by_username
            .remove(&Self::failure_key(username));
    }

    /// Drop every entry belonging to `user_id` from both caches. Called when
    /// the user is deactivated or deleted, so the next request re-reads
    /// `is_active` and cannot be served by a pre-deactivation bind.
    pub(crate) fn invalidate_user(&mut self, user_id: Uuid) {
        self.success.retain(|_, entry| entry.user_id != user_id);

        let affected: Vec<String> = self
            .failure
            .iter()
            .filter(|(_, entry)| entry.user_id == Some(user_id))
            .map(|(_, entry)| entry.username.clone())
            .collect();
        self.failure
            .retain(|_, entry| entry.user_id != Some(user_id));
        for username in affected {
            self.failures_by_username
                .remove(&Self::failure_key(&username));
        }
        self.failures_by_username
            .retain(|_, failures| failures.user_id != Some(user_id));
    }

    #[cfg(test)]
    fn success_len(&self) -> usize {
        self.success.len()
    }

    #[cfg(test)]
    fn failure_len(&self) -> usize {
        self.failure.len()
    }
}

static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

fn cache() -> &'static Mutex<Cache> {
    CACHE.get_or_init(|| Mutex::new(Cache::default()))
}

/// The `/v2/token` limiter state, installed once by `create_router` and shared
/// with the OCI credential exchange so a guess against either surface spends
/// the same per-`(username, IP)` budget and global backstop.
static RATE_LIMIT: OnceLock<RwLock<Option<LoginRateLimitState>>> = OnceLock::new();

fn rate_limit_cell() -> &'static RwLock<Option<LoginRateLimitState>> {
    RATE_LIMIT.get_or_init(|| RwLock::new(None))
}

/// Install the shared `/v2/token` limiter. Safe to call repeatedly; the latest
/// router's state wins (tests build routers repeatedly in one process).
pub fn install_rate_limit(state: LoginRateLimitState) {
    if let Ok(mut slot) = rate_limit_cell().write() {
        *slot = Some(state);
    }
}

fn rate_limit() -> Option<LoginRateLimitState> {
    rate_limit_cell().read().ok().and_then(|slot| slot.clone())
}

/// Outcome of a passthrough attempt for the auth middleware.
#[derive(Debug)]
pub(crate) enum Outcome {
    Resolved(Box<User>),
    Invalid,
    /// The shared login limiter refused the bind. Carries `Retry-After`.
    RateLimited(u64),
    /// Directory/DB infrastructure is unavailable; retryable 503.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthError {
    Invalid,
    Unavailable,
}

impl AuthError {
    fn from_app(error: &AppError) -> Self {
        match error {
            AppError::Authentication(_) | AppError::NotFound(_) | AppError::Conflict(_) => {
                Self::Invalid
            }
            other => {
                if other.is_db_unavailable() || matches!(other, AppError::ServiceUnavailable(_)) {
                    Self::Unavailable
                } else {
                    tracing::error!(error = %other, "LDAP Basic-auth passthrough infrastructure failure");
                    Self::Unavailable
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct KnownUser {
    id: Uuid,
    is_active: bool,
    auth_provider: String,
    ldap_provider_id: Option<Uuid>,
}

async fn find_user_by_username(db: &PgPool, username: &str) -> Result<Option<KnownUser>, AppError> {
    // Directory usernames are case-insensitive (AD in particular). Look up
    // case-insensitively so a case variant cannot dodge the local-account
    // refusal below and spend a same-named directory account's lockout
    // budget. Prefer an exact match, then an LDAP row over a local/SSO one.
    let row = sqlx::query_as::<_, (Uuid, bool, String, Option<Uuid>)>(
        r#"
        SELECT id, is_active, auth_provider::text, ldap_provider_id
        FROM users
        WHERE lower(username) = lower($1)
        ORDER BY (username = $1) DESC, (auth_provider = 'ldap') DESC, id
        LIMIT 1
        "#,
    )
    .bind(username)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(row.map(
        |(id, is_active, auth_provider, ldap_provider_id)| KnownUser {
            id,
            is_active,
            auth_provider,
            ldap_provider_id,
        },
    ))
}

async fn load_enabled_provider(
    db: &PgPool,
    provider_id: Option<Uuid>,
) -> Result<Option<(LdapConfigRow, Option<String>)>, AppError> {
    let id = match provider_id {
        Some(id) => id,
        None => {
            let Some(id) = sqlx::query_scalar::<_, Uuid>(
                r#"
                SELECT id FROM ldap_configs
                WHERE is_enabled = true
                ORDER BY priority ASC, name ASC
                LIMIT 1
                "#,
            )
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            else {
                return Ok(None);
            };
            id
        }
    };

    let (row, bind_password) = match AuthConfigService::get_ldap_decrypted(db, id).await {
        Ok(value) => value,
        // A recorded provider that was deleted or is no longer enabled must
        // not fall through to a different directory: that would let a
        // directory the operator turned off keep authenticating users.
        Err(AppError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if !row.is_enabled {
        return Ok(None);
    }
    Ok(Some((row, bind_password)))
}

async fn check_login_budget(username: &str) -> Result<(), u64> {
    let Some(state) = rate_limit() else {
        // No router installed the shared limiter (unit tests, hand-built
        // middleware). Production always has it; an absent limiter must not
        // turn the passthrough off by itself.
        return Ok(());
    };
    if !state.inner.enabled {
        return Ok(());
    }
    if state.inner.exemptions.usernames.contains(username) {
        return Ok(());
    }
    let client_ip = current_client_ip();
    if let Some(ip) = client_ip {
        if state.inner.exemptions.is_trusted_cidr(ip) {
            return Ok(());
        }
    }
    let ip_key = client_ip
        .map(|ip| format!("ip:{ip}"))
        .unwrap_or_else(|| "ip:unknown".to_string());
    // Same order as `run_login_with_key` / `token_rate_limit_middleware`:
    // global backstop first, then the per-(username, IP) bucket.
    state.backstop.check_rate_limit("login:global").await?;
    state
        .inner
        .limiter
        .check_rate_limit(&login_rate_limit_key(username, &ip_key))
        .await?;
    Ok(())
}

/// `<8 hex>_<32 hex>`: the shape of an Artifact Keeper API token.
fn is_api_token_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 41
        && bytes[8] == b'_'
        && bytes[..8].iter().all(u8::is_ascii_hexdigit)
        && bytes[9..].iter().all(u8::is_ascii_hexdigit)
}

/// Three non-empty base64url segments with a JSON header: a compact JWS.
fn is_jwt_shape(value: &str) -> bool {
    let mut segments = value.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    let base64url = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    header.starts_with("eyJ") && base64url(header) && base64url(payload) && base64url(signature)
}

/// Whether a Basic password is a credential Artifact Keeper itself issues.
pub(crate) fn looks_like_issued_token(password: &str) -> bool {
    is_api_token_shape(password) || is_jwt_shape(password)
}

/// Try to authenticate a package-manager Basic credential against the
/// configured LDAP/AD provider.
///
/// Callers must have already tried bcrypt local auth, JWT-as-password, and
/// API-token-as-password. This function additionally checks the opt-in flag,
/// so it is safe to call unconditionally on the format surfaces.
pub(crate) async fn try_authenticate(
    auth_service: &AuthService,
    username: &str,
    password: &str,
    path: &str,
    method: &str,
) -> Outcome {
    #[cfg(test)]
    let settings = test_seam::settings_override().unwrap_or_else(Settings::from_env);
    #[cfg(not(test))]
    let settings = Settings::from_env();
    try_authenticate_with_settings(auth_service, username, password, path, method, settings).await
}

/// [`try_authenticate`] with explicit settings, for tests that cannot mutate
/// the process environment safely.
pub(crate) async fn try_authenticate_with_settings(
    auth_service: &AuthService,
    username: &str,
    password: &str,
    path: &str,
    method: &str,
    settings: Settings,
) -> Outcome {
    if !settings.enabled || username.is_empty() || password.is_empty() {
        return Outcome::Invalid;
    }
    // A credential Artifact Keeper issued (API token, JWT) reaches this point
    // only because it is expired, revoked or malformed. It is never sent to
    // the directory as a password: that would hand the token to a third
    // system and spend the account's directory failure budget.
    if looks_like_issued_token(password) {
        return Outcome::Invalid;
    }

    let tag = credential_tag(username, password);
    let (now, _flight) = loop {
        let now = Instant::now();
        let step = {
            let mut cache = cache().lock().unwrap_or_else(|e| e.into_inner());
            match cache.precheck(&tag, username, &settings, now) {
                Precheck::Proceed => Ok(cache.claim(&tag, username, &settings, now)),
                other => Err(other),
            }
        };
        let precheck = match step {
            Ok(Claim::Bind(flight)) => break (now, flight),
            Ok(Claim::Wait(gate)) => {
                // Wait for the in-flight bind of this exact credential, then
                // re-check: its result is normally cached by then.
                drop(gate.lock().await);
                continue;
            }
            Ok(Claim::TooManyFailures) => Precheck::TooManyFailures,
            Err(precheck) => precheck,
        };
        match precheck {
            Precheck::Cached(user_id) => {
                return revalidate_cached(auth_service, user_id, &tag, username, path, method)
                    .await;
            }
            Precheck::CachedFailure => {
                audit_failure(auth_service.db(), username, path, method, "cached_failure").await;
                return Outcome::Invalid;
            }
            Precheck::TooManyFailures => {
                audit_failure(
                    auth_service.db(),
                    username,
                    path,
                    method,
                    "failed_password_cap",
                )
                .await;
                return Outcome::Invalid;
            }
            Precheck::Proceed => unreachable!("Proceed is answered by a claim"),
        }
    };

    // Only an actual bind consumes the login budget. Cached hits above do not,
    // so a busy CI job cannot exhaust the bucket without touching the
    // directory.
    if let Err(retry_after) = check_login_budget(username).await {
        tracing::warn!(
            target: "security",
            username = %username,
            retry_after,
            "LDAP Basic-auth passthrough refused by the shared login limiter"
        );
        return Outcome::RateLimited(retry_after);
    }

    match authenticate_uncached(
        auth_service,
        username,
        password,
        &tag,
        path,
        method,
        &settings,
        now,
    )
    .await
    {
        Ok(user) => Outcome::Resolved(Box::new(user)),
        Err(AuthError::Invalid) => Outcome::Invalid,
        Err(AuthError::Unavailable) => Outcome::Unavailable,
    }
}

async fn revalidate_cached(
    auth_service: &AuthService,
    user_id: Uuid,
    tag: &Tag,
    username: &str,
    path: &str,
    method: &str,
) -> Outcome {
    match auth_service.load_active_user(user_id).await {
        Ok(user) if user.auth_provider == AuthProvider::Ldap => Outcome::Resolved(Box::new(user)),
        Ok(_) => {
            // The account was switched away from LDAP. Drop the positive
            // entry so a later switch back cannot resurrect the old password.
            cache()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .invalidate_user(user_id);
            audit_failure(
                auth_service.db(),
                username,
                path,
                method,
                "provider_changed",
            )
            .await;
            Outcome::Invalid
        }
        Err(AppError::Authentication(_)) => {
            // Missing or inactive: deactivation must win immediately.
            {
                let mut cache = cache().lock().unwrap_or_else(|e| e.into_inner());
                cache.remove_success(tag);
                cache.invalidate_user(user_id);
            }
            audit_failure(auth_service.db(), username, path, method, "inactive").await;
            Outcome::Invalid
        }
        Err(error) if error.is_db_unavailable() => Outcome::Unavailable,
        Err(error) => {
            tracing::error!(
                user_id = %user_id,
                error = %error,
                "Failed to re-check LDAP Basic-auth cache hit; refusing"
            );
            Outcome::Unavailable
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_uncached(
    auth_service: &AuthService,
    username: &str,
    password: &str,
    tag: &Tag,
    path: &str,
    method: &str,
    settings: &Settings,
    now: Instant,
) -> Result<User, AuthError> {
    let db = auth_service.db();
    let known = find_user_by_username(db, username)
        .await
        .map_err(|e| AuthError::from_app(&e))?;

    if let Some(known) = &known {
        // Never bind a local/SSO account's mistyped password against the
        // directory: it would spend the directory account's lockout budget
        // for a credential that was never meant to work there.
        if known.auth_provider != "ldap" {
            return Err(AuthError::Invalid);
        }
        if !known.is_active {
            invalidate_user(known.id);
            audit_failure(db, username, path, method, "inactive").await;
            return Err(AuthError::Invalid);
        }
    }

    let Some((row, bind_password)) =
        load_enabled_provider(db, known.as_ref().and_then(|u| u.ldap_provider_id))
            .await
            .map_err(|e| AuthError::from_app(&e))?
    else {
        tracing::debug!(
            username = %username,
            "LDAP Basic-auth passthrough found no enabled provider"
        );
        return Err(AuthError::Invalid);
    };

    let ldap_service =
        AuthConfigService::ldap_service_from_row(db.clone(), &row, bind_password.as_deref());
    let ldap_user = match ldap_service.authenticate(username, password).await {
        Ok(user) => user,
        Err(error) => {
            let mapped = AuthError::from_app(&error);
            if mapped == AuthError::Invalid {
                record_failure(tag, username, known.as_ref().map(|u| u.id), settings, now);
                audit_failure(db, username, path, method, "bad_password").await;
            }
            return Err(mapped);
        }
    };

    let user = sync_directory_user(auth_service, &ldap_service, &row, &ldap_user).await?;

    record_success(tag, user.id, settings, Instant::now());
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear_failures_for_username(username);
    audit_success(db, &user, path, method).await;
    Ok(user)
}

async fn sync_directory_user(
    auth_service: &AuthService,
    ldap_service: &LdapService,
    row: &LdapConfigRow,
    ldap_user: &LdapUserInfo,
) -> Result<User, AuthError> {
    let db = auth_service.db();

    // The username lookup above covers the usual case, but a renamed account
    // is matched by its stable DN. Reject a deactivated row here too, before
    // the federated sync: an admin disable must stay effective for package
    // clients (#4933), and this check also covers the window before the sync's
    // own `is_active` preservation runs.
    let existing_by_dn = sqlx::query_as::<_, (Uuid, bool)>(
        "SELECT id, is_active FROM users WHERE external_id = $1 AND auth_provider = 'ldap'",
    )
    .bind(&ldap_user.dn)
    .fetch_optional(db)
    .await
    .map_err(|e| AuthError::from_app(&AppError::Database(e.to_string())))?;
    if let Some((id, false)) = existing_by_dn {
        invalidate_user(id);
        return Err(AuthError::Invalid);
    }

    let credentials = FederatedCredentials {
        external_id: ldap_user.dn.clone(),
        username: ldap_user.username.clone(),
        email: ldap_user.email.clone(),
        display_name: ldap_user.display_name.clone(),
        groups: ldap_user.groups.clone(),
        required_admin_group: row.admin_group_dn.clone(),
        // LDAP has no per-provider auto-create switch; login always
        // provisions, and the passthrough keeps that behaviour (#2057).
        auto_create_users: true,
    };
    let user = auth_service
        .sync_federated_user(AuthProvider::Ldap, &credentials)
        .await
        .map_err(|e| AuthError::from_app(&e))?;
    if !user.is_active {
        invalidate_user(user.id);
        return Err(AuthError::Invalid);
    }

    // Match the SSO LDAP login's last-login bookkeeping. Display-only and
    // throttled to once per five minutes; a failure must not fail the login.
    if let Err(error) = sqlx::query(
        "UPDATE users SET last_login_at = NOW() \
         WHERE id = $1 \
           AND (last_login_at IS NULL OR last_login_at < NOW() - INTERVAL '5 minutes')",
    )
    .bind(user.id)
    .execute(db)
    .await
    {
        tracing::warn!(
            user_id = %user.id,
            error = %error,
            "Failed to update last_login_at for a Basic-auth passthrough login"
        );
    }

    // Remember the provider for the periodic reconcile, exactly as the LDAP
    // login handler does. Non-fatal: the bind succeeded.
    if let Err(error) =
        crate::services::ldap_sync_service::record_ldap_provider(db, user.id, row.id).await
    {
        tracing::warn!(
            user_id = %user.id,
            provider_id = %row.id,
            error = %error,
            "Failed to record the LDAP provider for a Basic-auth passthrough login"
        );
    }

    if ldap_service.group_sync_configured() {
        let group_names = ldap_service
            .resolve_group_names(&ldap_user.dn, &ldap_user.username, &ldap_user.groups)
            .await;
        if let Err(error) = crate::api::handlers::sso::sync_federated_groups_to_local_groups(
            db,
            user.id,
            row.id,
            "ldap",
            &group_names,
        )
        .await
        {
            tracing::warn!(
                user_id = %user.id,
                provider_id = %row.id,
                error = %error,
                "Failed to sync LDAP groups for a Basic-auth passthrough login"
            );
        }
    }

    Ok(user)
}

fn record_success(tag: &Tag, user_id: Uuid, settings: &Settings, now: Instant) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .record_success(*tag, user_id, settings, now);
}

fn record_failure(
    tag: &Tag,
    username: &str,
    user_id: Option<Uuid>,
    settings: &Settings,
    now: Instant,
) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .record_failure(*tag, username, user_id, settings, now);
}

/// Clear every passthrough cache entry belonging to `user_id`.
///
/// Wired into
/// [`crate::services::auth_service::invalidate_user_token_cache_entries`], the
/// one function every deactivation and delete path already calls, so an admin
/// flip and a directory reconcile both invalidate immediately.
pub fn invalidate_user(user_id: Uuid) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .invalidate_user(user_id);
}

async fn audit_success(db: &PgPool, user: &User, path: &str, method: &str) {
    let entry = AuditEntry::new(AuditAction::Login, ResourceType::User)
        .user(user.id)
        .resource(user.id)
        .actor_name(user.username.clone())
        .with_request_client_ip()
        .details(federated_login_details(
            "ldap",
            serde_json::json!({
                "username": user.username,
                "auth_method": "basic",
                "surface": "package-manager",
                "path": path,
                "method": method,
            }),
        ));
    audit_fire_and_forget(db.clone(), entry).await;
}

async fn audit_failure(db: &PgPool, username: &str, path: &str, method: &str, reason: &str) {
    let entry = AuditEntry::new(AuditAction::LoginFailed, ResourceType::User)
        .actor_name(username.to_string())
        .with_request_client_ip()
        .details_typed(AuthDetails {
            username: Some(username.to_string()),
            path: Some(path.to_string()),
            method: Some(method.to_string()),
            reason: Some(reason.to_string()),
            provider: Some("ldap".to_string()),
            auth_method: Some("basic".to_string()),
        });
    audit_fire_and_forget(db.clone(), entry).await;
}

/// Test seam: settings a `#[tokio::test]` (current-thread runtime) pins for
/// the middleware entry point, instead of mutating the process environment
/// that parallel tests share.
#[cfg(test)]
pub(crate) mod test_seam {
    use super::Settings;

    thread_local! {
        static SETTINGS_OVERRIDE: std::cell::Cell<Option<Settings>> =
            const { std::cell::Cell::new(None) };
    }

    pub(crate) fn settings_override() -> Option<Settings> {
        SETTINGS_OVERRIDE.with(|cell| cell.get())
    }

    /// Pins `settings` on this thread until dropped.
    #[allow(dead_code)]
    pub(crate) struct SettingsOverride;

    #[allow(dead_code)]
    impl SettingsOverride {
        pub(crate) fn set(settings: Settings) -> Self {
            SETTINGS_OVERRIDE.with(|cell| cell.set(Some(settings)));
            Self
        }
    }

    impl Drop for SettingsOverride {
        fn drop(&mut self) {
            SETTINGS_OVERRIDE.with(|cell| cell.set(None));
        }
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            enabled: true,
            ..Settings::default()
        }
    }

    #[test]
    fn test_defaults_are_off_and_conservative() {
        let default = Settings::default();
        assert!(!default.enabled, "passthrough must be opt-in");
        assert_eq!(default.success_ttl, Duration::from_secs(300));
        assert_eq!(default.max_failed_passwords, 3);
        assert_eq!(parse_settings(None, None, None, None, None, None), default);
        assert!(!parse_settings(Some("false"), None, None, None, None, None).enabled);
        assert!(!parse_settings(Some("0"), None, None, None, None, None).enabled);
        assert!(parse_settings(Some("TRUE"), None, None, None, None, None).enabled);
        assert!(parse_settings(Some("1"), None, None, None, None, None).enabled);
    }

    #[test]
    fn test_parse_overrides_and_zero_semantics() {
        let parsed = parse_settings(
            Some("true"),
            Some("0"),
            Some("5"),
            Some("0"),
            Some("60"),
            Some("100"),
        );
        assert!(parsed.enabled);
        assert!(parsed.success_ttl.is_zero());
        assert_eq!(parsed.failure_ttl, Duration::from_secs(5));
        assert_eq!(parsed.max_failed_passwords, 0);
        assert_eq!(parsed.failed_window, Duration::from_secs(60));
        assert_eq!(parsed.max_cache_entries, 100);
    }

    #[test]
    fn test_credential_tag_is_domain_separated_and_length_prefixed() {
        let key = [7u8; 32];
        assert_ne!(
            credential_tag_with_key(&key, "ab", "c"),
            credential_tag_with_key(&key, "a", "bc"),
            "length prefix must prevent a boundary collision"
        );
        assert_ne!(
            credential_tag_with_key(&key, "alice", "pw"),
            credential_tag_with_key(&key, "Alice", "pw"),
            "usernames are case-sensitive at the auth layer"
        );
        assert_eq!(
            credential_tag_with_key(&key, "alice", "pw"),
            credential_tag_with_key(&key, "alice", "pw")
        );
    }

    #[test]
    fn test_success_cache_round_trip_and_ttl() {
        let mut cache = Cache::default();
        let s = settings();
        let tag = credential_tag_with_key(b"k", "alice", "correct");
        let user_id = Uuid::new_v4();
        let now = Instant::now();

        assert_eq!(cache.precheck(&tag, "alice", &s, now), Precheck::Proceed);
        cache.record_success(tag, user_id, &s, now);
        assert_eq!(
            cache.precheck(&tag, "alice", &s, now + Duration::from_secs(1)),
            Precheck::Cached(user_id)
        );
        assert_eq!(
            cache.precheck(&tag, "alice", &s, now + s.success_ttl),
            Precheck::Proceed,
            "entry expires exactly at the TTL"
        );
        assert_eq!(cache.success_len(), 0, "expired entry is pruned");
    }

    #[test]
    fn test_failure_cache_and_distinct_password_cap() {
        let mut cache = Cache::default();
        let s = settings();
        let now = Instant::now();
        let user_id = Some(Uuid::new_v4());

        for password in ["one", "two"] {
            let tag = credential_tag_with_key(b"k", "alice", password);
            assert_eq!(cache.precheck(&tag, "alice", &s, now), Precheck::Proceed);
            cache.record_failure(tag, "alice", user_id, &s, now);
        }
        assert_eq!(cache.failure_len(), 2);

        // The same rejected password is answered from the failure cache.
        let repeated = credential_tag_with_key(b"k", "alice", "one");
        assert_eq!(
            cache.precheck(&repeated, "alice", &s, now),
            Precheck::CachedFailure
        );

        // A third distinct failure is still allowed; a fourth is not bound.
        let third = credential_tag_with_key(b"k", "alice", "three");
        assert_eq!(cache.precheck(&third, "alice", &s, now), Precheck::Proceed);
        cache.record_failure(third, "alice", user_id, &s, now);
        let fourth = credential_tag_with_key(b"k", "alice", "four");
        assert_eq!(
            cache.precheck(&fourth, "alice", &s, now),
            Precheck::TooManyFailures
        );

        // AD usernames are case-insensitive. A case variant must not mint a
        // fresh budget against the same account.
        let case_variant = credential_tag_with_key(b"k", "ALICE", "four");
        assert_eq!(
            cache.precheck(&case_variant, "ALICE", &s, now),
            Precheck::TooManyFailures
        );

        // A different username has its own budget.
        let bob = credential_tag_with_key(b"k", "bob", "four");
        assert_eq!(cache.precheck(&bob, "bob", &s, now), Precheck::Proceed);
    }

    #[test]
    fn test_failure_window_expires_the_cap() {
        let mut cache = Cache::default();
        let s = Settings {
            max_failed_passwords: 1,
            failed_window: Duration::from_secs(10),
            failure_ttl: Duration::from_secs(1),
            ..settings()
        };
        let now = Instant::now();
        let first = credential_tag_with_key(b"k", "alice", "one");
        cache.record_failure(first, "alice", None, &s, now);
        let second = credential_tag_with_key(b"k", "alice", "two");
        assert_eq!(
            cache.precheck(&second, "alice", &s, now + Duration::from_secs(1)),
            Precheck::TooManyFailures
        );
        assert_eq!(
            cache.precheck(&second, "alice", &s, now + Duration::from_secs(10)),
            Precheck::Proceed,
            "the distinct-failure window expires"
        );
    }

    #[test]
    fn test_invalidate_user_clears_success_and_failure_caches() {
        let mut cache = Cache::default();
        let s = settings();
        let now = Instant::now();
        let user_id = Uuid::new_v4();
        let good = credential_tag_with_key(b"k", "alice", "good");
        let bad = credential_tag_with_key(b"k", "alice", "bad");
        cache.record_success(good, user_id, &s, now);
        cache.record_failure(bad, "alice", Some(user_id), &s, now);
        assert_eq!(cache.success_len(), 1);
        assert_eq!(cache.failure_len(), 1);

        cache.invalidate_user(user_id);
        assert_eq!(cache.success_len(), 0);
        assert_eq!(cache.failure_len(), 0);
        assert!(!cache.failures_by_username.contains_key("alice"));
        assert_eq!(cache.precheck(&good, "alice", &s, now), Precheck::Proceed);
    }

    #[test]
    fn test_cache_is_bounded() {
        let mut cache = Cache::default();
        let s = Settings {
            max_cache_entries: 2,
            ..settings()
        };
        let now = Instant::now();
        for index in 0..5 {
            let tag = credential_tag_with_key(b"k", "alice", &format!("pw{index}"));
            cache.record_failure(tag, "alice", None, &s, now);
            assert!(cache.failure_len() <= 2);
        }
    }

    // -----------------------------------------------------------------------
    // End-to-end against a scripted directory. These use the developer's
    // `artifact_registry` database (via the shared test pool) and skip when
    // the instance has no encryption key configured, like the other LDAP
    // suites.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers;
    use crate::services::auth_config_service::CreateLdapConfigRequest;
    use crate::services::ldap_service::tests::{
        spawn_mock_directory, MockDirectory, MOCK_SERVICE_DN,
    };

    const BASE: &str = "dc=example,dc=com";

    fn encryption_key_available() -> bool {
        std::env::var("SSO_ENCRYPTION_KEY").is_ok() || std::env::var("JWT_SECRET").is_ok()
    }

    async fn create_provider(pool: &PgPool, name: &str, port: u16) -> Uuid {
        AuthConfigService::create_ldap(
            pool,
            CreateLdapConfigRequest {
                name: name.into(),
                server_url: format!("ldap://127.0.0.1:{port}"),
                bind_dn: Some(MOCK_SERVICE_DN.into()),
                bind_password: Some("svc-secret".into()),
                user_base_dn: BASE.into(),
                user_filter: Some("(uid={0})".into()),
                group_base_dn: None,
                group_filter: None,
                email_attribute: None,
                display_name_attribute: None,
                username_attribute: None,
                groups_attribute: None,
                admin_group_dn: None,
                use_starttls: None,
                insecure_skip_verify: None,
                ca_certificate: None,
                is_enabled: Some(true),
                priority: Some(0),
            },
        )
        .await
        .expect("create provider")
        .id
    }

    async fn cleanup(pool: &PgPool, provider_id: Uuid, username: &str) {
        let _ = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(username)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM ldap_configs WHERE id = $1")
            .bind(provider_id)
            .execute(pool)
            .await;
    }

    /// Pin the provider on the account so the test is not at the mercy of
    /// other enabled providers another test may have left in the shared
    /// database. This also matches the production steady state: a directory
    /// user is recorded with the provider that created them.
    async fn insert_known_user(pool: &PgPool, username: &str, dn: &str, provider_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, email, auth_provider, external_id, is_active, \
             is_admin, ldap_provider_id) \
             VALUES ($1, $2, $3, 'ldap'::auth_provider, $4, true, false, $5)",
        )
        .bind(id)
        .bind(username)
        .bind(format!("{username}@example.com"))
        .bind(dn)
        .bind(provider_id)
        .execute(pool)
        .await
        .expect("insert known user");
        id
    }

    #[tokio::test]
    async fn test_passthrough_binds_provisions_and_honours_deactivation() {
        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };

        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("ldapbasic{suffix}");
        let dn = format!("uid={username},ou=people,{BASE}");
        let ops: crate::services::ldap_service::tests::OpsLog = Default::default();
        let port = spawn_mock_directory(MockDirectory {
            service_dn: MOCK_SERVICE_DN.to_string(),
            entry: Some((
                dn.clone(),
                username.clone(),
                format!("{username}@example.com"),
            )),
            user_bind_rc: 0x00,
            ops: ops.clone(),
        })
        .await;
        let provider_id = create_provider(&pool, &format!("basic-{suffix}"), port).await;
        let user_id = insert_known_user(&pool, &username, &dn, provider_id).await;
        let auth = AuthService::new(
            pool.clone(),
            std::sync::Arc::new(crate::config::Config::test_config()),
        );
        let settings = Settings {
            enabled: true,
            ..Settings::default()
        };

        match try_authenticate_with_settings(
            &auth,
            &username,
            "correct-password",
            "/npm/private/pkg",
            "GET",
            settings,
        )
        .await
        {
            Outcome::Resolved(user) => {
                assert_eq!(user.username, username);
                assert_eq!(user.auth_provider, AuthProvider::Ldap);
                assert!(user.is_active);
            }
            other => panic!("expected Resolved, got {other:?}"),
        }

        let row: (String, Option<String>, Option<Uuid>) = sqlx::query_as(
            "SELECT auth_provider::text, external_id, ldap_provider_id FROM users WHERE username = $1",
        )
        .bind(&username)
        .fetch_one(&pool)
        .await
        .expect("provisioned user");
        assert_eq!(row.0, "ldap");
        assert_eq!(row.1.as_deref(), Some(dn.as_str()));
        assert_eq!(row.2, Some(provider_id));

        let binds = |ops: &std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>| {
            ops.lock()
                .unwrap()
                .iter()
                .filter(|op| **op == "bind")
                .count()
        };
        assert_eq!(binds(&ops), 1, "the first login binds exactly once");

        // A second request with the same credential is served from the
        // success cache and must not bind again.
        assert!(matches!(
            try_authenticate_with_settings(
                &auth,
                &username,
                "correct-password",
                "/npm/private/pkg",
                "GET",
                settings,
            )
            .await,
            Outcome::Resolved(_)
        ));
        assert_eq!(binds(&ops), 1, "a cache hit must not bind");

        // An admin deactivation clears the positive entry and must win on the
        // very next request, without another bind being needed to discover it.
        sqlx::query("UPDATE users SET is_active = false WHERE username = $1")
            .bind(&username)
            .execute(&pool)
            .await
            .expect("deactivate");
        crate::services::auth_service::invalidate_user_token_cache_entries(user_id);
        assert!(matches!(
            try_authenticate_with_settings(
                &auth,
                &username,
                "correct-password",
                "/npm/private/pkg",
                "GET",
                settings,
            )
            .await,
            Outcome::Invalid
        ));
        assert_eq!(binds(&ops), 1, "a deactivated cache hit must not bind");

        cleanup(&pool, provider_id, &username).await;
    }

    #[tokio::test]
    async fn test_distinct_failure_cap_stops_binding() {
        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };

        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("ldapcap{suffix}");
        let dn = format!("uid={username},ou=people,{BASE}");
        let ops: crate::services::ldap_service::tests::OpsLog = Default::default();
        let port = spawn_mock_directory(MockDirectory {
            service_dn: MOCK_SERVICE_DN.to_string(),
            entry: Some((
                dn.clone(),
                username.clone(),
                format!("{username}@example.com"),
            )),
            user_bind_rc: 0x31, // invalidCredentials
            ops: ops.clone(),
        })
        .await;
        let provider_id = create_provider(&pool, &format!("cap-{suffix}"), port).await;
        insert_known_user(&pool, &username, &dn, provider_id).await;
        let auth = AuthService::new(
            pool.clone(),
            std::sync::Arc::new(crate::config::Config::test_config()),
        );
        let settings = Settings {
            enabled: true,
            max_failed_passwords: 3,
            ..Settings::default()
        };

        for password in ["wrong-one", "wrong-two", "wrong-three"] {
            assert!(matches!(
                try_authenticate_with_settings(
                    &auth,
                    &username,
                    password,
                    "/composer/private/pkg",
                    "GET",
                    settings,
                )
                .await,
                Outcome::Invalid
            ));
        }
        let binds = ops
            .lock()
            .unwrap()
            .iter()
            .filter(|op| **op == "bind")
            .count();
        assert_eq!(binds, 3, "each distinct password gets exactly one bind");

        // The fourth distinct password fails fast: the AD lockout budget is
        // not spent again.
        assert!(matches!(
            try_authenticate_with_settings(
                &auth,
                &username,
                "wrong-four",
                "/composer/private/pkg",
                "GET",
                settings,
            )
            .await,
            Outcome::Invalid
        ));
        let binds_after = ops
            .lock()
            .unwrap()
            .iter()
            .filter(|op| **op == "bind")
            .count();
        assert_eq!(binds_after, 3, "the cap must short-circuit before binding");

        cleanup(&pool, provider_id, &username).await;
    }

    // -----------------------------------------------------------------------
    // Directory lockout guard, issued-token refusal, outage mapping.
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejected_credential_is_not_rebound_inside_the_window() {
        let mut cache = Cache::default();
        let s = settings();
        let now = Instant::now();
        let tag = credential_tag_with_key(b"k", "alice", "wrong");
        cache.record_failure(tag, "alice", None, &s, now);
        // After the short exact-credential TTL lapses the same rejected
        // password must still not reach the directory again: re-binding it
        // every minute would walk the account into lockout without ever
        // tripping the distinct-password cap.
        let later = now + s.failure_ttl + Duration::from_secs(1);
        assert!(later < now + s.failed_window);
        assert_eq!(
            cache.precheck(&tag, "alice", &s, later),
            Precheck::CachedFailure
        );
        assert_eq!(
            cache.precheck(&tag, "alice", &s, now + s.failed_window),
            Precheck::Proceed,
            "the ledger entry expires with the failure window"
        );
    }

    #[test]
    fn test_default_failure_window_covers_a_typical_directory_window() {
        assert!(
            Settings::default().failed_window >= Duration::from_secs(1800),
            "AK must not forget failures before a 30 minute directory window does"
        );
    }

    #[test]
    fn test_claim_single_flights_and_counts_in_flight_guesses() {
        let mut cache = Cache::default();
        let s = settings();
        let now = Instant::now();
        let tags: Vec<Tag> = ["a", "b", "c", "d"]
            .iter()
            .map(|p| credential_tag_with_key(b"k", "alice", p))
            .collect();

        let first = cache.claim(&tags[0], "alice", &s, now);
        assert!(matches!(first, Claim::Bind(_)));
        // The same credential in parallel waits for the one bind.
        assert!(matches!(
            cache.claim(&tags[0], "alice", &s, now),
            Claim::Wait(_)
        ));
        // Distinct credentials in flight count toward the cap before any of
        // them has failed.
        let second = cache.claim(&tags[1], "ALICE", &s, now);
        assert!(matches!(second, Claim::Bind(_)));
        let third = cache.claim(&tags[2], "alice", &s, now);
        assert!(matches!(third, Claim::Bind(_)));
        assert!(matches!(
            cache.claim(&tags[3], "alice", &s, now),
            Claim::TooManyFailures
        ));
        // Another username is unaffected.
        let bob = credential_tag_with_key(b"k", "bob", "a");
        assert!(matches!(cache.claim(&bob, "bob", &s, now), Claim::Bind(_)));
        drop((first, second, third));
    }

    #[test]
    fn test_failure_ledger_is_never_cleared_wholesale() {
        let mut cache = Cache::default();
        let s = Settings {
            max_cache_entries: 2,
            ..settings()
        };
        let bound = 2 * FAILURE_LEDGER_BOUND_FACTOR;
        let now = Instant::now();
        for index in 0..bound {
            let user = format!("other{index}");
            let tag = credential_tag_with_key(b"k", &user, "x");
            cache.record_failure(tag, &user, None, &s, now);
        }
        let later = now + Duration::from_secs(1);
        for password in ["one", "two", "three"] {
            let tag = credential_tag_with_key(b"k", "victim", password);
            cache.record_failure(tag, "victim", None, &s, later);
        }
        // Overflowing the ledger evicts the oldest usernames; it does not
        // hand the capped username a fresh budget.
        let flood = credential_tag_with_key(b"k", "flood", "x");
        cache.record_failure(flood, "flood", None, &s, later + Duration::from_secs(1));
        assert!(cache.failures_by_username.len() <= bound);
        let fourth = credential_tag_with_key(b"k", "victim", "four");
        assert_eq!(
            cache.precheck(&fourth, "victim", &s, later + Duration::from_secs(2)),
            Precheck::TooManyFailures
        );
    }

    /// An unknown API-token-shaped value, generated so no literal lands in
    /// the source.
    fn fake_api_token() -> String {
        let id = Uuid::new_v4().simple().to_string();
        format!("{}_{}", &id[..8], Uuid::new_v4().simple())
    }

    /// A compact-JWS-shaped value with a random, unverifiable signature.
    fn fake_jwt() -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            b64.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
            b64.encode(format!(r#"{{"sub":"{}"}}"#, Uuid::new_v4())),
            b64.encode(Uuid::new_v4().as_bytes()),
        )
    }

    #[test]
    fn test_issued_token_shapes_are_recognised() {
        assert!(looks_like_issued_token(&fake_api_token()));
        assert!(looks_like_issued_token(&fake_jwt()));
        for password in [
            "Correct horse battery staple",
            "P@ssw0rd!",
            "eyJ-but-no-dots",
            "a.b.c",
            "0123abcd_short",
        ] {
            assert!(!looks_like_issued_token(password), "{password}");
        }
    }

    fn count(ops: &crate::services::ldap_service::tests::OpsLog, op: &str) -> usize {
        ops.lock().unwrap().iter().filter(|o| **o == op).count()
    }

    async fn scripted_directory(
        username: &str,
        dn: &str,
        user_bind_rc: u8,
    ) -> (u16, crate::services::ldap_service::tests::OpsLog) {
        let ops: crate::services::ldap_service::tests::OpsLog = Default::default();
        let port = spawn_mock_directory(MockDirectory {
            service_dn: MOCK_SERVICE_DN.to_string(),
            entry: Some((
                dn.to_string(),
                username.to_string(),
                format!("{username}@example.com"),
            )),
            user_bind_rc,
            ops: ops.clone(),
        })
        .await;
        (port, ops)
    }

    fn test_auth_service(pool: &PgPool) -> AuthService {
        AuthService::new(
            pool.clone(),
            std::sync::Arc::new(crate::config::Config::test_config()),
        )
    }

    /// The format-route resolver: a directory credential resolves only
    /// through the passthrough, a local account's wrong password is never
    /// sent to the directory, and an expired AK token in the password field
    /// is never sent either.
    #[tokio::test]
    async fn test_format_resolver_passthrough_ordering() {
        use crate::api::middleware::auth::{
            try_resolve_auth_outcome_with_passthrough, AuthOutcome, ExtractedToken,
        };
        use base64::Engine as _;

        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let dir_user = format!("ldapfmt{suffix}");
        let local_user = format!("localfmt{suffix}");
        let dn = format!("uid={dir_user},ou=people,{BASE}");
        // The directory accepts ANY password for both names, so a refusal
        // below can only come from AK's own guards.
        let (port, ops) = scripted_directory(&dir_user, &dn, 0x00).await;
        let provider_id = create_provider(&pool, &format!("fmt-{suffix}"), port).await;
        insert_known_user(&pool, &dir_user, &dn, provider_id).await;
        let local_hash = AuthService::hash_password("Local!Secret9").await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_active, is_admin) \
             VALUES ($1, $2, $3, $4, 'local', true, false)",
        )
        .bind(Uuid::new_v4())
        .bind(&local_user)
        .bind(format!("{local_user}@example.com"))
        .bind(&local_hash)
        .execute(&pool)
        .await
        .expect("insert local user");
        let auth = test_auth_service(&pool);
        let _pin = test_seam::SettingsOverride::set(settings());
        let basic = |user: &str, pass: &str| {
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        };

        // A directory user's directory password authenticates the format route.
        let encoded = basic(&dir_user, "directory-password");
        match try_resolve_auth_outcome_with_passthrough(
            &auth,
            ExtractedToken::Basic(&encoded),
            true,
            "/pypi/private/simple/",
            "GET",
        )
        .await
        {
            AuthOutcome::Resolved(ext) => assert_eq!(ext.username, dir_user),
            other => panic!("expected the passthrough to resolve, got {other:?}"),
        }
        assert_eq!(count(&ops, "bind"), 1);

        // The management API surface (`allow_basic_api_token = false`) never
        // runs the passthrough.
        let encoded = basic(&dir_user, "another-password");
        assert!(matches!(
            try_resolve_auth_outcome_with_passthrough(
                &auth,
                ExtractedToken::Basic(&encoded),
                false,
                "/api/v1/repositories",
                "GET",
            )
            .await,
            AuthOutcome::InvalidCredential
        ));
        assert_eq!(count(&ops, "bind"), 1);

        // A local account with a different password: no bind, no login,
        // whatever case the client sends.
        let connects_before = count(&ops, "connect");
        for name in [local_user.clone(), local_user.to_uppercase()] {
            let encoded = basic(&name, "directory-password");
            assert!(matches!(
                try_resolve_auth_outcome_with_passthrough(
                    &auth,
                    ExtractedToken::Basic(&encoded),
                    true,
                    "/pypi/private/simple/",
                    "GET",
                )
                .await,
                AuthOutcome::InvalidCredential
            ));
        }
        assert_eq!(
            count(&ops, "connect"),
            connects_before,
            "a local account's username must never reach the directory"
        );

        // The local account still works with its own password.
        let encoded = basic(&local_user, "Local!Secret9");
        assert!(matches!(
            try_resolve_auth_outcome_with_passthrough(
                &auth,
                ExtractedToken::Basic(&encoded),
                true,
                "/pypi/private/simple/",
                "GET",
            )
            .await,
            AuthOutcome::Resolved(_)
        ));

        // A revoked/unknown API token or an expired JWT in the password field
        // is refused without contacting the directory.
        let api_token = fake_api_token();
        let jwt = fake_jwt();
        for password in [api_token.as_str(), jwt.as_str()] {
            let encoded = basic(&dir_user, password);
            assert!(matches!(
                try_resolve_auth_outcome_with_passthrough(
                    &auth,
                    ExtractedToken::Basic(&encoded),
                    true,
                    "/pypi/private/simple/",
                    "GET",
                )
                .await,
                AuthOutcome::InvalidCredential
            ));
        }
        assert_eq!(
            count(&ops, "connect"),
            connects_before,
            "an AK-issued token must never be sent to the directory"
        );

        let _ = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(&local_user)
            .execute(&pool)
            .await;
        cleanup(&pool, provider_id, &dir_user).await;
    }

    /// Inner package-route auth for the guest-guard regression below: exactly
    /// what `repo_visibility_middleware` does with a Basic credential, minus
    /// the repository lookup.
    async fn package_route_auth(
        axum::extract::State(auth): axum::extract::State<std::sync::Arc<AuthService>>,
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        use crate::api::middleware::auth::{
            extract_visibility_token, try_resolve_auth_outcome_with_passthrough, AuthOutcome,
        };
        use axum::response::IntoResponse;

        let extracted = extract_visibility_token(&request);
        let outcome = try_resolve_auth_outcome_with_passthrough(
            &auth,
            extracted,
            true,
            request.uri().path(),
            request.method().as_str(),
        )
        .await;
        match outcome {
            AuthOutcome::Resolved(_) => next.run(request).await,
            _ => axum::http::StatusCode::UNAUTHORIZED.into_response(),
        }
    }

    async fn poll_login_failed(pool: &PgPool, username: &str) -> i64 {
        let mut last = 0;
        for _ in 0..100 {
            last = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_log \
                 WHERE action = 'LOGIN_FAILED' AND details->>'username' = $1",
            )
            .bind(username)
            .fetch_one(pool)
            .await
            .expect("count LOGIN_FAILED rows");
            if last > 0 {
                return last;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        last
    }

    /// #4933 items 1 and 2: with guest access off, the global guard must not
    /// bind against the directory. It defers a package-route Basic credential
    /// to the route middleware (one bind, one LOGIN_FAILED row) and answers
    /// management/Oci requests itself (no bind, no audit row).
    #[tokio::test]
    async fn test_guest_guard_does_not_bind_and_keeps_one_login_failed_row() {
        use crate::api::middleware::guest_access::{guest_access_guard, GuestAccessState};
        use crate::services::guest_access_policy::GuestAccessPolicy;
        use axum::body::Body;
        use axum::http::header::AUTHORIZATION;
        use axum::http::{Request as HttpRequest, StatusCode};
        use axum::middleware::from_fn_with_state;
        use axum::routing::get;
        use axum::Router;
        use base64::Engine as _;
        use tower::ServiceExt;

        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let denied_user = format!("ldapguarddenied{suffix}");
        let allowed_user = format!("ldapguardallowed{suffix}");
        let local_user = format!("localguard{suffix}");
        let denied_dn = format!("uid={denied_user},ou=people,{BASE}");
        let allowed_dn = format!("uid={allowed_user},ou=people,{BASE}");
        let (denied_port, denied_ops) = scripted_directory(&denied_user, &denied_dn, 0x31).await;
        let (allowed_port, allowed_ops) =
            scripted_directory(&allowed_user, &allowed_dn, 0x00).await;
        let denied_provider =
            create_provider(&pool, &format!("guard-denied-{suffix}"), denied_port).await;
        let allowed_provider =
            create_provider(&pool, &format!("guard-allowed-{suffix}"), allowed_port).await;
        insert_known_user(&pool, &denied_user, &denied_dn, denied_provider).await;
        insert_known_user(&pool, &allowed_user, &allowed_dn, allowed_provider).await;
        let local_hash = AuthService::hash_password("Local!Secret9").await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_active, is_admin) \
             VALUES ($1, $2, $3, $4, 'local', true, false)",
        )
        .bind(Uuid::new_v4())
        .bind(&local_user)
        .bind(format!("{local_user}@example.com"))
        .bind(&local_hash)
        .execute(&pool)
        .await
        .expect("insert local user");

        let auth = std::sync::Arc::new(test_auth_service(&pool));
        let app = Router::new()
            .route("/pypi/private/simple/pkg/", get(|| async { "package" }))
            .route(
                "/api/v1/repositories/private/download/pkg.whl",
                get(|| async { "download" }),
            )
            .route("/api/v1/repositories", get(|| async { "repos" }))
            .route(
                "/v2/library/nginx/manifests/latest",
                get(|| async { "manifest" }),
            )
            .layer(from_fn_with_state(auth.clone(), package_route_auth))
            .layer(from_fn_with_state(
                GuestAccessState {
                    policy: std::sync::Arc::new(GuestAccessPolicy::fixed(false)),
                    auth_service: auth.clone(),
                },
                guest_access_guard,
            ));
        let basic = |user: &str, pass: &str| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
            )
        };
        let _pin = test_seam::SettingsOverride::set(settings());

        // The management API and OCI answer the local decision: 401, no
        // directory connection, no LOGIN_FAILED row.
        for uri in ["/api/v1/repositories", "/v2/library/nginx/manifests/latest"] {
            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(uri)
                        .header(AUTHORIZATION, basic(&allowed_user, "directory-password"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
        assert_eq!(
            count(&allowed_ops, "connect"),
            0,
            "the guest guard must not reach the directory for management/Oci"
        );
        assert_eq!(
            poll_login_failed(&pool, &allowed_user).await,
            0,
            "the guard must not write a package-manager LOGIN_FAILED row"
        );

        // A wrong password on a package route: the guard defers, the package
        // middleware performs the one bind, and exactly one LOGIN_FAILED row
        // is written (not one from the guard plus one from the passthrough).
        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/pypi/private/simple/pkg/")
                    .header(AUTHORIZATION, basic(&denied_user, "wrong-password"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            count(&denied_ops, "bind"),
            1,
            "one bind, from the package route"
        );
        assert_eq!(
            poll_login_failed(&pool, &denied_user).await,
            1,
            "one rejected request must write exactly one LOGIN_FAILED row"
        );

        // Repeating the rejected credential is refused without another bind.
        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/pypi/private/simple/pkg/")
                    .header(AUTHORIZATION, basic(&denied_user, "wrong-password"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            count(&denied_ops, "bind"),
            1,
            "the failure window must not re-bind the rejected password"
        );

        // A local username with a directory-shaped password is refused by the
        // package route without a directory connection, and the generic
        // download route (also managed under /api/v1) still defers correctly.
        let connects_before = count(&denied_ops, "connect") + count(&allowed_ops, "connect");
        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/pypi/private/simple/pkg/")
                    .header(AUTHORIZATION, basic(&local_user, "directory-password"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            count(&denied_ops, "connect") + count(&allowed_ops, "connect"),
            connects_before,
            "a local account's username must never reach the directory"
        );

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/repositories/private/download/pkg.whl")
                    .header(AUTHORIZATION, basic(&allowed_user, "directory-password"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the generic download route must still run the passthrough under guest-off"
        );

        let _ = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(&local_user)
            .execute(&pool)
            .await;
        cleanup(&pool, denied_provider, &denied_user).await;
        cleanup(&pool, allowed_provider, &allowed_user).await;
    }

    /// The same rejected password is bound once per failure window, even
    /// with the short exact-credential cache disabled, and parallel requests
    /// cannot outrun the distinct-password cap.
    #[tokio::test]
    async fn test_lockout_guard_bounds_directory_binds() {
        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("ldaplock{suffix}");
        let dn = format!("uid={username},ou=people,{BASE}");
        let (port, ops) = scripted_directory(&username, &dn, 0x31).await;
        let provider_id = create_provider(&pool, &format!("lock-{suffix}"), port).await;
        insert_known_user(&pool, &username, &dn, provider_id).await;
        let auth = test_auth_service(&pool);
        let settings = Settings {
            enabled: true,
            failure_ttl: Duration::ZERO,
            ..Settings::default()
        };
        let attempt = |password: &'static str| {
            try_authenticate_with_settings(
                &auth,
                &username,
                password,
                "/maven/private/a/b/1/b-1.pom",
                "GET",
                settings,
            )
        };

        for _ in 0..3 {
            assert!(matches!(attempt("stale-password").await, Outcome::Invalid));
        }
        assert_eq!(
            count(&ops, "bind"),
            1,
            "a rejected password is not replayed against the directory"
        );

        // Parallel distinct guesses: at most the cap is ever bound.
        let results =
            futures::future::join_all(["g1", "g2", "g3", "g4", "g5", "g6"].map(attempt)).await;
        assert!(results.iter().all(|r| matches!(r, Outcome::Invalid)));
        assert!(
            count(&ops, "bind") <= settings.max_failed_passwords,
            "binds {} exceed the cap {}",
            count(&ops, "bind"),
            settings.max_failed_passwords
        );

        cleanup(&pool, provider_id, &username).await;
    }

    /// Parallel requests with the same good credential bind once.
    #[tokio::test]
    async fn test_parallel_same_credential_binds_once() {
        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("ldappar{suffix}");
        let dn = format!("uid={username},ou=people,{BASE}");
        let (port, ops) = scripted_directory(&username, &dn, 0x00).await;
        let provider_id = create_provider(&pool, &format!("par-{suffix}"), port).await;
        insert_known_user(&pool, &username, &dn, provider_id).await;
        let auth = test_auth_service(&pool);
        let results = futures::future::join_all((0..5).map(|_| {
            try_authenticate_with_settings(
                &auth,
                &username,
                "good-password",
                "/npm/private/pkg",
                "GET",
                settings(),
            )
        }))
        .await;
        assert!(results.iter().all(|r| matches!(r, Outcome::Resolved(_))));
        assert_eq!(count(&ops, "bind"), 1);
        cleanup(&pool, provider_id, &username).await;
    }

    /// A directory outage is a retryable 503, never a 401, and is not
    /// charged to the user's failure budget.
    #[tokio::test]
    async fn test_directory_outage_is_unavailable() {
        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("ldapdown{suffix}");
        let dn = format!("uid={username},ou=people,{BASE}");
        // A port with nothing listening.
        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let provider_id = create_provider(&pool, &format!("down-{suffix}"), closed).await;
        insert_known_user(&pool, &username, &dn, provider_id).await;
        let auth = test_auth_service(&pool);
        for _ in 0..4 {
            assert!(matches!(
                try_authenticate_with_settings(
                    &auth,
                    &username,
                    "good-password",
                    "/npm/private/pkg",
                    "GET",
                    settings(),
                )
                .await,
                Outcome::Unavailable
            ));
        }
        let tag = credential_tag(&username, "good-password");
        assert_eq!(
            cache()
                .lock()
                .unwrap()
                .precheck(&tag, &username, &settings(), Instant::now()),
            Precheck::Proceed,
            "an outage must not be recorded as a failed password"
        );
        cleanup(&pool, provider_id, &username).await;
    }

    /// A rejected service-account bind is a provider fault: 503, and the
    /// user's correct password is not recorded as a failure.
    #[tokio::test]
    async fn test_service_bind_rejection_is_unavailable() {
        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("ldapsvc{suffix}");
        let dn = format!("uid={username},ou=people,{BASE}");
        // The mock only accepts MOCK_SERVICE_DN as the service account; the
        // provider binds with a different DN, which the mock rejects (49).
        let (port, _ops) = scripted_directory(&username, &dn, 0x31).await;
        let provider_id = AuthConfigService::create_ldap(
            &pool,
            CreateLdapConfigRequest {
                name: format!("svc-{suffix}"),
                server_url: format!("ldap://127.0.0.1:{port}"),
                bind_dn: Some("cn=expired,dc=example,dc=com".into()),
                bind_password: Some("svc-secret".into()),
                user_base_dn: BASE.into(),
                user_filter: Some("(uid={0})".into()),
                group_base_dn: None,
                group_filter: None,
                email_attribute: None,
                display_name_attribute: None,
                username_attribute: None,
                groups_attribute: None,
                admin_group_dn: None,
                use_starttls: None,
                insecure_skip_verify: None,
                ca_certificate: None,
                is_enabled: Some(true),
                priority: Some(0),
            },
        )
        .await
        .expect("create provider")
        .id;
        insert_known_user(&pool, &username, &dn, provider_id).await;
        let auth = test_auth_service(&pool);
        assert!(matches!(
            try_authenticate_with_settings(
                &auth,
                &username,
                "good-password",
                "/npm/private/pkg",
                "GET",
                settings(),
            )
            .await,
            Outcome::Unavailable
        ));
        let tag = credential_tag(&username, "good-password");
        assert_eq!(
            cache()
                .lock()
                .unwrap()
                .precheck(&tag, &username, &settings(), Instant::now()),
            Precheck::Proceed
        );
        cleanup(&pool, provider_id, &username).await;
    }

    /// First bind for a directory user with no local row provisions it.
    #[tokio::test]
    async fn test_first_bind_provisions_unknown_directory_user() {
        if !encryption_key_available() {
            return;
        }
        let Some(pool) = test_db_helpers::try_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("ldapnew{suffix}");
        let dn = format!("uid={username},ou=people,{BASE}");
        let (port, _ops) = scripted_directory(&username, &dn, 0x00).await;
        // No local row yet, so the provider is chosen by priority; sort
        // ahead of any provider another test left enabled, and retire what an
        // earlier aborted run of this test may have left behind.
        sqlx::query("UPDATE ldap_configs SET is_enabled = false WHERE name LIKE '0000-new-%'")
            .execute(&pool)
            .await
            .expect("retire stale providers");
        let provider_id = AuthConfigService::create_ldap(
            &pool,
            CreateLdapConfigRequest {
                name: format!("0000-new-{suffix}"),
                server_url: format!("ldap://127.0.0.1:{port}"),
                bind_dn: Some(MOCK_SERVICE_DN.into()),
                bind_password: Some("svc-secret".into()),
                user_base_dn: BASE.into(),
                user_filter: Some("(uid={0})".into()),
                group_base_dn: None,
                group_filter: None,
                email_attribute: None,
                display_name_attribute: None,
                username_attribute: None,
                groups_attribute: None,
                admin_group_dn: None,
                use_starttls: None,
                insecure_skip_verify: None,
                ca_certificate: None,
                is_enabled: Some(true),
                priority: Some(i32::MIN),
            },
        )
        .await
        .expect("create provider")
        .id;
        let auth = test_auth_service(&pool);
        match try_authenticate_with_settings(
            &auth,
            &username,
            "good-password",
            "/npm/private/pkg",
            "GET",
            settings(),
        )
        .await
        {
            Outcome::Resolved(user) => {
                assert_eq!(user.username, username);
                assert_eq!(user.external_id.as_deref(), Some(dn.as_str()));
                assert!(!user.is_admin);
            }
            other => panic!("expected the first bind to provision, got {other:?}"),
        }
        let recorded: Option<Uuid> =
            sqlx::query_scalar("SELECT ldap_provider_id FROM users WHERE username = $1")
                .bind(&username)
                .fetch_one(&pool)
                .await
                .expect("provisioned row");
        assert_eq!(recorded, Some(provider_id));
        cleanup(&pool, provider_id, &username).await;
    }
}
