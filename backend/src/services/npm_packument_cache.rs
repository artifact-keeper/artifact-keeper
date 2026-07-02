//! Computed-packument response cache with stale-while-revalidate for the npm
//! metadata path (#2162).
//!
//! Every npm packument request against a remote or virtual repository pays an
//! upstream round-trip plus the full transform pipeline (parse, rewrite
//! `dist.tarball` URLs, abbreviate, serialize, compress). This module caches
//! the *final response bytes* (identity and gzip variants) so a warm hit
//! serves pre-encoded bytes with no upstream fetch and no recompute — the
//! computed analogue of the cargo `IndexCache` / APT `SignedReleaseCache`.
//!
//! Scope: the handler only engages this cache for **remote and virtual**
//! repositories, where the cost being removed is the upstream round-trip.
//! Local (hosted) packuments are a cheap indexed DB read, and caching them
//! would break read-your-writes across replicas with the in-process backend
//! (a publish on pod A would leave pod B serving the pre-publish entry as
//! fresh for the whole fresh window).
//!
//! Freshness model (stale-while-revalidate):
//! * age < fresh TTL — served directly.
//! * fresh TTL <= age < stale max — served immediately while a background
//!   task refreshes the entry; a per-key claim keeps a burst of stale hits
//!   from spawning more than one refresh.
//! * age >= stale max — the entry is gone (backends expire it) and the
//!   request recomputes inline, deduplicated through the same buffered
//!   single-flight primitive the proxy hydration path uses.
//!
//! Backends: the in-process map (default) or, when
//! `NPM_PACKUMENT_CACHE_REDIS_URL` is configured, a layered backend that
//! reads Redis first (shared across replicas) and falls back to an
//! always-warm in-process layer whenever Redis errors. Every operation
//! retries Redis, so recovery is automatic once it returns; a cache outage
//! never fails a request. Redis invalidation is driven by a per-package key
//! index (a small `SET` maintained on write), so it never scans the keyspace.
//!
//! Write-after-invalidate: stores run under a [`StoreGuard`] carrying a
//! per-package generation captured before the compute starts; an invalidation
//! bumps the generation, so a compute that raced a local write cannot
//! re-install pre-write data (checked before AND after the backend write).
//! The guard is process-local: a compute on replica A racing an invalidation
//! issued on replica B can still land pre-write data in Redis. That window is
//! bounded — the entry ages out of the fresh window after the fresh TTL and a
//! background refresh then replaces it — and is inherent to any shared cache
//! without a coordination primitive; a Redis-side tombstone is the known
//! follow-up if the bounded window ever matters in practice.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::services::proxy_hydration::coordinate_proxy_hydration;

/// Default fresh window. Aligned with the packument mutability policy in
/// [`crate::services::cache_classifier`]: a packument is a mutable pointer,
/// so 5 minutes bounds how long a warm hit can serve slightly-stale metadata
/// without any revalidation at all.
pub const NPM_PACKUMENT_FRESH_TTL_DEFAULT_SECS: u64 =
    crate::services::cache_classifier::MUTABLE_DEFAULT_TTL_SECS as u64;

/// Default stale window. Past the fresh TTL an entry is still served (a
/// background refresh brings it up to date); past this bound it is dropped
/// and the next request recomputes inline. For proxied packages there is no
/// upstream invalidation signal, so this is the worst-case metadata staleness
/// when the background refresh keeps failing.
pub const NPM_PACKUMENT_STALE_MAX_DEFAULT_SECS: u64 = 86_400;

/// Soft cap on in-process cache entries, mirroring
/// [`crate::api::SIGNED_RELEASE_CACHE_MAX_ENTRIES`]. A large install
/// re-resolve touches ~1k packuments; four variants each (full/corgi x
/// identity/gzip) fit comfortably, while the cap bounds worst-case memory.
pub const NPM_PACKUMENT_CACHE_MAX_ENTRIES: usize = 8_192;

/// Namespace for Redis keys, so cache entries never collide with other users
/// of a shared Redis database.
const REDIS_KEY_NAMESPACE: &str = "ak:npm-packument:";

/// Namespace for single-flight lease keys on the shared proxy-hydration map
/// (sibling of the proxy path's `proxy-cache:` / `proxy-stream:` prefixes).
const FLIGHT_LEASE_NAMESPACE: &str = "npm-packument:";

/// Bound on each Redis connection attempt, so a request never stalls behind
/// an unreachable Redis host (the in-process layer answers instead).
const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Bound on each Redis command, so a hung Redis degrades to the in-process
/// layer instead of adding seconds to every packument request.
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long operations skip Redis entirely after any Redis failure — a
/// failed initial connection OR a command error on an established manager
/// (e.g. a black-holed host where every command would otherwise pay the full
/// response timeout). In between, operations degrade to the in-process layer
/// immediately; the next operation after the window re-probes Redis, so at
/// most one request per window pays a bounded probe during an outage.
const REDIS_UNAVAILABLE_COOLDOWN: Duration = Duration::from_secs(5);

/// A fully-computed npm packument response body, ready to serve verbatim.
///
/// Holds already-encoded bytes (identity or gzip) plus the headers needed to
/// reproduce the response. `content_encoding` is set (`gzip`) only when the
/// bytes are gzip-compressed; the metadata compression layer passes through
/// responses that already carry a `Content-Encoding` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedPackument {
    pub bytes: Bytes,
    pub content_type: String,
    pub content_encoding: Option<String>,
}

/// A successful cache read: the entry plus its age, so freshness is always
/// classified by the caller regardless of which backend stored the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheHit {
    pub entry: CachedPackument,
    pub age: Duration,
}

/// Freshness of a cache hit. Entries older than the stale bound are dropped
/// by the backends and surface as misses, so only two states exist here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Younger than the fresh TTL: serve directly.
    Fresh,
    /// Past the fresh TTL but within the stale window: serve immediately and
    /// refresh in the background.
    Stale,
}

/// Classify a hit's age against the fresh TTL.
fn classify_freshness(age: Duration, fresh_ttl: Duration) -> Freshness {
    if age < fresh_ttl {
        Freshness::Fresh
    } else {
        Freshness::Stale
    }
}

/// True when an entry of this age must no longer be served at all.
fn is_expired(age: Duration, stale_max: Duration) -> bool {
    age >= stale_max
}

// ---------------------------------------------------------------------------
// Cache keys
// ---------------------------------------------------------------------------

/// The Accept-dimension of the cache key: `npm install` requests the
/// abbreviated ("corgi") document, which produces a different body from the
/// full packument, so they cache separately.
pub fn accept_variant(want_abbreviated: bool) -> &'static str {
    if want_abbreviated {
        "corgi"
    } else {
        "full"
    }
}

/// The encoding dimension of the cache key.
pub fn encoding_label(gzip: bool) -> &'static str {
    if gzip {
        "gzip"
    } else {
        "identity"
    }
}

/// Short digest of the request base URL. The rewritten `dist.tarball` URLs
/// are absolute (`{base_url}/npm/...`), so the computed body differs per
/// external host; folding the base URL into the key keeps a client reaching
/// the server via one host from being served another host's tarball URLs.
fn base_url_hash(base_url: &str) -> String {
    hex::encode(Sha256::digest(base_url.as_bytes()))[..16].to_string()
}

/// Cache key: `"{repo_key}:{package}:{accept_variant}:{encoding}:{base_hash}"`.
///
/// `repo_key` and `package` lead so [`invalidation_prefix`] can drop every
/// variant of one package with a single prefix match.
pub fn cache_key(
    repo_key: &str,
    package: &str,
    want_abbreviated: bool,
    gzip: bool,
    base_url: &str,
) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        repo_key,
        package,
        accept_variant(want_abbreviated),
        encoding_label(gzip),
        base_url_hash(base_url)
    )
}

/// Single-flight key for one refresh unit. A refresh recomputes and stores
/// *both* encodings of one `(repo, package, variant, base URL)`, so the
/// encoding dimension is deliberately absent: gzip and identity requests for
/// the same packument share one upstream fetch.
pub fn flight_key(repo_key: &str, package: &str, want_abbreviated: bool, base_url: &str) -> String {
    format!(
        "{}:{}:{}:{}",
        repo_key,
        package,
        accept_variant(want_abbreviated),
        base_url_hash(base_url)
    )
}

/// Prefix matching every cached variant (full/corgi x identity/gzip x any
/// base URL) of one package in one repo.
pub fn invalidation_prefix(repo_key: &str, package: &str) -> String {
    format!("{}:{}:", repo_key, package)
}

/// Recover the [`invalidation_prefix`] from a full cache key. Repo keys and
/// npm package names cannot contain `:`, so the prefix is everything up to
/// and including the second separator.
fn key_invalidation_prefix(key: &str) -> String {
    let mut end = 0;
    let mut separators = 0;
    for (idx, ch) in key.char_indices() {
        if ch == ':' {
            separators += 1;
            if separators == 2 {
                end = idx + 1;
                break;
            }
        }
    }
    key[..end].to_string()
}

// ---------------------------------------------------------------------------
// Backend traits
// ---------------------------------------------------------------------------

/// Storage backend for computed packument responses.
///
/// Implementations must degrade gracefully: a backend problem surfaces as a
/// miss (`get`) or a no-op (`set` / `invalidate_prefix`), never as a failure
/// the request path has to handle.
#[async_trait]
pub trait PackumentCacheBackend: Send + Sync {
    /// Look up a non-expired entry and report its age.
    async fn get(&self, key: &str) -> Option<CacheHit>;
    /// Store an entry, timestamped now. `prefix` is the key's
    /// [`invalidation_prefix`]; shared backends index the key under it so
    /// invalidation never has to scan the keyspace.
    async fn set(&self, key: &str, prefix: &str, entry: CachedPackument);
    /// Drop every entry whose key starts with `prefix`.
    async fn invalidate_prefix(&self, prefix: &str);
}

/// The shared cache is unreachable or misbehaving; the caller should use the
/// in-process layer for this operation and retry the shared cache next time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedCacheUnavailable;

/// A shared (cross-replica) cache that can fail, unlike
/// [`PackumentCacheBackend`] which must not. [`LayeredPackumentCache`]
/// composes one of these over the in-process backend so an error here
/// degrades to the local layer instead of losing caching entirely.
#[async_trait]
trait SharedCacheBackend: Send + Sync {
    async fn try_get(&self, key: &str) -> Result<Option<CacheHit>, SharedCacheUnavailable>;
    async fn try_set(
        &self,
        key: &str,
        prefix: &str,
        entry: CachedPackument,
    ) -> Result<(), SharedCacheUnavailable>;
    async fn try_invalidate_prefix(&self, prefix: &str) -> Result<(), SharedCacheUnavailable>;
}

// ---------------------------------------------------------------------------
// In-process backend
// ---------------------------------------------------------------------------

/// Default backend: a process-local map in the same style as the cargo
/// `IndexCache`, with expiry sweeps on write and a soft entry cap.
pub struct InProcessPackumentCache {
    entries: RwLock<HashMap<String, (CachedPackument, Instant)>>,
    stale_max: Duration,
    max_entries: usize,
}

impl InProcessPackumentCache {
    pub fn new(stale_max: Duration) -> Self {
        Self::with_max_entries(stale_max, NPM_PACKUMENT_CACHE_MAX_ENTRIES)
    }

    pub fn with_max_entries(stale_max: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            stale_max,
            max_entries: max_entries.max(1),
        }
    }

    /// Test hook: insert an entry with a back-dated timestamp so expiry and
    /// staleness paths are exercised without sleeping.
    #[cfg(test)]
    async fn set_with_stored_at(&self, key: &str, entry: CachedPackument, stored_at: Instant) {
        self.entries
            .write()
            .await
            .insert(key.to_string(), (entry, stored_at));
    }
}

#[async_trait]
impl PackumentCacheBackend for InProcessPackumentCache {
    async fn get(&self, key: &str) -> Option<CacheHit> {
        let entries = self.entries.read().await;
        let (entry, stored_at) = entries.get(key)?;
        let age = stored_at.elapsed();
        if is_expired(age, self.stale_max) {
            return None;
        }
        Some(CacheHit {
            entry: entry.clone(),
            age,
        })
    }

    async fn set(&self, key: &str, _prefix: &str, entry: CachedPackument) {
        let mut entries = self.entries.write().await;
        entries.retain(|_, (_, at)| !is_expired(at.elapsed(), self.stale_max));
        if entries.len() >= self.max_entries && !entries.contains_key(key) {
            // At cap with only live entries left: evict the oldest so the
            // map never exceeds the cap.
            if let Some(oldest) = entries
                .iter()
                .max_by_key(|(_, (_, at))| at.elapsed())
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key.to_string(), (entry, Instant::now()));
    }

    async fn invalidate_prefix(&self, prefix: &str) {
        self.entries
            .write()
            .await
            .retain(|k, _| !k.starts_with(prefix));
    }
}

// ---------------------------------------------------------------------------
// Redis (shared) backend
// ---------------------------------------------------------------------------

/// Version tag leading every encoded Redis value, so a future layout change
/// can never be misparsed as the current one.
const REDIS_ENTRY_VERSION: u8 = 1;

/// Milliseconds since the Unix epoch. Redis entries store their write time so
/// freshness is computed client-side; wall-clock time (not `Instant`) because
/// the reader may be a different process than the writer.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Serialize an entry for Redis:
/// `version(1) | stored_at_ms(8 BE) | ct_len(2 BE) | content_type |
///  enc_len(1) | content_encoding | body`.
fn encode_redis_entry(entry: &CachedPackument, stored_at_ms: u64) -> Vec<u8> {
    let ct = entry.content_type.as_bytes();
    let enc = entry
        .content_encoding
        .as_deref()
        .unwrap_or_default()
        .as_bytes();
    let mut out = Vec::with_capacity(12 + ct.len() + enc.len() + entry.bytes.len());
    out.push(REDIS_ENTRY_VERSION);
    out.extend_from_slice(&stored_at_ms.to_be_bytes());
    out.extend_from_slice(&(ct.len().min(u16::MAX as usize) as u16).to_be_bytes());
    out.extend_from_slice(&ct[..ct.len().min(u16::MAX as usize)]);
    out.push(enc.len().min(u8::MAX as usize) as u8);
    out.extend_from_slice(&enc[..enc.len().min(u8::MAX as usize)]);
    out.extend_from_slice(&entry.bytes);
    out
}

/// Parse a value produced by [`encode_redis_entry`]. Any structural problem
/// yields `None` (treated as a cache miss), never an error.
fn decode_redis_entry(raw: &[u8]) -> Option<(CachedPackument, u64)> {
    if raw.len() < 11 || raw[0] != REDIS_ENTRY_VERSION {
        return None;
    }
    let stored_at_ms = u64::from_be_bytes(raw[1..9].try_into().ok()?);
    let ct_len = u16::from_be_bytes(raw[9..11].try_into().ok()?) as usize;
    let ct_end = 11usize.checked_add(ct_len)?;
    let content_type = String::from_utf8(raw.get(11..ct_end)?.to_vec()).ok()?;
    let enc_len = *raw.get(ct_end)? as usize;
    let enc_end = ct_end.checked_add(1)?.checked_add(enc_len)?;
    let encoding = raw.get(ct_end + 1..enc_end)?;
    let content_encoding = if encoding.is_empty() {
        None
    } else {
        Some(String::from_utf8(encoding.to_vec()).ok()?)
    };
    let body = raw.get(enc_end..)?;
    Some((
        CachedPackument {
            bytes: Bytes::copy_from_slice(body),
            content_type,
            content_encoding,
        },
        stored_at_ms,
    ))
}

/// First-of-burst check for degraded-backend logging: `true` exactly once
/// per error burst; [`burst_reset`] re-arms it on the next success.
fn burst_should_warn(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::Relaxed)
}

fn burst_reset(flag: &AtomicBool) {
    flag.store(false, Ordering::Relaxed)
}

/// Shared backend for multi-replica deployments. Entries are written with
/// `EX stale_max`, so Redis expires what this process would classify as
/// expired anyway; freshness is still computed client-side from the stored
/// timestamp.
///
/// Every write also indexes its key in a per-package `SET` (same TTL), so
/// invalidation is `SMEMBERS` + `UNLINK` of exactly the affected keys —
/// never a keyspace scan, and non-blocking on the Redis side.
///
/// Failures are reported as [`SharedCacheUnavailable`] (logged warn once per
/// burst, debug thereafter) and arm a short cooldown during which operations
/// skip Redis entirely, so a black-holed host costs at most one bounded probe
/// per cooldown window instead of a response-timeout per request. Every
/// operation after the window retries, so recovery needs no restart.
pub struct RedisPackumentCache {
    client: redis::Client,
    manager: tokio::sync::OnceCell<redis::aio::ConnectionManager>,
    /// While set to a future instant, every operation degrades to the
    /// fallback layer without touching Redis. Armed on any Redis failure
    /// (connect or command), cleared on the next success.
    unavailable_until: Mutex<Option<Instant>>,
    stale_max: Duration,
    error_active: AtomicBool,
}

impl RedisPackumentCache {
    /// Validate the URL and build the backend. Connection establishment is
    /// deferred to first use so a Redis outage cannot block startup.
    pub fn new(url: &str, stale_max: Duration) -> Result<Self, redis::RedisError> {
        Ok(Self {
            client: redis::Client::open(url)?,
            manager: tokio::sync::OnceCell::new(),
            unavailable_until: Mutex::new(None),
            stale_max,
            error_active: AtomicBool::new(false),
        })
    }

    fn gate_armed(&self) -> bool {
        self.unavailable_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|until| Instant::now() < until)
    }

    fn arm_gate(&self) {
        *self
            .unavailable_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(Instant::now() + REDIS_UNAVAILABLE_COOLDOWN);
    }

    fn clear_gate(&self) {
        *self
            .unavailable_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    async fn connection(&self) -> Result<redis::aio::ConnectionManager, SharedCacheUnavailable> {
        if self.gate_armed() {
            return Err(SharedCacheUnavailable);
        }
        if let Some(manager) = self.manager.get() {
            return Ok(manager.clone());
        }
        // A single initial-connect retry: the cooldown gate paces re-attempts
        // instead, so a down Redis costs one bounded stall per cooldown window
        // rather than the manager's default six-attempt backoff inside a
        // request. Reconnects after a successful first connect are handled
        // internally by the manager.
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(REDIS_CONNECT_TIMEOUT))
            .set_response_timeout(Some(REDIS_RESPONSE_TIMEOUT))
            .set_number_of_retries(1);
        let init = self
            .manager
            .get_or_try_init(|| async {
                // Waiters queued behind a failed leader re-run this closure
                // serially; the leader arms the gate before releasing the
                // init slot, so they fail fast here instead of each paying
                // their own connect attempt.
                if self.gate_armed() {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Io,
                        "npm packument cache Redis in cooldown",
                    )));
                }
                match self.client.get_connection_manager_with_config(config).await {
                    Ok(manager) => Ok(manager),
                    Err(e) => {
                        self.arm_gate();
                        Err(e)
                    }
                }
            })
            .await;
        match init {
            Ok(manager) => Ok(manager.clone()),
            Err(e) => {
                self.note_error("connect", &e);
                Err(SharedCacheUnavailable)
            }
        }
    }

    /// Record a command failure: arm the cooldown gate and log (warn once per
    /// burst). Returns [`SharedCacheUnavailable`] for `map_err` ergonomics.
    fn command_error(&self, op: &str, err: &dyn Display) -> SharedCacheUnavailable {
        self.note_error(op, err);
        SharedCacheUnavailable
    }

    fn note_error(&self, op: &str, err: &dyn Display) {
        self.arm_gate();
        if burst_should_warn(&self.error_active) {
            tracing::warn!(
                op,
                error = %err,
                "npm packument cache: Redis unavailable, serving from the in-process \
                 layer until it recovers"
            );
        } else {
            tracing::debug!(op, error = %err, "npm packument cache: Redis error");
        }
    }

    fn note_success(&self) {
        self.clear_gate();
        burst_reset(&self.error_active);
    }

    fn namespaced(key: &str) -> String {
        format!("{}{}", REDIS_KEY_NAMESPACE, key)
    }

    /// The per-package key-index `SET` used for scan-free invalidation.
    fn index_key(prefix: &str) -> String {
        format!("{}idx:{}", REDIS_KEY_NAMESPACE, prefix)
    }
}

#[async_trait]
impl SharedCacheBackend for RedisPackumentCache {
    async fn try_get(&self, key: &str) -> Result<Option<CacheHit>, SharedCacheUnavailable> {
        let mut conn = self.connection().await?;
        let raw: Option<Vec<u8>> = redis::cmd("GET")
            .arg(Self::namespaced(key))
            .query_async(&mut conn)
            .await
            .map_err(|e| self.command_error("get", &e))?;
        self.note_success();
        let Some((entry, stored_at_ms)) = raw.as_deref().and_then(decode_redis_entry) else {
            return Ok(None);
        };
        let age = Duration::from_millis(now_unix_ms().saturating_sub(stored_at_ms));
        if is_expired(age, self.stale_max) {
            return Ok(None);
        }
        Ok(Some(CacheHit { entry, age }))
    }

    async fn try_set(
        &self,
        key: &str,
        prefix: &str,
        entry: CachedPackument,
    ) -> Result<(), SharedCacheUnavailable> {
        let mut conn = self.connection().await?;
        let value = encode_redis_entry(&entry, now_unix_ms());
        let namespaced_key = Self::namespaced(key);
        let index_key = Self::index_key(prefix);
        let ttl = self.stale_max.as_secs().max(1);
        // Entry + index maintained together: the index makes invalidation a
        // member lookup instead of a keyspace scan. The index carries the
        // same TTL (refreshed on every write), so it can hold at most a few
        // already-expired members, which UNLINK tolerates.
        redis::pipe()
            .cmd("SET")
            .arg(&namespaced_key)
            .arg(value)
            .arg("EX")
            .arg(ttl)
            .ignore()
            .cmd("SADD")
            .arg(&index_key)
            .arg(&namespaced_key)
            .ignore()
            .cmd("EXPIRE")
            .arg(&index_key)
            .arg(ttl)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| self.command_error("set", &e))?;
        self.note_success();
        Ok(())
    }

    async fn try_invalidate_prefix(&self, prefix: &str) -> Result<(), SharedCacheUnavailable> {
        let mut conn = self.connection().await?;
        let index_key = Self::index_key(prefix);
        let members: Vec<Vec<u8>> = redis::cmd("SMEMBERS")
            .arg(&index_key)
            .query_async(&mut conn)
            .await
            // A failed invalidation means other replicas may serve this
            // package stale for up to the stale window.
            .map_err(|e| self.command_error("invalidate-index", &e))?;
        let mut unlink = redis::cmd("UNLINK");
        for member in &members {
            unlink.arg(member);
        }
        unlink.arg(&index_key);
        unlink
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| self.command_error("invalidate-unlink", &e))?;
        self.note_success();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Layered backend: shared cache over the in-process layer
// ---------------------------------------------------------------------------

/// Composes a fallible shared cache (Redis) over the in-process backend.
///
/// * Reads hit the shared cache first — it is authoritative while healthy
///   (its misses are misses, so a cross-replica invalidation is respected
///   even when this replica's local layer still holds the entry). Only a
///   shared-cache *error* falls back to the local layer.
/// * Writes go to both layers, so the local layer is already warm when a
///   Redis outage starts.
/// * Invalidations always clear the local layer and attempt the shared one.
///
/// Every operation retries the shared cache, so recovery needs no restart.
struct LayeredPackumentCache {
    shared: Arc<dyn SharedCacheBackend>,
    local: InProcessPackumentCache,
}

impl LayeredPackumentCache {
    fn new(shared: Arc<dyn SharedCacheBackend>, local: InProcessPackumentCache) -> Self {
        Self { shared, local }
    }
}

#[async_trait]
impl PackumentCacheBackend for LayeredPackumentCache {
    async fn get(&self, key: &str) -> Option<CacheHit> {
        match self.shared.try_get(key).await {
            Ok(hit) => hit,
            Err(SharedCacheUnavailable) => self.local.get(key).await,
        }
    }

    async fn set(&self, key: &str, prefix: &str, entry: CachedPackument) {
        self.local.set(key, prefix, entry.clone()).await;
        let _ = self.shared.try_set(key, prefix, entry).await;
    }

    async fn invalidate_prefix(&self, prefix: &str) {
        self.local.invalidate_prefix(prefix).await;
        let _ = self.shared.try_invalidate_prefix(prefix).await;
    }
}

// ---------------------------------------------------------------------------
// Facade
// ---------------------------------------------------------------------------

/// RAII claim on a background refresh for one flight key. Dropping it (task
/// finished, failed, or was cancelled) releases the key so a later stale hit
/// can refresh again.
pub struct RefreshClaim {
    flights: Arc<Mutex<HashSet<String>>>,
    key: String,
}

impl Drop for RefreshClaim {
    fn drop(&mut self) {
        self.flights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.key);
    }
}

/// Soft cap on the per-package invalidation-generation map. Entries only
/// matter while a compute for that package is in flight (seconds); when the
/// map is cleared at cap, in-flight guards observe a generation change and
/// skip their store — a spurious cache miss, never a stale entry.
const INVALIDATION_GENERATIONS_MAX: usize = 1_024;

/// Snapshot of a package's invalidation generation, captured *before* a
/// compute starts. [`NpmPackumentCache::store_guarded`] refuses the store if
/// the package was invalidated in the meantime, so a compute racing a local
/// write cannot re-install pre-write data.
pub struct StoreGuard {
    prefix: String,
    generation: u64,
}

/// The computed-packument cache: freshness policy and refresh deduplication
/// over a pluggable [`PackumentCacheBackend`].
pub struct NpmPackumentCache {
    backend: Arc<dyn PackumentCacheBackend>,
    fresh_ttl: Duration,
    refresh_flights: Arc<Mutex<HashSet<String>>>,
    /// Per-package invalidation generation, bumped by
    /// [`Self::invalidate_package`] and checked by [`Self::store_guarded`].
    invalidation_generations: Mutex<HashMap<String, u64>>,
}

impl NpmPackumentCache {
    pub fn new(backend: Arc<dyn PackumentCacheBackend>, fresh_ttl: Duration) -> Self {
        Self {
            backend,
            fresh_ttl,
            refresh_flights: Arc::new(Mutex::new(HashSet::new())),
            invalidation_generations: Mutex::new(HashMap::new()),
        }
    }

    fn generation_of(&self, prefix: &str) -> u64 {
        self.invalidation_generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(prefix)
            .copied()
            .unwrap_or(0)
    }

    /// Build the cache described by the configuration, or `None` when the
    /// feature is disabled.
    ///
    /// With no Redis URL configured this is the in-process backend — caching
    /// works out of the box with zero configuration. A configured Redis URL
    /// selects the layered backend (shared cache over the in-process layer);
    /// an invalid URL falls back to in-process with a warning rather than
    /// failing startup.
    pub fn from_config(config: &Config) -> Option<Arc<Self>> {
        if !config.npm_packument_cache_enabled {
            return None;
        }
        let fresh_ttl = Duration::from_secs(config.npm_packument_cache_fresh_ttl_secs);
        // The stale window contains the fresh window by definition.
        let stale_max = Duration::from_secs(
            config
                .npm_packument_cache_stale_max_secs
                .max(config.npm_packument_cache_fresh_ttl_secs),
        );
        let backend: Arc<dyn PackumentCacheBackend> =
            match config.npm_packument_cache_redis_url.as_deref() {
                Some(url) => match RedisPackumentCache::new(url, stale_max) {
                    Ok(redis_backend) => Arc::new(LayeredPackumentCache::new(
                        Arc::new(redis_backend),
                        InProcessPackumentCache::new(stale_max),
                    )),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "NPM_PACKUMENT_CACHE_REDIS_URL is not a valid Redis URL; \
                             falling back to the in-process packument cache"
                        );
                        Arc::new(InProcessPackumentCache::new(stale_max))
                    }
                },
                None => Arc::new(InProcessPackumentCache::new(stale_max)),
            };
        Some(Arc::new(Self::new(backend, fresh_ttl)))
    }

    /// Look up an entry and classify its freshness.
    pub async fn lookup(&self, key: &str) -> Option<(CachedPackument, Freshness)> {
        let hit = self.backend.get(key).await?;
        Some((hit.entry, classify_freshness(hit.age, self.fresh_ttl)))
    }

    /// Store a computed entry without an invalidation-race guard. Only for
    /// callers that cannot race a local write (tests, warm-up); the request
    /// path uses [`Self::begin_store`] + [`Self::store_guarded`].
    pub async fn store(&self, key: &str, entry: CachedPackument) {
        self.backend
            .set(key, &key_invalidation_prefix(key), entry)
            .await;
    }

    /// Capture the package's invalidation generation before a compute starts.
    pub fn begin_store(&self, repo_key: &str, package: &str) -> StoreGuard {
        let prefix = invalidation_prefix(repo_key, package);
        StoreGuard {
            generation: self.generation_of(&prefix),
            prefix,
        }
    }

    /// Store a computed entry unless its package was invalidated after the
    /// guard was taken. Re-checked after the backend write too: if an
    /// invalidation raced the write itself, the just-written entry is dropped
    /// again, so a stale compute can never outlive a newer local write. (The
    /// guard is process-local — see the module docs for the bounded
    /// cross-replica window on the shared backend.)
    pub async fn store_guarded(&self, guard: &StoreGuard, key: &str, entry: CachedPackument) {
        if self.generation_of(&guard.prefix) != guard.generation {
            return;
        }
        self.backend.set(key, &guard.prefix, entry).await;
        if self.generation_of(&guard.prefix) != guard.generation {
            self.backend.invalidate_prefix(&guard.prefix).await;
        }
    }

    /// Drop every cached variant of `package` in `repo_key` (all Accept
    /// variants, encodings and base URLs) and bump the package's generation
    /// so in-flight computes started before this write cannot re-install
    /// pre-write data.
    pub async fn invalidate_package(&self, repo_key: &str, package: &str) {
        let prefix = invalidation_prefix(repo_key, package);
        {
            let mut generations = self
                .invalidation_generations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if generations.len() >= INVALIDATION_GENERATIONS_MAX
                && !generations.contains_key(&prefix)
            {
                // Clearing is safe-conservative: any in-flight guard sees a
                // generation change and skips its store.
                generations.clear();
            }
            *generations.entry(prefix.clone()).or_insert(0) += 1;
        }
        self.backend.invalidate_prefix(&prefix).await;
    }

    /// Claim the background refresh for `flight_key`. Returns `None` when a
    /// refresh is already in flight, so a burst of stale hits spawns exactly
    /// one refresh task.
    pub fn try_claim_refresh(&self, flight_key: &str) -> Option<RefreshClaim> {
        let mut flights = self
            .refresh_flights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !flights.insert(flight_key.to_string()) {
            return None;
        }
        Some(RefreshClaim {
            flights: self.refresh_flights.clone(),
            key: flight_key.to_string(),
        })
    }

    /// Serve one packument request through the cache.
    ///
    /// * Fresh hit — returned directly; `compute` never runs.
    /// * Stale hit — returned directly; `spawn_refresh` is invoked with the
    ///   refresh claim when this caller wins it (the callee is expected to
    ///   spawn a task that recomputes, stores, and drops the claim).
    /// * Miss — `compute` runs under buffered single-flight: one leader
    ///   computes (and stores) while concurrent callers wait and then serve
    ///   the leader's entry from the cache; `timeout_error` is returned if
    ///   the wait deadline elapses.
    pub async fn serve<E, Fut, Compute, Spawn, TimeoutErr>(
        &self,
        key: &str,
        flight_key: &str,
        compute: Compute,
        spawn_refresh: Spawn,
        timeout_error: TimeoutErr,
    ) -> Result<CachedPackument, E>
    where
        Compute: FnOnce() -> Fut,
        Fut: Future<Output = Result<CachedPackument, E>>,
        Spawn: FnOnce(RefreshClaim),
        TimeoutErr: Fn() -> E,
    {
        match self.lookup(key).await {
            Some((entry, Freshness::Fresh)) => Ok(entry),
            Some((entry, Freshness::Stale)) => {
                if let Some(claim) = self.try_claim_refresh(flight_key) {
                    spawn_refresh(claim);
                }
                Ok(entry)
            }
            None => {
                let lease_key = format!("{}{}", FLIGHT_LEASE_NAMESPACE, flight_key);
                coordinate_proxy_hydration(
                    &lease_key,
                    || async { Ok(self.lookup(key).await.map(|(entry, _)| entry)) },
                    compute,
                    timeout_error,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn entry(body: &'static [u8]) -> CachedPackument {
        CachedPackument {
            bytes: Bytes::from_static(body),
            content_type: "application/json".to_string(),
            content_encoding: None,
        }
    }

    fn gz_entry(body: &'static [u8]) -> CachedPackument {
        CachedPackument {
            bytes: Bytes::from_static(body),
            content_type: "application/vnd.npm.install-v1+json".to_string(),
            content_encoding: Some("gzip".to_string()),
        }
    }

    // -- freshness classification --------------------------------------------

    #[test]
    fn classify_freshness_boundaries() {
        let fresh_ttl = Duration::from_secs(300);
        assert_eq!(
            classify_freshness(Duration::ZERO, fresh_ttl),
            Freshness::Fresh
        );
        assert_eq!(
            classify_freshness(Duration::from_secs(299), fresh_ttl),
            Freshness::Fresh
        );
        // Exactly the TTL is stale (fresh window is half-open).
        assert_eq!(
            classify_freshness(Duration::from_secs(300), fresh_ttl),
            Freshness::Stale
        );
        assert_eq!(
            classify_freshness(Duration::from_secs(86_000), fresh_ttl),
            Freshness::Stale
        );
    }

    #[test]
    fn expiry_boundaries() {
        let stale_max = Duration::from_secs(86_400);
        assert!(!is_expired(Duration::from_secs(86_399), stale_max));
        assert!(is_expired(Duration::from_secs(86_400), stale_max));
        assert!(is_expired(Duration::from_secs(1_000_000), stale_max));
    }

    // -- keys ------------------------------------------------------------------

    #[test]
    fn cache_key_shape_and_dimensions() {
        let base = "https://registry.example.test";
        let key = cache_key("npm-main", "lodash", false, true, base);
        assert!(
            key.starts_with("npm-main:lodash:full:gzip:"),
            "unexpected key prefix: {key}"
        );
        // Base-URL dimension: 16 hex chars, stable, and distinct per host.
        let hash = key.rsplit(':').next().unwrap();
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(cache_key("npm-main", "lodash", false, true, base), key);
        let other = cache_key(
            "npm-main",
            "lodash",
            false,
            true,
            "http://other.example.test",
        );
        assert_ne!(key, other, "distinct base URLs must produce distinct keys");

        // Accept and encoding dimensions.
        let corgi = cache_key("npm-main", "@scope/pkg", true, false, base);
        assert!(corgi.starts_with("npm-main:@scope/pkg:corgi:identity:"));
    }

    #[test]
    fn flight_key_shares_encodings() {
        let base = "https://registry.example.test";
        let gzip_key = cache_key("r", "p", true, true, base);
        let identity_key = cache_key("r", "p", true, false, base);
        assert_ne!(gzip_key, identity_key);
        // One flight covers both encodings of the same packument...
        assert_eq!(
            flight_key("r", "p", true, base),
            flight_key("r", "p", true, base)
        );
        // ...but not the other Accept variant or another base URL.
        assert_ne!(
            flight_key("r", "p", true, base),
            flight_key("r", "p", false, base)
        );
        assert_ne!(
            flight_key("r", "p", true, base),
            flight_key("r", "p", true, "http://other.example.test")
        );
    }

    #[test]
    fn invalidation_prefix_matches_all_variants_of_one_package() {
        let base = "https://registry.example.test";
        let prefix = invalidation_prefix("repo", "pkg");
        for abbreviated in [false, true] {
            for gzip in [false, true] {
                assert!(cache_key("repo", "pkg", abbreviated, gzip, base).starts_with(&prefix));
            }
        }
        assert!(!cache_key("repo", "pkg2", false, false, base).starts_with(&prefix));
        // "pkg" must not shadow packages it merely prefixes lexically.
        assert!(!cache_key("repo", "pkg-extra", false, false, base).starts_with(&prefix));
    }

    // -- in-process backend ------------------------------------------------------

    #[tokio::test]
    async fn in_process_round_trip_reports_age() {
        let backend = InProcessPackumentCache::new(Duration::from_secs(60));
        assert!(backend.get("k").await.is_none());
        backend.set("k", "", entry(b"{}")).await;
        let hit = backend.get("k").await.expect("hit");
        assert_eq!(hit.entry, entry(b"{}"));
        assert!(hit.age < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn in_process_expired_entries_are_misses_and_swept() {
        let backend = InProcessPackumentCache::new(Duration::from_secs(60));
        let backdated = Instant::now() - Duration::from_secs(61);
        backend
            .set_with_stored_at("old", entry(b"{}"), backdated)
            .await;
        assert!(backend.get("old").await.is_none());

        // A write sweeps the expired entry out of the map entirely.
        backend.set("new", "", entry(b"{}")).await;
        assert!(!backend.entries.read().await.contains_key("old"));
        assert!(backend.get("new").await.is_some());
    }

    #[tokio::test]
    async fn in_process_cap_evicts_oldest() {
        let backend = InProcessPackumentCache::with_max_entries(Duration::from_secs(3600), 2);
        backend
            .set_with_stored_at(
                "oldest",
                entry(b"1"),
                Instant::now() - Duration::from_secs(30),
            )
            .await;
        backend
            .set_with_stored_at(
                "older",
                entry(b"2"),
                Instant::now() - Duration::from_secs(10),
            )
            .await;
        backend.set("newest", "", entry(b"3")).await;

        assert!(
            backend.get("oldest").await.is_none(),
            "oldest must be evicted"
        );
        assert!(backend.get("older").await.is_some());
        assert!(backend.get("newest").await.is_some());
        assert!(backend.entries.read().await.len() <= 2);
    }

    #[tokio::test]
    async fn in_process_overwrite_at_cap_keeps_other_entries() {
        let backend = InProcessPackumentCache::with_max_entries(Duration::from_secs(3600), 2);
        backend.set("a", "", entry(b"1")).await;
        backend.set("b", "", entry(b"2")).await;
        // Overwriting an existing key at cap must not evict anything.
        backend.set("a", "", entry(b"3")).await;
        assert_eq!(backend.get("a").await.unwrap().entry, entry(b"3"));
        assert!(backend.get("b").await.is_some());
    }

    #[tokio::test]
    async fn in_process_invalidate_prefix_is_scoped() {
        let backend = InProcessPackumentCache::new(Duration::from_secs(3600));
        let base = "https://registry.example.test";
        for abbreviated in [false, true] {
            for gzip in [false, true] {
                backend
                    .set(
                        &cache_key("repo", "pkg", abbreviated, gzip, base),
                        "",
                        entry(b"{}"),
                    )
                    .await;
            }
        }
        let survivor = cache_key("repo", "other", false, false, base);
        backend.set(&survivor, "", entry(b"{}")).await;

        backend
            .invalidate_prefix(&invalidation_prefix("repo", "pkg"))
            .await;

        for abbreviated in [false, true] {
            for gzip in [false, true] {
                assert!(backend
                    .get(&cache_key("repo", "pkg", abbreviated, gzip, base))
                    .await
                    .is_none());
            }
        }
        assert!(backend.get(&survivor).await.is_some());
    }

    // -- redis entry framing -------------------------------------------------------

    #[test]
    fn redis_entry_round_trips_identity_and_gzip() {
        for e in [entry(b"{\"name\":\"x\"}"), gz_entry(b"\x1f\x8b compressed")] {
            let raw = encode_redis_entry(&e, 1_234_567_890_123);
            let (decoded, stored_at) = decode_redis_entry(&raw).expect("decode");
            assert_eq!(decoded, e);
            assert_eq!(stored_at, 1_234_567_890_123);
        }
    }

    #[test]
    fn redis_entry_decode_rejects_corrupt_input() {
        let good = encode_redis_entry(&entry(b"{}"), 42);
        // Empty / too short.
        assert!(decode_redis_entry(&[]).is_none());
        assert!(decode_redis_entry(&good[..10]).is_none());
        // Unknown version byte.
        let mut wrong_version = good.clone();
        wrong_version[0] = 99;
        assert!(decode_redis_entry(&wrong_version).is_none());
        // Content-type length pointing past the buffer.
        let mut oversize_ct = good.clone();
        oversize_ct[9] = 0xFF;
        oversize_ct[10] = 0xFF;
        assert!(decode_redis_entry(&oversize_ct).is_none());
        // Non-UTF-8 content type.
        let mut bad_utf8 = good;
        bad_utf8[11] = 0xFF;
        assert!(decode_redis_entry(&bad_utf8).is_none());
    }

    #[test]
    fn redis_entry_empty_body_round_trips() {
        let e = CachedPackument {
            bytes: Bytes::new(),
            content_type: "application/json".to_string(),
            content_encoding: None,
        };
        let (decoded, _) = decode_redis_entry(&encode_redis_entry(&e, 7)).expect("decode");
        assert_eq!(decoded, e);
    }

    #[test]
    fn key_invalidation_prefix_recovers_prefix() {
        let base = "https://registry.example.test";
        for (repo, package) in [("repo", "pkg"), ("npm-all", "@scope/name")] {
            let key = cache_key(repo, package, true, true, base);
            assert_eq!(
                key_invalidation_prefix(&key),
                invalidation_prefix(repo, package)
            );
        }
        // Degenerate inputs never panic; they yield an empty prefix.
        assert_eq!(key_invalidation_prefix("no-separators"), "");
        assert_eq!(key_invalidation_prefix("one:separator"), "");
    }

    #[test]
    fn redis_index_key_is_namespaced_per_prefix() {
        let index = RedisPackumentCache::index_key(&invalidation_prefix("repo", "pkg"));
        assert_eq!(index, "ak:npm-packument:idx:repo:pkg:");
        assert_ne!(
            index,
            RedisPackumentCache::index_key(&invalidation_prefix("repo", "other"))
        );
    }

    #[test]
    fn redis_url_validation() {
        assert!(
            RedisPackumentCache::new("redis://localhost:6379", Duration::from_secs(60)).is_ok()
        );
        assert!(RedisPackumentCache::new("not a url", Duration::from_secs(60)).is_err());
    }

    #[tokio::test]
    async fn redis_unreachable_degrades_and_arms_cooldown_gate() {
        // Port 1 on loopback refuses immediately: the first call pays the
        // (failed) connect, then the cooldown gate short-circuits.
        let backend =
            RedisPackumentCache::new("redis://127.0.0.1:1", Duration::from_secs(60)).expect("url");
        assert!(!backend.gate_armed(), "gate must start disarmed");
        assert_eq!(backend.try_get("k").await, Err(SharedCacheUnavailable));
        assert!(
            backend.gate_armed(),
            "a failed connect must arm the unavailability gate"
        );
        // Within the cooldown, operations fail fast without touching Redis.
        assert_eq!(
            backend.try_set("k", "", entry(b"{}")).await,
            Err(SharedCacheUnavailable)
        );
        assert_eq!(
            backend.try_invalidate_prefix("p:").await,
            Err(SharedCacheUnavailable)
        );
    }

    #[tokio::test]
    async fn redis_command_errors_arm_gate_and_success_clears_it() {
        // The gate must also cover post-connect command errors (a black-holed
        // Redis would otherwise cost the response timeout per request), and a
        // success must re-open it.
        let backend = RedisPackumentCache::new("redis://localhost:6379", Duration::from_secs(60))
            .expect("url");
        backend.note_error("get", &"simulated command error");
        assert!(
            backend.gate_armed(),
            "a command error must arm the unavailability gate"
        );
        assert_eq!(
            backend.try_get("k").await,
            Err(SharedCacheUnavailable),
            "operations inside the cooldown must fail fast"
        );
        backend.note_success();
        assert!(!backend.gate_armed(), "a success must clear the gate");
    }

    #[test]
    fn burst_gate_warns_once_until_reset() {
        let flag = AtomicBool::new(false);
        assert!(burst_should_warn(&flag), "first error of a burst must warn");
        assert!(!burst_should_warn(&flag), "repeat errors must not warn");
        assert!(!burst_should_warn(&flag));
        burst_reset(&flag);
        assert!(burst_should_warn(&flag), "a success re-arms the warning");
    }

    // -- redis integration (env-gated) -----------------------------------------
    //
    // Mirrors the `DATABASE_URL` skip pattern: these run only when
    // `NPM_PACKUMENT_CACHE_TEST_REDIS_URL` points at a disposable Redis.

    fn redis_integration_backend() -> Option<RedisPackumentCache> {
        let url = std::env::var("NPM_PACKUMENT_CACHE_TEST_REDIS_URL").ok()?;
        RedisPackumentCache::new(&url, Duration::from_secs(60)).ok()
    }

    #[tokio::test]
    async fn redis_integration_round_trip_and_keyset_invalidation() {
        let Some(backend) = redis_integration_backend() else {
            return;
        };
        // Unique repo segment per run so reruns never see leftover state.
        let repo = format!("it-{}", uuid::Uuid::new_v4().simple());
        let base = "https://registry.example.test";
        let prefix = invalidation_prefix(&repo, "pkg");

        // Round trip both encodings through a real server, including the
        // framing (binary body, content type, stored-at derived age).
        for (gzip, e) in [
            (false, entry(b"{\"name\":\"x\"}")),
            (true, gz_entry(b"\x1f\x8b!")),
        ] {
            let key = cache_key(&repo, "pkg", false, gzip, base);
            backend
                .try_set(&key, &prefix, e.clone())
                .await
                .expect("set against live Redis");
            let hit = backend
                .try_get(&key)
                .await
                .expect("get against live Redis")
                .expect("entry just written must be readable");
            assert_eq!(hit.entry, e);
            assert!(hit.age < Duration::from_secs(5), "age must be near zero");
        }
        let survivor_key = cache_key(&repo, "other", false, false, base);
        backend
            .try_set(
                &survivor_key,
                &invalidation_prefix(&repo, "other"),
                entry(b"{}"),
            )
            .await
            .expect("set survivor");

        // Keyset invalidation: drops every variant of the package (via the
        // index SET, no scans) and leaves the sibling package alone.
        backend
            .try_invalidate_prefix(&prefix)
            .await
            .expect("invalidate against live Redis");
        for gzip in [false, true] {
            let key = cache_key(&repo, "pkg", false, gzip, base);
            assert_eq!(
                backend.try_get(&key).await.expect("get after invalidate"),
                None,
                "invalidated variants must be gone"
            );
        }
        assert!(
            backend
                .try_get(&survivor_key)
                .await
                .expect("get survivor")
                .is_some(),
            "invalidation must not touch other packages"
        );

        // Repeat invalidation of a now-empty index is a no-op, not an error.
        backend
            .try_invalidate_prefix(&prefix)
            .await
            .expect("second invalidate");

        // Cleanup.
        let _ = backend
            .try_invalidate_prefix(&invalidation_prefix(&repo, "other"))
            .await;
    }

    // -- layered backend ------------------------------------------------------------

    /// Scriptable shared cache: a real in-process store behind a health
    /// toggle, so outage / recovery transitions are deterministic.
    struct ScriptableSharedCache {
        healthy: AtomicBool,
        store: InProcessPackumentCache,
    }

    impl ScriptableSharedCache {
        fn new(healthy: bool) -> Self {
            Self {
                healthy: AtomicBool::new(healthy),
                store: InProcessPackumentCache::new(Duration::from_secs(3600)),
            }
        }

        fn set_healthy(&self, healthy: bool) {
            self.healthy.store(healthy, Ordering::SeqCst);
        }

        fn check(&self) -> Result<(), SharedCacheUnavailable> {
            if self.healthy.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(SharedCacheUnavailable)
            }
        }
    }

    #[async_trait]
    impl SharedCacheBackend for ScriptableSharedCache {
        async fn try_get(&self, key: &str) -> Result<Option<CacheHit>, SharedCacheUnavailable> {
            self.check()?;
            Ok(self.store.get(key).await)
        }
        async fn try_set(
            &self,
            key: &str,
            prefix: &str,
            entry: CachedPackument,
        ) -> Result<(), SharedCacheUnavailable> {
            self.check()?;
            self.store.set(key, prefix, entry).await;
            Ok(())
        }
        async fn try_invalidate_prefix(&self, prefix: &str) -> Result<(), SharedCacheUnavailable> {
            self.check()?;
            self.store.invalidate_prefix(prefix).await;
            Ok(())
        }
    }

    fn layered(healthy: bool) -> (Arc<ScriptableSharedCache>, LayeredPackumentCache) {
        let shared = Arc::new(ScriptableSharedCache::new(healthy));
        let backend = LayeredPackumentCache::new(
            shared.clone(),
            InProcessPackumentCache::new(Duration::from_secs(3600)),
        );
        (shared, backend)
    }

    #[tokio::test]
    async fn layered_healthy_shared_cache_is_authoritative() {
        let (shared, backend) = layered(true);
        backend.set("k", "", entry(b"{}")).await;
        assert!(backend.get("k").await.is_some());

        // A cross-replica invalidation (visible only in the shared layer)
        // must win over this replica's still-warm local copy.
        shared.store.invalidate_prefix("k").await;
        assert!(
            backend.get("k").await.is_none(),
            "a healthy shared-cache miss is authoritative; the local copy must not resurface"
        );
    }

    #[tokio::test]
    async fn layered_outage_serves_from_warm_local_layer() {
        let (shared, backend) = layered(true);
        // Written while healthy: both layers hold the entry.
        backend.set("k", "", entry(b"{}")).await;

        shared.set_healthy(false);
        let hit = backend.get("k").await;
        assert!(
            hit.is_some(),
            "with Redis down, the pre-outage entry must be served from the local layer"
        );
        assert_eq!(hit.unwrap().entry, entry(b"{}"));
    }

    #[tokio::test]
    async fn layered_outage_writes_and_invalidations_apply_locally() {
        let (shared, backend) = layered(false);
        // Written during the outage: the local layer still caches it.
        backend.set("k", "", entry(b"{}")).await;
        assert!(backend.get("k").await.is_some());

        // Invalidation during the outage clears the local layer.
        backend.invalidate_prefix("k").await;
        assert!(backend.get("k").await.is_none());
        let _ = shared; // outage for the whole test
    }

    #[tokio::test]
    async fn layered_recovers_without_restart() {
        let (shared, backend) = layered(false);
        backend.set("outage-key", "", entry(b"local")).await;

        shared.set_healthy(true);
        // Next operations use the shared cache again, no restart or reset.
        backend.set("recovered-key", "", entry(b"shared")).await;
        assert!(
            shared.store.get("recovered-key").await.is_some(),
            "after recovery, writes must reach the shared cache again"
        );
        assert!(
            backend.get("outage-key").await.is_none(),
            "a healthy shared-cache miss is authoritative again after recovery"
        );
    }

    // -- facade -----------------------------------------------------------------------

    /// Deterministic backend: always returns the configured hit (if any) and
    /// records writes, so freshness paths are tested without sleeping.
    struct FixedAgeBackend {
        hit: std::sync::Mutex<Option<CacheHit>>,
        sets: AtomicUsize,
    }

    impl FixedAgeBackend {
        fn new(hit: Option<CacheHit>) -> Self {
            Self {
                hit: std::sync::Mutex::new(hit),
                sets: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl PackumentCacheBackend for FixedAgeBackend {
        async fn get(&self, _key: &str) -> Option<CacheHit> {
            self.hit.lock().unwrap().clone()
        }
        async fn set(&self, _key: &str, _prefix: &str, entry: CachedPackument) {
            self.sets.fetch_add(1, Ordering::SeqCst);
            *self.hit.lock().unwrap() = Some(CacheHit {
                entry,
                age: Duration::ZERO,
            });
        }
        async fn invalidate_prefix(&self, _prefix: &str) {
            *self.hit.lock().unwrap() = None;
        }
    }

    fn facade_with_age(age_secs: Option<u64>) -> NpmPackumentCache {
        let hit = age_secs.map(|secs| CacheHit {
            entry: entry(b"cached"),
            age: Duration::from_secs(secs),
        });
        NpmPackumentCache::new(
            Arc::new(FixedAgeBackend::new(hit)),
            Duration::from_secs(300),
        )
    }

    #[tokio::test]
    async fn lookup_classifies_fresh_and_stale() {
        assert_eq!(
            facade_with_age(Some(0)).lookup("k").await.unwrap().1,
            Freshness::Fresh
        );
        assert_eq!(
            facade_with_age(Some(400)).lookup("k").await.unwrap().1,
            Freshness::Stale
        );
        assert!(facade_with_age(None).lookup("k").await.is_none());
    }

    #[tokio::test]
    async fn refresh_claim_dedupes_and_releases_on_drop() {
        let cache = facade_with_age(None);
        let claim = cache.try_claim_refresh("flight").expect("first claim wins");
        assert!(
            cache.try_claim_refresh("flight").is_none(),
            "second claim for the same flight must lose"
        );
        assert!(
            cache.try_claim_refresh("other-flight").is_some(),
            "other flights are unaffected"
        );
        drop(claim);
        assert!(
            cache.try_claim_refresh("flight").is_some(),
            "dropping the claim releases the flight"
        );
    }

    #[tokio::test]
    async fn store_guarded_lands_when_no_invalidation_raced() {
        let backend = Arc::new(InProcessPackumentCache::new(Duration::from_secs(3600)));
        let cache = NpmPackumentCache::new(backend, Duration::from_secs(300));
        let key = cache_key("repo", "pkg", false, false, "http://localhost");

        let guard = cache.begin_store("repo", "pkg");
        cache.store_guarded(&guard, &key, entry(b"fresh")).await;
        assert!(
            cache.lookup(&key).await.is_some(),
            "an unraced guarded store must land"
        );
    }

    #[tokio::test]
    async fn store_guarded_skips_after_racing_invalidation() {
        let backend = Arc::new(InProcessPackumentCache::new(Duration::from_secs(3600)));
        let cache = NpmPackumentCache::new(backend, Duration::from_secs(300));
        let key = cache_key("repo", "pkg", false, false, "http://localhost");

        // A compute captures its guard, then a publish invalidates the
        // package before the compute finishes: the store must be dropped so
        // pre-write data is never re-installed over the newer write.
        let guard = cache.begin_store("repo", "pkg");
        cache.invalidate_package("repo", "pkg").await;
        cache.store_guarded(&guard, &key, entry(b"pre-write")).await;
        assert!(
            cache.lookup(&key).await.is_none(),
            "a guarded store must be skipped after a racing invalidation"
        );

        // Other packages are unaffected: their generation did not change.
        let other_key = cache_key("repo", "other", false, false, "http://localhost");
        let other_guard = cache.begin_store("repo", "other");
        cache
            .store_guarded(&other_guard, &other_key, entry(b"ok"))
            .await;
        assert!(cache.lookup(&other_key).await.is_some());

        // A guard taken AFTER the invalidation stores normally again.
        let fresh_guard = cache.begin_store("repo", "pkg");
        cache
            .store_guarded(&fresh_guard, &key, entry(b"post-write"))
            .await;
        assert_eq!(
            cache.lookup(&key).await.expect("post-write entry").0,
            entry(b"post-write")
        );
    }

    fn unavailable() -> &'static str {
        "timed out"
    }

    #[tokio::test]
    async fn serve_fresh_hit_never_computes() {
        let cache = facade_with_age(Some(1));
        let computed = AtomicUsize::new(0);
        let spawned = AtomicUsize::new(0);
        let served = cache
            .serve(
                "k",
                "serve-fresh-flight",
                || async {
                    computed.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, &str>(entry(b"computed"))
                },
                |_claim| {
                    spawned.fetch_add(1, Ordering::SeqCst);
                },
                unavailable,
            )
            .await
            .expect("serve");
        assert_eq!(served, entry(b"cached"));
        assert_eq!(computed.load(Ordering::SeqCst), 0);
        assert_eq!(spawned.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn serve_stale_hit_serves_immediately_and_claims_one_refresh() {
        let cache = facade_with_age(Some(400));
        let computed = AtomicUsize::new(0);
        let spawned = AtomicUsize::new(0);
        for _ in 0..3 {
            let served = cache
                .serve(
                    "k",
                    "serve-stale-flight",
                    || async {
                        computed.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, &str>(entry(b"computed"))
                    },
                    |claim| {
                        spawned.fetch_add(1, Ordering::SeqCst);
                        // Keep the claim alive across iterations, as a real
                        // in-flight refresh task would.
                        std::mem::forget(claim);
                    },
                    unavailable,
                )
                .await
                .expect("serve");
            assert_eq!(served, entry(b"cached"), "stale entries serve immediately");
        }
        assert_eq!(
            computed.load(Ordering::SeqCst),
            0,
            "stale never computes inline"
        );
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            1,
            "a stale burst wins the refresh claim exactly once"
        );
    }

    #[tokio::test]
    async fn serve_miss_computes_inline() {
        let cache = facade_with_age(None);
        let computed = AtomicUsize::new(0);
        let served = cache
            .serve(
                "k",
                "serve-miss-flight",
                || async {
                    computed.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, &str>(entry(b"computed"))
                },
                |_claim| panic!("a miss must not spawn a background refresh"),
                unavailable,
            )
            .await
            .expect("serve");
        assert_eq!(served, entry(b"computed"));
        assert_eq!(computed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn serve_miss_propagates_compute_error() {
        let cache = facade_with_age(None);
        let result = cache
            .serve(
                "k",
                "serve-error-flight",
                || async { Err::<CachedPackument, _>("boom") },
                |_claim| {},
                unavailable,
            )
            .await;
        assert_eq!(result.unwrap_err(), "boom");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn serve_concurrent_misses_single_flight() {
        let backend = Arc::new(InProcessPackumentCache::new(Duration::from_secs(3600)));
        let cache = Arc::new(NpmPackumentCache::new(backend, Duration::from_secs(300)));
        let computed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let computed = computed.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .serve(
                        "concurrent-key",
                        "serve-concurrent-flight",
                        || async {
                            computed.fetch_add(1, Ordering::SeqCst);
                            // Hold the flight open long enough for the other
                            // tasks to join as followers.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            let e = entry(b"computed-once");
                            cache.store("concurrent-key", e.clone()).await;
                            Ok::<_, String>(e)
                        },
                        |_claim| {},
                        || "timed out".to_string(),
                    )
                    .await
            }));
        }
        for handle in handles {
            let served = handle.await.expect("task").expect("serve");
            assert_eq!(served, entry(b"computed-once"));
        }
        assert_eq!(
            computed.load(Ordering::SeqCst),
            1,
            "concurrent misses for one key must fetch upstream exactly once"
        );
    }

    #[tokio::test]
    async fn serve_with_failing_shared_cache_still_caches_locally() {
        // Redis erroring on every call: the first request computes and the
        // second is a warm hit from the in-process layer — the request path
        // never observes the outage.
        let (_shared, layered_backend) = layered(false);
        let cache = NpmPackumentCache::new(Arc::new(layered_backend), Duration::from_secs(300));
        let computed = AtomicUsize::new(0);
        for _ in 0..2 {
            let served = cache
                .serve(
                    "outage-key",
                    "serve-outage-flight",
                    || async {
                        computed.fetch_add(1, Ordering::SeqCst);
                        let e = entry(b"computed");
                        cache.store("outage-key", e.clone()).await;
                        Ok::<_, String>(e)
                    },
                    |_claim| {},
                    || "timed out".to_string(),
                )
                .await
                .expect("serve must succeed during a shared-cache outage");
            assert_eq!(served, entry(b"computed"));
        }
        assert_eq!(
            computed.load(Ordering::SeqCst),
            1,
            "the second request must be served from the local fallback layer"
        );
    }

    // -- from_config ----------------------------------------------------------------------

    #[tokio::test]
    async fn from_config_respects_enable_flag() {
        let mut config = Config::test_config();
        config.npm_packument_cache_enabled = false;
        assert!(NpmPackumentCache::from_config(&config).is_none());

        config.npm_packument_cache_enabled = true;
        let cache = NpmPackumentCache::from_config(&config).expect("enabled by default");
        // No Redis URL configured: the in-process backend serves out of the
        // box — a store is immediately readable and classified fresh.
        cache.store("k", entry(b"{}")).await;
        assert_eq!(cache.lookup("k").await.unwrap().1, Freshness::Fresh);
    }

    #[test]
    fn from_config_invalid_redis_url_falls_back_in_process() {
        let mut config = Config::test_config();
        config.npm_packument_cache_redis_url = Some("definitely not a redis url".to_string());
        // Must not panic or return None: it degrades to the in-process backend.
        assert!(NpmPackumentCache::from_config(&config).is_some());
    }
}
