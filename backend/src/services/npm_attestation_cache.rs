//! Negative-result cache for the npm attestation meta endpoint (#3764).
//!
//! `npm audit signatures` (and `npm install` with
//! `--foreground-scripts`/provenance checks) asks the registry for a
//! provenance attestation bundle per resolved package version:
//!
//! ```text
//! GET /npm/{repo}/-/npm/v1/attestations/{package}@{version}
//! ```
//!
//! The overwhelming majority of published npm versions have no provenance
//! attestation, so the registry answers `404` for almost every one of these.
//! Artifact Keeper relays that answer correctly — for Remote and Virtual
//! repositories the whole `/-/` meta namespace is proxied through
//! [`crate::api::handlers::npm`] and the upstream status is returned verbatim
//! — but it relayed it *without memoising anything*. Every repeat of the same
//! `pkg@version` question paid a fresh upstream round trip, a request slot
//! against the global concurrency cap, and the repo-resolve + permission
//! queries in front of it.
//!
//! That repeat rate is the whole problem: a CI fleet re-resolves the same
//! dependency graph continuously, so the distinct-URI count is one to two
//! orders of magnitude below the request count. A day of one mid-size
//! deployment's traffic showed ~3.4k distinct attestation URIs across ~231k
//! requests — ~67 identical questions per URI per day, every one of them
//! forwarded to the upstream registry.
//!
//! This cache stores those answers so the repeats never leave the process.
//!
//! Scope — deliberately narrow, because the `/-/` namespace as a whole is
//! **not** cacheable:
//!
//! * **Only `/-/npm/v1/attestations/*`.** `/-/whoami` is per-principal,
//!   `/-/v1/search` is query-dependent, `/-/npm/v1/user` is per-token.
//!   Caching the meta namespace wholesale would be a security bug, so the
//!   gate ([`attestation_spec`]) is a prefix match on exactly one endpoint.
//! * **Only negative answers** (`404`, `410`). npm forbids republishing a
//!   version, so "this version has no attestation" is effectively stable;
//!   `200` bodies are real provenance documents and are never cached, so a
//!   newly-published attestation is visible immediately. Authentication
//!   failures (`401`/`403`), rate limits and 5xx are transient and never
//!   cached either.
//! * **Only when the repository's npm scope policy is inactive.** An active
//!   policy rewrites meta bodies per repository
//!   (`filter_meta_response`), so a cached body would have to carry the
//!   policy's identity to stay correct. Skipping the cache there keeps the
//!   filtering path byte-for-byte unchanged.
//! * **Only for query-less requests.** An attestation request carries no
//!   query string; anything that does is a different question and is passed
//!   straight through.
//!
//! Key: `(member_repo_id, upstream_url, meta_path)`. The **answering member**
//! repository is the identity, not the repository named in the URL: a Virtual
//! repo resolves `/-/*` against the members *this caller is authorized to
//! read* (`authorized_virtual_members`), so keying on the virtual repo would
//! let one tenant's request be answered from an upstream response fetched for
//! a member they cannot reach. Keying on the member that actually answered
//! means the authorization walk still runs on every request and can only
//! reach entries for members the caller may use — while two virtual repos
//! sharing a member correctly share one cache entry. The upstream URL is
//! folded in so repointing a repository's upstream cannot be answered from
//! the previous upstream's entry.
//!
//! Bounds: entries expire at the TTL and the map is capped by entry count
//! (oldest-stored first eviction) with a per-body byte cap, so neither a
//! large dependency graph nor a hostile upstream error page can grow it
//! without limit. The cache is in-process and per-replica; there is no
//! cross-replica coordination to get wrong because there is nothing to
//! invalidate — entries are immutable facts that simply age out.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::StatusCode;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::Config;

/// The `/-/` meta path prefix this cache is scoped to, as captured by the
/// `/:repo_key/-/*rest` wildcard (no leading slash).
const ATTESTATION_PATH_PREFIX: &str = "npm/v1/attestations/";

/// Default TTL for a cached negative answer (24 h).
///
/// npm forbids republishing a version, so `404 no attestation for pkg@ver` is
/// stable for the lifetime of that version in all but one case: an
/// attestation added *after* publish. That is rare enough that a day of
/// staleness is an acceptable default, and
/// `NPM_ATTESTATION_NEGATIVE_CACHE_TTL_SECS` exists so an operator who cares
/// can shorten it. Even an hour removes the great majority of the repeats
/// (~67 identical questions per URI per day in the traffic sample above).
pub const NPM_ATTESTATION_NEGATIVE_TTL_DEFAULT_SECS: u64 = 86_400;

/// Soft cap on cached entries. One entry per distinct `pkg@version` asked
/// about per member repository; the observed distinct-URI count for a
/// mid-size deployment was ~3.4k/day, so this leaves an order of magnitude of
/// headroom while bounding worst-case memory to roughly
/// `MAX_ENTRIES * MAX_BODY_BYTES` (~64 MiB) even if every body were at the cap.
pub const NPM_ATTESTATION_CACHE_MAX_ENTRIES: usize = 16_384;

/// Largest upstream body this cache will store. A registry 404 body is a
/// couple of hundred bytes of JSON; anything larger is not the answer shape
/// this cache exists for, so it is served through and not stored rather than
/// letting a broken or hostile upstream size the map.
pub const NPM_ATTESTATION_CACHE_MAX_BODY_BYTES: usize = 4 * 1024;

/// Longest meta path this cache will key on. Bounds key memory against a
/// client that walks arbitrarily long `pkg@version` specs; longer paths are
/// proxied uncached.
const MAX_KEYED_PATH_LEN: usize = 512;

/// Whether `meta_path` addresses the npm attestation endpoint, and if so the
/// package spec it asks about.
///
/// `meta_path` is the `/:repo_key/-/*rest` wildcard capture, so it has no
/// leading slash — but leading and trailing slashes are tolerated because
/// axum's capture semantics for wildcards have changed across versions and
/// this gate must not silently stop matching if they change again.
///
/// The spec is returned only so callers can log or assert on it; the gate
/// itself is deliberately a plain prefix match with a non-empty remainder.
/// Nothing else lives under `/-/npm/v1/attestations/` in the npm registry
/// protocol, and the remainder may be a bare name (`lodash@4.17.21`), a
/// percent-encoded scoped name (`@scope%2fname@1.0.0`) or an unencoded one
/// (`@scope/name@1.0.0`) depending on the client — matching the prefix
/// handles all three without trying to parse the spec.
pub fn attestation_spec(meta_path: &str) -> Option<&str> {
    let normalized = meta_path.trim_matches('/');
    let spec = normalized.strip_prefix(ATTESTATION_PATH_PREFIX)?;
    if spec.is_empty() {
        return None;
    }
    Some(spec)
}

/// Short digest of the upstream base URL, folded into the cache key so an
/// upstream repoint is never answered from the old upstream's entry. Hashed
/// rather than embedded because an upstream URL may carry credentials in its
/// userinfo, and cache keys surface in debug logs.
fn upstream_hash(upstream_url: &str) -> String {
    hex::encode(Sha256::digest(
        upstream_url.trim_end_matches('/').as_bytes(),
    ))[..16]
        .to_string()
}

/// Cache key: `"{member_repo_id}|{upstream_hash}|{meta_path}"`.
///
/// The member repository id leads: it is the identity that makes a hit safe
/// (see the module docs). A UUID's text form cannot contain `|`, and neither
/// can the hex digest, so the three components can never run together
/// ambiguously.
///
/// `None` when the path is too long to key on, which the caller must treat as
/// "proxy this uncached".
pub fn cache_key(member_repo_id: Uuid, upstream_url: &str, meta_path: &str) -> Option<String> {
    let normalized = meta_path.trim_matches('/');
    if normalized.len() > MAX_KEYED_PATH_LEN {
        return None;
    }
    Some(format!(
        "{}|{}|{}",
        member_repo_id,
        upstream_hash(upstream_url),
        normalized
    ))
}

/// A proxied `/-/` meta response held verbatim: status *and* body together,
/// so a cached `404` replays as a `404` and never as an empty `200`.
///
/// `status` is a [`StatusCode`], not a `u16`: an entry's only source is an
/// upstream response, whose status has already been parsed into a
/// `StatusCode`, so keeping the integer would mean re-parsing on the way out
/// and inventing an "unrepresentable cached status" failure mode that cannot
/// occur. Holding the parsed type makes that state unrepresentable rather
/// than merely untested. (`u16` is deceptive here for a second reason: `http`
/// accepts every value in `100..=999`, so the obvious "invalid status" probe
/// is not actually invalid.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedMetaResponse {
    pub status: StatusCode,
    pub content_type: String,
    pub bytes: Bytes,
}

impl CachedMetaResponse {
    pub fn new(status: StatusCode, content_type: impl Into<String>, bytes: Bytes) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            bytes,
        }
    }
}

/// Whether an upstream answer may be stored.
///
/// `404`/`410` only — the two ways a registry says "this version has no
/// attestation", both of which npm's no-republish rule makes stable. A `200`
/// carries a real provenance bundle and is deliberately not cached so a
/// newly-published attestation is served the moment upstream has it; `401` and
/// `403` depend on credentials; `429` and 5xx are transient and caching them
/// would turn a blip into a TTL-long outage.
pub fn is_cacheable_status(status: u16) -> bool {
    matches!(status, 404 | 410)
}

/// Whether an upstream answer of this status and size may be stored.
pub fn is_cacheable(response: &CachedMetaResponse) -> bool {
    is_cacheable_status(response.status.as_u16())
        && response.bytes.len() <= NPM_ATTESTATION_CACHE_MAX_BODY_BYTES
}

struct CacheEntry {
    response: CachedMetaResponse,
    stored_at: Instant,
}

/// In-process, TTL'd negative cache for proxied npm attestation answers.
pub struct NpmAttestationCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_entries: usize,
}

impl NpmAttestationCache {
    pub fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, NPM_ATTESTATION_CACHE_MAX_ENTRIES)
    }

    pub fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
            max_entries: max_entries.max(1),
        }
    }

    /// Build the cache described by the configuration, or `None` when it is
    /// disabled. A TTL of zero disables it too: "cache for no time at all" is
    /// how an operator naturally spells "off", and honouring it here means
    /// that spelling does not silently install a cache that stores entries
    /// only to treat every one of them as already expired.
    pub fn from_config(config: &Config) -> Option<Arc<Self>> {
        if !config.npm_attestation_negative_cache_enabled
            || config.npm_attestation_negative_cache_ttl_secs == 0
        {
            return None;
        }
        Some(Arc::new(Self::new(Duration::from_secs(
            config.npm_attestation_negative_cache_ttl_secs,
        ))))
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The cached answer for `key`, or `None` when absent or past its TTL.
    ///
    /// An expired entry is left in place rather than removed: the read path
    /// holds a read lock, and the store that follows this miss evicts expired
    /// entries anyway, so taking a write lock here would only add contention
    /// on the hot path.
    pub async fn lookup(&self, key: &str) -> Option<CachedMetaResponse> {
        let entries = self.entries.read().await;
        let entry = entries.get(key)?;
        if entry.stored_at.elapsed() >= self.ttl {
            return None;
        }
        Some(entry.response.clone())
    }

    /// Store an answer, dropping expired entries and then the oldest entries
    /// if the map is over its cap.
    ///
    /// Callers must gate on [`is_cacheable`] first; this stores whatever it is
    /// given so tests can install entries directly.
    pub async fn store(&self, key: String, response: CachedMetaResponse) {
        let mut entries = self.entries.write().await;
        entries.insert(
            key.clone(),
            CacheEntry {
                response,
                stored_at: Instant::now(),
            },
        );
        // Expired entries are dropped first: reclaiming those is free
        // (nothing could have been served from them) and usually enough, so
        // a steady-state cache evicts live entries only when genuinely full.
        //
        // The just-inserted key is exempt, the same way the entry-cap loop
        // below always keeps the newest write. Without the exemption a TTL at
        // or below this sweep's own resolution makes `store` discard the very
        // entry it was asked to hold, so it silently does nothing -- and a
        // caller has no way to tell that apart from a successful store. It
        // cannot happen at a configured TTL (`from_config` rejects zero), but
        // "store means store" should not depend on that.
        let ttl = self.ttl;
        entries.retain(|entry_key, entry| *entry_key == key || entry.stored_at.elapsed() < ttl);
        while entries.len() > self.max_entries {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.stored_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&oldest);
        }
    }

    /// Number of entries currently held, expired ones included. Observability
    /// and test hook only.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: StatusCode, body: &'static [u8]) -> CachedMetaResponse {
        CachedMetaResponse::new(status, "application/json", Bytes::from_static(body))
    }

    fn not_found() -> CachedMetaResponse {
        response(StatusCode::NOT_FOUND, br#"{"error":"Not found"}"#)
    }

    // -- the endpoint gate ---------------------------------------------------

    #[test]
    fn attestation_spec_matches_the_attestation_endpoint() {
        assert_eq!(
            attestation_spec("npm/v1/attestations/lodash@4.17.21"),
            Some("lodash@4.17.21")
        );
        // Percent-encoded scoped name, which is what npm actually sends.
        assert_eq!(
            attestation_spec("npm/v1/attestations/@scope%2fname@1.0.0"),
            Some("@scope%2fname@1.0.0")
        );
        // Unencoded scoped name: extra path segments are still one spec.
        assert_eq!(
            attestation_spec("npm/v1/attestations/@scope/name@1.0.0"),
            Some("@scope/name@1.0.0")
        );
        // Leading / trailing slashes tolerated, so a change in axum's
        // wildcard-capture semantics cannot silently disable the gate.
        assert_eq!(
            attestation_spec("/npm/v1/attestations/lodash@4.17.21"),
            Some("lodash@4.17.21")
        );
    }

    /// The security-critical half of the gate: every other `/-/` endpoint must
    /// stay uncached. `/-/whoami` is per-principal, `/-/v1/search` is
    /// query-dependent, and the audit endpoints are request-body dependent, so
    /// caching any of them would serve one caller's answer to another.
    #[test]
    fn attestation_spec_rejects_every_other_meta_endpoint() {
        for path in [
            "whoami",
            "ping",
            "v1/search",
            "npm/v1/user",
            "npm/v1/security/advisories/bulk",
            "npm/v1/security/audits/quick",
            "user/alice/package",
            "org/acme/package",
            "by-user/alice",
            "all",
            // The prefix with no spec is not a package question.
            "npm/v1/attestations",
            "npm/v1/attestations/",
            // Near-misses must not match: a prefix check is only safe if it
            // is anchored at the start of the path.
            "attestations/lodash@4.17.21",
            "npm/v2/attestations/lodash@4.17.21",
            "evil/npm/v1/attestations/lodash@4.17.21",
        ] {
            assert_eq!(attestation_spec(path), None, "must not cache /-/{path}");
        }
    }

    // -- keys ---------------------------------------------------------------

    #[test]
    fn cache_key_separates_members_upstreams_and_paths() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let path = "npm/v1/attestations/lodash@4.17.21";
        let up = "https://registry.npmjs.org";

        let key = cache_key(a, up, path).expect("keyable");
        // Same member, same upstream, same path -> same entry (that is the
        // whole point: two virtual repos sharing a member share the answer).
        assert_eq!(cache_key(a, up, path).as_deref(), Some(key.as_str()));
        // A different member repository must never share an entry.
        assert_ne!(cache_key(b, up, path), Some(key.clone()));
        // Repointing the upstream must not be answered from the old one.
        assert_ne!(
            cache_key(a, "https://npm.example.test", path),
            Some(key.clone())
        );
        // A different package version is a different question.
        assert_ne!(
            cache_key(a, up, "npm/v1/attestations/lodash@4.17.20"),
            Some(key.clone())
        );
        // Trailing-slash differences must not split an entry in two.
        assert_eq!(
            cache_key(a, up, &format!("/{path}")).as_deref(),
            Some(key.as_str())
        );
        assert_eq!(
            cache_key(a, "https://registry.npmjs.org/", path).as_deref(),
            Some(key.as_str())
        );
    }

    #[test]
    fn cache_key_does_not_leak_upstream_credentials() {
        let key = cache_key(
            Uuid::from_u128(1),
            "https://user:s3cret@npm.example.test",
            "npm/v1/attestations/lodash@4.17.21",
        )
        .expect("keyable");
        assert!(!key.contains("s3cret"), "key must not carry userinfo");
        assert!(!key.contains("user:"), "key must not carry userinfo");
    }

    #[test]
    fn cache_key_refuses_paths_too_long_to_key_on() {
        let long = format!(
            "{}{}",
            ATTESTATION_PATH_PREFIX,
            "a".repeat(MAX_KEYED_PATH_LEN)
        );
        assert!(long.len() > MAX_KEYED_PATH_LEN);
        assert_eq!(
            cache_key(Uuid::from_u128(1), "https://up.test", &long),
            None
        );
    }

    // -- what may be stored -------------------------------------------------

    /// Only the two "no attestation exists" answers are cacheable. A `200` is
    /// a real provenance bundle, so leaving it uncached is what makes a
    /// newly-published attestation visible immediately; the rest are
    /// credential-dependent or transient.
    #[test]
    fn only_negative_answers_are_cacheable() {
        assert!(is_cacheable_status(404));
        assert!(is_cacheable_status(410));
        for status in [200, 201, 301, 304, 400, 401, 403, 429, 500, 502, 503] {
            assert!(
                !is_cacheable_status(status),
                "status {status} must not be cached"
            );
        }
    }

    #[test]
    fn oversized_bodies_are_not_cacheable() {
        let big = Bytes::from(vec![b'x'; NPM_ATTESTATION_CACHE_MAX_BODY_BYTES + 1]);
        assert!(!is_cacheable(&CachedMetaResponse::new(
            StatusCode::NOT_FOUND,
            "application/json",
            big
        )));
        let at_cap = Bytes::from(vec![b'x'; NPM_ATTESTATION_CACHE_MAX_BODY_BYTES]);
        assert!(is_cacheable(&CachedMetaResponse::new(
            StatusCode::NOT_FOUND,
            "application/json",
            at_cap
        )));
    }

    // -- store / lookup -----------------------------------------------------

    #[tokio::test]
    async fn stored_entry_is_returned_with_status_and_body_intact() {
        let cache = NpmAttestationCache::new(Duration::from_secs(60));
        assert!(cache.is_empty().await);
        cache.store("k".to_string(), not_found()).await;

        let hit = cache.lookup("k").await.expect("hit");
        assert_eq!(
            hit.status,
            StatusCode::NOT_FOUND,
            "a cached 404 must replay as a 404"
        );
        assert_eq!(hit.content_type, "application/json");
        assert_eq!(hit.bytes, Bytes::from_static(br#"{"error":"Not found"}"#));
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn unknown_key_misses() {
        let cache = NpmAttestationCache::new(Duration::from_secs(60));
        cache.store("k".to_string(), not_found()).await;
        assert_eq!(cache.lookup("other").await, None);
    }

    #[tokio::test]
    async fn entries_expire_at_the_ttl() {
        // A zero TTL would disable the cache via `from_config`; constructed
        // directly it makes every entry instantly expired, which is the
        // cheapest way to assert the age check actually runs.
        let cache = NpmAttestationCache::new(Duration::ZERO);
        cache.store("k".to_string(), not_found()).await;
        assert_eq!(cache.lookup("k").await, None, "expired entry must miss");
    }

    /// A stream of writes that expire immediately must not grow the map: each
    /// store sweeps the previous entry. The write being stored is exempt from
    /// its own sweep, so exactly one entry survives rather than zero — `store`
    /// must never silently discard what it was handed.
    #[tokio::test]
    async fn store_sweeps_expired_entries_but_keeps_the_new_one() {
        let cache = NpmAttestationCache::new(Duration::ZERO);
        cache.store("a".to_string(), not_found()).await;
        assert_eq!(cache.len().await, 1, "store must retain its own write");
        cache.store("b".to_string(), not_found()).await;
        assert_eq!(cache.len().await, 1, "the expired 'a' must be swept");
    }

    /// The expiry sweep must not evict entries that are still live.
    #[tokio::test]
    async fn store_keeps_live_entries() {
        let cache = NpmAttestationCache::new(Duration::from_secs(600));
        cache.store("a".to_string(), not_found()).await;
        cache.store("b".to_string(), not_found()).await;
        assert_eq!(cache.len().await, 2);
        assert!(cache.lookup("a").await.is_some());
        assert!(cache.lookup("b").await.is_some());
    }

    #[tokio::test]
    async fn store_enforces_the_entry_cap() {
        let cache = NpmAttestationCache::with_max_entries(Duration::from_secs(600), 2);
        for i in 0..5 {
            cache.store(format!("k{i}"), not_found()).await;
        }
        assert_eq!(cache.len().await, 2, "entry cap must bound the map");
        // The most recent write always survives eviction.
        assert!(cache.lookup("k4").await.is_some());
    }

    #[tokio::test]
    async fn max_entries_is_never_zero() {
        let cache = NpmAttestationCache::with_max_entries(Duration::from_secs(600), 0);
        cache.store("k".to_string(), not_found()).await;
        assert!(
            cache.lookup("k").await.is_some(),
            "a zero cap must clamp to one entry, not evict everything"
        );
    }

    // -- configuration ------------------------------------------------------

    #[test]
    fn enabled_by_default_with_a_one_day_ttl() {
        let config = Config::default();
        let cache = NpmAttestationCache::from_config(&config).expect("enabled by default");
        assert_eq!(cache.ttl(), Duration::from_secs(86_400));
        assert_eq!(NPM_ATTESTATION_NEGATIVE_TTL_DEFAULT_SECS, 86_400);
    }

    #[test]
    fn from_config_honours_the_opt_out() {
        let config = Config {
            npm_attestation_negative_cache_enabled: false,
            ..Config::default()
        };
        assert!(NpmAttestationCache::from_config(&config).is_none());
    }

    /// A zero TTL must disable the cache rather than install one whose every
    /// entry is born expired — otherwise the natural way to spell "off" would
    /// pay all of the cache's costs for none of its benefit.
    #[test]
    fn from_config_treats_a_zero_ttl_as_disabled() {
        let config = Config {
            npm_attestation_negative_cache_ttl_secs: 0,
            ..Config::default()
        };
        assert!(NpmAttestationCache::from_config(&config).is_none());
    }

    #[test]
    fn from_config_honours_a_custom_ttl() {
        let config = Config {
            npm_attestation_negative_cache_ttl_secs: 3_600,
            ..Config::default()
        };
        let cache = NpmAttestationCache::from_config(&config).expect("enabled");
        assert_eq!(cache.ttl(), Duration::from_secs(3_600));
    }
}
