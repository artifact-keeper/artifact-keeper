//! Per-remote upstream filter (#840, first slice).
//!
//! A Remote repository can declare which paths it is allowed to request from
//! its upstream: `include_patterns` (if non-empty, a path must match at least
//! one) and `exclude_patterns` (a path matching any is refused). The shape is
//! the same `{include_patterns, exclude_patterns}` object peers use for their
//! `replication_filter`.
//!
//! # Matching
//!
//! Patterns are Rust `regex` syntax with **search** semantics, exactly like
//! the peer `replication_filter`: a pattern matches if it matches anywhere in
//! the subject, so anchor it with `^` / `$` to pin a prefix or suffix
//! (`^com/acme/` admits the `com.acme` Maven group and nothing else). The
//! subject is the path the proxy would request from the upstream, relative to
//! the remote's `upstream_url` and without a leading `/` — for Maven that is
//! the repository layout path (`com/acme/lib/1.0/lib-1.0.jar`). When a format
//! fetches from an absolute URL instead (a PyPI file on
//! `files.pythonhosted.org`, a cargo `dl` host), the subject is that full URL
//! unless it lies under `upstream_url`, in which case the prefix is stripped.
//! A query string is part of the subject. npm metadata is fetched as the
//! percent-encoded `@scope%2Fname` while tarballs are `@scope/name/-/...`, so
//! a scope rule should match both forms (`^@acme(/|%2F)`). The subject is the
//! wire path on purpose: it is exactly what would leave the process, and
//! changing it later would silently change existing filters.
//!
//! Upstream contact made outside `ProxyService` is not filtered in this first
//! slice: the npm `/-/` passthroughs (search, attestations, ping), npm audit,
//! the curation upstream sync, change feeds and the admin `test-upstream`
//! probe.
//!
//! # Enforcement
//!
//! The filter gates **upstream contact**. `ProxyService` consults it at the one
//! point every fetch variant passes through before it builds an upstream URL
//! (`ProxyService::gated_upstream_url`), so a refused path answers `NotFound`
//! without a single byte leaving the process — and, since virtual repositories
//! resolve Remote members through the same service, a member whose filter
//! refuses the path is skipped without being contacted (#840: one dead fringe
//! remote no longer stalls every `maven-metadata.xml` merge).
//!
//! # Already-cached objects
//!
//! A proxy-cache entry for a now-refused path is served **only while it is
//! fresh**. Once it expires it is not revalidated (that would contact the
//! upstream) and stale-if-error does not apply: the expired entry is refused
//! with `NotFound` exactly like a miss. Immutable entries (released Maven
//! artifacts, content-addressed blobs) effectively never expire, so purge them
//! with `POST /api/v1/repositories/{key}/cache/invalidate` to hide them at once.
//!
//! # Validation
//!
//! Patterns are validated on write and bounded: at most
//! [`MAX_PATTERNS_PER_LIST`] per list, [`MAX_PATTERN_LEN`] bytes each, and each
//! list must compile to an NFA program of at most [`REGEX_SIZE_LIMIT`] bytes
//! (so a counted repetition such as `(\w{1000}){1000}` is rejected up front).
//! The `regex` crate has no backtracking, but its match time is still
//! proportional to program size times subject length, so the program ceiling
//! is deliberately small (64 KiB): the worst accepted list matches an 8 KiB
//! path in well under a millisecond, while realistic prefix/suffix filters use
//! a tiny fraction of it. The lazy-DFA cache uses the same bound (a cache
//! capacity, not a compile-time check). At match time, a subject longer than
//! [`MAX_SUBJECT_LEN`] is refused without being matched.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache as MokaCache;
use once_cell::sync::Lazy;
use regex::{RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// `repository_config` key the filter is stored under (JSON value).
pub const UPSTREAM_FILTER_CONFIG_KEY: &str = "upstream_filter";

/// Maximum number of patterns accepted in each of the two lists.
pub const MAX_PATTERNS_PER_LIST: usize = 64;

/// Maximum length, in bytes, of a single pattern.
pub const MAX_PATTERN_LEN: usize = 512;

/// Ceiling on the compiled NFA program size of each pattern list (bytes);
/// also used as the lazy-DFA cache capacity. Kept small because match cost
/// grows with program size (see the module doc).
pub const REGEX_SIZE_LIMIT: usize = 64 * 1024;

/// Longest subject a filter will match. A longer upstream path is refused
/// (when a filter is configured) instead of spending CPU matching it; no
/// legitimate package path comes near this, and the proxy cache key itself is
/// capped at 1 KiB.
pub const MAX_SUBJECT_LEN: usize = 4096;

/// Maximum syntactic nesting depth of a pattern.
const REGEX_NEST_LIMIT: u32 = 64;

/// How long a compiled filter is reused before being re-read from the
/// database. A write on this replica invalidates immediately; other replicas
/// converge within this window.
const FILTER_CACHE_TTL: Duration = Duration::from_secs(30);
const FILTER_CACHE_CAPACITY: u64 = 10_000;

/// Upstream filter of a Remote repository, as stored and as exchanged over
/// the API.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpstreamFilter {
    /// If non-empty, a path is fetched from upstream only when it matches at
    /// least one of these regexes (search semantics; anchor with `^`/`$`).
    #[serde(default)]
    pub include_patterns: Vec<String>,
    /// A path matching any of these regexes is never fetched from upstream.
    /// Exclusion wins over inclusion.
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

impl UpstreamFilter {
    /// Whether the filter constrains nothing (both lists empty).
    pub fn is_empty(&self) -> bool {
        self.include_patterns.is_empty() && self.exclude_patterns.is_empty()
    }

    /// Validate and compile. The error names the offending list and index so
    /// an API caller can find the pattern.
    pub fn compile(&self) -> std::result::Result<CompiledUpstreamFilter, String> {
        Ok(CompiledUpstreamFilter {
            include: compile_list("include_patterns", &self.include_patterns)?,
            exclude: compile_list("exclude_patterns", &self.exclude_patterns)?,
            deny_all: false,
        })
    }
}

fn set_builder<I, S>(patterns: I) -> RegexSetBuilder
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut builder = RegexSetBuilder::new(patterns);
    builder
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT);
    builder
}

/// Compile one list into a [`RegexSet`], or `None` when the list is empty.
fn compile_list(
    list_name: &str,
    patterns: &[String],
) -> std::result::Result<Option<RegexSet>, String> {
    if patterns.is_empty() {
        return Ok(None);
    }
    if patterns.len() > MAX_PATTERNS_PER_LIST {
        return Err(format!(
            "{list_name}: at most {MAX_PATTERNS_PER_LIST} patterns are allowed, got {}",
            patterns.len()
        ));
    }
    for (i, pattern) in patterns.iter().enumerate() {
        if pattern.is_empty() {
            return Err(format!("{list_name}[{i}]: pattern must not be empty"));
        }
        if pattern.len() > MAX_PATTERN_LEN {
            return Err(format!(
                "{list_name}[{i}]: pattern exceeds {MAX_PATTERN_LEN} bytes"
            ));
        }
        // Compile each pattern on its own first so the error names it.
        set_builder([pattern])
            .build()
            .map_err(|e| format!("{list_name}[{i}]: invalid regex: {e}"))?;
    }
    set_builder(patterns)
        .build()
        .map(Some)
        .map_err(|e| format!("{list_name}: {e}"))
}

/// A validated, compiled [`UpstreamFilter`].
#[derive(Debug, Clone)]
pub struct CompiledUpstreamFilter {
    include: Option<RegexSet>,
    exclude: Option<RegexSet>,
    /// Fail-closed stand-in for a stored value that no longer parses or
    /// compiles (only reachable by editing `repository_config` directly).
    deny_all: bool,
}

impl CompiledUpstreamFilter {
    fn deny_all() -> Self {
        Self {
            include: None,
            exclude: None,
            deny_all: true,
        }
    }

    /// Whether `subject` (see [`filter_subject`]) may be fetched from upstream.
    pub fn allows(&self, subject: &str) -> bool {
        if self.deny_all || subject.len() > MAX_SUBJECT_LEN {
            return false;
        }
        if let Some(include) = &self.include {
            if !include.is_match(subject) {
                return false;
            }
        }
        !self
            .exclude
            .as_ref()
            .is_some_and(|exclude| exclude.is_match(subject))
    }
}

/// The string the filter is matched against for a fetch of `fetch_path` from a
/// remote whose upstream is `upstream_url`: the upstream-relative path without
/// a leading `/`, or — for an absolute fetch URL outside `upstream_url` — the
/// full URL.
pub fn filter_subject<'a>(upstream_url: &str, fetch_path: &'a str) -> &'a str {
    if fetch_path.starts_with("http://") || fetch_path.starts_with("https://") {
        let base = upstream_url.trim_end_matches('/');
        return match fetch_path.strip_prefix(base) {
            Some(rest) if rest.starts_with('/') => rest.trim_start_matches('/'),
            _ => fetch_path,
        };
    }
    fetch_path.trim_start_matches('/')
}

/// Parse and compile a stored value, keeping the parsed form for display.
fn parse_stored(
    raw: &str,
) -> std::result::Result<(UpstreamFilter, CompiledUpstreamFilter), String> {
    let filter = serde_json::from_str::<UpstreamFilter>(raw)
        .map_err(|e| format!("stored value is not a valid upstream filter: {e}"))?;
    let compiled = filter.compile()?;
    Ok((filter, compiled))
}

/// Parse a stored value and compile it; a value that fails either step is
/// mapped to a deny-all filter (fail closed) so a corrupted row cannot
/// silently reopen a remote the operator restricted.
fn compile_stored(repo_id: Uuid, raw: &str) -> CompiledUpstreamFilter {
    parse_stored(raw).map(|(_, compiled)| compiled).unwrap_or_else(|err| {
        tracing::error!(
            repository_id = %repo_id,
            error = %err,
            "stored upstream_filter is unusable; refusing all upstream fetches for this repository until it is replaced"
        );
        CompiledUpstreamFilter::deny_all()
    })
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Read the raw stored filter, if any.
async fn load_raw(db: &PgPool, repo_id: Uuid) -> Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2")
            .bind(repo_id)
            .bind(UPSTREAM_FILTER_CONFIG_KEY)
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(row.map(|(v,)| v))
}

/// What is stored for a repository, as the read API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredUpstreamFilter {
    /// No filter configured: every path may be fetched.
    None,
    /// A valid filter, enforced as stored.
    Valid(UpstreamFilter),
    /// A stored value that no longer parses or compiles (only reachable by
    /// editing `repository_config` directly). Enforcement treats it as
    /// refuse-all, so the read API must not report it as "no filter".
    Unusable(String),
}

fn classify_stored(raw: Option<&str>) -> StoredUpstreamFilter {
    match raw {
        None => StoredUpstreamFilter::None,
        Some(raw) => match parse_stored(raw) {
            Ok((filter, _)) => StoredUpstreamFilter::Valid(filter),
            Err(err) => StoredUpstreamFilter::Unusable(err),
        },
    }
}

/// Load the stored filter for display, distinguishing an unusable row from
/// "no filter" (see [`StoredUpstreamFilter::Unusable`]).
pub async fn load_upstream_filter(db: &PgPool, repo_id: Uuid) -> Result<StoredUpstreamFilter> {
    Ok(classify_stored(load_raw(db, repo_id).await?.as_deref()))
}

/// Validate and persist `filter`. An empty filter removes the row. The
/// in-process compiled-filter cache is invalidated before returning.
pub async fn save_upstream_filter(
    db: &PgPool,
    repo_id: Uuid,
    filter: &UpstreamFilter,
) -> Result<()> {
    if filter.is_empty() {
        return delete_upstream_filter(db, repo_id).await;
    }
    filter.compile().map_err(AppError::Validation)?;
    let value = serde_json::to_string(filter)
        .map_err(|e| AppError::Internal(format!("Failed to serialize upstream filter: {e}")))?;
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $3, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(UPSTREAM_FILTER_CONFIG_KEY)
    .bind(&value)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    invalidate_everywhere(db, repo_id).await;
    Ok(())
}

/// Remove the filter (idempotent).
pub async fn delete_upstream_filter(db: &PgPool, repo_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM repository_config WHERE repository_id = $1 AND key = $2")
        .bind(repo_id)
        .bind(UPSTREAM_FILTER_CONFIG_KEY)
        .execute(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    invalidate_everywhere(db, repo_id).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

type CachedFilter = Option<Arc<CompiledUpstreamFilter>>;

static FILTER_CACHE: Lazy<MokaCache<Uuid, CachedFilter>> = Lazy::new(|| {
    MokaCache::builder()
        .max_capacity(FILTER_CACHE_CAPACITY)
        .time_to_live(FILTER_CACHE_TTL)
        .build()
});

/// Bumped on every invalidation. A loader only publishes what it read if no
/// invalidation happened since it started, so a read that raced a PUT/DELETE
/// can never re-insert the pre-write filter after the writer invalidated it.
static FILTER_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Drop this process's cached compiled filter for `repo_id`. Called locally by
/// the writer and, through the `upstream_filter_changed` cache-invalidation
/// event, on every other replica.
pub async fn invalidate_cached_filter(repo_id: Uuid) {
    FILTER_GENERATION.fetch_add(1, Ordering::SeqCst);
    FILTER_CACHE.invalidate(&repo_id).await;
}

/// Invalidate locally and tell the other replicas to do the same.
async fn invalidate_everywhere(db: &PgPool, repo_id: Uuid) {
    invalidate_cached_filter(repo_id).await;
    crate::services::cache_invalidation::notify_upstream_filter_changed(db, repo_id).await;
}

/// The compiled filter for `repo_id`, through the short-TTL in-process cache.
/// `Ok(None)` means "no filter configured". A database error is returned (and
/// not cached) rather than treated as "no filter".
async fn compiled_filter(db: &PgPool, repo_id: Uuid) -> Result<CachedFilter> {
    if let Some(hit) = FILTER_CACHE.get(&repo_id).await {
        return Ok(hit);
    }
    let generation = FILTER_GENERATION.load(Ordering::SeqCst);
    let compiled = load_raw(db, repo_id)
        .await?
        .map(|raw| Arc::new(compile_stored(repo_id, &raw)));
    if FILTER_GENERATION.load(Ordering::SeqCst) == generation {
        FILTER_CACHE.insert(repo_id, compiled.clone()).await;
    }
    Ok(compiled)
}

/// Pure decision used by [`ensure_upstream_allowed`]: `Err(NotFound)` when the
/// filter refuses the fetch.
fn check_filter(
    filter: Option<&CompiledUpstreamFilter>,
    repo_key: &str,
    upstream_url: &str,
    fetch_path: &str,
) -> Result<()> {
    let subject = filter_subject(upstream_url, fetch_path);
    match filter {
        // The subject is deliberately not echoed: it can be an absolute URL,
        // and this message reaches the proxy's 404 log line.
        Some(filter) if !filter.allows(subject) => Err(AppError::NotFound(format!(
            "path excluded by the upstream filter of repository '{repo_key}'"
        ))),
        _ => Ok(()),
    }
}

/// Refuse (with `NotFound`) a fetch of `fetch_path` from the upstream of the
/// Remote repository `repo_id` when its upstream filter does not admit it.
pub async fn ensure_upstream_allowed(
    db: &PgPool,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    fetch_path: &str,
) -> Result<()> {
    let filter = compiled_filter(db, repo_id).await?;
    let decision = check_filter(filter.as_deref(), repo_key, upstream_url, fetch_path);
    if decision.is_err() {
        tracing::debug!(
            repository_id = %repo_id,
            repo_key = %repo_key,
            "upstream fetch refused by upstream filter"
        );
    }
    decision
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn filter(include: &[&str], exclude: &[&str]) -> UpstreamFilter {
        UpstreamFilter {
            include_patterns: include.iter().map(|s| s.to_string()).collect(),
            exclude_patterns: exclude.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn compiled(include: &[&str], exclude: &[&str]) -> CompiledUpstreamFilter {
        filter(include, exclude).compile().expect("valid filter")
    }

    #[test]
    fn empty_filter_allows_everything() {
        let f = compiled(&[], &[]);
        assert!(filter(&[], &[]).is_empty());
        assert!(f.allows("com/acme/lib/1.0/lib-1.0.jar"));
        assert!(f.allows(""));
    }

    #[test]
    fn include_list_admits_only_matching_paths() {
        let f = compiled(&["^com/fringe/", "^org/fringe/"], &[]);
        assert!(f.allows("com/fringe/lib/1.0/lib-1.0.jar"));
        assert!(f.allows("org/fringe/x/maven-metadata.xml"));
        assert!(!f.allows("org/apache/commons/maven-metadata.xml"));
        // Search semantics: an unanchored pattern matches anywhere.
        let unanchored = compiled(&["fringe"], &[]);
        assert!(unanchored.allows("org/apache/fringe-tools/1.0/x.pom"));
    }

    #[test]
    fn exclude_wins_over_include() {
        let f = compiled(&["^com/acme/"], &["-SNAPSHOT/", r"\.asc$"]);
        assert!(f.allows("com/acme/lib/1.0/lib-1.0.jar"));
        assert!(!f.allows("com/acme/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar"));
        assert!(!f.allows("com/acme/lib/1.0/lib-1.0.jar.asc"));
        let exclude_only = compiled(&[], &["^express/"]);
        assert!(!exclude_only.allows("express/-/express-4.0.0.tgz"));
        assert!(exclude_only.allows("fastify/-/fastify-4.0.0.tgz"));
    }

    #[test]
    fn overlong_subject_is_refused_without_matching() {
        let f = compiled(&[], &["^never/"]);
        let at_limit = "a".repeat(MAX_SUBJECT_LEN);
        assert!(f.allows(&at_limit));
        assert!(!f.allows(&format!("{at_limit}a")));
        // Without a filter nothing is matched, so no cap applies.
        assert!(check_filter(None, "r", "https://u", &format!("{at_limit}a")).is_ok());
    }

    /// The program ceiling rejects the counted-repetition lists that would make
    /// every match cost hundreds of milliseconds under a larger limit.
    #[test]
    fn expensive_pattern_lists_are_rejected() {
        let costly: Vec<String> = (0..MAX_PATTERNS_PER_LIST)
            .map(|i| format!("a{{300}}{i}"))
            .collect();
        let err = UpstreamFilter {
            include_patterns: costly,
            exclude_patterns: vec![],
        }
        .compile()
        .unwrap_err();
        assert!(err.starts_with("include_patterns"), "{err}");
        // A realistic 64-entry prefix list stays well inside the limit.
        let realistic: Vec<String> = (0..MAX_PATTERNS_PER_LIST)
            .map(|i| format!("^com/group{i}/[a-z0-9._-]+/"))
            .collect();
        assert!(UpstreamFilter {
            include_patterns: realistic,
            exclude_patterns: vec![],
        }
        .compile()
        .is_ok());
    }

    #[tokio::test]
    async fn invalidation_bumps_the_generation() {
        let before = FILTER_GENERATION.load(Ordering::SeqCst);
        invalidate_cached_filter(Uuid::new_v4()).await;
        assert!(FILTER_GENERATION.load(Ordering::SeqCst) > before);
    }

    #[test]
    fn deny_all_refuses_everything() {
        assert!(!CompiledUpstreamFilter::deny_all().allows("anything"));
    }

    #[test]
    fn invalid_regex_is_rejected_with_its_position() {
        let err = filter(&["^ok/"], &["(unclosed"]).compile().unwrap_err();
        assert!(
            err.starts_with("exclude_patterns[0]: invalid regex"),
            "{err}"
        );
        let err = filter(&["ok", "[z-a]"], &[]).compile().unwrap_err();
        assert!(err.starts_with("include_patterns[1]"), "{err}");
    }

    #[test]
    fn empty_and_oversized_patterns_are_rejected() {
        let err = filter(&[""], &[]).compile().unwrap_err();
        assert!(err.contains("must not be empty"), "{err}");
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        let err = filter(&[long.as_str()], &[]).compile().unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
        let many: Vec<String> = (0..=MAX_PATTERNS_PER_LIST)
            .map(|i| format!("p{i}"))
            .collect();
        let err = UpstreamFilter {
            include_patterns: vec![],
            exclude_patterns: many,
        }
        .compile()
        .unwrap_err();
        assert!(err.contains("at most"), "{err}");
    }

    #[test]
    fn pathological_size_pattern_is_rejected() {
        // Short to type, enormous to compile: must trip the size limit rather
        // than allocate an automaton of hundreds of megabytes.
        let err = filter(&[r"(\w{1000}){1000}"], &[]).compile().unwrap_err();
        assert!(err.starts_with("include_patterns[0]"), "{err}");
        let nested = format!("{}a{}", "(".repeat(200), ")".repeat(200));
        assert!(filter(&[], &[nested.as_str()]).compile().is_err());
    }

    #[test]
    fn subject_is_upstream_relative() {
        let base = "https://repo.example.com/maven2/";
        assert_eq!(filter_subject(base, "com/a/b.jar"), "com/a/b.jar");
        assert_eq!(filter_subject(base, "/com/a/b.jar"), "com/a/b.jar");
        assert_eq!(
            filter_subject(base, "https://repo.example.com/maven2/com/a/b.jar"),
            "com/a/b.jar"
        );
        // Absolute URL elsewhere: matched as the full URL.
        assert_eq!(
            filter_subject(base, "https://files.example.org/p/x.whl"),
            "https://files.example.org/p/x.whl"
        );
        // A sibling path that merely shares a prefix is not "under" the base.
        assert_eq!(
            filter_subject(base, "https://repo.example.com/maven2-other/x"),
            "https://repo.example.com/maven2-other/x"
        );
    }

    #[test]
    fn check_filter_maps_refusal_to_not_found() {
        let f = compiled(&["^com/fringe/"], &[]);
        assert!(check_filter(None, "r", "https://u", "anything").is_ok());
        assert!(check_filter(Some(&f), "r", "https://u", "com/fringe/a.jar").is_ok());
        match check_filter(
            Some(&f),
            "fringe-remote",
            "https://u",
            "/org/x/maven-metadata.xml",
        ) {
            Err(AppError::NotFound(msg)) => {
                assert!(!msg.contains("org/x"), "subject must not be echoed: {msg}");
                assert!(msg.contains("fringe-remote"), "{msg}");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn stored_value_that_does_not_parse_or_compile_fails_closed() {
        let id = Uuid::new_v4();
        assert!(!compile_stored(id, "not json").allows("x"));
        assert!(!compile_stored(id, r#"{"include_patterns":["("]}"#).allows("x"));
        let ok = compile_stored(id, r#"{"exclude_patterns":["^bad/"]}"#);
        assert!(ok.allows("good/x") && !ok.allows("bad/x"));
    }

    #[test]
    fn classify_stored_distinguishes_absent_valid_and_unusable() {
        assert_eq!(classify_stored(None), StoredUpstreamFilter::None);
        assert_eq!(
            classify_stored(Some(r#"{"include_patterns":["^a/"]}"#)),
            StoredUpstreamFilter::Valid(filter(&["^a/"], &[]))
        );
        for raw in ["not json", r#"{"exclude_patterns":["("]}"#] {
            match classify_stored(Some(raw)) {
                StoredUpstreamFilter::Unusable(msg) => assert!(!msg.is_empty()),
                other => panic!("{raw}: expected Unusable, got {other:?}"),
            }
        }
    }

    #[test]
    fn serde_defaults_missing_lists_to_empty() {
        let f: UpstreamFilter = serde_json::from_str(r#"{"include_patterns":["^a/"]}"#).unwrap();
        assert_eq!(f, filter(&["^a/"], &[]));
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["exclude_patterns"], serde_json::json!([]));
    }

    /// DB-backed: save / load / cache invalidation / delete round trip.
    #[tokio::test]
    async fn save_load_enforce_delete_round_trip_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, dir) = tdh::create_repo(&pool, "remote", "maven").await;
        let base = "https://upstream.example";

        assert_eq!(
            load_upstream_filter(&pool, repo_id).await.unwrap(),
            StoredUpstreamFilter::None
        );
        ensure_upstream_allowed(&pool, repo_id, &repo_key, base, "org/x.pom")
            .await
            .expect("no filter allows");

        let f = filter(&["^com/fringe/"], &[]);
        save_upstream_filter(&pool, repo_id, &f).await.unwrap();
        assert_eq!(
            load_upstream_filter(&pool, repo_id).await.unwrap(),
            StoredUpstreamFilter::Valid(f)
        );
        // The save invalidated the cached "no filter" verdict.
        assert!(matches!(
            ensure_upstream_allowed(&pool, repo_id, &repo_key, base, "org/x.pom").await,
            Err(AppError::NotFound(_))
        ));
        ensure_upstream_allowed(&pool, repo_id, &repo_key, base, "com/fringe/x.pom")
            .await
            .expect("included path allowed");

        // Invalid filters never reach the table.
        let bad = filter(&["("], &[]);
        assert!(matches!(
            save_upstream_filter(&pool, repo_id, &bad).await,
            Err(AppError::Validation(_))
        ));

        // Saving an empty filter removes it, like DELETE.
        save_upstream_filter(&pool, repo_id, &UpstreamFilter::default())
            .await
            .unwrap();
        assert_eq!(
            load_upstream_filter(&pool, repo_id).await.unwrap(),
            StoredUpstreamFilter::None
        );
        ensure_upstream_allowed(&pool, repo_id, &repo_key, base, "org/x.pom")
            .await
            .expect("filter removed");

        save_upstream_filter(&pool, repo_id, &filter(&[], &["^org/"]))
            .await
            .unwrap();
        delete_upstream_filter(&pool, repo_id).await.unwrap();
        delete_upstream_filter(&pool, repo_id).await.unwrap();
        assert_eq!(
            load_upstream_filter(&pool, repo_id).await.unwrap(),
            StoredUpstreamFilter::None
        );

        tdh::cleanup_member_repo(&pool, repo_id, &dir).await;
    }
}
