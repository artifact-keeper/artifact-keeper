//! Conda as the second consumer of the metadata revision cache (#4174).
//!
//! A hosted subdir's documents (`repodata.json` and its `.zst`/`.bz2`
//! encodings, `current_repodata.json`, `run_exports.json` and the
//! `repodata.json.jlap` recorded for them, [`super::jlap_store`]) are
//! rendered together from one catalog walk and
//! kept under the subdir's revision ([`super::shard_store::subdir_state`]);
//! the CEP-16 shard index is kept the same way from the stored shard map, and
//! `channeldata.json` under the repository's revision. A request reads the
//! revision (one statement against the conda state tables, no catalog rows),
//! serves the kept bytes when it matches, and otherwise renders once under
//! the cache's per-`(repository, scope)` single-flight lock.
//!
//! The revision is the fingerprint, and it already covers quarantine state:
//! the catalog triggers mark a key dirty on every quarantine transition, and
//! the revision moves when the key is rebuilt, which every reader does before
//! it reads the revision. A lapsing hold moves it through
//! `next_hold_expiry`. Each render decides visibility at the database instant
//! the revision was read, so the bytes kept under a revision are the bytes
//! that revision describes.
//!
//! Other replicas learn of a rebuild through the conda invalidation channel
//! ([`crate::services::cache_invalidation::CONDA_REPODATA_INVALIDATION_CHANNEL`])
//! and drop their entries for the subdir; that frees memory early, while the
//! per-request revision check is what keeps every replica correct.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::repo_metadata_revision_cache::{
    CachedRender, Fingerprint, RepoMetadataRevisionCache, RevisionCacheConfig,
};

use super::shard_store;

/// Subdirs kept warm per process.
const SUBDIR_CACHE_MAX_ENTRIES: usize = 64;
/// Byte budget of the subdir cache. A 30,000-record subdir renders about
/// 25 MiB of pretty `repodata.json` plus a few MiB of compressed encodings.
const SUBDIR_CACHE_MAX_BYTES: usize = 512 * 1024 * 1024;
/// Shard indexes and channeldata documents kept per process.
const SMALL_CACHE_MAX_ENTRIES: usize = 256;
const SMALL_CACHE_MAX_BYTES: usize = 128 * 1024 * 1024;

/// The fingerprint of a hosted conda scope: its revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Revision(pub i64);

impl Fingerprint for Revision {}

/// One served document: bytes, their ETag, and a gzip rendering made on the
/// first request that asks for one.
pub(crate) struct Prepared {
    pub body: Bytes,
    pub etag: String,
    gzip: tokio::sync::OnceCell<Bytes>,
}

impl Prepared {
    pub fn new(body: impl Into<Bytes>) -> Self {
        let body: Bytes = body.into();
        let etag = crate::api::handlers::cache_headers::compute_etag(&body);
        Self {
            body,
            etag,
            gzip: tokio::sync::OnceCell::new(),
        }
    }

    fn weight(&self) -> usize {
        self.body.len() + self.gzip.get().map_or(0, Bytes::len)
    }

    /// The gzip rendering, compressed once on the blocking pool. `None` when
    /// the blocking task failed; the caller serves the identity body.
    pub async fn gzip(&self) -> Option<Bytes> {
        let body = self.body.clone();
        self.gzip
            .get_or_try_init(|| async move {
                tokio::task::spawn_blocking(move || Bytes::from(super::gzip_compress(&body))).await
            })
            .await
            .ok()
            .cloned()
    }
}

impl CachedRender for Prepared {
    fn weight_bytes(&self) -> usize {
        self.weight()
    }
}

/// Every document of one hosted subdir at one revision.
pub(crate) struct SubdirDocs {
    /// `repodata.json` as served (pretty-printed); what `.sig` signs and the
    /// JLAP footer hashes. `zst` and `bz2` hold these same bytes.
    pub json: Prepared,
    pub zst: Prepared,
    /// Rendered from `zst` by the first `.bz2` request of the revision and
    /// kept with it (#4882): bzip2 is the slowest encoding by far and the
    /// one modern clients ask for least. Already filled for a subdir no row
    /// has ever named, whose document is tiny (#5167).
    pub bz2: tokio::sync::OnceCell<Prepared>,
    pub current: Prepared,
    pub run_exports: Prepared,
    /// The stored JLAP, whose footer names `json`'s hash (#4175) unless
    /// another render of this revision was recorded first (#5167).
    pub jlap: Prepared,
}

impl CachedRender for SubdirDocs {
    fn weight_bytes(&self) -> usize {
        self.json.weight()
            + self.zst.weight()
            + self.bz2.get().map_or(0, Prepared::weight)
            + self.current.weight()
            + self.run_exports.weight()
            + self.jlap.weight()
    }
}

type SubdirCache = RepoMetadataRevisionCache<Revision, SubdirDocs>;
type DocCache = RepoMetadataRevisionCache<Revision, Prepared>;

fn config(scope_kind: &'static str, max_entries: usize, max_bytes: usize) -> RevisionCacheConfig {
    RevisionCacheConfig {
        format: "conda",
        scope_kind,
        max_entries,
        max_bytes,
        // A hosted document does not depend on the caller.
        max_partitions_per_scope: 1,
        lock_stripes: max_entries,
        incomplete_ttl: Duration::from_secs(60),
    }
}

pub(crate) fn subdir_cache() -> &'static SubdirCache {
    static CACHE: OnceLock<SubdirCache> = OnceLock::new();
    CACHE.get_or_init(|| {
        SubdirCache::with_config(config(
            "subdir",
            SUBDIR_CACHE_MAX_ENTRIES,
            SUBDIR_CACHE_MAX_BYTES,
        ))
    })
}

pub(crate) fn shard_index_cache() -> &'static DocCache {
    static CACHE: OnceLock<DocCache> = OnceLock::new();
    CACHE.get_or_init(|| {
        DocCache::with_config(config(
            "shard_index",
            SMALL_CACHE_MAX_ENTRIES,
            SMALL_CACHE_MAX_BYTES,
        ))
    })
}

pub(crate) fn channel_cache() -> &'static DocCache {
    static CACHE: OnceLock<DocCache> = OnceLock::new();
    CACHE.get_or_init(|| {
        DocCache::with_config(config(
            "channel",
            SMALL_CACHE_MAX_ENTRIES,
            SMALL_CACHE_MAX_BYTES,
        ))
    })
}

/// Default of [`REGEN_CONCURRENCY_ENV`].
const DEFAULT_REGEN_CONCURRENCY: usize = 2;
/// Process-wide bound on concurrent hosted conda renders (#4176).
pub(crate) const REGEN_CONCURRENCY_ENV: &str = "AK_CONDA_REGEN_CONCURRENCY";
/// Default of [`REGEN_WAIT_ENV`], seconds.
const DEFAULT_REGEN_WAIT_SECS: u64 = 30;
/// How long a request waits for a render before it is answered 503 (#4176).
pub(crate) const REGEN_WAIT_ENV: &str = "AK_CONDA_REGEN_WAIT_SECS";
/// `Retry-After` of that 503, seconds: a render of a large subdir takes
/// seconds, so an immediate retry would only queue again.
const REGEN_RETRY_AFTER_SECS: u64 = 5;

/// Parse [`REGEN_CONCURRENCY_ENV`]: a positive integer, else the default.
pub(crate) fn parse_regen_concurrency(raw: Option<&str>) -> usize {
    match raw.map(str::trim) {
        None | Some("") => DEFAULT_REGEN_CONCURRENCY,
        Some(v) => match v.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                tracing::warn!(
                    value = v,
                    default = DEFAULT_REGEN_CONCURRENCY,
                    "{REGEN_CONCURRENCY_ENV} is not a positive integer; using the default"
                );
                DEFAULT_REGEN_CONCURRENCY
            }
        },
    }
}

/// Parse [`REGEN_WAIT_ENV`]: seconds, `0` for no bound, else the default.
pub(crate) fn parse_regen_wait(raw: Option<&str>) -> Option<Duration> {
    match raw.map(str::trim) {
        None | Some("") => Some(Duration::from_secs(DEFAULT_REGEN_WAIT_SECS)),
        Some(v) => match v.parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(Duration::from_secs(n)),
            Err(_) => {
                tracing::warn!(
                    value = v,
                    default = DEFAULT_REGEN_WAIT_SECS,
                    "{REGEN_WAIT_ENV} is not a number of seconds; using the default"
                );
                Some(Duration::from_secs(DEFAULT_REGEN_WAIT_SECS))
            }
        },
    }
}

/// Bounds how many hosted conda renders run at once in this process, so a
/// fleet refreshing many subdirs cannot pin every core on JSON encoding and
/// compression (#4176). Per-subdir single flight comes from the revision
/// cache; this is the cap across subdirs and repositories.
pub(crate) struct RegenGate {
    permits: tokio::sync::Semaphore,
    in_flight: std::sync::atomic::AtomicUsize,
    /// Most renders seen running at once (tests and diagnostics).
    peak: std::sync::atomic::AtomicUsize,
}

impl RegenGate {
    pub(crate) fn new(concurrency: usize) -> Self {
        Self {
            permits: tokio::sync::Semaphore::new(concurrency.max(1)),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            peak: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Run `work` once a permit is free.
    pub(crate) async fn run<T>(&self, work: impl std::future::Future<Output = T>) -> T {
        use std::sync::atomic::Ordering;
        let _permit = self
            .permits
            .acquire()
            .await
            .expect("the regeneration semaphore is never closed");
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        metrics::gauge!("ak_conda_repodata_regenerations_in_flight").increment(1.0);
        struct Done<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                metrics::gauge!("ak_conda_repodata_regenerations_in_flight").decrement(1.0);
            }
        }
        let _done = Done(&self.in_flight);
        work.await
    }

    #[cfg(test)]
    pub(crate) fn peak(&self) -> usize {
        self.peak.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The process's [`RegenGate`], sized by [`REGEN_CONCURRENCY_ENV`].
pub(crate) fn regen_gate() -> &'static RegenGate {
    static GATE: OnceLock<RegenGate> = OnceLock::new();
    GATE.get_or_init(|| {
        RegenGate::new(parse_regen_concurrency(
            std::env::var(REGEN_CONCURRENCY_ENV).ok().as_deref(),
        ))
    })
}

pub(crate) fn regen_wait() -> Option<Duration> {
    static WAIT: OnceLock<Option<Duration>> = OnceLock::new();
    *WAIT.get_or_init(|| parse_regen_wait(std::env::var(REGEN_WAIT_ENV).ok().as_deref()))
}

/// The 503 a request gets when its document is not ready within the wait.
fn regen_busy() -> Response {
    metrics::counter!("ak_conda_repodata_requests_shed_total").increment(1);
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        "Conda channel metadata is being regenerated; retry shortly",
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(REGEN_RETRY_AFTER_SECS),
    );
    response
}

/// Wait at most `wait` for `work`, which runs as its own task: a request
/// that gives up (503 with `Retry-After`) leaves the rebuild or render
/// running, and its result is kept for the requests that follow.
pub(crate) async fn bounded_by<T: Send + 'static>(
    wait: Option<Duration>,
    work: impl std::future::Future<Output = Result<T, Response>> + Send + 'static,
) -> Result<T, Response> {
    let task = tokio::spawn(work);
    let joined = match wait {
        Some(wait) => match tokio::time::timeout(wait, task).await {
            Ok(joined) => joined,
            Err(_) => return Err(regen_busy()),
        },
        None => task.await,
    };
    joined.map_err(render_failed)?
}

async fn bounded<T: Send + 'static>(
    work: impl std::future::Future<Output = Result<T, Response>> + Send + 'static,
) -> Result<T, Response> {
    bounded_by(regen_wait(), work).await
}

/// Scope of a repository's `channeldata.json` entry.
const CHANNEL_SCOPE: &str = "";

/// Drop this process's entries for `subdirs` of `repo_id` (and its
/// channel-wide document). Called by the rebuild that moved them and by the
/// invalidation listener for rebuilds on other replicas.
/// An empty `subdirs` drops every entry of the repository.
pub(crate) async fn invalidate_local(repo_id: Uuid, subdirs: &[String]) {
    if subdirs.is_empty() {
        subdir_cache().invalidate_repo(repo_id).await;
        shard_index_cache().invalidate_repo(repo_id).await;
        channel_cache().invalidate_repo(repo_id).await;
        return;
    }
    for subdir in subdirs {
        subdir_cache().invalidate_scope(repo_id, subdir).await;
        shard_index_cache().invalidate_scope(repo_id, subdir).await;
    }
    channel_cache()
        .invalidate_scope(repo_id, CHANNEL_SCOPE)
        .await;
}

fn render_failed(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "conda repodata render failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
}

/// The documents of hosted `(repo_id, subdir)` at its current revision.
pub(crate) async fn hosted_subdir_docs(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
) -> Result<Arc<SubdirDocs>, Response> {
    super::validate_read_subdir(subdir)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid subdir: {}", e)).into_response())?;
    let db = db.clone();
    let subdir = subdir.to_string();
    bounded(async move {
        let state = shard_store::subdir_state(&db, repo_id, &subdir).await?;
        if state.backfilled && state.revision == 0 {
            // No row has ever named this subdir (every write and the
            // backfill give a named subdir a revision): its documents are
            // empty, so they cost no catalog walk, no permit and no cache
            // entry. Requests for made-up subdirs cannot evict real ones.
            return empty_subdir_docs(&subdir).map(Arc::new);
        }
        subdir_cache()
            .get_or_render_scoped(repo_id, &subdir, Revision(state.revision), || {
                regen_gate().run(render_subdir_docs(
                    db.clone(),
                    repo_id,
                    subdir.clone(),
                    state.revision,
                    state.now,
                ))
            })
            .await
    })
    .await
}

/// The documents of a subdir no row has ever named.
fn empty_subdir_docs(subdir: &str) -> Result<SubdirDocs, Response> {
    let rendered = super::repodata_render::render_empty(subdir)?;
    let jlap = super::build_bootstrap_jlap(&rendered.json);
    let bz2 = super::RepodataEncoding::Bz2.transcode_zst(&rendered.zst)?;
    Ok(SubdirDocs {
        json: Prepared::new(rendered.json),
        zst: Prepared::new(rendered.zst),
        bz2: tokio::sync::OnceCell::new_with(Some(Prepared::new(bz2))),
        current: Prepared::new(rendered.current),
        run_exports: Prepared::new(rendered.run_exports),
        jlap: Prepared::new(jlap),
    })
}

/// `docs` with its `.bz2` rendering made (#4882): rendered from the kept
/// zstd document by the first request that asks, under the regeneration
/// gate and wait, then kept for the revision's lifetime. Single-stream
/// bzip2 at level 9, the bytes 1.11 served.
pub(crate) async fn with_bz2(docs: Arc<SubdirDocs>) -> Result<Arc<SubdirDocs>, Response> {
    if docs.bz2.initialized() {
        return Ok(docs);
    }
    bounded(async move {
        docs.bz2
            .get_or_try_init(|| {
                regen_gate().run(async {
                    let zst = docs.zst.body.clone();
                    let body = tokio::task::spawn_blocking(move || {
                        super::RepodataEncoding::Bz2.transcode_zst(&zst)
                    })
                    .await
                    .map_err(render_failed)??;
                    Ok::<_, Response>(Prepared::new(body))
                })
            })
            .await?;
        Ok(docs)
    })
    .await
}

/// Render every document of a hosted subdir with one cursor walk of the
/// catalog ([`super::repodata_render`]), deciding visibility at `now`, and
/// record the new `repodata.json` in the subdir's stored JLAP before any of
/// them is kept or served ([`super::jlap_store::record`]), so the JLAP served
/// with a revision's `repodata.json` ends at that document, or at the render
/// of the revision recorded before it.
async fn render_subdir_docs(
    db: PgPool,
    repo_id: Uuid,
    subdir: String,
    revision: i64,
    now: DateTime<Utc>,
) -> Result<SubdirDocs, Response> {
    let removed = super::list_removed_artifacts_at(&db, repo_id, &subdir, now).await?;
    let rendered =
        super::repodata_render::render_subdir(&db, repo_id, &subdir, now, &removed).await?;
    let json = Bytes::from(rendered.json);
    let zst = Bytes::from(rendered.zst);
    let jlap = match super::jlap_store::record(&db, repo_id, &subdir, revision, &json, &zst).await {
        Ok(jlap) => jlap,
        Err(e) => {
            // Repodata is still served; a JLAP with no patches makes a
            // client download the whole document, which is correct.
            tracing::warn!(
                repo = %repo_id, subdir = %subdir, error = %e,
                "conda JLAP: could not record the revision; serving a JLAP without patches"
            );
            super::build_bootstrap_jlap(&json)
        }
    };
    Ok(SubdirDocs {
        json: Prepared::new(json),
        zst: Prepared::new(zst),
        bz2: tokio::sync::OnceCell::new(),
        current: Prepared::new(rendered.current),
        run_exports: Prepared::new(rendered.run_exports),
        jlap: Prepared::new(jlap),
    })
}

/// The CEP-16 shard index of hosted `(repo_id, subdir)`, serialised from the
/// stored shard map, or `None` while the repository's backfill has not
/// finished (the caller keeps the per-request walk).
pub(crate) async fn hosted_shard_index(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
) -> Result<Option<Arc<Prepared>>, Response> {
    let db = db.clone();
    let subdir = subdir.to_string();
    bounded(async move {
        let state = shard_store::subdir_state(&db, repo_id, &subdir).await?;
        if !state.backfilled {
            return Ok(None);
        }
        shard_index_cache()
            .get_or_render_scoped(repo_id, &subdir, Revision(state.revision), || async {
                let shards = shard_store::stored_index(&db, repo_id, &subdir).await?;
                let body =
                    super::serialize_msgpack_zst(&super::build_sharded_index(&subdir, &shards))?;
                Ok::<_, Response>(Prepared::new(body))
            })
            .await
            .map(Some)
    })
    .await
}

/// The stored shard at `address` of hosted `(repo_id, subdir)`. `Ok(None)`
/// while the backfill has not finished; `Ok(Some(None))` when no shard of the
/// subdir has that address.
pub(crate) async fn hosted_shard(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
    address: &[u8],
) -> Result<Option<Option<Vec<u8>>>, Response> {
    let state = shard_store::subdir_state(db, repo_id, subdir).await?;
    if !state.backfilled {
        return Ok(None);
    }
    shard_store::stored_shard(db, repo_id, subdir, address)
        .await
        .map(Some)
}

/// `channeldata.json` of hosted `repo_id` at its current revision.
pub(crate) async fn hosted_channeldata(
    db: &PgPool,
    repo_id: Uuid,
) -> Result<Arc<Prepared>, Response> {
    let db = db.clone();
    bounded(async move {
        let state = shard_store::repo_state(&db, repo_id).await?;
        channel_cache()
            .get_or_render_scoped(repo_id, CHANNEL_SCOPE, Revision(state.revision), || {
                regen_gate().run(async {
                    let body = super::render_hosted_channeldata(&db, repo_id, state.now).await?;
                    Ok::<_, Response>(Prepared::new(body))
                })
            })
            .await
    })
    .await
}
