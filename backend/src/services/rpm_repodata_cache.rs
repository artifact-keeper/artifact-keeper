//! Revision-validated cache for rendered RPM repodata (#2521, PF-004).
//!
//! Every hosted/virtual RPM repodata request used to fetch **every** live
//! `.rpm` row (plus its metadata JSON) and rebuild the full document set in
//! the request path: `repomd.xml` alone generated primary, filelists, other
//! and updateinfo XML, gzipped all four and hashed all eight variants — then
//! threw everything but the manifest away. A single `dnf makecache` issues
//! `repomd.xml` + `primary.xml.gz` + `filelists.xml.gz` + `other.xml.gz`
//! (and `repomd.xml.asc` when `repo_gpgcheck=1`), so one client refresh cost
//! O(repo) work five times over, and N concurrent CI jobs multiplied it.
//!
//! This cache stores the *complete rendered set* for a repository, keyed by a
//! [`RepodataFingerprint`] of the repository state the render was built from.
//! A request now:
//!
//! 1. computes the fingerprint with one cheap aggregate query
//!    (`COUNT(*)` + `MAX(updated_at)` over the repo's live `.rpm` rows —
//!    no row transfer, no metadata join);
//! 2. serves the cached bytes when the fingerprint matches (warm path:
//!    zero full-catalog queries, zero XML/gzip/hash work);
//! 3. otherwise renders once under a per-repository single-flight lock, so
//!    100 concurrent cold refreshes of the same state cause one render, and
//!    stores the set under the new fingerprint.
//!
//! Correctness / staleness model: the fingerprint is revalidated against the
//! database on **every** request, so a change is visible on the very next
//! read (no TTL window, and read-your-writes holds per replica even in
//! multi-replica deployments — each replica revalidates independently).
//! Publish adds a live row (count and max both move), delete removes one
//! (count moves), promotion inserts into the target repo (count moves), and
//! there is no un-delete path in the artifact service. The fingerprint is
//! captured *before* the rows are fetched, so a write racing a render can
//! only make the stored entry look older than it is — the next request
//! observes a fingerprint mismatch and re-renders. Over-invalidation is
//! possible; serving stale bytes as fresh is not.
//!
//! Determinism (#2636 contract): a cached set is by construction a pure
//! function of repository state, and `repomd.xml.asc` signs the *same cached
//! bytes* `repomd.xml` serves. Sibling documents (`primary.xml.gz`, …) come
//! from the same render as the `repomd.xml` that advertises their checksums,
//! so a client that fetches the set against unchanged state always sees
//! coherent checksums.
//!
//! Bounds: entry count and total byte budget are both capped; eviction is
//! oldest-render-first. One entry per repository, so the worst case is
//! `min(MAX_ENTRIES, active RPM repos)` rendered sets. Follow-ups tracked on
//! #2521: a durable cross-replica object store for prebuilt revisions and the
//! same treatment for the PyPI/Helm/Composer root indexes.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Soft cap on cached repositories. Each repository holds exactly one entry
/// (its current revision), so this bounds the number of distinct RPM repos
/// kept warm per process.
pub const RPM_REPODATA_CACHE_MAX_ENTRIES: usize = 32;

/// Total byte budget across all cached entries. Large repositories produce
/// multi-MiB compressed indexes; the budget keeps the worst case bounded
/// regardless of entry count. Oldest entries are evicted first when the
/// budget is exceeded (the newest entry is always retained, so a single
/// over-budget repository still gets warm-request behaviour).
pub const RPM_REPODATA_CACHE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Identity of the repository state a rendered set was built from.
///
/// * `repo_ids` — the sorted set of repositories the render covers (one id
///   for hosted repos, the member ids for virtual repos), so a virtual
///   membership change rotates the fingerprint even when counts collide.
/// * `live_rpm_count` — live `.rpm` rows across `repo_ids`; moves on upload,
///   delete and promotion.
/// * `latest_update` — `MAX(updated_at)` over those rows; moves on upload
///   and on any row-touching mutation. `None` for an empty repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepodataFingerprint {
    pub repo_ids: Vec<Uuid>,
    pub live_rpm_count: i64,
    pub latest_update: Option<DateTime<Utc>>,
}

/// One immutable rendered repodata set: the manifest plus the compressed
/// index documents its checksums describe. `Bytes` so a warm hit clones a
/// refcount, not the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedRepodata {
    pub repomd_xml: Bytes,
    pub primary_gz: Bytes,
    pub filelists_gz: Bytes,
    pub other_gz: Bytes,
}

impl RenderedRepodata {
    fn total_bytes(&self) -> usize {
        self.repomd_xml.len()
            + self.primary_gz.len()
            + self.filelists_gz.len()
            + self.other_gz.len()
    }
}

struct CacheEntry {
    fingerprint: RepodataFingerprint,
    rendered: Arc<RenderedRepodata>,
    rendered_at: Instant,
}

/// Fingerprint-validated, single-flight cache of rendered RPM repodata sets,
/// keyed by the serving repository's id.
pub struct RpmRepodataCache {
    entries: RwLock<HashMap<Uuid, CacheEntry>>,
    /// Per-repository render locks: concurrent misses for one repo coalesce
    /// behind a single render instead of each paying the O(repo) build.
    /// Guarded by a std `Mutex` (never held across an await).
    render_locks: std::sync::Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
    /// Number of full renders performed. Observability + the test hook that
    /// proves warm requests do not rebuild.
    renders: AtomicU64,
    max_entries: usize,
    max_bytes: usize,
}

impl Default for RpmRepodataCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RpmRepodataCache {
    pub fn new() -> Self {
        Self::with_limits(RPM_REPODATA_CACHE_MAX_ENTRIES, RPM_REPODATA_CACHE_MAX_BYTES)
    }

    pub fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            render_locks: std::sync::Mutex::new(HashMap::new()),
            renders: AtomicU64::new(0),
            max_entries: max_entries.max(1),
            max_bytes,
        }
    }

    /// Total full renders performed since startup.
    pub fn renders(&self) -> u64 {
        self.renders.load(Ordering::Relaxed)
    }

    /// The cached set for `repo_id`, but only when it was rendered from
    /// exactly the state `fingerprint` describes.
    pub async fn lookup(
        &self,
        repo_id: Uuid,
        fingerprint: &RepodataFingerprint,
    ) -> Option<Arc<RenderedRepodata>> {
        let entries = self.entries.read().await;
        let entry = entries.get(&repo_id)?;
        if entry.fingerprint == *fingerprint {
            Some(entry.rendered.clone())
        } else {
            None
        }
    }

    /// Serve the set for `(repo_id, fingerprint)`, rendering at most once per
    /// state change: a fingerprint hit returns the cached bytes; concurrent
    /// misses for one repository coalesce behind a per-repo lock, and every
    /// waiter re-checks the cache before rendering so exactly one of them
    /// pays the O(repo) build.
    ///
    /// A render failure is returned to the caller and caches nothing, so the
    /// next request retries.
    pub async fn get_or_render<E, F, Fut>(
        &self,
        repo_id: Uuid,
        fingerprint: RepodataFingerprint,
        render: F,
    ) -> Result<Arc<RenderedRepodata>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<RenderedRepodata, E>>,
    {
        if let Some(hit) = self.lookup(repo_id, &fingerprint).await {
            return Ok(hit);
        }
        let lock = self.render_lock(repo_id);
        let _guard = lock.lock().await;
        // Re-check: the leader that held the lock may have rendered exactly
        // this state while we waited.
        if let Some(hit) = self.lookup(repo_id, &fingerprint).await {
            return Ok(hit);
        }
        let rendered = Arc::new(render().await?);
        self.renders.fetch_add(1, Ordering::Relaxed);
        self.insert(repo_id, fingerprint, rendered.clone()).await;
        Ok(rendered)
    }

    /// The per-repository render lock, creating it on first use and sweeping
    /// locks no longer held by anyone so the map stays bounded by the number
    /// of concurrently-rendering repositories.
    fn render_lock(&self, repo_id: Uuid) -> Arc<Mutex<()>> {
        let mut locks = self
            .render_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.retain(|id, lock| *id == repo_id || Arc::strong_count(lock) > 1);
        locks.entry(repo_id).or_default().clone()
    }

    async fn insert(
        &self,
        repo_id: Uuid,
        fingerprint: RepodataFingerprint,
        rendered: Arc<RenderedRepodata>,
    ) {
        let mut entries = self.entries.write().await;
        entries.insert(
            repo_id,
            CacheEntry {
                fingerprint,
                rendered,
                rendered_at: Instant::now(),
            },
        );
        // Enforce the entry cap and the byte budget, oldest render first. The
        // just-inserted entry is the newest, so it survives unless it is the
        // only one left — a single over-budget repository still gets cached.
        loop {
            let over_entries = entries.len() > self.max_entries;
            let total: usize = entries.values().map(|e| e.rendered.total_bytes()).sum();
            let over_bytes = total > self.max_bytes && entries.len() > 1;
            if !over_entries && !over_bytes {
                break;
            }
            let Some(oldest) = entries
                .iter()
                .max_by_key(|(_, e)| e.rendered_at.elapsed())
                .map(|(id, _)| *id)
            else {
                break;
            };
            entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn fp(count: i64, secs: i64, repo_ids: Vec<Uuid>) -> RepodataFingerprint {
        RepodataFingerprint {
            repo_ids,
            live_rpm_count: count,
            latest_update: chrono::DateTime::from_timestamp(secs, 0),
        }
    }

    fn rendered(tag: &str) -> RenderedRepodata {
        RenderedRepodata {
            repomd_xml: Bytes::copy_from_slice(format!("repomd-{tag}").as_bytes()),
            primary_gz: Bytes::copy_from_slice(format!("primary-{tag}").as_bytes()),
            filelists_gz: Bytes::copy_from_slice(format!("filelists-{tag}").as_bytes()),
            other_gz: Bytes::copy_from_slice(format!("other-{tag}").as_bytes()),
        }
    }

    #[tokio::test]
    async fn matching_fingerprint_serves_cached_set_without_rerender() {
        let cache = RpmRepodataCache::new();
        let repo = Uuid::new_v4();
        let calls = AtomicUsize::new(0);

        for _ in 0..5 {
            let out = cache
                .get_or_render::<(), _, _>(repo, fp(3, 100, vec![repo]), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(rendered("v1"))
                })
                .await
                .unwrap();
            assert_eq!(out.repomd_xml, Bytes::from_static(b"repomd-v1"));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "five warm requests must cost exactly one render"
        );
        assert_eq!(cache.renders(), 1);
    }

    #[tokio::test]
    async fn changed_fingerprint_rerenders_and_replaces_entry() {
        let cache = RpmRepodataCache::new();
        let repo = Uuid::new_v4();

        cache
            .get_or_render::<(), _, _>(repo, fp(3, 100, vec![repo]), || async {
                Ok(rendered("v1"))
            })
            .await
            .unwrap();
        // One-artifact mutation: count and latest_update both move.
        let out = cache
            .get_or_render::<(), _, _>(repo, fp(4, 200, vec![repo]), || async {
                Ok(rendered("v2"))
            })
            .await
            .unwrap();
        assert_eq!(out.repomd_xml, Bytes::from_static(b"repomd-v2"));
        assert_eq!(
            cache.renders(),
            2,
            "one mutation causes exactly one re-render"
        );

        // The old revision is gone; the new one is served.
        assert!(cache.lookup(repo, &fp(3, 100, vec![repo])).await.is_none());
        assert!(cache.lookup(repo, &fp(4, 200, vec![repo])).await.is_some());
    }

    #[tokio::test]
    async fn virtual_member_set_change_rotates_fingerprint() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // Same counts and timestamps, different member sets: must not match.
        assert_ne!(fp(3, 100, vec![a]), fp(3, 100, vec![a, b]));
        assert_eq!(fp(3, 100, vec![a, b]), fp(3, 100, vec![a, b]));
    }

    #[tokio::test]
    async fn concurrent_cold_requests_coalesce_to_one_render() {
        let cache = Arc::new(RpmRepodataCache::new());
        let repo = Uuid::new_v4();
        let calls = Arc::new(AtomicUsize::new(0));

        let tasks: Vec<_> = (0..50)
            .map(|_| {
                let cache = cache.clone();
                let calls = calls.clone();
                tokio::spawn(async move {
                    cache
                        .get_or_render::<(), _, _>(repo, fp(3, 100, vec![repo]), || async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                            Ok(rendered("v1"))
                        })
                        .await
                        .unwrap()
                })
            })
            .collect();
        for task in tasks {
            let out = task.await.unwrap();
            assert_eq!(out.repomd_xml, Bytes::from_static(b"repomd-v1"));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "50 concurrent cold refreshes of one state must cause exactly one render"
        );
    }

    #[tokio::test]
    async fn render_failure_caches_nothing_and_next_request_retries() {
        let cache = RpmRepodataCache::new();
        let repo = Uuid::new_v4();

        let err = cache
            .get_or_render::<&str, _, _>(repo, fp(3, 100, vec![repo]), || async { Err("db down") })
            .await
            .unwrap_err();
        assert_eq!(err, "db down");
        assert_eq!(cache.renders(), 0);

        // The lock was released and nothing was cached: the retry renders.
        let out = cache
            .get_or_render::<&str, _, _>(repo, fp(3, 100, vec![repo]), || async {
                Ok(rendered("v1"))
            })
            .await
            .unwrap();
        assert_eq!(out.repomd_xml, Bytes::from_static(b"repomd-v1"));
        assert_eq!(cache.renders(), 1);
    }

    #[tokio::test]
    async fn entry_cap_evicts_oldest_repository() {
        let cache = RpmRepodataCache::with_limits(2, usize::MAX);
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let third = Uuid::new_v4();

        for (i, repo) in [first, second, third].into_iter().enumerate() {
            cache
                .get_or_render::<(), _, _>(repo, fp(1, 100, vec![repo]), || async move {
                    Ok(rendered(&format!("v{i}")))
                })
                .await
                .unwrap();
            // Distinct rendered_at ordering even on coarse clocks.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        assert!(
            cache
                .lookup(first, &fp(1, 100, vec![first]))
                .await
                .is_none(),
            "oldest entry must be evicted at the cap"
        );
        assert!(cache
            .lookup(second, &fp(1, 100, vec![second]))
            .await
            .is_some());
        assert!(cache
            .lookup(third, &fp(1, 100, vec![third]))
            .await
            .is_some());
    }

    #[tokio::test]
    async fn byte_budget_evicts_oldest_but_keeps_newest() {
        // Each rendered set from `rendered()` is ~40 bytes; budget of 100
        // holds two sets but not three.
        let cache = RpmRepodataCache::with_limits(usize::MAX, 100);
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let third = Uuid::new_v4();

        for repo in [first, second, third] {
            cache
                .get_or_render::<(), _, _>(repo, fp(1, 100, vec![repo]), || async move {
                    Ok(rendered("vv"))
                })
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        assert!(
            cache
                .lookup(first, &fp(1, 100, vec![first]))
                .await
                .is_none(),
            "oldest entry must be evicted when over the byte budget"
        );
        assert!(
            cache
                .lookup(third, &fp(1, 100, vec![third]))
                .await
                .is_some(),
            "the newest entry must always survive"
        );
    }
}
