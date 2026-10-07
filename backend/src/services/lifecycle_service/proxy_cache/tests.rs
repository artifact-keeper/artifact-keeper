//! #3734: lifecycle retention for Remote repositories' proxy cache.
//!
//! The DB-backed tests run against a real filesystem proxy-cache store: every
//! seeded entry has its `__content__` body and `__cache_meta__.json` sidecar on
//! disk, so each test proves which objects a run deleted and which it left.

use std::path::Path;

use serde_json::json;

use super::*;
use crate::api::handlers::test_db_helpers as tdh;
use crate::services::proxy_cache_scope::ProxyCacheScope;
use crate::services::proxy_service::CacheKeys;
use crate::services::storage_service::{FilesystemBackend, StorageService};
use tokio_util::sync::CancellationToken;

// ── pure decision table ───────────────────────────────────────────────────

fn arm(policy_type: &str, config: serde_json::Value) -> ProxyCacheArm {
    proxy_cache_arm(policy_type, &config).expect("valid config")
}

fn applies(clock: ProxyCacheClock, days: i32, prefix: Option<&str>) -> ProxyCacheArm {
    ProxyCacheArm::Applies(ProxyCacheRule {
        clock,
        days,
        path_prefix: prefix.map(str::to_string),
    })
}

#[test]
fn proxy_cache_arm_maps_age_and_idle_policies_3734() {
    assert_eq!(
        arm("max_age_days", json!({"days": 30})),
        applies(ProxyCacheClock::CachedAt, 30, None)
    );
    assert_eq!(
        arm("max_age_days", json!({"max_age_days": 7})),
        applies(ProxyCacheClock::CachedAt, 7, None),
        "the flat alias reaches the cache arm too"
    );
    assert_eq!(
        arm(
            "no_downloads_days",
            json!({"days": 14, "match": {"path_prefix": "simple/"}})
        ),
        applies(ProxyCacheClock::LastAccess, 14, Some("simple/"))
    );
    assert_eq!(
        arm(
            "no_downloads_days",
            json!({"days": i64::from(i32::MAX) + 1})
        ),
        applies(ProxyCacheClock::LastAccess, i32::MAX, None),
        "an out-of-range window saturates instead of wrapping negative"
    );
}

#[test]
fn proxy_cache_arm_refuses_what_it_cannot_evaluate_3734() {
    for (policy_type, config, needle) in [
        (
            "max_versions",
            json!({"keep": 1}),
            "max_versions has no proxy-cache",
        ),
        (
            "tag_pattern_keep",
            json!({"pattern": "x"}),
            "tag_pattern_keep",
        ),
        (
            "tag_pattern_delete",
            json!({"pattern": "x"}),
            "tag_pattern_delete",
        ),
        (
            "size_quota_bytes",
            json!({"quota_bytes": 1}),
            "size_quota_bytes",
        ),
        (
            "no_downloads_days",
            json!({"days": 1, "exclude": {"versions": ["latest"]}}),
            "exclude",
        ),
        (
            "max_age_days",
            json!({"days": 1, "exclude": {"version_patterns": ["^v"]}}),
            "exclude",
        ),
        (
            "max_age_days",
            json!({"days": 1, "min_keep": 3}),
            "min_keep",
        ),
        (
            "max_age_days",
            json!({"days": 1, "match": {"version_pattern": "^1"}}),
            "match.version_pattern",
        ),
        (
            "composite",
            json!({"conditions": [{"type": "max_age_days", "value": 1}]}),
            "composite has no proxy-cache",
        ),
    ] {
        match arm(policy_type, config) {
            ProxyCacheArm::Unsupported(reason) => {
                assert!(reason.contains(needle), "{policy_type}: {reason}")
            }
            other => panic!("{policy_type} must not reach the cache: {other:?}"),
        }
    }
    assert!(proxy_cache_arm("bogus", &json!({})).is_err());
    assert!(proxy_cache_arm("max_age_days", &json!({})).is_err());
}

#[test]
fn only_oci_remotes_keep_artifact_rows_3734() {
    for format in [
        RepositoryFormat::Docker,
        RepositoryFormat::Podman,
        RepositoryFormat::HelmOci,
        RepositoryFormat::WasmOci,
    ] {
        assert!(remote_keeps_artifact_rows(&format), "{format:?}");
    }
    for format in [
        RepositoryFormat::Pypi,
        RepositoryFormat::Npm,
        RepositoryFormat::Maven,
        RepositoryFormat::Helm,
    ] {
        assert!(!remote_keeps_artifact_rows(&format), "{format:?}");
    }
}

#[test]
fn preview_and_sweep_share_one_predicate_3734() {
    let predicate = proxy_cache_retention_where!();
    assert!(PROXY_CACHE_COUNT_SQL.ends_with(predicate));
    assert!(PROXY_CACHE_CANDIDATES_SQL.contains(predicate));
    assert!(predicate.contains("starts_with(p.path, $4::TEXT)"));
    for clock in [ProxyCacheClock::CachedAt, ProxyCacheClock::LastAccess] {
        assert!(predicate.contains(&format!("WHEN '{}' THEN", clock.as_bind())));
    }
}

#[test]
fn absorb_sums_repositories_and_keeps_first_skip_reason_3734() {
    let mut total = ProxyCacheExecutionResult::default();
    total.absorb(ProxyCacheExecutionResult {
        entries_matched: 2,
        entries_removed: 1,
        bytes_matched: 20,
        bytes_freed: 10,
        skipped_reason: None,
    });
    total.absorb(ProxyCacheExecutionResult::skipped("first"));
    total.absorb(ProxyCacheExecutionResult {
        entries_matched: 3,
        entries_removed: 3,
        bytes_matched: 30,
        bytes_freed: 30,
        skipped_reason: Some("second".into()),
    });
    assert_eq!(
        total,
        ProxyCacheExecutionResult {
            entries_matched: 5,
            entries_removed: 4,
            bytes_matched: 50,
            bytes_freed: 40,
            skipped_reason: Some("first".into()),
        }
    );
    assert_eq!(
        inert_remote_assignment_message("max_versions", "pypi-remote", "why"),
        "A max_versions policy cannot reclaim anything in Remote repository 'pypi-remote': why"
    );
}

// ── DB + filesystem fixtures ──────────────────────────────────────────────

/// A Remote repository and a proxy service whose cache store is a filesystem
/// backend rooted at the fixture's storage dir.
struct RemoteCache {
    fx: tdh::Fixture,
    scope: ProxyCacheScope,
    proxy: Arc<ProxyService>,
}

impl RemoteCache {
    async fn setup(format: &str, scope: ProxyCacheScope) -> Option<Self> {
        let fx = tdh::Fixture::setup("remote", format).await?;
        let backend = Arc::new(FilesystemBackend::new(fx.storage_dir.clone()));
        let proxy = Arc::new(ProxyService::new(
            fx.pool.clone(),
            Arc::new(StorageService::new(backend)),
            scope.clone(),
        ));
        Some(Self { fx, scope, proxy })
    }

    fn service(&self) -> LifecycleService {
        LifecycleService::new(self.fx.pool.clone()).with_proxy_service(Some(self.proxy.clone()))
    }

    fn on_disk(&self, key: &str) -> bool {
        self.fx.storage_dir.join(key).exists()
    }

    /// Seed one cache entry under this deployment's scope.
    async fn entry(&self, path: &str, cached_days: i32, accessed_days: Option<i32>) -> Entry {
        let keys = CacheKeys::derive(&self.scope, &self.fx.repo_key, path).expect("cache keys");
        self.entry_at(
            path,
            &keys.content,
            &keys.metadata,
            cached_days,
            accessed_days,
        )
        .await
    }

    /// Seed a catalogue row recording explicit keys, writing both objects.
    async fn entry_at(
        &self,
        path: &str,
        content: &str,
        metadata: &str,
        cached_days: i32,
        accessed_days: Option<i32>,
    ) -> Entry {
        write_object(&self.fx.storage_dir, content, b"body");
        write_object(&self.fx.storage_dir, metadata, b"{}");
        let id = sqlx::query_scalar(
            "INSERT INTO proxy_cache_artifacts \
               (repository_id, path, storage_key, metadata_key, size_bytes, checksum_sha256, \
                cached_at, last_accessed_at) \
             VALUES ($1, $2, $3, $4, 100, repeat('b', 64), \
                     NOW() - make_interval(days => $5::INT), \
                     NOW() - make_interval(days => $6::INT)) \
             RETURNING id",
        )
        .bind(self.fx.repo_id)
        .bind(path)
        .bind(content)
        .bind(metadata)
        .bind(cached_days)
        .bind(accessed_days)
        .fetch_one(&self.fx.pool)
        .await
        .expect("seed proxy_cache_artifacts");
        Entry {
            id,
            content: content.to_string(),
            metadata: metadata.to_string(),
        }
    }

    /// An entry whose body delete fails: a non-empty directory sits where the
    /// body file should be, so deleting it as a file is an I/O error, not
    /// NotFound.
    async fn stuck_entry(&self, path: &str) -> Entry {
        let entry = self.entry(path, 90, Some(90)).await;
        let body = self.fx.storage_dir.join(&entry.content);
        std::fs::remove_file(&body).expect("drop body file");
        write_object(&body, "pin", b"x");
        entry
    }

    async fn row_exists(&self, entry: &Entry) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM proxy_cache_artifacts WHERE id = $1)",
        )
        .bind(entry.id)
        .fetch_one(&self.fx.pool)
        .await
        .expect("row lookup")
    }

    /// Row and both objects present (`true`) or all three gone (`false`).
    async fn assert_entry(&self, entry: &Entry, present: bool, label: &str) {
        assert_eq!(
            self.row_exists(entry).await,
            present,
            "{label}: catalogue row"
        );
        assert_eq!(
            self.on_disk(&entry.content),
            present,
            "{label}: __content__"
        );
        assert_eq!(
            self.on_disk(&entry.metadata),
            present,
            "{label}: __cache_meta__"
        );
    }

    async fn policy(&self, policy_type: &str, config: serde_json::Value) -> LifecyclePolicy {
        self.service()
            .create_policy(CreateLifecyclePolicyRequest {
                name: format!("proxy-cache-3734-{}", Uuid::new_v4()),
                policy_type: policy_type.into(),
                config,
                repository_ids: Some(vec![self.fx.repo_id]),
                ..Default::default()
            })
            .await
            .expect("create policy")
    }
}

struct Entry {
    id: Uuid,
    content: String,
    metadata: String,
}

fn never() -> CancellationToken {
    CancellationToken::new()
}

fn write_object(root: &Path, key: &str, bytes: &[u8]) {
    let path = root.join(key);
    std::fs::create_dir_all(path.parent().expect("object parent")).expect("mkdir");
    std::fs::write(path, bytes).expect("write object");
}

// ── execution ─────────────────────────────────────────────────────────────

/// The acceptance test of #3734: an idle entry loses its row and both
/// objects, everything accessed, downloaded or cached inside the window keeps
/// all three, and the live run removes exactly what the preview reported.
#[tokio::test]
async fn no_downloads_evicts_idle_cache_entries_and_keeps_fresh_ones_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let idle = cache.entry("simple/idle/idle-1.whl", 90, Some(45)).await;
    let never_served = cache.entry("simple/old/old-1.whl", 60, None).await;
    let served = cache.entry("simple/hot/hot-1.whl", 90, Some(2)).await;
    let downloaded = cache.entry("simple/dl/dl-1.whl", 90, Some(45)).await;
    sqlx::query(
        "INSERT INTO proxy_download_statistics (proxy_cache_id, downloaded_at) \
         VALUES ($1, NOW() - INTERVAL '1 day')",
    )
    .bind(downloaded.id)
    .execute(&cache.fx.pool)
    .await
    .expect("seed download");
    let fresh = cache.entry("simple/new/new-1.whl", 3, None).await;

    let service = cache.service();
    let policy = cache.policy("no_downloads_days", json!({"days": 30})).await;

    let preview = service
        .execute_policy(policy.id, true)
        .await
        .expect("preview");
    assert_eq!(
        preview.artifacts_matched, 0,
        "a Remote repo has no artifacts"
    );
    assert_eq!(
        preview.proxy_cache,
        ProxyCacheExecutionResult {
            entries_matched: 2,
            entries_removed: 0,
            bytes_matched: 200,
            bytes_freed: 0,
            skipped_reason: None,
        }
    );
    for entry in [&idle, &never_served] {
        cache
            .assert_entry(entry, true, "preview deletes nothing")
            .await;
    }

    let run = service.execute_policy(policy.id, false).await.expect("run");
    assert!(run.errors.is_empty(), "{:?}", run.errors);
    assert_eq!(
        (run.proxy_cache.entries_removed, run.proxy_cache.bytes_freed),
        (
            preview.proxy_cache.entries_matched,
            preview.proxy_cache.bytes_matched
        ),
        "the live run evicts exactly what the preview reported"
    );
    cache.assert_entry(&idle, false, "idle").await;
    cache
        .assert_entry(&never_served, false, "never served")
        .await;
    cache.assert_entry(&served, true, "served recently").await;
    cache
        .assert_entry(&downloaded, true, "downloaded recently")
        .await;
    cache.assert_entry(&fresh, true, "cached recently").await;

    let stored = service.get_policy(policy.id).await.expect("policy");
    assert_eq!(stored.last_run_items_removed, Some(2));
    let again = service
        .execute_policy(policy.id, false)
        .await
        .expect("rerun");
    assert_eq!(
        again.proxy_cache.entries_matched, 0,
        "the sweep is idempotent"
    );
}

/// `max_age_days` ages by `cached_at` regardless of access, and
/// `match.path_prefix` scopes it to the catalogue's logical path.
#[tokio::test]
async fn max_age_evicts_by_cached_at_within_path_prefix_3734() {
    let Some(cache) = RemoteCache::setup("npm", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let old_in_scope = cache.entry("packages/a/-/a-1.tgz", 90, Some(1)).await;
    let old_out_of_scope = cache.entry("metadata/a", 90, Some(1)).await;
    let new_in_scope = cache.entry("packages/b/-/b-1.tgz", 2, Some(1)).await;
    let policy = cache
        .policy(
            "max_age_days",
            json!({"days": 30, "match": {"path_prefix": "packages/"}}),
        )
        .await;

    let run = cache
        .service()
        .execute_policy(policy.id, false)
        .await
        .expect("run");
    assert_eq!(run.proxy_cache.entries_matched, 1);
    assert_eq!(run.proxy_cache.entries_removed, 1);
    cache
        .assert_entry(&old_in_scope, false, "old, in scope")
        .await;
    cache
        .assert_entry(&old_out_of_scope, true, "old, out of scope")
        .await;
    cache
        .assert_entry(&new_in_scope, true, "new, in scope")
        .await;
}

/// An entry cached before #3454 records unscoped keys; the sweep reaches
/// them. A row recording keys outside this repository's cache keeps its row
/// and is reported, and the foreign objects it points at are not touched.
#[tokio::test]
async fn eviction_reaches_legacy_keys_and_keeps_foreign_ones_3734() {
    let scope = ProxyCacheScope::from_deployment_id(Uuid::new_v4());
    let Some(cache) = RemoteCache::setup("pypi", scope).await else {
        return;
    };
    let legacy_keys = CacheKeys::derive(
        &ProxyCacheScope::unscoped(),
        &cache.fx.repo_key,
        "simple/legacy",
    )
    .expect("legacy keys");
    let legacy = cache
        .entry_at(
            "simple/legacy",
            &legacy_keys.content,
            &legacy_keys.metadata,
            90,
            Some(90),
        )
        .await;
    let foreign = cache
        .entry_at(
            "simple/foreign",
            "repos/victim/victim-1.whl",
            "proxy-cache/another-repo/simple/x/__cache_meta__.json",
            90,
            Some(90),
        )
        .await;
    let policy = cache.policy("no_downloads_days", json!({"days": 30})).await;

    let run = cache
        .service()
        .execute_policy(policy.id, false)
        .await
        .expect("run");
    assert_eq!(run.proxy_cache.entries_removed, 1, "{:?}", run.errors);
    cache
        .assert_entry(&legacy, false, "legacy unscoped entry")
        .await;
    cache
        .assert_entry(&foreign, true, "corrupt row and the objects it names")
        .await;
    assert_eq!(run.errors.len(), 1, "{:?}", run.errors);
    assert!(run.errors[0].contains("simple/foreign"), "{:?}", run.errors);
}

/// A repository renamed after its entries were cached: the objects still sit
/// under the old key's root. The sweep must not forget them by dropping the
/// row (the only record of those objects); it keeps and reports the entry.
#[tokio::test]
async fn renamed_repository_entries_are_kept_and_reported_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let entry = cache.entry("simple/a/a-1.whl", 90, Some(90)).await;
    let renamed = format!("{}-renamed", cache.fx.repo_key);
    sqlx::query("UPDATE repositories SET key = $2 WHERE id = $1")
        .bind(cache.fx.repo_id)
        .bind(&renamed)
        .execute(&cache.fx.pool)
        .await
        .expect("rename repository");
    let policy = cache.policy("max_age_days", json!({"days": 30})).await;

    let run = cache
        .service()
        .execute_policy(policy.id, false)
        .await
        .expect("run");
    assert_eq!(run.proxy_cache.entries_matched, 1);
    assert_eq!(run.proxy_cache.entries_removed, 0);
    assert_eq!(run.errors.len(), 1, "{:?}", run.errors);
    assert!(
        run.errors[0].contains("renamed repository"),
        "{:?}",
        run.errors
    );
    cache
        .assert_entry(&entry, true, "entry under the old key")
        .await;
}

/// A storage delete that fails keeps the catalogue row, so the entry is
/// retried by the next run instead of becoming an object nothing reclaims.
#[tokio::test]
async fn storage_failure_keeps_the_catalogue_row_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let stuck = cache.stuck_entry("simple/stuck/stuck-1.whl").await;
    let ok = cache.entry("simple/ok/ok-1.whl", 90, Some(90)).await;
    let policy = cache.policy("max_age_days", json!({"days": 30})).await;

    let run = cache
        .service()
        .execute_policy(policy.id, false)
        .await
        .expect("a per-entry failure does not fail the run");
    assert_eq!(run.proxy_cache.entries_matched, 2);
    assert_eq!(run.proxy_cache.entries_removed, 1);
    assert_eq!(run.errors.len(), 1, "{:?}", run.errors);
    assert!(run.errors[0].contains("simple/stuck/stuck-1.whl"));
    assert!(cache.row_exists(&stuck).await, "failed entry keeps its row");
    assert!(
        cache.on_disk(&stuck.metadata),
        "bodies go before sidecars: a failed body delete leaves the sidecar"
    );
    cache.assert_entry(&ok, false, "healthy entry").await;
}

/// Without a proxy cache store a live run still reports candidates but
/// evicts nothing, and says why.
#[tokio::test]
async fn live_run_without_proxy_store_evicts_nothing_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let entry = cache.entry("simple/a/a-1.whl", 90, Some(90)).await;
    let policy = cache.policy("max_age_days", json!({"days": 30})).await;

    let service = LifecycleService::new(cache.fx.pool.clone());
    for dry_run in [true, false] {
        let run = service
            .execute_policy(policy.id, dry_run)
            .await
            .expect("run");
        assert_eq!(run.proxy_cache.entries_matched, 1);
        assert_eq!(run.proxy_cache.entries_removed, 0);
        assert!(
            run.proxy_cache
                .skipped_reason
                .as_deref()
                .is_some_and(|r| r.contains("no proxy cache store")),
            "dry_run={dry_run}: the preview must not promise an eviction"
        );
    }
    cache.assert_entry(&entry, true, "nothing evicted").await;
}

// ── assignment validation ─────────────────────────────────────────────────

fn create(
    policy_type: &str,
    config: serde_json::Value,
    ids: Vec<Uuid>,
) -> CreateLifecyclePolicyRequest {
    CreateLifecyclePolicyRequest {
        name: format!("inert-3734-{}", Uuid::new_v4()),
        policy_type: policy_type.into(),
        config,
        repository_ids: Some(ids),
        ..Default::default()
    }
}

fn assert_inert(result: Result<LifecyclePolicy>, label: &str) {
    match result {
        Err(AppError::UnprocessableEntity(message)) => {
            assert!(
                message.contains("cannot reclaim anything"),
                "{label}: {message}"
            )
        }
        other => panic!("{label}: expected 422, got {other:?}"),
    }
}

/// A policy that would match nothing in a (non-OCI) Remote repository is
/// refused at create, attach and config update, instead of being accepted and
/// silently doing nothing.
#[tokio::test]
async fn inert_policy_on_remote_repository_is_refused_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let service = cache.service();
    let remote = cache.fx.repo_id;

    assert_inert(
        service
            .create_policy(create("max_versions", json!({"keep": 1}), vec![remote]))
            .await,
        "max_versions on a pypi remote",
    );
    assert_inert(
        service
            .create_policy(create(
                "no_downloads_days",
                json!({"days": 1, "exclude": {"versions": ["latest"]}}),
                vec![remote],
            ))
            .await,
        "an exclude list on a pypi remote",
    );

    let idle = service
        .create_policy(create(
            "no_downloads_days",
            json!({"days": 1}),
            vec![remote],
        ))
        .await
        .expect("no_downloads_days reaches the cache");
    assert_inert(
        service
            .update_policy(
                idle.id,
                UpdateLifecyclePolicyRequest {
                    config: Some(json!({"days": 1, "exclude": {"versions": ["x"]}})),
                    ..Default::default()
                },
            )
            .await,
        "a config update that makes the policy inert",
    );

    let pattern = service
        .create_policy(create(
            "tag_pattern_delete",
            json!({"pattern": ".*"}),
            vec![],
        ))
        .await
        .expect("dormant policy");
    assert_inert(
        service
            .set_repository_assignment(pattern.id, remote, true)
            .await,
        "attaching tag_pattern_delete to a pypi remote",
    );
    assert_inert(
        service
            .update_policy(
                pattern.id,
                UpdateLifecyclePolicyRequest {
                    repository_ids: Some(vec![remote]),
                    ..Default::default()
                },
            )
            .await,
        "assigning tag_pattern_delete to a pypi remote by update",
    );

    // OCI remotes keep `artifacts` rows for pulled manifests, so every policy
    // type still has something to act on there.
    let (oci_remote, _, _) = tdh::create_repo(&cache.fx.pool, "remote", "docker").await;
    service
        .set_repository_assignment(pattern.id, oci_remote, true)
        .await
        .expect("an OCI remote accepts any policy type");
    service
        .create_policy(create("max_versions", json!({"keep": 1}), vec![oci_remote]))
        .await
        .expect("max_versions on an OCI remote");
}

/// A global policy that has no proxy-cache meaning reports why it skipped a
/// Remote repository instead of silently matching nothing there.
#[tokio::test]
async fn inert_arm_reports_skip_reason_for_remote_repository_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let entry = cache.entry("simple/a/a-1.whl", 90, Some(90)).await;
    let mut policy = crate::services::lifecycle_service::tests::make_policy(
        Uuid::new_v4(),
        "global tag pattern",
        "tag_pattern_delete",
    );
    policy.config = json!({"pattern": ".*"});
    let mut errors = Vec::new();
    let result = cache
        .service()
        .run_proxy_cache_arm(&policy, cache.fx.repo_id, false, &never(), &mut errors)
        .await
        .expect("arm");
    assert!(errors.is_empty());
    assert_eq!(result.entries_matched, 0);
    assert!(result
        .skipped_reason
        .as_deref()
        .is_some_and(|r| r.contains("tag_pattern_delete")));
    cache.assert_entry(&entry, true, "untouched").await;
}

/// Ten consecutive storage failures stop the repository's sweep with a final
/// error line; the entry after them is not attempted and keeps its row.
#[tokio::test]
async fn consecutive_storage_failures_stop_the_sweep_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let mut stuck = Vec::new();
    for i in 0..=MAX_EVICTION_FAILURES {
        stuck.push(cache.stuck_entry(&format!("simple/s{i}/s{i}-1.whl")).await);
    }
    let policy = cache.policy("max_age_days", json!({"days": 30})).await;

    let run = cache
        .service()
        .execute_policy(policy.id, false)
        .await
        .expect("run");
    assert_eq!(run.proxy_cache.entries_matched, 11);
    assert_eq!(run.proxy_cache.entries_removed, 0);
    assert_eq!(
        run.errors.len(),
        11,
        "10 entries plus the stop line: {:?}",
        run.errors
    );
    assert!(run.errors[10].contains("stopped the proxy-cache sweep"));
    let attempted = run.errors[..10].join("\n");
    for entry in &stuck {
        assert!(
            cache.row_exists(entry).await,
            "every stuck entry keeps its row"
        );
    }
    let untried: Vec<_> = (0..=MAX_EVICTION_FAILURES)
        .filter(|i| !attempted.contains(&format!("simple/s{i}/")))
        .collect();
    assert_eq!(
        untried.len(),
        1,
        "exactly the 11th entry is never attempted"
    );
}

/// A success resets the failure count, and a sweep keeps paging past a full
/// page: with a page size of 2, three entries need a second page.
#[tokio::test]
async fn sweep_pages_by_id_until_exhausted_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let mut entries = Vec::new();
    for i in 0..3 {
        entries.push(
            cache
                .entry(&format!("simple/p{i}/p{i}-1.whl"), 90, Some(90))
                .await,
        );
    }
    // A row whose objects were never written: removed, but frees no bytes.
    let ghost = cache.entry("simple/ghost/ghost-1.whl", 90, Some(90)).await;
    std::fs::remove_file(cache.fx.storage_dir.join(&ghost.content)).expect("rm body");
    std::fs::remove_file(cache.fx.storage_dir.join(&ghost.metadata)).expect("rm sidecar");
    let policy = cache.policy("max_age_days", json!({"days": 30})).await;

    let run = cache
        .service()
        .with_proxy_cache_page_size(2)
        .execute_policy(policy.id, false)
        .await
        .expect("run");
    assert!(run.errors.is_empty(), "{:?}", run.errors);
    assert_eq!(run.proxy_cache.entries_removed, 4);
    assert_eq!(
        run.proxy_cache.bytes_freed, 300,
        "the ghost row frees nothing"
    );
    for entry in entries.iter().chain([&ghost]) {
        cache.assert_entry(entry, false, "evicted").await;
    }
}

/// Upgrade safety: a global policy does not reach a Remote repository's
/// cache; only an explicit assignment does.
#[tokio::test]
async fn global_policy_does_not_evict_remote_cache_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let entry = cache.entry("simple/a/a-1.whl", 90, Some(90)).await;
    let mut policy = crate::services::lifecycle_service::tests::make_policy(
        Uuid::new_v4(),
        "global max age",
        "max_age_days",
    );
    policy.applies_to_all = true;
    policy.config = json!({"days": 30});
    let mut errors = Vec::new();
    let result = cache
        .service()
        .run_proxy_cache_arm(&policy, cache.fx.repo_id, false, &never(), &mut errors)
        .await
        .expect("arm");
    assert!(errors.is_empty());
    assert_eq!(
        result,
        ProxyCacheExecutionResult::skipped(GLOBAL_POLICY_REASON)
    );
    cache.assert_entry(&entry, true, "untouched").await;
}

/// A lost scheduler lease stops the sweep before it deletes anything more.
#[tokio::test]
async fn lease_loss_stops_the_sweep_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let entry = cache.entry("simple/a/a-1.whl", 90, Some(90)).await;
    let policy = cache.policy("max_age_days", json!({"days": 30})).await;
    let abort = CancellationToken::new();
    abort.cancel();
    let mut errors = Vec::new();
    let result = cache
        .service()
        .run_proxy_cache_arm(&policy, cache.fx.repo_id, false, &abort, &mut errors)
        .await
        .expect("arm");
    assert_eq!(result.entries_matched, 1);
    assert_eq!(result.entries_removed, 0);
    assert!(
        errors.iter().any(|e| e.contains("scheduler lease lost")),
        "{errors:?}"
    );
    cache.assert_entry(&entry, true, "untouched").await;
}

/// On an OCI remote the hosted executors act on pulled manifests, so a policy
/// type with no proxy-cache meaning is not reported as skipped there.
#[tokio::test]
async fn oci_remote_reports_no_skip_for_artifact_policies_3734() {
    let Some(cache) = RemoteCache::setup("docker", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let policy = cache.policy("max_versions", json!({"keep": 1})).await;
    let mut errors = Vec::new();
    let result = cache
        .service()
        .run_proxy_cache_arm(&policy, cache.fx.repo_id, false, &never(), &mut errors)
        .await
        .expect("arm");
    assert_eq!(result, ProxyCacheExecutionResult::default());
}

/// A policy assigned to a pypi remote before #3734 (inserted directly; the API
/// now refuses it) can still be renamed, disabled, or re-sent its unchanged
/// config; a real config change is checked and refused.
#[tokio::test]
async fn legacy_inert_assignment_can_be_renamed_and_disabled_3734() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let service = cache.service();
    let config = json!({"pattern": ".*"});
    let policy = service
        .create_policy(create("tag_pattern_delete", config.clone(), vec![]))
        .await
        .expect("dormant policy");
    sqlx::query(
        "INSERT INTO lifecycle_policy_repositories (policy_id, repository_id) VALUES ($1, $2)",
    )
    .bind(policy.id)
    .bind(cache.fx.repo_id)
    .execute(&cache.fx.pool)
    .await
    .expect("legacy assignment");

    for (label, req) in [
        (
            "rename",
            UpdateLifecyclePolicyRequest {
                name: Some(format!("renamed-{}", Uuid::new_v4())),
                ..Default::default()
            },
        ),
        (
            "disable",
            UpdateLifecyclePolicyRequest {
                enabled: Some(false),
                ..Default::default()
            },
        ),
        (
            "unchanged config re-sent",
            UpdateLifecyclePolicyRequest {
                config: Some(config.clone()),
                ..Default::default()
            },
        ),
    ] {
        service
            .update_policy(policy.id, req)
            .await
            .unwrap_or_else(|e| panic!("{label} must succeed: {e:?}"));
    }
    assert_inert(
        service
            .update_policy(
                policy.id,
                UpdateLifecyclePolicyRequest {
                    config: Some(json!({"pattern": "^tmp"})),
                    ..Default::default()
                },
            )
            .await,
        "a real config change on a legacy inert assignment",
    );
}

/// #2024: a `composite` policy has no proxy-cache arm, so it never evicts a
/// cache entry. An explicit assignment to a (non-OCI) Remote repository is
/// refused like the other inert types, a global one reports why it skipped,
/// and an OCI remote, which keeps `artifacts` rows, accepts it.
#[tokio::test]
async fn composite_policy_never_evicts_proxy_cache_2024() {
    let Some(cache) = RemoteCache::setup("pypi", ProxyCacheScope::unscoped()).await else {
        return;
    };
    let service = cache.service();
    let remote = cache.fx.repo_id;
    let entry = cache.entry("simple/a/a-1.whl", 90, Some(90)).await;
    let config = json!({"conditions": [
        {"type": "max_age_days", "value": 1},
        {"type": "no_downloads_days", "value": 1}
    ]});

    assert_inert(
        service
            .create_policy(create("composite", config.clone(), vec![remote]))
            .await,
        "composite on a pypi remote",
    );
    assert_inert(
        service
            .create_policy(create(
                "max_age_days",
                json!({"days": 1, "match": {"version_pattern": "^a"}}),
                vec![remote],
            ))
            .await,
        "match.version_pattern on a pypi remote",
    );

    let mut global = crate::services::lifecycle_service::tests::make_policy(
        Uuid::new_v4(),
        "global composite",
        "composite",
    );
    global.applies_to_all = true;
    global.config = config.clone();
    let mut errors = Vec::new();
    let result = service
        .run_proxy_cache_arm(&global, remote, false, &never(), &mut errors)
        .await
        .expect("arm");
    assert!(errors.is_empty());
    assert_eq!(result.entries_matched, 0);
    assert!(result
        .skipped_reason
        .as_deref()
        .is_some_and(|r| r.contains("composite has no proxy-cache equivalent")));
    cache.assert_entry(&entry, true, "untouched").await;

    let (oci_remote, _, _) = tdh::create_repo(&cache.fx.pool, "remote", "docker").await;
    let created = service
        .create_policy(create("composite", config, vec![oci_remote]))
        .await
        .expect("an OCI remote accepts a composite policy");
    assert_eq!(created.policy_type, "composite");
}
