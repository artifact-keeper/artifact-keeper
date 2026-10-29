use super::*;
use crate::api::handlers::proxy_scan_archive::test_support::minimal_rpm;
use crate::api::handlers::rpm::RpmArtifact;
use crate::api::handlers::test_db_helpers as tdh;
use axum::http::StatusCode;
use axum::Router;

const DOCS: [&str; 5] = [
    "repomd.xml",
    "primary.xml.gz",
    "filelists.xml.gz",
    "other.xml.gz",
    "updateinfo.xml.gz",
];

fn admin_app(f: &tdh::Fixture) -> Router {
    tdh::router_with_auth_ext(
        Router::new().nest("/rpm", rpm::router()),
        f.state.clone(),
        tdh::admin_auth(f.user_id, &f.username),
    )
}

async fn upload(f: &tdh::Fixture, path: &str, name: &str, version: &str) {
    let body = minimal_rpm(name, None, version, "1", "noarch", &[]);
    let (status, resp) = tdh::send(
        admin_app(f),
        tdh::put(format!("/rpm/{}/{path}", f.repo_key), Bytes::from(body)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&resp)
    );
}

async fn get(f: &tdh::Fixture, path: &str) -> (StatusCode, Bytes) {
    tdh::send(
        f.router_anon(Router::new().nest("/rpm", rpm::router())),
        tdh::get(format!("/rpm/{}/{path}", f.repo_key)),
    )
    .await
}

/// Every generated document of `root` (`""` for depth zero).
async fn documents(f: &tdh::Fixture, root: &str) -> Vec<Bytes> {
    let mut out = Vec::new();
    for doc in DOCS {
        let path = if root.is_empty() {
            format!("repodata/{doc}")
        } else {
            format!("{root}/repodata/{doc}")
        };
        let (status, body) = get(f, &path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        out.push(body);
    }
    out
}

async fn row(
    f: &tdh::Fixture,
    root: &str,
) -> Option<(Option<DateTime<Utc>>, Option<i64>, Option<i64>)> {
    fold_marks_waiting(&f.pool).await.expect("fold dirty marks");
    sqlx::query_as(
        "SELECT dirty_since, built_revision, previous_revision FROM rpm_repodata_roots \
          WHERE repository_id = $1 AND root = $2",
    )
    .bind(f.repo_id)
    .bind(root)
    .fetch_optional(&f.pool)
    .await
    .unwrap()
}

/// The due roots once every queued mark is folded.
async fn due(f: &tdh::Fixture, settings: &BuilderSettings) -> Vec<(Uuid, String)> {
    fold_marks_waiting(&f.pool).await.unwrap();
    due_roots(&f.pool, settings).await.unwrap()
}

async fn build(f: &tdh::Fixture, root: &str) -> BuildOutcome {
    try_build(&f.state, f.repo_id, root, &BuilderSettings::default())
        .await
        .expect("build")
}

async fn location(f: &tdh::Fixture) -> StorageLocation {
    let (backend, path): (String, String) =
        sqlx::query_as("SELECT storage_backend, storage_path FROM repositories WHERE id = $1")
            .bind(f.repo_id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    StorageLocation { backend, path }
}

async fn stored_at(
    f: &tdh::Fixture,
    location: &StorageLocation,
    root: &str,
    revision: i64,
    file: &str,
) -> bool {
    f.state
        .storage_for_repo(location)
        .unwrap()
        .exists(&format!(
            "{}/{file}",
            revision_prefix(f.repo_id, root, revision)
        ))
        .await
        .unwrap()
}

async fn object_exists(f: &tdh::Fixture, root: &str, revision: i64, file: &str) -> bool {
    stored_at(f, &location(f).await, root, revision, file).await
}

/// The stored revision serves exactly the bytes the on-request render
/// serves for the same rows, document for document, and the detached
/// signature still verifies over the stored `repomd.xml` (#4544).
#[tokio::test]
async fn stored_revision_is_byte_identical_to_the_on_request_render_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    for (name, version) in [("alpha", "1.0"), ("beta", "2.1"), ("gamma", "0.9")] {
        upload(
            &f,
            &format!("packages/{name}-{version}-1.noarch.rpm"),
            name,
            version,
        )
        .await;
    }
    let (dirty, built, _) = row(&f, "").await.expect("upload created the root row");
    assert!(dirty.is_some(), "an upload dirties the root");
    assert_eq!(built, None);

    // Never built: rendered on request.
    let on_request = documents(&f, "").await;
    let renders = f.state.rpm_repodata_cache.renders();

    let outcome = build(&f, "").await;
    assert_eq!(
        outcome,
        BuildOutcome::Built {
            revision: 1,
            packages: 3
        }
    );
    let (dirty, built, previous) = row(&f, "").await.unwrap();
    assert_eq!((dirty, built, previous), (None, Some(1), None));
    let stored = stored_revision(&f.pool, f.repo_id, "")
        .await
        .unwrap()
        .expect("stored revision");
    assert_eq!(stored.repomd_xml, on_request[0]);

    let precomputed = documents(&f, "").await;
    assert_eq!(precomputed, on_request, "stored bytes equal the render");
    assert_eq!(
        f.state.rpm_repodata_cache.renders(),
        renders,
        "a built root is not rendered on request"
    );
    for (i, file) in [
        "repomd.xml",
        "primary.xml.gz",
        "filelists.xml.gz",
        "other.xml.gz",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(object_exists(&f, "", 1, file).await, "{file} stored");
        assert_eq!(
            stored.sizes.get(file).copied(),
            Some(on_request[i].len() as u64)
        );
    }

    // Opting out renders on request again, with the same bytes.
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, 'on_request')",
    )
    .bind(f.repo_id)
    .bind(MODE_KEY)
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(stored_revision(&f.pool, f.repo_id, "")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        mode(&f.pool, f.repo_id).await.unwrap(),
        RepodataMode::OnRequest
    );
    assert_eq!(documents(&f, "").await, on_request);
    assert_eq!(build(&f, "").await, BuildOutcome::NotPrecomputed);
    // The GC drops an opted-out repository's revisions.
    collect_garbage(&f.state).await.unwrap();
    assert!(!object_exists(&f, "", 1, "primary.xml.gz").await);
    assert_eq!(
        row(&f, "").await.map(|r| r.1),
        Some(None),
        "revision dropped, row kept"
    );
    f.teardown().await;
}

/// A write after a build dirties the root; the built revision is served
/// until the next build, which then reflects the write. Two revisions are
/// kept and older ones are deleted (#4544).
#[tokio::test]
async fn writes_dirty_the_root_and_old_revisions_are_collected_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    upload(&f, "packages/one-1.0-1.noarch.rpm", "one", "1.0").await;
    assert!(matches!(
        build(&f, "").await,
        BuildOutcome::Built { revision: 1, .. }
    ));
    let first = documents(&f, "").await;

    upload(&f, "packages/two-1.0-1.noarch.rpm", "two", "1.0").await;
    let (dirty, built, _) = row(&f, "").await.unwrap();
    assert!(dirty.is_some());
    assert_eq!(built, Some(1));
    assert_eq!(
        documents(&f, "").await,
        first,
        "the built revision is served until the next build"
    );

    assert!(matches!(
        build(&f, "").await,
        BuildOutcome::Built { revision: 2, .. }
    ));
    let second = documents(&f, "").await;
    assert_ne!(second[1], first[1]);

    upload(&f, "packages/three-1.0-1.noarch.rpm", "three", "1.0").await;
    assert!(matches!(
        build(&f, "").await,
        BuildOutcome::Built { revision: 3, .. }
    ));
    let (dirty, built, previous) = row(&f, "").await.unwrap();
    assert_eq!((dirty, built, previous), (None, Some(3), Some(2)));
    assert!(
        !object_exists(&f, "", 1, "primary.xml.gz").await,
        "rev 1 collected"
    );
    assert!(
        object_exists(&f, "", 2, "primary.xml.gz").await,
        "previous kept"
    );
    assert!(object_exists(&f, "", 3, "primary.xml.gz").await);

    // Matches a fresh on-request render of the same state.
    let stored = documents(&f, "").await;
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, 'on_request')",
    )
    .bind(f.repo_id)
    .bind(MODE_KEY)
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(documents(&f, "").await, stored);
    f.teardown().await;
}

/// Heal bookkeeping does not dirty a root; any other metadata change does.
/// A change the triggers missed is found by the reconcile (#4544).
#[tokio::test]
async fn metadata_changes_and_reconcile_dirty_the_root_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    upload(&f, "packages/one-1.0-1.noarch.rpm", "one", "1.0").await;
    assert!(matches!(build(&f, "").await, BuildOutcome::Built { .. }));
    assert_eq!(row(&f, "").await.unwrap().0, None);

    sqlx::query(
        "UPDATE artifact_metadata SET metadata = metadata || '{\"repodata_heal_failures\": 1}' \
          WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)",
    )
    .bind(f.repo_id)
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(row(&f, "").await.unwrap().0, None, "heal bookkeeping");

    sqlx::query(
        "UPDATE artifact_metadata SET metadata = metadata || '{\"summary\": \"enriched\"}' \
          WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)",
    )
    .bind(f.repo_id)
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(row(&f, "").await.unwrap().0.is_some(), "metadata change");
    assert!(matches!(build(&f, "").await, BuildOutcome::Built { .. }));

    // Simulate a write whose dirty mark was lost to the snapshot race.
    upload(&f, "packages/two-1.0-1.noarch.rpm", "two", "1.0").await;
    sqlx::query("DELETE FROM rpm_repodata_dirty WHERE repository_id = $1")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE rpm_repodata_roots SET dirty_since = NULL WHERE repository_id = $1")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(reconcile(&f.pool).await.unwrap() >= 1);
    assert!(
        row(&f, "").await.unwrap().0.is_some(),
        "reconcile re-dirtied"
    );
    f.teardown().await;
}

/// The debounce: a root is due once quiet or once dirty for the maximum
/// delay; `request_build` skips the wait (#4544).
#[tokio::test]
async fn due_roots_are_debounced_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    upload(&f, "packages/one-1.0-1.noarch.rpm", "one", "1.0").await;
    let mine = |due: Vec<(Uuid, String)>| due.iter().any(|(id, _)| *id == f.repo_id);
    let patient = BuilderSettings {
        quiet: Duration::from_secs(3600),
        max_delay: Duration::from_secs(3600),
        batch: 10_000,
        ..BuilderSettings::default()
    };
    assert!(!mine(due(&f, &patient).await));
    let eager = BuilderSettings {
        quiet: Duration::ZERO,
        batch: 10_000,
        ..patient.clone()
    };
    assert!(mine(due(&f, &eager).await));
    request_build(&f.pool, f.repo_id, "").await.unwrap();
    assert!(mine(due(&f, &patient).await));
    f.teardown().await;
}

/// Depth roots are built and served independently; an emptied root is
/// dropped and renders on request (#4544).
#[tokio::test]
async fn depth_roots_build_independently_and_empty_roots_are_dropped_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    sqlx::query("INSERT INTO repository_config (repository_id, key, value) VALUES ($1, 'repodata_depth', '1')")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    upload(&f, "el9/a-1.0-1.noarch.rpm", "a", "1.0").await;
    upload(&f, "el10/b-1.0-1.noarch.rpm", "b", "1.0").await;
    let el9 = documents(&f, "el9").await;
    let el10 = documents(&f, "el10").await;
    assert!(matches!(build(&f, "el9").await, BuildOutcome::Built { .. }));
    assert!(stored_revision(&f.pool, f.repo_id, "el9")
        .await
        .unwrap()
        .is_some());
    assert!(stored_revision(&f.pool, f.repo_id, "el10")
        .await
        .unwrap()
        .is_none());
    assert_eq!(documents(&f, "el9").await, el9);
    assert_eq!(documents(&f, "el10").await, el10);

    sqlx::query(
        "UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND path LIKE 'el9/%'",
    )
    .bind(f.repo_id)
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(build(&f, "el9").await, BuildOutcome::Empty);
    assert_eq!(
        row(&f, "el9").await.map(|r| r.1),
        Some(None),
        "an empty root is not stored"
    );
    assert!(stored_revision(&f.pool, f.repo_id, "el9")
        .await
        .unwrap()
        .is_none());
    assert!(!object_exists(&f, "el9", 1, "primary.xml.gz").await);
    let (status, _) = get(&f, "el9/repodata/repomd.xml").await;
    assert_eq!(status, StatusCode::OK);
    f.teardown().await;
}

/// A deleted repository's revisions are deleted by the GC, then its rows.
#[tokio::test]
async fn deleted_repository_revisions_are_collected_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    upload(&f, "packages/one-1.0-1.noarch.rpm", "one", "1.0").await;
    assert!(matches!(build(&f, "").await, BuildOutcome::Built { .. }));
    let loc = location(&f).await;
    assert!(stored_at(&f, &loc, "", 1, "repomd.xml").await);
    sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    // The hard delete queued a dirty mark for the root (migration 309), and
    // the mark outlives the repository. Fold it first, as the builder's tick
    // does: folded after the GC removed the row, it would recreate the row.
    // Without this the test passed only when another test's fold on the
    // shared database happened to consume the mark in between.
    fold_marks_waiting(&f.pool).await.unwrap();
    // One pass handles a page of 64 roots in no set order, and another
    // test's GC may hold this root's lease, so a pass that collected
    // nothing does not mean this root was collected. Retry until this
    // repository's row is gone (its objects are deleted before the row).
    let mut remaining = 1;
    for _ in 0..100 {
        collect_garbage(&f.state).await.unwrap();
        remaining = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM rpm_repodata_roots WHERE repository_id = $1",
        )
        .bind(f.repo_id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        if remaining == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(remaining, 0, "the deleted repository's root was collected");
    assert!(!stored_at(&f, &loc, "", 1, "repomd.xml").await);
    assert!(row(&f, "").await.is_none());
    f.teardown().await;
}

fn artifact(i: usize) -> RpmArtifact {
    RpmArtifact {
        id: Uuid::from_u128(i as u128 + 1),
        path: format!("packages/pkg{i}-1.0-1.noarch.rpm"),
        name: format!("pkg{i}"),
        version: Some("1.0-1".into()),
        size_bytes: 1000 + i as i64,
        checksum_sha256: format!("{i:064x}"),
        storage_key: format!("k{i}"),
        metadata: Some(serde_json::json!({
            "summary": format!("package {i} ").repeat(40),
            "files": (0..50).map(|n| format!("/usr/share/pkg{i}/file{n}")).collect::<Vec<_>>(),
        })),
        updated_at: DateTime::from_timestamp(1_700_000_000 + i as i64, 0).unwrap(),
    }
}

/// The compressed bytes do not depend on the sink: a spool file receives
/// exactly what the in-memory render produces, spilled or not (#4544).
#[test]
fn file_sinks_receive_the_in_memory_bytes_4544() {
    use std::io::Read;
    let rows: Vec<RpmArtifact> = (0..40).map(artifact).collect();
    for spill in [1, 4096, rpm::RPM_REPODATA_DOC_SPILL_BYTES] {
        let mut memory = rpm::RepodataWriter::with_sinks(
            rows.len(),
            "",
            spill,
            [Vec::new(), Vec::new(), Vec::new()],
        );
        let files = [(); 3].map(|_| tempfile::NamedTempFile::new().unwrap());
        let mut spooled = rpm::RepodataWriter::with_sinks(
            rows.len(),
            "",
            spill,
            files
                .each_ref()
                .map(|f| BufWriter::new(f.reopen().unwrap())),
        );
        for chunk in rows.chunks(7) {
            memory.push_batch(chunk);
            spooled.push_batch(chunk);
        }
        let memory = memory.finish_docs().unwrap();
        let spooled = spooled.finish_docs().unwrap();
        assert_eq!(memory.repomd_xml, spooled.repomd_xml, "spill {spill}");
        for (mem, (doc, file)) in [memory.primary, memory.filelists, memory.other]
            .into_iter()
            .zip(
                [spooled.primary, spooled.filelists, spooled.other]
                    .into_iter()
                    .zip(&files),
            )
        {
            doc.sink.into_inner().unwrap();
            let mut on_disk = Vec::new();
            file.reopen().unwrap().read_to_end(&mut on_disk).unwrap();
            assert_eq!(on_disk, mem.sink, "spill {spill}");
            assert_eq!(doc.size, mem.size);
        }
    }
}

/// The claim waits for writers still holding the root's fence (their
/// trigger saw the root dirty and skipped it), so their rows are in the
/// snapshot; a writer that outlasts the fence timeout makes the root Busy
/// for this tick, still dirty. A build that dies after its claim is retried
/// once its deadline passes (#4544).
#[tokio::test]
async fn claim_waits_for_fenced_writers_and_crashed_builds_retry_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    upload(&f, "packages/one-1.0-1.noarch.rpm", "one", "1.0").await;
    let mut writer = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock_shared(ak_rpm_repodata_fence($1, ''))")
        .bind(f.repo_id)
        .execute(&mut *writer)
        .await
        .unwrap();
    let hasty = BuilderSettings {
        fence_timeout: Duration::from_millis(100),
        ..BuilderSettings::default()
    };
    let outcome = try_build(&f.state, f.repo_id, "", &hasty).await.unwrap();
    assert_eq!(outcome, BuildOutcome::WritersBusy);
    assert!(row(&f, "").await.unwrap().0.is_some(), "still dirty");
    writer.commit().await.unwrap();
    // Backed off: not due until the back-off passes.
    let eager = BuilderSettings {
        quiet: Duration::ZERO,
        batch: 10_000,
        ..BuilderSettings::default()
    };
    assert!(!due(&f, &eager).await.iter().any(|(id, _)| *id == f.repo_id));
    assert!(matches!(build(&f, "").await, BuildOutcome::Built { .. }));

    // A claim whose build never swapped: clean, deadline passed.
    sqlx::query(
        "UPDATE rpm_repodata_roots SET dirty_since = NULL, retry_at = now() - interval '1 second' \
          WHERE repository_id = $1",
    )
    .bind(f.repo_id)
    .execute(&f.pool)
    .await
    .unwrap();
    let patient = BuilderSettings {
        quiet: Duration::from_secs(3600),
        max_delay: Duration::from_secs(3600),
        batch: 10_000,
        ..BuilderSettings::default()
    };
    assert!(due(&f, &patient)
        .await
        .iter()
        .any(|(id, _)| *id == f.repo_id));
    f.teardown().await;
}

/// Two transactions that each dirty two clean roots, in opposite order, do
/// not wait on each other: writers only append dirty marks (migration 309),
/// so neither holds a lock the other needs. Under migration 308 alone the
/// second write of each transaction waited on the other's root row and
/// Postgres aborted one of them as a deadlock (#4544). Metadata writes are
/// the case that matters: they change no stored size, so unlike uploads they
/// do not already serialize on the repository's usage-ledger row.
#[tokio::test]
async fn writers_dirtying_two_roots_in_opposite_order_do_not_deadlock_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, 'repodata_depth', '1')",
    )
    .bind(f.repo_id)
    .execute(&f.pool)
    .await
    .unwrap();
    for (root, n) in [("a", 1), ("a", 2), ("b", 3), ("b", 4)] {
        upload(
            &f,
            &format!("{root}/x{n}-1.0-1.noarch.rpm"),
            &format!("x{n}"),
            "1.0",
        )
        .await;
    }
    assert!(matches!(build(&f, "a").await, BuildOutcome::Built { .. }));
    assert!(matches!(build(&f, "b").await, BuildOutcome::Built { .. }));
    assert_eq!(row(&f, "a").await.unwrap().0, None, "a is clean");
    assert_eq!(row(&f, "b").await.unwrap().0, None, "b is clean");

    async fn enrich(
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        f: &tdh::Fixture,
        path: &str,
    ) {
        let step = sqlx::query(
            "UPDATE artifact_metadata SET metadata = metadata || '{\"summary\": \"enriched\"}' \
              WHERE artifact_id = (SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2)",
        )
        .bind(f.repo_id)
        .bind(path)
        .execute(&mut **tx);
        tokio::time::timeout(Duration::from_secs(10), step)
            .await
            .expect("a writer waited on the other transaction")
            .expect("metadata update");
    }
    let mut t1 = f.pool.begin().await.unwrap();
    let mut t2 = f.pool.begin().await.unwrap();
    enrich(&mut t1, &f, "a/x1-1.0-1.noarch.rpm").await;
    enrich(&mut t2, &f, "b/x3-1.0-1.noarch.rpm").await;
    enrich(&mut t1, &f, "b/x4-1.0-1.noarch.rpm").await;
    enrich(&mut t2, &f, "a/x2-1.0-1.noarch.rpm").await;
    t1.commit().await.unwrap();
    t2.commit().await.unwrap();
    assert!(row(&f, "a").await.unwrap().0.is_some(), "a dirtied");
    assert!(row(&f, "b").await.unwrap().0.is_some(), "b dirtied");
    f.teardown().await;
}
