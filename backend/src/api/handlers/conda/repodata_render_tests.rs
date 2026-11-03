//! Tests of the cursor render, the regeneration gate and wait, and the lazy
//! `.bz2` rendering (#4176, #4882).

use super::repodata_cache::{self, RegenGate, Revision};
use super::revision_router_tests::{get, upload};
use super::{
    artifacts_for_subdir, list_conda_artifacts_at, list_removed_artifacts_at, repodata_document,
    repodata_render, run_exports_document, shard_store, RepodataEncoding,
};
use crate::api::handlers::test_db_helpers as tdh;
use axum::http::StatusCode;
use std::io::Read;
use std::time::Duration;

/// Insert a row (and its metadata, when given) the way an import or a
/// generic write path can shape it, bypassing the upload route.
async fn seed(
    fx: &tdh::Fixture,
    path: &str,
    name: &str,
    metadata: Option<serde_json::Value>,
    created_offset_secs: i64,
) -> uuid::Uuid {
    let id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
         checksum_sha256, content_type, storage_key, created_at) \
         VALUES ($1, $2, $3, '1.0', 10, repeat('b', 64), 'application/octet-stream', $4, \
                 NOW() - make_interval(secs => $5)) \
         RETURNING id",
    )
    .bind(fx.repo_id)
    .bind(path)
    .bind(name)
    .bind(format!("seed/{}/{path}", fx.repo_id))
    .bind(created_offset_secs as f64)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    if let Some(metadata) = metadata {
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, 'conda', $2)",
        )
        .bind(id)
        .bind(metadata)
        .execute(&fx.pool)
        .await
        .unwrap();
    }
    id
}

fn meta(name: &str, version: &str, subdir: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "version": version,
        "build": "h0_0",
        "build_number": 3,
        "subdir": subdir,
        "depends": ["python >=3.10", "zlib"],
        "constrains": [],
        "license": "MIT",
        "md5": "0123456789abcdef0123456789abcdef",
        "timestamp": 1700000000000u64,
        "noarch": "python",
        "run_exports": {"weak": [format!("{name} >=1")]},
    })
}

/// The documents the one-shot `serde_json::Value` render produces, the
/// reference the cursor render must match byte for byte.
async fn reference(
    fx: &tdh::Fixture,
    subdir: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let all = list_conda_artifacts_at(&fx.pool, fx.repo_id, now)
        .await
        .unwrap();
    let removed = list_removed_artifacts_at(&fx.pool, fx.repo_id, subdir, now)
        .await
        .unwrap();
    let in_subdir = artifacts_for_subdir(&all, subdir);
    let full = repodata_document(&in_subdir, subdir, false, &removed);
    let current = repodata_document(&in_subdir, subdir, true, &removed);
    let json = serde_json::to_vec_pretty(&full).unwrap();
    // Every encoding holds the bytes `repodata.json` serves (#4175).
    let zst = zstd::stream::encode_all(json.as_slice(), 3).unwrap();
    let mut bz2 = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    std::io::Write::write_all(&mut bz2, &json).unwrap();
    (
        json,
        zst,
        bz2.finish().unwrap(),
        serde_json::to_vec_pretty(&current).unwrap(),
        serde_json::to_vec_pretty(&run_exports_document(&in_subdir, subdir)).unwrap(),
    )
}

/// #4176: the cursor render produces exactly the bytes of the whole-document
/// render, for every encoding, over the row shapes that steer the listing:
/// both package formats, several versions of a name (current keeps the
/// newest), a duplicate filename (the oldest wins), a withdrawn and a lapsed
/// hold, a soft-deleted row (`removed`), a non-package file, a row whose
/// metadata names another subdir, rows without metadata, and the `.bz2`
/// derived from the kept zstd document.
#[tokio::test]
async fn cursor_render_is_byte_identical_to_the_document_render_4176() {
    let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
        return;
    };
    let s = "linux-64";
    seed(
        &fx,
        &format!("{s}/rr-a-1.0-h0_0.tar.bz2"),
        "rr-a",
        Some(meta("rr-a", "1.0", s)),
        50,
    )
    .await;
    seed(
        &fx,
        &format!("{s}/rr-a-2.0-h0_0.conda"),
        "rr-a",
        Some(meta("rr-a", "2.0", s)),
        40,
    )
    .await;
    seed(
        &fx,
        &format!("{s}/rr-a-2.0-h0_0.tar.bz2"),
        "rr-a",
        Some(meta("rr-a", "2.0", s)),
        30,
    )
    .await;
    // Duplicate filename: an older row in another path whose metadata puts
    // it in this subdir.
    seed(
        &fx,
        "elsewhere/rr-b-1.0-h0_0.conda",
        "rr-b",
        Some(meta("rr-b", "1.0", s)),
        60,
    )
    .await;
    seed(
        &fx,
        &format!("{s}/rr-b-1.0-h0_0.conda"),
        "rr-b",
        Some(meta("rr-b", "1.1", s)),
        20,
    )
    .await;
    // No metadata: path decides the subdir, the row name the package.
    seed(&fx, &format!("{s}/rr-c-0.1-0.tar.bz2"), "rr-c", None, 10).await;
    // Metadata naming another subdir: not listed here.
    seed(
        &fx,
        &format!("{s}/rr-d-1.0-h0_0.conda"),
        "rr-d",
        Some(meta("rr-d", "1.0", "noarch")),
        15,
    )
    .await;
    // A non-package file in the subdir.
    seed(&fx, &format!("{s}/notes.txt"), "rr-notes", None, 5).await;
    // Withdrawn and lapsed holds.
    let pulled = seed(
        &fx,
        &format!("{s}/rr-e-1.0-h0_0.conda"),
        "rr-e",
        Some(meta("rr-e", "1.0", s)),
        8,
    )
    .await;
    let lapsed = seed(
        &fx,
        &format!("{s}/rr-f-1.0-h0_0.conda"),
        "rr-f",
        Some(meta("rr-f", "1.0", s)),
        7,
    )
    .await;
    sqlx::query("UPDATE artifacts SET quarantine_status = 'rejected' WHERE id = $1")
        .bind(pulled)
        .execute(&fx.pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = 'quarantined', \
                quarantine_until = NOW() - INTERVAL '1 minute' WHERE id = $1",
    )
    .bind(lapsed)
    .execute(&fx.pool)
    .await
    .unwrap();
    // Held now: an upload hold that has not lapsed, and a permanent admin
    // hold (no expiry). Neither is listed; the name's older build is.
    let live_hold = seed(
        &fx,
        &format!("{s}/rr-h-2.0-h0_0.conda"),
        "rr-h",
        Some(meta("rr-h", "2.0", s)),
        4,
    )
    .await;
    seed(
        &fx,
        &format!("{s}/rr-h-1.0-h0_0.conda"),
        "rr-h",
        Some(meta("rr-h", "1.0", s)),
        45,
    )
    .await;
    let admin_hold = seed(
        &fx,
        &format!("{s}/rr-i-1.0-h0_0.tar.bz2"),
        "rr-i",
        Some(meta("rr-i", "1.0", s)),
        3,
    )
    .await;
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = 'quarantined', \
                quarantine_until = NOW() + INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(live_hold)
    .execute(&fx.pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_until = NULL \
          WHERE id = $1",
    )
    .bind(admin_hold)
    .execute(&fx.pool)
    .await
    .unwrap();
    // Soft-deleted: named in `removed`.
    let gone = seed(
        &fx,
        &format!("{s}/rr-g-1.0-h0_0.tar.bz2"),
        "rr-g",
        Some(meta("rr-g", "1.0", s)),
        6,
    )
    .await;
    sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
        .bind(gone)
        .execute(&fx.pool)
        .await
        .unwrap();

    // The fixture exercises every case it names: the listed set is exactly
    // the visible packages.
    let (json, ..) = reference(&fx, s, chrono::Utc::now()).await;
    let doc: serde_json::Value = serde_json::from_slice(&json).unwrap();
    let mut listed: Vec<&str> = doc["packages"]
        .as_object()
        .unwrap()
        .keys()
        .chain(doc["packages.conda"].as_object().unwrap().keys())
        .map(String::as_str)
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            "rr-a-1.0-h0_0.tar.bz2",
            "rr-a-2.0-h0_0.conda",
            "rr-a-2.0-h0_0.tar.bz2",
            "rr-b-1.0-h0_0.conda",
            "rr-c-0.1-0.tar.bz2",
            "rr-f-1.0-h0_0.conda",
            "rr-h-1.0-h0_0.conda",
        ]
    );

    for subdir in [s, "noarch", "osx-arm64"] {
        let now = chrono::Utc::now();
        let removed = list_removed_artifacts_at(&fx.pool, fx.repo_id, subdir, now)
            .await
            .unwrap();
        let (json, zst, bz2, current, run_exports) = reference(&fx, subdir, now).await;
        // One row per chunk, a few, and the default: chunk boundaries must
        // not show in any encoding.
        for rows_per_chunk in [1, 2, 512] {
            let rendered = repodata_render::render_subdir_chunked(
                &fx.pool,
                fx.repo_id,
                subdir,
                now,
                &removed,
                rows_per_chunk,
            )
            .await
            .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&rendered.json),
                String::from_utf8_lossy(&json),
                "{subdir} repodata.json, {rows_per_chunk} per chunk"
            );
            assert_eq!(
                rendered.zst, zst,
                "{subdir} repodata.json.zst, {rows_per_chunk} per chunk"
            );
            assert_eq!(
                String::from_utf8_lossy(&rendered.current),
                String::from_utf8_lossy(&current),
                "{subdir} current_repodata.json"
            );
            assert_eq!(
                String::from_utf8_lossy(&rendered.run_exports),
                String::from_utf8_lossy(&run_exports),
                "{subdir} run_exports.json"
            );
            assert_eq!(
                RepodataEncoding::Bz2.transcode_zst(&rendered.zst).unwrap(),
                bz2,
                "{subdir} repodata.json.bz2 from the kept zstd"
            );
        }
    }
}

/// #4176 acceptance: with the gate at one permit and six subdirs rendered at
/// once, at most one render is in flight at any time, and all six finish.
#[tokio::test]
async fn one_permit_runs_one_render_at_a_time_across_subdirs_4176() {
    let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
        return;
    };
    let subdirs = [
        "noarch",
        "linux-64",
        "linux-aarch64",
        "osx-64",
        "osx-arm64",
        "win-64",
    ];
    for (i, subdir) in subdirs.iter().enumerate() {
        upload(&fx, subdir, &format!("gate-{i}"), "1.0").await;
    }
    let gate = std::sync::Arc::new(RegenGate::new(1));
    let renders = subdirs.iter().map(|subdir| {
        let gate = gate.clone();
        let pool = fx.pool.clone();
        let repo_id = fx.repo_id;
        async move {
            gate.run(async {
                // Long enough that unbounded renders would overlap.
                tokio::time::sleep(Duration::from_millis(50)).await;
                repodata_render::render_subdir(&pool, repo_id, subdir, chrono::Utc::now(), &[])
                    .await
            })
            .await
        }
    });
    let results = futures::future::join_all(renders).await;
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(gate.peak(), 1, "one permit, one render in flight");

    let wide = std::sync::Arc::new(RegenGate::new(4));
    let renders = (0..6).map(|_| {
        let wide = wide.clone();
        async move {
            wide.run(tokio::time::sleep(Duration::from_millis(50)))
                .await
        }
    });
    futures::future::join_all(renders).await;
    assert_eq!(wide.peak(), 4, "the bound is the permit count");
}

/// #4176: a request that waits past the bound gets 503 with `Retry-After`,
/// and the work it was waiting for keeps running to completion.
#[tokio::test]
async fn a_wait_past_the_bound_is_503_and_the_render_completes_4176() {
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = finished.clone();
    let response = repodata_cache::bounded_by(Some(Duration::from_millis(50)), async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok::<_, axum::response::Response>(())
    })
    .await
    .unwrap_err();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get("retry-after").unwrap(), "5");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        finished.load(std::sync::atomic::Ordering::SeqCst),
        "the render outlives the request that gave up on it"
    );

    // Within the bound, and with no bound, the result is returned.
    assert_eq!(
        repodata_cache::bounded_by(Some(Duration::from_secs(5)), async {
            Ok::<_, axum::response::Response>(7)
        })
        .await
        .unwrap(),
        7
    );
    assert_eq!(
        repodata_cache::bounded_by(None, async { Ok::<_, axum::response::Response>(8) })
            .await
            .unwrap(),
        8
    );
}

#[test]
fn regen_settings_parse_4176() {
    use repodata_cache::{parse_regen_concurrency, parse_regen_wait};
    assert_eq!(parse_regen_concurrency(None), 2);
    assert_eq!(parse_regen_concurrency(Some(" 6 ")), 6);
    assert_eq!(parse_regen_concurrency(Some("0")), 2);
    assert_eq!(parse_regen_concurrency(Some("many")), 2);
    assert_eq!(parse_regen_wait(None), Some(Duration::from_secs(30)));
    assert_eq!(parse_regen_wait(Some("5")), Some(Duration::from_secs(5)));
    assert_eq!(parse_regen_wait(Some("0")), None);
    assert_eq!(
        parse_regen_wait(Some("soon")),
        Some(Duration::from_secs(30))
    );
}

/// #4882: `.bz2` is not rendered with the revision; the first `.bz2`
/// request renders it from the kept zstd document, and later ones are served
/// the kept bytes. It is the single-stream document 1.11 served.
#[tokio::test]
async fn bz2_is_rendered_on_first_request_and_kept_for_the_revision_4882() {
    let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
        return;
    };
    upload(&fx, "noarch", "lazy-a", "1.0").await;
    let (status, json, _) = get(&fx, "noarch/repodata.json").await;
    assert_eq!(status, StatusCode::OK);
    let revision = shard_store::subdir_state(&fx.pool, fx.repo_id, "noarch")
        .await
        .unwrap()
        .revision;
    let kept = repodata_cache::subdir_cache()
        .lookup_scoped(fx.repo_id, "noarch", &Revision(revision))
        .await
        .expect("the revision is kept");
    assert!(
        !kept.bz2.initialized(),
        "repodata.json does not pay for bz2"
    );

    let (status, first, h1) = get(&fx, "noarch/repodata.json.bz2").await;
    assert_eq!(status, StatusCode::OK);
    assert!(kept.bz2.initialized(), "kept with the revision");
    let (_, second, h2) = get(&fx, "noarch/repodata.json.bz2").await;
    assert_eq!(first, second);
    assert_eq!(h1.get("etag"), h2.get("etag"));

    // One bzip2 stream holding the compact form of what repodata.json lists.
    let mut decoder = bzip2::bufread::BzDecoder::new(&first[..]);
    let mut plain = Vec::new();
    decoder.read_to_end(&mut plain).unwrap();
    let mut rest = Vec::new();
    decoder.into_inner().read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "a single bzip2 stream");
    let from_bz2: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    let from_json: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(from_bz2, from_json);
}

/// A subdir no row has ever named is served its empty documents without a
/// render or a cache entry, byte-identical to a render of it.
#[tokio::test]
async fn a_never_named_subdir_is_served_without_a_render_4176() {
    let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
        return;
    };
    upload(&fx, "noarch", "empty-a", "1.0").await;
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);

    let (status, json, _) = get(&fx, "osx-arm64/repodata.json").await;
    assert_eq!(status, StatusCode::OK);
    let (status, zst, _) = get(&fx, "osx-arm64/repodata.json.zst").await;
    assert_eq!(status, StatusCode::OK);
    let rendered =
        repodata_render::render_subdir(&fx.pool, fx.repo_id, "osx-arm64", chrono::Utc::now(), &[])
            .await
            .unwrap();
    assert_eq!(json.as_ref(), rendered.json.as_slice());
    assert_eq!(zst.as_ref(), rendered.zst.as_slice());
    let empty = repodata_render::render_empty("osx-arm64").unwrap();
    assert_eq!(empty.current, rendered.current);
    assert_eq!(empty.run_exports, rendered.run_exports);

    let renders: u64 = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| key.key().name() == "ak_repo_metadata_regenerations_total")
        .map(|(_, _, _, value)| match value {
            metrics_util::debugging::DebugValue::Counter(n) => n,
            _ => 0,
        })
        .sum();
    assert_eq!(renders, 0, "no render for a subdir no row names");
    assert!(repodata_cache::subdir_cache()
        .lookup_scoped(fx.repo_id, "osx-arm64", &Revision(0))
        .await
        .is_none());
}

/// #5167: `.bz2` of a subdir no row has ever named is answered with every
/// regeneration permit taken, like its other encodings, and holds the same
/// document.
#[tokio::test]
async fn a_never_named_subdir_answers_bz2_without_a_permit_5167() {
    let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
        return;
    };
    upload(&fx, "noarch", "empty-bz2", "1.0").await;

    let permits = repodata_cache::parse_regen_concurrency(
        std::env::var(repodata_cache::REGEN_CONCURRENCY_ENV)
            .ok()
            .as_deref(),
    );
    let mut release = Vec::new();
    for _ in 0..permits {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(repodata_cache::regen_gate().run(async move {
            let _ = started_tx.send(());
            let _ = release_rx.await;
        }));
        started_rx.await.unwrap();
        release.push(release_tx);
    }

    let (status, bz2, _) = tokio::time::timeout(
        Duration::from_secs(10),
        get(&fx, "osx-arm64/repodata.json.bz2"),
    )
    .await
    .expect("answered while every permit is taken");
    drop(release);
    assert_eq!(status, StatusCode::OK);

    let mut plain = Vec::new();
    bzip2::bufread::BzDecoder::new(&bz2[..])
        .read_to_end(&mut plain)
        .unwrap();
    let (status, json, _) = get(&fx, "osx-arm64/repodata.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&plain).unwrap(),
        serde_json::from_slice::<serde_json::Value>(&json).unwrap()
    );
}
