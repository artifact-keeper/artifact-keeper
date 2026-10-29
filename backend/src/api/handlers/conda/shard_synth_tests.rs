//! Tests of CEP-16 shards synthesised for a Remote conda repository whose
//! upstream publishes no shard index (#4178).

use super::shard_synth::{
    self, for_each_record, for_each_record_capped, shards_of_partition, shards_of_partition_capped,
    spill_document, spill_document_in, SynthError,
};
use super::tests::{cleanup_conda_repo, insert_public_remote_conda_repo, state_with_proxy_cache};
use super::virtual_channel_tests::upstream_record;
use super::{shard_address, RepodataEncoding};
use crate::api::handlers::test_db_helpers as tdh;
use axum::http::StatusCode;
use std::io::Write;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// An upstream `repodata.json` with `.tar.bz2` records in `packages` and
/// `.conda` records in `packages.conda`, plus the members a real channel
/// carries around them.
fn repodata(subdir: &str, tar: &[&str], conda: &[&str]) -> serde_json::Value {
    let section = |files: &[&str]| -> serde_json::Map<String, serde_json::Value> {
        files
            .iter()
            .map(|f| (f.to_string(), upstream_record(subdir, f)))
            .collect()
    };
    serde_json::json!({
        "info": {"subdir": subdir, "base_url": "https://example.invalid/"},
        "packages": section(tar),
        "packages.conda": section(conda),
        "removed": ["gone-1.0-0.tar.bz2"],
        "repodata_version": 1,
    })
}

fn bz2(doc: &serde_json::Value) -> Vec<u8> {
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    enc.write_all(&serde_json::to_vec(doc).unwrap()).unwrap();
    enc.finish().unwrap()
}

async fn mount(server: &MockServer, path: &str, body: Vec<u8>) {
    Mock::given(method("GET"))
        .and(wm_path(path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(server)
        .await;
}

async fn hits(server: &MockServer, path: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == path)
        .count()
}

fn decode_index(body: &[u8]) -> rattler_conda_types::ShardedRepodata {
    rmp_serde::from_slice(&zstd::decode_all(body).unwrap()).unwrap()
}

fn names(index: &rattler_conda_types::ShardedRepodata) -> Vec<String> {
    let mut names: Vec<String> = index.shards.keys().cloned().collect();
    names.sort();
    names
}

fn decode_shard(body: &[u8]) -> rattler_conda_types::Shard {
    rmp_serde::from_slice(&zstd::decode_all(body).unwrap()).unwrap()
}

/// The streaming parse sees every record of both sections, in document
/// order, and nothing else; trailing garbage is refused.
#[test]
fn records_are_streamed_from_both_sections_4178() {
    let doc = repodata(
        "noarch",
        &["a-1.0-0.tar.bz2", "b-1.0-0.tar.bz2"],
        &["a-2.0-0.conda"],
    );
    let bytes = serde_json::to_vec_pretty(&doc).unwrap();
    let mut seen = Vec::new();
    let n = for_each_record(bytes.as_slice(), |v2, f, r| {
        seen.push((v2, f, r["name"].as_str().unwrap().to_string()));
        Ok(())
    })
    .unwrap();
    assert_eq!(n, 3);
    assert_eq!(
        seen,
        vec![
            (false, "a-1.0-0.tar.bz2".into(), "a".into()),
            (false, "b-1.0-0.tar.bz2".into(), "b".into()),
            (true, "a-2.0-0.conda".into(), "a".into()),
        ]
    );
    let mut bad = bytes.clone();
    bad.extend_from_slice(b" {}");
    assert!(for_each_record(bad.as_slice(), |_, _, _| Ok(())).is_err());
}

/// Spilled and grouped, a name's records from both sections land in one
/// shard; every encoding of the upstream document gives the same shards.
#[test]
fn shards_group_a_name_across_sections_and_encodings_4178() {
    let doc = repodata(
        "noarch",
        &["a-1.0-0.tar.bz2", "b-1.0-0.tar.bz2"],
        &["a-2.0-0.conda"],
    );
    let plain = serde_json::to_vec(&doc).unwrap();
    let zst = zstd::encode_all(plain.as_slice(), 3).unwrap();
    let mut results = Vec::new();
    for (bytes, source) in [
        (plain.clone(), RepodataEncoding::Json),
        (zst, RepodataEncoding::Zst),
        (bz2(&doc), RepodataEncoding::Bz2),
    ] {
        let (parts, records) = spill_document(bytes.into(), None, source).unwrap();
        assert_eq!(records, 3);
        let mut shards = Vec::new();
        for p in &parts.paths {
            shards.extend(shards_of_partition(p).unwrap());
        }
        shards.sort_by(|a, b| a.0.cmp(&b.0));
        results.push(shards);
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0], results[2]);
    let shards = &results[0];
    assert_eq!(
        shards.iter().map(|s| s.0.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    for (_, bytes, address) in shards {
        assert_eq!(&shard_address(bytes), address);
    }
    let a = decode_shard(&shards[0].1);
    assert_eq!(a.packages.len(), 1);
    assert_eq!(a.conda_packages.len(), 1);
    assert!(a
        .conda_packages
        .keys()
        .any(|k| k.to_string() == "a-2.0-0.conda"));
}

/// #4178, hostile upstream: a record whose `name` is not the package its
/// filename names lands in the shard of the name it carries (what a solver
/// reading the upstream `repodata.json` would see) and leaves the other
/// name's shard as it was; a filename listed twice keeps its last record,
/// as a JSON parser of the document would; a record with no name is skipped.
#[test]
fn a_mismatched_or_duplicate_record_cannot_reach_another_names_shard_4178() {
    let honest = repodata("noarch", &["numpy-1.0-0.tar.bz2"], &[]);
    let honest_shards = {
        let (parts, _) = spill_document(
            serde_json::to_vec(&honest).unwrap().into(),
            None,
            RepodataEncoding::Json,
        )
        .unwrap();
        let mut all = Vec::new();
        for p in &parts.paths {
            all.extend(shards_of_partition(p).unwrap());
        }
        all
    };
    let mut evil = upstream_record("noarch", "numpy-9.9-0.tar.bz2");
    evil["name"] = "evil".into();
    let mut first = upstream_record("noarch", "dup-1.0-0.tar.bz2");
    first["build"] = "first".into();
    let mut last = upstream_record("noarch", "dup-1.0-0.tar.bz2");
    last["build"] = "last".into();
    let mut nameless = upstream_record("noarch", "anon-1.0-0.tar.bz2");
    nameless.as_object_mut().unwrap().remove("name");
    let numpy = upstream_record("noarch", "numpy-1.0-0.tar.bz2");
    // Written by hand: a JSON object with a duplicate key.
    let doc = format!(
        "{{\"info\":{{\"subdir\":\"noarch\"}},\"packages\":{{\
         \"numpy-1.0-0.tar.bz2\":{numpy},\"numpy-9.9-0.tar.bz2\":{evil},\
         \"dup-1.0-0.tar.bz2\":{first},\"dup-1.0-0.tar.bz2\":{last},\
         \"anon-1.0-0.tar.bz2\":{nameless}}},\"packages.conda\":{{}}}}"
    );
    let (parts, records) =
        spill_document(doc.into_bytes().into(), None, RepodataEncoding::Json).unwrap();
    assert_eq!(records, 4, "the nameless record is skipped");
    let mut shards = Vec::new();
    for p in &parts.paths {
        shards.extend(shards_of_partition(p).unwrap());
    }
    shards.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        shards.iter().map(|s| s.0.as_str()).collect::<Vec<_>>(),
        ["dup", "evil", "numpy"]
    );
    let numpy_shard = shards.iter().find(|s| s.0 == "numpy").unwrap();
    assert_eq!(
        numpy_shard, &honest_shards[0],
        "numpy's shard is byte for byte the one an honest document gives"
    );
    let evil_shard = decode_shard(&shards.iter().find(|s| s.0 == "evil").unwrap().1);
    assert_eq!(evil_shard.packages.len(), 1);
    let dup = decode_shard(&shards.iter().find(|s| s.0 == "dup").unwrap().1);
    assert_eq!(dup.packages.len(), 1);
    assert_eq!(dup.packages.values().next().unwrap().build, "last");
}

/// #4178, hostile upstream: a document that decodes past the ceiling, one
/// enormous record, or one name whose records pass the per-name bound is
/// refused as an upstream failure before it is held, rather than parsed
/// into memory.
#[test]
fn an_oversized_upstream_document_is_refused_as_an_upstream_failure_4178() {
    let doc = repodata("noarch", &["a-1.0-0.tar.bz2", "b-1.0-0.tar.bz2"], &[]);
    let bytes = serde_json::to_vec(&doc).unwrap();
    // A decompression bomb: valid JSON whitespace past the decoded ceiling.
    let mut bomb = b"{\"packages\":".to_vec();
    bomb.extend(std::iter::repeat_n(b' ', 4 * 1024 * 1024));
    bomb.extend_from_slice(b"{}}");
    let err = for_each_record_capped(bomb.as_slice(), 1024 * 1024, u64::MAX / 2, |_, _, _| Ok(()))
        .unwrap_err();
    assert!(err.contains("ceiling"), "{err}");
    // One record past the record bound (its depends list is 2 MiB).
    let mut big = upstream_record("noarch", "huge-1.0-0.tar.bz2");
    big["depends"] = serde_json::Value::Array(
        (0..200_000)
            .map(|i| format!("dep{i} >=1"))
            .map(Into::into)
            .collect(),
    );
    let huge = serde_json::to_vec(&serde_json::json!({
        "packages": {"huge-1.0-0.tar.bz2": big},
    }))
    .unwrap();
    assert!(huge.len() > 2 * 1024 * 1024);
    let err = for_each_record_capped(huge.as_slice(), u64::MAX / 2, 1024 * 1024, |_, _, _| Ok(()))
        .unwrap_err();
    assert!(err.contains("record exceeds"), "{err}");
    // The default bounds admit a real-sized document.
    assert_eq!(
        for_each_record(bytes.as_slice(), |_, _, _| Ok(())).unwrap(),
        2
    );
    // One name past the per-name bound.
    let (parts, _) = spill_document(huge.into(), None, RepodataEncoding::Json).unwrap();
    let mut refused = 0;
    for p in &parts.paths {
        match shards_of_partition_capped(p, 1024 * 1024) {
            Ok(_) => {}
            Err(SynthError::Upstream(e)) => {
                assert!(e.contains("one package name"), "{e}");
                refused += 1;
            }
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(refused, 1);
}

/// #4178: a temporary directory that cannot hold the spill files (here not
/// a directory at all, as for a read-only or missing `TMPDIR`) is a local
/// failure, not an upstream one, and leaves nothing behind.
#[test]
fn an_unusable_temporary_directory_is_a_local_failure_4178() {
    let doc = repodata("noarch", &["a-1.0-0.tar.bz2"], &[]);
    let not_a_dir = tempfile::NamedTempFile::new().unwrap();
    match spill_document_in(
        not_a_dir.path(),
        serde_json::to_vec(&doc).unwrap().into(),
        None,
        RepodataEncoding::Json,
    ) {
        Err(SynthError::Local(e)) => assert!(e.contains("spill directory"), "{e}"),
        Err(e) => panic!("expected a local failure, got {e}"),
        Ok(_) => panic!("spilled into a file"),
    }
    // The partitions of a successful spill are removed with their handle.
    let parent = tempfile::tempdir().unwrap();
    let (parts, _) = spill_document_in(
        parent.path(),
        serde_json::to_vec(&doc).unwrap().into(),
        None,
        RepodataEncoding::Json,
    )
    .unwrap();
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 1);
    drop(parts);
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

/// #4178 acceptance: a remote whose upstream has no shard index serves a
/// shard index and shards built from the upstream `repodata.json.bz2`, the
/// shards hash to their addresses, and a second request within the cache
/// TTL does not read the upstream document again.
#[tokio::test]
async fn remote_without_upstream_shards_serves_synthesised_ones_4178() {
    let Some(pool) = tdh::try_pool().await else {
        return;
    };
    let server = MockServer::start().await;
    let doc = repodata(
        "noarch",
        &["syn-a-1.0-0.tar.bz2", "syn-b-1.0-0.tar.bz2"],
        &["syn-a-2.0-0.conda"],
    );
    mount(&server, "/noarch/repodata.json.bz2", bz2(&doc)).await;
    let (state, _cache) = state_with_proxy_cache(&pool);
    let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;
    let get = |uri: String| {
        let app = tdh::router_anon(super::router(), state.clone());
        async move { tdh::send_with_headers(app, tdh::get(uri)).await }
    };

    let (status, body, _) = get(format!("/{repo_key}/noarch/repodata_shards.msgpack.zst")).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let index = decode_index(&body);
    assert_eq!(index.info.subdir, "noarch");
    assert_eq!(index.info.shards_base_url, "./shards/");
    assert_eq!(names(&index), ["syn-a", "syn-b"]);
    for (name, hash) in &index.shards {
        let (status, shard, headers) = get(format!(
            "/{repo_key}/noarch/shards/{}.msgpack.zst",
            hex::encode(hash)
        ))
        .await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert_eq!(shard_address(&shard).as_slice(), hash.as_slice());
        assert_eq!(
            headers.get("cache-control").unwrap(),
            "public, max-age=31536000, immutable"
        );
        let shard = decode_shard(&shard);
        let records = shard.packages.len() + shard.conda_packages.len();
        assert_eq!(records, if name == "syn-a" { 2 } else { 1 });
    }
    let origins: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT origin FROM conda_shard_index WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(origins, ["synthesized"]);

    let (status, again, _) = get(format!("/{repo_key}/noarch/repodata_shards.msgpack.zst")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again, body);
    assert_eq!(hits(&server, "/noarch/repodata.json.bz2").await, 1);

    // A stored row whose bytes no longer hash to its address is refused (#4829).
    let hash = &index.shards["syn-a"];
    sqlx::query(
        "UPDATE conda_shard_index SET shard = $3 \
          WHERE repository_id = $1 AND subdir = 'noarch' AND package_name = $2",
    )
    .bind(repo_id)
    .bind("syn-a")
    .bind(b"not the shard".to_vec())
    .execute(&pool)
    .await
    .unwrap();
    let (status, _, _) = get(format!(
        "/{repo_key}/noarch/shards/{}.msgpack.zst",
        hex::encode(hash)
    ))
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    cleanup_conda_repo(&pool, repo_id).await;
}

/// #4178: a package added upstream appears after the refresh, a name the
/// upstream dropped leaves the index, and a refresh that finds the same
/// document changes nothing.
#[tokio::test]
async fn a_changed_upstream_index_is_resynthesised_on_refresh_4178() {
    let Some(pool) = tdh::try_pool().await else {
        return;
    };
    let server = MockServer::start().await;
    let first = repodata("noarch", &[], &["chg-a-1.0-0.conda", "chg-b-1.0-0.conda"]);
    mount(
        &server,
        "/noarch/repodata.json.zst",
        zstd::encode_all(serde_json::to_vec(&first).unwrap().as_slice(), 3).unwrap(),
    )
    .await;
    let (state, _cache) = state_with_proxy_cache(&pool);
    let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;
    // Every request revalidates the cached upstream document.
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, 'cache_ttl_secs', '0')",
    )
    .bind(repo_id)
    .execute(&pool)
    .await
    .unwrap();
    let index = || {
        let app = tdh::router_anon(super::router(), state.clone());
        let uri = format!("/{repo_key}/noarch/repodata_shards.msgpack.zst");
        async move {
            let (status, body) = tdh::send(app, tdh::get(uri)).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            decode_index(&body)
        }
    };
    let state_row = || async {
        sqlx::query_as::<
            _,
            (
                chrono::DateTime<chrono::Utc>,
                Option<chrono::DateTime<chrono::Utc>>,
            ),
        >(
            "SELECT built_at, stale_since FROM conda_synthesized_subdirs \
              WHERE repository_id = $1 AND subdir = 'noarch'",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .unwrap()
    };

    let before = index().await;
    assert_eq!(names(&before), ["chg-a", "chg-b"]);
    let (built, stale) = state_row().await;
    assert!(stale.is_none());

    // Same document again: nothing rebuilt.
    let same = index().await;
    assert_eq!(same.shards, before.shards);
    assert_eq!(state_row().await.0, built);

    server.reset().await;
    let second = repodata("noarch", &[], &["chg-a-1.0-0.conda", "chg-c-1.0-0.conda"]);
    mount(
        &server,
        "/noarch/repodata.json.zst",
        zstd::encode_all(serde_json::to_vec(&second).unwrap().as_slice(), 3).unwrap(),
    )
    .await;
    let after = index().await;
    assert_eq!(names(&after), ["chg-a", "chg-c"]);
    assert_eq!(
        after.shards["chg-a"], before.shards["chg-a"],
        "unchanged shard, same address"
    );
    let (rebuilt, stale) = state_row().await;
    assert!(rebuilt > built && stale.is_none());
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conda_shard_index WHERE repository_id = $1 AND subdir = 'noarch'",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 2, "the dropped name's shard is gone");
    cleanup_conda_repo(&pool, repo_id).await;
}

/// Peak memory of a synthesis of a real upstream document, without the
/// database: `AK_SYNTH_BENCH_FILE=<repodata.json.zst> cargo test ...
/// synthesis_peak_memory -- --ignored --nocapture`. Prints the record and
/// name counts, the elapsed time and the process's peak RSS (VmHWM) before
/// and after.
#[test]
#[ignore]
fn synthesis_peak_memory() {
    fn hwm() -> String {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find(|l| l.starts_with("VmHWM"))
            .unwrap_or("VmHWM: ?")
            .to_string()
    }
    let path = std::env::var("AK_SYNTH_BENCH_FILE").expect("AK_SYNTH_BENCH_FILE");
    let source = if path.ends_with(".zst") {
        RepodataEncoding::Zst
    } else if path.ends_with(".bz2") {
        RepodataEncoding::Bz2
    } else {
        RepodataEncoding::Json
    };
    let bytes = std::fs::read(&path).unwrap();
    println!("input {} bytes compressed; before: {}", bytes.len(), hwm());
    let started = std::time::Instant::now();
    let (parts, records) = spill_document(bytes.into(), None, source).unwrap();
    let spilled = started.elapsed();
    let mut names = 0usize;
    let mut shard_bytes = 0usize;
    for p in &parts.paths {
        let shards = shards_of_partition(p).unwrap();
        names += shards.len();
        shard_bytes += shards.iter().map(|s| s.1.len()).sum::<usize>();
    }
    println!(
        "records {records}, names {names}, shard bytes {shard_bytes}, spill {:?}, total {:?}; after: {}",
        spilled,
        started.elapsed(),
        hwm()
    );
    let _ = shard_synth::PARTITIONS;
}

/// #4929: an upstream that answers 403 for every optional document it does
/// not publish (an S3 bucket without list permission: the shard index, the
/// `.zst` and the `.bz2`) and serves only the plain `repodata.json` still gets
/// a synthesised shard index, built from that plain document, instead of a
/// 502 on the index.
#[tokio::test]
async fn an_upstream_refusing_optional_documents_is_synthesised_from_plain_json_4929() {
    let Some(pool) = tdh::try_pool().await else {
        return;
    };
    let server = MockServer::start().await;
    for path in [
        "/noarch/repodata_shards.msgpack.zst",
        "/noarch/repodata.json.zst",
        "/noarch/repodata.json.bz2",
    ] {
        Mock::given(method("GET"))
            .and(wm_path(path))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
    }
    let doc = repodata("noarch", &["s3-a-1.0-0.tar.bz2"], &["s3-b-1.0-0.conda"]);
    mount(
        &server,
        "/noarch/repodata.json",
        serde_json::to_vec(&doc).unwrap(),
    )
    .await;
    let (state, _cache) = state_with_proxy_cache(&pool);
    let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;
    let app = tdh::router_anon(super::router(), state.clone());
    let (status, body, _) = tdh::send_with_headers(
        app,
        tdh::get(format!("/{repo_key}/noarch/repodata_shards.msgpack.zst")),
    )
    .await;
    let plain_hits = hits(&server, "/noarch/repodata.json").await;
    cleanup_conda_repo(&pool, repo_id).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a 403 on optional documents means they are absent: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(names(&decode_index(&body)), ["s3-a", "s3-b"]);
    assert_eq!(plain_hits, 1, "the plain document is the synthesis source");
}
