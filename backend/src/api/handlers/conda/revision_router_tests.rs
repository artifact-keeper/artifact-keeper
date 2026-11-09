//! Router-level tests of the hosted read path at scale (#4173, #4174). They
//! use only the router, SQL and the metrics recorder, so they also run
//! against a build without the shard store (where they fail).

use crate::api::handlers::test_db_helpers as tdh;
use crate::crypto::digest::Sha256;
use axum::http::StatusCode;

/// A minimal `.tar.bz2` conda package carrying only `info/index.json`.
pub(super) fn conda_package(name: &str, version: &str, build: &str, subdir: &str) -> Vec<u8> {
    let index = serde_json::json!({
        "name": name,
        "version": version,
        "build": build,
        "build_number": 0,
        "depends": ["python >=3.10"],
        "license": "MIT",
        "subdir": subdir,
    });
    let index_bytes = serde_json::to_vec(&index).unwrap();
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        let mut header = tar::Header::new_gnu();
        header.set_path("info/index.json").unwrap();
        header.set_size(index_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &index_bytes[..]).unwrap();
        builder.finish().unwrap();
    }
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    std::io::Write::write_all(&mut enc, &tar_data).unwrap();
    enc.finish().unwrap()
}

pub(super) fn filename(name: &str, version: &str, build: &str) -> String {
    format!("{name}-{version}-{build}.tar.bz2")
}

pub(super) async fn upload(fx: &tdh::Fixture, subdir: &str, name: &str, version: &str) -> String {
    let file = filename(name, version, "h0_0");
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/{}/upload", fx.repo_key))
        .header("X-Conda-Subdir", subdir)
        .header("X-Package-Filename", &file)
        .body(axum::body::Body::from(conda_package(
            name, version, "h0_0", subdir,
        )))
        .unwrap();
    let (status, body) = tdh::send(fx.router_with_auth(super::router()), req).await;
    assert!(
        status.is_success(),
        "upload of {file} failed: {status} {}",
        String::from_utf8_lossy(&body)
    );
    file
}

pub(super) async fn get(
    fx: &tdh::Fixture,
    suffix: &str,
) -> (StatusCode, bytes::Bytes, axum::http::HeaderMap) {
    tdh::send_with_headers(
        fx.router_with_auth(super::router()),
        tdh::get(format!("/{}/{suffix}", fx.repo_key)),
    )
    .await
}

/// Counter values of `name` with the given labels, from a snapshot.
fn counter(
    snapshotter: &metrics_util::debugging::Snapshotter,
    name: &str,
    labels: &[(&str, &str)],
) -> u64 {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let metrics_util::debugging::DebugValue::Counter(n) = value else {
                return None;
            };
            let key = key.key();
            (key.name() == name
                && labels
                    .iter()
                    .all(|(k, v)| key.labels().any(|l| l.key() == *k && l.value() == *v)))
            .then_some(n)
        })
        .sum()
}

/// #4174 acceptance: after one upload, a burst of 24 concurrent cold
/// `repodata.json.zst` requests regenerates the subdir exactly once and all
/// 24 carry one ETag; a warm request after it regenerates nothing.
#[tokio::test]
async fn cold_zst_burst_after_an_upload_regenerates_once_4174() {
    let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
        return;
    };
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);

    upload(&fx, "noarch", "burst-a", "1.0").await;
    upload(&fx, "noarch", "burst-b", "1.0").await;
    // Drop what the uploads recorded.
    let _ = snapshotter.snapshot();

    let requests = (0..24).map(|_| get(&fx, "noarch/repodata.json.zst"));
    let responses = futures::future::join_all(requests).await;
    let mut etags = std::collections::BTreeSet::new();
    for (status, body, headers) in &responses {
        assert_eq!(*status, StatusCode::OK);
        assert!(!body.is_empty());
        etags.insert(
            headers
                .get("etag")
                .expect("every response carries an ETag")
                .to_str()
                .unwrap()
                .to_string(),
        );
    }
    assert_eq!(etags.len(), 1, "one ETag for one revision: {etags:?}");
    let regenerations = counter(
        &snapshotter,
        "ak_repo_metadata_regenerations_total",
        &[("format", "conda"), ("scope", "subdir")],
    );
    assert_eq!(
        regenerations, 1,
        "24 cold requests of one revision must regenerate the subdir once"
    );

    let (status, _, _) = get(&fx, "noarch/repodata.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        counter(
            &snapshotter,
            "ak_repo_metadata_regenerations_total",
            &[("format", "conda"), ("scope", "subdir")],
        ),
        0,
        "the plain encoding of the same revision is kept, not rebuilt"
    );
}

/// #4173: a shard request is answered from the stored shard (a lookup by
/// address), not by rebuilding shards from the catalog. The stored row is
/// replaced with other well-formed bytes under their own address: only a
/// handler that reads the stored shard can serve that address. A stored
/// row whose bytes do not hash to its address is never served (#4829).
#[tokio::test]
async fn shard_request_is_served_from_the_stored_shard_4173() {
    let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
        return;
    };
    upload(&fx, "noarch", "stored-a", "1.0").await;
    let (status, _, _) = get(&fx, "noarch/repodata_shards.msgpack.zst").await;
    assert_eq!(status, StatusCode::OK);

    // Well-formed CEP-16 shard bytes that no catalog row produces.
    let crafted = zstd::encode_all(
        &rmp_serde::to_vec_named(&serde_json::json!({
            "packages": {},
            "packages.conda": {},
            "removed": ["crafted-marker-0-0.tar.bz2"],
        }))
        .unwrap()[..],
        3,
    )
    .unwrap();
    let address: Vec<u8> = Sha256::digest(&crafted).to_vec();
    let updated = sqlx::query(
        "UPDATE conda_shard_index SET shard = $3, shard_hash = $4 \
          WHERE repository_id = $1 AND subdir = 'noarch' AND package_name = $2",
    )
    .bind(fx.repo_id)
    .bind("stored-a")
    .bind(&crafted)
    .bind(&address)
    .execute(&fx.pool)
    .await
    .expect("conda_shard_index exists")
    .rows_affected();
    assert_eq!(updated, 1, "the upload stored the package's shard");

    let (status, body, headers) = get(
        &fx,
        &format!("noarch/shards/{}.msgpack.zst", hex::encode(&address)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the stored shard is served");
    assert_eq!(body.as_ref(), crafted.as_slice());
    assert_eq!(
        headers.get("cache-control").unwrap(),
        "public, max-age=31536000, immutable"
    );

    // Same address, bytes that do not hash to it: refused.
    sqlx::query(
        "UPDATE conda_shard_index SET shard = $3 \
          WHERE repository_id = $1 AND subdir = 'noarch' AND package_name = $2",
    )
    .bind(fx.repo_id)
    .bind("stored-a")
    .bind(b"not the shard".to_vec())
    .execute(&fx.pool)
    .await
    .unwrap();
    let (status, _, _) = get(
        &fx,
        &format!("noarch/shards/{}.msgpack.zst", hex::encode(&address)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
