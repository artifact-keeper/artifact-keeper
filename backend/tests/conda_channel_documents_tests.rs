//! Integration target: withdrawal exclusion across every repodata encoding,
//! and `notices.json` authorization (#4158, covering #4059/#4148).
//!
//! Withdrawing ONE package must remove it from every served repodata variant
//! — `repodata.json`, `current_repodata.json`, the bz2/zst encodings, JLAP,
//! CEP-16 shards, `run_exports.json` and `channeldata.json` — and gate its
//! direct download, while a CEP-6 notice explains the withdrawal. And because
//! a notice carries the operator's free-text reason plus the withdrawn
//! filenames, `notices.json` must answer exactly as its sibling channel
//! documents do for every principal — never as the one document that
//! discloses more than the rest of the channel.
//!
//! These drive the production composition (conda router under
//! `repo_visibility_middleware`) through the public API.
//!
//! DB-gated: run under `--run-ignored ignored-only` with `DATABASE_URL` and
//! `AK_TESTS_REQUIRE_DB=1`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::conda_support as cs;

const GOOD: &str = "good-1.0-0.tar.bz2";
const BAD: &str = "bad-2.0-0.tar.bz2";

/// Upload both fixture packages through the native PUT route.
async fn seed_pair(app: axum::Router, repo_key: &str, auth: &str) {
    for (filename, name, version) in [(GOOD, "good", "1.0"), (BAD, "bad", "2.0")] {
        let body = cs::conda_v1_package(name, version, "0");
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/conda/{}/noarch/{}", repo_key, filename))
            .header("Authorization", auth)
            .header("Content-Type", "application/octet-stream")
            .body(Body::from(body))
            .unwrap();
        let status = app.clone().oneshot(req).await.unwrap().status();
        assert!(status.is_success(), "seeding {filename} failed: {status}");
    }
}

/// GET a channel document, returning status and raw body bytes.
async fn get_doc(
    app: axum::Router,
    repo_key: &str,
    suffix: &str,
    auth: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/conda/{}/{}", repo_key, suffix));
    if let Some(auth) = auth {
        builder = builder.header("Authorization", auth);
    }
    let resp = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    (status, bytes.to_vec())
}

/// Withdraw `filename` with `reason` as an admin.
async fn withdraw(
    app: axum::Router,
    repo_key: &str,
    filename: &str,
    reason: &str,
    auth: &str,
) -> StatusCode {
    let body = serde_json::to_vec(&serde_json::json!({ "reason": reason })).unwrap();
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/conda/{}/noarch/{}", repo_key, filename))
        .header("Authorization", auth)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

/// The package filenames a repodata document lists.
fn package_names(repodata: &serde_json::Value) -> Vec<String> {
    let mut names: Vec<String> = repodata["packages"]
        .as_object()
        .into_iter()
        .chain(repodata["packages.conda"].as_object())
        .flat_map(|m| m.keys().cloned())
        .collect();
    names.sort();
    names
}

/// BLAKE2b-256 hex of `data` — the JLAP `latest` hash algorithm.
fn blake2b256_hex(data: &[u8]) -> String {
    use blake2::digest::consts::U32;
    use blake2::digest::{FixedOutput, Update};
    use blake2::Blake2b;
    let mut hasher = Blake2b::<U32>::default();
    Update::update(&mut hasher, data);
    let result = hasher.finalize_fixed();
    hex::encode(result)
}

/// The acceptance test: publish two packages, withdraw one, and EVERY
/// repodata encoding serves the survivor only — while the withdrawn row
/// stays quarantine-gated (409) and the CEP-6 notice names the reason.
#[tokio::test]
#[ignore]
async fn withdrawn_package_disappears_from_every_repodata_encoding() {
    let pool = cs::require_pool().await;
    let admin_name = cs::unique_name("conda-wd-admin");
    let admin_id = cs::create_user(&pool, &admin_name, "wdpass", true).await;
    let (repo_id, repo_key, storage_path) =
        cs::create_repo(&pool, "conda-withdraw", "local", "conda", true).await;
    let state = cs::build_state(pool.clone(), &storage_path.to_string_lossy());
    let auth = cs::basic_auth(&admin_name, "wdpass");
    let app = cs::conda_full_stack(state);

    seed_pair(app.clone(), &repo_key, &auth).await;

    // Sanity: both packages are listed before withdrawal.
    let (status, body) = get_doc(app.clone(), &repo_key, "noarch/repodata.json", Some(&auth)).await;
    assert_eq!(status, StatusCode::OK);
    let repodata: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(package_names(&repodata), vec![BAD, GOOD]);

    // Capture the pre-withdrawal CEP-16 shard hash for "bad": after
    // withdrawal this content-addressed URL must stop serving.
    let (status, idx_body) = get_doc(
        app.clone(),
        &repo_key,
        "noarch/repodata_shards.msgpack.zst",
        Some(&auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let idx_msgpack = zstd::decode_all(std::io::Cursor::new(&idx_body[..])).unwrap();
    let pre_index: serde_json::Value = rmp_serde::from_slice(&idx_msgpack).unwrap();
    let bad_shard_hash = pre_index["shards"]["bad"]
        .as_str()
        .expect("pre-withdrawal shard index must list bad")
        .to_string();

    let status = withdraw(
        app.clone(),
        &repo_key,
        BAD,
        "malicious upload reported by vendor",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "withdrawal must succeed");

    // --- Every repodata variant serves the surviving package only ---------

    let (status, repodata_body) =
        get_doc(app.clone(), &repo_key, "noarch/repodata.json", Some(&auth)).await;
    assert_eq!(status, StatusCode::OK);
    let repodata: serde_json::Value = serde_json::from_slice(&repodata_body).unwrap();
    assert_eq!(
        package_names(&repodata),
        vec![GOOD],
        "repodata.json must list only the surviving package"
    );
    let removed: Vec<&str> = repodata["removed"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        removed.contains(&BAD),
        "the withdrawn package must be named in repodata's removed array"
    );

    let (status, body) = get_doc(
        app.clone(),
        &repo_key,
        "noarch/current_repodata.json",
        Some(&auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let current: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        package_names(&current),
        vec![GOOD],
        "current_repodata.json is stale"
    );

    let (status, body) = get_doc(
        app.clone(),
        &repo_key,
        "noarch/repodata.json.zst",
        Some(&auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let zst: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(std::io::Cursor::new(&body[..])).unwrap())
            .unwrap();
    assert_eq!(
        package_names(&zst),
        vec![GOOD],
        "repodata.json.zst is stale"
    );

    let (status, body) = get_doc(
        app.clone(),
        &repo_key,
        "noarch/repodata.json.bz2",
        Some(&auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bz2: serde_json::Value = {
        use std::io::Read;
        let mut out = Vec::new();
        bzip2::read::BzDecoder::new(&body[..])
            .read_to_end(&mut out)
            .unwrap();
        serde_json::from_slice(&out).unwrap()
    };
    assert_eq!(
        package_names(&bz2),
        vec![GOOD],
        "repodata.json.bz2 is stale"
    );

    let (status, body) = get_doc(
        app.clone(),
        &repo_key,
        "noarch/run_exports.json",
        Some(&auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let run_exports: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let re_packages: Vec<&str> = run_exports["packages"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(
        re_packages,
        vec![GOOD],
        "run_exports must drop the withdrawn package"
    );

    let (status, body) = get_doc(app.clone(), &repo_key, "channeldata.json", Some(&auth)).await;
    assert_eq!(status, StatusCode::OK);
    let channeldata: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cd_packages: Vec<&str> = channeldata["packages"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(
        cd_packages,
        vec!["good"],
        "channeldata must drop the withdrawn package"
    );

    // JLAP: the advertised `latest` hash must be the hash of the repodata the
    // server serves NOW — a stale JLAP would keep the withdrawn package in
    // every client that trusts it.
    let (status, jlap_body) = get_doc(
        app.clone(),
        &repo_key,
        "noarch/repodata.json.jlap",
        Some(&auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let jlap_text = String::from_utf8(jlap_body).unwrap();
    let lines: Vec<&str> = jlap_text.lines().collect();
    let metadata: serde_json::Value = serde_json::from_str(lines[lines.len() - 2]).unwrap();
    assert_eq!(
        metadata["latest"].as_str().unwrap(),
        blake2b256_hex(&repodata_body),
        "JLAP must advertise the post-withdrawal repodata hash"
    );

    // CEP-16: the index must no longer name "bad", and its pre-withdrawal
    // content-addressed shard URL must 404.
    let (status, idx_body) = get_doc(
        app.clone(),
        &repo_key,
        "noarch/repodata_shards.msgpack.zst",
        Some(&auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let idx_msgpack = zstd::decode_all(std::io::Cursor::new(&idx_body[..])).unwrap();
    let post_index: serde_json::Value = rmp_serde::from_slice(&idx_msgpack).unwrap();
    let shard_names: Vec<&str> = post_index["shards"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(
        shard_names,
        vec!["good"],
        "the shard index must drop the withdrawn package"
    );
    let (stale_status, _) = get_doc(
        app.clone(),
        &repo_key,
        &format!("noarch/shards/{}.msgpack.zst", bad_shard_hash),
        Some(&auth),
    )
    .await;
    assert_eq!(
        stale_status,
        StatusCode::NOT_FOUND,
        "the pre-withdrawal shard URL must not keep serving the withdrawn package"
    );

    // Direct download is gated; the survivor is untouched.
    let (status, _) = get_doc(
        app.clone(),
        &repo_key,
        &format!("noarch/{}", BAD),
        Some(&auth),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the withdrawn package's direct download must be quarantine-gated"
    );
    let (status, _) = get_doc(
        app.clone(),
        &repo_key,
        &format!("noarch/{}", GOOD),
        Some(&auth),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the rest of the channel is untouched"
    );

    // The CEP-6 notice explains the withdrawal.
    let (status, body) = get_doc(app.clone(), &repo_key, "notices.json", Some(&auth)).await;
    assert_eq!(status, StatusCode::OK);
    let notices: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let text = notices.to_string();
    assert!(
        text.contains(BAD) && text.contains("malicious upload"),
        "a CEP-6 notice must explain the withdrawal: {text}"
    );

    cs::cleanup_repo(&pool, repo_id).await;
    cs::cleanup_user(&pool, admin_id).await;
    cs::cleanup_storage(&storage_path);
}

/// `notices.json` carries the withdrawal reason — free text an operator
/// writes for an embargoed advisory — and the withdrawn filenames. On a
/// PRIVATE channel neither may reach an anonymous caller, so the endpoint
/// must answer exactly as `channeldata.json` does for every principal.
#[tokio::test]
#[ignore]
async fn notices_json_authorization_matches_its_siblings() {
    const SECRET: &str = "embargoed-vendor-advisory-7f3a9c";
    let pool = cs::require_pool().await;
    let admin_name = cs::unique_name("conda-notice-admin");
    let admin_id = cs::create_user(&pool, &admin_name, "noticepass", true).await;
    let member_name = cs::unique_name("conda-notice-member");
    let member_id = cs::create_user(&pool, &member_name, "memberpass", false).await;
    let (repo_id, repo_key, storage_path) =
        cs::create_repo(&pool, "conda-notices", "local", "conda", false).await;
    cs::grant_developer_role(&pool, repo_id, member_id).await;
    let state = cs::build_state(pool.clone(), &storage_path.to_string_lossy());
    let admin_auth = cs::basic_auth(&admin_name, "noticepass");
    let member_auth = cs::basic_auth(&member_name, "memberpass");
    let app = cs::conda_full_stack(state);

    // A channel with content and a withdrawal notice carrying the secret.
    seed_pair(app.clone(), &repo_key, &admin_auth).await;
    let status = withdraw(app.clone(), &repo_key, BAD, SECRET, &admin_auth).await;
    assert_eq!(status, StatusCode::OK);

    // Anonymous: refused — and indistinguishable from channeldata.json, so
    // notices.json never becomes the one document that discloses more.
    let (n_status, n_body) = get_doc(app.clone(), &repo_key, "notices.json", None).await;
    let (c_status, c_body) = get_doc(app.clone(), &repo_key, "channeldata.json", None).await;
    assert_eq!(
        n_status,
        StatusCode::UNAUTHORIZED,
        "an anonymous caller must be refused notices.json on a private channel"
    );
    assert_eq!(
        n_status, c_status,
        "notices.json must answer as channeldata.json does"
    );
    assert_eq!(
        n_body, c_body,
        "the anonymous responses must not be distinguishable"
    );
    assert!(
        !String::from_utf8_lossy(&n_body).contains(SECRET),
        "the refusal must not leak the notice text"
    );

    // A repository member reads the notice, reason included.
    let (status, body) = get_doc(app.clone(), &repo_key, "notices.json", Some(&member_auth)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&body).contains(SECRET),
        "a member must see the withdrawal reason: {}",
        String::from_utf8_lossy(&body),
    );

    cs::cleanup_repo(&pool, repo_id).await;
    cs::cleanup_user(&pool, admin_id).await;
    cs::cleanup_user(&pool, member_id).await;
    cs::cleanup_storage(&storage_path);
}
