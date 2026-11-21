//! Integration target: the DB-backed Homebrew bottle path (#5985).
//!
//! The in-crate tests cover the pure pieces (filename grammar, bottle
//! verification, formula rendering). These drive the production composition
//! (`homebrew::router()` nested at `/homebrew` under
//! `repo_visibility_middleware`) against a real database and filesystem
//! storage, so they pin what only the wired handler does:
//!
//! * an upload stores the bytes, writes one `artifacts` row under the
//!   canonical single-dash filename and records the bottle metadata the
//!   formula renderer reads;
//! * the stored bottle downloads byte-for-byte and appears in both formula
//!   JSON endpoints with its `sha256` and `cellar`;
//! * a re-upload of the same bottle in either spelling is a 409, and every
//!   refused upload (no credentials, contents that do not match the filename,
//!   a bad `cellar`, a Remote or virtual repository) leaves no row behind;
//! * a delete drops the bottle from the download route and the formula JSON,
//!   and frees its filename for a new upload.
//!
//! DB-gated: run under `--run-ignored ignored-only` with `DATABASE_URL` and
//! `AK_TESTS_REQUIRE_DB=1`.

#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)

mod common;

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use common::conda_support as cs;

const PASSWORD: &str = "homebrew-test-pass";

/// One test's database rows, storage dir and router.
struct Fixture {
    pool: PgPool,
    app: Router,
    repo_id: Uuid,
    repo_key: String,
    storage: PathBuf,
    user_id: Uuid,
    auth: String,
}

impl Fixture {
    /// An admin user and a homebrew repository of `repo_type`.
    async fn new(repo_type: &str) -> Self {
        let pool = cs::require_pool().await;
        let username = cs::unique_name("brew-admin");
        let user_id = cs::create_user(&pool, &username, PASSWORD, true).await;
        let (repo_id, repo_key, storage) =
            cs::create_repo(&pool, "brew", "local", "homebrew", false).await;
        if repo_type != "local" {
            // `check_upstream_url` requires an upstream on a Remote row.
            sqlx::query(
                "UPDATE repositories SET repo_type = $2::repository_type, \
                 upstream_url = CASE WHEN $2 = 'remote' THEN 'https://ghcr.io/v2/homebrew/core' END \
                 WHERE id = $1",
            )
            .bind(repo_id)
            .bind(repo_type)
            .execute(&pool)
            .await
            .expect("set repository type");
        }
        let state = cs::build_state(pool.clone(), &storage.to_string_lossy());
        let app = cs::format_full_stack(
            state,
            "/homebrew",
            artifact_keeper_backend::api::handlers::homebrew::router(),
        );
        Self {
            pool,
            app,
            repo_id,
            repo_key,
            storage,
            user_id,
            auth: cs::basic_auth(&username, PASSWORD),
        }
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, body)
    }

    /// `PUT /homebrew/{repo}/bottles/{filename}{query}` with `auth` (or none).
    async fn put(
        &self,
        filename: &str,
        query: &str,
        body: Vec<u8>,
        auth: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/homebrew/{}/bottles/{}{}",
                self.repo_key, filename, query
            ))
            .header("Content-Type", "application/octet-stream");
        if let Some(auth) = auth {
            req = req.header("Authorization", auth);
        }
        self.send(req.body(Body::from(body)).unwrap()).await
    }

    /// An authenticated request with no body to `/homebrew/{repo}/{rest}`.
    async fn call(&self, method: &str, rest: &str) -> (StatusCode, Vec<u8>) {
        let req = Request::builder()
            .method(method)
            .uri(format!("/homebrew/{}/{}", self.repo_key, rest))
            .header("Host", "ak.test")
            .header("Authorization", &self.auth)
            .body(Body::empty())
            .unwrap();
        self.send(req).await
    }

    async fn json(&self, rest: &str) -> (StatusCode, Value) {
        let (status, body) = self.call("GET", rest).await;
        let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, value)
    }

    /// Live (`is_deleted = false`) artifact rows in the repository.
    async fn live_rows(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
        )
        .bind(self.repo_id)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn teardown(self) {
        cs::cleanup_repo(&self.pool, self.repo_id).await;
        cs::cleanup_user(&self.pool, self.user_id).await;
        cs::cleanup_storage(&self.storage);
    }
}

/// A gzip tar that holds `{name}/{version}/INSTALL_RECEIPT.json` and one
/// payload file, the layout `brew bottle` produces.
fn bottle_archive(name: &str, version: &str) -> Vec<u8> {
    let entries: [(String, &[u8]); 2] = [
        (
            format!("{name}/{version}/INSTALL_RECEIPT.json"),
            br#"{"built_as_bottle":true,"poured_from_bottle":false}"#,
        ),
        (
            format!("{name}/{version}/bin/{name}"),
            b"#!/bin/sh\necho ok\n",
        ),
    ];
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, data) in &entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
    gz.finish().unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[tokio::test]
#[ignore = "requires PostgreSQL (DATABASE_URL)"]
async fn upload_stores_the_bottle_and_serves_it_back() {
    let fx = Fixture::new("local").await;
    let archive = bottle_archive("jq", "1.7.1");
    let sha = sha256_hex(&archive);

    // The `brew bottle` spelling, with an explicit cellar.
    let (status, body) = fx
        .put(
            "jq--1.7.1.arm64_sonoma.bottle.tar.gz",
            "?cellar=/opt/homebrew/Cellar",
            archive.clone(),
            Some(&fx.auth),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let created: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(created["filename"], "jq-1.7.1.arm64_sonoma.bottle.tar.gz");
    assert_eq!(created["sha256"], sha);
    assert_eq!(created["rebuild"], 0);

    // One row under the canonical path, owned by the uploader.
    let (path, name, version, checksum, size, uploaded_by, storage_key): (
        String,
        String,
        String,
        String,
        i64,
        Option<Uuid>,
        String,
    ) = sqlx::query_as(
        "SELECT path, name, version, checksum_sha256, size_bytes, uploaded_by, storage_key \
         FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
    )
    .bind(fx.repo_id)
    .fetch_one(&fx.pool)
    .await
    .expect("exactly one live artifact row");
    assert_eq!(path, "jq/1.7.1/jq-1.7.1.arm64_sonoma.bottle.tar.gz");
    assert_eq!((name.as_str(), version.as_str()), ("jq", "1.7.1"));
    assert_eq!(checksum, sha);
    assert_eq!(size, archive.len() as i64);
    assert_eq!(uploaded_by, Some(fx.user_id));
    assert!(!storage_key.is_empty());

    // The metadata the formula renderer reads.
    let metadata: Value = sqlx::query_scalar(
        "SELECT am.metadata FROM artifact_metadata am \
         JOIN artifacts a ON a.id = am.artifact_id WHERE a.repository_id = $1",
    )
    .bind(fx.repo_id)
    .fetch_one(&fx.pool)
    .await
    .expect("artifact_metadata row");
    assert_eq!(metadata["tag"], "arm64_sonoma");
    assert_eq!(metadata["cellar"], "/opt/homebrew/Cellar");
    assert_eq!(metadata["rebuild"], 0);

    // Download in either spelling returns the uploaded bytes.
    for filename in [
        "jq-1.7.1.arm64_sonoma.bottle.tar.gz",
        "jq--1.7.1.arm64_sonoma.bottle.tar.gz",
    ] {
        let (status, bytes) = fx.call("GET", &format!("bottles/{filename}")).await;
        assert_eq!(status, StatusCode::OK, "GET {filename}");
        assert_eq!(bytes, archive, "GET {filename} returns the stored bottle");
    }

    // Both formula endpoints advertise it.
    let (status, formula) = fx.json("api/formula/jq.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(formula["versions"]["stable"], "1.7.1");
    let file = &formula["bottle"]["stable"]["files"]["arm64_sonoma"];
    assert_eq!(file["sha256"], sha);
    assert_eq!(file["cellar"], "/opt/homebrew/Cellar");
    assert_eq!(
        file["url"],
        format!(
            "http://ak.test/homebrew/{}/bottles/jq-1.7.1.arm64_sonoma.bottle.tar.gz",
            fx.repo_key
        )
    );

    let (status, index) = fx.json("api/formula.json").await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = index
        .as_array()
        .expect("formula.json is an array")
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert_eq!(names, ["jq"]);

    fx.teardown().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL (DATABASE_URL)"]
async fn reupload_in_either_spelling_is_a_conflict() {
    let fx = Fixture::new("local").await;

    let (status, _) = fx
        .put(
            "jq-1.7.1.all.bottle.tar.gz",
            "",
            bottle_archive("jq", "1.7.1"),
            Some(&fx.auth),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    for filename in ["jq-1.7.1.all.bottle.tar.gz", "jq--1.7.1.all.bottle.tar.gz"] {
        let (status, _) = fx
            .put(filename, "", bottle_archive("jq", "1.7.1"), Some(&fx.auth))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "re-upload as {filename}");
    }
    assert_eq!(fx.live_rows().await, 1);

    // A rebuild is a new filename and is accepted.
    let (status, _) = fx
        .put(
            "jq-1.7.1.all.bottle.1.tar.gz",
            "",
            bottle_archive("jq", "1.7.1"),
            Some(&fx.auth),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, formula) = fx.json("api/formula/jq.json").await;
    assert_eq!(formula["bottle"]["stable"]["rebuild"], 1);

    fx.teardown().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL (DATABASE_URL)"]
async fn refused_uploads_store_nothing() {
    let fx = Fixture::new("local").await;
    let filename = "jq-1.7.1.all.bottle.tar.gz";

    // No credentials.
    let (status, _) = fx
        .put(filename, "", bottle_archive("jq", "1.7.1"), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "anonymous upload");

    // Contents for another version than the filename names.
    let (status, _) = fx
        .put(filename, "", bottle_archive("jq", "1.7.2"), Some(&fx.auth))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "mismatched contents");

    // Not a gzip tar at all.
    let (status, _) = fx
        .put(filename, "", b"not a bottle".to_vec(), Some(&fx.auth))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "garbage body");

    // Empty body.
    let (status, _) = fx.put(filename, "", Vec::new(), Some(&fx.auth)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "empty body");

    // A cellar that is neither a placeholder nor an absolute path.
    let (status, _) = fx
        .put(
            filename,
            "?cellar=relative/Cellar",
            bottle_archive("jq", "1.7.1"),
            Some(&fx.auth),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "bad cellar");

    // A filename that is not a bottle.
    let (status, _) = fx
        .put(
            "jq-1.7.1.zip",
            "",
            bottle_archive("jq", "1.7.1"),
            Some(&fx.auth),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "bad filename");

    assert_eq!(fx.live_rows().await, 0);
    let (status, _) = fx.json("api/formula/jq.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    fx.teardown().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL (DATABASE_URL)"]
async fn upload_to_a_remote_or_virtual_repository_is_not_implemented() {
    for repo_type in ["remote", "virtual"] {
        let fx = Fixture::new(repo_type).await;

        let (status, _) = fx
            .put(
                "jq-1.7.1.all.bottle.tar.gz",
                "",
                bottle_archive("jq", "1.7.1"),
                Some(&fx.auth),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{repo_type} upload");
        assert_eq!(fx.live_rows().await, 0, "{repo_type}");

        fx.teardown().await;
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL (DATABASE_URL)"]
async fn formula_serves_the_newest_version_only() {
    let fx = Fixture::new("local").await;

    for version in ["1.7.0", "1.7.1"] {
        let (status, _) = fx
            .put(
                &format!("jq-{version}.all.bottle.tar.gz"),
                "",
                bottle_archive("jq", version),
                Some(&fx.auth),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "upload {version}");
        // The renderer orders versions by upload time at second precision.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }

    let (status, formula) = fx.json("api/formula/jq.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(formula["versions"]["stable"], "1.7.1");
    assert!(formula["bottle"]["stable"]["files"]["all"]["url"]
        .as_str()
        .unwrap()
        .ends_with("/jq-1.7.1.all.bottle.tar.gz"));

    // The older bottle is still downloadable by name.
    let (status, _) = fx.call("GET", "bottles/jq-1.7.0.all.bottle.tar.gz").await;
    assert_eq!(status, StatusCode::OK);

    fx.teardown().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL (DATABASE_URL)"]
async fn delete_removes_the_bottle_and_frees_the_filename() {
    let fx = Fixture::new("local").await;
    let filename = "jq-1.7.1.all.bottle.tar.gz";

    let (status, _) = fx
        .put(filename, "", bottle_archive("jq", "1.7.1"), Some(&fx.auth))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = fx.call("DELETE", &format!("bottles/{filename}")).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(fx.live_rows().await, 0);

    let (status, _) = fx.call("GET", &format!("bottles/{filename}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "download after delete");
    let (status, _) = fx.json("api/formula/jq.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "formula after delete");
    let (status, _) = fx.call("DELETE", &format!("bottles/{filename}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "second delete");

    // The same filename can be published again.
    let (status, _) = fx
        .put(filename, "", bottle_archive("jq", "1.7.1"), Some(&fx.auth))
        .await;
    assert_eq!(status, StatusCode::CREATED, "re-upload after delete");
    assert_eq!(fx.live_rows().await, 1);

    fx.teardown().await;
}
