//! Index/metadata parity between the single-request generic upload and each
//! format's native publish (#5254).
//!
//! `PUT /api/v1/repositories/{repo}/artifacts/{path}` runs the format-native
//! finalize for a package at its native layout path in Alpine, Debian, Maven,
//! npm, PyPI, RPM and Incus repositories. For each of those formats these
//! tests publish the same package bytes at the same path into two
//! repositories -- one through the format's native route, one through the
//! generic PUT -- and assert the two agree on:
//!
//! * the package identity on the `artifacts` row (name, version, content type),
//! * the `artifact_metadata` (format, document) pair,
//! * the package catalog entry, and
//! * the index output a format client resolves the package through
//!   (`APKINDEX`, `Packages`, `maven-metadata.xml`, the npm packument, the PyPI
//!   simple index, `primary.xml`, `images.json`).
//!
//! Plus the edges of that parity: a package the native route refuses is
//! refused (400, nothing stored), an unreadable `.apk` is stored unindexed as
//! the native route stores it, and a file that is not a package keeps the
//! positional generic coordinates with no format document.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! AK_TESTS_REQUIRE_DB=1 \
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo nextest run --run-ignored ignored-only --test generic_put_format_parity_tests
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)] // test file: buffering response bodies in assertions is not an artifact path (#1608)

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine as _;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::{
    alpine, debian, incus, maven, npm, pypi, repositories, rpm,
};
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::models::access_scope::AccessScope;

/// A real `.apk` built by `abuild -F` (pkgname `dtf-marker`, pkgver `1.0-r0`,
/// arch `aarch64`).
const MARKER_APK: &[u8] = include_bytes!("fixtures/dtf-marker-1.0-r0.apk");
const MARKER_APK_PATH: &str = "v3.24/main/aarch64/dtf-marker-1.0-r0.apk";

/// Real minimal noarch RPM built with rpmbuild (Summary/License/URL set).
const TEST_RPM: &[u8] = include_bytes!("fixtures/ak-meta-test-1.0-1.noarch.rpm");
const TEST_RPM_FILENAME: &str = "ak-meta-test-1.0-1.noarch.rpm";
const TEST_RPM_SUMMARY: &str = "Artifact Keeper metadata test package";
const TEST_RPM_SOURCE_RPM: &str = "ak-meta-test-1.0-1.src.rpm";

/// Stands in for a repository key in index output, so two repositories'
/// indexes compare equal when they differ only in the key they are served
/// under.
const KEY_PLACEHOLDER: &str = "{repo}";

// ===========================================================================
// Harness
// ===========================================================================

/// A user, a shared app state, and the repositories a test created.
struct Ctx {
    pool: PgPool,
    state: SharedState,
    auth: AuthExtension,
    user_id: Uuid,
    root: PathBuf,
    repos: Vec<Uuid>,
}

/// One repository created by [`Ctx::repo`].
struct Repo {
    id: Uuid,
    key: String,
}

/// The package identity columns of an `artifacts` row.
#[derive(Debug, PartialEq, Eq)]
struct Row {
    name: String,
    version: Option<String>,
    content_type: String,
}

impl Ctx {
    /// Connect and create an admin user. `None` when no database is
    /// configured and none is required; PANICS when `AK_TESTS_REQUIRE_DB` is
    /// set and the database is missing or unreachable (no silent skip, #2924).
    async fn setup() -> Option<Self> {
        let pool = artifact_keeper_backend::testing::try_pool_with(5).await?;
        let user_id = Uuid::new_v4();
        let username = format!("gp5254-{}", &user_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
             VALUES ($1, $2, $3, NULL, 'local', true, true)",
        )
        .bind(user_id)
        .bind(&username)
        .bind(format!("{username}@test.local"))
        .execute(&pool)
        .await
        .expect("insert admin user");
        let root = std::env::temp_dir().join(format!("gp5254-{user_id}"));
        std::fs::create_dir_all(&root).expect("create storage root");
        let state = build_state(pool.clone(), root.to_str().unwrap());
        let auth = AuthExtension {
            user_id,
            username: username.clone(),
            email: format!("{username}@test.local"),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        Some(Self {
            pool,
            state,
            auth,
            user_id,
            root,
            repos: Vec::new(),
        })
    }

    /// Create a hosted (`local`) repository of `format`.
    async fn repo(&mut self, format: &str, label: &str) -> Repo {
        let id = Uuid::new_v4();
        let key = format!("gp5254-{format}-{label}-{}", &id.to_string()[..8]);
        let storage_path = self.root.join(&key);
        std::fs::create_dir_all(&storage_path).expect("create repo storage dir");
        let sql = format!(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', '{format}'::repository_format, true)"
        );
        sqlx::query(sqlx::AssertSqlSafe(&*sql))
            .bind(id)
            .bind(&key)
            .bind(&*storage_path.to_string_lossy())
            .execute(&self.pool)
            .await
            .expect("insert repository");
        self.repos.push(id);
        Repo { id, key }
    }

    /// `router` with the shared state and the admin principal, injected both
    /// ways the production auth middleware injects it.
    fn app(&self, router: Router<SharedState>) -> Router {
        router
            .with_state(self.state.clone())
            .layer(axum::Extension(self.auth.clone()))
            .layer(axum::Extension(Some(self.auth.clone())))
    }

    async fn send(&self, router: Router<SharedState>, req: Request<Body>) -> (StatusCode, Bytes) {
        let resp = self.app(router).oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024 * 1024)
            .await
            .unwrap();
        (status, body)
    }

    async fn get(&self, router: Router<SharedState>, uri: String) -> (StatusCode, Bytes) {
        self.send(
            router,
            Request::builder().uri(uri).body(Body::empty()).unwrap(),
        )
        .await
    }

    /// `PUT` raw `body` to `uri` on `router` (a native upload route).
    async fn put(
        &self,
        router: Router<SharedState>,
        uri: String,
        body: &[u8],
    ) -> (StatusCode, Bytes) {
        self.send(
            router,
            Request::builder()
                .method("PUT")
                .uri(uri)
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
    }

    /// The generic single-request upload,
    /// `PUT /api/v1/repositories/{repo}/artifacts/{path}`, with no declared
    /// content type unless `content_type` is given.
    async fn generic_put(
        &self,
        repo: &Repo,
        path: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> (StatusCode, Bytes) {
        let mut req = Request::builder()
            .method("PUT")
            .uri(format!("/{}/artifacts/{path}", repo.key));
        if let Some(content_type) = content_type {
            req = req.header("content-type", content_type);
        }
        self.send(
            repositories::router(),
            req.body(Body::from(body.to_vec())).unwrap(),
        )
        .await
    }

    async fn row(&self, repo: &Repo, path: &str) -> Row {
        let (name, version, content_type): (String, Option<String>, String) = sqlx::query_as(
            "SELECT name, version, content_type FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(repo.id)
        .bind(path)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|e| panic!("artifact row at {path} in {}: {e}", repo.key));
        Row {
            name,
            version,
            content_type,
        }
    }

    /// The `artifact_metadata` (format, document) pair at `path`, if any.
    async fn metadata(&self, repo: &Repo, path: &str) -> Option<(String, serde_json::Value)> {
        sqlx::query_as(
            "SELECT am.format, am.metadata FROM artifact_metadata am \
             JOIN artifacts a ON a.id = am.artifact_id \
             WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false",
        )
        .bind(repo.id)
        .bind(path)
        .fetch_optional(&self.pool)
        .await
        .expect("artifact_metadata lookup")
    }

    async fn artifact_count(&self, repo: &Repo) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
            .bind(repo.id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// The catalog versions registered for package `name`.
    async fn catalog_versions(&self, repo: &Repo, name: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT pv.version FROM packages p JOIN package_versions pv ON pv.package_id = p.id \
             WHERE p.repository_id = $1 AND p.name = $2 ORDER BY pv.version",
        )
        .bind(repo.id)
        .bind(name)
        .fetch_all(&self.pool)
        .await
        .expect("catalog lookup")
    }

    /// Assert the two repositories hold the same package identity and
    /// format document at `path`; returns the generic side's row and document.
    async fn assert_row_and_metadata_parity(
        &self,
        native: &Repo,
        generic: &Repo,
        path: &str,
    ) -> (Row, (String, serde_json::Value)) {
        let native_row = self.row(native, path).await;
        let generic_row = self.row(generic, path).await;
        assert_eq!(
            generic_row, native_row,
            "artifacts row identity at {path}: generic PUT vs native publish"
        );
        let native_doc = self
            .metadata(native, path)
            .await
            .unwrap_or_else(|| panic!("native publish recorded no artifact_metadata at {path}"));
        let generic_doc = self
            .metadata(generic, path)
            .await
            .unwrap_or_else(|| panic!("generic PUT recorded no artifact_metadata at {path}"));
        assert_eq!(
            generic_doc, native_doc,
            "artifact_metadata (format, document) at {path}: generic PUT vs native publish"
        );
        (generic_row, generic_doc)
    }

    async fn teardown(self) {
        for id in &self.repos {
            for q in [
                "DELETE FROM upload_sessions WHERE repository_id = $1",
                "DELETE FROM incus_upload_sessions WHERE repository_id = $1",
                "DELETE FROM package_versions WHERE package_id IN \
                 (SELECT id FROM packages WHERE repository_id = $1)",
                "DELETE FROM packages WHERE repository_id = $1",
                "DELETE FROM artifact_metadata WHERE artifact_id IN \
                 (SELECT id FROM artifacts WHERE repository_id = $1)",
                "DELETE FROM artifacts WHERE repository_id = $1",
                "DELETE FROM role_assignments WHERE repository_id = $1",
                "DELETE FROM repositories WHERE id = $1",
            ] {
                sqlx::query(sqlx::AssertSqlSafe(q))
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .ok();
            }
        }
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(self.user_id)
            .execute(&self.pool)
            .await
            .ok();
        std::fs::remove_dir_all(&self.root).ok();
    }
}

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let config = Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        setup_password_hint: None,
        ..Default::default()
    };
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(
        artifact_keeper_backend::storage::StorageRegistry::new(
            HashMap::new(),
            "filesystem".to_string(),
        )
        .with_filesystem_bucket_root(storage_path),
    );
    Arc::new(AppState::new(config, pool, storage, registry))
}

fn assert_success(what: &str, (status, body): &(StatusCode, Bytes)) {
    assert!(
        status.is_success(),
        "{what}: {status} {}",
        String::from_utf8_lossy(body)
    );
}

fn assert_created(what: &str, (status, body): &(StatusCode, Bytes)) {
    assert_eq!(
        *status,
        StatusCode::CREATED,
        "{what}: {}",
        String::from_utf8_lossy(body)
    );
}

fn text(body: &Bytes) -> String {
    String::from_utf8(body.to_vec()).expect("UTF-8 index body")
}

/// `text` with `key` replaced by [`KEY_PLACEHOLDER`].
fn without_key(text: &str, key: &str) -> String {
    text.replace(key, KEY_PLACEHOLDER)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(data))
}

// ===========================================================================
// Package builders
// ===========================================================================

fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for (path, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *body).unwrap();
        }
        builder.finish().unwrap();
    }
    gz.flush().unwrap();
    gz.finish().unwrap()
}

fn append_ar_member(out: &mut Vec<u8>, name: &str, content: &[u8]) {
    let header = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        name,
        0,
        0,
        0,
        "100644",
        content.len()
    );
    assert_eq!(header.len(), 60, "ar header must be exactly 60 bytes");
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(content);
    if content.len() % 2 == 1 {
        out.push(b'\n');
    }
}

/// A minimal binary `.deb` whose control file declares `Depends`.
fn minimal_deb(package: &str, version: &str, architecture: &str, description: &str) -> Vec<u8> {
    let control = format!(
        "Package: {package}\n\
         Version: {version}\n\
         Architecture: {architecture}\n\
         Maintainer: Test Maintainer <test@example.local>\n\
         Installed-Size: 7\n\
         Depends: libc6 (>= 2.36)\n\
         Section: utils\n\
         Priority: optional\n\
         Homepage: https://example.local/{package}\n\
         Description: {description}\n \
         extended description line\n"
    );
    let mut deb = Vec::new();
    deb.extend_from_slice(b"!<arch>\n");
    append_ar_member(&mut deb, "debian-binary", b"2.0\n");
    append_ar_member(
        &mut deb,
        "control.tar.gz",
        &tar_gz(&[("./control", control.as_bytes())]),
    );
    append_ar_member(&mut deb, "data.tar.gz", &tar_gz(&[]));
    deb
}

/// The `package.json` [`npm_tgz`] packs.
fn npm_package_json(name: &str, version: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "version": version,
        "description": "generic put parity package",
        "main": "index.js",
        "dependencies": { "left-pad": "^1.3.0" },
    })
}

/// An `npm pack`-shaped tarball: `package/package.json` + `package/index.js`.
fn npm_tgz(name: &str, version: &str) -> Vec<u8> {
    let package_json = npm_package_json(name, version).to_string();
    tar_gz(&[
        ("package/package.json", package_json.as_bytes()),
        ("package/index.js", b"module.exports = 1;\n"),
    ])
}

/// A wheel carrying only its `.dist-info/METADATA`.
fn wheel(dist: &str, version: &str) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options: zip::write::FileOptions<'_, '_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file(format!("{dist}-{version}.dist-info/METADATA"), options)
            .unwrap();
        write!(
            zip,
            "Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n\
             Summary: generic put parity wheel\nRequires-Python: >=3.9\n"
        )
        .unwrap();
        zip.finish().unwrap();
    }
    cursor.into_inner()
}

/// The `multipart/form-data` body `twine upload` posts, with the fields the
/// native route reads (`:action`, `name`, `version`, `sha256_digest`,
/// `content`). Returns (content type, body).
fn twine_form(name: &str, version: &str, filename: &str, content: &[u8]) -> (String, Vec<u8>) {
    let boundary = "gp5254-twine-boundary";
    let sha256 = sha256_hex(content);
    let mut body = Vec::new();
    for (field, value) in [
        (":action", "file_upload"),
        ("name", name),
        ("version", version),
        ("sha256_digest", sha256.as_str()),
    ] {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"content\"; \
             filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

/// A unified Incus image tarball carrying only `metadata.yaml`.
fn incus_image() -> Vec<u8> {
    tar_gz(&[(
        "metadata.yaml",
        b"architecture: x86_64\ncreation_date: 1761955200\nproperties:\n  os: Debian\n  release: trixie\n  description: Debian trixie amd64\n",
    )])
}

// ===========================================================================
// Index readers
// ===========================================================================

/// The `APKINDEX` text inside an `APKINDEX.tar.gz` (signed or not).
fn apkindex_text(tar_gz: &[u8]) -> String {
    let mut archive = tar::Archive::new(flate2::read::MultiGzDecoder::new(tar_gz));
    for entry in archive.entries().expect("APKINDEX tar") {
        let mut entry = entry.expect("APKINDEX tar entry");
        if entry.path().unwrap().to_string_lossy() == "APKINDEX" {
            let mut text = String::new();
            entry.read_to_string(&mut text).unwrap();
            return text;
        }
    }
    panic!("APKINDEX.tar.gz has no APKINDEX entry");
}

fn gunzip(gz: &[u8]) -> String {
    let mut text = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut text)
        .unwrap();
    text
}

/// The `<package>` entry of a one-package `primary.xml`, with the `file=`
/// attribute of `<time>` (the row's last-modified time, which differs between
/// any two uploads) blanked.
fn primary_package_entry(primary: &str) -> String {
    let start = primary.find("<package ").expect("a <package> entry");
    let end = primary.rfind("</package>").expect("a </package> close") + "</package>".len();
    primary[start..end]
        .lines()
        .map(
            |line| match line.trim_start().strip_prefix("<time file=\"") {
                Some(rest) => {
                    let after = rest.split_once('"').map_or("", |(_, after)| after);
                    format!("<time file=\"*\"{after}")
                }
                None => line.to_string(),
            },
        )
        .collect::<Vec<_>>()
        .join("\n")
}

/// `html` with every PEP 700 `data-upload-time="..."` value replaced by `*`.
///
/// The simple index renders each file's upload time (the row's `created_at`)
/// at one-second precision, so two uploads that straddle a second boundary
/// render different pages for the same package (#5365). The time is when the
/// bytes arrived, not something the upload route derives from the package.
fn without_upload_time(html: &str) -> String {
    const ATTR: &str = "data-upload-time=\"";
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(at) = rest.find(ATTR) {
        let value_start = at + ATTR.len();
        out.push_str(&rest[..value_start]);
        out.push('*');
        let value_len = rest[value_start..]
            .find('"')
            .expect("a closed data-upload-time attribute");
        rest = &rest[value_start + value_len..];
    }
    out.push_str(rest);
    out
}

// ===========================================================================
// Alpine
// ===========================================================================

/// An `.apk` PUT through the generic endpoint at its
/// `{branch}/{repository}/{arch}/{file}` path matches the native Alpine
/// upload: row identity, `alpine` document, catalog entry and `APKINDEX`.
#[tokio::test]
#[ignore]
async fn generic_put_apk_matches_native_alpine_upload() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let native = ctx.repo("alpine", "nat").await;
    let generic = ctx.repo("alpine", "gen").await;

    let resp = ctx
        .put(
            alpine::router(),
            format!("/{}/{MARKER_APK_PATH}", native.key),
            MARKER_APK,
        )
        .await;
    assert_success("native Alpine PUT", &resp);
    let resp = ctx
        .generic_put(&generic, MARKER_APK_PATH, MARKER_APK, None)
        .await;
    assert_created("generic PUT of the .apk", &resp);

    let (row, (format, doc)) = ctx
        .assert_row_and_metadata_parity(&native, &generic, MARKER_APK_PATH)
        .await;
    assert_eq!(row.name, "dtf-marker");
    assert_eq!(row.version.as_deref(), Some("1.0-r0"));
    assert_eq!(format, "alpine");
    assert!(doc["apk_checksum"].is_string(), "{doc}");

    for repo in [&native, &generic] {
        assert_eq!(
            ctx.catalog_versions(repo, "dtf-marker").await,
            vec!["1.0-r0".to_string()],
            "catalog in {}",
            repo.key
        );
    }

    let mut indexes = Vec::new();
    for repo in [&native, &generic] {
        let (status, body) = ctx
            .get(
                alpine::router(),
                format!("/{}/v3.24/main/aarch64/APKINDEX.tar.gz", repo.key),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "APKINDEX in {}", repo.key);
        indexes.push(without_key(&apkindex_text(&body), &repo.key));
    }
    let (native_index, generic_index) = (&indexes[0], &indexes[1]);
    assert!(generic_index.contains("P:dtf-marker\n"), "{generic_index}");
    assert!(generic_index.contains("V:1.0-r0\n"), "{generic_index}");
    assert!(generic_index.contains("A:aarch64\n"), "{generic_index}");
    assert_eq!(generic_index, native_index, "APKINDEX: generic vs native");

    ctx.teardown().await;
}

/// An `.apk` whose control segment cannot be read is stored, not refused,
/// with its file-name identity and no `apk_checksum`, so `APKINDEX` leaves it
/// out; the generic PUT and the native upload record it the same way.
#[tokio::test]
#[ignore]
async fn generic_put_unreadable_apk_is_stored_unindexed_like_native() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let native = ctx.repo("alpine", "nat").await;
    let generic = ctx.repo("alpine", "gen").await;
    let path = "edge/main/x86_64/broken-2.0-r1.apk";
    let bytes = b"not an apk at all";

    let resp = ctx
        .put(alpine::router(), format!("/{}/{path}", native.key), bytes)
        .await;
    assert_success("native Alpine PUT of an unreadable .apk", &resp);
    let resp = ctx.generic_put(&generic, path, bytes, None).await;
    assert_created("generic PUT of an unreadable .apk", &resp);

    let (row, (format, doc)) = ctx
        .assert_row_and_metadata_parity(&native, &generic, path)
        .await;
    assert_eq!(
        (row.name.as_str(), row.version.as_deref()),
        ("broken", Some("2.0-r1"))
    );
    assert_eq!(format, "alpine");
    assert_eq!(doc["name"], "broken");
    assert!(doc.get("apk_checksum").is_none(), "{doc}");

    for repo in [&native, &generic] {
        let (status, body) = ctx
            .get(
                alpine::router(),
                format!("/{}/edge/main/x86_64/APKINDEX.tar.gz", repo.key),
            )
            .await;
        if status == StatusCode::OK {
            let index = apkindex_text(&body);
            assert!(
                !index.contains("P:broken\n"),
                "an unreadable .apk must not be indexed in {}: {index}",
                repo.key
            );
        } else {
            assert_eq!(status, StatusCode::NOT_FOUND, "APKINDEX in {}", repo.key);
        }
    }

    ctx.teardown().await;
}

// ===========================================================================
// Debian
// ===========================================================================

/// A `.deb` PUT through the generic endpoint at its pool path matches the
/// native Debian upload: row identity, control document, catalog entry and
/// the `Packages` stanza (with `Depends`).
#[tokio::test]
#[ignore]
async fn generic_put_deb_matches_native_debian_upload() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let native = ctx.repo("debian", "nat").await;
    let generic = ctx.repo("debian", "gen").await;
    let (package, version, arch) = ("ak-parity-deb", "1.4.0-2", "amd64");
    let deb = minimal_deb(package, version, arch, "generic put parity deb");
    let path = format!("pool/main/a/{package}/{package}_{version}_{arch}.deb");

    let resp = ctx
        .put(debian::router(), format!("/{}/{path}", native.key), &deb)
        .await;
    assert_success("native Debian PUT", &resp);
    let resp = ctx.generic_put(&generic, &path, &deb, None).await;
    assert_created("generic PUT of the .deb", &resp);

    let (row, (format, _)) = ctx
        .assert_row_and_metadata_parity(&native, &generic, &path)
        .await;
    assert_eq!(
        (row.name.as_str(), row.version.as_deref()),
        (package, Some(version))
    );
    assert_eq!(format, "debian");
    for repo in [&native, &generic] {
        assert_eq!(
            ctx.catalog_versions(repo, package).await,
            vec![version.to_string()],
            "catalog in {}",
            repo.key
        );
    }

    let mut indexes = Vec::new();
    for repo in [&native, &generic] {
        let (status, body) = ctx
            .get(
                debian::router(),
                format!("/{}/dists/bookworm/main/binary-amd64/Packages", repo.key),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "Packages in {}", repo.key);
        indexes.push(without_key(&text(&body), &repo.key));
    }
    let (native_packages, generic_packages) = (&indexes[0], &indexes[1]);
    assert!(
        generic_packages.contains(&format!("Package: {package}\n")),
        "{generic_packages}"
    );
    assert!(
        generic_packages.contains(&format!("Version: {version}\n")),
        "{generic_packages}"
    );
    assert!(
        generic_packages.contains("Depends: libc6 (>= 2.36)\n"),
        "{generic_packages}"
    );
    assert_eq!(
        generic_packages, native_packages,
        "Packages: generic vs native"
    );

    ctx.teardown().await;
}

// ===========================================================================
// Maven
// ===========================================================================

/// A Maven jar and POM PUT through the generic endpoint match the native
/// Maven upload: row identity, `maven` documents, catalog entry and
/// `maven-metadata.xml` (generation time aside).
#[tokio::test]
#[ignore]
async fn generic_put_maven_jar_and_pom_match_native_maven_upload() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let native = ctx.repo("maven", "nat").await;
    let generic = ctx.repo("maven", "gen").await;
    let pom = br#"<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme.parity</groupId>
  <artifactId>demo</artifactId>
  <version>2.3.4</version>
  <description>generic put parity artifact</description>
</project>
"#;
    let base = "com/acme/parity/demo/2.3.4";
    let files = [
        (
            format!("{base}/demo-2.3.4.jar"),
            b"PK\x03\x04 jar body".to_vec(),
        ),
        (format!("{base}/demo-2.3.4.pom"), pom.to_vec()),
    ];
    for (path, bytes) in &files {
        let resp = ctx
            .put(maven::router(), format!("/{}/{path}", native.key), bytes)
            .await;
        assert_success(&format!("native Maven PUT of {path}"), &resp);
        let resp = ctx.generic_put(&generic, path, bytes, None).await;
        assert_created(&format!("generic PUT of {path}"), &resp);
    }
    for (path, _) in &files {
        let (row, (format, _)) = ctx
            .assert_row_and_metadata_parity(&native, &generic, path)
            .await;
        assert_eq!(
            (row.name.as_str(), row.version.as_deref()),
            ("demo", Some("2.3.4"))
        );
        assert_eq!(format, "maven");
    }
    for repo in [&native, &generic] {
        assert_eq!(
            ctx.catalog_versions(repo, "com.acme.parity:demo").await,
            vec!["2.3.4".to_string()],
            "catalog in {}",
            repo.key
        );
    }

    let mut indexes = Vec::new();
    for repo in [&native, &generic] {
        let (status, body) = ctx
            .get(
                maven::router(),
                format!("/{}/com/acme/parity/demo/maven-metadata.xml", repo.key),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "maven-metadata.xml in {}", repo.key);
        // `<lastUpdated>` is the generation time.
        let xml = text(&body)
            .lines()
            .filter(|line| !line.contains("<lastUpdated>"))
            .collect::<Vec<_>>()
            .join("\n");
        indexes.push(without_key(&xml, &repo.key));
    }
    let (native_xml, generic_xml) = (&indexes[0], &indexes[1]);
    assert!(
        generic_xml.contains("<groupId>com.acme.parity</groupId>"),
        "{generic_xml}"
    );
    assert!(
        generic_xml.contains("<artifactId>demo</artifactId>"),
        "{generic_xml}"
    );
    assert!(
        generic_xml.contains("<version>2.3.4</version>"),
        "{generic_xml}"
    );
    assert_eq!(
        generic_xml, native_xml,
        "maven-metadata.xml: generic vs native"
    );

    ctx.teardown().await;
}

// ===========================================================================
// npm
// ===========================================================================

/// An npm tarball PUT through the generic endpoint at
/// `{package}/{version}/{file}.tgz` matches the native `npm publish` of the
/// same tarball: row identity, `npm` document, catalog entry and the
/// packument's version document (dependencies included).
///
/// The publish manifest is the tarball's own `package.json`: the version
/// document a native publish records is the manifest the client sends, and
/// the generic PUT reads it from the tarball, so the two describe the package
/// the same way when the client sends the package's `package.json`.
#[tokio::test]
#[ignore]
async fn generic_put_npm_tarball_matches_native_npm_publish() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let native = ctx.repo("npm", "nat").await;
    let generic = ctx.repo("npm", "gen").await;
    let (package, version) = ("gp-parity-pkg", "1.2.0");
    let tarball = npm_tgz(package, version);
    let filename = format!("{package}-{version}.tgz");
    let path = format!("{package}/{version}/{filename}");

    let publish = serde_json::json!({
        "_id": package,
        "name": package,
        "dist-tags": { "latest": version },
        "versions": { version: npm_package_json(package, version) },
        "_attachments": {
            filename.clone(): {
                "content_type": "application/octet-stream",
                "data": base64::engine::general_purpose::STANDARD.encode(&tarball),
                "length": tarball.len(),
            }
        },
    });
    let resp = ctx
        .send(
            npm::router(),
            Request::builder()
                .method("PUT")
                .uri(format!("/{}/{package}", native.key))
                .header("content-type", "application/json")
                .body(Body::from(publish.to_string()))
                .unwrap(),
        )
        .await;
    assert_success("native npm publish", &resp);
    let resp = ctx.generic_put(&generic, &path, &tarball, None).await;
    assert_created("generic PUT of the npm tarball", &resp);

    let (row, (format, doc)) = ctx
        .assert_row_and_metadata_parity(&native, &generic, &path)
        .await;
    assert_eq!(
        (
            row.name.as_str(),
            row.version.as_deref(),
            row.content_type.as_str()
        ),
        (package, Some(version), "application/gzip")
    );
    assert_eq!(format, "npm");
    assert_eq!(
        doc["version_data"]["dependencies"]["left-pad"], "^1.3.0",
        "{doc}"
    );
    for repo in [&native, &generic] {
        assert_eq!(
            ctx.catalog_versions(repo, package).await,
            vec![version.to_string()],
            "catalog in {}",
            repo.key
        );
    }

    let mut documents = Vec::new();
    for repo in [&native, &generic] {
        let (status, body) = ctx
            .get(npm::router(), format!("/{}/{package}", repo.key))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "packument in {}: {}",
            repo.key,
            String::from_utf8_lossy(&body)
        );
        let packument: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let version_doc = packument["versions"][version].to_string();
        assert_ne!(
            version_doc, "null",
            "packument in {}: {packument}",
            repo.key
        );
        documents.push(without_key(&version_doc, &repo.key));
    }
    let (native_doc, generic_doc) = (&documents[0], &documents[1]);
    let generic_version: serde_json::Value = serde_json::from_str(generic_doc).unwrap();
    assert_eq!(
        generic_version["dependencies"]["left-pad"], "^1.3.0",
        "{generic_doc}"
    );
    assert_eq!(
        generic_doc, native_doc,
        "packument versions[{version}]: generic vs native"
    );

    ctx.teardown().await;
}

/// A tarball whose `package.json` names another package than its path is
/// refused (400) and nothing is stored.
#[tokio::test]
#[ignore]
async fn generic_put_npm_tarball_naming_another_package_is_refused() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let repo = ctx.repo("npm", "gen").await;
    let (status, body) = ctx
        .generic_put(
            &repo,
            "gp-parity-pkg/1.2.0/gp-parity-pkg-1.2.0.tgz",
            &npm_tgz("other-pkg", "1.2.0"),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(ctx.artifact_count(&repo).await, 0, "nothing is stored");
    assert!(
        ctx.catalog_versions(&repo, "gp-parity-pkg")
            .await
            .is_empty(),
        "no catalog entry"
    );
    ctx.teardown().await;
}

// ===========================================================================
// PyPI
// ===========================================================================

/// A wheel PUT through the generic endpoint at
/// `{project}/{version}/{file}` matches the native twine upload of the same
/// wheel: row identity, `pypi` document, catalog entry and the simple index
/// (file link and `data-requires-python`; upload time aside).
///
/// The upload form carries the fields the native route reads; extra twine
/// form fields are recorded by the native route as `upload_metadata`, which
/// a request without a form cannot carry.
#[tokio::test]
#[ignore]
async fn generic_put_wheel_matches_native_pypi_upload() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let native = ctx.repo("pypi", "nat").await;
    let generic = ctx.repo("pypi", "gen").await;
    let (dist, version) = ("gp_parity_dist", "0.9.0");
    let file = format!("{dist}-{version}-py3-none-any.whl");
    let path = format!("gp-parity-dist/{version}/{file}");
    let wheel = wheel(dist, version);

    let (content_type, form) = twine_form(dist, version, &file, &wheel);
    let resp = ctx
        .send(
            pypi::router(),
            Request::builder()
                .method("POST")
                .uri(format!("/{}/", native.key))
                .header("content-type", content_type)
                .body(Body::from(form))
                .unwrap(),
        )
        .await;
    assert_success("native PyPI upload", &resp);
    let resp = ctx.generic_put(&generic, &path, &wheel, None).await;
    assert_created("generic PUT of the wheel", &resp);

    let (row, (format, doc)) = ctx
        .assert_row_and_metadata_parity(&native, &generic, &path)
        .await;
    assert_eq!(
        (row.name.as_str(), row.version.as_deref()),
        ("gp-parity-dist", Some(version))
    );
    assert_eq!(format, "pypi");
    assert_eq!(doc["pkg_info"]["requires_python"], ">=3.9", "{doc}");
    for repo in [&native, &generic] {
        assert_eq!(
            ctx.catalog_versions(repo, "gp-parity-dist").await,
            vec![version.to_string()],
            "catalog in {}",
            repo.key
        );
    }

    let mut indexes = Vec::new();
    for repo in [&native, &generic] {
        let (status, body) = ctx
            .get(
                pypi::router(),
                format!("/{}/simple/gp-parity-dist/", repo.key),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "simple index in {}", repo.key);
        let html = text(&body);
        assert!(html.contains("data-upload-time=\""), "{html}");
        indexes.push(without_key(&without_upload_time(&html), &repo.key));
    }
    let (native_html, generic_html) = (&indexes[0], &indexes[1]);
    assert!(generic_html.contains(&file), "{generic_html}");
    assert!(
        generic_html.contains(&format!("#sha256={}", sha256_hex(&wheel))),
        "{generic_html}"
    );
    assert!(
        generic_html.contains("data-requires-python=\"&gt;=3.9\""),
        "{generic_html}"
    );
    assert_eq!(generic_html, native_html, "simple index: generic vs native");

    ctx.teardown().await;
}

// ===========================================================================
// RPM
// ===========================================================================

/// An RPM PUT through the generic endpoint at `packages/{file}` matches the
/// native RPM PUT: row identity, header-derived `rpm` document, catalog
/// entry and the `primary.xml` package entry (upload time aside).
#[tokio::test]
#[ignore]
async fn generic_put_rpm_matches_native_rpm_upload() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let native = ctx.repo("rpm", "nat").await;
    let generic = ctx.repo("rpm", "gen").await;
    let path = format!("packages/{TEST_RPM_FILENAME}");

    let resp = ctx
        .put(
            rpm::router(),
            format!("/{}/packages/{TEST_RPM_FILENAME}", native.key),
            TEST_RPM,
        )
        .await;
    assert_success("native RPM PUT", &resp);
    let resp = ctx.generic_put(&generic, &path, TEST_RPM, None).await;
    assert_created("generic PUT of the .rpm", &resp);

    let (row, (format, doc)) = ctx
        .assert_row_and_metadata_parity(&native, &generic, &path)
        .await;
    assert_eq!(
        (row.name.as_str(), row.version.as_deref()),
        ("ak-meta-test", Some("1.0-1"))
    );
    assert_eq!(format, "rpm");
    assert_eq!(doc["summary"], TEST_RPM_SUMMARY, "{doc}");
    assert_eq!(doc["source_rpm"], TEST_RPM_SOURCE_RPM, "{doc}");
    for repo in [&native, &generic] {
        assert_eq!(
            ctx.catalog_versions(repo, "ak-meta-test").await,
            vec!["1.0-1".to_string()],
            "catalog in {}",
            repo.key
        );
    }

    let mut entries = Vec::new();
    for repo in [&native, &generic] {
        let (status, body) = ctx
            .get(
                rpm::router(),
                format!("/{}/repodata/primary.xml.gz", repo.key),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "primary.xml.gz in {}", repo.key);
        entries.push(without_key(
            &primary_package_entry(&gunzip(&body)),
            &repo.key,
        ));
    }
    let (native_entry, generic_entry) = (&entries[0], &entries[1]);
    assert!(
        generic_entry.contains("<name>ak-meta-test</name>"),
        "{generic_entry}"
    );
    assert!(
        generic_entry.contains(&format!("<summary>{TEST_RPM_SUMMARY}</summary>")),
        "{generic_entry}"
    );
    assert!(
        generic_entry.contains(&format!(
            "<rpm:sourcerpm>{TEST_RPM_SOURCE_RPM}</rpm:sourcerpm>"
        )),
        "{generic_entry}"
    );
    assert!(
        generic_entry.contains(&format!("<location href=\"{path}\"/>")),
        "{generic_entry}"
    );
    assert_eq!(
        generic_entry, native_entry,
        "primary.xml package entry: generic vs native"
    );

    ctx.teardown().await;
}

// ===========================================================================
// Incus
// ===========================================================================

/// Wait for the native Incus upload session `session_id` (finalized in the
/// background after the 202) to complete.
async fn await_incus_session(ctx: &Ctx, session_id: Uuid) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let (status, error): (String, Option<String>) = sqlx::query_as(
            "SELECT status, finalize_error FROM incus_upload_sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_one(&ctx.pool)
        .await
        .expect("incus upload session");
        match status.as_str() {
            "completed" => return,
            "failed" => panic!("native Incus upload failed: {error:?}"),
            _ => {}
        }
        assert!(
            std::time::Instant::now() < deadline,
            "native Incus upload still {status} after 60s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// An Incus image PUT through the generic endpoint at
/// `{product}/{version}/{file}` matches the native Incus image PUT: row
/// identity, `incus` document and the `images.json` product.
#[tokio::test]
#[ignore]
async fn generic_put_incus_image_matches_native_incus_upload() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let native = ctx.repo("incus", "nat").await;
    let generic = ctx.repo("incus", "gen").await;
    let (product, version, file) = ("debian-trixie", "20261101", "incus.tar.gz");
    let path = format!("{product}/{version}/{file}");
    let image = incus_image();

    let (status, body) = ctx
        .put(
            incus::router(),
            format!("/{}/images/{path}", native.key),
            &image,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "native Incus PUT: {}",
        String::from_utf8_lossy(&body)
    );
    let accepted: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = Uuid::parse_str(accepted["session_id"].as_str().unwrap()).unwrap();
    await_incus_session(&ctx, session_id).await;
    let resp = ctx.generic_put(&generic, &path, &image, None).await;
    assert_created("generic PUT of the Incus image", &resp);

    let (row, (format, _)) = ctx
        .assert_row_and_metadata_parity(&native, &generic, &path)
        .await;
    assert_eq!(
        (row.name.as_str(), row.version.as_deref()),
        (product, Some(version))
    );
    assert_eq!(format, "incus");

    let mut products = Vec::new();
    for repo in [&native, &generic] {
        let (status, body) = ctx
            .get(
                incus::router(),
                format!("/{}/streams/v1/images.json", repo.key),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "images.json in {}", repo.key);
        let catalog: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entry = without_key(&catalog["products"][product].to_string(), &repo.key);
        products.push(serde_json::from_str::<serde_json::Value>(&entry).unwrap());
    }
    let (native_product, generic_product) = (&products[0], &products[1]);
    assert_eq!(generic_product["os"], "Debian", "{generic_product}");
    assert_eq!(generic_product["release"], "trixie", "{generic_product}");
    assert_eq!(generic_product["arch"], "x86_64", "{generic_product}");
    assert!(
        generic_product["versions"][version]["items"]
            .as_object()
            .is_some_and(|items| !items.is_empty()),
        "{generic_product}"
    );
    assert_eq!(
        generic_product, native_product,
        "images.json product {product}: generic vs native"
    );

    ctx.teardown().await;
}

// ===========================================================================
// Non-package files
// ===========================================================================

/// A file that is not a package at its format's layout path keeps the
/// generic behaviour: positional coordinates (first segment, second segment),
/// the declared content type, no format document, never refused.
#[tokio::test]
#[ignore]
async fn generic_put_of_a_non_package_file_keeps_generic_coordinates() {
    let Some(mut ctx) = Ctx::setup().await else {
        return;
    };
    let path = "docs/1.0/readme.txt";
    for format in ["debian", "alpine", "rpm"] {
        let repo = ctx.repo(format, "txt").await;
        let resp = ctx
            .generic_put(&repo, path, b"plain text", Some("text/plain"))
            .await;
        assert_created(&format!("generic PUT of {path} into {format}"), &resp);
        assert_eq!(
            ctx.row(&repo, path).await,
            Row {
                name: "docs".to_string(),
                version: Some("1.0".to_string()),
                content_type: "text/plain".to_string(),
            },
            "{format}"
        );
        assert!(
            ctx.metadata(&repo, path).await.is_none(),
            "{format}: a non-package file records no format document"
        );
    }
    ctx.teardown().await;
}
