//! Native-publish fixtures for the MCP name-shadowing regression tests
//! (#5456).
//!
//! The MCP resolver tests must see exactly the `artifacts.name` / `version` /
//! `path` columns production stores, so packages are seeded through each
//! format's real publish route (npm `PUT` packument, PyPI twine multipart,
//! NuGet `PUT api/v2/package`, Cargo `PUT api/v1/crates/new`) rather than by
//! inserting pre-normalized rows. [`mock_upstream`] stands in for the upstream
//! of a Remote member so a Virtual download walk goes upstream for real.

#![allow(dead_code)]
// streaming-invariant: test scaffolding exempt — hashing buffered response
// bodies in fixture tests is not an artifact path (#1608).
#![allow(clippy::disallowed_methods)]

use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256, Sha512};
use uuid::Uuid;

use crate::api::handlers::test_db_helpers::{self as tdh, Fixture};
use crate::api::SharedState;

/// What [`publish_native`] stored.
pub(crate) struct PublishedPackage {
    /// The `artifacts` rows the publish created in the repository.
    pub artifact_ids: Vec<Uuid>,
    /// SHA-256 hex of the stored file (what the native download returns).
    pub sha256: String,
    /// Native download path after `/{repo_key}`, starting with `/`.
    pub download_tail: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("tar path");
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, *data).expect("tar entry");
    }
    builder
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (path, data) in entries {
        zip.start_file(*path, zip::write::SimpleFileOptions::default())
            .expect("zip entry");
        zip.write_all(data).expect("zip write");
    }
    zip.finish().expect("finish zip").into_inner()
}

/// npm tarball basename: the scope is stripped (`@acme/echo` -> `echo`).
fn npm_short_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// PyPI default sdist filename: `<name with - and . as _>-<version>.tar.gz`.
fn pypi_default_filename(name: &str, version: &str) -> String {
    format!("{}-{version}.tar.gz", name.replace(['-', '.'], "_"))
}

/// NuGet's normalized, lowercased version (what the V3 flat container and
/// every NuGet client address a package by).
fn nuget_version(version: &str) -> String {
    crate::formats::nuget::NugetHandler::normalized_version(version)
        .unwrap_or_else(|| version.to_ascii_lowercase())
}

/// The file a native client would publish for `name@version` and later get
/// back from a download, with `seed` embedded so two packages' bytes differ.
/// Returns `(bytes, filename)`.
pub(crate) fn native_file(
    format: &str,
    name: &str,
    version: &str,
    seed: &[u8],
    pypi_filename: Option<&str>,
) -> (Vec<u8>, String) {
    match format {
        "npm" => {
            let manifest = serde_json::json!({ "name": name, "version": version }).to_string();
            let bytes = tgz(&[
                ("package/package.json", manifest.as_bytes()),
                ("package/seed.bin", seed),
            ]);
            (bytes, format!("{}-{version}.tgz", npm_short_name(name)))
        }
        "pypi" => {
            let filename = pypi_filename
                .map(str::to_string)
                .unwrap_or_else(|| pypi_default_filename(name, version));
            let pkg_info = format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n");
            let bytes = if let Some(stem) = filename.strip_suffix(".tar.gz") {
                tgz(&[
                    (&format!("{stem}/PKG-INFO"), pkg_info.as_bytes()),
                    (&format!("{stem}/seed.bin"), seed),
                ])
            } else {
                // Wheel: `<dist>-<version>-...whl` carries `<dist>-<version>.dist-info`.
                let mut parts = filename.split('-');
                let dist_info = format!(
                    "{}-{}.dist-info",
                    parts.next().unwrap_or(name),
                    parts.next().unwrap_or(version)
                );
                zip_of(&[
                    (&format!("{dist_info}/METADATA"), pkg_info.as_bytes()),
                    ("seed.bin", seed),
                ])
            };
            (bytes, filename)
        }
        "nuget" => {
            let nuspec = format!(
                "<?xml version=\"1.0\"?>\n<package><metadata><id>{name}</id>\
                 <version>{version}</version><description>fixture</description>\
                 <authors>Fixture</authors></metadata></package>"
            );
            let bytes = zip_of(&[
                (&format!("{name}.nuspec"), nuspec.as_bytes()),
                ("content/seed.bin", seed),
            ]);
            let (id, ver) = (name.to_lowercase(), nuget_version(version));
            (bytes, format!("{id}.{ver}.nupkg"))
        }
        "cargo" => {
            let manifest = format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n");
            let root = format!("{name}-{version}");
            let bytes = tgz(&[
                (&format!("{root}/Cargo.toml"), manifest.as_bytes()),
                (&format!("{root}/seed.bin"), seed),
            ]);
            (bytes, format!("{root}.crate"))
        }
        other => panic!("mcp_shadow_fixtures: unsupported format {other}"),
    }
}

/// The native download path (after `/{repo_key}`) a client GETs for the file
/// [`native_file`] names. Repository-independent, so it addresses the same
/// file through a Local, Remote or Virtual repository.
pub(crate) fn download_tail(
    format: &str,
    name: &str,
    version: &str,
    pypi_filename: Option<&str>,
) -> String {
    match format {
        "npm" => format!("/{name}/-/{}-{version}.tgz", npm_short_name(name)),
        "pypi" => {
            let project = crate::formats::pypi_name::NormalizedProjectName::parse(name)
                .unwrap_or_else(|| panic!("{name:?} is not a PEP 508 project name"));
            let filename = pypi_filename
                .map(str::to_string)
                .unwrap_or_else(|| pypi_default_filename(name, version));
            format!("/simple/{}/{filename}", project.as_str())
        }
        "nuget" => {
            let (id, ver) = (name.to_lowercase(), nuget_version(version));
            format!("/v3/flatcontainer/{id}/{ver}/{id}.{ver}.nupkg")
        }
        "cargo" => format!("/api/v1/crates/{name}/{version}/download"),
        other => panic!("mcp_shadow_fixtures: unsupported format {other}"),
    }
}

/// The publish request a native client sends for `bytes`.
fn publish_request(
    format: &str,
    repo_key: &str,
    name: &str,
    version: &str,
    bytes: &[u8],
    filename: &str,
) -> Request<axum::body::Body> {
    match format {
        "npm" => {
            let body = serde_json::json!({
                "name": name,
                "versions": { version: { "name": name, "version": version } },
                "dist-tags": { "latest": version },
                "_attachments": { filename: {
                    "data": base64::engine::general_purpose::STANDARD.encode(bytes)
                } },
            });
            tdh::put_json(format!("/{repo_key}/{name}"), Bytes::from(body.to_string()))
        }
        "pypi" => {
            let boundary = "ak-mcp-shadow-fixture";
            let sha = sha256_hex(bytes);
            let mut body = Vec::new();
            for (field, value) in [
                (":action", "file_upload"),
                ("protocol_version", "1"),
                ("metadata_version", "2.1"),
                ("name", name),
                ("version", version),
                ("sha256_digest", sha.as_str()),
            ] {
                body.extend_from_slice(
                    format!(
                        "--{boundary}\r\nContent-Disposition: form-data; \
                         name=\"{field}\"\r\n\r\n{value}\r\n"
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
            body.extend_from_slice(bytes);
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            tdh::post(
                format!("/{repo_key}/"),
                &format!("multipart/form-data; boundary={boundary}"),
                Bytes::from(body),
            )
        }
        "nuget" => Request::builder()
            .method("PUT")
            .uri(format!("/{repo_key}/api/v2/package"))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(bytes.to_vec()))
            .expect("build nuget push"),
        "cargo" => {
            let meta = serde_json::to_vec(&serde_json::json!({
                "name": name, "vers": version, "deps": [], "features": {},
            }))
            .expect("cargo publish metadata");
            let mut body = Vec::new();
            body.extend_from_slice(&(meta.len() as u32).to_le_bytes());
            body.extend_from_slice(&meta);
            body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            body.extend_from_slice(bytes);
            tdh::put(format!("/{repo_key}/api/v1/crates/new"), Bytes::from(body))
        }
        other => panic!("mcp_shadow_fixtures: unsupported format {other}"),
    }
}

async fn live_artifact_ids(pool: &sqlx::PgPool, repo_id: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND is_deleted = false ORDER BY id",
    )
    .bind(repo_id)
    .fetch_all(pool)
    .await
    .expect("list artifacts")
}

/// Publish `name@version` (spelled as the client spells it) into Local
/// repository `repo_key` / `repo_id` through the format's real upload route,
/// as `fx.user_id` (granted `developer` on the repository here). `seed` makes
/// the file bytes distinct; `pypi_filename` picks the PyPI distribution file
/// (sdist `.tar.gz` or `.whl`; default `<name_underscored>-<version>.tar.gz`).
/// Panics unless the route answers 2xx and creates at least one row.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_native(
    fx: &Fixture,
    format: &str,
    repo_key: &str,
    repo_id: Uuid,
    name: &str,
    version: &str,
    seed: &[u8],
    pypi_filename: Option<&str>,
) -> PublishedPackage {
    tdh::grant_repo_role(&fx.pool, repo_id, fx.user_id, "developer").await;
    let (bytes, filename) = native_file(format, name, version, seed, pypi_filename);
    let before = live_artifact_ids(&fx.pool, repo_id).await;
    let request = publish_request(format, repo_key, name, version, &bytes, &filename);
    let (status, body) = tdh::send(native_router(fx, format), request).await;
    assert!(
        status.is_success(),
        "{format} publish of {name}@{version} into {repo_key}: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let artifact_ids: Vec<Uuid> = live_artifact_ids(&fx.pool, repo_id)
        .await
        .into_iter()
        .filter(|id| !before.contains(id))
        .collect();
    assert!(
        !artifact_ids.is_empty(),
        "{format} publish of {name}@{version} created no artifact row"
    );
    PublishedPackage {
        artifact_ids,
        sha256: sha256_hex(&bytes),
        download_tail: download_tail(format, name, version, pypi_filename),
    }
}

/// `(name, version, path)` as stored for `ids`, in `ids` order.
pub(crate) async fn artifact_columns(
    pool: &sqlx::PgPool,
    ids: &[Uuid],
) -> Vec<(String, Option<String>, String)> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(
            sqlx::query_as("SELECT name, version, path FROM artifacts WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .expect("read artifact columns"),
        );
    }
    out
}

fn format_router(format: &str) -> Router<SharedState> {
    match format {
        "npm" => super::npm::router(),
        "pypi" => super::pypi::router(),
        "nuget" => super::nuget::router(),
        "cargo" => super::cargo::router(),
        other => panic!("mcp_shadow_fixtures: unsupported format {other}"),
    }
}

/// The format's router (mounted without its `/npm`, `/pypi`... prefix) with
/// the fixture's state and user.
pub(crate) fn native_router(fx: &Fixture, format: &str) -> Router {
    fx.router_with_auth(format_router(format))
}

async fn get_sha(app: Router, uri: &str) -> (StatusCode, Option<String>) {
    let (status, body) = tdh::send(app, tdh::get(uri.to_string())).await;
    (
        status,
        (status == StatusCode::OK).then(|| sha256_hex(&body)),
    )
}

/// GET `uri` through [`native_router`]: the status, and the body's SHA-256
/// hex when the status is 200.
pub(crate) async fn native_get(
    fx: &Fixture,
    format: &str,
    uri: &str,
) -> (StatusCode, Option<String>) {
    get_sha(native_router(fx, format), uri).await
}

/// Like [`native_get`] but on `state` (e.g. [`MockUpstream::state`], which
/// carries a proxy service so a Remote or Virtual repository goes upstream).
pub(crate) async fn native_get_with_state(
    state: &SharedState,
    fx: &Fixture,
    format: &str,
    uri: &str,
) -> (StatusCode, Option<String>) {
    let auth = tdh::make_auth(fx.user_id, &fx.username);
    get_sha(
        tdh::router_with_auth(format_router(format), state.clone(), auth),
        uri,
    )
    .await
}

/// A wiremock upstream serving one package, plus a proxy-carrying state.
/// Keep it alive for as long as requests may go upstream: it also holds the
/// SSRF allowlist for the mock's address.
pub(crate) struct MockUpstream {
    pub server: wiremock::MockServer,
    /// State built with a filesystem-cached proxy service.
    pub state: SharedState,
    _ssrf: tdh::SsrfTestAllowlistGuard,
    _cache: tempfile::TempDir,
}

/// Answers every GET a format's Remote fetch makes for one package: the file
/// itself, plus whatever index document leads to it.
struct PackageResponder {
    format: String,
    name: String,
    version: String,
    filename: String,
    body: Vec<u8>,
    base: String,
}

impl PackageResponder {
    fn is_file(&self, path: &str) -> bool {
        match self.format.as_str() {
            "cargo" => path.ends_with("/download") || path.ends_with(".crate"),
            "nuget" => path.to_ascii_lowercase().ends_with(&self.filename),
            _ => path.ends_with(&format!("/{}", self.filename)),
        }
    }

    fn index(&self, path: &str) -> wiremock::ResponseTemplate {
        use wiremock::ResponseTemplate;
        let (name, version, base) = (&self.name, &self.version, &self.base);
        let sha256 = sha256_hex(&self.body);
        match self.format.as_str() {
            "npm" => {
                let integrity = format!(
                    "sha512-{}",
                    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&self.body))
                );
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": name,
                    "dist-tags": { "latest": version },
                    "versions": { version.as_str(): {
                        "name": name, "version": version,
                        "dist": {
                            "tarball": format!("{base}/{name}/-/{}", self.filename),
                            "integrity": integrity,
                        },
                    } },
                }))
            }
            "pypi" => ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(format!(
                    "<html><body><a href=\"{base}/files/{0}#sha256={sha256}\">{0}</a>\
                     </body></html>",
                    self.filename
                )),
            "nuget" if path.contains("flatcontainer") => ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "versions": [nuget_version(version)] })),
            "nuget" => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "version": "3.0.0",
                "resources": [
                    { "@id": format!("{base}/v3-flatcontainer/"), "@type": "PackageBaseAddress/3.0.0" },
                    { "@id": format!("{base}/v3/registration/"), "@type": "RegistrationsBaseUrl/3.6.0" },
                ],
            })),
            "cargo" if path.ends_with("/config.json") => ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "dl": format!("{base}/api/v1/crates"), "api": base })),
            "cargo" => ResponseTemplate::new(200).set_body_string(
                serde_json::json!({
                    "name": name, "vers": version, "deps": [], "cksum": sha256,
                    "features": {}, "yanked": false,
                })
                .to_string()
                    + "\n",
            ),
            _ => ResponseTemplate::new(404),
        }
    }
}

impl wiremock::Respond for PackageResponder {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let path = request.url.path();
        if self.is_file(path) {
            wiremock::ResponseTemplate::new(200)
                .insert_header("content-type", "application/octet-stream")
                .set_body_bytes(self.body.clone())
        } else {
            self.index(path)
        }
    }
}

/// Point Remote repository `remote_id` of `format` at a fresh wiremock
/// upstream that serves `name@version` with file bytes `body` (the file
/// [`native_file`] names, `pypi_filename` choosing PyPI's) at every path that
/// format's Remote fetch uses: npm packument + tarball, PyPI simple index +
/// file, NuGet service index + flat container, Cargo `config.json` + sparse
/// index + download. The Remote is made public so a Virtual containing it
/// resolves it for any caller.
pub(crate) async fn mock_upstream(
    fx: &Fixture,
    format: &str,
    remote_id: Uuid,
    name: &str,
    version: &str,
    body: &[u8],
    pypi_filename: Option<&str>,
) -> MockUpstream {
    let (server, ssrf) = tdh::non_loopback_mock_server().await;
    let (_, filename) = native_file(format, name, version, b"", pypi_filename);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(PackageResponder {
            format: format.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            filename,
            body: body.to_vec(),
            base: server.uri(),
        })
        .mount(&server)
        .await;
    sqlx::query("UPDATE repositories SET upstream_url = $1, is_public = true WHERE id = $2")
        .bind(server.uri())
        .bind(remote_id)
        .execute(&fx.pool)
        .await
        .expect("point remote at mock upstream");
    let cache = tempfile::tempdir().expect("proxy cache dir");
    let cache_path = cache.path().to_str().expect("utf-8 cache path");
    let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), cache_path);
    let state = tdh::build_state_with_proxy(fx.pool.clone(), cache_path, proxy);
    MockUpstream {
        server,
        state,
        _ssrf: ssrf,
        _cache: cache,
    }
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    /// Publish into the fixture's fresh Local repo, then GET the returned
    /// tail and require the same bytes back.
    async fn local_round_trip(
        format: &str,
        name: &str,
        version: &str,
        pypi_filename: Option<&str>,
    ) {
        let Some(fx) = Fixture::setup("local", format).await else {
            return;
        };
        let published = publish_native(
            &fx,
            format,
            &fx.repo_key,
            fx.repo_id,
            name,
            version,
            b"seed-a",
            pypi_filename,
        )
        .await;
        let columns = artifact_columns(&fx.pool, &published.artifact_ids).await;
        eprintln!(
            "mcp_shadow_fixtures {format} {name}@{version}: stored {columns:?}, tail {}",
            published.download_tail
        );
        let uri = format!("/{}{}", fx.repo_key, published.download_tail);
        let got = native_get(&fx, format, &uri).await;
        tdh::cleanup_member_repo(&fx.pool, fx.repo_id, &fx.storage_dir).await;
        fx.teardown().await;
        assert_eq!(
            got,
            (StatusCode::OK, Some(published.sha256)),
            "GET {uri} must return the published bytes"
        );
    }

    #[tokio::test]
    async fn npm_scoped_publish_round_trips_db() {
        local_round_trip("npm", "@acme/echo", "1.0.0", None).await;
    }

    #[tokio::test]
    async fn pypi_sdist_publish_round_trips_db() {
        local_round_trip("pypi", "Acme_Echo", "1.0", None).await;
    }

    #[tokio::test]
    async fn pypi_wheel_publish_round_trips_db() {
        local_round_trip(
            "pypi",
            "Acme_Echo",
            "1.0",
            Some("acme_echo-1.0-py3-none-any.whl"),
        )
        .await;
    }

    #[tokio::test]
    async fn nuget_publish_round_trips_db() {
        local_round_trip("nuget", "Acme.Echo", "1.0.0", None).await;
    }

    #[tokio::test]
    async fn cargo_publish_round_trips_db() {
        local_round_trip("cargo", "acme-echo", "1.0.0", None).await;
    }

    #[tokio::test]
    async fn cargo_mixed_case_underscore_round_trips_db() {
        local_round_trip("cargo", "Acme_Echo", "1.0.0", None).await;
    }

    /// A Virtual whose only member is a Remote on [`mock_upstream`] serves the
    /// mock's bytes at the same tail a Local publish answers on.
    async fn virtual_remote_round_trip(format: &str, name: &str, version: &str) {
        let Some(fx) = Fixture::setup("virtual", format).await else {
            return;
        };
        let (member_id, _key, member_dir) = tdh::attach_remote_member(
            &fx.pool,
            fx.repo_id,
            format,
            "https://upstream.example.test",
            1,
        )
        .await;
        let (body, _) = native_file(format, name, version, b"seed-upstream", None);
        let upstream = mock_upstream(&fx, format, member_id, name, version, &body, None).await;
        let uri = format!(
            "/{}{}",
            fx.repo_key,
            download_tail(format, name, version, None)
        );
        let got = native_get_with_state(&upstream.state, &fx, format, &uri).await;
        let hits: Vec<String> = upstream
            .server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        tdh::cleanup_member_repo(&fx.pool, member_id, &member_dir).await;
        fx.teardown().await;
        assert_eq!(
            got,
            (StatusCode::OK, Some(sha256_hex(&body))),
            "Virtual GET {uri} must return the upstream bytes; upstream saw {hits:?}"
        );
    }

    #[tokio::test]
    async fn npm_virtual_remote_serves_mock_bytes_db() {
        virtual_remote_round_trip("npm", "@acme/echo", "1.0.0").await;
    }

    #[tokio::test]
    async fn pypi_virtual_remote_serves_mock_bytes_db() {
        virtual_remote_round_trip("pypi", "Acme_Echo", "1.0").await;
    }

    #[tokio::test]
    async fn nuget_virtual_remote_serves_mock_bytes_db() {
        virtual_remote_round_trip("nuget", "Acme.Echo", "1.0.0").await;
    }

    #[tokio::test]
    async fn cargo_virtual_remote_serves_mock_bytes_db() {
        virtual_remote_round_trip("cargo", "acme-echo", "1.0.0").await;
    }
}
