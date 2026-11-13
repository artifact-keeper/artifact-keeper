//! The HTTP side of the quotas: admission before an upload body is read, the
//! transfer meter on downloads, and the format envelopes of a refusal.
//!
//! * [`upload_admission`] runs on the routers that receive artifact bytes
//!   (every native format, OCI `/v2`, the repository artifact API and the
//!   chunked upload API) after authentication and before the handler. It
//!   refuses, without reading the body, a write whose `Content-Length` is
//!   over `MAX_UPLOAD_SIZE` (413), any write while the instance is at its
//!   storage quota or one whose declared length would take it over (403),
//!   and one whose declared length does not fit its repository's (or
//!   project's) quota (403). A body without a length is admitted here and
//!   checked once its size is known by the shared publish admission.
//! * [`transfer_meter`] runs on the routers that serve artifact bytes. It
//!   counts the body bytes of every successful `GET` (and the object size of
//!   a presigned redirect when it is issued), and once the monthly transfer
//!   quota's hard limit is reached it answers `429` instead of an artifact
//!   download. Metadata responses (JSON, XML, HTML, text and YAML indexes)
//!   are still served, so publishing clients that read metadata first keep
//!   working.
//! * [`quota_envelope`] wraps the whole router. It re-renders a refusal in
//!   the OCI error envelope on `/v2` and with npm's `error` field on `/npm`,
//!   and turns the plain-text `413` of a body limit into the JSON refusal.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::{OriginalUri, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body::{Frame, SizeHint};

use super::{storage, QuotaRefusal, TransferMeter};
use crate::api::SharedState;
use crate::services::repository_service::RepositoryService;

/// The full request path, also inside a nested router.
fn full_path(req: &Request) -> String {
    req.extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string())
}

/// The declared `Content-Length`, if present and well-formed.
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// What the upload admission checks for one write request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriteTarget {
    /// Whether the storage quotas are checked before the body is read.
    pub storage: bool,
    /// Whether `MAX_UPLOAD_SIZE` applies to the declared length.
    pub size_limited: bool,
    /// The repository the bytes land in, when the path names it.
    pub repo_key: Option<String>,
}

/// A write on a native format route that stores no artifact bytes: a login,
/// a search or audit `POST`, a dist-tag, lock or ownership change, a status
/// change.
fn is_metadata_format_write(method: &Method, path: &str) -> bool {
    if *method == Method::POST && crate::api::middleware::auth::is_non_mutating_format_post(path) {
        return true;
    }
    let mut segments = path.trim_start_matches('/').split('/');
    let format = segments.next().unwrap_or("");
    let tail: Vec<&str> = segments.skip(1).collect();
    match format {
        // Git LFS locks and the post-upload verify callback.
        "lfs" => {
            tail.first() == Some(&"locks")
                || (tail.first() == Some(&"objects") && tail.last() == Some(&"verify"))
        }
        // Cargo `unyank` and owner changes.
        "cargo" | "api" => tail.last() == Some(&"unyank") || tail.contains(&"owners"),
        // MCP registry status changes.
        "mcp" => *method == Method::PATCH,
        _ => false,
    }
}

/// Classify a `PUT` / `POST` / `PATCH` reaching an upload-admitted router:
/// `None` when it stores no artifact bytes and is never refused here.
pub(crate) fn write_target(method: &Method, path: &str) -> Option<WriteTarget> {
    if !matches!(*method, Method::PUT | Method::POST | Method::PATCH) {
        return None;
    }
    // OCI: blob uploads (session start, chunks, completion) and manifest
    // pushes. `/v2/<repo_key>/<image...>/blobs/uploads/...`.
    if let Some(rest) = path.strip_prefix("/v2/") {
        let stores = rest.contains("/blobs/uploads")
            || (*method == Method::PUT && rest.contains("/manifests/"));
        return stores.then(|| WriteTarget {
            storage: true,
            size_limited: true,
            repo_key: rest
                .split('/')
                .next()
                .filter(|k| !k.is_empty())
                .map(str::to_string),
        });
    }
    if let Some(rest) = path.strip_prefix("/api/v1/") {
        // Repository artifact API: `/api/v1/repositories/<key>/artifacts[/...]`,
        // and the OCI replication receive path a peer pushes images to
        // (`.../oci/blobs/<digest>`, `.../oci/manifests/<digest>`).
        if let Some(repo_rest) = rest.strip_prefix("repositories/") {
            let (key, tail) = repo_rest.split_once('/')?;
            let artifacts = tail == "artifacts"
                || tail.starts_with("artifacts/")
                || tail.starts_with("oci/blobs/")
                || tail.starts_with("oci/manifests/");
            return (artifacts && !key.is_empty()).then(|| WriteTarget {
                storage: true,
                size_limited: true,
                repo_key: Some(key.to_string()),
            });
        }
        // Chunked upload API (also how replication pushes into this
        // instance): the session names its repository in the body, and the
        // session start already checks its total size against the
        // repository quota.
        if rest == "uploads" || rest.starts_with("uploads/") {
            return Some(WriteTarget {
                storage: true,
                size_limited: true,
                repo_key: None,
            });
        }
        return None;
    }
    if is_metadata_format_write(method, path) {
        return None;
    }
    let format = path.trim_start_matches('/').split('/').next().unwrap_or("");
    let key = crate::api::middleware::auth::extract_repo_key(path);
    Some(WriteTarget {
        // An npm package document is both a publish and a metadata change
        // (deprecate, unpublish, dist-tags): the npm handler admits it once it
        // knows whether it carries a tarball.
        storage: format != "npm",
        // Incus/LXC image uploads have no body limit of their own.
        size_limited: !matches!(format, "incus" | "lxc"),
        repo_key: (!key.is_empty()).then(|| key.into_owned()),
    })
}

/// The repository-quota refusal of `declared` bytes into `repo_key`, if its
/// repository (or project) quota cannot take them. Repositories without a
/// quota cost one indexed lookup.
async fn repository_refusal(
    db: &sqlx::PgPool,
    repo_key: &str,
    declared: u64,
) -> crate::error::Result<Option<QuotaRefusal>> {
    let row: Option<(uuid::Uuid, bool)> = sqlx::query_as(
        "SELECT r.id, (COALESCE(r.quota_bytes, 0) > 0 OR COALESCE(p.quota_bytes, 0) > 0) \
           FROM repositories r LEFT JOIN projects p ON p.id = r.project_id \
          WHERE r.key = $1",
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await?;
    let Some((repo_id, true)) = row else {
        return Ok(None);
    };
    let additional = i64::try_from(declared).unwrap_or(i64::MAX);
    Ok(RepositoryService::new(db.clone())
        .quota_preflight(repo_id, additional)
        .await?
        .map(|denial| denial.refusal()))
}

/// The refusal, if any, of a write that declares `declared` bytes.
async fn admission_refusal(
    state: &SharedState,
    target: &WriteTarget,
    declared: Option<u64>,
) -> Option<QuotaRefusal> {
    let max = state.config.max_upload_size_bytes;
    if target.size_limited && max > 0 {
        if let Some(length) = declared.filter(|d| *d > max) {
            return Some(QuotaRefusal::upload_size(max, Some(length)));
        }
    }
    if !target.storage {
        return None;
    }
    // A failed lookup admits the request: the publish admission after the
    // body is read still enforces every quota.
    match storage::admit_declared(&state.db, declared).await {
        Ok(Some(refusal)) => return Some(refusal),
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "storage quota pre-check failed; admitting"),
    }
    let (Some(key), Some(length)) = (&target.repo_key, declared.filter(|d| *d > 0)) else {
        return None;
    };
    match repository_refusal(&state.db, key, length).await {
        Ok(refusal) => refusal,
        Err(e) => {
            tracing::warn!(error = %e, "repository quota pre-check failed; admitting");
            None
        }
    }
}

/// Middleware: refuse an upload over a quota or the size limit before its
/// body is read. See the module docs.
pub async fn upload_admission(
    State(state): State<SharedState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(target) = write_target(req.method(), &full_path(&req)) else {
        return next.run(req).await;
    };
    let declared = declared_length(req.headers());
    match admission_refusal(&state, &target, declared).await {
        // The body is dropped unread with the request.
        Some(refusal) => refusal.into_response(),
        None => next.run(req).await,
    }
}

/// Response extension: this redirect hands the client a presigned URL for
/// an object of this many bytes. The transfer meter counts the size when
/// the URL is issued, since the bytes then leave storage without passing
/// through the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresignedDownload(pub u64);

/// Mark `response` as a presigned download of `size_bytes` bytes.
pub fn tag_presigned_download(response: &mut Response, size_bytes: i64) {
    response
        .extensions_mut()
        .insert(PresignedDownload(u64::try_from(size_bytes).unwrap_or(0)));
}

/// Whether a response's `Content-Type` is an index or metadata document
/// (JSON, XML, HTML, text, YAML) rather than artifact bytes.
fn is_metadata_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let essence = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence.starts_with("text/")
        || essence.ends_with("json")
        || essence.contains("xml")
        || essence.contains("yaml")
}

/// Whether a successful `GET` answer on `path` is an artifact download the
/// transfer quota may refuse.
pub(crate) fn is_artifact_download(path: &str, status: StatusCode, response: &Response) -> bool {
    if response.extensions().get::<PresignedDownload>().is_some() {
        return true;
    }
    // Every presigned redirect names its source (`redirect-s3`, ...).
    if status.is_redirection()
        && response
            .headers()
            .get(crate::api::download_response::X_ARTIFACT_STORAGE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("redirect"))
    {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/v2/") {
        return (rest.contains("/blobs/") && !rest.contains("/blobs/uploads"))
            || rest.contains("/manifests/");
    }
    status.is_success() && !is_metadata_content_type(response.headers())
}

/// A response body that adds the bytes it yields to the transfer meter.
struct CountingBody {
    inner: Body,
    meter: Arc<TransferMeter>,
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled {
            if let Some(data) = frame.data_ref() {
                self.meter.record(data.len() as u64);
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Middleware: count download bytes and refuse artifact downloads at the
/// transfer quota's hard limit. See the module docs.
pub async fn transfer_meter(
    State(meter): State<Arc<TransferMeter>>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() != Method::GET {
        return next.run(req).await;
    }
    let path = full_path(&req);
    let response = next.run(req).await;
    let status = response.status();
    if !status.is_success() && !status.is_redirection() {
        return response;
    }
    if is_artifact_download(&path, status, &response) {
        if let Some(refusal) = meter.refusal() {
            // The handler's body is dropped unsent.
            return refusal.into_response();
        }
    }
    if status.is_redirection() {
        if let Some(PresignedDownload(size)) = response.extensions().get::<PresignedDownload>() {
            meter.record(*size);
        }
        return response;
    }
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Body::new(CountingBody { inner: body, meter }))
}

/// Which native error shape a refusal on `path` is rendered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Envelope {
    Standard,
    Oci,
    Npm,
}

pub(crate) fn envelope_for(path: &str) -> Envelope {
    if path == "/v2" || path.starts_with("/v2/") {
        Envelope::Oci
    } else if path.starts_with("/npm/") {
        Envelope::Npm
    } else {
        Envelope::Standard
    }
}

fn render(refusal: &QuotaRefusal, envelope: Envelope) -> Response {
    match envelope {
        Envelope::Standard => refusal.response_with_body(refusal.body()),
        Envelope::Oci => refusal.response_with_body(refusal.oci_body()),
        Envelope::Npm => refusal.response_with_body(refusal.npm_body()),
    }
}

/// Whether a plain `413` on `path` comes from `MAX_UPLOAD_SIZE` (the body
/// limit every upload route applies) rather than from a smaller limit of its
/// own (the OCI token exchange, the Protobuf routes).
fn upload_limit_413(path: &str) -> bool {
    !(path.starts_with("/proto/") || path == "/v2/token" || path.starts_with("/api/v1/auth"))
}

fn is_json(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("json"))
}

/// Middleware over the whole router: render quota refusals in the route's
/// native envelope, and make a body-limit `413` the JSON refusal.
pub async fn quota_envelope(State(max_upload): State<u64>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let response = next.run(req).await;
    let envelope = envelope_for(&path);
    if let Some(refusal) = response.extensions().get::<QuotaRefusal>() {
        if envelope == Envelope::Standard {
            return response;
        }
        let refusal = refusal.clone();
        return render(&refusal, envelope);
    }
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE
        && max_upload > 0
        && !is_json(&response)
        && upload_limit_413(&path)
    {
        let refusal = QuotaRefusal::upload_size(max_upload, None);
        // Counted and logged like every other refusal.
        let standard = refusal.clone().into_response();
        return match envelope {
            Envelope::Standard => standard,
            other => render(&refusal, other),
        };
    }
    response
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::QuotaSettings;
    use axum::routing::{get, put};
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn target(storage: bool, size_limited: bool, key: Option<&str>) -> Option<WriteTarget> {
        Some(WriteTarget {
            storage,
            size_limited,
            repo_key: key.map(str::to_string),
        })
    }

    #[test]
    fn write_targets_cover_every_upload_surface() {
        let put_ = Method::PUT;
        let post = Method::POST;
        let patch = Method::PATCH;
        let cases: &[(&Method, &str, Option<WriteTarget>)] = &[
            // Reads and deletes are never refused.
            (&Method::GET, "/maven/libs/a/b/1/b-1.jar", None),
            (&Method::DELETE, "/maven/libs/a/b/1/b-1.jar", None),
            (&Method::HEAD, "/v2/docker/app/blobs/sha256:aa", None),
            // Native formats.
            (
                &put_,
                "/maven/libs/a/b/1/b-1.jar",
                target(true, true, Some("libs")),
            ),
            (&post, "/pypi/py/", target(true, true, Some("py"))),
            (
                &put_,
                "/api/cargo/crates/api/v1/crates/new",
                target(true, true, Some("crates")),
            ),
            (
                &put_,
                "/incus/img/images/x",
                target(true, false, Some("img")),
            ),
            (&put_, "/npm/js/left-pad", target(false, true, Some("js"))),
            // Metadata writes on format routes.
            (&post, "/npm/js/-/npm/v1/security/advisories/bulk", None),
            (&post, "/pypi/py/pypi", None),
            (&post, "/lfs/big/objects/batch", None),
            (&post, "/lfs/big/locks", None),
            (&post, "/lfs/big/locks/1/unlock", None),
            (&post, "/lfs/big/objects/verify", None),
            (&put_, "/cargo/crates/api/v1/crates/foo/1.0.0/unyank", None),
            (&put_, "/cargo/crates/api/v1/crates/foo/owners", None),
            (&patch, "/mcp/servers/v0/servers/x/status", None),
            (&post, "/vscode/ext/gallery/extensionquery", None),
            // OCI.
            (
                &post,
                "/v2/docker/app/blobs/uploads/",
                target(true, true, Some("docker")),
            ),
            (
                &patch,
                "/v2/docker/a/b/blobs/uploads/123",
                target(true, true, Some("docker")),
            ),
            (
                &put_,
                "/v2/docker/app/blobs/uploads/123?digest=x",
                target(true, true, Some("docker")),
            ),
            (
                &put_,
                "/v2/docker/app/manifests/latest",
                target(true, true, Some("docker")),
            ),
            (&post, "/v2/token", None),
            // REST.
            (
                &put_,
                "/api/v1/repositories/gen/artifacts/a.bin",
                target(true, true, Some("gen")),
            ),
            (
                &post,
                "/api/v1/repositories/gen/artifacts",
                target(true, true, Some("gen")),
            ),
            (&put_, "/api/v1/repositories/gen/settings", None),
            (
                &put_,
                "/api/v1/repositories/d/oci/blobs/sha256:a",
                target(true, true, Some("d")),
            ),
            (
                &put_,
                "/api/v1/repositories/d/oci/manifests/sha256:a",
                target(true, true, Some("d")),
            ),
            (&post, "/api/v1/repositories/gen/artifacts-missing", None),
            (&post, "/api/v1/uploads", target(true, true, None)),
            (&put_, "/api/v1/uploads/1234", target(true, true, None)),
            (&post, "/api/v1/auth/login", None),
        ];
        for (method, path, expected) in cases {
            assert_eq!(&write_target(method, path), expected, "{method} {path}");
        }
    }

    #[test]
    fn artifact_downloads_are_told_apart_from_metadata() {
        let with_type = |ct: &str| {
            let mut r = Response::new(Body::empty());
            r.headers_mut()
                .insert(header::CONTENT_TYPE, ct.parse().unwrap());
            r
        };
        let ok = StatusCode::OK;
        for ct in [
            "application/json",
            "application/vnd.npm.install-v1+json; q=1.0",
            "application/xml",
            "text/html; charset=utf-8",
            "text/plain",
            "application/x-yaml",
        ] {
            assert!(
                !is_artifact_download("/npm/js/pkg", ok, &with_type(ct)),
                "{ct}"
            );
        }
        for ct in [
            "application/octet-stream",
            "application/java-archive",
            "application/gzip",
        ] {
            assert!(
                is_artifact_download("/maven/m/x.jar", ok, &with_type(ct)),
                "{ct}"
            );
        }
        assert!(is_artifact_download(
            "/maven/m/x.jar",
            ok,
            &Response::new(Body::empty())
        ));
        // OCI manifests are JSON and still downloads; upload status is not.
        let manifest = with_type("application/vnd.oci.image.manifest.v1+json");
        assert!(is_artifact_download("/v2/d/app/manifests/1", ok, &manifest));
        assert!(is_artifact_download(
            "/v2/d/app/blobs/sha256:a",
            ok,
            &manifest
        ));
        assert!(!is_artifact_download(
            "/v2/d/app/blobs/uploads/1",
            StatusCode::NO_CONTENT,
            &manifest
        ));
        assert!(!is_artifact_download("/v2/_catalog", ok, &manifest));
        // A presigned redirect is a download; another redirect is not.
        let mut redirect = Response::new(Body::empty());
        *redirect.status_mut() = StatusCode::FOUND;
        assert!(!is_artifact_download(
            "/maven/m/x.jar",
            StatusCode::FOUND,
            &redirect
        ));
        let mut unsized_redirect = Response::new(Body::empty());
        unsized_redirect.headers_mut().insert(
            crate::api::download_response::X_ARTIFACT_STORAGE,
            "redirect-s3".parse().unwrap(),
        );
        assert!(is_artifact_download(
            "/maven/m/x.jar",
            StatusCode::FOUND,
            &unsized_redirect
        ));
        tag_presigned_download(&mut redirect, 10);
        assert!(is_artifact_download(
            "/maven/m/x.jar",
            StatusCode::FOUND,
            &redirect
        ));
    }

    fn lazy_pool() -> sqlx::PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool")
    }

    fn meter(quota: u64) -> Arc<TransferMeter> {
        TransferMeter::new(
            lazy_pool(),
            &QuotaSettings {
                transfer_quota_bytes: quota,
                ..QuotaSettings::default()
            },
        )
    }

    fn metered_app(meter: Arc<TransferMeter>) -> Router {
        Router::new()
            .route(
                "/maven/m/x.jar",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "application/java-archive")],
                        vec![7u8; 1000],
                    )
                }),
            )
            .route(
                "/maven/m/maven-metadata.xml",
                get(|| async { ([(header::CONTENT_TYPE, "application/xml")], "<m/>") }),
            )
            .route(
                "/maven/m/presigned.jar",
                get(|| async {
                    let mut r =
                        (StatusCode::FOUND, [(header::LOCATION, "https://s3/x")]).into_response();
                    tag_presigned_download(&mut r, 5000);
                    r
                }),
            )
            .route("/maven/m/up.jar", put(|| async { StatusCode::CREATED }))
            .layer(axum::middleware::from_fn_with_state(meter, transfer_meter))
    }

    async fn call(app: &Router, method: Method, uri: &str) -> (StatusCode, HeaderMap, Bytes) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, bytes)
    }

    /// Downloads are counted on the bytes sent; at the hard limit artifact
    /// downloads answer 429 with Retry-After while metadata reads and uploads
    /// keep working.
    #[tokio::test]
    async fn the_meter_counts_downloads_and_refuses_at_the_hard_limit() {
        let meter = meter(2500);
        let app = metered_app(Arc::clone(&meter));

        let (status, _, body) = call(&app, Method::GET, "/maven/m/x.jar").await;
        assert_eq!((status, body.len()), (StatusCode::OK, 1000));
        assert_eq!(meter.used_bytes(), 1000);
        // HEAD and uploads are not counted.
        call(&app, Method::HEAD, "/maven/m/x.jar").await;
        assert_eq!(
            call(&app, Method::PUT, "/maven/m/up.jar").await.0,
            StatusCode::CREATED
        );
        assert_eq!(meter.used_bytes(), 1000);
        // A presigned redirect counts the object size at issue time.
        assert_eq!(
            call(&app, Method::GET, "/maven/m/presigned.jar").await.0,
            StatusCode::FOUND
        );
        assert_eq!(meter.used_bytes(), 6000);

        let (status, headers, body) = call(&app, Method::GET, "/maven/m/x.jar").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = headers[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=31 * 86_400).contains(&retry), "{retry}");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "TRANSFER_QUOTA_EXCEEDED");
        assert_eq!(json["retry_after_seconds"].as_u64(), Some(retry));
        assert_eq!(meter.used_bytes(), 6000, "the refused body is not counted");
        assert_eq!(
            call(&app, Method::GET, "/maven/m/presigned.jar").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );

        // Metadata and uploads still work.
        let (status, _, body) = call(&app, Method::GET, "/maven/m/maven-metadata.xml").await;
        assert_eq!((status, &body[..]), (StatusCode::OK, &b"<m/>"[..]));
        assert_eq!(
            call(&app, Method::PUT, "/maven/m/up.jar").await.0,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn refusals_take_the_native_envelope_of_their_route() {
        let app = Router::new()
            .route(
                "/v2/d/app/blobs/uploads/",
                axum::routing::post(|| async {
                    QuotaRefusal::instance_storage(10, 10, None).into_response()
                }),
            )
            .route(
                "/npm/js/pkg",
                put(|| async { QuotaRefusal::instance_storage(10, 10, None).into_response() }),
            )
            .route(
                "/maven/m/a.jar",
                put(|| async { QuotaRefusal::instance_storage(10, 10, None).into_response() }),
            )
            .route(
                "/maven/m/big.jar",
                put(|| async { (StatusCode::PAYLOAD_TOO_LARGE, "length limit exceeded") }),
            )
            .route(
                "/proto/p/big",
                put(|| async { (StatusCode::PAYLOAD_TOO_LARGE, "length limit exceeded") }),
            )
            .layer(axum::middleware::from_fn_with_state(100u64, quota_envelope));

        let (status, _, body) = call(&app, Method::POST, "/v2/d/app/blobs/uploads/").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errors"][0]["code"], "DENIED");
        assert_eq!(json["errors"][0]["detail"]["scope"], "instance");

        let (status, _, body) = call(&app, Method::PUT, "/npm/js/pkg").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "STORAGE_QUOTA_EXCEEDED");
        assert_eq!(json["error"], json["message"]);

        let (_, _, body) = call(&app, Method::PUT, "/maven/m/a.jar").await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_none() && json.get("errors").is_none());

        let (status, _, body) = call(&app, Method::PUT, "/maven/m/big.jar").await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "PAYLOAD_TOO_LARGE");
        assert_eq!(json["limit_bytes"], 100);

        let (status, _, body) = call(&app, Method::PUT, "/proto/p/big").await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(&body[..], b"length limit exceeded");
    }
}
