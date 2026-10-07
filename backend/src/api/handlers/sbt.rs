//! SBT/Ivy repository API handlers.
//!
//! Implements the endpoints required for SBT's Ivy-style artifact resolution.
//!
//! Routes are mounted at `/ivy/{repo_key}/...`:
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/ivys/ivy.xml               - Ivy descriptor
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/jars/{name}-{version}.jar  - Download JAR
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/srcs/{name}-{version}-sources.jar - Sources
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/docs/{name}-{version}-javadoc.jar - Javadoc
//!   PUT  /ivy/{repo_key}/*path                                             - Upload artifact
//!   HEAD /ivy/{repo_key}/*path                                             - Check existence

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::maven;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::sbt::SbtHandler;
use crate::models::repository::{RepositoryFormat, RepositoryType};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Single wildcard handles all Ivy layout paths:
        //   GET  — download artifact (ivy.xml, jars, srcs, docs, etc.)
        //   PUT  — upload artifact (auth required)
        //   HEAD — check artifact existence
        .route(
            "/:repo_key/*path",
            get(download_by_path)
                .put(upload_artifact)
                .head(check_exists),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_sbt_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["sbt"], "an sbt").await
}

// ---------------------------------------------------------------------------
// Remote serve + #4100 scan-on-proxy
// ---------------------------------------------------------------------------

/// Stream one proxied sbt/Ivy file from a Remote repository's upstream
/// through the proxy cache (the unscanned serve; the caller records it).
///
/// #1608 Phase 4: the body (sbt/ivy `.jar` and friends can be large) streams
/// to the client while teeing to the proxy cache, single-flight via the
/// merged coordinator (#1609). #3459: the real format is carried, because
/// `proxy_fetch_streaming` synthesizes a `Generic` repository with no
/// `cache_classifier` arm, which cached every sbt/ivy file with the
/// conservative 5-minute mutable TTL. Sbt shares Maven's classifier rules.
async fn sbt_remote_stream(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
) -> Result<Response, Response> {
    proxy_helpers::proxy_fetch_streaming_with_format(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        path,
        "application/octet-stream",
        RepositoryFormat::Sbt,
    )
    .await
}

/// Whether a proxied sbt path is a package archive the scan-on-proxy gate
/// grades (#4100) — the same allowlist rule as Maven
/// ([`maven::is_unscanned_jvm_companion`]) — and, if so, the coordinate it is
/// requested as: Ivy layout
/// `<org>/<module>/[scala_<v>/][sbt_<v>/]<revision>/<type>s/<file>` or, for an
/// sbt repository proxying a Maven-layout upstream, the Maven path grammar.
/// A scannable archive whose path names no coordinate is still scanned, with
/// no identity pin. Classified on the cache-normalized path, exactly as
/// [`maven::maven_scan_target`] is, so no alias of an archive's cache entry
/// (a trailing `/`, an upper-case extension) skips the gate.
fn sbt_scan_target(path: &str) -> Option<maven::JvmScanTarget> {
    let key = maven::jvm_proxy_serve_key(path);
    if !key.scannable {
        return None;
    }
    let path = key.cache_key.as_str();
    let segments: Vec<&str> = path.split('/').collect();
    let filename = segments.last().copied().unwrap_or_default();
    if !maven::is_jvm_archive_name(filename) {
        return Some(maven::JvmScanTarget {
            path: path.to_string(),
            coordinate: None,
        });
    }
    let n = segments.len();
    if n >= 5 && matches!(segments[n - 2], "jars" | "bundles" | "wars" | "ears") {
        let version = segments[n - 3];
        let mut module_at = n - 4;
        while module_at > 0
            && (segments[module_at].starts_with("scala_")
                || segments[module_at].starts_with("sbt_"))
        {
            module_at -= 1;
        }
        let org = segments[..module_at].join(".");
        let coordinate = (module_at > 0 && !org.is_empty() && !version.is_empty()).then(|| {
            maven::JvmArchiveCoordinate {
                group_id: org,
                artifact_id: segments[module_at].to_string(),
                version: version.to_string(),
            }
        });
        return Some(maven::JvmScanTarget {
            path: path.to_string(),
            coordinate,
        });
    }
    maven::maven_scan_target(path)
}

/// Inline scan-and-block for one proxied sbt package archive (#4100), on the
/// generic gate, cached under the same path the streaming route commits to.
async fn serve_scanned_sbt_archive(
    state: &SharedState,
    proxy: &crate::services::proxy_service::ProxyService,
    (repo_id, repo_key, upstream_url): (uuid::Uuid, &str, &str),
    path: &str,
    coordinate: Option<&maven::JvmArchiveCoordinate>,
    (action, severity_gate): (
        crate::services::proxy_scan_service::ProxyScanAction,
        crate::services::proxy_scan_service::ProxySeverityGate,
    ),
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let req = proxy_helpers::ScannedProxyRequest {
        repo_id,
        repo_key,
        fetch_base: upstream_url,
        format: RepositoryFormat::Sbt,
        source_path: path,
        cache_path: path,
        filename,
        action,
        severity_gate,
        ctx: Some(ctx),
    };
    let file = SbtScannedArchive {
        proxy,
        upstream_url,
        coordinate,
    };
    proxy_helpers::serve_scanned_proxy_file(state, proxy, &req, &file).await
}

/// The sbt Virtual download of a scannable archive (#4100). The member set
/// is authorized ONCE: a scanning Remote member serves through the gate
/// (see [`proxy_helpers::walk_virtual_members_with_scan`]); when no member
/// scans, the same authorized set goes to the untouched resolver.
async fn serve_scanned_sbt_virtual(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    proxy: &crate::services::proxy_service::ProxyService,
    virtual_id: uuid::Uuid,
    request_path: &str,
    target: &maven::JvmScanTarget,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let members = proxy_helpers::authorized_virtual_members(&state.db, auth, virtual_id).await?;
    let local_fetch = |member_id: uuid::Uuid, location: crate::storage::StorageLocation| async move {
        proxy_helpers::local_fetch_by_path(&state.db, state, member_id, &location, request_path)
            .await
    };
    // sbt's resolver path records no hosted download today (unlike Maven's,
    // #4268), so the walk keeps that: `record` is `None`.
    let resolve_run = |run: Vec<crate::models::repository::Repository>| {
        proxy_helpers::resolve_unscanned_member_run(
            run,
            Some(proxy),
            request_path,
            &local_fetch,
            "application/octet-stream",
            None,
        )
    };
    let scanned = |member: crate::models::repository::Repository, policy| async move {
        let upstream_url = member.upstream_url.clone().unwrap_or_default();
        serve_scanned_sbt_archive(
            state,
            proxy,
            (member.id, &member.key, &upstream_url),
            &target.path,
            target.coordinate.as_ref(),
            policy,
            ctx,
        )
        .await
    };
    if let Some(served) = proxy_helpers::walk_virtual_members_with_scan(
        &state.db,
        virtual_id,
        members.clone(),
        resolve_run,
        scanned,
    )
    .await
    {
        return served;
    }
    let result = proxy_helpers::resolve_virtual_download_from_members(
        members,
        Some(proxy),
        request_path,
        &local_fetch,
    )
    .await?;
    proxy_helpers::stream_fetch_result(result, "application/octet-stream", None)
}

/// The sbt half of the generic proxy scan gate. The wrapper records the
/// download on both serve arms, including the unscanned over-cap stream.
struct SbtScannedArchive<'a> {
    proxy: &'a crate::services::proxy_service::ProxyService,
    upstream_url: &'a str,
    coordinate: Option<&'a maven::JvmArchiveCoordinate>,
}

#[async_trait::async_trait]
impl proxy_helpers::ScannedProxyFile for SbtScannedArchive<'_> {
    const LABEL: &'static str = "sbt archive";

    fn synthetic_content_type(filename: &str) -> String {
        maven::content_type_for_path(filename).to_string()
    }

    fn identity(
        &self,
        _req: &proxy_helpers::ScannedProxyRequest<'_>,
        bytes: &Bytes,
        _digest: &str,
    ) -> proxy_helpers::ProxyScanIdentity {
        maven::jvm_archive_identity(self.coordinate, bytes)
    }

    async fn serve_unscanned_stream(
        &self,
        _state: &SharedState,
        req: &proxy_helpers::ScannedProxyRequest<'_>,
    ) -> Result<Response, Response> {
        sbt_remote_stream(
            self.proxy,
            req.repo_id,
            req.repo_key,
            self.upstream_url,
            req.source_path,
        )
        .await
    }

    fn scanned_response(
        &self,
        _req: &proxy_helpers::ScannedProxyRequest<'_>,
        body: proxy_helpers::ScannedProxyBody,
        _pending: bool,
    ) -> Response {
        maven::scanned_jvm_archive_response("application/octet-stream", body)
    }
}

// ---------------------------------------------------------------------------
// GET /ivy/{repo_key}/*path — Download artifact by path
// ---------------------------------------------------------------------------

async fn download_by_path(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    let artifact_path = artifact_path.trim_start_matches('/');
    // #4100: see `maven::reject_ambiguous_proxy_path`.
    if repo.repo_type == RepositoryType::Remote || repo.repo_type == RepositoryType::Virtual {
        maven::reject_ambiguous_proxy_path(artifact_path)?;
    }

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, storage_key, size_bytes, content_type
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // #4100: scan-on-proxy gates the package archives (jar /
                    // war / ear, Ivy or Maven layout; see `sbt_scan_target`).
                    // Ivy descriptors, POMs, sources/javadoc jars and
                    // checksums pass through, and a repository that has not
                    // enabled scan-on-proxy keeps the streaming path below.
                    if let Some(target) = sbt_scan_target(artifact_path) {
                        if let Some(policy) =
                            proxy_helpers::remote_scan_policy(&state.db, repo.id).await?
                        {
                            return serve_scanned_sbt_archive(
                                &state,
                                proxy,
                                (repo.id, &repo_key, upstream_url),
                                &target.path,
                                target.coordinate.as_ref(),
                                policy,
                                &ctx,
                            )
                            .await;
                        }
                    }
                    let response =
                        sbt_remote_stream(proxy, repo.id, &repo_key, upstream_url, artifact_path)
                            .await?;
                    // #3649: count the proxied serve. The streaming helper answers a warm
                    // cache HIT from storage and a cold MISS from upstream through the same
                    // call, so recording once it resolves counts both -- the cache hit #3649
                    // reported as invisible included -- while a 404/502 still counts nothing.
                    // Keyed on the proxy-cache path this fetch commits under, so the count
                    // lines up with the catalog row the artifact listing renders.
                    proxy_helpers::record_proxy_download(
                        &state,
                        repo.id,
                        &repo_key,
                        artifact_path,
                        &ctx,
                    )
                    .await;
                    return Ok(response);
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                // #4100: a scanning Remote member serves its package archive
                // through the scan gate; everything else keeps the resolver.
                if let (Some(target), Some(proxy)) =
                    (sbt_scan_target(artifact_path), state.proxy_service.as_ref())
                {
                    return serve_scanned_sbt_virtual(
                        &state,
                        auth.as_ref(),
                        proxy,
                        repo.id,
                        artifact_path,
                        &target,
                        &ctx,
                    )
                    .await;
                }
                let db = state.db.clone();
                let path_clone = artifact_path.to_string();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    auth.as_ref(),
                    state.proxy_service.as_deref(),
                    repo.id,
                    artifact_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let path = path_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db, &state, member_id, &location, &path,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    None,
                );
            }

            return Err((StatusCode::NOT_FOUND, "Artifact not found").into_response());
        }
    };

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    // #1945: offload eligible hosted Ivy/sbt blob binaries (.jar/.war/.aar/.zip/
    // .tar.gz/.jmod) to a presigned S3 redirect instead of streaming them
    // through the backend process. ivy.xml/POM/checksum files and filesystem
    // backends fall through to the inline stream below. The helper records the
    // download before issuing the 302 (count-at-redirect, #2260).
    if let Some(redirect) = proxy_helpers::try_hosted_blob_redirect(
        &state,
        storage.as_ref(),
        artifact_path,
        &artifact.storage_key,
        artifact.id,
        &ctx,
    )
    .await
    {
        return Ok(redirect);
    }

    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::api::handlers::storage_err_message(&e),
            )
                .into_response()
        })?;

    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    let content_type = if artifact.content_type.is_empty() {
        "application/octet-stream"
    } else {
        &artifact.content_type
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            "Content-Disposition",
            format!(
                "attachment; filename=\"{}\"",
                artifact_path.rsplit('/').next().unwrap_or(artifact_path)
            ),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /ivy/{repo_key}/*path — Upload artifact (auth required)
// ---------------------------------------------------------------------------

async fn upload_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, "ivy", "write:artifacts")?.user_id;
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let artifact_path = artifact_path.trim_start_matches('/').to_string();

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty artifact file").into_response());
    }

    // Validate path via format handler
    let path_info = SbtHandler::parse_path(&artifact_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid SBT path: {}", e)).into_response()
    })?;

    let artifact_name = if path_info.is_ivy_descriptor {
        format!("{}/{}", path_info.org, path_info.module)
    } else {
        path_info
            .artifact
            .clone()
            .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
    };

    let artifact_version = path_info.revision.clone().unwrap_or_default();

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "Artifact already exists at this path").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Determine content type
    let content_type = if path_info.is_ivy_descriptor {
        "application/xml"
    } else {
        "application/java-archive"
    };

    super::publish_quota::preflight_publish_quota(
        &state.db,
        repo.id,
        super::publish_quota::PublishAt::Path(&artifact_path),
        body.len() as i64,
    )
    .await?;

    // Store the file. #2624: on shared cloud namespaces new objects embed the
    // repository id (`sbt/{repository_id}/{path}`) so keys can never collide
    // across repositories; filesystem backends and STORAGE_KEY_SCHEME=flat
    // keep the legacy `sbt/{path}` shape. Downloads read the row-recorded
    // storage_key, so objects written under either scheme stay readable.
    let storage_key = crate::storage::StorageKeyScheme::from_env().write_key(
        &repo.storage_backend,
        "sbt",
        repo.id,
        &artifact_path,
    );
    proxy_helpers::guard_cross_repo_write(&state, repo.id, &repo.storage_backend, &storage_key)
        .await?;
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::api::handlers::storage_err_message(&e),
        )
            .into_response()
    })?;

    // The Ivy module coordinate, captured before `path_info`'s fields move
    // into the metadata JSON below (#3659).
    let catalog_name = format!("{}/{}", path_info.org, path_info.module);

    let sbt_metadata = serde_json::json!({
        "org": path_info.org,
        "module": path_info.module,
        "revision": path_info.revision,
        "artifact": path_info.artifact,
        "ext": path_info.ext,
        "is_ivy_descriptor": path_info.is_ivy_descriptor,
    });

    let size_bytes = body.len() as i64;

    let mut tx = super::publish_quota::begin_admitted_publish(
        &state.db,
        repo.id,
        &artifact_path,
        size_bytes,
    )
    .await?;
    let artifact_id = sqlx::query_scalar!(
        r#"
        INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        repo.id,
        artifact_path,
        artifact_name,
        artifact_version,
        size_bytes,
        computed_sha256,
        content_type,
        storage_key,
        user_id,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::api::handlers::db_err)?;
    tx.commit().await.map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'sbt', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        sbt_metadata,
    )
    .execute(&state.db)
    .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    // Surface the module on the Packages page (#3659), keyed on the Ivy
    // `org/module` coordinate and revision. `artifact_name` above is the
    // filename stem (it embeds the revision), so it is deliberately not used
    // as the catalog key; every asset of one revision (jar/sources/docs/ivy)
    // collapses into the same catalog version, as Maven's do.
    if !artifact_version.is_empty() {
        crate::services::package_service::register_published_package(
            &state.db,
            &state.event_bus,
            repo.id,
            "sbt",
            &catalog_name,
            &artifact_version,
            size_bytes,
            &computed_sha256,
            None,
        )
        .await;
    }

    info!(
        "SBT upload: {} {} to repo {}",
        artifact_path, artifact_version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Successfully uploaded SBT artifact"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// HEAD /ivy/{repo_key}/*path — Check artifact existence
// ---------------------------------------------------------------------------

async fn check_exists(
    State(state): State<SharedState>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    let artifact_path = artifact_path.trim_start_matches('/');

    let artifact = sqlx::query!(
        r#"
        SELECT size_bytes, content_type
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    let content_type = if artifact.content_type.is_empty() {
        "application/octet-stream"
    } else {
        &artifact.content_type
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::empty())
        .unwrap())
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_remote_download_streams_upstream_blob_1608() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "sbt").await else {
            return;
        };
        let server = MockServer::start().await;
        // A small deterministic body stands in for a large artifact; the point
        // is to exercise the streaming pull-through branch (proxy_fetch_streaming)
        // added in #1608 Phase 4, not the body size.
        let blob: &[u8] = b"\x00\x01\x02 #1608 phase4 streamed proxy blob \x03\x04\x05";
        Mock::given(method("GET"))
            .and(path("/org/example/1.0/jars/example-1.0.jar"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{key}/org/example/1.0/jars/example-1.0.jar",
                key = fx.repo_key
            )),
        )
        .await;

        let teardown = || async { fx.teardown().await };
        if status != axum::http::StatusCode::OK {
            teardown().await;
            panic!("expected 200 from streamed remote download, got {status}");
        }
        assert_eq!(&body[..], blob, "streamed body must equal upstream bytes");
        teardown().await;
    }

    /// #3459. The sbt/ivy remote download arm used `proxy_fetch_streaming`,
    /// which synthesizes a `RepositoryFormat::Generic` repository. `Generic`
    /// has no `cache_classifier` arm, so every released `.jar` was stamped
    /// with the conservative 5-minute mutable TTL and re-fetched from upstream
    /// after it. Sbt shares Maven's classifier rules, so a released coordinate
    /// must cache effectively forever.
    ///
    /// The `-SNAPSHOT` coordinate is the negative control: same branch, same
    /// helper, same format, but republished in place, so it must stay mutable.
    /// Asserts the SIDECAR TTL actually written, not the classifier — the
    /// classifier was already correct; it was being handed the wrong format.
    #[tokio::test]
    async fn test_remote_sbt_release_artifact_is_cached_immutably_3459() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Floor for "cached effectively forever" (the immutable write TTL is
        /// a decade); anything above a year is not the 300s mutable default.
        const IMMUTABLE_FLOOR_SECS: i64 = 365 * 24 * 3600;
        const RELEASE: &str = "org/example/1.0/jars/example-1.0.jar";
        /// Maven-shaped SNAPSHOT: the filename repeats the version. This is
        /// the shape this module's own doc comment describes
        /// (`jars/{name}-{version}.jar`).
        const SNAPSHOT: &str = "org/example/1.1-SNAPSHOT/jars/example-1.1-SNAPSHOT.jar";
        /// IVY-NATIVE SNAPSHOT: `Resolver.ivyStylePatterns` keeps the revision
        /// in the DIRECTORY only, so the leaf carries no `-SNAPSHOT` token.
        /// The route is a wildcard `*path`, so this shape reaches the same arm
        /// and is equally valid. Before the component-wise SNAPSHOT rule this
        /// classified as a released coordinate and was cached for a decade —
        /// and `cache_classifier::evaluate` short-circuits Immutable to Fresh
        /// without consulting `expires_at`, so a republished snapshot was
        /// never re-fetched.
        const IVY_SNAPSHOT: &str = "org.example/mylib/1.0.0-SNAPSHOT/jars/mylib.jar";
        /// A RESOLVED unique snapshot names exactly one deployment and must
        /// STAY immutable, in the Ivy layout too. Without this row, "make
        /// everything under a -SNAPSHOT directory mutable" would pass.
        const IVY_RESOLVED: &str =
            "org.example/mylib/1.0.0-SNAPSHOT/jars/mylib-20240101.120000-7.jar";

        let Some(fx) = tdh::Fixture::setup("remote", "sbt").await else {
            return;
        };
        let server = MockServer::start().await;
        for p in [RELEASE, SNAPSHOT, IVY_SNAPSHOT, IVY_RESOLVED] {
            Mock::given(method("GET"))
                .and(path(format!("/{p}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(b"sbt-3459-body".to_vec()))
                .mount(&server)
                .await;
        }

        let (state, cache_dir) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        for p in [RELEASE, SNAPSHOT, IVY_SNAPSHOT, IVY_RESOLVED] {
            let app = tdh::router_anon(super::router(), state.clone());
            let (status, _body) =
                tdh::send(app, tdh::get(format!("/{key}/{p}", key = fx.repo_key))).await;
            if status != axum::http::StatusCode::OK {
                fx.teardown().await;
                panic!("expected 200 from remote sbt download of {p}, got {status}");
            }
        }

        // The streaming arm commits the sidecar on a background writer.
        // Presence is polled, never asserted: both the fixed and the pre-fix
        // code write it, so a revert fails on the TTL under test.
        let sidecar = |p: &str| {
            cache_dir.path().join(format!(
                "proxy-cache/{key}/{p}/__cache_meta__.json",
                key = fx.repo_key
            ))
        };
        let ttl = |p: &str| -> i64 {
            let raw = std::fs::read(sidecar(p))
                .unwrap_or_else(|e| panic!("sidecar for {p} must exist: {e}"));
            let v: serde_json::Value = serde_json::from_slice(&raw).expect("sidecar JSON");
            let cached_at =
                chrono::DateTime::parse_from_rfc3339(v["cached_at"].as_str().expect("cached_at"))
                    .expect("rfc3339");
            let expires_at =
                chrono::DateTime::parse_from_rfc3339(v["expires_at"].as_str().expect("expires_at"))
                    .expect("rfc3339");
            (expires_at - cached_at).num_seconds()
        };
        for p in [RELEASE, SNAPSHOT, IVY_SNAPSHOT, IVY_RESOLVED] {
            for _ in 0..100 {
                if sidecar(p).exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        let release_ttl = ttl(RELEASE);
        let snapshot_ttl = ttl(SNAPSHOT);
        let ivy_snapshot_ttl = ttl(IVY_SNAPSHOT);
        let ivy_resolved_ttl = ttl(IVY_RESOLVED);
        fx.teardown().await;

        let mutable = crate::services::cache_classifier::MUTABLE_DEFAULT_TTL_SECS;
        assert!(
            release_ttl >= IMMUTABLE_FLOOR_SECS,
            "a released sbt coordinate must be cached immutably; got {release_ttl}s. \
             {mutable}s is the #3459 symptom: a `Generic` stand-in repository reaching \
             the cache-TTL classifier."
        );
        assert!(
            snapshot_ttl <= mutable,
            "a Maven-shaped SNAPSHOT is republished in place and must stay mutable; \
             got {snapshot_ttl}s. This negative control is what keeps the immutable \
             assertion from passing under a 'cache everything forever' change."
        );
        assert!(
            ivy_snapshot_ttl <= mutable,
            "an IVY-LAYOUT snapshot keeps its revision in the DIRECTORY only, so its \
             leaf carries no `-SNAPSHOT` token; got {ivy_snapshot_ttl}s. A leaf-only \
             SNAPSHOT test reads it as a released coordinate and caches it for a \
             decade, and `cache_classifier::evaluate` short-circuits Immutable to \
             Fresh without consulting `expires_at`, so a republished snapshot is \
             never re-fetched."
        );
        assert!(
            ivy_resolved_ttl >= IMMUTABLE_FLOOR_SECS,
            "a RESOLVED unique snapshot names exactly one deployment and must stay \
             immutable in the Ivy layout too; got {ivy_resolved_ttl}s. Without this \
             row, 'make everything under a -SNAPSHOT directory mutable' passes and \
             Maven's unique-snapshot behaviour is silently destroyed."
        );
    }

    #[test]
    fn test_content_type_ivy_descriptor() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "com.example".to_string(),
            module: "mylib".to_string(),
            revision: Some("1.0".to_string()),
            artifact: None,
            ext: Some("xml".to_string()),
            is_ivy_descriptor: true,
        };
        let content_type = if path_info.is_ivy_descriptor {
            "application/xml"
        } else {
            "application/java-archive"
        };
        assert_eq!(content_type, "application/xml");
    }

    #[test]
    fn test_content_type_jar() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "com.example".to_string(),
            module: "mylib".to_string(),
            revision: Some("1.0".to_string()),
            artifact: Some("mylib-1.0".to_string()),
            ext: Some("jar".to_string()),
            is_ivy_descriptor: false,
        };
        let content_type = if path_info.is_ivy_descriptor {
            "application/xml"
        } else {
            "application/java-archive"
        };
        assert_eq!(content_type, "application/java-archive");
    }

    // -----------------------------------------------------------------------
    // Artifact name construction logic (from upload_artifact)
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_name_ivy_descriptor() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "com.example".to_string(),
            module: "mylib".to_string(),
            revision: Some("1.0".to_string()),
            artifact: None,
            ext: Some("xml".to_string()),
            is_ivy_descriptor: true,
        };
        let artifact_name = if path_info.is_ivy_descriptor {
            format!("{}/{}", path_info.org, path_info.module)
        } else {
            path_info
                .artifact
                .clone()
                .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
        };
        assert_eq!(artifact_name, "com.example/mylib");
    }

    #[test]
    fn test_artifact_name_with_artifact_field() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "org.apache".to_string(),
            module: "commons".to_string(),
            revision: Some("2.0".to_string()),
            artifact: Some("commons-2.0".to_string()),
            ext: Some("jar".to_string()),
            is_ivy_descriptor: false,
        };
        let artifact_name = if path_info.is_ivy_descriptor {
            format!("{}/{}", path_info.org, path_info.module)
        } else {
            path_info
                .artifact
                .clone()
                .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
        };
        assert_eq!(artifact_name, "commons-2.0");
    }

    #[test]
    fn test_artifact_name_no_artifact_field() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "io.spray".to_string(),
            module: "spray-json".to_string(),
            revision: Some("1.3.6".to_string()),
            artifact: None,
            ext: None,
            is_ivy_descriptor: false,
        };
        let artifact_name = if path_info.is_ivy_descriptor {
            format!("{}/{}", path_info.org, path_info.module)
        } else {
            path_info
                .artifact
                .clone()
                .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
        };
        assert_eq!(artifact_name, "io.spray/spray-json");
    }

    // -----------------------------------------------------------------------
    // Storage key construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_key_format() {
        let artifact_path = "com.example/mylib/1.0/jars/mylib-1.0.jar";
        let storage_key = format!("sbt/{}", artifact_path);
        assert_eq!(storage_key, "sbt/com.example/mylib/1.0/jars/mylib-1.0.jar");
    }

    // -----------------------------------------------------------------------
    // Content-Disposition filename extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_disposition_filename() {
        let path = "com.example/mylib/1.0/jars/mylib-1.0.jar";
        let filename = path.rsplit('/').next().unwrap_or(path);
        assert_eq!(filename, "mylib-1.0.jar");
    }

    #[test]
    fn test_content_disposition_filename_no_slash() {
        let path = "mylib.jar";
        let filename = path.rsplit('/').next().unwrap_or(path);
        assert_eq!(filename, "mylib.jar");
    }

    #[test]
    fn test_content_disposition_filename_deeply_nested() {
        let path = "org/example/subgroup/lib/1.0/jars/lib-1.0.jar";
        let filename = path.rsplit('/').next().unwrap_or(path);
        assert_eq!(filename, "lib-1.0.jar");
    }

    // -----------------------------------------------------------------------
    // Content type fallback (from download_by_path)
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_fallback_empty() {
        let content_type_raw = "";
        let content_type = if content_type_raw.is_empty() {
            "application/octet-stream"
        } else {
            content_type_raw
        };
        assert_eq!(content_type, "application/octet-stream");
    }

    #[test]
    fn test_content_type_no_fallback() {
        let content_type_raw = "application/xml";
        let content_type = if content_type_raw.is_empty() {
            "application/octet-stream"
        } else {
            content_type_raw
        };
        assert_eq!(content_type, "application/xml");
    }

    // -----------------------------------------------------------------------
    // SHA256 computation (from upload_artifact)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        use sha2::{Digest, Sha256};
        let body = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let computed = format!("{:x}", hasher.finalize());
        assert_eq!(
            computed,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_empty_body() {
        use sha2::{Digest, Sha256};
        let body = b"";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let computed = format!("{:x}", hasher.finalize());
        assert_eq!(
            computed,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // -----------------------------------------------------------------------
    // SBT metadata JSON construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbt_metadata_json() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "com.typesafe".to_string(),
            module: "config".to_string(),
            revision: Some("1.4.2".to_string()),
            artifact: Some("config-1.4.2".to_string()),
            ext: Some("jar".to_string()),
            is_ivy_descriptor: false,
        };
        let metadata = serde_json::json!({
            "org": path_info.org,
            "module": path_info.module,
            "revision": path_info.revision,
            "artifact": path_info.artifact,
            "ext": path_info.ext,
            "is_ivy_descriptor": path_info.is_ivy_descriptor,
        });
        assert_eq!(metadata["org"], "com.typesafe");
        assert_eq!(metadata["module"], "config");
        assert_eq!(metadata["revision"], "1.4.2");
        assert_eq!(metadata["artifact"], "config-1.4.2");
        assert_eq!(metadata["ext"], "jar");
        assert_eq!(metadata["is_ivy_descriptor"], false);
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_sbt_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "sbt").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![format!("/{k}/org/name/1.0.0/name-1.0.0.jar")];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }
}

// ---------------------------------------------------------------------------
// #3659: the native publish path must register the package catalog row.
// ---------------------------------------------------------------------------

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod catalog_registration_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    /// An Ivy upload must register the catalog row under `org/module` and the
    /// revision — never the filename stem, which embeds the revision. Every
    /// asset of one revision collapses into a single catalog version.
    #[tokio::test]
    async fn ivy_upload_registers_catalog_row() {
        let Some(fx) = tdh::Fixture::setup("local", "sbt").await else {
            return;
        };
        for asset in ["jars/my-lib_2.13-1.0.0.jar", "srcs/my-lib_2.13-1.0.0.jar"] {
            let (status, body) = tdh::send(
                fx.router_with_auth(super::router()),
                tdh::put(
                    format!("/{}/com.example/my-lib_2.13/1.0.0/{asset}", fx.repo_key),
                    bytes::Bytes::from(format!("bytes-of-{asset}")),
                ),
            )
            .await;
            assert!(
                status.is_success(),
                "sbt upload failed: {status} {}",
                String::from_utf8_lossy(&body)
            );
        }

        let row = tdh::catalog_row(&fx.pool, fx.repo_id, "com.example/my-lib_2.13").await;
        let filename_keyed = tdh::catalog_row(&fx.pool, fx.repo_id, "my-lib_2.13-1.0.0").await;
        fx.teardown().await;

        let row = row.expect("an sbt upload must write a packages row (#3659)");
        assert_eq!(row.version, "1.0.0");
        assert_eq!(row.versions, vec!["1.0.0".to_string()]);
        assert!(
            filename_keyed.is_none(),
            "the catalog must not be keyed on the filename stem"
        );
    }
}

/// #4100: scan-on-proxy on sbt's Ivy route, Remote and Virtual.
#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod scan_on_proxy_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const IVY_JAR: &str = "org.acme/widget_2.13/1.0/jars/widget_2.13.jar";

    async fn mount(server: &MockServer, route: &str, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(wpath(format!("/{route}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(server)
            .await;
    }

    #[test]
    fn scan_targets_read_ivy_and_maven_layouts() {
        let ivy = sbt_scan_target(IVY_JAR).expect("an Ivy jar is scanned");
        assert_eq!(ivy.path, IVY_JAR);
        assert_eq!(
            ivy.coordinate,
            Some(maven::JvmArchiveCoordinate {
                group_id: "org.acme".into(),
                artifact_id: "widget_2.13".into(),
                version: "1.0".into(),
            })
        );
        // sbt plugin layout with cross-version segments.
        let plugin =
            sbt_scan_target("org.acme/sbt-thing/scala_2.12/sbt_1.0/0.3.1/jars/sbt-thing.jar")
                .unwrap()
                .coordinate
                .unwrap();
        assert_eq!(plugin.artifact_id, "sbt-thing");
        assert_eq!(plugin.version, "0.3.1");
        // A Maven-layout upstream behind an sbt repository.
        let mvn = sbt_scan_target("org/acme/widget_2.13/1.0/widget_2.13-1.0.jar")
            .unwrap()
            .coordinate
            .unwrap();
        assert_eq!(mvn.group_id, "org.acme");
        // Cache-key aliases classify as the key itself, and any archive
        // spelling is scanned.
        for alias in [format!("{IVY_JAR}/"), format!("/{IVY_JAR}")] {
            assert_eq!(sbt_scan_target(&alias).expect("alias").path, IVY_JAR);
        }
        let upper = sbt_scan_target("org.acme/widget_2.13/1.0/jars/widget_2.13.JAR").unwrap();
        assert!(upper.coordinate.is_some());
        assert!(sbt_scan_target("odd/thing.jar")
            .unwrap()
            .coordinate
            .is_none());
        for passthrough in [
            "org.acme/widget_2.13/1.0/ivys/ivy.xml",
            "org.acme/widget_2.13/1.0/srcs/widget_2.13-sources.jar",
            "org.acme/widget_2.13/1.0/docs/widget_2.13-javadoc.jar",
            "org.acme/widget_2.13/1.0/jars/widget_2.13.jar.sha1",
            "org/acme/widget_2.13/1.0/widget_2.13-1.0.pom",
            "org.acme/widget_2.13/1.0/ivys/ivy-1.0.XML",
        ] {
            assert!(sbt_scan_target(passthrough).is_none(), "{passthrough}");
        }
        // Outside the allowlist everything is scanned, unpinned unless it is
        // a jar/war/ear naming a coordinate.
        for unknown in [
            "org.acme/widget_2.13/1.0/natives/widget.so",
            "org.acme/widget_2.13/1.0/jars/widget_2.13.jar.bak",
        ] {
            assert!(sbt_scan_target(unknown)
                .expect(unknown)
                .coordinate
                .is_none());
        }
    }

    /// Remote: a vulnerable Ivy jar is blocked, a clean one is served and
    /// recorded once, and the Ivy descriptor passes through unscanned.
    #[tokio::test]
    async fn remote_ivy_jar_is_gated_and_descriptor_passes_through() {
        let Some(fx) = tdh::Fixture::setup("remote", "sbt").await else {
            return;
        };
        let server = MockServer::start().await;
        let bad_route = "org.acme/bad/1.0/jars/bad.jar";
        let bad = tdh::maven_jar_fixture("org.acme", "bad", "1.0");
        let good = tdh::maven_jar_fixture("org.acme", "widget_2.13", "1.0");
        let descriptor_route = "org.acme/widget_2.13/1.0/ivys/ivy.xml";
        let descriptor = format!(
            "<ivy-module version=\"2.0\"><!-- {} --></ivy-module>",
            uuid::Uuid::new_v4()
        );
        mount(&server, bad_route, bad.clone()).await;
        mount(&server, IVY_JAR, good.clone()).await;
        mount(&server, descriptor_route, descriptor.clone().into_bytes()).await;
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        tdh::enable_proxy_scan(&fx.pool, fx.repo_id, "fail_open").await;
        let digests = vec![
            tdh::seed_proxy_verdict(&fx.pool, &bad, fx.repo_id, true).await,
            tdh::seed_proxy_verdict(&fx.pool, &good, fx.repo_id, false).await,
            tdh::seed_proxy_verdict(&fx.pool, descriptor.as_bytes(), fx.repo_id, true).await,
        ];
        let pull = |route: &str| {
            tdh::send_with_headers(
                tdh::router_anon(super::router(), state.clone()),
                tdh::get(format!("/{}/{route}", fx.repo_key)),
            )
        };

        let (status, body, _) = pull(bad_route).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "scan_blocked");
        assert_eq!(
            tdh::proxy_downloads_recorded(&fx.pool, fx.repo_id, bad_route).await,
            0
        );

        let (status, body, headers) = pull(IVY_JAR).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], &good[..]);
        assert_eq!(headers["X-AK-Scan"], "clean");
        assert_eq!(
            tdh::proxy_downloads_recorded(&fx.pool, fx.repo_id, IVY_JAR).await,
            1
        );

        let (status, body, headers) = pull(descriptor_route).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], descriptor.as_bytes());
        assert!(headers.get("X-AK-Scan").is_none());

        tdh::drop_proxy_verdicts(&fx.pool, &digests).await;
        drop(server);
        fx.teardown().await;
    }

    /// The trailing-slash alias of a refused Ivy jar reads the same cache
    /// entry, so it must be refused too: Remote and Virtual.
    #[tokio::test]
    async fn archive_aliases_are_gated_on_remote_and_virtual() {
        let Some(fx) = tdh::Fixture::setup("local", "sbt").await else {
            return;
        };
        let server = MockServer::start().await;
        let bytes = tdh::maven_jar_fixture("org.acme", "widget_2.13", "1.0");
        let upper = "org.acme/widget_2.13/1.0/jars/widget_2.13.JAR";
        mount(&server, IVY_JAR, bytes.clone()).await;
        mount(&server, upper, bytes.clone()).await;
        let (remote_id, remote_key, virtual_id, virtual_key) =
            tdh::create_remote_and_virtual(&fx.pool, "sbt", &server.uri()).await;
        tdh::enable_proxy_scan(&fx.pool, remote_id, "fail_closed").await;
        let digest = tdh::seed_proxy_verdict(&fx.pool, &bytes, remote_id, true).await;
        let dir = tempfile::tempdir().unwrap();
        let storage = dir.path().to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage, proxy);

        for key in [&remote_key, &virtual_key] {
            for route in [
                IVY_JAR.to_string(),
                format!("{IVY_JAR}/"),
                upper.to_string(),
            ] {
                let (status, body) = tdh::send(
                    tdh::router_anon(super::router(), state.clone()),
                    tdh::get(format!("/{key}/{route}")),
                )
                .await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{key} {route}");
                assert_ne!(&body[..], &bytes[..], "{key} {route}");
            }
        }

        tdh::drop_proxy_verdicts(&fx.pool, &[digest]).await;
        drop(server);
        tdh::cleanup_member_repo(&fx.pool, remote_id, dir.path()).await;
        tdh::cleanup_member_repo(&fx.pool, virtual_id, dir.path()).await;
        fx.teardown().await;
    }

    /// Ambiguous spellings are refused (400), an unknown extension is
    /// scanned, and the allowlisted Ivy descriptor passes through: Remote and
    /// Virtual.
    #[tokio::test]
    async fn ambiguous_paths_refused_unknown_extensions_gated_on_remote_and_virtual() {
        let Some(fx) = tdh::Fixture::setup("local", "sbt").await else {
            return;
        };
        let server = MockServer::start().await;
        let blob_route = "org.acme/widget_2.13/1.0/natives/widget.so";
        let ivy_route = "org.acme/widget_2.13/1.0/ivys/ivy.xml";
        let blob = format!("native-{}", uuid::Uuid::new_v4()).into_bytes();
        let ivy =
            format!("<ivy-module><!-- {} --></ivy-module>", uuid::Uuid::new_v4()).into_bytes();
        mount(&server, blob_route, blob.clone()).await;
        mount(&server, ivy_route, ivy.clone()).await;
        let (remote_id, remote_key, virtual_id, virtual_key) =
            tdh::create_remote_and_virtual(&fx.pool, "sbt", &server.uri()).await;
        tdh::enable_proxy_scan(&fx.pool, remote_id, "fail_closed").await;
        let digests = vec![
            tdh::seed_proxy_verdict(&fx.pool, &blob, remote_id, true).await,
            tdh::seed_proxy_verdict(&fx.pool, &ivy, remote_id, true).await,
        ];
        let dir = tempfile::tempdir().unwrap();
        let storage = dir.path().to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage, proxy);
        let pull = |key: &str, route: &str| {
            tdh::send_with_headers(
                tdh::router_anon(super::router(), state.clone()),
                tdh::get(format!("/{key}/{route}")),
            )
        };

        for key in [&remote_key, &virtual_key] {
            for route in [
                format!("{IVY_JAR}%3Fx"),
                format!("{IVY_JAR}%23x"),
                format!("{IVY_JAR};jsessionid=x"),
                format!("{IVY_JAR}%3Bjsessionid=x"),
                format!("{IVY_JAR}."),
                format!("{IVY_JAR}%09"),
                "org.acme/widget_2.13/1.0/jars/widget_2.13.ja%09r".to_string(),
                "org.acme/widget_2.13/1.0/jars/widget_2.13.ja%2572".to_string(),
                "org.acme/widget_2.13/1.0/jars/widget%202.13.jar".to_string(),
            ] {
                let (status, _, _) = pull(key, &route).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{key} {route}");
            }
            let (status, body, _) = pull(key, blob_route).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{key}");
            assert_ne!(&body[..], &blob[..], "{key}");
            let (status, body, headers) = pull(key, ivy_route).await;
            assert_eq!(status, StatusCode::OK, "{key}");
            assert_eq!(&body[..], &ivy[..], "{key}");
            assert!(headers.get("X-AK-Scan").is_none(), "{key}");
        }

        tdh::drop_proxy_verdicts(&fx.pool, &digests).await;
        drop(server);
        tdh::cleanup_member_repo(&fx.pool, remote_id, dir.path()).await;
        tdh::cleanup_member_repo(&fx.pool, virtual_id, dir.path()).await;
        fx.teardown().await;
    }

    /// Virtual: a scanning member's vulnerable jar is blocked, and its
    /// quarantine hold is final rather than a miss.
    #[tokio::test]
    async fn virtual_member_scan_blocks_and_holds_are_final() {
        let Some(fx) = tdh::Fixture::setup("virtual", "sbt").await else {
            return;
        };
        let bad = tdh::maven_jar_fixture("org.acme", "widget_2.13", "1.0");
        let first_up = MockServer::start().await;
        mount(&first_up, IVY_JAR, bad.clone()).await;
        let (first, _, first_dir) =
            tdh::attach_remote_member(&fx.pool, fx.repo_id, "sbt", &first_up.uri(), 1).await;
        tdh::enable_proxy_scan(&fx.pool, first, "fail_open").await;
        let digest = tdh::seed_proxy_verdict(&fx.pool, &bad, first, true).await;
        let storage = fx.storage_dir.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage, proxy);
        let get = || {
            tdh::send(
                tdh::router_anon(super::router(), state.clone()),
                tdh::get(format!("/{}/{IVY_JAR}", fx.repo_key)),
            )
        };

        let (status, _) = get().await;
        assert_eq!(status, StatusCode::FORBIDDEN, "vulnerable member bytes");

        // A held (quarantined) scanning member stops the walk before a
        // lower-priority member could serve a different copy.
        let held_route = "org.acme/held/1.0/jars/held.jar";
        let held_jar = tdh::maven_jar_fixture("org.acme", "held", "1.0");
        let held_up = MockServer::start().await;
        mount(&held_up, held_route, held_jar.clone()).await;
        let fallback = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wpath(format!("/{held_route}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(held_jar))
            .expect(0)
            .mount(&fallback)
            .await;
        sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        let (held, _, held_dir) =
            tdh::attach_remote_member(&fx.pool, fx.repo_id, "sbt", &held_up.uri(), 1).await;
        let (second, _, second_dir) =
            tdh::attach_remote_member(&fx.pool, fx.repo_id, "sbt", &fallback.uri(), 2).await;
        for member in [held, second] {
            tdh::enable_proxy_scan(&fx.pool, member, "fail_open").await;
        }
        tdh::enable_proxy_quarantine(&fx.pool, held, 60).await;
        let (status, _) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            tdh::get(format!("/{}/{held_route}", fx.repo_key)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the hold is final, not a miss"
        );
        fallback.verify().await;

        tdh::drop_proxy_verdicts(&fx.pool, &[digest]).await;
        tdh::cleanup_member_repo(&fx.pool, first, &first_dir).await;
        tdh::cleanup_member_repo(&fx.pool, held, &held_dir).await;
        tdh::cleanup_member_repo(&fx.pool, second, &second_dir).await;
        fx.teardown().await;
    }
}

/// #4365 item 1: sbt `(cache_key, scannable)` decisions, through the Maven
/// helper both JVM routes share, for the Ivy and the Maven layouts.
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod serve_key_4365_tests {
    use super::*;

    #[test]
    fn sbt_serve_key_table() {
        for (path, key, scannable) in [
            (
                "org.acme/widget_2.13/1.0/jars/widget_2.13.jar",
                "org.acme/widget_2.13/1.0/jars/widget_2.13.jar",
                true,
            ),
            (
                "org.acme/widget_2.13/1.0/jars/widget_2.13.jar/",
                "org.acme/widget_2.13/1.0/jars/widget_2.13.jar",
                true,
            ),
            (
                "org.acme/widget_2.13/1.0/ivys/ivy.xml",
                "org.acme/widget_2.13/1.0/ivys/ivy.xml",
                false,
            ),
            (
                "org/acme/widget_2.13/1.0/widget_2.13-1.0.pom",
                "org/acme/widget_2.13/1.0/widget_2.13-1.0.pom",
                false,
            ),
        ] {
            let got = maven::jvm_proxy_serve_key(path);
            assert_eq!(
                (got.cache_key.as_str(), got.scannable),
                (key, scannable),
                "{path}"
            );
            let target = sbt_scan_target(path);
            assert_eq!(target.is_some(), scannable, "{path}");
            if let Some(target) = target {
                assert_eq!(target.path, key, "{path}");
            }
        }
    }
}
