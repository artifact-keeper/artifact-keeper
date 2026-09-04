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
                    // #1608 Phase 4: stream the artifact body (sbt/ivy .jar and
                    // friends can be large) to the client while teeing to the
                    // proxy cache, instead of buffering it in memory.
                    // Single-flight via the merged coordinator (#1609).
                    // UNRECORDED-PROXY-SERVE: #3446 - deferred, not exempt. This arm serves
                    // upstream/proxy-cached bytes without counting them, so this format's
                    // Downloads column reads 0 no matter how heavily the proxy is used. It is
                    // a reporting gap, not a serving defect: the artifact is returned
                    // correctly either way. The fix is the shape the cargo / debian / goproxy
                    // / helm / nuget / oci_v2 arms now carry - record against the proxy-cache
                    // path this fetch commits under, AFTER the fetch resolves so a 404 or 502
                    // is not counted. Removing this marker without adding that call fails the
                    // class guard in proxy_helpers.rs.
                    // #3459: carry the real format. `proxy_fetch_streaming`
                    // synthesizes a `Generic` repository, and `Generic` has no
                    // `cache_classifier` arm, so every sbt/ivy `.jar`, `.pom`
                    // and checksum sidecar was cached with the conservative
                    // 5-minute mutable TTL and re-fetched from upstream after
                    // it. Sbt shares Maven's classifier rules.
                    return proxy_helpers::proxy_fetch_streaming_with_format(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        artifact_path,
                        "application/octet-stream",
                        RepositoryFormat::Sbt,
                    )
                    .await;
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
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
                format!("Storage error: {}", e),
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
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let sbt_metadata = serde_json::json!({
        "org": path_info.org,
        "module": path_info.module,
        "revision": path_info.revision,
        "artifact": path_info.artifact,
        "ext": path_info.ext,
        "is_ivy_descriptor": path_info.is_ivy_descriptor,
    });

    let size_bytes = body.len() as i64;

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
    .fetch_one(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
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
        /// a decade); anything above a year is not a mutable TTL.
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

        // Mutable paths carry the repository's TTL, which for a fixture repo
        // with no override is the application default (#3706).
        let mutable = crate::services::proxy_service::DEFAULT_CACHE_TTL_SECS;
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
