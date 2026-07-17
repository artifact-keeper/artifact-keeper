//! CocoaPods Spec Repo API handlers.
//!
//! Implements the endpoints required for CocoaPods pod install and pod push.
//!
//! Routes are mounted at `/cocoapods/{repo_key}/...`:
//!   GET  /cocoapods/{repo_key}/CocoaPods-version.yml                     - CDN entrypoint
//!   GET  /cocoapods/{repo_key}/all_pods_versions_{a}_{b}_{c}.txt         - CDN shard index
//!   GET  /cocoapods/{repo_key}/deprecated_podspecs.txt                   - CDN deprecation list
//!   GET  /cocoapods/{repo_key}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json - Get podspec (CDN)
//!   GET  /cocoapods/{repo_key}/Specs/{name}/{version}/{name}.podspec.json - Get podspec (flat)
//!   GET  /cocoapods/{repo_key}/pods/{name}-{version}.tar.gz              - Download pod archive
//!   POST /cocoapods/{repo_key}/pods                                      - Push pod (auth required)
//!   GET  /cocoapods/{repo_key}/all_specs                                 - List all specs
//!
//! A real CocoaPods client resolves pods over the CDN layout: it probes
//! `CocoaPods-version.yml` to recognise the URL as a CDN source and to learn the
//! shard fan-out, reads the pre-rendered `all_pods_versions_*` index for the
//! shard a pod name hashes into, then fetches the podspec from the MD5-sharded
//! `Specs/` tree. Those files are generated on demand from the repository's
//! artifacts; see `crate::formats::cocoapods` for the layout rules. The flat
//! `Specs/{name}/{version}/...` layout and the `all_specs` JSON listing predate
//! CDN support and are kept for existing callers.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::cocoapods::{self, CocoaPodsHandler};
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Push pod
        .route("/:repo_key/pods", post(push_pod))
        // List all specs
        .route("/:repo_key/all_specs", get(all_specs))
        // CDN entrypoint
        .route(
            &format!("/:repo_key/{}", cocoapods::CDN_VERSION_FILE),
            get(cdn_version_file),
        )
        // CDN deprecation list
        .route(
            &format!("/:repo_key/{}", cocoapods::CDN_DEPRECATED_PODSPECS_FILE),
            get(cdn_deprecated_podspecs),
        )
        // CDN shard index (all_pods_versions_{a}_{b}_{c}.txt). The shard is part
        // of the file name rather than the path, so this is matched as a single
        // segment and validated in the handler.
        .route("/:repo_key/:index_file", get(cdn_all_pods_versions))
        // Get podspec (CDN sharded layout and flat layout, dispatched by shape)
        .route("/:repo_key/Specs/*spec_path", get(get_podspec))
        // Download pod archive
        .route("/:repo_key/pods/*pod_file", get(download_pod))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_cocoapods_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["cocoapods"], "a CocoaPods").await
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/CocoaPods-version.yml
// ---------------------------------------------------------------------------
//
// The CDN entrypoint. `pod repo add-cdn`, and the Podfile `source` resolution
// that follows it, GET this file first: a URL that does not serve it is not
// treated as a CDN source at all, so every later request is never made. The
// body tells the client the shard fan-out to use (`prefix_lengths`) and the
// minimum client version the layout supports (`Source::Metadata`).

async fn cdn_version_file(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let body = serde_yaml::to_string(&cocoapods::CdnMetadata::default()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to render CDN metadata: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/yaml")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/deprecated_podspecs.txt
// ---------------------------------------------------------------------------
//
// The CDN's list of deprecated podspec paths. Artifact Keeper does not track
// podspec deprecation, so the list is empty, but it still has to be served: the
// client reads the file straight back off disk after downloading it
// (`CDNSource#deprecated_local_podspecs`) and a 404 leaves nothing to read.

async fn cdn_deprecated_podspecs(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    resolve_cocoapods_repo(&state.db, &repo_key).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/all_pods_versions_{a}_{b}_{c}.txt
// ---------------------------------------------------------------------------
//
// A CDN cannot be listed, so the client cannot discover a pod's versions by
// walking the `Specs/` tree. Instead each shard publishes a pre-rendered index
// of every pod that hashes into it, one pod per line:
//
//     <pod>/<version>/<version>/...
//
// The client picks the index file from the pod name alone, so a pod is only
// resolvable if it appears in the index for its own shard.

async fn cdn_all_pods_versions(
    State(state): State<SharedState>,
    Path((repo_key, index_file)): Path<(String, String)>,
) -> Result<Response, Response> {
    let shard = cocoapods::parse_cdn_index_file_name(&index_file)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Not found").into_response())?;
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT name, version
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    // Group versions by pod name, keeping only the pods that hash into the
    // requested shard. BTree collections give the deterministic, sorted output
    // the trunk CDN publishes; the client sorts versions itself, so the order
    // within a line is presentational only.
    let mut versions_by_pod: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for artifact in artifacts {
        let Some(version) = artifact.version else {
            continue;
        };
        if version.is_empty() || cocoapods::cdn_shard_fragment(&artifact.name) != shard {
            continue;
        }
        versions_by_pod
            .entry(artifact.name)
            .or_default()
            .insert(version);
    }

    let mut body = String::new();
    for (pod, versions) in &versions_by_pod {
        body.push_str(pod);
        for version in versions {
            body.push('/');
            body.push_str(version);
        }
        body.push('\n');
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json
// GET /cocoapods/{repo_key}/Specs/{name}/{version}/{name}.podspec.json
// ---------------------------------------------------------------------------

async fn get_podspec(
    State(state): State<SharedState>,
    Path((repo_key, spec_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let spec_path = spec_path.trim_start_matches('/');

    // Validate via the format handler, which accepts both the CDN MD5-sharded
    // layout and the flat layout.
    let full_path = format!("Specs/{}", spec_path);
    let path_info = CocoaPodsHandler::parse_path(&full_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    // Find the artifact
    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.storage_key, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo.id,
        path_info.name,
        path_info.version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Podspec not found").into_response())?;

    // Return the podspec from metadata if available, otherwise read from storage
    let podspec_from_meta: Option<String> = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("podspec"))
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    if let Some(podspec_json) = podspec_from_meta {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(podspec_json))
            .unwrap());
    }

    // Fall back to reading the podspec file from storage
    let podspec_key = format!(
        "cocoapods/{}/{}/{}.podspec.json",
        path_info.name, path_info.version, path_info.name
    );
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let content = storage.get(&podspec_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/pods/{name}-{version}.tar.gz — Download pod archive
// ---------------------------------------------------------------------------

async fn download_pod(
    State(state): State<SharedState>,
    Path((repo_key, pod_file)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let filename = pod_file.trim_start_matches('/');

    // Parse the pod path to extract name and version
    let full_path = format!("pods/{}", filename);
    let path_info = CocoaPodsHandler::parse_path(&full_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    // Find artifact by name and version
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        path_info.name,
        path_info.version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Pod not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("pods/{}", filename);
                    // #1608 Phase 4: stream the pod archive to the client while
                    // teeing to the proxy cache, instead of buffering the whole
                    // pod in memory. Single-flight via the merged coordinator
                    // (#1609).
                    return proxy_helpers::proxy_fetch_streaming(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                        "application/octet-stream",
                    )
                    .await;
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!("pods/{}", filename);
                let vname = path_info.name.clone();
                let vversion = path_info.version.clone();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db, &state, member_id, &location, &vname, &vversion,
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
            return Err(not_found);
        }
    };

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

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

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /cocoapods/{repo_key}/pods — Push pod (body is tar.gz with podspec)
// ---------------------------------------------------------------------------

async fn push_pod(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, "cocoapods", "write")?.user_id;
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty pod archive").into_response());
    }

    // Try to extract podspec from the archive body.
    // The body should contain a tar.gz with a podspec.json inside.
    // #2561: permit-scoped decode, fast-fail 503 on saturation.
    let podspec = crate::util::bounded_archive::with_ingest_extraction(|| {
        extract_podspec_from_archive(&body)
    })
    .map_err(|e| e.into_response())?
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid pod archive: {}", e),
        )
            .into_response()
    })?;

    let pod_name = &podspec.name;
    let pod_version = &podspec.version;

    if pod_name.is_empty() || pod_version.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Pod name and version are required").into_response());
    }

    let filename = format!("{}-{}.tar.gz", pod_name, pod_version);
    let artifact_path = format!("{}/{}/{}", pod_name, pod_version, filename);

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
        return Err((StatusCode::CONFLICT, "Pod version already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the pod archive
    let storage_key = format!("cocoapods/{}/{}/{}", pod_name, pod_version, filename);
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

    // Also store the podspec JSON separately for direct retrieval
    let podspec_key = format!(
        "cocoapods/{}/{}/{}.podspec.json",
        pod_name, pod_version, pod_name
    );
    let podspec_json = serde_json::to_vec(&podspec).unwrap_or_default();
    proxy_helpers::guard_cross_repo_write(&state, repo.id, &repo.storage_backend, &podspec_key)
        .await?;
    storage
        .put(&podspec_key, Bytes::from(podspec_json))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    // Build metadata JSON
    let pod_metadata = serde_json::json!({
        "podspec": serde_json::to_value(&podspec).unwrap_or_default(),
        "filename": filename,
    });

    let size_bytes = body.len() as i64;

    // Insert artifact record
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
        pod_name,
        pod_version.to_string(),
        size_bytes,
        computed_sha256,
        "application/gzip",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    // Store metadata
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'cocoapods', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        pod_metadata,
    )
    .execute(&state.db)
    .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "CocoaPods push: {} {} ({}) to repo {}",
        pod_name, pod_version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Successfully registered pod"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/all_specs — List all specs (JSON)
// ---------------------------------------------------------------------------

async fn all_specs(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.name, a.version, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY a.name, a.created_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    // Group versions by pod name
    let mut specs: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for a in &artifacts {
        let name = a.name.clone();
        let version = a.version.clone().unwrap_or_default();

        let summary = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("podspec"))
            .and_then(|ps| ps.get("summary"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let version_info = serde_json::json!({
            "version": version,
            "summary": summary,
        });

        specs.entry(name).or_default().push(version_info);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&specs).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use crate::formats::cocoapods::PodSpec;

/// Extract a podspec.json from a tar.gz archive.
///
/// Scans the archive entries for any file ending in `.podspec.json` and
/// deserializes it into a PodSpec.
fn extract_podspec_from_archive(data: &[u8]) -> Result<PodSpec, String> {
    // Bound the gzip/tar decompression: total-byte budget + entry-count cap +
    // per-metadata-entry cap so a crafted pod archive cannot inflate unbounded
    // during metadata parsing (#2556).
    let contents = crate::util::bounded_archive::read_metadata_from_tar_gz(data, |path| {
        path.to_string_lossy().ends_with(".podspec.json")
    })
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "No .podspec.json found in archive".to_string())?;

    let podspec: PodSpec =
        serde_json::from_slice(&contents).map_err(|e| format!("Invalid podspec JSON: {}", e))?;

    Ok(podspec)
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_remote_pod_download_streams_upstream_blob_1608() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "cocoapods").await else {
            return;
        };
        let server = MockServer::start().await;
        // A small deterministic body stands in for a large artifact; the point
        // is to exercise the streaming pull-through branch (proxy_fetch_streaming)
        // added in #1608 Phase 4, not the body size.
        let blob: &[u8] = b"\x00\x01\x02 #1608 phase4 streamed proxy blob \x03\x04\x05";
        Mock::given(method("GET"))
            .and(path("/pods/AFNetworking-4.0.1.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{key}/pods/AFNetworking-4.0.1.tar.gz",
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
    use super::*;
    use crate::formats::cocoapods::PodSpec;

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Build the filename for a CocoaPods archive.
    fn build_cocoapods_filename(name: &str, version: &str) -> String {
        format!("{}-{}.tar.gz", name, version)
    }

    /// Build the artifact path for a CocoaPods package.
    fn build_cocoapods_artifact_path(name: &str, version: &str) -> String {
        let filename = build_cocoapods_filename(name, version);
        format!("{}/{}/{}", name, version, filename)
    }

    /// Build the storage key for a CocoaPods archive.
    fn build_cocoapods_storage_key(name: &str, version: &str) -> String {
        let filename = build_cocoapods_filename(name, version);
        format!("cocoapods/{}/{}/{}", name, version, filename)
    }

    /// Build the storage key for a CocoaPods podspec JSON file.
    fn build_cocoapods_podspec_key(name: &str, version: &str) -> String {
        format!("cocoapods/{}/{}/{}.podspec.json", name, version, name)
    }

    /// Build the metadata JSON for a published pod.
    fn build_cocoapods_metadata(podspec: &PodSpec, filename: &str) -> serde_json::Value {
        serde_json::json!({
            "podspec": serde_json::to_value(podspec).unwrap_or_default(),
            "filename": filename,
        })
    }

    // -----------------------------------------------------------------------
    // CDN routing
    // -----------------------------------------------------------------------

    /// The CDN shard index is matched as a bare path segment, so it sits
    /// alongside the static `all_specs` / `Specs` / `pods` segments in the same
    /// position. Building the router asserts those do not collide.
    #[test]
    fn test_router_builds_with_cdn_routes() {
        let _ = super::router();
    }

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // extract_podspec_from_archive
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_podspec_from_archive_empty() {
        let result = extract_podspec_from_archive(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_podspec_from_archive_invalid_data() {
        let result = extract_podspec_from_archive(b"not a gzip archive");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_podspec_from_archive_no_podspec() {
        // Create a valid tar.gz with no .podspec.json file
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let data = b"random content";
            let mut header = tar::Header::new_gnu();
            header.set_path("README.md").unwrap();
            header.set_size(data.len() as u64);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let compressed = gz.finish().unwrap();

        let result = extract_podspec_from_archive(&compressed);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No .podspec.json found"));
    }

    #[test]
    fn test_extract_podspec_from_archive_valid() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let podspec_json = serde_json::json!({
            "name": "Alamofire",
            "version": "5.8.0",
            "summary": "HTTP Networking in Swift",
            "homepage": "https://github.com/Alamofire/Alamofire",
        });
        let podspec_bytes = serde_json::to_vec(&podspec_json).unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_path("Alamofire.podspec.json").unwrap();
            header.set_size(podspec_bytes.len() as u64);
            header.set_cksum();
            builder.append(&header, &podspec_bytes[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let compressed = gz.finish().unwrap();

        let result = extract_podspec_from_archive(&compressed);
        assert!(result.is_ok());
        let podspec = result.unwrap();
        assert_eq!(podspec.name, "Alamofire");
        assert_eq!(podspec.version, "5.8.0");
    }

    /// End-to-end regression for #1286 at the handler layer: a publisher
    /// uploads a tar.gz whose `*.podspec.json` carries linker fields that the
    /// `PodSpec` struct historically did not name (`vendored_frameworks`,
    /// `xcconfig`, `preserve_paths`, `requires_arc`, `documentation_url`,
    /// `screenshots`). After extraction + serialization, every one of those
    /// fields must still be present in the JSON that the
    /// `Specs/<name>/<version>/<name>.podspec.json` endpoint will serve to the
    /// CocoaPods client.
    #[test]
    fn test_extract_podspec_from_archive_preserves_linker_fields() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let podspec_json = serde_json::json!({
            "name": "MyLibrary",
            "version": "2.8.45",
            "summary": "MyCompany MyLibrary",
            "description": "Library of my company",
            "homepage": "https://github.com/",
            "documentation_url": "https://github.com/",
            "screenshots": "https://github.com/",
            "license": { "type": "Apache 2.0", "file": "LICENSE" },
            "authors": { "My Company": "devteam@my.company" },
            "platforms": { "osx": "10.13", "ios": "11.2" },
            "source": { "http": "https://ak.int.local/cocoapods/repo/pods/MyLibrary-2.8.45.tar.gz" },
            "preserve_paths": ["MyLibrary.xcframework"],
            "vendored_frameworks": "MyLibrary.xcframework",
            "xcconfig": { "LD_RUNPATH_SEARCH_PATHS": "@loader_path/../Frameworks" },
            "requires_arc": true,
        });
        let podspec_bytes = serde_json::to_vec(&podspec_json).unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_path("MyLibrary.podspec.json").unwrap();
            header.set_size(podspec_bytes.len() as u64);
            header.set_cksum();
            builder.append(&header, &podspec_bytes[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let compressed = gz.finish().unwrap();

        let podspec = extract_podspec_from_archive(&compressed).unwrap();
        assert_eq!(podspec.name, "MyLibrary");
        assert_eq!(podspec.version, "2.8.45");

        // Re-serialize as the handler would when storing or serving the JSON.
        let served = serde_json::to_value(&podspec).unwrap();
        for field in [
            "documentation_url",
            "screenshots",
            "preserve_paths",
            "vendored_frameworks",
            "xcconfig",
            "requires_arc",
            "description",
        ] {
            assert_eq!(
                served.get(field),
                podspec_json.get(field),
                "podspec field {} was dropped between archive extraction and serving (regression for #1286)",
                field,
            );
        }
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_filename() {
        assert_eq!(
            build_cocoapods_filename("Alamofire", "5.8.0"),
            "Alamofire-5.8.0.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_filename_prerelease() {
        assert_eq!(
            build_cocoapods_filename("Moya", "15.0.0-beta.1"),
            "Moya-15.0.0-beta.1.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_filename_ends_with_tar_gz() {
        let f = build_cocoapods_filename("SnapKit", "5.7.1");
        assert!(f.ends_with(".tar.gz"));
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_artifact_path() {
        assert_eq!(
            build_cocoapods_artifact_path("Moya", "15.0.0"),
            "Moya/15.0.0/Moya-15.0.0.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_artifact_path_simple() {
        assert_eq!(
            build_cocoapods_artifact_path("SnapKit", "5.7.1"),
            "SnapKit/5.7.1/SnapKit-5.7.1.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_artifact_path_contains_name() {
        let path = build_cocoapods_artifact_path("AFNetworking", "4.0.0");
        assert!(path.starts_with("AFNetworking/"));
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_storage_key() {
        assert_eq!(
            build_cocoapods_storage_key("SnapKit", "5.7.1"),
            "cocoapods/SnapKit/5.7.1/SnapKit-5.7.1.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_storage_key_starts_with_cocoapods() {
        let key = build_cocoapods_storage_key("Alamofire", "5.8.0");
        assert!(key.starts_with("cocoapods/"));
    }

    #[test]
    fn test_build_cocoapods_storage_key_ends_with_tar_gz() {
        let key = build_cocoapods_storage_key("Moya", "15.0.0");
        assert!(key.ends_with(".tar.gz"));
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_podspec_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_podspec_key() {
        assert_eq!(
            build_cocoapods_podspec_key("AFNetworking", "4.0.0"),
            "cocoapods/AFNetworking/4.0.0/AFNetworking.podspec.json"
        );
    }

    #[test]
    fn test_build_cocoapods_podspec_key_ends_with_podspec_json() {
        let key = build_cocoapods_podspec_key("Alamofire", "5.8.0");
        assert!(key.ends_with(".podspec.json"));
    }

    #[test]
    fn test_build_cocoapods_podspec_key_contains_name_twice() {
        let key = build_cocoapods_podspec_key("SnapKit", "5.7.1");
        // The name appears in both the directory path and the filename
        assert_eq!(key.matches("SnapKit").count(), 2); // cocoapods/SnapKit/5.7.1/SnapKit.podspec.json
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_metadata() {
        let podspec = PodSpec {
            name: "Alamofire".to_string(),
            version: "5.8.0".to_string(),
            summary: Some("HTTP Networking in Swift".to_string()),
            homepage: Some("https://github.com/Alamofire/Alamofire".to_string()),
            license: None,
            authors: None,
            source: None,
            platforms: None,
            dependencies: None,
            extra: std::collections::HashMap::new(),
        };
        let meta = build_cocoapods_metadata(&podspec, "Alamofire-5.8.0.tar.gz");
        assert_eq!(meta["filename"], "Alamofire-5.8.0.tar.gz");
        assert!(meta["podspec"].is_object());
        assert_eq!(meta["podspec"]["name"], "Alamofire");
        assert_eq!(meta["podspec"]["version"], "5.8.0");
    }

    #[test]
    fn test_build_cocoapods_metadata_has_two_keys() {
        let podspec = PodSpec {
            name: "Moya".to_string(),
            version: "15.0.0".to_string(),
            summary: Some("Network abstraction layer".to_string()),
            homepage: Some("https://github.com/Moya/Moya".to_string()),
            license: None,
            authors: None,
            source: None,
            platforms: None,
            dependencies: None,
            extra: std::collections::HashMap::new(),
        };
        let meta = build_cocoapods_metadata(&podspec, "Moya-15.0.0.tar.gz");
        assert_eq!(meta.as_object().unwrap().len(), 2);
    }

    #[test]
    fn test_build_cocoapods_metadata_podspec_fields() {
        let podspec = PodSpec {
            name: "RxSwift".to_string(),
            version: "6.6.0".to_string(),
            summary: Some("Reactive Programming in Swift".to_string()),
            homepage: Some("https://github.com/ReactiveX/RxSwift".to_string()),
            license: None,
            authors: None,
            source: None,
            platforms: None,
            dependencies: None,
            extra: std::collections::HashMap::new(),
        };
        let meta = build_cocoapods_metadata(&podspec, "RxSwift-6.6.0.tar.gz");
        assert_eq!(meta["podspec"]["summary"], "Reactive Programming in Swift");
        assert_eq!(
            meta["podspec"]["homepage"],
            "https://github.com/ReactiveX/RxSwift"
        );
    }

    // -----------------------------------------------------------------------
    // SHA256 computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"pod content");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/cocoapods".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
        };
        assert_eq!(repo.id, id);
        assert_eq!(repo.repo_type, "hosted");
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/cache/cocoapods".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://cdn.cocoapods.org/".to_string()),
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://cdn.cocoapods.org/")
        );
    }
}

#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    /// #2561: an authenticated pod push decodes the podspec through the
    /// permit-scoped decode (uncontended) and stores the pod.
    #[tokio::test]
    async fn test_cocoapods_push_pod_succeeds_2561() {
        let Some(fx) = tdh::Fixture::setup("local", "cocoapods").await else {
            return;
        };
        let podspec_bytes = serde_json::to_vec(&serde_json::json!({
            "name": "PushPod",
            "version": "1.0.0",
            "summary": "coverage pod",
        }))
        .unwrap();
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_path("PushPod.podspec.json").unwrap();
            header.set_size(podspec_bytes.len() as u64);
            header.set_cksum();
            builder.append(&header, &podspec_bytes[..]).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let targz = gz.finish().unwrap();

        let app = fx.router_with_auth(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/pods", fx.repo_key))
            .body(axum::body::Body::from(targz))
            .unwrap();
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "pod push must succeed: {} {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );
        fx.teardown().await;
    }

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_cocoapods_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "cocoapods").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/pods"),
            format!("/{k}/all_specs"),
            format!("/{k}/Specs/name/1.0.0/name.podspec"),
            format!("/{k}/pods/x.tar.gz"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }

    /// Build a pushable pod archive carrying just a `<name>.podspec.json`.
    fn pod_archive(name: &str, version: &str) -> Vec<u8> {
        let podspec_bytes = serde_json::to_vec(&serde_json::json!({
            "name": name,
            "version": version,
            "summary": "cdn layout pod",
        }))
        .unwrap();
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_path(format!("{}.podspec.json", name)).unwrap();
            header.set_size(podspec_bytes.len() as u64);
            header.set_cksum();
            builder.append(&header, &podspec_bytes[..]).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        gz.finish().unwrap()
    }

    async fn push_pod(fx: &tdh::Fixture, name: &str, version: &str) {
        let app = fx.router_with_auth(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/pods", fx.repo_key))
            .body(axum::body::Body::from(pod_archive(name, version)))
            .unwrap();
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "pod push must succeed: {} {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );
    }

    /// The CDN entrypoint has to be served for a client to treat the repo as a
    /// CDN source at all, and it has to advertise the shard fan-out that the
    /// index/Specs routes are keyed by.
    #[tokio::test]
    async fn test_cocoapods_cdn_version_file_served() {
        let Some(fx) = tdh::Fixture::setup("local", "cocoapods").await else {
            return;
        };
        let app = fx.router_with_auth(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/CocoaPods-version.yml", fx.repo_key)),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);

        let meta: crate::formats::cocoapods::CdnMetadata =
            serde_yaml::from_slice(&body[..]).expect("CocoaPods-version.yml must be valid YAML");
        assert_eq!(
            meta.prefix_lengths,
            crate::formats::cocoapods::CDN_PREFIX_LENGTHS.to_vec()
        );
        assert_eq!(
            meta.min,
            crate::formats::cocoapods::CDN_MIN_COCOAPODS_VERSION
        );
        fx.teardown().await;
    }

    /// `deprecated_podspecs.txt` is read straight back off disk by the client
    /// after download, so it must resolve even though we never deprecate.
    #[tokio::test]
    async fn test_cocoapods_cdn_deprecated_podspecs_served_empty() {
        let Some(fx) = tdh::Fixture::setup("local", "cocoapods").await else {
            return;
        };
        let app = fx.router_with_auth(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/deprecated_podspecs.txt", fx.repo_key)),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(body.is_empty());
        fx.teardown().await;
    }

    /// A pushed pod must be listed in the index file for the shard its name
    /// hashes into, in the `<pod>/<version>...` line format the client parses,
    /// and must not leak into any other shard.
    #[tokio::test]
    async fn test_cocoapods_cdn_index_lists_pod_in_its_own_shard() {
        let Some(fx) = tdh::Fixture::setup("local", "cocoapods").await else {
            return;
        };
        push_pod(&fx, "Alamofire", "5.8.0").await;
        push_pod(&fx, "Alamofire", "5.9.0").await;

        // Alamofire hashes to shard d/a/2 (pinned against the trunk CDN).
        let index_file = crate::formats::cocoapods::cdn_index_file_name("Alamofire");
        assert_eq!(index_file, "all_pods_versions_d_a_2.txt");

        let app = fx.router_with_auth(super::router());
        let (status, body) =
            tdh::send(app, tdh::get(format!("/{}/{}", fx.repo_key, index_file))).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(
            text.lines().collect::<Vec<_>>(),
            vec!["Alamofire/5.8.0/5.9.0"],
            "index must list the pod and every version on one line",
        );

        // The same pod must not appear in a shard it does not hash into.
        let app = fx.router_with_auth(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/all_pods_versions_0_0_0.txt", fx.repo_key)),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(
            !String::from_utf8(body.to_vec())
                .unwrap()
                .contains("Alamofire"),
            "pod must only be indexed under its own shard",
        );
        fx.teardown().await;
    }

    /// The podspec must resolve at the MD5-sharded path the client derives from
    /// the pod name, and only there.
    #[tokio::test]
    async fn test_cocoapods_cdn_sharded_podspec_resolves() {
        let Some(fx) = tdh::Fixture::setup("local", "cocoapods").await else {
            return;
        };
        push_pod(&fx, "Alamofire", "5.8.0").await;

        let spec_path = crate::formats::cocoapods::cdn_podspec_path("Alamofire", "5.8.0");
        assert_eq!(
            spec_path,
            "Specs/d/a/2/Alamofire/5.8.0/Alamofire.podspec.json"
        );

        let app = fx.router_with_auth(super::router());
        let (status, body) =
            tdh::send(app, tdh::get(format!("/{}/{}", fx.repo_key, spec_path))).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let spec: serde_json::Value = serde_json::from_slice(&body[..]).unwrap();
        assert_eq!(spec["name"], "Alamofire");
        assert_eq!(spec["version"], "5.8.0");

        // Wrong fan-out is not an alias for the pod.
        let app = fx.router_with_auth(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/Specs/0/0/0/Alamofire/5.8.0/Alamofire.podspec.json",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        fx.teardown().await;
    }

    /// The pre-existing flat layout keeps working next to the CDN tree.
    #[tokio::test]
    async fn test_cocoapods_flat_podspec_still_resolves() {
        let Some(fx) = tdh::Fixture::setup("local", "cocoapods").await else {
            return;
        };
        push_pod(&fx, "Alamofire", "5.8.0").await;

        let app = fx.router_with_auth(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/Specs/Alamofire/5.8.0/Alamofire.podspec.json",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let spec: serde_json::Value = serde_json::from_slice(&body[..]).unwrap();
        assert_eq!(spec["name"], "Alamofire");
        fx.teardown().await;
    }

    /// A path that is not a shard index file is not swallowed by the index
    /// route.
    #[tokio::test]
    async fn test_cocoapods_cdn_non_index_file_not_found() {
        let Some(fx) = tdh::Fixture::setup("local", "cocoapods").await else {
            return;
        };
        let app = fx.router_with_auth(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/all_pods_versions_zz_a_2.txt", fx.repo_key)),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

        // The pre-existing all_specs listing must still route to its own handler.
        let app = fx.router_with_auth(super::router());
        let (status, _) = tdh::send(app, tdh::get(format!("/{}/all_specs", fx.repo_key))).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        fx.teardown().await;
    }
}
