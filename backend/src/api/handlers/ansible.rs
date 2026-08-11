//! Ansible Galaxy API handlers.
//!
//! Implements the endpoints required for Ansible collection management.
//!
//! Routes are mounted at `/ansible/{repo_key}/...`:
//!   GET  /ansible/{repo_key}/api[/]                                                    - API version discovery
//!   GET  /ansible/{repo_key}/api/v3/                                                   - v3 service index
//!   GET  /ansible/{repo_key}/api/v3/collections/                                      - List collections
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/                   - Collection info
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/           - Version list
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/{version}/ - Version info
//!   GET  /ansible/{repo_key}/download/{namespace}-{name}-{version}.tar.gz              - Download
//!   POST /ansible/{repo_key}/api/v3/artifacts/collections/                             - Upload collection
//!   GET  /ansible/{repo_key}/api/v3/imports/collections/{task_id}/                      - Import status
//!
//! The discovery endpoints are required by the `ansible-galaxy` CLI: before
//! any other call it performs `GET <server_url>/api` to negotiate which
//! Galaxy API version to use. Without it the CLI aborts with
//! `Error when finding available api versions (HTTP Code: 404, Message: Not Found)`.
//!
//! Note the discovery URL has NO trailing slash on the wire: ansible-core's
//! `g_connect` builds it as `_urljoin(n_url, '/api/')` and `_urljoin` strips
//! `/` from every component (`lib/ansible/galaxy/api.py`), so the client
//! requests `<server_url>/api`. All later v3 URLs get an explicit `+ '/'`,
//! which is why only the discovery route needs both spellings (#3137).
//!
//! # The Galaxy v3 publish contract (#3282)
//!
//! `ansible-galaxy collection publish` is a two-call sequence, not one upload.
//! `GalaxyAPI.publish_collection` (`lib/ansible/galaxy/api.py`) ends with a
//! *hard index* into the upload response — `return resp['task']` on
//! `stable-2.17` through `stable-2.20`, and `return urljoin(self.api_server,
//! resp['task'])` on `devel`. A response without a `task` key therefore kills
//! the CLI with `ERROR! Unexpected Exception, this is probably a bug: 'task'`
//! before `--no-wait` is ever consulted: `wait` is read one frame upstream, in
//! `lib/ansible/galaxy/collection/__init__.py::publish_collection`.
//!
//! The client then polls that task. **Emitting `task` without also serving the
//! import-status route converts the crash into an indefinite hang**, because
//! `wait_import_task` treats 404 as "the import has not started yet" and
//! retries, and the CLI defaults are `--import-timeout` `default=0` (never time
//! out) with `--no-wait` `dest='wait', action='store_false', default=True`
//! (wait by default). The route and the field have to land together.
//!
//! ## Why the emitted `task` is a root-absolute path
//!
//! One spelling has to satisfy both client generations, and they consume the
//! value differently:
//!
//! * `stable-2.17`..`stable-2.20`: the caller in `collection/__init__.py`
//!   reduces the value to its **last non-empty path segment**
//!   (`for path_segment in reversed(import_uri.split('/'))`) and
//!   `wait_import_task(task_id)` rebuilds the URL as
//!   `_urljoin(api_server, 'v3/', 'imports/collections', task_id, '/')`.
//!   Since `g_connect` has already rewritten `self.api_server` to the URL that
//!   served `available_versions` (`self.api_server = n_url`), that is
//!   `/ansible/{repo_key}/api/v3/imports/collections/{task_id}/`.
//! * `devel`: `urljoin(self.api_server, resp['task'])` is passed to
//!   `wait_import_task` **verbatim**, with no segment extraction. A
//!   root-absolute reference resolves against the origin, yielding the same
//!   URL.
//!
//! So a root-absolute path ending in `/{task_id}/` is correct for both — and it
//! is the shape ansible-core itself documents as the v3 reference response:
//! `{"task": "/api/automation-hub/v3/imports/collections/838d1308-...-7823f3806cd8/"}`.
//! A bare id would break `devel` (relative resolution drops the last segment of
//! `api_server`); a full path would break the stable line only if the stable
//! line used it verbatim, which it does not.
//!
//! ## The document is synthetic, and honestly so
//!
//! Artifact Keeper has no asynchronous import pipeline: `upload_collection`
//! validates, stores, and inserts the artifact row inline, so by the time the
//! `202` is written the "import" is already finished. The status route
//! therefore reports a completed import derived from the stored artifact rather
//! than from a job queue. It reports no progress because there is no progress
//! to report; a validation failure never reaches this route at all, because it
//! is returned as a `4xx` from the upload itself and `_call_galaxy` raises on
//! any non-2xx.

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::ansible::AnsibleHandler;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Both spellings of the discovery endpoint: `ansible-galaxy` requests
        // `<server>/api` WITHOUT a trailing slash (see module docs), while
        // axum matches `/api` and `/api/` as distinct routes. Registering only
        // the trailing-slash form 404s the CLI's version negotiation and the
        // install/publish flow dies before reaching any collection endpoint
        // (#3137).
        .route("/:repo_key/api", get(api_root))
        .route("/:repo_key/api/", get(api_root))
        .route("/:repo_key/api/v3/", get(api_v3_root))
        .route("/:repo_key/api/v3/collections/", get(list_collections))
        .route(
            "/:repo_key/api/v3/collections/:namespace/:name/",
            get(collection_info),
        )
        .route(
            "/:repo_key/api/v3/collections/:namespace/:name/versions/",
            get(version_list),
        )
        .route(
            "/:repo_key/api/v3/collections/:namespace/:name/versions/:version/",
            get(version_info),
        )
        .route("/:repo_key/download/*file_path", get(download_collection))
        .route(
            "/:repo_key/api/v3/artifacts/collections/",
            post(upload_collection),
        )
        // The import-status route the `task` field emitted by
        // `upload_collection` points at (#3282). Both spellings are registered
        // for the same reason as the discovery alias above, but the stakes are
        // higher here: `wait_import_task` retries on 404 forever by default, so
        // a missing route spelling is an indefinite hang rather than an error.
        // Every client generation verified in the module docs asks for the
        // trailing-slash form; the bare form is registered so a third-party
        // client that trims it gets an answer instead of a silent wedge.
        .route(
            "/:repo_key/api/v3/imports/collections/:task_id/",
            get(import_status),
        )
        .route(
            "/:repo_key/api/v3/imports/collections/:task_id",
            get(import_status),
        )
}

/// The `task` value returned by `upload_collection` and the `href` echoed back
/// by [`import_status`]. Root-absolute so `devel`'s
/// `urljoin(api_server, resp['task'])` resolves against the origin, and ending
/// in `/{task_id}/` so the stable line's last-non-empty-segment extraction
/// recovers the id (see the module docs).
fn import_task_href(repo_key: &str, task_id: &uuid::Uuid) -> String {
    format!(
        "/ansible/{}/api/v3/imports/collections/{}/",
        repo_key, task_id
    )
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/ — API version discovery
// ---------------------------------------------------------------------------
//
// Mirrors the Pulp Galaxy NG response shape so the `ansible-galaxy` CLI
// negotiates v3 successfully. The CLI only checks `available_versions` keys.

async fn api_root(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    // Validate the repo exists so misconfigured server URLs surface as 404.
    let _ = resolve_ansible_repo(&state.db, &repo_key).await?;

    let json = serde_json::json!({
        "description": "Artifact Keeper Ansible Galaxy API",
        "current_version": "v3",
        "available_versions": {
            "v3": "v3/"
        },
        "server_version": env!("CARGO_PKG_VERSION"),
        "version_name": "Artifact Keeper",
    });
    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/ — v3 service index
// ---------------------------------------------------------------------------

async fn api_v3_root(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let _ = resolve_ansible_repo(&state.db, &repo_key).await?;

    let json = serde_json::json!({
        "collections": format!("/ansible/{}/api/v3/collections/", repo_key),
        "artifacts": {
            "collections": format!("/ansible/{}/api/v3/artifacts/collections/", repo_key),
        },
    });
    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_ansible_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["ansible"], "an Ansible").await
}

/// The canonical Galaxy collection artifact filename `{namespace}-{name}-{version}.tar.gz`.
fn collection_filename(namespace: &str, name: &str, version: &str) -> String {
    format!("{}-{}-{}.tar.gz", namespace, name, version)
}

/// Build the `download_url` advertised in the collection/version metadata.
///
/// The download route (`GET /ansible/{repo}/download/{file}`) resolves a hosted
/// collection by its trailing filename suffix (#2587), so the advertised URL
/// must carry the artifact's actual stored basename. A collection published
/// through the native `ansible-galaxy` upload is stored at
/// `{namespace}-{name}-{version}.tar.gz`, byte-identical to the reconstructed
/// filename; one pushed through the generic upload flow is stored at its bare
/// path with generically-derived coordinates, so reconstructing the canonical
/// filename would advertise a path the download route cannot resolve (the
/// Ansible analogue of the RPM `<location>` fix, #2587 / #2589).
fn collection_download_url(
    repo_key: &str,
    path: &str,
    namespace: &str,
    name: &str,
    version: &str,
) -> String {
    let filename = proxy_helpers::advertised_download_filename(
        path,
        &collection_filename(namespace, name, version),
    );
    format!("/ansible/{}/download/{}", repo_key, filename)
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/collections/ — List collections (paginated)
// ---------------------------------------------------------------------------

async fn list_collections(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT ON (LOWER(name)) name, version
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY LOWER(name), created_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    let data: Vec<serde_json::Value> = artifacts
        .iter()
        .filter_map(|a| {
            let name = a.name.clone();
            // Artifact name is stored as "namespace-collection_name"
            let first_hyphen = name.find('-')?;
            let namespace = name[..first_hyphen].to_string();
            let coll_name = name[first_hyphen + 1..].to_string();
            let latest_version = a.version.clone().unwrap_or_default();

            Some(serde_json::json!({
                "namespace": namespace,
                "name": coll_name,
                "href": format!(
                    "/ansible/{}/api/v3/collections/{}/{}/",
                    repo_key, namespace, coll_name
                ),
                "highest_version": {
                    "version": latest_version,
                    "href": format!(
                        "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
                        repo_key, namespace, coll_name, latest_version
                    ),
                },
            }))
        })
        .collect();

    let json = serde_json::json!({
        "meta": {
            "count": data.len(),
        },
        "links": {
            "first": null,
            "previous": null,
            "next": null,
            "last": null,
        },
        "data": data,
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/ — Collection info
// ---------------------------------------------------------------------------

async fn collection_info(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    // Validate via format handler
    let validate_path = format!("api/v3/collections/{}/{}", namespace, name);
    let _ = AnsibleHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    let collection_name = format!("{}-{}", namespace, name);
    let artifact =
        proxy_helpers::find_artifact_by_name_lowercase(&state.db, repo.id, &collection_name)
            .await?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Collection not found").into_response())?;

    let latest_version = artifact.version.clone().unwrap_or_default();
    let description = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let json = serde_json::json!({
        "namespace": namespace,
        "name": name,
        "description": description,
        "highest_version": {
            "version": latest_version,
            "href": format!(
                "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
                repo_key, namespace, name, latest_version
            ),
        },
        "versions_url": format!(
            "/ansible/{}/api/v3/collections/{}/{}/versions/",
            repo_key, namespace, name
        ),
        "download_url": collection_download_url(
            &repo_key,
            &artifact.path,
            &namespace,
            &name,
            &latest_version,
        ),
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/ — Version list
// ---------------------------------------------------------------------------

async fn version_list(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    let collection_name = format!("{}-{}", namespace, name);
    let artifacts =
        proxy_helpers::list_artifacts_by_name_lowercase(&state.db, repo.id, &collection_name)
            .await?;

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "version": version,
                "href": format!(
                    "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
                    repo_key, namespace, name, version
                ),
            })
        })
        .collect();

    let json = serde_json::json!({
        "meta": {
            "count": versions.len(),
        },
        "links": {
            "first": null,
            "previous": null,
            "next": null,
            "last": null,
        },
        "data": versions,
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/{version}/ — Version info
// ---------------------------------------------------------------------------

async fn version_info(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, version)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    // Validate via format handler
    let validate_path = format!(
        "api/v3/collections/{}/{}/versions/{}",
        namespace, name, version
    );
    let _ = AnsibleHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    let collection_name = format!("{}-{}", namespace, name);
    let artifact = proxy_helpers::find_artifact_by_name_version(
        &state.db,
        repo.id,
        &collection_name,
        &version,
    )
    .await?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Collection version not found").into_response())?;

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "namespace": namespace,
        "name": name,
        "version": version,
        "download_url": collection_download_url(&repo_key, &artifact.path, &namespace, &name, &version),
        "artifact": {
            "filename": proxy_helpers::advertised_download_filename(
                &artifact.path,
                &collection_filename(&namespace, &name, &version),
            ),
            "size": artifact.size_bytes,
            "sha256": artifact.checksum_sha256,
        },
        "collection": {
            "href": format!(
                "/ansible/{}/api/v3/collections/{}/{}/",
                repo_key, namespace, name
            ),
        },
        "downloads": download_count,
        "metadata": artifact.metadata.unwrap_or(serde_json::json!({})),
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/download/{namespace}-{name}-{version}.tar.gz — Download
// ---------------------------------------------------------------------------

async fn download_collection(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, file_path)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    let filename = file_path.trim_start_matches('/');

    let artifact =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, filename).await? {
            Some(a) => a,
            None => {
                let upstream_path = format!("download/{}", filename);
                if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                    &state,
                    auth.as_ref(),
                    &repo,
                    &ctx,
                    proxy_helpers::DownloadResponseOpts {
                        upstream_path: &upstream_path,
                        virtual_lookup: proxy_helpers::VirtualLookup::PathSuffix(filename),
                        default_content_type: "application/octet-stream",
                        content_disposition_filename: None,
                        suppress_upstream_proxy: false,
                    },
                )
                .await?
                {
                    return Ok(resp);
                }
                return Err((StatusCode::NOT_FOUND, "Collection file not found").into_response());
            }
        };

    proxy_helpers::serve_local_artifact(
        &state,
        &repo,
        artifact.id,
        &artifact.storage_key,
        "application/gzip",
        Some(filename),
        &ctx,
    )
    .await
}

// ---------------------------------------------------------------------------
// POST /ansible/{repo_key}/api/v3/artifacts/collections/ — Upload collection (multipart)
// ---------------------------------------------------------------------------

async fn upload_collection(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, "ansible", "write:artifacts")?.user_id;
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // The `ansible-galaxy collection publish` CLI sends a multipart body with:
    //   * `file`: the tarball, with the canonical filename
    //     `<namespace>-<name>-<version>.tar.gz` in the field's Content-Disposition
    //   * `sha256`: a hex digest of the tarball (text field)
    // It does NOT send a separate JSON metadata blob. galaxykit and some
    // older clients still send a `collection` or `metadata` JSON field, so
    // accept either source for the namespace/name/version. The filename
    // takes precedence because it is what the CLI ships with.
    // Spool the tarball straight to a bounded scratch file instead of buffering
    // the whole body in memory; the small text/JSON fields are still read
    // in-hand. See proxy_helpers::stage_upload_field / put_artifact_stream.
    let mut staged: Option<proxy_helpers::StagedUpload> = None;
    let mut file_name: Option<String> = None;
    let mut declared_sha256: Option<String> = None;
    let mut collection_json: Option<serde_json::Value> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e)).into_response())?
    {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "file" {
            file_name = field.file_name().map(|s| s.to_string());
            staged = Some(proxy_helpers::stage_upload_field(&state, field).await?);
        } else if field_name == "sha256" {
            declared_sha256 = Some(field.text().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read sha256: {}", e),
                )
                    .into_response()
            })?);
        } else if field_name == "collection" || field_name == "metadata" {
            // Small JSON metadata field (not the artifact body): read as text (a
            // length-limited extractor) and parse in-hand.
            let data = field.text().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read metadata JSON: {}", e),
                )
                    .into_response()
            })?;
            collection_json = Some(serde_json::from_str(&data).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid metadata JSON: {}", e),
                )
                    .into_response()
            })?);
        }
    }

    let staged =
        staged.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing file field").into_response())?;
    if staged.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    // 1. Try the filename (this is what ansible-galaxy CLI sends).
    // 2. Fall back to the optional metadata JSON for older clients.
    let (namespace, collection_name, collection_version) =
        if let Some(ref fname) = file_name.as_ref().filter(|n| !n.is_empty()) {
            let archive_path = format!("collections/{}", fname);
            match AnsibleHandler::parse_path(&archive_path) {
                Ok(info) => (info.namespace, info.name, info.version.unwrap_or_default()),
                Err(e) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid collection filename: {}", e),
                    )
                        .into_response());
                }
            }
        } else if let Some(ref json) = collection_json {
            let namespace = json
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = json
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let version = json
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (namespace, name, version)
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                "Missing collection filename and metadata; cannot determine namespace/name/version",
            )
                .into_response());
        };

    if namespace.is_empty() || collection_name.is_empty() || collection_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Namespace, name, and version are required",
        )
            .into_response());
    }

    // Validate via format handler
    let validate_path = format!(
        "api/v3/collections/{}/{}/versions/{}",
        namespace, collection_name, collection_version
    );
    let _ = AnsibleHandler::parse_path(&validate_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid collection: {}", e),
        )
            .into_response()
    })?;

    let full_name = format!("{}-{}", namespace, collection_name);
    let filename = format!(
        "{}-{}-{}.tar.gz",
        namespace, collection_name, collection_version
    );

    let artifact_path = format!("{}/{}/{}", full_name, collection_version, filename);

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Collection version already exists",
    )
    .await?;

    // Stream the staged tarball into the repo's StorageBackend via `put_stream`,
    // which computes the SHA-256 incrementally as it copies (no re-hash).
    let storage_key = format!("ansible/{}/{}/{}", full_name, collection_version, filename);
    let put = proxy_helpers::put_artifact_stream(&state, &repo, &storage_key, staged).await?;
    let computed_sha256 = put.checksum_sha256;

    // If the client supplied a digest, verify the upload was not corrupted in
    // transit. ansible-galaxy CLI always sends one. On mismatch, remove the
    // just-written object so a corrupt upload leaves nothing behind.
    if let Some(declared) = declared_sha256.as_deref() {
        let declared = declared.trim();
        if !declared.is_empty() && !declared.eq_ignore_ascii_case(&computed_sha256) {
            if let Ok(storage) = state.storage_for_repo(&repo.storage_location()) {
                let _ = storage.delete(&storage_key).await;
            }
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Collection sha256 mismatch: declared {} but computed {}",
                    declared, computed_sha256
                ),
            )
                .into_response());
        }
    }

    let ansible_metadata = serde_json::json!({
        "namespace": namespace,
        "collection_name": collection_name,
        "version": collection_version,
        "filename": filename,
        "collection_json": collection_json,
    });

    let size_bytes = put.bytes_written as i64;

    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &full_name,
            version: &collection_version,
            size_bytes,
            checksum_sha256: &computed_sha256,
            content_type: "application/gzip",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    proxy_helpers::record_artifact_metadata(
        &state.db,
        artifact_id,
        repo.id,
        "ansible",
        &ansible_metadata,
    )
    .await;

    info!(
        "Ansible upload: {}-{} {} ({}) to repo {}",
        namespace, collection_name, collection_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "namespace": namespace,
        "name": collection_name,
        "version": collection_version,
        "href": format!(
            "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
            repo_key, namespace, collection_name, collection_version
        ),
        "download_url": format!(
            "/ansible/{}/download/{}",
            repo_key, filename
        ),
        // Required by the Galaxy v3 publish contract: `publish_collection`
        // indexes this key unconditionally, so omitting it crashes the CLI
        // after a successful upload (#3282). The artifact id doubles as the
        // import task id — the import is the upload.
        "task": import_task_href(&repo_key, &artifact_id),
    });

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/imports/collections/{task_id}/ — Import status
// ---------------------------------------------------------------------------
//
// The second half of the publish contract (#3282). See the module docs for why
// this route must exist the moment `upload_collection` emits a `task`, and why
// the document it serves is synthetic.
//
// Client-visible contract, read off `wait_import_task`
// (`lib/ansible/galaxy/api.py`, identical on `stable-2.17`..`devel`):
//
//   state       = data.get('state', 'waiting')   -> anything but 'waiting' or
//                                                   'failed' is success
//   finished_at = data.get('finished_at', None)  -> truthy breaks the poll loop
//   messages    = data.get('messages', [])       -> each entry is hard-indexed
//                                                   for ['level'] and ['message']
//   error       = data['error']                  -> read ONLY when state=='failed'
//
// Those are the only fields the client touches. The rest of the document is
// identity for humans and UIs, and mirrors the field names Galaxy NG serves.
//
// Authorization: this route serves per-repository data and lives in
// `handlers::ansible::router()`, which `routes.rs` nests under `/ansible`
// inside `format_routes` — the router that carries
// `repo_visibility_middleware`. That middleware is the credential authority for
// every format route, so a private repository's import tasks are unreachable
// without a credential that can read the repository, exactly like the
// collection endpoints beside it. `test_3282_import_status_through_visibility_middleware`
// pins that rather than assuming it.
//
// Repo scoping: the lookup is keyed on `(id, repository_id)`, so a task id
// minted in one repository is a plain 404 in another and the route is not a
// cross-repo existence oracle.
async fn import_status(
    State(state): State<SharedState>,
    Path((repo_key, task_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    let not_found =
        || -> Response { (StatusCode::NOT_FOUND, "Import task not found").into_response() };

    // A malformed id is indistinguishable from an unknown one, and answering
    // 404 for both keeps the route from confirming which ids are well-formed.
    let Ok(task_uuid) = uuid::Uuid::parse_str(task_id.trim()) else {
        return Err(not_found());
    };

    let row = sqlx::query!(
        r#"
        SELECT name, version, created_at
        FROM artifacts
        WHERE id = $1
          AND repository_id = $2
          AND is_deleted = false
        "#,
        task_uuid,
        repo.id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(super::db_err)?;

    let Some(row) = row else {
        return Err(not_found());
    };

    // Artifact name is stored as "namespace-collection_name" (see
    // `list_collections`); an artifact pushed through the generic upload flow
    // may not carry a hyphen, in which case there is no namespace to report.
    let (namespace, collection_name) = match row.name.find('-') {
        Some(i) => (row.name[..i].to_string(), row.name[i + 1..].to_string()),
        None => (String::new(), row.name.clone()),
    };

    // Upload is synchronous, so the import started and finished inside the
    // POST that created this row: one real timestamp, not three invented ones.
    let ts = row.created_at.to_rfc3339();

    let json = serde_json::json!({
        "id": task_uuid,
        "state": "completed",
        "created_at": ts,
        "started_at": ts,
        "finished_at": ts,
        "updated_at": ts,
        "namespace": namespace,
        "name": collection_name,
        "version": row.version.unwrap_or_default(),
        "href": import_task_href(&repo_key, &task_uuid),
        "messages": [],
    });

    Ok(super::json_response(&json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_info_struct() {
        let info = RepoInfo {
            id: uuid::Uuid::nil(),
            key: String::new(),
            storage_path: "/tmp/test".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: Some("https://example.com".to_string()),
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        assert_eq!(info.storage_path, "/tmp/test");
        assert_eq!(info.repo_type, "hosted");
        assert_eq!(info.upstream_url, Some("https://example.com".to_string()));
    }

    #[test]
    fn test_collection_download_url_native_path_is_byte_identical() {
        assert_eq!(
            collection_download_url(
                "gx",
                "community-general-1.2.3.tar.gz",
                "community",
                "general",
                "1.2.3"
            ),
            "/ansible/gx/download/community-general-1.2.3.tar.gz"
        );
    }

    #[test]
    fn test_collection_download_url_bare_path_advertises_stored_basename() {
        // Generic upload at a bare/arbitrary path: advertise the real basename
        // so the suffix download route (with #2587 exact-path fallback) serves
        // it, instead of the canonical filename that would 404.
        assert_eq!(
            collection_download_url("gx", "blob.tar.gz", "community", "general", "1.2.3"),
            "/ansible/gx/download/blob.tar.gz"
        );
        assert_eq!(
            collection_download_url("gx", "uploads/x/c.tar.gz", "community", "general", "1.2.3"),
            "/ansible/gx/download/c.tar.gz"
        );
    }

    #[test]
    fn test_collection_name_format() {
        let namespace = "community";
        let collection_name = "general";
        let collection_version = "1.2.3";
        let full_name = format!("{}-{}", namespace, collection_name);
        let filename = format!(
            "{}-{}-{}.tar.gz",
            namespace, collection_name, collection_version
        );
        let artifact_path = format!("{}/{}/{}", full_name, collection_version, filename);

        assert_eq!(full_name, "community-general");
        assert_eq!(filename, "community-general-1.2.3.tar.gz");
        assert_eq!(
            artifact_path,
            "community-general/1.2.3/community-general-1.2.3.tar.gz"
        );
    }

    #[test]
    fn test_storage_key_format() {
        let full_name = "namespace-collection";
        let version = "2.0.0";
        let filename = "namespace-collection-2.0.0.tar.gz";
        let storage_key = format!("ansible/{}/{}/{}", full_name, version, filename);
        assert_eq!(
            storage_key,
            "ansible/namespace-collection/2.0.0/namespace-collection-2.0.0.tar.gz"
        );
    }

    #[test]
    fn test_sha256_computation() {
        let data = b"test data for hashing";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let computed = format!("{:x}", hasher.finalize());
        assert_eq!(computed.len(), 64);
        // Known SHA-256 hash of "test data for hashing"
        assert!(!computed.is_empty());
    }

    #[test]
    fn test_collection_name_parsing_from_artifact() {
        let name = "community-general";
        let first_hyphen = name.find('-').unwrap();
        let namespace = &name[..first_hyphen];
        let coll_name = &name[first_hyphen + 1..];
        assert_eq!(namespace, "community");
        assert_eq!(coll_name, "general");
    }

    #[test]
    fn test_collection_name_parsing_no_hyphen() {
        let name = "nohyphen";
        let result = name.find('-');
        assert_eq!(result, None);
    }

    #[test]
    fn test_ansible_metadata_json_construction() {
        let namespace = "testns";
        let collection_name = "testcoll";
        let collection_version = "1.0.0";
        let filename = "testns-testcoll-1.0.0.tar.gz";
        let collection_json: Option<serde_json::Value> =
            Some(serde_json::json!({"namespace": "testns"}));

        let metadata = serde_json::json!({
            "namespace": namespace,
            "collection_name": collection_name,
            "version": collection_version,
            "filename": filename,
            "collection_json": collection_json,
        });

        assert_eq!(metadata["namespace"], "testns");
        assert_eq!(metadata["collection_name"], "testcoll");
        assert_eq!(metadata["version"], "1.0.0");
        assert_eq!(metadata["filename"], "testns-testcoll-1.0.0.tar.gz");
    }

    // -----------------------------------------------------------------------
    // DB-backed router tests for the proxy_helpers-call paths.
    //
    // No-op without DATABASE_URL; the CI coverage job seeds Postgres so
    // these run there and instrument the refactored helper-call sites.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    #[tokio::test]
    async fn test_ansible_download_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/download/missing-pkg-1.0.tar.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_ansible_download_serves_local_artifact() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "ansible/community-general-1.0.0.tar.gz",
            "community-general/1.0.0/community-general-1.0.0.tar.gz",
            "community-general",
            "1.0.0",
            "application/gzip",
            bytes::Bytes::from_static(b"fake-tar"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/download/community-general-1.0.0.tar.gz",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"fake-tar");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_ansible_collection_info_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/api/v3/collections/none/missing/", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_ansible_upload_unauthenticated_401() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = tdh::post(
            format!("/{}/api/v3/artifacts/collections/", f.repo_key),
            "multipart/form-data; boundary=B",
            bytes::Bytes::from_static(b"--B--\r\n"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_ansible_upload_remote_repo_405() {
        let Some(f) = tdh::Fixture::setup("remote", "ansible").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = tdh::post(
            format!("/{}/api/v3/artifacts/collections/", f.repo_key),
            "multipart/form-data; boundary=B",
            bytes::Bytes::from_static(b"--B--\r\n"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Regression tests for #1451: ansible-galaxy CLI requires a discovery
    // endpoint at `<server>/api/` and accepts uploads whose namespace/name/
    // version come from the multipart filename, not a JSON metadata blob.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ansible_api_discovery_returns_v3() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(app, tdh::get(format!("/{}/api/", f.repo_key))).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["current_version"], "v3");
        assert_eq!(json["available_versions"]["v3"], "v3/");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_3137_api_discovery_without_trailing_slash() {
        // `ansible-galaxy` requests the discovery document at `<server>/api`
        // with NO trailing slash: ansible-core's `g_connect` builds the URL as
        // `_urljoin(n_url, '/api/')` and `_urljoin` strips `/` from every
        // component (lib/ansible/galaxy/api.py). With only the `/api/` route
        // registered, the CLI's version negotiation 404s and every
        // install/publish attempt fails before touching a collection endpoint
        // (#3137).
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(app.clone(), tdh::get(format!("/{}/api", f.repo_key))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET /api without trailing slash must serve the discovery document"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // The CLI negotiates from the `available_versions` keys.
        assert!(
            json["available_versions"].get("v3").is_some(),
            "discovery must advertise v3"
        );

        // Positive control, same fixture: the trailing-slash spelling that
        // worked before this fix must keep working.
        let (status_slash, _) = tdh::send(app, tdh::get(format!("/{}/api/", f.repo_key))).await;
        assert_eq!(status_slash, StatusCode::OK);

        // Unknown repo: the alias must not bypass repo resolution — the
        // handler still runs `resolve_ansible_repo` and 404s.
        //
        // NOTE what this does *not* claim. This router is the bare handler
        // table; in the deployed stack `repo_visibility_middleware` runs first
        // and answers **401** for an unknown repo key presented without a
        // credential, because #1808 closed the 404-vs-401 repo-existence
        // oracle (`auth.rs`, the `no_credential` arm of the "no repo found"
        // branch). The production status for that request is pinned by
        // `test_3137_galaxy_api_through_visibility_middleware` below; here the
        // assertion is only that the alias is repo-scoped like every other
        // route in this table.
        let app2 = f.router_anon(super::router());
        let (status_missing, _) = tdh::send(app2, tdh::get("/no-such-repo/api".into())).await;
        assert_eq!(status_missing, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    /// Both #3137 fixes together, through the middleware that produced the
    /// reporter's 401 — the actual `ansible-galaxy` request shape.
    ///
    /// The two unit-level tests each cover one half in isolation: the router
    /// test above uses the bare handler table (no middleware), and
    /// `test_3137_galaxy_token_scheme_authenticates_api_token` in `auth.rs`
    /// calls `try_resolve_auth_outcome` directly (no routing). Neither pins
    /// the contract the user actually exercises, which is a single request:
    /// `GET /ansible/{repo}/api` (no trailing slash) carrying
    /// `Authorization: Token <api_key>`, through `repo_visibility_middleware`
    /// into the Galaxy discovery handler. Either fix missing turns this 200
    /// into the reporter's failure — 404 without the route alias, 401 without
    /// the `Token` scheme.
    #[tokio::test]
    async fn test_3137_galaxy_api_through_visibility_middleware() {
        use crate::api::middleware::auth::{repo_visibility_middleware, RepoVisibilityState};
        use crate::services::auth_service::AuthService;
        use crate::services::permission_service::PermissionService;
        use std::sync::Arc;

        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        // The fixture repository is PRIVATE (`repositories.is_public` defaults
        // to false) and the fixture user holds a `developer` role assignment
        // on it, so the request is only served if the credential resolves.
        let auth_service = Arc::new(AuthService::new(
            f.pool.clone(),
            Arc::new(crate::config::Config::default()),
        ));
        let (token, _tid) = auth_service
            .generate_api_token(f.user_id, "galaxy", vec!["read:artifacts".into()], None)
            .await
            .expect("generate api token");

        let vis_state = RepoVisibilityState {
            auth_service: auth_service.clone(),
            db: f.pool.clone(),
            repo_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            permission_service: Arc::new(PermissionService::new(f.pool.clone())),
        };
        // Mount the real handler table under the real middleware at the real
        // `/ansible` prefix so `extract_repo_key` sees the production path
        // shape (`/{format}/{repo_key}/...`).
        let app = axum::Router::new()
            .nest("/ansible", super::router())
            .with_state(f.state.clone())
            .layer(axum::middleware::from_fn_with_state(
                vis_state,
                repo_visibility_middleware,
            ));

        let galaxy_get = |uri: String, auth: Option<String>| {
            let mut b = axum::http::Request::builder().uri(uri);
            if let Some(v) = auth {
                b = b.header(axum::http::header::AUTHORIZATION, v);
            }
            b.body(axum::body::Body::empty()).expect("build request")
        };

        // THE user path: no trailing slash + the `Token` scheme.
        let (status, body) = tdh::send(
            app.clone(),
            galaxy_get(
                format!("/ansible/{}/api", f.repo_key),
                Some(format!("Token {token}")),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET /ansible/{{repo}}/api with `Authorization: Token <api_key>` must \
             serve the discovery document through repo_visibility_middleware"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["available_versions"].get("v3").is_some(),
            "discovery must advertise v3"
        );

        // Fail-closed controls in the same fixture, so the 200 above cannot be
        // explained by the middleware simply letting everything through.
        //
        // 1. Same URL, no credential -> 401 (private repo).
        let (anon_status, _) = tdh::send(
            app.clone(),
            galaxy_get(format!("/ansible/{}/api", f.repo_key), None),
        )
        .await;
        assert_eq!(
            anon_status,
            StatusCode::UNAUTHORIZED,
            "anonymous read of a private Ansible repo must stay 401"
        );

        // 2. Same URL, a bogus credential under the `Token` scheme -> 401.
        //    Recognizing the scheme must not fail open.
        let (bad_status, _) = tdh::send(
            app.clone(),
            galaxy_get(
                format!("/ansible/{}/api", f.repo_key),
                Some("Token not-a-valid-credential".into()),
            ),
        )
        .await;
        assert_eq!(
            bad_status,
            StatusCode::UNAUTHORIZED,
            "an invalid Token-scheme credential must stay 401"
        );

        // 3. Unknown repo key with no credential -> 401, NOT the handler's
        //    404: #1808 closed the anonymous repo-existence oracle in
        //    `repo_visibility_middleware`, which runs before the handler.
        //    This is the production counterpart of the bare-router 404
        //    asserted in `test_3137_api_discovery_without_trailing_slash`.
        let (missing_status, _) =
            tdh::send(app, galaxy_get("/ansible/no-such-repo/api".into(), None)).await;
        assert_eq!(
            missing_status,
            StatusCode::UNAUTHORIZED,
            "unknown repo key must return the same 401 as an existing private \
             repo (no existence oracle, #1808)"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn test_ansible_api_discovery_unknown_repo_404() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(app, tdh::get("/no-such-repo/api/".into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_ansible_api_v3_root_lists_collections_url() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(app, tdh::get(format!("/{}/api/v3/", f.repo_key))).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let collections = json["collections"].as_str().unwrap();
        assert!(collections.ends_with("/api/v3/collections/"));
        let artifacts = json["artifacts"]["collections"].as_str().unwrap();
        assert!(artifacts.ends_with("/api/v3/artifacts/collections/"));
        f.teardown().await;
    }

    /// Build a minimal multipart body matching what `ansible-galaxy collection
    /// publish` sends: a `file` part with the canonical filename and a
    /// `sha256` text part. No JSON metadata field. See ansible/galaxy/api.py
    /// in the ansible/ansible repo.
    fn galaxy_cli_multipart(boundary: &str, filename: &str, body: &[u8], sha256: &str) -> Bytes {
        let mut out = Vec::new();
        out.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        out.extend_from_slice(b"Content-Disposition: form-data; name=\"sha256\"\r\n\r\n");
        out.extend_from_slice(sha256.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        out.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
                filename
            )
            .as_bytes(),
        );
        out.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
        Bytes::from(out)
    }

    #[tokio::test]
    async fn test_ansible_upload_accepts_galaxy_cli_payload() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let body = b"fake-tar-content";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let sha = format!("{:x}", hasher.finalize());
        let multipart =
            galaxy_cli_multipart("BOUNDARY", "community-hashi_vault-7.1.0.tar.gz", body, &sha);

        let app = f.router_with_auth(super::router());
        let req = tdh::post(
            format!("/{}/api/v3/artifacts/collections/", f.repo_key),
            "multipart/form-data; boundary=BOUNDARY",
            multipart,
        );
        let (status, body_bytes) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "unexpected upload status, body={}",
            String::from_utf8_lossy(&body_bytes)
        );
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["namespace"], "community");
        assert_eq!(json["name"], "hashi_vault");
        assert_eq!(json["version"], "7.1.0");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_ansible_upload_rejects_sha256_mismatch() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let body = b"fake-tar-content";
        let bad_sha = "deadbeef".to_string();
        let multipart =
            galaxy_cli_multipart("BOUNDARY", "community-general-1.0.0.tar.gz", body, &bad_sha);

        let app = f.router_with_auth(super::router());
        let req = tdh::post(
            format!("/{}/api/v3/artifacts/collections/", f.repo_key),
            "multipart/form-data; boundary=BOUNDARY",
            multipart,
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_ansible_upload_rejects_bad_filename() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let body = b"fake-tar-content";
        let multipart = galaxy_cli_multipart("BOUNDARY", "not-a-collection.zip", body, "");

        let app = f.router_with_auth(super::router());
        let req = tdh::post(
            format!("/{}/api/v3/artifacts/collections/", f.repo_key),
            "multipart/form-data; boundary=BOUNDARY",
            multipart,
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // #3282: `ansible-galaxy collection publish` needs BOTH halves of the
    // Galaxy v3 publish contract — a `task` field on the upload response and
    // the import-status route it points at. Emitting one without the other
    // trades a crash for an indefinite hang (see the module docs).
    //
    // The two helpers below re-implement ansible-core's own URL derivation so
    // the tests exercise the client's real request shapes rather than echoing
    // back whatever the handler happens to format.
    // -----------------------------------------------------------------------

    /// The path `ansible-core` polls on `stable-2.17`..`stable-2.20`.
    ///
    /// `lib/ansible/galaxy/collection/__init__.py::publish_collection` reduces
    /// the response's `task` to its **last non-empty path segment**
    /// (`for path_segment in reversed(import_uri.split('/'))`), and
    /// `GalaxyAPI.wait_import_task` then rebuilds the URL as
    /// `_urljoin(api_server, 'v3/', 'imports/collections', task_id, '/')`.
    fn stable_line_poll_path(api_server_path: &str, task: &str) -> String {
        let task_id = task
            .split('/')
            .rev()
            .find(|segment| !segment.is_empty())
            .expect("publish response `task` must contain a non-empty path segment");
        format!(
            "{}/v3/imports/collections/{}/",
            api_server_path.trim_end_matches('/'),
            task_id
        )
    }

    /// The path `ansible-core` polls on `devel`.
    ///
    /// `GalaxyAPI.publish_collection` returns `urljoin(self.api_server,
    /// resp['task'])` and `wait_import_task` fetches that **verbatim** — there
    /// is no segment extraction on this branch. A root-absolute reference
    /// resolves against the origin, so the polled path is the `task` value
    /// itself; a bare id would instead resolve relative to `api_server` and
    /// miss.
    fn devel_poll_path(task: &str) -> String {
        assert!(
            task.starts_with('/'),
            "`task` must be root-absolute so devel's urljoin(api_server, task) \
             resolves against the origin instead of relative to the api root; got {task:?}"
        );
        task.to_string()
    }

    /// Mount the handler table at the production `/ansible` prefix so emitted
    /// root-absolute URLs are directly requestable, with the fixture user's
    /// auth injected (no middleware — the middleware path is pinned by
    /// `test_3282_import_status_through_visibility_middleware`).
    fn nested_app_with_auth(f: &tdh::Fixture) -> axum::Router {
        tdh::router_with_auth(
            axum::Router::new().nest("/ansible", super::router()),
            f.state.clone(),
            tdh::make_auth(f.user_id, &f.username),
        )
    }

    async fn publish_fixture_collection(
        f: &tdh::Fixture,
        filename: &str,
        body: &'static [u8],
    ) -> serde_json::Value {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let sha = format!("{:x}", hasher.finalize());
        let multipart = galaxy_cli_multipart("BOUNDARY", filename, body, &sha);
        let req = tdh::post(
            format!("/ansible/{}/api/v3/artifacts/collections/", f.repo_key),
            "multipart/form-data; boundary=BOUNDARY",
            multipart,
        );
        let (status, bytes) = tdh::send(nested_app_with_auth(f), req).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "publish must succeed, body={}",
            String::from_utf8_lossy(&bytes)
        );
        serde_json::from_slice(&bytes).expect("publish response must be JSON")
    }

    /// The whole `ansible-galaxy collection publish` sequence, driven through
    /// the client's own URL derivation for both live client generations, plus
    /// the `install` path that #3278 fixed as a same-fixture positive control.
    #[tokio::test]
    async fn test_3282_publish_task_resolves_for_both_client_generations() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let tarball: &'static [u8] = b"fake-tar-content-3282";
        let published =
            publish_fixture_collection(&f, "community-hashi_vault-7.1.0.tar.gz", tarball).await;

        // 1. The upload response carries the key `publish_collection` indexes.
        //    Without it the CLI dies with `Unexpected Exception ... 'task'`
        //    before `--no-wait` is even consulted.
        let task = published["task"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "publish response must carry a `task` key; got {}",
                    published
                )
            })
            .to_string();

        // 2. Both client generations must derive the SAME reachable URL from
        //    it. This is the property that constrains the emitted shape: a
        //    bare task id satisfies the stable line but breaks `devel`, and a
        //    fully-qualified URL satisfies `devel` but makes the stable line's
        //    `_urljoin` produce a doubled path.
        let api_server_path = format!("/ansible/{}/api", f.repo_key);
        let stable_path = stable_line_poll_path(&api_server_path, &task);
        let devel_path = devel_poll_path(&task);
        assert_eq!(
            stable_path, devel_path,
            "the emitted `task` must resolve to one URL under both ansible-core \
             derivations (stable-2.17..2.20 segment extraction vs devel urljoin)"
        );

        // 3. That URL must actually answer, and answer as a FINISHED import.
        //    A 404 here is the hang the module docs describe, not an error the
        //    user would ever see.
        for path in [stable_path.clone(), devel_path.clone()] {
            let (status, bytes) = tdh::send(nested_app_with_auth(&f), tdh::get(path.clone())).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "import-status poll of {path} must resolve; a 404 makes \
                 wait_import_task retry forever (--import-timeout defaults to 0)"
            );
            let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

            // The exact fields `wait_import_task` reads, and only those.
            let state = doc["state"].as_str().unwrap_or("waiting");
            assert_ne!(
                state, "waiting",
                "a `waiting` state at loop exit raises `Timeout while waiting for \
                 the Galaxy import process to finish`"
            );
            assert_ne!(
                state, "failed",
                "a successful publish must not report failed"
            );
            assert!(
                doc["finished_at"].as_str().is_some_and(|s| !s.is_empty()),
                "`finished_at` must be truthy or the poll loop never breaks; got {}",
                doc["finished_at"]
            );
            assert!(
                doc["messages"].is_array(),
                "`messages` is iterated unconditionally by wait_import_task"
            );
        }

        // 4. Positive control, same fixture: the #3278 `install` path still
        //    works. If publish handling had broken storage or metadata, the
        //    assertions above could pass against a registry nobody can pull
        //    from.
        let (ver_status, _) = tdh::send(
            nested_app_with_auth(&f),
            tdh::get(format!(
                "/ansible/{}/api/v3/collections/community/hashi_vault/versions/7.1.0/",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(
            ver_status,
            StatusCode::OK,
            "the just-published version must remain installable"
        );
        let (dl_status, dl_body) = tdh::send(
            nested_app_with_auth(&f),
            tdh::get(format!(
                "/ansible/{}/download/community-hashi_vault-7.1.0.tar.gz",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(dl_status, StatusCode::OK);
        assert_eq!(
            &dl_body[..],
            tarball,
            "install must serve the published bytes"
        );

        f.teardown().await;
    }

    /// A task id minted in one repository must not resolve in another.
    ///
    /// The caller here holds the widest possible access (`make_auth` sets
    /// `AccessScope::Admin` and `scopes: None`), so the 404 can only come from
    /// the handler's own `(id, repository_id)` predicate — not from a
    /// credential that happens to be too weak.
    #[tokio::test]
    async fn test_3282_import_status_is_repo_scoped() {
        let Some(a) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let Some(b) = tdh::Fixture::setup("local", "ansible").await else {
            a.teardown().await;
            return;
        };

        let published =
            publish_fixture_collection(&a, "community-hashi_vault-7.1.0.tar.gz", b"tar-a-3282")
                .await;
        let task_a = published["task"].as_str().expect("task").to_string();
        let task_id_a = task_a
            .split('/')
            .rev()
            .find(|s| !s.is_empty())
            .expect("task id")
            .to_string();

        // Positive control FIRST, in this same fixture: repo A's own task
        // resolves. Without this the 404 below would also be satisfied by an
        // import-status route that answers 404 for everything.
        let (own_status, _) = tdh::send(
            nested_app_with_auth(&a),
            tdh::get(format!(
                "/ansible/{}/api/v3/imports/collections/{}/",
                a.repo_key, task_id_a
            )),
        )
        .await;
        assert_eq!(
            own_status,
            StatusCode::OK,
            "repo A's own import task must resolve under repo A"
        );

        // Same task id, repo B's URL: 404, with a caller who can read B.
        let (cross_status, _) = tdh::send(
            nested_app_with_auth(&b),
            tdh::get(format!(
                "/ansible/{}/api/v3/imports/collections/{}/",
                b.repo_key, task_id_a
            )),
        )
        .await;
        assert_eq!(
            cross_status,
            StatusCode::NOT_FOUND,
            "an import task minted in another repository must not be an \
             existence oracle under this one"
        );

        // And repo B is not simply broken: its own publish round-trips.
        let published_b =
            publish_fixture_collection(&b, "community-general-2.0.0.tar.gz", b"tar-b-3282").await;
        let task_b = published_b["task"].as_str().expect("task").to_string();
        let (own_b_status, _) =
            tdh::send(nested_app_with_auth(&b), tdh::get(devel_poll_path(&task_b))).await;
        assert_eq!(
            own_b_status,
            StatusCode::OK,
            "repo B's own import task must resolve under repo B"
        );

        b.teardown().await;
        a.teardown().await;
    }

    /// The import-status route serves per-repository data, so it must sit
    /// behind the same credential authority as every other `/ansible/{repo}`
    /// route. It is registered in `handlers::ansible::router()`, which
    /// `routes.rs` nests inside `format_routes` under
    /// `repo_visibility_middleware`; this pins that composition instead of
    /// assuming it, on the real client URL, against a PRIVATE repository.
    #[tokio::test]
    async fn test_3282_import_status_through_visibility_middleware() {
        use crate::api::middleware::auth::{repo_visibility_middleware, RepoVisibilityState};
        use crate::services::auth_service::AuthService;
        use crate::services::permission_service::PermissionService;
        use std::sync::Arc;

        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let auth_service = Arc::new(AuthService::new(
            f.pool.clone(),
            Arc::new(crate::config::Config::default()),
        ));
        let (token, _tid) = auth_service
            .generate_api_token(
                f.user_id,
                "galaxy-publish",
                vec!["read:artifacts".into(), "write:artifacts".into()],
                None,
            )
            .await
            .expect("generate api token");

        let vis_state = RepoVisibilityState {
            auth_service: auth_service.clone(),
            db: f.pool.clone(),
            repo_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            permission_service: Arc::new(PermissionService::new(f.pool.clone())),
        };
        let state = f.state.clone();
        let app = move || {
            axum::Router::new()
                .nest("/ansible", super::router())
                .with_state(state.clone())
                .layer(axum::middleware::from_fn_with_state(
                    vis_state.clone(),
                    repo_visibility_middleware,
                ))
        };

        // Publish through the middleware with the `Token` scheme #3278 added.
        let tarball: &[u8] = b"fake-tar-content-3282-mw";
        let mut hasher = Sha256::new();
        hasher.update(tarball);
        let sha = format!("{:x}", hasher.finalize());
        let multipart = galaxy_cli_multipart(
            "BOUNDARY",
            "community-hashi_vault-7.1.0.tar.gz",
            tarball,
            &sha,
        );
        let mut publish_req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/ansible/{}/api/v3/artifacts/collections/",
                f.repo_key
            ))
            .header(CONTENT_TYPE, "multipart/form-data; boundary=BOUNDARY")
            .header(axum::http::header::AUTHORIZATION, format!("Token {token}"));
        publish_req = publish_req.header(axum::http::header::CONTENT_LENGTH, multipart.len());
        let (status, bytes) = tdh::send(
            app(),
            publish_req
                .body(axum::body::Body::from(multipart))
                .expect("build publish request"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "publish through repo_visibility_middleware must succeed, body={}",
            String::from_utf8_lossy(&bytes)
        );
        let published: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let task = published["task"].as_str().expect("task").to_string();
        let poll_path = devel_poll_path(&task);
        assert_eq!(
            poll_path,
            stable_line_poll_path(&format!("/ansible/{}/api", f.repo_key), &task)
        );

        let poll = |auth: Option<String>| {
            let mut b = axum::http::Request::builder().uri(poll_path.clone());
            if let Some(v) = auth {
                b = b.header(axum::http::header::AUTHORIZATION, v);
            }
            b.body(axum::body::Body::empty())
                .expect("build poll request")
        };

        // Credentialed poll: 200 and a finished import.
        let (ok_status, ok_body) = tdh::send(app(), poll(Some(format!("Token {token}")))).await;
        assert_eq!(
            ok_status,
            StatusCode::OK,
            "the publishing credential must be able to poll its own import task"
        );
        let doc: serde_json::Value = serde_json::from_slice(&ok_body).unwrap();
        assert_ne!(doc["state"].as_str().unwrap_or("waiting"), "waiting");
        assert!(doc["finished_at"].as_str().is_some_and(|s| !s.is_empty()));

        // Fail-closed controls in the same fixture, so the 200 above cannot be
        // explained by the middleware letting everything through. The fixture
        // repository is private (`repositories.is_public` defaults to false).
        let (anon_status, _) = tdh::send(app(), poll(None)).await;
        assert_eq!(
            anon_status,
            StatusCode::UNAUTHORIZED,
            "anonymous poll of a private repo's import task must be refused"
        );
        let (bad_status, _) =
            tdh::send(app(), poll(Some("Token not-a-valid-credential".into()))).await;
        assert_eq!(
            bad_status,
            StatusCode::UNAUTHORIZED,
            "an invalid credential must not fail open on the import-status route"
        );

        f.teardown().await;
    }

    /// A publish that fails validation must surface as a client-visible error,
    /// never as a task the client would then poll forever.
    ///
    /// The successful publish in the same fixture is the positive control: it
    /// makes the "no `task` on the 400" assertion able to fail, instead of
    /// being satisfied by a build that never emits `task` at all.
    #[tokio::test]
    async fn test_3282_failed_publish_returns_an_error_not_a_task() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };

        // Rejected upload: the sha256 the CLI always sends does not match.
        let multipart = galaxy_cli_multipart(
            "BOUNDARY",
            "community-general-1.0.0.tar.gz",
            b"fake-tar-content",
            "deadbeef",
        );
        let (status, bytes) = tdh::send(
            nested_app_with_auth(&f),
            tdh::post(
                format!("/ansible/{}/api/v3/artifacts/collections/", f.repo_key),
                "multipart/form-data; boundary=BOUNDARY",
                multipart,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a validation failure must be a non-2xx, which `_call_galaxy` raises on"
        );
        assert!(
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("task").cloned())
                .is_none(),
            "a rejected publish must not hand the client a task to poll"
        );

        // Positive control, same fixture: an accepted publish DOES carry one.
        let published =
            publish_fixture_collection(&f, "community-general-1.0.0.tar.gz", b"fake-tar-content")
                .await;
        assert!(
            published["task"].as_str().is_some_and(|s| !s.is_empty()),
            "an accepted publish must carry a task"
        );

        f.teardown().await;
    }
}
