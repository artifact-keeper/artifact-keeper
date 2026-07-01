//! Ansible Galaxy API handlers.
//!
//! Implements the endpoints required for Ansible collection management.
//!
//! Routes are mounted at `/ansible/{repo_key}/...`:
//!   GET  /ansible/{repo_key}/api/                                                      - API version discovery
//!   GET  /ansible/{repo_key}/api/v3/                                                   - v3 service index
//!   GET  /ansible/{repo_key}/api/v3/collections/                                      - List collections
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/                   - Collection info
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/           - Version list
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/{version}/ - Version info
//!   GET  /ansible/{repo_key}/download/{namespace}-{name}-{version}.tar.gz              - Download
//!   POST /ansible/{repo_key}/api/v3/artifacts/collections/                             - Upload collection
//!
//! The discovery endpoints are required by the `ansible-galaxy` CLI: before
//! any other call it performs `GET <server_url>/api/` to negotiate which
//! Galaxy API version to use. Without it the CLI aborts with
//! `Error when finding available api versions (HTTP Code: 404, Message: Not Found)`.

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::formats::ansible::AnsibleHandler;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
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
        "download_url": format!(
            "/ansible/{}/download/{}-{}-{}.tar.gz",
            repo_key, namespace, name, latest_version
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
        "download_url": format!(
            "/ansible/{}/download/{}-{}-{}.tar.gz",
            repo_key, namespace, name, version
        ),
        "artifact": {
            "filename": format!("{}-{}-{}.tar.gz", namespace, name, version),
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
    Path((repo_key, file_path)): Path<(String, String)>,
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
                    &repo,
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
    let user_id = require_auth_basic(auth, "ansible")?.user_id;
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
    let mut tarball: Option<Bytes> = None;
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
            tarball = Some(field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read file: {}", e),
                )
                    .into_response()
            })?);
        } else if field_name == "sha256" {
            declared_sha256 = Some(field.text().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read sha256: {}", e),
                )
                    .into_response()
            })?);
        } else if field_name == "collection" || field_name == "metadata" {
            let data = field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read metadata JSON: {}", e),
                )
                    .into_response()
            })?;
            collection_json = Some(serde_json::from_slice(&data).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid metadata JSON: {}", e),
                )
                    .into_response()
            })?);
        }
    }

    let tarball =
        tarball.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing file field").into_response())?;
    if tarball.is_empty() {
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

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&tarball);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    // If the client supplied a digest, verify the upload was not corrupted in
    // transit. ansible-galaxy CLI always sends one.
    if let Some(declared) = declared_sha256.as_deref() {
        let declared = declared.trim();
        if !declared.is_empty() && !declared.eq_ignore_ascii_case(&computed_sha256) {
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

    let artifact_path = format!("{}/{}/{}", full_name, collection_version, filename);

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Collection version already exists",
    )
    .await?;

    let storage_key = format!("ansible/{}/{}/{}", full_name, collection_version, filename);
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, tarball.clone()).await?;

    let ansible_metadata = serde_json::json!({
        "namespace": namespace,
        "collection_name": collection_name,
        "version": collection_version,
        "filename": filename,
        "collection_json": collection_json,
    });

    let size_bytes = tarball.len() as i64;

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
    });

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
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
            promotion_only: false,
        };
        assert_eq!(info.storage_path, "/tmp/test");
        assert_eq!(info.repo_type, "hosted");
        assert_eq!(info.upstream_url, Some("https://example.com".to_string()));
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
}
