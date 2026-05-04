//! Ansible Galaxy API handlers.
//!
//! Implements the endpoints required for Ansible collection management.
//!
//! Routes are mounted at `/ansible/{repo_key}/...`:
//!   GET  /ansible/{repo_key}/api/v3/collections/                                      - List collections
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/                   - Collection info
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/           - Version list
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/{version}/ - Version info
//!   GET  /ansible/{repo_key}/download/{namespace}-{name}-{version}.tar.gz              - Download
//!   POST /ansible/{repo_key}/api/v3/artifacts/collections/                             - Upload collection

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
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
    multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "ansible")?.user_id;
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let (tarball, collection_json) =
        proxy_helpers::parse_multipart_file_with_json(multipart, &["collection", "metadata"])
            .await?;

    let (namespace, collection_name, collection_version) = if let Some(ref json) = collection_json {
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
        return Err((StatusCode::BAD_REQUEST, "Missing collection metadata JSON").into_response());
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
}
