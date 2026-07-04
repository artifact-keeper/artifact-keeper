//! Chef Supermarket API handlers.
//!
//! Implements the endpoints required for Chef cookbook management.
//!
//! Routes are mounted at `/chef/{repo_key}/...`:
//!   GET  /chef/{repo_key}/api/v1/cookbooks                                  - List cookbooks
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}                           - Cookbook info
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}        - Version info
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}/download - Download tarball
//!   POST /chef/{repo_key}/api/v1/cookbooks                                  - Upload cookbook

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
#[cfg(test)]
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::formats::chef::ChefHandler;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:repo_key/api/v1/cookbooks",
            get(list_cookbooks).post(upload_cookbook),
        )
        .route("/:repo_key/api/v1/cookbooks/:name", get(cookbook_info))
        .route(
            "/:repo_key/api/v1/cookbooks/:name/versions/:version",
            get(version_info),
        )
        .route(
            "/:repo_key/api/v1/cookbooks/:name/versions/:version/download",
            get(download_cookbook),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_chef_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["chef"], "a Chef").await
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks — List cookbooks
// ---------------------------------------------------------------------------

async fn list_cookbooks(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

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
    .map_err(crate::api::handlers::db_err)?;

    let items: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let name = a.name.clone();
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "cookbook_name": name,
                "cookbook_maintainer": "",
                "cookbook_description": "",
                "cookbook": format!("/chef/{}/api/v1/cookbooks/{}", repo_key, name),
                "latest_version": version,
            })
        })
        .collect();

    let json = serde_json::json!({
        "start": 0,
        "total": items.len(),
        "items": items,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks/{name} — Cookbook info
// ---------------------------------------------------------------------------

async fn cookbook_info(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        name
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    if artifacts.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Cookbook not found").into_response());
    }

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "version": version,
                "url": format!(
                    "/chef/{}/api/v1/cookbooks/{}/versions/{}",
                    repo_key, name, version
                ),
            })
        })
        .collect();

    let latest_version = artifacts[0].version.clone().unwrap_or_default();
    let description = artifacts[0]
        .metadata
        .as_ref()
        .and_then(|m| m.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let json = serde_json::json!({
        "name": name,
        "maintainer": "",
        "description": description,
        "latest_version": latest_version,
        "versions": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version} — Version info
// ---------------------------------------------------------------------------

async fn version_info(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo.id,
        name,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Cookbook version not found").into_response())?;

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "cookbook": name,
        "version": version,
        "file": format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}/download",
            repo_key, name, version
        ),
        "tarball_file_size": artifact.size_bytes,
        "sha256": artifact.checksum_sha256,
        "downloads": download_count,
        "metadata": artifact.metadata.unwrap_or(serde_json::json!({})),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}/download
// ---------------------------------------------------------------------------

async fn download_cookbook(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, name, version, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        name,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Cookbook version not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path =
                        format!("api/v1/cookbooks/{}/versions/{}/download", name, version);
                    // #1608 Phase 4: stream the cookbook archive (.tar.gz) to
                    // the client while teeing to the proxy cache, instead of
                    // buffering the whole cookbook in memory. Single-flight via
                    // the merged coordinator (#1609).
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
                let upstream_path =
                    format!("api/v1/cookbooks/{}/versions/{}/download", name, version);
                let name_clone = name.clone();
                let version_clone = version.clone();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let n = name_clone.clone();
                        let v = version_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db, &state, member_id, &location, &n, &v,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(result, "application/gzip", None);
            }

            return Err(not_found);
        }
    };

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

    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let filename = format!("{}-{}.tar.gz", name, version);

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
// POST /chef/{repo_key}/api/v1/cookbooks — Upload cookbook (multipart)
// ---------------------------------------------------------------------------

async fn upload_cookbook(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "chef")?.user_id;
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Spool the tarball straight to a bounded scratch file instead of buffering
    // the whole body in memory; the small `cookbook` JSON field is still read
    // in-hand. See proxy_helpers::stage_upload_field / put_artifact_stream.
    let mut staged: Option<proxy_helpers::StagedUpload> = None;
    let mut cookbook_json: Option<serde_json::Value> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e)).into_response())?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "tarball" => {
                staged = Some(proxy_helpers::stage_upload_field(&state, field).await?);
            }
            "cookbook" => {
                // Small JSON metadata field (not the artifact body): read as
                // text (a length-limited extractor) and parse in-hand.
                let data = field.text().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read cookbook JSON: {}", e),
                    )
                        .into_response()
                })?;
                cookbook_json = Some(serde_json::from_str(&data).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid cookbook JSON: {}", e),
                    )
                        .into_response()
                })?);
            }
            _ => {}
        }
    }

    let staged =
        staged.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing tarball field").into_response())?;

    if staged.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    // Extract name and version from cookbook JSON or validate the tarball
    let (cookbook_name, cookbook_version) = if let Some(ref json) = cookbook_json {
        let name = json
            .get("cookbook_name")
            .or_else(|| json.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = json
            .get("cookbook_version")
            .or_else(|| json.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (name, version)
    } else {
        // Validate via format handler as fallback
        let path = "api/v1/cookbooks/unknown/versions/0.0.0";
        let _ = ChefHandler::parse_path(path);
        return Err((StatusCode::BAD_REQUEST, "Missing cookbook metadata JSON").into_response());
    };

    if cookbook_name.is_empty() || cookbook_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Cookbook name and version are required",
        )
            .into_response());
    }

    // Validate via format handler
    let validate_path = format!(
        "api/v1/cookbooks/{}/versions/{}",
        cookbook_name, cookbook_version
    );
    let _ = ChefHandler::parse_path(&validate_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid cookbook: {}", e)).into_response()
    })?;

    let filename = format!("{}-{}.tar.gz", cookbook_name, cookbook_version);

    let artifact_path = format!("{}/{}/{}", cookbook_name, cookbook_version, filename);

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
        return Err((StatusCode::CONFLICT, "Cookbook version already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Stream the staged tarball into the repo's StorageBackend via `put_stream`,
    // which computes the SHA-256 incrementally as it copies (no re-hash).
    let storage_key = format!("chef/{}/{}/{}", cookbook_name, cookbook_version, filename);
    let put = proxy_helpers::put_artifact_stream(&state, &repo, &storage_key, staged).await?;
    let computed_sha256 = put.checksum_sha256;

    let chef_metadata = serde_json::json!({
        "cookbook_name": cookbook_name,
        "cookbook_version": cookbook_version,
        "filename": filename,
        "cookbook_json": cookbook_json,
    });

    let size_bytes = put.bytes_written as i64;

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
        cookbook_name,
        cookbook_version,
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

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'chef', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        chef_metadata,
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
        "Chef upload: {} {} ({}) to repo {}",
        cookbook_name, cookbook_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "uri": format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}",
            repo_key, cookbook_name, cookbook_version
        ),
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_remote_cookbook_download_streams_upstream_blob_1608() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "chef").await else {
            return;
        };
        let server = MockServer::start().await;
        // A small deterministic body stands in for a large artifact; the point
        // is to exercise the streaming pull-through branch (proxy_fetch_streaming)
        // added in #1608 Phase 4, not the body size.
        let blob: &[u8] = b"\x00\x01\x02 #1608 phase4 streamed proxy blob \x03\x04\x05";
        Mock::given(method("GET"))
            .and(path("/api/v1/cookbooks/nginx/versions/1.0.0/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{key}/api/v1/cookbooks/nginx/versions/1.0.0/download",
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

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // Format-specific logic: filename, artifact_path, storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_cookbook_filename_format() {
        let name = "apache2";
        let version = "8.0.0";
        let filename = format!("{}-{}.tar.gz", name, version);
        assert_eq!(filename, "apache2-8.0.0.tar.gz");
    }

    #[test]
    fn test_cookbook_artifact_path_format() {
        let name = "nginx";
        let version = "12.0.0";
        let filename = format!("{}-{}.tar.gz", name, version);
        let artifact_path = format!("{}/{}/{}", name, version, filename);
        assert_eq!(artifact_path, "nginx/12.0.0/nginx-12.0.0.tar.gz");
    }

    #[test]
    fn test_cookbook_storage_key_format() {
        let name = "mysql";
        let version = "5.0.0";
        let filename = format!("{}-{}.tar.gz", name, version);
        let storage_key = format!("chef/{}/{}/{}", name, version, filename);
        assert_eq!(storage_key, "chef/mysql/5.0.0/mysql-5.0.0.tar.gz");
    }

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"cookbook content");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_hosted() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/chef".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            promotion_only: false,
        };
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/cache/chef".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://supermarket.chef.io".to_string()),
            promotion_only: false,
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://supermarket.chef.io")
        );
    }

    // -----------------------------------------------------------------------
    // Chef metadata JSON construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_chef_metadata_json() {
        let cookbook_name = "apache2";
        let cookbook_version = "8.0.0";
        let filename = format!("{}-{}.tar.gz", cookbook_name, cookbook_version);
        let cookbook_json: Option<serde_json::Value> = Some(serde_json::json!({
            "cookbook_name": cookbook_name,
            "version": cookbook_version,
        }));

        let meta = serde_json::json!({
            "cookbook_name": cookbook_name,
            "cookbook_version": cookbook_version,
            "filename": filename,
            "cookbook_json": cookbook_json,
        });

        assert_eq!(meta["cookbook_name"], "apache2");
        assert_eq!(meta["cookbook_version"], "8.0.0");
        assert_eq!(meta["filename"], "apache2-8.0.0.tar.gz");
        assert!(meta["cookbook_json"].is_object());
    }

    // -----------------------------------------------------------------------
    // Chef API URL format
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_info_url() {
        let repo_key = "chef-local";
        let name = "nginx";
        let version = "12.0.0";
        let url = format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}",
            repo_key, name, version
        );
        assert_eq!(
            url,
            "/chef/chef-local/api/v1/cookbooks/nginx/versions/12.0.0"
        );
    }

    #[test]
    fn test_download_url() {
        let repo_key = "chef-local";
        let name = "nginx";
        let version = "12.0.0";
        let url = format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}/download",
            repo_key, name, version
        );
        assert_eq!(
            url,
            "/chef/chef-local/api/v1/cookbooks/nginx/versions/12.0.0/download"
        );
    }
}

#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_chef_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "chef").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/api/v1/cookbooks"),
            format!("/{k}/api/v1/cookbooks/name"),
            format!("/{k}/api/v1/cookbooks/name/versions/1.0.0"),
            format!("/{k}/api/v1/cookbooks/name/versions/1.0.0/download"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }
}

#[cfg(test)]
mod upload_stream_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;
    use sha2::{Digest, Sha256};

    /// Build a `knife`-style cookbook upload body: a `cookbook` JSON metadata
    /// part plus a `tarball` file part.
    fn cookbook_multipart(
        boundary: &str,
        name: &str,
        version: &str,
        tarball: &[u8],
    ) -> bytes::Bytes {
        let meta = format!("{{\"cookbook_name\":\"{name}\",\"cookbook_version\":\"{version}\"}}");
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"cookbook\"\r\n\r\n");
        body.extend_from_slice(meta.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"tarball\"; filename=\"{name}-{version}.tar.gz\"\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/gzip\r\n\r\n");
        body.extend_from_slice(tarball);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        bytes::Bytes::from(body)
    }

    #[tokio::test]
    async fn test_chef_upload_streams_and_records_checksum() {
        let Some(fx) = tdh::Fixture::setup("local", "chef").await else {
            return;
        };
        // A padded payload much larger than one stream chunk, so the upload
        // exercises the spool-to-disk streaming path rather than a small buffer.
        let tarball = b"cookbook-payload-".repeat(8192); // ~135 KB
        let body = cookbook_multipart("CHEFBND", "apache2", "8.0.0", &tarball);

        let app = fx.router_with_auth(super::router());
        let (status, resp) = tdh::send(
            app,
            tdh::post(
                format!("/{}/api/v1/cookbooks", fx.repo_key),
                "multipart/form-data; boundary=CHEFBND",
                body,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "unexpected status, body={}",
            String::from_utf8_lossy(&resp)
        );

        // The artifact row carries the checksum computed incrementally by
        // put_stream and the true streamed size. Use the runtime query API so
        // this test needs no offline sqlx cache entry.
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT checksum_sha256, size_bytes, storage_key FROM artifacts \
             WHERE repository_id = $1 AND is_deleted = false",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("artifact row");
        let checksum: String = row.get("checksum_sha256");
        let size_bytes: i64 = row.get("size_bytes");
        let storage_key: String = row.get("storage_key");
        let mut hasher = Sha256::new();
        hasher.update(&tarball);
        assert_eq!(checksum, format!("{:x}", hasher.finalize()));
        assert_eq!(size_bytes, tarball.len() as i64);

        // The bytes really landed in the configured backend under the key.
        let stored = fx
            .state
            .storage
            .get(&storage_key)
            .await
            .expect("stored object");
        assert_eq!(stored.len(), tarball.len());

        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_chef_upload_rejects_empty_tarball() {
        let Some(fx) = tdh::Fixture::setup("local", "chef").await else {
            return;
        };
        let body = cookbook_multipart("CHEFBND", "apache2", "8.0.0", b"");
        let app = fx.router_with_auth(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::post(
                format!("/{}/api/v1/cookbooks", fx.repo_key),
                "multipart/form-data; boundary=CHEFBND",
                body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        fx.teardown().await;
    }
}
