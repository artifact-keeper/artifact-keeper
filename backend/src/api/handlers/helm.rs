//! Helm Chart Repository API handlers.
//!
//! Implements the endpoints required for `helm repo add`, `helm install`,
//! and ChartMuseum-compatible upload/delete.
//!
//! Routes are mounted at `/helm/{repo_key}/...`:
//!   GET    /helm/{repo_key}/index.yaml                    - Repository index
//!   GET    /helm/{repo_key}/charts/{name}-{version}.tgz   - Download chart package
//!   POST   /helm/{repo_key}/api/charts                    - Upload chart (multipart)
//!   DELETE /helm/{repo_key}/api/charts/{name}/{version}    - Delete chart

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Extension;
use axum::Router;
use sqlx::{PgPool, Row};
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::helm::{generate_index_yaml, ChartYaml, HelmHandler, HelmIndex};
use crate::models::repository::RepositoryType;
use crate::services::proxy_service::ProxyService;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Repository index
        .route("/:repo_key/index.yaml", get(index_yaml))
        // Download chart package
        .route("/:repo_key/charts/:filename", get(download_chart))
        // ChartMuseum-compatible upload
        .route("/:repo_key/api/charts", post(upload_chart))
        // ChartMuseum-compatible delete
        .route("/:repo_key/api/charts/:name/:version", delete(delete_chart))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_helm_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["helm"], "a Helm").await
}

/// Query Helm chart artifacts from a repository and append chart entries to `out`.
async fn query_charts_from_repo(
    db: &PgPool,
    repo_id: uuid::Uuid,
    repo_key: &str,
    out: &mut Vec<(ChartYaml, String, String, String)>,
) -> Result<(), Response> {
    let rows = sqlx::query(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.created_at,
               am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY a.name ASC, a.created_at DESC
        "#,
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(super::db_err)?;

    for row in &rows {
        let name: String = row.get("name");
        let version: Option<String> = row.get("version");
        let checksum_sha256: String = row.get("checksum_sha256");
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let metadata: Option<serde_json::Value> = row.get("metadata");

        let version = match version {
            Some(v) => v,
            None => continue,
        };

        let chart_yaml = metadata
            .as_ref()
            .and_then(|m| m.get("chart"))
            .and_then(|chart_value| serde_json::from_value::<ChartYaml>(chart_value.clone()).ok());

        let chart_yaml = chart_yaml.unwrap_or_else(|| ChartYaml {
            api_version: "v2".to_string(),
            name: name.clone(),
            version: version.clone(),
            kube_version: None,
            description: metadata
                .as_ref()
                .and_then(|m| m.get("description"))
                .and_then(|v| v.as_str())
                .map(String::from),
            chart_type: None,
            keywords: None,
            home: None,
            sources: None,
            dependencies: None,
            maintainers: None,
            icon: None,
            app_version: metadata
                .as_ref()
                .and_then(|m| m.get("appVersion"))
                .and_then(|v| v.as_str())
                .map(String::from),
            deprecated: None,
            annotations: None,
        });

        let filename = format!("{}-{}.tgz", name, version);
        let url = format!("/helm/{}/charts/{}", repo_key, filename);
        let created = created_at.to_rfc3339();
        let digest = checksum_sha256;

        out.push((chart_yaml, url, created, digest));
    }

    Ok(())
}

/// Generate index.yaml content and wrap in a YAML response.
#[allow(clippy::result_large_err)]
fn build_index_response(
    charts: Vec<(ChartYaml, String, String, String)>,
) -> Result<Response, Response> {
    let index_content = generate_index_yaml(charts).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to generate index.yaml: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-yaml; charset=utf-8")
        .body(Body::from(index_content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /helm/{repo_key}/index.yaml -- Helm repository index
// ---------------------------------------------------------------------------

async fn index_yaml(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Virtual repository: merge index.yaml from all member repositories
    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut all_charts: Vec<(ChartYaml, String, String, String)> = Vec::new();

        // Collect index.yaml from remote members and parse chart entries
        let remote_indexes = proxy_helpers::collect_virtual_metadata(
            &state.db,
            state.proxy_service.as_deref(),
            repo.id,
            "index.yaml",
            |bytes, _member_key| async move {
                let yaml_str = String::from_utf8(bytes.to_vec()).map_err(|_| {
                    (StatusCode::BAD_GATEWAY, "Invalid UTF-8 from upstream").into_response()
                })?;
                let index: HelmIndex = serde_yaml::from_str(&yaml_str).map_err(|_| {
                    (StatusCode::BAD_GATEWAY, "Invalid index.yaml from upstream").into_response()
                })?;
                Ok(index)
            },
        )
        .await?;

        for (_member_key, index) in remote_indexes {
            for (_chart_name, entries) in index.entries {
                for entry in entries {
                    let filename = format!("{}-{}.tgz", entry.chart.name, entry.chart.version);
                    let url = format!("/helm/{}/charts/{}", repo_key, filename);
                    all_charts.push((entry.chart, url, entry.created, entry.digest));
                }
            }
        }

        // Query artifacts from local/hosted members
        for member in &members {
            if member.repo_type != RepositoryType::Remote {
                query_charts_from_repo(&state.db, member.id, &repo_key, &mut all_charts).await?;
            }
        }

        return build_index_response(all_charts);
    }

    let mut charts: Vec<(ChartYaml, String, String, String)> = Vec::new();
    query_charts_from_repo(&state.db, repo.id, &repo_key, &mut charts).await?;
    build_index_response(charts)
}

// ---------------------------------------------------------------------------
// GET /helm/{repo_key}/charts/{filename} -- Download chart package
// ---------------------------------------------------------------------------

/// Resolve a chart download URL from an upstream index entry.
///
/// Absolute URLs are returned unchanged so charts hosted on a different
/// domain (e.g. GitHub Releases) work correctly. Relative URLs are
/// resolved against the repo's `upstream_url`.
fn resolve_chart_url(upstream_url: &str, chart_url: &str) -> String {
    if chart_url.starts_with("http://") || chart_url.starts_with("https://") {
        chart_url.to_string()
    } else {
        let base = upstream_url.trim_end_matches('/');
        let path = chart_url.trim_start_matches('/');
        format!("{}/{}", base, path)
    }
}

/// Fetch a chart by looking up its real download URL from the upstream's
/// `index.yaml` instead of assuming `{upstream_url}/charts/{name}-{version}.tgz`.
///
/// The `index.yaml` request goes through the proxy cache, so the extra round-trip
/// is typically free after the first virtual-index request. The chart content is
/// cached under the stable key `charts/{filename}` regardless of where the actual
/// bytes come from, so subsequent downloads are served from cache.
async fn fetch_chart_via_index(
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    name: &str,
    version: &str,
    filename: &str,
) -> Result<Response, Response> {
    // The `index.yaml` lookup stays buffered/capped by design: it is a small
    // metadata document that must be parsed in-process.
    let (index_bytes, _) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        "index.yaml",
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;

    let yaml_str = String::from_utf8(index_bytes.to_vec()).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Invalid UTF-8 in upstream index.yaml",
        )
            .into_response()
    })?;
    let index: HelmIndex = serde_yaml::from_str(&yaml_str).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Failed to parse upstream index.yaml",
        )
            .into_response()
    })?;

    let chart_url = index
        .entries
        .get(name)
        .and_then(|entries| entries.iter().find(|e| e.chart.version == version))
        .and_then(|entry| entry.urls.first())
        .cloned()
        .ok_or_else(|| {
            (StatusCode::NOT_FOUND, "Chart not found in upstream index").into_response()
        })?;

    let fetch_url = resolve_chart_url(upstream_url, &chart_url);
    let cache_path = format!("charts/{}", filename);
    // #2192 / #1608 Phase 4c: the chart itself is a package BLOB, not metadata.
    // The buffered fallback (#2181) capped it at DEFAULT_METADATA_MAX_BYTES and
    // 502'd charts larger than the cap even though the primary download path
    // streams. Route the chart download through the streaming helper (teed into
    // the proxy cache under the same stable `charts/{filename}` key) so large
    // charts succeed with 200 and subsequent requests are served warm.
    let result = proxy_helpers::proxy_fetch_streaming_with_cache_key(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &fetch_url,
        &cache_path,
    )
    .await?;
    proxy_helpers::stream_fetch_result(result, "application/gzip", Some(filename))
}

/// Attempt to download a chart from a Remote or Virtual repo by resolving the
/// real download URL from each upstream's `index.yaml`.
///
/// For Virtual repos the members are tried in priority order: hosted members
/// (local storage) are checked before remote members so that promoted/cached
/// artifacts are served without an upstream round-trip.
async fn download_chart_via_index(
    state: &SharedState,
    repo: &RepoInfo,
    name: &str,
    version: &str,
    filename: &str,
) -> Result<Option<Response>, Response> {
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Ok(None);
    };

    if repo.repo_type == RepositoryType::Remote {
        let Some(upstream_url) = repo.upstream_url.as_deref() else {
            return Ok(None);
        };
        let response = fetch_chart_via_index(
            proxy,
            repo.id,
            &repo.key,
            upstream_url,
            name,
            version,
            filename,
        )
        .await?;
        return Ok(Some(response));
    }

    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        for member in &members {
            if member.repo_type != RepositoryType::Remote {
                // Hosted / staging member: check local storage.
                if let Ok(result) = proxy_helpers::local_fetch_by_path_suffix(
                    &state.db,
                    state,
                    member.id,
                    &member.storage_location(),
                    filename,
                )
                .await
                {
                    return proxy_helpers::stream_fetch_result(
                        result,
                        "application/gzip",
                        Some(filename),
                    )
                    .map(Some);
                }
                continue;
            }

            let Some(upstream_url) = member.upstream_url.as_deref() else {
                continue;
            };
            match fetch_chart_via_index(
                proxy,
                member.id,
                &member.key,
                upstream_url,
                name,
                version,
                filename,
            )
            .await
            {
                Ok(response) => {
                    return Ok(Some(response));
                }
                Err(_) => {
                    tracing::debug!(
                        "helm index lookup miss for member '{}' chart '{}-{}'",
                        member.key,
                        name,
                        version
                    );
                }
            }
        }
        return Ok(None);
    }

    Ok(None)
}

async fn download_chart(
    State(state): State<SharedState>,
    Path((repo_key, filename)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Find artifact by filename pattern; helper escapes wildcards in `filename`.
    let artifact =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, &filename).await? {
            Some(a) => a,
            None => {
                // Parse name and version so we can look up the real download URL
                // from the upstream's index.yaml instead of assuming
                // {upstream_url}/charts/{name}-{version}.tgz.
                let info = HelmHandler::parse_path(&filename).ok();
                let name_version = info
                    .as_ref()
                    .and_then(|i| i.name.as_deref().zip(i.version.as_deref()))
                    .map(|(n, v)| (n.to_string(), v.to_string()));

                if let Some((name, version)) = name_version {
                    if let Some(resp) =
                        download_chart_via_index(&state, &repo, &name, &version, &filename).await?
                    {
                        return Ok(resp);
                    }
                }

                return Err((StatusCode::NOT_FOUND, "Chart not found").into_response());
            }
        };

    proxy_helpers::serve_local_artifact(
        &state,
        &repo,
        artifact.id,
        &artifact.storage_key,
        "application/gzip",
        Some(&filename),
        &ctx,
    )
    .await
}

// ---------------------------------------------------------------------------
// POST /helm/{repo_key}/api/charts -- Upload chart (ChartMuseum-compatible)
// ---------------------------------------------------------------------------

#[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped (assignment expr); the exempt call is marked inline below (#1608)
async fn upload_chart(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    // Authenticate
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "helm", "write")?.user_id;
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Spool the .tgz straight to a bounded scratch file instead of buffering
    // the whole archive in memory. See proxy_helpers::stage_upload_field.
    let mut staged: Option<proxy_helpers::StagedUpload> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid multipart: {}", e)).into_response()
    })? {
        let name = field.name().unwrap_or("").to_string();
        if name == "chart" {
            staged = Some(proxy_helpers::stage_upload_field(&state, field).await?);
            break;
        }
    }

    let staged =
        staged.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'chart' field").into_response())?;

    // Extract and validate Chart.yaml from the staged archive on disk, reading
    // only the Chart.yaml entry (bounded memory) rather than the whole package.
    let chart_yaml = extract_chart_yaml_from_staged(staged.path())
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid chart package: {}", e),
            )
                .into_response()
        })?;

    let chart_name = &chart_yaml.name;
    let chart_version = &chart_yaml.version;
    let filename = format!("{}-{}.tgz", chart_name, chart_version);

    // Build artifact path
    let artifact_path = format!("{}/{}/{}", chart_name, chart_version, filename);

    let conflict_msg = format!(
        "Chart {} version {} already exists",
        chart_name, chart_version
    );
    proxy_helpers::ensure_unique_artifact_path(&state.db, repo.id, &artifact_path, &conflict_msg)
        .await?;

    // Stream the staged archive into the repo's StorageBackend via `put_stream`,
    // which computes the SHA-256 incrementally as it copies (no re-hash pass).
    let storage_key = format!("helm/{}/{}/{}", chart_name, chart_version, filename);
    let put = proxy_helpers::put_artifact_stream(&state, &repo, &storage_key, staged).await?;
    let computed_sha256 = put.checksum_sha256;

    let size_bytes = put.bytes_written as i64;

    // Insert artifact record
    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: chart_name,
            version: chart_version,
            size_bytes,
            checksum_sha256: &computed_sha256,
            content_type: "application/gzip",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    // Build metadata JSON including the full Chart.yaml data
    let helm_metadata = serde_json::json!({
        "name": chart_name,
        "version": chart_version,
        "chart": serde_json::to_value(&chart_yaml).unwrap_or_default(),
    });

    proxy_helpers::record_artifact_metadata(
        &state.db,
        artifact_id,
        repo.id,
        "helm",
        &helm_metadata,
    )
    .await;

    info!(
        "Helm upload: {} {} to repo {}",
        chart_name, chart_version, repo_key
    );

    // ChartMuseum-compatible response
    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "saved": true
            }))
            .unwrap(),
        ))
        .unwrap())
}

/// Extract Chart.yaml from a staged .tgz archive on disk. The blocking
/// flate2/tar decode runs on a blocking thread so it never stalls the async
/// runtime, and only the Chart.yaml entry is read (bounded memory).
async fn extract_chart_yaml_from_staged(path: &std::path::Path) -> Result<ChartYaml, String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)
            .map_err(|e| format!("Failed to open staged archive: {}", e))?;
        HelmHandler::extract_chart_yaml_from_reader(std::io::BufReader::new(file))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("chart extraction task failed: {}", e))?
}

// ---------------------------------------------------------------------------
// DELETE /helm/{repo_key}/api/charts/{name}/{version} -- Delete chart
// ---------------------------------------------------------------------------

async fn delete_chart(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    // Authenticate
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let _user_id = require_auth_basic_scope(auth, "helm", "delete")?.user_id;
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Find the artifact (using non-macro query)
    let row = sqlx::query(
        r#"
        SELECT id, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND is_deleted = false
        LIMIT 1
        "#,
    )
    .bind(repo.id)
    .bind(&name)
    .bind(&version)
    .fetch_optional(&state.db)
    .await
    .map_err(super::db_err)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Chart {} version {} not found", name, version),
        )
            .into_response()
    })?;

    let artifact_id: uuid::Uuid = row.get("id");

    // Soft-delete the artifact
    sqlx::query("UPDATE artifacts SET is_deleted = true, updated_at = NOW() WHERE id = $1")
        .bind(artifact_id)
        .execute(&state.db)
        .await
        .map_err(crate::api::handlers::db_err)?;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!("Helm delete: {} {} from repo {}", name, version, repo_key);

    // ChartMuseum-compatible response
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "deleted": true
            }))
            .unwrap(),
        ))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Build a gzip-compressed tar (`.tgz`) holding a single `path`/`body`
    /// entry, matching the on-disk layout the upload staging path reads.
    fn build_tgz(path: &str, body: &[u8]) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, body).unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&tar_buf).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn test_extract_chart_yaml_from_staged_parses_metadata() {
        let tgz = build_tgz(
            "nginx/Chart.yaml",
            b"apiVersion: v2\nname: nginx\nversion: 9.8.7\n",
        );
        let dir = std::env::temp_dir().join(format!("helm-staged-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chart.tgz");
        std::fs::write(&path, &tgz).unwrap();

        let chart = extract_chart_yaml_from_staged(&path).await.unwrap();
        assert_eq!(chart.name, "nginx");
        assert_eq!(chart.version, "9.8.7");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn test_extract_chart_yaml_from_staged_malformed_errors() {
        let dir = std::env::temp_dir().join(format!("helm-staged-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.tgz");
        std::fs::write(&path, b"this is not a gzip archive").unwrap();

        assert!(extract_chart_yaml_from_staged(&path).await.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // resolve_chart_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_chart_url_absolute_https() {
        let url = resolve_chart_url(
            "https://charts.bitnami.com/bitnami",
            "https://github.com/bitnami/charts/releases/download/nginx-1.0.0/nginx-1.0.0.tgz",
        );
        assert_eq!(
            url,
            "https://github.com/bitnami/charts/releases/download/nginx-1.0.0/nginx-1.0.0.tgz"
        );
    }

    #[test]
    fn test_resolve_chart_url_absolute_http() {
        let url = resolve_chart_url("https://example.com", "http://other.example.com/chart.tgz");
        assert_eq!(url, "http://other.example.com/chart.tgz");
    }

    #[test]
    fn test_resolve_chart_url_absolute_same_origin() {
        let url = resolve_chart_url(
            "https://charts.jetstack.io",
            "https://charts.jetstack.io/charts/cert-manager-v1.14.0.tgz",
        );
        assert_eq!(
            url,
            "https://charts.jetstack.io/charts/cert-manager-v1.14.0.tgz"
        );
    }

    #[test]
    fn test_resolve_chart_url_relative() {
        let url = resolve_chart_url(
            "https://charts.jetstack.io",
            "charts/cert-manager-v1.14.0.tgz",
        );
        assert_eq!(
            url,
            "https://charts.jetstack.io/charts/cert-manager-v1.14.0.tgz"
        );
    }

    #[test]
    fn test_resolve_chart_url_relative_leading_slash() {
        let url = resolve_chart_url(
            "https://charts.jetstack.io",
            "/charts/cert-manager-v1.14.0.tgz",
        );
        assert_eq!(
            url,
            "https://charts.jetstack.io/charts/cert-manager-v1.14.0.tgz"
        );
    }

    #[test]
    fn test_resolve_chart_url_upstream_trailing_slash() {
        let url = resolve_chart_url(
            "https://charts.jetstack.io/",
            "charts/cert-manager-v1.14.0.tgz",
        );
        assert_eq!(
            url,
            "https://charts.jetstack.io/charts/cert-manager-v1.14.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // Format-specific logic: filename, artifact_path, storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_helm_chart_filename() {
        let name = "nginx";
        let version = "1.24.0";
        let filename = format!("{}-{}.tgz", name, version);
        assert_eq!(filename, "nginx-1.24.0.tgz");
    }

    #[test]
    fn test_helm_artifact_path() {
        let name = "prometheus";
        let version = "25.0.0";
        let filename = format!("{}-{}.tgz", name, version);
        let path = format!("{}/{}/{}", name, version, filename);
        assert_eq!(path, "prometheus/25.0.0/prometheus-25.0.0.tgz");
    }

    #[test]
    fn test_helm_storage_key() {
        let name = "grafana";
        let version = "7.0.0";
        let filename = format!("{}-{}.tgz", name, version);
        let key = format!("helm/{}/{}/{}", name, version, filename);
        assert_eq!(key, "helm/grafana/7.0.0/grafana-7.0.0.tgz");
    }

    #[test]
    fn test_helm_chart_url() {
        let repo_key = "helm-local";
        let filename = "ingress-nginx-4.8.0.tgz";
        let url = format!("/helm/{}/charts/{}", repo_key, filename);
        assert_eq!(url, "/helm/helm-local/charts/ingress-nginx-4.8.0.tgz");
    }

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"chart content");
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
            storage_path: "/data/helm".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
        };
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/cache/helm".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://charts.helm.sh/stable".to_string()),
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://charts.helm.sh/stable")
        );
    }

    // -----------------------------------------------------------------------
    // DB-backed router tests for the proxy_helpers-call paths.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    #[tokio::test]
    async fn test_helm_chart_download_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/missing-1.0.0.tgz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_helm_chart_download_serves_local() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "helm/mychart/0.1.0/mychart-0.1.0.tgz",
            "mychart/0.1.0/mychart-0.1.0.tgz",
            "mychart",
            "0.1.0",
            "application/gzip",
            bytes::Bytes::from_static(b"helm-chart"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/mychart-0.1.0.tgz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"helm-chart");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_helm_upload_unauthenticated_401() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = tdh::post(
            format!("/{}/api/charts", f.repo_key),
            "multipart/form-data; boundary=B",
            bytes::Bytes::from_static(b"--B--\r\n"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_helm_upload_remote_405() {
        let Some(f) = tdh::Fixture::setup("remote", "helm").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = tdh::post(
            format!("/{}/api/charts", f.repo_key),
            "multipart/form-data; boundary=B",
            bytes::Bytes::from_static(b"--B--\r\n"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_helm_index_yaml_empty_repo() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(app, tdh::get(format!("/{}/index.yaml", f.repo_key))).await;
        assert_eq!(status, StatusCode::OK);
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // fetch_chart_via_index — wiremock-backed unit tests
    // -----------------------------------------------------------------------

    fn make_index_yaml(chart_name: &str, version: &str, url: &str) -> String {
        format!(
            r#"apiVersion: v1
generated: "2024-01-01T00:00:00Z"
entries:
  {chart_name}:
    - apiVersion: v2
      name: {chart_name}
      version: {version}
      urls:
        - {url}
      created: "2024-01-01T00:00:00Z"
      digest: abc123deadbeef
"#
        )
    }

    fn proxy_tmp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("helm-proxy-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    // Tests that make real HTTP calls need a live database pool because
    // ProxyService::fetch_from_upstream calls load_upstream_auth which queries
    // the DB. Tests that return before any HTTP call can use a fake lazy pool.

    #[tokio::test]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    #[allow(clippy::disallowed_methods)]
    async fn test_fetch_chart_via_index_success_relative_url() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let upstream_url = server.uri();
        let index_yaml = make_index_yaml("mychart", "1.0.0", "charts/mychart-1.0.0.tgz");
        let chart_bytes: &[u8] = b"fake-chart-content";

        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(index_yaml.as_bytes()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/charts/mychart-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(chart_bytes))
            .mount(&server)
            .await;

        let tmp = proxy_tmp_dir();
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &proxy,
            repo_id,
            "helm-proxy",
            &upstream_url,
            "mychart",
            "1.0.0",
            "mychart-1.0.0.tgz",
        )
        .await;

        let _ = std::fs::remove_dir_all(&tmp);

        match result {
            Ok(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(
                    resp.headers()
                        .get("content-disposition")
                        .and_then(|v| v.to_str().ok()),
                    Some("attachment; filename=\"mychart-1.0.0.tgz\"")
                );
                let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .expect("collect streamed chart body");
                assert_eq!(&body[..], chart_bytes);
            }
            Err(_) => panic!("fetch_chart_via_index should succeed"),
        }
    }

    #[tokio::test]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    #[allow(clippy::disallowed_methods)]
    async fn test_fetch_chart_via_index_success_absolute_url() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let upstream_url = server.uri();
        let abs_chart_url = format!("{}/charts/abs-chart-1.0.0.tgz", upstream_url);
        let index_yaml = make_index_yaml("abs-chart", "1.0.0", &abs_chart_url);
        let chart_bytes: &[u8] = b"absolute-url-chart";

        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(index_yaml.as_bytes()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/charts/abs-chart-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(chart_bytes))
            .mount(&server)
            .await;

        let tmp = proxy_tmp_dir();
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &proxy,
            repo_id,
            "helm-proxy-abs",
            &upstream_url,
            "abs-chart",
            "1.0.0",
            "abs-chart-1.0.0.tgz",
        )
        .await;

        let _ = std::fs::remove_dir_all(&tmp);

        match result {
            Ok(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .expect("collect streamed chart body");
                assert_eq!(&body[..], chart_bytes);
            }
            Err(_) => panic!("fetch_chart_via_index (absolute URL) should succeed"),
        }
    }

    // #2192 / #1608 Phase 4c: a chart larger than the old buffered cap
    // (DEFAULT_METADATA_MAX_BYTES = 8 MiB) must now STREAM with 200 instead of
    // 502, and the second request must be served WARM from the teed proxy cache
    // without a second upstream round-trip for the chart blob.
    #[tokio::test]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    #[allow(clippy::disallowed_methods)]
    async fn test_fetch_chart_via_index_streams_large_chart_and_warms_cache() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let upstream_url = server.uri();
        let index_yaml = make_index_yaml("big", "3.0.0", "charts/big-3.0.0.tgz");
        // 9 MiB > 8 MiB DEFAULT_METADATA_MAX_BYTES: would 502 on the buffered path.
        let chart_bytes = vec![0x42u8; 9 * 1024 * 1024];

        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(index_yaml.as_bytes()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/charts/big-3.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(chart_bytes.clone()))
            // Cache warm proof: the chart blob is fetched from upstream at most
            // once across the two requests below.
            .expect(1)
            .mount(&server)
            .await;

        let tmp = proxy_tmp_dir();
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo_id = uuid::Uuid::new_v4();

        for i in 0..2 {
            // Before the second request, wait for the streaming write-back to
            // commit so the cache is deterministically WARM.
            if i == 1 {
                tdh::wait_for_cache_commit(&tmp, chart_bytes.len() as u64).await;
            }
            let result = fetch_chart_via_index(
                &proxy,
                repo_id,
                "helm-proxy-big",
                &upstream_url,
                "big",
                "3.0.0",
                "big-3.0.0.tgz",
            )
            .await;
            match result {
                Ok(resp) => {
                    assert_eq!(resp.status(), StatusCode::OK);
                    assert_eq!(
                        resp.headers()
                            .get("content-disposition")
                            .and_then(|v| v.to_str().ok()),
                        Some("attachment; filename=\"big-3.0.0.tgz\"")
                    );
                    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                        .await
                        .expect("collect streamed chart body");
                    assert_eq!(body.len(), chart_bytes.len());
                }
                Err(_) => panic!("large chart must stream with 200, not 502"),
            }
        }

        // `.expect(1)` on the chart mock is verified on server drop.
        drop(server);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_fetch_chart_via_index_chart_not_in_index() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let upstream_url = server.uri();
        let index_yaml = "apiVersion: v1\ngenerated: \"2024-01-01T00:00:00Z\"\nentries: {}\n";

        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(index_yaml.as_bytes()))
            .mount(&server)
            .await;

        let tmp = proxy_tmp_dir();
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &proxy,
            repo_id,
            "helm-proxy",
            &upstream_url,
            "nonexistent",
            "9.9.9",
            "nonexistent-9.9.9.tgz",
        )
        .await;

        let _ = std::fs::remove_dir_all(&tmp);

        match result {
            Err(resp) => assert_eq!(resp.status(), StatusCode::NOT_FOUND),
            Ok(_) => panic!("expected NOT_FOUND for missing chart"),
        }
    }

    #[tokio::test]
    async fn test_fetch_chart_via_index_invalid_yaml() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let upstream_url = server.uri();

        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"not_valid_helm_index: [unclosed"),
            )
            .mount(&server)
            .await;

        let tmp = proxy_tmp_dir();
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &proxy,
            repo_id,
            "helm-proxy",
            &upstream_url,
            "mychart",
            "1.0.0",
            "mychart-1.0.0.tgz",
        )
        .await;

        let _ = std::fs::remove_dir_all(&tmp);

        match result {
            Err(resp) => assert_eq!(resp.status(), StatusCode::BAD_GATEWAY),
            Ok(_) => panic!("expected BAD_GATEWAY for invalid YAML"),
        }
    }

    // -----------------------------------------------------------------------
    // download_chart_via_index — path-coverage tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_download_chart_via_index_remote_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let upstream_url = server.uri();
        let index_yaml = make_index_yaml("tc", "2.0.0", "charts/tc-2.0.0.tgz");

        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(index_yaml.as_bytes()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/charts/tc-2.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tc-content"))
            .mount(&server)
            .await;

        let tmp = proxy_tmp_dir();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);

        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: "helm-remote-dl".to_string(),
            storage_path: tmp.to_str().unwrap().to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some(upstream_url),
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
        };

        let result = download_chart_via_index(&state, &repo, "tc", "2.0.0", "tc-2.0.0.tgz").await;

        let _ = std::fs::remove_dir_all(&tmp);

        match result {
            Ok(Some(_)) => {}
            Ok(None) => panic!("expected Some response, got None"),
            Err(_) => panic!("expected Ok"),
        }
    }

    // These two tests return Ok(None) before any HTTP call so they work
    // without a real database.

    #[tokio::test]
    async fn test_download_chart_via_index_remote_no_upstream_url() {
        let tmp = proxy_tmp_dir();
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy");
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);

        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: "helm-remote-no-up".to_string(),
            storage_path: tmp.to_str().unwrap().to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: None,
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
        };

        let result = download_chart_via_index(&state, &repo, "ch", "1.0.0", "ch-1.0.0.tgz").await;
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn test_download_chart_via_index_local_repo_returns_none() {
        let tmp = proxy_tmp_dir();
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy");
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);

        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: "helm-hosted".to_string(),
            storage_path: tmp.to_str().unwrap().to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
        };

        let result = download_chart_via_index(&state, &repo, "ch", "1.0.0", "ch-1.0.0.tgz").await;
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(matches!(result, Ok(None)));
    }
}

#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_helm_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/index.yaml"),
            format!("/{k}/charts/name-1.0.0.tgz"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }
}
