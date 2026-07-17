//! Helm Chart Repository API handlers.
//!
//! Implements the endpoints required for `helm repo add`, `helm install`,
//! and ChartMuseum-compatible upload/delete.
//!
//! Routes are mounted at `/helm/{repo_key}/...`:
//!   GET    /helm/{repo_key}/index.yaml                        - Repository index
//!   GET    /helm/{repo_key}/charts/{name}-{version}.tgz       - Download chart package
//!   GET    /helm/{repo_key}/charts/{name}-{version}.tgz.prov  - Download chart provenance
//!   POST   /helm/{repo_key}/api/charts                        - Upload chart (multipart)
//!   DELETE /helm/{repo_key}/api/charts/{name}/{version}        - Delete chart
//!
//! ## Provenance (#2635)
//!
//! `helm package --sign` emits a clearsigned `<chart>.tgz.prov` next to the
//! chart. The client does **not** discover it from `index.yaml` — the helm
//! index schema has no provenance field. Instead `helm pull --verify` takes the
//! chart URL it resolved from `index.yaml` and string-appends `.prov`
//! (verified against helm 3.16.4). So provenance is served by the *existing*
//! `charts/{filename}` route: the upload stores the prov under the chart's
//! filename + `.prov`, and the download route resolves it by the same
//! suffix lookup the chart itself uses.

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
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::proxy_service::ProxyService;
use crate::services::quarantine_service;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Repository index
        .route("/:repo_key/index.yaml", get(index_yaml))
        // Download chart package (also serves `<chart>.tgz.prov` provenance)
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

// ---------------------------------------------------------------------------
// Provenance helpers (#2635)
// ---------------------------------------------------------------------------

/// Suffix helm appends to a chart URL to locate its provenance file.
const PROV_SUFFIX: &str = ".prov";

/// Armor header every `helm package --sign` provenance file starts with. The
/// prov is a *clearsigned* PGP document (chart metadata + a `files:` digest
/// block, then the signature).
const PROV_ARMOR_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";

/// Content type used when serving a provenance file.
const PROV_CONTENT_TYPE: &str = "application/pgp-signature";

/// Bytes read from the head of a staged prov to check its armor header.
const PROV_HEAD_PROBE_BYTES: usize = 128;

/// Provenance filename for a chart package filename
/// (`nginx-1.0.0.tgz` -> `nginx-1.0.0.tgz.prov`).
fn prov_filename(chart_filename: &str) -> String {
    format!("{}{}", chart_filename, PROV_SUFFIX)
}

/// Whether a requested `charts/{filename}` is a provenance file rather than a
/// chart package.
fn is_prov_filename(filename: &str) -> bool {
    filename.ends_with(PROV_SUFFIX)
}

/// Validate that an uploaded `prov` part really is a clearsigned provenance
/// document before it is stored.
///
/// Storing arbitrary bytes under `<chart>.tgz.prov` would just move the failure
/// downstream: `helm pull --verify` would fetch them and die with an opaque
/// error. Rejecting at the door keeps the upload response honest — the client
/// learns immediately that its provenance was not accepted (#2635).
fn validate_prov_bytes(head: &[u8]) -> Result<(), String> {
    if head.is_empty() {
        return Err("provenance file is empty".to_string());
    }
    let text = String::from_utf8_lossy(head);
    if !text.trim_start().starts_with(PROV_ARMOR_HEADER) {
        return Err(format!(
            "provenance file must be a clearsigned PGP document starting with '{}'",
            PROV_ARMOR_HEADER
        ));
    }
    Ok(())
}

/// ChartMuseum-compatible upload response body.
///
/// `saved` reports the chart. `prov` is reported **only** when a provenance
/// file was actually written to storage — never merely because a `prov` part
/// was present in the request. Answering `{"saved":true}` for provenance that
/// was discarded is the defect at the heart of #2635: it gives the publisher a
/// false assurance that their chart is verifiable.
fn upload_response_body(prov_stored: bool) -> serde_json::Value {
    if prov_stored {
        serde_json::json!({ "saved": true, "prov": true })
    } else {
        // Chart-only upload: byte-identical to the historical ChartMuseum reply.
        serde_json::json!({ "saved": true })
    }
}

/// Query Helm chart artifacts from a repository and append chart entries to `out`.
///
/// Provenance rows are excluded: a `.prov` is stored as its own artifact under
/// the same `name`/`version` as its chart (#2635), so without the filter every
/// signed chart would render a duplicate `index.yaml` entry.
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
          AND a.path NOT LIKE '%.prov'
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
        RepositoryFormat::Helm,
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

    // `<chart>.tgz.prov` is stored as an artifact under its own filename, so the
    // same suffix lookup resolves both a chart and its provenance (#2635). Only
    // the content type and the not-found wording differ.
    let is_prov = is_prov_filename(&filename);

    // Find artifact by filename pattern; helper escapes wildcards in `filename`.
    let artifact = match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, &filename)
        .await?
    {
        Some(a) => a,
        None => {
            if is_prov {
                // Provenance is only ever served from local storage: helm
                // derives this URL by appending `.prov` to the chart URL, so
                // there is no upstream index entry to resolve it through.
                return Err((StatusCode::NOT_FOUND, "Chart provenance not found").into_response());
            }
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

    let content_type = if is_prov {
        PROV_CONTENT_TYPE
    } else {
        "application/gzip"
    };

    proxy_helpers::serve_local_artifact(
        &state,
        &repo,
        artifact.id,
        &artifact.storage_key,
        content_type,
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
    //
    // #2635: the `prov` part is staged too rather than being dropped on the
    // floor. The loop no longer breaks on `chart` because ChartMuseum clients
    // may send the parts in either order, and a part that is never read is a
    // part that gets silently discarded.
    let mut staged: Option<proxy_helpers::StagedUpload> = None;
    let mut staged_prov: Option<proxy_helpers::StagedUpload> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid multipart: {}", e)).into_response()
    })? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "chart" => staged = Some(proxy_helpers::stage_upload_field(&state, field).await?),
            "prov" => staged_prov = Some(proxy_helpers::stage_upload_field(&state, field).await?),
            _ => {}
        }
    }

    let staged =
        staged.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'chart' field").into_response())?;

    // Validate the provenance before the chart is committed, so a bad prov
    // fails the whole upload instead of leaving a chart that advertises
    // provenance it cannot serve.
    if let Some(prov) = staged_prov.as_ref() {
        let head = read_prov_head(prov.path()).await?;
        validate_prov_bytes(&head).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid provenance file: {}", e),
            )
                .into_response()
        })?;
    }

    // Extract and validate Chart.yaml from the staged archive on disk, reading
    // only the Chart.yaml entry (bounded memory) rather than the whole package.
    // #2561: permit held across the blocking decode, fast-fail 503 on saturation.
    let chart_yaml = crate::util::bounded_archive::with_ingest_extraction_async(|| {
        extract_chart_yaml_from_staged(staged.path())
    })
    .await
    .map_err(|e| e.into_response())?
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

    // The prov is stored under the chart's filename + `.prov` -- the exact path
    // helm derives from the index URL (#2635).
    let prov_filename = prov_filename(&filename);
    let prov_artifact_path = format!("{}/{}/{}", chart_name, chart_version, prov_filename);
    if staged_prov.is_some() {
        proxy_helpers::ensure_unique_artifact_path(
            &state.db,
            repo.id,
            &prov_artifact_path,
            &conflict_msg,
        )
        .await?;
    }

    // A chart and its provenance are one publish, so they must land as one
    // unit (#2635). Ordering below is load-bearing:
    //
    //   1. BOTH objects go to storage first. Object storage cannot join a DB
    //      transaction, so every fallible storage write happens while the
    //      repository still has no row pointing at this coordinate.
    //   2. BOTH rows are inserted inside ONE transaction. A fault on the prov
    //      row rolls the chart row back with it.
    //
    // The property that matters is that a failure is *retryable*: nothing
    // commits a chart row until the prov is safely stored, so the publisher's
    // retry cannot collide with a half-finished predecessor in
    // `ensure_unique_artifact_path` and get a 409 it can never clear. An
    // orphaned object left in storage by an interrupted upload is overwritten
    // by that retry -- the storage key is fully determined by chart name and
    // version.

    // Stream the staged archive into the repo's StorageBackend via `put_stream`,
    // which computes the SHA-256 incrementally as it copies (no re-hash pass).
    let storage_key = format!("helm/{}/{}/{}", chart_name, chart_version, filename);
    let put = proxy_helpers::put_artifact_stream(&state, &repo, &storage_key, staged).await?;
    let computed_sha256 = put.checksum_sha256;

    let size_bytes = put.bytes_written as i64;

    // #2635: persist the provenance BEFORE the chart row is committed. Any
    // failure here is propagated with `?` -- the handler must never fall
    // through to a `{"saved":true}` reply while the prov is on the floor, and
    // must never leave behind a chart that advertises provenance it cannot
    // serve.
    let prov_storage_key = format!("helm/{}/{}/{}", chart_name, chart_version, prov_filename);
    let prov_put = match staged_prov {
        Some(prov) => {
            Some(proxy_helpers::put_artifact_stream(&state, &repo, &prov_storage_key, prov).await?)
        }
        None => None,
    };

    // Both objects are in storage. Commit both rows together or neither.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| proxy_helpers::internal_error("Database", e))?;

    let artifact_id = proxy_helpers::insert_artifact_row(
        &mut tx,
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

    let prov_artifact_id = match prov_put.as_ref() {
        Some(prov_put) => Some(
            proxy_helpers::insert_artifact_row(
                &mut tx,
                proxy_helpers::NewArtifact {
                    repository_id: repo.id,
                    path: &prov_artifact_path,
                    name: chart_name,
                    version: chart_version,
                    size_bytes: prov_put.bytes_written as i64,
                    checksum_sha256: &prov_put.checksum_sha256,
                    content_type: PROV_CONTENT_TYPE,
                    storage_key: &prov_storage_key,
                    uploaded_by: user_id,
                },
            )
            .await?,
        ),
        None => None,
    };

    // Until this returns, a fault has left the repository exactly as it was.
    tx.commit()
        .await
        .map_err(|e| proxy_helpers::internal_error("Database", e))?;

    // Post-commit follow-ups. The quarantine hold reads the artifact row back
    // through the pool, so it can only run once the rows are visible; metadata
    // recording is best-effort by contract.
    quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id).await;

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

    if let Some(prov_artifact_id) = prov_artifact_id {
        quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, prov_artifact_id).await;

        proxy_helpers::record_artifact_metadata(
            &state.db,
            prov_artifact_id,
            repo.id,
            "helm",
            &serde_json::json!({
                "name": chart_name,
                "version": chart_version,
                "provenance": true,
                "chart_filename": filename,
            }),
        )
        .await;
    }

    let prov_stored = prov_artifact_id.is_some();

    info!(
        "Helm upload: {} {} to repo {} (provenance: {})",
        chart_name, chart_version, repo_key, prov_stored
    );

    // ChartMuseum-compatible response
    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&upload_response_body(prov_stored)).unwrap(),
        ))
        .unwrap())
}

/// Read the leading bytes of a staged provenance file for armor validation.
///
/// Bounded on purpose: only the armor header is needed, so the whole prov is
/// never pulled into memory.
#[allow(clippy::result_large_err)]
async fn read_prov_head(path: &std::path::Path) -> Result<Vec<u8>, Response> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to read staged provenance: {}", e),
        )
            .into_response()
    })?;
    let mut head = vec![0u8; PROV_HEAD_PROBE_BYTES];
    let n = file.read(&mut head).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to read staged provenance: {}", e),
        )
            .into_response()
    })?;
    head.truncate(n);
    Ok(head)
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

    // Find the chart's artifacts. #2635: a signed chart owns TWO rows -- the
    // .tgz and its .tgz.prov -- under the same name/version. Select them all:
    // the previous `LIMIT 1` had no ORDER BY, so once provenance exists it could
    // just as easily have matched the .prov and left the chart behind.
    let rows = sqlx::query(
        r#"
        SELECT id, path
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND is_deleted = false
        "#,
    )
    .bind(repo.id)
    .bind(&name)
    .bind(&version)
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    if rows.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Chart {} version {} not found", name, version),
        )
            .into_response());
    }

    let artifact_ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.get("id")).collect();
    let prov_count = rows
        .iter()
        .filter(|r| is_prov_filename(&r.get::<String, _>("path")))
        .count();

    // Soft-delete the chart together with its provenance: leaving an orphaned
    // .prov behind would let a later re-upload serve provenance for a chart it
    // does not describe.
    sqlx::query("UPDATE artifacts SET is_deleted = true, updated_at = NOW() WHERE id = ANY($1)")
        .bind(&artifact_ids)
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

    info!(
        "Helm delete: {} {} from repo {} ({} artifact(s), {} provenance)",
        name,
        version,
        repo_key,
        artifact_ids.len(),
        prov_count
    );

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
    // Provenance (#2635)
    //
    // Ground truth for these tests came from real helm 3.16.4 (arm64), not from
    // a spec: `helm pull --verify` resolves the chart URL from `index.yaml` and
    // string-appends `.prov`, requesting
    //   GET /helm/<repo>/charts/<chart>-<version>.tgz.prov
    // With that file absent it dies with
    //   Error: failed to fetch provenance ".../<chart>-<version>.tgz.prov"
    // and with it present at exactly that path (index.yaml unchanged) it prints
    // "Chart Hash Verified: sha256:...". The helm index schema has no
    // provenance field, so serving that path IS the advertised layout.
    // -----------------------------------------------------------------------

    /// A real `helm package --sign` provenance file (helm 3.16.4), truncated in
    /// the signature body. The backend never checks the signature -- that is
    /// helm's job -- but the clearsigned armor is what it gates on.
    const REAL_PROV: &[u8] = b"-----BEGIN PGP SIGNED MESSAGE-----\n\
Hash: SHA512\n\
\n\
apiVersion: v2\n\
appVersion: 1.0.0\n\
description: probe\n\
name: provchart\n\
type: application\n\
version: 0.1.0\n\
\n\
...\n\
files:\n\
  provchart-0.1.0.tgz: sha256:20a0fa5a75b0929b97fc5b23e01333d2e1683a93cdbb2441baceb586c040c50e\n\
-----BEGIN PGP SIGNATURE-----\n\
\n\
wsDcBAEBCgAQBQJqWW7VCRA8wAoTVPCkgwAAVAoMACmQbvnhlkWncOkVJXfissGD\n\
-----END PGP SIGNATURE-----\n";

    #[test]
    fn test_prov_filename_appends_to_chart_filename() {
        // helm derives the provenance URL by appending `.prov` to the chart
        // URL -- the stored filename must match byte for byte.
        assert_eq!(prov_filename("nginx-1.24.0.tgz"), "nginx-1.24.0.tgz.prov");
        assert_eq!(
            prov_filename("my-chart-2.0.0-rc.1.tgz"),
            "my-chart-2.0.0-rc.1.tgz.prov"
        );
    }

    #[test]
    fn test_is_prov_filename_discriminates_chart_from_provenance() {
        assert!(is_prov_filename("nginx-1.24.0.tgz.prov"));
        assert!(!is_prov_filename("nginx-1.24.0.tgz"));
        // A chart whose name merely contains "prov" is not provenance.
        assert!(!is_prov_filename("provchart-0.1.0.tgz"));
    }

    #[test]
    fn test_validate_prov_bytes_accepts_real_helm_provenance() {
        assert!(validate_prov_bytes(REAL_PROV).is_ok());
        // Only the head is ever read, so validation must work on a probe-sized
        // prefix too.
        assert!(validate_prov_bytes(&REAL_PROV[..PROV_HEAD_PROBE_BYTES]).is_ok());
    }

    #[test]
    fn test_validate_prov_bytes_rejects_empty_and_non_pgp() {
        assert!(validate_prov_bytes(b"").is_err());
        assert!(validate_prov_bytes(b"not a signature").is_err());
        // gzip magic: a .tgz mistakenly sent as the prov part.
        assert!(validate_prov_bytes(&[0x1f, 0x8b, 0x08, 0x00]).is_err());
    }

    #[test]
    fn test_upload_response_body_chart_only_stays_chartmuseum_compatible() {
        // No prov uploaded -> byte-identical to the historical reply.
        assert_eq!(
            upload_response_body(false),
            serde_json::json!({"saved": true})
        );
    }

    #[test]
    fn test_upload_response_body_reports_stored_provenance() {
        assert_eq!(
            upload_response_body(true),
            serde_json::json!({"saved": true, "prov": true})
        );
    }

    /// REGRESSION GUARD (#2635): the response may never advertise provenance
    /// that was not written to storage. The original bug was not the missing
    /// feature alone -- it was answering `{"saved":true}` for a `prov` part that
    /// had been dropped, which left publishers believing their charts were
    /// verifiable. `upload_response_body` takes the *storage outcome*, never the
    /// mere presence of the part, so a dropped prov cannot be reported as saved.
    #[test]
    fn test_dropped_prov_can_never_report_saved_prov() {
        let dropped = upload_response_body(false);
        assert_ne!(dropped.get("prov"), Some(&serde_json::Value::Bool(true)));
        assert!(
            dropped.get("prov").is_none(),
            "a discarded prov must not appear in the upload response at all"
        );
    }

    // -----------------------------------------------------------------------
    // Format-specific logic: filename, artifact_path, storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_helm_prov_artifact_path_and_storage_key() {
        let name = "provchart";
        let version = "0.1.0";
        let filename = format!("{}-{}.tgz", name, version);
        let prov = prov_filename(&filename);
        assert_eq!(
            format!("{}/{}/{}", name, version, prov),
            "provchart/0.1.0/provchart-0.1.0.tgz.prov"
        );
        assert_eq!(
            format!("helm/{}/{}/{}", name, version, prov),
            "helm/provchart/0.1.0/provchart-0.1.0.tgz.prov"
        );
    }

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

    // -----------------------------------------------------------------------
    // Provenance round-trip through the real router (#2635)
    // -----------------------------------------------------------------------

    /// Build a multipart body of `(field_name, filename, bytes)` parts.
    fn multipart_body(boundary: &str, parts: &[(&str, &str, &[u8])]) -> bytes::Bytes {
        let mut body: Vec<u8> = Vec::new();
        for (field, filename, content) in parts {
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                    field, filename
                )
                .as_bytes(),
            );
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
        bytes::Bytes::from(body)
    }

    fn signed_chart_tgz() -> Vec<u8> {
        build_tgz(
            "provchart/Chart.yaml",
            b"apiVersion: v2\nname: provchart\nversion: 0.1.0\n",
        )
    }

    /// POST a ChartMuseum multipart upload; returns (status, body).
    async fn upload_parts(
        f: &tdh::Fixture,
        parts: &[(&str, &str, &[u8])],
    ) -> (StatusCode, bytes::Bytes) {
        let app = f.router_with_auth(super::router());
        let req = tdh::post(
            format!("/{}/api/charts", f.repo_key),
            "multipart/form-data; boundary=BOUNDARY",
            multipart_body("BOUNDARY", parts),
        );
        tdh::send(app, req).await
    }

    /// The core of #2635: a `.prov` uploaded next to its chart must be
    /// PERSISTED and served back byte-for-byte at the URL helm derives.
    #[tokio::test]
    async fn test_helm_upload_persists_prov_and_serves_exact_bytes() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let tgz = signed_chart_tgz();

        let (status, body) = upload_parts(
            &f,
            &[
                ("chart", "provchart-0.1.0.tgz", &tgz),
                ("prov", "provchart-0.1.0.tgz.prov", REAL_PROV),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // The response reports provenance only because it was really stored.
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["saved"], serde_json::json!(true));
        assert_eq!(json["prov"], serde_json::json!(true));

        // The chart still downloads.
        let app = f.router_anon(super::router());
        let (status, got) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/provchart-0.1.0.tgz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&got[..], &tgz[..]);

        // And the provenance is served at <chart>.tgz.prov -- EXACT bytes, or
        // helm's signature check would fail on a single changed byte.
        let app = f.router_anon(super::router());
        let (status, got) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/provchart-0.1.0.tgz.prov", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the .prov must not 404 (#2635)");
        assert_eq!(&got[..], REAL_PROV);

        f.teardown().await;
    }

    /// The advertised layout must resolve: take the URL out of `index.yaml`,
    /// append `.prov` exactly as helm does, and fetch it. Also guards against
    /// the prov artifact leaking into the index as a duplicate chart entry.
    #[tokio::test]
    async fn test_helm_index_yaml_advertised_url_resolves_prov() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let tgz = signed_chart_tgz();
        let (status, _) = upload_parts(
            &f,
            &[
                ("chart", "provchart-0.1.0.tgz", &tgz),
                ("prov", "provchart-0.1.0.tgz.prov", REAL_PROV),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(app, tdh::get(format!("/{}/index.yaml", f.repo_key))).await;
        assert_eq!(status, StatusCode::OK);

        let index: HelmIndex =
            serde_yaml::from_str(std::str::from_utf8(&body).expect("utf8 index")).expect("index");
        let entries = index.entries.get("provchart").expect("chart in index");
        // The .prov shares the chart's name/version: it must NOT render its own
        // index entry.
        assert_eq!(
            entries.len(),
            1,
            "provenance must not appear as a second chart entry in index.yaml"
        );

        // This is precisely what helm does: chart URL + ".prov".
        let chart_url = entries[0].urls.first().expect("chart url");
        assert_eq!(
            chart_url,
            &format!("/helm/{}/charts/provchart-0.1.0.tgz", f.repo_key)
        );
        let prov_url = format!("{}.prov", chart_url);
        // The router under test is mounted without the `/helm` nest prefix.
        let prov_path = prov_url.strip_prefix("/helm").expect("nest prefix");

        let app = f.router_anon(super::router());
        let (status, got) = tdh::send(app, tdh::get(prov_path.to_string())).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the URL helm derives from index.yaml must serve the prov"
        );
        assert_eq!(&got[..], REAL_PROV);

        f.teardown().await;
    }

    /// REGRESSION GUARD (#2635): an upload whose provenance is not stored must
    /// not answer `{"saved":true}`. A prov the backend refuses is rejected
    /// outright rather than dropped behind a success reply.
    #[tokio::test]
    async fn test_helm_upload_rejects_invalid_prov_instead_of_dropping_it() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let tgz = signed_chart_tgz();

        let (status, body) = upload_parts(
            &f,
            &[
                ("chart", "provchart-0.1.0.tgz", &tgz),
                (
                    "prov",
                    "provchart-0.1.0.tgz.prov",
                    b"totally-not-a-signature",
                ),
            ],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unstorable prov must fail the upload, not vanish"
        );
        assert!(
            !String::from_utf8_lossy(&body).contains("\"saved\":true"),
            "a dropped prov must never be reported as saved (#2635)"
        );

        // The chart must not have been committed either -- a chart that
        // advertises provenance it cannot serve is the original bug.
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/provchart-0.1.0.tgz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        f.teardown().await;
    }

    /// ATOMICITY (#2635), storage half: a fault while storing the provenance
    /// must not leave a committed chart row behind.
    ///
    /// The chart used to be `put` **and its row committed** before the prov was
    /// stored, so a storage fault on the prov returned 5xx over a repository
    /// that now held a chart with no provenance -- and the publisher's retry hit
    /// `ensure_unique_artifact_path` and got a permanent `409 Chart already
    /// exists`. Unretryable, and the exact "signed chart that cannot be
    /// verified" state this issue exists to eliminate.
    #[tokio::test]
    async fn test_helm_prov_storage_fault_leaves_no_chart_row_blocking_reupload() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let tgz = signed_chart_tgz();
        let parts: &[(&str, &str, &[u8])] = &[
            ("chart", "provchart-0.1.0.tgz", &tgz),
            ("prov", "provchart-0.1.0.tgz.prov", REAL_PROV),
        ];

        // A real storage fault, scoped to the PROV object only: a directory
        // squatting on the prov's destination makes the filesystem backend's
        // final rename fail with EISDIR, while the chart's own put succeeds.
        // This is the residual class the armor pre-validation cannot catch --
        // the prov is perfectly well-formed, the storage write is what breaks.
        let prov_object = f
            .storage_dir
            .join("helm/provchart/0.1.0/provchart-0.1.0.tgz.prov");
        std::fs::create_dir_all(&prov_object).expect("inject prov storage fault");

        let (status, _) = upload_parts(&f, parts).await;
        assert!(
            status.is_server_error(),
            "a prov that cannot be stored must fail the upload, got {status}"
        );

        // THE POINT: nothing is committed. Not the chart, not the prov.
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(f.repo_id)
                .fetch_one(&f.pool)
                .await
                .expect("count artifacts");
        assert_eq!(
            rows, 0,
            "a failed publish must leave no artifact row -- a committed chart \
             with no prov wedges the coordinate behind an unclearable 409"
        );

        // Clear the fault and retry exactly as the publisher would.
        std::fs::remove_dir_all(&prov_object).expect("clear prov storage fault");
        let (status, body) = upload_parts(&f, parts).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "the retry after a transient storage fault must succeed, not 409"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["prov"], serde_json::json!(true));

        // And the retry really did publish a verifiable chart.
        let app = f.router_anon(super::router());
        let (status, got) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/provchart-0.1.0.tgz.prov", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&got[..], REAL_PROV);

        f.teardown().await;
    }

    /// ATOMICITY (#2635), database half: the chart row and its prov row are
    /// inserted in ONE transaction, so a fault on the prov row takes the chart
    /// row with it instead of stranding a chart nobody can re-upload.
    ///
    /// Object storage cannot join the transaction, but the rows can -- and that
    /// alone is what turns an unretryable 409 into a retryable failure. The
    /// fault injected here is a `UNIQUE(repository_id, path)` violation, the
    /// shape a publisher racing between `ensure_unique_artifact_path` and the
    /// insert produces.
    #[tokio::test]
    async fn test_helm_chart_and_prov_rows_roll_back_together() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let chart_path = "provchart/0.1.0/provchart-0.1.0.tgz";
        let prov_path = "provchart/0.1.0/provchart-0.1.0.tgz.prov";

        let checksum = "a".repeat(64);
        let new_row = |path: &'static str, content_type: &'static str| proxy_helpers::NewArtifact {
            repository_id: f.repo_id,
            path,
            name: "provchart",
            version: "0.1.0",
            size_bytes: 1,
            checksum_sha256: &checksum,
            content_type,
            storage_key: path,
            uploaded_by: f.user_id,
        };

        // Somebody already occupies the prov coordinate.
        let mut conn = f.pool.acquire().await.expect("acquire");
        proxy_helpers::insert_artifact_row(&mut conn, new_row(prov_path, PROV_CONTENT_TYPE))
            .await
            .expect("seed the conflicting prov row");
        drop(conn);

        // The publish transaction: chart row inserts, prov row collides.
        let mut tx = f.pool.begin().await.expect("begin");
        proxy_helpers::insert_artifact_row(&mut tx, new_row(chart_path, "application/gzip"))
            .await
            .expect("the chart row itself inserts fine");
        let prov_result =
            proxy_helpers::insert_artifact_row(&mut tx, new_row(prov_path, PROV_CONTENT_TYPE))
                .await;
        assert!(
            prov_result.is_err(),
            "the conflicting prov row must fail the insert"
        );
        // Exactly what the handler's `?` does: drop the transaction unfinished.
        drop(tx);

        // The chart row must have gone with it, leaving the coordinate free.
        let chart_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(f.repo_id)
        .bind(chart_path)
        .fetch_one(&f.pool)
        .await
        .expect("count chart rows");
        assert_eq!(
            chart_rows, 0,
            "a rolled-back publish must not leave the chart row committed"
        );

        f.teardown().await;
    }

    /// A chart-only upload stays exactly ChartMuseum-compatible and honestly
    /// reports no provenance.
    #[tokio::test]
    async fn test_helm_upload_without_prov_is_unchanged_and_prov_404s() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let tgz = signed_chart_tgz();
        let (status, body) = upload_parts(&f, &[("chart", "provchart-0.1.0.tgz", &tgz)]).await;
        assert_eq!(status, StatusCode::CREATED);

        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json, serde_json::json!({"saved": true}));

        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/provchart-0.1.0.tgz.prov", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        f.teardown().await;
    }

    /// Deleting a chart must take its provenance with it: an orphaned .prov
    /// would otherwise be served for a chart it no longer describes.
    #[tokio::test]
    async fn test_helm_delete_chart_also_removes_prov() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let tgz = signed_chart_tgz();
        let (status, _) = upload_parts(
            &f,
            &[
                ("chart", "provchart-0.1.0.tgz", &tgz),
                ("prov", "provchart-0.1.0.tgz.prov", REAL_PROV),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let app = f.router_with_auth(super::router());
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}/api/charts/provchart/0.1.0", f.repo_key))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::OK);

        // Both the chart AND its provenance are gone.
        for path in ["provchart-0.1.0.tgz", "provchart-0.1.0.tgz.prov"] {
            let app = f.router_anon(super::router());
            let (status, _) =
                tdh::send(app, tdh::get(format!("/{}/charts/{}", f.repo_key, path))).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{} must be deleted", path);
        }

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
