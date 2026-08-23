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

/// ChartMuseum `cm-push` compatibility router, mounted at `/api/helm` (#2941).
///
/// The `cm-push` plugin constructs its push URL as
/// `{context_path}/api/{repo_path_minus_context}/charts`
/// (<https://github.com/chartmuseum/helm-push/blob/main/pkg/chartmuseum/upload.go>).
/// With a repository URL of `https://host/helm/{repo}` and no `--context-path`
/// that resolves to `POST /api/helm/{repo}/charts` and
/// `DELETE /api/helm/{repo}/charts/{name}/{version}` — not the native
/// `/{repo}/api/charts` shape [`router`] serves. This router exposes the same
/// upload/delete handlers under the plugin's default shape so `helm cm-push`
/// works against a plain repo URL.
pub fn cm_push_router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/charts", post(upload_chart))
        .route("/:repo_key/charts/:name/:version", delete(delete_chart))
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

/// OCI manifest rows are not classic Helm chart packages and must never be
/// rendered into `index.yaml`.
///
/// The path check repairs the read side for rows already written through the
/// OCI Distribution API before repository-format validation was added (#3150).
/// The media-type check is a second guard in case an imported manifest uses a
/// non-standard path.
///
/// This filter is LOAD-BEARING, not redundant with the `/v2` write gate. That
/// gate only covers the Distribution API; `services/oci_referenced_content.rs`
/// (migration import) and `services/peer_instance_service.rs` (federation
/// replication) also write OCI manifest rows and apply NO repository-format
/// check. Removing this filter would let those two paths put manifests back
/// into a classic Helm `index.yaml`.
///
/// NOTE on the `"v2/"` literal: this is the artifact PATH prefix written by
/// `oci_v2::upsert_manifest_artifact` (`format!("v2/{image}/manifests/{ref}")`,
/// the `artifacts.path` column). Do NOT "unify" it with
/// `storage::keys::OCI_MANIFEST_STORAGE_PREFIX` (`"oci-manifests/"`) — that
/// constant is a STORAGE KEY prefix (the `artifacts.storage_key` column). The
/// two live in different namespaces and only coincidentally describe the same
/// rows; substituting one for the other silently breaks this filter.
fn is_oci_manifest_artifact(path: &str, content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();

    (path.starts_with("v2/") && path.contains("/manifests/"))
        || matches!(
            media_type,
            "application/vnd.oci.image.manifest.v1+json"
                | "application/vnd.oci.image.index.v1+json"
                | "application/vnd.docker.distribution.manifest.v2+json"
                | "application/vnd.docker.distribution.manifest.list.v2+json"
        )
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

/// Build the hosted chart download URL advertised in `index.yaml` for the
/// repo's `charts/` route.
///
/// The Helm download route (`GET /helm/{repo}/charts/{filename}`) resolves a
/// chart by the trailing filename suffix, so the advertised URL must carry the
/// artifact's **actual** stored filename. Charts published through the native
/// ChartMuseum route are stored at `{name}/{version}/{name}-{version}.tgz`,
/// whose basename already equals `{name}-{version}.tgz` — so this is
/// byte-identical to the previous reconstruction for them. But a chart pushed
/// through the generic chunked-upload flow is stored at its bare filename with
/// a generically-derived `name`/`version` (an empty version falls back to
/// `sha256-<prefix>`; see `upload.rs::completed_format_artifact_version`), so
/// reconstructing `{name}-{version}.tgz` would advertise a path the download
/// route cannot resolve. Preferring the real basename of the stored `path`
/// keeps the advertised URL coherent with the served route for both upload
/// flows — the Helm analogue of the RPM `primary.xml` `<location>` fix
/// (#2587 / #2589).
///
/// `path` is `None` only for remote upstream entries, which have no local
/// stored object; those fall back to the `{name}-{version}.tgz` convention the
/// upstream index itself uses. Third-party name/version pairs that cannot form
/// one path segment never reach here — [`merge_upstream_index_entries`] drops
/// them (see [`upstream_chart_is_advertisable`]) — so the interpolation below
/// always yields a URL under this repository's own `charts/` route that
/// resolves back to the entry it was built from.
fn chart_download_url(repo_key: &str, path: Option<&str>, name: &str, version: &str) -> String {
    let filename = path
        .and_then(|p| p.rsplit('/').next())
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}-{}.tgz", name, version));
    format!("/helm/{}/charts/{}", repo_key, filename)
}

/// Whether a third-party index entry's `name`/`version` can be advertised as a
/// `charts/{name}-{version}.tgz` URL that resolves back to that same entry
/// (#3448).
///
/// The proxied index rebuilds every URL from the upstream entry's own name and
/// version, and those are attacker-influenced strings interpolated into a path.
/// A name of `../../../../etc/passwd` or `q?x=1#frag` produces an advertised URL
/// that is still same-origin — the `/helm/{repo}/charts/` prefix is fixed, so a
/// scheme-absolute or protocol-relative name cannot smuggle a host — but is no
/// longer a URL for the chart the index just promised. Percent-encoding was the
/// obvious alternative and was rejected: an encoder aggressive enough to cover
/// `%` also rewrites `+`, which is legal semver build metadata, so every
/// legitimate `1.0.0+build.5` chart URL would have moved.
///
/// Dropping the entry instead keeps the index's guarantee absolute — everything
/// it advertises resolves — and costs nothing real, because an entry that
/// cannot be addressed could not have been downloaded through this repository
/// anyway. `%` is refused alongside the separators because the router
/// percent-decodes before matching, so `%2F` is `/` arriving one step later.
fn upstream_chart_is_advertisable(name: &str, version: &str) -> bool {
    fn segment_safe(part: &str) -> bool {
        !part.is_empty()
            && !part
                .chars()
                .any(|c| matches!(c, '/' | '\\' | '?' | '#' | '%') || c.is_control())
    }
    segment_safe(name) && segment_safe(version) && name != "." && name != ".."
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
        SELECT a.id, a.name, a.version, a.path, a.content_type, a.checksum_sha256,
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
        let path: String = row.get("path");
        let content_type: String = row.get("content_type");
        let checksum_sha256: String = row.get("checksum_sha256");
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let metadata: Option<serde_json::Value> = row.get("metadata");

        if is_oci_manifest_artifact(&path, &content_type) {
            continue;
        }

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

        let url = chart_download_url(repo_key, Some(&path), &name, &version);
        let created = created_at.to_rfc3339();
        let digest = checksum_sha256;

        out.push((chart_yaml, url, created, digest));
    }

    Ok(())
}

/// Generate index.yaml content and wrap it in a YAML response.
///
/// `budget_permit` is the buffered-metadata reservation taken by
/// [`fetch_upstream_index`], threaded all the way here on the Remote path and
/// then handed to the response body (#2665/#2684). Everything between the
/// upstream read and this point — the parsed `HelmIndex`, the chart vector
/// `generate_index_yaml` clones out of it, and the rendered document itself —
/// is derived from that buffer and is larger than it, so releasing the
/// reservation at the fetch's return would have left the biggest allocations
/// unaccounted and bounded only the individual upstream read rather than the
/// concurrent total. A Local or Virtual index has no such reservation and
/// passes `None`, which serves the body exactly as before.
#[allow(clippy::result_large_err)]
fn build_index_response(
    charts: Vec<(ChartYaml, String, String, String)>,
    budget_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<Response, Response> {
    let index_content = generate_index_yaml(charts).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to generate index.yaml: {}", e),
        )
            .into_response()
    })?;

    let body = match budget_permit {
        Some(permit) => proxy_helpers::budgeted_body(bytes::Bytes::from(index_content), permit),
        None => Body::from(index_content),
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-yaml; charset=utf-8")
        .body(body)
        .unwrap())
}

/// Fetch and parse a Remote repository's upstream `index.yaml`.
///
/// The `index.yaml` lookup stays buffered by design: helm's index is the
/// discovery document and has to be parsed in-process before anything can be
/// merged or resolved from it. It is therefore byte-capped and reserved
/// against the shared buffered-metadata budget (#2665/#2684) so neither a
/// single hostile upstream nor a concurrent fan-out can drive resident memory
/// unbounded.
///
/// The reservation is RETURNED rather than dropped here, because the buffer is
/// not the peak: the parsed tree, the chart vector cloned out of it and the
/// rendered response are all derived from it and all larger. The caller must
/// hold the permit for as long as any of that is resident — the index path
/// hands it to the response body, and the chart-download path drops it once it
/// has copied the one URL it needs out of the parsed index.
///
/// The cap is [`LARGE_METADATA_MAX_BYTES`], not the 8 MiB default: a Helm
/// index is the whole-repository listing — the direct analogue of the PyPI
/// simple-index and npm packument documents already on the larger ceiling —
/// and real upstreams exceed 8 MiB (charts.bitnami.com's `index.yaml` is
/// ~26 MiB), which the default cap would turn into a 502 for every request.
///
/// The request goes through the proxy cache, so the upstream round-trip is
/// paid once per cache TTL and is shared with the chart download path, which
/// resolves real chart URLs out of the same document.
async fn fetch_upstream_index(
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
) -> Result<(HelmIndex, tokio::sync::OwnedSemaphorePermit), Response> {
    let (index_bytes, _content_type, budget_permit) = proxy_helpers::proxy_fetch_capped_budgeted(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        "index.yaml",
        proxy_helpers::LARGE_METADATA_MAX_BYTES,
    )
    .await?;

    let yaml_str = std::str::from_utf8(&index_bytes).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Invalid UTF-8 in upstream index.yaml",
        )
            .into_response()
    })?;
    let index: HelmIndex = serde_yaml::from_str(yaml_str).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Failed to parse upstream index.yaml",
        )
            .into_response()
    })?;
    Ok((index, budget_permit))
}

/// Merge an upstream `index.yaml`'s entries into the chart list an index
/// response is being built from, rewriting every URL to this repository's own
/// `charts/` route.
///
/// Entries already present in `out` win: a locally-held chart row carries the
/// artifact's REAL stored filename in its advertised URL, which is what
/// `download_chart` resolves before it ever consults upstream, so replacing it
/// with the `{name}-{version}.tgz` convention could advertise a path the
/// download route cannot resolve. An upstream entry for a `(name, version)`
/// that is not held locally is added; a different version of the same chart is
/// a different entry and is always added.
///
/// Remote upstream entries have no local stored path, so their URL is rebuilt
/// from the chart's own name/version — the ChartMuseum convention the upstream
/// index itself uses, and the shape `download_chart` parses back into a
/// name/version before proxying.
fn merge_upstream_index_entries(
    repo_key: &str,
    index: HelmIndex,
    out: &mut Vec<(ChartYaml, String, String, String)>,
) {
    let held: std::collections::HashSet<(String, String)> = out
        .iter()
        .map(|(chart, _url, _created, _digest)| (chart.name.clone(), chart.version.clone()))
        .collect();

    for (_chart_name, entries) in index.entries {
        for entry in entries {
            if held.contains(&(entry.chart.name.clone(), entry.chart.version.clone())) {
                continue;
            }
            if !upstream_chart_is_advertisable(&entry.chart.name, &entry.chart.version) {
                tracing::warn!(
                    repository = %repo_key,
                    chart = %entry.chart.name,
                    version = %entry.chart.version,
                    "upstream index entry cannot be addressed as a single path segment; \
                     omitting it from the proxied index"
                );
                continue;
            }
            let url = chart_download_url(repo_key, None, &entry.chart.name, &entry.chart.version);
            out.push((entry.chart, url, entry.created, entry.digest));
        }
    }
}

// ---------------------------------------------------------------------------
// GET /helm/{repo_key}/index.yaml -- Helm repository index
// ---------------------------------------------------------------------------

async fn index_yaml(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Virtual repository: merge index.yaml from all member repositories
    if repo.repo_type == RepositoryType::Virtual {
        // Caller-authorized member walk (#3323): index.yaml is the discovery
        // half of the chart download — names, versions, digests and the URLs
        // the client then fetches — so a member this caller may not read
        // directly must not contribute entries to it.
        let members =
            proxy_helpers::authorized_virtual_members(&state.db, auth.as_ref(), repo.id).await?;
        let mut all_charts: Vec<(ChartYaml, String, String, String)> = Vec::new();

        // Collect index.yaml from remote members and parse chart entries
        let remote_indexes = proxy_helpers::collect_virtual_metadata(
            &state.db,
            auth.as_ref(),
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
            merge_upstream_index_entries(&repo_key, index, &mut all_charts);
        }

        // Query artifacts from local/hosted members
        for member in &members {
            if member.repo_type != RepositoryType::Remote {
                query_charts_from_repo(&state.db, member.id, &repo_key, &mut all_charts).await?;
            }
        }

        return build_index_response(all_charts, None);
    }

    let mut charts: Vec<(ChartYaml, String, String, String)> = Vec::new();
    query_charts_from_repo(&state.db, repo.id, &repo_key, &mut charts).await?;

    // Remote (proxy) repository: the index is the DISCOVERY half of a chart
    // pull — `helm pull`/`install`/`upgrade` resolve a name and version out of
    // it before requesting any tarball — so building it from locally-catalogued
    // rows alone answered `entries: {}` and made a proxy repository unusable
    // for everything except a pinned, full-path fetch (#3448). Serve what the
    // upstream advertises, merged over whatever is held locally, which is the
    // same set `download_chart` can actually serve: it resolves a local
    // artifact row first and falls through to the upstream index otherwise.
    let mut budget_permit: Option<tokio::sync::OwnedSemaphorePermit> = None;
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(proxy), Some(upstream_url)) =
            (state.proxy_service.as_deref(), repo.upstream_url.as_deref())
        {
            match fetch_upstream_index(proxy, repo.id, &repo_key, upstream_url).await {
                Ok((index, permit)) => {
                    merge_upstream_index_entries(&repo_key, index, &mut charts);
                    // Held across the merge above and handed to the response
                    // body below, so the budget stays debited for the rendered
                    // document's whole resident lifetime (#2665).
                    budget_permit = Some(permit);
                }
                // Upstream is unreachable or unparseable. With nothing held
                // locally there is no honest index to serve: an empty
                // `entries: {}` is indistinguishable from "upstream publishes
                // no charts", which is precisely the silent failure this issue
                // is about, so the upstream's own error is surfaced and
                // `helm repo update` fails loudly. With charts held locally the
                // local set is still served (the handler half of
                // stale-if-error), so an upstream outage cannot break
                // resolution of a chart this repository already has. The proxy
                // cache applies RFC 5861 stale-if-error to the `index.yaml`
                // object itself, so a warm proxy keeps serving the last good
                // upstream index before this fallback is ever reached.
                Err(err) if charts.is_empty() => return Err(err),
                Err(err) => {
                    tracing::warn!(
                        repository = %repo_key,
                        status = %err.status(),
                        "upstream helm index unavailable; serving locally-held charts only"
                    );
                }
            }
        }
    }

    build_index_response(charts, budget_permit)
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
#[allow(clippy::too_many_arguments)]
async fn fetch_chart_via_index(
    state: &SharedState,
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    name: &str,
    version: &str,
    filename: &str,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    // The reservation covers the buffered document AND the parsed tree; it is
    // dropped below, once the single URL this path needs has been copied out.
    let (index, index_budget_permit) =
        fetch_upstream_index(proxy, repo_id, repo_key, upstream_url).await?;

    let chart_url = index
        .entries
        .get(name)
        .and_then(|entries| entries.iter().find(|e| e.chart.version == version))
        .and_then(|entry| entry.urls.first())
        .cloned()
        .ok_or_else(|| {
            (StatusCode::NOT_FOUND, "Chart not found in upstream index").into_response()
        })?;
    drop(index);
    drop(index_budget_permit);

    // A `.prov` provenance file is not its own `index.yaml` entry: helm derives
    // its URL by string-appending `.prov` to the chart URL it resolved from the
    // index (see module docs). We do the same against the upstream so
    // `helm pull --verify` works through a remote/proxy repo (#2653): resolve the
    // chart URL from the index, then append `.prov` for a provenance request.
    let is_prov = is_prov_filename(filename);
    let mut fetch_url = resolve_chart_url(upstream_url, &chart_url);
    if is_prov {
        fetch_url.push_str(PROV_SUFFIX);
    }
    // Cache under the stable requested filename (`charts/{filename}`), which is
    // already the `.prov` name for a provenance request, so warm reads are served
    // from the local proxy cache on the next request.
    let cache_path = format!("charts/{}", filename);
    let content_type = if is_prov {
        PROV_CONTENT_TYPE
    } else {
        "application/gzip"
    };
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
    // #3446: count the proxied chart (or its `.prov`). `cache_path` is the
    // stable `charts/{filename}` key this fetch is teed into, so the recorded
    // (repo, path) is exactly the catalog row the artifact listing renders.
    // Recorded after the fetch resolves, so a 404/502 from upstream does not
    // count as a download.
    proxy_helpers::record_proxy_download(state, repo_id, repo_key, &cache_path, ctx).await;
    proxy_helpers::stream_fetch_result(result, content_type, Some(filename))
}

/// Attempt to download a chart from a Remote or Virtual repo by resolving the
/// real download URL from each upstream's `index.yaml`.
///
/// For Virtual repos the members are tried in priority order: hosted members
/// (local storage) are checked before remote members so that promoted/cached
/// artifacts are served without an upstream round-trip.
///
/// `auth` is the CALLER (#3324). The route middleware authorizes only the URL
/// repository — for a public Virtual parent an anonymous caller passes — so
/// the member walk must be narrowed to the members this caller may read
/// directly, the same `authorize_virtual_members` filter the OCI virtual
/// walkers and `resolve_virtual_download` apply. Without it a public virtual
/// parent laundered a PRIVATE member's chart bytes to anonymous callers.
#[allow(clippy::too_many_arguments)]
async fn download_chart_via_index(
    state: &SharedState,
    repo: &RepoInfo,
    auth: Option<&AuthExtension>,
    name: &str,
    version: &str,
    filename: &str,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Option<Response>, Response> {
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Ok(None);
    };

    // `filename` may be a chart (`<chart>-<version>.tgz`) or its provenance
    // (`<chart>-<version>.tgz.prov`). A provenance served from a local/hosted
    // member must carry the prov content type, not `application/gzip` (#2653).
    let content_type = if is_prov_filename(filename) {
        PROV_CONTENT_TYPE
    } else {
        "application/gzip"
    };

    if repo.repo_type == RepositoryType::Remote {
        let Some(upstream_url) = repo.upstream_url.as_deref() else {
            return Ok(None);
        };
        let response = fetch_chart_via_index(
            state,
            proxy,
            repo.id,
            &repo.key,
            upstream_url,
            name,
            version,
            filename,
            ctx,
        )
        .await?;
        return Ok(Some(response));
    }

    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        // Narrow to the members the CALLER may read. The fallible form is
        // used so a failed visibility query surfaces as a retryable server
        // error rather than being flattened into the empty set, which the
        // caller would answer with a definitive "Chart not found" (#3321).
        // A denied member is simply skipped, indistinguishable from a miss.
        let members =
            proxy_helpers::try_authorize_virtual_members(&state.db, auth, repo.id, members).await?;
        for member in &members {
            if member.repo_type != RepositoryType::Remote {
                // Hosted / staging member: check local storage.
                match proxy_helpers::local_fetch_by_path_suffix(
                    &state.db,
                    state,
                    member.id,
                    &member.storage_location(),
                    filename,
                )
                .await
                {
                    Ok(result) => {
                        return proxy_helpers::stream_fetch_result(
                            result,
                            content_type,
                            Some(filename),
                        )
                        .map(Some);
                    }
                    // #3220: this member HAS the chart and its download gate
                    // (quarantine hold / scan policy) refuses to serve it. Fail
                    // closed — `continue`ing would fall through to another
                    // member or upstream and serve the blocked chart with a 200,
                    // which is how the direct `/helm/<hosted>/charts/<f>` route's
                    // 403 was bypassable through any virtual listing that repo.
                    Err(resp) if proxy_helpers::is_member_policy_block_response(&resp) => {
                        return Err(resp);
                    }
                    // Ordinary miss (404) or infrastructure failure: next member.
                    Err(_) => {}
                }
                continue;
            }

            let Some(upstream_url) = member.upstream_url.as_deref() else {
                continue;
            };
            // #3446: a Remote MEMBER's serve is recorded against the member,
            // not the virtual parent — the member owns the proxy cache the
            // bytes came from and the catalog row that carries the count.
            match fetch_chart_via_index(
                state,
                proxy,
                member.id,
                &member.key,
                upstream_url,
                name,
                version,
                filename,
                ctx,
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, filename)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // `<chart>.tgz.prov` is stored as an artifact under its own filename, so the
    // same suffix lookup resolves both a chart and its provenance (#2635). Only
    // the content type and the not-found wording differ.
    let is_prov = is_prov_filename(&filename);

    // Find artifact by filename pattern; helper escapes wildcards in `filename`.
    let artifact =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, &filename).await? {
            Some(a) => a,
            None => {
                // Not in local storage. On a remote/proxy (or virtual) repo, resolve
                // the real download URL from the upstream's index.yaml instead of
                // assuming {upstream_url}/charts/{name}-{version}.tgz.
                //
                // #2653: a `.prov` request must take this path too. Its name/version
                // come from the CHART filename, so strip the `.prov` suffix before
                // parsing; `fetch_chart_via_index` then re-appends `.prov` to the
                // resolved chart URL to fetch the provenance from upstream. Previously
                // provenance was served only from local storage, so `helm pull
                // --verify` against a remote AK helm repo always 404'd.
                let chart_filename = filename.strip_suffix(PROV_SUFFIX).unwrap_or(&filename);
                let info = HelmHandler::parse_path(chart_filename).ok();
                let name_version = info
                    .as_ref()
                    .and_then(|i| i.name.as_deref().zip(i.version.as_deref()))
                    .map(|(n, v)| (n.to_string(), v.to_string()));

                if let Some((name, version)) = name_version {
                    if let Some(resp) = download_chart_via_index(
                        &state,
                        &repo,
                        auth.as_ref(),
                        &name,
                        &version,
                        &filename,
                        &ctx,
                    )
                    .await?
                    {
                        return Ok(resp);
                    }
                }

                let not_found = if is_prov {
                    "Chart provenance not found"
                } else {
                    "Chart not found"
                };
                return Err((StatusCode::NOT_FOUND, not_found).into_response());
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
    let user_id = require_auth_basic_scope(auth, "helm", "write:artifacts")?.user_id;
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
    let _user_id = require_auth_basic_scope(auth, "helm", "delete:artifacts")?.user_id;
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
    fn test_chart_download_url_native_nested_path_is_byte_identical() {
        // A natively-published chart is stored at
        // `{name}/{version}/{name}-{version}.tgz`; the advertised URL must be
        // byte-identical to the previous `{name}-{version}.tgz` reconstruction.
        assert_eq!(
            chart_download_url(
                "myrepo",
                Some("nginx/1.24.0/nginx-1.24.0.tgz"),
                "nginx",
                "1.24.0"
            ),
            "/helm/myrepo/charts/nginx-1.24.0.tgz"
        );
    }

    #[test]
    fn test_chart_download_url_bare_path_uses_actual_filename() {
        // A chart pushed via the generic chunked-upload flow is stored at its
        // bare filename with a generically-derived name and a `sha256-...`
        // fallback version. The advertised URL must use the ACTUAL stored
        // filename (which the download route resolves by suffix), NOT the
        // broken `{name}-{version}.tgz` reconstruction that would 404 (#2589).
        let url = chart_download_url(
            "myrepo",
            Some("nginx-1.24.0.tgz"),
            "nginx-1.24.0.tgz",
            "sha256-deadbeef0000",
        );
        assert_eq!(url, "/helm/myrepo/charts/nginx-1.24.0.tgz");
        // Regression guard: the old reconstruction produced an unresolvable URL.
        assert_ne!(
            url,
            "/helm/myrepo/charts/nginx-1.24.0.tgz-sha256-deadbeef0000.tgz"
        );
    }

    #[test]
    fn test_chart_download_url_no_path_falls_back_to_reconstruction() {
        // Remote upstream entries have no local path; keep the ChartMuseum
        // `{name}-{version}.tgz` convention the upstream index itself uses.
        assert_eq!(
            chart_download_url("myrepo", None, "nginx", "1.24.0"),
            "/helm/myrepo/charts/nginx-1.24.0.tgz"
        );
    }

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

    /// Pins the PATH arm on its own: an OCI-shaped `artifacts.path` with a
    /// content type that matches NO entry in the media-type list. If the
    /// `path.starts_with("v2/") && path.contains("/manifests/")` arm is
    /// deleted, this case flips to false.
    #[test]
    fn test_oci_manifest_detected_by_path_arm_alone() {
        assert!(is_oci_manifest_artifact(
            "v2/keycloak/manifests/26.7.0",
            "application/json"
        ));
        // The exact shape upsert_manifest_artifact writes, with the generic
        // content type an older row may carry.
        assert!(is_oci_manifest_artifact(
            "v2/org/keycloak/manifests/sha256:abc",
            "application/octet-stream"
        ));
    }

    /// Pins the MEDIA-TYPE arm on its own: a path that fails the `v2/` test so
    /// only the media type can match. If the media-type arm is deleted, these
    /// flip to false.
    #[test]
    fn test_oci_manifest_detected_by_media_type_arm_alone() {
        for content_type in [
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.oci.image.index.v1+json; charset=utf-8",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ] {
            assert!(
                is_oci_manifest_artifact("imported/manifest", content_type),
                "{content_type} must be recognised without an OCI-shaped path"
            );
        }
    }

    /// Pins the `&&` INSIDE the path arm. Each of these satisfies exactly one
    /// half of the path test and carries a non-OCI media type, so flipping the
    /// `&&` to `||` turns them true and fails this test.
    #[test]
    fn test_oci_manifest_path_arm_requires_both_halves() {
        // `v2/` prefix but not a manifest path (a blob).
        assert!(!is_oci_manifest_artifact(
            "v2/keycloak/blobs/sha256:abc",
            "application/octet-stream"
        ));
        // `/manifests/` present but not under the `v2/` prefix: a classic
        // chart that merely lives in a directory called `manifests`.
        assert!(!is_oci_manifest_artifact(
            "keycloak/manifests/keycloak-26.7.0.tgz",
            "application/gzip"
        ));
    }

    #[test]
    fn test_classic_helm_chart_artifacts_are_not_oci_manifests() {
        assert!(!is_oci_manifest_artifact(
            "keycloak/26.7.0/keycloak-26.7.0.tgz",
            "application/gzip"
        ));
        assert!(!is_oci_manifest_artifact(
            "keycloak-26.7.0.tgz",
            "application/octet-stream"
        ));
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
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
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
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
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

    /// REGRESSION GUARD (#2589): a chart pushed through the generic chunked
    /// upload flow is stored at its BARE filename with a generically-derived
    /// name (the whole basename) and a `sha256-<prefix>` fallback version. The
    /// URL `index.yaml` advertises must be the one the `charts/` download route
    /// actually serves. Before the fix, the index reconstructed
    /// `{name}-{version}.tgz` (e.g. `mychart-0.1.0.tgz-sha256-....tgz`), a path
    /// the suffix-resolving download route could never match -> `helm install`
    /// 404'd even though the artifact was present and directly downloadable.
    #[tokio::test]
    async fn test_helm_index_url_resolves_for_bare_path_generic_upload() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        // Simulate the generic chunked-upload flow's stored coordinates for a
        // bare-path push of `mychart-0.1.0.tgz`: bare path, name = basename,
        // version = the deterministic `sha256-<prefix>` fallback.
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "abcd/ef/abcdef0123456789", // content-addressable storage key
            "mychart-0.1.0.tgz",        // bare artifact path (no directory)
            "mychart-0.1.0.tgz",        // generically-derived name
            "sha256-abcdef012345",      // fallback version
            "application/gzip",
            bytes::Bytes::from_static(b"helm-chart-bytes"),
            f.user_id,
        )
        .await;

        // Read the advertised URL out of index.yaml.
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(app, tdh::get(format!("/{}/index.yaml", f.repo_key))).await;
        assert_eq!(status, StatusCode::OK);
        let index: HelmIndex =
            serde_yaml::from_str(std::str::from_utf8(&body).expect("utf8 index")).expect("index");
        let entry = index
            .entries
            .values()
            .flatten()
            .next()
            .expect("chart entry in index");
        let chart_url = entry.urls.first().expect("chart url");
        assert_eq!(
            chart_url,
            &format!("/helm/{}/charts/mychart-0.1.0.tgz", f.repo_key),
            "index.yaml must advertise the actual stored filename, not the \
             broken name/version reconstruction"
        );

        // THE POINT: the advertised URL must actually serve the chart. The
        // router under test is mounted without the `/helm` nest prefix.
        let download_path = chart_url.strip_prefix("/helm").expect("nest prefix");
        let app = f.router_anon(super::router());
        let (status, got) = tdh::send(app, tdh::get(download_path.to_string())).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the URL helm derives from index.yaml must serve the chart"
        );
        assert_eq!(&got[..], b"helm-chart-bytes");

        f.teardown().await;
    }

    /// #3143 scope correction + regression guard: the Helm chart download
    /// route ALREADY enforces the scan policy, and must keep doing so.
    ///
    /// #3143 reported that "`helm.rs` and `terraform.rs` call neither gate on
    /// their download paths". That is accurate for terraform, but not for the
    /// Helm hosted download: `download_chart` serves through
    /// `proxy_helpers::serve_local_artifact`, which calls
    /// `check_artifact_download` -> `enforce_download_gate`. Grepping `helm.rs`
    /// for the gate finds nothing because the call is one level down. This test
    /// pins that indirect coverage so a future refactor away from
    /// `serve_local_artifact` cannot silently drop it.
    ///
    /// (The genuinely ungated Helm path is the VIRTUAL-member arm in
    /// `download_chart_via_index`, which resolves via `local_fetch_by_path_suffix`.
    /// That belongs to the cross-format virtual-member class tracked separately.)
    #[tokio::test]
    async fn test_hosted_chart_download_already_applies_scan_policy_3143() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let blob = bytes::Bytes::from_static(b"helm-gate-chart-bytes");
        let filename = "gatechart-0.1.0.tgz";
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &f.repo_info("local", None),
            filename,
            filename,
            "gatechart",
            "0.1.0",
            "application/gzip",
            blob.clone(),
            f.user_id,
        )
        .await;

        let uri = format!("/{}/charts/{}", f.repo_key, filename);

        // POSITIVE CONTROL: no policy -> serves.
        let (before_status, before_body) =
            tdh::send(f.router_anon(super::router()), tdh::get(uri.clone())).await;

        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'critical', true, false, true)",
        )
        .bind(format!("gate-3143-helm-{}", f.repo_id))
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .expect("insert block_unscanned policy");

        let (blocked_status, _) =
            tdh::send(f.router_anon(super::router()), tdh::get(uri.clone())).await;

        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(f.repo_id)
            .execute(&f.pool)
            .await;

        // NEGATIVE CONTROL: policy removed -> serves again.
        let (after_status, _) =
            tdh::send(f.router_anon(super::router()), tdh::get(uri.clone())).await;

        f.teardown().await;

        assert_eq!(
            before_status,
            StatusCode::OK,
            "positive control: with no scan policy the chart must download"
        );
        assert_eq!(&before_body[..], &blob[..], "positive control: chart bytes");
        assert_eq!(
            blocked_status,
            StatusCode::FORBIDDEN,
            "the Helm hosted download must enforce the scan policy (via \
             serve_local_artifact -> enforce_download_gate), got {blocked_status}"
        );
        assert_eq!(
            after_status,
            StatusCode::OK,
            "negative control: removing the policy must restore the download"
        );
    }

    /// #3220: the VIRTUAL-member arm of the Helm download must apply the
    /// resolving member's scan policy, exactly as the direct hosted route does
    /// (pinned by `test_hosted_chart_download_already_applies_scan_policy_3143`
    /// immediately above).
    ///
    /// `download_chart_via_index` walks members by hand and resolved hosted
    /// ones through `local_fetch_by_path_suffix` under `if let Ok(..)`, so both
    /// halves of the bug are exercised here: the helper applied no scan policy,
    /// and the loop's `continue` would have swallowed the rejection as "this
    /// member does not have the chart".
    ///
    /// The same request against the same member repository is a 403 on
    /// `/helm/<member>/charts/<f>` — so this test is the bypass in one file:
    /// direct route refuses, virtual route serves.
    ///
    /// POSITIVE CONTROLS in this fixture: the virtual route serves 200 with the
    /// real chart bytes before the policy exists and again after it is removed.
    #[tokio::test]
    async fn test_virtual_member_chart_download_applies_scan_policy_3220() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let blob = bytes::Bytes::from_static(b"helm-virtual-gate-chart-bytes");
        let filename = "vgatechart-0.2.0.tgz";
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &f.repo_info("local", None),
            filename,
            filename,
            "vgatechart",
            "0.2.0",
            "application/gzip",
            blob.clone(),
            f.user_id,
        )
        .await;

        // The member walk is caller-authorized since #3324 and this fixture
        // probes anonymously, so publish the member: the subject here is the
        // scan policy, which must hold for exactly the members a caller may
        // read (the anonymous-vs-private direction is pinned by
        // `virtual_member_authz_tests`).
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(f.repo_id)
            .execute(&f.pool)
            .await
            .expect("publish fixture member");

        // A virtual Helm repo whose only member is the fixture's hosted repo.
        let (virtual_id, virtual_key, _vdir) = tdh::create_repo(&f.pool, "virtual", "helm").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(virtual_id)
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .expect("link virtual member");

        // `download_chart_via_index` early-returns when no proxy service is
        // wired, so the member loop would never run on the bare fixture state.
        let storage_path = f.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(f.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(f.pool.clone(), &storage_path, proxy);
        let app = || tdh::router_anon(super::router(), state.clone());

        let virtual_uri = format!("/{}/charts/{}", virtual_key, filename);
        let direct_uri = format!("/{}/charts/{}", f.repo_key, filename);

        // POSITIVE CONTROL: no policy -> the virtual route serves the chart.
        let (before_status, before_body) = tdh::send(app(), tdh::get(virtual_uri.clone())).await;

        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'critical', true, false, true)",
        )
        .bind(format!("gate-3220-helm-{}", f.repo_id))
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .expect("insert block_unscanned policy");

        let (virtual_blocked, virtual_blocked_body) =
            tdh::send(app(), tdh::get(virtual_uri.clone())).await;
        // The direct route on the SAME repository, under the SAME policy: this
        // is the comparison the bug is defined by.
        let (direct_blocked, _) = tdh::send(app(), tdh::get(direct_uri)).await;

        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(f.repo_id)
            .execute(&f.pool)
            .await;

        // NEGATIVE CONTROL: policy removed -> the virtual route serves again.
        let (after_status, after_body) = tdh::send(app(), tdh::get(virtual_uri)).await;

        tdh::cleanup(&f.pool, virtual_id, f.user_id).await;
        f.teardown().await;

        assert_eq!(
            before_status,
            StatusCode::OK,
            "positive control: with no scan policy the virtual route must serve the chart"
        );
        assert_eq!(
            &before_body[..],
            &blob[..],
            "positive control: the virtual route must serve the seeded chart bytes"
        );
        assert_eq!(
            direct_blocked,
            StatusCode::FORBIDDEN,
            "control: the direct hosted route must refuse under this policy"
        );
        assert_eq!(
            virtual_blocked,
            StatusCode::FORBIDDEN,
            "#3220: the virtual-member route must refuse the same chart under the same \
             policy, got {virtual_blocked} body={:?}",
            String::from_utf8_lossy(&virtual_blocked_body)
        );
        assert_ne!(
            &virtual_blocked_body[..],
            &blob[..],
            "#3220: the blocked chart's bytes must not be served through the virtual repo"
        );
        assert_eq!(
            after_status,
            StatusCode::OK,
            "negative control: removing the policy must restore the virtual download"
        );
        assert_eq!(&after_body[..], &blob[..]);
    }

    /// Regression guard for #3150: OCI manifest rows written into a classic
    /// Helm repository by older versions must not leak into `index.yaml`.
    #[tokio::test]
    async fn test_helm_index_excludes_existing_oci_manifest_rows() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let repo = f.repo_info("local", None);

        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "helm/keycloak/26.7.0/keycloak-26.7.0.tgz",
            "keycloak/26.7.0/keycloak-26.7.0.tgz",
            "keycloak",
            "26.7.0",
            "application/gzip",
            bytes::Bytes::from_static(b"classic-chart"),
            f.user_id,
        )
        .await;
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "oci/manifests/abcdef",
            "v2/keycloak/manifests/26.7.0",
            "keycloak:26.7.0",
            "26.7.0",
            "application/vnd.oci.image.manifest.v1+json",
            bytes::Bytes::from_static(br#"{"schemaVersion":2}"#),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(app, tdh::get(format!("/{}/index.yaml", f.repo_key))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "index generation failed: {}",
            String::from_utf8_lossy(&body)
        );
        let index: HelmIndex = serde_yaml::from_slice(&body).expect("valid Helm index");
        assert_eq!(index.entries.len(), 1);
        assert!(index.entries.contains_key("keycloak"));
        assert!(!index.entries.contains_key("keycloak:26.7.0"));

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

    // -----------------------------------------------------------------------
    // cm-push default URL shape (#2941)
    // -----------------------------------------------------------------------

    /// `helm cm-push` POSTs to `{host}/api/helm/{repo}/charts` (the
    /// ChartMuseum context-path shape), not this registry's native
    /// `/{repo}/api/charts`. The `/api/helm` alias router must accept the
    /// plugin's default upload and delete URLs.
    #[tokio::test]
    async fn test_cm_push_default_url_shape_uploads_and_deletes() {
        let Some(f) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let tgz = build_tgz(
            "cmpushchart/Chart.yaml",
            b"apiVersion: v2\nname: cmpushchart\nversion: 0.1.0\n",
        );

        // POST the exact URL cm-push constructs for repo URL {host}/helm/{repo}.
        let app = f.router_with_auth(Router::new().nest("/api/helm", super::cm_push_router()));
        let req = tdh::post(
            format!("/api/helm/{}/charts", f.repo_key),
            "multipart/form-data; boundary=BOUNDARY",
            multipart_body("BOUNDARY", &[("chart", "cmpushchart-0.1.0.tgz", &tgz)]),
        );
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "cm-push's default push URL must be accepted; got body {:?}",
            String::from_utf8_lossy(&body)
        );

        // The chart is downloadable at the native path.
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/cmpushchart-0.1.0.tgz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // DELETE via the same ChartMuseum shape.
        let app = f.router_with_auth(Router::new().nest("/api/helm", super::cm_push_router()));
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/api/helm/{}/charts/cmpushchart/0.1.0", f.repo_key))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::OK);
        f.teardown().await;
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
    // #3448: a Remote repository's index.yaml must reflect the upstream
    // -----------------------------------------------------------------------

    /// Build a two-chart upstream index whose URLs are upstream-absolute, so a
    /// test can tell a merged entry (rewritten to this repo's `charts/` route)
    /// from a verbatim copy of the upstream document.
    fn upstream_two_chart_index() -> String {
        r#"apiVersion: v1
generated: "2024-01-01T00:00:00Z"
entries:
  cert-manager:
    - apiVersion: v2
      name: cert-manager
      version: v1.16.2
      appVersion: v1.16.2
      urls:
        - https://upstream.invalid/charts/cert-manager-v1.16.2.tgz
      created: "2024-01-01T00:00:00Z"
      digest: aaaa1111
    - apiVersion: v2
      name: cert-manager
      version: v1.16.1
      urls:
        - https://upstream.invalid/charts/cert-manager-v1.16.1.tgz
      created: "2023-12-01T00:00:00Z"
      digest: bbbb2222
  trust-manager:
    - apiVersion: v2
      name: trust-manager
      version: v0.12.0
      urls:
        - https://upstream.invalid/charts/trust-manager-v0.12.0.tgz
      created: "2024-02-01T00:00:00Z"
      digest: cccc3333
"#
        .to_string()
    }

    fn parse_index(body: &[u8]) -> HelmIndex {
        serde_yaml::from_slice(body).expect("response body must be a parseable index.yaml")
    }

    #[test]
    fn test_merge_upstream_index_entries_rewrites_urls_to_this_repo() {
        let index: HelmIndex = serde_yaml::from_str(&upstream_two_chart_index()).unwrap();
        let mut out: Vec<(ChartYaml, String, String, String)> = Vec::new();

        merge_upstream_index_entries("helm-remote", index, &mut out);

        assert_eq!(out.len(), 3, "every upstream entry must be merged: {out:?}");
        for (chart, url, _created, _digest) in &out {
            assert_eq!(
                url,
                &format!(
                    "/helm/helm-remote/charts/{}-{}.tgz",
                    chart.name, chart.version
                ),
                "an upstream URL must be rewritten to this repository's own charts/ \
                 route, or the client would be sent straight to the upstream and the \
                 proxy would serve nothing"
            );
        }
    }

    #[test]
    fn test_merge_upstream_index_entries_keeps_the_locally_held_entry() {
        let index: HelmIndex = serde_yaml::from_str(&upstream_two_chart_index()).unwrap();
        let local_chart = ChartYaml {
            api_version: "v2".to_string(),
            name: "cert-manager".to_string(),
            version: "v1.16.2".to_string(),
            kube_version: None,
            description: None,
            chart_type: None,
            keywords: None,
            home: None,
            sources: None,
            dependencies: None,
            maintainers: None,
            icon: None,
            app_version: None,
            deprecated: None,
            annotations: None,
        };
        // A stored chart whose real filename is NOT the {name}-{version}.tgz
        // convention, so a merge that overwrote it would be visible.
        let local_url = "/helm/helm-remote/charts/cert-manager-promoted.tgz".to_string();
        let mut out = vec![(
            local_chart,
            local_url.clone(),
            "2024-06-01T00:00:00Z".to_string(),
            "local-digest".to_string(),
        )];

        merge_upstream_index_entries("helm-remote", index, &mut out);

        let same_nv: Vec<_> = out
            .iter()
            .filter(|(c, ..)| c.name == "cert-manager" && c.version == "v1.16.2")
            .collect();
        assert_eq!(
            same_nv.len(),
            1,
            "a (name, version) held locally must not gain a duplicate upstream entry"
        );
        assert_eq!(
            same_nv[0].1, local_url,
            "the locally-held entry keeps its real stored filename, which is what the \
             download route resolves"
        );
        assert_eq!(
            out.len(),
            3,
            "the other upstream versions are still merged: {out:?}"
        );
    }

    #[tokio::test]
    async fn test_remote_index_yaml_serves_upstream_entries_3448() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "helm").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(upstream_two_chart_index().as_bytes()),
            )
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(app, tdh::get(format!("/{}/index.yaml", f.repo_key))).await;

        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let index = parse_index(&body);
        assert!(
            !index.entries.is_empty(),
            "a Remote repository's index must carry the upstream's charts; an empty \
             `entries` is what makes `helm pull` unable to resolve anything (#3448)"
        );
        let cert_manager = index
            .entries
            .get("cert-manager")
            .expect("upstream chart must be advertised by name");
        assert_eq!(cert_manager.len(), 2, "both upstream versions must appear");
        let latest = cert_manager
            .iter()
            .find(|e| e.chart.version == "v1.16.2")
            .expect("upstream version must appear");
        assert_eq!(
            latest.urls,
            vec![format!(
                "/helm/{}/charts/cert-manager-v1.16.2.tgz",
                f.repo_key
            )],
            "the advertised URL must point at this repository's charts/ route, which \
             is the route that proxies the tarball"
        );
        assert_eq!(latest.digest, "aaaa1111", "upstream digest is preserved");
        assert!(index.entries.contains_key("trust-manager"));
    }

    /// The two upstream failures an operator actually hits: the upstream is
    /// down (5xx), and the upstream URL is wrong so `index.yaml` 404s — the
    /// more common misconfiguration of the two. Neither may answer 200 with an
    /// empty index, which is indistinguishable from "this upstream publishes no
    /// charts" and leaves `helm repo update` reporting success (#3448).
    ///
    /// The exact status differs by cause and that is deliberate: `map_proxy_error`
    /// classifies an upstream 5xx as 503 and a definitive upstream 404 as 404,
    /// so the client is told which of the two it is rather than being given a
    /// uniform 502.
    #[tokio::test]
    async fn test_remote_index_yaml_surfaces_an_upstream_failure_when_nothing_is_held_3448() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        for (upstream_status, expected) in [
            (503u16, StatusCode::SERVICE_UNAVAILABLE),
            (404, StatusCode::NOT_FOUND),
        ] {
            let Some(f) = tdh::Fixture::setup("remote", "helm").await else {
                return;
            };
            let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
            Mock::given(method("GET"))
                .and(path("/index.yaml"))
                .respond_with(ResponseTemplate::new(upstream_status))
                .mount(&server)
                .await;
            let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

            let app = tdh::router_anon(super::router(), state);
            let (status, body) =
                tdh::send(app, tdh::get(format!("/{}/index.yaml", f.repo_key))).await;

            f.teardown().await;

            assert_ne!(
                status,
                StatusCode::OK,
                "upstream {upstream_status} with nothing held locally must not answer 200: \
                 an empty `entries` reads as 'upstream publishes no charts' and \
                 `helm repo update` reports success, which is the silent failure in #3448"
            );
            assert_eq!(
                status,
                expected,
                "upstream {upstream_status} must be reported as {expected}, so the operator \
                 can tell an outage from a wrong upstream URL; body: {}",
                String::from_utf8_lossy(&body)
            );
        }
    }

    #[tokio::test]
    async fn test_remote_index_yaml_still_serves_locally_held_charts_when_upstream_is_down_3448() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "helm").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let repo = f.repo_info("remote", Some(&server.uri()));
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "held-chart-storage-key",
            "heldchart-2.0.0.tgz",
            "heldchart",
            "2.0.0",
            "application/gzip",
            bytes::Bytes::from_static(b"helm-chart-bytes"),
            f.user_id,
        )
        .await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(app, tdh::get(format!("/{}/index.yaml", f.repo_key))).await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "an upstream outage must not stop a chart this repository already holds \
             from resolving (#3448)"
        );
        let index = parse_index(&body);
        assert!(
            index.entries.contains_key("heldchart"),
            "the locally-held chart must still be advertised: {:?}",
            index.entries.keys().collect::<Vec<_>>()
        );
    }

    /// #2665/#2684 via #3448: the buffered-metadata reservation must stay
    /// debited for the RENDERED response body's lifetime, not just the upstream
    /// read's. Everything between the two — the parsed index, the chart vector
    /// cloned out of it, and the rendered document — is derived from that buffer
    /// and larger than it, so a permit released at the fetch's return bounds
    /// each individual upstream read while leaving the concurrent total
    /// unbounded: the next request piles its buffer on top of a body still
    /// queued for the socket.
    #[tokio::test]
    async fn test_index_response_holds_the_budget_until_the_body_is_dropped_3448() {
        let budget = proxy_helpers::ProxyMetadataBudget::new(4096);
        let permit = budget.reserve(1000).await;
        assert_eq!(budget.available_bytes(), 3096, "reservation debited");

        let index: HelmIndex = serde_yaml::from_str(&upstream_two_chart_index()).unwrap();
        let mut charts: Vec<(ChartYaml, String, String, String)> = Vec::new();
        merge_upstream_index_entries("helm-remote", index, &mut charts);

        // The merge and the render both happen while the permit is held.
        assert_eq!(
            budget.available_bytes(),
            3096,
            "budget must stay debited across the merge"
        );
        let resp = build_index_response(charts, Some(permit)).expect("index response");
        assert_eq!(
            budget.available_bytes(),
            3096,
            "budget must stay debited while the rendered response body is alive"
        );

        drop(resp);
        assert_eq!(
            budget.available_bytes(),
            4096,
            "budget is released once the response body is dropped"
        );
    }

    /// A Local or Virtual index takes no reservation, so it must still render.
    #[test]
    fn test_index_response_without_a_reservation_still_renders() {
        let index: HelmIndex = serde_yaml::from_str(&upstream_two_chart_index()).unwrap();
        let mut charts: Vec<(ChartYaml, String, String, String)> = Vec::new();
        merge_upstream_index_entries("helm-local", index, &mut charts);
        let resp = build_index_response(charts, None).expect("index response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// #3448: an upstream index is parsed as ONE document, so a single
    /// non-conforming entry must not take the whole repository's discovery with
    /// it. `urls`, `created`, `digest` and `generated` default; `name` and
    /// `version` remain required because there is nothing to advertise without
    /// them.
    #[test]
    fn test_upstream_index_entry_missing_optional_fields_still_parses() {
        let yaml = r#"apiVersion: v1
entries:
  sparse:
    - apiVersion: v2
      name: sparse
      version: 1.0.0
"#;
        let index: HelmIndex = serde_yaml::from_str(yaml).expect(
            "an upstream entry with no urls/created/digest, in an index with no \
             `generated`, must still parse -- otherwise one malformed entry 502s the \
             entire Remote index (#3448)",
        );
        let mut out: Vec<(ChartYaml, String, String, String)> = Vec::new();
        merge_upstream_index_entries("helm-remote", index, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1, "/helm/helm-remote/charts/sparse-1.0.0.tgz");
        assert_eq!(
            out[0].3, "",
            "a missing digest defaults to empty, not invented"
        );
    }

    #[test]
    fn test_upstream_index_entry_without_a_name_is_still_rejected() {
        let yaml = r#"apiVersion: v1
entries:
  nameless:
    - apiVersion: v2
      version: 1.0.0
"#;
        assert!(
            serde_yaml::from_str::<HelmIndex>(yaml).is_err(),
            "an entry with no chart name cannot be advertised and must stay a parse error"
        );
    }

    /// #3448: the proxied index rebuilds every URL from a third party's
    /// `name`/`version`. An entry that cannot be addressed as one path segment
    /// is dropped rather than advertised, so the index keeps its guarantee that
    /// everything it lists resolves back to the entry it came from.
    #[test]
    fn test_merge_drops_upstream_entries_that_cannot_be_addressed() {
        for (name, version) in [
            ("../../../../etc/passwd", "1.0.0"),
            ("q?x=1#frag", "4.0"),
            ("a/b", "1.0.0"),
            ("https://evil.example/pwn", "1.0.0"),
            ("//evil.example/pwn", "1.0.0"),
            ("pct%2Fescape", "1.0.0"),
            ("ok", "1.0.0/../../etc"),
        ] {
            assert!(
                !upstream_chart_is_advertisable(name, version),
                "{name:?}/{version:?} cannot form one path segment and must not be advertised"
            );
            let yaml = format!(
                "apiVersion: v1\nentries:\n  k:\n    - apiVersion: v2\n      name: {name:?}\n      version: {version:?}\n"
            );
            let index: HelmIndex = serde_yaml::from_str(&yaml).expect("index parses");
            let mut out: Vec<(ChartYaml, String, String, String)> = Vec::new();
            merge_upstream_index_entries("helm-remote", index, &mut out);
            assert!(
                out.is_empty(),
                "the unaddressable entry must be omitted, got {out:?}"
            );
        }
    }

    /// The filter must not touch the names and versions real charts use,
    /// including semver build metadata — the reason an encoder was rejected.
    #[test]
    fn test_ordinary_chart_names_and_versions_stay_advertisable() {
        for (name, version) in [
            ("cert-manager", "v1.16.2"),
            ("my.chart_name", "1.0.0-rc.1+build.5"),
            ("trust-manager", "v0.12.0"),
        ] {
            assert!(
                upstream_chart_is_advertisable(name, version),
                "{name}/{version} is an ordinary chart and must be advertised"
            );
        }
    }

    /// Advertised URLs for ordinary charts are byte-identical to what this
    /// route served before, semver build metadata included.
    #[test]
    fn test_remote_chart_url_is_unchanged_for_ordinary_names() {
        assert_eq!(
            chart_download_url("helm-remote", None, "cert-manager", "v1.16.2"),
            "/helm/helm-remote/charts/cert-manager-v1.16.2.tgz"
        );
        assert_eq!(
            chart_download_url("helm-remote", None, "my.chart_name", "1.0.0-rc.1+build.5"),
            "/helm/helm-remote/charts/my.chart_name-1.0.0-rc.1+build.5.tgz"
        );
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
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        // #3446: `fetch_chart_via_index` now records the proxied chart, so it
        // needs the state (for the pool the recorder writes through) and a
        // download context. A default context is an anonymous, non-HEAD GET.
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);
        let proxy = state.proxy_service.as_deref().expect("proxy service");
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &state,
            proxy,
            repo_id,
            "helm-proxy",
            &upstream_url,
            "mychart",
            "1.0.0",
            "mychart-1.0.0.tgz",
            &ctx,
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
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        // #3446: `fetch_chart_via_index` now records the proxied chart, so it
        // needs the state (for the pool the recorder writes through) and a
        // download context. A default context is an anonymous, non-HEAD GET.
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);
        let proxy = state.proxy_service.as_deref().expect("proxy service");
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &state,
            proxy,
            repo_id,
            "helm-proxy-abs",
            &upstream_url,
            "abs-chart",
            "1.0.0",
            "abs-chart-1.0.0.tgz",
            &ctx,
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
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        // #3446: `fetch_chart_via_index` now records the proxied chart, so it
        // needs the state (for the pool the recorder writes through) and a
        // download context. A default context is an anonymous, non-HEAD GET.
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);
        let proxy = state.proxy_service.as_deref().expect("proxy service");
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();
        let repo_id = uuid::Uuid::new_v4();

        for i in 0..2 {
            // Before the second request, wait for the streaming write-back to
            // commit so the cache is deterministically WARM.
            if i == 1 {
                tdh::wait_for_cache_commit(&tmp, chart_bytes.len() as u64).await;
            }
            let result = fetch_chart_via_index(
                &state,
                proxy,
                repo_id,
                "helm-proxy-big",
                &upstream_url,
                "big",
                "3.0.0",
                "big-3.0.0.tgz",
                &ctx,
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

    // -----------------------------------------------------------------------
    // Remote/proxy provenance (#2653)
    //
    // `helm pull --verify` against a REMOTE/PROXY repo resolves the chart URL
    // from the upstream `index.yaml` and string-appends `.prov`. Before #2653
    // that request could only ever be served from LOCAL storage, so a remote
    // AK helm repo 404'd every `.prov` and `--verify` failed. The remote path
    // must now derive the upstream `.prov` URL (chart URL + `.prov`), fetch it
    // through the streaming proxy, and serve it with the provenance content
    // type.
    // -----------------------------------------------------------------------

    /// Unit: `fetch_chart_via_index` for a `.prov` request must fetch the
    /// upstream `<chart>.tgz.prov` (not the `.tgz`) and serve the provenance
    /// bytes with the prov content type.
    ///
    /// FAILS before #2653: the pre-fix code ignored the `.prov` suffix, fetched
    /// the chart `.tgz`, and returned chart bytes as `application/gzip`.
    #[tokio::test]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    #[allow(clippy::disallowed_methods)]
    async fn test_fetch_chart_via_index_serves_upstream_prov_2653() {
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
        // The chart itself: present, but must NOT be what a `.prov` request gets.
        Mock::given(method("GET"))
            .and(path("/charts/mychart-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(chart_bytes))
            .mount(&server)
            .await;
        // The provenance sibling helm derives by appending `.prov`.
        Mock::given(method("GET"))
            .and(path("/charts/mychart-1.0.0.tgz.prov"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(REAL_PROV))
            .mount(&server)
            .await;

        let tmp = proxy_tmp_dir();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        // #3446: `fetch_chart_via_index` now records the proxied chart, so it
        // needs the state (for the pool the recorder writes through) and a
        // download context. A default context is an anonymous, non-HEAD GET.
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);
        let proxy = state.proxy_service.as_deref().expect("proxy service");
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &state,
            proxy,
            repo_id,
            "helm-proxy-prov",
            &upstream_url,
            "mychart",
            "1.0.0",
            "mychart-1.0.0.tgz.prov",
            &ctx,
        )
        .await;

        let _ = std::fs::remove_dir_all(&tmp);

        match result {
            Ok(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(
                    resp.headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok()),
                    Some(PROV_CONTENT_TYPE),
                    "a .prov must be served with the provenance content type, not application/gzip"
                );
                assert_eq!(
                    resp.headers()
                        .get("content-disposition")
                        .and_then(|v| v.to_str().ok()),
                    Some("attachment; filename=\"mychart-1.0.0.tgz.prov\"")
                );
                let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .expect("collect streamed prov body");
                assert_eq!(
                    &body[..],
                    REAL_PROV,
                    "the .prov request must return the upstream provenance, not the chart .tgz"
                );
            }
            Err(resp) => panic!(
                "fetch_chart_via_index must fetch the upstream .prov, got {}",
                resp.status()
            ),
        }
    }

    /// End-to-end: a `GET .../charts/<chart>.tgz.prov` against a REMOTE helm
    /// repo must be routed through the proxy fetch (not short-circuited by the
    /// hosted-only 404) and serve the upstream provenance byte-for-byte.
    ///
    /// FAILS before #2653: `download_chart` returned 404 "Chart provenance not
    /// found" for any `.prov` that was not already in local storage, so a
    /// remote repo could never serve it.
    #[tokio::test]
    async fn test_remote_helm_prov_download_via_index_2653() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "helm").await else {
            return;
        };
        let server = MockServer::start().await;
        let index_yaml = make_index_yaml("mychart", "1.0.0", "charts/mychart-1.0.0.tgz");

        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(index_yaml.as_bytes()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/charts/mychart-1.0.0.tgz.prov"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(REAL_PROV))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/charts/mychart-1.0.0.tgz.prov", fx.repo_key)),
        )
        .await;

        let teardown = || async { fx.teardown().await };
        if status != StatusCode::OK {
            teardown().await;
            panic!("a .prov against a remote helm repo must be proxied, not 404'd; got {status}");
        }
        assert_eq!(
            &body[..],
            REAL_PROV,
            "remote .prov must be the upstream provenance, byte-for-byte"
        );
        teardown().await;
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
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        // #3446: `fetch_chart_via_index` now records the proxied chart, so it
        // needs the state (for the pool the recorder writes through) and a
        // download context. A default context is an anonymous, non-HEAD GET.
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);
        let proxy = state.proxy_service.as_deref().expect("proxy service");
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &state,
            proxy,
            repo_id,
            "helm-proxy",
            &upstream_url,
            "nonexistent",
            "9.9.9",
            "nonexistent-9.9.9.tgz",
            &ctx,
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
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), tmp.to_str().unwrap());
        // #3446: `fetch_chart_via_index` now records the proxied chart, so it
        // needs the state (for the pool the recorder writes through) and a
        // download context. A default context is an anonymous, non-HEAD GET.
        let state = tdh::build_state_with_proxy(pool, tmp.to_str().unwrap(), proxy);
        let proxy = state.proxy_service.as_deref().expect("proxy service");
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_chart_via_index(
            &state,
            proxy,
            repo_id,
            "helm-proxy",
            &upstream_url,
            "mychart",
            "1.0.0",
            "mychart-1.0.0.tgz",
            &ctx,
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
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();

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
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };

        let result =
            download_chart_via_index(&state, &repo, None, "tc", "2.0.0", "tc-2.0.0.tgz", &ctx)
                .await;

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
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();

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
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };

        let result =
            download_chart_via_index(&state, &repo, None, "ch", "1.0.0", "ch-1.0.0.tgz", &ctx)
                .await;
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
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();

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
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };

        let result =
            download_chart_via_index(&state, &repo, None, "ch", "1.0.0", "ch-1.0.0.tgz", &ctx)
                .await;
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

/// #3324 regression: a public Virtual helm repository must not launder a
/// PRIVATE member's chart bytes to an anonymous caller.
///
/// `GET /helm/{virtual}/charts/{filename}` reaches `download_chart_via_index`,
/// which walked `fetch_virtual_members` unfiltered and resolved hosted members
/// through `local_fetch_by_path_suffix(member.id)` — and `download_chart` binds
/// no auth extractor at all, so the walk structurally could not filter. The
/// member set is now narrowed through
/// `proxy_helpers::try_authorize_virtual_members` (the same filter the OCI
/// virtual walkers use), keyed on the CALLER.
#[cfg(test)]
mod virtual_member_authz_tests {
    use axum::http::StatusCode;
    use bytes::Bytes;

    use crate::api::handlers::test_db_helpers as tdh;

    /// Seed a hosted member's chart: an `artifacts` row plus the `.tgz` bytes
    /// in the member's own storage root, where
    /// `local_fetch_by_path_suffix(member.id, member.storage_location())`
    /// resolves them.
    async fn seed_member_chart(
        pool: &sqlx::PgPool,
        member_id: uuid::Uuid,
        member_dir: &std::path::Path,
        name: &str,
        version: &str,
        content: &[u8],
        uploaded_by: uuid::Uuid,
    ) -> String {
        let filename = format!("{name}-{version}.tgz");
        let storage_key = format!("charts/{filename}");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, $5, $6, 'application/gzip', $2, $7)",
        )
        .bind(member_id)
        .bind(&storage_key)
        .bind(name)
        .bind(version)
        .bind(content.len() as i64)
        .bind(format!("seed-{name}"))
        .bind(uploaded_by)
        .execute(pool)
        .await
        .expect("seed member chart artifact row");
        let dir = member_dir.join("charts");
        std::fs::create_dir_all(&dir).expect("member charts dir");
        std::fs::write(dir.join(&filename), content).expect("seed member chart bytes");
        filename
    }

    #[tokio::test]
    async fn virtual_chart_download_does_not_leak_a_private_members_bytes_to_anon() {
        const PRIVATE_BYTES: &[u8] = b"helm PRIVATE member chart bytes";
        const PUBLIC_BYTES: &[u8] = b"helm public member chart bytes";

        let Some(fx) = tdh::Fixture::setup("virtual", "helm").await else {
            return;
        };
        let (private_id, _private_key, private_dir) =
            tdh::create_repo(&fx.pool, "local", "helm").await;
        let (public_id, _public_key, public_dir) =
            tdh::create_repo(&fx.pool, "local", "helm").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(public_id)
            .execute(&fx.pool)
            .await
            .expect("publish public member");
        tdh::link_virtual_member(&fx.pool, fx.repo_id, private_id, 1).await;
        tdh::link_virtual_member(&fx.pool, fx.repo_id, public_id, 2).await;
        let private_file = seed_member_chart(
            &fx.pool,
            private_id,
            &private_dir,
            "privchart",
            "1.0.0",
            PRIVATE_BYTES,
            fx.user_id,
        )
        .await;
        let public_file = seed_member_chart(
            &fx.pool,
            public_id,
            &public_dir,
            "pubchart",
            "1.0.0",
            PUBLIC_BYTES,
            fx.user_id,
        )
        .await;
        // The fixture user holds a grant on the PRIVATE member (positive
        // control) — Fixture::setup already granted it the virtual parent.
        tdh::grant_repo_access(&fx.pool, private_id, fx.user_id).await;

        // `download_chart_via_index` early-returns None without a proxy
        // service, so build a state that carries one: without it every branch
        // 404s and the anonymous assertion below would be green on `main`.
        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        let uri_private = format!("/{}/charts/{}", fx.repo_key, private_file);
        let uri_public = format!("/{}/charts/{}", fx.repo_key, public_file);

        let (anon_private_status, anon_private_body) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            tdh::get(uri_private.clone()),
        )
        .await;
        let (anon_public_status, anon_public_body) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            tdh::get(uri_public),
        )
        .await;
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let (granted_status, granted_body) = tdh::send(
            tdh::router_with_auth(super::router(), state, auth),
            tdh::get(uri_private),
        )
        .await;

        tdh::cleanup_member_repo(&fx.pool, private_id, &private_dir).await;
        tdh::cleanup_member_repo(&fx.pool, public_id, &public_dir).await;
        fx.teardown().await;

        assert_ne!(
            anon_private_status,
            StatusCode::OK,
            "an ANONYMOUS caller must not download a PRIVATE member's chart \
             through a public Virtual parent; got body {:?}",
            String::from_utf8_lossy(&anon_private_body)
        );
        assert_eq!(
            (anon_public_status, anon_public_body),
            (StatusCode::OK, Bytes::from_static(PUBLIC_BYTES)),
            "a PUBLIC member's chart must still be served anonymously through \
             the same virtual — the walk is filtered, not broken"
        );
        assert_eq!(
            (granted_status, granted_body),
            (StatusCode::OK, Bytes::from_static(PRIVATE_BYTES)),
            "the private member's granted principal must still download its \
             chart through the virtual"
        );
    }
}
