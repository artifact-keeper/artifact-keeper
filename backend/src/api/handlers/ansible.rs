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
//! `stable-2.17` through `stable-2.19`, and `return urljoin(self.api_server,
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
//! * `stable-2.17`..`stable-2.19`: the caller in `collection/__init__.py`
//!   reduces the value to its **last non-empty path segment**
//!   (`for path_segment in reversed(import_uri.split('/'))`) and
//!   `wait_import_task(task_id)` rebuilds the URL as
//!   `_urljoin(api_server, 'v3/', 'imports/collections', task_id, '/')`.
//!   Since `g_connect` has already rewritten `self.api_server` to the URL that
//!   served `available_versions` (`self.api_server = n_url`), that is
//!   `/ansible/{repo_key}/api/v3/imports/collections/{task_id}/`.
//! * `stable-2.20` and `devel`: `urljoin(self.api_server, resp['task'])` is passed to
//!   `wait_import_task` **verbatim**, with no segment extraction. A
//!   root-absolute reference resolves against the origin, yielding the same
//!   URL.
//!
//! So a root-absolute path ending in `/{task_id}/` is correct for both — and it
//! is the shape ansible-core itself documents as the v3 reference response:
//! `{"task": "/api/automation-hub/v3/imports/collections/838d1308-...-7823f3806cd8/"}`.
//! A bare id would break `stable-2.20` and `devel` (relative resolution drops the last segment of
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
use crate::models::repository::RepositoryType;
use crate::services::proxy_service::ProxyService;

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
/// by [`import_status`]. Root-absolute so `stable-2.20`/`devel`'s
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
// Remote (proxy) upstream discovery (#3365)
// ---------------------------------------------------------------------------

/// Page size requested from an upstream Galaxy v3 `versions/` endpoint.
///
/// Galaxy NG paginates with DRF limit/offset and clamps `limit` server-side:
/// verified live against `galaxy.ansible.com`, a request for `limit=1000` on a
/// 239-version collection returns 100 items plus a `links.next`, so asking for
/// more does not save a round trip.
const UPSTREAM_VERSIONS_PAGE_SIZE: usize = 100;

/// Hard ceiling on upstream pages walked while answering one version list.
///
/// A version list has to be COMPLETE to be useful — `ansible-galaxy` resolves a
/// pinned version by membership in this list, and the largest real collections
/// run past a single page (`community.general` is 239 versions today) — so the
/// walk cannot stop at page one. It also cannot be unbounded: the page count is
/// driven by an upstream's own `meta.count`, and a hostile or broken upstream
/// that always reports a full page would otherwise spin this request forever.
/// Twenty pages is 2000 versions, an order of magnitude above the largest
/// collection published today, and the truncation is logged rather than silent.
const UPSTREAM_VERSIONS_MAX_PAGES: usize = 20;

/// Whether a Galaxy coordinate can be interpolated into a single path segment
/// of an upstream request and of the URLs this repository advertises back.
///
/// Two different strings reach this function and both are untrusted. The
/// `namespace`/`name` come from the client's own URL and are pushed OUT into an
/// upstream request path; the `version` strings come from a third party's
/// response and are pushed back into `href`/`download_url` values this server
/// publishes. Neither is a place for a separator: `..` walks the upstream path
/// out of the configured `upstream_url` prefix, and `?`/`#` truncate it into a
/// query or fragment, which would make the repository fetch — or advertise — a
/// resource other than the one it just named.
///
/// `%` is refused with the separators because axum percent-decodes a captured
/// parameter before the handler sees it and the `url` crate decodes again when
/// the upstream URL is parsed, so `%2F` is a `/` arriving one step later. This
/// is the same rule, and the same reasoning, as the Helm proxied index's
/// `upstream_chart_is_advertisable` (#3448); encoding rather than rejecting was
/// rejected there because an encoder covering `%` also rewrites `+`, which is
/// legal semver build metadata.
///
/// Rejecting costs nothing real: Galaxy's own namespace/name grammar is
/// `[a-z0-9_]+`, and a version that cannot be addressed could not have been
/// downloaded through this repository anyway.
fn galaxy_coordinate_is_addressable(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && !part
            .chars()
            .any(|c| matches!(c, '/' | '\\' | '?' | '#' | '%') || c.is_control())
}

/// The `href` this repository advertises for one collection version.
fn version_href(repo_key: &str, namespace: &str, name: &str, version: &str) -> String {
    format!(
        "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
        repo_key, namespace, name, version
    )
}

/// Fetch every version an upstream Galaxy server publishes for one collection.
///
/// # Why offset paging rather than following `links.next`
///
/// Galaxy's `links.next` is a **root-relative** path — live, `galaxy.ansible.com`
/// answers `/api/v3/collections/{ns}/{name}/versions/` with a 302 to
/// `/api/v3/plugin/ansible/content/published/collections/index/...` and its
/// `links.next` is spelled against the origin, not against the configured
/// `upstream_url`. Following it would mean reconstructing the upstream ORIGIN
/// and issuing a request outside the configured `upstream_url` prefix, which
/// widens what a repository is allowed to fetch on the say-so of the upstream's
/// own response body — the shape of an SSRF, not a paging strategy. A private
/// Automation Hub makes the same point without any malice: it serves Galaxy
/// under a `/api/galaxy/` prefix, so a root-relative `next` resolved against
/// the origin drops the prefix and 404s.
///
/// Re-requesting the SAME path with a growing `offset` keeps every request
/// underneath the configured prefix, needs nothing from the upstream but a
/// count of rows, and is the standard DRF limit/offset paging both
/// galaxy.ansible.com and Galaxy NG implement (verified live: `offset=0/100/200`
/// walk a 239-version collection with no gaps or repeats).
async fn fetch_upstream_versions(
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    namespace: &str,
    name: &str,
) -> Result<Vec<String>, Response> {
    let mut versions: Vec<String> = Vec::new();

    for page in 0..UPSTREAM_VERSIONS_MAX_PAGES {
        let upstream_path = format!(
            "api/v3/collections/{}/{}/versions/?limit={}&offset={}",
            namespace,
            name,
            UPSTREAM_VERSIONS_PAGE_SIZE,
            page * UPSTREAM_VERSIONS_PAGE_SIZE
        );

        // Buffered and byte-capped by design: a version list is a small
        // metadata document that has to be parsed in-process before anything
        // can be merged out of it. Only the version STRINGS survive this
        // scope, so unlike the Helm proxied index (#3448) there is no derived
        // working set to hold a budget reservation open for.
        let (body, _content_type) = proxy_helpers::proxy_fetch_capped(
            proxy,
            repo_id,
            repo_key,
            upstream_url,
            &upstream_path,
            proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
        )
        .await?;

        let doc: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "Failed to parse upstream collection version list",
            )
                .into_response()
        })?;

        let page_versions: Vec<String> = doc
            .get("data")
            .and_then(|d| d.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|e| e.get("version").and_then(|v| v.as_str()))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let page_len = page_versions.len();
        versions.extend(page_versions);

        // A short page is the last page. `links.next` is consulted only as a
        // stop signal, never as a URL to fetch (see the note above), so a
        // server that omits it simply falls back to the length check.
        let has_next = doc
            .pointer("/links/next")
            .map(|v| !v.is_null())
            .unwrap_or(false);
        if page_len < UPSTREAM_VERSIONS_PAGE_SIZE || !has_next {
            return Ok(versions);
        }
    }

    tracing::warn!(
        repository = %repo_key,
        collection = %format!("{}.{}", namespace, name),
        pages = UPSTREAM_VERSIONS_MAX_PAGES,
        collected = versions.len(),
        "upstream collection has more versions than the per-request page ceiling; \
         the advertised version list is truncated"
    );
    Ok(versions)
}

/// Merge upstream version strings into the version list being built, appending
/// only those the repository does not already hold.
///
/// Locally-held versions win their version string and keep their position: the
/// local row is the one `download_collection` resolves before it ever consults
/// upstream, and it carries the artifact's real stored filename. Re-advertising
/// the same version from upstream would produce a duplicate entry for a single
/// resolvable artifact, which `ansible-galaxy` would present as two candidates
/// for one version.
///
/// Upstream versions that cannot form a single path segment are dropped with a
/// warning rather than advertised: every entry here becomes an `href` under
/// this repository's own route, and an entry that cannot be addressed is a
/// promise the download route could not keep.
fn merge_upstream_versions(
    repo_key: &str,
    namespace: &str,
    name: &str,
    upstream: Vec<String>,
    out: &mut Vec<serde_json::Value>,
) {
    let held: std::collections::HashSet<String> = out
        .iter()
        .filter_map(|v| v.get("version").and_then(|s| s.as_str()))
        .map(str::to_string)
        .collect();
    let mut seen = held.clone();

    for version in upstream {
        if seen.contains(&version) {
            continue;
        }
        if !galaxy_coordinate_is_addressable(&version) {
            tracing::warn!(
                repository = %repo_key,
                collection = %format!("{}.{}", namespace, name),
                version = %version,
                "upstream collection version cannot be addressed as a single path \
                 segment; omitting it from the proxied version list"
            );
            continue;
        }
        out.push(serde_json::json!({
            "version": version,
            "href": version_href(repo_key, namespace, name, &version),
        }));
        seen.insert(version);
    }
}

/// Build the version-metadata document `ansible-galaxy` reads, for both a
/// locally-held collection version and one resolved from an upstream (#3365).
///
/// # The document shape is a hard client contract, not a convention
///
/// `GalaxyAPI.get_collection_version_metadata`
/// (`lib/ansible/galaxy/api.py`, identical on `stable-2.17`..`devel`) ends in
/// an unconditional index into five fields:
///
/// ```text
/// CollectionVersionMetadata(data['namespace']['name'], data['collection']['name'],
///                           data['version'], download_url,
///                           data['artifact']['sha256'],
///                           data['metadata']['dependencies'], data['href'], signatures)
/// ```
///
/// So `namespace` must be an OBJECT carrying `name` (a bare string raises
/// `TypeError: string indices must be integers`), `collection` must carry
/// `name` as well as its `href`, and `href` and `metadata.dependencies` must
/// both be present. `requires_ansible` and `signatures` are read with `.get`
/// and are genuinely optional. This is also the shape `galaxy.ansible.com`
/// itself serves, verified live.
///
/// One builder serves both branches deliberately. A Remote repository can hold
/// a version locally (promotion, peer replication, migration import) and proxy
/// its neighbours, so emitting a different document per branch would make the
/// contract depend on which copy happened to answer.
///
/// # `download_url`
///
/// The client accepts an absolute URL or a root-absolute path and resolves the
/// latter with `urljoin(self.api_server, ...)`; a bare relative path is a hard
/// error. Every URL emitted here is root-absolute and points at THIS
/// repository's own `download/` route, never at the upstream, so the tarball is
/// fetched back through the proxy -- which is what makes the cache, the
/// download accounting and the repository's own authorization apply to it.
#[allow(clippy::too_many_arguments)]
fn version_info_document(
    repo_key: &str,
    namespace: &str,
    name: &str,
    version: &str,
    filename: &str,
    download_url: &str,
    size_bytes: i64,
    sha256: &str,
    dependencies: serde_json::Value,
    metadata: serde_json::Value,
    requires_ansible: Option<&str>,
    downloads: i64,
) -> serde_json::Value {
    let mut metadata = match metadata {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    metadata.insert("dependencies".to_string(), dependencies);

    let mut doc = serde_json::json!({
        "version": version,
        "href": version_href(repo_key, namespace, name, version),
        // Object, not a bare string: the client indexes `['name']` into it.
        "namespace": { "name": namespace },
        "name": name,
        "collection": {
            "name": name,
            "href": format!(
                "/ansible/{}/api/v3/collections/{}/{}/",
                repo_key, namespace, name
            ),
        },
        "download_url": download_url,
        "artifact": {
            "filename": filename,
            "size": size_bytes,
            "sha256": sha256,
        },
        "downloads": downloads,
        "metadata": serde_json::Value::Object(metadata),
    });
    if let Some(req) = requires_ansible {
        doc["requires_ansible"] = serde_json::json!(req);
    }
    doc
}

/// Fetch one collection version's metadata from the upstream Galaxy server and
/// re-express it as this repository's own document (#3365).
///
/// Nothing is forwarded verbatim. The upstream's `download_url` points at the
/// upstream (`https://galaxy.ansible.com/api/v3/plugin/.../artifacts/...`), and
/// serving it as-is would send the client straight past this repository: no
/// cache, no download accounting, and none of this repository's authorization
/// applied to the bytes. The advertised URL is rebuilt against this
/// repository's own `download/` route, which already resolves a Remote miss
/// upstream.
///
/// The advertised filename is always the canonical
/// `{namespace}-{name}-{version}.tar.gz` for the requested coordinate, and the
/// upstream's `sha256` must be usable or the version is refused with a 502 --
/// see [`rewrite_upstream_version_info`] for both invariants. `dependencies`
/// is carried across unchanged.
///
/// Note the raw upstream document is cached by the proxy layer under its
/// mutable-metadata TTL, so a refusal repeats from cache until that TTL
/// expires and the upstream is consulted again; a refused version is never
/// served in the interim, only re-refused.
#[allow(clippy::too_many_arguments)]
async fn fetch_upstream_version_info(
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    namespace: &str,
    name: &str,
    version: &str,
) -> Result<serde_json::Value, Response> {
    let upstream_path = format!(
        "api/v3/collections/{}/{}/versions/{}/",
        namespace, name, version
    );
    let (body, _content_type) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;

    let doc: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Failed to parse upstream collection version metadata",
        )
            .into_response()
    })?;

    rewrite_upstream_version_info(repo_key, namespace, name, version, &doc).map_err(|reason| {
        tracing::warn!(
            repository = %repo_key,
            collection = %format!("{}.{}", namespace, name),
            version = %version,
            %reason,
            "refusing to advertise an upstream collection version"
        );
        (StatusCode::BAD_GATEWAY, reason).into_response()
    })
}

/// Fetch a collection's detail document from the upstream Galaxy server and
/// re-express it as this repository's own (#3365).
///
/// The upstream's `href`, `versions_url` and `highest_version.href` all point
/// into the upstream's own URL space (`/api/content/published/v3/plugin/...`
/// on galaxy.ansible.com), so they are rebuilt against this repository's
/// routes rather than forwarded -- a client that followed one would leave the
/// proxy. `created_at`/`updated_at` are carried across because the client reads
/// `updated_at` as its response-cache key; both are read with `.get`, so an
/// upstream that omits them is fine and nothing is invented for them.
async fn fetch_upstream_collection_info(
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    namespace: &str,
    name: &str,
) -> Result<serde_json::Value, Response> {
    let upstream_path = format!("api/v3/collections/{}/{}/", namespace, name);
    let (body, _content_type) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;

    let doc: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Failed to parse upstream collection metadata",
        )
            .into_response()
    })?;

    Ok(rewrite_upstream_collection_info(
        repo_key, namespace, name, &doc,
    ))
}

/// Pure half of [`fetch_upstream_collection_info`].
fn rewrite_upstream_collection_info(
    repo_key: &str,
    namespace: &str,
    name: &str,
    upstream: &serde_json::Value,
) -> serde_json::Value {
    let highest = upstream
        .pointer("/highest_version/version")
        .and_then(|v| v.as_str())
        .filter(|v| galaxy_coordinate_is_addressable(v))
        .unwrap_or_default()
        .to_string();

    let mut doc = serde_json::json!({
        "namespace": namespace,
        "name": name,
        "description": upstream.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "deprecated": upstream.get("deprecated").and_then(|v| v.as_bool()).unwrap_or(false),
        "href": format!("/ansible/{}/api/v3/collections/{}/{}/", repo_key, namespace, name),
        "versions_url": format!(
            "/ansible/{}/api/v3/collections/{}/{}/versions/",
            repo_key, namespace, name
        ),
        "highest_version": {
            "version": highest,
            "href": version_href(repo_key, namespace, name, &highest),
        },
    });
    // Read by the client as its response-cache key; forwarded when present and
    // omitted when not, rather than filled in with a value this server made up.
    for field in ["created_at", "updated_at"] {
        if let Some(v) = upstream.get(field) {
            doc[field] = v.clone();
        }
    }
    doc
}

/// Pure half of [`fetch_upstream_version_info`]: turn an upstream Galaxy
/// version document into this repository's own, or refuse it (`Err` carries
/// the reason, surfaced by the caller as a 502).
///
/// Two upstream fields are load-bearing for integrity and are therefore
/// validated rather than forwarded on trust:
///
/// * `artifact.filename` is only ever consulted, never advertised: the
///   emitted `download_url` ALWAYS names the canonical
///   `{namespace}-{name}-{version}.tar.gz` for the coordinate the client
///   asked about. An upstream that names any other file (a different
///   collection, a different version, a traversal) is attempting — or would
///   enable — content substitution: the advertised URL would resolve through
///   this repository's download route to bytes other than the version this
///   document claims to describe. The mismatch is logged and ignored.
/// * `artifact.sha256` must be a non-empty string. `ansible-galaxy` verifies
///   the downloaded tarball only `if expected_hash:` — an empty string is
///   falsy in Python, so relaying `""` silently DISABLES the client's
///   integrity check, and this server does not verify the proxied bytes
///   either. Inventing a digest would be worse than passing none, so a
///   version whose upstream document carries no usable digest is refused
///   outright rather than advertised as unverifiable.
fn rewrite_upstream_version_info(
    repo_key: &str,
    namespace: &str,
    name: &str,
    version: &str,
    upstream: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let filename = collection_filename(namespace, name, version);
    if let Some(claimed) = upstream
        .pointer("/artifact/filename")
        .and_then(|v| v.as_str())
    {
        if claimed != filename {
            tracing::warn!(
                repository = %repo_key,
                collection = %format!("{}.{}", namespace, name),
                version = %version,
                upstream_filename = %claimed,
                advertised = %filename,
                "upstream artifact.filename does not name the requested version; \
                 advertising the canonical filename instead (content-substitution guard)"
            );
        }
    }

    let size_bytes = upstream
        .pointer("/artifact/size")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let sha256 = match upstream
        .pointer("/artifact/sha256")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s,
        None => {
            return Err(format!(
                "Upstream did not supply an artifact sha256 for {}.{} {}; \
                 refusing to advertise a version the client could not verify",
                namespace, name, version
            ));
        }
    };
    let dependencies = upstream
        .pointer("/metadata/dependencies")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let metadata = upstream
        .get("metadata")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let requires_ansible = upstream.get("requires_ansible").and_then(|v| v.as_str());

    Ok(version_info_document(
        repo_key,
        namespace,
        name,
        version,
        &filename,
        &format!("/ansible/{}/download/{}", repo_key, filename),
        size_bytes,
        sha256,
        dependencies,
        metadata,
        requires_ansible,
        0,
    ))
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
    let local =
        proxy_helpers::find_artifact_by_name_lowercase(&state.db, repo.id, &collection_name)
            .await?;

    // Remote (proxy) repository: answering 404 here does not merely omit a
    // detail page, it silently empties the VERSION LIST. When the client has a
    // response cache configured -- which it does whenever the server is declared
    // in `ansible.cfg` under `[galaxy_server.*]`, the ordinary enterprise setup
    // -- `GalaxyAPI.get_collection_versions` first calls
    // `get_collection_metadata` to read the collection's `updated_at` as a
    // cache key, and treats a 404 from it as "no collection found" by
    // `return []`. So a proxy that served a complete version list still ended
    // up reporting no versions, and the install failed with the same
    // "Could not satisfy the following requirements" as before (#3365).
    // Reproduced live: identical requirements file, install succeeds against an
    // ad-hoc `source:` (cache off) and fails against a configured
    // `[galaxy_server.*]` (cache on) until this branch exists.
    if local.is_none() && repo.repo_type == RepositoryType::Remote {
        if let (Some(proxy), Some(upstream_url)) =
            (state.proxy_service.as_deref(), repo.upstream_url.as_deref())
        {
            if !galaxy_coordinate_is_addressable(&namespace)
                || !galaxy_coordinate_is_addressable(&name)
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid collection namespace or name",
                )
                    .into_response());
            }
            // Nothing is held locally on this path, so as in `version_info`
            // there is nothing to degrade to and the upstream's own error is
            // surfaced as `map_proxy_error` classifies it.
            let upstream = fetch_upstream_collection_info(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &namespace,
                &name,
            )
            .await?;
            return Ok(super::json_response(&upstream));
        }
    }

    let artifact =
        local.ok_or_else(|| (StatusCode::NOT_FOUND, "Collection not found").into_response())?;

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

    let mut versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "version": version,
                "href": version_href(&repo_key, &namespace, &name, &version),
            })
        })
        .collect();

    // Remote (proxy) repository: this list is the DISCOVERY half of a
    // collection install. `ansible-galaxy` resolves a version out of it before
    // it requests any tarball -- a pinned requirement has to appear here or the
    // resolver reports "Could not satisfy the following requirements" -- so
    // building it from locally-catalogued rows alone answered an empty `data`
    // with HTTP 200 and made a proxy repository unusable for install, even
    // though `download_collection` could already serve the tarball by name
    // (#3365). Serve what the upstream publishes, merged over whatever is held
    // locally, which is the same set the download route can actually resolve.
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(proxy), Some(upstream_url)) =
            (state.proxy_service.as_deref(), repo.upstream_url.as_deref())
        {
            // The coordinates are interpolated into an upstream request path,
            // so they are checked before they leave this process rather than
            // trusted to the cache-path validator downstream.
            if !galaxy_coordinate_is_addressable(&namespace)
                || !galaxy_coordinate_is_addressable(&name)
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid collection namespace or name",
                )
                    .into_response());
            }
            match fetch_upstream_versions(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &namespace,
                &name,
            )
            .await
            {
                Ok(upstream) => {
                    merge_upstream_versions(&repo_key, &namespace, &name, upstream, &mut versions)
                }
                // Upstream is unreachable or unparseable. With nothing held
                // locally there is no honest list to serve: an empty `data` is
                // indistinguishable from "this collection has no versions",
                // which is exactly the silent failure this issue is about, so
                // the upstream's own error is surfaced (`map_proxy_error`
                // classifies an upstream 5xx as 503, a definitive 404 as 404
                // and a connect failure as 502) and the install fails loudly
                // and legibly instead of reporting an unsatisfiable pin. With
                // versions held locally those are still served -- an upstream
                // outage must not stop a collection this repository already
                // has from resolving, which is the point of a cache. The proxy
                // cache applies RFC 5861 stale-if-error to the version
                // document itself, so a warm proxy keeps serving the last good
                // upstream list before this fallback is reached at all.
                Err(err) if versions.is_empty() => return Err(err),
                Err(err) => {
                    tracing::warn!(
                        repository = %repo_key,
                        collection = %format!("{}.{}", namespace, name),
                        status = %err.status(),
                        "upstream collection version list unavailable; serving \
                         locally-held versions only"
                    );
                }
            }
        }
    }

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
    let local = proxy_helpers::find_artifact_by_name_version(
        &state.db,
        repo.id,
        &collection_name,
        &version,
    )
    .await?;

    if let Some(artifact) = local {
        let download_count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
            artifact.id
        )
        .fetch_one(&state.db)
        .await
        .unwrap_or(Some(0))
        .unwrap_or(0);

        let metadata = artifact.metadata.unwrap_or_else(|| serde_json::json!({}));
        // A collection published through the native upload carries no
        // dependency map on the wire (`ansible-galaxy collection publish`
        // sends only `file` and `sha256`), so `collection_json` is populated
        // only by clients that send the optional metadata part. An absent map
        // is emitted as `{}` -- "declares no dependencies" -- rather than
        // omitted, because the client indexes the key unconditionally. Reading
        // the real map out of the uploaded tarball's `MANIFEST.json` is a
        // separate gap in the UPLOAD path and is filed on its own.
        let dependencies = metadata
            .pointer("/collection_json/dependencies")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        // Same fail-closed rule as the Remote branch: `ansible-galaxy` skips
        // tarball verification when `artifact.sha256` is falsy, so a stored
        // row with no checksum must be refused, not advertised with `""`.
        // Every native upload computes the digest at ingest; a NULL/empty
        // checksum means an out-of-band import and is a server-side data
        // problem, hence 500 rather than 502.
        let Some(sha256) = artifact
            .checksum_sha256
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            tracing::error!(
                repository = %repo_key,
                collection = %format!("{}.{}", namespace, name),
                version = %version,
                artifact_id = %artifact.id,
                "stored collection version has no sha256 checksum; refusing to \
                 advertise a version the client could not verify"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Stored collection version has no sha256 checksum; refusing to \
                 advertise a version the client could not verify",
            )
                .into_response());
        };

        let json = version_info_document(
            &repo_key,
            &namespace,
            &name,
            &version,
            &proxy_helpers::advertised_download_filename(
                &artifact.path,
                &collection_filename(&namespace, &name, &version),
            ),
            &collection_download_url(&repo_key, &artifact.path, &namespace, &name, &version),
            artifact.size_bytes.unwrap_or(0),
            sha256,
            dependencies,
            metadata,
            None,
            download_count,
        );
        return Ok(super::json_response(&json));
    }

    // Remote (proxy) repository: the version this metadata describes is not
    // held locally, so ask the upstream that publishes it. Without this the
    // route 404s for every collection a proxy has not already cached, which
    // fails the install one step after the version list resolved it (#3365).
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(proxy), Some(upstream_url)) =
            (state.proxy_service.as_deref(), repo.upstream_url.as_deref())
        {
            if !galaxy_coordinate_is_addressable(&namespace)
                || !galaxy_coordinate_is_addressable(&name)
                || !galaxy_coordinate_is_addressable(&version)
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid collection namespace, name, or version",
                )
                    .into_response());
            }
            // No local row exists on this path, so there is nothing to degrade
            // to: an upstream error is the only honest answer and is surfaced
            // as `map_proxy_error` classifies it (404 for a definitive
            // upstream 404, 503 for an upstream 5xx, 502 for a connect
            // failure). The locally-held case returned above and is therefore
            // unaffected by an upstream outage.
            let upstream = fetch_upstream_version_info(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &namespace,
                &name,
                &version,
            )
            .await?;
            return Ok(super::json_response(&upstream));
        }
    }

    Err((StatusCode::NOT_FOUND, "Collection version not found").into_response())
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

    /// The path `ansible-core` polls on `stable-2.17`..`stable-2.19`.
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

    /// The path `ansible-core` polls on `stable-2.20` and `devel`.
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
        //    bare task id satisfies the stable line but breaks `stable-2.20`
        //    and `devel`, whose `urljoin` resolves it relative to the server
        //    and drops the last path segment. A fully-qualified URL happens to
        //    work under both — the stable line extracts the last segment
        //    *before* any `_urljoin`, so no doubling occurs — but it hardcodes
        //    an origin the deployment may not be reached at (proxies, split
        //    horizon DNS), which is why the root-absolute path is emitted.
        let api_server_path = format!("/ansible/{}/api", f.repo_key);
        let stable_path = stable_line_poll_path(&api_server_path, &task);
        let devel_path = devel_poll_path(&task);
        assert_eq!(
            stable_path, devel_path,
            "the emitted `task` must resolve to one URL under both ansible-core \
             derivations (stable-2.17..2.19 segment extraction vs stable-2.20/devel urljoin)"
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
    // -----------------------------------------------------------------------
    // #3365: a Remote repository must serve the upstream's collection versions
    // -----------------------------------------------------------------------

    /// One page of a Galaxy v3 `versions/` response. `next` is spelled the way
    /// galaxy.ansible.com spells it -- root-relative, against the ORIGIN and
    /// not against the configured `upstream_url` -- so a test that accidentally
    /// started following it would go somewhere the mock does not serve.
    fn upstream_versions_page(versions: &[&str], count: usize, next: Option<&str>) -> String {
        let data: Vec<serde_json::Value> = versions
            .iter()
            .map(|v| {
                serde_json::json!({
                    "version": v,
                    "href": format!("/api/v3/plugin/ansible/content/published/collections/index/testns/testcoll/versions/{v}/"),
                })
            })
            .collect();
        serde_json::json!({
            "meta": { "count": count },
            "links": {
                "first": "/api/v3/plugin/ansible/content/published/collections/index/testns/testcoll/versions/?limit=100&offset=0",
                "previous": null,
                "next": next,
                "last": null,
            },
            "data": data,
        })
        .to_string()
    }

    /// An upstream version-metadata document in the shape galaxy.ansible.com
    /// actually serves, captured live: `download_url` is an ABSOLUTE upstream
    /// URL, so a test can tell a rewritten document from a forwarded one.
    fn upstream_version_info_doc() -> String {
        serde_json::json!({
            "version": "1.5.1",
            "href": "/api/content/published/v3/plugin/ansible/content/published/collections/index/testns/testcoll/versions/1.5.1/",
            "namespace": { "name": "testns", "metadata_sha256": "abc" },
            "name": "testcoll",
            "collection": { "name": "testcoll", "href": "/api/v3/.../testns/testcoll/" },
            "download_url": "https://upstream.invalid/api/v3/plugin/ansible/content/published/collections/artifacts/testns-testcoll-1.5.1.tar.gz",
            "artifact": {
                "filename": "testns-testcoll-1.5.1.tar.gz",
                "sha256": "112653d7e4e462827f1521130849c650e9dbc403f8b2e9dd5040f2ddabff33ed",
                "size": 175162,
            },
            "requires_ansible": ">=2.9.10",
            "metadata": {
                "description": "a collection",
                "dependencies": { "testns.other": ">=1.0.0" },
            },
        })
        .to_string()
    }

    #[test]
    fn test_merge_upstream_versions_advertises_them_under_this_repo_3365() {
        let mut out: Vec<serde_json::Value> = Vec::new();
        merge_upstream_versions(
            "gx",
            "testns",
            "testcoll",
            vec!["2.0.0".to_string(), "1.5.1".to_string()],
            &mut out,
        );

        assert_eq!(
            out.len(),
            2,
            "every upstream version must be merged: {out:?}"
        );
        // Literal expectations, not `version_href(..)` -- an href computed by
        // the code under test would agree with itself no matter what it emits.
        assert_eq!(out[0]["version"], "2.0.0");
        assert_eq!(
            out[0]["href"], "/ansible/gx/api/v3/collections/testns/testcoll/versions/2.0.0/",
            "the advertised href must point back at THIS repository's route; an \
             upstream href would send the client past the proxy"
        );
        assert_eq!(out[1]["version"], "1.5.1");
        assert_eq!(
            out[1]["href"],
            "/ansible/gx/api/v3/collections/testns/testcoll/versions/1.5.1/"
        );
    }

    #[test]
    fn test_merge_upstream_versions_keeps_the_locally_held_version_3365() {
        // The held version is deliberately one the upstream ALSO publishes, so
        // a merge that failed to dedup would be visible as a second entry; the
        // upstream's other version is one the fixture does NOT hold, so the
        // "still merged" assertion cannot pass by accident.
        let mut out = vec![serde_json::json!({
            "version": "1.5.1",
            "href": "/ansible/gx/api/v3/collections/testns/testcoll/versions/1.5.1/",
            "local_marker": true,
        })];

        merge_upstream_versions(
            "gx",
            "testns",
            "testcoll",
            vec!["1.5.1".to_string(), "2.0.0".to_string()],
            &mut out,
        );

        let same: Vec<_> = out.iter().filter(|v| v["version"] == "1.5.1").collect();
        assert_eq!(
            same.len(),
            1,
            "a version held locally must not gain a duplicate upstream entry: {out:?}"
        );
        assert_eq!(
            same[0]["local_marker"], true,
            "the locally-held entry must survive the merge, not be replaced"
        );
        assert_eq!(out.len(), 2, "the other upstream version is still merged");
        assert_eq!(out[1]["version"], "2.0.0");
    }

    /// #3365: upstream version strings are interpolated into `href` values this
    /// server publishes, so one that cannot form a single path segment is
    /// dropped rather than advertised.
    #[test]
    fn test_merge_drops_upstream_versions_that_cannot_be_addressed_3365() {
        for bad in [
            "../../../../etc/passwd",
            "1.0.0/../../etc",
            "q?x=1#frag",
            "a/b",
            "pct%2Fescape",
            "..",
            "",
        ] {
            assert!(
                !galaxy_coordinate_is_addressable(bad),
                "{bad:?} cannot form one path segment and must not be advertised"
            );
            let mut out: Vec<serde_json::Value> = Vec::new();
            merge_upstream_versions("gx", "testns", "testcoll", vec![bad.to_string()], &mut out);
            assert!(
                out.is_empty(),
                "the unaddressable version must be omitted, got {out:?}"
            );
        }
    }

    /// The negative control for the filter above: the version strings real
    /// collections publish -- including semver build metadata, the reason an
    /// encoder was rejected -- must be untouched. These are deliberately
    /// different strings from the rejection fixtures, so the control cannot
    /// collapse onto its own boundary.
    #[test]
    fn test_ordinary_collection_versions_stay_advertisable_3365() {
        for good in [
            "1.5.1",
            "2.0.0-rc.1",
            "1.0.0+build.5",
            "0.0.1-alpha.1+sha.abcdef",
            "10.20.30",
        ] {
            assert!(
                galaxy_coordinate_is_addressable(good),
                "{good:?} is a legitimate collection version and must stay advertisable"
            );
            let mut out: Vec<serde_json::Value> = Vec::new();
            merge_upstream_versions("gx", "testns", "testcoll", vec![good.to_string()], &mut out);
            assert_eq!(out.len(), 1, "{good:?} must be advertised");
            assert_eq!(out[0]["version"], good);
        }
    }

    /// #3365: `GalaxyAPI.get_collection_version_metadata` indexes five fields
    /// unconditionally. A bare-string `namespace` raises
    /// `TypeError: string indices must be integers` inside the client, which
    /// surfaces as "Unexpected Exception, this is probably a bug" and kills the
    /// install -- so the shape is a hard contract, not a preference.
    #[test]
    fn test_version_info_document_satisfies_the_client_contract_3365() {
        let doc = version_info_document(
            "gx",
            "testns",
            "testcoll",
            "1.5.1",
            "testns-testcoll-1.5.1.tar.gz",
            "/ansible/gx/download/testns-testcoll-1.5.1.tar.gz",
            175162,
            "deadbeef",
            serde_json::json!({ "testns.other": ">=1.0.0" }),
            serde_json::json!({ "description": "a collection" }),
            Some(">=2.9.10"),
            7,
        );

        // The exact five hard indexes the client performs.
        assert_eq!(
            doc["namespace"]["name"], "testns",
            "`namespace` must be an OBJECT carrying `name`; a bare string makes \
             the client raise TypeError before the install starts"
        );
        assert_eq!(doc["collection"]["name"], "testcoll");
        assert_eq!(doc["version"], "1.5.1");
        assert_eq!(doc["artifact"]["sha256"], "deadbeef");
        assert_eq!(doc["metadata"]["dependencies"]["testns.other"], ">=1.0.0");
        assert_eq!(
            doc["href"], "/ansible/gx/api/v3/collections/testns/testcoll/versions/1.5.1/",
            "`href` is read unconditionally and was absent entirely"
        );
        // Pre-existing metadata is preserved alongside the injected map.
        assert_eq!(doc["metadata"]["description"], "a collection");
        assert_eq!(doc["requires_ansible"], ">=2.9.10");
        assert_eq!(doc["downloads"], 7);
    }

    /// `metadata.dependencies` is indexed unconditionally, so it must exist
    /// even when nothing is known about the collection's dependencies.
    #[test]
    fn test_version_info_document_always_carries_a_dependency_map_3365() {
        let doc = version_info_document(
            "gx",
            "testns",
            "testcoll",
            "1.0.0",
            "testns-testcoll-1.0.0.tar.gz",
            "/ansible/gx/download/testns-testcoll-1.0.0.tar.gz",
            10,
            "abc",
            serde_json::json!({}),
            // A non-object metadata value must not be able to erase the key.
            serde_json::json!("not-an-object"),
            None,
            0,
        );
        assert!(
            doc["metadata"]["dependencies"].is_object(),
            "dependencies must be an object even when unknown: {doc}"
        );
        assert!(
            doc.get("requires_ansible").is_none(),
            "an absent requires_ansible must be omitted, not invented"
        );
    }

    /// #3365: the upstream's `download_url` is an ABSOLUTE upstream URL.
    /// Forwarding it would send the client straight to the upstream, past the
    /// cache, the download accounting and this repository's authorization.
    #[test]
    fn test_rewrite_upstream_version_info_points_download_at_this_repo_3365() {
        let upstream: serde_json::Value =
            serde_json::from_str(&upstream_version_info_doc()).unwrap();
        let doc = rewrite_upstream_version_info("gx", "testns", "testcoll", "1.5.1", &upstream)
            .expect("a complete upstream document must be accepted");

        assert_eq!(
            doc["download_url"], "/ansible/gx/download/testns-testcoll-1.5.1.tar.gz",
            "the advertised download_url must be this repository's own route"
        );
        assert!(
            !doc["download_url"]
                .as_str()
                .unwrap()
                .contains("upstream.invalid"),
            "the upstream host must not survive the rewrite: {doc}"
        );
        // The parts that must be carried across unchanged.
        assert_eq!(
            doc["artifact"]["sha256"],
            "112653d7e4e462827f1521130849c650e9dbc403f8b2e9dd5040f2ddabff33ed",
            "the client verifies the tarball against this digest"
        );
        assert_eq!(doc["artifact"]["size"], 175162);
        assert_eq!(doc["metadata"]["dependencies"]["testns.other"], ">=1.0.0");
        assert_eq!(doc["requires_ansible"], ">=2.9.10");
        // And the parts that must be re-expressed as ours.
        assert_eq!(
            doc["href"],
            "/ansible/gx/api/v3/collections/testns/testcoll/versions/1.5.1/"
        );
        assert_eq!(doc["namespace"]["name"], "testns");
    }

    /// An upstream filename that cannot be addressed must not reach a URL this
    /// server publishes; the canonical Galaxy filename is used instead.
    #[test]
    fn test_rewrite_upstream_version_info_rejects_an_unaddressable_filename_3365() {
        let upstream = serde_json::json!({
            "artifact": { "filename": "../../../../etc/passwd", "sha256": "abc", "size": 1 },
        });
        let doc = rewrite_upstream_version_info("gx", "testns", "testcoll", "1.5.1", &upstream)
            .expect("a document with a usable sha256 must be accepted");
        assert_eq!(
            doc["download_url"], "/ansible/gx/download/testns-testcoll-1.5.1.tar.gz",
            "an unaddressable upstream filename must never be interpolated into \
             an advertised URL: {doc}"
        );
    }

    /// Content-substitution guard: an upstream `artifact.filename` that IS a
    /// single addressable path segment but names a DIFFERENT collection or
    /// version must not survive into the advertised `download_url`. The
    /// document describes `testns.testcoll 1.5.1`; advertising
    /// `other-coll-9.9.9.tar.gz` would make this repository's own download
    /// route hand back another collection's bytes under this version's name.
    #[test]
    fn test_rewrite_upstream_version_info_pins_filename_to_the_requested_coordinate() {
        let upstream = serde_json::json!({
            "artifact": {
                "filename": "evilns-evilcoll-9.9.9.tar.gz",
                "sha256": "abc",
                "size": 1,
            },
        });
        let doc = rewrite_upstream_version_info("gx", "testns", "testcoll", "1.5.1", &upstream)
            .expect("a document with a usable sha256 must be accepted");
        assert_eq!(
            doc["download_url"], "/ansible/gx/download/testns-testcoll-1.5.1.tar.gz",
            "an addressable-but-substituted upstream filename must not reach the \
             advertised download_url: the URL must resolve to the version this \
             document names: {doc}"
        );
        assert_eq!(
            doc["artifact"]["filename"], "testns-testcoll-1.5.1.tar.gz",
            "the advertised artifact.filename must be the canonical name for the \
             requested coordinate: {doc}"
        );
    }

    /// Integrity fail-closed: `ansible-galaxy` verifies the tarball only
    /// `if expected_hash:`, so relaying an absent/null/non-string/empty
    /// upstream sha256 as `""` silently disables the client's verification.
    /// Such a version must be refused, not advertised.
    #[test]
    fn test_rewrite_upstream_version_info_refuses_an_unusable_sha256() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("no artifact object", serde_json::json!({})),
            (
                "sha256 absent",
                serde_json::json!({ "artifact": { "filename": "testns-testcoll-1.5.1.tar.gz", "size": 1 } }),
            ),
            (
                "sha256 null",
                serde_json::json!({ "artifact": { "sha256": null, "size": 1 } }),
            ),
            (
                "sha256 a number",
                serde_json::json!({ "artifact": { "sha256": 12345, "size": 1 } }),
            ),
            (
                "sha256 empty",
                serde_json::json!({ "artifact": { "sha256": "", "size": 1 } }),
            ),
            (
                "sha256 whitespace",
                serde_json::json!({ "artifact": { "sha256": "   ", "size": 1 } }),
            ),
        ];
        for (label, upstream) in cases {
            let err = rewrite_upstream_version_info("gx", "testns", "testcoll", "1.5.1", &upstream)
                .expect_err(&format!(
                    "an upstream document with {label} must be refused, not \
                     advertised with an empty sha256 the client reads as \
                     'skip verification'"
                ));
            assert!(
                err.contains("sha256"),
                "the refusal must name the missing digest ({label}): {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_remote_version_list_serves_upstream_versions_3365() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "ansible").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/collections/testns/testcoll/versions/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(upstream_versions_page(
                    &["2.0.0", "1.5.1"],
                    2,
                    None,
                )),
            )
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/v3/collections/testns/testcoll/versions/",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        let data = doc["data"].as_array().expect("data array");
        assert!(
            !data.is_empty(),
            "a Remote repository must advertise the upstream's versions; an empty \
             `data` is what makes `ansible-galaxy` report 'Could not satisfy the \
             following requirements' (#3365)"
        );
        let versions: Vec<&str> = data.iter().filter_map(|v| v["version"].as_str()).collect();
        assert_eq!(versions, vec!["2.0.0", "1.5.1"]);
        assert_eq!(doc["meta"]["count"], 2);
        assert_eq!(
            data[1]["href"],
            format!(
                "/ansible/{}/api/v3/collections/testns/testcoll/versions/1.5.1/",
                f.repo_key
            ),
            "hrefs must point at this repository, not the upstream"
        );
    }

    /// #3365: the version list is walked to completion. Galaxy clamps `limit`
    /// to 100 server-side and the largest real collections run past one page,
    /// so a pinned version living on page two must still resolve.
    #[tokio::test]
    async fn test_remote_version_list_walks_every_upstream_page_3365() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "ansible").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;

        // A full first page (100 entries) plus a `next`, then a short second
        // page carrying the version the caller actually wants.
        let first: Vec<String> = (0..UPSTREAM_VERSIONS_PAGE_SIZE)
            .map(|i| format!("9.0.{i}"))
            .collect();
        let first_refs: Vec<&str> = first.iter().map(String::as_str).collect();
        Mock::given(method("GET"))
            .and(path("/api/v3/collections/testns/testcoll/versions/"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(upstream_versions_page(
                &first_refs,
                UPSTREAM_VERSIONS_PAGE_SIZE + 1,
                Some("/api/v3/plugin/ansible/content/published/collections/index/testns/testcoll/versions/?limit=100&offset=100"),
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v3/collections/testns/testcoll/versions/"))
            .and(query_param("offset", "100"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(upstream_versions_page(
                    &["1.5.1"],
                    UPSTREAM_VERSIONS_PAGE_SIZE + 1,
                    None,
                )),
            )
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/v3/collections/testns/testcoll/versions/",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        let versions: Vec<&str> = doc["data"]
            .as_array()
            .expect("data array")
            .iter()
            .filter_map(|v| v["version"].as_str())
            .collect();
        assert_eq!(
            versions.len(),
            UPSTREAM_VERSIONS_PAGE_SIZE + 1,
            "both pages must be collected, not just the first"
        );
        assert!(
            versions.contains(&"1.5.1"),
            "a version living on the SECOND upstream page must still be \
             advertised, or a pinned requirement on it is unsatisfiable"
        );
    }

    /// #3365: the two upstream failures an operator actually hits -- the
    /// upstream is down (5xx) and the upstream URL is wrong so the collection
    /// 404s. Neither may answer 200 with an empty `data`, which is
    /// indistinguishable from "this collection has no versions" and leaves
    /// `ansible-galaxy` blaming the requirement instead of the server.
    #[tokio::test]
    async fn test_remote_version_list_surfaces_an_upstream_failure_when_nothing_is_held_3365() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        for (upstream_status, expected) in [
            (503u16, StatusCode::SERVICE_UNAVAILABLE),
            (404, StatusCode::NOT_FOUND),
        ] {
            let Some(f) = tdh::Fixture::setup("remote", "ansible").await else {
                return;
            };
            let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
            Mock::given(method("GET"))
                .and(path("/api/v3/collections/testns/testcoll/versions/"))
                .respond_with(ResponseTemplate::new(upstream_status))
                .mount(&server)
                .await;
            let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

            let app = tdh::router_anon(super::router(), state);
            let (status, body) = tdh::send(
                app,
                tdh::get(format!(
                    "/{}/api/v3/collections/testns/testcoll/versions/",
                    f.repo_key
                )),
            )
            .await;

            f.teardown().await;

            assert_ne!(
                status,
                StatusCode::OK,
                "upstream {upstream_status} with nothing held locally must not answer \
                 200: an empty `data` reads as 'this collection has no versions' and \
                 the install fails blaming the requirement (#3365)"
            );
            assert_eq!(
                status,
                expected,
                "upstream {upstream_status} must be reported as {expected}, so an \
                 operator can tell an outage from a wrong upstream URL; body: {}",
                String::from_utf8_lossy(&body)
            );
        }
    }

    #[tokio::test]
    async fn test_remote_version_list_still_serves_held_versions_when_upstream_is_down_3365() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "ansible").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/collections/testns/testcoll/versions/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        // A Remote repository acquires local rows by promotion, peer
        // replication or migration import -- direct upload is refused.
        let repo = f.repo_info("remote", Some(&server.uri()));
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "held-collection-storage-key",
            "testns-testcoll-3.3.3.tar.gz",
            "testns-testcoll",
            "3.3.3",
            "application/gzip",
            bytes::Bytes::from_static(b"collection-bytes"),
            f.user_id,
        )
        .await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/v3/collections/testns/testcoll/versions/",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "an upstream outage must not stop a collection this repository already \
             holds from resolving (#3365)"
        );
        let doc: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        let versions: Vec<&str> = doc["data"]
            .as_array()
            .expect("data array")
            .iter()
            .filter_map(|v| v["version"].as_str())
            .collect();
        assert_eq!(
            versions,
            vec!["3.3.3"],
            "the locally-held version must still be advertised"
        );
    }

    #[tokio::test]
    async fn test_remote_version_info_serves_upstream_metadata_3365() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "ansible").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/collections/testns/testcoll/versions/1.5.1/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(upstream_version_info_doc()))
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/v3/collections/testns/testcoll/versions/1.5.1/",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "a Remote repository must answer for a version it does not hold; a 404 \
             here fails the install one step after the version list resolved it \
             (#3365); body: {}",
            String::from_utf8_lossy(&body)
        );
        let doc: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(
            doc["download_url"],
            format!(
                "/ansible/{}/download/testns-testcoll-1.5.1.tar.gz",
                f.repo_key
            ),
            "the tarball must be fetched back through this repository"
        );
        assert_eq!(doc["namespace"]["name"], "testns");
        assert_eq!(doc["collection"]["name"], "testcoll");
        assert_eq!(
            doc["artifact"]["sha256"],
            "112653d7e4e462827f1521130849c650e9dbc403f8b2e9dd5040f2ddabff33ed"
        );
        assert_eq!(doc["metadata"]["dependencies"]["testns.other"], ">=1.0.0");
    }

    /// End-to-end shape of the sha256 refusal: an upstream version document
    /// with no usable digest must surface as a 502 from the route, not as a
    /// 200 whose empty `artifact.sha256` disables the client's verification.
    #[tokio::test]
    async fn test_remote_version_info_refuses_an_upstream_without_a_sha256() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "ansible").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        let doc_without_sha = serde_json::json!({
            "version": "1.5.1",
            "artifact": { "filename": "testns-testcoll-1.5.1.tar.gz", "size": 175162 },
            "metadata": { "dependencies": {} },
        })
        .to_string();
        Mock::given(method("GET"))
            .and(path("/api/v3/collections/testns/testcoll/versions/1.5.1/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(doc_without_sha))
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/v3/collections/testns/testcoll/versions/1.5.1/",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "a version whose upstream document carries no sha256 must be refused \
             (502), not served with an empty digest; body: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            String::from_utf8_lossy(&body).contains("sha256"),
            "the refusal must say why: {}",
            String::from_utf8_lossy(&body)
        );
    }

    /// The hosted branch of the same fail-closed rule: a locally-held row
    /// whose `checksum_sha256` is empty (or NULL, were the constraint ever
    /// relaxed) must be refused, because advertising `""` makes
    /// `ansible-galaxy` skip tarball verification exactly as an upstream
    /// omission does.
    #[tokio::test]
    async fn test_local_version_info_refuses_a_row_without_a_checksum() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "hosted-collection-storage-key",
            "testns-testcoll-1.0.0.tar.gz",
            "testns-testcoll",
            "1.0.0",
            "application/gzip",
            bytes::Bytes::from_static(b"collection-bytes"),
            f.user_id,
        )
        .await;

        let uri = format!(
            "/{}/api/v3/collections/testns/testcoll/versions/1.0.0/",
            f.repo_key
        );
        // A realistic full-width digest: the column is CHAR(64), so a shorter
        // value comes back space-padded and would make this test assert the
        // padding instead of the guard.
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        sqlx::query("UPDATE artifacts SET checksum_sha256 = $1 WHERE repository_id = $2")
            .bind(digest)
            .bind(f.repo_id)
            .execute(&f.pool)
            .await
            .expect("set control checksum");

        // Control: with a stored checksum the row is advertised, digest intact.
        let app = tdh::router_anon(super::router(), f.state.clone());
        let (status, body) = tdh::send(app, tdh::get(uri.clone())).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "control: a row with a checksum must be served; body: {}",
            String::from_utf8_lossy(&body)
        );
        let doc: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(
            doc["artifact"]["sha256"], digest,
            "control: the stored checksum must be advertised verbatim"
        );

        // The column is NOT NULL, so the realizable bad state is an empty
        // string (an out-of-band import or migration writing ''); the handler
        // guards NULL and '' identically.
        sqlx::query("UPDATE artifacts SET checksum_sha256 = '' WHERE repository_id = $1")
            .bind(f.repo_id)
            .execute(&f.pool)
            .await
            .expect("blank out checksum");

        let app = tdh::router_anon(super::router(), f.state.clone());
        let (status, body) = tdh::send(app, tdh::get(uri)).await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a stored row with no checksum must be refused, not advertised with \
             an empty sha256 the client reads as 'skip verification'; body: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            String::from_utf8_lossy(&body).contains("sha256"),
            "the refusal must say why: {}",
            String::from_utf8_lossy(&body)
        );
    }

    /// A hosted repository must keep answering from its own rows and must not
    /// acquire an upstream branch -- the no-regression control for the Remote
    /// change above.
    #[tokio::test]
    async fn test_local_version_list_is_unchanged_by_the_remote_branch_3365() {
        let Some(f) = tdh::Fixture::setup("local", "ansible").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "hosted-collection-storage-key",
            "testns-testcoll-1.0.0.tar.gz",
            "testns-testcoll",
            "1.0.0",
            "application/gzip",
            bytes::Bytes::from_static(b"collection-bytes"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/v3/collections/testns/testcoll/versions/",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        let versions: Vec<&str> = doc["data"]
            .as_array()
            .expect("data array")
            .iter()
            .filter_map(|v| v["version"].as_str())
            .collect();
        assert_eq!(versions, vec!["1.0.0"]);
    }
    /// #3365: a Remote repository must answer the collection DETAIL route, not
    /// just the version list.
    ///
    /// A 404 here does not merely omit a detail page -- when the client has a
    /// response cache configured (which it does whenever the server is declared
    /// under `[galaxy_server.*]` in `ansible.cfg`, the ordinary enterprise
    /// setup) `get_collection_versions` reads this route first for the
    /// collection's `updated_at`, and treats a 404 as "no collection found" by
    /// `return []`. The complete version list served by the route next door is
    /// then discarded and the install fails exactly as it did before.
    #[tokio::test]
    async fn test_remote_collection_info_serves_upstream_metadata_3365() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "ansible").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/collections/testns/testcoll/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                serde_json::json!({
                    // Upstream-namespaced links, so a forwarded document is
                    // distinguishable from a rewritten one.
                    "href": "/api/content/published/v3/plugin/ansible/content/published/collections/index/testns/testcoll/",
                    "versions_url": "/api/content/published/v3/plugin/.../versions/",
                    "namespace": "testns",
                    "name": "testcoll",
                    "deprecated": false,
                    "highest_version": { "version": "2.2.2", "href": "/api/content/published/v3/plugin/.../versions/2.2.2/" },
                    "created_at": "2023-05-08T20:27:28.415377Z",
                    "updated_at": "2026-07-13T02:34:05.009743Z",
                })
                .to_string(),
            ))
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/v3/collections/testns/testcoll/",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "a Remote repository must answer the collection detail route; a 404 \
             makes a cache-enabled client discard the whole version list (#3365); \
             body: {}",
            String::from_utf8_lossy(&body)
        );
        let doc: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(
            doc["updated_at"], "2026-07-13T02:34:05.009743Z",
            "the client reads `updated_at` as its response-cache key"
        );
        assert_eq!(doc["highest_version"]["version"], "2.2.2");
        // Every advertised link must be this repository's, not the upstream's.
        for pointer in ["/href", "/versions_url", "/highest_version/href"] {
            let link = doc.pointer(pointer).and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                link.starts_with(&format!("/ansible/{}/", f.repo_key)),
                "{pointer} must be rewritten to this repository's route, got {link:?}"
            );
        }
    }

    #[test]
    fn test_rewrite_upstream_collection_info_drops_an_unaddressable_highest_version_3365() {
        let upstream = serde_json::json!({
            "highest_version": { "version": "../../../../etc/passwd" },
        });
        let doc = rewrite_upstream_collection_info("gx", "testns", "testcoll", &upstream);
        assert_eq!(
            doc["highest_version"]["version"], "",
            "an unaddressable version must not be advertised: {doc}"
        );
        assert!(
            !doc["highest_version"]["href"]
                .as_str()
                .unwrap()
                .contains(".."),
            "and must not reach the href either: {doc}"
        );
    }
}
