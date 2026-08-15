//! HuggingFace Hub API handlers.
//!
//! Implements endpoints for HuggingFace-style model hosting and retrieval.
//!
//! Routes are mounted at `/huggingface/{repo_key}/...`:
//!   GET  /huggingface/{repo_key}/api/models                                   - List models
//!   GET  /huggingface/{repo_key}/api/models/{model_id}                        - Model info
//!   GET  /huggingface/{repo_key}/{model_id}/resolve/{revision}/{filename}     - Download file
//!   POST /huggingface/{repo_key}/api/models/{model_id}/upload/{revision}      - Upload file
//!   GET  /huggingface/{repo_key}/api/models/{model_id}/tree/{revision}        - List files
//!
//! `{model_id}` above is written as a single placeholder, but real Hugging
//! Face model IDs are almost always namespaced (`org/name`, e.g.
//! `sentence-transformers/all-MiniLM-L6-v2`). Axum's `:param` segments cannot
//! contain a literal `/`, so every route that carries a model ID is
//! registered twice: once with a single `:model_id` segment (bare IDs like
//! `gpt2`) and once with `:namespace/:name` (two segments, rejoined into
//! `"namespace/name"` inside the handler). See `router()` below.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_TYPE, ETAG};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::services::proxy_service::UPSTREAM_COMMIT_HEADER;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum model ID length. The `name` column in the artifacts table is
/// VARCHAR(512). HuggingFace model IDs follow the pattern `org/model-name`,
/// so 255 characters provides ample room while preventing DB constraint
/// violations with a clear error message.
const MAX_MODEL_ID_LEN: usize = 255;

/// Maximum revision length. The `version` column is VARCHAR(255).
const MAX_REVISION_LEN: usize = 255;

/// Maximum artifact path length. The `path` and `storage_key` columns are
/// VARCHAR(2048). The storage key adds a `huggingface/` prefix (12 chars),
/// so the artifact path must stay within 2036 to keep the storage key under
/// the column limit.
const MAX_PATH_LEN: usize = 2036;

/// Total deadline for the best-effort model-info fallback in
/// [`fetch_upstream_commit_sha`] (#2915).
///
/// The shared upstream client sets only `connect_timeout` and a per-frame
/// `read_timeout` (see `services::http_client`), so a model-info endpoint that
/// trickles bytes has no *total* bound and can stall a file download far longer
/// than the download itself would take. This fallback exists purely to recover
/// a metadata header, so it gets its own hard ceiling and gives up quietly
/// rather than holding the client's file response hostage.
const COMMIT_SHA_FALLBACK_TIMEOUT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Read-path input validation
// ---------------------------------------------------------------------------

/// Validate a `model_id` (and optionally a `revision`) taken from a request
/// path, on **every** route rather than only on upload (#2915).
///
/// The length ceilings are database-shaped: `artifacts.name` is VARCHAR(512)
/// and `artifacts.version` is VARCHAR(255), so an over-long value on a write
/// would fail with an opaque constraint error, and on a read it is simply a
/// value no stored row can ever match. Rejecting both at the boundary keeps the
/// error message the same on every route.
///
/// The `..` and NUL rejections mirror `npm::validate_package_name`: axum has
/// already percent-decoded these captures exactly once by the time a handler
/// sees them, so `%2e%2e` (from a doubly-encoded `%252e%252e`) arrives decoded
/// and a substring test on the decoded value is the check that actually bites.
/// Substrings like `foo..bar` are rejected too — Hugging Face model IDs and git
/// ref names do not contain `..` (git explicitly forbids it in ref names), so
/// there is no legitimate value to lose.
///
/// The `filename` capture is deliberately not checked here: it is a `*filename`
/// wildcard whose only use is the exact-match local lookup and the upstream
/// path, and the latter is validated where the proxy-cache key is derived (see
/// [`proxy_model_info`]).
#[allow(clippy::result_large_err)]
fn validate_model_coordinates(model_id: &str, revision: Option<&str>) -> Result<(), Response> {
    validate_path_component("Model ID", model_id, MAX_MODEL_ID_LEN)?;
    if let Some(revision) = revision {
        validate_path_component("Revision", revision, MAX_REVISION_LEN)?;
    }
    Ok(())
}

/// Shared body of [`validate_model_coordinates`], applied once per captured
/// component so both carry identical rules and identical error wording.
#[allow(clippy::result_large_err)]
fn validate_path_component(label: &str, value: &str, max_len: usize) -> Result<(), Response> {
    if value.is_empty() {
        return Err((StatusCode::BAD_REQUEST, format!("{label} cannot be empty")).into_response());
    }
    if value.len() > max_len {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{} exceeds maximum length of {} characters (got {})",
                label,
                max_len,
                value.len()
            ),
        )
            .into_response());
    }
    if value.contains('\0') {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{label} contains null bytes"),
        )
            .into_response());
    }
    if value.contains("..") {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{label} contains path traversal"),
        )
            .into_response());
    }
    Ok(())
}

/// Percent-encode a decoded revision so it occupies exactly one segment of an
/// upstream Hugging Face path (#2915).
///
/// `hf download --revision refs/pr/1` puts `resolve/refs%2Fpr%2F1/<file>` on
/// the wire; axum decodes that capture once, so the handler holds
/// `refs/pr/1`. Concatenating the decoded value straight into
/// `{model_id}/resolve/{revision}/{filename}` produced
/// `…/resolve/refs/pr/1/config.json`, which is a shape the Hub's API does not
/// serve — the download 404'd (or worse, resolved a different file) and the
/// model-info request built the same way silently returned nothing, so
/// `X-Repo-Commit` went missing too.
///
/// Re-encoding rather than rejecting is deliberate: `refs/pr/N` and
/// `refs/convert/parquet` are ordinary Hub revisions that `huggingface_hub`
/// itself emits (`hf_hub_url` builds them with `quote(revision, safe="")`), so
/// rejecting slash-bearing revisions would drop a supported client feature to
/// fix a spelling bug. `urlencoding::encode` matches `quote(safe="")` — it
/// leaves `A-Za-z0-9-_.~` alone, so ordinary revisions (`main`, a 40-hex sha,
/// `v1.0`) pass through byte-identical and no existing cache key moves.
fn encode_upstream_revision(revision: &str) -> String {
    urlencoding::encode(revision).into_owned()
}

/// The `X-Repo-Commit` / model-info `sha` value served for a Local/hosted (or
/// Virtual local-member) Hugging Face repository (#2915).
///
/// These repositories have no git history, so there is no real commit to
/// report — but `huggingface_hub` hard-requires the header on a resolve and
/// then *names the snapshot directory after it*
/// (`<cache>/models--org--name/snapshots/<commit>/`). That makes two
/// properties load-bearing, and neither is "be a real commit":
///
///   * **Stable per `(model_id, revision)`.** `snapshot_download` takes the
///     commit from model-info and computes the snapshot directory from it, then
///     downloads each file and files it under the commit *that file's* resolve
///     reported. A value that varied per file would scatter one model across
///     several snapshot directories and the directory `snapshot_download`
///     returns would come back incomplete. Deriving it from the coordinates
///     alone — not from any file's bytes — makes every file of a revision agree
///     by construction, with no extra query.
///   * **40 lowercase hex characters.** `huggingface_hub` matches candidate
///     commit hashes against `^[0-9a-f]{40}$` before it will treat a revision
///     as already-resolved, so a 64-character digest silently disables that
///     fast path.
///
/// Per-file content identity is carried by the ETag instead (the artifact's
/// `checksum_sha256`), which is what `huggingface_hub` keys its blob store on —
/// so re-uploading a file at the same revision still invalidates the client's
/// copy even though this value does not move.
fn local_repo_commit_sha(model_id: &str, revision: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(model_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(revision.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    digest[..40].to_string()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // List models
        .route("/:repo_key/api/models", get(list_models))
        // Model info: bare model id (e.g. "gpt2")
        .route("/:repo_key/api/models/:model_id", get(model_info))
        // Model info: namespaced model id (e.g. "org/name")
        .route(
            "/:repo_key/api/models/:namespace/:name",
            get(model_info_namespaced),
        )
        // Model info at a specific revision: bare model id. `huggingface_hub`
        // requests this variant whenever a revision is known (the CLI/
        // `snapshot_download` default is "main"), so without this route the
        // client 404s before it ever reaches `download_file`.
        .route(
            "/:repo_key/api/models/:model_id/revision/:revision",
            get(model_info_revision),
        )
        // Model info at a specific revision: namespaced model id.
        .route(
            "/:repo_key/api/models/:namespace/:name/revision/:revision",
            get(model_info_revision_namespaced),
        )
        // Upload file to model: bare model id
        .route(
            "/:repo_key/api/models/:model_id/upload/:revision",
            post(upload_file),
        )
        // Upload file to model: namespaced model id
        .route(
            "/:repo_key/api/models/:namespace/:name/upload/:revision",
            post(upload_file_namespaced),
        )
        // List files in model (tree): bare model id
        .route(
            "/:repo_key/api/models/:model_id/tree/:revision",
            get(list_files),
        )
        // List files in model (tree): namespaced model id
        .route(
            "/:repo_key/api/models/:namespace/:name/tree/:revision",
            get(list_files_namespaced),
        )
        // Download file from model: bare model id
        .route(
            "/:repo_key/:model_id/resolve/:revision/*filename",
            get(download_file),
        )
        // Download file from model: namespaced model id
        .route(
            "/:repo_key/:namespace/:name/resolve/:revision/*filename",
            get(download_file_namespaced),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_huggingface_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["huggingface"], "a Hugging Face").await
}

/// Extract a filename from request headers.
///
/// Prefers the `X-Filename` header; falls back to `Content-Disposition`
/// (parsing the `filename=` parameter, stripping surrounding quotes); if
/// neither is present, returns `"uploaded_file"`.
fn filename_from_headers(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-filename")
        .or(headers.get("content-disposition"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            if v.contains("filename=") {
                v.split("filename=")
                    .nth(1)
                    .map(|f| f.trim_matches('"').to_string())
            } else {
                Some(v.to_string())
            }
        })
        .unwrap_or_else(|| "uploaded_file".to_string())
}

// ---------------------------------------------------------------------------
// GET /huggingface/{repo_key}/api/models — List models
// ---------------------------------------------------------------------------

async fn list_models(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT ON (LOWER(name)) name, version,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY LOWER(name), a.created_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    let models: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let model_id = a.name.clone();
            let pipeline_tag = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("pipeline_tag"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            serde_json::json!({
                "modelId": model_id,
                "lastModified": a.version.clone().unwrap_or_default(),
                "pipeline_tag": pipeline_tag,
                "tags": [],
            })
        })
        .collect();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&models).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /huggingface/{repo_key}/api/models/{model_id} — Model info
// ---------------------------------------------------------------------------

async fn model_info(
    State(state): State<SharedState>,
    Path((repo_key, model_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    model_info_impl(state, repo_key, model_id, None).await
}

async fn model_info_namespaced(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    model_info_impl(state, repo_key, format!("{namespace}/{name}"), None).await
}

async fn model_info_revision(
    State(state): State<SharedState>,
    Path((repo_key, model_id, revision)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    model_info_impl(state, repo_key, model_id, Some(revision)).await
}

async fn model_info_revision_namespaced(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, revision)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    model_info_impl(
        state,
        repo_key,
        format!("{namespace}/{name}"),
        Some(revision),
    )
    .await
}

async fn model_info_impl(
    state: SharedState,
    repo_key: String,
    model_id: String,
    revision: Option<String>,
) -> Result<Response, Response> {
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;
    validate_model_coordinates(&model_id, revision.as_deref())?;

    let artifact =
        proxy_helpers::find_artifact_by_name_lowercase(&state.db, repo.id, &model_id).await?;

    // Not cached locally: for a Remote repo, proxy the upstream Hugging Face
    // model-info JSON instead of 404ing immediately. This mirrors the
    // pull-through `download_file_impl` already does for file downloads
    // (via `try_remote_or_virtual_download`) - without it, `hf download`
    // never gets past the initial file-listing call for any model that
    // hasn't already been cached by a prior download.
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if let Some(resp) =
                proxy_model_info(&state, &repo, &model_id, revision.as_deref()).await?
            {
                return Ok(resp);
            }
            return Err((StatusCode::NOT_FOUND, "Model not found").into_response());
        }
    };

    let siblings = sqlx::query!(
        r#"
        SELECT path, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
        ORDER BY path
        "#,
        repo.id,
        model_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    let files: Vec<serde_json::Value> = siblings
        .iter()
        .map(|s| {
            serde_json::json!({
                "rfilename": s.path,
                "size": s.size_bytes,
            })
        })
        .collect();

    let pipeline_tag = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("pipeline_tag"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // `sha` must be the SAME value the resolve route reports in
    // `X-Repo-Commit` for this `(model_id, revision)`, or `snapshot_download`
    // computes its snapshot directory from one value and files the downloaded
    // blobs under the other (#2915 - see `local_repo_commit_sha`). It used to
    // be this artifact's `checksum_sha256`, which is per-FILE and 64 hex
    // characters: it disagreed with every sibling in the same revision and was
    // never a commit identifier in the first place. Per-file content identity
    // is still exposed - as the resolve ETag, where `huggingface_hub` looks for
    // it.
    let commit_revision = revision
        .as_deref()
        .or(artifact.version.as_deref())
        .unwrap_or("main");
    let json = serde_json::json!({
        "modelId": model_id,
        "sha": local_repo_commit_sha(&model_id, commit_revision),
        "lastModified": artifact.version.clone().unwrap_or_default(),
        "pipeline_tag": pipeline_tag,
        "tags": [],
        "siblings": files,
    });

    Ok(super::json_response(&json))
}

/// Proxy the upstream Hugging Face model-info JSON for a Remote repo.
///
/// Returns `Ok(None)` when the repo isn't a Remote repo (or has no
/// `upstream_url`/proxy service wired up), so the caller falls through to its
/// existing 404. Returns `Err` for a genuine upstream failure (404, 5xx,
/// path-traversal rejection, ...) via `proxy_helpers::proxy_fetch_capped` -
/// never a silently-empty 200.
///
/// The upstream path mirrors the real `huggingface_hub` client request:
/// `api/models/{model_id}` with no revision, or
/// `api/models/{model_id}/revision/{revision}` when one is given, with the
/// revision put back into its single-segment wire spelling by
/// [`encode_upstream_revision`].
///
/// Two independent things check that path for traversal, and it is worth being
/// precise about which is which because only the first belongs to this module:
///
///   * The caller has already run [`validate_model_coordinates`] on `model_id`
///     and `revision`, which rejects `..` and NUL in the *decoded* values that
///     reach the handler. That is this file's own guarantee and the one the
///     read-path tests pin.
///   * `proxy_fetch_capped` then derives a proxy-cache key from the assembled
///     path, and that derivation validates it inside `ProxyService`
///     (`validate_cache_path`: empty/NUL/backslash/dot segments, including the
///     percent-encoded dot spellings `%2e`, `.%2e`, `%2e.` and `%2e%2e` that the
///     `url` crate folds back into dot segments when it parses the fetch URL).
///
/// An earlier version of this comment claimed the second check alone made a
/// local guard unnecessary. That was wrong at the time: the validator then
/// compared segments against `..` literally, and axum decodes a captured
/// parameter exactly once, so a request spelled `%252e%252e` arrived here as the
/// literal `%2e%2e`, passed the comparison, and was only collapsed into a dot
/// segment later by the URL parser. The validator has since been hardened to
/// reject the encoded spellings as well, but it lives in another module and can
/// change without this one, so it is relied on here as defence in depth rather
/// than as the guarantee.
async fn proxy_model_info(
    state: &SharedState,
    repo: &RepoInfo,
    model_id: &str,
    revision: Option<&str>,
) -> Result<Option<Response>, Response> {
    let upstream_path = match revision {
        Some(rev) => format!(
            "api/models/{model_id}/revision/{}",
            encode_upstream_revision(rev)
        ),
        None => format!("api/models/{model_id}"),
    };
    proxy_hf_metadata_json(state, repo, &upstream_path).await
}

/// Proxy the upstream Hugging Face file-tree JSON for a Remote repo (#2915).
///
/// `list_files_impl` answers from the local `artifacts` table, and a Remote
/// repository intentionally keeps no `artifacts` rows for proxied content
/// (#1278) - so its prefix query matched nothing and the endpoint returned `[]`
/// with 200 for every uncached model. That is the same fail-open this PR removed
/// from `model_info`, left standing on the sibling endpoint: a client cannot
/// tell "this revision has no files" from "this backend never asked upstream".
///
/// Same contract as [`proxy_model_info`]: `Ok(None)` for a non-Remote repo so
/// the caller keeps its existing behaviour, `Err` for a real upstream failure.
///
/// Only the first page is proxied. The Hub paginates large trees with a `Link:
/// rel="next"` header, which `proxy_fetch_capped` does not follow, so a model
/// with more entries than one page holds is reported short here. `hf download`
/// does not use this endpoint (it lists files from model-info `siblings`), so
/// that limitation is not on the download path.
async fn proxy_model_tree(
    state: &SharedState,
    repo: &RepoInfo,
    model_id: &str,
    revision: &str,
) -> Result<Option<Response>, Response> {
    let upstream_path = format!(
        "api/models/{model_id}/tree/{}",
        encode_upstream_revision(revision)
    );
    proxy_hf_metadata_json(state, repo, &upstream_path).await
}

/// Object keys removed from proxied Hugging Face metadata documents (#3334).
///
/// `xetHash` is per-file and appears on tree entries and model-info siblings;
/// `xetEnabled` is the repo-level flag on model-info.
const XET_METADATA_KEYS: [&str; 2] = ["xetHash", "xetEnabled"];

/// Recursively drop [`XET_METADATA_KEYS`] from every object in `value`.
///
/// Tree responses are arrays of entries, model-info is an object with a
/// `siblings` array, and `tree?expand=true` nests further still, so the walk
/// has to cover objects and arrays at any depth rather than the two shapes
/// known today.
fn remove_xet_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|key, _| !XET_METADATA_KEYS.contains(&key.as_str()));
            for nested in map.values_mut() {
                remove_xet_keys(nested);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                remove_xet_keys(item);
            }
        }
        _ => {}
    }
}

/// Strip Xet fields from an upstream metadata document so clients keep using
/// the ordinary `/resolve/` download path (#3334).
///
/// `huggingface_hub >= 1.26` caches the tree listing on disk, reads `xetHash`
/// back out of that cache, and from then on skips the HEAD call and asks for a
/// Xet read token at `api/models/{id}/xet-read-token/{rev}` - a route this
/// proxy does not implement, so the download dies on a bare 404.
///
/// Stripping the `X-Xet-Hash` response header would not help: `ProxyService`
/// already drops it, and on this path the client never reads response headers.
/// The leak is in the JSON body, which is why the fix lives here.
///
/// Proxying `xet-read-token` was considered and rejected. Once a client holds a
/// Xet token it pulls chunks straight from `cas-server.xethub.hf.co`, bypassing
/// the proxy entirely: no caching, and every client needs direct egress, which
/// is the opposite of what an air-gapped or controlled-egress deployment
/// installs a proxy for.
///
/// Bytes that do not parse as JSON come back untouched. A metadata passthrough
/// that works today must not start failing because of this filter.
fn strip_xet_metadata(bytes: Bytes) -> Bytes {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return bytes;
    };
    remove_xet_keys(&mut value);
    match serde_json::to_vec(&value) {
        Ok(rewritten) => Bytes::from(rewritten),
        Err(_) => bytes,
    }
}

/// Shared body of [`proxy_model_info`] and [`proxy_model_tree`]: fetch a
/// buffered JSON metadata document from a Remote repo's upstream and hand it
/// back with Xet fields removed by [`strip_xet_metadata`].
///
/// Keeping the Remote/upstream/proxy-wired guards and the capped fetch in one
/// place is what makes the two endpoints propagate upstream failures
/// identically - the fail-open the tree endpoint had was precisely a matter of
/// its not sharing this code.
async fn proxy_hf_metadata_json(
    state: &SharedState,
    repo: &RepoInfo,
    upstream_path: &str,
) -> Result<Option<Response>, Response> {
    if proxy_helpers::classify_remote_or_virtual(&repo.repo_type)
        != proxy_helpers::RemoteOrVirtualAction::Remote
    {
        return Ok(None);
    }
    let Some(upstream_url) = repo.upstream_url.as_deref() else {
        return Ok(None);
    };
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Ok(None);
    };

    let (bytes, _content_type) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;

    Ok(Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(strip_xet_metadata(bytes)))
            .unwrap(),
    ))
}

/// Last-resort recovery of upstream's commit sha for `(model_id, revision)`,
/// read out of the model-info document's `"sha"` field.
///
/// **This is a fallback, and only a fallback.** `ProxyService` now captures
/// upstream's own `X-Repo-Commit` response header, stores it in the cache
/// sidecar next to the bytes it describes, and replays it on cache hits and
/// stale-if-error serves; `build_streaming_response_with_disposition` emits it.
/// So the ordinary Remote resolve already carries the header, bound to the exact
/// bytes being served, and [`ensure_resolve_metadata_headers`] calls this
/// function *only* when that header is absent.
///
/// Why it is still worth keeping (#2915): the Hub serves LFS objects as a 302 to
/// its CDN and puts `X-Repo-Commit` (and `X-Linked-Etag`) on the *redirect*,
/// while the shared reqwest client follows redirects itself and only exposes the
/// final hop's headers. Model weights are exactly the files that take that path,
/// so dropping this fallback would leave `hf download` without a commit header
/// on the one file type it most needs one for. The genuinely correct fix is to
/// capture the header from the intermediate hop in `ProxyService`; until that
/// exists, this recovers the value from a document the Hub serves without a
/// redirect.
///
/// It is deliberately weaker than the forwarded header and must never be
/// preferred to it: model-info is a *separate* observation of a mutable ref, so
/// if `main` advances between the two calls this reports a commit that does not
/// contain the bytes just served - and `huggingface_hub` would then file those
/// bytes under the wrong snapshot directory.
///
/// Returns `None` when the repo isn't Remote, has no upstream/proxy wired up, or
/// the fetch fails, times out, or doesn't parse. Never propagates an error:
/// losing a metadata header degrades `hf download` to its
/// no-header path, whereas failing the request loses the file.
async fn fetch_upstream_commit_sha(
    state: &SharedState,
    repo: &RepoInfo,
    model_id: &str,
    revision: &str,
) -> Option<String> {
    if proxy_helpers::classify_remote_or_virtual(&repo.repo_type)
        != proxy_helpers::RemoteOrVirtualAction::Remote
    {
        return None;
    }
    let upstream_url = repo.upstream_url.as_deref()?;
    let proxy = state.proxy_service.as_deref()?;

    let upstream_path = format!(
        "api/models/{model_id}/revision/{}",
        encode_upstream_revision(revision)
    );
    let fetch = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    );

    // Own deadline, not the shared client's: see `COMMIT_SHA_FALLBACK_TIMEOUT`.
    let bytes = match tokio::time::timeout(COMMIT_SHA_FALLBACK_TIMEOUT, fetch).await {
        Ok(Ok((bytes, _content_type))) => bytes,
        Ok(Err(_response)) => {
            tracing::debug!(
                repo_key = %repo.key,
                model_id,
                revision,
                "upstream model-info lookup failed; serving the file without X-Repo-Commit"
            );
            return None;
        }
        Err(_elapsed) => {
            tracing::warn!(
                repo_key = %repo.key,
                model_id,
                revision,
                timeout_secs = COMMIT_SHA_FALLBACK_TIMEOUT.as_secs(),
                "upstream model-info lookup exceeded its deadline; serving the file \
                 without X-Repo-Commit"
            );
            return None;
        }
    };

    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("sha")?.as_str().map(str::to_string)
}

/// Give a resolve response the two headers `huggingface_hub`'s HEAD-based
/// metadata probe refuses to work without - an ETag and `X-Repo-Commit` - when
/// the arm that produced it did not already supply them (#2915).
///
/// Both are only *added*, never overwritten, so anything the upstream (or an
/// upstream-backed cache entry) already said wins. What "missing" means differs
/// per repository type:
///
///   * **Remote.** The bytes are upstream's, so an ETag is upstream's to state
///     and is never synthesized here - inventing one would let a client cache a
///     proxied object under an identity this backend made up. Only the commit is
///     recoverable, via [`fetch_upstream_commit_sha`].
///   * **Virtual.** A Remote member's serve already carries both. A *local*
///     member's serve comes back with neither, because it is assembled from
///     stored bytes rather than an HTTP response - so it gets the local
///     treatment below, keyed on the member row that actually won the
///     member-priority race.
///   * **Hosted.** Handled by the caller directly (it already holds the
///     artifact row), not through this function.
async fn ensure_resolve_metadata_headers(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    model_id: &str,
    revision: &str,
    artifact_path: &str,
    resp: &mut Response,
) {
    let needs_commit = !resp.headers().contains_key(UPSTREAM_COMMIT_HEADER);
    let needs_etag = !resp.headers().contains_key(ETAG);
    if !needs_commit && !needs_etag {
        return;
    }

    if proxy_helpers::classify_remote_or_virtual(&repo.repo_type)
        == proxy_helpers::RemoteOrVirtualAction::Remote
    {
        if needs_commit {
            if let Some(sha) = fetch_upstream_commit_sha(state, repo, model_id, revision).await {
                insert_header_if_valid(resp, UPSTREAM_COMMIT_HEADER, &sha);
            }
        }
        return;
    }

    // Virtual: only a local member's bytes get local metadata. If no local
    // member owns this path the serve came from a Remote member, and whatever
    // that member's upstream said (possibly nothing) is the honest answer.
    let Some(checksum) = virtual_member_checksum(&state.db, auth, repo.id, artifact_path).await
    else {
        return;
    };
    apply_local_metadata_headers(resp, Some(&checksum), model_id, revision);
}

/// Set the ETag and `X-Repo-Commit` for bytes this instance stores itself
/// (a hosted artifact, or a Virtual repo's local-member artifact).
///
/// The ETag is the artifact's stored `checksum_sha256`, quoted as RFC 9110
/// requires - `huggingface_hub` names its local blob file after this value, so a
/// content hash is exactly the right identity and an unquoted one would be an
/// invalid entity-tag. `X-Repo-Commit` comes from [`local_repo_commit_sha`].
///
/// The checksum is trimmed first: `artifacts.checksum_sha256` is `CHAR(64)`, so
/// Postgres blank-pads anything shorter than 64 characters on read and the raw
/// value would produce an entity-tag with trailing spaces inside the quotes.
/// A real SHA-256 fills the column exactly, but nothing enforces that at the
/// type level.
///
/// Neither header is overwritten if already present, and both go through
/// [`insert_header_if_valid`].
fn apply_local_metadata_headers(
    resp: &mut Response,
    checksum_sha256: Option<&str>,
    model_id: &str,
    revision: &str,
) {
    if !resp.headers().contains_key(ETAG) {
        if let Some(checksum) = checksum_sha256.map(str::trim).filter(|c| !c.is_empty()) {
            insert_header_if_valid(resp, ETAG.as_str(), &format!("\"{checksum}\""));
        }
    }
    if !resp.headers().contains_key(UPSTREAM_COMMIT_HEADER) {
        insert_header_if_valid(
            resp,
            UPSTREAM_COMMIT_HEADER,
            &local_repo_commit_sha(model_id, revision),
        );
    }
}

/// Insert `name: value` on `resp`, dropping the header if `value` cannot be a
/// header value at all.
///
/// Every value routed through here is derived from data (a stored checksum, an
/// upstream JSON field), so `HeaderValue::from_str` is checked rather than
/// unwrapped: its rejection of CR/LF is what stops an upstream `"sha"` from
/// splicing extra headers into our response, and a value we cannot represent is
/// worth losing a metadata header over, not the download.
fn insert_header_if_valid(resp: &mut Response, name: &str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        if let Ok(name) = axum::http::HeaderName::from_bytes(name.as_bytes()) {
            resp.headers_mut().insert(name, value);
        }
    }
}

/// `checksum_sha256` of the artifact a Virtual repository's local member served
/// for `artifact_path`, or `None` when no local member owns it.
///
/// Resolves the same row `resolve_virtual_download` finalizes on - first
/// non-Remote member by `virtual_repo_members.priority` holding a live artifact
/// at the exact path - so the ETag describes the bytes that were actually sent.
/// Mirrors `proxy_helpers::virtual_local_winner_artifact_id`, which re-derives
/// the same row for download attribution.
///
/// Best-effort like that helper: a database error logs and yields `None` so the
/// download proceeds without the header.
async fn virtual_member_checksum(
    db: &PgPool,
    auth: Option<&AuthExtension>,
    virtual_repo_id: uuid::Uuid,
    artifact_path: &str,
) -> Option<String> {
    // Caller-authorized member set (#3323). The bytes are resolved through the
    // authorized `resolve_virtual_download`, but this header query re-derived
    // the winner from an UNFILTERED member walk — so a caller served from
    // public member B could receive private member A's `checksum_sha256`. That
    // is both a metadata oracle and a plain correctness bug: the ETag then
    // describes bytes that were not sent. Constraining the query to the same
    // member set the download used makes the two agree by construction.
    let member_ids: Vec<uuid::Uuid> =
        match proxy_helpers::authorized_virtual_members(db, auth, virtual_repo_id).await {
            Ok(members) => members.into_iter().map(|m| m.id).collect(),
            Err(_) => return None,
        };
    match sqlx::query_scalar::<_, Option<String>>(
        "SELECT a.checksum_sha256 FROM artifacts a \
         JOIN virtual_repo_members vrm ON vrm.member_repo_id = a.repository_id \
         JOIN repositories r ON r.id = a.repository_id \
         WHERE vrm.virtual_repo_id = $1 \
           AND a.repository_id = ANY($3) \
           AND r.repo_type != 'remote' \
           AND a.path = $2 \
           AND a.is_deleted = false \
         ORDER BY vrm.priority \
         LIMIT 1",
    )
    .bind(virtual_repo_id)
    .bind(artifact_path)
    .bind(&member_ids)
    .fetch_optional(db)
    .await
    {
        Ok(checksum) => checksum.flatten(),
        Err(e) => {
            tracing::warn!(
                %virtual_repo_id,
                artifact_path,
                error = %e,
                "failed to resolve virtual member checksum; serving without an ETag"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// GET /huggingface/{repo_key}/{model_id}/resolve/{revision}/{filename} — Download file
// ---------------------------------------------------------------------------

async fn download_file(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, model_id, revision, filename)): Path<(String, String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    download_file_impl(state, auth, repo_key, model_id, revision, filename, ctx).await
}

async fn download_file_namespaced(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, name, revision, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    download_file_impl(
        state,
        auth,
        repo_key,
        format!("{namespace}/{name}"),
        revision,
        filename,
        ctx,
    )
    .await
}

async fn download_file_impl(
    state: SharedState,
    auth: Option<crate::api::middleware::auth::AuthExtension>,
    repo_key: String,
    model_id: String,
    revision: String,
    filename: String,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;
    validate_model_coordinates(&model_id, Some(&revision))?;

    let filename = filename.trim_start_matches('/');
    let artifact_path = format!("{}/{}/{}", model_id, revision, filename);

    // Runtime query rather than `sqlx::query!` so `checksum_sha256` can be read
    // alongside the storage key in a single round trip; this is the same
    // runtime-query + `try_get` shape
    // `proxy_helpers::find_artifact_by_name_lowercase` uses. The checksum feeds
    // the resolve ETag below (#2915).
    use sqlx::Row;
    let artifact = sqlx::query(
        "SELECT id, storage_key, checksum_sha256 FROM artifacts \
         WHERE repository_id = $1 \
           AND is_deleted = false \
           AND path = $2 \
         LIMIT 1",
    )
    .bind(repo.id)
    .bind(&artifact_path)
    .fetch_optional(&state.db)
    .await
    .map_err(super::db_err)?;

    let Some(artifact) = artifact else {
        // The revision is re-encoded here: axum handed us the decoded value, and
        // the Hub expects it as one segment (`refs%2Fpr%2F1`). See
        // `encode_upstream_revision`.
        let upstream_path = format!(
            "{}/resolve/{}/{}",
            model_id,
            encode_upstream_revision(&revision),
            filename
        );
        if let Some(mut resp) = proxy_helpers::try_remote_or_virtual_download(
            &state,
            auth.as_ref(),
            &repo,
            &ctx,
            proxy_helpers::DownloadResponseOpts {
                upstream_path: &upstream_path,
                virtual_lookup: proxy_helpers::VirtualLookup::ExactPath(&artifact_path),
                default_content_type: "application/octet-stream",
                content_disposition_filename: None,
                suppress_upstream_proxy: false,
            },
        )
        .await?
        {
            // Remote serves normally arrive with upstream's own ETag and
            // `X-Repo-Commit` already forwarded by the streaming response
            // builder; Virtual local-member serves arrive with neither. This
            // fills only what is actually missing - and, for Remote, only after
            // the file response exists, so the fallback round trip can be skipped
            // entirely whenever the header came through.
            ensure_resolve_metadata_headers(
                &state,
                auth.as_ref(),
                &repo,
                &model_id,
                &revision,
                &artifact_path,
                &mut resp,
            )
            .await;
            return Ok(resp);
        }
        return Err((StatusCode::NOT_FOUND, "File not found").into_response());
    };

    let artifact_id: uuid::Uuid = artifact.try_get("id").map_err(super::db_err)?;
    let storage_key: String = artifact.try_get("storage_key").map_err(super::db_err)?;
    let checksum: Option<String> = artifact
        .try_get::<Option<String>, _>("checksum_sha256")
        .ok()
        .flatten();

    let mut resp = proxy_helpers::serve_local_artifact(
        &state,
        &repo,
        artifact_id,
        &storage_key,
        "application/octet-stream",
        Some(filename),
        &ctx,
    )
    .await?;

    // A hosted serve is built by `proxy_helpers::build_download_response`, which
    // emits only Content-Type/Content-Length/Content-Disposition - so `hf
    // download` against a Local or hosted HF repo failed its HEAD metadata probe
    // outright, on content this instance owns. Adding the two headers here
    // rather than in `build_download_response` keeps the HF-specific commit
    // semantics out of the shared, format-agnostic builder (#2915).
    apply_local_metadata_headers(&mut resp, checksum.as_deref(), &model_id, &revision);
    Ok(resp)
}

// ---------------------------------------------------------------------------
// POST /huggingface/{repo_key}/api/models/{model_id}/upload/{revision} — Upload file
// ---------------------------------------------------------------------------

async fn upload_file(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, model_id, revision)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    upload_file_impl(state, auth, repo_key, model_id, revision, headers, body).await
}

async fn upload_file_namespaced(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, name, revision)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    upload_file_impl(
        state,
        auth,
        repo_key,
        format!("{namespace}/{name}"),
        revision,
        headers,
        body,
    )
    .await
}

async fn upload_file_impl(
    state: SharedState,
    auth: Option<AuthExtension>,
    repo_key: String,
    model_id: String,
    revision: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "huggingface", "write:artifacts")?.user_id;
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty file body").into_response());
    }

    // Length ceilings (`name` is VARCHAR(512), `version` is VARCHAR(255)) plus
    // the traversal/NUL rejections, from the one helper the read paths also use
    // so upload and download can never diverge on what they accept (#2915).
    validate_model_coordinates(&model_id, Some(&revision))?;

    // Extract filename from X-Filename or Content-Disposition header.
    let filename = filename_from_headers(&headers);

    let artifact_path = format!("{}/{}/{}", model_id, revision, filename);

    // Validate total path length: the `path` database column is VARCHAR(2048)
    if artifact_path.len() > MAX_PATH_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Artifact path exceeds maximum length of {} characters (got {}). \
                 Use a shorter model ID, revision, or filename.",
                MAX_PATH_LEN,
                artifact_path.len()
            ),
        )
            .into_response());
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "File already exists at this path",
    )
    .await?;

    let storage_key = format!("huggingface/{}/{}/{}", model_id, revision, filename);
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, body.clone()).await?;

    let size_bytes = body.len() as i64;

    let metadata = serde_json::json!({
        "model_id": model_id,
        "revision": revision,
        "filename": filename,
    });

    // Insert artifact record
    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &model_id,
            version: &revision,
            size_bytes,
            checksum_sha256: &computed_sha256,
            content_type: "application/octet-stream",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    // Store metadata
    proxy_helpers::record_artifact_metadata(
        &state.db,
        artifact_id,
        repo.id,
        "huggingface",
        &metadata,
    )
    .await;

    info!(
        "HuggingFace upload: {}/{}/{} to repo {}",
        model_id, revision, filename, repo_key
    );

    let response = serde_json::json!({
        "message": "File uploaded successfully",
        "path": artifact_path,
        "sha256": computed_sha256,
        "size": size_bytes,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /huggingface/{repo_key}/api/models/{model_id}/tree/{revision} — List files
// ---------------------------------------------------------------------------

async fn list_files(
    State(state): State<SharedState>,
    Path((repo_key, model_id, revision)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    list_files_impl(state, repo_key, model_id, revision).await
}

async fn list_files_namespaced(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, revision)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    list_files_impl(state, repo_key, format!("{namespace}/{name}"), revision).await
}

async fn list_files_impl(
    state: SharedState,
    repo_key: String,
    model_id: String,
    revision: String,
) -> Result<Response, Response> {
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;
    validate_model_coordinates(&model_id, Some(&revision))?;

    // Two prefixes, deliberately: the LIKE pattern is escaped so `%`/`_`/`\` in
    // a model ID or revision cannot widen the match, while the prefix stripped
    // off each returned path must be the LITERAL one. Using the escaped form for
    // both meant any model ID containing `_` (`bert_base_uncased`, and plenty of
    // real Hub IDs) produced a pattern of `bert\_base_uncased/main/`, which
    // `strip_prefix` could not match - so `unwrap_or` fell through and the
    // endpoint reported every entry under its full stored path instead of the
    // path relative to the revision.
    let like_prefix = super::escape_path_prefix(&[&model_id, &revision]);
    let path_prefix = format!("{}/{}/", model_id, revision);

    let artifacts = sqlx::query!(
        r#"
        SELECT path, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE $2 || '%' ESCAPE '\'
        ORDER BY path
        "#,
        repo.id,
        like_prefix
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    // Remote pull-through. Nothing local means one of two very different things
    // for a Remote repo, and answering `[]` with 200 conflated them - see
    // `proxy_model_tree`. Gating on emptiness (rather than on repo type) keeps
    // artifacts that were promoted into a Remote repo authoritative, exactly as
    // `model_info_impl` does.
    if artifacts.is_empty() {
        if let Some(resp) = proxy_model_tree(&state, &repo, &model_id, &revision).await? {
            return Ok(resp);
        }
    }

    let files: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let relative_path = a
                .path
                .strip_prefix(&path_prefix)
                .unwrap_or(&a.path)
                .to_string();

            serde_json::json!({
                "type": "file",
                "path": relative_path,
                "size": a.size_bytes,
                "oid": a.checksum_sha256,
            })
        })
        .collect();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&files).unwrap()))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // Filename extraction from headers
    // -----------------------------------------------------------------------

    #[test]
    fn test_filename_from_x_filename_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-filename", HeaderValue::from_static("model.bin"));
        assert_eq!(filename_from_headers(&headers), "model.bin");
    }

    #[test]
    fn test_filename_from_content_disposition() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-disposition",
            HeaderValue::from_static("attachment; filename=\"weights.safetensors\""),
        );
        assert_eq!(filename_from_headers(&headers), "weights.safetensors");
    }

    #[test]
    fn test_filename_default() {
        let headers = HeaderMap::new();
        assert_eq!(filename_from_headers(&headers), "uploaded_file");
    }

    // -----------------------------------------------------------------------
    // Format-specific logic: artifact_path, storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_path_format() {
        let model_id = "bert-base-uncased";
        let revision = "main";
        let filename = "pytorch_model.bin";
        let path = format!("{}/{}/{}", model_id, revision, filename);
        assert_eq!(path, "bert-base-uncased/main/pytorch_model.bin");
    }

    #[test]
    fn test_storage_key_format() {
        let model_id = "gpt2";
        let revision = "v1.0";
        let filename = "config.json";
        let key = format!("huggingface/{}/{}/{}", model_id, revision, filename);
        assert_eq!(key, "huggingface/gpt2/v1.0/config.json");
    }

    #[test]
    fn test_upstream_path_format() {
        let model_id = "bert-base-uncased";
        let revision = "main";
        let filename = "tokenizer.json";
        let path = format!("{}/resolve/{}/{}", model_id, revision, filename);
        assert_eq!(path, "bert-base-uncased/resolve/main/tokenizer.json");
    }

    #[test]
    fn test_path_prefix_for_file_listing() {
        let model_id = "llama-2-7b";
        let revision = "main";
        let prefix = format!("{}/{}/", model_id, revision);
        assert_eq!(prefix, "llama-2-7b/main/");
    }

    #[test]
    fn test_relative_path_stripping() {
        let path_prefix = "llama-2-7b/main/";
        let full_path = "llama-2-7b/main/model-00001.safetensors";
        let relative = full_path.strip_prefix(path_prefix).unwrap_or(full_path);
        assert_eq!(relative, "model-00001.safetensors");
    }

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"model weights");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
    }

    // -----------------------------------------------------------------------
    // Metadata JSON construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_metadata_json() {
        let model_id = "gpt2";
        let revision = "main";
        let filename = "config.json";
        let meta = serde_json::json!({
            "model_id": model_id,
            "revision": revision,
            "filename": filename,
        });
        assert_eq!(meta["model_id"], "gpt2");
        assert_eq!(meta["revision"], "main");
        assert_eq!(meta["filename"], "config.json");
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
            storage_path: "/data/huggingface".to_string(),
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
            storage_path: "/cache/hf".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://huggingface.co".to_string()),
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        assert_eq!(repo.upstream_url.as_deref(), Some("https://huggingface.co"));
    }

    // -----------------------------------------------------------------------
    // Length validation constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_model_id_within_limit() {
        let model_id = "a".repeat(MAX_MODEL_ID_LEN);
        assert!(model_id.len() <= MAX_MODEL_ID_LEN);
    }

    #[test]
    fn test_model_id_exceeds_limit() {
        let model_id = "a".repeat(MAX_MODEL_ID_LEN + 1);
        assert!(model_id.len() > MAX_MODEL_ID_LEN);
    }

    #[test]
    fn test_long_model_id_path_fits_in_db() {
        // A 255-char model_id with "main" revision and a typical filename
        // should produce a path under MAX_PATH_LEN.
        let model_id = "a".repeat(MAX_MODEL_ID_LEN);
        let revision = "main";
        let filename = "model.safetensors";
        let path = format!("{}/{}/{}", model_id, revision, filename);
        assert!(
            path.len() <= MAX_PATH_LEN,
            "path length {} exceeds MAX_PATH_LEN {}",
            path.len(),
            MAX_PATH_LEN
        );
    }

    #[test]
    fn test_long_model_id_storage_key_fits_in_db() {
        // Storage key adds "huggingface/" prefix (12 chars).
        let model_id = "a".repeat(MAX_MODEL_ID_LEN);
        let revision = "main";
        let filename = "model.safetensors";
        let key = format!("huggingface/{}/{}/{}", model_id, revision, filename);
        assert!(
            key.len() <= 2048,
            "storage_key length {} exceeds VARCHAR(2048)",
            key.len()
        );
    }

    #[test]
    fn test_revision_within_limit() {
        let revision = "v".repeat(MAX_REVISION_LEN);
        assert!(revision.len() <= MAX_REVISION_LEN);
    }

    #[test]
    fn test_long_model_name_artifact_path() {
        // A model name over 100 characters should still produce valid paths.
        let model_id = "x".repeat(120);
        assert_eq!(model_id.len(), 120);
        let path = format!("{}/{}/{}", model_id, "main", "weights.safetensors");
        assert!(path.len() <= MAX_PATH_LEN);
        let key = format!(
            "huggingface/{}/{}/{}",
            model_id, "main", "weights.safetensors"
        );
        assert!(key.len() <= 2048);
    }

    // -----------------------------------------------------------------------
    // DB-backed router tests for the proxy_helpers-call paths.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    #[tokio::test]
    async fn test_huggingface_resolve_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/missing-model/resolve/main/missing.bin",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_resolve_serves_local() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "huggingface/bert-base/main/config.json",
            "bert-base/main/config.json",
            "bert-base",
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"x\":1}"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/bert-base/resolve/main/config.json",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"{\"x\":1}");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_model_info_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) =
            tdh::send(app, tdh::get(format!("/{}/api/models/missing", f.repo_key))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_upload_unauthenticated_401() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/api/models/m/upload/main", f.repo_key))
            .header("x-filename", "file.bin")
            .body(axum::body::Body::from("data"))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_upload_succeeds_for_local() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/api/models/my-model/upload/main", f.repo_key))
            .header("x-filename", "weights.bin")
            .body(axum::body::Body::from(vec![0u8; 16]))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert!(
            status == StatusCode::OK || status == StatusCode::CREATED,
            "got {}",
            status
        );
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Namespaced model id ("org/name") routing.
    //
    // Real Hugging Face model IDs are almost always namespaced (e.g.
    // "sentence-transformers/all-MiniLM-L6-v2"). Axum's single-segment
    // `:model_id` placeholder cannot match a value containing `/`, so these
    // tests exercise the `:namespace/:name` router variants added to fix
    // that 404.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_huggingface_resolve_serves_local_namespaced() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let model_id = "sentence-transformers/all-MiniLM-L6-v2";
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &format!("huggingface/{model_id}/main/config.json"),
            &format!("{model_id}/main/config.json"),
            model_id,
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"x\":1}"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/{}/resolve/main/config.json",
                f.repo_key, model_id
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"{\"x\":1}");
        f.teardown().await;
    }

    /// The namespaced resolve route must 404 through `download_file_impl`, not
    /// through axum's router fallback.
    ///
    /// This distinction is the whole point of the assertion on the body. Before
    /// the namespaced routes existed, `/{repo}/org/model/resolve/main/f.bin`
    /// matched NO route, so axum's fallback produced a bodyless 404 and a
    /// status-only assertion passed on code that had no feature at all. Pinning
    /// the handler's own error string means this test can only pass when the
    /// request actually reached `download_file_impl` (#2915).
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_resolve_404_when_missing_namespaced() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/missing-org/missing-model/resolve/main/missing.bin",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            std::str::from_utf8(&body).unwrap_or_default(),
            "File not found",
            "the 404 must be `download_file_impl`'s own, proving the namespaced \
             route was matched rather than falling through to axum's router fallback"
        );
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_model_info_namespaced() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let model_id = "sentence-transformers/all-MiniLM-L6-v2";
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &format!("huggingface/{model_id}/main/config.json"),
            &format!("{model_id}/main/config.json"),
            model_id,
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"x\":1}"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/api/models/{}", f.repo_key, model_id)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["modelId"], model_id);
        f.teardown().await;
    }

    /// Namespaced model-info sibling of
    /// `test_huggingface_resolve_404_when_missing_namespaced`: assert the
    /// handler's own 404 body so "no route registered" (axum's bodyless
    /// fallback, which is what the pre-fix code produced here) cannot be
    /// mistaken for "route present, model genuinely absent" (#2915).
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_model_info_404_when_missing_namespaced() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/api/models/missing-org/missing", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            std::str::from_utf8(&body).unwrap_or_default(),
            "Model not found",
            "the 404 must be `model_info_impl`'s own, proving the namespaced \
             route was matched rather than falling through to axum's router fallback"
        );
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_tree_namespaced() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let model_id = "sentence-transformers/all-MiniLM-L6-v2";
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &format!("huggingface/{model_id}/main/config.json"),
            &format!("{model_id}/main/config.json"),
            model_id,
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"x\":1}"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/api/models/{}/tree/main", f.repo_key, model_id)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["path"], "config.json");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_upload_unauthenticated_401_namespaced() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/{}/api/models/my-org/my-model/upload/main",
                f.repo_key
            ))
            .header("x-filename", "file.bin")
            .body(axum::body::Body::from("data"))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_upload_succeeds_for_local_namespaced() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/{}/api/models/my-org/my-model/upload/main",
                f.repo_key
            ))
            .header("x-filename", "weights.bin")
            .body(axum::body::Body::from(vec![0u8; 16]))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert!(
            status == StatusCode::OK || status == StatusCode::CREATED,
            "got {}",
            status
        );
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Model-info `/revision/{revision}` routes and upstream pull-through.
    //
    // `hf download <org/model>` calls
    // `GET /api/models/{model_id}/revision/{revision}` to list a model's
    // files before downloading them. Before this fix there was no route for
    // that path at all (bare or namespaced), and even with a route,
    // `model_info_impl` never consulted the upstream Hugging Face API for an
    // uncached model - both gaps 404'd a fresh `hf download` immediately.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_huggingface_model_info_revision_route_serves_local() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "huggingface/gpt2/main/config.json",
            "gpt2/main/config.json",
            "gpt2",
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"x\":1}"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/api/models/gpt2/revision/main", f.repo_key)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the bare /revision/ route must exist and reach model_info_impl"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["modelId"], "gpt2");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_model_info_revision_route_serves_local_namespaced() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let model_id = "sentence-transformers/all-MiniLM-L6-v2";
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &format!("huggingface/{model_id}/main/config.json"),
            &format!("{model_id}/main/config.json"),
            model_id,
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"x\":1}"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/models/{}/revision/main",
                f.repo_key, model_id
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the namespaced /revision/ route must exist and reach model_info_impl"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["modelId"], model_id);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_model_info_proxies_upstream_for_uncached_remote_model() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        let upstream_json = serde_json::json!({
            "modelId": "sentence-transformers/all-MiniLM-L6-v2",
            "sha": "deadbeef",
            "siblings": [{"rfilename": "config.json"}, {"rfilename": "pytorch_model.bin"}],
        });
        Mock::given(method("GET"))
            .and(wm_path(
                "/api/models/sentence-transformers/all-MiniLM-L6-v2/revision/main",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&upstream_json))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/models/sentence-transformers/all-MiniLM-L6-v2/revision/main",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "an uncached model on a Remote repo must be proxied from upstream, not 404"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["modelId"], "sentence-transformers/all-MiniLM-L6-v2");
        assert_eq!(json["siblings"].as_array().unwrap().len(), 2);
    }

    /// `huggingface_hub`'s HEAD-based metadata check hard-requires an ETag
    /// (`X-Linked-Etag` or plain `ETag`) on the resolve response, or it raises
    /// `FileMetadataError` -> `LocalEntryNotFoundError` (see
    /// hf-deepdive-report.md). The proxy response builder must forward
    /// whatever ETag upstream sent rather than synthesizing a bare 200 with
    /// only Content-Type/Content-Length.
    #[tokio::test]
    async fn test_huggingface_resolve_carries_upstream_etag_header() {
        use tower::ServiceExt;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"72b987e498d7e3a1\"")
                    .set_body_bytes(b"{\"hidden_size\": 384}".to_vec()),
            )
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let resp = app
            .oneshot(tdh::get(format!(
                "/{}/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
                f.repo_key
            )))
            .await
            .expect("resolve oneshot");

        f.teardown().await;

        assert_eq!(resp.status(), StatusCode::OK);
        let etag = resp
            .headers()
            .get(axum::http::header::ETAG)
            .and_then(|v| v.to_str().ok());
        assert_eq!(
            etag,
            Some("\"72b987e498d7e3a1\""),
            "the proxy must forward the upstream ETag so huggingface_hub's \
             HEAD-based metadata check (which hard-requires an ETag) succeeds"
        );
    }

    /// `huggingface_hub`'s HEAD-based metadata check also hard-requires
    /// `X-Repo-Commit`, which only ever exists on the upstream redirect hop
    /// that the shared reqwest client's auto-follow swallows (see
    /// hf-deepdive-report.md). The handler recovers it from the model-info
    /// pull-through instead (`api/models/{model_id}/revision/{revision}`,
    /// parsing the `"sha"` field) and injects it as `X-Repo-Commit` on the
    /// resolve response.
    #[tokio::test]
    async fn test_huggingface_resolve_carries_x_repo_commit_from_model_info() {
        use tower::ServiceExt;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/api/models/sentence-transformers/all-MiniLM-L6-v2/revision/main",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "modelId": "sentence-transformers/all-MiniLM-L6-v2",
                "sha": "1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"{\"hidden_size\": 384}".to_vec()),
            )
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let resp = app
            .oneshot(tdh::get(format!(
                "/{}/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
                f.repo_key
            )))
            .await
            .expect("resolve oneshot");

        f.teardown().await;

        assert_eq!(resp.status(), StatusCode::OK);
        let commit = resp
            .headers()
            .get("x-repo-commit")
            .and_then(|v| v.to_str().ok());
        assert_eq!(
            commit,
            Some("1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf"),
            "the resolve response must carry X-Repo-Commit sourced from the \
             model-info sha, since huggingface_hub's HEAD-based metadata check \
             hard-requires it"
        );
    }

    /// REPRO (act2-fix-hf4): live testing against huggingface.co showed a
    /// cold-cache HEAD on a nested file (`1_Pooling/config.json`) succeeds,
    /// but `hf download` still failed on OTHER files in the same repo
    /// (`README.md`) with `FileMetadataError("Distant resource does not have
    /// a Content-Length.")`. Root cause, confirmed by `cargo tree -i
    /// reqwest@0.13.4 -e features`: this crate's `Cargo.toml` requests only
    /// `["json", "stream", "form"]`, but Cargo unifies features for a single
    /// resolved `reqwest` version across the whole build, and the
    /// `opensearch` dependency (full-text search) pulls in `reqwest` with
    /// its `gzip` feature — silently switching EVERY `reqwest::Client` in
    /// this binary, including the shared upstream client from
    /// `http_client::base_client_builder()`, into auto content-negotiation
    /// mode. That makes the client add `Accept-Encoding: gzip` to outbound
    /// requests and, whenever upstream compresses the response (HF's
    /// CloudFront does this for text/JSON responses above a size
    /// threshold — verified live: small nested configs stay under it,
    /// `README.md` does not), transparently decode the body AND strip both
    /// `Content-Encoding` and `Content-Length` from `response.headers()`
    /// before this proxy's header-capture code
    /// (`extract_streaming_headers`) ever sees them. This test does not
    /// depend on live negotiation: it mounts a mock that returns a
    /// `Content-Encoding: gzip` body regardless of what `Accept-Encoding`
    /// the client sent, exactly reproducing the header-loss this proxy must
    /// not exhibit.
    ///
    /// #2915 tightened the assertions. The original test checked only the status
    /// and `Content-Length`, never the body — so it passed while the client
    /// received a gzip blob labelled as identity-encoded and wrote compressed
    /// bytes to disk under a `.md` name. Now that `Content-Encoding` is forwarded
    /// alongside the coded length, this asserts the pair a client actually needs
    /// to make sense of the transfer: the declared encoding, and that the coded
    /// bytes really do inflate back to the original document.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_resolve_survives_upstream_gzip_content_length() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::{Read, Write};
        use tower::ServiceExt;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };

        let body = b"# sentence-transformers model card\n".repeat(200);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&body).expect("gzip encode");
        let compressed = encoder.finish().expect("gzip finish");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/sentence-transformers/all-MiniLM-L6-v2/resolve/main/README.md",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .insert_header("etag", "\"152b56c8ff5229192e0b1f405f5bf07699854738\"")
                    .set_body_bytes(compressed.clone()),
            )
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let resp = app
            .oneshot(tdh::get(format!(
                "/{}/sentence-transformers/all-MiniLM-L6-v2/resolve/main/README.md",
                f.repo_key
            )))
            .await
            .expect("resolve oneshot");

        f.teardown().await;

        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers().clone();
        let content_length = headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        assert_eq!(
            content_length.as_deref(),
            Some(compressed.len().to_string().as_str()),
            "the proxy's upstream HTTP client must not silently auto-decode \
             a gzip-encoded upstream response (which would strip \
             Content-Length before this proxy's header-capture code ever \
             sees it): huggingface_hub's HEAD-based metadata check \
             hard-requires a Content-Length or it raises FileMetadataError"
        );
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "the coded length above is only interpretable alongside the coding \
             that produced it: without Content-Encoding the client reads \
             `compressed.len()` bytes and stores them as if they were the file"
        );

        let served = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect resolve body");
        assert_eq!(
            &served[..],
            &compressed[..],
            "the body must be the still-coded upstream bytes, matching the \
             advertised Content-Length"
        );
        let mut inflated = Vec::new();
        flate2::read::GzDecoder::new(&served[..])
            .read_to_end(&mut inflated)
            .expect("served body must be valid gzip");
        assert_eq!(
            inflated, body,
            "a client that honours the declared gzip encoding must recover the \
             original document byte for byte"
        );
    }

    #[tokio::test]
    async fn test_huggingface_model_info_proxies_upstream_bare_no_revision() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        let upstream_json = serde_json::json!({"modelId": "gpt2", "siblings": []});
        Mock::given(method("GET"))
            .and(wm_path("/api/models/gpt2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&upstream_json))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) =
            tdh::send(app, tdh::get(format!("/{}/api/models/gpt2", f.repo_key))).await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "the no-revision variant must also proxy upstream for an uncached model"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["modelId"], "gpt2");
    }

    /// A genuine upstream 404 must surface as a 404, not a silent empty 200.
    ///
    /// The `.expect(1)` and the body assertion together are what make this test
    /// meaningful. `/{repo}/api/models/does-not-exist/revision/main` matched no
    /// route before this PR, so axum's fallback returned a bodyless 404 without
    /// upstream ever being contacted and a status-only assertion passed either
    /// way. Requiring exactly one upstream call proves the pull-through ran, and
    /// pinning `map_proxy_error`'s wording proves the 404 came back from it
    /// (#2915).
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_model_info_upstream_404_surfaces_not_empty_200() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/models/does-not-exist/revision/main"))
            .respond_with(ResponseTemplate::new(404))
            // Proof the handler consulted upstream at all: without a Remote
            // pull-through this counter stays at 0 and the mock's verification
            // fails when `server` drops.
            .expect(1)
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/models/does-not-exist/revision/main",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a genuine upstream 404 must surface as 404, not a silent empty 200"
        );
        assert_eq!(
            std::str::from_utf8(&body).unwrap_or_default(),
            "Artifact not found upstream",
            "the 404 must be the proxy's mapped upstream error, not axum's \
             bodyless router fallback"
        );
    }

    #[tokio::test]
    async fn test_huggingface_model_info_cached_model_skips_upstream_proxy() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        // No mock registered: if the handler tried to hit upstream for a
        // cached model, wiremock would return its default 404 and the test
        // would fail below, proving the DB path was bypassed.
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let repo = f.repo_info("remote", Some(&server.uri()));
        tdh::seed_artifact(
            &state,
            &f.pool,
            &repo,
            "huggingface/gpt2/main/config.json",
            "gpt2/main/config.json",
            "gpt2",
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"cached\":true}"),
            f.user_id,
        )
        .await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) =
            tdh::send(app, tdh::get(format!("/{}/api/models/gpt2", f.repo_key))).await;

        f.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "a model already cached in the DB must be served from there, not upstream"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["modelId"], "gpt2");
    }

    // -----------------------------------------------------------------------
    // #2914 / #2915: read-path input validation and upstream path spelling.
    //
    // These are pure-function tests for the boundary checks and the revision
    // re-encoding; the DB-backed behaviour they feed is covered further down.
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_model_coordinates_accepts_real_hub_shapes() {
        for (model_id, revision) in [
            ("gpt2", "main"),
            ("sentence-transformers/all-MiniLM-L6-v2", "main"),
            (
                "sentence-transformers/all-MiniLM-L6-v2",
                "1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf",
            ),
            // Slash-bearing Hub revisions must pass validation - they are
            // re-encoded for upstream, not rejected (see
            // `encode_upstream_revision`).
            ("openai/whisper-large-v3", "refs/pr/1"),
            ("openai/whisper-large-v3", "refs/convert/parquet"),
            // A dot inside a name/tag is ordinary; only `..` is traversal.
            ("stabilityai/sd.turbo", "v1.0"),
        ] {
            assert!(
                validate_model_coordinates(model_id, Some(revision)).is_ok(),
                "{model_id}@{revision} is a legitimate Hub coordinate"
            );
        }
    }

    #[test]
    fn test_validate_model_coordinates_rejects_traversal_and_overlong() {
        // axum percent-decodes a captured parameter exactly once, so a request
        // spelled `%252e%252e` reaches the handler as the literal `%2e%2e` and a
        // doubly-encoded `%2e%2e` reaches it as `..`. The decoded-value check is
        // therefore the one that has to catch traversal.
        for (model_id, revision) in [
            ("../../etc/passwd", "main"),
            ("org/..", "main"),
            ("gpt2", "../main"),
            ("gpt2", "refs/../../secret"),
        ] {
            let err = validate_model_coordinates(model_id, Some(revision));
            assert!(
                err.is_err(),
                "{model_id}@{revision} must be rejected at the handler boundary"
            );
        }
        assert!(validate_model_coordinates(&"a".repeat(MAX_MODEL_ID_LEN + 1), None).is_err());
        assert!(
            validate_model_coordinates("gpt2", Some(&"v".repeat(MAX_REVISION_LEN + 1))).is_err()
        );
        assert!(validate_model_coordinates("gpt2\0", None).is_err());
    }

    #[test]
    fn test_encode_upstream_revision_matches_hub_wire_spelling() {
        // `huggingface_hub` builds resolve URLs with `quote(revision, safe="")`,
        // so `refs/pr/1` travels as one segment. Ordinary revisions must pass
        // through byte-identical, or every existing proxy-cache key would move.
        assert_eq!(encode_upstream_revision("main"), "main");
        assert_eq!(
            encode_upstream_revision("1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf"),
            "1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf"
        );
        assert_eq!(encode_upstream_revision("v1.0"), "v1.0");
        assert_eq!(encode_upstream_revision("my-branch_x"), "my-branch_x");
        assert_eq!(encode_upstream_revision("refs/pr/1"), "refs%2Fpr%2F1");
        assert_eq!(
            encode_upstream_revision("refs/convert/parquet"),
            "refs%2Fconvert%2Fparquet"
        );
    }

    #[test]
    fn test_local_repo_commit_sha_is_stable_40_hex_per_coordinate() {
        let a = local_repo_commit_sha("gpt2", "main");
        assert_eq!(a.len(), 40, "huggingface_hub matches ^[0-9a-f]{{40}}$");
        assert!(a
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        // Stable: every file of a revision must report the same commit or
        // `snapshot_download` scatters one model across snapshot directories.
        assert_eq!(a, local_repo_commit_sha("gpt2", "main"));
        // Distinct per coordinate, and the separator keeps the two components
        // from running together (`("a/b", "c")` must not equal `("a", "b/c")`).
        assert_ne!(a, local_repo_commit_sha("gpt2", "dev"));
        assert_ne!(a, local_repo_commit_sha("gpt-2", "main"));
        assert_ne!(
            local_repo_commit_sha("a/b", "c"),
            local_repo_commit_sha("a", "b/c")
        );
    }

    // -----------------------------------------------------------------------
    // #2914 / #2915: the metadata headers `hf download` cannot work without.
    //
    // `huggingface_hub` probes every file with HEAD before downloading it
    // (`get_hf_file_metadata`) and raises `FileMetadataError` ->
    // `LocalEntryNotFoundError` unless that response carries an ETag, a
    // Content-Length and `X-Repo-Commit`. `X-Repo-Commit` is now captured from
    // upstream's own response header by `ProxyService`, stored in the cache
    // sidecar beside the bytes it describes, and replayed on cache hits - so
    // these tests pin both the forwarded path and the fallbacks around it.
    // -----------------------------------------------------------------------

    /// A **HEAD** resolve must return the full metadata header set and no body.
    ///
    /// Every other resolve test in this module issues a GET, so the exact
    /// request shape the bug reports came from had no coverage at all. axum
    /// dispatches HEAD to the `get(...)` handler and strips the body from the
    /// response afterwards, which is precisely the contract `huggingface_hub`
    /// depends on: headers as if it were a GET, zero bytes transferred.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_resolve_head_carries_etag_length_and_commit() {
        use tower::ServiceExt;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let payload = b"{\"hidden_size\": 384}".to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"72b987e498d7e3a1\"")
                    .insert_header("x-repo-commit", "1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf")
                    .set_body_bytes(payload.clone()),
            )
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let req = axum::http::Request::builder()
            .method("HEAD")
            .uri(format!(
                "/{}/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
                f.repo_key
            ))
            .body(Body::empty())
            .expect("build HEAD request");
        let resp = app.oneshot(req).await.expect("HEAD resolve must respond");

        f.teardown().await;

        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers().clone();
        assert_eq!(
            headers.get(ETAG).and_then(|v| v.to_str().ok()),
            Some("\"72b987e498d7e3a1\""),
            "huggingface_hub names its local blob file after the ETag and fails \
             the metadata probe outright without one"
        );
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(payload.len().to_string().as_str()),
            "HEAD must still advertise the body size it would have sent"
        );
        assert_eq!(
            headers
                .get(UPSTREAM_COMMIT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf"),
            "X-Repo-Commit names the snapshot directory huggingface_hub stores \
             the file under"
        );

        let collected = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect HEAD body");
        assert!(
            collected.is_empty(),
            "a HEAD probe must transfer no bytes, got {}",
            collected.len()
        );
    }

    /// `X-Repo-Commit` comes from the resolve response's OWN header when upstream
    /// sends one, and the model-info endpoint is not touched in that case.
    ///
    /// This is the path that matters most: a header captured from the same
    /// response as the bytes is bound to those bytes, whereas the model-info
    /// `sha` is a second, independent observation of a mutable ref and can
    /// describe a different commit entirely. The `.expect(0)` on the model-info
    /// mock is the load-bearing assertion — the old code fetched model-info on
    /// *every* Remote resolve, and did it after the file response had already
    /// been opened, so an idle file socket waited on a full extra round trip
    /// before the client saw a byte.
    #[tokio::test]
    async fn test_huggingface_resolve_prefers_forwarded_commit_header() {
        use tower::ServiceExt;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"72b987e498d7e3a1\"")
                    .insert_header("x-repo-commit", "aaaabbbbccccddddeeeeffff0000111122223333")
                    .set_body_bytes(b"{\"hidden_size\": 384}".to_vec()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/api/models/sentence-transformers/all-MiniLM-L6-v2/revision/main",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "9999999999999999999999999999999999999999",
            })))
            // The forwarded header must make this request unnecessary. A single
            // call here would also mean the returned commit could disagree with
            // the bytes served.
            .expect(0)
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let resp = app
            .oneshot(tdh::get(format!(
                "/{}/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
                f.repo_key
            )))
            .await
            .expect("resolve oneshot");

        f.teardown().await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(UPSTREAM_COMMIT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("aaaabbbbccccddddeeeeffff0000111122223333"),
            "the commit must be the one upstream sent with these bytes, not the \
             one a separate model-info call would report"
        );
    }

    /// A second request for the same file must serve the identical ETag and
    /// `X-Repo-Commit` from the proxy cache, without touching upstream.
    ///
    /// `.expect(1)` is what makes this a cache-hit test rather than a repeat of
    /// the test above: both headers now travel through the cache sidecar
    /// (`CacheMetadata::upstream_commit_sha`), so a warm serve that lost either
    /// one would leave `huggingface_hub` unable to validate a file it had
    /// already downloaded once.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_resolve_cache_hit_replays_etag_and_commit() {
        use tower::ServiceExt;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        // Distinct enough in size that `wait_for_cache_commit`'s size gate
        // cannot be satisfied by some other object in the cache directory.
        let payload = b"{\"hidden_size\": 384, \"num_layers\": 6}\n".repeat(64);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"72b987e498d7e3a1\"")
                    .insert_header("x-repo-commit", "1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf")
                    .set_body_bytes(payload.clone()),
            )
            // Cache-hit proof: one upstream fetch across the two requests below.
            .expect(1)
            .mount(&server)
            .await;

        let (state, cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let uri = format!(
            "/{}/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
            f.repo_key
        );

        let mut seen: Vec<(Option<String>, Option<String>)> = Vec::new();
        for attempt in 0..2 {
            // The streaming write-back tees into the cache as the body drains
            // and only the metadata sidecar makes the next lookup a hit, so wait
            // for the commit instead of racing it.
            if attempt == 1 {
                tdh::wait_for_cache_commit(cache.path(), payload.len() as u64).await;
            }
            let app = tdh::router_anon(super::router(), state.clone());
            let resp = app
                .oneshot(tdh::get(uri.clone()))
                .await
                .expect("resolve oneshot");
            assert_eq!(resp.status(), StatusCode::OK, "attempt {attempt}");
            let headers = resp.headers().clone();
            seen.push((
                headers
                    .get(ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
                headers
                    .get(UPSTREAM_COMMIT_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            ));
            // Drain so the tee can finish writing the cache entry.
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("collect resolve body");
            assert_eq!(&body[..], &payload[..], "attempt {attempt} body");
        }

        f.teardown().await;

        assert_eq!(
            seen[0],
            (
                Some("\"72b987e498d7e3a1\"".to_string()),
                Some("1110a243c5cd318b8688b1e73b6ba0b9c7d6f6cf".to_string())
            ),
            "cold serve must forward upstream's ETag and X-Repo-Commit"
        );
        assert_eq!(
            seen[1], seen[0],
            "the warm serve must replay the SAME ETag and X-Repo-Commit from the \
             cache sidecar; the mock's expect(1) proves it came from cache"
        );
    }

    /// The model-info fallback is best-effort: a broken model-info endpoint must
    /// cost the download its `X-Repo-Commit` header, never the file.
    ///
    /// Upstream here answers the resolve without a commit header (the shape the
    /// Hub produces when it 302s an LFS object to its CDN and the header stays on
    /// the redirect the HTTP client follows internally), and answers model-info
    /// with a 500. The `.expect(1)` pins that the fallback really was attempted;
    /// the body assertion pins that its failure changed nothing about the bytes.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_resolve_survives_model_info_failure() {
        use tower::ServiceExt;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let payload = b"{\"hidden_size\": 384}".to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"72b987e498d7e3a1\"")
                    .set_body_bytes(payload.clone()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/api/models/sentence-transformers/all-MiniLM-L6-v2/revision/main",
            ))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let resp = app
            .oneshot(tdh::get(format!(
                "/{}/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json",
                f.repo_key
            )))
            .await
            .expect("resolve oneshot");

        f.teardown().await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a failing metadata lookup must not fail the file download"
        );
        assert!(
            resp.headers().get(UPSTREAM_COMMIT_HEADER).is_none(),
            "with no forwarded header and a broken model-info endpoint there is \
             no commit to report, and inventing one would mislabel the bytes"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect resolve body");
        assert_eq!(&body[..], &payload[..]);
    }

    /// A Local/hosted HF repo's resolve must carry an ETag and `X-Repo-Commit`
    /// too, and the commit must agree with the `sha` model-info reports.
    ///
    /// Hosted serves go through `proxy_helpers::build_download_response`, which
    /// emits only Content-Type/Content-Length/Content-Disposition — so
    /// `hf download` failed its metadata probe against content this instance
    /// owns, not just against proxied content. The cross-endpoint equality is the
    /// real assertion: `snapshot_download` computes its snapshot directory from
    /// model-info's `sha` and then files each downloaded file under the commit
    /// that file's resolve reported, so the two disagreeing yields a snapshot
    /// directory with nothing in it.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_local_resolve_carries_etag_and_commit() {
        use tower::ServiceExt;

        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let model_id = "sentence-transformers/all-MiniLM-L6-v2";
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &format!("huggingface/{model_id}/main/config.json"),
            &format!("{model_id}/main/config.json"),
            model_id,
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"hidden_size\": 384}"),
            f.user_id,
        )
        .await;

        let resolve = f
            .router_anon(super::router())
            .oneshot(tdh::get(format!(
                "/{}/{}/resolve/main/config.json",
                f.repo_key, model_id
            )))
            .await
            .expect("resolve oneshot");
        assert_eq!(resolve.status(), StatusCode::OK);
        let headers = resolve.headers().clone();

        let (info_status, info_body) = tdh::send(
            f.router_anon(super::router()),
            tdh::get(format!(
                "/{}/api/models/{}/revision/main",
                f.repo_key, model_id
            )),
        )
        .await;

        f.teardown().await;

        // `tdh::seed_artifact` stores "test-seed" as the checksum; the point is
        // that the ETag is the stored per-file content hash, quoted as RFC 9110
        // requires for an entity-tag. The absence of interior padding also pins
        // the `CHAR(64)` blank-padding trim - Postgres returns "test-seed" plus
        // 55 spaces for this column.
        assert_eq!(
            headers.get(ETAG).and_then(|v| v.to_str().ok()),
            Some("\"test-seed\""),
            "a hosted resolve must expose the artifact's stored checksum as a \
             quoted ETag"
        );
        let commit = headers
            .get(UPSTREAM_COMMIT_HEADER)
            .and_then(|v| v.to_str().ok())
            .expect("hosted resolve must carry X-Repo-Commit")
            .to_string();
        assert_eq!(commit.len(), 40, "huggingface_hub matches ^[0-9a-f]{{40}}$");
        assert!(commit
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));

        assert_eq!(info_status, StatusCode::OK);
        let info: serde_json::Value = serde_json::from_slice(&info_body).unwrap();
        assert_eq!(
            info["sha"].as_str(),
            Some(commit.as_str()),
            "model-info's sha and the resolve's X-Repo-Commit must be the same \
             value or snapshot_download's directory and its file placement diverge"
        );
    }

    /// `hf download --revision refs/pr/1` must reach upstream with the revision
    /// spelled as one percent-encoded segment.
    ///
    /// The client puts `resolve/refs%2Fpr%2F1/<file>` on the wire; axum decodes
    /// that capture once, so the handler holds `refs/pr/1` and a naive
    /// `format!` produced `…/resolve/refs/pr/1/config.json` upstream — a shape
    /// the Hub's API does not serve. The wiremock path matcher compares against
    /// the still-encoded URL path, so an exact match here is proof the outbound
    /// request carries the spelling `huggingface_hub` itself generates. The
    /// `X-Repo-Commit` assertion is the second half of the same bug: the
    /// model-info path was mis-spelled the same way, so the header went missing
    /// too.
    #[tokio::test]
    async fn test_huggingface_resolve_reencodes_slash_bearing_revision() {
        use tower::ServiceExt;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/openai/whisper-large-v3/resolve/refs%2Fpr%2F1/config.json",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"5f2c1d0e\"")
                    .insert_header("x-repo-commit", "77778888999900001111222233334444aaaabbbb")
                    .set_body_bytes(b"{\"num_mel_bins\": 128}".to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let resp = app
            .oneshot(tdh::get(format!(
                "/{}/openai/whisper-large-v3/resolve/refs%2Fpr%2F1/config.json",
                f.repo_key
            )))
            .await
            .expect("resolve oneshot");

        f.teardown().await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a `refs/pr/N` revision is an ordinary Hub revision and must resolve, \
             not 404 against a mis-spelled upstream path"
        );
        assert_eq!(
            resp.headers()
                .get(UPSTREAM_COMMIT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("77778888999900001111222233334444aaaabbbb")
        );
    }

    /// A Virtual repo's local-member serve sources its ETag from the member row
    /// that actually won the member-priority race.
    ///
    /// `virtual_member_checksum` swallows database errors by design (a missing
    /// header must never fail a download), which means a wrong column or join in
    /// its SQL would degrade silently to "no ETag" rather than surfacing. This
    /// drives the query directly against a real virtual/member pair so that
    /// cannot happen unnoticed, and pins the two answers the calling code
    /// branches on: the winner's checksum, and `None` when no local member owns
    /// the path (which is how a Remote member's serve keeps whatever its own
    /// upstream said).
    #[tokio::test]
    async fn test_virtual_member_checksum_resolves_priority_winner() {
        let Some(f) = tdh::Fixture::setup("virtual", "huggingface").await else {
            return;
        };
        let (member_id, _member_key, member_dir) =
            tdh::create_repo(&f.pool, "local", "huggingface").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(f.repo_id)
        .bind(member_id)
        .execute(&f.pool)
        .await
        .expect("link virtual member");

        let artifact_path = "sentence-transformers/all-MiniLM-L6-v2/main/config.json";
        // A full 64-hex digest, so the assertion also shows that a real checksum
        // needs no `CHAR(64)` padding trim.
        let checksum = "b".repeat(64);
        sqlx::query(
            "INSERT INTO artifacts \
             (id, repository_id, name, version, path, storage_key, size_bytes, \
              checksum_sha256, content_type, is_deleted) \
             VALUES (gen_random_uuid(),$1,$2,'main',$3,$4,20,$5,'application/json',false)",
        )
        .bind(member_id)
        .bind("sentence-transformers/all-MiniLM-L6-v2")
        .bind(artifact_path)
        .bind(format!("huggingface/{artifact_path}"))
        .bind(&checksum)
        .execute(&f.pool)
        .await
        .expect("insert member artifact");

        let found = virtual_member_checksum(&f.pool, None, f.repo_id, artifact_path).await;
        let missing = virtual_member_checksum(
            &f.pool,
            None,
            f.repo_id,
            "sentence-transformers/all-MiniLM-L6-v2/main/absent.json",
        )
        .await;

        tdh::cleanup(&f.pool, member_id, f.user_id).await;
        let _ = std::fs::remove_dir_all(&member_dir);
        f.teardown().await;

        assert_eq!(
            found.as_deref().map(str::trim),
            Some(checksum.as_str()),
            "the ETag must come from the local member that owns the path"
        );
        assert!(
            missing.is_none(),
            "no local member owning the path means the bytes came from a Remote \
             member, whose own upstream metadata must stand unaltered"
        );
    }

    // -----------------------------------------------------------------------
    // #2915: `/api/models/{id}/tree/{revision}` Remote pull-through.
    //
    // `list_files_impl` answers from the local `artifacts` table by path prefix.
    // A Remote repo keeps no `artifacts` rows for proxied content (#1278), so
    // that query matched nothing and the endpoint returned `[]` with 200 for
    // every uncached model - the same fail-open this PR removed from
    // `model_info`, left standing on the sibling endpoint.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_huggingface_tree_proxies_upstream_for_remote_repo() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(
                "/api/models/sentence-transformers/all-MiniLM-L6-v2/tree/main",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"type": "file", "oid": "abc", "size": 612, "path": "config.json"},
                {"type": "file", "oid": "def", "size": 90868376, "path": "model.safetensors"},
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/models/sentence-transformers/all-MiniLM-L6-v2/tree/main",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = json
            .as_array()
            .expect("the tree endpoint must return a JSON array");
        assert_eq!(
            entries.len(),
            2,
            "an uncached model on a Remote repo must report upstream's tree, not \
             an empty list"
        );
        assert_eq!(entries[1]["path"], "model.safetensors");
    }

    /// #3334: the tree passthrough must not forward `xetHash`. A client that
    /// sees it caches the listing, skips the HEAD call on every later download
    /// and asks for a Xet read token this proxy does not serve, so the download
    /// dies on a 404 instead of falling back to `/resolve/`.
    #[tokio::test]
    async fn test_huggingface_tree_strips_xet_fields_from_upstream() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/models/openai-community/gpt2/tree/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"type": "file", "oid": "abc", "size": 665, "path": "config.json"},
                {
                    "type": "file",
                    "oid": "def",
                    "size": 548105171,
                    "path": "model.safetensors",
                    "xetHash": "607a30d783dfa663caf39e06633721c8d4cfcd7e",
                    "lfs": {"oid": "248dfc39", "size": 548105171, "pointerSize": 135},
                },
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/models/openai-community/gpt2/tree/main",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            !text.contains("xetHash"),
            "xetHash must not reach the client: {text}"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = json.as_array().expect("tree must stay a JSON array");
        assert_eq!(entries.len(), 2, "stripping must not drop entries");
        assert_eq!(entries[1]["path"], "model.safetensors");
        assert_eq!(
            entries[1]["lfs"]["oid"], "248dfc39",
            "the /resolve fallback still needs the rest of the entry"
        );
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test-only body buffering for assertions (#1608).
    async fn test_huggingface_tree_upstream_failure_surfaces_not_empty_200() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "huggingface").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/models/does-not-exist/tree/main"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/api/models/does-not-exist/tree/main",
                f.repo_key
            )),
        )
        .await;

        f.teardown().await;

        // #1445 folds an upstream 5xx into 503 in `map_proxy_error`; what matters
        // here is that the failure is visible at all rather than being flattened
        // into an authoritative-looking empty listing.
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a real upstream failure must surface as an error, not `[]` with 200"
        );
        assert_ne!(
            std::str::from_utf8(&body).unwrap_or_default(),
            "[]",
            "an empty list would tell the client the revision has no files"
        );
    }

    // -----------------------------------------------------------------------
    // Xet field stripping in proxied metadata (#3334)
    // -----------------------------------------------------------------------

    /// A tree entry as the Hub actually serves it. `xetHash` is the field that
    /// sends `huggingface_hub >= 1.26` down the Xet path.
    #[test]
    fn test_strip_xet_metadata_removes_xet_hash_from_tree_entry() {
        let upstream = br#"[
            {
                "type": "file",
                "oid": "7c5d3f4b8b76583b422fcb9189ad6c89d5d97a094541ce8932dce3ecabde1421",
                "size": 548105171,
                "path": "model.safetensors",
                "xetHash": "607a30d783dfa663caf39e06633721c8d4cfcd7e",
                "lfs": {
                    "oid": "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707",
                    "size": 548105171,
                    "pointerSize": 135
                }
            }
        ]"#;

        let stripped = strip_xet_metadata(Bytes::from_static(upstream));
        let json: serde_json::Value = serde_json::from_slice(&stripped).unwrap();
        let entry = &json[0];

        assert!(entry.get("xetHash").is_none(), "xetHash must not survive");
        assert_eq!(entry["path"], "model.safetensors");
        assert_eq!(entry["size"], 548105171u64);
        assert_eq!(
            entry["lfs"]["oid"], "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707",
            "the LFS pointer is what the /resolve fallback needs; it must stay"
        );
    }

    /// Model-info carries `xetEnabled` at the top level and one `xetHash` per
    /// sibling, so the walk has to reach both depths.
    #[test]
    fn test_strip_xet_metadata_removes_nested_xet_fields() {
        let upstream = br#"{
            "id": "openai-community/gpt2",
            "sha": "607a30d783dfa663caf39e06633721c8d4cfcd7e",
            "xetEnabled": true,
            "siblings": [
                {"rfilename": "config.json"},
                {"rfilename": "model.safetensors", "xetHash": "abc123"}
            ],
            "nested": {"deeper": [[{"xetHash": "def456", "keep": 1}]]}
        }"#;

        let stripped = strip_xet_metadata(Bytes::from_static(upstream));
        let json: serde_json::Value = serde_json::from_slice(&stripped).unwrap();

        assert!(json.get("xetEnabled").is_none());
        assert!(json["siblings"][1].get("xetHash").is_none());
        assert!(
            json["nested"]["deeper"][0][0].get("xetHash").is_none(),
            "the walk must descend through arrays of arrays"
        );
        assert_eq!(json["nested"]["deeper"][0][0]["keep"], 1);
        assert_eq!(json["id"], "openai-community/gpt2");
        assert_eq!(json["sha"], "607a30d783dfa663caf39e06633721c8d4cfcd7e");
        assert_eq!(json["siblings"][0]["rfilename"], "config.json");
        assert_eq!(json["siblings"][1]["rfilename"], "model.safetensors");
    }

    /// Only the two Xet keys go. Lookalike names and any value that merely
    /// mentions Xet are none of this function's business.
    #[test]
    fn test_strip_xet_metadata_preserves_non_xet_keys_and_values() {
        let upstream = br#"{
            "xetHashAlgorithm": "blake3",
            "notXetHash": "keep me",
            "description": "xetHash appears in this string value",
            "xet": {"still": "here"}
        }"#;

        let stripped = strip_xet_metadata(Bytes::from_static(upstream));
        let json: serde_json::Value = serde_json::from_slice(&stripped).unwrap();

        assert_eq!(json["xetHashAlgorithm"], "blake3");
        assert_eq!(json["notXetHash"], "keep me");
        assert_eq!(json["description"], "xetHash appears in this string value");
        assert_eq!(json["xet"]["still"], "here");
    }

    /// Fail open: anything that is not JSON is handed back untouched rather
    /// than turned into an error.
    #[test]
    fn test_strip_xet_metadata_passes_non_json_through_unchanged() {
        let raw = Bytes::from_static(b"<html>not json at all</html>");
        assert_eq!(strip_xet_metadata(raw.clone()), raw);

        let truncated = Bytes::from_static(br#"{"xetHash": "abc"#);
        assert_eq!(strip_xet_metadata(truncated.clone()), truncated);

        let empty = Bytes::new();
        assert_eq!(strip_xet_metadata(empty.clone()), empty);
    }

    /// A document with nothing to strip still has to come back intact.
    #[test]
    fn test_strip_xet_metadata_leaves_xet_free_document_intact() {
        let upstream = Bytes::from_static(br#"[{"type":"file","path":"config.json"}]"#);
        let stripped = strip_xet_metadata(upstream.clone());
        let json: serde_json::Value = serde_json::from_slice(&stripped).unwrap();

        assert_eq!(json[0]["type"], "file");
        assert_eq!(json[0]["path"], "config.json");
    }
}
