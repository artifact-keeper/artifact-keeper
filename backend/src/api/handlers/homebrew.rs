//! Homebrew bottle repository handlers (#5985).
//!
//! Routes are mounted at `/homebrew/{repo_key}/...`:
//!
//! ```text
//! PUT    /homebrew/{repo}/bottles/{filename}[?cellar=...]  upload a bottle (auth required)
//! GET    /homebrew/{repo}/bottles/{filename}               download a bottle
//! DELETE /homebrew/{repo}/bottles/{filename}               delete a bottle (auth required)
//! GET    /homebrew/{repo}/api/formula.json                 every formula, newest version
//! GET    /homebrew/{repo}/api/formula/{name}.json          one formula
//! ```
//!
//! `{filename}` is a bottle name in either the `brew bottle` (`name--version`)
//! or the download (`name-version`) spelling; see [`crate::formats::homebrew`].
//! The formula JSON is rendered on demand from live rows, so a published or
//! deleted bottle shows up in the next `brew update` with no index step.
//!
//! Hosted repositories only: Remote and virtual homebrew repositories answer
//! 501. The formula JSON is served unsigned, not as `formula.jws.json`.

use std::collections::{BTreeMap, HashMap};

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::handlers::upload_body::UploadBody;
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::homebrew::{BottleName, HomebrewHandler};
use crate::models::repository::RepositoryType;

/// `cellar` recorded for a bottle uploaded without one: relocatable, the value
/// `brew bottle` writes for a bottle that was built with placeholders.
const DEFAULT_CELLAR: &str = ":any";

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/api/formula.json", get(formula_index))
        .route("/:repo_key/api/formula/:name", get(formula_one))
        .route(
            "/:repo_key/bottles/:filename",
            get(download_bottle)
                .put(upload_bottle)
                .delete(delete_bottle),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_homebrew_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["homebrew"], "a Homebrew").await
}

/// Remote and virtual homebrew repositories are not implemented yet; say so
/// instead of serving an empty formula list `brew` would accept silently.
#[allow(clippy::result_large_err)]
fn reject_unsupported_repo_type(repo_type: &str) -> Result<(), Response> {
    if repo_type == RepositoryType::Remote || repo_type == RepositoryType::Virtual {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "Remote and virtual Homebrew repositories are not supported yet; use a local repository",
        )
            .into_response());
    }
    Ok(())
}

fn bad_request(message: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, message.into()).into_response()
}

fn parse_filename(filename: &str) -> Result<BottleName, Response> {
    HomebrewHandler::parse_bottle_filename(filename).map_err(|e| bad_request(e.to_string()))
}

// ---------------------------------------------------------------------------
// Formula JSON rendering (pure)
// ---------------------------------------------------------------------------

/// One stored bottle, as the formula renderer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedBottle {
    bottle: BottleName,
    cellar: String,
    sha256: String,
    /// Upload time, seconds since the epoch; breaks ties between versions.
    uploaded_at: i64,
}

/// What the handler stores in `artifact_metadata` for a bottle.
#[derive(Debug, Deserialize)]
struct StoredMetadata {
    name: String,
    version: String,
    tag: String,
    #[serde(default)]
    rebuild: u32,
    cellar: Option<String>,
}

/// Split a formula version into Homebrew's `versions.stable` and `revision`:
/// `1.7.1_2` is version `1.7.1`, revision 2.
fn split_revision(version: &str) -> (&str, u32) {
    match version.rsplit_once('_') {
        Some((stable, rev)) if !rev.is_empty() && rev.bytes().all(|b| b.is_ascii_digit()) => {
            (stable, rev.parse().unwrap_or(0))
        }
        _ => (version, 0),
    }
}

/// Render one formula document from the bottles of a single formula.
///
/// The newest uploaded version wins; within it, each platform tag is served by
/// its highest rebuild. Returns `None` for an empty slice.
fn render_formula(bottles: &[IndexedBottle], root_url: &str, tap: &str) -> Option<Value> {
    let latest = bottles
        .iter()
        .max_by(|a, b| (a.uploaded_at, &a.bottle.version).cmp(&(b.uploaded_at, &b.bottle.version)))?
        .bottle
        .version
        .clone();

    let mut per_tag: BTreeMap<&str, &IndexedBottle> = BTreeMap::new();
    for b in bottles.iter().filter(|b| b.bottle.version == latest) {
        let slot = per_tag.entry(b.bottle.tag.as_str()).or_insert(b);
        if (b.bottle.rebuild, b.uploaded_at) > (slot.bottle.rebuild, slot.uploaded_at) {
            *slot = b;
        }
    }

    let name = &per_tag.values().next()?.bottle.name;
    let rebuild = per_tag
        .values()
        .map(|b| b.bottle.rebuild)
        .max()
        .unwrap_or(0);
    let (stable, revision) = split_revision(&latest);
    let files: serde_json::Map<String, Value> = per_tag
        .iter()
        .map(|(tag, b)| {
            (
                (*tag).to_string(),
                json!({
                    "cellar": b.cellar,
                    "url": format!("{root_url}/{}", b.bottle.filename()),
                    "sha256": b.sha256,
                }),
            )
        })
        .collect();

    Some(json!({
        "name": name,
        "full_name": name,
        "tap": tap,
        "oldnames": [],
        "aliases": [],
        "versions": { "stable": stable, "head": null, "bottle": true },
        "revision": revision,
        "version_scheme": 0,
        "bottle": {
            "stable": { "rebuild": rebuild, "root_url": root_url, "files": files }
        },
        "dependencies": [],
        "build_dependencies": [],
        "test_dependencies": [],
        "recommended_dependencies": [],
        "optional_dependencies": [],
        "uses_from_macos": [],
        "conflicts_with": [],
        "deprecated": false,
        "disabled": false,
    }))
}

/// Render every formula in the repository, ordered by name.
fn render_formulae(bottles: Vec<IndexedBottle>, root_url: &str, tap: &str) -> Vec<Value> {
    let mut by_name: BTreeMap<String, Vec<IndexedBottle>> = BTreeMap::new();
    for b in bottles {
        by_name.entry(b.bottle.name.clone()).or_default().push(b);
    }
    by_name
        .values()
        .filter_map(|group| render_formula(group, root_url, tap))
        .collect()
}

fn bottles_root_url(base_url: &RequestBaseUrl, repo_key: &str) -> String {
    format!(
        "{}/homebrew/{}/bottles",
        base_url.as_str().trim_end_matches('/'),
        repo_key
    )
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct BottleRow {
    sha256: String,
    created_at: chrono::DateTime<chrono::Utc>,
    metadata: Option<Value>,
}

impl BottleRow {
    /// A row that carries no usable bottle metadata (published through a path
    /// that did not record it) is not advertised.
    fn into_indexed(self) -> Option<IndexedBottle> {
        let meta: StoredMetadata = serde_json::from_value(self.metadata?).ok()?;
        Some(IndexedBottle {
            bottle: BottleName {
                name: meta.name,
                version: meta.version,
                tag: meta.tag,
                rebuild: meta.rebuild,
            },
            cellar: meta.cellar.unwrap_or_else(|| DEFAULT_CELLAR.to_string()),
            sha256: self.sha256,
            uploaded_at: self.created_at.timestamp(),
        })
    }
}

/// Live bottles of a repository, optionally narrowed to one formula.
async fn load_bottles(
    db: &PgPool,
    repo_id: uuid::Uuid,
    name: Option<&str>,
) -> Result<Vec<IndexedBottle>, Response> {
    // Runtime query (not the `query!` macro): no offline sqlx data to regenerate.
    let rows: Vec<BottleRow> = sqlx::query_as(
        r#"
        SELECT a.checksum_sha256 AS sha256, a.created_at, am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND ($2::text IS NULL OR a.name = $2)
        ORDER BY a.name, a.created_at DESC
        "#,
    )
    .bind(repo_id)
    .bind(name)
    .fetch_all(db)
    .await
    .map_err(super::db_err)?;

    Ok(rows
        .into_iter()
        .filter_map(BottleRow::into_indexed)
        .collect())
}

/// The live artifact stored at `path`: its id and storage key.
async fn find_bottle(
    db: &PgPool,
    repo_id: uuid::Uuid,
    path: &str,
) -> Result<Option<(uuid::Uuid, String)>, Response> {
    sqlx::query_as(
        "SELECT id, storage_key FROM artifacts \
         WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
    )
    .bind(repo_id)
    .bind(path)
    .fetch_optional(db)
    .await
    .map_err(super::db_err)
}

// ---------------------------------------------------------------------------
// GET /homebrew/{repo}/api/formula.json and /api/formula/{name}.json
// ---------------------------------------------------------------------------

fn json_response(value: &Value) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}

async fn formula_index(
    State(state): State<SharedState>,
    base_url: RequestBaseUrl,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_homebrew_repo(&state.db, &repo_key).await?;
    reject_unsupported_repo_type(&repo.repo_type)?;
    let bottles = load_bottles(&state.db, repo.id, None).await?;
    let formulae = render_formulae(bottles, &bottles_root_url(&base_url, &repo.key), &repo.key);
    Ok(json_response(&Value::Array(formulae)))
}

async fn formula_one(
    State(state): State<SharedState>,
    base_url: RequestBaseUrl,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let not_found = || (StatusCode::NOT_FOUND, "Formula not found").into_response();
    let name = name.strip_suffix(".json").ok_or_else(not_found)?;

    let repo = resolve_homebrew_repo(&state.db, &repo_key).await?;
    reject_unsupported_repo_type(&repo.repo_type)?;
    let bottles = load_bottles(&state.db, repo.id, Some(name)).await?;
    let formula = render_formula(&bottles, &bottles_root_url(&base_url, &repo.key), &repo.key)
        .ok_or_else(not_found)?;
    Ok(json_response(&formula))
}

// ---------------------------------------------------------------------------
// GET /homebrew/{repo}/bottles/{filename}
// ---------------------------------------------------------------------------

async fn download_bottle(
    State(state): State<SharedState>,
    Path((repo_key, filename)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_homebrew_repo(&state.db, &repo_key).await?;
    reject_unsupported_repo_type(&repo.repo_type)?;
    let bottle = parse_filename(&filename)?;

    let (artifact_id, storage_key) = find_bottle(&state.db, repo.id, &bottle.artifact_path())
        .await?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Bottle not found").into_response())?;

    proxy_helpers::serve_local_artifact(
        &state,
        &repo,
        artifact_id,
        &storage_key,
        "application/gzip",
        Some(&bottle.filename()),
        &ctx,
    )
    .await
}

// ---------------------------------------------------------------------------
// PUT /homebrew/{repo}/bottles/{filename}
// ---------------------------------------------------------------------------

async fn upload_bottle(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, filename)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    UploadBody(body): UploadBody,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "homebrew", "write:artifacts")?.user_id;
    let repo = resolve_homebrew_repo(&state.db, &repo_key).await?;
    reject_unsupported_repo_type(&repo.repo_type)?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if body.is_empty() {
        return Err(bad_request("Empty bottle"));
    }
    let bottle = parse_filename(&filename)?;
    let cellar = query.get("cellar").map_or(DEFAULT_CELLAR, String::as_str);
    HomebrewHandler::validate_cellar(cellar).map_err(|e| bad_request(e.to_string()))?;

    // #2561-style permit-scoped, decompression-bounded decode: the archive
    // must really be a bottle for the name and version in its filename.
    crate::util::bounded_archive::with_ingest_extraction(|| {
        HomebrewHandler::verify_bottle_contents(&bottle, &body)
    })
    .map_err(|e| e.into_response())?
    .map_err(|e| e.into_response())?;

    let sha256 = format!("{:x}", Sha256::digest(&body));
    let artifact_path = bottle.artifact_path();
    // GHSA-vcq6-8hxw-4q67: reject traversal at ingest, though the parsed
    // grammar already excludes `/`.
    crate::services::upload_service::validate_artifact_path(&artifact_path)
        .map_err(|e| bad_request(e.to_string()))?;
    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Bottle already exists",
    )
    .await?;

    let storage_key = crate::storage::StorageKeyScheme::from_env().write_key(
        &repo.storage_backend,
        "homebrew",
        repo.id,
        &artifact_path,
    );
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, body.clone()).await?;

    let size_bytes = body.len() as i64;
    let canonical = bottle.filename();
    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &bottle.name,
            version: &bottle.version,
            size_bytes,
            checksum_sha256: &sha256,
            content_type: "application/gzip",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    let metadata = json!({
        "name": bottle.name,
        "version": bottle.version,
        "tag": bottle.tag,
        "rebuild": bottle.rebuild,
        "cellar": cellar,
        "filename": canonical,
    });
    proxy_helpers::record_artifact_metadata(&state.db, artifact_id, repo.id, "homebrew", &metadata)
        .await;
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;
    crate::services::package_service::register_published_package(
        &state.db,
        &state.event_bus,
        crate::services::package_service::PublishedArtifact::new(artifact_id, user_id),
        repo.id,
        "homebrew",
        &bottle.name,
        &bottle.version,
        size_bytes,
        &sha256,
        None,
    )
    .await;
    // #4725: fan out to subscribed push peers.
    super::queue_push_sync_tasks_for_upload(
        &state.db,
        &headers,
        repo.id,
        artifact_id,
        &artifact_path,
        size_bytes,
    )
    .await;

    info!(
        "Homebrew upload: {} {} ({}) to repo {}",
        bottle.name, bottle.version, bottle.tag, repo_key
    );

    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "name": bottle.name,
            "version": bottle.version,
            "tag": bottle.tag,
            "rebuild": bottle.rebuild,
            "filename": canonical,
            "sha256": sha256,
        })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// DELETE /homebrew/{repo}/bottles/{filename}
// ---------------------------------------------------------------------------

async fn delete_bottle(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, filename)): Path<(String, String)>,
) -> Result<Response, Response> {
    let auth = require_auth_basic_scope(auth, "homebrew", "delete:artifacts")?;
    let repo = resolve_homebrew_repo(&state.db, &repo_key).await?;
    reject_unsupported_repo_type(&repo.repo_type)?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    proxy_helpers::reject_direct_delete_if_promotion_only(
        repo.promotion_only,
        auth.is_admin || auth.is_service_account,
    )?;

    let bottle = parse_filename(&filename)?;
    let (artifact_id, _) = find_bottle(&state.db, repo.id, &bottle.artifact_path())
        .await?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Bottle not found").into_response())?;

    // The same soft delete the REST API performs, so the side effects (search
    // index, usage ledger, sync fan-out, audit) match exactly. The formula
    // JSON is rendered from live rows, so the bottle drops out of the next
    // `brew update` with no index rewrite.
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    state
        .create_artifact_service(storage)
        .delete_by(artifact_id, Some(&auth))
        .await
        .map_err(|e| e.into_response())?;

    info!(
        "Homebrew delete: {} from repo {}",
        bottle.filename(),
        repo.key
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn bottle(name: &str, version: &str, tag: &str, rebuild: u32, at: i64) -> IndexedBottle {
        IndexedBottle {
            bottle: BottleName {
                name: name.into(),
                version: version.into(),
                tag: tag.into(),
                rebuild,
            },
            cellar: ":any".into(),
            sha256: format!("sha-{name}-{version}-{tag}-{rebuild}"),
            uploaded_at: at,
        }
    }

    const ROOT: &str = "https://ak.example/homebrew/tools/bottles";

    #[test]
    fn split_revision_separates_the_underscore_revision() {
        assert_eq!(split_revision("1.7.1"), ("1.7.1", 0));
        assert_eq!(split_revision("1.7.1_2"), ("1.7.1", 2));
        assert_eq!(split_revision("2024_beta"), ("2024_beta", 0));
        assert_eq!(split_revision("1.0_"), ("1.0_", 0));
    }

    #[test]
    fn formula_lists_every_tag_of_the_newest_version() {
        let formula = render_formula(
            &[
                bottle("jq", "1.7.0", "arm64_sonoma", 0, 100),
                bottle("jq", "1.7.1", "arm64_sonoma", 0, 200),
                bottle("jq", "1.7.1", "x86_64_linux", 0, 201),
            ],
            ROOT,
            "tools",
        )
        .unwrap();

        assert_eq!(formula["name"], "jq");
        assert_eq!(formula["versions"]["stable"], "1.7.1");
        assert_eq!(formula["revision"], 0);
        let stable = &formula["bottle"]["stable"];
        assert_eq!(stable["root_url"], ROOT);
        let files = stable["files"].as_object().unwrap();
        assert_eq!(files.len(), 2, "the older 1.7.0 bottle is not advertised");
        assert_eq!(
            files["arm64_sonoma"]["url"],
            format!("{ROOT}/jq-1.7.1.arm64_sonoma.bottle.tar.gz")
        );
        assert_eq!(
            files["arm64_sonoma"]["sha256"],
            "sha-jq-1.7.1-arm64_sonoma-0"
        );
        assert_eq!(files["x86_64_linux"]["cellar"], ":any");
    }

    #[test]
    fn highest_rebuild_serves_a_tag_and_sets_the_rebuild() {
        let formula = render_formula(
            &[
                bottle("jq", "1.7.1", "all", 0, 100),
                bottle("jq", "1.7.1", "all", 2, 90),
                bottle("jq", "1.7.1", "all", 1, 200),
            ],
            ROOT,
            "tools",
        )
        .unwrap();
        let stable = &formula["bottle"]["stable"];
        assert_eq!(stable["rebuild"], 2);
        assert_eq!(
            stable["files"]["all"]["url"],
            format!("{ROOT}/jq-1.7.1.all.bottle.2.tar.gz")
        );
    }

    #[test]
    fn a_revision_version_renders_as_stable_plus_revision() {
        let formula =
            render_formula(&[bottle("jq", "1.7.1_3", "all", 0, 1)], ROOT, "tools").unwrap();
        assert_eq!(formula["versions"]["stable"], "1.7.1");
        assert_eq!(formula["revision"], 3);
        assert_eq!(
            formula["bottle"]["stable"]["files"]["all"]["url"],
            format!("{ROOT}/jq-1.7.1_3.all.bottle.tar.gz")
        );
    }

    #[test]
    fn no_bottles_means_no_formula() {
        assert!(render_formula(&[], ROOT, "tools").is_none());
        assert!(render_formulae(Vec::new(), ROOT, "tools").is_empty());
    }

    #[test]
    fn index_has_one_formula_per_name_in_name_order() {
        let formulae = render_formulae(
            vec![
                bottle("yq", "4.0.0", "all", 0, 1),
                bottle("jq", "1.7.1", "all", 0, 2),
                bottle("jq", "1.7.1", "arm64_sonoma", 0, 3),
            ],
            ROOT,
            "tools",
        );
        let names: Vec<_> = formulae
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["jq", "yq"]);
    }

    #[test]
    fn row_without_metadata_is_not_advertised() {
        let row = |metadata| BottleRow {
            sha256: "abc".into(),
            created_at: chrono::Utc::now(),
            metadata,
        };
        assert!(row(None).into_indexed().is_none());
        assert!(row(Some(json!({"unrelated": 1}))).into_indexed().is_none());
        let indexed = row(Some(
            json!({"name": "jq", "version": "1.7.1", "tag": "all", "rebuild": 1}),
        ))
        .into_indexed()
        .unwrap();
        assert_eq!(indexed.bottle.rebuild, 1);
        assert_eq!(indexed.cellar, DEFAULT_CELLAR);
    }

    #[test]
    fn remote_and_virtual_repositories_are_refused() {
        assert!(reject_unsupported_repo_type("local").is_ok());
        assert_eq!(
            reject_unsupported_repo_type("remote").unwrap_err().status(),
            StatusCode::NOT_IMPLEMENTED
        );
        assert!(reject_unsupported_repo_type("virtual").is_err());
    }

    #[test]
    fn bottles_root_url_trims_the_trailing_slash() {
        let base = RequestBaseUrl("https://ak.example/".into());
        assert_eq!(bottles_root_url(&base, "tools"), ROOT);
    }

    #[test]
    fn bad_bottle_filename_is_a_400() {
        assert_eq!(
            parse_filename("not-a-bottle.zip").unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        assert!(parse_filename("jq--1.7.1.all.bottle.tar.gz").is_ok());
    }
}
