//! MCP registry write path, Phase 2/3 (#5253): `POST /validate`, the admin
//! edit (`PUT .../versions/{v}`) and soft delete (`DELETE .../versions/{v}`),
//! MCPB bundle upload and download (`.../versions/{v}/bundles/{file}`), and
//! the publish-side helpers `handlers::mcp` calls (tombstones, staged
//! bundles, audits, the `202` answer of a resolving publish, ticketed bundle
//! URLs).
//!
//! Every refusal is the MCP surface's problem+json with `Cache-Control:
//! no-store` (the builders in `handlers::mcp`). Nothing here opens an
//! outbound connection.

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use bytes::Bytes;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use super::mcp::{
    self as surface, admit_document, body_rejection, internal, mcp_error, not_found, problem,
    reproblem, served_entry, server_name, stored_row, versions_of, writable_repo, VersionRow,
};
use super::proxy_helpers::RepoInfo;
use crate::api::extractors::RequestBaseUrl;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::formats::mcp::{self as fmt, McpError, RegistryState, ServerStatus};
use crate::services::audit_service::AuditAction;
use crate::services::mcp_packages::{self, McpSettings};
use crate::services::mcp_resolver::{self as resolver, Resolution, Target};
use crate::services::mcp_write::{self as writes, Actor};
use crate::services::mcpb;

type HandlerResult = Result<Response, Response>;

/// Lifetime of a bundle download ticket handed out in a served document.
const BUNDLE_TICKET_TTL_SECS: i64 = 300;

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// Read routes (merged under the read routes' CORS layer): bundle download.
pub fn read_routes(api: &str) -> Router<SharedState> {
    let p = |tail: &str| format!("/:repo_key/{api}{tail}");
    Router::new()
        .route(
            &p("/servers/:ns/versions/:version/bundles/:file"),
            get(download_bundle_encoded),
        )
        .route(
            &p("/servers/:ns/:name/versions/:version/bundles/:file"),
            get(download_bundle_split),
        )
}

/// Write routes with the 256 KiB document limit: validate, edit, delete.
pub fn document_routes(api: &str) -> Router<SharedState> {
    let p = |tail: &str| format!("/:repo_key/{api}{tail}");
    Router::new()
        .route(&p("/validate"), post(validate))
        .route(
            &p("/servers/:ns/versions/:version"),
            put(edit_encoded).delete(delete_encoded),
        )
        .route(
            &p("/servers/:ns/:name/versions/:version"),
            put(edit_split).delete(delete_split),
        )
}

/// Bundle upload routes (streamed; capped at [`mcpb::MCPB_MAX_BYTES`]).
pub fn bundle_routes(api: &str) -> Router<SharedState> {
    let p = |tail: &str| format!("/:repo_key/{api}{tail}");
    Router::new()
        .route(
            &p("/servers/:ns/versions/:version/bundles/:file"),
            put(upload_bundle_encoded),
        )
        .route(
            &p("/servers/:ns/:name/versions/:version/bundles/:file"),
            put(upload_bundle_split),
        )
        .layer(DefaultBodyLimit::disable())
}

// ---------------------------------------------------------------------------
// Publish-side helpers
// ---------------------------------------------------------------------------

/// `409 mcp_version_exists` for a `name@version` this repository ever
/// stored (the tombstone ledger outlives a delete and a trash purge).
pub async fn refuse_tombstoned(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    version: &str,
) -> Result<(), Response> {
    match writes::version_tombstoned(db, repo_id, name, version).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(mcp_error(McpError::VersionExists)),
        Err(e) => Err(internal(e)),
    }
}

/// The `packages[]` entry AK adds for a staged bundle.
pub fn bundle_entry(base: &str, route: &str, sha256: &str) -> serde_json::Value {
    serde_json::json!({
        "registryType": "mcpb",
        "identifier": format!("{}/{route}", base.trim_end_matches('/')),
        "fileSha256": sha256,
        "transport": {"type": "stdio"},
    })
}

/// Bundles uploaded beside `name@version` before its publish, as `(file,
/// sha256)`.
async fn staged_bundles(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    version: &str,
) -> Result<Vec<(String, String)>, Response> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT a.path, a.checksum_sha256 FROM artifacts a \
         JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.name = $2 AND a.version = $3 \
           AND a.is_deleted = false AND m.format = 'mcpb' ORDER BY a.path",
    )
    .bind(repo_id)
    .bind(name)
    .bind(version)
    .fetch_all(db)
    .await
    .map_err(internal)?;
    Ok(rows
        .into_iter()
        .map(|(path, sha)| {
            let file = path.rsplit('/').next().unwrap_or_default().to_string();
            (file, sha.trim().to_string())
        })
        .collect())
}

/// When a document names no `mcpb` package but bundles were uploaded for its
/// version, add one `packages[]` entry per bundle (identifier = the bundle's
/// Artifact Keeper URL, `fileSha256` computed at upload). Under the `open`
/// policy nothing is added.
pub async fn add_staged_bundles(
    db: &PgPool,
    repo: &RepoInfo,
    settings: &McpSettings,
    server: &mut fmt::ServerJson,
    base: &str,
) -> Result<(), Response> {
    if settings.policy == fmt::PackagePolicy::Open
        || server.packages.iter().any(|p| p.registry_type == "mcpb")
    {
        return Ok(());
    }
    for (file, sha) in staged_bundles(db, repo.id, &server.name, &server.version).await? {
        if server.packages.len() >= fmt::MAX_PACKAGES {
            break;
        }
        let route = resolver::bundle_route(&repo.key, &server.name, &server.version, &file);
        let pkg: fmt::Package = serde_json::from_value(bundle_entry(base, &route, &sha))
            .map_err(internal)?;
        server.packages.push(pkg);
    }
    Ok(())
}

/// The publish answer: `200` with the served entry, or `202` with the entry
/// plus `status: "resolving"` and the indexes still being filled.
pub fn publish_answer(mut entry: serde_json::Value, res: &Resolution) -> Response {
    if res.pending.is_empty() {
        return surface::json_ok(StatusCode::OK, &entry);
    }
    entry["status"] = "resolving".into();
    entry["pendingPackages"] = res.pending.iter().map(|p| p.index).collect::<Vec<_>>().into();
    surface::json_ok(StatusCode::ACCEPTED, &entry)
}

/// `MCP_SERVER_PUBLISHED`.
pub fn audit_published(
    db: &PgPool,
    user: Uuid,
    repo: &RepoInfo,
    artifact_id: Uuid,
    server: &fmt::ServerJson,
    res: &Resolution,
) {
    writes::audit(
        db,
        AuditAction::McpServerPublished,
        Actor::User(user),
        &repo.key,
        Some(artifact_id),
        &server.name,
        &server.version,
        serde_json::json!({
            "repository_id": repo.id,
            "packages": server.packages.len(),
            "remotes": server.remotes.len(),
            "pinned": res.pins.len(),
            "resolving": res.pending.iter().map(|p| p.index).collect::<Vec<_>>(),
        }),
    );
}

/// `MCP_SERVER_STATUS_CHANGED`.
pub fn audit_status_changed(
    db: &PgPool,
    user: Uuid,
    repo: &RepoInfo,
    row: &VersionRow,
    from: ServerStatus,
    to: &RegistryState,
) {
    writes::audit(
        db,
        AuditAction::McpServerStatusChanged,
        Actor::User(user),
        &repo.key,
        Some(row.artifact_id),
        &row.name,
        &row.version,
        serde_json::json!({
            "from": from.as_str(),
            "to": to.status.as_str(),
            "status_message": to.status_message,
        }),
    );
}

/// Append a single-use download ticket to every bundle URL of an exact-read
/// entry for an authenticated caller, so a client that is handed the
/// document can download the bundle of a private registry without its own
/// credential. Best-effort: a ticket that cannot be minted leaves the URL as
/// it is (it still works with a credential).
pub async fn ticket_bundle_urls(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    stored: &fmt::StoredVersion,
    entry: &mut serde_json::Value,
    base: &str,
) {
    let Some(auth) = auth else {
        return;
    };
    let Some(packages) = entry
        .pointer_mut("/server/packages")
        .and_then(|p| p.as_array_mut())
    else {
        return;
    };
    for pin in &stored.pins {
        let Some(route) = pin.resolved.download_path.as_deref() else {
            continue;
        };
        let Some(pkg) = packages.get_mut(pin.index) else {
            continue;
        };
        let path = format!("/{route}");
        let minted = crate::services::auth_config_service::AuthConfigService::
            create_download_ticket_with_ttl(
                &state.db,
                auth.user_id,
                &auth.allowed_repo_ids,
                "mcpb-download",
                Some(&path),
                BUNDLE_TICKET_TTL_SECS,
            )
            .await;
        match minted {
            Ok(ticket) => {
                pkg["identifier"] =
                    format!("{}{path}?ticket={ticket}", base.trim_end_matches('/')).into();
            }
            Err(e) => tracing::warn!(error = %e, "MCP: could not mint a bundle download ticket"),
        }
    }
}

// ---------------------------------------------------------------------------
// POST /validate
// ---------------------------------------------------------------------------

/// One upstream `ValidationIssue`.
fn issue(e: &McpError) -> serde_json::Value {
    let (kind, path) = match e {
        McpError::Invalid { path, .. } => ("schema", path.clone()),
        McpError::OciLegacyFields { index }
        | McpError::OciFloatingTag { index }
        | McpError::ExternalRegistry { index, .. }
        | McpError::PackageNotFound { index, .. }
        | McpError::PackageVersionUnpinned { index }
        | McpError::OciNotAnImage { index } => ("semantic", format!("packages[{index}]")),
        McpError::ReservedNamespace { .. } | McpError::NamespaceNotAllowed { .. } => {
            ("semantic", "name".to_string())
        }
        McpError::VersionExists => ("semantic", "version".to_string()),
        _ => ("semantic", String::new()),
    };
    serde_json::json!({
        "type": kind,
        "path": path,
        "message": e.detail(),
        "severity": "error",
        "reference": e.code(),
    })
}

/// The upstream `ValidationResult` (`{valid, issues}`), plus `packages`: what
/// a publish would do with each package (`pinned` or `fill`, the latter
/// meaning the publish would answer `202` and fill a Remote).
pub fn validation_result(outcome: Result<&Resolution, &McpError>) -> serde_json::Value {
    match outcome {
        Err(e) => serde_json::json!({"valid": false, "issues": [issue(e)]}),
        Ok(res) => {
            let mut packages: Vec<serde_json::Value> = res
                .pins
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "index": p.index, "registryType": p.registry_type, "outcome": "pinned",
                    })
                })
                .chain(res.pending.iter().map(|p| {
                    serde_json::json!({
                        "index": p.index, "registryType": p.registry_type, "outcome": "fill",
                        "fillRepository": p.fill_repository,
                    })
                }))
                .collect();
            packages.sort_by_key(|p| p["index"].as_u64());
            let issues: Vec<serde_json::Value> = res
                .pending
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "type": "semantic",
                        "path": format!("packages[{}]", p.index),
                        "message": format!(
                            "{} {} is not in repository '{}' yet; a publish answers 202 and \
                             fills it through the repository's proxy",
                            p.registry_type, p.identifier, p.fill_repository
                        ),
                        "severity": "info",
                        "reference": "mcp_package_fill",
                    })
                })
                .collect();
            serde_json::json!({"valid": true, "issues": issues, "packages": packages})
        }
    }
}

/// What one `/validate` call may check, by caller (see [`validate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidateScope {
    /// Whether `name@version` is taken (a holder may see held versions).
    pub version_taken: bool,
    /// Package resolution against the backing repositories.
    pub packages: bool,
}

/// The `packages` / `issues` members for a document whose packages were not
/// resolved because the caller may not see every backing repository.
fn unchecked_packages(mut result: serde_json::Value, count: usize) -> serde_json::Value {
    result["packages"] = (0..count)
        .map(|i| serde_json::json!({"index": i, "outcome": "unchecked"}))
        .collect::<Vec<_>>()
        .into();
    if count > 0 {
        if let Some(issues) = result["issues"].as_array_mut() {
            issues.push(serde_json::json!({
                "type": "semantic",
                "path": "packages",
                "message": "packages were not resolved: send a credential that can read this \
                            registry's backing repositories to check them",
                "severity": "info",
                "reference": "mcp_packages_unchecked",
            }));
        }
    }
    result
}

/// Which checks a caller of `/validate` gets: the version-taken check for a
/// repository holder (it would otherwise reveal a held version), package
/// resolution for an authenticated caller who may read every mapped backing
/// repository (it would otherwise reveal what a private backing repository
/// holds).
async fn validate_scope(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    settings: &McpSettings,
) -> ValidateScope {
    let Some(a) = auth else {
        return ValidateScope {
            version_taken: false,
            packages: false,
        };
    };
    let holder = surface::audience(&state.db, Some(a), repo.id).await
        == fmt::GateAudience::ReasonGated;
    let mut packages = true;
    for backing in settings.repos.values() {
        if !matches!(mcp_packages::caller_may_map(&state.db, a, backing.id).await, Ok(true)) {
            packages = false;
            break;
        }
    }
    ValidateScope {
        version_taken: holder,
        packages,
    }
}

/// `POST /validate` (`/v0` and `/v0.1`): the publish checks without any
/// write (no row, no pin, no retention hold, no fill). No credential is
/// needed beyond reading the registry (`mcp-publisher validate` sends
/// none); the checks that depend on what the caller may see are scoped by
/// [`validate_scope`]. Always `200` with `{valid, issues, packages}` for a
/// document; transport errors (unknown repository, body over the cap) are
/// the usual refusals.
async fn validate(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let repo = surface::resolve_mcp_repo(&state.db, &repo_key).await?;
    surface::reject_if_not_hosted_read(&repo)?;
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let settings = mcp_packages::load_settings(&state.db, repo.id)
        .await
        .map_err(mcp_error)?;
    let scope = validate_scope(&state, auth.as_ref(), &repo, &settings).await;
    let checked: Result<(fmt::ServerJson, Option<Resolution>), McpError> = async {
        let mut server = admit_document(&body, &settings)?;
        if scope.version_taken
            && writes::version_tombstoned(&state.db, repo.id, &server.name, &server.version)
                .await
                .map_err(|e| McpError::Internal(e.to_string()))?
        {
            return Err(McpError::VersionExists);
        }
        if !scope.packages {
            return Ok((server, None));
        }
        add_staged_bundles(&state.db, &repo, &settings, &mut server, base.as_str())
            .await
            .map_err(|_| McpError::Internal("bundle lookup failed".into()))?;
        let res = resolver::resolve_document(
            &state,
            &settings,
            Target {
                repo_id: repo.id,
                repo_key: &repo.key,
                name: &server.name,
                version: &server.version,
            },
            &server,
            base.as_str(),
        )
        .await?;
        Ok((server, Some(res)))
    }
    .await;
    if let Err(McpError::Internal(cause)) = &checked {
        return Err(internal(cause));
    }
    let body = match &checked {
        Ok((_, Some(res))) => validation_result(Ok(res)),
        Ok((server, None)) => unchecked_packages(
            validation_result(Ok(&Resolution::default())),
            server.packages.len(),
        ),
        Err(e) => validation_result(Err(e)),
    };
    Ok(surface::json_ok(StatusCode::OK, &body))
}

// ---------------------------------------------------------------------------
// PUT .../versions/{v} (admin edit)
// ---------------------------------------------------------------------------

async fn edit_encoded(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, version)): Path<(String, String, String)>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let name = server_name(&ns, None);
    edit_impl(&state, auth, &repo_key, &name, &version, &headers, &body, &base).await
}

#[allow(clippy::too_many_arguments)]
async fn edit_split(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, name, version)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let name = server_name(&ns, Some(&name));
    edit_impl(&state, auth, &repo_key, &name, &version, &headers, &body, &base).await
}

/// The hosted-write gates plus repository administration (instance admin,
/// or the `admin` action on the repository).
async fn admin_repo(
    state: &SharedState,
    auth: Option<AuthExtension>,
    repo_key: &str,
) -> Result<(AuthExtension, RepoInfo), Response> {
    let (ext, repo) = writable_repo(state, auth, repo_key).await?;
    repo.reject_if_promotion_only(false).map_err(reproblem)?;
    if super::repositories::require_repo_admin(&ext, repo.id, &state.permission_service)
        .await
        .is_err()
    {
        return Err(problem(
            403,
            "mcp_forbidden",
            "Editing a published server version needs repository administration",
            serde_json::json!({}),
        ));
    }
    Ok((ext, repo))
}

/// The live (not trashed) row of `name@version`, or the unknown-name 404.
async fn live_version(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    version: &str,
) -> Result<VersionRow, Response> {
    versions_of(db, repo_id, name)
        .await?
        .into_iter()
        .find(|r| r.version == version)
        .ok_or_else(not_found)
}

/// Whether two documents name the same packages (pins are kept then).
pub fn packages_unchanged(stored_server: &serde_json::Value, next: &fmt::ServerJson) -> bool {
    let stored = stored_server
        .get("packages")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    serde_json::to_value(&next.packages).ok() == Some(stored)
}

/// Body name/version must be the path's (an edit never renames).
fn check_same_identity(server: &fmt::ServerJson, name: &str, version: &str) -> Result<(), McpError> {
    if server.name != name || server.version != version {
        return Err(McpError::invalid(
            "",
            format!(
                "the document names {}@{} but the route names {name}@{version}; an edit cannot \
                 rename a version",
                server.name, server.version
            ),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn edit_impl(
    state: &SharedState,
    auth: Option<AuthExtension>,
    repo_key: &str,
    name: &str,
    version: &str,
    headers: &HeaderMap,
    body: &[u8],
    base: &RequestBaseUrl,
) -> HandlerResult {
    let (ext, repo) = admin_repo(state, auth, repo_key).await?;
    let settings = mcp_packages::load_settings(&state.db, repo.id)
        .await
        .map_err(mcp_error)?;
    let mut server = admit_document(body, &settings).map_err(mcp_error)?;
    check_same_identity(&server, name, version).map_err(mcp_error)?;
    let current = live_version(&state.db, repo.id, name, version).await?;
    add_staged_bundles(&state.db, &repo, &settings, &mut server, base.as_str()).await?;
    let keep_pins = packages_unchanged(&current.stored.server, &server);
    let resolution = if keep_pins {
        Resolution {
            pins: current.stored.pins.clone(),
            pending: Vec::new(),
        }
    } else {
        resolver::resolve_document(
            state,
            &settings,
            Target {
                repo_id: repo.id,
                repo_key: &repo.key,
                name,
                version,
            },
            &server,
            base.as_str(),
        )
        .await
        .map_err(mcp_error)?
    };
    let bytes = fmt::canonical_bytes(&server);
    let sha256 = fmt::sha256_hex(&bytes);
    if sha256 == current.checksum.trim() {
        // Nothing to change.
        let entry = served_entry(&current, &repo, base.as_str(), current.stored.registry.is_latest);
        return Ok(surface::json_ok(StatusCode::OK, &entry));
    }
    let key = fmt::storage_key(name, version, &sha256);
    super::proxy_helpers::put_artifact_bytes(state, &repo, &key, Bytes::from(bytes.clone()))
        .await
        .map_err(reproblem)?;
    let now = Utc::now();
    let mut registry = current.stored.registry.clone();
    registry.updated_at = now;
    let doc = fmt::metadata_doc(&server, &registry, settings.policy, &resolution.pins);
    let doc = resolver::metadata_with_resolution(
        &state.db,
        doc,
        &resolution,
        ext.user_id,
        base.as_str(),
    )
    .await
    .map_err(mcp_error)?;
    let hold_rows = match write_edit(state, &repo, &current, &doc, &key, &sha256, bytes.len() as i64, &resolution, ext.user_id, keep_pins).await {
        Ok(rows) => rows,
        Err(resp) => {
            surface::discard_unreferenced_bytes(state, &repo, &key).await;
            return Err(resp);
        }
    };
    let _ = headers;
    for (backing, row) in hold_rows {
        crate::services::scanner_service::trigger_scan_on_upload(
            &state.db,
            state.scanner_service.clone(),
            backing,
            row,
        )
        .await;
    }
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        current.artifact_id,
    )
    .await;
    writes::audit(
        &state.db,
        AuditAction::McpServerEdited,
        Actor::User(ext.user_id),
        &repo.key,
        Some(current.artifact_id),
        name,
        version,
        serde_json::json!({
            "previous_sha256": current.checksum.trim(),
            "sha256": sha256,
            "packages_changed": !keep_pins,
            "resolving": resolution.pending.iter().map(|p| p.index).collect::<Vec<_>>(),
        }),
    );
    if !keep_pins && resolution.pending.is_empty() {
        surface::audit_pins(
            &state.db,
            ext.user_id,
            &repo,
            current.artifact_id,
            &server,
            &resolution.pins,
        );
    }
    let row = stored_row(&state.db, current.artifact_id).await?;
    let latest = surface::row_is_latest(state, &repo, &row, settings.policy).await;
    let entry = served_entry(&row, &repo, base.as_str(), latest);
    Ok(publish_answer(entry, &resolution))
}

/// The edit's database half: the artifact row's bytes, the metadata, the
/// retention holds of new pins and (when packages are being filled) the
/// fill job, in one transaction under the per-server lock.
#[allow(clippy::too_many_arguments)]
async fn write_edit(
    state: &SharedState,
    repo: &RepoInfo,
    current: &VersionRow,
    doc: &serde_json::Value,
    key: &str,
    sha256: &str,
    size: i64,
    res: &Resolution,
    user: Uuid,
    keep_pins: bool,
) -> Result<Vec<(Uuid, Uuid)>, Response> {
    let mut tx = state.db.begin().await.map_err(internal)?;
    surface::lock_server(&mut tx, repo.id, &current.name)
        .await
        .map_err(internal)?;
    sqlx::query(
        "UPDATE artifacts SET size_bytes = $2, checksum_sha256 = $3, storage_key = $4, \
         updated_at = NOW() WHERE id = $1",
    )
    .bind(current.artifact_id)
    .bind(size)
    .bind(sha256)
    .bind(key)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query("UPDATE artifact_metadata SET metadata = $2 WHERE artifact_id = $1")
        .bind(current.artifact_id)
        .bind(doc)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let hold_rows = if keep_pins {
        Vec::new()
    } else {
        mcp_packages::hold_pins(&mut tx, &res.pins)
            .await
            .map_err(internal)?
    };
    if res.pending.is_empty() {
        sqlx::query("DELETE FROM mcp_resolve_jobs WHERE artifact_id = $1")
            .bind(current.artifact_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
    } else {
        resolver::enqueue(&mut tx, current.artifact_id, repo.id, user)
            .await
            .map_err(internal)?;
    }
    surface::recompute_latest_in(&mut tx, repo.id, &current.name)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(hold_rows)
}

// ---------------------------------------------------------------------------
// DELETE .../versions/{v} (soft delete)
// ---------------------------------------------------------------------------

async fn delete_encoded(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, version)): Path<(String, String, String)>,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let name = server_name(&ns, None);
    delete_impl(&state, auth, &repo_key, &name, &version, &body, &base).await
}

async fn delete_split(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, name, version)): Path<(String, String, String, String)>,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let name = server_name(&ns, Some(&name));
    delete_impl(&state, auth, &repo_key, &name, &version, &body, &base).await
}

/// The optional `{"statusMessage": "..."}` body of a delete.
fn delete_message(body: &[u8]) -> Result<Option<String>, McpError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct DeleteBody {
        #[serde(default)]
        status_message: Option<String>,
    }
    serde_json::from_slice::<DeleteBody>(body)
        .map(|b| b.status_message)
        .map_err(|e| McpError::invalid("", format!("invalid delete body: {e}")))
}

/// Soft delete: the version's status becomes `deleted` (it answers `404`
/// unless `include_deleted=true`, upstream parity) and its tombstone keeps
/// the version from ever being published again. The artifact row and bytes
/// stay. Needs repository write, as a status change does.
async fn delete_impl(
    state: &SharedState,
    auth: Option<AuthExtension>,
    repo_key: &str,
    name: &str,
    version: &str,
    body: &[u8],
    base: &RequestBaseUrl,
) -> HandlerResult {
    let (ext, repo) = writable_repo(state, auth, repo_key).await?;
    repo.reject_if_promotion_only(false).map_err(reproblem)?;
    let message = delete_message(body).map_err(mcp_error)?;
    let mut tx = state.db.begin().await.map_err(internal)?;
    surface::lock_server(&mut tx, repo.id, name)
        .await
        .map_err(internal)?;
    let row = versions_of(&mut *tx, repo.id, name)
        .await?
        .into_iter()
        .find(|r| r.version == version)
        .ok_or_else(not_found)?;
    let updated = surface::apply_status(
        &row.stored.registry,
        ServerStatus::Deleted,
        message.as_deref(),
        Utc::now(),
    )
    .map_err(mcp_error)?;
    surface::write_registry(&mut *tx, row.artifact_id, &updated).await?;
    sqlx::query(
        "INSERT INTO mcp_version_tombstones (repository_id, name, version, first_artifact_id) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(repo.id)
    .bind(name)
    .bind(version)
    .bind(row.artifact_id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    surface::recompute_latest_in(&mut tx, repo.id, name)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    writes::audit(
        &state.db,
        AuditAction::McpServerDeleted,
        Actor::User(ext.user_id),
        &repo.key,
        Some(row.artifact_id),
        name,
        version,
        serde_json::json!({
            "from": row.stored.registry.status.as_str(),
            "status_message": message,
        }),
    );
    let row = stored_row(&state.db, row.artifact_id).await?;
    Ok(surface::json_ok(
        StatusCode::OK,
        &served_entry(&row, &repo, base.as_str(), false),
    ))
}

// ---------------------------------------------------------------------------
// Bundles
// ---------------------------------------------------------------------------

/// Validate the coordinates of a bundle route.
fn check_bundle_coordinates(name: &str, version: &str, file: &str) -> Result<(), McpError> {
    fmt::check_name(name)?;
    fmt::check_version("version", version)?;
    if !mcpb::valid_file_name(file) {
        return Err(McpError::invalid(
            "file",
            "a bundle file is named <name>.mcpb (letters, digits, `.`, `_`, `-`)",
        ));
    }
    Ok(())
}

/// Refuse a bundle whose signature does not satisfy the repository: an
/// invalid signature always, an unsigned one under
/// `mcp_require_bundle_signature`. `None` when it may be stored.
pub fn signature_refusal(
    sig: &mcpb::SignatureInfo,
    require_signature: bool,
) -> Option<(&'static str, String)> {
    match sig.state {
        mcpb::SignatureState::Valid => None,
        mcpb::SignatureState::Invalid => Some((
            "mcp_bundle_signature_invalid",
            format!(
                "the bundle's signature does not verify: {}",
                sig.reason.as_deref().unwrap_or("invalid")
            ),
        )),
        mcpb::SignatureState::Unsigned if require_signature => Some((
            "mcp_bundle_unsigned",
            "this registry requires signed MCPB bundles (mcpb sign)".to_string(),
        )),
        mcpb::SignatureState::Unsigned => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn upload_bundle_encoded(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, version, file)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Body,
) -> HandlerResult {
    let name = server_name(&ns, None);
    upload_bundle(&state, auth, &repo_key, &name, &version, &file, &headers, &base, body).await
}

#[allow(clippy::too_many_arguments)]
async fn upload_bundle_split(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, name, version, file)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Body,
) -> HandlerResult {
    let name = server_name(&ns, Some(&name));
    upload_bundle(&state, auth, &repo_key, &name, &version, &file, &headers, &base, body).await
}

/// The 201 answer of a bundle upload.
pub fn bundle_answer(
    base: &str,
    route: &str,
    artifact_id: Uuid,
    facts: &serde_json::Value,
) -> serde_json::Value {
    let sha = facts["fileSha256"].as_str().unwrap_or_default();
    let mut out = facts.clone();
    out["artifactId"] = serde_json::json!(artifact_id);
    out["downloadUrl"] = format!("{}/{route}", base.trim_end_matches('/')).into();
    out["packageEntry"] = bundle_entry(base, route, sha);
    out
}

/// `PUT .../versions/{v}/bundles/{file}.mcpb`: upload a bundle for a version
/// that is not published yet. The body is streamed to staging while it is
/// hashed, the manifest read and the signature verified; the bundle is then
/// stored as an artifact beside the version (path
/// `servers/<name>/<version>/bundles/<file>`). Publishing the version then
/// pins it by `fileSha256`, or adds it as a `packages[]` entry.
#[allow(clippy::too_many_arguments)]
async fn upload_bundle(
    state: &SharedState,
    auth: Option<AuthExtension>,
    repo_key: &str,
    name: &str,
    version: &str,
    file: &str,
    headers: &HeaderMap,
    base: &RequestBaseUrl,
    body: Body,
) -> HandlerResult {
    let (ext, repo) = writable_repo(state, auth, repo_key).await?;
    repo.reject_if_promotion_only(false).map_err(reproblem)?;
    check_bundle_coordinates(name, version, file).map_err(mcp_error)?;
    let settings = mcp_packages::load_settings(&state.db, repo.id)
        .await
        .map_err(mcp_error)?;
    if fmt::is_reserved_namespace(name) {
        return Err(mcp_error(McpError::ReservedNamespace {
            namespace: fmt::namespace_of(name).to_string(),
        }));
    }
    if !fmt::namespace_allowed(name, &settings.namespace_allow) {
        return Err(mcp_error(McpError::NamespaceNotAllowed {
            namespace: fmt::namespace_of(name).to_string(),
        }));
    }
    // Bundles belong to a version before its publish; a published (or ever
    // published) version is write-once.
    refuse_tombstoned(&state.db, repo.id, name, version).await?;
    if super::upload_body::declared_content_length(headers)
        .is_some_and(|n| n > mcpb::MCPB_MAX_BYTES as u64)
    {
        return Err(bundle_too_large());
    }
    let path = resolver::bundle_path(name, version, file);
    let limited = Body::new(http_body_util::Limited::new(body, mcpb::MCPB_MAX_BYTES));
    let (staged, digests) = super::repositories::GenericStagedBody::stage_for_repo(
        state,
        &repo,
        limited.into_data_stream(),
    )
    .await
    .map_err(|resp| {
        if resp.status() == StatusCode::PAYLOAD_TOO_LARGE {
            bundle_too_large()
        } else {
            reproblem(resp)
        }
    })?;
    if staged.size_bytes() as usize > mcpb::MCPB_MAX_BYTES {
        return Err(bundle_too_large());
    }
    if staged.is_empty() {
        return Err(bundle_invalid("the bundle is empty"));
    }
    let facts = inspect_staged(state, &repo, &staged, &digests.sha256).await?;
    let require = crate::services::mcp_settings::load(&state.db, repo.id, &repo.repo_type)
        .await
        .map_err(internal)?
        .mcp_require_bundle_signature
        .unwrap_or(false);
    if let Some((code, detail)) = signature_refusal(&facts.signature, require) {
        writes::audit(
            &state.db,
            AuditAction::McpBundleSignatureRejected,
            Actor::User(ext.user_id),
            &repo.key,
            None,
            name,
            version,
            serde_json::json!({
                "file": file,
                "file_sha256": facts.file_sha256,
                "signature": facts.signature,
                "require_signature": require,
                "error": code,
            }),
        );
        return Err(problem(422, code, &detail, serde_json::json!({})));
    }
    // A re-upload of the identical bytes is idempotent; other bytes under
    // the same file name are a conflict.
    let existing: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, checksum_sha256 FROM artifacts WHERE repository_id = $1 AND path = $2 \
         AND is_deleted = false",
    )
    .bind(repo.id)
    .bind(&path)
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let route = resolver::bundle_route(&repo.key, name, version, file);
    let stored_facts = serde_json::json!({
        "file": file,
        "fileSha256": facts.file_sha256,
        "size": facts.size,
        "signature": facts.signature,
        "manifest": facts.manifest,
    });
    if let Some((id, sha)) = existing {
        if sha.trim() == digests.sha256 {
            return Ok(surface::json_ok(
                StatusCode::OK,
                &bundle_answer(base.as_str(), &route, id, &stored_facts),
            ));
        }
        return Err(problem(
            409,
            "mcp_bundle_exists",
            "a different bundle is already stored under this file name for this version",
            serde_json::json!({}),
        ));
    }
    let storage_key = format!("mcp/{name}/{version}/bundles/{}/{file}", digests.sha256);
    let size_bytes = staged.size_bytes();
    super::proxy_helpers::put_staged_body(
        state,
        &repo,
        super::publish_quota::PublishAt::StorageKey(&storage_key),
        &storage_key,
        staged,
        &digests,
    )
    .await
    .map_err(reproblem)?;
    let committed = insert_bundle_row(
        &state.db,
        super::proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &path,
            name,
            version,
            size_bytes,
            checksum_sha256: &digests.sha256,
            content_type: "application/zip",
            storage_key: &storage_key,
            uploaded_by: ext.user_id,
        },
        &stored_facts,
    )
    .await;
    let artifact_id = match committed {
        Ok(id) => id,
        Err(resp) => {
            surface::discard_unreferenced_bytes(state, &repo, &storage_key).await;
            return Err(resp);
        }
    };
    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
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
        repo.id,
        "mcp",
        name,
        version,
        size_bytes,
        &digests.sha256,
        None,
    )
    .await;
    super::queue_push_sync_tasks_for_upload(
        &state.db,
        headers,
        repo.id,
        artifact_id,
        &path,
        size_bytes,
    )
    .await;
    tracing::info!("MCP bundle upload: {name}@{version} {file} to repo {}", repo.key);
    Ok(surface::json_ok(
        StatusCode::CREATED,
        &bundle_answer(base.as_str(), &route, artifact_id, &stored_facts),
    ))
}

fn bundle_too_large() -> Response {
    problem(
        413,
        "mcp_bundle_too_large",
        &format!(
            "MCPB bundles are limited to {} MiB",
            mcpb::MCPB_MAX_BYTES / (1024 * 1024)
        ),
        serde_json::json!({}),
    )
}

fn bundle_invalid(detail: &str) -> Response {
    problem(400, "mcp_bundle_invalid", detail, serde_json::json!({}))
}

/// Inspect a staged bundle off the async runtime, within the shared archive
/// extraction budget.
async fn inspect_staged(
    state: &SharedState,
    repo: &RepoInfo,
    staged: &super::repositories::GenericStagedBody,
    sha256: &str,
) -> Result<mcpb::BundleFacts, Response> {
    let local = super::repositories::materialize_staged_for_repo(state, repo, staged).await?;
    let path = local.path().to_path_buf();
    let sha = sha256.to_string();
    let joined = crate::util::bounded_archive::with_ingest_extraction_async(|| async move {
        tokio::task::spawn_blocking(move || mcpb::inspect_file(&path, &sha)).await
    })
    .await
    .map_err(|e| reproblem(e.into_response()))?;
    drop(local);
    match joined {
        Ok(Ok(facts)) => Ok(facts),
        Ok(Err(e)) => Err(bundle_invalid(&e.0)),
        Err(e) => Err(internal(e)),
    }
}

/// The bundle's artifact row and its facts, quota-admitted, in one
/// transaction.
async fn insert_bundle_row(
    db: &PgPool,
    artifact: super::proxy_helpers::NewArtifact<'_>,
    facts: &serde_json::Value,
) -> Result<Uuid, Response> {
    let mut tx = super::publish_quota::begin_admitted_publish(
        db,
        artifact.repository_id,
        artifact.path,
        artifact.size_bytes,
    )
    .await?;
    let id = super::proxy_helpers::insert_artifact_row(&mut tx, artifact)
        .await
        .map_err(|_| {
            problem(
                409,
                "mcp_bundle_exists",
                "a bundle is already stored under this file name for this version",
                serde_json::json!({}),
            )
        })?;
    sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, 'mcpb', $2)",
    )
    .bind(id)
    .bind(facts)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(id)
}

async fn download_bundle_encoded(
    State(state): State<SharedState>,
    Path((repo_key, ns, version, file)): Path<(String, String, String, String)>,
) -> HandlerResult {
    download_bundle(&state, &repo_key, &server_name(&ns, None), &version, &file).await
}

async fn download_bundle_split(
    State(state): State<SharedState>,
    Path((repo_key, ns, name, version, file)): Path<(String, String, String, String, String)>,
) -> HandlerResult {
    download_bundle(&state, &repo_key, &server_name(&ns, Some(&name)), &version, &file).await
}

/// `GET .../versions/{v}/bundles/{file}`: a bundle of a published version,
/// gated by its own download gate (quarantine, scan policy). A bundle of a
/// version that is not published, or that is `deleted`, answers the
/// unknown-name 404, as does a held bundle for every caller (its reason is
/// on the artifact API). Streamed from storage.
async fn download_bundle(
    state: &SharedState,
    repo_key: &str,
    name: &str,
    version: &str,
    file: &str,
) -> HandlerResult {
    let repo = surface::resolve_mcp_repo(&state.db, repo_key).await?;
    surface::reject_if_not_hosted_read(&repo)?;
    if check_bundle_coordinates(name, version, file).is_err() {
        return Err(not_found());
    }
    let published = versions_of(&state.db, repo.id, name)
        .await?
        .into_iter()
        .any(|r| r.version == version && r.stored.registry.status != ServerStatus::Deleted);
    if !published {
        return Err(not_found());
    }
    let row: Option<(Uuid, String, i64, String)> = sqlx::query_as(
        "SELECT a.id, a.storage_key, a.size_bytes, a.checksum_sha256 FROM artifacts a \
         JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false AND m.format = 'mcpb'",
    )
    .bind(repo.id)
    .bind(resolver::bundle_path(name, version, file))
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let Some((id, key, size, sha)) = row else {
        return Err(not_found());
    };
    match crate::services::quarantine_service::enforce_download_gate(&state.db, id).await {
        Ok(()) => {}
        Err(e) => {
            return Err(match mcp_packages::outcome_for_gate_error(&e) {
                fmt::GateOutcome::Unavailable => problem(
                    503,
                    "mcp_gate_unavailable",
                    "The registry could not evaluate this bundle's gates; retry later",
                    serde_json::json!({}),
                ),
                _ => not_found(),
            })
        }
    }
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(internal)?;
    let stream = storage.get_stream(&key).await.map_err(internal)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CONTENT_LENGTH, size)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{file}\""),
        )
        .header("X-Checksum-Sha256", sha.trim())
        .header(header::CACHE_CONTROL, "private, no-store")
        .body(Body::from_stream(stream))
        .map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::Request;

    #[test]
    fn signature_policy() {
        let mut sig = mcpb::inspect(include_bytes!("../../../tests/fixtures/mcpb/echo-unsigned.mcpb"))
            .unwrap()
            .signature;
        assert!(signature_refusal(&sig, false).is_none());
        assert_eq!(signature_refusal(&sig, true).unwrap().0, "mcp_bundle_unsigned");
        sig.state = mcpb::SignatureState::Invalid;
        assert_eq!(
            signature_refusal(&sig, false).unwrap().0,
            "mcp_bundle_signature_invalid"
        );
        sig.state = mcpb::SignatureState::Valid;
        assert!(signature_refusal(&sig, true).is_none());
    }

    #[test]
    fn small_helpers() {
        assert!(check_bundle_coordinates("com.acme/echo", "1.0.0", "echo.mcpb").is_ok());
        assert!(check_bundle_coordinates("com.acme/echo", "latest", "echo.mcpb").is_err());
        assert!(check_bundle_coordinates("bad", "1.0.0", "echo.mcpb").is_err());
        assert!(check_bundle_coordinates("com.acme/echo", "1.0.0", "echo.zip").is_err());
        assert_eq!(delete_message(b"").unwrap(), None);
        assert_eq!(
            delete_message(br#"{"statusMessage":"gone"}"#).unwrap().as_deref(),
            Some("gone")
        );
        assert!(delete_message(br#"{"other":1}"#).is_err());
        let e = bundle_entry("https://ak.test/", "mcp/r/v0.1/servers/a/b/versions/1/bundles/x.mcpb", "ab");
        assert_eq!(
            e["identifier"],
            "https://ak.test/mcp/r/v0.1/servers/a/b/versions/1/bundles/x.mcpb"
        );
        let a = bundle_answer("https://ak.test", "r/x", Uuid::nil(), &serde_json::json!({"fileSha256": "ab"}));
        assert_eq!(a["downloadUrl"], "https://ak.test/r/x");
        assert_eq!(a["packageEntry"]["fileSha256"], "ab");
        assert_eq!(bundle_too_large().status(), 413);
        assert_eq!(bundle_invalid("x").status(), 400);
    }

    #[test]
    fn validation_result_shapes() {
        let err = McpError::PackageNotFound {
            index: 1,
            detail: "missing".into(),
        };
        let v = validation_result(Err(&err));
        assert_eq!(v["valid"], false);
        assert_eq!(v["issues"][0]["path"], "packages[1]");
        assert_eq!(v["issues"][0]["reference"], "mcp_package_not_found");
        assert_eq!(v["issues"][0]["severity"], "error");
        let v = validation_result(Err(&McpError::invalid("name", "bad")));
        assert_eq!((v["issues"][0]["type"].as_str(), v["issues"][0]["path"].as_str()), (Some("schema"), Some("name")));
        assert_eq!(validation_result(Err(&McpError::VersionExists))["issues"][0]["path"], "version");
        assert_eq!(
            validation_result(Err(&McpError::ReservedNamespace { namespace: "x".into() }))["issues"][0]["path"],
            "name"
        );
        let res = Resolution {
            pins: Vec::new(),
            pending: vec![resolver::Pending {
                index: 0,
                registry_type: "npm".into(),
                identifier: "@acme/x".into(),
                version: Some("1.0.0".into()),
                fill_repository: "npm-remote".into(),
                fill_repository_id: Uuid::nil(),
                fill_format: "npm".into(),
            }],
        };
        let v = validation_result(Ok(&res));
        assert_eq!(v["valid"], true);
        assert_eq!(v["packages"][0]["outcome"], "fill");
        assert_eq!(v["issues"][0]["severity"], "info");
        let unchecked = unchecked_packages(validation_result(Ok(&Resolution::default())), 2);
        assert_eq!(unchecked["packages"][1]["outcome"], "unchecked");
        assert_eq!(unchecked["issues"][0]["reference"], "mcp_packages_unchecked");
        assert!(unchecked_packages(validation_result(Ok(&Resolution::default())), 0)["issues"]
            .as_array()
            .unwrap()
            .is_empty());
        let answer = publish_answer(serde_json::json!({"server": {}}), &res);
        assert_eq!(answer.status(), StatusCode::ACCEPTED);
        assert_eq!(
            publish_answer(serde_json::json!({}), &Resolution::default()).status(),
            StatusCode::OK
        );
    }

    #[test]
    fn edit_identity_and_package_comparison() {
        let s: fmt::ServerJson = serde_json::from_value(serde_json::json!({
            "name": "com.acme/a", "description": "d", "version": "1.0.0",
            "remotes": [{"type": "streamable-http", "url": "https://x.test/mcp"}],
        }))
        .unwrap();
        assert!(check_same_identity(&s, "com.acme/a", "1.0.0").is_ok());
        assert!(check_same_identity(&s, "com.acme/b", "1.0.0").is_err());
        assert!(packages_unchanged(&serde_json::json!({}), &s));
        assert!(packages_unchanged(&serde_json::json!({"packages": []}), &s));
        assert!(!packages_unchanged(
            &serde_json::json!({"packages": [{"registryType": "npm"}]}),
            &s
        ));
    }

    // -----------------------------------------------------------------------
    // DB-backed
    // -----------------------------------------------------------------------

    const UNSIGNED: &[u8] = include_bytes!("../../../tests/fixtures/mcpb/echo-unsigned.mcpb");
    const SIGNED: &[u8] = include_bytes!("../../../tests/fixtures/mcpb/echo-signed.mcpb");
    const TAMPERED: &[u8] = include_bytes!("../../../tests/fixtures/mcpb/echo-tampered.mcpb");

    struct Env {
        fx: tdh::Fixture,
        state: SharedState,
        extra: Vec<(Uuid, std::path::PathBuf)>,
    }

    impl Env {
        async fn new() -> Option<Self> {
            let fx = tdh::Fixture::setup("local", "mcp").await?;
            let proxy =
                tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
            let state =
                tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
            Some(Self {
                fx,
                state,
                extra: Vec::new(),
            })
        }
        fn app(&self, auth: Option<AuthExtension>) -> Router {
            let r = super::super::mcp::router().with_state(self.state.clone());
            r.layer(axum::Extension::<Option<AuthExtension>>(auth))
        }
        fn member(&self) -> Router {
            self.app(Some(tdh::make_auth(self.fx.user_id, &self.fx.username)))
        }
        fn admin(&self) -> Router {
            self.app(Some(tdh::admin_auth(self.fx.user_id, &self.fx.username)))
        }
        fn anon(&self) -> Router {
            self.app(None)
        }
        fn url(&self, tail: &str) -> String {
            format!("/{}/v0.1{tail}", self.fx.repo_key)
        }
        async fn call(&self, app: Router, method: &str, tail: &str, body: Body) -> (StatusCode, Bytes) {
            let req = Request::builder()
                .method(method)
                .uri(self.url(tail))
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap();
            tdh::send(app, req).await
        }
        async fn json(&self, app: Router, method: &str, tail: &str, doc: Option<&serde_json::Value>) -> (StatusCode, serde_json::Value) {
            let body = doc
                .map(|d| Body::from(serde_json::to_vec(d).unwrap()))
                .unwrap_or_else(Body::empty);
            let (s, b) = self.call(app, method, tail, body).await;
            (s, serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null))
        }
        async fn config(&self, key: &str, value: &str) {
            sqlx::query(
                "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3) \
                 ON CONFLICT (repository_id, key) DO UPDATE SET value = $3",
            )
            .bind(self.fx.repo_id)
            .bind(key)
            .bind(value)
            .execute(&self.fx.pool)
            .await
            .unwrap();
        }
        async fn repo(&mut self, repo_type: &str, format: &str) -> (Uuid, String) {
            let (id, key, dir) = tdh::create_repo(&self.fx.pool, repo_type, format).await;
            self.extra.push((id, dir));
            (id, key)
        }
        async fn artifact(&self, name: &str, version: &str) -> Uuid {
            tdh::artifact_id_at(&self.fx.pool, self.fx.repo_id, &fmt::storage_path(name, version)).await
        }
        async fn teardown(self) {
            let pool = self.fx.pool.clone();
            let _ = sqlx::query("DELETE FROM mcp_version_tombstones WHERE repository_id = $1")
                .bind(self.fx.repo_id)
                .execute(&pool)
                .await;
            for (id, dir) in &self.extra {
                let _ = sqlx::query("DELETE FROM proxy_cache_artifacts WHERE repository_id = $1")
                    .bind(id)
                    .execute(&pool)
                    .await;
                tdh::cleanup_member_repo(&pool, *id, dir).await;
            }
            let _ = sqlx::query("DELETE FROM packages WHERE repository_id = $1")
                .bind(self.fx.repo_id)
                .execute(&pool)
                .await;
            self.fx.teardown().await;
        }
    }

    fn doc(name: &str, version: &str, packages: serde_json::Value) -> serde_json::Value {
        let mut d = serde_json::json!({
            "$schema": fmt::SCHEMA_URL, "name": name, "description": "Echo tools", "version": version,
        });
        if packages.as_array().is_some_and(|p| !p.is_empty()) {
            d["packages"] = packages;
        } else {
            d["remotes"] = serde_json::json!([{"type": "streamable-http", "url": "https://mcp.acme.test/mcp"}]);
        }
        d
    }

    fn npm(version: &str) -> serde_json::Value {
        serde_json::json!([{"registryType": "npm", "identifier": "@acme/echo", "version": version,
                            "transport": {"type": "stdio"}}])
    }

    #[tokio::test]
    async fn tombstones_audits_soft_delete_and_edit() {
        let Some(env) = Env::new().await else {
            return;
        };
        let d = doc("com.acme/t", "1.0.0", serde_json::json!([]));
        let (s, b) = env.json(env.member(), "POST", "/publish", Some(&d)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let id = env.artifact("com.acme/t", "1.0.0").await;
        assert_eq!(tdh::audit_count_eventually(&env.fx.pool, id, "MCP_SERVER_PUBLISHED", 1).await, 1);

        // Status change audited.
        let (s, _) = env
            .json(env.member(), "PATCH", "/servers/com.acme%2Ft/versions/1.0.0/status",
                  Some(&serde_json::json!({"status": "deprecated", "statusMessage": "old"})))
            .await;
        assert_eq!(s, StatusCode::OK);
        let row = tdh::audit_row_eventually(&env.fx.pool, id, "MCP_SERVER_STATUS_CHANGED").await;
        assert_eq!((row.details["from"].as_str(), row.details["to"].as_str()), (Some("active"), Some("deprecated")));

        // Admin edit: members are refused, the identity must match.
        let mut edited = d.clone();
        edited["description"] = "Edited".into();
        let tail = "/servers/com.acme/t/versions/1.0.0";
        assert_eq!(env.json(env.member(), "PUT", tail, Some(&edited)).await.0, StatusCode::FORBIDDEN);
        let mut renamed = edited.clone();
        renamed["version"] = "2.0.0".into();
        assert_eq!(env.json(env.admin(), "PUT", tail, Some(&renamed)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            env.json(env.admin(), "PUT", "/servers/com.acme/none/versions/1.0.0", Some(&edited)).await.0,
            StatusCode::NOT_FOUND
        );
        let (s, b) = env.json(env.admin(), "PUT", tail, Some(&edited)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["server"]["description"], "Edited");
        assert_eq!(b["_meta"][fmt::OFFICIAL_META_KEY]["status"], "deprecated");
        let edit = tdh::audit_row_eventually(&env.fx.pool, id, "MCP_SERVER_EDITED").await;
        assert_ne!(edit.details["previous_sha256"], edit.details["sha256"]);
        assert_eq!(edit.details["packages_changed"], false);
        // Identical bytes: no write.
        assert_eq!(env.json(env.admin(), "PUT", tail, Some(&edited)).await.0, StatusCode::OK);

        // Soft delete.
        let (s, b) = env
            .json(env.member(), "DELETE", tail, Some(&serde_json::json!({"statusMessage": "bye"})))
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["_meta"][fmt::OFFICIAL_META_KEY]["status"], "deleted");
        assert_eq!(env.json(env.member(), "DELETE", tail, None).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(env.json(env.anon(), "GET", tail, None).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            env.json(env.anon(), "GET", &format!("{tail}?include_deleted=true"), None).await.0,
            StatusCode::OK
        );
        assert_eq!(tdh::audit_count_eventually(&env.fx.pool, id, "MCP_SERVER_DELETED", 1).await, 1);

        // Purge (hard delete of the row, as a trash purge does), then
        // republish with other bytes: the tombstone answers 409.
        sqlx::query("DELETE FROM artifact_metadata WHERE artifact_id = $1").bind(id).execute(&env.fx.pool).await.unwrap();
        sqlx::query("DELETE FROM artifacts WHERE id = $1").bind(id).execute(&env.fx.pool).await.unwrap();
        let mut other = d.clone();
        other["description"] = "Different bytes".into();
        let (s, b) = env.json(env.member(), "POST", "/publish", Some(&other)).await;
        assert_eq!((s, b["error"].as_str()), (StatusCode::CONFLICT, Some("mcp_version_exists")));
        env.teardown().await;
    }

    #[tokio::test]
    async fn validate_is_a_scoped_dry_run() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let (npm_id, npm_key) = env.repo("local", "npm").await;
        tdh::grant_repo_access(&env.fx.pool, npm_id, env.fx.user_id).await;
        env.config(mcp_packages::REPOS_KEY, &serde_json::json!({"npm": npm_key}).to_string()).await;
        let d = doc("com.acme/v", "1.0.0", npm("1.0.0"));
        for v in ["v0", "v0.1"] {
            let req = Request::builder()
                .method("POST")
                .uri(format!("/{}/{v}/validate", env.fx.repo_key))
                .body(Body::from(serde_json::to_vec(&d).unwrap()))
                .unwrap();
            let (s, b) = tdh::send(env.anon(), req).await;
            let b: serde_json::Value = serde_json::from_slice(&b).unwrap();
            assert_eq!(s, StatusCode::OK, "{v}: {b}");
            // Anonymous: packages are not resolved (no backing-repo oracle).
            assert_eq!((b["valid"].as_bool(), b["packages"][0]["outcome"].as_str()), (Some(true), Some("unchecked")));
        }
        // A member who can read the backing repository gets resolution.
        let (_, b) = env.json(env.member(), "POST", "/validate", Some(&d)).await;
        assert_eq!(b["valid"], false, "{b}");
        assert_eq!(b["issues"][0]["reference"], "mcp_package_not_found");
        let (_, b) = env.json(env.anon(), "POST", "/validate", Some(&serde_json::json!({"name": "x"}))).await;
        assert_eq!((b["valid"].as_bool(), b["issues"][0]["type"].as_str()), (Some(false), Some("schema")));
        // Nothing was written.
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
            .bind(env.fx.repo_id).fetch_one(&env.fx.pool).await.unwrap();
        assert_eq!(n, 0);
        // The version-taken check is for repository holders only.
        let plain = doc("com.acme/v", "2.0.0", serde_json::json!([]));
        assert_eq!(env.json(env.member(), "POST", "/publish", Some(&plain)).await.0, StatusCode::OK);
        assert_eq!(env.json(env.anon(), "POST", "/validate", Some(&plain)).await.1["valid"], true);
        let (_, b) = env.json(env.admin(), "POST", "/validate", Some(&plain)).await;
        assert_eq!(b["issues"][0]["reference"], "mcp_version_exists");
        env.teardown().await;
    }

    #[tokio::test]
    async fn bundles_upload_pin_serve_and_download() {
        let Some(env) = Env::new().await else {
            return;
        };
        let up = |file: &str| format!("/servers/com.acme/echo/versions/1.0.0/bundles/{file}");
        let put = |app: Router, file: String, bytes: &'static [u8]| {
            let req = Request::builder().method("PUT").uri(env.url(&file)).body(Body::from(bytes)).unwrap();
            tdh::send(app, req)
        };
        // Tampered: always refused and audited.
        let (s, b) = put(env.member(), up("bad.mcpb"), TAMPERED).await;
        let b: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!((s, b["error"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("mcp_bundle_signature_invalid")));
        // Unsigned under mcp_require_bundle_signature.
        env.config(crate::services::mcp_settings::REQUIRE_BUNDLE_SIGNATURE_KEY, "true").await;
        let (s, _) = put(env.member(), up("echo.mcpb"), UNSIGNED).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        env.config(crate::services::mcp_settings::REQUIRE_BUNDLE_SIGNATURE_KEY, "false").await;
        // Bad names, anonymous.
        assert_eq!(put(env.member(), up("echo.zip"), UNSIGNED).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(put(env.anon(), up("echo.mcpb"), UNSIGNED).await.0, StatusCode::UNAUTHORIZED);
        // Signed: stored, idempotent, conflicting bytes refused.
        let (s, b) = put(env.member(), up("echo.mcpb"), SIGNED).await;
        let b: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(b["signature"]["state"], "valid");
        assert_eq!(b["manifest"]["tools"][0]["name"], "echo");
        let sha = b["fileSha256"].as_str().unwrap().to_string();
        assert_eq!(put(env.member(), up("echo.mcpb"), SIGNED).await.0, StatusCode::OK);
        assert_eq!(put(env.member(), up("echo.mcpb"), UNSIGNED).await.0, StatusCode::CONFLICT);
        // Not downloadable before the version is published.
        assert_eq!(env.call(env.anon(), "GET", &up("echo.mcpb"), Body::empty()).await.0, StatusCode::NOT_FOUND);

        // Publish without an mcpb entry: AK adds it.
        let d = doc("com.acme/echo", "1.0.0", serde_json::json!([]));
        let (s, b) = env.json(env.member(), "POST", "/publish", Some(&d)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let pkg = &b["server"]["packages"][0];
        assert_eq!(pkg["registryType"], "mcpb");
        assert_eq!(pkg["fileSha256"], sha.as_str());
        let served = format!("http://localhost/mcp/{}/v0.1/servers/com.acme/echo/versions/1.0.0/bundles/echo.mcpb", env.fx.repo_key);
        assert_eq!(pkg["identifier"], served.as_str());
        let id = env.artifact("com.acme/echo", "1.0.0").await;
        let meta: serde_json::Value = sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
            .bind(id).fetch_one(&env.fx.pool).await.unwrap();
        assert_eq!(meta["bundles"][0]["fileSha256"], sha.as_str());
        assert_eq!(meta["bundles"][0]["signature"]["state"], "valid");
        assert_eq!(meta["bundles"][0]["manifest"]["name"], "echo-mcpb");
        // An exact read by a credentialed caller tickets the URL.
        let (_, b) = env.json(env.member(), "GET", "/servers/com.acme/echo/versions/1.0.0", None).await;
        let ticketed = b["server"]["packages"][0]["identifier"].as_str().unwrap();
        assert!(ticketed.starts_with(&format!("{served}?ticket=")), "{ticketed}");
        let (_, b) = env.json(env.anon(), "GET", "/servers/com.acme/echo/versions/1.0.0", None).await;
        assert_eq!(b["server"]["packages"][0]["identifier"], served.as_str());
        // Download.
        let (s, bytes) = env.call(env.anon(), "GET", &up("echo.mcpb"), Body::empty()).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(&bytes[..], SIGNED);
        // A bundle for a published version is write-once.
        assert_eq!(put(env.member(), up("more.mcpb"), UNSIGNED).await.0, StatusCode::CONFLICT);
        // A quarantined bundle holds the version and is not downloadable.
        sqlx::query("UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_source = 'admin' WHERE repository_id = $1 AND path LIKE '%/bundles/%'")
            .bind(env.fx.repo_id).execute(&env.fx.pool).await.unwrap();
        assert_eq!(env.call(env.anon(), "GET", &up("echo.mcpb"), Body::empty()).await.0, StatusCode::NOT_FOUND);
        let (s, b) = env.json(env.admin(), "GET", "/servers/com.acme/echo/versions/1.0.0", None).await;
        assert_eq!((s, b["error"].as_str()), (StatusCode::NOT_FOUND, Some("mcp_backing_artifact_blocked")));
        // An explicit mcpb entry with an unknown sha is refused.
        let mut wrong = doc("com.acme/echo", "2.0.0", serde_json::json!([{
            "registryType": "mcpb", "identifier": "https://x.test/echo.mcpb", "fileSha256": "a".repeat(64),
            "transport": {"type": "stdio"}}]));
        let (s, b) = env.json(env.member(), "POST", "/publish", Some(&wrong)).await;
        assert_eq!((s, b["error"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("mcp_package_not_found")));
        wrong["packages"][0]["registryBaseUrl"] = "https://x.test".into();
        assert_eq!(env.json(env.member(), "POST", "/publish", Some(&wrong)).await.1["error"], "mcp_external_registry");
        let rejected: i64 = {
            let mut n = 0;
            for _ in 0..100 {
                n = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM audit_log WHERE action = 'MCP_BUNDLE_SIGNATURE_REJECTED' AND details->>'repository' = $1")
                    .bind(&env.fx.repo_key).fetch_one(&env.fx.pool).await.unwrap_or(0);
                if n >= 2 { break; }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            n
        };
        assert_eq!(rejected, 2);
        env.teardown().await;
    }

    /// A Remote npm backing repository: a package pulled through it pins
    /// from the proxy cache; a package not pulled yet is filled by the
    /// resolver (202 + resolving hold), and an upstream 404 fails the
    /// version.
    #[tokio::test]
    async fn remote_backing_pull_through_and_async_fill() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let Some(mut env) = Env::new().await else {
            return;
        };
        let upstream = MockServer::start().await;
        for v in ["1.0.0", "2.0.0"] {
            Mock::given(method("GET"))
                .and(path(format!("/@acme/echo/-/echo-{v}.tgz")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(format!("tgz-{v}").into_bytes()))
                .mount(&upstream)
                .await;
        }
        let (remote_id, remote_key) = env.repo("remote", "npm").await;
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream.uri()).bind(remote_id).execute(&env.fx.pool).await.unwrap();
        tdh::grant_repo_access(&env.fx.pool, remote_id, env.fx.user_id).await;
        env.config(mcp_packages::REPOS_KEY, &serde_json::json!({"npm": remote_key}).to_string()).await;
        let cached = |v: &'static str| {
            let pool = env.fx.pool.clone();
            async move {
                for _ in 0..400 {
                    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proxy_cache_artifacts WHERE repository_id = $1 AND path LIKE $2")
                        .bind(remote_id).bind(format!("%echo-{v}.tgz")).fetch_one(&pool).await.unwrap();
                    if n > 0 { return; }
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                panic!("{v} never reached the proxy cache");
            }
        };

        // 1. Pull 1.0.0 through the Remote, then publish: pinned from the cache.
        let npm_app = tdh::router_with_auth(
            crate::api::handlers::npm::router(),
            env.state.clone(),
            tdh::make_auth(env.fx.user_id, &env.fx.username),
        );
        let req = Request::builder().uri(format!("/{remote_key}/@acme/echo/-/echo-1.0.0.tgz")).body(Body::empty()).unwrap();
        assert_eq!(tdh::send(npm_app, req).await.0, StatusCode::OK);
        cached("1.0.0").await;
        let (s, b) = env.json(env.member(), "POST", "/publish", Some(&doc("com.acme/echo", "1.0.0", npm("1.0.0")))).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["server"]["packages"][0]["registryBaseUrl"], format!("http://localhost/npm/{remote_key}"));
        let id1 = env.artifact("com.acme/echo", "1.0.0").await;
        let pin: serde_json::Value = sqlx::query_scalar("SELECT metadata->'packages'->0->'resolved' FROM artifact_metadata WHERE artifact_id = $1")
            .bind(id1).fetch_one(&env.fx.pool).await.unwrap();
        assert_eq!(pin["cachePath"], "@acme/echo/-/echo-1.0.0.tgz");
        // The cache entry's hold holds the server version.
        sqlx::query("UPDATE proxy_cache_artifacts SET quarantine_until = NOW() + interval '1 day' WHERE repository_id = $1")
            .bind(remote_id).execute(&env.fx.pool).await.unwrap();
        let tail1 = "/servers/com.acme/echo/versions/1.0.0";
        assert_eq!(env.json(env.anon(), "GET", tail1, None).await.0, StatusCode::NOT_FOUND);
        assert_eq!(env.json(env.member(), "GET", tail1, None).await.1["error"], "mcp_backing_artifact_blocked");
        let (_, list) = env.json(env.member(), "GET", "/servers", None).await;
        assert_eq!(list["metadata"]["count"], 0);
        sqlx::query("UPDATE proxy_cache_artifacts SET quarantine_until = NULL WHERE repository_id = $1")
            .bind(remote_id).execute(&env.fx.pool).await.unwrap();
        assert_eq!(env.json(env.anon(), "GET", tail1, None).await.0, StatusCode::OK);

        // 2. 2.0.0 is not cached: 202, held as resolving, then filled.
        let (s, b) = env.json(env.member(), "POST", "/publish", Some(&doc("com.acme/echo", "2.0.0", npm("2.0.0")))).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        assert_eq!((b["status"].as_str(), b["pendingPackages"][0].as_u64()), (Some("resolving"), Some(0)));
        let tail2 = "/servers/com.acme/echo/versions/2.0.0";
        let (s, b) = env.json(env.member(), "GET", tail2, None).await;
        assert_eq!((s, b["error"].as_str(), b["hold"].as_str()), (StatusCode::NOT_FOUND, Some("mcp_resolving"), Some("resolving")));
        assert_eq!(env.json(env.anon(), "GET", "/servers/com.acme/echo/versions/latest", None).await.1["server"]["version"], "1.0.0");
        let id2 = env.artifact("com.acme/echo", "2.0.0").await;
        let mut done = false;
        for _ in 0..40 {
            sqlx::query("UPDATE mcp_resolve_jobs SET next_attempt_at = NOW() WHERE artifact_id = $1")
                .bind(id2).execute(&env.fx.pool).await.unwrap();
            resolver::run_due(&env.state).await;
            let state: Option<String> = sqlx::query_scalar("SELECT metadata->'resolution'->>'state' FROM artifact_metadata WHERE artifact_id = $1")
                .bind(id2).fetch_one(&env.fx.pool).await.unwrap();
            if state.as_deref() == Some("resolved") { done = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(done, "the resolver fills and pins 2.0.0");
        let (s, b) = env.json(env.anon(), "GET", tail2, None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["server"]["packages"][0]["registryBaseUrl"], format!("http://localhost/npm/{remote_key}"));
        assert_eq!(tdh::audit_count_eventually(&env.fx.pool, id2, "MCP_PACKAGE_PINNED", 1).await, 1);
        let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mcp_resolve_jobs WHERE artifact_id = $1")
            .bind(id2).fetch_one(&env.fx.pool).await.unwrap();
        assert_eq!(jobs, 0);

        // 3. Upstream has no 3.0.0: the version fails and stays hidden.
        let (s, _) = env.json(env.member(), "POST", "/publish", Some(&doc("com.acme/echo", "3.0.0", npm("3.0.0")))).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let id3 = env.artifact("com.acme/echo", "3.0.0").await;
        resolver::run_due(&env.state).await;
        let res: serde_json::Value = sqlx::query_scalar("SELECT metadata->'resolution' FROM artifact_metadata WHERE artifact_id = $1")
            .bind(id3).fetch_one(&env.fx.pool).await.unwrap();
        assert_eq!(res["state"], "failed", "{res}");
        assert_eq!(res["error"]["error"], "mcp_package_not_found");
        let (s, b) = env.json(env.member(), "GET", "/servers/com.acme/echo/versions/3.0.0", None).await;
        assert_eq!((s, b["error"].as_str()), (StatusCode::NOT_FOUND, Some("mcp_unresolvable")));
        env.teardown().await;
    }

    #[tokio::test]
    async fn pinned_digest_is_found_by_the_delete_guard() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (oci_id, _) = env.repo("local", "docker").await;
        assert!(!writes::digest_pinned_by_mcp(&env.fx.pool, oci_id, "acme/mcp", "sha256:aa").await.unwrap());
        let d = doc("com.acme/pin", "1.0.0", serde_json::json!([]));
        assert_eq!(env.json(env.member(), "POST", "/publish", Some(&d)).await.0, StatusCode::OK);
        let id = env.artifact("com.acme/pin", "1.0.0").await;
        sqlx::query("UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{packages}', $2) WHERE artifact_id = $1")
            .bind(id)
            .bind(serde_json::json!([{"resolved": {"repositoryId": oci_id, "name": "acme/mcp",
                                                     "digest": "sha256:aa", "gateDigest": "sha256:bb"}}]))
            .execute(&env.fx.pool).await.unwrap();
        for digest in ["sha256:aa", "sha256:bb"] {
            assert!(writes::digest_pinned_by_mcp(&env.fx.pool, oci_id, "acme/mcp", digest).await.unwrap());
        }
        assert!(!writes::digest_pinned_by_mcp(&env.fx.pool, oci_id, "acme/other", "sha256:aa").await.unwrap());
        // A trashed version no longer pins.
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1").bind(id).execute(&env.fx.pool).await.unwrap();
        assert!(!writes::digest_pinned_by_mcp(&env.fx.pool, oci_id, "acme/mcp", "sha256:aa").await.unwrap());
        env.teardown().await;
    }
}
