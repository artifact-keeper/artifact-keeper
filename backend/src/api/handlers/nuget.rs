//! NuGet v3 Server API handlers.
//!
//! Implements the endpoints required for `dotnet nuget push` and
//! `dotnet add package` against a NuGet v3 feed.
//!
//! Routes are mounted at `/nuget/{repo_key}/...`:
//!   GET  /nuget/{repo_key}/v3/index.json                                      — Service index
//!   GET  /nuget/{repo_key}/v3/search                                          — Search packages
//!   GET  /nuget/{repo_key}/v3/registration/{id}/index.json                    — Package registration
//!   GET  /nuget/{repo_key}/v3/flatcontainer/{id}/index.json                   — Version list
//!   GET  /nuget/{repo_key}/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg — Download
//!   PUT  /nuget/{repo_key}/api/v2/package                                     — Push package

use std::io::Read;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::models::repository::RepositoryType;
use crate::services::auth_service::AuthService;
use crate::services::curation_service::version_compare;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Service index (NuGet discovery document)
        .route("/:repo_key/v3/index.json", get(service_index))
        // Search
        .route("/:repo_key/v3/search", get(search_packages))
        // Package registration
        .route(
            "/:repo_key/v3/registration/:id/index.json",
            get(registration_index),
        )
        // Flat container — version list
        .route(
            "/:repo_key/v3/flatcontainer/:id/index.json",
            get(flatcontainer_versions),
        )
        // Flat container — download .nupkg
        .route(
            "/:repo_key/v3/flatcontainer/:id/:version/:filename",
            get(flatcontainer_download),
        )
        // Push package (dotnet nuget push).
        // Register both with and without trailing slash because `dotnet nuget
        // push` appends a trailing slash to the PackagePublish/2.0.0 URL
        // discovered from the v3 service index.
        .route("/:repo_key/api/v2/package", put(push_package))
        .route("/:repo_key/api/v2/package/", put(push_package))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_nuget_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(
        db,
        repo_key,
        &["nuget", "chocolatey", "powershell"],
        "a NuGet",
    )
    .await
}

/// Resolve the set of repository IDs whose local `artifacts` rows should back
/// a read query for `repo`.
///
/// * For a hosted / local repo this is simply `[repo.id]`.
/// * For a virtual repo it is the IDs of all **non-remote** member repos
///   (Local / Staging), so local listing/search endpoints federate across
///   members. Remote members are handled separately via the proxy fallback
///   because their content is fetched on demand rather than stored locally.
///
/// Returns the resolved IDs alongside the list of virtual members (empty for
/// non-virtual repos) so callers can additionally proxy remote members.
async fn effective_local_repo_ids(
    db: &PgPool,
    repo: &RepoInfo,
) -> Result<(Vec<uuid::Uuid>, Vec<crate::models::repository::Repository>), Response> {
    if repo.repo_type != RepositoryType::Virtual {
        return Ok((vec![repo.id], Vec::new()));
    }

    let members = proxy_helpers::fetch_virtual_members(db, repo.id).await?;
    let local_ids: Vec<uuid::Uuid> = members
        .iter()
        .filter(|m| m.repo_type != RepositoryType::Remote)
        .map(|m| m.id)
        .collect();
    Ok((local_ids, members))
}

/// Detect a NuGet pre-release version. Per the SemVer rules NuGet follows, a
/// pre-release version carries a `-` separated suffix after the version core
/// (e.g. `2.0.0-beta.1`). Stable versions have no such suffix.
fn is_prerelease_version(version: &str) -> bool {
    version.contains('-')
}

/// Pick the version to surface as "latest" for a package in search results.
///
/// When `include_prerelease` is false, the highest **stable** version wins and
/// pre-release versions are only considered when no stable version exists.
/// When true, the highest version overall (stable or pre-release) wins.
/// Returns `"0.0.0"` when `versions` is empty.
fn select_latest_version(versions: &[String], include_prerelease: bool) -> &str {
    let highest = |candidates: &[&String]| -> Option<String> {
        candidates
            .iter()
            .max_by(|a, b| version_compare(a, b).cmp(&0))
            .map(|s| s.to_string())
    };

    if !include_prerelease {
        let stable: Vec<&String> = versions
            .iter()
            .filter(|v| !is_prerelease_version(v))
            .collect();
        if let Some(best) = highest(&stable) {
            // Return a borrow of the original slice element matching `best`.
            return versions
                .iter()
                .find(|v| **v == best)
                .map(String::as_str)
                .unwrap_or("0.0.0");
        }
    }

    let all: Vec<&String> = versions.iter().collect();
    match highest(&all) {
        Some(best) => versions
            .iter()
            .find(|v| **v == best)
            .map(String::as_str)
            .unwrap_or("0.0.0"),
        None => "0.0.0",
    }
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/index.json — Service index
// ---------------------------------------------------------------------------

async fn service_index(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let _repo = resolve_nuget_repo(&state.db, &repo_key).await?;

    // Determine the base URL from reverse-proxy / Host headers.
    let base = format!("{}/nuget/{}", base_url.as_str(), repo_key);

    let index = serde_json::json!({
        "version": "3.0.0",
        "resources": [
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService/3.0.0-beta",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService/3.0.0-rc",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl/3.0.0-beta",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl/3.0.0-rc",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/flatcontainer/", base),
                "@type": "PackageBaseAddress/3.0.0",
                "comment": "Package content"
            },
            {
                "@id": format!("{}/api/v2/package", base),
                "@type": "PackagePublish/2.0.0",
                "comment": "Push packages"
            }
        ]
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string_pretty(&index).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/search — Search packages
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct SearchQuery {
    q: Option<String>,
    skip: Option<i64>,
    take: Option<i64>,
    #[serde(rename = "prerelease")]
    prerelease: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct SearchPackageRow {
    name: String,
    versions: Vec<String>,
    description: Option<String>,
}

async fn search_packages(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(params): Query<SearchQuery>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;

    let query_term = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20).min(100);
    let prerelease = params.prerelease.unwrap_or(false);

    // Determine base URL for building resource links.
    let base = format!("{}/nuget/{}", base_url.as_str(), repo_key);

    // Search distinct package names matching the query term.
    let search_pattern = format!("%{}%", query_term.to_lowercase());

    // Federate over virtual members (local/staging) when the repo is virtual;
    // otherwise query the repo itself.
    let (repo_ids, _members) = effective_local_repo_ids(&state.db, &repo).await?;

    // Pull the latest-by-created_at description per package via a LATERAL
    // join so the search payload carries the package summary instead of a
    // hardcoded empty string.
    let packages: Vec<SearchPackageRow> = sqlx::query_as(
        r#"
        SELECT a.name AS name,
               ARRAY_AGG(DISTINCT a.version) FILTER (WHERE a.version IS NOT NULL) AS versions,
               (
                   SELECT am.metadata->>'description'
                   FROM artifacts a2
                   LEFT JOIN artifact_metadata am ON am.artifact_id = a2.id
                   WHERE a2.repository_id = ANY($1::uuid[])
                     AND a2.is_deleted = false
                     AND LOWER(a2.name) = LOWER(a.name)
                   ORDER BY a2.created_at DESC
                   LIMIT 1
               ) AS description
        FROM artifacts a
        WHERE a.repository_id = ANY($1::uuid[])
          AND a.is_deleted = false
          AND LOWER(a.name) LIKE $2
        GROUP BY LOWER(a.name), a.name
        ORDER BY LOWER(a.name)
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(&repo_ids)
    .bind(&search_pattern)
    .bind(take)
    .bind(skip)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    // Get total count for pagination.
    let total_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT LOWER(name))::bigint
        FROM artifacts
        WHERE repository_id = ANY($1::uuid[])
          AND is_deleted = false
          AND LOWER(name) LIKE $2
        "#,
    )
    .bind(&repo_ids)
    .bind(&search_pattern)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let data: Vec<serde_json::Value> = packages
        .iter()
        .map(|p| {
            let id = &p.name;
            // When prerelease=false, prefer the highest *stable* version and
            // only fall back to a pre-release if no stable version exists.
            let latest = select_latest_version(&p.versions, prerelease);

            // Build version list entry for the latest version.
            let versions = vec![serde_json::json!({
                "version": latest,
                "@id": format!("{}/v3/registration/{}/{}.json", base, id, latest),
            })];

            serde_json::json!({
                "@id": format!("{}/v3/registration/{}/index.json", base, id),
                "@type": "Package",
                "registration": format!("{}/v3/registration/{}/index.json", base, id),
                "id": id,
                "version": latest,
                "description": p.description.clone().unwrap_or_default(),
                "totalDownloads": 0,
                "versions": versions
            })
        })
        .collect();

    let response = serde_json::json!({
        "totalHits": total_count,
        "data": data
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/registration/{id}/index.json — Registration index
// ---------------------------------------------------------------------------

async fn registration_index(
    State(state): State<SharedState>,
    Path((repo_key, package_id)): Path<(String, String)>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    let base = format!("{}/nuget/{}", base_url.as_str(), repo_key);

    // Resolve the set of local repo IDs to query: the repo itself, or all
    // local/staging members for a virtual repo.
    let (repo_ids, members) = effective_local_repo_ids(&state.db, &repo).await?;

    // Fetch all versions of this package across the effective repo IDs.
    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.version as "version?", a.path, a.size_bytes,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = ANY($1::uuid[])
          AND a.is_deleted = false
          AND LOWER(a.name) = $2
        ORDER BY a.created_at ASC
        "#,
        &repo_ids,
        package_id_lower
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if artifacts.is_empty() {
        // Cache miss: proxy the registration index from upstream.
        let upstream_path = format!("v3/registration/{}/index.json", package_id_lower);

        // Remote repo: fetch directly from its upstream.
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let (content, content_type) = proxy_helpers::proxy_fetch(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &upstream_path,
                )
                .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        CONTENT_TYPE,
                        content_type.unwrap_or_else(|| "application/json".to_string()),
                    )
                    .body(Body::from(content))
                    .unwrap());
            }
        }

        // Virtual repo: try each remote member's upstream in priority order.
        if repo.repo_type == RepositoryType::Virtual {
            if let Some(proxy) = &state.proxy_service {
                for member in &members {
                    if member.repo_type != RepositoryType::Remote {
                        continue;
                    }
                    let Some(upstream_url) = member.upstream_url.as_deref() else {
                        continue;
                    };
                    if let Ok((content, content_type)) = proxy_helpers::proxy_fetch(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await
                    {
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(
                                CONTENT_TYPE,
                                content_type.unwrap_or_else(|| "application/json".to_string()),
                            )
                            .body(Body::from(content))
                            .unwrap());
                    }
                }
            }
        }

        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let items: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.as_deref().unwrap_or("0.0.0");
            let description = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let authors = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("authors"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            serde_json::json!({
                "@id": format!("{}/v3/registration/{}/{}.json", base, package_id_lower, version),
                "catalogEntry": {
                    "@id": format!("{}/v3/registration/{}/{}.json", base, package_id_lower, version),
                    "id": package_id_lower,
                    "version": version,
                    "description": description,
                    "authors": authors,
                    "packageContent": format!(
                        "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                        base, package_id_lower, version, package_id_lower, version
                    ),
                    "listed": true,
                },
                "packageContent": format!(
                    "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                    base, package_id_lower, version, package_id_lower, version
                ),
            })
        })
        .collect();

    let lower_version = artifacts
        .first()
        .and_then(|a| a.version.as_deref())
        .unwrap_or("0.0.0");
    let upper_version = artifacts
        .last()
        .and_then(|a| a.version.as_deref())
        .unwrap_or("0.0.0");

    let response = serde_json::json!({
        "@id": format!("{}/v3/registration/{}/index.json", base, package_id_lower),
        "count": 1,
        "items": [
            {
                "@id": format!("{}/v3/registration/{}/index.json#page/0", base, package_id_lower),
                "count": items.len(),
                "lower": lower_version,
                "upper": upper_version,
                "items": items,
            }
        ]
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/flatcontainer/{id}/index.json — Version list
// ---------------------------------------------------------------------------

async fn flatcontainer_versions(
    State(state): State<SharedState>,
    Path((repo_key, package_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    // Resolve the set of local repo IDs to query: the repo itself, or all
    // local/staging members for a virtual repo.
    let (repo_ids, members) = effective_local_repo_ids(&state.db, &repo).await?;

    let mut versions: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT version
        FROM artifacts
        WHERE repository_id = ANY($1::uuid[])
          AND is_deleted = false
          AND LOWER(name) = $2
          AND version IS NOT NULL
        "#,
    )
    .bind(&repo_ids)
    .bind(&package_id_lower)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    versions.sort_by(|a, b| match version_compare(a, b) {
        n if n < 0 => std::cmp::Ordering::Less,
        n if n > 0 => std::cmp::Ordering::Greater,
        _ => std::cmp::Ordering::Equal,
    });

    if versions.is_empty() {
        // Cache miss: proxy the flatcontainer version index from upstream.
        let upstream_path = format!("v3/flatcontainer/{}/index.json", package_id_lower);

        // Remote repo: fetch directly from its upstream.
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let (content, content_type) = proxy_helpers::proxy_fetch(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &upstream_path,
                )
                .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        CONTENT_TYPE,
                        content_type.unwrap_or_else(|| "application/json".to_string()),
                    )
                    .body(Body::from(content))
                    .unwrap());
            }
        }

        // Virtual repo: try each remote member's upstream in priority order.
        if repo.repo_type == RepositoryType::Virtual {
            if let Some(proxy) = &state.proxy_service {
                for member in &members {
                    if member.repo_type != RepositoryType::Remote {
                        continue;
                    }
                    let Some(upstream_url) = member.upstream_url.as_deref() else {
                        continue;
                    };
                    if let Ok((content, content_type)) = proxy_helpers::proxy_fetch(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await
                    {
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(
                                CONTENT_TYPE,
                                content_type.unwrap_or_else(|| "application/json".to_string()),
                            )
                            .body(Body::from(content))
                            .unwrap());
                    }
                }
            }
        }

        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let response = serde_json::json!({
        "versions": versions
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/flatcontainer/{id}/{version}/{filename} — Download
// ---------------------------------------------------------------------------

async fn flatcontainer_download(
    State(state): State<SharedState>,
    Path((repo_key, package_id, version, filename)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    // Find the artifact matching this package/version.
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256, content_type
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = $2
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        package_id_lower,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package version not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!(
                        "v3/flatcontainer/{}/{}/{}",
                        package_id_lower, version, filename
                    );
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "Content-Type",
                            content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let vname = package_id_lower.clone();
                let vversion = version.clone();
                let upstream_path = format!(
                    "v3/flatcontainer/{}/{}/{}",
                    package_id_lower, version, filename
                );
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db, &state, member_id, &location, &vname, &vversion,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    Some(&filename),
                );
            }
            return Err(not_found);
        }
    };

    // Read from storage.
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    // Remote repos must keep the buffered cache-or-refetch path: a cache miss
    // re-pulls the package from upstream and writes it back. That recovery
    // read is small relative to the artifact and is re-wrapped as a one-shot
    // stream below. Local/cached hits stream the body straight from storage so
    // large `.nupkg` bodies never buffer in heap.
    let body: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>> =
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let package_id_lower = package_id_lower.clone();
                let version = version.clone();
                let filename = filename.clone();
                let repo_key = repo_key.clone();
                let content = proxy_helpers::get_cached_or_refetch(
                    &state.db,
                    artifact.id,
                    storage.as_ref(),
                    &artifact.storage_key,
                    || {
                        let package_id_lower = package_id_lower.clone();
                        let version = version.clone();
                        let filename = filename.clone();
                        let repo_key = repo_key.clone();
                        async move {
                            let upstream_path = format!(
                                "v3/flatcontainer/{}/{}/{}",
                                package_id_lower, version, filename
                            );
                            let (bytes, _content_type) = proxy_helpers::proxy_fetch(
                                proxy,
                                repo.id,
                                &repo_key,
                                upstream_url,
                                &upstream_path,
                            )
                            .await?;
                            Ok(bytes)
                        }
                    },
                )
                .await?;
                Box::pin(futures::stream::once(async move { Ok(content) }))
            } else {
                storage
                    .get_stream(&artifact.storage_key)
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Storage error: {}", e),
                        )
                            .into_response()
                    })?
            }
        } else {
            storage
                .get_stream(&artifact.storage_key)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Storage error: {}", e),
                    )
                        .into_response()
                })?
        };

    // Record download.
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    use futures::StreamExt as _;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(
            body.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /nuget/{repo_key}/api/v2/package — Push package
// ---------------------------------------------------------------------------

async fn push_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce write scope before doing anything else.
    crate::api::middleware::auth::require_scope_response(auth.as_ref(), "write")?;
    let user_id = match auth {
        Some(ext) => ext.user_id,
        None => {
            let api_key = headers
                .get("X-NuGet-ApiKey")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::from("Authentication required"))
                        .unwrap()
                })?;
            let (username, password) = if let Some((u, p)) = api_key.split_once(':') {
                (u.to_string(), p.to_string())
            } else {
                ("apikey".to_string(), api_key.to_string())
            };
            let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
            let (user, _) = auth_service
                .authenticate(&username, &password)
                .await
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid API key").into_response())?;
            user.id
        }
    };
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // The body may be multipart/form-data or raw binary .nupkg.
    let nupkg_bytes = extract_nupkg_bytes(&headers, body)?;

    if nupkg_bytes.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty package body").into_response());
    }

    // Parse .nuspec from the .nupkg (ZIP archive).
    let nuspec = parse_nuspec_from_nupkg(&nupkg_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to read .nuspec from package: {}", e),
        )
            .into_response()
    })?;

    let package_id = nuspec.id.to_lowercase();
    let version = nuspec.version.clone();

    if package_id.is_empty() || version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Package ID and version are required in .nuspec",
        )
            .into_response());
    }

    // Check for duplicate.
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND LOWER(name) = $2 AND version = $3 AND is_deleted = false",
        repo.id,
        package_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("Package {}.{} already exists", package_id, version),
        )
            .into_response());
    }

    // Compute SHA256.
    let mut hasher = Sha256::new();
    hasher.update(&nupkg_bytes);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = nupkg_bytes.len() as i64;
    let filename = format!("{}.{}.nupkg", package_id, version);
    let artifact_path = format!("{}/{}/{}", package_id, version, filename);
    let storage_key = format!("nuget/{}/{}/{}", package_id, version, filename);

    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &crate::models::repository::RepositoryFormat::Nuget,
        repo.id,
        &artifact_path,
        &checksum,
    )
    .await
    .map_err(|e| e.into_response())?;

    // Store the file.
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage.put(&storage_key, nupkg_bytes).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON.
    let metadata = serde_json::json!({
        "id": nuspec.id,
        "version": nuspec.version,
        "description": nuspec.description,
        "authors": nuspec.authors,
        "filename": filename,
    });

    // Insert artifact record.
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
        package_id,
        version,
        size_bytes,
        checksum,
        "application/octet-stream",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    // Store metadata.
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'nuget', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
    )
    .execute(&state.db)
    .await;

    // Populate packages / package_versions tables (best-effort) so the
    // package shows up in the UI Packages tab. Mirrors npm.rs / pypi.rs.
    let description = if nuspec.description.is_empty() {
        None
    } else {
        Some(nuspec.description.as_str())
    };
    crate::services::package_service::PackageService::new(state.db.clone())
        .try_create_or_update_from_artifact(
            repo.id,
            &nuspec.id,
            &version,
            size_bytes,
            &checksum,
            description,
            Some(serde_json::json!({ "format": "nuget" })),
        )
        .await;

    // Update repository timestamp.
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "NuGet push: {} {} ({}) to repo {}",
        nuspec.id, version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// .nupkg / .nuspec helpers
// ---------------------------------------------------------------------------

/// Extract the .nupkg bytes from the request body.
/// Handles both raw binary upload and multipart/form-data.
#[allow(clippy::result_large_err)]
fn extract_nupkg_bytes(headers: &HeaderMap, body: Bytes) -> Result<Bytes, Response> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("multipart/form-data") {
        // For multipart, we need to find the boundary and extract the file part.
        // The `dotnet nuget push` client sends multipart/form-data with the
        // .nupkg as the file field. We do a simple boundary-based extraction.
        extract_nupkg_from_multipart(content_type, &body)
    } else {
        // Raw binary body — the entire body is the .nupkg.
        Ok(body)
    }
}

/// Simple multipart extraction: find the file content between boundaries.
#[allow(clippy::result_large_err)]
fn extract_nupkg_from_multipart(content_type: &str, body: &[u8]) -> Result<Bytes, Response> {
    // Extract boundary from content-type header.
    let boundary = content_type
        .split(';')
        .find_map(|part| {
            let trimmed = part.trim();
            trimmed
                .strip_prefix("boundary=")
                .map(|b| b.trim_matches('"').to_string())
        })
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing multipart boundary").into_response())?;

    let boundary_marker = format!("--{}", boundary);
    let boundary_bytes = boundary_marker.as_bytes();

    // Find first boundary.
    let start = find_subsequence(body, boundary_bytes)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid multipart body").into_response())?;

    // Skip past the boundary line to the part headers.
    let after_boundary = start + boundary_bytes.len();

    // Find the blank line (\r\n\r\n) that separates headers from content.
    let header_end = find_subsequence(&body[after_boundary..], b"\r\n\r\n").ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Invalid multipart part headers").into_response()
    })?;

    let content_start = after_boundary + header_end + 4; // skip \r\n\r\n

    // Find the next boundary.
    let content_end = find_subsequence(&body[content_start..], boundary_bytes)
        .map(|pos| content_start + pos)
        .unwrap_or(body.len());

    // Strip trailing \r\n before the boundary.
    let end =
        if content_end >= 2 && body[content_end - 2] == b'\r' && body[content_end - 1] == b'\n' {
            content_end - 2
        } else {
            content_end
        };

    Ok(Bytes::copy_from_slice(&body[content_start..end]))
}

/// Find the position of a subsequence within a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Metadata extracted from a .nuspec file.
struct NuspecInfo {
    id: String,
    version: String,
    description: String,
    authors: String,
}

/// Parse the .nuspec XML from inside a .nupkg (ZIP) archive.
/// Uses simple string matching rather than a full XML parser.
fn parse_nuspec_from_nupkg(nupkg: &[u8]) -> Result<NuspecInfo, String> {
    let cursor = std::io::Cursor::new(nupkg);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("Invalid ZIP archive: {}", e))?;

    // Find the .nuspec file inside the archive.
    let mut nuspec_xml = String::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Cannot read ZIP entry: {}", e))?;
        if file.name().ends_with(".nuspec") {
            file.read_to_string(&mut nuspec_xml)
                .map_err(|e| format!("Cannot read .nuspec: {}", e))?;
            break;
        }
    }

    if nuspec_xml.is_empty() {
        return Err("No .nuspec file found in package".to_string());
    }

    // Simple tag extraction.
    let id = extract_xml_tag(&nuspec_xml, "id").unwrap_or_default();
    let version = extract_xml_tag(&nuspec_xml, "version").unwrap_or_default();
    let description = extract_xml_tag(&nuspec_xml, "description").unwrap_or_default();
    let authors = extract_xml_tag(&nuspec_xml, "authors").unwrap_or_default();

    Ok(NuspecInfo {
        id,
        version,
        description,
        authors,
    })
}

/// Extract the text content of a simple XML tag (no attributes, no nesting).
/// e.g. `<id>Foo</id>` returns `Some("Foo")`.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start_pos = xml.find(&open)?;
    // Skip past the opening tag (handle possible attributes or xmlns).
    let after_open = &xml[start_pos + open.len()..];
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end_pos = content.find(&close)?;
    Some(content[..end_pos].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use bytes::Bytes;

    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // Extracted pure functions (test-only)
    // -----------------------------------------------------------------------

    /// Build the base URL for NuGet service index resources.
    fn build_nuget_base_url(scheme: &str, host: &str, repo_key: &str) -> String {
        format!("{}://{}/nuget/{}", scheme, host, repo_key)
    }

    /// Build the NuGet service index JSON (v3/index.json).
    fn build_nuget_service_index(base: &str) -> serde_json::Value {
        serde_json::json!({
            "version": "3.0.0",
            "resources": [
                {
                    "@id": format!("{}/v3/search", base),
                    "@type": "SearchQueryService",
                    "comment": "Search packages"
                },
                {
                    "@id": format!("{}/v3/search", base),
                    "@type": "SearchQueryService/3.0.0-beta",
                    "comment": "Search packages"
                },
                {
                    "@id": format!("{}/v3/search", base),
                    "@type": "SearchQueryService/3.0.0-rc",
                    "comment": "Search packages"
                },
                {
                    "@id": format!("{}/v3/registration/", base),
                    "@type": "RegistrationsBaseUrl",
                    "comment": "Package registrations"
                },
                {
                    "@id": format!("{}/v3/registration/", base),
                    "@type": "RegistrationsBaseUrl/3.0.0-beta",
                    "comment": "Package registrations"
                },
                {
                    "@id": format!("{}/v3/registration/", base),
                    "@type": "RegistrationsBaseUrl/3.0.0-rc",
                    "comment": "Package registrations"
                },
                {
                    "@id": format!("{}/v3/flatcontainer/", base),
                    "@type": "PackageBaseAddress/3.0.0",
                    "comment": "Package content"
                },
                {
                    "@id": format!("{}/api/v2/package", base),
                    "@type": "PackagePublish/2.0.0",
                    "comment": "Push packages"
                }
            ]
        })
    }

    /// Build a single registration item JSON for a NuGet package version.
    fn build_registration_item(
        base: &str,
        package_id: &str,
        version: &str,
        description: &str,
        authors: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "@id": format!("{}/v3/registration/{}/{}.json", base, package_id, version),
            "catalogEntry": {
                "@id": format!("{}/v3/registration/{}/{}.json", base, package_id, version),
                "id": package_id,
                "version": version,
                "description": description,
                "authors": authors,
                "packageContent": format!(
                    "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                    base, package_id, version, package_id, version
                ),
                "listed": true,
            },
            "packageContent": format!(
                "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                base, package_id, version, package_id, version
            ),
        })
    }

    /// Build the flatcontainer versions JSON response.
    fn build_flatcontainer_versions_json(versions: &[String]) -> serde_json::Value {
        serde_json::json!({
            "versions": versions
        })
    }

    /// Build the NuGet artifact path for a .nupkg.
    fn build_nuget_artifact_path(package_id: &str, version: &str) -> String {
        let filename = format!("{}.{}.nupkg", package_id, version);
        format!("{}/{}/{}", package_id, version, filename)
    }

    /// Build the NuGet storage key for a .nupkg.
    fn build_nuget_storage_key(package_id: &str, version: &str) -> String {
        let filename = format!("{}.{}.nupkg", package_id, version);
        format!("nuget/{}/{}/{}", package_id, version, filename)
    }

    /// Build the NuGet push metadata JSON.
    fn build_nuget_push_metadata(info: &NuspecInfo) -> serde_json::Value {
        serde_json::json!({
            "id": info.id,
            "version": info.version,
            "description": info.description,
            "authors": info.authors,
            "filename": format!("{}.{}.nupkg", info.id.to_lowercase(), info.version),
        })
    }

    /// Build the search pattern for NuGet package queries.
    fn build_nuget_search_pattern(query_term: &str) -> String {
        format!("%{}%", query_term.to_lowercase())
    }

    // -----------------------------------------------------------------------
    // extract_xml_tag
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_tag_simple() {
        let xml = "<id>MyPackage</id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("MyPackage".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_with_whitespace() {
        let xml = "<id>  MyPackage  </id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("MyPackage".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_with_namespace() {
        let xml = r#"<id xmlns="http://example.com">PackageWithNS</id>"#;
        assert_eq!(
            extract_xml_tag(xml, "id"),
            Some("PackageWithNS".to_string())
        );
    }

    #[test]
    fn test_extract_xml_tag_missing() {
        let xml = "<name>Hello</name>";
        assert_eq!(extract_xml_tag(xml, "id"), None);
    }

    #[test]
    fn test_extract_xml_tag_empty_content() {
        let xml = "<id></id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_in_nuspec() {
        let xml = r#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.1</version>
    <description>Popular JSON framework</description>
    <authors>James Newton-King</authors>
  </metadata>
</package>"#;
        assert_eq!(
            extract_xml_tag(xml, "id"),
            Some("Newtonsoft.Json".to_string())
        );
        assert_eq!(extract_xml_tag(xml, "version"), Some("13.0.1".to_string()));
        assert_eq!(
            extract_xml_tag(xml, "description"),
            Some("Popular JSON framework".to_string())
        );
        assert_eq!(
            extract_xml_tag(xml, "authors"),
            Some("James Newton-King".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // find_subsequence
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_subsequence_found() {
        let haystack = b"hello world";
        let needle = b"world";
        assert_eq!(find_subsequence(haystack, needle), Some(6));
    }

    #[test]
    fn test_find_subsequence_at_start() {
        let haystack = b"hello world";
        let needle = b"hello";
        assert_eq!(find_subsequence(haystack, needle), Some(0));
    }

    #[test]
    fn test_find_subsequence_not_found() {
        let haystack = b"hello world";
        let needle = b"xyz";
        assert_eq!(find_subsequence(haystack, needle), None);
    }

    // NOTE: find_subsequence panics when needle is empty because
    // haystack.windows(0) panics. This is a potential bug in production
    // code if it ever receives an empty needle. Not fixing source code.
    #[test]
    #[should_panic(expected = "window size must be non-zero")]
    fn test_find_subsequence_empty_needle_panics() {
        let haystack = b"hello";
        let needle = b"";
        find_subsequence(haystack, needle);
    }

    #[test]
    fn test_find_subsequence_needle_longer_than_haystack() {
        let haystack = b"hi";
        let needle = b"hello world";
        assert_eq!(find_subsequence(haystack, needle), None);
    }

    #[test]
    fn test_find_subsequence_crlf() {
        let haystack = b"header\r\n\r\nbody";
        let needle = b"\r\n\r\n";
        assert_eq!(find_subsequence(haystack, needle), Some(6));
    }

    // -----------------------------------------------------------------------
    // extract_nupkg_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_nupkg_bytes_raw_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let body = Bytes::from_static(b"raw nupkg content");
        let result = extract_nupkg_bytes(&headers, body.clone()).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn test_extract_nupkg_bytes_no_content_type() {
        let headers = HeaderMap::new();
        let body = Bytes::from_static(b"raw content");
        let result = extract_nupkg_bytes(&headers, body.clone()).unwrap();
        assert_eq!(result, body);
    }

    // -----------------------------------------------------------------------
    // extract_nupkg_from_multipart
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_nupkg_from_multipart_valid() {
        let boundary = "----boundary123";
        let content_type = format!("multipart/form-data; boundary={}", boundary);
        let body = "------boundary123\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"pkg.nupkg\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             FILE_CONTENT_HERE\r\n\
             ------boundary123--\r\n"
            .to_string();
        let result = extract_nupkg_from_multipart(&content_type, body.as_bytes());
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.as_ref(), b"FILE_CONTENT_HERE");
    }

    #[test]
    fn test_extract_nupkg_from_multipart_missing_boundary() {
        let content_type = "multipart/form-data";
        let body = b"some body";
        let result = extract_nupkg_from_multipart(content_type, body);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_nupkg_from_multipart_quoted_boundary() {
        let content_type = "multipart/form-data; boundary=\"myboundary\"";
        let body = b"--myboundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nDATA\r\n--myboundary--\r\n";
        let result = extract_nupkg_from_multipart(content_type, body);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // parse_nuspec_from_nupkg
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuspec_from_nupkg_valid() {
        // Create a minimal ZIP with a .nuspec file
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("MyPackage.nuspec", options).unwrap();
        let nuspec_content = r#"<?xml version="1.0"?>
<package>
  <metadata>
    <id>MyPackage</id>
    <version>1.2.3</version>
    <description>A test package</description>
    <authors>Test Author</authors>
  </metadata>
</package>"#;
        std::io::Write::write_all(&mut zip, nuspec_content.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_ok());
        let nuspec = result.unwrap();
        assert_eq!(nuspec.id, "MyPackage");
        assert_eq!(nuspec.version, "1.2.3");
        assert_eq!(nuspec.description, "A test package");
        assert_eq!(nuspec.authors, "Test Author");
    }

    #[test]
    fn test_parse_nuspec_from_nupkg_no_nuspec() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("readme.txt", options).unwrap();
        std::io::Write::write_all(&mut zip, b"no nuspec here").unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("No .nuspec file found"));
    }

    #[test]
    fn test_parse_nuspec_from_nupkg_invalid_zip() {
        let result = parse_nuspec_from_nupkg(b"not a zip file");
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("Invalid ZIP archive"));
    }

    #[test]
    fn test_parse_nuspec_missing_fields() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Partial.nuspec", options).unwrap();
        let nuspec_content = r#"<?xml version="1.0"?>
<package><metadata><id>OnlyId</id></metadata></package>"#;
        std::io::Write::write_all(&mut zip, nuspec_content.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_ok());
        let nuspec = result.unwrap();
        assert_eq!(nuspec.id, "OnlyId");
        assert_eq!(nuspec.version, "");
        assert_eq!(nuspec.description, "");
        assert_eq!(nuspec.authors, "");
    }

    // -----------------------------------------------------------------------
    // NuspecInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuspec_info_construction() {
        let info = NuspecInfo {
            id: "TestPkg".to_string(),
            version: "2.0.0".to_string(),
            description: "A library".to_string(),
            authors: "Author Name".to_string(),
        };
        assert_eq!(info.id, "TestPkg");
        assert_eq!(info.version, "2.0.0");
    }

    // -----------------------------------------------------------------------
    // SearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_defaults() {
        let q: SearchQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.q.is_none());
        assert_eq!(q.skip, None);
        assert_eq!(q.take, None);
        assert_eq!(q.prerelease, None);
    }

    #[test]
    fn test_search_query_with_values() {
        let q: SearchQuery =
            serde_json::from_str(r#"{"q":"json","skip":10,"take":50,"prerelease":true}"#).unwrap();
        assert_eq!(q.q, Some("json".to_string()));
        assert_eq!(q.skip, Some(10));
        assert_eq!(q.take, Some(50));
        assert_eq!(q.prerelease, Some(true));
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuget_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/nuget".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // SHA256 checksum
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_checksum() {
        let data = b"nuget package data";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
        // Same input => same output
        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let checksum2 = format!("{:x}", hasher2.finalize());
        assert_eq!(checksum, checksum2);
    }

    // -----------------------------------------------------------------------
    // Path/storage key construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuget_artifact_path() {
        let package_id = "newtonsoft.json";
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id, version);
        let artifact_path = format!("{}/{}/{}", package_id, version, filename);
        assert_eq!(
            artifact_path,
            "newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    #[test]
    fn test_nuget_storage_key() {
        let package_id = "newtonsoft.json";
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id, version);
        let storage_key = format!("nuget/{}/{}/{}", package_id, version, filename);
        assert_eq!(
            storage_key,
            "nuget/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    // -----------------------------------------------------------------------
    // Service index base URL
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_index_base_url() {
        let scheme = "https";
        let host = "myregistry.example.com";
        let repo_key = "nuget-hosted";
        let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);
        assert_eq!(base, "https://myregistry.example.com/nuget/nuget-hosted");
    }

    #[test]
    fn test_service_index_default_host() {
        let scheme = "http";
        let host = "localhost";
        let repo_key = "main";
        let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);
        assert_eq!(base, "http://localhost/nuget/main");
    }

    // -----------------------------------------------------------------------
    // build_nuget_base_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_base_url_https() {
        assert_eq!(
            build_nuget_base_url("https", "registry.example.com", "nuget-hosted"),
            "https://registry.example.com/nuget/nuget-hosted"
        );
    }

    #[test]
    fn test_build_nuget_base_url_http_localhost() {
        assert_eq!(
            build_nuget_base_url("http", "localhost", "main"),
            "http://localhost/nuget/main"
        );
    }

    #[test]
    fn test_build_nuget_base_url_with_port() {
        assert_eq!(
            build_nuget_base_url("http", "localhost:8080", "nuget-local"),
            "http://localhost:8080/nuget/nuget-local"
        );
    }

    // -----------------------------------------------------------------------
    // build_nuget_service_index
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_service_index_structure() {
        let base = "https://example.com/nuget/main";
        let index = build_nuget_service_index(base);
        assert_eq!(index["version"], "3.0.0");
        let resources = index["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 8);
    }

    #[test]
    fn test_build_nuget_service_index_search_url() {
        let base = "https://example.com/nuget/repo";
        let index = build_nuget_service_index(base);
        let resources = index["resources"].as_array().unwrap();
        let search = &resources[0];
        assert_eq!(search["@id"], "https://example.com/nuget/repo/v3/search");
        assert_eq!(search["@type"], "SearchQueryService");
    }

    #[test]
    fn test_build_nuget_service_index_push_url() {
        let base = "https://example.com/nuget/repo";
        let index = build_nuget_service_index(base);
        let resources = index["resources"].as_array().unwrap();
        let push = &resources[7];
        assert_eq!(push["@id"], "https://example.com/nuget/repo/api/v2/package");
        assert_eq!(push["@type"], "PackagePublish/2.0.0");
    }

    #[test]
    fn test_build_nuget_service_index_registration_url() {
        let base = "https://example.com/nuget/repo";
        let index = build_nuget_service_index(base);
        let resources = index["resources"].as_array().unwrap();
        let reg = &resources[3];
        assert_eq!(
            reg["@id"],
            "https://example.com/nuget/repo/v3/registration/"
        );
        assert_eq!(reg["@type"], "RegistrationsBaseUrl");
    }

    // -----------------------------------------------------------------------
    // build_registration_item
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_registration_item_basic() {
        let item = build_registration_item(
            "https://example.com/nuget/repo",
            "newtonsoft.json",
            "13.0.1",
            "Popular JSON framework",
            "James Newton-King",
        );
        assert_eq!(item["catalogEntry"]["id"], "newtonsoft.json");
        assert_eq!(item["catalogEntry"]["version"], "13.0.1");
        assert_eq!(
            item["catalogEntry"]["description"],
            "Popular JSON framework"
        );
        assert_eq!(item["catalogEntry"]["authors"], "James Newton-King");
        assert_eq!(item["catalogEntry"]["listed"], true);
    }

    #[test]
    fn test_build_registration_item_package_content_url() {
        let item = build_registration_item(
            "https://example.com/nuget/repo",
            "mypackage",
            "1.0.0",
            "",
            "",
        );
        let url = item["packageContent"].as_str().unwrap();
        assert_eq!(
            url,
            "https://example.com/nuget/repo/v3/flatcontainer/mypackage/1.0.0/mypackage.1.0.0.nupkg"
        );
    }

    #[test]
    fn test_build_registration_item_empty_metadata() {
        let item = build_registration_item("http://localhost/nuget/local", "pkg", "0.1.0", "", "");
        assert_eq!(item["catalogEntry"]["description"], "");
        assert_eq!(item["catalogEntry"]["authors"], "");
    }

    // -----------------------------------------------------------------------
    // build_flatcontainer_versions_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_flatcontainer_versions_json_basic() {
        let versions = vec![
            "1.0.0".to_string(),
            "2.0.0".to_string(),
            "3.0.0".to_string(),
        ];
        let json = build_flatcontainer_versions_json(&versions);
        let arr = json["versions"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], "1.0.0");
        assert_eq!(arr[2], "3.0.0");
    }

    #[test]
    fn test_build_flatcontainer_versions_json_empty() {
        let versions: Vec<String> = vec![];
        let json = build_flatcontainer_versions_json(&versions);
        assert!(json["versions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_flatcontainer_versions_json_single() {
        let versions = vec!["1.0.0-beta".to_string()];
        let json = build_flatcontainer_versions_json(&versions);
        let arr = json["versions"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], "1.0.0-beta");
    }

    // -----------------------------------------------------------------------
    // build_nuget_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_artifact_path_basic() {
        assert_eq!(
            build_nuget_artifact_path("newtonsoft.json", "13.0.1"),
            "newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    #[test]
    fn test_build_nuget_artifact_path_prerelease() {
        assert_eq!(
            build_nuget_artifact_path("mypackage", "1.0.0-beta.1"),
            "mypackage/1.0.0-beta.1/mypackage.1.0.0-beta.1.nupkg"
        );
    }

    // -----------------------------------------------------------------------
    // build_nuget_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_storage_key_basic() {
        assert_eq!(
            build_nuget_storage_key("newtonsoft.json", "13.0.1"),
            "nuget/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    // -----------------------------------------------------------------------
    // build_nuget_push_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_push_metadata_basic() {
        let info = NuspecInfo {
            id: "TestPackage".to_string(),
            version: "2.0.0".to_string(),
            description: "A test package".to_string(),
            authors: "Author".to_string(),
        };
        let meta = build_nuget_push_metadata(&info);
        assert_eq!(meta["id"], "TestPackage");
        assert_eq!(meta["version"], "2.0.0");
        assert_eq!(meta["description"], "A test package");
        assert_eq!(meta["authors"], "Author");
        assert_eq!(meta["filename"], "testpackage.2.0.0.nupkg");
    }

    #[test]
    fn test_build_nuget_push_metadata_preserves_original_id() {
        let info = NuspecInfo {
            id: "Newtonsoft.Json".to_string(),
            version: "13.0.1".to_string(),
            description: "JSON framework".to_string(),
            authors: "James NK".to_string(),
        };
        let meta = build_nuget_push_metadata(&info);
        // id is preserved as-is (with original casing)
        assert_eq!(meta["id"], "Newtonsoft.Json");
        // filename is lowercased
        assert_eq!(meta["filename"], "newtonsoft.json.13.0.1.nupkg");
    }

    // -----------------------------------------------------------------------
    // build_nuget_search_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_search_pattern_basic() {
        assert_eq!(build_nuget_search_pattern("json"), "%json%");
    }

    #[test]
    fn test_build_nuget_search_pattern_case_insensitive() {
        assert_eq!(build_nuget_search_pattern("Newton"), "%newton%");
    }

    #[test]
    fn test_build_nuget_search_pattern_empty() {
        assert_eq!(build_nuget_search_pattern(""), "%%");
    }

    #[test]
    fn test_build_nuget_search_pattern_with_dots() {
        assert_eq!(
            build_nuget_search_pattern("Newtonsoft.Json"),
            "%newtonsoft.json%"
        );
    }

    // -----------------------------------------------------------------------
    // is_prerelease_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_prerelease_version_stable() {
        assert!(!is_prerelease_version("1.0.0"));
        assert!(!is_prerelease_version("13.0.1"));
        assert!(!is_prerelease_version("2.0.0"));
    }

    #[test]
    fn test_is_prerelease_version_prerelease() {
        assert!(is_prerelease_version("2.0.0-beta.1"));
        assert!(is_prerelease_version("1.0.0-rc1"));
        assert!(is_prerelease_version("3.1.0-alpha"));
    }

    // -----------------------------------------------------------------------
    // select_latest_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_select_latest_version_excludes_prerelease_by_default() {
        // prerelease=false: the stable 1.0.0 wins over 2.0.0-beta.1, matching
        // the QA finding where prerelease=false wrongly returned 2.0.0-beta.1.
        let versions = vec!["1.0.0".to_string(), "2.0.0-beta.1".to_string()];
        assert_eq!(select_latest_version(&versions, false), "1.0.0");
    }

    #[test]
    fn test_select_latest_version_includes_prerelease_when_requested() {
        // prerelease=true: the highest overall version (the beta) wins.
        let versions = vec!["1.0.0".to_string(), "2.0.0-beta.1".to_string()];
        assert_eq!(select_latest_version(&versions, true), "2.0.0-beta.1");
    }

    #[test]
    fn test_select_latest_version_falls_back_to_prerelease_when_no_stable() {
        // Only a pre-release exists; even with prerelease=false it must be
        // surfaced rather than the "0.0.0" placeholder.
        let versions = vec!["1.0.0-alpha".to_string()];
        assert_eq!(select_latest_version(&versions, false), "1.0.0-alpha");
    }

    #[test]
    fn test_select_latest_version_highest_stable() {
        let versions = vec![
            "1.0.0".to_string(),
            "1.2.0".to_string(),
            "1.1.0".to_string(),
        ];
        assert_eq!(select_latest_version(&versions, false), "1.2.0");
    }

    #[test]
    fn test_select_latest_version_empty() {
        let versions: Vec<String> = vec![];
        assert_eq!(select_latest_version(&versions, false), "0.0.0");
        assert_eq!(select_latest_version(&versions, true), "0.0.0");
    }

    #[tokio::test]
    async fn test_flatcontainer_download_remote_arm_routes_through_cached_or_refetch_helper() {
        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };

        let nupkg_bytes: &[u8] = b"cached-nupkg-from-disk";
        let package_id = "newtonsoft.json";
        let package_id_lower = package_id.to_lowercase();
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id_lower, version);

        // Upstream URL only needs to parse; no network I/O is performed here.
        let upstream = "https://upstream.example.test".to_string();
        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage_path.as_str(), proxy);

        let repo_info = fx.repo_info("remote", Some(&upstream));

        // Seed storage and DB row. The handler looks up by name (lowercased)
        // and version, so the exact `path` inserted is unimportant here.
        let storage_key = format!("nuget/{}/{}/{}", package_id_lower, version, filename);
        let artifact_path = format!(
            "v3/flatcontainer/{}/{}/{}",
            package_id_lower, version, filename
        );

        tdh::seed_artifact(
            &state,
            &fx.pool,
            &repo_info,
            &storage_key,
            &artifact_path,
            &package_id_lower,
            version,
            "application/octet-stream",
            Bytes::from_static(nupkg_bytes),
            fx.user_id,
        )
        .await;

        // Call the handler directly via extractors.
        let result = super::flatcontainer_download(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                fx.repo_key.clone(),
                package_id_lower.clone(),
                version.to_string(),
                filename.clone(),
            )),
        )
        .await;

        // Cleanup first so a panic does not leave DB state behind.
        let cleanup_pool = fx.pool.clone();
        let cleanup_repo = fx.repo_id;
        let cleanup_user = fx.user_id;
        let cleanup_dir = fx.storage_dir.clone();
        let cleanup = || async move {
            tdh::cleanup(&cleanup_pool, cleanup_repo, cleanup_user).await;
            let _ = std::fs::remove_dir_all(&cleanup_dir);
        };

        let response = match result {
            Ok(r) => r,
            Err(r) => {
                let status = r.status();
                cleanup().await;
                panic!("flatcontainer_download Remote arm must serve cached payload, got {status}");
            }
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("Content-Type")
                .to_str()
                .unwrap(),
            "application/octet-stream",
        );
        assert_eq!(
            response
                .headers()
                .get(CONTENT_LENGTH)
                .expect("Content-Length")
                .to_str()
                .unwrap(),
            nupkg_bytes.len().to_string(),
        );
        assert_eq!(
            response
                .headers()
                .get("Content-Disposition")
                .expect("Content-Disposition")
                .to_str()
                .unwrap(),
            format!("attachment; filename=\"{}\"", filename),
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        assert_eq!(&body_bytes[..], nupkg_bytes);

        cleanup().await;
    }
}

// ---------------------------------------------------------------------------
// DB-backed router tests for the `push_package` paths added in
// fix/nuget-push-trailing-slash-and-package-index:
//
//   1. The route is registered both with and without a trailing slash so
//      `dotnet nuget push` (which appends a slash to the PackagePublish URL)
//      hits the same handler. Each variant is exercised end-to-end.
//   2. After a successful push, the handler calls
//      `PackageService::try_create_or_update_from_artifact` so the package
//      surfaces in the UI Packages tab. The description is folded from an
//      empty `<description/>` in the nuspec to `Option::None` so the
//      `packages.description` column is NULL rather than the empty string.
//
// These tests rely on `DATABASE_URL` being set (CI seeds + migrates a
// Postgres before running `cargo llvm-cov --lib`). They no-op cleanly
// in environments without Postgres.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod push_db_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use std::io::Write;

    /// Build a minimal valid `.nupkg` (ZIP archive with a single `.nuspec`)
    /// using the given package id, version, and description. Mirrors the
    /// shape produced by `dotnet pack`. Authors is fixed since the new code
    /// path does not branch on it.
    fn build_nupkg(id: &str, version: &str, description: &str) -> Vec<u8> {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("{}.nuspec", id), options).unwrap();
        let nuspec = format!(
            "<?xml version=\"1.0\"?>\n\
             <package>\n  <metadata>\n\
             <id>{}</id>\n\
             <version>{}</version>\n\
             <description>{}</description>\n\
             <authors>Test Author</authors>\n\
             </metadata>\n</package>",
            id, version, description
        );
        zip.write_all(nuspec.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();
        cursor.into_inner()
    }

    /// Send a PUT to `uri` carrying `nupkg_bytes` as a raw application/octet
    /// stream body (the path `extract_nupkg_bytes` takes when no multipart
    /// boundary is present).
    async fn put_nupkg(uri: String, nupkg_bytes: Vec<u8>) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("PUT")
            .uri(uri)
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(nupkg_bytes))
            .expect("build PUT request")
    }

    // -----------------------------------------------------------------------
    // Route registration: trailing slash and no trailing slash both
    // reach `push_package`. We confirm via end-to-end success (HTTP 201 or
    // similar 2xx) for each URL shape.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn push_package_route_accepts_no_trailing_slash() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let pkg = build_nupkg("RouteNoSlashPkg", "1.0.0", "no-slash route");
        let app = f.router_with_auth(super::router());
        let req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), pkg).await;
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "expected 2xx for /api/v2/package, got {}: {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        // Verify the artifact landed in the DB.
        let exists: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM artifacts \
             WHERE repository_id = $1 AND LOWER(name) = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("routenoslashpkg")
        .bind("1.0.0")
        .fetch_optional(&f.pool)
        .await
        .expect("query artifact");
        assert!(exists.is_some(), "artifact row must exist after push");

        f.teardown().await;
    }

    #[tokio::test]
    async fn push_package_route_accepts_trailing_slash() {
        // The bug this PR fixes: `dotnet nuget push` appends a trailing
        // slash to the PackagePublish/2.0.0 URL from the v3 index. Before
        // the fix, this returned 405/404. After the fix the route maps to
        // `push_package` and the push succeeds end-to-end.
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let pkg = build_nupkg("RouteWithSlashPkg", "2.0.0", "trailing-slash route");
        let app = f.router_with_auth(super::router());
        let req = put_nupkg(format!("/{}/api/v2/package/", f.repo_key), pkg).await;
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "expected 2xx for /api/v2/package/ (with slash), got {}: {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        let exists: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM artifacts \
             WHERE repository_id = $1 AND LOWER(name) = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("routewithslashpkg")
        .bind("2.0.0")
        .fetch_optional(&f.pool)
        .await
        .expect("query artifact");
        assert!(
            exists.is_some(),
            "trailing-slash push must create the artifact row"
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Packages-index population: `try_create_or_update_from_artifact` runs
    // on every successful push and the description-folding branch must map
    // a non-empty `<description>` to `Some(...)` (persisted) and an empty
    // one to `None` (NULL column).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn push_package_populates_packages_index_with_description() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let pkg = build_nupkg("IndexedPkg", "3.1.4", "an indexed package");
        let app = f.router_with_auth(super::router());
        let req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), pkg).await;
        let (status, _) = tdh::send(app, req).await;
        assert!(status.is_success(), "push failed: {}", status);

        // The handler passes the original-case `nuspec.id` to
        // `PackageService::try_create_or_update_from_artifact`, so the
        // packages row is keyed by the original casing. (The artifacts row
        // uses the lowercased name from the duplicate-check path; the two
        // tables intentionally diverge for legacy reasons.)
        let row: Option<(String, String, Option<String>, Option<serde_json::Value>)> =
            sqlx::query_as(
                "SELECT name, version, description, metadata FROM packages \
                 WHERE repository_id = $1 AND name = $2",
            )
            .bind(f.repo_id)
            .bind("IndexedPkg")
            .fetch_optional(&f.pool)
            .await
            .expect("query packages");

        let (name, version, desc, meta) = row.expect("packages row must exist after push");
        assert_eq!(name, "IndexedPkg");
        assert_eq!(version, "3.1.4");
        assert_eq!(
            desc.as_deref(),
            Some("an indexed package"),
            "non-empty <description> must be persisted as Some(...)"
        );
        // The metadata JSON the handler passes is `{ "format": "nuget" }`.
        let meta = meta.expect("metadata must be set");
        assert_eq!(meta["format"], "nuget");

        // package_versions should be populated too (UPSERT in the service).
        let version_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2 AND pv.version = $3",
        )
        .bind(f.repo_id)
        .bind("IndexedPkg")
        .bind("3.1.4")
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions");
        assert_eq!(
            version_count.0, 1,
            "exactly one package_versions row expected after a single push"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn push_multiple_versions_collapses_into_one_package_row() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let app = f.router_with_auth(super::router());

        let first = build_nupkg("MultiVersionPkg", "9.0.0", "first");
        let first_req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), first).await;
        let (first_status, _) = tdh::send(app.clone(), first_req).await;
        assert!(
            first_status.is_success(),
            "first push failed: {}",
            first_status
        );

        let second = build_nupkg("MultiVersionPkg", "10.0.0", "second");
        let second_req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), second).await;
        let (second_status, _) = tdh::send(app, second_req).await;
        assert!(
            second_status.is_success(),
            "second push failed: {}",
            second_status
        );

        let package_rows: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM packages WHERE repository_id = $1 AND name = $2",
        )
        .bind(f.repo_id)
        .bind("MultiVersionPkg")
        .fetch_one(&f.pool)
        .await
        .expect("query packages");
        assert_eq!(
            package_rows.0, 1,
            "multiple versions should collapse into a single packages row"
        );

        let package: (String,) =
            sqlx::query_as("SELECT version FROM packages WHERE repository_id = $1 AND name = $2")
                .bind(f.repo_id)
                .bind("MultiVersionPkg")
                .fetch_one(&f.pool)
                .await
                .expect("query package version");
        assert_eq!(package.0, "10.0.0");

        let version_rows: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2",
        )
        .bind(f.repo_id)
        .bind("MultiVersionPkg")
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions");
        assert_eq!(version_rows.0, 2, "both versions should remain addressable");

        f.teardown().await;
    }

    #[tokio::test]
    async fn push_package_packages_index_empty_description_maps_to_null() {
        // Covers the `if nuspec.description.is_empty() { None } else
        // { Some(...) }` branch added in this PR: an empty <description/>
        // must land as NULL in the packages table rather than an empty
        // string.
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let pkg = build_nupkg("NoDescPkg", "0.1.0", "");
        let app = f.router_with_auth(super::router());
        let req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), pkg).await;
        let (status, _) = tdh::send(app, req).await;
        assert!(status.is_success(), "push failed: {}", status);

        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT description FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("NoDescPkg")
        .bind("0.1.0")
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");

        let (desc,) = row.expect("packages row must exist after push");
        assert!(
            desc.is_none(),
            "empty <description> must fold to NULL, got {:?}",
            desc
        );

        f.teardown().await;
    }
}

// ---------------------------------------------------------------------------
// DB-backed read-endpoint regression tests (#1778).
//
// These cover the QA findings that the search/registration/flatcontainer read
// endpoints:
//   * hardcoded an empty `description` in search results,
//   * ignored the `prerelease` flag,
//   * returned 404 instead of federating across virtual-repo members.
//
// They no-op cleanly when `DATABASE_URL` is unset.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod read_db_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;
    use std::io::Write;
    use uuid::Uuid;

    /// Build a minimal valid `.nupkg` (ZIP with a single `.nuspec`).
    fn build_nupkg(id: &str, version: &str, description: &str) -> Vec<u8> {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("{}.nuspec", id), options).unwrap();
        let nuspec = format!(
            "<?xml version=\"1.0\"?>\n\
             <package>\n  <metadata>\n\
             <id>{}</id>\n\
             <version>{}</version>\n\
             <description>{}</description>\n\
             <authors>Test Author</authors>\n\
             </metadata>\n</package>",
            id, version, description
        );
        zip.write_all(nuspec.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();
        cursor.into_inner()
    }

    /// Push a package into the repo identified by `repo_key` via the handler.
    async fn push_pkg(
        f: &tdh::Fixture,
        repo_key: &str,
        id: &str,
        version: &str,
        description: &str,
    ) {
        let app = f.router_with_auth(super::router());
        let req = tdh::put(
            format!("/{}/api/v2/package", repo_key),
            bytes::Bytes::from(build_nupkg(id, version, description)),
        );
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "push of {}.{} failed: {} {:?}",
            id,
            version,
            status,
            String::from_utf8_lossy(&body)
        );
    }

    /// GET a NuGet read endpoint anonymously (read paths require no auth).
    async fn get_json(f: &tdh::Fixture, uri: String) -> (StatusCode, serde_json::Value) {
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(app, tdh::get(uri)).await;
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    // Finding: search always returned a hardcoded empty `description`.
    #[tokio::test]
    async fn search_returns_package_description() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        push_pkg(
            &f,
            &f.repo_key,
            "Qa.DescPkg",
            "1.0.0",
            "a documented package",
        )
        .await;

        let (status, json) = get_json(&f, format!("/{}/v3/search?q=qa.descpkg", f.repo_key)).await;
        assert_eq!(status, StatusCode::OK);
        let data = json["data"].as_array().expect("data array");
        assert_eq!(data.len(), 1, "expected one hit; body={json}");
        assert_eq!(
            data[0]["description"], "a documented package",
            "search must surface the package description; body={json}"
        );

        f.teardown().await;
    }

    // Finding: the `prerelease` flag was parsed but ignored — search always
    // returned the highest version including pre-releases.
    #[tokio::test]
    async fn search_respects_prerelease_flag() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        push_pkg(&f, &f.repo_key, "Qa.PrerelPkg", "1.0.0", "stable").await;
        push_pkg(&f, &f.repo_key, "Qa.PrerelPkg", "2.0.0-beta.1", "beta").await;

        // prerelease=false → the stable 1.0.0 must win.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/search?q=qa.prerelpkg&prerelease=false", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["data"][0]["version"], "1.0.0",
            "prerelease=false must surface the stable version; body={json}"
        );

        // prerelease=true → the higher pre-release wins.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/search?q=qa.prerelpkg&prerelease=true", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["data"][0]["version"], "2.0.0-beta.1",
            "prerelease=true must surface the pre-release; body={json}"
        );

        f.teardown().await;
    }

    /// Create a virtual repo and link `member_id` as its sole member.
    async fn create_virtual_with_member(pool: &sqlx::PgPool, member_id: Uuid) -> (Uuid, String) {
        let (vid, vkey, _dir) = tdh::create_repo(pool, "virtual", "nuget").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(vid)
        .bind(member_id)
        .execute(pool)
        .await
        .expect("link virtual member");
        (vid, vkey)
    }

    async fn drop_virtual(pool: &sqlx::PgPool, vid: Uuid) {
        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(vid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(vid)
            .execute(pool)
            .await;
    }

    // Findings: registration/index, flatcontainer/index, and search all
    // returned 404 / empty instead of federating across virtual members.
    #[tokio::test]
    async fn virtual_repo_federates_read_endpoints_over_local_member() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        // Seed a package into the local member.
        push_pkg(&f, &f.repo_key, "Qa.FedPkg", "1.0.0", "federated package").await;

        let (vid, vkey) = create_virtual_with_member(&f.pool, f.repo_id).await;

        // registration/index must federate to the member and return 200.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/registration/qa.fedpkg/index.json", vkey),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "virtual registration must federate; body={json}"
        );
        let items = json["items"][0]["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["catalogEntry"]["version"], "1.0.0");

        // flatcontainer/index must federate to the member and return 200.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/flatcontainer/qa.fedpkg/index.json", vkey),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "virtual flatcontainer must federate; body={json}"
        );
        assert_eq!(json["versions"][0], "1.0.0");

        // search must federate to the member and return the hit.
        let (status, json) = get_json(&f, format!("/{}/v3/search?q=qa.fed", vkey)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["totalHits"], 1,
            "virtual search must federate over members; body={json}"
        );
        assert_eq!(json["data"][0]["id"], "qa.fedpkg");

        drop_virtual(&f.pool, vid).await;
        f.teardown().await;
    }
}
