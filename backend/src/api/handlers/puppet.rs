//! Puppet Forge API handlers.
//!
//! Implements the endpoints required for Puppet module management.
//!
//! Routes are mounted at `/puppet/{repo_key}/...`:
//!   GET  /puppet/{repo_key}/v3/modules/{owner}-{name}                  - Module info
//!   GET  /puppet/{repo_key}/v3/modules/{owner}-{name}/releases         - Release list
//!   GET  /puppet/{repo_key}/v3/releases/{owner}-{name}-{version}       - Release info
//!   GET  /puppet/{repo_key}/v3/files/{owner}-{name}-{version}.tar.gz   - Download
//!   POST /puppet/{repo_key}/v3/releases                                - Publish module

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
use crate::formats::puppet::PuppetHandler;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/v3/modules/:owner_name", get(module_info))
        .route(
            "/:repo_key/v3/modules/:owner_name/releases",
            get(release_list),
        )
        .route(
            "/:repo_key/v3/releases/:owner_name_version",
            get(release_info),
        )
        .route("/:repo_key/v3/files/*file_path", get(download_module))
        .route("/:repo_key/v3/releases", post(publish_module))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_puppet_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["puppet"], "a Puppet").await
}

/// Parse an "owner-name" string into (owner, name) by splitting on the first hyphen.
#[allow(clippy::result_large_err)]
fn parse_owner_name(s: &str) -> Result<(String, String), Response> {
    let first_hyphen = s.find('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid module identifier '{}': expected owner-name", s),
        )
            .into_response()
    })?;

    let owner = s[..first_hyphen].to_string();
    let name = s[first_hyphen + 1..].to_string();

    if owner.is_empty() || name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Owner and name must not be empty").into_response());
    }

    Ok((owner, name))
}

/// Parse an "owner-name-version" string into (owner, name, version).
#[allow(clippy::result_large_err)]
fn parse_owner_name_version(s: &str) -> Result<(String, String, String), Response> {
    let first_hyphen = s.find('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid release identifier '{}': expected owner-name-version",
                s
            ),
        )
            .into_response()
    })?;

    let owner = s[..first_hyphen].to_string();
    let remainder = &s[first_hyphen + 1..];

    let last_hyphen = remainder.rfind('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid release identifier '{}': expected owner-name-version",
                s
            ),
        )
            .into_response()
    })?;

    let name = remainder[..last_hyphen].to_string();
    let version = remainder[last_hyphen + 1..].to_string();

    if owner.is_empty() || name.is_empty() || version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Owner, name, and version must not be empty",
        )
            .into_response());
    }

    Ok((owner, name, version))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/modules/{owner}-{name} — Module info
// ---------------------------------------------------------------------------

async fn module_info(
    State(state): State<SharedState>,
    Path((repo_key, owner_name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name) = parse_owner_name(&owner_name)?;

    // Validate via format handler
    let validate_path = format!("v3/modules/{}-{}", owner, name);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    let artifact = proxy_helpers::find_artifact_by_name_lowercase(
        &state.db,
        repo.id,
        &format!("{}-{}", owner, name),
    )
    .await?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Module not found").into_response())?;

    let current_version = artifact.version.clone().unwrap_or_default();

    let json = serde_json::json!({
        "slug": format!("{}-{}", owner, name),
        "name": name,
        "owner": { "slug": owner, "username": owner },
        "current_release": {
            "version": current_version,
            "slug": format!("{}-{}-{}", owner, name, current_version),
            "file_uri": format!(
                "/puppet/{}/v3/files/{}-{}-{}.tar.gz",
                repo_key, owner, name, current_version
            ),
        },
        "releases": [],
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/modules/{owner}-{name}/releases — Release list
// ---------------------------------------------------------------------------

async fn release_list(
    State(state): State<SharedState>,
    Path((repo_key, owner_name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name) = parse_owner_name(&owner_name)?;

    let artifacts = proxy_helpers::list_artifacts_by_name_lowercase(
        &state.db,
        repo.id,
        &format!("{}-{}", owner, name),
    )
    .await?;

    let releases: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "slug": format!("{}-{}-{}", owner, name, version),
                "version": version,
                "file_uri": format!(
                    "/puppet/{}/v3/files/{}-{}-{}.tar.gz",
                    repo_key, owner, name, version
                ),
                "file_size": a.size_bytes,
                "file_sha256": a.checksum_sha256,
                "metadata": a.metadata.clone().unwrap_or(serde_json::json!({})),
            })
        })
        .collect();

    let json = serde_json::json!({
        "pagination": {
            "limit": 20,
            "offset": 0,
            "total": releases.len(),
        },
        "results": releases,
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/releases/{owner}-{name}-{version} — Release info
// ---------------------------------------------------------------------------

async fn release_info(
    State(state): State<SharedState>,
    Path((repo_key, owner_name_version)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name, version) = parse_owner_name_version(&owner_name_version)?;

    // Validate via format handler
    let validate_path = format!("v3/releases/{}-{}-{}", owner, name, version);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    let module_name = format!("{}-{}", owner, name);
    let artifact =
        proxy_helpers::find_artifact_by_name_version(&state.db, repo.id, &module_name, &version)
            .await?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Release not found").into_response())?;

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "slug": format!("{}-{}-{}", owner, name, version),
        "version": version,
        "module": {
            "slug": format!("{}-{}", owner, name),
            "name": name,
            "owner": { "slug": owner, "username": owner },
        },
        "file_uri": format!(
            "/puppet/{}/v3/files/{}-{}-{}.tar.gz",
            repo_key, owner, name, version
        ),
        "file_size": artifact.size_bytes,
        "file_sha256": artifact.checksum_sha256,
        "downloads": download_count,
        "metadata": artifact.metadata.unwrap_or(serde_json::json!({})),
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/files/{owner}-{name}-{version}.tar.gz — Download
// ---------------------------------------------------------------------------

async fn download_module(
    State(state): State<SharedState>,
    Path((repo_key, file_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;

    let filename = file_path.trim_start_matches('/');

    let artifact =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, filename).await? {
            Some(a) => a,
            None => {
                let upstream_path = format!("v3/files/{}", filename);
                // Remote: no Content-Disposition; Virtual: include filename.
                let (default_ct, cd_filename) = if repo.repo_type == RepositoryType::Virtual {
                    ("application/gzip", Some(filename))
                } else {
                    ("application/octet-stream", None)
                };
                if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                    &state,
                    &repo,
                    proxy_helpers::DownloadResponseOpts {
                        upstream_path: &upstream_path,
                        virtual_lookup: proxy_helpers::VirtualLookup::PathSuffix(filename),
                        default_content_type: default_ct,
                        content_disposition_filename: cd_filename,
                    },
                )
                .await?
                {
                    return Ok(resp);
                }
                return Err((StatusCode::NOT_FOUND, "Module file not found").into_response());
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
// POST /puppet/{repo_key}/v3/releases — Publish module (multipart)
// ---------------------------------------------------------------------------

async fn publish_module(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "puppet")?.user_id;
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let (tarball, module_json) =
        proxy_helpers::parse_multipart_file_with_json(multipart, &["module"]).await?;

    let (owner, module_name, module_version) = if let Some(ref json) = module_json {
        let owner = json
            .get("owner")
            .or_else(|| json.get("author"))
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
        (owner, name, version)
    } else {
        return Err((StatusCode::BAD_REQUEST, "Missing module metadata JSON").into_response());
    };

    if owner.is_empty() || module_name.is_empty() || module_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Owner, name, and version are required",
        )
            .into_response());
    }

    // Validate via format handler
    let validate_path = format!("v3/releases/{}-{}-{}", owner, module_name, module_version);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid module: {}", e)).into_response())?;

    let full_name = format!("{}-{}", owner, module_name);
    let filename = format!("{}-{}-{}.tar.gz", owner, module_name, module_version);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&tarball);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}/{}", full_name, module_version, filename);

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Module version already exists",
    )
    .await?;

    let storage_key = format!("puppet/{}/{}/{}", full_name, module_version, filename);
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, tarball.clone()).await?;

    let puppet_metadata = serde_json::json!({
        "owner": owner,
        "module_name": module_name,
        "version": module_version,
        "filename": filename,
        "module_json": module_json,
    });

    let size_bytes = tarball.len() as i64;

    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &full_name,
            version: &module_version,
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
        "puppet",
        &puppet_metadata,
    )
    .await;

    info!(
        "Puppet publish: {}-{} {} ({}) to repo {}",
        owner, module_name, module_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "slug": format!("{}-{}-{}", owner, module_name, module_version),
        "file_uri": format!(
            "/puppet/{}/v3/files/{}",
            repo_key, filename
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
    use super::*;

    #[test]
    fn test_parse_owner_name_valid() {
        let result = parse_owner_name("puppetlabs-stdlib");
        assert!(result.is_ok());
        let (owner, name) = result.unwrap();
        assert_eq!(owner, "puppetlabs");
        assert_eq!(name, "stdlib");
    }

    #[test]
    fn test_parse_owner_name_multiple_hyphens() {
        let result = parse_owner_name("puppetlabs-my-module");
        assert!(result.is_ok());
        let (owner, name) = result.unwrap();
        assert_eq!(owner, "puppetlabs");
        assert_eq!(name, "my-module");
    }

    #[test]
    fn test_parse_owner_name_no_hyphen() {
        let result = parse_owner_name("nohyphen");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_empty_owner() {
        let result = parse_owner_name("-name");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_empty_name() {
        let result = parse_owner_name("owner-");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_version_valid() {
        let result = parse_owner_name_version("puppetlabs-stdlib-1.2.3");
        assert!(result.is_ok());
        let (owner, name, version) = result.unwrap();
        assert_eq!(owner, "puppetlabs");
        assert_eq!(name, "stdlib");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn test_parse_owner_name_version_complex_name() {
        let result = parse_owner_name_version("myorg-my-complex-module-2.0.0");
        assert!(result.is_ok());
        let (owner, name, version) = result.unwrap();
        assert_eq!(owner, "myorg");
        assert_eq!(name, "my-complex-module");
        assert_eq!(version, "2.0.0");
    }

    #[test]
    fn test_parse_owner_name_version_no_hyphen() {
        let result = parse_owner_name_version("nohyphen");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_version_only_one_hyphen() {
        let result = parse_owner_name_version("owner-rest");
        // "rest" has no last_hyphen, since remainder="rest" and rfind('-') returns None
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_version_empty_parts() {
        let result = parse_owner_name_version("-name-version");
        assert!(result.is_err());
    }

    #[test]
    fn test_puppet_module_slug_format() {
        let owner = "puppetlabs";
        let name = "apache";
        let version = "5.0.0";
        let slug = format!("{}-{}-{}", owner, name, version);
        assert_eq!(slug, "puppetlabs-apache-5.0.0");
    }

    #[test]
    fn test_puppet_filename_format() {
        let owner = "puppetlabs";
        let module_name = "ntp";
        let module_version = "9.0.1";
        let filename = format!("{}-{}-{}.tar.gz", owner, module_name, module_version);
        assert_eq!(filename, "puppetlabs-ntp-9.0.1.tar.gz");
    }

    #[test]
    fn test_puppet_storage_key_format() {
        let full_name = "puppetlabs-ntp";
        let module_version = "9.0.1";
        let filename = "puppetlabs-ntp-9.0.1.tar.gz";
        let storage_key = format!("puppet/{}/{}/{}", full_name, module_version, filename);
        assert_eq!(
            storage_key,
            "puppet/puppetlabs-ntp/9.0.1/puppetlabs-ntp-9.0.1.tar.gz"
        );
    }

    #[test]
    fn test_puppet_metadata_json() {
        let owner = "puppetlabs";
        let module_name = "stdlib";
        let module_version = "8.0.0";
        let filename = "puppetlabs-stdlib-8.0.0.tar.gz";

        let metadata = serde_json::json!({
            "owner": owner,
            "module_name": module_name,
            "version": module_version,
            "filename": filename,
            "module_json": serde_json::json!(null),
        });

        assert_eq!(metadata["owner"], "puppetlabs");
        assert_eq!(metadata["module_name"], "stdlib");
    }
}
