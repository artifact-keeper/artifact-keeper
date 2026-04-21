//! Docker Registry V2 API (OCI Distribution Spec) handlers.
//!
//! Implements the minimum endpoints required for `docker login`, `docker push`,
//! and `docker pull` per the OCI Distribution Specification.
//!
// TODO(#553): OCI errors use a spec-mandated JSON envelope (oci_error fn) and
// cannot be converted to AppError without breaking Docker/OCI client compat.
// Consider wrapping oci_error to also log via tracing for consistency.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::models::repository::RepositoryType;
use crate::services::auth_service::AuthService;

// ---------------------------------------------------------------------------
// OCI error helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct OciErrorResponse {
    errors: Vec<OciErrorEntry>,
}

#[derive(Serialize)]
struct OciErrorEntry {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

fn oci_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = OciErrorResponse {
        errors: vec![OciErrorEntry {
            code: code.to_string(),
            message: message.to_string(),
            detail: None,
        }],
    };
    let json = serde_json::to_string(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(json))
        .unwrap()
}

fn www_authenticate_header(host: &str, scope: Option<&str>) -> String {
    match scope {
        Some(s) => format!(
            "Bearer realm=\"{}/v2/token\",service=\"artifact-keeper\",scope=\"{}\"",
            host, s
        ),
        None => format!(
            "Bearer realm=\"{}/v2/token\",service=\"artifact-keeper\"",
            host
        ),
    }
}

fn unauthorized_challenge(host: &str) -> Response {
    unauthorized_challenge_with_scope(host, None)
}

fn unauthorized_challenge_with_scope(host: &str, scope: Option<&str>) -> Response {
    let body = OciErrorResponse {
        errors: vec![OciErrorEntry {
            code: "UNAUTHORIZED".to_string(),
            message: "authentication required".to_string(),
            detail: None,
        }],
    };
    let json = serde_json::to_string(&body).unwrap_or_default();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", www_authenticate_header(host, scope))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(json))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/// Sentinel value returned by the token endpoint when no credentials are
/// supplied.  Read handlers accept this token and grant access only when
/// the target repository is marked as public.
const ANONYMOUS_TOKEN: &str = "anonymous";

/// Returns `true` when the bearer token is the anonymous pull token issued
/// to unauthenticated Docker clients.
fn is_anonymous_token(headers: &HeaderMap) -> bool {
    extract_bearer_token(headers).as_deref() == Some(ANONYMOUS_TOKEN)
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
        .map(|s| s.to_string())
}

fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
}

fn validate_token(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<crate::services::auth_service::Claims, ()> {
    let token = extract_bearer_token(headers).ok_or(())?;
    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    auth_service.validate_access_token(&token).map_err(|_| ())
}

/// Authenticate an OCI request by trying Bearer token first, then falling back
/// to Basic credentials (username/password or username/api-token).  This mirrors
/// the `version_check` logic so that Docker, Podman, and plain HTTP clients can
/// all authenticate regardless of whether they went through the token exchange.
async fn authenticate_oci(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<crate::services::auth_service::Claims, ()> {
    // Try Bearer token first (standard OCI token-exchange flow).
    if let Ok(claims) = validate_token(db, config, headers) {
        return Ok(claims);
    }

    // Fall back to Basic auth (curl, CI runners, HTTP clients that skip the
    // token exchange).
    let (username, password) = extract_basic_credentials(headers).ok_or(())?;
    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    if let Ok((user, _tokens)) = auth_service.authenticate(&username, &password).await {
        // Re-generate short-lived claims so downstream code has a consistent
        // Claims value regardless of the authentication method.
        return auth_service
            .generate_tokens(&user)
            .map_err(|_| ())
            .and_then(|tokens| {
                auth_service
                    .validate_access_token(&tokens.access_token)
                    .map_err(|_| ())
            });
    }

    // Also try API token in the password field (service accounts, CI pipelines).
    if let Ok(validation) = auth_service.validate_api_token(&password).await {
        return auth_service
            .generate_tokens(&validation.user)
            .map_err(|_| ())
            .and_then(|tokens| {
                auth_service
                    .validate_access_token(&tokens.access_token)
                    .map_err(|_| ())
            });
    }

    Err(())
}

/// Build a Docker/OCI scope string for a repository resource.
fn pull_scope(image_name: &str) -> String {
    format!("repository:{}:pull", image_name)
}

fn push_scope(image_name: &str) -> String {
    format!("repository:{}:pull,push", image_name)
}

fn request_host(headers: &HeaderMap) -> String {
    proxy_helpers::request_base_url(headers)
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn blob_storage_key(digest: &str) -> String {
    format!("oci-blobs/{}", digest)
}

fn manifest_storage_key(digest: &str) -> String {
    format!("oci-manifests/{}", digest)
}

fn upload_storage_key(uuid: &Uuid) -> String {
    format!("oci-uploads/{}", uuid)
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tags/list and catalog response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TagsListResponse {
    name: String,
    tags: Vec<String>,
}

#[derive(Serialize)]
struct CatalogResponse {
    repositories: Vec<String>,
}

/// Parse `n` and `last` pagination query parameters.
/// Returns `Err(Response)` with 400 PAGINATION_NUMBER_INVALID when `n` is
/// present but not a valid non-negative integer.
#[allow(clippy::result_large_err)] // Response-as-error is used throughout this module
fn parse_pagination_params(
    params: &std::collections::HashMap<String, String>,
) -> Result<(usize, Option<String>), Response> {
    let n = match params.get("n") {
        Some(v) => v.parse::<usize>().map_err(|_| {
            oci_error(
                StatusCode::BAD_REQUEST,
                "PAGINATION_NUMBER_INVALID",
                "invalid pagination parameter n",
            )
        })?,
        // OCI spec says "return all tags" without `n`, but we cap at a default
        // of 100 to prevent unbounded responses.  This matches Docker Hub's
        // observed behaviour.  A `Link` header is emitted when more results
        // exist, so well-behaved clients will paginate correctly.
        None => 100,
    }
    .min(10000);
    let last = params.get("last").cloned();
    Ok((n, last))
}

/// Build a `Link` header value for OCI pagination (RFC 5988).
/// Uses a relative URL which is reliable behind reverse proxies.
fn build_pagination_link_header(path: &str, last_item: &str, n: usize) -> String {
    let encoded_last = urlencoding::encode(last_item);
    format!("<{}?n={}&last={}>; rel=\"next\"", path, n, encoded_last)
}

fn oci_lexical_cmp(lhs: &str, rhs: &str) -> std::cmp::Ordering {
    lhs.to_ascii_lowercase()
        .cmp(&rhs.to_ascii_lowercase())
        .then_with(|| lhs.cmp(rhs))
}

/// Apply cursor-based pagination to a lexically sorted list.
/// Spec reference:
/// https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-tags
/// Returns (page, has_more).
fn apply_cursor_pagination(tags: Vec<String>, last: Option<&str>, n: usize) -> (Vec<String>, bool) {
    if n == 0 {
        return (vec![], false);
    }
    let start = match last {
        Some(cursor) => tags.partition_point(|t| {
            matches!(
                oci_lexical_cmp(t, cursor),
                std::cmp::Ordering::Less | std::cmp::Ordering::Equal
            )
        }),
        None => 0,
    };
    let end = (start + n).min(tags.len());
    let has_more = end < tags.len();
    (tags[start..end].to_vec(), has_more)
}

/// Merge multiple tag lists, deduplicate, and sort lexically
/// per OCI Distribution Spec.
/// Spec reference:
/// https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-tags
///
/// `dedup()` (consecutive-only) is sufficient here because `oci_lexical_cmp`
/// provides a total order: equal strings are always adjacent after `sort_by`.
fn merge_and_dedup_tags(tag_sets: Vec<Vec<String>>) -> Vec<String> {
    let mut all: Vec<String> = tag_sets.into_iter().flatten().collect();
    all.sort_by(|lhs, rhs| oci_lexical_cmp(lhs, rhs));
    all.dedup();
    all
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

/// Resolved OCI repository descriptor.
struct OciRepoInfo {
    id: Uuid,
    key: String,
    location: crate::storage::StorageLocation,
    repo_type: String,
    upstream_url: Option<String>,
    is_public: bool,
    image: String,
}

/// Resolve the first path segment as a repository key and the rest as the
/// image name within the repository.
async fn resolve_repo(db: &PgPool, image_name: &str) -> Result<OciRepoInfo, Response> {
    use sqlx::Row;
    // Split: "test/python" → repo_key="test", image="python"
    // Or:    "myrepo/org/image" → repo_key="myrepo", image="org/image"
    let (repo_key, image) = match image_name.find('/') {
        Some(idx) => (&image_name[..idx], &image_name[idx + 1..]),
        None => (image_name, image_name),
    };

    let repo = sqlx::query(
        "SELECT id, key, storage_backend, storage_path, repo_type::text as repo_type, \
         upstream_url, is_public FROM repositories WHERE key = $1",
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        )
    })?
    .ok_or_else(|| {
        oci_error(
            StatusCode::NOT_FOUND,
            "NAME_UNKNOWN",
            &format!("repository not found: {}", repo_key),
        )
    })?;

    let location = crate::storage::StorageLocation {
        backend: repo.try_get("storage_backend").unwrap_or_default(),
        path: repo.try_get("storage_path").unwrap_or_default(),
    };

    Ok(OciRepoInfo {
        id: repo.try_get("id").unwrap_or_default(),
        key: repo.try_get("key").unwrap_or_default(),
        location,
        repo_type: repo.try_get("repo_type").unwrap_or_default(),
        upstream_url: repo.try_get("upstream_url").ok(),
        is_public: repo.try_get("is_public").unwrap_or(false),
        image: image.to_string(),
    })
}

/// Check whether an upstream URL points to Docker Hub.
fn is_docker_hub(upstream_url: &str) -> bool {
    let host = upstream_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    host == "docker.io" || host.ends_with(".docker.io")
}

/// For Docker Hub upstreams, official images (single name, no slash) live under
/// the `library/` namespace. This function prepends it when needed.
fn normalize_docker_image(image: &str, upstream_url: &str) -> String {
    if !image.contains('/') && is_docker_hub(upstream_url) {
        format!("library/{}", image)
    } else {
        image.to_string()
    }
}

/// Check whether `reference` looks like an OCI content-addressable digest
/// rather than a human-readable tag. The grammar (from the OCI Distribution
/// Spec) is:
///
/// ```text
/// digest    ::= algorithm ":" encoded
/// algorithm ::= [a-z0-9]([a-z0-9._+-]*[a-z0-9])?
/// encoded   ::= [a-zA-Z0-9=_-]+
/// ```
fn is_digest_reference(reference: &str) -> bool {
    let Some((algorithm, encoded)) = reference.split_once(':') else {
        return false;
    };

    // OCI spec: algorithm = `[a-z0-9]+([+._-][a-z0-9]+)*` (lowercase only)
    !algorithm.is_empty()
        && !encoded.is_empty()
        && algorithm.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '+' | '.' | '-')
        })
        && encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '=' | '_' | '-'))
}

fn cached_manifest_reference_key(repo_type: &str, reference: &str, digest: &str) -> String {
    if repo_type == RepositoryType::Remote && !is_digest_reference(reference) {
        digest.to_string()
    } else {
        reference.to_string()
    }
}

async fn cache_manifest_reference_locally(
    state: &SharedState,
    repo: &OciRepoInfo,
    reference: &str,
    content: &Bytes,
    content_type: Option<&str>,
) -> Result<String, String> {
    let digest = compute_sha256(content);
    let storage = state
        .storage_for_repo(&repo.location)
        .map_err(|e| e.to_string())?;
    let manifest_key = manifest_storage_key(&digest);

    storage
        .put(&manifest_key, content.clone())
        .await
        .map_err(|e| e.to_string())?;

    let manifest_content_type = content_type
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();
    let cached_reference = cached_manifest_reference_key(&repo.repo_type, reference, &digest);

    sqlx::query(
        r#"INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (repository_id, name, tag) DO UPDATE SET
             manifest_digest = EXCLUDED.manifest_digest,
             manifest_content_type = EXCLUDED.manifest_content_type,
             updated_at = NOW()"#,
    )
    .bind(repo.id)
    .bind(&repo.image)
    .bind(cached_reference)
    .bind(&digest)
    .bind(&manifest_content_type)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(digest)
}

/// Cache a proxied manifest locally and return its digest. Falls back to
/// computing the digest without caching if persistence fails.
async fn cache_manifest_or_compute_digest(
    state: &SharedState,
    repo: &OciRepoInfo,
    image_name: &str,
    reference: &str,
    content: &Bytes,
    content_type: Option<&str>,
) -> String {
    match cache_manifest_reference_locally(state, repo, reference, content, content_type).await {
        Ok(digest) => digest,
        Err(e) => {
            warn!(
                image = image_name,
                reference = reference,
                error = %e,
                "Failed to persist proxied manifest locally — \
                 subsequent pulls will re-fetch from upstream until caching succeeds"
            );
            compute_sha256(content)
        }
    }
}

/// Try to fetch an OCI resource from the upstream registry for a remote repo.
/// Returns `None` if the repo is not remote, has no upstream configured, or the
/// fetch fails.
async fn try_upstream_fetch(
    repo: &OciRepoInfo,
    state: &SharedState,
    path_suffix: &str,
) -> Option<(Bytes, Option<String>)> {
    if repo.repo_type != RepositoryType::Remote {
        return None;
    }
    let upstream_url = repo.upstream_url.as_ref()?;
    let proxy = state.proxy_service.as_ref()?;
    let image = normalize_docker_image(&repo.image, upstream_url);
    let upstream_path = format!("v2/{}/{}", image, path_suffix);
    proxy_helpers::proxy_fetch(proxy, repo.id, &repo.key, upstream_url, &upstream_path)
        .await
        .ok()
}

/// Build an OCI registry response from proxied upstream content.
///
/// Used by both blob and manifest proxy handlers to avoid duplicating the
/// response-building logic across HEAD and GET variants.
fn build_oci_proxy_response(
    content: &Bytes,
    content_type: Option<String>,
    digest: &str,
    default_ct: &str,
    include_body: bool,
) -> Response {
    let ct = content_type.unwrap_or_else(|| default_ct.to_string());
    let body = if include_body {
        Body::from(content.clone())
    } else {
        Body::empty()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", digest)
        .header(CONTENT_LENGTH, content.len().to_string())
        .header(CONTENT_TYPE, ct)
        .body(body)
        .unwrap()
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenQuery {
    #[allow(dead_code)]
    service: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
    #[allow(dead_code)]
    account: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    access_token: String,
    expires_in: u64,
    issued_at: String,
}

async fn token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(_query): Query<TokenQuery>,
) -> Response {
    let credentials = match extract_basic_credentials(&headers) {
        Some(c) => c,
        None => {
            // Also try Bearer token (docker may send existing token)
            if let Ok(claims) = validate_token(&state.db, &state.config, &headers) {
                let auth_service =
                    AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
                let user = match sqlx::query_as!(
                    crate::models::user::User,
                    r#"SELECT id, username, email, password_hash, display_name,
                       auth_provider as "auth_provider: crate::models::user::AuthProvider",
                       external_id, is_admin, is_active, is_service_account, must_change_password,
                       totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                       failed_login_attempts, locked_until, last_failed_login_at,
                       password_changed_at, last_login_at, created_at, updated_at
                       FROM users WHERE id = $1"#,
                    claims.sub
                )
                .fetch_optional(&state.db)
                .await
                {
                    Ok(Some(u)) => u,
                    _ => {
                        return oci_error(
                            StatusCode::UNAUTHORIZED,
                            "UNAUTHORIZED",
                            "invalid credentials",
                        )
                    }
                };

                let tokens = match auth_service.generate_tokens(&user) {
                    Ok(t) => t,
                    Err(_) => {
                        return oci_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL_ERROR",
                            "token generation failed",
                        )
                    }
                };

                let resp = TokenResponse {
                    token: tokens.access_token.clone(),
                    access_token: tokens.access_token,
                    expires_in: tokens.expires_in,
                    issued_at: chrono::Utc::now().to_rfc3339(),
                };

                return Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&resp).unwrap()))
                    .unwrap();
            }

            // No credentials and no existing token. Issue an anonymous pull
            // token so that unauthenticated Docker clients can pull from public
            // repositories. The token carries no identity; read handlers check
            // repository visibility before granting access.
            let resp = TokenResponse {
                token: ANONYMOUS_TOKEN.to_string(),
                access_token: ANONYMOUS_TOKEN.to_string(),
                expires_in: 900,
                issued_at: chrono::Utc::now().to_rfc3339(),
            };
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&resp).unwrap()))
                .unwrap();
        }
    };

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (user, tokens, authenticated_via_api_token) = match auth_service
        .authenticate(&credentials.0, &credentials.1)
        .await
    {
        Ok((user, tokens)) => (user, tokens, false),
        Err(_) => {
            // Fall back to API token in the password field (for service accounts
            // and CI/CD pipelines that use `docker login -p <api-token>`)
            match auth_service.validate_api_token(&credentials.1).await {
                Ok(validation) => {
                    // TODO: Enforce token scopes and allowed_repo_ids for OCI
                    // token exchange. Currently the generated JWT inherits full
                    // user privileges regardless of token restrictions.
                    if !validation.scopes.is_empty()
                        && !validation.scopes.contains(&"*".to_string())
                    {
                        warn!(
                            user = %validation.user.username,
                            scopes = ?validation.scopes,
                            allowed_repo_ids = ?validation.allowed_repo_ids,
                            "API token has scope/repo restrictions that are not \
                             enforced during OCI token exchange"
                        );
                    }
                    let user = validation.user;
                    let tokens = match auth_service.generate_tokens(&user) {
                        Ok(t) => t,
                        Err(_) => {
                            return oci_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "INTERNAL_ERROR",
                                "failed to generate tokens",
                            )
                        }
                    };
                    (user, tokens, true)
                }
                Err(_) => {
                    return oci_error(
                        StatusCode::UNAUTHORIZED,
                        "UNAUTHORIZED",
                        "invalid username or password",
                    )
                }
            }
        }
    };

    // Block password-based OCI token requests when the user has TOTP 2FA
    // enabled. Docker CLI cannot perform a TOTP challenge, so the user
    // must create an API token (which bypasses TOTP) instead. API tokens
    // are the intended bypass mechanism for non-interactive flows, so skip
    // the TOTP guard when the user authenticated via one.
    if user.totp_enabled && !authenticated_via_api_token {
        return oci_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "TOTP 2FA is enabled on this account. \
             Create a personal access token and use it as your Docker password instead.",
        );
    }

    let resp = TokenResponse {
        token: tokens.access_token.clone(),
        access_token: tokens.access_token,
        expires_in: tokens.expires_in,
        issued_at: chrono::Utc::now().to_rfc3339(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Version check
// ---------------------------------------------------------------------------

fn version_check_ok() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

async fn version_check(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    // Accept Bearer token (standard Docker client flow)
    if validate_token(&state.db, &state.config, &headers).is_ok() {
        return version_check_ok();
    }

    // Accept Basic Auth directly (curl -u user:pass, HTTP clients)
    if let Some((username, password)) = extract_basic_credentials(&headers) {
        let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
        if auth_service
            .authenticate(&username, &password)
            .await
            .is_ok()
        {
            return version_check_ok();
        }

        // Fall back to API token in the password field
        if auth_service.validate_api_token(&password).await.is_ok() {
            return version_check_ok();
        }
    }

    let host = request_host(&headers);
    unauthorized_challenge(&host)
}

// ---------------------------------------------------------------------------
// Catch-all dispatcher: parses /v2/<name>/blobs|manifests/... paths
// ---------------------------------------------------------------------------

/// Parse a catch-all path into (image_name, operation, extra).
/// The path comes without the /v2 prefix since Axum strips it.
/// Examples:
///   "test/python/blobs/sha256:abc" → ("test/python", "blobs", "sha256:abc")
///   "test/python/manifests/latest" → ("test/python", "manifests", "latest")
///   "test/python/blobs/uploads/"   → ("test/python", "uploads", None)
///   "test/python/blobs/uploads/uuid" → ("test/python", "uploads", "uuid")
fn parse_oci_path(path: &str) -> Option<(String, String, Option<String>)> {
    let path = path.trim_start_matches('/');
    if let Some(name) = path.strip_suffix("/tags/list") {
        return Some((
            name.to_string(),
            "tags".to_string(),
            Some("list".to_string()),
        ));
    }

    let parts: Vec<&str> = path.split('/').collect();

    // Find terminal content operations in the remaining path.
    let op_idx = parts
        .iter()
        .position(|&p| p == "manifests" || p == "blobs")?;
    let name = parts[..op_idx].join("/");
    let operation = parts[op_idx];

    if operation == "blobs" && parts.get(op_idx + 1) == Some(&"uploads") {
        // Blob upload: either just "uploads/" or "uploads/<uuid>"
        let uuid = parts.get(op_idx + 2).map(|s| s.to_string());
        return Some((name, "uploads".to_string(), uuid));
    }

    let reference = parts.get(op_idx + 1).map(|s| s.to_string());
    Some((name, operation.to_string(), reference))
}

// ---------------------------------------------------------------------------
// Blob handlers
// ---------------------------------------------------------------------------

async fn handle_head_blob(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    digest: &str,
) -> Response {
    let host = request_host(headers);
    let scope = pull_scope(image_name);
    let is_anon = is_anonymous_token(headers);
    if !is_anon
        && authenticate_oci(&state.db, &state.config, headers)
            .await
            .is_err()
    {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Anonymous tokens may only access public repositories.
    if is_anon && !repo.is_public {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    // Check oci_blobs table
    let blob = sqlx::query!(
        "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        repo.id,
        digest
    )
    .fetch_optional(&state.db)
    .await;

    match blob {
        Ok(Some(b)) => {
            let storage = match state.storage_for_repo(&repo.location) {
                Ok(s) => s,
                Err(e) => {
                    return oci_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        &e.to_string(),
                    )
                }
            };
            if storage.exists(&b.storage_key).await.unwrap_or(false) {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("Docker-Content-Digest", digest)
                    .header(CONTENT_LENGTH, b.size_bytes.to_string())
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(Body::empty())
                    .unwrap();
            }
        }
        Ok(None) => {}
        Err(e) => {
            warn!("DB error checking blob: {}", e);
        }
    }

    // For remote repos, try fetching blob from upstream
    if let Some((content, ct)) =
        try_upstream_fetch(&repo, state, &format!("blobs/{}", digest)).await
    {
        return build_oci_proxy_response(&content, ct, digest, "application/octet-stream", false);
    }

    oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found")
}

async fn handle_get_blob(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    digest: &str,
) -> Response {
    let host = request_host(headers);
    let scope = pull_scope(image_name);
    let is_anon = is_anonymous_token(headers);
    if !is_anon
        && authenticate_oci(&state.db, &state.config, headers)
            .await
            .is_err()
    {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Anonymous tokens may only access public repositories.
    if is_anon && !repo.is_public {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    let blob = sqlx::query!(
        "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        repo.id,
        digest
    )
    .fetch_optional(&state.db)
    .await;

    match blob {
        Ok(Some(b)) => {
            let storage = match state.storage_for_repo(&repo.location) {
                Ok(s) => s,
                Err(e) => {
                    return oci_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        &e.to_string(),
                    )
                }
            };
            match storage.get(&b.storage_key).await {
                Ok(data) => {
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header("Docker-Content-Digest", digest)
                        .header(CONTENT_LENGTH, data.len().to_string())
                        .header(CONTENT_TYPE, "application/octet-stream")
                        .body(Body::from(data))
                        .unwrap();
                }
                Err(e) => {
                    warn!("Storage error reading blob {}: {}", digest, e);
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            warn!("DB error reading blob: {}", e);
        }
    }

    // For remote repos, try fetching blob from upstream
    if let Some((content, ct)) =
        try_upstream_fetch(&repo, state, &format!("blobs/{}", digest)).await
    {
        return build_oci_proxy_response(&content, ct, digest, "application/octet-stream", true);
    }

    oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found")
}

async fn handle_start_upload(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    query_digest: Option<&str>,
    body: Bytes,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let claims = match authenticate_oci(&state.db, &state.config, headers).await {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
    };

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let repo_id = repo.id;
    let location = repo.location;

    // Monolithic upload: if digest is provided and body is non-empty
    if let Some(digest) = query_digest {
        if !body.is_empty() {
            let computed = compute_sha256(&body);
            if computed != digest {
                return oci_error(
                    StatusCode::BAD_REQUEST,
                    "DIGEST_INVALID",
                    &format!(
                        "digest mismatch: computed {} != provided {}",
                        computed, digest
                    ),
                );
            }

            let storage = match state.storage_for_repo(&location) {
                Ok(s) => s,
                Err(e) => {
                    return oci_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        &e.to_string(),
                    )
                }
            };
            let key = blob_storage_key(digest);
            if let Err(e) = storage.put(&key, body.clone()).await {
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "BLOB_UPLOAD_UNKNOWN",
                    &e.to_string(),
                );
            }

            // Record in oci_blobs
            let _ = sqlx::query!(
                "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4) ON CONFLICT (repository_id, digest) DO NOTHING",
                repo_id, digest, body.len() as i64, key
            )
            .execute(&state.db)
            .await;

            return Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, format!("/v2/{}/blobs/{}", image_name, digest))
                .header("Docker-Content-Digest", digest)
                .header(CONTENT_LENGTH, "0")
                .body(Body::empty())
                .unwrap();
        }
    }

    // Create upload session
    let session_id = Uuid::new_v4();
    let temp_key = upload_storage_key(&session_id);

    // If body is non-empty, store it as initial chunk
    if !body.is_empty() {
        let storage = match state.storage_for_repo(&location) {
            Ok(s) => s,
            Err(e) => {
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    &e.to_string(),
                )
            }
        };
        if let Err(e) = storage.put(&temp_key, body.clone()).await {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "BLOB_UPLOAD_UNKNOWN",
                &e.to_string(),
            );
        }
    }

    let bytes_received = body.len() as i64;

    if let Err(e) = sqlx::query!(
        "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key) VALUES ($1, $2, $3, $4, $5)",
        session_id, repo_id, claims.sub, bytes_received, temp_key
    )
    .execute(&state.db)
    .await
    {
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
    }

    info!(
        "Started blob upload session {} for {}",
        session_id, image_name
    );

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(
            LOCATION,
            format!("/v2/{}/blobs/uploads/{}", image_name, session_id),
        )
        .header("Docker-Upload-UUID", session_id.to_string())
        .header("Range", format!("0-{}", bytes_received.max(0)))
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

async fn handle_patch_upload(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    uuid_str: &str,
    body: Bytes,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let claims = match authenticate_oci(&state.db, &state.config, headers).await {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
    };
    let _ = claims;

    let session_id: Uuid = match uuid_str.parse() {
        Ok(id) => id,
        Err(_) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "invalid upload UUID",
            )
        }
    };

    // Look up session
    let session = match sqlx::query!(
        "SELECT repository_id, bytes_received, storage_temp_key FROM oci_upload_sessions WHERE id = $1",
        session_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return oci_error(StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", "upload session not found"),
        Err(e) => return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string()),
    };

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let storage = match state.storage_for_repo(&repo.location) {
        Ok(s) => s,
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            )
        }
    };

    // Read existing data and append
    let mut existing = match storage.get(&session.storage_temp_key).await {
        Ok(data) => data.to_vec(),
        Err(_) => Vec::new(),
    };
    existing.extend_from_slice(&body);

    let new_bytes = existing.len() as i64;
    if let Err(e) = storage
        .put(&session.storage_temp_key, Bytes::from(existing))
        .await
    {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BLOB_UPLOAD_UNKNOWN",
            &e.to_string(),
        );
    }

    // Update session
    let _ = sqlx::query!(
        "UPDATE oci_upload_sessions SET bytes_received = $2, updated_at = NOW() WHERE id = $1",
        session_id,
        new_bytes
    )
    .execute(&state.db)
    .await;

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(
            LOCATION,
            format!("/v2/{}/blobs/uploads/{}", image_name, session_id),
        )
        .header("Docker-Upload-UUID", session_id.to_string())
        .header("Range", format!("0-{}", new_bytes))
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

async fn handle_complete_upload(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    uuid_str: &str,
    digest_query: Option<&str>,
    body: Bytes,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let claims = match authenticate_oci(&state.db, &state.config, headers).await {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
    };
    let _ = claims;

    let digest = match digest_query {
        Some(d) => d.to_string(),
        None => {
            return oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "digest query parameter required",
            )
        }
    };

    let session_id: Uuid = match uuid_str.parse() {
        Ok(id) => id,
        Err(_) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "invalid upload UUID",
            )
        }
    };

    let session = match sqlx::query!(
        "SELECT repository_id, storage_temp_key FROM oci_upload_sessions WHERE id = $1",
        session_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "upload session not found",
            )
        }
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            )
        }
    };

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let storage = match state.storage_for_repo(&repo.location) {
        Ok(s) => s,
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            )
        }
    };

    // Read accumulated data and append final chunk
    let mut data = match storage.get(&session.storage_temp_key).await {
        Ok(d) => d.to_vec(),
        Err(_) => Vec::new(),
    };
    if !body.is_empty() {
        data.extend_from_slice(&body);
    }

    // Verify digest
    let computed = compute_sha256(&data);
    if computed != digest {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!(
                "digest mismatch: computed {} != provided {}",
                computed, digest
            ),
        );
    }

    // Store blob permanently
    let blob_key = blob_storage_key(&digest);
    let size_bytes = data.len() as i64;
    if let Err(e) = storage.put(&blob_key, Bytes::from(data)).await {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BLOB_UPLOAD_UNKNOWN",
            &e.to_string(),
        );
    }

    // Record in oci_blobs
    let _ = sqlx::query!(
        "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4) ON CONFLICT (repository_id, digest) DO NOTHING",
        session.repository_id, digest, size_bytes, blob_key
    )
    .execute(&state.db)
    .await;

    // Cleanup: delete temp data and session
    let _ = storage.delete(&session.storage_temp_key).await;
    let _ = sqlx::query!("DELETE FROM oci_upload_sessions WHERE id = $1", session_id)
        .execute(&state.db)
        .await;

    info!(
        "Completed blob upload {}: {} ({} bytes)",
        session_id, digest, size_bytes
    );

    Response::builder()
        .status(StatusCode::CREATED)
        .header(LOCATION, format!("/v2/{}/blobs/{}", image_name, digest))
        .header("Docker-Content-Digest", &digest)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Manifest handlers
// ---------------------------------------------------------------------------

async fn handle_head_manifest(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    reference: &str,
) -> Response {
    let host = request_host(headers);
    let scope = pull_scope(image_name);
    let is_anon = is_anonymous_token(headers);
    if !is_anon
        && authenticate_oci(&state.db, &state.config, headers)
            .await
            .is_err()
    {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Anonymous tokens may only access public repositories.
    if is_anon && !repo.is_public {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    // Reference can be a tag or a digest. Look up locally first.
    let local_result: Option<(String, String)> = if is_digest_reference(reference) {
        sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
            repo.id, reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|t| (t.manifest_digest, t.manifest_content_type))
    } else {
        sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
            repo.id, repo.image, reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|t| (t.manifest_digest, t.manifest_content_type))
    };

    if let Some((manifest_digest, content_type)) = local_result {
        let storage = match state.storage_for_repo(&repo.location) {
            Ok(s) => s,
            Err(e) => {
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    &e.to_string(),
                )
            }
        };
        let manifest_key = manifest_storage_key(&manifest_digest);

        if let Ok(data) = storage.get(&manifest_key).await {
            return Response::builder()
                .status(StatusCode::OK)
                .header("Docker-Content-Digest", &manifest_digest)
                .header(CONTENT_LENGTH, data.len().to_string())
                .header(CONTENT_TYPE, &content_type)
                .body(Body::empty())
                .unwrap();
        }
    }

    // For remote repos, try fetching manifest from upstream
    if let Some((content, ct)) =
        try_upstream_fetch(&repo, state, &format!("manifests/{}", reference)).await
    {
        let digest = cache_manifest_or_compute_digest(
            state,
            &repo,
            image_name,
            reference,
            &content,
            ct.as_deref(),
        )
        .await;
        return build_oci_proxy_response(
            &content,
            ct,
            &digest,
            "application/vnd.oci.image.manifest.v1+json",
            false,
        );
    }

    oci_error(
        StatusCode::NOT_FOUND,
        "MANIFEST_UNKNOWN",
        "manifest not found",
    )
}

async fn handle_get_manifest(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    reference: &str,
) -> Response {
    let host = request_host(headers);
    let scope = pull_scope(image_name);
    let is_anon = is_anonymous_token(headers);
    if !is_anon
        && authenticate_oci(&state.db, &state.config, headers)
            .await
            .is_err()
    {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Anonymous tokens may only access public repositories.
    if is_anon && !repo.is_public {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    let local_result: Option<(String, String)> = if is_digest_reference(reference) {
        sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
            repo.id, reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|t| (t.manifest_digest, t.manifest_content_type))
    } else {
        sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
            repo.id, repo.image, reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|t| (t.manifest_digest, t.manifest_content_type))
    };

    if let Some((manifest_digest, content_type)) = local_result {
        let storage = match state.storage_for_repo(&repo.location) {
            Ok(s) => s,
            Err(e) => {
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    &e.to_string(),
                )
            }
        };
        let manifest_key = manifest_storage_key(&manifest_digest);

        if let Ok(data) = storage.get(&manifest_key).await {
            return Response::builder()
                .status(StatusCode::OK)
                .header("Docker-Content-Digest", &manifest_digest)
                .header(CONTENT_LENGTH, data.len().to_string())
                .header(CONTENT_TYPE, &content_type)
                .body(Body::from(data))
                .unwrap();
        }
    }

    // For remote repos, try fetching manifest from upstream
    if let Some((content, ct)) =
        try_upstream_fetch(&repo, state, &format!("manifests/{}", reference)).await
    {
        let digest = cache_manifest_or_compute_digest(
            state,
            &repo,
            image_name,
            reference,
            &content,
            ct.as_deref(),
        )
        .await;
        return build_oci_proxy_response(
            &content,
            ct,
            &digest,
            "application/vnd.oci.image.manifest.v1+json",
            true,
        );
    }

    oci_error(
        StatusCode::NOT_FOUND,
        "MANIFEST_UNKNOWN",
        "manifest not found",
    )
}

async fn handle_put_manifest(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    reference: &str,
    body: Bytes,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let claims = match authenticate_oci(&state.db, &state.config, headers).await {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
    };

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let repo_id = repo.id;
    let image = repo.image;

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();

    // Compute digest
    let digest = compute_sha256(&body);
    let manifest_key = manifest_storage_key(&digest);

    // Store manifest
    let storage = match state.storage_for_repo(&repo.location) {
        Ok(s) => s,
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            )
        }
    };
    if let Err(e) = storage.put(&manifest_key, body.clone()).await {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "MANIFEST_INVALID",
            &e.to_string(),
        );
    }

    // Upsert tag mapping
    if let Err(e) = sqlx::query!(
        r#"INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (repository_id, name, tag) DO UPDATE SET
             manifest_digest = EXCLUDED.manifest_digest,
             manifest_content_type = EXCLUDED.manifest_content_type,
             updated_at = NOW()"#,
        repo_id,
        image,
        reference,
        digest,
        content_type
    )
    .execute(&state.db)
    .await
    {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        );
    }

    // Calculate total image size from manifest (config + layers)
    let total_size: i64 =
        if let Ok(manifest_json) = serde_json::from_slice::<serde_json::Value>(&body) {
            let config_size = manifest_json
                .get("config")
                .and_then(|c| c.get("size"))
                .and_then(|s| s.as_i64())
                .unwrap_or(0);
            let layers_size: i64 = manifest_json
                .get("layers")
                .and_then(|l| l.as_array())
                .map(|layers| {
                    layers
                        .iter()
                        .filter_map(|l| l.get("size").and_then(|s| s.as_i64()))
                        .sum()
                })
                .unwrap_or(0);
            config_size + layers_size
        } else {
            body.len() as i64
        };

    // Also create an artifact record so it appears in the UI
    let artifact_path = format!("v2/{}/manifests/{}", image, reference);
    let artifact_name = format!("{}:{}", image, reference);
    let checksum = digest.strip_prefix("sha256:").unwrap_or(&digest);

    if let Err(e) = sqlx::query!(
        r#"INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (repository_id, path) DO UPDATE SET
             version = EXCLUDED.version,
             size_bytes = EXCLUDED.size_bytes,
             checksum_sha256 = EXCLUDED.checksum_sha256,
             content_type = EXCLUDED.content_type,
             storage_key = EXCLUDED.storage_key,
             uploaded_by = EXCLUDED.uploaded_by,
             is_deleted = false,
             updated_at = NOW()"#,
        repo_id,
        artifact_path,
        artifact_name,
        Some(reference),
        total_size,
        checksum,
        content_type,
        manifest_key,
        Some(claims.sub),
    )
    .execute(&state.db)
    .await
    {
        tracing::error!("Failed to upsert artifact record for {}: {}", artifact_path, e);
    }

    info!("Manifest pushed: {}:{} ({})", image_name, reference, digest);

    Response::builder()
        .status(StatusCode::CREATED)
        .header(LOCATION, format!("/v2/{}/manifests/{}", image_name, digest))
        .header("Docker-Content-Digest", &digest)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tags list handler
// ---------------------------------------------------------------------------

async fn handle_tags_list(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    query: &std::collections::HashMap<String, String>,
) -> Response {
    let host = request_host(headers);
    let scope = pull_scope(image_name);
    if authenticate_oci(&state.db, &state.config, headers)
        .await
        .is_err()
    {
        return unauthorized_challenge_with_scope(&host, Some(&scope));
    }

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let (n, last) = match parse_pagination_params(query) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // n=0: return empty list per spec
    if n == 0 {
        return build_tags_response(&repo.image, vec![]);
    }

    let (page, has_more) = match resolve_tags_page(state, &repo, n, last.as_deref()).await {
        Ok(page) => page,
        Err(e) => return e,
    };

    // OCI spec: return 404 NAME_UNKNOWN when the repository name is not
    // known to the registry. For local repos, if the first page is empty
    // and no cursor was provided, the image has never been pushed.
    if page.is_empty()
        && !has_more
        && last.is_none()
        && repo.repo_type != RepositoryType::Remote
        && !local_tags_exist(&state.db, repo.id, &repo.image)
            .await
            .unwrap_or(false)
    {
        return oci_error(
            StatusCode::NOT_FOUND,
            "NAME_UNKNOWN",
            &format!("repository name not known to registry: {}", image_name),
        );
    }

    build_tags_response_with_pagination(&repo.image, page, has_more, image_name, n)
}

async fn resolve_tags_page(
    state: &SharedState,
    repo: &OciRepoInfo,
    n: usize,
    last: Option<&str>,
) -> Result<(Vec<String>, bool), Response> {
    if repo.repo_type == RepositoryType::Remote {
        return resolve_remote_tags_page(state, repo, n, last).await;
    }

    if repo.repo_type == RepositoryType::Virtual {
        return resolve_virtual_tags_page(state, repo, n, last).await;
    }

    resolve_local_tags_page(state, repo, n, last).await
}

async fn resolve_remote_tags_page(
    state: &SharedState,
    repo: &OciRepoInfo,
    n: usize,
    last: Option<&str>,
) -> Result<(Vec<String>, bool), Response> {
    match tags_list_remote(state, repo, n, last).await {
        Ok(page) => Ok(page),
        Err(err) => {
            warn!(
                repo = %repo.key,
                image = %repo.image,
                status = %err.status(),
                "Upstream tags/list failed, falling back to cached tags"
            );
            let cached_page = tags_list_local(&state.db, repo.id, &repo.image, last, n).await?;
            let cache_populated = if cached_page.tags.is_empty() {
                local_tags_exist(&state.db, repo.id, &repo.image).await?
            } else {
                true
            };
            finalize_remote_tags_page(Err(err), cached_page, cache_populated)
        }
    }
}

/// Resolve a single page of tags for a virtual repository.
///
/// The cursor (`last`) is forwarded to each member query **and** applied again
/// on the merged result.  This double application is intentional: member repos
/// (especially remote upstreams) may sort tags differently than our canonical
/// `oci_lexical_cmp` order, so tags that the upstream considers "after" the
/// cursor may land "before" it in our ordering.  The second pass in
/// `apply_cursor_pagination` catches these strays and keeps pagination correct.
async fn resolve_virtual_tags_page(
    state: &SharedState,
    repo: &OciRepoInfo,
    n: usize,
    last: Option<&str>,
) -> Result<(Vec<String>, bool), Response> {
    let tags = tags_list_virtual(state, repo, n, last).await?;
    Ok(apply_cursor_pagination(tags, last, n))
}

async fn resolve_local_tags_page(
    state: &SharedState,
    repo: &OciRepoInfo,
    n: usize,
    last: Option<&str>,
) -> Result<(Vec<String>, bool), Response> {
    let page = tags_list_local(&state.db, repo.id, &repo.image, last, n).await?;
    Ok((page.tags, page.has_more))
}

/// Build a JSON response for tags/list with no pagination.
fn build_tags_response(image: &str, tags: Vec<String>) -> Response {
    let resp = TagsListResponse {
        name: image.to_string(),
        tags,
    };
    let json = serde_json::to_string(&resp).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, json.len().to_string())
        .body(Body::from(json))
        .unwrap()
}

/// Build a JSON response for tags/list with optional Link pagination header.
fn build_tags_response_with_pagination(
    image: &str,
    page: Vec<String>,
    has_more: bool,
    image_name: &str,
    n: usize,
) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json");

    if has_more {
        if let Some(last_tag) = page.last() {
            let path = format!("/v2/{}/tags/list", image_name);
            let link = build_pagination_link_header(&path, last_tag, n);
            builder = builder.header("Link", link);
        }
    }

    let resp = TagsListResponse {
        name: image.to_string(),
        tags: page,
    };
    let json = serde_json::to_string(&resp).unwrap_or_default();
    builder
        .header(CONTENT_LENGTH, json.len().to_string())
        .body(Body::from(json))
        .unwrap()
}

/// Build the upstream `tags/list` path for direct remote repositories.
///
/// Requests one extra tag so this server can determine whether it should emit
/// its own `Link` header while still returning at most `n` tags to the client.
fn build_remote_tags_list_path(n: usize, last: Option<&str>) -> String {
    let mut path = format!("tags/list?n={}", n.saturating_add(1));
    if let Some(last) = last {
        path.push_str("&last=");
        path.push_str(&urlencoding::encode(last));
    }
    path
}

/// Extract the upstream `last` cursor from an OCI pagination `Link` header.
fn parse_upstream_pagination_last(link: &str) -> Option<String> {
    let selected = link
        .split(',')
        .map(str::trim)
        .find(|segment| segment.contains("rel=\"next\""))?;

    let target = selected
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(uri, _)| uri)?;
    let query = target.split_once('?')?.1;

    serde_urlencoded::from_str::<Vec<(String, String)>>(query)
        .ok()?
        .into_iter()
        .find_map(|(key, value)| (key == "last").then_some(value))
}

/// Trim the extra upstream tag used to detect whether another page exists.
fn split_remote_tags_page(
    mut tags: Vec<String>,
    n: usize,
    upstream_has_more: bool,
) -> (Vec<String>, bool) {
    let has_more = upstream_has_more || tags.len() > n;
    if has_more {
        tags.truncate(n);
    }
    (tags, has_more)
}

#[allow(clippy::result_large_err)] // Response-as-error is used throughout this module
fn finalize_remote_tags_page(
    upstream: Result<(Vec<String>, bool), Response>,
    cached_page: LocalTagsPage,
    cache_populated: bool,
) -> Result<(Vec<String>, bool), Response> {
    match upstream {
        Ok(page) => Ok(page),
        Err(err) => {
            if !cache_populated {
                Err(err)
            } else {
                Ok((cached_page.tags, cached_page.has_more))
            }
        }
    }
}

fn missing_upload_uuid_response() -> Response {
    oci_error(
        StatusCode::NOT_FOUND,
        "BLOB_UPLOAD_UNKNOWN",
        "upload UUID required",
    )
}

/// Build a SQL query for local tags, excluding digest references (which
/// contain a ':' character, e.g. "sha256:abc…") so only human-readable tags
/// are returned. This uses `POSITION(':' IN tag) = 0` as a fast SQL-side
/// filter; the more precise `is_digest_reference()` is used on the Rust side
/// when validating individual references.
fn local_tags_query(has_cursor: bool) -> &'static str {
    if has_cursor {
        r#"SELECT tag
           FROM (
               SELECT DISTINCT tag
               FROM oci_tags
               WHERE repository_id = $1
                 AND name = $2
                 AND POSITION(':' IN tag) = 0
                 AND (LOWER(tag), tag) > (LOWER($3), $3)
           ) local_tags
           ORDER BY LOWER(tag), tag
           LIMIT $4"#
    } else {
        r#"SELECT tag
           FROM (
               SELECT DISTINCT tag
               FROM oci_tags
               WHERE repository_id = $1
                 AND name = $2
                 AND POSITION(':' IN tag) = 0
           ) local_tags
           ORDER BY LOWER(tag), tag
           LIMIT $3"#
    }
}

struct LocalTagsPage {
    tags: Vec<String>,
    has_more: bool,
}

async fn local_tags_exist(db: &PgPool, repo_id: Uuid, image_name: &str) -> Result<bool, Response> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
               SELECT 1
               FROM oci_tags
               WHERE repository_id = $1
                 AND name = $2
                 AND POSITION(':' IN tag) = 0
           )"#,
    )
    .bind(repo_id)
    .bind(image_name)
    .fetch_one(db)
    .await
    .map_err(|e| {
        warn!("Failed to check cached tags for {}: {}", image_name, e);
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "failed to list tags",
        )
    })
}

async fn tags_list_local(
    db: &PgPool,
    repo_id: Uuid,
    image_name: &str,
    last: Option<&str>,
    n: usize,
) -> Result<LocalTagsPage, Response> {
    let limit = (n.saturating_add(1)) as i64;
    let rows = if let Some(last) = last {
        sqlx::query_scalar::<_, String>(local_tags_query(true))
            .bind(repo_id)
            .bind(image_name)
            .bind(last)
            .bind(limit)
            .fetch_all(db)
            .await
    } else {
        sqlx::query_scalar::<_, String>(local_tags_query(false))
            .bind(repo_id)
            .bind(image_name)
            .bind(limit)
            .fetch_all(db)
            .await
    };

    rows.map(|tags| {
        let (tags, has_more) = split_remote_tags_page(tags, n, false);
        LocalTagsPage { tags, has_more }
    })
    .map_err(|e| {
        warn!("Failed to list tags for {}: {}", image_name, e);
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "failed to list tags",
        )
    })
}

struct UpstreamTagsPage {
    tags: Vec<String>,
    next_last: Option<String>,
}

async fn fetch_upstream_tags_page(
    state: &SharedState,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    image: &str,
    n: usize,
    last: Option<&str>,
) -> Result<UpstreamTagsPage, Response> {
    let proxy = state.proxy_service.as_ref().ok_or_else(|| {
        oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "proxy service unavailable",
        )
    })?;

    let upstream_path = format!("v2/{}/{}", image, build_remote_tags_list_path(n, last));
    let (content, _ct, link) = proxy_helpers::proxy_fetch_uncached_with_link(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
    )
    .await
    .map_err(|resp| match resp.status() {
        StatusCode::NOT_FOUND => oci_error(
            StatusCode::NOT_FOUND,
            "NAME_UNKNOWN",
            "repository not found upstream",
        ),
        _ => oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "failed to fetch tags from upstream",
        ),
    })?;

    let parsed = serde_json::from_slice::<serde_json::Value>(&content).map_err(|e| {
        warn!("Invalid upstream tags/list response for {}: {}", image, e);
        oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "invalid upstream tags response",
        )
    })?;
    let tags = parsed["tags"].as_array().ok_or_else(|| {
        warn!(
            "Upstream tags/list response for {} is missing a tags array",
            image
        );
        oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "invalid upstream tags response",
        )
    })?;

    Ok(UpstreamTagsPage {
        tags: tags
            .iter()
            .filter_map(|t| t.as_str().map(String::from))
            .collect(),
        next_last: link.as_deref().and_then(parse_upstream_pagination_last),
    })
}

async fn collect_upstream_tags(
    state: &SharedState,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    image: &str,
    max_tags: usize,
    last: Option<&str>,
) -> Result<(Vec<String>, bool), Response> {
    if max_tags == 0 {
        return Ok((vec![], false));
    }

    let mut collected = Vec::new();
    let mut cursor = last.map(String::from);
    let mut pages_fetched = 0usize;

    loop {
        let remaining = max_tags.saturating_sub(collected.len());
        if remaining == 0 {
            return Ok((collected, false));
        }

        let page = fetch_upstream_tags_page(
            state,
            repo_id,
            repo_key,
            upstream_url,
            image,
            remaining,
            cursor.as_deref(),
        )
        .await?;
        pages_fetched += 1;

        if pages_fetched > 1024 {
            warn!(
                "Stopping upstream tags pagination for {} after {} pages to avoid a loop",
                image, pages_fetched
            );
            return Ok((collected, true));
        }

        let had_extra_item = page.tags.len() > remaining;
        if had_extra_item {
            collected.extend(page.tags.into_iter().take(remaining));
            return Ok((collected, true));
        }

        let before_len = collected.len();
        collected.extend(page.tags);

        match page.next_last {
            Some(next_last) if collected.len() < max_tags => {
                if collected.len() == before_len || cursor.as_deref() == Some(next_last.as_str()) {
                    warn!(
                        "Upstream tags pagination for {} returned a non-advancing cursor, stopping early",
                        image
                    );
                    return Ok((collected, true));
                }
                cursor = Some(next_last);
            }
            Some(_) => return Ok((collected, true)),
            None => return Ok((collected, false)),
        }
    }
}

/// Fetch all tags from the upstream registry for a remote repo.
/// Returns a single page and whether another page exists so the caller can
/// emit artifact-keeper `Link` headers instead of upstream ones.
async fn tags_list_remote(
    state: &SharedState,
    repo: &OciRepoInfo,
    n: usize,
    last: Option<&str>,
) -> Result<(Vec<String>, bool), Response> {
    let upstream_url = repo.upstream_url.as_deref().ok_or_else(|| {
        oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "remote repository has no upstream configured",
        )
    })?;
    let image = normalize_docker_image(&repo.image, upstream_url);
    let (tags, upstream_has_more) =
        collect_upstream_tags(state, repo.id, &repo.key, upstream_url, &image, n + 1, last).await?;
    Ok(split_remote_tags_page(tags, n, upstream_has_more))
}

/// Aggregate tags from all virtual repo members.
///
/// Forward the merged cursor to every member because any tag at or before the
/// merged cursor cannot appear on the next merged page.
async fn tags_list_virtual(
    state: &SharedState,
    repo: &OciRepoInfo,
    n_limit: usize,
    last: Option<&str>,
) -> Result<Vec<String>, Response> {
    let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
    let member_limit = n_limit.saturating_add(1);
    let member_cursor = last;
    let image = repo.image.clone();

    let handles: Vec<_> = members
        .iter()
        .map(|member| {
            let image = image.clone();
            let member_id = member.id;
            let member_key = member.key.clone();
            let repo_type = member.repo_type.clone();
            let upstream_url = member.upstream_url.clone();
            async move {
                if repo_type == RepositoryType::Remote {
                    fetch_tags_from_remote_member(
                        state,
                        member_id,
                        &member_key,
                        upstream_url.as_deref(),
                        &image,
                        member_limit,
                        member_cursor,
                    )
                    .await
                } else {
                    tags_list_local(&state.db, member_id, &image, member_cursor, member_limit)
                        .await
                        .ok()
                        .map(|page| page.tags)
                }
            }
        })
        .collect();

    let tag_sets: Vec<Vec<String>> = futures::future::join_all(handles)
        .await
        .into_iter()
        .flatten()
        .collect();

    Ok(merge_and_dedup_tags(tag_sets))
}

/// Fetch tags from a single remote virtual member via upstream proxy.
async fn fetch_tags_from_remote_member(
    state: &SharedState,
    member_id: Uuid,
    member_key: &str,
    upstream_url: Option<&str>,
    image_name: &str,
    n_limit: usize,
    last: Option<&str>,
) -> Option<Vec<String>> {
    let upstream_url = upstream_url?;
    let image = normalize_docker_image(image_name, upstream_url);
    let (tags, upstream_has_more) = collect_upstream_tags(
        state,
        member_id,
        member_key,
        upstream_url,
        &image,
        n_limit,
        last,
    )
    .await
    .map_err(|_| {
        tracing::debug!(
            "Virtual member '{}': upstream tags/list failed, skipping",
            member_key
        );
    })
    .ok()?;

    tracing::debug!(
        "Virtual member '{}': fetched {} tags from upstream (has_more={})",
        member_key,
        tags.len(),
        upstream_has_more
    );
    Some(tags)
}

// ---------------------------------------------------------------------------
// Catalog handler
// ---------------------------------------------------------------------------

/// List all repositories visible to the authenticated user.
///
/// Note: `_catalog` is defined by the Docker Registry HTTP API V2
/// (distribution/distribution), **not** the OCI Distribution Spec.
/// Per the Docker spec, the catalog contents are implementation-specific:
/// registries MAY limit results based on access level. This implementation
/// returns all repositories to any authenticated user without per-repository
/// ACL filtering, consistent with Docker Hub and most registry implementations.
async fn handle_catalog(
    State(state): State<SharedState>,
    headers: HeaderMap,
    query: Query<std::collections::HashMap<String, String>>,
) -> Response {
    let host = request_host(&headers);
    if authenticate_oci(&state.db, &state.config, &headers)
        .await
        .is_err()
    {
        return unauthorized_challenge(&host);
    }

    let (n, last) = match parse_pagination_params(&query) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if n == 0 {
        let resp = CatalogResponse {
            repositories: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap_or_default();
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, json.len().to_string())
            .body(Body::from(json))
            .unwrap();
    }

    // `_catalog` is defined by the Docker Registry HTTP API V2 and is scoped
    // to repositories available in the local registry cluster. It must not
    // advertise what may exist only upstream.
    // Spec reference:
    // https://github.com/distribution/distribution/blob/v3.0.0/docs/content/spec/api.md#catalog
    let (page, has_more) = match catalog_local_entries(&state.db, last.as_deref(), n).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json");

    if has_more {
        if let Some(last_repo) = page.last() {
            let link = build_pagination_link_header("/v2/_catalog", last_repo, n);
            builder = builder.header("Link", link);
        }
    }

    let resp = CatalogResponse { repositories: page };
    let json = serde_json::to_string(&resp).unwrap_or_default();
    builder
        .header(CONTENT_LENGTH, json.len().to_string())
        .body(Body::from(json))
        .unwrap()
}

/// Fetch a single page of catalog entries from oci_tags using SQL-side
/// cursor pagination. Returns `(page, has_more)`.
///
/// Sorting uses `LOWER()` for case-insensitive primary order (matching
/// `oci_lexical_cmp`) with a case-sensitive tiebreaker. The cursor
/// comparison mirrors this ordering so pagination is consistent.
async fn catalog_local_entries(
    db: &PgPool,
    last: Option<&str>,
    n: usize,
) -> Result<(Vec<String>, bool), Response> {
    let limit = (n as i64).saturating_add(1);

    let rows: Vec<(String,)> = if let Some(cursor) = last {
        sqlx::query_as(
            "SELECT name FROM ( \
                 SELECT DISTINCT \
                     CASE WHEN t.name = r.key OR t.name = '' \
                          THEN r.key \
                          ELSE r.key || '/' || t.name \
                     END AS name \
                 FROM oci_tags t \
                 JOIN repositories r ON r.id = t.repository_id \
             ) catalog \
             WHERE (LOWER(name), name) > (LOWER($1), $1) \
             ORDER BY LOWER(name), name \
             LIMIT $2",
        )
        .bind(cursor)
        .bind(limit)
        .fetch_all(db)
        .await
    } else {
        sqlx::query_as(
            "SELECT name FROM ( \
                 SELECT DISTINCT \
                     CASE WHEN t.name = r.key OR t.name = '' \
                          THEN r.key \
                          ELSE r.key || '/' || t.name \
                     END AS name \
                 FROM oci_tags t \
                 JOIN repositories r ON r.id = t.repository_id \
             ) catalog \
             ORDER BY LOWER(name), name \
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(db)
        .await
    }
    .map_err(|e| {
        warn!("Failed to query local catalog entries: {}", e);
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "failed to list catalog",
        )
    })?;

    let mut entries: Vec<String> = rows.into_iter().map(|(name,)| name).collect();
    let has_more = entries.len() > n;
    if has_more {
        entries.truncate(n);
    }
    Ok((entries, has_more))
}

async fn handle_delete_manifest(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    reference: &str,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let claims = match authenticate_oci(&state.db, &state.config, headers).await {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
    };
    let _ = claims;

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Resolve the manifest digest. The reference may be a tag name or a digest.
    let manifest_digest: Option<String> = if reference.starts_with("sha256:") {
        // Verify the digest actually exists in our tag table
        sqlx::query_scalar!(
            "SELECT manifest_digest FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
            repo.id,
            reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
    } else {
        sqlx::query_scalar!(
            "SELECT manifest_digest FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
            repo.id,
            repo.image,
            reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
    };

    let digest = match manifest_digest {
        Some(d) => d,
        None => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "MANIFEST_UNKNOWN",
                "manifest not found",
            )
        }
    };

    // Delete all tag rows pointing to this digest within the repository
    if let Err(e) = sqlx::query!(
        "DELETE FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2",
        repo.id,
        digest
    )
    .execute(&state.db)
    .await
    {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        );
    }

    // Soft-delete the corresponding artifact record
    let artifact_path = format!("v2/{}/manifests/{}", repo.image, reference);
    let _ = sqlx::query!(
        "UPDATE artifacts SET is_deleted = true, updated_at = NOW() WHERE repository_id = $1 AND path = $2",
        repo.id,
        artifact_path
    )
    .execute(&state.db)
    .await;

    info!(
        "Manifest deleted: {}:{} (digest {})",
        image_name, reference, digest
    );

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Catch-all handlers
// ---------------------------------------------------------------------------

async fn catch_all(
    State(state): State<SharedState>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    query: Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Response {
    // Extract path from URI — the nest strips /v2 prefix already
    let path = uri.path().to_string();
    let parsed = match parse_oci_path(&path) {
        Some(p) => p,
        None => return oci_error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "invalid path"),
    };

    let (image_name, operation, reference) = parsed;

    // Helper to require a reference, reducing repeated match arms
    macro_rules! require_ref {
        ($ref:expr, $code:expr, $msg:expr) => {
            match $ref {
                Some(r) => r,
                None => return oci_error(StatusCode::BAD_REQUEST, $code, $msg),
            }
        };
    }

    match (method.as_str(), operation.as_str()) {
        ("HEAD", "blobs") => {
            let d = require_ref!(reference, "DIGEST_INVALID", "digest required");
            handle_head_blob(&state, &headers, &image_name, &d).await
        }
        ("GET", "blobs") => {
            let d = require_ref!(reference, "DIGEST_INVALID", "digest required");
            handle_get_blob(&state, &headers, &image_name, &d).await
        }
        ("POST", "uploads") => {
            let digest = query.get("digest").map(|s| s.as_str());
            handle_start_upload(&state, &headers, &image_name, digest, body).await
        }
        ("PATCH", "uploads") => {
            let Some(u) = reference else {
                return missing_upload_uuid_response();
            };
            handle_patch_upload(&state, &headers, &image_name, &u, body).await
        }
        ("PUT", "uploads") => {
            let Some(u) = reference else {
                return missing_upload_uuid_response();
            };
            let digest = query.get("digest").map(|s| s.as_str());
            handle_complete_upload(&state, &headers, &image_name, &u, digest, body).await
        }
        ("HEAD", "manifests") => {
            let r = require_ref!(reference, "NAME_INVALID", "reference required");
            handle_head_manifest(&state, &headers, &image_name, &r).await
        }
        ("GET", "manifests") => {
            let r = require_ref!(reference, "NAME_INVALID", "reference required");
            handle_get_manifest(&state, &headers, &image_name, &r).await
        }
        ("PUT", "manifests") => {
            let r = require_ref!(reference, "NAME_INVALID", "reference required");
            handle_put_manifest(&state, &headers, &image_name, &r, body).await
        }
        ("DELETE", "manifests") => {
            let r = require_ref!(reference, "NAME_INVALID", "reference required");
            handle_delete_manifest(&state, &headers, &image_name, &r).await
        }
        ("GET", "tags") => handle_tags_list(&state, &headers, &image_name, &query).await,
        _ => oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            &format!("method {} not supported for {}", method, operation),
        ),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(version_check))
        .route("/token", get(token).post(token))
        .route("/_catalog", get(handle_catalog))
        .fallback(catch_all)
        .layer(DefaultBodyLimit::disable())
}

/// Standalone version check handler for /v2/ (trailing slash).
/// Axum nest("/v2") + route("/") only matches /v2, not /v2/.
/// We add a top-level route for /v2/ to handle Docker's canonical check.
pub fn version_check_handler() -> axum::routing::MethodRouter<SharedState> {
    get(version_check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // oci_error
    // -----------------------------------------------------------------------

    #[test]
    fn test_oci_error_status() {
        let resp = oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_oci_error_bad_request() {
        let resp = oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "bad digest");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_oci_error_internal() {
        let resp = oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "oops");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // build_oci_proxy_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_oci_proxy_response_head() {
        let content = Bytes::from("hello");
        let resp = build_oci_proxy_response(
            &content,
            None,
            "sha256:abc",
            "application/octet-stream",
            false,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Docker-Content-Digest").unwrap(),
            "sha256:abc"
        );
        assert_eq!(resp.headers().get(CONTENT_LENGTH).unwrap(), "5");
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_build_oci_proxy_response_get_with_custom_ct() {
        let content = Bytes::from("{\"schemaVersion\":2}");
        let resp = build_oci_proxy_response(
            &content,
            Some("application/vnd.docker.distribution.manifest.v2+json".to_string()),
            "sha256:def",
            "application/vnd.oci.image.manifest.v1+json",
            true,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/vnd.docker.distribution.manifest.v2+json"
        );
        assert_eq!(
            resp.headers().get(CONTENT_LENGTH).unwrap(),
            content.len().to_string().as_str()
        );
    }

    #[test]
    fn test_build_oci_proxy_response_uses_default_ct_when_none() {
        let content = Bytes::from("data");
        let resp = build_oci_proxy_response(
            &content,
            None,
            "sha256:000",
            "application/vnd.oci.image.manifest.v1+json",
            true,
        );
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/vnd.oci.image.manifest.v1+json"
        );
    }

    // -----------------------------------------------------------------------
    // OciErrorResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_oci_error_response_serialization() {
        let resp = OciErrorResponse {
            errors: vec![OciErrorEntry {
                code: "BLOB_UNKNOWN".to_string(),
                message: "blob not found".to_string(),
                detail: None,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"code\":\"BLOB_UNKNOWN\""));
        assert!(json.contains("\"message\":\"blob not found\""));
        // detail should not be present when None
        assert!(!json.contains("\"detail\""));
    }

    #[test]
    fn test_oci_error_response_with_detail() {
        let resp = OciErrorResponse {
            errors: vec![OciErrorEntry {
                code: "MANIFEST_INVALID".to_string(),
                message: "invalid manifest".to_string(),
                detail: Some(serde_json::json!({"reason": "bad json"})),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"detail\""));
        assert!(json.contains("bad json"));
    }

    // -----------------------------------------------------------------------
    // www_authenticate_header
    // -----------------------------------------------------------------------

    #[test]
    fn test_www_authenticate_header_with_scheme() {
        let header = www_authenticate_header("http://localhost:8080", None);
        assert!(header.contains("realm=\"http://localhost:8080/v2/token\""));
        assert!(header.contains("service=\"artifact-keeper\""));
    }

    #[test]
    fn test_www_authenticate_header_https() {
        let header = www_authenticate_header("https://registry.example.com", None);
        assert!(header.contains("https://registry.example.com/v2/token"));
    }

    #[test]
    fn test_www_authenticate_header_with_scope() {
        let header = www_authenticate_header(
            "https://registry.example.com",
            Some("repository:myrepo/myimage:pull"),
        );
        assert!(header.contains("realm=\"https://registry.example.com/v2/token\""));
        assert!(header.contains("service=\"artifact-keeper\""));
        assert!(header.contains("scope=\"repository:myrepo/myimage:pull\""));
    }

    #[test]
    fn test_www_authenticate_header_with_push_scope() {
        let header = www_authenticate_header(
            "https://registry.example.com",
            Some("repository:myrepo/myimage:pull,push"),
        );
        assert!(header.contains("scope=\"repository:myrepo/myimage:pull,push\""));
    }

    #[test]
    fn test_www_authenticate_header_no_scope_omits_scope_field() {
        let header = www_authenticate_header("https://registry.example.com", None);
        assert!(!header.contains("scope="));
    }

    // -----------------------------------------------------------------------
    // unauthorized_challenge
    // -----------------------------------------------------------------------

    #[test]
    fn test_unauthorized_challenge_status() {
        let resp = unauthorized_challenge("http://localhost");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_unauthorized_challenge_has_www_authenticate_header() {
        let resp = unauthorized_challenge("http://localhost");
        assert!(resp.headers().get("WWW-Authenticate").is_some());
    }

    #[test]
    fn test_unauthorized_challenge_with_scope_includes_scope() {
        let resp = unauthorized_challenge_with_scope(
            "https://registry.example.com",
            Some("repository:docker/openjdk:pull"),
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let header = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(header.contains("scope=\"repository:docker/openjdk:pull\""));
    }

    #[test]
    fn test_unauthorized_challenge_with_scope_none_omits_scope() {
        let resp = unauthorized_challenge_with_scope("https://registry.example.com", None);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let header = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!header.contains("scope="));
    }

    // -----------------------------------------------------------------------
    // pull_scope / push_scope
    // -----------------------------------------------------------------------

    #[test]
    fn test_pull_scope() {
        assert_eq!(
            pull_scope("docker/openjdk"),
            "repository:docker/openjdk:pull"
        );
    }

    #[test]
    fn test_push_scope() {
        assert_eq!(
            push_scope("docker/openjdk"),
            "repository:docker/openjdk:pull,push"
        );
    }

    #[test]
    fn test_pull_scope_nested_name() {
        assert_eq!(
            pull_scope("myrepo/org/image"),
            "repository:myrepo/org/image:pull"
        );
    }

    // -----------------------------------------------------------------------
    // extract_bearer_token
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer my-token-123"),
        );
        assert_eq!(
            extract_bearer_token(&headers),
            Some("my-token-123".to_string())
        );
    }

    #[test]
    fn test_extract_bearer_token_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("bearer my-token"));
        assert_eq!(extract_bearer_token(&headers), Some("my-token".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());
    }

    #[test]
    fn test_extract_bearer_token_basic_auth_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert!(extract_bearer_token(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_basic_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic !!!invalid"));
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_no_colon() {
        let mut headers = HeaderMap::new();
        // "useronly" in base64 = "dXNlcm9ubHk="
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcm9ubHk="),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_password_with_colon() {
        let mut headers = HeaderMap::new();
        // "user:pa:ss" in base64 = "dXNlcjpwYTpzcw=="
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYTpzcw=="),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pa:ss".to_string())));
    }

    // -----------------------------------------------------------------------
    // request_host
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_host_with_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        assert_eq!(request_host(&headers), "http://registry.example.com");
    }

    #[test]
    fn test_request_host_with_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_static("https://registry.example.com"),
        );
        assert_eq!(request_host(&headers), "https://registry.example.com");
    }

    #[test]
    fn test_request_host_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(request_host(&headers), "http://localhost");
    }

    #[test]
    fn test_request_host_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:8080"));
        assert_eq!(request_host(&headers), "http://localhost:8080");
    }

    #[test]
    fn test_request_host_uses_x_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(request_host(&headers), "https://registry.example.com");
    }

    #[test]
    fn test_request_host_uses_x_forwarded_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example.com:30443"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(request_host(&headers), "https://registry.example.com:30443");
    }

    #[test]
    fn test_request_host_forwarded_host_without_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example.com"),
        );
        assert_eq!(request_host(&headers), "http://registry.example.com");
    }

    // -----------------------------------------------------------------------
    // Storage key helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_blob_storage_key() {
        assert_eq!(blob_storage_key("sha256:abc123"), "oci-blobs/sha256:abc123");
    }

    #[test]
    fn test_manifest_storage_key() {
        assert_eq!(
            manifest_storage_key("sha256:def456"),
            "oci-manifests/sha256:def456"
        );
    }

    #[test]
    fn test_upload_storage_key() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            upload_storage_key(&uuid),
            "oci-uploads/550e8400-e29b-41d4-a716-446655440000"
        );
    }

    // -----------------------------------------------------------------------
    // compute_sha256
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_sha256_empty() {
        let hash = compute_sha256(b"");
        assert!(hash.starts_with("sha256:"));
        // SHA256 of empty string is a well-known value
        assert_eq!(
            hash,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_sha256_hello_world() {
        let hash = compute_sha256(b"hello world");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(
            hash,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_sha256_deterministic() {
        let h1 = compute_sha256(b"test data");
        let h2 = compute_sha256(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_sha256_different_data() {
        let h1 = compute_sha256(b"data1");
        let h2 = compute_sha256(b"data2");
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // parse_oci_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_oci_path_blobs() {
        let result = parse_oci_path("/test/python/blobs/sha256:abc");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "blobs");
        assert_eq!(reference, Some("sha256:abc".to_string()));
    }

    #[test]
    fn test_parse_oci_path_manifests() {
        let result = parse_oci_path("/test/python/manifests/latest");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("latest".to_string()));
    }

    #[test]
    fn test_parse_oci_path_uploads_no_uuid() {
        let result = parse_oci_path("/test/python/blobs/uploads/");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "uploads");
        // Empty string from splitting trailing slash
        assert_eq!(reference, Some("".to_string()));
    }

    #[test]
    fn test_parse_oci_path_uploads_with_uuid() {
        let result = parse_oci_path("/test/python/blobs/uploads/some-uuid");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "uploads");
        assert_eq!(reference, Some("some-uuid".to_string()));
    }

    #[test]
    fn test_parse_oci_path_no_leading_slash() {
        let result = parse_oci_path("test/python/manifests/v1.0");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("v1.0".to_string()));
    }

    #[test]
    fn test_parse_oci_path_deep_name() {
        let result = parse_oci_path("myrepo/org/image/manifests/latest");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "myrepo/org/image");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("latest".to_string()));
    }

    #[test]
    fn test_parse_oci_path_no_operation() {
        let result = parse_oci_path("just/a/name");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_oci_path_tags_operation() {
        let result = parse_oci_path("test/image/tags/list");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/image");
        assert_eq!(op, "tags");
        assert_eq!(reference, Some("list".to_string()));
    }

    #[test]
    fn test_parse_oci_path_allows_tags_in_repository_name() {
        let result = parse_oci_path("acme/tags/api/manifests/latest");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "acme/tags/api");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("latest".to_string()));
    }

    #[test]
    fn test_parse_oci_path_allows_repo_key_named_tags() {
        let result = parse_oci_path("tags/myimage/manifests/latest");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "tags/myimage");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("latest".to_string()));
    }

    #[test]
    fn test_parse_oci_path_blobs_no_digest() {
        let result = parse_oci_path("test/image/blobs");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/image");
        assert_eq!(op, "blobs");
        assert!(reference.is_none());
    }

    #[test]
    fn test_parse_oci_path_manifests_sha256_reference() {
        let result = parse_oci_path("test/image/manifests/sha256:abc123");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/image");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("sha256:abc123".to_string()));
    }

    #[test]
    fn test_is_digest_reference_accepts_sha256_reference() {
        assert!(is_digest_reference(
            "sha256:4d3f1c5bcf9f2f7e4a3e2d1c0b9a887766554433221100ffeeddccbbaa998877"
        ));
    }

    #[test]
    fn test_is_digest_reference_accepts_non_hex_encoded() {
        // OCI spec allows [a-zA-Z0-9=_-]+ in the encoded part
        assert!(is_digest_reference(
            "multihash+base58:QmRZxt2b1FVZPNqd8hsiykDL3TdBDeTSPX9Kv46HmX4Kgd"
        ));
    }

    #[test]
    fn test_is_digest_reference_rejects_tag_name() {
        assert!(!is_digest_reference("latest"));
    }

    #[test]
    fn test_is_digest_reference_rejects_tag_with_dot() {
        assert!(!is_digest_reference("v1.0.0"));
    }

    #[test]
    fn test_cached_manifest_reference_key_uses_digest_for_remote_tags() {
        assert_eq!(
            cached_manifest_reference_key("remote", "latest", "sha256:abc"),
            "sha256:abc"
        );
    }

    #[test]
    fn test_cached_manifest_reference_key_preserves_remote_digest_reference() {
        assert_eq!(
            cached_manifest_reference_key("remote", "sha256:def", "sha256:def"),
            "sha256:def"
        );
    }

    #[test]
    fn test_cached_manifest_reference_key_preserves_local_tags() {
        assert_eq!(
            cached_manifest_reference_key("local", "latest", "sha256:abc"),
            "latest"
        );
    }

    #[test]
    fn test_build_remote_tags_list_path_without_cursor() {
        let path = build_remote_tags_list_path(100, None);
        assert_eq!(path, "tags/list?n=101");
    }

    #[test]
    fn test_build_remote_tags_list_path_forwards_cursor() {
        let path = build_remote_tags_list_path(50, Some("release+candidate"));
        assert_eq!(path, "tags/list?n=51&last=release%2Bcandidate");
    }

    #[test]
    fn test_local_tags_query_without_cursor_filters_digests_and_limits_in_sql() {
        let query = local_tags_query(false);
        assert!(query.contains("POSITION(':' IN tag) = 0"));
        assert!(query.contains("ORDER BY LOWER(tag), tag"));
        assert!(query.contains("LIMIT $3"));
    }

    #[test]
    fn test_local_tags_query_with_cursor_applies_cursor_in_sql() {
        let query = local_tags_query(true);
        assert!(query.contains("POSITION(':' IN tag) = 0"));
        assert!(query.contains("(LOWER(tag), tag) > (LOWER($3), $3)"));
        assert!(query.contains("ORDER BY LOWER(tag), tag"));
        assert!(query.contains("LIMIT $4"));
    }

    #[test]
    fn test_split_remote_tags_page_detects_next_page() {
        let tags = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let (page, has_more) = split_remote_tags_page(tags, 2, false);
        assert_eq!(page, vec!["a", "b"]);
        assert!(has_more);
    }

    #[test]
    fn test_split_remote_tags_page_without_extra_item() {
        let tags = vec!["a", "b"].into_iter().map(String::from).collect();
        let (page, has_more) = split_remote_tags_page(tags, 2, false);
        assert_eq!(page, vec!["a", "b"]);
        assert!(!has_more);
    }

    #[test]
    fn test_split_remote_tags_page_preserves_upstream_continuation() {
        let tags = vec!["a", "b"].into_iter().map(String::from).collect();
        let (page, has_more) = split_remote_tags_page(tags, 2, true);
        assert_eq!(page, vec!["a", "b"]);
        assert!(has_more);
    }

    #[test]
    fn test_parse_upstream_pagination_last_from_relative_link() {
        let next = parse_upstream_pagination_last(
            "</v2/library/alpine/tags/list?n=2&last=v1.0%2Bbuild>; rel=\"next\"",
        );
        assert_eq!(next.as_deref(), Some("v1.0+build"));
    }

    #[test]
    fn test_parse_upstream_pagination_last_from_absolute_link() {
        let next = parse_upstream_pagination_last(
            "<https://registry.example.test/v2/library/alpine/tags/list?n=2&last=rc-2>; rel=\"next\"",
        );
        assert_eq!(next.as_deref(), Some("rc-2"));
    }

    #[test]
    fn test_parse_upstream_pagination_last_ignores_non_next_rel() {
        let next = parse_upstream_pagination_last(
            "</v2/library/alpine/tags/list?n=2&last=v1.0>; rel=\"prev\"",
        );
        assert_eq!(next, None);
    }

    #[test]
    fn test_finalize_remote_tags_page_preserves_upstream_error_without_cache() {
        let upstream = Err(oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "upstream unavailable",
        ));

        let err = finalize_remote_tags_page(
            upstream,
            LocalTagsPage {
                tags: vec![],
                has_more: false,
            },
            false,
        )
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_finalize_remote_tags_page_falls_back_to_cached_tags() {
        let upstream = Err(oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "upstream unavailable",
        ));
        let cached_page = LocalTagsPage {
            tags: vec!["beta".to_string()],
            has_more: true,
        };

        let (page, has_more) = finalize_remote_tags_page(upstream, cached_page, true).unwrap();
        assert_eq!(page, vec!["beta"]);
        assert!(has_more);
    }

    #[test]
    fn test_missing_upload_uuid_response_uses_not_found() {
        let resp = missing_upload_uuid_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // version_check_ok
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_check_ok_status() {
        let resp = version_check_ok();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_version_check_ok_has_distribution_header() {
        let resp = version_check_ok();
        assert_eq!(
            resp.headers()
                .get("Docker-Distribution-API-Version")
                .unwrap(),
            "registry/2.0"
        );
    }

    #[test]
    fn test_version_check_ok_content_type() {
        let resp = version_check_ok();
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    // -----------------------------------------------------------------------
    // Auth dispatch: verify Basic vs Bearer extraction is mutually exclusive
    // (validate_token depends on extract_bearer_token, which these prove)
    // -----------------------------------------------------------------------

    #[test]
    fn test_basic_auth_not_extracted_as_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        // Bearer extraction returns None for Basic Auth
        assert!(extract_bearer_token(&headers).is_none());
        // Basic extraction returns the credentials
        assert!(extract_basic_credentials(&headers).is_some());
    }

    #[test]
    fn test_bearer_not_extracted_as_basic() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer some-jwt-token"),
        );
        // Basic extraction returns None for Bearer
        assert!(extract_basic_credentials(&headers).is_none());
        // Bearer extraction returns the token
        assert!(extract_bearer_token(&headers).is_some());
    }

    #[test]
    fn test_no_auth_header_returns_none_for_both() {
        let headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());
        assert!(extract_basic_credentials(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_basic_credentials edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_empty_password() {
        let mut headers = HeaderMap::new();
        // "user:" in base64 = "dXNlcjo="
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic dXNlcjo="));
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_bearer_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer some-token"));
        assert!(extract_basic_credentials(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_bearer_token edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_bearer_token_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(extract_bearer_token(&headers), Some("".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_with_spaces_in_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer token with spaces"),
        );
        assert_eq!(
            extract_bearer_token(&headers),
            Some("token with spaces".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // unauthorized_challenge body content
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_unauthorized_challenge_body_contains_error() {
        let resp = unauthorized_challenge("http://localhost:8080");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(www_auth.contains("realm=\"http://localhost:8080/v2/token\""));
        assert!(www_auth.contains("service=\"artifact-keeper\""));

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errors"][0]["code"], "UNAUTHORIZED");
        assert_eq!(json["errors"][0]["message"], "authentication required");
    }

    // -----------------------------------------------------------------------
    // TokenResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_response_serialization() {
        let resp = TokenResponse {
            token: "tok1".to_string(),
            access_token: "tok1".to_string(),
            expires_in: 3600,
            issued_at: "2024-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"token\":\"tok1\""));
        assert!(json.contains("\"access_token\":\"tok1\""));
        assert!(json.contains("\"expires_in\":3600"));
        assert!(json.contains("\"issued_at\""));
    }

    // -----------------------------------------------------------------------
    // OciRepoInfo
    // -----------------------------------------------------------------------

    fn make_repo_info(
        key: &str,
        repo_type: &str,
        upstream_url: Option<&str>,
        image: &str,
    ) -> OciRepoInfo {
        OciRepoInfo {
            id: Uuid::new_v4(),
            key: key.to_string(),
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: "/data/docker".to_string(),
            },
            repo_type: repo_type.to_string(),
            upstream_url: upstream_url.map(String::from),
            is_public: false,
            image: image.to_string(),
        }
    }

    #[test]
    fn test_oci_repo_info_remote_type() {
        let info = make_repo_info(
            "docker-hub",
            "remote",
            Some("https://registry-1.docker.io"),
            "library/nginx",
        );
        assert_eq!(info.repo_type, RepositoryType::Remote);
        assert_eq!(
            info.upstream_url.as_deref(),
            Some("https://registry-1.docker.io")
        );
        assert_eq!(info.image, "library/nginx");
    }

    #[test]
    fn test_oci_repo_info_local_type() {
        let info = make_repo_info("docker-local", "local", None, "myapp");
        assert_ne!(info.repo_type, RepositoryType::Remote);
        assert!(info.upstream_url.is_none());
    }

    // --- Docker Hub library/ prefix tests ---

    #[test]
    fn test_is_docker_hub_registry1() {
        assert!(super::is_docker_hub("https://registry-1.docker.io"));
    }

    #[test]
    fn test_is_docker_hub_plain() {
        assert!(super::is_docker_hub("https://docker.io"));
    }

    #[test]
    fn test_is_docker_hub_index() {
        assert!(super::is_docker_hub("https://index.docker.io"));
    }

    #[test]
    fn test_is_docker_hub_with_path() {
        assert!(super::is_docker_hub("https://registry-1.docker.io/v2"));
    }

    #[test]
    fn test_is_not_docker_hub_ghcr() {
        assert!(!super::is_docker_hub("https://ghcr.io"));
    }

    #[test]
    fn test_is_not_docker_hub_false_positive() {
        assert!(!super::is_docker_hub("https://not-docker.io.example.com"));
    }

    #[test]
    fn test_normalize_official_image_on_docker_hub() {
        assert_eq!(
            super::normalize_docker_image("alpine", "https://registry-1.docker.io"),
            "library/alpine"
        );
    }

    #[test]
    fn test_normalize_namespaced_image_on_docker_hub() {
        assert_eq!(
            super::normalize_docker_image("myorg/myimage", "https://registry-1.docker.io"),
            "myorg/myimage"
        );
    }

    #[test]
    fn test_normalize_multi_level_namespace_on_docker_hub() {
        assert_eq!(
            super::normalize_docker_image("myorg/subteam/myimage", "https://registry-1.docker.io"),
            "myorg/subteam/myimage"
        );
    }

    #[test]
    fn test_normalize_already_prefixed_library() {
        assert_eq!(
            super::normalize_docker_image("library/alpine", "https://registry-1.docker.io"),
            "library/alpine"
        );
    }

    #[test]
    fn test_normalize_official_image_on_non_docker_hub() {
        assert_eq!(
            super::normalize_docker_image("alpine", "https://ghcr.io"),
            "alpine"
        );
    }

    #[test]
    fn test_normalize_on_plain_docker_io() {
        assert_eq!(
            super::normalize_docker_image("nginx", "https://docker.io"),
            "library/nginx"
        );
    }

    // -----------------------------------------------------------------------
    // ANONYMOUS_TOKEN constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_anonymous_token_is_non_empty() {
        assert!(!ANONYMOUS_TOKEN.is_empty());
    }

    // -----------------------------------------------------------------------
    // is_anonymous_token
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_anonymous_token_with_anonymous_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer anonymous"));
        assert!(is_anonymous_token(&headers));
    }

    #[test]
    fn test_is_anonymous_token_with_real_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.test"),
        );
        assert!(!is_anonymous_token(&headers));
    }

    #[test]
    fn test_is_anonymous_token_no_header() {
        let headers = HeaderMap::new();
        assert!(!is_anonymous_token(&headers));
    }

    #[test]
    fn test_is_anonymous_token_basic_auth() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert!(!is_anonymous_token(&headers));
    }

    #[test]
    fn test_is_anonymous_token_lowercase_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("bearer anonymous"));
        assert!(is_anonymous_token(&headers));
    }

    // -----------------------------------------------------------------------
    // OciRepoInfo.is_public field
    // -----------------------------------------------------------------------

    #[test]
    fn test_oci_repo_info_default_not_public() {
        let info = make_repo_info("docker-local", "local", None, "myapp");
        assert!(!info.is_public);
    }

    #[test]
    fn test_oci_repo_info_public_flag() {
        let mut info = make_repo_info("docker-pub", "local", None, "myapp");
        info.is_public = true;
        assert!(info.is_public);
    }

    // -----------------------------------------------------------------------
    // apply_cursor_pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_apply_cursor_no_last_returns_first_n() {
        let tags = vec!["a", "b", "c", "d", "e"]
            .into_iter()
            .map(String::from)
            .collect();
        let (result, has_more) = apply_cursor_pagination(tags, None, 3);
        assert_eq!(result, vec!["a", "b", "c"]);
        assert!(has_more);
    }

    #[test]
    fn test_apply_cursor_with_last_skips_before() {
        let tags = vec!["a", "b", "c", "d", "e"]
            .into_iter()
            .map(String::from)
            .collect();
        let (result, has_more) = apply_cursor_pagination(tags, Some("b"), 2);
        assert_eq!(result, vec!["c", "d"]);
        assert!(has_more);
    }

    #[test]
    fn test_apply_cursor_last_item_returns_rest() {
        let tags = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let (result, has_more) = apply_cursor_pagination(tags, Some("a"), 10);
        assert_eq!(result, vec!["b", "c"]);
        assert!(!has_more);
    }

    #[test]
    fn test_apply_cursor_n_zero_returns_empty() {
        let tags = vec!["a", "b"].into_iter().map(String::from).collect();
        let (result, has_more) = apply_cursor_pagination(tags, None, 0);
        assert!(result.is_empty());
        assert!(!has_more);
    }

    #[test]
    fn test_apply_cursor_last_not_found_returns_from_lexicographic_position() {
        let tags = vec!["alpha", "beta", "gamma"]
            .into_iter()
            .map(String::from)
            .collect();
        // "az" is between "alpha" and "beta" lexicographically
        let (result, _) = apply_cursor_pagination(tags, Some("az"), 10);
        assert_eq!(result, vec!["beta", "gamma"]);
    }

    #[test]
    fn test_merge_and_dedup_tags() {
        let sets = vec![
            vec!["b".to_string(), "a".to_string(), "c".to_string()],
            vec!["c".to_string(), "d".to_string(), "a".to_string()],
        ];
        let merged = merge_and_dedup_tags(sets);
        assert_eq!(merged, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn test_merge_and_dedup_tags_lexical_order() {
        let sets = vec![vec![
            "Beta".to_string(),
            "alpha".to_string(),
            "GAMMA".to_string(),
        ]];
        let merged = merge_and_dedup_tags(sets);
        assert_eq!(merged, vec!["alpha", "Beta", "GAMMA"]);
    }

    #[test]
    fn test_merge_and_dedup_tags_empty() {
        let sets: Vec<Vec<String>> = vec![vec![], vec![]];
        let merged = merge_and_dedup_tags(sets);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_merge_and_dedup_tags_exact_dedup() {
        let sets = vec![
            vec!["Latest".to_string(), "v1.0".to_string()],
            vec!["latest".to_string(), "v1.0".to_string()],
        ];
        let merged = merge_and_dedup_tags(sets);
        // Case-sensitive dedup: "Latest" and "latest" are distinct tags
        assert_eq!(merged, vec!["Latest", "latest", "v1.0"]);
    }

    #[test]
    fn test_apply_cursor_lexical_ordering() {
        let tags = vec!["alpha", "Beta", "gamma"]
            .into_iter()
            .map(String::from)
            .collect();
        let (result, _) = apply_cursor_pagination(tags, Some("Beta"), 10);
        assert_eq!(result, vec!["gamma"]);
    }

    #[test]
    fn test_oci_lexical_cmp_is_case_insensitive_with_stable_tiebreak() {
        assert_eq!(oci_lexical_cmp("alpha", "Beta"), std::cmp::Ordering::Less);
        assert_eq!(oci_lexical_cmp("Beta", "beta"), std::cmp::Ordering::Less);
    }

    // -----------------------------------------------------------------------
    // TagsListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_tags_list_response_serialization() {
        let resp = TagsListResponse {
            name: "library/nginx".to_string(),
            tags: vec!["1.25".to_string(), "latest".to_string()],
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "library/nginx");
        assert_eq!(json["tags"], serde_json::json!(["1.25", "latest"]));
    }

    #[test]
    fn test_tags_list_response_empty_tags() {
        let resp = TagsListResponse {
            name: "myimage".to_string(),
            tags: vec![],
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["tags"], serde_json::json!([]));
    }

    // -----------------------------------------------------------------------
    // CatalogResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_catalog_response_serialization() {
        let resp = CatalogResponse {
            repositories: vec!["myrepo/alpine".to_string(), "myrepo/nginx".to_string()],
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            json["repositories"],
            serde_json::json!(["myrepo/alpine", "myrepo/nginx"])
        );
    }

    #[test]
    fn test_catalog_response_empty() {
        let resp = CatalogResponse {
            repositories: vec![],
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["repositories"], serde_json::json!([]));
    }

    // -----------------------------------------------------------------------
    // Pagination Link header
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_pagination_link_header_relative_url() {
        let link = build_pagination_link_header("/v2/myrepo/nginx/tags/list", "v2.0", 100);
        assert_eq!(
            link,
            "</v2/myrepo/nginx/tags/list?n=100&last=v2.0>; rel=\"next\""
        );
    }

    #[test]
    fn test_build_pagination_link_header_url_encodes_last() {
        let link = build_pagination_link_header("/v2/myrepo/nginx/tags/list", "v1.0+build", 50);
        assert!(link.contains("last=v1.0%2Bbuild"));
        assert!(link.contains("n=50"));
        assert!(link.starts_with("</v2/"));
    }

    #[test]
    fn test_parse_pagination_params_defaults() {
        let params = std::collections::HashMap::new();
        let (n, last) = parse_pagination_params(&params).unwrap();
        assert_eq!(n, 100);
        assert_eq!(last, None);
    }

    #[test]
    fn test_parse_pagination_params_custom() {
        let mut params = std::collections::HashMap::new();
        params.insert("n".to_string(), "50".to_string());
        params.insert("last".to_string(), "v1.0".to_string());
        let (n, last) = parse_pagination_params(&params).unwrap();
        assert_eq!(n, 50);
        assert_eq!(last, Some("v1.0".to_string()));
    }

    #[test]
    fn test_parse_pagination_params_n_zero() {
        let mut params = std::collections::HashMap::new();
        params.insert("n".to_string(), "0".to_string());
        let (n, _last) = parse_pagination_params(&params).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_parse_pagination_params_n_exceeds_max() {
        let mut params = std::collections::HashMap::new();
        params.insert("n".to_string(), "99999".to_string());
        let (n, _last) = parse_pagination_params(&params).unwrap();
        assert_eq!(n, 10000);
    }

    #[test]
    fn test_parse_pagination_params_invalid_n_returns_error() {
        let mut params = std::collections::HashMap::new();
        params.insert("n".to_string(), "abc".to_string());
        let err = parse_pagination_params(&params).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_parse_pagination_params_negative_n_returns_error() {
        let mut params = std::collections::HashMap::new();
        params.insert("n".to_string(), "-1".to_string());
        let err = parse_pagination_params(&params).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // handle_delete_manifest: path parsing for DELETE dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_oci_path_delete_manifest_by_tag() {
        let result = parse_oci_path("/myrepo/myimage/manifests/v1.0");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "myrepo/myimage");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("v1.0".to_string()));
    }

    #[test]
    fn test_parse_oci_path_delete_manifest_by_digest() {
        let result =
            parse_oci_path("/myrepo/myimage/manifests/sha256:abcdef1234567890abcdef1234567890");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "myrepo/myimage");
        assert_eq!(op, "manifests");
        assert_eq!(
            reference,
            Some("sha256:abcdef1234567890abcdef1234567890".to_string())
        );
    }
}
