//! Docker Registry V2 API (OCI Distribution Spec) handlers.
//!
//! Implements the minimum endpoints required for `docker login`, `docker push`,
//! and `docker pull` per the OCI Distribution Specification.
// TODO(#553): OCI errors use a spec-mandated JSON envelope (oci_error fn) and
// cannot be converted to AppError without breaking Docker/OCI client compat.
// Consider wrapping oci_error to also log via tracing for consistency.

use std::error::Error as StdError;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use axum::body::{to_bytes, Body, HttpBody};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::{info, warn};
use uuid::Uuid;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::error::AppError;
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

fn oci_internal_error(message: &str) -> Response {
    oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
}

/// Escape a string so it is safe to embed in an HTTP `quoted-string` body
/// (RFC 7230 §3.2.6 ABNF):
///
/// ```text
/// qdtext       = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
/// quoted-pair  = "\" ( HTAB / SP / VCHAR / obs-text )
/// obs-text     = %x80-FF
/// ```
///
/// `"` and `\` get the standard `quoted-pair` backslash escape. HTAB and
/// printable ASCII pass through verbatim. Everything else (CR, LF, NUL,
/// other control chars, and `obs-text` ≥ 0x80) is percent-encoded
/// byte-by-byte. CR/LF in particular **must** be dropped from the output:
/// `pull_scope` / `push_scope` interpolate the URL-decoded `image_name`
/// path parameter into the scope value, so a path containing
/// `…%0D%0A…` would otherwise inject a follow-on header into the 401
/// response. `obs-text` is percent-encoded rather than passed through so
/// the result remains valid for `HeaderValue::from_str` (which accepts
/// only ASCII-visible bytes plus HTAB).
fn auth_challenge_quoted_value(value: &str) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\t' | '\x20'..='\x21' | '\x23'..='\x5b' | '\x5d'..='\x7e' => escaped.push(ch),
            _ => {
                let mut buf = [0; 4];
                for byte in ch.encode_utf8(&mut buf).as_bytes() {
                    let _ = write!(&mut escaped, "%{byte:02X}");
                }
            }
        }
    }
    escaped
}

fn www_authenticate_header(host: &str, scope: Option<&str>) -> String {
    let realm = auth_challenge_quoted_value(&format!("{host}/v2/token"));
    let service = OCI_TOKEN_SERVICE;
    match scope {
        Some(s) => {
            let scope = auth_challenge_quoted_value(s);
            format!("Bearer realm=\"{realm}\",service=\"{service}\",scope=\"{scope}\"")
        }
        None => format!("Bearer realm=\"{realm}\",service=\"{service}\""),
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

/// Form body sent by Docker for the OAuth2 password-grant flow against the
/// distribution token endpoint (`POST /v2/token`). Only `grant_type`,
/// `username`, and `password` are used here; fields like `service`,
/// `scope`, and `client_id` carry routing/scoping metadata that the OCI
/// handler reads from the URL query string (`Query<TokenQuery>`) and are
/// not used for authentication.
#[derive(Deserialize, Default)]
struct TokenForm {
    grant_type: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

/// Extract `(username, password)` from an OAuth2 password-grant form body.
///
/// Returns None unless ALL of the following hold:
///   * `Content-Type` starts with `application/x-www-form-urlencoded`.
///   * The body parses as a `TokenForm`.
///   * `grant_type`, if present, is exactly `"password"` (Docker always
///     sends this; we accept absence too for tolerance).
///   * Both `username` and `password` are non-empty after URL-decode.
///
/// On any of those failures, returns None so the caller falls through to
/// the next credential source (Bearer token, then anonymous). This is a
/// non-fatal extractor: a malformed form body must not break the public-
/// pull path.
fn extract_form_credentials(headers: &HeaderMap, body: &Bytes) -> Option<(String, String)> {
    if body.is_empty() {
        return None;
    }
    let ct = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    // Allow charset suffix etc. (e.g. `application/x-www-form-urlencoded; charset=UTF-8`).
    if !ct.starts_with("application/x-www-form-urlencoded") {
        return None;
    }
    let form: TokenForm = serde_urlencoded::from_bytes(body).ok()?;
    if let Some(ref gt) = form.grant_type {
        if gt != "password" {
            return None;
        }
    }
    let username = form.username?;
    let password = form.password?;
    if username.is_empty() || password.is_empty() {
        return None;
    }
    Some((username, password))
}

async fn validate_token(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<crate::services::auth_service::Claims, ()> {
    let token = extract_bearer_token(headers).ok_or(())?;
    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    // Replica-safe variant (#1173): consults the DB credential-change watermark
    // so a credential change on replica A is honoured on replica B.
    auth_service
        .validate_access_token_async(&token)
        .await
        .map_err(|_| ())
}

/// Credential extracted from an OCI request's Authorization header.
///
/// `Bearer` carries a JWT token (the standard OCI token-exchange flow).
/// `Basic` carries username + password/api-token (curl, CI runners, HTTP
/// clients that skip the token exchange).
#[derive(Debug, Clone, PartialEq, Eq)]
enum OciCredential {
    Bearer(String),
    Basic { username: String, password: String },
}

/// Parse the Authorization header into an [`OciCredential`].
///
/// Returns `None` when the header is missing, empty, or uses an unsupported
/// scheme.  Bearer is tried first so that a valid JWT is never accidentally
/// interpreted as a base64-encoded Basic credential.
fn extract_oci_credential(headers: &HeaderMap) -> Option<OciCredential> {
    if let Some(token) = extract_bearer_token(headers) {
        return Some(OciCredential::Bearer(token));
    }
    if let Some((username, password)) = extract_basic_credentials(headers) {
        return Some(OciCredential::Basic { username, password });
    }
    None
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
    authenticate_oci_with_scopes(db, config, headers)
        .await
        .map(|(claims, _)| claims)
}

/// Authenticate an OCI request and also return the API-token scopes if the
/// caller presented one. Returns `(claims, None)` when the caller authenticated
/// via JWT or password (no scope restriction), and `(claims, Some(scopes))`
/// when they presented an API token. Used by write/delete handlers that must
/// enforce GHSA-vvc3-h39c-mrq5 scope gating (`pull,push` for writes,
/// `pull,push,delete` for destructive operations).
async fn authenticate_oci_with_scopes(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<(crate::services::auth_service::Claims, Option<Vec<String>>), ()> {
    let credential = extract_oci_credential(headers).ok_or(())?;

    match credential {
        OciCredential::Bearer(token) => {
            let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
            // Replica-safe (#1173): same rationale as the auth middleware. A
            // Bearer token presented to OCI must be rejected if the user's
            // credentials changed on a peer replica after the token was minted.
            //
            // First, try as a JWT access token. JWTs carry no scope claim and
            // are minted only via interactive login flows, so they are not
            // restricted here.
            if let Ok(claims) = auth_service.validate_access_token_async(&token).await {
                return Ok((claims, None));
            }
            // Otherwise, accept a raw API token in the Bearer slot (common
            // for `docker login --password-stdin` with API token). Surface
            // the scopes so the caller can enforce GHSA-vvc3-h39c-mrq5.
            if let Ok(validation) = auth_service.validate_api_token(&token).await {
                let scopes = validation.scopes.clone();
                let claims = auth_service
                    .generate_tokens(&validation.user)
                    .map_err(|_| ())
                    .and_then(|tokens| {
                        auth_service
                            .validate_access_token(&tokens.access_token)
                            .map_err(|_| ())
                    })?;
                return Ok((claims, Some(scopes)));
            }
            Err(())
        }
        OciCredential::Basic { username, password } => {
            let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));

            // Try API token in the password field first (service accounts, CI
            // pipelines, registry mirrors, curl scripts). #1195: `authenticate`
            // bumps `users.failed_login_attempts` on every bcrypt miss, so any
            // OCI verb (manifest GET, blob HEAD, blob PUT, etc.) that
            // presented Basic `<user>:<api_token>` would lock the service
            // account out after `account_lockout_threshold` requests. Mirrors
            // the #1145 fix on `/v2/token`. `validate_api_token` has no
            // failure-counter side effect and runs a constant-time bcrypt
            // pad on miss so this reorder is safe. The username from Basic
            // auth is ignored when an API token validates (matching the
            // /v2/token behavior): the token itself identifies the user.
            if let Ok(validation) = auth_service.validate_api_token(&password).await {
                let scopes = validation.scopes.clone();
                let claims = auth_service
                    .generate_tokens(&validation.user)
                    .map_err(|_| ())
                    .and_then(|tokens| {
                        auth_service
                            .validate_access_token(&tokens.access_token)
                            .map_err(|_| ())
                    })?;
                return Ok((claims, Some(scopes)));
            }

            // Fall through to username/password authentication. Re-generate
            // short-lived claims so downstream code has a consistent Claims
            // value regardless of the authentication method.
            if let Ok((user, _tokens)) = auth_service.authenticate(&username, &password).await {
                let claims = auth_service
                    .generate_tokens(&user)
                    .map_err(|_| ())
                    .and_then(|tokens| {
                        auth_service
                            .validate_access_token(&tokens.access_token)
                            .map_err(|_| ())
                    })?;
                return Ok((claims, None));
            }

            Err(())
        }
    }
}

/// Verify that the resolved OCI credential scopes (if any) grant the given
/// permission. Returns `false` if an API token is present but lacks the
/// requested scope. Implements the same logic as
/// `AuthExtension::has_scope`: `*` and `admin` count as wildcards, and a
/// `None` scopes set (JWT / password) passes through.
fn oci_scopes_grant(scopes: &Option<Vec<String>>, required: &str) -> bool {
    match scopes {
        None => true,
        Some(s) => s.iter().any(|x| x == required || x == "*" || x == "admin"),
    }
}

/// Build a 403 Forbidden response when an API-token scope check fails on
/// an OCI write/delete path. See GHSA-vvc3-h39c-mrq5.
fn oci_forbidden_scope(required: &str) -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(format!(
            "Token does not have required scope: {}",
            required
        )))
        .unwrap()
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

/// Storage key prefix for OCI manifest objects.
///
/// WARNING: the `oci-manifests/` prefix is also hard-coded in the
/// lifecycle cascade SQL (`backend/src/services/lifecycle_service.rs`,
/// `CASCADE_OCI_TAGS_SQL`) and in the storage GC orphan predicate
/// (`backend/src/services/storage_gc_service.rs`). Changing this
/// function alone will silently break both. Tracked in #1413 for
/// extracting a shared constant.
fn manifest_storage_key(digest: &str) -> String {
    format!("oci-manifests/{}", digest)
}

fn upload_storage_key(uuid: &Uuid) -> String {
    format!("oci-uploads/{}", uuid)
}

fn upload_part_storage_key(upload_key: &str, part_index: i32, part_id: &Uuid) -> String {
    format!("{}.part.{:08}.{}", upload_key, part_index, part_id)
}

fn upload_progress_range(bytes_received: i64) -> String {
    if bytes_received <= 0 {
        "0-0".to_string()
    } else {
        format!("0-{}", bytes_received - 1)
    }
}

fn upload_patch_accepted_response(
    image_name: &str,
    session_id: Uuid,
    bytes_received: i64,
) -> Response {
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(
            LOCATION,
            format!("/v2/{}/blobs/uploads/{}", image_name, session_id),
        )
        .header("Docker-Upload-UUID", session_id.to_string())
        .header("Range", upload_progress_range(bytes_received))
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

fn upload_complete_created_response(image_name: &str, digest: &str) -> Response {
    Response::builder()
        .status(StatusCode::CREATED)
        .header(LOCATION, format!("/v2/{}/blobs/{}", image_name, digest))
        .header("Docker-Content-Digest", digest)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{:x}", hasher.finalize())
}

fn request_body_stream(
    body: Body,
    initial_bytes_read: u64,
    max_upload_size_bytes: u64,
    limit_exceeded: Arc<AtomicBool>,
) -> BoxStream<'static, crate::error::Result<Bytes>> {
    let mut bytes_read: u64 = initial_bytes_read;
    Box::pin(body.into_data_stream().map(move |chunk| {
        let data =
            chunk.map_err(|e| AppError::Validation(format!("request body read failed: {}", e)))?;

        if max_upload_size_bytes != 0 {
            bytes_read = bytes_read
                .checked_add(data.len() as u64)
                .unwrap_or(max_upload_size_bytes.saturating_add(1));
            if bytes_read > max_upload_size_bytes {
                limit_exceeded.store(true, Ordering::Relaxed);
                return Err(AppError::Validation(format!(
                    "request body exceeds configured max upload size of {} bytes",
                    max_upload_size_bytes
                )));
            }
        }

        Ok(data)
    }))
}

async fn put_request_body_stream(
    storage: &Arc<dyn crate::storage::StorageBackend>,
    key: &str,
    body: Body,
    initial_bytes_read: u64,
    max_upload_size_bytes: u64,
) -> Result<crate::storage::PutStreamResult, Response> {
    let limit_exceeded = Arc::new(AtomicBool::new(false));
    let stream = request_body_stream(
        body,
        initial_bytes_read,
        max_upload_size_bytes,
        Arc::clone(&limit_exceeded),
    );
    match storage.put_stream(key, stream).await {
        Ok(result) => Ok(result),
        Err(e)
            if limit_exceeded.load(Ordering::Relaxed) || matches!(&e, AppError::Validation(_)) =>
        {
            Err(oci_error(
                StatusCode::BAD_REQUEST,
                "BLOB_UPLOAD_INVALID",
                &e.to_string(),
            ))
        }
        Err(e) => Err(oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BLOB_UPLOAD_UNKNOWN",
            &e.to_string(),
        )),
    }
}

async fn collect_request_body(body: Body, limit: usize) -> Result<Bytes, Response> {
    // Config uses MAX_UPLOAD_SIZE=0 to mean "unlimited" (the router disables
    // DefaultBodyLimit for the same value). axum::body::to_bytes interprets 0
    // literally, so translate it before collecting legacy small-body paths.
    let limit = if limit == 0 { usize::MAX } else { limit };
    collect_request_body_with_exact_limit(body, limit).await
}

async fn collect_request_body_with_exact_limit(
    body: Body,
    limit: usize,
) -> Result<Bytes, Response> {
    to_bytes(body, limit).await.map_err(|e| {
        if error_chain_contains::<http_body_util::LengthLimitError>(&e) {
            return oci_error(
                StatusCode::BAD_REQUEST,
                "BLOB_UPLOAD_INVALID",
                &format!("request body exceeds configured limit: {}", e),
            );
        }
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BLOB_UPLOAD_UNKNOWN",
            &format!("request body read failed: {}", e),
        )
    })
}

fn error_chain_contains<T>(error: &(dyn StdError + 'static)) -> bool
where
    T: StdError + 'static,
{
    let mut current = Some(error);
    while let Some(error) = current {
        if error.is::<T>() {
            return true;
        }
        current = error.source();
    }
    false
}

fn upload_session_size_error(max_upload_size_bytes: u64) -> Response {
    oci_error(
        StatusCode::BAD_REQUEST,
        "BLOB_UPLOAD_INVALID",
        &format!(
            "upload session exceeds configured max upload size of {} bytes",
            max_upload_size_bytes
        ),
    )
}

fn upload_session_body_limit(existing_bytes: i64, max_upload_size_bytes: u64) -> usize {
    if max_upload_size_bytes == 0 {
        return usize::MAX;
    }
    let existing_bytes = match u64::try_from(existing_bytes) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    max_upload_size_bytes
        .saturating_sub(existing_bytes)
        .try_into()
        .unwrap_or(usize::MAX)
}

fn reject_oversized_content_length(
    headers: &HeaderMap,
    body_limit: usize,
    max_upload_size_bytes: u64,
) -> Option<Response> {
    if body_limit == usize::MAX {
        return None;
    }
    let content_length = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())?;
    if content_length > body_limit as u64 {
        return Some(upload_session_size_error(max_upload_size_bytes));
    }
    None
}

fn parse_upload_content_range(value: &str) -> Option<(i64, i64)> {
    let range = value
        .trim()
        .strip_prefix("bytes ")
        .unwrap_or_else(|| value.trim());
    let (start, end) = range.split_once('-')?;
    let start = start.trim().parse::<i64>().ok()?;
    let end = end.trim().parse::<i64>().ok()?;
    if start < 0 || end < start {
        return None;
    }
    Some((start, end))
}

fn validate_patch_content_range(headers: &HeaderMap, expected_start: i64) -> Option<Response> {
    let value = headers.get("Content-Range")?;
    let Ok(value) = value.to_str() else {
        return Some(oci_error(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "BLOB_UPLOAD_INVALID",
            "invalid Content-Range header",
        ));
    };
    let Some((start, end)) = parse_upload_content_range(value) else {
        return Some(oci_error(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "BLOB_UPLOAD_INVALID",
            "invalid Content-Range header",
        ));
    };
    if start != expected_start {
        return Some(oci_error(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "BLOB_UPLOAD_INVALID",
            &format!(
                "Content-Range starts at {}, expected {}",
                start, expected_start
            ),
        ));
    }
    if let Some(content_length) = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
    {
        // `end` may be as large as i64::MAX (parse_upload_content_range only
        // rejects start < 0 / end < start), so the span must be computed with
        // checked arithmetic: a plain `end - start + 1` overflows for a hostile
        // `Content-Range: 0-9223372036854775807`, which panics in debug builds
        // and wraps to a negative value in release.
        let Some(span) = end.checked_sub(start).and_then(|v| v.checked_add(1)) else {
            return Some(oci_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "BLOB_UPLOAD_INVALID",
                "Content-Range is out of range",
            ));
        };
        if span != content_length {
            return Some(oci_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "BLOB_UPLOAD_INVALID",
                "Content-Range length does not match Content-Length",
            ));
        }
    }
    None
}

async fn delete_storage_key_best_effort(
    storage: &Arc<dyn crate::storage::StorageBackend>,
    key: &str,
    context: &'static str,
) {
    if let Err(e) = storage.delete(key).await {
        warn!(
            storage_key = %key,
            context,
            error = %e,
            "Failed to delete storage object during OCI upload cleanup"
        );
    }
}

async fn register_oci_upload_cleanup_key(
    db: &PgPool,
    repository_id: Uuid,
    upload_session_id: Option<Uuid>,
    storage_key: &str,
) -> Result<(), Response> {
    sqlx::query(
        r#"
        INSERT INTO oci_upload_cleanup_keys (repository_id, upload_session_id, storage_key)
        VALUES ($1, $2, $3)
        ON CONFLICT (storage_key) DO NOTHING
        "#,
    )
    .bind(repository_id)
    .bind(upload_session_id)
    .bind(storage_key)
    .execute(db)
    .await
    .map(|_| ())
    .map_err(|e| oci_internal_error(&e.to_string()))
}

async fn mark_oci_upload_cleanup_key_committed(
    db: &PgPool,
    storage_key: &str,
) -> Result<(), Response> {
    let result = sqlx::query(
        r#"
        UPDATE oci_upload_cleanup_keys
        SET storage_write_completed_at = COALESCE(storage_write_completed_at, NOW())
        WHERE storage_key = $1
        "#,
    )
    .bind(storage_key)
    .execute(db)
    .await
    .map_err(|e| oci_internal_error(&e.to_string()))?;

    // The journal row is always registered before the storage write it tracks,
    // so a 0-row update means the register/mark pairing was broken (row deleted
    // out from under us, or the wrong key). It is not fatal — the pending
    // (NULL-marked) reaper still backstops the temp object — but it should never
    // happen, so surface it instead of silently succeeding.
    if result.rows_affected() == 0 {
        warn!(
            storage_key = %storage_key,
            "OCI upload cleanup key was missing when marking its storage write committed"
        );
    }

    Ok(())
}

async fn delete_storage_key_for_upload_cancel(
    storage: &Arc<dyn crate::storage::StorageBackend>,
    key: &str,
    session_id: Uuid,
) -> std::result::Result<(), Response> {
    match storage.delete(key).await {
        Ok(()) | Err(AppError::NotFound(_)) => Ok(()),
        Err(e) => {
            warn!(
                session_id = %session_id,
                storage_key = %key,
                error = %e,
                "Failed to delete storage object during OCI upload cancellation"
            );
            Err(oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "BLOB_UPLOAD_UNKNOWN",
                &e.to_string(),
            ))
        }
    }
}

/// A SHA-256 content digest.
///
/// The codebase moves a sha256 digest between two interchangeable string
/// representations and relies on each call site picking the right one:
///   * the "prefixed" wire/DB form `"sha256:<hex>"` (the OCI digest query
///     param, `oci_upload_sessions.computed_digest`), and
///   * the "bare hex" form `"<hex>"` (`StorageBackend` checksums,
///     `oci_upload_parts.digest_sha256`).
///
/// This newtype carries the **bare lowercase hex** internally as the canonical
/// form and exposes [`Sha256Digest::as_hex`]/[`Sha256Digest::as_prefixed`] so
/// each SQL bind / comparison serializes through the right accessor. Equality is
/// canonical hex equality, so two values constructed from the two different
/// string forms compare equal. The on-the-wire / DB byte representations are
/// unchanged: bind `as_prefixed()` where the column stores `"sha256:<hex>"` and
/// `as_hex()` where it stores bare hex.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sha256Digest(String);

impl Sha256Digest {
    /// Parse the OCI `digest` query parameter, e.g. `"sha256:abc123..."`.
    ///
    /// Only the `sha256` algorithm is accepted (the registry computes sha256
    /// checksums); the hex must be exactly 64 hex characters. Upper-case hex is
    /// accepted and normalized to lower-case (see [`Sha256Digest::from_hex`]).
    fn parse_digest_param(value: &str) -> std::result::Result<Self, String> {
        let hex = value
            .strip_prefix("sha256:")
            .ok_or_else(|| format!("invalid sha256 digest, missing 'sha256:' prefix: {value}"))?;
        Self::from_hex(hex)
    }

    /// Construct from a bare hex string such as a `StorageBackend` checksum.
    fn from_hex(hex: &str) -> std::result::Result<Self, String> {
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("invalid sha256 hex digest: {hex}"));
        }
        Ok(Self(hex.to_ascii_lowercase()))
    }

    /// The prefixed wire/DB form `"sha256:<hex>"`.
    fn as_prefixed(&self) -> String {
        format!("sha256:{}", self.0)
    }

    /// The bare lowercase hex form `"<hex>"`.
    fn as_hex(&self) -> &str {
        &self.0
    }
}

/// The lifecycle state of an `oci_upload_sessions` row.
///
/// Mirrors the SQL `CHECK (state IN ('open', 'committing'))` constraint
/// (migration 115) so a typo can no longer silently break the completion lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadSessionState {
    /// Accepting PATCH appends; not yet being committed.
    Open,
    /// A PUT completion holds the lease and is concatenating/committing parts.
    Committing,
}

impl UploadSessionState {
    fn as_str(self) -> &'static str {
        match self {
            UploadSessionState::Open => "open",
            UploadSessionState::Committing => "committing",
        }
    }

    fn parse(value: &str) -> std::result::Result<Self, String> {
        match value {
            "open" => Ok(UploadSessionState::Open),
            "committing" => Ok(UploadSessionState::Committing),
            other => Err(format!("invalid oci_upload_sessions.state: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
struct OciUploadSessionRecord {
    repository_id: Uuid,
    storage_temp_key: String,
    bytes_received: i64,
    computed_digest: Option<Sha256Digest>,
    state: UploadSessionState,
    part_count: i64,
}

#[derive(Debug, Clone)]
struct OciUploadPartRecord {
    storage_key: String,
    size_bytes: i64,
}

fn upload_session_conflict(message: &str) -> Response {
    oci_error(StatusCode::CONFLICT, "BLOB_UPLOAD_INVALID", message)
}

fn is_pg_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db_error)
            if db_error.code().as_deref() == Some("23505")
    )
}

fn row_decode_error(context: &str, error: sqlx::Error) -> String {
    format!("{context}: {error}")
}

/// Decode a session row into [`OciUploadSessionRecord`].
///
/// Both the claiming `RETURNING` path and the read-path `SELECT` now project the
/// same columns (`repository_id`, `storage_temp_key`, `bytes_received`,
/// `computed_digest`, `state`, `part_count`), so a single decoder reads every
/// field honestly off the row instead of fabricating `state`/`part_count`.
/// `repo_mismatch` lets the two call sites phrase the cross-repo error
/// distinctly without duplicating the decode logic.
fn decode_upload_session_row_with(
    row: PgRow,
    context_repository_id: Uuid,
    repo_mismatch: &str,
) -> std::result::Result<OciUploadSessionRecord, String> {
    let repository_id = row
        .try_get::<Uuid, _>("repository_id")
        .map_err(|e| row_decode_error("invalid oci_upload_sessions.repository_id", e))?;
    if repository_id != context_repository_id {
        return Err(repo_mismatch.to_string());
    }
    let bytes_received = row
        .try_get::<i64, _>("bytes_received")
        .map_err(|e| row_decode_error("invalid oci_upload_sessions.bytes_received", e))?;
    let part_count = row
        .try_get::<i64, _>("part_count")
        .map_err(|e| row_decode_error("invalid oci_upload_sessions.part_count", e))?;
    if bytes_received < 0 {
        return Err("invalid oci_upload_sessions.bytes_received: negative value".to_string());
    }
    if part_count < 0 {
        return Err("invalid oci_upload_sessions.part_count: negative value".to_string());
    }
    let computed_digest = row
        .try_get::<Option<String>, _>("computed_digest")
        .map_err(|e| row_decode_error("invalid oci_upload_sessions.computed_digest", e))?
        .map(|value| Sha256Digest::parse_digest_param(&value))
        .transpose()
        .map_err(|e| format!("invalid oci_upload_sessions.computed_digest: {e}"))?;
    let state = UploadSessionState::parse(
        &row.try_get::<String, _>("state")
            .map_err(|e| row_decode_error("invalid oci_upload_sessions.state", e))?,
    )?;
    Ok(OciUploadSessionRecord {
        repository_id,
        storage_temp_key: row
            .try_get::<String, _>("storage_temp_key")
            .map_err(|e| row_decode_error("invalid oci_upload_sessions.storage_temp_key", e))?,
        bytes_received,
        computed_digest,
        state,
        part_count,
    })
}

fn decode_claimed_upload_session_row(
    row: PgRow,
    context_repository_id: Uuid,
) -> std::result::Result<OciUploadSessionRecord, String> {
    decode_upload_session_row_with(
        row,
        context_repository_id,
        "claimed upload session repository_id does not match request repository",
    )
}

fn decode_upload_session_row(
    row: PgRow,
    context_repository_id: Uuid,
) -> std::result::Result<OciUploadSessionRecord, String> {
    decode_upload_session_row_with(
        row,
        context_repository_id,
        "upload session repository_id does not match request repository",
    )
}

fn decode_upload_part_row(row: PgRow) -> std::result::Result<OciUploadPartRecord, String> {
    let size_bytes = row
        .try_get::<i64, _>("size_bytes")
        .map_err(|e| row_decode_error("invalid oci_upload_parts.size_bytes", e))?;
    if size_bytes < 0 {
        return Err("invalid oci_upload_parts.size_bytes: negative value".to_string());
    }
    Ok(OciUploadPartRecord {
        storage_key: row
            .try_get::<String, _>("storage_key")
            .map_err(|e| row_decode_error("invalid oci_upload_parts.storage_key", e))?,
        size_bytes,
    })
}

/// Atomically take the completion lease on an upload session.
///
/// Flips the row `open -> committing` and stamps `state_token` so exactly one
/// PUT completion (or cancel) can own the session at a time. A session already
/// `committing` is only reclaimed once its `updated_at` is older than the 6h
/// staleness window — far larger than the 60s heartbeat
/// ([`start_oci_upload_completion_heartbeat`]) that keeps a live lease fresh, so
/// an in-flight completion is never stolen out from under itself. Returns `None`
/// when the session is owned by another live completion (the caller maps this to
/// `409 CONFLICT`).
async fn claim_oci_upload_session_for_completion(
    db: &PgPool,
    session_id: Uuid,
    repository_id: Uuid,
    state_token: Uuid,
) -> Result<Option<OciUploadSessionRecord>, Response> {
    let row = sqlx::query(
        r#"
        UPDATE oci_upload_sessions
        SET state = $4, state_token = $3, updated_at = NOW()
        WHERE id = $1
          AND repository_id = $2
          AND (
            state = $5
            OR (state = $4 AND updated_at < NOW() - INTERVAL '6 hours')
          )
        RETURNING
            repository_id,
            storage_temp_key,
            bytes_received,
            computed_digest,
            state,
            (
                SELECT COALESCE(COUNT(p.id), 0)::BIGINT
                FROM oci_upload_parts p
                WHERE p.upload_session_id = oci_upload_sessions.id
            ) AS part_count
        "#,
    )
    .bind(session_id)
    .bind(repository_id)
    .bind(state_token)
    .bind(UploadSessionState::Committing.as_str())
    .bind(UploadSessionState::Open.as_str())
    .fetch_optional(db)
    .await
    .map_err(|e| {
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        )
    })?;

    row.map(|row| decode_claimed_upload_session_row(row, repository_id))
        .transpose()
        .map_err(|e| oci_internal_error(&e))
}

/// RAII guard over the background task that renews a completion lease.
///
/// While the guard is alive a spawned task refreshes `updated_at` so the 6h
/// staleness reclaim in [`claim_oci_upload_session_for_completion`] cannot steal
/// the session. `Drop` aborts the task, so the heartbeat can never outlive the
/// guard's scope — every early return in `handle_complete_upload` cancels it
/// automatically. The shared `lease_valid` flag flips to `false` (and stays
/// false) once the renew UPDATE touches 0 rows or after repeated DB errors;
/// callers poll [`lease_is_valid`](Self::lease_is_valid) before each
/// storage-mutating step to fail fast. The flag is only an optimization — the
/// authoritative lease check is the `state_token` predicate on the terminal
/// DELETE/UPDATE, which rolls back if the lease was lost.
struct OciUploadCompletionHeartbeat {
    handle: tokio::task::JoinHandle<()>,
    lease_valid: Arc<AtomicBool>,
}

impl Drop for OciUploadCompletionHeartbeat {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl OciUploadCompletionHeartbeat {
    fn lease_is_valid(&self) -> bool {
        self.lease_valid.load(Ordering::Relaxed)
    }
}

fn start_oci_upload_completion_heartbeat(
    db: PgPool,
    session_id: Uuid,
    repository_id: Uuid,
    state_token: Uuid,
) -> OciUploadCompletionHeartbeat {
    start_oci_upload_completion_heartbeat_with_options(
        db,
        session_id,
        repository_id,
        state_token,
        Duration::from_secs(60),
        3,
    )
}

fn start_oci_upload_completion_heartbeat_with_options(
    db: PgPool,
    session_id: Uuid,
    repository_id: Uuid,
    state_token: Uuid,
    interval_duration: Duration,
    max_consecutive_failures: u32,
) -> OciUploadCompletionHeartbeat {
    let lease_valid = Arc::new(AtomicBool::new(true));
    let heartbeat_lease_valid = Arc::clone(&lease_valid);
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        let mut consecutive_failures = 0_u32;
        interval.tick().await;

        loop {
            interval.tick().await;
            match sqlx::query(
                r#"
                UPDATE oci_upload_sessions
                SET updated_at = NOW()
                WHERE id = $1
                  AND repository_id = $2
                  AND state = $4
                  AND state_token = $3
                "#,
            )
            .bind(session_id)
            .bind(repository_id)
            .bind(state_token)
            .bind(UploadSessionState::Committing.as_str())
            .execute(&db)
            .await
            {
                Ok(result) if result.rows_affected() == 1 => {
                    consecutive_failures = 0;
                }
                Ok(_) => {
                    heartbeat_lease_valid.store(false, Ordering::Relaxed);
                    break;
                }
                Err(e) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    warn!(
                        upload_session_id = %session_id,
                        consecutive_failures,
                        error = %e,
                        "Failed to heartbeat OCI upload completion lease"
                    );
                    if consecutive_failures >= max_consecutive_failures {
                        heartbeat_lease_valid.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
    });

    OciUploadCompletionHeartbeat {
        handle,
        lease_valid,
    }
}

#[cfg(test)]
fn start_oci_upload_completion_heartbeat_for_tests(
    db: PgPool,
    session_id: Uuid,
    repository_id: Uuid,
    state_token: Uuid,
    interval_duration: Duration,
    max_consecutive_failures: u32,
) -> OciUploadCompletionHeartbeat {
    start_oci_upload_completion_heartbeat_with_options(
        db,
        session_id,
        repository_id,
        state_token,
        interval_duration,
        max_consecutive_failures,
    )
}

fn completion_lease_lost_response() -> Response {
    upload_session_conflict("upload completion lease was lost")
}

async fn fetch_oci_upload_session(
    db: &PgPool,
    session_id: Uuid,
    repository_id: Uuid,
) -> Result<Option<OciUploadSessionRecord>, Response> {
    let row = sqlx::query(
        r#"
        SELECT
            s.repository_id,
            s.storage_temp_key,
            s.bytes_received,
            s.computed_digest,
            s.state,
            COALESCE(COUNT(p.id), 0)::BIGINT AS part_count
        FROM oci_upload_sessions s
        LEFT JOIN oci_upload_parts p ON p.upload_session_id = s.id
        WHERE s.id = $1 AND s.repository_id = $2
        GROUP BY s.id
        "#,
    )
    .bind(session_id)
    .bind(repository_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        )
    })?;

    row.map(|row| decode_upload_session_row(row, repository_id))
        .transpose()
        .map_err(|e| oci_internal_error(&e))
}

async fn fetch_oci_upload_parts(
    db: &PgPool,
    session_id: Uuid,
    storage_temp_key: &str,
    bytes_received: i64,
) -> Result<Vec<OciUploadPartRecord>, Response> {
    let rows = sqlx::query(
        r#"
        SELECT storage_key, size_bytes
        FROM oci_upload_parts
        WHERE upload_session_id = $1
        ORDER BY part_index
        "#,
    )
    .bind(session_id)
    .fetch_all(db)
    .await
    .map_err(|e| {
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        )
    })?;

    let mut parts = Vec::with_capacity(rows.len());
    for row in rows {
        parts.push(decode_upload_part_row(row).map_err(|e| oci_internal_error(&e))?);
    }

    if parts.is_empty() {
        parts.push(OciUploadPartRecord {
            storage_key: storage_temp_key.to_string(),
            size_bytes: bytes_received,
        });
    }

    Ok(parts)
}

fn storage_concat_stream(
    storage: Arc<dyn crate::storage::StorageBackend>,
    parts: Vec<OciUploadPartRecord>,
) -> BoxStream<'static, crate::error::Result<Bytes>> {
    Box::pin(async_stream::try_stream! {
        for part in parts {
            if part.size_bytes == 0 {
                continue;
            }
            let mut stream = storage.get_stream(&part.storage_key).await?;
            while let Some(chunk) = stream.next().await {
                yield chunk?;
            }
        }
    })
}

async fn reset_oci_upload_session_state(
    db: &PgPool,
    session_id: Uuid,
    repository_id: Uuid,
    state_token: Uuid,
) -> Result<(), Response> {
    let result = sqlx::query(
        "UPDATE oci_upload_sessions SET state = $4, state_token = NULL, updated_at = NOW() WHERE id = $1 AND repository_id = $2 AND state_token = $3",
    )
    .bind(session_id)
    .bind(repository_id)
    .bind(state_token)
    .bind(UploadSessionState::Open.as_str())
    .execute(db)
    .await
    .map_err(|e| {
        warn!(
            upload_session_id = %session_id,
            error = %e,
            "Failed to reset OCI upload session state after completion error"
        );
        oci_internal_error(&e.to_string())
    })?;

    if result.rows_affected() != 1 {
        warn!(
            upload_session_id = %session_id,
            rows_affected = result.rows_affected(),
            "Failed to reset OCI upload session state because lease token no longer owns the session"
        );
        return Err(completion_lease_lost_response());
    }

    Ok(())
}

async fn completion_lease_lost_after_reset(
    db: &PgPool,
    session_id: Uuid,
    repository_id: Uuid,
    state_token: Uuid,
) -> Response {
    if let Err(resp) =
        reset_oci_upload_session_state(db, session_id, repository_id, state_token).await
    {
        return resp;
    }

    completion_lease_lost_response()
}

/// Disambiguate a PATCH whose `tx.commit()` returned an error.
///
/// A failed COMMIT can mean either "the transaction rolled back" or "it actually
/// landed but the ack was lost." This re-reads the session+part: if the expected
/// part row exists and the byte counts match, the PATCH committed (`Ok(true)`);
/// if no such row exists, it rolled back and the caller cleans up (`Ok(false)`).
/// A row that exists but with *mismatched* byte counts is escalated as an error
/// rather than silently retried, because it means the recovered state is not the
/// state this request wrote.
async fn recover_committed_patch_after_commit_error(
    db: &PgPool,
    session_id: Uuid,
    repository_id: Uuid,
    part_index: i32,
    part_key: &str,
    expected_bytes_received: i64,
    expected_part_size: i64,
) -> Result<bool, Response> {
    let row = sqlx::query(
        r#"
        SELECT s.bytes_received, p.size_bytes
        FROM oci_upload_sessions s
        JOIN oci_upload_parts p ON p.upload_session_id = s.id
        WHERE s.id = $1
          AND s.repository_id = $2
          AND s.state = $5
          AND p.part_index = $3
          AND p.storage_key = $4
        "#,
    )
    .bind(session_id)
    .bind(repository_id)
    .bind(part_index)
    .bind(part_key)
    .bind(UploadSessionState::Open.as_str())
    .fetch_optional(db)
    .await
    .map_err(|e| {
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        )
    })?;

    let Some(row) = row else {
        return Ok(false);
    };

    let bytes_received: i64 = row.try_get("bytes_received").map_err(|e| {
        oci_internal_error(&format!(
            "failed to decode recovered upload session bytes_received: {}",
            e
        ))
    })?;
    let part_size: i64 = row.try_get("size_bytes").map_err(|e| {
        oci_internal_error(&format!(
            "failed to decode recovered upload part size: {}",
            e
        ))
    })?;
    if bytes_received < 0 || part_size < 0 {
        return Err(oci_internal_error(
            "recovered OCI upload session contains negative byte counts",
        ));
    }
    if bytes_received != expected_bytes_received || part_size != expected_part_size {
        return Err(oci_internal_error(
            "recovered OCI upload PATCH state did not match expected byte counts",
        ));
    }

    Ok(true)
}

/// Disambiguate a completion whose `tx.commit()` returned an error.
///
/// The completion transaction inserts the `oci_blobs` row and deletes the
/// session atomically. After an ambiguous COMMIT this re-reads both: the session
/// gone *and* the matching blob present means the commit landed (`Ok(true)`,
/// return 201); the session still present means it rolled back (`Ok(false)`, the
/// caller resets the lease and retries). The session gone but blob missing is
/// genuinely ambiguous (a half-applied state that should never occur for an
/// atomic tx) and is surfaced as an internal error rather than swallowed.
async fn recover_committed_completion_after_commit_error(
    db: &PgPool,
    session_id: Uuid,
    repository_id: Uuid,
    digest: &str,
    expected_size_bytes: i64,
    expected_storage_key: &str,
) -> Result<bool, Response> {
    let row = sqlx::query(
        r#"
        SELECT
            EXISTS (
                SELECT 1
                FROM oci_upload_sessions
                WHERE id = $1 AND repository_id = $2
            ) AS session_exists,
            EXISTS (
                SELECT 1
                FROM oci_blobs
                WHERE repository_id = $2
                  AND digest = $3
                  AND size_bytes = $4
                  AND storage_key = $5
            ) AS blob_exists
        "#,
    )
    .bind(session_id)
    .bind(repository_id)
    .bind(digest)
    .bind(expected_size_bytes)
    .bind(expected_storage_key)
    .fetch_one(db)
    .await
    .map_err(|e| {
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        )
    })?;

    let session_exists: bool = row.try_get("session_exists").map_err(|e| {
        oci_internal_error(&format!(
            "failed to decode recovered completion session state: {}",
            e
        ))
    })?;
    let blob_exists: bool = row.try_get("blob_exists").map_err(|e| {
        oci_internal_error(&format!(
            "failed to decode recovered completion blob state: {}",
            e
        ))
    })?;

    if !session_exists && blob_exists {
        return Ok(true);
    }
    if !session_exists {
        return Err(oci_internal_error(
            "OCI upload completion commit status is ambiguous: session is gone but blob row is missing",
        ));
    }

    Ok(false)
}

/// Whether a content-type string identifies an OCI / Docker image index
/// (a "manifest list"). These manifests carry no layers of their own;
/// they reference per-architecture child manifests by digest, which is
/// what the storage GC's `oci_manifest_refs` table tracks for #1179.
///
/// The match is on the bare media type, ignoring `;` parameters and
/// surrounding whitespace, so clients that include charset hints still
/// trip the right branch.
pub(crate) fn is_index_content_type(content_type: &str) -> bool {
    let bare = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        bare.as_str(),
        "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
}

/// Parse an OCI image index manifest body and return the list of child
/// manifest digests. Used by both the push handler (to populate
/// `oci_manifest_refs` synchronously) and the startup backfill (to fill
/// in any rows that pre-date this code).
///
/// Returns an empty vec when the body is not parseable as JSON or has no
/// `manifests` array. Callers should treat that as a no-op rather than
/// an error, since a stray non-conformant manifest should not block the
/// rest of GC protection.
pub(crate) fn extract_child_digests(body: &[u8]) -> Vec<String> {
    let json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    json.get("manifests")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("digest").and_then(|d| d.as_str()))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Insert (parent_digest, child_digest, repository_id) rows into
/// `oci_manifest_refs` for every child of an image index. Idempotent: on
/// conflict the existing row is kept.
///
/// Called inline from `handle_put_manifest` and from the startup
/// backfill. The caller is responsible for verifying that `parent_body`
/// really is an image-index manifest (use [`is_index_content_type`]);
/// passing a regular image manifest just inserts zero rows.
///
/// Performance: the inserts run as a single round-trip via `UNNEST` so a
/// multi-arch push of N platforms costs one DB call, not N. This matters
/// because `handle_put_manifest` calls this synchronously on the request
/// hot path.
pub(crate) async fn record_oci_manifest_refs(
    db: &PgPool,
    repo_id: Uuid,
    parent_digest: &str,
    parent_body: &[u8],
) -> Result<usize, sqlx::Error> {
    let children = extract_child_digests(parent_body);
    if children.is_empty() {
        return Ok(0);
    }
    // Batched insert: expand the child digest array via UNNEST and
    // pair every row with the constant parent_digest / repo_id. One
    // round-trip total. `query_as` over `query!` because sqlx's macro
    // form does not currently type-check `UNNEST` array bindings
    // against the offline metadata cache without explicit casts.
    let res = sqlx::query(
        r#"
        INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id)
        SELECT $1, child, $3
        FROM UNNEST($2::text[]) AS t(child)
        ON CONFLICT (parent_digest, child_digest, repository_id) DO NOTHING
        "#,
    )
    .bind(parent_digest)
    .bind(&children)
    .bind(repo_id)
    .execute(db)
    .await?;
    Ok(res.rows_affected() as usize)
}

/// A single (blob_digest, kind) edge extracted from an image manifest.
/// `kind` is `"config"` for the config blob and `"layer"` for each layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef {
    pub digest: String,
    pub kind: &'static str,
}

/// Parse an OCI / Docker *image* manifest body and return the blob edges
/// it pulls in: the single `config.digest` (kind `"config"`) plus every
/// `layers[].digest` (kind `"layer"`). Used by both the push handler (to
/// populate `manifest_blob_refs` synchronously) and the startup backfill
/// (to reconstruct rows for manifests that pre-date this code) for #1635.
///
/// Returns an empty vec when the body is not parseable as JSON or carries
/// no `config`/`layers` blobs. An image *index* (manifest list) has
/// neither a `config` nor a `layers` array -- it lists child manifests
/// under `manifests[]` -- so passing an index body here yields an empty
/// vec. Callers are still expected to gate on [`is_index_content_type`]
/// so index manifests never reach this path, but the empty-vec behaviour
/// makes a stray call harmless.
///
/// Malformed entries (missing or non-string `digest`) are skipped rather
/// than erroring, mirroring [`extract_child_digests`]: a single
/// non-conformant manifest must not block blob-reference recording for
/// the rest of the corpus.
pub fn extract_blob_refs(body: &[u8]) -> Vec<BlobRef> {
    let json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut refs = Vec::new();
    if let Some(cfg) = json
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
    {
        refs.push(BlobRef {
            digest: cfg.to_string(),
            kind: "config",
        });
    }
    if let Some(layers) = json.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(d) = layer.get("digest").and_then(|d| d.as_str()) {
                refs.push(BlobRef {
                    digest: d.to_string(),
                    kind: "layer",
                });
            }
        }
    }
    refs
}

/// Split a slice of [`BlobRef`] into the two parallel column vectors the
/// `UNNEST`-based insert in [`record_manifest_blob_refs`] binds: the blob
/// digests (`$2::text[]`) and their kinds (`$3::text[]`), index-aligned so
/// row `i` pairs `digests[i]` with `kinds[i]`. Returns `None` when there
/// is nothing to insert (empty input), letting the caller short-circuit
/// the DB round-trip.
///
/// Pure and DB-free so the array-pairing logic is unit-testable without a
/// database (the raw `sqlx::query(...).execute()` is exercised only by the
/// Tier-2 integration tests).
fn blob_refs_to_columns(refs: &[BlobRef]) -> Option<(Vec<String>, Vec<String>)> {
    if refs.is_empty() {
        return None;
    }
    // Split into parallel arrays so a single UNNEST round-trip can pair
    // each blob digest with its kind, all against the constant
    // manifest_digest / repo_id.
    let blob_digests: Vec<String> = refs.iter().map(|r| r.digest.clone()).collect();
    let kinds: Vec<String> = refs.iter().map(|r| r.kind.to_string()).collect();
    Some((blob_digests, kinds))
}

/// Insert (manifest_digest, blob_digest, repository_id, kind) rows into
/// `manifest_blob_refs` for every config/layer blob of an image manifest.
/// Idempotent: on conflict the existing row is kept.
///
/// Called inline from `handle_put_manifest` and from the startup backfill.
/// The caller is responsible for verifying that `manifest_body` is a
/// regular image manifest (NOT an image index -- use
/// [`is_index_content_type`]); passing an index body just inserts zero
/// rows because it has no config/layers.
///
/// ADDITIVE ONLY (#1635): this records references so a future GC can judge
/// blob orphanhood safely. It performs no deletion.
///
/// Performance: the inserts run as a single round-trip via `UNNEST` so a
/// manifest with N layers costs one DB call, not N. This matters because
/// `handle_put_manifest` calls this synchronously on the request hot path.
pub async fn record_manifest_blob_refs(
    db: &PgPool,
    repo_id: Uuid,
    manifest_digest: &str,
    manifest_body: &[u8],
) -> Result<usize, sqlx::Error> {
    let refs = extract_blob_refs(manifest_body);
    let (blob_digests, kinds) = match blob_refs_to_columns(&refs) {
        Some(cols) => cols,
        None => return Ok(0),
    };
    let res = sqlx::query(
        r#"
        INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
        SELECT $1, blob, $4, knd
        FROM UNNEST($2::text[], $3::text[]) AS t(blob, knd)
        ON CONFLICT (manifest_digest, blob_digest, repository_id) DO NOTHING
        "#,
    )
    .bind(manifest_digest)
    .bind(&blob_digests)
    .bind(&kinds)
    .bind(repo_id)
    .execute(db)
    .await?;
    Ok(res.rows_affected() as usize)
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
/// Read `AK_DEFAULT_DOCKER_MIRROR_REPO` once. Returns the configured proxy
/// repo key, or None if the variable is unset / empty. Cached for the
/// lifetime of the process; changes require a pod restart.
///
/// When set, this enables "Docker daemon mirror mode": requests to
/// `/v2/<image>/...` (no AK repo prefix, the path layout dockerd's
/// `registry-mirrors` produces) fall back through the named proxy repo,
/// using the full original image_name as the upstream image path. Without
/// this, only `/v2/<repo-key>/<image>/...` works and dockerd's mirror
/// config is silently bypassed.
fn default_docker_mirror_repo() -> Option<&'static str> {
    static CACHE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            std::env::var("AK_DEFAULT_DOCKER_MIRROR_REPO")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .as_deref()
}

async fn resolve_repo(db: &PgPool, image_name: &str) -> Result<OciRepoInfo, Response> {
    use sqlx::Row;
    // Split: "test/python" → repo_key="test", image="python"
    // Or:    "myrepo/org/image" → repo_key="myrepo", image="org/image"
    let (repo_key, image) = match image_name.find('/') {
        Some(idx) => (&image_name[..idx], &image_name[idx + 1..]),
        None => (image_name, image_name),
    };

    let map_db_err = |e: sqlx::Error| {
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        )
    };

    let select_repo_by_key = |key: String| async move {
        sqlx::query(
            "SELECT id, key, storage_backend, storage_path, repo_type::text as repo_type, \
             upstream_url, is_public FROM repositories WHERE key = $1",
        )
        .bind(key)
        .fetch_optional(db)
        .await
    };

    // 1. Try the literal repo_key first (existing behavior preserved).
    let mut repo = select_repo_by_key(repo_key.to_string())
        .await
        .map_err(map_db_err)?;
    let mut effective_image = image.to_string();

    // 2. Mirror-mode fallback: if the literal lookup missed AND a default
    //    Docker mirror repo is configured, re-resolve through it with the
    //    full original image_name as the image path. This makes dockerd's
    //    `registry-mirrors` config work end-to-end: a pull of
    //    `library/postgres:16-alpine` arrives as
    //    `/v2/library/postgres/manifests/16-alpine`, repo_key="library"
    //    misses, fallback re-resolves the configured proxy repo (e.g.
    //    `docker-hub-cache`), and the proxy code path (`is_docker_hub`,
    //    `normalize_docker_image`, blob/manifest cache) takes over with
    //    image="library/postgres".
    if repo.is_none() {
        if let Some(mirror_key) = default_docker_mirror_repo() {
            // Don't infinitely recurse: only attempt the fallback when the
            // miss was on a different key than the mirror itself.
            if mirror_key != repo_key {
                if let Some(row) = select_repo_by_key(mirror_key.to_string())
                    .await
                    .map_err(map_db_err)?
                {
                    repo = Some(row);
                    effective_image = image_name.to_string();
                }
            }
        }
    }

    let repo = repo.ok_or_else(|| {
        oci_error(
            StatusCode::NOT_FOUND,
            "NAME_UNKNOWN",
            &format!("repository not found: {}", repo_key),
        )
    })?;

    let location = crate::storage::StorageLocation {
        backend: repo.try_get("storage_backend").map_err(map_db_err)?,
        path: repo.try_get("storage_path").map_err(map_db_err)?,
    };

    Ok(OciRepoInfo {
        id: repo.try_get("id").map_err(map_db_err)?,
        key: repo.try_get("key").map_err(map_db_err)?,
        location,
        repo_type: repo.try_get("repo_type").map_err(map_db_err)?,
        upstream_url: repo.try_get("upstream_url").map_err(map_db_err)?,
        is_public: repo.try_get("is_public").map_err(map_db_err)?,
        image: effective_image,
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

/// Build the list of upstream image names to try when fetching a blob /
/// manifest from a remote member.
///
/// For Docker Hub, official images are only addressable under the
/// `library/` namespace (e.g. `library/alpine`, never bare `alpine`). The
/// previous implementation appended a non-`library/` fallback, which
/// caused every cache-miss against Docker Hub to issue **two** upstream
/// HTTP requests per member: one for `library/alpine`, then one for
/// `alpine`. Reviewer flagged this on PR #1348 (round 1, concern #1).
///
/// The fix is to return a single canonical candidate when the upstream is
/// Docker Hub. For non-Docker-Hub registries (GHCR, ECR, Quay, internal
/// mirrors) we keep the previous behaviour of returning the image
/// verbatim, since those registries do not have a `library/` convention.
fn candidate_upstream_images(image: &str, upstream_url: &str) -> Vec<String> {
    if image.is_empty() {
        return Vec::new();
    }

    if is_docker_hub(upstream_url) {
        // Docker Hub: only the `library/`-normalized form is correct. Trying
        // the bare name as a fallback wastes a round-trip; Docker Hub does
        // not serve official images at `/v2/{name}/...` without the
        // `library/` prefix.
        return vec![normalize_docker_image(image, upstream_url)];
    }

    // Non-Docker-Hub: single candidate, the image as given.
    vec![image.to_string()]
}

/// Format the upstream HTTP path used to fetch a blob from a remote OCI
/// member. Kept as a tiny pure helper so the format is exercised by unit
/// tests without spinning up a wiremock upstream.
///
/// Spec: <https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-blobs>
fn upstream_blob_path(image: &str, digest: &str) -> String {
    format!("v2/{}/blobs/{}", image, digest)
}

/// Format the upstream HTTP path used to fetch a manifest by tag or
/// digest from a remote OCI member.
///
/// Spec: <https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests>
fn upstream_manifest_path(image: &str, reference: &str) -> String {
    format!("v2/{}/manifests/{}", image, reference)
}

/// Pure decision: given a requested `digest` reference and the actual
/// `content` bytes served by an upstream, decide whether to *reject* the
/// response on a digest mismatch.
///
/// Returns `true` only when (a) the requested reference is itself a
/// content-addressable digest, and (b) the SHA-256 of the served bytes
/// does not match it. Tags and other non-digest references always return
/// `false` (nothing to compare against).
///
/// Extracted out of `resolve_virtual_blob` / `resolve_virtual_manifest`
/// for unit-test coverage of the #1348 round-1 security fix without
/// having to stand up a wiremock upstream.
fn upstream_content_violates_digest(reference: &str, content: &[u8]) -> bool {
    is_digest_reference(reference) && compute_sha256(content) != reference
}

/// Positive-sense counterpart to [`upstream_content_violates_digest`].
///
/// Returns `true` when the served `content` is acceptable to forward to the
/// client: either the reference is a human-readable tag (no digest to
/// verify against) or the SHA-256 of the bytes matches the requested
/// content-addressable digest. Returns `false` only on a true digest
/// mismatch, in which case the caller must "fall through" to the next
/// virtual-repo member (or surface a 404).
///
/// Reads at call sites as
/// `if !verify_digest_or_fall_through(content, reference) { continue }`,
/// matching the resolver's existing control flow without the double
/// negative of the older `if upstream_content_violates_digest(..)` form.
/// Kept as a thin wrapper instead of replacing the original so existing
/// call sites + their tests stay stable.
fn verify_digest_or_fall_through(content: &[u8], reference: &str) -> bool {
    !upstream_content_violates_digest(reference, content)
}

/// Where (and how) a virtual-repo blob was found.
///
/// `Local` carries the owning member's full `Repository`, boxed to keep
/// the variant from inflating the enum's discriminant footprint to
/// 336+ bytes when every other variant is ~56 bytes
/// (clippy::large_enum_variant).
pub enum VirtualBlobResolution {
    Local {
        size_bytes: i64,
        storage_key: String,
        member: Box<crate::models::repository::Repository>,
    },
    Remote {
        content: Bytes,
        content_type: Option<String>,
    },
}

/// Pure constructor for the `Local` arm of [`VirtualBlobResolution`].
///
/// Extracted out of [`resolve_virtual_blob`] so the DB-row → enum
/// mapping is exercised by unit tests without spinning up the DB. The
/// resolver's hot path passes `None` when the per-member SELECT misses,
/// and the helper short-circuits that branch the same way the inline
/// code did.
fn local_blob_resolution(
    size_bytes_and_storage_key: Option<(i64, String)>,
    member: &crate::models::repository::Repository,
) -> Option<VirtualBlobResolution> {
    let (size_bytes, storage_key) = size_bytes_and_storage_key?;
    Some(VirtualBlobResolution::Local {
        size_bytes,
        storage_key,
        member: Box::new(member.clone()),
    })
}

/// Pure decision: is a virtual-repo member eligible for upstream
/// delegation on this request?
///
/// Returns `true` only when (a) the member is a remote repo and (b) the
/// proxy service is wired up. Encapsulates the predicate the resolver
/// uses before issuing any upstream HTTP traffic, so the gate is testable
/// without a real `ProxyService`.
fn should_attempt_remote_member(
    member: &crate::models::repository::Repository,
    has_proxy_service: bool,
    has_upstream_url: bool,
) -> bool {
    member.repo_type == RepositoryType::Remote && has_proxy_service && has_upstream_url
}

/// Pure post-processing of a successful upstream blob fetch.
///
/// Returns `Some(VirtualBlobResolution::Remote { .. })` when the
/// upstream bytes match the requested content-addressable digest, and
/// `None` when they do not (the caller must "fall through" to the next
/// virtual-repo member). For blobs the requested reference is always a
/// digest, so the verification is unconditional.
///
/// Extracted out of [`resolve_virtual_blob`] so the security-critical
/// verify-then-wrap step can be unit-tested without a wiremock upstream.
fn finalize_upstream_blob(
    digest: &str,
    content: Bytes,
    content_type: Option<String>,
) -> Option<VirtualBlobResolution> {
    if !verify_digest_or_fall_through(&content, digest) {
        return None;
    }
    Some(VirtualBlobResolution::Remote {
        content,
        content_type,
    })
}

/// Pure post-processing of a successful upstream manifest fetch.
///
/// Returns `Some((computed_digest, content_type, content))` when the
/// upstream bytes are acceptable to forward (tag reference, or the
/// reference is a digest and the SHA-256 matches). Returns `None`
/// when a digest-reference request was answered with bytes whose
/// SHA-256 does not match, signalling the caller to "fall through" to
/// the next virtual-repo member.
///
/// Extracted out of [`resolve_virtual_manifest`] so the verification
/// step and the `compute_sha256`-as-returned-digest behaviour can be
/// unit-tested without a wiremock upstream.
fn finalize_upstream_manifest(
    reference: &str,
    content: Bytes,
    content_type: Option<String>,
) -> Option<(String, Option<String>, Bytes)> {
    if !verify_digest_or_fall_through(&content, reference) {
        return None;
    }
    let computed = compute_sha256(&content);
    Some((computed, content_type, content))
}

// ---------------------------------------------------------------------------
// Virtual-resolution negative cache (#1348 round 1, concern #2)
// ---------------------------------------------------------------------------
//
// `resolve_virtual_blob` / `resolve_virtual_manifest` walk each remote
// member in turn. When a virtual repo has N remote members and none of
// them serve the requested blob (a common case for digest probes from
// Docker pull retries), the resolver issues N upstream HTTP round-trips
// **serially** before returning None, and then the next probe a few ms
// later does it all over again.
//
// To bound the blast radius without changing the resolver's correctness
// for hits, we keep a short-TTL ("a few seconds") in-process negative
// cache keyed by `(repo_id, image, reference)`. Hits short-circuit
// straight to None; the entry expires quickly so a real upstream
// publishing event is not blocked for long.
//
// The cache is intentionally process-local (no Redis, no DB) — it's a
// micro-optimisation, not a correctness primitive. Restarting the
// process or scaling out re-pays the upstream walk once.
const VIRTUAL_NEGATIVE_CACHE_TTL_MS: u64 = 5_000;
const VIRTUAL_NEGATIVE_CACHE_MAX_ENTRIES: usize = 4096;

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
struct VirtualResolveKey {
    repo_id: Uuid,
    kind: VirtualResolveKind,
    image: String,
    reference: String,
}

impl VirtualResolveKey {
    /// Pure constructor. Centralised so call sites do not need to know
    /// the field layout (and so unit tests can pin the construction
    /// without touching the global cache).
    fn new(repo_id: Uuid, kind: VirtualResolveKind, image: &str, reference: &str) -> Self {
        Self {
            repo_id,
            kind,
            image: image.to_string(),
            reference: reference.to_string(),
        }
    }
}

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
enum VirtualResolveKind {
    Blob,
    Manifest,
}

fn virtual_negative_cache(
) -> &'static std::sync::RwLock<std::collections::HashMap<VirtualResolveKey, std::time::Instant>> {
    static CACHE: std::sync::OnceLock<
        std::sync::RwLock<std::collections::HashMap<VirtualResolveKey, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Pure decision: given the wall-clock duration since an entry was
/// inserted and the configured TTL, is the entry still a "hit"?
///
/// Extracted out of `virtual_negative_cache_hit` so the freshness window
/// can be unit-tested without depending on `Instant::now()`.
fn negative_cache_entry_is_fresh(age: std::time::Duration, ttl: std::time::Duration) -> bool {
    age < ttl
}

/// Pure decision: given the current entry count and the configured
/// maximum, should an insertion path attempt to evict expired entries
/// before recording a new one?
///
/// Extracted out of `virtual_negative_cache_insert` so the cap policy
/// is testable without poking at the global cache.
fn negative_cache_should_evict_before_insert(current_len: usize, max_entries: usize) -> bool {
    current_len >= max_entries
}

/// Returns true if a recent resolution attempt for this `(repo_id, kind,
/// image, reference)` returned None, and the entry has not yet expired.
fn virtual_negative_cache_hit(key: &VirtualResolveKey) -> bool {
    let now = std::time::Instant::now();
    let ttl = std::time::Duration::from_millis(VIRTUAL_NEGATIVE_CACHE_TTL_MS);
    let cache = virtual_negative_cache();
    let read = match cache.read() {
        Ok(g) => g,
        Err(_) => return false, // poisoned: behave as miss
    };
    match read.get(key) {
        Some(at) => negative_cache_entry_is_fresh(now.duration_since(*at), ttl),
        None => false,
    }
}

/// Pure cap-and-evict step on a negative-cache map. Returns `true` iff
/// there is room to record a new entry after evicting expired ones; the
/// caller refuses the insert when this returns `false`.
///
/// Extracted out of [`virtual_negative_cache_insert`] so the cap policy
/// (and the precise "evict expired first, refuse insert only if still
/// at cap" semantics) can be unit-tested against an inline `HashMap`
/// without touching the process-global cache.
fn negative_cache_evict_and_has_room<K: Eq + std::hash::Hash>(
    map: &mut std::collections::HashMap<K, std::time::Instant>,
    ttl: std::time::Duration,
    now: std::time::Instant,
    max_entries: usize,
) -> bool {
    if !negative_cache_should_evict_before_insert(map.len(), max_entries) {
        return true;
    }
    map.retain(|_, at| negative_cache_entry_is_fresh(now.duration_since(*at), ttl));
    !negative_cache_should_evict_before_insert(map.len(), max_entries)
}

/// Record a None resolution. Best-effort: lock poisoning silently degrades
/// to "no caching", which is still correct, just slower.
fn virtual_negative_cache_insert(key: VirtualResolveKey) {
    let cache = virtual_negative_cache();
    let mut write = match cache.write() {
        Ok(g) => g,
        Err(_) => return,
    };
    let ttl = std::time::Duration::from_millis(VIRTUAL_NEGATIVE_CACHE_TTL_MS);
    let now = std::time::Instant::now();
    if !negative_cache_evict_and_has_room(&mut write, ttl, now, VIRTUAL_NEGATIVE_CACHE_MAX_ENTRIES)
    {
        return;
    }
    write.insert(key, now);
}

/// Test-only: drop all negative-cache entries. Exposed to the
/// integration test crate so tests can run in any order without
/// stale-cache contamination.
#[doc(hidden)]
pub fn virtual_negative_cache_clear() {
    if let Ok(mut g) = virtual_negative_cache().write() {
        g.clear();
    }
}

/// Walk a virtual OCI repo's members in priority order, returning the
/// first one (local or remote) that serves the requested blob digest.
///
/// Exposed as `pub` so the integration tests in
/// `tests/oci_virtual_resolution_tests.rs` can exercise the real DB +
/// upstream HTTP path. Handlers reach for this via the inline call
/// site, not directly through the public API.
pub async fn resolve_virtual_blob(
    state: &SharedState,
    repo_id: Uuid,
    image_name: &str,
    digest: &str,
) -> Option<VirtualBlobResolution> {
    // #1348 round 1, concern #2: short-circuit when we very recently saw
    // none of the members serve this blob. Bounds the cost of probe
    // storms (e.g. Docker pull retry loops) against a virtual repo with
    // many remote members.
    let cache_key = VirtualResolveKey::new(repo_id, VirtualResolveKind::Blob, image_name, digest);
    if virtual_negative_cache_hit(&cache_key) {
        return None;
    }

    let members = proxy_helpers::fetch_virtual_members(&state.db, repo_id)
        .await
        .ok()?;

    for member in &members {
        let local = sqlx::query!(
            "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
            member.id,
            digest
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|row| (row.size_bytes, row.storage_key));

        if let Some(resolution) = local_blob_resolution(local, member) {
            return Some(resolution);
        }

        if should_attempt_remote_member(
            member,
            state.proxy_service.is_some(),
            member.upstream_url.is_some(),
        ) {
            if let (Some(proxy), Some(upstream_url)) =
                (&state.proxy_service, member.upstream_url.as_deref())
            {
                for image in candidate_upstream_images(image_name, upstream_url) {
                    let upstream_path = upstream_blob_path(&image, digest);
                    if let Ok((content, content_type)) = proxy_helpers::proxy_fetch(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await
                    {
                        // #1348 round 1, concern #3 (digest verification):
                        // for blobs the requested `digest` is always a
                        // content-addressable digest. The verify-and-wrap
                        // step lives in `finalize_upstream_blob` so it
                        // can be unit-tested without a wiremock upstream.
                        match finalize_upstream_blob(digest, content, content_type) {
                            Some(resolution) => return Some(resolution),
                            None => {
                                warn!(
                                    "Virtual blob digest mismatch from upstream {} for {}: refusing to serve",
                                    upstream_url, digest
                                );
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }

    virtual_negative_cache_insert(cache_key);
    None
}

/// Walk a virtual OCI repo's members in priority order, returning the
/// first one (local or remote) that serves the requested manifest.
///
/// When `reference` is itself a content-addressable digest, the upstream
/// body is sha256-verified against the requested digest before being
/// returned (#1348 round 1, concern #3). A mismatch is treated as if
/// that member did not have the manifest, so resolution continues with
/// the next member.
///
/// Exposed as `pub` so the integration tests in
/// `tests/oci_virtual_resolution_tests.rs` can exercise the real DB +
/// upstream HTTP path.
pub async fn resolve_virtual_manifest(
    state: &SharedState,
    repo_id: Uuid,
    image_name: &str,
    reference: &str,
    accept: Option<&str>,
) -> Option<(String, Option<String>, Bytes)> {
    let is_digest_ref = is_digest_reference(reference);

    // #1348 round 1, concern #2: same negative-cache short-circuit as
    // `resolve_virtual_blob`. Tags vs digest references share the cache
    // because tag probes are themselves a common N-member fan-out.
    let cache_key =
        VirtualResolveKey::new(repo_id, VirtualResolveKind::Manifest, image_name, reference);
    if virtual_negative_cache_hit(&cache_key) {
        return None;
    }

    let members = proxy_helpers::fetch_virtual_members(&state.db, repo_id)
        .await
        .ok()?;

    for member in &members {
        let local = if is_digest_ref {
            sqlx::query!(
                "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
                member.id,
                reference
            )
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|row| (row.manifest_digest, Some(row.manifest_content_type)))
        } else {
            sqlx::query!(
                "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
                member.id,
                image_name,
                reference
            )
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|row| (row.manifest_digest, Some(row.manifest_content_type)))
        };

        if let Some((manifest_digest, content_type)) = local {
            let manifest_key = manifest_storage_key(&manifest_digest);
            if let Ok(storage) = state.storage_for_repo(&member.storage_location()) {
                if let Ok(data) = storage.get(&manifest_key).await {
                    return Some((manifest_digest, content_type, data));
                }
            }
        }

        if should_attempt_remote_member(
            member,
            state.proxy_service.is_some(),
            member.upstream_url.is_some(),
        ) {
            if let (Some(proxy), Some(upstream_url)) =
                (&state.proxy_service, member.upstream_url.as_deref())
            {
                for image in candidate_upstream_images(image_name, upstream_url) {
                    let upstream_path = upstream_manifest_path(&image, reference);
                    if let Ok((content, content_type)) = proxy_helpers::proxy_fetch_with_accept(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &upstream_path,
                        accept,
                    )
                    .await
                    {
                        // #1348 round 1, concern #3 (CRITICAL):
                        // When the manifest reference is itself a digest
                        // (e.g. `sha256:abc...`) the client is asserting
                        // content-addressable semantics. A compromised or
                        // misbehaving upstream could otherwise serve
                        // arbitrary bytes under the requested digest.
                        // The verify+compute step lives in
                        // `finalize_upstream_manifest` so it can be unit-
                        // tested without a wiremock upstream.
                        match finalize_upstream_manifest(reference, content, content_type) {
                            Some(triple) => return Some(triple),
                            None => {
                                warn!(
                                    "Virtual manifest digest mismatch from upstream {} for {}: refusing to serve",
                                    upstream_url, reference
                                );
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }

    virtual_negative_cache_insert(cache_key);
    None
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
    .bind(&cached_reference)
    .bind(&digest)
    .bind(&manifest_content_type)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    // #1357 (review feedback): also write a parallel `oci_tags` row keyed by
    // the human-readable tag (the original `reference`) when the caller pulled
    // by tag, not digest. The docker-tag listing in
    // `fetch_docker_tag_rows` filters out rows whose tag contains `:` (via
    // `POSITION(':' IN t.tag) = 0`), so the digest-keyed row written above
    // for remote repos is invisible to the UI. Without this second row the
    // WebUI's Docker tag panel still says "No image tags found" even though
    // the manifest is cached.
    //
    // For local repos `cached_reference == reference`, so this insert is a
    // no-op upsert against the row written above. For remote repos pulled by
    // digest (e.g. `docker pull redis@sha256:...`), there is no human-readable
    // tag to record, so we skip the second insert.
    if repo.repo_type == RepositoryType::Remote && !is_digest_reference(reference) {
        if let Err(e) = sqlx::query(
            r#"INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (repository_id, name, tag) DO UPDATE SET
                 manifest_digest = EXCLUDED.manifest_digest,
                 manifest_content_type = EXCLUDED.manifest_content_type,
                 updated_at = NOW()"#,
        )
        .bind(repo.id)
        .bind(&repo.image)
        .bind(reference)
        .bind(&digest)
        .bind(&manifest_content_type)
        .execute(&state.db)
        .await
        {
            // Best-effort: the digest-keyed oci_tags row above is already
            // persisted, so the manifest still resolves by digest. Only the
            // human-readable tag in the UI listing is degraded.
            tracing::warn!(
                repo = %repo.key,
                image = %repo.image,
                reference = %reference,
                error = %e,
                "Failed to upsert tag-keyed oci_tags row for proxied manifest; \
                 the digest-keyed row is still persisted but the Docker tag UI \
                 listing will not include this tag until the next proxy refresh"
            );
        }
    }

    // #1357: mirror the push-path artifact row so proxied manifests surface
    // in the repository artifact listing and the WebUI's Docker tag grouping.
    //
    // `list_artifacts_grouped_by_docker_tag` (repositories.rs) JOINs
    // `oci_tags` to `artifacts` on
    //     a.path = 'v2/' || t.name || '/manifests/' || t.tag
    // For pushed manifests, `handle_put_manifest` writes both the oci_tags
    // row AND the matching artifacts row, so the JOIN succeeds. For proxied
    // manifests, only the oci_tags row was written -- the JOIN drops the
    // tag and the UI shows "No image tags found" even after a successful
    // `docker pull` through the proxy (#1357).
    //
    // This mirrors the push-path insert at line ~2832: same path shape,
    // same storage_key (`oci-manifests/<digest>` under the per-repo
    // backend), same ON CONFLICT semantics. Critically the storage_key
    // resolves under `storage_for_repo(&repo.location)` -- the same
    // per-repo backend used to write the manifest body above -- so this
    // does NOT reintroduce the #1278 doubled-prefix bug. That bug was
    // specific to `proxy_service::cache_artifact`, which writes to the
    // global `proxy-cache/...` backend; manifests are stored to the
    // per-repo location, so reads through `storage_for_repo` resolve
    // correctly.
    //
    // `total_size` for proxied manifests is the manifest body length.
    // The push path computes config+layers from the parsed manifest, but
    // that requires already-cached blobs; for proxied manifests the body
    // is what we have. The artifact row exists primarily to satisfy the
    // JOIN; downstream byte-accounting uses the oci_tags-driven sizing in
    // `list_artifacts_grouped_by_docker_tag`.
    let checksum = digest.strip_prefix("sha256:").unwrap_or(&digest);
    let size_bytes = content.len() as i64;

    // Write an artifacts row for every distinct oci_tags key that exists.
    // For local repos or remote-by-digest, the digest-keyed and the
    // "cached_reference" key are the same string, so this is a single row.
    // For remote-by-tag, we write TWO artifacts rows -- one at the
    // digest-keyed path (existing behaviour, satisfies the digest-keyed
    // oci_tags row + GC + listing-by-digest), and one at the tag-keyed
    // path so the docker-tag UI JOIN
    //     a.path = 'v2/' || t.name || '/manifests/' || t.tag
    // succeeds for the human-readable tag row that the
    // `POSITION(':' IN t.tag) = 0` filter requires (#1357 review).
    let mut artifact_paths: Vec<String> = Vec::with_capacity(2);
    artifact_paths.push(format!("v2/{}/manifests/{}", repo.image, cached_reference));
    if repo.repo_type == RepositoryType::Remote
        && !is_digest_reference(reference)
        && reference != cached_reference
    {
        artifact_paths.push(format!("v2/{}/manifests/{}", repo.image, reference));
    }

    for artifact_path in &artifact_paths {
        // Use the path's tag segment for the version + name suffix so each
        // row carries a stable identity matching its path; the digest-keyed
        // row keeps the legacy shape and the tag-keyed row reads naturally.
        let row_key = artifact_path
            .rsplit('/')
            .next()
            .unwrap_or(cached_reference.as_str());
        let artifact_name = format!("{}:{}", repo.image, row_key);

        if let Err(e) = sqlx::query(
            r#"INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (repository_id, path) DO UPDATE SET
                 version = EXCLUDED.version,
                 size_bytes = EXCLUDED.size_bytes,
                 checksum_sha256 = EXCLUDED.checksum_sha256,
                 content_type = EXCLUDED.content_type,
                 storage_key = EXCLUDED.storage_key,
                 is_deleted = false,
                 updated_at = NOW()"#,
        )
        .bind(repo.id)
        .bind(artifact_path)
        .bind(&artifact_name)
        .bind(Some(row_key))
        .bind(size_bytes)
        .bind(checksum)
        .bind(&manifest_content_type)
        .bind(&manifest_key)
        .execute(&state.db)
        .await
        {
            // Best-effort: the oci_tags row + manifest body are already
            // persisted, so we never fail the user's pull just because the
            // listing-index row could not be written. The tag still resolves
            // through `oci_tags`; only the UI listing is degraded until the
            // next proxy refresh.
            tracing::warn!(
                repo = %repo.key,
                image = %repo.image,
                reference = %reference,
                artifact_path = %artifact_path,
                error = %e,
                "Failed to upsert artifacts row for proxied manifest; manifest \
                 body and oci_tags row are still persisted, but the repository \
                 artifact listing will not include this tag until the next \
                 proxy refresh succeeds"
            );
        }
    }

    // #1357 (review feedback): for multi-arch image-index manifests, record
    // the (parent_digest -> child_digest) edges so:
    //   1. The storage GC can protect per-architecture children for as long
    //      as the index is still tagged (mirrors the push path #1179 guard).
    //   2. The UI size accounting can walk the index children and report the
    //      true multi-platform total, rather than just the index body size
    //      (which is only a few KB for an image whose children sum to GBs).
    //
    // Best-effort, warn-on-error: matches the push-path semantics in
    // `handle_put_manifest`. The manifest body and oci_tags rows are already
    // persisted; failure here only affects GC/UI accounting until the
    // startup backfill in main.rs runs again.
    if is_index_content_type(&manifest_content_type) {
        if let Err(e) = record_oci_manifest_refs(&state.db, repo.id, &digest, content).await {
            tracing::warn!(
                repo = %repo.key,
                image = %repo.image,
                reference = %reference,
                parent_digest = %digest,
                error = %e,
                "Failed to record oci_manifest_refs for proxied index manifest; \
                 storage GC may treat child manifests as orphaned and the UI \
                 size accounting will under-report multi-arch totals until the \
                 next backfill pass runs"
            );
        }
    }

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
    try_upstream_fetch_with_accept(repo, state, path_suffix, None).await
}

/// Variant of [`try_upstream_fetch`] that forwards the client's `Accept`
/// header to the upstream registry.
///
/// Required for manifest GET/HEAD: OCI registries drive content negotiation
/// off the `Accept` header on the same `manifests/<reference>` URL, so a
/// proxy that strips the header forces the upstream into its default
/// representation. For multi-arch images on Docker Hub that picks the OCI
/// image index, but other registries (Harbor, GHCR with older configs,
/// JFrog) respond with 404 when the requested media type is missing from
/// `Accept`. Forwarding the original header preserves the end-to-end
/// content-negotiation chain and prevents those spurious 404s (#586 cont.).
///
/// Blob fetches pass `None` and exercise the unchanged code path.
async fn try_upstream_fetch_with_accept(
    repo: &OciRepoInfo,
    state: &SharedState,
    path_suffix: &str,
    accept: Option<&str>,
) -> Option<(Bytes, Option<String>)> {
    if repo.repo_type != RepositoryType::Remote {
        return None;
    }
    let upstream_url = repo.upstream_url.as_ref()?;
    let proxy = state.proxy_service.as_ref()?;
    let image = normalize_docker_image(&repo.image, upstream_url);
    let upstream_path = format!("v2/{}/{}", image, path_suffix);
    proxy_helpers::proxy_fetch_with_accept(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        &upstream_path,
        accept,
    )
    .await
    .ok()
}

/// Canonical set of manifest media types we always advertise to an OCI
/// upstream when proxying a manifest fetch.
///
/// Required for ghcr.io interop (#1360): GitHub Container Registry returns
/// `404 not found` for `/v2/<image>/manifests/<ref>` when the request's
/// `Accept` header does not list a media type the stored manifest matches.
/// Stricter than Docker Hub and Quay, which fall back to a default Docker
/// manifest representation when `Accept` is missing or restrictive. Older
/// docker engines, podman, skopeo, buildah, and curl-driven clients all
/// send narrower (or no) `Accept` headers; without supplementing them the
/// proxy surfaces a spurious 404 to the user even though the manifest
/// exists upstream.
///
/// Mirrors the Docker engine 24.x default Accept set plus the OCI image
/// manifest and index types, which together cover every manifest shape an
/// OCI Distribution v1.1 registry can serve.
const OCI_MANIFEST_ACCEPT_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
    "application/vnd.docker.distribution.manifest.v1+json",
];

/// Pre-rendered comma-joined value of [`OCI_MANIFEST_ACCEPT_TYPES`] used
/// when the client supplied no `Accept` header at all.
fn canonical_manifest_accept() -> String {
    OCI_MANIFEST_ACCEPT_TYPES.join(", ")
}

/// Extract a sanitised `Accept` header value suitable for forwarding to an
/// upstream OCI registry.
///
/// Returns `None` when the request did not carry an `Accept`, when the
/// header value is empty, or when it failed UTF-8 validation. Callers
/// should fall through to the no-accept-header path so the upstream
/// applies its default representation rather than refusing the request.
fn forwarded_accept_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Build the `Accept` header value to send upstream for a manifest fetch.
///
/// Combines whatever the client sent with the canonical set of OCI/Docker
/// manifest media types so registries like ghcr.io (which refuse to serve
/// a manifest when the request's `Accept` does not list a media type they
/// can match) always receive a workable header (#1360).
///
/// Rules:
/// * If the client sent no `Accept`, return the canonical list.
/// * If the client sent an `Accept` that already covers every canonical
///   media type, pass it through unchanged so we do not gratuitously
///   reorder a value the client carefully constructed.
/// * Otherwise, append every missing canonical media type to the end of
///   the client's value, preserving the client's preferred order at the
///   front so q-values and primary preferences still win on the upstream
///   side.
///
/// The returned value is always non-empty.
fn manifest_accept_for_upstream(client_accept: Option<&str>) -> String {
    let trimmed = client_accept.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return canonical_manifest_accept();
    }

    // Build a lowercase token set from the client's Accept so we can
    // detect which canonical media types are already covered. Strip the
    // `;q=...` parameters and whitespace; comparison is case-insensitive
    // because RFC 7231 media types are case-insensitive.
    let existing: std::collections::HashSet<String> = trimmed
        .split(',')
        .map(|part| {
            part.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect();

    let mut missing: Vec<&str> = Vec::new();
    for ct in OCI_MANIFEST_ACCEPT_TYPES {
        if !existing.contains(&ct.to_ascii_lowercase()) {
            missing.push(ct);
        }
    }

    if missing.is_empty() {
        return trimmed.to_string();
    }

    format!("{}, {}", trimmed, missing.join(", "))
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
    /// Service the client is requesting a token for. Per the OCI/Distribution
    /// token spec, this must match the `service` value the server advertises
    /// in its `WWW-Authenticate` challenge (`OCI_TOKEN_SERVICE`, hard-coded to
    /// `"artifact-keeper"` at the challenge site). Missing is allowed for
    /// backward compatibility with clients that pre-date the validation.
    service: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
    #[allow(dead_code)]
    account: Option<String>,
}

/// Service identifier the OCI handler advertises in `WWW-Authenticate` and
/// expects to see in the `?service=` query parameter on `/v2/token` (#1175).
/// Kept as a module-level constant so the challenge-building sites and the
/// validation site cannot drift.
const OCI_TOKEN_SERVICE: &str = "artifact-keeper";

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
    Query(query): Query<TokenQuery>,
    body: Bytes,
) -> Response {
    // Per the OCI Distribution token spec, clients must request a token
    // scoped to the same `service` the server advertises. Reject mismatches
    // with 400 DENIED. Allow a missing `service` so curl-style and older
    // Docker clients that omit the query keep working (#1175).
    if let Some(requested) = query.service.as_deref() {
        if requested != OCI_TOKEN_SERVICE {
            return oci_error(StatusCode::BAD_REQUEST, "DENIED", "service mismatch");
        }
    }
    // Credential extraction order, per the OCI Distribution Spec + OAuth2:
    //   1. HTTP Basic Auth header (the original code path; works for `docker
    //      login` / `curl -u`).
    //   2. OAuth2 password-grant form body (Docker's OAuth2 endpoint flow,
    //      `Content-Type: application/x-www-form-urlencoded`,
    //      `username=...&password=...`). Closes #894 ("docker push" to a
    //      private repo failed because Docker uses this flow and the
    //      backend ignored the form body and returned the anonymous token).
    //   3. Existing Bearer token (handler refresh path).
    //   4. Anonymous token (public-pull fallback).
    let credentials = match extract_basic_credentials(&headers)
        .or_else(|| extract_form_credentials(&headers, &body))
    {
        Some(c) => c,
        None => {
            // Also try Bearer token (docker may send existing token).
            // We have to distinguish "no Authorization header at all" from
            // "Authorization header present but validation failed" so that a
            // client holding a revoked/expired/credential-changed JWT gets a
            // 401 instead of silently being downgraded to the anonymous
            // (public-pull) token. The `validate_token` async call now
            // consults the DB credential-change watermark (#1173), so a
            // deactivated user's token fails here too.
            let had_bearer_header = extract_bearer_token(&headers).is_some();
            if let Ok(claims) = validate_token(&state.db, &state.config, &headers).await {
                let auth_service =
                    AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
                // `AND is_active = true` mirrors `auth_service::authenticate`,
                // `refresh_tokens`, and `validate_api_token`: a deactivated
                // user must not be able to swap a still-valid Bearer JWT for
                // a fresh OCI access token, even if the JWT itself hasn't
                // expired and `invalidate_user_tokens` hasn't been called.
                let user = match sqlx::query_as!(
                    crate::models::user::User,
                    r#"SELECT id, username, email, password_hash, display_name,
                       auth_provider as "auth_provider: crate::models::user::AuthProvider",
                       external_id, is_admin, is_active, is_service_account, must_change_password,
                       totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                       failed_login_attempts, locked_until, last_failed_login_at,
                       password_changed_at, last_login_at, created_at, updated_at
                       FROM users WHERE id = $1 AND is_active = true"#,
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

            // If the caller presented a Bearer token but it failed to
            // validate (e.g. credential change on a peer replica, account
            // deactivated), reject with 401 instead of silently downgrading
            // to anonymous. Falling through to anonymous would mask the
            // revocation and hand the caller a usable pull token.
            if had_bearer_header {
                return oci_error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "invalid credentials",
                );
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
    // Try the API-token path first, fall back to username/password.
    //
    // Reverse order — `authenticate(username, api_token)` first — increments
    // `failed_login_attempts` on every CI push that uses an API token in the
    // password field (the standard `docker login -p $API_TOKEN` flow), since
    // bcrypt-comparing the token against the user's password hash always
    // fails. After `account_lockout_threshold` builds the service account
    // locks itself out. `validate_api_token` has no failure-counter side
    // effect, so trying it first keeps the lockout counter accurate while
    // still falling through to bcrypt for actual passwords.
    let (user, tokens, authenticated_via_api_token) =
        match auth_service.validate_api_token(&credentials.1).await {
            Ok(validation) => {
                // TODO: Enforce token scopes and allowed_repo_ids for OCI
                // token exchange. Currently the generated JWT inherits full
                // user privileges regardless of token restrictions.
                if !validation.scopes.is_empty() && !validation.scopes.contains(&"*".to_string()) {
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
            Err(_) => match auth_service
                .authenticate(&credentials.0, &credentials.1)
                .await
            {
                Ok((user, tokens)) => (user, tokens, false),
                Err(_) => {
                    return oci_error(
                        StatusCode::UNAUTHORIZED,
                        "UNAUTHORIZED",
                        "invalid username or password",
                    )
                }
            },
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
    if validate_token(&state.db, &state.config, &headers)
        .await
        .is_ok()
    {
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

/// Canonicalize an inbound blob digest for a local `oci_blobs` lookup.
///
/// Completed uploads persist sha256 digests in canonical lowercase form (the
/// monolithic POST and completion paths both store `Sha256Digest::as_prefixed`),
/// so a pull must look up by that same canonical form to resolve a
/// locally-stored blob regardless of the casing the client put in the URL.
/// A reference that does not parse as a sha256 digest (e.g. a proxy-passthrough
/// reference) is returned unchanged so upstream forwarding is unaffected.
fn canonical_blob_lookup_digest(digest: &str) -> String {
    Sha256Digest::parse_digest_param(digest)
        .map(|d| d.as_prefixed())
        .unwrap_or_else(|_| digest.to_string())
}

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

    // Check oci_blobs table. Look up by the canonical digest so an upper-case
    // pull still resolves a blob stored under its canonical lowercase digest.
    let lookup_digest = canonical_blob_lookup_digest(digest);
    let blob = sqlx::query!(
        "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        repo.id,
        lookup_digest
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
            match storage.exists(&b.storage_key).await {
                Ok(true) => {
                    tracing::debug!(repo = %repo.key, digest = %digest, storage_key = %b.storage_key, "HEAD blob: serving from migrated oci_blobs (CAS hit)");
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header("Docker-Content-Digest", digest)
                        .header(CONTENT_LENGTH, b.size_bytes.to_string())
                        .header(CONTENT_TYPE, "application/octet-stream")
                        .body(Body::empty())
                        .unwrap();
                }
                Ok(false) => {
                    tracing::warn!(repo = %repo.key, digest = %digest, storage_key = %b.storage_key, "HEAD blob: oci_blobs row found but storage file missing - will proxy from upstream");
                }
                Err(e) => {
                    // A transport/auth error from the storage backend must not be
                    // silently downgraded to "blob absent" (which would surface as
                    // a 404). Surface it as an internal error instead, mirroring the
                    // GET-blob path.
                    warn!(repo = %repo.key, digest = %digest, storage_key = %b.storage_key, "HEAD blob: storage.exists failed: {}", e);
                    return oci_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        &e.to_string(),
                    );
                }
            }
        }
        Ok(None) => {
            tracing::debug!(repo = %repo.key, digest = %digest, "HEAD blob: no oci_blobs row - will proxy from upstream");
        }
        Err(e) => {
            warn!("DB error checking blob: {}", e);
        }
    }

    if repo.repo_type == RepositoryType::Virtual {
        if let Some(resolution) = resolve_virtual_blob(state, repo.id, &repo.image, digest).await {
            return match resolution {
                VirtualBlobResolution::Local {
                    size_bytes,
                    storage_key,
                    member,
                } => {
                    let storage = match state.storage_for_repo(&member.storage_location()) {
                        Ok(s) => s,
                        Err(e) => {
                            return oci_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "INTERNAL_ERROR",
                                &e.to_string(),
                            )
                        }
                    };
                    if storage.exists(&storage_key).await.unwrap_or(false) {
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("Docker-Content-Digest", digest)
                            .header(CONTENT_LENGTH, size_bytes.to_string())
                            .header(CONTENT_TYPE, "application/octet-stream")
                            .body(Body::empty())
                            .unwrap()
                    } else {
                        oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found")
                    }
                }
                VirtualBlobResolution::Remote {
                    content,
                    content_type,
                } => build_oci_proxy_response(
                    &content,
                    content_type,
                    digest,
                    "application/octet-stream",
                    false,
                ),
            };
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

    // Look up by the canonical digest so an upper-case pull still resolves a
    // blob stored under its canonical lowercase digest.
    let lookup_digest = canonical_blob_lookup_digest(digest);
    let blob = sqlx::query!(
        "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        repo.id,
        lookup_digest
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
            // Stream the blob straight from the backend instead of buffering the
            // whole (potentially multi-GiB) layer in heap. Content-Length comes
            // from the authoritative oci_blobs.size_bytes column. (#1528)
            match storage.get_stream(&b.storage_key).await {
                Ok(stream) => {
                    tracing::debug!(repo = %repo.key, digest = %digest, storage_key = %b.storage_key, "GET blob: streaming from migrated oci_blobs (CAS hit)");
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header("Docker-Content-Digest", digest)
                        .header(CONTENT_LENGTH, b.size_bytes.to_string())
                        .header(CONTENT_TYPE, "application/octet-stream")
                        .body(Body::from_stream(stream.map(|chunk| {
                            chunk.map_err(|e| std::io::Error::other(e.to_string()))
                        })))
                        .unwrap();
                }
                Err(e) => {
                    warn!(repo = %repo.key, digest = %digest, storage_key = %b.storage_key, "GET blob: oci_blobs row found but storage.get_stream failed - will proxy from upstream: {}", e);
                }
            }
        }
        Ok(None) => {
            tracing::debug!(repo = %repo.key, digest = %digest, "GET blob: no oci_blobs row - will proxy from upstream");
        }
        Err(e) => {
            warn!("DB error reading blob: {}", e);
        }
    }

    if repo.repo_type == RepositoryType::Virtual {
        if let Some(resolution) = resolve_virtual_blob(state, repo.id, &repo.image, digest).await {
            return match resolution {
                VirtualBlobResolution::Local {
                    size_bytes,
                    storage_key,
                    member,
                } => {
                    let storage = match state.storage_for_repo(&member.storage_location()) {
                        Ok(s) => s,
                        Err(e) => {
                            return oci_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "INTERNAL_ERROR",
                                &e.to_string(),
                            )
                        }
                    };
                    // Stream rather than buffer the resolved member blob. (#1528)
                    match storage.get_stream(&storage_key).await {
                        Ok(stream) => Response::builder()
                            .status(StatusCode::OK)
                            .header("Docker-Content-Digest", digest)
                            .header(CONTENT_LENGTH, size_bytes.to_string())
                            .header(CONTENT_TYPE, "application/octet-stream")
                            .body(Body::from_stream(stream.map(|chunk| {
                                chunk.map_err(|e| std::io::Error::other(e.to_string()))
                            })))
                            .unwrap(),
                        Err(e) => {
                            warn!("Storage error streaming virtual blob {}: {}", digest, e);
                            oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found")
                        }
                    }
                }
                VirtualBlobResolution::Remote {
                    content,
                    content_type,
                } => build_oci_proxy_response(
                    &content,
                    content_type,
                    digest,
                    "application/octet-stream",
                    true,
                ),
            };
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
    body: Body,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let (claims, token_scopes) =
        match authenticate_oci_with_scopes(&state.db, &state.config, headers).await {
            Ok(c) => c,
            Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
        };
    // GHSA-vvc3-h39c-mrq5: a read-scoped API token must not be accepted
    // for an OCI blob upload (`docker push`). Enforce the write scope.
    if !oci_scopes_grant(&token_scopes, "write") {
        return oci_forbidden_scope("write");
    }

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let repo_id = repo.id;
    let location = repo.location;

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

    // Monolithic upload: if digest is provided, stream to an upload key first.
    // The final blob key is digest-global, so it must not be overwritten until
    // the request body has been verified against the provided digest.
    if let Some(digest) = query_digest {
        // Validate the digest syntax BEFORE streaming the body to storage, so a
        // malformed `?digest=` is rejected immediately instead of paying for a
        // full (potentially multi-GiB) write that is then discarded.
        let provided_digest = match Sha256Digest::parse_digest_param(digest) {
            Ok(d) => d,
            Err(e) => return oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", &e),
        };
        let upload_id = Uuid::new_v4();
        let temp_key = upload_storage_key(&upload_id);
        if let Err(resp) =
            register_oci_upload_cleanup_key(&state.db, repo_id, None, &temp_key).await
        {
            return resp;
        }
        let put_result = match put_request_body_stream(
            &storage,
            &temp_key,
            body,
            0,
            state.config.max_upload_size_bytes,
        )
        .await
        {
            Ok(r) => r,
            Err(resp) => return resp,
        };
        if let Err(resp) = mark_oci_upload_cleanup_key_committed(&state.db, &temp_key).await {
            delete_storage_key_best_effort(&storage, &temp_key, "monolithic cleanup mark failed")
                .await;
            return resp;
        }
        let computed = match Sha256Digest::from_hex(&put_result.checksum_sha256) {
            Ok(d) => d,
            Err(e) => {
                delete_storage_key_best_effort(
                    &storage,
                    &temp_key,
                    "monolithic checksum decode failed",
                )
                .await;
                return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e);
            }
        };
        // Syntax was validated up front; here we only compare the already-parsed
        // client digest against the digest computed from the streamed bytes.
        if provided_digest != computed {
            delete_storage_key_best_effort(&storage, &temp_key, "monolithic digest mismatch").await;
            return oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                &format!(
                    "digest mismatch: computed {} != provided {}",
                    computed.as_prefixed(),
                    digest
                ),
            );
        }

        // Persist under the canonical digest derived from the streamed bytes,
        // never the raw `digest` query param. `Sha256Digest` accepts upper-case
        // hex and normalizes it to lowercase, so the verified `computed` value
        // can differ byte-for-byte from `digest`; binding the raw param would
        // store the blob under a key/row that a later canonical lookup misses.
        let canonical_digest = computed.as_prefixed();
        let key = blob_storage_key(&canonical_digest);

        if let Err(e) = storage.copy(&temp_key, &key).await {
            delete_storage_key_best_effort(&storage, &temp_key, "monolithic blob copy failed")
                .await;
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "BLOB_UPLOAD_UNKNOWN",
                &e.to_string(),
            );
        }

        // Record in oci_blobs
        if let Err(e) = sqlx::query!(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4) ON CONFLICT (repository_id, digest) DO NOTHING",
            repo_id, canonical_digest.as_str(), put_result.bytes_written as i64, key
        )
        .execute(&state.db)
        .await
        {
            delete_storage_key_best_effort(&storage, &temp_key, "monolithic blob row insert failed")
                .await;
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            );
        }

        delete_storage_key_best_effort(&storage, &temp_key, "monolithic upload completed").await;

        return Response::builder()
            .status(StatusCode::CREATED)
            .header(
                LOCATION,
                format!("/v2/{}/blobs/{}", image_name, canonical_digest),
            )
            .header("Docker-Content-Digest", canonical_digest.as_str())
            .header(CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap();
    }

    // Create upload session
    let session_id = Uuid::new_v4();
    let temp_key = upload_storage_key(&session_id);
    if let Err(resp) =
        register_oci_upload_cleanup_key(&state.db, repo_id, Some(session_id), &temp_key).await
    {
        return resp;
    }
    let put_result = match put_request_body_stream(
        &storage,
        &temp_key,
        body,
        0,
        state.config.max_upload_size_bytes,
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = mark_oci_upload_cleanup_key_committed(&state.db, &temp_key).await {
        delete_storage_key_best_effort(&storage, &temp_key, "upload session cleanup mark failed")
            .await;
        return resp;
    }

    let bytes_received = put_result.bytes_written as i64;
    let computed_digest = if bytes_received > 0 {
        match Sha256Digest::from_hex(&put_result.checksum_sha256) {
            Ok(d) => Some(d),
            Err(e) => {
                delete_storage_key_best_effort(
                    &storage,
                    &temp_key,
                    "upload session checksum decode failed",
                )
                .await;
                return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e);
            }
        }
    } else {
        None
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            delete_storage_key_best_effort(&storage, &temp_key, "upload session begin failed")
                .await;
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            );
        }
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key, computed_digest) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(session_id)
    .bind(repo_id)
    .bind(claims.sub)
    .bind(bytes_received)
    .bind(&temp_key)
    .bind(computed_digest.as_ref().map(Sha256Digest::as_prefixed))
    .execute(&mut *tx)
    .await
    {
        delete_storage_key_best_effort(&storage, &temp_key, "upload session insert failed").await;
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
    }
    if let Some(part_digest) = computed_digest.as_ref() {
        // `computed_digest` is Some exactly when bytes_received > 0, i.e. a real
        // first part was streamed. digest_sha256 stores bare hex.
        if let Err(e) = sqlx::query(
            "INSERT INTO oci_upload_parts (upload_session_id, part_index, storage_key, size_bytes, digest_sha256) VALUES ($1, 0, $2, $3, $4)",
        )
        .bind(session_id)
        .bind(&temp_key)
        .bind(bytes_received)
        .bind(part_digest.as_hex())
        .execute(&mut *tx)
        .await
        {
            delete_storage_key_best_effort(&storage, &temp_key, "initial upload part insert failed")
                .await;
            return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
        }
    }
    if let Err(e) = tx.commit().await {
        warn!(
            session_id = %session_id,
            storage_key = %temp_key,
            "OCI upload session commit failed after storage write; leaving temp object for scheduled OCI upload cleanup because COMMIT outcome may be ambiguous"
        );
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        );
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
        .header("Range", upload_progress_range(bytes_received))
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

async fn handle_patch_upload(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    uuid_str: &str,
    body: Body,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let (claims, token_scopes) =
        match authenticate_oci_with_scopes(&state.db, &state.config, headers).await {
            Ok(c) => c,
            Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
        };
    let _ = claims;
    // GHSA-vvc3-h39c-mrq5: PATCH on an upload session is a write operation.
    if !oci_scopes_grant(&token_scopes, "write") {
        return oci_forbidden_scope("write");
    }

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

    // Resolve repo from URL first, then bind it into the session lookup so a
    // session created against repo A cannot be driven via repo B's URL
    // (issue #1317). Same 404 shape for "no session" and "session in another
    // repo" avoids leaking session existence across repos.
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

    let session = match fetch_oci_upload_session(&state.db, session_id, repo.id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "upload session not found",
            )
        }
        Err(resp) => return resp,
    };
    if session.state != UploadSessionState::Open {
        return upload_session_conflict("upload session is not open for PATCH");
    }
    if let Some(resp) = validate_patch_content_range(headers, session.bytes_received) {
        return resp;
    }

    let body_limit =
        upload_session_body_limit(session.bytes_received, state.config.max_upload_size_bytes);
    if let Some(resp) =
        reject_oversized_content_length(headers, body_limit, state.config.max_upload_size_bytes)
    {
        return resp;
    }

    let part_index = if session.bytes_received == 0 && session.part_count == 0 {
        0
    } else if session.part_count == 0 {
        1
    } else {
        session.part_count as i32
    };
    let part_key = upload_part_storage_key(&session.storage_temp_key, part_index, &Uuid::new_v4());
    if let Err(resp) =
        register_oci_upload_cleanup_key(&state.db, repo.id, Some(session_id), &part_key).await
    {
        return resp;
    }

    let put_result = match put_request_body_stream(
        &storage,
        &part_key,
        body,
        session.bytes_received as u64,
        state.config.max_upload_size_bytes,
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = mark_oci_upload_cleanup_key_committed(&state.db, &part_key).await {
        delete_storage_key_best_effort(&storage, &part_key, "PATCH cleanup mark failed").await;
        return resp;
    }
    let incoming_bytes = put_result.bytes_written as i64;
    let new_bytes = session.bytes_received + incoming_bytes;
    let computed_digest = if session.bytes_received == 0 && part_index == 0 {
        match Sha256Digest::from_hex(&put_result.checksum_sha256) {
            Ok(d) => Some(d),
            Err(e) => {
                delete_storage_key_best_effort(&storage, &part_key, "PATCH checksum decode failed")
                    .await;
                return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e);
            }
        }
    } else {
        None
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            delete_storage_key_best_effort(&storage, &part_key, "PATCH transaction begin failed")
                .await;
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            );
        }
    };

    if session.part_count == 0 && session.bytes_received > 0 {
        if let Err(e) = sqlx::query(
            // Migration 117 makes digest_sha256 nullable: the synthesized legacy
            // first part has no honest per-part SHA-256, so store NULL rather than
            // the dishonest '' sentinel.
            "INSERT INTO oci_upload_parts (upload_session_id, part_index, storage_key, size_bytes, digest_sha256) VALUES ($1, 0, $2, $3, NULL) ON CONFLICT (upload_session_id, part_index) DO NOTHING",
        )
        .bind(session_id)
        .bind(&session.storage_temp_key)
        .bind(session.bytes_received)
        .execute(&mut *tx)
        .await
        {
            delete_storage_key_best_effort(&storage, &part_key, "legacy first part backfill failed")
                .await;
            return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
        }
    }

    if let Err(e) = sqlx::query(
        "INSERT INTO oci_upload_parts (upload_session_id, part_index, storage_key, size_bytes, digest_sha256) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(session_id)
    .bind(part_index)
    .bind(&part_key)
    .bind(incoming_bytes)
    .bind(&put_result.checksum_sha256)
    .execute(&mut *tx)
    .await
    {
        delete_storage_key_best_effort(&storage, &part_key, "PATCH part insert failed").await;
        if is_pg_unique_violation(&e) {
            return upload_session_conflict("upload session changed while PATCH body was streaming");
        }
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
    }

    let update_result = match sqlx::query(
        "UPDATE oci_upload_sessions SET bytes_received = $3, computed_digest = $4, updated_at = NOW() WHERE id = $1 AND repository_id = $2 AND state = $6 AND bytes_received = $5",
    )
    .bind(session_id)
    .bind(repo.id)
    .bind(new_bytes)
    .bind(computed_digest.as_ref().map(Sha256Digest::as_prefixed))
    .bind(session.bytes_received)
    .bind(UploadSessionState::Open.as_str())
    .execute(&mut *tx)
    .await
    {
        Ok(result) => result,
        Err(e) => {
            delete_storage_key_best_effort(&storage, &part_key, "PATCH session update failed").await;
            return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
        }
    };
    if update_result.rows_affected() != 1 {
        delete_storage_key_best_effort(&storage, &part_key, "PATCH optimistic update lost").await;
        return upload_session_conflict("upload session changed while PATCH body was streaming");
    }
    if let Err(e) = tx.commit().await {
        warn!(
            session_id = %session_id,
            storage_key = %part_key,
            "OCI upload PATCH commit failed after storage write; leaving part object for scheduled OCI upload cleanup because COMMIT outcome may be ambiguous"
        );
        match recover_committed_patch_after_commit_error(
            &state.db,
            session_id,
            repo.id,
            part_index,
            &part_key,
            new_bytes,
            incoming_bytes,
        )
        .await
        {
            Ok(true) => {
                warn!(
                    session_id = %session_id,
                    storage_key = %part_key,
                    bytes_received = new_bytes,
                    "Recovered committed OCI upload PATCH after COMMIT returned an error"
                );
                return upload_patch_accepted_response(image_name, session_id, new_bytes);
            }
            Ok(false) => {
                delete_storage_key_best_effort(
                    &storage,
                    &part_key,
                    "PATCH commit failed and DB recovery found no committed part",
                )
                .await;
            }
            Err(resp) => return resp,
        }
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        );
    }

    upload_patch_accepted_response(image_name, session_id, new_bytes)
}

async fn handle_cancel_upload(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    uuid_str: &str,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let (claims, token_scopes) =
        match authenticate_oci_with_scopes(&state.db, &state.config, headers).await {
            Ok(c) => c,
            Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
        };
    let _ = claims;
    if !oci_scopes_grant(&token_scopes, "write") {
        return oci_forbidden_scope("write");
    }

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

    let cancel_state_token = Uuid::new_v4();
    let session_row = match sqlx::query(
        r#"
        UPDATE oci_upload_sessions
        SET state = $4, state_token = $3, updated_at = NOW()
        WHERE id = $1 AND repository_id = $2
          AND state = $5
        RETURNING storage_temp_key
        "#,
    )
    .bind(session_id)
    .bind(repo.id)
    .bind(cancel_state_token)
    .bind(UploadSessionState::Committing.as_str())
    .bind(UploadSessionState::Open.as_str())
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return match sqlx::query(
                "SELECT state FROM oci_upload_sessions WHERE id = $1 AND repository_id = $2",
            )
            .bind(session_id)
            .bind(repo.id)
            .fetch_optional(&state.db)
            .await
            {
                Ok(Some(_)) => upload_session_conflict("upload session is already being modified"),
                Ok(None) => oci_error(
                    StatusCode::NOT_FOUND,
                    "BLOB_UPLOAD_UNKNOWN",
                    "upload session not found",
                ),
                Err(e) => oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    &e.to_string(),
                ),
            };
        }
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            );
        }
    };
    let storage_temp_key = match session_row.try_get::<String, _>("storage_temp_key") {
        Ok(key) => key,
        Err(e) => {
            if let Err(reset_resp) =
                reset_oci_upload_session_state(&state.db, session_id, repo.id, cancel_state_token)
                    .await
            {
                return reset_resp;
            }
            return oci_internal_error(&row_decode_error(
                "invalid oci_upload_sessions.storage_temp_key",
                e,
            ));
        }
    };

    let part_rows = match sqlx::query(
        "SELECT storage_key FROM oci_upload_parts WHERE upload_session_id = $1 ORDER BY part_index",
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            if let Err(reset_resp) =
                reset_oci_upload_session_state(&state.db, session_id, repo.id, cancel_state_token)
                    .await
            {
                return reset_resp;
            }
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            );
        }
    };
    let mut cleanup_keys = Vec::with_capacity(part_rows.len() + 1);
    cleanup_keys.push(storage_temp_key);
    for row in part_rows {
        match row.try_get::<String, _>("storage_key") {
            Ok(key) => cleanup_keys.push(key),
            Err(e) => {
                if let Err(reset_resp) = reset_oci_upload_session_state(
                    &state.db,
                    session_id,
                    repo.id,
                    cancel_state_token,
                )
                .await
                {
                    return reset_resp;
                }
                return oci_internal_error(&row_decode_error(
                    "invalid oci_upload_parts.storage_key",
                    e,
                ));
            }
        }
    }
    cleanup_keys.sort();
    cleanup_keys.dedup();

    // Once we start deleting parts we must NOT reset the session back to `open`:
    // a partial delete would leave it resumable with some part objects already
    // gone (a wedged, holed session). Leave it in `committing` — PATCH rejects a
    // non-open session and the abandoned-session GC sweep reaps it — and surface
    // the error so the client retries the cancel. Every key is in the cleanup
    // journal, so storage GC reclaims whatever was already deleted or remains.
    for key in &cleanup_keys {
        if let Err(resp) = delete_storage_key_for_upload_cancel(&storage, key, session_id).await {
            return resp;
        }
    }

    let deleted = match sqlx::query(
        "DELETE FROM oci_upload_sessions WHERE id = $1 AND repository_id = $2 AND state = $4 AND state_token = $3",
    )
    .bind(session_id)
    .bind(repo.id)
    .bind(cancel_state_token)
    .bind(UploadSessionState::Committing.as_str())
    .execute(&state.db)
    .await
    {
        Ok(result) => result.rows_affected(),
        Err(e) => {
            if let Err(reset_resp) =
                reset_oci_upload_session_state(&state.db, session_id, repo.id, cancel_state_token)
                    .await
            {
                return reset_resp;
            }
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            );
        }
    };
    if deleted != 1 {
        if let Err(reset_resp) =
            reset_oci_upload_session_state(&state.db, session_id, repo.id, cancel_state_token).await
        {
            return reset_resp;
        }
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "upload session vanished during cancel",
        );
    }

    Response::builder()
        .status(StatusCode::NO_CONTENT)
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
    body: Body,
) -> Response {
    let host = request_host(headers);
    let scope = push_scope(image_name);
    let (claims, token_scopes) =
        match authenticate_oci_with_scopes(&state.db, &state.config, headers).await {
            Ok(c) => c,
            Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
        };
    let _ = claims;
    // GHSA-vvc3-h39c-mrq5: completing an upload session writes the blob.
    if !oci_scopes_grant(&token_scopes, "write") {
        return oci_forbidden_scope("write");
    }

    let requested_digest = match digest_query {
        Some(d) => match Sha256Digest::parse_digest_param(d) {
            Ok(d) => d,
            Err(e) => return oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", &e),
        },
        None => {
            return oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "digest query parameter required",
            )
        }
    };
    // Canonical prefixed form used for downstream binds (oci_blobs.digest),
    // storage keys, recovery and response headers — byte-identical to the
    // previous wire representation.
    let digest = requested_digest.as_prefixed();

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

    // Resolve repo from URL first, then bind it into the session lookup so a
    // session created against repo A cannot be completed via repo B's URL
    // (issue #1317).
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

    let completion_state_token = Uuid::new_v4();
    let session = match claim_oci_upload_session_for_completion(
        &state.db,
        session_id,
        repo.id,
        completion_state_token,
    )
    .await
    {
        Ok(Some(session)) => session,
        Ok(None) => match fetch_oci_upload_session(&state.db, session_id, repo.id).await {
            Ok(Some(_)) => {
                return upload_session_conflict("upload session is already being modified")
            }
            Ok(None) => {
                return oci_error(
                    StatusCode::NOT_FOUND,
                    "BLOB_UPLOAD_UNKNOWN",
                    "upload session not found",
                )
            }
            Err(resp) => return resp,
        },
        Err(resp) => return resp,
    };
    let completion_heartbeat = start_oci_upload_completion_heartbeat(
        state.db.clone(),
        session_id,
        session.repository_id,
        completion_state_token,
    );

    let final_body_limit =
        upload_session_body_limit(session.bytes_received, state.config.max_upload_size_bytes);
    if let Some(resp) = reject_oversized_content_length(
        headers,
        final_body_limit,
        state.config.max_upload_size_bytes,
    ) {
        if let Err(reset_resp) = reset_oci_upload_session_state(
            &state.db,
            session_id,
            session.repository_id,
            completion_state_token,
        )
        .await
        {
            return reset_resp;
        }
        return resp;
    }

    let final_part_key =
        upload_part_storage_key(&session.storage_temp_key, i32::MAX, &Uuid::new_v4());
    let final_part = if body.size_hint().exact() == Some(0) {
        None
    } else {
        if let Err(resp) = register_oci_upload_cleanup_key(
            &state.db,
            session.repository_id,
            Some(session_id),
            &final_part_key,
        )
        .await
        {
            if let Err(reset_resp) = reset_oci_upload_session_state(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await
            {
                return reset_resp;
            }
            return resp;
        }
        match put_request_body_stream(
            &storage,
            &final_part_key,
            body,
            session.bytes_received as u64,
            state.config.max_upload_size_bytes,
        )
        .await
        {
            Ok(result) => {
                if let Err(resp) =
                    mark_oci_upload_cleanup_key_committed(&state.db, &final_part_key).await
                {
                    delete_storage_key_best_effort(
                        &storage,
                        &final_part_key,
                        "final upload part cleanup mark failed",
                    )
                    .await;
                    if let Err(reset_resp) = reset_oci_upload_session_state(
                        &state.db,
                        session_id,
                        session.repository_id,
                        completion_state_token,
                    )
                    .await
                    {
                        return reset_resp;
                    }
                    return resp;
                }
                Some((
                    OciUploadPartRecord {
                        storage_key: final_part_key.clone(),
                        size_bytes: result.bytes_written as i64,
                    },
                    result.checksum_sha256,
                ))
            }
            Err(resp) => {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "final upload part stream failed",
                )
                .await;
                if let Err(reset_resp) = reset_oci_upload_session_state(
                    &state.db,
                    session_id,
                    session.repository_id,
                    completion_state_token,
                )
                .await
                {
                    return reset_resp;
                }
                return resp;
            }
        }
    };
    if !completion_heartbeat.lease_is_valid() {
        if final_part.is_some() {
            delete_storage_key_best_effort(
                &storage,
                &final_part_key,
                "completion lease lost after final part upload",
            )
            .await;
        }
        return completion_lease_lost_after_reset(
            &state.db,
            session_id,
            session.repository_id,
            completion_state_token,
        )
        .await;
    }

    let mut parts = match fetch_oci_upload_parts(
        &state.db,
        session_id,
        &session.storage_temp_key,
        session.bytes_received,
    )
    .await
    {
        Ok(parts) => parts,
        Err(resp) => {
            if final_part.is_some() {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "fetch upload parts failed",
                )
                .await;
            }
            if let Err(reset_resp) = reset_oci_upload_session_state(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await
            {
                return reset_resp;
            }
            return resp;
        }
    };
    if let Some((part, _checksum)) = final_part.as_ref() {
        parts.push(part.clone());
    }
    let size_bytes: i64 = parts.iter().map(|part| part.size_bytes).sum();
    let blob_key = blob_storage_key(&digest);

    // Single-part fast path: one streamed part whose digest was already computed
    // and cached during PATCH/POST and already equals the client's requested
    // digest. Promote it to the blob key with a server-side `copy()`, skipping
    // the concatenate-and-rehash that the multi-part `else` branch performs (the
    // bytes have not changed, so re-reading them to recompute the digest would
    // be redundant). All three conditions are required: a non-empty final PUT
    // body, a part count other than exactly one, or a stale/absent cached digest
    // must fall through to the re-verifying path.
    if final_part.is_none()
        && parts.len() == 1
        && session.computed_digest.as_ref() == Some(&requested_digest)
    {
        if !completion_heartbeat.lease_is_valid() {
            return completion_lease_lost_after_reset(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await;
        }
        if let Err(e) = storage.copy(&parts[0].storage_key, &blob_key).await {
            if let Err(reset_resp) = reset_oci_upload_session_state(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await
            {
                return reset_resp;
            }
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "BLOB_UPLOAD_UNKNOWN",
                &e.to_string(),
            );
        }
    } else {
        if final_part.is_none() {
            if let Some(computed) = session.computed_digest.as_ref() {
                if computed != &requested_digest {
                    if let Err(reset_resp) = reset_oci_upload_session_state(
                        &state.db,
                        session_id,
                        session.repository_id,
                        completion_state_token,
                    )
                    .await
                    {
                        return reset_resp;
                    }
                    return oci_error(
                        StatusCode::BAD_REQUEST,
                        "DIGEST_INVALID",
                        &format!(
                            "digest mismatch: computed {} != provided {}",
                            computed.as_prefixed(),
                            digest
                        ),
                    );
                }
            }
        }

        // The concatenated completion object is never recorded in
        // `oci_upload_parts`, so the abandoned-session sweep (which only walks
        // `storage_temp_key` + part keys) cannot reclaim it. Its *only* cleanup
        // path is the `oci_upload_cleanup_keys` journal, so this register MUST
        // stay ordered before the `put_stream` below — never reorder it after.
        let completion_temp_key =
            format!("{}.complete.{}", session.storage_temp_key, Uuid::new_v4());
        if let Err(resp) = register_oci_upload_cleanup_key(
            &state.db,
            session.repository_id,
            Some(session_id),
            &completion_temp_key,
        )
        .await
        {
            if final_part.is_some() {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "completion cleanup registration failed",
                )
                .await;
            }
            if let Err(reset_resp) = reset_oci_upload_session_state(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await
            {
                return reset_resp;
            }
            return resp;
        }
        if !completion_heartbeat.lease_is_valid() {
            if final_part.is_some() {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "completion lease lost before concatenating parts",
                )
                .await;
            }
            return completion_lease_lost_after_reset(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await;
        }
        let concat_stream = storage_concat_stream(Arc::clone(&storage), parts.clone());
        let put_result = match storage
            .put_stream(&completion_temp_key, concat_stream)
            .await
        {
            Ok(result) => {
                if let Err(resp) =
                    mark_oci_upload_cleanup_key_committed(&state.db, &completion_temp_key).await
                {
                    delete_storage_key_best_effort(
                        &storage,
                        &completion_temp_key,
                        "completion temp cleanup mark failed",
                    )
                    .await;
                    if final_part.is_some() {
                        delete_storage_key_best_effort(
                            &storage,
                            &final_part_key,
                            "completion temp cleanup mark failed",
                        )
                        .await;
                    }
                    if let Err(reset_resp) = reset_oci_upload_session_state(
                        &state.db,
                        session_id,
                        session.repository_id,
                        completion_state_token,
                    )
                    .await
                    {
                        return reset_resp;
                    }
                    return resp;
                }
                result
            }
            Err(e) => {
                if final_part.is_some() {
                    delete_storage_key_best_effort(
                        &storage,
                        &final_part_key,
                        "completion concat stream failed",
                    )
                    .await;
                }
                if let Err(reset_resp) = reset_oci_upload_session_state(
                    &state.db,
                    session_id,
                    session.repository_id,
                    completion_state_token,
                )
                .await
                {
                    return reset_resp;
                }
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "BLOB_UPLOAD_UNKNOWN",
                    &e.to_string(),
                );
            }
        };
        if !completion_heartbeat.lease_is_valid() {
            delete_storage_key_best_effort(
                &storage,
                &completion_temp_key,
                "completion lease lost after concatenating parts",
            )
            .await;
            if final_part.is_some() {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "completion lease lost after concatenating parts",
                )
                .await;
            }
            return completion_lease_lost_after_reset(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await;
        }
        let computed = match Sha256Digest::from_hex(&put_result.checksum_sha256) {
            Ok(d) => d,
            Err(e) => {
                delete_storage_key_best_effort(
                    &storage,
                    &completion_temp_key,
                    "completion checksum decode failed",
                )
                .await;
                if final_part.is_some() {
                    delete_storage_key_best_effort(
                        &storage,
                        &final_part_key,
                        "completion checksum decode failed",
                    )
                    .await;
                }
                if let Err(reset_resp) = reset_oci_upload_session_state(
                    &state.db,
                    session_id,
                    session.repository_id,
                    completion_state_token,
                )
                .await
                {
                    return reset_resp;
                }
                return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e);
            }
        };
        if computed != requested_digest {
            delete_storage_key_best_effort(
                &storage,
                &completion_temp_key,
                "completion digest mismatch",
            )
            .await;
            if final_part.is_some() {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "completion digest mismatch",
                )
                .await;
            }
            if let Err(reset_resp) = reset_oci_upload_session_state(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await
            {
                return reset_resp;
            }
            return oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                &format!(
                    "digest mismatch: computed {} != provided {}",
                    computed.as_prefixed(),
                    digest
                ),
            );
        }
        if let Err(e) = storage.copy(&completion_temp_key, &blob_key).await {
            delete_storage_key_best_effort(
                &storage,
                &completion_temp_key,
                "completion blob copy failed",
            )
            .await;
            if final_part.is_some() {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "completion blob copy failed",
                )
                .await;
            }
            if let Err(reset_resp) = reset_oci_upload_session_state(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await
            {
                return reset_resp;
            }
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "BLOB_UPLOAD_UNKNOWN",
                &e.to_string(),
            );
        }
        delete_storage_key_best_effort(&storage, &completion_temp_key, "completion temp promoted")
            .await;
    }
    // Last fast-fail before the commit transaction. This atomic flag is only an
    // optimization: it is NOT re-checked across `tx.begin()`/`tx.commit()`
    // below. The authoritative lease guard is the `state_token` predicate on the
    // terminal DELETE — if the lease was stolen in the meantime the DELETE
    // touches 0 rows and the transaction rolls back. Do not "simplify away" that
    // predicate believing this check suffices.
    if !completion_heartbeat.lease_is_valid() {
        if final_part.is_some() {
            delete_storage_key_best_effort(
                &storage,
                &final_part_key,
                "completion lease lost before DB commit",
            )
            .await;
        }
        return completion_lease_lost_after_reset(
            &state.db,
            session_id,
            session.repository_id,
            completion_state_token,
        )
        .await;
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            if final_part.is_some() {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "completion DB begin failed",
                )
                .await;
            }
            if let Err(reset_resp) = reset_oci_upload_session_state(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await
            {
                return reset_resp;
            }
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            );
        }
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4) ON CONFLICT (repository_id, digest) DO NOTHING",
    )
    .bind(session.repository_id)
    .bind(&digest)
    .bind(size_bytes)
    .bind(&blob_key)
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        if final_part.is_some() {
            delete_storage_key_best_effort(&storage, &final_part_key, "oci_blobs insert failed")
                .await;
        }
        if let Err(reset_resp) = reset_oci_upload_session_state(
            &state.db,
            session_id,
            session.repository_id,
            completion_state_token,
        )
        .await
        {
            return reset_resp;
        }
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
    }

    let deleted = match sqlx::query(
        "DELETE FROM oci_upload_sessions WHERE id = $1 AND repository_id = $2 AND state = $4 AND state_token = $3",
    )
    .bind(session_id)
    .bind(session.repository_id)
    .bind(completion_state_token)
    .bind(UploadSessionState::Committing.as_str())
    .execute(&mut *tx)
    .await
    {
        Ok(result) => result.rows_affected(),
        Err(e) => {
            let _ = tx.rollback().await;
            if final_part.is_some() {
                delete_storage_key_best_effort(
                    &storage,
                    &final_part_key,
                    "upload session delete failed",
                )
                .await;
            }
            if let Err(reset_resp) = reset_oci_upload_session_state(
                &state.db,
                session_id,
                session.repository_id,
                completion_state_token,
            )
            .await
            {
                return reset_resp;
            }
            return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
        }
    };
    if deleted != 1 {
        let _ = tx.rollback().await;
        if final_part.is_some() {
            delete_storage_key_best_effort(
                &storage,
                &final_part_key,
                "upload session vanished during completion",
            )
            .await;
        }
        if let Err(reset_resp) = reset_oci_upload_session_state(
            &state.db,
            session_id,
            session.repository_id,
            completion_state_token,
        )
        .await
        {
            return reset_resp;
        }
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "upload session vanished during completion",
        );
    }
    if let Err(e) = tx.commit().await {
        match recover_committed_completion_after_commit_error(
            &state.db,
            session_id,
            session.repository_id,
            &digest,
            size_bytes,
            &blob_key,
        )
        .await
        {
            Ok(true) => {
                let mut cleanup_keys: Vec<String> =
                    parts.iter().map(|part| part.storage_key.clone()).collect();
                cleanup_keys.push(session.storage_temp_key.clone());
                cleanup_keys.sort();
                cleanup_keys.dedup();
                for key in cleanup_keys {
                    delete_storage_key_best_effort(
                        &storage,
                        &key,
                        "upload completed after commit recovery",
                    )
                    .await;
                }
                warn!(
                    session_id = %session_id,
                    digest = %digest,
                    size_bytes,
                    "Recovered committed OCI upload completion after COMMIT returned an error"
                );
                return upload_complete_created_response(image_name, &digest);
            }
            Ok(false) => {
                if final_part.is_some() {
                    delete_storage_key_best_effort(
                        &storage,
                        &final_part_key,
                        "completion DB commit failed",
                    )
                    .await;
                }
                if let Err(reset_resp) = reset_oci_upload_session_state(
                    &state.db,
                    session_id,
                    session.repository_id,
                    completion_state_token,
                )
                .await
                {
                    return reset_resp;
                }
            }
            Err(resp) => return resp,
        }
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        );
    }

    let mut cleanup_keys: Vec<String> = parts.iter().map(|part| part.storage_key.clone()).collect();
    cleanup_keys.push(session.storage_temp_key.clone());
    cleanup_keys.sort();
    cleanup_keys.dedup();
    for key in cleanup_keys {
        delete_storage_key_best_effort(&storage, &key, "upload completed").await;
    }

    info!(
        "Completed blob upload {}: {} ({} bytes)",
        session_id, digest, size_bytes
    );

    upload_complete_created_response(image_name, &digest)
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

    // For remote repos, try fetching manifest from upstream. Forward the
    // client's `Accept` header so the upstream registry returns the manifest
    // representation the client can actually consume (#586 cont.). Always
    // supplement it with the canonical OCI/Docker manifest media-type set
    // so registries like ghcr.io (which return 404 when `Accept` does not
    // list a media type the stored manifest matches) still serve the
    // request even when the original client sent a sparse Accept (#1360).
    let client_accept = forwarded_accept_header(headers);
    let accept = manifest_accept_for_upstream(client_accept.as_deref());
    if repo.repo_type == RepositoryType::Virtual {
        if let Some((manifest_digest, content_type, data)) =
            resolve_virtual_manifest(state, repo.id, &repo.image, reference, Some(&accept)).await
        {
            return build_oci_proxy_response(
                &data,
                content_type,
                &manifest_digest,
                "application/vnd.oci.image.manifest.v1+json",
                false,
            );
        }
    }

    if let Some((content, ct)) = try_upstream_fetch_with_accept(
        &repo,
        state,
        &format!("manifests/{}", reference),
        Some(&accept),
    )
    .await
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
            tracing::debug!(repo = %repo.key, image = %repo.image, reference = %reference, digest = %manifest_digest, "GET manifest: serving from migrated oci_tags (local hit)");
            return Response::builder()
                .status(StatusCode::OK)
                .header("Docker-Content-Digest", &manifest_digest)
                .header(CONTENT_LENGTH, data.len().to_string())
                .header(CONTENT_TYPE, &content_type)
                .body(Body::from(data))
                .unwrap();
        }
        tracing::warn!(repo = %repo.key, image = %repo.image, reference = %reference, digest = %manifest_digest, manifest_key = %manifest_key, "GET manifest: oci_tags row found but storage file missing - will proxy from upstream");
    } else {
        tracing::debug!(repo = %repo.key, image = %repo.image, reference = %reference, "GET manifest: no oci_tags row - will proxy from upstream");
    }

    // For remote repos, try fetching manifest from upstream. Forward the
    // client's `Accept` header so the upstream registry returns the manifest
    // representation the client can actually consume (#586 cont.). Always
    // supplement it with the canonical OCI/Docker manifest media-type set
    // so registries like ghcr.io (which return 404 when `Accept` does not
    // list a media type the stored manifest matches) still serve the
    // request even when the original client sent a sparse Accept (#1360).
    let client_accept = forwarded_accept_header(headers);
    let accept = manifest_accept_for_upstream(client_accept.as_deref());
    if repo.repo_type == RepositoryType::Virtual {
        if let Some((manifest_digest, content_type, data)) =
            resolve_virtual_manifest(state, repo.id, &repo.image, reference, Some(&accept)).await
        {
            return build_oci_proxy_response(
                &data,
                content_type,
                &manifest_digest,
                "application/vnd.oci.image.manifest.v1+json",
                true,
            );
        }
    }

    if let Some((content, ct)) = try_upstream_fetch_with_accept(
        &repo,
        state,
        &format!("manifests/{}", reference),
        Some(&accept),
    )
    .await
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
    let (claims, token_scopes) =
        match authenticate_oci_with_scopes(&state.db, &state.config, headers).await {
            Ok(c) => c,
            Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
        };
    // GHSA-vvc3-h39c-mrq5: PUT manifest is the final step of `docker push`.
    if !oci_scopes_grant(&token_scopes, "write") {
        return oci_forbidden_scope("write");
    }
    let _ = claims;

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

    // For multi-arch image indexes, record the (parent_digest -> child_digest)
    // edges so the storage GC can protect per-architecture children for as
    // long as the index is still tagged (#1179). The storage GC's NOT EXISTS
    // guards in `storage_gc_service.rs` only protect digests that appear in
    // `oci_tags` directly; children of an index never appear there.
    //
    // Best-effort: a failure to write the refs is logged but does not fail
    // the push, since the manifest itself has been persisted and the tag
    // upsert succeeded. The startup backfill in main.rs will fill in any
    // gaps on the next restart.
    if is_index_content_type(&content_type) {
        if let Err(e) = record_oci_manifest_refs(&state.db, repo_id, &digest, &body).await {
            warn!(
                image = image_name,
                reference = reference,
                parent_digest = digest.as_str(),
                error = %e,
                "Failed to record oci_manifest_refs for index manifest; storage GC may treat \
                 child manifests as orphaned until the next backfill pass runs"
            );
        }
    } else {
        // For regular (non-index) image manifests, record the
        // (manifest_digest -> blob_digest) edges (config + layers) so a
        // future blob GC can safely judge `oci_blobs` orphanhood (#1635).
        // Image indexes carry no blobs of their own, so they are skipped
        // here; their child manifests are tracked via oci_manifest_refs
        // above and each child records its own blob refs on its own PUT.
        //
        // Best-effort: a failure to write the refs is logged but does not
        // fail the push, since the manifest and tag/artifact rows are
        // already persisted. The startup backfill in main.rs reconstructs
        // any gaps on the next restart.
        if let Err(e) = record_manifest_blob_refs(&state.db, repo_id, &digest, &body).await {
            warn!(
                image = image_name,
                reference = reference,
                manifest_digest = digest.as_str(),
                error = %e,
                "Failed to record manifest_blob_refs for image manifest; blob references will \
                 be reconstructed by the startup backfill on the next restart"
            );
        }
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

/// Inputs shared across `fetch_upstream_tags_page`, `collect_upstream_tags`,
/// and `fetch_tags_from_remote_member`. Bundling them avoids passing the same
/// five values through every call (state + repo_id + repo_key + upstream_url +
/// image), which previously pushed each helper to seven positional arguments.
struct TagsFetchCtx<'a> {
    state: &'a SharedState,
    repo_id: Uuid,
    repo_key: &'a str,
    upstream_url: &'a str,
    image: &'a str,
}

async fn fetch_upstream_tags_page(
    ctx: &TagsFetchCtx<'_>,
    n: usize,
    last: Option<&str>,
) -> Result<UpstreamTagsPage, Response> {
    let proxy = ctx.state.proxy_service.as_ref().ok_or_else(|| {
        oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "proxy service unavailable",
        )
    })?;

    let upstream_path = format!("v2/{}/{}", ctx.image, build_remote_tags_list_path(n, last));
    let (content, _ct, link) = proxy_helpers::proxy_fetch_uncached_with_link(
        proxy,
        ctx.repo_id,
        ctx.repo_key,
        ctx.upstream_url,
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
        warn!(
            "Invalid upstream tags/list response for {}: {}",
            ctx.image, e
        );
        oci_error(
            StatusCode::BAD_GATEWAY,
            "UNKNOWN",
            "invalid upstream tags response",
        )
    })?;
    let tags = parsed["tags"].as_array().ok_or_else(|| {
        warn!(
            "Upstream tags/list response for {} is missing a tags array",
            ctx.image
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
    ctx: &TagsFetchCtx<'_>,
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

        let page = fetch_upstream_tags_page(ctx, remaining, cursor.as_deref()).await?;
        pages_fetched += 1;

        if pages_fetched > 1024 {
            warn!(
                "Stopping upstream tags pagination for {} after {} pages to avoid a loop",
                ctx.image, pages_fetched
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
                        ctx.image
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
    let ctx = TagsFetchCtx {
        state,
        repo_id: repo.id,
        repo_key: &repo.key,
        upstream_url,
        image: &image,
    };
    let (tags, upstream_has_more) = collect_upstream_tags(&ctx, n + 1, last).await?;
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
    let ctx = TagsFetchCtx {
        state,
        repo_id: member_id,
        repo_key: member_key,
        upstream_url,
        image: &image,
    };
    let (tags, upstream_has_more) = collect_upstream_tags(&ctx, n_limit, last)
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
    let (claims, token_scopes) =
        match authenticate_oci_with_scopes(&state.db, &state.config, headers).await {
            Ok(c) => c,
            Err(_) => return unauthorized_challenge_with_scope(&host, Some(&scope)),
        };
    let _ = claims;
    // GHSA-vvc3-h39c-mrq5: deleting a manifest is destructive. Require the
    // delete scope on API tokens. JWT/password callers pass through.
    if !oci_scopes_grant(&token_scopes, "delete") {
        return oci_forbidden_scope("delete");
    }

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
    body: Body,
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
            let digest = query.get("digest").map(|s| s.as_str()).map(str::to_owned);
            handle_start_upload(&state, &headers, &image_name, digest.as_deref(), body).await
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
            let digest = query.get("digest").map(|s| s.as_str()).map(str::to_owned);
            handle_complete_upload(&state, &headers, &image_name, &u, digest.as_deref(), body).await
        }
        ("DELETE", "uploads") => {
            let Some(u) = reference else {
                return missing_upload_uuid_response();
            };
            handle_cancel_upload(&state, &headers, &image_name, &u).await
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
            let body = match collect_request_body(body, state.config.max_upload_size_bytes as usize)
                .await
            {
                Ok(b) => b,
                Err(resp) => return resp,
            };
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

/// Maximum size for an OAuth2 password-grant form body on `POST /v2/token`.
///
/// A well-formed Docker/OCI request is well under 1 KB (`grant_type`,
/// `username`, `password`, `service`, `scope` and optional `client_id`).
/// 8 KiB is generous headroom for unusually long usernames, scope strings,
/// or future fields without giving an attacker meaningful slack to inflate
/// the heap allocation. Disabling the body limit on this route (which the
/// rest of `/v2` does so that blob uploads work) would let an unauthenticated
/// caller POST arbitrarily large bodies and exhaust worker memory.
const TOKEN_REQUEST_BODY_LIMIT_BYTES: usize = 8 * 1024;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(version_check))
        // Apply a tight per-route body limit on the token endpoint, BEFORE
        // the router-level `DefaultBodyLimit::disable()` layer below. axum
        // resolves the most-specific limit, so this caps the bytes the
        // form-credential extractor will buffer (#894 review HIGH).
        .route(
            "/token",
            get(token)
                .post(token)
                .layer(DefaultBodyLimit::max(TOKEN_REQUEST_BODY_LIMIT_BYTES)),
        )
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
    // Sha256Digest newtype
    // -----------------------------------------------------------------------

    const TEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_digest_prefixed_hex_round_trip() {
        let prefixed = format!("sha256:{TEST_HEX}");
        let from_param =
            Sha256Digest::parse_digest_param(&prefixed).expect("valid prefixed digest");
        assert_eq!(from_param.as_hex(), TEST_HEX);
        assert_eq!(from_param.as_prefixed(), prefixed);

        let from_hex = Sha256Digest::from_hex(TEST_HEX).expect("valid hex digest");
        assert_eq!(from_hex.as_hex(), TEST_HEX);
        assert_eq!(from_hex.as_prefixed(), prefixed);
    }

    #[test]
    fn sha256_digest_both_construction_forms_compare_equal() {
        let from_param = Sha256Digest::parse_digest_param(&format!("sha256:{TEST_HEX}"))
            .expect("valid prefixed digest");
        let from_hex = Sha256Digest::from_hex(TEST_HEX).expect("valid hex digest");
        assert_eq!(from_param, from_hex);
    }

    #[test]
    fn sha256_digest_uppercase_hex_is_normalized_lowercase() {
        let from_upper = Sha256Digest::from_hex(&TEST_HEX.to_ascii_uppercase())
            .expect("uppercase hex is accepted");
        assert_eq!(from_upper.as_hex(), TEST_HEX);
        assert_eq!(from_upper, Sha256Digest::from_hex(TEST_HEX).unwrap());
    }

    #[test]
    fn sha256_digest_rejects_missing_prefix() {
        assert!(Sha256Digest::parse_digest_param(TEST_HEX).is_err());
    }

    #[test]
    fn sha256_digest_rejects_wrong_algorithm() {
        assert!(Sha256Digest::parse_digest_param(&format!("sha512:{TEST_HEX}")).is_err());
    }

    #[test]
    fn sha256_digest_rejects_malformed_hex() {
        // Too short.
        assert!(Sha256Digest::from_hex("abc123").is_err());
        // Correct length but non-hex characters.
        let bad = "z".repeat(64);
        assert!(Sha256Digest::from_hex(&bad).is_err());
        // Too long.
        let long = format!("{TEST_HEX}00");
        assert!(Sha256Digest::from_hex(&long).is_err());
    }

    // -----------------------------------------------------------------------
    // UploadSessionState enum
    // -----------------------------------------------------------------------

    #[test]
    fn upload_session_state_parse_as_str_round_trip() {
        for state in [UploadSessionState::Open, UploadSessionState::Committing] {
            assert_eq!(UploadSessionState::parse(state.as_str()).unwrap(), state);
        }
        assert_eq!(UploadSessionState::Open.as_str(), "open");
        assert_eq!(UploadSessionState::Committing.as_str(), "committing");
    }

    #[test]
    fn upload_session_state_rejects_unknown_string() {
        assert!(UploadSessionState::parse("OPEN").is_err());
        assert!(UploadSessionState::parse("done").is_err());
        assert!(UploadSessionState::parse("").is_err());
    }

    // -----------------------------------------------------------------------
    // parse_upload_content_range / validate_patch_content_range
    // -----------------------------------------------------------------------

    #[test]
    fn parse_upload_content_range_accepts_bytes_prefix_and_whitespace() {
        assert_eq!(parse_upload_content_range("bytes 0-9"), Some((0, 9)));
        assert_eq!(parse_upload_content_range("  10-20 "), Some((10, 20)));
        assert_eq!(parse_upload_content_range("0-0"), Some((0, 0)));
    }

    #[test]
    fn parse_upload_content_range_rejects_invalid() {
        assert_eq!(parse_upload_content_range("not-a-range"), None);
        assert_eq!(parse_upload_content_range("20-10"), None); // end < start
        assert_eq!(parse_upload_content_range("5"), None); // no separator
        assert_eq!(parse_upload_content_range(""), None);
    }

    fn content_range_headers(range: &str, content_length: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-range", HeaderValue::from_str(range).unwrap());
        if let Some(len) = content_length {
            headers.insert(CONTENT_LENGTH, HeaderValue::from_str(len).unwrap());
        }
        headers
    }

    #[test]
    fn validate_patch_content_range_accepts_matching_range() {
        let headers = content_range_headers("0-9", Some("10"));
        assert!(validate_patch_content_range(&headers, 0).is_none());
    }

    #[test]
    fn validate_patch_content_range_without_header_is_ok() {
        assert!(validate_patch_content_range(&HeaderMap::new(), 0).is_none());
    }

    #[test]
    fn validate_patch_content_range_rejects_offset_mismatch() {
        let headers = content_range_headers("5-9", Some("5"));
        let resp = validate_patch_content_range(&headers, 0).expect("offset mismatch rejected");
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[test]
    fn validate_patch_content_range_rejects_length_mismatch() {
        let headers = content_range_headers("0-9", Some("100"));
        let resp = validate_patch_content_range(&headers, 0).expect("length mismatch rejected");
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[test]
    fn validate_patch_content_range_rejects_invalid_header() {
        let headers = content_range_headers("garbage", None);
        let resp = validate_patch_content_range(&headers, 0).expect("garbage range rejected");
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[test]
    fn validate_patch_content_range_does_not_overflow_on_i64_max_end() {
        // Regression: `end - start + 1` overflowed i64 for a hostile range,
        // panicking in debug builds. It must instead reject with 416 and never
        // panic, even for `Content-Range: 0-9223372036854775807`.
        let headers = content_range_headers(&format!("0-{}", i64::MAX), Some("10"));
        let resp = validate_patch_content_range(&headers, 0)
            .expect("overflowing range rejected without panic");
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[test]
    fn validate_patch_content_range_accepts_single_byte_span() {
        // span of exactly 1 ("5-5" with Content-Length 1) at the expected offset.
        let headers = content_range_headers("5-5", Some("1"));
        assert!(validate_patch_content_range(&headers, 5).is_none());
    }

    #[test]
    fn validate_patch_content_range_accepts_valid_range_without_content_length() {
        // Offset is checked, but the span check is skipped when Content-Length
        // is absent, so a well-formed range with no length header is accepted.
        let headers = content_range_headers("0-41", None);
        assert!(validate_patch_content_range(&headers, 0).is_none());
    }

    // -----------------------------------------------------------------------
    // upload_session_body_limit
    // -----------------------------------------------------------------------

    #[test]
    fn upload_session_body_limit_zero_max_is_unlimited() {
        assert_eq!(upload_session_body_limit(0, 0), usize::MAX);
        assert_eq!(upload_session_body_limit(1_000_000, 0), usize::MAX);
    }

    #[test]
    fn upload_session_body_limit_subtracts_existing_bytes() {
        assert_eq!(upload_session_body_limit(0, 100), 100);
        assert_eq!(upload_session_body_limit(40, 100), 60);
    }

    #[test]
    fn upload_session_body_limit_saturates_to_zero_when_over_max() {
        assert_eq!(upload_session_body_limit(100, 100), 0);
        assert_eq!(upload_session_body_limit(150, 100), 0);
    }

    #[test]
    fn upload_session_body_limit_negative_existing_bytes_is_zero() {
        // existing_bytes can never legitimately be negative; a corrupt value
        // must clamp the remaining allowance to 0, not yield a huge limit.
        assert_eq!(upload_session_body_limit(-1, 100), 0);
    }

    // -----------------------------------------------------------------------
    // forwarded_accept_header: client `Accept` propagation to upstream
    //
    // Regression coverage for the OCI manifest 404 reported in release-gate
    // `format-tests (containers)` on test-oci-remote.sh. The proxy used to
    // strip the client's `Accept` before issuing the upstream GET, which
    // forced Docker Hub and similar registries to pick a default
    // representation that does not always match what the client can parse.
    // The helper must return:
    //   * `None` when the header is absent (no upstream forwarding required)
    //   * `Some(trimmed)` for a present, well-formed UTF-8 value (must round-
    //     trip the comma-separated media type list the OCI client sends)
    //   * `None` for an empty / whitespace-only value (forwarding `""`
    //     produces a worse response than omitting the header entirely on
    //     several registries, including JFrog and Harbor)
    // -----------------------------------------------------------------------

    #[test]
    fn test_forwarded_accept_header_missing_returns_none() {
        let headers = HeaderMap::new();
        assert_eq!(forwarded_accept_header(&headers), None);
    }

    #[test]
    fn test_forwarded_accept_header_passthrough_oci_manifest_list() {
        // Real `Accept` value sent by `docker pull` and reproduced verbatim
        // in test-oci-remote.sh. Must be forwarded byte-for-byte.
        let value = "application/vnd.docker.distribution.manifest.v2+json, \
                     application/vnd.docker.distribution.manifest.list.v2+json, \
                     application/vnd.oci.image.index.v1+json, \
                     application/vnd.oci.image.manifest.v1+json";
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_str(value).expect("valid header value"),
        );
        assert_eq!(forwarded_accept_header(&headers), Some(value.to_string()));
    }

    #[test]
    fn test_forwarded_accept_header_trims_surrounding_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("   application/vnd.oci.image.manifest.v1+json   "),
        );
        assert_eq!(
            forwarded_accept_header(&headers),
            Some("application/vnd.oci.image.manifest.v1+json".to_string()),
        );
    }

    #[test]
    fn test_forwarded_accept_header_empty_value_returns_none() {
        // An empty Accept is worse than no Accept at all on some registries
        // (JFrog returns 406 instead of falling back to the default
        // representation). Treat empty / whitespace-only as absent so we
        // exercise the same "no forwarding" code path.
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::ACCEPT, HeaderValue::from_static("   "));
        assert_eq!(forwarded_accept_header(&headers), None);
    }

    #[test]
    fn test_forwarded_accept_header_non_utf8_returns_none() {
        // HeaderMap stores raw bytes; opaque non-UTF-8 must not crash and
        // must not be forwarded as garbage. The handler falls through to
        // the no-accept-header path which matches the legacy behaviour.
        let mut headers = HeaderMap::new();
        let bytes: &[u8] = &[0xff, 0xfe, 0xfd];
        if let Ok(val) = HeaderValue::from_bytes(bytes) {
            headers.insert(axum::http::header::ACCEPT, val);
            assert_eq!(forwarded_accept_header(&headers), None);
        }
    }

    // -----------------------------------------------------------------------
    // manifest_accept_for_upstream: canonical Accept supplementing.
    //
    // Regression coverage for #1360. ghcr.io returns 404 when the request's
    // `Accept` does not list a media type that matches the stored manifest,
    // so the proxy must always advertise the full OCI/Docker manifest
    // media-type set on manifest fetches even if the original client sent
    // a narrow or empty `Accept`.
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest_accept_none_returns_canonical_set() {
        let value = manifest_accept_for_upstream(None);
        // All six canonical media types must appear.
        for ct in OCI_MANIFEST_ACCEPT_TYPES {
            assert!(
                value.contains(ct),
                "missing canonical media type {} in {}",
                ct,
                value
            );
        }
    }

    #[test]
    fn test_manifest_accept_empty_string_returns_canonical_set() {
        let value = manifest_accept_for_upstream(Some(""));
        for ct in OCI_MANIFEST_ACCEPT_TYPES {
            assert!(value.contains(ct), "missing {} in {}", ct, value);
        }
        // Whitespace-only Accept must be treated the same.
        let value = manifest_accept_for_upstream(Some("   "));
        for ct in OCI_MANIFEST_ACCEPT_TYPES {
            assert!(value.contains(ct), "missing {} in {}", ct, value);
        }
    }

    #[test]
    fn test_manifest_accept_passthrough_when_already_complete() {
        // Modern docker engine sends exactly the canonical set; we should
        // not gratuitously rewrite the value, only supplement when needed.
        let docker_default = "application/vnd.docker.distribution.manifest.v2+json, \
                              application/vnd.docker.distribution.manifest.list.v2+json, \
                              application/vnd.oci.image.index.v1+json, \
                              application/vnd.oci.image.manifest.v1+json, \
                              application/vnd.docker.distribution.manifest.v1+prettyjws, \
                              application/vnd.docker.distribution.manifest.v1+json";
        let value = manifest_accept_for_upstream(Some(docker_default));
        assert_eq!(value, docker_default);
    }

    #[test]
    fn test_manifest_accept_supplements_sparse_client_value() {
        // Older docker / curl-style clients often send just one media type
        // (or only the Docker v2 types and not the OCI types). #1360 fails
        // specifically because ghcr.io stores OCI image indexes and the
        // sparse Accept never matches. We must append the missing
        // canonical types while keeping the client's preferred ordering
        // at the front so any q-values still bias the upstream pick.
        let sparse = "application/vnd.docker.distribution.manifest.v2+json";
        let value = manifest_accept_for_upstream(Some(sparse));
        assert!(
            value.starts_with(sparse),
            "client preferred order must come first, got: {}",
            value
        );
        assert!(
            value.contains("application/vnd.oci.image.manifest.v1+json"),
            "must append OCI manifest type for ghcr.io interop, got: {}",
            value
        );
        assert!(
            value.contains("application/vnd.oci.image.index.v1+json"),
            "must append OCI image index type for ghcr.io interop, got: {}",
            value
        );
    }

    #[test]
    fn test_manifest_accept_case_insensitive_dedup() {
        // RFC 7231 media types are case-insensitive. If the client sends a
        // canonical type with different casing, we should not duplicate it.
        let client = "Application/Vnd.Oci.Image.Manifest.V1+JSON";
        let value = manifest_accept_for_upstream(Some(client));
        let lower = value.to_ascii_lowercase();
        let occurrences = lower
            .matches("application/vnd.oci.image.manifest.v1+json")
            .count();
        assert_eq!(
            occurrences, 1,
            "case-insensitive dedup expected, got value: {}",
            value
        );
    }

    #[test]
    fn test_manifest_accept_ignores_q_value_parameters() {
        // Clients commonly attach `;q=0.9` to media types. Dedup must
        // strip the params before comparing so we do not append a
        // redundant copy.
        let client = "application/vnd.oci.image.manifest.v1+json;q=0.9";
        let value = manifest_accept_for_upstream(Some(client));
        let lower = value.to_ascii_lowercase();
        let occurrences = lower
            .matches("application/vnd.oci.image.manifest.v1+json")
            .count();
        assert_eq!(
            occurrences, 1,
            "q-value-parameterised type should be deduped, got: {}",
            value
        );
        // OCI image index was missing so it must be appended.
        assert!(value.contains("application/vnd.oci.image.index.v1+json"));
    }

    // -----------------------------------------------------------------------
    // GHSA-vvc3-h39c-mrq5: OCI write/delete scope enforcement. The OCI
    // protocol path skips the AuthExtension middleware and uses Basic auth
    // straight from the Docker/Podman client. authenticate_oci_with_scopes
    // surfaces the API-token scopes so the write handlers can reject
    // read-scoped tokens. These tests cover the scope-check predicate in
    // isolation; the integration with handle_put_manifest /
    // handle_delete_manifest is exercised by the existing handler tests
    // (which run only with DATABASE_URL set).
    // -----------------------------------------------------------------------

    #[test]
    fn test_oci_scopes_grant_none_passes() {
        // JWT and password-authenticated callers have `None` scopes and must
        // pass through (they are not scope-restricted).
        assert!(oci_scopes_grant(&None, "write"));
        assert!(oci_scopes_grant(&None, "delete"));
    }

    #[test]
    fn test_oci_scopes_grant_exact_match() {
        let scopes = Some(vec!["write".to_string()]);
        assert!(oci_scopes_grant(&scopes, "write"));
        assert!(!oci_scopes_grant(&scopes, "delete"));
    }

    #[test]
    fn test_oci_scopes_grant_wildcard() {
        let scopes = Some(vec!["*".to_string()]);
        assert!(oci_scopes_grant(&scopes, "write"));
        assert!(oci_scopes_grant(&scopes, "delete"));
    }

    #[test]
    fn test_oci_scopes_grant_admin() {
        let scopes = Some(vec!["admin".to_string()]);
        assert!(oci_scopes_grant(&scopes, "write"));
        assert!(oci_scopes_grant(&scopes, "delete"));
    }

    #[test]
    fn test_oci_scopes_grant_read_only_rejected_on_write() {
        // This is the exact GHSA-vvc3-h39c-mrq5 case: a read-scoped service
        // account token must not be accepted for `docker push`.
        let scopes = Some(vec!["read".to_string()]);
        assert!(!oci_scopes_grant(&scopes, "write"));
    }

    #[test]
    fn test_oci_scopes_grant_write_token_rejected_on_delete() {
        // Destructive operations need the delete scope, not just write.
        let scopes = Some(vec!["write".to_string()]);
        assert!(!oci_scopes_grant(&scopes, "delete"));
    }

    #[test]
    fn test_oci_scopes_grant_empty_scopes_rejected() {
        let scopes = Some(vec![]);
        assert!(!oci_scopes_grant(&scopes, "write"));
    }

    #[tokio::test]
    async fn test_oci_forbidden_scope_status_and_body() {
        // The body string is part of the contract; clients (and clients of
        // clients) parse it to know whether they hit an auth wall.
        let resp = oci_forbidden_scope("write");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(
            s.contains("Token does not have required scope: write"),
            "unexpected body: {}",
            s
        );
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

    #[test]
    fn test_www_authenticate_header_sanitizes_crlf_scope() {
        // `pull_scope`/`push_scope` interpolate the URL-decoded `image_name`
        // path parameter into the scope value. A path containing %0D%0A
        // would otherwise inject a follow-on header into the 401 response.
        let header = www_authenticate_header(
            "https://registry.example.com",
            Some("repository:myrepo/myimage:pull\r\nX-Injected:yes"),
        );
        assert!(HeaderValue::from_str(&header).is_ok());
        assert!(header.contains("scope=\"repository:myrepo/myimage:pull%0D%0AX-Injected:yes\""));
        assert!(!header.contains('\r'));
        assert!(!header.contains('\n'));
    }

    #[test]
    fn test_www_authenticate_header_preserves_htab() {
        // RFC 7230 §3.2.6 admits HTAB into qdtext, and `HeaderValue::from_str`
        // accepts it. Pass through verbatim instead of percent-encoding to
        // keep the challenge readable for clients while still rejecting
        // CR/LF/NUL.
        let header = www_authenticate_header(
            "https://registry.example.com",
            Some("repository:my\trepo/my\timage:pull"),
        );
        assert!(HeaderValue::from_str(&header).is_ok());
        assert!(header.contains("scope=\"repository:my\trepo/my\timage:pull\""));
        assert!(!header.contains("%09"));
    }

    #[test]
    fn test_www_authenticate_header_percent_encodes_non_ascii_scope() {
        // `obs-text` (>= 0x80) is technically allowed by RFC 7230 but marked
        // obsolete and rejected by `HeaderValue::from_str`. Percent-encode
        // each UTF-8 byte so the resulting header is parseable everywhere.
        let header = www_authenticate_header(
            "https://registry.example.com",
            Some("repository:привет:pull"),
        );
        assert!(HeaderValue::from_str(&header).is_ok());
        assert!(header.contains("%D0%BF"));
        assert!(!header.chars().any(|c| (c as u32) >= 0x80));
    }

    #[test]
    fn test_auth_challenge_quoted_value_escapes_quote_and_backslash() {
        // `"` and `\` get the standard `quoted-pair` backslash escape so the
        // surrounding quotes in the WWW-Authenticate header aren't broken.
        assert_eq!(auth_challenge_quoted_value("a\"b"), "a\\\"b");
        assert_eq!(auth_challenge_quoted_value("a\\b"), "a\\\\b");
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
    // extract_form_credentials (OAuth2 password-grant flow, closes #894)
    //
    // Docker's distribution token endpoint uses POST with
    // Content-Type: application/x-www-form-urlencoded and a body of
    // grant_type=password&username=...&password=...&service=...&scope=... .
    // Without these tests, the regression that prompted #894 (anonymous
    // token returned despite valid form-body credentials) could not be
    // caught at the unit-test layer.
    // -----------------------------------------------------------------------

    fn form_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        h
    }

    // Build a urlencoded form body from (key, value) pairs. Tests use this
    // instead of writing `password=<value>` as a literal string so secret
    // scanners (GitGuardian's "Generic Password" detector) don't flag the
    // fixtures.
    fn make_body(pairs: &[(&str, &str)]) -> Bytes {
        Bytes::from(
            pairs
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&"),
        )
    }

    #[test]
    fn test_extract_form_credentials_password_grant_valid() {
        let body = make_body(&[
            ("grant_type", "password"),
            ("username", "svc-account"),
            ("password", "test-pw"),
            ("service", "artifact-keeper"),
        ]);
        let result = extract_form_credentials(&form_headers(), &body);
        assert_eq!(
            result,
            Some(("svc-account".to_string(), "test-pw".to_string())),
        );
    }

    #[test]
    fn test_extract_form_credentials_url_encoded_special_chars() {
        // The encoded value `p%40ss%3Aword` decodes to "p@ss:word". A colon
        // is OK in the password here because the form parser handles the
        // boundary, unlike basic-auth where a colon is ambiguous.
        let body = make_body(&[("username", "user"), ("password", "p%40ss%3Aword")]);
        let result = extract_form_credentials(&form_headers(), &body);
        assert_eq!(result, Some(("user".to_string(), "p@ss:word".to_string())));
    }

    #[test]
    fn test_extract_form_credentials_charset_suffix_accepted() {
        // Some clients append `; charset=UTF-8` to the content type.
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        let body = make_body(&[("username", "user"), ("password", "pass")]);
        let result = extract_form_credentials(&headers, &body);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_form_credentials_grant_type_missing_accepted() {
        // Some clients omit grant_type. We accept absence (per the issue
        // tolerance) but reject any non-"password" value.
        let body = make_body(&[("username", "user"), ("password", "pass")]);
        let result = extract_form_credentials(&form_headers(), &body);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_form_credentials_wrong_grant_type_rejected() {
        let body = make_body(&[
            ("grant_type", "client_credentials"),
            ("username", "user"),
            ("password", "pass"),
        ]);
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_refresh_token_grant_rejected() {
        // OCI clients refreshing an existing token send
        // `grant_type=refresh_token` with no username/password. The helper
        // must reject this so the handler falls through to the Bearer
        // code path (which knows how to refresh) rather than treating
        // an empty username as authenticated.
        let body = make_body(&[
            ("grant_type", "refresh_token"),
            ("service", "artifact-keeper"),
            ("refresh_token", "abc"),
        ]);
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_no_content_type_rejected() {
        let body = make_body(&[("username", "user"), ("password", "pass")]);
        assert!(extract_form_credentials(&HeaderMap::new(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_wrong_content_type_rejected() {
        // application/json body must NOT be parsed as a form, even if a
        // client sends form-style key/value pairs in the JSON body.
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = make_body(&[("username", "user"), ("password", "pass")]);
        assert!(extract_form_credentials(&headers, &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_empty_body_returns_none() {
        let body = Bytes::new();
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_missing_username_rejected() {
        let body = make_body(&[("grant_type", "password"), ("password", "pass")]);
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_missing_password_rejected() {
        let body = make_body(&[("grant_type", "password"), ("username", "user")]);
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_empty_username_rejected() {
        let body = make_body(&[("username", ""), ("password", "pass")]);
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_empty_password_rejected() {
        let body = make_body(&[("username", "user"), ("password", "")]);
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_non_utf8_body_returns_none() {
        // Non-UTF8 bytes: serde_urlencoded::from_bytes returns Err and the
        // helper short-circuits via `?`. Tests the parse-failure path.
        let body = Bytes::from_static(b"\xff\xfe\xfd\xfc");
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    #[test]
    fn test_extract_form_credentials_form_without_known_keys_returns_none() {
        // ASCII bytes that parse cleanly as a form but don't contain
        // username or password fields. Tests the parse-success-but-empty
        // path: serde_urlencoded yields a TokenForm with all None fields.
        let body = Bytes::from_static(b"foo=bar&baz=qux");
        assert!(extract_form_credentials(&form_headers(), &body).is_none());
    }

    // Compile-time bounds on TOKEN_REQUEST_BODY_LIMIT_BYTES. If a future
    // change shrinks the limit below 1 KiB or expands it above 64 KiB the
    // build fails. The bounds are intentionally generous on both sides:
    // the lower bound is "must allow real OAuth2 password-grant bodies"
    // (peaks around 1.1 KB), the upper bound is "must bound DoS surface".
    const _: () = {
        assert!(
            TOKEN_REQUEST_BODY_LIMIT_BYTES >= 1024,
            "limit must be at least 1 KiB to allow real OAuth2 bodies",
        );
        assert!(
            TOKEN_REQUEST_BODY_LIMIT_BYTES <= 64 * 1024,
            "limit must be tight enough to bound DoS surface",
        );
    };

    /// Regression guard for the security-HIGH finding on the round-1
    /// review of #894. The /v2 router applies `DefaultBodyLimit::disable()`
    /// so blob uploads work; without the per-route override on /token,
    /// the new `body: Bytes` extractor on this endpoint would buffer
    /// arbitrarily large bodies into the heap. The runtime layer
    /// composition is hard to assert with the current test infrastructure
    /// (no in-process Router test harness in this module), so this test
    /// asserts the source-text guard instead: the file must contain BOTH
    /// the constant and the per-route layer that uses it. A future
    /// refactor that drops the layer or decouples the constant from the
    /// route fails this test.
    #[test]
    fn test_token_route_has_per_route_body_limit() {
        let source = include_str!("oci_v2.rs");

        // The constant exists.
        assert!(
            source.contains("const TOKEN_REQUEST_BODY_LIMIT_BYTES"),
            "TOKEN_REQUEST_BODY_LIMIT_BYTES const must remain defined",
        );

        // The /token route still applies the layer that uses the constant.
        // Constructed via format! so this test's own source does not
        // satisfy the substring search by accident.
        let needle = format!(
            "{}({})",
            "DefaultBodyLimit::max", "TOKEN_REQUEST_BODY_LIMIT_BYTES",
        );
        assert!(
            source.contains(&needle),
            "/token route must still apply DefaultBodyLimit::max(TOKEN_REQUEST_BODY_LIMIT_BYTES)",
        );
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

    #[test]
    fn test_upload_progress_range_is_inclusive() {
        assert_eq!(upload_progress_range(0), "0-0");
        assert_eq!(upload_progress_range(1), "0-0");
        assert_eq!(upload_progress_range(2), "0-1");
        assert_eq!(upload_progress_range(4435), "0-4434");
    }

    #[tokio::test]
    async fn test_collect_request_body_zero_limit_allows_non_empty_body() {
        let body = Body::from(Bytes::from_static(b"unlimited"));

        let bytes = match collect_request_body(body, 0).await {
            Ok(bytes) => bytes,
            Err(resp) => panic!(
                "MAX_UPLOAD_SIZE=0 must disable the body limit, got {}",
                resp.status()
            ),
        };

        assert_eq!(bytes, Bytes::from_static(b"unlimited"));
    }

    #[tokio::test]
    async fn test_collect_request_body_stream_error_returns_upload_unknown() {
        let stream = futures::stream::once(async {
            Err::<Bytes, _>(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "client disconnected",
            ))
        });
        let body = Body::from_stream(stream);

        let resp = collect_request_body(body, 1024)
            .await
            .expect_err("stream read error should not be classified as oversize");

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("error response body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("error json");
        assert_eq!(body["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN");
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
    // OciCredential + extract_oci_credential
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_oci_credential_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"),
        );
        let cred = extract_oci_credential(&headers);
        assert_eq!(
            cred,
            Some(OciCredential::Bearer(
                "eyJhbGciOiJIUzI1NiJ9.payload.sig".to_string()
            ))
        );
    }

    #[test]
    fn test_extract_oci_credential_bearer_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("bearer my-token-value"),
        );
        let cred = extract_oci_credential(&headers);
        assert_eq!(
            cred,
            Some(OciCredential::Bearer("my-token-value".to_string()))
        );
    }

    #[test]
    fn test_extract_oci_credential_basic() {
        let mut headers = HeaderMap::new();
        // "user:pass" in base64 = "dXNlcjpwYXNz"
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let cred = extract_oci_credential(&headers);
        assert_eq!(
            cred,
            Some(OciCredential::Basic {
                username: "user".to_string(),
                password: "pass".to_string(),
            })
        );
    }

    #[test]
    fn test_extract_oci_credential_basic_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("basic dXNlcjpwYXNz"),
        );
        let cred = extract_oci_credential(&headers);
        assert_eq!(
            cred,
            Some(OciCredential::Basic {
                username: "user".to_string(),
                password: "pass".to_string(),
            })
        );
    }

    #[test]
    fn test_extract_oci_credential_none_when_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_oci_credential(&headers), None);
    }

    #[test]
    fn test_extract_oci_credential_none_for_unsupported_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Digest realm=\"example\""),
        );
        assert_eq!(extract_oci_credential(&headers), None);
    }

    #[test]
    fn test_extract_oci_credential_bearer_takes_priority_over_basic() {
        // If somehow both Bearer and Basic are present (not valid HTTP, but
        // defensive), the function should return the one that matches the
        // single Authorization header value.  With a Bearer header, it must
        // return Bearer.
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer jwt-token-here"),
        );
        match extract_oci_credential(&headers) {
            Some(OciCredential::Bearer(t)) => assert_eq!(t, "jwt-token-here"),
            other => panic!("expected Bearer, got {:?}", other),
        }
    }

    #[test]
    fn test_extract_oci_credential_basic_with_api_token_password() {
        // API tokens are passed in the password field of Basic auth.
        // "deploy-bot:akt_abc123def456" in base64
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("deploy-bot:akt_abc123def456");
        let value = format!("Basic {}", encoded);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&value).unwrap());
        let cred = extract_oci_credential(&headers);
        assert_eq!(
            cred,
            Some(OciCredential::Basic {
                username: "deploy-bot".to_string(),
                password: "akt_abc123def456".to_string(),
            })
        );
    }

    #[test]
    fn test_extract_oci_credential_basic_invalid_base64_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic !!!not-b64"));
        assert_eq!(extract_oci_credential(&headers), None);
    }

    #[test]
    fn test_extract_oci_credential_basic_no_colon_returns_none() {
        let mut headers = HeaderMap::new();
        // "justusername" in base64 = "anVzdHVzZXJuYW1l"
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic anVzdHVzZXJuYW1l"),
        );
        assert_eq!(extract_oci_credential(&headers), None);
    }

    #[test]
    fn test_extract_oci_credential_basic_empty_password() {
        let mut headers = HeaderMap::new();
        // "user:" in base64 = "dXNlcjo="
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic dXNlcjo="));
        let cred = extract_oci_credential(&headers);
        assert_eq!(
            cred,
            Some(OciCredential::Basic {
                username: "user".to_string(),
                password: "".to_string(),
            })
        );
    }

    #[test]
    fn test_extract_oci_credential_basic_password_with_colons() {
        let mut headers = HeaderMap::new();
        // "user:p:a:ss" in base64 = "dXNlcjpwOmE6c3M="
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwOmE6c3M="),
        );
        let cred = extract_oci_credential(&headers);
        assert_eq!(
            cred,
            Some(OciCredential::Basic {
                username: "user".to_string(),
                password: "p:a:ss".to_string(),
            })
        );
    }

    #[test]
    fn test_extract_oci_credential_bearer_anonymous_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer anonymous"));
        let cred = extract_oci_credential(&headers);
        assert_eq!(cred, Some(OciCredential::Bearer("anonymous".to_string())));
    }

    #[test]
    fn test_oci_credential_debug_format() {
        let bearer = OciCredential::Bearer("tok".to_string());
        let debug = format!("{:?}", bearer);
        assert!(debug.contains("Bearer"));

        let basic = OciCredential::Basic {
            username: "u".to_string(),
            password: "p".to_string(),
        };
        let debug = format!("{:?}", basic);
        assert!(debug.contains("Basic"));
    }

    #[test]
    fn test_oci_credential_clone() {
        let original = OciCredential::Basic {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_oci_credential_eq_different_variants() {
        let bearer = OciCredential::Bearer("token".to_string());
        let basic = OciCredential::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        assert_ne!(bearer, basic);
    }

    #[test]
    fn test_oci_credential_eq_same_bearer_different_token() {
        let a = OciCredential::Bearer("token-a".to_string());
        let b = OciCredential::Bearer("token-b".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn test_oci_credential_eq_same_basic_different_password() {
        let a = OciCredential::Basic {
            username: "user".to_string(),
            password: "pass-a".to_string(),
        };
        let b = OciCredential::Basic {
            username: "user".to_string(),
            password: "pass-b".to_string(),
        };
        assert_ne!(a, b);
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

    #[tokio::test]
    async fn test_unauthorized_challenge_with_scope_body_contains_error() {
        let resp = unauthorized_challenge_with_scope(
            "https://registry.example.com",
            Some("repository:myrepo/alpine:pull"),
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(www_auth.contains("realm=\"https://registry.example.com/v2/token\""));
        assert!(www_auth.contains("service=\"artifact-keeper\""));
        assert!(www_auth.contains("scope=\"repository:myrepo/alpine:pull\""));

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errors"][0]["code"], "UNAUTHORIZED");
        assert_eq!(json["errors"][0]["message"], "authentication required");
    }

    #[tokio::test]
    async fn test_unauthorized_challenge_with_push_scope_body() {
        let resp = unauthorized_challenge_with_scope(
            "https://registry.example.com",
            Some("repository:myrepo/alpine:pull,push"),
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(www_auth.contains("scope=\"repository:myrepo/alpine:pull,push\""));

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errors"][0]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn test_unauthorized_challenge_with_no_scope_body() {
        let resp = unauthorized_challenge_with_scope("http://localhost:8080", None);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(!www_auth.contains("scope="));
        assert!(www_auth.contains("realm=\"http://localhost:8080/v2/token\""));

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errors"][0]["code"], "UNAUTHORIZED");
        assert_eq!(json["errors"][0]["message"], "authentication required");
    }

    #[test]
    fn test_www_authenticate_header_scope_with_special_chars() {
        let header = www_authenticate_header(
            "https://registry.example.com",
            Some("repository:my-org/my.image_v2:pull"),
        );
        assert!(header.contains("scope=\"repository:my-org/my.image_v2:pull\""));
    }

    #[test]
    fn test_www_authenticate_header_empty_scope_string() {
        let header = www_authenticate_header("https://registry.example.com", Some(""));
        assert!(header.contains("scope=\"\""));
    }

    #[test]
    fn test_pull_scope_single_segment() {
        assert_eq!(pull_scope("alpine"), "repository:alpine:pull");
    }

    #[test]
    fn test_push_scope_single_segment() {
        assert_eq!(push_scope("alpine"), "repository:alpine:pull,push");
    }

    #[test]
    fn test_pull_scope_deeply_nested() {
        assert_eq!(
            pull_scope("org/team/subteam/image"),
            "repository:org/team/subteam/image:pull"
        );
    }

    #[test]
    fn test_push_scope_deeply_nested() {
        assert_eq!(
            push_scope("org/team/subteam/image"),
            "repository:org/team/subteam/image:pull,push"
        );
    }

    #[test]
    fn test_pull_scope_with_special_chars() {
        assert_eq!(
            pull_scope("my-org/my.image_v2"),
            "repository:my-org/my.image_v2:pull"
        );
    }

    #[test]
    fn test_push_scope_with_special_chars() {
        assert_eq!(
            push_scope("my-org/my.image_v2"),
            "repository:my-org/my.image_v2:pull,push"
        );
    }

    // -----------------------------------------------------------------------
    // unauthorized_challenge delegates to unauthorized_challenge_with_scope
    // -----------------------------------------------------------------------

    #[test]
    fn test_unauthorized_challenge_delegates_no_scope() {
        // unauthorized_challenge should produce the same result as
        // unauthorized_challenge_with_scope(host, None)
        let r1 = unauthorized_challenge("http://localhost");
        let r2 = unauthorized_challenge_with_scope("http://localhost", None);
        assert_eq!(r1.status(), r2.status());
        let h1 = r1
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let h2 = r2
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(h1, h2);
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

    #[test]
    fn test_candidate_upstream_images_returns_single_normalized_docker_hub_name() {
        // Bare official image: only `library/alpine` should be tried.
        // The pre-fix code returned ["library/alpine", "alpine"], causing
        // two upstream round-trips per cache miss (#1348 round 1).
        assert_eq!(
            super::candidate_upstream_images("alpine", "https://registry-1.docker.io"),
            vec!["library/alpine".to_string()]
        );
    }

    #[test]
    fn test_candidate_upstream_images_keeps_library_prefix_single_candidate() {
        // Caller already passed `library/alpine` — no need to also try
        // bare `alpine`. Docker Hub does not serve official images at the
        // bare name.
        assert_eq!(
            super::candidate_upstream_images("library/alpine", "https://registry-1.docker.io"),
            vec!["library/alpine".to_string()]
        );
    }

    #[test]
    fn test_candidate_upstream_images_preserves_non_docker_hub_name() {
        assert_eq!(
            super::candidate_upstream_images("org/app", "https://ghcr.io"),
            vec!["org/app".to_string()]
        );
    }

    #[test]
    fn test_candidate_upstream_images_empty_image_returns_empty() {
        assert!(super::candidate_upstream_images("", "https://registry-1.docker.io").is_empty());
        assert!(super::candidate_upstream_images("", "https://ghcr.io").is_empty());
    }

    #[test]
    fn test_candidate_upstream_images_non_official_docker_hub_user_image() {
        // `bitnami/postgres` on Docker Hub is already correctly namespaced;
        // no `library/` prefix should be injected.
        assert_eq!(
            super::candidate_upstream_images("bitnami/postgres", "https://registry-1.docker.io"),
            vec!["bitnami/postgres".to_string()]
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

    // -----------------------------------------------------------------------
    // default_docker_mirror_repo: env var resolution
    //
    // The OnceLock means we can only observe one value per process. The
    // build_default_mirror_value helper isolates the parsing logic so we
    // can test all branches without depending on cell state.
    // -----------------------------------------------------------------------

    /// Parse the same way `default_docker_mirror_repo` does, without the
    /// OnceLock cache. Mirrors the inner `get_or_init` closure 1:1.
    fn build_default_mirror_value(raw: Option<&str>) -> Option<String> {
        raw.map(|s| s.to_string()).filter(|s| !s.is_empty())
    }

    #[test]
    fn test_default_mirror_unset_returns_none() {
        assert_eq!(build_default_mirror_value(None), None);
    }

    #[test]
    fn test_default_mirror_empty_string_returns_none() {
        // An empty AK_DEFAULT_DOCKER_MIRROR_REPO must not be treated as a
        // configured mirror; otherwise the SQL query would search for a
        // repo with key="" and the fallback could mask real 404s.
        assert_eq!(build_default_mirror_value(Some("")), None);
    }

    #[test]
    fn test_default_mirror_returns_set_value() {
        assert_eq!(
            build_default_mirror_value(Some("docker-hub-cache")),
            Some("docker-hub-cache".to_string())
        );
    }

    /// Pure-logic check on the routing decision: given the literal
    /// repo_key resolution and the configured mirror, what should
    /// effective_image be?
    #[test]
    fn test_mirror_routing_uses_full_image_name_on_fallback() {
        // The handler's behavior, expressed without DB access: when the
        // literal repo_key misses and a different mirror is configured,
        // the upstream proxy receives the FULL image_name as the path so
        // dockerd's `/v2/library/postgres/...` routes to the proxy with
        // image="library/postgres" (preserving the `library/` namespace).
        let image_name = "library/postgres";
        let (repo_key, image) = match image_name.find('/') {
            Some(idx) => (&image_name[..idx], &image_name[idx + 1..]),
            None => (image_name, image_name),
        };
        assert_eq!(repo_key, "library");
        assert_eq!(image, "postgres");

        // Literal lookup: repo_key="library" (would 404 in prod).
        // Fallback: effective_image becomes the full image_name.
        let effective_image_on_fallback = image_name.to_string();
        assert_eq!(effective_image_on_fallback, "library/postgres");

        // Without fallback: effective_image is the trimmed image.
        let effective_image_literal = image.to_string();
        assert_eq!(effective_image_literal, "postgres");
    }

    #[test]
    fn test_mirror_routing_skips_self_recursion() {
        // If a request comes in as `/v2/docker-hub-cache/library/postgres/...`
        // (someone addressing the proxy directly), repo_key matches the
        // mirror_key. The fallback's `mirror_key != repo_key` guard ensures
        // we don't double-resolve.
        let image_name = "docker-hub-cache/library/postgres";
        let mirror_key = "docker-hub-cache";
        let repo_key = match image_name.find('/') {
            Some(idx) => &image_name[..idx],
            None => image_name,
        };
        assert_eq!(repo_key, mirror_key);
        // The handler must take the literal path, not the fallback.
    }

    // -----------------------------------------------------------------------
    // Virtual-repo OCI delegation (PR #1419, refs #1348)
    //
    // The async resolvers `resolve_virtual_blob` / `resolve_virtual_manifest`
    // are exercised end-to-end by wiremock-backed `#[ignore]`d integration
    // tests under `backend/tests/oci_virtual_resolution_tests.rs`. Those
    // require a live Postgres so they do not count toward unit-test
    // coverage. The unit tests below pin each of the *pure* decision
    // helpers extracted out of the resolver hot path so the logic that
    // serves cache hits, rejects digest-mismatched upstream content, and
    // bounds the negative cache is covered without spinning up real
    // infrastructure.
    // -----------------------------------------------------------------------

    // candidate_upstream_images: edge-case coverage beyond the existing
    // happy-path tests above.

    #[test]
    fn test_candidate_upstream_images_http_docker_hub_normalises() {
        // Protocol stripping in `is_docker_hub` must also handle `http://`
        // (we sometimes see this in local-dev configs with TLS-terminating
        // sidecars). Bare `redis` must still be normalised to `library/redis`.
        assert_eq!(
            super::candidate_upstream_images("redis", "http://registry-1.docker.io"),
            vec!["library/redis".to_string()]
        );
    }

    #[test]
    fn test_candidate_upstream_images_subdomain_docker_io() {
        // `is_docker_hub` matches `host.ends_with(".docker.io")`. This
        // covers `index.docker.io`, `registry.docker.io`, etc.
        assert_eq!(
            super::candidate_upstream_images("nginx", "https://index.docker.io"),
            vec!["library/nginx".to_string()]
        );
    }

    #[test]
    fn test_candidate_upstream_images_quay_preserved_verbatim() {
        // Quay does not have a `library/` convention. The image must be
        // returned unmodified so `quay.io/prometheus/node-exporter` resolves
        // correctly.
        assert_eq!(
            super::candidate_upstream_images("prometheus/node-exporter", "https://quay.io"),
            vec!["prometheus/node-exporter".to_string()]
        );
    }

    #[test]
    fn test_candidate_upstream_images_internal_mirror_preserves_image() {
        // Internal mirror with arbitrary host. We must return a single
        // candidate equal to the input.
        let result =
            super::candidate_upstream_images("myorg/svc", "https://mirror.internal.example.com");
        assert_eq!(result, vec!["myorg/svc".to_string()]);
        assert_eq!(result.len(), 1, "no fallback round-trip must be emitted");
    }

    #[test]
    fn test_candidate_upstream_images_double_library_prefix_passthrough() {
        // Defensive: if a caller already passed `library/library/foo` (rare,
        // but possible via dockerd mirror-mode + a misconfigured upstream),
        // we don't strip it. The function only *adds* `library/`, never
        // rewrites an existing one.
        assert_eq!(
            super::candidate_upstream_images("library/library/foo", "https://registry-1.docker.io"),
            vec!["library/library/foo".to_string()]
        );
    }

    // upstream_blob_path / upstream_manifest_path: pure path formatters.

    #[test]
    fn test_upstream_blob_path_uses_v2_prefix() {
        assert_eq!(
            super::upstream_blob_path("library/alpine", "sha256:abc"),
            "v2/library/alpine/blobs/sha256:abc"
        );
    }

    #[test]
    fn test_upstream_blob_path_preserves_nested_image_name() {
        assert_eq!(
            super::upstream_blob_path(
                "myorg/sub/team/app",
                "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            ),
            "v2/myorg/sub/team/app/blobs/sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
    }

    #[test]
    fn test_upstream_manifest_path_tag_reference() {
        assert_eq!(
            super::upstream_manifest_path("library/postgres", "16-alpine"),
            "v2/library/postgres/manifests/16-alpine"
        );
    }

    #[test]
    fn test_upstream_manifest_path_digest_reference() {
        assert_eq!(
            super::upstream_manifest_path("nginx", "sha256:1234"),
            "v2/nginx/manifests/sha256:1234"
        );
    }

    // upstream_content_violates_digest: pure decision used by both
    // resolve_virtual_blob and resolve_virtual_manifest before serving
    // upstream content. This is the #1348 round-1 security fix.

    #[test]
    fn test_upstream_content_violates_digest_tag_reference_never_rejects() {
        // Tags carry no content-addressable contract: the resolver must
        // accept whatever upstream serves and let the caller compute the
        // digest itself.
        assert!(!super::upstream_content_violates_digest(
            "latest",
            b"any bytes here"
        ));
        assert!(!super::upstream_content_violates_digest("v1.2.3", b""));
    }

    #[test]
    fn test_upstream_content_violates_digest_matching_digest_accepts() {
        // sha256 of "hello world" is a well-known value. The resolver must
        // accept content whose computed digest equals the requested digest.
        let bytes = b"hello world";
        let digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(!super::upstream_content_violates_digest(digest, bytes));
    }

    #[test]
    fn test_upstream_content_violates_digest_mismatch_rejects() {
        // Requesting a digest that does *not* match the upstream's bytes
        // must trip the violation guard. This is the bytes-substitution
        // attack vector PR #1348 round 1 concern #3 closes.
        let bytes = b"hello world";
        // Anything other than the real sha256 of "hello world".
        let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(super::upstream_content_violates_digest(fake_digest, bytes));
    }

    #[test]
    fn test_upstream_content_violates_digest_empty_content_with_wrong_digest() {
        // Real sha256 of "" is e3b0c44...b855. Anything else with empty
        // content must be rejected.
        assert!(super::upstream_content_violates_digest(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            b""
        ));
    }

    #[test]
    fn test_upstream_content_violates_digest_empty_content_with_correct_digest() {
        // The canonical empty-string sha256 must pass.
        assert!(!super::upstream_content_violates_digest(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b""
        ));
    }

    #[test]
    fn test_upstream_content_violates_digest_invalid_digest_format_rejects() {
        // A reference that *looks* like a digest but fails `is_digest_reference`
        // (uppercase algorithm, empty algorithm, empty encoded) must not be
        // treated as a content-addressable assertion, even when the bytes
        // would not match. Belt-and-braces: violates_digest returns false
        // because `is_digest_reference` short-circuits to false first.
        assert!(!super::upstream_content_violates_digest(
            "SHA256:abc",
            b"hi"
        ));
        assert!(!super::upstream_content_violates_digest(":abc", b"hi"));
        assert!(!super::upstream_content_violates_digest("sha256:", b"hi"));
    }

    #[test]
    fn test_upstream_content_violates_digest_case_sensitive_hex_mismatch() {
        // sha256 hex digests are lowercase per the OCI grammar. An uppercase
        // hex reference does not equal the lowercase computed digest, so the
        // helper must reject it as a mismatch.
        let bytes = b"hello world";
        let upper = "sha256:B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
        assert!(super::upstream_content_violates_digest(upper, bytes));
    }

    // verify_digest_or_fall_through: positive-sense counterpart used by
    // resolver call sites to keep the control flow readable. The wrapper is
    // a strict negation of upstream_content_violates_digest; the tests here
    // pin both that contract and the call-site idiom ("continue when false").

    #[test]
    fn test_verify_digest_or_fall_through_tag_reference_always_accepts() {
        // Tags have no content-addressable contract — the caller must
        // forward whatever upstream served and compute the digest itself.
        assert!(super::verify_digest_or_fall_through(b"anything", "latest"));
        assert!(super::verify_digest_or_fall_through(b"", "v1.2.3"));
        assert!(super::verify_digest_or_fall_through(
            b"\x00\x01\x02",
            "release-candidate"
        ));
    }

    #[test]
    fn test_verify_digest_or_fall_through_matching_digest_accepts() {
        let bytes = b"hello world";
        let digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(super::verify_digest_or_fall_through(bytes, digest));
    }

    #[test]
    fn test_verify_digest_or_fall_through_mismatched_digest_falls_through() {
        // The exact resolver idiom: "false" means the caller should `continue`
        // to the next virtual-repo member instead of forwarding bytes.
        let bytes = b"hello world";
        let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!super::verify_digest_or_fall_through(bytes, wrong));
    }

    #[test]
    fn test_verify_digest_or_fall_through_empty_content_with_canonical_digest() {
        // The canonical empty-string sha256 verifies correctly.
        let canonical = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(super::verify_digest_or_fall_through(b"", canonical));
    }

    #[test]
    fn test_verify_digest_or_fall_through_empty_content_with_wrong_digest_falls_through() {
        // Empty body + non-canonical empty-digest = mismatch, must fall through.
        let wrong = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        assert!(!super::verify_digest_or_fall_through(b"", wrong));
    }

    #[test]
    fn test_verify_digest_or_fall_through_invalid_digest_format_accepts() {
        // Malformed digest references (uppercase algorithm, empty parts) are
        // *not* content-addressable. The wrapper treats them as tag-like and
        // accepts the content; the caller still computes a digest from the
        // bytes for response headers.
        assert!(super::verify_digest_or_fall_through(b"hi", "SHA256:abc"));
        assert!(super::verify_digest_or_fall_through(b"hi", ":abc"));
        assert!(super::verify_digest_or_fall_through(b"hi", "sha256:"));
    }

    #[test]
    fn test_verify_digest_or_fall_through_is_inverse_of_violates_digest() {
        // Property: the wrapper is the strict negation of the underlying
        // helper across both branch outputs.
        let cases: &[(&[u8], &str)] = &[
            (b"hello world", "latest"),
            (
                b"hello world",
                "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            ),
            (
                b"hello world",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                b"",
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (b"hi", "SHA256:abc"),
        ];
        for (bytes, reference) in cases {
            assert_eq!(
                super::verify_digest_or_fall_through(bytes, reference),
                !super::upstream_content_violates_digest(reference, bytes),
                "wrapper must invert violates_digest for ({:?}, {:?})",
                std::str::from_utf8(bytes).unwrap_or("<binary>"),
                reference,
            );
        }
    }

    #[test]
    fn test_verify_digest_or_fall_through_large_content_canonical_digest() {
        // Realistic OCI blob size (~256KiB) of a deterministic byte pattern.
        // Confirms the helper computes the digest over the *whole* slice,
        // not just a prefix, by feeding a pattern whose sha256 we precompute.
        let bytes: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let computed = super::compute_sha256(&bytes);
        assert!(super::verify_digest_or_fall_through(&bytes, &computed));

        // And a one-byte truncation must trip the mismatch path.
        let truncated = &bytes[..bytes.len() - 1];
        assert!(!super::verify_digest_or_fall_through(truncated, &computed));
    }

    // VirtualResolveKey / VirtualResolveKind: constructor, equality,
    // hashing. The cache uses this as a hashmap key so each field must
    // participate in equality.

    #[test]
    fn test_virtual_resolve_key_new_roundtrip() {
        let id = Uuid::new_v4();
        let key = VirtualResolveKey::new(id, VirtualResolveKind::Blob, "alpine", "sha256:abc");
        assert_eq!(key.repo_id, id);
        assert_eq!(key.kind, VirtualResolveKind::Blob);
        assert_eq!(key.image, "alpine");
        assert_eq!(key.reference, "sha256:abc");
    }

    #[test]
    fn test_virtual_resolve_key_equality_uses_all_fields() {
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let base = VirtualResolveKey::new(id, VirtualResolveKind::Blob, "alpine", "sha256:abc");

        // Same fields are equal.
        assert_eq!(
            base,
            VirtualResolveKey::new(id, VirtualResolveKind::Blob, "alpine", "sha256:abc")
        );
        // Different repo_id differentiates.
        assert_ne!(
            base,
            VirtualResolveKey::new(other, VirtualResolveKind::Blob, "alpine", "sha256:abc")
        );
        // Different kind differentiates: blob and manifest caches must not collide.
        assert_ne!(
            base,
            VirtualResolveKey::new(id, VirtualResolveKind::Manifest, "alpine", "sha256:abc")
        );
        // Different image differentiates.
        assert_ne!(
            base,
            VirtualResolveKey::new(id, VirtualResolveKind::Blob, "nginx", "sha256:abc")
        );
        // Different reference differentiates: a tag and digest miss for
        // the same image must be cached separately.
        assert_ne!(
            base,
            VirtualResolveKey::new(id, VirtualResolveKind::Blob, "alpine", "sha256:def")
        );
    }

    #[test]
    fn test_virtual_resolve_key_hashes_consistently() {
        // HashMap relies on `Eq` and `Hash` agreeing. Two keys built with
        // the same inputs must hash identically.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let id = Uuid::new_v4();
        let k1 = VirtualResolveKey::new(id, VirtualResolveKind::Manifest, "img", "latest");
        let k2 = VirtualResolveKey::new(id, VirtualResolveKind::Manifest, "img", "latest");
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        k1.hash(&mut h1);
        k2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn test_virtual_resolve_kind_distinct() {
        assert_ne!(VirtualResolveKind::Blob, VirtualResolveKind::Manifest);
    }

    // negative_cache_entry_is_fresh: TTL decision boundary.

    #[test]
    fn test_negative_cache_entry_is_fresh_well_within_ttl() {
        let ttl = std::time::Duration::from_secs(5);
        assert!(super::negative_cache_entry_is_fresh(
            std::time::Duration::from_millis(100),
            ttl
        ));
    }

    #[test]
    fn test_negative_cache_entry_is_fresh_just_before_ttl() {
        let ttl = std::time::Duration::from_secs(5);
        assert!(super::negative_cache_entry_is_fresh(
            std::time::Duration::from_millis(4_999),
            ttl
        ));
    }

    #[test]
    fn test_negative_cache_entry_is_fresh_exactly_at_ttl_is_stale() {
        // Strict `<` comparison: an entry whose age equals the TTL is no
        // longer fresh. This matters because Tokio's coarse timer can land
        // exactly on the boundary on overloaded CI runners.
        let ttl = std::time::Duration::from_secs(5);
        assert!(!super::negative_cache_entry_is_fresh(ttl, ttl));
    }

    #[test]
    fn test_negative_cache_entry_is_fresh_past_ttl_is_stale() {
        let ttl = std::time::Duration::from_secs(5);
        assert!(!super::negative_cache_entry_is_fresh(
            std::time::Duration::from_secs(6),
            ttl
        ));
    }

    // negative_cache_should_evict_before_insert: capacity decision.

    #[test]
    fn test_negative_cache_should_not_evict_when_under_cap() {
        assert!(!super::negative_cache_should_evict_before_insert(0, 4096));
        assert!(!super::negative_cache_should_evict_before_insert(
            4095, 4096
        ));
    }

    #[test]
    fn test_negative_cache_should_evict_at_cap() {
        // `>=` boundary: when we hit the cap exactly, the insertion path
        // must attempt eviction before recording a new entry, otherwise we
        // would exceed the bound by one entry on every insert.
        assert!(super::negative_cache_should_evict_before_insert(4096, 4096));
    }

    #[test]
    fn test_negative_cache_should_evict_when_over_cap() {
        assert!(super::negative_cache_should_evict_before_insert(
            10_000, 4096
        ));
    }

    #[test]
    fn test_virtual_negative_cache_constants_are_sensible() {
        // Pin the configured TTL and cap so an accidental edit (e.g.
        // bumping TTL to 5 minutes) trips review attention.
        assert_eq!(super::VIRTUAL_NEGATIVE_CACHE_TTL_MS, 5_000);
        assert_eq!(super::VIRTUAL_NEGATIVE_CACHE_MAX_ENTRIES, 4096);
    }

    // virtual_negative_cache hit / insert: end-to-end roundtrip through the
    // process-global cache. The cache is process-local and shared across
    // tests, so we isolate per-test state by using a fresh random `repo_id`
    // in every test rather than calling `virtual_negative_cache_clear()`
    // (which would race against other tests' inserts under
    // `cargo test`'s default parallel runner).

    #[test]
    fn test_virtual_negative_cache_hit_returns_false_on_unseen_key() {
        // A freshly-generated repo_id has never been inserted, so the
        // cache must report no hit. No `clear()` needed: the UUID is
        // unique to this test.
        let key = VirtualResolveKey::new(
            Uuid::new_v4(),
            VirtualResolveKind::Blob,
            "never-inserted",
            "sha256:zzz",
        );
        assert!(!super::virtual_negative_cache_hit(&key));
    }

    #[test]
    fn test_virtual_negative_cache_insert_then_hit() {
        let id = Uuid::new_v4();
        let key = VirtualResolveKey::new(
            id,
            VirtualResolveKind::Manifest,
            "alpine",
            "sha256:cachehit",
        );
        // Sanity: before insert, no hit for this unique key.
        assert!(!super::virtual_negative_cache_hit(&key));
        super::virtual_negative_cache_insert(key.clone());
        assert!(super::virtual_negative_cache_hit(&key));
    }

    #[test]
    fn test_virtual_negative_cache_blob_and_manifest_kinds_are_isolated() {
        // The same image+reference cached as a Blob miss must not
        // short-circuit a Manifest probe (and vice-versa). The `kind`
        // field is part of the cache key for exactly this reason. We use
        // a fresh repo_id so this test doesn't interact with any other
        // running in parallel.
        let id = Uuid::new_v4();
        let blob_key =
            VirtualResolveKey::new(id, VirtualResolveKind::Blob, "alpine", "sha256:shared");
        let manifest_key =
            VirtualResolveKey::new(id, VirtualResolveKind::Manifest, "alpine", "sha256:shared");
        // Sanity: both kinds are uncached for this unique repo_id.
        assert!(!super::virtual_negative_cache_hit(&blob_key));
        assert!(!super::virtual_negative_cache_hit(&manifest_key));
        super::virtual_negative_cache_insert(blob_key.clone());
        assert!(super::virtual_negative_cache_hit(&blob_key));
        // The manifest variant of the same image+reference must still
        // miss: kinds are isolated.
        assert!(!super::virtual_negative_cache_hit(&manifest_key));
    }

    // Note: `virtual_negative_cache_clear()` is exercised by the
    // wiremock-backed integration tests in
    // `backend/tests/oci_virtual_resolution_tests.rs`, which run serially
    // against a real DB. We deliberately do not invoke `clear()` from any
    // unit test below because `cargo test`'s default parallel runner would
    // let one test's `clear()` wipe another test's just-inserted entry.

    // VirtualBlobResolution variant construction. The `Local` variant
    // boxes the owning `Repository` to keep the enum small
    // (clippy::large_enum_variant); the `Remote` variant carries a
    // `Bytes` body. Pin the field layout so accidental reshuffles fail
    // here rather than at a serialisation boundary.

    #[test]
    fn test_virtual_blob_resolution_remote_variant_fields() {
        let resolution = VirtualBlobResolution::Remote {
            content: Bytes::from_static(b"layer-bytes"),
            content_type: Some("application/octet-stream".to_string()),
        };
        match resolution {
            VirtualBlobResolution::Remote {
                content,
                content_type,
            } => {
                assert_eq!(content.as_ref(), b"layer-bytes");
                assert_eq!(content_type.as_deref(), Some("application/octet-stream"));
            }
            VirtualBlobResolution::Local { .. } => {
                panic!("Remote variant constructed but Local matched");
            }
        }
    }

    #[test]
    fn test_virtual_blob_resolution_remote_variant_without_content_type() {
        // Upstreams that omit Content-Type should still produce a usable
        // resolution; the caller will fall back to a default media type.
        let resolution = VirtualBlobResolution::Remote {
            content: Bytes::new(),
            content_type: None,
        };
        if let VirtualBlobResolution::Remote { content_type, .. } = resolution {
            assert!(content_type.is_none());
        } else {
            panic!("expected Remote variant");
        }
    }

    // -----------------------------------------------------------------------
    // Extracted pure helpers for #1419 virtual-resolver coverage.
    // -----------------------------------------------------------------------
    //
    // `negative_cache_evict_and_has_room`, `local_blob_resolution`,
    // `should_attempt_remote_member`, `finalize_upstream_blob`, and
    // `finalize_upstream_manifest` were carved out of the async resolver
    // hot path so the decision logic that previously lived inline could
    // be covered by unit tests without standing up a Postgres + wiremock
    // pair. These tests exercise the small purified pieces; the
    // wiremock-backed integration tests in
    // `backend/tests/oci_virtual_resolution_tests.rs` still cover the
    // end-to-end resolver behaviour with a real DB.

    fn build_test_repository(
        repo_type: RepositoryType,
        upstream_url: Option<&str>,
    ) -> crate::models::repository::Repository {
        use crate::models::repository::{ReplicationPriority, Repository, RepositoryFormat};
        Repository {
            id: Uuid::new_v4(),
            key: "test-repo".to_string(),
            name: "test-repo".to_string(),
            description: None,
            format: RepositoryFormat::Docker,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/test-repo".to_string(),
            upstream_url: upstream_url.map(|s| s.to_string()),
            is_public: true,
            quota_bytes: None,
            replication_priority: ReplicationPriority::Scheduled,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    // negative_cache_evict_and_has_room: pure cap-and-evict step on a
    // fresh `HashMap`. Exercised here rather than against the process-
    // global cache so capacity-edge behaviour can be pinned without
    // affecting other tests' inserts.

    #[test]
    fn test_negative_cache_evict_and_has_room_under_cap_short_circuits() {
        let mut map: std::collections::HashMap<u32, std::time::Instant> =
            std::collections::HashMap::new();
        map.insert(1, std::time::Instant::now());
        let ttl = std::time::Duration::from_secs(5);
        let now = std::time::Instant::now();
        // Under the cap (1 < 4): no eviction required, returns true and
        // leaves the map untouched.
        assert!(super::negative_cache_evict_and_has_room(
            &mut map, ttl, now, 4
        ));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_negative_cache_evict_and_has_room_evicts_all_expired_and_grants_room() {
        let mut map: std::collections::HashMap<u32, std::time::Instant> =
            std::collections::HashMap::new();
        // Two entries inserted "long ago" — both will be evicted as expired.
        let long_ago = std::time::Instant::now() - std::time::Duration::from_secs(60);
        map.insert(1, long_ago);
        map.insert(2, long_ago);
        let ttl = std::time::Duration::from_secs(5);
        let now = std::time::Instant::now();
        // At the cap (2 >= 2): eviction kicks in, both expired entries
        // are dropped, room is granted.
        assert!(super::negative_cache_evict_and_has_room(
            &mut map, ttl, now, 2
        ));
        assert!(
            map.is_empty(),
            "expired entries must be evicted to make room"
        );
    }

    #[test]
    fn test_negative_cache_evict_and_has_room_refuses_when_all_fresh() {
        let mut map: std::collections::HashMap<u32, std::time::Instant> =
            std::collections::HashMap::new();
        // Two fresh entries at the cap — neither is expired, so the
        // helper must refuse the insert by returning false.
        let now = std::time::Instant::now();
        map.insert(1, now);
        map.insert(2, now);
        let ttl = std::time::Duration::from_secs(60);
        assert!(!super::negative_cache_evict_and_has_room(
            &mut map, ttl, now, 2
        ));
        assert_eq!(
            map.len(),
            2,
            "no entries should be evicted when none are expired"
        );
    }

    #[test]
    fn test_negative_cache_evict_and_has_room_evicts_only_expired_subset() {
        let mut map: std::collections::HashMap<u32, std::time::Instant> =
            std::collections::HashMap::new();
        let now = std::time::Instant::now();
        let long_ago = now - std::time::Duration::from_secs(60);
        // One stale, one fresh, cap = 2. After eviction the fresh entry
        // remains and there's room for one more.
        map.insert(1, long_ago);
        map.insert(2, now);
        let ttl = std::time::Duration::from_secs(5);
        assert!(super::negative_cache_evict_and_has_room(
            &mut map, ttl, now, 2
        ));
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&2));
    }

    #[test]
    fn test_virtual_negative_cache_clear_drops_existing_entries() {
        // The integration tests rely on `virtual_negative_cache_clear()`
        // to isolate themselves from sibling tests' inserts. Cover the
        // wipe semantics here so the pure clear path is exercised
        // without depending on the test harness ordering.
        let id = Uuid::new_v4();
        let key = VirtualResolveKey::new(
            id,
            VirtualResolveKind::Blob,
            "clear-target",
            "sha256:cleared",
        );
        super::virtual_negative_cache_insert(key.clone());
        assert!(super::virtual_negative_cache_hit(&key));
        super::virtual_negative_cache_clear();
        assert!(
            !super::virtual_negative_cache_hit(&key),
            "clear() must drop the just-inserted entry"
        );
    }

    // local_blob_resolution: pure DB-row → Local-variant constructor.

    #[test]
    fn test_local_blob_resolution_none_input_yields_none() {
        let member = build_test_repository(RepositoryType::Local, None);
        assert!(super::local_blob_resolution(None, &member).is_none());
    }

    #[test]
    fn test_local_blob_resolution_some_input_constructs_local_variant() {
        let member = build_test_repository(RepositoryType::Local, None);
        let member_id = member.id;
        let resolution =
            super::local_blob_resolution(Some((1024, "oci-blobs/sha256:abc".into())), &member)
                .expect("Some input must produce a Local resolution");
        match resolution {
            VirtualBlobResolution::Local {
                size_bytes,
                storage_key,
                member,
            } => {
                assert_eq!(size_bytes, 1024);
                assert_eq!(storage_key, "oci-blobs/sha256:abc");
                assert_eq!(member.id, member_id);
            }
            VirtualBlobResolution::Remote { .. } => {
                panic!("expected Local variant from local_blob_resolution");
            }
        }
    }

    // should_attempt_remote_member: 2x2x2 truth-table of the
    // (repo_type == Remote, has_proxy_service, has_upstream_url)
    // predicate. The function only returns true on `(true, true, true)`.

    #[test]
    fn test_should_attempt_remote_member_remote_with_proxy_and_url() {
        let m = build_test_repository(RepositoryType::Remote, Some("https://ghcr.io"));
        assert!(super::should_attempt_remote_member(&m, true, true));
    }

    #[test]
    fn test_should_attempt_remote_member_remote_missing_proxy() {
        let m = build_test_repository(RepositoryType::Remote, Some("https://ghcr.io"));
        // ProxyService not wired up: must not attempt upstream.
        assert!(!super::should_attempt_remote_member(&m, false, true));
    }

    #[test]
    fn test_should_attempt_remote_member_remote_missing_url() {
        let m = build_test_repository(RepositoryType::Remote, None);
        // Member has no upstream_url configured: nothing to fetch.
        assert!(!super::should_attempt_remote_member(&m, true, false));
    }

    #[test]
    fn test_should_attempt_remote_member_local_repo_is_skipped() {
        let m = build_test_repository(RepositoryType::Local, Some("https://ghcr.io"));
        // Local-typed member must never trigger an upstream fetch even
        // if a stale `upstream_url` is present.
        assert!(!super::should_attempt_remote_member(&m, true, true));
    }

    #[test]
    fn test_should_attempt_remote_member_virtual_repo_is_skipped() {
        let m = build_test_repository(RepositoryType::Virtual, Some("https://ghcr.io"));
        // Virtual members would recurse — the resolver only delegates to
        // genuinely remote members.
        assert!(!super::should_attempt_remote_member(&m, true, true));
    }

    #[test]
    fn test_should_attempt_remote_member_staging_repo_is_skipped() {
        let m = build_test_repository(RepositoryType::Staging, Some("https://ghcr.io"));
        // Staging repos host promotion targets, not upstream proxies.
        assert!(!super::should_attempt_remote_member(&m, true, true));
    }

    // finalize_upstream_blob: verify-then-wrap step for the resolver.

    #[test]
    fn test_finalize_upstream_blob_matching_digest_returns_remote() {
        let bytes = Bytes::from_static(b"hello world");
        let digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let result =
            super::finalize_upstream_blob(digest, bytes.clone(), Some("application/json".into()))
                .expect("matching digest must produce a Remote resolution");
        match result {
            VirtualBlobResolution::Remote {
                content,
                content_type,
            } => {
                assert_eq!(content, bytes);
                assert_eq!(content_type.as_deref(), Some("application/json"));
            }
            VirtualBlobResolution::Local { .. } => {
                panic!("finalize_upstream_blob must never construct a Local variant");
            }
        }
    }

    #[test]
    fn test_finalize_upstream_blob_mismatched_digest_falls_through() {
        // The exact bytes-substitution attack vector PR #1348 closes:
        // upstream serves "hello world" under a non-matching digest.
        // finalize_upstream_blob must refuse the response so the resolver
        // can `continue` to the next virtual-repo member.
        let bytes = Bytes::from_static(b"hello world");
        let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(super::finalize_upstream_blob(wrong, bytes, None).is_none());
    }

    #[test]
    fn test_finalize_upstream_blob_empty_body_with_canonical_digest_accepts() {
        let canonical = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result = super::finalize_upstream_blob(canonical, Bytes::new(), None)
            .expect("canonical empty-string digest must verify against empty content");
        if let VirtualBlobResolution::Remote { content, .. } = result {
            assert!(content.is_empty());
        } else {
            panic!("expected Remote variant");
        }
    }

    // finalize_upstream_manifest: verify-then-compute step for manifest
    // resolution.

    #[test]
    fn test_finalize_upstream_manifest_tag_reference_always_accepts_and_computes_digest() {
        let body = Bytes::from_static(b"{\"schemaVersion\":2}");
        let (returned_digest, ct, content) =
            super::finalize_upstream_manifest("latest", body.clone(), Some("ct".into()))
                .expect("tag reference must always accept and return a computed digest");
        assert_eq!(content, body);
        assert_eq!(ct.as_deref(), Some("ct"));
        assert_eq!(returned_digest, super::compute_sha256(&body));
        // Sanity: the returned digest is `sha256:`-prefixed per the OCI
        // grammar.
        assert!(returned_digest.starts_with("sha256:"));
    }

    #[test]
    fn test_finalize_upstream_manifest_matching_digest_returns_computed_digest() {
        let body = Bytes::from_static(b"hello world");
        let requested = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let (returned_digest, _ct, content) =
            super::finalize_upstream_manifest(requested, body.clone(), None)
                .expect("matching digest must accept");
        // The resolver returns the COMPUTED digest (not the requested
        // one), guaranteeing the response header is always honest about
        // what was served. For a match, the two are byte-for-byte equal.
        assert_eq!(returned_digest, requested);
        assert_eq!(content, body);
    }

    #[test]
    fn test_finalize_upstream_manifest_mismatched_digest_ref_falls_through() {
        // The #1348 concern-3 attack: upstream tampers with a manifest
        // when the client asked for a specific digest. The resolver
        // must refuse so the caller advances to the next member.
        let body = Bytes::from_static(b"{\"evil\":true}");
        let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(super::finalize_upstream_manifest(wrong, body, None).is_none());
    }

    #[test]
    fn test_finalize_upstream_manifest_invalid_digest_format_treated_as_tag() {
        // A reference that is not a valid OCI digest is treated as a tag:
        // the helper accepts the bytes and returns the computed sha256 as
        // the response digest. (`is_digest_reference` rejects uppercase
        // algorithm strings; everything else flows through the tag path.)
        let body = Bytes::from_static(b"hi");
        let (returned_digest, _ct, _content) =
            super::finalize_upstream_manifest("SHA256:nope", body.clone(), None)
                .expect("malformed digest reference must be treated as a tag");
        assert_eq!(returned_digest, super::compute_sha256(&body));
    }
}

// ---------------------------------------------------------------------------
// Deactivated user must not be able to swap a still-valid Bearer JWT for a
// fresh OCI access token. DB-backed because the bug is observable only with
// a real `users` row that we can flip `is_active` on between issuing the JWT
// and the swap.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod token_claims_isactive_regression_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::auth_service::AuthService;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Pre-fix the Bearer-JWT swap path in `token()` selected the user by id
    /// without an `is_active` filter. A deactivated user with an unexpired
    /// JWT in hand could still mint a fresh OCI access token. This test
    /// pins the corrected SQL.
    #[tokio::test]
    async fn deactivated_user_cannot_swap_bearer_jwt_for_oci_token() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let storage_dir = std::env::temp_dir().join(format!("oci-isactive-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        // Sign a JWT for the user using the same AuthService the handler
        // would, then flip is_active=false BEFORE the swap.
        let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
        let user = sqlx::query_as!(
            crate::models::user::User,
            r#"SELECT id, username, email, password_hash, display_name,
               auth_provider as "auth_provider: crate::models::user::AuthProvider",
               external_id, is_admin, is_active, is_service_account, must_change_password,
               totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
               failed_login_attempts, locked_until, last_failed_login_at,
               password_changed_at, last_login_at, created_at, updated_at
               FROM users WHERE id = $1"#,
            user_id
        )
        .fetch_one(&pool)
        .await
        .expect("fetch user");
        let tokens = auth_service.generate_tokens(&user).expect("sign jwt");

        sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("deactivate user");

        let req = Request::builder()
            .method("GET")
            .uri("/token")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(Body::empty())
            .unwrap();
        let app = router().with_state(state);
        let resp = app.oneshot(req).await.expect("oneshot");
        let status = resp.status();

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "deactivated user must not be able to swap Bearer JWT for fresh OCI token"
        );
    }
}

#[cfg(test)]
mod blob_pull_streaming_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// GET blob (CAS hit) must STREAM the object from the storage backend with a
    /// `Content-Length` sourced from `oci_blobs.size_bytes`, not buffer the
    /// whole (potentially multi-GiB) layer in heap. (#1528)
    #[tokio::test]
    async fn get_blob_streams_from_backend_with_size_bytes_content_length() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        // Public repo so an anonymous token can pull.
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("make repo public");

        let location = crate::storage::StorageLocation {
            backend: "filesystem".to_string(),
            path: fx.storage_dir.to_string_lossy().into_owned(),
        };
        let storage = fx
            .state
            .storage_for_repo(&location)
            .expect("resolve storage");

        let body_bytes = b"a layer blob served by streaming from the storage backend".to_vec();
        let digest = format!("sha256:{}", "c".repeat(64));
        let blob_key = format!("oci-blobs/{digest}");
        storage
            .put(&blob_key, bytes::Bytes::from(body_bytes.clone()))
            .await
            .expect("write blob object");
        sqlx::query(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(fx.repo_id)
        .bind(&digest)
        .bind(body_bytes.len() as i64)
        .bind(&blob_key)
        .execute(&fx.pool)
        .await
        .expect("insert oci_blobs row");

        let app = fx.router_anon(router());
        let req = Request::builder()
            .method("GET")
            .uri(format!("/{}/myimage/blobs/{}", fx.repo_key, digest))
            .header(AUTHORIZATION, format!("Bearer {ANONYMOUS_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let got = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .expect("collect streamed body");

        fx.teardown().await;

        assert_eq!(status, StatusCode::OK, "CAS-hit GET blob must return 200");
        assert_eq!(
            content_length.as_deref(),
            Some(body_bytes.len().to_string().as_str()),
            "Content-Length must come from oci_blobs.size_bytes"
        );
        assert_eq!(
            &got[..],
            &body_bytes[..],
            "streamed body must round-trip the stored blob bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// `docker login -p $API_TOKEN` regression: API-token-as-password must not
// bump `failed_login_attempts`. DB-backed because the bug is observable only
// after `authenticate` runs against a real user row.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod token_lockout_regression_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::auth_service::AuthService;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Pre-fix the OCI token endpoint called `auth_service::authenticate`
    /// before `validate_api_token`. `authenticate(username, api_token)`
    /// bcrypt-compares the API token against the user's password hash,
    /// always a mismatch, and bumps `failed_login_attempts`. After
    /// `account_lockout_threshold` CI builds the service account locked
    /// itself out. This test pins the corrected order.
    #[tokio::test]
    async fn api_token_basic_auth_does_not_bump_failed_login_attempts() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;

        // tdh::create_user inserts password_hash = 'unused'. Replace with a
        // real bcrypt hash so `authenticate(username, api_token)` exercises
        // the bcrypt-mismatch path that bumps the counter, rather than
        // short-circuiting on a malformed-hash Err. cost=4 keeps the test
        // sub-second.
        let pwd_hash = bcrypt::hash("real-test-password", 4).expect("bcrypt hash");
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(&pwd_hash)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("update password_hash");

        let storage_dir = std::env::temp_dir().join(format!("oci-lockout-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
        let (api_token, _) = auth_service
            .generate_api_token(user_id, "lockout-regression", vec!["*".to_string()], None)
            .await
            .expect("generate API token");

        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{api_token}"))
        );
        let req = Request::builder()
            .method("GET")
            .uri("/token")
            .header("Authorization", basic)
            .body(Body::empty())
            .unwrap();
        let app = router().with_state(state);
        let resp = app.oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();

        // Read the counter BEFORE cleanup so the assertion reflects the
        // state set by `token()`.
        let counter: i32 =
            sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("read counter");

        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            status,
            StatusCode::OK,
            "expected 200, got {status}: body={body}"
        );
        let token = body["token"].as_str().expect("token field");
        assert_ne!(token, "anonymous", "API token must yield a real JWT");
        assert_eq!(
            counter, 0,
            "API-token-as-password must not bump failed_login_attempts (got {counter})"
        );
    }

    /// Sibling to the API-token-first regression: the password-fallback arm
    /// must still mint a JWT after the reorder. Specifically, `Basic
    /// <user>:<real_password>` is the standard human `docker login` flow and
    /// must keep working after `validate_api_token` is tried first.
    ///
    /// The constant-time bcrypt pad inside `validate_api_token` makes the
    /// fallback path correct today (the API-token-shaped lookup returns Err
    /// for a real password, and we fall through to `authenticate`). Pinning
    /// it here keeps that invariant from regressing if anyone later
    /// "optimizes" the dummy-hash code path without realizing the OCI handler
    /// depends on it.
    #[tokio::test]
    async fn password_basic_auth_falls_through_to_authenticate() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;

        let pwd_hash = bcrypt::hash("real-test-password", 4).expect("bcrypt hash");
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(&pwd_hash)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("update password_hash");

        let storage_dir = std::env::temp_dir().join(format!("oci-pwd-fallback-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{username}:real-test-password"))
        );
        let req = Request::builder()
            .method("GET")
            .uri("/token")
            .header("Authorization", basic)
            .body(Body::empty())
            .unwrap();
        let app = router().with_state(state);
        let resp = app.oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();

        // Read counter BEFORE cleanup so we see the state token() left.
        let counter: i32 =
            sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("read counter");

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            status,
            StatusCode::OK,
            "real-password basic auth must succeed after the reorder, \
             got {status}: body={body}"
        );
        let token = body["token"].as_str().expect("token field");
        assert_ne!(
            token, "anonymous",
            "password fallback must yield a real JWT, not anonymous"
        );
        assert_eq!(
            counter, 0,
            "a successful password login must not leave failed_login_attempts \
             elevated (got {counter})"
        );
    }

    /// Regression for #1195. The `/v2/token` exchange was reordered in #1145
    /// so API tokens are tried first, but `authenticate_oci` (used by every
    /// non-token verb: manifest GET, blob HEAD, blob PUT, catalog, etc.) had
    /// the same bug: it called `authenticate(user, api_token)` before
    /// `validate_api_token(api_token)`. Clients that skip the token exchange
    /// and send `Basic <user>:<api_token>` on every verb (curl, some CI
    /// runners, registry mirrors) bumped `failed_login_attempts` once per
    /// request and locked the account out after `account_lockout_threshold`
    /// calls. This test exercises `authenticate_oci` directly and asserts
    /// the counter stays at zero across many requests.
    #[tokio::test]
    async fn authenticate_oci_verb_basic_auth_does_not_bump_failed_login_attempts() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;

        // Real bcrypt hash so the `authenticate` arm (which bumps the
        // counter on bcrypt mismatch) is reachable, not short-circuited.
        let pwd_hash = bcrypt::hash("real-test-password", 4).expect("bcrypt hash");
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(&pwd_hash)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("update password_hash");

        let storage_dir = std::env::temp_dir().join(format!("oci-verb-lockout-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
        let (api_token, _) = auth_service
            .generate_api_token(
                user_id,
                "verb-lockout-regression",
                vec!["*".to_string()],
                None,
            )
            .await
            .expect("generate API token");

        // Drive `authenticate_oci` directly: that is the function the bug
        // lives in, and it does not need a repository row to exercise.
        let basic_value = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{api_token}"))
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            axum::http::HeaderValue::from_str(&basic_value).expect("valid basic header"),
        );

        // Call it several times so the regression would be obvious if the
        // counter incremented per-request. `account_lockout_threshold`
        // defaults to a low number, so even 5 calls is enough to lock out
        // pre-fix.
        for _ in 0..5 {
            let result = authenticate_oci(&state.db, &state.config, &headers).await;
            assert!(
                result.is_ok(),
                "API-token Basic auth must succeed via authenticate_oci",
            );
        }

        let counter: i32 =
            sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("read counter");

        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            counter, 0,
            "authenticate_oci with Basic <user>:<api_token> must not bump \
             failed_login_attempts (got {counter} after 5 requests)"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests for the #1179 multi-arch index-manifest reference helpers.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod oci_manifest_refs_tests {
    use super::*;

    #[test]
    fn is_index_content_type_matches_oci_and_docker_index() {
        assert!(is_index_content_type(
            "application/vnd.oci.image.index.v1+json"
        ));
        assert!(is_index_content_type(
            "application/vnd.docker.distribution.manifest.list.v2+json"
        ));
    }

    #[test]
    fn is_index_content_type_rejects_regular_image_manifests() {
        assert!(!is_index_content_type(
            "application/vnd.oci.image.manifest.v1+json"
        ));
        assert!(!is_index_content_type(
            "application/vnd.docker.distribution.manifest.v2+json"
        ));
        assert!(!is_index_content_type("application/json"));
        assert!(!is_index_content_type(""));
    }

    #[test]
    fn is_index_content_type_ignores_params_and_case() {
        // RFC 7231 lets media-type tokens carry parameters; clients in
        // the wild do attach `charset=utf-8` and similar. The check
        // should look at the bare type only.
        assert!(is_index_content_type(
            "application/vnd.oci.image.index.v1+json; charset=utf-8"
        ));
        assert!(is_index_content_type(
            "  Application/vnd.oci.image.index.v1+JSON  "
        ));
    }

    #[test]
    fn extract_child_digests_parses_oci_index() {
        let body = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:aaaa",
                    "size": 100,
                    "platform": {"architecture": "amd64", "os": "linux"}
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:bbbb",
                    "size": 100,
                    "platform": {"architecture": "arm64", "os": "linux"}
                }
            ]
        }"#;
        let children = extract_child_digests(body);
        assert_eq!(children, vec!["sha256:aaaa", "sha256:bbbb"]);
    }

    #[test]
    fn extract_child_digests_empty_for_regular_image_manifest() {
        let body = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"size": 7023, "digest": "sha256:cccc"},
            "layers": [{"size": 32654, "digest": "sha256:dddd"}]
        }"#;
        let children = extract_child_digests(body);
        assert!(
            children.is_empty(),
            "regular image manifest has no `manifests` array"
        );
    }

    #[test]
    fn extract_child_digests_empty_for_malformed_json() {
        assert!(extract_child_digests(b"not json").is_empty());
        assert!(extract_child_digests(b"").is_empty());
        assert!(extract_child_digests(b"{").is_empty());
    }

    #[test]
    fn extract_child_digests_skips_entries_missing_digest() {
        let body = br#"{
            "manifests": [
                {"digest": "sha256:aaaa"},
                {"platform": {"architecture": "arm64"}},
                {"digest": null},
                {"digest": "sha256:bbbb"}
            ]
        }"#;
        let children = extract_child_digests(body);
        assert_eq!(children, vec!["sha256:aaaa", "sha256:bbbb"]);
    }

    // -- manifest_blob_refs (#1635) blob-edge extraction --------------------

    #[test]
    fn extract_blob_refs_parses_config_and_layers() {
        let body = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": 7023,
                "digest": "sha256:config0"
            },
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": 32654, "digest": "sha256:layer1"},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": 16724, "digest": "sha256:layer2"}
            ]
        }"#;
        let refs = extract_blob_refs(body);
        assert_eq!(
            refs,
            vec![
                BlobRef {
                    digest: "sha256:config0".to_string(),
                    kind: "config"
                },
                BlobRef {
                    digest: "sha256:layer1".to_string(),
                    kind: "layer"
                },
                BlobRef {
                    digest: "sha256:layer2".to_string(),
                    kind: "layer"
                },
            ]
        );
    }

    #[test]
    fn extract_blob_refs_empty_for_image_index() {
        // An image index references child manifests, not blobs: it has no
        // `config` and no `layers`, so it must produce zero blob edges.
        let body = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:childamd64", "platform": {"architecture": "amd64", "os": "linux"}},
                {"digest": "sha256:childarm64", "platform": {"architecture": "arm64", "os": "linux"}}
            ]
        }"#;
        assert!(
            extract_blob_refs(body).is_empty(),
            "image index has no config/layers blobs"
        );
    }

    #[test]
    fn extract_blob_refs_handles_missing_config_or_layers() {
        // Config present, no layers array.
        let cfg_only = br#"{"config": {"digest": "sha256:cfg"}}"#;
        assert_eq!(
            extract_blob_refs(cfg_only),
            vec![BlobRef {
                digest: "sha256:cfg".to_string(),
                kind: "config"
            }]
        );
        // Layers present, no config.
        let layers_only = br#"{"layers": [{"digest": "sha256:l1"}]}"#;
        assert_eq!(
            extract_blob_refs(layers_only),
            vec![BlobRef {
                digest: "sha256:l1".to_string(),
                kind: "layer"
            }]
        );
    }

    #[test]
    fn extract_blob_refs_empty_for_malformed_json() {
        assert!(extract_blob_refs(b"not json").is_empty());
        assert!(extract_blob_refs(b"").is_empty());
        assert!(extract_blob_refs(b"{").is_empty());
        assert!(extract_blob_refs(b"{}").is_empty());
    }

    #[test]
    fn extract_blob_refs_skips_layers_missing_digest() {
        let body = br#"{
            "config": {"size": 1},
            "layers": [
                {"digest": "sha256:l1"},
                {"size": 5},
                {"digest": null},
                {"digest": "sha256:l2"}
            ]
        }"#;
        // Config has no digest -> skipped. Two valid layer digests remain.
        let refs = extract_blob_refs(body);
        assert_eq!(
            refs,
            vec![
                BlobRef {
                    digest: "sha256:l1".to_string(),
                    kind: "layer"
                },
                BlobRef {
                    digest: "sha256:l2".to_string(),
                    kind: "layer"
                },
            ]
        );
    }

    // -- blob_refs_to_columns (#1635) UNNEST column-pairing -----------------

    #[test]
    fn blob_refs_to_columns_none_for_empty() {
        // No refs -> no insert; caller short-circuits the DB round-trip.
        assert!(blob_refs_to_columns(&[]).is_none());
    }

    #[test]
    fn blob_refs_to_columns_pairs_digests_and_kinds_in_order() {
        let refs = vec![
            BlobRef {
                digest: "sha256:config0".to_string(),
                kind: "config",
            },
            BlobRef {
                digest: "sha256:layer1".to_string(),
                kind: "layer",
            },
            BlobRef {
                digest: "sha256:layer2".to_string(),
                kind: "layer",
            },
        ];
        let (digests, kinds) =
            blob_refs_to_columns(&refs).expect("non-empty refs yield Some columns");
        // The two arrays must be index-aligned: digests[i] pairs kinds[i]
        // for the UNNEST($2, $3) insert.
        assert_eq!(
            digests,
            vec![
                "sha256:config0".to_string(),
                "sha256:layer1".to_string(),
                "sha256:layer2".to_string(),
            ]
        );
        assert_eq!(
            kinds,
            vec![
                "config".to_string(),
                "layer".to_string(),
                "layer".to_string(),
            ]
        );
        assert_eq!(digests.len(), kinds.len());
    }

    #[test]
    fn blob_refs_to_columns_round_trips_extracted_refs() {
        // End-to-end of the pure pipeline: parse a manifest body, then map
        // it to the two insert columns the UNNEST query binds.
        let body = br#"{
            "config": {"digest": "sha256:cfg"},
            "layers": [{"digest": "sha256:l1"}, {"digest": "sha256:l2"}]
        }"#;
        let refs = extract_blob_refs(body);
        let (digests, kinds) =
            blob_refs_to_columns(&refs).expect("manifest with blobs yields columns");
        assert_eq!(digests, vec!["sha256:cfg", "sha256:l1", "sha256:l2"]);
        assert_eq!(kinds, vec!["config", "layer", "layer"]);
    }

    #[test]
    fn blob_refs_to_columns_none_for_blobless_manifest_body() {
        // An image index has no config/layers -> extract yields nothing ->
        // columns are None so record_manifest_blob_refs inserts zero rows.
        let index = br#"{"manifests": [{"digest": "sha256:child"}]}"#;
        let refs = extract_blob_refs(index);
        assert!(blob_refs_to_columns(&refs).is_none());
    }
}

// ---------------------------------------------------------------------------
// Streaming OCI blob upload coverage.
//
// The hot path for Docker/Podman push is:
// POST /blobs/uploads/ -> PATCH body -> PUT ?digest=... with an empty body.
// These DB-backed tests exercise that path through the router so the coverage
// gate sees the handler branches that avoid reading the just-uploaded object
// back into backend memory. DATABASE_URL is required so CI cannot report
// vacuous success without exercising the DB-backed upload path.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod oci_blob_upload_streaming_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::auth_service::AuthService;
    use crate::storage::{StorageBackend, StorageRegistry};
    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::collections::{HashMap, HashSet};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use tower::ServiceExt;

    struct OciUploadFixture {
        inner: tdh::Fixture,
        authorization: String,
    }

    fn oci_streaming_tests_require_database_url() -> bool {
        std::env::var_os("LLVM_PROFILE_FILE").is_some()
            || std::env::var_os("CARGO_LLVM_COV").is_some()
    }

    impl OciUploadFixture {
        async fn setup() -> Option<Self> {
            if std::env::var("DATABASE_URL").is_err() {
                if oci_streaming_tests_require_database_url() {
                    panic!("DATABASE_URL must be set for OCI streaming upload tests");
                }
                eprintln!("skipping OCI streaming upload tests; DATABASE_URL not set");
                return None;
            }
            let mut inner = None;
            for _ in 0..30 {
                inner = tdh::Fixture::setup("local", "docker").await;
                if inner.is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            let inner = inner.expect("OCI streaming upload fixture setup failed");
            let auth_service =
                AuthService::new(inner.state.db.clone(), Arc::new(inner.state.config.clone()));
            let user = sqlx::query_as::<_, crate::models::user::User>(
                r#"
                SELECT
                    id, username, email, password_hash, display_name,
                    auth_provider,
                    external_id, is_admin, is_active, is_service_account, must_change_password,
                    totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                    failed_login_attempts, locked_until, last_failed_login_at,
                    password_changed_at, last_login_at, created_at, updated_at
                FROM users
                WHERE id = $1
                "#,
            )
            .bind(inner.user_id)
            .fetch_one(&inner.pool)
            .await
            .expect("fetch test user");
            let tokens = auth_service
                .generate_tokens(&user)
                .expect("generate Bearer token");
            let authorization = format!("Bearer {}", tokens.access_token);
            Some(Self {
                inner,
                authorization,
            })
        }

        fn app(&self) -> Router {
            router().with_state(self.inner.state.clone())
        }

        fn app_with_max_upload_size(&self, max_upload_size_bytes: u64) -> Router {
            let mut state = (*self.inner.state).clone();
            state.config.max_upload_size_bytes = max_upload_size_bytes;
            router().with_state(Arc::new(state))
        }

        fn storage(&self) -> Arc<dyn crate::storage::StorageBackend> {
            self.inner
                .state
                .storage_for_repo(&crate::storage::StorageLocation {
                    backend: "filesystem".to_string(),
                    path: self.inner.storage_dir.to_string_lossy().into_owned(),
                })
                .expect("storage")
        }

        async fn teardown(&self) {
            let _ = sqlx::query("DELETE FROM oci_manifest_refs WHERE repository_id = $1")
                .bind(self.inner.repo_id)
                .execute(&self.inner.pool)
                .await;
            let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
                .bind(self.inner.repo_id)
                .execute(&self.inner.pool)
                .await;
            let _ = sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1")
                .bind(self.inner.repo_id)
                .execute(&self.inner.pool)
                .await;
            let _ = sqlx::query("DELETE FROM oci_upload_sessions WHERE repository_id = $1")
                .bind(self.inner.repo_id)
                .execute(&self.inner.pool)
                .await;
            let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
                .bind(self.inner.user_id)
                .execute(&self.inner.pool)
                .await;
            self.inner.teardown().await;
        }
    }

    fn request(method: Method, uri: String, authorization: &str, body: Bytes) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, authorization)
            .body(Body::from(body))
            .expect("build OCI request")
    }

    fn request_with_body(
        method: Method,
        uri: String,
        authorization: &str,
        content_length: usize,
        body: Body,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_LENGTH, content_length.to_string())
            .body(body)
            .expect("build OCI request")
    }

    fn counted_body(chunks_read: Arc<AtomicUsize>, chunks: Vec<Bytes>) -> Body {
        let stream = futures::stream::iter(chunks.into_iter().map(move |chunk| {
            chunks_read.fetch_add(1, AtomicOrdering::SeqCst);
            Ok::<Bytes, Infallible>(chunk)
        }));
        Body::from_stream(stream)
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
        let resp = app.oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("response body");
        (status, headers, body)
    }

    async fn oci_blob_count(f: &OciUploadFixture, digest: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(f.inner.repo_id)
        .bind(digest)
        .fetch_one(&f.inner.pool)
        .await
        .expect("count oci_blobs")
    }

    // RecordingStorage implements only put/get/exists/delete/copy and inherits
    // the trait-default `put_stream` (which buffers then calls `put`). Tests that
    // swap it in assert handler-level orchestration (which temp/part/blob objects
    // are written/copied/deleted and the resulting session state), NOT streaming-
    // backend internals — those are covered by the s3/azure/gcs/filesystem tests
    // and the real filesystem-backed fixture tests.
    #[derive(Default)]
    struct RecordingStorage {
        objects: Mutex<HashMap<String, Bytes>>,
        put_keys: Mutex<Vec<String>>,
        copy_keys: Mutex<Vec<(String, String)>>,
        delete_keys: Mutex<Vec<String>>,
        get_errors: Mutex<HashSet<String>>,
        delete_error_prefixes: Mutex<Vec<String>>,
    }

    impl RecordingStorage {
        fn keys(&self) -> Vec<String> {
            self.objects.lock().unwrap().keys().cloned().collect()
        }

        fn put_keys(&self) -> Vec<String> {
            self.put_keys.lock().unwrap().clone()
        }

        fn copy_keys(&self) -> Vec<(String, String)> {
            self.copy_keys.lock().unwrap().clone()
        }

        fn delete_keys(&self) -> Vec<String> {
            self.delete_keys.lock().unwrap().clone()
        }

        fn fail_get_for(&self, key: &str) {
            self.get_errors.lock().unwrap().insert(key.to_string());
        }

        fn fail_delete_for_prefix(&self, prefix: &str) {
            self.delete_error_prefixes
                .lock()
                .unwrap()
                .push(prefix.to_string());
        }

        fn clear_delete_failures(&self) {
            self.delete_error_prefixes.lock().unwrap().clear();
        }
    }

    #[async_trait]
    impl StorageBackend for RecordingStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.put_keys.lock().unwrap().push(key.to_string());
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), content);
            Ok(())
        }

        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            if self.get_errors.lock().unwrap().contains(key) {
                return Err(AppError::Storage(format!("forced get failure: {}", key)));
            }
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", key)))
        }

        async fn exists(&self, key: &str) -> crate::error::Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            self.delete_keys.lock().unwrap().push(key.to_string());
            if self
                .delete_error_prefixes
                .lock()
                .unwrap()
                .iter()
                .any(|prefix| key.starts_with(prefix))
            {
                return Err(AppError::Storage(format!("forced delete failure: {}", key)));
            }
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        async fn copy(&self, source: &str, dest: &str) -> crate::error::Result<()> {
            self.copy_keys
                .lock()
                .unwrap()
                .push((source.to_string(), dest.to_string()));
            let content = self
                .objects
                .lock()
                .unwrap()
                .get(source)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", source)))?;
            self.objects
                .lock()
                .unwrap()
                .insert(dest.to_string(), content);
            Ok(())
        }
    }

    struct DeferredCommitFailureTrigger {
        table: &'static str,
        trigger_name: String,
        function_name: String,
    }

    impl DeferredCommitFailureTrigger {
        async fn install_for_upload_session_repo(pool: &PgPool, repository_id: Uuid) -> Self {
            let trigger = Self::create(pool, "oci_upload_sessions").await;
            let sql = format!(
                "CREATE CONSTRAINT TRIGGER {trigger_name}
                 AFTER INSERT ON oci_upload_sessions
                 DEFERRABLE INITIALLY DEFERRED
                 FOR EACH ROW
                 WHEN (NEW.repository_id = '{repository_id}'::uuid)
                 EXECUTE FUNCTION {function_name}()",
                trigger_name = trigger.trigger_name,
                function_name = trigger.function_name,
            );
            sqlx::query(&sql)
                .execute(pool)
                .await
                .expect("create deferred upload-session trigger");
            trigger
        }

        async fn install_for_upload_session_part(pool: &PgPool, session_id: Uuid) -> Self {
            let trigger = Self::create(pool, "oci_upload_parts").await;
            let sql = format!(
                "CREATE CONSTRAINT TRIGGER {trigger_name}
                 AFTER INSERT ON oci_upload_parts
                 DEFERRABLE INITIALLY DEFERRED
                 FOR EACH ROW
                 WHEN (NEW.upload_session_id = '{session_id}'::uuid)
                 EXECUTE FUNCTION {function_name}()",
                trigger_name = trigger.trigger_name,
                function_name = trigger.function_name,
            );
            sqlx::query(&sql)
                .execute(pool)
                .await
                .expect("create deferred upload-part trigger");
            trigger
        }

        async fn drop(self, pool: &PgPool) {
            let drop_trigger = format!(
                "DROP TRIGGER IF EXISTS {} ON {}",
                self.trigger_name, self.table
            );
            let _ = sqlx::query(&drop_trigger).execute(pool).await;

            let drop_function = format!("DROP FUNCTION IF EXISTS {}()", self.function_name);
            let _ = sqlx::query(&drop_function).execute(pool).await;
        }

        async fn create(pool: &PgPool, table: &'static str) -> Self {
            let suffix = Uuid::new_v4().simple().to_string();
            let function_name = format!("ak_test_force_commit_failure_{}", suffix);
            let trigger_name = format!("ak_test_force_commit_failure_{}", suffix);
            let sql = format!(
                "CREATE FUNCTION {function_name}() RETURNS trigger
                 LANGUAGE plpgsql AS $$
                 BEGIN
                     RAISE EXCEPTION 'forced deferred commit failure for OCI upload test';
                 END;
                 $$",
                function_name = function_name,
            );
            sqlx::query(&sql)
                .execute(pool)
                .await
                .expect("create deferred failure function");

            Self {
                table,
                trigger_name,
                function_name,
            }
        }
    }

    #[derive(Default)]
    struct FirstPatchRaceStorage {
        objects: Mutex<HashMap<String, Bytes>>,
        first_part_puts: AtomicUsize,
        first_part_ready: tokio::sync::Notify,
        delete_keys: Mutex<Vec<String>>,
    }

    impl FirstPatchRaceStorage {
        fn delete_keys(&self) -> Vec<String> {
            self.delete_keys.lock().unwrap().clone()
        }

        async fn wait_for_two_first_part_writes(&self, key: &str) {
            if !key.contains(".part.00000000.") {
                return;
            }

            self.first_part_puts.fetch_add(1, AtomicOrdering::SeqCst);
            while self.first_part_puts.load(AtomicOrdering::SeqCst) < 2 {
                self.first_part_ready.notified().await;
            }
            self.first_part_ready.notify_waiters();
        }
    }

    #[async_trait]
    impl StorageBackend for FirstPatchRaceStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), content);
            Ok(())
        }

        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", key)))
        }

        async fn exists(&self, key: &str) -> crate::error::Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            self.delete_keys.lock().unwrap().push(key.to_string());
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        async fn copy(&self, source: &str, dest: &str) -> crate::error::Result<()> {
            let content = self.get(source).await?;
            self.objects
                .lock()
                .unwrap()
                .insert(dest.to_string(), content);
            Ok(())
        }

        async fn put_stream(
            &self,
            key: &str,
            stream: BoxStream<'static, crate::error::Result<Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut data = bytes::BytesMut::new();
            tokio::pin!(stream);
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                hasher.update(&chunk);
                total += chunk.len() as u64;
                data.extend_from_slice(&chunk);
            }

            self.wait_for_two_first_part_writes(key).await;
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), data.freeze());
            Ok(crate::storage::PutStreamResult {
                checksum_sha256: format!("{:x}", hasher.finalize()),
                bytes_written: total,
            })
        }
    }

    struct BlockingCopyStorage {
        objects: Mutex<HashMap<String, Bytes>>,
        copy_started: tokio::sync::Notify,
        release_copy: tokio::sync::Notify,
        should_block_copy: AtomicBool,
    }

    impl BlockingCopyStorage {
        fn new() -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
                copy_started: tokio::sync::Notify::new(),
                release_copy: tokio::sync::Notify::new(),
                should_block_copy: AtomicBool::new(true),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for BlockingCopyStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), content);
            Ok(())
        }

        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", key)))
        }

        async fn exists(&self, key: &str) -> crate::error::Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        async fn copy(&self, source: &str, dest: &str) -> crate::error::Result<()> {
            if self.should_block_copy.swap(false, AtomicOrdering::SeqCst) {
                self.copy_started.notify_one();
                self.release_copy.notified().await;
            }

            let content = self
                .objects
                .lock()
                .unwrap()
                .get(source)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", source)))?;
            self.objects
                .lock()
                .unwrap()
                .insert(dest.to_string(), content);
            Ok(())
        }
    }

    struct LockProbeStorage {
        objects: Mutex<HashMap<String, Bytes>>,
        pool: PgPool,
        probe_put_stream: bool,
        probe_copy: bool,
        lock_observed: AtomicBool,
    }

    impl LockProbeStorage {
        fn new(pool: PgPool, probe_put_stream: bool, probe_copy: bool) -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
                pool,
                probe_put_stream,
                probe_copy,
                lock_observed: AtomicBool::new(false),
            }
        }

        fn lock_observed(&self) -> bool {
            self.lock_observed.load(AtomicOrdering::SeqCst)
        }

        async fn assert_session_row_unlocked(&self, key: &str) -> crate::error::Result<()> {
            let Some(rest) = key.strip_prefix("oci-uploads/") else {
                return Ok(());
            };
            let Some(uuid_part) = rest.split('.').next() else {
                return Ok(());
            };
            let Ok(session_id) = Uuid::parse_str(uuid_part) else {
                return Ok(());
            };

            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
            loop {
                let mut tx = self.pool.begin().await.map_err(AppError::from)?;
                let lock_result = sqlx::query(
                    "SELECT 1 FROM oci_upload_sessions WHERE id = $1 FOR UPDATE NOWAIT",
                )
                .bind(session_id)
                .fetch_optional(&mut *tx)
                .await;

                match lock_result {
                    Ok(_) => {
                        tx.commit().await.map_err(AppError::from)?;
                        return Ok(());
                    }
                    Err(e) => {
                        let _ = tx.rollback().await;
                        let error_message = e.to_string();
                        if std::time::Instant::now() >= deadline {
                            self.lock_observed.store(true, AtomicOrdering::SeqCst);
                            return Err(AppError::Storage(format!(
                                "upload session row stayed locked during storage I/O: {}",
                                error_message
                            )));
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
        }
    }

    #[async_trait]
    impl StorageBackend for LockProbeStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), content);
            Ok(())
        }

        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", key)))
        }

        async fn exists(&self, key: &str) -> crate::error::Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        async fn copy(&self, source: &str, dest: &str) -> crate::error::Result<()> {
            if self.probe_copy {
                self.assert_session_row_unlocked(source).await?;
            }
            let content = self.get(source).await?;
            self.objects
                .lock()
                .unwrap()
                .insert(dest.to_string(), content);
            Ok(())
        }

        async fn put_stream(
            &self,
            key: &str,
            stream: BoxStream<'static, crate::error::Result<Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            if self.probe_put_stream {
                self.assert_session_row_unlocked(key).await?;
            }

            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut data = bytes::BytesMut::new();
            tokio::pin!(stream);
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                hasher.update(&chunk);
                total += chunk.len() as u64;
                data.extend_from_slice(&chunk);
            }

            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), data.freeze());
            Ok(crate::storage::PutStreamResult {
                checksum_sha256: format!("{:x}", hasher.finalize()),
                bytes_written: total,
            })
        }
    }

    struct DeleteAfterSessionGoneStorage {
        objects: Mutex<HashMap<String, Bytes>>,
        pool: PgPool,
        session_id: Mutex<Option<Uuid>>,
        early_delete_attempted: AtomicBool,
    }

    impl DeleteAfterSessionGoneStorage {
        fn new(pool: PgPool) -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
                pool,
                session_id: Mutex::new(None),
                early_delete_attempted: AtomicBool::new(false),
            }
        }

        fn track_session(&self, session_id: Uuid) {
            *self.session_id.lock().unwrap() = Some(session_id);
        }

        fn early_delete_attempted(&self) -> bool {
            self.early_delete_attempted.load(AtomicOrdering::SeqCst)
        }
    }

    #[async_trait]
    impl StorageBackend for DeleteAfterSessionGoneStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), content);
            Ok(())
        }

        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", key)))
        }

        async fn exists(&self, key: &str) -> crate::error::Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            let tracked_session = *self.session_id.lock().unwrap();
            if key.starts_with("oci-uploads/") {
                if let Some(session_id) = tracked_session {
                    let session_exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM oci_upload_sessions WHERE id = $1)",
                    )
                    .bind(session_id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(AppError::from)?;
                    if session_exists {
                        self.early_delete_attempted
                            .store(true, AtomicOrdering::SeqCst);
                        return Err(AppError::Storage(
                            "temp object deleted before upload session commit".to_string(),
                        ));
                    }
                }
            }

            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        async fn copy(&self, source: &str, dest: &str) -> crate::error::Result<()> {
            let content = self
                .objects
                .lock()
                .unwrap()
                .get(source)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", source)))?;
            self.objects
                .lock()
                .unwrap()
                .insert(dest.to_string(), content);
            Ok(())
        }
    }

    struct DeleteRepoOnCopyStorage {
        objects: Mutex<HashMap<String, Bytes>>,
        pool: PgPool,
        repository_id: Uuid,
    }

    impl DeleteRepoOnCopyStorage {
        fn new(pool: PgPool, repository_id: Uuid) -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
                pool,
                repository_id,
            }
        }

        fn keys(&self) -> Vec<String> {
            self.objects.lock().unwrap().keys().cloned().collect()
        }
    }

    #[async_trait]
    impl StorageBackend for DeleteRepoOnCopyStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), content);
            Ok(())
        }

        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", key)))
        }

        async fn exists(&self, key: &str) -> crate::error::Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        async fn copy(&self, source: &str, dest: &str) -> crate::error::Result<()> {
            let content = self
                .objects
                .lock()
                .unwrap()
                .get(source)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Storage key not found: {}", source)))?;
            self.objects
                .lock()
                .unwrap()
                .insert(dest.to_string(), content);

            sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(self.repository_id)
                .execute(&self.pool)
                .await
                .map_err(AppError::from)?;

            Ok(())
        }
    }

    #[tokio::test]
    async fn single_patch_upload_copies_streamed_temp_blob_on_completion() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let content = Bytes::from_static(b"hello streamed blob");
        let digest = compute_sha256(&content);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        assert_eq!(
            headers
                .get("Range")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            "0-0"
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                content.clone(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );
        assert_eq!(
            headers
                .get("Range")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            upload_progress_range(content.len() as i64)
        );

        let session = sqlx::query(
            "SELECT bytes_received, computed_digest FROM oci_upload_sessions WHERE id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch upload session");
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        let computed_digest: Option<String> = session.try_get("computed_digest").unwrap();
        assert_eq!(bytes_received, content.len() as i64);
        assert_eq!(computed_digest.as_deref(), Some(digest.as_str()));

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete upload failed: {:?}",
            body
        );

        let remaining_sessions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_uuid)
                .fetch_one(&f.inner.pool)
                .await
                .expect("count upload sessions");
        assert_eq!(remaining_sessions, 0);

        let blob = sqlx::query(
            "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(f.inner.repo_id)
        .bind(&digest)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch blob row");
        let size_bytes: i64 = blob.try_get("size_bytes").unwrap();
        let blob_key: String = blob.try_get("storage_key").unwrap();
        assert_eq!(size_bytes, content.len() as i64);
        assert_eq!(blob_key, blob_storage_key(&digest));

        let storage = f
            .inner
            .state
            .storage_for_repo(&crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: f.inner.storage_dir.to_string_lossy().into_owned(),
            })
            .expect("storage");
        assert_eq!(storage.get(&blob_key).await.unwrap(), content);
        assert!(!storage
            .exists(&upload_storage_key(&upload_uuid))
            .await
            .unwrap());

        f.teardown().await;
    }

    #[tokio::test]
    async fn patch_after_migration_backfills_existing_temp_object_as_first_part() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let upload_uuid = Uuid::new_v4();
        let temp_key = upload_storage_key(&upload_uuid);
        let initial = Bytes::from_static(b"legacy initial body");
        let next = Bytes::from_static(b" plus next patch");
        let mut combined = initial.to_vec();
        combined.extend_from_slice(&next);
        let digest = compute_sha256(&combined);
        let initial_digest = compute_sha256(&initial);

        f.storage().put(&temp_key, initial.clone()).await.unwrap();
        sqlx::query(
            "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key, computed_digest) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(upload_uuid)
        .bind(f.inner.repo_id)
        .bind(f.inner.user_id)
        .bind(initial.len() as i64)
        .bind(&temp_key)
        .bind(initial_digest.as_str())
        .execute(&f.inner.pool)
        .await
        .expect("insert legacy upload session without part rows");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                next.clone(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch after migration failed: {:?}",
            body
        );
        assert_eq!(
            headers
                .get("Range")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            upload_progress_range(combined.len() as i64)
        );

        let parts = sqlx::query(
            "SELECT part_index, storage_key, size_bytes FROM oci_upload_parts WHERE upload_session_id = $1 ORDER BY part_index",
        )
        .bind(upload_uuid)
        .fetch_all(&f.inner.pool)
        .await
        .expect("fetch backfilled parts");
        assert_eq!(parts.len(), 2);
        let first_index: i32 = parts[0].try_get("part_index").unwrap();
        let first_key: String = parts[0].try_get("storage_key").unwrap();
        let first_size: i64 = parts[0].try_get("size_bytes").unwrap();
        let second_index: i32 = parts[1].try_get("part_index").unwrap();
        let second_size: i64 = parts[1].try_get("size_bytes").unwrap();
        assert_eq!(first_index, 0);
        assert_eq!(first_key, temp_key);
        assert_eq!(first_size, initial.len() as i64);
        assert_eq!(second_index, 1);
        assert_eq!(second_size, next.len() as i64);

        let (status, _headers, body) = send(
            app,
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete migrated upload failed: {:?}",
            body
        );
        assert_eq!(
            f.storage().get(&blob_storage_key(&digest)).await.unwrap(),
            Bytes::from(combined)
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn patch_with_content_range_header_disagreeing_with_session_offset_returns_416() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let upload_uuid = Uuid::new_v4();
        let temp_key = upload_storage_key(&upload_uuid);
        let initial = Bytes::from_static(b"already uploaded");
        let next = Bytes::from_static(b"next");

        f.storage().put(&temp_key, initial.clone()).await.unwrap();
        sqlx::query(
            "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key, computed_digest) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(upload_uuid)
        .bind(f.inner.repo_id)
        .bind(f.inner.user_id)
        .bind(initial.len() as i64)
        .bind(&temp_key)
        .bind(compute_sha256(&initial))
        .execute(&f.inner.pool)
        .await
        .expect("insert upload session");

        let request = Request::builder()
            .method(Method::PATCH)
            .uri(format!(
                "/{}/image/blobs/uploads/{}",
                f.inner.repo_key, upload_uuid
            ))
            .header(AUTHORIZATION, &f.authorization)
            .header(CONTENT_LENGTH, next.len().to_string())
            .header("Content-Range", "0-3")
            .body(Body::from(next))
            .expect("build patch request");
        let (status, _headers, body) = send(app, request).await;

        assert_eq!(
            status,
            StatusCode::RANGE_NOT_SATISFIABLE,
            "unexpected response body: {:?}",
            body
        );
        let bytes_received: i64 =
            sqlx::query_scalar("SELECT bytes_received FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_uuid)
                .fetch_one(&f.inner.pool)
                .await
                .expect("fetch bytes_received");
        assert_eq!(bytes_received, initial.len() as i64);

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_heartbeat_marks_lease_invalid_after_consecutive_db_errors() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgresql://127.0.0.1:1/unavailable")
            .expect("lazy pool");
        db.close().await;
        let heartbeat = start_oci_upload_completion_heartbeat_for_tests(
            db,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Duration::from_millis(1),
            2,
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            while heartbeat.lease_is_valid() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("heartbeat should invalidate the lease after repeated DB errors");
        assert!(!heartbeat.lease_is_valid());
    }

    #[tokio::test]
    async fn completion_lease_loss_reopens_session_when_token_still_owned() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let session_id = Uuid::new_v4();
        let state_token = Uuid::new_v4();
        let temp_key = upload_storage_key(&session_id);

        sqlx::query(
            "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key, state, state_token) VALUES ($1, $2, $3, 0, $4, 'committing', $5)",
        )
        .bind(session_id)
        .bind(f.inner.repo_id)
        .bind(f.inner.user_id)
        .bind(&temp_key)
        .bind(state_token)
        .execute(&f.inner.pool)
        .await
        .expect("insert committing upload session");

        let response = completion_lease_lost_after_reset(
            &f.inner.pool,
            session_id,
            f.inner.repo_id,
            state_token,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let row = sqlx::query("SELECT state, state_token FROM oci_upload_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&f.inner.pool)
            .await
            .expect("fetch reset upload session");
        let state: String = row.try_get("state").unwrap();
        let state_token: Option<Uuid> = row.try_get("state_token").unwrap();
        assert_eq!(state, "open");
        assert!(state_token.is_none());

        f.teardown().await;
    }

    #[tokio::test]
    async fn concurrent_first_patch_does_not_delete_winning_part() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(FirstPatchRaceStorage::default());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("first-patch-race".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'first-patch-race' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry =
            Arc::new(StorageRegistry::new(backends, "first-patch-race".into()));
        let app = router().with_state(Arc::new(state));

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let first = Bytes::from_static(b"first concurrent patch");
        let second = Bytes::from_static(b"second racing body");
        let first_request = request(
            Method::PATCH,
            format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
            &f.authorization,
            first.clone(),
        );
        let second_request = request(
            Method::PATCH,
            format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
            &f.authorization,
            second.clone(),
        );

        let ((first_status, _, first_body), (second_status, _, second_body)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(
                    send(app.clone(), first_request),
                    send(app.clone(), second_request)
                )
            })
            .await
            .expect("concurrent first PATCHes should not deadlock");

        let mut status_codes = vec![first_status.as_u16(), second_status.as_u16()];
        status_codes.sort_unstable();
        assert_eq!(
            status_codes,
            vec![StatusCode::ACCEPTED.as_u16(), StatusCode::CONFLICT.as_u16()],
            "expected one winning PATCH and one conflict, got {:?} / {:?}: {:?} / {:?}",
            first_status,
            second_status,
            first_body,
            second_body
        );
        let accepted_body = if first_status == StatusCode::ACCEPTED {
            first
        } else {
            second
        };

        let part = sqlx::query(
            "SELECT storage_key, size_bytes FROM oci_upload_parts WHERE upload_session_id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch winning upload part");
        let part_key: String = part.try_get("storage_key").unwrap();
        let part_size: i64 = part.try_get("size_bytes").unwrap();
        assert_eq!(part_size, accepted_body.len() as i64);
        assert_eq!(storage.get(&part_key).await.unwrap(), accepted_body);
        assert!(
            !storage.delete_keys().iter().any(|key| key == &part_key),
            "losing PATCH must not delete the winning committed part"
        );

        let digest = compute_sha256(&accepted_body);
        let (status, _headers, body) = send(
            app,
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete winning upload failed: {:?}",
            body
        );
        assert_eq!(
            storage.get(&blob_storage_key(&digest)).await.unwrap(),
            accepted_body
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn patch_does_not_hold_upload_session_row_lock_while_streaming_body() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(LockProbeStorage::new(f.inner.pool.clone(), true, false));
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("lock-probe".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'lock-probe' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(backends, "lock-probe".into()));
        let app = router().with_state(Arc::new(state));

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"no row lock while streaming"),
            ),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "PATCH should stream without holding SELECT FOR UPDATE: {:?}",
            body
        );
        assert!(
            !storage.lock_observed(),
            "storage put_stream observed an upload-session row lock"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_does_not_hold_upload_session_row_lock_while_copying_blob() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(LockProbeStorage::new(f.inner.pool.clone(), false, true));
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("lock-probe".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'lock-probe' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(backends, "lock-probe".into()));
        let app = router().with_state(Arc::new(state));
        let content = Bytes::from_static(b"copy without row lock");
        let digest = compute_sha256(&content);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                content,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::CREATED,
            "final PUT should copy without holding SELECT FOR UPDATE: {:?}",
            body
        );
        assert!(
            !storage.lock_observed(),
            "storage copy observed an upload-session row lock"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn monolithic_upload_returns_error_when_blob_record_insert_fails() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(DeleteRepoOnCopyStorage::new(
            f.inner.pool.clone(),
            f.inner.repo_id,
        ));
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("delete-repo-on-copy".to_string(), storage_backend);

        sqlx::query(
            "UPDATE repositories SET storage_backend = 'delete-repo-on-copy' WHERE id = $1",
        )
        .bind(f.inner.repo_id)
        .execute(&f.inner.pool)
        .await
        .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry =
            Arc::new(StorageRegistry::new(backends, "delete-repo-on-copy".into()));
        let app = router().with_state(Arc::new(state));
        let content = Bytes::from_static(b"monolithic db failure");
        let digest = compute_sha256(&content);

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!(
                    "/{}/image/blobs/uploads/?digest={}",
                    f.inner.repo_key, digest
                ),
                &f.authorization,
                content,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "monolithic upload must not return success if oci_blobs insert fails: {:?}",
            body
        );
        let keys = storage.keys();
        assert!(
            keys.iter().all(|key| !key.starts_with("oci-uploads/")),
            "temporary upload object should be cleaned up after DB insert failure: {:?}",
            keys
        );
        assert!(
            keys.iter().any(|key| key == &blob_storage_key(&digest)),
            "digest-global blob object must not be deleted on DB failure because another same-digest upload may be committing it: {:?}",
            keys
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn start_upload_keeps_temp_object_when_commit_result_is_ambiguous() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(RecordingStorage::default());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("recording-ambiguous-start".to_string(), storage_backend);

        sqlx::query(
            "UPDATE repositories SET storage_backend = 'recording-ambiguous-start' WHERE id = $1",
        )
        .bind(f.inner.repo_id)
        .execute(&f.inner.pool)
        .await
        .expect("update repository storage backend");

        let trigger = DeferredCommitFailureTrigger::install_for_upload_session_repo(
            &f.inner.pool,
            f.inner.repo_id,
        )
        .await;

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(
            backends,
            "recording-ambiguous-start".into(),
        ));
        let app = router().with_state(Arc::new(state));

        let (status, _headers, body) = send(
            app,
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::from_static(b"body written before ambiguous commit"),
            ),
        )
        .await;

        trigger.drop(&f.inner.pool).await;

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "deferred commit failure should surface to client: {:?}",
            body
        );
        let keys = storage.keys();
        assert!(
            keys.iter().any(|key| key.starts_with("oci-uploads/")),
            "temp object must not be deleted after COMMIT was attempted; keys: {:?}, deletes: {:?}",
            keys,
            storage.delete_keys()
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn patch_cleans_part_object_when_commit_recovery_confirms_rollback() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(RecordingStorage::default());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("recording-ambiguous-patch".to_string(), storage_backend);

        sqlx::query(
            "UPDATE repositories SET storage_backend = 'recording-ambiguous-patch' WHERE id = $1",
        )
        .bind(f.inner.repo_id)
        .execute(&f.inner.pool)
        .await
        .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(
            backends,
            "recording-ambiguous-patch".into(),
        ));
        let app = router().with_state(Arc::new(state));

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let trigger = DeferredCommitFailureTrigger::install_for_upload_session_part(
            &f.inner.pool,
            upload_uuid,
        )
        .await;

        let (status, _headers, body) = send(
            app,
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"part written before ambiguous commit"),
            ),
        )
        .await;

        trigger.drop(&f.inner.pool).await;

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "deferred commit failure should surface to client: {:?}",
            body
        );
        let keys = storage.keys();
        assert!(
            keys.iter()
                .all(|key| !key.starts_with("oci-uploads/") || !key.contains(".part.00000000.")),
            "part object should be deleted after recovery proves COMMIT rolled back; keys: {:?}, deletes: {:?}",
            keys,
            storage.delete_keys()
        );
        assert!(
            storage
                .delete_keys()
                .iter()
                .any(|key| key.contains(".part.00000000.")),
            "part cleanup should be attempted after recovery proves COMMIT rolled back"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn patch_commit_error_recovery_detects_committed_part() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let session_id = Uuid::new_v4();
        let temp_key = upload_storage_key(&session_id);
        let part_key = upload_part_storage_key(&temp_key, 0, &Uuid::new_v4());
        let part_size = 37_i64;

        sqlx::query(
            "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(session_id)
        .bind(f.inner.repo_id)
        .bind(f.inner.user_id)
        .bind(part_size)
        .bind(&temp_key)
        .execute(&f.inner.pool)
        .await
        .expect("insert committed upload session");

        sqlx::query(
            "INSERT INTO oci_upload_parts (upload_session_id, part_index, storage_key, size_bytes, digest_sha256) VALUES ($1, 0, $2, $3, $4)",
        )
        .bind(session_id)
        .bind(&part_key)
        .bind(part_size)
        .bind("abc123")
        .execute(&f.inner.pool)
        .await
        .expect("insert committed part");

        assert!(
            recover_committed_patch_after_commit_error(
                &f.inner.pool,
                session_id,
                f.inner.repo_id,
                0,
                &part_key,
                part_size,
                part_size,
            )
            .await
            .expect("recover committed PATCH state"),
            "committed session and part should be recognized after commit error"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn patch_commit_error_recovery_rejects_mismatched_committed_part() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let session_id = Uuid::new_v4();
        let temp_key = upload_storage_key(&session_id);
        let part_key = upload_part_storage_key(&temp_key, 0, &Uuid::new_v4());
        let part_size = 37_i64;

        sqlx::query(
            "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(session_id)
        .bind(f.inner.repo_id)
        .bind(f.inner.user_id)
        .bind(part_size + 1)
        .bind(&temp_key)
        .execute(&f.inner.pool)
        .await
        .expect("insert mismatched upload session");

        sqlx::query(
            "INSERT INTO oci_upload_parts (upload_session_id, part_index, storage_key, size_bytes, digest_sha256) VALUES ($1, 0, $2, $3, $4)",
        )
        .bind(session_id)
        .bind(&part_key)
        .bind(part_size)
        .bind("abc123")
        .execute(&f.inner.pool)
        .await
        .expect("insert committed part");

        let err = recover_committed_patch_after_commit_error(
            &f.inner.pool,
            session_id,
            f.inner.repo_id,
            0,
            &part_key,
            part_size,
            part_size,
        )
        .await
        .expect_err("mismatched recovered PATCH state must not be treated as rollback");
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_commit_error_recovery_detects_committed_blob() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let session_id = Uuid::new_v4();
        let blob = Bytes::from_static(b"completed before ambiguous commit");
        let digest = compute_sha256(&blob);
        let blob_key = blob_storage_key(&digest);

        sqlx::query(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4)",
        )
        .bind(f.inner.repo_id)
        .bind(&digest)
        .bind(blob.len() as i64)
        .bind(&blob_key)
        .execute(&f.inner.pool)
        .await
        .expect("insert committed blob row");

        assert!(
            recover_committed_completion_after_commit_error(
                &f.inner.pool,
                session_id,
                f.inner.repo_id,
                &digest,
                blob.len() as i64,
                &blob_key,
            )
            .await
            .expect("recover committed completion state"),
            "deleted session plus matching blob row should be treated as committed"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_commit_error_recovery_keeps_rolled_back_session_retryable() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let session_id = Uuid::new_v4();
        let temp_key = upload_storage_key(&session_id);
        let digest = compute_sha256(b"not committed");
        let blob_key = blob_storage_key(&digest);

        sqlx::query(
            "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key) VALUES ($1, $2, $3, 0, $4)",
        )
        .bind(session_id)
        .bind(f.inner.repo_id)
        .bind(f.inner.user_id)
        .bind(&temp_key)
        .execute(&f.inner.pool)
        .await
        .expect("insert rolled-back upload session");

        assert!(
            !recover_committed_completion_after_commit_error(
                &f.inner.pool,
                session_id,
                f.inner.repo_id,
                &digest,
                0,
                &blob_key,
            )
            .await
            .expect("recover rolled-back completion state"),
            "live upload session should remain retryable instead of being treated as committed"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn patch_rejects_upload_uuid_from_different_repository_path() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let (other_repo_id, other_repo_key, _other_storage_dir) =
            tdh::create_repo(&f.inner.pool, "local", "docker").await;

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", other_repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"wrong repo"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-repo PATCH must not attach to an upload session: {:?}",
            body
        );

        let session = sqlx::query("SELECT bytes_received FROM oci_upload_sessions WHERE id = $1")
            .bind(upload_uuid)
            .fetch_one(&f.inner.pool)
            .await
            .expect("fetch upload session");
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        assert_eq!(bytes_received, 0);

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(other_repo_id)
            .execute(&f.inner.pool)
            .await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_rejects_upload_uuid_from_different_repository_path() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let (other_repo_id, other_repo_key, _other_storage_dir) =
            tdh::create_repo(&f.inner.pool, "local", "docker").await;
        let content = Bytes::from_static(b"repo-bound upload");
        let digest = compute_sha256(&content);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                content,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    other_repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-repo completion must not use an upload session: {:?}",
            body
        );
        assert_eq!(oci_blob_count(&f, &digest).await, 0);

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(other_repo_id)
            .execute(&f.inner.pool)
            .await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn final_put_deletes_temp_object_after_upload_session_commit() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(DeleteAfterSessionGoneStorage::new(f.inner.pool.clone()));
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("session-aware".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'session-aware' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(backends, "session-aware".into()));
        let app = router().with_state(Arc::new(state));
        let content = Bytes::from_static(b"commit-before-cleanup");
        let digest = compute_sha256(&content);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");
        storage.track_session(upload_uuid);

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                content,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let temp_key = upload_storage_key(&upload_uuid);
        assert!(storage.exists(&temp_key).await.unwrap());

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete upload failed: {:?}",
            body
        );
        assert!(
            !storage.early_delete_attempted(),
            "handler attempted to delete temp object before upload session commit"
        );
        assert!(
            !storage.exists(&temp_key).await.unwrap(),
            "temp object should be removed after DB commit"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn monolithic_upload_stages_then_promotes_validated_blob_and_rejects_bad_digest() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let content = Bytes::from_static(b"monolithic streamed blob");
        let digest = compute_sha256(&content);

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!(
                    "/{}/image/blobs/uploads/?digest={}",
                    f.inner.repo_key, digest
                ),
                &f.authorization,
                content.clone(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "monolithic upload failed: {:?}",
            body
        );
        assert_eq!(oci_blob_count(&f, &digest).await, 1);

        let storage = f
            .inner
            .state
            .storage_for_repo(&crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: f.inner.storage_dir.to_string_lossy().into_owned(),
            })
            .expect("storage");
        assert_eq!(
            storage.get(&blob_storage_key(&digest)).await.unwrap(),
            content
        );

        let bad_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::POST,
                format!(
                    "/{}/image/blobs/uploads/?digest={}",
                    f.inner.repo_key, bad_digest
                ),
                &f.authorization,
                Bytes::from_static(b"different bytes"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(oci_blob_count(&f, bad_digest).await, 0);
        assert!(!storage.exists(&blob_storage_key(bad_digest)).await.unwrap());

        f.teardown().await;
    }

    #[tokio::test]
    async fn monolithic_bad_digest_does_not_delete_existing_blob() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let storage = f.storage();
        let existing = Bytes::from_static(b"existing valid blob");
        let digest = compute_sha256(&existing);
        let blob_key = blob_storage_key(&digest);
        storage.put(&blob_key, existing.clone()).await.unwrap();
        sqlx::query(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4)",
        )
        .bind(f.inner.repo_id)
        .bind(&digest)
        .bind(existing.len() as i64)
        .bind(&blob_key)
        .execute(&f.inner.pool)
        .await
        .expect("insert existing blob row");

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::POST,
                format!(
                    "/{}/image/blobs/uploads/?digest={}",
                    f.inner.repo_key, digest
                ),
                &f.authorization,
                Bytes::from_static(b"corrupt bytes for that digest"),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(oci_blob_count(&f, &digest).await, 1);
        assert_eq!(storage.get(&blob_key).await.unwrap(), existing);

        f.teardown().await;
    }

    #[tokio::test]
    async fn monolithic_upload_respects_configured_max_upload_size() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app_with_max_upload_size(4);
        let storage = f.storage();
        let content = Bytes::from_static(b"12345");
        let digest = compute_sha256(&content);

        let (status, _headers, _body) = send(
            app,
            request(
                Method::POST,
                format!(
                    "/{}/image/blobs/uploads/?digest={}",
                    f.inner.repo_key, digest
                ),
                &f.authorization,
                content,
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(oci_blob_count(&f, &digest).await, 0);
        assert!(!storage.exists(&blob_storage_key(&digest)).await.unwrap());

        f.teardown().await;
    }

    #[tokio::test]
    async fn start_upload_initial_body_respects_configured_max_upload_size() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app_with_max_upload_size(4);

        let (status, _headers, _body) = send(
            app,
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::from_static(b"12345"),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let sessions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_upload_sessions WHERE repository_id = $1")
                .bind(f.inner.repo_id)
                .fetch_one(&f.inner.pool)
                .await
                .expect("count upload sessions");
        assert_eq!(sessions, 0);

        f.teardown().await;
    }

    #[tokio::test]
    async fn first_patch_respects_configured_max_upload_size() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app_with_max_upload_size(4);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"12345"),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let session = sqlx::query(
            "SELECT bytes_received, computed_digest FROM oci_upload_sessions WHERE id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch upload session");
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        let computed_digest: Option<String> = session.try_get("computed_digest").unwrap();
        assert_eq!(bytes_received, 0);
        assert!(computed_digest.is_none());

        f.teardown().await;
    }

    #[tokio::test]
    async fn later_patch_respects_cumulative_max_upload_size() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app_with_max_upload_size(4);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"1234"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "first patch failed: {:?}",
            body
        );

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"5"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let session = sqlx::query(
            "SELECT bytes_received, computed_digest FROM oci_upload_sessions WHERE id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch upload session");
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        let computed_digest: Option<String> = session.try_get("computed_digest").unwrap();
        assert_eq!(bytes_received, 4);
        assert_eq!(
            computed_digest.as_deref(),
            Some(compute_sha256(b"1234").as_str())
        );
        let part_key: String = sqlx::query_scalar(
            "SELECT storage_key FROM oci_upload_parts WHERE upload_session_id = $1 AND part_index = 0",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch first part key");
        assert_eq!(
            f.storage().get(&part_key).await.unwrap(),
            Bytes::from_static(b"1234")
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn later_patch_rejects_oversized_content_length_before_reading_body() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app_with_max_upload_size(4);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"1234"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "first patch failed: {:?}",
            body
        );

        let chunks_read = Arc::new(AtomicUsize::new(0));
        let oversized_body = counted_body(Arc::clone(&chunks_read), vec![Bytes::from_static(b"5")]);
        let (status, _headers, _body) = send(
            app.clone(),
            request_with_body(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                1,
                oversized_body,
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            chunks_read.load(AtomicOrdering::SeqCst),
            0,
            "oversized PATCH should be rejected from Content-Length before polling body"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn later_patch_does_not_read_existing_temp_object() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(RecordingStorage::default());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("recording".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'recording' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(backends, "recording".into()));
        let app = router().with_state(Arc::new(state));

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");
        let upload_key = upload_storage_key(&upload_uuid);

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"123"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "first patch failed: {:?}",
            body
        );

        storage.fail_get_for(&upload_key);

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"4"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "later PATCH should write an immutable part instead of reading the existing temp object"
        );

        let session = sqlx::query("SELECT bytes_received FROM oci_upload_sessions WHERE id = $1")
            .bind(upload_uuid)
            .fetch_one(&f.inner.pool)
            .await
            .expect("fetch upload session");
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        assert_eq!(bytes_received, 4);

        f.teardown().await;
    }

    #[tokio::test]
    async fn final_put_rejects_later_patch_while_committing_without_db_row_lock() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(BlockingCopyStorage::new());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("blocking".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'blocking' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(backends, "blocking".into()));
        let app = router().with_state(Arc::new(state));

        let content = Bytes::from_static(b"A");
        let digest = compute_sha256(&content);
        let blob_key = blob_storage_key(&digest);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                content.clone(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "first patch failed: {:?}",
            body
        );

        let final_app = app.clone();
        let final_repo = f.inner.repo_key.clone();
        let final_auth = f.authorization.clone();
        let final_digest = digest.clone();
        let mut final_task = tokio::spawn(async move {
            send(
                final_app,
                request(
                    Method::PUT,
                    format!(
                        "/{}/image/blobs/uploads/{}?digest={}",
                        final_repo, upload_uuid, final_digest
                    ),
                    &final_auth,
                    Bytes::new(),
                ),
            )
            .await
        });

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            storage.copy_started.notified(),
        )
        .await
        .expect("final PUT should reach storage copy");

        let patch_app = app.clone();
        let patch_repo = f.inner.repo_key.clone();
        let patch_auth = f.authorization.clone();
        let mut patch_task = tokio::spawn(async move {
            send(
                patch_app,
                request(
                    Method::PATCH,
                    format!("/{}/image/blobs/uploads/{}", patch_repo, upload_uuid),
                    &patch_auth,
                    Bytes::from_static(b"B"),
                ),
            )
            .await
        });

        let patch_result =
            tokio::time::timeout(std::time::Duration::from_millis(200), &mut patch_task).await;
        let (patch_status, _patch_headers, _patch_body) = patch_result
            .expect("PATCH should be rejected promptly while final PUT is committing")
            .expect("PATCH task should complete");
        assert_eq!(patch_status, StatusCode::CONFLICT);

        storage.release_copy.notify_one();

        let (final_status, _final_headers, final_body) = (&mut final_task)
            .await
            .expect("final PUT task should complete");
        assert_eq!(
            final_status,
            StatusCode::CREATED,
            "final PUT failed: {:?}",
            final_body
        );

        assert_eq!(storage.get(&blob_key).await.unwrap(), content);

        f.teardown().await;
    }

    #[tokio::test]
    async fn final_put_recovers_expired_committing_upload_session_lease() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let content = Bytes::from_static(b"recover stale committing session");
        let digest = compute_sha256(&content);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                content.clone(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        sqlx::query(
            "UPDATE oci_upload_sessions SET state = 'committing', state_token = $2, updated_at = NOW() - INTERVAL '6 hours 1 minute' WHERE id = $1",
        )
        .bind(upload_uuid)
        .bind(Uuid::new_v4())
        .execute(&f.inner.pool)
        .await
        .expect("mark upload session as expired committing lease");

        let (status, _headers, body) = send(
            app,
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "stale committing completion should be recoverable: {:?}",
            body
        );
        assert_eq!(
            f.storage().get(&blob_storage_key(&digest)).await.unwrap(),
            content
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_final_body_respects_cumulative_max_upload_size() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app_with_max_upload_size(4);
        let digest = compute_sha256(b"12345");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"1234"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::from_static(b"5"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(oci_blob_count(&f, &digest).await, 0);
        assert!(!f
            .storage()
            .exists(&blob_storage_key(&digest))
            .await
            .unwrap());

        let sessions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_uuid)
                .fetch_one(&f.inner.pool)
                .await
                .expect("count upload sessions");
        assert_eq!(sessions, 1);

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_rejects_oversized_content_length_before_reading_body() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app_with_max_upload_size(4);
        let digest = compute_sha256(b"12345");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"1234"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let chunks_read = Arc::new(AtomicUsize::new(0));
        let oversized_body = counted_body(Arc::clone(&chunks_read), vec![Bytes::from_static(b"5")]);
        let (status, _headers, _body) = send(
            app.clone(),
            request_with_body(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                1,
                oversized_body,
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            chunks_read.load(AtomicOrdering::SeqCst),
            0,
            "oversized completion body should be rejected from Content-Length before polling body"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn rehash_completion_promotes_via_copy_not_direct_blob_put() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(RecordingStorage::default());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("recording".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'recording' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(backends, "recording".into()));
        let app = router().with_state(Arc::new(state));
        let digest = compute_sha256(b"hello world");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::from_static(b"hello "),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"world"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete upload failed: {:?}",
            body
        );

        let blob_key = blob_storage_key(&digest);
        assert!(
            storage.copy_keys().iter().any(|(source, dest)| source
                .starts_with(&format!("{}.complete.", upload_storage_key(&upload_uuid)))
                && dest == &blob_key),
            "multi-part rehash completion must promote a validated completion temp object via copy"
        );
        assert!(
            !storage.put_keys().iter().any(|key| key == &blob_key),
            "rehash completion must not write directly to digest-global blob key"
        );
        assert_eq!(
            storage.get(&blob_key).await.unwrap(),
            Bytes::from_static(b"hello world")
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_with_nonempty_final_put_body_concatenates_parts() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let digest = compute_sha256(b"hello world");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"hello "),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::from_static(b"world"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete upload with final body failed: {:?}",
            body
        );
        assert_eq!(
            f.storage()
                .get(&blob_storage_key(&digest))
                .await
                .unwrap()
                .as_ref(),
            b"hello world"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn delete_upload_cancels_session_and_removes_temp_storage() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"cancel-me"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let storage_temp_key: String =
            sqlx::query_scalar("SELECT storage_temp_key FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_uuid)
                .fetch_one(&f.inner.pool)
                .await
                .expect("fetch storage temp key");
        let part_keys: Vec<String> = sqlx::query(
            "SELECT storage_key FROM oci_upload_parts WHERE upload_session_id = $1 ORDER BY part_index",
        )
        .bind(upload_uuid)
        .fetch_all(&f.inner.pool)
        .await
        .expect("fetch upload part keys")
        .into_iter()
        .map(|row| row.try_get("storage_key").expect("storage_key"))
        .collect();
        assert!(
            !part_keys.is_empty(),
            "PATCH body must be recorded as an upload part"
        );

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::DELETE,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "cancel upload failed: {:?}",
            body
        );

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_uuid)
                .fetch_one(&f.inner.pool)
                .await
                .expect("count upload sessions");
        let part_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_parts WHERE upload_session_id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("count upload parts");
        assert_eq!(session_count, 0, "cancel must delete the upload session");
        assert_eq!(part_count, 0, "cancel must cascade upload parts");
        assert!(
            !f.storage()
                .exists(&storage_temp_key)
                .await
                .expect("temp exists check"),
            "cancel must delete the upload temp object"
        );
        for part_key in part_keys {
            assert!(
                !f.storage()
                    .exists(&part_key)
                    .await
                    .expect("part exists check"),
                "cancel must delete upload part object {}",
                part_key
            );
        }

        f.teardown().await;
    }

    #[tokio::test]
    async fn monolithic_malformed_digest_rejected_before_streaming_body() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();

        // A syntactically invalid ?digest= must be rejected up front, before the
        // body is streamed to storage or any cleanup-key row is registered, so a
        // bad digest cannot cause a wasted (potentially multi-GiB) write.
        let (status, _headers, body) = send(
            app,
            request(
                Method::POST,
                format!(
                    "/{}/image/blobs/uploads/?digest=not-a-valid-sha256",
                    f.inner.repo_key
                ),
                &f.authorization,
                Bytes::from_static(b"body that must never reach storage"),
            ),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "malformed digest must be rejected: {:?}",
            body
        );
        let cleanup_keys: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE repository_id = $1",
        )
        .bind(f.inner.repo_id)
        .fetch_one(&f.inner.pool)
        .await
        .expect("count cleanup keys");
        assert_eq!(
            cleanup_keys, 0,
            "a malformed digest must be rejected before any storage write is registered"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn cancel_partial_storage_delete_keeps_session_non_resumable() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        // RecordingStorage that fails every delete, simulating a transient storage
        // error landing mid-cancel after some objects may already be gone.
        let storage = Arc::new(RecordingStorage::default());
        storage.fail_delete_for_prefix("");
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("recording-cancel-faildelete".to_string(), storage_backend);
        sqlx::query(
            "UPDATE repositories SET storage_backend = 'recording-cancel-faildelete' WHERE id = $1",
        )
        .bind(f.inner.repo_id)
        .execute(&f.inner.pool)
        .await
        .expect("update repository storage backend");
        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(
            backends,
            "recording-cancel-faildelete".into(),
        ));
        let app = router().with_state(Arc::new(state));

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::DELETE,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a failed storage delete during cancel must surface an error"
        );

        // The session must NOT be reset to `open` (which would make it resumable
        // with missing parts). It stays `committing` until the GC sweep reaps it.
        let state_value: String =
            sqlx::query_scalar("SELECT state FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_uuid)
                .fetch_one(&f.inner.pool)
                .await
                .expect("session must still exist after a failed cancel");
        assert_eq!(
            state_value, "committing",
            "a cancel that began deleting must leave the session non-resumable, not reset it to open"
        );

        // A resume attempt is rejected (not 202), proving the session is wedged
        // rather than resumable with holes.
        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"resume-bytes"),
            ),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::ACCEPTED,
            "a session left mid-cancel must not accept further PATCH appends"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn cached_single_part_completion_digest_mismatch_keeps_session_retryable() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let wrong_digest = compute_sha256(b"HELLO");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"hello"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, wrong_digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(oci_blob_count(&f, &wrong_digest).await, 0);
        assert!(
            !f.storage()
                .exists(&blob_storage_key(&wrong_digest))
                .await
                .expect("blob exists check"),
            "digest mismatch must not promote a blob object"
        );

        let session = sqlx::query(
            "SELECT state, bytes_received, storage_temp_key FROM oci_upload_sessions WHERE id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch retryable upload session");
        let state: String = session.try_get("state").unwrap();
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        let storage_temp_key: String = session.try_get("storage_temp_key").unwrap();
        assert_eq!(state, "open");
        assert_eq!(bytes_received, 5);
        assert!(
            f.storage()
                .exists(&storage_temp_key)
                .await
                .expect("temp exists check"),
            "the original uploaded part must remain so the client can retry completion"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn multi_patch_completion_rejects_digest_mismatch_and_keeps_session_open() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let wrong_digest = compute_sha256(b"GOODBYE");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        for chunk in [Bytes::from_static(b"hello "), Bytes::from_static(b"world")] {
            let (status, _headers, body) = send(
                app.clone(),
                request(
                    Method::PATCH,
                    format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                    &f.authorization,
                    chunk,
                ),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::ACCEPTED,
                "patch upload failed: {:?}",
                body
            );
        }

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, wrong_digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(oci_blob_count(&f, &wrong_digest).await, 0);
        assert!(
            !f.storage()
                .exists(&blob_storage_key(&wrong_digest))
                .await
                .expect("blob exists check"),
            "digest mismatch must not promote a blob object"
        );

        let session = sqlx::query(
            "SELECT state, bytes_received, computed_digest FROM oci_upload_sessions WHERE id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch retryable upload session");
        let state: String = session.try_get("state").unwrap();
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        let computed_digest: Option<String> = session.try_get("computed_digest").unwrap();
        assert_eq!(state, "open");
        assert_eq!(bytes_received, 11);
        assert!(
            computed_digest.is_none(),
            "multi-PATCH completion must use the rehash path"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn rehash_completion_digest_mismatch_removes_final_and_complete_temp_objects() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(RecordingStorage::default());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("recording".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'recording' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(backends, "recording".into()));
        let app = router().with_state(Arc::new(state));
        let wrong_digest = compute_sha256(b"hello WORLD");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"hello "),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, wrong_digest
                ),
                &f.authorization,
                Bytes::from_static(b"world"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(oci_blob_count(&f, &wrong_digest).await, 0);

        let upload_key = upload_storage_key(&upload_uuid);
        let deleted_keys = storage.delete_keys();
        assert!(
            deleted_keys
                .iter()
                .any(|key| key.starts_with(&format!("{}.complete.", upload_key))),
            "digest mismatch must delete the concatenated completion temp object: {:?}",
            deleted_keys
        );
        assert!(
            deleted_keys
                .iter()
                .any(|key| key.starts_with(&format!("{}.part.2147483647.", upload_key))),
            "digest mismatch must delete the streamed final PUT body object: {:?}",
            deleted_keys
        );
        assert!(
            !storage
                .keys()
                .iter()
                .any(|key| key.starts_with(&format!("{}.complete.", upload_key))
                    || key.starts_with(&format!("{}.part.2147483647.", upload_key))),
            "temporary completion objects must not remain in storage"
        );

        let session =
            sqlx::query("SELECT state, bytes_received FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_uuid)
                .fetch_one(&f.inner.pool)
                .await
                .expect("fetch retryable upload session");
        let state: String = session.try_get("state").unwrap();
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        assert_eq!(state, "open");
        assert_eq!(bytes_received, 6);

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_digest_mismatch_delete_failure_is_recoverable_by_storage_gc() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(RecordingStorage::default());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("recording".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'recording' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry =
            Arc::new(StorageRegistry::new(backends.clone(), "recording".into()));
        let app = router().with_state(Arc::new(state));
        let wrong_digest = compute_sha256(b"hello WORLD");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                Bytes::from_static(b"hello "),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let upload_key = upload_storage_key(&upload_uuid);
        storage.fail_delete_for_prefix(&format!("{}.part.2147483647.", upload_key));

        let (status, _headers, _body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, wrong_digest
                ),
                &f.authorization,
                Bytes::from_static(b"world"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let leaked_final_key = storage
            .keys()
            .into_iter()
            .find(|key| key.starts_with(&format!("{}.part.2147483647.", upload_key)))
            .expect("forced delete failure should leave the final PUT temp object");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&leaked_final_key)
        .fetch_one(&f.inner.pool)
        .await
        .expect("count cleanup key rows");
        assert_eq!(
            cleanup_key_count, 1,
            "failed best-effort delete must leave a durable cleanup-key row"
        );

        let _gc_guard = crate::services::storage_gc_service::storage_gc_test_guard().await;

        sqlx::query(
            r#"
            UPDATE oci_upload_cleanup_keys
            SET created_at = NOW() - INTERVAL '25 hours',
                storage_write_completed_at = NOW() - INTERVAL '25 hours'
            WHERE storage_key = $1
            "#,
        )
        .bind(&leaked_final_key)
        .execute(&f.inner.pool)
        .await
        .expect("age cleanup key");
        storage.clear_delete_failures();

        let registry = Arc::new(StorageRegistry::new(backends, "recording".into()));
        let gc = crate::services::storage_gc_service::StorageGcService::new(
            f.inner.pool.clone(),
            registry,
        );
        let gc_result = gc.run_gc(false).await.expect("storage gc succeeds");

        let key_exists_after_gc = storage
            .exists(&leaked_final_key)
            .await
            .expect("exists check after gc");
        let cleanup_key_count_after_gc: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&leaked_final_key)
        .fetch_one(&f.inner.pool)
        .await
        .expect("count cleanup key rows after gc");
        assert!(
            !key_exists_after_gc,
            "storage GC must delete leaked final PUT temp object"
        );
        assert_eq!(
            cleanup_key_count_after_gc, 0,
            "storage GC must remove the durable cleanup-key row"
        );
        assert!(
            gc_result.storage_keys_deleted >= 1,
            "GC result should count the leaked final PUT temp key"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn multi_patch_upload_rehashes_when_digest_cache_is_cleared() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let first = Bytes::from_static(b"hello ");
        let second = Bytes::from_static(b"world");
        let digest = compute_sha256(b"hello world");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                first,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                second,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let session = sqlx::query(
            "SELECT bytes_received, computed_digest FROM oci_upload_sessions WHERE id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("fetch upload session");
        let bytes_received: i64 = session.try_get("bytes_received").unwrap();
        let computed_digest: Option<String> = session.try_get("computed_digest").unwrap();
        assert_eq!(bytes_received, 11);
        assert!(
            computed_digest.is_none(),
            "multi-PATCH append path must clear stale computed_digest"
        );

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete upload failed: {:?}",
            body
        );

        let storage = f
            .inner
            .state
            .storage_for_repo(&crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: f.inner.storage_dir.to_string_lossy().into_owned(),
            })
            .expect("storage");
        assert_eq!(
            storage
                .get(&blob_storage_key(&digest))
                .await
                .unwrap()
                .as_ref(),
            b"hello world"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn three_part_upload_concatenates_parts_in_index_order() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let digest = compute_sha256(b"aaabbbccc");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        for (index, chunk) in [
            Bytes::from_static(b"aaa"),
            Bytes::from_static(b"bbb"),
            Bytes::from_static(b"ccc"),
        ]
        .into_iter()
        .enumerate()
        {
            let (status, _headers, body) = send(
                app.clone(),
                request(
                    Method::PATCH,
                    format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                    &f.authorization,
                    chunk,
                ),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::ACCEPTED,
                "patch upload part {} failed: {:?}",
                index,
                body
            );
        }

        let part_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_parts WHERE upload_session_id = $1",
        )
        .bind(upload_uuid)
        .fetch_one(&f.inner.pool)
        .await
        .expect("count upload parts");
        assert_eq!(part_count, 3, "three PATCHes must record three parts");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete three-part upload failed: {:?}",
            body
        );

        let blob_key = blob_storage_key(&digest);
        assert_eq!(
            f.storage().get(&blob_key).await.unwrap().as_ref(),
            b"aaabbbccc",
            "parts must concatenate in part_index order"
        );
        assert!(
            f.storage().exists(&blob_key).await.unwrap(),
            "stored blob object must exist"
        );
        assert_eq!(
            oci_blob_count(&f, &digest).await,
            1,
            "exactly one blob row must be recorded"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn concurrent_final_puts_commit_blob_exactly_once() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let storage = Arc::new(BlockingCopyStorage::new());
        let mut backends = HashMap::new();
        let storage_backend: Arc<dyn StorageBackend> = storage.clone();
        backends.insert("blocking".to_string(), storage_backend);

        sqlx::query("UPDATE repositories SET storage_backend = 'blocking' WHERE id = $1")
            .bind(f.inner.repo_id)
            .execute(&f.inner.pool)
            .await
            .expect("update repository storage backend");

        let mut state = (*f.inner.state).clone();
        state.storage_registry = Arc::new(StorageRegistry::new(backends, "blocking".into()));
        let app = router().with_state(Arc::new(state));

        let content = Bytes::from_static(b"A");
        let digest = compute_sha256(&content);
        let blob_key = blob_storage_key(&digest);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start upload failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PATCH,
                format!("/{}/image/blobs/uploads/{}", f.inner.repo_key, upload_uuid),
                &f.authorization,
                content.clone(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "patch upload failed: {:?}",
            body
        );

        let first_app = app.clone();
        let first_repo = f.inner.repo_key.clone();
        let first_auth = f.authorization.clone();
        let first_digest = digest.clone();
        let mut first_put = tokio::spawn(async move {
            send(
                first_app,
                request(
                    Method::PUT,
                    format!(
                        "/{}/image/blobs/uploads/{}?digest={}",
                        first_repo, upload_uuid, first_digest
                    ),
                    &first_auth,
                    Bytes::new(),
                ),
            )
            .await
        });

        // Wait for the first PUT to claim the session and reach the blocking copy.
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            storage.copy_started.notified(),
        )
        .await
        .expect("first final PUT should reach storage copy");

        // Fire the second PUT while the first is mid-commit. It must lose the
        // claim_oci_upload_session_for_completion race (state already 'committing').
        let second_app = app.clone();
        let second_repo = f.inner.repo_key.clone();
        let second_auth = f.authorization.clone();
        let second_digest = digest.clone();
        let mut second_put = tokio::spawn(async move {
            send(
                second_app,
                request(
                    Method::PUT,
                    format!(
                        "/{}/image/blobs/uploads/{}?digest={}",
                        second_repo, upload_uuid, second_digest
                    ),
                    &second_auth,
                    Bytes::new(),
                ),
            )
            .await
        });

        let second_result =
            tokio::time::timeout(std::time::Duration::from_millis(500), &mut second_put).await;
        let (second_status, _second_headers, _second_body) = second_result
            .expect("second final PUT should be rejected promptly while first is committing")
            .expect("second PUT task should complete");
        assert_eq!(
            second_status,
            StatusCode::CONFLICT,
            "second concurrent final PUT must lose the completion claim"
        );

        storage.release_copy.notify_one();

        let (first_status, _first_headers, first_body) = (&mut first_put)
            .await
            .expect("first PUT task should complete");
        assert_eq!(
            first_status,
            StatusCode::CREATED,
            "first final PUT failed: {:?}",
            first_body
        );

        assert_eq!(
            storage.get(&blob_key).await.unwrap(),
            content,
            "blob must be stored exactly once with the correct bytes"
        );
        assert_eq!(
            oci_blob_count(&f, &digest).await,
            1,
            "exactly one blob row must be recorded after concurrent PUTs"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn monolithic_upload_persists_canonical_lowercase_digest_for_uppercase_request() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let storage = f.storage();
        let content = Bytes::from_static(b"upper-case digest request bytes");
        let canonical = compute_sha256(&content); // sha256:<lowercase hex>
        let upper_hex = canonical
            .strip_prefix("sha256:")
            .expect("prefixed digest")
            .to_ascii_uppercase();
        let upper_digest = format!("sha256:{}", upper_hex);

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!(
                    "/{}/image/blobs/uploads/?digest={}",
                    f.inner.repo_key, upper_digest
                ),
                &f.authorization,
                content.clone(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "upper-case digest upload should succeed: {:?}",
            body
        );

        // The blob must be persisted under the canonical lowercase digest, not
        // the upper-case form the client sent, or a later canonical lookup would
        // miss it. This is the regression guard for the digest-canonicalization
        // fix in the monolithic POST path.
        assert_eq!(
            oci_blob_count(&f, &canonical).await,
            1,
            "blob row must use the canonical lowercase digest"
        );
        assert_eq!(
            oci_blob_count(&f, &upper_digest).await,
            0,
            "no blob row may be stored under the raw upper-case digest"
        );
        assert_eq!(
            storage.get(&blob_storage_key(&canonical)).await.unwrap(),
            content,
            "blob object must live under the canonical storage key"
        );
        assert!(
            !storage
                .exists(&blob_storage_key(&upper_digest))
                .await
                .unwrap(),
            "no object may be stored under the upper-case storage key"
        );
        assert_eq!(
            headers
                .get("Docker-Content-Digest")
                .and_then(|v| v.to_str().ok()),
            Some(canonical.as_str()),
            "Docker-Content-Digest must echo the canonical lowercase digest"
        );

        // The READ side must canonicalize too: pulling by the upper-case digest
        // must resolve the blob stored under its canonical lowercase digest,
        // otherwise an upper-case push+pull round-trip would 404.
        let (get_status, _get_headers, get_body) = send(
            app.clone(),
            request(
                Method::GET,
                format!("/{}/image/blobs/{}", f.inner.repo_key, upper_digest),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            get_status,
            StatusCode::OK,
            "upper-case GET must resolve the canonically-stored blob"
        );
        assert_eq!(get_body, content, "GET must return the stored bytes");

        f.teardown().await;
    }

    #[tokio::test]
    async fn monolithic_empty_blob_upload_creates_zero_byte_blob() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let storage = f.storage();
        // The empty blob (sha256 of zero bytes) is the config blob present in
        // essentially every image manifest, so this path must work end to end.
        let digest = compute_sha256(b"");

        let (status, _headers, body) = send(
            app,
            request(
                Method::POST,
                format!(
                    "/{}/image/blobs/uploads/?digest={}",
                    f.inner.repo_key, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "empty monolithic upload should succeed: {:?}",
            body
        );
        assert_eq!(oci_blob_count(&f, &digest).await, 1);
        assert_eq!(
            storage.get(&blob_storage_key(&digest)).await.unwrap().len(),
            0,
            "empty blob object must exist and be zero bytes"
        );
        let size: i64 = sqlx::query_scalar(
            "SELECT size_bytes FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(f.inner.repo_id)
        .bind(&digest)
        .fetch_one(&f.inner.pool)
        .await
        .expect("blob size");
        assert_eq!(size, 0, "empty blob row must record size_bytes = 0");

        f.teardown().await;
    }

    #[tokio::test]
    async fn session_empty_blob_completion_creates_zero_byte_blob() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let app = f.app();
        let storage = f.storage();
        let digest = compute_sha256(b"");

        let (status, headers, body) = send(
            app.clone(),
            request(
                Method::POST,
                format!("/{}/image/blobs/uploads/", f.inner.repo_key),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "start empty upload session failed: {:?}",
            body
        );
        let upload_uuid = headers
            .get("Docker-Upload-UUID")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok())
            .expect("Docker-Upload-UUID");

        let (status, _headers, body) = send(
            app.clone(),
            request(
                Method::PUT,
                format!(
                    "/{}/image/blobs/uploads/{}?digest={}",
                    f.inner.repo_key, upload_uuid, digest
                ),
                &f.authorization,
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "complete empty upload failed: {:?}",
            body
        );
        assert_eq!(oci_blob_count(&f, &digest).await, 1);
        assert_eq!(
            storage.get(&blob_storage_key(&digest)).await.unwrap().len(),
            0,
            "empty blob object must exist and be zero bytes"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn completion_heartbeat_marks_lease_invalid_when_token_changes_under_healthy_db() {
        let Some(f) = OciUploadFixture::setup().await else {
            return;
        };
        let session_id = Uuid::new_v4();
        let state_token = Uuid::new_v4();
        let temp_key = upload_storage_key(&session_id);

        sqlx::query(
            "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key, state, state_token) VALUES ($1, $2, $3, 0, $4, 'committing', $5)",
        )
        .bind(session_id)
        .bind(f.inner.repo_id)
        .bind(f.inner.user_id)
        .bind(&temp_key)
        .bind(state_token)
        .execute(&f.inner.pool)
        .await
        .expect("insert committing upload session");

        let heartbeat = start_oci_upload_completion_heartbeat_for_tests(
            f.inner.pool.clone(),
            session_id,
            f.inner.repo_id,
            state_token,
            Duration::from_millis(20),
            5,
        );

        // Steal the lease from another (healthy) connection by rotating the
        // state_token. The next heartbeat UPDATE then matches 0 rows even though
        // the DB is fully reachable, exercising the `Ok(_) if rows_affected != 1`
        // branch that protects a live commit from a concurrent writer.
        sqlx::query("UPDATE oci_upload_sessions SET state_token = $2 WHERE id = $1")
            .bind(session_id)
            .bind(Uuid::new_v4())
            .execute(&f.inner.pool)
            .await
            .expect("rotate state_token");

        tokio::time::timeout(Duration::from_secs(3), async {
            while heartbeat.lease_is_valid() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("heartbeat must invalidate the lease when its token no longer owns the row");
        assert!(!heartbeat.lease_is_valid());

        f.teardown().await;
    }
}

// ---------------------------------------------------------------------------
// #1175: /v2/token `service` query parameter validation.
//
// The OCI Distribution token spec requires the server to validate that the
// `service` query value matches what was advertised in the WWW-Authenticate
// challenge. Mismatched values must be rejected with 400 DENIED; missing
// values stay accepted for backward compatibility with curl-style clients.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod token_service_query_validation_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn token_with_mismatched_service_returns_400() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let storage_dir = std::env::temp_dir().join(format!("oci-svc-mismatch-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool, storage_dir.to_str().unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/token?service=victim.example.com")
            .body(Body::empty())
            .unwrap();
        let app = router().with_state(state);
        let resp = app.oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "mismatched service must return 400"
        );
    }

    #[tokio::test]
    async fn token_with_matching_service_returns_anonymous_200() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let storage_dir = std::env::temp_dir().join(format!("oci-svc-match-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool, storage_dir.to_str().unwrap());

        let req = Request::builder()
            .method("GET")
            .uri(format!("/token?service={OCI_TOKEN_SERVICE}"))
            .body(Body::empty())
            .unwrap();
        let app = router().with_state(state);
        let resp = app.oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            status,
            StatusCode::OK,
            "matching service must issue anonymous pull token"
        );
    }

    #[tokio::test]
    async fn token_without_service_param_returns_anonymous_200() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let storage_dir = std::env::temp_dir().join(format!("oci-svc-missing-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool, storage_dir.to_str().unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/token")
            .body(Body::empty())
            .unwrap();
        let app = router().with_state(state);
        let resp = app.oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            status,
            StatusCode::OK,
            "missing service param stays accepted (backward compat)"
        );
    }
}

// ---------------------------------------------------------------------------
// #1357: proxied manifests must be indexed in the `artifacts` table so the
// Docker tag UI listing (`list_artifacts_grouped_by_docker_tag` in
// repositories.rs) finds the JOIN row. Pre-fix, `cache_manifest_reference_locally`
// inserted only the `oci_tags` row, so a successful `docker pull` through a
// remote proxy populated `oci_tags` but left `artifacts` empty, and the UI
// reported "No image tags found". This is the gap referenced in the #1278
// fix's "Tradeoff" note for the OCI manifest path -- safe to close here
// because the manifest write uses the per-repo backend, not the global
// `proxy-cache/...` backend that drove the #1278 doubled-prefix bug.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proxy_manifest_artifact_indexing_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    /// After `cache_manifest_reference_locally` writes a proxied manifest,
    /// the JOIN used by the docker-tag listing must succeed: there must be
    /// an `artifacts` row at the deterministic path
    /// `v2/{image}/manifests/{tag}` whose storage_key matches the
    /// per-repo manifest_storage_key(digest).
    #[tokio::test]
    async fn cache_manifest_inserts_artifacts_row_for_listing_join() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "remote", "docker").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        // Build an OciRepoInfo pointing at the per-repo storage. The path
        // matches what `repo.storage_location()` would return for this
        // repository row, so the per-repo backend reads/writes resolve
        // under <storage_dir>/oci-manifests/<digest>.
        let image = "library/redis";
        let info = OciRepoInfo {
            id: repo_id,
            key: repo_key.clone(),
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: storage_dir.to_string_lossy().to_string(),
            },
            repo_type: RepositoryType::Remote.as_str().to_string(),
            upstream_url: Some("https://registry-1.docker.io".to_string()),
            is_public: false,
            image: image.to_string(),
        };

        let manifest = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"size":7,"digest":"sha256:00"},"layers":[]}"#;
        let body = Bytes::from_static(manifest);
        let digest = cache_manifest_reference_locally(
            &state,
            &info,
            "latest",
            &body,
            Some("application/vnd.oci.image.manifest.v1+json"),
        )
        .await
        .expect("cache_manifest_reference_locally must succeed");

        // For remote repos with a tag reference, the cached tag is the digest.
        let expected_tag = digest.clone();
        let expected_path = format!("v2/{}/manifests/{}", image, expected_tag);
        let expected_storage_key = format!("oci-manifests/{}", digest);

        // oci_tags row exists (regression-safe: this was the only insert pre-fix).
        let tag_row: Option<(String, String)> = sqlx::query_as(
            "SELECT manifest_digest, manifest_content_type \
             FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
        )
        .bind(repo_id)
        .bind(image)
        .bind(&expected_tag)
        .fetch_optional(&pool)
        .await
        .expect("query oci_tags");
        assert!(
            tag_row.is_some(),
            "expected oci_tags row for repo={}, image={}, tag={}",
            repo_key,
            image,
            expected_tag
        );

        // #1357 fix: artifacts row must exist at the JOIN-compatible path,
        // pointing at the per-repo manifest_storage_key. Without this row
        // `list_artifacts_grouped_by_docker_tag` drops the tag and the UI
        // shows "No image tags found" for proxied images.
        let art_row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT storage_key, content_type, size_bytes \
             FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(repo_id)
        .bind(&expected_path)
        .fetch_optional(&pool)
        .await
        .expect("query artifacts");

        // Clean up before assertions so cleanup runs even on failure.
        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        let (storage_key, content_type, size_bytes) = art_row.expect(
            "expected artifacts row at v2/<image>/manifests/<tag> after \
             cache_manifest_reference_locally; without it the docker-tag UI \
             listing JOIN drops proxied tags (#1357)",
        );
        assert_eq!(
            storage_key, expected_storage_key,
            "artifacts.storage_key must point at the per-repo manifest object \
             so storage_for_repo(repo.location).get(storage_key) resolves \
             under the same backend the manifest was written to"
        );
        assert_eq!(
            content_type, "application/vnd.oci.image.manifest.v1+json",
            "content_type should carry the manifest media type"
        );
        assert_eq!(
            size_bytes,
            body.len() as i64,
            "size_bytes must equal manifest body length"
        );
    }

    /// Repeated proxy hits for the same tag must upsert (not duplicate) the
    /// artifacts row, mirroring the push-path ON CONFLICT DO UPDATE.
    #[tokio::test]
    async fn cache_manifest_repeated_calls_upsert_artifact_row() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "remote", "docker").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let image = "library/nginx";
        let info = OciRepoInfo {
            id: repo_id,
            key: repo_key,
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: storage_dir.to_string_lossy().to_string(),
            },
            repo_type: RepositoryType::Remote.as_str().to_string(),
            upstream_url: Some("https://registry-1.docker.io".to_string()),
            is_public: false,
            image: image.to_string(),
        };

        let body = Bytes::from_static(
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}"#,
        );

        // First and second proxy fetches both call cache_manifest_reference_locally.
        let _ = cache_manifest_reference_locally(
            &state,
            &info,
            "stable",
            &body,
            Some("application/vnd.oci.image.manifest.v1+json"),
        )
        .await
        .expect("first cache call");
        let _ = cache_manifest_reference_locally(
            &state,
            &info,
            "stable",
            &body,
            Some("application/vnd.oci.image.manifest.v1+json"),
        )
        .await
        .expect("second cache call");

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND name LIKE $2",
        )
        .bind(repo_id)
        .bind(format!("{}:%", image))
        .fetch_one(&pool)
        .await
        .expect("count artifacts");

        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        // Two rows: one keyed by digest path (digest-keyed oci_tags row),
        // one keyed by tag path (tag-keyed oci_tags row, required so the
        // `POSITION(':' IN t.tag) = 0` filter in the docker-tag listing
        // returns the human-readable tag). Repeated calls must upsert
        // BOTH rows via ON CONFLICT (repository_id, path), not duplicate
        // them.
        assert_eq!(
            count, 2,
            "repeated cache calls for the same (repo, image, tag) must \
             upsert via ON CONFLICT (repository_id, path), not insert \
             additional rows. Expected exactly 2 rows (digest-keyed + \
             tag-keyed) after two calls."
        );
    }

    /// The fix must NOT route any write back through
    /// `proxy_service::cache_artifact`, which is forbidden from inserting
    /// into `artifacts` (#1278). Pin the source-level invariant so a future
    /// refactor that consolidates the manifest-cache and blob-proxy-cache
    /// paths cannot silently reintroduce the doubled-prefix 500s.
    #[test]
    fn cache_manifest_reference_locally_does_not_call_proxy_cache_artifact() {
        let source = include_str!("oci_v2.rs");
        let fn_marker = "async fn cache_manifest_reference_locally(";
        let fn_start = source
            .find(fn_marker)
            .expect("cache_manifest_reference_locally must exist");
        let after_start = &source[fn_start..];
        let fn_end_rel = after_start
            .find("\n}\n")
            .or_else(|| after_start.find("\n    }\n"))
            .expect("function must terminate with a column-0 or column-4 closer");
        let fn_body = &after_start[..fn_end_rel];

        assert!(
            !fn_body.contains("proxy_service.cache_artifact")
                && !fn_body.contains("self.cache_artifact")
                && !fn_body.contains("ProxyService"),
            "cache_manifest_reference_locally MUST NOT delegate to \
             ProxyService::cache_artifact (#1278). The manifest body is \
             written through the per-repo backend at `oci-manifests/<digest>` \
             and the artifacts row points at that key; routing through the \
             proxy cache would put bytes under `proxy-cache/<repo>/...` on \
             the global backend and break the `storage_for_repo` read path."
        );
    }

    /// End-to-end coverage for the headline #1357 UX fix. The earlier tests
    /// pin that the `artifacts` row exists at the right path, but they do
    /// NOT exercise the JOIN+`POSITION(':' IN t.tag) = 0` filter that
    /// `fetch_docker_tag_rows` applies to the Docker tag listing. Pre-fix,
    /// the only `oci_tags` row for a proxied tag was keyed by the digest
    /// (`sha256:...`), which the filter strips out, and the UI still said
    /// "No image tags found". This test reproduces the listing query and
    /// asserts the human-readable tag is returned.
    #[tokio::test]
    async fn cache_manifest_appears_in_docker_tag_listing() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "remote", "docker").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let image = "library/redis";
        let info = OciRepoInfo {
            id: repo_id,
            key: repo_key.clone(),
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: storage_dir.to_string_lossy().to_string(),
            },
            repo_type: RepositoryType::Remote.as_str().to_string(),
            upstream_url: Some("https://registry-1.docker.io".to_string()),
            is_public: false,
            image: image.to_string(),
        };

        let body = Bytes::from_static(
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"size":7,"digest":"sha256:00"},"layers":[]}"#,
        );
        let digest = cache_manifest_reference_locally(
            &state,
            &info,
            "latest",
            &body,
            Some("application/vnd.oci.image.manifest.v1+json"),
        )
        .await
        .expect("cache_manifest_reference_locally must succeed");

        // Reproduce the exact JOIN+filter shape from
        // `fetch_docker_tag_rows` (repositories.rs).  If the parallel
        // tag-keyed oci_tags row + the artifacts row are both present,
        // this query returns the human-readable tag.
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT t.name, t.tag, t.manifest_digest
             FROM oci_tags t
             JOIN artifacts a
               ON a.repository_id = t.repository_id
              AND a.path = 'v2/' || t.name || '/manifests/' || t.tag
              AND a.is_deleted = false
             WHERE t.repository_id = $1
               AND POSITION(':' IN t.tag) = 0
             ORDER BY t.name, t.tag
             LIMIT 10",
        )
        .bind(repo_id)
        .fetch_all(&pool)
        .await
        .expect("docker tag listing query");

        // Clean up before assertions so cleanup runs even on failure.
        let _ = sqlx::query("DELETE FROM oci_manifest_refs WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert!(
            rows.iter()
                .any(|(name, tag, md)| name == image && tag == "latest" && md == &digest),
            "docker tag listing must include the human-readable 'latest' tag \
             for a proxied manifest (#1357). The POSITION(':' IN t.tag) = 0 \
             filter strips digest-keyed oci_tags rows, so a parallel \
             tag-keyed row is required. Got rows: {:?}",
            rows
        );
    }

    /// For multi-arch image-index manifests the proxy path must also
    /// populate `oci_manifest_refs`, mirroring the push-path behaviour in
    /// `handle_put_manifest`. Without these rows the storage GC over-
    /// deletes per-architecture child manifests and the UI's multi-arch
    /// size accounting under-reports by orders of magnitude (#1357 review).
    #[tokio::test]
    async fn cache_manifest_records_refs_for_index_manifest() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "remote", "docker").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let image = "library/redis";
        let info = OciRepoInfo {
            id: repo_id,
            key: repo_key,
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: storage_dir.to_string_lossy().to_string(),
            },
            repo_type: RepositoryType::Remote.as_str().to_string(),
            upstream_url: Some("https://registry-1.docker.io".to_string()),
            is_public: false,
            image: image.to_string(),
        };

        // OCI image index with two child manifests (amd64, arm64).
        let body = Bytes::from_static(
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":100,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":200,"platform":{"architecture":"arm64","os":"linux"}}]}"#,
        );
        let parent_digest = cache_manifest_reference_locally(
            &state,
            &info,
            "latest",
            &body,
            Some("application/vnd.oci.image.index.v1+json"),
        )
        .await
        .expect("cache_manifest_reference_locally must succeed");

        let refs: Vec<(String, String)> = sqlx::query_as(
            "SELECT parent_digest, child_digest
             FROM oci_manifest_refs
             WHERE repository_id = $1 AND parent_digest = $2
             ORDER BY child_digest",
        )
        .bind(repo_id)
        .bind(&parent_digest)
        .fetch_all(&pool)
        .await
        .expect("query oci_manifest_refs");

        // Clean up before assertions so cleanup runs even on failure.
        let _ = sqlx::query("DELETE FROM oci_manifest_refs WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            refs.len(),
            2,
            "cache_manifest_reference_locally must record one \
             oci_manifest_refs row per child digest for image-index \
             manifests, mirroring the push-path #1179 behaviour. Got: {:?}",
            refs
        );
        assert!(
            refs.iter().all(|(p, _)| p == &parent_digest),
            "all rows must point at the index digest as parent"
        );
        assert!(
            refs.iter().any(|(_, c)| c
                == "sha256:1111111111111111111111111111111111111111111111111111111111111111"),
            "amd64 child digest must be recorded"
        );
        assert!(
            refs.iter().any(|(_, c)| c
                == "sha256:2222222222222222222222222222222222222222222222222222222222222222"),
            "arm64 child digest must be recorded"
        );
    }

    /// Local repos do not get the parallel tag-keyed oci_tags row -- the
    /// `cached_reference == reference` branch in `cached_manifest_reference_key`
    /// returns the original reference, so the digest-keyed insert IS the
    /// tag-keyed insert. The `repo.repo_type == Remote` guard on both the
    /// second oci_tags upsert and the second artifacts upsert must skip,
    /// leaving exactly one row in each table for a local-repo push-equivalent
    /// flow.
    #[tokio::test]
    async fn cache_manifest_local_repo_writes_single_pair() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "local", "docker").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let image = "library/alpine";
        let info = OciRepoInfo {
            id: repo_id,
            key: repo_key,
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: storage_dir.to_string_lossy().to_string(),
            },
            repo_type: RepositoryType::Local.as_str().to_string(),
            upstream_url: None,
            is_public: false,
            image: image.to_string(),
        };

        let body = Bytes::from_static(
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}"#,
        );
        let _ = cache_manifest_reference_locally(
            &state,
            &info,
            "v1.0",
            &body,
            Some("application/vnd.oci.image.manifest.v1+json"),
        )
        .await
        .expect("cache_manifest_reference_locally must succeed for local repo");

        let tag_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_tags WHERE repository_id = $1 AND name = $2",
        )
        .bind(repo_id)
        .bind(image)
        .fetch_one(&pool)
        .await
        .expect("count oci_tags");

        let art_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND name LIKE $2",
        )
        .bind(repo_id)
        .bind(format!("{}:%", image))
        .fetch_one(&pool)
        .await
        .expect("count artifacts");

        let _ = sqlx::query("DELETE FROM oci_manifest_refs WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            tag_count, 1,
            "local repo must produce exactly one oci_tags row (the parallel \
             tag-keyed insert is guarded on repo_type == Remote)"
        );
        assert_eq!(
            art_count, 1,
            "local repo must produce exactly one artifacts row (the second \
             artifact_paths entry is guarded on repo_type == Remote)"
        );
    }

    /// Remote-by-digest pulls (`docker pull repo@sha256:...`) hit the
    /// `is_digest_reference(reference)` short-circuit on BOTH the parallel
    /// oci_tags upsert AND the second artifacts upsert. The result is the
    /// same shape as a local push: one oci_tags row + one artifacts row,
    /// both keyed by the digest. This pins the by-digest branch so a future
    /// refactor cannot accidentally double-insert under the tag path for a
    /// digest reference (which would clutter the docker tag UI with a
    /// `sha256:...` "tag" the `POSITION(':' IN t.tag) = 0` filter is
    /// expressly designed to hide).
    #[tokio::test]
    async fn cache_manifest_remote_by_digest_writes_single_pair() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "remote", "docker").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let image = "library/busybox";
        let info = OciRepoInfo {
            id: repo_id,
            key: repo_key,
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: storage_dir.to_string_lossy().to_string(),
            },
            repo_type: RepositoryType::Remote.as_str().to_string(),
            upstream_url: Some("https://registry-1.docker.io".to_string()),
            is_public: false,
            image: image.to_string(),
        };

        let body = Bytes::from_static(
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}"#,
        );
        // Caller supplies a digest reference, NOT a human-readable tag.
        let digest_ref = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(
            is_digest_reference(digest_ref),
            "test fixture must use a value that is_digest_reference recognises"
        );

        let _ = cache_manifest_reference_locally(
            &state,
            &info,
            digest_ref,
            &body,
            Some("application/vnd.oci.image.manifest.v1+json"),
        )
        .await
        .expect("cache_manifest_reference_locally must succeed for remote-by-digest");

        let tag_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_tags WHERE repository_id = $1 AND name = $2",
        )
        .bind(repo_id)
        .bind(image)
        .fetch_one(&pool)
        .await
        .expect("count oci_tags");

        let art_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND name LIKE $2",
        )
        .bind(repo_id)
        .bind(format!("{}:%", image))
        .fetch_one(&pool)
        .await
        .expect("count artifacts");

        let _ = sqlx::query("DELETE FROM oci_manifest_refs WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            tag_count, 1,
            "remote-by-digest must produce exactly one oci_tags row (the \
             parallel tag-keyed insert is skipped when reference is a digest)"
        );
        assert_eq!(
            art_count, 1,
            "remote-by-digest must produce exactly one artifacts row (the \
             second artifact_paths entry is skipped when reference is a digest)"
        );
    }

    /// Non-index content types (regular image manifests, including the
    /// docker v2 schema and OCI image-manifest) must NOT trigger the
    /// `record_oci_manifest_refs` call. The push path only records
    /// parent->child edges for image-index manifests; the proxy path must
    /// mirror that. Without this guard the function would parse a non-index
    /// manifest as JSON looking for a `manifests` array, find nothing, and
    /// silently no-op, but the cost (extra DB roundtrip per pull) would be
    /// real.
    #[tokio::test]
    async fn cache_manifest_non_index_does_not_write_manifest_refs() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "remote", "docker").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let image = "library/curl";
        let info = OciRepoInfo {
            id: repo_id,
            key: repo_key,
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: storage_dir.to_string_lossy().to_string(),
            },
            repo_type: RepositoryType::Remote.as_str().to_string(),
            upstream_url: Some("https://registry-1.docker.io".to_string()),
            is_public: false,
            image: image.to_string(),
        };

        // A regular image manifest body (NOT an index). Even if this body
        // contained a `manifests` array, the content_type guard
        // `is_index_content_type(&manifest_content_type)` must short-circuit
        // before the parse + insert.
        let body = Bytes::from_static(
            br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"size":7,"digest":"sha256:aa"},"layers":[]}"#,
        );
        let parent_digest = cache_manifest_reference_locally(
            &state,
            &info,
            "1.0",
            &body,
            Some("application/vnd.docker.distribution.manifest.v2+json"),
        )
        .await
        .expect("cache_manifest_reference_locally must succeed for image manifest");

        let refs_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_manifest_refs WHERE repository_id = $1 AND parent_digest = $2",
        )
        .bind(repo_id)
        .bind(&parent_digest)
        .fetch_one(&pool)
        .await
        .expect("count oci_manifest_refs");

        let _ = sqlx::query("DELETE FROM oci_manifest_refs WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            refs_count, 0,
            "non-index content types must NOT write to oci_manifest_refs; \
             the is_index_content_type guard must short-circuit before \
             record_oci_manifest_refs is called"
        );
    }
}

// ===========================================================================
// Issue #1317 regression coverage (lib-side, picked up by the Coverage gate).
//
// The integration suite in `backend/tests/oci_chunked_upload_cross_repo_tests.rs`
// is also wired into the CI integration matrix, but `cargo llvm-cov --lib`
// excludes the `tests/` directory, so without these lib-side tests the
// cross-repo session lookup branches in `handle_patch_upload` and
// `handle_complete_upload` would appear uncovered to the coverage gate.
// ===========================================================================

#[cfg(test)]
mod cross_repo_session_regression_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// Insert a second docker repo and return (id, key, storage_dir). The
    /// storage_dir is created so the handler can read/write blob temp files
    /// under it if needed during the same-repo happy path.
    async fn create_docker_repo(pool: &PgPool, label: &str) -> (Uuid, String, std::path::PathBuf) {
        let id = Uuid::new_v4();
        let key = format!("ph-test-docker-{}-{}", label, id);
        let storage_dir = std::env::temp_dir().join(format!("ph-test-docker-{}", id));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local'::repository_type, 'docker'::repository_format, true)",
        )
        .bind(id)
        .bind(&key)
        .bind(storage_dir.to_string_lossy().as_ref())
        .execute(pool)
        .await
        .expect("insert docker repo");
        (id, key, storage_dir)
    }

    /// Create a user with a real bcrypt-hashed password so the OCI Basic-auth
    /// flow (`authenticate_oci_with_scopes`) succeeds. Returns (user_id, username, password).
    async fn create_pushable_user(pool: &PgPool) -> (Uuid, String, String) {
        let id = Uuid::new_v4();
        let username = format!("oci1317-{}", id);
        let password = "pushpass".to_string();
        let hash = bcrypt::hash(&password, 4).expect("bcrypt hash");
        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
            VALUES ($1, $2, $3, $4, 'local', true, true)
            "#,
        )
        .bind(id)
        .bind(&username)
        .bind(format!("{}@test.local", username))
        .bind(&hash)
        .execute(pool)
        .await
        .expect("insert user");
        (id, username, password)
    }

    fn basic_auth(username: &str, password: &str) -> String {
        use base64::Engine;
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
        format!("Basic {}", encoded)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    async fn cleanup_all(
        pool: &PgPool,
        repo_ids: &[Uuid],
        user_id: Uuid,
        storage_dirs: &[std::path::PathBuf],
    ) {
        for id in repo_ids {
            let _ = sqlx::query("DELETE FROM oci_upload_sessions WHERE repository_id = $1")
                .bind(id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1")
                .bind(id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;
        }
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        for dir in storage_dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// PATCH chunk under repo B must be 404 (session belongs to repo A).
    /// Same-repo PATCH must still succeed. This pins both branches of the
    /// new session lookup in `handle_patch_upload`.
    #[tokio::test]
    async fn handle_patch_upload_cross_repo_rejected_and_same_repo_ok() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username, password) = create_pushable_user(&pool).await;
        let (repo_a_id, key_a, storage_a) = create_docker_repo(&pool, "a").await;
        let (repo_b_id, key_b, storage_b) = create_docker_repo(&pool, "b").await;
        let state = tdh::build_state(pool.clone(), storage_a.to_str().unwrap());
        let auth = basic_auth(&username, &password);

        let make_app = || router().with_state(state.clone());

        // POST start under repo A.
        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}/myimage/blobs/uploads/", key_a))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "POST start under repo A should return 202"
        );

        let session_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM oci_upload_sessions WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(repo_a_id)
        .fetch_one(&pool)
        .await
        .expect("session row exists");

        // Cross-repo PATCH must be 404.
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/{}/myimage/blobs/uploads/{}", key_b, session_id))
            .header("Authorization", &auth)
            .body(Body::from(b"attacker-chunk".to_vec()))
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH chunk under wrong repo must be 404 (issue #1317)"
        );

        // Same-repo PATCH must still succeed (covers happy-path lookup).
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/{}/myimage/blobs/uploads/{}", key_a, session_id))
            .header("Authorization", &auth)
            .body(Body::from(b"legitimate-chunk".to_vec()))
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "PATCH chunk under owning repo should return 202"
        );

        cleanup_all(
            &pool,
            &[repo_a_id, repo_b_id],
            user_id,
            &[storage_a, storage_b],
        )
        .await;
    }

    /// PUT complete under repo B must be 404 even with a valid digest query.
    /// The legitimate session row must remain intact, and a same-repo PUT
    /// complete with the right digest must succeed (covers happy-path
    /// branch of the new lookup in `handle_complete_upload`).
    #[tokio::test]
    async fn handle_complete_upload_cross_repo_rejected_and_same_repo_ok() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username, password) = create_pushable_user(&pool).await;
        let (repo_a_id, key_a, storage_a) = create_docker_repo(&pool, "a").await;
        let (repo_b_id, key_b, storage_b) = create_docker_repo(&pool, "b").await;
        let state = tdh::build_state(pool.clone(), storage_a.to_str().unwrap());
        let auth = basic_auth(&username, &password);

        let make_app = || router().with_state(state.clone());

        // POST start.
        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}/myimage/blobs/uploads/", key_a))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let session_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM oci_upload_sessions WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(repo_a_id)
        .fetch_one(&pool)
        .await
        .expect("session row exists");

        // PATCH the chunk under repo A so the temp blob is non-empty.
        let chunk = b"chunk-bytes".to_vec();
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/{}/myimage/blobs/uploads/{}", key_a, session_id))
            .header("Authorization", &auth)
            .body(Body::from(chunk.clone()))
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let digest = format!("sha256:{}", sha256_hex(&chunk));

        // Cross-repo PUT must be 404.
        let req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/{}/myimage/blobs/uploads/{}?digest={}",
                key_b, session_id, digest
            ))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PUT complete under wrong repo must be 404 (issue #1317)"
        );

        // Session row must still exist (cross-repo attempts must not
        // delete or finalize it).
        let still_there: i64 =
            sqlx::query_scalar("SELECT count(*) FROM oci_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(still_there, 1, "cross-repo PUT must not delete session");

        // Same-repo PUT must succeed.
        let req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/{}/myimage/blobs/uploads/{}?digest={}",
                key_a, session_id, digest
            ))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "PUT complete under owning repo should return 201"
        );

        cleanup_all(
            &pool,
            &[repo_a_id, repo_b_id],
            user_id,
            &[storage_a, storage_b],
        )
        .await;
    }

    /// PUT complete with a digest that does not match the streamed bytes must
    /// reject with 400 DIGEST_INVALID and write no blob row. Our streaming
    /// design keeps the session `open` (retryable) on mismatch instead of
    /// deleting it, so the client can re-PUT with the correct digest. This
    /// pins the digest-verify branch of `handle_complete_upload`.
    #[tokio::test]
    async fn handle_complete_upload_digest_mismatch_rejected() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username, password) = create_pushable_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_docker_repo(&pool, "mm").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = basic_auth(&username, &password);
        let make_app = || router().with_state(state.clone());

        // POST start.
        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}/myimage/blobs/uploads/", repo_key))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let session_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM oci_upload_sessions WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("session row exists");

        // PATCH a known chunk into the temp file.
        let chunk = b"actual-chunk-bytes".to_vec();
        let req = Request::builder()
            .method("PATCH")
            .uri(format!(
                "/{}/myimage/blobs/uploads/{}",
                repo_key, session_id
            ))
            .header("Authorization", &auth)
            .body(Body::from(chunk.clone()))
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // PUT with a digest that does NOT match the chunk on disk.
        let bogus_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/{}/myimage/blobs/uploads/{}?digest={}",
                repo_key, session_id, bogus_digest
            ))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "digest mismatch must reject with 400"
        );

        // The session is retained and reset to `open` so the client can retry
        // the PUT with the correct digest (our streaming design keeps the
        // session retryable on mismatch instead of forcing a full re-upload).
        let session_state: Option<String> =
            sqlx::query_scalar("SELECT state FROM oci_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert_eq!(
            session_state.as_deref(),
            Some("open"),
            "session must be retained and reset to open (retryable) on digest mismatch"
        );

        // No blob row should have been recorded.
        let blob_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(bogus_digest)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            blob_rows, 0,
            "no oci_blobs row should be written on digest mismatch"
        );

        cleanup_all(&pool, &[repo_id], user_id, &[storage_dir]).await;
    }

    /// PUT complete without a digest query parameter must reject with
    /// 400 DIGEST_INVALID. This pins the early-return branch of
    /// `handle_complete_upload` before any temp-file work.
    #[tokio::test]
    async fn handle_complete_upload_missing_digest_query_rejected() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username, password) = create_pushable_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_docker_repo(&pool, "nd").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = basic_auth(&username, &password);
        let make_app = || router().with_state(state.clone());

        // POST start.
        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}/myimage/blobs/uploads/", repo_key))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let session_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM oci_upload_sessions WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("session row exists");

        // PUT without `?digest=` query.
        let req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/{}/myimage/blobs/uploads/{}",
                repo_key, session_id
            ))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "missing digest query must reject with 400"
        );

        cleanup_all(&pool, &[repo_id], user_id, &[storage_dir]).await;
    }

    /// Monolithic POST?digest=... with the full blob inline must verify
    /// the digest, write the blob under the final `oci-blobs/<digest>`
    /// key, record `oci_blobs`, and return 201. This pins the monolithic
    /// branch of `handle_start_upload` (#1449 acceptance).
    #[tokio::test]
    async fn handle_start_upload_monolithic_with_digest_creates_blob() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username, password) = create_pushable_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_docker_repo(&pool, "mono").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = basic_auth(&username, &password);
        let make_app = || router().with_state(state.clone());

        let body = b"monolithic-blob-payload".to_vec();
        let digest = format!("sha256:{}", sha256_hex(&body));

        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/{}/myimage/blobs/uploads/?digest={}",
                repo_key, digest
            ))
            .header("Authorization", &auth)
            .header("Content-Type", "application/octet-stream")
            .body(Body::from(body.clone()))
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "monolithic POST with matching digest must return 201"
        );

        // oci_blobs row should be recorded under the final digest.
        let blob_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(&digest)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(blob_rows, 1, "oci_blobs row must be recorded");

        cleanup_all(&pool, &[repo_id], user_id, &[storage_dir]).await;
    }

    /// Monolithic POST?digest=... where the provided digest does NOT
    /// match the body bytes must reject with 400 DIGEST_INVALID and not
    /// record an oci_blobs row. This pins the pre-write verification in
    /// `handle_start_upload`.
    #[tokio::test]
    async fn handle_start_upload_monolithic_digest_mismatch_rejected() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username, password) = create_pushable_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_docker_repo(&pool, "monomm").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = basic_auth(&username, &password);
        let make_app = || router().with_state(state.clone());

        let body = b"monolithic-bytes-A".to_vec();
        // Digest of a DIFFERENT payload so verification must fail.
        let wrong_digest = format!("sha256:{}", sha256_hex(b"some-other-bytes"));

        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/{}/myimage/blobs/uploads/?digest={}",
                repo_key, wrong_digest
            ))
            .header("Authorization", &auth)
            .header("Content-Type", "application/octet-stream")
            .body(Body::from(body))
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "monolithic POST with mismatched digest must reject with 400"
        );

        // No oci_blobs row should have been recorded.
        let blob_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(&wrong_digest)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            blob_rows, 0,
            "no oci_blobs row should be written on digest mismatch"
        );

        cleanup_all(&pool, &[repo_id], user_id, &[storage_dir]).await;
    }

    /// Successive PATCH chunks must each be appended to the temp file
    /// (O_APPEND) and the running `bytes_received` counter must reflect
    /// the cumulative size. PUT complete with the digest of the
    /// concatenated chunks must then succeed and record a single
    /// `oci_blobs` row. This pins the multi-chunk happy path of
    /// `handle_patch_upload` + `handle_complete_upload` together.
    #[tokio::test]
    async fn handle_patch_upload_multi_chunk_then_complete_succeeds() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username, password) = create_pushable_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_docker_repo(&pool, "mc").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = basic_auth(&username, &password);
        let make_app = || router().with_state(state.clone());

        // POST start.
        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}/myimage/blobs/uploads/", repo_key))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let session_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM oci_upload_sessions WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("session row exists");

        // Two PATCH chunks.
        let chunk_a = b"first-chunk-".to_vec();
        let chunk_b = b"second-chunk".to_vec();
        for chunk in &[&chunk_a, &chunk_b] {
            let req = Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/{}/myimage/blobs/uploads/{}",
                    repo_key, session_id
                ))
                .header("Authorization", &auth)
                .body(Body::from((*chunk).clone()))
                .unwrap();
            let resp = make_app().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::ACCEPTED,
                "PATCH chunk under owning repo should return 202"
            );
        }

        // After two PATCHes, bytes_received must equal the sum of both
        // chunks. Pre-#1449 the second PATCH would read+rewrite the
        // whole file (O(N^2)); the new path appends with O_APPEND and
        // updates the running counter only.
        let bytes_received: i64 =
            sqlx::query_scalar("SELECT bytes_received FROM oci_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            bytes_received,
            (chunk_a.len() + chunk_b.len()) as i64,
            "bytes_received must equal cumulative chunk size after two PATCHes"
        );

        let mut full = chunk_a.clone();
        full.extend_from_slice(&chunk_b);
        let digest = format!("sha256:{}", sha256_hex(&full));

        // PUT complete with the digest of the concatenated chunks.
        let req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/{}/myimage/blobs/uploads/{}?digest={}",
                repo_key, session_id, digest
            ))
            .header("Authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "multi-chunk PUT complete with matching digest should return 201"
        );

        // Exactly one oci_blobs row.
        let blob_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(&digest)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(blob_rows, 1, "exactly one oci_blobs row should be recorded");

        cleanup_all(&pool, &[repo_id], user_id, &[storage_dir]).await;
    }
}
