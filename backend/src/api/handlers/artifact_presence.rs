//! Artifact presence checks for air-gap ferry imports (first slice of #3427).
//!
//! Two pieces share the lookup here:
//!
//! * `POST /api/v1/repositories/{key}/artifacts-missing` takes a list of
//!   `{path, sha256}` pairs and returns the subset the repository does not
//!   already hold, so a client importing a dependency tree transfers only the
//!   genuinely new bytes. It generalises the shape of the Git LFS batch
//!   endpoint (`gitlfs.rs`) to any hosted repository, with a hard item cap.
//! * [`already_present_for_session`] answers "already present" at chunked
//!   upload init (`POST /api/v1/uploads` with `skip_if_present: true`) when a
//!   live artifact at the requested path already carries the declared
//!   checksum and its stored object is still there.
//!
//! Both are reads of the repository's contents, so both go through the same
//! `require_visible` gate as `GET /{key}/artifacts/{path}`: a caller who cannot
//! read the repository gets the existence-hiding 404 (bulk endpoint) or a
//! normal upload session (init short-circuit), never a presence answer.

use std::collections::{HashMap, HashSet};

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::repositories::require_visible;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryType};
use crate::services::repository_service::RepositoryService;
use crate::services::upload_service::{validate_artifact_path, MAX_ARTIFACT_PATH_LEN};

/// Hard cap on the number of items one request may check. Requests over the
/// cap are rejected with 400 rather than truncated, so a client never mistakes
/// an unchecked tail for "present".
pub const MAX_PRESENCE_ITEMS: usize = 1000;

/// Request body ceiling for the bulk check: every item at the maximum path
/// length plus its digest and JSON framing. The `/repositories` nest otherwise
/// inherits the artifact upload limit, which is far too generous for JSON.
const PRESENCE_BODY_LIMIT: usize = MAX_PRESENCE_ITEMS * (MAX_ARTIFACT_PATH_LEN + 256);

/// Repository sub-router for the bulk presence check. Merged into the
/// `/api/v1/repositories` nest, so it runs under `optional_auth_middleware`.
pub fn repo_router() -> Router<SharedState> {
    Router::new().route(
        "/:key/artifacts-missing",
        post(missing_artifacts).layer(DefaultBodyLimit::max(PRESENCE_BODY_LIMIT)),
    )
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// One artifact the client holds locally.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ArtifactPresenceItem {
    /// Repository path the client would upload to (e.g. `com/acme/lib/1.0/lib-1.0.jar`).
    pub path: String,
    /// Lowercase or uppercase hex SHA-256 of the local file.
    pub sha256: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MissingArtifactsRequest {
    /// Items to check, at most 1000 per request.
    pub items: Vec<ArtifactPresenceItem>,
}

/// Why an item is reported missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    /// No live artifact exists at the path.
    NotFound,
    /// An artifact exists at the path but with different content. Uploading
    /// may be refused with 409 if the repository treats the path as immutable.
    ChecksumMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MissingArtifact {
    pub path: String,
    /// The requested SHA-256, normalised to lowercase hex.
    pub sha256: String,
    pub reason: MissingReason,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MissingArtifactsResponse {
    /// Number of items checked (the request's item count).
    pub checked: usize,
    /// Items the repository does not hold with the given content, in request order.
    pub missing: Vec<MissingArtifact>,
}

/// Returned by `POST /api/v1/uploads` (status 200, no session opened) when
/// `skip_if_present` is set and the artifact is already stored.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AlreadyPresentResponse {
    /// Always `true`; lets a client tell this body from a session body.
    pub already_present: bool,
    pub artifact_id: Uuid,
    pub path: String,
    pub size: i64,
    pub checksum_sha256: String,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Normalise a hex SHA-256 to lowercase, or `None` if it is not 64 hex chars.
pub(crate) fn normalize_sha256(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// Presence is answered from the `artifacts` table, which only hosted
/// repositories populate: remote repositories cache outside it (#1280) and a
/// virtual repository's contents belong to its members.
fn presence_supported(repo_type: &RepositoryType) -> bool {
    matches!(repo_type, RepositoryType::Local | RepositoryType::Staging)
}

/// Enforce the item cap and validate each item, returning `(path, sha256)`
/// pairs with the digest normalised. Errors name the offending index.
fn validate_items(items: &[ArtifactPresenceItem]) -> Result<Vec<(String, String)>> {
    if items.len() > MAX_PRESENCE_ITEMS {
        return Err(AppError::Validation(format!(
            "too many items: {} (maximum {MAX_PRESENCE_ITEMS} per request)",
            items.len()
        )));
    }
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            validate_artifact_path(&item.path)
                .map_err(|e| AppError::Validation(format!("items[{i}].path: {e}")))?;
            let sha = normalize_sha256(&item.sha256).ok_or_else(|| {
                AppError::Validation(format!(
                    "items[{i}].sha256: expected 64 hexadecimal characters"
                ))
            })?;
            Ok((item.path.clone(), sha))
        })
        .collect()
}

/// Distinct paths to look up, in first-seen order.
fn distinct_paths(items: &[(String, String)]) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .iter()
        .filter(|(path, _)| seen.insert(path.as_str()))
        .map(|(path, _)| path.clone())
        .collect()
}

/// Classify each requested item against the live checksums per path.
fn classify_missing(
    items: Vec<(String, String)>,
    live: &HashMap<String, HashSet<String>>,
) -> Vec<MissingArtifact> {
    items
        .into_iter()
        .filter_map(|(path, sha256)| {
            let reason = match live.get(&path) {
                None => MissingReason::NotFound,
                Some(sums) if sums.contains(&sha256) => return None,
                Some(_) => MissingReason::ChecksumMismatch,
            };
            Some(MissingArtifact {
                path,
                sha256,
                reason,
            })
        })
        .collect()
}

/// Whether an existing artifact row satisfies an upload-init request. The
/// checksum already matched in SQL; the declared size must agree, and a
/// version, when the client names one, must be the stored one.
fn row_satisfies_request(
    row_size: i64,
    row_version: Option<&str>,
    total_size: i64,
    requested_version: Option<&str>,
) -> bool {
    row_size == total_size && requested_version.is_none_or(|v| row_version == Some(v))
}

// ---------------------------------------------------------------------------
// DB lookups
// ---------------------------------------------------------------------------

/// Live (non-deleted) checksums per path for the given paths in one repository.
async fn live_checksums(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    paths: &[String],
) -> Result<HashMap<String, HashSet<String>>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT path, lower(checksum_sha256) FROM artifacts \
         WHERE repository_id = $1 AND path = ANY($2) AND is_deleted = false",
    )
    .bind(repo_id)
    .bind(paths)
    .fetch_all(db)
    .await?;
    let mut live: HashMap<String, HashSet<String>> = HashMap::new();
    for (path, sha) in rows {
        live.entry(path).or_default().insert(sha);
    }
    Ok(live)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Report which of the given artifacts the repository does not already hold.
#[utoipa::path(
    post,
    path = "/{key}/artifacts-missing",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(("key" = String, Path, description = "Repository key")),
    request_body = MissingArtifactsRequest,
    responses(
        (status = 200, description = "The subset of items not present with the given checksum", body = MissingArtifactsResponse),
        (status = 400, description = "Too many items, an invalid path or digest, or a remote/virtual repository", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found or not readable by the caller", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []), ())
)]
pub async fn missing_artifacts(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<MissingArtifactsRequest>,
) -> Result<Json<MissingArtifactsResponse>> {
    // Visibility first: a caller who cannot read the repository must get the
    // same 404 as for a nonexistent one, whatever the body contains.
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;
    if !presence_supported(&repo.repo_type) {
        return Err(AppError::Validation(format!(
            "presence checks are only supported on hosted repositories; '{key}' is {}",
            repo.repo_type.as_str()
        )));
    }

    let items = validate_items(&req.items)?;
    let checked = items.len();
    let live = if items.is_empty() {
        HashMap::new()
    } else {
        live_checksums(&state.db, repo.id, &distinct_paths(&items)).await?
    };
    Ok(Json(MissingArtifactsResponse {
        checked,
        missing: classify_missing(items, &live),
    }))
}

/// What an upload-init request declares about the file it is about to send.
pub(crate) struct DeclaredUpload<'a> {
    pub path: &'a str,
    pub checksum_sha256: &'a str,
    pub total_size: i64,
    pub version: Option<&'a str>,
}

/// Upload-init short-circuit: the artifact at `declared.path` in `repo`, if it
/// is already stored with the declared checksum and size and the caller may
/// read the repository.
///
/// Any failure (no read access, malformed digest, DB or storage error) yields
/// `None`, and the caller opens a normal session: this is an optimisation and
/// must never turn an upload that would have worked into an error.
pub(crate) async fn already_present_for_session(
    state: &SharedState,
    auth: &AuthExtension,
    repo: &Repository,
    repo_service: &RepositoryService,
    declared: DeclaredUpload<'_>,
) -> Option<AlreadyPresentResponse> {
    // Opening a session needs write; answering "already present" discloses
    // what is stored, which needs read. A write-only caller gets a session.
    require_visible(repo, &Some(auth.clone()), repo_service)
        .await
        .ok()?;
    let sha = normalize_sha256(declared.checksum_sha256)?;
    let (artifact_id, size, version, storage_key): (Uuid, i64, Option<String>, String) =
        sqlx::query_as(
            "SELECT id, size_bytes, version, storage_key FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false \
               AND lower(checksum_sha256) = $3 \
             LIMIT 1",
        )
        .bind(repo.id)
        .bind(declared.path)
        .bind(&sha)
        .fetch_optional(&state.db)
        .await
        .ok()??;
    if !row_satisfies_request(
        size,
        version.as_deref(),
        declared.total_size,
        declared.version,
    ) {
        return None;
    }
    // The row alone is not enough: the object must still be in storage, or a
    // re-upload is exactly what repairs it. `content_already_stored` answers
    // `false` on a migration-mode backend, which also falls through.
    let storage = state.storage_for_repo(&repo.storage_location()).ok()?;
    if !storage
        .content_already_stored(&storage_key)
        .await
        .unwrap_or(false)
    {
        return None;
    }
    Some(AlreadyPresentResponse {
        already_present: true,
        artifact_id,
        path: declared.path.to_string(),
        size,
        checksum_sha256: sha,
    })
}

#[derive(OpenApi)]
#[openapi(paths(missing_artifacts))]
pub struct ArtifactPresenceApiDoc;

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
// streaming-invariant: test scaffolding exempt — buffering bounded response
// bodies in DB-backed handler tests is not an artifact path (#1608).
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;
    use bytes::Bytes;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn item(path: &str, sha256: &str) -> ArtifactPresenceItem {
        ArtifactPresenceItem {
            path: path.to_string(),
            sha256: sha256.to_string(),
        }
    }

    #[test]
    fn normalize_sha256_accepts_hex_and_lowercases() {
        assert_eq!(normalize_sha256(&SHA_A.to_uppercase()), Some(SHA_A.into()));
        assert_eq!(normalize_sha256(&SHA_A[..63]), None);
        assert_eq!(normalize_sha256(&format!("{}g", &SHA_A[..63])), None);
        assert_eq!(normalize_sha256(""), None);
    }

    #[test]
    fn presence_only_supported_on_hosted_repositories() {
        assert!(presence_supported(&RepositoryType::Local));
        assert!(presence_supported(&RepositoryType::Staging));
        assert!(!presence_supported(&RepositoryType::Remote));
        assert!(!presence_supported(&RepositoryType::Virtual));
    }

    #[test]
    fn validate_items_enforces_cap_and_names_bad_index() {
        let at_cap = vec![item("a/b.jar", SHA_A); MAX_PRESENCE_ITEMS];
        assert_eq!(validate_items(&at_cap).unwrap().len(), MAX_PRESENCE_ITEMS);

        let over = vec![item("a/b.jar", SHA_A); MAX_PRESENCE_ITEMS + 1];
        let err = validate_items(&over).unwrap_err().to_string();
        assert!(err.contains("too many items"), "{err}");

        let bad_sha = [item("a/b.jar", SHA_A), item("a/c.jar", "xyz")];
        let err = validate_items(&bad_sha).unwrap_err().to_string();
        assert!(err.contains("items[1].sha256"), "{err}");

        let bad_path = [item("../etc/passwd", SHA_A)];
        let err = validate_items(&bad_path).unwrap_err().to_string();
        assert!(err.contains("items[0].path"), "{err}");

        let ok = validate_items(&[item("a/b.jar", &SHA_B.to_uppercase())]).unwrap();
        assert_eq!(ok, vec![("a/b.jar".to_string(), SHA_B.to_string())]);
    }

    #[test]
    fn distinct_paths_dedupes_in_order() {
        let items = vec![
            ("b".to_string(), SHA_A.to_string()),
            ("a".to_string(), SHA_A.to_string()),
            ("b".to_string(), SHA_B.to_string()),
        ];
        assert_eq!(distinct_paths(&items), vec!["b", "a"]);
    }

    #[test]
    fn classify_missing_reports_absent_and_mismatched_in_order() {
        let mut live = HashMap::new();
        live.insert("present".to_string(), HashSet::from([SHA_A.to_string()]));
        live.insert("changed".to_string(), HashSet::from([SHA_B.to_string()]));
        let items = vec![
            ("absent".to_string(), SHA_A.to_string()),
            ("present".to_string(), SHA_A.to_string()),
            ("changed".to_string(), SHA_A.to_string()),
        ];
        let missing = classify_missing(items, &live);
        assert_eq!(
            missing,
            vec![
                MissingArtifact {
                    path: "absent".into(),
                    sha256: SHA_A.into(),
                    reason: MissingReason::NotFound,
                },
                MissingArtifact {
                    path: "changed".into(),
                    sha256: SHA_A.into(),
                    reason: MissingReason::ChecksumMismatch,
                },
            ]
        );
    }

    #[test]
    fn row_satisfies_request_checks_size_and_named_version() {
        assert!(row_satisfies_request(10, Some("1.0"), 10, None));
        assert!(row_satisfies_request(10, Some("1.0"), 10, Some("1.0")));
        assert!(!row_satisfies_request(10, Some("1.0"), 11, None));
        assert!(!row_satisfies_request(10, Some("1.0"), 10, Some("2.0")));
        assert!(!row_satisfies_request(10, None, 10, Some("1.0")));
    }

    // -----------------------------------------------------------------------
    // DB-backed: the endpoint and the upload-init short-circuit end to end.
    // -----------------------------------------------------------------------

    /// Store `content` under its CAS key and insert a live artifact row at
    /// `path` carrying its real SHA-256. Returns `(artifact_id, sha256)`.
    async fn seed(fx: &tdh::Fixture, path: &str, content: &[u8]) -> (Uuid, String) {
        use sha2::{Digest, Sha256};
        let sha = format!("{:x}", Sha256::digest(content));
        let key =
            crate::services::artifact_service::ArtifactService::storage_key_from_checksum(&sha);
        let repo = fx.repo_info("local", None);
        crate::api::handlers::proxy_helpers::put_artifact_bytes(
            &fx.state,
            &repo,
            &key,
            Bytes::copy_from_slice(content),
        )
        .await
        .expect("seed bytes");
        let id = crate::api::handlers::proxy_helpers::insert_artifact(
            &fx.pool,
            crate::api::handlers::proxy_helpers::NewArtifact {
                repository_id: fx.repo_id,
                path,
                name: path.rsplit('/').next().unwrap_or(path),
                version: "1.0",
                size_bytes: content.len() as i64,
                checksum_sha256: &sha,
                content_type: "application/octet-stream",
                storage_key: &key,
                uploaded_by: fx.user_id,
            },
        )
        .await
        .expect("seed row");
        (id, sha)
    }

    fn post_json(uri: String, body: &serde_json::Value) -> axum::http::Request<axum::body::Body> {
        tdh::post(
            uri,
            "application/json",
            Bytes::from(serde_json::to_vec(body).unwrap()),
        )
    }

    async fn check(
        app: axum::Router,
        repo_key: &str,
        items: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = post_json(
            format!("/{repo_key}/artifacts-missing"),
            &serde_json::json!({ "items": items }),
        );
        let (status, body) = tdh::send(app, req).await;
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Mixed present / missing / mismatched items, the cap, and a caller who
    /// cannot read the repository.
    #[tokio::test]
    async fn missing_endpoint_returns_only_missing_subset() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let (_, sha_lib) = seed(&fx, "deps/lib-1.0.jar", b"lib bytes").await;
        let (_, sha_pom) = seed(&fx, "deps/lib-1.0.pom", b"pom bytes").await;
        let app = fx.router_with_auth(repo_router());

        let (status, body) = check(
            app.clone(),
            &fx.repo_key,
            serde_json::json!([
                { "path": "deps/lib-1.0.jar", "sha256": sha_lib.to_uppercase() },
                { "path": "deps/lib-1.0.pom", "sha256": SHA_A },
                { "path": "deps/new-2.0.jar", "sha256": SHA_B },
                { "path": "deps/lib-1.0.pom", "sha256": sha_pom },
            ]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["checked"], 4);
        assert_eq!(
            body["missing"],
            serde_json::json!([
                { "path": "deps/lib-1.0.pom", "sha256": SHA_A, "reason": "checksum_mismatch" },
                { "path": "deps/new-2.0.jar", "sha256": SHA_B, "reason": "not_found" },
            ])
        );

        // Over the cap is a 400, not a truncated answer.
        let over: Vec<_> = (0..=MAX_PRESENCE_ITEMS)
            .map(|i| serde_json::json!({ "path": format!("p/{i}"), "sha256": SHA_A }))
            .collect();
        let (status, body) = check(app.clone(), &fx.repo_key, serde_json::json!(over)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // A soft-deleted artifact is missing again.
        sqlx::query(
            "UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND path = $2",
        )
        .bind(fx.repo_id)
        .bind("deps/lib-1.0.jar")
        .execute(&fx.pool)
        .await
        .unwrap();
        let (_, body) = check(
            app,
            &fx.repo_key,
            serde_json::json!([{ "path": "deps/lib-1.0.jar", "sha256": sha_lib }]),
        )
        .await;
        assert_eq!(body["missing"][0]["reason"], "not_found");

        // A non-member gets the existence-hiding 404, even for an item that
        // is present, and even with an over-cap body.
        let (stranger_id, stranger_name) = tdh::create_user(&fx.pool).await;
        let stranger = tdh::router_with_auth(
            repo_router(),
            fx.state.clone(),
            tdh::make_auth(stranger_id, &stranger_name),
        );
        let (status, _) = check(
            stranger.clone(),
            &fx.repo_key,
            serde_json::json!([{ "path": "deps/lib-1.0.pom", "sha256": sha_pom }]),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = check(stranger, &fx.repo_key, serde_json::json!(over)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = check(
            fx.router_anon(repo_router()),
            &fx.repo_key,
            serde_json::json!([]),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        tdh::cleanup_user(&fx.pool, stranger_id).await;
        fx.teardown().await;
    }

    #[tokio::test]
    async fn missing_endpoint_rejects_virtual_repository() {
        let Some(fx) = tdh::Fixture::setup("virtual", "generic").await else {
            return;
        };
        let (status, body) = check(
            fx.router_with_auth(repo_router()),
            &fx.repo_key,
            serde_json::json!([]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        fx.teardown().await;
    }

    async fn init_session(
        fx: &tdh::Fixture,
        auth: AuthExtension,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let app = crate::api::handlers::upload::router()
            .with_state(fx.state.clone())
            .layer(Extension::<AuthExtension>(auth));
        let (status, body) = tdh::send(app, post_json("/".to_string(), &body)).await;
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn drop_session(fx: &tdh::Fixture, body: &serde_json::Value) {
        if let Some(id) = body["session_id"]
            .as_str()
            .and_then(|s| s.parse::<Uuid>().ok())
        {
            let _ = sqlx::query("DELETE FROM upload_chunks WHERE session_id = $1")
                .bind(id)
                .execute(&fx.pool)
                .await;
            let _ = sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
                .bind(id)
                .execute(&fx.pool)
                .await;
        }
    }

    /// `skip_if_present` answers 200 `already_present` without opening a
    /// session only when the row, checksum, size and stored object all line up
    /// and the caller can read the repository; every other case still opens a
    /// session (201), and so does a request that does not opt in.
    #[tokio::test]
    async fn upload_init_short_circuits_when_already_present() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let content = b"ferried bytes";
        let (artifact_id, sha) = seed(&fx, "ferry/blob.bin", content).await;
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let request = |path: &str, sha: &str, size: usize, skip: Option<bool>| {
            let mut body = serde_json::json!({
                "repository_key": fx.repo_key,
                "artifact_path": path,
                "total_size": size as i64,
                "checksum_sha256": sha,
            });
            if let Some(skip) = skip {
                body["skip_if_present"] = serde_json::json!(skip);
            }
            body
        };

        let (status, body) = init_session(
            &fx,
            auth.clone(),
            request(
                "ferry/blob.bin",
                &sha.to_uppercase(),
                content.len(),
                Some(true),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["already_present"], true);
        assert_eq!(body["artifact_id"], artifact_id.to_string());
        assert_eq!(body["checksum_sha256"], sha);
        assert!(body.get("session_id").is_none());

        let cases = [
            (
                "not opted in",
                request("ferry/blob.bin", &sha, content.len(), None),
            ),
            (
                "opted out",
                request("ferry/blob.bin", &sha, content.len(), Some(false)),
            ),
            (
                "different path",
                request("ferry/other.bin", &sha, content.len(), Some(true)),
            ),
            (
                "different checksum",
                request("ferry/blob.bin", SHA_A, content.len(), Some(true)),
            ),
            (
                "different size",
                request("ferry/blob.bin", &sha, content.len() + 1, Some(true)),
            ),
        ];
        for (label, req) in cases {
            let (status, body) = init_session(&fx, auth.clone(), req).await;
            assert_eq!(status, StatusCode::CREATED, "{label}: {body}");
            assert!(body.get("session_id").is_some(), "{label}: {body}");
            drop_session(&fx, &body).await;
        }

        // A write-only caller (no read grant) must not learn the artifact is
        // there: it gets an ordinary session.
        let (writer_id, writer_name) = tdh::create_user(&fx.pool).await;
        tdh::grant_repo_actions(&fx.pool, fx.repo_id, writer_id, &["write"]).await;
        let (status, body) = init_session(
            &fx,
            tdh::make_auth(writer_id, &writer_name),
            request("ferry/blob.bin", &sha, content.len(), Some(true)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "write-only: {body}");
        drop_session(&fx, &body).await;
        tdh::cleanup_user(&fx.pool, writer_id).await;

        // The row alone is not enough: with the object gone the client must
        // upload again so the blob is repaired.
        let key =
            crate::services::artifact_service::ArtifactService::storage_key_from_checksum(&sha);
        let storage = fx
            .state
            .storage_for_repo(&fx.repo_info("local", None).storage_location())
            .unwrap();
        storage.delete(&key).await.unwrap();
        let (status, body) = init_session(
            &fx,
            auth,
            request("ferry/blob.bin", &sha, content.len(), Some(true)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "object missing: {body}");
        drop_session(&fx, &body).await;

        fx.teardown().await;
    }
}
