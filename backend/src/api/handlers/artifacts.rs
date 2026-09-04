//! Artifact handlers - standalone artifact operations.
//!
//! These handlers provide direct access to artifacts by ID, complementing
//! the repository-nested artifact routes in repositories.rs.

use axum::{
    extract::{Path, State},
    routing::get,
    Extension, Json, Router,
};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::repositories::ArtifactResponse;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Check that the caller is allowed to see this artifact.
///
/// Unauthenticated requests are rejected for artifacts in private repos.
/// Authenticated requests with repository-scoped API tokens are rejected
/// if the artifact's repository is not in the token's allowed set.
///
/// # The `action` argument (#3704)
///
/// `action` is the `permissions` verb the calling handler performs — `read`
/// for the by-id reads and their sub-resource siblings, `write` / `delete` for
/// the label and SBOM mutations that share this gate. It is threaded (rather
/// than fixed, the way `require_visible` fixes `read`) precisely because the
/// call sites genuinely differ, and only the `read` ones take the public
/// short-circuit below.
///
/// On a `read`, a **public** repository satisfies the token repository-scope
/// ceiling, via the same [`public_read_satisfies_acl`] baseline
/// `require_visible` — the canonical REST read gate on the very same
/// repositories — has always applied unconditionally (#2329). Without it the
/// ceiling ran first, and the `None` arm below serves an anonymous caller a
/// public artifact without ever reaching it: presenting a repository-scoped
/// credential returned 403 where presenting no credential returned 200.
///
/// Writes and deletes are unaffected: `public_read_satisfies_acl` is read-only
/// by construction, so a token scoped to repo A still cannot set or remove a
/// label on an artifact in public repo B — which matters here because
/// `authorize_label_write` checks only the token's *action* scope, leaving this
/// gate as the sole repository ceiling on that path. Private repositories never
/// take the shortcut.
///
/// [`public_read_satisfies_acl`]: crate::api::middleware::auth::public_read_satisfies_acl
pub(crate) async fn check_artifact_visibility(
    auth: &Option<AuthExtension>,
    artifact_id: Uuid,
    db: &sqlx::PgPool,
    action: &str,
) -> Result<()> {
    // Always fetch repo info so we can check both visibility and token scope.
    let repo_info: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT r.id, r.is_public FROM repositories r \
         JOIN artifacts a ON a.repository_id = r.id WHERE a.id = $1",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some((repo_id, is_public)) = repo_info else {
        // No matching repo means the artifact query upstream will 404.
        return Ok(());
    };

    match auth {
        Some(ext) => {
            // #3704: a public repository confers a read baseline that the token
            // repository-scope ceiling must not take away, since the `None` arm
            // below grants exactly that baseline with no credential at all.
            if crate::api::middleware::auth::public_read_satisfies_acl(is_public, action) {
                return Ok(());
            }
            // Enforce API token repository scope: if the token is restricted
            // to specific repos, the artifact's repo must be in that set.
            if !ext.can_access_repo(repo_id) {
                return Err(AppError::Authorization(
                    "Token does not have access to this repository".to_string(),
                ));
            }
            // Per-repo authorization for private repos: admins bypass; every
            // other caller must hold a role assignment scoped to the repo
            // (direct or global). NotFound (not Forbidden) avoids leaking the
            // existence of repositories the caller may not see.
            if !is_public && !ext.is_admin {
                let repo_service =
                    crate::services::repository_service::RepositoryService::new(db.clone());
                if !repo_service
                    .user_can_access_repo(
                        repo_id,
                        ext.user_id,
                        // CONTENT path (#3331): this gate fronts the artifact
                        // bytes and their label / security / SBOM / quality-gate
                        // siblings, so it asks for `read`, not merely "holds a
                        // grant".
                        crate::services::repository_service::RepoAccess::READ,
                    )
                    .await?
                {
                    return Err(AppError::NotFound("Artifact not found".to_string()));
                }
            }
            Ok(())
        }
        None => {
            if !is_public {
                return Err(AppError::NotFound("Artifact not found".to_string()));
            }
            Ok(())
        }
    }
}

/// Create artifact routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:id", get(get_artifact))
        .route("/:id/metadata", get(get_artifact_metadata))
        .route("/:id/stats", get(get_artifact_stats))
        .merge(super::artifact_labels::artifact_labels_router())
}

/// Row shape for the by-id artifact lookup.
///
/// Runtime `query_as` (not the compile-time macro) so the query needs no
/// `.sqlx` offline entry; the columns mirror what
/// [`ArtifactResponse`] needs.
#[derive(Debug, sqlx::FromRow)]
struct ArtifactByIdRow {
    id: Uuid,
    repository_key: String,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    content_type: String,
    created_at: chrono::DateTime<chrono::Utc>,
    quarantine_status: Option<String>,
    quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Uploader id from the `artifacts` row, plus the display name resolved
    /// by the same query's `LEFT JOIN users` (#3271) — so the detail view
    /// gets the uploader without a second, admin-only user lookup. The join
    /// is a LEFT one: a deleted uploader leaves the id with a `NULL` name.
    uploaded_by: Option<Uuid>,
    uploaded_by_username: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactMetadataResponse {
    pub artifact_id: Uuid,
    pub format: String,
    pub metadata: serde_json::Value,
    pub properties: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactStatsResponse {
    pub artifact_id: Uuid,
    pub download_count: i64,
    pub first_downloaded: Option<chrono::DateTime<chrono::Utc>>,
    pub last_downloaded: Option<chrono::DateTime<chrono::Utc>>,
}

/// Get artifact by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/artifacts",
    tag = "artifacts",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "Artifact details", body = ArtifactResponse),
        (status = 404, description = "Artifact not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactResponse>> {
    let artifact: ArtifactByIdRow = sqlx::query_as(
        "SELECT a.id, r.key AS repository_key, a.path, a.name, a.version, \
                a.size_bytes, a.checksum_sha256, a.content_type, a.created_at, \
                a.quarantine_status, a.quarantine_until, \
                a.uploaded_by, u.username AS uploaded_by_username \
         FROM artifacts a \
         JOIN repositories r ON r.id = a.repository_id \
         LEFT JOIN users u ON u.id = a.uploaded_by \
         WHERE a.id = $1 AND a.is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    check_artifact_visibility(&auth, id, &state.db, "read").await?;

    let download_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let metadata: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(ArtifactResponse {
        id: artifact.id,
        repository_key: artifact.repository_key,
        path: artifact.path,
        name: artifact.name,
        version: artifact.version,
        size_bytes: artifact.size_bytes,
        checksum_sha256: artifact.checksum_sha256,
        content_type: artifact.content_type,
        download_count,
        created_at: artifact.created_at,
        uploaded_by: artifact.uploaded_by,
        uploaded_by_username: artifact.uploaded_by_username,
        metadata,
        // This handler resolves a real `artifacts` row by id, so it is
        // always a hosted artifact (analyzable), matching the by-path
        // handler in repositories.rs.
        analyzable: true,
        // Proxy cache freshness is a Remote-repo, by-path concern; the
        // by-id surface does not resolve through the proxy cache.
        cache_cached_at: None,
        cache_expires_at: None,
        // Revision history is a by-path, versioned-repo concern (#2367);
        // the by-id surface leaves it unset.
        revision: None,
        version_label: None,
        // Surface the resolved row's quarantine state, matching the listing
        // (#2940). Same joined query — no extra round-trip.
        quarantine_status: crate::api::handlers::repositories::quarantine_status_label(
            artifact.quarantine_status.as_deref(),
        ),
        quarantine_until: artifact.quarantine_until,
    }))
}

/// Precondition shared by the by-id sub-resource endpoints (`/metadata`,
/// `/stats`): the artifact must exist and not be soft-deleted, and the caller
/// must be allowed to see the repository that owns it.
///
/// `get_artifact_metadata` and `get_artifact_stats` carried byte-identical
/// copies of this guard. The ORDER is load-bearing and is preserved exactly:
/// the existence check runs first and returns the same generic "Artifact not
/// found" for a soft-deleted or non-existent id, and only then is
/// [`check_artifact_visibility`] consulted — so the pair of checks cannot be
/// used to distinguish "exists but you may not see it" from "does not exist".
async fn require_existing_visible_artifact(
    state: &SharedState,
    auth: &Option<AuthExtension>,
    id: Uuid,
) -> Result<()> {
    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = $1 AND is_deleted = false)",
        id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if exists != Some(true) {
        return Err(AppError::NotFound("Artifact not found".to_string()));
    }

    check_artifact_visibility(auth, id, &state.db, "read").await
}

/// Get artifact metadata by artifact ID
#[utoipa::path(
    get,
    path = "/{id}/metadata",
    context_path = "/api/v1/artifacts",
    tag = "artifacts",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "Artifact metadata", body = ArtifactMetadataResponse),
        (status = 404, description = "Artifact or metadata not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_artifact_metadata(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactMetadataResponse>> {
    require_existing_visible_artifact(&state, &auth, id).await?;

    let metadata = sqlx::query!(
        r#"
        SELECT artifact_id, format, metadata, properties
        FROM artifact_metadata
        WHERE artifact_id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact metadata not found".to_string()))?;

    Ok(Json(ArtifactMetadataResponse {
        artifact_id: metadata.artifact_id,
        format: metadata.format,
        metadata: metadata.metadata,
        properties: metadata.properties,
    }))
}

/// Get artifact download statistics
#[utoipa::path(
    get,
    path = "/{id}/stats",
    context_path = "/api/v1/artifacts",
    tag = "artifacts",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "Artifact download statistics", body = ArtifactStatsResponse),
        (status = 404, description = "Artifact not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_artifact_stats(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactStatsResponse>> {
    require_existing_visible_artifact(&state, &auth, id).await?;

    let stats = sqlx::query!(
        r#"
        SELECT
            COUNT(*) as "download_count!",
            MIN(downloaded_at) as first_downloaded,
            MAX(downloaded_at) as last_downloaded
        FROM download_statistics
        WHERE artifact_id = $1
        "#,
        id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(ArtifactStatsResponse {
        artifact_id: id,
        download_count: stats.download_count,
        first_downloaded: stats.first_downloaded,
        last_downloaded: stats.last_downloaded,
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(get_artifact, get_artifact_metadata, get_artifact_stats,),
    // `ArtifactResponse` is intentionally NOT registered here: the canonical
    // schema lives in repositories.rs (RepositoriesApiDoc). Registering a
    // second struct under the same name used to shadow it (utoipa merge is
    // first-wins on schema names) and published a stale shape for
    // GET /api/v1/artifacts/{id}. See the schema-name-uniqueness regression
    // test in openapi.rs.
    components(schemas(ArtifactMetadataResponse, ArtifactStatsResponse,))
)]
pub struct ArtifactsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Baseline `ArtifactResponse` for the serialization tests below.
    ///
    /// The tests differ in only a handful of fields each, so they share one
    /// constructor and override just what they exercise. Previously every test
    /// spelled out the whole literal, which meant each field added to the
    /// struct was duplicated four more times.
    fn sample_response() -> ArtifactResponse {
        ArtifactResponse {
            revision: None,
            version_label: None,
            id: Uuid::new_v4(),
            repository_key: "generic-local".to_string(),
            path: "file.tar.gz".to_string(),
            name: "file".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "sha".to_string(),
            content_type: "application/octet-stream".to_string(),
            download_count: 0,
            created_at: Utc::now(),
            uploaded_by: None,
            uploaded_by_username: None,
            metadata: None,
            analyzable: true,
            cache_cached_at: None,
            cache_expires_at: None,
            quarantine_status: "not_quarantined".to_string(),
            quarantine_until: None,
        }
    }

    // ── ArtifactResponse serialization tests ────────────────────────
    //
    // The by-id endpoint now serves the canonical repositories.rs
    // ArtifactResponse (the shape the published OpenAPI spec has always
    // declared). These tests pin the on-the-wire contract of that shape as
    // served by GET /api/v1/artifacts/{id}.

    #[test]
    fn test_artifact_response_serialization_all_fields() {
        let id = Uuid::new_v4();
        let resp = ArtifactResponse {
            id,
            repository_key: "maven-releases".to_string(),
            path: "com/example/lib/1.0/lib-1.0.jar".to_string(),
            name: "lib".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 102400,
            checksum_sha256: "abc123".to_string(),
            content_type: "application/java-archive".to_string(),
            download_count: 42,
            metadata: Some(serde_json::json!({"groupId": "com.example"})),
            ..sample_response()
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], id.to_string());
        assert_eq!(json["repository_key"], "maven-releases");
        assert_eq!(json["path"], "com/example/lib/1.0/lib-1.0.jar");
        assert_eq!(json["name"], "lib");
        assert_eq!(json["version"], "1.0");
        assert_eq!(json["size_bytes"], 102400);
        assert_eq!(json["checksum_sha256"], "abc123");
        assert_eq!(json["content_type"], "application/java-archive");
        // Spec-required fields the by-id endpoint previously omitted (#98).
        assert_eq!(json["download_count"], 42);
        assert_eq!(json["analyzable"], true);
        assert_eq!(json["metadata"]["groupId"], "com.example");
    }

    #[test]
    fn test_artifact_response_no_undeclared_fields() {
        // The previous local ArtifactResponse leaked DB columns the spec
        // never declared. Pin their absence on the serialized output.
        let resp = sample_response();
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        for undeclared in [
            "repository_id",
            "checksum_md5",
            "checksum_sha1",
            "updated_at",
        ] {
            assert!(
                !obj.contains_key(undeclared),
                "`{undeclared}` is not part of the published ArtifactResponse schema"
            );
        }
        // Cache freshness fields are skip_serializing_if = None.
        assert!(!obj.contains_key("cache_cached_at"));
        assert!(!obj.contains_key("cache_expires_at"));
        assert!(json["version"].is_null());
        assert!(json["metadata"].is_null());
    }

    #[test]
    fn test_artifact_response_zero_size() {
        let resp = ArtifactResponse {
            path: "empty".to_string(),
            name: "empty".to_string(),
            size_bytes: 0,
            checksum_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            analyzable: false,
            ..sample_response()
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["size_bytes"], 0);
        assert_eq!(json["analyzable"], false);
    }

    // ── ArtifactMetadataResponse serialization tests ────────────────

    #[test]
    fn test_artifact_metadata_response_serialization() {
        let resp = ArtifactMetadataResponse {
            artifact_id: Uuid::new_v4(),
            format: "maven".to_string(),
            metadata: serde_json::json!({"groupId": "com.example", "artifactId": "lib"}),
            properties: serde_json::json!({"build.number": "42"}),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["format"], "maven");
        assert_eq!(json["metadata"]["groupId"], "com.example");
        assert_eq!(json["properties"]["build.number"], "42");
    }

    #[test]
    fn test_artifact_metadata_response_empty_metadata() {
        let resp = ArtifactMetadataResponse {
            artifact_id: Uuid::new_v4(),
            format: "generic".to_string(),
            metadata: serde_json::json!({}),
            properties: serde_json::json!({}),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["metadata"].as_object().unwrap().is_empty());
        assert!(json["properties"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_artifact_metadata_response_complex_metadata() {
        let resp = ArtifactMetadataResponse {
            artifact_id: Uuid::new_v4(),
            format: "npm".to_string(),
            metadata: serde_json::json!({
                "name": "@scope/pkg",
                "version": "2.0.0",
                "dependencies": {"lodash": "^4.0.0"},
                "keywords": ["test", "example"]
            }),
            properties: serde_json::json!(null),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["metadata"]["dependencies"]["lodash"], "^4.0.0");
        assert!(json["properties"].is_null());
    }

    // ── ArtifactStatsResponse serialization tests ───────────────────

    #[test]
    fn test_artifact_stats_response_with_downloads() {
        let now = Utc::now();
        let resp = ArtifactStatsResponse {
            artifact_id: Uuid::new_v4(),
            download_count: 1234,
            first_downloaded: Some(now - chrono::Duration::days(30)),
            last_downloaded: Some(now),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["download_count"], 1234);
        assert!(!json["first_downloaded"].is_null());
        assert!(!json["last_downloaded"].is_null());
    }

    #[test]
    fn test_artifact_stats_response_no_downloads() {
        let resp = ArtifactStatsResponse {
            artifact_id: Uuid::new_v4(),
            download_count: 0,
            first_downloaded: None,
            last_downloaded: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["download_count"], 0);
        assert!(json["first_downloaded"].is_null());
        assert!(json["last_downloaded"].is_null());
    }

    #[test]
    fn test_artifact_stats_response_large_download_count() {
        let resp = ArtifactStatsResponse {
            artifact_id: Uuid::new_v4(),
            download_count: i64::MAX,
            first_downloaded: None,
            last_downloaded: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["download_count"], i64::MAX);
    }

    // ── Struct field visibility / construction tests ─────────────────

    #[test]
    fn test_artifact_response_debug_impl() {
        let resp = sample_response();
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("ArtifactResponse"));
    }

    #[test]
    fn test_artifact_metadata_response_debug_impl() {
        let resp = ArtifactMetadataResponse {
            artifact_id: Uuid::nil(),
            format: "generic".to_string(),
            metadata: serde_json::json!(null),
            properties: serde_json::json!(null),
        };
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("ArtifactMetadataResponse"));
    }
}

// ---------------------------------------------------------------------------
// #3704: the by-id artifact gate must not put a repository-scoped credential
// below the anonymous read baseline of a PUBLIC repository.
//
// Router-level and DB-backed, driven through the real `artifacts::router()`
// (which merges the label routes) so both the read and the write halves of
// `check_artifact_visibility` are proven where they actually run. No-ops when
// no database is configured; `AK_TESTS_REQUIRE_DB=1` turns an unreachable
// database into a hard failure rather than a silent skip.
// ---------------------------------------------------------------------------
#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod public_read_repo_scope_3704 {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use bytes::Bytes;

    /// The refusal the token repository-scope ceiling emits, rendered by
    /// `AppError::Authorization` (403 `FORBIDDEN`). Asserted as the BODY and
    /// not merely the status because this gate can also refuse with
    /// `AppError::NotFound` ("Artifact not found") from the private-repo arm
    /// below it — a status-only assertion cannot tell the two apart.
    fn scope_denied() -> (StatusCode, String) {
        (
            StatusCode::FORBIDDEN,
            "{\"code\":\"FORBIDDEN\",\"message\":\"Token does not have access to this \
             repository\"}"
                .to_string(),
        )
    }

    /// Verified-bug regression for #3704 (REST artifact read path).
    ///
    /// `check_artifact_visibility` ran the #504 token repository-scope check
    /// before anything looked at `is_public`, while its own `None` arm serves
    /// an anonymous caller a public repository's artifact unconditionally.
    /// Reproduced live on `main`:
    ///
    ///   GET /api/v1/artifacts/{id-in-public-B}  no credential           -> 200
    ///   GET /api/v1/artifacts/{id-in-public-B}  token scoped to repo A  -> 403
    ///
    /// The fix is READ-ONLY, which matters more here than on the other #3704
    /// surfaces: `authorize_label_write` checks only the token's *action*
    /// scope, so this gate is the sole repository ceiling on the label
    /// mutations that share it. The write assertions below are therefore not
    /// vacuous — the caller holds a real `write`/`delete` grant on public repo
    /// B, so with the ceiling gone the PUT and the DELETE SUCCEED rather than
    /// falling through to a second refusal.
    #[tokio::test]
    async fn test_3704_public_repo_artifact_read_is_not_refused_to_an_out_of_scope_token() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        // A: the token's own repository (private, granted) — positive control.
        // B: a PUBLIC repository outside the scope — the subject.
        // C: a PRIVATE repository outside the scope, granted, so only the
        //    scope ceiling can refuse it.
        let (repo_a, key_a, dir_a) = tdh::create_repo(&pool, "local", "generic").await;
        let (repo_b, key_b, dir_b) = tdh::create_repo(&pool, "local", "generic").await;
        let (repo_c, key_c, dir_c) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::publish_repo(&pool, repo_b).await;
        for repo in [repo_a, repo_b, repo_c] {
            tdh::grant_repo_access(&pool, repo, user_id).await;
            // Fine-grained read/write/delete on every repository, so the ONLY
            // thing that can refuse below is the repository-scope ceiling.
            tdh::grant_repo_actions(&pool, repo, user_id, &["read", "write", "delete"]).await;
        }

        let state = tdh::build_state(pool.clone(), dir_b.to_str().unwrap());
        let seed = |repo: Uuid, key: &str, dir: &std::path::Path| {
            let state = state.clone();
            let pool = pool.clone();
            let info = tdh::make_repo_info(repo, key, dir, "local", None);
            async move {
                tdh::seed_artifact(
                    &state,
                    &pool,
                    &info,
                    "pkg/file.txt",
                    "pkg/file.txt",
                    "file.txt",
                    "1.0.0",
                    "text/plain",
                    Bytes::from_static(b"public-artifact-3704"),
                    user_id,
                )
                .await
            }
        };
        let art_a = seed(repo_a, &key_a, &dir_a).await;
        let art_b = seed(repo_b, &key_b, &dir_b).await;
        let art_c = seed(repo_c, &key_c, &dir_c).await;

        // Exactly what `optional_auth_middleware` injects for a repository-scoped
        // API token: `AccessScope::Restricted([A])`, which is what
        // `validate_api_token` builds from the `api_token_repositories` rows.
        let mut scoped = tdh::make_auth(user_id, &username);
        scoped.is_api_token = true;
        scoped.allowed_repo_ids =
            crate::models::access_scope::AccessScope::Restricted(vec![repo_a]);

        let probe = |auth: Option<AuthExtension>, req: Request<Body>| {
            let state = state.clone();
            async move {
                let app = match auth {
                    Some(a) => tdh::router_with_auth(router(), state, a),
                    None => tdh::router_anon(router(), state),
                };
                let (status, body) = tdh::send(app, req).await;
                (status, String::from_utf8_lossy(&body).into_owned())
            }
        };
        let labels_body = || Bytes::from_static(br#"{"labels":[{"key":"k","value":"v"}]}"#);
        let delete_label = |id: Uuid| {
            Request::builder()
                .method("DELETE")
                .uri(format!("/{id}/labels/k"))
                .body(Body::empty())
                .expect("build DELETE")
        };

        let in_scope = probe(Some(scoped.clone()), tdh::get(format!("/{art_a}"))).await;
        let public_anon = probe(None, tdh::get(format!("/{art_b}"))).await;
        let public_scoped = probe(Some(scoped.clone()), tdh::get(format!("/{art_b}"))).await;
        let metadata_anon = probe(None, tdh::get(format!("/{art_b}/metadata"))).await;
        let metadata_scoped =
            probe(Some(scoped.clone()), tdh::get(format!("/{art_b}/metadata"))).await;
        let stats_anon = probe(None, tdh::get(format!("/{art_b}/stats"))).await;
        let stats_scoped = probe(Some(scoped.clone()), tdh::get(format!("/{art_b}/stats"))).await;
        let public_put = probe(
            Some(scoped.clone()),
            tdh::put_json(format!("/{art_b}/labels"), labels_body()),
        )
        .await;
        let public_delete = probe(Some(scoped.clone()), delete_label(art_b)).await;
        let private_scoped = probe(Some(scoped.clone()), tdh::get(format!("/{art_c}"))).await;
        let private_anon = probe(None, tdh::get(format!("/{art_c}"))).await;
        // Positive control for the write half: the SAME PUT, in scope, succeeds.
        let in_scope_put = probe(
            Some(scoped.clone()),
            tdh::put_json(format!("/{art_a}/labels"), labels_body()),
        )
        .await;

        for repo in [repo_a, repo_b, repo_c] {
            tdh::cleanup(&pool, repo, user_id).await;
        }
        for dir in [&dir_a, &dir_b, &dir_c] {
            let _ = std::fs::remove_dir_all(dir);
        }

        assert_eq!(
            in_scope.0,
            StatusCode::OK,
            "POSITIVE CONTROL: the token must read the repository it IS scoped to, \
             or every assertion below is vacuous"
        );
        assert_eq!(
            public_anon.0,
            StatusCode::OK,
            "POSITIVE CONTROL / unchanged: an anonymous caller reads an artifact in \
             a public repository"
        );

        // The bug. The by-id read handler's response does not vary with the
        // caller, so status AND body must match the anonymous answer exactly.
        assert_eq!(
            public_scoped, public_anon,
            "#3704: reading an artifact in a PUBLIC repository with a token scoped \
             to another repository must answer exactly what NO credential answers. \
             Before the fix `check_artifact_visibility` ran the #504 scope check \
             before consulting `is_public`, so this was 403 while the anonymous \
             request was 200 -- a credential granting strictly less access than none"
        );
        assert_eq!(
            metadata_scoped, metadata_anon,
            "#3704: the `/metadata` sub-resource shares the gate and must match too"
        );
        assert_eq!(
            stats_scoped, stats_anon,
            "#3704: and so must `/stats` -- a per-handler fix would leave siblings \
             inverted, which is how this class of bug spread across four surfaces"
        );

        // The security half: reads only. `public_read_satisfies_acl` is
        // read-only by construction, and these are NOT vacuous -- the caller
        // holds `write`/`delete` on public repo B, so without the ceiling the
        // mutation succeeds rather than being refused somewhere else.
        assert_eq!(
            in_scope_put.0,
            StatusCode::OK,
            "POSITIVE CONTROL: the identical label PUT succeeds IN scope, so the \
             two refusals below are about the scope ceiling and not about a \
             broken fixture"
        );
        assert_eq!(
            public_put,
            scope_denied(),
            "#3704 must not widen writes: a token scoped to repo A still must not \
             SET labels on an artifact in public repo B. This gate is the only \
             repository ceiling on that path -- `authorize_label_write` checks the \
             token's action scope alone"
        );
        assert_eq!(
            public_delete,
            scope_denied(),
            "#3704 must not widen deletes: DELETE of a label on a public \
             repository outside the token's scope stays refused"
        );
        assert_eq!(
            private_scoped,
            scope_denied(),
            "#3704 must not widen private repositories: a PRIVATE repository \
             outside the token's scope never takes the public bypass. The caller \
             HOLDS a read grant on C, so this is not vacuous -- drop the ceiling \
             and it answers 200"
        );
        assert_eq!(
            private_anon.0,
            StatusCode::NOT_FOUND,
            "unchanged: an anonymous caller still gets the existence-hiding 404 on \
             a private repository's artifact"
        );
    }
}
