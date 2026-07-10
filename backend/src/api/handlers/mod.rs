//! HTTP request handlers.

use axum::http::HeaderMap;

/// Request marker set by peer replication writes. Receiving handlers use this
/// to avoid queuing the replicated write back to the origin peer.
pub(crate) fn is_replication_request(headers: &HeaderMap) -> bool {
    headers
        .get("x-artifact-keeper-replication")
        .and_then(|value| value.to_str().ok())
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

/// Remove any soft-deleted artifact at the given `(repository_id, path)` so
/// that a subsequent INSERT won't violate the UNIQUE constraint.  This is a
/// fire-and-forget cleanup: if the DELETE fails or finds nothing we just
/// continue with the INSERT.
pub async fn cleanup_soft_deleted_artifact(
    db: &sqlx::PgPool,
    repository_id: uuid::Uuid,
    path: &str,
) {
    let _ = sqlx::query(
        "DELETE FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = true",
    )
    .bind(repository_id)
    .bind(path)
    .execute(db)
    .await;
}

/// Remove any soft-deleted artifact at `(repository_id, path)` so a subsequent
/// INSERT won't violate `UNIQUE(repository_id, path)` — UNLESS the coordinate is
/// a *released* one AND the incoming bytes differ from the tombstoned bytes.
///
/// This is the pre-insert chokepoint the format handlers that do their own
/// INSERT (cargo / maven / npm / nuget / conan / composer / conda) share, and it
/// mirrors the release-immutability backstop in
/// [`ArtifactService::upload_with_sync_options`] for the service-backed paths.
///
/// A coordinate is *released* (immutable) when a prior row exists there AND the
/// path is not a format's genuinely in-place-rewritten index file
/// (`maven-metadata.xml`, npm packument, OCI tag, ...). The structural
/// [`cache_classifier`] supplies the index/immutable distinction; for the
/// default-format families (Nuget / Conan / Composer / Generic / ...) every
/// stored path is a release coordinate, so a versioned re-upload is protected
/// too. Re-uploading the IDENTICAL bytes (idempotent republish / undelete) and
/// genuine mutable index files are always allowed — the purge proceeds as
/// before.
pub async fn cleanup_soft_deleted_artifact_checked(
    db: &sqlx::PgPool,
    format: &crate::models::repository::RepositoryFormat,
    repository_id: uuid::Uuid,
    path: &str,
    new_checksum_sha256: &str,
) -> crate::error::Result<()> {
    use crate::error::AppError;
    use crate::services::cache_classifier;

    // Genuine in-place index files (a format's mutable pointers) are always
    // freely re-uploadable; everything else is a candidate release coordinate.
    if !cache_classifier::is_explicitly_mutable_index(format, path) {
        // Inspect the tombstone (if any) BEFORE it is purged.
        let prior = sqlx::query!(
            "SELECT checksum_sha256, version FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = true",
            repository_id,
            path
        )
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(prior) = prior {
            // Released = versioned coordinate or structurally immutable path.
            let is_released =
                prior.version.is_some() || cache_classifier::classify(format, path).is_immutable();
            if is_released
                && !prior
                    .checksum_sha256
                    .eq_ignore_ascii_case(new_checksum_sha256)
            {
                return Err(AppError::Conflict(
                    "Artifact version already exists and is immutable".to_string(),
                ));
            }
        }
    }

    cleanup_soft_deleted_artifact(db, repository_id, path).await;
    Ok(())
}

/// Escape SQL `LIKE` wildcards (`%`, `_`) and the escape character (`\`) in
/// user-supplied input that will be concatenated into a `LIKE` pattern.
///
/// Use together with an `ESCAPE '\'` clause on the SQL side. Without this
/// helper, a user-supplied path component containing `%` or `_` would act
/// as a wildcard rather than a literal, leaking other artifact paths inside
/// the same repository (info disclosure / wrong-artifact serving).
pub fn escape_like_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Escape a user-supplied filename from a URL path segment for safe
/// `LIKE '%/' || $n ESCAPE '\'` suffix matching. Strips a single leading
/// slash (URL extractors often hand us one) and escapes `%`, `_`, `\`.
pub fn escape_filename_for_like(file_path: &str) -> String {
    escape_like_literal(file_path.trim_start_matches('/'))
}

/// Build a 200 OK `application/json` response from a serde JSON value.
/// Centralizes the boilerplate every metadata endpoint otherwise repeats:
/// `Response::builder().status(OK).header(CONTENT_TYPE, "application/json")
/// .body(serde_json::to_string(&json).unwrap()).unwrap()`.
pub fn json_response(value: &serde_json::Value) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(value).unwrap(),
    )
        .into_response()
}

/// Map a database error to an HTTP response.
///
/// Centralizes the boilerplate that every format handler otherwise repeats
/// after `sqlx::query!(...).fetch_*().await.map_err(...)` calls.
///
/// A saturated sqlx pool is a transient capacity event, not a server fault, so
/// it is shed to 503 + `Retry-After` (via `map_db_err`, which also sanitizes
/// the body) so clients back off instead of retrying into the saturation
/// (#2083). Every other DB failure keeps the previous behaviour: a 500
/// plain-text "Database error: {e}" response.
pub fn db_err(e: impl std::fmt::Display) -> axum::response::Response {
    use axum::response::IntoResponse;
    let text = e.to_string();
    if crate::error::is_pool_timeout(&text) {
        return error_helpers::map_db_err(text);
    }
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        format!("Database error: {}", text),
    )
        .into_response()
}

/// Pick the HTTP status for a database error when the response envelope is
/// format-specific (npm/OCI/Git-LFS/etc.) and cannot go through `db_err`.
///
/// A saturated sqlx pool is transient capacity, so it must surface as 503
/// (clients back off); every other DB failure stays 500. Callers keep their
/// own format-specific error body and pass this for the status argument
/// (#2083).
pub fn db_status<E: std::fmt::Display + ?Sized>(e: &E) -> axum::http::StatusCode {
    if crate::error::is_pool_timeout(&e.to_string()) {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    } else {
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// Attach `Retry-After: 1` to a 503 response (capacity shed) so clients back
/// off; no-op for any other status.
///
/// `AppError::into_response` already adds this for `db_err`-routed responses;
/// format-specific error envelopes (npm/OCI/Git-LFS/protobuf-Connect/upload)
/// build responses manually, so they wrap their output with this to stay
/// consistent when `db_status` selects 503 (#2083).
pub fn with_retry_after_on_503(mut resp: axum::response::Response) -> axum::response::Response {
    if resp.status() == axum::http::StatusCode::SERVICE_UNAVAILABLE {
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
    }
    resp
}

/// Build a `/`-joined path prefix from user-supplied components, escaping
/// each component for safe `LIKE $n || '%' ESCAPE '\'` prefix matching.
/// A trailing `/` is appended. Empty input produces an empty string.
pub fn escape_path_prefix(components: &[&str]) -> String {
    let mut out = String::new();
    for c in components {
        out.push_str(&escape_like_literal(c));
        out.push('/');
    }
    out
}

pub mod error_helpers;

#[cfg(test)]
pub(crate) mod test_db_helpers;

pub mod admin;
pub mod admin_security;
pub mod age_gate;
pub mod alpine;
pub mod analytics;
pub mod ansible;
pub mod approval;
pub mod artifact_labels;
pub mod artifacts;
pub mod auth;
pub mod builds;
pub mod cache_headers;
pub mod cargo;
pub mod chef;
pub mod ci_auth;
pub mod ci_auth_admin;
pub mod cocoapods;
pub mod composer;
pub mod conan;
pub mod conda;
pub mod cran;
pub mod curation;
pub mod debian;
pub mod dependency_track;
pub mod email_subscriptions;
pub mod events;
pub mod general;
pub mod gitlfs;
pub mod goproxy;
pub mod groups;
pub mod health;
pub mod helm;
pub mod hex;
pub mod huggingface;
pub mod incus;
pub mod jetbrains;
pub mod lifecycle;
pub mod maven;
pub mod maven_proxy;
pub mod migration;
pub mod monitoring;
pub mod npm;
pub mod nuget;
pub mod oci_v2;
pub mod packages;
pub mod peer;
pub mod peer_instance_labels;
pub mod peers;
pub mod permissions;
pub mod plugins;
pub mod profile;
pub mod promotion;
pub mod promotion_rules;
pub mod protobuf;
pub mod proxy_helpers;
pub mod pub_registry;
pub mod puppet;
pub mod pypi;
pub mod quality_gates;
pub mod quarantine;
pub mod remote_instances;
pub mod repo_tokens;
pub mod repositories;
pub mod repository_labels;
pub mod rpm;
pub mod rubygems;
pub mod sbom;
pub mod sbt;
pub mod search;
pub mod security;
pub mod service_accounts;
pub mod signing;
pub mod smtp;
pub mod sso;
pub mod sso_admin;
pub mod storage_gc;
pub mod swift;
pub mod sync_policies;
pub mod system_config;
pub mod telemetry;
pub mod terraform;
pub mod totp;
pub mod transfer;
pub mod tree;
pub mod upload;
pub mod users;
pub mod vscode;
pub mod wasm_proxy;
pub mod webhooks;

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // escape_like_literal — SQL LIKE wildcard escape for user-supplied input
    // -----------------------------------------------------------------------

    #[test]
    fn test_escape_like_literal_passes_safe_chars_through() {
        assert_eq!(escape_like_literal("foo-1.0.0.tgz"), "foo-1.0.0.tgz");
        assert_eq!(escape_like_literal(""), "");
        assert_eq!(escape_like_literal("@types/mdurl"), "@types/mdurl");
    }

    #[test]
    fn test_escape_like_literal_escapes_percent() {
        // SECURITY: a `%` from user input must not act as a LIKE wildcard.
        assert_eq!(escape_like_literal("%"), r"\%");
        assert_eq!(escape_like_literal("%.gem"), r"\%.gem");
        assert_eq!(escape_like_literal("foo%bar%baz"), r"foo\%bar\%baz");
    }

    #[test]
    fn test_escape_like_literal_escapes_underscore() {
        // SECURITY: a `_` from user input must not act as a LIKE single-char wildcard.
        assert_eq!(escape_like_literal("_"), r"\_");
        assert_eq!(escape_like_literal("foo_bar"), r"foo\_bar");
    }

    #[test]
    fn test_escape_like_literal_escapes_backslash() {
        // SECURITY: a `\` must be escaped so it doesn't itself act as the LIKE
        // escape character (we use `ESCAPE '\'` on the SQL side).
        assert_eq!(escape_like_literal(r"\"), r"\\");
        assert_eq!(escape_like_literal(r"foo\bar"), r"foo\\bar");
    }

    #[test]
    fn test_escape_like_literal_combined_payload() {
        // Adversarial filename mixing all special chars.
        assert_eq!(escape_like_literal(r"%_\evil"), r"\%\_\\evil");
    }

    // -----------------------------------------------------------------------
    // escape_filename_for_like — strip leading slash + escape
    // -----------------------------------------------------------------------

    #[test]
    fn test_escape_filename_strips_leading_slash() {
        assert_eq!(escape_filename_for_like("/foo.tgz"), "foo.tgz");
        assert_eq!(escape_filename_for_like("//foo.tgz"), "foo.tgz");
        assert_eq!(escape_filename_for_like("foo.tgz"), "foo.tgz");
        assert_eq!(escape_filename_for_like(""), "");
    }

    #[test]
    fn test_escape_filename_escapes_wildcards() {
        // SECURITY: a `%` or `_` in a download URL filename must not
        // broaden the LIKE match to other artifacts in the repository.
        assert_eq!(escape_filename_for_like("/%.whl"), r"\%.whl");
        assert_eq!(escape_filename_for_like("foo_bar.gem"), r"foo\_bar.gem");
        assert_eq!(escape_filename_for_like(r"/%_\evil"), r"\%\_\\evil");
    }

    #[test]
    fn test_escape_filename_preserves_internal_slashes() {
        // `/` is not a LIKE special char; internal path separators in
        // a filename are matched literally.
        assert_eq!(
            escape_filename_for_like("/v3/files/foo-1.0.0.tar.gz"),
            "v3/files/foo-1.0.0.tar.gz"
        );
    }

    // -----------------------------------------------------------------------
    // escape_path_prefix — multi-component path prefix
    // -----------------------------------------------------------------------

    #[test]
    fn test_escape_path_prefix_two_components() {
        assert_eq!(
            escape_path_prefix(&["bert-base", "main"]),
            "bert-base/main/"
        );
    }

    #[test]
    fn test_escape_path_prefix_three_components() {
        // SECURITY: alpine paths use `branch/repository/arch/` from URL;
        // `_` in `x86_64` must be escaped so it's matched literally.
        assert_eq!(
            escape_path_prefix(&["v3.18", "main", "x86_64"]),
            r"v3.18/main/x86\_64/"
        );
    }

    #[test]
    fn test_escape_path_prefix_escapes_each_component() {
        // SECURITY: every component is escaped independently before the
        // separator is emitted, so a `/` in user input would be a literal
        // (which is fine; `/` isn't a LIKE wildcard) but `%` and `_`
        // become escaped in place.
        assert_eq!(escape_path_prefix(&["%", "_evil"]), r"\%/\_evil/");
    }

    #[test]
    fn test_escape_path_prefix_empty_inputs() {
        assert_eq!(escape_path_prefix(&[]), "");
        assert_eq!(escape_path_prefix(&[""]), "/");
    }

    // -----------------------------------------------------------------------
    // db_err — sqlx error → 500 plain-text response
    // -----------------------------------------------------------------------

    #[test]
    fn test_db_err_returns_500() {
        let resp = db_err("connection refused");
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_db_err_pool_timeout_returns_503() {
        // A stringified sqlx pool timeout must shed to 503 (transient capacity),
        // not 500, so format-handler clients back off under saturation (#2083).
        let resp = db_err(sqlx::Error::PoolTimedOut.to_string());
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_db_status_sheds_pool_timeout_only() {
        // Format-specific envelopes (npm/OCI/Git-LFS/etc.) keep their body and
        // pass db_status for the status: 503 on pool timeout, 500 otherwise.
        assert_eq!(
            db_status(&sqlx::Error::PoolTimedOut.to_string()),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            db_status("connection refused"),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_with_retry_after_on_503_adds_header_only_for_503() {
        use axum::response::IntoResponse;
        let r503 = with_retry_after_on_503(
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "x").into_response(),
        );
        assert_eq!(
            r503.headers().get(axum::http::header::RETRY_AFTER).unwrap(),
            "1"
        );
        let r500 = with_retry_after_on_503(
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "x").into_response(),
        );
        assert!(r500
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none());
    }

    #[test]
    fn test_db_err_accepts_string() {
        let resp = db_err(String::from("query failed"));
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_db_err_accepts_anyhow_like_error() {
        // Anything that implements Display works.
        let err = std::io::Error::other("io failure");
        let resp = db_err(err);
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_db_err_body_includes_label_and_message() {
        let resp = db_err("disk full");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.starts_with("Database error: "));
        assert!(text.contains("disk full"));
    }

    // -----------------------------------------------------------------------
    // json_response — serde_json::Value → 200 JSON response
    // -----------------------------------------------------------------------

    #[test]
    fn test_json_response_status_ok() {
        let v = serde_json::json!({"hello": "world"});
        let resp = json_response(&v);
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn test_json_response_sets_content_type_application_json() {
        let v = serde_json::json!({"x": 1});
        let resp = json_response(&v);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn test_json_response_body_serializes_value() {
        let v = serde_json::json!({"name": "foo", "version": "1.0.0"});
        let resp = json_response(&v);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["name"], "foo");
        assert_eq!(parsed["version"], "1.0.0");
    }

    #[tokio::test]
    async fn test_json_response_array_value() {
        let v = serde_json::json!([1, 2, 3]);
        let resp = json_response(&v);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed[0], 1);
        assert_eq!(parsed[1], 2);
        assert_eq!(parsed[2], 3);
    }

    #[tokio::test]
    async fn test_json_response_null_value() {
        let v = serde_json::Value::Null;
        let resp = json_response(&v);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "null".as_bytes());
    }

    // -----------------------------------------------------------------------
    // cleanup_soft_deleted_artifact_checked — release-immutability swap guard
    //
    // DB-backed; no-ops cleanly when DATABASE_URL is unset (CI seeds Postgres
    // before `cargo llvm-cov --lib`). Validates that a DELETE + re-upload of
    // DIFFERENT bytes to a structurally-immutable coordinate is rejected with
    // a 409, while identical-bytes republish, mutable paths, and the
    // no-tombstone case all proceed.
    // -----------------------------------------------------------------------

    use crate::models::repository::RepositoryFormat;

    /// Create a hosted repo of the given `format` (a `repository_format` enum
    /// literal such as `'maven'`). Returns its id.
    async fn make_repo(pool: &sqlx::PgPool, format: &str) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        let key = format!("immut-test-{}", id);
        let dir = std::env::temp_dir().join(&key);
        let sql = format!(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'local'::repository_type, '{}'::repository_format)",
            format
        );
        sqlx::query(&sql)
            .bind(id)
            .bind(&key)
            .bind(&key)
            .bind(dir.to_string_lossy().as_ref())
            .execute(pool)
            .await
            .expect("create test repo");
        id
    }

    /// Insert a SOFT-DELETED (tombstoned) artifact row at `(repo, path)` with
    /// the given sha256 — simulating a prior publish that was then DELETEd.
    async fn insert_tombstone(pool: &sqlx::PgPool, repo: uuid::Uuid, path: &str, sha: &str) {
        sqlx::query(
            "INSERT INTO artifacts \
             (repository_id, path, name, version, size_bytes, checksum_sha256, \
              content_type, storage_key, is_deleted) \
             VALUES ($1, $2, $3, '1.0.0', 1, $4, 'application/octet-stream', $5, true)",
        )
        .bind(repo)
        .bind(path)
        .bind(path)
        .bind(sha)
        .bind(format!("sk/{}", sha))
        .execute(pool)
        .await
        .expect("insert tombstone");
    }

    async fn cleanup_repo(pool: &sqlx::PgPool, repo: uuid::Uuid) {
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn checked_cleanup_blocks_immutable_swap_different_bytes() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let repo = make_repo(&pool, "maven").await;
        let path = "com/x/app/1.0.0/app-1.0.0.jar"; // classifier: immutable
        insert_tombstone(
            &pool,
            repo,
            path,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await;

        // Re-upload DIFFERENT bytes -> must be rejected (the exploit, blocked).
        let res = cleanup_soft_deleted_artifact_checked(
            &pool,
            &RepositoryFormat::Maven,
            repo,
            path,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await;
        assert!(
            matches!(res, Err(crate::error::AppError::Conflict(_))),
            "delete + re-upload of different bytes to an immutable Maven coordinate must 409",
        );
        // Tombstone must still be present (purge refused).
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(repo)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 1, "immutable tombstone must not be purged");

        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    async fn checked_cleanup_allows_identical_bytes_republish() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let repo = make_repo(&pool, "maven").await;
        let path = "com/x/app/1.0.0/app-1.0.0.jar";
        insert_tombstone(
            &pool,
            repo,
            path,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await;

        // Re-upload IDENTICAL bytes -> allowed (idempotent republish).
        let res = cleanup_soft_deleted_artifact_checked(
            &pool,
            &RepositoryFormat::Maven,
            repo,
            path,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // same sha, case-insensitive
        )
        .await;
        assert!(res.is_ok(), "identical-bytes republish must be allowed");
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(repo)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            remaining, 0,
            "tombstone purged for identical-bytes republish"
        );

        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    async fn checked_cleanup_allows_mutable_path_swap() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let repo = make_repo(&pool, "maven").await;
        let path = "com/x/app/maven-metadata.xml"; // classifier: mutable
        insert_tombstone(
            &pool,
            repo,
            path,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await;

        // Mutable coordinate: re-upload of different bytes proceeds (purge).
        let res = cleanup_soft_deleted_artifact_checked(
            &pool,
            &RepositoryFormat::Maven,
            repo,
            path,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await;
        assert!(
            res.is_ok(),
            "mutable maven-metadata.xml swap must be allowed"
        );
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(repo)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0, "mutable tombstone purged as before");

        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    async fn checked_cleanup_no_tombstone_proceeds() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let repo = make_repo(&pool, "maven").await;
        let path = "com/x/app/2.0.0/app-2.0.0.jar"; // immutable, but no tombstone

        // First upload (no prior tombstone) -> proceeds unconditionally.
        let res = cleanup_soft_deleted_artifact_checked(
            &pool,
            &RepositoryFormat::Maven,
            repo,
            path,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )
        .await;
        assert!(res.is_ok(), "first upload with no tombstone must proceed");

        cleanup_repo(&pool, repo).await;
    }
}
