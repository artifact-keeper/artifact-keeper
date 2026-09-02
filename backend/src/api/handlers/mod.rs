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
/// Every failure goes through `map_db_err` -> `AppError::Database`, which is
/// the same sanitizer the generic routes use: the client gets the stable
/// `{"code":"DATABASE_ERROR","message":"Database operation failed"}` envelope
/// and the raw sqlx/Postgres text is logged server-side only (#3623). It used
/// to be interpolated into a 500 plain-text "Database error: {e}" body, which
/// handed anonymous callers on public repositories the driver message
/// verbatim (e.g. `invalid byte sequence for encoding "UTF8": 0x00`).
///
/// A saturated sqlx pool is a transient capacity event, not a server fault, so
/// it is still shed to 503 + `Retry-After` so clients back off instead of
/// retrying into the saturation (#2083).
pub fn db_err(e: impl std::fmt::Display) -> axum::response::Response {
    error_helpers::map_db_err(e.to_string())
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
pub mod metadata_epoch;

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
pub mod projects;
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
    // result_large_err threshold anchor (#3551)
    // -----------------------------------------------------------------------

    /// `.clippy.toml` sets `large-error-threshold = 129` so that the axum
    /// `Result<T, Response>` idiom used by every handler in this module does
    /// not trip `clippy::result_large_err`. That number is derived from the
    /// size of one concrete type, and nothing in the lint configuration can
    /// notice when the type outgrows it: the symptom is instead hundreds of
    /// clippy errors across hundreds of unchanged functions, attributed to
    /// whichever pull request happens to reach CI first. That is exactly how
    /// #3551 presented.
    ///
    /// This is the assertion that fires first, by name, with the two numbers
    /// side by side. If it fails, an axum or compiler upgrade has changed the
    /// layout of `Response`: raise `large-error-threshold` to the new size
    /// plus one in the same pull request that takes the upgrade, and record
    /// why in the CHANGELOG. Do not silence it with an `allow`.
    #[test]
    fn response_fits_under_the_result_large_err_threshold() {
        const LARGE_ERROR_THRESHOLD: usize = 129; // must match .clippy.toml
        let actual = std::mem::size_of::<axum::response::Response>();
        assert!(
            actual < LARGE_ERROR_THRESHOLD,
            "size_of::<axum::response::Response>() is {actual} bytes, which is \
             not below the large-error-threshold of {LARGE_ERROR_THRESHOLD} in \
             .clippy.toml. Every `Result<_, Response>` in backend/src/api/handlers \
             is about to fail clippy::result_large_err. See #3551."
        );
    }

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
    async fn test_db_err_body_is_sanitized_envelope() {
        // The body is the same envelope `AppError::Database` emits on the
        // generic routes -- no driver text (#3623).
        let resp = db_err("disk full");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "DATABASE_ERROR");
        assert_eq!(json["message"], "Database operation failed");
        assert!(!String::from_utf8_lossy(&body).contains("disk full"));
    }

    #[tokio::test]
    async fn test_db_err_does_not_leak_raw_postgres_text() {
        // SECURITY (#3623): `db_err` is reached by unauthenticated callers on
        // public repositories (rpm, ansible, hex, debian, ...). A raw driver
        // message -- here the encoding error a NUL byte in a client-supplied
        // string produces -- must never reach the response body.
        let raw =
            r#"error returned from database: invalid byte sequence for encoding "UTF8": 0x00"#;
        let resp = db_err(raw);
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("invalid byte sequence"),
            "db_err leaked the driver message: {text}"
        );
        assert!(
            !text.contains("UTF8"),
            "db_err leaked the encoding name: {text}"
        );
        assert!(
            text.contains("DATABASE_ERROR"),
            "unexpected envelope: {text}"
        );
    }

    #[tokio::test]
    async fn test_db_err_pool_timeout_body_matches_generic_path() {
        // The 503 shed keeps its own user-facing message and Retry-After, and
        // still carries no driver text.
        let resp = db_err(sqlx::Error::PoolTimedOut.to_string());
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER).unwrap(),
            "1"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "POOL_EXHAUSTED");
        assert_eq!(
            json["message"],
            "Database connection pool is saturated, retry shortly"
        );
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
        sqlx::query(sqlx::AssertSqlSafe(&*sql))
            .bind(id)
            .bind(&key)
            .bind(&key)
            .bind(&*dir.to_string_lossy())
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
    async fn checked_cleanup_allows_nonunique_snapshot_redeploy_different_bytes() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let repo = make_repo(&pool, "maven").await;
        // Non-unique SNAPSHOT artifact: redeployed in place per Maven semantics.
        let path = "com/x/app/1.0.0-SNAPSHOT/app-1.0.0-SNAPSHOT.jar";
        insert_tombstone(
            &pool,
            repo,
            path,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await;

        // Redeploy with DIFFERENT bytes -> allowed (SNAPSHOTs are mutable).
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
            "non-unique SNAPSHOT redeploy over a tombstone must be allowed, got {res:?}",
        );
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(repo)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            remaining, 0,
            "SNAPSHOT tombstone purged so redeploy can land"
        );

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

// ---------------------------------------------------------------------------
// #3500: a SQL-assembled `LIKE` pattern must escape its operand.
//
// The class is narrow and mechanically recognisable: a predicate that builds
// its `LIKE` *pattern* inside SQL by concatenating an operand (`LIKE $2 ||
// '%'`, `LIKE '%' || $2 || '%'`, `$2 LIKE a.name || '-%'`, `LIKE concat($2,
// '%')`). At those sites the Rust call site shows a plain bind and nothing
// hints that a pattern is being assembled, which is why four of them survived
// the #998/#1000 escaping wave and the #3492 audit. A constant pattern
// (`LIKE 'maven/%'`) is not in the class — escaping applies to the pattern,
// not to the column being probed.
//
// WHAT ACTUALLY FIXES IT, and why this gate checks a PAIR. `ESCAPE '\'` names
// the character Postgres already uses by default, so on its own that clause
// changes nothing: `'ab/x' LIKE 'a\b/' || '%'` and the same predicate with
// `ESCAPE '\'` are both true, and `_` stays a wildcard either way. What fixes
// the bug is [`escape_like_literal`] on the value that becomes the pattern.
// A gate that demanded only the clause would therefore be green while #3500
// was fully live. So a site must satisfy BOTH:
//
//   1. an `ESCAPE` clause on the predicate, and
//   2. either `ESCAPE ''` — for an operand derived in SQL, which the Rust
//      helper cannot reach (see `maven_flat_attribution::
//      metadata_rollup_dir_anchor_sql`, #3492/#3493) — or an
//      `escape_like_literal` in the same function, for an operand that is a
//      bind parameter.
//
// WHAT THIS CANNOT PROVE. Requirement 2 is function-scoped: it shows an
// escaper is applied somewhere in the function that owns the predicate, NOT
// that it is applied to *this* operand. A function that escapes one value and
// binds another raw still passes. Only the per-site behavioural tests
// (`tree.rs`, `rubygems.rs`, `repositories.rs`, `cargo.rs`,
// `artifact_service.rs`) prove the operand half, and they are what caught the
// bug. This gate's job is narrower: stop a NEW site in this shape from being
// added with no escaping story at all.
//
// THE SECOND SHAPE (#3557): the pattern is assembled in RUST -- `format!(
// "%{}%", q)` for a free-text search box, `format!("{}%", p)` for a prefix --
// and bound whole to a bare `path LIKE $2`. The SQL scanner above cannot see
// those: by the time the string reaches SQL it is a single bind, with no
// concatenation to key on. So they get their own scanner, keyed on the RUST
// literal instead, in `every_rust_assembled_like_pattern_escapes_its_operand`.
// Its shape recogniser is deliberately narrow -- a `format!` whose entire
// literal is `%{...}%` or `{...}%` -- which is exactly the cohort #3557
// audited and matches nothing else in the tree (a `format!("%{b:02X}")`
// percent-encoder ends at `}`, not `%`).
//
// STILL OUT OF SCOPE: `LIKE ANY($n)` over a Rust-built array, where the site
// deliberately over-fetches and re-checks the match exactly in Rust. Those
// carry [`OVERMATCH_MARKER`], and the marker is only honoured on a function
// that really does use `LIKE ANY`, so it cannot become a blanket opt-out.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod like_pattern_escape_class_tests {
    /// A `LIKE`-family operator, in every spelling that reaches the same
    /// pattern-matching semantics. `~~` is `LIKE`'s operator form and is what
    /// `LIKE ... ESCAPE` is rewritten to before planning, so a site written
    /// that way is the same defect.
    /// One entry per predicate, not per spelling: a `NOT LIKE` is matched by
    /// `LIKE ` and every `~~` spelling (`~~*`, `!~~`, `!~~*`) by `~~`, so a
    /// single predicate is never counted twice. `LIKE ` matched inside
    /// `ILIKE ` is rejected by the preceding-character guard in [`scan`].
    const OPERATORS: &[&str] = &["ILIKE ", "LIKE ", "SIMILAR TO ", "~~"];

    /// How far past the operator the pattern expression and its `ESCAPE`
    /// clause may run. Generous enough to span a wrapped predicate, short
    /// enough that an `ESCAPE` belonging to a LATER, unrelated predicate
    /// cannot vouch for this one.
    const OPERAND_WINDOW: usize = 160;

    /// The sanctioned escapers. `escape_filename_for_like` and
    /// `escape_path_prefix` are thin wrappers that route through
    /// [`escape_like_literal`]; `the_escaper_family_all_routes_through_the_helper`
    /// pins that, so accepting them here cannot become a way in for a helper
    /// that does not actually escape.
    const ESCAPERS: &[&str] = &[
        "escape_like_literal(",
        "escape_filename_for_like(",
        "escape_path_prefix(",
    ];

    /// Marker for a site whose operand is escaped by a DIFFERENT function —
    /// a SQL fragment builder whose callers do the binding. It must name the
    /// binding functions, each of which is then checked for the escaper, so
    /// the exception is verified rather than merely asserted.
    const CALLER_ESCAPES_MARKER: &str = "LIKE-OPERAND-ESCAPED-BY-CALLER:";

    /// One flagged site.
    struct Offender {
        location: String,
        line: String,
        reason: &'static str,
    }

    /// Collapse every run of ASCII whitespace to one space, keeping a map from
    /// each output byte to its source line number.
    ///
    /// Wrapping is the realistic way this class re-appears: the offending
    /// lines are 80+ characters, so the next author to let rustfmt or a hand
    /// edit split `LIKE $2` from `|| '%'` would have silently disabled a
    /// line-based scanner.
    fn flatten(src: &str) -> (String, Vec<usize>) {
        let mut out = String::with_capacity(src.len());
        let mut lines = Vec::with_capacity(src.len());
        let mut line = 1usize;
        let mut in_ws = false;
        for ch in src.chars() {
            if ch == '\n' {
                line += 1;
            }
            if ch.is_ascii_whitespace() {
                if !in_ws {
                    out.push(' ');
                    lines.push(line);
                    in_ws = true;
                }
                continue;
            }
            in_ws = false;
            let mut buf = [0u8; 4];
            for _ in ch.encode_utf8(&mut buf).bytes() {
                lines.push(line);
            }
            out.push(ch);
        }
        (out, lines)
    }

    /// Whether `window` carries a real `ESCAPE` clause, i.e. `ESCAPE` followed
    /// by a quoted character. The quote requirement is what stops a trailing
    /// SQL comment (`-- TODO ESCAPE later`) from satisfying the check.
    fn escape_clause(window: &str) -> Option<&str> {
        let at = window.find("ESCAPE ")?;
        let rest = window[at + "ESCAPE ".len()..].trim_start();
        if !rest.starts_with('\'') {
            return None;
        }
        let end = rest[1..].find('\'')? + 2;
        Some(&rest[..end])
    }

    /// The source of the `fn` item containing byte offset `at`.
    ///
    /// Split on `fn` header lines rather than on column-0 braces so methods
    /// inside an `impl` are scoped to themselves. `cargo fmt --check` is
    /// enforced in CI, so a header line is reliably `…fn name(`.
    fn enclosing_fn(src: &str, at: usize) -> &str {
        let is_fn_header = |line: &str| {
            let t = line.trim_start();
            t.starts_with("fn ")
                || t.starts_with("async fn ")
                || t.starts_with("pub fn ")
                || t.starts_with("pub async fn ")
                || (t.starts_with("pub(") && t.contains(") fn "))
                || (t.starts_with("pub(") && t.contains(") async fn "))
        };
        let mut start = 0usize;
        let mut end = src.len();
        let mut header_index = 0usize;
        let mut lines: Vec<(usize, &str)> = Vec::new();
        for (index, (offset, line)) in line_offsets(src).enumerate() {
            lines.push((offset, line));
            if !is_fn_header(line) {
                continue;
            }
            if offset <= at {
                start = offset;
                header_index = index;
            } else if end == src.len() {
                end = offset;
            }
        }
        // Include the item's own doc comment and attributes: a
        // `LIKE-OPERAND-ESCAPED-BY-CALLER` marker belongs in the doc, and an
        // explanatory `///` above the `fn` line is part of the item.
        let mut from = header_index;
        while from > 0 {
            let candidate = lines[from - 1].1.trim_start();
            if candidate.starts_with("///")
                || candidate.starts_with("//")
                || candidate.starts_with("#[")
            {
                from -= 1;
                start = lines[from].0;
            } else {
                break;
            }
        }
        &src[start..end]
    }

    /// `(byte offset, line)` for every line of `src`.
    fn line_offsets(src: &str) -> impl Iterator<Item = (usize, &str)> {
        let mut offset = 0usize;
        src.split_inclusive('\n').map(move |line| {
            let at = offset;
            offset += line.len();
            (at, line.trim_end_matches('\n'))
        })
    }

    /// Every `.rs` file under `backend/src`, scanned for the class. Read at
    /// test time rather than from a hardcoded list so a NEW file carrying a
    /// new site is covered too.
    fn rust_sources() -> Vec<(std::path::PathBuf, String)> {
        let mut out = Vec::new();
        let mut stack = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(current) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    if let Ok(src) = std::fs::read_to_string(&path) {
                        out.push((path, src));
                    }
                }
            }
        }
        assert!(!out.is_empty(), "#3500: the source scan found no files");
        out
    }

    /// Scan the tree and return `(offenders, sites_examined)`.
    fn scan() -> (Vec<Offender>, usize) {
        let mut offenders = Vec::new();
        let mut examined = 0usize;

        for (path, raw) in rust_sources() {
            // This module's own prose describes the shape it hunts for.
            if path.ends_with("api/handlers/mod.rs") {
                continue;
            }
            let (flat, lines) = flatten(&raw);
            for operator in OPERATORS {
                for (at, _) in flat.match_indices(operator) {
                    let from = at + operator.len();
                    let to = (from + OPERAND_WINDOW).min(flat.len());
                    let (from, to) = (floor_boundary(&flat, from), floor_boundary(&flat, to));
                    let window = predicate_window(&flat[from..to]);

                    // `LIKE ` inside `ILIKE ` is the same predicate, already
                    // matched by the `ILIKE ` entry.
                    if *operator == "LIKE "
                        && flat[..at].ends_with(|c: char| c.is_ascii_alphanumeric())
                    {
                        continue;
                    }
                    // Only a pattern ASSEMBLED in SQL is in this class. The
                    // pattern EXPRESSION ends at the next boolean operand or
                    // the end of the SQL literal; without that bound a
                    // constant pattern inherits the `||` of an unrelated
                    // predicate further down the same statement.
                    if !assembles_pattern(window) {
                        continue;
                    }
                    // A Rust string mentioning the operator inside a comment
                    // is not a predicate.
                    let line_no = lines.get(at).copied().unwrap_or(0);
                    let line = raw.lines().nth(line_no.saturating_sub(1)).unwrap_or("");
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    examined += 1;

                    let location = format!("{}:{}", path.display(), line_no);
                    let Some(clause) = escape_clause(window) else {
                        offenders.push(Offender {
                            location,
                            line: line.trim().to_string(),
                            reason: "no ESCAPE clause on a SQL-assembled pattern",
                        });
                        continue;
                    };
                    // `ESCAPE ''` disables escape processing: the operand is
                    // derived in SQL and the Rust helper cannot reach it.
                    if clause == "''" {
                        continue;
                    }
                    // Otherwise the operand is a bind, and the clause alone is
                    // a no-op (it names Postgres's default). Require the
                    // escaper in the same function, or a verified marker.
                    let owner = enclosing_fn(&raw, byte_of_line(&raw, line_no));
                    if escapes_operand(&raw, owner) {
                        continue;
                    }
                    if let Some(binders) = marker_binders(owner) {
                        if binders.iter().all(|name| binder_escapes(&raw, name)) {
                            continue;
                        }
                        offenders.push(Offender {
                            location,
                            line: line.trim().to_string(),
                            reason: "the marker names a binder that does not escape its operand",
                        });
                        continue;
                    }
                    offenders.push(Offender {
                        location,
                        line: line.trim().to_string(),
                        reason: "ESCAPE '\\' names Postgres's DEFAULT escape character, so it \
                                 changes nothing on its own; the bound operand must go through \
                                 one of the escape_like_literal helpers",
                    });
                }
            }
        }
        (offenders, examined)
    }

    /// Trim a raw look-ahead window to the single PREDICATE that starts at the
    /// operator: everything up to the next boolean operand or the end of the
    /// enclosing SQL string literal.
    ///
    /// Without this the `ESCAPE` check is not scoped to the operator it
    /// matched, and an `ESCAPE` belonging to a LATER predicate — even one in a
    /// different function further down the flattened file — vouches for this
    /// one. Caught in review on `… LIKE $2 || '%' ESCAPE '' AND … LIKE $3 ||
    /// '%'`, where the unescaped second predicate borrowed the first's clause.
    fn predicate_window(window: &str) -> &str {
        let mut end = window.len();
        for stop in ["\"", ";", " AND ", " OR "] {
            if let Some(at) = window.find(stop) {
                end = end.min(at);
            }
        }
        &window[..floor_boundary(window, end)]
    }

    /// Whether the pattern expression starting at `window` is ASSEMBLED in
    /// SQL rather than being a single constant, bind or column.
    ///
    /// Decided by reading the FIRST term of the pattern expression and asking
    /// whether the very next token concatenates onto it. Searching the window
    /// for a `||` anywhere instead would inherit the concatenation of an
    /// unrelated later branch of the same statement — `NOT LIKE
    /// 'oci-manifests/%'` followed twelve tokens later by a `UNION ALL SELECT
    /// 'oci-blobs/' || digest` is a constant pattern, not a member of this
    /// class.
    fn assembles_pattern(window: &str) -> bool {
        let expr = window.trim_start();
        if expr.starts_with("concat(") {
            return true;
        }
        match skip_term(expr) {
            Some(rest) => rest.trim_start().starts_with("||"),
            None => false,
        }
    }

    /// Consume one SQL term — a quoted literal, a `$n` placeholder, a `{…}`
    /// interpolation, or an identifier with an optional call/argument list —
    /// and return what follows it.
    fn skip_term(expr: &str) -> Option<&str> {
        let bytes = expr.as_bytes();
        let first = *bytes.first()?;
        let mut i = 0usize;
        match first {
            b'\'' => {
                i = 1;
                loop {
                    let close = expr[i..].find('\'')? + i;
                    // `''` is an escaped quote inside a SQL literal.
                    if bytes.get(close + 1) == Some(&b'\'') {
                        i = close + 2;
                        continue;
                    }
                    i = close + 1;
                    break;
                }
            }
            b'$' => {
                i = 1;
                while bytes.get(i).is_some_and(u8::is_ascii_alphanumeric) {
                    i += 1;
                }
            }
            b'{' => {
                i = expr.find('}')? + 1;
            }
            _ => {
                while bytes
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'.')
                {
                    i += 1;
                }
                if i == 0 {
                    return None;
                }
                // A call: consume the balanced argument list.
                if bytes.get(i) == Some(&b'(') {
                    let mut depth = 0usize;
                    for (offset, ch) in expr[i..].char_indices() {
                        match ch {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    i += offset + 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        expr.get(i..)
    }

    /// Byte offset of the first character of 1-based `line_no`.
    fn byte_of_line(src: &str, line_no: usize) -> usize {
        line_offsets(src)
            .nth(line_no.saturating_sub(1))
            .map(|(at, _)| at)
            .unwrap_or(0)
    }

    /// Largest index `<= at` that is a UTF-8 char boundary (the sources carry
    /// em dashes, and slicing mid-codepoint would panic).
    fn floor_boundary(src: &str, at: usize) -> usize {
        let mut at = at.min(src.len());
        while at > 0 && !src.is_char_boundary(at) {
            at -= 1;
        }
        at
    }

    /// The binder function names a [`CALLER_ESCAPES_MARKER`] comment lists.
    fn marker_binders(owner: &str) -> Option<Vec<String>> {
        let at = owner.find(CALLER_ESCAPES_MARKER)?;
        let rest = &owner[at + CALLER_ESCAPES_MARKER.len()..];
        let list = rest.lines().next()?;
        let names: Vec<String> = list
            .split(',')
            .map(|n| n.trim().trim_end_matches('.').to_string())
            .filter(|n| !n.is_empty())
            .collect();
        (!names.is_empty()).then_some(names)
    }

    /// Whether `owner` escapes the value it binds — directly, or through a
    /// helper in the same file that it calls.
    ///
    /// One level of call-following, because the escape step is routinely
    /// factored out next to the query that needs it
    /// (`proxy_helpers::reverse_suffix_for_like`, whose whole reason to exist
    /// is that the reverse must happen BEFORE the escape). Following further
    /// would start vouching for arbitrarily distant code.
    fn escapes_operand(src: &str, owner: &str) -> bool {
        if ESCAPERS.iter().any(|e| owner.contains(e)) {
            return true;
        }
        called_helpers(src, owner)
            .iter()
            .any(|body| ESCAPERS.iter().any(|e| body.contains(e)))
    }

    /// Bodies of the same-file functions `owner` calls by name.
    fn called_helpers<'a>(src: &'a str, owner: &str) -> Vec<&'a str> {
        let mut out = Vec::new();
        for (at, line) in line_offsets(src) {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed
                .split_once("fn ")
                .filter(|(head, _)| head.is_empty() || head.ends_with(' '))
                .map(|(_, rest)| rest)
            else {
                continue;
            };
            let Some((name, _)) = rest.split_once('(') else {
                continue;
            };
            if name.is_empty() || !owner.contains(&format!("{name}(")) {
                continue;
            }
            out.push(enclosing_fn(src, at));
        }
        out
    }

    /// Whether the named function in `src` escapes its operand.
    fn binder_escapes(src: &str, name: &str) -> bool {
        let Some(at) = src.find(&format!("fn {name}(")) else {
            return false;
        };
        let owner = enclosing_fn(src, at);
        escapes_operand(src, owner)
    }

    /// The whole class, in one assertion. A new site that assembles its
    /// pattern in SQL without an escaping story fails here with its own file
    /// and line.
    #[test]
    fn every_sql_assembled_like_pattern_escapes_its_operand() {
        let (offenders, examined) = scan();
        assert!(
            examined >= 10,
            "#3500: the scan examined only {examined} SQL-assembled pattern sites (13 at \
             the time of writing); it has stopped recognising the shape and would pass \
             vacuously"
        );
        assert!(
            offenders.is_empty(),
            "#3500: a `LIKE` pattern assembled in SQL must escape its operand. Use \
             `escape_like_literal` on the bound value and match under `ESCAPE '\\'` \
             when the operand is a Rust value; use `ESCAPE ''` when it is a SQL \
             expression the helper cannot reach. Offenders:\n{}",
            offenders
                .iter()
                .map(|o| format!("  {}: {}\n      -> {}", o.location, o.line, o.reason))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The scanner's own recognisers, pinned against the evasions found in
    /// review: an `ESCAPE '\'` clause with a raw operand (#3500 fully live and
    /// the gate green), a predicate wrapped across lines, the `~~` operator
    /// form, `concat()`, a trailing SQL comment containing the word ESCAPE,
    /// and two predicates on one line where only the first is escaped.
    #[test]
    fn the_scanner_recognises_the_shapes_it_claims_to() {
        // The pattern-assembly recogniser.
        for probe in [
            "path LIKE $2 || '%'",
            "path LIKE $2\n    || '%'",
            "path LIKE\n    $2 || '%'",
            "name ILIKE '%' || $2 || '%'",
            "path ~~ $2 || '%'",
            "path LIKE concat($2, '%')",
            "path SIMILAR TO $2 || '%'",
        ] {
            assert!(
                assembled_sites(probe) >= 1,
                "the scanner must see a SQL-assembled pattern in {probe:?}"
            );
        }
        // Two predicates on one line: BOTH must be examined.
        assert_eq!(
            assembled_sites("a.path LIKE $2 || '%' AND b.path LIKE $3 || '%'"),
            2,
            "a second predicate on the same line must not be skipped"
        );
        // A constant pattern is not in the class.
        for probe in ["path LIKE 'maven/%'", "path LIKE ANY($2)"] {
            assert_eq!(
                assembled_sites(probe),
                0,
                "{probe:?} assembles no pattern in SQL and is out of this class"
            );
        }
        // The ESCAPE recogniser.
        assert!(escape_clause(" $2 || '%' ESCAPE '\\' AND x").is_some());
        assert!(escape_clause(" $2 || '%' ESCAPE '' AND x").is_some());
        assert_eq!(escape_clause(" $2 || '%' ESCAPE '' AND x"), Some("''"));
        assert!(
            escape_clause(" $2 || '%' -- TODO ESCAPE later").is_none(),
            "the word ESCAPE in a trailing SQL comment is not an ESCAPE clause"
        );
        // The clause must belong to THIS operator, not a later predicate.
        assert!(
            escape_clause(predicate_window(
                " $3 || '%'\" ); fn other() { LIKE $2 ESCAPE '\\'"
            ))
            .is_none(),
            "an ESCAPE clause further down the flattened file must not vouch for an \
             unescaped predicate"
        );
        assert!(
            escape_clause(predicate_window(" $2 || '%' ESCAPE '' AND b.path LIKE $3")).is_some(),
            "the predicate's own clause must still be found"
        );
    }

    /// Count the SQL-assembled sites the scanner finds in a snippet, using the
    /// same recogniser [`scan`] uses.
    fn assembled_sites(probe: &str) -> usize {
        let (flat, _) = flatten(probe);
        let mut n = 0;
        for operator in OPERATORS {
            for (at, _) in flat.match_indices(operator) {
                if *operator == "LIKE " && flat[..at].ends_with(|c: char| c.is_ascii_alphanumeric())
                {
                    continue;
                }
                let from = at + operator.len();
                let to = (from + OPERAND_WINDOW).min(flat.len());
                let window = &flat[floor_boundary(&flat, from)..floor_boundary(&flat, to)];
                if assembles_pattern(window) {
                    n += 1;
                }
            }
        }
        n
    }

    /// The wrappers [`ESCAPERS`] accepts must really escape. Without this,
    /// adding a name to that list would be a way to silence the gate.
    #[test]
    fn the_escaper_family_all_routes_through_the_helper() {
        let src = include_str!("mod.rs");
        for wrapper in ["escape_filename_for_like", "escape_path_prefix"] {
            let at = src
                .find(&format!("pub fn {wrapper}("))
                .unwrap_or_else(|| panic!("{wrapper} is defined here"));
            assert!(
                enclosing_fn(src, at).contains("escape_like_literal("),
                "#3500: `{wrapper}` is accepted as an escaper by the class gate, so it \
                 must route through `escape_like_literal`"
            );
        }
    }

    // -----------------------------------------------------------------------
    // #3557: the same class, assembled in RUST instead of in SQL.
    // -----------------------------------------------------------------------

    /// Marker for a Rust-assembled pattern that is deliberately left
    /// unescaped: a `LIKE ANY($n)` fan-out that may over-fetch because its
    /// caller re-checks every returned row exactly in Rust
    /// (`ArtifactService::list_by_path_prefixes`,
    /// `proxy_catalog::paths_under_prefixes`). Honoured only on a function
    /// that really does use `LIKE ANY`, so it cannot be pasted onto an
    /// ordinary search site to silence the gate.
    const OVERMATCH_MARKER: &str = "LIKE-PATTERN-OVERMATCHES-RECHECKED-IN-RUST";

    /// Whether a `format!` literal IS a `LIKE` pattern: the whole literal is
    /// one interpolation with a `%` on the end (`"{…}%"`, a prefix match) or
    /// on both ends (`"%{…}%"`, a substring match).
    ///
    /// The recogniser insists on the WHOLE literal rather than a `%` anywhere
    /// in one, because the tree is full of strings that carry a `%` for
    /// unrelated reasons — the percent-encoders in `saml_service`,
    /// `sync_worker` and `popularity_source` all write `format!("%{b:02X}")`,
    /// which ends at the `}` and is not a pattern.
    fn rust_like_pattern_literal(literal: &str) -> bool {
        let Some(body) = literal.strip_suffix('%') else {
            return false;
        };
        let body = body.strip_prefix('%').unwrap_or(body);
        body.len() >= 2
            && body.starts_with('{')
            && body.ends_with('}')
            && !body[1..body.len() - 1].contains(['{', '}'])
    }

    /// Byte offset of every `format!("…")` in `src` whose literal is a
    /// Rust-assembled `LIKE` pattern. The literals in this class hold a single
    /// interpolation and no escapes, so the closing quote is the next one.
    fn rust_assembled_pattern_sites(src: &str) -> Vec<usize> {
        let mut out = Vec::new();
        for (at, _) in src.match_indices("format!(") {
            let rest = &src[at + "format!(".len()..];
            // rustfmt wraps a long `format!` after the paren, so the literal
            // is not reliably on the same line as the macro.
            let Some(quoted) = rest.trim_start().strip_prefix('"') else {
                continue;
            };
            let Some(end) = quoted.find('"') else {
                continue;
            };
            if rust_like_pattern_literal(&quoted[..end]) {
                out.push(at);
            }
        }
        out
    }

    /// Byte ranges covered by `#[cfg(test)] mod … { … }` blocks.
    ///
    /// Test fixtures build `LIKE` patterns out of literals they chose
    /// themselves (`target_has_artifact(pool, repo, "pr1940/x")` in
    /// `approval.rs` and `promotion.rs`), so they are not part of the class
    /// and flagging them would only teach the next author to silence the
    /// gate. A `#[cfg(test)] use …` — a test-only import, of which
    /// `terraform.rs` has two ABOVE its production code — introduces no
    /// region, so the check is on the attributed ITEM, not the attribute.
    fn test_module_ranges(src: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for (at, _) in src.match_indices("#[cfg(test)]") {
            let mut cursor = at;
            let item = loop {
                let Some(newline) = src[cursor..].find('\n') else {
                    break None;
                };
                cursor += newline + 1;
                let line = src[cursor..].lines().next().unwrap_or("").trim_start();
                if line.starts_with("//") || line.starts_with("#[") {
                    continue;
                }
                break Some(line);
            };
            let Some(item) = item else { continue };
            if !(item.starts_with("mod ") || item.contains(" mod ")) {
                continue;
            }
            let Some(open) = src[cursor..].find('{') else {
                continue;
            };
            let open = cursor + open;
            let mut depth = 0usize;
            for (offset, ch) in src[open..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            out.push((at, open + offset));
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        out
    }

    /// Scan the tree for Rust-assembled patterns; `(offenders, examined)`.
    fn scan_rust_assembled() -> (Vec<Offender>, usize) {
        let mut offenders = Vec::new();
        let mut examined = 0usize;

        for (path, raw) in rust_sources() {
            // This module's own prose describes the shape it hunts for.
            if path.ends_with("api/handlers/mod.rs") {
                continue;
            }
            let tests = test_module_ranges(&raw);
            for at in rust_assembled_pattern_sites(&raw) {
                if tests.iter().any(|(from, to)| at >= *from && at <= *to) {
                    continue;
                }
                examined += 1;
                let owner = enclosing_fn(&raw, at);
                if escapes_operand(&raw, owner) {
                    continue;
                }
                let line_no = raw[..at].matches('\n').count() + 1;
                let line = raw
                    .lines()
                    .nth(line_no - 1)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let location = format!("{}:{}", path.display(), line_no);
                if owner.contains(OVERMATCH_MARKER) {
                    if owner.contains("LIKE ANY(") {
                        continue;
                    }
                    offenders.push(Offender {
                        location,
                        line,
                        reason: "the over-match marker is honoured only on a `LIKE ANY` \
                                 fan-out whose rows are re-checked in Rust",
                    });
                    continue;
                }
                offenders.push(Offender {
                    location,
                    line,
                    reason: "a pattern built in Rust binds whole, so the SQL text shows \
                             nothing to key on; the interpolated value must go through \
                             one of the escape_like_literal helpers BEFORE the `%` is \
                             appended",
                });
            }
        }
        (offenders, examined)
    }

    /// The Rust-assembled half of the class (#3557), in one assertion.
    ///
    /// Same function-scoped limitation as the SQL gate above: this shows an
    /// escaper is applied somewhere in the function that owns the `format!`,
    /// not that it is applied to THIS value. The per-endpoint behavioural
    /// tests (`repositories.rs`, `users.rs`) prove the operand half.
    #[test]
    fn every_rust_assembled_like_pattern_escapes_its_operand() {
        let (offenders, examined) = scan_rust_assembled();
        assert!(
            examined >= 20,
            "#3557: the scan examined only {examined} Rust-assembled pattern sites (29 at \
             the time of writing); it has stopped recognising the shape and would pass \
             vacuously"
        );
        assert!(
            offenders.is_empty(),
            "#3557: a `LIKE` pattern assembled in Rust must escape the value it \
             interpolates. Wrap it in `escape_like_literal` before appending the `%`, \
             and match it under `ESCAPE '\\'`. Offenders:\n{}",
            offenders
                .iter()
                .map(|o| format!("  {}: {}\n      -> {}", o.location, o.line, o.reason))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The Rust scanner's own recognisers, pinned against the shapes that
    /// made the #3557 audit a per-site read rather than a sweep.
    #[test]
    fn the_rust_pattern_scanner_recognises_the_shapes_it_claims_to() {
        for probe in ["%{}%", "{}%", "%{q}%", "{prefix}%"] {
            assert!(
                rust_like_pattern_literal(probe),
                "{probe:?} is a Rust-assembled LIKE pattern"
            );
        }
        // A `%` that is not a wildcard: percent-encoders, path joins, and a
        // literal that interpolates twice.
        for probe in ["%{b:02X}", "%{:02x}{}", "{}", "%%", "{}/%/", "{}/{}%"] {
            assert!(
                !rust_like_pattern_literal(probe),
                "{probe:?} is not a LIKE pattern"
            );
        }
        // Wrapped by rustfmt: the literal need not share the macro's line.
        assert_eq!(
            rust_assembled_pattern_sites("let p = format!(\n    \"%{}%\",\n    q,\n);").len(),
            1,
            "a `format!` wrapped after the paren must still be seen"
        );
        // `#[cfg(test)] use` starts no region; `#[cfg(test)] mod` does.
        let src =
            "#[cfg(test)]\nuse bytes::Bytes;\nfn f() {}\n#[cfg(test)]\nmod t {\n    fn g() {}\n}\n";
        let ranges = test_module_ranges(src);
        assert_eq!(ranges.len(), 1, "only the `mod` item introduces a region");
        assert!(
            ranges[0].0 > src.find("fn f()").unwrap(),
            "the region must start at the test module, not at the test-only import"
        );
    }
}
