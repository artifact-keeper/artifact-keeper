//! Maven-specific helpers for the virtual-repo proxy / fallback path.
//!
//! Sits between the Maven protocol handlers (`handlers/maven.rs`) and the
//! generic virtual-repo plumbing (`handlers/proxy_helpers.rs`). The shared
//! `proxy_helpers` module only owns format-agnostic primitives
//! (`local_fetch_by_path`, `check_quarantine_row`, the row type); anything
//! Maven-specific lives here.
//!
//! Currently exposes:
//!
//! - [`maven_local_fetch_storage_fallback`] — bridges the gap between
//!   Maven's GAV-grouped storage layout (where `.pom`, `.module`,
//!   `-sources.jar`, `.sha512`, etc. share the primary `.jar`'s DB row)
//!   and the SQL-only virtual download path that would otherwise 404 on
//!   those secondary files. Enforces three gates internally so the
//!   fallback can't bypass quarantine / soft-delete policy.
//!
//! As other formats hit the same primary+companion shape — Debian
//! (`.deb`, `.changes`, `.dsc`), RPM (`.rpm`, `.src.rpm`), NuGet
//! (`.nupkg`, `.snupkg`), Helm (`.tgz`, `.tgz.prov`) — they should
//! follow this same `handlers/<format>_proxy.rs` pattern rather than
//! piling format-specific logic into `proxy_helpers.rs`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::{check_quarantine_row, internal_error, LocalArtifactRow};
use crate::api::AppState;
use crate::storage::StorageLocation;

/// Extensions for Maven GAV-grouped *secondary* files that share the
/// primary's DB row. Returning bytes for any of these via the storage
/// fallback is safe as long as the primary GAV is live and not under
/// quarantine.
///
/// Primary file extensions (`.jar`, `.aar`, `.war`, `.ear`, `.zip`) are
/// **deliberately excluded** from this list. Primary files always have
/// their own row in `artifacts` (and therefore go through the
/// SQL-backed `proxy_helpers::local_fetch_by_path`); allowing the
/// storage fallback to serve a primary would silently bypass the
/// quarantine and soft-delete gating on the primary's own row. The
/// allowlist scopes the fallback to its documented purpose.
const MAVEN_SECONDARY_FILE_EXTENSIONS: &[&str] = &[
    ".pom",
    ".module",
    "-sources.jar",
    "-javadoc.jar",
    "-tests.jar",
    "-test-sources.jar",
    ".sha1",
    ".sha256",
    ".sha512",
    ".md5",
    ".asc",
];

#[inline]
fn is_maven_secondary_path(path: &str) -> bool {
    MAVEN_SECONDARY_FILE_EXTENSIONS
        .iter()
        .any(|ext| path.ends_with(ext))
}

/// Derive the GAV directory prefix for a maven artifact path.
///
/// Maven's storage layout is `<group>/<artifact>/<version>/<file>`,
/// so the GAV directory is everything up to the last `/`. The primary
/// `.jar` (and any sibling secondaries) live in that directory.
fn maven_gav_directory(artifact_path: &str) -> Option<&str> {
    artifact_path.rsplit_once('/').map(|(dir, _)| dir)
}

/// Maven-specific storage-direct fallback for virtual-repo downloads.
///
/// The Maven download handler (`handlers/maven.rs`) groups artifacts by
/// GAV coordinate — only the primary file (typically the `.jar`/`.aar`)
/// gets a row in `artifacts`, while the secondary files (`.pom`,
/// `.module`, `-sources.jar`, `.sha512`, …) live on storage at the same
/// path but **don't** have their own DB row. When such a request hits a
/// **local** repo, the maven handler already has a storage-direct
/// fallback (`maven.rs`: "For hosted repos, fall back to serving from
/// storage directly"). When the same request hits a **virtual** repo,
/// the resolution goes through `resolve_virtual_download` →
/// `local_fetch_by_path`, which is SQL-only — the secondary file
/// returns `NotFound` and the virtual response is a 404 even though
/// the bytes are sitting in S3 in the member local repo.
///
/// ## Quarantine + soft-delete contract
///
/// Naively reading `maven/<path>` directly from storage would bypass
/// the quarantine and soft-delete gating that `local_fetch_by_path`
/// enforces on the SQL row. To preserve those policies for secondary
/// files (which have no row of their own), this helper:
///
/// 1. Refuses any path that doesn't match one of the documented
///    secondary-file extensions ([`MAVEN_SECONDARY_FILE_EXTENSIONS`]).
///    Primary `.jar`/`.aar`/`.war`/`.ear` paths fall back to
///    `NotFound` here so the caller can't accidentally route them
///    around their own SQL row.
/// 2. Looks up a "primary" sibling row in the same GAV directory and
///    verifies it is not soft-deleted and not quarantined before
///    serving the secondary bytes. A quarantined or deleted primary
///    means the whole GAV is gated; the secondary travels with it.
/// 3. Only then reads `maven/<path>` from storage.
///
/// ## Composition
///
/// Same return shape as `proxy_helpers::local_fetch_by_path` so callers
/// can chain `Result` fallthrough. Designed to be invoked as a
/// sequential fallback inside a `resolve_virtual_download` callback,
/// not as the callback itself.
///
/// Content-Type is returned as `None`; the caller infers from the
/// path extension via `content_type_for_path` on the outer request
/// path.
pub(crate) async fn maven_local_fetch_storage_fallback(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    artifact_path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    // Gate 1: Only known secondary-file extensions are eligible. A
    // primary `.jar`/`.aar`/etc. always has its own row and must travel
    // the SQL path so its quarantine/soft-delete state is honored.
    if !is_maven_secondary_path(artifact_path) {
        return Err((StatusCode::NOT_FOUND, "Artifact not found").into_response());
    }

    // Gate 2: Verify a live primary exists in the same GAV directory.
    // We look for ANY non-deleted artifact whose path is a sibling of
    // `artifact_path`; a hit means the GAV is live and the secondary
    // inherits its policy state. A miss means there is no primary to
    // anchor the secondary, so a stray storage byte at `maven/<path>`
    // (e.g. orphaned by a botched delete) must not be served.
    let gav_dir = match maven_gav_directory(artifact_path) {
        Some(dir) if !dir.is_empty() => dir,
        // Top-level / empty-dir paths can't be valid maven artifact paths.
        _ => return Err((StatusCode::NOT_FOUND, "Artifact not found").into_response()),
    };
    let sibling_prefix = format!("{}/%", gav_dir);
    let primary = sqlx::query_as::<_, LocalArtifactRow>(
        "SELECT storage_key, content_type, quarantine_status, quarantine_until \
         FROM artifacts \
         WHERE repository_id = $1 \
           AND path LIKE $2 \
           AND is_deleted = false \
         ORDER BY created_at DESC \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(&sibling_prefix)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    // Gate 3: Honor quarantine on the primary. A quarantined primary
    // means the whole GAV is gated; do not leak its companion files.
    check_quarantine_row(&primary)?;

    // Gates passed — read the secondary bytes from storage. A storage
    // backend error (transient S3 5xx, network) is mapped to a real
    // 500 (not 404) so an outage isn't masked as a missing file; the
    // caller's `if let Ok(...)` retains the existing "try next member"
    // semantics for legitimate misses.
    let storage = state.storage_for_repo_or_500(location)?;
    let storage_key = format!("maven/{}", artifact_path);
    let content = storage.get(&storage_key).await.map_err(|e| {
        // Distinguish missing object from real I/O error. Conservative:
        // every backend's "missing" error has "not found" in its
        // Display impl; anything else is internal.
        let msg = e.to_string();
        if msg.to_ascii_lowercase().contains("not found") {
            (StatusCode::NOT_FOUND, "Artifact not found").into_response()
        } else {
            internal_error("Storage", e)
        }
    })?;
    Ok((content, None))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::proxy_helpers::{
        insert_artifact, put_artifact_bytes, NewArtifact, RepoInfo,
    };
    use crate::api::handlers::test_db_helpers as db_helpers;

    // ── pure-function gates ─────────────────────────────────────────

    #[test]
    fn test_is_maven_secondary_path_known_extensions() {
        for ext in [
            ".pom",
            ".module",
            "-sources.jar",
            "-javadoc.jar",
            "-tests.jar",
            "-test-sources.jar",
            ".sha1",
            ".sha256",
            ".sha512",
            ".md5",
            ".asc",
        ] {
            let path = format!("g/a/1.0/a-1.0{}", ext);
            assert!(
                is_maven_secondary_path(&path),
                "{} should be recognized as secondary",
                ext
            );
        }
    }

    #[test]
    fn test_is_maven_secondary_path_primaries_rejected() {
        for primary in [".jar", ".aar", ".war", ".ear", ".zip"] {
            let path = format!("g/a/1.0/a-1.0{}", primary);
            assert!(
                !is_maven_secondary_path(&path),
                "{} must NOT be classified as secondary (primary files own their row)",
                primary
            );
        }
        assert!(!is_maven_secondary_path(""));
        assert!(!is_maven_secondary_path("/"));
    }

    #[test]
    fn test_maven_gav_directory_extraction() {
        assert_eq!(
            maven_gav_directory("com/example/foo/1.0/foo-1.0.pom"),
            Some("com/example/foo/1.0"),
        );
        // No slash returns None (defensive: callers reject this so a
        // bare filename can't produce an over-broad `LIKE '%'` query).
        assert_eq!(maven_gav_directory("nopath"), None);
        // Empty dir surfaces as Some(""); the caller treats it as a
        // refusal (would otherwise let `LIKE '/%'` match every row).
        assert_eq!(maven_gav_directory("/foo.pom"), Some(""));
    }

    // ── DB-backed integration tests (no_op without DATABASE_URL) ───

    /// Stand up a fresh local-maven repo plus an AppState rooted at the
    /// same storage dir. Matches the helper-fixture shape used elsewhere
    /// in `proxy_helpers::mod tests`.
    async fn maven_fixture() -> Option<(sqlx::PgPool, crate::api::SharedState, Uuid, RepoInfo, Uuid)>
    {
        let pool = db_helpers::try_pool().await?;
        let (user_id, _username) = db_helpers::create_user(&pool).await;
        let (repo_id, _, storage_dir) = db_helpers::create_repo(&pool, "local", "maven").await;
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let repo = RepoInfo {
            id: repo_id,
            key: "irrelevant".to_string(),
            storage_path: storage_dir.to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
        };
        Some((pool, state, repo_id, repo, user_id))
    }

    async fn insert_primary_jar(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        user_id: Uuid,
        path: &str,
        storage_key: &str,
    ) -> Uuid {
        insert_artifact(
            pool,
            NewArtifact {
                repository_id: repo_id,
                path,
                name: "foo",
                version: "1.0",
                size_bytes: 100,
                checksum_sha256: "primary-sha",
                content_type: "application/java-archive",
                storage_key,
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert primary")
    }

    #[tokio::test]
    async fn test_storage_fallback_hit_with_live_primary() {
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let _primary = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/foo/1.0/foo-1.0.jar",
            "maven/com/example/foo/1.0/foo-1.0.jar",
        )
        .await;
        let bytes = Bytes::from_static(b"<project>pom-bytes</project>");
        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/foo/1.0/foo-1.0.pom",
            bytes.clone(),
        )
        .await
        .expect("put");

        let location = repo.storage_location();
        let (content, ct) = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/foo/1.0/foo-1.0.pom",
        )
        .await
        .expect("fetch");
        assert_eq!(&content[..], &bytes[..]);
        assert!(ct.is_none(), "helper returns None for content-type");

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_serves_each_secondary_extension() {
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let _primary = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/foo/1.0/foo-1.0.jar",
            "maven/com/example/foo/1.0/foo-1.0.jar",
        )
        .await;
        let location = repo.storage_location();

        for (suffix, payload) in [
            (".pom", b"<project/>".to_vec()),
            (".module", b"{\"name\":\"foo\"}".to_vec()),
            ("-sources.jar", b"sources-jar-bytes".to_vec()),
            ("-javadoc.jar", b"javadoc-jar-bytes".to_vec()),
            (".sha512", b"a".repeat(128)),
            (".sha256", b"b".repeat(64)),
            (".sha1", b"c".repeat(40)),
            (".md5", b"d".repeat(32)),
            (".asc", b"-----BEGIN PGP SIGNATURE-----\n".to_vec()),
        ] {
            let path = format!("com/example/foo/1.0/foo-1.0{}", suffix);
            put_artifact_bytes(
                &state,
                &repo,
                &format!("maven/{}", path),
                Bytes::from(payload.clone()),
            )
            .await
            .expect("put");
            let (content, _) =
                maven_local_fetch_storage_fallback(&pool, &state, repo_id, &location, &path)
                    .await
                    .unwrap_or_else(|_| panic!("must serve secondary extension {}", suffix));
            assert_eq!(
                &content[..],
                &payload[..],
                "round-trip mismatch for {}",
                suffix
            );
        }

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_refuses_primary_extensions() {
        // SECURITY: even if bytes exist at `maven/<path>.jar`, the
        // storage fallback must refuse — primaries always have their
        // own row and must travel the SQL path.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let location = repo.storage_location();

        for primary_ext in [".jar", ".aar", ".war", ".ear", ".zip"] {
            let path = format!("com/example/foo/1.0/foo-1.0{}", primary_ext);
            put_artifact_bytes(
                &state,
                &repo,
                &format!("maven/{}", path),
                Bytes::from_static(b"primary-bytes-must-not-leak"),
            )
            .await
            .expect("put");
            let err = maven_local_fetch_storage_fallback(&pool, &state, repo_id, &location, &path)
                .await
                .expect_err(&format!("primary {} must be refused", primary_ext));
            assert_eq!(err.status(), StatusCode::NOT_FOUND);
        }

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_refuses_orphan_secondary() {
        // SECURITY: secondary bytes without an anchoring primary row
        // are orphans (botched delete, manual S3 upload) and must be
        // refused.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let location = repo.storage_location();

        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/orphan/1.0/orphan-1.0.pom",
            Bytes::from_static(b"<project>orphan</project>"),
        )
        .await
        .expect("put");

        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/orphan/1.0/orphan-1.0.pom",
        )
        .await
        .expect_err("orphan secondary must be refused");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_honors_quarantine_on_primary() {
        // SECURITY: quarantined primary -> its companions must NOT leak.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let primary_id = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/qfoo/1.0/qfoo-1.0.jar",
            "maven/com/example/qfoo/1.0/qfoo-1.0.jar",
        )
        .await;
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', \
             quarantine_until = NULL WHERE id = $1",
        )
        .bind(primary_id)
        .execute(&pool)
        .await
        .expect("set quarantine");

        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/qfoo/1.0/qfoo-1.0.pom",
            Bytes::from_static(b"<project>qfoo</project>"),
        )
        .await
        .expect("put");

        let location = repo.storage_location();
        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/qfoo/1.0/qfoo-1.0.pom",
        )
        .await
        .expect_err("quarantined primary must hold back its companions");
        // `check_quarantine_row` delegates to
        // `quarantine_service::check_download_allowed`, which returns
        // `AppError::Conflict` (409) when `quarantine_status = 'quarantined'`
        // and `quarantine_until` is in the past or NULL. Other policies
        // (`Forbidden` / 451 / 404) are reachable in other code paths
        // (e.g. tenant-policy plug-ins), so accept any of those too —
        // what matters for this SECURITY test is that the companion
        // .pom is NOT served, regardless of which refusal status the
        // current policy returns.
        assert!(
            err.status() == StatusCode::CONFLICT
                || err.status() == StatusCode::FORBIDDEN
                || err.status() == StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
                || err.status() == StatusCode::NOT_FOUND,
            "expected a refusal status, got {}",
            err.status()
        );

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_honors_soft_delete_on_primary() {
        // SECURITY: soft-deleted primary -> its companions are
        // refused (the GAV has been retracted).
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let primary_id = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/dfoo/1.0/dfoo-1.0.jar",
            "maven/com/example/dfoo/1.0/dfoo-1.0.jar",
        )
        .await;
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(primary_id)
            .execute(&pool)
            .await
            .expect("soft-delete");

        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/dfoo/1.0/dfoo-1.0.pom",
            Bytes::from_static(b"<project>dfoo</project>"),
        )
        .await
        .expect("put");

        let location = repo.storage_location();
        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/dfoo/1.0/dfoo-1.0.pom",
        )
        .await
        .expect_err("soft-deleted primary must hold back its companions");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_isolates_maven_prefix() {
        // The prior version of this test was a tautology — it planted
        // pypi/... bytes and queried with a maven path, which would
        // miss regardless of the helper's prefix. This version:
        //   (a) positive control: bytes at maven/<path> with a live
        //       primary -> served;
        //   (b) negative control: bytes at pypi/<other-path> -> NOT
        //       picked up by the maven fallback.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let location = repo.storage_location();

        // (a)
        let _primary = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/iso/1.0/iso-1.0.jar",
            "maven/com/example/iso/1.0/iso-1.0.jar",
        )
        .await;
        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/iso/1.0/iso-1.0.pom",
            Bytes::from_static(b"maven-pom"),
        )
        .await
        .expect("put maven");
        let (got, _) = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/iso/1.0/iso-1.0.pom",
        )
        .await
        .expect("positive: maven/<path> with live primary serves");
        assert_eq!(&got[..], b"maven-pom");

        // (b)
        put_artifact_bytes(
            &state,
            &repo,
            "pypi/com/example/leak/1.0/leak-1.0.pom",
            Bytes::from_static(b"pypi-bytes-must-not-leak"),
        )
        .await
        .expect("put pypi");
        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/leak/1.0/leak-1.0.pom",
        )
        .await
        .expect_err("pypi-prefixed bytes must not satisfy a maven fallback");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }
}
