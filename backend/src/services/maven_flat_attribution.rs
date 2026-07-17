//! Repository attribution for row-less Maven flat-key objects (#2574, #2584).
//!
//! On shared cloud namespaces (S3/GCS/Azure) every repository's Maven objects
//! live under the same bare `maven/{path}` key space -- the per-repository
//! `storage_path` prefix that isolates filesystem backends is not applied. A
//! *row-less* object (a GAV-grouped companion file, a verbatim
//! `maven-metadata.xml`, or a stored checksum sidecar) carries no inherent
//! repository attribution, so a naive "is there a foreign row?" check treats it
//! as unowned for *every* repository and re-opens the cross-tenant hole #2504
//! closed.
//!
//! This module resolves the single owning repository of a flat key from the
//! catalog (live artifact rows, parent-artifact metadata `files[]`, and the
//! `maven_flat_object_owner` attribution table backfilled by migration 163 and
//! qualified by storage backend in migration 168), and uses that to:
//!
//! * gate reads -- serve a legacy flat object only to its genuine owner
//!   ([`flat_key_readable`]); and
//! * gate writes -- refuse a cross-repository overwrite before the write
//!   ([`guard_flat_key_writable`], a read-only check), then commit a
//!   first-writer-wins attribution claim only after the object bytes are
//!   successfully written ([`claim_flat_key_on_write`]). Splitting the check
//!   from the claim keeps an aborted or coordinate-invalid write from flipping
//!   ownership of a foreign unattributed key (#2584, V3b).
//!
//! Filesystem backends physically isolate each repository's key space, so every
//! entry point short-circuits to the pre-existing behavior there and never
//! consults the catalog.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Checksum / signature suffixes that inherit their base object's owner.
const CHECKSUM_SUFFIXES: [&str; 4] = [".sha1", ".md5", ".sha256", ".asc"];

/// If `storage_key` ends in a checksum/signature suffix, return the base key.
fn strip_checksum_suffix(storage_key: &str) -> Option<&str> {
    CHECKSUM_SUFFIXES
        .iter()
        .find_map(|suffix| storage_key.strip_suffix(suffix))
}

// Every owner lookup is parameterized by `$1` = storage_key and `$2` =
// storage_backend. The backend qualifier is what closes #2671: on a MIXED
// backend deployment the same flat storage-key string names two physically
// distinct objects (one per cloud), so owner resolution must only consider rows
// whose repository lives on the *same* backend as the caller. Without it, two
// repositories on different backends collide on one key and both fail closed.

/// Distinct owning repositories of a live `artifacts` row at exactly this key,
/// restricted to repositories on `$2` (LIMIT 2 -- one row is a clean owner, two
/// rows means the key is ambiguous on that backend).
const OWNER_BY_ARTIFACT_ROW_SQL: &str = "SELECT DISTINCT a.repository_id FROM artifacts a \
     JOIN repositories r ON r.id = a.repository_id \
     WHERE a.storage_key = $1 AND a.is_deleted = false AND r.storage_backend = $2 \
     LIMIT 2";

/// Distinct owning repositories of a live parent artifact whose metadata
/// `files[]` array lists this key (legacy GAV-grouped uploads whose companion
/// files have no row of their own), restricted to repositories on `$2`. LIMIT 2
/// for the same ambiguity test.
const OWNER_BY_METADATA_FILES_SQL: &str = "SELECT DISTINCT a.repository_id \
     FROM artifact_metadata am \
     JOIN artifacts a ON a.id = am.artifact_id \
     JOIN repositories r ON r.id = a.repository_id \
     WHERE a.is_deleted = false \
       AND r.storage_backend = $2 \
       AND jsonb_typeof(am.metadata->'files') = 'array' \
       AND EXISTS ( \
         SELECT 1 FROM jsonb_array_elements(am.metadata->'files') f \
         WHERE f->>'storage_key' = $1) \
     LIMIT 2";

/// The attribution table (backfilled legacy keys + write-time claims). The
/// `(storage_backend, storage_key)` primary key means this yields at most one
/// owner per backend.
const OWNER_BY_ATTRIBUTION_TABLE_SQL: &str = "SELECT repository_id FROM maven_flat_object_owner \
     WHERE storage_key = $1 AND storage_backend = $2 LIMIT 2";

/// Outcome of a single attribution-layer lookup.
enum LayerResult {
    /// No repository owns the key in this layer -- try the next layer.
    Absent,
    /// Exactly one repository owns the key.
    Owner(Uuid),
    /// Two or more repositories reference the key -- ambiguous, fail closed.
    Ambiguous,
}

/// Run one owner lookup (parameterized by storage_key + storage_backend) and
/// classify the result.
async fn query_layer(
    db: &PgPool,
    sql: &str,
    storage_backend: &str,
    storage_key: &str,
) -> Result<LayerResult> {
    let owners: Vec<Uuid> = sqlx::query_scalar(sql)
        .bind(storage_key)
        .bind(storage_backend)
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(match owners.as_slice() {
        [] => LayerResult::Absent,
        [only] => LayerResult::Owner(*only),
        _ => LayerResult::Ambiguous,
    })
}

/// Resolve the owner of a flat key on `storage_backend` directly (without
/// checksum-suffix stripping): (a) a live `artifacts` row, then (b) a live
/// parent artifact whose metadata `files[]` references the key, then (c) the
/// `maven_flat_object_owner` table -- each restricted to the same backend. A
/// layer that names two or more repositories is ambiguous and resolves to
/// `None` (no tenant may read it) rather than arbitrarily picking one owner.
async fn resolve_direct(
    db: &PgPool,
    storage_backend: &str,
    storage_key: &str,
) -> Result<Option<Uuid>> {
    for sql in [
        OWNER_BY_ARTIFACT_ROW_SQL,
        OWNER_BY_METADATA_FILES_SQL,
        OWNER_BY_ATTRIBUTION_TABLE_SQL,
    ] {
        match query_layer(db, sql, storage_backend, storage_key).await? {
            LayerResult::Absent => continue,
            LayerResult::Owner(owner) => return Ok(Some(owner)),
            LayerResult::Ambiguous => return Ok(None),
        }
    }
    Ok(None)
}

/// Resolve the single repository that owns the physical object at
/// (`storage_backend`, `storage_key`), or `None` when the key is unattributed
/// (unowned, or ambiguous across repositories on that backend). The backend is
/// part of the object's physical identity: the same flat key on two different
/// backends names two distinct objects with independent owners (#2671).
/// Resolution order: (a) live `artifacts` row, (b) live parent artifact metadata
/// `files[]`, (c) `maven_flat_object_owner` table, and if the key is a
/// checksum/signature sidecar, (d) strip the suffix and resolve the base key the
/// same way.
pub async fn attributed_owner(
    db: &PgPool,
    storage_backend: &str,
    storage_key: &str,
) -> Result<Option<Uuid>> {
    if let Some(owner) = resolve_direct(db, storage_backend, storage_key).await? {
        return Ok(Some(owner));
    }
    // (d) Checksum/signature sidecar: inherit the base object's owner.
    if let Some(base) = strip_checksum_suffix(storage_key) {
        if let Some(owner) = resolve_direct(db, storage_backend, base).await? {
            return Ok(Some(owner));
        }
    }
    Ok(None)
}

/// May the flat `maven/{path}` object at `storage_key` be served to
/// `repository_id`?
///
/// Filesystem backends short-circuit to `true` -- each repository physically
/// owns its whole key space. On shared cloud namespaces the key is readable iff
/// it is attributed to exactly this repository; unowned and foreign-owned keys
/// are both refused. A database error fails closed (`false`): never serve a flat
/// key we cannot prove belongs to the caller.
pub async fn flat_key_readable(
    db: &PgPool,
    repository_id: Uuid,
    storage_backend: &str,
    storage_key: &str,
) -> bool {
    if storage_backend == "filesystem" {
        return true;
    }
    matches!(
        attributed_owner(db, storage_backend, storage_key).await,
        Ok(Some(owner)) if owner == repository_id
    )
}

/// Insert a single first-writer-wins claim row (racing claims resolved by the
/// `(storage_backend, storage_key)` primary-key `ON CONFLICT DO NOTHING`).
async fn insert_claim(
    db: &PgPool,
    repository_id: Uuid,
    storage_backend: &str,
    storage_key: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO maven_flat_object_owner (storage_backend, storage_key, repository_id, source) \
         VALUES ($1, $2, $3, 'write_claim') \
         ON CONFLICT (storage_backend, storage_key) DO NOTHING",
    )
    .bind(storage_backend)
    .bind(storage_key)
    .bind(repository_id)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Guard a flat `maven/{path}` write by `repository_id`, BEFORE the write runs.
///
/// This is a read-only check -- it must never mutate attribution, because it
/// runs before the object bytes are written and before coordinate/validation
/// steps that can still reject the request. A guard that claimed the key here
/// would flip ownership of a foreign *unattributed* key on any aborted or
/// coordinate-invalid write, leaking the victim's bytes on the next GET (V3b).
///
/// Filesystem backends short-circuit to `Ok` (isolated key space). On shared
/// cloud namespaces: a key owned by a *different* repository is refused with a
/// `403 Forbidden` ([`AppError::Authorization`], the cross-repository poisoning
/// guard, #2584); a key already owned by this repository, and a currently
/// unowned key, are both allowed to proceed. The unowned key is only *claimed*
/// after its bytes are successfully written, via [`claim_flat_key_on_write`].
pub async fn guard_flat_key_writable(
    db: &PgPool,
    repository_id: Uuid,
    storage_backend: &str,
    storage_key: &str,
) -> Result<()> {
    if storage_backend == "filesystem" {
        return Ok(());
    }
    match attributed_owner(db, storage_backend, storage_key).await? {
        Some(owner) if owner != repository_id => Err(AppError::Authorization(format!(
            "storage key '{storage_key}' is owned by another repository; \
             refusing cross-repository overwrite"
        ))),
        // Own key, or currently unowned: allow the write. Attribution for an
        // unowned key is committed only on write success (claim_flat_key_on_write).
        Some(_) | None => Ok(()),
    }
}

/// Record the first-writer-wins attribution claim for a flat key that this
/// repository has just SUCCESSFULLY written, closing V3b: a claim row exists
/// only for a request that actually persisted the requester's own bytes to
/// exactly this key. Call this immediately after the `storage.put` for
/// `storage_key` returns `Ok` (for both row-less puts and the main artifact).
///
/// Filesystem backends short-circuit (isolated key space, no attribution rows).
/// On cloud the claim is idempotent (`ON CONFLICT DO NOTHING`); a concurrent
/// legitimate first-writer race resolves to whichever `put` committed first,
/// the same accepted first-publish race as before. Only the exact written key
/// is claimed -- derived checksum/signature sidecars are claimed by their own
/// successful puts, never speculatively here.
pub async fn claim_flat_key_on_write(
    db: &PgPool,
    repository_id: Uuid,
    storage_backend: &str,
    storage_key: &str,
) -> Result<()> {
    if storage_backend == "filesystem" {
        return Ok(());
    }
    insert_claim(db, repository_id, storage_backend, storage_key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    async fn seed_artifact(pool: &PgPool, repo_id: Uuid, path: &str, storage_key: &str) {
        sqlx::query(
            "INSERT INTO artifacts \
             (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $3, 1, $4, 'application/octet-stream', $5)",
        )
        .bind(repo_id)
        .bind(path)
        .bind(path)
        .bind("0".repeat(64))
        .bind(storage_key)
        .execute(pool)
        .await
        .expect("seed artifact");
    }

    #[test]
    fn test_strip_checksum_suffix() {
        assert_eq!(
            strip_checksum_suffix("maven/a/b.jar.sha1"),
            Some("maven/a/b.jar")
        );
        assert_eq!(
            strip_checksum_suffix("maven/a/b.jar.md5"),
            Some("maven/a/b.jar")
        );
        assert_eq!(
            strip_checksum_suffix("maven/a/b.jar.sha256"),
            Some("maven/a/b.jar")
        );
        assert_eq!(
            strip_checksum_suffix("maven/a/b.pom.asc"),
            Some("maven/a/b.pom")
        );
        assert_eq!(strip_checksum_suffix("maven/a/b.jar"), None);
    }

    #[tokio::test]
    async fn test_attributed_owner_from_live_row() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_a, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        set_repo_backend(&pool, repo_a, "s3").await;
        let key = format!("maven/com/acme/live/1.0/live-1.0-{}.jar", Uuid::new_v4());
        seed_artifact(&pool, repo_a, "com/acme/live/1.0/live-1.0.jar", &key).await;
        assert_eq!(
            attributed_owner(&pool, "s3", &key).await.expect("query"),
            Some(repo_a)
        );
        tdh::cleanup(&pool, repo_a, Uuid::nil()).await;
    }

    #[tokio::test]
    async fn test_attributed_owner_checksum_inherits_base() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_a, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        set_repo_backend(&pool, repo_a, "s3").await;
        let base = format!("maven/com/acme/cs/1.0/cs-1.0-{}.jar", Uuid::new_v4());
        seed_artifact(&pool, repo_a, "com/acme/cs/1.0/cs-1.0.jar", &base).await;
        // The .sha1 sidecar has no row of its own but inherits the base owner.
        let checksum = format!("{base}.sha1");
        assert_eq!(
            attributed_owner(&pool, "s3", &checksum)
                .await
                .expect("query"),
            Some(repo_a)
        );
        tdh::cleanup(&pool, repo_a, Uuid::nil()).await;
    }

    #[tokio::test]
    async fn test_attributed_owner_none_when_orphan() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let key = format!("maven/com/acme/orphan/{}/orphan.pom", Uuid::new_v4());
        assert_eq!(
            attributed_owner(&pool, "s3", &key).await.expect("query"),
            None
        );
    }

    #[tokio::test]
    async fn test_attributed_owner_none_when_ambiguous() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_a, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let (repo_b, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        // Two repositories on the SAME backend hold a live row at the SAME flat
        // key (legacy pre-#2504 multi-owner state on one shared namespace). The
        // key is ambiguous, so it is attributed to neither -- 404 for both
        // tenants, not an arbitrary pick.
        set_repo_backend(&pool, repo_a, "s3").await;
        set_repo_backend(&pool, repo_b, "s3").await;
        let key = format!("maven/com/acme/amb/1.0/amb-1.0-{}.jar", Uuid::new_v4());
        seed_artifact(&pool, repo_a, "com/acme/amb/1.0/amb-1.0.jar", &key).await;
        seed_artifact(&pool, repo_b, "com/acme/amb/1.0/amb-1.0.jar", &key).await;
        assert_eq!(
            attributed_owner(&pool, "s3", &key).await.expect("query"),
            None
        );
        assert!(!flat_key_readable(&pool, repo_a, "s3", &key).await);
        assert!(!flat_key_readable(&pool, repo_b, "s3", &key).await);
        tdh::cleanup(&pool, repo_b, Uuid::nil()).await;
        tdh::cleanup(&pool, repo_a, Uuid::nil()).await;
    }

    #[tokio::test]
    async fn test_flat_key_readable_ownership_polarity() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_a, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let (repo_b, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        set_repo_backend(&pool, repo_a, "s3").await;
        set_repo_backend(&pool, repo_b, "s3").await;
        let key = format!("maven/com/acme/pol/1.0/pol-1.0-{}.jar", Uuid::new_v4());
        seed_artifact(&pool, repo_b, "com/acme/pol/1.0/pol-1.0.jar", &key).await;

        // Owner reads it on cloud; a foreign repo does not (the #2504 hole
        // stays closed).
        assert!(flat_key_readable(&pool, repo_b, "s3", &key).await);
        assert!(!flat_key_readable(&pool, repo_a, "s3", &key).await);

        // An unowned key is refused on cloud (fail-closed) ...
        let orphan = format!("maven/com/acme/pol/1.0/pol-1.0-{}.pom", Uuid::new_v4());
        assert!(!flat_key_readable(&pool, repo_a, "s3", &orphan).await);
        // ... but every key is readable on a repo-isolated filesystem backend.
        assert!(flat_key_readable(&pool, repo_a, "filesystem", &key).await);
        assert!(flat_key_readable(&pool, repo_a, "filesystem", &orphan).await);

        tdh::cleanup(&pool, repo_b, Uuid::nil()).await;
        tdh::cleanup(&pool, repo_a, Uuid::nil()).await;
    }

    #[tokio::test]
    async fn test_guard_does_not_claim_then_claim_on_write_blocks_second_tenant() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_a, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let (repo_b, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let key = format!("maven/com/acme/claim/1.0/claim-1.0-{}.pom", Uuid::new_v4());

        // The pre-write guard allows an unowned key BUT must NOT attribute it
        // (V3b): a request that aborts before writing must leave no owner row.
        guard_flat_key_writable(&pool, repo_a, "s3", &key)
            .await
            .expect("unowned key allowed to proceed");
        assert_eq!(
            attributed_owner(&pool, "s3", &key).await.expect("query"),
            None,
            "guard must not create a claim before the write succeeds"
        );

        // Only after a successful write is the claim committed -- for exactly
        // the written key, not its derived checksum sidecars.
        claim_flat_key_on_write(&pool, repo_a, "s3", &key)
            .await
            .expect("claim on write success");
        assert_eq!(
            attributed_owner(&pool, "s3", &key).await.expect("query"),
            Some(repo_a)
        );
        // No speculative claim ROW is inserted for the derived checksum key --
        // it is claimed only by its own successful write. (It still *resolves*
        // to the base owner via checksum-suffix inheritance, which is intended.)
        let sidecar_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM maven_flat_object_owner WHERE storage_key = $1",
        )
        .bind(format!("{key}.sha1"))
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(sidecar_rows, 0, "no speculative sidecar claim row");

        // The owner may overwrite its own key; a second tenant is refused (403).
        guard_flat_key_writable(&pool, repo_a, "s3", &key)
            .await
            .expect("owner re-write allowed");
        let err = guard_flat_key_writable(&pool, repo_b, "s3", &key)
            .await
            .expect_err("second tenant must be refused");
        assert!(matches!(err, AppError::Authorization(_)));

        // Filesystem writes never consult or mutate the catalog.
        let fs_key = format!("maven/com/acme/fs/1.0/fs-1.0-{}.pom", Uuid::new_v4());
        guard_flat_key_writable(&pool, repo_b, "filesystem", &fs_key)
            .await
            .expect("filesystem write always allowed");
        claim_flat_key_on_write(&pool, repo_b, "filesystem", &fs_key)
            .await
            .expect("filesystem claim is a no-op");
        assert_eq!(
            attributed_owner(&pool, "filesystem", &fs_key)
                .await
                .expect("query"),
            None
        );

        clear_claims(&pool, &[repo_a, repo_b]).await;
        tdh::cleanup(&pool, repo_b, Uuid::nil()).await;
        tdh::cleanup(&pool, repo_a, Uuid::nil()).await;
    }

    #[tokio::test]
    async fn test_aborted_write_does_not_flip_ownership_of_foreign_key() {
        // V3b regression: an attacker's write that passes the pre-write guard
        // (the key is unattributed) but then ABORTS -- coordinate-invalid path,
        // validation failure, storage error -- must leave the key unattributed,
        // so a victim's legacy bytes are never re-attributed to the attacker.
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (attacker, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let key = format!("maven/com/victimco/internal-{}.txt", Uuid::new_v4());

        // Guard passes (unowned), but the request aborts -> claim_on_write is
        // never reached.
        guard_flat_key_writable(&pool, attacker, "s3", &key)
            .await
            .expect("guard allows unowned key to proceed");

        // No owner row was created, so nobody can read the key on cloud (404).
        assert_eq!(
            attributed_owner(&pool, "s3", &key).await.expect("query"),
            None
        );
        assert!(!flat_key_readable(&pool, attacker, "s3", &key).await);

        clear_claims(&pool, &[attacker]).await;
        tdh::cleanup(&pool, attacker, Uuid::nil()).await;
    }

    async fn set_repo_backend(pool: &PgPool, repo_id: Uuid, backend: &str) {
        sqlx::query("UPDATE repositories SET storage_backend = $1 WHERE id = $2")
            .bind(backend)
            .bind(repo_id)
            .execute(pool)
            .await
            .expect("set repo backend");
    }

    /// #2671 regression: on a MIXED-backend deployment the same flat storage
    /// key names two physically distinct objects (one per cloud). Attribution
    /// must be qualified by backend so each tenant resolves to ITSELF as the
    /// single owner of its own object, instead of both collapsing onto one
    /// `storage_key`-only PK row that reads as ambiguous and fails closed
    /// (404 read / 403 write) for BOTH tenants.
    ///
    /// This test FAILS on the pre-fix code (`attributed_owner` ignored the
    /// backend, so the two live rows collided into an ambiguous result and
    /// `flat_key_readable` returned false for both) and PASSES after the fix
    /// (migration 168 + backend-scoped resolution).
    #[tokio::test]
    async fn test_mixed_backend_same_key_no_collision_2671() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_s3, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let (repo_gcs, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        // The two repositories live on two DIFFERENT cloud backends.
        set_repo_backend(&pool, repo_s3, "s3").await;
        set_repo_backend(&pool, repo_gcs, "gcs").await;

        // The SAME flat storage key -- the same Maven GAV maps to the same key
        // string, but the two objects are physically distinct (one in S3, one
        // in GCS).
        let key = format!("maven/com/acme/mix/1.0/mix-1.0-{}.jar", Uuid::new_v4());
        seed_artifact(&pool, repo_s3, "com/acme/mix/1.0/mix-1.0.jar", &key).await;
        seed_artifact(&pool, repo_gcs, "com/acme/mix/1.0/mix-1.0.jar", &key).await;

        // Each backend's object resolves to its OWN single owner -- no collision.
        assert_eq!(
            attributed_owner(&pool, "s3", &key).await.expect("query"),
            Some(repo_s3),
            "the s3 object must attribute to the s3 repository"
        );
        assert_eq!(
            attributed_owner(&pool, "gcs", &key).await.expect("query"),
            Some(repo_gcs),
            "the gcs object must attribute to the gcs repository"
        );

        // Each tenant can read its OWN object on its OWN backend (the bug made
        // both 404).
        assert!(
            flat_key_readable(&pool, repo_s3, "s3", &key).await,
            "s3 tenant must read its own object"
        );
        assert!(
            flat_key_readable(&pool, repo_gcs, "gcs", &key).await,
            "gcs tenant must read its own object"
        );

        // Cross-backend isolation still holds: neither owns the other's object.
        assert!(!flat_key_readable(&pool, repo_s3, "gcs", &key).await);
        assert!(!flat_key_readable(&pool, repo_gcs, "s3", &key).await);

        // And write attribution is likewise per-backend: each may claim/own its
        // own object without the other's claim blocking it (#2671, write side).
        let wkey = format!("maven/com/acme/mix/1.0/mix-1.0-{}.pom", Uuid::new_v4());
        claim_flat_key_on_write(&pool, repo_s3, "s3", &wkey)
            .await
            .expect("s3 claim");
        claim_flat_key_on_write(&pool, repo_gcs, "gcs", &wkey)
            .await
            .expect("gcs claim must not collide with the s3 claim");
        guard_flat_key_writable(&pool, repo_s3, "s3", &wkey)
            .await
            .expect("s3 owner re-write allowed");
        guard_flat_key_writable(&pool, repo_gcs, "gcs", &wkey)
            .await
            .expect("gcs owner re-write allowed");
        assert_eq!(
            attributed_owner(&pool, "s3", &wkey).await.expect("query"),
            Some(repo_s3)
        );
        assert_eq!(
            attributed_owner(&pool, "gcs", &wkey).await.expect("query"),
            Some(repo_gcs)
        );

        clear_claims(&pool, &[repo_s3, repo_gcs]).await;
        tdh::cleanup(&pool, repo_gcs, Uuid::nil()).await;
        tdh::cleanup(&pool, repo_s3, Uuid::nil()).await;
    }

    async fn clear_claims(pool: &PgPool, repos: &[Uuid]) {
        for repo in repos {
            sqlx::query("DELETE FROM maven_flat_object_owner WHERE repository_id = $1")
                .bind(repo)
                .execute(pool)
                .await
                .ok();
        }
    }
}
