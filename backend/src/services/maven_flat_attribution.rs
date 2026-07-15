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
//! `maven_flat_object_owner` attribution table backfilled by migration 163),
//! and uses that to:
//!
//! * gate reads -- serve a legacy flat object only to its genuine owner
//!   ([`flat_key_readable`]); and
//! * gate writes -- refuse a cross-repository overwrite and claim a
//!   previously-unowned key first-writer-wins ([`guard_flat_key_writable`]),
//!   which closes the write-side poisoning gap (#2584).
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

/// Distinct owning repositories of a live `artifacts` row at exactly this key
/// (LIMIT 2 -- one row is a clean owner, two rows means the key is ambiguous).
const OWNER_BY_ARTIFACT_ROW_SQL: &str = "SELECT DISTINCT repository_id FROM artifacts \
     WHERE storage_key = $1 AND is_deleted = false \
     LIMIT 2";

/// Distinct owning repositories of a live parent artifact whose metadata
/// `files[]` array lists this key (legacy GAV-grouped uploads whose companion
/// files have no row of their own). LIMIT 2 for the same ambiguity test.
const OWNER_BY_METADATA_FILES_SQL: &str = "SELECT DISTINCT a.repository_id \
     FROM artifact_metadata am \
     JOIN artifacts a ON a.id = am.artifact_id \
     WHERE a.is_deleted = false \
       AND jsonb_typeof(am.metadata->'files') = 'array' \
       AND EXISTS ( \
         SELECT 1 FROM jsonb_array_elements(am.metadata->'files') f \
         WHERE f->>'storage_key' = $1) \
     LIMIT 2";

/// The attribution table (backfilled legacy keys + write-time claims). The
/// `storage_key` primary key means this yields at most one owner.
const OWNER_BY_ATTRIBUTION_TABLE_SQL: &str =
    "SELECT repository_id FROM maven_flat_object_owner WHERE storage_key = $1 LIMIT 2";

/// Outcome of a single attribution-layer lookup.
enum LayerResult {
    /// No repository owns the key in this layer -- try the next layer.
    Absent,
    /// Exactly one repository owns the key.
    Owner(Uuid),
    /// Two or more repositories reference the key -- ambiguous, fail closed.
    Ambiguous,
}

/// Run one `storage_key`-parameterized owner lookup and classify the result.
async fn query_layer(db: &PgPool, sql: &str, storage_key: &str) -> Result<LayerResult> {
    let owners: Vec<Uuid> = sqlx::query_scalar(sql)
        .bind(storage_key)
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(match owners.as_slice() {
        [] => LayerResult::Absent,
        [only] => LayerResult::Owner(*only),
        _ => LayerResult::Ambiguous,
    })
}

/// Resolve the owner of a flat key directly (without checksum-suffix stripping):
/// (a) a live `artifacts` row, then (b) a live parent artifact whose metadata
/// `files[]` references the key, then (c) the `maven_flat_object_owner` table.
/// A layer that names two or more repositories is ambiguous and resolves to
/// `None` (no tenant may read it) rather than arbitrarily picking one owner.
async fn resolve_direct(db: &PgPool, storage_key: &str) -> Result<Option<Uuid>> {
    for sql in [
        OWNER_BY_ARTIFACT_ROW_SQL,
        OWNER_BY_METADATA_FILES_SQL,
        OWNER_BY_ATTRIBUTION_TABLE_SQL,
    ] {
        match query_layer(db, sql, storage_key).await? {
            LayerResult::Absent => continue,
            LayerResult::Owner(owner) => return Ok(Some(owner)),
            LayerResult::Ambiguous => return Ok(None),
        }
    }
    Ok(None)
}

/// Resolve the single repository that owns the physical object at `storage_key`,
/// or `None` when the key is unattributed (unowned, or ambiguous across
/// repositories). Resolution order: (a) live `artifacts` row, (b) live parent
/// artifact metadata `files[]`, (c) `maven_flat_object_owner` table, and if the
/// key is a checksum/signature sidecar, (d) strip the suffix and resolve the
/// base key the same way.
pub async fn attributed_owner(db: &PgPool, storage_key: &str) -> Result<Option<Uuid>> {
    if let Some(owner) = resolve_direct(db, storage_key).await? {
        return Ok(Some(owner));
    }
    // (d) Checksum/signature sidecar: inherit the base object's owner.
    if let Some(base) = strip_checksum_suffix(storage_key) {
        if let Some(owner) = resolve_direct(db, base).await? {
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
    matches!(attributed_owner(db, storage_key).await, Ok(Some(owner)) if owner == repository_id)
}

/// Insert a single first-writer-wins claim row (racing claims resolved by the
/// primary-key `ON CONFLICT DO NOTHING`).
async fn insert_claim(db: &PgPool, repository_id: Uuid, storage_key: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO maven_flat_object_owner (storage_key, repository_id, source) \
         VALUES ($1, $2, 'write_claim') \
         ON CONFLICT (storage_key) DO NOTHING",
    )
    .bind(storage_key)
    .bind(repository_id)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Insert a first-writer-wins claim for a previously-unowned flat key (and its
/// derived checksum/signature sidecars). The loser of a race reads back the
/// winner's row on its next attribution lookup.
async fn claim_flat_key(db: &PgPool, repository_id: Uuid, storage_key: &str) -> Result<()> {
    insert_claim(db, repository_id, storage_key).await?;

    // Claim the derived checksum/signature sidecars of a base key too, so a
    // second tenant cannot poison a companion of a GAV this repository owns.
    if strip_checksum_suffix(storage_key).is_none() {
        for suffix in CHECKSUM_SUFFIXES {
            insert_claim(db, repository_id, &format!("{storage_key}{suffix}")).await?;
        }
    }
    Ok(())
}

/// Guard a flat `maven/{path}` write by `repository_id`.
///
/// Filesystem backends short-circuit to `Ok` (isolated key space). On shared
/// cloud namespaces: a key owned by a *different* repository is refused with a
/// `403 Forbidden` ([`AppError::Authorization`], the cross-repository poisoning
/// guard, #2584); a key already owned by this repository is allowed; an unowned
/// key is claimed first-writer-wins and allowed. A database error propagates so
/// the caller fails the write rather than risk an unattributed overwrite.
pub async fn guard_flat_key_writable(
    db: &PgPool,
    repository_id: Uuid,
    storage_backend: &str,
    storage_key: &str,
) -> Result<()> {
    if storage_backend == "filesystem" {
        return Ok(());
    }
    match attributed_owner(db, storage_key).await? {
        Some(owner) if owner != repository_id => Err(AppError::Authorization(format!(
            "storage key '{storage_key}' is owned by another repository; \
             refusing cross-repository overwrite"
        ))),
        Some(_) => Ok(()),
        None => claim_flat_key(db, repository_id, storage_key).await,
    }
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
        let key = format!("maven/com/acme/live/1.0/live-1.0-{}.jar", Uuid::new_v4());
        seed_artifact(&pool, repo_a, "com/acme/live/1.0/live-1.0.jar", &key).await;
        assert_eq!(
            attributed_owner(&pool, &key).await.expect("query"),
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
        let base = format!("maven/com/acme/cs/1.0/cs-1.0-{}.jar", Uuid::new_v4());
        seed_artifact(&pool, repo_a, "com/acme/cs/1.0/cs-1.0.jar", &base).await;
        // The .sha1 sidecar has no row of its own but inherits the base owner.
        let checksum = format!("{base}.sha1");
        assert_eq!(
            attributed_owner(&pool, &checksum).await.expect("query"),
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
        assert_eq!(attributed_owner(&pool, &key).await.expect("query"), None);
    }

    #[tokio::test]
    async fn test_attributed_owner_none_when_ambiguous() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_a, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let (repo_b, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        // Two repositories hold a live row at the SAME flat key (legacy
        // pre-#2504 multi-owner state). The key is ambiguous, so it is
        // attributed to neither -- 404 for both tenants, not an arbitrary pick.
        let key = format!("maven/com/acme/amb/1.0/amb-1.0-{}.jar", Uuid::new_v4());
        seed_artifact(&pool, repo_a, "com/acme/amb/1.0/amb-1.0.jar", &key).await;
        seed_artifact(&pool, repo_b, "com/acme/amb/1.0/amb-1.0.jar", &key).await;
        assert_eq!(attributed_owner(&pool, &key).await.expect("query"), None);
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
    async fn test_guard_writable_claims_then_blocks_second_tenant() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_a, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let (repo_b, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let key = format!("maven/com/acme/claim/1.0/claim-1.0-{}.pom", Uuid::new_v4());

        // First writer claims the unowned key and is allowed.
        guard_flat_key_writable(&pool, repo_a, "s3", &key)
            .await
            .expect("first writer claims unowned key");
        // The claim now attributes the key (and its checksum sidecars) to repo_a.
        assert_eq!(
            attributed_owner(&pool, &key).await.expect("query"),
            Some(repo_a)
        );
        assert_eq!(
            attributed_owner(&pool, &format!("{key}.sha1"))
                .await
                .expect("query"),
            Some(repo_a)
        );

        // The owner may overwrite its own key; a second tenant is refused (403).
        guard_flat_key_writable(&pool, repo_a, "s3", &key)
            .await
            .expect("owner re-write allowed");
        let err = guard_flat_key_writable(&pool, repo_b, "s3", &key)
            .await
            .expect_err("second tenant must be refused");
        assert!(matches!(err, AppError::Authorization(_)));

        // Filesystem writes never consult the catalog.
        let fs_key = format!("maven/com/acme/fs/1.0/fs-1.0-{}.pom", Uuid::new_v4());
        guard_flat_key_writable(&pool, repo_b, "filesystem", &fs_key)
            .await
            .expect("filesystem write always allowed");

        // Clean up the claims (FK is ON DELETE CASCADE from repositories, but
        // these repos may be reused by the harness).
        sqlx::query(
            "DELETE FROM maven_flat_object_owner WHERE repository_id = $1 OR repository_id = $2",
        )
        .bind(repo_a)
        .bind(repo_b)
        .execute(&pool)
        .await
        .ok();
        tdh::cleanup(&pool, repo_b, Uuid::nil()).await;
        tdh::cleanup(&pool, repo_a, Uuid::nil()).await;
    }
}
