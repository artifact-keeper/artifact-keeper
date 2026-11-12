//! The per-object publish lock shared by hosted format handlers whose storage
//! key is derived from the artifact path (#4837, #4892, #5399).
//!
//! Every publish of one coordinate writes the same object. Without a lock that
//! covers the storage write, a request that loses the `artifacts` row insert
//! has already replaced the winner's bytes, and the committed row then names
//! bytes that are not in storage. A handler therefore takes
//! [`lock_publish_key`] inside its publishing transaction, re-checks for a
//! live row under it, writes, inserts and commits while holding it; a failed
//! publish removes its object through [`discard_unreferenced_publish_object`],
//! which decides under the same lock.

use std::sync::Arc;

use sqlx::{PgConnection, PgPool};
use tracing::warn;
use uuid::Uuid;

/// Take the transaction-scoped advisory lock that serialises every decision
/// about the object at one storage key.
///
/// `namespace` keeps the lock names of different handlers apart. The name is
/// the physical object: backend plus key, plus the repository id on
/// repo-isolated backends (filesystem), where the same key string in two
/// repositories names two different objects. A hash collision between two
/// names only serialises two unrelated publishes; it never lets two holders
/// of one name overlap.
pub(crate) async fn lock_publish_key(
    conn: &mut PgConnection,
    namespace: &str,
    repository_id: Uuid,
    storage_backend: &str,
    storage_key: &str,
) -> Result<(), sqlx::Error> {
    let scope = if crate::storage::registry::backend_is_repo_isolated(storage_backend) {
        repository_id.to_string()
    } else {
        String::new()
    };
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "{namespace}\u{1f}{storage_backend}\u{1f}{scope}\u{1f}{storage_key}"
        ))
        .execute(conn)
        .await?;
    Ok(())
}

/// Whether a live `artifacts` row names the object at `storage_key`.
///
/// On a repo-isolated backend the same key string in another repository is a
/// different object, so only this repository's rows count there. On a shared
/// namespace any live row naming the key shares the object.
pub(crate) async fn object_still_published(
    conn: &mut PgConnection,
    repository_id: Uuid,
    storage_backend: &str,
    storage_key: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM artifacts \
         WHERE storage_key = $1 AND is_deleted = false \
           AND (repository_id = $2 OR NOT $3))",
    )
    .bind(storage_key)
    .bind(repository_id)
    .bind(crate::storage::registry::backend_is_repo_isolated(
        storage_backend,
    ))
    .fetch_one(conn)
    .await
}

/// Remove the object a publish wrote when that publish never committed, unless
/// a committed row references it.
///
/// Runs under [`lock_publish_key`] for the same `namespace`, so it waits for an
/// in-flight publish of the key and then sees its committed row (and keeps the
/// object) or its rollback. Best-effort: the caller is already returning the
/// failure that triggered this, so an error before the delete keeps the
/// object (fail closed) and is only logged.
pub(crate) async fn discard_unreferenced_publish_object(
    db: &PgPool,
    storage: &Arc<dyn crate::storage::StorageBackend>,
    namespace: &str,
    repository_id: Uuid,
    storage_backend: &str,
    storage_key: &str,
) {
    let result: Result<(), String> = async {
        let mut tx = db.begin().await.map_err(|e| e.to_string())?;
        lock_publish_key(
            &mut tx,
            namespace,
            repository_id,
            storage_backend,
            storage_key,
        )
        .await
        .map_err(|e| e.to_string())?;
        if object_still_published(&mut tx, repository_id, storage_backend, storage_key)
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(());
        }
        if let Err(e) = storage.delete(storage_key).await {
            warn!(
                error = %e,
                storage_key = %storage_key,
                namespace = %namespace,
                "failed to remove the object of an uncommitted publish; it stays \
                 unreferenced in storage and needs manual cleanup"
            );
        }
        tx.commit().await.map_err(|e| e.to_string())
    }
    .await;
    if let Err(e) = result {
        warn!(
            error = %e,
            storage_key = %storage_key,
            namespace = %namespace,
            "could not decide whether the object of an uncommitted publish is \
             unreferenced; it was kept"
        );
    }
}
