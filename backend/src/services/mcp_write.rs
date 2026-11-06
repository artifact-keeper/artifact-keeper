//! MCP registry write path (#5253, Phase 2/3): version tombstones, the
//! guard that keeps a pinned OCI manifest from being deleted by digest, and
//! the write-side audit rows.
//!
//! Database operations only; nothing here opens an outbound connection.

use sqlx::PgPool;
use uuid::Uuid;

use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};

/// Whether `name@version` was ever stored in `repo_id` (published, replicated
/// or promoted in, whatever happened to it since): the ledger
/// `mcp_version_tombstones` (migration 323) is written by trigger on every
/// server.json row insert and outlives a trash purge, so such a version can
/// never be published again.
pub async fn version_tombstoned(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    version: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mcp_version_tombstones \
         WHERE repository_id = $1 AND name = $2 AND version = $3)",
    )
    .bind(repo_id)
    .bind(name)
    .bind(version)
    .fetch_one(db)
    .await
}

/// Whether copying an artifact at `path` (`name@version`) into `target_repo_id`
/// would store a server version the MCP repository recorded before
/// (promotion, #5253). The copy would replace a trashed row or bring a
/// purged version back, possibly with other bytes; it is refused before the
/// trashed row at the target path is cleared (the insert guard of migration
/// 327 refuses it as well). Always `false` for other formats and other
/// paths.
pub async fn copy_reuses_recorded_version(
    db: &PgPool,
    target_format: &crate::models::repository::RepositoryFormat,
    target_repo_id: Uuid,
    path: &str,
    name: &str,
    version: Option<&str>,
) -> Result<bool, sqlx::Error> {
    if target_format != &crate::models::repository::RepositoryFormat::Mcp
        || !(path.starts_with("servers/") && path.ends_with("/server.json"))
    {
        return Ok(false);
    }
    version_tombstoned(db, target_repo_id, name, version.unwrap_or_default()).await
}

/// The refusal text of [`copy_reuses_recorded_version`].
pub const COPY_REUSES_VERSION: &str =
    "this MCP server version was stored in the target repository before (deleted, trashed or \
     purged); a server version is write-once";

/// The SQL predicate (over `artifact_metadata m`) of a version whose first
/// package resolution failed. An admin edit that re-resolves a version marks
/// its resolution `afterEdit` ([`mark_resolution_after_edit`]): that version
/// may have been served before the edit, so its failure never frees it.
const FAILED_NEVER_SERVED: &str = "m.metadata->'resolution'->>'state' = 'failed' \
     AND COALESCE(m.metadata->'resolution'->>'afterEdit', 'false') <> 'true'";

/// Mark a re-resolution started by an admin edit (`PUT`) in the stored
/// metadata `doc`: the edited version may have been served, so a failure of
/// this resolution keeps the version number taken.
pub fn mark_resolution_after_edit(doc: &mut serde_json::Value) {
    if let Some(r) = doc.get_mut("resolution").and_then(|r| r.as_object_mut()) {
        r.insert("afterEdit".into(), serde_json::Value::Bool(true));
    }
}

/// The live server.json artifact of `name@version` in `repo_id` whose async
/// package resolution FAILED (`metadata.resolution.state = "failed"`) on its
/// first resolution. Such a version was never served (a resolving version is
/// hidden, and a failed one never leaves that state), so it does not consume
/// the version number: see [`version_reserved`] and
/// [`release_failed_version`]. A failure after an admin edit does not count.
pub async fn failed_version(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    version: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT a.id FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false \
           AND {FAILED_NEVER_SERVED}"
    )))
    .bind(repo_id)
    .bind(crate::formats::mcp::storage_path(name, version))
    .fetch_optional(db)
    .await
}

/// Whether `name@version` is taken in `repo_id`: it was ever stored
/// ([`version_tombstoned`]) and is not a version whose resolution failed
/// ([`failed_version`]). A taken version answers `409 mcp_version_exists`.
pub async fn version_reserved(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    version: &str,
) -> Result<bool, sqlx::Error> {
    if !version_tombstoned(db, repo_id, name, version).await? {
        return Ok(false);
    }
    Ok(failed_version(db, repo_id, name, version).await?.is_none())
}

/// Free `name@version` for a republish when its stored version failed to
/// resolve: remove that artifact row (as a trash purge does; the
/// content-addressed object is left to storage GC) and its tombstone, in one
/// transaction. Whether a failed version was released. A version that was
/// ever served, or that was deleted, keeps its tombstone.
pub async fn release_failed_version(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    version: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    let row: Option<(Uuid, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT a.id, a.checksum_sha256 FROM artifacts a \
         JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false \
           AND {FAILED_NEVER_SERVED} \
         FOR UPDATE OF a"
    )))
    .bind(repo_id)
    .bind(crate::formats::mcp::storage_path(name, version))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, checksum)) = row else {
        return Ok(false);
    };
    for sql in [
        "DELETE FROM promotion_approvals WHERE artifact_id = $1",
        "DELETE FROM mcp_resolve_jobs WHERE artifact_id = $1",
        "DELETE FROM artifacts WHERE id = $1",
    ] {
        sqlx::query(sql).bind(id).execute(&mut *tx).await?;
    }
    if let Err(e) = crate::services::package_service::prune_catalog_for_purged_artifact(
        &mut tx, repo_id, &checksum,
    )
    .await
    {
        tracing::warn!(artifact_id = %id, error = %e, "MCP: catalog rows of a failed version not pruned");
    }
    sqlx::query(
        "DELETE FROM mcp_version_tombstones \
         WHERE repository_id = $1 AND name = $2 AND version = $3",
    )
    .bind(repo_id)
    .bind(name)
    .bind(version)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(artifact_id = %id, server = %name, %version, "MCP: a version whose resolution failed was released for a republish");
    Ok(true)
}

/// The containment probes (GIN-indexed `metadata @> ...`) that find a server
/// version pinning `digest` of image `name` in `repo_id`, as the index digest
/// or as the gated platform child.
pub fn pin_probes(repo_id: Uuid, name: &str, digest: &str) -> [serde_json::Value; 2] {
    let probe = |field: &str| {
        serde_json::json!({ "packages": [{ "resolved": {
            "repositoryId": repo_id, "name": name, field: digest,
        }}]})
    };
    [probe("digest"), probe("gateDigest")]
}

/// Whether a live (not trashed) MCP server version, in any status, pins
/// `digest` of image `name` in the OCI repository `repo_id`. A soft-deleted
/// version still counts: `include_deleted=true` serves it.
pub async fn digest_pinned_by_mcp(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    digest: &str,
) -> Result<bool, sqlx::Error> {
    let any_mcp: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM repositories WHERE format = 'mcp')")
            .fetch_one(db)
            .await?;
    if !any_mcp {
        return Ok(false);
    }
    let [by_index, by_child] = pin_probes(repo_id, name, digest);
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM artifact_metadata m JOIN artifacts a ON a.id = m.artifact_id \
         WHERE m.format = 'mcp' AND a.is_deleted = false \
           AND (m.metadata @> $1::jsonb OR m.metadata @> $2::jsonb))",
    )
    .bind(&by_index)
    .bind(&by_child)
    .fetch_one(db)
    .await
}

/// Who did an MCP write, for its audit row.
#[derive(Debug, Clone, Copy)]
pub enum Actor {
    User(Uuid),
    System(&'static str),
}

/// One write-side MCP audit row (fire-and-forget): `MCP_SERVER_PUBLISHED`,
/// `MCP_SERVER_STATUS_CHANGED`, `MCP_SERVER_EDITED`, `MCP_SERVER_DELETED`,
/// `MCP_SERVER_PURGED`, `MCP_BUNDLE_SIGNATURE_REJECTED`. `details` gains `repository`, `server`
/// and `version`.
#[allow(clippy::too_many_arguments)]
pub fn audit(
    db: &PgPool,
    action: AuditAction,
    actor: Actor,
    repo_key: &str,
    artifact_id: Option<Uuid>,
    server: &str,
    version: &str,
    mut details: serde_json::Value,
) {
    if let Some(obj) = details.as_object_mut() {
        obj.insert("repository".into(), repo_key.into());
        obj.insert("server".into(), server.into());
        obj.insert("version".into(), version.into());
    }
    let resource_type = if artifact_id.is_some() {
        ResourceType::Artifact
    } else {
        ResourceType::Repository
    };
    let mut entry = AuditEntry::new(action, resource_type)
        .resource_name(format!("{server}@{version}"))
        .with_request_client_ip()
        .details(details);
    if let Some(id) = artifact_id {
        entry = entry.resource(id);
    }
    entry = match actor {
        Actor::User(id) => entry.user(id),
        Actor::System(name) => entry.system_actor(name),
    };
    tokio::spawn(audit_fire_and_forget(db.clone(), entry));
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_probes_cover_index_and_child() {
        let id = Uuid::new_v4();
        let [a, b] = pin_probes(id, "acme/mcp", "sha256:aa");
        assert_eq!(a["packages"][0]["resolved"]["digest"], "sha256:aa");
        assert_eq!(b["packages"][0]["resolved"]["gateDigest"], "sha256:aa");
        assert_eq!(a["packages"][0]["resolved"]["repositoryId"], id.to_string());
        assert_eq!(b["packages"][0]["resolved"]["name"], "acme/mcp");
    }
}
