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
/// `mcp_version_tombstones` (migration 322) is written by trigger on every
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
/// `MCP_BUNDLE_SIGNATURE_REJECTED`. `details` gains `repository`, `server`
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
