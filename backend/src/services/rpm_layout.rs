//! Hosted RPM subtree layout (#4216). Persistence is guarded by migration 234.

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use serde::Deserialize;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::upload_service::{validate_artifact_path, MAX_ARTIFACT_PATH_LEN};

pub const MAX_REPODATA_DEPTH: u32 = ((MAX_ARTIFACT_PATH_LEN - 1) / 2) as u32;
pub const CONFIG_KEY: &str = "repodata_depth";
pub const UNSUPPORTED: &str = "Repodata depth requires a local RPM repository without curation, publications, or virtual membership";
pub const POPULATED: &str = "Cannot change repodata_depth while the repository contains artifacts (including deleted artifacts)";
pub const INVALID_PATH: &str = "Artifact path must be canonical, outside reserved repodata/@N paths, and have at least repodata_depth parent directories";
pub const UNSUPPORTED_STORAGE: &str = "Depth-enabled RPM repositories require content-addressed storage; re-upload this artifact using its complete relative path";

pub fn deserialize_depth<'de, D>(deserializer: D) -> std::result::Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u32::deserialize(deserializer)?;
    validate_depth(value).map_err(serde::de::Error::custom)?;
    Ok(Some(value))
}

pub fn validate_depth(depth: u32) -> Result<()> {
    if depth > MAX_REPODATA_DEPTH {
        return Err(AppError::Validation(format!(
            "repodata_depth must be an integer between 0 and {MAX_REPODATA_DEPTH}"
        )));
    }
    Ok(())
}

pub fn validate_path(path: &str, depth: u32) -> Result<()> {
    if depth == 0 {
        return Ok(());
    }
    validate_artifact_path(path).map_err(|_| AppError::Validation(INVALID_PATH.into()))?;
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() <= depth as usize
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "repodata"
                || part.trim() != *part
                || part.chars().any(char::is_control)
        })
        || parts[0]
            .strip_prefix('@')
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(AppError::Validation(INVALID_PATH.into()));
    }
    Ok(())
}

pub fn validate_root(root: &str, depth: u32) -> Result<()> {
    if depth == 0 && root.is_empty() {
        return Ok(());
    }
    validate_path(&format!("{root}/x"), depth)?;
    if root.split('/').count() != depth as usize {
        return Err(AppError::NotFound(
            "No repodata at this directory depth".into(),
        ));
    }
    Ok(())
}

/// Encode each segment, not the separators. Literal '%' must be encoded too.
pub fn location_href(path: &str) -> String {
    path.split('/')
        .map(|part| urlencoding::encode(part).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

pub async fn depth(db: &PgPool, repo_id: Uuid) -> Result<u32> {
    let depth: i32 = sqlx::query_scalar("SELECT ak_rpm_repodata_depth($1)")
        .bind(repo_id)
        .fetch_one(db)
        .await?;
    u32::try_from(depth).map_err(|_| AppError::Config("Invalid stored repodata_depth".into()))
}

pub async fn validate_upload(db: &PgPool, repo_id: Uuid, path: &str) -> Result<u32> {
    let depth = depth(db, repo_id).await?;
    validate_path(path, depth)?;
    Ok(depth)
}

pub async fn reject_unsupported(db: &PgPool, repo_id: Uuid) -> Result<()> {
    if depth(db, repo_id).await? > 0 {
        return Err(AppError::UnprocessableEntity(UNSUPPORTED.into()));
    }
    Ok(())
}

/// Fail before approval/storage side effects; the persistence trigger rechecks
/// inside the writer's transaction to close configuration races.
pub async fn validate_copy(
    db: &PgPool,
    repo_id: Uuid,
    path: &str,
    checksum: &str,
    storage_key: &str,
) -> Result<()> {
    if validate_upload(db, repo_id, path).await? > 0 {
        if checksum.len() != 64
            || !checksum
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(AppError::UnprocessableEntity(UNSUPPORTED_STORAGE.into()));
        }
        let expected =
            crate::services::artifact_service::ArtifactService::storage_key_from_checksum(checksum);
        if expected != storage_key {
            return Err(AppError::UnprocessableEntity(UNSUPPORTED_STORAGE.into()));
        }
    }
    Ok(())
}

/// Exclusive config lock uses the same namespace as the shared persistence
/// guards. Take it before UPDATE repositories; never hold a usage-ledger lock.
pub async fn set_depth(conn: &mut PgConnection, repo_id: Uuid, depth: u32) -> Result<()> {
    validate_depth(depth)?;
    sqlx::query(
        "INSERT INTO repository_config(repository_id, key, value) VALUES ($1, $2, $3) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(repo_id)
    .bind(CONFIG_KEY)
    .bind(depth.to_string())
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn settings(db: &PgPool, ids: &[Uuid]) -> Result<HashMap<Uuid, (u32, bool)>> {
    let rows: Vec<(Uuid, i32, bool)> = sqlx::query_as(
        "SELECT id, ak_rpm_repodata_depth(id), \
            ak_rpm_depth_eligible(id) AND NOT EXISTS \
                (SELECT 1 FROM artifacts WHERE repository_id = r.id) \
         FROM repositories r WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|(id, depth, editable)| {
            u32::try_from(depth)
                .map(|depth| (id, (depth, editable)))
                .map_err(|_| AppError::Config("Invalid stored repodata_depth".into()))
        })
        .collect()
}

/// Only fixed, non-sensitive trigger messages are exposed. Most existing
/// mutation paths stringify SQLx errors; retain their standard error envelope.
pub fn database_error(message: &str) -> Option<AppError> {
    if message.contains("AK_RPM_DEPTH_PATH") {
        Some(AppError::Validation(INVALID_PATH.into()))
    } else if message.contains("AK_RPM_DEPTH_RANGE") {
        Some(AppError::Validation(
            "repodata_depth must be an integer between 0 and 1023".into(),
        ))
    } else if message.contains("AK_RPM_DEPTH_POPULATED") {
        Some(AppError::Conflict(POPULATED.into()))
    } else if message.contains("AK_RPM_DEPTH_BUSY") {
        Some(AppError::Conflict(
            "Repository layout is being changed; retry the operation".into(),
        ))
    } else if message.contains("AK_RPM_DEPTH_UNSUPPORTED") {
        Some(AppError::UnprocessableEntity(UNSUPPORTED.into()))
    } else if message.contains("AK_RPM_DEPTH_STORAGE") {
        Some(AppError::UnprocessableEntity(UNSUPPORTED_STORAGE.into()))
    } else {
        None
    }
}
