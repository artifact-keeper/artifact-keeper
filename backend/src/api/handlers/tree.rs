//! Tree browser handler.
//!
//! Provides a virtual folder tree derived from artifact paths within a repository.

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};

pub fn router() -> Router<SharedState> {
    Router::new().route("/", get(get_tree))
}

#[derive(Debug, Deserialize)]
pub struct TreeQuery {
    pub repository_key: Option<String>,
    pub path: Option<String>,
    pub include_metadata: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct TreeNodeResponse {
    pub id: String,
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_count: Option<i64>,
    pub has_children: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TreeResponse {
    pub nodes: Vec<TreeNodeResponse>,
}

/// Row returned from folder query.
struct FolderEntry {
    segment: String,
    is_file: bool,
    artifact_id: Option<Uuid>,
    size_bytes: Option<i64>,
    created_at: Option<String>,
    child_count: i64,
}

pub async fn get_tree(
    State(state): State<SharedState>,
    Query(params): Query<TreeQuery>,
) -> Result<Json<TreeResponse>> {
    let repo_key = match params.repository_key {
        Some(k) if !k.is_empty() => k,
        _ => {
            return Err(AppError::Validation(
                "repository_key is required".to_string(),
            ));
        }
    };

    // Verify repository exists
    let repo = sqlx::query!(
        "SELECT id FROM repositories WHERE key = $1",
        repo_key
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound(format!("Repository '{}' not found", repo_key)))?;

    let prefix = params.path.unwrap_or_default();
    let prefix_depth = if prefix.is_empty() {
        0
    } else {
        prefix.chars().filter(|c| *c == '/').count() + 1
    };

    // Query all artifact paths in this repository and derive tree structure.
    // We split each path, pick the segment at the current depth, and group.
    let rows = sqlx::query!(
        r#"
        SELECT
            a.id,
            a.path,
            a.size_bytes,
            a.created_at
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND ($2 = '' OR a.path LIKE $2 || '%')
        ORDER BY a.path
        "#,
        repo.id,
        if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix)
        }
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Group by next path segment at current depth
    let mut folders: BTreeMap<String, FolderEntry> = BTreeMap::new();

    for row in &rows {
        let parts: Vec<&str> = row.path.split('/').collect();
        if parts.len() <= prefix_depth {
            continue;
        }

        let segment = parts[prefix_depth].to_string();
        let is_file = parts.len() == prefix_depth + 1;

        let entry = folders.entry(segment.clone()).or_insert(FolderEntry {
            segment: segment.clone(),
            is_file,
            artifact_id: if is_file { Some(row.id) } else { None },
            size_bytes: if is_file { Some(row.size_bytes) } else { None },
            created_at: if is_file {
                Some(row.created_at.to_rfc3339())
            } else {
                None
            },
            child_count: 0,
        });

        if !is_file {
            entry.child_count += 1;
            // Folder always has children
            entry.is_file = false;
        }
    }

    let full_prefix = if prefix.is_empty() {
        repo_key.clone()
    } else {
        format!("{}/{}", repo_key, prefix)
    };

    let nodes: Vec<TreeNodeResponse> = folders
        .into_values()
        .map(|entry| {
            let node_path = format!("{}/{}", full_prefix, entry.segment);
            let node_id = if let Some(aid) = entry.artifact_id {
                aid.to_string()
            } else {
                // Deterministic ID for folders based on path
                format!("folder:{}", node_path)
            };

            TreeNodeResponse {
                id: node_id,
                name: entry.segment,
                path: node_path,
                node_type: if entry.is_file {
                    "file".to_string()
                } else {
                    "folder".to_string()
                },
                size_bytes: entry.size_bytes,
                children_count: if !entry.is_file {
                    Some(entry.child_count)
                } else {
                    None
                },
                has_children: !entry.is_file,
                repository_key: Some(repo_key.clone()),
                created_at: entry.created_at,
            }
        })
        .collect();

    Ok(Json(TreeResponse { nodes }))
}
