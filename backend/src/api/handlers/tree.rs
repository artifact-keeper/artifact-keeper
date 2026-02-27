//! Tree browser handler.
//!
//! Provides a virtual folder tree derived from artifact paths within a repository.

use axum::{
    extract::{Extension, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};

pub fn router() -> Router<SharedState> {
    Router::new().route("/", get(get_tree))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct TreeQuery {
    /// Repository key to browse
    pub repository_key: Option<String>,
    /// Path prefix to browse within the repository
    pub path: Option<String>,
    /// Whether to include metadata in the response
    pub include_metadata: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/tree",
    tag = "repositories",
    params(TreeQuery),
    responses(
        (status = 200, description = "Virtual folder tree for the repository", body = TreeResponse),
        (status = 400, description = "Validation error (e.g. missing repository_key)", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_tree(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
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

    // Verify repository exists and check visibility
    let repo_row: Option<(Uuid, bool)> =
        sqlx::query_as("SELECT id, is_public FROM repositories WHERE key = $1")
            .bind(&repo_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let (repo_id, is_public) = repo_row
        .ok_or_else(|| AppError::NotFound(format!("Repository '{}' not found", repo_key)))?;

    // Private repos require authentication
    if !is_public && auth.is_none() {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            repo_key
        )));
    }

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
        repo_id,
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
            let node_id = entry
                .artifact_id
                .map(|aid| aid.to_string())
                .unwrap_or_else(|| format!("folder:{}", node_path));

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

#[derive(OpenApi)]
#[openapi(paths(get_tree), components(schemas(TreeResponse, TreeNodeResponse,)))]
pub struct TreeApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // ── TreeQuery deserialization tests ──────────────────────────────

    #[test]
    fn test_tree_query_empty() {
        let json = r#"{}"#;
        let q: TreeQuery = serde_json::from_str(json).unwrap();
        assert!(q.repository_key.is_none());
        assert!(q.path.is_none());
        assert!(q.include_metadata.is_none());
    }

    #[test]
    fn test_tree_query_with_repo_key() {
        let json = r#"{"repository_key": "maven-releases"}"#;
        let q: TreeQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.repository_key, Some("maven-releases".to_string()));
    }

    #[test]
    fn test_tree_query_with_path() {
        let json = r#"{"repository_key": "npm", "path": "lodash/4.0.0"}"#;
        let q: TreeQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.path, Some("lodash/4.0.0".to_string()));
    }

    #[test]
    fn test_tree_query_include_metadata() {
        let json = r#"{"repository_key": "x", "include_metadata": true}"#;
        let q: TreeQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.include_metadata, Some(true));
    }

    // ── Prefix depth calculation tests ──────────────────────────────

    #[test]
    fn test_prefix_depth_empty() {
        let prefix = "";
        let depth = if prefix.is_empty() {
            0
        } else {
            prefix.chars().filter(|c| *c == '/').count() + 1
        };
        assert_eq!(depth, 0);
    }

    #[test]
    fn test_prefix_depth_one_level() {
        let prefix = "com";
        let depth = if prefix.is_empty() {
            0
        } else {
            prefix.chars().filter(|c| *c == '/').count() + 1
        };
        assert_eq!(depth, 1);
    }

    #[test]
    fn test_prefix_depth_two_levels() {
        let prefix = "com/example";
        let depth = if prefix.is_empty() {
            0
        } else {
            prefix.chars().filter(|c| *c == '/').count() + 1
        };
        assert_eq!(depth, 2);
    }

    #[test]
    fn test_prefix_depth_deep_path() {
        let prefix = "com/example/lib/1.0";
        let depth = if prefix.is_empty() {
            0
        } else {
            prefix.chars().filter(|c| *c == '/').count() + 1
        };
        assert_eq!(depth, 4);
    }

    // ── FolderEntry and tree grouping logic tests ───────────────────

    #[test]
    fn test_folder_entry_construction() {
        let entry = FolderEntry {
            segment: "src".to_string(),
            is_file: false,
            artifact_id: None,
            size_bytes: None,
            created_at: None,
            child_count: 3,
        };
        assert_eq!(entry.segment, "src");
        assert!(!entry.is_file);
        assert!(entry.artifact_id.is_none());
        assert_eq!(entry.child_count, 3);
    }

    #[test]
    fn test_folder_entry_file() {
        let id = Uuid::new_v4();
        let entry = FolderEntry {
            segment: "pom.xml".to_string(),
            is_file: true,
            artifact_id: Some(id),
            size_bytes: Some(1024),
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            child_count: 0,
        };
        assert!(entry.is_file);
        assert_eq!(entry.artifact_id, Some(id));
        assert_eq!(entry.size_bytes, Some(1024));
    }

    // ── Path splitting / segment extraction tests ───────────────────

    #[test]
    fn test_path_segment_extraction_root() {
        let path = "com/example/lib/1.0/lib-1.0.jar";
        let parts: Vec<&str> = path.split('/').collect();
        let prefix_depth = 0;
        assert!(parts.len() > prefix_depth);
        assert_eq!(parts[prefix_depth], "com");
        let is_file = parts.len() == prefix_depth + 1;
        assert!(!is_file);
    }

    #[test]
    fn test_path_segment_extraction_leaf() {
        let path = "lib-1.0.jar";
        let parts: Vec<&str> = path.split('/').collect();
        let prefix_depth = 0;
        let is_file = parts.len() == prefix_depth + 1;
        assert!(is_file);
    }

    #[test]
    fn test_path_segment_extraction_nested() {
        let path = "com/example/lib/1.0/lib-1.0.jar";
        let parts: Vec<&str> = path.split('/').collect();
        let prefix_depth = 2;
        assert_eq!(parts[prefix_depth], "lib");
    }

    // ── TreeNodeResponse serialization tests ────────────────────────

    #[test]
    fn test_tree_node_response_file() {
        let node = TreeNodeResponse {
            id: Uuid::new_v4().to_string(),
            name: "lib-1.0.jar".to_string(),
            path: "maven-releases/com/example/lib-1.0.jar".to_string(),
            node_type: "file".to_string(),
            size_bytes: Some(102400),
            children_count: None,
            has_children: false,
            repository_key: Some("maven-releases".to_string()),
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_value(&node).unwrap();
        assert_eq!(json["type"], "file");
        assert_eq!(json["name"], "lib-1.0.jar");
        assert_eq!(json["size_bytes"], 102400);
        assert_eq!(json["has_children"], false);
        // children_count should be absent (skip_serializing_if)
        assert!(json.get("children_count").is_none() || json["children_count"].is_null());
    }

    #[test]
    fn test_tree_node_response_folder() {
        let node = TreeNodeResponse {
            id: "folder:maven-releases/com".to_string(),
            name: "com".to_string(),
            path: "maven-releases/com".to_string(),
            node_type: "folder".to_string(),
            size_bytes: None,
            children_count: Some(5),
            has_children: true,
            repository_key: Some("maven-releases".to_string()),
            created_at: None,
        };
        let json = serde_json::to_value(&node).unwrap();
        assert_eq!(json["type"], "folder");
        assert_eq!(json["has_children"], true);
        assert_eq!(json["children_count"], 5);
        // size_bytes should be absent (skip_serializing_if)
        assert!(json.get("size_bytes").is_none() || json["size_bytes"].is_null());
    }

    #[test]
    fn test_tree_node_response_type_field_rename() {
        let node = TreeNodeResponse {
            id: "x".to_string(),
            name: "n".to_string(),
            path: "p".to_string(),
            node_type: "file".to_string(),
            size_bytes: None,
            children_count: None,
            has_children: false,
            repository_key: None,
            created_at: None,
        };
        let json = serde_json::to_value(&node).unwrap();
        // The field should be serialized as "type", not "node_type"
        assert!(json.get("type").is_some());
        assert!(json.get("node_type").is_none());
    }

    // ── TreeResponse serialization tests ────────────────────────────

    #[test]
    fn test_tree_response_empty() {
        let resp = TreeResponse { nodes: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["nodes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_tree_response_multiple_nodes() {
        let resp = TreeResponse {
            nodes: vec![
                TreeNodeResponse {
                    id: "1".to_string(),
                    name: "src".to_string(),
                    path: "repo/src".to_string(),
                    node_type: "folder".to_string(),
                    size_bytes: None,
                    children_count: Some(2),
                    has_children: true,
                    repository_key: Some("repo".to_string()),
                    created_at: None,
                },
                TreeNodeResponse {
                    id: "2".to_string(),
                    name: "README.md".to_string(),
                    path: "repo/README.md".to_string(),
                    node_type: "file".to_string(),
                    size_bytes: Some(256),
                    children_count: None,
                    has_children: false,
                    repository_key: Some("repo".to_string()),
                    created_at: Some("2024-01-01T00:00:00Z".to_string()),
                },
            ],
        };
        let json = serde_json::to_value(&resp).unwrap();
        let nodes = json["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["type"], "folder");
        assert_eq!(nodes[1]["type"], "file");
    }

    // ── Full prefix construction tests ──────────────────────────────

    #[test]
    fn test_full_prefix_empty_path() {
        let prefix = "";
        let repo_key = "maven-releases".to_string();
        let full_prefix = if prefix.is_empty() {
            repo_key.clone()
        } else {
            format!("{}/{}", repo_key, prefix)
        };
        assert_eq!(full_prefix, "maven-releases");
    }

    #[test]
    fn test_full_prefix_with_path() {
        let prefix = "com/example";
        let repo_key = "maven-releases".to_string();
        let full_prefix = if prefix.is_empty() {
            repo_key.clone()
        } else {
            format!("{}/{}", repo_key, prefix)
        };
        assert_eq!(full_prefix, "maven-releases/com/example");
    }

    // ── BTreeMap grouping logic simulation tests ────────────────────

    #[test]
    fn test_btree_grouping_single_file() {
        let paths = vec!["README.md"];
        let prefix_depth: usize = 0;
        let mut folders: BTreeMap<String, FolderEntry> = BTreeMap::new();

        for path in paths {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() <= prefix_depth {
                continue;
            }
            let segment = parts[prefix_depth].to_string();
            let is_file = parts.len() == prefix_depth + 1;
            let entry = folders.entry(segment.clone()).or_insert(FolderEntry {
                segment: segment.clone(),
                is_file,
                artifact_id: None,
                size_bytes: None,
                created_at: None,
                child_count: 0,
            });
            if !is_file {
                entry.child_count += 1;
                entry.is_file = false;
            }
        }

        assert_eq!(folders.len(), 1);
        assert!(folders.get("README.md").unwrap().is_file);
    }

    #[test]
    fn test_btree_grouping_folder_with_children() {
        let paths = vec!["src/main.rs", "src/lib.rs", "src/util/mod.rs"];
        let prefix_depth: usize = 0;
        let mut folders: BTreeMap<String, FolderEntry> = BTreeMap::new();

        for path in paths {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() <= prefix_depth {
                continue;
            }
            let segment = parts[prefix_depth].to_string();
            let is_file = parts.len() == prefix_depth + 1;
            let entry = folders.entry(segment.clone()).or_insert(FolderEntry {
                segment: segment.clone(),
                is_file,
                artifact_id: None,
                size_bytes: None,
                created_at: None,
                child_count: 0,
            });
            if !is_file {
                entry.child_count += 1;
                entry.is_file = false;
            }
        }

        assert_eq!(folders.len(), 1);
        let src = folders.get("src").unwrap();
        assert!(!src.is_file);
        assert_eq!(src.child_count, 3);
    }
}
