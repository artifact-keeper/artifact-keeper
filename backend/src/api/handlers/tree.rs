//! Tree browser handler.
//!
//! Provides a virtual folder tree derived from artifact paths within a repository.

use axum::{
    extract::{Extension, Query, State},
    http::header,
    response::IntoResponse,
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
    Router::new()
        .route("/", get(get_tree))
        .route("/content", get(get_content))
}

/// Pure authorization decision for a tree/content read of a single repository.
///
/// The tree-browser routes are nested under `optional_auth_middleware` only,
/// so they never pass through `repo_visibility_middleware` and must enforce
/// per-repo authorization themselves (#1803). This mirrors the visibility +
/// token-scope + role-grant logic of `repo_visibility_middleware` /
/// `RepositoryService::user_can_access_repo`:
///
/// * admins always pass;
/// * a public repo is readable by anyone **whose token scope permits it**
///   (`token_allows`), including anonymous callers;
/// * a private repo requires an authenticated caller that holds a role
///   assignment on the repo (`has_role_grant`) **and** whose token scope
///   permits it.
///
/// `token_allows` already encodes `AuthExtension::can_access_repo` (an
/// unrestricted token / non-API-token / anonymous caller passes `true`).
fn tree_access_allowed(
    is_admin: bool,
    is_public: bool,
    is_authed: bool,
    token_allows: bool,
    has_role_grant: bool,
) -> bool {
    if is_admin {
        return true;
    }
    if !token_allows {
        return false;
    }
    if is_public {
        return true;
    }
    // Private repo: must be authenticated AND hold a role grant on it.
    is_authed && has_role_grant
}

/// Resolve and enforce read authorization for a tree/content request against a
/// single repository, returning the existence-hiding 404 on denial so we never
/// leak whether a private repo exists (#1803).
async fn authorize_tree_read(
    state: &SharedState,
    auth: &Option<AuthExtension>,
    repo_id: Uuid,
    is_public: bool,
    repo_key: &str,
) -> Result<()> {
    let not_found = || AppError::NotFound(format!("Repository '{}' not found", repo_key));

    let is_admin = auth.as_ref().map(|a| a.is_admin).unwrap_or(false);
    let is_authed = auth.is_some();
    // Token repo-scope (`allowed_repo_ids`): unrestricted / anonymous => true.
    let token_allows = auth
        .as_ref()
        .map(|a| a.can_access_repo(repo_id))
        .unwrap_or(true);

    // Only consult role grants when they can actually change the outcome
    // (private repo, non-admin, authenticated, token-permitted). This avoids
    // an unnecessary DB round-trip for public reads.
    let has_role_grant = if !is_admin && !is_public && is_authed && token_allows {
        match auth.as_ref() {
            Some(a) => state
                .create_repository_service()
                .user_can_access_repo(repo_id, a.user_id)
                .await
                .unwrap_or(false),
            None => false,
        }
    } else {
        false
    };

    if tree_access_allowed(is_admin, is_public, is_authed, token_allows, has_role_grant) {
        Ok(())
    } else {
        Err(not_found())
    }
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

#[derive(Debug, Deserialize, IntoParams)]
pub struct ContentQuery {
    /// Repository key containing the artifact
    pub repository_key: String,
    /// Full artifact path within the repository
    pub path: String,
    /// Optional maximum number of bytes to return (truncates the response)
    pub max_bytes: Option<i64>,
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

    // Per-repo read authorization (#1803). These routes bypass
    // repo_visibility_middleware, so enforce admin / public+token-scope /
    // role-grant+token-scope here; deny with an existence-hiding 404.
    authorize_tree_read(&state, &auth, repo_id, is_public, &repo_key).await?;

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

#[utoipa::path(
    get,
    path = "/content",
    context_path = "/api/v1/tree",
    tag = "repositories",
    params(ContentQuery),
    responses(
        (status = 200, description = "Artifact file content", content_type = "application/octet-stream"),
        (status = 400, description = "Validation error", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Artifact not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_content(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(params): Query<ContentQuery>,
) -> Result<impl IntoResponse> {
    // Verify repository exists and check visibility
    let repo_row: Option<(Uuid, bool, String, String)> = sqlx::query_as(
        "SELECT id, is_public, storage_backend, storage_path FROM repositories WHERE key = $1",
    )
    .bind(&params.repository_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let (repo_id, is_public, storage_backend, storage_path) = repo_row.ok_or_else(|| {
        AppError::NotFound(format!("Repository '{}' not found", params.repository_key))
    })?;

    // Per-repo read authorization (#1803). These routes bypass
    // repo_visibility_middleware, so enforce admin / public+token-scope /
    // role-grant+token-scope here; deny with an existence-hiding 404.
    authorize_tree_read(&state, &auth, repo_id, is_public, &params.repository_key).await?;

    // Look up the artifact by repository_id + path
    #[derive(sqlx::FromRow)]
    struct ArtifactRow {
        id: uuid::Uuid,
        size_bytes: i64,
        content_type: String,
        storage_key: String,
    }

    let artifact = sqlx::query_as::<_, ArtifactRow>(
        r#"
        SELECT id, size_bytes, content_type, storage_key
        FROM artifacts
        WHERE repository_id = $1 AND path = $2 AND is_deleted = false
        "#,
    )
    .bind(repo_id)
    .bind(&params.path)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound(format!("Artifact '{}' not found", params.path)))?;

    // Fetch content from storage
    let location = crate::storage::StorageLocation {
        backend: storage_backend,
        path: storage_path,
    };
    let storage = state.storage_for_repo(&location)?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id).await?;

    let content = storage.get(&artifact.storage_key).await?;

    // Truncate to max_bytes if specified
    let body = match params.max_bytes {
        Some(max) if max >= 0 && (max as usize) < content.len() => content.slice(..max as usize),
        _ => content,
    };

    // Detect content type: use the stored value, fall back to mime_guess
    let content_type = if artifact.content_type.is_empty()
        || artifact.content_type == "application/octet-stream"
    {
        mime_guess::from_path(&params.path)
            .first_or_octet_stream()
            .to_string()
    } else {
        artifact.content_type
    };

    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::HeaderName::from_static("x-content-size"),
                artifact.size_bytes.to_string(),
            ),
            (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
        ],
        body,
    ))
}

#[derive(OpenApi)]
#[openapi(
    paths(get_tree, get_content),
    components(schemas(TreeResponse, TreeNodeResponse,))
)]
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

    // ── ContentQuery deserialization tests ────────────────────────────

    #[test]
    fn test_content_query_required_fields() {
        let json = r#"{"repository_key": "maven-releases", "path": "com/example/lib-1.0.jar"}"#;
        let q: ContentQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.repository_key, "maven-releases");
        assert_eq!(q.path, "com/example/lib-1.0.jar");
        assert!(q.max_bytes.is_none());
    }

    #[test]
    fn test_content_query_with_max_bytes() {
        let json = r#"{"repository_key": "npm", "path": "lodash/package.json", "max_bytes": 4096}"#;
        let q: ContentQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.repository_key, "npm");
        assert_eq!(q.path, "lodash/package.json");
        assert_eq!(q.max_bytes, Some(4096));
    }

    #[test]
    fn test_content_query_max_bytes_zero() {
        let json = r#"{"repository_key": "x", "path": "y", "max_bytes": 0}"#;
        let q: ContentQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.max_bytes, Some(0));
    }

    // ── tree_access_allowed authorization decision (#1803) ───────────────

    #[test]
    fn test_access_admin_always_allowed_even_private_out_of_scope() {
        // Admin bypasses visibility, token scope, and role grants.
        assert!(tree_access_allowed(
            /* is_admin */ true, /* is_public */ false, /* is_authed */ true,
            /* token_allows */ false, /* has_role_grant */ false,
        ));
    }

    #[test]
    fn test_access_public_anonymous_allowed() {
        assert!(tree_access_allowed(false, true, false, true, false));
    }

    #[test]
    fn test_access_public_out_of_token_scope_denied() {
        // Public repo but the token's allowed_repo_ids does not include it.
        assert!(!tree_access_allowed(false, true, true, false, true));
    }

    #[test]
    fn test_access_private_with_grant_and_scope_allowed() {
        assert!(tree_access_allowed(false, false, true, true, true));
    }

    #[test]
    fn test_access_private_zero_grant_denied() {
        // The exact #1803 exploit shape: non-admin, authed, token scoped to a
        // public repo (token_allows happens to be true), zero role grants on
        // the private target -> must be denied.
        assert!(!tree_access_allowed(false, false, true, true, false));
    }

    #[test]
    fn test_access_private_anonymous_denied() {
        assert!(!tree_access_allowed(false, false, false, true, false));
    }

    // ── DB-backed handler authorization (#1803) ──────────────────────────
    //
    // No-ops when no test DB is configured (`try_pool` returns None).

    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;

    /// A non-admin caller with NO role assignment on a private repo must get a
    /// 404 (existence-hiding) from GET /tree — not the private tree.
    #[tokio::test]
    async fn test_get_tree_private_zero_grant_nonadmin_denied() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        // create_repo defaults to is_public = false (private).
        let (repo_id, repo_key, _dir) = tdh::create_repo(&pool, "local", "pypi").await;

        let auth = tdh::make_auth(user_id, &username);
        let state = tdh::build_state(pool.clone(), "/tmp");
        let app = tdh::router_with_auth(router(), state, auth);

        let uri = format!("/?repository_key={}", repo_key);
        let (status, _body) = tdh::send(app, tdh::get(uri)).await;

        // Clean up before asserting so a failure does not leak rows.
        tdh::cleanup(&pool, repo_id, user_id).await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "zero-grant non-admin must be denied (404) on a private repo tree"
        );
    }

    /// A non-admin caller WITH a role grant on the private repo is authorized
    /// and reaches the handler (200 + empty node list for an empty repo).
    #[tokio::test]
    async fn test_get_tree_private_with_grant_nonadmin_allowed() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, repo_key, _dir) = tdh::create_repo(&pool, "local", "pypi").await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;

        let auth = tdh::make_auth(user_id, &username);
        let state = tdh::build_state(pool.clone(), "/tmp");
        let app = tdh::router_with_auth(router(), state, auth);

        let uri = format!("/?repository_key={}", repo_key);
        let (status, _body) = tdh::send(app, tdh::get(uri)).await;

        tdh::cleanup(&pool, repo_id, user_id).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "non-admin with a role grant must be allowed to browse the private tree"
        );
    }

    /// A token scoped to a different repo (allowed_repo_ids excludes the
    /// target) must be denied even though the caller holds a role grant.
    #[tokio::test]
    async fn test_get_tree_private_token_out_of_scope_denied() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, repo_key, _dir) = tdh::create_repo(&pool, "local", "pypi").await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;

        // Token scoped to some OTHER repo id only.
        let mut auth = tdh::make_auth(user_id, &username);
        auth.is_api_token = true;
        auth.allowed_repo_ids = Some(vec![Uuid::new_v4()]);
        let state = tdh::build_state(pool.clone(), "/tmp");
        let app = tdh::router_with_auth(router(), state, auth);

        let uri = format!("/?repository_key={}", repo_key);
        let (status, _body) = tdh::send(app, tdh::get(uri)).await;

        tdh::cleanup(&pool, repo_id, user_id).await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "token whose scope excludes the repo must be denied even with a role grant"
        );
    }
}
