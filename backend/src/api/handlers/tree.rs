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

/// The `permissions` action every route on this router performs. Both are
/// `GET`s (`/` and `/content`), which `middleware::auth::action_for_method`
/// maps to `read`; naming it keeps the public-read exemption below visibly
/// read-only rather than an unconditional `is_public` short-circuit.
const TREE_READ_ACTION: &str = "read";

/// Pure authorization decision for a tree/content read of a single repository.
///
/// The tree-browser routes are nested under `optional_auth_middleware` only,
/// so they never pass through `repo_visibility_middleware` and must enforce
/// per-repo authorization themselves (#1803). This mirrors the visibility +
/// token-scope + role-grant logic of `repo_visibility_middleware` /
/// `RepositoryService::user_can_access_repo`:
///
/// * admins always pass;
/// * a public repo is readable by anyone, including anonymous callers;
/// * a private repo requires an authenticated caller that holds a role
///   assignment on the repo (`has_role_grant`) **and** whose token scope
///   permits it.
///
/// `token_allows` already encodes `AuthExtension::can_access_repo` (an
/// unrestricted token / non-API-token / anonymous caller passes `true`).
///
/// The public arm runs BEFORE the token-scope check (#3704). Both routes on
/// this router are `GET`s, so every request through here is a read, and
/// `public_read_satisfies_acl` is the same baseline `require_visible` and the
/// OCI `/v2` read gate apply (#2329): an anonymous caller passes `token_allows`
/// vacuously and is served a public repository, so testing the scope ceiling
/// first made a repository-scoped credential strictly worse off than no
/// credential at all — 404 where anonymous got 200. Private repositories never
/// take the shortcut, so the scope ceiling still confines them.
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
    if crate::api::middleware::auth::public_read_satisfies_acl(is_public, TREE_READ_ACTION) {
        return true;
    }
    if !token_allows {
        return false;
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
                .user_can_access_repo(
                    repo_id,
                    a.user_id,
                    // CONTENT (#3331): `/tree/content` serves artifact bytes, so
                    // the grant must carry `read`. Fails closed on error, as
                    // before.
                    crate::services::repository_service::RepoAccess::READ,
                )
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
          AND ($2 = '' OR a.path LIKE $2 || '%' ESCAPE '\')
        ORDER BY a.path
        "#,
        repo_id,
        // #3500: the requested folder is REQUEST input that becomes part of a
        // `LIKE` pattern, so it must be escaped before it is bound. Unescaped,
        // a `%` or `_` in the path acted as a wildcard and the listing pulled
        // in sibling folders, and a backslash — Postgres's DEFAULT `LIKE`
        // escape character — quoted the character after it, so browsing
        // `a\b` returned `ab/`'s contents and hid `a\b`'s own.
        //
        // Escaped in Rust with `ESCAPE '\'`, rather than the `ESCAPE ''` the
        // Maven rollup delete guards use (#3492/#3493): there the pattern is
        // derived in SQL and `escape_like_literal` cannot reach it, and
        // over-matching is the SAFE direction for a `NOT EXISTS` delete guard.
        // Here the pattern is a bind parameter, and on a read path
        // over-matching IS the defect — a folder listing that includes another
        // folder's entries. Same rule the shared helper documents, applied to
        // the operand shape this site actually has.
        if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", crate::api::handlers::escape_like_literal(&prefix))
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

    /// Flipped by #3704 (was `test_access_public_out_of_token_scope_denied`,
    /// which pinned the inverted behaviour): a public repository is a read
    /// baseline the token-scope ceiling must not take away, because the
    /// anonymous caller — who passes `token_allows` vacuously — is served the
    /// same repository. `has_role_grant` is `false` here so the allowance can
    /// only come from the public arm.
    #[test]
    fn test_access_public_out_of_token_scope_allowed() {
        // Public repo, and the token's allowed_repo_ids does NOT include it.
        assert!(tree_access_allowed(false, true, true, false, false));
    }

    /// The other half of #3704: the exemption is scoped to PUBLIC repositories.
    /// A private repo outside the token's scope stays denied even when the
    /// caller holds a role grant on it — the ceiling is still a ceiling.
    #[test]
    fn test_access_private_out_of_token_scope_denied() {
        assert!(!tree_access_allowed(false, false, true, false, true));
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
    use bytes::Bytes;

    // ── #3500: the folder prefix is a LIKE pattern operand ────────────────
    //
    // `GET /tree?path=<folder>` built `a.path LIKE $2 || '%'` from the
    // requested folder with no `ESCAPE` clause, so the pattern stopped
    // describing the folder it was derived from whenever the folder contained
    // a `LIKE` metacharacter.

    /// Insert an `artifacts` row at `path`. The tree handler reads only the
    /// `artifacts` table, so no storage object is needed.
    async fn seed_tree_path(pool: &sqlx::PgPool, repo_id: Uuid, path: &str) {
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) VALUES ($1, $2, $3, 1, \
             '0000000000000000000000000000000000000000000000000000000000000000', \
             'application/octet-stream', $2)",
        )
        .bind(repo_id)
        .bind(path)
        .bind(path.rsplit('/').next().unwrap_or(path))
        .execute(pool)
        .await
        .expect("seed artifact row");
    }

    /// The segments `GET /tree?path=<folder>` reports, sorted.
    async fn tree_segments(state: &SharedState, repo_key: &str, folder: &str) -> Vec<String> {
        let app = tdh::router_anon(router(), state.clone());
        let uri = format!(
            "/?repository_key={}&path={}",
            repo_key,
            urlencoding::encode(folder)
        );
        let (status, body) = tdh::send(app, tdh::get(uri)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET /tree?path={folder} must be 200"
        );
        let v: serde_json::Value = serde_json::from_slice(&body).expect("tree JSON");
        let mut out: Vec<String> = v["nodes"]
            .as_array()
            .expect("nodes array")
            .iter()
            .map(|n| n["name"].as_str().expect("name").to_string())
            .collect();
        out.sort();
        out
    }

    /// #3500. Browsing a folder whose name contains a `LIKE` metacharacter
    /// must list that folder's own contents and nothing else.
    ///
    /// Both directions of the defect are asserted, because the unescaped
    /// pattern failed in both:
    ///
    /// * `\` is Postgres's DEFAULT `LIKE` escape character, so the pattern
    ///   `a\b/%` was read as `ab/%` — it MISSED the requested folder's own
    ///   entry and MATCHED the unrelated `ab/` folder instead.
    /// * `%` and `_` acted as wildcards, so `a%b/%` matched `axxxb/`.
    ///
    /// A plain folder in the same fixture is the positive control: escaping
    /// must not stop ordinary browsing from working.
    #[tokio::test]
    async fn test_get_tree_folder_with_like_metacharacters_lists_only_its_own_entries_3500() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, _dir) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::publish_repo(&pool, repo_id).await;

        for path in [
            r"a\b/real.jar",    // the requested folder's own entry
            "ab/collapsed.jar", // what the unescaped pattern matched instead
            "a%b/pct.jar",      // the requested folder's own entry
            "axxxb/wide.jar",   // what the `%` wildcard matched instead
            "a_b/underscore.jar",
            "aXb/single.jar", // what the `_` wildcard matched instead
            "plain/ok.jar",   // positive control
        ] {
            seed_tree_path(&pool, repo_id, path).await;
        }

        let state = tdh::build_state(pool.clone(), "/tmp");
        let backslash = tree_segments(&state, &repo_key, r"a\b").await;
        let percent = tree_segments(&state, &repo_key, "a%b").await;
        let underscore = tree_segments(&state, &repo_key, "a_b").await;
        let plain = tree_segments(&state, &repo_key, "plain").await;

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;

        assert_eq!(
            backslash,
            vec!["real.jar".to_string()],
            r"browsing `a\b` must list only its own entry: a backslash is \
              Postgres's default LIKE escape character, so the unescaped \
              pattern `a\b/%` was read as `ab/%` — it hid `a\b/real.jar` and \
              returned `ab/collapsed.jar` in its place"
        );
        assert_eq!(
            percent,
            vec!["pct.jar".to_string()],
            "browsing `a%b` must list only its own entry; unescaped, the `%` \
             is a wildcard and `axxxb/`'s contents appear in the folder view"
        );
        assert_eq!(
            underscore,
            vec!["underscore.jar".to_string()],
            "browsing `a_b` must list only its own entry; unescaped, the `_` \
             matches any single character and `aXb/`'s contents appear"
        );
        assert_eq!(
            plain,
            vec!["ok.jar".to_string()],
            "positive control: an ordinary folder must still browse normally, \
             so a fix that escaped its way into matching nothing fails here"
        );
    }

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
        auth.allowed_repo_ids =
            crate::models::access_scope::AccessScope::Restricted(vec![Uuid::new_v4()]);
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

    /// Verified-bug regression for #3704 (tree browser), the same shape #3703
    /// fixed in `repo_visibility_middleware` for the native format routes.
    ///
    /// `tree_access_allowed` tested the token repository-scope ceiling
    /// (`token_allows`) BEFORE the `is_public` arm. An anonymous caller passes
    /// `token_allows` vacuously (`can_access_repo` is unreachable with no
    /// `AuthExtension`), so it was served a public repository's tree, while the
    /// same request carrying a repository-scoped API token got the
    /// existence-hiding 404 — a credential granting strictly less access than
    /// none, on exactly the repositories that are readable by everyone.
    /// Reproduced live on `main`:
    ///
    ///   GET /tree?repository_key={public-B}  no credential           -> 200
    ///   GET /tree?repository_key={public-B}  token scoped to repo A  -> 404
    ///
    /// Both routes on this router are `GET`s, so there is no write case to pin
    /// here; the read-only half of the exemption is pinned by
    /// `test_access_private_out_of_token_scope_denied` above, and the private
    /// repository below is the router-level half of the same thing.
    ///
    /// The negative cases are deliberately NOT vacuous: the caller holds a real
    /// role grant on the private repository C, so the scope ceiling is the only
    /// thing that can refuse it. Remove the ceiling and C answers 200.
    ///
    /// DB-backed: no-ops when `DATABASE_URL` is unset, and `AK_TESTS_REQUIRE_DB=1`
    /// turns an unreachable database into a hard failure rather than a silent skip.
    #[tokio::test]
    async fn test_3704_public_repo_tree_is_not_refused_to_an_out_of_scope_token() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        // A: the token's own repository (private, granted) — positive control.
        // B: a PUBLIC repository outside the scope — the subject.
        // C: a PRIVATE repository outside the scope, granted, so only the
        //    scope ceiling can refuse it.
        let (repo_a, key_a, dir_a) = tdh::create_repo(&pool, "local", "generic").await;
        let (repo_b, key_b, dir_b) = tdh::create_repo(&pool, "local", "generic").await;
        let (repo_c, key_c, dir_c) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::publish_repo(&pool, repo_b).await;
        for repo in [repo_a, repo_b, repo_c] {
            tdh::grant_repo_access(&pool, repo, user_id).await;
        }

        let state = tdh::build_state(pool.clone(), dir_b.to_str().unwrap());
        let repo_b_info = tdh::make_repo_info(repo_b, &key_b, &dir_b, "local", None);
        let content = Bytes::from_static(b"public-tree-content-3704");
        tdh::seed_artifact(
            &state,
            &pool,
            &repo_b_info,
            "pkg/file.txt",
            "pkg/file.txt",
            "file.txt",
            "1.0.0",
            "text/plain",
            content.clone(),
            user_id,
        )
        .await;
        for repo in [repo_a, repo_c] {
            seed_tree_path(&pool, repo, "pkg/file.txt").await;
        }

        // Exactly what `optional_auth_middleware` injects for a repository-scoped
        // API token: `AccessScope::Restricted([A])`, which is what
        // `validate_api_token` builds from the `api_token_repositories` rows.
        let mut scoped = tdh::make_auth(user_id, &username);
        scoped.is_api_token = true;
        scoped.allowed_repo_ids =
            crate::models::access_scope::AccessScope::Restricted(vec![repo_a]);

        let probe = |auth: Option<AuthExtension>, uri: String| {
            let state = state.clone();
            async move {
                let app = match auth {
                    Some(a) => tdh::router_with_auth(router(), state, a),
                    None => tdh::router_anon(router(), state),
                };
                let (status, body) = tdh::send(app, tdh::get(uri)).await;
                (status, String::from_utf8_lossy(&body).into_owned())
            }
        };
        let tree_uri = |key: &str| format!("/?repository_key={}", key);
        let content_uri = |key: &str| format!("/content?repository_key={}&path=pkg/file.txt", key);

        let public_anon = probe(None, tree_uri(&key_b)).await;
        let public_scoped = probe(Some(scoped.clone()), tree_uri(&key_b)).await;
        let content_anon = probe(None, content_uri(&key_b)).await;
        let content_scoped = probe(Some(scoped.clone()), content_uri(&key_b)).await;
        let private_anon = probe(None, tree_uri(&key_c)).await;
        let private_scoped = probe(Some(scoped.clone()), tree_uri(&key_c)).await;
        let in_scope = probe(Some(scoped.clone()), tree_uri(&key_a)).await;

        for repo in [repo_a, repo_b, repo_c] {
            tdh::cleanup(&pool, repo, user_id).await;
        }
        for dir in [&dir_a, &dir_b, &dir_c] {
            let _ = std::fs::remove_dir_all(dir);
        }

        assert_eq!(
            in_scope.0,
            StatusCode::OK,
            "POSITIVE CONTROL: the token must browse the repository it IS scoped \
             to, or every assertion below is vacuous"
        );
        assert_eq!(
            public_anon.0,
            StatusCode::OK,
            "POSITIVE CONTROL / unchanged: an anonymous caller browses a public \
             repository's tree"
        );

        // The bug.
        assert_eq!(
            public_scoped, public_anon,
            "#3704: browsing a PUBLIC repository's tree with a token scoped to \
             another repository must answer exactly what NO credential answers \
             -- same status, same body. Before the fix `tree_access_allowed` \
             tested `token_allows` before `is_public`, so this was 404 while the \
             anonymous request was 200"
        );
        assert_eq!(
            content_scoped, content_anon,
            "#3704: /tree/content serves the artifact BYTES, so it must match the \
             anonymous answer too -- a fix applied to the listing alone would \
             leave the download half inverted"
        );
        assert_eq!(
            content_anon.1, "public-tree-content-3704",
            "POSITIVE CONTROL: the byte-parity assertion above is only meaningful \
             if the anonymous read actually served the seeded content"
        );

        // The security half: the exemption is PUBLIC-read only.
        assert_eq!(
            private_scoped,
            (
                StatusCode::NOT_FOUND,
                format!(
                    "{{\"code\":\"NOT_FOUND\",\"message\":\"Repository '{}' not found\"}}",
                    key_c
                )
            ),
            "#3704 must not widen private repositories: a PRIVATE repository \
             outside the token's scope never takes the public bypass, so the \
             scope ceiling still refuses it with the existence-hiding 404. The \
             caller HOLDS a role grant on C, so this assertion is not vacuous -- \
             drop the ceiling and it answers 200"
        );
        assert_eq!(
            private_anon.0,
            StatusCode::NOT_FOUND,
            "unchanged: an anonymous caller still cannot browse a private tree"
        );
    }
}
