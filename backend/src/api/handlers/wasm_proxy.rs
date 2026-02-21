//! WASM plugin protocol proxy handler.
//!
//! Routes HTTP requests to WASM plugins that implement the request-handler
//! interface (v2 WIT). This allows plugins to serve native client protocols
//! like PEP 503 (pip) or repodata (dnf) directly from WASM.

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, Method, Response, StatusCode},
    routing::any,
    Router,
};

use crate::api::SharedState;
use crate::error::AppError;
use crate::services::repository_service::RepositoryService;
use crate::services::wasm_bindings::{WasmHttpRequest, WasmRepoContext};
use crate::services::wasm_runtime::WasmMetadata;

/// Create the WASM proxy router.
///
/// Mounts at `/ext` and handles `/:format_key/:repo_key/*path`.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:format_key/:repo_key", any(handle_wasm_request))
        .route("/:format_key/:repo_key/", any(handle_wasm_request))
        .route("/:format_key/:repo_key/*path", any(handle_wasm_request))
}

async fn handle_wasm_request(
    State(state): State<SharedState>,
    method: Method,
    headers: HeaderMap,
    Path(params): Path<Vec<(String, String)>>,
    body: Bytes,
) -> Result<Response<Body>, Response<Body>> {
    // Extract path params: format_key, repo_key, and optional path
    let format_key = params
        .iter()
        .find(|(k, _)| k == "format_key")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let repo_key = params
        .iter()
        .find(|(k, _)| k == "repo_key")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let sub_path = params
        .iter()
        .find(|(k, _)| k == "path")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    // Normalize path: ensure leading slash
    let request_path = if sub_path.is_empty() {
        "/".to_string()
    } else if sub_path.starts_with('/') {
        sub_path.to_string()
    } else {
        format!("/{}", sub_path)
    };

    // 1. Check plugin registry exists
    let registry = state
        .plugin_registry
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "WASM plugins not enabled"))?;

    // 2. Check plugin exists and supports handle_request
    if !registry.has_handle_request(format_key).await {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            &format!("No protocol handler for format '{}'", format_key),
        ));
    }

    // 3. Look up repo and verify format_key matches
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(repo_key).await.map_err(|_| {
        error_response(
            StatusCode::NOT_FOUND,
            &format!("Repository '{}' not found", repo_key),
        )
    })?;

    let repo_format_key = repo_service.get_format_key(repo.id).await.map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to look up format key",
        )
    })?;

    if repo_format_key.as_deref() != Some(format_key) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            &format!(
                "Repository '{}' uses format '{}', not '{}'",
                repo_key,
                repo_format_key.as_deref().unwrap_or("none"),
                format_key
            ),
        ));
    }

    // 4. Gather artifact metadata from DB
    let artifacts = fetch_repo_artifacts(&state, repo.id).await.map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to fetch artifacts: {}", e),
        )
    })?;

    // 5. Build request and context
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let scheme = if host.contains("localhost") || host.contains("127.0.0.1") {
        "http"
    } else {
        "https"
    };
    let base_url = format!("{}://{}/ext/{}/{}", scheme, host, format_key, repo_key);
    let download_base_url = format!(
        "{}://{}/api/v1/repositories/{}/download",
        scheme, host, repo_key
    );

    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect();

    let wasm_request = WasmHttpRequest {
        method: method.to_string(),
        path: request_path,
        query: String::new(), // TODO: extract from raw URI if needed
        headers: header_pairs,
        body: body.to_vec(),
    };

    let wasm_context = WasmRepoContext {
        repo_key: repo_key.to_string(),
        base_url,
        download_base_url,
    };

    // 6. Execute plugin
    let response = registry
        .execute_handle_request(format_key, &wasm_request, &wasm_context, &artifacts)
        .await
        .map_err(|e| {
            tracing::error!("WASM handle_request error: {}", e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Plugin error: {}", e),
            )
        })?;

    // 7. Convert WASM response to HTTP response
    let mut builder = Response::builder().status(response.status);
    for (key, value) in &response.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    builder
        .body(Body::from(response.body))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

/// Fetch all non-deleted artifacts for a repository as WasmMetadata.
async fn fetch_repo_artifacts(
    state: &SharedState,
    repo_id: uuid::Uuid,
) -> std::result::Result<Vec<WasmMetadata>, AppError> {
    #[derive(sqlx::FromRow)]
    struct ArtifactRow {
        path: String,
        version: Option<String>,
        content_type: String,
        size_bytes: i64,
        checksum_sha256: String,
    }

    let rows = sqlx::query_as::<_, ArtifactRow>(
        "SELECT path, version, content_type, size_bytes, checksum_sha256 \
         FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
    )
    .bind(repo_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(rows
        .into_iter()
        .map(|r| WasmMetadata {
            path: r.path,
            version: r.version,
            content_type: r.content_type,
            size_bytes: r.size_bytes as u64,
            checksum_sha256: Some(r.checksum_sha256),
        })
        .collect())
}

/// Build a JSON error response.
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let body = serde_json::json!({
        "code": status.canonical_reason().unwrap_or("ERROR"),
        "message": message,
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap_or_default()))
        .unwrap()
}
