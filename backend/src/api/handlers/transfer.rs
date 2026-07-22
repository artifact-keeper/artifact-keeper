//! Chunked transfer API handlers for swarm-based artifact distribution.

use axum::{
    extract::{Extension, Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::transfer_service::{InitTransferRequest, TransferService};

/// Create transfer routes (nested under /api/v1/peers/:id/transfer)
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/init", post(init_transfer))
        .route("/:session_id/chunks", get(get_chunk_manifest))
        .route("/:session_id", get(get_session))
        .route(
            "/:session_id/chunk/:chunk_index/complete",
            post(complete_chunk),
        )
        .route("/:session_id/chunk/:chunk_index/fail", post(fail_chunk))
        .route("/:session_id/chunk/:chunk_index/retry", post(retry_chunk))
        .route("/:session_id/complete", post(complete_session))
        .route("/:session_id/fail", post(fail_session))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct InitTransferBody {
    pub artifact_id: Uuid,
    pub chunk_size: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TransferSessionResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub requesting_peer_id: Uuid,
    pub total_size: i64,
    pub chunk_size: i32,
    pub total_chunks: i32,
    pub completed_chunks: i32,
    pub checksum_algo: String,
    pub artifact_checksum: String,
    pub status: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChunkManifestResponse {
    pub session_id: Uuid,
    pub chunks: Vec<ChunkEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChunkEntry {
    pub chunk_index: i32,
    pub byte_offset: i64,
    pub byte_length: i32,
    pub checksum: String,
    pub status: String,
    pub source_peer_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CompleteChunkBody {
    pub checksum: String,
    pub source_peer_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct FailBody {
    pub error: String,
}

/// POST /api/v1/peers/:id/transfer/init
#[utoipa::path(
    post,
    path = "/{id}/transfer/init",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
    ),
    request_body = InitTransferBody,
    responses(
        (status = 200, description = "Transfer session initialized", body = TransferSessionResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn init_transfer(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(peer_id): Path<Uuid>,
    Json(body): Json<InitTransferBody>,
) -> Result<Json<TransferSessionResponse>> {
    auth.require_admin()?;
    let service = TransferService::new(state.db.clone());

    let session = service
        .init_transfer(InitTransferRequest {
            artifact_id: body.artifact_id,
            requesting_peer_id: peer_id,
            chunk_size: body.chunk_size,
        })
        .await?;

    Ok(Json(TransferSessionResponse {
        id: session.id,
        artifact_id: session.artifact_id,
        requesting_peer_id: session.requesting_peer_id,
        total_size: session.total_size,
        chunk_size: session.chunk_size,
        total_chunks: session.total_chunks,
        completed_chunks: session.completed_chunks,
        checksum_algo: session.checksum_algo,
        artifact_checksum: session.artifact_checksum,
        status: format!("{:?}", session.status).to_lowercase(),
    }))
}

/// GET /api/v1/peers/:id/transfer/:session_id/chunks
#[utoipa::path(
    get,
    path = "/{id}/transfer/{session_id}/chunks",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("session_id" = Uuid, Path, description = "Transfer session ID"),
    ),
    responses(
        (status = 200, description = "Chunk manifest for the transfer session", body = ChunkManifestResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_chunk_manifest(
    State(state): State<SharedState>,
    Path((_peer_id, session_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ChunkManifestResponse>> {
    let service = TransferService::new(state.db.clone());
    let chunks = service.get_chunk_manifest(session_id).await?;

    Ok(Json(ChunkManifestResponse {
        session_id,
        chunks: chunks
            .into_iter()
            .map(|c| ChunkEntry {
                chunk_index: c.chunk_index,
                byte_offset: c.byte_offset,
                byte_length: c.byte_length,
                checksum: c.checksum,
                status: c.status,
                source_peer_id: c.source_peer_id,
            })
            .collect(),
    }))
}

/// GET /api/v1/peers/:id/transfer/:session_id
#[utoipa::path(
    get,
    path = "/{id}/transfer/{session_id}",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("session_id" = Uuid, Path, description = "Transfer session ID"),
    ),
    responses(
        (status = 200, description = "Transfer session details", body = TransferSessionResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_session(
    State(state): State<SharedState>,
    Path((_peer_id, session_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<TransferSessionResponse>> {
    let service = TransferService::new(state.db.clone());
    let session = service.get_session(session_id).await?;

    Ok(Json(TransferSessionResponse {
        id: session.id,
        artifact_id: session.artifact_id,
        requesting_peer_id: session.requesting_peer_id,
        total_size: session.total_size,
        chunk_size: session.chunk_size,
        total_chunks: session.total_chunks,
        completed_chunks: session.completed_chunks,
        checksum_algo: session.checksum_algo,
        artifact_checksum: session.artifact_checksum,
        status: format!("{:?}", session.status).to_lowercase(),
    }))
}

/// POST /api/v1/peers/:id/transfer/:session_id/chunk/:chunk_index/complete
#[utoipa::path(
    post,
    path = "/{id}/transfer/{session_id}/chunk/{chunk_index}/complete",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("session_id" = Uuid, Path, description = "Transfer session ID"),
        ("chunk_index" = i32, Path, description = "Chunk index"),
    ),
    request_body = CompleteChunkBody,
    responses(
        (status = 200, description = "Chunk marked as complete"),
    ),
    security(("bearer_auth" = []))
)]
async fn complete_chunk(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((_peer_id, session_id, chunk_index)): Path<(Uuid, Uuid, i32)>,
    Json(body): Json<CompleteChunkBody>,
) -> Result<()> {
    auth.require_admin()?;
    let service = TransferService::new(state.db.clone());
    service
        .complete_chunk(session_id, chunk_index, &body.checksum, body.source_peer_id)
        .await
}

/// POST /api/v1/peers/:id/transfer/:session_id/chunk/:chunk_index/fail
#[utoipa::path(
    post,
    path = "/{id}/transfer/{session_id}/chunk/{chunk_index}/fail",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("session_id" = Uuid, Path, description = "Transfer session ID"),
        ("chunk_index" = i32, Path, description = "Chunk index"),
    ),
    request_body = FailBody,
    responses(
        (status = 200, description = "Chunk marked as failed"),
    ),
    security(("bearer_auth" = []))
)]
async fn fail_chunk(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((_peer_id, session_id, chunk_index)): Path<(Uuid, Uuid, i32)>,
    Json(body): Json<FailBody>,
) -> Result<()> {
    auth.require_admin()?;
    let service = TransferService::new(state.db.clone());
    service
        .fail_chunk(session_id, chunk_index, &body.error)
        .await
}

/// POST /api/v1/peers/:id/transfer/:session_id/chunk/:chunk_index/retry
#[utoipa::path(
    post,
    path = "/{id}/transfer/{session_id}/chunk/{chunk_index}/retry",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("session_id" = Uuid, Path, description = "Transfer session ID"),
        ("chunk_index" = i32, Path, description = "Chunk index"),
    ),
    responses(
        (status = 200, description = "Chunk queued for retry"),
    ),
    security(("bearer_auth" = []))
)]
async fn retry_chunk(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((_peer_id, session_id, chunk_index)): Path<(Uuid, Uuid, i32)>,
) -> Result<()> {
    auth.require_admin()?;
    let service = TransferService::new(state.db.clone());
    service.retry_chunk(session_id, chunk_index).await
}

/// POST /api/v1/peers/:id/transfer/:session_id/complete
#[utoipa::path(
    post,
    path = "/{id}/transfer/{session_id}/complete",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("session_id" = Uuid, Path, description = "Transfer session ID"),
    ),
    responses(
        (status = 200, description = "Transfer session marked as complete"),
    ),
    security(("bearer_auth" = []))
)]
async fn complete_session(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((_peer_id, session_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    auth.require_admin()?;
    let service = TransferService::new(state.db.clone());
    service.complete_session(session_id).await
}

/// POST /api/v1/peers/:id/transfer/:session_id/fail
#[utoipa::path(
    post,
    path = "/{id}/transfer/{session_id}/fail",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("session_id" = Uuid, Path, description = "Transfer session ID"),
    ),
    request_body = FailBody,
    responses(
        (status = 200, description = "Transfer session marked as failed"),
    ),
    security(("bearer_auth" = []))
)]
async fn fail_session(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((_peer_id, session_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<FailBody>,
) -> Result<()> {
    auth.require_admin()?;
    let service = TransferService::new(state.db.clone());
    service.fail_session(session_id, &body.error).await
}

#[derive(OpenApi)]
#[openapi(
    paths(
        init_transfer,
        get_chunk_manifest,
        get_session,
        complete_chunk,
        fail_chunk,
        retry_chunk,
        complete_session,
        fail_session,
    ),
    components(schemas(
        InitTransferBody,
        TransferSessionResponse,
        ChunkManifestResponse,
        ChunkEntry,
        CompleteChunkBody,
        FailBody,
    ))
)]
pub struct TransferApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    // -----------------------------------------------------------------------
    // InitTransferBody deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_init_transfer_body_minimal() {
        let artifact_id = Uuid::new_v4();
        let json = serde_json::json!({
            "artifact_id": artifact_id
        });
        let body: InitTransferBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.artifact_id, artifact_id);
        assert!(body.chunk_size.is_none());
    }

    #[test]
    fn test_init_transfer_body_with_chunk_size() {
        let artifact_id = Uuid::new_v4();
        let json = serde_json::json!({
            "artifact_id": artifact_id,
            "chunk_size": 65536
        });
        let body: InitTransferBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.artifact_id, artifact_id);
        assert_eq!(body.chunk_size, Some(65536));
    }

    #[test]
    fn test_init_transfer_body_missing_artifact_id_fails() {
        let json = serde_json::json!({
            "chunk_size": 1024
        });
        let result: std::result::Result<InitTransferBody, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_init_transfer_body_invalid_artifact_id_fails() {
        let json = serde_json::json!({
            "artifact_id": "not-a-uuid"
        });
        let result: std::result::Result<InitTransferBody, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // TransferSessionResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_transfer_session_response_serialize() {
        let id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let peer_id = Uuid::new_v4();
        let resp = TransferSessionResponse {
            id,
            artifact_id,
            requesting_peer_id: peer_id,
            total_size: 1_000_000,
            chunk_size: 65536,
            total_chunks: 16,
            completed_chunks: 5,
            checksum_algo: "sha256".to_string(),
            artifact_checksum: "abcdef1234567890".to_string(),
            status: "pending".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], id.to_string());
        assert_eq!(json["artifact_id"], artifact_id.to_string());
        assert_eq!(json["requesting_peer_id"], peer_id.to_string());
        assert_eq!(json["total_size"], 1_000_000);
        assert_eq!(json["chunk_size"], 65536);
        assert_eq!(json["total_chunks"], 16);
        assert_eq!(json["completed_chunks"], 5);
        assert_eq!(json["checksum_algo"], "sha256");
        assert_eq!(json["artifact_checksum"], "abcdef1234567890");
        assert_eq!(json["status"], "pending");
    }

    #[test]
    fn test_transfer_session_response_all_fields_present() {
        let resp = TransferSessionResponse {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            requesting_peer_id: Uuid::new_v4(),
            total_size: 0,
            chunk_size: 0,
            total_chunks: 0,
            completed_chunks: 0,
            checksum_algo: String::new(),
            artifact_checksum: String::new(),
            status: String::new(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("artifact_id"));
        assert!(obj.contains_key("requesting_peer_id"));
        assert!(obj.contains_key("total_size"));
        assert!(obj.contains_key("chunk_size"));
        assert!(obj.contains_key("total_chunks"));
        assert!(obj.contains_key("completed_chunks"));
        assert!(obj.contains_key("checksum_algo"));
        assert!(obj.contains_key("artifact_checksum"));
        assert!(obj.contains_key("status"));
        assert_eq!(obj.len(), 10);
    }

    // -----------------------------------------------------------------------
    // ChunkEntry serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_chunk_entry_serialize_with_source_peer() {
        let peer_id = Uuid::new_v4();
        let entry = ChunkEntry {
            chunk_index: 3,
            byte_offset: 196608,
            byte_length: 65536,
            checksum: "deadbeef".to_string(),
            status: "completed".to_string(),
            source_peer_id: Some(peer_id),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["chunk_index"], 3);
        assert_eq!(json["byte_offset"], 196608);
        assert_eq!(json["byte_length"], 65536);
        assert_eq!(json["checksum"], "deadbeef");
        assert_eq!(json["status"], "completed");
        assert_eq!(json["source_peer_id"], peer_id.to_string());
    }

    #[test]
    fn test_chunk_entry_serialize_without_source_peer() {
        let entry = ChunkEntry {
            chunk_index: 0,
            byte_offset: 0,
            byte_length: 1024,
            checksum: "aabbccdd".to_string(),
            status: "pending".to_string(),
            source_peer_id: None,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["chunk_index"], 0);
        assert!(json["source_peer_id"].is_null());
    }

    #[test]
    fn test_chunk_entry_zero_offset() {
        let entry = ChunkEntry {
            chunk_index: 0,
            byte_offset: 0,
            byte_length: 65536,
            checksum: "first-chunk".to_string(),
            status: "pending".to_string(),
            source_peer_id: None,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["byte_offset"], 0);
        assert_eq!(json["chunk_index"], 0);
    }

    // -----------------------------------------------------------------------
    // ChunkManifestResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_chunk_manifest_response_serialize_empty() {
        let session_id = Uuid::new_v4();
        let resp = ChunkManifestResponse {
            session_id,
            chunks: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["session_id"], session_id.to_string());
        assert!(json["chunks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_chunk_manifest_response_serialize_multiple_chunks() {
        let session_id = Uuid::new_v4();
        let chunks = vec![
            ChunkEntry {
                chunk_index: 0,
                byte_offset: 0,
                byte_length: 1000,
                checksum: "c0".to_string(),
                status: "completed".to_string(),
                source_peer_id: None,
            },
            ChunkEntry {
                chunk_index: 1,
                byte_offset: 1000,
                byte_length: 1000,
                checksum: "c1".to_string(),
                status: "pending".to_string(),
                source_peer_id: None,
            },
        ];
        let resp = ChunkManifestResponse { session_id, chunks };
        let json = serde_json::to_value(&resp).unwrap();
        let arr = json["chunks"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["chunk_index"], 0);
        assert_eq!(arr[1]["chunk_index"], 1);
    }

    // -----------------------------------------------------------------------
    // CompleteChunkBody deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_complete_chunk_body_minimal() {
        let json = serde_json::json!({
            "checksum": "sha256:abcdef"
        });
        let body: CompleteChunkBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.checksum, "sha256:abcdef");
        assert!(body.source_peer_id.is_none());
    }

    #[test]
    fn test_complete_chunk_body_with_peer() {
        let peer_id = Uuid::new_v4();
        let json = serde_json::json!({
            "checksum": "sha256:123456",
            "source_peer_id": peer_id
        });
        let body: CompleteChunkBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.checksum, "sha256:123456");
        assert_eq!(body.source_peer_id, Some(peer_id));
    }

    #[test]
    fn test_complete_chunk_body_missing_checksum_fails() {
        let json = serde_json::json!({
            "source_peer_id": Uuid::new_v4()
        });
        let result: std::result::Result<CompleteChunkBody, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // FailBody deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_fail_body_deserialize() {
        let json = serde_json::json!({
            "error": "connection timeout"
        });
        let body: FailBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.error, "connection timeout");
    }

    #[test]
    fn test_fail_body_missing_error_fails() {
        let json = serde_json::json!({});
        let result: std::result::Result<FailBody, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_fail_body_empty_error() {
        let json = serde_json::json!({"error": ""});
        let body: FailBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.error, "");
    }

    // -----------------------------------------------------------------------
    // Status formatting (simulating handler pattern)
    // -----------------------------------------------------------------------

    #[test]
    fn test_status_format_debug_lowercase() {
        // The handler uses: format!("{:?}", session.status).to_lowercase()
        // Simulate with a simple enum-like string
        #[derive(Debug)]
        enum TransferStatus {
            Pending,
            InProgress,
            Completed,
            Failed,
        }
        assert_eq!(
            format!("{:?}", TransferStatus::Pending).to_lowercase(),
            "pending"
        );
        assert_eq!(
            format!("{:?}", TransferStatus::InProgress).to_lowercase(),
            "inprogress"
        );
        assert_eq!(
            format!("{:?}", TransferStatus::Completed).to_lowercase(),
            "completed"
        );
        assert_eq!(
            format!("{:?}", TransferStatus::Failed).to_lowercase(),
            "failed"
        );
    }

    // -----------------------------------------------------------------------
    // Authorization tests for the transfer data-plane routes (GHSA-f7qf).
    //
    // init_transfer (and its sibling chunk/session mutators) drive federation
    // transfer sessions and are admin-only, mirroring `peers::register_peer`. A
    // non-admin authenticated caller must be rejected with 403 FORBIDDEN before
    // any session is created; an admin passes the gate. Before the guard a
    // non-admin was let straight through to the service layer.
    //
    // Runtime-skips when no `DATABASE_URL` is set (NOT `#[ignore]`).
    // -----------------------------------------------------------------------
    mod authz {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::middleware::auth::AuthExtension;
        use axum::body::Bytes;
        use axum::http::StatusCode;
        use axum::Router;
        use uuid::Uuid;

        fn admin() -> AuthExtension {
            let mut a = tdh::make_auth(Uuid::new_v4(), "fed.admin");
            a.is_admin = true;
            a
        }

        fn non_admin() -> AuthExtension {
            tdh::make_auth(Uuid::new_v4(), "low.priv")
        }

        fn transfer_app(state: crate::api::SharedState, auth: AuthExtension) -> Router {
            // Mirror the production mount point: transfer::router() lives under
            // /:id/transfer.
            let router = Router::new().nest("/:id/transfer", super::super::router());
            tdh::router_with_auth_ext(router, state, auth)
        }

        fn init_req(peer: Uuid) -> axum::http::Request<axum::body::Body> {
            tdh::post(
                format!("/{}/transfer/init", peer),
                "application/json",
                Bytes::from(format!("{{\"artifact_id\":\"{}\"}}", Uuid::new_v4()).into_bytes()),
            )
        }

        #[tokio::test]
        async fn non_admin_cannot_init_transfer() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let state = tdh::build_state(pool.clone(), "/tmp/ph-transfer-authz");
            let peer = tdh::register_test_peer(&pool, "authz-init", "deny").await;

            let (status, _) = tdh::send(transfer_app(state, non_admin()), init_req(peer)).await;

            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a non-admin must be denied (403) on init_transfer, before any \
                 transfer session is created"
            );

            let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
                .bind(peer)
                .execute(&pool)
                .await;
        }

        #[tokio::test]
        async fn admin_passes_init_transfer_gate() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let state = tdh::build_state(pool.clone(), "/tmp/ph-transfer-authz");
            let peer = tdh::register_test_peer(&pool, "authz-init", "allow").await;

            // An admin clears the authorization gate and reaches the service
            // layer; with a random artifact id the service returns 404
            // "Artifact not found" — crucially NOT a 403. This proves the guard
            // does not over-block legitimate admin callers.
            let (status, _) = tdh::send(transfer_app(state, admin()), init_req(peer)).await;

            assert_ne!(
                status,
                StatusCode::FORBIDDEN,
                "an admin must clear the authorization gate on init_transfer"
            );
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "admin reaches the service layer; unknown artifact -> 404"
            );

            let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
                .bind(peer)
                .execute(&pool)
                .await;
        }
    }
}
