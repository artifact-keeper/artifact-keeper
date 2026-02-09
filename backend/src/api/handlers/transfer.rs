//! Chunked transfer API handlers for swarm-based artifact distribution.

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

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
    Path(peer_id): Path<Uuid>,
    Json(body): Json<InitTransferBody>,
) -> Result<Json<TransferSessionResponse>> {
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
    Path((_peer_id, session_id, chunk_index)): Path<(Uuid, Uuid, i32)>,
    Json(body): Json<CompleteChunkBody>,
) -> Result<()> {
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
    Path((_peer_id, session_id, chunk_index)): Path<(Uuid, Uuid, i32)>,
    Json(body): Json<FailBody>,
) -> Result<()> {
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
    Path((_peer_id, session_id, chunk_index)): Path<(Uuid, Uuid, i32)>,
) -> Result<()> {
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
    Path((_peer_id, session_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
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
    Path((_peer_id, session_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<FailBody>,
) -> Result<()> {
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
