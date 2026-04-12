//! Quarantine period management handlers.
//!
//! Provides endpoints to query and manage artifact quarantine status:
//! - GET  /quarantine/:artifact_id     - get quarantine status
//! - POST /quarantine/:artifact_id/release - admin: release from quarantine
//! - POST /quarantine/:artifact_id/reject  - admin: reject quarantined artifact

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
use crate::error::{AppError, Result};
use crate::services::quarantine_service;

/// Create quarantine routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:artifact_id", get(get_quarantine_status))
        .route("/:artifact_id/release", post(release_artifact))
        .route("/:artifact_id/reject", post(reject_artifact))
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantineStatusResponse {
    pub artifact_id: Uuid,
    pub quarantine_status: Option<String>,
    pub quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
    pub is_blocked: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RejectRequest {
    /// Optional reason for rejection.
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantineActionResponse {
    pub artifact_id: Uuid,
    pub new_status: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Get quarantine status for an artifact
#[utoipa::path(
    get,
    path = "/{artifact_id}",
    context_path = "/api/v1/quarantine",
    tag = "quarantine",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Quarantine status", body = QuarantineStatusResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn get_quarantine_status(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Json<QuarantineStatusResponse>> {
    let _auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;

    let (status, until) = quarantine_service::get_status(&state.db, artifact_id).await?;

    let now = chrono::Utc::now();
    let is_blocked =
        quarantine_service::check_download_allowed(status.as_deref(), until, now).is_err();

    Ok(Json(QuarantineStatusResponse {
        artifact_id,
        quarantine_status: status,
        quarantine_until: until,
        is_blocked,
    }))
}

/// Release an artifact from quarantine (admin only)
#[utoipa::path(
    post,
    path = "/{artifact_id}/release",
    context_path = "/api/v1/quarantine",
    tag = "quarantine",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifact released", body = QuarantineActionResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn release_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Json<QuarantineActionResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    auth.require_admin()?;

    // Verify artifact exists
    quarantine_service::get_status(&state.db, artifact_id).await?;

    quarantine_service::transition(
        &state.db,
        artifact_id,
        quarantine_service::QuarantineState::Released,
    )
    .await?;

    tracing::info!(
        artifact_id = %artifact_id,
        admin = %auth.username,
        "Artifact released from quarantine by admin"
    );

    state.event_bus.emit(
        "artifact.quarantine.released",
        artifact_id,
        Some(auth.username),
    );

    Ok(Json(QuarantineActionResponse {
        artifact_id,
        new_status: "released".to_string(),
        message: "Artifact released from quarantine".to_string(),
    }))
}

/// Reject a quarantined artifact (admin only)
#[utoipa::path(
    post,
    path = "/{artifact_id}/reject",
    context_path = "/api/v1/quarantine",
    tag = "quarantine",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    request_body = RejectRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifact rejected", body = QuarantineActionResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn reject_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(artifact_id): Path<Uuid>,
    Json(req): Json<RejectRequest>,
) -> Result<Json<QuarantineActionResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    auth.require_admin()?;

    // Verify artifact exists
    quarantine_service::get_status(&state.db, artifact_id).await?;

    quarantine_service::transition(
        &state.db,
        artifact_id,
        quarantine_service::QuarantineState::Rejected,
    )
    .await?;

    let reason = req.reason.as_deref().unwrap_or("No reason provided");
    tracing::info!(
        artifact_id = %artifact_id,
        admin = %auth.username,
        reason = %reason,
        "Artifact rejected by admin"
    );

    state.event_bus.emit(
        "artifact.quarantine.rejected",
        artifact_id,
        Some(auth.username),
    );

    Ok(Json(QuarantineActionResponse {
        artifact_id,
        new_status: "rejected".to_string(),
        message: format!("Artifact rejected: {}", reason),
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_quarantine_status,
        release_artifact,
        reject_artifact,
    ),
    components(schemas(
        QuarantineStatusResponse,
        QuarantineActionResponse,
        RejectRequest,
    )),
    tags(
        (name = "quarantine", description = "Artifact quarantine period management"),
    )
)]
pub struct QuarantineApiDoc;
