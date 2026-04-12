//! Quarantine status API handler.
//!
//! Provides an endpoint to check the quarantine status of an artifact, and
//! admin endpoints to manually release or reject a quarantined artifact.

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::quarantine_service;

/// OpenAPI documentation for quarantine endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(get_quarantine_status, release_artifact, reject_artifact),
    components(schemas(QuarantineStatusResponse, QuarantineActionRequest)),
    tags(
        (name = "quarantine", description = "Artifact quarantine management")
    )
)]
pub struct QuarantineApiDoc;

/// Create quarantine routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/artifacts/:id/quarantine", get(get_quarantine_status))
        .route("/artifacts/:id/quarantine/release", post(release_artifact))
        .route("/artifacts/:id/quarantine/reject", post(reject_artifact))
}

/// Quarantine status response.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantineStatusResponse {
    /// The artifact ID.
    pub artifact_id: Uuid,
    /// Current quarantine status: 'quarantined', 'released', 'rejected',
    /// 'clean', 'flagged', 'unscanned', or null (no status set).
    pub quarantine_status: String,
    /// When the quarantine period expires. Null if not quarantined.
    pub quarantine_until: Option<DateTime<Utc>>,
    /// Whether the artifact is currently blocked from download.
    pub is_blocked: bool,
    /// Human-readable reason for the current state.
    pub reason: String,
}

/// Request body for manual quarantine actions.
#[derive(Debug, Deserialize, ToSchema)]
pub struct QuarantineActionRequest {
    /// Optional reason for the manual action (for audit trail).
    #[serde(default)]
    pub reason: Option<String>,
}

/// Get the quarantine status of an artifact.
#[utoipa::path(
    get,
    path = "/artifacts/{id}/quarantine",
    context_path = "/api/v1/quarantine",
    tag = "quarantine",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "Quarantine status", body = QuarantineStatusResponse),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn get_quarantine_status(
    State(state): State<SharedState>,
    Extension(_auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<QuarantineStatusResponse>> {
    let info = quarantine_service::get_quarantine_info(&state.db, id)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    let (status, until) = info;
    let now = Utc::now();
    let status_str = status.as_deref().unwrap_or("none");
    let decision = quarantine_service::is_quarantine_blocked(Some(status_str), until, now);

    let (is_blocked, reason) = match decision {
        quarantine_service::QuarantineDecision::Blocked { expires_at } => (
            true,
            format!(
                "Artifact is under quarantine review until {}",
                expires_at.to_rfc3339()
            ),
        ),
        quarantine_service::QuarantineDecision::Rejected => {
            (true, "Artifact was rejected by security scans".to_string())
        }
        quarantine_service::QuarantineDecision::Expired => (
            false,
            "Quarantine period has expired, artifact will be auto-released on next download"
                .to_string(),
        ),
        quarantine_service::QuarantineDecision::Allowed => {
            (false, "Artifact is available for download".to_string())
        }
    };

    Ok(Json(QuarantineStatusResponse {
        artifact_id: id,
        quarantine_status: status_str.to_string(),
        quarantine_until: until,
        is_blocked,
        reason,
    }))
}

/// Manually release an artifact from quarantine. Requires admin privileges.
#[utoipa::path(
    post,
    path = "/artifacts/{id}/quarantine/release",
    context_path = "/api/v1/quarantine",
    tag = "quarantine",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    request_body(content = QuarantineActionRequest, description = "Release details"),
    responses(
        (status = 200, description = "Artifact released from quarantine", body = QuarantineStatusResponse),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn release_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(_body): Json<QuarantineActionRequest>,
) -> Result<Json<QuarantineStatusResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;

    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Admin privileges required to release quarantined artifacts".to_string(),
        ));
    }

    // Verify artifact exists and check current status
    let info = quarantine_service::get_quarantine_info(&state.db, id)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    let (current_status, _) = &info;
    let current = current_status.as_deref().unwrap_or("none");

    if current != "quarantined" && current != "rejected" {
        return Err(AppError::Validation(format!(
            "Artifact is not in a quarantined or rejected state (current: {})",
            current
        )));
    }

    quarantine_service::release_quarantine(&state.db, id)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    tracing::info!(
        artifact_id = %id,
        admin = %auth.username,
        "Artifact manually released from quarantine"
    );

    state
        .event_bus
        .emit("quarantine.released", id, Some(auth.username.clone()));

    Ok(Json(QuarantineStatusResponse {
        artifact_id: id,
        quarantine_status: "released".to_string(),
        quarantine_until: None,
        is_blocked: false,
        reason: "Artifact manually released by administrator".to_string(),
    }))
}

/// Manually reject a quarantined artifact. Requires admin privileges.
#[utoipa::path(
    post,
    path = "/artifacts/{id}/quarantine/reject",
    context_path = "/api/v1/quarantine",
    tag = "quarantine",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    request_body(content = QuarantineActionRequest, description = "Rejection details"),
    responses(
        (status = 200, description = "Artifact rejected", body = QuarantineStatusResponse),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn reject_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(_body): Json<QuarantineActionRequest>,
) -> Result<Json<QuarantineStatusResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;

    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Admin privileges required to reject quarantined artifacts".to_string(),
        ));
    }

    // Verify artifact exists
    quarantine_service::get_quarantine_info(&state.db, id)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    quarantine_service::reject_quarantine(&state.db, id)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    tracing::info!(
        artifact_id = %id,
        admin = %auth.username,
        "Artifact manually rejected"
    );

    state
        .event_bus
        .emit("quarantine.rejected", id, Some(auth.username.clone()));

    Ok(Json(QuarantineStatusResponse {
        artifact_id: id,
        quarantine_status: "rejected".to_string(),
        quarantine_until: None,
        is_blocked: true,
        reason: "Artifact manually rejected by administrator".to_string(),
    }))
}
