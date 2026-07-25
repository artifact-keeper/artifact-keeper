//! Quarantine period management handlers.
//!
//! Provides endpoints to query and manage artifact quarantine status:
//! - GET  /quarantine/:artifact_id            - get quarantine status
//! - POST /quarantine/:artifact_id/quarantine - admin: quarantine now
//! - POST /quarantine/:artifact_id/release    - admin: release from quarantine
//! - POST /quarantine/:artifact_id/reject     - admin: reject quarantined artifact

use axum::{
    body::Bytes,
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
        .route("/:artifact_id/quarantine", post(quarantine_artifact))
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
    /// Why the artifact is held, when one was recorded by a scan policy or an
    /// admin. This is the only surface that discloses the reason: blocked
    /// downloads return a generic message because they are reachable
    /// anonymously on public repositories (#2912).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_reason: Option<String>,
    pub is_blocked: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct QuarantineNowRequest {
    /// Reason shown to developers whose downloads are blocked.
    pub reason: Option<String>,
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
    let auth_ext =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;

    // Fetch quarantine status along with the artifact's repository to check visibility
    let row = quarantine_service::get_status_with_repo(&state.db, artifact_id).await?;

    // Check that the user has access to the artifact's repository.
    // For private repos, unauthenticated or unauthorized users get 404.
    let repo_service =
        crate::services::repository_service::RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_id(row.repository_id).await?;
    if !repo.is_public && !auth_ext.can_access_repo(row.repository_id) {
        return Err(AppError::NotFound("Artifact not found".to_string()));
    }

    let now = chrono::Utc::now();
    let is_blocked = quarantine_service::check_download_allowed(
        row.quarantine_status.as_deref(),
        row.quarantine_until,
        now,
    )
    .is_err();

    // The reason is per-artifact security detail, so it is disclosed only to
    // callers who can administer the repository — not to every user who can read
    // a public repo.
    // `can_access_repo` is unrestricted for admin scope, so this covers admins and
    // scoped users who genuinely hold the repository, and excludes an
    // authenticated caller who merely happens to be able to read a public repo.
    let quarantine_reason = if auth_ext.can_access_repo(row.repository_id) {
        row.quarantine_reason
    } else {
        None
    };

    Ok(Json(QuarantineStatusResponse {
        artifact_id,
        quarantine_status: row.quarantine_status,
        quarantine_until: row.quarantine_until,
        quarantine_reason,
        is_blocked,
    }))
}

/// Quarantine an artifact immediately (admin only)
#[utoipa::path(
    post,
    path = "/{artifact_id}/quarantine",
    context_path = "/api/v1/quarantine",
    operation_id = "quarantine_artifact_now",
    tag = "quarantine",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    request_body(content = QuarantineNowRequest, description = "Optional; empty body uses the default reason"),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifact quarantined", body = QuarantineActionResponse),
        (status = 400, description = "Malformed request body"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Artifact not found"),
        (status = 409, description = "Artifact was rejected during security review"),
    )
)]
pub async fn quarantine_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(artifact_id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<QuarantineActionResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    auth.require_admin()?;

    // The body is optional, but a body that was *sent* and is malformed must be a
    // 400 rather than silently defaulting the reason. `Option<Json<T>>` cannot
    // express that on axum 0.7 — its `FromRequest` impl maps every rejection,
    // including a wrong content-type and invalid JSON, to `None` — so parse the
    // raw bytes instead (#2912).
    let reason = if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<QuarantineNowRequest>(&body)
            .map_err(|e| AppError::Validation(format!("Invalid request body: {e}")))?
            .reason
    };
    let new_status = quarantine_service::quarantine_now(&state.db, artifact_id, reason).await?;

    tracing::info!(
        artifact_id = %artifact_id,
        admin = %auth.username,
        "Artifact quarantined by admin"
    );

    state.event_bus.emit(
        "artifact.quarantine.quarantined",
        artifact_id,
        Some(auth.username),
    );

    Ok(Json(QuarantineActionResponse {
        artifact_id,
        new_status: new_status.to_string(),
        message: "Artifact quarantined".to_string(),
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
        (status = 409, description = "Artifact is not in quarantined state"),
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
        None,
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
    operation_id = "reject_quarantined_artifact",
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
        (status = 409, description = "Artifact is not in quarantined state"),
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

    // Persist the admin's rejection reason rather than only logging it, so the
    // stored reason describes the rejection instead of whatever the preceding
    // quarantine recorded (#2912).
    quarantine_service::transition(
        &state.db,
        artifact_id,
        quarantine_service::QuarantineState::Rejected,
        req.reason.as_deref(),
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
        quarantine_artifact,
        release_artifact,
        reject_artifact,
    ),
    components(schemas(
        QuarantineStatusResponse,
        QuarantineNowRequest,
        QuarantineActionResponse,
        RejectRequest,
    )),
    tags(
        (name = "quarantine", description = "Artifact quarantine period management"),
    )
)]
pub struct QuarantineApiDoc;
