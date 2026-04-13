//! SMTP administration handlers.

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Create SMTP admin routes.
pub fn router() -> Router<SharedState> {
    Router::new().route("/test", post(send_test_email))
}

#[derive(OpenApi)]
#[openapi(
    paths(send_test_email),
    components(schemas(SmtpTestRequest, SmtpTestResponse))
)]
pub struct SmtpApiDoc;

/// Request body for the SMTP test endpoint.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SmtpTestRequest {
    /// Recipient email address for the test message.
    pub to: String,
}

/// Response from the SMTP test endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct SmtpTestResponse {
    /// Whether the test email was sent successfully.
    pub success: bool,
    /// Human-readable status message.
    pub message: String,
}

/// Send a test email to verify SMTP configuration.
///
/// Requires admin privileges. Sends a short test message to the provided
/// recipient address and reports whether delivery succeeded.
#[utoipa::path(
    post,
    path = "/test",
    context_path = "/api/v1/admin/smtp",
    tag = "admin",
    security(("bearer_auth" = [])),
    request_body = SmtpTestRequest,
    responses(
        (status = 200, description = "Test email sent successfully", body = SmtpTestResponse),
        (status = 400, description = "Invalid request (e.g. bad email address)"),
        (status = 403, description = "Admin privileges required"),
        (status = 503, description = "SMTP not configured"),
    )
)]
pub async fn send_test_email(
    State(state): State<SharedState>,
    Json(req): Json<SmtpTestRequest>,
) -> Result<Json<SmtpTestResponse>> {
    let smtp = state
        .smtp_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("SMTP service not initialized".into()))?;

    if !smtp.is_configured() {
        return Err(AppError::Validation(
            "SMTP is not configured. Set SMTP_HOST to enable email delivery.".into(),
        ));
    }

    if req.to.trim().is_empty() {
        return Err(AppError::Validation(
            "Recipient email address is required.".into(),
        ));
    }

    smtp.send_test_email(&req.to).await.map_err(|e| {
        tracing::error!(error = %e, to = %req.to, "SMTP test email failed");
        AppError::Internal(format!("SMTP test failed: {e}"))
    })?;

    Ok(Json(SmtpTestResponse {
        success: true,
        message: format!("Test email sent to {}", req.to),
    }))
}
