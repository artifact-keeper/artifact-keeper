//! SMTP administration handlers.

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::smtp_service::SmtpError;

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
    ///
    /// Accepts `recipient` as an alias for backward compatibility with Web UI
    /// versions <= 1.1.3, which send `{"recipient": "..."}`.
    #[serde(alias = "recipient")]
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
        (status = 502, description = "The SMTP server refused or the connection failed; the message carries the server's reply, what it advertised, and a configuration hint"),
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

    match smtp.send_test_email(&req.to).await {
        Ok(()) => {}
        Err(SmtpError::Delivery(failure)) => {
            // Probe EHLO separately so the message can say what the server
            // offered (lettre's own error cannot name NTLM or GSSAPI).
            let probe = smtp.probe().await;
            let failure = match smtp.hint_context() {
                Some(ctx) => failure.with_probe(ctx, &probe),
                None => failure,
            };
            tracing::error!(error = %failure, to = %req.to, "SMTP test email failed");
            // 502, not 500: the upstream mail server refused, and the message
            // is meant for the administrator (500 bodies are redacted).
            return Err(AppError::BadGateway(format!("SMTP test failed: {failure}")));
        }
        Err(SmtpError::Address(msg)) => {
            return Err(AppError::Validation(msg));
        }
        Err(e) => {
            tracing::error!(error = %e, to = %req.to, "SMTP test email failed");
            return Err(AppError::Internal(format!("SMTP test failed: {e}")));
        }
    }

    Ok(Json(SmtpTestResponse {
        success: true,
        message: format!("Test email sent to {}", req.to),
    }))
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_test_request_accepts_to_field() {
        let body = r#"{"to":"user@example.com"}"#;
        let req: SmtpTestRequest = serde_json::from_str(body).expect("should parse `to`");
        assert_eq!(req.to, "user@example.com");
    }

    #[test]
    fn smtp_test_request_accepts_recipient_alias() {
        // Web UI 1.1.3 and earlier send `{"recipient": "..."}`. The backend
        // must accept this for backward compatibility (issue #1332).
        let body = r#"{"recipient":"user@example.com"}"#;
        let req: SmtpTestRequest =
            serde_json::from_str(body).expect("should parse `recipient` alias");
        assert_eq!(req.to, "user@example.com");
    }

    #[test]
    fn smtp_test_request_rejects_missing_field() {
        let body = r#"{}"#;
        let result: std::result::Result<SmtpTestRequest, _> = serde_json::from_str(body);
        assert!(result.is_err());
    }
}
