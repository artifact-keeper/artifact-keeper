//! Setup mode middleware that locks the API until the admin password is changed.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::api::AppState;

/// Middleware that blocks most API requests when setup is required.
///
/// When `state.setup_required` is true, only health/readiness checks,
/// auth endpoints (login, refresh), the password-change endpoint, and
/// the setup status endpoint are allowed. Everything else gets a 403
/// with instructions on how to complete setup.
pub async fn setup_guard(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !state.setup_required.load(Ordering::Relaxed) {
        return next.run(request).await;
    }

    let path = request.uri().path();

    let is_oci_v2 = super::oci_errors::is_oci_v2_path(path);
    let is_allowed = matches!(
        path,
        "/health"
            | "/healthz"
            | "/ready"
            | "/readyz"
            | "/livez"
            | "/metrics"
            | "/api/v1/setup/status"
    ) || path.starts_with("/api/v1/auth")
        || (path.starts_with("/api/v1/users/") && path.ends_with("/password"));

    if is_allowed {
        return next.run(request).await;
    }

    // This replica still believes setup is pending and would block the
    // request. Re-check the authoritative DB state first: the password
    // change may have been served by a DIFFERENT replica, which cleared
    // only its own in-process flag. Without this re-check every other
    // replica stayed locked (403 SETUP_REQUIRED) until it was restarted
    // (#2492). `setup_still_required` latches the flag to false on
    // confirmation, so the extra query happens at most until the first
    // confirmation and never once setup is known to be complete.
    if !state.setup_still_required().await {
        return next.run(request).await;
    }

    // #3284: a refusal on the OCI surface must be the distribution-spec
    // error envelope, not the REST body below — docker cannot render the
    // REST shape, so an unconfigured instance reported a `docker login`
    // failure with no usable message.
    if is_oci_v2 {
        return super::oci_errors::oci_denied_response(
            StatusCode::FORBIDDEN,
            "DENIED",
            "initial setup is required: change the admin password via the API to unlock the registry",
        );
    }

    // Block everything else
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "SETUP_REQUIRED",
            "message": "Initial setup is required. Change the admin password to unlock the API.",
            "instructions": [
                "1. Read the generated password by exec'ing into the artifact-keeper backend container and running: cat /data/storage/admin.password",
                "   - Docker:     docker exec artifact-keeper-backend cat /data/storage/admin.password && echo",
                "   - Kubernetes: kubectl exec deploy/artifact-keeper-backend -- cat /data/storage/admin.password",
                "2. Login: POST /api/v1/auth/login with {\"username\":\"admin\",\"password\":\"<from-file>\"}",
                "3. Change password: POST /api/v1/users/<id>/password with {\"new_password\":\"<your-password>\"}",
                "4. The API will unlock automatically after the password is changed.",
                "If the password file is missing, restart the container. A new password will be generated automatically."
            ]
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    /// #3284: while setup is pending, a refusal on `/v2` must be the
    /// distribution-spec error envelope so `docker login` renders a usable
    /// message; REST routes keep the instructional SETUP_REQUIRED body.
    #[tokio::test]
    async fn setup_guard_emits_oci_envelope_on_v2_and_rest_shape_elsewhere() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        // Seed the DB-side condition `setup_still_required` re-checks: an
        // admin account that must still change its password.
        let admin = format!("setup-guard-admin-{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO users (username, email, password_hash, is_admin, must_change_password) \
             VALUES ($1, $2, 'x', true, true)",
        )
        .bind(&admin)
        .bind(format!("{admin}@test.local"))
        .execute(&pool)
        .await
        .expect("seed admin");

        let dir = std::env::temp_dir().join(format!("ak-setup-guard-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let state =
            crate::api::handlers::test_db_helpers::build_state(pool.clone(), dir.to_str().unwrap());
        state
            .setup_required
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = axum::Router::new()
            .fallback(|| async { StatusCode::OK })
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                setup_guard,
            ));

        let send = |app: axum::Router, uri: &'static str| async move {
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            let (status, bytes) = crate::api::handlers::test_db_helpers::send(app, req).await;
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        };

        let (status, body) = send(app.clone(), "/v2/").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body["errors"][0]["code"], "DENIED",
            "OCI surface must get the spec envelope, got: {body}"
        );
        assert!(body.get("error").is_none());

        let (status, body) = send(app.clone(), "/api/v1/repositories").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body["error"], "SETUP_REQUIRED",
            "REST surface keeps the instructional body"
        );

        let _ = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(&admin)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
