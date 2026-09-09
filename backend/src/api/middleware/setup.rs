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
                "If the password file is missing, restart the container. A new password will be generated automatically.",
                "This flow needs an ACTIVE built-in admin: a deactivated admin cannot log in. For SSO-only deployments set SKIP_ADMIN_PROVISIONING=true and restart to skip the built-in admin and this gate."
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

    /// #3723: a deactivated built-in admin cannot log in (local auth filters
    /// on `is_active`), so a pending `must_change_password` on it must not
    /// keep the gate armed. The DB re-check is what every replica consults
    /// before refusing a request, so it has to agree with login.
    #[tokio::test]
    async fn setup_still_required_ignores_inactive_admin_3723() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let admin = format!("setup-3723-admin-{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO users (username, email, password_hash, is_admin, must_change_password, is_active) \
             VALUES ($1, $2, 'x', true, true, false)",
        )
        .bind(&admin)
        .bind(format!("{admin}@test.local"))
        .execute(&pool)
        .await
        .expect("seed inactive admin");

        let dir = std::env::temp_dir().join(format!("ak-setup-3723-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let state =
            crate::api::handlers::test_db_helpers::build_state(pool.clone(), dir.to_str().unwrap());

        state.setup_required.store(true, Ordering::Relaxed);
        let inactive_still_required = state.setup_still_required().await;
        let latched_off = !state.setup_required.load(Ordering::Relaxed);

        // Control: the same row, active, still gates.
        sqlx::query("UPDATE users SET is_active = true WHERE username = $1")
            .bind(&admin)
            .execute(&pool)
            .await
            .expect("reactivate admin");
        state.setup_required.store(true, Ordering::Relaxed);
        let active_still_required = state.setup_still_required().await;

        // Clean up BEFORE asserting: a leaked local pending admin poisons
        // every later run of the bin-side provisioning test on this DB.
        let _ = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(&admin)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            !inactive_still_required,
            "a deactivated admin cannot complete the flow, so it must not keep the gate armed"
        );
        assert!(
            latched_off,
            "the re-check latches the flag off once the DB says nothing is pending"
        );
        assert!(
            active_still_required,
            "an active admin with a pending password change still gates"
        );
    }

    /// #3723, through the real router: with the built-in admin deactivated
    /// and still flagged `must_change_password`, an SSO admin's authenticated
    /// `GET /api/v1/users` must reach the handler rather than the setup 403
    /// -- that listing is how they would find the admin's id to unlock it,
    /// and on `main` it was gated along with everything else.
    #[tokio::test]
    async fn setup_guard_passes_authenticated_request_with_inactive_admin_3723() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let admin = format!("setup-3723-admin-{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO users (username, email, password_hash, is_admin, must_change_password, is_active) \
             VALUES ($1, $2, 'x', true, true, false)",
        )
        .bind(&admin)
        .bind(format!("{admin}@test.local"))
        .execute(&pool)
        .await
        .expect("seed inactive admin");

        // The caller: an OIDC-provisioned admin (federated, no local password).
        let sso_id = uuid::Uuid::new_v4();
        let sso_name = format!("setup-3723-oidc-{}", sso_id.simple());
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, external_id, \
                                is_admin, is_active) \
             VALUES ($1, $2, $3, NULL, 'oidc', $4, true, true)",
        )
        .bind(sso_id)
        .bind(&sso_name)
        .bind(format!("{sso_name}@test.local"))
        .bind(format!("oidc|{sso_id}"))
        .execute(&pool)
        .await
        .expect("seed oidc admin");

        let dir = std::env::temp_dir().join(format!("ak-setup-3723-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let state =
            crate::api::handlers::test_db_helpers::build_state(pool.clone(), dir.to_str().unwrap());
        state.setup_required.store(true, Ordering::Relaxed);

        let bearer = crate::api::handlers::test_db_helpers::bearer_for(&state, sso_id).await;
        let app = crate::api::routes::create_router(state);
        let mut req = crate::api::handlers::test_db_helpers::get("/api/v1/users".to_string());
        req.headers_mut()
            .insert("authorization", bearer.parse().expect("bearer header"));
        let (status, bytes) = crate::api::handlers::test_db_helpers::send(app, req).await;
        let body = String::from_utf8_lossy(&bytes).into_owned();

        // Clean up BEFORE asserting (see the sibling test).
        let _ = sqlx::query("DELETE FROM users WHERE username = $1 OR id = $2")
            .bind(&admin)
            .bind(sso_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            !body.contains("SETUP_REQUIRED"),
            "the setup gate must not block an authenticated admin when the built-in admin \
             is deactivated, got {status}: {body}"
        );
        assert_eq!(status, StatusCode::OK, "body: {body}");
    }

    /// Seed a local admin with a pending password change and the given
    /// `is_active`, returning its id. Callers delete it by id.
    async fn seed_pending_local_admin(pool: &sqlx::PgPool, is_active: bool) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        let name = format!("setup-3723-admin-{}", id.simple());
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, \
                                must_change_password, is_active) \
             VALUES ($1, $2, $3, 'x', 'local', true, true, $4)",
        )
        .bind(id)
        .bind(&name)
        .bind(format!("{name}@test.local"))
        .bind(is_active)
        .execute(pool)
        .await
        .expect("seed pending local admin");
        id
    }

    /// Seed an OIDC-provisioned admin (federated, no local password).
    async fn seed_oidc_admin(pool: &sqlx::PgPool) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        let name = format!("setup-3723-oidc-{}", id.simple());
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, external_id, \
                                is_admin, is_active) \
             VALUES ($1, $2, $3, NULL, 'oidc', $4, true, true)",
        )
        .bind(id)
        .bind(&name)
        .bind(format!("{name}@test.local"))
        .bind(format!("oidc|{id}"))
        .execute(pool)
        .await
        .expect("seed oidc admin");
        id
    }

    fn json_request(method: &str, uri: String, bearer: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", bearer)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// #3723 follow-up: once the gate is latched off for a deactivated admin,
    /// reactivating that admin (`PATCH /api/v1/users/{id}` with
    /// `is_active: true`) recreates the row that arms the gate. The latch
    /// must re-arm on that replica at once, so the very next gated request
    /// is refused again, rather than only at the next restart.
    #[tokio::test]
    async fn setup_guard_rearms_when_pending_admin_is_reactivated_3723() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let admin_id = seed_pending_local_admin(&pool, false).await;
        let sso_id = seed_oidc_admin(&pool).await;

        let dir = std::env::temp_dir().join(format!("ak-setup-3723-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let state =
            crate::api::handlers::test_db_helpers::build_state(pool.clone(), dir.to_str().unwrap());
        // The post-fix steady state: nothing pending, latch off.
        state.setup_required.store(false, Ordering::Relaxed);

        let bearer = crate::api::handlers::test_db_helpers::bearer_for(&state, sso_id).await;
        let app = crate::api::routes::create_router(state);
        let (reactivate_status, _) = crate::api::handlers::test_db_helpers::send(
            app.clone(),
            json_request(
                "PATCH",
                format!("/api/v1/users/{admin_id}"),
                &bearer,
                r#"{"is_active": true}"#,
            ),
        )
        .await;
        let mut req =
            crate::api::handlers::test_db_helpers::get("/api/v1/repositories".to_string());
        req.headers_mut()
            .insert("authorization", bearer.parse().expect("bearer header"));
        let (status, bytes) = crate::api::handlers::test_db_helpers::send(app, req).await;
        let body = String::from_utf8_lossy(&bytes).into_owned();

        // Clean up BEFORE asserting: the reactivated row is an active pending
        // admin, i.e. exactly what arms the gate for every other test.
        let _ = sqlx::query("DELETE FROM users WHERE id = $1 OR id = $2")
            .bind(admin_id)
            .bind(sso_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            reactivate_status,
            StatusCode::OK,
            "reactivation itself succeeds"
        );
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the next gated request must be refused again after reactivation, got: {body}"
        );
        assert!(
            body.contains("SETUP_REQUIRED"),
            "setup body expected, got: {body}"
        );
    }

    /// #3723 follow-up: with the gate latched off, an ACTIVE admin still
    /// flagged `must_change_password` must not be able to use admin routes
    /// before rotating -- `admin_middleware` has to apply the same 428 that
    /// `auth_middleware` does. Measured on the pre-fix branch: 200, the
    /// pending admin deactivated itself through an admin mutation.
    #[tokio::test]
    async fn admin_route_refuses_pending_admin_with_428_when_gate_latched_off_3723() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let admin_id = seed_pending_local_admin(&pool, true).await;

        let dir = std::env::temp_dir().join(format!("ak-setup-3723-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let state =
            crate::api::handlers::test_db_helpers::build_state(pool.clone(), dir.to_str().unwrap());
        state.setup_required.store(false, Ordering::Relaxed);

        let bearer = crate::api::handlers::test_db_helpers::bearer_for(&state, admin_id).await;
        let app = crate::api::routes::create_router(state);
        let (status, bytes) = crate::api::handlers::test_db_helpers::send(
            app,
            json_request(
                "PATCH",
                format!("/api/v1/users/{admin_id}"),
                &bearer,
                r#"{"is_active": false}"#,
            ),
        )
        .await;
        let body = String::from_utf8_lossy(&bytes).into_owned();

        // Clean up BEFORE asserting (active pending admin, see above).
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(admin_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            status,
            StatusCode::PRECONDITION_REQUIRED,
            "a pending admin must be 428'd on an admin route, got {status}: {body}"
        );
    }
}
