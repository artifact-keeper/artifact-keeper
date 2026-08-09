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

    // EXISTENCE gate: the caller must be able to SEE the artifact's repository.
    //
    // This used to be `!repo.is_public && !auth_ext.can_access_repo(...)`.
    // `can_access_repo` is the caller's TOKEN SCOPE — it resolves to
    // `access_scope().grants(repo_id)`, and `AccessScope::Admin` grants
    // unconditionally — so for every browser JWT session and every unscoped API
    // token it returned `true` for EVERY repository in the instance. As a
    // visibility gate it was inert for the most common caller, and any
    // authenticated user holding an artifact UUID could confirm the existence
    // of another tenant's private artifact (#3174).
    //
    // `require_repo_id_visible` is the canonical predicate,
    // `is_public OR (in_scope AND (is_admin OR grants))`, and it collapses
    // "repository row is gone" into the same existence-hiding 404 rather than
    // surfacing a "Repository '<key>' not found" message that would name it.
    crate::api::handlers::repositories::require_repo_id_visible(
        &state.db,
        &auth_ext,
        row.repository_id,
        "Artifact not found",
    )
    .await?;

    let now = chrono::Utc::now();
    let is_blocked = quarantine_service::check_download_allowed(
        row.quarantine_status.as_deref(),
        row.quarantine_until,
        now,
    )
    .is_err();

    // REASON gate, deliberately STRICTER than the existence gate above.
    //
    // The reason is per-artifact security detail — the policy name, finding
    // counts and free-text admin incident notes behind the hold. #2912 keeps it
    // off the blocked-download 403 for exactly that reason, because that path is
    // reachable anonymously on a public repository. So it goes ONLY to callers
    // who genuinely HOLD the repository: the `is_public` arm of the visibility
    // predicate is dropped, leaving `in_scope AND (is_admin OR grants)`. A
    // caller who can see the artifact only because its repository happens to be
    // public does not get the finding text.
    //
    // That is precisely what the comment here claimed before #3174 — "excludes
    // an authenticated caller who merely happens to be able to read a public
    // one". The code did not implement it. Testing `can_access_repo` alone
    // tested TOKEN SCOPE, which is unconditionally `true` for `AccessScope::
    // Admin` — every browser JWT session, every unscoped API token — so the
    // field was handed to any authenticated caller on any repository. The
    // comment is why the gate survived review; the predicate is now spelled out
    // instead of delegated to a name that means something else.
    let repo_service =
        crate::services::repository_service::RepositoryService::new(state.db.clone());
    let holds_repository = auth_ext.can_access_repo(row.repository_id)
        && (auth_ext.is_admin
            || repo_service
                .user_can_access_repo(row.repository_id, auth_ext.user_id)
                .await?);
    let quarantine_reason = if holds_repository {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;
    use bytes::Bytes;
    use chrono::{DateTime, Duration, Utc};

    /// Insert an artifact in a given quarantine state and return its id.
    async fn seed_artifact(
        fx: &tdh::Fixture,
        status: Option<&str>,
        until: Option<DateTime<Utc>>,
        reason: Option<&str>,
    ) -> Uuid {
        let artifact_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, path, size_bytes, checksum_sha256,
                content_type, storage_key, is_deleted,
                quarantine_status, quarantine_until, quarantine_reason
            )
            VALUES ($1, $2, $8, $8, 4, $3,
                    'application/octet-stream', $4, false, $5, $6, $7)
            "#,
        )
        .bind(artifact_id)
        .bind(fx.repo_id)
        .bind(format!("{:064x}", artifact_id.as_u128()))
        .bind(format!("q-test/{artifact_id}.bin"))
        .bind(status)
        .bind(until)
        .bind(reason)
        // Unique per artifact: several tests seed more than one row in the same
        // fixture repository, and (repository_id, path) is unique.
        .bind(format!("pkg-{artifact_id}.bin"))
        .execute(&fx.pool)
        .await
        .expect("insert artifact");
        artifact_id
    }

    async fn read_state(
        fx: &tdh::Fixture,
        artifact_id: Uuid,
    ) -> (Option<String>, Option<DateTime<Utc>>, Option<String>) {
        sqlx::query_as(
            "SELECT quarantine_status, quarantine_until, quarantine_reason \
             FROM artifacts WHERE id = $1",
        )
        .bind(artifact_id)
        .fetch_one(&fx.pool)
        .await
        .expect("read quarantine state")
    }

    fn admin_router(fx: &tdh::Fixture) -> axum::Router {
        let auth = tdh::admin_auth(fx.user_id, &fx.username);
        crate::api::handlers::test_db_helpers::router_with_auth(router(), fx.state.clone(), auth)
    }

    fn quarantine_req(
        artifact_id: Uuid,
        body: &'static str,
    ) -> axum::http::Request<axum::body::Body> {
        tdh::post(
            format!("/{artifact_id}/quarantine"),
            "application/json",
            Bytes::from_static(body.as_bytes()),
        )
    }

    /// The endpoint must be admin-only. Nothing tested this, so dropping
    /// `require_admin` would have left it world-writable with a green suite (#2912).
    #[tokio::test]
    async fn test_quarantine_now_requires_admin() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let artifact_id = seed_artifact(&fx, Some("clean"), None, None).await;

        // `router_with_auth` injects the fixture's ordinary (non-admin) principal.
        let app = fx.router_with_auth(router());
        let (status, _) = tdh::send(app, quarantine_req(artifact_id, "{}")).await;
        let (db_status, _, _) = read_state(&fx, artifact_id).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            db_status.as_deref(),
            Some("clean"),
            "a rejected request must not change state"
        );
    }

    #[tokio::test]
    async fn test_quarantine_now_admin_sets_permanent_block_and_reason() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let artifact_id = seed_artifact(&fx, Some("clean"), None, None).await;

        let (status, _) = tdh::send(
            admin_router(&fx),
            quarantine_req(artifact_id, r#"{"reason":"CVE-2026-9999 exploited"}"#),
        )
        .await;
        let (db_status, until, reason) = read_state(&fx, artifact_id).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(db_status.as_deref(), Some("quarantined"));
        assert!(until.is_none(), "an admin quarantine must have no expiry");
        assert_eq!(reason.as_deref(), Some("CVE-2026-9999 exploited"));
    }

    /// The blocker this endpoint shipped with: `quarantined` covers both an
    /// expiring upload hold and a permanent block, and the handler returned 200
    /// without writing when the status already read `quarantined`. The admin's block
    /// then lapsed with the hold — or, for an already-expired hold, never applied at
    /// all, since the download gate treats `('quarantined', past)` as downloadable.
    #[tokio::test]
    async fn test_quarantine_now_converts_timed_hold_to_permanent() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let future_hold = Utc::now() + Duration::minutes(30);
        let live = seed_artifact(&fx, Some("quarantined"), Some(future_hold), None).await;
        // An expired hold is the worse case: downloadable right now.
        let expired = seed_artifact(
            &fx,
            Some("quarantined"),
            Some(Utc::now() - Duration::minutes(30)),
            None,
        )
        .await;

        let (live_status, _) = tdh::send(
            admin_router(&fx),
            quarantine_req(live, r#"{"reason":"malware confirmed"}"#),
        )
        .await;
        let (expired_status, _) = tdh::send(
            admin_router(&fx),
            quarantine_req(expired, r#"{"reason":"malware confirmed"}"#),
        )
        .await;

        let (live_db, live_until, live_reason) = read_state(&fx, live).await;
        let (expired_db, expired_until, expired_reason) = read_state(&fx, expired).await;
        fx.teardown().await;

        assert_eq!(live_status, StatusCode::OK);
        assert_eq!(expired_status, StatusCode::OK);

        assert_eq!(live_db.as_deref(), Some("quarantined"));
        assert!(
            live_until.is_none(),
            "the hold's expiry must be cleared, or the admin block lapses with it"
        );
        assert_eq!(live_reason.as_deref(), Some("malware confirmed"));

        assert_eq!(expired_db.as_deref(), Some("quarantined"));
        assert!(
            expired_until.is_none(),
            "an expired hold must become a permanent block, not stay downloadable"
        );
        assert_eq!(expired_reason.as_deref(), Some("malware confirmed"));
    }

    #[tokio::test]
    async fn test_quarantine_now_is_idempotent_and_refreshes_reason() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let artifact_id = seed_artifact(&fx, Some("quarantined"), None, Some("first reason")).await;

        let (status, _) = tdh::send(
            admin_router(&fx),
            quarantine_req(artifact_id, r#"{"reason":"second reason"}"#),
        )
        .await;
        let (db_status, until, reason) = read_state(&fx, artifact_id).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK, "re-quarantining must not conflict");
        assert_eq!(db_status.as_deref(), Some("quarantined"));
        assert!(until.is_none());
        assert_eq!(
            reason.as_deref(),
            Some("second reason"),
            "an admin correcting the reason must not be silently ignored"
        );
    }

    #[tokio::test]
    async fn test_quarantine_now_conflicts_on_rejected() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let artifact_id = seed_artifact(&fx, Some("rejected"), None, Some("terminal")).await;

        let (status, _) = tdh::send(admin_router(&fx), quarantine_req(artifact_id, "{}")).await;
        let (db_status, _, reason) = read_state(&fx, artifact_id).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            db_status.as_deref(),
            Some("rejected"),
            "a terminal rejection must be preserved"
        );
        assert_eq!(reason.as_deref(), Some("terminal"));
    }

    #[tokio::test]
    async fn test_quarantine_now_unknown_artifact_is_404() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let (status, _) = tdh::send(admin_router(&fx), quarantine_req(Uuid::new_v4(), "{}")).await;
        fx.teardown().await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// An empty body is allowed (default reason), but a body that was *sent* and is
    /// malformed must be a 400. `Option<Json<T>>` mapped every rejection to `None`
    /// on axum 0.7, so a wrong content-type or invalid JSON returned 200 with the
    /// reason silently defaulted (#2912).
    #[tokio::test]
    async fn test_quarantine_now_body_handling() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let empty_body = seed_artifact(&fx, Some("clean"), None, None).await;
        let bad_json = seed_artifact(&fx, Some("clean"), None, None).await;
        let wrong_type = seed_artifact(&fx, Some("clean"), None, None).await;

        let (empty_status, _) = tdh::send(
            admin_router(&fx),
            tdh::post(
                format!("/{empty_body}/quarantine"),
                "application/json",
                Bytes::new(),
            ),
        )
        .await;
        let (bad_status, _) = tdh::send(
            admin_router(&fx),
            quarantine_req(bad_json, r#"{"reason": 42}"#),
        )
        .await;
        let (wrong_status, _) = tdh::send(
            admin_router(&fx),
            tdh::post(
                format!("/{wrong_type}/quarantine"),
                "text/plain",
                Bytes::from_static(b"reason=whatever"),
            ),
        )
        .await;

        let (empty_db, _, empty_reason) = read_state(&fx, empty_body).await;
        let (bad_db, _, _) = read_state(&fx, bad_json).await;
        let (wrong_db, _, _) = read_state(&fx, wrong_type).await;
        fx.teardown().await;

        assert_eq!(
            empty_status,
            StatusCode::OK,
            "an omitted body is valid and uses the default reason"
        );
        assert_eq!(empty_db.as_deref(), Some("quarantined"));
        assert_eq!(
            empty_reason.as_deref(),
            Some("Quarantined by administrator")
        );

        assert_eq!(
            bad_status,
            StatusCode::BAD_REQUEST,
            "a malformed JSON body must not be silently defaulted"
        );
        assert_eq!(
            bad_db.as_deref(),
            Some("clean"),
            "a rejected body must not change state"
        );

        assert_eq!(
            wrong_status,
            StatusCode::BAD_REQUEST,
            "a non-JSON body must not be silently defaulted"
        );
        assert_eq!(wrong_db.as_deref(), Some("clean"));
    }

    /// The reason is disclosed here — the authenticated, visibility-checked read
    /// path — and not in blocked-download errors, which are reachable anonymously
    /// on public repositories (#2912).
    #[tokio::test]
    async fn test_status_endpoint_exposes_reason_to_authorized_caller() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let artifact_id = seed_artifact(
            &fx,
            Some("quarantined"),
            None,
            Some("Policy 'cve-gate': 2 findings at or above high"),
        )
        .await;

        let app = fx.router_with_auth(router());
        let (status, body) = tdh::send(app, tdh::get(format!("/{artifact_id}"))).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("status response must be JSON");
        assert_eq!(json["quarantine_status"], "quarantined");
        assert_eq!(json["is_blocked"], true);
        assert_eq!(
            json["quarantine_reason"],
            "Policy 'cve-gate': 2 findings at or above high"
        );
    }

    /// Rejecting must persist the admin's stated reason, not merely log it.
    #[tokio::test]
    async fn test_reject_persists_admin_reason() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let artifact_id =
            seed_artifact(&fx, Some("quarantined"), None, Some("earlier hold reason")).await;

        let (status, _) = tdh::send(
            admin_router(&fx),
            tdh::post(
                format!("/{artifact_id}/reject"),
                "application/json",
                Bytes::from_static(br#"{"reason":"malicious maintainer takeover"}"#),
            ),
        )
        .await;
        let (db_status, _, reason) = read_state(&fx, artifact_id).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(db_status.as_deref(), Some("rejected"));
        assert_eq!(
            reason.as_deref(),
            Some("malicious maintainer takeover"),
            "the rejection reason must replace the earlier quarantine reason"
        );
    }

    // -----------------------------------------------------------------------
    // #3174: `can_access_repo` is TOKEN SCOPE, not repository visibility.
    // -----------------------------------------------------------------------

    /// Flip the fixture repository's `is_public` flag.
    async fn set_repo_public(fx: &tdh::Fixture, public: bool) {
        sqlx::query("UPDATE repositories SET is_public = $1 WHERE id = $2")
            .bind(public)
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("set is_public");
    }

    /// `GET /{artifact_id}` as `auth`, decoded.
    async fn status_as(
        fx: &tdh::Fixture,
        auth: crate::api::middleware::auth::AuthExtension,
        artifact_id: Uuid,
    ) -> (StatusCode, serde_json::Value) {
        let app = tdh::router_with_auth(router(), fx.state.clone(), auth);
        let (status, body) = tdh::send(app, tdh::get(format!("/{artifact_id}"))).await;
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// A private repository's quarantine status must not be readable by an
    /// authenticated caller who holds no grant on it (#3174).
    ///
    /// The caller shape that matters is [`tdh::make_auth`]: a non-admin with
    /// `allowed_repo_ids = AccessScope::Admin`, i.e. unrestricted token scope.
    /// That is exactly a browser JWT session, and it is the shape for which the
    /// pre-fix `can_access_repo` gate returned `true` for every repository in
    /// the instance — so the endpoint disclosed existence, hold status, and the
    /// free-text `quarantine_reason` (the malware / CVE finding) cross-tenant.
    ///
    /// Both positive controls run against the SAME fixture and the SAME
    /// artifact, so a "fix" that denied everyone would fail here.
    #[tokio::test]
    async fn test_status_private_repo_denies_non_member_but_not_holders() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let reason = "Policy 'cve-gate': 2 findings at or above high";
        let artifact_id = seed_artifact(&fx, Some("quarantined"), None, Some(reason)).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;

        // NEGATIVE: authenticated, unrestricted scope, no grant on the repo.
        let (out_status, out_json) =
            status_as(&fx, tdh::make_auth(outsider, &outname), artifact_id).await;
        // POSITIVE CONTROL 1: the fixture user holds a developer grant.
        let (member_status, member_json) =
            status_as(&fx, tdh::make_auth(fx.user_id, &fx.username), artifact_id).await;
        // POSITIVE CONTROL 2: a global admin.
        let (admin_status, admin_json) =
            status_as(&fx, tdh::admin_auth(fx.user_id, &fx.username), artifact_id).await;

        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;

        assert_eq!(
            out_status,
            StatusCode::NOT_FOUND,
            "a non-member must not learn that a private repo's artifact exists; got {out_json}"
        );
        assert!(
            out_json.get("quarantine_reason").is_none(),
            "the security finding must not be disclosed to a non-member: {out_json}"
        );

        assert_eq!(
            member_status,
            StatusCode::OK,
            "member must still read status"
        );
        assert_eq!(member_json["quarantine_status"], "quarantined");
        assert_eq!(member_json["quarantine_reason"], reason);

        assert_eq!(admin_status, StatusCode::OK, "admin must still read status");
        assert_eq!(admin_json["quarantine_reason"], reason);
    }

    /// On a PUBLIC repository the existence gate opens — anyone may see that
    /// the artifact is held — but `quarantine_reason` is per-artifact security
    /// detail and stays with callers who actually HOLD the repository (#3174).
    ///
    /// This is the behavior the pre-fix comment claimed ("excludes an
    /// authenticated caller who merely happens to be able to read a public
    /// one") and did not implement: `can_access_repo` is `true` for every
    /// unscoped principal, so the reason went to everyone.
    ///
    /// The member and admin controls are in the same fixture, so hiding the
    /// reason unconditionally would fail.
    #[tokio::test]
    async fn test_status_public_repo_reason_only_to_repo_holders() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        set_repo_public(&fx, true).await;
        let reason = "Policy 'malware-gate': eicar signature match";
        let artifact_id = seed_artifact(&fx, Some("quarantined"), None, Some(reason)).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;

        // NEGATIVE: reads the public repo fine, but holds no grant on it.
        let (out_status, out_json) =
            status_as(&fx, tdh::make_auth(outsider, &outname), artifact_id).await;
        // POSITIVE CONTROL 1: grant holder.
        let (member_status, member_json) =
            status_as(&fx, tdh::make_auth(fx.user_id, &fx.username), artifact_id).await;
        // POSITIVE CONTROL 2: admin.
        let (admin_status, admin_json) =
            status_as(&fx, tdh::admin_auth(fx.user_id, &fx.username), artifact_id).await;

        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;

        assert_eq!(
            out_status,
            StatusCode::OK,
            "a public repo's hold STATUS stays readable: {out_json}"
        );
        assert_eq!(out_json["quarantine_status"], "quarantined");
        assert_eq!(out_json["is_blocked"], true);
        assert!(
            out_json.get("quarantine_reason").is_none(),
            "the finding text must not reach a caller who merely reads a public \
             repo: {out_json}"
        );

        assert_eq!(member_status, StatusCode::OK);
        assert_eq!(
            member_json["quarantine_reason"], reason,
            "a grant holder must still receive the reason"
        );
        assert_eq!(admin_status, StatusCode::OK);
        assert_eq!(
            admin_json["quarantine_reason"], reason,
            "an admin must still receive the reason"
        );
    }
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
