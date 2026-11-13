//! Admin API for MCP namespace proofs (#5253, Phase 3):
//! `/api/v1/admin/mcp/namespace-proofs`. See
//! [`crate::services::mcp_namespace_proofs`] for the checks.

use axum::extract::{Extension, Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::mcp_namespace_proofs as proofs;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/:id", get(get_one).delete(remove))
        .route("/:id/verify", post(verify))
}

/// The OpenAPI paths of the namespace-proof admin API.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list, get_one, create, remove, verify),
    components(schemas(CreateProof))
)]
pub struct McpNamespaceProofsApiDoc;

/// One proof as stored.
#[derive(Debug, Clone, sqlx::FromRow)]
struct ProofRow {
    id: Uuid,
    namespace: String,
    domain: String,
    method: String,
    token: String,
    status: String,
    last_error: Option<String>,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    last_checked_at: Option<DateTime<Utc>>,
    verified_at: Option<DateTime<Utc>>,
}

const COLUMNS: &str = "id, namespace, domain, method, token, status, last_error, created_by, \
                       created_at, last_checked_at, verified_at";

/// The response shape (documented in docs/mcp-registry.md).
fn to_json(r: &ProofRow) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "namespace": r.namespace,
        "domain": r.domain,
        "method": r.method,
        "status": r.status,
        "last_error": r.last_error,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "last_checked_at": r.last_checked_at,
        "verified_at": r.verified_at,
        "challenge": proofs::instructions(&r.method, &r.domain, &r.token),
    })
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateProof {
    pub namespace: String,
    pub method: String,
}

/// Validate a create request: the method and the namespace's domain.
pub fn validate_create(req: &CreateProof) -> Result<(String, String)> {
    if !proofs::METHODS.contains(&req.method.as_str()) {
        return Err(AppError::Validation(
            "method must be one of: dns, http".into(),
        ));
    }
    let domain = proofs::domain_of(&req.namespace).map_err(AppError::Validation)?;
    Ok((req.namespace.trim().to_ascii_lowercase(), domain))
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Database(e.to_string())
}

async fn fetch(state: &SharedState, id: Uuid) -> Result<ProofRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM mcp_namespace_proofs WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?
    .ok_or_else(|| AppError::NotFound("Namespace proof not found".into()))
}

#[utoipa::path(
    get,
    extensions(("x-required-permission" = json!("system.settings.read")), ("x-resource" = json!("instance"))),
    operation_id = "mcp_list_namespace_proofs",
    path = "",
    context_path = "/api/v1/admin/mcp/namespace-proofs",
    tag = "mcp",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = Object, description = "`{items: [Proof]}`, at most 1000, by namespace"),
        (status = 403, description = "Not an instance administrator"),
    )
)]
async fn list(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<serde_json::Value>> {
    auth.require_admin()?;
    let rows: Vec<ProofRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM mcp_namespace_proofs ORDER BY namespace, created_at DESC LIMIT 1000"
    )))
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(
        serde_json::json!({"items": rows.iter().map(to_json).collect::<Vec<_>>()}),
    ))
}

#[utoipa::path(
    get,
    extensions(("x-required-permission" = json!("system.settings.read")), ("x-resource" = json!("instance"))),
    operation_id = "mcp_get_namespace_proof",
    path = "/{id}",
    context_path = "/api/v1/admin/mcp/namespace-proofs",
    tag = "mcp",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Proof id")),
    responses(
        (status = 200, body = Object, description = "The proof"),
        (status = 403, description = "Not an instance administrator"),
        (status = 404, description = "Unknown proof"),
    )
)]
async fn get_one(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    auth.require_admin()?;
    Ok(Json(to_json(&fetch(&state, id).await?)))
}

#[utoipa::path(
    post,
    extensions(("x-required-permission" = json!("system.settings.update")), ("x-resource" = json!("instance"))),
    operation_id = "mcp_create_namespace_proof",
    path = "",
    context_path = "/api/v1/admin/mcp/namespace-proofs",
    tag = "mcp",
    security(("bearer_auth" = [])),
    request_body = CreateProof,
    responses(
        (status = 200, body = Object, description = "The new proof (`status: pending`) with its challenge"),
        (status = 400, description = "Another method, or a namespace that is not reverse-DNS"),
        (status = 403, description = "Not an instance administrator"),
    )
)]
async fn create(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateProof>,
) -> Result<Json<serde_json::Value>> {
    auth.require_admin()?;
    let (namespace, domain) = validate_create(&req)?;
    let row: ProofRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "INSERT INTO mcp_namespace_proofs (namespace, domain, method, token, created_by) \
         VALUES ($1, $2, $3, $4, $5) RETURNING {COLUMNS}"
    )))
    .bind(&namespace)
    .bind(&domain)
    .bind(&req.method)
    .bind(proofs::new_token())
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(to_json(&row)))
}

#[utoipa::path(
    delete,
    extensions(("x-required-permission" = json!("system.settings.update")), ("x-resource" = json!("instance"))),
    operation_id = "mcp_delete_namespace_proof",
    path = "/{id}",
    context_path = "/api/v1/admin/mcp/namespace-proofs",
    tag = "mcp",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Proof id")),
    responses(
        (status = 200, description = "Deleted"),
        (status = 403, description = "Not an instance administrator"),
        (status = 404, description = "Unknown proof"),
    )
)]
async fn remove(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    auth.require_admin()?;
    let done = sqlx::query("DELETE FROM mcp_namespace_proofs WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound("Namespace proof not found".into()));
    }
    Ok(())
}

/// Check the proof now (outbound, SSRF-guarded), record and audit the result.
#[utoipa::path(
    post,
    extensions(("x-required-permission" = json!("system.settings.update")), ("x-resource" = json!("instance"))),
    operation_id = "mcp_verify_namespace_proof",
    path = "/{id}/verify",
    context_path = "/api/v1/admin/mcp/namespace-proofs",
    tag = "mcp",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Proof id")),
    responses(
        (status = 200, body = Object, description = "The proof with `status` `verified` or `failed` (`last_error` says why)"),
        (status = 403, description = "Not an instance administrator"),
        (status = 404, description = "Unknown proof"),
    )
)]
async fn verify(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    auth.require_admin()?;
    let proof = fetch(&state, id).await?;
    let outcome = proofs::check(&proof.method, &proof.domain, &proof.token).await;
    let row = record_outcome(&state, &auth, &proof, outcome).await?;
    Ok(Json(to_json(&row)))
}

/// Store a check's outcome and audit it. A failed re-check of a verified
/// proof marks it failed: the owner removed the record.
async fn record_outcome(
    state: &SharedState,
    auth: &AuthExtension,
    proof: &ProofRow,
    outcome: std::result::Result<(), String>,
) -> Result<ProofRow> {
    let (status, error, action) = match &outcome {
        Ok(()) => ("verified", None, AuditAction::McpNamespaceProofVerified),
        Err(e) => (
            "failed",
            Some(e.clone()),
            AuditAction::McpNamespaceProofFailed,
        ),
    };
    let row: ProofRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE mcp_namespace_proofs SET status = $2, last_error = $3, last_checked_at = NOW(), \
         verified_at = CASE WHEN $2 = 'verified' THEN NOW() ELSE NULL END \
         WHERE id = $1 RETURNING {COLUMNS}"
    )))
    .bind(proof.id)
    .bind(status)
    .bind(&error)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    audit_fire_and_forget(
        state.db.clone(),
        AuditEntry::for_principal(action, ResourceType::Setting, auth)
            .resource(proof.id)
            .resource_name(proof.namespace.clone())
            .details(serde_json::json!({
                "proof_id": proof.id,
                "namespace": proof.namespace,
                "domain": proof.domain,
                "method": proof.method,
                "error": error,
            })),
    )
    .await;
    Ok(row)
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    #[test]
    fn create_requests_are_validated() {
        let ok = CreateProof {
            namespace: "Com.Acme".into(),
            method: "dns".into(),
        };
        assert_eq!(
            validate_create(&ok).unwrap(),
            ("com.acme".to_string(), "acme.com".to_string())
        );
        for (ns, m) in [("com.acme", "smtp"), ("acme", "http")] {
            let r = CreateProof {
                namespace: ns.into(),
                method: m.into(),
            };
            assert!(validate_create(&r).is_err(), "{ns} {m}");
        }
    }

    #[tokio::test]
    async fn proof_lifecycle_is_admin_only_and_audited() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, name) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let admin =
            || tdh::router_with_auth_ext(router(), state.clone(), tdh::admin_auth(user, &name));
        let call = |app: Router, method: &str, uri: String, body: Option<serde_json::Value>| {
            let mut b = Request::builder().method(method).uri(uri);
            if body.is_some() {
                b = b.header("content-type", "application/json");
            }
            let body = body
                .map(|v| Body::from(v.to_string()))
                .unwrap_or_else(Body::empty);
            tdh::send(app, b.body(body).unwrap())
        };
        let (s, b) = call(
            admin(),
            "POST",
            "/".into(),
            Some(serde_json::json!({"namespace": "com.example-ak-test", "method": "http"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let created: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(created["status"], "pending");
        assert_eq!(created["domain"], "example-ak-test.com");
        let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        let user_app =
            tdh::router_with_auth_ext(router(), state.clone(), tdh::make_auth(user, &name));
        assert_eq!(
            call(user_app, "GET", "/".into(), None).await.0,
            StatusCode::FORBIDDEN
        );

        let row = fetch(&state, id).await.unwrap();
        let auth = tdh::admin_auth(user, &name);
        let failed = record_outcome(&state, &auth, &row, Err("nope".into()))
            .await
            .unwrap();
        assert_eq!(
            (failed.status.as_str(), failed.last_error.as_deref()),
            ("failed", Some("nope"))
        );
        let ok = record_outcome(&state, &auth, &row, Ok(())).await.unwrap();
        assert!(ok.verified_at.is_some() && ok.last_error.is_none());
        assert!(
            tdh::audit_count_eventually(&pool, id, "MCP_NAMESPACE_PROOF_VERIFIED", 1).await >= 1
        );
        assert!(tdh::audit_count_eventually(&pool, id, "MCP_NAMESPACE_PROOF_FAILED", 1).await >= 1);

        let (s, b) = call(admin(), "GET", format!("/{id}"), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&b).unwrap()["status"],
            "verified"
        );
        assert_eq!(
            call(admin(), "DELETE", format!("/{id}"), None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(admin(), "DELETE", format!("/{id}"), None).await.0,
            StatusCode::NOT_FOUND
        );
        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await;
    }
}
