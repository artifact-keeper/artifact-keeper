//! Webhook management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::webhook_payloads::{self, PayloadTemplate};
use crate::services::webhook_secret_crypto;

/// Versions the backend currently knows how to render. Adding a new
/// version is an additive change; removing one is a breaking change.
const SUPPORTED_EVENT_VERSIONS: &[&str] = &["2026-04-01"];

fn validate_event_version(v: &str) -> std::result::Result<(), AppError> {
    if SUPPORTED_EVENT_VERSIONS.contains(&v) {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "unsupported event_schema_version '{}', supported: {:?}",
            v, SUPPORTED_EVENT_VERSIONS
        )))
    }
}

/// Create webhook routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_webhooks).post(create_webhook))
        .route("/:id", get(get_webhook).delete(delete_webhook))
        .route("/:id/enable", post(enable_webhook))
        .route("/:id/disable", post(disable_webhook))
        .route("/:id/test", post(test_webhook))
        .route("/:id/rotate-secret", post(rotate_webhook_secret))
        .route("/:id/deliveries", get(list_deliveries))
        .route("/:id/deliveries/:delivery_id/redeliver", post(redeliver))
}

/// Pure authorization decision for a webhook, given the two ownership
/// anchors stored on the row (`created_by`, `repository_id`) and whether the
/// caller can access that repository.
///
/// A caller may act on a webhook iff they are an admin, they created it
/// (`created_by == user_id`), or it is attached to a repository they can
/// access (`repo_accessible == true`, as decided by
/// `RepositoryService::user_can_access_repo`). A webhook with no
/// `repository_id` (e.g. a global/system webhook) is reachable only by an
/// admin or its creator — closing the cross-user/cross-tenant BOLA where any
/// authenticated principal could act on any webhook by id.
///
/// This is factored out as a pure function so the authorization invariant
/// can be regression-tested without standing up a Postgres harness; the
/// async wrapper supplies the row and the repo-access bit from the DB.
pub fn webhook_access_allowed(
    is_admin: bool,
    user_id: Uuid,
    created_by: Option<Uuid>,
    repository_id: Option<Uuid>,
    repo_accessible: bool,
) -> bool {
    if is_admin {
        return true;
    }
    if created_by == Some(user_id) {
        return true;
    }
    repository_id.is_some() && repo_accessible
}

/// Authorize the caller to act on a specific webhook.
///
/// Webhooks are not globally accessible: the isolation boundary is the
/// repository (per-repo `role_assignments`) plus resource ownership
/// (`created_by`), the same model the repository handlers enforce. See
/// [`webhook_access_allowed`] for the decision.
///
/// Denials (and missing rows) return `NotFound` rather than `Forbidden` so
/// the endpoint does not leak the existence of other principals' webhooks,
/// matching the existence-hiding convention used elsewhere.
async fn authorize_webhook_access(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
) -> Result<()> {
    use sqlx::Row;
    let row = sqlx::query("SELECT created_by, repository_id FROM webhooks WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    let created_by: Option<Uuid> = row.get("created_by");
    let repository_id: Option<Uuid> = row.get("repository_id");

    // Only consult the (DB-backed) repo-access check when the cheaper
    // admin/owner checks have not already settled the decision.
    let repo_accessible = if auth.is_admin || created_by == Some(auth.user_id) {
        false
    } else if let Some(repo_id) = repository_id {
        let repo_service = state.create_repository_service();
        repo_service
            .user_can_access_repo(repo_id, auth.user_id)
            .await?
    } else {
        false
    };

    if webhook_access_allowed(
        auth.is_admin,
        auth.user_id,
        created_by,
        repository_id,
        repo_accessible,
    ) {
        Ok(())
    } else {
        Err(AppError::NotFound("Webhook not found".to_string()))
    }
}

/// Webhook event types
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    ArtifactUploaded,
    ArtifactDeleted,
    RepositoryCreated,
    RepositoryDeleted,
    UserCreated,
    UserDeleted,
    BuildStarted,
    BuildCompleted,
    BuildFailed,
    AgeGateQueued,
    AgeGateApproved,
    AgeGateRejected,
}

impl std::fmt::Display for WebhookEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookEvent::ArtifactUploaded => write!(f, "artifact_uploaded"),
            WebhookEvent::ArtifactDeleted => write!(f, "artifact_deleted"),
            WebhookEvent::RepositoryCreated => write!(f, "repository_created"),
            WebhookEvent::RepositoryDeleted => write!(f, "repository_deleted"),
            WebhookEvent::UserCreated => write!(f, "user_created"),
            WebhookEvent::UserDeleted => write!(f, "user_deleted"),
            WebhookEvent::BuildStarted => write!(f, "build_started"),
            WebhookEvent::BuildCompleted => write!(f, "build_completed"),
            WebhookEvent::BuildFailed => write!(f, "build_failed"),
            WebhookEvent::AgeGateQueued => write!(f, "age_gate_queued"),
            WebhookEvent::AgeGateApproved => write!(f, "age_gate_approved"),
            WebhookEvent::AgeGateRejected => write!(f, "age_gate_rejected"),
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListWebhooksQuery {
    pub repository_id: Option<Uuid>,
    pub enabled: Option<bool>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    /// Optional caller-supplied secret. When omitted the server generates a
    /// fresh `whsec_*` secret. Either way the raw value is returned in the
    /// 201 response body exactly once and is unrecoverable thereafter.
    pub secret: Option<String>,
    pub repository_id: Option<Uuid>,
    #[schema(value_type = Option<Object>)]
    pub headers: Option<serde_json::Value>,
    /// Payload layout for the target platform (default: generic).
    #[serde(default)]
    pub payload_template: PayloadTemplate,
    /// Pinned event payload version. Defaults to "2026-04-01" when omitted.
    /// Must match a value in `SUPPORTED_EVENT_VERSIONS` or the request is
    /// rejected with HTTP 422.
    pub event_schema_version: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookResponse {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub is_enabled: bool,
    pub repository_id: Option<Uuid>,
    #[schema(value_type = Option<Object>)]
    pub headers: Option<serde_json::Value>,
    pub payload_template: PayloadTemplate,
    /// Pinned event payload version (e.g. "2026-04-01"). Determines the
    /// shape of the rendered payload and the value sent in the
    /// `X-ArtifactKeeper-Event-Version` header.
    pub event_schema_version: String,
    /// Short non-reversible identifier for the current signing secret
    /// (`whsec_...abcd`), suitable for display in operator UIs. The raw
    /// secret is never returned by GET or LIST.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_digest: Option<String>,
    /// True while a previous secret is still accepted by the retry path
    /// during a rotation overlap window.
    #[serde(default)]
    pub secret_rotation_active: bool,
    pub last_triggered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Response returned exactly once when a webhook is created or its secret
/// is rotated. The raw `secret` value is not retrievable afterwards.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookSecretCreatedResponse {
    #[serde(flatten)]
    pub webhook: WebhookResponse,
    /// Raw signing secret. Display this to the operator immediately and
    /// instruct them to record it; the server retains only the encrypted
    /// form and a short digest.
    ///
    /// Absent when the webhook was created without a signing secret. This
    /// happens when no secret was supplied and the deployment has no
    /// `AK_WEBHOOK_SECRET_KEY` configured: rather than fail the create with
    /// a 500, the webhook is stored unsigned and deliveries omit the
    /// signature header. Configure the key and rotate the secret later to
    /// enable signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// Response returned by the rotate-secret endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct RotateWebhookSecretResponse {
    pub id: Uuid,
    /// Raw signing secret produced by this rotation. Shown exactly once.
    pub secret: String,
    pub secret_digest: String,
    /// When the previously active secret stops being accepted.
    pub previous_secret_expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookListResponse {
    pub items: Vec<WebhookResponse>,
    pub total: i64,
}

/// List webhooks
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(ListWebhooksQuery),
    responses(
        (status = 200, description = "List of webhooks", body = WebhookListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_webhooks(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ListWebhooksQuery>,
) -> Result<Json<WebhookListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    use sqlx::Row;

    // Scope the listing to webhooks the caller is authorized to see. Admins
    // see everything; non-admins see only webhooks they created or that are
    // attached to a repository they can access (mirrors
    // `user_can_access_repo`, including the global `repository_id IS NULL`
    // role grant). `$5` is NULL for admins, which disables the predicate.
    let scope_user: Option<Uuid> = if auth.is_admin {
        None
    } else {
        Some(auth.user_id)
    };

    // The scope predicate is parameterized on a single user id whose
    // position differs between the list query ($5) and the count query ($3).
    // It is NULL for admins, which disables the predicate entirely.
    fn scope_sql(user_param: &str) -> String {
        format!(
            "({u}::uuid IS NULL \
             OR created_by = {u} \
             OR repository_id IN ( \
                 SELECT repository_id FROM role_assignments \
                 WHERE user_id = {u} AND repository_id IS NOT NULL \
             ) \
             OR EXISTS ( \
                 SELECT 1 FROM role_assignments \
                 WHERE user_id = {u} AND repository_id IS NULL \
             ))",
            u = user_param
        )
    }

    let webhooks = sqlx::query(&format!(
        r#"
        SELECT id, name, url, events, is_enabled, repository_id, headers,
               payload_template, event_schema_version, secret_digest,
               secret_previous_expires_at, last_triggered_at, created_at
        FROM webhooks
        WHERE ($1::uuid IS NULL OR repository_id = $1)
          AND ($2::boolean IS NULL OR is_enabled = $2)
          AND {scope}
        ORDER BY name
        OFFSET $3
        LIMIT $4
        "#,
        scope = scope_sql("$5"),
    ))
    .bind(query.repository_id)
    .bind(query.enabled)
    .bind(offset)
    .bind(per_page as i64)
    .bind(scope_user)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total_row = sqlx::query(&format!(
        r#"
        SELECT COUNT(*) as count
        FROM webhooks
        WHERE ($1::uuid IS NULL OR repository_id = $1)
          AND ($2::boolean IS NULL OR is_enabled = $2)
          AND {scope}
        "#,
        scope = scope_sql("$3"),
    ))
    .bind(query.repository_id)
    .bind(query.enabled)
    .bind(scope_user)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    let total: i64 = total_row.get("count");

    let items = webhooks
        .into_iter()
        .map(|w| {
            let tpl: String = w.get("payload_template");
            let prev_expires: Option<chrono::DateTime<chrono::Utc>> =
                w.get("secret_previous_expires_at");
            WebhookResponse {
                id: w.get("id"),
                name: w.get("name"),
                url: w.get("url"),
                events: w.get("events"),
                is_enabled: w.get("is_enabled"),
                repository_id: w.get("repository_id"),
                headers: w.get("headers"),
                payload_template: PayloadTemplate::from_str_lossy(&tpl),
                event_schema_version: w.get("event_schema_version"),
                secret_digest: w.get("secret_digest"),
                secret_rotation_active: prev_expires
                    .map(|e| e > chrono::Utc::now())
                    .unwrap_or(false),
                last_triggered_at: w.get("last_triggered_at"),
                created_at: w.get("created_at"),
            }
        })
        .collect();

    Ok(Json(WebhookListResponse { items, total }))
}

/// Create webhook.
///
/// Generates a fresh signing secret (or accepts a caller-supplied one),
/// encrypts it at rest, and returns the raw secret in the response body
/// **once**. After this call, GET on the webhook returns only
/// `secret_digest`, never the raw secret.
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    request_body = CreateWebhookRequest,
    responses(
        (status = 200, description = "Webhook created. Body includes the raw secret exactly once (omitted when created unsigned).", body = WebhookSecretCreatedResponse),
        (status = 422, description = "Validation error, including: a secret was supplied but AK_WEBHOOK_SECRET_KEY is not configured, so the secret cannot be encrypted at rest (create the webhook without a secret, or have an administrator configure the signing key)"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_webhook(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookSecretCreatedResponse>> {
    // #2321 G4: creating an outbound webhook provisions an egress target and a
    // signing secret — a global integration/security action, not something any
    // authenticated user should do. Require admin BEFORE URL validation, secret
    // generation, or any DB write, and record the RBAC-deny. Read/list webhook
    // handlers are unchanged (non-admin owners keep their existing read access).
    crate::services::audit_service::enforce_admin_audited(
        auth.is_admin,
        state.db.clone(),
        auth.user_id,
        crate::services::audit_service::ResourceType::Setting,
        "/api/v1/webhooks",
        "POST",
    )
    .await?;

    // Validate URL (SSRF prevention)
    validate_webhook_url(&payload.url)?;

    // Validate events
    if payload.events.is_empty() {
        return Err(AppError::Validation(
            "At least one event required".to_string(),
        ));
    }

    let event_version = payload
        .event_schema_version
        .as_deref()
        .unwrap_or("2026-04-01")
        .to_string();
    validate_event_version(&event_version)?;

    // Decide how to handle the signing secret. The key insight (B4): a
    // normal create with no secret and no `AK_WEBHOOK_SECRET_KEY` must
    // succeed without storing any secret rather than 500ing. Encryption
    // is only attempted when a secret is actually going to be stored AND
    // a key is configured. See `prepare_secret_for_storage`.
    let key_configured = webhook_secret_crypto::ensure_configured().is_ok();
    let prepared = prepare_secret_for_storage(
        payload.secret.as_deref(),
        key_configured,
        webhook_secret_crypto::generate_secret,
    )?;

    use sqlx::Row;

    let template_str = payload.payload_template.to_string();
    let webhook = sqlx::query(
        r#"
        INSERT INTO webhooks
            (name, url, events, repository_id, headers, payload_template,
             secret_encrypted, secret_digest, event_schema_version, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, name, url, events, is_enabled, repository_id, headers,
                  payload_template, event_schema_version, secret_digest,
                  secret_previous_expires_at, last_triggered_at, created_at
        "#,
    )
    .bind(&payload.name)
    .bind(&payload.url)
    .bind(&payload.events)
    .bind(payload.repository_id)
    .bind(&payload.headers)
    .bind(&template_str)
    .bind(prepared.encrypted.as_deref())
    .bind(prepared.digest.as_deref())
    .bind(&event_version)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let tpl: String = webhook.get("payload_template");
    let prev_expires: Option<chrono::DateTime<chrono::Utc>> =
        webhook.get("secret_previous_expires_at");
    let response = WebhookResponse {
        id: webhook.get("id"),
        name: webhook.get("name"),
        url: webhook.get("url"),
        events: webhook.get("events"),
        is_enabled: webhook.get("is_enabled"),
        repository_id: webhook.get("repository_id"),
        headers: webhook.get("headers"),
        payload_template: PayloadTemplate::from_str_lossy(&tpl),
        event_schema_version: webhook.get("event_schema_version"),
        secret_digest: webhook.get("secret_digest"),
        secret_rotation_active: prev_expires
            .map(|e| e > chrono::Utc::now())
            .unwrap_or(false),
        last_triggered_at: webhook.get("last_triggered_at"),
        created_at: webhook.get("created_at"),
    };

    Ok(Json(WebhookSecretCreatedResponse {
        webhook: response,
        secret: prepared.raw_secret,
    }))
}

/// What a create request should store for the webhook signing secret, and
/// the raw secret (if any) to surface back to the caller exactly once.
///
/// All three fields are `None` together when the webhook is stored without
/// a signing secret.
#[derive(Debug, Default)]
struct PreparedSecret {
    /// Raw secret to return in the 201 body once; `None` when unsigned.
    raw_secret: Option<String>,
    /// AES-GCM ciphertext for the `secret_encrypted` column; `None` when unsigned.
    encrypted: Option<Vec<u8>>,
    /// Display digest for the `secret_digest` column; `None` when unsigned.
    digest: Option<String>,
}

/// Decide what to do with a webhook's signing secret at create time, and
/// perform the encryption when (and only when) a secret will actually be
/// stored.
///
/// Behavior (B4 fix):
/// - Caller supplied a secret, key configured: encrypt and store it.
/// - Caller supplied a secret, NO key configured: return a clear
///   `Validation` (4xx) error, never a bare 500 or a retryable 503. The
///   caller asked to sign but the deployment cannot encrypt the secret at
///   rest; this is a permanent client-side condition, and the secret is
///   never stored in the clear.
/// - No secret supplied, key configured: generate a fresh secret, encrypt
///   and store it (preserves the pre-fix signing-by-default behavior).
/// - No secret supplied, NO key configured: store nothing. The webhook is
///   created unsigned and the create returns 201. This is the path that
///   the release-gate test cluster hits, and the one that previously 500'd.
///
/// `gen_secret` is injected so unit tests can avoid pulling in the CSPRNG
/// and assert on a deterministic value.
fn prepare_secret_for_storage(
    supplied_secret: Option<&str>,
    key_configured: bool,
    gen_secret: impl FnOnce() -> String,
) -> Result<PreparedSecret> {
    // Treat an empty/whitespace-only supplied secret as "no secret".
    let supplied = supplied_secret.filter(|s| !s.trim().is_empty());

    let raw_secret = match (supplied, key_configured) {
        // Caller wants signing but the deployment has no signing key, so the
        // secret cannot be encrypted at rest. This is a permanent client-side
        // condition, not a transient server fault: returning 503 wrongly
        // implies the request is retryable and drives CI retry loops. Surface
        // a clear validation (4xx) error and never store the secret in the
        // clear. Enabling signing is an operator action (see #950).
        (Some(_), false) => {
            return Err(AppError::Validation(
                "webhook secret signing is not enabled on this deployment \
                 (AK_WEBHOOK_SECRET_KEY is unset); create the webhook without \
                 a secret, or ask an administrator to configure the signing key"
                    .to_string(),
            ));
        }
        // Caller supplied a secret and we can encrypt it.
        (Some(s), true) => s.to_string(),
        // No secret supplied but a key exists: sign by default.
        (None, true) => gen_secret(),
        // No secret supplied and no key: store unsigned, succeed.
        (None, false) => return Ok(PreparedSecret::default()),
    };

    let encrypted = webhook_secret_crypto::encrypt_secret(&raw_secret).map_err(|e| {
        // ensure_configured() said the key was present, so a failure here is
        // a genuine crypto/config fault, not the routine "no key" path.
        tracing::error!("webhook secret encryption failed: {}", e);
        AppError::Internal("webhook secret encryption failed".to_string())
    })?;
    let digest = webhook_secret_crypto::digest_for_display(&raw_secret);

    Ok(PreparedSecret {
        raw_secret: Some(raw_secret),
        encrypted: Some(encrypted),
        digest: Some(digest),
    })
}

/// Get webhook by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Webhook details", body = WebhookResponse),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_webhook(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<WebhookResponse>> {
    authorize_webhook_access(&state, &auth, id).await?;

    use sqlx::Row;

    let webhook = sqlx::query(
        r#"
        SELECT id, name, url, events, is_enabled, repository_id, headers,
               payload_template, event_schema_version, secret_digest,
               secret_previous_expires_at, last_triggered_at, created_at
        FROM webhooks
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    let tpl: String = webhook.get("payload_template");
    let prev_expires: Option<chrono::DateTime<chrono::Utc>> =
        webhook.get("secret_previous_expires_at");
    Ok(Json(WebhookResponse {
        id: webhook.get("id"),
        name: webhook.get("name"),
        url: webhook.get("url"),
        events: webhook.get("events"),
        is_enabled: webhook.get("is_enabled"),
        repository_id: webhook.get("repository_id"),
        headers: webhook.get("headers"),
        payload_template: PayloadTemplate::from_str_lossy(&tpl),
        event_schema_version: webhook.get("event_schema_version"),
        secret_digest: webhook.get("secret_digest"),
        secret_rotation_active: prev_expires
            .map(|e| e > chrono::Utc::now())
            .unwrap_or(false),
        last_triggered_at: webhook.get("last_triggered_at"),
        created_at: webhook.get("created_at"),
    }))
}

/// Delete webhook
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Webhook deleted successfully"),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_webhook(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    authorize_webhook_access(&state, &auth, id).await?;

    let result = sqlx::query!("DELETE FROM webhooks WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    Ok(())
}

/// Set webhook enabled state, returning NotFound if the webhook does not exist.
async fn set_webhook_enabled(state: &SharedState, id: Uuid, enabled: bool) -> Result<()> {
    let result = sqlx::query("UPDATE webhooks SET is_enabled = $2 WHERE id = $1")
        .bind(id)
        .bind(enabled)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    Ok(())
}

/// Enable webhook
#[utoipa::path(
    post,
    path = "/{id}/enable",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Webhook enabled successfully"),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_webhook(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    authorize_webhook_access(&state, &auth, id).await?;
    set_webhook_enabled(&state, id, true).await
}

/// Disable webhook
#[utoipa::path(
    post,
    path = "/{id}/disable",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Webhook disabled successfully"),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_webhook(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    authorize_webhook_access(&state, &auth, id).await?;
    set_webhook_enabled(&state, id, false).await
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TestWebhookResponse {
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
    pub error: Option<String>,
}

/// Test webhook by sending a test payload
#[utoipa::path(
    post,
    path = "/{id}/test",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Test delivery result", body = TestWebhookResponse),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_webhook(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<TestWebhookResponse>> {
    authorize_webhook_access(&state, &auth, id).await?;

    use sqlx::Row;

    let webhook = sqlx::query(
        "SELECT url, headers, payload_template, event_schema_version \
         FROM webhooks WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    let url: String = webhook.get("url");
    let headers: Option<serde_json::Value> = webhook.get("headers");
    let tpl_str: String = webhook.get("payload_template");
    let template = PayloadTemplate::from_str_lossy(&tpl_str);
    let event_version: String = webhook
        .try_get::<Option<String>, _>("event_schema_version")
        .ok()
        .flatten()
        .unwrap_or_else(|| "2026-04-01".to_string());

    // Create test payload using the configured template
    let test_details = serde_json::json!({
        "message": "This is a test webhook delivery"
    });
    let timestamp = chrono::Utc::now().to_rfc3339();
    let payload = webhook_payloads::render_payload(template, "test", &test_details, &timestamp);

    // Re-validate URL at delivery time to prevent DNS rebinding attacks
    validate_webhook_url(&url)?;

    // Serialize once so the bytes we sign are exactly the bytes we POST.
    let body_bytes = serde_json::to_vec(&payload).map_err(|e| AppError::Internal(e.to_string()))?;

    let unix_secs = chrono::Utc::now().timestamp();
    let secrets = load_active_secrets(&state.db, id).await.unwrap_or_default();
    let secret_refs: Vec<&str> = secrets.iter().map(|s| s.as_str()).collect();

    // Test deliveries have no `webhook_deliveries` row; mint a fresh
    // delivery id so receivers still get a unique correlation handle.
    let test_delivery_id = Uuid::new_v4();

    // Send webhook
    let client = crate::services::http_client::default_client();
    let header_inputs = DeliveryHeaderInputs {
        delivery_id: test_delivery_id,
        event: "test",
        event_version: &event_version,
        retry_attempt: None,
        custom_headers: headers.as_ref(),
        secrets: &secret_refs,
        unix_secs,
        body_bytes: &body_bytes,
    };
    let mut request = client.post(&url);
    for (name, value) in build_delivery_request_headers(&header_inputs) {
        request = request.header(name, value);
    }

    match request.body(body_bytes).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.ok();

            Ok(Json(TestWebhookResponse {
                success: (200..300).contains(&status),
                status_code: Some(status),
                response_body: body,
                error: None,
            }))
        }
        Err(e) => Ok(Json(TestWebhookResponse {
            success: false,
            status_code: None,
            response_body: None,
            error: Some(e.to_string()),
        })),
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListDeliveriesQuery {
    pub status: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryResponse {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event: String,
    #[schema(value_type = Object)]
    pub payload: serde_json::Value,
    pub response_status: Option<i32>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempts: i32,
    pub delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryListResponse {
    pub items: Vec<DeliveryResponse>,
    pub total: i64,
}

/// List webhook deliveries
#[utoipa::path(
    get,
    path = "/{id}/deliveries",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID"),
        ListDeliveriesQuery,
    ),
    responses(
        (status = 200, description = "List of webhook deliveries", body = DeliveryListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_deliveries(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(webhook_id): Path<Uuid>,
    Query(query): Query<ListDeliveriesQuery>,
) -> Result<Json<DeliveryListResponse>> {
    // Deliveries inherit the authorization of their parent webhook.
    authorize_webhook_access(&state, &auth, webhook_id).await?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let success_filter = query.status.as_ref().map(|s| s == "success");

    let deliveries = sqlx::query!(
        r#"
        SELECT id, webhook_id, event, payload, response_status, response_body, success, attempts, delivered_at, created_at
        FROM webhook_deliveries
        WHERE webhook_id = $1
          AND ($2::boolean IS NULL OR success = $2)
        ORDER BY created_at DESC
        OFFSET $3
        LIMIT $4
        "#,
        webhook_id,
        success_filter,
        offset,
        per_page as i64
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM webhook_deliveries
        WHERE webhook_id = $1
          AND ($2::boolean IS NULL OR success = $2)
        "#,
        webhook_id,
        success_filter
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let items = deliveries
        .into_iter()
        .map(|d| DeliveryResponse {
            id: d.id,
            webhook_id: d.webhook_id,
            event: d.event,
            payload: d.payload,
            response_status: d.response_status,
            response_body: d.response_body,
            success: d.success,
            attempts: d.attempts,
            delivered_at: d.delivered_at,
            created_at: d.created_at,
        })
        .collect();

    Ok(Json(DeliveryListResponse { items, total }))
}

/// Redeliver a failed webhook
#[utoipa::path(
    post,
    path = "/{id}/deliveries/{delivery_id}/redeliver",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID"),
        ("delivery_id" = Uuid, Path, description = "Delivery ID"),
    ),
    responses(
        (status = 200, description = "Redelivery result", body = DeliveryResponse),
        (status = 404, description = "Webhook or delivery not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn redeliver(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((webhook_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliveryResponse>> {
    authorize_webhook_access(&state, &auth, webhook_id).await?;

    // Get original delivery
    let delivery = sqlx::query!(
        r#"
        SELECT id, webhook_id, event, payload
        FROM webhook_deliveries
        WHERE id = $1 AND webhook_id = $2
        "#,
        delivery_id,
        webhook_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Delivery not found".to_string()))?;

    // Get webhook details. Uses sqlx::query (not the macro) so we don't
    // need to regenerate the offline cache for the new
    // `event_schema_version` column added in migration 084. Signing-secret
    // material is loaded separately via `load_active_secrets`.
    use sqlx::Row;
    let webhook_row =
        sqlx::query("SELECT url, headers, event_schema_version FROM webhooks WHERE id = $1")
            .bind(webhook_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    let webhook_url: String = webhook_row.get("url");
    let webhook_headers: Option<serde_json::Value> = webhook_row.get("headers");
    let event_version: String = webhook_row
        .try_get::<Option<String>, _>("event_schema_version")
        .ok()
        .flatten()
        .unwrap_or_else(|| "2026-04-01".to_string());

    // Re-validate URL at delivery time to prevent DNS rebinding attacks
    validate_webhook_url(&webhook_url)?;

    // Serialize once so the bytes we sign are exactly the bytes we POST.
    let body_bytes =
        serde_json::to_vec(&delivery.payload).map_err(|e| AppError::Internal(e.to_string()))?;

    let unix_secs = chrono::Utc::now().timestamp();
    let secrets = load_active_secrets(&state.db, webhook_id)
        .await
        .unwrap_or_default();
    let secret_refs: Vec<&str> = secrets.iter().map(|s| s.as_str()).collect();

    // Send webhook
    let client = crate::services::http_client::default_client();
    let header_inputs = DeliveryHeaderInputs {
        delivery_id,
        event: &delivery.event,
        event_version: &event_version,
        retry_attempt: None,
        custom_headers: webhook_headers.as_ref(),
        secrets: &secret_refs,
        unix_secs,
        body_bytes: &body_bytes,
    };
    let mut request = client.post(&webhook_url);
    for (name, value) in build_delivery_request_headers(&header_inputs) {
        request = request.header(name, value);
    }

    let (success, response_status, response_body) = match request.body(body_bytes).send().await {
        Ok(response) => {
            let status = response.status().as_u16() as i32;
            let body = response.text().await.ok();
            ((200..300).contains(&status), Some(status), body)
        }
        Err(e) => (false, None, Some(e.to_string())),
    };

    // Update delivery record
    let updated = sqlx::query!(
        r#"
        UPDATE webhook_deliveries
        SET
            response_status = $2,
            response_body = $3,
            success = $4,
            attempts = attempts + 1,
            delivered_at = CASE WHEN $4 THEN NOW() ELSE delivered_at END
        WHERE id = $1
        RETURNING id, webhook_id, event, payload, response_status, response_body, success, attempts, delivered_at, created_at
        "#,
        delivery_id,
        response_status,
        response_body,
        success
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(DeliveryResponse {
        id: updated.id,
        webhook_id: updated.webhook_id,
        event: updated.event,
        payload: updated.payload,
        response_status: updated.response_status,
        response_body: updated.response_body,
        success: updated.success,
        attempts: updated.attempts,
        delivered_at: updated.delivered_at,
        created_at: updated.created_at,
    }))
}

/// Length of the rotation overlap window. Both the previous and the
/// current secret are accepted by the retry path during this window.
const SECRET_ROTATION_OVERLAP: chrono::Duration = chrono::Duration::hours(24);

/// Pure helper that mirrors the SQL WHERE clause guarding the rotate
/// endpoint. Returns `true` iff a rotation should be allowed for a row
/// whose `secret_previous_expires_at` column currently holds `previous`.
///
/// This exists so the unit tests can pin the rotation-window semantics
/// without standing up a Postgres test harness. The SQL UPDATE in
/// `rotate_webhook_secret` and this helper must agree.
#[cfg(test)]
fn rotation_guard_allows(
    previous: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match previous {
        None => true,
        Some(expires_at) => expires_at < now,
    }
}

/// Rotate the signing secret for a webhook.
///
/// Generates a new raw secret, encrypts it, moves the existing
/// `secret_encrypted` into `secret_previous_encrypted`, and stamps an
/// expiry 24 hours in the future. The new raw secret is returned in the
/// response body **once**. The HMAC signing path (added in a later ticket)
/// signs deliveries with both secrets while the previous one is within
/// its expiry window so consumers can rotate without dropped events.
///
/// If a previous-secret window is still active when the rotate request
/// arrives, the request is REJECTED with HTTP 409 Conflict. This prevents
/// two near-simultaneous rotations from clobbering the original
/// `secret_previous_encrypted` material before the operator has finished
/// distributing the previous new key. The 409 body is structured:
/// `{"error": "rotation_already_in_progress", "expires_at": "<RFC3339>"}`.
#[utoipa::path(
    post,
    path = "/{id}/rotate-secret",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Secret rotated. Body includes the new raw secret exactly once.", body = RotateWebhookSecretResponse),
        (status = 404, description = "Webhook not found"),
        (status = 409, description = "A previous rotation overlap window is still active"),
        (status = 500, description = "Encryption key not configured")
    ),
    security(("bearer_auth" = []))
)]
pub async fn rotate_webhook_secret(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;

    authorize_webhook_access(&state, &auth, id).await?;

    let new_secret = webhook_secret_crypto::generate_secret();
    let new_encrypted = webhook_secret_crypto::encrypt_secret(&new_secret).map_err(|e| {
        tracing::error!("webhook secret encryption failed during rotation: {}", e);
        AppError::Internal("webhook secret encryption is not configured".to_string())
    })?;
    let new_digest = webhook_secret_crypto::digest_for_display(&new_secret);
    let now = chrono::Utc::now();
    let previous_expires_at = now + SECRET_ROTATION_OVERLAP;

    // Conditional UPDATE: only proceed if no rotation overlap is currently
    // active. A row passes the guard when its `secret_previous_expires_at`
    // is NULL (never rotated, or the cleanup job has already cleared it)
    // or already in the past. If the WHERE clause excludes the row we get
    // 0 rows updated and respond 409 with the active expiry timestamp.
    let updated = sqlx::query_scalar::<_, Uuid>(
        r#"
        UPDATE webhooks
        SET
            secret_previous_encrypted   = secret_encrypted,
            secret_previous_expires_at  = CASE
                WHEN secret_encrypted IS NOT NULL THEN $2
                ELSE NULL
            END,
            secret_encrypted            = $3,
            secret_digest               = $4,
            secret_rotation_started_at  = $5,
            updated_at                  = NOW()
        WHERE id = $1
          AND (secret_previous_expires_at IS NULL OR secret_previous_expires_at < NOW())
        RETURNING id
        "#,
    )
    .bind(id)
    .bind(previous_expires_at)
    .bind(&new_encrypted)
    .bind(&new_digest)
    .bind(now)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if updated.is_none() {
        // Either the row is missing or the rotation guard failed. Disambiguate
        // by reading the row's `secret_previous_expires_at` directly; the read
        // is cheap and the 409 body needs the active expiry timestamp anyway.
        let active = sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
            "SELECT secret_previous_expires_at FROM webhooks WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        return match active {
            None => Err(AppError::NotFound("Webhook not found".to_string())),
            Some(maybe_expires) => match maybe_expires {
                Some(expires_at) if expires_at >= chrono::Utc::now() => {
                    let body = serde_json::json!({
                        "error": "rotation_already_in_progress",
                        "expires_at": expires_at,
                    });
                    Ok((axum::http::StatusCode::CONFLICT, Json(body)).into_response())
                }
                // Should not happen: a NULL or past expiry means the UPDATE
                // would have succeeded. Fall back to a generic 409 rather
                // than racing again automatically.
                _ => {
                    let body = serde_json::json!({
                        "error": "rotation_already_in_progress",
                        "expires_at": serde_json::Value::Null,
                    });
                    Ok((axum::http::StatusCode::CONFLICT, Json(body)).into_response())
                }
            },
        };
    }

    Ok(Json(RotateWebhookSecretResponse {
        id,
        secret: new_secret,
        secret_digest: new_digest,
        previous_secret_expires_at: previous_expires_at,
    })
    .into_response())
}

/// Background-task entry point: clear expired previous-secret material so
/// stale ciphertext does not linger past the rotation overlap window.
///
/// Returns the number of rows updated. Safe to call from a scheduler tick.
pub async fn cleanup_expired_previous_secrets(
    db: &sqlx::PgPool,
) -> std::result::Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE webhooks
        SET secret_previous_encrypted  = NULL,
            secret_previous_expires_at = NULL
        WHERE secret_previous_encrypted IS NOT NULL
          AND secret_previous_expires_at IS NOT NULL
          AND secret_previous_expires_at <= NOW()
        "#,
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

/// Validate a webhook URL to prevent SSRF attacks.
///
/// Blocks URLs pointing to private/internal networks, loopback addresses,
/// link-local addresses (AWS/cloud metadata), and known internal hostnames.
///
/// Reads `WEBHOOK_ALLOW_PRIVATE_IPS` (not `UPSTREAM_ALLOW_PRIVATE_IPS`)
/// for the RFC1918 / IPv6 unique-local relaxation toggle. Split from the
/// upstream env var in issue #1435 so a test cluster that needs to allow
/// webhook deliveries to a local mock receiver does not also relax the
/// SSRF guard on the remote-proxy upstream path.
fn validate_webhook_url(url_str: &str) -> Result<()> {
    crate::api::validation::validate_outbound_webhook_url(url_str, "Webhook URL")
}

/// Whether a webhook row carries any form of signing secret.
///
/// `secret_encrypted` (AES-GCM, E1) is the authoritative new form. The
/// legacy bcrypt `secret_hash` column is kept around so pre-v1.1.9 rows
/// that have not yet been rotated continue to advertise that they are
/// configured for signing. Returns `true` iff at least one form is set
/// to a non-empty value. Rows where both are NULL or empty are treated
/// as "no signing configured" and the retry path omits the
/// `X-Webhook-Signature` header entirely.
///
/// Retained for one release after E2 wired up real HMAC signing in
/// `process_webhook_retries`/`redeliver`/`test_webhook` (which now use
/// `load_active_secrets` directly). External call sites and tests may
/// still reference this helper. Removed in v1.3.0.
#[allow(dead_code)]
fn has_signing_secret(secret_hash: &Option<String>, secret_encrypted: Option<&[u8]>) -> bool {
    let hash_present = secret_hash.as_deref().is_some_and(|s| !s.is_empty());
    let enc_present = secret_encrypted.is_some_and(|b| !b.is_empty());
    hash_present || enc_present
}

/// V2 retry schedule: 12 attempts, jittered exponential, capped near 24h.
/// `attempt` is 1-indexed (the attempt number we are scheduling).
///
/// Schedule (without jitter): 30s, 1m, 2m, 5m, 10m, 30m, 1h, 2h, 4h, 8h,
/// 16h, 24h. Total max retry window: ~37h, but most failures resolve in
/// the first hour. Each computed delay is jittered +/- 20% so a herd of
/// receivers that all fail at the same instant don't synchronize their
/// next retry.
fn webhook_retry_delay_secs(attempt: i32) -> i64 {
    let base = base_delay_secs(attempt);
    apply_jitter(base, deterministic_jitter_seed(attempt))
}

/// Pure base-schedule lookup, exposed for tests so they can pin the
/// schedule without dealing with jitter randomness.
fn base_delay_secs(attempt: i32) -> i64 {
    match attempt {
        1 => 30,
        2 => 60,
        3 => 120,
        4 => 300,
        5 => 600,
        6 => 1_800,
        7 => 3_600,
        8 => 7_200,
        9 => 14_400,
        10 => 28_800,
        11 => 57_600,
        _ => 86_400,
    }
}

/// Apply +/- 20% jitter to a base delay. A `seed` of 0 returns the base
/// unchanged so unit tests can opt out of randomness.
fn apply_jitter(base: i64, seed: u64) -> i64 {
    if seed == 0 {
        return base;
    }
    let span = (base / 5).max(1);
    let mag = (seed as i64).rem_euclid(span);
    let delta = if seed & 1 == 0 { mag } else { -mag };
    (base + delta).max(1)
}

/// Cheap PRNG seed used at runtime; tests can pass 0 to disable jitter.
fn deterministic_jitter_seed(attempt: i32) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos
        .wrapping_add(attempt as u64)
        .wrapping_mul(2_654_435_761)
}

/// Outcome of a webhook delivery retry attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RetryOutcome {
    /// Delivery succeeded (2xx status).
    Success,
    /// Max attempts exhausted, delivery is dead-lettered.
    DeadLetter,
    /// Should retry after the given delay in seconds.
    Retry { delay_secs: i64 },
}

/// Determine the outcome of a webhook delivery attempt.
///
/// Given the current attempt count, max attempts, and whether the HTTP call
/// succeeded, returns whether to mark success, dead-letter, or schedule a retry.
fn determine_retry_outcome(
    success: bool,
    current_attempts: i32,
    max_attempts: i32,
) -> RetryOutcome {
    let new_attempts = current_attempts + 1;
    if success {
        RetryOutcome::Success
    } else if new_attempts >= max_attempts {
        RetryOutcome::DeadLetter
    } else {
        RetryOutcome::Retry {
            delay_secs: webhook_retry_delay_secs(new_attempts),
        }
    }
}

/// Check whether an HTTP status code indicates a successful webhook delivery.
fn is_webhook_delivery_success(status_code: u16) -> bool {
    (200..300).contains(&status_code)
}

/// A row from the webhook_deliveries retry queue.
#[derive(Debug)]
struct RetryDeliveryRow {
    pub id: uuid::Uuid,
    pub webhook_id: uuid::Uuid,
    pub event: String,
    pub payload: serde_json::Value,
    pub attempts: i32,
    pub max_attempts: i32,
}

/// Inputs to the v2-wire-contract header builder. Captured as a struct so
/// the three delivery paths (test endpoint, retry path, manual redeliver)
/// can share one well-tested header set.
struct DeliveryHeaderInputs<'a> {
    pub delivery_id: Uuid,
    pub event: &'a str,
    pub event_version: &'a str,
    /// `Some(n)` on the retry path (1-indexed), `None` on the test/redeliver paths.
    pub retry_attempt: Option<i32>,
    /// Caller-supplied custom headers from the webhook row's `headers` JSON.
    pub custom_headers: Option<&'a serde_json::Value>,
    /// Webhook secrets ordered current-first. Empty means "no signing
    /// configured" and the signature header is omitted.
    pub secrets: &'a [&'a str],
    /// `t=<unix_secs>` value embedded in the signature header. Caller MUST
    /// pass the same value to `webhook_signing::render_header`.
    pub unix_secs: i64,
    /// Bytes that will be POSTed. Must equal the bytes signed by
    /// `webhook_signing::render_header`.
    pub body_bytes: &'a [u8],
}

/// Build the full ordered header set for a v2 webhook delivery. Returns
/// `(header_name, header_value)` pairs so callers can fold them into a
/// `reqwest::RequestBuilder` or assert against them in tests. The order
/// matches the spec: required headers first, custom headers second,
/// signature headers last.
fn build_delivery_request_headers(inputs: &DeliveryHeaderInputs<'_>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(16);

    out.push(("Content-Type".into(), "application/json".into()));
    // v2 headers
    out.push((
        "X-ArtifactKeeper-Delivery".into(),
        inputs.delivery_id.to_string(),
    ));
    out.push(("X-ArtifactKeeper-Event".into(), inputs.event.into()));
    out.push((
        "X-ArtifactKeeper-Event-Version".into(),
        inputs.event_version.into(),
    ));
    if let Some(attempt) = inputs.retry_attempt {
        out.push(("X-ArtifactKeeper-Retry-Attempt".into(), attempt.to_string()));
    }
    // legacy headers (dropped in v1.3.0)
    out.push(("X-Webhook-Event".into(), inputs.event.into()));
    out.push(("X-Webhook-Delivery".into(), inputs.delivery_id.to_string()));
    if let Some(attempt) = inputs.retry_attempt {
        out.push(("X-Webhook-Retry-Attempt".into(), attempt.to_string()));
    }

    // Custom headers from the webhook row.
    if let Some(h) = inputs.custom_headers {
        if let Some(obj) = h.as_object() {
            for (key, value) in obj {
                if let Some(v) = value.as_str() {
                    out.push((key.clone(), v.to_string()));
                }
            }
        }
    }

    // Signature headers (if configured).
    if !inputs.secrets.is_empty() {
        let sig_header = crate::services::webhook_signing::render_header(
            inputs.unix_secs,
            inputs.body_bytes,
            inputs.secrets,
        );
        out.push(("X-ArtifactKeeper-Signature".into(), sig_header));
        let legacy_sig = crate::services::webhook_signing::compute_v1_signature(
            inputs.secrets[0],
            inputs.unix_secs,
            inputs.body_bytes,
        );
        out.push((
            "X-Webhook-Signature".into(),
            format!("sha256={}", legacy_sig),
        ));
    }

    out
}

/// Pure decision logic for `load_active_secrets`. Takes the already-loaded
/// encrypted bytes and the previous-secret expiry, decrypts each via
/// `webhook_secret_crypto::decrypt_secret`, and returns the surfaced
/// secrets in current-first order. Bytes that are empty or that fail to
/// decrypt are silently skipped (with a tracing::warn from the I/O
/// wrapper); this function does no logging itself so unit tests can pin
/// behavior without intercepting tracing output.
///
/// Returns a tuple `(secrets, decrypt_failures)` so the wrapper can log
/// each failure with a stable message format. The Vec contents matter
/// for the wire contract; the failure count is purely diagnostic.
fn decide_active_secrets(
    current_encrypted: Option<&[u8]>,
    previous_encrypted: Option<&[u8]>,
    previous_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> (Vec<String>, usize) {
    let mut out: Vec<String> = Vec::with_capacity(2);
    let mut failures: usize = 0;

    if let Some(bytes) = current_encrypted {
        if !bytes.is_empty() {
            match webhook_secret_crypto::decrypt_secret(bytes) {
                Ok(s) => out.push(s),
                Err(_) => failures += 1,
            }
        }
    }

    if let (Some(bytes), Some(exp)) = (previous_encrypted, previous_expires_at) {
        if !bytes.is_empty() && exp > now {
            match webhook_secret_crypto::decrypt_secret(bytes) {
                Ok(s) => out.push(s),
                Err(_) => failures += 1,
            }
        }
    }

    (out, failures)
}

/// Load and decrypt the secrets that should currently sign deliveries
/// for the given webhook row. Thin I/O wrapper around
/// `decide_active_secrets`. See that function for the decision logic.
async fn load_active_secrets(
    db: &sqlx::PgPool,
    webhook_id: Uuid,
) -> std::result::Result<Vec<String>, String> {
    use sqlx::Row;

    let row = sqlx::query(
        r#"
        SELECT secret_encrypted,
               secret_previous_encrypted,
               secret_previous_expires_at
        FROM webhooks
        WHERE id = $1
        "#,
    )
    .bind(webhook_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("load_active_secrets query: {}", e))?;

    let row = match row {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    let cur: Option<Vec<u8>> = row.get("secret_encrypted");
    let prev: Option<Vec<u8>> = row.get("secret_previous_encrypted");
    let exp: Option<chrono::DateTime<chrono::Utc>> = row.get("secret_previous_expires_at");

    let (out, failures) =
        decide_active_secrets(cur.as_deref(), prev.as_deref(), exp, chrono::Utc::now());

    if failures > 0 {
        tracing::warn!(
            webhook_id = %webhook_id,
            failures = failures,
            "one or more webhook secrets failed to decrypt; deliveries may be unsigned"
        );
    }

    Ok(out)
}

/// Process failed webhook deliveries that are due for retry.
///
/// Queries the retry queue for deliveries where `next_retry_at <= NOW()`,
/// attempts the HTTP POST again, and updates the delivery record with the
/// result. Uses `sqlx::query()` (not the macro) because the new columns
/// are not in the offline SQLx cache.
pub async fn process_webhook_retries(db: &sqlx::PgPool) -> std::result::Result<(), String> {
    use sqlx::Row;

    // Fetch deliveries due for retry (using sqlx::query, not the macro)
    let raw_rows = sqlx::query(
        r#"
        SELECT id, webhook_id, event, payload, attempts, max_attempts
        FROM webhook_deliveries
        WHERE success = false
          AND next_retry_at IS NOT NULL
          AND next_retry_at <= NOW()
          AND attempts < max_attempts
        ORDER BY next_retry_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to fetch retry queue: {}", e))?;

    let rows: Vec<RetryDeliveryRow> = raw_rows
        .into_iter()
        .map(|row| RetryDeliveryRow {
            id: row.get("id"),
            webhook_id: row.get("webhook_id"),
            event: row.get("event"),
            payload: row.get("payload"),
            attempts: row.get("attempts"),
            max_attempts: row.get("max_attempts"),
        })
        .collect();

    if rows.is_empty() {
        return Ok(());
    }

    tracing::debug!("Processing {} webhook deliveries due for retry", rows.len());

    let client = crate::services::http_client::base_client_builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    for delivery in &rows {
        // Look up the webhook URL and headers. Signing-secret material is
        // loaded separately via `load_active_secrets` so the retry path can
        // use the AES-GCM-decrypted secrets directly for HMAC. The legacy
        // bcrypt `secret_hash` cannot sign (irreversible) and is therefore
        // not read here.
        let webhook_row =
            sqlx::query("SELECT url, headers FROM webhooks WHERE id = $1 AND is_enabled = true")
                .bind(delivery.webhook_id)
                .fetch_optional(db)
                .await
                .map_err(|e| format!("Failed to fetch webhook: {}", e))?;

        let webhook_row = match webhook_row {
            Some(w) => w,
            None => {
                // Webhook deleted or disabled: mark delivery as dead letter
                let _ =
                    sqlx::query("UPDATE webhook_deliveries SET next_retry_at = NULL WHERE id = $1")
                        .bind(delivery.id)
                        .execute(db)
                        .await;
                continue;
            }
        };

        let url: String = webhook_row.get("url");
        let headers: Option<serde_json::Value> = webhook_row.get("headers");

        // Validate URL before delivery (SSRF prevention)
        if validate_webhook_url(&url).is_err() {
            let _ = sqlx::query("UPDATE webhook_deliveries SET next_retry_at = NULL WHERE id = $1")
                .bind(delivery.id)
                .execute(db)
                .await;
            tracing::warn!(
                "Webhook URL failed validation during retry, delivery {} dead-lettered",
                delivery.id
            );
            continue;
        }

        // Serialize once so the bytes we sign are exactly the bytes we POST.
        let body_bytes = match serde_json::to_vec(&delivery.payload) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    delivery_id = %delivery.id,
                    error = %e,
                    "Failed to serialize webhook payload; dead-lettering"
                );
                let _ =
                    sqlx::query("UPDATE webhook_deliveries SET next_retry_at = NULL WHERE id = $1")
                        .bind(delivery.id)
                        .execute(db)
                        .await;
                continue;
            }
        };

        // Look up the pinned event_schema_version for this webhook so
        // the header is correct even when the delivery row was enqueued
        // before E4 landed. Cheap; one row, one column.
        let event_version: String =
            sqlx::query_scalar("SELECT event_schema_version FROM webhooks WHERE id = $1")
                .bind(delivery.webhook_id)
                .fetch_optional(db)
                .await
                .map_err(|e| format!("load event_schema_version: {}", e))?
                .unwrap_or_else(|| "2026-04-01".to_string());

        let unix_secs = chrono::Utc::now().timestamp();
        let secrets = load_active_secrets(db, delivery.webhook_id)
            .await
            .unwrap_or_default();
        let secret_refs: Vec<&str> = secrets.iter().map(|s| s.as_str()).collect();

        let header_inputs = DeliveryHeaderInputs {
            delivery_id: delivery.id,
            event: &delivery.event,
            event_version: &event_version,
            retry_attempt: Some(delivery.attempts + 1),
            custom_headers: headers.as_ref(),
            secrets: &secret_refs,
            unix_secs,
            body_bytes: &body_bytes,
        };
        let mut request = client.post(&url);
        for (name, value) in build_delivery_request_headers(&header_inputs) {
            request = request.header(name, value);
        }

        let (success, response_status, response_body) = match request.body(body_bytes).send().await
        {
            Ok(response) => {
                let status = response.status().as_u16() as i32;
                let body = response.text().await.ok();
                (
                    is_webhook_delivery_success(status as u16),
                    Some(status),
                    body,
                )
            }
            Err(e) => (false, None, Some(e.to_string())),
        };

        let new_attempts = delivery.attempts + 1;
        let outcome = determine_retry_outcome(success, delivery.attempts, delivery.max_attempts);

        if outcome == RetryOutcome::Success {
            // Delivery succeeded
            let _ = sqlx::query(
                r#"
                UPDATE webhook_deliveries
                SET success = true,
                    response_status = $2,
                    response_body = $3,
                    attempts = $4,
                    delivered_at = NOW(),
                    next_retry_at = NULL
                WHERE id = $1
                "#,
            )
            .bind(delivery.id)
            .bind(response_status)
            .bind(&response_body)
            .bind(new_attempts)
            .execute(db)
            .await;
        } else if outcome == RetryOutcome::DeadLetter {
            // Max attempts exhausted: dead letter
            let _ = sqlx::query(
                r#"
                UPDATE webhook_deliveries
                SET response_status = $2,
                    response_body = $3,
                    attempts = $4,
                    next_retry_at = NULL
                WHERE id = $1
                "#,
            )
            .bind(delivery.id)
            .bind(response_status)
            .bind(&response_body)
            .bind(new_attempts)
            .execute(db)
            .await;

            tracing::info!(
                "Webhook delivery {} exhausted {} attempts, dead-lettered",
                delivery.id,
                new_attempts
            );

            // Auto-disable + notifier. Failures here are logged but do
            // not retry the (already dead-lettered) delivery.
            if let Err(e) = crate::services::webhook_notifier::auto_disable_webhook_for_dead_letter(
                db,
                delivery.webhook_id,
                delivery.id,
            )
            .await
            {
                tracing::warn!(
                    delivery_id = %delivery.id,
                    webhook_id = %delivery.webhook_id,
                    error = %e,
                    "auto-disable on dead-letter failed"
                );
            }

            crate::services::metrics_service::record_webhook_dead_letter(&delivery.event);
        } else if let RetryOutcome::Retry { delay_secs } = outcome {
            // Schedule next retry
            let _ = sqlx::query(
                r#"
                UPDATE webhook_deliveries
                SET response_status = $2,
                    response_body = $3,
                    attempts = $4,
                    next_retry_at = NOW() + ($5 || ' seconds')::interval
                WHERE id = $1
                "#,
            )
            .bind(delivery.id)
            .bind(response_status)
            .bind(&response_body)
            .bind(new_attempts)
            .bind(delay_secs.to_string())
            .execute(db)
            .await;
        }

        crate::services::metrics_service::record_webhook_delivery(&delivery.event, success);
    }

    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_webhooks,
        create_webhook,
        get_webhook,
        delete_webhook,
        enable_webhook,
        disable_webhook,
        test_webhook,
        rotate_webhook_secret,
        list_deliveries,
        redeliver,
    ),
    components(schemas(
        WebhookEvent,
        PayloadTemplate,
        CreateWebhookRequest,
        WebhookResponse,
        WebhookSecretCreatedResponse,
        RotateWebhookSecretResponse,
        WebhookListResponse,
        TestWebhookResponse,
        DeliveryResponse,
        DeliveryListResponse,
    ))
)]
pub struct WebhooksApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // webhook_access_allowed — object-level authorization invariant
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_access_admin_always_allowed() {
        let me = Uuid::new_v4();
        let other = Uuid::new_v4();
        // Admin reaches a webhook they neither own nor share a repo with.
        assert!(webhook_access_allowed(
            true,
            me,
            Some(other),
            Some(Uuid::new_v4()),
            false
        ));
        // ...including a global (repository-less) webhook.
        assert!(webhook_access_allowed(true, me, Some(other), None, false));
    }

    #[test]
    fn test_webhook_access_creator_allowed() {
        let me = Uuid::new_v4();
        // Creator of a global webhook may act on it.
        assert!(webhook_access_allowed(false, me, Some(me), None, false));
        // Creator of a repo-attached webhook may act on it even without repo access.
        assert!(webhook_access_allowed(
            false,
            me,
            Some(me),
            Some(Uuid::new_v4()),
            false
        ));
    }

    #[test]
    fn test_webhook_access_repo_member_allowed_only_when_accessible() {
        let me = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let repo = Uuid::new_v4();
        // Non-owner with repo access to the webhook's repository is allowed.
        assert!(webhook_access_allowed(
            false,
            me,
            Some(owner),
            Some(repo),
            true
        ));
        // Same caller, no repo access -> denied.
        assert!(!webhook_access_allowed(
            false,
            me,
            Some(owner),
            Some(repo),
            false
        ));
    }

    #[test]
    fn test_webhook_access_global_webhook_denied_to_stranger() {
        let me = Uuid::new_v4();
        let owner = Uuid::new_v4();
        // The BOLA: a non-admin, non-owner cannot reach a global
        // (repository_id = NULL) webhook regardless of any repo access bit.
        assert!(!webhook_access_allowed(false, me, Some(owner), None, true));
        assert!(!webhook_access_allowed(false, me, Some(owner), None, false));
    }

    #[test]
    fn test_webhook_access_legacy_null_owner_denied_to_nonadmin() {
        let me = Uuid::new_v4();
        // Legacy rows (created_by = NULL) with no repository are reachable
        // only by admins, never by an arbitrary authenticated caller.
        assert!(!webhook_access_allowed(false, me, None, None, false));
        // A legacy repo-attached row still honors repo access.
        assert!(webhook_access_allowed(
            false,
            me,
            None,
            Some(Uuid::new_v4()),
            true
        ));
    }

    // -----------------------------------------------------------------------
    // WebhookEvent Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_event_display_artifact_uploaded() {
        assert_eq!(
            WebhookEvent::ArtifactUploaded.to_string(),
            "artifact_uploaded"
        );
    }

    #[test]
    fn test_webhook_event_display_artifact_deleted() {
        assert_eq!(
            WebhookEvent::ArtifactDeleted.to_string(),
            "artifact_deleted"
        );
    }

    #[test]
    fn test_webhook_event_display_repository_created() {
        assert_eq!(
            WebhookEvent::RepositoryCreated.to_string(),
            "repository_created"
        );
    }

    #[test]
    fn test_webhook_event_display_repository_deleted() {
        assert_eq!(
            WebhookEvent::RepositoryDeleted.to_string(),
            "repository_deleted"
        );
    }

    #[test]
    fn test_webhook_event_display_user_created() {
        assert_eq!(WebhookEvent::UserCreated.to_string(), "user_created");
    }

    #[test]
    fn test_webhook_event_display_user_deleted() {
        assert_eq!(WebhookEvent::UserDeleted.to_string(), "user_deleted");
    }

    #[test]
    fn test_webhook_event_display_build_events() {
        assert_eq!(WebhookEvent::BuildStarted.to_string(), "build_started");
        assert_eq!(WebhookEvent::BuildCompleted.to_string(), "build_completed");
        assert_eq!(WebhookEvent::BuildFailed.to_string(), "build_failed");
    }

    // -----------------------------------------------------------------------
    // WebhookEvent serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_event_serialization() {
        let json = serde_json::to_string(&WebhookEvent::ArtifactUploaded).unwrap();
        assert_eq!(json, "\"artifact_uploaded\"");
    }

    #[test]
    fn test_webhook_event_deserialization() {
        let event: WebhookEvent = serde_json::from_str("\"build_failed\"").unwrap();
        assert_eq!(event.to_string(), "build_failed");
    }

    #[test]
    fn test_webhook_event_roundtrip() {
        let original = WebhookEvent::RepositoryCreated;
        let json = serde_json::to_string(&original).unwrap();
        let parsed: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.to_string(), original.to_string());
    }

    // -----------------------------------------------------------------------
    // validate_webhook_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_webhook_url_valid_https() {
        assert!(validate_webhook_url("https://hooks.example.com/webhook").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_valid_http() {
        assert!(validate_webhook_url("http://hooks.example.com/webhook").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_invalid_scheme_ftp() {
        assert!(validate_webhook_url("ftp://example.com/path").is_err());
    }

    #[test]
    fn test_validate_webhook_url_invalid_scheme_file() {
        assert!(validate_webhook_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_webhook_url_invalid_format() {
        assert!(validate_webhook_url("not-a-url").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_localhost() {
        assert!(validate_webhook_url("http://localhost/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_metadata_google() {
        assert!(validate_webhook_url("http://metadata.google.internal/computeMetadata").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_metadata_azure() {
        assert!(validate_webhook_url("http://metadata.azure.com/instance").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_aws_metadata_ip() {
        assert!(validate_webhook_url("http://169.254.169.254/latest/meta-data").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_internal_hosts() {
        assert!(validate_webhook_url("http://backend/api").is_err());
        assert!(validate_webhook_url("http://postgres/").is_err());
        assert!(validate_webhook_url("http://redis/").is_err());
        assert!(validate_webhook_url("http://opensearch/").is_err());
        assert!(validate_webhook_url("http://trivy/").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_loopback_ip() {
        // Hard-blocked regardless of env vars, no guard needed.
        assert!(validate_webhook_url("http://127.0.0.1/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_private_ip_10() {
        // Takes the env guard so a sibling test that sets
        // WEBHOOK_ALLOW_PRIVATE_IPS for an allowlist scenario does not
        // race this default-deny baseline. Issue #1435.
        let _g = WebhookEnvGuard::new();
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_private_ip_172() {
        let _g = WebhookEnvGuard::new();
        assert!(validate_webhook_url("http://172.16.0.1/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_private_ip_192() {
        let _g = WebhookEnvGuard::new();
        assert!(validate_webhook_url("http://192.168.1.1/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_unspecified() {
        assert!(validate_webhook_url("http://0.0.0.0/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_allows_public_ip() {
        assert!(validate_webhook_url("http://8.8.8.8/hook").is_ok());
    }

    // -----------------------------------------------------------------------
    // Issue #1435: webhook validator reads WEBHOOK_ALLOW_PRIVATE_IPS, NOT
    // UPSTREAM_ALLOW_PRIVATE_IPS. These tests pin the env-var split so a
    // future refactor cannot silently re-couple the two surfaces.
    //
    // Tests serialize on a local lock because they mutate process env.
    // -----------------------------------------------------------------------

    /// Local env lock for the env-var-split tests below. Independent of
    /// `validation.rs`'s lock; both can race in `cargo test --workspace`
    /// but each module's mutations are serialized internally and the
    /// validator helper functions read env on each call.
    static WEBHOOK_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Snapshot + restore the two private-IP env vars so a test that
    /// flips one cannot leak state into a sibling.
    struct WebhookEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev_webhook: Option<String>,
        prev_upstream: Option<String>,
        prev_cidrs: Option<String>,
        prev_alias: Option<String>,
    }

    impl WebhookEnvGuard {
        fn new() -> Self {
            let lock = WEBHOOK_ENV_LOCK.lock().unwrap();
            let g = Self {
                _lock: lock,
                prev_webhook: std::env::var("WEBHOOK_ALLOW_PRIVATE_IPS").ok(),
                prev_upstream: std::env::var("UPSTREAM_ALLOW_PRIVATE_IPS").ok(),
                prev_cidrs: std::env::var("AK_SSRF_ALLOW_PRIVATE_CIDRS").ok(),
                prev_alias: std::env::var("UPSTREAM_PRIVATE_IP_ALLOWLIST").ok(),
            };
            std::env::remove_var("WEBHOOK_ALLOW_PRIVATE_IPS");
            std::env::remove_var("UPSTREAM_ALLOW_PRIVATE_IPS");
            std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS");
            std::env::remove_var("UPSTREAM_PRIVATE_IP_ALLOWLIST");
            g
        }
    }

    impl Drop for WebhookEnvGuard {
        fn drop(&mut self) {
            for (name, val) in [
                ("WEBHOOK_ALLOW_PRIVATE_IPS", &self.prev_webhook),
                ("UPSTREAM_ALLOW_PRIVATE_IPS", &self.prev_upstream),
                ("AK_SSRF_ALLOW_PRIVATE_CIDRS", &self.prev_cidrs),
                ("UPSTREAM_PRIVATE_IP_ALLOWLIST", &self.prev_alias),
            ] {
                match val {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    #[test]
    fn test_validate_webhook_url_rejects_rfc1918_with_only_upstream_env() {
        // Security regression #1435: the validator used by the webhook
        // handler must NOT be relaxed by UPSTREAM_ALLOW_PRIVATE_IPS.
        // Before the split, the test cluster setting this env var to
        // enable webhook tests also defeated SSRF protection on the
        // remote-proxy upstream path AND let webhooks reach private IPs.
        let _g = WebhookEnvGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_webhook_url("http://10.0.0.1/hook").is_err(),
            "webhook validator must reject RFC1918 when only the upstream env var is set"
        );
    }

    #[test]
    fn test_validate_webhook_url_accepts_rfc1918_with_webhook_env() {
        // After the split, operators relax the webhook surface (and only
        // the webhook surface) by setting WEBHOOK_ALLOW_PRIVATE_IPS.
        let _g = WebhookEnvGuard::new();
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_webhook_url("http://10.0.0.1/hook").is_ok(),
            "webhook validator must accept RFC1918 when WEBHOOK_ALLOW_PRIVATE_IPS=true"
        );
        assert!(
            validate_webhook_url("http://192.168.1.5/hook").is_ok(),
            "192.168.1.5 must also be accepted"
        );
    }

    #[test]
    fn test_validate_webhook_url_returns_validation_error_for_4xx_mapping() {
        // Webhook handler returns 4xx (not 500) on RFC1918 because the
        // validator returns AppError::Validation, which `error.rs` maps
        // to HTTP 400. Pins the error variant so a future refactor that
        // changes the variant (e.g. to AppError::Internal) gets caught
        // here BEFORE producing a 500 in production. Issue #1435 Part B.
        let _g = WebhookEnvGuard::new();
        let err = validate_webhook_url("http://10.0.0.1/hook")
            .expect_err("RFC1918 webhook URL must be rejected");
        assert!(
            matches!(err, AppError::Validation(_)),
            "expected AppError::Validation (→ HTTP 400), got: {err:?}"
        );
    }

    #[test]
    fn test_validate_webhook_url_loopback_still_blocked_under_webhook_env() {
        // Loopback must NEVER be unblocked, even with the per-surface
        // env var. The webhook validator delegating to the shared SSRF
        // logic ensures loopback is hard-blocked at the IP layer.
        let _g = WebhookEnvGuard::new();
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        assert!(validate_webhook_url("http://127.0.0.1/hook").is_err());
        assert!(validate_webhook_url("http://[::1]:8080/hook").is_err());
    }

    // -----------------------------------------------------------------------
    // Request/Response serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_webhook_request_deserialization() {
        let json = r#"{
            "name": "deploy",
            "url": "https://hooks.example.com/deploy",
            "events": ["artifact_uploaded"]
        }"#;
        let req: CreateWebhookRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "deploy");
        assert_eq!(req.url, "https://hooks.example.com/deploy");
        assert_eq!(req.events.len(), 1);
        assert!(req.secret.is_none());
        assert!(req.repository_id.is_none());
        assert_eq!(req.payload_template, PayloadTemplate::Generic);
    }

    #[test]
    fn test_create_webhook_request_with_all_fields() {
        let json = serde_json::json!({
            "name": "full",
            "url": "https://hooks.example.com/full",
            "events": ["artifact_uploaded", "artifact_deleted"],
            "secret": "my-secret-key",
            "repository_id": Uuid::new_v4(),
            "headers": {"X-Custom": "value"},
            "payload_template": "slack"
        });
        let req: CreateWebhookRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.events.len(), 2);
        assert!(req.secret.is_some());
        assert!(req.repository_id.is_some());
        assert!(req.headers.is_some());
        assert_eq!(req.payload_template, PayloadTemplate::Slack);
    }

    #[test]
    fn test_webhook_response_serialization() {
        let resp = WebhookResponse {
            id: Uuid::nil(),
            name: "test".to_string(),
            url: "https://example.com/hook".to_string(),
            events: vec!["artifact_uploaded".to_string()],
            is_enabled: true,
            repository_id: None,
            headers: None,
            payload_template: PayloadTemplate::Generic,
            event_schema_version: "2026-04-01".to_string(),
            secret_digest: Some("whsec_...abcd".to_string()),
            secret_rotation_active: false,
            last_triggered_at: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["is_enabled"], true);
        assert_eq!(json["events"].as_array().unwrap().len(), 1);
        assert_eq!(json["payload_template"], "generic");
        assert_eq!(json["event_schema_version"], "2026-04-01");
    }

    #[test]
    fn test_webhook_response_omits_secret_material_keys() {
        // Write-once contract: GET/LIST responses must NEVER include the
        // raw secret, the encrypted blob, the previous-secret blob, or the
        // legacy bcrypt hash. The serialized form is allowed to carry
        // `secret_digest` (a non-reversible last-4 indicator) and
        // `secret_rotation_active` (a boolean), nothing else secret-related.
        let resp = WebhookResponse {
            id: Uuid::nil(),
            name: "test".to_string(),
            url: "https://example.com/hook".to_string(),
            events: vec!["artifact_uploaded".to_string()],
            is_enabled: true,
            repository_id: None,
            headers: None,
            payload_template: PayloadTemplate::Generic,
            event_schema_version: "2026-04-01".to_string(),
            secret_digest: Some("whsec_...abcd".to_string()),
            secret_rotation_active: false,
            last_triggered_at: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json
            .as_object()
            .expect("WebhookResponse serializes to object");
        let forbidden_keys = [
            "secret",
            "secret_encrypted",
            "secret_previous_encrypted",
            "secret_hash",
            "secret_previous_expires_at",
            "secret_rotation_started_at",
        ];
        for key in forbidden_keys {
            assert!(
                !obj.contains_key(key),
                "WebhookResponse must not serialize key `{}`; got keys: {:?}",
                key,
                obj.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_test_webhook_response_serialization() {
        let resp = TestWebhookResponse {
            success: true,
            status_code: Some(200),
            response_body: Some("OK".to_string()),
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["status_code"], 200);
    }

    #[test]
    fn test_test_webhook_response_failure() {
        let resp = TestWebhookResponse {
            success: false,
            status_code: None,
            response_body: None,
            error: Some("Connection refused".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Connection refused"));
    }

    #[test]
    fn test_delivery_response_serialization() {
        let resp = DeliveryResponse {
            id: Uuid::nil(),
            webhook_id: Uuid::nil(),
            event: "artifact_uploaded".to_string(),
            payload: serde_json::json!({"key": "value"}),
            response_status: Some(200),
            response_body: Some("OK".to_string()),
            success: true,
            attempts: 1,
            delivered_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["attempts"], 1);
    }

    // -----------------------------------------------------------------------
    // validate_webhook_url (delegates to validation::validate_outbound_url)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_webhook_url_allows_valid() {
        assert!(validate_webhook_url("https://hooks.example.com/notify").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_rejects_localhost() {
        assert!(validate_webhook_url("http://localhost/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_rejects_private_ip() {
        // Env guard so the env-var-split tests below do not race this
        // baseline default-deny check. Issue #1435.
        let _g = WebhookEnvGuard::new();
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
    }

    // -----------------------------------------------------------------------
    // webhook_retry_delay_secs / base_delay_secs / apply_jitter
    // -----------------------------------------------------------------------

    #[test]
    fn base_schedule_caps_at_24h() {
        assert_eq!(base_delay_secs(12), 86_400);
        assert_eq!(base_delay_secs(99), 86_400);
    }

    #[test]
    fn base_schedule_attempt_1_is_30s() {
        assert_eq!(base_delay_secs(1), 30);
    }

    #[test]
    fn base_schedule_is_monotonically_non_decreasing() {
        let mut last = 0;
        for attempt in 1..=12 {
            let d = base_delay_secs(attempt);
            assert!(
                d >= last,
                "schedule regressed at attempt {}: {} < {}",
                attempt,
                d,
                last
            );
            last = d;
        }
    }

    #[test]
    fn jitter_with_zero_seed_is_no_op() {
        assert_eq!(apply_jitter(600, 0), 600);
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        let base = 1_000;
        for seed in 1..200u64 {
            let v = apply_jitter(base, seed);
            let delta = (v - base).abs();
            assert!(
                delta <= base / 5,
                "delta {} exceeded 20% of {}",
                delta,
                base
            );
        }
    }

    #[test]
    fn jitter_clamps_to_min_1() {
        // base=4, seed odd -> potential negative drag; result must stay >= 1.
        for seed in 1..50u64 {
            let v = apply_jitter(4, seed);
            assert!(v >= 1, "jittered delay went below 1 for seed {}", seed);
        }
    }

    // -----------------------------------------------------------------------
    // determine_retry_outcome (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_retry_outcome_success() {
        assert_eq!(determine_retry_outcome(true, 0, 5), RetryOutcome::Success);
    }

    #[test]
    fn test_retry_outcome_dead_letter() {
        // attempts=4, max=5: new_attempts = 5 >= 5 → DeadLetter
        assert_eq!(
            determine_retry_outcome(false, 4, 5),
            RetryOutcome::DeadLetter
        );
    }

    #[test]
    fn test_retry_outcome_retry_first_attempt() {
        // attempts=0, max=5: new_attempts = 1 < 5 → Retry with delay for attempt 1.
        // V2 base is 30s with +/- 20% jitter.
        match determine_retry_outcome(false, 0, 5) {
            RetryOutcome::Retry { delay_secs } => {
                assert!(
                    (24..=36).contains(&delay_secs),
                    "delay {} outside attempt-1 jitter window (24..=36)",
                    delay_secs
                );
            }
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn test_retry_outcome_retry_second_attempt() {
        // attempts=1, max=5: new_attempts = 2 < 5 → Retry with delay for attempt 2.
        // V2 base is 60s with +/- 20% jitter.
        match determine_retry_outcome(false, 1, 5) {
            RetryOutcome::Retry { delay_secs } => {
                assert!(
                    (48..=72).contains(&delay_secs),
                    "delay {} outside attempt-2 jitter window (48..=72)",
                    delay_secs
                );
            }
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn test_retry_outcome_retry_third_attempt() {
        // attempts=2, max=5: new_attempts = 3 < 5 → Retry with delay for attempt 3.
        // V2 base is 120s with +/- 20% jitter.
        match determine_retry_outcome(false, 2, 5) {
            RetryOutcome::Retry { delay_secs } => {
                assert!(
                    (96..=144).contains(&delay_secs),
                    "delay {} outside attempt-3 jitter window (96..=144)",
                    delay_secs
                );
            }
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn test_retry_outcome_dead_letter_exact() {
        // attempts=2, max=3: new_attempts = 3 >= 3 → DeadLetter
        assert_eq!(
            determine_retry_outcome(false, 2, 3),
            RetryOutcome::DeadLetter
        );
    }

    #[test]
    fn test_retry_outcome_success_ignores_attempts() {
        // Even with high attempt count, success is success
        assert_eq!(determine_retry_outcome(true, 4, 5), RetryOutcome::Success);
    }

    // -----------------------------------------------------------------------
    // is_webhook_delivery_success (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_delivery_success_200() {
        assert!(is_webhook_delivery_success(200));
    }

    #[test]
    fn test_is_delivery_success_201() {
        assert!(is_webhook_delivery_success(201));
    }

    #[test]
    fn test_is_delivery_success_204() {
        assert!(is_webhook_delivery_success(204));
    }

    #[test]
    fn test_is_delivery_success_299() {
        assert!(is_webhook_delivery_success(299));
    }

    #[test]
    fn test_is_delivery_success_300() {
        assert!(!is_webhook_delivery_success(300));
    }

    #[test]
    fn test_is_delivery_success_400() {
        assert!(!is_webhook_delivery_success(400));
    }

    #[test]
    fn test_is_delivery_success_500() {
        assert!(!is_webhook_delivery_success(500));
    }

    #[test]
    fn test_is_delivery_success_199() {
        assert!(!is_webhook_delivery_success(199));
    }

    // -----------------------------------------------------------------------
    // has_signing_secret: unified gate for X-Webhook-Signature header
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_signing_secret_neither_form() {
        // Migration 081 leaves both NULL. The retry path must NOT advertise
        // a signature header for these rows.
        assert!(!has_signing_secret(&None, None));
    }

    #[test]
    fn test_has_signing_secret_legacy_bcrypt_only() {
        // Pre-v1.1.9 rows that have not been rotated yet have only the
        // legacy bcrypt hash; the gate still considers them configured.
        let bcrypt_hash = Some("$2b$12$abcdefghijklmnop".to_string());
        assert!(has_signing_secret(&bcrypt_hash, None));
    }

    #[test]
    fn test_has_signing_secret_encrypted_only() {
        // New rows from `create_webhook` populate `secret_encrypted` only.
        let ct: &[u8] = b"\x00\x01\x02ciphertext";
        assert!(has_signing_secret(&None, Some(ct)));
    }

    #[test]
    fn test_has_signing_secret_both_forms() {
        // Mid-migration rows can briefly carry both. Still configured.
        let bcrypt_hash = Some("$2b$12$abcdefghijklmnop".to_string());
        let ct: &[u8] = b"ciphertext";
        assert!(has_signing_secret(&bcrypt_hash, Some(ct)));
    }

    #[test]
    fn test_has_signing_secret_empty_strings_treated_as_absent() {
        // Defensive: an empty string in secret_hash (e.g. older rows from
        // the prior migration variant) is not a valid hash and must NOT
        // count as signing-configured.
        let empty_hash = Some(String::new());
        let empty_bytes: &[u8] = b"";
        assert!(!has_signing_secret(&empty_hash, Some(empty_bytes)));
        assert!(!has_signing_secret(&empty_hash, None));
        assert!(!has_signing_secret(&None, Some(empty_bytes)));
    }

    // -----------------------------------------------------------------------
    // Rotation overlap window: pure-function semantics
    // -----------------------------------------------------------------------

    #[test]
    fn test_rotation_overlap_constant_is_24_hours() {
        // The integration contract documented in the PR body and the
        // operator docs says 24 hours. Tying it down here means a future
        // edit cannot silently change the window from under callers.
        assert_eq!(SECRET_ROTATION_OVERLAP, chrono::Duration::hours(24));
    }

    #[test]
    fn test_rotation_guard_allows_when_no_previous() {
        // A row that has never been rotated has NULL previous-expiry.
        let now = chrono::Utc::now();
        assert!(rotation_guard_allows(None, now));
    }

    #[test]
    fn test_rotation_guard_allows_when_previous_already_expired() {
        // The cleanup tick may not have fired yet, but logically the
        // overlap window has closed: rotation is fine.
        let now = chrono::Utc::now();
        let an_hour_ago = now - chrono::Duration::hours(1);
        assert!(rotation_guard_allows(Some(an_hour_ago), now));
    }

    #[test]
    fn test_rotation_guard_blocks_when_previous_still_active() {
        // Mid-overlap: a second rotation must NOT be allowed; the API
        // returns 409 Conflict.
        let now = chrono::Utc::now();
        let in_three_hours = now + chrono::Duration::hours(3);
        assert!(!rotation_guard_allows(Some(in_three_hours), now));
    }

    #[test]
    fn test_rotation_guard_boundary_now_is_blocked() {
        // Strict `<` in the SQL means a row whose previous expiry equals
        // now is still considered active. Mirror that here.
        let now = chrono::Utc::now();
        assert!(!rotation_guard_allows(Some(now), now));
    }

    #[test]
    fn test_rotation_overlap_window_math() {
        // The `previous_expires_at = now + SECRET_ROTATION_OVERLAP` formula
        // used in the rotate handler. Lock the math down so a future
        // refactor cannot accidentally use minutes vs hours.
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-27T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let previous_expires_at = now + SECRET_ROTATION_OVERLAP;
        assert_eq!(
            previous_expires_at,
            chrono::DateTime::parse_from_rfc3339("2026-04-28T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        );
        // Second rotate within the window is blocked.
        assert!(!rotation_guard_allows(Some(previous_expires_at), now));
        // After the window closes, rotate is allowed again.
        let after = previous_expires_at + chrono::Duration::seconds(1);
        assert!(rotation_guard_allows(Some(previous_expires_at), after));
    }

    // -----------------------------------------------------------------------
    // Cleanup tick semantics
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_predicate_matches_only_expired_rows() {
        // The SQL in `cleanup_expired_previous_secrets` uses the predicate
        // `secret_previous_expires_at <= NOW()`. Pure-function expression
        // of that predicate so callers can unit-test their inputs without
        // a database. A row is cleared iff it has a previous expiry AND
        // that expiry is in the past or now.
        fn would_clear(
            expires_at: Option<chrono::DateTime<chrono::Utc>>,
            now: chrono::DateTime<chrono::Utc>,
        ) -> bool {
            matches!(expires_at, Some(t) if t <= now)
        }
        let now = chrono::Utc::now();
        // Row with no previous: never cleared.
        assert!(!would_clear(None, now));
        // Row with future expiry: not cleared.
        assert!(!would_clear(Some(now + chrono::Duration::hours(1)), now));
        // Row at exactly now: cleared (<=).
        assert!(would_clear(Some(now), now));
        // Row in the past: cleared.
        assert!(would_clear(Some(now - chrono::Duration::seconds(1)), now));
    }

    // ---------------- DeliveryHeaderInputs / build_delivery_request_headers ----------------

    fn sample_inputs<'a>(secrets: &'a [&'a str], body: &'a [u8]) -> DeliveryHeaderInputs<'a> {
        DeliveryHeaderInputs {
            delivery_id: Uuid::nil(),
            event: "artifact.uploaded",
            event_version: "2026-04-01",
            retry_attempt: None,
            custom_headers: None,
            secrets,
            unix_secs: 1_700_000_000,
            body_bytes: body,
        }
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn delivery_headers_include_required_v2_set() {
        let inputs = sample_inputs(&[], b"{}");
        let h = build_delivery_request_headers(&inputs);
        assert_eq!(header(&h, "Content-Type"), Some("application/json"));
        assert_eq!(
            header(&h, "X-ArtifactKeeper-Delivery"),
            Some(Uuid::nil().to_string().as_str())
        );
        assert_eq!(
            header(&h, "X-ArtifactKeeper-Event"),
            Some("artifact.uploaded")
        );
        assert_eq!(
            header(&h, "X-ArtifactKeeper-Event-Version"),
            Some("2026-04-01")
        );
    }

    #[test]
    fn delivery_headers_include_legacy_set() {
        let inputs = sample_inputs(&[], b"{}");
        let h = build_delivery_request_headers(&inputs);
        assert_eq!(header(&h, "X-Webhook-Event"), Some("artifact.uploaded"));
        assert!(header(&h, "X-Webhook-Delivery").is_some());
    }

    #[test]
    fn delivery_headers_omit_retry_attempt_when_none() {
        let inputs = sample_inputs(&[], b"{}");
        let h = build_delivery_request_headers(&inputs);
        assert!(header(&h, "X-ArtifactKeeper-Retry-Attempt").is_none());
        assert!(header(&h, "X-Webhook-Retry-Attempt").is_none());
    }

    #[test]
    fn delivery_headers_emit_retry_attempt_when_some() {
        let mut inputs = sample_inputs(&[], b"{}");
        inputs.retry_attempt = Some(7);
        let h = build_delivery_request_headers(&inputs);
        assert_eq!(header(&h, "X-ArtifactKeeper-Retry-Attempt"), Some("7"));
        assert_eq!(header(&h, "X-Webhook-Retry-Attempt"), Some("7"));
    }

    #[test]
    fn delivery_headers_omit_signature_when_no_secrets() {
        let inputs = sample_inputs(&[], b"{}");
        let h = build_delivery_request_headers(&inputs);
        assert!(header(&h, "X-ArtifactKeeper-Signature").is_none());
        assert!(header(&h, "X-Webhook-Signature").is_none());
    }

    #[test]
    fn delivery_headers_emit_signature_when_secret_present() {
        let secrets = ["whsec_a"];
        let secret_refs: Vec<&str> = secrets.to_vec();
        let inputs = sample_inputs(&secret_refs, b"{}");
        let h = build_delivery_request_headers(&inputs);
        let sig = header(&h, "X-ArtifactKeeper-Signature").unwrap();
        assert!(sig.starts_with("t=1700000000,"));
        assert_eq!(sig.matches("v1=").count(), 1);
        let legacy = header(&h, "X-Webhook-Signature").unwrap();
        assert!(legacy.starts_with("sha256="));
    }

    #[test]
    fn delivery_headers_emit_two_v1_tokens_during_rotation() {
        let secrets = ["whsec_new", "whsec_old"];
        let secret_refs: Vec<&str> = secrets.to_vec();
        let inputs = sample_inputs(&secret_refs, b"{}");
        let h = build_delivery_request_headers(&inputs);
        let sig = header(&h, "X-ArtifactKeeper-Signature").unwrap();
        assert_eq!(sig.matches("v1=").count(), 2);
    }

    #[test]
    fn delivery_headers_pass_through_custom_string_headers() {
        let custom = serde_json::json!({"X-Trace-Id": "abc-123", "X-Drop-Me": 42});
        let mut inputs = sample_inputs(&[], b"{}");
        inputs.custom_headers = Some(&custom);
        let h = build_delivery_request_headers(&inputs);
        assert_eq!(header(&h, "X-Trace-Id"), Some("abc-123"));
        // Non-string custom-header values are silently dropped (matches prior behavior).
        assert_eq!(header(&h, "X-Drop-Me"), None);
    }

    #[test]
    fn delivery_headers_signed_body_matches_signature() {
        let secret = "whsec_test";
        let body = b"hello world";
        let unix_secs = 1_700_000_000;
        let secret_refs = [secret];
        let mut inputs = sample_inputs(&secret_refs, body);
        inputs.unix_secs = unix_secs;
        let h = build_delivery_request_headers(&inputs);
        // The legacy header is HMAC over body alone (no timestamp prefix).
        let legacy = header(&h, "X-Webhook-Signature").unwrap();
        let expected_legacy = format!(
            "sha256={}",
            crate::services::webhook_signing::compute_v1_signature(secret, unix_secs, body)
        );
        assert_eq!(legacy, expected_legacy);
        // The v2 header includes the same hex token.
        let v2 = header(&h, "X-ArtifactKeeper-Signature").unwrap();
        assert!(v2.contains(&legacy[7..]));
    }

    #[test]
    fn delivery_headers_skip_non_object_custom_headers() {
        // headers = JSON array (not an object): the `as_object()` branch
        // returns None and the loop is skipped without panicking.
        let custom = serde_json::json!(["X-Stray", "ignored"]);
        let mut inputs = sample_inputs(&[], b"{}");
        inputs.custom_headers = Some(&custom);
        let h = build_delivery_request_headers(&inputs);
        assert!(header(&h, "X-Stray").is_none());
        // Required v2 headers are still emitted.
        assert!(header(&h, "X-ArtifactKeeper-Delivery").is_some());
    }

    #[test]
    fn delivery_headers_signature_omitted_when_secrets_slice_empty() {
        // Sanity duplicate of delivery_headers_omit_signature_when_no_secrets
        // that explicitly exercises the "no secrets and custom headers
        // present" combination — covers the join branch where the
        // signature push is gated but custom-header push is not.
        let custom = serde_json::json!({"X-Trace": "abc"});
        let mut inputs = sample_inputs(&[], b"{}");
        inputs.custom_headers = Some(&custom);
        let h = build_delivery_request_headers(&inputs);
        assert_eq!(header(&h, "X-Trace"), Some("abc"));
        assert!(header(&h, "X-ArtifactKeeper-Signature").is_none());
        assert!(header(&h, "X-Webhook-Signature").is_none());
    }

    // ---------------- validate_event_version ----------------

    #[test]
    fn validate_event_version_accepts_known() {
        assert!(validate_event_version("2026-04-01").is_ok());
    }

    #[test]
    fn validate_event_version_rejects_unknown() {
        let err = validate_event_version("9999-99-99").unwrap_err();
        match err {
            AppError::Validation(msg) => {
                assert!(msg.contains("9999-99-99"));
                assert!(msg.contains("supported"));
            }
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn supported_event_versions_includes_inaugural() {
        assert!(SUPPORTED_EVENT_VERSIONS.contains(&"2026-04-01"));
    }

    // ---------------- decide_active_secrets ----------------

    use std::sync::Mutex as StdMutex;

    /// Serializes env mutation across tests (process-global env vars).
    static SECRET_ENV_LOCK: StdMutex<()> = StdMutex::new(());

    fn set_test_secret_key() {
        // 32 bytes of zeros, base64-encoded — same shape webhook_secret_crypto's tests use.
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let key = B64.encode([0u8; 32]);
        // SAFETY: SECRET_ENV_LOCK serializes env access for tests in this module.
        unsafe {
            std::env::set_var(crate::services::webhook_secret_crypto::ENV_KEY, key);
        }
    }

    fn encrypt_test_secret(plaintext: &str) -> Vec<u8> {
        crate::services::webhook_secret_crypto::encrypt_secret(plaintext)
            .expect("test crypto roundtrip")
    }

    #[test]
    fn decide_active_secrets_returns_only_current_when_no_previous() {
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        let cur = encrypt_test_secret("whsec_alpha");
        let now = chrono::Utc::now();
        let (out, fails) = decide_active_secrets(Some(&cur), None, None, now);
        assert_eq!(out, vec!["whsec_alpha".to_string()]);
        assert_eq!(fails, 0);
    }

    #[test]
    fn decide_active_secrets_returns_both_during_overlap() {
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        let cur = encrypt_test_secret("whsec_new");
        let prev = encrypt_test_secret("whsec_old");
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::hours(12);
        let (out, fails) = decide_active_secrets(Some(&cur), Some(&prev), Some(exp), now);
        assert_eq!(out, vec!["whsec_new".to_string(), "whsec_old".to_string()]);
        assert_eq!(fails, 0);
    }

    #[test]
    fn decide_active_secrets_skips_previous_after_expiry() {
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        let cur = encrypt_test_secret("whsec_new");
        let prev = encrypt_test_secret("whsec_old");
        let now = chrono::Utc::now();
        let exp = now - chrono::Duration::hours(1); // already expired
        let (out, fails) = decide_active_secrets(Some(&cur), Some(&prev), Some(exp), now);
        assert_eq!(out, vec!["whsec_new".to_string()]);
        assert_eq!(fails, 0);
    }

    #[test]
    fn decide_active_secrets_returns_empty_when_neither_present() {
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        let now = chrono::Utc::now();
        let (out, fails) = decide_active_secrets(None, None, None, now);
        assert!(out.is_empty());
        assert_eq!(fails, 0);
    }

    #[test]
    fn decide_active_secrets_treats_empty_bytes_as_absent() {
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        let empty: Vec<u8> = Vec::new();
        let now = chrono::Utc::now();
        let (out, fails) = decide_active_secrets(Some(&empty), Some(&empty), Some(now), now);
        assert!(out.is_empty());
        assert_eq!(fails, 0);
    }

    #[test]
    fn decide_active_secrets_counts_failed_decrypt() {
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        // Garbage bytes that won't decrypt under the test key.
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let now = chrono::Utc::now();
        let (out, fails) = decide_active_secrets(Some(&garbage), None, None, now);
        assert!(out.is_empty());
        assert_eq!(fails, 1);
    }

    #[test]
    fn decide_active_secrets_skips_previous_when_expiry_missing() {
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        let cur = encrypt_test_secret("whsec_new");
        let prev = encrypt_test_secret("whsec_old");
        let now = chrono::Utc::now();
        // Previous bytes present but expiry None means rotation row is malformed; treat as expired.
        let (out, fails) = decide_active_secrets(Some(&cur), Some(&prev), None, now);
        assert_eq!(out, vec!["whsec_new".to_string()]);
        assert_eq!(fails, 0);
    }

    // ---------------- prepare_secret_for_storage (B4) ----------------
    //
    // Regression coverage for the webhook-create HTTP 500 (release-gate
    // run 26613046674). A normal create (no secret, no AK_WEBHOOK_SECRET_KEY)
    // must succeed and store nothing rather than 500ing on a missing key.

    #[test]
    fn prepare_secret_no_secret_no_key_stores_nothing_and_succeeds() {
        // The release-gate cluster path: no caller secret, no key configured.
        // Must NOT attempt encryption and must NOT error.
        let prepared = prepare_secret_for_storage(None, false, || {
            panic!("must not generate a secret when no key is configured")
        })
        .expect("create without secret must succeed when no key is configured");
        assert!(prepared.raw_secret.is_none());
        assert!(prepared.encrypted.is_none());
        assert!(prepared.digest.is_none());
    }

    #[test]
    fn prepare_secret_empty_string_secret_treated_as_no_secret() {
        // An explicit but empty/whitespace secret is equivalent to "none".
        let prepared =
            prepare_secret_for_storage(Some("   "), false, || panic!("must not generate a secret"))
                .expect("blank secret with no key must succeed unsigned");
        assert!(prepared.raw_secret.is_none());
        assert!(prepared.encrypted.is_none());
    }

    #[test]
    fn prepare_secret_no_secret_with_key_generates_and_encrypts() {
        // When a key IS configured, the pre-fix sign-by-default behavior is
        // preserved: a secret is generated, encrypted, and returned once.
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        let prepared = prepare_secret_for_storage(None, true, || "whsec_generated".to_string())
            .expect("generate + encrypt must succeed when key is configured");
        assert_eq!(prepared.raw_secret.as_deref(), Some("whsec_generated"));
        assert!(prepared.encrypted.as_ref().is_some_and(|b| !b.is_empty()));
        assert!(prepared.digest.is_some());
    }

    #[test]
    fn prepare_secret_supplied_secret_with_key_encrypts_caller_value() {
        let _g = SECRET_ENV_LOCK.lock().unwrap();
        set_test_secret_key();
        let prepared = prepare_secret_for_storage(Some("whsec_caller_supplied"), true, || {
            panic!("must not generate when caller supplies a secret")
        })
        .expect("supplied secret + key must succeed");
        assert_eq!(
            prepared.raw_secret.as_deref(),
            Some("whsec_caller_supplied")
        );
        let ct = prepared.encrypted.expect("ciphertext present");
        let pt = crate::services::webhook_secret_crypto::decrypt_secret(&ct)
            .expect("ciphertext must decrypt under the configured key");
        assert_eq!(pt, "whsec_caller_supplied");
    }

    #[test]
    fn prepare_secret_supplied_secret_without_key_is_clear_non_500_error() {
        // The one case that must error: caller wants signing but the
        // deployment cannot encrypt at rest. Must be a clear client-side
        // Validation error, not a bare AppError::Internal (500) nor a
        // retryable AppError::ServiceUnavailable (503) that drives CI retry
        // loops. The message must name the missing env var.
        let err = prepare_secret_for_storage(Some("whsec_caller_supplied"), false, || {
            panic!("must not generate")
        })
        .expect_err("supplied secret with no key must error");
        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains("AK_WEBHOOK_SECRET_KEY"),
                    "error should name the missing key var, got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn prepare_secret_supplied_secret_without_key_maps_to_client_error_not_5xx() {
        use axum::response::IntoResponse;
        let err = prepare_secret_for_storage(Some("whsec_x"), false, || unreachable!())
            .expect_err("must error");
        // Drive the error through the real IntoResponse path the handler uses
        // so we assert the wire status, not an internal detail. The whole
        // point: a permanent client-side condition must be a 4xx, never a 5xx
        // (500 looks like a server fault; 503 looks retryable).
        let response = err.into_response();
        let status = response.status();
        assert!(
            status.is_client_error(),
            "supplied-secret-no-key must map to a 4xx client error, got {status}"
        );
        assert!(
            !status.is_server_error(),
            "supplied-secret-no-key must not be a 5xx, got {status}"
        );
    }

    // -----------------------------------------------------------------------
    // DB-backed object-level authorization (companion coverage for the BOLA
    // fix in PR #1942).
    //
    // These exercise the *async* authorization seam end-to-end against a real
    // Postgres so the new authz lines in each per-webhook handler are counted
    // under `cargo llvm-cov --lib`. The pure decision (`webhook_access_allowed`)
    // is unit-tested above; here we drive get/delete/enable/disable/test/
    // deliveries/redeliver/rotate plus list scoping and create-stamps-owner.
    //
    // Each test runtime-skips (returns early) when `DATABASE_URL` is unset, so
    // they no-op locally without Postgres but RUN in CI (which seeds the DB).
    // -----------------------------------------------------------------------
    mod object_level_authz_tests {
        use super::super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::middleware::auth::AuthExtension;
        use sqlx::PgPool;
        use uuid::Uuid;

        /// Build an `AuthExtension` for a JWT-style (non-token) caller.
        fn auth_for(user_id: Uuid, is_admin: bool) -> AuthExtension {
            AuthExtension {
                user_id,
                username: format!("u-{}", &user_id.to_string()[..8]),
                email: format!("{}@test.local", &user_id.to_string()[..8]),
                is_admin,
                is_api_token: false,
                is_service_account: false,
                scopes: None,
                allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
                iat_ms: None,
            }
        }

        async fn create_user(pool: &PgPool, is_admin: bool) -> Uuid {
            let id = Uuid::new_v4();
            let username = format!("wh1942-{}", &id.to_string()[..8]);
            sqlx::query(
                "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
                 VALUES ($1, $2, $3, 'x', 'local', $4, true)",
            )
            .bind(id)
            .bind(&username)
            .bind(format!("{}@test.local", username))
            .bind(is_admin)
            .execute(pool)
            .await
            .expect("insert user");
            id
        }

        async fn create_repo(pool: &PgPool) -> Uuid {
            let id = Uuid::new_v4();
            let key = format!("wh1942-repo-{}", &id.to_string()[..8]);
            sqlx::query(
                "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
                 VALUES ($1, $2, $2, '/tmp/wh1942', 'local', 'docker'::repository_format, false)",
            )
            .bind(id)
            .bind(&key)
            .execute(pool)
            .await
            .expect("insert repo");
            id
        }

        /// Grant `user` access to `repo` via a per-repo role assignment (the
        /// same boundary `user_can_access_repo` consults).
        async fn grant_repo_access(pool: &PgPool, user: Uuid, repo: Uuid) {
            let role_id: Uuid = sqlx::query_scalar("SELECT id FROM roles WHERE name = 'developer'")
                .fetch_one(pool)
                .await
                .expect("developer role must exist");
            sqlx::query(
                "INSERT INTO role_assignments (user_id, role_id, repository_id) \
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(user)
            .bind(role_id)
            .bind(repo)
            .execute(pool)
            .await
            .expect("grant repo access");
        }

        /// Insert a webhook row directly. `created_by`/`repository_id` are the
        /// two ownership anchors the authz decision keys off; both may be NULL.
        async fn insert_webhook(
            pool: &PgPool,
            created_by: Option<Uuid>,
            repository_id: Option<Uuid>,
        ) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO webhooks (id, name, url, events, is_enabled, repository_id, \
                                       payload_template, event_schema_version, created_by) \
                 VALUES ($1, $2, 'http://198.51.100.7/hook', ARRAY['artifact.created'], true, $3, \
                         'default', '2026-04-01', $4)",
            )
            .bind(id)
            .bind(format!("wh-{}", &id.to_string()[..8]))
            .bind(repository_id)
            .bind(created_by)
            .execute(pool)
            .await
            .expect("insert webhook");
            id
        }

        async fn webhook_exists(pool: &PgPool, id: Uuid) -> bool {
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM webhooks WHERE id = $1)")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap()
        }

        async fn is_enabled(pool: &PgPool, id: Uuid) -> bool {
            sqlx::query_scalar::<_, bool>("SELECT is_enabled FROM webhooks WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap()
        }

        fn is_not_found<T: std::fmt::Debug>(r: &Result<T>) -> bool {
            matches!(r, Err(AppError::NotFound(_)))
        }

        async fn cleanup(pool: &PgPool, repos: &[Uuid], users: &[Uuid]) {
            for u in users {
                sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
                    .bind(u)
                    .execute(pool)
                    .await
                    .ok();
            }
            sqlx::query(
                "DELETE FROM webhooks WHERE created_by = ANY($1) OR repository_id = ANY($2)",
            )
            .bind(users)
            .bind(repos)
            .execute(pool)
            .await
            .ok();
            for r in repos {
                sqlx::query("DELETE FROM webhooks WHERE repository_id = $1")
                    .bind(r)
                    .execute(pool)
                    .await
                    .ok();
                sqlx::query("DELETE FROM repositories WHERE id = $1")
                    .bind(r)
                    .execute(pool)
                    .await
                    .ok();
            }
            for u in users {
                sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(u)
                    .execute(pool)
                    .await
                    .ok();
            }
        }

        // ===================================================================
        // get_webhook — read path across all four authz outcomes
        // ===================================================================

        #[tokio::test]
        async fn get_webhook_authz_matrix() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let owner = create_user(&pool, false).await;
            let stranger = create_user(&pool, false).await;
            let admin = create_user(&pool, true).await;
            let repo = create_repo(&pool).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            // A global (repository-less) webhook owned by `owner`.
            let global_wh = insert_webhook(&pool, Some(owner), None).await;
            // A repo-attached webhook owned by `owner`; `stranger` gets repo access.
            let repo_wh = insert_webhook(&pool, Some(owner), Some(repo)).await;
            grant_repo_access(&pool, stranger, repo).await;
            // A legacy row: no creator, no repo (admin-only).
            let legacy_wh = insert_webhook(&pool, None, None).await;

            // Owner reads their own global webhook.
            assert!(
                get_webhook(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(owner, false)),
                    axum::extract::Path(global_wh),
                )
                .await
                .is_ok(),
                "owner must read own global webhook"
            );

            // Stranger (non-admin, non-owner) is denied on the GLOBAL webhook -> 404.
            // This is the exact cross-user/cross-tenant BOLA the fix closes.
            let r = get_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(stranger, false)),
                axum::extract::Path(global_wh),
            )
            .await;
            assert!(
                is_not_found(&r),
                "stranger must get 404 on global webhook, got {r:?}"
            );

            // Admin reads any webhook, including the legacy NULL-owner row...
            assert!(get_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(admin, true)),
                axum::extract::Path(global_wh),
            )
            .await
            .is_ok());
            assert!(get_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(admin, true)),
                axum::extract::Path(legacy_wh),
            )
            .await
            .is_ok());

            // ...but a non-admin is denied the legacy NULL-owner row.
            assert!(is_not_found(
                &get_webhook(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path(legacy_wh),
                )
                .await
            ));

            // Repo member can read the repo-attached webhook (not its owner)...
            assert!(
                get_webhook(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path(repo_wh),
                )
                .await
                .is_ok(),
                "repo member must read repo-attached webhook"
            );
            // ...but a non-member, non-owner cannot.
            let outsider = create_user(&pool, false).await;
            assert!(is_not_found(
                &get_webhook(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(outsider, false)),
                    axum::extract::Path(repo_wh),
                )
                .await
            ));

            cleanup(&pool, &[repo], &[owner, stranger, admin, outsider]).await;
        }

        // ===================================================================
        // delete_webhook — mutating path; denial must not delete the row
        // ===================================================================

        #[tokio::test]
        async fn delete_webhook_authz() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let owner = create_user(&pool, false).await;
            let stranger = create_user(&pool, false).await;
            let admin = create_user(&pool, true).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let wh = insert_webhook(&pool, Some(owner), None).await;

            // Stranger denied: 404 AND the row survives.
            assert!(is_not_found(
                &delete_webhook(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path(wh),
                )
                .await
            ));
            assert!(
                webhook_exists(&pool, wh).await,
                "denied delete must not remove the row"
            );

            // Owner can delete their own.
            assert!(delete_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(owner, false)),
                axum::extract::Path(wh),
            )
            .await
            .is_ok());
            assert!(!webhook_exists(&pool, wh).await);

            // Admin can delete another principal's webhook.
            let wh2 = insert_webhook(&pool, Some(owner), None).await;
            assert!(delete_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(admin, true)),
                axum::extract::Path(wh2),
            )
            .await
            .is_ok());
            assert!(!webhook_exists(&pool, wh2).await);

            cleanup(&pool, &[], &[owner, stranger, admin]).await;
        }

        // ===================================================================
        // enable_webhook / disable_webhook — toggle paths
        // ===================================================================

        #[tokio::test]
        async fn enable_disable_webhook_authz() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let owner = create_user(&pool, false).await;
            let stranger = create_user(&pool, false).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let wh = insert_webhook(&pool, Some(owner), None).await;

            // Stranger denied on disable -> 404, state unchanged (still enabled).
            assert!(is_not_found(
                &disable_webhook(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path(wh),
                )
                .await
            ));
            assert!(
                is_enabled(&pool, wh).await,
                "denied disable must not change state"
            );

            // Owner can disable then enable.
            assert!(disable_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(owner, false)),
                axum::extract::Path(wh),
            )
            .await
            .is_ok());
            assert!(!is_enabled(&pool, wh).await);

            assert!(enable_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(owner, false)),
                axum::extract::Path(wh),
            )
            .await
            .is_ok());
            assert!(is_enabled(&pool, wh).await);

            // Stranger denied on enable too.
            assert!(is_not_found(
                &enable_webhook(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path(wh),
                )
                .await
            ));

            cleanup(&pool, &[], &[owner, stranger]).await;
        }

        // ===================================================================
        // test_webhook — denial must short-circuit BEFORE any outbound delivery
        // ===================================================================

        #[tokio::test]
        async fn test_webhook_denied_cross_user() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let owner = create_user(&pool, false).await;
            let stranger = create_user(&pool, false).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let wh = insert_webhook(&pool, Some(owner), None).await;

            // Stranger denied -> 404 (authz runs before the delivery attempt, so
            // no outbound request is made for another principal's endpoint).
            assert!(is_not_found(
                &test_webhook(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path(wh),
                )
                .await
            ));

            cleanup(&pool, &[], &[owner, stranger]).await;
        }

        // ===================================================================
        // list_deliveries — read path inheriting parent-webhook authz
        // ===================================================================

        #[tokio::test]
        async fn list_deliveries_authz() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let owner = create_user(&pool, false).await;
            let stranger = create_user(&pool, false).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let wh = insert_webhook(&pool, Some(owner), None).await;

            // Owner can list deliveries of their own webhook.
            assert!(list_deliveries(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(owner, false)),
                axum::extract::Path(wh),
                axum::extract::Query(ListDeliveriesQuery {
                    status: None,
                    page: None,
                    per_page: None,
                }),
            )
            .await
            .is_ok());

            // Stranger denied -> 404 (delivery listing inherits webhook authz).
            assert!(is_not_found(
                &list_deliveries(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path(wh),
                    axum::extract::Query(ListDeliveriesQuery {
                        status: None,
                        page: None,
                        per_page: None,
                    }),
                )
                .await
            ));

            cleanup(&pool, &[], &[owner, stranger]).await;
        }

        // ===================================================================
        // redeliver — denial must short-circuit before re-sending
        // ===================================================================

        #[tokio::test]
        async fn redeliver_denied_cross_user() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let owner = create_user(&pool, false).await;
            let stranger = create_user(&pool, false).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let wh = insert_webhook(&pool, Some(owner), None).await;
            let delivery_id = Uuid::new_v4();

            // Stranger denied -> 404 from the webhook authz gate, before the
            // delivery row is ever looked up or re-sent.
            assert!(is_not_found(
                &redeliver(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path((wh, delivery_id)),
                )
                .await
            ));

            cleanup(&pool, &[], &[owner, stranger]).await;
        }

        // ===================================================================
        // rotate_webhook_secret — mutating path
        // ===================================================================

        #[tokio::test]
        async fn rotate_secret_authz() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let owner = create_user(&pool, false).await;
            let stranger = create_user(&pool, false).await;
            let admin = create_user(&pool, true).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let wh = insert_webhook(&pool, Some(owner), None).await;

            // Stranger denied -> 404.
            assert!(is_not_found(
                &rotate_webhook_secret(
                    axum::extract::State(state.clone()),
                    axum::Extension(auth_for(stranger, false)),
                    axum::extract::Path(wh),
                )
                .await
            ));

            // Owner passes the authz gate (the rotation may still fail later if
            // the deployment has no `AK_WEBHOOK_SECRET_KEY` configured for
            // encryption — that is orthogonal to authorization, so we only
            // assert it is NOT the existence-hiding 404 the gate emits).
            assert!(
                !is_not_found(
                    &rotate_webhook_secret(
                        axum::extract::State(state.clone()),
                        axum::Extension(auth_for(owner, false)),
                        axum::extract::Path(wh),
                    )
                    .await
                ),
                "owner must pass the rotate authz gate"
            );

            // Admin passes the authz gate on another principal's webhook.
            assert!(
                !is_not_found(
                    &rotate_webhook_secret(
                        axum::extract::State(state.clone()),
                        axum::Extension(auth_for(admin, true)),
                        axum::extract::Path(wh),
                    )
                    .await
                ),
                "admin must pass the rotate authz gate"
            );

            cleanup(&pool, &[], &[owner, stranger, admin]).await;
        }

        // ===================================================================
        // list_webhooks — scoping: owner sees own, admin sees all, repo member
        // sees repo-attached.
        // ===================================================================

        #[tokio::test]
        async fn list_webhooks_scoping() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let owner = create_user(&pool, false).await;
            let stranger = create_user(&pool, false).await;
            let member = create_user(&pool, false).await;
            let admin = create_user(&pool, true).await;
            let repo = create_repo(&pool).await;
            grant_repo_access(&pool, member, repo).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let owner_global = insert_webhook(&pool, Some(owner), None).await;
            let owner_repo = insert_webhook(&pool, Some(owner), Some(repo)).await;

            let empty_query = || ListWebhooksQuery {
                repository_id: None,
                enabled: None,
                page: None,
                per_page: Some(100),
            };

            // Owner sees both of their own webhooks.
            let owner_list = list_webhooks(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(owner, false)),
                axum::extract::Query(empty_query()),
            )
            .await
            .unwrap();
            let owner_ids: Vec<Uuid> = owner_list.0.items.iter().map(|w| w.id).collect();
            assert!(
                owner_ids.contains(&owner_global),
                "owner must see own global webhook"
            );
            assert!(
                owner_ids.contains(&owner_repo),
                "owner must see own repo webhook"
            );

            // Stranger (no ownership, no repo role) sees neither.
            let stranger_list = list_webhooks(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(stranger, false)),
                axum::extract::Query(empty_query()),
            )
            .await
            .unwrap();
            let stranger_ids: Vec<Uuid> = stranger_list.0.items.iter().map(|w| w.id).collect();
            assert!(
                !stranger_ids.contains(&owner_global) && !stranger_ids.contains(&owner_repo),
                "stranger must not see other principals' webhooks"
            );

            // Repo member sees the repo-attached one but not the owner's global one.
            let member_list = list_webhooks(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(member, false)),
                axum::extract::Query(empty_query()),
            )
            .await
            .unwrap();
            let member_ids: Vec<Uuid> = member_list.0.items.iter().map(|w| w.id).collect();
            assert!(
                member_ids.contains(&owner_repo),
                "repo member must see repo-attached webhook"
            );
            assert!(
                !member_ids.contains(&owner_global),
                "repo member must not see foreign global webhook"
            );

            // Admin sees everything (scope predicate disabled).
            let admin_list = list_webhooks(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(admin, true)),
                axum::extract::Query(empty_query()),
            )
            .await
            .unwrap();
            let admin_ids: Vec<Uuid> = admin_list.0.items.iter().map(|w| w.id).collect();
            assert!(
                admin_ids.contains(&owner_global) && admin_ids.contains(&owner_repo),
                "admin must see all webhooks"
            );

            cleanup(&pool, &[repo], &[owner, stranger, member, admin]).await;
        }

        // ===================================================================
        // create_webhook — stamps created_by with the caller (ownership anchor).
        // ===================================================================

        #[tokio::test]
        async fn create_webhook_records_created_by() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            // #2321 G4: webhook creation is admin-only. Create as an admin
            // identity; `created_by` is still stamped with that caller, and the
            // NON-admin owner read path below must keep working for the same id.
            let creator = create_user(&pool, true).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let resp = create_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(creator, true)),
                axum::Json(CreateWebhookRequest {
                    name: format!("created-by-{}", &creator.to_string()[..8]),
                    url: "http://198.51.100.9/hook".to_string(),
                    events: vec!["artifact.created".to_string()],
                    repository_id: None,
                    headers: None,
                    secret: None,
                    payload_template: Default::default(),
                    event_schema_version: None,
                }),
            )
            .await
            .expect("create webhook");

            let new_id = resp.0.webhook.id;
            let stored: Option<Uuid> =
                sqlx::query_scalar("SELECT created_by FROM webhooks WHERE id = $1")
                    .bind(new_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(
                stored,
                Some(creator),
                "create_webhook must stamp created_by with the caller"
            );

            // And the creator can immediately reach it (owner path), confirming
            // the ownership anchor is wired through to the authz decision.
            assert!(get_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(creator, false)),
                axum::extract::Path(new_id),
            )
            .await
            .is_ok());

            cleanup(&pool, &[], &[creator]).await;
        }

        /// #2321 G4 (denial): a non-admin caller cannot create a webhook. The
        /// gate fires BEFORE URL validation / secret generation / any DB write,
        /// so a valid request body still returns 403.
        #[tokio::test]
        async fn create_webhook_requires_admin() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let creator = create_user(&pool, false).await;
            let state = tdh::build_state(pool.clone(), "/tmp");

            let result = create_webhook(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(creator, false)),
                axum::Json(CreateWebhookRequest {
                    name: "nonadmin-denied".to_string(),
                    url: "http://198.51.100.9/hook".to_string(),
                    events: vec!["artifact.created".to_string()],
                    repository_id: None,
                    headers: None,
                    secret: None,
                    payload_template: Default::default(),
                    event_schema_version: None,
                }),
            )
            .await;

            // Nothing must have been written.
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE created_by = $1")
                    .bind(creator)
                    .fetch_one(&pool)
                    .await
                    .unwrap();

            cleanup(&pool, &[], &[creator]).await;

            assert!(
                matches!(result, Err(AppError::Authorization(_))),
                "non-admin create_webhook must be 403, got: {result:?}"
            );
            assert_eq!(count, 0, "a denied create must not persist a webhook");
        }
    }
}
