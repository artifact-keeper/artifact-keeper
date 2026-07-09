//! Email subscription CRUD API.
//!
//! Replaces the email side of the v1.1.x `/api/v1/repositories/:key/notifications`
//! routes (deleted in #920). Operators manage email subscriptions per-repo
//! (or globally with `repository_id IS NULL`) through this surface; the
//! delivery side lives in [`crate::services::email_dispatcher`].
//!
//! Auth contract: every mutation requires `write:repositories` scope AND
//! `can_access_repo` on the target repository. Listing requires the same
//! scope. Global (NULL repo_id) subscriptions require admin.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::repositories::require_repo_write_access;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
use crate::services::repository_service::RepositoryService;

/// Defense-in-depth cap on how many recipient addresses one subscription
/// can fan out to. Old `notification_dispatcher` had no cap (security M1);
/// even with this in place, a malicious operator could create N subscriptions
/// each at this size, so per-event rate limiting is the proper backstop.
/// 32 covers realistic ops mailing lists (oncall + secondary + 2-3 humans)
/// with a safety margin.
const MAX_RECIPIENTS_PER_SUBSCRIPTION: usize = 32;

/// Allowed event-type tokens. The dispatcher does substring filtering against
/// this list when matching events to subscriptions; rejecting unknown tokens
/// at write time prevents a typo from silently dropping all notifications.
const VALID_EVENT_TYPES: &[&str] = &[
    "artifact.uploaded",
    "artifact.deleted",
    "scan.completed",
    "scan.failed",
    "repository.created",
    "repository.deleted",
    "license.violation",
    "vulnerability.detected",
    "age_gate.queued",
    "age_gate.approved",
    "age_gate.rejected",
];

pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:key/email-subscriptions",
            get(list_subscriptions).post(create_subscription),
        )
        .route(
            "/:key/email-subscriptions/:subscription_id",
            delete(delete_subscription),
        )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateEmailSubscriptionRequest {
    /// Email addresses to deliver matching events to. Bounded length;
    /// see `MAX_RECIPIENTS_PER_SUBSCRIPTION` for the operator-facing limit.
    pub recipients: Vec<String>,
    /// Event-type tokens to listen for. Must be drawn from `VALID_EVENT_TYPES`.
    pub event_types: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EmailSubscriptionResponse {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub recipients: Vec<String>,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// FromRow shape for the seven columns the handlers read out of
/// `email_subscriptions`. Splitting this from the response struct lets
/// the DB read use the typed `query_as!` style and lets the pure
/// row->response conversion be unit-tested without spinning up a
/// database (the response derives `Serialize` for the JSON output but
/// nothing in serde's macro pipeline understands `sqlx::FromRow`).
#[derive(Debug, sqlx::FromRow)]
pub(crate) struct EmailSubscriptionRow {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub recipients: Vec<String>,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<EmailSubscriptionRow> for EmailSubscriptionResponse {
    fn from(row: EmailSubscriptionRow) -> Self {
        Self {
            id: row.id,
            repository_id: row.repository_id,
            recipients: row.recipients,
            event_types: row.event_types,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EmailSubscriptionListResponse {
    pub subscriptions: Vec<EmailSubscriptionResponse>,
}

/// Fire-and-forget audit log for email subscription mutations (#1170).
///
/// Pattern follows the 2026-03-23 audit sprint shape (see
/// `api::handlers::auth::audit_auth`): write failures are swallowed at
/// `warn!` level so an audit-store hiccup never turns into a 500 on the
/// caller's mutating request. The subscription is already committed
/// (we audit AFTER the SQL) so a missed audit row is the lesser evil.
///
/// `resource_type = Repository, resource_id = repository_id` so audit
/// queries scoped to a repository surface the subscription mutation
/// (per the issue spec). `subscription_id` is carried in `details` so
/// the row is still traceable back to the specific subscription.
async fn audit_subscription_mutation(
    state: &SharedState,
    action: AuditAction,
    actor_user_id: Uuid,
    repository_id: Uuid,
    subscription_id: Uuid,
    extra_details: serde_json::Value,
) {
    let mut details = serde_json::Map::new();
    details.insert(
        "subscription_id".to_string(),
        serde_json::Value::String(subscription_id.to_string()),
    );
    if let serde_json::Value::Object(extras) = extra_details {
        for (k, v) in extras {
            details.insert(k, v);
        }
    }

    let entry = AuditEntry::new(action, ResourceType::Repository)
        .user(actor_user_id)
        .resource(repository_id)
        .details(serde_json::Value::Object(details));

    if let Err(e) = AuditService::new(state.db.clone()).log(entry).await {
        tracing::warn!(
            error = %e,
            action = action.as_str(),
            repository_id = %repository_id,
            subscription_id = %subscription_id,
            "Failed to write email subscription audit log; mutation already committed"
        );
    }
}

/// Require that the caller can mutate email subscriptions on this repository.
///
/// 1. Authenticated.
/// 2. `write:repositories` scope (or admin).
/// 3. `can_access_repo` on the target repo.
///
/// 404 (not 403) on the access-denied case to avoid leaking the existence
/// of repo ids; same pattern as the SBOM endpoints (#903 F6).
fn require_repo_write(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    if auth.is_admin {
        return Ok(auth);
    }
    auth.require_scope("write:repositories")?;
    Ok(auth)
}

/// Resolve a repository by key and fully authorize the caller for an
/// email-subscription operation on it. Combines the three gates the handlers
/// share: write scope (`require_repo_write`), token repo-scope with
/// existence-hiding 404 (`can_access_repo`), and the canonical tenant gate
/// (`require_repo_write_access` = is_public + per-repo role-assignment
/// membership). Returns the authorized principal and the resolved repository id.
///
/// The /repositories nest runs under `optional_auth_middleware` only, NOT
/// `repo_visibility_middleware`, so this enforcement lives in-handler; factoring
/// it here keeps the three handlers from re-deriving (or forgetting) the gate.
async fn authorize_subscription_repo(
    state: &SharedState,
    auth: Option<AuthExtension>,
    key: &str,
) -> Result<(AuthExtension, Uuid)> {
    let auth = require_repo_write(auth)?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(key).await?;
    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }
    require_repo_write_access(&auth, &repo, &repo_service).await?;
    Ok((auth, repo.id))
}

/// Validate the supplied event-type tokens against [`VALID_EVENT_TYPES`].
/// Returns `Err(Validation)` listing unknown tokens; doing this at write
/// time prevents typos from silently dropping notifications at delivery.
pub(crate) fn validate_event_types(event_types: &[String]) -> Result<()> {
    if event_types.is_empty() {
        return Err(AppError::Validation(
            "event_types must contain at least one entry".to_string(),
        ));
    }
    let unknown: Vec<&String> = event_types
        .iter()
        .filter(|t| !VALID_EVENT_TYPES.contains(&t.as_str()))
        .collect();
    if !unknown.is_empty() {
        return Err(AppError::Validation(format!(
            "Unknown event types: {:?}. Valid: {:?}",
            unknown, VALID_EVENT_TYPES
        )));
    }
    Ok(())
}

/// Validate the supplied recipient list.
///
/// - Non-empty
/// - Bounded length (`MAX_RECIPIENTS_PER_SUBSCRIPTION`)
/// - Each entry passes minimal syntactic checks (contains `@`, non-empty
///   local + domain parts). This is intentionally light; SMTP delivery
///   itself is the canonical validator. The goal here is to reject
///   obvious junk before it reaches the database.
pub(crate) fn validate_recipients(recipients: &[String]) -> Result<()> {
    if recipients.is_empty() {
        return Err(AppError::Validation(
            "recipients must contain at least one address".to_string(),
        ));
    }
    if recipients.len() > MAX_RECIPIENTS_PER_SUBSCRIPTION {
        return Err(AppError::Validation(format!(
            "recipients count ({}) exceeds maximum of {}",
            recipients.len(),
            MAX_RECIPIENTS_PER_SUBSCRIPTION
        )));
    }
    for addr in recipients {
        let trimmed = addr.trim();
        // Reject log-forgery payloads before any other check: a recipient
        // like `"victim@x.com\n[ERROR] forged"` is syntactically a valid
        // email by the @-count rule below but is a log-forgery payload
        // (it survives into the dispatcher's `tracing::warn!` lines).
        // The dispatcher additionally sanitizes at log time, but rejecting
        // at write time prevents bad rows from ever landing.
        //
        // Bans: ASCII control range AND Unicode line/paragraph separators
        // (U+2028, U+2029) and U+0085 NEL. The latter are general-category
        // Zl/Zp/Cc-but-not-C0 and `char::is_control()` does NOT cover the
        // separators, yet many log viewers render them as newlines.
        let forbidden =
            |c: char| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{0085}');
        if addr.chars().any(forbidden) {
            return Err(AppError::Validation(
                "recipient contains control or line-separator characters".to_string(),
            ));
        }
        let bad = trimmed.is_empty()
            || !trimmed.contains('@')
            || trimmed.starts_with('@')
            || trimmed.ends_with('@')
            || trimmed.split('@').filter(|p| !p.is_empty()).count() != 2;
        if bad {
            return Err(AppError::Validation(format!(
                "recipient '{}' is not a valid email address",
                trimmed
            )));
        }
    }
    Ok(())
}

/// List the email subscriptions configured on a repository.
#[utoipa::path(
    get,
    path = "/{key}/email-subscriptions",
    context_path = "/api/v1/repositories",
    tag = "email_subscriptions",
    params(("key" = String, Path, description = "Repository key")),
    responses(
        (status = 200, description = "List of email subscriptions", body = EmailSubscriptionListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_subscriptions(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<EmailSubscriptionListResponse>> {
    let (_auth, repo_id) = authorize_subscription_repo(&state, auth, &key).await?;

    let rows: Vec<EmailSubscriptionRow> = sqlx::query_as(
        r#"
        SELECT id, repository_id, recipients, event_types, enabled,
               created_at, updated_at
        FROM email_subscriptions
        WHERE repository_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(repo_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let subscriptions = rows.into_iter().map(Into::into).collect();
    Ok(Json(EmailSubscriptionListResponse { subscriptions }))
}

/// Create an email subscription scoped to a repository.
#[utoipa::path(
    post,
    path = "/{key}/email-subscriptions",
    context_path = "/api/v1/repositories",
    tag = "email_subscriptions",
    params(("key" = String, Path, description = "Repository key")),
    request_body = CreateEmailSubscriptionRequest,
    responses(
        (status = 201, description = "Subscription created", body = EmailSubscriptionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_subscription(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(body): Json<CreateEmailSubscriptionRequest>,
) -> Result<(StatusCode, Json<EmailSubscriptionResponse>)> {
    let (auth, repo_id) = authorize_subscription_repo(&state, auth, &key).await?;

    validate_event_types(&body.event_types)?;
    validate_recipients(&body.recipients)?;

    let row: EmailSubscriptionRow = sqlx::query_as(
        r#"
        INSERT INTO email_subscriptions
            (repository_id, recipients, event_types, enabled)
        VALUES ($1, $2, $3, $4)
        RETURNING id, repository_id, recipients, event_types, enabled,
                  created_at, updated_at
        "#,
    )
    .bind(repo_id)
    .bind(&body.recipients)
    .bind(&body.event_types)
    .bind(body.enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // #1170: audit log AFTER successful insert. recipient_count is
    // surfaced so SOC 2 auditors can spot a sub being created with a
    // wide fan-out without reading the raw recipient list (which is
    // PII).
    audit_subscription_mutation(
        &state,
        AuditAction::EmailSubscriptionCreated,
        auth.user_id,
        repo_id,
        row.id,
        serde_json::json!({
            "recipient_count": row.recipients.len(),
            "event_types": row.event_types,
            "enabled": row.enabled,
        }),
    )
    .await;

    // 201 to match the published spec (`status = 201` above); the handler
    // used to return a bare 200, which strict generated SDKs reject.
    Ok((StatusCode::CREATED, Json(row.into())))
}

/// Delete an email subscription by id.
#[utoipa::path(
    delete,
    path = "/{key}/email-subscriptions/{subscription_id}",
    context_path = "/api/v1/repositories",
    tag = "email_subscriptions",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("subscription_id" = Uuid, Path, description = "Subscription ID")
    ),
    responses(
        (status = 204, description = "Subscription deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Subscription or repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_subscription(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, subscription_id)): Path<(String, Uuid)>,
) -> Result<axum::http::StatusCode> {
    let (auth, repo_id) = authorize_subscription_repo(&state, auth, &key).await?;

    let result =
        sqlx::query("DELETE FROM email_subscriptions WHERE id = $1 AND repository_id = $2")
            .bind(subscription_id)
            .bind(repo_id)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Email subscription '{}' not found on repository '{}'",
            subscription_id, key
        )));
    }

    // #1170: audit AFTER the row is gone. Match the create-side shape so
    // an audit consumer can pair the two events on `subscription_id`.
    audit_subscription_mutation(
        &state,
        AuditAction::EmailSubscriptionDeleted,
        auth.user_id,
        repo_id,
        subscription_id,
        serde_json::json!({}),
    )
    .await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(OpenApi)]
#[openapi(
    paths(list_subscriptions, create_subscription, delete_subscription),
    components(schemas(
        CreateEmailSubscriptionRequest,
        EmailSubscriptionResponse,
        EmailSubscriptionListResponse,
    )),
    tags((name = "email_subscriptions", description = "Per-repository email subscription management"))
)]
pub struct EmailSubscriptionsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-tenant authz guard (xtenant-write-authz-systemic). The
    /// email-subscription endpoints live under the /repositories nest (not gated
    /// by repo_visibility_middleware) and previously enforced only token-scope
    /// (`can_access_repo`), which falls open across tenants. Assert each handler
    /// also calls the tenant gate `require_repo_write_access` (is_public +
    /// role_assignments membership). String-grep because the handlers need a DB.
    #[test]
    fn test_email_subscription_handlers_enforce_tenant_gate() {
        let source = include_str!("email_subscriptions.rs");
        for handler in [
            "list_subscriptions",
            "create_subscription",
            "delete_subscription",
        ] {
            let marker = format!("pub async fn {}(", handler);
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("handler `{}` not found", handler));
            let rest = &source[start + marker.len()..];
            let end = rest.find("\npub async fn ").unwrap_or(rest.len());
            assert!(
                rest[..end].contains("authorize_subscription_repo("),
                "handler `{}` must authorize through authorize_subscription_repo (xtenant)",
                handler
            );
        }
        // The shared helper is where the tenant gate actually lives.
        let helper_start = source
            .find("async fn authorize_subscription_repo(")
            .expect("authorize_subscription_repo helper not found");
        let helper = &source[helper_start..];
        let helper_end = helper.find("\n}\n").map(|i| i + 2).unwrap_or(helper.len());
        assert!(
            helper[..helper_end].contains("require_repo_write_access("),
            "authorize_subscription_repo must call require_repo_write_access (xtenant)"
        );
    }

    #[test]
    fn test_validate_event_types_accepts_known_tokens() {
        validate_event_types(&[
            "artifact.uploaded".to_string(),
            "scan.completed".to_string(),
        ])
        .expect("known event types must validate");
    }

    #[test]
    fn test_validate_event_types_rejects_unknown_token() {
        let err = validate_event_types(&["nope.unknown".to_string()]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("nope.unknown")),
            other => panic!("expected Validation error, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_event_types_rejects_empty() {
        let err = validate_event_types(&[]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_accepts_simple_addresses() {
        validate_recipients(&[
            "ops@example.com".to_string(),
            "team@example.org".to_string(),
        ])
        .expect("syntactically valid addresses must pass");
    }

    #[test]
    fn test_validate_recipients_rejects_empty() {
        let err = validate_recipients(&[]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_rejects_over_cap() {
        let many: Vec<String> = (0..MAX_RECIPIENTS_PER_SUBSCRIPTION + 1)
            .map(|i| format!("u{}@example.com", i))
            .collect();
        let err = validate_recipients(&many).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("exceeds maximum")),
            other => panic!("expected Validation error, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_recipients_rejects_malformed() {
        let cases = [
            "no-at-sign",
            "@no-local-part",
            "no-domain@",
            "two@at@signs",
            "  ",
        ];
        for bad in cases {
            let err = validate_recipients(&[bad.to_string()]).unwrap_err();
            assert!(
                matches!(err, AppError::Validation(_)),
                "expected Validation for {:?}",
                bad
            );
        }
    }

    #[test]
    fn test_max_recipients_per_subscription_is_documented_constant() {
        assert_eq!(MAX_RECIPIENTS_PER_SUBSCRIPTION, 32);
    }

    // -----------------------------------------------------------------------
    // EmailSubscriptionRow -> EmailSubscriptionResponse: pure conversion
    // that lives between the sqlx Row layer and the JSON response layer.
    // Unit-tested here without a DB so the coverage gate can see it
    // exercised; integration coverage on the surrounding handler is
    // implicit via the smoke / E2E tiers.
    // -----------------------------------------------------------------------

    fn sample_row() -> EmailSubscriptionRow {
        EmailSubscriptionRow {
            id: Uuid::new_v4(),
            repository_id: Some(Uuid::new_v4()),
            recipients: vec![
                "ops@example.com".to_string(),
                "team@example.com".to_string(),
            ],
            event_types: vec!["artifact.uploaded".to_string()],
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_row_into_response_preserves_all_scalars() {
        let row = sample_row();
        let expected_id = row.id;
        let expected_repo = row.repository_id;
        let expected_created = row.created_at;
        let expected_updated = row.updated_at;
        let response: EmailSubscriptionResponse = row.into();
        assert_eq!(response.id, expected_id);
        assert_eq!(response.repository_id, expected_repo);
        assert_eq!(response.created_at, expected_created);
        assert_eq!(response.updated_at, expected_updated);
        assert!(response.enabled);
    }

    #[test]
    fn test_row_into_response_preserves_vec_fields_in_order() {
        // Order matters for the UI's "recipient list" display + for any
        // checksum-based caching downstream. The conversion is a value
        // move so order is preserved by Vec's iteration, but verify
        // since this is the contract.
        let row = EmailSubscriptionRow {
            id: Uuid::nil(),
            repository_id: None,
            recipients: vec![
                "a@x.com".to_string(),
                "b@x.com".to_string(),
                "c@x.com".to_string(),
            ],
            event_types: vec![
                "artifact.uploaded".to_string(),
                "scan.completed".to_string(),
            ],
            enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let response: EmailSubscriptionResponse = row.into();
        assert_eq!(
            response.recipients,
            vec![
                "a@x.com".to_string(),
                "b@x.com".to_string(),
                "c@x.com".to_string()
            ]
        );
        assert_eq!(
            response.event_types,
            vec![
                "artifact.uploaded".to_string(),
                "scan.completed".to_string()
            ]
        );
        assert!(!response.enabled);
        assert!(response.repository_id.is_none());
    }

    #[test]
    fn test_row_into_response_handles_empty_recipients_and_events() {
        // The DB schema has NOT NULL constraints on the arrays but allows
        // empty arrays. The conversion must not drop or rewrite them.
        let row = EmailSubscriptionRow {
            id: Uuid::new_v4(),
            repository_id: Some(Uuid::new_v4()),
            recipients: vec![],
            event_types: vec![],
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let response: EmailSubscriptionResponse = row.into();
        assert!(response.recipients.is_empty());
        assert!(response.event_types.is_empty());
    }

    // -----------------------------------------------------------------------
    // Request / response serialization round-trips. These exercise the
    // serde derives so the wire shape is locked in even when no handler
    // runs (which is the coverage gate's blind spot on DB-bound code).
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_request_deserialize_full() {
        let json = r#"{
            "recipients": ["ops@x.com"],
            "event_types": ["scan.completed"],
            "enabled": true
        }"#;
        let req: CreateEmailSubscriptionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.recipients, vec!["ops@x.com".to_string()]);
        assert_eq!(req.event_types, vec!["scan.completed".to_string()]);
        assert!(req.enabled);
    }

    #[test]
    fn test_create_request_enabled_defaults_to_true() {
        let json = r#"{
            "recipients": ["ops@x.com"],
            "event_types": ["scan.completed"]
        }"#;
        let req: CreateEmailSubscriptionRequest = serde_json::from_str(json).unwrap();
        assert!(req.enabled, "missing `enabled` field must default to true");
    }

    #[test]
    fn test_response_serialize_round_trip() {
        let response = EmailSubscriptionResponse {
            id: Uuid::nil(),
            repository_id: Some(Uuid::nil()),
            recipients: vec!["x@y.com".to_string()],
            event_types: vec!["artifact.uploaded".to_string()],
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&response).expect("serializes");
        assert!(json.contains("\"recipients\""));
        assert!(json.contains("\"event_types\""));
        assert!(json.contains("\"enabled\":true"));
    }

    #[test]
    fn test_list_response_serialize_includes_subscriptions_field() {
        let list = EmailSubscriptionListResponse {
            subscriptions: vec![],
        };
        let json = serde_json::to_string(&list).unwrap();
        assert!(
            json.contains("\"subscriptions\""),
            "list response must wrap entries under `subscriptions`; got {}",
            json
        );
    }

    // -----------------------------------------------------------------------
    // VALID_EVENT_TYPES pin: the dispatcher's substring filter relies on
    // this list having coverage for every event class operators expect
    // to subscribe to. Locking this in via test catches accidental
    // deletes that would silently drop notifications for the missing
    // class. Also doubles as documentation of the public contract.
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_event_types_includes_artifact_class() {
        assert!(VALID_EVENT_TYPES.contains(&"artifact.uploaded"));
        assert!(VALID_EVENT_TYPES.contains(&"artifact.deleted"));
    }

    #[test]
    fn test_valid_event_types_includes_scan_class() {
        assert!(VALID_EVENT_TYPES.contains(&"scan.completed"));
        assert!(VALID_EVENT_TYPES.contains(&"scan.failed"));
    }

    #[test]
    fn test_valid_event_types_includes_security_classes() {
        assert!(VALID_EVENT_TYPES.contains(&"license.violation"));
        assert!(VALID_EVENT_TYPES.contains(&"vulnerability.detected"));
    }

    #[test]
    fn test_valid_event_types_includes_repository_class() {
        assert!(VALID_EVENT_TYPES.contains(&"repository.created"));
        assert!(VALID_EVENT_TYPES.contains(&"repository.deleted"));
    }

    #[test]
    fn test_validate_event_types_accepts_all_known_tokens() {
        // Round-trip every token in VALID_EVENT_TYPES through the
        // validator. If any token in the constant fails its own
        // validator, the constant is internally inconsistent.
        for et in VALID_EVENT_TYPES {
            validate_event_types(&[et.to_string()])
                .unwrap_or_else(|_| panic!("event type {:?} must validate", et));
        }
    }

    #[test]
    fn test_validate_event_types_partial_unknown_still_rejects() {
        // Mix one valid + one unknown. Must still error so the typo
        // doesn't silently subscribe the caller only to the valid half.
        let err =
            validate_event_types(&["artifact.uploaded".to_string(), "typo.invalid".to_string()])
                .unwrap_err();
        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains("typo.invalid"),
                    "msg should name the bad token: {}",
                    msg
                );
            }
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_recipients_accepts_exactly_at_cap() {
        // Boundary: exactly MAX is allowed, MAX+1 is the rejection threshold
        // (already covered by test_validate_recipients_rejects_over_cap).
        let exactly: Vec<String> = (0..MAX_RECIPIENTS_PER_SUBSCRIPTION)
            .map(|i| format!("u{}@x.com", i))
            .collect();
        validate_recipients(&exactly).expect("exactly cap-many must pass");
    }

    #[test]
    fn test_validate_recipients_accepts_single() {
        validate_recipients(&["sole@example.com".to_string()]).expect("single recipient must pass");
    }

    #[test]
    fn test_validate_recipients_rejects_whitespace_only() {
        let err = validate_recipients(&["   ".to_string()]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_rejects_no_at_sign() {
        let err = validate_recipients(&["plain-no-at".to_string()]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("plain-no-at")),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_recipients_rejects_newline_in_address() {
        // Log-forgery prevention: a stored recipient that survives into
        // the dispatcher's tracing logs could otherwise inject fake log
        // lines. Reject at write time.
        let err = validate_recipients(&["victim@x.com\n[ERROR] fake".to_string()]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("control")),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_recipients_rejects_carriage_return() {
        let err = validate_recipients(&["a\rb@x.com".to_string()]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_rejects_ansi_escape() {
        // ESC (0x1b) is a control char; rejection prevents ANSI-colored
        // log forgery in terminal log viewers.
        let err = validate_recipients(&["a\x1b[31m@x.com".to_string()]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_rejects_null_byte() {
        let err = validate_recipients(&["a\0b@x.com".to_string()]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_rejects_unicode_line_separator() {
        // U+2028 LINE SEPARATOR: NOT an ASCII control char so
        // `is_control()` alone would miss it. Many log viewers render
        // it as a newline, enabling the same forgery as `\n`.
        let err = validate_recipients(&["a\u{2028}b@x.com".to_string()]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_rejects_unicode_paragraph_separator() {
        let err = validate_recipients(&["a\u{2029}b@x.com".to_string()]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_rejects_nel() {
        // U+0085 NEXT LINE: ECMA-48 line terminator.
        let err = validate_recipients(&["a\u{0085}b@x.com".to_string()]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_first_bad_in_batch_short_circuits() {
        // The validator iterates in order and bails on the first bad
        // entry. A batch with [good, bad, good] must error with the
        // BAD entry's message, not the trailing good entry.
        let err = validate_recipients(&[
            "first@good.com".to_string(),
            "no-at-here".to_string(),
            "third@good.com".to_string(),
        ])
        .unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("no-at-here")),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn test_default_enabled_returns_true() {
        // The serde `default = "default_enabled"` plumbing is exercised
        // by test_create_request_enabled_defaults_to_true, but pin the
        // raw default value too in case the wiring is ever changed.
        assert!(default_enabled());
    }

    #[test]
    fn test_router_builds_without_panic() {
        // Smoke: the router constructor itself has no behaviour beyond
        // wiring routes, but exercising it covers the route-table
        // construction lines. Axum's Router doesn't expose route
        // introspection without consuming so this is just construction.
        let _r = router();
    }

    #[test]
    fn test_email_subscription_row_construction_round_trip() {
        // The FromRow struct itself is not a free function but its
        // field ordering is part of the SQL contract. Construct,
        // convert, and verify shape.
        let now = Utc::now();
        let row = EmailSubscriptionRow {
            id: Uuid::nil(),
            repository_id: None,
            recipients: vec![],
            event_types: vec![],
            enabled: false,
            created_at: now,
            updated_at: now,
        };
        assert!(!row.enabled);
        let r: EmailSubscriptionResponse = row.into();
        assert_eq!(r.created_at, now);
        assert_eq!(r.updated_at, now);
    }
}
