//! SBOM (Software Bill of Materials) REST API handlers.

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::sbom::{
    CveStatus, CveTrends, LicensePolicy, PolicyAction, SbomComponent, SbomDocument, SbomFormat,
};
use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
use crate::services::sbom_service::{DependencyInfo, LicenseCheckResult, SbomService};

/// Emit an audit log entry for an SBOM action against an artifact. Failures
/// are logged but never propagated: the mutation/read is already complete and
/// breaking the response over a best-effort audit write would do callers no
/// favors. Mirrors `email_subscriptions::write_audit_log` (#1170).
async fn write_sbom_audit(
    state: &SharedState,
    action: AuditAction,
    actor_user_id: Uuid,
    artifact_id: Uuid,
    extra: serde_json::Value,
) {
    let entry = AuditEntry::new(action, ResourceType::Artifact)
        .user(actor_user_id)
        .resource(artifact_id)
        .details(extra);

    if let Err(e) = AuditService::new(state.db.clone()).log(entry).await {
        tracing::warn!(
            error = %e,
            action = action.as_str(),
            artifact_id = %artifact_id,
            "Failed to write SBOM audit log; SBOM operation already committed"
        );
    }
}

/// Build the JSON `details` payload recorded against an `SBOM_GENERATED`
/// audit entry. Extracted as a pure helper so the audit shape (the contract
/// SOC 2 / EU CRA reviewers read) is unit-testable without spinning up a
/// `SharedState` / Postgres pool.
pub(crate) fn sbom_generated_details(
    sbom_id: Uuid,
    format: &str,
    repository_id: Uuid,
    force_regenerate: bool,
) -> serde_json::Value {
    serde_json::json!({
        "sbom_id": sbom_id.to_string(),
        "format": format,
        "repository_id": repository_id.to_string(),
        "force_regenerate": force_regenerate,
    })
}

/// Build the JSON `details` payload recorded against an `SBOM_READ` audit
/// entry. `lookup` distinguishes the two read endpoints (`by_id` for
/// `GET /sbom/:id`, `by_artifact` for `GET /sbom/by-artifact/:artifact_id`)
/// so auditors can tell automated supply-chain scrapers from interactive
/// console viewers.
pub(crate) fn sbom_read_details(
    sbom_id: Uuid,
    format: &str,
    lookup: &'static str,
) -> serde_json::Value {
    serde_json::json!({
        "sbom_id": sbom_id.to_string(),
        "format": format,
        "lookup": lookup,
    })
}

/// Create SBOM routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        // SBOM operations
        .route("/", get(list_sboms).post(generate_sbom))
        .route("/:id", get(get_sbom).delete(delete_sbom))
        .route("/:id/components", get(get_sbom_components))
        .route("/:id/convert", post(convert_sbom))
        .route("/by-artifact/:artifact_id", get(get_sbom_by_artifact))
        // CVE history. Three routes share the same backing handlers:
        //   - `/cve/history/by-artifact/{uuid}`  -- typed UUID, REST-clean
        //   - `/cve/history/by-cve/{cve_id}`     -- typed CVE-id, REST-clean
        //   - `/cve/history/{id}`                -- legacy overload, kept for
        //     compatibility with the in-flight v1.2.0 SDKs that already
        //     consumed the overloaded shape. New clients should prefer the
        //     two split routes. (#1375 round-2 decision: SPLIT + legacy.)
        .route(
            "/cve/history/by-artifact/:artifact_id",
            get(get_cve_history_by_artifact),
        )
        .route("/cve/history/by-cve/:cve_id", get(get_cve_history_by_cve))
        .route("/cve/history/:id", get(get_cve_history))
        .route("/cve/status/:id", post(update_cve_status))
        .route("/cve/trends", get(get_cve_trends))
        // License policies
        .route(
            "/license-policies",
            get(list_license_policies).post(upsert_license_policy),
        )
        .route(
            "/license-policies/:id",
            get(get_license_policy).delete(delete_license_policy),
        )
        .route("/check-compliance", post(check_license_compliance))
}

// === Request/Response types ===

#[derive(Debug, Deserialize, ToSchema)]
pub struct GenerateSbomRequest {
    pub artifact_id: Uuid,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub force_regenerate: bool,
}

fn default_format() -> String {
    "cyclonedx".to_string()
}

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct ListSbomsQuery {
    pub artifact_id: Option<Uuid>,
    pub repository_id: Option<Uuid>,
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConvertSbomRequest {
    pub target_format: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCveStatusRequest {
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct GetCveTrendsQuery {
    pub repository_id: Option<Uuid>,
    pub days: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckLicenseComplianceRequest {
    pub licenses: Vec<String>,
    pub repository_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SbomResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub format: String,
    pub format_version: String,
    pub spec_version: Option<String>,
    pub component_count: i32,
    pub dependency_count: i32,
    pub license_count: i32,
    pub licenses: Vec<String>,
    pub content_hash: String,
    pub generator: Option<String>,
    pub generator_version: Option<String>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<SbomDocument> for SbomResponse {
    fn from(doc: SbomDocument) -> Self {
        Self {
            id: doc.id,
            artifact_id: doc.artifact_id,
            repository_id: doc.repository_id,
            format: doc.format,
            format_version: doc.format_version,
            spec_version: doc.spec_version,
            component_count: doc.component_count,
            dependency_count: doc.dependency_count,
            license_count: doc.license_count,
            licenses: doc.licenses,
            content_hash: doc.content_hash,
            generator: doc.generator,
            generator_version: doc.generator_version,
            generated_at: doc.generated_at,
            created_at: doc.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SbomContentResponse {
    #[serde(flatten)]
    pub metadata: SbomResponse,
    #[schema(value_type = Object)]
    pub content: serde_json::Value,
}

impl From<SbomDocument> for SbomContentResponse {
    fn from(doc: SbomDocument) -> Self {
        let content = doc.content.clone();
        Self {
            metadata: SbomResponse::from(doc),
            content,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ComponentResponse {
    pub id: Uuid,
    pub sbom_id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub component_type: Option<String>,
    pub licenses: Vec<String>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub supplier: Option<String>,
    pub author: Option<String>,
}

impl From<SbomComponent> for ComponentResponse {
    fn from(c: SbomComponent) -> Self {
        Self {
            id: c.id,
            sbom_id: c.sbom_id,
            name: c.name,
            version: c.version,
            purl: c.purl,
            cpe: c.cpe,
            component_type: c.component_type,
            licenses: c.licenses,
            sha256: c.sha256,
            sha1: c.sha1,
            md5: c.md5,
            supplier: c.supplier,
            author: c.author,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LicensePolicyResponse {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub allowed_licenses: Vec<String>,
    pub denied_licenses: Vec<String>,
    pub allow_unknown: bool,
    pub action: String,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<LicensePolicy> for LicensePolicyResponse {
    fn from(p: LicensePolicy) -> Self {
        Self {
            id: p.id,
            repository_id: p.repository_id,
            name: p.name,
            description: p.description,
            allowed_licenses: p.allowed_licenses,
            denied_licenses: p.denied_licenses,
            allow_unknown: p.allow_unknown,
            action: p.action.as_str().to_string(),
            is_enabled: p.is_enabled,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertLicensePolicyRequest {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub allowed_licenses: Vec<String>,
    pub denied_licenses: Vec<String>,
    #[serde(default = "default_true")]
    pub allow_unknown: bool,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_true")]
    pub is_enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_action() -> String {
    "warn".to_string()
}

// === Handlers ===

/// Generate an SBOM for an artifact
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    request_body = GenerateSbomRequest,
    responses(
        (status = 200, description = "Generated SBOM", body = SbomResponse),
        (status = 404, description = "Artifact not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn generate_sbom(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(body): Json<GenerateSbomRequest>,
) -> Result<Json<SbomResponse>> {
    let service = SbomService::new(state.db.clone());
    let format = SbomFormat::parse(&body.format)
        .ok_or_else(|| AppError::Validation(format!("Unknown format: {}", body.format)))?;

    // Get artifact and repository
    let (_, repository_id): (Uuid, Uuid) =
        sqlx::query_as("SELECT id, repository_id FROM artifacts WHERE id = $1")
            .bind(body.artifact_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Artifact not found".into()))?;

    // If force_regenerate, delete existing SBOM first
    if body.force_regenerate {
        if let Some(existing) = service
            .get_sbom_by_artifact(body.artifact_id, format)
            .await?
        {
            service.delete_sbom(existing.id).await?;
        }
    }

    // Generate SBOM (extract dependencies from scan results if available)
    let deps = extract_dependencies_for_artifact(&state.db, body.artifact_id).await?;

    let doc = service
        .generate_sbom(body.artifact_id, repository_id, format, deps)
        .await?;

    // #1156: SBOMs are an attestation surface relied on for SOC 2 / EU CRA
    // compliance. Record who generated which SBOM, when, and for which
    // artifact. Best-effort: an audit-log failure must not undo the SBOM.
    write_sbom_audit(
        &state,
        AuditAction::SbomGenerated,
        auth.user_id,
        body.artifact_id,
        sbom_generated_details(doc.id, &doc.format, repository_id, body.force_regenerate),
    )
    .await;

    Ok(Json(SbomResponse::from(doc)))
}

/// List SBOMs with optional filters
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(ListSbomsQuery),
    responses(
        (status = 200, description = "List of SBOMs", body = Vec<SbomResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_sboms(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ListSbomsQuery>,
) -> Result<Json<Vec<SbomResponse>>> {
    // #903 F6: when a specific artifact is requested, verify caller access
    // to its repository before enumerating. The repository_id filter below
    // also enforces access (callers cannot list a repo's SBOMs without
    // having access to that repo).
    if let Some(artifact_id) = query.artifact_id {
        ensure_artifact_repo_access(&state.db, &auth, artifact_id).await?;
    }
    if let Some(repo_id) = query.repository_id {
        if !auth.can_access_repo(repo_id) {
            return Err(AppError::NotFound("Repository not found".into()));
        }
    }
    let service = SbomService::new(state.db.clone());

    let sboms = if let Some(artifact_id) = query.artifact_id {
        let summaries = service.list_sboms_for_artifact(artifact_id).await?;
        summaries
            .into_iter()
            .map(|s| SbomResponse {
                id: s.id,
                artifact_id: s.artifact_id,
                repository_id: Uuid::nil(), // Not in summary
                format: s.format.to_string(),
                format_version: s.format_version,
                spec_version: None,
                component_count: s.component_count,
                dependency_count: s.dependency_count,
                license_count: s.license_count,
                licenses: s.licenses,
                content_hash: String::new(),
                generator: s.generator,
                generator_version: None,
                generated_at: s.generated_at,
                created_at: s.created_at,
            })
            .collect()
    } else {
        // #903 F6: a scope-restricted token (allowed_repo_ids = Some) MUST
        // narrow by repository or artifact. Listing all SBOMs would let
        // a token scoped to repo A enumerate dep trees of every other
        // repo. Force the caller to be explicit about the repo scope.
        if auth.is_api_token && auth.allowed_repo_ids.is_some() {
            return Err(AppError::Validation(
                "Scope-restricted tokens must filter by repository_id or artifact_id".into(),
            ));
        }
        // List all SBOMs (with optional filters)
        let mut sql = "SELECT * FROM sbom_documents WHERE 1=1".to_string();
        if query.repository_id.is_some() {
            sql.push_str(" AND repository_id = $1");
        }
        if query.format.is_some() {
            sql.push_str(if query.repository_id.is_some() {
                " AND format = $2"
            } else {
                " AND format = $1"
            });
        }
        sql.push_str(" ORDER BY created_at DESC LIMIT 100");

        let docs: Vec<SbomDocument> = if let Some(repo_id) = query.repository_id {
            if let Some(fmt) = &query.format {
                sqlx::query_as(&sql)
                    .bind(repo_id)
                    .bind(fmt)
                    .fetch_all(&state.db)
                    .await?
            } else {
                sqlx::query_as(&sql)
                    .bind(repo_id)
                    .fetch_all(&state.db)
                    .await?
            }
        } else if let Some(fmt) = &query.format {
            sqlx::query_as(&sql).bind(fmt).fetch_all(&state.db).await?
        } else {
            sqlx::query_as("SELECT * FROM sbom_documents ORDER BY created_at DESC LIMIT 100")
                .fetch_all(&state.db)
                .await?
        };

        docs.into_iter().map(SbomResponse::from).collect()
    };

    Ok(Json(sboms))
}

/// Get SBOM by ID with full content
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("id" = Uuid, Path, description = "SBOM ID")
    ),
    responses(
        (status = 200, description = "SBOM with content", body = SbomContentResponse),
        (status = 404, description = "SBOM not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_sbom(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<SbomContentResponse>> {
    ensure_sbom_repo_access(&state.db, &auth, id).await?;
    let service = SbomService::new(state.db.clone());
    let doc = service
        .get_sbom(id)
        .await?
        .ok_or_else(|| AppError::NotFound("SBOM not found".into()))?;

    // #1156: record SBOM read against the underlying artifact so the chain
    // of custody is queryable per artifact.
    write_sbom_audit(
        &state,
        AuditAction::SbomRead,
        auth.user_id,
        doc.artifact_id,
        sbom_read_details(doc.id, &doc.format, "by_id"),
    )
    .await;

    Ok(Json(SbomContentResponse::from(doc)))
}

/// Get SBOM by artifact ID
#[utoipa::path(
    get,
    path = "/by-artifact/{artifact_id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "SBOM for the artifact", body = SbomContentResponse),
        (status = 404, description = "SBOM not found for artifact", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_sbom_by_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<ListSbomsQuery>,
) -> Result<Json<SbomContentResponse>> {
    ensure_artifact_repo_access(&state.db, &auth, artifact_id).await?;
    let service = SbomService::new(state.db.clone());
    let format = query
        .format
        .as_ref()
        .and_then(|f| SbomFormat::parse(f))
        .unwrap_or(SbomFormat::CycloneDX);

    let doc = service
        .get_sbom_by_artifact(artifact_id, format)
        .await?
        .ok_or_else(|| AppError::NotFound("SBOM not found for artifact".into()))?;

    // #1156: by-artifact lookups are the path most exposed to scripted
    // supply-chain consumers; record them so unusual access patterns are
    // visible in the audit trail.
    write_sbom_audit(
        &state,
        AuditAction::SbomRead,
        auth.user_id,
        artifact_id,
        sbom_read_details(doc.id, &doc.format, "by_artifact"),
    )
    .await;

    Ok(Json(SbomContentResponse::from(doc)))
}

/// Delete an SBOM
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("id" = Uuid, Path, description = "SBOM ID")
    ),
    responses(
        (status = 200, description = "SBOM deleted", body = Object),
        (status = 404, description = "SBOM not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn delete_sbom(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    ensure_sbom_repo_access(&state.db, &auth, id).await?;
    let service = SbomService::new(state.db.clone());
    service.delete_sbom(id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// Get components of an SBOM
#[utoipa::path(
    get,
    path = "/{id}/components",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("id" = Uuid, Path, description = "SBOM ID")
    ),
    responses(
        (status = 200, description = "List of SBOM components", body = Vec<ComponentResponse>),
        (status = 404, description = "SBOM not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_sbom_components(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ComponentResponse>>> {
    ensure_sbom_repo_access(&state.db, &auth, id).await?;
    let service = SbomService::new(state.db.clone());
    let components = service.get_sbom_components(id).await?;
    let responses: Vec<ComponentResponse> = components
        .into_iter()
        .map(ComponentResponse::from)
        .collect();
    Ok(Json(responses))
}

/// Convert an SBOM to a different format
#[utoipa::path(
    post,
    path = "/{id}/convert",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("id" = Uuid, Path, description = "SBOM ID")
    ),
    request_body = ConvertSbomRequest,
    responses(
        (status = 200, description = "Converted SBOM", body = SbomResponse),
        (status = 404, description = "SBOM not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn convert_sbom(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<ConvertSbomRequest>,
) -> Result<Json<SbomResponse>> {
    let service = SbomService::new(state.db.clone());
    let target_format = SbomFormat::parse(&body.target_format)
        .ok_or_else(|| AppError::Validation(format!("Unknown format: {}", body.target_format)))?;

    let doc = service.convert_sbom(id, target_format).await?;
    Ok(Json(SbomResponse::from(doc)))
}

// === CVE History ===

/// Validate that a string is a well-formed CVE identifier.
///
/// Accepts the canonical NVD shape `CVE-YYYY-N` where `N` is any positive
/// integer (4+ digits per CVE 2014 numbering scheme, but the count has grown
/// past 5 digits for high-volume years like 2019). The match is
/// case-insensitive so callers may pass `cve-2019-10744` lowercased.
///
/// Examples:
///   - `CVE-2019-10744`  → true (5 digits, the v1.1.0 release-gate fixture)
///   - `CVE-2024-12345`  → true (5 digits, modern)
///   - `CVE-2024-123456` → true (6 digits, high-volume year)
///   - `CVE-1999-0001`   → true (4 digits, oldest valid form)
///   - `CVE-2019-1`      → false (sub-4-digit suffix, rejected by NVD)
///   - `not-a-cve`       → false
///   - empty             → false
///
/// Previously the endpoint rejected `CVE-2019-10744` outright because the
/// path param was typed as `Uuid`, producing a generic 400 with no useful
/// error message. (#1375)
pub(crate) fn is_valid_cve_id(s: &str) -> bool {
    let s = s.trim();
    let mut parts = s.split('-');
    let prefix = match parts.next() {
        Some(p) => p,
        None => return false,
    };
    if !prefix.eq_ignore_ascii_case("CVE") {
        return false;
    }
    let year = match parts.next() {
        Some(y) => y,
        None => return false,
    };
    let number = match parts.next() {
        Some(n) => n,
        None => return false,
    };
    if parts.next().is_some() {
        // Extra dashes (e.g. `CVE-2024-12345-extra`) are not part of the
        // canonical form. Reject so a stray suffix doesn't silently slip
        // through.
        return false;
    }
    // Year is exactly four ASCII digits (NVD numbering: CVE-1999-* through
    // CVE-9999-*). We tolerate the future-year tail.
    if year.len() != 4 || !year.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Number must be at least four ASCII digits. CVE numbering uses 4+ digits
    // and allows arbitrary growth (six-digit numbers exist in 2024+).
    if number.len() < 4 || !number.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    true
}

/// Outcome of dispatching the overloaded `/cve/history/{id}` path param.
///
/// Pure typing of the UUID-vs-CVE-id sniff so the dispatch decision is
/// unit-testable without booting Axum or Postgres. The handler reads
/// `classify_cve_history_path` and branches on the variant.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CveHistoryPath {
    /// Parsed UUID; treat as artifact_id lookup.
    Artifact(Uuid),
    /// Parsed CVE id (canonical upper-case form); treat as cross-artifact
    /// CVE lookup.
    Cve(String),
    /// Neither parse succeeded; handler returns 400.
    Invalid,
}

/// Classify an overloaded `/cve/history/{id}` path parameter. UUID first
/// (legacy semantic), then CVE id, else invalid.
///
/// Extracted from `get_cve_history` so the routing decision is exercised
/// by unit tests; the async wrapper only owns the DB calls. (#1375)
pub(crate) fn classify_cve_history_path(id: &str) -> CveHistoryPath {
    if let Ok(uuid) = Uuid::parse_str(id) {
        return CveHistoryPath::Artifact(uuid);
    }
    if is_valid_cve_id(id) {
        // Normalize to upper-case so the downstream lookup matches the
        // schema's storage convention.
        return CveHistoryPath::Cve(id.trim().to_ascii_uppercase());
    }
    CveHistoryPath::Invalid
}

/// Construct the 400 message returned when neither a UUID nor a CVE id
/// matches. Pulled out so the message wording (which clients sometimes
/// parse) is pinned by a test.
pub(crate) fn invalid_cve_history_path_message(id: &str) -> String {
    format!("Path id '{id}' is neither a valid UUID nor a CVE identifier (expected `CVE-YYYY-N`)")
}

/// Get CVE history by artifact UUID or CVE identifier (legacy overload).
///
/// The path param accepts either:
///   - A UUID `artifact_id` (legacy shape, returns all CVEs for one artifact)
///   - A CVE id like `CVE-2019-10744` (returns this CVE across every artifact
///     the caller can access)
///
/// # URL design decision (#1385 round-2)
///
/// Overloading a single `{id}` path parameter to mean two different lookups
/// is a REST anti-pattern: the route's behavior changes based on a runtime
/// content sniff. We considered splitting into two routes vs documenting the
/// overload and chose **both**: the split routes
/// `GET /cve/history/by-artifact/{uuid}` and `GET /cve/history/by-cve/{cve_id}`
/// are the canonical shape for new clients (typed path params, no sniff),
/// while this overload remains so the v1.2.0 SDKs that already shipped
/// against the single-route shape keep working. New code should prefer the
/// split routes; the overload may be deprecated in v1.3.
///
/// Issue #1375: prior to this fix the route was typed `Path<Uuid>`, so any
/// CVE-id call (e.g. the release-gate `GET /sbom/cve/history/CVE-2019-10744`)
/// failed Axum's path extractor with a bare HTTP 400, leaving consumers
/// unable to look up history by CVE.
#[utoipa::path(
    get,
    path = "/cve/history/{id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("id" = String, Path, description = "Artifact UUID or CVE identifier (e.g. CVE-2019-10744). Prefer the typed routes /cve/history/by-artifact/{uuid} or /cve/history/by-cve/{cve_id}.")
    ),
    responses(
        (status = 200, description = "CVE history entries", body = Vec<crate::models::sbom::CveHistoryEntry>),
        (status = 400, description = "Path id is neither a valid UUID nor a valid CVE identifier"),
    ),
    security(("bearer_auth" = []))
)]
async fn get_cve_history(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<String>,
) -> Result<Json<Vec<crate::models::sbom::CveHistoryEntry>>> {
    let service = SbomService::new(state.db.clone());

    match classify_cve_history_path(&id) {
        CveHistoryPath::Artifact(artifact_id) => {
            ensure_artifact_repo_access(&state.db, &auth, artifact_id).await?;
            let entries = service.get_cve_history(artifact_id).await?;
            Ok(Json(entries))
        }
        CveHistoryPath::Cve(cve_id) => {
            let entries = service
                .get_cve_history_by_cve_id(&cve_id, auth.allowed_repo_ids.as_deref())
                .await?;
            Ok(Json(entries))
        }
        CveHistoryPath::Invalid => Err(AppError::Validation(invalid_cve_history_path_message(&id))),
    }
}

/// Get CVE history for one artifact (typed UUID variant).
///
/// Canonical replacement for the UUID branch of the overloaded
/// `/cve/history/{id}` route. Returns every CVE ever detected against the
/// given artifact, deduped across curated `cve_history` rows and live
/// `scan_findings` projections.
#[utoipa::path(
    get,
    path = "/cve/history/by-artifact/{artifact_id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact UUID")
    ),
    responses(
        (status = 200, description = "CVE history entries", body = Vec<crate::models::sbom::CveHistoryEntry>),
        (status = 403, description = "Caller does not have access to this artifact's repository"),
        (status = 404, description = "Artifact not found"),
    ),
    security(("bearer_auth" = []))
)]
async fn get_cve_history_by_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Json<Vec<crate::models::sbom::CveHistoryEntry>>> {
    let service = SbomService::new(state.db.clone());
    ensure_artifact_repo_access(&state.db, &auth, artifact_id).await?;
    let entries = service.get_cve_history(artifact_id).await?;
    Ok(Json(entries))
}

/// Construct the 400 message for the typed `/cve/history/by-cve/{cve_id}`
/// route. Separated from `invalid_cve_history_path_message` because the
/// wording is slightly different (typed route knows the id is meant to
/// be a CVE id, not "either a UUID or a CVE id").
pub(crate) fn invalid_cve_id_route_message(cve_id: &str) -> String {
    format!("Path id '{cve_id}' is not a valid CVE identifier (expected `CVE-YYYY-N`)")
}

/// Get CVE history for one CVE identifier across artifacts (typed CVE-id
/// variant).
///
/// Canonical replacement for the CVE-id branch of the overloaded
/// `/cve/history/{id}` route. Returns every artifact the caller can access
/// where the given CVE has been detected.
#[utoipa::path(
    get,
    path = "/cve/history/by-cve/{cve_id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("cve_id" = String, Path, description = "CVE identifier (e.g. CVE-2019-10744)")
    ),
    responses(
        (status = 200, description = "CVE history entries", body = Vec<crate::models::sbom::CveHistoryEntry>),
        (status = 400, description = "Path id is not a valid CVE identifier"),
    ),
    security(("bearer_auth" = []))
)]
async fn get_cve_history_by_cve(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(cve_id): Path<String>,
) -> Result<Json<Vec<crate::models::sbom::CveHistoryEntry>>> {
    if !is_valid_cve_id(&cve_id) {
        return Err(AppError::Validation(invalid_cve_id_route_message(&cve_id)));
    }
    let service = SbomService::new(state.db.clone());
    let entries = service
        .get_cve_history_by_cve_id(&cve_id, auth.allowed_repo_ids.as_deref())
        .await?;
    Ok(Json(entries))
}

/// Update CVE status
#[utoipa::path(
    post,
    path = "/cve/status/{id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("id" = Uuid, Path, description = "CVE history entry ID")
    ),
    request_body = UpdateCveStatusRequest,
    responses(
        (status = 200, description = "Updated CVE entry", body = crate::models::sbom::CveHistoryEntry),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn update_cve_status(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateCveStatusRequest>,
) -> Result<Json<crate::models::sbom::CveHistoryEntry>> {
    let service = SbomService::new(state.db.clone());
    let status = CveStatus::parse(&body.status)
        .ok_or_else(|| AppError::Validation(format!("Unknown status: {}", body.status)))?;

    // #1438 (1c): a non-existent CVE history id used to bubble out of
    // sqlx::Error::RowNotFound as 500 DATABASE_ERROR. Map it explicitly to
    // 404 so the client can distinguish bad input from server failure. All
    // other sqlx errors continue to flow through the default mapping.
    let entry = service
        .update_cve_status(id, status, Some(auth.user_id), body.reason.as_deref())
        .await
        .map_err(|e| match e {
            AppError::Sqlx(sqlx::Error::RowNotFound) => {
                AppError::NotFound(format!("CVE history entry {} not found", id))
            }
            other => other,
        })?;

    Ok(Json(entry))
}

/// Get CVE trends and statistics
#[utoipa::path(
    get,
    path = "/cve/trends",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(GetCveTrendsQuery),
    responses(
        (status = 200, description = "CVE trends", body = CveTrends),
    ),
    security(("bearer_auth" = []))
)]
async fn get_cve_trends(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Query(query): Query<GetCveTrendsQuery>,
) -> Result<Json<CveTrends>> {
    let service = SbomService::new(state.db.clone());
    let trends = service.get_cve_trends(query.repository_id).await?;
    Ok(Json(trends))
}

// === License Policies ===

/// List all license policies
#[utoipa::path(
    get,
    path = "/license-policies",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    responses(
        (status = 200, description = "List of license policies", body = Vec<LicensePolicyResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_license_policies(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<LicensePolicyResponse>>> {
    let policies: Vec<LicensePolicy> =
        sqlx::query_as("SELECT * FROM license_policies ORDER BY name")
            .fetch_all(&state.db)
            .await?;

    let responses: Vec<LicensePolicyResponse> = policies
        .into_iter()
        .map(LicensePolicyResponse::from)
        .collect();
    Ok(Json(responses))
}

/// Get a license policy by ID
#[utoipa::path(
    get,
    path = "/license-policies/{id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("id" = Uuid, Path, description = "License policy ID")
    ),
    responses(
        (status = 200, description = "License policy details", body = LicensePolicyResponse),
        (status = 404, description = "License policy not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_license_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<LicensePolicyResponse>> {
    let policy: LicensePolicy = sqlx::query_as("SELECT * FROM license_policies WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("License policy not found".into()))?;

    Ok(Json(LicensePolicyResponse::from(policy)))
}

/// Create or update a license policy
#[utoipa::path(
    post,
    path = "/license-policies",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    request_body = UpsertLicensePolicyRequest,
    responses(
        (status = 200, description = "Created or updated license policy", body = LicensePolicyResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn upsert_license_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(body): Json<UpsertLicensePolicyRequest>,
) -> Result<Json<LicensePolicyResponse>> {
    let action = PolicyAction::parse(&body.action)
        .ok_or_else(|| AppError::Validation(format!("Unknown action: {}", body.action)))?;

    let policy: LicensePolicy = sqlx::query_as(
        r#"
        INSERT INTO license_policies (
            repository_id, name, description, allowed_licenses,
            denied_licenses, allow_unknown, action, is_enabled
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'), name)
        DO UPDATE SET
            description = EXCLUDED.description,
            allowed_licenses = EXCLUDED.allowed_licenses,
            denied_licenses = EXCLUDED.denied_licenses,
            allow_unknown = EXCLUDED.allow_unknown,
            action = EXCLUDED.action,
            is_enabled = EXCLUDED.is_enabled,
            updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(body.repository_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.allowed_licenses)
    .bind(&body.denied_licenses)
    .bind(body.allow_unknown)
    .bind(action.as_str())
    .bind(body.is_enabled)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(LicensePolicyResponse::from(policy)))
}

/// Delete a license policy
#[utoipa::path(
    delete,
    path = "/license-policies/{id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("id" = Uuid, Path, description = "License policy ID")
    ),
    responses(
        (status = 200, description = "License policy deleted", body = Object),
        (status = 404, description = "License policy not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn delete_license_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    sqlx::query("DELETE FROM license_policies WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// Check license compliance against policies
#[utoipa::path(
    post,
    path = "/check-compliance",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    request_body = CheckLicenseComplianceRequest,
    responses(
        (status = 200, description = "License compliance result", body = LicenseCheckResult),
        (status = 404, description = "No license policy configured", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn check_license_compliance(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(body): Json<CheckLicenseComplianceRequest>,
) -> Result<Json<LicenseCheckResult>> {
    let service = SbomService::new(state.db.clone());
    let policy = service
        .get_license_policy(body.repository_id)
        .await?
        .ok_or_else(|| AppError::NotFound("No license policy configured".into()))?;

    let result = service.check_license_compliance(&policy, &body.licenses);
    Ok(Json(result))
}

// === Helpers ===

/// Upper bound on rows surfaced into one SBOM document. Realistic
/// monorepos (Ubuntu 22.04 base + Java + Node) can exceed 5k packages
/// once `--list-all-pkgs` enumerates every apt package, JAR, and
/// node_module. The cap exists to keep one runaway scan from
/// generating an unbounded response; the alphabetical ordering on
/// `name` previously meant an attacker could position malicious
/// packages late in the alphabet to evade attestation. The new
/// ceiling is well above any realistic dep tree, and a truncated
/// response would log a warning so operators see it.
const SBOM_INVENTORY_ROW_CAP: i64 = 50_000;

/// Build a [`DependencyInfo`] from raw row fields, dropping rows whose
/// `name` is empty (data-quality filter shared by both read paths).
fn build_dep(
    name: String,
    version: Option<String>,
    purl: Option<String>,
    license: Option<String>,
) -> Option<DependencyInfo> {
    if name.is_empty() {
        None
    } else {
        Some(DependencyInfo {
            name,
            version,
            purl,
            license,
            sha256: None,
        })
    }
}

/// Extract dependencies for SBOM generation.
///
/// Read-path order (#903):
///
/// 1. **`scan_packages`** restricted to each scan_type's latest completed
///    scan per artifact. This mirrors the #1126 / #1136 DISTINCT-ON CTE
///    used for `scan_findings` aggregation; without it, a rescan that
///    removed a dep would still surface the removed dep forever because
///    the old scan's row lingers.
/// 2. **`scan_findings`** legacy fallback for artifacts scanned before
///    the inventory table existed, or by scanners that do not enumerate
///    packages (Grype, OpenSCAP, custom WASM plugins). Returns only
///    CVE-bearing components — exactly the bug #903 fixes for new scans,
///    but the best we can do for legacy data.
///
/// Soft-deleted artifacts (`artifacts.is_deleted = true`) are excluded
/// from both paths so consumers cannot rehydrate dep trees for content
/// the operator has deliberately retired.
async fn extract_dependencies_for_artifact(
    db: &sqlx::PgPool,
    artifact_id: Uuid,
) -> Result<Vec<DependencyInfo>> {
    // Primary path: the inventory table, windowed to each scan_type's
    // latest completed scan. The DISTINCT ON inside `latest_scans`
    // picks the most recent scan per (artifact, scan_type); the outer
    // DISTINCT collapses cross-scan-type packages with identical
    // (name, version, purl, license) tuples (e.g. Trivy fs + Grype
    // both reporting the same lockfile dep).
    //
    // Row tuple: (name, version, purl, license). Tuple is local to this
    // read path — the SBOM endpoint is the only consumer, so a derived
    // FromRow type would pay no dividend.
    let packages_sql = format!(
        "{}
        SELECT DISTINCT sp.name, sp.version, sp.purl, sp.license
        FROM scan_packages sp
        WHERE sp.scan_result_id IN (SELECT id FROM latest_scans)
        ORDER BY sp.name
        LIMIT $2",
        crate::services::scanner_service::LATEST_SCANS_FOR_ARTIFACT_CTE,
    );
    #[allow(clippy::type_complexity)]
    let packages: Vec<(String, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as(&packages_sql)
            .bind(artifact_id)
            .bind(SBOM_INVENTORY_ROW_CAP)
            .fetch_all(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    if !packages.is_empty() {
        if packages.len() as i64 >= SBOM_INVENTORY_ROW_CAP {
            tracing::warn!(
                "SBOM read for artifact {} hit the {} row cap; output may \
                 be truncated. Investigate scanner output sizes.",
                artifact_id,
                SBOM_INVENTORY_ROW_CAP
            );
        }
        return Ok(packages
            .into_iter()
            .filter_map(|(name, version, purl, license)| build_dep(name, version, purl, license))
            .collect());
    }

    // Legacy fallback: derive a component list from scan_findings, also
    // windowed to the latest scan per scan_type for consistency with
    // the primary path. This is the pre-#903 vulnerability-only shape;
    // preferable to returning empty for artifacts scanned before the
    // inventory table existed.
    let findings_sql = format!(
        "{}
        SELECT DISTINCT
            COALESCE(sf.affected_component, sf.title) AS name,
            sf.affected_version AS version
        FROM scan_findings sf
        WHERE sf.scan_result_id IN (SELECT id FROM latest_scans)
        ORDER BY name
        LIMIT 1000",
        crate::services::scanner_service::LATEST_SCANS_FOR_ARTIFACT_CTE,
    );
    let findings: Vec<(String, Option<String>)> = sqlx::query_as(&findings_sql)
        .bind(artifact_id)
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(findings
        .into_iter()
        .filter_map(|(name, version)| build_dep(name, version, None, None))
        .collect())
}

/// Decide whether a caller can access a repo-scoped resource, returning
/// Err(NotFound, missing_msg) for both "resource does not exist" and
/// "exists but caller lacks access". 404-not-403 is deliberate: a 403
/// leaks existence of the resource id, which can be sensitive (private
/// package names enumerated by UUID guessing). Same pattern as format-
/// handler routes. (#903 F6.)
///
/// Extracted from `ensure_*_access` so the decision logic is unit-
/// testable without a DB; the helpers below are thin DB-lookup wrappers.
fn require_repo_access(
    auth: &AuthExtension,
    repo_id: Option<Uuid>,
    missing_msg: &'static str,
) -> Result<()> {
    let repo_id = repo_id.ok_or_else(|| AppError::NotFound(missing_msg.into()))?;
    if !auth.can_access_repo(repo_id) {
        return Err(AppError::NotFound(missing_msg.into()));
    }
    Ok(())
}

/// Resolve `artifact_id → repository_id` and apply [`require_repo_access`].
async fn ensure_artifact_repo_access(
    db: &sqlx::PgPool,
    auth: &AuthExtension,
    artifact_id: Uuid,
) -> Result<()> {
    let repo_id: Option<Uuid> =
        sqlx::query_scalar("SELECT repository_id FROM artifacts WHERE id = $1 AND NOT is_deleted")
            .bind(artifact_id)
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    require_repo_access(auth, repo_id, "Artifact not found")
}

/// Like [`ensure_artifact_repo_access`] but resolves through `sbom_documents`
/// when the caller has only the SBOM id.
async fn ensure_sbom_repo_access(
    db: &sqlx::PgPool,
    auth: &AuthExtension,
    sbom_id: Uuid,
) -> Result<()> {
    let repo_id: Option<Uuid> =
        sqlx::query_scalar("SELECT repository_id FROM sbom_documents WHERE id = $1")
            .bind(sbom_id)
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    require_repo_access(auth, repo_id, "SBOM not found")
}

#[derive(OpenApi)]
#[openapi(
    paths(
        generate_sbom,
        list_sboms,
        get_sbom,
        get_sbom_by_artifact,
        delete_sbom,
        get_sbom_components,
        convert_sbom,
        get_cve_history,
        get_cve_history_by_artifact,
        get_cve_history_by_cve,
        update_cve_status,
        get_cve_trends,
        list_license_policies,
        get_license_policy,
        upsert_license_policy,
        delete_license_policy,
        check_license_compliance,
    ),
    components(schemas(
        GenerateSbomRequest,
        ListSbomsQuery,
        ConvertSbomRequest,
        UpdateCveStatusRequest,
        GetCveTrendsQuery,
        CheckLicenseComplianceRequest,
        SbomResponse,
        SbomContentResponse,
        ComponentResponse,
        LicensePolicyResponse,
        UpsertLicensePolicyRequest,
    ))
)]
pub struct SbomApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // -----------------------------------------------------------------------
    // Default functions
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_format() {
        assert_eq!(default_format(), "cyclonedx");
    }

    #[test]
    fn test_default_true() {
        assert!(default_true());
    }

    #[test]
    fn test_default_action() {
        assert_eq!(default_action(), "warn");
    }

    // -----------------------------------------------------------------------
    // SbomResponse From<SbomDocument>
    // -----------------------------------------------------------------------

    fn make_sbom_doc() -> SbomDocument {
        let now = Utc::now();
        SbomDocument {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            format: "cyclonedx".to_string(),
            format_version: "1.5".to_string(),
            spec_version: Some("1.5".to_string()),
            content: serde_json::json!({"components": []}),
            component_count: 10,
            dependency_count: 5,
            license_count: 3,
            licenses: vec![
                "MIT".to_string(),
                "Apache-2.0".to_string(),
                "BSD-3-Clause".to_string(),
            ],
            content_hash: "sha256:abc123".to_string(),
            generator: Some("syft".to_string()),
            generator_version: Some("0.90.0".to_string()),
            generated_at: now,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_sbom_response_from_document() {
        let doc = make_sbom_doc();
        let doc_id = doc.id;
        let doc_artifact = doc.artifact_id;
        let doc_repo = doc.repository_id;
        let resp = SbomResponse::from(doc);
        assert_eq!(resp.id, doc_id);
        assert_eq!(resp.artifact_id, doc_artifact);
        assert_eq!(resp.repository_id, doc_repo);
        assert_eq!(resp.format, "cyclonedx");
        assert_eq!(resp.format_version, "1.5");
        assert_eq!(resp.spec_version, Some("1.5".to_string()));
        assert_eq!(resp.component_count, 10);
        assert_eq!(resp.dependency_count, 5);
        assert_eq!(resp.license_count, 3);
        assert_eq!(resp.licenses.len(), 3);
        assert_eq!(resp.content_hash, "sha256:abc123");
        assert_eq!(resp.generator, Some("syft".to_string()));
        assert_eq!(resp.generator_version, Some("0.90.0".to_string()));
    }

    #[test]
    fn test_sbom_response_from_document_no_optionals() {
        let now = Utc::now();
        let doc = SbomDocument {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            format: "spdx".to_string(),
            format_version: "2.3".to_string(),
            spec_version: None,
            content: serde_json::json!({}),
            component_count: 0,
            dependency_count: 0,
            license_count: 0,
            licenses: vec![],
            content_hash: "sha256:empty".to_string(),
            generator: None,
            generator_version: None,
            generated_at: now,
            created_at: now,
            updated_at: now,
        };
        let resp = SbomResponse::from(doc);
        assert_eq!(resp.format, "spdx");
        assert!(resp.spec_version.is_none());
        assert!(resp.generator.is_none());
        assert!(resp.generator_version.is_none());
        assert!(resp.licenses.is_empty());
    }

    #[test]
    fn test_sbom_response_serialize() {
        let doc = make_sbom_doc();
        let resp = SbomResponse::from(doc);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["format"], "cyclonedx");
        assert_eq!(json["component_count"], 10);
        assert!(json["licenses"].is_array());
    }

    // -----------------------------------------------------------------------
    // SbomContentResponse From<SbomDocument>
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbom_content_response_from_document() {
        let doc = make_sbom_doc();
        let resp = SbomContentResponse::from(doc);
        assert_eq!(resp.metadata.format, "cyclonedx");
        assert!(resp.content.is_object());
    }

    #[test]
    fn test_sbom_content_response_preserves_content() {
        let now = Utc::now();
        let content = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"name": "serde", "version": "1.0"}]
        });
        let doc = SbomDocument {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            format: "cyclonedx".to_string(),
            format_version: "1.5".to_string(),
            spec_version: Some("1.5".to_string()),
            content: content.clone(),
            component_count: 1,
            dependency_count: 0,
            license_count: 0,
            licenses: vec![],
            content_hash: "hash".to_string(),
            generator: None,
            generator_version: None,
            generated_at: now,
            created_at: now,
            updated_at: now,
        };
        let resp = SbomContentResponse::from(doc);
        assert_eq!(resp.content, content);
        assert_eq!(resp.content["components"][0]["name"], "serde");
    }

    // -----------------------------------------------------------------------
    // ComponentResponse From<SbomComponent>
    // -----------------------------------------------------------------------

    #[test]
    fn test_component_response_from_sbom_component() {
        let now = Utc::now();
        let component = SbomComponent {
            id: Uuid::new_v4(),
            sbom_id: Uuid::new_v4(),
            name: "serde".to_string(),
            version: Some("1.0.195".to_string()),
            purl: Some("pkg:cargo/serde@1.0.195".to_string()),
            cpe: Some("cpe:2.3:a:serde:serde:1.0.195".to_string()),
            component_type: Some("library".to_string()),
            licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            sha256: Some("abc123".to_string()),
            sha1: Some("def456".to_string()),
            md5: Some("ghi789".to_string()),
            supplier: Some("serde-rs".to_string()),
            author: Some("David Tolnay".to_string()),
            external_refs: serde_json::json!([]),
            created_at: now,
        };
        let cid = component.id;
        let sbom_id = component.sbom_id;
        let resp = ComponentResponse::from(component);
        assert_eq!(resp.id, cid);
        assert_eq!(resp.sbom_id, sbom_id);
        assert_eq!(resp.name, "serde");
        assert_eq!(resp.version, Some("1.0.195".to_string()));
        assert_eq!(resp.purl, Some("pkg:cargo/serde@1.0.195".to_string()));
        assert_eq!(resp.cpe, Some("cpe:2.3:a:serde:serde:1.0.195".to_string()));
        assert_eq!(resp.component_type, Some("library".to_string()));
        assert_eq!(resp.licenses.len(), 2);
        assert_eq!(resp.sha256, Some("abc123".to_string()));
        assert_eq!(resp.sha1, Some("def456".to_string()));
        assert_eq!(resp.md5, Some("ghi789".to_string()));
        assert_eq!(resp.supplier, Some("serde-rs".to_string()));
        assert_eq!(resp.author, Some("David Tolnay".to_string()));
    }

    #[test]
    fn test_component_response_from_minimal_component() {
        let now = Utc::now();
        let component = SbomComponent {
            id: Uuid::new_v4(),
            sbom_id: Uuid::new_v4(),
            name: "unknown-lib".to_string(),
            version: None,
            purl: None,
            cpe: None,
            component_type: None,
            licenses: vec![],
            sha256: None,
            sha1: None,
            md5: None,
            supplier: None,
            author: None,
            external_refs: serde_json::json!(null),
            created_at: now,
        };
        let resp = ComponentResponse::from(component);
        assert_eq!(resp.name, "unknown-lib");
        assert!(resp.version.is_none());
        assert!(resp.purl.is_none());
        assert!(resp.licenses.is_empty());
    }

    #[test]
    fn test_component_response_serialize() {
        let now = Utc::now();
        let component = SbomComponent {
            id: Uuid::nil(),
            sbom_id: Uuid::nil(),
            name: "tokio".to_string(),
            version: Some("1.35.0".to_string()),
            purl: None,
            cpe: None,
            component_type: Some("library".to_string()),
            licenses: vec!["MIT".to_string()],
            sha256: None,
            sha1: None,
            md5: None,
            supplier: None,
            author: None,
            external_refs: serde_json::json!([]),
            created_at: now,
        };
        let resp = ComponentResponse::from(component);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "tokio");
        assert_eq!(json["version"], "1.35.0");
        assert!(json["purl"].is_null());
    }

    // -----------------------------------------------------------------------
    // LicensePolicyResponse From<LicensePolicy>
    // -----------------------------------------------------------------------

    #[test]
    fn test_license_policy_response_from_policy() {
        let now = Utc::now();
        let repo_id = Uuid::new_v4();
        let policy = LicensePolicy {
            id: Uuid::new_v4(),
            repository_id: Some(repo_id),
            name: "strict-policy".to_string(),
            description: Some("Block GPL licenses".to_string()),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
            is_enabled: true,
            created_at: now,
            updated_at: Some(now),
        };
        let pid = policy.id;
        let resp = LicensePolicyResponse::from(policy);
        assert_eq!(resp.id, pid);
        assert_eq!(resp.repository_id, Some(repo_id));
        assert_eq!(resp.name, "strict-policy");
        assert_eq!(resp.description, Some("Block GPL licenses".to_string()));
        assert_eq!(resp.allowed_licenses, vec!["MIT", "Apache-2.0"]);
        assert_eq!(resp.denied_licenses, vec!["GPL-3.0"]);
        assert!(!resp.allow_unknown);
        assert_eq!(resp.action, "block");
        assert!(resp.is_enabled);
        assert!(resp.updated_at.is_some());
    }

    #[test]
    fn test_license_policy_response_global_policy() {
        let now = Utc::now();
        let policy = LicensePolicy {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "global-warn".to_string(),
            description: None,
            allowed_licenses: vec![],
            denied_licenses: vec![],
            allow_unknown: true,
            action: PolicyAction::Warn,
            is_enabled: true,
            created_at: now,
            updated_at: None,
        };
        let resp = LicensePolicyResponse::from(policy);
        assert!(resp.repository_id.is_none());
        assert_eq!(resp.action, "warn");
        assert!(resp.allow_unknown);
        assert!(resp.updated_at.is_none());
    }

    #[test]
    fn test_license_policy_response_allow_action() {
        let now = Utc::now();
        let policy = LicensePolicy {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "permissive".to_string(),
            description: None,
            allowed_licenses: vec![],
            denied_licenses: vec![],
            allow_unknown: true,
            action: PolicyAction::Allow,
            is_enabled: false,
            created_at: now,
            updated_at: None,
        };
        let resp = LicensePolicyResponse::from(policy);
        assert_eq!(resp.action, "allow");
        assert!(!resp.is_enabled);
    }

    #[test]
    fn test_license_policy_response_serialize() {
        let now = Utc::now();
        let policy = LicensePolicy {
            id: Uuid::nil(),
            repository_id: None,
            name: "test".to_string(),
            description: None,
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec![],
            allow_unknown: true,
            action: PolicyAction::Warn,
            is_enabled: true,
            created_at: now,
            updated_at: None,
        };
        let resp = LicensePolicyResponse::from(policy);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["action"], "warn");
        assert_eq!(json["allow_unknown"], true);
    }

    // -----------------------------------------------------------------------
    // Request deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_sbom_request_deserialize_full() {
        let uid = Uuid::new_v4();
        let json = format!(
            r#"{{"artifact_id":"{}","format":"spdx","force_regenerate":true}}"#,
            uid
        );
        let req: GenerateSbomRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.artifact_id, uid);
        assert_eq!(req.format, "spdx");
        assert!(req.force_regenerate);
    }

    #[test]
    fn test_generate_sbom_request_defaults() {
        let uid = Uuid::new_v4();
        let json = format!(r#"{{"artifact_id":"{}"}}"#, uid);
        let req: GenerateSbomRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.format, "cyclonedx");
        assert!(!req.force_regenerate);
    }

    #[test]
    fn test_convert_sbom_request_deserialize() {
        let json = r#"{"target_format":"spdx"}"#;
        let req: ConvertSbomRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.target_format, "spdx");
    }

    #[test]
    fn test_update_cve_status_request_deserialize() {
        let json = r#"{"status":"acknowledged","reason":"Won't fix - not exploitable"}"#;
        let req: UpdateCveStatusRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.status, "acknowledged");
        assert_eq!(req.reason, Some("Won't fix - not exploitable".to_string()));
    }

    #[test]
    fn test_update_cve_status_request_no_reason() {
        let json = r#"{"status":"fixed"}"#;
        let req: UpdateCveStatusRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.status, "fixed");
        assert!(req.reason.is_none());
    }

    #[test]
    fn test_check_license_compliance_request_deserialize() {
        let json = r#"{"licenses":["MIT","GPL-3.0"]}"#;
        let req: CheckLicenseComplianceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.licenses, vec!["MIT", "GPL-3.0"]);
        assert!(req.repository_id.is_none());
    }

    #[test]
    fn test_check_license_compliance_request_with_repo() {
        let rid = Uuid::new_v4();
        let json = format!(r#"{{"licenses":["Apache-2.0"],"repository_id":"{}"}}"#, rid);
        let req: CheckLicenseComplianceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.repository_id, Some(rid));
    }

    #[test]
    fn test_upsert_license_policy_request_deserialize_full() {
        let rid = Uuid::new_v4();
        let json = format!(
            r#"{{
                "repository_id": "{}",
                "name": "strict",
                "description": "Strict policy",
                "allowed_licenses": ["MIT"],
                "denied_licenses": ["GPL-3.0"],
                "allow_unknown": false,
                "action": "block",
                "is_enabled": true
            }}"#,
            rid
        );
        let req: UpsertLicensePolicyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.repository_id, Some(rid));
        assert_eq!(req.name, "strict");
        assert!(!req.allow_unknown);
        assert_eq!(req.action, "block");
        assert!(req.is_enabled);
    }

    #[test]
    fn test_upsert_license_policy_request_defaults() {
        let json = r#"{"name":"default","allowed_licenses":[],"denied_licenses":[]}"#;
        let req: UpsertLicensePolicyRequest = serde_json::from_str(json).unwrap();
        assert!(req.repository_id.is_none());
        assert!(req.description.is_none());
        assert!(req.allow_unknown); // default_true
        assert_eq!(req.action, "warn"); // default_action
        assert!(req.is_enabled); // default_true
    }

    #[test]
    fn test_list_sboms_query_deserialize() {
        let json = r#"{"format":"cyclonedx"}"#;
        let q: ListSbomsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.format, Some("cyclonedx".to_string()));
        assert!(q.artifact_id.is_none());
        assert!(q.repository_id.is_none());
    }

    #[test]
    fn test_get_cve_trends_query_deserialize() {
        let json = r#"{"days":30}"#;
        let q: GetCveTrendsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.days, Some(30));
        assert!(q.repository_id.is_none());
    }

    // -----------------------------------------------------------------------
    // build_dep: shared row→DependencyInfo helper used by both SBOM read
    // paths (scan_packages primary, scan_findings legacy fallback). #903.
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_dep_drops_empty_name() {
        assert!(
            build_dep(String::new(), Some("1.0".to_string()), None, None).is_none(),
            "data-quality filter: rows with empty name must not produce \
             a DependencyInfo (would otherwise serialize as a nameless \
             entry in the CycloneDX components array)"
        );
    }

    #[test]
    fn test_build_dep_preserves_all_fields() {
        let dep = build_dep(
            "body-parser".to_string(),
            Some("1.20.1".to_string()),
            Some("pkg:npm/body-parser@1.20.1".to_string()),
            Some("MIT".to_string()),
        )
        .expect("non-empty name must produce a DependencyInfo");
        assert_eq!(dep.name, "body-parser");
        assert_eq!(dep.version.as_deref(), Some("1.20.1"));
        assert_eq!(dep.purl.as_deref(), Some("pkg:npm/body-parser@1.20.1"));
        assert_eq!(dep.license.as_deref(), Some("MIT"));
        assert!(
            dep.sha256.is_none(),
            "sha256 is not yet sourced from scan_packages"
        );
    }

    #[test]
    fn test_build_dep_optional_fields_pass_through_as_none() {
        // Legacy scan_findings fallback supplies only (name, version); purl
        // and license are None. The helper must round-trip those Nones as
        // is — substituting empty strings would pollute CycloneDX output.
        let dep = build_dep("zlib".to_string(), None, None, None).unwrap();
        assert_eq!(dep.name, "zlib");
        assert!(dep.version.is_none());
        assert!(dep.purl.is_none());
        assert!(dep.license.is_none());
    }

    #[test]
    fn test_build_dep_single_char_name_is_allowed() {
        // Defensive: the empty-name check is exact, not length-bounded.
        // A single-char name (rare but valid: e.g. Go's `q`, Crates `c`)
        // must round-trip.
        let dep = build_dep("c".to_string(), None, None, None).unwrap();
        assert_eq!(dep.name, "c");
    }

    // -----------------------------------------------------------------------
    // SBOM_INVENTORY_ROW_CAP: enforce the documented contract that this
    // cap is set well above any realistic monorepo, and is the SAME
    // ceiling for the SBOM read path. Pinning the constant catches
    // accidental down-tunes that would re-introduce the truncation-by-
    // alphabetical-position attestation-evasion finding (security F1).
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // require_repo_access: pure decision used by ensure_*_access helpers.
    // Tests the four-way truth table without touching the DB. (#903 F6.)
    // -----------------------------------------------------------------------

    fn make_auth(allowed: Option<Vec<Uuid>>, is_api_token: bool) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::nil(),
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            is_admin: false,
            is_api_token,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: allowed,
        }
    }

    #[test]
    fn test_require_repo_access_missing_resource_yields_404() {
        // The resource doesn't exist (or is soft-deleted) — the DB
        // lookup returned None. Must return NotFound regardless of
        // the caller's scope.
        let auth = make_auth(None, false);
        let err = require_repo_access(&auth, None, "SBOM not found").unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[test]
    fn test_require_repo_access_unrestricted_jwt_passes() {
        // JWT session (is_api_token = false): allowed_repo_ids is None,
        // can_access_repo always returns true.
        let auth = make_auth(None, false);
        let repo_id = Uuid::new_v4();
        require_repo_access(&auth, Some(repo_id), "SBOM not found")
            .expect("unrestricted auth must access any existing resource");
    }

    #[test]
    fn test_require_repo_access_scoped_token_with_access_passes() {
        // API token scoped to a whitelist that includes the resource's repo.
        let repo_id = Uuid::new_v4();
        let auth = make_auth(Some(vec![repo_id]), true);
        require_repo_access(&auth, Some(repo_id), "Artifact not found")
            .expect("scoped token whose whitelist includes repo must pass");
    }

    #[test]
    fn test_require_repo_access_scoped_token_without_access_yields_404_not_403() {
        // API token scoped to a different repo. Must return 404 (not 403)
        // so the caller cannot enumerate which UUIDs exist by status code.
        let auth = make_auth(Some(vec![Uuid::new_v4()]), true);
        let other_repo = Uuid::new_v4();
        let err = require_repo_access(&auth, Some(other_repo), "Artifact not found").unwrap_err();
        match err {
            AppError::NotFound(msg) => assert_eq!(msg, "Artifact not found"),
            other => panic!(
                "scoped token without access MUST return NotFound (404) \
                 to avoid existence-disclosure; got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_require_repo_access_missing_msg_propagates() {
        // The same helper is used by both ensure_artifact_repo_access and
        // ensure_sbom_repo_access; the per-call missing_msg must round-trip
        // unchanged so the response body matches the endpoint's contract.
        let auth = make_auth(None, false);
        let err = require_repo_access(&auth, None, "SBOM not found").unwrap_err();
        match err {
            AppError::NotFound(msg) => assert_eq!(msg, "SBOM not found"),
            _ => panic!("expected NotFound with the supplied missing_msg"),
        }

        let err = require_repo_access(&auth, None, "Artifact not found").unwrap_err();
        match err {
            AppError::NotFound(msg) => assert_eq!(msg, "Artifact not found"),
            _ => panic!("expected NotFound with the supplied missing_msg"),
        }
    }

    /// The biggest real-world dep tree we've measured is ~12k for a full
    /// Ubuntu 22.04 + Java + Node monorepo. The cap is 50k. Any future PR
    /// that drops this below 30k breaks compilation here, forcing a
    /// re-evaluation of the threat model documented at the const-site
    /// (attestation-evasion-by-truncation, #903 F1).
    const _: () = assert!(
        SBOM_INVENTORY_ROW_CAP >= 30_000,
        "SBOM_INVENTORY_ROW_CAP must remain comfortably above realistic \
         monorepo dep counts; see security review F1"
    );

    // -----------------------------------------------------------------------
    // Audit-log detail payloads (#1156). The handler bodies call into these
    // pure helpers so the audit-trail shape that SOC 2 / EU CRA auditors
    // read is exercised here without a Postgres pool.
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbom_generated_details_contains_all_fields() {
        let sbom_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let v = sbom_generated_details(sbom_id, "cyclonedx", repo_id, true);
        assert_eq!(v["sbom_id"], sbom_id.to_string());
        assert_eq!(v["format"], "cyclonedx");
        assert_eq!(v["repository_id"], repo_id.to_string());
        assert_eq!(v["force_regenerate"], true);
    }

    #[test]
    fn test_sbom_generated_details_force_regenerate_false_is_recorded() {
        // The auditor needs to be able to tell a fresh generation from a
        // deliberate overwrite of an existing SBOM, so the boolean must be
        // present even when false (not just omitted).
        let v = sbom_generated_details(Uuid::new_v4(), "spdx", Uuid::new_v4(), false);
        assert_eq!(v["force_regenerate"], false);
        assert!(v.get("force_regenerate").is_some());
    }

    #[test]
    fn test_sbom_generated_details_preserves_format_string_verbatim() {
        // We pass `&doc.format` from the persisted SbomDocument, not the
        // normalized SbomFormat enum, so unusual stored values round-trip
        // unchanged into the audit details.
        let v = sbom_generated_details(Uuid::new_v4(), "SPDX-JSON-2.3", Uuid::new_v4(), true);
        assert_eq!(v["format"], "SPDX-JSON-2.3");
    }

    #[test]
    fn test_sbom_read_details_by_id_lookup() {
        let sbom_id = Uuid::new_v4();
        let v = sbom_read_details(sbom_id, "cyclonedx", "by_id");
        assert_eq!(v["sbom_id"], sbom_id.to_string());
        assert_eq!(v["format"], "cyclonedx");
        assert_eq!(v["lookup"], "by_id");
    }

    #[test]
    fn test_sbom_read_details_by_artifact_lookup() {
        let sbom_id = Uuid::new_v4();
        let v = sbom_read_details(sbom_id, "spdx", "by_artifact");
        assert_eq!(v["lookup"], "by_artifact");
        assert_eq!(v["format"], "spdx");
    }

    #[test]
    fn test_sbom_read_details_lookup_field_distinguishes_endpoints() {
        // Compliance reviewers correlate SBOM_READ entries with their
        // originating endpoint to spot automated scrapers vs interactive
        // viewers; the two payloads must therefore not be byte-identical.
        let id = Uuid::new_v4();
        let by_id = sbom_read_details(id, "cyclonedx", "by_id");
        let by_artifact = sbom_read_details(id, "cyclonedx", "by_artifact");
        assert_ne!(by_id, by_artifact);
        assert_ne!(by_id["lookup"], by_artifact["lookup"]);
    }

    #[test]
    fn test_sbom_audit_detail_payloads_are_valid_json_objects() {
        // Audit-log persistence stores `details` as JSONB; both helpers must
        // produce JSON *objects* (not arrays / scalars) so the column query
        // contract (`details->>'sbom_id'`) keeps working.
        let g = sbom_generated_details(Uuid::new_v4(), "cyclonedx", Uuid::new_v4(), false);
        let r = sbom_read_details(Uuid::new_v4(), "cyclonedx", "by_id");
        assert!(g.is_object(), "generated payload must be a JSON object");
        assert!(r.is_object(), "read payload must be a JSON object");
    }

    // -----------------------------------------------------------------------
    // is_valid_cve_id: regression coverage for #1375. The bug surfaced as a
    // bare HTTP 400 from `GET /sbom/cve/history/CVE-2019-10744` because the
    // path extractor was typed `Path<Uuid>`. The fix moves the validator into
    // application code so these cases are exercised in unit tests rather
    // than only at the route boundary.
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_valid_cve_id_release_gate_fixture() {
        // CVE-2019-10744 is the lodash 4.17.4 prototype-pollution fixture
        // pinned by the release-gate scan-completion tests. The 400 bug
        // (#1375) reproduced specifically on this id.
        assert!(is_valid_cve_id("CVE-2019-10744"));
    }

    #[test]
    fn test_is_valid_cve_id_five_digit_suffix() {
        assert!(is_valid_cve_id("CVE-2024-12345"));
    }

    #[test]
    fn test_is_valid_cve_id_six_digit_suffix() {
        // Modern CVE numbering exceeds 5 digits in high-volume years; the
        // validator must accept arbitrary digit counts >= 4 to keep working
        // as the catalogue grows.
        assert!(is_valid_cve_id("CVE-2024-123456"));
    }

    #[test]
    fn test_is_valid_cve_id_four_digit_suffix() {
        // CVE-1999-0001 is the canonical oldest valid id; 4 digits is the
        // documented minimum.
        assert!(is_valid_cve_id("CVE-1999-0001"));
    }

    #[test]
    fn test_is_valid_cve_id_lowercase_accepted() {
        // Callers sometimes lowercase the prefix; the response shape is
        // identical to upper-case so we accept it rather than 400ing.
        assert!(is_valid_cve_id("cve-2019-10744"));
    }

    #[test]
    fn test_is_valid_cve_id_rejects_short_suffix() {
        // < 4 digit suffix is malformed under NVD numbering.
        assert!(!is_valid_cve_id("CVE-2019-1"));
        assert!(!is_valid_cve_id("CVE-2019-12"));
        assert!(!is_valid_cve_id("CVE-2019-123"));
    }

    #[test]
    fn test_is_valid_cve_id_rejects_non_cve_string() {
        assert!(!is_valid_cve_id("not-a-cve"));
        assert!(!is_valid_cve_id(""));
        assert!(!is_valid_cve_id("uuid-style-string"));
    }

    #[test]
    fn test_is_valid_cve_id_rejects_wrong_year_shape() {
        // The year segment is exactly four ASCII digits.
        assert!(!is_valid_cve_id("CVE-19-10744"));
        assert!(!is_valid_cve_id("CVE-20191-10744"));
        assert!(!is_valid_cve_id("CVE-YYYY-10744"));
    }

    #[test]
    fn test_is_valid_cve_id_rejects_trailing_garbage() {
        // The canonical form is exactly two dashes; a stray suffix must not
        // pass.
        assert!(!is_valid_cve_id("CVE-2019-10744-extra"));
        // Trailing non-digit, non-whitespace bytes are not stripped.
        assert!(!is_valid_cve_id("CVE-2019-10744x"));
        assert!(!is_valid_cve_id("CVE-2019-1074a"));
    }

    #[test]
    fn test_is_valid_cve_id_strips_outer_whitespace() {
        // `trim` only — interior whitespace still invalidates.
        assert!(is_valid_cve_id("  CVE-2019-10744  "));
        assert!(!is_valid_cve_id("CVE -2019-10744"));
    }

    #[test]
    fn test_is_valid_cve_id_path_dispatch_distinguishes_uuid_vs_cve() {
        // The handler's dispatch decides UUID-first, CVE-id-second, else
        // 400. Make sure a UUID parses as a UUID (so artifact lookup wins)
        // and a CVE id parses as a CVE id (so cross-artifact lookup wins).
        let uuid = Uuid::new_v4();
        assert!(Uuid::parse_str(&uuid.to_string()).is_ok());
        assert!(!is_valid_cve_id(&uuid.to_string()));
        assert!(Uuid::parse_str("CVE-2019-10744").is_err());
        assert!(is_valid_cve_id("CVE-2019-10744"));
    }

    // -----------------------------------------------------------------------
    // classify_cve_history_path: pure dispatch over the overloaded path
    // parameter. Pulled out of the async handler so the routing decision
    // (UUID first, CVE second, else 400) is unit-testable. (#1375)
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_cve_history_path_uuid_wins() {
        let uuid = Uuid::new_v4();
        let result = classify_cve_history_path(&uuid.to_string());
        assert_eq!(result, CveHistoryPath::Artifact(uuid));
    }

    #[test]
    fn test_classify_cve_history_path_cve_id_release_gate_fixture() {
        // CVE-2019-10744 is the release-gate fixture; the pre-fix
        // Path<Uuid> extractor 400'd it. Now it must route to the CVE
        // branch.
        let result = classify_cve_history_path("CVE-2019-10744");
        assert_eq!(result, CveHistoryPath::Cve("CVE-2019-10744".to_string()));
    }

    #[test]
    fn test_classify_cve_history_path_cve_id_normalizes_to_upper() {
        // Lower-case input must normalize to canonical upper-case before
        // hitting the lookup, so the case-insensitive DB compare lives
        // in one place.
        let result = classify_cve_history_path("cve-2024-12345");
        assert_eq!(result, CveHistoryPath::Cve("CVE-2024-12345".to_string()));
    }

    #[test]
    fn test_classify_cve_history_path_cve_id_trims_whitespace() {
        // Reverse-proxy / curl quirks sometimes leave leading whitespace;
        // the classify step must strip it before forwarding.
        let result = classify_cve_history_path("  CVE-2024-1234  ");
        assert_eq!(result, CveHistoryPath::Cve("CVE-2024-1234".to_string()));
    }

    #[test]
    fn test_classify_cve_history_path_invalid_returns_invalid() {
        assert_eq!(
            classify_cve_history_path("not-a-uuid"),
            CveHistoryPath::Invalid
        );
        assert_eq!(classify_cve_history_path(""), CveHistoryPath::Invalid);
        // 7-byte malformed UUID-ish string.
        assert_eq!(
            classify_cve_history_path("abcdefg"),
            CveHistoryPath::Invalid
        );
        // CVE-shape but invalid (suffix too short).
        assert_eq!(
            classify_cve_history_path("CVE-2024-1"),
            CveHistoryPath::Invalid
        );
    }

    #[test]
    fn test_classify_cve_history_path_uuid_preferred_over_cve_id() {
        // A canonical UUID never matches the CVE shape (no leading
        // "CVE-"), so this is mostly a smoke check that the UUID branch
        // runs first. If someone ever changed `is_valid_cve_id` to match
        // arbitrary strings, this test would catch the routing flip.
        let uuid_str = "12345678-1234-1234-1234-123456789abc";
        match classify_cve_history_path(uuid_str) {
            CveHistoryPath::Artifact(_) => (),
            other => panic!("expected Artifact, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // 400 error wording: pin the strings so a refactor that renames them
    // does not silently break clients that grep the body for keywords.
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalid_cve_history_path_message_includes_offending_id() {
        let msg = invalid_cve_history_path_message("zzz");
        assert!(msg.contains("zzz"));
        assert!(msg.contains("UUID"));
        assert!(msg.contains("CVE-YYYY-N"));
    }

    #[test]
    fn test_invalid_cve_id_route_message_includes_offending_id() {
        let msg = invalid_cve_id_route_message("CVE-bad");
        assert!(msg.contains("CVE-bad"));
        assert!(msg.contains("CVE-YYYY-N"));
        // The typed-route message must NOT mention "UUID" since the route
        // does not accept UUIDs.
        assert!(!msg.contains("UUID"));
    }

    #[test]
    fn test_invalid_cve_history_path_message_distinct_from_typed_route_message() {
        // The overloaded route and the typed CVE route emit different
        // messages because they accept different shapes; pin that they
        // do not collapse.
        let overload = invalid_cve_history_path_message("xxx");
        let typed = invalid_cve_id_route_message("xxx");
        assert_ne!(overload, typed);
    }

    // -----------------------------------------------------------------------
    // #1438 (1c): POST /sbom/cve/status/{uuid} for a missing id used to
    // surface `sqlx::Error::RowNotFound` as 500 DATABASE_ERROR. The handler
    // now maps that one variant to NotFound (404) explicitly. The mapping
    // is a small inline closure inside `update_cve_status`; we replicate
    // the exact match arm here so the contract is pinned without spinning
    // up Postgres.
    // -----------------------------------------------------------------------

    fn map_update_cve_status_err(id: Uuid, e: AppError) -> AppError {
        match e {
            AppError::Sqlx(sqlx::Error::RowNotFound) => {
                AppError::NotFound(format!("CVE history entry {} not found", id))
            }
            other => other,
        }
    }

    #[test]
    fn test_update_cve_status_maps_row_not_found_to_404() {
        let id = Uuid::new_v4();
        let err = AppError::Sqlx(sqlx::Error::RowNotFound);
        match map_update_cve_status_err(id, err) {
            AppError::NotFound(msg) => {
                assert!(msg.contains(&id.to_string()));
                assert!(msg.contains("CVE history entry"));
            }
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_update_cve_status_passes_through_other_db_errors() {
        // A non-RowNotFound sqlx error must keep flowing as a DB error so
        // operators still see 500s for genuine database failures.
        let id = Uuid::new_v4();
        let err = AppError::Sqlx(sqlx::Error::PoolTimedOut);
        match map_update_cve_status_err(id, err) {
            AppError::Sqlx(sqlx::Error::PoolTimedOut) => {}
            other => panic!(
                "expected Sqlx(PoolTimedOut) to pass through, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_update_cve_status_passes_through_validation_errors() {
        // Validation errors (e.g. unknown status string) reach the mapper
        // unchanged so the client sees the original 400 message.
        let id = Uuid::new_v4();
        let err = AppError::Validation("Unknown status: maybe".to_string());
        match map_update_cve_status_err(id, err) {
            AppError::Validation(msg) => assert_eq!(msg, "Unknown status: maybe"),
            other => panic!("expected Validation to pass through, got {:?}", other),
        }
    }
}
