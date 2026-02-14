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
use crate::services::sbom_service::{DependencyInfo, LicenseCheckResult, SbomService};

/// Create SBOM routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        // SBOM operations
        .route("/", get(list_sboms).post(generate_sbom))
        .route("/:id", get(get_sbom).delete(delete_sbom))
        .route("/:id/components", get(get_sbom_components))
        .route("/:id/convert", post(convert_sbom))
        .route("/by-artifact/:artifact_id", get(get_sbom_by_artifact))
        // CVE history
        .route("/cve/history/:artifact_id", get(get_cve_history))
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
    Extension(_auth): Extension<AuthExtension>,
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
    Extension(_auth): Extension<AuthExtension>,
    Query(query): Query<ListSbomsQuery>,
) -> Result<Json<Vec<SbomResponse>>> {
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
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<SbomContentResponse>> {
    let service = SbomService::new(state.db.clone());
    let doc = service
        .get_sbom(id)
        .await?
        .ok_or_else(|| AppError::NotFound("SBOM not found".into()))?;

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
    Extension(_auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<ListSbomsQuery>,
) -> Result<Json<SbomContentResponse>> {
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
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
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
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ComponentResponse>>> {
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

/// Get CVE history for an artifact
#[utoipa::path(
    get,
    path = "/cve/history/{artifact_id}",
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "CVE history entries", body = Vec<crate::models::sbom::CveHistoryEntry>),
    ),
    security(("bearer_auth" = []))
)]
async fn get_cve_history(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Json<Vec<crate::models::sbom::CveHistoryEntry>>> {
    let service = SbomService::new(state.db.clone());
    let entries = service.get_cve_history(artifact_id).await?;
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

    let entry = service
        .update_cve_status(id, status, Some(auth.user_id), body.reason.as_deref())
        .await?;

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

/// Extract dependencies from scan results to populate SBOM.
async fn extract_dependencies_for_artifact(
    db: &sqlx::PgPool,
    artifact_id: Uuid,
) -> Result<Vec<DependencyInfo>> {
    // Try to get findings from the latest scan
    let findings: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT DISTINCT
            COALESCE(affected_component, title) as name,
            affected_version as version,
            NULL::text as purl
        FROM scan_findings sf
        JOIN scan_results sr ON sf.scan_result_id = sr.id
        WHERE sr.artifact_id = $1
        ORDER BY name
        LIMIT 1000
        "#,
    )
    .bind(artifact_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let deps: Vec<DependencyInfo> = findings
        .into_iter()
        .filter_map(|(name, version, purl)| {
            if name.is_empty() {
                None
            } else {
                Some(DependencyInfo {
                    name,
                    version,
                    purl,
                    license: None,
                    sha256: None,
                })
            }
        })
        .collect();

    Ok(deps)
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
}
