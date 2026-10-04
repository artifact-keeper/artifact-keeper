//! Bundle export/import API (#2464, Export/Import P1).
//!
//! Admin-only (the nest is wrapped in `admin_middleware` in `routes.rs`): an
//! export reads whole repositories and an import provisions content into
//! them, the same tier as `/migrations`.
//!
//! This is the PR1 skeleton. Every route is registered and documented so the
//! API shape is fixed, but only the metadata endpoints do work today:
//!
//! * `GET  /format`             format version, layout and media profiles
//! * `POST /manifest/validate`  decode + validate a `manifest.json`
//! * `GET  /jobs`, `/jobs/{id}`, `/jobs/{id}/items`   job bookkeeping
//! * `POST /exports`            validates the request, then 501 (PR2)
//! * `POST /imports`            501 (PR3)

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::bundle::layout::{is_valid_repo_key, MANIFEST_PATH};
use crate::services::bundle::manifest::{
    decode_manifest, sha256_hex, unsupported_features, validate_manifest, BundleKind,
    BundleManifest, MediaProfile, BUNDLE_FORMAT, MANIFEST_SCHEMA_VERSION, MIN_SCHEMA_VERSION,
};
use crate::services::bundle::BundleLimits;

/// Issue tracking the unimplemented parts of this API.
const TRACKING_ISSUE: &str = "#2464";
/// Most repositories one export request may name.
pub const MAX_EXPORT_REPOSITORIES: usize = 100;
const JOB_DIRECTIONS: &[&str] = &["export", "import"];
const JOB_STATUSES: &[&str] = &[
    "pending",
    "running",
    "verifying",
    "committing",
    "completed",
    "failed",
    "cancelled",
];
const ITEM_STATUSES: &[&str] = &[
    "pending",
    "verified",
    "committed",
    "skipped",
    "conflict",
    "failed",
];

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/format", get(get_bundle_format))
        .route("/manifest/validate", post(validate_bundle_manifest))
        .route("/exports", post(create_bundle_export))
        .route("/imports", post(create_bundle_import))
        .route("/jobs", get(list_bundle_jobs))
        .route("/jobs/:id", get(get_bundle_job))
        .route("/jobs/:id/items", get(list_bundle_job_items))
}

// ============ Types ============

/// One media profile and its nominal capacity.
#[derive(Debug, Serialize, ToSchema)]
pub struct MediaProfileInfo {
    pub profile: MediaProfile,
    /// Nominal bytes per volume; absent for `unbounded`.
    pub capacity_bytes: Option<u64>,
}

/// What this server reads and writes.
#[derive(Debug, Serialize, ToSchema)]
pub struct BundleFormatResponse {
    pub format: String,
    pub schema_version: u32,
    pub min_schema_version: u32,
    /// Container: always an uncompressed `tar`.
    pub container: String,
    pub file_extension: String,
    pub manifest_path: String,
    /// Path templates of every file a bundle may contain.
    pub layout: Vec<String>,
    pub media_profiles: Vec<MediaProfileInfo>,
    /// Whether this build can produce and ingest bundles yet.
    pub export_available: bool,
    pub import_available: bool,
}

/// Result of validating a `manifest.json`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ManifestValidationReport {
    /// Decoded and internally consistent.
    pub valid: bool,
    /// Valid and uses no feature this server cannot import yet.
    pub importable: bool,
    pub schema_version: Option<u32>,
    pub supported_schema_versions: [u32; 2],
    pub bundle_id: Option<Uuid>,
    pub kind: Option<BundleKind>,
    pub repository_count: usize,
    pub item_count: usize,
    pub total_bytes: u64,
    pub scan_evidence_count: usize,
    /// SHA-256 of the submitted manifest bytes.
    pub manifest_sha256: String,
    pub problems: Vec<String>,
    pub unsupported_features: Vec<String>,
}

/// Request to export repositories into a bundle.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateBundleExportRequest {
    pub repository_keys: Vec<String>,
    /// Media the volume set is sized for (default `unbounded`).
    #[serde(default)]
    pub media_profile: Option<MediaProfile>,
    /// Custodian's media control number, recorded in the manifest.
    #[serde(default)]
    pub media_control_number: Option<String>,
}

/// Structured 501 for operations a later PR implements.
#[derive(Debug, Serialize, ToSchema)]
pub struct BundleNotImplementedResponse {
    pub code: String,
    pub message: String,
    pub tracking_issue: String,
}

/// A bundle export or import job.
#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct BundleJob {
    pub id: Uuid,
    pub direction: String,
    pub status: String,
    pub bundle_id: Option<Uuid>,
    pub manifest_schema_version: Option<i32>,
    pub manifest_sha256: Option<String>,
    pub bundle_kind: String,
    pub media_profile: Option<String>,
    pub volume_count: Option<i32>,
    pub repository_keys: Vec<String>,
    pub total_items: i32,
    pub completed_items: i32,
    pub failed_items: i32,
    pub skipped_items: i32,
    pub total_bytes: i64,
    pub transferred_bytes: i64,
    pub error_summary: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One artifact record within a job.
#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct BundleJobItem {
    pub id: Uuid,
    pub job_id: Uuid,
    pub repository_key: String,
    pub logical_path: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub blob_path: String,
    pub status: String,
    pub artifact_id: Option<Uuid>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListBundleJobsQuery {
    /// `export` or `import`.
    pub direction: Option<String>,
    /// Job status filter.
    pub status: Option<String>,
    /// 1-based page (default 1).
    pub page: Option<i64>,
    /// Rows per page (1-200, default 50).
    pub per_page: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListBundleItemsQuery {
    /// Item status filter.
    pub status: Option<String>,
    /// 1-based page (default 1).
    pub page: Option<i64>,
    /// Rows per page (1-200, default 50).
    pub per_page: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BundleJobListResponse {
    pub items: Vec<BundleJob>,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BundleJobItemListResponse {
    pub items: Vec<BundleJobItem>,
    pub page: i64,
    pub per_page: i64,
}

// ============ Pure helpers ============

/// The `/format` description.
pub fn format_description() -> BundleFormatResponse {
    BundleFormatResponse {
        format: BUNDLE_FORMAT.to_string(),
        schema_version: MANIFEST_SCHEMA_VERSION,
        min_schema_version: MIN_SCHEMA_VERSION,
        container: "tar".to_string(),
        file_extension: ".akbundle.tar".to_string(),
        manifest_path: MANIFEST_PATH.to_string(),
        layout: [
            "manifest.json",
            "repos/<repository-key>/repo.json",
            "repos/<repository-key>/artifacts.json",
            "repos/<repository-key>/oci.json",
            "blobs/<sha256[0..2]>/<sha256><.ext>",
            "evidence/<sha256[0..2]>/<sha256>.json",
            "signing/<name>.json",
        ]
        .map(String::from)
        .to_vec(),
        media_profiles: MediaProfile::ALL
            .iter()
            .map(|p| MediaProfileInfo {
                profile: *p,
                capacity_bytes: p.capacity_bytes(),
            })
            .collect(),
        export_available: false,
        import_available: false,
    }
}

/// Decode and validate submitted manifest bytes into a report. Never fails:
/// a manifest this server cannot read is reported, not rejected with an error.
pub fn build_validation_report(bytes: &[u8], limits: &BundleLimits) -> ManifestValidationReport {
    let mut report = ManifestValidationReport {
        valid: false,
        importable: false,
        schema_version: None,
        supported_schema_versions: [MIN_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION],
        bundle_id: None,
        kind: None,
        repository_count: 0,
        item_count: 0,
        total_bytes: 0,
        scan_evidence_count: 0,
        manifest_sha256: sha256_hex(bytes),
        problems: Vec::new(),
        unsupported_features: Vec::new(),
    };
    let manifest: BundleManifest = match decode_manifest(bytes, limits) {
        Ok(m) => m,
        Err(e) => {
            report.problems.push(e.to_string());
            return report;
        }
    };
    report.schema_version = Some(manifest.schema_version);
    report.bundle_id = Some(manifest.bundle_id);
    report.kind = Some(manifest.kind);
    match validate_manifest(&manifest, limits) {
        Ok(summary) => {
            report.valid = true;
            report.repository_count = summary.repository_count;
            report.item_count = summary.item_count;
            report.total_bytes = summary.total_bytes;
            report.scan_evidence_count = summary.scan_evidence_count;
            report.unsupported_features = unsupported_features(&manifest);
            report.importable = report.unsupported_features.is_empty();
        }
        Err(problems) => report.problems = problems,
    }
    report
}

/// Validate an export request's shape (repository existence is checked by the
/// export worker, PR2).
pub fn validate_export_request(req: &CreateBundleExportRequest) -> Result<()> {
    if req.repository_keys.is_empty() {
        return Err(AppError::Validation(
            "repository_keys must name at least one repository".into(),
        ));
    }
    if req.repository_keys.len() > MAX_EXPORT_REPOSITORIES {
        return Err(AppError::Validation(format!(
            "at most {MAX_EXPORT_REPOSITORIES} repositories per export"
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for key in &req.repository_keys {
        if !is_valid_repo_key(key) {
            return Err(AppError::Validation(format!(
                "{key:?} is not a valid repository key"
            )));
        }
        if !seen.insert(key) {
            return Err(AppError::Validation(format!(
                "repository {key:?} is listed twice"
            )));
        }
    }
    if let Some(mcn) = &req.media_control_number {
        if mcn.is_empty() || mcn.len() > 64 || mcn.chars().any(char::is_control) {
            return Err(AppError::Validation(
                "media_control_number must be 1-64 printable characters".into(),
            ));
        }
    }
    Ok(())
}

/// Clamp pagination to `(page, per_page, offset)`.
pub fn page_window(page: Option<i64>, per_page: Option<i64>) -> (i64, i64, i64) {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(50).clamp(1, 200);
    (page, per_page, (page - 1).saturating_mul(per_page))
}

/// Refuse a filter value outside `allowed`, so a typo is a 400 rather than an
/// empty list.
pub fn check_filter(name: &str, value: Option<&str>, allowed: &[&str]) -> Result<()> {
    match value {
        Some(v) if !allowed.contains(&v) => Err(AppError::Validation(format!(
            "{name} must be one of {}",
            allowed.join(", ")
        ))),
        _ => Ok(()),
    }
}

fn not_implemented(what: &str, phase: &str) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(BundleNotImplementedResponse {
            code: "NOT_IMPLEMENTED".into(),
            message: format!("bundle {what} is not implemented in this release ({phase})"),
            tracking_issue: TRACKING_ISSUE.into(),
        }),
    )
        .into_response()
}

// ============ Handlers ============

/// Describe the bundle format this server reads and writes.
#[utoipa::path(
    get,
    path = "/format",
    context_path = "/api/v1/bundles",
    tag = "bundles",
    responses(
        (status = 200, description = "Bundle format description", body = BundleFormatResponse),
        (status = 403, description = "Admin access required")
    ),
    security(("bearer_auth" = []))
)]
async fn get_bundle_format() -> Json<BundleFormatResponse> {
    Json(format_description())
}

/// Validate a bundle `manifest.json` without importing anything.
#[utoipa::path(
    post,
    path = "/manifest/validate",
    context_path = "/api/v1/bundles",
    tag = "bundles",
    request_body(content = BundleManifest, content_type = "application/json"),
    responses(
        (status = 200, description = "Validation report (valid or not)", body = ManifestValidationReport),
        (status = 403, description = "Admin access required")
    ),
    security(("bearer_auth" = []))
)]
async fn validate_bundle_manifest(body: Bytes) -> Json<ManifestValidationReport> {
    Json(build_validation_report(&body, &BundleLimits::from_env()))
}

/// Export repositories into a bundle (not implemented yet: PR2 of #2464).
#[utoipa::path(
    post,
    path = "/exports",
    context_path = "/api/v1/bundles",
    tag = "bundles",
    request_body = CreateBundleExportRequest,
    responses(
        (status = 400, description = "Invalid export request"),
        (status = 403, description = "Admin access required"),
        (status = 501, description = "Export is not implemented yet", body = BundleNotImplementedResponse)
    ),
    security(("bearer_auth" = []))
)]
async fn create_bundle_export(Json(req): Json<CreateBundleExportRequest>) -> Result<Response> {
    validate_export_request(&req)?;
    Ok(not_implemented(
        "export",
        "streaming export lands in a later 1.11.x PR",
    ))
}

/// Import a bundle (not implemented yet: PR3 of #2464).
#[utoipa::path(
    post,
    path = "/imports",
    context_path = "/api/v1/bundles",
    tag = "bundles",
    responses(
        (status = 403, description = "Admin access required"),
        (status = 501, description = "Import is not implemented yet", body = BundleNotImplementedResponse)
    ),
    security(("bearer_auth" = []))
)]
async fn create_bundle_import() -> Response {
    not_implemented(
        "import",
        "verify-before-commit import lands in a later 1.11.x PR",
    )
}

const BUNDLE_JOB_COLUMNS: &str = "id, direction, status, bundle_id, manifest_schema_version, \
     manifest_sha256, bundle_kind, media_profile, volume_count, repository_keys, total_items, \
     completed_items, failed_items, skipped_items, total_bytes, transferred_bytes, \
     error_summary, created_by, created_at, started_at, finished_at";

/// List bundle jobs, newest first.
#[utoipa::path(
    get,
    path = "/jobs",
    context_path = "/api/v1/bundles",
    tag = "bundles",
    params(ListBundleJobsQuery),
    responses(
        (status = 200, description = "Bundle jobs", body = BundleJobListResponse),
        (status = 400, description = "Invalid filter"),
        (status = 403, description = "Admin access required")
    ),
    security(("bearer_auth" = []))
)]
async fn list_bundle_jobs(
    State(state): State<SharedState>,
    Query(q): Query<ListBundleJobsQuery>,
) -> Result<Json<BundleJobListResponse>> {
    check_filter("direction", q.direction.as_deref(), JOB_DIRECTIONS)?;
    check_filter("status", q.status.as_deref(), JOB_STATUSES)?;
    let (page, per_page, offset) = page_window(q.page, q.per_page);
    let items: Vec<BundleJob> = sqlx::query_as(sqlx::AssertSqlSafe(&*format!(
        "SELECT {BUNDLE_JOB_COLUMNS} FROM bundle_jobs \
         WHERE ($1::text IS NULL OR direction = $1) AND ($2::text IS NULL OR status = $2) \
         ORDER BY created_at DESC, id LIMIT $3 OFFSET $4"
    )))
    .bind(q.direction)
    .bind(q.status)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(BundleJobListResponse {
        items,
        page,
        per_page,
    }))
}

async fn fetch_job(state: &SharedState, id: Uuid) -> Result<BundleJob> {
    sqlx::query_as(sqlx::AssertSqlSafe(&*format!(
        "SELECT {BUNDLE_JOB_COLUMNS} FROM bundle_jobs WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Bundle job not found".into()))
}

/// Get one bundle job.
#[utoipa::path(
    get,
    path = "/jobs/{id}",
    context_path = "/api/v1/bundles",
    tag = "bundles",
    params(("id" = Uuid, Path, description = "Bundle job ID")),
    responses(
        (status = 200, description = "Bundle job", body = BundleJob),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Bundle job not found")
    ),
    security(("bearer_auth" = []))
)]
async fn get_bundle_job(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<BundleJob>> {
    Ok(Json(fetch_job(&state, id).await?))
}

/// List the artifact records of a bundle job.
#[utoipa::path(
    get,
    path = "/jobs/{id}/items",
    context_path = "/api/v1/bundles",
    tag = "bundles",
    params(("id" = Uuid, Path, description = "Bundle job ID"), ListBundleItemsQuery),
    responses(
        (status = 200, description = "Bundle job items", body = BundleJobItemListResponse),
        (status = 400, description = "Invalid filter"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Bundle job not found")
    ),
    security(("bearer_auth" = []))
)]
async fn list_bundle_job_items(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<ListBundleItemsQuery>,
) -> Result<Json<BundleJobItemListResponse>> {
    check_filter("status", q.status.as_deref(), ITEM_STATUSES)?;
    fetch_job(&state, id).await?;
    let (page, per_page, offset) = page_window(q.page, q.per_page);
    let items: Vec<BundleJobItem> = sqlx::query_as(
        "SELECT id, job_id, repository_key, logical_path, sha256, size_bytes, blob_path, \
         status, artifact_id, error_message, created_at, updated_at \
         FROM bundle_items WHERE job_id = $1 AND ($2::text IS NULL OR status = $2) \
         ORDER BY repository_key, logical_path LIMIT $3 OFFSET $4",
    )
    .bind(id)
    .bind(q.status)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(BundleJobItemListResponse {
        items,
        page,
        per_page,
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_bundle_format,
        validate_bundle_manifest,
        create_bundle_export,
        create_bundle_import,
        list_bundle_jobs,
        get_bundle_job,
        list_bundle_job_items,
    ),
    components(schemas(
        BundleFormatResponse,
        MediaProfileInfo,
        ManifestValidationReport,
        CreateBundleExportRequest,
        BundleNotImplementedResponse,
        BundleJob,
        BundleJobItem,
        BundleJobListResponse,
        BundleJobItemListResponse,
        BundleManifest,
    ))
)]
pub struct BundlesApiDoc;

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::bundle::manifest::encode_manifest;
    use crate::services::bundle::manifest::tests::sample_manifest;

    fn export_req(keys: &[&str]) -> CreateBundleExportRequest {
        CreateBundleExportRequest {
            repository_keys: keys.iter().map(|k| k.to_string()).collect(),
            media_profile: None,
            media_control_number: None,
        }
    }

    #[test]
    fn format_description_reports_an_uncompressed_tar() {
        let f = format_description();
        assert_eq!(f.container, "tar");
        assert_eq!(f.file_extension, ".akbundle.tar");
        assert_eq!(f.schema_version, MANIFEST_SCHEMA_VERSION);
        assert_eq!(f.media_profiles.len(), MediaProfile::ALL.len());
        assert!(!f.export_available && !f.import_available);
    }

    #[test]
    fn validation_report_for_a_good_manifest() {
        let bytes = encode_manifest(&sample_manifest()).unwrap();
        let r = build_validation_report(&bytes, &BundleLimits::default());
        assert!(r.valid && r.importable, "{:?}", r.problems);
        assert_eq!(r.item_count, 2);
        assert_eq!(r.total_bytes, 30);
        assert_eq!(r.schema_version, Some(1));
        assert_eq!(r.manifest_sha256, sha256_hex(&bytes));
    }

    #[test]
    fn validation_report_for_bad_manifests() {
        let r = build_validation_report(
            br#"{"format":"akbundle","schema_version":99}"#,
            &BundleLimits::default(),
        );
        assert!(!r.valid && !r.importable);
        assert!(
            r.problems[0].contains("schema_version 99"),
            "{:?}",
            r.problems
        );

        let mut m = sample_manifest();
        m.items[0].logical_path = "../../etc/passwd".into();
        let r = build_validation_report(&encode_manifest(&m).unwrap(), &BundleLimits::default());
        assert!(!r.valid);
        assert_eq!(r.schema_version, Some(1));
        assert!(r.problems.iter().any(|p| p.contains("traversal")));

        let mut m = sample_manifest();
        m.volume_set.volume_count = 3;
        let r = build_validation_report(&encode_manifest(&m).unwrap(), &BundleLimits::default());
        assert!(r.valid && !r.importable);
        assert!(r.unsupported_features[0].contains("multi-volume"));
    }

    #[test]
    fn export_request_validation() {
        assert!(validate_export_request(&export_req(&["libs", "npm-local"])).is_ok());
        assert!(validate_export_request(&export_req(&[])).is_err());
        assert!(validate_export_request(&export_req(&["../x"])).is_err());
        assert!(validate_export_request(&export_req(&["a", "a"])).is_err());
        let many: Vec<String> = (0..=MAX_EXPORT_REPOSITORIES)
            .map(|i| format!("r{i}"))
            .collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(validate_export_request(&export_req(&refs)).is_err());
        let mut req = export_req(&["libs"]);
        req.media_control_number = Some("bad\u{7}".into());
        assert!(validate_export_request(&req).is_err());
        req.media_control_number = Some("MCN-42".into());
        assert!(validate_export_request(&req).is_ok());
    }

    #[test]
    fn paging_and_filters() {
        assert_eq!(page_window(None, None), (1, 50, 0));
        assert_eq!(page_window(Some(3), Some(10)), (3, 10, 20));
        assert_eq!(page_window(Some(-4), Some(10_000)), (1, 200, 0));
        assert_eq!(page_window(Some(1), Some(0)), (1, 1, 0));
        assert!(check_filter("status", None, JOB_STATUSES).is_ok());
        assert!(check_filter("status", Some("running"), JOB_STATUSES).is_ok());
        assert!(check_filter("status", Some("bogus"), JOB_STATUSES).is_err());
    }

    mod db {
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;

        async fn seed_job(pool: &sqlx::PgPool, direction: &str) -> Uuid {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO bundle_jobs (direction, repository_keys) \
                 VALUES ($1, ARRAY['libs']) RETURNING id",
            )
            .bind(direction)
            .fetch_one(pool)
            .await
            .expect("seed bundle job");
            sqlx::query(
                "INSERT INTO bundle_items (job_id, repository_key, logical_path, sha256, \
                 size_bytes, blob_path) VALUES ($1, 'libs', 'a/a-1.jar', $2, 3, $3)",
            )
            .bind(id)
            .bind("a".repeat(64))
            .bind(format!("blobs/aa/{}.jar", "a".repeat(64)))
            .execute(pool)
            .await
            .expect("seed bundle item");
            id
        }

        #[tokio::test]
        async fn bundle_endpoints_round_trip() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let job = seed_job(&pool, "import").await;
            let state = tdh::build_state(pool.clone(), "/tmp/ak-bundles-test");
            let app = || {
                tdh::router_with_auth_ext(
                    router(),
                    state.clone(),
                    tdh::admin_auth(Uuid::new_v4(), "bundle-admin"),
                )
            };

            let (status, body) = tdh::send(app(), tdh::get("/format".into())).await;
            assert_eq!(status, StatusCode::OK);
            assert!(String::from_utf8_lossy(&body).contains("akbundle"));

            let (status, body) = tdh::send(
                app(),
                tdh::get("/jobs?direction=import&per_page=200".into()),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(list["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|j| j["id"] == job.to_string()));

            let (status, _) = tdh::send(app(), tdh::get("/jobs?status=nope".into())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            let (status, body) = tdh::send(app(), tdh::get(format!("/jobs/{job}"))).await;
            assert_eq!(status, StatusCode::OK);
            let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(got["status"], "pending");
            assert_eq!(got["bundle_kind"], "full");

            let (status, body) =
                tdh::send(app(), tdh::get(format!("/jobs/{job}/items?status=pending"))).await;
            assert_eq!(status, StatusCode::OK);
            let items: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(items["items"][0]["logical_path"], "a/a-1.jar");

            let missing = Uuid::new_v4();
            let (status, _) = tdh::send(app(), tdh::get(format!("/jobs/{missing}"))).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, _) = tdh::send(app(), tdh::get(format!("/jobs/{missing}/items"))).await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            let manifest = encode_manifest(&sample_manifest()).unwrap();
            let (status, body) = tdh::send(
                app(),
                tdh::post(
                    "/manifest/validate".into(),
                    "application/json",
                    manifest.into(),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(report["valid"], true);

            let (status, body) = tdh::send(
                app(),
                tdh::post(
                    "/exports".into(),
                    "application/json",
                    br#"{"repository_keys":["libs"],"media_profile":"bd_r"}"#
                        .to_vec()
                        .into(),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
            let ni: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(ni["code"], "NOT_IMPLEMENTED");
            assert_eq!(ni["tracking_issue"], TRACKING_ISSUE);

            let (status, _) = tdh::send(
                app(),
                tdh::post(
                    "/exports".into(),
                    "application/json",
                    br#"{"repository_keys":[]}"#.to_vec().into(),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            let (status, _) = tdh::send(
                app(),
                tdh::post("/imports".into(), "application/json", Bytes::new()),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

            sqlx::query("DELETE FROM bundle_jobs WHERE id = $1")
                .bind(job)
                .execute(&pool)
                .await
                .unwrap();
            let left: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM bundle_items WHERE job_id = $1")
                    .bind(job)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(left, 0, "bundle_items must cascade with their job");
        }

        /// Imported scan evidence has its own table, cascading with its job,
        /// and `scan_results.origin` exists with its CHECK so hash-based dedup
        /// can filter on it (#2464 adversarial constraint 1).
        #[tokio::test]
        async fn scan_evidence_is_stored_apart_from_scan_results() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let job = seed_job(&pool, "import").await;
            sqlx::query(
                "INSERT INTO bundle_scan_evidence (job_id, bundle_id, manifest_entry_index, \
                 artifact_sha256, scanner, scanned_at, verdict) \
                 VALUES ($1, $2, 0, $3, 'grype', NOW(), '{}'::jsonb)",
            )
            .bind(job)
            .bind(Uuid::new_v4())
            .bind("a".repeat(64))
            .execute(&pool)
            .await
            .expect("evidence row");
            let check: Option<String> = sqlx::query_scalar(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
                 WHERE conname = 'scan_results_origin_check'",
            )
            .fetch_optional(&pool)
            .await
            .unwrap();
            let check = check.expect("scan_results.origin CHECK constraint");
            assert!(
                check.contains("local_scan") && check.contains("imported"),
                "{check}"
            );
            sqlx::query("DELETE FROM bundle_jobs WHERE id = $1")
                .bind(job)
                .execute(&pool)
                .await
                .unwrap();
            let left: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM bundle_scan_evidence WHERE job_id = $1")
                    .bind(job)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(left, 0);
        }
    }
}
