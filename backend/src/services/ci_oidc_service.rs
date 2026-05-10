//! CI OIDC provider service.
//!
//! Manages trusted CI/CD identity providers (GitLab, GitHub Actions, generic
//! OIDC) and validates CI-issued JWTs so pipelines can exchange them for
//! short-lived Artifact Keeper access tokens without storing static secrets.
//!
//! ## Identity Mapping model
//!
//! Each provider holds a priority-ordered list of **identity mappings**.
//! On token exchange the service evaluates mappings in priority order (lower
//! number = higher priority); the first enabled mapping whose `claim_filters`
//! all match the incoming JWT wins.  The mapping determines:
//!
//! * Which AK **Role** the resulting service account receives.
//! * An optional explicit **repository scope** (`allowed_repo_ids`).
//! * A **stable username** derived from the mapping's UUID — the same pipeline
//!   configuration always authenticates as the same service account regardless
//!   of the branch/ref, giving a clean audit trail.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::user::AuthProvider;
use crate::services::auth_service::FederatedCredentials;

// ---------------------------------------------------------------------------
// DB models
// ---------------------------------------------------------------------------

/// A row from `ci_oidc_providers` (provider-level claim columns dropped in
/// migration 087).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CiOidcProvider {
    pub id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub issuer_url: String,
    pub audience: String,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// A row from `ci_oidc_identity_mappings`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CiOidcIdentityMapping {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub name: String,
    pub priority: i32,
    /// JSONB claim-filter map.  Each key is a claim name; the value is either
    /// a single string (exact match) or an array of strings (any-of match).
    pub claim_filters: serde_json::Value,
    /// Optional AK Role assigned to the service account for this mapping.
    pub role_id: Option<Uuid>,
    /// Optional repository-scope restriction (further narrows Role access).
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// API request / response types — providers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateCiOidcProviderRequest {
    pub name: String,
    pub provider_type: Option<String>,
    pub issuer_url: String,
    pub audience: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCiOidcProviderRequest {
    pub name: Option<String>,
    pub provider_type: Option<String>,
    pub issuer_url: Option<String>,
    pub audience: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CiOidcProviderResponse {
    pub id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub issuer_url: String,
    pub audience: String,
    pub is_enabled: bool,
    pub mapping_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Body for toggle endpoint.
#[derive(Debug, Deserialize)]
pub struct CiOidcToggleRequest {
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// API request / response types — identity mappings
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateCiOidcMappingRequest {
    pub name: String,
    pub priority: Option<i32>,
    pub claim_filters: serde_json::Value,
    pub role_id: Option<Uuid>,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCiOidcMappingRequest {
    pub name: Option<String>,
    pub priority: Option<i32>,
    pub claim_filters: Option<serde_json::Value>,
    pub role_id: Option<Uuid>,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CiOidcMappingResponse {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub name: String,
    pub priority: i32,
    pub claim_filters: serde_json::Value,
    pub role_id: Option<Uuid>,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<CiOidcIdentityMapping> for CiOidcMappingResponse {
    fn from(m: CiOidcIdentityMapping) -> Self {
        Self {
            id: m.id,
            provider_id: m.provider_id,
            name: m.name,
            priority: m.priority,
            claim_filters: m.claim_filters,
            role_id: m.role_id,
            allowed_repo_ids: m.allowed_repo_ids,
            is_enabled: m.is_enabled,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

// ---------------------------------------------------------------------------
// JWKS cache entry
// ---------------------------------------------------------------------------

struct JwksCacheEntry {
    keys: serde_json::Value,
    fetched_at: Instant,
}

const JWKS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// How long to wait for OIDC discovery and JWKS endpoint responses before
/// treating the request as failed. Prevents a slow or unreachable provider
/// from holding an Axum worker indefinitely.
const OIDC_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Process-wide JWKS cache shared across all `CiOidcService` instances.
///
/// Keyed by JWKS URI; entries expire after [`JWKS_CACHE_TTL`].  Using a
/// global avoids the per-request cache-miss that occurred when the cache
/// was a field on the short-lived `CiOidcService` struct.
static JWKS_CACHE: OnceLock<RwLock<HashMap<String, JwksCacheEntry>>> = OnceLock::new();

fn jwks_cache() -> &'static RwLock<HashMap<String, JwksCacheEntry>> {
    JWKS_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// CI OIDC provider service.
pub struct CiOidcService {
    db: PgPool,
    http: reqwest::Client,
}

impl CiOidcService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            http: crate::services::http_client::default_client(),
        }
    }

    // -----------------------------------------------------------------------
    // Provider CRUD
    // -----------------------------------------------------------------------

    pub async fn list(&self) -> Result<Vec<CiOidcProviderResponse>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            provider_type: String,
            issuer_url: String,
            audience: String,
            is_enabled: bool,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            mapping_count: i64,
        }
        let rows = sqlx::query_as::<_, Row>(
            r#"SELECT p.id, p.name, p.provider_type, p.issuer_url, p.audience,
                      p.is_enabled, p.created_at, p.updated_at,
                      COUNT(m.id) AS mapping_count
               FROM ci_oidc_providers p
               LEFT JOIN ci_oidc_identity_mappings m ON m.provider_id = p.id
               GROUP BY p.id
               ORDER BY p.created_at ASC"#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| CiOidcProviderResponse {
                id: r.id,
                name: r.name,
                provider_type: r.provider_type,
                issuer_url: r.issuer_url,
                audience: r.audience,
                is_enabled: r.is_enabled,
                mapping_count: r.mapping_count,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<CiOidcProvider> {
        sqlx::query_as::<_, CiOidcProvider>(
            r#"SELECT id, name, provider_type, issuer_url, audience, is_enabled,
                      created_at, updated_at
               FROM ci_oidc_providers
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("CI OIDC provider not found".into()))
    }

    /// Get a provider as a `CiOidcProviderResponse` (includes mapping_count).
    pub async fn get_response(&self, id: Uuid) -> Result<CiOidcProviderResponse> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            provider_type: String,
            issuer_url: String,
            audience: String,
            is_enabled: bool,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            mapping_count: i64,
        }
        let r = sqlx::query_as::<_, Row>(
            r#"SELECT p.id, p.name, p.provider_type, p.issuer_url, p.audience,
                      p.is_enabled, p.created_at, p.updated_at,
                      COUNT(m.id) AS mapping_count
               FROM ci_oidc_providers p
               LEFT JOIN ci_oidc_identity_mappings m ON m.provider_id = p.id
               WHERE p.id = $1
               GROUP BY p.id"#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("CI OIDC provider not found".into()))?;
        Ok(CiOidcProviderResponse {
            id: r.id,
            name: r.name,
            provider_type: r.provider_type,
            issuer_url: r.issuer_url,
            audience: r.audience,
            is_enabled: r.is_enabled,
            mapping_count: r.mapping_count,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }

    pub async fn create(&self, req: CreateCiOidcProviderRequest) -> Result<CiOidcProviderResponse> {
        let provider_type = req.provider_type.unwrap_or_else(|| "generic".into());
        let audience = req.audience.unwrap_or_else(|| "artifact-keeper".into());
        let is_enabled = req.is_enabled.unwrap_or(true);

        let id = sqlx::query_scalar::<_, Uuid>(
            r#"INSERT INTO ci_oidc_providers
                    (name, provider_type, issuer_url, audience, is_enabled)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id"#,
        )
        .bind(&req.name)
        .bind(&provider_type)
        .bind(&req.issuer_url)
        .bind(&audience)
        .bind(is_enabled)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        self.get_response(id).await
    }

    pub async fn update(
        &self,
        id: Uuid,
        req: UpdateCiOidcProviderRequest,
    ) -> Result<CiOidcProviderResponse> {
        let existing = self.get(id).await?;

        sqlx::query(
            r#"UPDATE ci_oidc_providers
               SET name          = $2,
                   provider_type = $3,
                   issuer_url    = $4,
                   audience      = $5,
                   is_enabled    = $6,
                   updated_at    = NOW()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(req.name.unwrap_or(existing.name))
        .bind(req.provider_type.unwrap_or(existing.provider_type))
        .bind(req.issuer_url.unwrap_or(existing.issuer_url))
        .bind(req.audience.unwrap_or(existing.audience))
        .bind(req.is_enabled.unwrap_or(existing.is_enabled))
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        self.get_response(id).await
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM ci_oidc_providers WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("CI OIDC provider not found".into()));
        }
        Ok(())
    }

    pub async fn toggle(&self, id: Uuid, enabled: bool) -> Result<CiOidcProviderResponse> {
        let result = sqlx::query(
            "UPDATE ci_oidc_providers SET is_enabled = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(enabled)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("CI OIDC provider not found".into()));
        }
        self.get_response(id).await
    }

    // -----------------------------------------------------------------------
    // Mapping CRUD
    // -----------------------------------------------------------------------

    pub async fn list_mappings(&self, provider_id: Uuid) -> Result<Vec<CiOidcMappingResponse>> {
        self.get(provider_id).await?;
        let rows = sqlx::query_as::<_, CiOidcIdentityMapping>(
            r#"SELECT id, provider_id, name, priority, claim_filters, role_id,
                      allowed_repo_ids, is_enabled, created_at, updated_at
               FROM ci_oidc_identity_mappings
               WHERE provider_id = $1
               ORDER BY priority ASC, created_at ASC"#,
        )
        .bind(provider_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get_mapping(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
    ) -> Result<CiOidcMappingResponse> {
        sqlx::query_as::<_, CiOidcIdentityMapping>(
            r#"SELECT id, provider_id, name, priority, claim_filters, role_id,
                      allowed_repo_ids, is_enabled, created_at, updated_at
               FROM ci_oidc_identity_mappings
               WHERE id = $1 AND provider_id = $2"#,
        )
        .bind(mapping_id)
        .bind(provider_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .map(Into::into)
        .ok_or_else(|| AppError::NotFound("CI OIDC identity mapping not found".into()))
    }

    pub async fn create_mapping(
        &self,
        provider_id: Uuid,
        req: CreateCiOidcMappingRequest,
    ) -> Result<CiOidcMappingResponse> {
        self.get(provider_id).await?;
        let priority = req.priority.unwrap_or(100);
        let is_enabled = req.is_enabled.unwrap_or(true);

        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(
            r#"INSERT INTO ci_oidc_identity_mappings
                    (provider_id, name, priority, claim_filters, role_id,
                     allowed_repo_ids, is_enabled)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, provider_id, name, priority, claim_filters, role_id,
                         allowed_repo_ids, is_enabled, created_at, updated_at"#,
        )
        .bind(provider_id)
        .bind(req.name)
        .bind(priority)
        .bind(req.claim_filters)
        .bind(req.role_id)
        .bind(req.allowed_repo_ids)
        .bind(is_enabled)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(row.into())
    }

    pub async fn update_mapping(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
        req: UpdateCiOidcMappingRequest,
    ) -> Result<CiOidcMappingResponse> {
        let existing = sqlx::query_as::<_, CiOidcIdentityMapping>(
            r#"SELECT id, provider_id, name, priority, claim_filters, role_id,
                      allowed_repo_ids, is_enabled, created_at, updated_at
               FROM ci_oidc_identity_mappings
               WHERE id = $1 AND provider_id = $2"#,
        )
        .bind(mapping_id)
        .bind(provider_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("CI OIDC identity mapping not found".into()))?;

        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(
            r#"UPDATE ci_oidc_identity_mappings
               SET name             = $3,
                   priority         = $4,
                   claim_filters    = $5,
                   role_id          = $6,
                   allowed_repo_ids = $7,
                   is_enabled       = $8,
                   updated_at       = NOW()
               WHERE id = $1 AND provider_id = $2
               RETURNING id, provider_id, name, priority, claim_filters, role_id,
                         allowed_repo_ids, is_enabled, created_at, updated_at"#,
        )
        .bind(mapping_id)
        .bind(provider_id)
        .bind(req.name.unwrap_or(existing.name))
        .bind(req.priority.unwrap_or(existing.priority))
        .bind(req.claim_filters.unwrap_or(existing.claim_filters))
        .bind(req.role_id.or(existing.role_id))
        .bind(req.allowed_repo_ids.or(existing.allowed_repo_ids))
        .bind(req.is_enabled.unwrap_or(existing.is_enabled))
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(row.into())
    }

    pub async fn delete_mapping(&self, provider_id: Uuid, mapping_id: Uuid) -> Result<()> {
        let result =
            sqlx::query("DELETE FROM ci_oidc_identity_mappings WHERE id = $1 AND provider_id = $2")
                .bind(mapping_id)
                .bind(provider_id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(
                "CI OIDC identity mapping not found".into(),
            ));
        }
        Ok(())
    }

    pub async fn toggle_mapping(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
        enabled: bool,
    ) -> Result<CiOidcMappingResponse> {
        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(
            r#"UPDATE ci_oidc_identity_mappings
               SET is_enabled = $3, updated_at = NOW()
               WHERE id = $1 AND provider_id = $2
               RETURNING id, provider_id, name, priority, claim_filters, role_id,
                         allowed_repo_ids, is_enabled, created_at, updated_at"#,
        )
        .bind(mapping_id)
        .bind(provider_id)
        .bind(enabled)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("CI OIDC identity mapping not found".into()))?;
        Ok(row.into())
    }

    // -----------------------------------------------------------------------
    // JWT validation
    // -----------------------------------------------------------------------

    /// Validate a CI-issued JWT against the provider's JWKS (signature,
    /// audience, issuer).  Returns the validated claims on success.
    ///
    /// Claim-filter matching is deferred to [`Self::resolve_mapping`].
    pub async fn validate_ci_jwt(
        &self,
        provider: &CiOidcProvider,
        jwt_str: &str,
    ) -> Result<serde_json::Value> {
        let discovery = self.fetch_discovery(&provider.issuer_url).await?;
        let jwks_uri = discovery["jwks_uri"]
            .as_str()
            .ok_or_else(|| AppError::Internal("OIDC discovery missing jwks_uri".into()))?
            .to_owned();

        let jwks = self.fetch_jwks(&jwks_uri).await?;

        let header = decode_header(jwt_str)
            .map_err(|e| AppError::Authentication(format!("Invalid CI JWT header: {e}")))?;

        let keys = jwks["keys"]
            .as_array()
            .ok_or_else(|| AppError::Internal("JWKS missing keys array".into()))?;

        let decoding_key = Self::select_jwk_key(keys, header.kid.as_deref())?;

        let alg = match header.alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
            jsonwebtoken::Algorithm::PS256 => Algorithm::PS256,
            jsonwebtoken::Algorithm::PS384 => Algorithm::PS384,
            jsonwebtoken::Algorithm::PS512 => Algorithm::PS512,
            other => {
                return Err(AppError::Authentication(format!(
                    "Unsupported CI JWT algorithm: {other:?}"
                )))
            }
        };

        let mut validation = Validation::new(alg);
        validation.set_audience(&[provider.audience.as_str()]);
        validation.set_issuer(&[provider.issuer_url.as_str()]);

        let token_data = decode::<serde_json::Value>(jwt_str, &decoding_key, &validation)
            .map_err(|e| AppError::Authentication(format!("CI JWT validation failed: {e}")))?;

        Ok(token_data.claims)
    }

    // -----------------------------------------------------------------------
    // Identity mapping resolution
    // -----------------------------------------------------------------------

    /// Find the first enabled mapping (ordered by priority ASC) whose
    /// `claim_filters` all match the provided JWT claims.
    ///
    /// Returns `Err(AppError::Authentication)` when no mapping matches.
    pub async fn resolve_mapping(
        &self,
        provider_id: Uuid,
        claims: &serde_json::Value,
    ) -> Result<CiOidcIdentityMapping> {
        let mappings = sqlx::query_as::<_, CiOidcIdentityMapping>(
            r#"SELECT id, provider_id, name, priority, claim_filters, role_id,
                      allowed_repo_ids, is_enabled, created_at, updated_at
               FROM ci_oidc_identity_mappings
               WHERE provider_id = $1 AND is_enabled = true
               ORDER BY priority ASC, created_at ASC"#,
        )
        .bind(provider_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if mappings.is_empty() {
            return Err(AppError::Authentication(
                "No CI OIDC identity mappings configured for this provider".into(),
            ));
        }

        for mapping in mappings {
            if self
                .check_claim_policy(&mapping.claim_filters, claims)
                .is_ok()
            {
                return Ok(mapping);
            }
        }

        Err(AppError::Authentication(
            "CI JWT did not match any identity mapping".into(),
        ))
    }

    /// Derive stable `FederatedCredentials` from the resolved mapping.
    ///
    /// The **username** is `ci-<mapping_id_short>` — stable across branches,
    /// refs and pipeline reruns.  One service account per mapping, not per job.
    pub fn extract_identity_from_mapping(
        provider: &CiOidcProvider,
        mapping: &CiOidcIdentityMapping,
        claims: &serde_json::Value,
    ) -> FederatedCredentials {
        let id_short: String = mapping
            .id
            .to_string()
            .replace('-', "")
            .chars()
            .take(8)
            .collect();
        let username = format!("ci-{id_short}");

        let display_name = match provider.provider_type.as_str() {
            "gitlab" => {
                let project = claims["project_path"]
                    .as_str()
                    .unwrap_or(claims["namespace_path"].as_str().unwrap_or("unknown"));
                format!("CI [GitLab] {} — {}", mapping.name, project)
            }
            "github" => {
                let repo = claims["repository"].as_str().unwrap_or("unknown");
                format!("CI [GitHub] {} — {}", mapping.name, repo)
            }
            _ => format!("CI [{}] {}", provider.name, mapping.name),
        };

        let email = format!("{username}@ci.artifact-keeper.internal");
        let external_id = claims["sub"].as_str().unwrap_or(&username).to_owned();

        FederatedCredentials {
            external_id,
            username,
            email,
            display_name: Some(display_name),
            groups: vec!["ci".to_string()],
            required_admin_group: None,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn fetch_discovery(&self, issuer_url: &str) -> Result<serde_json::Value> {
        // SSRF protection: reject private/internal addresses and non-HTTPS schemes.
        // The issuer_url is admin-controlled DB data; validating here (not just at
        // write time) provides defence-in-depth for values already in the database.
        if !issuer_url.starts_with("https://") {
            return Err(AppError::Validation(
                "CI OIDC issuer URL must use HTTPS".into(),
            ));
        }
        crate::api::validation::validate_outbound_url(issuer_url, "CI OIDC issuer URL")?;

        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let discovery: serde_json::Value = self
            .http
            .get(&url)
            .timeout(OIDC_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("CI OIDC discovery fetch failed: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("CI OIDC discovery parse failed: {e}")))?;
        Ok(discovery)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<serde_json::Value> {
        {
            let cache = jwks_cache().read().await;
            if let Some(entry) = cache.get(jwks_uri) {
                if entry.fetched_at.elapsed() < JWKS_CACHE_TTL {
                    return Ok(entry.keys.clone());
                }
            }
        }

        let jwks: serde_json::Value = self
            .http
            .get(jwks_uri)
            .timeout(OIDC_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("CI JWKS fetch failed: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("CI JWKS parse failed: {e}")))?;

        let mut cache = jwks_cache().write().await;
        cache.insert(
            jwks_uri.to_owned(),
            JwksCacheEntry {
                keys: jwks.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok(jwks)
    }

    fn select_jwk_key(keys: &[serde_json::Value], kid: Option<&str>) -> Result<DecodingKey> {
        let key = match kid {
            Some(kid) => keys
                .iter()
                .find(|k| k["kid"].as_str() == Some(kid))
                .or_else(|| keys.first()),
            None => keys.first(),
        }
        .ok_or_else(|| AppError::Internal("No matching JWK found".into()))?;

        let kty = key["kty"].as_str().unwrap_or("");
        match kty {
            "RSA" => {
                let n = key["n"]
                    .as_str()
                    .ok_or_else(|| AppError::Internal("JWK RSA missing 'n'".into()))?;
                let e = key["e"]
                    .as_str()
                    .ok_or_else(|| AppError::Internal("JWK RSA missing 'e'".into()))?;
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| AppError::Internal(format!("Invalid RSA JWK: {e}")))
            }
            "EC" => {
                let x = key["x"]
                    .as_str()
                    .ok_or_else(|| AppError::Internal("JWK EC missing 'x'".into()))?;
                let y = key["y"]
                    .as_str()
                    .ok_or_else(|| AppError::Internal("JWK EC missing 'y'".into()))?;
                DecodingKey::from_ec_components(x, y)
                    .map_err(|e| AppError::Internal(format!("Invalid EC JWK: {e}")))
            }
            other => Err(AppError::Internal(format!("Unsupported JWK kty: {other}"))),
        }
    }

    /// Enforce that every key/value pair in `policy` appears in `claims`.
    ///
    /// Array values use any-of semantics:
    /// `"namespace_path": ["group-a", "group-b"]` passes if the claim equals
    /// either "group-a" or "group-b".
    ///
    /// The error returned to the caller is deliberately generic — it does not
    /// name which claim failed so that mapping configuration is not leaked to
    /// the CI pipeline.  The detail is emitted via `tracing::debug!` for
    /// operator visibility without exposing it in API responses.
    fn check_claim_policy(
        &self,
        policy: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> Result<()> {
        let map = policy
            .as_object()
            .ok_or_else(|| AppError::Internal("claim_filters must be a JSON object".into()))?;

        for (key, expected) in map {
            let actual = &claims[key];
            let matches = match expected {
                serde_json::Value::Array(allowed_values) => {
                    allowed_values.iter().any(|v| v == actual)
                }
                _ => actual == expected,
            };
            if !matches {
                tracing::debug!(
                    claim = %key,
                    "CI JWT claim did not match required value(s) for this mapping"
                );
                return Err(AppError::Authentication(
                    "CI JWT did not match any configured identity mapping".into(),
                ));
            }
        }
        Ok(())
    }

    /// Returns the `AuthProvider` constant used when provisioning CI service
    /// accounts via `authenticate_federated`.
    pub fn auth_provider() -> AuthProvider {
        AuthProvider::Ci
    }
}
