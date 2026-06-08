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
use utoipa::ToSchema;
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
    /// Optional repository restriction for this mapping.
    /// `None` = unrestricted, `Some(vec![])` = deny all repos.
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// API request / response types — providers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCiOidcProviderRequest {
    pub name: String,
    pub provider_type: Option<String>,
    pub issuer_url: String,
    pub audience: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCiOidcProviderRequest {
    pub name: Option<String>,
    pub provider_type: Option<String>,
    pub issuer_url: Option<String>,
    pub audience: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, Clone, ToSchema)]
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
#[derive(Debug, Deserialize, ToSchema)]
pub struct CiOidcToggleRequest {
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// API request / response types — identity mappings
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCiOidcMappingRequest {
    pub name: String,
    pub priority: Option<i32>,
    pub claim_filters: serde_json::Value,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCiOidcMappingRequest {
    pub name: Option<String>,
    pub priority: Option<i32>,
    pub claim_filters: Option<serde_json::Value>,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct CiOidcMappingResponse {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub name: String,
    pub priority: i32,
    pub claim_filters: serde_json::Value,
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
            r#"SELECT id, provider_id, name, priority, claim_filters, allowed_repo_ids,
                      is_enabled, created_at, updated_at
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
            r#"SELECT id, provider_id, name, priority, claim_filters, allowed_repo_ids,
                      is_enabled, created_at, updated_at
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
                (provider_id, name, priority, claim_filters, allowed_repo_ids, is_enabled)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, provider_id, name, priority, claim_filters, allowed_repo_ids,
                         is_enabled, created_at, updated_at"#,
        )
        .bind(provider_id)
        .bind(req.name)
        .bind(priority)
        .bind(req.claim_filters)
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
            r#"SELECT id, provider_id, name, priority, claim_filters, allowed_repo_ids,
                      is_enabled, created_at, updated_at
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
                   allowed_repo_ids = $6,
                   is_enabled       = $7,
                   updated_at       = NOW()
               WHERE id = $1 AND provider_id = $2
               RETURNING id, provider_id, name, priority, claim_filters, allowed_repo_ids,
                         is_enabled, created_at, updated_at"#,
        )
        .bind(mapping_id)
        .bind(provider_id)
        .bind(req.name.unwrap_or(existing.name))
        .bind(req.priority.unwrap_or(existing.priority))
        .bind(req.claim_filters.unwrap_or(existing.claim_filters))
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
               RETURNING id, provider_id, name, priority, claim_filters, allowed_repo_ids,
                         is_enabled, created_at, updated_at"#,
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
            r#"SELECT id, provider_id, name, priority, claim_filters, allowed_repo_ids,
                      is_enabled, created_at, updated_at
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
            // CI service accounts are provisioned on first exchange by design:
            // the admin-configured identity mapping is the explicit opt-in
            // (mappings gate which CI identities may mint accounts).
            auto_create_users: true,
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

#[cfg(test)]
mod tests {
    use super::{CiOidcIdentityMapping, CiOidcProvider, CiOidcService};
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::models::user::AuthProvider;
    use chrono::Utc;
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    fn test_service() -> CiOidcService {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/artifact_keeper_test")
            .expect("lazy pool creation should succeed for unit tests");
        CiOidcService::new(pool)
    }

    fn sample_provider(provider_type: &str) -> CiOidcProvider {
        let now = Utc::now();
        CiOidcProvider {
            id: Uuid::new_v4(),
            name: "CI Provider".to_string(),
            provider_type: provider_type.to_string(),
            issuer_url: "https://issuer.example.com".to_string(),
            audience: "artifact-keeper".to_string(),
            is_enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn sample_mapping(name: &str) -> CiOidcIdentityMapping {
        let now = Utc::now();
        CiOidcIdentityMapping {
            id: Uuid::parse_str("11111111-2222-3333-4444-555555555555")
                .expect("static UUID should be valid"),
            provider_id: Uuid::new_v4(),
            name: name.to_string(),
            priority: 10,
            claim_filters: json!({"sub": "ci:example"}),
            allowed_repo_ids: None,
            is_enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn check_claim_policy_accepts_exact_and_array_matches() {
        let svc = test_service();
        let policy = json!({
            "project_path": ["group/repo", "other/repo"],
            "ref_type": "branch"
        });
        let claims = json!({
            "project_path": "group/repo",
            "ref_type": "branch"
        });

        assert!(svc.check_claim_policy(&policy, &claims).is_ok());
    }

    #[tokio::test]
    async fn check_claim_policy_rejects_non_object_policy() {
        let svc = test_service();
        let policy = json!("not-an-object");
        let claims = json!({"sub": "ci:job"});

        let err = svc
            .check_claim_policy(&policy, &claims)
            .expect_err("non-object policy must fail");
        assert!(err
            .to_string()
            .contains("claim_filters must be a JSON object"));
    }

    #[tokio::test]
    async fn check_claim_policy_rejects_mismatched_claim_value() {
        let svc = test_service();
        let policy = json!({"ref": "refs/heads/main"});
        let claims = json!({"ref": "refs/heads/feature"});

        let err = svc
            .check_claim_policy(&policy, &claims)
            .expect_err("mismatched claims must fail");
        assert!(err
            .to_string()
            .contains("did not match any configured identity mapping"));
    }

    #[test]
    fn select_jwk_key_rejects_empty_key_set() {
        let keys = vec![];
        let err = CiOidcService::select_jwk_key(&keys, None).expect_err("empty keys must fail");
        assert!(err.to_string().contains("No matching JWK found"));
    }

    #[test]
    fn select_jwk_key_rejects_missing_rsa_n() {
        let keys = vec![json!({"kid": "k1", "kty": "RSA", "e": "AQAB"})];
        let err = CiOidcService::select_jwk_key(&keys, Some("k1"))
            .expect_err("RSA key without modulus must fail");
        assert!(err.to_string().contains("JWK RSA missing 'n'"));
    }

    #[test]
    fn select_jwk_key_rejects_missing_ec_x() {
        let keys = vec![json!({"kid": "k1", "kty": "EC", "y": "abc"})];
        let err = CiOidcService::select_jwk_key(&keys, Some("k1"))
            .expect_err("EC key without x must fail");
        assert!(err.to_string().contains("JWK EC missing 'x'"));
    }

    #[test]
    fn select_jwk_key_rejects_unsupported_kty() {
        let keys = vec![json!({"kid": "k1", "kty": "OKP"})];
        let err = CiOidcService::select_jwk_key(&keys, Some("k1"))
            .expect_err("unsupported kty must fail");
        assert!(err.to_string().contains("Unsupported JWK kty"));
    }

    #[test]
    fn extract_identity_from_mapping_formats_gitlab_identity() {
        let provider = sample_provider("gitlab");
        let mapping = sample_mapping("Deploy Main");
        let claims = json!({
            "project_path": "group/repo",
            "sub": "gitlab-subject"
        });

        let identity = CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);
        assert_eq!(identity.external_id, "gitlab-subject");
        assert!(identity.username.starts_with("ci-"));
        assert_eq!(
            identity.email,
            format!("{}@ci.artifact-keeper.internal", identity.username)
        );
        assert_eq!(
            identity.display_name,
            Some("CI [GitLab] Deploy Main — group/repo".to_string())
        );
    }

    #[test]
    fn extract_identity_from_mapping_formats_github_identity() {
        let provider = sample_provider("github");
        let mapping = sample_mapping("Release Job");
        let claims = json!({
            "repository": "org/repo",
            "sub": "github-subject"
        });

        let identity = CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);
        assert_eq!(identity.external_id, "github-subject");
        assert_eq!(
            identity.display_name,
            Some("CI [GitHub] Release Job — org/repo".to_string())
        );
    }

    #[test]
    fn extract_identity_from_mapping_uses_defaults_for_unknown_provider() {
        let provider = sample_provider("custom");
        let mapping = sample_mapping("Any Pipeline");
        let claims = json!({});

        let identity = CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);
        assert_eq!(
            identity.display_name,
            Some("CI [CI Provider] Any Pipeline".to_string())
        );
        assert_eq!(identity.groups, vec!["ci".to_string()]);
        assert_eq!(identity.required_admin_group, None);
    }

    #[test]
    fn auth_provider_is_ci() {
        assert_eq!(CiOidcService::auth_provider(), AuthProvider::Ci);
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_non_https_url() {
        let svc = test_service();
        let err = svc
            .fetch_discovery("http://issuer.example.com")
            .await
            .expect_err("non-https issuer must be rejected");
        assert!(err.to_string().contains("must use HTTPS"));
    }

    #[tokio::test]
    async fn provider_crud_roundtrip() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let svc = CiOidcService::new(pool.clone());

        let created = svc
            .create(super::CreateCiOidcProviderRequest {
                name: "test-provider-crud".to_string(),
                provider_type: None,
                issuer_url: "https://issuer.example.com".to_string(),
                audience: None,
                is_enabled: None,
            })
            .await
            .expect("provider should be created");

        assert_eq!(created.provider_type, "generic");
        assert_eq!(created.audience, "artifact-keeper");
        assert!(created.is_enabled);

        let listed = svc.list().await.expect("providers should list");
        assert!(listed.iter().any(|p| p.id == created.id));

        let got = svc
            .get_response(created.id)
            .await
            .expect("provider should be readable");
        assert_eq!(got.name, "test-provider-crud");

        let updated = svc
            .update(
                created.id,
                super::UpdateCiOidcProviderRequest {
                    name: Some("test-provider-crud-updated".to_string()),
                    provider_type: Some("github".to_string()),
                    issuer_url: Some("https://issuer2.example.com".to_string()),
                    audience: Some("artifact-keeper-ci".to_string()),
                    is_enabled: Some(true),
                },
            )
            .await
            .expect("provider should update");
        assert_eq!(updated.name, "test-provider-crud-updated");
        assert_eq!(updated.provider_type, "github");

        let toggled = svc
            .toggle(created.id, false)
            .await
            .expect("provider should toggle");
        assert!(!toggled.is_enabled);

        svc.delete(created.id)
            .await
            .expect("provider should be deleted");

        let err = svc
            .get_response(created.id)
            .await
            .expect_err("deleted provider should not exist");
        assert!(err.to_string().contains("provider not found"));
    }

    #[tokio::test]
    async fn mapping_crud_and_resolve_mapping_roundtrip() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let svc = CiOidcService::new(pool.clone());
        let provider = svc
            .create(super::CreateCiOidcProviderRequest {
                name: "test-provider-mapping".to_string(),
                provider_type: Some("gitlab".to_string()),
                issuer_url: "https://issuer.example.com".to_string(),
                audience: Some("artifact-keeper".to_string()),
                is_enabled: Some(true),
            })
            .await
            .expect("provider should be created");

        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();

        let created = svc
            .create_mapping(
                provider.id,
                super::CreateCiOidcMappingRequest {
                    name: "main-branch".to_string(),
                    priority: None,
                    claim_filters: json!({"ref": "refs/heads/main"}),
                    allowed_repo_ids: Some(vec![repo_a]),
                    is_enabled: None,
                },
            )
            .await
            .expect("mapping should be created");
        assert_eq!(created.priority, 100);
        assert!(created.is_enabled);
        assert_eq!(created.allowed_repo_ids, Some(vec![repo_a]));

        let listed = svc
            .list_mappings(provider.id)
            .await
            .expect("mappings should list");
        assert!(listed.iter().any(|m| m.id == created.id));

        let got = svc
            .get_mapping(provider.id, created.id)
            .await
            .expect("mapping should be readable");
        assert_eq!(got.name, "main-branch");
        assert_eq!(got.allowed_repo_ids, Some(vec![repo_a]));

        let updated = svc
            .update_mapping(
                provider.id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: Some("release-branch".to_string()),
                    priority: Some(5),
                    claim_filters: Some(json!({"ref": ["refs/heads/main", "refs/heads/release"]})),
                    allowed_repo_ids: Some(vec![repo_a, repo_b]),
                    is_enabled: Some(true),
                },
            )
            .await
            .expect("mapping should update");
        assert_eq!(updated.name, "release-branch");
        assert_eq!(updated.priority, 5);
        assert_eq!(updated.allowed_repo_ids, Some(vec![repo_a, repo_b]));

        let unchanged_scope = svc
            .update_mapping(
                provider.id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: None,
                    is_enabled: Some(true),
                },
            )
            .await
            .expect("missing repo scope field should preserve existing scope");
        assert_eq!(unchanged_scope.allowed_repo_ids, Some(vec![repo_a, repo_b]));

        let deny_all = svc
            .update_mapping(
                provider.id,
                created.id,
                super::UpdateCiOidcMappingRequest {
                    name: None,
                    priority: None,
                    claim_filters: None,
                    allowed_repo_ids: Some(vec![]),
                    is_enabled: Some(true),
                },
            )
            .await
            .expect("explicit empty repo scope should be persisted as deny-all");
        assert_eq!(deny_all.allowed_repo_ids, Some(vec![]));

        let resolved = svc
            .resolve_mapping(provider.id, &json!({"ref": "refs/heads/release"}))
            .await
            .expect("matching claims should resolve mapping");
        assert_eq!(resolved.id, created.id);
        assert_eq!(resolved.allowed_repo_ids, Some(vec![]));

        let toggled = svc
            .toggle_mapping(provider.id, created.id, false)
            .await
            .expect("mapping should toggle");
        assert!(!toggled.is_enabled);

        let err = svc
            .resolve_mapping(provider.id, &json!({"ref": "refs/heads/release"}))
            .await
            .expect_err("disabled mapping should not resolve");
        assert!(err
            .to_string()
            .contains("No CI OIDC identity mappings configured"));

        svc.delete_mapping(provider.id, created.id)
            .await
            .expect("mapping should delete");
        svc.delete(provider.id)
            .await
            .expect("provider should delete");
    }
}
