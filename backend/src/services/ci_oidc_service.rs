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

/// Column list of `ci_oidc_providers`, in [`CiOidcProvider`] field order.
///
/// A macro, not a `const`: sqlx 0.9 accepts only `&'static str` as a
/// statement, so the fragments have to be spliced by `concat!` at compile
/// time. Mirrors `lifecycle_service::exclusion_predicate!`.
macro_rules! provider_columns {
    () => {
        "id, name, provider_type, issuer_url, audience, is_enabled, created_at, updated_at"
    };
}

/// Column list of `ci_oidc_identity_mappings`, in [`CiOidcIdentityMapping`]
/// field order. Shared by every statement that selects or returns a mapping,
/// so a column added to one cannot go missing from another.
macro_rules! mapping_columns {
    () => {
        "id, provider_id, name, priority, claim_filters, allowed_repo_ids, \
         is_enabled, created_at, updated_at"
    };
}

/// Projection behind [`ProviderResponseRow`]: a provider joined with its
/// mapping count. The two provider read paths differ only in the filter and
/// ordering they append to it.
macro_rules! provider_response_select {
    () => {
        concat!(
            "SELECT p.id, p.name, p.provider_type, p.issuer_url, p.audience, ",
            "p.is_enabled, p.created_at, p.updated_at, COUNT(m.id) AS mapping_count ",
            "FROM ci_oidc_providers p ",
            "LEFT JOIN ci_oidc_identity_mappings m ON m.provider_id = p.id "
        )
    };
}

/// Load one mapping by `(id, provider_id)`. The `provider_id` conjunct is
/// load-bearing: it is what stops a mapping being read or edited through a
/// sibling provider's route.
macro_rules! select_mapping_by_id {
    () => {
        concat!(
            "SELECT ",
            mapping_columns!(),
            " FROM ci_oidc_identity_mappings WHERE id = $1 AND provider_id = $2"
        )
    };
}

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

/// `iss` / `aud` read out of an assertion that has NOT been verified yet,
/// used only to choose which configured provider to verify it against (#3548).
struct UnverifiedAssertionHints {
    issuer: String,
    audiences: Vec<String>,
}

/// Compare issuer URLs ignoring a trailing slash.
///
/// The same normalisation [`CiOidcService::fetch_discovery`] applies before
/// appending `/.well-known/openid-configuration`, so a row configured as
/// `https://gitlab.example.com/` resolves the assertions its own discovery
/// document covers. Resolution is deliberately the only place this is
/// relaxed: `validate_ci_jwt` still requires the exact configured `iss`, so
/// normalising here can select a provider but never accept a token.
fn normalize_issuer(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
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

/// A `ci_oidc_providers` row joined with its mapping count, as both
/// [`CiOidcService::list`] and [`CiOidcService::get_response`] select it.
/// One type and one conversion, so the two cannot drift apart.
#[derive(sqlx::FromRow)]
struct ProviderResponseRow {
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

impl From<ProviderResponseRow> for CiOidcProviderResponse {
    fn from(r: ProviderResponseRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            provider_type: r.provider_type,
            issuer_url: r.issuer_url,
            audience: r.audience,
            is_enabled: r.is_enabled,
            mapping_count: r.mapping_count,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
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
            // SSO trust class: CI-OIDC discovery/JWKS fetches target an
            // operator-configured identity provider (the same class as the
            // SSO/OIDC login path), so the connect-time SSRF check honors
            // SSO_ALLOW_PRIVATE_IPS / AK_SSRF_ALLOW_PRIVATE_CIDRS instead of
            // the fail-closed upstream default (issue #2405). Cloud-metadata,
            // loopback and link-local addresses stay hard-blocked regardless.
            http: crate::services::http_client::sso_client(),
        }
    }

    // -----------------------------------------------------------------------
    // Provider CRUD
    // -----------------------------------------------------------------------

    pub async fn list(&self) -> Result<Vec<CiOidcProviderResponse>> {
        let rows = sqlx::query_as::<_, ProviderResponseRow>(concat!(
            provider_response_select!(),
            "GROUP BY p.id ORDER BY p.created_at ASC"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<CiOidcProvider> {
        sqlx::query_as::<_, CiOidcProvider>(concat!(
            "SELECT ",
            provider_columns!(),
            " FROM ci_oidc_providers WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("CI OIDC provider not found".into()))
    }

    /// Get a provider as a `CiOidcProviderResponse` (includes mapping_count).
    pub async fn get_response(&self, id: Uuid) -> Result<CiOidcProviderResponse> {
        sqlx::query_as::<_, ProviderResponseRow>(concat!(
            provider_response_select!(),
            "WHERE p.id = $1 GROUP BY p.id"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .map(Into::into)
        .ok_or_else(|| AppError::NotFound("CI OIDC provider not found".into()))
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
        let rows = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "SELECT ",
            mapping_columns!(),
            " FROM ci_oidc_identity_mappings WHERE provider_id = $1 ",
            "ORDER BY priority ASC, created_at ASC"
        ))
        .bind(provider_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Load one mapping by `(mapping_id, provider_id)`, or 404. Shared by the
    /// read endpoint and the update path, which need exactly this.
    async fn fetch_mapping_row(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
    ) -> Result<CiOidcIdentityMapping> {
        sqlx::query_as::<_, CiOidcIdentityMapping>(select_mapping_by_id!())
            .bind(mapping_id)
            .bind(provider_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("CI OIDC identity mapping not found".into()))
    }

    pub async fn get_mapping(
        &self,
        provider_id: Uuid,
        mapping_id: Uuid,
    ) -> Result<CiOidcMappingResponse> {
        self.fetch_mapping_row(provider_id, mapping_id)
            .await
            .map(Into::into)
    }

    pub async fn create_mapping(
        &self,
        provider_id: Uuid,
        req: CreateCiOidcMappingRequest,
    ) -> Result<CiOidcMappingResponse> {
        self.get(provider_id).await?;
        let priority = req.priority.unwrap_or(100);
        let is_enabled = req.is_enabled.unwrap_or(true);

        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "INSERT INTO ci_oidc_identity_mappings ",
            "(provider_id, name, priority, claim_filters, allowed_repo_ids, is_enabled) ",
            "VALUES ($1, $2, $3, $4, $5, $6) RETURNING ",
            mapping_columns!()
        ))
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
        let existing = self.fetch_mapping_row(provider_id, mapping_id).await?;

        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "UPDATE ci_oidc_identity_mappings SET name = $3, priority = $4, ",
            "claim_filters = $5, allowed_repo_ids = $6, is_enabled = $7, ",
            "updated_at = NOW() WHERE id = $1 AND provider_id = $2 RETURNING ",
            mapping_columns!()
        ))
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
        let row = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "UPDATE ci_oidc_identity_mappings SET is_enabled = $3, updated_at = NOW() ",
            "WHERE id = $1 AND provider_id = $2 RETURNING ",
            mapping_columns!()
        ))
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
    // Provider resolution (issue #3548)
    // -----------------------------------------------------------------------

    /// Pick the provider an incoming assertion should be verified against.
    ///
    /// Before #3548 the caller had to name the `ci_oidc_providers` row by
    /// UUID, and the only endpoint publishing that UUID is admin-only — so a
    /// "keyless" CI job had to start by using the admin password. The issuer
    /// is already part of what the verifier checks, so it is enough to select
    /// on: read the **unverified** `iss` (and `aud`) out of the assertion, use
    /// them only to choose a configured row, then run the unchanged full
    /// verification in [`Self::validate_ci_jwt`] against that row. Nothing is
    /// trusted from the peeked claims — a forged `iss` can at most select a
    /// provider whose JWKS will then refuse the signature.
    ///
    /// `provider_id_override` keeps the pre-#3548 request shape working. When
    /// it is supplied it wins, but it must agree with the assertion's `iss`:
    /// a request naming a provider the assertion was not issued for is a
    /// configuration mistake, and answering it with the verifier's generic
    /// "validation failed" would send the operator looking in the wrong place.
    pub async fn resolve_provider_for_assertion(
        &self,
        jwt_str: &str,
        provider_id_override: Option<Uuid>,
    ) -> Result<CiOidcProvider> {
        if let Some(id) = provider_id_override {
            let provider = self.get(id).await?;
            if !provider.is_enabled {
                return Err(AppError::Authentication(
                    "CI OIDC provider is disabled".into(),
                ));
            }
            // A malformed assertion is deliberately NOT rejected here: the
            // override path only cross-checks what it can read, and
            // `validate_ci_jwt` is the single place that decides whether an
            // assertion is acceptable.
            if let Some(hints) = Self::peek_assertion_hints(jwt_str) {
                if normalize_issuer(&hints.issuer) != normalize_issuer(&provider.issuer_url) {
                    return Err(AppError::Validation(format!(
                        "provider_id names a provider for issuer {}, but the presented                          assertion was issued by {}. Omit provider_id to resolve the                          provider from the assertion's iss claim.",
                        provider.issuer_url, hints.issuer
                    )));
                }
            }
            return Ok(provider);
        }

        let hints = Self::peek_assertion_hints(jwt_str).ok_or_else(|| {
            AppError::Authentication(
                "Could not read the iss claim from the presented CI assertion".into(),
            )
        })?;

        // Enabled providers are a handful of operator-created rows, so the
        // whole set is fetched and matched in Rust rather than in SQL: the
        // trailing-slash normalisation below has no index-friendly SQL form,
        // and keeping it in one pure function is what makes it testable.
        let candidates = self.list_enabled_providers().await?;
        Self::select_provider_by_issuer(candidates, &hints)
    }

    /// Read `iss` and `aud` out of an **unverified** assertion.
    ///
    /// Returns `None` for anything that is not a decodable JWT carrying a
    /// string `iss`. `aud` is accepted in both RFC 7519 §4.1.3 shapes (a
    /// single string or an array of strings) and is only ever used to break a
    /// tie between providers that share an issuer.
    fn peek_assertion_hints(jwt_str: &str) -> Option<UnverifiedAssertionHints> {
        // `dangerous::insecure_decode` skips signature AND claim validation,
        // which is exactly what is wanted: the assertion has not been verified
        // yet and an expired or wrong-audience one must still be routed to its
        // provider so the verifier can produce the accurate error.
        let claims = jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(jwt_str)
            .ok()?
            .claims;
        let issuer = claims.get("iss")?.as_str()?.to_owned();
        let audiences = match claims.get("aud") {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(vs)) => vs
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        Some(UnverifiedAssertionHints { issuer, audiences })
    }

    async fn list_enabled_providers(&self) -> Result<Vec<CiOidcProvider>> {
        sqlx::query_as::<_, CiOidcProvider>(concat!(
            "SELECT ",
            provider_columns!(),
            " FROM ci_oidc_providers WHERE is_enabled = true ORDER BY created_at ASC"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Select the one enabled provider that matches the assertion's issuer.
    ///
    /// `ci_oidc_providers` has no uniqueness constraint on `issuer_url`
    /// (migration 145 indexes it, but does not make it unique), so two enabled
    /// rows may legitimately share an issuer — the same GitLab instance
    /// configured twice for two audiences, for example. The tie is broken on
    /// the audience the assertion actually declares, because that is the other
    /// value the verifier checks; if that still leaves a choice, the request is
    /// refused with a 400 telling the caller to name the provider explicitly
    /// rather than guessing which configuration was meant.
    fn select_provider_by_issuer(
        candidates: Vec<CiOidcProvider>,
        hints: &UnverifiedAssertionHints,
    ) -> Result<CiOidcProvider> {
        let issuer = normalize_issuer(&hints.issuer);
        let mut matched: Vec<CiOidcProvider> = candidates
            .into_iter()
            .filter(|p| p.is_enabled && normalize_issuer(&p.issuer_url) == issuer)
            .collect();

        if matched.len() > 1 {
            let by_audience: Vec<CiOidcProvider> = matched
                .iter()
                .filter(|p| hints.audiences.iter().any(|a| a == &p.audience))
                .cloned()
                .collect();
            if by_audience.len() == 1 {
                matched = by_audience;
            }
        }

        match matched.len() {
            1 => Ok(matched.remove(0)),
            0 => Err(AppError::NotFound(format!(
                "No enabled CI OIDC provider is configured for issuer {issuer}"
            ))),
            _ => Err(AppError::Validation(format!(
                "{} enabled CI OIDC providers are configured for issuer {issuer};                  supply provider_id to choose one",
                matched.len()
            ))),
        }
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
        let mappings = sqlx::query_as::<_, CiOidcIdentityMapping>(concat!(
            "SELECT ",
            mapping_columns!(),
            " FROM ci_oidc_identity_mappings WHERE provider_id = $1 AND is_enabled = true ",
            "ORDER BY priority ASC, created_at ASC"
        ))
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
        // SSRF protection: reject blocked addresses and non-HTTPS schemes.
        // The issuer_url is admin-controlled DB data; validating here (not just at
        // write time) provides defence-in-depth for values already in the database.
        // Validated in the SSO trust class (issue #2405) to match the connect-time
        // check of the SSO client: a private-IP identity provider is reachable when
        // the operator opts in via SSO_ALLOW_PRIVATE_IPS / AK_SSRF_ALLOW_PRIVATE_CIDRS,
        // while metadata / loopback / link-local targets stay hard-blocked.
        if !issuer_url.starts_with("https://") {
            return Err(AppError::Validation(
                "CI OIDC issuer URL must use HTTPS".into(),
            ));
        }
        crate::api::validation::validate_outbound_sso_url(issuer_url, "CI OIDC issuer URL")?;

        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let response = self
            .http
            .get(&url)
            .timeout(OIDC_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("CI OIDC discovery fetch failed: {e}")))?;
        let discovery: serde_json::Value = crate::services::http_client::read_json_capped(
            response,
            crate::services::http_client::MAX_OIDC_RESPONSE_BYTES,
        )
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

        let response = self
            .http
            .get(jwks_uri)
            .timeout(OIDC_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("CI JWKS fetch failed: {e}")))?;
        let jwks: serde_json::Value = crate::services::http_client::read_json_capped(
            response,
            crate::services::http_client::MAX_OIDC_RESPONSE_BYTES,
        )
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
    use super::{
        normalize_issuer, CiOidcIdentityMapping, CiOidcProvider, CiOidcService,
        UnverifiedAssertionHints,
    };
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

    /// Serializes the SSRF-toggle tests below: they mutate process-wide env
    /// vars that must stay in place across an `.await`, so this is a tokio
    /// mutex (held across the awaited fetch) rather than a std one. Without
    /// it, `cargo test`'s parallel threads could flip a toggle under another
    /// test's nose. (Under `cargo nextest`, per-test process isolation makes
    /// this a no-op safety net.) Mirrors the `ssrf_dns` test pattern.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Await `fut()` with ONLY the given env toggles set (all other
    /// private-IP allow knobs cleared), restoring the prior values
    /// afterwards. The env must be manipulated around the *await* (not just
    /// future construction): an async fn body runs on poll.
    async fn with_ssrf_toggles<F, Fut, R>(set: &[(&str, &str)], fut: F) -> R
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        const VARS: [&str; 5] = [
            "WEBHOOK_ALLOW_PRIVATE_IPS",
            "SSO_ALLOW_PRIVATE_IPS",
            "UPSTREAM_ALLOW_PRIVATE_IPS",
            "AK_SSRF_ALLOW_PRIVATE_CIDRS",
            "UPSTREAM_PRIVATE_IP_ALLOWLIST",
        ];
        let _lock = ENV_LOCK.lock().await;
        let prev: Vec<(&str, Option<String>)> =
            VARS.iter().map(|v| (*v, std::env::var(v).ok())).collect();
        for v in VARS {
            std::env::remove_var(v);
        }
        for (k, val) in set {
            std::env::set_var(k, val);
        }
        let out = fut().await;
        for (k, val) in prev {
            match val {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        out
    }

    /// With no toggle set, a private-IP issuer stays blocked (fail-closed
    /// default), and the error names the SSO-surface knobs — discriminating
    /// for the #2405 fix: the old `Upstream`-context validation produced a
    /// block message with no `SSO_ALLOW_PRIVATE_IPS` guidance.
    #[tokio::test]
    async fn fetch_discovery_blocks_private_issuer_by_default_with_sso_guidance() {
        let svc = test_service();
        let err = with_ssrf_toggles(&[], || svc.fetch_discovery("https://10.10.0.8"))
            .await
            .expect_err("private-IP issuer must be blocked with no toggle set");
        let msg = err.to_string();
        assert!(
            msg.contains("SSO_ALLOW_PRIVATE_IPS") && msg.contains("AK_SSRF_ALLOW_PRIVATE_CIDRS"),
            "block error must name the SSO-surface opt-in knobs (#2405), got: {msg}"
        );
    }

    /// Cloud-metadata and loopback issuers stay hard-blocked even in the
    /// MOST permissive configuration (`SSO_ALLOW_PRIVATE_IPS=true`) — the
    /// toggle relaxes only the RFC1918/CGNAT/ULA class, never the SSRF
    /// hard-block class.
    #[tokio::test]
    async fn fetch_discovery_hard_blocks_metadata_and_loopback_even_with_toggle_on() {
        let svc = test_service();
        for issuer in [
            "https://169.254.169.254",
            "https://127.0.0.1",
            "https://[::1]",
        ] {
            let err = with_ssrf_toggles(&[("SSO_ALLOW_PRIVATE_IPS", "true")], || {
                svc.fetch_discovery(issuer)
            })
            .await
            .expect_err(
                "metadata/loopback issuer must stay blocked even with SSO_ALLOW_PRIVATE_IPS=true",
            );
            let msg = err.to_string();
            assert!(
                !msg.contains("discovery fetch failed"),
                "{issuer} must be rejected by validation, not attempted, got: {msg}"
            );
        }
    }

    /// With `SSO_ALLOW_PRIVATE_IPS=true`, a private-IP issuer passes the
    /// SSRF validation (the #2405 fix) — the fetch proceeds to the network
    /// layer and fails there (nothing listens at the unroutable target),
    /// NOT with a validation block. Asserts on the error class only, so no
    /// live endpoint is required.
    #[tokio::test]
    async fn fetch_discovery_private_issuer_passes_validation_when_toggle_on() {
        let svc = test_service();
        let err = with_ssrf_toggles(&[("SSO_ALLOW_PRIVATE_IPS", "true")], || {
            svc.fetch_discovery("https://10.255.255.1")
        })
        .await
        .expect_err("no IdP is listening at 10.255.255.1, so the fetch itself must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("discovery fetch failed"),
            "with the toggle on, a private-IP issuer must get past SSRF validation \
             and fail at the connection layer, got: {msg}"
        );
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
    // -----------------------------------------------------------------------
    // Provider resolution from the assertion's issuer (#3548)
    // -----------------------------------------------------------------------

    /// Build a syntactically valid but unsigned JWT carrying `claims`.
    ///
    /// Resolution reads the claims WITHOUT verifying the signature, so an
    /// unsigned token is exactly the right input here: it proves the peek
    /// works and — because `validate_ci_jwt` still runs afterwards in the
    /// handler — that a forged `iss` buys nothing but a provider whose JWKS
    /// then refuses it.
    fn unsigned_jwt(claims: serde_json::Value) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(b"not-a-real-signature");
        format!("{header}.{payload}.{signature}")
    }

    fn provider_at(issuer: &str, audience: &str, is_enabled: bool) -> CiOidcProvider {
        CiOidcProvider {
            issuer_url: issuer.to_string(),
            audience: audience.to_string(),
            is_enabled,
            ..sample_provider("generic")
        }
    }

    fn hints(issuer: &str, audiences: &[&str]) -> UnverifiedAssertionHints {
        UnverifiedAssertionHints {
            issuer: issuer.to_string(),
            audiences: audiences.iter().map(|a| (*a).to_string()).collect(),
        }
    }

    #[test]
    fn peek_assertion_hints_reads_iss_and_both_aud_shapes() {
        let single = CiOidcService::peek_assertion_hints(&unsigned_jwt(serde_json::json!({
            "iss": "https://gitlab.example.com",
            "aud": "artifact-keeper",
        })))
        .expect("a JWT with a string iss must be peekable");
        assert_eq!(single.issuer, "https://gitlab.example.com");
        assert_eq!(single.audiences, vec!["artifact-keeper".to_string()]);

        // RFC 7519 §4.1.3 also permits an array of audiences.
        let multi = CiOidcService::peek_assertion_hints(&unsigned_jwt(serde_json::json!({
            "iss": "https://gitlab.example.com",
            "aud": ["artifact-keeper", "other"],
        })))
        .expect("array aud must be peekable");
        assert_eq!(
            multi.audiences,
            vec!["artifact-keeper".to_string(), "other".to_string()]
        );
    }

    /// The peek must not reject an assertion for being expired or
    /// wrong-audience: routing it to its provider is what lets
    /// `validate_ci_jwt` return the accurate error instead of "no provider".
    #[test]
    fn peek_assertion_hints_ignores_claim_validity() {
        let expired = CiOidcService::peek_assertion_hints(&unsigned_jwt(serde_json::json!({
            "iss": "https://gitlab.example.com",
            "aud": "artifact-keeper",
            "exp": 1_000_000_000i64,
        })))
        .expect("an expired assertion must still resolve to its provider");
        assert_eq!(expired.issuer, "https://gitlab.example.com");
    }

    #[test]
    fn peek_assertion_hints_rejects_garbage_and_missing_iss() {
        assert!(CiOidcService::peek_assertion_hints("ci.jwt.token").is_none());
        assert!(CiOidcService::peek_assertion_hints("not-a-jwt-at-all").is_none());
        assert!(
            CiOidcService::peek_assertion_hints(&unsigned_jwt(serde_json::json!({"sub": "x"})))
                .is_none(),
            "an assertion with no iss cannot select a provider"
        );
    }

    #[test]
    fn select_provider_by_issuer_matches_the_configured_issuer() {
        let wanted = provider_at("https://gitlab.example.com", "artifact-keeper", true);
        let candidates = vec![
            provider_at("https://token.actions.githubusercontent.com", "ak", true),
            wanted.clone(),
        ];

        let picked = CiOidcService::select_provider_by_issuer(
            candidates,
            &hints("https://gitlab.example.com", &["artifact-keeper"]),
        )
        .expect("the matching issuer must resolve");
        assert_eq!(picked.id, wanted.id);
    }

    /// A row configured with a trailing slash and an `iss` without one (or the
    /// reverse) are the same issuer — the normalisation `fetch_discovery`
    /// already applies before building the discovery URL.
    #[test]
    fn select_provider_by_issuer_normalises_trailing_slashes() {
        assert_eq!(
            normalize_issuer("https://gitlab.example.com/"),
            normalize_issuer("https://gitlab.example.com")
        );

        let stored_with_slash = provider_at("https://gitlab.example.com/", "artifact-keeper", true);
        let picked = CiOidcService::select_provider_by_issuer(
            vec![stored_with_slash.clone()],
            &hints("https://gitlab.example.com", &["artifact-keeper"]),
        )
        .expect("a trailing slash on the stored row must not hide it");
        assert_eq!(picked.id, stored_with_slash.id);

        let stored_bare = provider_at("https://gitlab.example.com", "artifact-keeper", true);
        let picked = CiOidcService::select_provider_by_issuer(
            vec![stored_bare.clone()],
            &hints("https://gitlab.example.com/", &["artifact-keeper"]),
        )
        .expect("a trailing slash on the assertion's iss must not hide the row");
        assert_eq!(picked.id, stored_bare.id);
    }

    #[test]
    fn select_provider_by_issuer_ignores_disabled_providers() {
        let disabled = provider_at("https://gitlab.example.com", "artifact-keeper", false);
        let err = CiOidcService::select_provider_by_issuer(
            vec![disabled],
            &hints("https://gitlab.example.com", &["artifact-keeper"]),
        )
        .expect_err("a disabled provider must not be resolvable");
        assert!(
            err.to_string().contains("No enabled CI OIDC provider"),
            "got: {err}"
        );
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::NOT_FOUND,
            "an unconfigured issuer is a 404, not a 500"
        );
    }

    #[test]
    fn select_provider_by_issuer_reports_an_unconfigured_issuer() {
        let err = CiOidcService::select_provider_by_issuer(
            vec![provider_at("https://gitlab.example.com", "ak", true)],
            &hints("https://token.actions.githubusercontent.com", &["ak"]),
        )
        .expect_err("an issuer nobody configured must not resolve");
        assert!(
            err.to_string().contains("No enabled CI OIDC provider"),
            "got: {err}"
        );
    }

    /// `ci_oidc_providers` has no UNIQUE constraint on `issuer_url`, so two
    /// enabled rows may share an issuer. The declared audience breaks the tie
    /// when it can.
    #[test]
    fn select_provider_by_issuer_breaks_a_tie_on_the_declared_audience() {
        let for_ci = provider_at("https://gitlab.example.com", "artifact-keeper-ci", true);
        let candidates = vec![
            provider_at("https://gitlab.example.com", "artifact-keeper", true),
            for_ci.clone(),
        ];

        let picked = CiOidcService::select_provider_by_issuer(
            candidates,
            &hints("https://gitlab.example.com", &["artifact-keeper-ci"]),
        )
        .expect("the audience must disambiguate two rows on one issuer");
        assert_eq!(picked.id, for_ci.id);
    }

    /// When the audience cannot break the tie either, refuse with a 400 that
    /// asks for `provider_id` — guessing which of two configurations an
    /// operator meant is exactly the wrong thing for an auth endpoint to do.
    #[test]
    fn select_provider_by_issuer_rejects_an_ambiguous_issuer() {
        let candidates = vec![
            provider_at("https://gitlab.example.com", "artifact-keeper", true),
            provider_at("https://gitlab.example.com", "artifact-keeper", true),
        ];

        let err = CiOidcService::select_provider_by_issuer(
            candidates,
            &hints("https://gitlab.example.com", &["artifact-keeper"]),
        )
        .expect_err("two providers on one issuer and one audience must not be guessed between");
        let msg = err.to_string();
        assert!(msg.contains("supply provider_id"), "got: {msg}");
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    /// DB-backed: an assertion carrying only its `iss` resolves the provider
    /// with no `provider_id` at all — the whole point of #3548 — and a
    /// `provider_id` naming a different issuer is refused with a 400 rather
    /// than silently verified against the wrong configuration.
    #[tokio::test]
    async fn resolve_provider_for_assertion_roundtrip() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = CiOidcService::new(pool.clone());

        // Unique issuers so concurrent tests on a shared database cannot make
        // this one ambiguous.
        let tag = &Uuid::new_v4().to_string()[..8];
        let issuer = format!("https://issuer-{tag}.example.com");
        let other_issuer = format!("https://other-{tag}.example.com");

        let wanted = svc
            .create(super::CreateCiOidcProviderRequest {
                name: format!("resolve-by-issuer-{tag}"),
                provider_type: None,
                // Stored WITH a trailing slash; the assertion's iss has none.
                issuer_url: format!("{issuer}/"),
                audience: None,
                is_enabled: Some(true),
            })
            .await
            .expect("provider should be created");
        let other = svc
            .create(super::CreateCiOidcProviderRequest {
                name: format!("resolve-other-{tag}"),
                provider_type: None,
                issuer_url: other_issuer.clone(),
                audience: None,
                is_enabled: Some(true),
            })
            .await
            .expect("second provider should be created");

        let jwt = unsigned_jwt(serde_json::json!({
            "iss": issuer,
            "aud": "artifact-keeper",
            "sub": "ci:job",
        }));

        let resolved = svc
            .resolve_provider_for_assertion(&jwt, None)
            .await
            .expect("iss alone must resolve the provider");
        assert_eq!(resolved.id, wanted.id);

        // The explicit override still works (backward compatibility).
        let resolved = svc
            .resolve_provider_for_assertion(&jwt, Some(wanted.id))
            .await
            .expect("an agreeing provider_id override must still work");
        assert_eq!(resolved.id, wanted.id);

        // ... but only when it agrees with the assertion.
        let err = svc
            .resolve_provider_for_assertion(&jwt, Some(other.id))
            .await
            .expect_err("a provider_id for a different issuer must be refused");
        assert!(
            err.to_string().contains("Omit provider_id"),
            "the error must say how to fix it, got: {err}"
        );
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            axum::http::StatusCode::BAD_REQUEST
        );

        // A disabled row is invisible to issuer resolution.
        svc.toggle(wanted.id, false)
            .await
            .expect("provider should toggle");
        let err = svc
            .resolve_provider_for_assertion(&jwt, None)
            .await
            .expect_err("a disabled provider must not be resolvable by issuer");
        assert!(
            err.to_string().contains("No enabled CI OIDC provider"),
            "got: {err}"
        );
        // ... and naming it explicitly still reports it as disabled.
        let err = svc
            .resolve_provider_for_assertion(&jwt, Some(wanted.id))
            .await
            .expect_err("a disabled provider must be refused via the override too");
        assert!(
            err.to_string().contains("provider is disabled"),
            "got: {err}"
        );

        svc.delete(wanted.id).await.expect("cleanup wanted");
        svc.delete(other.id).await.expect("cleanup other");
    }
}
