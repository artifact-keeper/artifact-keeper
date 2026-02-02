//! Service for managing per-repository scan configurations.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;
use crate::models::security::ScanConfig;

/// Request to create or update a scan configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UpsertScanConfigRequest {
    pub scan_enabled: bool,
    pub scan_on_upload: bool,
    pub scan_on_proxy: bool,
    pub block_on_policy_violation: bool,
    pub severity_threshold: String,
}

pub struct ScanConfigService {
    db: PgPool,
}

impl ScanConfigService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Get scan configuration for a repository, if one exists.
    pub async fn get_config(&self, repository_id: Uuid) -> Result<Option<ScanConfig>> {
        let config = sqlx::query_as!(
            ScanConfig,
            r#"
            SELECT id, repository_id, scan_enabled, scan_on_upload, scan_on_proxy,
                   block_on_policy_violation, severity_threshold, created_at, updated_at
            FROM scan_configs
            WHERE repository_id = $1
            "#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        Ok(config)
    }

    /// Create or update scan configuration for a repository.
    pub async fn upsert_config(
        &self,
        repository_id: Uuid,
        req: &UpsertScanConfigRequest,
    ) -> Result<ScanConfig> {
        let config = sqlx::query_as!(
            ScanConfig,
            r#"
            INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, scan_on_proxy,
                                      block_on_policy_violation, severity_threshold)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (repository_id)
            DO UPDATE SET
                scan_enabled = EXCLUDED.scan_enabled,
                scan_on_upload = EXCLUDED.scan_on_upload,
                scan_on_proxy = EXCLUDED.scan_on_proxy,
                block_on_policy_violation = EXCLUDED.block_on_policy_violation,
                severity_threshold = EXCLUDED.severity_threshold,
                updated_at = NOW()
            RETURNING id, repository_id, scan_enabled, scan_on_upload, scan_on_proxy,
                      block_on_policy_violation, severity_threshold, created_at, updated_at
            "#,
            repository_id,
            req.scan_enabled,
            req.scan_on_upload,
            req.scan_on_proxy,
            req.block_on_policy_violation,
            req.severity_threshold,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        Ok(config)
    }

    /// List all scan configurations (for admin overview / filtering).
    pub async fn list_configs(&self) -> Result<Vec<ScanConfig>> {
        let configs = sqlx::query_as!(
            ScanConfig,
            r#"
            SELECT id, repository_id, scan_enabled, scan_on_upload, scan_on_proxy,
                   block_on_policy_violation, severity_threshold, created_at, updated_at
            FROM scan_configs
            WHERE scan_enabled = true
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        Ok(configs)
    }

    /// Quick check: is scanning enabled for this repository?
    pub async fn is_scan_enabled(&self, repository_id: Uuid) -> Result<bool> {
        let result = sqlx::query_scalar!(
            r#"SELECT scan_enabled FROM scan_configs WHERE repository_id = $1"#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        Ok(result.unwrap_or(false))
    }

    /// Quick check: is scan-on-proxy enabled for this repository?
    pub async fn is_proxy_scan_enabled(&self, repository_id: Uuid) -> Result<bool> {
        let result = sqlx::query_scalar!(
            r#"SELECT scan_on_proxy FROM scan_configs WHERE repository_id = $1"#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        Ok(result.unwrap_or(false))
    }
}
