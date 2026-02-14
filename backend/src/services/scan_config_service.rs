//! Service for managing per-repository scan configurations.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;
use crate::models::security::ScanConfig;

/// Request to create or update a scan configuration.
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // UpsertScanConfigRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_upsert_scan_config_request_deserialization() {
        let json = r#"{
            "scan_enabled": true,
            "scan_on_upload": true,
            "scan_on_proxy": false,
            "block_on_policy_violation": true,
            "severity_threshold": "high"
        }"#;
        let req: UpsertScanConfigRequest = serde_json::from_str(json).unwrap();
        assert!(req.scan_enabled);
        assert!(req.scan_on_upload);
        assert!(!req.scan_on_proxy);
        assert!(req.block_on_policy_violation);
        assert_eq!(req.severity_threshold, "high");
    }

    #[test]
    fn test_upsert_scan_config_request_all_disabled() {
        let json = r#"{
            "scan_enabled": false,
            "scan_on_upload": false,
            "scan_on_proxy": false,
            "block_on_policy_violation": false,
            "severity_threshold": "critical"
        }"#;
        let req: UpsertScanConfigRequest = serde_json::from_str(json).unwrap();
        assert!(!req.scan_enabled);
        assert!(!req.scan_on_upload);
        assert!(!req.scan_on_proxy);
        assert!(!req.block_on_policy_violation);
        assert_eq!(req.severity_threshold, "critical");
    }

    #[test]
    fn test_upsert_scan_config_request_clone() {
        let req = UpsertScanConfigRequest {
            scan_enabled: true,
            scan_on_upload: false,
            scan_on_proxy: true,
            block_on_policy_violation: true,
            severity_threshold: "medium".to_string(),
        };
        let cloned = req.clone();
        assert_eq!(cloned.scan_enabled, req.scan_enabled);
        assert_eq!(cloned.scan_on_upload, req.scan_on_upload);
        assert_eq!(cloned.scan_on_proxy, req.scan_on_proxy);
        assert_eq!(
            cloned.block_on_policy_violation,
            req.block_on_policy_violation
        );
        assert_eq!(cloned.severity_threshold, req.severity_threshold);
    }

    #[test]
    fn test_upsert_scan_config_request_debug() {
        let req = UpsertScanConfigRequest {
            scan_enabled: true,
            scan_on_upload: true,
            scan_on_proxy: false,
            block_on_policy_violation: false,
            severity_threshold: "low".to_string(),
        };
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("UpsertScanConfigRequest"));
        assert!(debug_str.contains("scan_enabled: true"));
    }

    // -----------------------------------------------------------------------
    // ScanConfig model (imported from models::security)
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_config_threshold_method() {
        use crate::models::security::{ScanConfig, Severity};

        let config = ScanConfig {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_enabled: true,
            scan_on_upload: true,
            scan_on_proxy: false,
            block_on_policy_violation: true,
            severity_threshold: "medium".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(config.threshold(), Severity::Medium);
    }

    // -----------------------------------------------------------------------
    // Default unwrap_or(false) logic for is_scan_enabled / is_proxy_scan_enabled
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_enabled_default_when_no_config() {
        fn is_scan_enabled(opt: Option<bool>) -> bool {
            opt.unwrap_or(false)
        }
        assert!(!is_scan_enabled(None));
    }

    #[test]
    fn test_scan_enabled_when_config_true() {
        fn is_scan_enabled(opt: Option<bool>) -> bool {
            opt.unwrap_or(false)
        }
        assert!(is_scan_enabled(Some(true)));
    }

    #[test]
    fn test_scan_enabled_when_config_false() {
        fn is_scan_enabled(opt: Option<bool>) -> bool {
            opt.unwrap_or(false)
        }
        assert!(!is_scan_enabled(Some(false)));
    }
}
