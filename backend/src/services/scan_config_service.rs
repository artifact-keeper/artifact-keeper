//! Service for managing per-repository scan configurations.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;
use crate::models::security::ScanConfig;

/// Request to create or update a scan configuration.
///
/// Every field is optional so a `PUT /repositories/{key}/security` can carry
/// any subset of mutable columns; fields the client omits keep their existing
/// value (or fall back to the documented default when the row does not exist
/// yet). The previous shape required all of `scan_enabled`, `scan_on_upload`,
/// `scan_on_proxy`, `block_on_policy_violation`, `severity_threshold` on every
/// call. That was the #1374 bug class on a second entity: a partial PUT (for
/// example just `{scan_enabled: true}`) either bounced as a 422 or, worse,
/// silently reset every other column to its default so a follow-up GET showed
/// the untouched fields stale. The upsert is now a read-modify-write that
/// merges the patch over the existing row, so multiple fields persist together
/// and an omitted field is never clobbered. See #1374 / B11.
#[derive(Debug, Clone, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct UpsertScanConfigRequest {
    #[serde(default)]
    pub scan_enabled: Option<bool>,
    #[serde(default)]
    pub scan_on_upload: Option<bool>,
    #[serde(default)]
    pub scan_on_proxy: Option<bool>,
    #[serde(default)]
    pub block_on_policy_violation: Option<bool>,
    #[serde(default)]
    pub severity_threshold: Option<String>,
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
    ///
    /// This is a partial (read-modify-write) upsert: any field the caller left
    /// as `None` keeps its current value when a config row already exists, or
    /// the documented default when one does not. A multi-field patch persists
    /// every field it carries, and an omitted field is never reset. This fixes
    /// the #1374 bug class on the repo scan-config entity (B11), where a PUT
    /// that touched one field silently clobbered the others.
    pub async fn upsert_config(
        &self,
        repository_id: Uuid,
        req: &UpsertScanConfigRequest,
    ) -> Result<ScanConfig> {
        // Defaults applied when no config row exists yet. These mirror the
        // historical column defaults: scanning off, severity threshold "high".
        let existing = self.get_config(repository_id).await?;

        let scan_enabled = req
            .scan_enabled
            .unwrap_or_else(|| existing.as_ref().map(|c| c.scan_enabled).unwrap_or(false));
        let scan_on_upload = req
            .scan_on_upload
            .unwrap_or_else(|| existing.as_ref().map(|c| c.scan_on_upload).unwrap_or(false));
        let scan_on_proxy = req
            .scan_on_proxy
            .unwrap_or_else(|| existing.as_ref().map(|c| c.scan_on_proxy).unwrap_or(false));
        let block_on_policy_violation = req.block_on_policy_violation.unwrap_or_else(|| {
            existing
                .as_ref()
                .map(|c| c.block_on_policy_violation)
                .unwrap_or(false)
        });
        let severity_threshold = req.severity_threshold.clone().unwrap_or_else(|| {
            existing
                .as_ref()
                .map(|c| c.severity_threshold.clone())
                .unwrap_or_else(|| "high".to_string())
        });

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
            scan_enabled,
            scan_on_upload,
            scan_on_proxy,
            block_on_policy_violation,
            severity_threshold,
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
        assert_eq!(req.scan_enabled, Some(true));
        assert_eq!(req.scan_on_upload, Some(true));
        assert_eq!(req.scan_on_proxy, Some(false));
        assert_eq!(req.block_on_policy_violation, Some(true));
        assert_eq!(req.severity_threshold.as_deref(), Some("high"));
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
        assert_eq!(req.scan_enabled, Some(false));
        assert_eq!(req.scan_on_upload, Some(false));
        assert_eq!(req.scan_on_proxy, Some(false));
        assert_eq!(req.block_on_policy_violation, Some(false));
        assert_eq!(req.severity_threshold.as_deref(), Some("critical"));
    }

    #[test]
    fn test_upsert_scan_config_request_partial_omits_default_to_none() {
        // B11 / #1374 class: a partial PUT carries only the fields the client
        // wants to change. Omitted fields deserialize to None so the service
        // can preserve the existing row value instead of clobbering it.
        let json = r#"{ "scan_enabled": true }"#;
        let req: UpsertScanConfigRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.scan_enabled, Some(true));
        assert_eq!(req.scan_on_upload, None);
        assert_eq!(req.scan_on_proxy, None);
        assert_eq!(req.block_on_policy_violation, None);
        assert_eq!(req.severity_threshold, None);
    }

    #[test]
    fn test_upsert_scan_config_request_empty_body_all_none() {
        let req: UpsertScanConfigRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(req.scan_enabled, None);
        assert_eq!(req.scan_on_upload, None);
        assert_eq!(req.scan_on_proxy, None);
        assert_eq!(req.block_on_policy_violation, None);
        assert_eq!(req.severity_threshold, None);
    }

    // -----------------------------------------------------------------------
    // Merge semantics: every provided field overrides; every omitted field
    // falls back to the existing row (or the documented default on first
    // insert). This is the pure-function core of the partial upsert; it does
    // not touch the database, so it runs without DATABASE_URL.
    // -----------------------------------------------------------------------

    /// Re-implements the merge logic in `upsert_config` against an optional
    /// existing config so we can assert the field-preservation contract
    /// without a live Postgres connection.
    fn merge_for_test(
        req: &UpsertScanConfigRequest,
        existing: Option<&ScanConfig>,
    ) -> (bool, bool, bool, bool, String) {
        let scan_enabled = req
            .scan_enabled
            .unwrap_or_else(|| existing.map(|c| c.scan_enabled).unwrap_or(false));
        let scan_on_upload = req
            .scan_on_upload
            .unwrap_or_else(|| existing.map(|c| c.scan_on_upload).unwrap_or(false));
        let scan_on_proxy = req
            .scan_on_proxy
            .unwrap_or_else(|| existing.map(|c| c.scan_on_proxy).unwrap_or(false));
        let block_on_policy_violation = req.block_on_policy_violation.unwrap_or_else(|| {
            existing
                .map(|c| c.block_on_policy_violation)
                .unwrap_or(false)
        });
        let severity_threshold = req.severity_threshold.clone().unwrap_or_else(|| {
            existing
                .map(|c| c.severity_threshold.clone())
                .unwrap_or_else(|| "high".to_string())
        });
        (
            scan_enabled,
            scan_on_upload,
            scan_on_proxy,
            block_on_policy_violation,
            severity_threshold,
        )
    }

    fn sample_config() -> ScanConfig {
        ScanConfig {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_enabled: true,
            scan_on_upload: true,
            scan_on_proxy: false,
            block_on_policy_violation: true,
            severity_threshold: "medium".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_partial_upsert_preserves_omitted_fields_b11() {
        // The exact B11 symptom: flip scan_on_proxy only. Every other field
        // must keep its existing value, not reset to a default.
        let existing = sample_config();
        let req = UpsertScanConfigRequest {
            scan_on_proxy: Some(true),
            ..Default::default()
        };
        let (enabled, on_upload, on_proxy, block, sev) = merge_for_test(&req, Some(&existing));
        assert!(enabled, "scan_enabled must be preserved");
        assert!(on_upload, "scan_on_upload must be preserved");
        assert!(on_proxy, "scan_on_proxy must be the new value");
        assert!(block, "block_on_policy_violation must be preserved");
        assert_eq!(sev, "medium", "severity_threshold must be preserved");
    }

    #[test]
    fn test_partial_upsert_multi_field_all_persist_b11() {
        // A two-field patch must persist BOTH fields and leave the rest alone.
        let existing = sample_config();
        let req = UpsertScanConfigRequest {
            scan_enabled: Some(false),
            severity_threshold: Some("critical".to_string()),
            ..Default::default()
        };
        let (enabled, on_upload, on_proxy, block, sev) = merge_for_test(&req, Some(&existing));
        assert!(!enabled, "scan_enabled must take the new value");
        assert_eq!(
            sev, "critical",
            "severity_threshold must take the new value"
        );
        assert!(on_upload, "scan_on_upload must be preserved");
        assert!(!on_proxy, "scan_on_proxy must be preserved");
        assert!(block, "block_on_policy_violation must be preserved");
    }

    #[test]
    fn test_partial_upsert_first_insert_uses_defaults() {
        // No existing row: omitted fields fall back to documented defaults
        // (scanning off, severity "high"); provided fields take effect.
        let req = UpsertScanConfigRequest {
            scan_enabled: Some(true),
            ..Default::default()
        };
        let (enabled, on_upload, on_proxy, block, sev) = merge_for_test(&req, None);
        assert!(enabled);
        assert!(!on_upload);
        assert!(!on_proxy);
        assert!(!block);
        assert_eq!(sev, "high");
    }

    #[test]
    fn test_upsert_scan_config_request_clone() {
        let req = UpsertScanConfigRequest {
            scan_enabled: Some(true),
            scan_on_upload: Some(false),
            scan_on_proxy: Some(true),
            block_on_policy_violation: Some(true),
            severity_threshold: Some("medium".to_string()),
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
            scan_enabled: Some(true),
            scan_on_upload: Some(true),
            scan_on_proxy: Some(false),
            block_on_policy_violation: Some(false),
            severity_threshold: Some("low".to_string()),
        };
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("UpsertScanConfigRequest"));
        assert!(debug_str.contains("scan_enabled: Some(true)"));
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
