//! Service for managing per-repository scan configurations.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{ScanConfig, Severity};
use crate::services::proxy_scan_service::ProxyScanAction;

/// Canonicalize a client-supplied `proxy_scan_action` (#2954), preserving the
/// existing row's value when the patch omits it and defaulting to `fail_open`.
///
/// Unknown values are coerced to `fail_open` rather than passed through to the
/// DB CHECK constraint (which would surface as an opaque 500). Pure /
/// unit-testable.
fn normalize_proxy_scan_action(patch: Option<&str>, existing: Option<&str>) -> String {
    let raw = patch
        .or(existing)
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "fail_open".to_string());
    match raw.as_str() {
        "fail_closed" => "fail_closed".to_string(),
        _ => "fail_open".to_string(),
    }
}

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
    /// #2954: `'fail_open'` (default) | `'fail_closed'` for the inline proxy
    /// scan-on-fetch action.
    #[serde(default)]
    pub proxy_scan_action: Option<String>,
}

/// Validate + normalize a caller-supplied `severity_threshold` to the canonical
/// lowercase form enforced by the `scan_configs_severity_threshold_check` CHECK
/// constraint (`critical|high|medium|low|info`).
///
/// Accepts input case-insensitively and resolves aliases ("moderate" -> "medium",
/// "informational"/"none" -> "info"). A genuinely-invalid value yields a
/// `Validation` error (HTTP 400) instead of being passed to Postgres where it
/// would trip the constraint and surface as a raw DB error / HTTP 500 (#2953).
fn normalize_severity_threshold(raw: &str) -> Result<String> {
    Severity::from_str_loose(raw)
        .map(|s| s.as_str().to_string())
        .ok_or_else(|| {
            AppError::Validation(format!(
                "invalid severity_threshold '{raw}'; allowed values are \
                 critical, high, medium, low, info"
            ))
        })
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
                   block_on_policy_violation, severity_threshold, proxy_scan_action,
                   created_at, updated_at
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
        // Validate + normalize the caller-supplied severity_threshold BEFORE the
        // DB write. The column carries a `scan_configs_severity_threshold_check`
        // CHECK constraint over the canonical lowercase set
        // (critical|high|medium|low|info); passing a raw casing like "High" or a
        // bogus value like "yolo" straight through surfaced the constraint
        // violation as a raw DB error -> HTTP 500 (#2953). Accept case-insensitive
        // input and aliases ("moderate" -> "medium"), normalize to the canonical
        // form, and reject a genuinely-invalid value with a 400. An omitted field
        // keeps the existing (already-valid) row value, or the documented default.
        let severity_threshold = match req.severity_threshold.as_deref() {
            Some(raw) => normalize_severity_threshold(raw)?,
            None => existing
                .as_ref()
                .map(|c| c.severity_threshold.clone())
                .unwrap_or_else(|| "high".to_string()),
        };
        // #2954: default fail-open (matches the column default) so operators who
        // have not opted into fail-closed see today's behavior. A bad value is
        // normalized to fail-open rather than tripping the DB CHECK constraint.
        let proxy_scan_action = normalize_proxy_scan_action(
            req.proxy_scan_action.as_deref(),
            existing.as_ref().map(|c| c.proxy_scan_action.as_str()),
        );

        let config = sqlx::query_as!(
            ScanConfig,
            r#"
            INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, scan_on_proxy,
                                      block_on_policy_violation, severity_threshold,
                                      proxy_scan_action)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (repository_id)
            DO UPDATE SET
                scan_enabled = EXCLUDED.scan_enabled,
                scan_on_upload = EXCLUDED.scan_on_upload,
                scan_on_proxy = EXCLUDED.scan_on_proxy,
                block_on_policy_violation = EXCLUDED.block_on_policy_violation,
                severity_threshold = EXCLUDED.severity_threshold,
                proxy_scan_action = EXCLUDED.proxy_scan_action,
                updated_at = NOW()
            RETURNING id, repository_id, scan_enabled, scan_on_upload, scan_on_proxy,
                      block_on_policy_violation, severity_threshold, proxy_scan_action,
                      created_at, updated_at
            "#,
            repository_id,
            scan_enabled,
            scan_on_upload,
            scan_on_proxy,
            block_on_policy_violation,
            severity_threshold,
            proxy_scan_action,
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
                   block_on_policy_violation, severity_threshold, proxy_scan_action,
                   created_at, updated_at
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

    /// The inline proxy scan action (fail-open / fail-closed) for this repo
    /// (#2954). Defaults to fail-open when no config row exists, matching the
    /// column default and preserving today's availability-first behavior.
    pub async fn proxy_scan_action(&self, repository_id: Uuid) -> Result<ProxyScanAction> {
        let result = sqlx::query_scalar!(
            r#"SELECT proxy_scan_action FROM scan_configs WHERE repository_id = $1"#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        Ok(result
            .map(|v| ProxyScanAction::from_db(&v))
            .unwrap_or(ProxyScanAction::FailOpen))
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
    fn test_normalize_proxy_scan_action() {
        // Patch wins over existing.
        assert_eq!(
            normalize_proxy_scan_action(Some("fail_closed"), Some("fail_open")),
            "fail_closed"
        );
        // Omitted patch preserves existing.
        assert_eq!(
            normalize_proxy_scan_action(None, Some("fail_closed")),
            "fail_closed"
        );
        // Neither => fail-open default.
        assert_eq!(normalize_proxy_scan_action(None, None), "fail_open");
        // Case-insensitive + trimmed.
        assert_eq!(
            normalize_proxy_scan_action(Some("  FAIL_CLOSED "), None),
            "fail_closed"
        );
        // Unknown value coerced to fail-open (never trips the DB CHECK).
        assert_eq!(
            normalize_proxy_scan_action(Some("garbage"), None),
            "fail_open"
        );
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
            proxy_scan_action: "fail_open".to_string(),
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
            proxy_scan_action: Some("fail_closed".to_string()),
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
            proxy_scan_action: None,
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
            proxy_scan_action: "fail_open".to_string(),
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

    // -----------------------------------------------------------------------
    // severity_threshold validation / normalization (#2953)
    //
    // The handler used to pass the raw string straight to Postgres, so a
    // non-lowercase casing ("High") or a bogus value ("yolo") tripped the
    // `scan_configs_severity_threshold_check` CHECK constraint and leaked as an
    // HTTP 500. normalize_severity_threshold now canonicalizes valid input and
    // rejects invalid input with a Validation error (HTTP 400) before the DB
    // write. These tests are pure and need no DATABASE_URL.
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_severity_accepts_canonical_lowercase() {
        for v in ["critical", "high", "medium", "low", "info"] {
            assert_eq!(normalize_severity_threshold(v).unwrap(), v);
        }
    }

    #[test]
    fn test_normalize_severity_normalizes_casing() {
        // The exact #2953 repro: "High" must be accepted and normalized, not 500.
        assert_eq!(normalize_severity_threshold("High").unwrap(), "high");
        assert_eq!(
            normalize_severity_threshold("CRITICAL").unwrap(),
            "critical"
        );
        assert_eq!(normalize_severity_threshold("Medium").unwrap(), "medium");
    }

    #[test]
    fn test_normalize_severity_resolves_aliases() {
        assert_eq!(normalize_severity_threshold("moderate").unwrap(), "medium");
        assert_eq!(normalize_severity_threshold("Moderate").unwrap(), "medium");
        assert_eq!(
            normalize_severity_threshold("informational").unwrap(),
            "info"
        );
        assert_eq!(normalize_severity_threshold("none").unwrap(), "info");
    }

    #[test]
    fn test_normalize_severity_rejects_invalid_with_validation_error() {
        // "yolo" must be a 400 (Validation), never reach Postgres as a 500.
        let err = normalize_severity_threshold("yolo").unwrap_err();
        assert!(
            matches!(err, AppError::Validation(_)),
            "invalid severity must map to Validation (400), got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("severity_threshold") && msg.contains("critical"),
            "message must name the field and list allowed values: {msg}"
        );
    }

    #[test]
    fn test_normalize_severity_rejects_empty() {
        assert!(matches!(
            normalize_severity_threshold("").unwrap_err(),
            AppError::Validation(_)
        ));
    }
}
