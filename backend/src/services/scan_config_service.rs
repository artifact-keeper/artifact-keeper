//! Service for managing per-repository scan configurations.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::{ScanConfig, Severity};
use crate::services::proxy_scan_service::ProxyScanAction;

/// Canonicalize a client-supplied `proxy_scan_action` (#2954, `record_only`
/// since #3645), preserving the existing row's value when the patch omits it
/// and defaulting to `fail_open`.
///
/// A value the CLIENT sent must be one of `fail_open` / `fail_closed` /
/// `record_only` (case-insensitive, trimmed); anything else -- including the
/// hyphenated spellings `fail-closed` / `record-only` -- is a 400, never a
/// silent fallback to `fail_open` (which would arm the blocking gate the
/// operator was trying to configure differently). An EXISTING row value is
/// re-normalized leniently, so a legacy value can never wedge a later patch.
/// Pure / unit-testable.
fn normalize_proxy_scan_action(patch: Option<&str>, existing: Option<&str>) -> Result<String> {
    if let Some(raw) = patch {
        let canon = raw.trim().to_ascii_lowercase();
        return match canon.as_str() {
            "fail_open" | "fail_closed" | "record_only" => Ok(canon),
            _ => Err(AppError::Validation(format!(
                "invalid proxy_scan_action {raw:?}: expected one of \
                 fail_open, fail_closed, record_only"
            ))),
        };
    }
    Ok(
        ProxyScanAction::from_db(existing.unwrap_or("fail_open").trim())
            .as_db_str()
            .to_string(),
    )
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
    /// Opt-in that makes `severity_threshold` enforced on the proxy/OCI
    /// inline scan gate (#3243/#3246). `false` (the default) does NOT mean
    /// "don't block": it means the threshold is off and the gate blocks on
    /// ANY finding. To scan without ever blocking, set
    /// `proxy_scan_action = record_only`.
    #[serde(default)]
    pub block_on_policy_violation: Option<bool>,
    /// Severity floor for the inline proxy scan gate, live only when
    /// `block_on_policy_violation` is set (#3243/#3246).
    #[serde(default)]
    pub severity_threshold: Option<String>,
    /// Inline proxy scan-on-fetch action: `'fail_open'` (default) |
    /// `'fail_closed'` (#2954) | `'record_only'` (#3645). `record_only` is
    /// the non-blocking mode: findings, SBOM and verdicts are recorded but no
    /// pull is ever blocked, whatever `block_on_policy_violation` /
    /// `severity_threshold` say. Any other value is rejected with 400.
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
        Ok(self
            .upsert_config_with_previous(repository_id, req)
            .await?
            .current)
    }

    /// [`Self::upsert_config`], also returning the row it replaced (#3645),
    /// for the scan-config audit trail.
    ///
    /// The read of the previous row and the write run in ONE transaction,
    /// serialized per repository by a transaction-scoped advisory lock (a row
    /// lock alone cannot cover the first insert, when there is no row to
    /// lock), so two concurrent PUTs can never both report the same
    /// "previous" value. Runtime (non-macro) queries, so this adds no offline
    /// sqlx data.
    pub async fn upsert_config_with_previous(
        &self,
        repository_id: Uuid,
        req: &UpsertScanConfigRequest,
    ) -> Result<ScanConfigWrite> {
        let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
        let mut tx = self.db.begin().await.map_err(db_err)?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('scan_configs:' || $1::text, 0))",
        )
        .bind(repository_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        let existing: Option<ScanConfig> = sqlx::query_as(
            r#"
            SELECT id, repository_id, scan_enabled, scan_on_upload, scan_on_proxy,
                   block_on_policy_violation, severity_threshold, proxy_scan_action,
                   created_at, updated_at
            FROM scan_configs
            WHERE repository_id = $1
            FOR UPDATE
            "#,
        )
        .bind(repository_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let m = merge_scan_config(req, existing.as_ref())?;
        let current: ScanConfig = sqlx::query_as(
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
        )
        .bind(repository_id)
        .bind(m.scan_enabled)
        .bind(m.scan_on_upload)
        .bind(m.scan_on_proxy)
        .bind(m.block_on_policy_violation)
        .bind(&m.severity_threshold)
        .bind(&m.proxy_scan_action)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;

        Ok(ScanConfigWrite {
            previous: existing,
            current,
        })
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

    /// The severity gate the inline proxy scan gate applies to a `vulnerable`
    /// verdict for this repo (#3243 stage 3 / #3246).
    ///
    /// `proxy_scan_action = 'record_only'` (#3645) resolves to
    /// [`ProxySeverityGate::RecordOnly`](crate::services::proxy_scan_service::ProxySeverityGate::RecordOnly)
    /// whatever the other two columns say: it is the one explicit
    /// "record, never block" switch. Otherwise `block_on_policy_violation`
    /// (DEFAULT false) is the explicit opt-in; only when it is set does
    /// `severity_threshold` participate. An absent `scan_configs` row — like
    /// an opted-out one — keeps the historical block-on-any-finding posture,
    /// so no repository changes behavior without an operator having turned
    /// the toggle on. Runtime (non-macro) query so this adds no offline sqlx
    /// data.
    pub async fn proxy_severity_gate(
        &self,
        repository_id: Uuid,
    ) -> Result<crate::services::proxy_scan_service::ProxySeverityGate> {
        let row: Option<(bool, String, String)> = sqlx::query_as(
            r#"SELECT block_on_policy_violation, severity_threshold, proxy_scan_action
               FROM scan_configs WHERE repository_id = $1"#,
        )
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        Ok(match row {
            Some((block_on_policy_violation, severity_threshold, action)) => {
                proxy_severity_gate_for_row(block_on_policy_violation, &severity_threshold, &action)
            }
            None => crate::services::proxy_scan_service::ProxySeverityGate::BlockOnAny,
        })
    }
}

/// The outcome of [`ScanConfigService::upsert_config_with_previous`]: the row
/// before the write (`None` when the repository had no config, i.e. it ran
/// on the defaults) and the row after it.
#[derive(Debug, Clone)]
pub struct ScanConfigWrite {
    pub previous: Option<ScanConfig>,
    pub current: ScanConfig,
}

/// The six mutable columns of a scan-config write, after merging a partial
/// patch over the existing row (or the documented defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MergedScanConfig {
    pub scan_enabled: bool,
    pub scan_on_upload: bool,
    pub scan_on_proxy: bool,
    pub block_on_policy_violation: bool,
    pub severity_threshold: String,
    pub proxy_scan_action: String,
}

impl MergedScanConfig {
    /// The effective config of a repository with NO `scan_configs` row: the
    /// historical column defaults (scanning off, threshold `high`,
    /// `fail_open`).
    pub(crate) fn defaults() -> Self {
        Self {
            scan_enabled: false,
            scan_on_upload: false,
            scan_on_proxy: false,
            block_on_policy_violation: false,
            severity_threshold: "high".to_string(),
            proxy_scan_action: "fail_open".to_string(),
        }
    }

    pub(crate) fn of(c: &ScanConfig) -> Self {
        Self {
            scan_enabled: c.scan_enabled,
            scan_on_upload: c.scan_on_upload,
            scan_on_proxy: c.scan_on_proxy,
            block_on_policy_violation: c.block_on_policy_violation,
            severity_threshold: c.severity_threshold.clone(),
            proxy_scan_action: c.proxy_scan_action.clone(),
        }
    }
}

/// Merge a partial scan-config patch over the existing row (B11 / #1374):
/// an omitted field keeps the existing value, or the documented default when
/// there is no row. Validates `severity_threshold` (#2953) and
/// `proxy_scan_action` (#3645) so a bad value is a 400, not a DB 500.
pub(crate) fn merge_scan_config(
    req: &UpsertScanConfigRequest,
    existing: Option<&ScanConfig>,
) -> Result<MergedScanConfig> {
    let base = existing
        .map(MergedScanConfig::of)
        .unwrap_or_else(MergedScanConfig::defaults);
    let severity_threshold = match req.severity_threshold.as_deref() {
        Some(raw) => normalize_severity_threshold(raw)?,
        None => base.severity_threshold.clone(),
    };
    let proxy_scan_action = normalize_proxy_scan_action(
        req.proxy_scan_action.as_deref(),
        existing.map(|c| c.proxy_scan_action.as_str()),
    )?;
    Ok(MergedScanConfig {
        scan_enabled: req.scan_enabled.unwrap_or(base.scan_enabled),
        scan_on_upload: req.scan_on_upload.unwrap_or(base.scan_on_upload),
        scan_on_proxy: req.scan_on_proxy.unwrap_or(base.scan_on_proxy),
        block_on_policy_violation: req
            .block_on_policy_violation
            .unwrap_or(base.block_on_policy_violation),
        severity_threshold,
        proxy_scan_action,
    })
}

/// The severity gate one `scan_configs` row resolves to (#3645): the
/// record-only action overrides the threshold knobs; otherwise
/// [`ProxySeverityGate::from_config`](crate::services::proxy_scan_service::ProxySeverityGate::from_config).
/// Pure so the precedence is unit-testable without a DB.
pub(crate) fn proxy_severity_gate_for_row(
    block_on_policy_violation: bool,
    severity_threshold: &str,
    proxy_scan_action: &str,
) -> crate::services::proxy_scan_service::ProxySeverityGate {
    use crate::services::proxy_scan_service::ProxySeverityGate;
    if ProxyScanAction::from_db(proxy_scan_action).is_record_only() {
        return ProxySeverityGate::RecordOnly;
    }
    ProxySeverityGate::from_config(block_on_policy_violation, severity_threshold)
}

#[cfg(ak_test_shard = "services-2")]
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
        let n = |p, e| normalize_proxy_scan_action(p, e).unwrap();
        // Patch wins over existing.
        assert_eq!(n(Some("fail_closed"), Some("fail_open")), "fail_closed");
        // Omitted patch preserves existing.
        assert_eq!(n(None, Some("fail_closed")), "fail_closed");
        // Neither => fail-open default.
        assert_eq!(n(None, None), "fail_open");
        // Case-insensitive + trimmed.
        assert_eq!(n(Some("  FAIL_CLOSED "), None), "fail_closed");
        // A legacy/unknown EXISTING value re-normalizes leniently.
        assert_eq!(n(None, Some("garbage")), "fail_open");
    }

    /// #3645: `record_only` is a first-class action value (case-insensitive,
    /// preserved when a patch omits it), and a client value outside the
    /// three canonical tokens is a 400 rather than a silent `fail_open`.
    #[test]
    fn test_normalize_proxy_scan_action_record_only() {
        let n = |p, e| normalize_proxy_scan_action(p, e).unwrap();
        assert_eq!(n(Some(" Record_Only "), Some("fail_closed")), "record_only");
        assert_eq!(n(None, Some("record_only")), "record_only");
        assert_eq!(n(Some("fail_open"), Some("record_only")), "fail_open");
        for bad in ["record-only", "fail-closed", "garbage", ""] {
            assert!(
                matches!(
                    normalize_proxy_scan_action(Some(bad), Some("record_only")),
                    Err(AppError::Validation(_))
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    /// The merge the transactional upsert writes: a partial patch keeps every
    /// omitted field, an absent row merges over the documented defaults, and
    /// a bad action is rejected before any write.
    #[test]
    fn test_merge_scan_config_partial_and_defaults() {
        let patch = UpsertScanConfigRequest {
            proxy_scan_action: Some("record_only".into()),
            ..Default::default()
        };
        let m = merge_scan_config(&patch, None).unwrap();
        assert_eq!(
            m,
            MergedScanConfig {
                proxy_scan_action: "record_only".into(),
                ..MergedScanConfig::defaults()
            }
        );
        let existing = sample_config();
        let m = merge_scan_config(&patch, Some(&existing)).unwrap();
        assert_eq!(m.severity_threshold, existing.severity_threshold);
        assert_eq!(
            m.block_on_policy_violation,
            existing.block_on_policy_violation
        );
        assert_eq!(m.proxy_scan_action, "record_only");
        let bad = UpsertScanConfigRequest {
            proxy_scan_action: Some("record-only".into()),
            ..Default::default()
        };
        assert!(matches!(
            merge_scan_config(&bad, Some(&existing)),
            Err(AppError::Validation(_))
        ));
    }

    /// #3645 / #3868: the record-only action overrides the threshold knobs;
    /// without it the knobs keep their #3243/#3246 meaning, including the
    /// #3868 reporter's `block_on_policy_violation = false` +
    /// `severity_threshold = critical`, which never opted into the threshold
    /// and so is block-on-any.
    #[test]
    fn test_proxy_severity_gate_for_row_precedence() {
        use crate::services::proxy_scan_service::ProxySeverityGate;
        for (block, threshold) in [(false, "critical"), (true, "critical"), (true, "info")] {
            assert_eq!(
                proxy_severity_gate_for_row(block, threshold, "record_only"),
                ProxySeverityGate::RecordOnly
            );
        }
        assert_eq!(
            proxy_severity_gate_for_row(false, "critical", "fail_open"),
            ProxySeverityGate::BlockOnAny
        );
        assert_eq!(
            proxy_severity_gate_for_row(true, "critical", "fail_closed"),
            ProxySeverityGate::Threshold(Severity::Critical)
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

    /// DB-backed round trip for the #2954 `proxy_scan_action` column: default
    /// when no config row exists, persist via `upsert_config`, read back via
    /// `proxy_scan_action` / `is_proxy_scan_enabled`, and preserve the stored
    /// value when a later patch omits the field (#1374 B11 semantics).
    /// Skips cleanly when DATABASE_URL is unset.
    #[tokio::test]
    async fn test_proxy_scan_action_db_default_upsert_and_patch_preserve() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let svc = ScanConfigService::new(fx.pool.clone());

        // No config row: action defaults to fail-open (today's behavior) and
        // scan-on-proxy reads disabled.
        assert_eq!(
            svc.proxy_scan_action(fx.repo_id).await.expect("action"),
            ProxyScanAction::FailOpen
        );
        assert!(!svc
            .is_proxy_scan_enabled(fx.repo_id)
            .await
            .expect("enabled"));

        // Upsert with fail_closed persists and round-trips.
        let req = UpsertScanConfigRequest {
            scan_enabled: Some(true),
            scan_on_upload: None,
            scan_on_proxy: Some(true),
            block_on_policy_violation: None,
            severity_threshold: None,
            proxy_scan_action: Some("fail_closed".to_string()),
        };
        let cfg = svc.upsert_config(fx.repo_id, &req).await.expect("upsert");
        assert_eq!(cfg.proxy_scan_action, "fail_closed");
        assert!(cfg.scan_on_proxy);
        assert_eq!(
            svc.proxy_scan_action(fx.repo_id).await.expect("action"),
            ProxyScanAction::FailClosed
        );
        assert!(svc
            .is_proxy_scan_enabled(fx.repo_id)
            .await
            .expect("enabled"));

        // A later patch that omits proxy_scan_action must PRESERVE the stored
        // fail_closed, not silently reset the security posture to fail-open.
        let patch = UpsertScanConfigRequest {
            scan_enabled: None,
            scan_on_upload: Some(true),
            scan_on_proxy: None,
            block_on_policy_violation: None,
            severity_threshold: None,
            proxy_scan_action: None,
        };
        let cfg = svc.upsert_config(fx.repo_id, &patch).await.expect("patch");
        assert_eq!(
            cfg.proxy_scan_action, "fail_closed",
            "an omitted proxy_scan_action must keep the existing value"
        );
        // get_config reads the column back too.
        let read = svc.get_config(fx.repo_id).await.expect("get").expect("row");
        assert_eq!(read.proxy_scan_action, "fail_closed");

        fx.teardown().await;
    }

    /// DB-backed round trip for the #3243/#3246 severity gate: absent row is
    /// block-on-any; the DEFAULT `severity_threshold = 'high'` stays inert
    /// while `block_on_policy_violation` (DEFAULT false) is off; opting in
    /// makes the stored threshold live. Skips cleanly when DATABASE_URL is
    /// unset.
    #[tokio::test]
    async fn test_proxy_severity_gate_db_requires_opt_in() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxySeverityGate;
        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let svc = ScanConfigService::new(fx.pool.clone());

        // No config row: block-on-any.
        assert_eq!(
            svc.proxy_severity_gate(fx.repo_id).await.expect("gate"),
            ProxySeverityGate::BlockOnAny
        );

        // A row created WITHOUT touching the toggle sits on the column
        // defaults (`block_on_policy_violation = false`,
        // `severity_threshold = 'high'`): the threshold must stay inert.
        let req = UpsertScanConfigRequest {
            scan_enabled: Some(true),
            scan_on_upload: None,
            scan_on_proxy: Some(true),
            block_on_policy_violation: None,
            severity_threshold: None,
            proxy_scan_action: None,
        };
        let cfg = svc.upsert_config(fx.repo_id, &req).await.expect("upsert");
        assert!(!cfg.block_on_policy_violation);
        assert_eq!(cfg.severity_threshold, "high");
        assert_eq!(
            svc.proxy_severity_gate(fx.repo_id).await.expect("gate"),
            ProxySeverityGate::BlockOnAny,
            "the defaulted 'high' threshold must NOT weaken the gate while \
             the opt-in is off (#3243's silent-default hazard)"
        );

        // Explicit opt-in makes the stored threshold live.
        let opt_in = UpsertScanConfigRequest {
            scan_enabled: None,
            scan_on_upload: None,
            scan_on_proxy: None,
            block_on_policy_violation: Some(true),
            severity_threshold: Some("medium".to_string()),
            proxy_scan_action: None,
        };
        svc.upsert_config(fx.repo_id, &opt_in)
            .await
            .expect("opt in");
        assert_eq!(
            svc.proxy_severity_gate(fx.repo_id).await.expect("gate"),
            ProxySeverityGate::Threshold(crate::models::security::Severity::Medium)
        );

        // Opting back out restores block-on-any while preserving the value.
        let opt_out = UpsertScanConfigRequest {
            scan_enabled: None,
            scan_on_upload: None,
            scan_on_proxy: None,
            block_on_policy_violation: Some(false),
            severity_threshold: None,
            proxy_scan_action: None,
        };
        let cfg = svc.upsert_config(fx.repo_id, &opt_out).await.expect("out");
        assert_eq!(cfg.severity_threshold, "medium");
        assert_eq!(
            svc.proxy_severity_gate(fx.repo_id).await.expect("gate"),
            ProxySeverityGate::BlockOnAny
        );

        fx.teardown().await;
    }
}
