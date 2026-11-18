//! Instance-wide quotas: storage, monthly download transfer, upload size.
//!
//! An operator who runs the registry on metered object storage or behind
//! metered egress needs a hard ceiling on what the instance stores and
//! serves. Three limits give it one, each optional and off by default
//! ([`crate::config::QuotaSettings`]):
//!
//! * **Storage** ([`storage`], `STORAGE_QUOTA_BYTES`): the total bytes the
//!   instance stores, read from the same usage ledger as
//!   `GET /api/v1/admin/stats` `total_storage_bytes`. At the quota the
//!   instance is read-only for writes: every request that would store new
//!   bytes is refused with `403 STORAGE_QUOTA_EXCEEDED`, before its body is
//!   read when it declares a `Content-Length` ([`http::upload_admission`]) and
//!   by the shared publish admission once its size is known
//!   ([`crate::api::handlers::publish_quota`]). Downloads, deletes, listing,
//!   sign-in and settings are never refused, and a delete frees its bytes at
//!   once. A remote (proxy) repository keeps serving upstream content at the
//!   quota; it only stops caching it.
//! * **Transfer** ([`transfer`], `TRANSFER_QUOTA_BYTES`): artifact download
//!   bytes per calendar month (UTC), counted on the bytes actually sent and
//!   kept in Postgres so every replica and restart shares one counter. Above
//!   the quota downloads keep working through the grace band
//!   (`TRANSFER_QUOTA_GRACE_PERCENT`); at the hard limit artifact downloads
//!   answer `429 TRANSFER_QUOTA_EXCEEDED` with `Retry-After` until the next
//!   month. Uploads, deletes, the API and the UI keep working.
//! * **Upload size** (`MAX_UPLOAD_SIZE`): one request larger than the limit
//!   is refused with `413 PAYLOAD_TOO_LARGE`, on its `Content-Length` before
//!   the body is read, and by counting for a body without one.
//!
//! Every refusal is a 4xx with a JSON body ([`QuotaRefusal`]); none is a 5xx,
//! which clients would retry and monitoring would read as a server fault.
//! A per-repository or per-project quota refusal answers `403 QUOTA_EXCEEDED`
//! with the same extra fields.

pub mod http;
pub mod refusal;
#[cfg(ak_test_shard = "router")]
#[cfg(test)]
mod router_tests;
pub mod storage;
pub mod transfer;

pub use refusal::{QuotaRefusal, RefusalKind};
pub use storage::StorageQuotaStatus;
pub use transfer::{TransferMeter, TransferQuotaStatus};

use serde::Serialize;
use utoipa::ToSchema;

/// The quota figures `GET /api/v1/system/quota` answers and
/// `GET /api/v1/admin/stats` embeds.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct QuotaOverview {
    pub storage_quota: StorageQuotaStatus,
    pub transfer_quota: TransferQuotaStatus,
    /// `MAX_UPLOAD_SIZE` in bytes; `0` means no limit.
    pub max_upload_bytes: u64,
    /// `QUOTA_HELP_URL`, when configured.
    pub quota_help_url: Option<String>,
}

impl QuotaOverview {
    /// Current figures for this instance.
    pub async fn collect(state: &crate::api::AppState) -> crate::error::Result<Self> {
        Ok(Self {
            storage_quota: storage::status(&state.db).await?,
            transfer_quota: state.transfer_meter.status().await,
            max_upload_bytes: state.config.max_upload_size_bytes,
            quota_help_url: state.config.quotas.help_url.clone(),
        })
    }
}

/// `part / whole` as a percentage with two decimals, `None` for an unset
/// (zero) whole.
pub(crate) fn percent(part: u64, whole: u64) -> Option<f64> {
    if whole == 0 {
        return None;
    }
    Some(((part as f64 / whole as f64) * 10_000.0).round() / 100.0)
}

/// Bytes for a message: binary units with one decimal (`10.0 GiB`), so the
/// figures match how the limits are configured.
pub(crate) fn format_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (unit, size) in UNITS {
        if bytes >= size {
            return format!("{:.1} {unit}", bytes as f64 / size as f64);
        }
    }
    if bytes == 1 {
        "1 byte".to_string()
    } else {
        format!("{bytes} bytes")
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_formatted_in_binary_units() {
        assert_eq!(format_bytes(0), "0 bytes");
        assert_eq!(format_bytes(1), "1 byte");
        assert_eq!(format_bytes(1023), "1023 bytes");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(10 * (1 << 30)), "10.0 GiB");
        assert_eq!(format_bytes(1536 * (1 << 20)), "1.5 GiB");
        assert_eq!(format_bytes(2 * (1 << 40)), "2.0 TiB");
    }

    #[test]
    fn percent_rounds_to_two_decimals_and_is_none_without_a_quota() {
        assert_eq!(percent(1, 0), None);
        assert_eq!(percent(0, 100), Some(0.0));
        assert_eq!(percent(80, 100), Some(80.0));
        assert_eq!(percent(1, 3), Some(33.33));
        assert_eq!(percent(250, 200), Some(125.0));
    }
}
