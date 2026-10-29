//! A process-wide byte budget: one semaphore bounding the TOTAL bytes a class
//! of buffered reads may hold resident at once, however many requests run
//! (#2665).
//!
//! It began as the buffered proxy-metadata budget in
//! `api::handlers::proxy_helpers`, which still exports it as
//! `ProxyMetadataBudget`. It lives here so the storage layer can bound its
//! serve-time verification buffer with the same type (#4989) without
//! depending on the API layer.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Accounting granularity of every [`ByteBudget`]: the semaphore counts one
/// permit per 4 KiB, and a reservation is rounded UP to whole units (#4881).
/// Counting bytes made the permit count bounded by the `u32` that
/// `acquire_many` takes, which silently clamped any budget above 4 GiB. In
/// 4 KiB units the semaphore can hold a budget as large as `usize` can
/// express, and one reservation can hold up to 16 TiB.
pub const BYTE_BUDGET_UNIT_BYTES: usize = 4 * 1024;

/// Largest budget [`ByteBudget`] can represent: tokio's permit ceiling in
/// [`BYTE_BUDGET_UNIT_BYTES`] units, which on a 64-bit target saturates at
/// `usize::MAX`.
pub const MAX_BYTE_BUDGET_BYTES: usize =
    Semaphore::MAX_PERMITS.saturating_mul(BYTE_BUDGET_UNIT_BYTES);

/// Whole budget units covering `bytes`, rounded up.
fn budget_units(bytes: usize) -> usize {
    bytes.div_ceil(BYTE_BUDGET_UNIT_BYTES)
}

/// A byte budget: reservations draw on one shared total, accounted in
/// [`BYTE_BUDGET_UNIT_BYTES`] units, and each reservation's permit gives its
/// bytes back when dropped, so hold it for as long as the bytes it accounts
/// for are resident. The total is fixed at construction.
pub struct ByteBudget {
    sem: Arc<Semaphore>,
    total: usize,
}

impl ByteBudget {
    /// Build a budget of `total_bytes`, clamped to
    /// `[1, MAX_BYTE_BUDGET_BYTES]`. The semaphore holds the total
    /// in [`BYTE_BUDGET_UNIT_BYTES`] units, rounded up, so the
    /// byte-facing methods keep byte semantics while the permit count stays
    /// inside tokio's limits for any budget (#4881).
    pub fn new(total_bytes: usize) -> Self {
        let total = total_bytes.clamp(1, MAX_BYTE_BUDGET_BYTES);
        Self {
            sem: Arc::new(Semaphore::new(budget_units(total))),
            total,
        }
    }

    /// Total budget in bytes.
    pub fn total_bytes(&self) -> usize {
        self.total
    }

    /// Currently unreserved bytes (observability / test helper). Counted in
    /// whole units, so never more than [`Self::total_bytes`].
    pub fn available_bytes(&self) -> usize {
        self.sem
            .available_permits()
            .saturating_mul(BYTE_BUDGET_UNIT_BYTES)
            .min(self.total)
    }

    fn permits_for(&self, bytes: usize) -> u32 {
        // A single request can reserve at most the whole budget, so an oversized
        // request degrades to "hold the whole budget" rather than deadlocking on
        // a permit count the semaphore can never satisfy. One `acquire_many`
        // takes at most `u32::MAX` units (16 TiB); a budget larger than that
        // still satisfies such a request, it just leaves the rest free.
        let ceiling = budget_units(self.total).min(u32::MAX as usize);
        budget_units(bytes).clamp(1, ceiling) as u32
    }

    /// Reserve `bytes` of the budget, awaiting when it is exhausted. The
    /// returned permit releases the reservation on drop — hold it for as long
    /// as the buffered bytes are resident.
    pub async fn reserve(&self, bytes: usize) -> OwnedSemaphorePermit {
        // `acquire_many_owned` only errors when the semaphore is closed; this
        // one lives for the process lifetime and is never closed.
        Arc::clone(&self.sem)
            .acquire_many_owned(self.permits_for(bytes))
            .await
            .expect("byte budget semaphore is never closed")
    }

    /// Non-blocking reservation: `None` when the budget cannot currently satisfy
    /// `bytes`. For a caller that must never wait on the budget (the serve-time
    /// verification buffer, #4989, falls back to streaming instead), and to
    /// prove the bound rejects once exhausted.
    pub fn try_reserve(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.sem)
            .try_acquire_many_owned(self.permits_for(bytes))
            .ok()
    }
}

/// Resolve a byte-budget environment override to the effective budget in
/// bytes, plus why the configured value was not taken as is (#4881): `None`
/// when it was unset or used verbatim, otherwise a reason fit for a warning.
/// A blank, non-numeric or zero value falls back to `default`; a value past
/// [`MAX_BYTE_BUDGET_BYTES`] is clamped to it.
pub fn resolve_budget_bytes(
    configured: Option<&str>,
    default: usize,
) -> (usize, Option<&'static str>) {
    let Some(raw) = configured else {
        return (default, None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return (default, Some("is blank, falling back to the default"));
    }
    // Parse wide so a value past `usize` is reported as clamped, not as junk.
    match raw.parse::<u128>() {
        Err(_) => (
            default,
            Some("is not a byte count, falling back to the default"),
        ),
        Ok(0) => (default, Some("is zero, falling back to the default")),
        Ok(v) if v > MAX_BYTE_BUDGET_BYTES as u128 => (
            MAX_BYTE_BUDGET_BYTES,
            Some("exceeds the largest representable budget, clamping"),
        ),
        Ok(v) => (v as usize, None),
    }
}

/// The budget the environment variable `env` sizes, under the
/// [`resolve_budget_bytes`] rules with `default`. A configured value that is
/// not taken as is logs a warning naming the variable and the configured and
/// effective values (#4881).
pub fn budget_from_env(env: &'static str, default: usize) -> ByteBudget {
    let configured = std::env::var(env).ok();
    let (total, adjustment) = resolve_budget_bytes(configured.as_deref(), default);
    if let Some(reason) = adjustment {
        tracing::warn!(
            env,
            configured = configured.as_deref().unwrap_or_default(),
            effective_bytes = total,
            max_bytes = MAX_BYTE_BUDGET_BYTES,
            "{env} {reason}; using {total} bytes"
        );
    }
    ByteBudget::new(total)
}
