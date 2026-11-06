//! Per-Remote upstream mode: a declared cache-only (offline) mode (#5282).
//!
//! An operator who seeded a Remote and then disconnected the instance can
//! declare the Remote `cache_only`:
//!
//! * the upstream is never contacted: the shared upstream gate
//!   ([`crate::services::upstream_filter::ensure_upstream_allowed`], which
//!   `ProxyService::gated_upstream_url` and every caller outside the proxy
//!   service go through) refuses with [`AppError::NotFound`] before any
//!   request is built;
//! * a cached entry is served whether it is fresh or not, without
//!   revalidation (a stale serve carries `X-AK-Stale-Since`);
//! * a miss is a 404 whose reason names the mode, distinct from the upstream
//!   filter's refusal.
//!
//! [`UpstreamMode::Online`] is the default and the behaviour of every release
//! before #5282.
//!
//! The value is stored as one `repository_config` row
//! (`key = 'upstream_mode'`), like `on_upstream_not_found` (#4640), so no
//! migration is required and an unset row means the default. The instance-wide
//! `PROXY_UPSTREAM_MODE=cache_only` environment variable puts every Remote in
//! cache-only mode regardless of its row.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use moka::future::Cache as MokaCache;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Whether a `Remote` repository may contact its upstream (#5282).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamMode {
    /// Normal pull-through proxying. The default.
    #[default]
    Online,
    /// Serve only what is cached, fresh or stale; never contact upstream. A
    /// miss is a 404 naming the mode.
    CacheOnly,
}

impl UpstreamMode {
    /// The `repository_config.key` this mode is stored under.
    pub const CONFIG_KEY: &'static str = "upstream_mode";

    /// Environment variable that forces every Remote into a mode.
    pub const ENV_OVERRIDE: &'static str = "PROXY_UPSTREAM_MODE";

    /// Canonical spelling, as stored and on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::CacheOnly => "cache_only",
        }
    }

    /// Parse the stored/wire spelling. A blank, missing or unrecognized value
    /// is the default (`online`), like [`crate::services::upstream_not_found_policy::OnUpstreamNotFound::parse`].
    /// `cache-only` is accepted as an alias of `cache_only`.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            Some(value)
                if value.eq_ignore_ascii_case(Self::CacheOnly.as_str())
                    || value.eq_ignore_ascii_case("cache-only") =>
            {
                Self::CacheOnly
            }
            _ => Self::Online,
        }
    }

    /// Whether the upstream must not be contacted.
    pub const fn is_cache_only(self) -> bool {
        matches!(self, Self::CacheOnly)
    }
}

/// The instance-wide override, read once per process. `Online` (or unset)
/// means "use each repository's own row".
static ENV_MODE: Lazy<UpstreamMode> = Lazy::new(|| {
    let mode = UpstreamMode::parse(std::env::var(UpstreamMode::ENV_OVERRIDE).ok().as_deref());
    if mode.is_cache_only() {
        tracing::warn!(
            "{}=cache_only: every Remote repository serves from its cache only and never \
             contacts its upstream",
            UpstreamMode::ENV_OVERRIDE
        );
    }
    mode
});

/// Whether the instance-wide override forces cache-only mode.
pub fn instance_forces_cache_only() -> bool {
    ENV_MODE.is_cache_only()
}

/// How long a looked-up mode is reused. The writer invalidates its own replica
/// at once (and the others through the `upstream_filter_changed` event); this
/// bounds convergence if that notification is lost.
const MODE_CACHE_TTL: Duration = Duration::from_secs(30);
const MODE_CACHE_CAPACITY: u64 = 10_000;

static MODE_CACHE: Lazy<MokaCache<Uuid, UpstreamMode>> = Lazy::new(|| {
    MokaCache::builder()
        .max_capacity(MODE_CACHE_CAPACITY)
        .time_to_live(MODE_CACHE_TTL)
        .build()
});

/// Bumped on every invalidation, so a read that raced a write never
/// re-inserts the pre-write mode (same scheme as the upstream filter cache).
static MODE_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Drop this process's cached mode for `repo_id`.
pub async fn invalidate_cached_mode(repo_id: Uuid) {
    MODE_GENERATION.fetch_add(1, Ordering::SeqCst);
    MODE_CACHE.invalidate(&repo_id).await;
}

/// The repository's stored mode, ignoring the instance override. An absent or
/// unrecognized row is `online`; a database error is returned, never cached.
pub async fn stored_upstream_mode(db: &PgPool, repo_id: Uuid) -> Result<UpstreamMode> {
    if let Some(hit) = MODE_CACHE.get(&repo_id).await {
        return Ok(hit);
    }
    let generation = MODE_GENERATION.load(Ordering::SeqCst);
    let raw = sqlx::query_scalar::<_, String>(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(UpstreamMode::CONFIG_KEY)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    let mode = UpstreamMode::parse(raw.as_deref());
    if MODE_GENERATION.load(Ordering::SeqCst) == generation {
        MODE_CACHE.insert(repo_id, mode).await;
    }
    Ok(mode)
}

/// The mode the proxy enforces for `repo_id`: cache-only when the instance
/// override says so, else the stored row.
pub async fn effective_upstream_mode(db: &PgPool, repo_id: Uuid) -> Result<UpstreamMode> {
    if instance_forces_cache_only() {
        return Ok(UpstreamMode::CacheOnly);
    }
    stored_upstream_mode(db, repo_id).await
}

/// Persist `mode` for `repo_id` and invalidate the cached copy here and,
/// through the shared upstream-gate event, on every other replica.
pub async fn save_upstream_mode(db: &PgPool, repo_id: Uuid, mode: UpstreamMode) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO repository_config (repository_id, key, value)
        VALUES ($1, $2, $3)
        ON CONFLICT (repository_id, key)
        DO UPDATE SET value = $3, updated_at = NOW()
        "#,
    )
    .bind(repo_id)
    .bind(UpstreamMode::CONFIG_KEY)
    .bind(mode.as_str())
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    invalidate_cached_mode(repo_id).await;
    crate::services::cache_invalidation::notify_upstream_filter_changed(db, repo_id).await;
    Ok(())
}

/// Text that ends every cache-only refusal, so [`is_cache_only_refusal`] can
/// tell it apart from the upstream filter's refusal and from an upstream 404.
const CACHE_ONLY_REASON: &str = "is cache-only";

/// The `NotFound` a cache-only Remote answers for a path it does not hold.
pub fn cache_only_miss(repo_key: &str) -> AppError {
    AppError::NotFound(format!(
        "not in cache; repository '{repo_key}' {CACHE_ONLY_REASON}"
    ))
}

/// Whether `err` is a [`cache_only_miss`].
pub fn is_cache_only_refusal(err: &AppError) -> bool {
    matches!(err, AppError::NotFound(msg) if msg.ends_with(CACHE_ONLY_REASON))
}

/// Refuse upstream contact for a cache-only Remote (#5282). Called first by the
/// shared upstream gate, so every upstream contact inherits it.
pub async fn ensure_upstream_contact_allowed(
    db: &PgPool,
    repo_id: Uuid,
    repo_key: &str,
) -> Result<()> {
    if effective_upstream_mode(db, repo_id).await?.is_cache_only() {
        tracing::debug!(
            repository_id = %repo_id,
            repo_key = %repo_key,
            "upstream fetch refused: repository is cache-only"
        );
        return Err(cache_only_miss(repo_key));
    }
    Ok(())
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_online() {
        assert_eq!(UpstreamMode::default(), UpstreamMode::Online);
        assert!(!UpstreamMode::default().is_cache_only());
    }

    #[test]
    fn parse_recognizes_cache_only_spellings() {
        for raw in ["cache_only", "CACHE_ONLY", " cache_only ", "cache-only"] {
            assert_eq!(
                UpstreamMode::parse(Some(raw)),
                UpstreamMode::CacheOnly,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn parse_degrades_unknown_and_absent_to_online() {
        for raw in [None, Some(""), Some("  "), Some("online"), Some("offline")] {
            assert_eq!(UpstreamMode::parse(raw), UpstreamMode::Online, "{raw:?}");
        }
    }

    #[test]
    fn as_str_round_trips_and_serde_uses_snake_case() {
        for mode in [UpstreamMode::Online, UpstreamMode::CacheOnly] {
            assert_eq!(UpstreamMode::parse(Some(mode.as_str())), mode);
            assert_eq!(
                serde_json::to_string(&mode).unwrap(),
                format!("\"{}\"", mode.as_str())
            );
        }
        assert_eq!(
            serde_json::from_str::<UpstreamMode>("\"cache_only\"").unwrap(),
            UpstreamMode::CacheOnly
        );
        assert!(serde_json::from_str::<UpstreamMode>("\"offline\"").is_err());
    }

    #[test]
    fn cache_only_miss_is_recognized_and_distinct_from_other_not_founds() {
        let err = cache_only_miss("maven-remote");
        assert!(is_cache_only_refusal(&err));
        assert!(
            err.to_string()
                .contains("repository 'maven-remote' is cache-only"),
            "{err}"
        );
        for other in [
            AppError::NotFound(
                "path excluded by the upstream filter of repository 'maven-remote'".into(),
            ),
            AppError::NotFound("Upstream returned 404 (negative-cached) for x".into()),
            AppError::Validation("is cache-only".into()),
        ] {
            assert!(!is_cache_only_refusal(&other), "{other:?}");
        }
    }
}
