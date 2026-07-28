//! Pluggable download-count ("popularity") data sources for the `popularity`
//! curation rule (#2949).
//!
//! The contract is deliberately narrow: given an ecosystem format and a
//! package name, return either a **known** download count for the recent
//! window or [`PopularityResult::Unknown`]. A source must NEVER fabricate a
//! count — any transport error, non-2xx status, unparseable body, timeout, or
//! unsupported ecosystem degrades to `Unknown`. The policy layer
//! ([`super::popularity::evaluate`]) maps `Unknown` to a *flag-for-review*
//! decision, never a hard block, so a data-source outage cannot break
//! legitimate installs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

/// Outcome of a download-count lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopularityResult {
    /// The source returned an authoritative recent download count.
    Known(u64),
    /// The count could not be determined (source outage, rate limit,
    /// unknown package, unsupported ecosystem). Callers must treat this as
    /// "no data", not "zero downloads".
    Unknown,
}

/// A provider of recent download counts for packages in an ecosystem.
#[async_trait]
pub trait PopularitySource: Send + Sync {
    /// Return the recent (last-month) download count for `name` in the
    /// ecosystem identified by `format` (e.g. `"pypi"`, `"npm"`), or
    /// [`PopularityResult::Unknown`] when no authoritative answer exists.
    async fn downloads(&self, format: &str, name: &str) -> PopularityResult;
}

/// Default total-request timeout for popularity lookups. These are small JSON
/// responses from public APIs; a short hard deadline keeps a slow upstream
/// from stalling curation evaluation.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Default TTL for cached `Known` results.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// TTL for cached `Unknown` results. Deliberately shorter than the positive
/// TTL: it shields an unavailable upstream from a request storm while still
/// retrying soon after an outage or a freshly published package.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Map a repository format (including registry-compatible aliases) to the
/// upstream download-count ecosystem it belongs to.
///
/// Returns `None` for formats without a public download-count API; the
/// evaluator treats those as not applicable rather than unpopular.
pub fn ecosystem_for_format(format: &str) -> Option<&'static str> {
    match format.to_ascii_lowercase().as_str() {
        // Poetry/conda repos serve packages published on PyPI.
        "pypi" | "poetry" => Some("pypi"),
        // Yarn and pnpm resolve against the npm registry.
        "npm" | "yarn" | "pnpm" => Some("npm"),
        _ => None,
    }
}

/// Real download-count source backed by public registry statistics APIs:
///
/// - **PyPI** → `GET https://pypistats.org/api/packages/{name}/recent`
///   (last-month total from the `data.last_month` field)
/// - **npm** → `GET https://api.npmjs.org/downloads/point/last-month/{name}`
///   (the `downloads` field)
///
/// All failures — timeouts, non-2xx (including 429 rate limiting), malformed
/// bodies — degrade to [`PopularityResult::Unknown`]. Wrap in
/// [`CachedPopularitySource`] (see [`HttpPopularitySource::cached`]) for
/// production use so repeated evaluations of the same package do not hammer
/// the public APIs.
pub struct HttpPopularitySource {
    client: reqwest::Client,
    pypistats_base: String,
    npm_base: String,
}

impl HttpPopularitySource {
    /// Build a source using the repo-standard SSRF-guarded HTTP client with a
    /// short total-request timeout.
    pub fn new() -> Self {
        let client = crate::services::http_client::base_client_builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(3))
            .build()
            .expect("failed to build popularity HTTP client");
        Self {
            client,
            pypistats_base: "https://pypistats.org".to_string(),
            npm_base: "https://api.npmjs.org".to_string(),
        }
    }

    /// Override the upstream base URLs (tests / air-gapped mirrors).
    pub fn with_base_urls(mut self, pypistats_base: &str, npm_base: &str) -> Self {
        self.pypistats_base = pypistats_base.trim_end_matches('/').to_string();
        self.npm_base = npm_base.trim_end_matches('/').to_string();
        self
    }

    /// Wrap this source in an in-memory TTL cache with the default TTL.
    pub fn cached(self) -> CachedPopularitySource<Self> {
        CachedPopularitySource::new(self, DEFAULT_CACHE_TTL)
    }

    async fn fetch_json(&self, url: &str) -> Option<serde_json::Value> {
        let resp = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(url, error = %e, "popularity lookup failed");
                return None;
            }
        };
        if !resp.status().is_success() {
            tracing::debug!(url, status = %resp.status(), "popularity lookup non-success");
            return None;
        }
        match resp.json::<serde_json::Value>().await {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::debug!(url, error = %e, "popularity response not valid JSON");
                None
            }
        }
    }
}

impl Default for HttpPopularitySource {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the last-month total from a pypistats.org `/recent` response body:
/// `{"data": {"last_day": .., "last_month": N, "last_week": ..}, ...}`.
pub fn parse_pypistats_recent(body: &serde_json::Value) -> PopularityResult {
    match body
        .get("data")
        .and_then(|d| d.get("last_month"))
        .and_then(serde_json::Value::as_u64)
    {
        Some(n) => PopularityResult::Known(n),
        None => PopularityResult::Unknown,
    }
}

/// Extract the download count from an npm point-downloads response body:
/// `{"downloads": N, "start": .., "end": .., "package": ..}`.
pub fn parse_npm_point(body: &serde_json::Value) -> PopularityResult {
    match body.get("downloads").and_then(serde_json::Value::as_u64) {
        Some(n) => PopularityResult::Known(n),
        None => PopularityResult::Unknown,
    }
}

/// Percent-encode a package name for safe use as a single path segment.
/// Keeps unreserved characters plus `@` untouched for readability of scoped
/// npm names in logs; encodes `/` (scoped-package separator) and everything
/// else that could alter the request path.
fn encode_path_segment(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[async_trait]
impl PopularitySource for HttpPopularitySource {
    async fn downloads(&self, format: &str, name: &str) -> PopularityResult {
        let Some(ecosystem) = ecosystem_for_format(format) else {
            return PopularityResult::Unknown;
        };
        match ecosystem {
            "pypi" => {
                // PEP 503 normalization: lowercase, runs of -_. become -.
                let normalized = normalize_pypi_name(name);
                let url = format!(
                    "{}/api/packages/{}/recent",
                    self.pypistats_base,
                    encode_path_segment(&normalized)
                );
                match self.fetch_json(&url).await {
                    Some(body) => parse_pypistats_recent(&body),
                    None => PopularityResult::Unknown,
                }
            }
            "npm" => {
                let url = format!(
                    "{}/downloads/point/last-month/{}",
                    self.npm_base,
                    encode_path_segment(name)
                );
                match self.fetch_json(&url).await {
                    Some(body) => parse_npm_point(&body),
                    None => PopularityResult::Unknown,
                }
            }
            _ => PopularityResult::Unknown,
        }
    }
}

/// Normalize a PyPI project name per PEP 503 (lowercase; runs of `-`, `_`,
/// `.` collapse to a single `-`), which is what pypistats.org expects.
pub fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// In-memory TTL cache decorator over any [`PopularitySource`].
///
/// `Known` results are cached for the configured TTL; `Unknown` results are
/// cached for the shorter [`NEGATIVE_CACHE_TTL`] so a source outage is not
/// amplified into a request storm but recovery is picked up quickly.
pub struct CachedPopularitySource<S: PopularitySource> {
    inner: S,
    ttl: Duration,
    cache: Mutex<HashMap<(String, String), (Instant, PopularityResult)>>,
}

impl<S: PopularitySource> CachedPopularitySource<S> {
    /// Wrap `inner` with a positive-result TTL of `ttl`.
    pub fn new(inner: S, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl<S: PopularitySource> PopularitySource for CachedPopularitySource<S> {
    async fn downloads(&self, format: &str, name: &str) -> PopularityResult {
        let key = (format.to_string(), name.to_string());
        if let Ok(cache) = self.cache.lock() {
            if let Some((at, result)) = cache.get(&key) {
                let ttl = match result {
                    PopularityResult::Known(_) => self.ttl,
                    PopularityResult::Unknown => NEGATIVE_CACHE_TTL.min(self.ttl),
                };
                if at.elapsed() < ttl {
                    return *result;
                }
            }
        }
        let result = self.inner.downloads(format, name).await;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, (Instant::now(), result));
        }
        result
    }
}

/// Deterministic in-memory test double. Returns `Known` for seeded
/// `(format, name)` pairs and `Unknown` otherwise, and counts lookups so
/// tests can assert caching behavior.
#[derive(Default)]
pub struct FakePopularitySource {
    counts: HashMap<(String, String), u64>,
    calls: AtomicUsize,
}

impl FakePopularitySource {
    /// Empty fake: every lookup returns `Unknown`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a known download count for `(format, name)`.
    pub fn with(mut self, format: &str, name: &str, downloads: u64) -> Self {
        self.counts
            .insert((format.to_string(), name.to_string()), downloads);
        self
    }

    /// Number of `downloads` calls made against this fake.
    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PopularitySource for FakePopularitySource {
    async fn downloads(&self, format: &str, name: &str) -> PopularityResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.counts.get(&(format.to_string(), name.to_string())) {
            Some(n) => PopularityResult::Known(*n),
            None => PopularityResult::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pypistats_recent_body() {
        let body = serde_json::json!({
            "data": {"last_day": 100, "last_month": 12345, "last_week": 900},
            "package": "requests",
            "type": "recent_downloads"
        });
        assert_eq!(
            parse_pypistats_recent(&body),
            PopularityResult::Known(12345)
        );
    }

    #[test]
    fn parses_npm_point_body() {
        let body = serde_json::json!({
            "downloads": 987654,
            "start": "2026-06-01",
            "end": "2026-06-30",
            "package": "lodash"
        });
        assert_eq!(parse_npm_point(&body), PopularityResult::Known(987654));
    }

    #[test]
    fn malformed_bodies_degrade_to_unknown() {
        assert_eq!(
            parse_pypistats_recent(&serde_json::json!({"error": "not found"})),
            PopularityResult::Unknown
        );
        assert_eq!(
            parse_npm_point(&serde_json::json!({"error": "package not found"})),
            PopularityResult::Unknown
        );
        // Negative / non-integer counts are not trusted.
        assert_eq!(
            parse_npm_point(&serde_json::json!({"downloads": -5})),
            PopularityResult::Unknown
        );
    }

    #[test]
    fn ecosystem_mapping_covers_aliases_and_rejects_others() {
        assert_eq!(ecosystem_for_format("pypi"), Some("pypi"));
        assert_eq!(ecosystem_for_format("poetry"), Some("pypi"));
        assert_eq!(ecosystem_for_format("npm"), Some("npm"));
        assert_eq!(ecosystem_for_format("yarn"), Some("npm"));
        assert_eq!(ecosystem_for_format("pnpm"), Some("npm"));
        assert_eq!(ecosystem_for_format("NPM"), Some("npm"));
        assert_eq!(ecosystem_for_format("generic"), None);
        assert_eq!(ecosystem_for_format("docker"), None);
        assert_eq!(ecosystem_for_format("maven"), None);
    }

    #[test]
    fn pypi_name_normalization_is_pep503() {
        assert_eq!(normalize_pypi_name("Django"), "django");
        assert_eq!(
            normalize_pypi_name("typing_extensions"),
            "typing-extensions"
        );
        assert_eq!(normalize_pypi_name("zope.interface"), "zope-interface");
        assert_eq!(normalize_pypi_name("a--b__c"), "a-b-c");
    }

    #[test]
    fn path_segment_encoding_escapes_separators() {
        assert_eq!(encode_path_segment("@scope/pkg"), "@scope%2Fpkg");
        assert_eq!(encode_path_segment("simple-name"), "simple-name");
        assert_eq!(encode_path_segment("a b"), "a%20b");
    }

    #[tokio::test]
    async fn fake_source_returns_seeded_counts_and_unknown() {
        let fake = FakePopularitySource::new().with("pypi", "requests", 1_000_000);
        assert_eq!(
            fake.downloads("pypi", "requests").await,
            PopularityResult::Known(1_000_000)
        );
        assert_eq!(
            fake.downloads("pypi", "not-seeded").await,
            PopularityResult::Unknown
        );
        assert_eq!(fake.call_count(), 2);
    }

    #[tokio::test]
    async fn cache_serves_repeat_lookups_without_inner_calls() {
        let fake = FakePopularitySource::new().with("npm", "lodash", 50_000_000);
        let cached = CachedPopularitySource::new(fake, Duration::from_secs(60));
        assert_eq!(
            cached.downloads("npm", "lodash").await,
            PopularityResult::Known(50_000_000)
        );
        assert_eq!(
            cached.downloads("npm", "lodash").await,
            PopularityResult::Known(50_000_000)
        );
        assert_eq!(cached.inner.call_count(), 1);
    }

    #[tokio::test]
    async fn cache_expires_after_ttl() {
        let fake = FakePopularitySource::new().with("npm", "react", 40_000_000);
        let cached = CachedPopularitySource::new(fake, Duration::from_millis(10));
        assert_eq!(
            cached.downloads("npm", "react").await,
            PopularityResult::Known(40_000_000)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            cached.downloads("npm", "react").await,
            PopularityResult::Known(40_000_000)
        );
        assert_eq!(cached.inner.call_count(), 2);
    }

    #[tokio::test]
    async fn unknown_results_are_negatively_cached_within_short_ttl() {
        let fake = FakePopularitySource::new();
        // Positive TTL shorter than NEGATIVE_CACHE_TTL: min() applies, so the
        // Unknown entry is still fresh on the second lookup.
        let cached = CachedPopularitySource::new(fake, Duration::from_secs(30));
        assert_eq!(
            cached.downloads("pypi", "ghost-pkg").await,
            PopularityResult::Unknown
        );
        assert_eq!(
            cached.downloads("pypi", "ghost-pkg").await,
            PopularityResult::Unknown
        );
        assert_eq!(cached.inner.call_count(), 1);
    }

    #[tokio::test]
    async fn http_source_unsupported_format_is_unknown_without_network() {
        // No network I/O happens for a format outside the ecosystem map.
        let source =
            HttpPopularitySource::new().with_base_urls("http://127.0.0.1:1", "http://127.0.0.1:1");
        assert_eq!(
            source.downloads("generic", "whatever").await,
            PopularityResult::Unknown
        );
    }

    #[tokio::test]
    async fn http_source_degrades_to_unknown_on_connection_error() {
        // Unroutable base URL: the request errors and the source degrades.
        let source =
            HttpPopularitySource::new().with_base_urls("http://127.0.0.1:1", "http://127.0.0.1:1");
        assert_eq!(
            source.downloads("pypi", "requests").await,
            PopularityResult::Unknown
        );
        assert_eq!(
            source.downloads("npm", "lodash").await,
            PopularityResult::Unknown
        );
    }
}
