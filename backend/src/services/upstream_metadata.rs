//! Upstream publish-time metadata for age-gate decisions.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDateTime, Utc};
use reqwest::Client;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::http_client;

const PYPI_CACHE_TTL: Duration = Duration::from_secs(60);

/// Hard ceiling on distinct `(repository, project)` publish-time entries held
/// in process. Each entry is small (one version->timestamp map), but the key
/// space is attacker-influenced — any project name requested through an
/// age-gated repo creates one — so growth must be bounded (#1607 lesson).
/// At the cap, expired entries are dropped first; if everything is somehow
/// still fresh, the map is cleared: a rare burst of cache misses is cheaper
/// than unbounded memory.
const PYPI_CACHE_MAX_ENTRIES: usize = 4096;

type PublishTimeMap = HashMap<String, DateTime<Utc>>;

#[derive(Clone)]
struct CacheEntry {
    times: PublishTimeMap,
    fetched_at: Instant,
}

/// In-process cache for PyPI Warehouse JSON publish times.
#[derive(Default)]
pub struct UpstreamMetadataCache {
    pypi: RwLock<HashMap<(Uuid, String), CacheEntry>>,
}

impl UpstreamMetadataCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse npm packument JSON `time` map into version -> published_at.
    pub fn parse_npm_publish_times(packument: &serde_json::Value) -> PublishTimeMap {
        let mut map = PublishTimeMap::new();
        let Some(time_obj) = packument.get("time").and_then(|t| t.as_object()) else {
            return map;
        };
        for (version, ts) in time_obj {
            if version == "created" || version == "modified" {
                continue;
            }
            if let Some(parsed) = parse_iso_timestamp(ts) {
                map.insert(version.clone(), parsed);
            }
        }
        map
    }

    /// Fetch PyPI Warehouse JSON and extract upload times per version.
    pub async fn fetch_pypi_publish_times(
        &self,
        client: &Client,
        repo_id: Uuid,
        upstream_url: &str,
        project: &str,
    ) -> Result<PublishTimeMap> {
        let cache_key = pypi_cache_key(repo_id, project);
        if let Some(cached) = self.get_pypi_cached(&cache_key) {
            return Ok(cached);
        }

        let url = pypi_json_url(upstream_url, project);
        let response = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| AppError::BadGateway(format!("PyPI metadata fetch failed: {e}")))?;

        if !response.status().is_success() {
            return Err(AppError::BadGateway(format!(
                "PyPI metadata fetch returned {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::BadGateway(format!("PyPI metadata parse failed: {e}")))?;

        let times = parse_pypi_releases_json(&body);
        self.set_pypi_cached(cache_key, times.clone());
        Ok(times)
    }

    fn get_pypi_cached(&self, key: &(Uuid, String)) -> Option<PublishTimeMap> {
        let guard = self.pypi.read().ok()?;
        let entry = guard.get(key)?;
        if is_pypi_cache_fresh(entry.fetched_at.elapsed(), PYPI_CACHE_TTL) {
            Some(entry.times.clone())
        } else {
            None
        }
    }

    fn set_pypi_cached(&self, key: (Uuid, String), times: PublishTimeMap) {
        if let Ok(mut guard) = self.pypi.write() {
            if guard.len() >= PYPI_CACHE_MAX_ENTRIES {
                guard.retain(|_, entry| {
                    is_pypi_cache_fresh(entry.fetched_at.elapsed(), PYPI_CACHE_TTL)
                });
                if guard.len() >= PYPI_CACHE_MAX_ENTRIES {
                    guard.clear();
                }
            }
            guard.insert(
                key,
                CacheEntry {
                    times,
                    fetched_at: Instant::now(),
                },
            );
        }
    }
}

/// Shared HTTP client for upstream metadata fetches.
pub fn metadata_http_client() -> Result<Client> {
    http_client::base_client_builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AppError::Internal(format!("HTTP client build failed: {e}")))
}

fn pypi_cache_key(repo_id: Uuid, project: &str) -> (Uuid, String) {
    (repo_id, project.to_ascii_lowercase())
}

fn is_pypi_cache_fresh(elapsed: Duration, ttl: Duration) -> bool {
    elapsed <= ttl
}

/// Build the PyPI Warehouse JSON URL from a simple-index upstream base.
pub fn pypi_json_url(upstream_url: &str, project: &str) -> String {
    let mut base = upstream_url.trim_end_matches('/');
    if let Some(stripped) = base.strip_suffix("/simple") {
        base = stripped;
    }
    format!("{base}/pypi/{project}/json")
}

/// Parse PyPI Warehouse `releases` JSON into version -> earliest upload time.
pub fn parse_pypi_releases_json(body: &serde_json::Value) -> PublishTimeMap {
    let mut map = PublishTimeMap::new();
    let Some(releases) = body.get("releases").and_then(|r| r.as_object()) else {
        return map;
    };
    for (version, files) in releases {
        let Some(arr) = files.as_array() else {
            continue;
        };
        let mut earliest: Option<DateTime<Utc>> = None;
        for file in arr {
            let ts = file
                .get("upload_time_iso_8601")
                .or_else(|| file.get("upload_time"))
                .and_then(parse_iso_timestamp);
            if let Some(parsed) = ts {
                earliest = Some(match earliest {
                    Some(existing) if existing <= parsed => existing,
                    _ => parsed,
                });
            }
        }
        if let Some(ts) = earliest {
            map.insert(version.clone(), ts);
        }
    }
    map
}

pub(crate) fn parse_iso_timestamp(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    let s = value.as_str()?;
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Fallback for offset-less ISO 8601 timestamps such as PyPI's `upload_time`
    // ("2024-07-01T12:00:00"): parse as naive and assume UTC. Parsing into a
    // fixed-offset `DateTime` can never succeed without a zone in the format string,
    // so a naive parse is required to avoid failing closed on these values.
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|naive| naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_npm_publish_times_skips_meta_keys() {
        let packument = json!({
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "1.0.0": "2024-06-01T12:00:00.000Z",
                "2.0.0": "2024-07-01T12:00:00.000Z"
            }
        });
        let times = UpstreamMetadataCache::parse_npm_publish_times(&packument);
        assert_eq!(times.len(), 2);
        assert!(times.contains_key("1.0.0"));
        assert!(times.contains_key("2.0.0"));
    }

    #[test]
    fn parse_pypi_releases_json_extracts_upload_time() {
        let body = json!({
            "releases": {
                "1.0.0": [{
                    "upload_time_iso_8601": "2024-06-01T12:00:00.000Z"
                }],
                "2.0.0": [{
                    "upload_time": "2024-07-01T12:00:00.000Z"
                }]
            }
        });
        let times = parse_pypi_releases_json(&body);
        assert_eq!(times.len(), 2);
    }

    #[test]
    fn pypi_json_url_strips_simple_suffix() {
        assert_eq!(
            pypi_json_url("https://pypi.org/simple", "requests"),
            "https://pypi.org/pypi/requests/json"
        );
        assert_eq!(
            pypi_json_url("https://pypi.org/simple/", "requests"),
            "https://pypi.org/pypi/requests/json"
        );
    }

    #[test]
    fn parse_iso_timestamp_handles_rfc3339_and_offsetless() {
        // RFC3339 with explicit zone.
        assert!(parse_iso_timestamp(&json!("2024-07-01T12:00:00.000Z")).is_some());
        // Offset-less ISO 8601 (PyPI `upload_time`) must parse as UTC, not fail closed.
        let parsed = parse_iso_timestamp(&json!("2024-07-01T12:00:00"))
            .expect("offset-less timestamp should parse");
        assert_eq!(parsed.to_rfc3339(), "2024-07-01T12:00:00+00:00");
        // Non-timestamps stay None.
        assert!(parse_iso_timestamp(&json!("not-a-date")).is_none());
        assert!(parse_iso_timestamp(&json!(12345)).is_none());
    }

    #[test]
    fn parse_npm_publish_times_missing_time_is_empty() {
        assert!(UpstreamMetadataCache::parse_npm_publish_times(&json!({})).is_empty());
    }

    #[test]
    fn parse_pypi_releases_json_earliest_wins() {
        let body = json!({
            "releases": {
                "1.0.0": [
                    { "upload_time_iso_8601": "2024-07-02T12:00:00.000Z" },
                    { "upload_time_iso_8601": "2024-06-01T12:00:00.000Z" }
                ]
            }
        });
        let times = parse_pypi_releases_json(&body);
        let ts = times.get("1.0.0").unwrap();
        // Earliest of the two files wins; `to_rfc3339` renders zero-fraction UTC
        // as `+00:00` (see `parse_iso_timestamp_handles_rfc3339_and_offsetless`).
        assert_eq!(ts.to_rfc3339(), "2024-06-01T12:00:00+00:00");
    }

    #[test]
    fn parse_pypi_releases_json_handles_missing_and_malformed() {
        // Body without a `releases` object yields no publish times.
        assert!(parse_pypi_releases_json(&json!({})).is_empty());
        // A release whose file list is not an array is skipped, not panicked on.
        let body = json!({ "releases": { "1.0.0": "not-an-array" } });
        assert!(parse_pypi_releases_json(&body).is_empty());
    }

    #[test]
    fn pypi_cache_key_lowercases_project() {
        let id = Uuid::new_v4();
        assert_eq!(pypi_cache_key(id, "Requests"), (id, "requests".to_string()));
    }

    #[test]
    fn is_pypi_cache_fresh_boundary() {
        assert!(is_pypi_cache_fresh(
            Duration::from_secs(30),
            Duration::from_secs(60)
        ));
        assert!(!is_pypi_cache_fresh(
            Duration::from_secs(61),
            Duration::from_secs(60)
        ));
    }

    #[tokio::test]
    async fn fetch_pypi_publish_times_fetches_and_reuses_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/demo/json"))
            .and(header("Accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "releases": {
                    "1.0.0": [
                        { "upload_time_iso_8601": "2024-01-02T00:00:00.000Z" },
                        { "upload_time_iso_8601": "2024-01-01T00:00:00.000Z" }
                    ]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cache = UpstreamMetadataCache::new();
        let client = reqwest::Client::new();
        let repo_id = Uuid::new_v4();
        let first = cache
            .fetch_pypi_publish_times(&client, repo_id, &server.uri(), "demo")
            .await
            .expect("fetch pypi metadata");
        assert_eq!(first.len(), 1);
        assert_eq!(
            first.get("1.0.0").unwrap().to_rfc3339(),
            "2024-01-01T00:00:00+00:00"
        );

        let second = cache
            .fetch_pypi_publish_times(&client, repo_id, &server.uri(), "Demo")
            .await
            .expect("cache hit");
        assert_eq!(second, first);
    }

    #[tokio::test]
    async fn fetch_pypi_publish_times_reports_status_and_json_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/missing/json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pypi/bad-json/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("not json")
                    .insert_header("Content-Type", "application/json"),
            )
            .mount(&server)
            .await;

        let cache = UpstreamMetadataCache::new();
        let client = metadata_http_client().expect("metadata client");
        assert!(cache
            .fetch_pypi_publish_times(&client, Uuid::new_v4(), &server.uri(), "missing")
            .await
            .is_err());
        assert!(cache
            .fetch_pypi_publish_times(&client, Uuid::new_v4(), &server.uri(), "bad-json")
            .await
            .is_err());
    }

    #[test]
    fn pypi_cache_growth_is_bounded() {
        let cache = UpstreamMetadataCache::new();
        let repo = Uuid::new_v4();
        for i in 0..PYPI_CACHE_MAX_ENTRIES {
            cache.set_pypi_cached((repo, format!("pkg-{i}")), PublishTimeMap::new());
        }
        assert_eq!(
            cache.pypi.read().unwrap().len(),
            PYPI_CACHE_MAX_ENTRIES,
            "cache fills to the cap"
        );

        // Every entry is still fresh, so the next insert must clear the map
        // rather than grow past the cap.
        cache.set_pypi_cached((repo, "overflow".to_string()), PublishTimeMap::new());
        let guard = cache.pypi.read().unwrap();
        assert_eq!(guard.len(), 1, "cap enforced even when nothing is stale");
        assert!(guard.contains_key(&(repo, "overflow".to_string())));
    }
}
