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
        let cache_key = (repo_id, project.to_ascii_lowercase());
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
        if entry.fetched_at.elapsed() <= PYPI_CACHE_TTL {
            Some(entry.times.clone())
        } else {
            None
        }
    }

    fn set_pypi_cached(&self, key: (Uuid, String), times: PublishTimeMap) {
        if let Ok(mut guard) = self.pypi.write() {
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

fn pypi_json_url(upstream_url: &str, project: &str) -> String {
    let mut base = upstream_url.trim_end_matches('/');
    if let Some(stripped) = base.strip_suffix("/simple") {
        base = stripped;
    }
    format!("{base}/pypi/{project}/json")
}

fn parse_pypi_releases_json(body: &serde_json::Value) -> PublishTimeMap {
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

fn parse_iso_timestamp(value: &serde_json::Value) -> Option<DateTime<Utc>> {
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
}
