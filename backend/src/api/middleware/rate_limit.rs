//! Rate limiting middleware.
//!
//! Provides per-IP and per-user rate limiting with configurable limits.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::{header::HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tokio::sync::RwLock;

use super::auth::AuthExtension;

/// Rate limiter that tracks requests per key (IP or user ID).
#[derive(Debug)]
pub struct RateLimiter {
    /// Map of key -> (request count, window start time)
    requests: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    /// Maximum number of requests allowed per window
    max_requests: u32,
    /// Duration of the rate limiting window
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified limits.
    ///
    /// # Arguments
    /// * `max_requests` - Maximum number of requests allowed per window
    /// * `window_secs` - Duration of the rate limiting window in seconds
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check if a request should be rate limited.
    ///
    /// Returns `Ok(remaining)` with the number of remaining requests if allowed,
    /// or `Err(retry_after_secs)` if the rate limit has been exceeded.
    pub async fn check_rate_limit(&self, key: &str) -> Result<u32, u64> {
        let now = Instant::now();
        let mut requests = self.requests.write().await;

        let entry = requests.entry(key.to_string()).or_insert((0, now));

        // Check if the window has expired
        if now.duration_since(entry.1) >= self.window {
            // Reset the window
            entry.0 = 1;
            entry.1 = now;
            return Ok(self.max_requests.saturating_sub(1));
        }

        // Check if we've exceeded the limit
        if entry.0 >= self.max_requests {
            let retry_after = self.window.as_secs() - now.duration_since(entry.1).as_secs();
            return Err(retry_after.max(1));
        }

        // Increment the counter
        entry.0 += 1;
        Ok(self.max_requests.saturating_sub(entry.0))
    }

    /// Clean up expired entries from the rate limiter.
    /// Call this periodically to prevent memory bloat.
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut requests = self.requests.write().await;
        requests.retain(|_, (_, window_start)| now.duration_since(*window_start) < self.window);
    }
}

/// Rate limiting middleware.
///
/// Applies rate limiting based on:
/// 1. User ID (if authenticated)
/// 2. IP address (if not authenticated or as fallback)
///
/// Returns 429 Too Many Requests when the limit is exceeded,
/// with a Retry-After header indicating when to retry.
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    // Determine the rate limit key
    // Priority: authenticated user ID > IP address
    let key = if let Some(auth) = request.extensions().get::<AuthExtension>() {
        format!("user:{}", auth.user_id)
    } else if let Some(Some(auth)) = request.extensions().get::<Option<AuthExtension>>() {
        // Handle optional auth middleware case
        format!("user:{}", auth.user_id)
    } else {
        extract_client_ip(&request)
    };

    // Check rate limit
    match limiter.check_rate_limit(&key).await {
        Ok(remaining) => {
            let mut response = next.run(request).await;

            // Add rate limit headers to successful responses
            let headers = response.headers_mut();
            if let Ok(value) = HeaderValue::from_str(&limiter.max_requests.to_string()) {
                headers.insert("X-RateLimit-Limit", value);
            }
            if let Ok(value) = HeaderValue::from_str(&remaining.to_string()) {
                headers.insert("X-RateLimit-Remaining", value);
            }

            response
        }
        Err(retry_after) => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later.",
            )
                .into_response();

            // Add Retry-After header
            let headers = response.headers_mut();
            if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                headers.insert("Retry-After", value);
            }
            if let Ok(value) = HeaderValue::from_str(&limiter.max_requests.to_string()) {
                headers.insert("X-RateLimit-Limit", value);
            }
            if let Ok(value) = HeaderValue::from_str("0") {
                headers.insert("X-RateLimit-Remaining", value);
            }

            response
        }
    }
}

/// Extract the client IP address from the request.
///
/// Uses the actual TCP peer address from ConnectInfo as the primary source.
/// Proxy headers (X-Forwarded-For, X-Real-IP) are NOT trusted because they
/// can be trivially spoofed by clients. Only the socket-level peer address
/// is reliable for rate limiting.
fn extract_client_ip(request: &Request) -> String {
    // Use the actual TCP connection peer address (set by axum's ConnectInfo)
    if let Some(connect_info) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return format!("ip:{}", connect_info.0.ip());
    }

    // Fallback: use a single key for all requests so rate limiting still works.
    // This means all unauthenticated requests share one bucket, which is
    // conservative but safe (cannot be bypassed via header spoofing).
    "ip:unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_requests_within_limit() {
        let limiter = RateLimiter::new(5, 60);

        for i in 0..5 {
            let result = limiter.check_rate_limit("test_key").await;
            assert!(result.is_ok(), "Request {} should be allowed", i + 1);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_requests_over_limit() {
        let limiter = RateLimiter::new(3, 60);

        // Use up the limit
        for _ in 0..3 {
            let result = limiter.check_rate_limit("test_key").await;
            assert!(result.is_ok());
        }

        // Next request should be blocked
        let result = limiter.check_rate_limit("test_key").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_returns_retry_after() {
        let limiter = RateLimiter::new(1, 60);

        // Use up the limit
        let _ = limiter.check_rate_limit("test_key").await;

        // Check retry_after value
        let result = limiter.check_rate_limit("test_key").await;
        assert!(matches!(result, Err(retry_after) if retry_after > 0 && retry_after <= 60));
    }

    #[tokio::test]
    async fn test_rate_limiter_tracks_separate_keys() {
        let limiter = RateLimiter::new(2, 60);

        // Use up limit for key1
        for _ in 0..2 {
            let _ = limiter.check_rate_limit("key1").await;
        }

        // key1 should be blocked
        assert!(limiter.check_rate_limit("key1").await.is_err());

        // key2 should still work
        assert!(limiter.check_rate_limit("key2").await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_returns_remaining() {
        let limiter = RateLimiter::new(5, 60);

        let result = limiter.check_rate_limit("test_key").await;
        assert_eq!(result, Ok(4)); // 5 - 1 = 4 remaining

        let result = limiter.check_rate_limit("test_key").await;
        assert_eq!(result, Ok(3)); // 5 - 2 = 3 remaining
    }

    // -----------------------------------------------------------------------
    // Additional RateLimiter tests for improved coverage
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limiter_remaining_counts_down_to_zero() {
        let limiter = RateLimiter::new(3, 60);

        assert_eq!(limiter.check_rate_limit("k").await, Ok(2));
        assert_eq!(limiter.check_rate_limit("k").await, Ok(1));
        assert_eq!(limiter.check_rate_limit("k").await, Ok(0));
        // Next should be blocked
        assert!(limiter.check_rate_limit("k").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_window_reset() {
        // Use a very short window (1 second) to test reset
        let limiter = RateLimiter::new(1, 1);

        // Use up the limit
        assert!(limiter.check_rate_limit("reset_key").await.is_ok());
        assert!(limiter.check_rate_limit("reset_key").await.is_err());

        // Wait for the window to expire
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        // Should be allowed again after window reset
        let result = limiter.check_rate_limit("reset_key").await;
        assert!(result.is_ok());
        // After reset, remaining should be max_requests - 1
        assert_eq!(result.unwrap(), 0); // 1 - 1 = 0
    }

    #[tokio::test]
    async fn test_rate_limiter_cleanup_expired() {
        let limiter = RateLimiter::new(5, 1);

        // Add some entries
        let _ = limiter.check_rate_limit("key1").await;
        let _ = limiter.check_rate_limit("key2").await;

        // Wait for expiry
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        // Add a fresh entry
        let _ = limiter.check_rate_limit("key3").await;

        // Cleanup should remove expired entries (key1, key2) but keep key3
        limiter.cleanup_expired().await;

        let requests = limiter.requests.read().await;
        assert!(
            !requests.contains_key("key1"),
            "Expired key1 should be removed"
        );
        assert!(
            !requests.contains_key("key2"),
            "Expired key2 should be removed"
        );
        assert!(requests.contains_key("key3"), "Fresh key3 should be kept");
    }

    #[tokio::test]
    async fn test_rate_limiter_retry_after_minimum_is_one() {
        // When the limit is just reached, retry_after should be at least 1
        let limiter = RateLimiter::new(1, 60);

        let _ = limiter.check_rate_limit("key").await;
        let result = limiter.check_rate_limit("key").await;

        match result {
            Err(retry_after) => {
                assert!(
                    retry_after >= 1,
                    "retry_after should be at least 1, got {}",
                    retry_after
                );
                assert!(
                    retry_after <= 60,
                    "retry_after should be <= window, got {}",
                    retry_after
                );
            }
            Ok(_) => panic!("Expected rate limit error"),
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_single_request_limit() {
        // With max_requests = 1, first request succeeds, second fails
        let limiter = RateLimiter::new(1, 60);
        assert_eq!(limiter.check_rate_limit("k").await, Ok(0)); // 1-1 = 0 remaining
        assert!(limiter.check_rate_limit("k").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_many_independent_keys() {
        let limiter = RateLimiter::new(1, 60);

        for i in 0..100 {
            let key = format!("key_{}", i);
            assert!(limiter.check_rate_limit(&key).await.is_ok());
        }

        // Each key should now be exhausted
        for i in 0..100 {
            let key = format!("key_{}", i);
            assert!(limiter.check_rate_limit(&key).await.is_err());
        }
    }

    // -----------------------------------------------------------------------
    // extract_client_ip
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_client_ip_ignores_x_forwarded_for() {
        // X-Forwarded-For is client-spoofable, so the rate limiter ignores it
        let request = axum::extract::Request::builder()
            .header("X-Forwarded-For", "192.168.1.1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_client_ip(&request), "ip:unknown");
    }

    #[test]
    fn test_extract_client_ip_ignores_x_real_ip() {
        let request = axum::extract::Request::builder()
            .header("X-Real-IP", "10.20.30.40")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_client_ip(&request), "ip:unknown");
    }

    #[test]
    fn test_extract_client_ip_no_headers_returns_unknown() {
        let request = axum::extract::Request::builder()
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_client_ip(&request), "ip:unknown");
    }

    #[test]
    fn test_extract_client_ip_uses_connect_info() {
        use std::net::SocketAddr;
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let mut request = axum::extract::Request::builder()
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        assert_eq!(extract_client_ip(&request), "ip:192.168.1.100");
    }

    #[test]
    fn test_extract_client_ip_connect_info_over_headers() {
        use std::net::SocketAddr;
        let addr: SocketAddr = "10.0.0.5:9999".parse().unwrap();
        let mut request = axum::extract::Request::builder()
            .header("X-Forwarded-For", "1.2.3.4")
            .header("X-Real-IP", "5.6.7.8")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        // ConnectInfo takes priority over spoofable headers
        assert_eq!(extract_client_ip(&request), "ip:10.0.0.5");
    }
}
