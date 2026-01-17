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
            let retry_after = self.window.as_secs()
                - now.duration_since(entry.1).as_secs();
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
        requests.retain(|_, (_, window_start)| {
            now.duration_since(*window_start) < self.window
        });
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
    } else if let Some(auth) = request.extensions().get::<Option<AuthExtension>>() {
        // Handle optional auth middleware case
        if let Some(auth) = auth {
            format!("user:{}", auth.user_id)
        } else {
            extract_client_ip(&request)
        }
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
/// Checks the following headers in order:
/// 1. X-Forwarded-For (first IP)
/// 2. X-Real-IP
/// 3. Falls back to "unknown"
fn extract_client_ip(request: &Request) -> String {
    // Try X-Forwarded-For first
    if let Some(forwarded_for) = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
    {
        // Take the first IP (client IP in proxy chain)
        if let Some(client_ip) = forwarded_for.split(',').next() {
            return format!("ip:{}", client_ip.trim());
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = request
        .headers()
        .get("X-Real-IP")
        .and_then(|h| h.to_str().ok())
    {
        return format!("ip:{}", real_ip.trim());
    }

    // Fallback to unknown (in production, you might want to use connection info)
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
}
