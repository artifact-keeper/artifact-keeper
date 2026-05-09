//! HMAC-SHA256 signing for the v2 webhook wire contract.
//!
//! The signed payload is `"<unix_seconds>.<raw_body>"` so receivers can
//! detect replay independent of body inspection. The header form is
//! Stripe-style multi-value:
//!
//! ```text
//! X-ArtifactKeeper-Signature: t=1746135420,v1=<hex>,v1=<hex>
//! ```
//!
//! During the 24h rotation overlap window we emit both signatures (new
//! secret first) so a receiver that has not yet rotated keys can still
//! validate. Receivers MUST accept any `v1=` token whose constant-time
//! comparison succeeds.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// One-shot compute helper. `body` is the exact bytes that will be sent
/// on the wire; do not re-serialize after calling this. `unix_secs` is
/// the timestamp embedded in the header; the caller is responsible for
/// using the same value when building the header.
pub fn compute_v1_signature(secret: &str, unix_secs: i64, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(unix_secs.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Render the full `X-ArtifactKeeper-Signature` header value. `secrets`
/// is ordered current-first so receivers that pin to the leftmost token
/// stay on the freshest secret. An empty `secrets` slice returns an
/// empty string; callers MUST omit the header in that case rather than
/// emit a useless `t=...` with no signatures.
pub fn render_header(unix_secs: i64, body: &[u8], secrets: &[&str]) -> String {
    if secrets.is_empty() {
        return String::new();
    }
    let mut parts = vec![format!("t={}", unix_secs)];
    for secret in secrets {
        parts.push(format!(
            "v1={}",
            compute_v1_signature(secret, unix_secs, body)
        ));
    }
    parts.join(",")
}

/// Parse a v2 signature header into (timestamp, vec_of_v1_hex). Returns
/// None on any structural error.
pub fn parse_header(header: &str) -> Option<(i64, Vec<String>)> {
    let mut ts: Option<i64> = None;
    let mut sigs: Vec<String> = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("t=") {
            ts = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("v1=") {
            sigs.push(v.to_string());
        }
    }
    let ts = ts?;
    if sigs.is_empty() {
        return None;
    }
    Some((ts, sigs))
}

/// Default replay window in seconds when the per-webhook override is
/// unset. Stripe / Slack / Plaid converge on 5 minutes.
pub const DEFAULT_REPLAY_WINDOW_SECS: i64 = 300;

/// Returns true iff `signed_at` is within `window_secs` of `now`.
pub fn within_replay_window(now: i64, signed_at: i64, window_secs: i64) -> bool {
    let delta = (now - signed_at).abs();
    delta <= window_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_deterministic_and_hex_64() {
        let s = compute_v1_signature("whsec_x", 1_700_000_000, b"hello");
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(s, compute_v1_signature("whsec_x", 1_700_000_000, b"hello"));
    }

    #[test]
    fn signature_changes_with_timestamp() {
        let a = compute_v1_signature("whsec_x", 1_700_000_000, b"hello");
        let b = compute_v1_signature("whsec_x", 1_700_000_001, b"hello");
        assert_ne!(a, b);
    }

    #[test]
    fn signature_changes_with_body() {
        let a = compute_v1_signature("whsec_x", 1_700_000_000, b"hello");
        let b = compute_v1_signature("whsec_x", 1_700_000_000, b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn signature_changes_with_secret() {
        let a = compute_v1_signature("whsec_a", 1_700_000_000, b"hello");
        let b = compute_v1_signature("whsec_b", 1_700_000_000, b"hello");
        assert_ne!(a, b);
    }

    #[test]
    fn header_is_empty_when_no_secrets() {
        assert!(render_header(1_700_000_000, b"hi", &[]).is_empty());
    }

    #[test]
    fn header_carries_one_v1_token_when_one_secret() {
        let h = render_header(1_700_000_000, b"hi", &["whsec_a"]);
        assert!(h.starts_with("t=1700000000,"));
        assert_eq!(h.matches("v1=").count(), 1);
    }

    #[test]
    fn header_carries_two_v1_tokens_during_rotation() {
        let h = render_header(1_700_000_000, b"hi", &["whsec_new", "whsec_old"]);
        assert_eq!(h.matches("v1=").count(), 2);
        // Current-first ordering is observable.
        let new_sig = compute_v1_signature("whsec_new", 1_700_000_000, b"hi");
        let old_sig = compute_v1_signature("whsec_old", 1_700_000_000, b"hi");
        let new_pos = h.find(&new_sig).unwrap();
        let old_pos = h.find(&old_sig).unwrap();
        assert!(new_pos < old_pos);
    }

    #[test]
    fn parse_round_trip() {
        let h = render_header(1_700_000_000, b"hi", &["whsec_a", "whsec_b"]);
        let (ts, sigs) = parse_header(&h).unwrap();
        assert_eq!(ts, 1_700_000_000);
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn parse_rejects_missing_timestamp() {
        assert!(parse_header("v1=abc").is_none());
    }

    #[test]
    fn parse_rejects_missing_signatures() {
        assert!(parse_header("t=1700000000").is_none());
    }

    #[test]
    fn replay_window_inclusive_at_boundary() {
        assert!(within_replay_window(1_000, 700, 300));
        assert!(!within_replay_window(1_000, 699, 300));
    }

    #[test]
    fn replay_window_rejects_future_clock_skew() {
        assert!(!within_replay_window(1_000, 2_000, 300));
    }
}
