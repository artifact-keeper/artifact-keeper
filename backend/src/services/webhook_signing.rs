//! HMAC-SHA256 (`v1=`) and Ed25519 (`v2=`, #921) signing for the v2
//! webhook wire contract.
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
//!
//! Webhooks whose `signing_mode` is `asymmetric` or `both` also carry
//! `v2=<kid>:<base64url Ed25519 signature>` over the same message, verified
//! against `GET /api/v1/webhooks/jwks` (see
//! [`crate::services::webhook_signing_keys`]). Receivers that only know
//! `v1=` ignore the `v2=` token.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use utoipa::ToSchema;

use crate::services::webhook_signing_keys::InstanceSigningKey;

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

/// Which signature tokens a webhook's deliveries carry (#921). Stored in
/// `webhooks.signing_mode`.
///
/// * `hmac` (default): `v1=` HMAC tokens only, byte-identical to the wire
///   format that predates asymmetric signing.
/// * `asymmetric`: a `v2=<kid>:<sig>` Ed25519 token only, verified against
///   the instance JWKS; no shared secret is used.
/// * `both`: `v1=` tokens followed by the `v2=` token, so receivers can
///   migrate from HMAC to asymmetric verification without a cut-over.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum SigningMode {
    #[default]
    Hmac,
    Asymmetric,
    Both,
}

impl SigningMode {
    /// The value stored in `webhooks.signing_mode`.
    pub fn as_str(self) -> &'static str {
        match self {
            SigningMode::Hmac => "hmac",
            SigningMode::Asymmetric => "asymmetric",
            SigningMode::Both => "both",
        }
    }

    /// Parse a stored value. Unknown values fall back to `hmac`, the mode
    /// every row had before the column existed (the column's CHECK keeps
    /// unknown values out; this is belt and braces for a read path).
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "asymmetric" => SigningMode::Asymmetric,
            "both" => SigningMode::Both,
            _ => SigningMode::Hmac,
        }
    }

    /// Whether deliveries carry `v1=` HMAC tokens.
    pub fn uses_hmac(self) -> bool {
        matches!(self, SigningMode::Hmac | SigningMode::Both)
    }

    /// Whether deliveries carry the `v2=` Ed25519 token.
    pub fn uses_asymmetric(self) -> bool {
        matches!(self, SigningMode::Asymmetric | SigningMode::Both)
    }
}

/// Render the `X-ArtifactKeeper-Signature` value for any signing mode:
/// `t=<ts>`, then one `v1=<hex>` per HMAC secret (current first), then one
/// `v2=<kid>:<base64url sig>` per Ed25519 key. With no keys this returns
/// exactly [`render_header`]'s output, which is what keeps `hmac` mode
/// byte-identical. Returns an empty string when there is nothing to sign
/// with; callers omit the header then.
pub fn render_signature_header(
    unix_secs: i64,
    body: &[u8],
    secrets: &[&str],
    v2_keys: &[InstanceSigningKey],
) -> String {
    let mut header = render_header(unix_secs, body, secrets);
    if v2_keys.is_empty() {
        return header;
    }
    if header.is_empty() {
        header = format!("t={}", unix_secs);
    }
    for key in v2_keys {
        header.push_str(&format!(
            ",v2={}:{}",
            key.kid(),
            key.sign_v2(unix_secs, body)
        ));
    }
    header
}

/// Parse the `v2=` tokens of a signature header into
/// `(timestamp, vec_of_(kid, base64url_sig))`. Returns None when the
/// timestamp is missing or no well-formed `v2=` token is present; `v1=`
/// tokens are ignored, exactly as [`parse_header`] ignores `v2=`.
pub fn parse_v2_tokens(header: &str) -> Option<(i64, Vec<(String, String)>)> {
    let mut ts: Option<i64> = None;
    let mut sigs: Vec<(String, String)> = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("t=") {
            ts = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("v2=") {
            if let Some((kid, sig)) = v.split_once(':') {
                if !kid.is_empty() && !sig.is_empty() {
                    sigs.push((kid.to_string(), sig.to_string()));
                }
            }
        }
    }
    let ts = ts?;
    if sigs.is_empty() {
        return None;
    }
    Some((ts, sigs))
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

#[cfg(ak_test_shard = "services-2")]
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

    // ---------------- v2 (Ed25519) tokens, #921 ----------------

    fn test_key() -> InstanceSigningKey {
        InstanceSigningKey::from_seed(&[9u8; 32])
    }

    #[test]
    fn signature_header_without_keys_is_render_header() {
        for secrets in [&[][..], &["whsec_a"][..], &["whsec_new", "whsec_old"][..]] {
            assert_eq!(
                render_signature_header(1_700_000_000, b"hi", secrets, &[]),
                render_header(1_700_000_000, b"hi", secrets)
            );
        }
    }

    #[test]
    fn signature_header_both_appends_v2_after_v1() {
        let key = test_key();
        let h = render_signature_header(
            1_700_000_000,
            b"hi",
            &["whsec_a"],
            std::slice::from_ref(&key),
        );
        let v1 = compute_v1_signature("whsec_a", 1_700_000_000, b"hi");
        let v2 = key.sign_v2(1_700_000_000, b"hi");
        assert_eq!(h, format!("t=1700000000,v1={},v2={}:{}", v1, key.kid(), v2));
        // An HMAC-only receiver still parses the header and sees one v1.
        let (ts, v1s) = parse_header(&h).unwrap();
        assert_eq!(ts, 1_700_000_000);
        assert_eq!(v1s, vec![v1]);
    }

    #[test]
    fn signature_header_asymmetric_only_has_no_v1() {
        let key = test_key();
        let h = render_signature_header(1_700_000_000, b"hi", &[], std::slice::from_ref(&key));
        assert!(h.starts_with("t=1700000000,v2="));
        assert!(!h.contains("v1="));
        assert!(parse_header(&h).is_none());
        let (ts, v2s) = parse_v2_tokens(&h).unwrap();
        assert_eq!(ts, 1_700_000_000);
        assert_eq!(v2s.len(), 1);
        assert_eq!(v2s[0].0, key.kid());
    }

    #[test]
    fn v2_token_verifies_against_jwks() {
        let key = test_key();
        let body = br#"{"event":"artifact.uploaded"}"#;
        let h = render_signature_header(
            1_700_000_000,
            body,
            &["whsec_a"],
            std::slice::from_ref(&key),
        );
        let jwks = crate::services::webhook_signing_keys::jwks_from_public_keys(&[key
            .public_key_bytes()
            .to_vec()]);
        let (ts, tokens) = parse_v2_tokens(&h).unwrap();
        for (kid, sig) in tokens {
            let jwk = jwks.keys.iter().find(|j| j.kid == kid).unwrap();
            assert!(jwk.verify_v2(ts, body, &sig));
            assert!(!jwk.verify_v2(ts, b"tampered", &sig));
        }
    }

    #[test]
    fn parse_v2_rejects_missing_parts() {
        assert!(parse_v2_tokens("v2=kid:sig").is_none());
        assert!(parse_v2_tokens("t=1,v1=abc").is_none());
        assert!(parse_v2_tokens("t=1,v2=nocolon").is_none());
        assert!(parse_v2_tokens("t=1,v2=:sig,v2=kid:").is_none());
        assert_eq!(
            parse_v2_tokens("t=1, v2=k:s").unwrap(),
            (1, vec![("k".to_string(), "s".to_string())])
        );
    }

    #[test]
    fn signing_mode_round_trips_and_defaults_to_hmac() {
        for m in [
            SigningMode::Hmac,
            SigningMode::Asymmetric,
            SigningMode::Both,
        ] {
            assert_eq!(SigningMode::from_str_lossy(m.as_str()), m);
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(json, format!("\"{}\"", m.as_str()));
            assert_eq!(serde_json::from_str::<SigningMode>(&json).unwrap(), m);
        }
        assert_eq!(SigningMode::default(), SigningMode::Hmac);
        assert_eq!(SigningMode::from_str_lossy("garbage"), SigningMode::Hmac);
        assert!(serde_json::from_str::<SigningMode>("\"rsa\"").is_err());
    }

    #[test]
    fn signing_mode_token_families() {
        assert!(SigningMode::Hmac.uses_hmac() && !SigningMode::Hmac.uses_asymmetric());
        assert!(!SigningMode::Asymmetric.uses_hmac() && SigningMode::Asymmetric.uses_asymmetric());
        assert!(SigningMode::Both.uses_hmac() && SigningMode::Both.uses_asymmetric());
    }
}
