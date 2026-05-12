//! Per-event token-bucket rate limiter for email dispatch fan-out.
//!
//! Fix for #1169 (security M1, follow-up to #920 / PR #1167).
//!
//! `email_dispatcher::deliver_email` iterates the `recipients` list with no
//! per-recipient throttle and no per-domain throttle. A noisy event class
//! firing against many subscriptions can amplify outbound mail enough that
//! SMTP relays blocklist us. This module backstops that.
//!
//! ## Design
//!
//! Two token buckets, both keyed and both refilled every `tick`:
//!
//! - **Recipient bucket**: keyed on `(subscription_id, recipient_address)`.
//!   Capacity = `AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN` (default 100).
//!   Refilled `capacity / 60` tokens per second so the steady-state rate is
//!   `capacity / minute`. Per-subscription scoping means a runaway event
//!   class on one subscription cannot starve emails to a different one.
//!
//! - **Domain bucket**: keyed on the lowercased part-after-`@` of the
//!   recipient. Capacity = `AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN`
//!   (default 1000). This is the SMTP-boundary throttle: even if a hundred
//!   distinct subscriptions each get their own per-recipient allowance,
//!   the upstream relay still rate-limits us per receiving domain. A
//!   global per-domain cap caps the total send rate to e.g. `gmail.com`
//!   regardless of how many subscriptions route through it.
//!
//! Both checks must pass for `try_acquire` to succeed; both consume one
//! token on success. If either bucket is empty, the call fails fast
//! (non-blocking) so the dispatch loop is never stalled waiting on a
//! refill. The caller drops the message with `warn!` + a Prometheus
//! counter increment (`email_dispatch_rate_limited_total`).
//!
//! ## Implementation choice
//!
//! `Arc<Mutex<HashMap>>` rather than `DashMap` or `governor` to avoid new
//! dependencies. Lock-contention isn't a concern at the email-dispatch
//! call rate (orders of magnitude below HTTP-handler rates where the
//! existing `Mutex<HashMap>`-based rate limiter in
//! `crate::api::middleware::rate_limit` already lives without issue).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

/// Default capacity for the per-(subscription, recipient) bucket. Overridable
/// via `AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN`.
pub const DEFAULT_PER_RECIPIENT_PER_MIN: u32 = 100;

/// Default capacity for the per-domain bucket. Overridable via
/// `AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN`.
pub const DEFAULT_PER_DOMAIN_PER_MIN: u32 = 1000;

/// Soft cap on the recipient-bucket map. When exceeded, entries idle
/// longer than [`PRUNE_IDLE_THRESHOLD`] are evicted lazily on access so
/// memory is bounded under subscription churn / attacker-driven
/// recipient variation.
const RECIPIENT_MAP_SOFT_CAP: usize = 10_000;

/// Soft cap on the domain-bucket map. Same eviction trigger as the
/// recipient map.
const DOMAIN_MAP_SOFT_CAP: usize = 2_000;

/// Minimum interval between prune sweeps. Caps the amortized cost of
/// pruning at O(1) per `try_acquire` even when the map sits above the
/// soft cap indefinitely (the case an attacker can force by creating
/// SOFT_CAP+1 active subscriptions).
const PRUNE_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// Age beyond which an idle bucket is guaranteed to have refilled to
/// full capacity from any past consumption. With the longest refill
/// window being `capacity / (capacity / 60) = 60s`, anything older than
/// 90s is observationally indistinguishable from a fresh bucket, so
/// dropping it changes no operator-visible behaviour. We pad to 120s
/// for safety against clock jitter.
const PRUNE_IDLE_THRESHOLD: Duration = Duration::from_secs(120);

/// Parse an `AK_EMAIL_RATE_LIMIT_*_PER_MIN` env value, applying the
/// fallback policy:
/// - unset / unparseable / non-numeric => `default`
/// - `0` => `default` (treated as misconfiguration: `0` would otherwise
///   build a permanently-empty bucket and silently drop 100% of mail,
///   which is almost never what an operator typing `=0` intends)
/// - any other `u32` => that value
pub(crate) fn parse_per_min_env(raw: Option<&str>, default: u32) -> u32 {
    match raw.and_then(|v| v.parse::<u32>().ok()) {
        Some(0) => {
            tracing::warn!(
                default = default,
                "Email rate-limit env var parsed as 0, which would block all mail. Falling back to default."
            );
            default
        }
        Some(n) => n,
        None => default,
    }
}

/// A single token bucket: capacity, current token count, refill rate, last
/// refill timestamp. Refill is computed lazily on `try_consume` from the
/// elapsed wall-clock so we don't need a background ticker task.
#[derive(Debug)]
struct Bucket {
    /// Maximum tokens the bucket can hold.
    capacity: f64,
    /// Tokens refilled per second.
    refill_per_sec: f64,
    /// Current token count (fractional so refill math is exact).
    tokens: f64,
    /// When we last refilled this bucket.
    last_refill: Instant,
}

impl Bucket {
    /// Build a bucket at full capacity, refilling `capacity_per_minute / 60`
    /// tokens per second.
    fn new_full(capacity_per_minute: u32, now: Instant) -> Self {
        let capacity = capacity_per_minute as f64;
        Self {
            capacity,
            refill_per_sec: capacity / 60.0,
            tokens: capacity,
            last_refill: now,
        }
    }

    /// Lazily refill based on elapsed time, then try to take one token.
    /// Returns true if the token was taken, false if the bucket was empty.
    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let refill = elapsed.as_secs_f64() * self.refill_per_sec;
        self.tokens = (self.tokens + refill).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Reason a rate-limit acquisition failed. Surfaced so the caller (and
/// the Prometheus counter label) can distinguish a per-recipient ceiling
/// from a per-domain SMTP-boundary ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Token granted. Send the email.
    Allowed,
    /// Per-(subscription_id, recipient) bucket empty.
    RecipientLimited,
    /// Per-domain bucket empty.
    DomainLimited,
}

impl RateLimitDecision {
    /// Stable label string for Prometheus.
    pub fn label(self) -> &'static str {
        match self {
            RateLimitDecision::Allowed => "allowed",
            RateLimitDecision::RecipientLimited => "recipient",
            RateLimitDecision::DomainLimited => "domain",
        }
    }
}

/// Token-bucket rate limiter for outbound email dispatch.
///
/// Two-tier check: per-(subscription, recipient) AND per-domain. Both must
/// pass. Failing either drops the message non-blockingly (no waiting on
/// refill) so the dispatch loop stays responsive under load.
#[derive(Debug)]
pub struct EmailRateLimiter {
    per_recipient_per_min: u32,
    per_domain_per_min: u32,
    state: Mutex<RateLimiterState>,
}

#[derive(Debug, Default)]
struct RateLimiterState {
    recipients: HashMap<(Uuid, String), Bucket>,
    domains: HashMap<String, Bucket>,
    /// When the last prune sweep ran. Used to throttle sweep frequency
    /// to at most one per [`PRUNE_MIN_INTERVAL`].
    last_prune: Option<Instant>,
}

impl EmailRateLimiter {
    /// Build a limiter with explicit per-minute caps. Use [`from_env`] to
    /// pick up the operator overrides at startup.
    pub fn new(per_recipient_per_min: u32, per_domain_per_min: u32) -> Self {
        Self {
            per_recipient_per_min,
            per_domain_per_min,
            state: Mutex::new(RateLimiterState::default()),
        }
    }

    /// Construct from `AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN` and
    /// `AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN`. Unset / unparseable / `0`
    /// values fall back to defaults via [`parse_per_min_env`]; we never
    /// panic the boot on a typo and never silently disable enforcement.
    pub fn from_env() -> Self {
        let per_recipient = parse_per_min_env(
            std::env::var("AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN")
                .ok()
                .as_deref(),
            DEFAULT_PER_RECIPIENT_PER_MIN,
        );
        let per_domain = parse_per_min_env(
            std::env::var("AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN")
                .ok()
                .as_deref(),
            DEFAULT_PER_DOMAIN_PER_MIN,
        );
        Self::new(per_recipient, per_domain)
    }

    /// Configured per-(subscription, recipient) capacity.
    pub fn per_recipient_per_min(&self) -> u32 {
        self.per_recipient_per_min
    }

    /// Configured per-domain capacity.
    pub fn per_domain_per_min(&self) -> u32 {
        self.per_domain_per_min
    }

    /// Try to consume one token for delivery to `recipient` under
    /// `subscription_id`. Returns the decision; callers should drop and
    /// log on any non-`Allowed` value rather than retry.
    pub fn try_acquire(&self, subscription_id: Uuid, recipient: &str) -> RateLimitDecision {
        self.try_acquire_at(subscription_id, recipient, Instant::now())
    }

    /// `try_acquire` with an injected clock. Exposed for tests so bucket
    /// refill behavior can be exercised deterministically.
    pub fn try_acquire_at(
        &self,
        subscription_id: Uuid,
        recipient: &str,
        now: Instant,
    ) -> RateLimitDecision {
        let recipient_lc = recipient.to_ascii_lowercase();
        let domain = extract_domain(&recipient_lc);
        let recipient_key = (subscription_id, recipient_lc);

        let mut state = match self.state.lock() {
            Ok(g) => g,
            // Poisoned lock: another thread panicked mid-update. Recover
            // by taking the inner state; we'd rather rate-limit forward
            // than refuse all email forever.
            Err(p) => p.into_inner(),
        };

        // Bound the maps under subscription churn / attacker-driven
        // recipient or domain variation. Pruning is:
        //
        // - Lazy: only runs when over the soft cap.
        // - Frequency-capped: at most once per `PRUNE_MIN_INTERVAL`, so
        //   even if the map stays over-cap indefinitely the amortized
        //   per-call cost stays O(1) (otherwise an attacker driving the
        //   map to SOFT_CAP+1 with all-warm buckets would force an O(N)
        //   scan on every dispatch — Security R2 B2).
        // - Age-based: drops entries whose `last_refill` is older than
        //   `PRUNE_IDLE_THRESHOLD`. Such buckets would refill to full on
        //   their next access anyway, so dropping them changes nothing
        //   operator-visible. (A `tokens < capacity` predicate would not
        //   catch idle-but-once-consumed buckets, since `tokens` is only
        //   updated inside `try_consume`.)
        let over_cap = state.recipients.len() > RECIPIENT_MAP_SOFT_CAP
            || state.domains.len() > DOMAIN_MAP_SOFT_CAP;
        let interval_ok = state
            .last_prune
            .map(|t| now.saturating_duration_since(t) >= PRUNE_MIN_INTERVAL)
            .unwrap_or(true);
        if over_cap && interval_ok {
            state
                .recipients
                .retain(|_, b| now.saturating_duration_since(b.last_refill) < PRUNE_IDLE_THRESHOLD);
            state
                .domains
                .retain(|_, b| now.saturating_duration_since(b.last_refill) < PRUNE_IDLE_THRESHOLD);
            state.last_prune = Some(now);
        }

        // Per-recipient gate first. Cheap and per-subscription scoped so
        // a runaway sub can't drain the global domain pool by itself.
        let recipient_bucket = state
            .recipients
            .entry(recipient_key.clone())
            .or_insert_with(|| Bucket::new_full(self.per_recipient_per_min, now));
        if !recipient_bucket.try_consume(now) {
            return RateLimitDecision::RecipientLimited;
        }

        // Per-domain gate. SMTP-boundary throttle.
        let domain_bucket = state
            .domains
            .entry(domain)
            .or_insert_with(|| Bucket::new_full(self.per_domain_per_min, now));
        if !domain_bucket.try_consume(now) {
            // Roll back the recipient token so the caller's accounting
            // matches the actual send. Otherwise a flapping domain
            // limiter would silently leak tokens out of the per-recipient
            // bucket and skew its rate.
            //
            // SAFETY of correctness: the recipient bucket capacity is
            // bounded so saturating at capacity is fine.
            if let Some(b) = state.recipients.get_mut(&recipient_key) {
                b.tokens = (b.tokens + 1.0).min(b.capacity);
            }
            return RateLimitDecision::DomainLimited;
        }

        RateLimitDecision::Allowed
    }

    /// Number of recipient-bucket entries currently tracked. Exposed for
    /// tests + observability; bounded by `RECIPIENT_MAP_SOFT_CAP` via
    /// lazy pruning in `try_acquire_at`.
    #[cfg(test)]
    pub(crate) fn recipient_entry_count(&self) -> usize {
        self.state.lock().map(|s| s.recipients.len()).unwrap_or(0)
    }

    /// Number of domain-bucket entries currently tracked. Exposed for
    /// tests; bounded by `DOMAIN_MAP_SOFT_CAP`.
    #[cfg(test)]
    pub(crate) fn domain_entry_count(&self) -> usize {
        self.state.lock().map(|s| s.domains.len()).unwrap_or(0)
    }
}

/// Extract the lowercased domain part of an email address. Returns the
/// raw lowercased input if there's no `@` (the upstream validator should
/// have rejected this case before delivery, but we don't want to panic
/// on a malformed row that bypassed validation, e.g. from a hand-rolled
/// SQL insert).
fn extract_domain(addr: &str) -> String {
    match addr.rsplit_once('@') {
        Some((_local, domain)) => domain.to_ascii_lowercase(),
        None => addr.to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sub() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn test_extract_domain_basic() {
        assert_eq!(extract_domain("alice@example.com"), "example.com");
    }

    #[test]
    fn test_extract_domain_lowercases() {
        assert_eq!(extract_domain("Bob@Example.COM"), "example.com");
    }

    #[test]
    fn test_extract_domain_no_at_sign_returns_input_lower() {
        // Malformed row that bypassed validation; we don't panic.
        assert_eq!(extract_domain("noAtSign"), "noatsign");
    }

    #[test]
    fn test_extract_domain_multiple_at_uses_last() {
        // RFC 5321 disallows multiple unquoted `@`s but our validator
        // also rejects this; even so, `rsplit_once` is well-defined.
        assert_eq!(extract_domain("a@b@example.com"), "example.com");
    }

    #[test]
    fn test_decision_label_strings_are_stable() {
        // Prometheus label cardinality contract. Don't rename casually.
        assert_eq!(RateLimitDecision::Allowed.label(), "allowed");
        assert_eq!(RateLimitDecision::RecipientLimited.label(), "recipient");
        assert_eq!(RateLimitDecision::DomainLimited.label(), "domain");
    }

    #[test]
    fn test_bucket_refills_over_time() {
        // Snapshot `t0` once and reuse for the drain loop; reading
        // `Instant::now()` each iteration would let the bucket refill
        // mid-drain on a slow CI runner and make the empty-check flake.
        let t0 = Instant::now();
        let mut b = Bucket::new_full(60, t0);
        for _ in 0..60 {
            assert!(b.try_consume(t0));
        }
        // Empty at `t0`.
        assert!(!b.try_consume(t0));
        // Advance one second: refill_per_sec = 60/60 = 1 token/sec
        let future = t0 + Duration::from_secs(1);
        assert!(b.try_consume(future));
    }

    #[test]
    fn test_bucket_cap_at_capacity() {
        let t0 = Instant::now();
        let mut b = Bucket::new_full(100, t0);
        // Advance an hour: refill_per_sec * 3600 = 100*60 tokens worth,
        // but capacity caps at 100.
        let future = t0 + Duration::from_secs(3600);
        // Consume one to force refill computation.
        assert!(b.try_consume(future));
        // After the consume, tokens is capacity - 1 = 99.
        assert!(b.tokens <= 99.0 + 0.0001);
        assert!(b.tokens >= 99.0 - 0.0001);
    }

    #[test]
    fn test_default_caps_allow_first_send() {
        let limiter =
            EmailRateLimiter::new(DEFAULT_PER_RECIPIENT_PER_MIN, DEFAULT_PER_DOMAIN_PER_MIN);
        assert_eq!(
            limiter.try_acquire(sub(), "ops@example.com"),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn test_per_recipient_bucket_drains_on_burst() {
        // Cap = 3/min so we can exhaust quickly.
        let limiter = EmailRateLimiter::new(3, 1000);
        let s = sub();
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(
                limiter.try_acquire_at(s, "alice@a.com", now),
                RateLimitDecision::Allowed
            );
        }
        // 4th in the same instant: drained.
        assert_eq!(
            limiter.try_acquire_at(s, "alice@a.com", now),
            RateLimitDecision::RecipientLimited
        );
    }

    #[test]
    fn test_per_recipient_does_not_starve_other_recipients() {
        // alice's bucket exhausted; bob on a different domain still sends.
        let limiter = EmailRateLimiter::new(1, 1000);
        let s = sub();
        let now = Instant::now();
        assert_eq!(
            limiter.try_acquire_at(s, "alice@a.com", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.try_acquire_at(s, "alice@a.com", now),
            RateLimitDecision::RecipientLimited
        );
        assert_eq!(
            limiter.try_acquire_at(s, "bob@b.com", now),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn test_per_recipient_does_not_starve_other_subscriptions() {
        // Same recipient address but a different subscription_id is a
        // distinct bucket. This is the property #1169 specifically calls
        // for ("keyed on (subscription_id, recipient)").
        let limiter = EmailRateLimiter::new(1, 1000);
        let now = Instant::now();
        let sub_a = sub();
        let sub_b = sub();
        assert_eq!(
            limiter.try_acquire_at(sub_a, "ops@a.com", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.try_acquire_at(sub_a, "ops@a.com", now),
            RateLimitDecision::RecipientLimited
        );
        // Different sub, same address: independent bucket, allowed.
        assert_eq!(
            limiter.try_acquire_at(sub_b, "ops@a.com", now),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn test_per_domain_throttles_across_subscriptions() {
        // Two subs sending to the same domain: per-recipient still ok
        // for each, but the domain bucket runs out first.
        let limiter = EmailRateLimiter::new(100, 2);
        let now = Instant::now();
        let sub_a = sub();
        let sub_b = sub();
        assert_eq!(
            limiter.try_acquire_at(sub_a, "a@example.com", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.try_acquire_at(sub_b, "b@example.com", now),
            RateLimitDecision::Allowed
        );
        // Both eaten the per-domain pool. Third hit should be domain-
        // limited.
        assert_eq!(
            limiter.try_acquire_at(sub_a, "c@example.com", now),
            RateLimitDecision::DomainLimited
        );
    }

    #[test]
    fn test_domain_limit_refunds_recipient_token() {
        // When the domain bucket trips, the recipient bucket must not
        // be charged. Otherwise a busy domain would silently drain
        // per-recipient allowances even for messages that never sent.
        // Per-recipient cap = 1, per-domain cap = 1. If the recipient
        // bucket got charged on the failed attempt, the recipient would
        // be locked out even after the domain bucket refills.
        let limiter = EmailRateLimiter::new(1, 1);
        let t0 = Instant::now();
        let s = sub();

        // Eat the one domain token on first@d.com.
        assert_eq!(
            limiter.try_acquire_at(s, "first@d.com", t0),
            RateLimitDecision::Allowed
        );

        // second@d.com: per-recipient bucket has 1 (fresh), but domain
        // is empty. Must be DomainLimited.
        assert_eq!(
            limiter.try_acquire_at(s, "second@d.com", t0),
            RateLimitDecision::DomainLimited
        );

        // Advance one minute so the domain bucket refills back to 1.
        let t1 = t0 + Duration::from_secs(60);

        // If the refund worked, second@d.com still has its full
        // per-recipient token AND the domain bucket has one again, so
        // this must be Allowed. If the recipient was charged on the
        // earlier failed attempt, this would be RecipientLimited.
        assert_eq!(
            limiter.try_acquire_at(s, "second@d.com", t1),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn test_per_domain_refills_over_time() {
        // Domain cap=1/min => refill_per_sec = 1/60 ~= 0.0167.
        // Advancing 60 seconds gives back one full token.
        let limiter = EmailRateLimiter::new(100, 1);
        let s = sub();
        let t0 = Instant::now();
        assert_eq!(
            limiter.try_acquire_at(s, "a@example.com", t0),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.try_acquire_at(s, "b@example.com", t0),
            RateLimitDecision::DomainLimited
        );
        let t1 = t0 + Duration::from_secs(60);
        assert_eq!(
            limiter.try_acquire_at(s, "b@example.com", t1),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn test_recipient_case_normalized() {
        // RFC 5321 says the local part is case-sensitive in theory but
        // in practice every receiver normalizes. Keying on the
        // lowercased form prevents `Alice@x.com` and `alice@x.com`
        // having independent buckets, which would let a noisy sender
        // double its allowance by capitalization.
        let limiter = EmailRateLimiter::new(1, 1000);
        let s = sub();
        let now = Instant::now();
        assert_eq!(
            limiter.try_acquire_at(s, "Alice@x.com", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.try_acquire_at(s, "alice@x.com", now),
            RateLimitDecision::RecipientLimited
        );
    }

    #[test]
    fn test_domain_case_normalized() {
        // Same property at the domain layer.
        let limiter = EmailRateLimiter::new(100, 1);
        let s = sub();
        let now = Instant::now();
        assert_eq!(
            limiter.try_acquire_at(s, "a@Example.COM", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.try_acquire_at(s, "b@example.com", now),
            RateLimitDecision::DomainLimited
        );
    }

    #[test]
    fn test_parse_per_min_env_unset_returns_default() {
        assert_eq!(parse_per_min_env(None, 100), 100);
    }

    #[test]
    fn test_parse_per_min_env_valid_value() {
        assert_eq!(parse_per_min_env(Some("250"), 100), 250);
    }

    #[test]
    fn test_parse_per_min_env_zero_clamps_to_default() {
        // `0` would build a permanently-empty bucket and silently drop
        // all mail. That's almost never what an operator typing `=0`
        // intends, so we clamp.
        assert_eq!(parse_per_min_env(Some("0"), 100), 100);
        assert_eq!(parse_per_min_env(Some("0"), 1000), 1000);
    }

    #[test]
    fn test_parse_per_min_env_garbage_returns_default() {
        assert_eq!(parse_per_min_env(Some("not-a-number"), 100), 100);
        assert_eq!(parse_per_min_env(Some(""), 100), 100);
        assert_eq!(parse_per_min_env(Some("-1"), 100), 100); // u32 parse fails
    }

    #[test]
    fn test_parse_per_min_env_huge_value_passes_through() {
        // u32::MAX is parseable; we don't impose an upper bound here
        // because the operator may want effectively-no-cap.
        assert_eq!(parse_per_min_env(Some("4294967295"), 100), u32::MAX);
    }

    /// Serializes env-mutation tests in this module. Other tests in the
    /// crate may inspect or set the same vars; without this lock,
    /// parallel `cargo test` runs race the var state.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_from_env_uses_defaults_when_env_unset() {
        // Tight assertion: from_env() must return defaults specifically,
        // not just any positive number. Serialized + cleaned to defend
        // against ambient env-var carryover.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_r = std::env::var("AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN").ok();
        let prev_d = std::env::var("AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN").ok();
        std::env::remove_var("AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN");
        std::env::remove_var("AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN");

        let limiter = EmailRateLimiter::from_env();
        assert_eq!(
            limiter.per_recipient_per_min(),
            DEFAULT_PER_RECIPIENT_PER_MIN
        );
        assert_eq!(limiter.per_domain_per_min(), DEFAULT_PER_DOMAIN_PER_MIN);

        if let Some(v) = prev_r {
            std::env::set_var("AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN", v);
        }
        if let Some(v) = prev_d {
            std::env::set_var("AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN", v);
        }
    }

    #[test]
    fn test_from_env_picks_up_overrides() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_r = std::env::var("AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN").ok();
        let prev_d = std::env::var("AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN").ok();
        std::env::set_var("AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN", "42");
        std::env::set_var("AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN", "777");

        let limiter = EmailRateLimiter::from_env();
        assert_eq!(limiter.per_recipient_per_min(), 42);
        assert_eq!(limiter.per_domain_per_min(), 777);

        match prev_r {
            Some(v) => std::env::set_var("AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN", v),
            None => std::env::remove_var("AK_EMAIL_RATE_LIMIT_PER_RECIPIENT_PER_MIN"),
        }
        match prev_d {
            Some(v) => std::env::set_var("AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN", v),
            None => std::env::remove_var("AK_EMAIL_RATE_LIMIT_PER_DOMAIN_PER_MIN"),
        }
    }

    #[test]
    fn test_entry_count_grows_with_distinct_recipients() {
        // Sanity check that the recipient map keys on the lowercased
        // tuple, not on every input variant. Otherwise the map would
        // grow unboundedly under casing churn.
        let limiter = EmailRateLimiter::new(100, 1000);
        let s = sub();
        let now = Instant::now();
        let _ = limiter.try_acquire_at(s, "Alice@x.com", now);
        let _ = limiter.try_acquire_at(s, "alice@x.com", now);
        let _ = limiter.try_acquire_at(s, "ALICE@x.com", now);
        assert_eq!(limiter.recipient_entry_count(), 1);
    }

    #[test]
    fn test_recipient_map_prunes_idle_entries_past_soft_cap() {
        // Plant SOFT_CAP+1 distinct (sub, recipient) pairs at t0. Each
        // plant uses a DISTINCT domain so the per-domain bucket can't
        // bottleneck the seeding loop — the per-domain cap is 1000/min,
        // and reusing one domain across 10001 inserts would trip the
        // DomainLimited branch after 1000 calls. Then advance past
        // PRUNE_IDLE_THRESHOLD and trigger one more acquire — the lazy
        // prune fires and drops every stale entry.
        let limiter = EmailRateLimiter::new(100, 1000);
        let t0 = Instant::now();
        for i in 0..(RECIPIENT_MAP_SOFT_CAP + 1) {
            let s = Uuid::from_u128(i as u128);
            let addr = format!("a@d{}.com", i);
            assert_eq!(
                limiter.try_acquire_at(s, &addr, t0),
                RateLimitDecision::Allowed,
                "seed iteration {} should be Allowed",
                i
            );
        }
        assert!(limiter.recipient_entry_count() > RECIPIENT_MAP_SOFT_CAP);

        // Advance past the idle threshold so every planted entry's
        // `last_refill` is too old to survive the prune.
        let t1 = t0 + PRUNE_IDLE_THRESHOLD + Duration::from_secs(1);

        // One more acquire triggers the prune (first sweep, interval
        // gate is vacuously satisfied; map is still over cap).
        let trigger_sub = Uuid::from_u128(u128::MAX);
        let _ = limiter.try_acquire_at(trigger_sub, "trigger@x.com", t1);

        // After pruning, only the freshly-inserted trigger remains.
        assert_eq!(
            limiter.recipient_entry_count(),
            1,
            "pruner should have left only the trigger entry; got {}",
            limiter.recipient_entry_count()
        );
    }

    #[test]
    fn test_domain_map_prunes_idle_entries_past_soft_cap() {
        // Same property at the domain layer. The per-domain cap is small
        // so distinct addresses don't trip the per-domain limit and the
        // map fills cleanly.
        let limiter = EmailRateLimiter::new(100, 100);
        let s = sub();
        let t0 = Instant::now();
        for i in 0..(DOMAIN_MAP_SOFT_CAP + 1) {
            let addr = format!("a@d{}.com", i);
            assert_eq!(
                limiter.try_acquire_at(s, &addr, t0),
                RateLimitDecision::Allowed
            );
        }
        assert!(limiter.domain_entry_count() > DOMAIN_MAP_SOFT_CAP);

        let t1 = t0 + PRUNE_IDLE_THRESHOLD + Duration::from_secs(1);
        let _ = limiter.try_acquire_at(s, "trigger@trigger-domain.com", t1);
        assert_eq!(
            limiter.domain_entry_count(),
            1,
            "domain pruner should have left only the trigger; got {}",
            limiter.domain_entry_count()
        );
    }

    #[test]
    fn test_pruning_is_frequency_capped() {
        // After a prune, subsequent over-cap acquires within
        // `PRUNE_MIN_INTERVAL` must NOT trigger another sweep. This
        // closes the DoS amplification path where an attacker holds
        // the map at SOFT_CAP+1 with all-active buckets and forces
        // an O(N) scan on every dispatch (Security R2 B2).
        let limiter = EmailRateLimiter::new(100, 1000);
        let t0 = Instant::now();

        // First wave of stale plants. Distinct domains per address so
        // the per-domain bucket (1000/min) doesn't run dry mid-seed.
        for i in 0..(RECIPIENT_MAP_SOFT_CAP + 1) {
            let addr = format!("a@d{}.com", i);
            let _ = limiter.try_acquire_at(Uuid::from_u128(i as u128), &addr, t0);
        }
        let t1 = t0 + PRUNE_IDLE_THRESHOLD + Duration::from_secs(1);
        let _ = limiter.try_acquire_at(Uuid::from_u128(u128::MAX), "trigger@x.com", t1);
        assert_eq!(limiter.recipient_entry_count(), 1);

        // Second wave: fresh entries at t1 with `last_refill=t1`. These
        // would still be too young to evict on age. Re-cross the cap.
        // Same distinct-domain pattern as above.
        for i in 0..(RECIPIENT_MAP_SOFT_CAP + 1) {
            let addr = format!("b@d{}.com", i);
            let _ =
                limiter.try_acquire_at(Uuid::from_u128((i as u128) | (1u128 << 100)), &addr, t1);
        }
        assert!(limiter.recipient_entry_count() > RECIPIENT_MAP_SOFT_CAP);

        // 1s later — well inside PRUNE_MIN_INTERVAL (10s). Even though
        // we're over cap, the interval gate must suppress the sweep.
        let t2 = t1 + Duration::from_secs(1);
        let _ = limiter.try_acquire_at(Uuid::from_u128(u128::MAX - 1), "trigger2@x.com", t2);

        assert!(
            limiter.recipient_entry_count() > RECIPIENT_MAP_SOFT_CAP,
            "frequency cap should have suppressed second prune within interval; got {}",
            limiter.recipient_entry_count()
        );
    }
}
