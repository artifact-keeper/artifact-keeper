//! Admin-configurable API token expiration policy (#3460).
//!
//! Historically `expires_in_days: None` minted a token that never expires.
//! This module adds an operator-level policy that can *require* an expiration
//! on newly-minted API tokens, bound it to an acceptable range, and apply a
//! default when the caller does not specify one — without ever touching tokens
//! that already exist.
//!
//! # Semantics
//!
//! * The policy is evaluated **only at mint time**, inside the single
//!   choke-point [`crate::services::auth_service::AuthService::generate_api_token_with_policy`],
//!   which every token-creating handler (personal, profile, repo-scoped,
//!   service-account) funnels through. Tokens minted before the policy was
//!   enabled keep working: `validate_api_token` continues to honour whatever
//!   `expires_at` (including `NULL`) is stamped on the row, so enabling the
//!   policy on upgrade can never lock a running pipeline out. The admin
//!   endpoint surfaces a count of live never-expiring tokens instead, so an
//!   operator can rotate them deliberately.
//! * When the policy requires an expiration and the request omits one, the
//!   configured `default_days` is applied (instead of rejecting), so older
//!   clients that never send `expires_in_days` keep working the moment the
//!   policy is switched on. Only an explicitly out-of-range request is
//!   rejected, with an error that states the permitted range.
//! * Service-account tokens are **exempt by default**
//!   (`apply_to_service_accounts: false`): they are the credentials CI
//!   pipelines run on, and a mandatory expiry there is an outage on a
//!   schedule. Operators whose compliance posture requires it can opt them in
//!   explicitly.
//!
//! # Configuration
//!
//! Mirrors the TOTP enforcement policy (#2805): the policy lives in the
//! key/value `system_settings` table (runtime-editable via
//! `GET/PUT /api/v1/admin/settings/token-policy`), and the
//! `API_TOKEN_EXPIRATION_*` environment variables pin it when
//! `API_TOKEN_EXPIRATION_REQUIRED` is set. The env pin wins over the stored
//! row in BOTH directions, so `API_TOKEN_EXPIRATION_REQUIRED=false` plus a
//! restart is an offline break-glass that needs no working login at all.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The `system_settings` key the stored policy lives under.
pub const TOKEN_POLICY_SETTING_KEY: &str = "security.api_token_expiry_policy";

/// Hard ceiling on any token expiration, mirroring the `clamp(1, 3650)`
/// historically applied in `generate_api_token`.
pub const ABSOLUTE_MAX_EXPIRY_DAYS: i64 = 3650;

/// Environment variables that pin (and break-glass override) the policy.
/// The pin is active iff `API_TOKEN_EXPIRATION_REQUIRED` parses as a bool;
/// the remaining variables refine the pinned policy and fall back to the
/// defaults below when unset.
pub const ENV_REQUIRED: &str = "API_TOKEN_EXPIRATION_REQUIRED";
pub const ENV_DAYS_MIN: &str = "API_TOKEN_EXPIRATION_DAYS_MIN";
pub const ENV_DAYS_MAX: &str = "API_TOKEN_EXPIRATION_DAYS_MAX";
pub const ENV_DAYS_DEFAULT: &str = "API_TOKEN_EXPIRATION_DAYS_DEFAULT";
pub const ENV_INCLUDE_SERVICE_ACCOUNTS: &str = "API_TOKEN_EXPIRATION_INCLUDE_SERVICE_ACCOUNTS";

/// The API token expiration policy, as stored and as served by the admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiTokenExpiryPolicy {
    /// When false the policy is entirely inert (historical behaviour).
    pub require_expiration: bool,
    /// Minimum acceptable `expires_in_days` while enforcing (inclusive).
    pub min_days: i64,
    /// Maximum acceptable `expires_in_days` while enforcing (inclusive).
    pub max_days: i64,
    /// Applied when an enforced request omits `expires_in_days`. `None`
    /// means such requests are rejected instead.
    #[serde(default)]
    pub default_days: Option<i64>,
    /// Whether service-account token mints are subject to the policy.
    /// Defaults to false: expiring the credential a pipeline runs on is an
    /// outage on a schedule, so it must be an explicit opt-in.
    #[serde(default)]
    pub apply_to_service_accounts: bool,
}

impl Default for ApiTokenExpiryPolicy {
    fn default() -> Self {
        Self {
            require_expiration: false,
            min_days: 1,
            max_days: 90,
            default_days: Some(90),
            apply_to_service_accounts: false,
        }
    }
}

impl ApiTokenExpiryPolicy {
    /// Validate internal consistency before the policy is stored or pinned.
    ///
    /// Deliberately strict: a policy whose `default_days` falls outside its
    /// own `[min_days, max_days]` range would make every defaulted mint fail,
    /// which is exactly the upgrade-lockout this feature is designed to avoid.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_days < 1 {
            return Err("min_days must be at least 1".to_string());
        }
        if self.max_days < self.min_days {
            return Err(format!(
                "max_days ({}) must be >= min_days ({})",
                self.max_days, self.min_days
            ));
        }
        if self.max_days > ABSOLUTE_MAX_EXPIRY_DAYS {
            return Err(format!(
                "max_days ({}) must be <= {ABSOLUTE_MAX_EXPIRY_DAYS}",
                self.max_days
            ));
        }
        if let Some(d) = self.default_days {
            if d < self.min_days || d > self.max_days {
                return Err(format!(
                    "default_days ({d}) must fall within [min_days, max_days] = [{}, {}]",
                    self.min_days, self.max_days
                ));
            }
        }
        // `require_expiration && default_days.is_none()` is legal but sharp:
        // clients that omit expires_in_days will be rejected outright. Allowed
        // (an operator may want exactly that) — validation only rejects
        // self-contradiction.
        Ok(())
    }

    /// Build the environment pin from raw env values. Returns `None` (no pin,
    /// stored setting governs) unless `required` parses as a boolean. A pin
    /// that fails [`Self::validate`] is dropped with a warning rather than
    /// silently misconfiguring enforcement — same failure posture as the
    /// `TOTP_POLICY` pin.
    pub fn from_env_values(
        required: Option<&str>,
        min_days: Option<&str>,
        max_days: Option<&str>,
        default_days: Option<&str>,
        include_service_accounts: Option<&str>,
    ) -> Option<Self> {
        let required = match required.map(str::trim) {
            None | Some("") => return None,
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                other => {
                    tracing::warn!(
                        value = %other,
                        "{ENV_REQUIRED} is set but not a boolean; ignoring the \
                         API token expiration policy env pin"
                    );
                    return None;
                }
            },
        };
        let defaults = Self::default();
        let parse_days = |name: &str, raw: Option<&str>, fallback: i64| -> Option<i64> {
            match raw.map(str::trim) {
                None | Some("") => Some(fallback),
                Some(v) => match v.parse::<i64>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        tracing::warn!(value = %v, "{name} is not an integer; ignoring the pin");
                        None
                    }
                },
            }
        };
        let policy = Self {
            require_expiration: required,
            min_days: parse_days(ENV_DAYS_MIN, min_days, defaults.min_days)?,
            max_days: parse_days(ENV_DAYS_MAX, max_days, defaults.max_days)?,
            default_days: match default_days.map(str::trim) {
                None | Some("") => defaults.default_days,
                Some(v) if v.eq_ignore_ascii_case("none") => None,
                Some(v) => match v.parse::<i64>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        tracing::warn!(
                            value = %v,
                            "{ENV_DAYS_DEFAULT} is not an integer or 'none'; ignoring the pin"
                        );
                        return None;
                    }
                },
            },
            apply_to_service_accounts: matches!(
                include_service_accounts.map(str::trim),
                Some("true") | Some("1")
            ),
        };
        match policy.validate() {
            Ok(()) => Some(policy),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "API_TOKEN_EXPIRATION_* env pin is inconsistent; ignoring the pin and \
                     using the stored {TOKEN_POLICY_SETTING_KEY} setting"
                );
                None
            }
        }
    }
}

/// Where the effective policy came from, surfaced on the admin read endpoint
/// so an operator can tell why a `PUT` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenPolicySource {
    /// Pinned by `API_TOKEN_EXPIRATION_*` env vars (not editable via API).
    Environment,
    /// Read from the `system_settings` table (editable via API).
    Database,
}

/// Outcome of resolving a mint request against the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedExpiry {
    /// The expiration to actually stamp on the token.
    pub expires_in_days: Option<i64>,
    /// True when the policy changed or constrained the outcome (an applied
    /// default or an enforced range), for the response and the audit trail.
    pub policy_applied: bool,
}

/// Decide what expiration a mint request gets under `policy`.
///
/// Pure, so every branch is unit-testable without a database. Returns
/// `Err(message)` when the request must be rejected; the message names the
/// permitted range so a client can self-correct.
pub fn resolve_expiry(
    policy: &ApiTokenExpiryPolicy,
    requested_days: Option<i64>,
    is_service_account: bool,
) -> Result<ResolvedExpiry, String> {
    if !policy.require_expiration || (is_service_account && !policy.apply_to_service_accounts) {
        return Ok(ResolvedExpiry {
            expires_in_days: requested_days,
            policy_applied: false,
        });
    }
    match requested_days {
        None => match policy.default_days {
            Some(d) => Ok(ResolvedExpiry {
                expires_in_days: Some(d),
                policy_applied: true,
            }),
            None => Err(format!(
                "This instance requires API tokens to expire: set expires_in_days \
                 between {} and {} days",
                policy.min_days, policy.max_days
            )),
        },
        Some(d) if d < policy.min_days || d > policy.max_days => Err(format!(
            "expires_in_days ({d}) violates this instance's token expiration policy: \
             it must be between {} and {} days",
            policy.min_days, policy.max_days
        )),
        Some(d) => Ok(ResolvedExpiry {
            expires_in_days: Some(d),
            policy_applied: true,
        }),
    }
}

/// Read the stored policy, falling back to the (inert) default on any read or
/// parse failure. Failing open to "inert" is deliberate for the same reason
/// the mint-time-only design is: a transient settings-read failure must not
/// start rejecting token mints, and it cannot weaken anything already minted.
pub async fn stored_policy(db: &sqlx::PgPool) -> ApiTokenExpiryPolicy {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
            .bind(TOKEN_POLICY_SETTING_KEY)
            .fetch_optional(db)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "failed to read API token expiration policy; treating as not enforced"
                );
                None
            })
            .flatten();
    let Some(raw) = value else {
        return ApiTokenExpiryPolicy::default();
    };
    match serde_json::from_value::<ApiTokenExpiryPolicy>(raw) {
        Ok(policy) => policy,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "unrecognized {TOKEN_POLICY_SETTING_KEY} value; treating as not enforced"
            );
            ApiTokenExpiryPolicy::default()
        }
    }
}

/// The policy actually in force, together with where it came from.
pub async fn effective_policy(
    db: &sqlx::PgPool,
    env_override: Option<ApiTokenExpiryPolicy>,
) -> (ApiTokenExpiryPolicy, TokenPolicySource) {
    match env_override {
        Some(policy) => (policy, TokenPolicySource::Environment),
        None => (stored_policy(db).await, TokenPolicySource::Database),
    }
}

/// Persist a new policy value, recording the admin who changed it.
pub async fn store_policy(
    db: &sqlx::PgPool,
    policy: &ApiTokenExpiryPolicy,
    updated_by: uuid::Uuid,
) -> crate::error::Result<()> {
    let value = serde_json::to_value(policy)
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    sqlx::query(
        r#"
        INSERT INTO system_settings (key, value, description, updated_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (key) DO UPDATE
            SET value = $2, updated_by = $4, updated_at = NOW()
        "#,
    )
    .bind(TOKEN_POLICY_SETTING_KEY)
    .bind(value)
    .bind("API token expiration policy (#3460): mint-time enforcement of mandatory token expiry")
    .bind(updated_by)
    .execute(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
    Ok(())
}

/// Cap a to-be-minted access token's expiry at the expiry of the credential
/// it was exchanged from: a `/v2/token` exchange must never yield a bearer
/// that outlives the credential that produced it, otherwise re-exchanging
/// before each JWT expiry would renew access indefinitely and any expiration
/// on the underlying credential (including this policy's) would be escaped.
pub fn cap_access_expiry(
    base_exp: DateTime<Utc>,
    credential_exp: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    match credential_exp {
        Some(cap) if cap < base_exp => cap,
        _ => base_exp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforcing() -> ApiTokenExpiryPolicy {
        ApiTokenExpiryPolicy {
            require_expiration: true,
            min_days: 1,
            max_days: 90,
            default_days: Some(90),
            apply_to_service_accounts: false,
        }
    }

    #[test]
    fn default_policy_is_inert_and_valid() {
        let p = ApiTokenExpiryPolicy::default();
        assert!(!p.require_expiration);
        assert!(p.validate().is_ok());
        // Negative control: with the default policy a never-expiring request
        // passes through untouched — the pre-#3460 behaviour.
        let r = resolve_expiry(&p, None, false).expect("inert policy accepts None");
        assert_eq!(r.expires_in_days, None);
        assert!(!r.policy_applied);
        // And an explicit long expiry is not range-checked while inert.
        let r = resolve_expiry(&p, Some(3650), false).expect("inert policy accepts 3650");
        assert_eq!(r.expires_in_days, Some(3650));
        assert!(!r.policy_applied);
    }

    #[test]
    fn enforced_policy_defaults_an_omitted_expiry() {
        let r = resolve_expiry(&enforcing(), None, false).expect("default applies");
        assert_eq!(r.expires_in_days, Some(90));
        assert!(r.policy_applied);
    }

    #[test]
    fn enforced_policy_without_default_rejects_an_omitted_expiry() {
        let p = ApiTokenExpiryPolicy {
            default_days: None,
            ..enforcing()
        };
        let err = resolve_expiry(&p, None, false).expect_err("must reject");
        assert!(
            err.contains("requires API tokens to expire"),
            "error must explain the policy: {err}"
        );
        assert!(
            err.contains("between 1 and 90 days"),
            "error names range: {err}"
        );
    }

    #[test]
    fn enforced_policy_rejects_out_of_range_and_accepts_boundaries() {
        let p = enforcing();
        for bad in [0, -5, 91, 3650] {
            let err = resolve_expiry(&p, Some(bad), false).expect_err("out of range");
            assert!(
                err.contains("must be between 1 and 90 days"),
                "error names the permitted range: {err}"
            );
        }
        for good in [1, 45, 90] {
            let r = resolve_expiry(&p, Some(good), false).expect("in range");
            assert_eq!(r.expires_in_days, Some(good));
            assert!(r.policy_applied);
        }
    }

    #[test]
    fn service_accounts_are_exempt_unless_opted_in() {
        let p = enforcing();
        // Exempt by default: a service-account mint with no expiry passes.
        let r = resolve_expiry(&p, None, true).expect("SA exempt");
        assert_eq!(r.expires_in_days, None);
        assert!(!r.policy_applied);
        // Opting in subjects service accounts to the same rules.
        let p = ApiTokenExpiryPolicy {
            apply_to_service_accounts: true,
            ..p
        };
        let r = resolve_expiry(&p, None, true).expect("defaulted");
        assert_eq!(r.expires_in_days, Some(90));
        assert!(r.policy_applied);
        assert!(resolve_expiry(&p, Some(400), true).is_err());
    }

    #[test]
    fn validate_rejects_inconsistent_policies() {
        let base = enforcing();
        assert!(ApiTokenExpiryPolicy {
            min_days: 0,
            ..base
        }
        .validate()
        .is_err());
        assert!(ApiTokenExpiryPolicy {
            max_days: 0,
            ..base
        }
        .validate()
        .is_err());
        assert!(
            ApiTokenExpiryPolicy {
                max_days: 3651,
                ..base
            }
            .validate()
            .is_err(),
            "max_days above the absolute ceiling must be refused"
        );
        assert!(
            ApiTokenExpiryPolicy {
                default_days: Some(91),
                ..base
            }
            .validate()
            .is_err(),
            "default outside [min, max] would make every defaulted mint fail"
        );
        assert!(
            ApiTokenExpiryPolicy {
                default_days: None,
                ..base
            }
            .validate()
            .is_ok(),
            "no default is legal (explicit-expiry-only posture)"
        );
    }

    #[test]
    fn env_pin_parses_and_validates() {
        // No pin unless REQUIRED is set to a bool.
        assert_eq!(
            ApiTokenExpiryPolicy::from_env_values(None, None, None, None, None),
            None
        );
        assert_eq!(
            ApiTokenExpiryPolicy::from_env_values(Some("maybe"), None, None, None, None),
            None
        );
        // REQUIRED=false is a real pin (the offline break-glass).
        let p = ApiTokenExpiryPolicy::from_env_values(Some("false"), None, None, None, None)
            .expect("pin");
        assert!(!p.require_expiration);
        // Full pin round-trips values.
        let p = ApiTokenExpiryPolicy::from_env_values(
            Some("true"),
            Some("7"),
            Some("180"),
            Some("30"),
            Some("true"),
        )
        .expect("pin");
        assert_eq!(
            p,
            ApiTokenExpiryPolicy {
                require_expiration: true,
                min_days: 7,
                max_days: 180,
                default_days: Some(30),
                apply_to_service_accounts: true,
            }
        );
        // default_days=none disables the default (reject omitted expiry).
        let p = ApiTokenExpiryPolicy::from_env_values(Some("true"), None, None, Some("none"), None)
            .expect("pin");
        assert_eq!(p.default_days, None);
        // An inconsistent pin is dropped, not half-applied.
        assert_eq!(
            ApiTokenExpiryPolicy::from_env_values(Some("true"), Some("30"), Some("7"), None, None),
            None
        );
    }

    /// DB-backed: stored policy round-trips and the env pin wins in both
    /// directions. No-ops cleanly when DATABASE_URL is unset (CI provisions
    /// Postgres before `cargo test --lib`).
    #[tokio::test]
    async fn stored_policy_round_trips_and_env_pin_wins() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let _guard = crate::api::handlers::test_db_helpers::token_policy_serial_lock().await;

        let before = stored_policy(&pool).await;
        // `system_settings.updated_by` is a real FK, so the writer must exist.
        let (admin, _) = crate::api::handlers::test_db_helpers::create_user(&pool).await;

        let enforced_policy = ApiTokenExpiryPolicy {
            require_expiration: true,
            min_days: 2,
            max_days: 45,
            default_days: Some(10),
            apply_to_service_accounts: true,
        };
        store_policy(&pool, &enforced_policy, admin)
            .await
            .expect("store");
        assert_eq!(stored_policy(&pool).await, enforced_policy);

        // No env pin => the stored value governs, source is Database.
        assert_eq!(
            effective_policy(&pool, None).await,
            (enforced_policy, TokenPolicySource::Database)
        );

        // Env pin wins in BOTH directions — this is the offline break-glass:
        // an inert pin turns enforcement off no matter what is stored.
        let inert_pin = ApiTokenExpiryPolicy::default();
        assert_eq!(
            effective_policy(&pool, Some(inert_pin)).await,
            (inert_pin, TokenPolicySource::Environment)
        );

        store_policy(&pool, &before, admin).await.expect("restore");
        crate::api::handlers::test_db_helpers::cleanup_user(&pool, admin).await;
    }

    #[test]
    fn cap_access_expiry_never_extends() {
        let now = Utc::now();
        let base = now + chrono::Duration::minutes(30);
        // No credential expiry: base stands.
        assert_eq!(cap_access_expiry(base, None), base);
        // Credential outlives the JWT: base stands.
        assert_eq!(
            cap_access_expiry(base, Some(now + chrono::Duration::days(30))),
            base
        );
        // Credential expires first: the bearer is capped to it.
        let sooner = now + chrono::Duration::minutes(5);
        assert_eq!(cap_access_expiry(base, Some(sooner)), sooner);
    }
}
