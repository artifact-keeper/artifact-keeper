//! System-wide TOTP (2FA) enforcement policy (#2805).
//!
//! TOTP is implemented per user (enrollment, backup codes, login challenge) but
//! has historically been strictly opt-in. This module adds an operator-level
//! policy that can *require* enrollment, plus the lockout-safety rules that make
//! turning it on non-destructive.
//!
//! # Semantics
//!
//! * The policy has three values: [`TotpPolicy::Disabled`] (the default, which
//!   preserves the historical opt-in behaviour), [`TotpPolicy::RequiredForAdmins`]
//!   and [`TotpPolicy::RequiredForAll`].
//! * It is evaluated **only** on the interactive local password login
//!   (`POST /api/v1/auth/login`). API tokens, service accounts, package-client
//!   basic auth, already-issued sessions and the refresh grant are untouched, so
//!   turning the policy on never breaks CI or a running `docker pull`.
//! * SSO/LDAP/CI-authenticated users are exempt: their MFA is delegated to the
//!   identity provider, and Artifact Keeper holds no password for them.
//! * A subject user who has not enrolled is **not rejected**. Instead of a
//!   session, the login returns a short-lived *enrollment ticket* which
//!   authorizes exactly two calls — `/auth/totp/enroll/setup` and
//!   `/auth/totp/enroll/complete` — and the completing call issues the real
//!   session. The grace is "finish enrolling inside this login", never a
//!   countdown of days, so there is no moment at which a valid password stops
//!   yielding a way in.
//!
//! # Lockout safety
//!
//! Two independent guards, because "the operator cannot lock every admin out of
//! their own instance" has to hold even when the *client* is at fault:
//!
//! 1. [`check_policy_activation`] refuses to turn enforcement on unless the
//!    admin making the change already has TOTP enabled. That admin's login path
//!    (password + `/auth/totp/verify`) is the pre-existing, already-working one,
//!    so at least one administrator provably retains access no matter how the
//!    new enrollment exchange is handled by whatever UI is deployed.
//! 2. The `TOTP_POLICY` environment variable pins the effective policy and wins
//!    over the stored setting, so `TOTP_POLICY=disabled` plus a restart is an
//!    offline break-glass that needs no working login at all.
//!
//! Relaxing the policy (towards [`TotpPolicy::Disabled`], or from
//! `required_for_all` to `required_for_admins`) is never blocked: a guard that
//! can trap an operator in the strict state would defeat the point.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::models::user::AuthProvider;

/// The `system_settings` key the stored policy lives under.
pub const TOTP_POLICY_SETTING_KEY: &str = "security.totp_policy";

/// The environment variable that pins (and break-glass overrides) the policy.
pub const TOTP_POLICY_ENV_VAR: &str = "TOTP_POLICY";

/// System-wide 2FA enforcement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum TotpPolicy {
    /// TOTP stays strictly opt-in (historical behaviour, and the default).
    #[default]
    Disabled,
    /// Administrators must have TOTP enrolled.
    RequiredForAdmins,
    /// Every local user must have TOTP enrolled.
    RequiredForAll,
}

impl TotpPolicy {
    /// Canonical wire/storage spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            TotpPolicy::Disabled => "disabled",
            TotpPolicy::RequiredForAdmins => "required_for_admins",
            TotpPolicy::RequiredForAll => "required_for_all",
        }
    }

    /// Parse a stored/env spelling. Case- and whitespace-insensitive; returns
    /// `None` for anything unrecognized so callers can decide how to fail.
    ///
    /// Deliberately strict about *which* strings are accepted: a typo in
    /// `TOTP_POLICY` must not silently read as "required", nor silently read as
    /// "disabled" when the operator meant to enforce. Callers log and fall back.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disabled" | "off" | "none" => Some(TotpPolicy::Disabled),
            "required_for_admins" | "admins" => Some(TotpPolicy::RequiredForAdmins),
            "required_for_all" | "all" => Some(TotpPolicy::RequiredForAll),
            _ => None,
        }
    }

    /// Whether this policy enforces anything at all.
    pub fn is_enforcing(self) -> bool {
        !matches!(self, TotpPolicy::Disabled)
    }
}

/// Where the effective policy came from, surfaced on the admin read endpoint so
/// an operator can tell why a `PUT` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TotpPolicySource {
    /// Pinned by the `TOTP_POLICY` environment variable (not editable via API).
    Environment,
    /// Read from the `system_settings` table (editable via API).
    Database,
}

/// What the login flow must do about 2FA for one authenticating user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpLoginRequirement {
    /// Issue a session as usual — the policy has nothing to say about this user.
    NotRequired,
    /// The user already has TOTP enabled; the existing challenge path applies.
    ChallengeExisting,
    /// The policy applies and the user has not enrolled: return an enrollment
    /// ticket instead of a session.
    EnrollmentRequired,
}

/// Facts about the authenticating principal that the decision depends on.
///
/// A plain struct rather than five positional `bool`s so a caller cannot
/// transpose `is_admin` and `is_service_account` at a call site and silently
/// invert the policy.
#[derive(Debug, Clone, Copy)]
pub struct TotpSubject {
    pub auth_provider: AuthProvider,
    pub is_admin: bool,
    pub is_service_account: bool,
    pub totp_enabled: bool,
}

/// Decide what the login flow owes this user under `policy`.
///
/// Pure, so every branch is unit-testable without a database. The ordering
/// matters and is deliberate:
///
/// * `totp_enabled` wins first — an enrolled user is always challenged, even
///   under `disabled`, because per-user opt-in TOTP predates the policy and must
///   keep working.
/// * Service accounts are exempt next. They authenticate non-interactively and
///   cannot type a 6-digit code; enforcing here would break automation with no
///   security gain (their credentials are already single-purpose secrets).
/// * Non-local providers are exempt: MFA belongs to the IdP, and there is no
///   local password to be a first factor.
pub fn totp_login_requirement(policy: TotpPolicy, subject: TotpSubject) -> TotpLoginRequirement {
    if subject.totp_enabled {
        return TotpLoginRequirement::ChallengeExisting;
    }
    if subject.is_service_account {
        return TotpLoginRequirement::NotRequired;
    }
    if subject.auth_provider != AuthProvider::Local {
        return TotpLoginRequirement::NotRequired;
    }
    match policy {
        TotpPolicy::Disabled => TotpLoginRequirement::NotRequired,
        TotpPolicy::RequiredForAdmins if !subject.is_admin => TotpLoginRequirement::NotRequired,
        TotpPolicy::RequiredForAdmins | TotpPolicy::RequiredForAll => {
            TotpLoginRequirement::EnrollmentRequired
        }
    }
}

/// Whether the policy currently requires `subject` to keep TOTP enabled, used to
/// refuse `POST /auth/totp/disable` for a user the policy covers.
pub fn policy_requires_totp(policy: TotpPolicy, subject: TotpSubject) -> bool {
    matches!(
        totp_login_requirement(
            policy,
            TotpSubject {
                totp_enabled: false,
                ..subject
            }
        ),
        TotpLoginRequirement::EnrollmentRequired
    )
}

/// Why a policy change was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyActivationRefusal {
    /// `TOTP_POLICY` pins the policy; the stored setting has no effect.
    PinnedByEnvironment,
    /// The admin making the change has not enrolled in TOTP themselves.
    ActorNotEnrolled,
}

impl PolicyActivationRefusal {
    /// Operator-facing explanation, including the way out.
    pub fn message(self) -> &'static str {
        match self {
            PolicyActivationRefusal::PinnedByEnvironment => {
                "The TOTP enforcement policy is pinned by the TOTP_POLICY environment variable \
                 and cannot be changed through the API. Unset TOTP_POLICY and restart to manage \
                 it here."
            }
            PolicyActivationRefusal::ActorNotEnrolled => {
                "Enable TOTP on your own account before requiring it for others. This guarantees \
                 at least one administrator can still sign in if the enrollment flow does not \
                 work in your environment."
            }
        }
    }
}

/// Lockout-safety gate for a policy change.
///
/// * A change while the environment pins the policy is refused outright — it
///   would silently do nothing.
/// * *Loosening* is always permitted, including all the way to `disabled`.
///   Blocking a loosening move is how an operator gets trapped, which is the
///   opposite of what this guard is for.
/// * *Tightening* (any move that makes strictly more users subject to the
///   policy) requires the acting admin to already have TOTP enabled, so a
///   working, already-proven login survives the change regardless of how any
///   particular client handles the new enrollment exchange.
///
/// Pure: `actor_totp_enabled` is passed in rather than read here, so the whole
/// matrix is unit-testable without a database.
pub fn check_policy_activation(
    current: TotpPolicy,
    requested: TotpPolicy,
    pinned_by_env: bool,
    actor_totp_enabled: bool,
) -> Result<(), PolicyActivationRefusal> {
    if pinned_by_env {
        return Err(PolicyActivationRefusal::PinnedByEnvironment);
    }
    if !is_tightening(current, requested) {
        return Ok(());
    }
    if actor_totp_enabled {
        Ok(())
    } else {
        Err(PolicyActivationRefusal::ActorNotEnrolled)
    }
}

/// Whether moving from `current` to `requested` subjects strictly more users to
/// the policy. Ordered `disabled < required_for_admins < required_for_all`.
fn is_tightening(current: TotpPolicy, requested: TotpPolicy) -> bool {
    strictness(requested) > strictness(current)
}

fn strictness(policy: TotpPolicy) -> u8 {
    match policy {
        TotpPolicy::Disabled => 0,
        TotpPolicy::RequiredForAdmins => 1,
        TotpPolicy::RequiredForAll => 2,
    }
}

/// Read the stored policy from `system_settings`.
///
/// A missing row, a non-string value, or an unrecognized spelling all resolve to
/// [`TotpPolicy::Disabled`] — the *safe* direction for availability, since a
/// corrupt setting must not lock anyone out. The unrecognized case is logged so
/// it is not silent.
pub async fn stored_policy(db: &sqlx::PgPool) -> TotpPolicy {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM system_settings WHERE key = $1",
    )
    .bind(TOTP_POLICY_SETTING_KEY)
    .fetch_optional(db)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to read TOTP enforcement policy; treating as disabled");
        None
    })
    .flatten();

    let Some(raw) = value.as_ref().and_then(|v| v.as_str()) else {
        return TotpPolicy::Disabled;
    };
    TotpPolicy::parse(raw).unwrap_or_else(|| {
        tracing::warn!(
            value = %raw,
            "unrecognized {TOTP_POLICY_SETTING_KEY} value; treating as disabled"
        );
        TotpPolicy::Disabled
    })
}

/// The policy actually in force, together with where it came from.
///
/// `env_override` is [`crate::config::Config::totp_policy`], parsed once at
/// startup. When set it wins over the stored row: that is the documented
/// break-glass (`TOTP_POLICY=disabled` + restart) for an operator who cannot
/// complete the enrollment exchange with their client.
pub async fn effective_policy(
    db: &sqlx::PgPool,
    env_override: Option<TotpPolicy>,
) -> (TotpPolicy, TotpPolicySource) {
    match env_override {
        Some(policy) => (policy, TotpPolicySource::Environment),
        None => (stored_policy(db).await, TotpPolicySource::Database),
    }
}

/// Persist a new policy value, recording the admin who changed it.
pub async fn store_policy(
    db: &sqlx::PgPool,
    policy: TotpPolicy,
    updated_by: uuid::Uuid,
) -> crate::error::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO system_settings (key, value, description, updated_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (key) DO UPDATE
            SET value = $2, updated_by = $4, updated_at = NOW()
        "#,
    )
    .bind(TOTP_POLICY_SETTING_KEY)
    .bind(serde_json::Value::String(policy.as_str().to_owned()))
    .bind("TOTP 2FA enforcement policy: disabled | required_for_admins | required_for_all")
    .bind(updated_by)
    .execute(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(provider: AuthProvider, is_admin: bool) -> TotpSubject {
        TotpSubject {
            auth_provider: provider,
            is_admin,
            is_service_account: false,
            totp_enabled: false,
        }
    }

    #[test]
    fn parse_round_trips_every_canonical_spelling() {
        for policy in [
            TotpPolicy::Disabled,
            TotpPolicy::RequiredForAdmins,
            TotpPolicy::RequiredForAll,
        ] {
            assert_eq!(TotpPolicy::parse(policy.as_str()), Some(policy));
        }
    }

    #[test]
    fn parse_is_case_and_whitespace_insensitive_and_rejects_typos() {
        assert_eq!(
            TotpPolicy::parse("  Required_For_Admins "),
            Some(TotpPolicy::RequiredForAdmins)
        );
        // A typo must not read as either extreme.
        assert_eq!(TotpPolicy::parse("requird_for_all"), None);
        assert_eq!(TotpPolicy::parse(""), None);
        assert_eq!(TotpPolicy::parse("true"), None);
    }

    #[test]
    fn policy_serializes_snake_case_for_the_api() {
        assert_eq!(
            serde_json::to_string(&TotpPolicy::RequiredForAll).unwrap(),
            "\"required_for_all\""
        );
    }

    #[test]
    fn disabled_policy_requires_nothing() {
        assert_eq!(
            totp_login_requirement(TotpPolicy::Disabled, subject(AuthProvider::Local, true)),
            TotpLoginRequirement::NotRequired
        );
    }

    #[test]
    fn enrolled_user_is_always_challenged_even_under_disabled() {
        let s = TotpSubject {
            totp_enabled: true,
            ..subject(AuthProvider::Local, false)
        };
        assert_eq!(
            totp_login_requirement(TotpPolicy::Disabled, s),
            TotpLoginRequirement::ChallengeExisting
        );
        assert_eq!(
            totp_login_requirement(TotpPolicy::RequiredForAll, s),
            TotpLoginRequirement::ChallengeExisting
        );
    }

    #[test]
    fn required_for_admins_covers_admins_only() {
        assert_eq!(
            totp_login_requirement(
                TotpPolicy::RequiredForAdmins,
                subject(AuthProvider::Local, true)
            ),
            TotpLoginRequirement::EnrollmentRequired
        );
        assert_eq!(
            totp_login_requirement(
                TotpPolicy::RequiredForAdmins,
                subject(AuthProvider::Local, false)
            ),
            TotpLoginRequirement::NotRequired
        );
    }

    #[test]
    fn required_for_all_covers_non_admins_too() {
        assert_eq!(
            totp_login_requirement(
                TotpPolicy::RequiredForAll,
                subject(AuthProvider::Local, false)
            ),
            TotpLoginRequirement::EnrollmentRequired
        );
    }

    #[test]
    fn sso_ldap_and_ci_users_are_exempt_from_every_policy() {
        for provider in [
            AuthProvider::Ldap,
            AuthProvider::Saml,
            AuthProvider::Oidc,
            AuthProvider::Ci,
        ] {
            for policy in [TotpPolicy::RequiredForAdmins, TotpPolicy::RequiredForAll] {
                assert_eq!(
                    totp_login_requirement(policy, subject(provider, true)),
                    TotpLoginRequirement::NotRequired,
                    "{provider:?} under {policy:?} must delegate MFA to the IdP"
                );
            }
        }
    }

    #[test]
    fn service_accounts_are_exempt_so_automation_keeps_working() {
        let s = TotpSubject {
            is_service_account: true,
            ..subject(AuthProvider::Local, true)
        };
        assert_eq!(
            totp_login_requirement(TotpPolicy::RequiredForAll, s),
            TotpLoginRequirement::NotRequired
        );
    }

    #[test]
    fn policy_requires_totp_matches_the_login_decision() {
        assert!(policy_requires_totp(
            TotpPolicy::RequiredForAdmins,
            subject(AuthProvider::Local, true)
        ));
        assert!(!policy_requires_totp(
            TotpPolicy::RequiredForAdmins,
            subject(AuthProvider::Local, false)
        ));
        // An already-enrolled subject is still *required* to stay enrolled.
        let enrolled = TotpSubject {
            totp_enabled: true,
            ..subject(AuthProvider::Local, true)
        };
        assert!(policy_requires_totp(
            TotpPolicy::RequiredForAdmins,
            enrolled
        ));
        assert!(!policy_requires_totp(TotpPolicy::Disabled, enrolled));
    }

    #[test]
    fn tightening_requires_the_acting_admin_to_be_enrolled() {
        assert_eq!(
            check_policy_activation(
                TotpPolicy::Disabled,
                TotpPolicy::RequiredForAdmins,
                false,
                false
            ),
            Err(PolicyActivationRefusal::ActorNotEnrolled)
        );
        assert_eq!(
            check_policy_activation(
                TotpPolicy::Disabled,
                TotpPolicy::RequiredForAdmins,
                false,
                true
            ),
            Ok(())
        );
        // required_for_admins -> required_for_all is also a tightening.
        assert_eq!(
            check_policy_activation(
                TotpPolicy::RequiredForAdmins,
                TotpPolicy::RequiredForAll,
                false,
                false
            ),
            Err(PolicyActivationRefusal::ActorNotEnrolled)
        );
    }

    #[test]
    fn loosening_is_never_blocked_so_an_operator_cannot_be_trapped() {
        for (current, requested) in [
            (TotpPolicy::RequiredForAll, TotpPolicy::RequiredForAdmins),
            (TotpPolicy::RequiredForAll, TotpPolicy::Disabled),
            (TotpPolicy::RequiredForAdmins, TotpPolicy::Disabled),
        ] {
            assert_eq!(
                check_policy_activation(current, requested, false, false),
                Ok(()),
                "loosening {current:?} -> {requested:?} must always be allowed"
            );
        }
    }

    #[test]
    fn a_no_op_change_is_allowed_without_enrollment() {
        assert_eq!(
            check_policy_activation(
                TotpPolicy::RequiredForAll,
                TotpPolicy::RequiredForAll,
                false,
                false
            ),
            Ok(())
        );
    }

    #[test]
    fn env_pin_refuses_every_change_including_loosening() {
        // Loosening is refused here *because it would silently do nothing* --
        // the env var still wins. The break-glass is to unset it and restart,
        // which the refusal message says.
        assert_eq!(
            check_policy_activation(TotpPolicy::RequiredForAll, TotpPolicy::Disabled, true, true),
            Err(PolicyActivationRefusal::PinnedByEnvironment)
        );
    }

    #[test]
    fn refusal_messages_name_the_way_out() {
        assert!(PolicyActivationRefusal::PinnedByEnvironment
            .message()
            .contains("TOTP_POLICY"));
        assert!(PolicyActivationRefusal::ActorNotEnrolled
            .message()
            .contains("your own account"));
    }

    #[test]
    fn is_enforcing_only_for_the_required_variants() {
        assert!(!TotpPolicy::Disabled.is_enforcing());
        assert!(TotpPolicy::RequiredForAdmins.is_enforcing());
        assert!(TotpPolicy::RequiredForAll.is_enforcing());
        assert_eq!(TotpPolicy::default(), TotpPolicy::Disabled);
    }

    // -----------------------------------------------------------------------
    // DB-backed: the stored setting and the environment pin. These no-op
    // cleanly when DATABASE_URL is unset; CI provisions Postgres before
    // `cargo test --lib`.
    //
    // They serialize on one advisory lock because `system_settings` holds a
    // single row for this key — concurrent tests mutating it would flake.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn stored_policy_round_trips_and_env_pin_wins() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let _guard = crate::api::handlers::test_db_helpers::totp_policy_serial_lock().await;

        let before = stored_policy(&pool).await;
        // `system_settings.updated_by` is a real FK, so the writer must exist.
        let (admin, _) = crate::api::handlers::test_db_helpers::create_user(&pool).await;

        store_policy(&pool, TotpPolicy::RequiredForAll, admin)
            .await
            .expect("store");
        assert_eq!(stored_policy(&pool).await, TotpPolicy::RequiredForAll);

        // No env pin => the stored value governs, source is Database.
        assert_eq!(
            effective_policy(&pool, None).await,
            (TotpPolicy::RequiredForAll, TotpPolicySource::Database)
        );

        // Env pin wins in BOTH directions -- this is the offline break-glass.
        assert_eq!(
            effective_policy(&pool, Some(TotpPolicy::Disabled)).await,
            (TotpPolicy::Disabled, TotpPolicySource::Environment)
        );

        // A corrupt/unknown stored value must fail OPEN (disabled): a bad
        // setting must never lock everyone out.
        sqlx::query("UPDATE system_settings SET value = $2 WHERE key = $1")
            .bind(TOTP_POLICY_SETTING_KEY)
            .bind(serde_json::Value::String("bogus".to_owned()))
            .execute(&pool)
            .await
            .expect("corrupt the row");
        assert_eq!(stored_policy(&pool).await, TotpPolicy::Disabled);

        // A non-string JSON value likewise.
        sqlx::query("UPDATE system_settings SET value = $2 WHERE key = $1")
            .bind(TOTP_POLICY_SETTING_KEY)
            .bind(serde_json::json!(true))
            .execute(&pool)
            .await
            .expect("corrupt the row");
        assert_eq!(stored_policy(&pool).await, TotpPolicy::Disabled);

        store_policy(&pool, before, admin).await.expect("restore");
        crate::api::handlers::test_db_helpers::cleanup_user(&pool, admin).await;
    }
}
