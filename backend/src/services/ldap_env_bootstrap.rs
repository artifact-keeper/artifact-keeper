//! LDAP environment-variable bootstrap (#1434, #1887, #3904).
//!
//! `main.rs` reads the `LDAP_*` process environment and hands the raw values
//! to this module; the request assembly and every reconcile decision live in
//! the library so the crate's unit-test target covers them (`cargo test --lib`
//! does not build the binary target).
//!
//! # Ownership rule (#3904)
//!
//! The provider named by `LDAP_NAME` is reconciled on every boot. Before
//! #3904 the reconcile wrote every column the environment derived and forced
//! `is_enabled = true`, `priority = 0` and `use_starttls = false` (when
//! `LDAP_USE_STARTTLS` was unset), so an admin-API change to the provider was
//! undone, silently, by the next restart. The reconcile now applies a
//! *complete* desired configuration with explicit ownership, the #3507 OIDC
//! pattern:
//!
//! - a field the environment **sets this boot** is written (env wins);
//! - a field the environment **set on the previous boot and no longer sets**
//!   is reset to its default (nullable columns to NULL), so unsetting a
//!   variable removes its effect;
//! - **every other field** keeps whatever the admin API stored: the
//!   environment has no opinion about a value it never wrote. `is_enabled`,
//!   `priority`, `insecure_skip_verify` and `ca_certificate` are not derivable
//!   from `LDAP_*` at all and are never touched after the create.
//!
//! `admin_group_dn` is the exception, exactly like `OIDC_ADMIN_GROUP` (#3420):
//! it grants admin, so it is unconditionally env-owned on an env-managed
//! provider and an unset `LDAP_ADMIN_GROUP_DN` clears it.
//!
//! "Previously set" is the persisted `ldap_configs.env_owned_fields` record
//! (migration 255). A row with no record (created by the admin API, or by an
//! env bootstrap before the upgrade) is treated as owning nothing but the
//! always-owned fields, so the first boot after the upgrade preserves every
//! admin-set value the environment does not currently set. Every value the
//! reconcile overwrites or removes is logged at WARN, never silently.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::auth_config_service::{
    encryption_key, plan_provider_reconcile, AuthConfigService, CreateLdapConfigRequest,
    LdapConfigRow, ReconcileAction,
};
use crate::services::encryption::encrypt_credentials;

/// Default `user_filter` for a provider that does not set one.
pub const DEFAULT_USER_FILTER: &str = "(uid={0})";
/// Default `email_attribute`.
pub const DEFAULT_EMAIL_ATTRIBUTE: &str = "mail";
/// Default `display_name_attribute`.
pub const DEFAULT_DISPLAY_NAME_ATTRIBUTE: &str = "cn";
/// Default `username_attribute`.
pub const DEFAULT_USERNAME_ATTRIBUTE: &str = "uid";
/// Default `groups_attribute`.
pub const DEFAULT_GROUPS_ATTRIBUTE: &str = "memberOf";

/// Every `ldap_configs` column the `LDAP_*` environment can derive. Bounds the
/// persisted ownership record so a hand-edited row cannot make the reconcile
/// reset an unrelated column.
pub const DERIVABLE_FIELDS: [&str; 13] = [
    "server_url",
    "user_base_dn",
    "bind_dn",
    "bind_password",
    "user_filter",
    "group_base_dn",
    "group_filter",
    "email_attribute",
    "display_name_attribute",
    "username_attribute",
    "groups_attribute",
    "admin_group_dn",
    "use_starttls",
];

/// Fields the environment owns whether or not it set them last boot: an
/// elevation rule must not survive even one boot past the variable that
/// granted it (#3420).
pub const ALWAYS_ENV_OWNED_FIELDS: [&str; 1] = ["admin_group_dn"];

/// Raw LDAP environment variable values for bootstrap.
#[derive(Default, Debug, Clone)]
pub struct LdapEnvVars {
    pub name: Option<String>,
    pub url: Option<String>,
    pub base_dn: Option<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub user_filter: Option<String>,
    pub username_attr: Option<String>,
    pub email_attr: Option<String>,
    pub display_name_attr: Option<String>,
    pub groups_attr: Option<String>,
    pub group_base_dn: Option<String>,
    pub group_filter: Option<String>,
    pub admin_group_dn: Option<String>,
    pub use_starttls: Option<String>,
}

/// Assemble a `CreateLdapConfigRequest` from optional values.
///
/// Returns None if the LDAP server URL or base DN are missing or empty: both
/// are required to bind and search the directory. Every optional field is
/// `None` when its variable is unset or empty, including `use_starttls`: an
/// unset `LDAP_USE_STARTTLS` means "the environment has no opinion", not
/// "false" (#3904). A create still defaults it to false.
pub fn build_ldap_request_from_values(env: LdapEnvVars) -> Option<CreateLdapConfigRequest> {
    let server_url = env.url.filter(|v| !v.is_empty())?;
    let user_base_dn = env.base_dn.filter(|v| !v.is_empty())?;

    let name = env
        .name
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "default".to_string());

    let use_starttls = env
        .use_starttls
        .filter(|v| !v.is_empty())
        .map(|v| v == "true" || v == "1");

    Some(CreateLdapConfigRequest {
        name,
        server_url,
        bind_dn: env.bind_dn.filter(|v| !v.is_empty()),
        bind_password: env.bind_password.filter(|v| !v.is_empty()),
        user_base_dn,
        user_filter: env.user_filter.filter(|v| !v.is_empty()),
        group_base_dn: env.group_base_dn.filter(|v| !v.is_empty()),
        group_filter: env.group_filter.filter(|v| !v.is_empty()),
        email_attribute: env.email_attr.filter(|v| !v.is_empty()),
        display_name_attribute: env.display_name_attr.filter(|v| !v.is_empty()),
        username_attribute: env.username_attr.filter(|v| !v.is_empty()),
        groups_attribute: env.groups_attr.filter(|v| !v.is_empty()),
        admin_group_dn: env.admin_group_dn.filter(|v| !v.is_empty()),
        use_starttls,
        // TLS trust for the env-bootstrapped provider stays governed by the
        // global LDAP_INSECURE_TLS / LDAP_CA_CERT_PATH env fallback (#2782);
        // the per-provider overrides are set via the admin SSO API.
        insecure_skip_verify: None,
        ca_certificate: None,
        // Only applied on create. A reconcile never touches either (#3904).
        is_enabled: Some(true),
        priority: Some(0),
    })
}

/// The fields the environment sets this boot, in [`DERIVABLE_FIELDS`] order.
pub fn env_set_fields(env: &CreateLdapConfigRequest) -> Vec<String> {
    let set = [
        ("server_url", true),
        ("user_base_dn", true),
        ("bind_dn", env.bind_dn.is_some()),
        ("bind_password", env.bind_password.is_some()),
        ("user_filter", env.user_filter.is_some()),
        ("group_base_dn", env.group_base_dn.is_some()),
        ("group_filter", env.group_filter.is_some()),
        ("email_attribute", env.email_attribute.is_some()),
        (
            "display_name_attribute",
            env.display_name_attribute.is_some(),
        ),
        ("username_attribute", env.username_attribute.is_some()),
        ("groups_attribute", env.groups_attribute.is_some()),
        ("admin_group_dn", env.admin_group_dn.is_some()),
        ("use_starttls", env.use_starttls.is_some()),
    ];
    set.iter()
        .filter(|(_, is_set)| *is_set)
        .map(|(f, _)| f.to_string())
        .collect()
}

/// What a reconcile does with the stored bind password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretAction {
    /// Leave the stored (encrypted) value alone.
    Keep,
    /// Encrypt and store this value.
    Set(String),
    /// Remove the stored value.
    Clear,
}

/// A stored value the reconcile overwrites or removes, for the WARN line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardedField {
    pub field: &'static str,
    /// The stored value (`<redacted>` for the bind password).
    pub from: String,
    /// The value installed in its place, or `None` when it is reset/cleared.
    pub to: Option<String>,
}

/// The complete configuration an env reconcile writes for the env-derivable
/// columns. Columns the environment cannot derive are not represented and
/// are never written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapDesired {
    pub server_url: String,
    pub user_base_dn: String,
    pub bind_dn: Option<String>,
    pub user_filter: String,
    pub group_base_dn: Option<String>,
    pub group_filter: Option<String>,
    pub email_attribute: String,
    pub display_name_attribute: String,
    pub username_attribute: String,
    pub groups_attribute: String,
    pub admin_group_dn: Option<String>,
    pub use_starttls: bool,
}

/// Plan for one reconcile of an existing env-managed provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapReconcile {
    pub desired: LdapDesired,
    pub bind_password: SecretAction,
    /// Ownership record to persist for the next boot.
    pub env_owned_fields: Vec<String>,
    /// Stored values this reconcile overwrites or removes, sorted by field.
    pub discarded: Vec<DiscardedField>,
}

struct Resolver<'a> {
    owned_before: &'a [String],
    discarded: Vec<DiscardedField>,
}

impl Resolver<'_> {
    fn was_owned(&self, field: &str) -> bool {
        ALWAYS_ENV_OWNED_FIELDS.contains(&field) || self.owned_before.iter().any(|f| f == field)
    }

    /// Env value wins; an env-owned field the environment no longer sets
    /// resets to `unset`; anything else keeps its stored value.
    fn resolve<T: Clone + PartialEq>(
        &mut self,
        field: &'static str,
        current: T,
        env: Option<T>,
        unset: T,
        render: fn(&T) -> Option<String>,
    ) -> T {
        let next = match env {
            Some(v) => v,
            None if self.was_owned(field) => unset,
            None => return current,
        };
        if next != current {
            if let Some(from) = render(&current) {
                self.discarded.push(DiscardedField {
                    field,
                    from,
                    to: render(&next),
                });
            }
        }
        next
    }
}

fn render_opt(v: &Option<String>) -> Option<String> {
    v.clone()
}

// `fn(&T)` pointer shape with `T = String`; a `&str` parameter would not fit.
#[allow(clippy::ptr_arg)]
fn render_str(v: &String) -> Option<String> {
    Some(v.clone())
}

fn render_bool(v: &bool) -> Option<String> {
    Some(v.to_string())
}

/// Plan the reconcile of the env-managed provider `current` against the
/// environment's request (#3904). `previously_owned` is the row's persisted
/// `env_owned_fields` (`None` when it has never been recorded).
pub fn plan_ldap_reconcile(
    current: &LdapConfigRow,
    previously_owned: Option<&[String]>,
    env: &CreateLdapConfigRequest,
) -> LdapReconcile {
    let owned_before: Vec<String> = previously_owned
        .unwrap_or(&[])
        .iter()
        .filter(|f| DERIVABLE_FIELDS.contains(&f.as_str()))
        .cloned()
        .collect();
    let mut r = Resolver {
        owned_before: &owned_before,
        discarded: Vec::new(),
    };

    let desired = LdapDesired {
        server_url: r.resolve(
            "server_url",
            current.server_url.clone(),
            Some(env.server_url.clone()),
            env.server_url.clone(),
            render_str,
        ),
        user_base_dn: r.resolve(
            "user_base_dn",
            current.user_base_dn.clone(),
            Some(env.user_base_dn.clone()),
            env.user_base_dn.clone(),
            render_str,
        ),
        bind_dn: r.resolve(
            "bind_dn",
            current.bind_dn.clone(),
            env.bind_dn.clone().map(Some),
            None,
            render_opt,
        ),
        user_filter: r.resolve(
            "user_filter",
            current.user_filter.clone(),
            env.user_filter.clone(),
            DEFAULT_USER_FILTER.to_string(),
            render_str,
        ),
        group_base_dn: r.resolve(
            "group_base_dn",
            current.group_base_dn.clone(),
            env.group_base_dn.clone().map(Some),
            None,
            render_opt,
        ),
        group_filter: r.resolve(
            "group_filter",
            current.group_filter.clone(),
            env.group_filter.clone().map(Some),
            None,
            render_opt,
        ),
        email_attribute: r.resolve(
            "email_attribute",
            current.email_attribute.clone(),
            env.email_attribute.clone(),
            DEFAULT_EMAIL_ATTRIBUTE.to_string(),
            render_str,
        ),
        display_name_attribute: r.resolve(
            "display_name_attribute",
            current.display_name_attribute.clone(),
            env.display_name_attribute.clone(),
            DEFAULT_DISPLAY_NAME_ATTRIBUTE.to_string(),
            render_str,
        ),
        username_attribute: r.resolve(
            "username_attribute",
            current.username_attribute.clone(),
            env.username_attribute.clone(),
            DEFAULT_USERNAME_ATTRIBUTE.to_string(),
            render_str,
        ),
        groups_attribute: r.resolve(
            "groups_attribute",
            current.groups_attribute.clone(),
            env.groups_attribute.clone(),
            DEFAULT_GROUPS_ATTRIBUTE.to_string(),
            render_str,
        ),
        admin_group_dn: r.resolve(
            "admin_group_dn",
            current.admin_group_dn.clone(),
            env.admin_group_dn.clone().map(Some),
            None,
            render_opt,
        ),
        use_starttls: r.resolve(
            "use_starttls",
            current.use_starttls,
            env.use_starttls,
            false,
            render_bool,
        ),
    };

    // The password is stored encrypted, so it is not compared: a set variable
    // is always (re)written, and the value is never logged.
    let has_stored_password = current
        .bind_password_encrypted
        .as_deref()
        .is_some_and(|p| !p.is_empty());
    let bind_password = match &env.bind_password {
        Some(pw) => SecretAction::Set(pw.clone()),
        None if r.was_owned("bind_password") && has_stored_password => {
            r.discarded.push(DiscardedField {
                field: "bind_password",
                from: "<redacted>".to_string(),
                to: None,
            });
            SecretAction::Clear
        }
        None => SecretAction::Keep,
    };

    let mut discarded = r.discarded;
    discarded.sort_by(|a, b| a.field.cmp(b.field));

    LdapReconcile {
        desired,
        bind_password,
        env_owned_fields: env_set_fields(env),
        discarded,
    }
}

/// One-line summary of the discarded values, for the WARN line.
pub fn describe_discarded_fields(discarded: &[DiscardedField]) -> String {
    discarded
        .iter()
        .map(|d| match &d.to {
            Some(to) => format!("{} ('{}' -> '{}')", d.field, d.from, to),
            None => format!("{} ('{}' removed)", d.field, d.from),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Log the stored values an env reconcile throws away. Silent when nothing
/// is discarded, so a steady-state boot stays quiet.
pub fn warn_discarded_fields(provider_name: &str, discarded: &[DiscardedField]) {
    if discarded.is_empty() {
        return;
    }
    tracing::warn!(
        "LDAP provider '{}': the LDAP_* environment owns these fields and is discarding the \
         values currently stored for them: {}. Set the matching LDAP_* variable to the value \
         you want, or give the provider a name other than LDAP_NAME so the admin API owns it. \
         Fields the environment does not set are preserved.",
        provider_name,
        describe_discarded_fields(discarded)
    );
    if let Some(d) = discarded.iter().find(|d| d.field == "admin_group_dn") {
        if d.to.is_none() {
            tracing::warn!(
                "LDAP provider '{}': LDAP_ADMIN_GROUP_DN is not set, so the persisted admin group \
                 '{}' is cleared: nobody is newly granted admin through it. Users already \
                 granted admin keep it -- with no admin group configured neither login nor the \
                 LDAP directory reconcile changes is_admin -- until an administrator removes \
                 it. Set LDAP_ADMIN_GROUP_DN to keep the group; the env bootstrap owns this \
                 field.",
                provider_name,
                d.from
            );
        }
    }
    if discarded
        .iter()
        .any(|d| d.field == "use_starttls" && d.from == "true" && d.to.as_deref() == Some("false"))
    {
        tracing::warn!(
            "LDAP provider '{}': STARTTLS is being turned OFF by the LDAP_* environment \
             (LDAP_USE_STARTTLS unset or false). Unless the URL is ldaps://, bind passwords -- \
             the service account's and every user's -- now cross the network in plaintext. Set \
             LDAP_USE_STARTTLS=true to keep it on.",
            provider_name
        );
    }
}

/// The env-derivable fields an admin-API update changes (#3904): each one
/// present in the request with a value different from the stored one. The
/// bind password cannot be compared (stored encrypted), so sending one counts
/// as a change.
pub fn admin_changed_fields(
    current: &LdapConfigRow,
    req: &crate::services::auth_config_service::UpdateLdapConfigRequest,
) -> Vec<String> {
    fn differs<T: PartialEq>(new: &Option<T>, old: &T) -> bool {
        new.as_ref().is_some_and(|n| n != old)
    }
    fn differs_opt(new: &Option<String>, old: &Option<String>) -> bool {
        new.as_ref().is_some_and(|n| Some(n) != old.as_ref())
    }
    let changed = [
        ("server_url", differs(&req.server_url, &current.server_url)),
        (
            "user_base_dn",
            differs(&req.user_base_dn, &current.user_base_dn),
        ),
        ("bind_dn", differs_opt(&req.bind_dn, &current.bind_dn)),
        ("bind_password", req.bind_password.is_some()),
        (
            "user_filter",
            differs(&req.user_filter, &current.user_filter),
        ),
        (
            "group_base_dn",
            differs_opt(&req.group_base_dn, &current.group_base_dn),
        ),
        (
            "group_filter",
            differs_opt(&req.group_filter, &current.group_filter),
        ),
        (
            "email_attribute",
            differs(&req.email_attribute, &current.email_attribute),
        ),
        (
            "display_name_attribute",
            differs(&req.display_name_attribute, &current.display_name_attribute),
        ),
        (
            "username_attribute",
            differs(&req.username_attribute, &current.username_attribute),
        ),
        (
            "groups_attribute",
            differs(&req.groups_attribute, &current.groups_attribute),
        ),
        (
            "admin_group_dn",
            differs_opt(&req.admin_group_dn, &current.admin_group_dn),
        ),
        (
            "use_starttls",
            differs(&req.use_starttls, &current.use_starttls),
        ),
    ];
    changed
        .iter()
        .filter(|(_, c)| *c)
        .map(|(f, _)| f.to_string())
        .collect()
}

/// Drop `fields` from a provider's env-ownership record (#3904).
pub async fn release_env_ownership(pool: &PgPool, id: Uuid, fields: &[String]) -> Result<()> {
    if fields.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "UPDATE ldap_configs          SET env_owned_fields = ARRAY(SELECT f FROM unnest(env_owned_fields) AS f                                       WHERE f <> ALL($1))          WHERE id = $2 AND env_owned_fields IS NOT NULL",
    )
    .bind(fields)
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Outcome of one boot's reconcile, for the caller's log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapEnvOutcome {
    /// No provider existed; the env-managed one was created.
    Created { id: Uuid, name: String },
    /// The env-managed provider was reconciled in place.
    Reconciled {
        id: Uuid,
        name: String,
        discarded: Vec<DiscardedField>,
    },
    /// Other providers exist but none carries the env-managed name.
    Skipped { existing_name: String },
}

/// The stored row, without decrypting the bind password: the reconcile never
/// needs the plaintext, and a key rotation must not fail the boot.
async fn load_ldap_row(pool: &PgPool, id: Uuid) -> Result<LdapConfigRow> {
    sqlx::query_as::<_, LdapConfigRow>(
        r#"
        SELECT id, name, server_url, bind_dn, bind_password_encrypted,
               user_base_dn, user_filter, group_base_dn, group_filter,
               email_attribute, display_name_attribute, username_attribute,
               groups_attribute, admin_group_dn, use_starttls,
               insecure_skip_verify, ca_certificate,
               is_enabled, priority, created_at, updated_at
        FROM ldap_configs
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound(format!("LDAP config {id} not found")))
}

async fn load_env_owned_fields(pool: &PgPool, id: Uuid) -> Result<Option<Vec<String>>> {
    let owned: Option<Option<Vec<String>>> =
        sqlx::query_scalar("SELECT env_owned_fields FROM ldap_configs WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(owned.flatten())
}

async fn store_env_owned_fields(pool: &PgPool, id: Uuid, fields: &[String]) -> Result<()> {
    sqlx::query("UPDATE ldap_configs SET env_owned_fields = $1 WHERE id = $2")
        .bind(fields)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Write a planned reconcile: the env-derivable columns, the password per
/// [`SecretAction`], and the ownership record, in one UPDATE.
async fn apply_ldap_reconcile(pool: &PgPool, id: Uuid, plan: &LdapReconcile) -> Result<()> {
    let (write_password, password_hex) = match &plan.bind_password {
        SecretAction::Keep => (false, None),
        SecretAction::Set(pw) => (
            true,
            Some(hex::encode(encrypt_credentials(pw, &encryption_key()))),
        ),
        SecretAction::Clear => (true, None),
    };
    let d = &plan.desired;
    sqlx::query(
        r#"
        UPDATE ldap_configs
        SET server_url = $1, user_base_dn = $2, bind_dn = $3, user_filter = $4,
            group_base_dn = $5, group_filter = $6, email_attribute = $7,
            display_name_attribute = $8, username_attribute = $9,
            groups_attribute = $10, admin_group_dn = $11, use_starttls = $12,
            bind_password_encrypted = CASE WHEN $13 THEN $14::text
                                           ELSE bind_password_encrypted END,
            env_owned_fields = $15, updated_at = NOW()
        WHERE id = $16
        "#,
    )
    .bind(&d.server_url)
    .bind(&d.user_base_dn)
    .bind(&d.bind_dn)
    .bind(&d.user_filter)
    .bind(&d.group_base_dn)
    .bind(&d.group_filter)
    .bind(&d.email_attribute)
    .bind(&d.display_name_attribute)
    .bind(&d.username_attribute)
    .bind(&d.groups_attribute)
    .bind(&d.admin_group_dn)
    .bind(d.use_starttls)
    .bind(write_password)
    .bind(password_hex)
    .bind(&plan.env_owned_fields)
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Reconcile the env-managed LDAP provider for this boot (#3904). See the
/// module docs for the ownership rule.
pub async fn reconcile_ldap_from_env(
    pool: &PgPool,
    req: CreateLdapConfigRequest,
) -> Result<LdapEnvOutcome> {
    let existing = AuthConfigService::list_ldap(pool).await?;
    let pairs: Vec<(Uuid, String)> = existing.iter().map(|c| (c.id, c.name.clone())).collect();

    match plan_provider_reconcile(&req.name, &pairs) {
        ReconcileAction::Create => {
            let owned = env_set_fields(&req);
            let config = AuthConfigService::create_ldap(pool, req).await?;
            store_env_owned_fields(pool, config.id, &owned).await?;
            Ok(LdapEnvOutcome::Created {
                id: config.id,
                name: config.name,
            })
        }
        ReconcileAction::Update(id) => {
            let row = load_ldap_row(pool, id).await?;
            let owned_before = load_env_owned_fields(pool, id).await?;
            let plan = plan_ldap_reconcile(&row, owned_before.as_deref(), &req);
            apply_ldap_reconcile(pool, id, &plan).await?;
            Ok(LdapEnvOutcome::Reconciled {
                id,
                name: req.name,
                discarded: plan.discarded,
            })
        }
        ReconcileAction::Skip(existing_name) => Ok(LdapEnvOutcome::Skipped { existing_name }),
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // build_ldap_request_from_values (issue #1434)
    // -----------------------------------------------------------------------

    fn ldap_env(url: Option<&str>, base_dn: Option<&str>) -> LdapEnvVars {
        LdapEnvVars {
            url: url.map(String::from),
            base_dn: base_dn.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_ldap_bootstrap_request_required_fields() {
        let req = build_ldap_request_from_values(ldap_env(
            Some("ldap://dc.local:389"),
            Some("DC=domain,DC=local"),
        ))
        .unwrap();

        assert_eq!(req.name, "default");
        assert_eq!(req.server_url, "ldap://dc.local:389");
        assert_eq!(req.user_base_dn, "DC=domain,DC=local");
        // Bootstrapped providers are enabled so they show up in the SSO list.
        assert_eq!(req.is_enabled, Some(true));
        assert_eq!(req.priority, Some(0));
        // Unset LDAP_USE_STARTTLS is "no opinion", not "false" (#3904); a
        // create still stores false via `create_ldap`'s default.
        assert_eq!(req.use_starttls, None);
    }

    #[test]
    fn test_ldap_bootstrap_request_name_override() {
        // LDAP_NAME lets operators point the env-managed provider at an
        // existing one, mirroring OIDC_NAME (#1887).
        let req = build_ldap_request_from_values(LdapEnvVars {
            name: Some("Corporate AD".to_string()),
            url: Some("ldap://dc.local:389".to_string()),
            base_dn: Some("DC=domain,DC=local".to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(req.name, "Corporate AD");
    }

    #[test]
    fn test_ldap_bootstrap_request_empty_name_defaults() {
        let req = build_ldap_request_from_values(LdapEnvVars {
            name: Some("".to_string()),
            url: Some("ldap://dc.local:389".to_string()),
            base_dn: Some("DC=domain,DC=local".to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(req.name, "default");
    }

    #[test]
    fn test_ldap_bootstrap_request_missing_url() {
        let req = build_ldap_request_from_values(ldap_env(None, Some("DC=domain,DC=local")));
        assert!(req.is_none());
    }

    #[test]
    fn test_ldap_bootstrap_request_missing_base_dn() {
        let req = build_ldap_request_from_values(ldap_env(Some("ldap://dc.local:389"), None));
        assert!(req.is_none());
    }

    #[test]
    fn test_ldap_bootstrap_request_empty_url() {
        let req = build_ldap_request_from_values(ldap_env(Some(""), Some("DC=domain,DC=local")));
        assert!(req.is_none());
    }

    #[test]
    fn test_ldap_bootstrap_request_empty_base_dn() {
        let req = build_ldap_request_from_values(ldap_env(Some("ldap://dc.local:389"), Some("")));
        assert!(req.is_none());
    }

    #[test]
    fn test_ldap_bootstrap_request_full_active_directory_config() {
        // Mirrors the Active Directory example from issue #1434.
        let req = build_ldap_request_from_values(LdapEnvVars {
            name: None,
            url: Some("ldap://dc.local:389".to_string()),
            base_dn: Some("DC=domain,DC=local".to_string()),
            bind_dn: Some("user@domain".to_string()),
            bind_password: Some("superPassword".to_string()),
            user_filter: Some("(sAMAccountName={0})".to_string()),
            username_attr: Some("sAMAccountName".to_string()),
            email_attr: None,
            display_name_attr: None,
            groups_attr: None,
            group_base_dn: Some("OU=Groups,DC=domain,DC=local".to_string()),
            group_filter: Some("(memberUid={0})".to_string()),
            admin_group_dn: Some("CN=admin_users_group,OU=Groups,DC=domain,DC=local".to_string()),
            use_starttls: Some("false".to_string()),
        })
        .unwrap();

        assert_eq!(req.bind_dn.as_deref(), Some("user@domain"));
        assert_eq!(req.bind_password.as_deref(), Some("superPassword"));
        assert_eq!(req.user_filter.as_deref(), Some("(sAMAccountName={0})"));
        assert_eq!(req.username_attribute.as_deref(), Some("sAMAccountName"));
        assert_eq!(
            req.group_base_dn.as_deref(),
            Some("OU=Groups,DC=domain,DC=local")
        );
        assert_eq!(req.group_filter.as_deref(), Some("(memberUid={0})"));
        assert_eq!(
            req.admin_group_dn.as_deref(),
            Some("CN=admin_users_group,OU=Groups,DC=domain,DC=local")
        );
        assert_eq!(req.use_starttls, Some(false));
        assert_eq!(req.is_enabled, Some(true));
    }

    #[test]
    fn test_ldap_bootstrap_request_starttls_truthy_values() {
        for v in ["true", "1"] {
            let req = build_ldap_request_from_values(LdapEnvVars {
                url: Some("ldap://dc.local:389".to_string()),
                base_dn: Some("DC=domain,DC=local".to_string()),
                use_starttls: Some(v.to_string()),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(
                req.use_starttls,
                Some(true),
                "value {v} should enable STARTTLS"
            );
        }
    }

    #[test]
    fn test_ldap_bootstrap_request_empty_optional_fields_become_none() {
        // Empty strings (e.g. unset compose interpolations) must not produce
        // empty bind DNs or filters that would break directory binds.
        let req = build_ldap_request_from_values(LdapEnvVars {
            url: Some("ldap://dc.local:389".to_string()),
            base_dn: Some("DC=domain,DC=local".to_string()),
            bind_dn: Some("".to_string()),
            bind_password: Some("".to_string()),
            user_filter: Some("".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert!(req.bind_dn.is_none());
        assert!(req.bind_password.is_none());
        assert!(req.user_filter.is_none());
    }

    // -----------------------------------------------------------------------
    // plan_ldap_reconcile (#3904)
    // -----------------------------------------------------------------------

    fn row() -> LdapConfigRow {
        LdapConfigRow {
            id: Uuid::nil(),
            name: "default".into(),
            server_url: "ldap://dc.local:389".into(),
            bind_dn: None,
            bind_password_encrypted: None,
            user_base_dn: "DC=domain,DC=local".into(),
            user_filter: DEFAULT_USER_FILTER.into(),
            group_base_dn: None,
            group_filter: None,
            email_attribute: DEFAULT_EMAIL_ATTRIBUTE.into(),
            display_name_attribute: DEFAULT_DISPLAY_NAME_ATTRIBUTE.into(),
            username_attribute: DEFAULT_USERNAME_ATTRIBUTE.into(),
            groups_attribute: DEFAULT_GROUPS_ATTRIBUTE.into(),
            admin_group_dn: None,
            use_starttls: false,
            insecure_skip_verify: false,
            ca_certificate: None,
            is_enabled: true,
            priority: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn base_env() -> CreateLdapConfigRequest {
        build_ldap_request_from_values(ldap_env(
            Some("ldap://dc.local:389"),
            Some("DC=domain,DC=local"),
        ))
        .unwrap()
    }

    fn owned(fields: &[&str]) -> Vec<String> {
        fields.iter().map(|f| f.to_string()).collect()
    }

    /// The #3904 headline: fields an admin set through the admin API that the
    /// environment does not set survive the boot. Before the fix the
    /// reconcile forced `use_starttls` back to false whenever
    /// `LDAP_USE_STARTTLS` was unset.
    #[test]
    fn test_reconcile_preserves_admin_set_fields_env_does_not_set() {
        let mut current = row();
        current.use_starttls = true;
        current.user_filter = "(&(objectClass=user)(sAMAccountName={0}))".into();
        current.group_base_dn = Some("OU=Groups,DC=domain,DC=local".into());
        current.bind_password_encrypted = Some("abcd".into());

        let plan = plan_ldap_reconcile(
            &current,
            Some(owned(&["server_url"]).as_slice()),
            &base_env(),
        );

        assert!(plan.desired.use_starttls, "admin-set STARTTLS must survive");
        assert_eq!(
            plan.desired.user_filter,
            "(&(objectClass=user)(sAMAccountName={0}))"
        );
        assert_eq!(
            plan.desired.group_base_dn.as_deref(),
            Some("OU=Groups,DC=domain,DC=local")
        );
        assert_eq!(plan.bind_password, SecretAction::Keep);
        assert!(plan.discarded.is_empty(), "{:?}", plan.discarded);
        assert_eq!(
            plan.env_owned_fields,
            owned(&["server_url", "user_base_dn"])
        );
    }

    /// A row with no ownership record (admin-created, or pre-upgrade) keeps
    /// everything the environment does not currently set.
    #[test]
    fn test_reconcile_legacy_row_without_record_owns_only_what_env_sets() {
        let mut current = row();
        current.group_filter = Some("(member={0})".into());
        current.email_attribute = "userPrincipalName".into();
        let plan = plan_ldap_reconcile(&current, None, &base_env());
        assert_eq!(plan.desired.group_filter.as_deref(), Some("(member={0})"));
        assert_eq!(plan.desired.email_attribute, "userPrincipalName");
        assert!(plan.discarded.is_empty());
    }

    #[test]
    fn test_reconcile_env_set_field_wins_and_is_reported() {
        let mut current = row();
        current.user_filter = "(cn={0})".into();
        let mut env = base_env();
        env.user_filter = Some("(sAMAccountName={0})".into());
        let plan = plan_ldap_reconcile(&current, None, &env);
        assert_eq!(plan.desired.user_filter, "(sAMAccountName={0})");
        assert_eq!(
            plan.discarded,
            vec![DiscardedField {
                field: "user_filter",
                from: "(cn={0})".into(),
                to: Some("(sAMAccountName={0})".into()),
            }]
        );
        assert!(plan.env_owned_fields.contains(&"user_filter".to_string()));
    }

    /// Unsetting a variable the environment set last boot removes its effect:
    /// nullable columns go to NULL, defaulted ones back to the default.
    #[test]
    fn test_reconcile_resets_env_owned_field_when_variable_unset() {
        let mut current = row();
        current.group_filter = Some("(member={0})".into());
        current.username_attribute = "sAMAccountName".into();
        current.use_starttls = true;
        current.bind_password_encrypted = Some("abcd".into());
        let before = owned(&[
            "group_filter",
            "username_attribute",
            "use_starttls",
            "bind_password",
        ]);
        let plan = plan_ldap_reconcile(&current, Some(before.as_slice()), &base_env());
        assert_eq!(plan.desired.group_filter, None);
        assert_eq!(plan.desired.username_attribute, DEFAULT_USERNAME_ATTRIBUTE);
        assert!(!plan.desired.use_starttls);
        assert_eq!(plan.bind_password, SecretAction::Clear);
        let fields: Vec<&str> = plan.discarded.iter().map(|d| d.field).collect();
        assert_eq!(
            fields,
            vec![
                "bind_password",
                "group_filter",
                "use_starttls",
                "username_attribute"
            ]
        );
        let pw = &plan.discarded[0];
        assert_eq!(pw.from, "<redacted>", "a password must never be logged");
    }

    /// `admin_group_dn` grants admin, so it is env-owned even without a
    /// record: an unset LDAP_ADMIN_GROUP_DN clears it (#3420 parity).
    #[test]
    fn test_reconcile_admin_group_dn_is_always_env_owned() {
        let mut current = row();
        current.admin_group_dn = Some("CN=admins,DC=domain,DC=local".into());
        let plan = plan_ldap_reconcile(&current, None, &base_env());
        assert_eq!(plan.desired.admin_group_dn, None);
        assert_eq!(plan.discarded.len(), 1);
        assert_eq!(plan.discarded[0].field, "admin_group_dn");
        assert_eq!(plan.discarded[0].to, None);
    }

    /// A hand-edited record naming a column the env cannot derive is ignored.
    #[test]
    fn test_reconcile_ignores_non_derivable_fields_in_record() {
        let current = row();
        let plan = plan_ldap_reconcile(
            &current,
            Some(owned(&["is_enabled", "priority"]).as_slice()),
            &base_env(),
        );
        assert!(plan.discarded.is_empty());
    }

    #[test]
    fn test_reconcile_env_password_is_set() {
        let mut env = base_env();
        env.bind_password = Some("s3cret".into());
        let plan = plan_ldap_reconcile(&row(), None, &env);
        assert_eq!(plan.bind_password, SecretAction::Set("s3cret".into()));
        assert!(plan.env_owned_fields.contains(&"bind_password".to_string()));
    }

    #[test]
    fn test_describe_discarded_fields() {
        let d = vec![
            DiscardedField {
                field: "a",
                from: "x".into(),
                to: Some("y".into()),
            },
            DiscardedField {
                field: "b",
                from: "z".into(),
                to: None,
            },
        ];
        assert_eq!(
            describe_discarded_fields(&d),
            "a ('x' -> 'y'), b ('z' removed)"
        );
        warn_discarded_fields("p", &d);
        warn_discarded_fields("p", &[]);
    }

    #[test]
    fn test_env_set_fields_lists_only_set_variables() {
        let mut env = base_env();
        env.use_starttls = Some(false);
        env.admin_group_dn = Some("CN=a".into());
        assert_eq!(
            env_set_fields(&env),
            owned(&[
                "server_url",
                "user_base_dn",
                "admin_group_dn",
                "use_starttls"
            ])
        );
    }

    // -----------------------------------------------------------------------
    // reconcile_ldap_from_env across two boots, against a real database
    // -----------------------------------------------------------------------

    async fn stored(pool: &PgPool, id: Uuid) -> (LdapConfigRow, Option<Vec<String>>) {
        (
            load_ldap_row(pool, id).await.expect("row"),
            load_env_owned_fields(pool, id).await.expect("owned"),
        )
    }

    /// Two boots with an admin-API edit in between (#3904). Isolated database
    /// because `plan_provider_reconcile` keys off *every* LDAP row.
    #[tokio::test]
    async fn test_two_boots_preserve_admin_edits_and_apply_env_changes() {
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;

        // Boot 1: env sets the group filter and an admin group; no STARTTLS.
        let mut env = base_env();
        env.group_filter = Some("(member={0})".into());
        env.admin_group_dn = Some("CN=admins,DC=domain,DC=local".into());
        let id = match reconcile_ldap_from_env(pool, env.clone()).await.unwrap() {
            LdapEnvOutcome::Created { id, .. } => id,
            other => panic!("expected create, got {other:?}"),
        };
        let (_, rec) = stored(pool, id).await;
        assert_eq!(
            rec.unwrap(),
            owned(&[
                "server_url",
                "user_base_dn",
                "group_filter",
                "admin_group_dn"
            ])
        );

        // Admin API: enable STARTTLS, disable the provider, bump priority,
        // set a user filter the environment does not set.
        AuthConfigService::update_ldap(
            pool,
            id,
            crate::services::auth_config_service::UpdateLdapConfigRequest {
                user_filter: Some("(sAMAccountName={0})".into()),
                use_starttls: Some(true),
                is_enabled: Some(false),
                priority: Some(7),
                ..empty_update()
            },
        )
        .await
        .unwrap();

        // Boot 2: same variables, except LDAP_GROUP_FILTER is now unset.
        env.group_filter = None;
        match reconcile_ldap_from_env(pool, env.clone()).await.unwrap() {
            LdapEnvOutcome::Reconciled {
                id: rid, discarded, ..
            } => {
                assert_eq!(rid, id);
                let fields: Vec<&str> = discarded.iter().map(|d| d.field).collect();
                assert_eq!(fields, vec!["group_filter"]);
            }
            other => panic!("expected reconcile, got {other:?}"),
        }
        let (row2, rec2) = stored(pool, id).await;
        assert!(row2.use_starttls, "admin-set STARTTLS must survive a boot");
        assert!(!row2.is_enabled, "admin disable must survive a boot");
        assert_eq!(row2.priority, 7, "admin priority must survive a boot");
        assert_eq!(row2.user_filter, "(sAMAccountName={0})");
        assert_eq!(row2.group_filter, None, "unset env-owned field is removed");
        assert_eq!(
            row2.admin_group_dn.as_deref(),
            Some("CN=admins,DC=domain,DC=local")
        );
        assert_eq!(
            rec2.unwrap(),
            owned(&["server_url", "user_base_dn", "admin_group_dn"])
        );

        // Boot 3: LDAP_ADMIN_GROUP_DN removed -> the elevation rule goes.
        env.admin_group_dn = None;
        reconcile_ldap_from_env(pool, env).await.unwrap();
        let (row3, _) = stored(pool, id).await;
        assert_eq!(row3.admin_group_dn, None);
        assert!(row3.use_starttls);
    }

    fn empty_update() -> crate::services::auth_config_service::UpdateLdapConfigRequest {
        crate::services::auth_config_service::UpdateLdapConfigRequest {
            name: None,
            server_url: None,
            bind_dn: None,
            bind_password: None,
            user_base_dn: None,
            user_filter: None,
            group_base_dn: None,
            group_filter: None,
            email_attribute: None,
            display_name_attribute: None,
            username_attribute: None,
            groups_attribute: None,
            admin_group_dn: None,
            use_starttls: None,
            insecure_skip_verify: None,
            ca_certificate: None,
            is_enabled: None,
            priority: None,
        }
    }

    #[test]
    fn test_admin_changed_fields_lists_only_real_changes() {
        let current = row();
        let mut req = empty_update();
        req.user_filter = Some(DEFAULT_USER_FILTER.into()); // unchanged
        req.group_filter = Some("(member={0})".into());
        req.use_starttls = Some(true);
        req.bind_password = Some("x".into());
        req.is_enabled = Some(false); // not env-derivable
        assert_eq!(
            admin_changed_fields(&current, &req),
            owned(&["bind_password", "group_filter", "use_starttls"])
        );
    }

    /// Review nit on #3904: an admin edit of an env-owned field hands the
    /// field to the admin, so removing the variable later keeps the admin's
    /// value instead of resetting it.
    #[tokio::test]
    async fn test_admin_edit_takes_ownership_of_env_owned_field() {
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let mut env = base_env();
        env.group_filter = Some("(member={0})".into());
        let LdapEnvOutcome::Created { id, .. } =
            reconcile_ldap_from_env(pool, env.clone()).await.unwrap()
        else {
            panic!("expected create");
        };
        let mut req = empty_update();
        req.group_filter = Some("(uniqueMember={0})".into());
        AuthConfigService::update_ldap(pool, id, req).await.unwrap();
        let (_, rec) = stored(pool, id).await;
        assert_eq!(rec.unwrap(), owned(&["server_url", "user_base_dn"]));

        env.group_filter = None;
        reconcile_ldap_from_env(pool, env).await.unwrap();
        let (row, _) = stored(pool, id).await;
        assert_eq!(row.group_filter.as_deref(), Some("(uniqueMember={0})"));
    }

    #[test]
    fn test_starttls_downgrade_and_admin_group_warnings() {
        warn_discarded_fields(
            "p",
            &[
                DiscardedField {
                    field: "admin_group_dn",
                    from: "cn=admins".into(),
                    to: None,
                },
                DiscardedField {
                    field: "use_starttls",
                    from: "true".into(),
                    to: Some("false".into()),
                },
            ],
        );
    }
}
