//! OIDC environment-variable bootstrap: the pure half.
//!
//! `main.rs` reads the `OIDC_*` process environment and hands the raw values
//! to this module; everything that decides *what* the per-boot reconcile
//! should do lives in the library so the crate's unit-test target covers it.
//! `cargo test --lib` — which is what CI runs — does not build the binary
//! target, so logic kept in `main.rs` is effectively unenforced.

use serde_json::Value;

use crate::services::auth_config_service::CreateOidcConfigRequest;

/// Raw OIDC environment variable values for bootstrap.
#[derive(Default)]
pub struct OidcEnvVars {
    pub name: Option<String>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<String>,
    pub groups_claim: Option<String>,
    pub admin_group: Option<String>,
    pub redirect_uri: Option<String>,
    pub username_claim: Option<String>,
    pub email_claim: Option<String>,
    pub map_groups_to_groups: Option<String>,
    pub auto_create_users: Option<String>,
    pub pkce_enabled: Option<String>,
}

/// Pure function that assembles a CreateOidcConfigRequest from optional values.
/// Returns None if issuer, client_id, or client_secret are missing or empty.
pub fn build_oidc_request_from_values(env: OidcEnvVars) -> Option<CreateOidcConfigRequest> {
    let issuer = env.issuer.filter(|v| !v.is_empty())?;
    let client_id = env.client_id.filter(|v| !v.is_empty())?;
    let client_secret = env.client_secret.filter(|v| !v.is_empty())?;
    let name = env
        .name
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "default".to_string());

    let scopes = env
        .scopes
        .map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>());

    let mut attr_map = serde_json::Map::new();
    // Insert groups_claim ONLY when explicitly configured (mirrors
    // username_claim/email_claim below). Leaving it absent lets the OIDC
    // callback's multi-name candidate resolution engage, so an env-bootstrapped
    // GitLab provider (which publishes under `groups_direct`) syncs groups
    // without the operator having to set OIDC_GROUPS_CLAIM (#2831).
    if let Some(claim) = env.groups_claim.filter(|v| !v.is_empty()) {
        attr_map.insert("groups_claim".into(), serde_json::Value::String(claim));
    }
    if let Some(uri) = env.redirect_uri {
        attr_map.insert("redirect_uri".into(), serde_json::Value::String(uri));
    }
    if let Some(claim) = env.username_claim {
        attr_map.insert("username_claim".into(), serde_json::Value::String(claim));
    }
    if let Some(claim) = env.email_claim {
        attr_map.insert("email_claim".into(), serde_json::Value::String(claim));
    }

    // Provider toggles configurable via env for GitOps/disconnected deploys
    // (#2792). Absent vars preserve the prior bootstrap defaults so existing
    // deployments are unaffected: `auto_create_users` stays on, while
    // `map_groups_to_groups` (#1879, pairs with #2781) and `pkce_enabled` fall
    // through to the service-layer create defaults (false / true respectively).
    // Accepts "true"/"1" (case-sensitive, mirroring the LDAP bootstrap).
    let env_flag = |v: String| v == "true" || v == "1";
    let map_groups_to_groups = env.map_groups_to_groups.map(env_flag);
    let pkce_enabled = env.pkce_enabled.map(env_flag);
    let auto_create_users = Some(env.auto_create_users.map(env_flag).unwrap_or(true));

    let admin_group = env.admin_group.filter(|v| !v.is_empty());

    Some(CreateOidcConfigRequest {
        name,
        issuer_url: issuer,
        client_id,
        client_secret,
        scopes,
        attribute_mapping: Some(serde_json::Value::Object(attr_map)),
        is_enabled: Some(true),
        auto_create_users,
        pkce_enabled,
        map_groups_to_groups,
        admin_group,
        allow_legacy_rsa_keys: None,
    })
}

/// What the per-boot env reconcile does to an env-managed provider's admin
/// group, so the caller can log the transition instead of changing an
/// elevation rule silently.
///
/// `OIDC_ADMIN_GROUP` is **env-definitive**, like every other key the
/// bootstrap writes: the reconcile replaces `attribute_mapping` wholesale, so
/// a variable that is no longer set clears the persisted value. Unsetting the
/// variable and redeploying is how an operator revokes group-based admin, and
/// it has to actually revoke it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminGroupReconcile {
    /// The environment supplies a value the provider does not already carry.
    /// `from` is the value being replaced, if there was one.
    Set { from: Option<String>, to: String },
    /// The environment supplies no value and the provider carried one, which
    /// this boot clears: group-based admin elevation stops.
    Cleared(String),
    /// Nothing changes — both sides agree, or neither side has a value.
    Unchanged,
}

/// Classify the admin-group transition an env reconcile is about to apply.
///
/// `env_admin_group` is the value the environment supplies (already normalised
/// to `None` for an empty variable by [`build_oidc_request_from_values`]);
/// `existing_mapping` is the provider's currently persisted
/// `attribute_mapping`. This only *describes* the transition — the change
/// itself is carried by the wholesale `attribute_mapping` replacement, so the
/// classification cannot drift from the behaviour by being skipped.
pub fn plan_admin_group_reconcile(
    env_admin_group: Option<&str>,
    existing_mapping: &Value,
) -> AdminGroupReconcile {
    let persisted = existing_mapping.get("admin_group").and_then(|v| v.as_str());

    match (env_admin_group, persisted) {
        (Some(env), Some(cur)) if env == cur => AdminGroupReconcile::Unchanged,
        (Some(env), cur) => AdminGroupReconcile::Set {
            from: cur.map(String::from),
            to: env.to_string(),
        },
        (None, Some(cur)) => AdminGroupReconcile::Cleared(cur.to_string()),
        (None, None) => AdminGroupReconcile::Unchanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // build_oidc_request_from_values
    // -----------------------------------------------------------------------

    fn env(
        issuer: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
    ) -> OidcEnvVars {
        OidcEnvVars {
            issuer: issuer.map(String::from),
            client_id: client_id.map(String::from),
            client_secret: client_secret.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_bootstrap_request_all_required_fields() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("my-client"),
            Some("my-secret"),
        ))
        .unwrap();

        assert_eq!(req.name, "default");
        assert_eq!(req.issuer_url, "https://idp.example.com");
        assert_eq!(req.client_id, "my-client");
        assert_eq!(req.client_secret, "my-secret");
        assert_eq!(req.is_enabled, Some(true));
        assert_eq!(req.auto_create_users, Some(true));
    }

    #[test]
    fn test_bootstrap_request_custom_name() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.name = Some("Corporate SSO".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.name, "Corporate SSO");
    }

    #[test]
    fn test_bootstrap_request_empty_name_defaults_to_default() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.name = Some(String::new());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.name, "default");
    }

    #[test]
    fn test_bootstrap_request_missing_issuer() {
        let req = build_oidc_request_from_values(env(None, Some("client"), Some("secret")));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_missing_client_id() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            None,
            Some("secret"),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_missing_client_secret() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            None,
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_issuer() {
        let req = build_oidc_request_from_values(env(Some(""), Some("client"), Some("secret")));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_client_id() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some(""),
            Some("secret"),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_client_secret() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some(""),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_default_groups_claim_absent() {
        // When OIDC_GROUPS_CLAIM is unset, groups_claim must NOT be persisted,
        // so the OIDC callback's multi-name candidate fallback can engage for
        // env-bootstrapped GitLab providers (#2831).
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert!(attr.as_object().unwrap().get("groups_claim").is_none());
    }

    #[test]
    fn test_bootstrap_request_custom_groups_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.groups_claim = Some("roles".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["groups_claim"], "roles");
    }

    #[test]
    fn test_bootstrap_request_admin_group() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.admin_group = Some("ArtifactKeeperAdmins".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.admin_group.as_deref(), Some("ArtifactKeeperAdmins"));
    }

    /// An empty `OIDC_ADMIN_GROUP=` must not become an admin group named "".
    /// `""` would be persisted into `attribute_mapping.admin_group` and the
    /// login path would then compare IdP group names against it, so the empty
    /// filter is load-bearing rather than cosmetic.
    #[test]
    fn test_bootstrap_request_empty_admin_group_is_none() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.admin_group = Some(String::new());
        let req = build_oidc_request_from_values(e).unwrap();

        assert!(req.admin_group.is_none());
    }

    /// Forward guard, not evidence of the #3420 fix: with the variable absent
    /// this holds on both sides of the change. It pins that an unset variable
    /// contributes nothing — neither the request field nor an `admin_group`
    /// key smuggled into the attribute mapping — which is what makes the
    /// reconcile's wholesale mapping replacement clear a persisted group.
    #[test]
    fn test_bootstrap_request_no_admin_group() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        assert!(req.admin_group.is_none());
        let attr = req.attribute_mapping.unwrap();
        assert!(!attr.as_object().unwrap().contains_key("admin_group"));
    }

    #[test]
    fn test_bootstrap_request_scopes_parsing() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.scopes = Some("openid email profile offline_access".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(
            req.scopes.unwrap(),
            vec!["openid", "email", "profile", "offline_access"]
        );
    }

    #[test]
    fn test_bootstrap_request_no_scopes() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        assert!(req.scopes.is_none());
    }

    #[test]
    fn test_bootstrap_request_redirect_uri() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.redirect_uri = Some("https://app.example.com/callback".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["redirect_uri"], "https://app.example.com/callback");
    }

    #[test]
    fn test_bootstrap_request_no_redirect_uri() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert!(attr.get("redirect_uri").is_none());
    }

    #[test]
    fn test_bootstrap_request_custom_username_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.username_claim = Some("upn".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["username_claim"], "upn");
    }

    #[test]
    fn test_bootstrap_request_custom_email_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.email_claim = Some("mail".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["email_claim"], "mail");
    }

    #[test]
    fn test_bootstrap_request_default_toggles() {
        // With none of the toggle env vars set, the bootstrap request preserves
        // the historical defaults: auto_create_users forced on, and
        // map_groups_to_groups / pkce_enabled left to the service-layer create
        // defaults (None -> false / true respectively) (#2792).
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        assert_eq!(req.auto_create_users, Some(true));
        assert_eq!(req.map_groups_to_groups, None);
        assert_eq!(req.pkce_enabled, None);
    }

    #[test]
    fn test_bootstrap_request_map_groups_to_groups_enabled() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.map_groups_to_groups = Some("true".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.map_groups_to_groups, Some(true));
    }

    #[test]
    fn test_bootstrap_request_map_groups_to_groups_numeric_true() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.map_groups_to_groups = Some("1".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.map_groups_to_groups, Some(true));
    }

    #[test]
    fn test_bootstrap_request_map_groups_to_groups_disabled() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.map_groups_to_groups = Some("false".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.map_groups_to_groups, Some(false));
    }

    #[test]
    fn test_bootstrap_request_auto_create_users_override() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.auto_create_users = Some("false".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.auto_create_users, Some(false));
    }

    #[test]
    fn test_bootstrap_request_auto_create_users_explicit_true() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.auto_create_users = Some("1".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.auto_create_users, Some(true));
    }

    #[test]
    fn test_bootstrap_request_pkce_enabled_override() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.pkce_enabled = Some("false".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.pkce_enabled, Some(false));
    }

    #[test]
    fn test_bootstrap_request_pkce_enabled_true() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.pkce_enabled = Some("true".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.pkce_enabled, Some(true));
    }

    #[test]
    fn test_bootstrap_request_all_optional_fields() {
        let req = build_oidc_request_from_values(OidcEnvVars {
            name: Some("Corporate OIDC".into()),
            issuer: Some("https://auth.corp.com/realms/main".into()),
            client_id: Some("artifact-keeper".into()),
            client_secret: Some("super-secret-123".into()),
            scopes: Some("openid email profile".into()),
            groups_claim: Some("roles".into()),
            admin_group: Some("platform-admins".into()),
            redirect_uri: Some("https://app.corp.com/sso/callback".into()),
            username_claim: Some("samaccountname".into()),
            email_claim: Some("mail".into()),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(req.name, "Corporate OIDC");
        assert_eq!(req.issuer_url, "https://auth.corp.com/realms/main");
        assert_eq!(req.client_id, "artifact-keeper");
        assert_eq!(req.client_secret, "super-secret-123");
        assert_eq!(req.scopes.unwrap(), vec!["openid", "email", "profile"]);
        assert_eq!(req.admin_group.as_deref(), Some("platform-admins"));

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["groups_claim"], "roles");
        assert_eq!(attr["redirect_uri"], "https://app.corp.com/sso/callback");
        assert_eq!(attr["username_claim"], "samaccountname");
        assert_eq!(attr["email_claim"], "mail");
    }

    #[test]
    fn test_bootstrap_request_no_optional_claims_in_attr_map() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        let obj = attr.as_object().unwrap();
        // With no optional claims set, the attribute_mapping is empty:
        // groups_claim is now only inserted when explicitly configured (#2831).
        assert!(obj.is_empty());
        assert!(!obj.contains_key("groups_claim"));
        assert!(!obj.contains_key("redirect_uri"));
        assert!(!obj.contains_key("username_claim"));
        assert!(!obj.contains_key("email_claim"));
    }

    // -----------------------------------------------------------------------
    // plan_admin_group_reconcile
    // -----------------------------------------------------------------------

    #[test]
    fn test_plan_admin_group_env_set_replaces_persisted() {
        let existing = serde_json::json!({"admin_group": "artifact-keeper-admins"});
        assert_eq!(
            plan_admin_group_reconcile(Some("ArtifactKeeperAdmins"), &existing),
            AdminGroupReconcile::Set {
                from: Some("artifact-keeper-admins".into()),
                to: "ArtifactKeeperAdmins".into(),
            }
        );
    }

    #[test]
    fn test_plan_admin_group_env_set_on_provider_without_one() {
        let existing = serde_json::json!({"groups_claim": "roles"});
        assert_eq!(
            plan_admin_group_reconcile(Some("ArtifactKeeperAdmins"), &existing),
            AdminGroupReconcile::Set {
                from: None,
                to: "ArtifactKeeperAdmins".into(),
            }
        );
    }

    #[test]
    fn test_plan_admin_group_env_matches_persisted_is_unchanged() {
        let existing = serde_json::json!({"admin_group": "artifact-keeper-admins"});
        assert_eq!(
            plan_admin_group_reconcile(Some("artifact-keeper-admins"), &existing),
            AdminGroupReconcile::Unchanged
        );
    }

    /// #3420: unsetting `OIDC_ADMIN_GROUP` is how an operator revokes
    /// group-based admin, so the reconcile must report (and the wholesale
    /// mapping replacement must perform) a clear — never a carry-over.
    #[test]
    fn test_plan_admin_group_env_unset_clears_persisted() {
        let existing = serde_json::json!({"admin_group": "artifact-keeper-admins"});
        assert_eq!(
            plan_admin_group_reconcile(None, &existing),
            AdminGroupReconcile::Cleared("artifact-keeper-admins".into())
        );
    }

    #[test]
    fn test_plan_admin_group_env_unset_no_persisted_is_unchanged() {
        assert_eq!(
            plan_admin_group_reconcile(None, &serde_json::json!({})),
            AdminGroupReconcile::Unchanged
        );
    }

    /// A non-string `admin_group` (hand-edited mapping) is not a group name;
    /// treat it as absent rather than stringifying it into an elevation rule.
    #[test]
    fn test_plan_admin_group_non_string_persisted_is_ignored() {
        let existing = serde_json::json!({"admin_group": ["a", "b"]});
        assert_eq!(
            plan_admin_group_reconcile(None, &existing),
            AdminGroupReconcile::Unchanged
        );
        assert_eq!(
            plan_admin_group_reconcile(Some("admins"), &existing),
            AdminGroupReconcile::Set {
                from: None,
                to: "admins".into(),
            }
        );
    }
}
