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

/// `attribute_mapping` keys the `OIDC_*` bootstrap is capable of deriving.
///
/// Exactly the keys [`build_oidc_request_from_values`] can put in the mapping
/// (from `OIDC_GROUPS_CLAIM`, `OIDC_REDIRECT_URI`, `OIDC_USERNAME_CLAIM` and
/// `OIDC_EMAIL_CLAIM`). Nothing outside this set and
/// [`ALWAYS_ENV_OWNED_MAPPING_KEYS`] is ever removed by a reconcile, which
/// bounds the damage a hand-edited [`ENV_OWNED_KEYS_MARKER`] can do.
pub const DERIVABLE_MAPPING_KEYS: [&str; 4] = [
    "email_claim",
    "groups_claim",
    "redirect_uri",
    "username_claim",
];

/// `attribute_mapping` keys the environment owns whether or not it currently
/// sets them.
///
/// `admin_group` alone: #3420/#3439 make `OIDC_ADMIN_GROUP` definitive because
/// unsetting it and redeploying is how an operator revokes group-based admin,
/// so it must not depend on a marker that a row written by an older release
/// (or a wholesale admin `PUT`) does not carry. It reaches `update_oidc` on
/// `UpdateOidcConfigRequest::admin_group` rather than inside the mapping, so
/// the reconcile drops it here and `update_oidc` writes it back only when the
/// variable is set.
pub const ALWAYS_ENV_OWNED_MAPPING_KEYS: [&str; 1] = ["admin_group"];

/// Reserved `attribute_mapping` key recording which mapping keys the `OIDC_*`
/// environment set on the previous reconcile (#3507).
///
/// This is the "previously owned" half of the ownership rule, and it is
/// persisted rather than derived from [`DERIVABLE_MAPPING_KEYS`] because the
/// two answer different questions. The derivable set says which keys the
/// bootstrap *could* write; treating all of them as owned would keep deleting
/// an admin-set `groups_claim` on every boot, which is the bug in #3507. The
/// marker says which keys it *did* write, so unsetting `OIDC_GROUPS_CLAIM`
/// still removes the value that variable installed, while a `groups_claim` the
/// environment never set survives.
///
/// Across upgrades: rows written before this change carry no marker, so the
/// first boot after an upgrade treats the environment as owning only what it
/// currently sets. A claim key the environment used to set and no longer sets
/// is therefore carried over once, and governed by the marker from then on —
/// harmless for a claim *name*, and the reason `admin_group` is in
/// [`ALWAYS_ENV_OWNED_MAPPING_KEYS`] instead: an elevation rule must not
/// survive even one boot past the variable that granted it. Keeping the marker
/// inside the mapping also means it is written by the same UPDATE as the value
/// it describes, so the two cannot disagree, and it needs no migration.
pub const ENV_OWNED_KEYS_MARKER: &str = "env_owned_keys";

/// A persisted value for an env-owned mapping key that a reconcile throws
/// away, so the caller can log it instead of discarding it silently (#3507).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardedMappingKey {
    /// The `attribute_mapping` key.
    pub key: String,
    /// The value that was persisted (rendered as JSON when not a string).
    pub from: String,
    /// The value the environment installs in its place, or `None` when the
    /// variable is no longer set and the key is being removed outright.
    pub to: Option<String>,
}

/// The complete `attribute_mapping` an env reconcile intends, plus what it
/// discards to get there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingReconcile {
    /// The whole desired mapping, to be sent with replace semantics.
    pub desired: Value,
    /// Env-owned keys whose persisted value this boot overwrites or removes.
    pub discarded: Vec<DiscardedMappingKey>,
}

/// Build the *complete* `attribute_mapping` the environment intends for the
/// env-managed provider (#3507).
///
/// The bootstrap only ever derives a handful of mapping keys from `OIDC_*`,
/// but the reconcile applies its result with replace semantics — so before
/// this, every key an admin set through `PUT /api/v1/admin/sso/oidc/{id}`
/// (`groups_claim` for an IdP that publishes groups under `groups_direct`,
/// say) was erased on the next boot, silently. The fix is to express a
/// complete desired mapping with explicit ownership:
///
/// - **set** every key the environment supplies this boot;
/// - **delete** every key the environment owned before and no longer supplies
///   — the [`ENV_OWNED_KEYS_MARKER`] list (intersected with
///   [`DERIVABLE_MAPPING_KEYS`]) plus [`ALWAYS_ENV_OWNED_MAPPING_KEYS`], so
///   removing a variable still removes its effect;
/// - **preserve** everything else verbatim: the environment has no opinion
///   about an admin-set key it never wrote.
///
/// `env_mapping` is the mapping [`build_oidc_request_from_values`] assembled
/// from the process environment. `admin_group` is never in it: it rides on the
/// request's `admin_group` field and `update_oidc` writes it into the mapping
/// after the replace, so [`MappingReconcile::desired`] always comes back
/// without that key and its transition is described — and logged — by
/// [`plan_admin_group_reconcile`] rather than appearing in `discarded`.
pub fn plan_mapping_reconcile(
    existing_mapping: &Value,
    env_mapping: Option<&Value>,
) -> MappingReconcile {
    let mut desired = existing_mapping.as_object().cloned().unwrap_or_default();
    let mut discarded = Vec::new();

    let env_keys: Vec<(String, Value)> = env_mapping
        .and_then(|m| m.as_object())
        .map(|m| {
            m.iter()
                .filter(|(k, _)| k.as_str() != ENV_OWNED_KEYS_MARKER)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();

    // Keys the environment owned on the previous reconcile. Bounded by what
    // the bootstrap can actually derive so a hand-edited marker cannot make
    // the reconcile delete an unrelated admin-set key.
    let previously_owned: Vec<String> = desired
        .get(ENV_OWNED_KEYS_MARKER)
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|k| DERIVABLE_MAPPING_KEYS.contains(k))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    for (key, value) in &env_keys {
        if let Some(previous) = desired.insert(key.clone(), value.clone()) {
            if previous != *value {
                discarded.push(DiscardedMappingKey {
                    key: key.clone(),
                    from: render_mapping_value(&previous),
                    to: Some(render_mapping_value(value)),
                });
            }
        }
    }

    for key in previously_owned
        .iter()
        .map(String::as_str)
        .chain(ALWAYS_ENV_OWNED_MAPPING_KEYS)
    {
        if env_keys.iter().any(|(k, _)| k == key) {
            continue;
        }
        let Some(previous) = desired.remove(key) else {
            continue;
        };
        // `admin_group` is dropped here like any other key the environment no
        // longer supplies, but its removal revokes admin elevation, so the
        // caller logs it through `plan_admin_group_reconcile` with wording
        // that says so. Reporting it here too would only duplicate that line.
        if ALWAYS_ENV_OWNED_MAPPING_KEYS.contains(&key) {
            continue;
        }
        discarded.push(DiscardedMappingKey {
            key: key.to_string(),
            from: render_mapping_value(&previous),
            to: None,
        });
    }

    // Re-record ownership for the next boot.
    let mut owned_now: Vec<String> = env_keys.iter().map(|(k, _)| k.clone()).collect();
    owned_now.sort();
    desired.insert(
        ENV_OWNED_KEYS_MARKER.to_string(),
        Value::Array(owned_now.into_iter().map(Value::String).collect()),
    );

    discarded.sort_by(|a, b| a.key.cmp(&b.key));

    MappingReconcile {
        desired: Value::Object(desired),
        discarded,
    }
}

/// Render a mapping value for a log line: strings unquoted, anything else as
/// compact JSON.
fn render_mapping_value(value: &Value) -> String {
    match value.as_str() {
        Some(s) => s.to_string(),
        None => value.to_string(),
    }
}

/// One-line summary of the keys a reconcile discards, for the WARN below:
/// `groups_claim ('groups_direct' -> 'groups'), email_claim ('mail' removed)`.
pub fn describe_discarded_keys(discarded: &[DiscardedMappingKey]) -> String {
    discarded
        .iter()
        .map(|d| match &d.to {
            Some(to) => format!("{} ('{}' -> '{}')", d.key, d.from, to),
            None => format!("{} ('{}' removed)", d.key, d.from),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Log the values an env reconcile is about to throw away (#3507).
///
/// Overwriting a key an admin set through the admin API is legitimate — the
/// environment owns it — but it must never be silent: the reported symptom was
/// an operator setting `groups_claim` through the admin API, watching group
/// sync work, redeploying, and finding it broken with nothing in the log.
/// Emits nothing when nothing is discarded, so a steady-state boot stays quiet.
///
/// Nothing on the row records *who* wrote the value being replaced, so this
/// reports every replaced value, including the case where the operator simply
/// changed the variable. Over-reporting is the safe direction: the line names
/// the key and both values, and only appears on the boot that changes them.
pub fn warn_discarded_mapping_keys(provider_name: &str, discarded: &[DiscardedMappingKey]) {
    if discarded.is_empty() {
        return;
    }
    tracing::warn!(
        "OIDC provider '{}': the OIDC_* environment owns these attribute mapping keys and is \
         discarding the values currently stored for them: {}. Set the matching OIDC_* variable \
         to the value you want, or give the provider a name other than OIDC_NAME so the admin \
         API owns it. Keys the environment does not own are preserved.",
        provider_name,
        describe_discarded_keys(discarded)
    );
}

#[cfg(ak_test_shard = "services-1")]
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

    // -----------------------------------------------------------------------
    // plan_mapping_reconcile (#3507)
    // -----------------------------------------------------------------------

    fn marker(keys: &[&str]) -> Value {
        Value::Array(keys.iter().map(|k| Value::String((*k).into())).collect())
    }

    fn owned_marker(mapping: &Value) -> Vec<String> {
        mapping[ENV_OWNED_KEYS_MARKER]
            .as_array()
            .expect("marker array")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    /// The enumeration of derivable keys must stay in step with what the
    /// bootstrap actually writes, or ownership silently drifts.
    #[test]
    fn test_derivable_keys_match_what_the_bootstrap_writes() {
        let req = build_oidc_request_from_values(OidcEnvVars {
            issuer: Some("https://idp.example.com".into()),
            client_id: Some("client".into()),
            client_secret: Some("secret".into()),
            groups_claim: Some("roles".into()),
            redirect_uri: Some("https://ak.example.com/cb".into()),
            username_claim: Some("samaccountname".into()),
            email_claim: Some("mail".into()),
            admin_group: Some("platform-admins".into()),
            ..Default::default()
        })
        .unwrap();

        let mut written: Vec<&str> = req
            .attribute_mapping
            .as_ref()
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        written.sort();
        assert_eq!(written, DERIVABLE_MAPPING_KEYS.to_vec());
        // admin_group never rides in the mapping; it is env-owned via the
        // request field and ALWAYS_ENV_OWNED_MAPPING_KEYS.
        assert!(!written.contains(&"admin_group"));
        assert_eq!(req.admin_group.as_deref(), Some("platform-admins"));
    }

    /// The #3507 headline: a `groups_claim` an admin set through the admin API
    /// for an IdP that publishes under `groups_direct` must survive a boot
    /// where `OIDC_GROUPS_CLAIM` is not set.
    #[test]
    fn test_mapping_reconcile_preserves_admin_set_claim_key() {
        let existing = serde_json::json!({
            "groups_claim": "groups_direct",
            "fetch_userinfo_groups": false,
        });
        let env_mapping = serde_json::json!({"redirect_uri": "https://ak.example.com/cb"});

        let plan = plan_mapping_reconcile(&existing, Some(&env_mapping));

        assert_eq!(plan.desired["groups_claim"], "groups_direct");
        assert_eq!(plan.desired["fetch_userinfo_groups"], false);
        assert_eq!(plan.desired["redirect_uri"], "https://ak.example.com/cb");
        assert!(
            plan.discarded.is_empty(),
            "nothing was discarded: {:?}",
            plan.discarded
        );
        assert_eq!(owned_marker(&plan.desired), vec!["redirect_uri"]);
    }

    /// A key the environment supplies wins over the stored value, and says so.
    #[test]
    fn test_mapping_reconcile_env_owned_key_is_updated_and_reported() {
        let existing = serde_json::json!({
            "groups_claim": "groups_direct",
            ENV_OWNED_KEYS_MARKER: marker(&["groups_claim"]),
        });
        let env_mapping = serde_json::json!({"groups_claim": "groups"});

        let plan = plan_mapping_reconcile(&existing, Some(&env_mapping));

        assert_eq!(plan.desired["groups_claim"], "groups");
        assert_eq!(
            plan.discarded,
            vec![DiscardedMappingKey {
                key: "groups_claim".into(),
                from: "groups_direct".into(),
                to: Some("groups".into()),
            }]
        );
    }

    /// Unsetting the variable that installed a key removes the key: the marker
    /// is what makes "remove the variable, redeploy" still undo its effect.
    #[test]
    fn test_mapping_reconcile_removes_env_owned_key_when_variable_unset() {
        let existing = serde_json::json!({
            "groups_claim": "roles",
            "email_claim": "mail",
            "fetch_userinfo_groups": false,
            ENV_OWNED_KEYS_MARKER: marker(&["email_claim", "groups_claim"]),
        });
        let env_mapping = serde_json::json!({"email_claim": "mail"});

        let plan = plan_mapping_reconcile(&existing, Some(&env_mapping));

        assert_eq!(plan.desired.get("groups_claim"), None);
        assert_eq!(plan.desired["email_claim"], "mail");
        // Not env-owned, so untouched.
        assert_eq!(plan.desired["fetch_userinfo_groups"], false);
        assert_eq!(
            plan.discarded,
            vec![DiscardedMappingKey {
                key: "groups_claim".into(),
                from: "roles".into(),
                to: None,
            }]
        );
        assert_eq!(owned_marker(&plan.desired), vec!["email_claim"]);
    }

    /// #3420/#3439 must not regress: `admin_group` is env-definitive with or
    /// without a marker, so the desired mapping never carries it forward.
    /// `update_oidc` writes it back from the request only when the variable is
    /// set, which is how unsetting it revokes elevation.
    #[test]
    fn test_mapping_reconcile_always_drops_admin_group() {
        for existing in [
            serde_json::json!({"admin_group": "artifact-keeper-admins"}),
            serde_json::json!({
                "admin_group": "artifact-keeper-admins",
                ENV_OWNED_KEYS_MARKER: marker(&["groups_claim"]),
            }),
        ] {
            let plan = plan_mapping_reconcile(&existing, Some(&serde_json::json!({})));
            assert_eq!(
                plan.desired.get("admin_group"),
                None,
                "admin_group must never survive a reconcile in the mapping"
            );
            // Logged by plan_admin_group_reconcile, not duplicated here.
            assert!(plan.discarded.is_empty(), "{:?}", plan.discarded);
        }
    }

    /// A row written before #3507 carries no marker. The environment then owns
    /// only what it currently sets — an admin-set key is preserved — while
    /// `admin_group` is still cleared, because an elevation rule must not
    /// outlive the variable that granted it by even one boot.
    #[test]
    fn test_mapping_reconcile_upgrade_from_unmarked_row() {
        let existing = serde_json::json!({
            "groups_claim": "groups_direct",
            "admin_group": "artifact-keeper-admins",
        });

        let plan = plan_mapping_reconcile(&existing, Some(&serde_json::json!({})));

        assert_eq!(plan.desired["groups_claim"], "groups_direct");
        assert_eq!(plan.desired.get("admin_group"), None);
        assert_eq!(owned_marker(&plan.desired), Vec::<String>::new());
    }

    /// A hand-edited marker must not turn into a delete list for keys the
    /// bootstrap cannot derive in the first place.
    #[test]
    fn test_mapping_reconcile_marker_cannot_delete_non_derivable_keys() {
        let existing = serde_json::json!({
            "fetch_userinfo_groups": false,
            ENV_OWNED_KEYS_MARKER: marker(&["fetch_userinfo_groups"]),
        });

        let plan = plan_mapping_reconcile(&existing, Some(&serde_json::json!({})));

        assert_eq!(plan.desired["fetch_userinfo_groups"], false);
        assert!(plan.discarded.is_empty());
    }

    /// A provider whose mapping is not an object (hand-edited row) still gets
    /// a well-formed desired mapping instead of a panic.
    #[test]
    fn test_mapping_reconcile_non_object_existing_mapping() {
        let plan = plan_mapping_reconcile(
            &Value::Null,
            Some(&serde_json::json!({"username_claim": "sub"})),
        );
        assert_eq!(plan.desired["username_claim"], "sub");
        assert_eq!(owned_marker(&plan.desired), vec!["username_claim"]);
    }

    #[test]
    fn test_describe_discarded_keys_names_every_key() {
        let discarded = vec![
            DiscardedMappingKey {
                key: "groups_claim".into(),
                from: "groups_direct".into(),
                to: Some("groups".into()),
            },
            DiscardedMappingKey {
                key: "email_claim".into(),
                from: "mail".into(),
                to: None,
            },
        ];
        assert_eq!(
            describe_discarded_keys(&discarded),
            "groups_claim ('groups_direct' -> 'groups'), email_claim ('mail' removed)"
        );
    }

    // -- WARN emission ------------------------------------------------------

    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8 logs")
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture_logs(f: impl FnOnce()) -> String {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        logs.contents()
    }

    /// Discarding an admin-set value is allowed, but never silent (#3507).
    #[test]
    fn test_warn_names_the_overwritten_keys() {
        let existing = serde_json::json!({
            "groups_claim": "groups_direct",
            ENV_OWNED_KEYS_MARKER: marker(&["groups_claim"]),
        });
        let env_mapping = serde_json::json!({"groups_claim": "groups"});
        let plan = plan_mapping_reconcile(&existing, Some(&env_mapping));

        let output = capture_logs(|| warn_discarded_mapping_keys("default", &plan.discarded));

        assert!(
            output.contains("WARN"),
            "expected a WARN line, got: {output}"
        );
        assert!(output.contains("groups_claim"), "got: {output}");
        assert!(output.contains("groups_direct"), "got: {output}");
        assert!(output.contains("default"), "got: {output}");
    }

    /// A boot that changes nothing must not add noise to the log.
    #[test]
    fn test_warn_is_silent_when_nothing_is_discarded() {
        let output = capture_logs(|| warn_discarded_mapping_keys("default", &[]));
        assert!(output.is_empty(), "expected no output, got: {output}");
    }
}
