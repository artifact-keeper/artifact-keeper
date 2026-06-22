//! Runtime configuration endpoint.
//!
//! Reachable without authentication so frontends and clients can discover
//! pre-login affordances (upload limits, guest access, available login
//! providers). Security-posture values (scanner / auth-provider / permission /
//! plugin-signing / storage configuration) are disclosed **only to
//! authenticated admins** so an unauthenticated attacker cannot fingerprint the
//! deployment's defensive configuration. Secrets, credentials, and internal
//! connection strings are never returned to anyone.

use axum::{extract::State, routing::get, Extension, Json, Router};
use serde::Serialize;
use sqlx;
use utoipa::{OpenApi, ToSchema};

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;

/// Router for the system configuration endpoint.
///
/// Mounted under `/system` behind `optional_auth_middleware` so the handler
/// receives an `Option<AuthExtension>` and can decide how much to disclose.
pub fn router() -> Router<SharedState> {
    Router::new().route("/config", get(get_system_config))
}

/// Fine-grained permissions enforcement status.
#[derive(Serialize, ToSchema)]
pub struct PermissionsConfig {
    /// Whether the permissions table (from migration 018) has any rows.
    /// When true, an administrator has configured permission rules.
    pub rules_exist: bool,
    /// Whether those rules are actively enforced on API requests.
    /// The permission-check middleware and handler guards are wired in,
    /// so this is `true` when the server is running.
    pub enforcement_enabled: bool,
}

/// Scanner availability flags.
#[derive(Serialize, ToSchema)]
pub struct ScannersConfig {
    /// Whether the Trivy vulnerability scanner is configured.
    pub trivy_enabled: bool,
    /// Whether the OpenSCAP compliance scanner is configured.
    pub openscap_enabled: bool,
    /// Whether the Dependency-Track integration is configured.
    pub dependency_track_enabled: bool,
}

/// Plugin signature-verification (supply-chain) policy status.
///
/// Exposes only booleans — never the trusted key material itself — so frontends
/// and operators can see whether unsigned plugin installs are rejected and
/// whether a trusted publisher key has been provisioned.
#[derive(Serialize, ToSchema)]
pub struct PluginSigningConfig {
    /// Whether a valid signature is required to install a WASM plugin.
    pub required: bool,
    /// Whether an operator trusted public key has been configured. When
    /// `required` is true but this is false, every install is rejected
    /// (fail-closed).
    pub trusted_key_configured: bool,
}

/// Authentication provider availability.
#[derive(Serialize, ToSchema)]
pub struct AuthConfig {
    /// Whether an OIDC provider is configured.
    pub oidc_enabled: bool,
    /// Whether an LDAP directory is configured.
    pub ldap_enabled: bool,
    /// Whether SAML SSO is configured (derived from the SSO admin settings in the DB,
    /// but for this endpoint we report whether the OIDC issuer is set as a proxy).
    pub sso_enabled: bool,
}

/// Runtime configuration values.
///
/// This response intentionally omits all secrets, credentials, and internal
/// connection strings.
///
/// Disclosure is tiered (see `get_system_config`):
///
/// * **Public-safe fields** are always present — they only describe UI/client
///   affordances a caller needs *before* authenticating (upload limit, demo
///   mode, whether guest access and which login providers are available).
/// * **Security-posture fields** (`scanners`, `search_engine`,
///   `storage_backend`, `permissions`, `plugin_signing`) describe the
///   instance's defensive configuration. They are returned **only to
///   authenticated admins** and are omitted for anonymous / non-admin callers,
///   so the deployment's security posture cannot be fingerprinted by an
///   unauthenticated attacker.
#[derive(Serialize, ToSchema)]
pub struct SystemConfigResponse {
    /// Maximum upload size in bytes (0 means no limit).
    pub max_upload_size_bytes: u64,
    /// Whether the instance is running in demo mode (writes blocked).
    pub demo_mode: bool,
    /// Whether anonymous (unauthenticated) access is permitted at all (issue #850).
    /// When `false`, the server rejects all unauthenticated requests except for
    /// the login, setup, health, and OCI challenge endpoints. Frontends should
    /// hide UI affordances that imply public access (e.g. the "public repo"
    /// toggle) and redirect unauthenticated users to the login page.
    pub guest_access_enabled: bool,
    /// Authentication provider availability. Needed by the login UI before the
    /// user authenticates, so this is public-safe.
    pub auth: AuthConfig,
    /// OIDC issuer URL, if configured. This is public information needed by
    /// clients to initiate the OIDC flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_issuer: Option<String>,
    /// Scanner availability. Admin-only (security posture).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanners: Option<ScannersConfig>,
    /// Search engine type: "opensearch" when configured, "database" otherwise.
    /// Admin-only (security posture).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_engine: Option<String>,
    /// Storage backend type (e.g. "filesystem", "s3", "gcs", "azure").
    /// Admin-only (security posture).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_backend: Option<String>,
    /// Fine-grained permissions enforcement status. Permission rules can be
    /// managed via /api/v1/permissions and are actively enforced.
    /// Admin-only (security posture).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<PermissionsConfig>,
    /// Plugin signature-verification (supply-chain) policy status.
    /// Admin-only (security posture).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_signing: Option<PluginSigningConfig>,
}

/// Return runtime configuration.
///
/// Reachable without authentication so frontends can discover pre-login
/// affordances (upload limits, guest access, available login providers). The
/// security-posture fields (scanner/auth-provider/permission/plugin-signing/
/// storage configuration) are returned **only to authenticated admins**; for
/// anonymous and non-admin callers they are omitted so the instance's
/// defensive configuration cannot be fingerprinted by an unauthenticated
/// attacker.
#[utoipa::path(
    get,
    path = "/config",
    context_path = "/api/v1/system",
    tag = "system",
    responses(
        (status = 200, description = "Runtime configuration (security-posture fields admin-only)", body = SystemConfigResponse),
    )
)]
pub async fn get_system_config(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
) -> Json<SystemConfigResponse> {
    let config = &state.config;
    let is_admin = auth.as_ref().map(|a| a.is_admin).unwrap_or(false);

    // Public-safe fields: always returned. Login UI needs to know which
    // providers are available before the user authenticates.
    let auth_config = AuthConfig {
        oidc_enabled: config.oidc_issuer.is_some(),
        ldap_enabled: config.ldap_url.is_some(),
        sso_enabled: config.oidc_issuer.is_some(),
    };

    // Non-admin / anonymous callers receive only the public-safe subset. The
    // sensitive security-posture fields stay `None` and are dropped from the
    // JSON by `skip_serializing_if`.
    if !is_admin {
        return Json(SystemConfigResponse {
            max_upload_size_bytes: config.max_upload_size_bytes,
            demo_mode: config.demo_mode,
            guest_access_enabled: config.guest_access_enabled,
            auth: auth_config,
            oidc_issuer: config.oidc_issuer.clone(),
            scanners: None,
            search_engine: None,
            storage_backend: None,
            permissions: None,
            plugin_signing: None,
        });
    }

    // Admin caller: include the full security posture.

    // Dependency-Track is considered enabled only when the service was
    // actually wired into application state at startup. That requires both
    // `DEPENDENCY_TRACK_ENABLED=true` and a usable `DEPENDENCY_TRACK_URL`
    // and `DEPENDENCY_TRACK_API_KEY`. Reporting `is_some()` here (instead
    // of `config.dependency_track_url.is_some()`) guarantees the frontend
    // sees a single, consistent disabled/enabled signal that matches both
    // the `/api/v1/dependency-track/status` endpoint and the health
    // monitor; this is the fix for the mixed "Disabled" vs "unavailable"
    // banners reported in issue #1395, and the "monitoring green while DT
    // unavailable" inconsistency in issue #1480.
    let scanners = ScannersConfig {
        trivy_enabled: config.trivy_url.is_some(),
        openscap_enabled: config.openscap_url.is_some(),
        dependency_track_enabled: state.dependency_track.is_some(),
    };

    let search_engine = if config.opensearch_url.is_some() {
        "opensearch".to_string()
    } else {
        "database".to_string()
    };

    // Check whether any permission rules exist in the database. The
    // permissions table is created by migration 018 and may not exist on
    // very old schema versions, so we fall back to false on any error.
    let rules_exist: bool =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM permissions LIMIT 1)")
            .fetch_one(&state.db)
            .await
            .unwrap_or(false);

    let permissions = PermissionsConfig {
        rules_exist,
        enforcement_enabled: true,
    };

    // Expose only booleans about the plugin signing policy — never the key
    // material — so the supply-chain posture is observable without leaking the
    // trusted public key.
    let plugin_signing = PluginSigningConfig {
        required: config.plugins_require_signed,
        trusted_key_configured: config.plugins_trusted_pubkey.is_some(),
    };

    Json(SystemConfigResponse {
        max_upload_size_bytes: config.max_upload_size_bytes,
        demo_mode: config.demo_mode,
        guest_access_enabled: config.guest_access_enabled,
        auth: auth_config,
        oidc_issuer: config.oidc_issuer.clone(),
        scanners: Some(scanners),
        search_engine: Some(search_engine),
        storage_backend: Some(config.storage_backend.clone()),
        permissions: Some(permissions),
        plugin_signing: Some(plugin_signing),
    })
}

#[derive(OpenApi)]
#[openapi(
    paths(get_system_config),
    components(schemas(
        SystemConfigResponse,
        ScannersConfig,
        AuthConfig,
        PermissionsConfig,
        PluginSigningConfig
    ))
)]
pub struct SystemConfigApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an admin-tier response from a config with all integrations
    /// disabled (security-posture fields present, all `false`/default).
    fn minimal_response() -> SystemConfigResponse {
        SystemConfigResponse {
            max_upload_size_bytes: 10_737_418_240,
            demo_mode: false,
            guest_access_enabled: true,
            scanners: Some(ScannersConfig {
                trivy_enabled: false,
                openscap_enabled: false,
                dependency_track_enabled: false,
            }),
            search_engine: Some("database".to_string()),
            storage_backend: Some("filesystem".to_string()),
            auth: AuthConfig {
                oidc_enabled: false,
                ldap_enabled: false,
                sso_enabled: false,
            },
            oidc_issuer: None,
            permissions: Some(PermissionsConfig {
                rules_exist: false,
                enforcement_enabled: false,
            }),
            plugin_signing: Some(PluginSigningConfig {
                required: true,
                trusted_key_configured: false,
            }),
        }
    }

    /// Build the redacted (anonymous / non-admin) response from the same
    /// config as `minimal_response`: public-safe fields present, every
    /// security-posture field `None`.
    fn redacted_response() -> SystemConfigResponse {
        SystemConfigResponse {
            scanners: None,
            search_engine: None,
            storage_backend: None,
            permissions: None,
            plugin_signing: None,
            ..minimal_response()
        }
    }

    #[test]
    fn test_system_config_response_serialization() {
        let response = minimal_response();
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"max_upload_size_bytes\":10737418240"));
        assert!(json.contains("\"demo_mode\":false"));
        assert!(json.contains("\"guest_access_enabled\":true"));
        assert!(json.contains("\"search_engine\":\"database\""));
        assert!(json.contains("\"storage_backend\":\"filesystem\""));
        assert!(json.contains("\"trivy_enabled\":false"));
        assert!(json.contains("\"openscap_enabled\":false"));
        assert!(json.contains("\"dependency_track_enabled\":false"));
        assert!(json.contains("\"oidc_enabled\":false"));
        assert!(json.contains("\"ldap_enabled\":false"));
        assert!(json.contains("\"sso_enabled\":false"));
        // oidc_issuer should be omitted when None
        assert!(!json.contains("\"oidc_issuer\""));
        // Permissions enforcement status
        assert!(json.contains("\"rules_exist\":false"));
        assert!(json.contains("\"enforcement_enabled\":false"));
    }

    #[test]
    fn test_system_config_response_with_all_enabled() {
        let response = SystemConfigResponse {
            max_upload_size_bytes: 21_474_836_480,
            demo_mode: true,
            guest_access_enabled: false,
            scanners: Some(ScannersConfig {
                trivy_enabled: true,
                openscap_enabled: true,
                dependency_track_enabled: true,
            }),
            search_engine: Some("opensearch".to_string()),
            storage_backend: Some("s3".to_string()),
            auth: AuthConfig {
                oidc_enabled: true,
                ldap_enabled: true,
                sso_enabled: true,
            },
            oidc_issuer: Some("https://auth.example.com".to_string()),
            permissions: Some(PermissionsConfig {
                rules_exist: true,
                enforcement_enabled: true,
            }),
            plugin_signing: Some(PluginSigningConfig {
                required: true,
                trusted_key_configured: true,
            }),
        };

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"max_upload_size_bytes\":21474836480"));
        assert!(json.contains("\"demo_mode\":true"));
        assert!(json.contains("\"search_engine\":\"opensearch\""));
        assert!(json.contains("\"storage_backend\":\"s3\""));
        assert!(json.contains("\"trivy_enabled\":true"));
        assert!(json.contains("\"openscap_enabled\":true"));
        assert!(json.contains("\"dependency_track_enabled\":true"));
        assert!(json.contains("\"oidc_enabled\":true"));
        assert!(json.contains("\"ldap_enabled\":true"));
        assert!(json.contains("\"sso_enabled\":true"));
        assert!(json.contains("\"oidc_issuer\":\"https://auth.example.com\""));
        assert!(json.contains("\"rules_exist\":true"));
        assert!(json.contains("\"enforcement_enabled\":true"));
    }

    #[test]
    fn test_system_config_no_sensitive_fields() {
        let response = minimal_response();
        let json = serde_json::to_string(&response).unwrap();

        // Verify no sensitive fields leak into the response
        assert!(!json.contains("database_url"));
        assert!(!json.contains("jwt_secret"));
        assert!(!json.contains("jwt_expiration"));
        assert!(!json.contains("peer_api_key"));
        assert!(!json.contains("oidc_client_secret"));
        assert!(!json.contains("oidc_client_id"));
        assert!(!json.contains("opensearch_password"));
        assert!(!json.contains("opensearch_url"));
        assert!(!json.contains("s3_bucket"));
        assert!(!json.contains("s3_region"));
        assert!(!json.contains("s3_endpoint"));
        assert!(!json.contains("bind_address"));
        assert!(!json.contains("storage_path"));
        assert!(!json.contains("scan_workspace"));
    }

    #[test]
    fn test_system_config_upload_limit_zero() {
        let response = SystemConfigResponse {
            max_upload_size_bytes: 0,
            ..minimal_response()
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"max_upload_size_bytes\":0"));
    }

    #[test]
    fn test_system_config_scanners_serialization() {
        let scanners = ScannersConfig {
            trivy_enabled: true,
            openscap_enabled: false,
            dependency_track_enabled: true,
        };
        let json = serde_json::to_string(&scanners).unwrap();
        assert!(json.contains("\"trivy_enabled\":true"));
        assert!(json.contains("\"openscap_enabled\":false"));
        assert!(json.contains("\"dependency_track_enabled\":true"));
    }

    #[test]
    fn test_system_config_auth_serialization() {
        let auth = AuthConfig {
            oidc_enabled: true,
            ldap_enabled: false,
            sso_enabled: true,
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"oidc_enabled\":true"));
        assert!(json.contains("\"ldap_enabled\":false"));
        assert!(json.contains("\"sso_enabled\":true"));
    }

    #[test]
    fn test_system_config_oidc_issuer_omitted_when_none() {
        let response = minimal_response();
        let json = serde_json::to_string(&response).unwrap();
        // The oidc_issuer field uses skip_serializing_if = "Option::is_none"
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("oidc_issuer").is_none());
    }

    #[test]
    fn test_system_config_oidc_issuer_present_when_some() {
        let response = SystemConfigResponse {
            oidc_issuer: Some("https://accounts.google.com".to_string()),
            auth: AuthConfig {
                oidc_enabled: true,
                ldap_enabled: false,
                sso_enabled: true,
            },
            ..minimal_response()
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["oidc_issuer"].as_str().unwrap(),
            "https://accounts.google.com"
        );
    }

    #[test]
    fn test_system_config_permissions_serialization() {
        let perms = PermissionsConfig {
            rules_exist: false,
            enforcement_enabled: false,
        };
        let json = serde_json::to_string(&perms).unwrap();
        assert!(json.contains("\"rules_exist\":false"));
        assert!(json.contains("\"enforcement_enabled\":false"));
    }

    #[test]
    fn test_system_config_guest_access_enabled_default_true() {
        // Issue #850: when the server is configured with guests enabled (the
        // default), the response advertises that fact so frontends keep
        // showing public-repo affordances.
        let response = minimal_response();
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["guest_access_enabled"], true);
    }

    #[test]
    fn test_system_config_guest_access_disabled_serialized_false() {
        // Issue #850: frontends rely on this flag to hide the "public repo"
        // toggle and to short-circuit anonymous browsing, so the value must
        // round-trip through serde without surprises.
        let response = SystemConfigResponse {
            guest_access_enabled: false,
            ..minimal_response()
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["guest_access_enabled"], false);
        assert!(json.contains("\"guest_access_enabled\":false"));
    }

    #[test]
    fn test_system_config_plugin_signing_serialization() {
        // plugin_signing must expose exactly {required, trusted_key_configured}
        // and never leak any key material.
        let response = SystemConfigResponse {
            plugin_signing: Some(PluginSigningConfig {
                required: true,
                trusted_key_configured: true,
            }),
            ..minimal_response()
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["plugin_signing"]["required"], true);
        assert_eq!(parsed["plugin_signing"]["trusted_key_configured"], true);

        // Only the two boolean fields are present — no key bytes anywhere.
        let obj = parsed["plugin_signing"].as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert!(!json.contains("plugins_trusted_pubkey"));
        assert!(!json.to_lowercase().contains("pubkey"));
    }

    #[test]
    fn test_system_config_plugin_signing_default_required() {
        // minimal_response models the fail-closed default: required, no key yet.
        let response = minimal_response();
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["plugin_signing"]["required"], true);
        assert_eq!(parsed["plugin_signing"]["trusted_key_configured"], false);
    }

    #[test]
    fn test_system_config_permissions_rules_exist_and_enforced() {
        let response = SystemConfigResponse {
            permissions: Some(PermissionsConfig {
                rules_exist: true,
                enforcement_enabled: true,
            }),
            ..minimal_response()
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["permissions"]["rules_exist"], true);
        assert_eq!(parsed["permissions"]["enforcement_enabled"], true);
    }

    // ---- Redaction (anonymous / non-admin disclosure) tests ----
    //
    // These cover the 1.2.2 fix: the security-posture fields must be present
    // for admins (the `minimal_response`/all-enabled tests above) and absent
    // for anonymous / non-admin callers (the `redacted_response` below).

    #[test]
    fn test_redacted_response_omits_security_posture_fields() {
        // Anonymous / non-admin: scanners, search_engine, storage_backend,
        // permissions and plugin_signing must NOT appear in the JSON at all.
        let json = serde_json::to_string(&redacted_response()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().unwrap();

        assert!(
            !obj.contains_key("scanners"),
            "scanners leaked to non-admin"
        );
        assert!(
            !obj.contains_key("search_engine"),
            "search_engine leaked to non-admin"
        );
        assert!(
            !obj.contains_key("storage_backend"),
            "storage_backend leaked to non-admin"
        );
        assert!(
            !obj.contains_key("permissions"),
            "permissions leaked to non-admin"
        );
        assert!(
            !obj.contains_key("plugin_signing"),
            "plugin_signing leaked to non-admin"
        );

        // None of the sensitive sub-field names should appear either.
        for needle in [
            "trivy_enabled",
            "openscap_enabled",
            "dependency_track_enabled",
            "rules_exist",
            "enforcement_enabled",
            "trusted_key_configured",
            "filesystem",
        ] {
            assert!(
                !json.contains(needle),
                "field `{needle}` leaked to non-admin"
            );
        }
    }

    #[test]
    fn test_redacted_response_keeps_public_safe_fields() {
        // The login/upload affordances a frontend needs before authenticating
        // remain present even when redacted.
        let json = serde_json::to_string(&redacted_response()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().unwrap();

        assert!(obj.contains_key("max_upload_size_bytes"));
        assert!(obj.contains_key("demo_mode"));
        assert!(obj.contains_key("guest_access_enabled"));
        // `auth` (which login providers exist) is public-safe and retained.
        assert!(obj.contains_key("auth"));
        assert!(obj["auth"]
            .as_object()
            .unwrap()
            .contains_key("oidc_enabled"));
    }

    #[test]
    fn test_admin_response_includes_security_posture_fields() {
        // The admin tier (modeled by minimal_response) still carries the full
        // posture, so admins keep their operational visibility.
        let json = serde_json::to_string(&minimal_response()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().unwrap();

        assert!(obj.contains_key("scanners"));
        assert!(obj.contains_key("search_engine"));
        assert!(obj.contains_key("storage_backend"));
        assert!(obj.contains_key("permissions"));
        assert!(obj.contains_key("plugin_signing"));
    }

    // ---- Handler-level disclosure tests ----
    //
    // The tests above only exercise the *serialization* of a hand-built
    // `SystemConfigResponse`. These call `get_system_config` directly with each
    // auth state so the handler's own tiering logic (the `is_admin` decision,
    // the anonymous/non-admin early return, and the admin branch that builds
    // the full posture) is exercised. They use the in-crate DB scaffolding and
    // no-op when `DATABASE_URL` is unset, so they run in CI (which seeds
    // Postgres) without being `#[ignore]`d.

    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::middleware::auth::AuthExtension;
    use axum::{extract::State, Extension};

    /// Drive `get_system_config` and return the serialized JSON object the
    /// handler produced for the given auth state.
    async fn call_handler(
        state: crate::api::SharedState,
        auth: Option<AuthExtension>,
    ) -> serde_json::Map<String, serde_json::Value> {
        let Json(response) = get_system_config(State(state), Extension(auth)).await;
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        parsed.as_object().unwrap().clone()
    }

    /// Anonymous caller (no `AuthExtension`): the handler must take the
    /// non-admin early-return branch — public-safe fields present, every
    /// security-posture field omitted.
    #[tokio::test]
    async fn test_handler_anonymous_redacts_security_posture() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool, "/tmp/sysconfig-anon");

        let obj = call_handler(state, None).await;

        // Public-safe fields are always returned so the login UI works.
        assert!(obj.contains_key("max_upload_size_bytes"));
        assert!(obj.contains_key("demo_mode"));
        assert!(obj.contains_key("guest_access_enabled"));
        assert!(obj.contains_key("auth"));

        // Security-posture fields must be omitted for an anonymous caller.
        assert!(!obj.contains_key("scanners"), "scanners leaked to anon");
        assert!(
            !obj.contains_key("search_engine"),
            "search_engine leaked to anon"
        );
        assert!(
            !obj.contains_key("storage_backend"),
            "storage_backend leaked to anon"
        );
        assert!(
            !obj.contains_key("permissions"),
            "permissions leaked to anon"
        );
        assert!(
            !obj.contains_key("plugin_signing"),
            "plugin_signing leaked to anon"
        );
    }

    /// Authenticated non-admin caller: same redaction as anonymous — the
    /// `is_admin == false` path still drops the security-posture fields.
    #[tokio::test]
    async fn test_handler_non_admin_redacts_security_posture() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool, "/tmp/sysconfig-nonadmin");

        // `tdh::make_auth` builds a non-admin (`is_admin: false`) extension.
        let auth = tdh::make_auth(uuid::Uuid::new_v4(), "non-admin-tester");
        assert!(!auth.is_admin, "fixture auth must be non-admin");

        let obj = call_handler(state, Some(auth)).await;

        assert!(obj.contains_key("auth"));
        assert!(
            !obj.contains_key("scanners"),
            "scanners leaked to non-admin"
        );
        assert!(
            !obj.contains_key("search_engine"),
            "search_engine leaked to non-admin"
        );
        assert!(
            !obj.contains_key("storage_backend"),
            "storage_backend leaked to non-admin"
        );
        assert!(
            !obj.contains_key("permissions"),
            "permissions leaked to non-admin"
        );
        assert!(
            !obj.contains_key("plugin_signing"),
            "plugin_signing leaked to non-admin"
        );
    }

    /// Authenticated admin caller: the handler takes the admin branch and
    /// returns the full security posture. This also exercises the
    /// `permissions` DB query against the seeded Postgres.
    #[tokio::test]
    async fn test_handler_admin_includes_security_posture() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool, "/tmp/sysconfig-admin");

        let mut auth = tdh::make_auth(uuid::Uuid::new_v4(), "admin-tester");
        auth.is_admin = true;

        let obj = call_handler(state, Some(auth)).await;

        // Public-safe fields remain present.
        assert!(obj.contains_key("max_upload_size_bytes"));
        assert!(obj.contains_key("auth"));

        // Full security posture is disclosed to the admin.
        assert!(obj.contains_key("scanners"), "scanners missing for admin");
        assert!(
            obj.contains_key("search_engine"),
            "search_engine missing for admin"
        );
        assert!(
            obj.contains_key("storage_backend"),
            "storage_backend missing for admin"
        );
        assert!(
            obj.contains_key("permissions"),
            "permissions missing for admin"
        );
        assert!(
            obj.contains_key("plugin_signing"),
            "plugin_signing missing for admin"
        );

        // The test config wires no scanners / opensearch, so the admin view
        // should reflect the default disabled posture (admin branch values).
        assert_eq!(obj["search_engine"], "database");
        assert_eq!(obj["scanners"]["trivy_enabled"], false);
        assert_eq!(obj["permissions"]["enforcement_enabled"], true);
    }
}
