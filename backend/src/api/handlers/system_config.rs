//! Public runtime configuration endpoint.
//!
//! Exposes non-sensitive configuration values so that frontends and clients can
//! discover upload limits, enabled integrations, and feature flags without
//! hardcoding assumptions.

use axum::{extract::State, Json};
use serde::Serialize;
use sqlx;
use utoipa::{OpenApi, ToSchema};

use crate::api::SharedState;

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

/// Public runtime configuration values.
///
/// This response intentionally omits all secrets, credentials, and internal
/// connection strings. Only values useful for UI/client behavior are included.
#[derive(Serialize, ToSchema)]
pub struct SystemConfigResponse {
    /// Maximum upload size in bytes (0 means no limit).
    pub max_upload_size_bytes: u64,
    /// Whether the instance is running in demo mode (writes blocked).
    pub demo_mode: bool,
    /// Scanner availability.
    pub scanners: ScannersConfig,
    /// Search engine type: "meilisearch" when configured, "database" otherwise.
    pub search_engine: String,
    /// Storage backend type (e.g. "filesystem", "s3", "gcs", "azure").
    pub storage_backend: String,
    /// Authentication provider availability.
    pub auth: AuthConfig,
    /// OIDC issuer URL, if configured. This is public information needed by
    /// clients to initiate the OIDC flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_issuer: Option<String>,
    /// Fine-grained permissions enforcement status. Permission rules can be
    /// managed via /api/v1/permissions and are actively enforced.
    pub permissions: PermissionsConfig,
}

/// Return public runtime configuration.
///
/// No authentication required. This endpoint exposes only non-sensitive
/// configuration values that help frontends adapt their behavior (e.g.
/// showing upload limits, conditionally rendering scanner UI, initiating
/// OIDC flows).
#[utoipa::path(
    get,
    path = "/config",
    context_path = "/api/v1/system",
    tag = "system",
    responses(
        (status = 200, description = "Public runtime configuration", body = SystemConfigResponse),
    )
)]
pub async fn get_system_config(State(state): State<SharedState>) -> Json<SystemConfigResponse> {
    let config = &state.config;

    let scanners = ScannersConfig {
        trivy_enabled: config.trivy_url.is_some(),
        openscap_enabled: config.openscap_url.is_some(),
        dependency_track_enabled: config.dependency_track_url.is_some(),
    };

    let auth = AuthConfig {
        oidc_enabled: config.oidc_issuer.is_some(),
        ldap_enabled: config.ldap_url.is_some(),
        sso_enabled: config.oidc_issuer.is_some(),
    };

    let search_engine = if config.meilisearch_url.is_some() {
        "meilisearch".to_string()
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

    Json(SystemConfigResponse {
        max_upload_size_bytes: config.max_upload_size_bytes,
        demo_mode: config.demo_mode,
        scanners,
        search_engine,
        storage_backend: config.storage_backend.clone(),
        auth,
        oidc_issuer: config.oidc_issuer.clone(),
        permissions,
    })
}

#[derive(OpenApi)]
#[openapi(
    paths(get_system_config),
    components(schemas(SystemConfigResponse, ScannersConfig, AuthConfig, PermissionsConfig))
)]
pub struct SystemConfigApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response from a config with all integrations disabled.
    fn minimal_response() -> SystemConfigResponse {
        SystemConfigResponse {
            max_upload_size_bytes: 10_737_418_240,
            demo_mode: false,
            scanners: ScannersConfig {
                trivy_enabled: false,
                openscap_enabled: false,
                dependency_track_enabled: false,
            },
            search_engine: "database".to_string(),
            storage_backend: "filesystem".to_string(),
            auth: AuthConfig {
                oidc_enabled: false,
                ldap_enabled: false,
                sso_enabled: false,
            },
            oidc_issuer: None,
            permissions: PermissionsConfig {
                rules_exist: false,
                enforcement_enabled: false,
            },
        }
    }

    #[test]
    fn test_system_config_response_serialization() {
        let response = minimal_response();
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"max_upload_size_bytes\":10737418240"));
        assert!(json.contains("\"demo_mode\":false"));
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
            scanners: ScannersConfig {
                trivy_enabled: true,
                openscap_enabled: true,
                dependency_track_enabled: true,
            },
            search_engine: "meilisearch".to_string(),
            storage_backend: "s3".to_string(),
            auth: AuthConfig {
                oidc_enabled: true,
                ldap_enabled: true,
                sso_enabled: true,
            },
            oidc_issuer: Some("https://auth.example.com".to_string()),
            permissions: PermissionsConfig {
                rules_exist: true,
                enforcement_enabled: true,
            },
        };

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"max_upload_size_bytes\":21474836480"));
        assert!(json.contains("\"demo_mode\":true"));
        assert!(json.contains("\"search_engine\":\"meilisearch\""));
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
        assert!(!json.contains("meilisearch_api_key"));
        assert!(!json.contains("meilisearch_url"));
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
    fn test_system_config_permissions_rules_exist_and_enforced() {
        let response = SystemConfigResponse {
            permissions: PermissionsConfig {
                rules_exist: true,
                enforcement_enabled: true,
            },
            ..minimal_response()
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["permissions"]["rules_exist"], true);
        assert_eq!(parsed["permissions"]["enforcement_enabled"], true);
    }
}
