//! Application configuration loaded from environment variables.

use crate::error::{AppError, Result};
use std::env;

/// Read an environment variable and parse it, falling back to a default on missing or invalid values.
fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Database connection URL
    pub database_url: String,

    /// Server bind address (host:port)
    pub bind_address: String,

    /// Log level
    pub log_level: String,

    /// Storage backend: "filesystem" or "s3"
    pub storage_backend: String,

    /// Filesystem storage path (when storage_backend = "filesystem")
    pub storage_path: String,

    /// S3 bucket name (when storage_backend = "s3")
    pub s3_bucket: Option<String>,

    /// S3 region
    pub s3_region: Option<String>,

    /// S3 endpoint URL (for MinIO or other S3-compatible services)
    pub s3_endpoint: Option<String>,

    /// JWT secret key for signing tokens
    pub jwt_secret: String,

    /// JWT token expiration in seconds (legacy, use jwt_access_token_expiry_minutes)
    pub jwt_expiration_secs: u64,

    /// JWT access token expiry in minutes
    pub jwt_access_token_expiry_minutes: i64,

    /// JWT refresh token expiry in days
    pub jwt_refresh_token_expiry_days: i64,

    /// OIDC issuer URL (optional)
    pub oidc_issuer: Option<String>,

    /// OIDC client ID (optional)
    pub oidc_client_id: Option<String>,

    /// OIDC client secret (optional)
    pub oidc_client_secret: Option<String>,

    /// LDAP server URL (optional)
    pub ldap_url: Option<String>,

    /// LDAP base DN (optional)
    pub ldap_base_dn: Option<String>,

    /// Trivy server URL for container image scanning (optional)
    pub trivy_url: Option<String>,

    /// OpenSCAP wrapper URL for compliance scanning (optional)
    pub openscap_url: Option<String>,

    /// OpenSCAP SCAP profile to evaluate (default: standard)
    pub openscap_profile: String,

    /// Meilisearch URL for search indexing (optional)
    pub meilisearch_url: Option<String>,

    /// Meilisearch API key
    pub meilisearch_api_key: Option<String>,

    /// Path for scan workspace shared with Trivy
    pub scan_workspace_path: String,

    /// Demo mode: blocks all write operations (POST/PUT/DELETE/PATCH) except auth
    pub demo_mode: bool,

    /// Peer instance name for mesh identification
    pub peer_instance_name: String,

    /// Public endpoint URL where this instance can be reached by peers
    pub peer_public_endpoint: String,

    /// API key for authenticating peer-to-peer requests
    pub peer_api_key: String,

    /// Dependency-Track API URL for vulnerability management (optional)
    pub dependency_track_url: Option<String>,

    /// OpenTelemetry OTLP endpoint (optional, enables OTel when set).
    pub otel_exporter_otlp_endpoint: Option<String>,

    /// OpenTelemetry service name (default: "artifact-keeper").
    pub otel_service_name: String,

    /// Cron expression (6-field) for storage garbage collection (default: hourly).
    pub gc_schedule: String,

    /// How often (in seconds) the lifecycle scheduler checks for due policies.
    pub lifecycle_check_interval_secs: u64,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")
                .map_err(|_| AppError::Config("DATABASE_URL not set".into()))?,
            bind_address: env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            storage_backend: env::var("STORAGE_BACKEND").unwrap_or_else(|_| "filesystem".into()),
            storage_path: env::var("STORAGE_PATH")
                .unwrap_or_else(|_| "/var/lib/artifact-keeper/artifacts".into()),
            s3_bucket: env::var("S3_BUCKET").ok(),
            s3_region: env::var("S3_REGION").ok(),
            s3_endpoint: env::var("S3_ENDPOINT").ok(),
            jwt_secret: env::var("JWT_SECRET")
                .map_err(|_| AppError::Config("JWT_SECRET not set".into()))?,
            jwt_expiration_secs: env_parse("JWT_EXPIRATION_SECS", 86400),
            jwt_access_token_expiry_minutes: env_parse("JWT_ACCESS_TOKEN_EXPIRY_MINUTES", 30),
            jwt_refresh_token_expiry_days: env_parse("JWT_REFRESH_TOKEN_EXPIRY_DAYS", 7),
            oidc_issuer: env::var("OIDC_ISSUER").ok(),
            oidc_client_id: env::var("OIDC_CLIENT_ID").ok(),
            oidc_client_secret: env::var("OIDC_CLIENT_SECRET").ok(),
            ldap_url: env::var("LDAP_URL").ok(),
            ldap_base_dn: env::var("LDAP_BASE_DN").ok(),
            trivy_url: env::var("TRIVY_URL").ok(),
            openscap_url: env::var("OPENSCAP_URL").ok(),
            openscap_profile: env::var("OPENSCAP_PROFILE")
                .unwrap_or_else(|_| "xccdf_org.ssgproject.content_profile_standard".into()),
            meilisearch_url: env::var("MEILISEARCH_URL").ok(),
            meilisearch_api_key: env::var("MEILISEARCH_API_KEY").ok(),
            scan_workspace_path: env::var("SCAN_WORKSPACE_PATH")
                .unwrap_or_else(|_| "/scan-workspace".into()),
            demo_mode: matches!(env::var("DEMO_MODE").as_deref(), Ok("true" | "1")),
            peer_instance_name: env::var("PEER_INSTANCE_NAME")
                .unwrap_or_else(|_| "artifact-keeper-local".into()),
            peer_public_endpoint: env::var("PEER_PUBLIC_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            peer_api_key: env::var("PEER_API_KEY").unwrap_or_else(|_| {
                let key = format!("{:032x}", rand::random::<u128>());
                tracing::warn!(
                    "PEER_API_KEY not set, generated random key. \
                     Set PEER_API_KEY in your environment for stable peer authentication."
                );
                key
            }),
            dependency_track_url: env::var("DEPENDENCY_TRACK_URL").ok(),
            otel_exporter_otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
            otel_service_name: env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "artifact-keeper".into()),
            gc_schedule: env::var("GC_SCHEDULE").unwrap_or_else(|_| "0 0 * * * *".into()),
            lifecycle_check_interval_secs: env_parse("LIFECYCLE_CHECK_INTERVAL_SECS", 60),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Environment variable tests must be serialized because env is global state.
    // We use a mutex to prevent parallel test interference.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // -----------------------------------------------------------------------
    // env_parse
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_parse_returns_default_when_var_not_set() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Use a unique key unlikely to be set
        env::remove_var("__TEST_ENV_PARSE_MISSING_12345__");
        let result: u64 = env_parse("__TEST_ENV_PARSE_MISSING_12345__", 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_env_parse_parses_valid_value() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_VALID__", "100");
        let result: u64 = env_parse("__TEST_ENV_PARSE_VALID__", 42);
        assert_eq!(result, 100);
        env::remove_var("__TEST_ENV_PARSE_VALID__");
    }

    #[test]
    fn test_env_parse_returns_default_on_invalid_value() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_INVALID__", "not-a-number");
        let result: u64 = env_parse("__TEST_ENV_PARSE_INVALID__", 42);
        assert_eq!(result, 42);
        env::remove_var("__TEST_ENV_PARSE_INVALID__");
    }

    #[test]
    fn test_env_parse_bool() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_BOOL__", "true");
        let result: bool = env_parse("__TEST_ENV_PARSE_BOOL__", false);
        assert!(result);
        env::remove_var("__TEST_ENV_PARSE_BOOL__");
    }

    #[test]
    fn test_env_parse_i64() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_I64__", "-30");
        let result: i64 = env_parse("__TEST_ENV_PARSE_I64__", 7);
        assert_eq!(result, -30);
        env::remove_var("__TEST_ENV_PARSE_I64__");
    }

    #[test]
    fn test_env_parse_empty_string_falls_back_to_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_EMPTY__", "");
        // Empty string is not parseable as u64, so default is used
        let result: u64 = env_parse("__TEST_ENV_PARSE_EMPTY__", 99);
        assert_eq!(result, 99);
        env::remove_var("__TEST_ENV_PARSE_EMPTY__");
    }

    // -----------------------------------------------------------------------
    // Config::from_env
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_from_env_missing_database_url_errors() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Save and remove required vars
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        env::remove_var("DATABASE_URL");
        env::set_var("JWT_SECRET", "test-secret");

        let result = Config::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("DATABASE_URL"));

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    fn test_config_from_env_missing_jwt_secret_errors() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        env::set_var("DATABASE_URL", "postgresql://localhost/test");
        env::remove_var("JWT_SECRET");

        let result = Config::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("JWT_SECRET"));

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        }
    }

    #[test]
    fn test_config_from_env_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Save existing env vars
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_bind = env::var("BIND_ADDRESS").ok();
        let saved_log = env::var("LOG_LEVEL").ok();
        let saved_storage = env::var("STORAGE_BACKEND").ok();
        let saved_demo = env::var("DEMO_MODE").ok();

        // Set only required vars
        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", "super-secret");

        // Remove optional vars to test defaults
        env::remove_var("BIND_ADDRESS");
        env::remove_var("LOG_LEVEL");
        env::remove_var("STORAGE_BACKEND");
        env::remove_var("DEMO_MODE");

        let config = Config::from_env().expect("Config should load with required vars");

        assert_eq!(config.database_url, "postgresql://localhost/testdb");
        assert_eq!(config.jwt_secret, "super-secret");
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.storage_backend, "filesystem");
        assert_eq!(config.jwt_expiration_secs, 86400);
        assert_eq!(config.jwt_access_token_expiry_minutes, 30);
        assert_eq!(config.jwt_refresh_token_expiry_days, 7);
        assert!(!config.demo_mode);
        assert_eq!(config.scan_workspace_path, "/scan-workspace");
        assert_eq!(config.peer_instance_name, "artifact-keeper-local");
        assert_eq!(config.peer_public_endpoint, "http://localhost:8080");

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_bind {
            env::set_var("BIND_ADDRESS", v);
        }
        if let Some(v) = saved_log {
            env::set_var("LOG_LEVEL", v);
        }
        if let Some(v) = saved_storage {
            env::set_var("STORAGE_BACKEND", v);
        }
        if let Some(v) = saved_demo {
            env::set_var("DEMO_MODE", v);
        }
    }

    #[test]
    fn test_config_demo_mode_true() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_demo = env::var("DEMO_MODE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", "secret");
        env::set_var("DEMO_MODE", "true");

        let config = Config::from_env().unwrap();
        assert!(config.demo_mode);

        // Also test "1"
        env::set_var("DEMO_MODE", "1");
        let config = Config::from_env().unwrap();
        assert!(config.demo_mode);

        // Test "false" is not demo mode
        env::set_var("DEMO_MODE", "false");
        let config = Config::from_env().unwrap();
        assert!(!config.demo_mode);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_demo {
            env::set_var("DEMO_MODE", v);
        } else {
            env::remove_var("DEMO_MODE");
        }
    }

    #[test]
    fn test_config_custom_jwt_expiry() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_exp = env::var("JWT_EXPIRATION_SECS").ok();
        let saved_access = env::var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES").ok();
        let saved_refresh = env::var("JWT_REFRESH_TOKEN_EXPIRY_DAYS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", "secret");
        env::set_var("JWT_EXPIRATION_SECS", "3600");
        env::set_var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES", "15");
        env::set_var("JWT_REFRESH_TOKEN_EXPIRY_DAYS", "14");

        let config = Config::from_env().unwrap();
        assert_eq!(config.jwt_expiration_secs, 3600);
        assert_eq!(config.jwt_access_token_expiry_minutes, 15);
        assert_eq!(config.jwt_refresh_token_expiry_days, 14);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_exp {
            env::set_var("JWT_EXPIRATION_SECS", v);
        } else {
            env::remove_var("JWT_EXPIRATION_SECS");
        }
        if let Some(v) = saved_access {
            env::set_var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES", v);
        } else {
            env::remove_var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES");
        }
        if let Some(v) = saved_refresh {
            env::set_var("JWT_REFRESH_TOKEN_EXPIRY_DAYS", v);
        } else {
            env::remove_var("JWT_REFRESH_TOKEN_EXPIRY_DAYS");
        }
    }

    #[test]
    fn test_config_gc_schedule_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_gc = env::var("GC_SCHEDULE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", "secret");
        env::remove_var("GC_SCHEDULE");

        let config = Config::from_env().unwrap();
        assert_eq!(config.gc_schedule, "0 0 * * * *");

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_gc {
            env::set_var("GC_SCHEDULE", v);
        }
    }

    #[test]
    fn test_config_gc_schedule_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_gc = env::var("GC_SCHEDULE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", "secret");
        env::set_var("GC_SCHEDULE", "0 30 2 * * *");

        let config = Config::from_env().unwrap();
        assert_eq!(config.gc_schedule, "0 30 2 * * *");

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_gc {
            env::set_var("GC_SCHEDULE", v);
        } else {
            env::remove_var("GC_SCHEDULE");
        }
    }

    #[test]
    fn test_config_lifecycle_check_interval_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_lc = env::var("LIFECYCLE_CHECK_INTERVAL_SECS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", "secret");
        env::remove_var("LIFECYCLE_CHECK_INTERVAL_SECS");

        let config = Config::from_env().unwrap();
        assert_eq!(config.lifecycle_check_interval_secs, 60);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_lc {
            env::set_var("LIFECYCLE_CHECK_INTERVAL_SECS", v);
        }
    }

    #[test]
    fn test_config_lifecycle_check_interval_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_lc = env::var("LIFECYCLE_CHECK_INTERVAL_SECS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", "secret");
        env::set_var("LIFECYCLE_CHECK_INTERVAL_SECS", "300");

        let config = Config::from_env().unwrap();
        assert_eq!(config.lifecycle_check_interval_secs, 300);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_lc {
            env::set_var("LIFECYCLE_CHECK_INTERVAL_SECS", v);
        } else {
            env::remove_var("LIFECYCLE_CHECK_INTERVAL_SECS");
        }
    }

    #[test]
    fn test_config_optional_s3_fields() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_bucket = env::var("S3_BUCKET").ok();
        let saved_region = env::var("S3_REGION").ok();
        let saved_endpoint = env::var("S3_ENDPOINT").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", "secret");
        env::set_var("S3_BUCKET", "my-bucket");
        env::set_var("S3_REGION", "us-east-1");
        env::set_var("S3_ENDPOINT", "http://minio:9000");

        let config = Config::from_env().unwrap();
        assert_eq!(config.s3_bucket.as_deref(), Some("my-bucket"));
        assert_eq!(config.s3_region.as_deref(), Some("us-east-1"));
        assert_eq!(config.s3_endpoint.as_deref(), Some("http://minio:9000"));

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_bucket {
            env::set_var("S3_BUCKET", v);
        } else {
            env::remove_var("S3_BUCKET");
        }
        if let Some(v) = saved_region {
            env::set_var("S3_REGION", v);
        } else {
            env::remove_var("S3_REGION");
        }
        if let Some(v) = saved_endpoint {
            env::set_var("S3_ENDPOINT", v);
        } else {
            env::remove_var("S3_ENDPOINT");
        }
    }
}
