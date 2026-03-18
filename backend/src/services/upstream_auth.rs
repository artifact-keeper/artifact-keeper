//! Upstream authentication for remote/proxy repositories.
//!
//! Loads encrypted credentials from `repository_config` and applies them
//! to outgoing HTTP requests. Supports Basic and Bearer auth types.

use reqwest::RequestBuilder;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::auth_config_service::encryption_key;
use crate::services::encryption::{decrypt_credentials, encrypt_credentials};

/// Auth types supported for upstream repositories.
#[derive(Debug, Clone, PartialEq)]
pub enum UpstreamAuthType {
    Basic { username: String, password: String },
    Bearer { token: String },
}

/// Load upstream auth credentials for a repository.
/// Returns None if no auth is configured.
pub async fn load_upstream_auth(db: &PgPool, repo_id: Uuid) -> Result<Option<UpstreamAuthType>> {
    // Load auth type
    let auth_type: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'upstream_auth_type'",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .flatten();

    let auth_type = match filter_auth_type(auth_type) {
        Some(t) => t,
        None => return Ok(None),
    };

    // Load and decrypt credentials
    let encrypted_hex: String = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'upstream_auth_credentials'",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .flatten()
    .ok_or_else(|| {
        AppError::Config(
            "Upstream auth type is configured but credentials are missing".to_string(),
        )
    })?;

    let credentials_json = decrypt_credentials_hex(&encrypted_hex, &encryption_key())?;

    parse_credentials_json(&auth_type, &credentials_json).map(Some)
}

/// Parse auth credentials from a JSON value given an auth type string.
/// Returns the appropriate `UpstreamAuthType` variant.
pub(crate) fn parse_auth_credentials(
    auth_type: &str,
    creds: &serde_json::Value,
) -> Result<UpstreamAuthType> {
    match auth_type {
        "basic" => {
            let username = creds["username"].as_str().unwrap_or_default().to_string();
            let password = creds["password"].as_str().unwrap_or_default().to_string();
            Ok(UpstreamAuthType::Basic { username, password })
        }
        "bearer" => {
            let token = creds["token"].as_str().unwrap_or_default().to_string();
            Ok(UpstreamAuthType::Bearer { token })
        }
        other => Err(AppError::Config(format!(
            "Unknown upstream auth type: {other}"
        ))),
    }
}

/// Apply upstream auth to a reqwest RequestBuilder.
pub fn apply_upstream_auth(builder: RequestBuilder, auth: &UpstreamAuthType) -> RequestBuilder {
    match auth {
        UpstreamAuthType::Basic { username, password } => {
            builder.basic_auth(username, Some(password))
        }
        UpstreamAuthType::Bearer { token } => builder.bearer_auth(token),
    }
}

/// Store upstream auth credentials for a repository.
/// Encrypts credentials before writing to repository_config.
pub async fn save_upstream_auth(
    db: &PgPool,
    repo_id: Uuid,
    auth_type: &str,
    credentials_json: &str,
) -> Result<()> {
    let encrypted_hex = encrypt_credentials_hex(credentials_json, &encryption_key());

    // Upsert auth type
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, 'upstream_auth_type', $2) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $2, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(auth_type)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Upsert encrypted credentials
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, 'upstream_auth_credentials', $2) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $2, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(&encrypted_hex)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Remove upstream auth credentials for a repository.
pub async fn remove_upstream_auth(db: &PgPool, repo_id: Uuid) -> Result<()> {
    sqlx::query(
        "DELETE FROM repository_config WHERE repository_id = $1 \
         AND key IN ('upstream_auth_type', 'upstream_auth_credentials')",
    )
    .bind(repo_id)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Check whether upstream auth is configured for a repository.
/// Returns the auth type string (e.g. "basic", "bearer") or None.
pub async fn get_upstream_auth_type(db: &PgPool, repo_id: Uuid) -> Result<Option<String>> {
    let val: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'upstream_auth_type'",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .flatten();

    Ok(filter_auth_type(val))
}

/// Filter an auth type value: returns None for empty, "none", or missing values.
pub(crate) fn filter_auth_type(val: Option<String>) -> Option<String> {
    match val {
        Some(t) if !t.is_empty() && t != "none" => Some(t),
        _ => None,
    }
}

/// Encrypt credentials and return hex-encoded ciphertext.
pub(crate) fn encrypt_credentials_hex(credentials_json: &str, key: &str) -> String {
    let encrypted = encrypt_credentials(credentials_json, key);
    hex::encode(&encrypted)
}

/// Decode hex ciphertext and decrypt to get the original credentials JSON.
pub(crate) fn decrypt_credentials_hex(hex_str: &str, key: &str) -> Result<String> {
    let encrypted_bytes = hex::decode(hex_str)
        .map_err(|e| AppError::Internal(format!("Failed to decode upstream credentials: {e}")))?;
    decrypt_credentials(&encrypted_bytes, key)
        .map_err(|e| AppError::Internal(format!("Failed to decrypt upstream credentials: {e}")))
}

/// Parse a credentials JSON string into an UpstreamAuthType.
/// Combines JSON parsing with auth type dispatch.
pub(crate) fn parse_credentials_json(
    auth_type: &str,
    credentials_json: &str,
) -> Result<UpstreamAuthType> {
    let creds: serde_json::Value = serde_json::from_str(credentials_json)
        .map_err(|e| AppError::Internal(format!("Invalid upstream credentials JSON: {e}")))?;
    parse_auth_credentials(auth_type, &creds)
}

/// Build the JSON credential payload for a given auth type.
/// Used by save_upstream_auth callers to construct the right shape.
pub fn build_credentials_json(auth: &UpstreamAuthType) -> String {
    match auth {
        UpstreamAuthType::Basic { username, password } => {
            serde_json::json!({"username": username, "password": password}).to_string()
        }
        UpstreamAuthType::Bearer { token } => serde_json::json!({"token": token}).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // apply_upstream_auth
    // -----------------------------------------------------------------------

    #[test]
    fn test_apply_basic_auth() {
        let client = reqwest::Client::new();
        let auth = UpstreamAuthType::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        let _builder = apply_upstream_auth(client.get("http://example.com"), &auth);
    }

    #[test]
    fn test_apply_bearer_auth() {
        let client = reqwest::Client::new();
        let auth = UpstreamAuthType::Bearer {
            token: "tok_123".to_string(),
        };
        let _builder = apply_upstream_auth(client.get("http://example.com"), &auth);
    }

    // -----------------------------------------------------------------------
    // encrypt / decrypt roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = "test-secret-key";
        let creds = r#"{"username":"bot","password":"s3cret"}"#;
        let encrypted = encrypt_credentials(creds, key);
        let decrypted = decrypt_credentials(&encrypted, key).unwrap();
        assert_eq!(creds, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_bearer_roundtrip() {
        let key = "another-key-456";
        let creds = r#"{"token":"ghp_abc123xyz"}"#;
        let encrypted = encrypt_credentials(creds, key);
        let decrypted = decrypt_credentials(&encrypted, key).unwrap();
        assert_eq!(creds, decrypted);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let creds = r#"{"token":"secret"}"#;
        let encrypted = encrypt_credentials(creds, "correct-key");
        let result = decrypt_credentials(&encrypted, "wrong-key");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // parse_auth_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_basic_credentials() {
        let creds = serde_json::json!({"username": "admin", "password": "hunter2"});
        let auth = parse_auth_credentials("basic", &creds).unwrap();
        assert_eq!(
            auth,
            UpstreamAuthType::Basic {
                username: "admin".to_string(),
                password: "hunter2".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_bearer_credentials() {
        let creds = serde_json::json!({"token": "ghp_abc123"});
        let auth = parse_auth_credentials("bearer", &creds).unwrap();
        assert_eq!(
            auth,
            UpstreamAuthType::Bearer {
                token: "ghp_abc123".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_unknown_auth_type() {
        let creds = serde_json::json!({"key": "value"});
        let result = parse_auth_credentials("oauth2", &creds);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("Unknown upstream auth type: oauth2"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_basic_missing_fields_defaults_to_empty() {
        let creds = serde_json::json!({});
        let auth = parse_auth_credentials("basic", &creds).unwrap();
        assert_eq!(
            auth,
            UpstreamAuthType::Basic {
                username: "".to_string(),
                password: "".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_bearer_missing_token_defaults_to_empty() {
        let creds = serde_json::json!({});
        let auth = parse_auth_credentials("bearer", &creds).unwrap();
        assert_eq!(
            auth,
            UpstreamAuthType::Bearer {
                token: "".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_basic_with_extra_fields_ignores_them() {
        let creds = serde_json::json!({
            "username": "bot",
            "password": "pass",
            "extra": "ignored"
        });
        let auth = parse_auth_credentials("basic", &creds).unwrap();
        assert_eq!(
            auth,
            UpstreamAuthType::Basic {
                username: "bot".to_string(),
                password: "pass".to_string(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // filter_auth_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_auth_type_basic() {
        assert_eq!(
            filter_auth_type(Some("basic".to_string())),
            Some("basic".to_string())
        );
    }

    #[test]
    fn test_filter_auth_type_bearer() {
        assert_eq!(
            filter_auth_type(Some("bearer".to_string())),
            Some("bearer".to_string())
        );
    }

    #[test]
    fn test_filter_auth_type_none_string() {
        assert_eq!(filter_auth_type(Some("none".to_string())), None);
    }

    #[test]
    fn test_filter_auth_type_empty_string() {
        assert_eq!(filter_auth_type(Some("".to_string())), None);
    }

    #[test]
    fn test_filter_auth_type_none_value() {
        assert_eq!(filter_auth_type(None), None);
    }

    // -----------------------------------------------------------------------
    // build_credentials_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_credentials_json_basic() {
        let auth = UpstreamAuthType::Basic {
            username: "deploy".to_string(),
            password: "s3cret".to_string(),
        };
        let json_str = build_credentials_json(&auth);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["username"], "deploy");
        assert_eq!(parsed["password"], "s3cret");
    }

    #[test]
    fn test_build_credentials_json_bearer() {
        let auth = UpstreamAuthType::Bearer {
            token: "ghp_xyz".to_string(),
        };
        let json_str = build_credentials_json(&auth);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["token"], "ghp_xyz");
    }

    #[test]
    fn test_build_then_parse_roundtrip_basic() {
        let original = UpstreamAuthType::Basic {
            username: "ci-bot".to_string(),
            password: "p@ssw0rd!".to_string(),
        };
        let json_str = build_credentials_json(&original);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let restored = parse_auth_credentials("basic", &parsed).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn test_build_then_parse_roundtrip_bearer() {
        let original = UpstreamAuthType::Bearer {
            token: "tok_abc123!@#".to_string(),
        };
        let json_str = build_credentials_json(&original);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let restored = parse_auth_credentials("bearer", &parsed).unwrap();
        assert_eq!(original, restored);
    }

    // -----------------------------------------------------------------------
    // UpstreamAuthType traits
    // -----------------------------------------------------------------------

    #[test]
    fn test_upstream_auth_type_clone() {
        let auth = UpstreamAuthType::Basic {
            username: "u".to_string(),
            password: "p".to_string(),
        };
        let cloned = auth.clone();
        assert_eq!(auth, cloned);
    }

    #[test]
    fn test_upstream_auth_type_debug() {
        let auth = UpstreamAuthType::Bearer {
            token: "tok".to_string(),
        };
        let debug = format!("{:?}", auth);
        assert!(debug.contains("Bearer"));
        assert!(debug.contains("tok"));
    }

    #[test]
    fn test_upstream_auth_type_inequality() {
        let basic = UpstreamAuthType::Basic {
            username: "a".to_string(),
            password: "b".to_string(),
        };
        let bearer = UpstreamAuthType::Bearer {
            token: "t".to_string(),
        };
        assert_ne!(basic, bearer);
    }

    #[test]
    fn test_upstream_auth_type_basic_field_inequality() {
        let a = UpstreamAuthType::Basic {
            username: "user1".to_string(),
            password: "pass".to_string(),
        };
        let b = UpstreamAuthType::Basic {
            username: "user2".to_string(),
            password: "pass".to_string(),
        };
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // encrypt_credentials_hex / decrypt_credentials_hex
    // -----------------------------------------------------------------------

    #[test]
    fn test_encrypt_decrypt_hex_roundtrip_basic() {
        let key = "test-key-123";
        let creds = r#"{"username":"admin","password":"secret"}"#;
        let hex = encrypt_credentials_hex(creds, key);
        let decrypted = decrypt_credentials_hex(&hex, key).unwrap();
        assert_eq!(creds, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_hex_roundtrip_bearer() {
        let key = "another-key";
        let creds = r#"{"token":"ghp_xyz789"}"#;
        let hex = encrypt_credentials_hex(creds, key);
        let decrypted = decrypt_credentials_hex(&hex, key).unwrap();
        assert_eq!(creds, decrypted);
    }

    #[test]
    fn test_decrypt_hex_invalid_hex() {
        let result = decrypt_credentials_hex("not-valid-hex!!", "any-key");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decode"));
    }

    #[test]
    fn test_decrypt_hex_wrong_key() {
        let hex = encrypt_credentials_hex(r#"{"token":"secret"}"#, "correct-key");
        let result = decrypt_credentials_hex(&hex, "wrong-key");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_hex_produces_valid_hex() {
        let hex = encrypt_credentials_hex("test", "key");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!hex.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_credentials_json (JSON string -> UpstreamAuthType)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_credentials_json_basic() {
        let json = r#"{"username":"bot","password":"s3cret"}"#;
        let auth = parse_credentials_json("basic", json).unwrap();
        assert_eq!(
            auth,
            UpstreamAuthType::Basic {
                username: "bot".to_string(),
                password: "s3cret".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_credentials_json_bearer() {
        let json = r#"{"token":"ghp_abc"}"#;
        let auth = parse_credentials_json("bearer", json).unwrap();
        assert_eq!(
            auth,
            UpstreamAuthType::Bearer {
                token: "ghp_abc".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_credentials_json_invalid_json() {
        let result = parse_credentials_json("basic", "not-json{{{");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid"));
    }

    #[test]
    fn test_parse_credentials_json_unknown_type() {
        let json = r#"{"key":"val"}"#;
        let result = parse_credentials_json("apikey", json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown"));
    }

    // -----------------------------------------------------------------------
    // Full pipeline: build -> encrypt -> decrypt -> parse
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_pipeline_basic() {
        let original = UpstreamAuthType::Basic {
            username: "deploy-bot".to_string(),
            password: "p@ss!word#123".to_string(),
        };
        let key = "pipeline-test-key";
        let json = build_credentials_json(&original);
        let hex = encrypt_credentials_hex(&json, key);
        let decrypted = decrypt_credentials_hex(&hex, key).unwrap();
        let restored = parse_credentials_json("basic", &decrypted).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn test_full_pipeline_bearer() {
        let original = UpstreamAuthType::Bearer {
            token: "glpat-xxxx-yyyy-zzzz".to_string(),
        };
        let key = "pipeline-key-2";
        let json = build_credentials_json(&original);
        let hex = encrypt_credentials_hex(&json, key);
        let decrypted = decrypt_credentials_hex(&hex, key).unwrap();
        let restored = parse_credentials_json("bearer", &decrypted).unwrap();
        assert_eq!(original, restored);
    }
}
