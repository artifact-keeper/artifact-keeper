//! gRPC authentication and authorization interceptor.
//!
//! Validates JWT tokens from the `authorization` metadata field on all gRPC
//! requests. In addition to authentication (valid token, correct type), the
//! interceptor enforces authorization by requiring the `is_admin` claim. All
//! current gRPC services (SBOM, CVE History, Security Policy) are admin-only
//! operations, matching the HTTP layer's `admin_middleware` behaviour.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use sqlx::PgPool;
use tonic::{Request, Status};

use crate::services::auth_service::Claims;

/// gRPC auth interceptor that validates JWT Bearer tokens and enforces admin authorization.
#[derive(Clone)]
pub struct AuthInterceptor {
    decoding_key: DecodingKey,
    require_admin: bool,
    /// Optional DB pool. When `Some`, the interceptor consults the replica-safe
    /// credential-change watermark (#1173) so a credential change on a peer
    /// replica is honoured even on the gRPC plane. When `None` (e.g. in unit
    /// tests that don't have a DB) the interceptor falls back to the in-memory
    /// fast-path map only.
    db: Option<PgPool>,
}

impl AuthInterceptor {
    /// Create an interceptor that requires admin privileges (default for all
    /// current gRPC services).
    ///
    /// `db` is the shared PostgreSQL pool used for the replica-safe credential
    /// invalidation check. Pass the same pool the rest of the application
    /// uses; pass `None` only in tests that don't want a DB roundtrip.
    pub fn new(jwt_secret: &str, db: Option<PgPool>) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
            require_admin: true,
            db,
        }
    }

    /// Create an interceptor that only requires authentication, not admin.
    /// Available for future gRPC services that should be accessible to all
    /// authenticated users.
    #[allow(dead_code)]
    pub fn new_auth_only(jwt_secret: &str, db: Option<PgPool>) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
            require_admin: false,
            db,
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn intercept(&self, req: Request<()>) -> Result<Request<()>, Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authorization token"))?;

        let validation = Validation::new(Algorithm::HS256);
        let mut token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

        if token_data.claims.token_type != "access" {
            return Err(Status::unauthenticated("Invalid token type"));
        }

        // Check whether the token has been invalidated (e.g. password change,
        // credential rotation). On replica deployments, fall through to the
        // DB-backed watermark so a change made on a peer replica is honoured
        // here too (#1173 / PR #1190 review). tonic interceptors are sync;
        // we run the async DB check via `block_in_place` which is safe on
        // the multi-threaded runtime tonic always uses.
        let invalidated = if let Some(db) = &self.db {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    crate::services::auth_service::is_token_invalidated_replica_safe(
                        db,
                        token_data.claims.sub,
                        token_data.claims.effective_iat_ms(),
                    ),
                )
            })
            .unwrap_or(false)
        } else {
            // No DB pool wired (test mode) — fall back to in-memory only.
            crate::services::auth_service::is_token_invalidated(
                token_data.claims.sub,
                token_data.claims.effective_iat_ms(),
            )
        };
        if invalidated {
            return Err(Status::unauthenticated("Token has been revoked"));
        }

        // Re-derive `is_admin` from the live server-side role. The JWT claim is
        // client-supplied and must not be the authorization source of truth: a
        // validly-signed token forged for a real low-priv subject with
        // `is_admin:true` must NOT be granted admin here either. When a DB pool
        // is wired we overwrite the claim with the live `users.is_admin`
        // (mirroring `validate_access_token_async`); a missing active row means
        // the subject is gone/deactivated and is rejected. In test mode
        // (`db = None`) there is no DB to consult, so we keep trusting the
        // claim, matching the in-memory invalidation fallback above.
        if let Some(db) = &self.db {
            let live_is_admin = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    crate::services::auth_service::fetch_live_is_admin(db, token_data.claims.sub),
                )
            })
            .map_err(|e| Status::internal(format!("Authorization lookup failed: {}", e)))?;
            match live_is_admin {
                Some(db_is_admin) => token_data.claims.is_admin = db_is_admin,
                None => {
                    return Err(Status::unauthenticated(
                        "Token subject is no longer an active user",
                    ));
                }
            }
        }

        // Authorization: reject non-admin users when admin is required.
        // This mirrors the HTTP admin_middleware check.
        if self.require_admin && !token_data.claims.is_admin {
            return Err(Status::permission_denied("Admin access required"));
        }

        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use uuid::Uuid;

    fn make_token(jwt_secret: &str, is_admin: bool, token_type: &str) -> String {
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            is_admin,
            allowed_repo_ids: None,
            iat: chrono::Utc::now().timestamp(),
            iat_ms: None,
            exp: chrono::Utc::now().timestamp() + 3600,
            token_type: token_type.to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap()
    }

    fn request_with_token(token: &str) -> Request<()> {
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token).parse().unwrap(),
        );
        req
    }

    // -----------------------------------------------------------------------
    // Authentication tests (token validation)
    // -----------------------------------------------------------------------

    #[test]
    fn test_missing_authorization_header() {
        let interceptor = AuthInterceptor::new("secret", None);
        let req = Request::new(());
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("Missing"));
    }

    #[test]
    fn test_invalid_token() {
        let interceptor = AuthInterceptor::new("secret", None);
        let req = request_with_token("not-a-valid-jwt");
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("Invalid token"));
    }

    #[test]
    fn test_wrong_token_type_rejected() {
        let token = make_token("secret", true, "refresh");
        let interceptor = AuthInterceptor::new("secret", None);
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("Invalid token type"));
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let token = make_token("secret-a", true, "access");
        let interceptor = AuthInterceptor::new("secret-b", None);
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // -----------------------------------------------------------------------
    // Authorization tests (admin check)
    // -----------------------------------------------------------------------

    #[test]
    fn test_admin_user_allowed() {
        let token = make_token("secret", true, "access");
        let interceptor = AuthInterceptor::new("secret", None);
        let req = request_with_token(&token);
        assert!(interceptor.intercept(req).is_ok());
    }

    #[test]
    fn test_non_admin_rejected_by_default() {
        let token = make_token("secret", false, "access");
        let interceptor = AuthInterceptor::new("secret", None);
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("Admin access required"));
    }

    #[test]
    fn test_non_admin_allowed_with_auth_only() {
        let token = make_token("secret", false, "access");
        let interceptor = AuthInterceptor::new_auth_only("secret", None);
        let req = request_with_token(&token);
        assert!(interceptor.intercept(req).is_ok());
    }

    #[test]
    fn test_auth_only_still_validates_token_type() {
        let token = make_token("secret", false, "refresh");
        let interceptor = AuthInterceptor::new_auth_only("secret", None);
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_auth_only_still_validates_token() {
        let interceptor = AuthInterceptor::new_auth_only("secret", None);
        let req = request_with_token("garbage");
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // -----------------------------------------------------------------------
    // Token invalidation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_revoked_token_rejected() {
        let user_id = Uuid::new_v4();
        // Issue the token in the past so invalidation timestamp is strictly later
        let iat = chrono::Utc::now().timestamp() - 10;
        let claims = Claims {
            sub: user_id,
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            is_admin: true,
            allowed_repo_ids: None,
            iat,
            iat_ms: Some(iat.saturating_mul(1000)),
            exp: iat + 3600,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        // Invalidate the user's tokens (timestamp will be now, after iat)
        crate::services::auth_service::invalidate_user_tokens(user_id);

        let interceptor = AuthInterceptor::new("secret", None);
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("revoked"));
    }

    // -----------------------------------------------------------------------
    // Admin authorization derives from the live DB role, not the JWT claim.
    // When a DB pool is wired the interceptor re-stamps is_admin from
    // `users.is_admin` before the require_admin gate, so a forged is_admin=true
    // token for a real low-priv subject is denied. DB-backed; skips silently
    // without DATABASE_URL. The interceptor runs the async DB lookup via
    // `block_in_place`, so this test needs a multi-thread runtime.
    // -----------------------------------------------------------------------

    fn make_token_for_sub(jwt_secret: &str, sub: Uuid, is_admin: bool) -> String {
        let claims = Claims {
            sub,
            username: "forged".to_string(),
            email: "forged@test.local".to_string(),
            is_admin,
            allowed_repo_ids: None,
            iat: chrono::Utc::now().timestamp(),
            iat_ms: Some(chrono::Utc::now().timestamp_millis()),
            exp: chrono::Utc::now().timestamp() + 3600,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap()
    }

    async fn insert_user(pool: &PgPool, is_admin: bool) -> Uuid {
        let id = Uuid::new_v4();
        let username = format!("grpc_{}", &id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, \
             is_admin, is_active, failed_login_attempts, password_changed_at, \
             created_at, updated_at) \
             VALUES ($1, $2, $3, 'unused', 'local', $4, true, 0, \
             NOW() - INTERVAL '60 seconds', NOW() - INTERVAL '60 seconds', \
             NOW() - INTERVAL '60 seconds')",
        )
        .bind(id)
        .bind(&username)
        .bind(format!("{username}@test.local"))
        .bind(is_admin)
        .execute(pool)
        .await
        .expect("insert user");
        id
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_grpc_forged_admin_denied_when_db_role_is_non_admin() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        // Make sure the in-memory invalidation cache doesn't short-circuit.
        let low_id = insert_user(&pool, false).await;

        let interceptor = AuthInterceptor::new("secret", Some(pool.clone()));
        let forged = make_token_for_sub("secret", low_id, true);
        let err = interceptor
            .intercept(request_with_token(&forged))
            .unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::PermissionDenied,
            "a forged is_admin=true token for a non-admin DB user must be denied"
        );

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(low_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_grpc_real_admin_allowed_with_db() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        let admin_id = insert_user(&pool, true).await;

        let interceptor = AuthInterceptor::new("secret", Some(pool.clone()));
        // Even a token claiming is_admin=false is re-stamped to the DB truth.
        let token = make_token_for_sub("secret", admin_id, false);
        assert!(
            interceptor.intercept(request_with_token(&token)).is_ok(),
            "a real DB admin must be allowed (is_admin re-stamped from the DB)"
        );

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(admin_id)
            .execute(&pool)
            .await;
    }
}
