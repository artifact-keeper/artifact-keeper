//! gRPC authentication and authorization interceptor.
//!
//! Validates JWT tokens from the `authorization` metadata field on all gRPC
//! requests. In addition to authentication (valid token, correct type), the
//! interceptor enforces authorization by requiring the `is_admin` claim. All
//! current gRPC services (SBOM, CVE History, Security Policy) are admin-only
//! operations, matching the HTTP layer's `admin_middleware` behaviour.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use tonic::{Request, Status};

use crate::services::auth_service::Claims;

/// gRPC auth interceptor that validates JWT Bearer tokens and enforces admin authorization.
#[derive(Clone)]
pub struct AuthInterceptor {
    decoding_key: DecodingKey,
    require_admin: bool,
}

impl AuthInterceptor {
    /// Create an interceptor that requires admin privileges (default for all
    /// current gRPC services).
    pub fn new(jwt_secret: &str) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
            require_admin: true,
        }
    }

    /// Create an interceptor that only requires authentication, not admin.
    /// Available for future gRPC services that should be accessible to all
    /// authenticated users.
    #[allow(dead_code)]
    pub fn new_auth_only(jwt_secret: &str) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
            require_admin: false,
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
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

        if token_data.claims.token_type != "access" {
            return Err(Status::unauthenticated("Invalid token type"));
        }

        // Check whether the token has been invalidated (e.g. password change,
        // credential rotation). Mirrors the HTTP auth middleware check.
        if crate::services::auth_service::is_token_invalidated(
            token_data.claims.sub,
            token_data.claims.iat,
        ) {
            return Err(Status::unauthenticated("Token has been revoked"));
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
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 3600,
            token_type: token_type.to_string(),
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
        let interceptor = AuthInterceptor::new("secret");
        let req = Request::new(());
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("Missing"));
    }

    #[test]
    fn test_invalid_token() {
        let interceptor = AuthInterceptor::new("secret");
        let req = request_with_token("not-a-valid-jwt");
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("Invalid token"));
    }

    #[test]
    fn test_wrong_token_type_rejected() {
        let token = make_token("secret", true, "refresh");
        let interceptor = AuthInterceptor::new("secret");
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("Invalid token type"));
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let token = make_token("secret-a", true, "access");
        let interceptor = AuthInterceptor::new("secret-b");
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
        let interceptor = AuthInterceptor::new("secret");
        let req = request_with_token(&token);
        assert!(interceptor.intercept(req).is_ok());
    }

    #[test]
    fn test_non_admin_rejected_by_default() {
        let token = make_token("secret", false, "access");
        let interceptor = AuthInterceptor::new("secret");
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("Admin access required"));
    }

    #[test]
    fn test_non_admin_allowed_with_auth_only() {
        let token = make_token("secret", false, "access");
        let interceptor = AuthInterceptor::new_auth_only("secret");
        let req = request_with_token(&token);
        assert!(interceptor.intercept(req).is_ok());
    }

    #[test]
    fn test_auth_only_still_validates_token_type() {
        let token = make_token("secret", false, "refresh");
        let interceptor = AuthInterceptor::new_auth_only("secret");
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_auth_only_still_validates_token() {
        let interceptor = AuthInterceptor::new_auth_only("secret");
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
            iat,
            exp: iat + 3600,
            token_type: "access".to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        // Invalidate the user's tokens (timestamp will be now, after iat)
        crate::services::auth_service::invalidate_user_tokens(user_id);

        let interceptor = AuthInterceptor::new("secret");
        let req = request_with_token(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("revoked"));
    }
}
