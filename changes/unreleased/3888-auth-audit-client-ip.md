---
section: Fixed
issues: [#3888]
---
- **Authentication audit events now record the client IP address** (#3888). Login, logout, token-refresh, SSO (OIDC/SAML/LDAP), and TOTP second-factor events were written to `audit_log` with `ip_address = NULL`. A new request-scoped client-IP context, resolved from the TCP peer with `X-Forwarded-For` believed only when the peer is inside a configured `RATE_LIMIT_TRUSTED_PROXY_CIDRS` range (the same trusted-proxy policy the rate limiter keys on), is now attached to every authentication audit entry. Events emitted outside a request (background jobs) still record NULL rather than a sentinel.
