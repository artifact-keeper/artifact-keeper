---
section: Security
issues: [#5484]
---
- **A password alone no longer gets past TOTP or the SSO-only login policy** ([#5484]). Password sign-in outside `POST /api/v1/auth/login` skipped the two policies that endpoint applies after the password. With only a TOTP-enrolled user's password, `curl -u user:pw -X POST /api/v1/auth/tokens` minted a non-expiring API token and admin routes were served. LDAP login, the OIDC callback and the SAML ACS issued a session, and the format routes and direct OCI Basic auth served requests. Now:
  - HTTP Basic `username:password` on `/api/v1` (and the base64 form some clients send as a Bearer token) gets the same `401` as a wrong password for an account with TOTP enrolled, an account the TOTP enforcement policy requires to enrol, or a non-admin local account while an SSO provider is enabled. The verified-admin break-glass is kept as at `/auth/login`.
  - `POST /api/v1/auth/sso/ldap/{id}/login`, and the exchange code from the OIDC callback and SAML ACS, return the `/auth/login` TOTP challenge (`totp_required: true` and a `totp_token` to redeem at `POST /api/v1/auth/totp/verify`) for a user who enrolled TOTP. No session cookies are set until then.
  - On the format and registry routes, a password for an account with TOTP enrolled gets `401`, as `/v2/token` already answered.

  **Upgrade note:** automation that sends such an account's password must switch to an API token (`Authorization: Bearer <token>`, or the token as the Basic password on format routes). The web UI needs a matching update to show its TOTP step after LDAP and SSO sign-in. See `docs/two-factor-and-passwords.md`.
