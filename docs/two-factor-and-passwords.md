# Two-factor authentication and password-only sign-in

`POST /api/v1/auth/login` checks two policies after a correct password: the
TOTP gate (an account that enrolled TOTP, or one the TOTP enforcement policy
requires to enrol, gets a TOTP step) and the SSO-only local-login policy (while
an SSO provider is enabled, a non-admin local account must use SSO; the
verified-admin break-glass is kept). Since 1.12.0 ([#5484]) every other
password-based sign-in applies the same policies, or refuses when it cannot
run the TOTP step.

| Surface | Account with TOTP enrolled | Policy requires enrolment | Local account while SSO is enabled |
|---|---|---|---|
| `POST /api/v1/auth/login` | TOTP challenge | enrolment ticket | refused (admin break-glass kept) |
| HTTP Basic `user:password` on `/api/v1` (and base64 `user:password` as a Bearer) | `401` | `401` | `401` (admin break-glass kept) |
| `POST /api/v1/auth/sso/ldap/{id}/login` | TOTP challenge | n/a (applies to local accounts) | n/a |
| OIDC callback and SAML ACS | TOTP challenge through the exchange code | n/a | n/a |
| Format and registry routes: Basic password, base64 Bearer password, LDAP Basic passthrough, direct OCI Basic | `401` | unchanged | unchanged |
| `POST /v2/token` (Docker) | `401` (unchanged) | unchanged | unchanged |

A refused password gets the same `401` as a wrong one. The server logs the
reason at INFO under the `security` target and counts it as
`ak_auth_failures_total{surface="basic",reason="scope"}`.

## Automation for these accounts

Use an API token. On `/api/v1` send it as `Authorization: Bearer <token>`. On
the format and registry routes it also works as the Basic password
(`user:<api_token>`), for example in `.netrc`, `pip.conf`, `.npmrc` or
`docker login -p`.

## The TOTP challenge

The challenge has the same shape everywhere:

```json
{ "access_token": "", "refresh_token": "", "totp_required": true, "totp_token": "<single-use>" }
```

Redeem `totp_token` with a code at `POST /api/v1/auth/totp/verify`. That call
issues the session. No session cookies are set before it.

For OIDC and SAML, the IdP completion redirects to `/callback?code=…` as
before, but sets no session cookies. `POST /api/v1/auth/sso/exchange` with that
code returns the challenge above instead of tokens. The web UI must send the
user to its TOTP step when `totp_required` is `true`.

[#5484]: https://github.com/artifact-keeper/artifact-keeper/issues/5484
