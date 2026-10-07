---
section: Security
issues: [#4314]
---
- **A credential from the CI OIDC exchange can no longer mint an API token for its service account** (#4314). `POST /api/v1/profile/access-tokens`, `POST /api/v1/auth/tokens` and `POST /api/v1/repositories/{key}/tokens` now return 403 when the caller is a CI OIDC service account (`auth_provider = ci`), whichever provider type issued the credential. Before this, a pull-only, non-renewable `kubernetes` credential, or a GitHub/GitLab pipeline credential, could mint a `read:artifacts` API token that, under the default token policy, never expires, turning a short-lived credential into a permanent one. A pipeline that needs a longer-lived token should exchange a fresh CI token per job; an administrator can still issue a token for a CI account through the admin endpoints.
