---
section: Fixed
issues: [#5683]
---
- **OCI Basic credentials and the Bearer `base64(user:secret)` form are checked token-first, so a dead token no longer costs a password bcrypt** ([#5683]). `GET /v2/`, every `/v2` verb that reads Basic credentials itself, `/v2/token`, and a `Bearer` header carrying base64 `user:<secret>` (npm, cargo, goproxy) now classify the secret by its shape like the other Basic surfaces: an API-token-shaped secret is only an API token, a JWT-shaped one only an access token, and anything else one password check. A never-minted, expired or revoked token, or a JWT signed by another server, answers `401` without a bcrypt, without an auth-capacity permit and without a failed-login write, so `docker login` retries with a stale token no longer push the auth cap toward `503`. On the package routes the Bearer base64 form now also accepts `user:<api_token>` as that token, as Basic already did; on the management API it refuses an API token, as Basic does.
