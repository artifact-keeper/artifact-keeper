---
section: Fixed
issues: [#4558, #4020]
---
- **OCI `/v2/token` credential exchanges have their own per-user rate-limit bucket instead of spending the ten-per-fifteen-minutes login budget** (#4558, #4020). Since #4020 the token exchange drew from the same per-(username, IP) bucket as `/api/v1/auth/login`, but a container client exchanges credentials once per repository scope and per tool, so an ordinary `podman push` followed by `cosign sign` and `cosign verify` ran out of budget and got `429`. `/v2/token` now has a separate per-(username, IP) bucket, `RATE_LIMIT_TOKEN_EXCHANGE_PER_WINDOW` (default 300) per `RATE_LIMIT_LOGIN_WINDOW_SECS`, while the global login backstop and the per-IP failed-verification budget stay shared with the login endpoint, so the two surfaces together still bound total password verification.
