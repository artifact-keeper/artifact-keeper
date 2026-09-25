---
section: Security
issues: [#4020]
---
- **The OCI `/v2/token` credential exchange is now rate limited with the same budget as `/api/v1/auth/login`** (#4020). The endpoint is unauthenticated by design and was mounted outside the API rate-limit layers, so password guessing against it was bounded only by account lockout. The Basic-auth and OAuth2 password-grant exits now draw from the login limiter's per-(username, IP) budget (default 10 attempts / 15 minutes) and global backstop — shared with `/api/v1/auth/login`, so a guess against either endpoint spends the same budget — answering excess attempts with `429` and `Retry-After`. The refresh-grant, bearer-swap, and anonymous-mint exits, which present an already-issued credential or no credential, are deliberately not limited.
