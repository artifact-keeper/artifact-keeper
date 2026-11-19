---
section: Fixed
issues: [#6215]
---
- **A burst of requests carrying one valid API token no longer gets some `503 Authentication service is at capacity` while the token cache is cold** (#6215). A validated token is cached for five minutes, but every request that arrived while the first validation was still running missed the cache and ran its own bcrypt under `AUTH_MAX_CONCURRENCY`, so a burst larger than the cap was partly shed, at process start and again each time the cache entry expired. Concurrent requests for the same token now wait for the first validation and share its result, so one valid token costs one bcrypt per cache period whatever the fan-out. Only successes are cached; a refusal is shared only with the requests already waiting on it, and a database or capacity error is not shared at all. Every bcrypt that does run still takes a permit from the cap, and each request still counts as its own success or failure.
