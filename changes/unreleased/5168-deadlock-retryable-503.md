---
section: Fixed
issues: [#5168, #4989]
---
- **A Postgres deadlock now answers a retryable 503 instead of a 500** (#5168, #4989). Postgres breaks a lock cycle by rolling one transaction back, so a `40P01` that reaches a client means that transaction changed nothing and running it again succeeds. It answered `500 DATABASE_ERROR`, which clients read as a server bug and do not retry. It now answers `503 DATABASE_DEADLOCK` with `Retry-After`, and is still logged at error level.
