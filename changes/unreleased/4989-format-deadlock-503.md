---
section: Fixed
issues: [#4989]
---
- **A database deadlock on npm, OCI, Git LFS and the other routes with their own error format is a retryable 503** ([#4989]). Routes that build their own error body answered a deadlock Postgres broke by rolling the transaction back with `500`, while the generic routes have answered `503 DATABASE_DEADLOCK` with `Retry-After` since #5168. They now answer `503` with `Retry-After` and the message "Database transaction was rolled back by a lock conflict, retry shortly". The deadlock is still logged at error level.
