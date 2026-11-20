---
section: Fixed
issues: [#6316]
---
- **The quota check before an upload body is read no longer waits on an exhausted connection pool** (#6316). Its storage and repository lookups each waited the full pool acquire timeout (`DATABASE_ACQUIRE_TIMEOUT_SECS`, 5 s by default) and then admitted the upload anyway, so under pool pressure an upload spent about 10 s before any real work, and a 503 `POOL_EXHAUSTED` came 10 to 16 s late. Both lookups now share one budget, `QUOTA_PRECHECK_BUDGET_MS` (default 500). When it runs out the upload is admitted with one warning and an `ak_quota_precheck_skipped_total` increment, and the publish admission after the body is read still enforces every quota. The `MAX_UPLOAD_SIZE` check, which needs no database, runs before the budget.
