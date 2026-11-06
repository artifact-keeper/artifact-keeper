---
section: Fixed
issues: [#5475]
---
- **Proxy load can no longer exhaust the main database pool through download recording or cross-replica locks** (#5475). The inline download recorder took a pooled connection on every proxy serve with no ceiling, and with `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED=true` every advisory lock detached a connection the pool then replaced, also unbounded. The recorder is now capped at the same ceiling as the deferred recorder (#3778) and skips the download count past it, and `PgAdvisoryLock` caps its detached connections, releasing the key before refusing so the caller falls back to per-process single-flight. `PROXY_SINGLEFLIGHT_LOCK_MAX_CONNECTIONS` sets the lock cap and defaults to `PROXY_SINGLEFLIGHT_MAX_LOCK_WAITERS` + 1.
