---
section: Changed
issues: [#5002]
---
- **An asynchronous chunked completion holds a ten-minute lease instead of six hours** (#5002). `Prefer: respond-async` now claims the session with a shorter completion lease and renews it with the same TTL while the detached commit is alive. A replica that restarts mid-commit no longer strands the session in `committing` for six hours: the lease lapses after ten minutes without a renewal and the same completion request can be retried with the staged chunks still present. The in-request completion keeps the six-hour lease, and a live renewal still blocks a duplicate completion and fences a stale owner.
