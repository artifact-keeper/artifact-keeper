---
section: Fixed
issues: [#5395]
---
- **An MCP resolver fill now has one deadline over the whole fill, response body included** (#5395). The in-process request that fills a Remote backing repository was bounded only until the response head arrived; the body was read afterwards with no deadline, so a slow upstream trickling a package could hold a resolver job, and its worker slot, indefinitely. Every request of a fill (head and body, both PyPI requests) now has to finish within one 300 s deadline, and a fill that misses it is recorded as a retryable failure and retried with backoff like any other transient fill error.
