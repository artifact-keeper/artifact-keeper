---
section: Security
issues: [#5397]
---
- **A search request no longer re-evaluates the MCP listing decision for every version of every MCP registry in scope** (#5397). `/api/v1/search/*` hides MCP server versions a caller is not served (#5253). For a caller who does not hold a registry, anonymous ones included, every request read all of that registry's artifact rows (unbounded) and ran the listing decision over up to 10,000 versions, with nothing reused between requests, so cheap repeated searches could load the server.

  Whether the caller holds a registry is still decided on every request. The set of artifacts served to readers, which is the same for every caller who does not hold the registry, is now computed at most once per registry every 5 seconds on each replica and shared across requests; concurrent requests wait for one computation, and a holder's decision is never cached. A hold, release or status change therefore reaches search within 5 seconds (the `/v0.1` listings and the generic artifact routes still evaluate it on every request). Search now shows a reader of such a registry only the artifacts that set names, read with a bound of 10,000 versions and 20,000 rows per registry: rows past the bound, and rows stored since the set was computed, are hidden until it is recomputed (fail closed).
