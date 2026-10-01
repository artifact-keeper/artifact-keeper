---
section: Fixed
issues: [#3951]
---
- **npm virtual repositories with a private member no longer re-fetch a member's definitive 404 on every packument request, and buffered proxy-cache hits no longer read the same `__cache_meta__.json` twice** (#3951). The virtual member walk now keeps a short-lived in-process negative cache per (member, package) — the mechanism #3527 added for OCI — absorbing repeated misses within `NPM_VIRTUAL_NEGATIVE_CACHE_TTL_MS` (default 5 s, clamped to the proxy layer's 45 s negative window; `NPM_VIRTUAL_NEGATIVE_CACHE_MAX_ENTRIES`, default 4096, bounds memory; 0 disables). Only a definitive upstream 404 is recorded — throttling and 5xx are never pinned as absences. Separately, the buffered cache-read path reuses the metadata sidecar its freshness evaluation already loaded instead of bypassing the in-process sidecar LRU for a second storage read.
