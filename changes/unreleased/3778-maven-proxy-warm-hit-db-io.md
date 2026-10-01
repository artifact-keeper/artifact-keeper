---
section: Fixed
issues: [#3778]
---
- **Warm Maven proxy-cache hits no longer perform synchronous PostgreSQL I/O on every GET** (#3778). The Maven resolver now reads repository metadata from the shared 60-second in-process repo cache that `repo_visibility_middleware` already maintains (the enforcement columns `promotion_only`/`age_gate_*`/`curation_*` ride the same cache entry and are covered by the fleet-wide invalidation trigger, so gates cannot go stale), and the `proxy_cache_artifacts` upsert + `proxy_download_statistics` insert are recorded from a bounded background task instead of blocking the response — falling back to inline recording when the background limiter is saturated, so download statistics stay exact under load. A warm hit is now memory lookup + cache storage read, with database latency off the critical path.
