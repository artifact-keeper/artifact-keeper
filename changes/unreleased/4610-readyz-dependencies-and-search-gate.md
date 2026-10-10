---
section: Added
issues: [#4610]
---
- **`/readyz` reports its dependencies, and `READYZ_REQUIRE_SEARCH` makes OpenSearch gate readiness** (#4610). `/readyz` keeps meaning "this replica can serve artifacts" (database reachable, migrations applied), but with OpenSearch stopped it answered 200 with nothing in the body to say search was down. Its response now always carries a `dependencies` object (`opensearch`, `storage`, `scanner`, `ldap`, each `healthy`, `unhealthy` or `not_configured`, with whether it is `required`), probed concurrently through the `/health` caches with a 2 second deadline each, and a `failing` list when not ready. Probe error text is only included with `EXPOSE_DETAILED_HEALTH=true`. Setting `READYZ_REQUIRE_SEARCH=true` (default false) makes an unhealthy or unconfigured OpenSearch a `503` naming `opensearch`; a database failure is a `503` either way. The endpoint stays exempt from the global concurrency limit. See `docs/operations/health-probes.md`.
