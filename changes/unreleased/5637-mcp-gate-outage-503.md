---
section: Fixed
issues: [#5637]
---
- **MCP registry `503`s carry `Retry-After`, and holds-listing entries name their version during a gate outage** (#5637). A `503 mcp_gate_unavailable` (for example `scan_policies` unreachable) on an exact read, the holds listing or `POST /api/v1/mcp/introspection/jobs/claim` gave clients no backoff hint; every `503` the registry surface renders now sends `Retry-After: 5`, and a `503` from the shared middleware keeps its own value. During such an outage a holds-listing entry carried only `error`, `detail` and `status`, so CI tooling could not tell which server was held; every entry now carries `name`, `version` and `instance`. `docs/mcp-registry.md` now says that a NUL byte in the URL answers `400 mcp_bad_request` (the instance-wide guard runs first) and that cursors are bound to the listing kind, not the query.
