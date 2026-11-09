---
section: Security
issues: [#5454]
---
- **`/api/v1/packages` no longer shows a soft-deleted MCP server version to a reader** (#5454). A server whose only version had been soft-deleted (status `deleted`) still had a catalog row in `/api/v1/packages` for anonymous callers and callers without a grant on the registry, with its name, version, size and times, and it was counted in `pagination.total`; `GET /api/v1/packages/{id}/versions` listed the deleted version too. Both now use the same visibility rule as the `/v0.1` listing and the other generic routes (search, artifact listing, storage figures and tree, tree browser and tree content), which already left the version out. Holders of the registry still see every version.
