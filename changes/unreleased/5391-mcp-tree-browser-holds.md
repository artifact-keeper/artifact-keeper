---
section: Security
issues: [#5391, #5253]
---
- **The tree browser no longer shows or serves MCP server versions a reader is not served, and no longer lets shared caches keep private content** (#5391, #5253). `GET /api/v1/tree` left a held, refused, resolving, unresolvable, denied or soft-deleted server version in the listing, and `GET /api/v1/tree/content` returned its server.json to anyone who could read the repository, anonymous callers of a public registry included. Both now apply the registry's serve decision: such a version has no node, and its content is the same `404` as a missing path. `/api/v1/tree/content` sent `Cache-Control: public, max-age=3600` for every repository. It now sends `no-store` for an MCP registry and `private, max-age=3600` for any non-public repository. Successful `/mcp/` reads now send `Cache-Control: no-store` for a version and `private, no-cache` with `Vary: Authorization, Cookie` for a listing. Holders keep full access.
