---
section: Security
issues: [#5338, #5253]
---
- **MCP registries: search, the storage tree and listing totals no longer reveal server versions a reader is not served** (#5338, #5253). A caller who does not hold an MCP registry already got the registry's own `404` and no listing row for a held, refused, resolving, unresolvable or soft-deleted server version on the generic artifact routes. `/api/v1/search/*` (items, totals, facets, suggestions, trending and recent) now leaves those versions out too. So does the repository storage tree, which is rebuilt from the versions the caller is served. The artifact listing's total now counts only served versions on every page, with `total_is_exact: false` past 10,000 matching rows. Holders keep full access.
