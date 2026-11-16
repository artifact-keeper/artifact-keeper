---
section: Added
issues: [#6097]
---
- **The build list filters by name, branch, agent and creation time** (#6097, artifact-keeper/artifact-keeper-web#618). `GET /api/v1/builds` takes `name` (exact), `branch`, `agent`, `created_after` and `created_before` (RFC 3339) next to `status` and `search`, and the total counts the same filtered set
