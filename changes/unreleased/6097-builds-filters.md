---
section: Added
issues: [#6097]
---
- **The build list filters by name, branch, agent and creation time** (#6097, artifact-keeper/artifact-keeper-web#618). `GET /api/v1/builds` takes `name` (exact), `branch`, `agent`, `created_after` and `created_before` (RFC 3339) next to `status` and `search`, and the total counts the same filtered set. `branch` matches only the caller's own builds unless the caller is an administrator with an unrestricted credential (a repository-scoped token only matches its own builds), since `vcs_branch` is owner or admin only on read (#6240)
