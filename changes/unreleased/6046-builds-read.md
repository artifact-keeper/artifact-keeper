---
section: Fixed
issues: [#6046]
---
- **The builds API returns the VCS fields, metadata and attached artifacts it stores, and honours `sort_by`** (#6046, artifact-keeper/artifact-keeper-web#618). `GET /api/v1/builds` and `GET /api/v1/builds/{id}` answered without `vcs_url`, `vcs_revision`, `vcs_branch`, `vcs_message`, `metadata` and `modules`, although create and attach stored them. Both now return them, with `modules[].artifacts` grouped by module name. `sort_by` takes `created_at`, `started_at`, `duration`, `duration_ms` or `name`, anything else keeps the build number order
