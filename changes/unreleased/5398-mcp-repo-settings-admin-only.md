---
section: Security
issues: [#5398]
---
- **An MCP registry's package mapping, deny list and other MCP settings are shown only to its administrators** (#5398). `GET /api/v1/repositories/{key}` returned `mcp_package_repos` (the backing repository key per `registryType`, which can name a private repository the generic routes hide behind a `404`), `mcp_server_deny`, `mcp_namespace_allow` and the rest of the Phase 2/3 MCP settings to every caller who could read the registry, anonymous callers of a public one included. The repository responses (`POST`, `GET` and `PATCH`) now carry them only when the caller has the repository `admin` action or is an instance administrator (the same check as `mcp_caller_is_repo_admin`), and omit them for everyone else. `mcp_package_policy` is still echoed to every reader.
