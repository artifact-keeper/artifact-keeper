---
section: Fixed
issues: [#3831]
---
- **Repository-management endpoints now require scopes an API token can actually carry** (#3831). Fourteen handlers (repository create/update, cache TTL and invalidation, npm scope policy, PyPI tracks, virtual members, upstream auth, egress proxy, routing rules) gated on the bare `write` scope, which is deliberately not mintable — only session auth and `admin`/`*` tokens could ever call them, and a `write:repositories` token held by a global admin got a 403. They now require `write:repositories`; the read-side handlers (`get_npm_scope_policy`, `get_egress_proxy`, `test_upstream`) require `read:repositories`, `DELETE /repositories/{key}` requires `delete:repositories`, and `DELETE /repositories/{key}/artifacts/{path}` plus the chunked-upload cancel endpoint require `delete:artifacts`, so the Web UI's non-admin token types work for CI automation such as evicting stale proxy-cache entries. All existing per-repository permission checks are unchanged.
