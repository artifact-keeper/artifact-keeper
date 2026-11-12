---
section: Fixed
issues: [#5549]
---
- **MCP publish refuses an npm or PyPI package version the introspection sandbox cannot run** (#5549). Publish only refused `latest`, ranges and wildcards, so `1.2`, `v1.2.3` or a dist-tag such as `next` on an npm package (or a non-PEP 440 version on a PyPI one) was stored, and the introspection worker then reported the version `unsupported` at render time. Publish now applies the sandbox's exact-version rule and answers `400 mcp_invalid_server_json` naming `packages[N].version`: npm needs one SemVer 2.0.0 version without build metadata, PyPI one PEP 440 version, and neither may end in `.tgz`, `.tar` or `.tar.gz`. Both sides share one implementation. Documents ingested from an upstream registry into a Remote keep the generic rule. `docs/mcp-registry.md` documents the rule.
