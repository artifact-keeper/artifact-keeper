---
section: Security
issues: [#5390, #5253]
---
- **MCP sandbox: the introspector's token is no longer readable by a guest that escapes gVisor** (#5390, #5253). In the reference deployment (Option A) the worker, rootless Podman and the gVisor sentry all run as `ak-sbx`, so a sentry escape could read the `mcp:introspect` token from the worker's `/proc/<pid>/environ`. `ak-mcp-introspector run` now takes `--token-file <path | ->` (`AK_MCP_INTROSPECTOR_TOKEN_FILE`) and makes itself non-dumpable at startup (its `/proc` files become root-owned, `ptrace` by its own user is refused). The systemd unit passes the root-only `/etc/ak-mcp-introspector/token` as standard input (`StandardInput=file:`, `--token-file -`), so no file or environment the worker's user can open holds the token, and the Kubernetes Deployment mounts the Secret as a file. `--token` / `AK_MCP_INTROSPECTOR_TOKEN` still work but log a warning. See `docs/security/mcp-sandbox.md`.
