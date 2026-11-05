#!/bin/sh
# A minimal stdio MCP server for the ak-mcp-introspector sandbox checks
# (#5253): the `sandbox-probe` unit test runs it as an external runner, and
# the `mcp-sandbox` workflow bakes it into an image run under gVisor.
# It answers `server/discover` with "method not found" (so the probe falls
# back to `initialize`), `initialize`, and `tools/list` with one tool whose
# description is the kernel the guest sees (gVisor reports its own).
# Arguments (the external runner's guest spec) are ignored.
kernel=$(uname -sr 2>/dev/null | tr -d '"\\')
while IFS= read -r line; do
  id=$(printf '%s' "$line" | grep -o '"id":[0-9][0-9]*' | head -n 1 | cut -d: -f2)
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"ak-sandbox-echo","version":"1.0.0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"kernel: %s","inputSchema":{"type":"object"}}]}}\n' "$id" "$kernel" ;;
    *)
      if [ -n "$id" ]; then
        printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}\n' "$id"
      fi ;;
  esac
done
