# Guest image for the sandbox check (#5253): a stdio MCP server in POSIX
# shell (backend/tests/fixtures/mcp_sandbox/echo-mcp-server.sh). The
# `mcp-sandbox` workflow runs it under gVisor through
# `ak-mcp-introspector sandbox-probe`; push it to an AK OCI repository to
# check a deployment the same way.
# Build context: backend/tests/fixtures/mcp_sandbox
FROM docker.io/library/alpine:3.20
COPY --chmod=0555 echo-mcp-server.sh /usr/local/bin/echo-mcp-server
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/echo-mcp-server"]
