---
section: Security
issues: [#5447]
---
- **Rootless Podman sandbox guests can no longer connect to other guests** (#5447). The reference Podman deployment put every npm and PyPI guest on one shared internal network, `ak-mcp-sandbox`, and containers on one bridge reach each other, so an install script or MCP server in one guest could connect to a second, concurrent guest. The OCI runner now creates an internal network of its own for every npm or PyPI guest, attaches the AK forwarder to it under the AK hostname, starts the guest on it and removes it after the run; a crashed run's networks are reaped at startup. If the network cannot be created or the forwarder cannot join it, the guest is not started (`start_failed`). OCI guests keep `--network=none`.

  Upgrading: `AK_MCP_SANDBOX_NETWORK` is retired and a worker that still sets it refuses every sandbox job; unset it, set `AK_MCP_SANDBOX_GATEWAY` if the forwarder's container is not `ak-gateway`, recreate the forwarder from the updated `deploy/mcp-introspector/compose.sandbox-network.yaml` and remove the old `ak-mcp-sandbox` network. `AK_URL` must use a host name for npm and PyPI sandbox jobs. `deploy/mcp-introspector/sandbox-check/guest-isolation-check.sh` checks a host's guest isolation, with a shared-network control that must fail, and the `mcp-sandbox` workflow runs it under gVisor.
