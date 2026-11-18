---
section: Fixed
issues: [#6030]
---
- **A peer that stops answering is demoted instead of staying `syncing` or `online`** (#6030). After `PEER_DEGRADED_FAILURE_THRESHOLD` (default 3) failed heartbeat probes or transfers in a row an `online` or `syncing` peer goes `degraded`, the stale-heartbeat sweep now also takes `syncing` and `degraded` peers to `offline`, and the next good probe brings it back to `online`. Its sync tasks wait while it is down. With `PEER_HEARTBEAT_ENABLED=false` transfer failures no longer demote, since nothing would probe the peer back
