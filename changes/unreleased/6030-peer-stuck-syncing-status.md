---
section: Fixed
issues: [#6030]
---
- **Peers stuck in `syncing` now transition to degraded or unhealthy after failed probes or transfers** (#6030). Stale-peer detection and liveness probes update peer status from any active state, including `syncing`, and successful probes recover peers back to `online`.
