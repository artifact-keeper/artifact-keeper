---
section: Security
issues: [#5464]
---
- **A stale MCP capability observation can no longer replace a newer current one** (#5464). The current capability view, the drift baseline, snapshot deduplication, history order and retention ranked snapshots by arrival, so an introspection result or CI/gateway report completed later with an earlier `observedAt` became current over a fresher observation. They now rank by the latest time the content was validly seen (`lastSeenAt`, else `observedAt`), then arrival, with deterministic ties: a stale observation is kept as history, is answered `current: false` on completion and raises no `tool_drift` finding or lint. An introspection result's `observedAt` must lie between the job's claim and its arrival (with five minutes of clock skew either side), else it is refused with `400` and the claim is left as it was.
