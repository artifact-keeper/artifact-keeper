---
section: Fixed
issues: [#6388, #6249]
---
- **Polling a Remote MCP sync no longer shows `running: false` beside the previous pass's result** (#6388, #6249). `GET /api/v1/repositories/{key}/mcp/sync` read the stored state before it checked the sync lock. A pass that recorded its outcome and released the lock between those two reads was reported as finished, with the older state. The endpoint now checks the lock first, so a `running: false` answer always carries the outcome of the pass that just ended.
