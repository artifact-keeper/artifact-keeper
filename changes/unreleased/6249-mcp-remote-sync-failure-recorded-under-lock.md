---
section: Fixed
issues: [#6249]
---
- **A failed Remote MCP sync pass is now recorded before its sync lock is released** (#6249). A background pass that failed on a database error released the lock first and recorded the failure afterwards, so a client polling `GET /api/v1/repositories/{key}/mcp/sync` in between saw `running: false` beside the previous pass's result and could report success for a pass that failed; a pass started in that window could also have its state overwritten by the late record. The failure is now written while the lock is still held.
