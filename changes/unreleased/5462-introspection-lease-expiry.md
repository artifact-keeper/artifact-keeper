---
section: Security
issues: [#5462]
---
- **An MCP introspection claim whose lease has expired can no longer complete before the reaper runs** (#5462). A completion now requires a live lease in the same locked transaction that ends the claim and stores the result, checked against the clock when the job row is locked, so the result of an expired claim, or a retry of it, answers `409 mcp_claim_invalid`, stores no snapshot, changes no current view and leaves the job for the reaper, whatever the reaper's schedule. A completion racing the reaper has exactly one outcome.
