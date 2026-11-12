---
section: Security
issues: [#5533]
---
- **An MCP introspection result is now checked against the whole serve gate after its locks are taken** ([#5533]). `POST /api/v1/mcp/introspection/jobs/{id}/complete` evaluated the full reader serve gate before its transaction, and inside the transaction re-read only the version's and its pinned packages' quarantine, rejection and deletion. A scan-policy block, a deny-list entry, a curation or age-gate hold or a Virtual shadowing change that committed in between let a verified observation be stored for a version that was already held. The full gate now runs once the version and the claim are locked, so such a hold answers `409 mcp_target_ineligible`, stores nothing and cancels the job; a gate that cannot be evaluated answers `503 mcp_gate_unavailable` and leaves the claim unchanged.
