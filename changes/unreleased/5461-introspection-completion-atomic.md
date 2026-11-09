---
section: Security
issues: [#5461]
---
- **Concurrent completions of one MCP introspection claim have exactly one winner** (#5461). Claim consumption, the snapshot insert and the job's terminal (or retry) status commit or roll back together in one transaction that locks the claimed job row, so of several identical or divergent results posted at once only one stores a snapshot and every other one answers `409 mcp_claim_invalid` and stores nothing, and a transient retry racing a successful result can no longer leave a stored snapshot behind a job that is still pending. The audit, lint and drift side effects run only for the committed winner. The transactional completion landed with #5389; this release adds the concurrent HTTP regression coverage and extends the same transaction with the lease, revalidation and freshness checks of #5462, #5463 and #5464.
