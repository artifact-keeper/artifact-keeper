---
section: Security
issues: [#5435]
---
- **A promotion can no longer bring a case-only twin of a server name into an MCP registry, and a replicated twin is reported** (#5435). The case-only-twin rule of #5434 covered publish only, so `io.Acme/tool` could reach a Local registry holding `io.acme/tool` by being published to Staging and promoted. Single and bulk promotion now apply the same check under the same lowercased-name lock and answer `409` with code `mcp_name_case_conflict` (nothing copied); the recorded spelling still promotes. Peer replication keeps storing names exactly as the peer sends them, since refusing would leave the mirror out of step for good, and now audits `MCP_NAME_CASE_TWIN_REPLICATED` naming the other recorded spellings so an admin can act on it.
