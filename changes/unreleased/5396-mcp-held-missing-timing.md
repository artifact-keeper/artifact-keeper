---
section: Security
issues: [#5396]
---
- **An MCP registry read of a missing server version now does the same gate work as a read of a held one, narrowing the timing difference between them** (#5396). A held version and a missing one already answered the same `404` bytes on `/v0.1/servers/{name}/versions/{version}`, but a miss returned as soon as no row matched while a held version first evaluated its gates, so a caller could tell them apart by response time. A miss now runs the same repository-level gate reads before it answers (the refusal audit was already written off the response path). A residual remains and is documented: a held version also checks its pinned backing packages.
