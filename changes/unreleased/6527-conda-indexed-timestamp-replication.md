---
section: Fixed
issues: [#6527]
---
- **Push peers keep the source's conda `indexed_timestamp` instead of stamping their receipt time** (#6527). A replicated conda package reported a different CEP 47 `indexed_timestamp` on each replica, so behind a load balancer a client's `exclude-newer` decision could change from one request to the next. A replication now carries the source's indexing time (the chunked upload session's optional `indexed_at` field, and the optional `X-Artifact-Indexed-At` header on a single-request PUT), and a receiving peer that trusts the replication keeps it. Both are optional: a peer on an older release ignores them and keeps its own time, as before, so mixed-version clusters keep replicating.
