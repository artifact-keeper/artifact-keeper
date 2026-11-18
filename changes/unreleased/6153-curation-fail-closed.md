---
section: Security
issues: [#6153]
---
- **Curation fails closed when its evaluation or config lookup errors** (#6153). The proxy curation gate used to serve a pull when reading the repository's curation config or rules failed. It now refuses the pull with a retryable `503` and `Retry-After` (`UNAVAILABLE` in the OCI `/v2` envelope) on every format that goes through the gate. A rule verdict is still a `403` with the same body, and hosted repositories or repositories with curation off never read the policy
