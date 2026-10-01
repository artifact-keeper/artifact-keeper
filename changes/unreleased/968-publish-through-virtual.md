---
section: Added
issues: [#968]
---
- **npm publishes and dist-tag writes addressed at a virtual repository are routed to its deployment target** (#968). A publish to a virtual repository was rejected with 400 "Cannot publish to a virtual repository", forcing clients to bypass the single entry point and publish to the hosted repository directly. The write now lands in the first hosted (local/staging) member, in the virtual's flattened resolution order, that accepts direct uploads and that the caller may write — the same caller-relative composition the read side uses, so routing through a virtual can never publish where a direct publish would have been refused. A virtual with no writable hosted member still answers 400.
