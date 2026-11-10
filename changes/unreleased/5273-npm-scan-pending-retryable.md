---
section: Fixed
issues: [#5273]
---
- **npm now retries tarballs whose scans are still pending under fail-closed** (#5273). npm does not retry the previous `423 scan_pending` response. Remote and Virtual npm tarball routes now return `503` with `Retry-After: 5` when a scan is still queued or running, allowing the same install to retry. An install can still fail if it exhausts its retry budget before a verdict is available. Permanent refusals retain `423`, policy blocks retain `403`, and other package formats are unchanged.
