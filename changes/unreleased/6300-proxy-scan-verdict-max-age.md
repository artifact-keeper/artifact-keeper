---
section: Added
issues: [#6300]
---
- **Operators can reuse a proxy-scan verdict for a fixed number of hours across vulnerability DB updates** (#6300). Grype's scanner version carries the DB build date, so every DB update made every stored verdict stale at once and the next pulls of every cached package were scanned again together. `PROXY_SCAN_VERDICT_MAX_AGE_HOURS=24` reuses a verdict for 24 hours whatever DB build graded it, each verdict expiring on its own schedule. A scanner binary upgrade still forces a rescan, `0` rescans on every pull, and leaving it unset keeps the current behaviour.
