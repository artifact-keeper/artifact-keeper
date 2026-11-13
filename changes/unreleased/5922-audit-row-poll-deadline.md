---
section: Fixed
issues: [#5922]
---

- The test helper that waits for a fire-and-forget audit row now polls against the same 10 s deadline as the audit count helper instead of giving up after a fixed 100 tries, so the conda attestation audit test no longer fails on a loaded runner (#5922)
