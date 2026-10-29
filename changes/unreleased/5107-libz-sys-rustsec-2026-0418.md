---
section: Security
issues: [#5107]
---
- **libz-sys moved to 1.1.31 for RUSTSEC-2026-0418** (#5107). The advisory concerns the crate's build script output when it is built with `cc` 1.6.0 or later; the backend builds with `cc` 1.2.55, so this clears the audit finding rather than a runtime exposure.
