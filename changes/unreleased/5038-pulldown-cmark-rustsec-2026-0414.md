---
section: Security
issues: [#5038]
---
- **pulldown-cmark moved to 0.13.5 for RUSTSEC-2026-0414** (#5038). The crate is a build-time dependency of `prost-build`, which formats doc comments of the checked-in `.proto` files; it is not linked into the backend and never parsed untrusted markdown, so this clears the audit finding rather than a runtime exposure.
