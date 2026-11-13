---
section: Security
issues: [#5935]
---
- **quinn-udp moved to 0.5.16 for RUSTSEC-2026-0538** (#5935). The crate reaches the lockfile only through `reqwest`'s optional HTTP/3 support, which the backend does not build, so this clears the audit finding rather than a runtime exposure.
