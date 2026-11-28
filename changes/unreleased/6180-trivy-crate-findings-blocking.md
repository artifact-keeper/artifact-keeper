---
section: Security
issues: [#6180]
---
- **Trivy now blocks publication on Rust crate findings in the backend image** (#6180). After one report-only publish (Docker Publish run 45849075661, zero crate findings), the blocking scan no longer skips `/usr/local/bin/artifact-keeper`; `.trivyignore` defines the exception policy of reason, owner or issue, and expiry, with no exceptions currently. Rust advisories also block merges through `cargo audit`.
