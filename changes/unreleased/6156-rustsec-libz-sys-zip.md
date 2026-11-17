---
section: Security
issues: [#6156]
---
- **libz-sys moves to 1.1.33 for RUSTSEC-2026-0544** (#6156). The two zip advisories of the same batch (RUSTSEC-2026-0545, 0548) only hit the zip 2.4.2 that utoipa-swagger-ui uses at build time, through code paths it never calls, and are ignored next to the existing zip 2.4.2 entries until the utoipa 6 move (#5176)
