---
section: Fixed
issues: [#4557]
---
- **Promoting an artifact now copies its format metadata, so a promoted conda package keeps its dependencies and attestation** (#4557). Promotion (single and bulk) inserted a new `artifacts` row in the target repository but no `artifact_metadata` row, and everything a format serves about a package is read from that document: a conda channel built the promoted package's repodata record with empty `depends` and `constrains`, an empty `md5` and license, and no `attestations_sha256`, so a client could install it without its dependencies and the attestation verified in staging was gone. The metadata document is now copied onto the promoted row.
