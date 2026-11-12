---
section: Fixed
issues: [#5619]
---
- **The generic download through a Virtual OCI repository now refuses a manifest whose digest is held or rejected under another reference** ([#5619]). `HEAD` and `GET /api/v1/repositories/{virtual}/download/v2/<image>/manifests/<ref>` (and `/general/{virtual}/...`) checked only the member row at that path, so a tag whose digest was rejected through its digest row answered `200` through the Virtual, while the hosted repository and the native `/v2` pull refused it. The member walk now checks every row of the digest, as the other manifest reads have since 1.12.0, and answers the member's refusal (`403` for a rejection or a scan-policy hold, `409` for a quarantine) instead of a `404`.
