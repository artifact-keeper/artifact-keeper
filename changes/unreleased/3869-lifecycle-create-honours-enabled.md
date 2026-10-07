---
section: Fixed
issues: [#3869]
---
- **Creating a lifecycle policy with `"enabled": false` now creates it disabled** (#3869). `POST /api/v1/admin/lifecycle` silently dropped the `enabled` field and the row fell through to the column default, so a retention policy meant to be reviewed first was live (and eligible for the scheduled sweep) until a follow-up `PATCH` disabled it. The create request now accepts an optional `enabled`; omitting it keeps the existing enabled-by-default behaviour, and a disabled policy can still be previewed.
