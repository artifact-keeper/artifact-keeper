---
section: Fixed
issues: [#4504]
---
- **A live run of a lifecycle policy with a stored pattern PostgreSQL cannot compile now returns 400 naming the field instead of 500 `DATABASE_ERROR`** (#4504). A policy stored before create/update validated its patterns with PostgreSQL (or written to the database directly) could carry a `match.version_pattern` or `pattern` such as `foo\z`. The preview already listed it in `errors`, but `POST /api/v1/admin/lifecycle/{id}/execute` and scheduled runs sent it to PostgreSQL and failed with a 500. The live run now runs the same check as the preview first and refuses the policy with `400 VALIDATION_ERROR` ("... is not a valid PostgreSQL regular expression"). Nothing was deleted before and nothing is now; fix the pattern with `PATCH /api/v1/admin/lifecycle/{id}`.
