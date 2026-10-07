---
section: Fixed
issues: [#4558]
---
- **A second scan policy with the same name on the same repository is refused with 409** (#4558). Creating or renaming a repository-scoped scan policy accepted a name already used on that repository, so a re-run setup script silently stacked identical policies that the UI and promotion refusals (which name the policy) could not tell apart. `POST /api/v1/security/policies` and the policy update now answer `409 Conflict` when another policy on the same repository has the same name, compared case-insensitively. The same name on a different repository, and unscoped policies, are unaffected.
