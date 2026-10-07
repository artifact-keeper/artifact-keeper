---
section: Security
issues: [#4418]
---
- **The promotion-history endpoint now enforces repository read access** (#4418). `GET /api/v1/promotion/repositories/{key}/promotion-history` only required a logged-in caller, so any authenticated user could read the promotion and rejection history of any repository, including private ones: artifact paths, the counterpart repository's key, rejection reasons, who promoted, and policy results. It now takes the same existence-hiding read gate as the other repository read endpoints (a caller who cannot read the repository, or whose token is scoped away from it, gets the same 404 as for a repository that does not exist), and the key of a counterpart repository the caller cannot read is returned as an empty string, matching the redaction the per-artifact `last_promotion` field already applies.
