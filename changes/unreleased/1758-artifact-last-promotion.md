---
section: Added
issues: [#1758]
---
- **Artifacts now show whether and where they were last promoted** (#1758). Artifact responses (the repository artifact listing, `GET /api/v1/repositories/{key}/artifacts/{path}` and `GET /api/v1/artifacts/{id}`) carry `last_promotion: {target_repo_key, promoted_at, status}`, taken from the newest `promotion_history` row with status `promoted`. Rejected and pending attempts never count, and the field is `null` for an artifact that was never promoted. The Maven-component and Docker-tag groupings carry the same field, so the signal is there for Maven and Docker staging repositories too. `target_repo_key` is `null` when the caller cannot read the target repository, so a staging listing does not reveal the name of a private release repository.
