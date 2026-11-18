---
section: Security
issues: [#5611]
---
- **The repository-token and email-subscription routes no longer tell a private repository from a nonexistent one by the 404 body** (#5611). `GET|DELETE /api/v1/repositories/{key}/tokens[/{id}]` and `GET`/`DELETE /api/v1/repositories/{key}/email-subscriptions[/{id}]` answered a caller who could not see a private repository (no grant, or a token whose repository list leaves it out) with `Repository '<key>' not found`, while an unknown key answered `Repository not found`, so comparing the two bodies revealed which keys exist. Both now answer the shared `Repository not found` response, byte for byte. Other routes that still name the key in their 404 are not changed here.
