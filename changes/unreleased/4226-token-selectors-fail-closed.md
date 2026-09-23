---
section: Security
issues: [#4226]
---
- **A token's repository restriction no longer fails open when its stored selector cannot be read, or when a mint request misspells a field** (#4226). At authentication a stored `repo_selector` that did not parse was read as empty, which means unrestricted, and service-account token creation stored the selector as given. A stored selector that does not parse, or that carries a criterion the server does not know, now grants no repository at all and is logged at `warn` with the token id; `POST /api/v1/service-accounts/{id}/tokens` validates `repo_selector` with the same rules as personal tokens and refuses an empty `repository_ids`, both with 400. The token-mint requests of `/users/{id}/tokens`, `/users/me/tokens`, `/profile/access-tokens`, `/service-accounts/{id}/tokens` and `/repositories/{key}/tokens` now refuse unknown fields with 400 instead of ignoring them, so a misspelled `repo_selector` can no longer mint an unrestricted token; malformed bodies on these endpoints are now 400 rather than 422.

  **Operator note:** a service-account token whose stored selector misspelled a criterion was broader than written (unrestricted, if every criterion was misspelled) and now reaches no repository. Its holder sees 404s for repositories it used to reach; re-mint it with a corrected selector.
