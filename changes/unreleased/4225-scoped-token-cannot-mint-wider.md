---
section: Security
issues: [#4225]
---
- **A repository-restricted API token can no longer mint a token without that restriction** (#4225). Every token-mint endpoint (`POST /api/v1/auth/tokens`, `/users/{id}/tokens`, `/users/me/tokens`, `/profile/access-tokens` and `/service-accounts/{id}/tokens`) checked the new token's permission scopes against the presenting credential but not its repository scope, so a token restricted by `repo_selector` or `repository_ids` could mint a sibling with no repository restriction in one call. A token minted by a repository-restricted credential (or by a session exchanged from one) now inherits that credential's repositories, stored as a `match_repos` selector so it is never widened by a later repository deletion; the credential may not name its own `repo_selector` or `repository_ids` for the new token (403), and a credential whose restriction currently matches no repository cannot mint at all. Interactive sessions and unrestricted tokens mint exactly as before. Repository-scoped tokens (`/repositories/{key}/tokens`) were already confined to a repository the caller's credential can reach.

  **Operator note:** tokens minted through a repository-restricted token before this release may be unrestricted. Tokens a token minted carry no marker of it; review tokens created by automation that authenticates with a restricted token, and rotate them.
