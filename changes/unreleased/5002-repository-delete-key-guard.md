---
section: Fixed
issues: [#5002]
---
- **A repository renamed to `~deleting~<job id>` is unreachable through every by-key path, not only its original key** (#5002). Repository deletion renames the row in the request transaction and lets a background job remove it, but a direct lookup of the renamed key could still resolve the repository while the job ran or after it failed. The `~deleting~` prefix is now a shared predicate rejected by `RepositoryService::get_by_key`, the proxy and format resolvers, the auth visibility middleware, repository listings and every search path, so no route, virtual member, search result or stale job can expose a repository that is still being deleted. A repeated `DELETE` of the renamed repository still returns the job in flight. See `docs/operations/repository-delete.md`.
