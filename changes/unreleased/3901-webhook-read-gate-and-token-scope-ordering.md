---
section: Security
issues: [#3901]
---
- **Webhook fetch-by-id now requires the same read-carrying grant as the webhook listing, and repository-scoped tokens confine admins consistently** (#3901). `GET /api/v1/webhooks/{id}` and its deliveries endpoint admitted any non-empty fine-grained grant, so a `{write}`-only grantee refused the webhook in the listing was still served its URL, headers and secret metadata by id; the by-id path now asks for `RepoAccess::READ`, which also means a custom role without `read`/`admin` no longer qualifies (built-in roles all carry `read`). Separately, the packages listing and the repository listing evaluated `is_admin` before the token's repository scope, letting an admin with a repository-scoped token enumerate everything; the scope now binds first, matching search and the webhook reads.
