---
section: Security
issues: [#4219]
---
- **A personal API token created with a `repo_selector` is now confined to it** (#4219). `POST /api/v1/auth/tokens` had no `repo_selector` field and ignored unknown fields, so the selector the web UI sends when a user scopes a personal token was dropped and the token was minted unrestricted, with no error. The endpoint now accepts `repo_selector`, stores it where service-account tokens store theirs, and the same authentication path enforces it: the token reaches only the repositories the selector matches that its owner can already reach. A selector that would resolve as unrestricted (empty, unparseable, or with a misspelled criterion) is refused with 400, and so is any other unknown field in the request.

  **Operator note:** personal tokens created before this release with a repository selector were issued **unrestricted**, and nothing about them records the scope that was asked for. Review personal tokens minted through the web UI's Access Tokens page with a repository scope, and rotate them.
