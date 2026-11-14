---
section: Fixed
issues: [#5744]
---
- **Creating a repository answers `201 Created` with a `Location` header instead of `200 OK`** (#5744). `POST /api/v1/repositories` answered `200 OK`, so a client could not tell a create from an idempotent read and a strict generated SDK treated the success as an unexpected status. It now answers `201` and names the new repository's GET endpoint in `Location` (`/api/v1/repositories/{key}`); the response body is unchanged, and the `#[utoipa::path]` contract documents `201`.

  Upgrade: this is a public API change. A client that checks `status == 200` rather than any `2xx` on this route must be updated before the 1.13.0 upgrade; the web UI, CLI, SDKs and the DTF suite consume that contract.
