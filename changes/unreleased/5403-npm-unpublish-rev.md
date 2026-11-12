---
section: Fixed
issues: [#5403]
---
- **`npm unpublish` can no longer remove versions published while it runs** ([#5403]). `npm unpublish <pkg>@<version>` reads the packument (`GET /{pkg}?write=true`), drops the version and writes the rest back (`PUT /{pkg}/-rev/{rev}`); the registry unpublished every stored version missing from that body and accepted any revision, so a version published between the read and the write was unpublished as well, and both requests answered `200`. A hosted package's full packument now carries a `_rev` derived from its live versions, and a packument rewrite or whole-package unpublish (`DELETE /{pkg}/-rev/{rev}`) with a revision that is no longer current answers `409 Conflict`, so the client reads the packument again and retries. A client that sends no revision (`-rev/undefined`, for example with a packument read before the upgrade) may still remove exactly one version per rewrite; a rewrite that would remove more answers `409`.
