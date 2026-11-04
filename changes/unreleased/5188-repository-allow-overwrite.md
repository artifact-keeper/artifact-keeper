---
section: Added
issues: [#5188]
---
- **A repository can be made mutable so a re-upload replaces the existing file instead of answering 409** (#5188). Set `mutable: true` on `POST /api/v1/repositories` or `PATCH /api/v1/repositories/{key}` (it is echoed back on every repository response). Snapshot and development channels can then republish under the same version and filename ("latest build wins"), which clients with no overwrite option, such as `twine`, need. The default is `false`, so every existing repository stays write-once.

  The flag is honoured by the direct, streaming and chunked upload paths and by the PyPI upload route. The replaced object is handed to storage GC, which deletes it once nothing else references it. On a Generic or Mlmodel repository with `versioning_enabled`, versioning still applies and a re-upload appends a revision instead. Clients that pin hashes (`pip --require-hashes`, `poetry.lock`, `uv.lock`) will reject a replaced file, and a remote repository proxying this one keeps serving the copy it already cached, so reserve the flag for channels whose consumers expect content to change.
