---
section: Fixed
issues: [#6317]
---
- **An upload that was stored is no longer answered with an error, and PyPI and Debian packages are never stored without their metadata** (#6317). PyPI and Debian wrote the format metadata that the index is built from as a separate step after the artifact row committed. If that step failed, for example on a pool acquire timeout under load (503 `POOL_EXHAUSTED`), the client got an error for a package that was in fact stored, its retry got 409, and the package had no metadata. The metadata now commits in the same transaction as the artifact row. If the write fails, nothing is stored and the retry succeeds. The generic `PUT /api/v1/repositories/{key}/artifacts/{path}` no longer fails after the commit on reads that only fill the response (download count, revision): it logs a warning and answers 201 with `download_count: 0` (or no revision). Responses are unchanged when nothing fails.
