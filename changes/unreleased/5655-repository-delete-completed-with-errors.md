---
section: Fixed
issues: [#5655]
---
- **A repository delete job whose object deletes failed now reports `completed_with_errors`, not `completed`** ([#5655]). During a storage outage a `DELETE /api/v1/repositories/{key}` job finished with 7 of 8 object deletes failed, and `GET /api/v1/repository-deletions/{id}` answered `completed` with no error. It now answers `status: completed_with_errors`, with `failed_items` and an `error_summary` naming the count and the first failed keys. The repository and its rows are gone as before, and the failed keys stay journaled so storage GC deletes them on a later run. A client polling `status_url` should treat `completed_with_errors` as terminal, like `completed` and `failed`.
