---
section: Fixed
issues: [#5856]
---
- **A restore into a fresh server brings back the repositories, artifacts and webhooks of archived users and roles, and reports what it could not insert** (#5856). Every install creates its own `admin` and seeds its own roles with random ids, so on a fresh server the archived `admin` and roles were skipped as duplicates and every row that referred to them failed its foreign key: repositories, artifacts, webhooks, Docker images and scan data all stayed behind, and the restore still answered `status: completed` with no errors. A restore now maps archived users by username and roles and groups by name onto the rows the server already has before inserting anything. A row that still fails counts as an error of the restore, which then reports `partial` and names the row by its key. The WARN log for a failed row names its table and key instead of printing the whole row, which could hold token hashes or encrypted secrets.
