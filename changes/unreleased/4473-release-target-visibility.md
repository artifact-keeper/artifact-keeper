---
section: Security
issues: [#4473]
---
- **The release-target read endpoint now enforces repository read access** (#4473). `GET /api/v1/promotion/repositories/{key}/release-target` only required a logged-in caller, so any authenticated user could read which release repository a staging repository is linked to (key and id), and its 400 "only available for staging repositories" revealed the type of a repository the caller could not read. It now takes the same existence-hiding read gate as promotion history (#4418): a caller who cannot read the repository, or whose token is scoped away from it, gets 404 before the type check. When the caller can read the staging repository but not the linked release repository, the response still reports `linked: true` but returns its key and id as null.
