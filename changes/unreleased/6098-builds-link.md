---
section: Added
issues: [#6098]
---
- **A build artifact can link a stored artifact** (#6098, artifact-keeper/artifact-keeper-web#618). `POST /api/v1/builds/{id}/artifacts` accepts `artifact_id`, or `repository_key` and `path`, next to the free-form fields, and takes the checksum and size from the artifact and its path as `<repository_key>/<path>`. A missing, trashed or unreadable artifact is a 404, and one request links at most 100 artifacts. Reads add `artifact_id`, `repository_key` and `artifact_deleted` for callers who can read that repository. On another user's build a linked entry shows only while the artifact is stored in a repository the caller can read (#6240), and `GET /api/v1/builds/diff` now compares the two builds' artifacts by path instead of answering empty lists
