---
section: Added
issues: [#6096]
---
- **Build records can be deleted** (#6096, artifact-keeper/artifact-keeper-web#618). `DELETE /api/v1/builds/{id}` and `POST /api/v1/builds/delete` (up to 100 ids, a per-id result) delete the record and its artifact list, the artifacts in repositories stay. The creator or an administrator can delete a build (a repository-scoped token, even an administrator's, only its own builds), a token needs `delete:artifacts`, and each deletion writes a `BUILD_DELETED` audit row
