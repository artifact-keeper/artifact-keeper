---
section: Deprecated
issues: [#5002]
---
- **The Incus native chunked upload endpoints are deprecated in favour of `/api/v1/uploads`** (#5002). Every response from `POST /incus/{repo_key}/images/{product}/{version}/{filename}/uploads` and the `PATCH`, `PUT`, `GET` and `DELETE /incus/{repo_key}/uploads/{uuid}` routes now carries `Deprecation: @1793404800` and `Link: </api/v1/uploads>; rel="successor-version"`, including error responses. The routes remain functional for existing Incus clients; new integrations should use the shared resumable API with an Incus repository. See `docs/chunked-uploads.md`.
