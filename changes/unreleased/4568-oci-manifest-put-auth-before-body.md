---
section: Fixed
issues: [#4568]
---
- **An anonymous `docker`/`crane` manifest push to a public repository gets 401 instead of 500** (#4568). `PUT /v2/<name>/manifests/<ref>` read the whole request body before it checked credentials. crane re-sends a used-up body after the first 401, so that read failed and the refusal became a `500 BLOB_UPLOAD_UNKNOWN` (a 502 behind Caddy). The handler now authenticates and checks write access first and reads the body afterwards, as the blob upload handlers already do. This also stops a client without credentials from making the server buffer a manifest body before refusing it.
