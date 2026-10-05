---
section: Fixed
issues: [#4404, #3916]
---
- **Multipart uploads into S3-, GCS- and Azure-backed repositories no longer spool to local disk** (#4404, #3916). The multipart `POST /api/v1/repositories/{key}/artifacts` and `.../artifacts/{path}` routes still wrote the file field to a scratch file under `STORAGE_PATH` before it reached the repository's object storage; they now stream it into a `generic-upload-staging/<uuid>` object on the repository's backend and promote it, as the raw `PUT` route does since #4321. Filesystem repositories and repositories with a WASM format plugin keep the local spool. In RPM repositories, `.rpm` packages keep it (their header parse reads the file), and so does every file sent to `POST /api/v1/repositories/{key}/artifacts`, whose form can name the path after the file field. A new operations page, `docs/operations/upload-scratch-disk.md`, lists which upload paths still use local scratch and how to size it.
