---
section: Added
issues: [#4405, #3427]
---
- **Bulk artifact existence check and opt-in dedup at chunked-upload init, so air-gap imports transfer only new bytes** (#4405, #3427). `POST /api/v1/repositories/{key}/artifacts-missing` takes up to 1000 `{path, sha256}` items and returns the ones the hosted repository does not already hold with that content, each marked `not_found` or `checksum_mismatch`; more than 1000 items is a 400. It needs read access to the repository, and a caller without it gets the same 404 as for a nonexistent repository. `POST /api/v1/uploads` accepts `skip_if_present: true`: when a live artifact already exists at the path with the declared checksum and size, and its stored object is present, the server answers 200 with `already_present: true` and the existing artifact id instead of opening a session. Clients that do not send the flag see no change.
