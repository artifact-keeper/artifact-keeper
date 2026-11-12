---
section: Fixed
issues: [#5606]
---
- **`docker push` can replace a tag whose image is held by a scan policy or a quarantine** ([#5606]). Before uploading, docker checks the manifest and each layer with `HEAD` and gives up on any answer other than `200` or `404`. The pull gate answered those checks with the hold's `403`/`409`, so the usual fix (push a rebuilt image to the same tag) failed with `Artifact download is blocked by the repository's scan policy`. A caller who may push to the repository (write permission, and a token with `write:artifacts`) now gets the held manifest's and blobs' headers on `HEAD`, with no body. `GET` of the held manifest or blobs is still refused for every caller, including that one. Pull-only callers are still refused `HEAD` as well. After the push, the held image stays refused by digest.
