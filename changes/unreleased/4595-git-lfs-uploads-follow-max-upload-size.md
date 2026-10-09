---
section: Fixed
issues: [#4595]
---
- **Git LFS object uploads are limited by `MAX_UPLOAD_SIZE` instead of a fixed 2 GB** (#4595). `PUT /lfs/{key}/objects/{oid}` refused every object over 2 GB with `413`, whatever `MAX_UPLOAD_SIZE` was set to, so a repository with a larger LFS object (datasets, model weights, media) could not be pushed. Since #4588 the upload streams to the scratch disk while it is hashed, so the separate cap no longer protects memory. LFS uploads now use the same limit as other uploads (10 GiB by default, `0` for no limit): a declared `Content-Length` over the limit is refused before the body is read, and the received bytes are counted against it while streaming. The sha256 check against the oid is unchanged.
