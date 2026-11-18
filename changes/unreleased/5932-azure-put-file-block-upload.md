---
section: Fixed
issues: [#5932]
---
- **Azure uploads of large files from disk no longer fail at about 30 seconds or above 5000 MiB** (#5932). The Azure backend's `put_file`, used when a chunked upload is finalized from a local file, by OCI blob spooling and by migration, sent the whole file as one Put Blob request: Azure refuses those above 5000 MiB, and since Azure answers only once the whole body is in, the storage client's 30 s read timeout aborted every upload that took longer, reported as `Azure upload failed: error sending request`. `put_file` now stages the file in 4 MiB blocks like `put_stream`, and storage transport errors include their underlying cause.
