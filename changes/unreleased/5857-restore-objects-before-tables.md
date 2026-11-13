---
section: Fixed
issues: [#5857]
---
- **A restore that stops in its object pass no longer leaves the server half-restored** (#5857). The tables were committed before the second pass wrote the objects, so when that pass stopped (the archive changed after it was verified, or the store went away) every row was in the database while only some of its objects existed. A restore now writes the objects first and restores the tables after them. If the object pass stops, no row has been written, and the error says how many objects were written and that re-running the restore is safe. The backup and restore guide also documents an `AbortIncompleteMultipartUpload` lifecycle rule for the backup bucket, which cleans up the multipart upload a backup cannot abort while its store is down.
