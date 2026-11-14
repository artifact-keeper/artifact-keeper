---
section: Fixed
issues: [#5858]
---
- **A backup opens each artifact only when the archive writer is ready for it, so a slow store no longer times out queued objects** (#5858). The streaming backup opened up to three artifact downloads ahead of the writer, and `S3_BULK_TIMEOUT_SECS` runs from the start of a download, so an object waiting behind a large or slow one lost part of its time limit before a byte of it was read, and the backup could fail on a store that serves every object within the limit. A connection the store resets is now also reported as "S3 connection reset" instead of "S3 connection timed out": the timeout message came from object_store's `retry_timeout` setting, which is printed on every retried error.
