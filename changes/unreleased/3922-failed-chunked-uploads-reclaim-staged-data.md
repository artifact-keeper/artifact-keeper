---
section: Fixed
issues: [#3922]
---
- **Failed, cancelled and abandoned chunked uploads no longer leave staged data behind** (#3922). A completion that failed (for example an Azure `InvalidBlockList` error, a checksum mismatch or a quota rejection) left the assembled multi-GiB session file on the pod's disk with nothing to reclaim it, which filled emptyDir volumes and got pods evicted. The completion's scratch copy is now removed on every path, a terminally failed or cancelled session's staged chunks are deleted immediately, and the hourly upload reaper deletes the staged chunks of any failed, cancelled, completed or expired session that still has them (recorded in the new `upload_sessions.staging_purged_at` column), on whichever replica runs it.
