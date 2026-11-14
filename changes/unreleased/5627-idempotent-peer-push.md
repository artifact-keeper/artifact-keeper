---
section: Fixed
issues: [#5627]
---
- **A push to a peer that already holds the same bytes completes instead of failing** ([#5627]). When a restore cancels a queued peer delete that the peer never applied, the push queued again by the restore sends the bytes the peer still holds, and the peer refuses the overwrite with `409 Artifact version already exists and is immutable`. That left a permanently failed sync task and an error line on the hub for every such restore, although the peer's content was correct. On that `409`, the hub now reads the peer's artifact metadata and compares its `checksum_sha256` with the pushed one. If they match, the push counts as applied: the task completes with no retry and no failure is charged to the peer. A different digest, or a peer that cannot confirm it, still fails the task as before.
