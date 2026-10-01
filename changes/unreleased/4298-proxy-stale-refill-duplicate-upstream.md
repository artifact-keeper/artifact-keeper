---
section: Fixed
issues: [#4298]
---
- **A request that arrives while an expired proxy-cache entry is being refilled no longer sends a duplicate upstream request** (#4298). The in-process metadata cache could still hold the expired sidecar for a moment after the refill had written the fresh one to storage, so a second request in that window treated the entry as stale and fetched it from upstream again (a duplicate GET, or a duplicate conditional HEAD when a validator exists). An expired sidecar now waits for an in-flight publish of the same key, as a missing sidecar already did, and then reloads the fresh metadata. Fresh cache hits are unaffected.
