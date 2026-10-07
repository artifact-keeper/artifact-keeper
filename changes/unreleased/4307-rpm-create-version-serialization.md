---
section: Fixed
issues: [#4307]
---
- **Concurrent RPM curated snapshot creates for one repository no longer fail with a serialization error** (#4307). Two `create_version` calls for the same repository ran as competing SERIALIZABLE transactions with an identical, deterministic retry backoff, so they could abort each other with `40001` on every attempt and surface a 500 once the retries ran out. Creates for one repository are now serialized by a per-repository advisory lock taken at the start of the transaction (which runs at READ COMMITTED so the waiter sees the winner's version number), the `UNIQUE(repository_id, version_number)` constraint remains the backstop, and the retry backoff is jittered.
