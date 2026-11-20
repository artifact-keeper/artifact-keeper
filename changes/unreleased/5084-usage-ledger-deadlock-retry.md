---
section: Fixed
issues: [#5084]
---
- **A restore of a depth-bearing backup no longer fails when it deadlocks on the usage ledger; it is retried** (#5084). Such a restore writes every archived repository's rows in one transaction, and the usage-ledger triggers lock each repository's `repository_usage_ledger` row on its first write and hold it until commit, so it could deadlock with another write that takes two of the same rows in the other order and fail with `deadlock detected`. The transaction is now retried as a whole up to three times with a jittered backoff, and each retry is logged. No schema or trigger change; applying ledger deltas in repository-id order at commit is planned for 1.13.
