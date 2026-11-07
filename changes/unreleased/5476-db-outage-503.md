---
section: Fixed
issues: [#5476]
---
- **An anonymous pull answers a retryable 503, not 401, when the repository lookup hits a database outage** (#5476). Format routes and `/repositories/{key}/download/*path` read the repository row and treated any lookup error as "no such repository", so a pool timeout or a database restart gave anonymous Bazel and cargo clients a 401, which they treat as fatal, and whole CI jobs failed on a few seconds of pool exhaustion. An unavailable database (the `is_db_unavailable` cases from #4750) now answers 503 with `Retry-After`. A missing or private repository still gets the same 401 as before, so the answer is no existence oracle (#1808), and a lookup error is still not negative-cached (#3750).
