---
section: Fixed
issues: [#5347]
---
- **The upstream `HEAD` that answers a cold `HEAD` is recorded as an `UPSTREAM_FETCHED` audit event** (#5347). With `AUDIT_UPSTREAM_FETCHES` set to `all` (or `errors`, for a failed probe), every request the proxy sends upstream is recorded, but the `HEAD` probe added for #5322 used the plain sender and was missing, so an egress audit did not see cold `HEAD`s. It now records one event with method `HEAD` and caller `proxy`. A `HEAD` answered from the cache contacts nothing and records nothing, as before.
