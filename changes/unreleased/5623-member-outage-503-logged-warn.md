---
section: Fixed
issues: [#5623, #5701]
---
- **An upstream outage behind a virtual repository no longer floods the error log** ([#5623], [#5701]). When every member of a virtual repository was unavailable, each client request was answered with the intended `503` and `Retry-After`, and also logged twice at `ERROR`: `Request error … SERVICE_UNAVAILABLE` and `tower_http`'s `response failed … 503`. That drowned real errors and tripped log-based alerts during an outage. The member outage `503` is now logged once at `WARN`, and `tower_http` no longer logs a deliberate `5xx` the error path logged below `ERROR` (the member outage `503`, a saturated database pool's `503`, a quota `507`, a documented `501`) as a failure. Unexpected server errors still log at `ERROR`.
