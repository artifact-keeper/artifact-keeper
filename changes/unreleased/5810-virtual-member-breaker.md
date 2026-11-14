---
section: Added
issues: [#5810]
---
- **Virtual downloads skip a member that keeps failing** ([#5810]). After `AK_VIRTUAL_MEMBER_BREAKER_FAILURES` (default `3`) failures in a row (a missed download deadline, a connect error or an upstream `5xx`), a Remote member's breaker opens, and for `AK_VIRTUAL_MEMBER_BREAKER_OPEN_SECS` (default `30`) downloads through its virtual repositories pass over it without dialling it. One download is then let through as a probe, and an answer closes the breaker. A `404`, `401` or `403` never trips it. The state is in memory per replica, `ak_virtual_member_breaker_open{member}` reports it, and `AK_VIRTUAL_MEMBER_BREAKER_OPEN_SECS=0` disables it. See `docs/virtual-downloads.md`.
