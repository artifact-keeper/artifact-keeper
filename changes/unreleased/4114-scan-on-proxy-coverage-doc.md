---
section: Added
issues: [#4114, #4097]
---
- **New `docs/security/scan-on-proxy.md` documents scan-on-proxy and which formats enforce it** (#4114, part of #4097). It covers what the gate does, the settings, the verdict cache and its freshness rules (30 days, invalidated by a scanner or vulnerability-database version change), `fail_open` / `fail_closed` / `record_only`, the stricter-of-two rule for Virtual repositories, a per-format coverage table (`enforced` / `accepted` / `unsupported`), and the known gaps, including the generic `/api/v1/repositories/{key}/download/*path` route (#4442). A unit test fails when the table disagrees with the `scan_on_proxy` capability that `GET /api/v1/formats` reports, so the two cannot drift apart.
