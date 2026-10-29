---
section: Fixed
issues: [#4903]
---
- **Accept an API token presented as a Bearer credential at `/v2/token`, so Renovate and other clients that configure a bare token can list Docker tags** (#4903). The exchange previously recognized only JWTs in that slot and answered 401, which surfaced as a failed `tags/list` request.
