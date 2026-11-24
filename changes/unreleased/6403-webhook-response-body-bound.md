---
section: Fixed
issues: [#6403]
---
- **Webhook deliveries no longer buffer an unbounded receiver response body** (#6403). The 4 KiB `WEBHOOK_RESPONSE_BODY_MAX_BYTES` cap (configurable) now applies to the worker, manual redelivery, and test paths; truncated excerpts record the omitted length when the receiver announces it, and success still depends only on the status code.
