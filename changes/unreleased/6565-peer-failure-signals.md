---
section: Added
issues: [#6565]
---
- **Peer API responses now include `consecutive_failures`, `backoff_until` and `transfer_failures_total`, and expose `consecutive_failures` as `ak_peer_consecutive_failures{peer_id}`** (#6565). Operators can set their own threshold for "has kept failing" from the same signals the sync worker already stores, without a new peer status or a database migration. The fields are additive: existing clients see the same values for the fields they already use, and the gauge is refreshed from `peer_instances` on the existing metrics tick.
