---
section: Security
issues: [#5393]
---
- **The event stream and the peer and transfer reads are scoped to the caller** (#5393). `GET /api/v1/events/stream` forwarded every domain event to any signed-in user. An administrator still receives every event. Anyone else now receives only the events of repositories it may read, without the actor. Events about users, groups, permissions, service accounts and quality gates are for administrators, except a `user.*` event about the caller itself. The `GET` routes under `/api/v1/peers` (a peer, its sync tasks, subscriptions, labels, connections, chunk availability and transfer sessions) now require an administrator, like their mutations. `GET /api/v1/peers` still answers a non-admin `200`, so a peer's heartbeat keeps working, but lists no peer.
