---
section: Added
issues: [#3069]
---
- **Admins can read the npm upstream change-feed status over the API** (#3069). `GET /api/v1/admin/npm/upstream-feed/status` reports whether the feed is enabled, the feed URL (credentials removed), the persisted cursor and when it last moved, whether the answering replica runs the consumer and holds leadership, whether any replica holds the feed lock cluster-wide, the leadership term, and the most recent feed error. The response names the replica that answered (`replica_id`, `<POD_NAME or HOSTNAME>:<pid>:<boot-uuid>`), because the consumer, leadership and last-error fields describe that replica only and a load balancer may route successive calls to different replicas. Configuration stays environment-only (`NPM_UPSTREAM_FEED_ENABLED`, `NPM_UPSTREAM_FEED_URL`).
