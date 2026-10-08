---
section: Security
issues: [#0000]
---
- **Changing a repository's scan configuration now requires the `write:repositories` token scope** (#0000, GHSA-gvhj-8vg9-358g). `PUT /api/v1/repositories/{key}/security` checked the tenant gate and the repository `admin` action but not the presenting token's action scope, so an API token minted with only `read:artifacts` by a user who is a repository admin could turn scanning off, lower the severity threshold or switch the proxy scan action to record-only. The sibling repository-configuration endpoints (cache TTL, npm scope policy, cache invalidation, egress proxy) already required `write:repositories`. This one now does too, and answers 403 to a token without it. Interactive sessions and tokens carrying `write:repositories` are unaffected.
