---
section: Changed
issues: [#5768]
---
- **The proxy cache HA guide now says how to mount a shared NFS volume so cross-replica single-flight does not stall** (#5768). With `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED=true` a replica waiting on another replica's fill of a small cold object reads the shared filesystem every 200 ms, and the NFS client's cached "file not found" hides the finished entry for as long as the attribute cache lasts, about 30 s per race with `actimeo=30`. `docs/operations/proxy-cache-ha.md` now recommends `actimeo=0`, a low `actimeo` or `lookupcache=positive` and says what each one costs.
