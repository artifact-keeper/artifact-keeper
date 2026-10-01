---
section: Fixed
issues: [#3982]
---
- **Maven proxy GETs no longer pay two sequential proxy-cache round-trips per artifact** (#3982). `serve_artifact` awaited the upstream `.sha1` sidecar fetch to completion before even starting the content fetch, doubling the per-request storage latency of resolve-heavy Maven builds on network-attached storage (NFS). The sidecar digest now resolves concurrently with the body stream and is only awaited at cache-commit time: a warm hit never touches the sidecar at all (one round-trip total), and a cold miss overlaps the two fetches while gating the cache commit on both results exactly as before (GHSA-qxv7-p3mq-88fv posture unchanged — a digest mismatch is still served-but-never-cached).
