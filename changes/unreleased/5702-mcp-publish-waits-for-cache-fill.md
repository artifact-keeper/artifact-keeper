---
section: Fixed
issues: [#5702]
---
- **An MCP publish right after a Remote pull-through of its package answers `200`, not `202 resolving`** (#5702). Publish looked the package up in `proxy_cache_artifacts` only, and a streaming pull-through writes that row in the cache writer's tail, after the client already has the last byte. A publish arriving in that window stored the version as `resolving` and queued a resolver job, so `npm install` through AK followed by `mcp-publisher publish` could print the `202` as an error and the version stayed hidden for up to one resolver tick. On a miss the lookup now waits for this process's in-flight commit of the matching cache entry, bounded by twice the streaming publish tail's own limit (10 seconds) and never longer than one `MCP_RESOLVER_INTERVAL_SECS` tick, and reads the catalog again. A fill on another replica still falls back to the documented `202`.
