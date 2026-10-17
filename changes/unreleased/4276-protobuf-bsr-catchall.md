---
section: Added
issues: [#4284]
---
- **Remote Protobuf repositories reverse-proxy allowlisted BSR Connect reads** (#4284). `POST /proto/{repo}/*` forwards explicit `buf.registry.module.v1` metadata RPCs upstream without copying Artifact Keeper credentials, caching the body, or proxying `Download`.
