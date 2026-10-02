---
section: Added
issues: [#4276]
---
- **Remote Protobuf repositories reverse-proxy allowlisted BSR Connect reads** (#4276). `POST /proto/{repo}/*` forwards `buf.registry.*` Get/List/Download RPCs upstream without copying Artifact Keeper credentials or caching the body.
