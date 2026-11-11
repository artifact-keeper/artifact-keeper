---
section: Added
issues: [#5810]
---
- **Virtual repositories can refuse to fall back past an unavailable member** ([#5810]). Set `virtual_member_fallback` to `strict` on a virtual (`PUT /api/v1/repositories/<key>`, or on create) and an artifact download whose higher-priority Remote member is unavailable (an upstream `5xx`, a transport failure or timeout, a missed download deadline or an open member breaker) answers `503` with `Retry-After` instead of serving a lower member's copy. Use it when members can hold different content at the same coordinates. A `404` is still a miss, and metadata merges are not affected. The default, `available`, keeps serving the next member. GET and the repository listing report the value on virtual repositories. See `docs/virtual-downloads.md`.
