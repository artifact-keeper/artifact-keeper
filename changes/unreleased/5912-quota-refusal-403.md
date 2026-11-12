---
section: Changed
issues: [#5912]
---
- **A repository or project storage quota refusal is now `403 QUOTA_EXCEEDED`, not `507`, and is checked before the body is read** (#5912). Docker, npm and pip retry a 5xx, and monitoring read the refusal as a server fault, although the client had only reached its quota. The `QUOTA_EXCEEDED` code is unchanged. The body adds `scope` (`repository` or `project`), `repository`, `project`, `limit_bytes` and `used_bytes`. An upload whose declared `Content-Length` does not fit is now refused before its body is streamed. The chunked upload API's session-create check answers the same `403` (it was `413`). A storage backend that is genuinely full still answers `507 STORAGE_FULL`, because that is a server-side condition. Peer replication treats the new `403` as an item rejection, as it treated `413` and `507`.
