---
section: Fixed
issues: [#5634]
---
- **`npm whoami` and `npm ping` are answered by Artifact Keeper on Remote and Virtual npm repositories** (#5634). They were forwarded anonymously to the upstream, so `npm whoami` answered the upstream's `401` even with a valid Artifact Keeper token, and every `npm ping` paid an upstream round trip. Every repository type now answers `/-/ping` with `200 {}` and `/-/whoami` with the caller's username (or `401` without credentials), as a Local already did. The documented `501` for a `/-/` endpoint a repository cannot serve (`npm search` on a Local) is no longer logged at ERROR, and the LDAP Basic-auth guide no longer shows `npm login`, which is not supported: put Basic credentials in `.npmrc`.
