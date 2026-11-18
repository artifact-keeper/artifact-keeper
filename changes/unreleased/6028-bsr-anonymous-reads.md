---
section: Fixed
issues: [#6028]
---
- **`buf dep update` and `buf build` work without a token against a public hosted protobuf repository** (#6028). Connect sends every RPC as a `POST`, and the repository visibility middleware refuses an anonymous `POST` as a write, so every BSR read (`GetModules`, `GetCommits`, `GetGraph`, `Download`, ...) answered 401 even on a public repository, and a member with read access only got 403 because the read was permission-checked as a write. The read-only BSR RPCs are now classified as reads, by the same list the protobuf handlers use. `CreateModules`, `Upload` and `CreateOrUpdateLabels` still require authentication and `write:artifacts`, and a private repository still answers 401.
