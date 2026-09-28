---
section: Fixed
issues: [#4120]
---
- **Remote Go repositories cache module versions instead of revalidating them upstream every five minutes** (#4120). Every `goproxy` fetch handed the cache classifier the `Generic` stand-in format, and the classifier had no Go arm, so a module version's `@v/<version>.info`, `.mod` and `.zip` — pinned by the checksum database and never changed upstream — were stamped with the 5-minute mutable TTL and re-fetched from the upstream proxy on the next request after it. The Go handler now carries the real format, and a canonical `vMAJOR.MINOR.PATCH[-pre][+build]` version (pseudo-versions and `+incompatible` included) under `@v/` classifies immutable; `@v/list`, `@latest` and a non-canonical query such as `@v/master.info` stay mutable.
