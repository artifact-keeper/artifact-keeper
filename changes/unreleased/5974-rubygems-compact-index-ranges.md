---
section: Changed
issues: [#5974]
---
- **Remote RubyGems Compact Index responses now honor Bundler's conditional and byte-range requests** (#5974). Bundler previously downloaded the full `/versions` document on every run even when its cached copy was unchanged or only needed an append. The proxy now exposes the upstream ETag, answers matching `If-None-Match` with `304 Not Modified`, serves single `Range` requests as `206 Partial Content`, and returns `416` for unsatisfiable ranges while leaving Hosted and Virtual behavior unchanged.
