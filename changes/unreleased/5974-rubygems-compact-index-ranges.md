---
section: Changed
issues: [#5974]
---
- **Remote RubyGems Compact Index responses now honor Bundler's conditional and byte-range requests** (#5974). Bundler previously downloaded the full `/versions` document on every run even when its cached copy was unchanged or only needed an append. When the upstream supplies an ETag, the proxy replays it, answers matching `If-None-Match` with `304 Not Modified`, and serves single `Range` requests for identity-encoded documents as `206 Partial Content`, with `416` for unsatisfiable ranges. Hosted and Virtual behavior is unchanged.
