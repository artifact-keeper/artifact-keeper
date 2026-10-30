---
section: Fixed
issues: [#5117]
---
- **Hosted protobuf repositories answer the `buf` CLI** (#5117). They now serve the binary Connect codec with BSR-conformant ids and b5 digests, including the `buf.registry.module.v1` upload and download services the CLI uses, so `buf push` and `buf dep update` work against a hosted repository instead of failing with `415 Unsupported Media Type`. Pointing `buf` at one still requires a reverse proxy mapping a host root onto `/proto/{repo_key}/`, since a `buf.yaml` module name has no room for that prefix. A reference to a module or commit that does not exist now answers the Connect `not_found` the schema calls for, rather than omitting it from the reply.
