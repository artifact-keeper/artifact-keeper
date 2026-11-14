---
section: Fixed
issues: [#5117]
---
- **Hosted protobuf repositories answer the `buf` CLI** (#5117). They now serve the binary Connect codec (`application/proto`) with BSR-conformant ids and b5 digests, including the `buf.registry.module.v1` upload and download services and the `buf.registry.owner.v1` owner lookup the CLI uses, so `buf push --create`, `buf dep update` and `buf build` work against a hosted repository, dependency chains included, instead of failing with `415 Unsupported Media Type`. JSON callers are answered exactly as before. Pointing `buf` at a hosted repository still needs a reverse proxy that maps a host root onto `/proto/{repo_key}/`, because a `buf.yaml` module name has no room for that prefix. Contributed by @loyalpartner.
