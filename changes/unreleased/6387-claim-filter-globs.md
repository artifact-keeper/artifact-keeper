---
section: Added
issues: [#6387]
---
- **CI OIDC identity mappings can now filter string claims with `*` and `?` globs** (#6387). Exact matching stays unchanged for patterns without either wildcard, and malformed globs are refused with `400` when a mapping is created or updated.
