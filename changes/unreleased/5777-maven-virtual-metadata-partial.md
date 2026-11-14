---
section: Fixed
issues: [#5777]
---
- **A Maven virtual metadata merge no longer serves a partial `maven-metadata.xml` or `.meta/prefixes.txt` as a complete `200`** (#5777). When a member was unavailable, the GA, plugin-prefix and SNAPSHOT metadata merges and the prefix union now answer the retryable `503` with `Retry-After` unless the virtual sets `virtual_metadata_partial`; with the setting, the merge of the answering members is served with `X-AK-Partial-Members`, `Cache-Control: no-store` and `Warning: 199`, and is not cached. A merged `<versions>` list or prefix allowlist without that member made Maven pick the wrong `latest`/`release` and skip everything behind it.
