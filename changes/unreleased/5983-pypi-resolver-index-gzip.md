---
section: Changed
issues: [#5983]
---
- **The PyPI resolver reads the upstream simple index gzip-compressed** (#5983). Resolving a Remote file or `.whl.metadata` sidecar reads the project's whole simple index, and that read always went out as `Accept-Encoding: identity`, about 5x the bytes on the wire for a large project. That one read now asks for `gzip` and decodes it under the same 128 MiB `LARGE_METADATA_MAX_BYTES` cap the identity read had, a body that would inflate past it is refused instead of inflated. The index is only parsed, never served or cached, so downloads and every client-facing response keep the `identity` behaviour from #2915
