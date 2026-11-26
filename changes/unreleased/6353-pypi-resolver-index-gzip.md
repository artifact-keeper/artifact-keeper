---
section: Fixed
issues: [#6353, #5983]
---
- **A cold PyPI `.whl.metadata` or file request downloaded the whole upstream simple index uncompressed** (#6353, #5983). Resolving a Remote file or sidecar reads the project's simple index, and since #2915 that read went out as `Accept-Encoding: identity`, about 5x the bytes on the wire for a large project (2.86 MB against 566 KB in the issue). That one read now asks for `gzip` and decodes it under the same 128 MiB `LARGE_METADATA_MAX_BYTES` cap the identity read had. A body that would inflate past the cap, a corrupt one or an unsupported coding is refused with a 502. The index is only parsed, never served or cached, so downloads and every client-facing response, the client-facing simple index included, keep the `identity` behaviour from #2915. Concurrent cold misses already share one read since #6047
