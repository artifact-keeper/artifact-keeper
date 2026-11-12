---
section: Fixed
issues: [#5593]
---
- **An MCP introspection result can no longer be accepted while a tag move takes the pinned image's rejection off the row the backing gate locked** ([#5593]). The completion's backing gate read the pinned rows, then locked them `FOR SHARE` without checking them again. An OCI tag move that committed between the two steps rewrote the tag-path row to other, clean bytes and moved the hold onto a digest-path row the gate never locked, so the result was stored while the native manifest gate refused the pinned digest. The gate now re-reads its rows under the locks and takes them again when the row set or a checksum changed. A set that is still changing after three attempts is treated as held.
