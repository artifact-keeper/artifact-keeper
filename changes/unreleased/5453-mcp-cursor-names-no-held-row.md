---
section: Security
issues: [#5453]
---
- **An MCP listing cursor no longer carries the name or version of a server version the reader is not served** (#5453). When a `/v0.1/servers` request (raw or `version=latest`, hosted, Remote or Virtual) stopped at its row bound after reading only held versions, its sealed `nextCursor` named the last held row it read. The cursor now holds the last row the listing served and, for such a stop, only the internal artifact id (a random UUID) of the last row read, so the walk still moves past the held rows, at keyset cost and unaffected by versions deleted between pages, without any cursor naming a held server or version. Cursors issued before the upgrade are still accepted.
