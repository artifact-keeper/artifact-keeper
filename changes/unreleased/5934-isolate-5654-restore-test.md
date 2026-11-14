---
section: Fixed
issues: [#5934]
---

- The #5654 Docker repository, group and webhook backup round-trip test now restores only its own rows, so it no longer comes back `partial` or fails when other tests in its shard delete users or artifacts while its restore runs (#5934)
