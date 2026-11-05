---
section: Fixed
---
- Omit the redundant filename field from CEP-16 shard records so Conda 26.7 can search hosted and synthesized channels. Preserve filename keys and ordinary repodata fields, and schedule existing stored shards for rebuilding after upgrade.

Existing stored shards are rebuilt in bounded background batches after upgrade. Stop all older backend instances before starting this version so older writers cannot restore incompatible shard records.
