---
section: Fixed
issues: [#5432]
---
- **Conda 26.7 can search CEP-16 sharded channels without duplicate filename errors** (#5432). Omit the redundant `fn` field from shard records while preserving filename keys and ordinary repodata metadata. Existing stored and synthesized shards are scheduled for rebuilding after upgrade.

  Existing hosted shards are rebuilt in bounded background batches.
