---
section: Fixed
issues: [#5432]
---
- **Conda 26.7 can search CEP-16 sharded channels** (#5432). Every CEP-16 shard record carried `fn`, which the enclosing map already names as the record's key, and conda 26.7 passes that key as `fn` itself, so `conda search` and `conda install` against a hosted, virtual or synthesised remote channel failed with "PackageRecord() got multiple values for keyword argument 'fn'". Shard records now omit `fn` and keep every other field, and the monolithic `repodata.json` is unchanged. On upgrade, stored hosted shards are rebuilt by the existing background backfill, whose channels serve the per-request shards until it finishes, and synthesised remote shards are rebuilt on their next request. Contributed by @imanlotfimahyari.
