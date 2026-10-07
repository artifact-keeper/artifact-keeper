---
section: Fixed
issues: [#4555, #4173]
---
- **Hosted conda channels serve CEP-16 shard indexes and shards in the encoding the spec and rattler expect** (#4555, #4173). The shard index carried each shard's SHA-256 as a 64-character hex string, because it was built as a `serde_json::Value` (which has no byte type) and then written as msgpack; the shards carried each record's `sha256` and `md5` as hex strings for the same reason; and both responses declared `Content-Encoding: zstd` although the zstd frame is part of the `.msgpack.zst` document, which invites an HTTP client to strip it before the CEP-16 reader sees the bytes. The index and shards are now written with msgpack `bin` digests and map-keyed structs, served without a `Content-Encoding`, and a test decodes both with `rattler_conda_types`' own `ShardedRepodata` and `Shard`. This is the encoding half of #4173; materialising the shard set at write time is still open.
