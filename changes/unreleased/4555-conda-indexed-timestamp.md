---
section: Added
issues: [#4555]
---
- **Hosted conda repodata carries a server-set `indexed_timestamp` on every record (CEP-47)** (#4555). A record's `timestamp` is whatever the build machine's clock said, so a client cooldown such as pixi's `exclude-newer` could be defeated by any publisher. Every record served from a hosted channel (and every hosted record in a virtual channel's merge) now has `indexed_timestamp`: the moment the package entered that channel, in Unix milliseconds, taken from the artifact row's `created_at`, which is written once at upload and never rewritten, so every rebuild of `repodata.json`, its `.bz2`/`.zst` encodings, `current_repodata.json` and the CEP-16 shards reports the same value. A package promoted into a channel is indexed at its promotion time there.
