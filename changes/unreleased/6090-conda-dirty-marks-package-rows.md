---
section: Changed
issues: [#6090]
---
- **Uploads in formats other than conda no longer run the conda shard triggers** (#6090). The triggers that mark conda shards dirty fired on every insert and update of `artifacts` and every change of `artifact_metadata`, in every format, and looked up the repository to find out it was not conda. They now fire only for package rows (`.conda` and `.tar.bz2`), the only rows a shard, repodata record or `removed` entry can contain. Measured on a mixed-format upload run: the two artifact-level trigger functions go from 4,360 calls to none, and PL/pgSQL time per run drops 15%. A conda subdir's revision no longer moves when only a non-package file in a conda repository changes, because nothing it serves changed.
