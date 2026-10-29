---
section: Fixed
issues: [#5082]
---
- **The Debian backfill dry run now checks where each misfiled package would move** (#5082). `POST /api/v1/admin/repositories/{key}/backfill-debian` with `dry_run: true` counted a package whose `pool/<component>/` destination holds a different package or a trashed row as registered and relocated, while the real run refuses it. The dry run now reads the destination (without locking or writing), including one an earlier package of the same call would move into, and reports the same `artifacts_failed` count and reasons as the real run.
