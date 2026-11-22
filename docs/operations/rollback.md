# Rolling back to an earlier Artifact Keeper release

**The short version:** set `SKIP_MIGRATIONS=true` on the older deployment. That
is the supported rollback path, within the limits listed under
[Releases you cannot roll back across](#releases-you-cannot-roll-back-across).

> **Warning: 1.11.x to 1.10.x.** A database that has run the 1.11.0 migrations
> cannot serve a 1.10.x backend for OCI and Docker pushes. Migration 243
> replaced the unique key the 1.10.x upload path names in its `ON CONFLICT`
> clause, so after such a rollback every `docker push` fails with
> `there is no unique or exclusion constraint matching the ON CONFLICT
> specification`. Stay on the 1.11.x line, or roll back by restoring a database
> backup taken before the upgrade to 1.11.0. See the table below (#4915).

It is worth reading the rest of this page *before* you need it, because the
procedure is counter-intuitive in a way that makes it useless to discover under
pressure: **you set a flag that sounds dangerous in order to roll back safely.**
An operator halfway through a bad upgrade, meeting `SKIP_MIGRATIONS=true` for
the first time, will reasonably assume it risks their data and go looking for
another way. There isn't one, and the alternatives people reach for instead
(editing `_sqlx_migrations`, restoring from backup) are worse.

---

## What actually happens when you roll back

You start the older image against the newer database, and it exits before it
binds a port. In the logs:

```
Error: VersionMissing(203)
```

or the equivalent `MigrateError::VersionMissing` for whichever version it is.

**This is not a data compatibility problem.** Nothing has been read, nothing has
been found wrong with your rows, and no query has failed. What failed is a
*ledger check*, and it ran before the application looked at any data at all.

Artifact Keeper embeds its migrations with `sqlx::migrate!("./migrations")`
(`backend/src/main.rs`). The `Migrator` that builds carries
`ignore_missing = false`. At startup it compares two lists:

* the migrations recorded as applied in the `_sqlx_migrations` table, and
* the migrations compiled into the binary that is starting.

If the database reports an applied version the binary does not contain, sqlx
treats that as an inconsistent ledger and returns `VersionMissing`. A newer
database always has such versions — that is the whole of what "newer" means
here. So the older binary refuses to start.

It is checking its own bookkeeping, not your data. Stating it that way matters:
operators who read the failure as data incompatibility hesitate to proceed, and
the hesitation is the expensive part.

## The supported path

Set `SKIP_MIGRATIONS=true` in the environment of the older deployment and start
it.

```yaml
# docker-compose.yml, on the rolled-back backend service
services:
  backend:
    image: ghcr.io/artifact-keeper/artifact-keeper-backend:1.7.1
    environment:
      SKIP_MIGRATIONS: "true"
```

You should see, instead of the error:

```
SKIP_MIGRATIONS=true, skipping automatic database migrations
```

### Why this is safe, and not merely "skipping a safety check"

The flag takes a branch that **never constructs the `Migrator` at all**. There
is no relaxed validation and no partially-applied state: the code path that
would have compared the ledger simply does not run. Nothing is skipped except
the comparison that was wrong to make.

The data survives because Artifact Keeper's migrations are **additive**. New
migrations add tables, add columns that are nullable or carry a default, and add
indexes. They do not drop, rename, or retype anything that an older binary
reads. So the older binary continues to write correct rows: the columns it does
not know about either accept `NULL` or fill in their default, and the columns it
does know about are unchanged. There is no data migration to undo and no
restore-from-backup step.

The legacy migration-repair routines (`repair_legacy_073_checksum` and friends)
run *ahead* of the `SKIP_MIGRATIONS` gate and still run. They no-op on a healthy
database, which is what makes running them unconditionally safe.

### Rolling forward again

Remove the flag and start the newer image. The migrations the newer binary
expects are already applied, so the runner has nothing to do and validates
cleanly. There is no cleanup step.

### Do not delete rows from `_sqlx_migrations`

This is the tempting alternative — the ledger complains about three rows, so
remove the three rows — and it is a trap. sqlx will then believe those
migrations were never applied and will try to **re-run** them against a schema
that already contains their objects. You get a duplicate-object failure at best,
and a partially re-applied migration at worst. Use the flag.

## The boundary condition

**This recipe holds for additive migrations. It is not unconditional.**

If a migration between the two versions **drops or renames a column the older
binary reads**, `SKIP_MIGRATIONS=true` will let the old binary start and it will
then fail at query time, when it selects a column that is no longer there. The
flag silences the startup ledger check; it cannot conjure back a dropped column.
The failure mode is worse than the one you were avoiding, because it surfaces as
scattered runtime errors under load rather than as a clean refusal to boot.

The same holds for a migration that **drops or replaces a unique constraint or
unique index that an older binary's `INSERT ... ON CONFLICT (...)` names**.
Postgres resolves `ON CONFLICT (columns)` against an existing unique index on
exactly those columns; when that index is gone the statement fails with `there
is no unique or exclusion constraint matching the ON CONFLICT specification`,
even though every column it names still exists. Look for `DROP CONSTRAINT`,
`DROP INDEX` and `ADD CONSTRAINT ... UNIQUE` as well as the column changes
below.

There is currently **no marker in the codebase distinguishing an additive
migration from a destructive one**, so this is a judgement call each time rather
than a rule you can check. In practice the project's migration discipline
(documented under "Database" in `ARCHITECTURE.md`) is append-only and additive,
and destructive changes are rare — but "rare" is not "never", and the way to
find out today is to read the migration files between the two versions and look
for `DROP COLUMN`, `DROP TABLE`, `ALTER COLUMN ... TYPE`, and `RENAME`.

```bash
# Everything added between the version you are rolling back TO and the one you are on.
git diff v1.7.1..v1.7.3 -- backend/migrations/ | grep -iE '^\+.*(DROP|RENAME|ALTER COLUMN|UNIQUE)'
```

Empty output means the rollback is within the additive case this page covers.
Output is not automatically a blocker: many migrations drop and recreate an
index or a check constraint in a compatible form. Check each hit against the
table below first, and read the migration's header comment, which says when a
rollback needs more than this page.

> **Maintainer note.** Flagging destructive migrations as such at authoring time
> — a header comment convention, or a filename marker, checked by CI — would let
> this section point at a rule instead of a judgement call, and would let the
> startup path tell an operator which kind of rollback they are attempting.
> Tracked on #3314.

## Releases you cannot roll back across

Migrations known to break an older binary that runs against the migrated
database with `SKIP_MIGRATIONS=true`. A rollback from a release at or above
**Introduced in** to a release below it is not supported for the affected
paths; restore a database backup taken before the upgrade, or stay on the newer
line.

| Migration | Introduced in | Older binaries affected | What breaks | Way back |
|---|---|---|---|---|
| `243_oci_cleanup_keys_per_repository` (#3851) | 1.11.0 | 1.10.x and older | Every OCI and Docker push (upload POST, PATCH and PUT). The migration replaced `UNIQUE (storage_key)` on `oci_upload_cleanup_keys` with `UNIQUE (repository_id, storage_key)`; the 1.10.x upload path registers cleanup keys with `ON CONFLICT (storage_key)` and fails with `there is no unique or exclusion constraint matching the ON CONFLICT specification`. Pulls and the other formats are not affected. | Stay on 1.11.x, or restore a pre-1.11.0 backup. Re-adding the old constraint is not a fix: it fails once two repositories hold rows for one key, and where it succeeds it brings back the cross-repository push failure #3851 fixed (#4915). |

### Rolling back across `414_row_count_deltas` (1.13.0)

This rollback is not broken, but it needs upkeep. The migration's triggers keep appending one row to `row_count_deltas` per write statement on `artifacts`, `proxy_cache_artifacts`, `download_statistics` and `proxy_download_statistics`. Only a 1.13.0+ binary compacts that table, so on an older release it grows without limit. Fold it periodically, for example daily:

```sql
WITH gone AS (DELETE FROM row_count_deltas RETURNING table_name, delta)
INSERT INTO row_count_deltas (table_name, delta)
SELECT table_name, SUM(delta) FROM gone GROUP BY table_name;
```

Every count stays exact. Do not drop the triggers: rolling forward again does not re-run the migration, and without them `/admin/stats` would be correct only right after each daily true-up.

When a later migration is found to break a rollback, add a row here and a line
to that release's upgrade notes in `CHANGELOG.md`.

## How far back this is known to work

**Verified:** rolling a **1.7.3** database back to a **1.7.1** binary. All three
migrations in that range (193, 194, 195) are additive — an index, a nullable
timestamp plus a partial index, and six columns on `curation_packages` that
either default or accept `NULL`.

**Known not to work:** rolling a 1.11.x database back to a 1.10.x binary, for
OCI pushes (migration 243, see the table above).

**Untested:** everything else wider. Rolling back across a minor version, or across
several patch releases, has not been exercised. The mechanism is not
version-specific and there is no reason to expect it to fail, but that is a
prediction, not a result — treat a wider rollback as something to verify against
a copy of your database first, rather than something this page has promised you.

## Related

* `ARCHITECTURE.md`, "Database" — migration discipline and the append-only rule.
* `CHANGELOG.md` — the per-release upgrade notes, which call out any release
  whose rollback needs more than this page.
