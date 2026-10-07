# Writing a migration that does not stop uploads

**The short version:** at a million artifacts, a `CREATE INDEX` on `artifacts`
is an outage. Put the index in a migration of its own whose **first line** is
`-- no-transaction` and whose **only statement** is `CREATE INDEX CONCURRENTLY`.

A CI gate enforces this (`backend/src/migration_safety.rs`, PF-008 / #2524). If
you are here because it failed your build, skip to
[The five rewrites](#the-five-rewrites).

---

## Why this page exists

Artifact Keeper's release gate for the million-artifact operating model
(epic #2516) says upload and download SLOs must stay within 2x baseline while a
large index or backfill is deployed. Migration history did not meet that bar: 47
statements across 34 of the 199 migration files take a lock that blocks writes to
a table holding one row per artifact, download or scan — 27 non-concurrent index
builds, 8 constraints validated as they are added, 8 whole-table backfills and 4
column rewrites. The full inventory, with the reason each is grandfathered, is
the `ALLOWLIST` in `backend/src/migration_safety.rs`.

They were not careless. `sqlx::migrate!` runs every migration file inside a
transaction, and PostgreSQL rejects `CREATE INDEX CONCURRENTLY` inside a
transaction block — so until now there was no way to build an index online from
a migration at all. Several files say so in their comments and hand the operator
an out-of-band recipe instead
(`106_artifacts_lower_name_index.sql`, `108_artifacts_filename_index.sql`,
`110_artifacts_repo_path_pattern_ops.sql`).

The escape hatch exists: sqlx skips the transaction wrapper when a migration
file's first bytes are exactly `-- no-transaction`
(`sqlx-core/src/migrate/source.rs`). Nothing in the tree used it. New migrations
should.

### It buys you exactly one statement

sqlx applies a migration with `conn.execute(&sql)` and no bind parameters
(`sqlx-postgres/src/migrate.rs`), which is the PostgreSQL *simple* query
protocol — and a multi-statement simple query runs inside an **implicit
transaction block**. So a `-- no-transaction` file with two statements is back
inside a transaction, and the header bought nothing. Measured against
`postgres:16-alpine`:

```console
$ psql -c "CREATE INDEX CONCURRENTLY idx_t_v ON t (v);"
CREATE INDEX

$ psql -c "DROP INDEX IF EXISTS idx_t_v2; CREATE INDEX CONCURRENTLY idx_t_v2 ON t (v);"
DROP INDEX
ERROR:  CREATE INDEX CONCURRENTLY cannot run inside a transaction block

$ psql -c "DO \$\$ BEGIN COMMIT; END \$\$;"
DO

$ psql -c "SELECT 1; DO \$\$ BEGIN COMMIT; END \$\$;"
 ?column?
----------
        1
ERROR:  invalid transaction termination
```

**One statement per `-- no-transaction` migration.** A CI gate enforces it
(`no_transaction_migrations_hold_one_statement`).

## The locks, precisely

| Statement | Lock | Who is blocked |
|---|---|---|
| `CREATE [UNIQUE] INDEX` | `SHARE` | writers, for the whole build; readers are fine |
| `CREATE INDEX CONCURRENTLY` | `SHARE UPDATE EXCLUSIVE` | nobody (two passes, no write block) |
| `ALTER TABLE … ADD CONSTRAINT` (validating) | `ACCESS EXCLUSIVE` | everyone, while every row is checked |
| `ALTER TABLE … ADD CONSTRAINT … NOT VALID` | `ACCESS EXCLUSIVE` | everyone, but only for a catalogue update |
| `ALTER TABLE … VALIDATE CONSTRAINT` | `SHARE UPDATE EXCLUSIVE` | nobody |
| `ALTER COLUMN … TYPE` | `ACCESS EXCLUSIVE` | everyone, for a full rewrite |
| `ALTER COLUMN … SET NOT NULL` | `ACCESS EXCLUSIVE` | everyone, for a full scan |
| `ADD COLUMN … DEFAULT <constant>` | `ACCESS EXCLUSIVE` | everyone, briefly — catalogue-only since PG 11 |
| `ADD COLUMN … DEFAULT <volatile>` | `ACCESS EXCLUSIVE` | everyone, for a full rewrite |
| whole-table `UPDATE` / `DELETE` | row locks | nobody directly — but it doubles the heap and lands one WAL burst |

Note row 1. A non-concurrent index build takes `SHARE`, not `ACCESS EXCLUSIVE`
as three migrations in history claim. The distinction does not change the
conclusion — uploads stall for the duration either way — and those files must
not be edited.

`ACCESS EXCLUSIVE` also queues: a statement waiting for it blocks every
subsequent reader behind it, so a five-minute rewrite on `artifacts` stops reads
too. `backend/src/main.rs` sets `lock_timeout = '5min'` and
`statement_timeout = '30min'` for the migration session, which bounds the wait
but not the hold.

## The five rewrites

### 1. Index build

Two files and one registration. `220_artifacts_example_index_reset.sql`, an
ordinary transactional migration:

```sql
-- Clear an index left INVALID by a concurrent build attempted outside the
-- migrator before this release (by hand, from this runbook, and cancelled).
-- This runs once: sqlx records it on the first boot and never runs it again,
-- so it does NOT clean up after a failed attempt of the next migration --
-- the startup repair does (see below).
DROP INDEX IF EXISTS idx_artifacts_example;
```

then `221_artifacts_example_index.sql`:

```sql
-- no-transaction
-- <why this index exists, which query it serves, issue number>
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_example
    ON artifacts (repository_id, created_at)
    WHERE is_deleted = false;
```

and register the build migration, by version and index name, in
`CONCURRENT_INDEX_MIGRATIONS` (`backend/src/migration_repair.rs`):

```rust
(221, "idx_artifacts_example"),
```

The registration is what makes a failed build recoverable. sqlx records a
migration only after its SQL succeeds. If the concurrent build fails part-way
(a lock timeout behind a long transaction, a killed pod, a
`pg_cancel_backend`), it leaves an INVALID index and is not recorded, so it
re-runs on the next boot. On its own, that re-run is worse than the failure:
`CREATE INDEX CONCURRENTLY IF NOT EXISTS` finds the INVALID leftover, skips it,
and the migration is recorded as a success with an index the planner never
uses. A later "drop the old index" migration then removes the only valid one.
The reset migration cannot help, because it was recorded on the first boot and
does not run again.

So the backend repairs it before migrating. On every start that runs
migrations (not with `SKIP_MIGRATIONS=true`), before `MIGRATOR.run` and under
the migrator's advisory lock,
`migration_repair::repair_invalid_concurrent_indexes` walks
`CONCURRENT_INDEX_MIGRATIONS`. For each registered build migration that is not
yet recorded in `_sqlx_migrations`, it drops the named index if
`pg_index.indisvalid` is false, and the build re-runs from scratch. A recorded
migration and a valid index are never touched. Keep the reset migration as
well: it covers an attempt made outside the migrator, which the repair does not
know about.

One index per migration. `CONCURRENTLY` cannot share a file with anything else,
and a file that builds two indexes has two ways to fail half-way.

### 2. Check or foreign-key constraint

Two statements, in **two separate migrations**. `0300_artifacts_size_check.sql`:

```sql
ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_size_nonneg CHECK (size_bytes >= 0) NOT VALID;
```

then `0301_artifacts_size_check_validate.sql`:

```sql
ALTER TABLE artifacts VALIDATE CONSTRAINT artifacts_size_nonneg;
```

`NOT VALID` is a catalogue update — new rows are checked immediately, existing
rows are not. `VALIDATE CONSTRAINT` then scans under
`SHARE UPDATE EXCLUSIVE`, which does not block writes — **but only in a
transaction of its own.** sqlx runs each migration file in one transaction and
PostgreSQL holds locks until commit, so a `VALIDATE` in the same file as the
`ADD CONSTRAINT … NOT VALID` (or an `ADD COLUMN`) still holds that statement's
`ACCESS EXCLUSIVE` for the whole scan, blocking every reader and writer.

If every existing row satisfies the constraint by construction — the column
was added in the same migration with a constant default that passes the
check — skip the `VALIDATE` entirely: the `NOT VALID` constraint already
enforces every new write.

### 3. Unique constraint

Same shape as (1): a transactional
`DROP INDEX IF EXISTS packages_repository_id_name_key;` first, then the build,
registered in `CONCURRENT_INDEX_MIGRATIONS` as
`(<its version>, "packages_repository_id_name_key")`:

```sql
-- no-transaction
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS packages_repository_id_name_key
    ON packages (repository_id, name);
```

then, in a third (ordinary) migration:

```sql
ALTER TABLE packages
    ADD CONSTRAINT packages_repository_id_name_key
    UNIQUE USING INDEX packages_repository_id_name_key;
```

`ADD CONSTRAINT … UNIQUE` on its own builds the index under
`ACCESS EXCLUSIVE`; `USING INDEX` adopts the one you already built online.

### 4. Backfill

Never one `UPDATE` over the whole table. That holds row locks on every row it
touches, doubles the heap through MVCC, and lands the whole thing in one WAL
burst. Batch by primary key with a `LIMIT`:

```sql
-- no-transaction
DO $$
DECLARE
    touched integer;
BEGIN
    LOOP
        WITH batch AS (
            SELECT id FROM artifacts
             WHERE search_vector IS NULL
             ORDER BY id
             LIMIT 5000
        )
        UPDATE artifacts a
           SET search_vector = to_tsvector('english', a.name)
          FROM batch b
         WHERE a.id = b.id;
        GET DIAGNOSTICS touched = ROW_COUNT;
        EXIT WHEN touched = 0;
        COMMIT;                 -- needs -- no-transaction AND a single-statement file
        PERFORM pg_sleep(0.05); -- let foreground traffic through
    END LOOP;
END $$;
```

The `DO` block is the file's only statement — `COMMIT` inside it raises
`invalid transaction termination` otherwise, as measured above.

The predicate must be the thing the backfill fixes (`… IS NULL`), not a row
counter, so an interrupted run resumes where it stopped instead of starting over.

`176_artifacts_search_vector.sql` is the file this example is modelled on, and
the one not to copy: it backfills every live artifact row in one statement and
then builds a GIN index over the result, in a single transaction.

#### Bound every wait (#4153)

A backfill's row locks, and a `CREATE TRIGGER … ON <hot table>` (`SHARE ROW
EXCLUSIVE`, which queues behind any open transaction and blocks every write
behind it while it waits), must not sit on the migration session's 5-minute
`lock_timeout`. From migration 270 on, a gate
(`hot_table_backfills_and_triggers_set_timeouts`) requires any migration that
backfills (`UPDATE`, `DELETE`, `INSERT … SELECT`) or creates a trigger
(`CREATE [OR REPLACE | CONSTRAINT] TRIGGER`) on a hot table to set
`lock_timeout`, and fails any `ALTER TABLE <hot table> DISABLE|ENABLE TRIGGER`.
In a batching `DO` block `SET LOCAL` ends at each `COMMIT`, so set it per
batch, and retry a batch that hits `lock_not_available` rather than failing
the deploy:

```sql
LOOP
    attempt := 0;
    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            -- one batch
            EXIT;
        EXCEPTION WHEN lock_not_available THEN
            attempt := attempt + 1;
            IF attempt >= 5 THEN RAISE; END IF;
            PERFORM pg_sleep(attempt);
        END;
    END LOOP;
    COMMIT;   -- outside the EXCEPTION block: a subtransaction cannot COMMIT
    ...
END LOOP;
```

The gate checks only that the file sets `lock_timeout` somewhere; that the SET
reaches every batch is the author's job.

`statement_timeout` is **not** a per-batch bound here. PostgreSQL arms the
statement timer once per top-level statement, and the whole `DO` block is one
statement: a `SET LOCAL statement_timeout` inside it, before or after a
`COMMIT`, does not apply to the statements that follow in the block. A batched
`DO` migration is bounded only by the migration session's
`statement_timeout = '30min'` (main.rs) over the whole file, so keep batches
small and the total work well inside that.

#### Rewriting `artifacts.origin`

`artifacts.origin` is immutable by trigger (`ak_artifacts_origin_immutable`).
Never `ALTER TABLE artifacts DISABLE TRIGGER` to rewrite it: the ALTER takes a
table lock, and in a `-- no-transaction` file the disabled state commits and is
visible to every session until re-enabled. Instead, open a window in the
migration itself, as 270 and 271 do: `CREATE OR REPLACE` the trigger function
with a clause that admits exactly the one rewrite the migration performs, and
only on a transaction that set `SET LOCAL ak.origin_rewrite = 'on'`; run the
batches with that GUC; and end the file by restoring the strict function from
migration 227. A file interrupted mid-run leaves its narrow clause in place
until it is re-run on the next boot.

### 5. Column type change

There is no online `ALTER COLUMN … TYPE`. Add a new column, backfill it in
batches per (4), switch the application to read it, then drop the old one — four
migrations across two releases. If the change is a pure widening of a
`VARCHAR(n)` length with no `USING` clause, PostgreSQL 16 does it as a catalogue
update and none of this is needed
(`211_packages_version_oci_tag_length.sql`).

## Before you merge

- [ ] The migration touches `artifacts`, `download_statistics`, `audit_log`,
      `packages`, `scan_results` or another table in `HOT_TABLES`
      (`backend/src/migration_safety.rs`) — if not, none of this applies.
- [ ] `cargo nextest run -p artifact-keeper-backend --lib -E 'test(migration_safety)'`
      passes.
- [ ] A `-- no-transaction` file starts with that exact line, byte 0, no BOM and
      no blank line before it. sqlx tests it with `starts_with`.
- [ ] A `-- no-transaction` file contains exactly one statement.
- [ ] A `-- no-transaction` file is re-runnable from any point: it will re-run
      in full if it fails, because nothing was recorded.
- [ ] A `-- no-transaction` `CREATE INDEX CONCURRENTLY` migration is
      registered in `CONCURRENT_INDEX_MIGRATIONS`
      (`backend/src/migration_repair.rs`), so a failed build's INVALID index
      is dropped before it re-runs.
- [ ] The file's header comment says what the statement costs on a table with a
      million rows.

## Before you deploy

- [ ] `SELECT count(*) FROM artifacts WHERE is_deleted = false;` — know the row
      count you are about to scan.
- [ ] `SELECT pg_size_pretty(pg_total_relation_size('artifacts'));` — a
      concurrent build needs room for the new index plus the old table.
- [ ] No long-running transaction is open. `CREATE INDEX CONCURRENTLY` waits for
      every transaction that started before it, including idle-in-transaction
      ones:
      ```sql
      SELECT pid, state, now() - xact_start AS age, query
        FROM pg_stat_activity
       WHERE xact_start IS NOT NULL
       ORDER BY xact_start
       LIMIT 10;
      ```

## While it runs

```sql
SELECT phase, blocks_done, blocks_total, tuples_done, tuples_total
  FROM pg_stat_progress_create_index;

SELECT relid::regclass, phase, heap_blks_scanned, heap_blks_total
  FROM pg_stat_progress_vacuum;
```

and, if uploads have stopped, find who holds the lock:

```sql
SELECT a.pid, a.state, l.mode, l.granted, now() - a.xact_start AS age, a.query
  FROM pg_locks l JOIN pg_stat_activity a USING (pid)
 WHERE l.relation = 'artifacts'::regclass
 ORDER BY a.xact_start;
```

`SELECT pg_cancel_backend(<pid>)` stops a concurrent build safely. It leaves an
invalid index, and the build migration is not recorded. On the next start the
startup repair drops that index (for a migration registered in
`CONCURRENT_INDEX_MIGRATIONS`) and the build runs again from scratch. The
reset migration before it does not help here: it has already been recorded.

## Afterwards

```sql
-- Any index left INVALID by a cancelled or crashed concurrent build.
SELECT c.relname
  FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
 WHERE NOT i.indisvalid;
```

An invalid index is not used by the planner but *is* maintained on every write,
so it costs and gives nothing. If its build migration is not recorded yet, the
next start repairs it (see "Index build"). If the migration is recorded -- an
`IF NOT EXISTS` build that skipped the leftover -- drop the index with
`DROP INDEX CONCURRENTLY` and rebuild it by hand with the migration's
`CREATE INDEX CONCURRENTLY` statement.

Confirm the plan the index was built for actually changed:
`EXPLAIN (ANALYZE, BUFFERS)` the query named in the migration header, and
`ANALYZE <table>` first if the build just finished.

## Rolling back

Dropping an index is cheap and online (`DROP INDEX CONCURRENTLY`). Undoing a
backfill usually is not — which is why the batched form above is written to be
resumable rather than reversible. See `docs/operations/rollback.md` for reverting
to an older release with `SKIP_MIGRATIONS=true`.
