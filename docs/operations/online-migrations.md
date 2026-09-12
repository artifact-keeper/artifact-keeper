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

Two files. `220_artifacts_example_index_reset.sql`, an ordinary transactional
migration:

```sql
-- Clear any index left INVALID by an earlier interrupted concurrent build.
--
-- The next migration is `-- no-transaction`: if it fails part-way it is NOT
-- rolled back and NOT recorded, so it re-runs on the next boot — and
-- `CREATE INDEX CONCURRENTLY IF NOT EXISTS` will happily skip a leftover
-- INVALID index and leave it invalid forever. Drop first, unconditionally.
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

One index per pair. `CONCURRENTLY` cannot share a file with anything else, and a
file that builds two indexes has two ways to fail half-way.

### 2. Check or foreign-key constraint

Two statements, and they may be in the same transactional migration:

```sql
ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_size_nonneg CHECK (size_bytes >= 0) NOT VALID;

ALTER TABLE artifacts VALIDATE CONSTRAINT artifacts_size_nonneg;
```

`NOT VALID` is a catalogue update — new rows are checked immediately, existing
rows are not. `VALIDATE CONSTRAINT` then scans under
`SHARE UPDATE EXCLUSIVE`, which does not block writes. On a very large table,
put the `VALIDATE` in a later migration so the two scans are separately
restartable.

### 3. Unique constraint

Same two-file shape as (1) — a transactional
`DROP INDEX IF EXISTS packages_repository_id_name_key;` first, then:

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

`SELECT pg_cancel_backend(<pid>)` stops a concurrent build safely; it leaves an
invalid index, which the preceding `DROP INDEX IF EXISTS` migration clears on the
next attempt.

## Afterwards

```sql
-- Any index left INVALID by a cancelled or crashed concurrent build.
SELECT c.relname
  FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
 WHERE NOT i.indisvalid;
```

An invalid index is not used by the planner but *is* maintained on every write,
so it costs and gives nothing. Drop it and re-run the migration.

Confirm the plan the index was built for actually changed:
`EXPLAIN (ANALYZE, BUFFERS)` the query named in the migration header, and
`ANALYZE <table>` first if the build just finished.

## Rolling back

Dropping an index is cheap and online (`DROP INDEX CONCURRENTLY`). Undoing a
backfill usually is not — which is why the batched form above is written to be
resumable rather than reversible. See `docs/operations/rollback.md` for reverting
to an older release with `SKIP_MIGRATIONS=true`.
