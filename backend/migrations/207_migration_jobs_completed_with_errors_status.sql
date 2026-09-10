-- Allow `completed_with_errors` on migration_jobs.status (#3497).
--
-- `determine_final_status` (migration_worker.rs) has returned
-- `MigrationJobStatus::CompletedWithErrors` for the mixed outcome
-- (`total_failed > 0 && total_completed > 0`) since #2457, and
-- `MigrationJobStatus`'s `Display` renders it as `completed_with_errors`.
-- The CHECK constraint migration 020 created never listed that value and has
-- never been altered, so `finalize_job_status`'s UPDATE raised
--
--   new row for relation "migration_jobs" violates check constraint
--   "migration_jobs_status_check"
--
-- for EVERY partially-successful migration. The error propagated out of
-- `process_job` and the spawn wrapper in api/handlers/migration.rs then stamped
-- the job `failed` with the raw Postgres message in `error_summary` — reporting
-- a total failure for a run whose transferred artifacts are present and
-- correct, and burning the one field that exists to say which items failed.
--
-- The rest of the system already believes in the value: `is_terminal_status`
-- (models/migration.rs) lists it, so the SSE progress stream advertises it as a
-- terminal state a client may wait for, and the report endpoint synthesises a
-- report for it. The schema was the only place it was missing, which is why the
-- code's own pure-function tests on `determine_final_status` could pass while
-- the write was impossible.
--
-- Only the constraint changes. No column, no data, no index. Postgres validates
-- the new CHECK against existing rows on ADD; every value already stored is
-- from the old (strictly smaller) set, so validation cannot fail and the scan
-- is over a table with one row per migration job.
--
-- Historical rows are deliberately NOT rewritten. A job stamped `failed` whose
-- `error_summary` contains `migration_jobs_status_check` was in fact a partial
-- success, but re-labelling terminal history is the operator's call, not a
-- migration's. See the CHANGELOG entry for #3497 for the query that identifies
-- them.
--
-- Idempotent: the constraint is dropped IF EXISTS before being recreated, so
-- re-running against a database that already has the new definition is a no-op.

ALTER TABLE migration_jobs
    DROP CONSTRAINT IF EXISTS migration_jobs_status_check;

ALTER TABLE migration_jobs
    ADD CONSTRAINT migration_jobs_status_check
    CHECK (status IN (
        'pending',
        'assessing',
        'ready',
        'running',
        'paused',
        'completed',
        'completed_with_errors',
        'failed',
        'cancelled'
    ));
