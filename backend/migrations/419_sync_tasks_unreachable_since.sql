-- #6134: bound the retries of a sync task whose peer cannot be reached.
--
-- A transfer that never connected to its peer (refused, connect timeout,
-- name resolution) no longer uses up the task's retry budget, so a write
-- made as its peer drops off the network is delivered after the heal. To
-- keep a peer that stays online but never accepts a connection from here
-- from retrying a task forever, the worker stamps the first such failure in
-- an unbroken run of them; a failure more than SYNC_TASK_UNREACHABLE_MAX_SECS
-- (default 24 h) later fails the task for good. A delivery, an answered
-- failure or a re-queue clears it.
--
-- Additive: one nullable timestamp, no default, no backfill and no index
-- (catalog-only). A replica on the previous release neither reads nor writes
-- it. The short lock timeout keeps the brief ACCESS EXCLUSIVE lock from
-- queueing behind a long `sync_tasks` reader; a busy table fails the
-- migration fast and it is retried on the next start.
SET LOCAL lock_timeout = '5s';

ALTER TABLE sync_tasks
    ADD COLUMN IF NOT EXISTS unreachable_since TIMESTAMPTZ;

COMMENT ON COLUMN sync_tasks.unreachable_since IS
    'First of the current run of transfers that could not reach the peer (#6134); NULL when the last attempt reached it';
