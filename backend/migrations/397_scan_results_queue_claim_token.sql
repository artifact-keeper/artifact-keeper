-- #6232: the scan-job claim that created a `running` scan_results row.
--
-- A queued scan creates its row under the job's claim. When the worker dies
-- the claim lapses, recovery requeues the job, and the rerun writes a new row,
-- so the old one stayed `running` until the stuck-scan janitor failed it 30
-- minutes later. Recovery now fails the rows stamped with the claim it
-- revokes. Rows created outside a queued job keep NULL and are untouched.
--
-- Additive and nullable, no backfill: a replica on the previous release
-- neither writes nor reads it, and its rows fall back to the janitor.
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS queue_claim_token UUID;

COMMENT ON COLUMN scan_results.queue_claim_token IS
    'Claim token of the scan_queue job that created this row; recovery of a lapsed claim fails its running rows';
