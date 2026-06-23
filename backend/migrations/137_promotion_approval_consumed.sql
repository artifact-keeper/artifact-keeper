-- Single-use enforcement for promotion approvals.
--
-- The /promote routes (promote_artifact, promote_artifacts_bulk) now require an
-- APPROVED promotion_approvals row for the exact (artifact, source, target) pair
-- when the source repository has require_approval = true, and consume that row so
-- it cannot be replayed. This column marks the moment an approved request was
-- spent by a promotion (via either the /promote routes or the approve path).
--
-- NULL = approved but not yet promoted (still usable once); non-NULL = already
-- promoted. Existing rows default to NULL so an already-approved request remains
-- usable exactly once, matching intent. We add a nullable column rather than a new
-- status value so the migration-054 status CHECK (pending/approved/rejected) and
-- the approval.rs status filters/history endpoint are untouched.
ALTER TABLE promotion_approvals
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;
