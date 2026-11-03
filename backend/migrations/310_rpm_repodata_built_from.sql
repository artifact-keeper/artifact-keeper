-- #5128: remember when the current revision's snapshot was claimed.
--
-- A replica's fold can read a dirty mark, then wait on the root row while
-- another replica's build clears the flag, and finally apply the stale mark
-- to the now-clean row. That asks for a redundant rebuild, so `rebuild?
-- wait=true` returns a new revision although nothing changed.
--
-- `built_from_at` is the claim instant, taken after the exclusive fence and
-- written by the claim itself (not by the later swap, which a racing fold
-- would not see in time). Every mark at or before it belongs to a write that
-- committed before the build's snapshot and is already in the revision. The
-- fold drops such marks instead of dirtying the root again. Marks written
-- after the claim may or may not be in the snapshot, so they still dirty the
-- root: a false positive only costs one build, a false negative would serve
-- stale repodata.
ALTER TABLE rpm_repodata_roots ADD COLUMN built_from_at timestamptz;

COMMENT ON COLUMN rpm_repodata_roots.built_from_at IS
    'Claim instant of the current revision: folded marks at or before it are already in its snapshot (#5128)';
