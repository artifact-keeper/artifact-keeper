-- Finalize lease for Incus upload sessions (StateMachineLease).
--
-- The chunked complete endpoint flipped sessions to 'finalizing' with an
-- unconditional UPDATE (no `WHERE status = 'receiving'` predicate) and
-- spawned a background finalizer, so duplicate complete requests — possibly
-- on different replicas — could spawn duplicate finalizers for one session,
-- and the background finalizer's terminal updates carried no ownership
-- proof. The stale-session reaper could also delete a temp file that a live
-- finalizer on the same pod was still streaming.
--
-- The 'receiving' -> 'finalizing' transition now stamps these columns and is
-- predicated on the previous state; finalizer terminal updates and the
-- checksum-mismatch cleanup must present the token, and the stale reaper
-- skips sessions whose finalize lease is still live.
ALTER TABLE incus_upload_sessions
    ADD COLUMN IF NOT EXISTS finalize_token UUID,
    ADD COLUMN IF NOT EXISTS finalize_claimed_until TIMESTAMPTZ;

COMMENT ON COLUMN incus_upload_sessions.finalize_token IS
    'Random finalize-lease token; terminal status transitions must match it';
COMMENT ON COLUMN incus_upload_sessions.finalize_claimed_until IS
    'Finalize-lease deadline; an expired lease is reclaimable by a new complete request';
