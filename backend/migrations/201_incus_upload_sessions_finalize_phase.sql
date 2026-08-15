-- Distinguish a post-#3072 finalize from a pre-#3072 one left in flight.
--
-- Issue #3083: #3072 closed the reclaim double-append for every NEW upload
-- session by sealing the staged chunks (rename) before appending the
-- completing request's body. One window remained by construction: a session
-- that was already in `finalizing` under pre-#3072 code when the upgrade
-- happened. Old code appended the final body straight onto the staging file
-- and could have advanced `bytes_received` past it, so on disk that state is
-- indistinguishable from a legitimately committed session -- and reclaiming it
-- with the new algorithm can append the final body a second time.
--
-- `finalize_phase` is that missing bit. Post-#3072 code stamps it whenever it
-- claims the finalize lease, so:
--
--   status = 'finalizing' AND finalize_phase IS NOT NULL
--       -> claimed by code that seals; the reclaim is safe and idempotent.
--   status = 'finalizing' AND finalize_phase IS NULL
--       -> left mid-finalize by pre-#3072 code across the upgrade; the on-disk
--          state is ambiguous, so the reclaim is refused (409) and the client
--          is told to cancel and re-upload rather than risk a corrupt image.
--
-- NULL default is deliberate: it is exactly the "written by old code" marker,
-- and existing `receiving` rows pick the column up on their next claim.
ALTER TABLE incus_upload_sessions
    ADD COLUMN IF NOT EXISTS finalize_phase TEXT;

COMMENT ON COLUMN incus_upload_sessions.finalize_phase IS
    'Set by post-#3072 finalize code when it claims the lease. NULL on a '
    'finalizing row means the session was left mid-finalize by pre-#3072 '
    'code and must not be reclaimed (#3083).';
