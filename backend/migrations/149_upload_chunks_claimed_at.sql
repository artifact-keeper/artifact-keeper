-- Add upload_chunks.claimed_at to timestamp the pending -> uploading claim.
--
-- The chunked-upload service (services/upload_service.rs) claims a chunk by
-- transitioning it 'pending' -> 'uploading' before writing data. Under the
-- web UI's concurrent chunk uploader a second PATCH for the SAME chunk used to
-- hit a terminal 400 (issue #2316). The fix serializes duplicate requests on a
-- row-level lock and, as a defensive fallback, allows re-claiming a chunk whose
-- 'uploading' lease has expired (a claim left behind by a crashed request or a
-- pre-fix backend). `claimed_at` records when the lease was taken so that
-- staleness can be evaluated.
--
-- Nullable with no default: existing rows keep NULL, which the service treats
-- as an expired (immediately reclaimable) lease — the correct behaviour for any
-- chunk stuck 'uploading' by the old code path.
ALTER TABLE upload_chunks
    ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
