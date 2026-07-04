-- Two-phase mark-and-sweep marker for blob GC (artifact-keeper #1660).
--
-- Blob GC currently deletes the storage object before committing the
-- `oci_blobs` row delete, so a crash between the two leaves a row pointing at
-- an absent object (a dangling reference that breaks a pull). The fix is a
-- mark-and-sweep GC: mark a candidate row (`pending_delete_at = NOW()`) in one
-- transaction without touching storage, then sweep (storage delete + row
-- delete) in a later pass under the same `FOR UPDATE` lock the push path takes
-- (#1610/#2190). A concurrent re-push that re-adopts a marked blob "resurrects"
-- it by clearing the marker under that lock, so no live blob is ever swept.
--
-- This migration adds only the marker column + a partial index for the sweep
-- selection. The column is nullable and defaults NULL, so every existing blob
-- is treated as "not pending" — no backfill, and no behaviour change until the
-- sweep pass is enabled (that lands separately). PR1 writes/clears the marker
-- (resurrection) but does not yet change the deletion timing.
--
-- The partial index keeps the sweep-selection scan off the (large) set of
-- healthy, unmarked blobs; it only indexes the rare rows actually pending
-- deletion.
ALTER TABLE oci_blobs
    ADD COLUMN IF NOT EXISTS pending_delete_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS oci_blobs_pending_delete_idx
    ON oci_blobs (pending_delete_at)
    WHERE pending_delete_at IS NOT NULL;
