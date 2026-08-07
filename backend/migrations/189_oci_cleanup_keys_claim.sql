-- Atomic multi-replica claims for OCI upload cleanup-journal sweeps
-- (RowClaimedQueue pattern).
--
-- The storage GC cleanup-journal sweeps SELECTed unreferenced/pending
-- cleanup keys, deleted the storage object, and only then deleted the row,
-- so multiple replicas ticking on the same GC schedule could select and
-- delete the same key concurrently — and the external storage delete
-- happened before any durable row claim, so the guarded row DELETE could
-- not stop a duplicate external delete attempt. Rows are now claimed with
-- FOR UPDATE SKIP LOCKED before the storage delete; the row DELETE and the
-- failure release must present the claim token.
ALTER TABLE oci_upload_cleanup_keys
    ADD COLUMN claimed_by TEXT,
    ADD COLUMN claim_token UUID,
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD COLUMN last_error TEXT;

COMMENT ON COLUMN oci_upload_cleanup_keys.claimed_by IS
    'Diagnostic worker identity that claimed the sweep; not the correctness guard';
COMMENT ON COLUMN oci_upload_cleanup_keys.claim_token IS
    'Random per-claim token; the row DELETE and failure release must match it';
COMMENT ON COLUMN oci_upload_cleanup_keys.claim_expires_at IS
    'Sweep-claim lease deadline; an expired claim makes the key sweepable again';
COMMENT ON COLUMN oci_upload_cleanup_keys.last_error IS
    'Most recent storage-delete failure for this key, recorded on claim release';
