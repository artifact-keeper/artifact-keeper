-- Two-phase tombstone on the OCI upload cleanup journal, closing the
-- pre-delete liveness window #3158 deliberately only narrowed (#3187).
--
-- #3158 re-asserts blob liveness in the same atomic UPDATE that extends a
-- claimed key's lease, immediately before the object-store delete. That
-- UPDATE runs on the pool as a single autocommit statement: its row lock is
-- on `oci_upload_cleanup_keys`, never on `oci_blobs`, and it is released the
-- instant the statement commits. The sweep then deletes the object holding
-- nothing, so a push that commits its `oci_blobs` row inside that gap still
-- has its bytes destroyed.
--
-- The racing push INSERTs a *new* `oci_blobs` row, so there is no `oci_blobs`
-- row to lock -- `FOR UPDATE` there would lock nothing. The only object both
-- sides already touch is the journal row (UNIQUE on `storage_key`, registered
-- by the push before the storage write it tracks), so that row is where the
-- two sides have to meet.
--
-- `pending_delete_at` makes the sweep's intent durable and visible BEFORE the
-- destructive delete, which is the property that closes the window:
--
--   sweep  phase 1: UPDATE ... SET pending_delete_at = NOW() WHERE <liveness>
--                   -- atomic with the liveness check, then committed
--   sweep  phase 2: storage.delete()          -- no lock held, no tx open
--   sweep  phase 3: DELETE ... WHERE pending_delete_at IS NOT NULL AND <liveness>
--
--   push:           SELECT ... FOR UPDATE on the same journal row, in the SAME
--                   transaction that commits `oci_blobs`. A live tombstone
--                   means the bytes are already being destroyed, so the push
--                   refuses to commit; no tombstone means the push deletes the
--                   journal row under the lock, and the sweep's phase-1 UPDATE
--                   then matches zero rows and skips its storage delete.
--
-- This is the same shape migration 141 gave `oci_blobs` for blob GC
-- (`run_blob_gc_mark` / `run_blob_gc_sweep`), applied one layer up. It is
-- preferred over holding an explicit `FOR UPDATE` transaction across the
-- object-store call: a cleanup batch is up to
-- OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT (1000) keys, and holding a pooled
-- connection plus a row lock across each of 1000 sequential object-store
-- round trips would make every push of a swept digest wait on object-store
-- latency (or its timeout). Here neither side holds anything across storage.
ALTER TABLE oci_upload_cleanup_keys
    ADD COLUMN pending_delete_at TIMESTAMPTZ;

COMMENT ON COLUMN oci_upload_cleanup_keys.pending_delete_at IS
    'Two-phase sweep tombstone (#3187): set atomically with the pre-delete liveness re-check, before the object-store delete. A push that finds it set while claim_expires_at is still in the future must not commit an oci_blobs row for this key.';

-- The tombstone is only meaningful while the sweep that set it still holds a
-- live claim. A crashed sweep leaves a tombstone behind; it expires with the
-- claim lease (OCI_CLEANUP_KEY_CLAIM_TTL) rather than dooming the key's
-- digest forever, and the push side treats an expired claim as no tombstone.
--
-- Partial index: the push's commit-time guard looks the row up by primary key,
-- but operators and the reaper need to find stranded tombstones cheaply, and
-- tombstoned rows are a vanishing fraction of the table.
CREATE INDEX IF NOT EXISTS idx_oci_upload_cleanup_keys_pending_delete
    ON oci_upload_cleanup_keys (pending_delete_at)
    WHERE pending_delete_at IS NOT NULL;

-- CREATE INDEX CONCURRENTLY is intentionally not used: sqlx::migrate! runs
-- each migration file inside a transaction and CONCURRENTLY is rejected in a
-- transaction block (same constraint as migrations 166 and 193). The ALTER
-- TABLE ... ADD COLUMN is a catalog-only change on PostgreSQL 11+ (no default,
-- so no table rewrite), and the partial index build only sees rows that
-- already satisfy the predicate -- of which there are none at migration time.
-- Both take ACCESS EXCLUSIVE / SHARE only momentarily.
--
-- Reversible: DROP INDEX idx_oci_upload_cleanup_keys_pending_delete;
--             ALTER TABLE oci_upload_cleanup_keys DROP COLUMN pending_delete_at;
