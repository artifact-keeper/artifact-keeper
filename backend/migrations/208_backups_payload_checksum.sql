-- Record each backup archive's payload digest OUTSIDE the archive (#3373).
--
-- #3011 gave `BackupManifest` a real `checksum` and made `restore` verify it,
-- but the expected value travels inside the very file it is supposed to
-- authenticate: `verify_archive_checksum` skipped verification entirely when
-- `manifest.checksum` was empty, so anyone who could rewrite the archive could
-- also blank that field and turn the control off. A self-contained checksum
-- detects corruption; it cannot detect tampering.
--
-- `BackupService::restore` only ever consumes an archive it has a `backups`
-- row for -- it resolves `backup_id` against this table and reads the archive
-- from the `storage_path` the server generated. There is no import path that
-- ingests a foreign archive. So this row IS an anchor outside the archive:
-- the threat the issue describes (an archive tampered with at rest, or pulled
-- back from compromised/third-party storage) does not reach the database.
--
-- `payload_checksum` holds the SHA-256 that `payload_summary` computes over the
-- archive's payload entries at capture time -- the same digest that is also
-- written into the manifest. On restore the two are compared against a digest
-- recomputed from the extracted entries; the recorded one wins, and its absence
-- can no longer be arranged by editing the archive.
--
-- NULL means "captured before this release" (or by a path that did not record
-- one). Those archives fall back to their manifest checksum, and a restore of
-- one with no manifest checksum either is refused unless the operator
-- explicitly opts in -- see the CHANGELOG entry for #3373.
--
-- Nullable with no default and no backfill: an existing row's archive really
-- does have no recorded digest, and inventing one would assert an integrity
-- guarantee that was never established. Adding a nullable column with no
-- default is a catalog-only operation in Postgres 11+, so this does not
-- rewrite the table.

ALTER TABLE backups
    ADD COLUMN IF NOT EXISTS payload_checksum TEXT;

COMMENT ON COLUMN backups.payload_checksum IS
    'SHA-256 over the archive payload, recorded at capture time and verified on '
    'restore (#3373). NULL for archives captured before this column existed. '
    'The anchor is deliberately here rather than only in the archive manifest, '
    'so rewriting the archive cannot also rewrite the expected digest.';
