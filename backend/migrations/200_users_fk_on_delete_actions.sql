-- Give every `REFERENCES users(id)` foreign key an explicit ON DELETE action.
--
-- Issue #2878: deleting a user returned a bare "db operation failed" whenever
-- that user was referenced by a FK with no ON DELETE clause. Postgres defaults
-- such a constraint to NO ACTION (RESTRICT semantics), so the DELETE aborted
-- with a foreign-key violation the API surfaced as an opaque 500. A user who
-- had ever created a migration job or a signing key could therefore never be
-- deleted -- including the OIDC accounts in the original report (#2875).
--
-- Disposition per column (deliberate, not mechanical):
--
--   * SET NULL for provenance / audit attribution columns (`created_by`,
--     `performed_by`, `promoted_by`, `acknowledged_by`). These record *who*
--     did something; the row itself is history that must survive the account.
--     Cascading would destroy audit trails (signing-key operations, promotion
--     history, CVE acknowledgements) as a side effect of deleting a user, and
--     RESTRICT makes the account undeletable. Nulling the attribution keeps
--     the record and matches the pattern already established everywhere else
--     in this schema (009_backups, 071_curation, 128_repositories_created_by).
--     Every column below is already nullable, so no data rewrite is needed.
--
--   * CASCADE for the NOT NULL `user_id` of transient upload-session rows.
--     These are in-flight, resumable-upload scratch records owned by exactly
--     one user; they are meaningless once that user is gone and cannot be
--     nulled (NOT NULL). This mirrors 083_download_tickets_cascade.sql, which
--     made the identical call for short-lived download tickets.
--
-- The constraint name is discovered from the system catalog rather than
-- assumed: Postgres auto-generates it and the conventional
-- `<table>_<column>_fkey` spelling is not guaranteed. Driven by a single
-- catalog-driven loop so the remediation list stays readable and the DDL is
-- written once.
DO $$
DECLARE
    target record;
    fk_name text;
BEGIN
    FOR target IN
        SELECT * FROM (VALUES
            -- Provenance / audit attribution: keep the row, drop the pointer.
            ('source_connections',  'created_by',      'SET NULL'),
            ('migration_jobs',      'created_by',      'SET NULL'),
            ('signing_keys',        'created_by',      'SET NULL'),
            ('signing_key_audit',   'performed_by',    'SET NULL'),
            ('promotion_history',   'promoted_by',     'SET NULL'),
            ('cve_history',         'acknowledged_by', 'SET NULL'),
            -- Transient per-user upload scratch: NOT NULL, so cascade.
            ('oci_upload_sessions',   'user_id', 'CASCADE'),
            ('upload_sessions',       'user_id', 'CASCADE'),
            ('incus_upload_sessions', 'user_id', 'CASCADE')
        ) AS v(tbl, col, action)
    LOOP
        -- Tolerate a table that does not exist on this deployment rather than
        -- failing the whole migration.
        CONTINUE WHEN to_regclass(target.tbl) IS NULL;

        SELECT con.conname INTO fk_name
        FROM pg_constraint con
        JOIN pg_attribute att
          ON att.attrelid = con.conrelid
         AND att.attnum = ANY (con.conkey)
        WHERE con.conrelid = to_regclass(target.tbl)
          AND con.confrelid = to_regclass('users')
          AND con.contype = 'f'
          AND att.attname = target.col
        LIMIT 1;

        IF fk_name IS NOT NULL THEN
            EXECUTE format(
                'ALTER TABLE %I DROP CONSTRAINT %I',
                target.tbl, fk_name
            );
        END IF;

        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (%I) '
            'REFERENCES users(id) ON DELETE %s',
            target.tbl,
            target.tbl || '_' || target.col || '_fkey',
            target.col,
            target.action
        );

        fk_name := NULL;
    END LOOP;
END $$;
