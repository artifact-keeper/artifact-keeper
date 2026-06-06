-- Make every foreign key that can block a repository delete clean up on delete,
-- so DELETE /api/v1/repositories/{key} no longer fails with 500 DATABASE_ERROR
-- (#1550).
--
-- Deleting a repository cascades to its `artifacts` rows, so a delete can be
-- blocked by any FK referencing repositories(id) OR artifacts(id) that uses the
-- default NO ACTION. A pg_catalog audit of a fully migrated database shows the
-- blocking set is:
--   * upload_sessions.repository_id             -> repositories (every upload creates a row)
--   * promotion_history.source_repo_id/target   -> repositories
--   * promotion_approvals.source_repo_id/target -> repositories (named fk_approval_*)
--   * promotion_approvals.artifact_id           -> artifacts    (named fk_approval_artifact)
-- plus the nullable self-pointer repositories.promotion_target_id -> repositories.
--
-- This migration is NAME-AGNOSTIC: for each (table, column) it drops whatever
-- single-column FK exists on that column (some were created with explicit names
-- like fk_approval_source, others with the conventional <table>_<col>_fkey) and
-- recreates a single canonical FK with the desired ON DELETE action. That makes
-- it correct regardless of how the original constraint was named, and idempotent
-- on re-run.

DO $$
DECLARE
    spec   RECORD;
    fk     RECORD;
    parent regclass;
BEGIN
    FOR spec IN
        SELECT *
        FROM (VALUES
            ('upload_sessions',     'repository_id',       'repositories', 'CASCADE'),
            ('promotion_history',   'source_repo_id',      'repositories', 'CASCADE'),
            ('promotion_history',   'target_repo_id',      'repositories', 'CASCADE'),
            ('promotion_approvals', 'source_repo_id',      'repositories', 'CASCADE'),
            ('promotion_approvals', 'target_repo_id',      'repositories', 'CASCADE'),
            ('promotion_approvals', 'artifact_id',         'artifacts',    'CASCADE'),
            ('repositories',        'promotion_target_id', 'repositories', 'SET NULL')
        ) AS t(tbl, col, refs, action)
    LOOP
        -- Skip if the child table or the column does not exist in this database.
        IF to_regclass('public.' || spec.tbl) IS NULL THEN
            CONTINUE;
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = spec.tbl AND column_name = spec.col
        ) THEN
            CONTINUE;
        END IF;

        parent := ('public.' || spec.refs)::regclass;

        -- Drop every existing single-column FK on this column that points at the
        -- expected parent, whatever it is named (handles both fk_approval_* and
        -- the conventional names, plus any duplicate added by an earlier draft).
        FOR fk IN
            SELECT con.conname
            FROM pg_constraint con
            JOIN pg_attribute att
              ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey)
            WHERE con.conrelid = ('public.' || spec.tbl)::regclass
              AND con.contype = 'f'
              AND con.confrelid = parent
              AND att.attname = spec.col
              AND array_length(con.conkey, 1) = 1
        LOOP
            EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', spec.tbl, fk.conname);
        END LOOP;

        -- Recreate a single canonical FK with the desired delete behavior.
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES %I(id) ON DELETE %s',
            spec.tbl,
            spec.tbl || '_' || spec.col || '_fkey',
            spec.col,
            spec.refs,
            spec.action
        );
    END LOOP;
END $$;
