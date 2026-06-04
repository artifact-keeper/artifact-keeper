-- Make every foreign key that references repositories(id) clean up on delete,
-- so deleting a repository no longer fails with a 500 DATABASE_ERROR (#1550).
--
-- Several promotion and upload-session tables referenced repositories(id) with
-- the default NO ACTION. The most common trigger is upload_sessions: every
-- upload creates a row there, so any repository that has ever been uploaded to
-- could not be deleted (the FK violation surfaced as DATABASE_ERROR / HTTP 500).
-- promotion_history, promotion_approvals, and the nullable
-- repositories.promotion_target_id pointer had the same gap.
--
-- Each block is guarded so it is a no-op when the table/column is absent, and
-- re-creatable (DROP CONSTRAINT IF EXISTS) so re-running is safe.

-- upload_sessions.repository_id: the "fails every time" case for uploaded repos.
DO $$
BEGIN
    IF to_regclass('public.upload_sessions') IS NOT NULL THEN
        ALTER TABLE upload_sessions DROP CONSTRAINT IF EXISTS upload_sessions_repository_id_fkey;
        ALTER TABLE upload_sessions
            ADD CONSTRAINT upload_sessions_repository_id_fkey
            FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;
    END IF;
END $$;

-- promotion_history source/target repositories.
DO $$
BEGIN
    IF to_regclass('public.promotion_history') IS NOT NULL THEN
        ALTER TABLE promotion_history DROP CONSTRAINT IF EXISTS promotion_history_source_repo_id_fkey;
        ALTER TABLE promotion_history
            ADD CONSTRAINT promotion_history_source_repo_id_fkey
            FOREIGN KEY (source_repo_id) REFERENCES repositories(id) ON DELETE CASCADE;

        ALTER TABLE promotion_history DROP CONSTRAINT IF EXISTS promotion_history_target_repo_id_fkey;
        ALTER TABLE promotion_history
            ADD CONSTRAINT promotion_history_target_repo_id_fkey
            FOREIGN KEY (target_repo_id) REFERENCES repositories(id) ON DELETE CASCADE;
    END IF;
END $$;

-- promotion_approvals source/target repositories.
DO $$
BEGIN
    IF to_regclass('public.promotion_approvals') IS NOT NULL THEN
        ALTER TABLE promotion_approvals DROP CONSTRAINT IF EXISTS promotion_approvals_source_repo_id_fkey;
        ALTER TABLE promotion_approvals
            ADD CONSTRAINT promotion_approvals_source_repo_id_fkey
            FOREIGN KEY (source_repo_id) REFERENCES repositories(id) ON DELETE CASCADE;

        ALTER TABLE promotion_approvals DROP CONSTRAINT IF EXISTS promotion_approvals_target_repo_id_fkey;
        ALTER TABLE promotion_approvals
            ADD CONSTRAINT promotion_approvals_target_repo_id_fkey
            FOREIGN KEY (target_repo_id) REFERENCES repositories(id) ON DELETE CASCADE;
    END IF;
END $$;

-- repositories.promotion_target_id is a nullable pointer at another repository;
-- deleting that target should just clear the pointer, not block the delete.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'repositories' AND column_name = 'promotion_target_id'
    ) THEN
        ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_promotion_target_id_fkey;
        ALTER TABLE repositories
            ADD CONSTRAINT repositories_promotion_target_id_fkey
            FOREIGN KEY (promotion_target_id) REFERENCES repositories(id) ON DELETE SET NULL;
    END IF;
END $$;
