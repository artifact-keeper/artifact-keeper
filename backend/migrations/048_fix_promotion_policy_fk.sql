-- Fix: Remove dangling FK reference to non-existent security_policies table
-- The promotion_policy_id column referenced security_policies(id) which was never created.
-- The PromotionPolicyService evaluates policies by repository_id directly via
-- scan_policies and license_policies, so this FK is unnecessary.

-- Drop the broken foreign key constraint (if it was created)
-- Since the migration would have failed on the FK, the column may not exist at all.
-- Use a DO block to handle both cases safely.

DO $$
BEGIN
    -- If the column doesn't exist (because migration 047 failed on the FK), add it without FK
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'repositories' AND column_name = 'promotion_policy_id'
    ) THEN
        ALTER TABLE repositories ADD COLUMN promotion_policy_id UUID;
    END IF;

    -- If the column exists with a FK constraint, drop the constraint
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints tc
        JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name
        WHERE tc.table_name = 'repositories'
          AND ccu.column_name = 'promotion_policy_id'
          AND tc.constraint_type = 'FOREIGN KEY'
    ) THEN
        EXECUTE format(
            'ALTER TABLE repositories DROP CONSTRAINT %I',
            (SELECT tc.constraint_name FROM information_schema.table_constraints tc
             JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name
             WHERE tc.table_name = 'repositories'
               AND ccu.column_name = 'promotion_policy_id'
               AND tc.constraint_type = 'FOREIGN KEY'
             LIMIT 1)
        );
    END IF;
END $$;

COMMENT ON COLUMN repositories.promotion_policy_id IS 'Security policy to evaluate before promotion (resolved via scan_policies/license_policies by repo)';
