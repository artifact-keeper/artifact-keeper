-- 361_grade_status_enforcement.sql
-- #4994: enforce on the repository grade status of #4336.
--
-- * quality_gates.accepted_grade_status / promotion_rules.accepted_grade_status:
--   the weakest repository grade status a gate's score thresholds
--   (min_security_score, min_health_score) or a rule's min_health_score
--   accepts. 'rated' (only a fully assessed repository passes; the default
--   for new gates and rules),
--   'incomplete' (rated or incomplete) or 'any' (the score alone decides, as
--   before 1.12). Existing and new rows get different values, from two
--   separate statements below. ADD COLUMN's DEFAULT fills every gate and
--   rule that exists at upgrade: 'any', so they decide exactly as in 1.11.
--   The following ALTER COLUMN ... SET DEFAULT 'rated' is what a gate or
--   rule created afterwards gets (the API's own default is also 'rated'), so
--   new ones fail closed on a repository whose scans failed or cataloged
--   nothing. Set 'rated' or 'incomplete' on an existing gate or rule to
--   enforce on the grade status.
-- * scan_policies.block_uncataloged: refuse an artifact whose latest
--   completed scan of some scanner cataloged nothing (scan_completeness =
--   'not_cataloged'). Off by default, so no policy changes outcome.
-- * repositories.uncataloged_policy: 'fail' (default, as since #4036) or
--   'warn'. Under 'warn' an artifact no scanner could catalog still shows in
--   coverage.uncataloged and has_uncataloged_scan, but no longer lowers the
--   repository's grade_status. There is deliberately no 'ignore'.
--
-- Rolling upgrade: additive only. A 1.11 replica never reads these columns:
-- its explicit column lists leave them out and its SELECT * reads into
-- structs that ignore unknown columns. A gate, rule, policy or repository a
-- 1.11 replica creates gets the column default (for a gate or rule that is
-- 'rated', as for one created on 1.12). While 1.11 replicas still
-- serve, they evaluate gates, rules and scan policies without these checks
-- and recalculate scores without the uncataloged policy, so the outcome of a
-- promotion or download depends on which replica serves it until the
-- upgrade finishes.
--
-- Cost: catalogue-only. Constant defaults have been catalogue-only since
-- PostgreSQL 11, SET DEFAULT only rewrites the column default, and the
-- checks are added NOT VALID (existing rows hold the default), each under a
-- bounded lock_timeout.
SET LOCAL lock_timeout = '5s';

-- accepted_grade_status of every gate and rule that exists at upgrade:
-- 'any', the 1.11 behaviour.
ALTER TABLE quality_gates
    ADD COLUMN IF NOT EXISTS accepted_grade_status TEXT NOT NULL DEFAULT 'any';

ALTER TABLE promotion_rules
    ADD COLUMN IF NOT EXISTS accepted_grade_status TEXT NOT NULL DEFAULT 'any';

-- accepted_grade_status of a gate or rule created after the upgrade without
-- the field: 'rated' (the API's own default is also 'rated').
ALTER TABLE quality_gates
    ALTER COLUMN accepted_grade_status SET DEFAULT 'rated';

ALTER TABLE promotion_rules
    ALTER COLUMN accepted_grade_status SET DEFAULT 'rated';

ALTER TABLE scan_policies
    ADD COLUMN IF NOT EXISTS block_uncataloged BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS uncataloged_policy TEXT NOT NULL DEFAULT 'fail';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'ck_quality_gates_accepted_grade_status') THEN
        ALTER TABLE quality_gates
            ADD CONSTRAINT ck_quality_gates_accepted_grade_status
            CHECK (accepted_grade_status IN ('rated', 'incomplete', 'any'))
            NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'ck_promotion_rules_accepted_grade_status') THEN
        ALTER TABLE promotion_rules
            ADD CONSTRAINT ck_promotion_rules_accepted_grade_status
            CHECK (accepted_grade_status IN ('rated', 'incomplete', 'any'))
            NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'ck_repositories_uncataloged_policy') THEN
        ALTER TABLE repositories
            ADD CONSTRAINT ck_repositories_uncataloged_policy
            CHECK (uncataloged_policy IN ('fail', 'warn'))
            NOT VALID;
    END IF;
END $$;

-- Down path: rollback is SKIP_MIGRATIONS=true on the older release (see
-- docs/operations/rollback.md); 1.11 never reads or writes these columns, so
-- they can stay. To remove them by hand:
--   ALTER TABLE quality_gates
--       DROP CONSTRAINT IF EXISTS ck_quality_gates_accepted_grade_status,
--       DROP COLUMN IF EXISTS accepted_grade_status;
--   ALTER TABLE promotion_rules
--       DROP CONSTRAINT IF EXISTS ck_promotion_rules_accepted_grade_status,
--       DROP COLUMN IF EXISTS accepted_grade_status;
--   ALTER TABLE scan_policies DROP COLUMN IF EXISTS block_uncataloged;
--   ALTER TABLE repositories
--       DROP CONSTRAINT IF EXISTS ck_repositories_uncataloged_policy,
--       DROP COLUMN IF EXISTS uncataloged_policy;
