-- The age_gate_reviews key gains gate, so one version can hold an age, a scan and a curation row (#5152)
-- Contract: the previous release upserts ON CONFLICT (repository_id, package_name, package_version), the key this drops,
-- so an upgrade to the release with 420 and 429 can't roll (docs/operations/online-migrations.md)

-- The old UNIQUE (repository_id, package_name, package_version) forbids an age row and a scan row for one version
-- Its generated name sits at the 63-char identifier limit, so it is looked up rather than hardcoded
DO $$
DECLARE
    con_name TEXT;
BEGIN
    SELECT conname INTO con_name
    FROM pg_constraint
    WHERE conrelid = 'age_gate_reviews'::regclass
      AND contype = 'u'
      AND pg_get_constraintdef(oid)
          LIKE 'UNIQUE (repository_id, package_name, package_version)%';

    IF con_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE age_gate_reviews DROP CONSTRAINT %I', con_name);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'age_gate_reviews'::regclass
          AND conname = 'age_gate_reviews_gate_coord_key'
    ) THEN
        ALTER TABLE age_gate_reviews
            ADD CONSTRAINT age_gate_reviews_gate_coord_key
                UNIQUE (gate, repository_id, package_name, package_version);
    END IF;
END $$;

-- Every ON CONFLICT on this table must name gate too, or it fails at runtime (not caught by sqlx)
