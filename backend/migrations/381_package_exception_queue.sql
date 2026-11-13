-- One package-exception queue for the age, scan and curation gates, in place on age_gate_reviews
-- An approved row serves those bytes until expires_at (NULL never expires), it does not change any policy

ALTER TABLE age_gate_reviews
    ADD COLUMN IF NOT EXISTS gate TEXT NOT NULL DEFAULT 'age'
        CHECK (gate IN ('age', 'scan', 'curation')),
    -- NULL means the row exists only because a pull was refused
    ADD COLUMN IF NOT EXISTS justification TEXT,
    ADD COLUMN IF NOT EXISTS requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    -- Scan gate only: the content digest the exception was granted for, so republished bytes re-block
    ADD COLUMN IF NOT EXISTS basis_digest TEXT;

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

-- Reviewer queue reads: pending rows for one gate, newest demand first
CREATE INDEX IF NOT EXISTS idx_age_gate_reviews_gate_pending
    ON age_gate_reviews (gate, status, last_requested_at DESC)
    WHERE status = 'pending';

-- The reviewer default view: human-justified requests only
CREATE INDEX IF NOT EXISTS idx_age_gate_reviews_justified
    ON age_gate_reviews (gate, status, last_requested_at DESC)
    WHERE justification IS NOT NULL;

-- The per-user open-request cap on POST /api/v1/exceptions/requests
CREATE INDEX IF NOT EXISTS idx_age_gate_reviews_open_requests
    ON age_gate_reviews (requested_by)
    WHERE status = 'pending' AND justification IS NOT NULL;

-- Global capability to decide exceptions, it grants no say over repository scan or age settings
INSERT INTO roles (name, description, permissions, is_system)
VALUES (
    'security-reviewer',
    'Grant, expire and revoke per-package exceptions to the age, scan and curation gates',
    ARRAY['security_review'],
    true
)
ON CONFLICT (name) DO NOTHING;
