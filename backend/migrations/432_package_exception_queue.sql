-- One package-exception queue for the age, scan and curation gates, in place on age_gate_reviews
-- An approved row serves those bytes until expires_at (NULL never expires), it does not change any policy

ALTER TABLE age_gate_reviews
    ADD COLUMN IF NOT EXISTS gate TEXT NOT NULL DEFAULT 'age'
        CHECK (gate IN ('age', 'scan', 'curation')),
    -- NULL means the row exists only because a pull was refused
    ADD COLUMN IF NOT EXISTS justification TEXT,
    ADD COLUMN IF NOT EXISTS requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    -- Everyone who has filed a request on the row, so a co-requester can't grant it either
    ADD COLUMN IF NOT EXISTS requesters UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    -- Scan gate only: the content digest the exception was granted for, so republished bytes re-block
    ADD COLUMN IF NOT EXISTS basis_digest TEXT;

-- Reviewer queue reads: pending rows for one gate, newest demand first
CREATE INDEX IF NOT EXISTS idx_age_gate_reviews_gate_pending
    ON age_gate_reviews (gate, status, last_requested_at DESC)
    WHERE status = 'pending';

-- The reviewer default view: human-justified requests only
CREATE INDEX IF NOT EXISTS idx_age_gate_reviews_justified
    ON age_gate_reviews (gate, status, last_requested_at DESC)
    WHERE justification IS NOT NULL;

-- The requested_by foreign key (ON DELETE SET NULL on a user delete), the per-user open-request cap and a requester's own list
CREATE INDEX IF NOT EXISTS idx_age_gate_reviews_requested_by
    ON age_gate_reviews (requested_by)
    WHERE requested_by IS NOT NULL;

-- Global capability to decide exceptions, it grants no say over repository scan or age settings
INSERT INTO roles (name, description, permissions, is_system)
VALUES (
    'security-reviewer',
    'Grant, expire and revoke per-package exceptions to the age, scan and curation gates',
    ARRAY['security_review'],
    true
)
ON CONFLICT (name) DO NOTHING;
