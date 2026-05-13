-- CI OIDC: providers, service-account enum value, and identity mappings
-- (T-CI-OIDC)
--
-- Enables keyless authentication for CI/CD pipelines: a pipeline exchanges a
-- CI-issued OIDC JWT for a short-lived Artifact Keeper access token without
-- storing any static secrets.
--
-- Schema overview
-- ───────────────
-- ci_oidc_providers        — trusted issuers (GitLab, GitHub Actions, generic)
-- ci_oidc_identity_mappings — priority-ordered claim-filter rules that map a
--                            validated JWT to an AK service account + role
-- auth_provider enum        — extended with 'ci' to tag service-account rows

-- ---------------------------------------------------------------------------
-- 1. Trusted CI/CD identity providers
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ci_oidc_providers (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(255) NOT NULL,
    -- 'gitlab' | 'github' | 'generic'
    provider_type    VARCHAR(50)  NOT NULL DEFAULT 'generic',
    -- Issuer URL exactly as it appears in the CI JWT 'iss' claim
    -- e.g. 'https://gitlab.com', 'https://token.actions.githubusercontent.com'
    issuer_url       TEXT         NOT NULL,
    -- Audience the CI JWT must declare in its 'aud' claim
    audience         TEXT         NOT NULL DEFAULT 'artifact-keeper',
    is_enabled       BOOLEAN      NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ci_oidc_providers_issuer
    ON ci_oidc_providers (issuer_url);
CREATE INDEX IF NOT EXISTS idx_ci_oidc_providers_enabled
    ON ci_oidc_providers (is_enabled);

-- ---------------------------------------------------------------------------
-- 2. Extend auth_provider enum with 'ci'
--
--    Rows with auth_provider = 'ci' are CI service accounts provisioned
--    automatically on first token exchange.  They have password_hash = NULL
--    and cannot log in via the normal username/password flow.
-- ---------------------------------------------------------------------------

ALTER TYPE auth_provider ADD VALUE IF NOT EXISTS 'ci';

-- ---------------------------------------------------------------------------
-- 3. Priority-ordered claim-filter rules (identity mappings)
--
--    On token exchange the service evaluates mappings in priority order
--    (lower number = higher priority).  The first enabled mapping whose
--    claim_filters all match the incoming JWT claims wins.  The matching
--    mapping determines:
--      • an optional explicit repository scope (allowed_repo_ids)
--      • a stable username derived from the mapping UUID
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ci_oidc_identity_mappings (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id      UUID         NOT NULL
                                  REFERENCES ci_oidc_providers(id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    -- Lower number = higher priority (evaluated in ascending order)
    priority         INTEGER      NOT NULL DEFAULT 100,
    -- JSONB claim-filter map.  Each key is a claim name; the value is either
    -- a single string (exact match) or an array of strings (any-of match).
    -- An empty object {} matches every JWT (catch-all).
    claim_filters    JSONB        NOT NULL DEFAULT '{}',
    -- Optional repository-scope restriction (further narrows Role access).
    -- NULL means the mapping does not restrict by repository.
    allowed_repo_ids UUID[],
    is_enabled       BOOLEAN      NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ci_oidc_mappings_provider_priority
    ON ci_oidc_identity_mappings (provider_id, priority);

-- ---------------------------------------------------------------------------
-- 4. Compatibility guard for mixed deployment histories
--
-- If `allowed_repo_ids` was removed on any existing environment by a prior
-- migration variant, add it back. On fresh installs this is a no-op because
-- the column is already created above.
-- ---------------------------------------------------------------------------

ALTER TABLE ci_oidc_identity_mappings
	ADD COLUMN IF NOT EXISTS allowed_repo_ids UUID[];
