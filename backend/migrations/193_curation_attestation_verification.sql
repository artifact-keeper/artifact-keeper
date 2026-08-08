-- 193_curation_attestation_verification.sql
-- #2955: persist the result of cryptographic attestation verification for
-- `publisher_trust match:attestation`. A successful record is the ONLY thing
-- that lets `publisher_source::extract_publisher` emit verified=true; absence of
-- a record reproduces exactly the pre-#2955 fail-safe behaviour (Flag).
--
-- Renumber at PR-open if upstream has moved past 192 (standing convention).
--
-- CONCURRENTLY N/A: ADD COLUMN with a constant/NULL default is a fast,
-- catalog-only change on modern Postgres (no table rewrite, no long lock).

ALTER TABLE curation_packages
    -- unverified: no material / not attempted (the default, = today's behavior).
    -- verified:   full chain verified; the cert-bound identity below is trusted.
    -- failed:     material present but verification failed (includes the
    --             npm-unsupported case, distinguished by attestation_error).
    ADD COLUMN IF NOT EXISTS attestation_state TEXT NOT NULL DEFAULT 'unverified'
        CHECK (attestation_state IN ('unverified', 'verified', 'failed')),
    -- The certificate-bound workflow identity (SAN URI). Populated on success
    -- ONLY, and always sourced from the verified certificate, never the blob.
    ADD COLUMN IF NOT EXISTS attestation_identity TEXT,
    -- The certificate-bound OIDC issuer (e.g. GitHub Actions). Success only.
    ADD COLUMN IF NOT EXISTS attestation_issuer TEXT,
    -- The certificate-bound repository owner (org/user) — the value that may
    -- satisfy a trusted-publisher allowlist. Success only, cert-bound.
    ADD COLUMN IF NOT EXISTS attestation_owner TEXT,
    -- When verification last ran (success or failure).
    ADD COLUMN IF NOT EXISTS attestation_verified_at TIMESTAMPTZ,
    -- The specific failing-check reason (or unsupported reason). NULL on success.
    ADD COLUMN IF NOT EXISTS attestation_error TEXT;

-- The typed-rule evaluation loop reads the verification record for a package by
-- its catalog identity; the existing idx_curation_pkg_unique already covers the
-- (staging_repo_id, format, package_name, version, …) lookup, so no new index
-- is needed for the read path. A partial index over verified rows keeps the
-- "show me everything that verified" admin view cheap.
CREATE INDEX IF NOT EXISTS idx_curation_pkg_attested
    ON curation_packages (staging_repo_id)
    WHERE attestation_state = 'verified';
