-- #2569 (RPM curation fail-closed default): explicit opt-in to ingest
-- UNVERIFIED upstream metadata when no trusted_gpg_key is configured.
--
-- With #2568 landed (create/update API for `trusted_gpg_key`), the safe default
-- flips fail-closed: a curation sync whose staging repo has NO trusted GPG key
-- available now REFUSES to ingest unverified upstream metadata rather than
-- silently trusting an unauthenticated upstream (the pre-#2569 behavior). A
-- repository may opt back into the legacy "unverified upstream" behavior by
-- setting this flag true — the deliberate, auditable escape hatch for existing
-- keyless RPM curation repos.
--
-- Defaults false (fail-closed). Read on the keyless RPM curation-sync path
-- (`run_curation_sync_cycle`); NULL/absent is impossible (NOT NULL DEFAULT).
--
-- Reversible: DROP COLUMN restores the pre-#2569 shape.
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS curation_allow_unverified BOOLEAN NOT NULL DEFAULT false;
