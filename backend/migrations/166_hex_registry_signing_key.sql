-- Hex registry signing keys.
--
-- A hex repository is only usable by a real `mix` client if its registry
-- resources (/names, /versions, /packages/{name}) are signed and the matching
-- public key is published at /hex/{repo}/public_key. Unlike Debian's optional
-- Release.gpg, the signature is mandatory in the hex protocol, so every hosted
-- hex repository needs exactly one dedicated registry key. The key is
-- provisioned on demand and reuses the existing `signing_keys` table (RSA
-- material, private half encrypted at rest).
--
-- This partial unique index makes that provisioning idempotent: concurrent
-- first-touch requests race on the INSERT, the losers hit ON CONFLICT DO
-- NOTHING and re-select the winner's row, so a repository can never end up
-- with two registry keys (which would make signatures verify only half the
-- time, depending on which row was read).
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_hex_registry_per_repo
    ON signing_keys (repository_id)
    WHERE name = 'hex-registry' AND repository_id IS NOT NULL;
