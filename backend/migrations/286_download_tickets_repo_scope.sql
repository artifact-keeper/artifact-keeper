-- GHSA-2mfv-xg68-gq4p: a download ticket carries the repository restriction
-- of the credential that minted it, so redeeming it cannot read a repository
-- that credential could not.
--
-- `scope_recorded` is false for every ticket minted before this migration;
-- redemption refuses those (fail closed). Tickets live 30 seconds by default
-- and at most ten minutes (the Terraform mirror's archive tickets), so the
-- only effect is that a ticket minted across the upgrade has to be minted
-- again. `allowed_repo_ids` is NULL for an unrestricted credential and the
-- allowlist for a repository-restricted one.
--
-- Both are catalogue-only changes on PostgreSQL 11+ (a constant default and
-- a nullable column): no table rewrite, no validation scan.
ALTER TABLE download_tickets
    ADD COLUMN IF NOT EXISTS scope_recorded BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS allowed_repo_ids UUID[];
