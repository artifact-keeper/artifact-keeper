-- Ensure CI OIDC mapping repository scope exists.
--
-- Safe for mixed deployment histories:
-- - If `085` was never applied (or is now a no-op), this does nothing.
-- - If `085` previously dropped the column, this restores it.

ALTER TABLE ci_oidc_identity_mappings
	ADD COLUMN IF NOT EXISTS allowed_repo_ids UUID[];
