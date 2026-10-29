-- CI OIDC: the minted access token's lifetime comes from the provider (#5054).
--
-- Since #3820 a CI exchange capped the minted access token at the presented
-- assertion's own `exp`. GitHub Actions ID tokens live about five minutes, so
-- every token exchanged from GitHub Actions died after about five minutes,
-- whatever TTL was configured. The assertion now only has to be valid when it
-- is exchanged; the minted token lives `token_ttl_secs`, set per provider.
--
--   token_ttl_secs  default 900 (15 minutes), between 60 and 3600. The upper
--                   bound is a hard maximum, enforced here and again in the
--                   application at mint time.
--
-- Kubernetes providers ignore the column: their pull-only credential keeps
-- expiring with the presented ServiceAccount token.
--
-- `ci_oidc_providers` is a handful of operator-created rows and not a hot
-- table (`migration_safety::HOT_TABLES`), so a constant default and a CHECK
-- validated inline are free. It is read on every CI OIDC exchange, so
-- lock_timeout bounds the wait for the ACCESS EXCLUSIVE lock behind an old
-- replica's open transaction (docs/operations/online-migrations.md).

SET LOCAL lock_timeout = '5s';

ALTER TABLE ci_oidc_providers
    ADD COLUMN IF NOT EXISTS token_ttl_secs INTEGER NOT NULL DEFAULT 900;

ALTER TABLE ci_oidc_providers
    ADD CONSTRAINT ci_oidc_providers_token_ttl_secs_check
        CHECK (token_ttl_secs BETWEEN 60 AND 3600);
