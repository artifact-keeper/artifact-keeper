-- #4265 follow-up to #4228.
--
-- (1) Recover repository tokens that had ALREADY lost every repository
--     before migration 235 ran. 235 marked only tokens with live
--     `api_token_repositories` rows; a token whose rows had cascaded away
--     earlier was left unmarked -- unrestricted, and invisible in the
--     repository-token listing (which joins the pin table), so nobody would
--     notice. Every mint through the repository-token surface writes an
--     `API_TOKEN_CREATED` audit row whose details carry `surface = "repo"`,
--     which is enough to tell those tokens apart: they were minted pinned
--     to exactly one repository, so with no pin row left they must be
--     deny-all. Service-account tokens minted with an explicit
--     `repository_ids` list share the `service_account` surface with
--     unrestricted ones and cannot be recovered this way; the changelog
--     asks administrators to review those.
--
-- (2) Re-declare the marker trigger function with a pinned `search_path`
--     and make the whole file re-runnable (`IF NOT EXISTS`, `OR REPLACE`,
--     `DROP ... IF EXISTS`), under the lock-timeout fail-fast migration 232
--     established, so a partially applied run converges instead of erroring.
SET LOCAL lock_timeout = '5s';

ALTER TABLE api_tokens
    ADD COLUMN IF NOT EXISTS repository_restricted BOOLEAN NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION mark_api_token_repository_restricted() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    UPDATE api_tokens SET repository_restricted = true WHERE id = NEW.token_id;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS api_token_repositories_marks_restricted ON api_token_repositories;
CREATE TRIGGER api_token_repositories_marks_restricted
AFTER INSERT ON api_token_repositories
FOR EACH ROW EXECUTE FUNCTION mark_api_token_repository_restricted();

UPDATE api_tokens t
SET repository_restricted = true
WHERE t.repository_restricted = false
  AND t.repo_selector IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM api_token_repositories atr WHERE atr.token_id = t.id
  )
  AND EXISTS (
      SELECT 1 FROM audit_log a
       WHERE a.action = 'API_TOKEN_CREATED'
         AND a.resource_type = 'api_token'
         AND a.resource_id = t.id
         AND a.details->>'surface' = 'repo'
  );
