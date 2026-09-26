-- #4228: a token restricted to explicit repositories must stay restricted
-- when those repositories are deleted.
--
-- `api_token_repositories.repo_id` is `ON DELETE CASCADE`, so deleting every
-- repository a token names leaves it with zero rows -- and zero rows has
-- always meant "unrestricted". A CI token pinned to one repository therefore
-- silently widened to every repository in the instance the moment that
-- repository was deleted.
--
-- The fix is an explicit restriction marker on the token itself: once any
-- `api_token_repositories` row has existed for a token, the token is
-- restricted for the rest of its life, and an empty allowlist denies all
-- repositories instead of falling open. Deleting repositories can now only
-- ever NARROW a token, never widen it.
ALTER TABLE api_tokens
    ADD COLUMN repository_restricted BOOLEAN NOT NULL DEFAULT false;

-- Backfill: every token with at least one live join row is restricted today.
-- Tokens whose rows already cascaded away are indistinguishable from
-- never-restricted tokens and are left as-is.
UPDATE api_tokens t
SET repository_restricted = true
WHERE EXISTS (
    SELECT 1 FROM api_token_repositories atr WHERE atr.token_id = t.id
);

-- Keep the marker honest regardless of which code path pins rows: any
-- insert into the join table means the token carries an explicit repository
-- allow-list. The marker is deliberately never cleared -- removing rows
-- (a repository deletion cascade) narrows the allow-list, it does not
-- un-restrict the token.
CREATE FUNCTION mark_api_token_repository_restricted() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE api_tokens SET repository_restricted = true WHERE id = NEW.token_id;
    RETURN NULL;
END;
$$;

CREATE TRIGGER api_token_repositories_marks_restricted
AFTER INSERT ON api_token_repositories
FOR EACH ROW EXECUTE FUNCTION mark_api_token_repository_restricted();

COMMENT ON COLUMN api_tokens.repository_restricted IS
    'True once any api_token_repositories row has existed for this token. A restricted token whose allow-list is empty (every repository deleted) denies all repositories; it never falls open (#4228).';
