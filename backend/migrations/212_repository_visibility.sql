-- Repository visibility axis: public / internal / private.
--
-- Access was previously a single boolean, `repositories.is_public`, giving two
-- states: anonymous-readable, or grant-holders-only. There was no way to say
-- "readable by every authenticated principal, but never anonymously" -- the
-- state most internal repositories on a corporate instance actually need.
--
-- The server-wide guest-access flag (#850) was not a substitute for it, and was
-- actively lossy: `coerce_is_public_for_create`/`_for_update` silently rewrote a
-- requested `is_public = true` to `false` when guest access was disabled, so the
-- operator's intent was destroyed rather than reinterpreted, and re-enabling
-- guest access did not restore it.
--
-- `visibility` is the authoritative field from here on. `is_public` is KEPT as a
-- real column -- not a view and not a generated column, both of which would stop
-- the existing write paths and the out-of-tree Terraform provider from working --
-- and is held equal to `visibility = 'public'` by a trigger added in this same
-- migration.
--
-- Backfill is exactly access-preserving: no repository's read audience changes
-- at upgrade time, and no repository becomes `internal` automatically. Rows that
-- were meant to be internal but had already been coerced to `is_public = false`
-- by the old code are indistinguishable from ordinary private repositories; they
-- are recovered by a documented operator review step, not here.

CREATE TYPE repository_visibility AS ENUM ('public', 'internal', 'private');

ALTER TABLE repositories
    ADD COLUMN visibility repository_visibility;

UPDATE repositories
SET visibility = CASE WHEN is_public THEN 'public'::repository_visibility
                      ELSE 'private'::repository_visibility
                 END;

ALTER TABLE repositories
    ALTER COLUMN visibility SET NOT NULL,
    ALTER COLUMN visibility SET DEFAULT 'private'::repository_visibility;

COMMENT ON COLUMN repositories.visibility IS
    'Baseline read audience: public = anonymous, internal = any authenticated '
    'principal, private = grant holders only. Confers READ only -- never write, '
    'delete, or admin. Authoritative; is_public mirrors (visibility = ''public'').';

COMMENT ON COLUMN repositories.is_public IS
    'DEPRECATED mirror of (visibility = ''public''), kept for API and Terraform '
    'provider compatibility. Maintained by ak_repositories_sync_visibility; do '
    'not write both columns in one statement expecting independent effects.';

-- Listing, search, and the OCI/native read gates all filter on visibility, and
-- `private` rows dominate on a typical instance. Index the two states that are
-- actually selected for.
CREATE INDEX IF NOT EXISTS idx_repositories_visibility
    ON repositories (visibility)
    WHERE visibility <> 'private';

-- ---------------------------------------------------------------------------
-- Keep `is_public` and `visibility` consistent, in the database rather than in
-- application code, so that no write path -- including direct SQL, the older
-- generated SDK, and the out-of-tree Terraform provider -- can bypass it.
--
-- Resolution rules:
--
--   INSERT  If `visibility` was set to anything other than the column default
--           (`private`), it is authoritative and `is_public` is derived from
--           it. Otherwise `visibility` is derived from `is_public`, which is
--           the legacy insert path. A BEFORE trigger cannot distinguish "set
--           explicitly to private" from "defaulted to private", but both mean
--           the same thing whenever `is_public` is false, and a legacy client
--           setting `is_public = true` can only have defaulted the visibility.
--
--   UPDATE  Whichever column the statement actually changed is authoritative.
--           When a statement changes both, `visibility` wins, because that is
--           the modern client writing the authoritative field.
--
-- Deriving from the column that CHANGED, rather than from the column's value,
-- is what makes an `internal` repository safe under a legacy full-object write.
-- An `internal` repository already carries `is_public = false`, so a legacy
-- client that rewrites `is_public = false` on every update -- which is what the
-- Terraform provider does, since it declares the field and sends its whole
-- desired state -- produces no column change here, and `visibility` is left
-- alone. Verified idempotent across repeated writes.
--
-- The only path that lands on `private` from a legacy write is a genuine
-- `true -> false` transition, which can only happen on a repository that was
-- `public`. That narrowing is legitimate and is what the legacy field means.
--
-- A value-based rule (`is_public = false` therefore `private`) would instead
-- silently narrow every `internal` repository on each such write, so do not
-- "simplify" this trigger into one.
--
-- The corollary binds the application layer: the repository update path must
-- write `visibility` ONLY when the caller actually supplied it. If it derives
-- and writes `visibility` from a legacy `is_public` field, the first branch
-- below takes over and the protection above is lost.
CREATE OR REPLACE FUNCTION ak_repositories_sync_visibility() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.visibility IS DISTINCT FROM 'private'::repository_visibility THEN
            NEW.is_public := (NEW.visibility = 'public');
        ELSE
            NEW.visibility := CASE WHEN NEW.is_public
                                   THEN 'public'::repository_visibility
                                   ELSE 'private'::repository_visibility
                              END;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.visibility IS DISTINCT FROM NEW.visibility THEN
        -- `visibility` changed: authoritative, whether or not `is_public` also
        -- changed in the same statement.
        NEW.is_public := (NEW.visibility = 'public');
    ELSIF OLD.is_public IS DISTINCT FROM NEW.is_public THEN
        NEW.visibility := CASE WHEN NEW.is_public
                               THEN 'public'::repository_visibility
                               ELSE 'private'::repository_visibility
                          END;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_repositories_sync_visibility ON repositories;
CREATE TRIGGER ak_repositories_sync_visibility
    BEFORE INSERT OR UPDATE ON repositories
    FOR EACH ROW
    EXECUTE FUNCTION ak_repositories_sync_visibility();

-- Final invariant. CHECK runs after the BEFORE trigger has reconciled the two
-- columns, so this can only fire if the trigger is dropped or its logic breaks
-- -- which is exactly when a silent divergence between the authorization field
-- and the field legacy clients read would be most dangerous.
ALTER TABLE repositories
    ADD CONSTRAINT repositories_is_public_mirrors_visibility
    CHECK (is_public = (visibility = 'public'));

-- ---------------------------------------------------------------------------
-- Cache invalidation must fire on a visibility change.
--
-- The repository-changed NOTIFY trigger from migration 142 lists the columns
-- that affect cached repository metadata, and `repo_cache` in the repo
-- visibility middleware now carries `visibility` instead of `is_public`.
-- Without adding it here, narrowing a repository from `internal` to `private`
-- would keep being served under the OLD access decision on every instance
-- until the cache TTL expired -- a stale-authorization window, not merely a
-- stale-metadata one.
--
-- `is_public` is retained in the clause. It is redundant while the sync trigger
-- above holds (the two columns always change together), but keeping it means a
-- future change to that trigger cannot quietly disable invalidation.
DROP TRIGGER IF EXISTS ak_repository_changed_notify ON repositories;
CREATE TRIGGER ak_repository_changed_notify
    AFTER UPDATE ON repositories
    FOR EACH ROW
    WHEN (
        OLD.key IS DISTINCT FROM NEW.key
        OR OLD.format IS DISTINCT FROM NEW.format
        OR OLD.repo_type IS DISTINCT FROM NEW.repo_type
        OR OLD.upstream_url IS DISTINCT FROM NEW.upstream_url
        OR OLD.storage_backend IS DISTINCT FROM NEW.storage_backend
        OR OLD.storage_path IS DISTINCT FROM NEW.storage_path
        OR OLD.is_public IS DISTINCT FROM NEW.is_public
        OR OLD.visibility IS DISTINCT FROM NEW.visibility
    )
    EXECUTE FUNCTION ak_notify_repository_changed();
