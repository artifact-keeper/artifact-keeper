-- Repository visibility axis: public / internal / private.
--
-- Access was previously a single boolean, `repositories.is_public`, giving two
-- states: anonymous-readable, or grant-holders-only. There was no way to say
-- "readable by every authenticated principal, but never anonymously" -- the
-- state most internal repositories on a corporate instance actually need.
--
-- The server-wide guest-access flag (#850) is not a substitute for it, and using
-- it as one is lossy: `coerce_visibility_for_create`/`_for_update` silently
-- rewrite a requested `public` to `private` when guest access is disabled, so
-- the operator's intent is destroyed rather than reinterpreted, and re-enabling
-- guest access does not restore it. That coercion is UNCHANGED by this
-- migration -- the point here is that a state worth asking for should not have
-- to be approximated by a server-wide switch, not that the switch is being
-- fixed. An operator who wants "readable by everyone logged in" now declares it
-- on the repository.
--
-- `visibility` is the authoritative field from here on. `is_public` is KEPT as a
-- real column -- not a view and not a generated column, both of which would stop
-- the existing write paths and the out-of-tree Terraform provider from working --
-- and is held equal to `visibility = 'public'` by a trigger added in this same
-- migration.
--
-- Backfill is exactly access-preserving: no repository's read audience changes
-- at upgrade time, and no repository becomes `internal` automatically. Rows that
-- were meant to be internal but were coerced to `is_public = false` by the
-- guest-access rule above are indistinguishable from ordinary private
-- repositories; they are recovered by a documented operator review step, not
-- here.

CREATE TYPE repository_visibility AS ENUM ('public', 'internal', 'private');

ALTER TABLE repositories
    ADD COLUMN visibility repository_visibility;

UPDATE repositories
SET visibility = CASE WHEN is_public THEN 'public'::repository_visibility
                      ELSE 'private'::repository_visibility
                 END;

-- NOT NULL, but deliberately NO DEFAULT. The column is filled by the BEFORE
-- INSERT trigger below, which runs before constraints are checked, so an INSERT
-- that omits `visibility` still lands NOT NULL.
--
-- A `DEFAULT 'private'` here would be the obvious choice and is the wrong one:
-- it makes "the caller did not supply a visibility" indistinguishable from "the
-- caller asked for private", and the trigger then has to GUESS which one a
-- legacy `is_public = true` insert meant. Guessing resolves toward `public`,
-- i.e. toward the wider state. Leaving the column NULL until the trigger fills
-- it turns that guess into a fact the trigger can read.
ALTER TABLE repositories
    ALTER COLUMN visibility SET NOT NULL;

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
--   INSERT  If `visibility` was supplied (i.e. is not NULL -- the column has no
--           default, see above), it is authoritative and `is_public` is derived
--           from it; an `is_public = true` contradicting it is REFUSED, not
--           resolved. If it was not supplied, `visibility` is derived from
--           `is_public`, which is the legacy insert path.
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
        IF NEW.visibility IS NULL THEN
            -- Legacy insert: the caller supplied no visibility at all, so
            -- `is_public` is authoritative. `is_public` has its own DEFAULT
            -- false, so an insert naming neither column lands `private`.
            NEW.visibility := CASE WHEN NEW.is_public
                                   THEN 'public'::repository_visibility
                                   ELSE 'private'::repository_visibility
                              END;
        ELSE
            -- Visibility was supplied and is authoritative. An `is_public =
            -- true` alongside a non-public visibility is a genuine
            -- contradiction: `is_public` defaults to false, so a true here was
            -- written deliberately. Refuse it rather than resolving it -- every
            -- resolution of this pair picks a state one of the two fields says
            -- is wrong, and the tempting one (trust `is_public`) picks the
            -- WIDER state. This mirrors the API layer's 400
            -- (`reject_contradictory_visibility`) and satisfies D4's rule that
            -- contradictory input is rejected, never silently resolved.
            --
            -- The mirror-image pair (`is_public = false` with `visibility =
            -- 'public'`) is NOT refused, and must not be: false is also what
            -- the column defaults to, so refusing it would break every modern
            -- client that writes `visibility = 'public'` and leaves `is_public`
            -- alone. It is resolved in favour of `visibility`, as intended.
            IF NEW.is_public AND NEW.visibility <> 'public'::repository_visibility THEN
                RAISE EXCEPTION
                    'contradictory repository visibility on insert: is_public = true '
                    'with visibility = %. Set one or the other; is_public is a '
                    'derived mirror of (visibility = ''public'').', NEW.visibility
                    USING ERRCODE = 'check_violation';
            END IF;
            NEW.is_public := (NEW.visibility = 'public');
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
