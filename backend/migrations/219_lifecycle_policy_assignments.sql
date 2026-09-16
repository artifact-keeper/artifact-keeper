-- Preserve historical scopes before changing the default for new policies.
ALTER TABLE lifecycle_policies
    ADD COLUMN applies_to_all BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE lifecycle_policy_repositories (
    policy_id UUID NOT NULL REFERENCES lifecycle_policies(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, repository_id)
);
CREATE INDEX idx_lifecycle_policy_repositories_repo
    ON lifecycle_policy_repositories(repository_id);

UPDATE lifecycle_policies SET applies_to_all = true WHERE repository_id IS NULL;
INSERT INTO lifecycle_policy_repositories (policy_id, repository_id)
    SELECT id, repository_id FROM lifecycle_policies WHERE repository_id IS NOT NULL;

-- The legacy column is a singleton projection, not ownership or global scope.
ALTER TABLE lifecycle_policies
    DROP CONSTRAINT lifecycle_policies_repository_id_fkey,
    ADD CONSTRAINT lifecycle_policies_repository_id_fkey
        FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE SET NULL;

-- This also handles repository deletion's FK cascade: a shared policy survives
-- and its legacy projection reflects the remaining assignments in the same tx.
CREATE FUNCTION sync_lifecycle_repository_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    affected_id UUID;
BEGIN
    FOR affected_id IN
        SELECT DISTINCT id FROM unnest(ARRAY[
            CASE WHEN TG_OP <> 'INSERT' THEN OLD.policy_id END,
            CASE WHEN TG_OP <> 'DELETE' THEN NEW.policy_id END
        ]) AS ids(id) WHERE id IS NOT NULL ORDER BY id
    LOOP
        PERFORM 1 FROM lifecycle_policies WHERE id = affected_id FOR UPDATE;
        UPDATE lifecycle_policies
        SET repository_id = (
            SELECT CASE WHEN count(*) = 1 THEN min(repository_id::text)::uuid END
            FROM lifecycle_policy_repositories WHERE policy_id = affected_id
        ), updated_at = NOW()
        WHERE id = affected_id;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE TRIGGER lifecycle_repository_projection
AFTER INSERT OR UPDATE OR DELETE ON lifecycle_policy_repositories
FOR EACH ROW EXECUTE FUNCTION sync_lifecycle_repository_projection();

COMMENT ON COLUMN lifecycle_policies.repository_id IS
    'Deprecated singleton projection. NULL does not imply global; use applies_to_all and lifecycle_policy_repositories.';
COMMENT ON COLUMN lifecycle_policies.applies_to_all IS
    'Explicit opt-in to all current and future repositories. False with no assignments is dormant.';
