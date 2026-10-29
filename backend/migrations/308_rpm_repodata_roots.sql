-- #4544: precomputed hosted RPM repodata. One row per hosted repository and
-- repodata root: whether the root changed since its last build
-- (`dirty_since`), and the revision the background builder last stored under
-- `repodata/<repo>/<root>/<rev>/` in the repository's storage.
--
-- No foreign key to `repositories`: when a repository is deleted its rows
-- outlive it so the builder can still find (by `storage_backend` /
-- `storage_path`) and delete the stored revisions, then the rows.
CREATE TABLE rpm_repodata_roots (
    repository_id uuid NOT NULL,
    -- The first `repodata_depth` path segments of the root's packages, ''
    -- at depth zero (the same derivation as migration 247's layout).
    root text NOT NULL,
    -- Set (only when NULL) by the triggers below on any change to the
    -- root's packages; cleared by the builder when it starts a build.
    dirty_since timestamptz,
    -- Build again at this time even if nothing changed: an incomplete build
    -- (a package header could not be read back, #3801), a heal marker that
    -- falls due, or the back-off after a failed build.
    retry_at timestamptz,
    -- Last revision number handed out. Revisions are never reused, so a
    -- failed build's objects cannot be mistaken for a later build's.
    next_revision bigint NOT NULL DEFAULT 0,
    built_revision bigint,
    -- The revision served before `built_revision`, kept for clients that
    -- are mid-refresh; older ones are deleted.
    previous_revision bigint,
    -- Revisions below this are deleted from storage.
    gc_floor bigint NOT NULL DEFAULT 1,
    -- Fingerprint (live `.rpm` count, MAX(updated_at)) of the snapshot the
    -- current revision was built from.
    built_count bigint,
    built_latest timestamptz,
    built_at timestamptz,
    -- The current revision's repomd.xml (about 2 KB): served and signed
    -- without a storage read.
    built_repomd bytea,
    -- Byte sizes of the stored documents, by file name.
    built_sizes jsonb,
    storage_backend text,
    storage_path text,
    last_error text,
    PRIMARY KEY (repository_id, root)
);

CREATE INDEX rpm_repodata_roots_pending_idx ON rpm_repodata_roots (dirty_since)
    WHERE dirty_since IS NOT NULL OR retry_at IS NOT NULL;

-- The repodata root of a package path in `repo_id`, as migration 247 lays
-- it out: the first `repodata_depth` segments, or '' at depth zero.
CREATE FUNCTION ak_rpm_repodata_root(repo_id uuid, path text) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN d = 0 THEN ''
                ELSE array_to_string((string_to_array(path, '/'))[1:d], '/') END
    FROM (SELECT ak_rpm_repodata_depth(repo_id) AS d) depth
$$;

-- Mark the root of `path` in `repo_id` dirty. Only hosted RPM repositories
-- are tracked. A root that is already dirty is only read, never written, so
-- the inserts of a bulk import into one root do not queue on its row lock.
CREATE FUNCTION ak_rpm_repodata_mark_dirty(repo_id uuid, path text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    r text;
BEGIN
    IF path IS NULL OR path NOT LIKE '%.rpm' THEN RETURN; END IF;
    IF NOT EXISTS (SELECT 1 FROM repositories
                   WHERE id = repo_id AND format = 'rpm' AND repo_type = 'local') THEN
        RETURN;
    END IF;
    r := ak_rpm_repodata_root(repo_id, path);
    IF EXISTS (SELECT 1 FROM rpm_repodata_roots
               WHERE repository_id = repo_id AND root = r AND dirty_since IS NOT NULL) THEN
        RETURN;
    END IF;
    INSERT INTO rpm_repodata_roots (repository_id, root, dirty_since)
    VALUES (repo_id, r, clock_timestamp())
    ON CONFLICT (repository_id, root) DO UPDATE SET dirty_since = clock_timestamp()
        WHERE rpm_repodata_roots.dirty_since IS NULL;
END
$$;

CREATE FUNCTION ak_rpm_repodata_artifact_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        PERFORM ak_rpm_repodata_mark_dirty(OLD.repository_id, OLD.path);
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        IF TG_OP = 'INSERT' OR OLD.repository_id <> NEW.repository_id
           OR OLD.path <> NEW.path THEN
            PERFORM ak_rpm_repodata_mark_dirty(NEW.repository_id, NEW.path);
        END IF;
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER rpm_repodata_artifact_inserted
AFTER INSERT ON artifacts
FOR EACH ROW WHEN (NEW.path LIKE '%.rpm')
EXECUTE FUNCTION ak_rpm_repodata_artifact_changed();

-- Only the columns a repodata document is built from; download counters and
-- scan or quarantine bookkeeping do not dirty a root.
CREATE TRIGGER rpm_repodata_artifact_updated
AFTER UPDATE OF repository_id, path, name, version, size_bytes, checksum_sha256,
    storage_key, updated_at, is_deleted ON artifacts
FOR EACH ROW WHEN ((OLD.path LIKE '%.rpm' OR NEW.path LIKE '%.rpm') AND (
    OLD.repository_id, OLD.path, OLD.name, OLD.version, OLD.size_bytes,
    OLD.checksum_sha256, OLD.storage_key, OLD.updated_at, OLD.is_deleted)
    IS DISTINCT FROM (
    NEW.repository_id, NEW.path, NEW.name, NEW.version, NEW.size_bytes,
    NEW.checksum_sha256, NEW.storage_key, NEW.updated_at, NEW.is_deleted))
EXECUTE FUNCTION ak_rpm_repodata_artifact_changed();

CREATE TRIGGER rpm_repodata_artifact_deleted
AFTER DELETE ON artifacts
FOR EACH ROW WHEN (OLD.path LIKE '%.rpm')
EXECUTE FUNCTION ak_rpm_repodata_artifact_changed();

-- Metadata feeds primary.xml (dependencies, descriptions, file lists). The
-- repodata heal's own bookkeeping (#3801) is ignored exactly as migration
-- 247 ignores it: the builder heals before it builds, so those writes are
-- already in the build that made them.
CREATE FUNCTION ak_rpm_repodata_metadata_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    artifact uuid;
    repo uuid;
    p text;
BEGIN
    IF TG_OP = 'DELETE' THEN artifact := OLD.artifact_id;
    ELSE artifact := NEW.artifact_id;
    END IF;
    IF TG_OP = 'INSERT' AND ak_rpm_depth_heal_bookkeeping_only(NULL, NEW.metadata) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.artifact_id = OLD.artifact_id
       AND NEW.format IS NOT DISTINCT FROM OLD.format
       AND NEW.properties IS NOT DISTINCT FROM OLD.properties
       AND ak_rpm_depth_heal_bookkeeping_only(OLD.metadata, NEW.metadata) THEN
        RETURN NULL;
    END IF;
    SELECT a.repository_id, a.path INTO repo, p FROM artifacts a WHERE a.id = artifact;
    IF FOUND THEN
        PERFORM ak_rpm_repodata_mark_dirty(repo, p);
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER rpm_repodata_metadata_changed
AFTER INSERT OR UPDATE OR DELETE ON artifact_metadata
FOR EACH ROW EXECUTE FUNCTION ak_rpm_repodata_metadata_changed();

-- Every populated root of an existing hosted RPM repository starts dirty, so
-- the builder builds it after the upgrade; until then it renders on request
-- as before.
INSERT INTO rpm_repodata_roots (repository_id, root, dirty_since)
SELECT DISTINCT a.repository_id,
       CASE WHEN COALESCE(c.value::integer, 0) = 0 THEN ''
            ELSE array_to_string((string_to_array(a.path, '/'))[1:c.value::integer], '/')
       END,
       now()
FROM artifacts a
JOIN repositories r ON r.id = a.repository_id
LEFT JOIN repository_config c ON c.repository_id = r.id AND c.key = 'repodata_depth'
WHERE r.format = 'rpm' AND r.repo_type = 'local'
  AND NOT a.is_deleted AND a.path LIKE '%.rpm'
ON CONFLICT DO NOTHING;
