-- #4216: layout admission must cover direct imports, restores, promotions and
-- chunk completion as well as native uploads. Like the usage ledger (182),
-- artifacts is the persistence boundary shared by all these writers.
CREATE FUNCTION ak_rpm_repodata_depth(repo_id uuid) RETURNS integer
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((SELECT value::integer FROM repository_config
                    WHERE repository_id = repo_id AND key = 'repodata_depth'), 0)
$$;

CREATE FUNCTION ak_rpm_depth_eligible(repo_id uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM repositories r WHERE r.id = repo_id
          AND r.format = 'rpm' AND r.repo_type = 'local'
          AND (r.format_key IS NULL OR r.format_key = 'rpm')
          AND NOT r.curation_enabled
          AND r.curation_source_repo_id IS NULL AND r.curation_target_repo_id IS NULL
          AND r.active_publication_id IS NULL
          AND NOT EXISTS (SELECT 1 FROM repository_versions WHERE repository_id = r.id)
          AND NOT EXISTS (SELECT 1 FROM virtual_repo_members WHERE member_repo_id = r.id)
          AND NOT EXISTS (SELECT 1 FROM repositories
                          WHERE curation_source_repo_id = r.id OR curation_target_repo_id = r.id)
    )
$$;

CREATE FUNCTION ak_rpm_depth_config_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    repo_id uuid;
    requested integer;
    previous integer;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.key <> 'repodata_depth' THEN RETURN OLD; END IF;
        repo_id := OLD.repository_id;
        -- Cascading deletion has already removed the parent repository.
        IF NOT EXISTS (SELECT 1 FROM repositories WHERE id = repo_id) THEN
            RETURN OLD;
        END IF;
        requested := 0;
    ELSE
        IF TG_OP = 'UPDATE' AND OLD.key = 'repodata_depth'
           AND (OLD.key <> NEW.key OR OLD.repository_id <> NEW.repository_id) THEN
            RAISE EXCEPTION 'AK_RPM_DEPTH_UNSUPPORTED';
        END IF;
        IF NEW.key <> 'repodata_depth' THEN RETURN NEW; END IF;
        repo_id := NEW.repository_id;
        IF NEW.value IS NULL OR NEW.value !~ '^[0-9]{1,4}$' THEN
            RAISE EXCEPTION 'AK_RPM_DEPTH_RANGE';
        END IF;
        requested := NEW.value::integer;
        IF requested > 1023 THEN RAISE EXCEPTION 'AK_RPM_DEPTH_RANGE'; END IF;
    END IF;
    -- Config writers never take a usage-ledger lock. Artifact writers may
    -- already hold that lock; they only share this independent layout lock.
    IF NOT pg_try_advisory_xact_lock(hashtextextended('rpm-depth:' || repo_id::text, 0)) THEN
        RAISE EXCEPTION 'AK_RPM_DEPTH_BUSY';
    END IF;
    previous := ak_rpm_repodata_depth(repo_id);
    IF requested = previous THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;
    IF requested > 0 AND NOT ak_rpm_depth_eligible(repo_id) THEN
        RAISE EXCEPTION 'AK_RPM_DEPTH_UNSUPPORTED';
    END IF;
    IF EXISTS (SELECT 1 FROM artifacts WHERE repository_id = repo_id) THEN
        RAISE EXCEPTION 'AK_RPM_DEPTH_POPULATED';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END
$$;
CREATE TRIGGER rpm_depth_config_guard
BEFORE INSERT OR UPDATE OR DELETE ON repository_config
FOR EACH ROW EXECUTE FUNCTION ak_rpm_depth_config_guard();

CREATE FUNCTION ak_rpm_depth_artifact_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    depth integer;
    parts text[];
    part text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM repositories WHERE id = NEW.repository_id AND format = 'rpm') THEN
        RETURN NEW;
    END IF;
    -- Even depth-zero RPM inserts must participate: an admin enabling depth
    -- on an empty repo must not race an upload that read the old layout.
    IF NOT pg_try_advisory_xact_lock_shared(
        hashtextextended('rpm-depth:' || NEW.repository_id::text, 0)) THEN
        RAISE EXCEPTION 'AK_RPM_DEPTH_BUSY';
    END IF;
    depth := ak_rpm_repodata_depth(NEW.repository_id);
    IF depth = 0 THEN RETURN NEW; END IF;
    parts := string_to_array(NEW.path, '/');
    IF octet_length(NEW.path) > 2048 OR NEW.path = ''
       OR array_length(parts, 1) <= depth
       OR NEW.path ~ '[[:cntrl:]]' OR position(chr(92) IN NEW.path) > 0
       OR lower(NEW.path) ~ '%(2e|2f|5c)' OR parts[1] ~ '^@[0-9]+$' THEN
        RAISE EXCEPTION 'AK_RPM_DEPTH_PATH';
    END IF;
    FOREACH part IN ARRAY parts LOOP
        -- Match Rust str::trim independently of the database collation.
        IF part IN ('', '.', '..', 'repodata')
           OR btrim(part, U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000') <> part THEN
            RAISE EXCEPTION 'AK_RPM_DEPTH_PATH';
        END IF;
    END LOOP;
    -- The old RPM basename storage key cannot represent identical NEVRA in
    -- two roots. CAS is already used by generic, chunked and import writers.
    IF NEW.checksum_sha256 !~ '^[0-9a-f]{64}$'
       OR NEW.storage_key <> substr(NEW.checksum_sha256, 1, 2) || '/' ||
          substr(NEW.checksum_sha256, 3, 2) || '/' || NEW.checksum_sha256 THEN
        RAISE EXCEPTION 'AK_RPM_DEPTH_STORAGE';
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END
$$;
CREATE TRIGGER rpm_depth_artifact_guard
BEFORE INSERT OR UPDATE ON artifacts
FOR EACH ROW EXECUTE FUNCTION ak_rpm_depth_artifact_guard();

-- Both ends are protected: enabling depth checks existing dependencies, and
-- creating a dependency checks the depth under the same transaction lock.
CREATE FUNCTION ak_rpm_depth_dependency_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    repo_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'virtual_repo_members' THEN repo_id := NEW.member_repo_id;
    ELSE repo_id := NEW.repository_id;
    END IF;
    IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('rpm-depth:' || repo_id::text, 0)) THEN
        RAISE EXCEPTION 'AK_RPM_DEPTH_BUSY';
    END IF;
    IF ak_rpm_repodata_depth(repo_id) > 0 THEN
        RAISE EXCEPTION 'AK_RPM_DEPTH_UNSUPPORTED';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER rpm_depth_virtual_guard
BEFORE INSERT OR UPDATE OF member_repo_id ON virtual_repo_members
FOR EACH ROW EXECUTE FUNCTION ak_rpm_depth_dependency_guard();
CREATE TRIGGER rpm_depth_version_guard
BEFORE INSERT OR UPDATE OF repository_id ON repository_versions
FOR EACH ROW EXECUTE FUNCTION ak_rpm_depth_dependency_guard();

CREATE FUNCTION ak_rpm_depth_repository_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    repo_id uuid;
BEGIN
    -- Lock referenced curation repositories in UUID order. A failed try-lock
    -- aborts rather than forming a cycle with a layout update or another move.
    FOR repo_id IN SELECT DISTINCT id FROM unnest(ARRAY[
        NEW.curation_source_repo_id, NEW.curation_target_repo_id]) id
        WHERE id IS NOT NULL ORDER BY id LOOP
        IF NOT pg_try_advisory_xact_lock_shared(
            hashtextextended('rpm-depth:' || repo_id::text, 0)) THEN
            RAISE EXCEPTION 'AK_RPM_DEPTH_BUSY';
        END IF;
        IF ak_rpm_repodata_depth(repo_id) > 0 THEN
            RAISE EXCEPTION 'AK_RPM_DEPTH_UNSUPPORTED';
        END IF;
    END LOOP;
    IF NEW.format <> 'rpm' OR (NEW.format_key IS NOT NULL AND NEW.format_key <> 'rpm') OR (
        NEW.curation_enabled OR NEW.curation_source_repo_id IS NOT NULL
        OR NEW.curation_target_repo_id IS NOT NULL OR NEW.active_publication_id IS NOT NULL
        OR NEW.repo_type <> 'local'
    ) THEN
        -- UPDATE already holds the repository row; never wait in the inverse
        -- row -> layout order while a config writer holds layout -> row.
        IF NOT pg_try_advisory_xact_lock_shared(
            hashtextextended('rpm-depth:' || NEW.id::text, 0)) THEN
            RAISE EXCEPTION 'AK_RPM_DEPTH_BUSY';
        END IF;
        IF ak_rpm_repodata_depth(NEW.id) > 0 THEN
            RAISE EXCEPTION 'AK_RPM_DEPTH_UNSUPPORTED';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER rpm_depth_repository_guard
BEFORE INSERT OR UPDATE OF curation_enabled, curation_source_repo_id, curation_target_repo_id,
    active_publication_id, repo_type, format, format_key ON repositories
FOR EACH ROW EXECUTE FUNCTION ak_rpm_depth_repository_guard();

CREATE FUNCTION ak_rpm_depth_metadata_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    artifact uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN artifact := OLD.artifact_id;
    ELSE artifact := NEW.artifact_id;
    END IF;
    UPDATE artifacts SET updated_at = clock_timestamp()
        WHERE id = artifact AND ak_rpm_repodata_depth(repository_id) > 0;
    RETURN NULL;
END
$$;
CREATE TRIGGER rpm_depth_metadata_changed
AFTER INSERT OR UPDATE OR DELETE ON artifact_metadata
FOR EACH ROW EXECUTE FUNCTION ak_rpm_depth_metadata_changed();
