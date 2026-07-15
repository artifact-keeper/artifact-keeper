-- Repository attribution for row-less Maven flat-key objects (#2574, #2584).
--
-- #2504 closed a cross-tenant read hole on shared cloud namespaces
-- (S3/GCS/Azure) by refusing to serve any bare `maven/{path}` key that is not
-- anchored to an artifact row scoped to the requesting repository. That also
-- broke legitimate reads of *row-less* legacy objects that never had a row of
-- their own -- GAV-grouped companion files (`.pom`, `.module`, `-sources.jar`),
-- verbatim `maven-metadata.xml`, and stored checksum sidecars -- because a
-- row-less object on a flat namespace carries no inherent repository
-- attribution, so a catalog lookup alone cannot tell "my legacy file" from
-- "another tenant's".
--
-- This table records, per flat storage key, the single repository that owns the
-- physical object, derived entirely from the catalog (no bucket/storage
-- listing). A key is attributed only when the database proves a single owner;
-- ambiguous (multi-owner) keys and truly-orphan objects are intentionally left
-- UNATTRIBUTED (no row) so they stay 404 for every tenant on cloud backends.
-- Reads consult this table (plus live rows) to serve a legacy object only to
-- its genuine owner; writes consult it to refuse cross-repository overwrites and
-- to claim previously-unowned keys first-writer-wins.
CREATE TABLE IF NOT EXISTS maven_flat_object_owner (
    storage_key   TEXT PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    source        TEXT NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_maven_flat_object_owner_repository_id
    ON maven_flat_object_owner (repository_id);

-- ---------------------------------------------------------------------------
-- Backfill. Cloud repositories only (filesystem physically isolates each
-- repository's key space, so those keys are never ambiguous and need no row).
-- LIVE rows only (is_deleted = false). Single-owner only
-- (GROUP BY ... HAVING COUNT(DISTINCT repository_id) = 1): a key referenced by
-- more than one repository is ambiguous and stays unattributed.
-- ---------------------------------------------------------------------------

-- (1) Primary artifact rows whose storage_key is a flat maven key.
INSERT INTO maven_flat_object_owner (storage_key, repository_id, source)
SELECT a.storage_key,
       MIN(a.repository_id::text)::uuid,
       'primary_row'
FROM artifacts a
JOIN repositories r ON r.id = a.repository_id
WHERE a.storage_key LIKE 'maven/%'
  AND a.is_deleted = false
  AND r.storage_backend <> 'filesystem'
GROUP BY a.storage_key
HAVING COUNT(DISTINCT a.repository_id) = 1
ON CONFLICT (storage_key) DO NOTHING;

-- (2) Companion files recorded in a parent artifact's metadata `files[]` array
--     (legacy GAV-grouped uploads whose companions have no row of their own).
INSERT INTO maven_flat_object_owner (storage_key, repository_id, source)
SELECT elem->>'storage_key' AS storage_key,
       MIN(a.repository_id::text)::uuid,
       'metadata_files'
FROM artifact_metadata am
JOIN artifacts a ON a.id = am.artifact_id
JOIN repositories r ON r.id = a.repository_id
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(am.metadata->'files') = 'array'
         THEN am.metadata->'files'
         ELSE '[]'::jsonb END
) AS elem
WHERE a.is_deleted = false
  AND r.storage_backend <> 'filesystem'
  AND elem->>'storage_key' LIKE 'maven/%'
GROUP BY elem->>'storage_key'
HAVING COUNT(DISTINCT a.repository_id) = 1
ON CONFLICT (storage_key) DO NOTHING;

-- (3) Derived checksum sidecars for every attributed base key: `.sha1`, `.md5`,
--     `.sha256`, `.asc` inherit the base object's owner.
INSERT INTO maven_flat_object_owner (storage_key, repository_id, source)
SELECT o.storage_key || s.suffix,
       o.repository_id,
       'derived_checksum'
FROM maven_flat_object_owner o
CROSS JOIN (VALUES ('.sha1'), ('.md5'), ('.sha256'), ('.asc')) AS s(suffix)
WHERE o.source IN ('primary_row', 'metadata_files')
  AND o.storage_key NOT LIKE '%.sha1'
  AND o.storage_key NOT LIKE '%.md5'
  AND o.storage_key NOT LIKE '%.sha256'
  AND o.storage_key NOT LIKE '%.asc'
ON CONFLICT (storage_key) DO NOTHING;

-- (4a) Artifact-level `maven-metadata.xml` rollup: a `{groupPath}/{artifactId}`
--      directory owned entirely by one repository owns its `maven-metadata.xml`.
--      The artifactId directory is the storage key with the last two path
--      segments (version dir + filename) stripped.
INSERT INTO maven_flat_object_owner (storage_key, repository_id, source)
SELECT dir.artifact_dir || '/maven-metadata.xml',
       dir.repository_id,
       'metadata_rollup'
FROM (
    SELECT regexp_replace(a.storage_key, '/[^/]*/[^/]*$', '') AS artifact_dir,
           MIN(a.repository_id::text)::uuid AS repository_id
    FROM artifacts a
    JOIN repositories r ON r.id = a.repository_id
    WHERE a.storage_key LIKE 'maven/%'
      AND a.is_deleted = false
      AND r.storage_backend <> 'filesystem'
    GROUP BY regexp_replace(a.storage_key, '/[^/]*/[^/]*$', '')
    HAVING COUNT(DISTINCT a.repository_id) = 1
) dir
WHERE dir.artifact_dir LIKE 'maven/%/%'
ON CONFLICT (storage_key) DO NOTHING;

-- (4b) SNAPSHOT-level `maven-metadata.xml` rollup: a `{groupPath}/{artifactId}/
--      {version}-SNAPSHOT` directory owned entirely by one repository owns its
--      `maven-metadata.xml`. The GAV directory is the storage key with the last
--      path segment (filename) stripped.
INSERT INTO maven_flat_object_owner (storage_key, repository_id, source)
SELECT dir.gav_dir || '/maven-metadata.xml',
       dir.repository_id,
       'metadata_rollup'
FROM (
    SELECT regexp_replace(a.storage_key, '/[^/]*$', '') AS gav_dir,
           MIN(a.repository_id::text)::uuid AS repository_id
    FROM artifacts a
    JOIN repositories r ON r.id = a.repository_id
    WHERE a.storage_key LIKE 'maven/%-SNAPSHOT/%'
      AND a.is_deleted = false
      AND r.storage_backend <> 'filesystem'
    GROUP BY regexp_replace(a.storage_key, '/[^/]*$', '')
    HAVING COUNT(DISTINCT a.repository_id) = 1
) dir
WHERE dir.gav_dir LIKE 'maven/%-SNAPSHOT'
ON CONFLICT (storage_key) DO NOTHING;

-- (4c) Derived checksum sidecars for the rolled-up `maven-metadata.xml` files.
INSERT INTO maven_flat_object_owner (storage_key, repository_id, source)
SELECT o.storage_key || s.suffix,
       o.repository_id,
       'derived_checksum'
FROM maven_flat_object_owner o
CROSS JOIN (VALUES ('.sha1'), ('.md5'), ('.sha256'), ('.asc')) AS s(suffix)
WHERE o.source = 'metadata_rollup'
ON CONFLICT (storage_key) DO NOTHING;
